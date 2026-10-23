"""Worker-side analysis processing. This module imports the TShark adapter
and the ML classifier and must only be imported by the Celery worker — never
by the API (the API must not import or run TShark).
"""

import hashlib
import logging
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.ml.classifier import TrafficClassifier, unavailable_prediction
from ipsec_analyzer.ml.features import capture_features, flow_features
from ipsec_analyzer.models import (
    AnalysisRun,
    AnalysisStatus,
    Capture,
    CaptureManifest,
    CaptureState,
    EvidenceRecord,
    EvidenceSource,
    EvidenceVisibility,
    Finding,
    FindingSeverity,
)
from ipsec_analyzer.parsing.magic import detect_format
from ipsec_analyzer.parsing.tshark import ParserError, ParserUnavailable, TsharkAdapter
from ipsec_analyzer.pipeline.evidence import build_evidence
from ipsec_analyzer.pipeline.manifest_facts import discrepancies, manifest_facts
from ipsec_analyzer.services.analyses import transition
from ipsec_analyzer.services.audit import record_event
from ipsec_analyzer.storage.base import ObjectStorage, StorageError, StorageNotFound

logger = logging.getLogger(__name__)


def _fail(db: Session, run: AnalysisRun, code: str) -> str:
    transition(run, AnalysisStatus.FAILED)
    run.error_code = code
    run.finished_at = datetime.now(UTC)
    db.commit()
    logger.info("analysis failed analysis_id=%s error_code=%s", run.id, code)
    return "failed"


def _unavailable(db: Session, run: AnalysisRun, code: str) -> str:
    transition(run, AnalysisStatus.UNAVAILABLE)
    run.error_code = code
    run.finished_at = datetime.now(UTC)
    db.commit()
    logger.info("analysis unavailable analysis_id=%s error_code=%s", run.id, code)
    return "unavailable"


def process_analysis(
    db: Session,
    storage: ObjectStorage,
    analysis_id: uuid.UUID,
    settings: Settings,
    parser: TsharkAdapter | None = None,
) -> str:
    """Idempotent worker entry point. Returns the resulting status string.

    Duplicate delivery is safe: the queued->running claim is a single atomic
    UPDATE; if the run is already running/terminal, this is a no-op and no
    duplicate evidence or findings are written.
    """
    # Atomic claim: only one delivery can move queued/pending -> running.
    claimed = db.execute(
        update(AnalysisRun)
        .where(
            AnalysisRun.id == analysis_id,
            AnalysisRun.status.in_([AnalysisStatus.QUEUED, AnalysisStatus.PENDING]),
        )
        .values(
            status=AnalysisStatus.RUNNING,
            started_at=datetime.now(UTC),
            attempts=AnalysisRun.attempts + 1,
            error_code=None,
        )
    )
    db.commit()
    run = db.get(AnalysisRun, analysis_id)
    if run is None:
        logger.warning("analysis task for unknown run id=%s", analysis_id)
        return "unknown"
    if claimed.rowcount == 0:
        # Already running (duplicate in flight) or terminal: do not redo work.
        logger.info(
            "analysis duplicate delivery ignored analysis_id=%s status=%s", run.id, run.status
        )
        return str(run.status)

    capture = db.get(Capture, run.capture_id)
    if capture is None:
        return _fail(db, run, "capture_not_found")
    if capture.organization_id != run.organization_id:
        return _fail(db, run, "capture_tenant_mismatch")
    if CaptureState(capture.state) is not CaptureState.READY:
        return _fail(db, run, "unsupported_capture_state")
    # Download to a private temp dir (worker only), verify integrity BEFORE
    # parsing, parse with the fixed TShark adapter, then clean up on all paths.
    parser = parser or TsharkAdapter(settings)
    with tempfile.TemporaryDirectory(prefix="ipsec-worker-") as tmp:
        path = Path(tmp) / "capture.bin"  # server-generated name, never user input
        digest = hashlib.sha256()
        total = 0
        magic = b""
        try:
            with path.open("wb") as fh:
                for chunk in storage.stream(capture.object_key):
                    if not magic:
                        magic = chunk[:4]
                    total += len(chunk)
                    if total > settings.max_upload_bytes:
                        return _fail(db, run, "limit_exceeded")
                    digest.update(chunk)
                    fh.write(chunk)
        except StorageNotFound:
            return _fail(db, run, "capture_content_unavailable")
        except StorageError:
            # Transient infrastructure failure: requeue while attempts remain.
            if (run.attempts or 0) < settings.analysis_max_attempts:
                transition(run, AnalysisStatus.QUEUED)
                run.error_code = "storage_unavailable"
                run.started_at = None
                db.commit()
                logger.info("analysis requeued (transient) analysis_id=%s", run.id)
                return "retry"
            return _fail(db, run, "storage_unavailable")

        if total != capture.size_bytes or digest.hexdigest() != capture.sha256:
            return _fail(db, run, "integrity_mismatch")
        detected = detect_format(magic)
        if detected is None or str(detected) != str(capture.format):
            return _fail(db, run, "invalid_capture")

        try:
            result = parser.parse(path)
        except ParserUnavailable:
            return _unavailable(db, run, "parser_unavailable")
        except ParserError as exc:
            run.summary = {"stage": settings.pipeline_version, "parser_error": exc.code}
            return _fail(db, run, exc.code)
    # temp dir (and the downloaded capture) is deleted here on every path

    packets = result.packets
    meta = result.metadata
    drafts = build_evidence(packets, allow_plain_addresses=settings.evidence_allow_plain_addresses)
    drafts.insert(
        0,
        type(drafts[0])(
            fact_name="capture.integrity_verified",
            fact_value={"sha256_verified": True, "size_bytes": total, "format": str(detected)},
            source=EvidenceSource.PACKET_OBSERVED,
            visibility=EvidenceVisibility.VISIBLE,
            confidence=1.0,
            quality=1.0,
            limitation="hash of the downloaded object matched the database record before parsing",
        )
        if drafts
        else None,
    )
    drafts = [d for d in drafts if d is not None]

    manifest_row = db.scalar(
        select(CaptureManifest).where(CaptureManifest.capture_id == capture.id)
    )
    discrepancy_drafts = []
    if manifest_row is not None:
        drafts.extend(manifest_facts(manifest_row.manifest))
        discrepancy_drafts = discrepancies(manifest_row.manifest, drafts)
        drafts.extend(discrepancy_drafts)

    features = capture_features(packets)
    flows = flow_features(packets)
    classifier = TrafficClassifier.load(settings.ml_model_path, settings.ml_abstain_threshold)
    prediction = classifier.predict(features) if classifier else unavailable_prediction()
    if classifier is not None:
        from ipsec_analyzer.pipeline.evidence import EvidenceDraft

        drafts.append(
            EvidenceDraft(
                fact_name="ml.traffic_category",
                fact_value=prediction["predicted_category"],
                source=EvidenceSource.MODEL_INFERRED,
                visibility=EvidenceVisibility.DERIVED,
                confidence=prediction["confidence"],
                quality=prediction["confidence"],
                limitation=prediction["limitations"],
            )
        )
        run.model_version = prediction["model_version"]

    # Replace (never duplicate) this run's evidence/findings, then succeed.
    db.execute(Finding.__table__.delete().where(Finding.analysis_id == run.id))
    db.execute(EvidenceRecord.__table__.delete().where(EvidenceRecord.analysis_id == run.id))
    records: dict[int, EvidenceRecord] = {}
    for draft in drafts:
        record = EvidenceRecord(
            organization_id=run.organization_id,
            analysis_id=run.id,
            fact_name=draft.fact_name,
            fact_value=draft.fact_value,
            source=draft.source,
            visibility=draft.visibility,
            confidence=draft.confidence,
            quality=draft.quality,
            packet_refs=draft.packet_refs,
            limitation=draft.limitation,
        )
        db.add(record)
        records[id(draft)] = record
    db.flush()
    for draft in discrepancy_drafts:
        record = records.get(id(draft))
        db.add(
            Finding(
                organization_id=run.organization_id,
                analysis_id=run.id,
                rule_id="MANIFEST_PACKET_DISCREPANCY",
                severity=FindingSeverity.MEDIUM,
                confidence=1.0,
                evidence_refs=[str(record.id)] if record else [],
                recommendation=(
                    "Review lab manifest vs packet-observed selection; both sources retained."
                ),
                status="open",
            )
        )

    transition(run, AnalysisStatus.SUCCEEDED)
    run.summary = {
        "stage": settings.pipeline_version,
        "tshark_version": meta.tshark_version,
        "parser_version": meta.parser_version,
        "packet_count": meta.packet_count,
        "packets_parsed": meta.packet_count,
        "truncated": meta.truncated,
        "truncation_warnings": meta.truncation_warnings,
        "parse_limitations": meta.limitations,
        "unsupported_fields": meta.unsupported_fields,
        "flow_features": flows,
        "ml_prediction": prediction,
    }
    protocols_seen = {p.protocol for p in packets}
    run.evidence_coverage = {
        "capture_integrity": "packet_observed",
        "ike": "packet_observed" if "ike" in protocols_seen else "unknown",
        "esp": "packet_observed" if "esp" in protocols_seen else "unknown",
        "child_sa": "unknown",
        "esp_cipher": "unknown",
        "traffic_category": prediction["status"],
    }
    run.finished_at = datetime.now(UTC)
    record_event(
        db,
        action="analysis.succeeded",
        resource_type="analysis_run",
        resource_id=run.id,
        actor_user_id=None,
        organization_id=run.organization_id,
        metadata={"capture_id": str(capture.id), "packet_count": meta.packet_count},
    )
    db.commit()
    logger.info(
        "analysis succeeded analysis_id=%s packets=%s tshark=%s",
        run.id,
        meta.packet_count,
        meta.tshark_version,
    )
    return "succeeded"
