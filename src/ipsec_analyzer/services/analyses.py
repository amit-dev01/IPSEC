"""AnalysisRun lifecycle: creation, dispatch, retry, reconciliation, processing.

State machine (enforced by `transition`):

    queued -> running -> succeeded
                      -> failed
    queued -> cancelled
    failed -> queued        (documented retry path; transient failures only,
                             and only while attempts < analysis_max_attempts)
    running -> queued       (worker-internal requeue after a transient failure
                             with attempts remaining)

`succeeded`/`cancelled` are terminal. Anything else raises InvalidTransition.
PostgreSQL is the authoritative status store; Celery is transport only.

The current pipeline stage ("verification-0.1") does bounded, honest work:
stream the stored object, verify size + SHA-256 + magic bytes, and record that
as evidence. It produces no findings and no scores — packet parsing arrives in
a later stage and must replace/extend this stage, not fabricate results.
"""

import hashlib
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.models import (
    AnalysisRun,
    AnalysisStatus,
    Capture,
    CaptureState,
    EvidenceRecord,
    EvidenceSource,
    EvidenceVisibility,
    User,
)
from ipsec_analyzer.parsing.magic import detect_format
from ipsec_analyzer.services.audit import record_event
from ipsec_analyzer.services.dispatch import DispatchError
from ipsec_analyzer.storage.base import ObjectStorage, StorageError, StorageNotFound

logger = logging.getLogger(__name__)

VALID_TRANSITIONS: dict[AnalysisStatus, frozenset[AnalysisStatus]] = {
    AnalysisStatus.QUEUED: frozenset({AnalysisStatus.RUNNING, AnalysisStatus.CANCELLED}),
    AnalysisStatus.PENDING: frozenset({AnalysisStatus.RUNNING, AnalysisStatus.CANCELLED}),
    AnalysisStatus.RUNNING: frozenset(
        {AnalysisStatus.SUCCEEDED, AnalysisStatus.FAILED, AnalysisStatus.QUEUED}
    ),
    AnalysisStatus.FAILED: frozenset({AnalysisStatus.QUEUED}),
    AnalysisStatus.SUCCEEDED: frozenset(),
    AnalysisStatus.UNAVAILABLE: frozenset(),
    AnalysisStatus.CANCELLED: frozenset(),
}

# Only these failure codes may be retried. Invalid/unsupported captures,
# integrity failures, and missing objects are terminal.
TRANSIENT_ERROR_CODES = frozenset(
    {"storage_unavailable", "worker_timeout", "broker_unavailable", "dispatch_failed"}
)

Dispatcher = Callable[[uuid.UUID], None]


class InvalidTransition(Exception):
    pass


class RetryNotAllowed(Exception):
    pass


def transition(run: AnalysisRun, target: AnalysisStatus) -> None:
    current = AnalysisStatus(run.status)
    if target not in VALID_TRANSITIONS.get(current, frozenset()):
        raise InvalidTransition(f"{current.value} -> {target.value} is not a valid transition")
    run.status = target


def create_analysis(db: Session, user: User, capture: Capture, settings: Settings) -> AnalysisRun:
    run = AnalysisRun(
        organization_id=user.organization_id,
        capture_id=capture.id,
        requester_id=user.id,
        status=AnalysisStatus.QUEUED,
        pipeline_version=settings.pipeline_version,
        policy_version=settings.policy_version,
        model_version=None,  # no model runs at this pipeline stage
    )
    db.add(run)
    db.flush()
    record_event(
        db,
        action="analysis.queued",
        resource_type="analysis_run",
        resource_id=run.id,
        actor_user_id=user.id,
        organization_id=user.organization_id,
        metadata={"capture_id": str(capture.id), "pipeline_version": settings.pipeline_version},
    )
    db.commit()  # the row exists BEFORE any dispatch attempt
    db.refresh(run)
    return run


def dispatch(db: Session, run: AnalysisRun, dispatcher: Dispatcher) -> bool:
    """Try to enqueue; on broker failure record dispatch_failed (never stuck silently)."""
    run.dispatch_attempts = (run.dispatch_attempts or 0) + 1
    db.commit()
    try:
        dispatcher(run.id)
    except DispatchError:
        run.error_code = "dispatch_failed"
        db.commit()
        logger.warning("analysis dispatch_failed analysis_id=%s", run.id)
        return False
    if run.error_code == "dispatch_failed":
        run.error_code = None
        db.commit()
    return True


def retry_analysis(
    db: Session, run: AnalysisRun, dispatcher: Dispatcher, settings: Settings
) -> bool:
    """Documented retry path. Returns True if (re)dispatched."""
    status = AnalysisStatus(run.status)
    if status is AnalysisStatus.QUEUED and run.error_code == "dispatch_failed":
        return dispatch(db, run, dispatcher)
    if status is AnalysisStatus.FAILED:
        if run.error_code not in TRANSIENT_ERROR_CODES:
            raise RetryNotAllowed(f"error_code={run.error_code} is not retryable")
        if (run.attempts or 0) >= settings.analysis_max_attempts:
            raise RetryNotAllowed("maximum attempts reached")
        transition(run, AnalysisStatus.QUEUED)
        run.error_code = None
        run.started_at = None
        run.finished_at = None
        db.commit()
        return dispatch(db, run, dispatcher)
    raise RetryNotAllowed(f"cannot retry an analysis in status {status.value}")


def reconcile_stale(db: Session, dispatcher: Dispatcher, settings: Settings) -> int:
    """Redispatch queued runs that never started (broker was down, worker lost).

    Intended to run periodically (Celery beat task `reconcile_queued_analyses`).
    Returns the number of runs redispatched successfully.
    """
    cutoff = datetime.now(UTC) - timedelta(seconds=settings.dispatch_stale_seconds)
    stale = list(
        db.scalars(
            select(AnalysisRun).where(
                AnalysisRun.status.in_([AnalysisStatus.QUEUED, AnalysisStatus.PENDING]),
                AnalysisRun.started_at.is_(None),
                AnalysisRun.queued_at < cutoff,
            )
        )
    )
    recovered = 0
    for run in stale:
        if dispatch(db, run, dispatcher):
            recovered += 1
    if stale:
        logger.info("reconciled %s/%s stale queued analyses", recovered, len(stale))
    return recovered


def _fail(db: Session, run: AnalysisRun, code: str) -> str:
    transition(run, AnalysisStatus.FAILED)
    run.error_code = code
    run.finished_at = datetime.now(UTC)
    db.commit()
    logger.info("analysis failed analysis_id=%s error_code=%s", run.id, code)
    return "failed"


def process_analysis(
    db: Session, storage: ObjectStorage, analysis_id: uuid.UUID, settings: Settings
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
    # Stream the object once: size, SHA-256, magic. Bytes are never stored/logged.
    digest = hashlib.sha256()
    total = 0
    magic = b""
    try:
        for chunk in storage.stream(capture.object_key):
            if not magic:
                magic = chunk[:4]
            total += len(chunk)
            if total > settings.max_upload_bytes:
                return _fail(db, run, "limit_exceeded")
            digest.update(chunk)
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

    # Replace (never duplicate) this stage's evidence, then succeed.
    db.execute(EvidenceRecord.__table__.delete().where(EvidenceRecord.analysis_id == run.id))
    db.add(
        EvidenceRecord(
            organization_id=run.organization_id,
            analysis_id=run.id,
            fact_name="capture.integrity_verified",
            fact_value={
                "sha256_verified": True,
                "size_bytes": total,
                "format": str(detected),
                "scope": "storage integrity and format only; packets not yet parsed",
            },
            source=EvidenceSource.PACKET_OBSERVED,
            visibility=EvidenceVisibility.VISIBLE,
            confidence=1.0,
            quality=1.0,
        )
    )
    transition(run, AnalysisStatus.SUCCEEDED)
    run.summary = {
        "stage": settings.pipeline_version,
        "packets_parsed": 0,
        "note": "capture integrity verified; packet parsing is a later pipeline stage",
    }
    run.evidence_coverage = {"capture_integrity": "packet_observed", "ipsec_protocol": "unknown"}
    run.finished_at = datetime.now(UTC)
    record_event(
        db,
        action="analysis.succeeded",
        resource_type="analysis_run",
        resource_id=run.id,
        actor_user_id=None,
        organization_id=run.organization_id,
        metadata={"capture_id": str(capture.id)},
    )
    db.commit()
    logger.info("analysis succeeded analysis_id=%s", run.id)
    return "succeeded"
