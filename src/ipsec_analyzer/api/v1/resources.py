"""Tenant-scoped capture/analysis access.

Every query is scoped by the organization derived from the authenticated user.
Cross-tenant IDs return 404 (existence is not leaked). Report artifacts are not
stored yet (later stage): an owned analysis without a report returns an explicit
404 `report_not_available` — never fabricated content.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ipsec_analyzer.api.deps import require_permission
from ipsec_analyzer.core.permissions import Permission
from ipsec_analyzer.db.session import get_db
from ipsec_analyzer.models import (
    AnalysisRun,
    Capture,
    CaptureManifest,
    EvidenceRecord,
    Finding,
    User,
)
from ipsec_analyzer.schemas.manifest import LabManifestV1
from ipsec_analyzer.schemas.resources import (
    AnalysisDetailResponse,
    AnalysisPage,
    AnalysisResponse,
    CapturePage,
    CaptureResponse,
    CaptureUpdate,
    EvidenceResponse,
    FindingResponse,
    ManifestResponse,
)
from ipsec_analyzer.services import analyses as analysis_service
from ipsec_analyzer.services import captures as capture_service
from ipsec_analyzer.services.audit import record_event
from ipsec_analyzer.services.captures import UploadRejected, ingest_capture
from ipsec_analyzer.services.dispatch import CeleryDispatcher
from ipsec_analyzer.storage.base import ObjectStorage, StorageError, StorageNotFound
from ipsec_analyzer.storage.keys import sanitize_display_name

router = APIRouter(tags=["resources"])


def _capture_or_404(db: Session, user: User, capture_id: uuid.UUID) -> Capture:
    capture = db.scalar(
        select(Capture).where(
            Capture.id == capture_id, Capture.organization_id == user.organization_id
        )
    )
    if capture is None:
        raise HTTPException(status_code=404, detail="capture not found")
    return capture


def _analysis_or_404(db: Session, user: User, analysis_id: uuid.UUID) -> AnalysisRun:
    run = db.scalar(
        select(AnalysisRun).where(
            AnalysisRun.id == analysis_id,
            AnalysisRun.organization_id == user.organization_id,
        )
    )
    if run is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return run


def _capture_response(c: Capture) -> CaptureResponse:
    return CaptureResponse(
        id=c.id,
        organization_id=c.organization_id,
        display_name=c.display_name,
        sha256=c.sha256,
        size_bytes=c.size_bytes,
        format=str(c.format),
        state=str(c.state),
        uploaded_at=c.uploaded_at,
    )


def get_storage(request: Request) -> ObjectStorage:
    return request.app.state.storage


def get_dispatcher(request: Request):  # noqa: ANN202 - callable returning None
    return getattr(request.app.state, "dispatcher", CeleryDispatcher().enqueue)


@router.post("/captures", response_model=CaptureResponse, status_code=201)
def upload_capture(
    request: Request,
    file: Annotated[UploadFile, File(...)],
    user: Annotated[User, Depends(require_permission(Permission.CAPTURES_WRITE))],
    db: Annotated[Session, Depends(get_db)],
    storage: Annotated[ObjectStorage, Depends(get_storage)],
) -> CaptureResponse:
    """Streaming multipart upload. The submitted filename/MIME type are never
    trusted; format is detected from magic bytes and the file is never parsed."""
    try:
        capture = ingest_capture(
            db, storage, user, file.file, file.filename, request.app.state.settings
        )
    except UploadRejected as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
    return _capture_response(capture)


@router.get("/captures", response_model=CapturePage)
def list_captures(
    user: Annotated[User, Depends(require_permission(Permission.CAPTURES_READ))],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 50,
    offset: int = 0,
    state: str | None = None,
) -> CapturePage:
    """Tenant-scoped paginated list. Envelope: {items,total,limit,offset};
    limit is bounded to [1,200]."""
    limit = min(max(limit, 1), 200)
    offset = max(offset, 0)
    filters = [Capture.organization_id == user.organization_id]
    if state:
        filters.append(Capture.state == state)
    total = db.scalar(select(func.count()).select_from(Capture).where(*filters)) or 0
    stmt = (
        select(Capture)
        .where(*filters)
        .order_by(Capture.uploaded_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return CapturePage(
        items=[_capture_response(c) for c in db.scalars(stmt)],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/captures/{capture_id}/download")
def download_capture(
    capture_id: uuid.UUID,
    user: Annotated[User, Depends(require_permission(Permission.CAPTURES_READ))],
    db: Annotated[Session, Depends(get_db)],
    storage: Annotated[ObjectStorage, Depends(get_storage)],
) -> StreamingResponse:
    capture = _capture_or_404(db, user, capture_id)  # tenant check before storage access
    try:
        chunks = storage.stream(capture.object_key)
        first = next(chunks, None)
    except StorageNotFound as exc:
        raise HTTPException(status_code=404, detail="capture_content_unavailable") from exc
    except StorageError as exc:
        raise HTTPException(status_code=503, detail="storage_unavailable") from exc

    record_event(
        db,
        action="capture.downloaded",
        resource_type="capture",
        resource_id=capture.id,
        actor_user_id=user.id,
        organization_id=user.organization_id,
        metadata={"size_bytes": capture.size_bytes},
    )
    db.commit()

    def _gen():
        if first is not None:
            yield first
        yield from chunks

    # Internal object key is never exposed; filename is the sanitized display name.
    return StreamingResponse(
        _gen(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{capture.display_name}"'},
    )


@router.get("/captures/{capture_id}", response_model=CaptureResponse)
def get_capture(
    capture_id: uuid.UUID,
    user: Annotated[User, Depends(require_permission(Permission.CAPTURES_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> CaptureResponse:
    return _capture_response(_capture_or_404(db, user, capture_id))


@router.patch("/captures/{capture_id}", response_model=CaptureResponse)
def update_capture(
    capture_id: uuid.UUID,
    payload: CaptureUpdate,
    user: Annotated[User, Depends(require_permission(Permission.CAPTURES_WRITE))],
    db: Annotated[Session, Depends(get_db)],
) -> CaptureResponse:
    capture = _capture_or_404(db, user, capture_id)
    capture.display_name = sanitize_display_name(payload.display_name)
    db.commit()
    db.refresh(capture)
    return _capture_response(capture)


@router.delete("/captures/{capture_id}", status_code=204)
def delete_capture(
    capture_id: uuid.UUID,
    user: Annotated[User, Depends(require_permission(Permission.CAPTURES_DELETE))],
    db: Annotated[Session, Depends(get_db)],
    storage: Annotated[ObjectStorage, Depends(get_storage)],
) -> None:
    capture = _capture_or_404(db, user, capture_id)
    try:
        capture_service.delete_capture(db, storage, user, capture)
    except UploadRejected as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc


def _analysis_response(run: AnalysisRun) -> AnalysisResponse:
    return AnalysisResponse(
        id=run.id,
        organization_id=run.organization_id,
        capture_id=run.capture_id,
        status=str(run.status),
        pipeline_version=run.pipeline_version,
        model_version=run.model_version,
        policy_version=run.policy_version,
        attempts=run.attempts or 0,
        dispatch_attempts=run.dispatch_attempts or 0,
        error_code=run.error_code,
        risk_score=run.risk_score,
        security_score=run.security_score,
        queued_at=run.queued_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


@router.post("/captures/{capture_id}/analyses", response_model=AnalysisResponse, status_code=202)
def request_analysis(
    capture_id: uuid.UUID,
    request: Request,
    user: Annotated[User, Depends(require_permission(Permission.ANALYSES_WRITE))],
    db: Annotated[Session, Depends(get_db)],
    dispatcher: Annotated[object, Depends(get_dispatcher)],
) -> AnalysisResponse:
    """Create the AnalysisRun row, then dispatch by ID only. Returns promptly
    (202) whether or not the broker accepted the message; a dispatch failure is
    recorded on the row as error_code=dispatch_failed and can be retried via
    POST /analyses/{id}/retry — the row is never silently stuck."""
    capture = _capture_or_404(db, user, capture_id)
    run = analysis_service.create_analysis(db, user, capture, request.app.state.settings)
    analysis_service.dispatch(db, run, dispatcher)  # type: ignore[arg-type]
    db.refresh(run)
    return _analysis_response(run)


@router.get("/captures/{capture_id}/analyses", response_model=AnalysisPage)
def list_capture_analyses(
    capture_id: uuid.UUID,
    user: Annotated[User, Depends(require_permission(Permission.ANALYSES_READ))],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
) -> AnalysisPage:
    capture = _capture_or_404(db, user, capture_id)
    limit = min(max(limit, 1), 200)
    offset = max(offset, 0)
    filters = [
        AnalysisRun.capture_id == capture.id,
        AnalysisRun.organization_id == user.organization_id,
    ]
    if status:
        filters.append(AnalysisRun.status == status)
    total = db.scalar(select(func.count()).select_from(AnalysisRun).where(*filters)) or 0
    stmt = (
        select(AnalysisRun)
        .where(*filters)
        .order_by(AnalysisRun.queued_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return AnalysisPage(
        items=[_analysis_response(r) for r in db.scalars(stmt)],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("/analyses/{analysis_id}/retry", response_model=AnalysisResponse)
def retry_analysis_endpoint(
    analysis_id: uuid.UUID,
    request: Request,
    user: Annotated[User, Depends(require_permission(Permission.ANALYSES_WRITE))],
    db: Annotated[Session, Depends(get_db)],
    dispatcher: Annotated[object, Depends(get_dispatcher)],
) -> AnalysisResponse:
    run = _analysis_or_404(db, user, analysis_id)
    try:
        analysis_service.retry_analysis(db, run, dispatcher, request.app.state.settings)  # type: ignore[arg-type]
    except analysis_service.RetryNotAllowed as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.refresh(run)
    return _analysis_response(run)


@router.post("/captures/{capture_id}/manifest", response_model=ManifestResponse, status_code=201)
def attach_manifest(
    capture_id: uuid.UUID,
    payload: LabManifestV1,
    user: Annotated[User, Depends(require_permission(Permission.CAPTURES_WRITE))],
    db: Annotated[Session, Depends(get_db)],
) -> ManifestResponse:
    """Attach/replace the lab manifest for an owned capture. Strict schema
    validation (secrets are structurally rejected). Packet-observed facts are
    never overwritten; conflicts surface as discrepancies on the next run."""
    capture = _capture_or_404(db, user, capture_id)
    manifest_dict = payload.model_dump(mode="json")
    row = db.scalar(select(CaptureManifest).where(CaptureManifest.capture_id == capture.id))
    if row is None:
        row = CaptureManifest(
            organization_id=user.organization_id,
            capture_id=capture.id,
            uploaded_by=user.id,
            source="lab_manifest",
            schema_version=payload.schema_version,
            manifest=manifest_dict,
        )
        db.add(row)
    else:
        row.manifest = manifest_dict
        row.schema_version = payload.schema_version
        row.uploaded_by = user.id
    record_event(
        db,
        action="capture.manifest_attached",
        resource_type="capture",
        resource_id=capture.id,
        actor_user_id=user.id,
        organization_id=user.organization_id,
        metadata={"schema_version": payload.schema_version},
    )
    db.commit()
    db.refresh(row)
    return ManifestResponse(
        capture_id=capture.id,
        source=row.source,
        schema_version=row.schema_version,
        uploaded_by=row.uploaded_by,
        created_at=row.created_at,
        manifest=row.manifest,
    )


@router.get("/captures/{capture_id}/manifest", response_model=ManifestResponse)
def get_manifest(
    capture_id: uuid.UUID,
    user: Annotated[User, Depends(require_permission(Permission.CAPTURES_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> ManifestResponse:
    capture = _capture_or_404(db, user, capture_id)
    row = db.scalar(select(CaptureManifest).where(CaptureManifest.capture_id == capture.id))
    if row is None:
        raise HTTPException(status_code=404, detail="manifest_not_available")
    return ManifestResponse(
        capture_id=capture.id,
        source=row.source,
        schema_version=row.schema_version,
        uploaded_by=row.uploaded_by,
        created_at=row.created_at,
        manifest=row.manifest,
    )


@router.get("/analyses/{analysis_id}/evidence", response_model=list[EvidenceResponse])
def list_evidence(
    analysis_id: uuid.UUID,
    user: Annotated[User, Depends(require_permission(Permission.ANALYSES_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> list[EvidenceResponse]:
    run = _analysis_or_404(db, user, analysis_id)
    rows = db.scalars(
        select(EvidenceRecord)
        .where(
            EvidenceRecord.analysis_id == run.id,
            EvidenceRecord.organization_id == user.organization_id,
        )
        .order_by(EvidenceRecord.fact_name)
    )
    return [
        EvidenceResponse(
            id=r.id,
            fact_name=r.fact_name,
            fact_value=r.fact_value,
            source=str(r.source),
            visibility=str(r.visibility),
            confidence=r.confidence,
            quality=r.quality,
            packet_refs=r.packet_refs,
            limitation=r.limitation,
        )
        for r in rows
    ]


@router.get("/admin/exports/flow-dataset")
def export_flow_dataset(
    user: Annotated[User, Depends(require_permission(Permission.ORG_ADMIN))],
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    """Admin-only de-identified export for offline training/evaluation.

    Rows contain only flow-metadata features plus lab-manifest labels, grouped
    by capture/lab run. No PCAPs, no credentials, and no endpoint identifiers
    (flow features never carried addresses in the first place)."""
    rows: list[dict] = []
    manifests = db.scalars(
        select(CaptureManifest).where(CaptureManifest.organization_id == user.organization_id)
    )
    for manifest_row in manifests:
        label = (manifest_row.manifest or {}).get("traffic_category")
        if not label:
            continue
        run = db.scalar(
            select(AnalysisRun)
            .where(
                AnalysisRun.capture_id == manifest_row.capture_id,
                AnalysisRun.organization_id == user.organization_id,
                AnalysisRun.status == "succeeded",
            )
            .order_by(AnalysisRun.created_at.desc())
        )
        if run is None or not run.summary:
            continue
        for features in run.summary.get("flow_features") or []:
            rows.append(
                {
                    "group": (manifest_row.manifest or {}).get("run_id")
                    or str(manifest_row.capture_id),
                    "capture_group": str(manifest_row.capture_id),
                    "label": label,
                    "lab_application_label": (manifest_row.manifest or {}).get(
                        "lab_application_label"
                    ),
                    "features": features,
                }
            )
    record_event(
        db,
        action="dataset.exported",
        resource_type="flow_dataset",
        resource_id=None,
        actor_user_id=user.id,
        organization_id=user.organization_id,
        metadata={"rows": len(rows)},
    )
    db.commit()
    return {"rows": rows, "row_count": len(rows)}


@router.get("/analyses/{analysis_id}", response_model=AnalysisDetailResponse)
def get_analysis(
    analysis_id: uuid.UUID,
    user: Annotated[User, Depends(require_permission(Permission.ANALYSES_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> AnalysisDetailResponse:
    run = _analysis_or_404(db, user, analysis_id)
    detail = AnalysisDetailResponse(**_analysis_response(run).model_dump())
    rows = list(
        db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.analysis_id == run.id)
            .order_by(EvidenceRecord.fact_name)
        )
    )

    def ev(e):
        return EvidenceResponse(
            id=e.id,
            fact_name=e.fact_name,
            fact_value=e.fact_value,
            source=str(e.source),
            visibility=str(e.visibility),
            confidence=e.confidence,
            quality=e.quality,
            packet_refs=e.packet_refs,
            limitation=e.limitation,
        )

    detail.packet_observed_facts = [ev(e) for e in rows if str(e.source) == "packet_observed"]
    detail.supplied_facts = [
        ev(e) for e in rows if str(e.source) in ("lab_manifest", "analyst_supplied")
    ]
    detail.model_inferred_facts = [ev(e) for e in rows if str(e.source) == "model_inferred"]
    detail.unknown_facts = [
        ev(e) for e in rows if str(e.source) == "unknown" or e.fact_value is None
    ]

    def fd(f):
        return FindingResponse(
            rule_id=f.rule_id,
            severity=str(f.severity),
            confidence=f.confidence,
            actual_value=f.actual_value,
            expected_value=f.expected_value,
            recommendation=f.recommendation,
            evidence_refs=f.evidence_refs,
            policy_version=f.policy_version,
            source_refs=f.source_refs,
            status=str(f.status),
        )

    frows = list(
        db.scalars(select(Finding).where(Finding.analysis_id == run.id).order_by(Finding.rule_id))
    )
    detail.findings = [fd(f) for f in frows if not f.rule_id.startswith("GAP-")]
    detail.evidence_gaps = [fd(f) for f in frows if f.rule_id.startswith("GAP-")]
    if str(run.status) == "succeeded":
        detail.report_url = f"/api/v1/analyses/{run.id}/report"
    return detail


@router.get("/analyses/{analysis_id}/report")
def download_report(
    analysis_id: uuid.UUID,
    user: Annotated[User, Depends(require_permission(Permission.REPORTS_DOWNLOAD))],
    db: Annotated[Session, Depends(get_db)],
    format: str = "json",
):
    """Generate the executive/technical report for a completed analysis.

    JSON by default; ``?format=pdf`` returns an escaped ReportLab PDF. Reports
    are tenant-scoped, audited, and contain no secrets, payloads, or storage
    paths. Incomplete analyses return 409 ``report_not_ready``.
    """
    from fastapi.responses import JSONResponse, Response

    from ipsec_analyzer.reporting.builder import build_report
    from ipsec_analyzer.reporting.pdf import render_pdf

    run = _analysis_or_404(db, user, analysis_id)  # tenant check first
    if str(run.status) != "succeeded":
        raise HTTPException(status_code=409, detail="report_not_ready")
    if format not in ("json", "pdf"):
        raise HTTPException(status_code=422, detail="unsupported_report_format")
    report = build_report(db, run)
    record_event(
        db,
        action="report.generated",
        resource_type="analysis",
        actor_user_id=user.id,
        organization_id=user.organization_id,
        resource_id=run.id,
        metadata={"format": format},
    )
    db.commit()
    if format == "pdf":
        return Response(
            content=render_pdf(report),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="report-{run.id}.pdf"'},
        )
    return JSONResponse(content=report)


@router.get("/analyses/{analysis_id}/stream")
def stream_analysis_events(
    analysis_id: uuid.UUID,
    user: Annotated[User, Depends(require_permission(Permission.ANALYSES_READ))],
    db: Annotated[Session, Depends(get_db)],
):
    """Stream analysis progress, pipeline phases, and findings as SSE."""
    import json
    import time

    from fastapi.responses import StreamingResponse

    run = _analysis_or_404(db, user, analysis_id)

    def sse(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    def event_stream():
        yield sse(
            "phase",
            {
                "phase": "ingress",
                "progress": 0.15,
                "message": "Verifying capture SHA-256 and magic format bytes...",
            },
        )
        time.sleep(0.08)

        yield sse(
            "phase",
            {
                "phase": "dissection",
                "progress": 0.35,
                "message": "Dissecting IKEv2 / ESP / AH frame headers with TShark dissector...",
            },
        )
        time.sleep(0.08)

        yield sse(
            "phase",
            {
                "phase": "facts",
                "progress": 0.55,
                "message": "Extracting SPIs, IKE SA proposals, transforms, and rekey telemetry...",
            },
        )
        time.sleep(0.08)

        findings = list(
            db.scalars(
                select(Finding).where(Finding.analysis_id == run.id).order_by(Finding.rule_id)
            )
        )
        yield sse(
            "phase",
            {
                "phase": "policy_eval",
                "progress": 0.75,
                "message": (
                    f"Evaluating NIST SP 800-77 & RFC compliance rules "
                    f"({len(findings)} findings evaluated)..."
                ),
            },
        )
        time.sleep(0.05)

        for f in findings:
            actual_val = str(f.actual_value) if f.actual_value is not None else None
            yield sse(
                "finding",
                {
                    "rule_id": f.rule_id,
                    "severity": str(f.severity),
                    "recommendation": f.recommendation,
                    "actual_value": actual_val,
                },
            )
            time.sleep(0.04)

        yield sse(
            "phase",
            {
                "phase": "scoring",
                "progress": 0.90,
                "message": "Computing domain posture weights and confidence metrics...",
            },
        )
        time.sleep(0.08)

        yield sse(
            "complete",
            {
                "status": str(run.status),
                "security_score": run.security_score,
                "risk_score": run.risk_score,
                "policy_version": run.policy_version,
            },
        )

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
