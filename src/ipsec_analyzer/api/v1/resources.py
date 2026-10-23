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
from sqlalchemy import select
from sqlalchemy.orm import Session

from ipsec_analyzer.api.deps import require_permission
from ipsec_analyzer.core.permissions import Permission
from ipsec_analyzer.db.session import get_db
from ipsec_analyzer.models import AnalysisRun, Capture, User
from ipsec_analyzer.schemas.resources import AnalysisResponse, CaptureResponse, CaptureUpdate
from ipsec_analyzer.services import captures as capture_service
from ipsec_analyzer.services.audit import record_event
from ipsec_analyzer.services.captures import UploadRejected, ingest_capture
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


@router.get("/captures", response_model=list[CaptureResponse])
def list_captures(
    user: Annotated[User, Depends(require_permission(Permission.CAPTURES_READ))],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 50,
    offset: int = 0,
) -> list[CaptureResponse]:
    stmt = (
        select(Capture)
        .where(Capture.organization_id == user.organization_id)
        .order_by(Capture.uploaded_at.desc())
        .limit(min(max(limit, 1), 200))
        .offset(max(offset, 0))
    )
    return [_capture_response(c) for c in db.scalars(stmt)]


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


@router.get("/analyses/{analysis_id}", response_model=AnalysisResponse)
def get_analysis(
    analysis_id: uuid.UUID,
    user: Annotated[User, Depends(require_permission(Permission.ANALYSES_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> AnalysisResponse:
    run = _analysis_or_404(db, user, analysis_id)
    return AnalysisResponse(
        id=run.id,
        organization_id=run.organization_id,
        capture_id=run.capture_id,
        status=str(run.status),
        error_code=run.error_code,
        risk_score=run.risk_score,
        security_score=run.security_score,
    )


@router.get("/analyses/{analysis_id}/report")
def download_report(
    analysis_id: uuid.UUID,
    user: Annotated[User, Depends(require_permission(Permission.REPORTS_DOWNLOAD))],
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    _analysis_or_404(db, user, analysis_id)  # tenant check first; 404 cross-tenant
    raise HTTPException(status_code=404, detail="report_not_available")
