"""Tenant-scoped capture/analysis access.

Every query is scoped by the organization derived from the authenticated user.
Cross-tenant IDs return 404 (existence is not leaked). Report artifacts are not
stored yet (later stage): an owned analysis without a report returns an explicit
404 `report_not_available` — never fabricated content.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ipsec_analyzer.api.deps import require_permission
from ipsec_analyzer.core.permissions import Permission
from ipsec_analyzer.db.session import get_db
from ipsec_analyzer.models import AnalysisRun, Capture, CaptureState, User
from ipsec_analyzer.schemas.resources import AnalysisResponse, CaptureResponse, CaptureUpdate

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
    capture.display_name = payload.display_name
    db.commit()
    db.refresh(capture)
    return _capture_response(capture)


@router.delete("/captures/{capture_id}", status_code=204)
def delete_capture(
    capture_id: uuid.UUID,
    user: Annotated[User, Depends(require_permission(Permission.CAPTURES_DELETE))],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    capture = _capture_or_404(db, user, capture_id)
    # Tombstone only; physical object/DB deletion follows the retention flow in a
    # later stage. Cross-tenant IDs already 404 above.
    capture.state = CaptureState.DELETION_PENDING
    db.commit()


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
