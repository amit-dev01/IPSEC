"""Tenant-scoped data access. Every query requires an explicit tenant_id."""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ipsec_analyzer.models.models import Capture


def get_capture_for_tenant(
    db: Session, tenant_id: uuid.UUID, capture_id: uuid.UUID
) -> Capture | None:
    """Return the capture only if it belongs to `tenant_id`; otherwise None (not found)."""
    stmt = select(Capture).where(Capture.id == capture_id, Capture.organization_id == tenant_id)
    return db.scalar(stmt)
