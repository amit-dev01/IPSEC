"""Lab-manifest persistence (ground truth supplied by the authorized testbed)."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from ipsec_analyzer.db.base import Base
from ipsec_analyzer.models.models import JSONBType


def _utcnow() -> datetime:
    return datetime.now(UTC)


class CaptureManifest(Base):
    """One versioned lab manifest per capture. A manifest never overwrites
    packet-observed facts; both are retained and conflicts surface as
    discrepancy evidence during analysis."""

    __tablename__ = "capture_manifests"
    __table_args__ = (UniqueConstraint("capture_id", name="uq_manifest_capture"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    capture_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("captures.id", ondelete="CASCADE"), nullable=False
    )
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="lab_manifest")
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONBType, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
