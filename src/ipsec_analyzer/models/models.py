import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ipsec_analyzer.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class CaptureStatus(StrEnum):
    UPLOADED = "uploaded"
    VERIFYING = "verifying"
    READY = "ready"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"  # worker/capability not available; never faked as success


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Capture(Base):
    """Metadata only. PCAP bytes live in private object storage, never in the DB."""

    __tablename__ = "captures"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    uploaded_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    object_key: Mapped[str] = mapped_column(String(1024))
    sha256: Mapped[str] = mapped_column(String(64))  # hex digest, verified after upload
    size_bytes: Mapped[int]
    status: Mapped[str] = mapped_column(String(32), default=CaptureStatus.UNKNOWN)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    capture_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("captures.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default=JobStatus.PENDING)
    # Explicit reason when status is unavailable/failed; no fabricated findings are stored.
    status_detail: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
