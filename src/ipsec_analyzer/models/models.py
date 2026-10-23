"""ORM models (SQLAlchemy 2, typed).

Design rules (see docs/architecture.md and docs/adr/0002):
- PostgreSQL stores metadata only. PCAP bytes never enter the database.
- Tenant = Organization. Every tenant-owned row carries `organization_id` and
  tenant predicates belong in queries and composite indexes, not post-filtering.
- Typed columns for frequently filtered fields; JSONB only for genuinely
  variable data (run summaries, evidence coverage, fact values, reference lists).
- All timestamps are UTC (`timestamptz`).
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ipsec_analyzer.db.base import Base

# JSONB on PostgreSQL; plain JSON elsewhere (unit-test portability only —
# production/migrations always target PostgreSQL).
JSONBType = JSONB().with_variant(JSON(), "sqlite")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _enum(enum_cls: type[StrEnum], name: str) -> Enum:
    # native_enum=False => VARCHAR + CHECK on PostgreSQL (values enforced by the DB,
    # portable DDL, and the Python StrEnum remains the single source of values).
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        length=32,
        validate_strings=True,
        values_callable=lambda e: [m.value for m in e],
    )


class CaptureFormat(StrEnum):
    PCAP = "pcap"
    PCAPNG = "pcapng"


class CaptureState(StrEnum):
    UPLOADED = "uploaded"
    VERIFYING = "verifying"
    READY = "ready"
    REJECTED = "rejected"
    DELETION_PENDING = "deletion_pending"
    UNKNOWN = "unknown"


# Backwards-compatible names from the scaffold stage.
CaptureStatus = CaptureState


class AnalysisStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"  # capability missing; never faked as success
    CANCELLED = "cancelled"


JobStatus = AnalysisStatus


class EvidenceSource(StrEnum):
    PACKET_OBSERVED = "packet_observed"
    LAB_MANIFEST = "lab_manifest"
    ANALYST_SUPPLIED = "analyst_supplied"
    MODEL_INFERRED = "model_inferred"
    UNKNOWN = "unknown"


class EvidenceVisibility(StrEnum):
    VISIBLE = "visible"
    ENCRYPTED_NOT_VISIBLE = "encrypted_not_visible"  # e.g. ESP payload, IKE_AUTH contents
    NOT_IN_CAPTURE = "not_in_capture"  # capture started mid-session / wrong vantage point
    UNKNOWN = "unknown"


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UserRole(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class Organization(Base):
    """A tenant. Deleting an organization cascades to its owned rows (see FKs);
    audit events survive with a null organization (SET NULL) for accountability."""

    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
        server_default=func.now(),
    )

    users: Mapped[list["User"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    captures: Mapped[list["Capture"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


# Scaffold-stage alias: the tenant concept is the Organization.
Tenant = Organization


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("organization_id", "email", name="uq_user_org_email"),
        Index("ix_users_org_active", "organization_id", "is_active"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    # Argon2id hash only — plaintext passwords are never stored or logged.
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    role: Mapped[UserRole] = mapped_column(
        _enum(UserRole, "user_role"), nullable=False, default=UserRole.VIEWER
    )
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
        server_default=func.now(),
    )

    organization: Mapped[Organization] = relationship(back_populates="users")

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.organization_id


class Capture(Base):
    """Capture metadata only. Object-storage key is a server-generated random key;
    the user-supplied display name is stored separately and never used as a path."""

    __tablename__ = "captures"
    __table_args__ = (
        UniqueConstraint("object_key", name="uq_capture_object_key"),
        CheckConstraint(
            "length(sha256) = 64 AND sha256 ~ '^[0-9a-f]{64}$'", name="ck_capture_sha256_hex"
        ),
        CheckConstraint("size_bytes >= 0", name="ck_capture_size_nonneg"),
        Index("ix_captures_org_state", "organization_id", "state"),
        Index("ix_captures_org_uploaded", "organization_id", "uploaded_at"),
        Index("ix_captures_org_sha256", "organization_id", "sha256"),
        Index("ix_captures_retention", "retention_until"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    uploader_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    object_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    format: Mapped[CaptureFormat] = mapped_column(
        _enum(CaptureFormat, "capture_format"), nullable=False
    )
    state: Mapped[CaptureState] = mapped_column(
        _enum(CaptureState, "capture_state"), nullable=False, default=CaptureState.UNKNOWN
    )
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
        server_default=func.now(),
    )

    organization: Mapped[Organization] = relationship(back_populates="captures")

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.organization_id

    @property
    def uploaded_by(self) -> uuid.UUID | None:
        return self.uploader_id


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"
    __table_args__ = (
        CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 1)",
            name="ck_run_risk_score_range",
        ),
        CheckConstraint(
            "security_score IS NULL OR (security_score >= 0 AND security_score <= 1)",
            name="ck_run_security_score_range",
        ),
        CheckConstraint(
            "finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at",
            name="ck_run_time_order",
        ),
        Index("ix_runs_org_status", "organization_id", "status"),
        Index("ix_runs_org_created", "organization_id", "created_at"),
        Index("ix_runs_capture_created", "capture_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    capture_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("captures.id", ondelete="CASCADE"), nullable=False
    )
    requester_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[AnalysisStatus] = mapped_column(
        _enum(AnalysisStatus, "analysis_status"), nullable=False, default=AnalysisStatus.PENDING
    )
    pipeline_version: Mapped[str] = mapped_column(String(64), nullable=False)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    # Safe, coarse error code only (e.g. "malformed_capture"); never raw parser output.
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary: Mapped[dict[str, Any] | None] = mapped_column(JSONBType, nullable=True)
    evidence_coverage: Mapped[dict[str, Any] | None] = mapped_column(JSONBType, nullable=True)
    # Genuinely variable data -> JSONB. Scores stay typed/nullable: NULL means
    # "not available", which must never be rendered as a passing score.
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    security_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    queued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
        server_default=func.now(),
    )

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.organization_id


# Scaffold-stage alias.
AnalysisJob = AnalysisRun


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"
    __table_args__ = (
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_evidence_conf_range",
        ),
        CheckConstraint(
            "quality IS NULL OR (quality >= 0 AND quality <= 1)", name="ck_evidence_quality_range"
        ),
        Index("ix_evidence_org_fact", "organization_id", "fact_name"),
        Index("ix_evidence_run_fact", "analysis_id", "fact_name"),
        Index("ix_evidence_run_source", "analysis_id", "source"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False
    )
    fact_name: Mapped[str] = mapped_column(String(200), nullable=False)
    fact_value: Mapped[Any] = mapped_column(JSONBType, nullable=False)
    # Fact values are genuinely variable (str/int/list/dict) -> JSONB.
    source: Mapped[EvidenceSource] = mapped_column(
        _enum(EvidenceSource, "evidence_source"), nullable=False
    )
    visibility: Mapped[EvidenceVisibility] = mapped_column(
        _enum(EvidenceVisibility, "evidence_visibility"),
        nullable=False,
        default=EvidenceVisibility.UNKNOWN,
    )
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    quality: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_refs: Mapped[list[Any] | None] = mapped_column(JSONBType, nullable=True)
    # Optional [{"frame": 12, "packet": 12}, ...] references -> JSONB list.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.organization_id


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_finding_conf_range",
        ),
        Index("ix_findings_org_severity", "organization_id", "severity"),
        Index("ix_findings_run_rule", "analysis_id", "rule_id"),
        Index("ix_findings_org_status", "organization_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        _enum(FindingSeverity, "finding_severity"), nullable=False
    )
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    # List of EvidenceRecord UUIDs (as strings) backing this finding -> JSONB.
    evidence_refs: Mapped[list[Any] | None] = mapped_column(JSONBType, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[FindingStatus] = mapped_column(
        _enum(FindingStatus, "finding_status"), nullable=False, default=FindingStatus.OPEN
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
        server_default=func.now(),
    )

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.organization_id


class AuditEvent(Base):
    """Append-only audit trail. `event_hash` chains events per organization:
    sha256(previous_event_hash || canonical_payload). The canonical payload is
    stored so any third party can recompute the hash. Contains metadata only."""

    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("event_hash", name="uq_audit_event_hash"),
        CheckConstraint("length(event_hash) = 64", name="ck_audit_hash_len"),
        Index("ix_audit_org_time", "organization_id", "occurred_at"),
        Index("ix_audit_resource", "resource_type", "resource_id"),
        Index("ix_audit_actor_time", "actor_user_id", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # SET NULL: audit history survives tenant/user deletion (accountability).
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_label: Mapped[str | None] = mapped_column(
        String(200), nullable=True
    )  # e.g. "system", agent id
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    event_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSONBType, nullable=True)
    canonical_payload: Mapped[str] = mapped_column(Text, nullable=False)
    previous_event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    @property
    def tenant_id(self) -> uuid.UUID | None:
        return self.organization_id
