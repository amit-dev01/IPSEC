import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class CaptureResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    display_name: str
    sha256: str
    size_bytes: int
    format: str
    state: str
    uploaded_at: datetime


class CaptureUpdate(BaseModel):
    display_name: str = Field(min_length=1, max_length=255)


class AnalysisResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    capture_id: uuid.UUID
    status: str  # queued | running | succeeded | failed | unavailable | cancelled
    pipeline_version: str
    model_version: str | None  # null: no model ran / not available
    policy_version: str
    attempts: int
    dispatch_attempts: int
    # Safe coarse error code only; never a stack trace, path, or parser output.
    error_code: str | None
    risk_score: float | None  # null = unavailable, never rendered as a pass
    security_score: float | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class EvidenceResponse(BaseModel):
    id: uuid.UUID
    fact_name: str
    fact_value: object  # JSON value; null means explicitly unknown
    source: str
    visibility: str
    confidence: float | None
    quality: float | None
    packet_refs: list | None
    limitation: str | None


class ManifestResponse(BaseModel):
    capture_id: uuid.UUID
    source: str
    schema_version: str
    uploaded_by: uuid.UUID | None
    created_at: datetime
    manifest: dict


class Page(BaseModel):
    items: list
    total: int
    limit: int
    offset: int


class CapturePage(Page):
    items: list[CaptureResponse]


class AnalysisPage(Page):
    items: list[AnalysisResponse]


class FindingResponse(BaseModel):
    rule_id: str
    severity: str
    confidence: float | None
    actual_value: object = None
    expected_value: object = None
    recommendation: str | None = None
    evidence_refs: list | None = None
    policy_version: str | None = None
    source_refs: list | None = None
    status: str


class AnalysisDetailResponse(AnalysisResponse):
    """Sections kept strictly separate: packet-observed facts are never merged
    with manifest/analyst-supplied facts or model inferences."""

    packet_observed_facts: list[EvidenceResponse] = []
    supplied_facts: list[EvidenceResponse] = []
    model_inferred_facts: list[EvidenceResponse] = []
    unknown_facts: list[EvidenceResponse] = []
    findings: list[FindingResponse] = []
    evidence_gaps: list[FindingResponse] = []
    report_url: str | None = None


class ProblemDetail(BaseModel):
    """RFC 9457-style Problem Details. Kept additive: ``detail`` mirrors
    ``title`` so existing clients keep working."""

    type: str = "about:blank"
    title: str
    detail: str
    status: int
    code: str | None = None
