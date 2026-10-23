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
