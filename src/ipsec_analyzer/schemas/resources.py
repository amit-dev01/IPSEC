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
    status: str
    error_code: str | None
    risk_score: float | None  # null = unavailable, never rendered as a pass
    security_score: float | None
