from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str  # "ok" for liveness


class ReadinessResponse(BaseModel):
    status: str  # "ready" only if dependencies answer, else "unavailable"
    database: str  # "ok" | "unavailable"
