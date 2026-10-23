from fastapi import APIRouter, Response

from ipsec_analyzer.db.session import engine
from ipsec_analyzer.schemas.health import HealthResponse, ReadinessResponse
from ipsec_analyzer.services.health import database_ready

router = APIRouter(tags=["health"])


@router.get("/health/live", response_model=HealthResponse)
def live() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/health/ready", response_model=ReadinessResponse)
def ready(response: Response) -> ReadinessResponse:
    """Ready only if the database actually answers; otherwise 503 unavailable."""
    if not database_ready(engine):
        response.status_code = 503
        return ReadinessResponse(status="unavailable", database="unavailable")
    return ReadinessResponse(status="ready", database="ok")
