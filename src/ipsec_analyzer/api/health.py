from fastapi import APIRouter, Response
from sqlalchemy import text

from ipsec_analyzer.db.session import engine

router = APIRouter(tags=["health"])


@router.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready")
def ready(response: Response) -> dict[str, str]:
    """Report ready only if the database actually answers; otherwise 503 unavailable."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        response.status_code = 503
        return {"status": "unavailable", "database": "unavailable"}
    return {"status": "ready", "database": "ok"}
