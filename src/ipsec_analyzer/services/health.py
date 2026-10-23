"""Readiness checks. Blocking (sync SQLAlchemy) — call only from `def` handlers."""

import logging

from sqlalchemy import text
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)


def database_ready(engine: Engine) -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        logger.warning("readiness: database unavailable")
        return False
    return True
