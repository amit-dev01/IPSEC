"""PostgreSQL-backed fixtures.

PG-specific behaviour (JSONB, check constraints, native DDL, indexes, FK actions)
cannot be verified on SQLite. Tests using `db` are skipped unless
IPSEC_TEST_DATABASE_URL points at a disposable PostgreSQL database, e.g.:

    IPSEC_TEST_DATABASE_URL=postgresql+psycopg://ipsec@/ipsec_test?host=/tmp&port=54329 \
        uv run pytest tests/test_persistence_pg.py

The fixture applies the real Alembic migrations (never metadata.create_all).
"""

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

_TABLES = "audit_events, findings, evidence_records, analysis_runs, captures, users, organizations"


@pytest.fixture(scope="session")
def pg_engine():
    url = os.environ.get("IPSEC_TEST_DATABASE_URL")
    if not url:
        pytest.skip("IPSEC_TEST_DATABASE_URL not set; skipping PostgreSQL tests")

    os.environ["IPSEC_DATABASE_URL"] = url
    from ipsec_analyzer.core.config import get_settings

    get_settings.cache_clear()

    from alembic import command
    from alembic.config import Config

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")

    engine = create_engine(url)
    yield engine
    engine.dispose()


@pytest.fixture()
def db(pg_engine):
    with pg_engine.begin() as conn:
        conn.execute(text(f"TRUNCATE {_TABLES} RESTART IDENTITY CASCADE"))
    with Session(pg_engine) as session:
        yield session
