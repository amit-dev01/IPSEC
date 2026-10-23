# IPSEC — IPsec Analyzer

Defensive analysis of captures **supplied by authorized users** (or an explicitly
allowlisted passive agent). It does not inject packets, probe targets, recover keys,
decrypt traffic, or handle PSKs/private keys. PCAPs are never sent to any external
LLM/third-party AI service.

See [`docs/architecture.md`](docs/architecture.md) for the full scaffold description.

## Status: scaffold stage

Implemented: the FastAPI project scaffold only — app factory with lifespan handling,
pydantic-settings configuration, structured JSON logging, SQLAlchemy 2 models,
tenant-scoped capture lookup, tenant-isolated S3 object keys, streaming SHA-256,
Celery worker configuration, and `/api/v1/health/live` + `/api/v1/health/ready`
(ready only when PostgreSQL actually answers, otherwise 503 `unavailable`).

**Not implemented yet** (later stages, on request): packet processing, authentication,
capture upload, TShark parsing, evidence extraction, ML classification, assessment
rules, reporting. Absent capabilities surface as explicit `unknown`/`unavailable`,
never as fabricated findings or a "secure" result.

## Local development

Prerequisite: [`uv`](https://docs.astral.sh/uv/).

```bash
cp .env.example .env        # local-only placeholder values; never commit real secrets
uv sync --frozen --group dev   # install exactly from uv.lock
uv run uvicorn ipsec_analyzer.main:app --host 0.0.0.0 --port 8000
curl http://localhost:8000/api/v1/health/live
uv run pytest -q
uv run ruff check src tests
uv run ruff format --check src tests
```

Secrets are read only from environment variables (or a secret manager that injects
them into the environment). `.env.example` contains placeholder values only.

## Version / pinning notes
Dependencies were resolved against PyPI and pinned in `uv.lock` (FastAPI 0.161.1,
SQLAlchemy 2.1.6, Pydantic 2.14.1, Celery 5.6.3, Psycopg 3.3.6, scikit-learn 1.9.1 —
see `uv.lock`). Development used the sandbox's Python 3.11.2; Python 3.13 could not
be downloaded there (TLS failure to GitHub), so containers targeting 3.13 are not yet
locally verified. Container/Compose images are pinned by version tag only; digests
could not be verified (no Docker/registry access in the sandbox) and must be
digest-pinned before production.
