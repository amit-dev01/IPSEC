# IPSEC — IPsec Analyzer

Defensive analysis of captures **supplied by authorized users** (or an explicitly
allowlisted passive agent). It does not inject packets, probe targets, recover keys,
decrypt traffic, or handle PSKs/private keys. PCAPs are never sent to any external
LLM/third-party AI service.

## Status: Stage 1 — foundation only

Implemented: project scaffold (`src/ipsec_analyzer/`), settings with fail-closed
production checks, SQLAlchemy 2 models (tenants/users/captures/analysis_jobs),
tenant-scoped capture lookup, tenant-isolated S3 object keys, streaming SHA-256,
Celery app configuration (no analysis tasks yet), `/health/live` and `/health/ready`
(ready only when PostgreSQL actually answers, otherwise 503 `unavailable`).

Not implemented yet (later stages, on request): authentication, capture upload,
TShark parsing, protocol evidence extraction, ML classification, assessment rules,
reporting. Absent capabilities surface as explicit `unknown`/`unavailable`, never
as fabricated findings or a "secure" result.

## Layout
- `api/` FastAPI routes (sync `def` handlers for blocking DB/storage work)
- `db/` SQLAlchemy 2 + Psycopg 3 models/session/repository
- `storage/` private S3-compatible storage (MinIO locally), tenant-prefixed keys
- `tasks/` Celery app (Redis broker); TShark exists only in `Dockerfile.worker`
- `parsing/`, `evidence/`, `ml/`, `assessment/`, `reporting/` module boundaries

## Develop
```bash
uv sync --group dev
uv run pytest -q
uv run ruff check src tests
uv run uvicorn ipsec_analyzer.main:app --reload
```

## Version / pinning notes
Dependencies were resolved and pinned in `uv.lock` against PyPI on 2026-10-23
(FastAPI 0.161.1, SQLAlchemy 2.1.6, Pydantic 2.14.1, Celery 5.6.3, Psycopg 3.3.6,
scikit-learn 1.9.1 — see `uv.lock`). Development used the sandbox's Python 3.11.2;
Python 3.13 could not be downloaded there (TLS failure to GitHub), so 3.13 is the
container target but is **not yet verified locally**. Container images and Compose
services are pinned by version tag only; **digests could not be verified** (no
Docker/registry access in the sandbox) and must be digest-pinned before production.
