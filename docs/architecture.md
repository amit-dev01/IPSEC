# Architecture (scaffold stage)

Defensive IPsec capture analyzer for **authorized captures only**. Out of scope by
design: packet injection, active probing, key recovery/decryption, PSK/private-key
handling, and sending PCAPs to any external AI service. No packet processing,
authentication, or analysis results exist at this stage.

## Package layout (`src/ipsec_analyzer/`)
| Module | Responsibility |
|---|---|
| `api/` | FastAPI routers, versioned under `/api/v1` (`api/v1/`). Sync `def` handlers for blocking DB/storage work. |
| `core/` | Configuration (`pydantic-settings`), structured logging, integrity helpers (SHA-256). |
| `db/` | SQLAlchemy 2 engine/session (`db/session.py`), declarative `Base`, tenant-scoped repositories. |
| `models/` | ORM models (tenants, users, captures, analysis jobs). |
| `schemas/` | Pydantic v2 request/response schemas. |
| `services/` | Application services used by routes (e.g. health/readiness checks). |
| `storage/` | Private S3-compatible object storage (MinIO locally); tenant-prefixed keys. |
| `workers/` | Celery app (Redis broker). TShark belongs only to the worker image, in a later stage. |
| `tasks/` | Backwards-compatible re-export of `workers/` Celery app. |
| `pipeline/` | Boundary for the future analysis pipeline. **Not implemented**: no packet parsing or findings. |
| `evidence/`, `parsing/`, `ml/`, `assessment/`, `reporting/` | Future-stage boundaries; unavailable evidence stays `unknown`/`insufficient_evidence`, never "secure". |

Tests live in the top-level `tests/` directory (not shipped in the wheel).

## Runtime
- `create_app()` in `ipsec_analyzer.main` builds the app; the lifespan handler
  configures logging at startup and disposes the DB engine at shutdown.
- Configuration comes from environment variables (`IPSEC_` prefix, see
  `.env.example`); secrets are read only from the environment / a secret manager
  injected via the environment — never committed.
- `GET /api/v1/health/live` is process liveness. `GET /api/v1/health/ready`
  reports `ready` only when PostgreSQL answers; otherwise `503 unavailable`.

## Local commands
```bash
uv sync --frozen --group dev          # install from uv.lock
uv run uvicorn ipsec_analyzer.main:app --host 0.0.0.0 --port 8000
uv run pytest -q
uv run ruff check src tests
uv run ruff format --check src tests
```
