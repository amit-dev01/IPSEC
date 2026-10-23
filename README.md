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

## Capture ingestion

`POST /api/v1/captures` (multipart, `captures:write`) streams the upload to a
temp file in bounded chunks — computing SHA-256, enforcing
`IPSEC_MAX_UPLOAD_BYTES` while reading, and detecting PCAP/PCAPNG from magic
bytes (extension and client MIME type are ignored; the API never parses the
capture). Objects are stored first under random tenant-prefixed keys
(`tenants/{org}/captures/{id}/{random}` — the submitted filename is only a
sanitized display name and keys are never exposed to clients), then the
database row and a hash-chained `capture.uploaded` audit event commit together;
a failed commit deletes the object, and a failed storage write leaves no row.
Tenant-scoped `GET /api/v1/captures`, `GET /api/v1/captures/{id}`,
`GET /api/v1/captures/{id}/download` (audited, streamed), and
`DELETE /api/v1/captures/{id}` (object deleted, audited; tombstoned if storage
deletion fails) are provided. Captures are never parsed in the API process.

Storage is private S3-compatible storage behind an abstraction
(`storage/base.py`, `storage/s3.py`); MinIO is the development backend
(`docker compose up minio`, then create the `ipsec-captures` bucket, e.g.
`mc mb local/ipsec-captures`). TLS is on by default
(`IPSEC_S3_USE_TLS`); server-side encryption is requested only when
`IPSEC_S3_SSE_ALGORITHM` (`AES256` or `aws:kms`) is configured — the system
never claims encryption is enabled when it is not, and production refuses to
start without TLS + SSE configured.

### Reverse proxy (production guidance)
Set the proxy body limit slightly above `IPSEC_MAX_UPLOAD_BYTES` so oversized
uploads are rejected cheaply at the edge, and keep the application limit as the
authoritative check (the proxy limit alone is not sufficient):

```nginx
client_max_body_size 513m;        # app limit (512 MiB default) + multipart overhead
location /api/v1/captures {
    proxy_request_buffering off;  # stream uploads; do not buffer whole files
    proxy_pass http://ipsec-api;
}
```

## Worker parsing, evidence, manifests, and ML baseline

The Celery worker (the only image containing TShark — see `Dockerfile.worker`;
**the API never imports or runs TShark**, verified by an import-graph check)
downloads the capture to a private temp directory, verifies the downloaded
object's SHA-256 against the database record **before** parsing, then runs
TShark with a fixed executable and fixed arguments (`-n`, EK JSON lines, no
shell, no user-supplied options/filters/paths/environment), under configurable
time/packet-count/output-size/temp limits. Required TShark fields are
validated against the installed version (`tshark -G fields`); unsupported
fields fail explicitly (`parser_unsupported_field`), never silently zeroed.
Temp directories are removed on success and failure; only packet summaries
and aggregates are produced — payloads are never persisted or logged. Runs
record TShark version, parser version, truncation warnings, and limitations.

**Evidence** (`GET /api/v1/analyses/{id}/evidence`) gives every fact a name,
value, source (`packet_observed`/`lab_manifest`/`analyst_supplied`/
`model_inferred`/`unknown`), visibility (`visible`/`encrypted_or_unavailable`/
`derived`), confidence/quality, frame references, and limitations. Offered IKE
transforms are kept distinct from the responder-selected ones, IKE-SA
transforms distinct from Child-SA/ESP transforms, and the ESP cipher, PFS,
replay-window configuration, configured lifetimes, and tunnel/transport mode
are reported `unknown` unless genuinely observed or supplied — an observed
rekey interval is labelled derived and is *not* the configured lifetime. Outer
addresses in evidence are hashed unless `IPSEC_EVIDENCE_ALLOW_PLAIN_ADDRESSES`
is explicitly enabled.

**Lab manifests** (`POST/GET /api/v1/captures/{id}/manifest`, schema `1.0`) let
the authorized testbed declare ground truth (selected IKE config, mode,
IPv4/6, ESP/DH/PFS, lifetimes, replay, traffic category, lab-only application
label, testbed/run/capture IDs). The strict Pydantic schema structurally
rejects PSKs/private/session keys and any secret-named field. Manifests never
overwrite packet-observed facts; conflicts on the next run produce discrepancy
evidence plus a `MANIFEST_PACKET_DISCREPANCY` finding. Admins can export a
de-identified flow-feature dataset (`GET /api/v1/admin/exports/flow-dataset`).

**ML baseline** (local scikit-learn, no LLM, no external lookups): features are
flow metadata only (counts, length/IAT statistics, direction, bursts,
duration, byte rate, ESP/NAT-T ratios) — never payloads, raw IPs, domains, or
usernames. Train offline from the admin export with group-by-capture/run
splitting (no packet-level leakage):

```bash
uv run ipsec-ml train --dataset export.json --out model.joblib \
  --model-card model_card.json --model-version baseline-1.0
```

Point `IPSEC_ML_MODEL_PATH` at the administrator-built artifact; inference
returns `{status, predicted_category, calibrated confidence, model_version,
features_used, limitations}`, abstains to `unknown` below
`IPSEC_ML_ABSTAIN_THRESHOLD`, and returns `unavailable` when no valid model is
installed. Categories are broad (web/email/voice/video/messaging/ICMP/other);
**exact app/vendor predictions (e.g. "this is WhatsApp") are not supported by
default** — such labels exist only as lab ground truth for evaluation.

## Analysis jobs (Celery + Redis)

`POST /api/v1/captures/{id}/analyses` (`analyses:write`) stores an `AnalysisRun`
row first, then dispatches a Celery message containing **only the analysis ID**
— never PCAP data, secrets, or user options. It returns `202` promptly; the
worker does the (bounded) processing. PostgreSQL is the authoritative status
store (the Celery result backend is disabled). Lifecycle:
`queued → running → succeeded|failed`, with a documented retry path
`failed → queued` for transient error codes only (`storage_unavailable`,
`worker_timeout`, `broker_unavailable`, `dispatch_failed`) while attempts remain
(`IPSEC_ANALYSIS_MAX_ATTEMPTS`, default 3) via `POST /api/v1/analyses/{id}/retry`.
Invalid/unsupported captures fail terminally and are never retried. If the
broker is down at request time, the row stays `queued` with
`error_code=dispatch_failed` (never silently stuck): retry it via the endpoint,
or let the periodic `reconcile_queued_analyses` beat task redispatch stale
queued runs. Worker claim is atomic and processing is idempotent — duplicate
deliveries are no-ops and never duplicate evidence/findings. The current
pipeline stage (`verification-0.1`) verifies stored-capture size/SHA-256/magic
in the worker and records that as evidence; it produces no findings or scores.
Run a worker with: `uv run celery -A ipsec_analyzer.workers.celery_app:celery_app worker`
(concurrency `IPSEC_WORKER_CONCURRENCY`, default 2, prefetch 1).

## Authentication & authorization

Argon2id password hashing (pwdlib), short-lived HS256 JWT access tokens
(issuer/audience/expiry/signature validated; settings under `IPSEC_JWT_*` /
`IPSEC_AUTH_*` in `.env.example`). `POST /api/v1/auth/login` takes a JSON
email/password (not the OAuth2 password grant) and returns a bearer token.
There is **no public registration** — bootstrap via the admin CLI:

```bash
IPSEC_ADMIN_PASSWORD='use-a-long-random-password' \
  uv run ipsec-admin create-org-admin --organization "Acme" --email admin@example.com
uv run ipsec-admin create-user --organization-id <uuid> --email a@example.com --role analyst
```

Roles: `admin` (all), `analyst` (read/write captures & analyses, read/download
reports), `viewer` (read + report download). The organization is always derived
from the authenticated user; cross-tenant resource access returns 404. Login is
rate-limited per client IP + email (in-process limiter — a multi-instance
deployment must back it with Redis). Only `/api/v1/health/*` and explicitly
enabled development docs are unauthenticated.

## Persistence (PostgreSQL)

Models live in `src/ipsec_analyzer/models/` (Organization/User, Capture, AnalysisRun,
EvidenceRecord, Finding, AuditEvent); SQLAlchemy 2 + Psycopg 3, Alembic migrations in
`migrations/versions/` — deployment must use migrations, never `metadata.create_all()`.
PostgreSQL stores metadata only; PCAP bytes belong in object storage.

```bash
uv run alembic upgrade head     # apply migrations (IPSEC_DATABASE_URL)
uv run alembic check            # verify models match the migrated schema
# PostgreSQL-backed tests (skip automatically without the env var):
IPSEC_TEST_DATABASE_URL=postgresql+psycopg://ipsec:change-me-local-only@localhost:5432/ipsec_test \
  uv run pytest tests/test_persistence_pg.py tests/test_tenant_isolation.py
```

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
