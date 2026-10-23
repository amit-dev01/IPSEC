# Deployment & Security Runbook (demo)

## Topology
`docker-compose.yml`: PostgreSQL, Redis, MinIO, one-shot migration job, API
(no TShark, read-only FS, non-root), worker (only image with TShark,
read-only FS, `/tmp` tmpfs 512 MB, all capabilities dropped, Celery
concurrency 2). Scale workers horizontally; PostgreSQL remains authoritative
for status — never trust the broker for state.

## Honest limitations of this demo
- Image digests are **not pinned**: this sandbox has no registry access, so
  digests could not be verified. Before any real deployment, pin every image
  as `name:tag@sha256:<digest>` obtained from the registry, and re-verify the
  TShark version inside the built worker image (`tshark --version` is recorded
  per-analysis).
- MinIO via `${MINIO_IMAGE:-minio/minio:latest}` is a floating default for the
  demo only.
- Compose secrets come from the environment; use a secrets manager in
  production. Terminate TLS at a reverse proxy; set upload size limits there
  as well as in the app (`IPSEC_MAX_UPLOAD_BYTES`).

## Security operations
- Auth: Argon2id passwords, JWT validated for issuer/audience/expiry/
  signature; organization always derives from the authenticated user.
- Storage: private S3 bucket, random tenant-scoped object keys, SHA-256
  verified on upload and again in the worker before parsing. Enable SSE and
  TLS to S3 in production (`IPSEC_S3_*` settings fail closed in production
  config); do not claim at-rest encryption unless actually configured.
- Audit: uploads, downloads, deletions, analysis creation, and report
  generation/download are audit-logged with actor/tenant/resource. If a hash
  chain is added later, canonical-data hashing makes it *tamper-evident*
  only — never "immutable"; keep payloads/secrets off-chain.
- Retention: delete captures via the API (object + row + audit event). Back
  up PostgreSQL (authoritative) and the bucket together; restore drill:
  restore PG, restore bucket, run `alembic upgrade head`, verify a report.

## Passive agent (optional, separate deployment)
The API never captures. `ipsec_analyzer.agent` runs only on authorized hosts:
admin-allowlisted opaque interface IDs/profiles, bounded duration (≤300 s)
and bytes, authenticated (mTLS preferred) upload through the normal ingestion
API, least-privilege capture process (CAP_NET_RAW only). Enable only with
documented authorization for the monitored network.

## Scoring honesty
Reports show risk (0–100), security (only when `assessed`), coverage, and
separate protocol/ML confidences. `insufficient_evidence` withholds scores —
a low score with poor coverage is never presented as "safe", and no report
makes certification/compliance claims.
