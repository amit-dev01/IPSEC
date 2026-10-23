# ADR-0003: S3-compatible storage for captures

## Context
Captures and report artifacts are large, opaque objects needing streaming upload,
lifecycle/deletion control, and local-dev parity without cloud lock-in.

## Decision
Private S3-compatible object storage (MinIO locally). Keys are generated server-side
as `tenants/{tenant_id}/captures/{capture_id}/{sanitized_filename}`; user input is
never a raw path/key. Buckets are private (no public ACLs), versioning supports
verified deletion. SHA-256 (computed at upload, re-verified by the worker) provides
integrity — captures are never placed on a blockchain.

## Consequences
+ Streaming, presignable, tenant-prefixed isolation; same code path locally (MinIO)
  and in production.
− Deletion must enumerate versions; storage credentials must be least-privilege and scoped.
