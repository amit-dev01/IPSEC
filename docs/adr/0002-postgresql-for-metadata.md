# ADR-0002: PostgreSQL for metadata

## Context
The system needs transactional, tenant-scoped metadata: tenants, users, captures,
jobs, findings, reports. Capture bytes are large blobs unsuited to a relational DB.

## Decision
PostgreSQL via SQLAlchemy 2 (sync) with Psycopg 3 stores **metadata only** — never
PCAP bytes, packet payloads, secrets, or keys. Tenant predicates are part of every
query; Alembic manages migrations. Blocking DB work runs in sync `def` handlers.

## Consequences
+ Strong relational integrity for tenant/job/capture relationships; mature
  backup/retention tooling supports the deletion flow (architecture §10).
+ Readiness can be honestly reported (health endpoint checks a real `SELECT 1`).
− Binary/blob handling, streaming, and lifecycle policies move to object storage (ADR-0003).
