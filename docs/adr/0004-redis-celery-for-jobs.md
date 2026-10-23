# ADR-0004: Redis/Celery for analysis jobs

## Context
Analysis is long-running (large captures, parser timeouts up to the configured cap)
and must not block HTTP requests. Jobs need enqueueing, status tracking, hard time
limits, and a lifecycle including explicit `unavailable` (never fake success).

## Decision
Celery with a Redis broker/result backend. Messages carry **job IDs only** — no file
paths, filters, commands, or packet data. Celery soft/hard time limits mirror the
settings caps; workers use prefetch=1. PostgreSQL remains the source of truth for job
status; Redis is transport, not record.

## Consequences
+ Mature task lifecycle, retries-as-new-jobs, and worker isolation; small messages
  limit broker data exposure (credentials still required: authenticated, private Redis).
− Redis is another service to secure and monitor; per-tenant fairness needs explicit
  enqueue controls in a later stage (threat model T4).
