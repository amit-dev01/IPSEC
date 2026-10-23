# Architecture Decision Records

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-separate-api-and-worker.md) | Separate API and packet-analysis worker | Accepted (design) |
| [0002](0002-postgresql-for-metadata.md) | PostgreSQL for metadata | Accepted (design) |
| [0003](0003-s3-compatible-storage-for-captures.md) | S3-compatible storage for captures | Accepted (design) |
| [0004](0004-redis-celery-for-jobs.md) | Redis/Celery for analysis jobs | Accepted (design) |
| [0005](0005-tshark-for-packet-decoding.md) | TShark for packet decoding (worker only) | Accepted (design) |
| [0006](0006-deterministic-parsing-plus-bounded-ml.md) | Deterministic parsing plus a bounded metadata ML classifier | Accepted (design) |

"Accepted (design)" means the decision governs upcoming implementation stages; per
`../architecture.md`, most capabilities are not yet implemented in the scaffold.
