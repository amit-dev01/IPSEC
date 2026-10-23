# Threat Model — IPsec VPN Analysis Backend

Scope: the system described in `architecture.md` (upload-based MVP; optional passive
agent post-MVP). Method: assets → trust boundaries → threats (STRIDE-informed) →
mitigations → residual risk. This document describes **planned controls**; the current
codebase is a scaffold (health/config/models only) and does not yet implement upload,
auth, parsing, or reporting.

## Assets
- Capture files (PCAP/PCAPNG) — potentially sensitive network traffic of a tenant.
- Extracted metadata and reports (endpoints, SPIs, timing, observed proposals).
- Tenant/user accounts and authorization data; agent credentials (post-MVP).
- Service credentials (DB, object storage, Redis), signing/session secrets.
- Integrity of findings: a false "secure" result is a safety-relevant failure.

## Trust boundaries
1. Client/agent → API (internet-facing, fully untrusted input).
2. API → PostgreSQL / object storage / Redis (private data plane).
3. Redis → worker (job IDs cross into the component that parses untrusted bytes).
4. Worker → TShark process and temp filesystem (hostile-file parsing boundary).
5. Any component → logs/observability (data-leak boundary).

Attacker models: (a) unauthenticated internet attacker; (b) authenticated tenant user
attacking other tenants or the platform; (c) malicious or compromised capture file
(possibly crafted by a third party and uploaded in good faith); (d) compromised
worker; (e) malicious allowlisted agent or stolen agent credentials. A fully
compromised API host or cloud account is out of scope.

## Threats and mitigations

### T1. Malicious PCAP/PCAPNG files (parser exploitation, decompression bombs)
- **Risk**: crafted captures exploiting TShark/dissector bugs (RCE in the worker),
  malformed headers causing hangs/OOM, nested/oversized records exhausting disk.
- **Mitigations**: parsing only in the separate worker image (ADR-0001, ADR-0005),
  run as non-root with read-only root FS, isolated temp dir with size quota, CPU /
  memory / wall-clock limits (Celery soft+hard time limits), packet-count cap,
  SHA-256 verified before parsing, TShark invoked with a **fixed argument vector**
  built by the code (no user-supplied args/filters/paths/interfaces, no shell),
  TShark kept patched via image rebuilds, worker has no internet egress and scoped
  storage/DB credentials so a parser exploit lands in a low-privilege sandbox.
- **Residual**: a zero-day in TShark can still compromise the worker container; blast
  radius is limited per T5. Parser stderr is discarded/sanitized (may contain
  packet-derived bytes).

### T2. Tenant isolation failure (cross-tenant data access)
- **Risk**: user of tenant A reads/deletes tenant B's captures, findings, or reports
  (IDOR, missing filters, key guessing, error messages leaking existence).
- **Mitigations**: tenant resolved from the authenticated principal, never from
  request parameters; tenant predicate inside every query (e.g. capture lookup by
  `id AND tenant_id`) and every storage key (`tenants/{tenant_id}/…` generated
  server-side); cross-tenant access returns 404, not 403, to avoid existence leaks;
  presigned URLs (if used) are short-lived and minted only after the tenant check;
  DB unique/foreign-key constraints keep job→capture→tenant consistent; isolation
  covered by tests (a cross-tenant lookup regression test already exists in the scaffold).
- **Residual**: an authorization bug is still the highest-impact application risk;
  requires code review discipline and per-endpoint isolation tests as endpoints land.

### T3. Unauthorized capture access (unauthenticated / credential attacks)
- **Risk**: unauthenticated upload/download, credential stuffing, session theft,
  enumeration of capture IDs.
- **Mitigations**: authentication is a prerequisite stage for every non-health
  endpoint (no anonymous capture access); UUIDv4 identifiers (unguessable, but never
  treated as authorization); TLS everywhere; hashed credentials / standard password
  hashing and rate-limited login (when auth lands); short-lived sessions; agent
  ingestion requires allowlisted mTLS identity bound to one tenant (revocable).
- **Residual**: depends on the future auth stage; this design forbids shipping upload
  endpoints before it.

### T4. Upload denial of service
- **Risk**: huge files, slow-loris streaming, many concurrent uploads/jobs,
  packet-count bombs that pass the byte cap, queue flooding starving other tenants.
- **Mitigations**: streaming upload with a hard byte cap enforced *during* streaming
  (abort + cleanup, not after buffering), per-tenant rate/concurrency limits and
  quotas (planned), worker-side packet-count/time/disk caps with `limit_exceeded`
  failure, Celery prefetch=1 and per-tenant fairness to be enforced at enqueue,
  health/readiness isolation so analysis load cannot take down the API process,
  decompressed/temp size is bounded by the temp quota, not the compressed size alone.
- **Residual**: volumetric network DDoS is an infrastructure concern (LB/CDN), out of
  application scope; shared-worker fairness needs the planned per-tenant controls.

### T5. Worker compromise
- **Risk**: attacker-controlled capture achieves code execution in the worker
  (see T1), then attempts lateral movement, data theft, or result forgery.
- **Mitigations**: worker credentials are least-privilege and *scoped*: storage access
  via keys minted per job or a role that can only read/write tenant-prefixed keys for
  claimed jobs (design requirement for implementation), DB role limited to job/
  finding tables; worker re-checks job→capture→tenant consistency before fetching;
  no internet egress; no inbound ports; one job per isolated temp workspace, wiped
  after completion; findings written by the worker are treated as data, and any
  future integrity-sensitive step (report signing) stays outside the worker;
  suspicious worker behaviour is detectable via job audit metadata (IDs/timestamps only).
- **Residual**: a compromised worker can forge findings for jobs it processes until
  detected; mitigated (not eliminated) by deterministic, reproducible parsing —
  re-running a job on a clean worker must reproduce packet_observed facts.

### T6. Sensitive metadata exposure
- **Risk**: even "metadata-only" outputs leak (internal hostnames/IPs, SPIs, traffic
  timing, filenames, manifest contents); logs or error messages leak packet contents,
  IPs, or secrets; over-broad report sharing.
- **Mitigations**: database stores metadata only — never packet payloads; structured
  logs carry IDs and status codes, never packet contents, credentials, or personal
  data beyond operational necessity; error responses use a stable sanitized envelope;
  filenames are sanitized before storage and treated as sensitive (not echoed into
  public URLs); reports inherit tenant scoping (T2) and retention/deletion
  (architecture Section 10); `model_inferred` labels prevent metadata guesses from
  being read as facts.
- **Residual**: metadata is inherently revealing to anyone authorized for the tenant;
  tenants must treat reports as confidential. Redaction beyond this is a product decision.

### T7. Credentials and secrets
- **Risk**: secrets in git/images/logs, overly broad DB/storage roles, secret leakage
  via config errors or verbose errors; PSK/private-key material being offered to the
  system by users.
- **Mitigations**: secrets only from environment/secret-manager injection; safe
  `.env.example` with placeholders; production config **fails closed** on placeholder
  secrets (already implemented in the scaffold); least-privilege per-service roles;
  rotation via redeploy; the product **never accepts PSKs or private keys** — there is
  no upload field, decryption feature, or key-handling code path to abuse; TShark is
  invoked without key-log/decryption options.
- **Residual**: host/secret-manager compromise is out of scope; client-side secret
  hygiene remains the operator's duty.

### T8. Report access and result-integrity abuse
- **Risk**: report URLs shared/guessed beyond the tenant; tampered reports; findings
  presented as stronger than the evidence (e.g. an executive summary claiming
  "compliant" where Child-SA/PFS/lifetime data were `unknown`).
- **Mitigations**: reports are objects under the tenant prefix fetched only through
  tenant-checked endpoints (or short-lived presigned URLs minted after the check);
  every finding carries its evidence class and job provenance; report templates must
  render `unknown` explicitly and are forbidden from aggregating unknowns into a pass
  (architecture Section 7 rules); model output is labelled `model_inferred` with model
  version and confidence (ADR-0006); lab data uses `lab_manifest`, never merged
  silently with `packet_observed`.
- **Residual**: an authorized user can still export and overshare a report; that is a
  tenant governance issue, mitigated only by access logging metadata.

## Explicit non-goals / honest limits
- ESP contents are encrypted: this system cannot and does not identify inner
  applications, users, or content. Any such label can only be `model_inferred` from
  metadata (size/timing/endpoints) with stated confidence — or `unknown`.
- IKEv2 negotiation details inside encrypted messages, Child-SA settings, PFS, replay
  windows, and configured SA lifetimes may be unrecoverable from a passive capture;
  the system reports `unknown` rather than promising visibility.
- No claim of ML accuracy is made: the classifier is a bounded baseline whose
  precision/recall must be measured on labelled lab data before any reliance, and it
  never overrides deterministic evidence.
- The system does not protect a tenant from itself (authorized users seeing their own
  traffic metadata is the product's purpose).

## Prompt 0 invariants (carried through all stages)
Authorized captures only; no injection/probing/key-handling/decryption; no PCAP data
to external AI services; untrusted-file limits everywhere; no user-controlled shell/
TShark/filter/path input; no packet contents or secrets in logs; tenant authorization
on every DB and storage operation; SHA-256 integrity for captures; no blockchain for
PCAPs or sensitive metadata; unavailable evidence is `unknown`, never "secure".
