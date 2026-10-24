# Frontend Architecture — IPsec Analyst Workbench

> Status: **specification (docs-only stage)**. No frontend application code
> exists yet. Every backend fact below was verified on 2026-10-24 against the
> FastAPI application (`create_app().openapi()`, title `IPsec Analyzer`,
> version `0.1.0`, 14 paths, 20 schemas) and the backend source. Where the
> backend does not provide something, this document says so instead of
> assuming it.

## 1. Placement and stack

The frontend lives in a new top-level **`frontend/`** directory. It must not
be placed inside the backend's Python `src/` tree (import collision and
tooling confusion), and the existing root `package.json` (Neon CLI tooling
only) is not the frontend manifest.

| Concern | Direction | Version rule |
|---|---|---|
| Runtime/tooling | Node.js current LTS, `pnpm` | Verify LTS + package versions from official registry metadata **at scaffold time**; no alpha/beta/RC. Commit `pnpm-lock.yaml`. |
| Framework | React + Vite, strict TypeScript | `strict: true`, `noUncheckedIndexedAccess: true` in `tsconfig`. Verify React/Vite major conventions at scaffold time — never mix major-version syntax. |
| API types | `openapi-typescript` + thin typed fetch wrapper | Generated from the FastAPI OpenAPI document (Section 4). No hand-written duplicate response interfaces. |
| Server state | TanStack Query | Polling and invalidation rules in Section 6. Verify major version at scaffold time. |
| Routing | Type-safe client routing with protected guards | One router library, chosen and verified at scaffold time; guards are UX only — the backend authorizes every request. |
| Styling/UI | Tailwind CSS + headless accessible primitives (e.g. Radix) owned in-repo | Verify Tailwind major version before writing any config (v3 vs v4 config syntax must not be mixed). |
| Tests | Vitest + Testing Library, MSW, Playwright | Section 9. |

Container images for the frontend, when introduced, must be pinned by exact
version/digest obtained from the registry — digests are never guessed.

## 2. Directory structure

```
frontend/
  openapi.json                # exported backend contract snapshot (Section 4)
  package.json  pnpm-lock.yaml  vite.config.ts  tsconfig.json
  src/
    app/                      # composition root only
      main.tsx                # mounts React, providers, router
      providers.tsx           # QueryClient, auth context, theme
      router.tsx              # route table + protected-route guards
      routes/                 # one file per route, lazy-loaded
        login.tsx
        captures.tsx          # capture list
        capture-detail.tsx    # one capture: analyses, manifest
        analysis-detail.tsx   # evidence, findings, scores, report actions
        admin.tsx             # org admin: dataset export (admin role only)
    api/
      generated/schema.d.ts   # openapi-typescript output — NEVER hand-edit
      client.ts               # thin typed fetch wrapper (auth header, errors)
      uploads.ts              # XHR-based multipart upload with progress
      downloads.ts            # authenticated blob downloads
    features/                 # feature modules own their queries/mutations
      auth/                   # login form, session context, logout
      captures/               # list/upload/rename/delete/download
      analyses/               # run analysis, polling, retry
      evidence/               # provenance-grouped evidence views
      findings/               # findings + evidence-gap lists
      reports/                # JSON/PDF report viewer + download
      manifest/               # lab-manifest attach/view form
      admin/                  # dataset export (ORG_ADMIN backend permission)
    components/               # shared, presentation-only
      ui/                     # in-repo primitives (button, dialog, table…)
      badges/                 # SourceBadge, VisibilityBadge, SeverityBadge,
                              # JobStatusBadge, ScoreBadge (docs/ux-epistemics.md)
      layout/                 # app shell, nav, tenant indicator
      feedback/               # problem-details alert, empty/loading states
    lib/
      format.ts               # hashes, SPIs, timestamps, bytes (mono/tabular)
      scores.ts               # null-score + assessment-status presentation rules
      files.ts                # magic-byte sniff via Blob.slice (pre-validation)
      sanitize.ts             # safe display-name / filename handling (text only)
    test/
      msw/                    # MSW handlers built from OpenAPI-shaped fixtures
      fixtures/               # deterministic API payloads (no real captures)
      setup.ts                # Testing Library + MSW server bootstrap
  e2e/                        # Playwright specs against MSW or a test backend
```

Rules: `features/*` may import from `api/`, `components/`, `lib/` — never
from another feature's internals. `components/` never imports `api/`.
`app/routes` compose features; they contain no fetch logic themselves.

## 3. Same-origin reverse-proxy topology

The browser only ever talks to **one origin**. All API traffic goes to the
relative path `/api/v1/...` and is proxied to FastAPI:

```
Browser ──► https://<app-origin>/            → static frontend (Vite build)
        └─► https://<app-origin>/api/v1/...  → reverse proxy → FastAPI
```

- **Development:** Vite dev-server proxy: `/api/v1` → `http://localhost:8000`
  (the backend's `/api/v1` prefix comes from `app.include_router(...,
  prefix="/api/v1")`). The proxy target is configuration, never hardcoded
  into feature code.
- **Production:** the same split at the hosting layer (e.g. static site +
  rewrite/proxy rule to the API service). The current Render demo serves
  only the API; adding the frontend there is a later deployment stage and
  must preserve this same-origin shape.
- **Why mandatory:** the backend currently configures **no CORS middleware**
  (verified in source). A cross-origin frontend would be blocked by the
  browser. Enabling CORS is a backend change and is out of scope unless a
  later stage explicitly approves it; the frontend must not be designed
  around direct cross-origin calls, public backend URLs, or `VITE_*`
  variables containing backend hosts or credentials.

## 4. OpenAPI synchronization workflow

Backend contract (verified 2026-10-24): `GET /openapi.json` when docs are
enabled (`title: IPsec Analyzer`, `version: 0.1.0`). Paths:

```
/api/v1/health/live            GET
/api/v1/health/ready           GET
/api/v1/auth/login             POST        /api/v1/auth/me            GET
/api/v1/captures               GET, POST   /api/v1/captures/{id}      GET, PATCH, DELETE
/api/v1/captures/{id}/download GET
/api/v1/captures/{id}/analyses GET, POST   /api/v1/captures/{id}/manifest GET, POST
/api/v1/analyses/{id}          GET         /api/v1/analyses/{id}/evidence GET
/api/v1/analyses/{id}/report   GET (?format=json|pdf)
/api/v1/analyses/{id}/retry    POST
/api/v1/admin/exports/flow-dataset GET     (admin only)
```

Workflow (automated in the frontend package scripts):

1. **Export:** start the backend (or reuse a running one) and save the
   document, e.g. `curl http://localhost:8000/openapi.json >
   frontend/openapi.json`. Committing the snapshot makes contract drift
   reviewable in PRs.
2. **Generate:** `openapi-typescript openapi.json -o
   src/api/generated/schema.d.ts`.
3. **Drift check (CI):** re-export + regenerate; fail the build if
   `git diff` shows changes to `openapi.json` or `schema.d.ts` that are not
   committed. A backend contract change must visibly regenerate frontend
   types in the same PR that consumes it.
4. **Consume:** `client.ts` wraps `openapi-fetch`-style typing (or an
   equivalent minimal wrapper) over the generated `paths` type. Feature code
   uses generated `components["schemas"]` types (`CaptureResponse`,
   `AnalysisDetailResponse`, `EvidenceResponse`, …) — duplicating these by
   hand is forbidden.
5. **Non-JSON responses** (capture download, PDF report) are not described
   by response schemas; they are handled by `downloads.ts` (Section 7) and
   typed manually at that single boundary.

Error contract the wrapper must normalize: FastAPI/Problem-Details bodies —
HTTP errors carry `{type, title, detail, status, code, instance}` (the
backend's exception handler keeps `detail` mirroring the stable machine
code, e.g. `report_not_ready`, `dispatch_failed`); validation failures are
HTTP 422 with FastAPI's `detail` array. The wrapper surfaces `{status, code,
detail}` to features; UI renders these as **plain text only**.

## 5. Authentication and token lifecycle

Verified backend facts: `POST /api/v1/auth/login` (JSON email/password,
optional `organization_id` disambiguator) returns
`{access_token, token_type: "bearer", expires_in}` (`expires_in` defaults
to 900 s; the backend setting `access_token_expire_minutes` defaults to
15). Login is rate-limited (HTTP 429 with `Retry-After`). `GET
/api/v1/auth/me` returns `{id, organization_id, email, role}` with roles
`admin | analyst | viewer`. **The backend has no refresh-token endpoint and
sets no cookies** — when the token expires, the user logs in again. The
frontend must not invent a refresh flow.

Rules:

- The bearer token is held **only in memory** (module-scoped session store
  + React context). Never `localStorage`, never `sessionStorage`, never a
  JS-readable cookie, never in a URL. A page reload ends the session by
  design (re-login); this is accepted and documented for the analyst
  workbench.
- `client.ts` attaches `Authorization: Bearer <token>` per request. On any
  **401**: clear the token, call `queryClient.clear()`, and route to
  `/login`. Logout does the same, in the same order (token first, then
  caches, then navigation).
- **Multi-tenant isolation:** the organization is taken *only* from
  `GET /auth/me` (the backend derives it from the authenticated user; the
  UI never sends a tenant ID to scope data). All TanStack Query keys are
  prefixed with the organization ID, e.g.
  `["org", orgId, "captures", {limit, offset}]`. Switching user/org
  without a reload is impossible without passing through logout/401 cache
  clearing — this is deliberate cache-isolation, not an optimization.
- Route guards check "token present + `/auth/me` loaded" and role for
  admin-only routes (`/admin` export requires the backend `ORG_ADMIN`
  permission). Guards are UX conveniences: every API call is independently
  authorized by the backend, and 403s are rendered as such, never hidden
  by pretending a resource does not exist (backend cross-tenant behaviour
  is 404, which the UI displays as "not found").

## 6. Polling strategy for analysis jobs

Verified state machine: statuses are `queued → running → succeeded |
failed`, plus `unavailable` and `cancelled` (`pending` is a legacy value
that is no longer emitted; the UI maps it to `queued` if ever seen).
`POST /captures/{id}/analyses` returns **202** with the run; `POST
/analyses/{id}/retry` re-dispatches only a `queued` run with
`error_code=dispatch_failed` or a `failed` run with a transient
`error_code` below the attempt cap, otherwise **409**.

- Poll the analysis detail (and any visible list rows) with TanStack
  Query `refetchInterval` driven by status: `queued` every 2 s, `running`
  every 3 s, backing off to at most 10 s after ~1 minute. Terminal states
  (`succeeded`, `failed`, `unavailable`, `cancelled`) stop polling
  (`refetchInterval: false`).
- `refetchIntervalInBackground: false` — no polling while the tab is
  hidden; TanStack's focus refetch gives fresh state on return.
- On transition to a terminal state: invalidate `["org", orgId,
  "captures", captureId, "analyses"]`, the capture's analysis list, and
  remove any cached report URL assumption — `report_url` is only present
  in `AnalysisDetailResponse` when the backend has set it (succeeded
  runs); the UI enables report actions from the *detail response*, not
  from status alone.
- Retry button visibility mirrors the backend rule above; a 409 from
  retry is shown as a Problem-Details alert, not swallowed.
- Only safe `error_code` strings are ever displayed (backend guarantees no
  stack traces/paths); raw `detail` text is rendered as text.

## 7. Secure binary handling

**Uploads (PCAP/PCAPNG):**

- Multipart `POST /api/v1/captures` with the file in the `file` form field
  (verified signature). Use `FormData`; do not set `Content-Type` manually.
- The browser **never parses the capture** and never reads it fully into
  memory. Optional pre-validation reads only the first bytes via
  `file.slice(0, 16)` to sniff magic numbers (classic PCAP
  `d4 c3 b2 a1`/`a1 b2 c3 d4`, PCAPNG `0a 0d 0d 0a`) and checks the
  extension/name for display. This is UX feedback only — the backend's
  magic-byte validation and SHA-256 are authoritative, and the UI labels
  it as such ("final validation happens on the server").
- Upload progress requires `XMLHttpRequest` (fetch has no upload
  progress); `uploads.ts` is the single XHR boundary, still attaching the
  in-memory bearer header. The SHA-256 shown after upload is the value
  returned by the backend (`CaptureResponse.sha256`), never a
  browser-computed digest presented as authoritative.
- No client-side size limit is presented as policy: the backend enforces
  the byte limit while streaming; server rejections surface as
  Problem-Details alerts. The UI may show the selected file's size (from
  `File.size`, no read) next to a "server enforces the upload limit" note.

**Downloads (captures, reports, exports):**

- Protected binaries are fetched with authenticated `fetch` (in-memory
  bearer header) and saved via `Blob` + temporary object URL, revoked
  immediately after the save dialog is triggered. **Tokens never appear
  in URLs** — no `?token=`, no signed-URL workarounds.
- Endpoints: `GET /captures/{id}/download` (streams the capture),
  `GET /analyses/{id}/report?format=json|pdf` (409 `report_not_ready`
  until the run has succeeded), `GET /admin/exports/flow-dataset`
  (admin-only JSON; contains flow features and lab labels, no PCAPs).
- Filenames come from `Content-Disposition` when present, sanitized
  through `lib/sanitize.ts` (strip path separators/control characters,
  length-cap) and rendered only as text. The backend never exposes
  storage keys or paths; the UI must never display `object_key`-like
  fields even if a future payload contained them (field allow-listing at
  the feature boundary).

## 8. Security and accessibility invariants (all stages)

- No `dangerouslySetInnerHTML` anywhere. Filenames, protocol strings,
  manifest fields, fact values, and error messages render through React
  text escaping; JSON fact values render via a structured JSON viewer
  that stringifies, never via HTML injection.
- Monospace font + `tabular-nums` for hashes, SPIs, IPs, scores, and table
  metrics. Severity/status/provenance are **never color-only**: every
  badge pairs color with an icon and a text label, with an accessible
  name (`aria-label`/visible text) — see `docs/ux-epistemics.md`.
- Keyboard-reachable controls, visible focus, WCAG-AA contrast for badge
  text (badges use dark text on tinted fills, verified per token).
- No placeholder/fabricated data in production code paths: loading,
  empty, and error states are rendered as such; MSW/Playwright fixtures
  live only under `src/test/` and `e2e/`.
- No PCAP is ever sent anywhere except the backend `/api/v1` origin; no
  third-party analytics/telemetry SDKs in the workbench.

## 9. Testing strategy (built up per stage)

- **Vitest + Testing Library:** components and feature hooks; badge
  presentation rules (null scores, provenance) are unit-tested against
  the matrices in `docs/ux-epistemics.md`.
- **MSW:** handlers return payloads shaped by the generated OpenAPI types
  (compile-time checked), including Problem-Details errors, 409 report,
  401 expiry, and every job status. MSW is dev/test-only infrastructure.
- **Playwright:** login → upload (small synthetic fixture) → queued →
  succeeded polling → evidence/report download, against MSW or a
  disposable backend. No real user captures in fixtures.
- **Type gate:** `tsc --noEmit` with the strict flags above plus a
  generated-types drift check (Section 4) in CI.
