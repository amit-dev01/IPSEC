import { http, HttpResponse } from "msw";

function problem(status: number, code: string, extra: Record<string, string> = {}): Response {
  return HttpResponse.json(
    { type: "about:blank", title: code, detail: code, status, code, instance: "/test" },
    { status, headers: extra },
  );
}

function roleForEmail(email: string): "admin" | "analyst" | "viewer" {
  if (email.startsWith("admin@")) return "admin";
  if (email.startsWith("analyst@")) return "analyst";
  return "viewer";
}

export const ORG_ID = "22222222-2222-4222-8222-222222222222";

export interface TestCapture {
  id: string;
  organization_id: string;
  display_name: string;
  sha256: string;
  size_bytes: number;
  format: string;
  state: string;
  uploaded_at: string;
}

export interface TestAnalysis {
  id: string;
  organization_id: string;
  capture_id: string;
  status: string;
  pipeline_version: string;
  model_version: string | null;
  policy_version: string;
  attempts: number;
  dispatch_attempts: number;
  error_code: string | null;
  risk_score: number | null;
  security_score: number | null;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
}

const capturesFixture: TestCapture[] = [];
const analysesByCapture = new Map<string, TestAnalysis[]>();
const manifests = new Map<string, Record<string, unknown>>();
const analysisPolls = new Map<string, number>();
const detailOverrides = new Map<string, Record<string, unknown>>();
let uploadSizeLimit = Number.MAX_SAFE_INTEGER;
let liveCaptureEnabled = false;

export function resetFixtureState(): void {
  capturesFixture.length = 0;
  analysesByCapture.clear();
  manifests.clear();
  analysisPolls.clear();
  detailOverrides.clear();
  uploadSizeLimit = Number.MAX_SAFE_INTEGER;
  liveCaptureEnabled = false;
}

export function setUploadSizeLimit(bytes: number): void {
  uploadSizeLimit = bytes;
}

export function setLiveCaptureEnabled(enabled: boolean): void {
  liveCaptureEnabled = enabled;
}

export function seedCapture(capture: Partial<TestCapture> & { id: string }): TestCapture {
  const full: TestCapture = {
    organization_id: ORG_ID,
    display_name: "lab.pcap",
    sha256: "a".repeat(64),
    size_bytes: 128,
    format: "pcap",
    state: "available",
    uploaded_at: "2026-10-24T00:00:00Z",
    ...capture,
  };
  capturesFixture.push(full);
  return full;
}

export function seedAnalysis(
  captureId: string,
  analysis: Partial<TestAnalysis> & { id: string },
): TestAnalysis {
  const full: TestAnalysis = {
    organization_id: ORG_ID,
    capture_id: captureId,
    status: "queued",
    pipeline_version: "tshark-parse-0.2",
    model_version: null,
    policy_version: "default-2026.1",
    attempts: 0,
    dispatch_attempts: 1,
    error_code: null,
    risk_score: null,
    security_score: null,
    queued_at: "2026-10-24T00:00:00Z",
    started_at: null,
    finished_at: null,
    ...analysis,
  };
  const list = analysesByCapture.get(captureId) ?? [];
  list.push(full);
  analysesByCapture.set(captureId, list);
  return full;
}

export function seedAnalysisDetail(analysisId: string, override: Record<string, unknown>): void {
  detailOverrides.set(analysisId, override);
}

export function seedManifest(captureId: string, manifest: Record<string, unknown>): void {
  manifests.set(captureId, manifest);
}

function findAnalysis(id: string): TestAnalysis | null {
  for (const list of analysesByCapture.values()) {
    const found = list.find((a) => a.id === id);
    if (found) return found;
  }
  return null;
}

function manifestResponse(captureId: string, manifest: Record<string, unknown>): Response {
  return HttpResponse.json({
    capture_id: captureId,
    source: "lab_manifest",
    schema_version: "1.0",
    uploaded_by: null,
    created_at: "2026-10-24T00:00:00Z",
    manifest,
  });
}

export const handlers = [
  http.get("*/api/v1/health/ready", () => HttpResponse.json({ status: "ready" })),

  http.post("/api/v1/auth/login", async ({ request }) => {
    const body = (await request.json()) as { email: string; password: string };
    if (body.email.startsWith("rate@")) {
      return problem(429, "too many login attempts", { "Retry-After": "300" });
    }
    if (body.password !== "correct-password") {
      return problem(401, "invalid credentials");
    }
    return HttpResponse.json({
      access_token: `test-token-${roleForEmail(body.email)}`,
      token_type: "bearer",
      expires_in: 900,
    });
  }),

  http.get("/api/v1/auth/me", ({ request }) => {
    const auth = request.headers.get("Authorization") ?? "";
    const role = auth.replace("Bearer test-token-", "");
    if (role !== "admin" && role !== "analyst" && role !== "viewer") {
      return problem(401, "invalid credentials");
    }
    return HttpResponse.json({
      id: "11111111-1111-4111-8111-111111111111",
      organization_id: ORG_ID,
      email: `${role}@example.test`,
      role,
    });
  }),

  http.get("/api/v1/captures", ({ request }) => {
    const url = new URL(request.url);
    const state = url.searchParams.get("state");
    const limit = Number(url.searchParams.get("limit") ?? 50);
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const filtered = state ? capturesFixture.filter((c) => c.state === state) : capturesFixture;
    return HttpResponse.json({
      items: filtered.slice(offset, offset + limit),
      total: filtered.length,
      limit,
      offset,
    });
  }),

  http.post("/api/v1/captures", async ({ request }) => {
    const form = await request.formData();
    const file = form.get("file");
    const size = file instanceof File ? file.size : 0;
    if (size > uploadSizeLimit) return problem(413, "capture exceeds maximum size");
    const capture = seedCapture({
      id: `capture-${Math.random().toString(36).slice(2, 8)}`,
      display_name: file instanceof File ? file.name : "upload.pcap",
      size_bytes: size,
    });
    return HttpResponse.json(capture, { status: 201 });
  }),

  http.get("/api/v1/captures/:captureId", ({ params }) => {
    const found = capturesFixture.find((c) => c.id === params["captureId"]);
    if (!found) return problem(404, "capture_not_found");
    return HttpResponse.json(found);
  }),

  http.delete("/api/v1/captures/:captureId", ({ params }) => {
    const idx = capturesFixture.findIndex((c) => c.id === params["captureId"]);
    if (idx >= 0) capturesFixture.splice(idx, 1);
    return new HttpResponse(null, { status: 204 });
  }),

  http.get("/api/v1/captures/:captureId/download", () =>
    HttpResponse.text("FAKE-PCAP-BYTES", {
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": 'attachment; filename="lab.pcap"',
      },
    }),
  ),

  http.get("*/api/v1/captures/:id/analyses", ({ params, request }) => {
    const url = new URL(request.url);
    const statusFilter = url.searchParams.get("status");
    let items = analysesByCapture.get(String(params.id)) ?? [];
    if (statusFilter) items = items.filter((a) => a.status === statusFilter);
    return HttpResponse.json({ items, total: items.length, limit: 50, offset: 0 });
  }),

  http.post("*/api/v1/captures/:id/analyses", ({ params }) => {
    const run = seedAnalysis(String(params.id), {
      id: `analysis-${Math.random().toString(36).slice(2, 8)}`,
    });
    return HttpResponse.json(run, { status: 202 });
  }),

  http.get("*/api/v1/captures/:id/manifest", ({ params }) => {
    const found = manifests.get(String(params.id));
    if (!found) return problem(404, "manifest not found");
    return manifestResponse(String(params.id), found);
  }),

  http.post("*/api/v1/captures/:id/manifest", async ({ params, request }) => {
    const manifest = (await request.json()) as Record<string, unknown>;
    const serialized = JSON.stringify(manifest).toLowerCase();
    if (
      serialized.includes('"psk"') ||
      serialized.includes("private_key") ||
      serialized.includes('"secret"')
    ) {
      return problem(422, "manifest contains secret-bearing key");
    }
    manifests.set(String(params.id), manifest);
    return manifestResponse(String(params.id), manifest);
  }),

  http.get("*/api/v1/analyses/:id", ({ params }) => {
    const run = findAnalysis(String(params.id));
    if (!run) return problem(404, "analysis not found");
    const polls = (analysisPolls.get(run.id) ?? 0) + 1;
    analysisPolls.set(run.id, polls);
    if (run.status === "queued" && polls >= 2) run.status = "running";
    if (run.status === "running" && polls >= 3) {
      run.status = "succeeded";
      run.risk_score = 20;
      run.security_score = 80;
    }
    const succeeded = run.status === "succeeded";
    const override = detailOverrides.get(run.id) ?? {};
    return HttpResponse.json({
      ...run,
      ...override,
      packet_observed_facts: succeeded
        ? [
            {
              id: "ev-1",
              fact_name: "ike.version",
              fact_value: 2,
              source: "packet_observed",
              visibility: "visible",
              confidence: 1,
              quality: 1,
              packet_refs: [{ frame: 1 }],
              limitation: null,
            },
          ]
        : [],
      supplied_facts: [],
      model_inferred_facts: succeeded
        ? [
            {
              id: "ev-3",
              fact_name: "ml.traffic_category",
              fact_value: {
                status: "available",
                predicted_category: "web",
                confidence: 0.87,
                model_version: "traffic-baseline/1",
                limitations: ["Metadata only; not payload inspection."],
              },
              source: "model_inferred",
              visibility: "derived",
              confidence: 0.87,
              quality: null,
              packet_refs: [],
              limitation: null,
            },
          ]
        : [],
      unknown_facts: succeeded
        ? [
            {
              id: "ev-2",
              fact_name: "esp.encryption_algorithm",
              fact_value: null,
              source: "unknown",
              visibility: "encrypted_or_unavailable",
              confidence: null,
              quality: null,
              packet_refs: [],
              limitation: "ESP payloads are encrypted.",
            },
          ]
        : [],
      findings: (override["findings"] as unknown[]) ?? [],
      evidence_gaps: (override["evidence_gaps"] as unknown[]) ?? [],
      report_url: null,
    });
  }),

  http.post("*/api/v1/analyses/:id/retry", ({ params }) => {
    const run = findAnalysis(String(params.id));
    if (!run) return problem(404, "analysis not found");
    analysisPolls.set(run.id, 0);
    run.status = "queued";
    run.error_code = null;
    return HttpResponse.json(run);
  }),

  http.get("*/api/v1/analyses/:id/report", ({ request }) => {
    const format = new URL(request.url).searchParams.get("format") ?? "json";
    if (format === "pdf") {
      return HttpResponse.text("%PDF-1.4 fake-fixture", {
        headers: { "Content-Type": "application/pdf" },
      });
    }
    return HttpResponse.json({
      report_version: "1.0",
      executive_summary: { assessment_status: "assessed" },
    });
  }),

  http.get("*/api/v1/admin/audit-events", ({ request }) => {
    const url = new URL(request.url);
    const limit = Number(url.searchParams.get("limit") ?? 20);
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const all = Array.from({ length: 45 }, (_, i) => ({
      id: `evt-${i + 1}`,
      timestamp: "2026-10-24T00:00:00Z",
      actor: "admin@example.test",
      action: i % 2 === 0 ? "capture.uploaded" : "analysis.created",
      resource_type: "capture",
      resource_id: `cap-${i + 1}`,
      event_hash: `${String(i).padStart(4, "0")}${"a".repeat(60)}`,
      previous_hash: i === 0 ? null : `${String(i - 1).padStart(4, "0")}${"a".repeat(60)}`,
    }));
    const action = url.searchParams.get("action");
    const filtered = action ? all.filter((e) => e.action === action) : all;
    return HttpResponse.json({
      items: filtered.slice(offset, offset + limit),
      total: filtered.length,
      limit,
      offset,
    });
  }),

  http.get("*/api/v1/admin/live-capture/allowlist", () =>
    liveCaptureEnabled
      ? HttpResponse.json({
          agents: [{ id: "agent-lab-1", label: "Lab agent 1" }],
          interfaces: [{ id: "if-eth0", label: "eth0 (allowlisted)" }],
          profiles: [{ id: "metadata-only", label: "Metadata only" }],
          duration_options_seconds: [30, 60],
          max_bytes_options: [10_000_000],
        })
      : problem(404, "live capture disabled"),
  ),

  http.post("*/api/v1/admin/live-capture/trigger", async ({ request }) => {
    const body = (await request.json()) as Record<string, unknown>;
    if (typeof body["interface_id"] !== "string" || body["interface_id"] === "") {
      return problem(422, "interface must be allowlisted");
    }
    return HttpResponse.json(
      { capture_id: "cap-live-1", analysis_id: "run-live-1", status: "queued" },
      { status: 202 },
    );
  }),

  http.get("*/api/v1/admin/exports/flow-dataset", () =>
    HttpResponse.text('{"deidentified":true}\n'),
  ),
];
