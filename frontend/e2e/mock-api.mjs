// Deterministic mock FastAPI-compatible server for Playwright e2e.
// Implements only the documented OpenAPI surface the frontend consumes.
import http from "node:http";

const ORG = "22222222-2222-4222-8222-222222222222";
const captures = new Map();
const analyses = new Map();
const manifests = new Map();
let polls = new Map();

function json(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}
function problem(res, status, code) {
  json(res, status, { type: "about:blank", title: code, detail: code, status, code });
}
function roleOf(req) {
  const auth = req.headers.authorization ?? "";
  return auth.replace("Bearer test-token-", "");
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://mock");
  const path = url.pathname;
  const role = roleOf(req);

  if (path === "/api/v1/health/ready") return json(res, 200, { status: "ready" });
  if (path === "/api/v1/auth/login" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { email, password } = JSON.parse(body || "{}");
      if (password !== "correct-password") return problem(res, 401, "invalid credentials");
      const r = email.startsWith("admin@") ? "admin" : email.startsWith("analyst@") ? "analyst" : "viewer";
      json(res, 200, { access_token: `test-token-${r}`, token_type: "bearer", expires_in: 900 });
    });
    return;
  }
  if (path === "/api/v1/auth/me") {
    if (!["admin", "analyst", "viewer"].includes(role)) return problem(res, 401, "unauthorized");
    return json(res, 200, { id: "u1", organization_id: ORG, email: `${role}@example.test`, role });
  }
  if (path === "/api/v1/captures" && req.method === "GET") {
    const items = [...captures.values()];
    return json(res, 200, { items, total: items.length, limit: 50, offset: 0 });
  }
  if (path === "/api/v1/captures" && req.method === "POST") {
    // consume multipart roughly; honor the size declared by test header
    let size = 0;
    req.on("data", (c) => (size += c.length));
    req.on("end", () => {
      const id = `cap-${captures.size + 1}`;
      const capture = {
        id, organization_id: ORG, display_name: "journey.pcap",
        sha256: "b".repeat(64), size_bytes: Math.max(size, 24), format: "pcap",
        state: "available", uploaded_at: "2026-10-24T00:00:00Z",
      };
      captures.set(id, capture);
      json(res, 201, capture);
    });
    return;
  }
  const capMatch = path.match(/^\/api\/v1\/captures\/([^/]+)$/);
  if (capMatch && req.method === "GET") {
    const c = captures.get(capMatch[1]);
    return c ? json(res, 200, c) : problem(res, 404, "capture_not_found");
  }
  if (capMatch && req.method === "DELETE") {
    captures.delete(capMatch[1]);
    res.writeHead(204); return res.end();
  }
  const dlMatch = path.match(/^\/api\/v1\/captures\/([^/]+)\/download$/);
  if (dlMatch) {
    res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Disposition": 'attachment; filename="journey.pcap"' });
    return res.end("FAKE-PCAP");
  }
  const capAnalyses = path.match(/^\/api\/v1\/captures\/([^/]+)\/analyses$/);
  if (capAnalyses && req.method === "GET") {
    const items = [...analyses.values()].filter((a) => a.capture_id === capAnalyses[1]);
    return json(res, 200, { items, total: items.length, limit: 50, offset: 0 });
  }
  if (capAnalyses && req.method === "POST") {
    const id = `run-${analyses.size + 1}`;
    const run = {
      id, organization_id: ORG, capture_id: capAnalyses[1], status: "queued",
      pipeline_version: "tshark-parse-0.2", model_version: null, policy_version: "default-2026.1",
      attempts: 0, dispatch_attempts: 1, error_code: null, risk_score: null, security_score: null,
      queued_at: "2026-10-24T00:00:00Z", started_at: null, finished_at: null,
    };
    analyses.set(id, run); polls.set(id, 0);
    return json(res, 202, run);
  }
  const manifestMatch = path.match(/^\/api\/v1\/captures\/([^/]+)\/manifest$/);
  if (manifestMatch && req.method === "GET") {
    const m = manifests.get(manifestMatch[1]);
    return m
      ? json(res, 200, { capture_id: manifestMatch[1], source: "lab_manifest", schema_version: "1.0", uploaded_by: null, created_at: "2026-10-24T00:00:00Z", manifest: m })
      : problem(res, 404, "manifest not found");
  }
  if (manifestMatch && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const manifest = JSON.parse(body || "{}");
      if (JSON.stringify(manifest).toLowerCase().includes('"psk"')) return problem(res, 422, "secret key rejected");
      manifests.set(manifestMatch[1], manifest);
      json(res, 201, { capture_id: manifestMatch[1], source: "lab_manifest", schema_version: "1.0", uploaded_by: null, created_at: "2026-10-24T00:00:00Z", manifest });
    });
    return;
  }
  const analysisMatch = path.match(/^\/api\/v1\/analyses\/([^/]+)$/);
  if (analysisMatch && req.method === "GET") {
    const run = analyses.get(analysisMatch[1]);
    if (!run) return problem(res, 404, "analysis not found");
    const n = (polls.get(run.id) ?? 0) + 1;
    polls.set(run.id, n);
    if (run.status === "queued" && n >= 2) run.status = "running";
    // cap-2 journey = insufficient evidence: succeeded but null scores
    if (run.status === "running" && n >= 3) {
      run.status = "succeeded";
      if (run.capture_id !== "cap-poor") { run.risk_score = 15; run.security_score = 85; }
    }
    const succeeded = run.status === "succeeded";
    const poor = run.capture_id === "cap-poor";
    return json(res, 200, {
      ...run,
      packet_observed_facts: succeeded ? [
        { id: "ev-1", fact_name: "ike.version", fact_value: 2, source: "packet_observed", visibility: "visible", confidence: 1, quality: 1, packet_refs: [{ frame: 1 }], limitation: null },
        { id: "ev-2", fact_name: "ike_sa.selected_transforms", fact_value: "ENCR_AES_GCM_16 PRF_HMAC_SHA2_256 DH_19", source: "packet_observed", visibility: "visible", confidence: 1, quality: 1, packet_refs: [{ frame: 2 }], limitation: null },
      ] : [],
      supplied_facts: manifests.has(run.capture_id) ? [
        { id: "ev-9", fact_name: "lab.esp_config", fact_value: { encryption: "aes-cbc", aead: false }, source: "lab_manifest", visibility: "visible", confidence: 1, quality: null, packet_refs: [], limitation: null },
      ] : [],
      model_inferred_facts: [],
      unknown_facts: succeeded ? [
        { id: "ev-3", fact_name: "esp.encryption_algorithm", fact_value: null, source: "unknown", visibility: "encrypted_or_unavailable", confidence: null, quality: null, packet_refs: [], limitation: "ESP payloads are encrypted." },
      ] : [],
      findings: [],
      evidence_gaps: poor ? [
        { rule_id: "GAP-ESP-CIPHER-001", severity: "info", confidence: null, actual_value: null, expected_value: "ESP cipher", recommendation: "Attach a lab manifest.", evidence_refs: [], policy_version: "default-2026.1", source_refs: [], status: "gap" },
      ] : [
        { rule_id: "DISCREPANCY-ESP-001", severity: "medium", confidence: 1, actual_value: "aes-gcm (wire IKE)", expected_value: "aes-cbc (manifest ESP)", recommendation: "Reconcile lab configuration.", evidence_refs: ["ev-2"], policy_version: "default-2026.1", source_refs: [], status: "finding" },
      ],
      report_url: succeeded ? `/api/v1/analyses/${run.id}/report` : null,
    });
  }
  const reportMatch = path.match(/^\/api\/v1\/analyses\/([^/]+)\/report$/);
  if (reportMatch) {
    const format = url.searchParams.get("format") ?? "json";
    if (format === "pdf") {
      res.writeHead(200, { "Content-Type": "application/pdf", "Content-Disposition": 'attachment; filename="report.pdf"' });
      return res.end("%PDF-1.4 fixture");
    }
    return json(res, 200, { report_version: "1.0", executive_summary: { assessment_status: "assessed" } });
  }
  if (path === "/api/v1/admin/audit-events") {
    const items = Array.from({ length: 45 }, (_, i) => ({
      id: `evt-${i}`, timestamp: "2026-10-24T00:00:00Z", actor: "admin@example.test",
      action: "capture.uploaded", resource_type: "capture", resource_id: `cap-${i}`,
      event_hash: "a".repeat(64), previous_hash: i === 0 ? null : "b".repeat(64),
    }));
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? 20);
    return json(res, 200, { items: items.slice(offset, offset + limit), total: 45, limit, offset });
  }
  if (path === "/api/v1/admin/live-capture/allowlist") return problem(res, 404, "live capture disabled");
  return problem(res, 404, "not found");
});

// Seed an insufficient-evidence capture for journey 3
captures.set("cap-poor", {
  id: "cap-poor", organization_id: ORG, display_name: "poor.pcap",
  sha256: "c".repeat(64), size_bytes: 64, format: "pcap", state: "available",
  uploaded_at: "2026-10-24T00:00:00Z",
});

server.listen(8000, "127.0.0.1", () => console.log("mock api on 8000"));
