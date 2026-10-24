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

export const handlers = [
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
      organization_id: "22222222-2222-4222-8222-222222222222",
      email: `${role}@example.test`,
      role,
    });
  }),

  http.get("/api/v1/captures", () =>
    HttpResponse.json({ items: [], total: 0, limit: 50, offset: 0 }),
  ),

  http.get("/api/v1/captures/:captureId", ({ params }) => {
    if (params["captureId"] === "missing") return problem(404, "capture_not_found");
    return HttpResponse.json({
      id: params["captureId"],
      organization_id: "22222222-2222-4222-8222-222222222222",
      display_name: "lab.pcap",
      sha256: "a".repeat(64),
      size_bytes: 128,
      format: "pcap",
      state: "uploaded",
      uploaded_at: "2026-10-24T00:00:00Z",
    });
  }),

  http.get("/api/v1/captures/:captureId/download", () =>
    HttpResponse.text("FAKE-PCAP-BYTES", {
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": 'attachment; filename="lab.pcap"',
      },
    }),
  ),

  http.post("/api/v1/captures/:captureId/analyses", ({ params }) =>
    HttpResponse.json(
      {
        id: "33333333-3333-4333-8333-333333333333",
        organization_id: "22222222-2222-4222-8222-222222222222",
        capture_id: params["captureId"],
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
      },
      { status: 202 },
    ),
  ),
];
