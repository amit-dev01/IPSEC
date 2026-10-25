import { QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createQueryClient } from "@/app/query-client";
import Shell from "@/app/Shell";
import { ToastProvider } from "@/app/toast";
import { AuthProvider } from "@/features/auth/AuthProvider";
import { endSession, startSession } from "@/features/auth/auth-store";
import OverviewPage from "@/features/auth/OverviewPage";
import { RequireAuth } from "@/features/auth/guards";
import AnalysisDetailPage from "@/features/analyses/AnalysisDetailPage";
import DatasetPage from "@/features/dataset/DatasetPage";
import CapturesPage from "@/features/captures/CapturesPage";
import CaptureDetailPage from "@/features/captures/CaptureDetailPage";
import {
  resetFixtureState,
  seedAnalysis,
  seedCapture,
  seedManifest,
  setUploadSizeLimit,
} from "@/test/msw/handlers";
import { server } from "@/test/setup";

const ORG = "22222222-2222-4222-8222-222222222222";

function loginAs(role: "admin" | "analyst" | "viewer"): void {
  startSession(`test-token-${role}`, {
    id: "11111111-1111-4111-8111-111111111111",
    organization_id: ORG,
    email: `${role}@example.test`,
    role,
  });
}

function renderApp(initialEntries: string[], role: "admin" | "analyst" | "viewer"): void {
  loginAs(role);
  const queryClient = createQueryClient();
  const tree: ReactNode = (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={initialEntries}>
        <AuthProvider>
          <ToastProvider>
            <Routes>
              <Route
                path="/"
                element={
                  <RequireAuth>
                    <Shell />
                  </RequireAuth>
                }
              >
                <Route index element={<OverviewPage />} />
                <Route path="captures" element={<CapturesPage />} />
                <Route path="captures/:captureId" element={<CaptureDetailPage />} />
                <Route path="analyses/:analysisId" element={<AnalysisDetailPage />} />
                <Route path="dataset" element={<DatasetPage />} />
              </Route>
            </Routes>
          </ToastProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
  render(tree);
}

beforeEach(() => resetFixtureState());
afterEach(() => endSession());

describe("shell + overview", () => {
  it("shows role-dependent nav: dataset/admin links hidden for viewer", async () => {
    renderApp(["/"], "viewer");
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Dataset/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Admin/ })).not.toBeInTheDocument();
  });

  it("admin sees Dataset & Lab and Admin links", async () => {
    renderApp(["/"], "admin");
    expect(await screen.findByRole("link", { name: /Dataset & Lab/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Admin \/ Audit/ })).toBeInTheDocument();
  });

  it("empty workspace shows onboarding, not fabricated metrics", async () => {
    renderApp(["/"], "analyst");
    expect(await screen.findByText(/no captures yet/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Upload Capture" })).toBeInTheDocument();
  });

  it("shows a degraded-health banner when readiness fails", async () => {
    server.use(http.get("*/api/v1/health/ready", () => new HttpResponse(null, { status: 503 })));
    renderApp(["/"], "analyst");
    expect(await screen.findByRole("alert")).toHaveTextContent(/Backend degraded/);
  });

  it("overview counters come from real composed queries", async () => {
    seedCapture({ id: "cap-1" });
    seedAnalysis("cap-1", { id: "run-1", status: "succeeded", security_score: 80, risk_score: 20 });
    renderApp(["/"], "analyst");
    expect(await screen.findByText("Tenant captures")).toBeInTheDocument();
    expect(screen.getByText("Active / queued runs")).toBeInTheDocument();
  });
});

describe("capture vault", () => {
  it("viewer sees captures read-only: no upload or delete controls", async () => {
    seedCapture({ id: "cap-1", display_name: "site-a.pcap" });
    seedAnalysis("cap-1", { id: "run-1", status: "succeeded" });
    renderApp(["/captures"], "viewer");
    expect(await screen.findByText("site-a.pcap")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Upload Capture" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
    expect(screen.getByText(/Retention expiry is enforced server-side/)).toBeInTheDocument();
  });

  it("rejects a non-capture file before upload (magic check)", async () => {
    renderApp(["/captures"], "analyst");
    await userEvent.setup().click(await screen.findByRole("button", { name: "Upload Capture" }));
    const input = screen.getByLabelText("Choose a capture file");
    const bad = new File([new Uint8Array([0x25, 0x50, 0x44, 0x46, 1, 2, 3])], "evil.pcap");
    await userEvent.setup().upload(input, bad);
    expect(await screen.findByRole("alert")).toHaveTextContent(/Rejected before upload/);
    expect(screen.getByRole("button", { name: "Start upload" })).toBeDisabled();
  });

  it("keeps the modal open showing the authoritative server SHA-256 after upload", async () => {
    class OkXHR {
      upload: {
        onprogress:
          ((e: { loaded: number; total: number; lengthComputable: boolean }) => void) | null;
      } = { onprogress: null };
      onload: (() => void) | null = null;
      onabort: (() => void) | null = null;
      onerror: (() => void) | null = null;
      ontimeout: (() => void) | null = null;
      status = 201;
      responseText = JSON.stringify({
        id: "cap-up-1",
        organization_id: "org",
        display_name: "ok.pcapng",
        sha256: "c".repeat(64),
        size_bytes: 68,
        format: "pcapng",
        state: "available",
        uploaded_at: "2026-10-24T00:00:00Z",
      });
      responseType = "";
      timeout = 0;
      open(): void {
        return;
      }
      setRequestHeader(): void {
        return;
      }
      getResponseHeader(): string | null {
        return null;
      }
      abort(): void {
        this.onabort?.();
      }
      send(): void {
        window.setTimeout(() => this.onload?.(), 0);
      }
    }
    vi.stubGlobal("XMLHttpRequest", OkXHR);
    renderApp(["/captures"], "analyst");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Upload Capture" }));
    const head = new Uint8Array([0x0a, 0x0d, 0x0d, 0x0a, ...new Array(64).fill(0)]);
    await user.upload(
      screen.getByLabelText("Choose a capture file"),
      new File([head], "ok.pcapng"),
    );
    await user.click(screen.getByRole("button", { name: "Start upload" }));
    expect(await screen.findByText(/server-computed SHA-256/)).toBeInTheDocument();
    expect(screen.getByText("c".repeat(64))).toBeInTheDocument();
    // Modal stays open until the user dismisses it.
    await user.click(screen.getByRole("button", { name: "Done" }));
    expect(screen.queryByText(/server-computed SHA-256/)).not.toBeInTheDocument();
    vi.unstubAllGlobals();
  });

  it("reports progress and surfaces a server 413 for an oversized upload", async () => {
    setUploadSizeLimit(10);
    class FakeXHR {
      upload: {
        onprogress:
          ((e: { loaded: number; total: number; lengthComputable: boolean }) => void) | null;
      } = { onprogress: null };
      onload: (() => void) | null = null;
      onabort: (() => void) | null = null;
      onerror: (() => void) | null = null;
      ontimeout: (() => void) | null = null;
      status = 413;
      responseText = JSON.stringify({
        title: "too large",
        detail: "capture exceeds maximum size",
        status: 413,
      });
      responseType = "";
      timeout = 0;
      open(): void {
        return;
      }
      setRequestHeader(): void {
        return;
      }
      getResponseHeader(): string | null {
        return null;
      }
      abort(): void {
        this.onabort?.();
      }
      send(): void {
        this.upload.onprogress?.({ loaded: 5, total: 68, lengthComputable: true });
        window.setTimeout(() => this.onload?.(), 0);
      }
    }
    vi.stubGlobal("XMLHttpRequest", FakeXHR);
    renderApp(["/captures"], "analyst");
    await userEvent.setup().click(await screen.findByRole("button", { name: "Upload Capture" }));
    const input = screen.getByLabelText("Choose a capture file");
    const head = new Uint8Array([0x0a, 0x0d, 0x0d, 0x0a, ...new Array(64).fill(0)]);
    const big = new File([head], "big.pcapng");
    await userEvent.setup().upload(input, big);
    await userEvent.setup().click(screen.getByRole("button", { name: "Start upload" }));
    expect(
      await screen.findByText(/413|maximum upload size/, undefined, { timeout: 5_000 }),
    ).toBeInTheDocument();
  });
});

describe("analysis polling + inspector + traffic", () => {
  it("polls queued→running→succeeded and stops; inspector separates Child SA unknown", async () => {
    seedCapture({ id: "cap-1" });
    seedAnalysis("cap-1", { id: "run-9", status: "queued" });
    renderApp(["/analyses/run-9"], "analyst");
    expect(await screen.findByText(/Stage: queued/)).toBeInTheDocument();
    expect(
      await screen.findByLabelText("Status: succeeded", undefined, { timeout: 10_000 }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Risk score:/)).toBeInTheDocument();

    await userEvent
      .setup()
      .click(screen.getByRole("tab", { name: /Protocol & Security Inspector/ }));
    expect(
      await screen.findByText(/Visibility boundary/, undefined, { timeout: 5_000 }),
    ).toBeInTheDocument();
    expect(screen.getByText("Child SA / ESP — strictly separate from IKE SA")).toBeInTheDocument();
    expect(screen.getByText("IKE SA — offered vs selected (never conflated)")).toBeInTheDocument();
    expect(screen.getByText(/#1/)).toBeInTheDocument();

    await userEvent.setup().click(screen.getByRole("tab", { name: /AI Traffic Inference/ }));
    expect(await screen.findByText(/Methodological notice/)).toBeInTheDocument();
    expect(screen.getByText(/Predicted traffic category:/)).toBeInTheDocument();
    expect(screen.getByText(/calibrated probability/)).toBeInTheDocument();
    expect(screen.queryByText(/payload inspection guaranteed/i)).not.toBeInTheDocument();
  }, 15000);
});

describe("manifest + dataset", () => {
  it("blocks secret-like keys in the JSON editor", async () => {
    seedCapture({ id: "cap-1" });
    seedManifest("cap-1", { testbed_id: "lab-a" });
    renderApp(["/captures/cap-1"], "analyst");
    const editor = await screen.findByLabelText(/paste a validated lab manifest JSON/);
    await userEvent.setup().type(editor, '{{"testbed_id":"lab-a","psk":"hunter2"}');
    await userEvent.setup().click(screen.getByRole("button", { name: /Validate JSON & attach/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Secret-like keys are rejected/);
  });

  it("dataset page states de-identification and admin export", async () => {
    renderApp(["/dataset"], "admin");
    expect(await screen.findByRole("heading", { name: "Dataset & Lab" })).toBeInTheDocument();
    expect(screen.getByText(/Privacy notice/)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Download de-identified dataset/ }),
    ).toBeInTheDocument();
  });
});
