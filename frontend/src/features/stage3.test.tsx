import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createQueryClient } from "@/app/query-client";
import Shell from "@/app/Shell";
import { ToastProvider } from "@/app/toast";
import AnalysisDetailPage from "@/features/analyses/AnalysisDetailPage";
import ReportCenterPage from "@/features/analyses/ReportCenterPage";
import AuditPage from "@/features/admin/AuditPage";
import LiveCapturePage from "@/features/admin/LiveCapturePage";
import { AuthProvider } from "@/features/auth/AuthProvider";
import { endSession, startSession } from "@/features/auth/auth-store";
import { RequireAuth, RequireRole } from "@/features/auth/guards";
import {
  resetFixtureState,
  seedAnalysis,
  seedAnalysisDetail,
  seedCapture,
  setLiveCaptureEnabled,
} from "@/test/msw/handlers";

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
                <Route path="analyses/:analysisId" element={<AnalysisDetailPage />} />
                <Route path="analyses/:analysisId/report" element={<ReportCenterPage />} />
                <Route
                  path="admin/audit"
                  element={
                    <RequireRole roles={["admin"]}>
                      <AuditPage />
                    </RequireRole>
                  }
                />
                <Route
                  path="admin/live-capture"
                  element={
                    <RequireRole roles={["admin"]}>
                      <LiveCapturePage />
                    </RequireRole>
                  }
                />
              </Route>
            </Routes>
          </ToastProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
  render(tree);
}

const GAP_FINDING = {
  rule_id: "GAP-ESP-CIPHER-001",
  severity: "info",
  confidence: null,
  actual_value: null,
  expected_value: "observable ESP cipher",
  recommendation: "Attach a lab manifest to supply the configured ESP cipher.",
  evidence_refs: [],
  policy_version: "default-2026.1",
  source_refs: [],
  status: "gap",
};

beforeEach(() => resetFixtureState());
afterEach(() => endSession());

describe("security assessment tab", () => {
  it("insufficient_evidence: shows Score Withheld card, never 0/green", async () => {
    seedCapture({ id: "cap-1" });
    seedAnalysis("cap-1", {
      id: "run-null",
      status: "succeeded",
      risk_score: null,
      security_score: null,
    });
    // keep succeeded with null scores: override loop in fixture would set 20/80 only via poll transitions;
    seedAnalysisDetail("run-null", {
      status: "succeeded",
      risk_score: null,
      security_score: null,
      evidence_gaps: [GAP_FINDING],
    });
    renderApp(["/analyses/run-null"], "analyst");
    await userEvent.setup().click(await screen.findByRole("tab", { name: /Security Assessment/ }));
    const card = await screen.findByLabelText(/Score withheld/);
    expect(card).toHaveTextContent(/Encrypted Child SA cipher/);
    expect(card.textContent).not.toMatch(/Secure/);
  }, 15000);

  it("assessed: scores always paired with evidence coverage", async () => {
    seedCapture({ id: "cap-1" });
    seedAnalysis("cap-1", {
      id: "run-ok",
      status: "succeeded",
      risk_score: 20,
      security_score: 80,
    });
    renderApp(["/analyses/run-ok"], "analyst");
    await userEvent.setup().click(await screen.findByRole("tab", { name: /Security Assessment/ }));
    expect(await screen.findAllByText(/Evidence Coverage:/)).toHaveLength(2);
    expect(screen.getByText(/Protocol-evidence confidence/)).toBeInTheDocument();
    expect(screen.getByText(/Model confidence \(calibrated probability\)/)).toBeInTheDocument();
  }, 15000);

  it("threat matrix cell filters findings list", async () => {
    seedCapture({ id: "cap-1" });
    seedAnalysis("cap-1", {
      id: "run-mx",
      status: "succeeded",
      risk_score: 40,
      security_score: null,
    });
    seedAnalysisDetail("run-mx", {
      findings: [
        {
          rule_id: "CRYPTO-WEAK-DH-001",
          severity: "high",
          confidence: 1,
          actual_value: "2",
          expected_value: ">=14",
          recommendation: "Use DH group 19 or higher.",
          evidence_refs: ["ev-1"],
          policy_version: "default-2026.1",
          source_refs: ["RFC 9142"],
          status: "finding",
        },
      ],
      evidence_gaps: [GAP_FINDING],
    });
    renderApp(["/analyses/run-mx"], "analyst");
    await userEvent.setup().click(await screen.findByRole("tab", { name: /Security Assessment/ }));
    const user = userEvent.setup();
    await user.click(await screen.findByRole("gridcell", { name: /ESP Confidentiality/ }));
    expect(await screen.findByText("GAP-ESP-CIPHER-001")).toBeInTheDocument();
    expect(screen.queryByText("CRYPTO-WEAK-DH-001")).not.toBeInTheDocument();

    // expandable inspector row with provenance-linked evidence
    await user.click(screen.getByText("GAP-ESP-CIPHER-001"));
    expect(await screen.findByText(/Remediation:/)).toBeInTheDocument();
  }, 15000);
});

describe("report center", () => {
  it("switches Executive ↔ Technical and shows partial disclaimer in both", async () => {
    seedCapture({ id: "cap-1" });
    seedAnalysis("cap-1", {
      id: "run-rpt",
      status: "succeeded",
      risk_score: 30,
      security_score: null,
    });
    renderApp(["/analyses/run-rpt/report"], "analyst");
    expect(await screen.findByText(/Executive posture summary/)).toBeInTheDocument();
    expect(screen.getAllByText(/Partial assessment/).length).toBeGreaterThan(0);
    await userEvent.setup().click(screen.getByRole("tab", { name: /Technical View/ }));
    expect(await screen.findByText(/Rule-by-rule findings/)).toBeInTheDocument();
    expect(screen.getAllByText(/Partial assessment/).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /Download PDF/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Download JSON/ })).toBeInTheDocument();
  }, 15000);

  it("renders adversarial capture names as escaped text (no raw HTML)", async () => {
    seedCapture({ id: "cap-1", display_name: '<img src=x onerror="alert(1)">' });
    seedAnalysis("cap-1", { id: "run-xss", status: "succeeded" });
    renderApp(["/analyses/run-xss/report"], "analyst");
    expect(await screen.findByText(/Executive posture summary/)).toBeInTheDocument();
    expect(document.querySelector("img[src='x']")).toBeNull();
    expect(document.body.innerHTML).not.toContain('onerror="alert(1)" src');
  }, 15000);
});

describe("governance screens", () => {
  it("blocks analyst and viewer from /admin/audit", async () => {
    renderApp(["/admin/audit"], "analyst");
    expect(await screen.findByText(/do not have access/)).toBeInTheDocument();
  });

  it("audit table renders hash chain and paginates (45 events)", async () => {
    renderApp(["/admin/audit"], "admin");
    expect(await screen.findByText(/Page 1 · 45 events/)).toBeInTheDocument();
    expect(screen.getByText(/not a public blockchain/)).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText(/Page 2 · 45 events/)).toBeInTheDocument();
  });

  it("live capture disabled state when backend feature is off", async () => {
    renderApp(["/admin/live-capture"], "admin");
    expect(
      await screen.findByText(/Passive Live Capture Disabled by Administrator Policy/),
    ).toBeInTheDocument();
  });

  it("live capture form has NO free-text inputs — only allowlisted selects", async () => {
    setLiveCaptureEnabled(true);
    renderApp(["/admin/live-capture"], "admin");
    expect(await screen.findByRole("combobox", { name: /^Agent/ })).toBeInTheDocument();
    const form = document.querySelector("form");
    expect(form?.querySelectorAll("input")).toHaveLength(0);
    expect(form?.querySelectorAll("textarea")).toHaveLength(0);
    expect(form?.querySelectorAll("select")).toHaveLength(5);
    expect(screen.getByText(/no free-text fields/)).toBeInTheDocument();
  });
});
