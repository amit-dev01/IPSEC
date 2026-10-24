import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, describe, expect, it } from "vitest";

import { createQueryClient } from "@/app/query-client";
import Shell from "@/app/Shell";
import { AuthProvider } from "@/features/auth/AuthProvider";
import { RequireAuth } from "@/features/auth/guards";
import { LoginPage } from "@/features/auth/LoginPage";
import OverviewPage from "@/features/auth/OverviewPage";
import CapturesPage from "@/features/captures/CapturesPage";
import { endSession } from "@/features/auth/auth-store";

afterEach(() => {
  endSession();
});

function renderApp(initialEntries: string[] = ["/login"]) {
  const queryClient = createQueryClient();
  const tree: ReactNode = (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={initialEntries}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
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
            </Route>
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
  const utils = render(tree);
  return { ...utils, queryClient };
}

async function fillAndSubmit(email: string, password: string): Promise<void> {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Email"), email);
  await user.type(screen.getByLabelText("Password"), password);
  await user.click(screen.getByRole("button", { name: "Sign in" }));
}

describe("authentication", () => {
  it("logs in and shows identity, organization, and role", async () => {
    renderApp();
    await fillAndSubmit("analyst@example.test", "correct-password");
    expect(await screen.findByText("Session overview")).toBeInTheDocument();
    expect(screen.getAllByText(/analyst@example\.test/).length).toBeGreaterThan(0);
    expect(screen.getByText(/role analyst/)).toBeInTheDocument();
    expect(screen.queryByText("Sign in", { selector: "button" })).not.toBeInTheDocument();
  });

  it("shows a generic message on 401 invalid credentials", async () => {
    renderApp();
    await fillAndSubmit("analyst@example.test", "wrong-password");
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Invalid credentials or inactive account.",
    );
  });

  it("shows the rate-limit message on 429 without leaking details", async () => {
    renderApp();
    await fillAndSubmit("rate@example.test", "correct-password");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Too many sign-in attempts");
    expect(alert).toHaveTextContent("300 seconds");
    expect(alert.textContent).not.toContain("correct-password");
  });

  it("hides upload for viewer and shows it for analyst", async () => {
    const viewer = renderApp();
    await fillAndSubmit("viewer@example.test", "correct-password");
    await screen.findByText("Session overview");
    await userEvent.setup().click(screen.getByRole("link", { name: "Captures" }));
    expect(await screen.findByText(/No captures yet/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Upload capture file")).not.toBeInTheDocument();
    viewer.unmount();
    endSession();

    renderApp();
    await fillAndSubmit("analyst@example.test", "correct-password");
    await screen.findByText("Session overview");
    await userEvent.setup().click(screen.getByRole("link", { name: "Captures" }));
    expect(await screen.findByLabelText("Upload capture file")).toBeInTheDocument();
  });

  it("wipes the entire query cache on logout", async () => {
    const { queryClient } = renderApp();
    await fillAndSubmit("admin@example.test", "correct-password");
    await screen.findByText("Session overview");
    queryClient.setQueryData(["org", "22222222-2222-4222-8222-222222222222", "captures"], {
      items: [{ id: "secret-tenant-row" }],
    });
    expect(queryClient.getQueryCache().getAll()).not.toHaveLength(0);

    await userEvent.setup().click(screen.getByRole("button", { name: "Sign out" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
    });
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  });
});
