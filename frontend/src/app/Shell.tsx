import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { NavLink, Outlet } from "react-router";

import { fetchReadiness } from "@/api/client";
import { useAuth } from "@/features/auth/auth-context";
import { RequireAction } from "@/features/auth/guards";

export default function Shell(): ReactNode {
  const { email, organizationId, role, logout } = useAuth();

  const healthQuery = useQuery({
    queryKey: ["health", "ready"],
    queryFn: fetchReadiness,
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
    retry: false,
    staleTime: 15_000,
  });
  const backendReady = healthQuery.data === true;
  const degraded = healthQuery.isSuccess && !backendReady;

  const linkClass = ({ isActive }: { isActive: boolean }): string =>
    `block rounded px-3 py-2 text-sm ${isActive ? "bg-surface-sunken font-medium" : ""}`;

  return (
    <div className="flex min-h-screen">
      <nav
        aria-label="Primary"
        className="flex w-52 shrink-0 flex-col gap-1 border-r border-line bg-surface-raised p-3"
      >
        <p className="px-3 py-2 font-semibold">IPsec Analyzer</p>
        <NavLink to="/" end className={linkClass}>
          Overview
        </NavLink>
        <NavLink to="/captures" className={linkClass}>
          Captures
        </NavLink>
        <NavLink to="/analyses" className={linkClass}>
          Analyses
        </NavLink>
        <RequireAction action="dataset:export">
          <NavLink to="/dataset" className={linkClass}>
            Dataset &amp; Lab
          </NavLink>
        </RequireAction>
        {role === "admin" && (
          <NavLink to="/admin" className={linkClass}>
            Admin / Audit / Capture Agents
          </NavLink>
        )}
        <p className="mt-auto px-3 text-xs text-ink-muted">
          Unknown evidence is shown as unknown — never as secure.
        </p>
      </nav>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-center gap-3 border-b border-line bg-surface-raised px-4 py-3">
          <span
            className="inline-flex items-center gap-1 rounded border border-line px-2 py-0.5 text-xs"
            aria-label={`Organization ${organizationId ?? ""}`}
          >
            Org <span className="mono">{organizationId}</span>
          </span>
          <span
            className="inline-flex items-center gap-1 rounded border border-line px-2 py-0.5 text-xs font-medium"
            aria-label={`Role ${role ?? ""}`}
          >
            Role: {role}
          </span>
          <span
            role="status"
            aria-label={backendReady ? "Backend ready" : "Backend degraded"}
            className="inline-flex items-center gap-1 rounded border border-line px-2 py-0.5 text-xs"
          >
            <span aria-hidden="true">{backendReady ? "●" : "▲"}</span>
            Backend: {healthQuery.isPending ? "checking…" : backendReady ? "ready" : "degraded"}
          </span>
          <span className="ml-auto flex items-center gap-3 text-sm">
            <span className="font-medium">{email}</span>
            <button
              type="button"
              onClick={logout}
              className="rounded border border-line px-2 py-1 text-sm"
            >
              Sign Out
            </button>
          </span>
        </header>

        {degraded && (
          <div
            role="alert"
            className="border-b border-sev-medium bg-surface-sunken px-4 py-2 text-sm"
          >
            <strong>Backend degraded:</strong> the API readiness check is failing. Data shown may be
            stale; analysis jobs may not start until the backend recovers.
          </div>
        )}

        <main className="mx-auto w-full max-w-6xl flex-1 p-4">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
