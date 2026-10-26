import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Link, NavLink, Outlet } from "react-router";

import { fetchReadiness } from "@/api/client";
import { useAuth } from "@/features/auth/auth-context";
import { RequireAction } from "@/features/auth/guards";

export default function Shell(): ReactNode {
  const { email, organizationId, role, logout, isDemoMode, isAuthenticated } = useAuth();

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
    `flex items-center gap-2.5 rounded-full px-3.5 py-2 text-xs font-medium transition ${
      isActive
        ? "bg-[#0071e3] text-[#ffffff] shadow-sm font-semibold"
        : "text-[#1d1d1f] hover:bg-[#e6e6e8] hover:text-[#0071e3]"
    }`;

  return (
    <div className="flex min-h-screen bg-[#f5f5f7] text-[#1d1d1f] antialiased selection:bg-[#0071e3] selection:text-[#ffffff]">
      {/* Primary Sidebar — Apple Gallery Studio style */}
      <nav
        aria-label="Primary"
        className="flex w-64 shrink-0 flex-col gap-1 border-r border-[#e6e6e8] bg-[#ffffff] p-5 shadow-[1px_0_0_0_#e6e6e8]"
      >
        <Link
          to="/"
          className="mb-4 block border-b border-[#e6e6e8] px-2 pb-4 transition hover:opacity-85"
        >
          <div className="flex items-center gap-2.5">
            <span className="flex h-7 w-7 items-center justify-center rounded-full bg-[#0071e3] text-white shadow-sm font-semibold text-xs">
              ⚡
            </span>
            <div>
              <p className="font-display text-sm font-semibold tracking-tight text-[#1d1d1f]">
                IPsec Analyzer
              </p>
              <p className="text-[11px] text-[#707070] font-normal">Security Intelligence</p>
            </div>
          </div>
        </Link>

        <p className="px-3.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-[#86868b]">
          Navigation
        </p>

        <NavLink to="/app" end className={linkClass}>
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

        {/* Sidebar Footer — Subtle Apple Information Pill */}
        <div className="mt-auto rounded-2xl border border-[#e6e6e8] bg-[#f5f5f7] p-3 text-[11px] text-[#707070]">
          <div className="flex items-center gap-1.5 font-medium text-[#1d1d1f]">
            <span className="h-2 w-2 rounded-full bg-[#34c759]" />
            <span>Passive TShark Engine</span>
          </div>
          <p className="mt-1 leading-relaxed text-[#707070]">
            Epistemic integrity: unknown evidence is reported as unknown — never as secure.
          </p>
        </div>
      </nav>

      {/* Main Content Area */}
      <div className="flex min-w-0 flex-1 flex-col bg-[#f5f5f7]">
        {/* Apple Frosted Glass Header */}
        <header className="sticky top-0 z-30 flex flex-wrap items-center gap-3 border-b border-[#e6e6e8] bg-white/85 px-8 py-3.5 backdrop-blur-xl">
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 rounded-full border border-[#d6d6d6] bg-white px-3.5 py-1 text-xs font-medium text-[#1d1d1f] transition hover:bg-[#f5f5f7]"
            title="Return to Public Landing Page"
          >
            ← Landing Page
          </Link>

          <span
            className="inline-flex items-center gap-1.5 rounded-full border border-[#e6e6e8] bg-[#f5f5f7] px-3 py-1 text-xs text-[#707070]"
            aria-label={`Organization ${organizationId ?? ""}`}
          >
            Org: <span className="font-medium text-[#1d1d1f]">{organizationId}</span>
          </span>

          <span
            className="inline-flex items-center gap-1.5 rounded-full border border-[#e6e6e8] bg-[#f5f5f7] px-3 py-1 text-xs text-[#707070]"
            aria-label={`Role ${role ?? ""}`}
          >
            Role: <span className="font-semibold uppercase text-[#0071e3]">{role}</span>
          </span>

          <span
            role="status"
            aria-label={backendReady ? "Backend ready" : "Backend degraded"}
            className="inline-flex items-center gap-1.5 rounded-full border border-[#e6e6e8] bg-[#f5f5f7] px-3 py-1 text-xs"
          >
            <span
              aria-hidden="true"
              className={
                backendReady
                  ? "h-2 w-2 rounded-full bg-[#34c759]"
                  : "h-2 w-2 rounded-full bg-amber-500"
              }
            />
            <span className="text-[#1d1d1f] font-medium">
              Backend: {healthQuery.isPending ? "checking…" : backendReady ? "ready" : "degraded"}
            </span>
          </span>

          <span className="ml-auto flex items-center gap-3 text-xs">
            {isDemoMode && (
              <span
                role="status"
                className="inline-flex items-center gap-1 rounded-full border border-[#ff9500]/30 bg-[#ff9500]/10 px-3 py-1 text-xs font-medium text-[#b64400]"
              >
                <span className="h-1.5 w-1.5 rounded-full bg-[#ff9500]" />
                Demo Mode
              </span>
            )}
            <span className="font-medium text-[#1d1d1f]">{email ?? "admin@ipsec.lab"}</span>
            <button
              type="button"
              onClick={logout}
              className="cursor-pointer rounded-full border border-[#d6d6d6] bg-white px-3.5 py-1 text-xs font-medium text-[#1d1d1f] transition hover:bg-[#f5f5f7]"
            >
              Sign Out
            </button>
            {isAuthenticated && <span className="sr-only">Signed in as {email}</span>}
          </span>
        </header>

        {degraded && (
          <div
            role="alert"
            className="border-b border-amber-200 bg-[#fff9e6] px-8 py-3 text-xs text-[#b64400]"
          >
            <strong>Backend degraded:</strong> the API readiness check is failing. Data shown may be
            stale; analysis jobs may not start until the backend recovers.
          </div>
        )}

        <main className="mx-auto w-full max-w-7xl flex-1 p-6 md:p-10">
          <Outlet />
        </main>

        {/* Clean Apple Studio Footer */}
        <footer className="border-t border-[#e6e6e8] bg-white py-5 px-8 text-xs text-[#707070]">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="font-medium text-[#1d1d1f]">IPsec Cryptographic Analyzer</span>
              <span>·</span>
              <span>Automated Posture &amp; Evidence Engine</span>
            </div>
            <div className="flex items-center gap-3">
              <span>Passive Deep Packet Inspection</span>
              <span>·</span>
              <span className="font-medium text-[#0066cc]">Enterprise Defense Edition</span>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}
