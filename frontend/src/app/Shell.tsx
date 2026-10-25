import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { NavLink, Outlet } from "react-router";

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
    `flex items-center gap-2.5 rounded-[8px] px-3 py-2 text-xs font-mono uppercase tracking-[0.1em] transition ${
      isActive
        ? "bg-[#af50ff]/15 text-[#f7f9fa] border border-[#af50ff]/30 font-medium"
        : "text-[#828384] hover:bg-[#f7f9fa]/5 hover:text-[#f7f9fa]"
    }`;

  return (
    <div className="flex min-h-screen bg-[#090909] text-[#f7f9fa] selection:bg-[#af50ff] selection:text-[#090909]">
      {/* Primary Sidebar — dope.security midnight terminal style */}
      <nav
        aria-label="Primary"
        className="flex w-60 shrink-0 flex-col gap-1 border-r border-[#f7f9fa]/10 bg-[#090909] p-4"
      >
        <div className="px-2 py-3 mb-2 border-b border-[#f7f9fa]/10">
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 rounded-full bg-[#af50ff] shadow-[0_0_8px_#af50ff]" />
            <p className="font-mono text-xs font-semibold tracking-[0.2em] text-[#f7f9fa]">
              IPSEC // ANALYZER
            </p>
          </div>
          <p className="mt-1 text-[10px] font-mono uppercase tracking-wider text-[#828384]">
            Midnight Workbench
          </p>
        </div>

        <p className="px-3 py-1 font-mono text-[9px] uppercase tracking-[0.2em] text-[#6b6b6b]">
          TERMINAL // VIEWS
        </p>

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


        {/* Sidebar Footer Stamp */}
        <div className="mt-auto border-t border-[#f7f9fa]/10 pt-4 px-2">
          <div className="flex items-center gap-1.5 font-mono text-[10px] text-[#828384]">
            <span className="h-1.5 w-1.5 rounded-full bg-[#af50ff]" />
            <span>PASSIVE ENGINE // TSHARK</span>
          </div>
          <p className="mt-1 text-[9px] text-[#6b6b6b] font-mono leading-tight">
            Unknown evidence is reported as unknown — never as secure.
          </p>
        </div>
      </nav>

      {/* Main Content Area */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Frosted Header Bar */}
        <header className="flex flex-wrap items-center gap-3 border-b border-[#f7f9fa]/10 bg-[rgba(18,16,28,0.75)] px-6 py-3.5 backdrop-blur-md">
          <span
            className="inline-flex items-center gap-1.5 rounded-[6px] border border-[#f7f9fa]/15 bg-[rgba(247,249,250,0.03)] px-2.5 py-1 font-mono text-[11px] text-[#828384]"
            aria-label={`Organization ${organizationId ?? ""}`}
          >
            ORG // <span className="text-[#f7f9fa]">{organizationId}</span>
          </span>

          <span
            className="inline-flex items-center gap-1.5 rounded-[6px] border border-[#f7f9fa]/15 bg-[rgba(247,249,250,0.03)] px-2.5 py-1 font-mono text-[11px] font-medium text-[#f7f9fa]"
            aria-label={`Role ${role ?? ""}`}
          >
            ROLE // <span className="text-[#af50ff] uppercase">{role}</span>
          </span>

          <span
            role="status"
            aria-label={backendReady ? "Backend ready" : "Backend degraded"}
            className="inline-flex items-center gap-1.5 rounded-[6px] border border-[#f7f9fa]/15 bg-[rgba(247,249,250,0.03)] px-2.5 py-1 font-mono text-[11px]"
          >
            <span
              aria-hidden="true"
              className={backendReady ? "text-[#af50ff] animate-pulse" : "text-amber-400"}
            >
              ●
            </span>
            <span className="text-[#828384]">
              BACKEND: {healthQuery.isPending ? "checking…" : backendReady ? "ready" : "degraded"}
            </span>
          </span>

          <span className="ml-auto flex items-center gap-3 text-xs">
            {isDemoMode && (
              <span
                role="status"
                className="inline-flex items-center gap-1 rounded-full border border-[#af50ff]/30 bg-[#af50ff]/10 px-3 py-1 font-mono text-[11px] font-medium text-[#e1bdff]"
              >
                <span className="h-1.5 w-1.5 rounded-full bg-[#af50ff]" />
                Demo Mode
              </span>
            )}
            <span className="font-mono text-[#f7f9fa]">{email ?? "admin@ipsec.lab"}</span>
            <button
              type="button"
              onClick={logout}
              className="cursor-pointer rounded-[8px] border border-[#f7f9fa]/20 bg-[#090909] px-3 py-1 font-mono text-xs uppercase tracking-wider text-[#f7f9fa] transition hover:border-[#af50ff] hover:text-[#af50ff]"
            >
              Sign Out
            </button>
            {isAuthenticated && <span className="sr-only">Signed in as {email}</span>}
          </span>
        </header>

        {degraded && (
          <div
            role="alert"
            className="border-b border-amber-500/30 bg-amber-500/10 px-6 py-2.5 text-xs text-amber-300 font-mono"
          >
            <strong>Backend degraded:</strong> the API readiness check is failing. Data shown may be
            stale; analysis jobs may not start until the backend recovers.
          </div>

        )}

        <main className="mx-auto w-full max-w-6xl flex-1 p-6 md:p-8">
          <Outlet />
        </main>

        {/* Coordinate Footer on App Shell */}
        <footer className="border-t border-[#f7f9fa]/10 py-4 px-6 md:px-8 text-[11px] font-mono text-[#828384]">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-[#f7f9fa]">+</span>
              <span className="text-[#f7f9fa]">Fly Direct</span>
              <span>·</span>
              <span>IPsec Cryptographic Analyzer</span>
            </div>
            <div className="flex items-center gap-3">
              <span>37.7749° N, 122.4194° W</span>
              <span>·</span>
              <span className="text-[#af50ff]">♥ PASSIVE DEFENSE</span>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}
