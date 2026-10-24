import type { ReactNode } from "react";
import { Link, NavLink, Outlet } from "react-router";

import { useAuth } from "@/features/auth/auth-context";
import { RequireAction } from "@/features/auth/guards";

export default function Shell(): ReactNode {
  const { email, organizationId, role, logout } = useAuth();
  const linkClass = ({ isActive }: { isActive: boolean }): string =>
    `rounded px-2 py-1 text-sm ${isActive ? "bg-surface-sunken font-medium" : ""}`;
  return (
    <div className="min-h-screen">
      <header className="flex flex-wrap items-center gap-4 border-b border-line bg-surface-raised px-4 py-3">
        <Link to="/" className="font-semibold">
          IPsec Analyzer
        </Link>
        <nav aria-label="Primary" className="flex gap-2">
          <NavLink to="/" end className={linkClass}>
            Overview
          </NavLink>
          <NavLink to="/captures" className={linkClass}>
            Captures
          </NavLink>
          <RequireAction action="dataset:export">
            <NavLink to="/admin" className={linkClass}>
              Admin
            </NavLink>
          </RequireAction>
        </nav>
        <div className="ml-auto flex items-center gap-3 text-sm">
          <span>
            <span className="font-medium">{email}</span>{" "}
            <span className="text-ink-muted">
              · org <span className="mono">{organizationId}</span> · role {role}
            </span>
          </span>
          <button
            type="button"
            onClick={logout}
            className="rounded border border-line px-2 py-1 text-sm"
          >
            Sign out
          </button>
        </div>
      </header>
      <main className="mx-auto max-w-6xl p-4">
        <Outlet />
      </main>
    </div>
  );
}
