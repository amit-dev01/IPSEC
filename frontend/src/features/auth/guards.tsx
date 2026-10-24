import type { ReactNode } from "react";
import { Navigate } from "react-router";

import { useAuth } from "@/features/auth/auth-context";
import type { Role } from "@/features/auth/auth-store";
import { can } from "@/lib/permissions";
import type { Action } from "@/lib/permissions";

/** Requires any authenticated session; otherwise redirects to /login. */
export function RequireAuth({ children }: { children: ReactNode }): ReactNode {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return children;
}

/**
 * Requires one of the given roles. Without it, renders `fallback`
 * (default: an explicit access notice — never a silent blank, and never
 * renders the protected children). Backend still enforces permissions.
 */
export function RequireRole({
  roles,
  children,
  fallback,
}: {
  roles: readonly Role[];
  children: ReactNode;
  fallback?: ReactNode;
}): ReactNode {
  const { role } = useAuth();
  if (role === null || !roles.includes(role)) {
    return (
      fallback ?? (
        <p role="alert" className="p-4 text-sm">
          You do not have access to this area.
        </p>
      )
    );
  }
  return children;
}

/** Conditionally renders an action control by capability. */
export function RequireAction({
  action,
  children,
  fallback = null,
}: {
  action: Action;
  children: ReactNode;
  fallback?: ReactNode;
}): ReactNode {
  const { role } = useAuth();
  return can(role, action) ? children : fallback;
}
