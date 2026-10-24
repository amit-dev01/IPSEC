import type { Role } from "@/features/auth/auth-store";

/**
 * UI capability map. This mirrors the backend role model (viewer <
 * analyst < admin) for showing/hiding actions — it is NOT authorization.
 * The backend enforces every permission on every request.
 */
export type Action =
  | "captures:read"
  | "captures:upload"
  | "captures:delete"
  | "analyses:run"
  | "manifests:edit"
  | "reports:download"
  | "audit:read"
  | "dataset:export"
  | "agent:control";

const CAPABILITIES: Record<Role, ReadonlySet<Action>> = {
  viewer: new Set<Action>(["captures:read", "reports:download"]),
  analyst: new Set<Action>([
    "captures:read",
    "reports:download",
    "captures:upload",
    "captures:delete",
    "analyses:run",
    "manifests:edit",
  ]),
  admin: new Set<Action>([
    "captures:read",
    "reports:download",
    "captures:upload",
    "captures:delete",
    "analyses:run",
    "manifests:edit",
    "audit:read",
    "dataset:export",
    "agent:control",
  ]),
};

export function can(role: Role | null, action: Action): boolean {
  return role !== null && CAPABILITIES[role].has(action);
}

/** Honest assessment label from documented score nullability. */
export function assessmentLabel(run: {
  status: string;
  security_score: number | null;
  risk_score: number | null;
}): string {
  if (run.status !== "succeeded") return `Not assessed (${run.status})`;
  if (run.security_score !== null) return "Assessed from observable evidence";
  if (run.risk_score !== null)
    return "Partially assessed — security score not computable from observable evidence";
  return "Insufficient evidence — no score claimed";
}
