import type { ReactNode } from "react";
import { Link } from "react-router";

import { Skeleton, StatusPill, EmptyState } from "@/components/ui";
import { useAuth } from "@/features/auth/auth-context";
import { useWorkspace } from "@/features/overview/useWorkspace";
import { formatTimestamp } from "@/lib/format";

export default function AnalysesPage(): ReactNode {
  const { organizationId } = useAuth();
  const ws = useWorkspace(organizationId);

  if (ws.isPending) return <Skeleton label="Loading analysis runs" rows={5} />;
  if (ws.isError) {
    return (
      <p role="alert" className="text-sm text-sev-critical">
        Could not load analysis runs.
      </p>
    );
  }

  return (
    <section aria-labelledby="analyses-heading" className="space-y-6">
      <div>
        <h1
          id="analyses-heading"
          className="font-display text-3xl font-semibold tracking-tight text-[#1d1d1f]"
        >
          Security Analyses
        </h1>
        <p className="mt-1 text-sm text-[#707070]">
          Deterministic IPsec protocol inspection, compliance evaluations, and cryptographic
          assessment records.
        </p>
      </div>

      {ws.recentRuns.length === 0 ? (
        <div className="mt-4">
          <EmptyState title="No analysis runs yet">
            <p>
              Open a capture in the vault and choose <strong>Run Security Analysis</strong>. The
              backend applies its configured cryptographic policy.
            </p>
            <p className="mt-4">
              <Link to="/captures" className="apple-btn-primary text-xs">
                Go to Captures Vault
              </Link>
            </p>
          </EmptyState>
        </div>
      ) : (
        <ul className="space-y-3">
          {ws.runs.map((run) => (
            <li
              key={run.id}
              className="apple-card flex flex-wrap items-center gap-4 p-5 text-sm transition hover:border-[#d6d6d6]"
            >
              <StatusPill status={run.status} />
              <Link
                to={`/analyses/${run.id}`}
                className="mono font-semibold text-[#0066cc] hover:underline"
              >
                {run.id}
              </Link>
              <span className="text-xs text-[#707070]">
                capture <span className="mono font-medium text-[#1d1d1f]">{run.capture_id}</span> ·
                queued {formatTimestamp(run.queued_at)} · policy{" "}
                <span className="mono">{run.policy_version}</span>
              </span>
              <span className="tnum ml-auto font-semibold text-[#1d1d1f]">
                {run.risk_score !== null ? `risk ${run.risk_score} / 100` : "not scored"}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
