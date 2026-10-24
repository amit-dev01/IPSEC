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
    <section aria-labelledby="analyses-heading">
      <h1 id="analyses-heading" className="text-xl font-semibold">
        Analyses
      </h1>
      <p className="mt-1 text-sm text-ink-muted">
        Runs are composed from each capture&apos;s analysis history (the API exposes runs per
        capture). Select a run to inspect evidence, findings, and reports.
      </p>
      {ws.recentRuns.length === 0 ? (
        <div className="mt-6">
          <EmptyState title="No analysis runs yet">
            <p>
              Open a capture and choose <strong>Run Security Analysis</strong>. The backend applies
              its configured assessment policy; the run shows the applied policy version.
            </p>
            <p className="mt-3">
              <Link to="/captures" className="underline">
                Go to Captures
              </Link>
            </p>
          </EmptyState>
        </div>
      ) : (
        <ul className="mt-4 space-y-2">
          {ws.runs.map((run) => (
            <li
              key={run.id}
              className="flex flex-wrap items-center gap-3 rounded border border-line px-3 py-2 text-sm"
            >
              <StatusPill status={run.status} />
              <Link to={`/analyses/${run.id}`} className="mono underline">
                {run.id}
              </Link>
              <span className="text-ink-muted">
                capture <span className="mono">{run.capture_id}</span> · queued{" "}
                {formatTimestamp(run.queued_at)} · policy {run.policy_version}
              </span>
              <span className="tnum ml-auto">
                {run.risk_score !== null ? `risk ${run.risk_score} / 100` : "not scored"}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
