import type { ReactNode } from "react";
import { Link } from "react-router";

import { StatusPill, Skeleton, EmptyState } from "@/components/ui";
import { useAuth } from "@/features/auth/auth-context";
import { RequireAction } from "@/features/auth/guards";
import { useWorkspace } from "@/features/overview/useWorkspace";
import { formatBytes, formatTimestamp } from "@/lib/format";

export default function OverviewPage(): ReactNode {
  const { organizationId, role } = useAuth();
  const ws = useWorkspace(organizationId);

  if (ws.isPending) return <Skeleton label="Loading workspace overview" rows={5} />;
  if (ws.isError) {
    return (
      <p role="alert" className="text-sm text-sev-critical">
        Could not load the workspace overview. Check backend status above and retry.
      </p>
    );
  }

  const empty = ws.capturesTotal === 0;

  return (
    <section aria-labelledby="overview-heading">
      <div className="flex flex-wrap items-center gap-3">
        <h1 id="overview-heading" className="text-xl font-semibold">
          Overview
        </h1>
        <RequireAction action="captures:upload">
          <Link
            to="/captures"
            className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-accent-ink"
          >
            Upload Capture
          </Link>
        </RequireAction>
        <span className="text-xs text-ink-muted">Role: {role}</span>
      </div>

      {empty ? (
        <div className="mt-6">
          <EmptyState title="Welcome — this workspace has no captures yet">
            <p>
              Upload a PCAP/PCAPNG capture from an authorized testbed to begin. Analyses run against
              packet-observed evidence; anything not observable is reported as unknown, never as
              secure.
            </p>
            <RequireAction action="captures:upload">
              <p className="mt-3">
                <Link to="/captures" className="underline">
                  Go to Captures to upload your first capture
                </Link>
              </p>
            </RequireAction>
          </EmptyState>
        </div>
      ) : (
        <>
          <dl className="mt-6 grid grid-cols-2 gap-4 md:grid-cols-4">
            <div className="rounded border border-line p-3">
              <dt className="text-xs text-ink-muted">Tenant captures</dt>
              <dd className="tnum text-2xl font-semibold">{ws.capturesTotal}</dd>
            </div>
            <div className="rounded border border-line p-3">
              <dt className="text-xs text-ink-muted">Active / queued runs</dt>
              <dd className="tnum text-2xl font-semibold">{ws.activeRuns.length}</dd>
            </div>
            <div className="rounded border border-line p-3">
              <dt className="text-xs text-ink-muted">Partial / insufficient-evidence analyses</dt>
              <dd className="tnum text-2xl font-semibold">{ws.partialOrInsufficientCount}</dd>
            </div>
            <div className="rounded border border-line p-3">
              <dt className="text-xs text-ink-muted">Recent high-risk findings (high/critical)</dt>
              <dd className="tnum text-2xl font-semibold">{ws.recentHighRiskFindings}</dd>
            </div>
          </dl>

          <h2 className="mt-8 text-lg font-medium">Recent captures</h2>
          <table className="mt-2 w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-line text-left">
                <th scope="col" className="py-2 pr-3">
                  Name
                </th>
                <th scope="col" className="py-2 pr-3">
                  Format
                </th>
                <th scope="col" className="py-2 pr-3">
                  Size
                </th>
                <th scope="col" className="py-2">
                  Uploaded
                </th>
              </tr>
            </thead>
            <tbody>
              {ws.captures.slice(0, 5).map((capture) => (
                <tr key={capture.id} className="border-b border-line">
                  <td className="py-2 pr-3">
                    <Link to={`/captures/${capture.id}`} className="underline">
                      {capture.display_name}
                    </Link>
                  </td>
                  <td className="py-2 pr-3">{capture.format}</td>
                  <td className="tnum py-2 pr-3">{formatBytes(capture.size_bytes)}</td>
                  <td className="py-2">{formatTimestamp(capture.uploaded_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h2 className="mt-8 text-lg font-medium">Active / recent analysis runs</h2>
          {ws.recentRuns.length === 0 ? (
            <p className="mt-2 text-sm text-ink-muted">No analysis runs yet.</p>
          ) : (
            <ul className="mt-2 space-y-2">
              {ws.recentRuns.map((run) => (
                <li
                  key={run.id}
                  className="flex flex-wrap items-center gap-3 rounded border border-line px-3 py-2 text-sm"
                >
                  <StatusPill status={run.status} />
                  <Link to={`/analyses/${run.id}`} className="mono underline">
                    {run.id}
                  </Link>
                  <span className="text-ink-muted">
                    queued {formatTimestamp(run.queued_at)} · policy {run.policy_version}
                  </span>
                  <span className="tnum ml-auto">
                    {run.risk_score !== null ? `risk ${run.risk_score}` : "risk not scored"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </section>
  );
}
