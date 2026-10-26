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
      <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-xs text-red-600">
        Could not load the workspace overview. Check backend status above and retry.
      </div>
    );
  }

  const empty = ws.capturesTotal === 0;

  return (
    <section aria-labelledby="overview-heading" className="space-y-8">
      {/* Top Header — Apple Editorial Title */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#e6e6e8] pb-6">
        <div>
          <span className="text-xs font-semibold uppercase tracking-wider text-[#707070]">
            Cryptographic Audit Intelligence
          </span>
          <h1
            id="overview-heading"
            className="font-display text-3xl font-semibold tracking-tight text-[#1d1d1f] mt-1"
          >
            Overview
          </h1>
        </div>

        <div className="flex items-center gap-3">
          <span className="rounded-full border border-[#e6e6e8] bg-white px-3.5 py-1 text-xs font-medium text-[#707070]">
            Role: <span className="text-[#1d1d1f] uppercase font-semibold">{role}</span>
          </span>
          <RequireAction action="captures:upload">
            <Link to="/captures" className="apple-btn-primary shadow-sm hover:shadow">
              Upload Capture
            </Link>
          </RequireAction>
        </div>
      </div>

      {empty ? (
        <div className="mt-6">
          <EmptyState title="Welcome — this workspace has no captures yet">
            <p className="text-sm text-[#707070] font-normal max-w-lg mx-auto">
              Upload a PCAP/PCAPNG capture from an authorized testbed to begin. Analyses run against
              packet-observed evidence; anything not observable is reported as unknown, never as
              secure.
            </p>
            <RequireAction action="captures:upload">
              <p className="mt-5">
                <Link
                  to="/captures"
                  className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#0066cc] hover:underline"
                >
                  Go to Captures to upload your first capture →
                </Link>
              </p>
            </RequireAction>
          </EmptyState>
        </div>
      ) : (
        <>
          {/* 4 Metric Cards — Apple 28px Gallery White Cards */}
          <dl className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <div className="apple-card p-6 transition-all hover:border-[#d6d6d6]">
              <dt className="text-xs font-medium text-[#707070]">Tenant captures</dt>
              <dd className="tnum mt-2 font-display text-4xl font-semibold text-[#1d1d1f]">
                {ws.capturesTotal}
              </dd>
            </div>
            <div className="apple-card p-6 transition-all hover:border-[#d6d6d6]">
              <dt className="text-xs font-medium text-[#707070]">Active / queued runs</dt>
              <dd className="tnum mt-2 font-display text-4xl font-semibold text-[#0071e3]">
                {ws.activeRuns.length}
              </dd>
            </div>
            <div className="apple-card p-6 transition-all hover:border-[#d6d6d6]">
              <dt className="text-xs font-medium text-[#707070]">Partial / withheld analyses</dt>
              <dd className="tnum mt-2 font-display text-4xl font-semibold text-[#86868b]">
                {ws.partialOrInsufficientCount}
              </dd>
            </div>
            <div className="apple-card p-6 transition-all hover:border-[#d6d6d6]">
              <dt className="text-xs font-medium text-[#707070]">High-risk findings</dt>
              <dd className="tnum mt-2 font-display text-4xl font-semibold text-[#b64400]">
                {ws.recentHighRiskFindings}
              </dd>
            </div>
          </dl>

          {/* Recent Captures — Apple White Card */}
          <div className="apple-card p-7">
            <div className="flex items-center justify-between mb-5">
              <h2 className="font-display text-lg font-semibold tracking-tight text-[#1d1d1f]">
                Recent captures
              </h2>
              <Link to="/captures" className="text-xs font-medium text-[#0066cc] hover:underline">
                View all captures →
              </Link>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-[#e6e6e8] text-[#707070] font-medium">
                    <th scope="col" className="py-3 pr-4 font-medium">
                      Name
                    </th>
                    <th scope="col" className="py-3 pr-4 font-medium">
                      Format
                    </th>
                    <th scope="col" className="py-3 pr-4 font-medium">
                      Size
                    </th>
                    <th scope="col" className="py-3 font-medium">
                      Uploaded
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#f5f5f7] text-[#1d1d1f]">
                  {ws.captures.slice(0, 5).map((capture) => (
                    <tr key={capture.id} className="hover:bg-[#f5f5f7]/60 transition-colors">
                      <td className="py-3.5 pr-4 text-sm font-medium">
                        <Link
                          to={`/captures/${capture.id}`}
                          className="text-[#0066cc] hover:underline"
                        >
                          {capture.display_name}
                        </Link>
                      </td>
                      <td className="py-3.5 pr-4 text-[#707070] uppercase font-mono text-[11px]">
                        {capture.format}
                      </td>
                      <td className="tnum py-3.5 pr-4 text-[#707070]">
                        {formatBytes(capture.size_bytes)}
                      </td>
                      <td className="py-3.5 text-[#707070]">
                        {formatTimestamp(capture.uploaded_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Active / Recent Analysis Runs */}
          <div className="apple-card p-7">
            <h2 className="font-display text-lg font-semibold tracking-tight text-[#1d1d1f] mb-4">
              Active / recent analysis runs
            </h2>

            {ws.recentRuns.length === 0 ? (
              <p className="text-xs text-[#707070]">No analysis runs recorded yet.</p>
            ) : (
              <ul className="space-y-2.5">
                {ws.recentRuns.map((run) => (
                  <li
                    key={run.id}
                    className="flex flex-wrap items-center gap-3 rounded-2xl border border-[#e6e6e8] bg-[#fafafc] px-5 py-3.5 text-xs transition hover:border-[#d6d6d6]"
                  >
                    <StatusPill status={run.status} />
                    <Link
                      to={`/analyses/${run.id}`}
                      className="font-medium text-[#0066cc] hover:underline"
                    >
                      {run.id}
                    </Link>
                    <span className="text-[#707070]">
                      queued {formatTimestamp(run.queued_at)} · policy {run.policy_version}
                    </span>
                    <span className="tnum ml-auto font-medium text-[#1d1d1f]">
                      {run.risk_score !== null ? `Risk: ${run.risk_score}` : "Risk withheld"}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </>
      )}
    </section>
  );
}
