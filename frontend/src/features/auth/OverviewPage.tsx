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
      <p role="alert" className="text-xs font-mono text-red-400">
        Could not load the workspace overview. Check backend status above and retry.
      </p>
    );
  }

  const empty = ws.capturesTotal === 0;

  return (
    <section aria-labelledby="overview-heading" className="space-y-8">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#f7f9fa]/10 pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-[#af50ff]" />
            <span className="font-mono text-xs uppercase tracking-[0.2em] text-[#af50ff]">
              WORKSPACE // MONITOR
            </span>
          </div>
          <h1 id="overview-heading" className="text-2xl md:text-3xl font-normal text-[#f7f9fa] mt-1 tracking-tight">
            Overview
          </h1>
        </div>

        <div className="flex items-center gap-3">
          <span className="font-mono text-xs text-[#828384] border border-[#f7f9fa]/10 rounded-[6px] px-2.5 py-1">
            ROLE // {role}
          </span>
          <RequireAction action="captures:upload">
            <Link
              to="/captures"
              className="rounded-[8px] bg-[#090909] border border-[#f7f9fa] px-4 py-2 font-mono text-xs uppercase tracking-wider text-[#f7f9fa] transition hover:bg-[#af50ff] hover:border-[#af50ff] hover:text-[#090909]"
            >
              Upload Capture
            </Link>
          </RequireAction>
        </div>
      </div>

      {empty ? (
        <div className="mt-6">
          <EmptyState title="Welcome — this workspace has no captures yet">
            <p className="text-sm text-[#828384] font-light">
              Upload a PCAP/PCAPNG capture from an authorized testbed to begin. Analyses run against
              packet-observed evidence; anything not observable is reported as unknown, never as
              secure.
            </p>
            <RequireAction action="captures:upload">
              <p className="mt-4">
                <Link
                  to="/captures"
                  className="font-mono text-xs uppercase tracking-wider text-[#af50ff] hover:underline"
                >
                  Go to Captures to upload your first capture →
                </Link>
              </p>
            </RequireAction>
          </EmptyState>
        </div>
      ) : (
        <>
          {/* 4 Metric Cards — dope.security 19.2px radius */}
          <dl className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <div className="rounded-[19.2px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-5">
              <dt className="font-mono text-[11px] text-[#828384]">
                Tenant captures
              </dt>
              <dd className="tnum mt-2 font-mono text-3xl font-light text-[#f7f9fa]">
                {ws.capturesTotal}
              </dd>
            </div>
            <div className="rounded-[19.2px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-5">
              <dt className="font-mono text-[11px] text-[#828384]">
                Active / queued runs
              </dt>
              <dd className="tnum mt-2 font-mono text-3xl font-light text-[#af50ff]">
                {ws.activeRuns.length}
              </dd>
            </div>
            <div className="rounded-[19.2px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-5">
              <dt className="font-mono text-[11px] text-[#828384]">
                Partial / insufficient-evidence analyses
              </dt>
              <dd className="tnum mt-2 font-mono text-3xl font-light text-[#828384]">
                {ws.partialOrInsufficientCount}
              </dd>
            </div>
            <div className="rounded-[19.2px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-5">
              <dt className="font-mono text-[11px] text-[#828384]">
                Recent high-risk findings (high/critical)
              </dt>
              <dd className="tnum mt-2 font-mono text-3xl font-light text-amber-400">
                {ws.recentHighRiskFindings}
              </dd>
            </div>
          </dl>

          {/* Recent Captures */}
          <div className="rounded-[19.2px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-6">
            <h2 className="font-mono text-sm tracking-wider text-[#f0f0f0] mb-4">
              Recent captures
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-[#f7f9fa]/10 text-[#828384] uppercase tracking-wider">
                    <th scope="col" className="py-2.5 pr-4 font-normal">
                      Name
                    </th>
                    <th scope="col" className="py-2.5 pr-4 font-normal">
                      Format
                    </th>
                    <th scope="col" className="py-2.5 pr-4 font-normal">
                      Size
                    </th>
                    <th scope="col" className="py-2.5 font-normal">
                      Uploaded
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#f7f9fa]/5 text-[#f7f9fa]">
                  {ws.captures.slice(0, 5).map((capture) => (
                    <tr key={capture.id} className="hover:bg-[#f7f9fa]/5 transition-colors">
                      <td className="py-3 pr-4 font-sans text-sm">
                        <Link to={`/captures/${capture.id}`} className="text-[#f7f9fa] hover:text-[#af50ff] transition-colors">
                          {capture.display_name}
                        </Link>
                      </td>
                      <td className="py-3 pr-4 text-[#828384]">{capture.format}</td>
                      <td className="tnum py-3 pr-4 text-[#828384]">{formatBytes(capture.size_bytes)}</td>
                      <td className="py-3 text-[#828384]">{formatTimestamp(capture.uploaded_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Active / Recent Analysis Runs */}
          <div className="rounded-[19.2px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-6">
            <h2 className="font-mono text-sm tracking-wider text-[#f0f0f0] mb-4">
              Active / recent analysis runs
            </h2>

            {ws.recentRuns.length === 0 ? (
              <p className="text-xs font-mono text-[#828384]">No analysis runs recorded yet.</p>
            ) : (
              <ul className="space-y-2">
                {ws.recentRuns.map((run) => (
                  <li
                    key={run.id}
                    className="flex flex-wrap items-center gap-3 rounded-[10.8px] border border-[#f7f9fa]/10 bg-[#090909] px-4 py-3 text-xs font-mono"
                  >
                    <StatusPill status={run.status} />
                    <Link to={`/analyses/${run.id}`} className="text-[#f7f9fa] hover:text-[#af50ff] underline">
                      {run.id}
                    </Link>
                    <span className="text-[#828384]">
                      queued {formatTimestamp(run.queued_at)} · policy {run.policy_version}
                    </span>
                    <span className="tnum ml-auto text-[#f7f9fa]">
                      {run.risk_score !== null ? `risk ${run.risk_score}` : "risk not scored"}
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
