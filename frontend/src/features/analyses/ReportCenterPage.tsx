import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useState } from "react";
import { Link, useParams } from "react-router";

import { ApiError, downloadReport, fetchReportJson, getAnalysis } from "@/api/client";
import { useToast } from "@/app/toast-context";
import { ConfidenceMeter, ProvenanceBadge } from "@/components/epistemic";
import { SeverityBadge } from "@/components/badges";
import type { Severity } from "@/components/badges";
import { Skeleton } from "@/components/ui";
import { useAuth } from "@/features/auth/auth-context";

import { assessmentStatus, evidenceCoverage, missingKeyFacts } from "./assessment-lib";
import { allEvidence, asSource } from "./evidence-lib";
import ReportExportButton from "./ReportExportButton";

/**
 * In-app dual-mode report viewer. All values render through React text
 * nodes (auto-escaped); no raw HTML is ever injected. Downloads use the
 * authenticated Blob helper — tokens never appear in URLs. Print CSS in
 * index.css provides a clean fallback; the backend PDF is authoritative.
 */
export default function ReportCenterPage(): ReactNode {
  const { analysisId = "" } = useParams();
  const { organizationId } = useAuth();
  const toast = useToast();
  const [mode, setMode] = useState<"executive" | "technical">("executive");

  const detailQuery = useQuery({
    queryKey: ["org", organizationId, "analyses", analysisId],
    queryFn: ({ signal }) => getAnalysis(analysisId, { signal }),
    enabled: organizationId !== null && analysisId !== "",
  });
  const reportQuery = useQuery({
    queryKey: ["org", organizationId, "analyses", analysisId, "report-json"],
    queryFn: ({ signal }) => fetchReportJson(analysisId, { signal }),
    enabled:
      organizationId !== null && analysisId !== "" && detailQuery.data?.status === "succeeded",
    retry: false,
  });

  if (detailQuery.isPending) return <Skeleton label="Loading report" rows={5} />;
  if (detailQuery.isError || detailQuery.data === undefined) {
    return (
      <p role="alert" className="text-sm text-sev-critical">
        Analysis not found.{" "}
        {detailQuery.error instanceof ApiError ? detailQuery.error.userMessage() : ""}
      </p>
    );
  }
  const detail = detailQuery.data;
  const status = assessmentStatus(detail);
  const coverage = evidenceCoverage(detail);
  const withheld = detail.risk_score === null || detail.security_score === null;
  const partialNote =
    status !== "assessed" ? (
      <div role="note" className="rounded border border-sev-medium bg-surface-sunken p-3 text-sm">
        <strong>{status === "partial" ? "Partial assessment." : "Insufficient evidence."}</strong>{" "}
        Scores are {withheld ? "withheld" : "shown with reduced coverage"} because these facts are
        not observable: {missingKeyFacts(detail).join("; ") || "none recorded"}. Unknown settings
        are gaps, never passes. This report is not a certification or compliance claim.
      </div>
    ) : null;

  const findings = [...detail.findings, ...detail.evidence_gaps];
  const topRisks = [...findings]
    .sort((a, b) => a.rule_id.localeCompare(b.rule_id))
    .filter((f) => f.severity === "critical" || f.severity === "high" || f.severity === "medium")
    .slice(0, 5);
  const evidence = allEvidence(detail);

  const download = (format: "pdf" | "json"): void => {
    void downloadReport(analysisId, format).catch((error: unknown) =>
      toast.push("error", error instanceof ApiError ? error.userMessage() : "Download failed."),
    );
  };

  return (
    <section aria-labelledby="report-heading" className="report-print space-y-6">
      <div className="print-hidden flex items-center justify-between">
        <Link
          to={`/analyses/${analysisId}`}
          className="text-xs font-medium text-[#0066cc] hover:underline inline-flex items-center gap-1"
        >
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M10 19l-7-7m0 0l7-7m-7 7h18"
            />
          </svg>
          Back to analysis
        </Link>
        <span className="rounded-full border border-[#e6e6e8] bg-[#fafafc] px-3 py-1 font-mono text-[11px] text-[#707070]">
          {analysisId}
        </span>
      </div>

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1
            id="report-heading"
            className="font-display text-2xl font-semibold tracking-tight text-[#1d1d1f]"
          >
            Audit Report Center
          </h1>
          <p className="mt-1 text-xs text-[#707070]">
            Authoritative zero-trust compliance assessment &amp; cryptographic evaluation
          </p>
        </div>

        {/* Apple Segmented Control */}
        <div
          role="tablist"
          aria-label="Report view mode"
          className="print-hidden inline-flex rounded-full border border-[#e6e6e8] bg-[#ffffff] p-1 shadow-sm"
        >
          {(["executive", "technical"] as const).map((m) => (
            <button
              key={m}
              type="button"
              role="tab"
              aria-selected={mode === m}
              onClick={() => setMode(m)}
              className={`rounded-full px-4 py-1.5 text-xs font-medium transition ${
                mode === m
                  ? "bg-[#1d1d1f] text-white shadow-sm"
                  : "text-[#707070] hover:text-[#1d1d1f]"
              }`}
            >
              {m === "executive" ? "Executive View" : "Technical View"}
            </button>
          ))}
        </div>
      </div>

      {/* Action Toolbar */}
      <div className="print-hidden apple-card p-4 flex flex-wrap items-center justify-between gap-3">
        <ReportExportButton detail={detail} />
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => download("pdf")}
            className="apple-btn-secondary text-xs"
          >
            Download PDF
          </button>
          <button
            type="button"
            onClick={() => download("json")}
            className="apple-btn-secondary text-xs"
          >
            Download JSON
          </button>
          {reportQuery.isSuccess && (
            <span className="ml-2 text-[11px] text-[#86868b]">
              Schema v{String(reportQuery.data["report_version"] ?? "1.0")}
            </span>
          )}
        </div>
      </div>

      {mode === "executive" ? (
        <div role="tabpanel" aria-label="Executive report" className="space-y-6">
          <h2 className="font-display text-lg font-semibold tracking-tight text-[#1d1d1f]">
            Executive posture summary
          </h2>
          {partialNote}

          {/* 3 Large Metric Cards */}
          <div className="grid gap-4 md:grid-cols-3">
            <div className="apple-card p-6">
              <span className="text-xs font-medium text-[#707070]">Assessment Status</span>
              <p className="mt-2 font-display text-2xl font-semibold capitalize text-[#1d1d1f]">
                {status}
              </p>
              <p className="mt-1 text-xs text-[#86868b]">Strict multi-domain verification</p>
            </div>
            <div className="apple-card p-6">
              <span className="text-xs font-medium text-[#707070]">
                Security Score / Risk Index
              </span>
              <p className="mt-2 font-display text-2xl font-semibold text-[#1d1d1f]">
                {withheld ? (
                  <span className="text-sm font-medium text-[#707070]">
                    Withheld (Evidence Gap)
                  </span>
                ) : (
                  `${detail.security_score} / 100`
                )}
              </p>
              <p className="mt-1 text-xs text-[#86868b]">
                {withheld
                  ? "Requires observable transform facts"
                  : `Evidence coverage ${coverage}% · Risk: ${detail.risk_score}/100`}
              </p>
            </div>
            <div className="apple-card p-6">
              <span className="text-xs font-medium text-[#707070]">Policy Benchmark</span>
              <p className="mt-2 font-mono text-xl font-semibold text-[#1d1d1f]">
                {detail.policy_version}
              </p>
              <p className="mt-1 text-xs text-[#86868b]">RFC 7296 &amp; NIST SP 800-77 benchmark</p>
            </div>
          </div>

          {/* Top Prioritized Risks */}
          <div className="apple-card p-6 space-y-4">
            <h3 className="font-display text-base font-semibold text-[#1d1d1f]">
              Top Prioritized Security Findings
            </h3>
            {topRisks.length === 0 ? (
              <p className="text-sm text-[#707070]">
                No high or critical findings recorded. Note that visibility limitations may withhold
                conclusions.
              </p>
            ) : (
              <div className="space-y-2.5">
                {topRisks.map((f, i) => (
                  <div
                    key={`${f.rule_id}-${i}`}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-[18px] border border-[#e6e6e8] bg-[#fafafc] p-3.5 text-xs"
                  >
                    <div className="flex items-center gap-2.5">
                      <SeverityBadge severity={f.severity as Severity} />
                      <span className="font-mono font-medium text-[#1d1d1f]">{f.rule_id}</span>
                    </div>
                    <span className="font-mono text-[#707070]">
                      observed:{" "}
                      <strong className="text-[#1d1d1f]">{JSON.stringify(f.actual_value)}</strong>
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Remediation Roadmap */}
          <div className="apple-card p-6 space-y-4">
            <h3 className="font-display text-base font-semibold text-[#1d1d1f]">
              Recommended Remediation Roadmap
            </h3>
            <ol className="list-decimal space-y-2 pl-5 text-sm text-[#1d1d1f]">
              {findings
                .filter((f) => f.recommendation !== null)
                .slice(0, 6)
                .map((f, i) => (
                  <li
                    key={`${f.rule_id}-${i}`}
                    className="pl-1 text-xs leading-relaxed text-[#1d1d1f]"
                  >
                    <strong className="font-mono text-[#0066cc]">{f.rule_id}</strong>:{" "}
                    {f.recommendation}
                  </li>
                ))}
              {findings.every((f) => f.recommendation === null) && (
                <li className="text-xs text-[#707070]">
                  No rule recommendations recorded for this run.
                </li>
              )}
            </ol>
          </div>

          {/* Key Visibility Limitations */}
          <div className="apple-card p-6 space-y-3">
            <h3 className="font-display text-base font-semibold text-[#1d1d1f]">
              Key Visibility Boundaries &amp; Epistemic Notes
            </h3>
            <ul className="list-disc space-y-1.5 pl-5 text-xs text-[#707070] leading-relaxed">
              {missingKeyFacts(detail).map((m) => (
                <li key={m}>
                  <strong className="text-[#1d1d1f]">{m}</strong> — unknown from the wire (payload
                  encrypted or omitted from capture).
                </li>
              ))}
              <li>
                Traffic categories are probabilistic metadata inferences based on packet timing/size
                distributions — never payload decryption.
              </li>
            </ul>
          </div>
        </div>
      ) : (
        <div role="tabpanel" aria-label="Technical report" className="space-y-6">
          {partialNote}

          {/* Technical Metadata Card */}
          <div className="apple-card p-6 space-y-4">
            <h3 className="font-display text-base font-semibold text-[#1d1d1f]">
              Pipeline Execution Details
            </h3>
            <div className="grid gap-3 sm:grid-cols-2 md:grid-cols-4 text-xs">
              <div className="rounded-[16px] border border-[#e6e6e8] bg-[#fafafc] p-3">
                <span className="text-[#707070]">Pipeline Engine</span>
                <p className="mt-1 font-mono font-medium text-[#1d1d1f]">
                  {detail.pipeline_version}
                </p>
              </div>
              <div className="rounded-[16px] border border-[#e6e6e8] bg-[#fafafc] p-3">
                <span className="text-[#707070]">Inference Model</span>
                <p className="mt-1 font-mono font-medium text-[#1d1d1f]">
                  {detail.model_version ?? "None"}
                </p>
              </div>
              <div className="rounded-[16px] border border-[#e6e6e8] bg-[#fafafc] p-3">
                <span className="text-[#707070]">Policy Profile</span>
                <p className="mt-1 font-mono font-medium text-[#1d1d1f]">{detail.policy_version}</p>
              </div>
              <div className="rounded-[16px] border border-[#e6e6e8] bg-[#fafafc] p-3">
                <span className="text-[#707070]">Queue Time</span>
                <p className="mt-1 font-mono font-medium text-[#1d1d1f]">{detail.queued_at}</p>
              </div>
            </div>

            <div className="pt-2">
              <ConfidenceMeter
                value={
                  detail.packet_observed_facts.length > 0
                    ? detail.packet_observed_facts
                        .map((e) => e.confidence)
                        .filter((c): c is number => c !== null)
                        .reduce((a, b, _i, arr) => a + b / arr.length, 0) || null
                    : null
                }
                kind="protocol"
              />
            </div>
          </div>

          {/* Evidence Table */}
          <div className="apple-card p-6 space-y-4">
            <h3 className="font-display text-base font-semibold text-[#1d1d1f]">
              Protocol Evidence (Provenance &amp; Frame Tracing)
            </h3>
            <div className="overflow-x-auto rounded-[20px] border border-[#e6e6e8]">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-[#e6e6e8] bg-[#fafafc] text-[#707070]">
                    <th scope="col" className="px-4 py-3 font-medium">
                      Fact Identifier
                    </th>
                    <th scope="col" className="px-4 py-3 font-medium">
                      Observed Value
                    </th>
                    <th scope="col" className="px-4 py-3 font-medium">
                      Provenance
                    </th>
                    <th scope="col" className="px-4 py-3 font-medium">
                      Packet Frames
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#e6e6e8] bg-white">
                  {evidence.map((item) => (
                    <tr key={item.id} className="hover:bg-[#fafafc]">
                      <td className="px-4 py-2.5 font-mono text-[#1d1d1f]">{item.fact_name}</td>
                      <td className="px-4 py-2.5 font-mono text-[#707070]">
                        {JSON.stringify(item.fact_value)}
                      </td>
                      <td className="px-4 py-2.5">
                        <ProvenanceBadge source={asSource(item.source)} />
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[#0066cc]">
                        {(item.packet_refs ?? [])
                          .map((r) => `#${String((r as { frame?: unknown }).frame ?? "?")}`)
                          .join(" ") || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Findings List */}
          <div className="apple-card p-6 space-y-4">
            <h3 className="font-display text-base font-semibold text-[#1d1d1f]">
              Rule-by-rule findings (actual vs expected)
            </h3>
            <div className="space-y-3">
              {findings.map((f, i) => (
                <div
                  key={`${f.rule_id}-${i}`}
                  className="rounded-[20px] border border-[#e6e6e8] bg-[#fafafc] p-4 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={f.severity as Severity} />
                      <span className="font-mono font-semibold text-[#1d1d1f]">{f.rule_id}</span>
                    </div>
                  </div>
                  <p className="mt-2 font-mono text-[11px] text-[#707070]">
                    actual:{" "}
                    <strong className="text-[#1d1d1f]">{JSON.stringify(f.actual_value)}</strong> ·
                    expected:{" "}
                    <strong className="text-[#1d1d1f]">{JSON.stringify(f.expected_value)}</strong>
                  </p>
                  {f.recommendation !== null && (
                    <p className="mt-1.5 text-xs text-[#1d1d1f]">Remediation: {f.recommendation}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
