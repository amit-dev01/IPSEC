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
    <section aria-labelledby="report-heading" className="report-print">
      <p className="text-sm text-ink-muted print-hidden">
        <Link to={`/analyses/${analysisId}`} className="underline">
          ← Back to analysis
        </Link>
      </p>
      <div className="mt-1 flex flex-wrap items-center gap-3">
        <h1 id="report-heading" className="text-xl font-semibold">
          Report Center
        </h1>
        <span className="mono text-sm">{analysisId}</span>
      </div>

      <div
        role="tablist"
        aria-label="Report view mode"
        className="print-hidden mt-4 flex gap-1 border-b border-line"
      >
        {(["executive", "technical"] as const).map((m) => (
          <button
            key={m}
            role="tab"
            aria-selected={mode === m}
            onClick={() => setMode(m)}
            className={`rounded-t px-3 py-2 text-sm capitalize ${mode === m ? "bg-surface-sunken font-medium" : ""}`}
          >
            {m === "executive" ? "Executive View" : "Technical View"}
          </button>
        ))}
      </div>

      <div className="print-hidden mt-3 flex gap-2">
        <button
          type="button"
          onClick={() => download("pdf")}
          className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-accent-ink"
        >
          Download PDF (authoritative)
        </button>
        <button
          type="button"
          onClick={() => download("json")}
          className="rounded border border-line px-3 py-1.5 text-sm"
        >
          Download JSON
        </button>
        {reportQuery.isSuccess && (
          <span className="text-xs text-ink-muted">
            Structured report v{String(reportQuery.data["report_version"] ?? "1.0")} loaded from the
            backend.
          </span>
        )}
      </div>

      {mode === "executive" ? (
        <div role="tabpanel" aria-label="Executive report" className="space-y-4 py-4">
          <h2 className="text-lg font-medium">Executive posture summary</h2>
          {partialNote}
          <dl className="grid gap-3 text-sm md:grid-cols-3">
            <div className="rounded border border-line p-3">
              <dt className="text-ink-muted">Assessment status</dt>
              <dd className="text-lg font-medium">{status}</dd>
            </div>
            <div className="rounded border border-line p-3">
              <dt className="text-ink-muted">Risk / Security (with coverage)</dt>
              <dd className="tnum text-lg">
                {withheld
                  ? "Score Withheld — Insufficient Evidence"
                  : `${detail.risk_score} / ${detail.security_score} · coverage ${coverage}%`}
              </dd>
            </div>
            <div className="rounded border border-line p-3">
              <dt className="text-ink-muted">Policy</dt>
              <dd className="mono text-lg">{detail.policy_version}</dd>
            </div>
          </dl>

          <h3 className="font-medium">Top prioritized risks</h3>
          {topRisks.length === 0 ? (
            <p className="text-sm text-ink-muted">
              No high/medium findings recorded. That is not a guarantee of safety — see visibility
              limitations below.
            </p>
          ) : (
            <ol className="space-y-2">
              {topRisks.map((f, i) => (
                <li key={`${f.rule_id}-${i}`} className="flex flex-wrap items-center gap-2 text-sm">
                  <SeverityBadge severity={f.severity as Severity} />
                  <span className="mono text-xs">{f.rule_id}</span>
                  <span>observed {JSON.stringify(f.actual_value)}</span>
                </li>
              ))}
            </ol>
          )}

          <h3 className="font-medium">Remediation roadmap</h3>
          <ol className="list-decimal space-y-1 pl-5 text-sm">
            {findings
              .filter((f) => f.recommendation !== null)
              .slice(0, 6)
              .map((f, i) => (
                <li key={`${f.rule_id}-${i}`}>
                  <span className="mono text-xs">{f.rule_id}</span>: {f.recommendation}
                </li>
              ))}
            {findings.every((f) => f.recommendation === null) && (
              <li>No rule recommendations recorded for this run.</li>
            )}
          </ol>

          <h3 className="font-medium">Key visibility limitations</h3>
          <ul className="list-disc space-y-1 pl-5 text-sm">
            {missingKeyFacts(detail).map((m) => (
              <li key={m}>{m} — unknown from the wire (encrypted or not in capture).</li>
            ))}
            <li>
              Traffic categories, when present, are probabilistic metadata inference — not payload
              inspection or application identification.
            </li>
          </ul>
        </div>
      ) : (
        <div role="tabpanel" aria-label="Technical report" className="space-y-4 py-4">
          <h2 className="text-lg font-medium">Technical report</h2>
          {partialNote}
          <dl className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
            <span>
              Pipeline: <span className="mono">{detail.pipeline_version}</span>
            </span>
            <span>
              Model: <span className="mono">{detail.model_version ?? "not reported"}</span>
            </span>
            <span>
              Policy: <span className="mono">{detail.policy_version}</span>
            </span>
            <span>
              Queued (UTC): <span className="tnum">{detail.queued_at}</span>
            </span>
            <span>
              Finished (UTC): <span className="tnum">{detail.finished_at ?? "not finished"}</span>
            </span>
          </dl>
          <div className="flex flex-wrap gap-8">
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

          <h3 className="font-medium">Protocol evidence (provenance + frame references)</h3>
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-line text-left">
                <th scope="col" className="py-2 pr-3">
                  Fact
                </th>
                <th scope="col" className="py-2 pr-3">
                  Value
                </th>
                <th scope="col" className="py-2 pr-3">
                  Provenance
                </th>
                <th scope="col" className="py-2">
                  Frames
                </th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((item) => (
                <tr key={item.id} className="border-b border-line align-top">
                  <td className="mono py-2 pr-3 text-xs">{item.fact_name}</td>
                  <td className="mono py-2 pr-3 text-xs">{JSON.stringify(item.fact_value)}</td>
                  <td className="py-2 pr-3">
                    <ProvenanceBadge source={asSource(item.source)} />
                  </td>
                  <td className="mono py-2 text-xs">
                    {(item.packet_refs ?? [])
                      .map((r) => `#${String((r as { frame?: unknown }).frame ?? "?")}`)
                      .join(" ") || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <h3 className="font-medium">Rule-by-rule findings (actual vs expected)</h3>
          <ul className="space-y-2 text-sm">
            {findings.map((f, i) => (
              <li key={`${f.rule_id}-${i}`} className="rounded border border-line p-3">
                <span className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity as Severity} />
                  <span className="mono text-xs">{f.rule_id}</span>
                </span>
                <p className="mono mt-1 text-xs">
                  actual {JSON.stringify(f.actual_value)} · expected{" "}
                  {JSON.stringify(f.expected_value)}
                </p>
                {f.recommendation !== null && (
                  <p className="mt-1">Remediation: {f.recommendation}</p>
                )}
              </li>
            ))}
          </ul>
          <p className="text-sm text-ink-muted">
            Unknowns/encrypted gaps are listed in the Evidence and Inspector views; probabilistic
            traffic analysis appears in the AI Traffic tab with its methodological notice.
          </p>
        </div>
      )}
    </section>
  );
}
