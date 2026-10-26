import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Suspense, lazy, useState } from "react";
import { Link, useParams } from "react-router";

import { ApiError, downloadReport, getAnalysis, retryAnalysis } from "@/api/client";
import type { AnalysisDetail } from "@/api/client";
import { useToast } from "@/app/toast-context";
import { RiskGauge, ScoreBar, SeverityBadge } from "@/components/badges";
import type { Severity } from "@/components/badges";
import {
  ConfidenceMeter,
  FrameReferenceList,
  ProvenanceBadge,
  UnknownValue,
} from "@/components/epistemic";
import { Skeleton, StatusPill } from "@/components/ui";
import { useAuth } from "@/features/auth/auth-context";
import { RequireAction } from "@/features/auth/guards";
import { formatTimestamp } from "@/lib/format";
import { assessmentLabel } from "@/lib/permissions";

import { allEvidence, asSource, isUnknown } from "./evidence-lib";
import type { Evidence } from "./evidence-lib";
import AssessmentTab from "./AssessmentTab";
import ComplianceMatrix from "./ComplianceMatrix";
import InspectorTab from "./InspectorTab";
import LiveAnalysisFeed from "./LiveAnalysisFeed";
import ReportExportButton from "./ReportExportButton";
import TrafficTab from "./TrafficTab";
import ThreatTimeline from "./ThreatTimeline";
const CryptoGraph3D = lazy(() => import("./CryptoGraph3D"));

type TabId =
  | "overview"
  | "assessment"
  | "compliance"
  | "crypto3d"
  | "timeline"
  | "feed"
  | "inspector"
  | "traffic"
  | "findings"
  | "evidence"
  | "report";

function PollStatus({
  status,
  detail,
}: {
  status: string;
  detail?: AnalysisDetail | undefined;
}): ReactNode {
  if (status === "queued") {
    return (
      <div className="mb-4 space-y-2">
        <p role="status" className="text-ink-muted">
          Stage: queued — waiting for an analysis worker.
        </p>
        {detail && <LiveAnalysisFeed detail={detail} />}
      </div>
    );
  }
  if (status === "running") {
    return (
      <div className="mb-4 space-y-2">
        <p role="status" aria-live="polite" className="text-ink-muted">
          Stage: running — packet parsing and evidence extraction in progress. This page refreshes
          automatically.
        </p>
        {detail && <LiveAnalysisFeed detail={detail} />}
      </div>
    );
  }
  return null;
}

export default function AnalysisDetailPage(): ReactNode {
  const { analysisId = "" } = useParams();
  const { organizationId } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<TabId>("overview");
  const [provenanceFilter, setProvenanceFilter] = useState<string>("");

  const detailQuery = useQuery({
    queryKey: ["org", organizationId, "analyses", analysisId],
    queryFn: ({ signal }) => getAnalysis(analysisId, { signal }),
    enabled: organizationId !== null && analysisId !== "",
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "queued" || status === "running" ? 2_000 : false;
    },
    refetchIntervalInBackground: false,
  });

  const retryMutation = useMutation({
    mutationFn: () => retryAnalysis(analysisId),
    onSuccess: async () => {
      toast.push("success", "Analysis re-queued.");
      await queryClient.invalidateQueries({
        queryKey: ["org", organizationId, "analyses", analysisId],
      });
      await detailQuery.refetch();
    },
    onError: (error: Error) =>
      toast.push("error", error instanceof ApiError ? error.userMessage() : "Retry failed."),
  });

  if (detailQuery.isPending) return <Skeleton label="Loading analysis" rows={5} />;
  if (detailQuery.isError || detailQuery.data === undefined) {
    return (
      <p role="alert" className="text-sm text-sev-critical">
        Analysis not found.{" "}
        {detailQuery.error instanceof ApiError ? detailQuery.error.userMessage() : ""}
      </p>
    );
  }

  const detail: AnalysisDetail = detailQuery.data;
  const run = detail;
  const evidence = allEvidence(detail);
  const filteredEvidence: Evidence[] =
    provenanceFilter === ""
      ? evidence
      : evidence.filter((e) => asSource(e.source) === provenanceFilter);
  // Deterministic protocol-evidence confidence: mean of packet-observed fact
  // confidences (never merged with model probability).
  const observedConfidences = detail.packet_observed_facts
    .map((e) => e.confidence)
    .filter((c): c is number => c !== null);
  const protocolConfidence =
    observedConfidences.length > 0
      ? observedConfidences.reduce((a, b) => a + b, 0) / observedConfidences.length
      : null;

  const tabs: { id: TabId; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "assessment", label: "Security Assessment & Threat Matrix" },
    { id: "compliance", label: "Compliance Matrix" },
    { id: "crypto3d", label: "3D Crypto Graph" },
    { id: "timeline", label: "Threat Timeline" },
    { id: "feed", label: "Live Telemetry Feed" },
    { id: "inspector", label: "Protocol & Security Inspector" },
    { id: "traffic", label: "AI Traffic Inference & Metadata" },
    { id: "findings", label: `Findings (${detail.findings.length})` },
    { id: "evidence", label: `Evidence (${evidence.length})` },
    { id: "report", label: "Report" },
  ];

  return (
    <section aria-labelledby="analysis-heading" className="space-y-6">
      <div>
        <p className="text-xs font-medium text-[#707070]">
          <Link to={`/captures/${run.capture_id}`} className="text-[#0066cc] hover:underline">
            ← Capture <span className="mono">{run.capture_id}</span>
          </Link>
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <h1
            id="analysis-heading"
            className="font-display text-2xl font-semibold tracking-tight text-[#1d1d1f] md:text-3xl"
          >
            Cryptographic Analysis
          </h1>
          <StatusPill status={run.status} />
          <span className="mono text-xs text-[#707070]">{run.id}</span>
        </div>
      </div>

      <div className="text-sm">
        <PollStatus status={run.status} detail={detail} />
        {run.status === "failed" && (
          <div
            role="alert"
            className="rounded-2xl border border-[#d70015]/30 bg-[#d70015]/5 p-4 text-[#1d1d1f]"
          >
            <p className="font-semibold text-[#d70015]">
              Run failed. Safe error code:{" "}
              <span className="mono">{run.error_code ?? "not reported"}</span>
            </p>
            <RequireAction action="analyses:run">
              <button
                type="button"
                disabled={retryMutation.isPending}
                onClick={() => retryMutation.mutate()}
                className="apple-btn-primary mt-3 text-xs disabled:opacity-50"
              >
                Retry analysis
              </button>
            </RequireAction>
          </div>
        )}
      </div>

      <dl className="flex flex-wrap gap-x-6 gap-y-2 rounded-2xl border border-[#e6e6e8] bg-[#ffffff] p-4 text-xs text-[#707070]">
        <span>
          Queued:{" "}
          <span className="tnum font-medium text-[#1d1d1f]">{formatTimestamp(run.queued_at)}</span>
        </span>
        <span>
          Started:{" "}
          <span className="tnum font-medium text-[#1d1d1f]">
            {run.started_at !== null ? formatTimestamp(run.started_at) : "not started"}
          </span>
        </span>
        <span>
          Finished:{" "}
          <span className="tnum font-medium text-[#1d1d1f]">
            {run.finished_at !== null ? formatTimestamp(run.finished_at) : "not finished"}
          </span>
        </span>
        <span>
          Pipeline:{" "}
          <span className="mono font-semibold text-[#1d1d1f]">{run.pipeline_version}</span>
        </span>
        <span>
          Model:{" "}
          <span className="mono font-medium text-[#1d1d1f]">
            {run.model_version ?? "not reported"}
          </span>
        </span>
        <span>
          Policy: <span className="mono font-semibold text-[#1d1d1f]">{run.policy_version}</span>
        </span>
        <span>
          Attempts: <span className="tnum font-medium text-[#1d1d1f]">{run.attempts}</span>
        </span>
      </dl>

      {/* Apple Chapter / Tab Switcher */}
      <div
        role="tablist"
        aria-label="Analysis sections"
        className="flex flex-wrap items-center gap-1.5 rounded-[22px] border border-[#e6e6e8] bg-[#ffffff] p-1.5"
      >
        {tabs.map((t) => {
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              role="tab"
              id={`tab-${t.id}`}
              aria-selected={active}
              aria-controls={`panel-${t.id}`}
              onClick={() => setTab(t.id)}
              className={`rounded-full px-3.5 py-1.5 text-xs font-medium tracking-tight transition-all duration-150 ${
                active
                  ? "bg-[#1d1d1f] text-[#ffffff] shadow-sm"
                  : "text-[#707070] hover:text-[#1d1d1f] hover:bg-[#f5f5f7]"
              }`}
            >
              {t.label}
            </button>
          );
        })}
      </div>

      {tab === "overview" && (
        <div
          role="tabpanel"
          id="panel-overview"
          aria-labelledby="tab-overview"
          className="apple-card p-6 space-y-6"
        >
          <div>
            <p className="text-xs uppercase tracking-wider text-[#707070]">Assessment State</p>
            <p className="font-display text-2xl font-semibold tracking-tight text-[#1d1d1f] mt-1">
              {assessmentLabel(run)}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-8 pt-2">
            <RiskGauge value={run.risk_score} />
            <ScoreBar label="Security score" value={run.security_score} max={100} />
          </div>
          <div className="pt-2">
            <ConfidenceMeter value={protocolConfidence} kind="protocol" />
          </div>
          <p className="max-w-3xl text-xs leading-relaxed text-[#707070] pt-2 border-t border-[#f5f5f7]">
            Scores are computed only from observable evidence. A missing score means the evidence
            was insufficient or the assessment partial — it is never a default pass.
          </p>
        </div>
      )}

      {tab === "assessment" && (
        <div
          role="tabpanel"
          id="panel-assessment"
          aria-labelledby="tab-assessment"
          className="space-y-4"
        >
          <AssessmentTab detail={detail} />
        </div>
      )}

      {tab === "compliance" && (
        <div
          role="tabpanel"
          id="panel-compliance"
          aria-labelledby="tab-compliance"
          className="space-y-4"
        >
          <ComplianceMatrix detail={detail} />
        </div>
      )}

      {tab === "crypto3d" && (
        <div
          role="tabpanel"
          id="panel-crypto3d"
          aria-labelledby="tab-crypto3d"
          className="space-y-4"
        >
          <Suspense fallback={<p className="text-sm text-[#707070]">Loading 3D engine…</p>}>
            <CryptoGraph3D detail={detail} />
          </Suspense>
        </div>
      )}

      {tab === "timeline" && (
        <div
          role="tabpanel"
          id="panel-timeline"
          aria-labelledby="tab-timeline"
          className="space-y-4"
        >
          <ThreatTimeline detail={detail} />
        </div>
      )}

      {tab === "feed" && (
        <div role="tabpanel" id="panel-feed" aria-labelledby="tab-feed" className="space-y-4">
          <LiveAnalysisFeed detail={detail} />
        </div>
      )}

      {tab === "inspector" && (
        <div
          role="tabpanel"
          id="panel-inspector"
          aria-labelledby="tab-inspector"
          className="apple-card p-6 space-y-4"
        >
          <InspectorTab detail={detail} />
        </div>
      )}

      {tab === "traffic" && (
        <div
          role="tabpanel"
          id="panel-traffic"
          aria-labelledby="tab-traffic"
          className="apple-card p-6 space-y-4"
        >
          <TrafficTab detail={detail} />
        </div>
      )}

      {tab === "findings" && (
        <div
          role="tabpanel"
          id="panel-findings"
          aria-labelledby="tab-findings"
          className="apple-card p-6 space-y-4"
        >
          <h3 className="font-display text-lg font-semibold text-[#1d1d1f]">
            Identified Cryptographic Findings
          </h3>
          {detail.findings.length === 0 && detail.evidence_gaps.length === 0 ? (
            <p className="text-sm text-[#707070]">
              No findings recorded. Absence of findings is not evidence of security.
            </p>
          ) : (
            <ul className="space-y-3">
              {[...detail.findings, ...detail.evidence_gaps].map((finding, i) => (
                <li
                  key={`${finding.rule_id}-${i}`}
                  className="rounded-2xl border border-[#e6e6e8] bg-[#fafafc] p-4 transition hover:bg-[#ffffff]"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={finding.severity as Severity} />
                    <span className="mono text-xs font-semibold text-[#1d1d1f]">
                      {finding.rule_id}
                    </span>
                    <span className="text-xs text-[#707070]">status: {finding.status}</span>
                  </div>
                  <dl className="mt-3 space-y-1.5 text-xs">
                    <div>
                      <dt className="inline font-semibold text-[#707070]">Observed: </dt>
                      <dd className="mono inline text-[#1d1d1f]">
                        {JSON.stringify(finding.actual_value)}
                      </dd>
                    </div>
                    <div>
                      <dt className="inline font-semibold text-[#707070]">Expected: </dt>
                      <dd className="mono inline text-[#1d1d1f]">
                        {JSON.stringify(finding.expected_value)}
                      </dd>
                    </div>
                    {finding.recommendation !== null && (
                      <p className="text-[#1d1d1f] pt-1">
                        <strong className="text-[#0071e3]">Recommendation:</strong>{" "}
                        {finding.recommendation}
                      </p>
                    )}
                    {finding.policy_version !== null && (
                      <p className="text-[11px] text-[#707070]">
                        Policy: <span className="mono">{finding.policy_version}</span>
                      </p>
                    )}
                  </dl>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {tab === "evidence" && (
        <div
          role="tabpanel"
          id="panel-evidence"
          aria-labelledby="tab-evidence"
          className="apple-card p-6 space-y-4"
        >
          <div className="flex items-center justify-between">
            <h3 className="font-display text-lg font-semibold text-[#1d1d1f]">Evidence Store</h3>
            <label className="flex items-center gap-2 text-xs font-medium text-[#707070]">
              Provenance:
              <select
                value={provenanceFilter}
                onChange={(e) => setProvenanceFilter(e.target.value)}
                className="rounded-full border border-[#d6d6d6] bg-white px-3 py-1 text-xs text-[#1d1d1f] focus:outline-none focus:border-[#0071e3]"
              >
                <option value="">All provenance</option>
                <option value="packet_observed">Packet Observed</option>
                <option value="lab_manifest">Lab Manifest</option>
                <option value="analyst_supplied">Analyst Supplied</option>
                <option value="model_inferred">Model Inferred</option>
                <option value="unknown">Unknown / Encrypted</option>
              </select>
            </label>
          </div>

          {filteredEvidence.length === 0 ? (
            <p className="text-sm text-[#707070]">No evidence matches this filter.</p>
          ) : (
            <ul className="space-y-3">
              {filteredEvidence.map((item) => (
                <li
                  key={item.id}
                  className="rounded-2xl border border-[#e6e6e8] bg-[#fafafc] p-4 transition hover:bg-[#ffffff]"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <ProvenanceBadge source={asSource(item.source)} />
                    <span className="mono text-xs font-semibold text-[#1d1d1f]">
                      {item.fact_name}
                    </span>
                    {item.confidence !== null && (
                      <span className="tnum text-xs font-medium text-[#0071e3]">
                        confidence {Math.round(item.confidence * 100)}%
                      </span>
                    )}
                    {isUnknown(item) && (
                      <span className="text-xs font-medium text-[#b64400]">
                        unknown / not observable
                      </span>
                    )}
                  </div>
                  <pre className="mono mt-2 overflow-x-auto whitespace-pre-wrap rounded-xl bg-white p-3 text-xs border border-[#e6e6e8]">
                    {JSON.stringify(item.fact_value, null, 2)}
                  </pre>
                  {item.limitation !== null && (
                    <p className="mt-2 text-xs font-medium text-[#b64400]">
                      Limitation: {item.limitation}
                    </p>
                  )}
                  <div className="mt-2">
                    <FrameReferenceList frames={(item.packet_refs ?? []) as never[]} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {tab === "report" && (
        <div
          role="tabpanel"
          id="panel-report"
          aria-labelledby="tab-report"
          className="apple-card p-6 space-y-6"
        >
          <div>
            <h3 className="font-display text-lg font-semibold text-[#1d1d1f]">
              Audit Report Dispatch
            </h3>
            <p className="mt-1 max-w-3xl text-xs leading-relaxed text-[#707070]">
              Download the versioned JSON or vector PDF report. Reports are fetched as authenticated
              blobs — tokens are never placed in URLs.
            </p>
            <div className="mt-4">
              <Link to={`/analyses/${analysisId}/report`} className="apple-btn-primary text-xs">
                Open Full Report Center (Executive & Technical)
              </Link>
            </div>
          </div>

          <div className="rounded-2xl border border-[#e6e6e8] bg-[#fafafc] p-5">
            <h4 className="text-sm font-semibold text-[#1d1d1f]">Instant Compliance Export</h4>
            <p className="mt-1 text-xs text-[#707070]">
              Generate a client-side vector PDF audit document or structured machine-readable
              compliance JSON with RFC citations.
            </p>
            <div className="mt-4">
              <ReportExportButton detail={detail} />
            </div>
          </div>

          <div className="space-y-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#707070]">
              Authoritative Server Reports
            </h4>
            <div className="flex gap-3">
              {(["json", "pdf"] as const).map((format) => (
                <button
                  key={format}
                  type="button"
                  className="apple-btn-secondary px-4 py-2 text-xs"
                  onClick={() =>
                    void downloadReport(analysisId, format).catch((error: unknown) =>
                      toast.push(
                        "error",
                        error instanceof ApiError ? error.userMessage() : "Report download failed.",
                      ),
                    )
                  }
                >
                  Download {format.toUpperCase()} report
                </button>
              ))}
            </div>
          </div>
          {run.status !== "succeeded" && (
            <div className="pt-2">
              <UnknownValue reason="Reports are available once the run succeeds." />
            </div>
          )}
        </div>
      )}
    </section>
  );
}
