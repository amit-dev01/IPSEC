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
  if (status === "queued" || status === "running") {
    return <div className="mb-4">{detail && <LiveAnalysisFeed detail={detail} />}</div>;
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
    <section aria-labelledby="analysis-heading">
      <p className="text-sm text-ink-muted">
        <Link to={`/captures/${run.capture_id}`} className="underline">
          ← Capture <span className="mono">{run.capture_id}</span>
        </Link>
      </p>
      <div className="mt-1 flex flex-wrap items-center gap-3">
        <h1 id="analysis-heading" className="text-xl font-semibold">
          Analysis
        </h1>
        <StatusPill status={run.status} />
        <span className="mono text-sm">{run.id}</span>
      </div>

      <div className="mt-2 text-sm">
        <PollStatus status={run.status} detail={detail} />
        {run.status === "failed" && (
          <div role="alert" className="mt-2 rounded border border-sev-critical p-3">
            <p>
              <strong>Run failed.</strong> Safe error code:{" "}
              <span className="mono">{run.error_code ?? "not reported"}</span>
            </p>
            <RequireAction action="analyses:run">
              <button
                type="button"
                disabled={retryMutation.isPending}
                onClick={() => retryMutation.mutate()}
                className="mt-2 rounded bg-accent px-3 py-1.5 font-medium text-accent-ink disabled:opacity-50"
              >
                Retry analysis
              </button>
            </RequireAction>
          </div>
        )}
      </div>

      <dl className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-sm">
        <span>
          Queued: <span className="tnum">{formatTimestamp(run.queued_at)}</span>
        </span>
        <span>
          Started:{" "}
          <span className="tnum">
            {run.started_at !== null ? formatTimestamp(run.started_at) : "not started"}
          </span>
        </span>
        <span>
          Finished:{" "}
          <span className="tnum">
            {run.finished_at !== null ? formatTimestamp(run.finished_at) : "not finished"}
          </span>
        </span>
        <span>
          Pipeline: <span className="mono">{run.pipeline_version}</span>
        </span>
        <span>
          Model: <span className="mono">{run.model_version ?? "not reported"}</span>
        </span>
        <span>
          Policy: <span className="mono">{run.policy_version}</span>
        </span>
        <span>
          Attempts: <span className="tnum">{run.attempts}</span>
        </span>
      </dl>

      <div
        role="tablist"
        aria-label="Analysis sections"
        className="mt-6 flex flex-wrap gap-1 border-b border-line"
      >
        {tabs.map((t) => (
          <button
            key={t.id}
            role="tab"
            id={`tab-${t.id}`}
            aria-selected={tab === t.id}
            aria-controls={`panel-${t.id}`}
            onClick={() => setTab(t.id)}
            className={`rounded-t px-3 py-2 text-sm ${tab === t.id ? "bg-surface-sunken font-medium" : ""}`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <div role="tabpanel" id="panel-overview" aria-labelledby="tab-overview" className="py-4">
          <p className="text-sm text-ink-muted">
            Assessment state: <strong>{assessmentLabel(run)}</strong>
          </p>
          <div className="mt-3 flex flex-wrap gap-8">
            <RiskGauge value={run.risk_score} />
            <ScoreBar label="Security score" value={run.security_score} max={100} />
          </div>
          <div className="mt-4">
            <ConfidenceMeter value={protocolConfidence} kind="protocol" />
          </div>
          <p className="mt-4 max-w-3xl text-sm text-ink-muted">
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
          className="py-4"
        >
          <AssessmentTab detail={detail} />
        </div>
      )}

      {tab === "compliance" && (
        <div
          role="tabpanel"
          id="panel-compliance"
          aria-labelledby="tab-compliance"
          className="py-4"
        >
          <ComplianceMatrix detail={detail} />
        </div>
      )}

      {tab === "crypto3d" && (
        <div role="tabpanel" id="panel-crypto3d" aria-labelledby="tab-crypto3d" className="py-4">
          <Suspense fallback={<p className="text-sm text-ink-muted">Loading 3D engine…</p>}>
            <CryptoGraph3D detail={detail} />
          </Suspense>
        </div>
      )}

      {tab === "timeline" && (
        <div role="tabpanel" id="panel-timeline" aria-labelledby="tab-timeline" className="py-4">
          <ThreatTimeline detail={detail} />
        </div>
      )}

      {tab === "feed" && (
        <div role="tabpanel" id="panel-feed" aria-labelledby="tab-feed" className="py-4">
          <LiveAnalysisFeed detail={detail} />
        </div>
      )}

      {tab === "inspector" && (
        <div role="tabpanel" id="panel-inspector" aria-labelledby="tab-inspector" className="py-4">
          <InspectorTab detail={detail} />
        </div>
      )}

      {tab === "traffic" && (
        <div role="tabpanel" id="panel-traffic" aria-labelledby="tab-traffic" className="py-4">
          <TrafficTab detail={detail} />
        </div>
      )}

      {tab === "findings" && (
        <div role="tabpanel" id="panel-findings" aria-labelledby="tab-findings" className="py-4">
          {detail.findings.length === 0 && detail.evidence_gaps.length === 0 ? (
            <p className="text-sm text-ink-muted">
              No findings recorded. Absence of findings is not evidence of security.
            </p>
          ) : (
            <ul className="space-y-3">
              {[...detail.findings, ...detail.evidence_gaps].map((finding, i) => (
                <li key={`${finding.rule_id}-${i}`} className="rounded border border-line p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={finding.severity as Severity} />
                    <span className="mono text-xs">{finding.rule_id}</span>
                    <span className="text-xs">status: {finding.status}</span>
                  </div>
                  <dl className="mt-2 space-y-1 text-sm">
                    <div>
                      <dt className="inline font-medium">Observed: </dt>
                      <dd className="mono inline">{JSON.stringify(finding.actual_value)}</dd>
                    </div>
                    <div>
                      <dt className="inline font-medium">Expected: </dt>
                      <dd className="mono inline">{JSON.stringify(finding.expected_value)}</dd>
                    </div>
                    {finding.recommendation !== null && (
                      <p className="text-ink-muted">Recommendation: {finding.recommendation}</p>
                    )}
                    {finding.policy_version !== null && (
                      <p className="text-xs text-ink-muted">
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
        <div role="tabpanel" id="panel-evidence" aria-labelledby="tab-evidence" className="py-4">
          <label className="text-sm">
            Filter by provenance{" "}
            <select
              value={provenanceFilter}
              onChange={(e) => setProvenanceFilter(e.target.value)}
              className="rounded border border-line px-2 py-1"
            >
              <option value="">All provenance</option>
              <option value="packet_observed">Packet Observed</option>
              <option value="lab_manifest">Lab Manifest</option>
              <option value="analyst_supplied">Analyst Supplied</option>
              <option value="model_inferred">Model Inferred</option>
              <option value="unknown">Unknown / Encrypted</option>
            </select>
          </label>
          {filteredEvidence.length === 0 ? (
            <p className="mt-3 text-sm text-ink-muted">No evidence matches this filter.</p>
          ) : (
            <ul className="mt-3 space-y-3">
              {filteredEvidence.map((item) => (
                <li key={item.id} className="rounded border border-line p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <ProvenanceBadge source={asSource(item.source)} />
                    <span className="mono text-sm">{item.fact_name}</span>
                    {item.confidence !== null && (
                      <span className="tnum text-xs text-ink-muted">
                        confidence {Math.round(item.confidence * 100)}%
                      </span>
                    )}
                    {isUnknown(item) && (
                      <span className="text-xs font-medium">unknown / not observable</span>
                    )}
                  </div>
                  <pre className="mono mt-2 overflow-x-auto whitespace-pre-wrap text-xs">
                    {JSON.stringify(item.fact_value, null, 2)}
                  </pre>
                  {item.limitation !== null && (
                    <p className="mt-1 text-xs text-sev-medium">Limitation: {item.limitation}</p>
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
        <div role="tabpanel" id="panel-report" aria-labelledby="tab-report" className="py-4">
          <p className="max-w-3xl text-sm text-ink-muted">
            Download the versioned JSON or HTML report. Reports are fetched as authenticated blobs —
            tokens are never placed in URLs.
          </p>
          <p className="mt-3">
            <Link to={`/analyses/${analysisId}/report`} className="underline font-medium">
              Open Report Center (Executive / Technical views)
            </Link>
          </p>

          <div className="mt-4 rounded border border-line bg-surface-raised p-4">
            <h4 className="text-sm font-semibold text-ink-bright">Instant Compliance Export</h4>
            <p className="mt-1 text-xs text-ink-muted">
              Generate a client-side vector PDF audit document or structured machine-readable
              compliance JSON with RFC citations.
            </p>
            <div className="mt-3">
              <ReportExportButton detail={detail} />
            </div>
          </div>

          <div className="mt-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
              Authoritative Server Reports
            </h4>
            <div className="mt-2 flex gap-2">
              {(["json", "pdf"] as const).map((format) => (
                <button
                  key={format}
                  type="button"
                  className="rounded border border-line px-3 py-1.5 text-xs text-ink transition hover:border-signal-violet"
                  onClick={() =>
                    void downloadReport(analysisId, format).catch((error: unknown) =>
                      toast.push(
                        "error",
                        error instanceof ApiError ? error.userMessage() : "Report download failed.",
                      ),
                    )
                  }
                >
                  Download Server {format.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          {run.status !== "succeeded" && (
            <p className="mt-3">
              <UnknownValue reason="Reports are available once the run succeeds." />
            </p>
          )}
        </div>
      )}
    </section>
  );
}
