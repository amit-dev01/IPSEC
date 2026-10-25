import type { ReactNode } from "react";
import { useMemo, useState } from "react";

import type { AnalysisDetail } from "@/api/client";
import { ConfidenceMeter, ProvenanceBadge, UnknownValue } from "@/components/epistemic";
import { ScoreBar, SeverityBadge } from "@/components/badges";
import type { Severity } from "@/components/badges";
import { ScoreRadial } from "@/components/ScoreRadial";

import {
  DOMAINS,
  DOMAIN_STATE_META,
  assessmentStatus,
  domainForRule,
  domainState,
  evidenceCoverage,
  findingKind,
  integrityMode,
  missingKeyFacts,
} from "./assessment-lib";
import type { DomainId, Finding } from "./assessment-lib";
import { allEvidence, asSource } from "./evidence-lib";

const STATUS_META: Record<string, { label: string; icon: string }> = {
  assessed: { label: "Assessed", icon: "✓" },
  partial: { label: "Partial assessment", icon: "◐" },
  insufficient_evidence: { label: "Insufficient evidence", icon: "?" },
};

const KIND_LABEL: Record<string, string> = {
  cryptographic: "Cryptographic finding",
  informational: "Informational / metadata exposure",
  evidence_gap: "Evidence gap",
};

export default function AssessmentTab({ detail }: { detail: AnalysisDetail }): ReactNode {
  const [domainFilter, setDomainFilter] = useState<DomainId | null>(null);
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const status = assessmentStatus(detail);
  const coverage = evidenceCoverage(detail);
  const missing = missingKeyFacts(detail);
  const scoresWithheld = detail.risk_score === null || detail.security_score === null;

  const evidenceById = useMemo(() => {
    const map = new Map<string, ReturnType<typeof allEvidence>[number]>();
    for (const item of allEvidence(detail)) map.set(item.id, item);
    return map;
  }, [detail]);

  const protocolConfidence = useMemo(() => {
    const values = detail.packet_observed_facts
      .map((e) => e.confidence)
      .filter((c): c is number => c !== null);
    return values.length > 0 ? values.reduce((a, b) => a + b, 0) / values.length : null;
  }, [detail]);

  const mlItem = detail.model_inferred_facts.find((e) => e.fact_name === "ml.traffic_category");
  const mlConfidence =
    mlItem?.fact_value !== null &&
    typeof mlItem?.fact_value === "object" &&
    typeof (mlItem.fact_value as { confidence?: unknown }).confidence === "number"
      ? ((mlItem.fact_value as { confidence: number }).confidence as number)
      : (mlItem?.confidence ?? null);

  const combined: Finding[] = useMemo(
    () => [...detail.findings, ...detail.evidence_gaps],
    [detail],
  );
  const filtered = combined.filter(
    (f) =>
      (domainFilter === null || domainForRule(f.rule_id) === domainFilter) &&
      (severityFilter === "" || f.severity === severityFilter) &&
      (statusFilter === "" || f.status === statusFilter),
  );

  const selectedTransforms = JSON.stringify(
    detail.packet_observed_facts.find((e) => e.fact_name === "ike_sa.selected_transforms")
      ?.fact_value ?? "",
  );
  const mode = integrityMode(selectedTransforms);

  /**
   * Per-domain scores: map domainState → approximate 0–100 values.
   * strong=90, exposure=60, weak=25, unknown=null (withheld).
   * These are front-end display approximations derived from packet-observed
   * evidence — they are NOT the authoritative backend scores.
   */
  const DOMAIN_STATE_SCORE: Record<string, number | null> = {
    strong: 90,
    exposure: 60,
    weak: 25,
    unknown: null,
  };

  const domainScores = useMemo(
    () =>
      DOMAINS.map((d) => ({
        label: d.label,
        value: DOMAIN_STATE_SCORE[domainState(detail, d.id)] ?? null,
      })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [detail],
  );

  return (
    <div>
      <div className="flex flex-wrap items-center gap-3">
        <span
          role="img"
          aria-label={`Assessment status: ${STATUS_META[status]?.label ?? status}`}
          className="inline-flex items-center gap-1 rounded border border-line px-2 py-0.5 text-sm font-medium"
        >
          <span aria-hidden="true">{STATUS_META[status]?.icon}</span>
          Assessment: {STATUS_META[status]?.label ?? status}
        </span>
        <span className="text-sm">
          Policy profile: <span className="mono">{detail.policy_version}</span> (active profile
          recorded by the backend for this run)
        </span>
      </div>

      {/* ── Score section: Radial chart + Confidence meters ── */}
      <div className="mt-4 grid gap-4 md:grid-cols-[auto_1fr_auto]">
        {/* Left: Radial donut */}
        <div className="flex items-start justify-center rounded border border-line bg-surface-sunken p-4">
          <ScoreRadial
            securityScore={detail.security_score}
            riskScore={detail.risk_score}
            domains={domainScores}
            coverage={coverage}
          />
        </div>

        {/* Center: Withheld notice or score breakdown */}
        {scoresWithheld ? (
          <div
            role="note"
            aria-label="Score withheld — insufficient evidence"
            className="rounded border border-sev-medium bg-surface-sunken p-4"
          >
            <p className="font-semibold">Score Withheld — Insufficient Evidence</p>
            <p className="mt-1 text-sm">
              Risk and security scores are intentionally not computed (never rendered as 0 or a
              pass) because key facts are not observable in this capture:
            </p>
            <ul className="mt-1 list-disc pl-5 text-sm">
              {missing.map((m) => (
                <li key={m}>{m}</li>
              ))}
            </ul>
            <p className="tnum mt-1 text-sm">Evidence coverage so far: {coverage}%</p>
          </div>
        ) : (
          <div className="space-y-3 rounded border border-line p-4">
            <ScoreBar
              label="Risk score (0–100, higher = higher risk)"
              value={detail.risk_score}
              max={100}
            />
            <div className="my-1 border-t border-line" />
            <ScoreBar
              label="Security score (0–100, higher = stronger posture)"
              value={detail.security_score}
              max={100}
            />
            <p className="tnum text-sm text-ink-muted">
              Evidence coverage: <strong className="text-ink">{coverage}%</strong>
            </p>
          </div>
        )}

        {/* Right: Confidence meters */}
        <div className="space-y-3 rounded border border-line p-4">
          <ConfidenceMeter value={protocolConfidence} kind="protocol" />
          <ConfidenceMeter value={mlConfidence} kind="ml_traffic" />
        </div>
      </div>

      {mode !== "other" && (
        <p className="mt-3 text-sm">
          Selected IKE transforms indicate <strong>{mode}</strong> operation
          {mode === "AEAD"
            ? " (authenticated encryption; no separate HMAC integrity transform)."
            : " (block-cipher encryption with a separate HMAC integrity transform)."}{" "}
          <span className="mono text-xs">{selectedTransforms}</span>
        </p>
      )}

      <h3 className="mt-6 font-medium" id="threat-matrix-heading">
        Interactive Threat &amp; Posture Matrix
      </h3>
      <p className="text-sm text-ink-muted">
        Select a cell to filter the Findings &amp; Evidence Gaps list below. States pair icons with
        text — never color alone. Unknown means encrypted/not observable, not secure.
      </p>
      <div
        role="grid"
        aria-labelledby="threat-matrix-heading"
        className="mt-2 grid gap-2 md:grid-cols-3"
      >
        {DOMAINS.map((domain) => {
          const state = domainState(detail, domain.id);
          const meta = DOMAIN_STATE_META[state];
          const selected = domainFilter === domain.id;
          return (
            <button
              key={domain.id}
              type="button"
              role="gridcell"
              aria-pressed={selected}
              aria-label={`${domain.label}: ${meta.label}. Activate to filter findings.`}
              onClick={() => setDomainFilter(selected ? null : domain.id)}
              className={`rounded border p-3 text-left ${selected ? "border-accent ring-2 ring-accent" : "border-line"}`}
            >
              <span className="block font-medium">{domain.label}</span>
              <span className="mt-1 inline-flex items-center gap-1 text-sm">
                <span aria-hidden="true">{meta.icon}</span>
                {meta.label}
              </span>
            </button>
          );
        })}
      </div>
      {domainFilter !== null && (
        <p className="mt-2 text-sm" role="status">
          Filtering by domain: {DOMAINS.find((d) => d.id === domainFilter)?.label}.{" "}
          <button type="button" className="underline" onClick={() => setDomainFilter(null)}>
            Clear filter
          </button>
        </p>
      )}

      <h3 className="mt-6 font-medium">Findings &amp; Remediation Inspector</h3>
      <fieldset className="mt-2 flex flex-wrap gap-3 text-sm">
        <legend className="sr-only">Filter findings</legend>
        <label>
          Severity{" "}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded border border-line px-2 py-1"
          >
            <option value="">All</option>
            {["critical", "high", "medium", "low", "info"].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label>
          Status{" "}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded border border-line px-2 py-1"
          >
            <option value="">All</option>
            {[...new Set(combined.map((f) => f.status))].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
      </fieldset>

      {filtered.length === 0 ? (
        <p className="mt-3 text-sm text-ink-muted">
          No findings match the current filters. Absence of findings is not evidence of security.
        </p>
      ) : (
        <ul className="mt-3 space-y-2">
          {filtered.map((finding, i) => {
            const key = `${finding.rule_id}-${i}`;
            const kind = findingKind(finding);
            const open = expanded === key;
            return (
              <li key={key} className="rounded border border-line">
                <button
                  type="button"
                  aria-expanded={open}
                  onClick={() => setExpanded(open ? null : key)}
                  className="flex w-full flex-wrap items-center gap-2 p-3 text-left"
                >
                  <SeverityBadge severity={finding.severity as Severity} />
                  <span className="mono text-xs">{finding.rule_id}</span>
                  <span className="text-xs font-medium">{KIND_LABEL[kind]}</span>
                  <span className="text-xs text-ink-muted">
                    {DOMAINS.find((d) => d.id === domainForRule(finding.rule_id))?.label}
                  </span>
                  <span className="ml-auto text-xs">{open ? "Hide details" : "Show details"}</span>
                </button>
                {open && (
                  <div className="space-y-2 border-t border-line p-3 text-sm">
                    <p>
                      <strong>Confidence:</strong>{" "}
                      <span className="tnum">
                        {finding.confidence !== null
                          ? `${Math.round(finding.confidence * 100)}%`
                          : "not reported"}
                      </span>{" "}
                      · <strong>Status:</strong> {finding.status}
                    </p>
                    <p>
                      <strong>Actual:</strong>{" "}
                      <span className="mono">{JSON.stringify(finding.actual_value)}</span>
                    </p>
                    <p>
                      <strong>Expected:</strong>{" "}
                      <span className="mono">{JSON.stringify(finding.expected_value)}</span>
                    </p>
                    {finding.recommendation !== null && (
                      <p>
                        <strong>Remediation:</strong> {finding.recommendation}
                      </p>
                    )}
                    <p className="text-xs text-ink-muted">
                      Policy reference:{" "}
                      <span className="mono">
                        {finding.policy_version ?? detail.policy_version}
                      </span>
                      {(finding.source_refs ?? []).length > 0 && (
                        <>
                          {" "}
                          · Standard/policy refs:{" "}
                          <span className="mono">{(finding.source_refs ?? []).join(", ")}</span>
                        </>
                      )}
                    </p>
                    <div>
                      <p className="font-medium">Linked evidence</p>
                      {(finding.evidence_refs ?? []).length === 0 ? (
                        <UnknownValue reason="No evidence records are linked to this finding." />
                      ) : (
                        <ul className="mt-1 space-y-1">
                          {(finding.evidence_refs ?? []).map((ref) => {
                            const item = evidenceById.get(String(ref));
                            return (
                              <li key={String(ref)} className="flex flex-wrap items-center gap-2">
                                {item !== undefined ? (
                                  <>
                                    <ProvenanceBadge source={asSource(item.source)} />
                                    <span className="mono text-xs">{item.fact_name}</span>
                                  </>
                                ) : (
                                  <span className="mono text-xs">evidence {String(ref)}</span>
                                )}
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </div>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
