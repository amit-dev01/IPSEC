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
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span
          role="img"
          aria-label={`Assessment status: ${STATUS_META[status]?.label ?? status}`}
          className="inline-flex items-center gap-1.5 rounded-full border border-[#e6e6e8] bg-white px-3 py-1 text-xs font-semibold text-[#1d1d1f]"
        >
          <span aria-hidden="true" className="text-[#0071e3]">
            {STATUS_META[status]?.icon}
          </span>
          Assessment: {STATUS_META[status]?.label ?? status}
        </span>
        <span className="text-xs text-[#707070]">
          Policy profile:{" "}
          <span className="mono font-semibold text-[#1d1d1f]">{detail.policy_version}</span>
        </span>
      </div>

      {/* ── Score section: Radial chart + Confidence meters ── */}
      <div className="grid gap-4 md:grid-cols-[auto_1fr_auto]">
        {/* Left: Radial donut */}
        <div className="apple-card p-6 flex items-center justify-center">
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
            className="apple-card p-6 border-[#b64400]/30 bg-[#b64400]/5 text-[#1d1d1f]"
          >
            <p className="font-display font-semibold text-[#b64400] text-base">
              Score Withheld — Insufficient Evidence
            </p>
            <p className="mt-2 text-xs leading-relaxed text-[#707070]">
              Risk and security scores are intentionally not computed (never rendered as 0 or a
              pass) because key facts are not observable in this capture:
            </p>
            <ul className="mt-2 list-disc pl-5 text-xs text-[#1d1d1f] space-y-1">
              {missing.map((m) => (
                <li key={m}>{m}</li>
              ))}
            </ul>
            <p className="tnum mt-3 text-xs font-semibold text-[#707070]">
              Evidence coverage so far: {coverage}%
            </p>
          </div>
        ) : (
          <div className="apple-card p-6 space-y-5">
            <div>
              <ScoreBar
                label="Risk score (0–100, higher = higher risk)"
                value={detail.risk_score}
                max={100}
              />
              <p className="tnum mt-1.5 text-xs text-[#707070]">
                Evidence Coverage: <strong className="text-[#1d1d1f]">{coverage}%</strong>
              </p>
            </div>
            <div className="border-t border-[#f5f5f7]" />
            <div>
              <ScoreBar
                label="Security score (0–100, higher = stronger posture)"
                value={detail.security_score}
                max={100}
              />
              <p className="tnum mt-1.5 text-xs text-[#707070]">
                Evidence Coverage: <strong className="text-[#1d1d1f]">{coverage}%</strong>
              </p>
            </div>
          </div>
        )}

        {/* Right: Confidence meters */}
        <div className="apple-card p-6 space-y-4">
          <ConfidenceMeter value={protocolConfidence} kind="protocol" />
          <ConfidenceMeter value={mlConfidence} kind="ml_traffic" />
        </div>
      </div>

      {mode !== "other" && (
        <div className="rounded-2xl border border-[#0071e3]/20 bg-[#0071e3]/5 p-4 text-xs text-[#1d1d1f]">
          Selected IKE transforms indicate <strong className="text-[#0071e3]">{mode}</strong>{" "}
          operation
          {mode === "AEAD"
            ? " (authenticated encryption; no separate HMAC integrity transform)."
            : " (block-cipher encryption with a separate HMAC integrity transform)."}{" "}
          <span className="mono font-semibold">{selectedTransforms}</span>
        </div>
      )}

      {/* Threat Matrix */}
      <div className="apple-card p-6 space-y-4">
        <div>
          <h3
            className="font-display text-lg font-semibold text-[#1d1d1f]"
            id="threat-matrix-heading"
          >
            Interactive Threat &amp; Posture Matrix
          </h3>
          <p className="mt-1 text-xs text-[#707070]">
            Select a domain cell to filter the Findings list below. States pair icons with text —
            never color alone.
          </p>
        </div>
        <div
          role="grid"
          aria-labelledby="threat-matrix-heading"
          className="grid gap-3 md:grid-cols-3"
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
                className={`rounded-2xl border p-4 text-left transition-all ${
                  selected
                    ? "border-[#0071e3] bg-[#ffffff] ring-2 ring-[#0071e3]/20 shadow-sm"
                    : "border-[#e6e6e8] bg-[#fafafc] hover:border-[#d6d6d6] hover:bg-[#ffffff]"
                }`}
              >
                <span className="block font-semibold text-sm text-[#1d1d1f]">{domain.label}</span>
                <span className="mt-2 inline-flex items-center gap-1.5 text-xs text-[#707070]">
                  <span aria-hidden="true" className="font-bold text-[#0071e3]">
                    {meta.icon}
                  </span>
                  {meta.label}
                </span>
              </button>
            );
          })}
        </div>
        {domainFilter !== null && (
          <p className="text-xs text-[#707070]" role="status">
            Filtering by domain:{" "}
            <strong className="text-[#1d1d1f]">
              {DOMAINS.find((d) => d.id === domainFilter)?.label}
            </strong>
            .{" "}
            <button
              type="button"
              className="text-[#0066cc] font-medium hover:underline"
              onClick={() => setDomainFilter(null)}
            >
              Clear filter
            </button>
          </p>
        )}
      </div>

      {/* Findings Inspector */}
      <div className="apple-card p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="font-display text-lg font-semibold text-[#1d1d1f]">
            Findings &amp; Remediation Inspector
          </h3>
          <fieldset className="flex flex-wrap gap-3 text-xs">
            <legend className="sr-only">Filter findings</legend>
            <label className="flex items-center gap-2 text-[#707070]">
              Severity
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="rounded-full border border-[#d6d6d6] bg-white px-3 py-1 text-xs text-[#1d1d1f] focus:outline-none focus:border-[#0071e3]"
              >
                <option value="">All</option>
                {["critical", "high", "medium", "low", "info"].map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-2 text-[#707070]">
              Status
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="rounded-full border border-[#d6d6d6] bg-white px-3 py-1 text-xs text-[#1d1d1f] focus:outline-none focus:border-[#0071e3]"
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
        </div>

        {filtered.length === 0 ? (
          <p className="text-sm text-[#707070]">
            No findings match the current filters. Absence of findings is not evidence of security.
          </p>
        ) : (
          <ul className="space-y-3">
            {filtered.map((finding, i) => {
              const key = `${finding.rule_id}-${i}`;
              const kind = findingKind(finding);
              const open = expanded === key;
              return (
                <li
                  key={key}
                  className="rounded-2xl border border-[#e6e6e8] bg-[#ffffff] transition hover:border-[#d6d6d6]"
                >
                  <button
                    type="button"
                    aria-expanded={open}
                    onClick={() => setExpanded(open ? null : key)}
                    className="flex w-full flex-wrap items-center gap-3 p-4 text-left"
                  >
                    <SeverityBadge severity={finding.severity as Severity} />
                    <span className="mono text-xs font-semibold text-[#1d1d1f]">
                      {finding.rule_id}
                    </span>
                    <span className="text-xs font-medium text-[#707070]">{KIND_LABEL[kind]}</span>
                    <span className="text-xs text-[#707070]">
                      {DOMAINS.find((d) => d.id === domainForRule(finding.rule_id))?.label}
                    </span>
                    <span className="ml-auto text-xs font-medium text-[#0066cc]">
                      {open ? "Hide details" : "Show details"}
                    </span>
                  </button>
                  {open && (
                    <div className="space-y-2 border-t border-[#f5f5f7] p-4 text-xs bg-[#fafafc] rounded-b-2xl">
                      <p>
                        <strong className="text-[#1d1d1f]">Confidence:</strong>{" "}
                        <span className="tnum font-semibold text-[#0071e3]">
                          {finding.confidence !== null
                            ? `${Math.round(finding.confidence * 100)}%`
                            : "not reported"}
                        </span>{" "}
                        · <strong className="text-[#1d1d1f]">Status:</strong> {finding.status}
                      </p>
                      <p>
                        <strong className="text-[#1d1d1f]">Actual:</strong>{" "}
                        <span className="mono text-[#1d1d1f]">
                          {JSON.stringify(finding.actual_value)}
                        </span>
                      </p>
                      <p>
                        <strong className="text-[#1d1d1f]">Expected:</strong>{" "}
                        <span className="mono text-[#1d1d1f]">
                          {JSON.stringify(finding.expected_value)}
                        </span>
                      </p>
                      {finding.recommendation !== null && (
                        <p className="text-[#1d1d1f]">
                          <strong className="text-[#0071e3]">Remediation:</strong>{" "}
                          {finding.recommendation}
                        </p>
                      )}
                      <p className="text-[11px] text-[#707070]">
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
                      <div className="pt-2">
                        <p className="font-semibold text-[#1d1d1f] mb-1">Linked evidence</p>
                        {(finding.evidence_refs ?? []).length === 0 ? (
                          <UnknownValue reason="No evidence records are linked to this finding." />
                        ) : (
                          <ul className="space-y-1">
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
    </div>
  );
}
