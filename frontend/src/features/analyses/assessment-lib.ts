import type { AnalysisDetail, Schemas } from "@/api/client";

import { factMap, isUnknown } from "./evidence-lib";
import type { Evidence } from "./evidence-lib";

export type Finding = Schemas["FindingResponse"];
export type AssessmentStatus = "assessed" | "partial" | "insufficient_evidence";
export type DomainId =
  | "key_exchange"
  | "esp_confidentiality"
  | "integrity_aead"
  | "forward_secrecy_lifetimes"
  | "replay_protection"
  | "metadata_exposure";
export type DomainState = "strong" | "weak" | "exposure" | "unknown";

export const DOMAINS: { id: DomainId; label: string }[] = [
  { id: "key_exchange", label: "Key Exchange / IKE" },
  { id: "esp_confidentiality", label: "ESP Confidentiality" },
  { id: "integrity_aead", label: "Integrity / AEAD" },
  { id: "forward_secrecy_lifetimes", label: "Forward Secrecy & Lifetimes" },
  { id: "replay_protection", label: "Replay Protection" },
  { id: "metadata_exposure", label: "Metadata & Traffic Analysis Exposure" },
];

export const DOMAIN_STATE_META: Record<DomainState, { label: string; icon: string }> = {
  strong: { label: "Strong / Compliant", icon: "✓" },
  weak: { label: "Weak / Misconfigured", icon: "!" },
  exposure: { label: "Exposure / Informational", icon: "◉" },
  unknown: { label: "Unknown / Encrypted Gap", icon: "?" },
};

/** Documented backend logic (assessment/scoring.py), derived from scores. */
export function assessmentStatus(detail: AnalysisDetail): AssessmentStatus {
  if (detail.status !== "succeeded") return "insufficient_evidence";
  if (detail.security_score !== null) return "assessed";
  if (detail.risk_score !== null) return "partial";
  return "insufficient_evidence";
}

/**
 * Evidence Coverage % mirroring the backend policy coverage dimensions and
 * weights (assessment/policies.py, sum = 1.0). A dimension is covered when a
 * non-unknown fact backs it. Authoritative value ships in the report JSON.
 */
const COVERAGE_DIMENSIONS: { weight: number; facts: string[] }[] = [
  { weight: 0.15, facts: ["ike.version"] },
  { weight: 0.25, facts: ["ike_sa.selected_transforms", "ike_sa.proposal_selected"] },
  { weight: 0.15, facts: ["esp.spi_observed", "ipsec.protocols_observed"] },
  { weight: 0.15, facts: ["child_sa.proposals", "lab.esp_config", "esp.encryption_algorithm"] },
  { weight: 0.1, facts: ["security.pfs", "lab.esp_config"] },
  { weight: 0.1, facts: ["security.configured_sa_lifetime", "lab.configured_sa_lifetime_seconds"] },
  { weight: 0.1, facts: ["security.replay_window_configured", "lab.replay_protection"] },
];

export function evidenceCoverage(detail: AnalysisDetail): number {
  const facts = factMap(detail);
  let covered = 0;
  for (const dim of COVERAGE_DIMENSIONS) {
    const backed = dim.facts.some((name) => {
      const item = facts.get(name);
      return item !== undefined && !isUnknown(item);
    });
    if (backed) covered += dim.weight;
  }
  return Math.round(covered * 100);
}

/** Key facts whose absence withholds scores (shown on the withheld card). */
export function missingKeyFacts(detail: AnalysisDetail): string[] {
  const facts = factMap(detail);
  const checks: [string, string][] = [
    ["esp.encryption_algorithm", "Encrypted Child SA cipher (ESP encryption algorithm)"],
    ["security.pfs", "Perfect Forward Secrecy (PFS) state"],
    ["security.configured_sa_lifetime", "Configured SA lifetime"],
    ["child_sa.proposals", "Child SA proposals"],
    ["security.replay_window_configured", "Configured replay window"],
    ["ike_sa.selected_transforms", "Responder-selected IKE transforms"],
  ];
  return checks
    .filter(([name]) => {
      const item = facts.get(name);
      return item === undefined || isUnknown(item);
    })
    .map(([, label]) => label);
}

const RULE_DOMAIN: [RegExp, DomainId][] = [
  [/^IKE-/, "key_exchange"],
  [/^CRYPTO-WEAK-DH|^CRYPTO-WEAK-OFFERED/, "key_exchange"],
  [/^CRYPTO-(WEAK-ENCRYPTION|KEY-LENGTH)/, "esp_confidentiality"],
  [/^CRYPTO-(CBC-INTEGRITY|WEAK-INTEGRITY)/, "integrity_aead"],
  [/^PFS-/, "forward_secrecy_lifetimes"],
  [/^SA-LIFETIME-/, "forward_secrecy_lifetimes"],
  [/^REPLAY-/, "replay_protection"],
  [/^META-/, "metadata_exposure"],
  [/^GAP-IKE/, "key_exchange"],
  [/^GAP-CHILD|^GAP-ESP/, "esp_confidentiality"],
];

export function domainForRule(ruleId: string): DomainId {
  for (const [pattern, domain] of RULE_DOMAIN) {
    if (pattern.test(ruleId)) return domain;
  }
  if (ruleId.startsWith("GAP-")) return "esp_confidentiality";
  return "key_exchange";
}

export type FindingKind = "cryptographic" | "informational" | "evidence_gap";

export function findingKind(finding: Finding): FindingKind {
  if (finding.rule_id.startsWith("GAP-")) return "evidence_gap";
  if (finding.rule_id.startsWith("META-")) return "informational";
  return "cryptographic";
}

const WEAK_SEVERITIES = new Set(["critical", "high", "medium"]);

export function domainState(detail: AnalysisDetail, domain: DomainId): DomainState {
  const all = [...detail.findings, ...detail.evidence_gaps];
  const inDomain = all.filter((f) => domainForRule(f.rule_id) === domain);
  if (inDomain.some((f) => findingKind(f) === "cryptographic" && WEAK_SEVERITIES.has(f.severity))) {
    return "weak";
  }
  if (domain === "metadata_exposure") {
    const facts = factMap(detail);
    const endpoints = facts.get("network.outer_endpoints");
    return endpoints !== undefined && !isUnknown(endpoints) ? "exposure" : "unknown";
  }
  if (inDomain.some((f) => findingKind(f) === "evidence_gap")) return "unknown";
  const facts = factMap(detail);
  const domainFacts: Record<DomainId, string[]> = {
    key_exchange: ["ike.version", "ike_sa.selected_transforms"],
    esp_confidentiality: ["esp.encryption_algorithm", "child_sa.proposals"],
    integrity_aead: ["ike_sa.selected.integrity", "ike_sa.selected_transforms"],
    forward_secrecy_lifetimes: ["security.pfs", "security.configured_sa_lifetime"],
    replay_protection: ["security.replay_window_configured"],
    metadata_exposure: ["network.outer_endpoints"],
  };
  const known = domainFacts[domain].some((name) => {
    const item = facts.get(name);
    return item !== undefined && !isUnknown(item);
  });
  return known ? "strong" : "unknown";
}

/** AEAD vs CBC+HMAC classification from a transform description. */
export function integrityMode(transformText: string): "AEAD" | "CBC+HMAC" | "other" {
  const t = transformText.toUpperCase();
  if (/GCM|CHACHA|CCM|POLY1305/.test(t)) return "AEAD";
  if (/CBC/.test(t) && /HMAC|SHA/.test(t)) return "CBC+HMAC";
  if (/CBC/.test(t)) return "CBC+HMAC";
  return "other";
}

export type { Evidence };
