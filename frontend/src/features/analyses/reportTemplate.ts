import type { AnalysisDetail } from "@/api/client";
import { RFC_CATALOG } from "./rfcCatalog";

export interface ComplianceJsonReport {
  schema_version: string;
  generated_at: string;
  metadata: {
    analysis_id: string;
    capture_id: string;
    organization_id: string;
    policy_version: string;
    pipeline_version: string;
  };
  executive_summary: {
    status: string;
    security_score: number | null;
    risk_score: number | null;
    compliance_percentage: number;
    verdict: string;
    total_findings: number;
    critical_findings: number;
    high_findings: number;
  };
  rfc_compliance_matrix: Array<{
    standard: string;
    algorithm: string;
    domain: string;
    rfc_citation: string;
    requirement: string;
    observed_value: string;
    verdict: string;
    notes: string;
  }>;
  findings: Array<{
    rule_id: string;
    severity: string;
    confidence: number | null;
    recommendation: string | null | undefined;
    actual_value: unknown;
    expected_value: unknown;
  }>;
  evidence_summary: {
    packet_observed_count: number;
    supplied_count: number;
    model_inferred_count: number;
    unknown_count: number;
  };
  disclaimer: string;
}

export function buildComplianceJson(detail: AnalysisDetail): ComplianceJsonReport {
  const rfcEvaluations = RFC_CATALOG.map((std) => {
    const res = std.evaluator(detail);
    return {
      standard: std.title,
      algorithm: std.algorithm,
      domain: std.domain,
      rfc_citation: std.rfc,
      requirement: std.requirement,
      observed_value: res.observedValue ?? "Not Observed",
      verdict: res.verdict.toUpperCase(),
      notes: res.notes,
    };
  });

  const compliantCount = rfcEvaluations.filter((r) => r.verdict === "COMPLIANT").length;
  const totalAudited = rfcEvaluations.filter((r) => r.verdict !== "NOT-OBSERVED").length;
  const compliancePercentage = Math.round((compliantCount / Math.max(1, totalAudited)) * 100);

  const criticals = detail.findings.filter((f) => f.severity.toLowerCase() === "critical").length;
  const highs = detail.findings.filter((f) => f.severity.toLowerCase() === "high").length;

  let verdict = "SATISFACTORY";
  if (detail.security_score !== null) {
    if (detail.security_score < 50 || criticals > 0) verdict = "NON-COMPLIANT / HIGH RISK";
    else if (detail.security_score < 75 || highs > 0)
      verdict = "PARTIAL COMPLIANCE / REVIEW REQUIRED";
    else verdict = "ENTERPRISE COMPLIANT";
  }

  return {
    schema_version: "2.1-compliance",
    generated_at: new Date().toISOString(),
    metadata: {
      analysis_id: detail.id,
      capture_id: detail.capture_id,
      organization_id: detail.organization_id,
      policy_version: detail.policy_version,
      pipeline_version: detail.pipeline_version,
    },
    executive_summary: {
      status: detail.status,
      security_score: detail.security_score,
      risk_score: detail.risk_score,
      compliance_percentage: compliancePercentage,
      verdict,
      total_findings: detail.findings.length,
      critical_findings: criticals,
      high_findings: highs,
    },
    rfc_compliance_matrix: rfcEvaluations,
    findings: detail.findings.map((f) => ({
      rule_id: f.rule_id,
      severity: f.severity,
      confidence: f.confidence,
      recommendation: f.recommendation,
      actual_value: f.actual_value,
      expected_value: f.expected_value,
    })),
    evidence_summary: {
      packet_observed_count: detail.packet_observed_facts.length,
      supplied_count: detail.supplied_facts.length,
      model_inferred_count: detail.model_inferred_facts.length,
      unknown_count: detail.unknown_facts.length,
    },
    disclaimer:
      "This audit report reflects cryptographic parameters and transforms directly observed in passive packet capture. Unknown or unnegotiated parameters are audited as gaps. Not a substitute for formal ISO/IEC 15408 Common Criteria or FIPS 140-3 certification.",
  };
}
