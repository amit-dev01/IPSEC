import { describe, expect, it } from "vitest";

import type { AnalysisDetail } from "@/api/client";

import {
  assessmentStatus,
  domainState,
  evidenceCoverage,
  findingKind,
  integrityMode,
  missingKeyFacts,
} from "./assessment-lib";

function detail(partial: Partial<AnalysisDetail>): AnalysisDetail {
  return {
    id: "run-1",
    organization_id: "org",
    capture_id: "cap-1",
    status: "succeeded",
    pipeline_version: "tshark-parse-0.2",
    model_version: null,
    policy_version: "default-2026.1",
    attempts: 1,
    dispatch_attempts: 1,
    error_code: null,
    risk_score: null,
    security_score: null,
    queued_at: "2026-10-24T00:00:00Z",
    started_at: null,
    finished_at: null,
    packet_observed_facts: [],
    supplied_facts: [],
    model_inferred_facts: [],
    unknown_facts: [],
    findings: [],
    evidence_gaps: [],
    report_url: null,
    ...partial,
  };
}

describe("assessment status (deterministic, from documented scoring rules)", () => {
  it("assessed when security score present", () => {
    expect(assessmentStatus(detail({ risk_score: 20, security_score: 80 }))).toBe("assessed");
  });
  it("partial when risk present but security withheld", () => {
    expect(assessmentStatus(detail({ risk_score: 30, security_score: null }))).toBe("partial");
  });
  it("insufficient_evidence when both scores null on a succeeded run", () => {
    expect(assessmentStatus(detail({}))).toBe("insufficient_evidence");
  });
});

describe("AEAD vs CBC+HMAC display accuracy", () => {
  it("detects AEAD transforms", () => {
    expect(integrityMode("ENCR_AES_GCM_16")).toBe("AEAD");
    expect(integrityMode("ENCR_CHACHA20_POLY1305")).toBe("AEAD");
  });
  it("detects CBC with separate HMAC integrity", () => {
    expect(integrityMode("ENCR_AES_CBC + AUTH_HMAC_SHA2_256")).toBe("CBC+HMAC");
  });
  it("does not misclassify plain text", () => {
    expect(integrityMode("nothing here")).toBe("other");
  });
});

describe("threat matrix domain states", () => {
  it("unknown ESP cipher is an encrypted gap, never strong", () => {
    const d = detail({
      unknown_facts: [
        {
          id: "e1",
          fact_name: "esp.encryption_algorithm",
          fact_value: null,
          source: "unknown",
          visibility: "encrypted_or_unavailable",
          confidence: null,
          quality: null,
          packet_refs: [],
          limitation: "ESP payloads are encrypted.",
        },
      ],
    });
    expect(domainState(d, "esp_confidentiality")).toBe("unknown");
    expect(missingKeyFacts(d)).toContain("Encrypted Child SA cipher (ESP encryption algorithm)");
    expect(evidenceCoverage(d)).toBeLessThan(40);
  });

  it("weak DH finding marks Key Exchange weak; META is informational exposure", () => {
    const d = detail({
      findings: [
        {
          rule_id: "CRYPTO-WEAK-DH-001",
          severity: "high",
          confidence: 1,
          actual_value: "2",
          expected_value: ">=14",
          recommendation: "Use DH group 19+.",
          evidence_refs: [],
          policy_version: "default-2026.1",
          source_refs: ["RFC 9142"],
          status: "finding",
        },
        {
          rule_id: "META-OUTER-ENDPOINTS-001",
          severity: "info",
          confidence: 1,
          actual_value: "203.0.113.1",
          expected_value: null,
          recommendation: null,
          evidence_refs: [],
          policy_version: "default-2026.1",
          source_refs: [],
          status: "finding",
        },
      ],
    });
    expect(domainState(d, "key_exchange")).toBe("weak");
    expect(findingKind(d.findings[0]!)).toBe("cryptographic");
    expect(findingKind(d.findings[1]!)).toBe("informational");
  });
});
