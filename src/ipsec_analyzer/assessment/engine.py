"""Deterministic rules over evidence drafts/records.

Inputs are evidence items with (fact_name, fact_value, source, visibility,
confidence). Output findings are sorted by rule_id for stable, reproducible
results. Facts are looked up by name; `unknown`-source facts never satisfy a
rule and never count as passing.
"""

from dataclasses import dataclass, field
from typing import Any

from ipsec_analyzer.assessment.policies import PolicyProfile
from ipsec_analyzer.assessment.scoring import risk_from_findings


@dataclass
class FactView:
    name: str
    value: Any
    source: str
    visibility: str
    confidence: float | None = 1.0
    id: str | None = None  # evidence record id, when persisted


@dataclass
class FindingDraft:
    rule_id: str
    severity: str
    confidence: float
    evidence_refs: list[str]
    actual_value: Any
    expected_value: Any
    recommendation: str
    policy_version: str
    source_refs: list[str] = field(default_factory=list)


@dataclass
class AssessmentResult:
    findings: list[FindingDraft]
    risk_score: float | None
    security_score: float | None
    coverage: dict[str, Any]
    assessment_status: str  # assessed | partial | insufficient_evidence
    protocol_evidence_confidence: float
    ml_traffic_confidence: float | None


def _norm(value: Any) -> str:
    return str(value).strip().upper().replace("_", "-")


def _esp_observed(by_name: dict) -> bool:
    f = by_name.get("ipsec.protocols_observed")
    return f is not None and f.value is not None and "esp" in str(f.value).lower()


def evaluate(
    facts: list[FactView],
    profile: PolicyProfile,
    *,
    ml_confidence: float | None = None,
) -> AssessmentResult:
    by_name: dict[str, FactView] = {}
    for f in facts:
        by_name.setdefault(f.name, f)

    def known(name: str) -> FactView | None:
        fact = by_name.get(name)
        if fact is None or fact.source == "unknown" or fact.value is None:
            return None
        return fact

    def refs(*fs: FactView | None) -> list[str]:
        return [f.id for f in fs if f is not None and f.id]

    findings: list[FindingDraft] = []
    pv = profile.version
    docs = ["policy-profile:" + pv]

    # IKE version
    ike_version = known("ike.version")
    if ike_version is not None:
        versions = ike_version.value if isinstance(ike_version.value, list) else [ike_version.value]
        if any(str(v) == "1" for v in versions):
            findings.append(
                FindingDraft(
                    rule_id="IKE-VERSION-001",
                    severity="medium",
                    confidence=0.95,
                    evidence_refs=refs(ike_version),
                    actual_value=versions,
                    expected_value=["2"],
                    recommendation="Migrate IKEv1 peers to IKEv2; IKEv1 lacks modern "
                    "negotiation protections.",
                    policy_version=pv,
                    source_refs=docs + ["RFC 7296 (IKEv2)"],
                )
            )

    selected_enc = known("ike_sa.selected.encryption_algorithm")
    offered_enc = known("ike_sa.offered.encryption_algorithms")
    selected_dh = known("ike_sa.selected.dh_group")
    selected_integ = known("ike_sa.selected.integrity_algorithm")
    selected_keylen = known("ike_sa.selected.key_length")

    def _check_weak_enc(fact: FactView | None, *, selected: bool) -> None:
        if fact is None:
            return
        values = fact.value if isinstance(fact.value, list) else [fact.value]
        weak = [v for v in values if _norm(v) in profile.deprecated_encryption]
        if weak:
            findings.append(
                FindingDraft(
                    rule_id="CRYPTO-WEAK-ENCRYPTION-001" if selected else "CRYPTO-WEAK-OFFERED-001",
                    severity="high" if selected else "low",
                    confidence=0.95 if selected else 0.7,
                    evidence_refs=refs(fact),
                    actual_value=weak,
                    expected_value="not in deprecated set (DES/3DES/NULL/RC4/...)",
                    recommendation="Remove deprecated encryption transforms from the IKE proposal; "
                    "prefer AEAD suites (AES-GCM or ChaCha20-Poly1305).",
                    policy_version=pv,
                    source_refs=docs,
                )
            )

    _check_weak_enc(selected_enc, selected=True)
    _check_weak_enc(offered_enc, selected=False)

    # AEAD correctness: AEAD suites provide integrity; never flag missing HMAC.
    if selected_enc is not None:
        enc_values = (
            selected_enc.value if isinstance(selected_enc.value, list) else [selected_enc.value]
        )
        is_aead = any(_norm(v) in profile.aead_encryption for v in enc_values)
        if is_aead:
            pass  # explicit: no integrity finding for AEAD
        else:
            # Non-AEAD (e.g. AES-CBC) requires a separate integrity transform.
            if selected_integ is None:
                findings.append(
                    FindingDraft(
                        rule_id="CRYPTO-CBC-INTEGRITY-001",
                        severity="medium",
                        confidence=0.6,
                        evidence_refs=refs(selected_enc),
                        actual_value={"encryption": enc_values, "integrity": None},
                        expected_value="an integrity transform (e.g. HMAC-SHA-256) "
                        "with CBC, or an AEAD suite",
                        recommendation="Use an AEAD suite (AES-GCM/ChaCha20-Poly1305), or ensure "
                        "AES-CBC is paired with a strong integrity transform.",
                        policy_version=pv,
                        source_refs=docs,
                    )
                )
            else:
                integ_values = (
                    selected_integ.value
                    if isinstance(selected_integ.value, list)
                    else [selected_integ.value]
                )
                if any(_norm(v) in profile.deprecated_integrity for v in integ_values):
                    findings.append(
                        FindingDraft(
                            rule_id="CRYPTO-WEAK-INTEGRITY-001",
                            severity="medium",
                            confidence=0.9,
                            evidence_refs=refs(selected_integ),
                            actual_value=integ_values,
                            expected_value="HMAC-SHA-256 or stronger (or AEAD)",
                            recommendation="Replace MD5/SHA1 integrity with HMAC-SHA-256+ or "
                            "move to AEAD.",
                            policy_version=pv,
                            source_refs=docs,
                        )
                    )

    # DH group (selected only; offered-only produces no DH finding)
    if selected_dh is not None:
        groups = selected_dh.value if isinstance(selected_dh.value, list) else [selected_dh.value]
        for g in groups:
            gs = str(g)
            if gs in profile.deprecated_dh_groups:
                findings.append(
                    FindingDraft(
                        rule_id="CRYPTO-WEAK-DH-001",
                        severity="high",
                        confidence=0.95,
                        evidence_refs=refs(selected_dh),
                        actual_value=gs,
                        expected_value=f"DH group >= {profile.min_dh_group} (19+ preferred)",
                        recommendation="Disable legacy MODP groups (1/2/5); use group 19/20/21 "
                        "or at least 14.",
                        policy_version=pv,
                        source_refs=docs,
                    )
                )
            else:
                try:
                    gi = int(gs)
                except ValueError:
                    continue
                if gi < profile.min_dh_group:
                    findings.append(
                        FindingDraft(
                            rule_id="CRYPTO-WEAK-DH-001",
                            severity="medium",
                            confidence=0.9,
                            evidence_refs=refs(selected_dh),
                            actual_value=gs,
                            expected_value=f"DH group >= {profile.min_dh_group}",
                            recommendation="Raise the minimum DH group in the IKE proposal.",
                            policy_version=pv,
                            source_refs=docs,
                        )
                    )

    if selected_keylen is not None:
        try:
            klen = int(selected_keylen.value)
        except (TypeError, ValueError):
            klen = None
        if klen is not None and klen < profile.min_encryption_key_length:
            findings.append(
                FindingDraft(
                    rule_id="CRYPTO-KEY-LENGTH-001",
                    severity="high",
                    confidence=0.9,
                    evidence_refs=refs(selected_keylen),
                    actual_value=klen,
                    expected_value=f">= {profile.min_encryption_key_length} bits",
                    recommendation="Use at least 128-bit (preferably 256-bit) encryption keys.",
                    policy_version=pv,
                    source_refs=docs,
                )
            )

    # PFS / lifetime / replay: only when trustworthy config/manifest states it.
    pfs_known: FactView | None = None
    esp_manifest = known("lab.esp_config")
    if esp_manifest is not None and isinstance(esp_manifest.value, dict):
        if esp_manifest.value.get("pfs_enabled") is False:
            pfs_known = esp_manifest
            findings.append(
                FindingDraft(
                    rule_id="PFS-DISABLED-001",
                    severity="medium",
                    confidence=0.9,
                    evidence_refs=refs(esp_manifest),
                    actual_value={"pfs_enabled": False},
                    expected_value={"pfs_enabled": True},
                    recommendation="Enable Perfect Forward Secrecy (Child-SA DH group) so session "
                    "keys are not derivable from long-term keys alone.",
                    policy_version=pv,
                    source_refs=docs + ["lab_manifest:esp.pfs_enabled"],
                )
            )
        elif esp_manifest.value.get("pfs_enabled") is True:
            pfs_known = esp_manifest

    lifetime = known("lab.configured_sa_lifetime_seconds")
    lifetime_covered = lifetime is not None
    if lifetime is not None:
        try:
            secs = int(lifetime.value)
        except (TypeError, ValueError):
            secs = None
        if secs is not None and secs > profile.max_configured_lifetime_seconds:
            findings.append(
                FindingDraft(
                    rule_id="SA-LIFETIME-LONG-001",
                    severity="low",
                    confidence=0.9,
                    evidence_refs=refs(lifetime),
                    actual_value=secs,
                    expected_value=f"<= {profile.max_configured_lifetime_seconds} seconds (policy)",
                    recommendation="Shorten configured SA lifetimes to limit key exposure per SA.",
                    policy_version=pv,
                    source_refs=docs + ["lab_manifest:configured_sa_lifetime_seconds"],
                )
            )

    replay = known("lab.replay_protection")
    replay_covered = replay is not None
    if (
        replay is not None
        and isinstance(replay.value, dict)
        and replay.value.get("enabled") is False
    ):
        findings.append(
            FindingDraft(
                rule_id="REPLAY-DISABLED-001",
                severity="medium",
                confidence=0.9,
                evidence_refs=refs(replay),
                actual_value={"enabled": False},
                expected_value={"enabled": True},
                recommendation="Enable ESP anti-replay protection on the gateways.",
                policy_version=pv,
                source_refs=docs + ["lab_manifest:replay_protection"],
            )
        )

    # Descriptive metadata observation — explicitly NOT a vulnerability.
    endpoints = known("network.outer_endpoints")
    if endpoints is not None:
        findings.append(
            FindingDraft(
                rule_id="META-OUTER-ENDPOINTS-001",
                severity="info",
                confidence=0.8,
                evidence_refs=refs(endpoints),
                actual_value={"outer_endpoints_observed": True},
                expected_value=None,
                recommendation="Descriptive only: outer endpoint/timing metadata is visible to a "
                "passive observer of ESP traffic. This is inherent to IPsec metadata exposure, "
                "not a vulnerability; consider NAT-T/padding only if "
                "your threat model requires it.",
                policy_version=pv,
                source_refs=docs,
            )
        )

    # Evidence gaps (informational; gaps never count as passing).
    for name, rule, label in (
        ("ike_sa.selected_transforms", "GAP-IKE-SELECTED-001", "selected IKE transforms"),
        ("child_sa.proposals", "GAP-CHILD-SA-001", "Child-SA parameters"),
        ("esp.encryption_algorithm", "GAP-ESP-CIPHER-001", "ESP cipher"),
    ):
        gap_fact = by_name.get(name)
        if gap_fact is None or gap_fact.source == "unknown" or gap_fact.value is None:
            findings.append(
                FindingDraft(
                    rule_id=rule,
                    severity="info",
                    confidence=1.0,
                    evidence_refs=refs(gap_fact),
                    actual_value=None,
                    expected_value=f"observable {label}",
                    recommendation=f"{label} could not be determined from the available evidence; "
                    "treat as unknown, not as compliant. Supply a lab manifest "
                    "or analyst attestation "
                    "if this must be assessed.",
                    policy_version=pv,
                    source_refs=docs,
                )
            )

    findings.sort(key=lambda x: x.rule_id)

    # Coverage
    dims = profile.coverage_dimensions
    covered = {
        "ike_version": ike_version is not None,
        "ike_selected_transforms": selected_enc is not None or selected_dh is not None,
        "esp_observed": _esp_observed(by_name),
        "child_sa_or_manifest": esp_manifest is not None or known("child_sa.proposals") is not None,
        "pfs_state": pfs_known is not None,
        "lifetime_config": lifetime_covered,
        "replay_config": replay_covered,
    }
    coverage_value = sum(dims[k] for k in dims if covered.get(k))
    if coverage_value >= profile.assessed_threshold:
        status = "assessed"
    elif coverage_value >= profile.partial_threshold:
        status = "partial"
    else:
        status = "insufficient_evidence"

    risk = (
        risk_from_findings([f.severity for f in findings])
        if status != "insufficient_evidence"
        else None
    )
    security = (100.0 - risk) if (status == "assessed" and risk is not None) else None

    packet_conf = [
        f.confidence for f in facts if f.source == "packet_observed" and f.confidence is not None
    ]
    protocol_confidence = sum(packet_conf) / len(packet_conf) if packet_conf else 0.0

    return AssessmentResult(
        findings=findings,
        risk_score=risk,
        security_score=security,
        coverage={
            "value": round(coverage_value, 4),
            "dimensions": {k: bool(covered.get(k)) for k in dims},
            "weights": dims,
        },
        assessment_status=status,
        protocol_evidence_confidence=round(protocol_confidence, 4),
        ml_traffic_confidence=ml_confidence,
    )
