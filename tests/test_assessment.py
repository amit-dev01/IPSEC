"""Deterministic rules-engine tests."""

from ipsec_analyzer.assessment.engine import FactView, evaluate
from ipsec_analyzer.assessment.policies import get_profile

PROFILE = get_profile("default-2026.1")


def F(name, value, source="packet_observed", confidence=1.0):
    return FactView(
        name=name,
        value=value,
        source=source,
        visibility="visible",
        confidence=confidence,
        id=f"ev-{name}",
    )


def _strong_facts():
    return [
        F("ike.version", ["2"]),
        F("ipsec.protocols_observed", ["esp", "ike"]),
        F("ike_sa.selected.encryption_algorithm", "AES-GCM"),
        F("ike_sa.selected.dh_group", "20"),
        F("ike_sa.selected.key_length", 256),
        F("network.outer_endpoints", [{"src": "sha256:x"}]),
        F("lab.esp_config", {"pfs_enabled": True, "encryption": "AES-GCM"}, source="lab_manifest"),
        F("lab.configured_sa_lifetime_seconds", 3600, source="lab_manifest"),
        F("lab.replay_protection", {"enabled": True}, source="lab_manifest"),
    ]


def _rules(result):
    return {f.rule_id: f for f in result.findings}


def test_strong_aead_case_scores_and_no_integrity_false_positive():
    r = evaluate(_strong_facts(), PROFILE, ml_confidence=0.9)
    rules = _rules(r)
    # AES-GCM is AEAD: a missing separate HMAC must NOT be flagged.
    assert "CRYPTO-CBC-INTEGRITY-001" not in rules
    assert "CRYPTO-WEAK-ENCRYPTION-001" not in rules
    assert "CRYPTO-WEAK-DH-001" not in rules
    assert r.assessment_status == "assessed"
    assert r.risk_score == 0.0
    assert r.security_score == 100.0
    assert r.protocol_evidence_confidence > 0.9
    assert r.ml_traffic_confidence == 0.9
    # Deterministic: identical input, identical output.
    r2 = evaluate(_strong_facts(), PROFILE, ml_confidence=0.9)
    assert [f.rule_id for f in r.findings] == [f.rule_id for f in r2.findings]
    assert r.risk_score == r2.risk_score


def test_cbc_with_hmac_is_acceptable_but_cbc_without_is_flagged():
    facts = _strong_facts()
    facts[2] = F("ike_sa.selected.encryption_algorithm", "AES-CBC")
    facts.append(F("ike_sa.selected.integrity_algorithm", "HMAC-SHA256"))
    r = evaluate(facts, PROFILE)
    assert "CRYPTO-CBC-INTEGRITY-001" not in _rules(r)
    assert "CRYPTO-WEAK-INTEGRITY-001" not in _rules(r)

    facts2 = _strong_facts()
    facts2[2] = F("ike_sa.selected.encryption_algorithm", "AES-CBC")
    r2 = evaluate(facts2, PROFILE)
    f = _rules(r2)["CRYPTO-CBC-INTEGRITY-001"]
    assert f.actual_value["integrity"] is None
    assert "AEAD" in f.expected_value


def test_weak_mixed_case():
    facts = [
        F("ike.version", ["1"]),
        F("ipsec.protocols_observed", ["esp", "ike"]),
        F("ike_sa.selected.encryption_algorithm", "3DES"),
        F("ike_sa.offered.encryption_algorithms", ["3DES", "AES-CBC"]),
        F("ike_sa.selected.dh_group", "2"),
        F("ike_sa.selected.key_length", 56),
        F("lab.esp_config", {"pfs_enabled": False}, source="lab_manifest"),
        F("lab.replay_protection", {"enabled": False}, source="lab_manifest"),
        F("lab.configured_sa_lifetime_seconds", 999999, source="lab_manifest"),
    ]
    r = evaluate(facts, PROFILE)
    rules = _rules(r)
    for rule_id in (
        "IKE-VERSION-001",
        "CRYPTO-WEAK-ENCRYPTION-001",
        "CRYPTO-WEAK-OFFERED-001",
        "CRYPTO-WEAK-DH-001",
        "CRYPTO-KEY-LENGTH-001",
        "PFS-DISABLED-001",
        "REPLAY-DISABLED-001",
        "SA-LIFETIME-LONG-001",
    ):
        assert rule_id in rules, rule_id
    sev = {f.rule_id: f.severity for f in r.findings}
    assert sev["CRYPTO-WEAK-ENCRYPTION-001"] == "high"  # selected weak
    assert sev["CRYPTO-WEAK-OFFERED-001"] == "low"  # offered only is weaker evidence
    assert r.risk_score is not None and r.risk_score >= 50
    finding = rules["CRYPTO-WEAK-DH-001"]
    assert finding.actual_value == "2"
    assert finding.policy_version == "default-2026.1"
    assert finding.evidence_refs  # evidence references required
    assert finding.recommendation


def test_unknowns_are_gaps_not_passes_and_insufficient_evidence():
    facts = [
        F("child_sa.proposals", None, source="unknown", confidence=0.0),
        F("esp.encryption_algorithm", None, source="unknown", confidence=0.0),
    ]
    r = evaluate(facts, PROFILE)
    assert r.assessment_status == "insufficient_evidence"
    assert r.risk_score is None  # never read thin evidence as safe
    assert r.security_score is None
    rules = _rules(r)
    assert "GAP-CHILD-SA-001" in rules and "GAP-ESP-CIPHER-001" in rules
    assert all(f.severity == "info" for f in r.findings)
    assert r.protocol_evidence_confidence == 0.0


def test_partial_coverage_bounds():
    # Only IKE version + selected transforms: coverage 0.15+0.25=0.40 -> partial (boundary).
    facts = [
        F("ike.version", ["2"]),
        F("ike_sa.selected.encryption_algorithm", "AES-GCM"),
    ]
    r = evaluate(facts, PROFILE)
    assert r.coverage["value"] == 0.4
    assert r.assessment_status == "partial"
    assert r.risk_score is not None  # risk shown, security withheld
    assert r.security_score is None

    # One dimension less (0.25): insufficient, both scores null.
    r2 = evaluate([F("ike_sa.selected.encryption_algorithm", "AES-GCM")], PROFILE)
    assert r2.coverage["value"] == 0.25
    assert r2.assessment_status == "insufficient_evidence"
    assert r2.risk_score is None and r2.security_score is None


def test_metadata_observation_is_descriptive_not_vulnerability():
    r = evaluate(_strong_facts(), PROFILE)
    f = _rules(r)["META-OUTER-ENDPOINTS-001"]
    assert f.severity == "info"
    assert "not a vulnerability" in f.recommendation
    assert r.risk_score == 0.0  # info findings add no risk


def test_rule_version_changes_behavior():
    facts = _strong_facts()
    facts[3] = F("ike_sa.selected.dh_group", "5")
    new = evaluate(facts, get_profile("default-2026.1"))
    old = evaluate(facts, get_profile("default-2025.1"))
    assert "CRYPTO-WEAK-DH-001" in _rules(new)  # DH5 deprecated in 2026.1
    assert "CRYPTO-WEAK-DH-001" not in _rules(old)  # tolerated by 2025.1
    assert all(
        f.policy_version == "default-2025.1" for f in old.findings if f.rule_id.startswith("CRYPTO")
    )
