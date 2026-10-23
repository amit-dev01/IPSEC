"""Manifest -> facts, and manifest-vs-packet discrepancy detection.

A manifest never overwrites packet-observed facts. Both are retained; when the
manifest's declared *selected* configuration conflicts with a packet-observed
*selected* value, a discrepancy fact (and, at persistence time, a Finding) is
produced. Comparisons against unknown packet facts produce nothing.
"""

from typing import Any

from ipsec_analyzer.models import EvidenceSource, EvidenceVisibility
from ipsec_analyzer.pipeline.evidence import EvidenceDraft


def _add(facts, name, value, limitation=None):
    facts.append(
        EvidenceDraft(
            fact_name=name,
            fact_value=value,
            source=EvidenceSource.LAB_MANIFEST,
            visibility=EvidenceVisibility.VISIBLE,
            confidence=1.0,
            quality=1.0,
            limitation=limitation or "declared by lab manifest; not packet-observed",
        )
    )


def manifest_facts(manifest: dict[str, Any]) -> list[EvidenceDraft]:
    facts: list[EvidenceDraft] = []
    _add(
        facts,
        "lab.testbed_run",
        {
            "testbed_id": manifest.get("testbed_id"),
            "run_id": manifest.get("run_id"),
            "capture_id": manifest.get("capture_id"),
        },
    )
    if manifest.get("ike_version") is not None:
        _add(facts, "lab.ike_version", manifest["ike_version"])
    if manifest.get("selected_ike"):
        _add(facts, "lab.ike_sa.selected_config", manifest["selected_ike"])
    if manifest.get("mode"):
        _add(facts, "lab.vpn_mode", manifest["mode"])
    if manifest.get("ip_version") is not None:
        _add(facts, "lab.ip_version", manifest["ip_version"])
    if manifest.get("esp"):
        _add(facts, "lab.esp_config", manifest["esp"])
    if manifest.get("configured_sa_lifetime_seconds") is not None:
        _add(
            facts, "lab.configured_sa_lifetime_seconds", manifest["configured_sa_lifetime_seconds"]
        )
    if manifest.get("replay_protection_enabled") is not None:
        _add(
            facts,
            "lab.replay_protection",
            {
                "enabled": manifest.get("replay_protection_enabled"),
                "window_size": manifest.get("replay_window_size"),
            },
        )
    if manifest.get("traffic_category"):
        _add(facts, "lab.traffic_category", manifest["traffic_category"])
    if manifest.get("lab_application_label"):
        _add(
            facts,
            "lab.application_label",
            manifest["lab_application_label"],
            limitation="lab-only ground truth for evaluation; not a validated "
            "production application identification",
        )
    return facts


def _observed_selected(facts_by_name: dict[str, EvidenceDraft], key: str):
    draft = facts_by_name.get(f"ike_sa.selected.{key}")
    if draft is None or draft.source.name != "PACKET_OBSERVED":
        return None
    return draft.fact_value


def discrepancies(
    manifest: dict[str, Any], packet_facts: list[EvidenceDraft]
) -> list[EvidenceDraft]:
    by_name = {f.fact_name: f for f in packet_facts}
    out: list[EvidenceDraft] = []
    selected_ike = manifest.get("selected_ike") or {}
    checks = [
        ("encryption_algorithm", selected_ike.get("encryption")),
        ("integrity_algorithm", selected_ike.get("integrity")),
        ("prf_algorithm", selected_ike.get("prf")),
        ("dh_group", selected_ike.get("dh_group")),
        ("key_length", selected_ike.get("key_length")),
    ]
    for label, manifest_value in checks:
        if manifest_value is None:
            continue
        observed = _observed_selected(by_name, label)
        if observed is None:
            continue  # packet side unknown: no conflict can be claimed
        observed_values = observed if isinstance(observed, list) else [observed]
        if str(manifest_value).lower() not in [str(v).lower() for v in observed_values]:
            out.append(
                EvidenceDraft(
                    fact_name=f"discrepancy.ike_sa.{label}",
                    fact_value={
                        "lab_manifest": manifest_value,
                        "packet_observed": observed,
                        "sources_retained": ["lab_manifest", "packet_observed"],
                    },
                    source=EvidenceSource.LAB_MANIFEST,
                    visibility=EvidenceVisibility.DERIVED,
                    confidence=1.0,
                    limitation="manifest and packet-observed selection disagree; "
                    "both sources are retained and neither is overwritten",
                )
            )
    return out
