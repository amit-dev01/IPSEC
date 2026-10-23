"""Protocol evidence extraction from packet summaries.

Every fact carries: name, value, source, visibility, confidence/quality,
packet/frame references (capped), and a limitation where relevant.

Hard rules enforced here:
- Offered transforms are never presented as negotiated/selected ones.
- Child-SA/ESP parameters negotiated inside encrypted IKE_AUTH are `unknown`.
- The ESP cipher is never inferred from ESP packet bytes.
- PFS, replay-window configuration, and configured SA lifetimes are `unknown`
  from passive observation; an observed rekey interval is labelled derived
  with an explicit "not the configured lifetime" limitation.
- Outer addresses are hashed unless plaintext evidence addresses are
  explicitly enabled in configuration.
"""

import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from ipsec_analyzer.models import EvidenceSource, EvidenceVisibility
from ipsec_analyzer.parsing.types import PacketSummary

_MAX_REFS = 20


@dataclass
class EvidenceDraft:
    fact_name: str
    fact_value: Any
    source: EvidenceSource
    visibility: EvidenceVisibility
    confidence: float | None = 1.0
    quality: float | None = 1.0
    packet_refs: list[dict[str, int]] | None = None
    limitation: str | None = None


@dataclass
class _EspObs:
    count: int = 0
    seq_min: int | None = None
    seq_max: int | None = None
    duplicates: int = 0
    refs: list[dict[str, int]] = field(default_factory=list)
    _seen: set[int] = field(default_factory=set)


def _hash_addr(addr: str) -> str:
    return "sha256:" + hashlib.sha256(f"addr:{addr}".encode()).hexdigest()[:16]


def _transform_dicts(proposals, role: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in proposals:
        if p.role != role:
            continue
        for t in p.transforms:
            out.append(
                {
                    "protocol": t.protocol,
                    "encryption": t.encryption,
                    "key_length": t.key_length,
                    "integrity": t.integrity,
                    "prf": t.prf,
                    "dh_group": t.dh_group,
                }
            )
    return out


def _values(transforms: list[dict[str, Any]], key: str) -> list[Any]:
    return sorted({t[key] for t in transforms if t.get(key) is not None}, key=str)


def build_evidence(
    packets: list[PacketSummary], *, allow_plain_addresses: bool = False
) -> list[EvidenceDraft]:
    facts: list[EvidenceDraft] = []

    def add(name, value, source, visibility, confidence=1.0, refs=None, limitation=None):
        facts.append(
            EvidenceDraft(
                fact_name=name,
                fact_value=value,
                source=source,
                visibility=visibility,
                confidence=confidence,
                quality=confidence,
                packet_refs=(refs or [])[:_MAX_REFS] or None,
                limitation=limitation,
            )
        )

    def refs_for(pred) -> list[dict[str, int]]:
        return [{"frame": p.frame} for p in packets if pred(p)][:_MAX_REFS]

    protocols = Counter(p.protocol for p in packets if p.protocol in ("esp", "ah", "ike"))
    if protocols:
        add(
            "ipsec.protocols_observed",
            sorted(protocols),
            EvidenceSource.PACKET_OBSERVED,
            EvidenceVisibility.VISIBLE,
            refs=refs_for(lambda p: p.protocol in ("esp", "ah", "ike")),
        )
    add(
        "capture.packet_count_observed",
        len(packets),
        EvidenceSource.PACKET_OBSERVED,
        EvidenceVisibility.DERIVED,
        confidence=0.99,
    )

    # --- outer endpoints (privacy-controlled) ---
    pairs = {(p.src, p.dst) for p in packets if p.src and p.dst}

    def render(addr: str) -> str:
        return addr if allow_plain_addresses else _hash_addr(addr)

    if pairs:
        add(
            "network.outer_endpoints",
            [{"src": render(s), "dst": render(d)} for s, d in sorted(pairs)][:50],
            EvidenceSource.PACKET_OBSERVED,
            EvidenceVisibility.VISIBLE,
            refs=refs_for(lambda p: bool(p.src)),
            limitation=None
            if allow_plain_addresses
            else "endpoint identifiers hashed (privacy control); "
            "enable explicitly to store plaintext",
        )

    # --- IKE ---
    ike_packets = [p for p in packets if p.protocol == "ike"]
    if ike_packets:
        versions = sorted({p.ike_version for p in ike_packets if p.ike_version})
        if versions:
            add(
                "ike.version",
                versions,
                EvidenceSource.PACKET_OBSERVED,
                EvidenceVisibility.VISIBLE,
                refs=[{"frame": p.frame} for p in ike_packets][:_MAX_REFS],
            )
        exchanges = sorted({p.ike_exchange_type for p in ike_packets if p.ike_exchange_type})
        if exchanges:
            add(
                "ike.exchange_types_observed",
                exchanges,
                EvidenceSource.PACKET_OBSERVED,
                EvidenceVisibility.VISIBLE,
                refs=[{"frame": p.frame} for p in ike_packets][:_MAX_REFS],
            )
        nat_t = any(p.nat_t for p in packets)
        add(
            "ike.nat_traversal_observed",
            nat_t,
            EvidenceSource.PACKET_OBSERVED,
            EvidenceVisibility.VISIBLE,
            refs=refs_for(lambda p: p.nat_t),
            limitation="NAT-T inferred from UDP/4500 usage with IKE/ESP, when observed",
        )

        all_proposals = [pr for p in ike_packets for pr in p.proposals]
        offered = _transform_dicts(all_proposals, "offered")
        selected = _transform_dicts(all_proposals, "selected")
        if offered:
            add(
                "ike_sa.proposals_offered",
                offered,
                EvidenceSource.PACKET_OBSERVED,
                EvidenceVisibility.VISIBLE,
                refs=[{"frame": p.frame} for p in ike_packets if p.proposals][:_MAX_REFS],
                limitation="offered by the initiator; NOT the negotiated result",
            )
            for key, label in (
                ("encryption", "encryption_algorithms"),
                ("integrity", "integrity_algorithms"),
                ("prf", "prf_algorithms"),
                ("dh_group", "dh_groups"),
                ("key_length", "key_lengths"),
            ):
                vals = _values(offered, key)
                if vals:
                    add(
                        f"ike_sa.offered.{label}",
                        vals,
                        EvidenceSource.PACKET_OBSERVED,
                        EvidenceVisibility.VISIBLE,
                        limitation="offered only; do not treat as selected",
                    )
        if selected:
            add(
                "ike_sa.proposal_selected",
                selected,
                EvidenceSource.PACKET_OBSERVED,
                EvidenceVisibility.VISIBLE,
                limitation="as returned in the responder's IKE_SA_INIT response, when captured",
            )
            for key, label in (
                ("encryption", "encryption_algorithm"),
                ("integrity", "integrity_algorithm"),
                ("prf", "prf_algorithm"),
                ("dh_group", "dh_group"),
                ("key_length", "key_length"),
            ):
                vals = _values(selected, key)
                if vals:
                    add(
                        f"ike_sa.selected.{label}",
                        vals[0] if len(vals) == 1 else vals,
                        EvidenceSource.PACKET_OBSERVED,
                        EvidenceVisibility.VISIBLE,
                    )
        else:
            add(
                "ike_sa.selected_transforms",
                None,
                EvidenceSource.UNKNOWN,
                EvidenceVisibility.ENCRYPTED_OR_UNAVAILABLE,
                confidence=0.0,
                limitation="no responder IKE_SA_INIT selection visible in this capture",
            )
        # Observed rekey cadence is NOT the configured lifetime.
        init_times = sorted(
            p.timestamp
            for p in ike_packets
            if p.ike_exchange_type in ("34", "IKE_SA_INIT") and p.timestamp is not None
        )
        if len(init_times) >= 2:
            intervals = [
                round(b - a, 3) for a, b in zip(init_times, init_times[1:], strict=False) if b > a
            ]
            if intervals:
                add(
                    "ike.observed_rekey_intervals_seconds",
                    intervals,
                    EvidenceSource.PACKET_OBSERVED,
                    EvidenceVisibility.DERIVED,
                    confidence=0.5,
                    limitation="observed interval between negotiations in this capture; "
                    "this is NOT the configured SA lifetime",
                )

    # --- ESP / AH ---
    for proto, spi_attr, seq_attr in (
        ("esp", "esp_spi", "esp_sequence"),
        ("ah", "ah_spi", "ah_sequence"),
    ):
        obs: dict[str, _EspObs] = defaultdict(_EspObs)
        for p in packets:
            if p.protocol != proto:
                continue
            spi = getattr(p, spi_attr)
            if spi is None:
                continue
            o = obs[str(spi)]
            o.count += 1
            seq = getattr(p, seq_attr)
            if seq is not None:
                if seq in o._seen:
                    o.duplicates += 1
                o._seen.add(seq)
                o.seq_min = seq if o.seq_min is None else min(o.seq_min, seq)
                o.seq_max = seq if o.seq_max is None else max(o.seq_max, seq)
            if len(o.refs) < _MAX_REFS:
                o.refs.append({"frame": p.frame})
        for spi, o in sorted(obs.items()):
            add(
                f"{proto}.spi_observed",
                {
                    "spi": spi,
                    "packets": o.count,
                    "sequence_min": o.seq_min,
                    "sequence_max": o.seq_max,
                    "duplicate_sequences_observed": o.duplicates,
                },
                EvidenceSource.PACKET_OBSERVED,
                EvidenceVisibility.VISIBLE,
                refs=o.refs,
                limitation="sequence observations describe this capture only; they do "
                "not reveal the configured replay window",
            )

    # --- Explicit unknowns (never promoted to secure/known) ---
    add(
        "esp.encryption_algorithm",
        None,
        EvidenceSource.UNKNOWN,
        EvidenceVisibility.ENCRYPTED_OR_UNAVAILABLE,
        confidence=0.0,
        limitation="ESP payloads are encrypted; the cipher is negotiated inside "
        "encrypted IKE_AUTH and cannot be read from ESP packet bytes",
    )
    add(
        "child_sa.proposals",
        None,
        EvidenceSource.UNKNOWN,
        EvidenceVisibility.ENCRYPTED_OR_UNAVAILABLE,
        confidence=0.0,
        limitation="Child-SA negotiation occurs inside encrypted IKE_AUTH; "
        "not recoverable from a passive capture (IKE-SA transforms are kept separate)",
    )
    add(
        "vpn.mode",
        None,
        EvidenceSource.UNKNOWN,
        EvidenceVisibility.ENCRYPTED_OR_UNAVAILABLE,
        confidence=0.0,
        limitation="tunnel/transport mode is not explicitly signalled in ESP bytes; "
        "traffic selectors are encrypted. Requires analyst/lab-supplied evidence",
    )
    add(
        "security.pfs",
        None,
        EvidenceSource.UNKNOWN,
        EvidenceVisibility.ENCRYPTED_OR_UNAVAILABLE,
        confidence=0.0,
        limitation="PFS for Child SAs is negotiated inside encrypted IKE_AUTH",
    )
    add(
        "security.replay_window_configured",
        None,
        EvidenceSource.UNKNOWN,
        EvidenceVisibility.ENCRYPTED_OR_UNAVAILABLE,
        confidence=0.0,
        limitation="replay-window size is endpoint configuration, not signalled on the wire",
    )
    add(
        "security.configured_sa_lifetime",
        None,
        EvidenceSource.UNKNOWN,
        EvidenceVisibility.ENCRYPTED_OR_UNAVAILABLE,
        confidence=0.0,
        limitation="configured lifetimes are not signalled; observed rekey timing "
        "is not the configured lifetime",
    )
    return facts
