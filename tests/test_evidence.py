from ipsec_analyzer.models import EvidenceSource, EvidenceVisibility
from ipsec_analyzer.parsing.types import PacketSummary, Proposal, TransformSet
from ipsec_analyzer.pipeline.evidence import build_evidence


def _by_name(facts):
    return {f.fact_name: f for f in facts}


def _ike_packets():
    offered = Proposal(
        role="offered",
        transforms=[
            TransformSet(
                protocol="IKE",
                encryption="AES-CBC",
                key_length=256,
                integrity="HMAC-SHA256",
                prf="PRF-HMAC-SHA256",
                dh_group="14",
            ),
            TransformSet(
                protocol="IKE",
                encryption="3DES",
                key_length=None,
                integrity="HMAC-SHA1",
                prf="PRF-HMAC-SHA1",
                dh_group="2",
            ),
        ],
    )
    selected = Proposal(
        role="selected",
        transforms=[
            TransformSet(
                protocol="IKE",
                encryption="AES-CBC",
                key_length=256,
                integrity="HMAC-SHA256",
                prf="PRF-HMAC-SHA256",
                dh_group="14",
            )
        ],
    )
    return [
        PacketSummary(
            frame=1,
            timestamp=1.0,
            length=300,
            protocol="ike",
            src="10.0.0.1",
            dst="10.0.0.2",
            src_port=500,
            dst_port=500,
            ike_version="2",
            ike_exchange_type="34",
            proposals=[offered],
        ),
        PacketSummary(
            frame=2,
            timestamp=1.1,
            length=200,
            protocol="ike",
            src="10.0.0.2",
            dst="10.0.0.1",
            src_port=500,
            dst_port=500,
            ike_version="2",
            ike_exchange_type="34",
            ike_is_response=True,
            proposals=[selected],
        ),
        PacketSummary(
            frame=3,
            timestamp=1.2,
            length=120,
            protocol="esp",
            src="10.0.0.1",
            dst="10.0.0.2",
            esp_spi="0x00001001",
            esp_sequence=10,
        ),
        PacketSummary(
            frame=4,
            timestamp=1.3,
            length=120,
            protocol="esp",
            src="10.0.0.1",
            dst="10.0.0.2",
            esp_spi="0x00001001",
            esp_sequence=10,
        ),
    ]


def test_visible_ike_esp_facts_and_offered_vs_selected():
    facts = _by_name(build_evidence(_ike_packets()))
    assert facts["ike.version"].fact_value == ["2"]
    assert facts["ipsec.protocols_observed"].fact_value == ["esp", "ike"]
    offered = facts["ike_sa.proposals_offered"].fact_value
    assert {t["encryption"] for t in offered} == {"AES-CBC", "3DES"}
    # 3DES was offered but must NOT appear as selected.
    assert facts["ike_sa.selected.encryption_algorithm"].fact_value == "AES-CBC"
    assert facts["ike_sa.offered.encryption_algorithms"].fact_value == ["3DES", "AES-CBC"]
    assert "ike_sa.selected_transforms" not in facts
    esp = facts["esp.spi_observed"].fact_value
    assert esp["spi"] == "0x00001001"
    assert esp["sequence_min"] == 10 and esp["duplicate_sequences_observed"] == 1
    assert facts["esp.spi_observed"].packet_refs == [{"frame": 3}, {"frame": 4}]
    # IKE-SA transforms are stored distinctly from Child-SA/ESP transforms.
    assert facts["child_sa.proposals"].source is EvidenceSource.UNKNOWN


def test_encrypted_and_unobservable_facts_are_unknown():
    facts = _by_name(build_evidence(_ike_packets()))
    for name in (
        "esp.encryption_algorithm",
        "child_sa.proposals",
        "vpn.mode",
        "security.pfs",
        "security.replay_window_configured",
        "security.configured_sa_lifetime",
    ):
        f = facts[name]
        assert f.fact_value is None
        assert f.source is EvidenceSource.UNKNOWN
        assert f.visibility is EvidenceVisibility.ENCRYPTED_OR_UNAVAILABLE
        assert f.confidence == 0.0
        assert f.limitation  # explanation is mandatory


def test_addresses_hashed_by_default_and_no_plain_leak():
    facts = _by_name(build_evidence(_ike_packets()))
    endpoints = facts["network.outer_endpoints"].fact_value
    rendered = str(endpoints)
    assert "10.0.0.1" not in rendered and "sha256:" in rendered
    plain = _by_name(build_evidence(_ike_packets(), allow_plain_addresses=True))
    assert "10.0.0.1" in str(plain["network.outer_endpoints"].fact_value)


def test_selected_unknown_when_no_responder_selection():
    packets = [p for p in _ike_packets() if p.frame == 1]  # only initiator offer
    facts = _by_name(build_evidence(packets))
    f = facts["ike_sa.selected_transforms"]
    assert f.fact_value is None and f.source is EvidenceSource.UNKNOWN
    assert "ike_sa.proposal_selected" not in facts
