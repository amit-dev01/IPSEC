import uuid

from ipsec_analyzer.core.integrity import sha256_bytes
from ipsec_analyzer.evidence.types import EvidenceStatus
from ipsec_analyzer.storage.keys import capture_object_key


def test_sha256_known_vector() -> None:
    assert sha256_bytes(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_object_key_is_tenant_scoped_random_and_filename_free() -> None:
    tenant, capture = uuid.uuid4(), uuid.uuid4()
    key = capture_object_key(tenant, capture)
    assert key.startswith(f"tenants/{tenant}/captures/{capture}/")
    assert "passwd" not in key and ".." not in key
    # Random per call: never derived from user input.
    assert capture_object_key(tenant, capture) != key


def test_unknown_evidence_is_explicit() -> None:
    assert EvidenceStatus.UNKNOWN.value == "unknown"
    assert EvidenceStatus.INSUFFICIENT_EVIDENCE.value == "insufficient_evidence"
