import uuid

from ipsec_analyzer.db.repository import get_capture_for_tenant
from ipsec_analyzer.models import Capture, CaptureFormat, Organization, User


def _seed(db, org_name: str, email: str):
    org = Organization(id=uuid.uuid4(), name=org_name)
    user = User(id=uuid.uuid4(), organization_id=org.id, email=email)
    db.add_all([org, user])
    db.flush()
    return org, user


def test_capture_lookup_is_tenant_scoped(db) -> None:
    org_a, user_a = _seed(db, "a", "a@example.test")
    org_b, _ = _seed(db, "b", "b@example.test")
    capture = Capture(
        organization_id=org_a.id,
        uploader_id=user_a.id,
        display_name="a.pcap",
        object_key=f"tenants/{org_a.id}/captures/x/a.pcap",
        sha256="0" * 64,
        size_bytes=1,
        format=CaptureFormat.PCAP,
    )
    db.add(capture)
    db.commit()
    assert get_capture_for_tenant(db, org_a.id, capture.id) is not None
    assert get_capture_for_tenant(db, org_b.id, capture.id) is None
