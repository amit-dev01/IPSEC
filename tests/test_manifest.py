"""Lab-manifest tests: schema, secrets, tenant access, discrepancies."""

import uuid

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.core.security import create_access_token, hash_password
from ipsec_analyzer.db.session import get_db
from ipsec_analyzer.main import create_app
from ipsec_analyzer.models import (
    Capture,
    CaptureFormat,
    CaptureState,
    EvidenceSource,
    Organization,
    User,
    UserRole,
)
from ipsec_analyzer.pipeline.evidence import EvidenceDraft
from ipsec_analyzer.pipeline.manifest_facts import discrepancies, manifest_facts
from ipsec_analyzer.schemas.manifest import LabManifestV1

MANIFEST = {
    "schema_version": "1.0",
    "testbed_id": "lab-1",
    "run_id": "run-42",
    "capture_id": "session-7",
    "ike_version": 2,
    "selected_ike": {"encryption": "AES-GCM", "key_length": 256, "dh_group": "20"},
    "mode": "tunnel",
    "ip_version": 4,
    "esp": {
        "encryption": "AES-GCM",
        "key_length": 256,
        "aead": True,
        "pfs_enabled": True,
        "dh_group": "20",
    },
    "configured_sa_lifetime_seconds": 3600,
    "replay_protection_enabled": True,
    "replay_window_size": 1024,
    "traffic_category": "web",
    "lab_application_label": "WhatsApp",
}


def test_valid_manifest_and_lab_facts():
    m = LabManifestV1(**MANIFEST)
    assert m.traffic_category.value == "web"
    facts = {f.fact_name: f for f in manifest_facts(m.model_dump(mode="json"))}
    assert facts["lab.vpn_mode"].fact_value == "tunnel"
    assert facts["lab.configured_sa_lifetime_seconds"].fact_value == 3600
    # Lab app label stays labelled lab-only ground truth, never packet-observed.
    assert facts["lab.application_label"].source is EvidenceSource.LAB_MANIFEST
    assert "lab-only" in facts["lab.application_label"].limitation


@pytest.mark.parametrize(
    "bad",
    [
        {**MANIFEST, "schema_version": "9.9"},
        {**MANIFEST, "ike_version": 7},
        {**MANIFEST, "mode": "sideways"},
        {**MANIFEST, "traffic_category": "tiktok-live"},
        {**MANIFEST, "esp": {"encryption": "AES-GCM", "psk": "supersecret"}},
        {**MANIFEST, "private_key": "-----BEGIN-----"},
        {**MANIFEST, "selected_ike": {"encryption": "AES", "session_key": "abcd"}},
        {k: v for k, v in MANIFEST.items() if k != "run_id"},
    ],
)
def test_invalid_schemas_and_secret_fields_rejected(bad):
    with pytest.raises(ValidationError):
        LabManifestV1(**bad)


@pytest.fixture()
def ctx(db):
    def make(name):
        org = Organization(name=name)
        db.add(org)
        db.flush()
        users = {}
        for role in (UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER):
            u = User(
                organization_id=org.id,
                email=f"{role.value}@{name}.test",
                password_hash=hash_password("pw-irrelevant"),
                role=role,
            )
            db.add(u)
            users[role] = u
        db.flush()
        cap = Capture(
            organization_id=org.id,
            uploader_id=users[UserRole.ADMIN].id,
            display_name="c.pcap",
            object_key=f"obj-{uuid.uuid4()}",
            sha256="c" * 64,
            size_bytes=10,
            format=CaptureFormat.PCAP,
            state=CaptureState.READY,
        )
        db.add(cap)
        db.commit()
        return org, users, cap

    a = make("manorga")
    b = make("manorgb")
    settings = Settings(
        environment="test",
        jwt_signing_key="test-signing-key-that-is-long-enough-32",
        enable_docs=False,
    )
    app = create_app(settings)
    app.dependency_overrides[get_db] = lambda: (yield db)
    tokens = {
        (org.id, role): create_access_token(settings, u.id, org.id)
        for org, users, _c in (a, b)
        for role, u in users.items()
    }
    with TestClient(app) as client:
        yield {"client": client, "db": db, "a": a, "b": b, "tokens": tokens}


def _h(ctx, org, role=UserRole.ADMIN):
    return {"Authorization": f"Bearer {ctx['tokens'][(org.id, role)]}"}


def test_manifest_attach_get_and_tenant_access(ctx):
    org_a, _ua, cap_a = ctx["a"]
    org_b, _ub, _cap_b = ctx["b"]
    r = ctx["client"].post(
        f"/api/v1/captures/{cap_a.id}/manifest",
        json=MANIFEST,
        headers=_h(ctx, org_a, UserRole.ANALYST),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["schema_version"] == "1.0" and body["source"] == "lab_manifest"
    assert body["uploaded_by"]

    got = ctx["client"].get(
        f"/api/v1/captures/{cap_a.id}/manifest", headers=_h(ctx, org_a, UserRole.VIEWER)
    )
    assert got.status_code == 200
    assert got.json()["manifest"]["run_id"] == "run-42"

    # Cross-tenant attach/get are 404; viewer cannot attach.
    assert (
        ctx["client"]
        .post(f"/api/v1/captures/{cap_a.id}/manifest", json=MANIFEST, headers=_h(ctx, org_b))
        .status_code
        == 404
    )
    assert (
        ctx["client"]
        .get(f"/api/v1/captures/{cap_a.id}/manifest", headers=_h(ctx, org_b))
        .status_code
        == 404
    )
    assert (
        ctx["client"]
        .post(
            f"/api/v1/captures/{cap_a.id}/manifest",
            json=MANIFEST,
            headers=_h(ctx, org_a, UserRole.VIEWER),
        )
        .status_code
        == 403
    )


def test_manifest_secret_payload_rejected_by_api(ctx):
    org_a, _ua, cap_a = ctx["a"]
    bad = {**MANIFEST, "psk": "do-not-store-me"}
    r = ctx["client"].post(
        f"/api/v1/captures/{cap_a.id}/manifest", json=bad, headers=_h(ctx, org_a)
    )
    assert r.status_code == 422
    assert (
        ctx["client"]
        .get(f"/api/v1/captures/{cap_a.id}/manifest", headers=_h(ctx, org_a))
        .status_code
        == 404
    )


def test_manifest_packet_conflict_produces_discrepancy_without_overwrite():
    observed = [
        EvidenceDraft(
            fact_name="ike_sa.selected.encryption_algorithm",
            fact_value="AES-CBC",
            source=EvidenceSource.PACKET_OBSERVED,
            visibility="visible",
        ),
    ]
    # MANIFEST selected_ike.encryption = AES-GCM vs observed AES-CBC -> conflict.
    out = discrepancies(MANIFEST, observed)
    assert len(out) == 1
    d = out[0]
    assert d.fact_value["lab_manifest"] == "AES-GCM"
    assert d.fact_value["packet_observed"] == "AES-CBC"
    assert d.fact_value["sources_retained"] == ["lab_manifest", "packet_observed"]
    # No conflict when they agree.
    agreeing = {**MANIFEST, "selected_ike": {"encryption": "AES-CBC"}}
    assert discrepancies(agreeing, observed) == []
    # No discrepancy claimed when the packet side is unknown.
    assert discrepancies(MANIFEST, []) == []
