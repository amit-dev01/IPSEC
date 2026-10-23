"""ML baseline tests: features, group-split, abstention, missing model, export."""

import uuid

import pytest
from fastapi.testclient import TestClient

from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.core.security import create_access_token, hash_password
from ipsec_analyzer.db.session import get_db
from ipsec_analyzer.main import create_app
from ipsec_analyzer.ml.classifier import TrafficClassifier, unavailable_prediction
from ipsec_analyzer.ml.features import FEATURE_NAMES, capture_features, flow_features
from ipsec_analyzer.ml.training import train_and_evaluate
from ipsec_analyzer.models import (
    AnalysisRun,
    Capture,
    CaptureFormat,
    CaptureManifest,
    CaptureState,
    Organization,
    User,
    UserRole,
)
from ipsec_analyzer.parsing.types import PacketSummary


def _packets(n=6, length=1200, interval=0.01, proto="esp"):
    return [
        PacketSummary(
            frame=i + 1,
            timestamp=i * interval,
            length=length,
            protocol=proto,
            src="10.0.0.1",
            dst="10.0.0.2",
            esp_spi="0x1",
            esp_sequence=i,
            src_port=4500,
            dst_port=4500,
            nat_t=True,
        )
        for i in range(n)
    ]


def test_feature_generation_has_no_identifiers():
    rows = flow_features(_packets())
    assert len(rows) == 1
    row = rows[0]
    assert set(row) == set(FEATURE_NAMES)
    assert row["packet_count"] == 6
    assert row["esp_packet_ratio"] == 1.0
    assert row["nat_t"] == 1.0
    assert "10.0.0.1" not in str(row)  # raw IPs are never feature values
    agg = capture_features(_packets())
    assert agg["length_mean"] == 1200


def _rows():
    rows = []
    for gi in range(6):
        for label, length, interval in (("web", 1400, 0.005), ("voice", 200, 0.02)):
            feats = capture_features(_packets(8, length, interval))
            rows.append({"group": f"run-{gi}-{label}", "label": label, "features": feats})
    return rows


def test_group_split_training_and_model_card():
    rows = _rows()
    bundle, card = train_and_evaluate(rows, model_version="test-1.0")
    assert set(card["split"]["train_groups"]).isdisjoint(card["split"]["test_groups"])
    assert card["model_card_version"] == "1.0"
    assert card["metrics"]["confusion_matrix"]["labels"] == ["voice", "web"]
    assert "voice" in card["metrics"]["per_class"]
    assert bundle["model_version"] == "test-1.0"

    # Leakage guard: a single capture/group cannot be split.
    with pytest.raises(ValueError):
        train_and_evaluate(
            rows[:2] and [dict(rows[0], group="only"), dict(rows[1], group="only")],
            model_version="x",
        )


def test_inference_stable_and_abstention(tmp_path):
    import joblib

    bundle, _card = train_and_evaluate(_rows(), model_version="test-1.0")
    path = tmp_path / "model.joblib"
    joblib.dump(bundle, path)
    clf = TrafficClassifier.load(str(path), abstain_threshold=0.5)
    assert clf is not None
    feats = capture_features(_packets(8, 1400, 0.005))
    first = clf.predict(feats)
    second = clf.predict(feats)
    assert first == second  # stable output for identical input
    assert first["status"] in ("available", "unknown")
    assert first["features_used"] == FEATURE_NAMES
    assert (
        "not application" in first["limitations"]
        or "not application identification" in first["limitations"]
    )


class _StubProba:
    classes_ = ["web", "voice"]

    def predict_proba(self, x):
        return [[0.55, 0.45]]


def test_abstains_below_threshold_and_missing_model_unavailable():
    clf = TrafficClassifier(
        {"model": _StubProba(), "model_version": "stub-1", "classes": ["web"]},
        abstain_threshold=0.6,
    )
    out = clf.predict({name: 0.0 for name in FEATURE_NAMES})
    assert out["status"] == "unknown"
    assert out["predicted_category"] is None

    assert TrafficClassifier.load(None) is None
    assert TrafficClassifier.load("/nonexistent/model.joblib") is None
    unavailable = unavailable_prediction()
    assert unavailable["status"] == "unavailable"
    assert unavailable["predicted_category"] is None


# --- admin export ------------------------------------------------------------


@pytest.fixture()
def ctx(db):
    org = Organization(name="mlorg")
    db.add(org)
    db.flush()
    users = {}
    for role in (UserRole.ADMIN, UserRole.ANALYST):
        u = User(
            organization_id=org.id,
            email=f"{role.value}@ml.test",
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
        sha256="d" * 64,
        size_bytes=10,
        format=CaptureFormat.PCAP,
        state=CaptureState.READY,
    )
    db.add(cap)
    db.flush()
    db.add(
        CaptureManifest(
            organization_id=org.id,
            capture_id=cap.id,
            uploaded_by=users[UserRole.ADMIN].id,
            source="lab_manifest",
            schema_version="1.0",
            manifest={
                "run_id": "run-9",
                "traffic_category": "web",
                "lab_application_label": "WhatsApp",
            },
        )
    )
    run = AnalysisRun(
        organization_id=org.id,
        capture_id=cap.id,
        requester_id=users[UserRole.ADMIN].id,
        pipeline_version="tshark-parse-0.2",
        policy_version="policy-0.1",
        status="succeeded",
        summary={"flow_features": [{name: 1.0 for name in FEATURE_NAMES} | {"checked_no_ip": 1}]},
    )
    db.add(run)
    db.commit()
    settings = Settings(
        environment="test",
        jwt_signing_key="test-signing-key-that-is-long-enough-32",
        enable_docs=False,
    )
    app = create_app(settings)
    app.dependency_overrides[get_db] = lambda: (yield db)
    tokens = {role: create_access_token(settings, u.id, org.id) for role, u in users.items()}
    with TestClient(app) as client:
        yield {"client": client, "tokens": tokens}


def test_admin_export_is_deidentified_and_admin_only(ctx):
    admin = {"Authorization": f"Bearer {ctx['tokens'][UserRole.ADMIN]}"}
    analyst = {"Authorization": f"Bearer {ctx['tokens'][UserRole.ANALYST]}"}
    assert (
        ctx["client"].get("/api/v1/admin/exports/flow-dataset", headers=analyst).status_code == 403
    )

    r = ctx["client"].get("/api/v1/admin/exports/flow-dataset", headers=admin)
    assert r.status_code == 200, r.text
    rows = r.json()["rows"]
    assert len(rows) == 1
    row = rows[0]
    assert row["group"] == "run-9" and row["label"] == "web"
    # Lab label is retained only as lab ground truth; no identifiers exported.
    text = str(rows)
    assert "10.0.0" not in text and "object_key" not in text and "sha256" not in text
    assert "WhatsApp" in text  # lab-only label, labelled as such in docs/model card
