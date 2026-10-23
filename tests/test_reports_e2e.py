"""End-to-end lifecycle: upload -> queue -> worker (fake parser) -> evidence
-> assessment -> JSON/PDF reports, plus manifest non-overwrite behavior."""

import uuid

import pytest
from fastapi.testclient import TestClient

from ipsec_analyzer.core.security import create_access_token
from ipsec_analyzer.models import AnalysisRun, AuditEvent, UserRole
from ipsec_analyzer.workers.processing import process_analysis
from tests.test_analyses import PCAP, FakeParser, FakeStorage, _settings


def _token(settings, user):
    return create_access_token(settings, user_id=user.id, organization_id=user.organization_id)


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture()
def ctx(db):
    from ipsec_analyzer.core.security import hash_password
    from ipsec_analyzer.db.session import get_db
    from ipsec_analyzer.main import create_app
    from ipsec_analyzer.models import Organization, User

    settings = _settings()
    orgs = {}
    for name in ("reporgs", "reporgb"):
        org = Organization(name=name)
        db.add(org)
        db.flush()
        users = {}
        for role in (UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER):
            u = User(
                organization_id=org.id,
                email=f"{role.value}@{name}.test",
                password_hash=hash_password("pw"),
                role=role,
            )
            db.add(u)
            users[role] = u
        db.flush()
        orgs[name] = (org, users)

    storage = FakeStorage()
    dispatched = []
    app = create_app(settings)
    app.state.storage = storage
    app.state.dispatcher = lambda aid: dispatched.append(aid)

    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)
    return {
        "db": db,
        "settings": settings,
        "storage": storage,
        "client": client,
        "orgs": orgs,
        "dispatched": dispatched,
    }


def _upload_and_run(ctx, packets=None):
    org, users = ctx["orgs"]["reporgs"]
    analyst = users[UserRole.ANALYST]
    tok = _token(ctx["settings"], analyst)
    r = ctx["client"].post(
        "/api/v1/captures",
        headers=_h(tok),
        files={"file": ("lab.pcap", PCAP, "application/octet-stream")},
    )
    assert r.status_code == 201, r.text
    cap_id = r.json()["id"]
    r = ctx["client"].post(f"/api/v1/captures/{cap_id}/analyses", headers=_h(tok))
    assert r.status_code == 202, r.text
    run_id = uuid.UUID(r.json()["id"])
    assert ctx["dispatched"] == [run_id]  # ID-only dispatch happened after row stored
    process_analysis(ctx["db"], ctx["storage"], run_id, ctx["settings"], parser=FakeParser(packets))
    return cap_id, run_id, tok, users


def test_full_lifecycle_and_reports(ctx):
    cap_id, run_id, tok, users = _upload_and_run(ctx)
    db = ctx["db"]
    run = db.get(AnalysisRun, run_id)
    assert str(run.status) == "succeeded"

    # Detail separates sections; ESP cipher stays explicitly unknown.
    detail = ctx["client"].get(f"/api/v1/analyses/{run_id}", headers=_h(tok))
    assert detail.status_code == 200
    body = detail.json()
    assert body["report_url"] == f"/api/v1/analyses/{run_id}/report"
    unknown_names = {f["fact_name"] for f in body["unknown_facts"]}
    assert "esp.encryption_algorithm" in unknown_names
    assert all(f["source"] == "packet_observed" for f in body["packet_observed_facts"])

    # JSON report
    rep = ctx["client"].get(f"/api/v1/analyses/{run_id}/report", headers=_h(tok))
    assert rep.status_code == 200
    doc = rep.json()
    assert doc["executive_summary"]["assessment_status"] in (
        "assessed",
        "partial",
        "insufficient_evidence",
    )
    assert "esp.encryption_algorithm" in {
        u["fact"] for u in doc["unknowns_and_limitations"]["unknowns"]
    }
    assert doc["versions"]["policy_version"] == "default-2026.1"
    assert "tenants/" not in rep.text and "object_key" not in rep.text

    # PDF report (magic + escaping path exercised)
    pdf = ctx["client"].get(f"/api/v1/analyses/{run_id}/report?format=pdf", headers=_h(tok))
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"

    # Audit trail includes report generation.
    actions = {e.action for e in db.query(AuditEvent).all()}
    assert "report.generated" in actions and "capture.uploaded" in actions

    # Pagination envelopes
    page = ctx["client"].get(f"/api/v1/captures/{cap_id}/analyses", headers=_h(tok)).json()
    assert page["total"] == 1 and page["items"][0]["id"] == str(run_id)
    caps = ctx["client"].get("/api/v1/captures?limit=1", headers=_h(tok)).json()
    assert caps["limit"] == 1 and caps["total"] >= 1

    # Problem Details shape on 404, with legacy `detail` retained.
    missing = ctx["client"].get(f"/api/v1/analyses/{uuid.uuid4()}", headers=_h(tok))
    assert missing.status_code == 404
    assert missing.json()["code"] and missing.json()["detail"]


def test_report_access_control(ctx):
    cap_id, run_id, tok, users = _upload_and_run(ctx)
    org_b, users_b = ctx["orgs"]["reporgb"]
    intruder = _token(ctx["settings"], users_b[UserRole.ADMIN])
    assert (
        ctx["client"].get(f"/api/v1/analyses/{run_id}/report", headers=_h(intruder)).status_code
        == 404
    )
    assert (
        ctx["client"]
        .get(f"/api/v1/analyses/{run_id}/report?format=pdf", headers=_h(intruder))
        .status_code
        == 404
    )
    # Unauthenticated access is denied; same-tenant viewer may download.
    assert ctx["client"].get(f"/api/v1/analyses/{run_id}/report").status_code == 401
    viewer = _token(ctx["settings"], users[UserRole.VIEWER])
    assert (
        ctx["client"].get(f"/api/v1/analyses/{run_id}/report", headers=_h(viewer)).status_code
        == 200
    )


def test_manifest_supplies_config_without_overwriting_packet_facts(ctx):
    org, users = ctx["orgs"]["reporgs"]
    analyst = users[UserRole.ANALYST]
    tok = _token(ctx["settings"], analyst)
    r = ctx["client"].post(
        "/api/v1/captures",
        headers=_h(tok),
        files={"file": ("lab.pcap", PCAP, "application/octet-stream")},
    )
    cap_id = r.json()["id"]
    from tests.test_manifest import MANIFEST

    manifest = MANIFEST
    r = ctx["client"].post(f"/api/v1/captures/{cap_id}/manifest", headers=_h(tok), json=manifest)
    assert r.status_code == 201, r.text
    r = ctx["client"].post(f"/api/v1/captures/{cap_id}/analyses", headers=_h(tok))
    run_id = uuid.UUID(r.json()["id"])
    process_analysis(ctx["db"], ctx["storage"], run_id, ctx["settings"], parser=FakeParser())
    body = ctx["client"].get(f"/api/v1/analyses/{run_id}", headers=_h(tok)).json()
    supplied = {f["fact_name"]: f["fact_value"] for f in body["supplied_facts"]}
    packet = {f["fact_name"]: f["fact_value"] for f in body["packet_observed_facts"]}
    # Manifest config present as supplied evidence...
    assert any("pfs" in k or "esp" in k for k in supplied)
    # ...and packet-observed ESP cipher remains unknown, not overwritten.
    assert "esp.encryption_algorithm" in {f["fact_name"] for f in body["unknown_facts"]}
    assert packet.get("esp.encryption_algorithm") is None
