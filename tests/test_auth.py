"""AuthN/AuthZ tests against PostgreSQL (skipped without IPSEC_TEST_DATABASE_URL)."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from ipsec_analyzer.admin import create_org_admin
from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.core.security import (
    TokenError,
    create_access_token,
    decode_access_token,
    hash_password,
)
from ipsec_analyzer.db.session import get_db
from ipsec_analyzer.main import create_app
from ipsec_analyzer.models import (
    AnalysisRun,
    Capture,
    CaptureFormat,
    Organization,
    User,
    UserRole,
)

PASSWORD = "correct-horse-battery"  # noqa: S105 - test fixture credential
SHA = "b" * 64


def _settings(**kw) -> Settings:
    base = {
        "environment": "test",
        "jwt_signing_key": "test-signing-key-that-is-long-enough-32",
        "enable_docs": False,
        "login_max_attempts": 5,
        "login_window_seconds": 300,
    }
    base.update(kw)
    return Settings(**base)


@pytest.fixture()
def seeded(db):
    def make_org(name: str):
        org = Organization(name=name)
        db.add(org)
        db.flush()
        users = {}
        for role in UserRole:
            u = User(
                organization_id=org.id,
                email=f"{role.value}@{name}.test",
                password_hash=hash_password(PASSWORD),
                role=role,
            )
            db.add(u)
            users[role] = u
        inactive = User(
            organization_id=org.id,
            email=f"inactive@{name}.test",
            password_hash=hash_password(PASSWORD),
            role=UserRole.ANALYST,
            is_active=False,
        )
        db.add(inactive)
        users["inactive"] = inactive
        db.flush()
        capture = Capture(
            organization_id=org.id,
            uploader_id=users[UserRole.ADMIN].id,
            display_name=f"{name}.pcap",
            object_key=f"obj-{uuid.uuid4()}",
            sha256=SHA,
            size_bytes=10,
            format=CaptureFormat.PCAP,
        )
        db.add(capture)
        db.flush()
        run = AnalysisRun(
            organization_id=org.id,
            capture_id=capture.id,
            requester_id=users[UserRole.ADMIN].id,
            pipeline_version="0.1.0",
            policy_version="2026-01",
        )
        db.add(run)
        db.commit()
        return {"org": org, "users": users, "capture": capture, "run": run}

    return {"a": make_org("orga"), "b": make_org("orgb")}


@pytest.fixture()
def client(db, seeded):
    app = create_app(_settings())
    app.dependency_overrides[get_db] = lambda: db

    # get_db is a generator dependency; override must yield too
    def _override():
        yield db

    app.dependency_overrides[get_db] = _override
    with TestClient(app) as c:
        yield c


def _login(client, email, password=PASSWORD):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def _token(client, email):
    r = _login(client, email)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


# --- tokens ---------------------------------------------------------------


def test_token_roundtrip_and_claims(pg_engine):
    s = _settings()
    uid, oid = uuid.uuid4(), uuid.uuid4()
    claims = decode_access_token(s, create_access_token(s, uid, oid))
    assert claims["sub"] == str(uid)
    assert claims["iss"] == s.auth_issuer and claims["aud"] == s.auth_audience


def test_token_tampered_expired_and_wrong_audience_rejected():
    s = _settings()
    token = create_access_token(s, uuid.uuid4(), uuid.uuid4())
    with pytest.raises(TokenError):
        decode_access_token(s, token[:-2] + "xx")
    now = datetime.now(UTC)
    expired = pyjwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "iss": s.auth_issuer,
            "aud": s.auth_audience,
            "iat": now - timedelta(hours=1),
            "exp": now - timedelta(minutes=5),
            "type": "access",
        },
        s.signing_key,
        algorithm="HS256",
    )
    with pytest.raises(TokenError):
        decode_access_token(s, expired)
    wrong_aud = pyjwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "iss": s.auth_issuer,
            "aud": "someone-else",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "type": "access",
        },
        s.signing_key,
        algorithm="HS256",
    )
    with pytest.raises(TokenError):
        decode_access_token(s, wrong_aud)


# --- login ------------------------------------------------------------------


def test_login_valid_invalid_and_me(client, seeded):
    r = _login(client, "admin@orga.test")
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"  # noqa: S105 - token type label and body["expires_in"] == 900

    me = client.get("/api/v1/auth/me", headers=_h(body["access_token"]))
    assert me.status_code == 200
    assert me.json()["organization_id"] == str(seeded["a"]["org"].id)  # derived, not supplied
    assert me.json()["role"] == "admin"

    assert _login(client, "admin@orga.test", "wrong-password").status_code == 401
    assert _login(client, "nobody@orga.test").status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/auth/me", headers=_h("not-a-token")).status_code == 401


def test_inactive_user_cannot_login_or_use_token(client, seeded, db):
    assert _login(client, "inactive@orga.test").status_code == 403
    # Token issued while active stops working once the user is deactivated.
    token = _token(client, "analyst@orga.test")
    user = seeded["a"]["users"][UserRole.ANALYST]
    user.is_active = False
    db.commit()
    assert client.get("/api/v1/auth/me", headers=_h(token)).status_code == 403


def test_no_public_registration_and_docs_disabled(client):
    assert client.post("/api/v1/auth/register", json={}).status_code in (404, 405)
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/api/v1/health/live").status_code == 200  # health stays open


def test_login_rate_limit(db, seeded):
    app = create_app(_settings(login_max_attempts=3))
    app.dependency_overrides[get_db] = lambda: (yield db)
    with TestClient(app) as c:
        for _ in range(3):
            assert _login(c, "admin@orga.test", "bad-password").status_code == 401
        limited = _login(c, "admin@orga.test")  # even correct creds are limited now
        assert limited.status_code == 429
        assert "Retry-After" in limited.headers


# --- roles & cross-tenant ---------------------------------------------------


def test_role_permissions(client, seeded):
    cap_id = seeded["a"]["capture"].id
    viewer = _token(client, "viewer@orga.test")
    analyst = _token(client, "analyst@orga.test")
    admin = _token(client, "admin@orga.test")

    assert client.get(f"/api/v1/captures/{cap_id}", headers=_h(viewer)).status_code == 200
    assert (
        client.patch(
            f"/api/v1/captures/{cap_id}", json={"display_name": "x"}, headers=_h(viewer)
        ).status_code
        == 403
    )
    assert client.delete(f"/api/v1/captures/{cap_id}", headers=_h(viewer)).status_code == 403
    assert (
        client.patch(
            f"/api/v1/captures/{cap_id}", json={"display_name": "renamed"}, headers=_h(analyst)
        ).status_code
        == 200
    )
    assert client.delete(f"/api/v1/captures/{cap_id}", headers=_h(analyst)).status_code == 403
    assert client.delete(f"/api/v1/captures/{cap_id}", headers=_h(admin)).status_code == 204


def test_cross_tenant_access_denied_everywhere(client, seeded):
    cap_a, run_a = seeded["a"]["capture"].id, seeded["a"]["run"].id
    intruder = _token(client, "admin@orgb.test")  # admin, but of another organization

    assert client.get(f"/api/v1/captures/{cap_a}", headers=_h(intruder)).status_code == 404
    assert (
        client.patch(
            f"/api/v1/captures/{cap_a}", json={"display_name": "pwned"}, headers=_h(intruder)
        ).status_code
        == 404
    )
    assert client.delete(f"/api/v1/captures/{cap_a}", headers=_h(intruder)).status_code == 404
    assert client.get(f"/api/v1/analyses/{run_a}", headers=_h(intruder)).status_code == 404
    assert client.get(f"/api/v1/analyses/{run_a}/report", headers=_h(intruder)).status_code == 404

    # The object is untouched and still reachable by its owner.
    owner = _token(client, "admin@orga.test")
    r = client.get(f"/api/v1/captures/{cap_a}", headers=_h(owner))
    assert r.status_code == 200 and r.json()["display_name"] == "orga.pcap"
    # Own-tenant report is explicitly unavailable (not fabricated) at this stage.
    own_report = client.get(f"/api/v1/analyses/{run_a}/report", headers=_h(owner))
    assert own_report.status_code == 404
    assert own_report.json()["detail"] == "report_not_available"


def test_admin_cli_bootstrap(db, pg_engine):
    factory = lambda: Session(pg_engine)  # noqa: E731
    org, admin = create_org_admin("cli-org", "root@cli.test", "a-very-long-password", factory)
    assert admin.role is UserRole.ADMIN and admin.organization_id == org.id
    assert admin.password_hash != "a-very-long-password"  # noqa: S105 - dummy test password
    assert "$argon2id$" in admin.password_hash
