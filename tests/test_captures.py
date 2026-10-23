"""Capture ingestion tests (PostgreSQL + in-memory fake storage)."""

import hashlib
import io
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.core.security import create_access_token, hash_password
from ipsec_analyzer.db.session import get_db
from ipsec_analyzer.main import create_app
from ipsec_analyzer.models import AuditEvent, Capture, Organization, User, UserRole
from ipsec_analyzer.services.captures import UploadRejected, ingest_capture
from ipsec_analyzer.storage.base import StorageError, StorageNotFound

PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20 + b"FAKEPACKETDATA-not-real-traffic"
PCAPNG = b"\x0a\x0d\x0d\x0a" + b"\x00" * 24 + b"FAKEPACKETDATA"


class FakeStorage:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put_file(self, key: str, path: Path) -> None:
        self.objects[key] = path.read_bytes()

    def stream(self, key: str) -> Iterator[bytes]:
        if key not in self.objects:
            raise StorageNotFound("missing")
        yield self.objects[key]

    def delete(self, key: str) -> None:
        self.objects.pop(key, None)


class FailingPutStorage(FakeStorage):
    def put_file(self, key: str, path: Path) -> None:
        raise StorageError("boom")


def _settings(**kw) -> Settings:
    base = {
        "environment": "test",
        "jwt_signing_key": "test-signing-key-that-is-long-enough-32",
        "enable_docs": False,
    }
    base.update(kw)
    return Settings(**base)


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
                password_hash=hash_password("pw-irrelevant-token-used"),
                role=role,
            )
            db.add(u)
            users[role] = u
        db.commit()
        return org, users

    org_a, users_a = make("uporga")
    org_b, users_b = make("uporgb")
    storage = FakeStorage()
    settings = _settings()
    app = create_app(settings)
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.state.storage = storage
    tokens = {
        (org.id, role): create_access_token(settings, u.id, org.id)
        for org, users in ((org_a, users_a), (org_b, users_b))
        for role, u in users.items()
    }
    with TestClient(app) as client:
        yield {
            "client": client,
            "db": db,
            "storage": storage,
            "settings": settings,
            "a": (org_a, users_a),
            "b": (org_b, users_b),
            "tokens": tokens,
        }


def _h(ctx, org, role=UserRole.ADMIN):
    return {"Authorization": f"Bearer {ctx['tokens'][(org.id, role)]}"}


def _upload(
    ctx,
    org,
    data=PCAP,
    filename="capture.pcap",
    role=UserRole.ADMIN,
    mime="application/octet-stream",
):
    return ctx["client"].post(
        "/api/v1/captures",
        files={"file": (filename, io.BytesIO(data), mime)},
        headers=_h(ctx, org, role),
    )


def test_valid_pcap_and_pcapng_upload(ctx):
    org_a, _ = ctx["a"]
    r = _upload(
        ctx, org_a, PCAP, "../../evil/capture.pcap", mime="text/plain"
    )  # MIME/extension ignored
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["sha256"] == hashlib.sha256(PCAP).hexdigest()
    assert body["format"] == "pcap"
    assert body["display_name"] == "capture.pcap"
    assert "object_key" not in body and "object_key" not in r.text

    r2 = _upload(ctx, org_a, PCAPNG, "x.bin")
    assert r2.status_code == 201 and r2.json()["format"] == "pcapng"

    # Random tenant-prefixed keys, no filename influence, bytes intact in storage.
    assert len(ctx["storage"].objects) == 2
    for key, data in ctx["storage"].objects.items():
        assert key.startswith(f"tenants/{org_a.id}/captures/")
        assert "capture.pcap" not in key and "evil" not in key
        assert data in (PCAP, PCAPNG)
    actions = ctx["db"].scalars(select(AuditEvent.action)).all()
    assert actions.count("capture.uploaded") == 2


def test_invalid_magic_empty_and_tiny_files_rejected(ctx):
    org_a, _ = ctx["a"]
    for data in (b"this is not a capture at all", b"ab", b""):
        r = _upload(ctx, org_a, data)
        assert r.status_code == 422, (data, r.text)
    assert ctx["storage"].objects == {}
    assert ctx["db"].query(Capture).count() == 0


def test_oversized_upload_rejected_while_streaming(ctx):
    org_a, users_a = ctx["a"]
    ctx["client"].app.state.settings = _settings(max_upload_bytes=32)
    r = _upload(ctx, org_a, PCAP * 10)
    assert r.status_code == 413
    assert ctx["storage"].objects == {}
    assert ctx["db"].query(Capture).count() == 0


def test_storage_failure_leaves_no_db_row(ctx):
    org_a, _ = ctx["a"]
    ctx["client"].app.state.storage = FailingPutStorage()
    r = _upload(ctx, org_a)
    assert r.status_code == 503
    assert ctx["db"].query(Capture).count() == 0


def test_db_commit_failure_cleans_up_object(ctx, monkeypatch):
    from sqlalchemy.orm import Session

    org_a, _ = ctx["a"]
    original_commit = Session.commit
    calls = {"n": 0}

    def flaky(self):
        calls["n"] += 1
        raise RuntimeError("commit exploded")

    monkeypatch.setattr(Session, "commit", flaky)
    try:
        r = _upload(ctx, org_a)
    finally:
        monkeypatch.setattr(Session, "commit", original_commit)
    assert r.status_code == 500
    assert ctx["storage"].objects == {}  # compensating delete ran
    ctx["db"].rollback()
    assert ctx["db"].query(Capture).count() == 0


def test_interrupted_upload_service_level(ctx):
    class BrokenStream:
        def __init__(self):
            self.calls = 0

        def read(self, _n=-1):
            self.calls += 1
            if self.calls == 1:
                return PCAP
            raise ConnectionResetError("client went away")

    org_a, users_a = ctx["a"]
    user = users_a[UserRole.ADMIN]
    with pytest.raises(UploadRejected) as exc:
        ingest_capture(ctx["db"], ctx["storage"], user, BrokenStream(), "x.pcap", ctx["settings"])
    assert exc.value.code == "upload_interrupted"
    assert ctx["storage"].objects == {}
    assert ctx["db"].query(Capture).count() == 0


def test_list_detail_download_delete_and_cross_tenant(ctx, caplog):
    org_a, _ = ctx["a"]
    org_b, _ = ctx["b"]
    cap_id = _upload(ctx, org_a).json()["id"]

    assert ctx["client"].get("/api/v1/captures", headers=_h(ctx, org_b)).json()["items"] == []
    own_list = ctx["client"].get("/api/v1/captures", headers=_h(ctx, org_a)).json()
    assert [c["id"] for c in own_list["items"]] == [cap_id]
    assert own_list["total"] == 1

    dl = ctx["client"].get(f"/api/v1/captures/{cap_id}/download", headers=_h(ctx, org_a))
    assert dl.status_code == 200 and dl.content == PCAP
    assert "tenants/" not in dl.headers.get("content-disposition", "")

    for method in ("get", "patch", "delete"):
        kwargs = {"headers": _h(ctx, org_b)}
        if method == "patch":
            kwargs["json"] = {"display_name": "pwned"}
        url = f"/api/v1/captures/{cap_id}" + ("/download" if method == "get" else "")
        assert getattr(ctx["client"], method)(url, **kwargs).status_code == 404
        dl_b = ctx["client"].get(f"/api/v1/captures/{cap_id}/download", headers=_h(ctx, org_b))
        assert dl_b.status_code == 404

    viewer = ctx["client"].post(
        "/api/v1/captures",
        files={"file": ("v.pcap", io.BytesIO(PCAP), "application/octet-stream")},
        headers=_h(ctx, org_a, UserRole.VIEWER),
    )
    assert viewer.status_code == 403

    assert (
        ctx["client"].delete(f"/api/v1/captures/{cap_id}", headers=_h(ctx, org_a)).status_code
        == 204
    )
    assert ctx["storage"].objects == {}
    assert ctx["db"].query(Capture).count() == 0
    actions = ctx["db"].scalars(select(AuditEvent.action)).all()
    assert "capture.downloaded" in actions and "capture.deleted" in actions

    # Logs must never contain packet contents.
    assert "FAKEPACKETDATA" not in caplog.text


def test_sha256_matches_stored_bytes(ctx):
    org_a, _ = ctx["a"]
    data = PCAPNG + uuid.uuid4().bytes
    body = _upload(ctx, org_a, data).json()
    stored = next(iter(ctx["storage"].objects.values()))
    assert hashlib.sha256(stored).hexdigest() == body["sha256"] == hashlib.sha256(data).hexdigest()
