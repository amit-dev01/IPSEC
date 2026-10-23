"""Analysis-job orchestration tests (PostgreSQL; fake dispatcher/storage)."""

import hashlib
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.core.security import create_access_token, hash_password
from ipsec_analyzer.db.session import get_db
from ipsec_analyzer.main import create_app
from ipsec_analyzer.models import (
    AnalysisRun,
    AnalysisStatus,
    Capture,
    CaptureFormat,
    CaptureState,
    EvidenceRecord,
    Organization,
    User,
    UserRole,
)
from ipsec_analyzer.services import analyses as svc
from ipsec_analyzer.services.dispatch import CeleryDispatcher, DispatchError
from ipsec_analyzer.storage.base import StorageError, StorageNotFound
from ipsec_analyzer.workers.celery_app import celery_app
from ipsec_analyzer.workers.processing import process_analysis

PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20 + b"PAYLOAD-BYTES"


class FakeParser:
    """Fake parser adapter: summaries only, records the temp path it was given."""

    def __init__(self, packets=None):
        from ipsec_analyzer.parsing.types import PacketSummary, ParseMetadata, ParseResult

        self._packets = packets or [
            PacketSummary(
                frame=1,
                timestamp=1.0,
                length=len(PCAP),
                protocol="esp",
                src="10.0.0.1",
                dst="10.0.0.2",
                esp_spi="0x00001001",
                esp_sequence=7,
            )
        ]
        self.seen_paths = []
        self._types = (ParseResult, ParseMetadata)

    def parse(self, path):
        from ipsec_analyzer.parsing.types import ParseMetadata, ParseResult

        self.seen_paths.append(path)
        assert path.exists()
        return ParseResult(
            packets=list(self._packets),
            metadata=ParseMetadata(
                tshark_version="FakeTShark 1.0", packet_count=len(self._packets)
            ),
        )


class FakeStorage:
    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.stream_failures = 0

    def put_file(self, key: str, path: Path) -> None:
        self.objects[key] = path.read_bytes()

    def stream(self, key: str) -> Iterator[bytes]:
        if self.stream_failures > 0:
            self.stream_failures -= 1
            raise StorageError("transient boom")
        if key not in self.objects:
            raise StorageNotFound("missing")
        yield self.objects[key]

    def delete(self, key: str) -> None:
        self.objects.pop(key, None)


class FakeDispatcher:
    def __init__(self, fail=False):
        self.calls: list[uuid.UUID] = []
        self.fail = fail

    def __call__(self, analysis_id: uuid.UUID) -> None:
        if self.fail:
            raise DispatchError("broker_unavailable")
        self.calls.append(analysis_id)


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
                password_hash=hash_password("pw-irrelevant"),
                role=role,
            )
            db.add(u)
            users[role] = u
        db.flush()
        return org, users

    org_a, users_a = make("joborga")
    org_b, users_b = make("joborgb")
    storage = FakeStorage()

    def add_capture(org, uploader, data=PCAP):
        key = f"tenants/{org.id}/captures/x/{uuid.uuid4()}"
        cap = Capture(
            organization_id=org.id,
            uploader_id=uploader.id,
            display_name="c.pcap",
            object_key=key,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
            format=CaptureFormat.PCAP,
            state=CaptureState.READY,
        )
        db.add(cap)
        db.flush()
        storage.objects[key] = data
        return cap

    cap_a = add_capture(org_a, users_a[UserRole.ADMIN])
    cap_b = add_capture(org_b, users_b[UserRole.ADMIN])
    db.commit()

    settings = _settings()
    dispatcher = FakeDispatcher()
    app = create_app(settings)
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.state.storage = storage
    app.state.dispatcher = dispatcher
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
            "dispatcher": dispatcher,
            "tokens": tokens,
            "a": (org_a, users_a, cap_a),
            "b": (org_b, users_b, cap_b),
        }


def _h(ctx, org, role=UserRole.ADMIN):
    return {"Authorization": f"Bearer {ctx['tokens'][(org.id, role)]}"}


def _request(ctx, org, cap) -> dict:
    r = ctx["client"].post(f"/api/v1/captures/{cap.id}/analyses", headers=_h(ctx, org))
    assert r.status_code == 202, r.text
    return r.json()


def test_request_analysis_returns_promptly_queued(ctx):
    org_a, _users, cap_a = ctx["a"]
    body = _request(ctx, org_a, cap_a)
    assert body["status"] == "queued"
    assert body["pipeline_version"] == "tshark-parse-0.2"
    assert body["model_version"] is None
    assert body["started_at"] is None
    # Message carried only the analysis ID.
    assert ctx["dispatcher"].calls == [uuid.UUID(body["id"])]
    # Row was stored before dispatch and is the authoritative status.
    run = ctx["db"].get(AnalysisRun, uuid.UUID(body["id"]))
    assert run.status is AnalysisStatus.QUEUED and run.dispatch_attempts == 1

    # Cross-tenant request is 404; viewer lacks analyses:write.
    org_b, _ub, _cap_b = ctx["b"]
    assert (
        ctx["client"]
        .post(f"/api/v1/captures/{cap_a.id}/analyses", headers=_h(ctx, org_b))
        .status_code
        == 404
    )
    assert (
        ctx["client"]
        .post(f"/api/v1/captures/{cap_a.id}/analyses", headers=_h(ctx, org_a, UserRole.VIEWER))
        .status_code
        == 403
    )


def test_broker_failure_marks_dispatch_failed_and_retry_recovers(ctx):
    org_a, _users, cap_a = ctx["a"]
    ctx["client"].app.state.dispatcher = FakeDispatcher(fail=True)
    body = _request(ctx, org_a, cap_a)  # prompt 202 despite broker failure
    assert body["status"] == "queued"
    assert body["error_code"] == "dispatch_failed"
    assert body["dispatch_attempts"] == 1

    good = FakeDispatcher()
    ctx["client"].app.state.dispatcher = good
    r = ctx["client"].post(f"/api/v1/analyses/{body['id']}/retry", headers=_h(ctx, org_a))
    assert r.status_code == 200, r.text
    assert r.json()["error_code"] is None
    assert r.json()["dispatch_attempts"] == 2
    assert good.calls == [uuid.UUID(body["id"])]


def test_reconcile_stale_queued_runs(ctx):
    org_a, users_a, cap_a = ctx["a"]
    run = svc.create_analysis(ctx["db"], users_a[UserRole.ADMIN], cap_a, ctx["settings"])
    run.queued_at = datetime.now(UTC) - timedelta(hours=1)
    ctx["db"].commit()
    good = FakeDispatcher()
    assert svc.reconcile_stale(ctx["db"], good, ctx["settings"]) == 1
    assert good.calls == [run.id]


def test_duplicate_delivery_is_idempotent(ctx):
    org_a, _users, cap_a = ctx["a"]
    run_id = uuid.UUID(_request(ctx, org_a, cap_a)["id"])
    assert (
        process_analysis(ctx["db"], ctx["storage"], run_id, ctx["settings"], parser=FakeParser())
        == "succeeded"
    )
    first = ctx["db"].get(AnalysisRun, run_id)
    assert first.attempts == 1 and first.started_at and first.finished_at
    evidence_after_first = ctx["db"].query(EvidenceRecord).filter_by(analysis_id=run_id).count()
    assert evidence_after_first > 1  # integrity + protocol/unknown facts

    # Duplicate deliveries change nothing: no extra attempt, no duplicate evidence.
    assert (
        process_analysis(ctx["db"], ctx["storage"], run_id, ctx["settings"], parser=FakeParser())
        == "succeeded"
    )
    again = ctx["db"].get(AnalysisRun, run_id)
    assert again.attempts == 1
    assert (
        ctx["db"].query(EvidenceRecord).filter_by(analysis_id=run_id).count()
        == evidence_after_first
    )

    got = ctx["client"].get(f"/api/v1/analyses/{run_id}", headers=_h(ctx, org_a))
    assert got.json()["status"] == "succeeded"
    assert got.json()["risk_score"] is None  # no fabricated scores


def test_transient_storage_failure_retries_then_succeeds_and_exhausts(ctx):
    org_a, _users, cap_a = ctx["a"]
    run_id = uuid.UUID(_request(ctx, org_a, cap_a)["id"])
    ctx["storage"].stream_failures = 1
    assert (
        process_analysis(ctx["db"], ctx["storage"], run_id, ctx["settings"], parser=FakeParser())
        == "retry"
    )
    run = ctx["db"].get(AnalysisRun, run_id)
    assert run.status is AnalysisStatus.QUEUED and run.error_code == "storage_unavailable"
    assert (
        process_analysis(ctx["db"], ctx["storage"], run_id, ctx["settings"], parser=FakeParser())
        == "succeeded"
    )

    # Exhaustion: max 3 attempts, then terminal failure; API retry also refuses.
    run2_id = uuid.UUID(_request(ctx, org_a, cap_a)["id"])
    ctx["storage"].stream_failures = 10
    outcomes = [
        process_analysis(ctx["db"], ctx["storage"], run2_id, ctx["settings"], parser=FakeParser())
        for _ in range(3)
    ]
    assert outcomes == ["retry", "retry", "failed"]
    run2 = ctx["db"].get(AnalysisRun, run2_id)
    assert run2.error_code == "storage_unavailable" and run2.attempts == 3
    r = ctx["client"].post(f"/api/v1/analyses/{run2_id}/retry", headers=_h(ctx, org_a))
    assert r.status_code == 409


def test_invalid_capture_fails_terminally_without_retry(ctx):
    org_a, _users, cap_a = ctx["a"]
    # Corrupt the stored object: hash will not match the DB record.
    ctx["storage"].objects[cap_a.object_key] = b"\xd4\xc3\xb2\xa1" + b"tampered"
    run_id = uuid.UUID(_request(ctx, org_a, cap_a)["id"])
    assert (
        process_analysis(ctx["db"], ctx["storage"], run_id, ctx["settings"], parser=FakeParser())
        == "failed"
    )
    run = ctx["db"].get(AnalysisRun, run_id)
    assert run.error_code == "integrity_mismatch"
    # Duplicate delivery to a terminal run is a no-op; retry endpoint refuses.
    assert (
        process_analysis(ctx["db"], ctx["storage"], run_id, ctx["settings"], parser=FakeParser())
        == "failed"
    )
    assert ctx["db"].get(AnalysisRun, run_id).attempts == 1
    r = ctx["client"].post(f"/api/v1/analyses/{run_id}/retry", headers=_h(ctx, org_a))
    assert r.status_code == 409
    assert "/" not in r.json()["detail"]  # no local paths leaked


def test_invalid_state_transitions_enforced(ctx):
    org_a, _users, cap_a = ctx["a"]
    run_id = uuid.UUID(_request(ctx, org_a, cap_a)["id"])
    run = ctx["db"].get(AnalysisRun, run_id)
    with pytest.raises(svc.InvalidTransition):
        svc.transition(run, AnalysisStatus.SUCCEEDED)  # queued -> succeeded is illegal
    with pytest.raises(svc.InvalidTransition):
        svc.transition(run, AnalysisStatus.FAILED)
    # Retry endpoint on a running/queued-without-dispatch-failure run conflicts.
    process_analysis(ctx["db"], ctx["storage"], run_id, ctx["settings"], parser=FakeParser())
    r = ctx["client"].post(f"/api/v1/analyses/{run_id}/retry", headers=_h(ctx, org_a))
    assert r.status_code == 409  # succeeded is terminal


def test_celery_message_contains_only_analysis_id(monkeypatch):
    sent = {}

    def fake_send_task(name, args=None, kwargs=None, **opts):
        sent.update(name=name, args=args, kwargs=kwargs)

    monkeypatch.setattr(celery_app, "send_task", fake_send_task)
    rid = uuid.uuid4()
    CeleryDispatcher().enqueue(rid)
    assert sent["name"] == "ipsec_analyzer.analyze_capture"
    assert sent["args"] == [str(rid)]
    assert not sent["kwargs"]


def test_celery_config_uses_postgres_as_status_store():
    assert celery_app.conf.task_ignore_result is True
    assert celery_app.conf.result_backend is None
    assert celery_app.conf.worker_prefetch_multiplier == 1
    assert celery_app.conf.worker_concurrency == 2


def test_worker_parse_evidence_and_temp_cleanup(ctx):
    org_a, _users, cap_a = ctx["a"]
    run_id = uuid.UUID(_request(ctx, org_a, cap_a)["id"])
    parser = FakeParser()
    assert (
        process_analysis(ctx["db"], ctx["storage"], run_id, ctx["settings"], parser=parser)
        == "succeeded"
    )
    # The downloaded capture lived in a private temp dir that is now gone.
    assert parser.seen_paths and not parser.seen_paths[0].exists()

    run = ctx["db"].get(AnalysisRun, run_id)
    assert run.summary["tshark_version"] == "FakeTShark 1.0"
    assert run.summary["ml_prediction"]["status"] == "unavailable"  # no model configured
    facts = {
        e.fact_name: e for e in ctx["db"].query(EvidenceRecord).filter_by(analysis_id=run_id).all()
    }
    assert facts["esp.spi_observed"].fact_value["spi"] == "0x00001001"
    assert facts["esp.encryption_algorithm"].fact_value is None
    assert str(facts["esp.encryption_algorithm"].source) == "unknown"
    got = ctx["client"].get(f"/api/v1/analyses/{run_id}/evidence", headers=_h(ctx, org_a))
    assert got.status_code == 200
    assert any(f["fact_name"] == "esp.spi_observed" for f in got.json())
    # Cross-tenant evidence access is 404.
    org_b, _ub, _cb = ctx["b"]
    assert (
        ctx["client"].get(f"/api/v1/analyses/{run_id}/evidence", headers=_h(ctx, org_b)).status_code
        == 404
    )
