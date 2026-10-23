"""PostgreSQL persistence tests (skipped without IPSEC_TEST_DATABASE_URL)."""

import uuid
from datetime import UTC

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from ipsec_analyzer.db.audit import canonical_payload, compute_event_hash
from ipsec_analyzer.models import (
    AnalysisRun,
    AnalysisStatus,
    AuditEvent,
    Capture,
    CaptureFormat,
    CaptureState,
    EvidenceRecord,
    EvidenceSource,
    EvidenceVisibility,
    Finding,
    FindingSeverity,
    Organization,
    User,
)

SHA = "a" * 64


def _org_user(db, email="u@example.test"):
    org = Organization(name="org")
    db.add(org)
    db.flush()
    user = User(organization_id=org.id, email=email)
    db.add(user)
    db.flush()
    return org, user


def _capture(db, org, user, **kw):
    fields = {
        "organization_id": org.id,
        "uploader_id": user.id,
        "display_name": "test.pcapng",
        "object_key": f"obj-{uuid.uuid4()}",
        "sha256": SHA,
        "size_bytes": 100,
        "format": CaptureFormat.PCAPNG,
    }
    fields.update(kw)
    cap = Capture(**fields)
    db.add(cap)
    db.flush()
    return cap


def _run(db, org, cap, user, **kw):
    run = AnalysisRun(
        organization_id=org.id,
        capture_id=cap.id,
        requester_id=user.id,
        pipeline_version="0.1.0",
        policy_version="2026-01",
        **kw,
    )
    db.add(run)
    db.flush()
    return run


def test_defaults_and_state_values(db):
    org, user = _org_user(db)
    cap = _capture(db, org, user)
    run = _run(db, org, cap, user)
    assert cap.state is CaptureState.UNKNOWN
    assert run.status is AnalysisStatus.PENDING
    assert run.risk_score is None and run.security_score is None  # unknown, not a pass
    assert cap.created_at.tzinfo is not None
    db.commit()


def test_unique_user_email_per_org(db):
    org, _user = _org_user(db)
    db.add(User(organization_id=org.id, email="u@example.test"))
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_unique_object_key(db):
    org, user = _org_user(db)
    cap = _capture(db, org, user)
    db.add(
        Capture(
            organization_id=org.id,
            uploader_id=user.id,
            display_name="d.pcap",
            object_key=cap.object_key,
            sha256=SHA,
            size_bytes=1,
            format=CaptureFormat.PCAP,
        )
    )
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_check_constraint_sha_hex(db):
    org, user = _org_user(db)
    db.add(
        Capture(
            organization_id=org.id,
            uploader_id=user.id,
            display_name="x.pcap",
            object_key=f"obj-{uuid.uuid4()}",
            sha256="zz" * 32,
            size_bytes=1,
            format=CaptureFormat.PCAP,
        )
    )
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_check_constraint_size_nonneg(db):
    org, user = _org_user(db)
    db.add(
        Capture(
            organization_id=org.id,
            uploader_id=user.id,
            display_name="x.pcap",
            object_key=f"obj-{uuid.uuid4()}",
            sha256=SHA,
            size_bytes=-1,
            format=CaptureFormat.PCAP,
        )
    )
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_check_constraint_score_range(db):
    org, user = _org_user(db)
    cap = _capture(db, org, user)
    db.add(
        AnalysisRun(
            organization_id=org.id,
            capture_id=cap.id,
            requester_id=user.id,
            pipeline_version="0.1.0",
            policy_version="2026-01",
            risk_score=1.5,
        )
    )
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_invalid_state_value_rejected(db):
    org, user = _org_user(db)
    cap = _capture(db, org, user)
    cap.state = "bogus-state"
    with pytest.raises(Exception):  # noqa: B017 - DB/ORM must reject, exact type is driver-level
        db.flush()
    db.rollback()


def test_jsonb_roundtrip_and_types(db):
    org, user = _org_user(db)
    cap = _capture(db, org, user)
    run = _run(
        db,
        org,
        cap,
        user,
        summary={"packets": 10},
        evidence_coverage={"ike_sa_init": "packet_observed", "child_sa": "unknown"},
    )
    ev = EvidenceRecord(
        organization_id=org.id,
        analysis_id=run.id,
        fact_name="ike.encryption_algorithm",
        fact_value={"name": "AES-GCM-256", "observed": True},
        source=EvidenceSource.PACKET_OBSERVED,
        visibility=EvidenceVisibility.VISIBLE,
        confidence=0.9,
        quality=1.0,
        packet_refs=[{"frame": 4}],
    )
    db.add(ev)
    db.flush()  # assign ev.id before referencing it
    finding = Finding(
        organization_id=org.id,
        analysis_id=run.id,
        rule_id="IKE-WEAK-DH",
        severity=FindingSeverity.HIGH,
        confidence=0.8,
        evidence_refs=[str(ev.id)],
        recommendation="Use DH group 20+.",
    )
    db.add(finding)
    db.commit()
    db.expire_all()
    assert db.get(EvidenceRecord, ev.id).fact_value["name"] == "AES-GCM-256"
    assert db.get(Finding, finding.id).evidence_refs == [str(ev.id)]

    rows = db.execute(
        text(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_name='evidence_records' AND column_name IN ('fact_value','packet_refs') "
            "UNION ALL SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_name='analysis_runs' AND column_name IN ('summary','evidence_coverage')"
        )
    ).all()
    assert {r[1] for r in rows} == {"jsonb"}
    # Captures must never store PCAP bytes in PostgreSQL.
    bytea = db.execute(
        text(
            "SELECT count(*) FROM information_schema.columns "
            "WHERE table_name='captures' AND data_type='bytea'"
        )
    ).scalar()
    assert bytea == 0


def test_tenant_indexes_exist(db):
    names = {
        r[0]
        for r in db.execute(
            text("SELECT indexname FROM pg_indexes WHERE schemaname='public'")
        ).all()
    }
    expected = {
        "ix_captures_org_state",
        "ix_captures_org_uploaded",
        "ix_captures_org_sha256",
        "ix_runs_org_status",
        "ix_evidence_org_fact",
        "ix_findings_org_severity",
        "ix_audit_org_time",
        "ix_users_org_active",
    }
    assert expected <= names
    insp = inspect(db.get_bind())
    assert any(
        c["name"] == "uq_capture_object_key" for c in insp.get_unique_constraints("captures")
    )


def test_cascade_and_audit_set_null(db):
    org, user = _org_user(db)
    cap = _capture(db, org, user)
    run = _run(db, org, cap, user)
    db.add(
        EvidenceRecord(
            organization_id=org.id,
            analysis_id=run.id,
            fact_name="esp.spi",
            fact_value={"spi": "0x1"},
            source=EvidenceSource.PACKET_OBSERVED,
            visibility=EvidenceVisibility.VISIBLE,
        )
    )
    payload = canonical_payload(
        action="capture.uploaded",
        resource_type="capture",
        resource_id=cap.id,
        actor_user_id=user.id,
        organization_id=org.id,
        occurred_at=cap.created_at,
    )
    event = AuditEvent(
        organization_id=org.id,
        actor_user_id=user.id,
        action="capture.uploaded",
        resource_type="capture",
        resource_id=cap.id,
        canonical_payload=payload,
        event_hash=compute_event_hash(payload),
    )
    db.add(event)
    db.commit()

    db.delete(cap)  # capture deletion cascades to runs/evidence
    db.commit()
    assert db.query(AnalysisRun).count() == 0
    assert db.query(EvidenceRecord).count() == 0

    db.delete(org)  # audit survives with NULL tenant; users/captures cascade
    db.commit()
    kept = db.get(AuditEvent, event.id)
    assert kept is not None and kept.organization_id is None


def test_audit_hash_is_deterministic_and_chained():
    kwargs = dict(
        action="job.created",
        resource_type="analysis_run",
        resource_id=uuid.uuid4(),
        actor_user_id=None,
        organization_id=None,
        occurred_at=__import__("datetime").datetime(2026, 1, 1, tzinfo=UTC),
    )
    p1 = canonical_payload(**kwargs)
    assert p1 == canonical_payload(**kwargs)
    h1 = compute_event_hash(p1)
    h2 = compute_event_hash(p1, previous_event_hash=h1)
    assert h1 != h2 and len(h1) == 64
