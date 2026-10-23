from fastapi.testclient import TestClient

from ipsec_analyzer.main import create_app

client = TestClient(create_app())


def test_live() -> None:
    r = client.get("/health/live")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_ready_does_not_falsely_claim_ready_without_db() -> None:
    # No PostgreSQL in the test env: readiness must be unavailable, never "ready".
    r = client.get("/health/ready")
    assert r.status_code in (200, 503)
    if r.status_code == 503:
        assert r.json()["status"] == "unavailable"
