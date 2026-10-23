import json
import logging

from fastapi.testclient import TestClient

from ipsec_analyzer.core.logging import JsonFormatter, configure_logging
from ipsec_analyzer.main import create_app


def test_app_factory_and_openapi() -> None:
    app = create_app()
    with TestClient(app) as client:  # exercises the lifespan handler
        assert client.get("/api/v1/health/live").status_code == 200
        spec = client.get("/openapi.json")
        assert spec.status_code == 200
        assert "/api/v1/health/live" in spec.json()["paths"]
        assert "/api/v1/health/ready" in spec.json()["paths"]


def test_structured_logging_is_json() -> None:
    configure_logging("INFO")
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "hello", (), None)
    payload = json.loads(JsonFormatter().format(record))
    assert payload["level"] == "INFO"
    assert payload["message"] == "hello"
    assert "timestamp" in payload
