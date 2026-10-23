import pytest
from pydantic import ValidationError

from ipsec_analyzer.core.config import Settings


def test_production_rejects_default_secret() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="production")


def test_production_requires_tls_and_sse_for_storage() -> None:
    base = {
        "environment": "production",
        "jwt_signing_key": "production-signing-key-that-is-long-enough",
        "database_url": "postgresql+psycopg://ipsec:real-password@db:5432/ipsec",
    }
    with pytest.raises(ValidationError):  # SSE not configured -> refuse to imply encryption
        Settings(**base)
    ok = Settings(**base, s3_sse_algorithm="AES256")
    assert ok.storage_encryption_configured is True
    with pytest.raises(ValidationError):  # TLS disabled in production
        Settings(**base, s3_sse_algorithm="AES256", s3_use_tls=False)
