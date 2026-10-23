import pytest
from pydantic import ValidationError

from ipsec_analyzer.core.config import Settings


def test_production_rejects_default_secret() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="production")
