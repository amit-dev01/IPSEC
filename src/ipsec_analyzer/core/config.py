from enum import StrEnum
from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_SECRET = "change-me-local-only-at-least-32-chars"  # noqa: S105 - local-dev sentinel, rejected in production


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IPSEC_", env_file=".env", extra="ignore")

    environment: Environment = Environment.DEVELOPMENT
    log_level: str = "INFO"
    secret_key: str = _DEV_SECRET
    database_url: str = "postgresql+psycopg://ipsec:change-me-local-only@localhost:5432/ipsec"
    redis_url: str = "redis://localhost:6379/0"
    s3_endpoint_url: str | None = None  # None => AWS S3; set for MinIO/other S3-compatible
    s3_bucket: str = "ipsec-captures"
    s3_access_key: str | None = None
    s3_secret_key: str | None = None
    s3_region: str = "us-east-1"

    # Hard limits for untrusted captures (enforced at upload/worker layers in later stages)
    max_upload_bytes: int = Field(default=512 * 1024 * 1024, gt=0)
    max_packets: int = Field(default=2_000_000, gt=0)
    max_analysis_seconds: int = Field(default=900, gt=0)

    @model_validator(mode="after")
    def _fail_closed_in_production(self) -> "Settings":
        if self.environment is Environment.PRODUCTION:
            if self.secret_key == _DEV_SECRET or len(self.secret_key) < 32:
                raise ValueError("IPSEC_SECRET_KEY must be set to >=32 chars in production")
            if "change-me" in self.database_url:
                raise ValueError("IPSEC_DATABASE_URL must be explicitly configured in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
