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
    # "auto" (AWS/MinIO default), "path" (required by Neon Object Storage),
    # or "virtual". Only affects request addressing, never authorization.
    s3_addressing_style: str = Field(default="auto", pattern="^(auto|path|virtual)$")
    # TLS is on by default; local MinIO over http must opt out explicitly in dev.
    s3_use_tls: bool = True
    s3_verify_tls: bool = True
    # Server-side encryption at rest: None (not requested), "AES256", or "aws:kms".
    # The system never claims encryption is enabled unless one of these is set
    # (and production refuses to start without it — see validator below).
    s3_sse_algorithm: str | None = None
    s3_sse_kms_key_id: str | None = None
    capture_retention_days: int | None = Field(default=90, gt=0)

    @property
    def storage_encryption_configured(self) -> bool:
        return self.s3_sse_algorithm in ("AES256", "aws:kms")

    # Authentication: signing key via env/secret manager only (falls back to
    # secret_key for single-secret deployments). Tokens are short-lived JWTs.
    jwt_signing_key: str | None = None
    jwt_algorithm: str = "HS256"
    auth_issuer: str = "ipsec-analyzer"
    auth_audience: str = "ipsec-analyzer-api"
    access_token_expire_minutes: int = Field(default=15, gt=0, le=60)
    login_max_attempts: int = Field(default=5, gt=0)
    login_window_seconds: int = Field(default=300, gt=0)
    # One-time bootstrap admin (e.g. first hosted deploy). When BOTH are set,
    # startup creates this org+admin iff no user with the email exists; it is
    # idempotent and never re-runs afterwards. Remove both env vars after the
    # first successful login. The password is never logged.
    # Demo Mode: when true, ALL API requests run as an auto-created demo
    # admin (no token required, permissions bypassed by the admin role).
    # Intended only for public demos - never enable on a real deployment.
    demo_mode: bool = False
    bootstrap_email: str | None = None
    bootstrap_password: str | None = None
    bootstrap_organization: str = "Demo Lab"
    # None => docs only in development. Explicitly configured otherwise.
    enable_docs: bool | None = None

    @property
    def signing_key(self) -> str:
        return self.jwt_signing_key or self.secret_key

    @property
    def docs_enabled(self) -> bool:
        if self.enable_docs is not None:
            return self.enable_docs
        return self.environment is Environment.DEVELOPMENT

    # Analysis orchestration
    pipeline_version: str = "tshark-parse-0.2"
    policy_version: str = "policy-0.1"
    assessment_policy_version: str = "default-2026.1"
    analysis_max_attempts: int = Field(default=3, ge=1, le=10)
    worker_concurrency: int = Field(default=2, ge=1, le=16)
    dispatch_stale_seconds: int = Field(default=300, gt=0)

    # Worker-side TShark parsing (worker image only; the API never runs this)
    tshark_path: str = "/usr/bin/tshark"  # fixed executable; never user-supplied
    tshark_timeout_seconds: int = Field(default=120, gt=0)
    max_tshark_output_bytes: int = Field(default=64 * 1024 * 1024, gt=0)
    parser_version: str = "tshark-adapter-0.2"

    # Evidence privacy: outer addresses are hashed in evidence by default.
    evidence_allow_plain_addresses: bool = False

    # Local ML baseline (trusted, administrator-built artifacts only)
    ml_model_path: str | None = None
    ml_abstain_threshold: float = Field(default=0.6, ge=0.0, le=1.0)

    # Hard limits for untrusted captures (enforced at upload/worker layers in later stages)
    max_upload_bytes: int = Field(default=512 * 1024 * 1024, gt=0)
    max_packets: int = Field(default=2_000_000, gt=0)
    max_analysis_seconds: int = Field(default=900, gt=0)

    @model_validator(mode="after")
    def _fail_closed_in_production(self) -> "Settings":
        if self.environment is Environment.PRODUCTION:
            if self.signing_key == _DEV_SECRET or len(self.signing_key) < 32:
                raise ValueError(
                    "IPSEC_JWT_SIGNING_KEY/IPSEC_SECRET_KEY must be >=32 chars in production"
                )
            if "change-me" in self.database_url:
                raise ValueError("IPSEC_DATABASE_URL must be explicitly configured in production")
            if not self.s3_use_tls:
                raise ValueError("IPSEC_S3_USE_TLS must be enabled in production")
            if not self.storage_encryption_configured:
                raise ValueError(
                    "IPSEC_S3_SSE_ALGORITHM (AES256 or aws:kms) is required in production; "
                    "encryption at rest is never assumed"
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
