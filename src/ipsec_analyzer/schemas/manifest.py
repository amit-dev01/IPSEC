"""Versioned lab-manifest schema (authorized IPsec testbed ground truth).

Secrets are rejected structurally: the schema is strict (`extra="forbid"` at
every level), has no field that could hold key material, and any key whose name
suggests secrets (psk/secret/password/private/session key/credential) is
rejected before validation. This module never accepts PSKs, private keys, or
session keys.
"""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

MANIFEST_SCHEMA_VERSION = "1.0"

_FORBIDDEN_KEY_PARTS = (
    "psk",
    "secret",
    "password",
    "passwd",
    "private_key",
    "privatekey",
    "session_key",
    "sessionkey",
    "credential",
    "key_material",
    "preshared",
)


def _reject_secret_keys(obj: Any, path: str = "") -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            lowered = str(key).lower()
            for part in _FORBIDDEN_KEY_PARTS:
                if part in lowered:
                    raise ValueError(f"secret-bearing field rejected in manifest: {path}{key}")
            _reject_secret_keys(value, f"{path}{key}.")
    elif isinstance(obj, list):
        for item in obj:
            _reject_secret_keys(item, path)


class TrafficCategory(StrEnum):
    WEB = "web"
    EMAIL = "email"
    VOICE = "voice"
    VIDEO = "video"
    MESSAGING = "messaging"
    ICMP = "icmp"
    OTHER = "other"


class SelectedIkeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    encryption: str | None = None
    key_length: int | None = Field(default=None, gt=0)
    integrity: str | None = None
    prf: str | None = None
    dh_group: str | None = None


class EspConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    encryption: str | None = None
    key_length: int | None = Field(default=None, gt=0)
    integrity: str | None = None
    aead: bool | None = None
    dh_group: str | None = None  # Child-SA/PFS DH group, when PFS is used
    pfs_enabled: bool | None = None


class LabManifestV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=MANIFEST_SCHEMA_VERSION)
    testbed_id: str = Field(min_length=1, max_length=200)
    run_id: str = Field(min_length=1, max_length=200)
    capture_id: str = Field(min_length=1, max_length=200)  # lab capture/session ID
    ike_version: int | None = Field(default=None, ge=1, le=2)
    selected_ike: SelectedIkeConfig | None = None
    mode: str | None = Field(default=None, pattern="^(tunnel|transport)$")
    ip_version: int | None = Field(default=None, ge=4, le=6)
    esp: EspConfig | None = None
    configured_sa_lifetime_seconds: int | None = Field(default=None, gt=0)
    replay_protection_enabled: bool | None = None
    replay_window_size: int | None = Field(default=None, gt=0)
    traffic_category: TrafficCategory | None = None
    # Lab-only ground truth (e.g. a testbed application label). Retained for
    # evaluation; must never be presented as a reliable production prediction.
    lab_application_label: str | None = Field(default=None, max_length=100)

    @model_validator(mode="before")
    @classmethod
    def _no_secrets(cls, data: Any) -> Any:
        _reject_secret_keys(data)
        return data

    @model_validator(mode="after")
    def _version_supported(self) -> "LabManifestV1":
        if self.schema_version != MANIFEST_SCHEMA_VERSION:
            raise ValueError(f"unsupported manifest schema_version: {self.schema_version}")
        return self


class ManifestAttachRequest(BaseModel):
    """The manifest document itself is the request body (validated as V1)."""

    manifest: LabManifestV1
