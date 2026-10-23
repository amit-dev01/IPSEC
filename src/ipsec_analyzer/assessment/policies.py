"""Versioned policy profiles. Rule behaviour changes only with a new version."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PolicyProfile:
    version: str
    description: str
    deprecated_encryption: frozenset[str] = frozenset(
        {"DES", "3DES", "DES-CBC", "TRIPLE-DES", "NULL", "RC4", "BLOWFISH"}
    )
    deprecated_integrity: frozenset[str] = frozenset(
        {"MD5", "HMAC-MD5", "SHA1", "HMAC-SHA1", "NULL"}
    )
    # DH groups below min_dh_group are weak; groups in deprecated_dh_groups are broken/legacy.
    deprecated_dh_groups: frozenset[str] = frozenset({"0", "1", "2", "5", "22"})
    min_dh_group: int = 14  # 2048-bit MODP minimum; 19+ (ECP) preferred
    min_encryption_key_length: int = 128
    preferred_key_length: int = 256
    max_configured_lifetime_seconds: int = 86_400
    aead_encryption: frozenset[str] = frozenset(
        {"AES-GCM", "AES-GCM-16", "AES-GCM-12", "AES-GCM-8", "CHACHA20-POLY1305", "AES-CCM"}
    )
    # Coverage dimensions and weights (sum = 1.0); see scoring.py.
    coverage_dimensions: dict[str, float] = field(
        default_factory=lambda: {
            "ike_version": 0.15,
            "ike_selected_transforms": 0.25,
            "esp_observed": 0.15,
            "child_sa_or_manifest": 0.15,
            "pfs_state": 0.10,
            "lifetime_config": 0.10,
            "replay_config": 0.10,
        }
    )
    assessed_threshold: float = 0.8
    partial_threshold: float = 0.4


PROFILES: dict[str, PolicyProfile] = {
    "default-2026.1": PolicyProfile(
        version="default-2026.1",
        description="Current baseline: AEAD preferred, DH >= 14, no deprecated transforms.",
    ),
    # Previous profile retained so historical runs remain reproducible and
    # rule-version change tests can show behaviour differences.
    "default-2025.1": PolicyProfile(
        version="default-2025.1",
        description="Legacy baseline: DH group 5 tolerated (deprecated in 2026.1).",
        deprecated_dh_groups=frozenset({"0", "1", "2", "22"}),
        min_dh_group=5,
    ),
}


def get_profile(version: str) -> PolicyProfile:
    try:
        return PROFILES[version]
    except KeyError as exc:
        raise ValueError(f"unknown policy profile version: {version}") from exc
