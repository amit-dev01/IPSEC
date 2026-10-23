"""Parser output types: packet summaries and aggregates only.

No payload bytes ever appear here. Addresses are carried in summaries inside
the worker only; evidence generation hashes them unless plaintext storage is
explicitly enabled in configuration.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TransformSet:
    """One SA proposal's transforms (names as decoded, e.g. 'AES-GCM')."""

    protocol: str | None = None  # IKE / ESP / AH
    encryption: str | None = None
    key_length: int | None = None
    integrity: str | None = None
    prf: str | None = None
    dh_group: str | None = None


@dataclass
class Proposal:
    role: str  # "offered" (initiator request) or "selected" (responder choice)
    transforms: list[TransformSet] = field(default_factory=list)


@dataclass
class PacketSummary:
    frame: int
    timestamp: float | None = None
    length: int = 0
    ip_version: int | None = None
    src: str | None = None
    dst: str | None = None
    protocol: str | None = None  # esp/ah/ike/udp/tcp/other
    src_port: int | None = None
    dst_port: int | None = None
    nat_t: bool = False
    ike_version: str | None = None
    ike_exchange_type: str | None = None
    ike_is_response: bool | None = None
    esp_spi: str | None = None
    esp_sequence: int | None = None
    ah_spi: str | None = None
    ah_sequence: int | None = None
    proposals: list[Proposal] = field(default_factory=list)


@dataclass
class ParseMetadata:
    tshark_version: str | None = None
    parser_version: str = "tshark-adapter-0.2"
    packet_count: int = 0
    truncated: bool = False
    truncation_warnings: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    unsupported_fields: list[str] = field(default_factory=list)


@dataclass
class ParseResult:
    packets: list[PacketSummary]  # bounded by max_packets; aggregates built by caller
    metadata: ParseMetadata
    raw_for_aggregates: list[dict[str, Any]] = field(default_factory=list)
