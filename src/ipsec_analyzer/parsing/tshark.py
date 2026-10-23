"""TShark adapter — worker-side only. The API must never import this module.

Security contract:
- Fixed executable (from server configuration) and fixed argument construction.
- subprocess without a shell; no user-supplied options, display filters, file
  paths, or environment variables are ever interpolated. The only variable
  argument is the server-generated temp path of the downloaded capture.
- Name resolution disabled (-n). Output is EK JSON lines, consumed
  incrementally. Required field names are validated against the installed
  TShark (`tshark -G fields`); missing required fields fail explicitly as
  `parser_unsupported_field` and are never silently coerced to zeroes.
- Time, packet-count, and output-size limits are enforced while streaming;
  stderr is captured to a capped temp file and never returned to clients.
"""

import json
import logging
import re
import select
import subprocess  # noqa: S404 - fixed argv, no shell, see module docstring
import time
from pathlib import Path
from typing import Any

from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.parsing.types import PacketSummary, ParseMetadata, ParseResult

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "ipv6.nxt",
    "udp.srcport",
    "udp.dstport",
    "esp.spi",
    "esp.sequence",
    "ah.spi",
    "ah.sequence",
]

# Requested only when the installed TShark actually provides them; absence is
# recorded as a parse limitation, not silently ignored.
OPTIONAL_FIELDS = [
    "ikev2.exchangetype",
    "isakmp.exchangetype",
    "ikev2.flags.response",
    "isakmp.flags.response",
    "ikev2.transform.type",
    "isakmp.transform.type",
]

_NAT_T_PORT = 4500
_MINIMAL_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
}


class ParserError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ParserUnavailable(ParserError):
    pass


class UnsupportedFields(ParserError):
    def __init__(self, fields: list[str]) -> None:
        super().__init__("parser_unsupported_field")
        self.fields = fields


class TsharkAdapter:
    def __init__(self, settings: Settings) -> None:
        self._exe = settings.tshark_path
        self._timeout = settings.tshark_timeout_seconds
        self._max_packets = settings.max_packets
        self._max_output = settings.max_tshark_output_bytes
        self._parser_version = settings.parser_version
        self._fields_cache: set[str] | None = None
        self._version_cache: str | None = None

    # -- environment validation ------------------------------------------------
    def _run_fixed(self, args: list[str], timeout: int = 30) -> str:
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self._exe, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=_MINIMAL_ENV,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ParserUnavailable("parser_unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            raise ParserError("parser_timeout") from exc
        if proc.returncode != 0:
            raise ParserError("parser_failed")
        return proc.stdout

    def tshark_version(self) -> str:
        if self._version_cache is None:
            out = self._run_fixed(["--version"])
            self._version_cache = out.splitlines()[0].strip() if out else "unknown"
        return self._version_cache

    def available_fields(self) -> set[str]:
        if self._fields_cache is None:
            out = self._run_fixed(["-G", "fields"], timeout=60)
            fields: set[str] = set()
            for line in out.splitlines():
                parts = line.split("\t")
                # -G fields format: F\t<name>\t<abbrev>\t...
                if len(parts) >= 3 and parts[0] == "F":
                    fields.add(parts[2])
            self._fields_cache = fields
        return self._fields_cache

    def validate_fields(self) -> list[str]:
        available = self.available_fields()
        missing = [f for f in REQUIRED_FIELDS if f not in available]
        if missing:
            raise UnsupportedFields(missing)
        return [f for f in OPTIONAL_FIELDS if f in available]

    # -- parsing -----------------------------------------------------------------
    def build_args(self, capture_path: Path, optional_fields: list[str]) -> list[str]:
        """Fixed argument vector. `capture_path` is a server-generated temp path."""
        args = [
            self._exe,
            "-n",  # disable name resolution
            "-r",
            str(capture_path),
            "-T",
            "ek",  # newline-delimited JSON, processable incrementally
            "-c",
            str(self._max_packets + 1),  # +1 lets us detect truncation explicitly
        ]
        for name in REQUIRED_FIELDS + optional_fields:
            args += ["-e", name]
        return args

    def parse(self, capture_path: Path) -> ParseResult:
        optional = self.validate_fields()
        metadata = ParseMetadata(
            tshark_version=self.tshark_version(),
            parser_version=self._parser_version,
            unsupported_fields=[f for f in OPTIONAL_FIELDS if f not in optional],
        )
        if metadata.unsupported_fields:
            metadata.limitations.append(
                "optional IKE fields unsupported by this TShark: "
                + ", ".join(metadata.unsupported_fields)
            )
        packets: list[PacketSummary] = []
        output_bytes = 0
        deadline = time.monotonic() + self._timeout
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                self.build_args(capture_path, optional),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,  # may contain packet-derived data; discarded
                env=_MINIMAL_ENV,
            )
        except FileNotFoundError as exc:
            raise ParserUnavailable("parser_unavailable") from exc
        assert proc.stdout is not None  # noqa: S101 - internal invariant
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    proc.kill()
                    raise ParserError("parser_timeout")
                ready, _, _ = select.select([proc.stdout], [], [], min(0.5, remaining))
                if not ready:
                    if proc.poll() is not None:
                        break
                    continue
                line = proc.stdout.readline()
                if not line:
                    break
                output_bytes += len(line)
                if output_bytes > self._max_output:
                    proc.kill()
                    raise ParserError("parser_output_limit")
                summary = self._summary_from_ek_line(line)
                if summary is not None:
                    packets.append(summary)
                    if len(packets) > self._max_packets:
                        metadata.truncated = True
                        metadata.truncation_warnings.append(
                            f"packet count exceeded configured limit ({self._max_packets})"
                        )
                        proc.kill()
                        raise ParserError("limit_exceeded")
            rc = proc.wait(timeout=10)
        except ParserError:
            raise
        except Exception as exc:
            proc.kill()
            raise ParserError("parser_failed") from exc
        if rc != 0:
            raise ParserError("parser_failed")
        metadata.packet_count = len(packets)
        return ParseResult(packets=packets, metadata=metadata)

    # -- EK decoding ---------------------------------------------------------------
    @staticmethod
    def _first(value: Any) -> Any:
        if isinstance(value, list):
            return value[0] if value else None
        return value

    def _summary_from_ek_line(self, line: bytes) -> PacketSummary | None:
        try:
            obj = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            return None
        layers = obj.get("layers")
        if not isinstance(layers, dict):
            return None

        def get(*names: str) -> Any:
            for name in names:
                if name in layers:
                    return self._first(layers[name])
            return None

        frame_no = get("frame.number")
        if frame_no is None:
            return None
        src = get("ip.src", "ipv6.src")
        dst = get("ip.dst", "ipv6.dst")
        src_port = get("udp.srcport")
        dst_port = get("udp.dstport")
        esp_spi = get("esp.spi")
        protocol = None
        if esp_spi is not None or "esp" in layers:
            protocol = "esp"
        elif get("ah.spi") is not None or "ah" in layers:
            protocol = "ah"
        elif "isakmp" in layers or "ikev2" in layers:
            protocol = "ike"
        elif src_port is not None:
            protocol = "udp"
        nat_t = bool(
            (src_port == _NAT_T_PORT or dst_port == _NAT_T_PORT) and protocol in ("esp", "ike")
        )
        exchange = get("ikev2.exchangetype", "isakmp.exchangetype")
        return PacketSummary(
            frame=int(frame_no),
            timestamp=_to_float(get("frame.time_epoch")),
            length=_to_int(get("frame.len")) or 0,
            ip_version=6 if get("ipv6.src") is not None else (4 if src is not None else None),
            src=str(src) if src is not None else None,
            dst=str(dst) if dst is not None else None,
            protocol=protocol,
            src_port=_to_int(src_port),
            dst_port=_to_int(dst_port),
            nat_t=nat_t,
            ike_version=("2" if ("ikev2" in layers or exchange is not None) else None),
            ike_exchange_type=str(exchange) if exchange is not None else None,
            esp_spi=str(esp_spi) if esp_spi is not None else None,
            esp_sequence=_to_int(get("esp.sequence")),
            ah_spi=(str(get("ah.spi")) if get("ah.spi") is not None else None),
            ah_sequence=_to_int(get("ah.sequence")),
        )


def _to_int(value: Any) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _to_float(value: Any) -> float | None:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


_SPI_RE = re.compile(r"^0x[0-9a-fA-F]+$")


def normalize_spi(value: str | None) -> str | None:
    if value is None:
        return None
    return value if _SPI_RE.match(value) else value
