"""TShark adapter tests using a fake `tshark` executable script, plus a real
TShark integration test that runs only where TShark is installed (worker image)."""

import json
import os
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.parsing.tshark import (
    REQUIRED_FIELDS,
    ParserError,
    TsharkAdapter,
    UnsupportedFields,
)


def _settings(**kw) -> Settings:
    base = {"environment": "test", "jwt_signing_key": "test-signing-key-that-is-long-enough-32"}
    base.update(kw)
    return Settings(**base)


def _write_fake_tshark(tmp_path: Path, body: str) -> str:
    script = tmp_path / "faketshark"
    script.write_text("#!" + sys.executable + "\n" + body)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


_FIELDS_OK = "\n".join(
    f"F\tField {f}\t{f}\tx"
    for f in REQUIRED_FIELDS
    + [
        "ikev2.exchangetype",
    ]
)


def _ek_line(frame=1, spi="0x00001001", seq=7):
    return json.dumps(
        {
            "layers": {
                "frame.number": [str(frame)],
                "frame.time_epoch": ["1.0"],
                "frame.len": ["100"],
                "ip.src": ["10.0.0.1"],
                "ip.dst": ["10.0.0.2"],
                "ip.proto": ["50"],
                "esp.spi": [spi],
                "esp.sequence": [str(seq)],
            }
        }
    )


def _fake(tmp_path, *, fields=_FIELDS_OK, lines=None, rc=0, sleep=0):
    lines = lines if lines is not None else (_ek_line(),)
    body = f"""
import sys, time
args = sys.argv[1:]
if "--version" in args:
    print("TShark (Wireshark) 4.4.0 (fake)")
    sys.exit(0)
if "-G" in args:
    print({fields!r})
    sys.exit(0)
time.sleep({sleep})
for line in {list(lines)!r}:
    print(line)
sys.exit({rc})
"""
    return _write_fake_tshark(tmp_path, body)


def _capture(tmp_path) -> Path:
    p = tmp_path / "capture.bin"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    return p


def test_fixed_args_and_summary_parsing(tmp_path):
    exe = _fake(tmp_path)
    adapter = TsharkAdapter(_settings(tshark_path=exe))
    args = adapter.build_args(_capture(tmp_path), [])
    assert args[1] == "-n"  # name resolution disabled
    assert "-Y" not in args and "--" not in args[2]
    assert not any("filter" in a for a in args)

    result = adapter.parse(_capture(tmp_path))
    assert result.metadata.tshark_version.startswith("TShark")
    assert result.metadata.packet_count == 1
    pkt = result.packets[0]
    assert pkt.protocol == "esp" and pkt.esp_spi == "0x00001001" and pkt.esp_sequence == 7
    # Optional field absent from the fake's -G output is reported, not hidden.
    assert "ikev2.flags.response" in result.metadata.unsupported_fields
    assert result.metadata.limitations


def test_unsupported_required_fields_fail_explicitly(tmp_path):
    fields = "\n".join(f"F\tField {f}\t{f}\tx" for f in REQUIRED_FIELDS if f != "esp.spi")
    exe = _fake(tmp_path, fields=fields)
    adapter = TsharkAdapter(_settings(tshark_path=exe))
    with pytest.raises(UnsupportedFields) as exc:
        adapter.parse(_capture(tmp_path))
    assert exc.value.code == "parser_unsupported_field"
    assert exc.value.fields == ["esp.spi"]


def test_tshark_failure_timeout_output_and_packet_limits(tmp_path):
    cap = _capture(tmp_path)
    exe = _fake(tmp_path, rc=3)
    with pytest.raises(ParserError) as exc:
        TsharkAdapter(_settings(tshark_path=exe)).parse(cap)
    assert exc.value.code == "parser_failed"

    exe = _fake(tmp_path, sleep=5)
    start = time.monotonic()
    with pytest.raises(ParserError) as exc:
        TsharkAdapter(_settings(tshark_path=exe, tshark_timeout_seconds=1)).parse(cap)
    assert exc.value.code == "parser_timeout"
    assert time.monotonic() - start < 4

    exe = _fake(tmp_path, lines=[_ek_line(i) for i in range(5)])
    with pytest.raises(ParserError) as exc:
        TsharkAdapter(_settings(tshark_path=exe, max_packets=2)).parse(cap)
    assert exc.value.code == "limit_exceeded"

    exe = _fake(tmp_path, lines=[_ek_line(1) + "x" * 5000])
    with pytest.raises(ParserError) as exc:
        TsharkAdapter(_settings(tshark_path=exe, max_tshark_output_bytes=1024)).parse(cap)
    assert exc.value.code == "parser_output_limit"


def test_missing_executable_is_unavailable(tmp_path):
    adapter = TsharkAdapter(_settings(tshark_path=str(tmp_path / "nope")))
    with pytest.raises(ParserError) as exc:
        adapter.parse(_capture(tmp_path))
    assert exc.value.code == "parser_unavailable"


# --- real TShark integration (worker image) ---------------------------------


def _ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ipv4(proto: int, payload: bytes, src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02") -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack("!H", _ip_checksum(hdr)) + hdr[12:]
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + struct.pack("!H", 0x0800)
    return eth + hdr + payload


def _pcap(packets: list[bytes]) -> bytes:
    out = [struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for i, pkt in enumerate(packets):
        out.append(struct.pack("<IIII", i + 1, 0, len(pkt), len(pkt)))
        out.append(pkt)
    return b"".join(out)


def _synthetic_pcap_bytes() -> bytes:
    # ESP packet (IP proto 50): SPI 0x1001, sequence 7, opaque encrypted bytes.
    esp = struct.pack("!II", 0x1001, 7) + b"\xaa" * 32
    # IKEv2 IKE_SA_INIT request on UDP/500 (header only; no credentials, no keys).
    ike = (
        struct.pack("!QQBBI", 0x1111111111111111, 0, 33, 0x20, 34)
        + struct.pack("!BBI", 0x08, 0, 0)
        + struct.pack("!I", 28)
    )
    udp = struct.pack("!HHHH", 500, 500, 8 + len(ike), 0) + ike
    return _pcap([_ipv4(50, esp), _ipv4(17, udp)])


@pytest.mark.skipif(
    not Path("/usr/bin/tshark").exists() and not os.environ.get("TSHARK_PATH"),
    reason="TShark not installed here; runs in the worker image (Dockerfile.worker)",
)
def test_real_tshark_parses_synthetic_pcap(tmp_path):
    exe = os.environ.get("TSHARK_PATH", "/usr/bin/tshark")
    cap = tmp_path / "synthetic.pcap"
    cap.write_bytes(_synthetic_pcap_bytes())
    adapter = TsharkAdapter(_settings(tshark_path=exe))
    result = adapter.parse(cap)
    assert result.metadata.packet_count == 2
    protocols = {p.protocol for p in result.packets}
    assert "esp" in protocols
    esp_pkt = next(p for p in result.packets if p.protocol == "esp")
    assert esp_pkt.esp_spi in ("0x00001001", "0x1001")
    assert esp_pkt.esp_sequence == 7
    assert subprocess.run([exe, "-v"], capture_output=True).returncode == 0  # noqa: S603 - fixed argv
