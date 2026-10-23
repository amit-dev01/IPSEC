"""PCAP/PCAPNG format detection from magic bytes only.

The API never parses captures; this checks the first bytes of the stream to
reject files that are not captures. Extension and client MIME type are ignored.
"""

from ipsec_analyzer.models import CaptureFormat

# libpcap magic: microsecond/nanosecond, both endiannesses.
_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # Section Header Block


def detect_format(header: bytes) -> CaptureFormat | None:
    if len(header) < 4:
        return None
    magic = header[:4]
    if magic in _PCAP_MAGICS:
        return CaptureFormat.PCAP
    if magic == _PCAPNG_MAGIC:
        return CaptureFormat.PCAPNG
    return None
