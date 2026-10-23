"""Flow-level metadata features from packet summaries (no payloads, no IPs)."""

import statistics
from collections import defaultdict
from typing import Any

from ipsec_analyzer.parsing.types import PacketSummary

FEATURE_NAMES = [
    "packet_count",
    "total_bytes",
    "duration_seconds",
    "bytes_per_second",
    "length_mean",
    "length_std",
    "length_min",
    "length_max",
    "iat_mean",
    "iat_std",
    "forward_ratio",
    "burst_max_1s",
    "esp_packet_ratio",
    "nat_t",
]


def _stats(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    if len(values) == 1:
        return values[0], 0.0
    return statistics.fmean(values), statistics.pstdev(values)


def flow_features(packets: list[PacketSummary]) -> list[dict[str, Any]]:
    """One feature row per bidirectional outer flow. Endpoint identities are
    used only to group packets inside the worker and are never emitted."""
    flows: dict[tuple, list[PacketSummary]] = defaultdict(list)
    for p in packets:
        if not p.src or not p.dst:
            continue
        a, b = sorted([(p.src, p.src_port or 0), (p.dst, p.dst_port or 0)])
        flows[(a, b, p.protocol or "other")].append(p)

    rows: list[dict[str, Any]] = []
    for _key, pkts in flows.items():
        pkts.sort(key=lambda p: (p.timestamp or 0.0, p.frame))
        lengths = [float(p.length) for p in pkts]
        times = [p.timestamp for p in pkts if p.timestamp is not None]
        iats = [b - a for a, b in zip(times, times[1:], strict=False)] if len(times) > 1 else []
        duration = (times[-1] - times[0]) if len(times) > 1 else 0.0
        total_bytes = sum(lengths)
        first_src = pkts[0].src
        forward = sum(1 for p in pkts if p.src == first_src)
        # Burst: max packets starting within any 1-second window.
        burst = 0
        if times:
            j = 0
            for i, t in enumerate(times):
                while times[j] < t - 1.0:
                    j += 1
                burst = max(burst, i - j + 1)
        len_mean, len_std = _stats(lengths)
        iat_mean, iat_std = _stats([float(x) for x in iats])
        rows.append(
            {
                "packet_count": len(pkts),
                "total_bytes": total_bytes,
                "duration_seconds": duration,
                "bytes_per_second": (total_bytes / duration) if duration > 0 else 0.0,
                "length_mean": len_mean,
                "length_std": len_std,
                "length_min": min(lengths) if lengths else 0.0,
                "length_max": max(lengths) if lengths else 0.0,
                "iat_mean": iat_mean,
                "iat_std": iat_std,
                "forward_ratio": forward / len(pkts) if pkts else 0.0,
                "burst_max_1s": burst,
                "esp_packet_ratio": (
                    sum(1 for p in pkts if p.protocol == "esp") / len(pkts) if pkts else 0.0
                ),
                "nat_t": 1.0 if any(p.nat_t for p in pkts) else 0.0,
            }
        )
    return rows


def capture_features(packets: list[PacketSummary]) -> dict[str, float]:
    """Capture-level aggregate: byte-weighted mean of per-flow features."""
    rows = flow_features(packets)
    if not rows:
        return {name: 0.0 for name in FEATURE_NAMES}
    weights = [max(r["total_bytes"], 1.0) for r in rows]
    total_w = sum(weights)
    return {
        name: sum(r[name] * w for r, w in zip(rows, weights, strict=True)) / total_w
        for name in FEATURE_NAMES
    }
