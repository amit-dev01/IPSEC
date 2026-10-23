"""Passive capture execution behind an injectable runner.

The production runner invokes dumpcap with a fixed argument vector built
only from allowlisted values (no shell, no user filters, no arbitrary
interface names). Tests inject a fake runner; the API never imports this
module. The agent process must run with the least privileges possible
(typically CAP_NET_RAW only, read-only output dir) — see docs/runbook.md.
"""

import hashlib
import subprocess  # noqa: S404 - fixed argv, no shell, allowlisted values only
from pathlib import Path
from typing import Protocol

from ipsec_analyzer.agent.policy import AgentPolicy, CaptureRequest


class CaptureRunner(Protocol):
    def run(self, argv: list[str], output_path: Path, timeout: float) -> None: ...


class DumpcapRunner:
    """Real runner (never exercised in CI/tests). Fixed argv, no shell."""

    def run(self, argv: list[str], output_path: Path, timeout: float) -> None:
        subprocess.run(  # noqa: S603
            argv,
            check=True,
            timeout=timeout,
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def build_argv(kernel_name: str, snaplen: int, duration: int, output_path: Path) -> list[str]:
    return [
        "dumpcap",
        "-i",
        kernel_name,
        "-a",
        f"duration:{duration}",
        "-s",
        str(snaplen),
        "-w",
        str(output_path),
    ]


def run_capture(
    policy: AgentPolicy,
    request: CaptureRequest,
    output_dir: Path,
    runner: CaptureRunner,
) -> dict:
    """Authorize, capture passively, hash. Upload is the caller's job via the
    normal ingestion client; returns metadata only."""
    entry, profile = policy.authorize(request)
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"{request.idempotency_key}.pcapng"
    argv = build_argv(entry.kernel_name, profile.snaplen, request.duration_seconds, out)
    runner.run(argv, out, timeout=request.duration_seconds + 30)
    data = out.read_bytes()
    if len(data) > request.max_bytes:
        out.unlink(missing_ok=True)
        raise ValueError("capture_exceeded_size_limit")
    return {
        "path": out,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "interface_id": entry.interface_id,
        "profile_id": profile.profile_id,
        "agent_id": policy.agent_id,
    }
