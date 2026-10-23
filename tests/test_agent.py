"""Passive-agent policy tests — mocked runner, no real capture tool runs."""

from pathlib import Path

import pytest

from ipsec_analyzer.agent.policy import (
    AgentPolicy,
    AgentPolicyError,
    CaptureProfile,
    CaptureRequest,
    InterfaceAllowlistEntry,
)
from ipsec_analyzer.agent.runner import run_capture


def _policy():
    return AgentPolicy(
        agent_id="agent-lab-1",
        interfaces={"lab-uplink-1": InterfaceAllowlistEntry("lab-uplink-1", "eth9", "orga")},
        profiles={"metadata": CaptureProfile("metadata", "fixed profile")},
    )


def _req(**kw):
    base = dict(
        agent_id="agent-lab-1",
        interface_id="lab-uplink-1",
        profile_id="metadata",
        duration_seconds=10,
        max_bytes=1024,
        idempotency_key="k1",
    )
    base.update(kw)
    return CaptureRequest(**base)


class FakeRunner:
    def __init__(self):
        self.argv = None

    def run(self, argv, output_path, timeout):
        self.argv = argv
        Path(output_path).write_bytes(b"\x0a\x0d\x0d\x0a" + b"x" * 32)


def test_allowlisted_capture_uses_fixed_argv(tmp_path):
    runner = FakeRunner()
    result = run_capture(_policy(), _req(), tmp_path, runner)
    assert runner.argv[:3] == ["dumpcap", "-i", "eth9"]  # resolved server-side
    assert "eth9" in runner.argv and "-i" in runner.argv
    assert result["sha256"] and result["size_bytes"] == 36


@pytest.mark.parametrize(
    "kw",
    [
        {"agent_id": "other"},
        {"interface_id": "eth0"},
        {"interface_id": "../../etc"},
        {"profile_id": "custom-filter"},
        {"duration_seconds": 99999},
        {"max_bytes": 10**12},
        {"idempotency_key": ""},
    ],
)
def test_anything_outside_allowlist_fails_closed(kw, tmp_path):
    with pytest.raises(AgentPolicyError):
        run_capture(_policy(), _req(**kw), tmp_path, FakeRunner())
