"""Agent allowlist policy. Nothing here trusts caller-supplied interface
names, commands, or filters: requests reference opaque allowlisted IDs only.
"""

from dataclasses import dataclass

MAX_DURATION_SECONDS = 300
MAX_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class CaptureProfile:
    profile_id: str
    description: str
    # Fixed server-side argument template; {interface} is substituted only
    # with the allowlisted kernel name resolved from the interface ID.
    snaplen: int = 262144


@dataclass(frozen=True)
class InterfaceAllowlistEntry:
    interface_id: str  # opaque ID presented by admins, e.g. "lab-uplink-1"
    kernel_name: str  # real interface name, configured only on the agent host
    tenant_hint: str


@dataclass(frozen=True)
class CaptureRequest:
    agent_id: str
    interface_id: str
    profile_id: str
    duration_seconds: int
    max_bytes: int
    idempotency_key: str


class AgentPolicyError(ValueError):
    """Raised for any request outside the allowlist/bounds (fail closed)."""


class AgentPolicy:
    def __init__(
        self,
        agent_id: str,
        interfaces: dict[str, InterfaceAllowlistEntry],
        profiles: dict[str, CaptureProfile],
    ) -> None:
        self.agent_id = agent_id
        self.interfaces = interfaces
        self.profiles = profiles

    def authorize(self, request: CaptureRequest) -> tuple[InterfaceAllowlistEntry, CaptureProfile]:
        if request.agent_id != self.agent_id:
            raise AgentPolicyError("agent_not_allowlisted")
        entry = self.interfaces.get(request.interface_id)
        if entry is None:
            raise AgentPolicyError("interface_not_allowlisted")
        profile = self.profiles.get(request.profile_id)
        if profile is None:
            raise AgentPolicyError("profile_not_allowlisted")
        if not (1 <= request.duration_seconds <= MAX_DURATION_SECONDS):
            raise AgentPolicyError("duration_out_of_bounds")
        if not (1 <= request.max_bytes <= MAX_BYTES):
            raise AgentPolicyError("size_out_of_bounds")
        if not request.idempotency_key:
            raise AgentPolicyError("idempotency_key_required")
        return entry, profile
