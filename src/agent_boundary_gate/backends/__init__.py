"""Driver interfaces separate execution health from independent observations."""

from dataclasses import dataclass
from threading import Event
from typing import Protocol

from agent_boundary_gate.contracts import Binding, ComponentIdentity, ReplayAction
from agent_boundary_gate.receipts import LeaseBinding

# Only these portable diagnostics may be copied into shared gate decisions.
BACKEND_DIAGNOSTIC_REASONS = frozenset(
    f"backend-{phase}-cli-{failure}"
    for phase in ("readiness", "replay", "cleanup")
    for failure in (
        "timeout",
        "exit-nonzero",
        "start-failed",
        "output-limit",
        "group-cleanup-failed",
    )
)


class BackendFailure(Exception):
    """Allowlisted infrastructure failure, without child output or private arguments."""

    def __init__(self, reason: str):
        if reason not in BACKEND_DIAGNOSTIC_REASONS:
            raise ValueError("unknown backend diagnostic")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class Readiness:
    components: tuple[ComponentIdentity, ...]
    effective_policy_digest: str
    ready: bool


class BoundaryBackend(Protocol):
    backend_id: str
    capabilities: frozenset[str]
    lease: LeaseBinding | None

    def require_binding(self, binding: Binding) -> None: ...

    def readiness(self, *, deadline: float, cancelled: Event) -> Readiness: ...

    def replay(
        self,
        action: ReplayAction,
        url: str | None,
        attempt_id: str,
        *,
        deadline: float,
        cancelled: Event,
    ) -> bool: ...

    def destroy(self, *, deadline: float) -> bool: ...


class UnsupportedCapability(Exception):
    """A valid case cannot be evaluated by the selected adapter combination."""
