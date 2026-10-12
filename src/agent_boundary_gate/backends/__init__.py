"""Driver interfaces separate execution health from independent observations."""

from dataclasses import dataclass
from threading import Event
from typing import Protocol

from agent_boundary_gate.contracts import ComponentIdentity, ReplayAction


@dataclass(frozen=True)
class Readiness:
    components: tuple[ComponentIdentity, ...]
    effective_policy_digest: str
    ready: bool


class BoundaryBackend(Protocol):
    backend_id: str
    capabilities: frozenset[str]

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
