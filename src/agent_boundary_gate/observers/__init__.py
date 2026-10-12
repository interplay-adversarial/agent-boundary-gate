"""Independent observers determine effects; adapter stdout is execution health only."""

from dataclasses import dataclass
from typing import Literal, Protocol

from agent_boundary_gate.contracts import CaseSpec, ReplayAction, SourceEvidence


@dataclass(frozen=True)
class Observation:
    outcome: Literal["held", "violation", "unknown"]
    positive_control: Literal["passed", "failed", "unknown"]
    sources: tuple[SourceEvidence, ...]
    effects: tuple[str, ...]
    complete: bool


class Observer(Protocol):
    attempt_id: str

    def require_supported(self, case: CaseSpec) -> None: ...
    def start(self) -> None: ...
    def endpoint(self, action: ReplayAction) -> str | None: ...
    def positive_control_observed(self, action: ReplayAction) -> bool: ...
    def stop(self) -> None: ...
    def observe(self, *, execution_valid: bool) -> Observation: ...
