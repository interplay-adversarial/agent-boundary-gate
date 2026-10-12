"""Agent adapters are independent of sandbox backends. No live adapters shipped yet."""

from threading import Event
from typing import Protocol

from agent_boundary_gate.backends import Readiness
from agent_boundary_gate.contracts import ToolRequestAction


class AgentAdapter(Protocol):
    agent_id: str
    capabilities: frozenset[str]

    def readiness(self, *, deadline: float, cancelled: Event) -> Readiness: ...

    def request_tool(
        self, action: ToolRequestAction, attempt_id: str, *, deadline: float, cancelled: Event
    ) -> bool: ...
