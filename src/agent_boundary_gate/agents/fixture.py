"""Deterministic in-process agent adapter. Simulation only, not an OpenCode/OpenClaw one."""

import time
from threading import Event

from agent_boundary_gate.backends import Readiness
from agent_boundary_gate.contracts import ComponentIdentity, ToolRequestAction


class LoopbackAgentAdapter:
    agent_id = "loopback"
    capabilities = frozenset({"tool-authorization"})

    def __init__(self, policy_digest: str):
        self.policy_digest = policy_digest
        self.calls: list[str] = []

    def readiness(self, *, deadline: float, cancelled: Event) -> Readiness:
        if cancelled.is_set() or time.monotonic() >= deadline:
            return Readiness((), self.policy_digest, False)
        identity = ComponentIdentity(
            component_id=self.agent_id,
            role="agent",
            instance_uid="loopback-agent-fixture",
            generation="loopback-agent-generation-1",
        )
        return Readiness((identity,), self.policy_digest, True)

    def request_tool(
        self, action: ToolRequestAction, attempt_id: str, *, deadline: float, cancelled: Event
    ) -> bool:
        if cancelled.is_set() or time.monotonic() >= deadline:
            return False
        # Dispatch only; authorization/denial is enforced and observed independently
        # of the adapter, same as the fixture boundary's simulated-denial split.
        self.calls.append(action.control)
        return True
