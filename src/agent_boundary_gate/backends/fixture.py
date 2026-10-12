"""Local simulation driver with real HTTP traffic. Does not execute OpenShell."""

import sys
from threading import Event

from agent_boundary_gate.backends import Readiness, UnsupportedCapability
from agent_boundary_gate.contracts import Binding, ComponentIdentity, HttpGetAction, ReplayAction
from agent_boundary_gate.probes import PROBE
from agent_boundary_gate.process import bounded_process


class LoopbackBackend:
    backend_id = "loopback"
    lease = None
    capabilities = frozenset({"network-egress"})

    def __init__(self, policy_digest: str, *, weakened: bool = False):
        self.policy_digest = policy_digest
        self.weakened = weakened
        self.destroyed = False

    def require_binding(self, binding: Binding) -> None:
        # Fixture validation only; there is no authenticated provisioning lease.
        if binding.effective_policy_digest != self.policy_digest:
            raise UnsupportedCapability("fixture-policy-binding-mismatch")

    def readiness(self, *, deadline: float, cancelled: Event) -> Readiness:
        identity = ComponentIdentity(
            component_id=self.backend_id,
            role="boundary",
            instance_uid="loopback-fixture",
            generation="loopback-generation-1",
        )
        return Readiness((identity,), self.policy_digest, True)

    def replay(
        self,
        action: ReplayAction,
        url: str | None,
        attempt_id: str,
        *,
        deadline: float,
        cancelled: Event,
    ) -> bool:
        if not isinstance(action, HttpGetAction) or url is None:
            raise UnsupportedCapability("loopback-action-unsupported")
        if action.receiver == "forbidden" and not self.weakened:
            # Explicitly simulated denial. This is not an OpenShell enforcement check.
            code = "import sys; print('agent-boundary-gate-probe-complete:' + sys.argv[2])"
        else:
            code = PROBE
        result = bounded_process(
            [sys.executable, "-c", code, url, attempt_id, str(action.timeout_seconds)],
            deadline=deadline,
            cancelled=cancelled,
        )
        return (
            result.returncode == 0
            and result.stdout.strip()
            == ("agent-boundary-gate-probe-complete:" + attempt_id).encode()
        )

    def destroy(self, *, deadline: float) -> bool:
        self.destroyed = True
        return True
