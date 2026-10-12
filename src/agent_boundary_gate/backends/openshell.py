"""Direct CLI driver for an independently provisioned, leased OpenShell sandbox.

CLI JSON/flags correspond to cached source f745aa4df4b1e63ca362cb4624d3952796a7c31c.
This driver does not provision containment, issue leases or invent supervisor readiness.
"""

import json
import math
import re
import time
from collections.abc import Callable
from pathlib import Path
from threading import Event
from urllib.parse import urlsplit

from agent_boundary_gate.backends import Readiness, UnsupportedCapability
from agent_boundary_gate.contracts import ComponentIdentity, HttpGetAction, ReplayAction
from agent_boundary_gate.evidence import bytes_digest
from agent_boundary_gate.process import bounded_process

# A completed request attempt is execution health, never the security oracle.
PROBE = """import sys, urllib.request, urllib.error
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
request = urllib.request.Request(sys.argv[1], headers={'X-Gate-Attempt': sys.argv[2]})
try:
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=float(sys.argv[3])) as response:
        response.read(1)
except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
    pass
print('agent-boundary-gate-probe-complete:' + sys.argv[2])
"""


def validate_receiver_url(url: str) -> None:
    value = urlsplit(url)
    if (
        value.scheme != "http"
        or not value.hostname
        or value.username
        or value.password
        or value.path != "/probe"
        or value.query
        or value.fragment
        or not value.port
    ):
        raise ValueError("receiver must be an explicit HTTP /probe endpoint")


class OpenShellBackend:
    backend_id = "openshell"
    capabilities = frozenset({"network-egress"})

    def __init__(
        self,
        *,
        executable: Path,
        executable_digest: str,
        gateway: str,
        sandbox: str,
        sandbox_uid: str,
        policy_digest: str,
        policy_revision: int,
        supervisor_receipt: Callable[[], str | None],
        cleanup_receipt: Callable[[], bool],
    ):
        if bytes_digest(executable.read_bytes()) != executable_digest:
            raise ValueError("OpenShell binary does not match its pin")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}", gateway):
            raise ValueError("invalid gateway name")
        if not re.fullmatch(r"gate-[a-z0-9-]{1,80}", sandbox):
            raise ValueError("driver accepts only explicitly leased gate-* sandbox names")
        if type(policy_revision) is not int or policy_revision <= 0:
            raise ValueError("policy revision must be positive")
        self.executable = str(executable.resolve())
        self.executable_digest = executable_digest
        self.gateway, self.sandbox, self.sandbox_uid = gateway, sandbox, sandbox_uid
        self.policy_digest, self.policy_revision = policy_digest, policy_revision
        self.supervisor_receipt, self.cleanup_receipt = supervisor_receipt, cleanup_receipt

    def _command(self, args: list[str], deadline: float, cancelled: Event):
        if bytes_digest(Path(self.executable).read_bytes()) != self.executable_digest:
            raise ValueError("OpenShell binary changed after validation")
        return bounded_process(
            [self.executable, "--gateway", self.gateway, *args],
            deadline=deadline,
            cancelled=cancelled,
        )

    def readiness(self, *, deadline: float, cancelled: Event) -> Readiness:
        sandbox = self._command(["sandbox", "get", self.sandbox, "-o", "json"], deadline, cancelled)
        policy = self._command(
            [
                "policy",
                "get",
                self.sandbox,
                "--rev",
                str(self.policy_revision),
                "--full",
                "-o",
                "json",
            ],
            deadline,
            cancelled,
        )
        if sandbox.returncode or policy.returncode:
            return self._state("unknown", False)
        metadata, revision = json.loads(sandbox.stdout), json.loads(policy.stdout)
        generation = self.supervisor_receipt()
        ready = (
            metadata.get("id") == self.sandbox_uid
            and metadata.get("phase") == "Ready"
            and revision.get("sandbox") == self.sandbox
            and revision.get("status") == "loaded"
            and type(revision.get("version")) is int
            and type(revision.get("active_version")) is int
            and revision.get("version") == self.policy_revision
            and revision.get("active_version") == self.policy_revision
            and "sha256:" + revision.get("hash", "").removeprefix("sha256:") == self.policy_digest
            and bool(generation)
        )
        return self._state(generation or "unknown", ready)

    def _state(self, generation: str, ready: bool) -> Readiness:
        identity = ComponentIdentity(
            component_id=self.backend_id,
            role="boundary",
            instance_uid=self.sandbox_uid,
            generation=generation,
        )
        return Readiness((identity,), self.policy_digest, ready)

    def replay(
        self, action: ReplayAction, url: str, attempt_id: str, *, deadline: float, cancelled: Event
    ) -> bool:
        if not isinstance(action, HttpGetAction) or url is None:
            raise UnsupportedCapability("openshell-action-unsupported")
        validate_receiver_url(url)
        seconds = max(1, math.ceil(deadline - time.monotonic()))
        result = self._command(
            [
                "sandbox",
                "exec",
                self.sandbox,
                "--no-tty",
                "--no-login-shell",
                "--timeout",
                str(seconds),
                "--",
                "python3",
                "-c",
                PROBE,
                url,
                attempt_id,
                str(action.timeout_seconds),
            ],
            deadline,
            cancelled,
        )
        return (
            result.returncode == 0
            and result.stdout.strip()
            == ("agent-boundary-gate-probe-complete:" + attempt_id).encode()
        )

    def destroy(self, *, deadline: float) -> bool:
        # Never delete a same-name replacement. The broker owns whole-cell destruction.
        cancelled = Event()
        current = self._command(["sandbox", "get", self.sandbox, "-o", "json"], deadline, cancelled)
        if current.returncode or json.loads(current.stdout).get("id") != self.sandbox_uid:
            return False
        deleted = self._command(["sandbox", "delete", self.sandbox], deadline, cancelled)
        # Delete acceptance is not proof of resource teardown.
        return deleted.returncode == 0 and self.cleanup_receipt()
