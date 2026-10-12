"""Direct CLI driver for an independently provisioned, leased OpenShell sandbox.

CLI JSON/flags correspond to cached source f745aa4df4b1e63ca362cb4624d3952796a7c31c.
This driver does not provision containment, issue leases or invent supervisor readiness.
"""

import ipaddress
import json
import math
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Literal
from urllib.parse import urlsplit

from agent_boundary_gate.auth import digest
from agent_boundary_gate.backends import BackendFailure, Readiness, UnsupportedCapability
from agent_boundary_gate.contracts import Binding, ComponentIdentity, HttpGetAction, ReplayAction
from agent_boundary_gate.evidence import bytes_digest
from agent_boundary_gate.probe_delivery import (
    DeliveryProvider,
    DeliveryRejected,
    DeliveryVerifier,
    RustProbeDeployment,
)
from agent_boundary_gate.probes import PERL_PROBE, PROBE, validate_receiver_url
from agent_boundary_gate.process import AttemptStopped, bounded_process
from agent_boundary_gate.receipts import (
    LeaseBinding,
    LifecycleReceipt,
    Purpose,
    ReceiptProvider,
    ReceiptRejected,
    ReceiptVerifier,
)


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
        lease: LeaseBinding,
        receipt_provider: ReceiptProvider,
        receipt_verifier: ReceiptVerifier,
        probe_runtime: Literal["python3", "perl", "rust"] = "python3",
        rust_deployment: RustProbeDeployment | None = None,
        delivery_provider: DeliveryProvider | None = None,
        delivery_verifier: DeliveryVerifier | None = None,
    ):
        if probe_runtime not in ("python3", "perl", "rust"):
            raise ValueError("unsupported probe runtime")
        if probe_runtime == "rust":
            if rust_deployment is None or delivery_provider is None or delivery_verifier is None:
                raise ValueError("rust probe requires trusted delivery configuration")
            rust_deployment = RustProbeDeployment.model_validate(rust_deployment)
        elif any(
            item is not None for item in (rust_deployment, delivery_provider, delivery_verifier)
        ):
            raise ValueError("rust delivery configuration requires explicit rust selection")
        if bytes_digest(executable.read_bytes()) != executable_digest:
            raise ValueError("OpenShell binary does not match its pin")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}", gateway):
            raise ValueError("invalid gateway name")
        if not re.fullmatch(r"gate-[a-z0-9-]{1,80}", sandbox):
            raise ValueError("driver accepts only explicitly leased gate-* sandbox names")
        if type(policy_revision) is not int or policy_revision <= 0:
            raise ValueError("policy revision must be positive")
        if (
            lease.component.component_id != self.backend_id
            or lease.component.instance_uid != sandbox_uid
            or lease.effective_policy_digest != policy_digest
        ):
            raise ValueError("backend configuration must match the trusted lease")
        self.executable = str(executable.resolve())
        self.executable_digest = executable_digest
        self.gateway, self.sandbox, self.sandbox_uid = gateway, sandbox, sandbox_uid
        self.policy_digest, self.policy_revision = policy_digest, policy_revision
        self.lease = lease
        self.receipt_provider, self.receipt_verifier = receipt_provider, receipt_verifier
        self.probe_runtime = probe_runtime
        self.rust_deployment = rust_deployment
        self.delivery_provider, self.delivery_verifier = delivery_provider, delivery_verifier
        self._attempt_bound = False
        self._last_readiness: LifecycleReceipt | None = None

    def require_binding(self, binding: Binding) -> None:
        self._attempt_bound = False
        self._last_readiness = None
        if (
            digest(binding) != self.lease.binding_digest
            or binding.run_id != self.lease.run_id
            or binding.attempt_id != self.lease.attempt_id
        ):
            raise UnsupportedCapability("openshell-lease-binding-mismatch")
        self._attempt_bound = True

    def _receipt(
        self, purpose: Purpose, *, deadline: float, cancelled: Event
    ) -> LifecycleReceipt | None:
        if cancelled.is_set() or time.monotonic() >= deadline:
            return None
        request = self.receipt_verifier.request(purpose, self.lease)
        raw = self.receipt_provider.fetch(request, deadline=deadline, cancelled=cancelled)
        if raw is None or cancelled.is_set() or time.monotonic() >= deadline:
            return None
        try:
            return self.receipt_verifier.verify(raw, request=request, now=datetime.now(UTC))
        except ReceiptRejected:
            return None

    def _command(self, args: list[str], deadline: float, cancelled: Event, *, phase: str):
        if bytes_digest(Path(self.executable).read_bytes()) != self.executable_digest:
            raise ValueError("OpenShell binary changed after validation")
        try:
            result = bounded_process(
                [self.executable, "--gateway", self.gateway, *args],
                deadline=deadline,
                cancelled=cancelled,
            )
        except AttemptStopped as stopped:
            if stopped.reason == "cancelled":
                raise
            failure = {
                "timeout": "timeout",
                "output-limit": "output-limit",
                "process-group-cleanup-not-confirmed": "group-cleanup-failed",
            }[stopped.reason]
            reason = f"backend-{phase}-cli-{failure}"
            if failure == "timeout":
                raise AttemptStopped(reason) from None
            raise BackendFailure(reason) from None
        except OSError:
            raise BackendFailure(f"backend-{phase}-cli-start-failed") from None
        if result.returncode:
            raise BackendFailure(f"backend-{phase}-cli-exit-nonzero")
        return result

    def readiness(self, *, deadline: float, cancelled: Event) -> Readiness:
        self._last_readiness = None
        sandbox = self._command(
            ["sandbox", "get", self.sandbox, "-o", "json"], deadline, cancelled, phase="readiness"
        )
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
            phase="readiness",
        )
        if sandbox.returncode or policy.returncode:
            return self._state("unknown", False)
        metadata, revision = json.loads(sandbox.stdout), json.loads(policy.stdout)
        receipt = self._receipt("readiness", deadline=deadline, cancelled=cancelled)
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
            and receipt is not None
        )
        if ready:
            self._last_readiness = receipt
        generation = self.lease.component.generation if ready else "unknown"
        return self._state(generation, ready)

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
        now = datetime.now(UTC)
        if (
            not self._attempt_bound
            or attempt_id != self.lease.attempt_id
            or self._last_readiness is None
            or now < self._last_readiness.issued_at
            or now >= self._last_readiness.expires_at
            or now >= self.lease.lease_expires_at
        ):
            return False
        deadline = min(
            deadline,
            time.monotonic()
            + (
                min(self.lease.lease_expires_at, self._last_readiness.expires_at) - now
            ).total_seconds(),
        )
        validate_receiver_url(url)
        if self.probe_runtime == "python3":
            probe = ["python3", "-c", PROBE, url, attempt_id, str(action.timeout_seconds)]
        elif self.probe_runtime == "perl":
            receiver = urlsplit(url)
            probe = [
                "perl",
                "-e",
                PERL_PROBE,
                "--",
                receiver.hostname,
                str(receiver.port),
                attempt_id,
                str(max(1, math.ceil(action.timeout_seconds))),
            ]
        else:
            receiver = urlsplit(url)
            try:
                host = str(ipaddress.ip_address(receiver.hostname))
            except ValueError:
                raise UnsupportedCapability("rust-probe-ip-literal-required") from None
            timeout = math.ceil(action.timeout_seconds)
            if not 1 <= timeout <= 30 or not re.fullmatch(
                r"[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}", attempt_id
            ):
                raise UnsupportedCapability("rust-probe-input-unsupported")
            request = self.delivery_verifier.request(self.lease, self.rust_deployment)
            try:
                if cancelled.is_set() or time.monotonic() >= deadline:
                    return False
                raw = self.delivery_provider.fetch(request, deadline=deadline, cancelled=cancelled)
                if cancelled.is_set() or time.monotonic() >= deadline:
                    return False
                receipt = self.delivery_verifier.verify(raw, request=request, now=datetime.now(UTC))
            except (DeliveryRejected, OSError):
                raise BackendFailure("backend-probe-delivery-rejected") from None
            if cancelled.is_set() or time.monotonic() >= deadline:
                return False
            deadline = min(
                deadline,
                time.monotonic() + (receipt.expires_at - datetime.now(UTC)).total_seconds(),
            )
            if time.monotonic() >= deadline:
                return False
            probe = [
                self.rust_deployment.executable_path,
                host,
                str(receiver.port),
                attempt_id,
                str(timeout),
            ]
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
                *probe,
            ],
            deadline,
            cancelled,
            phase="replay",
        )
        return (
            result.returncode == 0
            and result.stdout.strip()
            == ("agent-boundary-gate-probe-complete:" + attempt_id).encode()
        )

    def destroy(self, *, deadline: float) -> bool:
        self._attempt_bound = False
        self._last_readiness = None
        # Never delete a same-name replacement. The broker owns whole-cell destruction.
        cancelled = Event()
        current = self._command(
            ["sandbox", "get", self.sandbox, "-o", "json"], deadline, cancelled, phase="cleanup"
        )
        if current.returncode or json.loads(current.stdout).get("id") != self.sandbox_uid:
            return False
        deleted = self._command(
            ["sandbox", "delete", self.sandbox], deadline, cancelled, phase="cleanup"
        )
        # Delete acceptance is not proof of resource teardown.
        return (
            deleted.returncode == 0
            and self._receipt("cleanup", deadline=deadline, cancelled=cancelled) is not None
        )
