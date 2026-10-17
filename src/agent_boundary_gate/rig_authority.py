"""Host-side signing service backed by an operator-owned independent inspector.

The inspector is an explicit trust boundary, not workload code. No implementation
here infers whole-cell readiness/destruction from an OpenShell delete ACK.
"""

import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock
from types import MappingProxyType
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import TypeAdapter

from agent_boundary_gate.command_transport import CommandTransport
from agent_boundary_gate.contracts import Digest, Identifier
from agent_boundary_gate.doctor import read_regular_input
from agent_boundary_gate.evidence import EvidenceStore, bytes_digest
from agent_boundary_gate.monitor import MonitorHeartbeat, MonitorRequest, sign_heartbeat
from agent_boundary_gate.probe_delivery import (
    DeliveryReceipt,
    DeliveryRequest,
    RustProbeDeployment,
    sign_delivery,
)
from agent_boundary_gate.process import bounded_process
from agent_boundary_gate.receipts import (
    CleanupClaim,
    LeaseBinding,
    LifecycleReceipt,
    ReadinessClaim,
    ReceiptContract,
    ReceiptRequest,
    sign_receipt,
)
from agent_boundary_gate.rig_transport import UnixClient


class InspectionRequest(ReceiptContract):
    operation: Literal["inspect", "destroy", "monitor"]
    binding: LeaseBinding


class CellInspection(ReceiptContract):
    """Fresh authoritative observation; all claims must come from host inventory."""

    binding: LeaseBinding
    observed_at: datetime
    state: Literal["ready", "contained", "destroyed", "lost", "incident"]
    outer_boundary_closed: bool
    workload_cannot_access_authority: bool
    watchdog_active: bool
    deployment: RustProbeDeployment | None = None
    immutable_until: datetime | None = None
    executable_authorized: bool = False


class InspectorCommand(ReceiptContract):
    executable: str
    executable_digest: Digest

    def inspect(self, request: InspectionRequest, *, deadline: float, cancelled: Event):
        raw = read_regular_input(Path(self.executable), limit=64 * 1024 * 1024)
        if bytes_digest(raw) != self.executable_digest:
            raise ValueError("inspector-pin-mismatch")
        # Snapshot the verified executable. Its interpreter, dynamic libraries,
        # subprocess dependencies and environment belong to the trusted host.
        with tempfile.TemporaryDirectory(prefix="gate-inspector-") as directory:
            executable = Path(directory) / "inspector"
            executable.write_bytes(raw)
            executable.chmod(0o500)
            result = bounded_process(
                [str(executable)],
                input_data=request.model_dump_json().encode(),
                deadline=deadline,
                cancelled=cancelled,
            )
        if result.returncode:
            raise ValueError("inspector-failed")
        return CellInspection.model_validate_json(result.stdout)


class CellRegistration(ReceiptContract):
    lease: LeaseBinding
    deployment: RustProbeDeployment


Request = ReceiptRequest | DeliveryRequest | MonitorRequest


class RigAuthority:
    def __init__(
        self,
        *,
        registrations: tuple[CellRegistration, ...],
        inspector: InspectorCommand,
        monitor_inspector: InspectorCommand,
        identity: str,
        monitor_generation: str,
        keys: dict[str, Ed25519PrivateKey],
        store: EvidenceStore,
    ):
        identifier = TypeAdapter(Identifier)
        self.identity = identifier.validate_python(identity, strict=True)
        self.generation = identifier.validate_python(monitor_generation, strict=True)
        self.cells = MappingProxyType(
            {
                entry.lease.lease_id: CellRegistration.model_validate(entry)
                for entry in registrations
            }
        )
        if not self.cells or len(self.cells) != len(registrations):
            raise ValueError("invalid-cell-register")
        if set(keys) != {"readiness", "cleanup", "delivery", "monitor"}:
            raise ValueError("purpose-keys-required")
        if monitor_inspector is inspector:
            raise ValueError("separate-monitor-inspector-required")
        self.keys, self.inspector, self.store = dict(keys), inspector, store
        self.monitor_inspector = monitor_inspector
        self.sequence = 0
        self.lock = Lock()
        self.monitor_lock = Lock()
        self.sequence_lock = Lock()

    def handle(self, raw: bytes, deadline: float, cancelled: Event) -> bytes:
        monitoring = isinstance(TypeAdapter(Request).validate_json(raw), MonitorRequest)
        # Each inspector instance receives serialized calls. The separately
        # configured monitor inspector can continue during slow destruction.
        lock = self.monitor_lock if monitoring else self.lock
        while not lock.acquire(timeout=0.02):
            if cancelled.is_set() or time.monotonic() >= deadline:
                raise ValueError("authority-stopped")
        try:
            if cancelled.is_set() or time.monotonic() >= deadline:
                raise ValueError("authority-stopped")
            return self._handle(raw, deadline, cancelled)
        finally:
            lock.release()

    def _handle(self, raw, deadline, cancelled):
        request = TypeAdapter(Request).validate_json(raw)
        registered = self.cells.get(request.binding.lease_id)
        if registered is None or registered.lease != request.binding:
            raise ValueError("unregistered-cell")
        cleanup = isinstance(request, ReceiptRequest) and request.purpose == "cleanup"
        if isinstance(request, DeliveryRequest) and request.deployment != registered.deployment:
            raise ValueError("unapproved-deployment")
        if not cleanup and datetime.now(UTC) >= request.binding.lease_expires_at:
            raise ValueError("lease-expired")
        inspector = (
            self.monitor_inspector if isinstance(request, MonitorRequest) else self.inspector
        )
        inspection = inspector.inspect(
            InspectionRequest(
                operation="destroy"
                if cleanup
                else "monitor"
                if isinstance(request, MonitorRequest)
                else "inspect",
                binding=registered.lease,
            ),
            deadline=deadline,
            cancelled=cancelled,
        )
        now = datetime.now(UTC)
        if (
            cancelled.is_set()
            or time.monotonic() >= deadline
            or inspection.binding != registered.lease
            or inspection.observed_at.utcoffset() is None
            or not 0 <= (now - inspection.observed_at).total_seconds() <= 5
        ):
            raise ValueError("inspection-rejected")
        expires = now + timedelta(seconds=8 if isinstance(request, MonitorRequest) else 30)
        if not cleanup:
            expires = min(expires, request.binding.lease_expires_at)
            if expires <= now:
                raise ValueError("lease-expired")
        healthy = (
            inspection.state == "ready"
            and inspection.outer_boundary_closed
            and inspection.workload_cannot_access_authority
            and inspection.watchdog_active
        )
        if isinstance(request, MonitorRequest):
            with self.sequence_lock:
                self.sequence += 1
                sequence = self.sequence
            signed = sign_heartbeat(
                MonitorHeartbeat(
                    request=request,
                    signer_identity=self.identity,
                    generation=self.generation,
                    sequence=sequence,
                    state="incident"
                    if inspection.state == "incident"
                    else "healthy"
                    if healthy
                    or (
                        inspection.state in ("contained", "destroyed")
                        and inspection.outer_boundary_closed
                        and inspection.workload_cannot_access_authority
                        and inspection.watchdog_active
                    )
                    else "lost",
                    issued_at=now,
                    expires_at=expires,
                ),
                self.keys["monitor"],
            )
        elif isinstance(request, DeliveryRequest):
            if not (
                healthy
                and inspection.deployment == registered.deployment
                and inspection.executable_authorized
                and inspection.immutable_until is not None
                and inspection.immutable_until.utcoffset() is not None
                and inspection.immutable_until >= registered.lease.lease_expires_at
            ):
                raise ValueError("delivery-unverified")
            signed = sign_delivery(
                DeliveryReceipt(
                    request=request,
                    signer_identity=self.identity,
                    issued_at=now,
                    expires_at=expires,
                    immutable_until=inspection.immutable_until,
                    state="verified-immutable-delivery",
                ),
                self.keys["delivery"],
            )
        else:
            if cleanup:
                if inspection.state != "destroyed":
                    raise ValueError("cleanup-unverified")
                claim = CleanupClaim(state="destroyed", scope="whole-cell")
            else:
                if not healthy:
                    raise ValueError("readiness-unverified")
                claim = ReadinessClaim(
                    state="ready", effective_policy_digest=registered.lease.effective_policy_digest
                )
            signed = sign_receipt(
                LifecycleReceipt(
                    request=request,
                    signer_identity=self.identity,
                    issued_at=now,
                    expires_at=expires,
                    claim=claim,
                ),
                self.keys[request.purpose],
            )
        # Retain inspected facts and signed proof before returning admission.
        reply = signed.model_dump_json().encode()
        try:
            self.store.persist(inspection.model_dump_json().encode())
            self.store.persist(reply)
        except (OSError, ValueError):
            if not isinstance(request, MonitorRequest) or signed.heartbeat.state != "incident":
                raise
            # An independently observed incident must survive storage failure.
        return reply


class AuthorityClient:
    def __init__(self, path: Path, store: EvidenceStore | None = None):
        # CommandAuthorityClient below overrides this with a CommandTransport: both
        # share the same call(raw, *, deadline, cancelled) -> bytes interface.
        self.client: UnixClient | CommandTransport = UnixClient(path)
        self.store = store

    def fetch(self, request: Request, *, deadline: float, cancelled: Event) -> bytes:
        raw = self.client.call(
            request.model_dump_json().encode(), deadline=deadline, cancelled=cancelled
        )
        if self.store is not None and not isinstance(request, MonitorRequest):
            # Bounded untrusted receipt retention. Existing verifiers establish
            # admission; retention alone cannot establish proof semantics.
            self.store.persist(raw)
        return raw

    def destroy(self, request: ReceiptRequest, *, deadline: float, cancelled: Event) -> bytes:
        if request.purpose != "cleanup":
            raise ValueError("cleanup-request-required")
        return self.fetch(request, deadline=deadline, cancelled=cancelled)


class CommandAuthorityClient(AuthorityClient):
    """Library composition for signed receipt/delivery/monitor command providers.

    Trust still comes from independently configured verifier keys and bindings,
    never from command completion. Each command must consult external authority;
    process-local state is not retained between invocations.
    """

    def __init__(self, command: CommandTransport, store: EvidenceStore | None = None):
        self.client, self.store = CommandTransport.model_validate(command), store
