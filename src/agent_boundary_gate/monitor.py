"""Fail-stop monitor sessions; only authenticated, fresh heartbeats establish health."""

import json
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from types import MappingProxyType
from typing import Annotated, Literal, Protocol, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, TypeAdapter, ValidationError, field_validator, model_validator

from agent_boundary_gate.auth import digest
from agent_boundary_gate.contracts import Binding, Identifier
from agent_boundary_gate.evidence import EvidenceStore
from agent_boundary_gate.receipts import Challenge, LeaseBinding, ReceiptContract

DOMAIN = b"agent-boundary-gate/monitor-heartbeat/1.0\0"
MAX_HEARTBEAT_BYTES = 65536
MAX_HEARTBEAT_LIFETIME = timedelta(seconds=10)
MAX_HEARTBEAT_REFS = 256


class MonitorRequest(ReceiptContract):
    purpose: Literal["containment-monitor"] = "containment-monitor"
    challenge: Challenge
    binding: LeaseBinding


class MonitorHeartbeat(ReceiptContract):
    request: MonitorRequest
    signer_identity: Identifier
    generation: Identifier
    sequence: Annotated[int, Field(gt=0, le=2**63 - 1)]
    state: Literal["healthy", "lost", "incident"]
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("monitor times must be timezone aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def ordered_times(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("heartbeat expiry must follow issuance")
        return self


class SignedMonitorHeartbeat(ReceiptContract):
    heartbeat: MonitorHeartbeat
    algorithm: Literal["Ed25519"] = "Ed25519"
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


def heartbeat_payload(heartbeat: MonitorHeartbeat) -> bytes:
    return (
        DOMAIN
        + json.dumps(
            heartbeat.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    )


def sign_heartbeat(heartbeat: MonitorHeartbeat, key: Ed25519PrivateKey) -> SignedMonitorHeartbeat:
    return SignedMonitorHeartbeat(
        heartbeat=heartbeat, signature=key.sign(heartbeat_payload(heartbeat)).hex()
    )


@dataclass(frozen=True)
class MonitorSnapshot:
    state: Literal["unknown", "healthy", "lost", "incident"]
    identity: str
    generation: str
    incident: bool = False
    heartbeat_refs: tuple[str, ...] = ()
    dropped_events: int = 0

    @property
    def healthy(self) -> bool:
        return self.state == "healthy"


class ContainmentMonitor(Protocol):
    def require_binding(self, binding: Binding) -> bool: ...

    def snapshot(self) -> MonitorSnapshot: ...


class UnknownMonitor:
    def require_binding(self, binding: Binding) -> bool:
        return False

    def snapshot(self) -> MonitorSnapshot:
        return MonitorSnapshot("unknown", "unknown-monitor", "unknown")


class FixtureMonitor:
    """Explicit simulation, never an authenticated monitor or live health source."""

    def __init__(self, binding: Binding):
        self._binding = binding
        self._lost = False
        self._incident = False
        self._lock = Lock()

    def require_binding(self, binding: Binding) -> bool:
        if binding != self._binding:
            self.mark_lost()
            return False
        return True

    def mark_lost(self) -> None:
        with self._lock:
            self._lost = True

    def mark_incident(self) -> None:
        with self._lock:
            self._incident = True

    def snapshot(self) -> MonitorSnapshot:
        with self._lock:
            return MonitorSnapshot(
                "incident" if self._incident else "lost" if self._lost else "healthy",
                "local-fixture-monitor",
                self._binding.attempt_id,
                self._incident,
            )


class MonitorSession:
    """One attempt's containment coverage; loss/incident are terminal for that attempt."""

    def __init__(
        self,
        *,
        lease: LeaseBinding,
        identity: str,
        generation: str,
        trusted_keys: Mapping[str, Ed25519PublicKey],
        store: EvidenceStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.lease = LeaseBinding.model_validate(lease)
        identifier = TypeAdapter(Identifier)
        self.identity = identifier.validate_python(identity, strict=True)
        self.generation = identifier.validate_python(generation, strict=True)
        self._keys = MappingProxyType(dict(trusted_keys))
        self._store, self._clock = store, monotonic
        self._lock = Lock()
        self._pending: MonitorRequest | None = None
        self._deadline: float | None = None
        self._sequence = 0
        self._lost = False
        self._incident = False
        self._refs: list[str] = []
        self._dropped = 0

    def require_binding(self, binding: Binding) -> bool:
        with self._lock:
            valid = (
                digest(binding) == self.lease.binding_digest
                and binding.run_id == self.lease.run_id
                and binding.attempt_id == self.lease.attempt_id
                and binding.target_profile.boundary.id == self.lease.component.component_id
                and binding.effective_policy_digest == self.lease.effective_policy_digest
            )
            if not valid:
                self._lost = True
            return valid

    def request(self) -> MonitorRequest:
        with self._lock:
            self._expire()
            self._pending = MonitorRequest(challenge=secrets.token_hex(32), binding=self.lease)
            return self._pending

    def _expire(self) -> None:
        if self._deadline is not None and self._clock() >= self._deadline:
            self._lost = True

    def accept(self, raw: bytes, *, now: datetime | None = None) -> bool:
        now = now if now is not None else datetime.now(UTC)
        with self._lock:
            received_at = self._clock()
            self._expire()
            request = self._pending
            try:
                if (
                    request is None
                    or not isinstance(raw, bytes)
                    or len(raw) > MAX_HEARTBEAT_BYTES
                    or now.utcoffset() is None
                ):
                    raise ValueError("heartbeat-rejected")
                signed = SignedMonitorHeartbeat.model_validate_json(raw)
                heartbeat = signed.heartbeat
                key = self._keys.get(heartbeat.signer_identity)
                if key is None:
                    raise ValueError("heartbeat-rejected")
                key.verify(bytes.fromhex(signed.signature), heartbeat_payload(heartbeat))
                if not (
                    heartbeat.request == request
                    and heartbeat.signer_identity == self.identity
                    and heartbeat.generation == self.generation
                    and heartbeat.sequence > self._sequence
                    and heartbeat.issued_at <= now < heartbeat.expires_at
                    and heartbeat.expires_at - heartbeat.issued_at <= MAX_HEARTBEAT_LIFETIME
                    and heartbeat.expires_at <= self.lease.lease_expires_at
                ):
                    raise ValueError("heartbeat-rejected")
                # Consume only an authenticated, matching response. Rejected
                # input must not discard an outstanding challenge: a late valid
                # incident for it still needs to be retained after health is lost.
                self._pending = None
                # A verified incident is latched before storage, so storage loss
                # cannot erase a proven incident. Health requires durable evidence.
                self._incident |= heartbeat.state == "incident"
                # An authenticated loss means required coverage is missing for
                # this attempt. Later health cannot reconstruct that evidence
                # or undo cancelled replay; recovery needs a new attempt/session.
                self._lost |= heartbeat.state == "lost"
                if len(self._refs) >= MAX_HEARTBEAT_REFS:
                    self._dropped += 1
                    raise ValueError("heartbeat-evidence-capacity-exceeded")
                reference = self._store.persist(raw)
                self._refs.append(reference)
                self._sequence = heartbeat.sequence
                self._deadline = received_at + (heartbeat.expires_at - now).total_seconds()
                self._expire()
                return not self._lost and not self._incident
            except (OSError, ValueError, ValidationError, InvalidSignature):
                # Rejection makes health uncertain, not a proven incident.
                # Keep fail-stop health while allowing authenticated findings
                # for an unconsumed request to be retained on a later response.
                self._lost = True
                return False

    def snapshot(self) -> MonitorSnapshot:
        with self._lock:
            self._expire()
            state: Literal["unknown", "healthy", "lost", "incident"] = (
                "incident"
                if self._incident
                else "lost"
                if self._lost
                else "healthy"
                if self._deadline is not None
                else "unknown"
            )
            return MonitorSnapshot(
                state,
                self.identity,
                self.generation,
                self._incident,
                tuple(self._refs),
                self._dropped,
            )
