"""Paired host-side receivers and signed, challenge-bound capture snapshots."""

import ipaddress
import json
import secrets
import select
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlunsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field

from agent_boundary_gate.backends import UnsupportedCapability
from agent_boundary_gate.contracts import CaseSpec, HttpGetAction, ReplayAction, SourceEvidence
from agent_boundary_gate.evidence import EvidenceStore
from agent_boundary_gate.observers import Observation
from agent_boundary_gate.observers.denied_egress import DeniedEgressObserver
from agent_boundary_gate.probes import validate_receiver_url
from agent_boundary_gate.receipts import Challenge, Identifier, LeaseBinding, ReceiptContract
from agent_boundary_gate.rig_transport import UnixClient

DOMAIN = b"agent-boundary-gate/receiver-snapshot/1.0\0"


class CaptureRequest(ReceiptContract):
    purpose: Literal["receiver-capture"] = "receiver-capture"
    operation: Literal["start", "sample", "drain"]
    challenge: Challenge
    binding: LeaseBinding


class CaptureSnapshot(ReceiptContract):
    request: CaptureRequest
    signer_identity: Identifier
    generation: Identifier
    issued_at: datetime
    expires_at: datetime
    started: bool
    drained: bool
    allowed_count: Annotated[int, Field(ge=0, le=1000000)]
    forbidden_count: Annotated[int, Field(ge=0, le=1000000)]
    dropped_events: Annotated[int, Field(ge=0, le=1000000)]
    allowed_url: str
    forbidden_url: str


class SignedCaptureSnapshot(ReceiptContract):
    snapshot: CaptureSnapshot
    algorithm: Literal["Ed25519"] = "Ed25519"
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


def snapshot_payload(snapshot: CaptureSnapshot) -> bytes:
    return (
        DOMAIN
        + json.dumps(
            snapshot.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    )


class ReceiverServer(ThreadingHTTPServer):
    """Finite concurrent connections; bounded socket/header processing."""

    daemon_threads = False
    block_on_close = True

    def __init__(self, address, handler, on_loss):
        self.slots = threading.BoundedSemaphore(8)
        self.on_loss = on_loss
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(0.5)
        return connection, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.on_loss()
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        self.on_loss()


class ReceiverService:
    """One serial disposable capture at a time. Admin socket stays outside VM."""

    def __init__(
        self,
        *,
        leases: tuple[LeaseBinding, ...],
        identity: str,
        generation: str,
        key: Ed25519PrivateKey,
        store: EvidenceStore,
        addresses: dict[str, tuple[str, int]],
        advertise_host: str = "127.0.0.1",
    ):
        self.leases = {lease.lease_id: lease for lease in leases}
        if not self.leases or len(self.leases) != len(leases):
            raise ValueError("receiver-register-required")
        if set(addresses) != {"allowed", "forbidden"}:
            raise ValueError("paired-receivers-required")
        for host, port in addresses.values():
            if ipaddress.ip_address(host).version != 4 or not 0 <= port <= 65535:
                raise ValueError("receiver-ipv4-bind-required")
        self.identity, self.generation, self.key, self.store = identity, generation, key, store
        if ipaddress.ip_address(advertise_host).version != 4 or advertise_host == "0.0.0.0":
            raise ValueError("receiver-advertised-ip-required")
        self.advertise_host = advertise_host
        self.addresses = dict(addresses)
        self.servers = {}
        self.threads = []
        self.server_threads = {}
        self.lock = threading.Lock()
        self.admin_lock = threading.Lock()
        self.active: LeaseBinding | None = None
        self.used: set[str] = set()
        self.counts = {"allowed": 0, "forbidden": 0}
        self.dropped = 0
        self.drained = False

    def _handler(self, receiver):
        capture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                status = 404
                with capture.lock:
                    if (
                        capture.active is not None
                        and not capture.drained
                        and datetime.now(UTC) < capture.active.lease_expires_at
                        and self.path == "/probe"
                        and self.headers.get_all("X-Gate-Attempt") == [capture.active.attempt_id]
                    ):
                        capture.counts[receiver] = min(1000000, capture.counts[receiver] + 1)
                        # Capture counts are durable before HTTP acknowledgement.
                        # A storage failure still retains the observed effect.
                        try:
                            if sum(capture.counts.values()) > 1000:
                                raise ValueError("capture-event-capacity")
                            capture.store.persist_json(
                                {
                                    "attempt_id": capture.active.attempt_id,
                                    "receiver": receiver,
                                    "observed_at": datetime.now(UTC).isoformat(),
                                    "count": capture.counts[receiver],
                                }
                            )
                            status = 204
                        except (OSError, ValueError):
                            capture.dropped = min(1000000, capture.dropped + 1)
                            status = 503
                self.send_response(status)
                self.end_headers()
                self.close_connection = True

            def log_message(self, *args):
                pass

            def log_error(self, *args):
                capture.mark_loss()

        return Handler

    def mark_loss(self):
        with self.lock:
            if self.active is not None and not self.drained:
                self.dropped = min(1000000, self.dropped + 1)

    def start(self):
        try:
            for receiver in ("allowed", "forbidden"):
                server = ReceiverServer(
                    self.addresses[receiver], self._handler(receiver), self.mark_loss
                )
                self.addresses[receiver] = (self.addresses[receiver][0], server.server_port)
                self.servers[receiver] = server
                thread = threading.Thread(
                    target=server.serve_forever, kwargs={"poll_interval": 0.02}
                )
                thread.start()
                self.threads.append(thread)
                self.server_threads[receiver] = thread
        except BaseException:
            self.stop()
            raise

    def stop(self):
        for receiver, server in self.servers.items():
            thread = self.server_threads.get(receiver)
            if thread is not None and thread.is_alive():
                server.shutdown()
                # Process already queued connections before closing the listener.
                # Capacity loss is recorded instead of silently treated as denial.
                for _ in range(16):
                    if not select.select([server.socket], [], [], 0)[0]:
                        break
                    request, address = server.get_request()
                    server.process_request(request, address)
                if select.select([server.socket], [], [], 0)[0]:
                    self.mark_loss()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)

    def handle(self, raw: bytes, deadline: float, cancelled: threading.Event) -> bytes:
        request = CaptureRequest.model_validate_json(raw)
        if self.leases.get(request.binding.lease_id) != request.binding:
            raise ValueError("unregistered-capture")
        while not self.admin_lock.acquire(timeout=0.02):
            if cancelled.is_set() or time.monotonic() >= deadline:
                raise ValueError("capture-stopped")
        try:
            if request.operation == "start" and request.binding.lease_id in self.used:
                raise ValueError("capture-start-rejected")
            if request.operation == "drain":
                with self.lock:
                    if self.active != request.binding:
                        raise ValueError("capture-binding-mismatch")
                self.stop()
            elif (
                request.operation == "start"
                and self.servers
                and all(server.fileno() < 0 for server in self.servers.values())
            ):
                self.start()
            return self._handle(raw, deadline, cancelled)
        finally:
            self.admin_lock.release()

    def _handle(self, raw: bytes, deadline: float, cancelled: threading.Event) -> bytes:
        request = CaptureRequest.model_validate_json(raw)
        if self.leases.get(request.binding.lease_id) != request.binding:
            raise ValueError("unregistered-capture")
        while not self.lock.acquire(timeout=0.02):
            if cancelled.is_set() or time.monotonic() >= deadline:
                raise ValueError("capture-stopped")
        try:
            if cancelled.is_set() or time.monotonic() >= deadline:
                raise ValueError("capture-stopped")
            now = datetime.now(UTC)
            if request.operation == "start":
                if (
                    request.binding.lease_id in self.used
                    or (self.active is not None and not self.drained)
                    or now >= request.binding.lease_expires_at
                    or set(self.servers) != {"allowed", "forbidden"}
                ):
                    raise ValueError("capture-start-rejected")
                self.active = request.binding
                self.used.add(request.binding.lease_id)
                self.counts = {"allowed": 0, "forbidden": 0}
                self.dropped, self.drained = 0, False
            if self.active != request.binding:
                raise ValueError("capture-binding-mismatch")
            if request.operation == "drain":
                # Serializes against admitted GETs. Later requests cannot enter
                # this attempt; no next-attempt traffic can contaminate it.
                self.drained = True
            snapshot = CaptureSnapshot(
                request=request,
                signer_identity=self.identity,
                generation=self.generation,
                issued_at=now,
                expires_at=now + timedelta(seconds=30),
                started=True,
                drained=self.drained,
                allowed_count=self.counts["allowed"],
                forbidden_count=self.counts["forbidden"],
                dropped_events=self.dropped,
                allowed_url=self.url("allowed"),
                forbidden_url=self.url("forbidden"),
            )
            reply = (
                SignedCaptureSnapshot(
                    snapshot=snapshot, signature=self.key.sign(snapshot_payload(snapshot)).hex()
                )
                .model_dump_json()
                .encode()
            )
            try:
                self.store.persist(reply)
            except (OSError, ValueError):
                # Retain a signed finding even when collector storage fails;
                # mark required evidence incomplete so this cannot produce pass.
                self.dropped = min(1000000, self.dropped + 1)
                snapshot = snapshot.model_copy(update={"dropped_events": self.dropped})
                reply = (
                    SignedCaptureSnapshot(
                        snapshot=snapshot, signature=self.key.sign(snapshot_payload(snapshot)).hex()
                    )
                    .model_dump_json()
                    .encode()
                )
            return reply
        finally:
            self.lock.release()

    def url(self, receiver: str) -> str:
        port = self.servers[receiver].server_port
        return urlunsplit(("http", f"{self.advertise_host}:{port}", "/probe", "", ""))


class RemoteDeniedEgressObserver:
    def require_supported(self, case: CaseSpec):
        DeniedEgressObserver.require_supported(self, case)
        if case.observer_version != "signed-receiver-count-v1":
            raise UnsupportedCapability("signed-receiver-version-required")

    def __init__(
        self,
        *,
        lease: LeaseBinding,
        socket_path: Path,
        endpoints: dict[str, str],
        identity: str,
        generation: str,
        key: Ed25519PublicKey,
        store: EvidenceStore,
        deadline: float,
        cancelled: threading.Event,
    ):
        if set(endpoints) != {"allowed", "forbidden"} or len(set(endpoints.values())) != 2:
            raise ValueError("distinct-paired-endpoints-required")
        for endpoint in endpoints.values():
            validate_receiver_url(endpoint)
        self.lease, self.attempt_id = lease, lease.attempt_id
        self.client, self.endpoints = UnixClient(socket_path), dict(endpoints)
        self.identity, self.generation, self.key = identity, generation, key
        self.store, self.deadline, self.cancelled = store, deadline, cancelled
        self.started, self.drained, self.failed = False, False, False
        self.allowed, self.forbidden, self.dropped = 0, 0, 0
        self.reference: str | None = None
        self.effects: set[str] = set()

    def _call(self, operation, *, cleanup=False):
        request = CaptureRequest(
            operation=operation, challenge=secrets.token_hex(32), binding=self.lease
        )
        raw = self.client.call(
            request.model_dump_json().encode(),
            deadline=time.monotonic() + 5 if cleanup else min(self.deadline, time.monotonic() + 5),
            cancelled=threading.Event() if cleanup else self.cancelled,
        )
        signed = SignedCaptureSnapshot.model_validate_json(raw)
        snapshot = signed.snapshot
        self.key.verify(bytes.fromhex(signed.signature), snapshot_payload(snapshot))
        now = datetime.now(UTC)
        if not (
            snapshot.request == request
            and snapshot.signer_identity == self.identity
            and snapshot.generation == self.generation
            and snapshot.issued_at.utcoffset() is not None
            and snapshot.expires_at.utcoffset() is not None
            and snapshot.issued_at <= now < snapshot.expires_at
            and snapshot.expires_at - snapshot.issued_at <= timedelta(seconds=30)
            and snapshot.started
            and snapshot.allowed_count >= self.allowed
            and snapshot.forbidden_count >= self.forbidden
            and snapshot.dropped_events >= self.dropped
            and snapshot.allowed_url == self.endpoints["allowed"]
            and snapshot.forbidden_url == self.endpoints["forbidden"]
            and (operation != "drain" or snapshot.drained)
            and (operation != "start" or not snapshot.drained)
        ):
            raise ValueError("receiver-snapshot-rejected")
        self.allowed, self.forbidden, self.dropped = (
            snapshot.allowed_count,
            snapshot.forbidden_count,
            snapshot.dropped_events,
        )
        # Latch findings before persistence; storage loss cannot erase them.
        from agent_boundary_gate.evidence import bytes_digest

        reference = bytes_digest(raw)
        if self.forbidden:
            self.effects.add(reference)
        self.reference = self.store.persist(raw)
        self.started, self.drained = True, snapshot.drained

    def start(self):
        self._call("start")

    def endpoint(self, action: ReplayAction) -> str:
        if not isinstance(action, HttpGetAction):
            raise ValueError("unsupported-receiver-action")
        return self.endpoints[action.receiver]

    def positive_control_observed(self, action: ReplayAction) -> bool:
        try:
            self._call("sample")
        except Exception:
            self.failed = True
            return False
        return (
            not isinstance(action, HttpGetAction)
            or action.receiver != "allowed"
            or self.allowed > 0
        )

    def stop(self):
        try:
            if self.started:
                # Preserve effects before cleanup; keep receivers open until
                # lifecycle calls observe after whole-cell destruction.
                self._call("sample", cleanup=True)
        except Exception:
            self.failed = True

    def observe(self, *, execution_valid: bool):
        try:
            if self.started and not self.drained:
                self._call("drain", cleanup=True)
        except Exception:
            self.failed = True
        complete = self.started and self.drained and not self.failed and not self.dropped
        outcome = (
            "violation"
            if self.forbidden
            else "held"
            if (complete and self.allowed and execution_valid)
            else "unknown"
        )
        source = SourceEvidence(
            source_id="receiver",
            identity=self.identity,
            generation=self.generation,
            designation="required",
            ready_before_replay=self.started,
            drained=complete,
            dropped_events=self.dropped,
            truncated=not complete,
            artifact_digest=self.reference or "sha256:" + "0" * 64,
        )
        return Observation(
            outcome,
            "passed" if self.allowed else "failed",
            (source,),
            tuple(sorted(self.effects)),
            complete,
        )
