"""Service entry points; configuration and keys remain on the trusted rig host."""

import signal
from pathlib import Path
from threading import Event
from typing import Annotated

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field

from agent_boundary_gate.evidence import EvidenceStore
from agent_boundary_gate.live import PublicKeyHex, public_key, read_private
from agent_boundary_gate.receipts import Identifier, LeaseBinding, ReceiptContract, ReceiptVerifier
from agent_boundary_gate.recovery import LeaseJournal, RecoveryWorker, utc_now
from agent_boundary_gate.rig_authority import (
    AuthorityClient,
    CellRegistration,
    InspectorCommand,
    RigAuthority,
)
from agent_boundary_gate.rig_receivers import ReceiverService
from agent_boundary_gate.rig_transport import UnixService


class AuthorityConfig(ReceiptContract):
    socket_path: str
    registrations: Annotated[tuple[CellRegistration, ...], Field(min_length=1, max_length=128)]
    inspector: InspectorCommand
    monitor_inspector: InspectorCommand
    identity: Identifier
    monitor_generation: Identifier
    readiness_key_file: str
    cleanup_key_file: str
    delivery_key_file: str
    monitor_key_file: str
    evidence_directory: str


class ReceiverConfig(ReceiptContract):
    socket_path: str
    leases: Annotated[tuple[LeaseBinding, ...], Field(min_length=1, max_length=128)]
    identity: Identifier
    generation: Identifier
    key_file: str
    evidence_directory: str
    bind_host: str
    advertise_host: str
    allowed_port: Annotated[int, Field(gt=0, le=65535)]
    forbidden_port: Annotated[int, Field(gt=0, le=65535)]


class WatchdogConfig(ReceiptContract):
    authority_socket: str
    authority_identity: Identifier
    cleanup_public_key: PublicKeyHex
    journal_directory: str
    leases: Annotated[tuple[LeaseBinding, ...], Field(min_length=1, max_length=128)]


def _signals(stop: Event):
    previous = {}
    for number in (signal.SIGTERM, signal.SIGINT):
        previous[number] = signal.signal(number, lambda *_: stop.set())
    return previous


def serve_authority(path: Path):
    config = AuthorityConfig.model_validate_json(read_private(path))
    keys = {
        purpose: Ed25519PrivateKey.from_private_bytes(
            read_private(Path(getattr(config, purpose + "_key_file")), limit=32)
        )
        for purpose in ("readiness", "cleanup", "delivery", "monitor")
    }
    authority = RigAuthority(
        registrations=config.registrations,
        inspector=config.inspector,
        monitor_inspector=config.monitor_inspector,
        identity=config.identity,
        monitor_generation=config.monitor_generation,
        keys=keys,
        store=EvidenceStore(Path(config.evidence_directory)),
    )
    _serve(UnixService(Path(config.socket_path), authority.handle, budget=55))


def _serve(service: UnixService):
    previous = _signals(service.stop)
    try:
        service.run()
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def serve_receivers(path: Path):
    config = ReceiverConfig.model_validate_json(read_private(path))
    if config.allowed_port == config.forbidden_port:
        raise ValueError("distinct-receiver-ports-required")
    receiver = ReceiverService(
        leases=config.leases,
        identity=config.identity,
        generation=config.generation,
        key=Ed25519PrivateKey.from_private_bytes(read_private(Path(config.key_file), limit=32)),
        store=EvidenceStore(Path(config.evidence_directory)),
        addresses={
            "allowed": (config.bind_host, config.allowed_port),
            "forbidden": (config.bind_host, config.forbidden_port),
        },
        advertise_host=config.advertise_host,
    )
    try:
        receiver.start()
        _serve(UnixService(Path(config.socket_path), receiver.handle))
    finally:
        receiver.stop()


def run_watchdog(path: Path):
    config = WatchdogConfig.model_validate_json(read_private(path))
    journal = LeaseJournal(Path(config.journal_directory))
    # Registration precedes controller execution; re-registration never renews
    # an expired/lost lease. Allocation-before-registration is still a provisioner obligation.
    for lease in config.leases:
        journal.register(lease, now=utc_now(), heartbeat_ttl=60)
    worker = RecoveryWorker(
        journal,
        AuthorityClient(Path(config.authority_socket)),
        ReceiptVerifier(
            readiness_keys={},
            cleanup_keys={config.authority_identity: public_key(config.cleanup_public_key)},
        ),
        cleanup_budget=45,
        claim_ttl=60,
    )
    stop = Event()
    previous = _signals(stop)
    try:
        worker.run(stop)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
