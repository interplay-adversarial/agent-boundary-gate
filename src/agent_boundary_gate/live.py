"""Explicit private composition for experimental live OpenShell boundary tests."""

import ipaddress
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Thread
from typing import Annotated
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, model_validator

from agent_boundary_gate.auth import digest
from agent_boundary_gate.backends.openshell import OpenShellBackend
from agent_boundary_gate.case_registry import replay_digest
from agent_boundary_gate.contracts import CaseSpec, Digest, Dispatch, Identifier
from agent_boundary_gate.doctor import read_regular_input
from agent_boundary_gate.evidence import EvidenceStore, bytes_digest
from agent_boundary_gate.gate_policy import EXIT_CODES, evaluate
from agent_boundary_gate.lifecycle import AttemptControl, run_attempt
from agent_boundary_gate.monitor import MonitorSession
from agent_boundary_gate.probe_delivery import DeliveryVerifier, RustProbeDeployment
from agent_boundary_gate.receipts import LeaseBinding, ReceiptContract, ReceiptVerifier
from agent_boundary_gate.recovery import ControllerLease, LeaseJournal
from agent_boundary_gate.reporting import operator_report
from agent_boundary_gate.rig_authority import AuthorityClient
from agent_boundary_gate.rig_receivers import RemoteDeniedEgressObserver

PublicKeyHex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Budget = Annotated[float, Field(gt=0, le=60, allow_inf_nan=False)]


class LiveConfig(ReceiptContract):
    """All values are trusted private inputs; none are learned from responses."""

    case_file: str
    dispatch: Dispatch
    lease: LeaseBinding
    deployment: RustProbeDeployment
    cli_executable: str
    cli_digest: Digest
    gateway: str
    sandbox: str
    policy_revision: Annotated[int, Field(gt=0)]
    authority_socket: str
    authority_identity: Identifier
    monitor_generation: Identifier
    readiness_public_key: PublicKeyHex
    cleanup_public_key: PublicKeyHex
    delivery_public_key: PublicKeyHex
    monitor_public_key: PublicKeyHex
    receiver_socket: str
    receiver_identity: Identifier
    receiver_generation: Identifier
    receiver_public_key: PublicKeyHex
    allowed_url: str
    forbidden_url: str
    journal_directory: str
    terminal_key_file: str
    terminal_identity: Identifier
    readiness_budget: Budget = 15.0
    cleanup_budget: Budget = 45.0

    @model_validator(mode="after")
    def bound(self):
        if (
            digest(self.dispatch.binding) != self.lease.binding_digest
            or self.dispatch.binding.run_id != self.lease.run_id
            or self.dispatch.binding.attempt_id != self.lease.attempt_id
            or self.dispatch.binding.effective_policy_digest != self.lease.effective_policy_digest
            or self.dispatch.binding.target_profile.boundary.id != "openshell"
            or self.dispatch.binding.target_profile.agent is not None
            or self.dispatch.exceptions
            or self.dispatch.deadline > self.lease.lease_expires_at
        ):
            raise ValueError("live-config-binding-mismatch")
        if self.allowed_url == self.forbidden_url:
            raise ValueError("distinct-receivers-required")
        for value in (self.allowed_url, self.forbidden_url):
            endpoint = urlsplit(value)
            ipaddress.ip_address(endpoint.hostname)
        return self


def read_private(path: Path, *, limit=65536) -> bytes:
    return read_regular_input(path, limit=limit, private=True)


def public_key(value: str):
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(value))


def live_run(config: LiveConfig, output: Path) -> tuple[dict, int]:
    config = LiveConfig.model_validate(config)
    case = CaseSpec.model_validate_json(read_regular_input(Path(config.case_file), limit=65536))
    if (
        len(config.dispatch.instances) != 1
        or config.dispatch.instances[0].case_spec_digest != digest(case)
        or case.replay_digest != replay_digest(case)
    ):
        raise ValueError("live-case-pin-mismatch")
    if datetime.now(UTC) >= config.dispatch.deadline:
        raise ValueError("dispatch-expired")
    if output.exists() or output.is_symlink():
        raise ValueError("new-evidence-directory-required")
    key = Ed25519PrivateKey.from_private_bytes(
        read_private(Path(config.terminal_key_file), limit=32)
    )
    cli_bytes = read_regular_input(Path(config.cli_executable), limit=64 * 1024 * 1024)
    if bytes_digest(cli_bytes) != config.cli_digest:
        raise ValueError("cli-pin-mismatch")
    store = EvidenceStore(output)
    journal = LeaseJournal(Path(config.journal_directory))
    authority = AuthorityClient(Path(config.authority_socket), store)
    receipt_verifier = ReceiptVerifier(
        readiness_keys={config.authority_identity: public_key(config.readiness_public_key)},
        cleanup_keys={config.authority_identity: public_key(config.cleanup_public_key)},
    )
    deadline = time.monotonic() + max(
        0, (config.dispatch.deadline - datetime.now(UTC)).total_seconds()
    )
    monitor = MonitorSession(
        lease=config.lease,
        identity=config.authority_identity,
        generation=config.monitor_generation,
        trusted_keys={config.authority_identity: public_key(config.monitor_public_key)},
        store=store,
    )
    control = AttemptControl(monitor)
    done = Event()

    def refresh():
        try:
            request = monitor.request()
            raw = authority.fetch(
                request, deadline=min(deadline, time.monotonic() + 3), cancelled=done
            )
            return monitor.accept(raw)
        except Exception:
            # Explicitly latch loss, including before the first handshake.
            monitor.accept(b"")
            return False

    def maintain():
        while not done.wait(1):
            if not refresh():
                control.cancelled.set()
                return

    refresh()
    thread = Thread(target=maintain, name="live-monitor-refresh")
    thread.start()
    try:
        # The CLI snapshot prevents replacement between digest checks and exec.
        with tempfile.TemporaryDirectory(prefix="gate-live-cli-") as directory:
            executable = Path(directory) / "openshell"
            executable.write_bytes(cli_bytes)
            executable.chmod(0o500)
            backend = OpenShellBackend(
                executable=executable,
                executable_digest=config.cli_digest,
                gateway=config.gateway,
                sandbox=config.sandbox,
                sandbox_uid=config.lease.component.instance_uid,
                policy_digest=config.lease.effective_policy_digest,
                policy_revision=config.policy_revision,
                lease=config.lease,
                receipt_provider=authority,
                receipt_verifier=receipt_verifier,
                probe_runtime="rust",
                rust_deployment=config.deployment,
                delivery_provider=authority,
                delivery_verifier=DeliveryVerifier(
                    {config.authority_identity: public_key(config.delivery_public_key)}
                ),
            )
            observer = RemoteDeniedEgressObserver(
                lease=config.lease,
                socket_path=Path(config.receiver_socket),
                endpoints={"allowed": config.allowed_url, "forbidden": config.forbidden_url},
                identity=config.receiver_identity,
                generation=config.receiver_generation,
                key=public_key(config.receiver_public_key),
                store=store,
                deadline=deadline,
                cancelled=control.cancelled,
            )
            record = run_attempt(
                config.dispatch,
                case,
                # OpenShellBackend deliberately narrows BoundaryBackend's Protocol-level
                # lease: LeaseBinding | None to a required LeaseBinding, and replay's
                # url: str | None to a required str: unlike the loopback/fixture
                # backend, a real OpenShell probe always has an authenticated lease and
                # a concrete receiver URL, and every method on this class already relies
                # on that without a None-guard. Widening either to satisfy the Protocol
                # would be the wrong direction -- it would weaken a real invariant, not
                # fix a bug. See backends/openshell.py's __init__/replay for where that
                # invariant is actually enforced.
                backend,  # type: ignore[arg-type]
                observer,
                store,
                key,
                config.terminal_identity,
                control,
                recovery=ControllerLease(journal, config.lease),
                readiness_budget=config.readiness_budget,
                cleanup_budget=config.cleanup_budget,
            )
    finally:
        done.set()
        thread.join(timeout=4)
    decision = evaluate(
        config.dispatch,
        [record],
        {config.terminal_identity: key.public_key()},
        now=datetime.now(UTC),
        job_complete=True,
        server_aggregate=record.result.invariant_held,
        evidence_store=store,
    )
    report = operator_report(decision, record)
    store.persist_json(
        {
            "mode": "experimental-live",
            "dispatch": config.dispatch.model_dump(mode="json"),
            "record": record.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json"),
            "report": report,
        }
    )
    return report, EXIT_CODES[decision.release_decision]
