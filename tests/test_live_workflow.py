"""Real host IPC/HTTP with explicitly synthetic target inspection and CLI behavior."""

import contextlib
import json
import socket
import struct
import sys
import tempfile
import time
import unittest
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from receipt_support import lease_and_binding

from agent_boundary_gate.auth import digest
from agent_boundary_gate.campaign import matches
from agent_boundary_gate.case_registry import load_case
from agent_boundary_gate.contracts import HttpGetAction
from agent_boundary_gate.evidence import EvidenceStore, bytes_digest
from agent_boundary_gate.fixtures import fixture
from agent_boundary_gate.live import LiveConfig, live_run, read_private
from agent_boundary_gate.monitor import MonitorSession
from agent_boundary_gate.probe_delivery import (
    DeliveryVerifier,
    RustProbeArtifact,
    RustProbeDeployment,
)
from agent_boundary_gate.process import AttemptStopped, bounded_process
from agent_boundary_gate.receipts import ReceiptVerifier
from agent_boundary_gate.recovery import LeaseJournal, RecoveryWorker
from agent_boundary_gate.reporting import operator_report
from agent_boundary_gate.rig_authority import (
    AuthorityClient,
    CellInspection,
    CellRegistration,
    InspectionRequest,
    InspectorCommand,
    RigAuthority,
)
from agent_boundary_gate.rig_receivers import ReceiverService, RemoteDeniedEgressObserver
from agent_boundary_gate.rig_transport import UnixClient, UnixService, receive_packet

ROOT = Path(__file__).resolve().parents[1]
D = "sha256:" + "a" * 64


class SyntheticInspector:
    def __init__(self, lease, deployment):
        self.lease, self.deployment = lease, deployment
        self.state = "ready"
        self.changes = {}
        self.requests = []

    def inspect(self, request, *, deadline, cancelled):
        self.requests.append(request)
        if request.operation == "destroy":
            self.state = "destroyed"
        return CellInspection(
            binding=self.lease,
            observed_at=datetime.now(UTC),
            state=self.state,
            outer_boundary_closed=True,
            workload_cannot_access_authority=True,
            watchdog_active=True,
            deployment=self.deployment,
            immutable_until=self.lease.lease_expires_at,
            executable_authorized=True,
        ).model_copy(update=self.changes)


@contextlib.contextmanager
def running(service):
    service.open()
    thread = Thread(target=service.run)
    thread.start()
    try:
        yield service
    finally:
        service.stop.set()
        thread.join(timeout=6)
        if thread.is_alive():
            raise AssertionError("service thread did not stop")


class LiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gate-live-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.lease, self.binding = lease_and_binding()
        self.deployment = RustProbeDeployment(
            artifact=RustProbeArtifact(
                target="x86_64-unknown-linux-musl",
                binary_digest=D,
                source_digest=D,
                manifest_digest=D,
            ),
            workload_image_digest=D,
        )
        self.keys = {
            purpose: Ed25519PrivateKey.generate()
            for purpose in ("readiness", "cleanup", "delivery", "monitor")
        }
        self.inspector = SyntheticInspector(self.lease, self.deployment)
        self.authority = RigAuthority(
            registrations=(CellRegistration(lease=self.lease, deployment=self.deployment),),
            inspector=self.inspector,
            identity="synthetic-authority",
            monitor_generation="monitor-1",
            keys=self.keys,
            store=EvidenceStore(self.root / "authority-evidence"),
        )
        self.verifier = ReceiptVerifier(
            readiness_keys={"synthetic-authority": self.keys["readiness"].public_key()},
            cleanup_keys={"synthetic-authority": self.keys["cleanup"].public_key()},
        )
        self.client = AuthorityClient(self.root / "authority.sock")

    def call(self, request):
        return self.authority.handle(
            request.model_dump_json().encode(), time.monotonic() + 2, Event()
        )

    def test_real_rpc_lifecycle_and_delivery_purpose_keys(self):
        with running(UnixService(self.root / "authority.sock", self.authority.handle)):
            for purpose in ("readiness", "cleanup"):
                request = self.verifier.request(purpose, self.lease)
                raw = self.client.fetch(request, deadline=time.monotonic() + 2, cancelled=Event())
                self.verifier.verify(raw, request=request, now=datetime.now(UTC))
                if purpose == "readiness":
                    delivery = DeliveryVerifier(
                        {"synthetic-authority": self.keys["delivery"].public_key()}
                    )
                    request = delivery.request(self.lease, self.deployment)
                    raw = self.client.fetch(
                        request, deadline=time.monotonic() + 2, cancelled=Event()
                    )
                    delivery.verify(raw, request=request, now=datetime.now(UTC))
        self.assertEqual(self.inspector.state, "destroyed")

    def test_unregistered_lease_and_wrong_deployment_never_inspected(self):
        request = self.verifier.request(
            "readiness", self.lease.model_copy(update={"cell_uid": "other"})
        )
        with self.assertRaises(ValueError):
            self.call(request)
        self.assertEqual(self.inspector.requests, [])
        verifier = DeliveryVerifier({})
        request = verifier.request(
            self.lease,
            self.deployment.model_copy(update={"workload_image_digest": "sha256:" + "b" * 64}),
        )
        with self.assertRaises(ValueError):
            self.call(request)
        self.assertEqual(self.inspector.requests, [])

    def test_inspection_freshness_identity_and_containment_fail_closed(self):
        request = self.verifier.request("readiness", self.lease)
        for changes in (
            {"state": "lost"},
            {"outer_boundary_closed": False},
            {"workload_cannot_access_authority": False},
            {"watchdog_active": False},
            {"binding": self.lease.model_copy(update={"cell_uid": "other"})},
            {"observed_at": datetime.now(UTC) - timedelta(seconds=10)},
            {"observed_at": datetime.now(UTC) + timedelta(seconds=10)},
        ):
            self.inspector.changes = changes
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.call(request)

    def test_mutable_or_unauthorized_delivery_rejected(self):
        request = DeliveryVerifier({}).request(self.lease, self.deployment)
        for changes in (
            {"immutable_until": datetime.now(UTC)},
            {"executable_authorized": False},
            {"deployment": None},
        ):
            self.inspector.changes = changes
            with self.assertRaises(ValueError):
                self.call(request)

    def test_monitor_incident_survives_authority_storage_loss(self):
        monitor = MonitorSession(
            lease=self.lease,
            identity="synthetic-authority",
            generation="monitor-1",
            trusted_keys={"synthetic-authority": self.keys["monitor"].public_key()},
            store=EvidenceStore(self.root / "monitor"),
        )
        self.inspector.state = "incident"
        with patch.object(self.authority.store, "persist", side_effect=OSError()):
            raw = self.call(monitor.request())
        self.assertFalse(monitor.accept(raw))
        self.assertTrue(monitor.snapshot().incident)

    def test_transport_timeout_cancellation_limit_and_private_socket(self):
        def delayed(raw, deadline, cancelled):
            cancelled.wait(0.2)
            return b"{}"

        with running(UnixService(self.root / "slow.sock", delayed)):
            client = UnixClient(self.root / "slow.sock")
            started = time.monotonic()
            with self.assertRaises(AttemptStopped):
                client.call(b"{}", deadline=started + 0.05, cancelled=Event())
            self.assertLess(time.monotonic() - started, 0.2)
            cancelled = Event()
            cancelled.set()
            with self.assertRaises(AttemptStopped):
                client.call(b"{}", deadline=time.monotonic() + 1, cancelled=cancelled)
            (self.root / "slow.sock").chmod(0o666)
            with self.assertRaises(ValueError):
                client.call(b"{}", deadline=time.monotonic() + 1, cancelled=Event())
        left, right = socket.socketpair()
        with left, right:
            right.sendall(struct.pack("!I", 65537))
            with self.assertRaises(ValueError):
                receive_packet(left, deadline=time.monotonic() + 1, cancelled=Event())

    def test_private_input_and_process_stdin(self):
        path = self.root / "input"
        path.write_bytes(b"private-data")
        with self.assertRaises(ValueError):
            read_private(path)
        path.chmod(0o600)
        self.assertEqual(read_private(path), b"private-data")
        result = bounded_process(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
            input_data=b"{}",
            deadline=time.monotonic() + 2,
            cancelled=Event(),
        )
        self.assertEqual(result.stdout, b"{}")
        with self.assertRaises(ValueError):
            bounded_process(
                [sys.executable],
                input_data=b"x" * 65537,
                deadline=time.monotonic() + 2,
                cancelled=Event(),
            )

    def receiver(self):
        key = Ed25519PrivateKey.generate()
        receiver = ReceiverService(
            leases=(self.lease,),
            identity="synthetic-receiver",
            generation="receiver-1",
            key=key,
            store=EvidenceStore(self.root / "receiver-evidence"),
            addresses={"allowed": ("127.0.0.1", 0), "forbidden": ("127.0.0.1", 0)},
        )
        receiver.start()
        self.addCleanup(receiver.stop)
        endpoints = {
            name: f"http://127.0.0.1:{server.server_port}/probe"
            for name, server in receiver.servers.items()
        }
        observer = RemoteDeniedEgressObserver(
            lease=self.lease,
            socket_path=self.root / "receiver.sock",
            endpoints=endpoints,
            identity="synthetic-receiver",
            generation="receiver-1",
            key=key.public_key(),
            store=EvidenceStore(self.root / "controller-evidence"),
            deadline=time.monotonic() + 15,
            cancelled=Event(),
        )
        return receiver, observer, key

    def send(self, observer, name):
        request = urllib.request.Request(
            observer.endpoints[name], headers={"X-Gate-Attempt": self.lease.attempt_id}
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            response.read(1)

    def test_signed_remote_receivers_pair_drain_and_no_restart(self):
        receiver, observer, _ = self.receiver()
        with running(UnixService(self.root / "receiver.sock", receiver.handle)):
            observer.start()
            self.send(observer, "allowed")
            self.assertTrue(
                observer.positive_control_observed(
                    HttpGetAction(
                        operation="http_get", path="/probe", receiver="allowed", timeout_seconds=1
                    )
                )
            )
            self.send(observer, "forbidden")
            observer.stop()
            observation = observer.observe(execution_valid=True)
            self.assertEqual(observation.outcome, "violation")
            self.assertTrue(observation.complete)
            self.assertTrue(observation.effects)
            with self.assertRaises(ValueError):
                observer.start()

    def test_receiver_binding_key_endpoint_tampering_rejected(self):
        receiver, observer, key = self.receiver()
        with running(UnixService(self.root / "receiver.sock", receiver.handle)):
            observer.key = Ed25519PrivateKey.generate().public_key()
            with self.assertRaises(InvalidSignature):
                observer.start()
            observer.key = key.public_key()
            observer.endpoints["forbidden"] = "http://127.0.0.1:1/probe"
            with self.assertRaises(ValueError):
                observer._call("sample")

    def test_forbidden_effect_survives_receiver_storage_failure(self):
        receiver, observer, _ = self.receiver()
        with running(UnixService(self.root / "receiver.sock", receiver.handle)):
            observer.start()
            with patch.object(receiver.store, "persist_json", side_effect=OSError()):
                with self.assertRaises(urllib.error.HTTPError):
                    self.send(observer, "forbidden")
            with patch.object(receiver.store, "persist", side_effect=OSError()):
                observer.stop()
            observation = observer.observe(execution_valid=False)
            self.assertEqual(observation.outcome, "violation")
            self.assertFalse(observation.complete)

    def config(self, observer, *, weakened=False, suppress_allowed=False):
        case = load_case(ROOT / "examples/denied-egress-live-v1.json")
        dispatch = fixture("healthy")[0]
        instance = dispatch.instances[0].model_copy(
            update={
                "case_spec_digest": digest(case),
                "case_id": case.id,
                "observer_version": case.observer_version,
            }
        )
        dispatch = dispatch.model_copy(
            update={
                "binding": self.binding,
                "instances": (instance,),
                "deadline": datetime.now(UTC) + timedelta(seconds=30),
            }
        )
        self.lease = self.lease.model_copy(update={"binding_digest": digest(self.binding)})
        cli = self.root / "synthetic-cli"
        allowed_port = int(observer.endpoints["allowed"].split(":")[2].split("/")[0])
        # Explicit synthetic OpenShell behavior, no real deployment claim.
        cli.write_text(
            f"#!{sys.executable}\n"
            + f"""
import json, sys, urllib.request
args = sys.argv
if "get" in args and "sandbox" in args:
    print(json.dumps({{"id": "sandbox-1", "phase": "Ready"}}))
elif "get" in args and "policy" in args:
    print(json.dumps({{"sandbox": "gate-synthetic", "status": "loaded", "version": 2,
                       "active_version": 2, "hash": {self.lease.effective_policy_digest!r}}}))
elif "exec" in args:
    host, port, attempt, timeout = args[-4:]
    if not {suppress_allowed!r} and ({weakened!r} or int(port) == {allowed_port}):
        request = urllib.request.Request("http://" + host + ":" + port + "/probe",
                    headers={{"X-Gate-Attempt": attempt}})
        with urllib.request.urlopen(request, timeout=2) as response:
            response.read(1)
    print("agent-boundary-gate-probe-complete:" + attempt)
elif "delete" in args:
    pass
else:
    sys.exit(2)
"""
        )
        cli.chmod(0o500)
        key_file = self.root / "terminal-key"
        key_file.write_bytes(Ed25519PrivateKey.generate().private_bytes_raw())
        key_file.chmod(0o600)
        return LiveConfig(
            case_file=str(ROOT / "examples/denied-egress-live-v1.json"),
            dispatch=dispatch,
            lease=self.lease,
            deployment=self.deployment,
            cli_executable=str(cli),
            cli_digest=bytes_digest(cli.read_bytes()),
            gateway="synthetic",
            sandbox="gate-synthetic",
            policy_revision=2,
            authority_socket=str(self.root / "authority.sock"),
            authority_identity="synthetic-authority",
            monitor_generation="monitor-1",
            **{
                purpose + "_public_key": key.public_key().public_bytes_raw().hex()
                for purpose, key in self.keys.items()
            },
            receiver_socket=str(self.root / "receiver.sock"),
            receiver_identity="synthetic-receiver",
            receiver_generation="receiver-1",
            receiver_public_key=observer.key.public_bytes_raw().hex(),
            allowed_url=observer.endpoints["allowed"],
            forbidden_url=observer.endpoints["forbidden"],
            journal_directory=str(self.root / "journal"),
            terminal_key_file=str(key_file),
            terminal_identity="synthetic-terminal",
        )

    def test_full_live_composition_with_synthetic_target_healthy(self):
        receiver, observer, _ = self.receiver()
        config = self.config(observer)
        with (
            running(UnixService(self.root / "authority.sock", self.authority.handle)),
            running(UnixService(self.root / "receiver.sock", receiver.handle)),
        ):
            report, code = live_run(config, self.root / "run")
        self.assertEqual(code, 0, report)
        self.assertTrue(matches("healthy", report), report)
        self.assertEqual(self.inspector.state, "destroyed")

    def test_full_live_composition_with_synthetic_target_weakened(self):
        receiver, observer, _ = self.receiver()
        config = self.config(observer, weakened=True)
        with (
            running(UnixService(self.root / "authority.sock", self.authority.handle)),
            running(UnixService(self.root / "receiver.sock", receiver.handle)),
        ):
            report, code = live_run(config, self.root / "run")
        self.assertEqual(code, 1, report)
        self.assertTrue(matches("weakened", report), report)

    def test_reports_never_echo_supplied_identifiers_or_diagnostics(self):
        dispatch, record, _ = fixture("healthy")
        from agent_boundary_gate.gate_policy import evaluate

        decision = evaluate(
            dispatch, [record], {}, now=datetime.now(UTC), job_complete=True, server_aggregate=None
        )
        decision = decision.model_copy(
            update={
                "decision_reasons": ("private-sentinel",),
                "confirmed_violations": ("private-sentinel",),
            }
        )
        record = record.model_copy(
            update={
                "result": record.result.model_copy(
                    update={"run_status_reasons": ("private-sentinel",)}
                )
            }
        )
        report = operator_report(decision, record)
        self.assertNotIn("private-sentinel", json.dumps(report))
        self.assertFalse(report["release_eligible"])

    def test_pinned_inspector_executes_snapshot_not_unverified_command(self):
        command = InspectorCommand(executable=str(self.root / "missing"), executable_digest=D)
        with self.assertRaises(OSError):
            command.inspect(
                self.inspector.requests[0] if self.inspector.requests else None,
                deadline=time.monotonic() + 1,
                cancelled=Event(),
            )

    def test_pinned_inspector_consumes_stdin_and_rejects_changed_bytes(self):
        executable = self.root / "inspector"
        script = (
            f"#!{sys.executable}\n" + "import json,sys\n"
            "from datetime import UTC, datetime\n"
            "request=json.load(sys.stdin)\n"
            "print(json.dumps(dict(binding=request['binding'],"
            "observed_at=datetime.now(UTC).isoformat(),"
            "state='lost',outer_boundary_closed=False,"
            "workload_cannot_access_authority=False,watchdog_active=False)))\n"
        )
        executable.write_text(script)
        command = InspectorCommand(
            executable=str(executable), executable_digest=bytes_digest(executable.read_bytes())
        )
        request = InspectionRequest(operation="inspect", binding=self.lease)
        result = command.inspect(request, deadline=time.monotonic() + 2, cancelled=Event())
        self.assertEqual(result.state, "lost")
        self.assertEqual(result.binding, self.lease)
        executable.write_text(script + "# changed\n")
        with self.assertRaises(ValueError):
            command.inspect(request, deadline=time.monotonic() + 2, cancelled=Event())

    def test_full_live_composition_missing_positive_control_is_inconclusive(self):
        receiver, observer, _ = self.receiver()
        config = self.config(observer, suppress_allowed=True)
        with (
            running(UnixService(self.root / "authority.sock", self.authority.handle)),
            running(UnixService(self.root / "receiver.sock", receiver.handle)),
        ):
            report, code = live_run(config, self.root / "run")
        self.assertEqual(code, 2, report)
        self.assertTrue(matches("positive-control-loss", report), report)

    def test_unknown_monitor_cannot_start_replay_and_cleanup_still_runs(self):
        receiver, observer, _ = self.receiver()
        config = self.config(observer)
        self.inspector.changes = {"watchdog_active": False}
        with (
            running(UnixService(self.root / "authority.sock", self.authority.handle)),
            running(UnixService(self.root / "receiver.sock", receiver.handle)),
        ):
            report, code = live_run(config, self.root / "run")
        self.assertEqual(code, 2, report)
        self.assertEqual(receiver.counts, {"allowed": 0, "forbidden": 0})
        self.assertEqual(report["cleanup"], "destroyed")

    def test_real_cleanup_rpc_reconciles_controller_loss_and_reopens_after_expiry(self):
        journal = LeaseJournal(self.root / "recovery")
        now = datetime.now(UTC)
        journal.register(self.lease, now=now, heartbeat_ttl=1)
        worker = RecoveryWorker(
            journal, self.client, self.verifier, clock=lambda: now + timedelta(seconds=2)
        )
        with running(UnixService(self.root / "authority.sock", self.authority.handle)):
            self.assertEqual(worker.step(), "destroyed")
        reopened = LeaseJournal(self.root / "recovery")
        reopened.register(self.lease, now=self.lease.lease_expires_at + timedelta(seconds=1))
        self.assertEqual(reopened.inspect(self.lease.lease_id)["state"], "destroyed")
        self.assertEqual(self.inspector.state, "destroyed")

    def test_receiver_schema_is_frozen(self):
        from agent_boundary_gate.rig_receivers import SignedCaptureSnapshot

        self.assertEqual(
            SignedCaptureSnapshot.model_json_schema(),
            json.loads(
                (ROOT / "schemas/receiver-snapshot/1.0/signed-receiver-snapshot.json").read_text()
            ),
        )

    def test_monitor_coverage_is_not_starved_by_slow_whole_cell_cleanup(self):
        destroying, release = Event(), Event()
        original = self.inspector.inspect

        def inspect(request, *, deadline, cancelled):
            if request.operation == "destroy":
                destroying.set()
                release.wait(2)
            if request.operation == "monitor" and destroying.is_set():
                self.inspector.state = "contained"
            return original(request, deadline=deadline, cancelled=cancelled)

        monitor = MonitorSession(
            lease=self.lease,
            identity="synthetic-authority",
            generation="monitor-1",
            trusted_keys={"synthetic-authority": self.keys["monitor"].public_key()},
            store=EvidenceStore(self.root / "monitor"),
        )
        cleanup_results = []
        with (
            patch.object(self.inspector, "inspect", side_effect=inspect),
            running(UnixService(self.root / "authority.sock", self.authority.handle)),
        ):
            request = self.verifier.request("cleanup", self.lease)
            worker = Thread(
                target=lambda: cleanup_results.append(
                    self.client.destroy(request, deadline=time.monotonic() + 3, cancelled=Event())
                )
            )
            worker.start()
            try:
                self.assertTrue(destroying.wait(1))
                raw = self.client.fetch(
                    monitor.request(), deadline=time.monotonic() + 0.5, cancelled=Event()
                )
                self.assertTrue(monitor.accept(raw))
            finally:
                release.set()
                worker.join(timeout=3)
        self.assertEqual(len(cleanup_results), 1)

    def test_capture_counter_limit_keeps_violation_but_withholds_completeness(self):
        receiver, observer, _ = self.receiver()
        with running(UnixService(self.root / "receiver.sock", receiver.handle)):
            observer.start()
            receiver.counts["allowed"] = 1000
            with self.assertRaises(urllib.error.HTTPError):
                self.send(observer, "forbidden")
            observer.stop()
            observation = observer.observe(execution_valid=True)
        self.assertEqual(observation.outcome, "violation")
        self.assertFalse(observation.complete)

    def test_image_context_preparation_verifies_bytes_and_rolls_back_bad_inputs(self):
        from test_probe_delivery import StagingTests

        from scripts.prepare_owned_image import prepare

        fixture_inputs = StagingTests()
        fixture_inputs.setUp()
        self.addCleanup(fixture_inputs.doCleanups)
        destination = self.root / "image"
        arguments = dict(
            binary=fixture_inputs.binary,
            manifest=fixture_inputs.manifest,
            pins=fixture_inputs.pins,
            base_image="example/image@sha256:" + "a" * 64,
        )
        report = prepare(destination=destination, **arguments)
        self.assertFalse(report["release_eligible"])
        self.assertEqual(
            (destination / "probe/gate-http-probe").read_bytes(), fixture_inputs.binary.read_bytes()
        )
        self.assertIn("probe/*", (destination / ".dockerignore").read_text())
        fixture_inputs.binary.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            prepare(destination=self.root / "bad-image", **arguments)
        self.assertFalse((self.root / "bad-image").exists())

    def test_owned_image_context_rejects_mutable_base_and_never_overwrites(self):
        from scripts.prepare_owned_image import prepare

        arguments = dict(
            binary=self.root / "missing",
            manifest=self.root / "missing",
            pins=self.deployment.artifact,
            destination=self.root / "image",
        )
        for base in ("example/image:latest", "example/image@sha256:" + "a" * 64 + "\nRUN unsafe"):
            with self.assertRaises(ValueError):
                prepare(base_image=base, **arguments)
        self.assertFalse((self.root / "image").exists())
        (self.root / "image").mkdir()
        with self.assertRaises(FileExistsError):
            prepare(base_image="example/image@sha256:" + "a" * 64, **arguments)
        self.assertTrue((self.root / "image").is_dir())

    def test_forbidden_effect_during_cleanup_window_is_retained(self):
        receiver, observer, _ = self.receiver()
        with running(UnixService(self.root / "receiver.sock", receiver.handle)):
            observer.start()
            self.send(observer, "allowed")
            observer.stop()
            self.send(observer, "forbidden")
            observation = observer.observe(execution_valid=True)
        self.assertEqual(observation.outcome, "violation")
        self.assertTrue(observation.effects)
        self.assertTrue(observation.complete)

    def test_receiver_thread_start_failure_closes_bound_socket(self):
        receiver = ReceiverService(
            leases=(self.lease,),
            identity="synthetic-receiver",
            generation="receiver-1",
            key=Ed25519PrivateKey.generate(),
            store=EvidenceStore(self.root / "receiver-start-failed"),
            addresses={"allowed": ("127.0.0.1", 0), "forbidden": ("127.0.0.1", 0)},
        )
        with patch(
            "agent_boundary_gate.rig_receivers.threading.Thread.start",
            side_effect=RuntimeError("synthetic-resource-exhaustion"),
        ):
            with self.assertRaises(RuntimeError):
                receiver.start()
        self.assertTrue(all(server.fileno() < 0 for server in receiver.servers.values()))
