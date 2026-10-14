"""Real service/watchdog death and restart with explicitly synthetic cell inventory."""

import json
import os
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from receipt_support import lease_and_binding

from agent_boundary_gate.auth import authenticate, digest
from agent_boundary_gate.backends import Readiness
from agent_boundary_gate.case_registry import load_case
from agent_boundary_gate.evidence import EvidenceStore, bytes_digest, json_bytes
from agent_boundary_gate.fixtures import fixture
from agent_boundary_gate.gate_policy import evaluate
from agent_boundary_gate.host_services import AuthorityConfig, ReceiverConfig, WatchdogConfig
from agent_boundary_gate.lifecycle import AttemptControl, run_attempt
from agent_boundary_gate.monitor import MonitorSession
from agent_boundary_gate.probe_delivery import RustProbeArtifact, RustProbeDeployment
from agent_boundary_gate.process import AttemptStopped
from agent_boundary_gate.receipts import ReceiptVerifier, SignedLifecycleReceipt
from agent_boundary_gate.recovery import ControllerLease, LeaseJournal, RecoveryClaim
from agent_boundary_gate.rig_authority import AuthorityClient, CellRegistration, InspectorCommand
from agent_boundary_gate.rig_receivers import RemoteDeniedEgressObserver

ROOT = Path(__file__).resolve().parents[1]


class ServiceWatchdogDrills(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gate-svc-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.children = []
        self.socket_inodes = {}
        # Release blocked inspectors before graceful service cancellation. Each
        # owned process has its own group; no arbitrary host PID is selected.
        self.addCleanup(self.stop_children)
        self.lease, self.binding = lease_and_binding()
        self.keys = {
            purpose: Ed25519PrivateKey.generate()
            for purpose in ("readiness", "cleanup", "delivery", "monitor", "receiver")
        }
        self.key_paths = {}
        for purpose, key in self.keys.items():
            path = self.root / (purpose + ".key")
            self.private_write(path, key.private_bytes_raw())
            self.key_paths[purpose] = str(path)
        self.inventory = self.root / "inventory.json"
        self.save_inventory(
            state="ready",
            cleanup_calls=0,
            current_cell_uid=self.lease.cell_uid,
            binding=self.lease.model_dump(mode="json"),
        )
        inspector = self.root / "inspector"
        self.private_write(
            inspector,
            f"#!{sys.executable}\n".encode()
            + (ROOT / "tests/service_drill_inspector.py").read_bytes(),
        )
        pin = bytes_digest(inspector.read_bytes())
        command = InspectorCommand(executable=str(inspector), executable_digest=pin)
        artifact_pin = "sha256:" + "a" * 64
        deployment = RustProbeDeployment(
            artifact=RustProbeArtifact(
                target="x86_64-unknown-linux-musl",
                binary_digest=artifact_pin,
                source_digest=artifact_pin,
                manifest_digest=artifact_pin,
            ),
            workload_image_digest=artifact_pin,
        )
        self.authority_config = AuthorityConfig(
            socket_path=str(self.root / "a.sock"),
            registrations=(CellRegistration(lease=self.lease, deployment=deployment),),
            inspector=command,
            monitor_inspector=command.model_copy(),
            identity="synthetic-authority",
            monitor_generation="monitor-1",
            readiness_key_file=self.key_paths["readiness"],
            cleanup_key_file=self.key_paths["cleanup"],
            delivery_key_file=self.key_paths["delivery"],
            monitor_key_file=self.key_paths["monitor"],
            evidence_directory=str(self.root / "authority-evidence"),
        )
        self.verifier = ReceiptVerifier(
            readiness_keys={"synthetic-authority": self.keys["readiness"].public_key()},
            cleanup_keys={"synthetic-authority": self.keys["cleanup"].public_key()},
        )
        self.client = AuthorityClient(Path(self.authority_config.socket_path))
        self.journal = LeaseJournal(self.root / "journal")
        self.fault = self.root / "write-fault"
        self.watchdog_config = WatchdogConfig(
            authority_socket=self.authority_config.socket_path,
            authority_identity="synthetic-authority",
            cleanup_public_key=self.keys["cleanup"].public_key().public_bytes_raw().hex(),
            journal_directory=str(self.journal.store.root),
            leases=(self.lease,),
            heartbeat_ttl=0.15,
            cleanup_budget=0.6,
            claim_ttl=1.2,
            retry_delay=0.05,
            poll_interval=0.02,
        )

    @staticmethod
    def private_write(path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)

    def save_inventory(self, **changes):
        current = json.loads(self.inventory.read_text()) if self.inventory.exists() else {}
        temporary = self.root / "parent-inventory.new"
        self.private_write(temporary, json_bytes(current | changes))
        temporary.replace(self.inventory)

    def wait(self, predicate, *, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = predicate()
            if result:
                return result
            time.sleep(0.01)
        self.fail("synthetic-service-checkpoint-timeout")

    def launch(self, command, config, *, fault_injection=False):
        path = self.root / (command + ".json")
        self.private_write(path, config.model_dump_json().encode())
        environment = os.environ.copy()
        environment.update(
            PYTHONPATH=str(ROOT / "src"),
            GATE_DRILL_INVENTORY=str(self.root),
            GATE_DRILL_JOURNAL=str(self.journal.store.root),
            GATE_DRILL_WRITE_FAULT=str(self.fault),
        )
        entry = (
            [str(ROOT / "tests/service_drill_worker.py")]
            if fault_injection
            else ["-m", "agent_boundary_gate.cli"]
        )
        child = subprocess.Popen(
            [sys.executable, *entry, command, "--config", str(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=environment,
        )
        self.children.append(child)
        return child

    def stop_child(self, child, *, abrupt=False):
        if child.poll() is not None:
            return
        os.killpg(child.pid, signal.SIGCONT)
        os.killpg(child.pid, signal.SIGKILL if abrupt else signal.SIGTERM)
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=2)
            self.fail("owned-service-did-not-stop-cooperatively")

    def stop_children(self):
        (self.root / "block-cleanup").unlink(missing_ok=True)
        errors = []
        for child in reversed(self.children):
            try:
                self.stop_child(child)
            except AssertionError as error:
                errors.append(error)
        if errors:
            raise errors[0]

    def socket_ready(self, path, child):
        self.assertIsNone(child.poll(), "synthetic-service-exited-before-admission")
        if not path.exists():
            return False
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(0.05)
                connection.connect(str(path))
            metadata = path.lstat()
            self.socket_inodes[(path, child.pid)] = (metadata.st_dev, metadata.st_ino)
            return True
        except (ConnectionRefusedError, FileNotFoundError):
            return False

    def authority(self):
        child = self.launch("authority-serve", self.authority_config)
        self.wait(lambda: self.socket_ready(Path(self.authority_config.socket_path), child))
        return child

    def reconcile_socket(self, path, child):
        # Fixture-owner reconciliation only after wait/reap. Never auto-delete
        # a live service or a non-socket/replacement path.
        self.assertIsNotNone(child.poll())
        metadata = path.lstat()
        self.assertTrue(stat.S_ISSOCK(metadata.st_mode))
        self.assertEqual(metadata.st_uid, os.geteuid())
        self.assertEqual((metadata.st_dev, metadata.st_ino), self.socket_inodes[(path, child.pid)])
        path.unlink()

    def monitor(self, *, monotonic=time.monotonic):
        monitor = MonitorSession(
            lease=self.lease,
            identity="synthetic-authority",
            generation="monitor-1",
            trusted_keys={"synthetic-authority": self.keys["monitor"].public_key()},
            store=EvidenceStore(self.root / "monitor-evidence"),
            monotonic=monotonic,
        )
        self.refresh(monitor)
        self.assertTrue(monitor.snapshot().healthy)
        return monitor

    def refresh(self, monitor, *, timeout=2):
        request = monitor.request()
        try:
            raw = self.client.fetch(request, deadline=time.monotonic() + timeout, cancelled=Event())
        except (OSError, ValueError, AttemptStopped):
            raw = b""
        return monitor.accept(raw)

    def receiver(self):
        sockets = [socket.socket(), socket.socket()]
        try:
            for connection in sockets:
                connection.bind(("127.0.0.1", 0))
            ports = [connection.getsockname()[1] for connection in sockets]
        finally:
            for connection in sockets:
                connection.close()
        config = ReceiverConfig(
            socket_path=str(self.root / "r.sock"),
            leases=(self.lease,),
            identity="synthetic-receiver",
            generation="receiver-1",
            key_file=self.key_paths["receiver"],
            evidence_directory=str(self.root / "receiver-evidence"),
            bind_host="127.0.0.1",
            advertise_host="127.0.0.1",
            allowed_port=ports[0],
            forbidden_port=ports[1],
        )
        child = self.launch("receiver-serve", config)
        self.wait(lambda: self.socket_ready(Path(config.socket_path), child))
        observer = RemoteDeniedEgressObserver(
            lease=self.lease,
            socket_path=Path(config.socket_path),
            endpoints={
                name: f"http://127.0.0.1:{port}/probe"
                for name, port in zip(("allowed", "forbidden"), ports, strict=True)
            },
            identity=config.identity,
            generation=config.generation,
            key=self.keys["receiver"].public_key(),
            store=EvidenceStore(self.root / "observer-evidence"),
            deadline=time.monotonic() + 15,
            cancelled=Event(),
        )
        return child, observer, config

    def send(self, observer, name):
        request = urllib.request.Request(
            observer.endpoints[name], headers={"X-Gate-Attempt": self.lease.attempt_id}
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=1) as response:
            self.assertEqual(response.status, 204)

    def register_due(self):
        self.journal.register(
            self.lease, now=datetime.now(UTC) - timedelta(seconds=1), heartbeat_ttl=0.15
        )

    def destroyed(self):
        return self.journal.inspect(self.lease.lease_id)["state"] == "destroyed"

    def assert_cleanup_proof(self):
        state = self.journal.inspect(self.lease.lease_id)
        self.assertEqual(state["state"], "destroyed")
        raw = self.journal.store.read(state["receipt_ref"])
        signed = SignedLifecycleReceipt.model_validate_json(raw)
        self.verifier.verify(raw, request=signed.receipt.request, now=datetime.now(UTC))
        self.assertEqual(signed.receipt.request.binding, self.lease)
        self.assertEqual(signed.receipt.claim.state, "destroyed")
        self.assertEqual(
            json.loads(self.inventory.read_text())["current_cell_uid"], self.lease.cell_uid
        )
        return state

    def test_watchdog_budgets_keep_defaults_and_reject_unbounded_claims(self):
        names = ("heartbeat_ttl", "cleanup_budget", "claim_ttl", "retry_delay", "poll_interval")
        original_config = self.watchdog_config.model_dump(mode="json")
        for name in names:
            original_config.pop(name)
        parsed = WatchdogConfig.model_validate_json(json_bytes(original_config))
        fields = {name: getattr(parsed, name) for name in names}
        self.assertEqual(
            fields,
            dict(
                heartbeat_ttl=60.0,
                cleanup_budget=45.0,
                claim_ttl=60.0,
                retry_delay=5.0,
                poll_interval=1.0,
            ),
        )
        values = self.watchdog_config.model_dump()
        for name in fields:
            for value in (0.0, -1.0, float("inf"), float("nan"), 61.0, True):
                with self.subTest(name=name, value=value), self.assertRaises(ValidationError):
                    WatchdogConfig.model_validate(values | {name: value})
        with self.assertRaises(ValidationError):
            WatchdogConfig.model_validate(values | {"cleanup_budget": 1.2})

    def test_authority_death_and_new_generation_cannot_heal_monitor_loss(self):
        child = self.authority()
        monitor = self.monitor()
        references = monitor.snapshot().heartbeat_refs
        self.stop_child(child, abrupt=True)
        self.assertFalse(self.refresh(monitor))
        self.assertEqual(monitor.snapshot().state, "lost")
        refused = self.launch("authority-serve", self.authority_config)
        self.wait(lambda: refused.poll() is not None)
        self.assertNotEqual(refused.returncode, 0)
        self.reconcile_socket(Path(self.authority_config.socket_path), child)
        self.authority_config = self.authority_config.model_copy(
            update={"monitor_generation": "monitor-2"}
        )
        self.authority()
        self.assertFalse(self.refresh(monitor))
        self.assertEqual(monitor.snapshot().heartbeat_refs, references)

    def test_suspended_authority_obeys_client_deadline_and_loss_stays_latched(self):
        child = self.authority()
        monitor = self.monitor()
        os.killpg(child.pid, signal.SIGSTOP)
        started = time.monotonic()
        self.assertFalse(self.refresh(monitor, timeout=0.15))
        self.assertLess(time.monotonic() - started, 1)
        os.killpg(child.pid, signal.SIGCONT)
        self.assertFalse(self.refresh(monitor))
        self.assertEqual(monitor.snapshot().state, "lost")

    def test_signed_heartbeat_expiry_is_terminal_after_authority_recovers(self):
        self.authority()
        clock = [time.monotonic()]
        monitor = self.monitor(monotonic=lambda: clock[0])
        clock[0] += 9
        self.assertEqual(monitor.snapshot().state, "lost")
        self.assertFalse(self.refresh(monitor))
        self.assertEqual(monitor.snapshot().state, "lost")

    def test_suspended_receiver_cannot_turn_capture_gap_into_held(self):
        child, observer, _ = self.receiver()
        observer.start()
        self.send(observer, "allowed")
        observer._call("sample")
        os.killpg(child.pid, signal.SIGSTOP)
        observer.deadline = time.monotonic() + 0.15
        action = load_case(ROOT / "examples/denied-egress-live-v1.json").actions[0]
        self.assertFalse(observer.positive_control_observed(action))
        os.killpg(child.pid, signal.SIGCONT)
        observation = observer.observe(execution_valid=True)
        self.assertFalse(observation.complete)
        self.assertEqual(observation.positive_control, "passed")
        self.assertEqual(observation.outcome, "unknown")

    def test_receiver_restart_generation_rejects_prior_capture_and_retains_effects(self):
        child, observer, config = self.receiver()
        observer.start()
        self.send(observer, "forbidden")
        observer._call("sample")
        effects = set(observer.effects)
        self.stop_child(child, abrupt=True)
        self.reconcile_socket(Path(config.socket_path), child)
        replacement = self.launch(
            "receiver-serve", config.model_copy(update={"generation": "receiver-2"})
        )
        self.wait(lambda: self.socket_ready(Path(config.socket_path), replacement))
        with self.assertRaisesRegex(ValueError, "receiver-snapshot-rejected"):
            observer.start()
        observation = observer.observe(execution_valid=True)
        self.assertFalse(observation.complete)
        self.assertEqual(observation.outcome, "violation")
        self.assertEqual(set(observation.effects), effects)

    def test_watchdog_without_controller_recovers_due_lease_with_signed_proof(self):
        self.authority()
        self.register_due()
        child = self.launch("watchdog", self.watchdog_config)
        self.wait(self.destroyed)
        self.assertIsNone(child.poll())
        self.assertEqual(self.assert_cleanup_proof()["attempts"], 1)
        self.assertFalse(self.journal.heartbeat(self.lease, now=datetime.now(UTC)))

    def test_blocked_cleanup_keeps_monitor_live_and_sigterm_reaps_inspector(self):
        authority = self.authority()
        self.register_due()
        (self.root / "block-cleanup").touch()
        self.launch(
            "watchdog",
            self.watchdog_config.model_copy(update={"cleanup_budget": 2.0, "claim_ttl": 3.0}),
        )
        entered = self.root / "cleanup-entered.json"
        self.wait(entered.exists)
        inspector_pid = json.loads(entered.read_text())["pid"]
        monitor = self.monitor()
        self.assertTrue(monitor.snapshot().healthy)
        os.kill(inspector_pid, 0)
        self.stop_child(authority)
        with self.assertRaises(ProcessLookupError):
            os.kill(inspector_pid, 0)
        self.assertFalse(self.refresh(monitor))
        self.assertFalse(self.destroyed())
        self.assertIsNone(self.journal.inspect(self.lease.lease_id)["receipt_ref"])

    def test_absolute_expiry_triggers_real_watchdog_despite_long_heartbeat_ttl(self):
        self.lease = self.lease.model_copy(
            update={"lease_expires_at": datetime.now(UTC) + timedelta(seconds=1.5)}
        )
        self.save_inventory(binding=self.lease.model_dump(mode="json"))
        entry = self.authority_config.registrations[0].model_copy(update={"lease": self.lease})
        self.authority_config = self.authority_config.model_copy(update={"registrations": (entry,)})
        self.watchdog_config = self.watchdog_config.model_copy(
            update={"leases": (self.lease,), "heartbeat_ttl": 10.0}
        )
        self.journal.register(self.lease, now=datetime.now(UTC), heartbeat_ttl=10)
        self.authority()
        self.launch("watchdog", self.watchdog_config)
        self.wait(self.destroyed)
        self.assert_cleanup_proof()

    def test_worker_sigkill_claim_expires_and_restart_rejects_old_owner(self):
        self.authority()
        self.register_due()
        block = self.root / "block-cleanup"
        block.touch()
        old_worker = self.launch("watchdog", self.watchdog_config)
        self.wait(lambda: (self.root / "cleanup-entered.json").exists())
        with sqlite3.connect(self.journal.path) as connection:
            token = connection.execute("SELECT claim_token FROM leases").fetchone()[0]
        self.stop_child(old_worker, abrupt=True)
        block.unlink()
        self.wait(lambda: json.loads(self.inventory.read_text())["state"] == "destroyed")
        self.assertEqual(self.journal.inspect(self.lease.lease_id)["state"], "recovering")
        self.assertIsNone(self.journal.inspect(self.lease.lease_id)["receipt_ref"])
        self.launch("watchdog", self.watchdog_config)
        self.wait(self.destroyed)
        state = self.assert_cleanup_proof()
        self.assertEqual(state["attempts"], 2)
        old = RecoveryClaim(self.lease, token, "controller-lost")
        self.assertFalse(
            self.journal._finish(old, now=datetime.now(UTC), receipt_ref=state["receipt_ref"])
        )
        self.assertGreaterEqual(json.loads(self.inventory.read_text())["cleanup_calls"], 2)

    def test_replacement_uid_cannot_be_deleted_or_confirm_original_cleanup(self):
        self.authority()
        self.register_due()
        self.save_inventory(current_cell_uid="synthetic-replacement")
        self.launch("watchdog", self.watchdog_config)
        self.wait(lambda: self.journal.inspect(self.lease.lease_id)["attempts"] >= 2)
        state = self.journal.inspect(self.lease.lease_id)
        self.assertNotEqual(state["state"], "destroyed")
        self.assertIsNone(state["receipt_ref"])
        self.assertEqual(json.loads(self.inventory.read_text())["cleanup_calls"], 0)
        self.save_inventory(current_cell_uid=self.lease.cell_uid)
        self.wait(self.destroyed)
        self.assert_cleanup_proof()

    def test_authority_storage_outage_withholds_receipts_then_recovery_retries(self):
        self.authority()
        self.register_due()
        directory = Path(self.authority_config.evidence_directory)
        saved = self.root / "saved-authority-evidence"
        directory.rename(saved)
        self.private_write(directory, b"synthetic-filesystem-obstruction")
        self.launch("watchdog", self.watchdog_config)
        self.wait(lambda: self.journal.inspect(self.lease.lease_id)["attempts"] >= 2)
        self.assertFalse(self.destroyed())
        self.assertIsNone(self.journal.inspect(self.lease.lease_id)["receipt_ref"])
        self.assertEqual(json.loads(self.inventory.read_text())["state"], "destroyed")
        directory.unlink()
        saved.rename(directory)
        self.wait(self.destroyed)
        self.assert_cleanup_proof()

    def test_receipt_write_failure_never_confirms_until_durable_retry(self):
        self.authority()
        self.register_due()
        self.fault.write_text("receipt")
        self.launch("watchdog", self.watchdog_config, fault_injection=True)
        self.wait(lambda: self.journal.inspect(self.lease.lease_id)["attempts"] >= 2)
        self.assertFalse(self.destroyed())
        self.assertIsNone(self.journal.inspect(self.lease.lease_id)["receipt_ref"])
        self.fault.unlink()
        self.wait(self.destroyed)
        self.assert_cleanup_proof()

    def test_journal_commit_failure_exits_and_restart_recovers_unconfirmed_proof(self):
        self.authority()
        self.register_due()
        self.fault.write_text("finish")
        child = self.launch("watchdog", self.watchdog_config, fault_injection=True)
        self.wait(lambda: child.poll() is not None)
        self.assertNotEqual(child.returncode, 0)
        self.assertEqual(self.journal.inspect(self.lease.lease_id)["state"], "recovering")
        self.assertIsNone(self.journal.inspect(self.lease.lease_id)["receipt_ref"])
        self.assertTrue(list(self.journal.store.root.glob("*.json")))
        self.fault.unlink()
        self.launch("watchdog", self.watchdog_config)
        self.wait(self.destroyed)
        self.assertEqual(self.assert_cleanup_proof()["attempts"], 2)

    def terminal_after_service_death(self, victim):
        authority = self.authority()
        receiver, observer, _ = self.receiver()
        monitor = self.monitor()
        control = AttemptControl(monitor)
        owner = self

        class SyntheticBoundary:
            backend_id = "openshell"
            capabilities = frozenset({"network-egress"})
            lease = owner.lease

            def require_binding(self, binding):
                if binding != owner.binding:
                    raise ValueError("synthetic-binding-mismatch")

            def readiness(self, *, deadline, cancelled):
                request = owner.verifier.request("readiness", self.lease)
                raw = owner.client.fetch(request, deadline=deadline, cancelled=cancelled)
                owner.verifier.verify(raw, request=request, now=datetime.now(UTC))
                return Readiness((self.lease.component,), self.lease.effective_policy_digest, True)

            def replay(self, action, url, attempt_id, *, deadline, cancelled):
                owner.send(observer, action.receiver)
                if action.receiver == "forbidden":
                    observer._call("sample")
                    owner.stop_child(receiver if victim == "receiver" else authority, abrupt=True)
                    if victim == "authority":
                        owner.refresh(monitor)
                return True

            def destroy(self, *, deadline):
                request = owner.verifier.request("cleanup", self.lease)
                raw = owner.client.destroy(request, deadline=deadline, cancelled=Event())
                owner.verifier.verify(raw, request=request, now=datetime.now(UTC))
                return True

        case = load_case(ROOT / "examples/denied-egress-live-v1.json")
        dispatch, _, _ = fixture("healthy")
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
                "deadline": datetime.now(UTC) + timedelta(seconds=15),
            }
        )
        key = Ed25519PrivateKey.generate()
        record = run_attempt(
            dispatch,
            case,
            SyntheticBoundary(),
            observer,
            EvidenceStore(self.root / "terminal"),
            key,
            "drill-terminal",
            control,
            recovery=ControllerLease(
                self.journal, self.lease, heartbeat_ttl=3, heartbeat_interval=0.1
            ),
            readiness_budget=2,
            cleanup_budget=1,
        )
        self.assertTrue(authenticate(record, {"drill-terminal": key.public_key()}))
        self.assertEqual(record.evidence.observer_outcome, "violation")
        self.assertTrue(record.evidence.observed_effect_refs)
        self.assertNotEqual(record.result.run_status.value, "complete")
        decision = evaluate(
            dispatch,
            [record],
            {"drill-terminal": key.public_key()},
            now=datetime.now(UTC),
            job_complete=True,
            server_aggregate=record.result.invariant_held,
        )
        self.assertNotEqual(decision.release_decision.value, "pass")
        self.assertFalse(decision.release_eligible)
        if victim == "authority":
            self.assertFalse(record.evidence.containment_monitor_healthy)
            self.assertNotEqual(record.result.cleanup_status, "destroyed")
        else:
            self.assertFalse(
                next(
                    source for source in record.evidence.sources if source.source_id == "receiver"
                ).complete
            )

    def test_receiver_sigkill_retains_violation_in_signed_terminal_and_gate(self):
        self.terminal_after_service_death("receiver")

    def test_sigkill_authority_terminates_active_inspector_before_fresh_recovery(self):
        child = self.authority()
        self.register_due()
        (self.root / "block-cleanup").touch()
        watchdog = self.launch("watchdog", self.watchdog_config)
        entered = self.root / "cleanup-entered.json"
        self.wait(entered.exists)
        inspector_pid = json.loads(entered.read_text())["pid"]

        def alive():
            try:
                os.kill(inspector_pid, 0)
                return True
            except ProcessLookupError:
                return False

        # Regression teardown owns this exact checkpoint PID even on the old
        # implementation, which leaks the inspector after authority SIGKILL.
        def stop_leaked_inspector():
            if alive():
                os.kill(inspector_pid, signal.SIGKILL)

        self.addCleanup(stop_leaked_inspector)
        self.assertTrue(alive())
        self.stop_child(child, abrupt=True)
        self.wait(lambda: not alive(), timeout=2)
        self.assertFalse(self.destroyed())
        self.assertIsNone(self.journal.inspect(self.lease.lease_id)["receipt_ref"])
        self.assertEqual(json.loads(self.inventory.read_text())["state"], "ready")
        (self.root / "block-cleanup").unlink()
        time.sleep(0.1)
        self.assertEqual(json.loads(self.inventory.read_text())["cleanup_calls"], 0)
        self.stop_child(watchdog)
        self.reconcile_socket(Path(self.authority_config.socket_path), child)
        self.authority()
        self.launch("watchdog", self.watchdog_config)
        self.wait(self.destroyed)
        self.assert_cleanup_proof()

    def test_authority_sigkill_retains_violation_and_withholds_cleanup_in_signed_gate(self):
        self.terminal_after_service_death("authority")
