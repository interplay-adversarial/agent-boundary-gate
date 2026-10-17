import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from receipt_support import FakeReceiptBroker, lease_and_binding

from agent_boundary_gate.auth import authenticate, digest, sign
from agent_boundary_gate.backends import BackendFailure, Readiness, UnsupportedCapability
from agent_boundary_gate.backends.fixture import LoopbackBackend
from agent_boundary_gate.backends.openshell import OpenShellBackend, validate_receiver_url
from agent_boundary_gate.case_registry import load_case
from agent_boundary_gate.contracts import HttpGetAction
from agent_boundary_gate.evidence import EvidenceStore, bytes_digest
from agent_boundary_gate.fixtures import fixture
from agent_boundary_gate.gate_policy import evaluate
from agent_boundary_gate.lifecycle import AttemptControl, run_attempt
from agent_boundary_gate.local_rig import local_run
from agent_boundary_gate.monitor import (
    MonitorHeartbeat,
    MonitorSession,
    MonitorSnapshot,
    sign_heartbeat,
)
from agent_boundary_gate.observers.denied_egress import DeniedEgressObserver
from agent_boundary_gate.process import AttemptStopped, ProcessResult, bounded_process

ROOT = Path(__file__).resolve().parents[1]


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.store = EvidenceStore(self.folder / "evidence")
        self.case = load_case(ROOT / "examples/denied-egress-v1.json")
        self.dispatch, _, _ = fixture("healthy")
        instance = self.dispatch.instances[0].model_copy(
            update={"case_spec_digest": digest(self.case)}
        )
        self.dispatch = self.dispatch.model_copy(update={"instances": (instance,)})
        self.control = AttemptControl.for_fixture(self.dispatch.binding)
        self.key = Ed25519PrivateKey.generate()
        self.driver = LoopbackBackend(self.dispatch.binding.effective_policy_digest)
        self.capture = DeniedEgressObserver(self.dispatch.binding.attempt_id, self.store)

    def attempt(self, **kwargs):
        return run_attempt(
            self.dispatch,
            self.case,
            self.driver,
            self.capture,
            self.store,
            self.key,
            "runtime-test-verifier",
            self.control,
            **kwargs,
        )

    def decision(self, record):
        return evaluate(
            self.dispatch,
            [record],
            {"runtime-test-verifier": self.key.public_key()},
            now=datetime.now(UTC),
            job_complete=True,
            server_aggregate=record.result.invariant_held,
        )

    def test_lease_binding_mismatch_stops_before_observer_and_replay(self):
        with (
            patch.object(self.driver, "require_binding", side_effect=UnsupportedCapability()),
            patch.object(self.driver, "replay") as replay,
            patch.object(self.capture, "start") as start,
        ):
            record = self.attempt()
        self.assertEqual(record.result.run_status, "unsupported-detector")
        self.assertIsNone(record.result.invariant_held)
        self.assertFalse(start.called)
        self.assertFalse(replay.called)
        self.assertTrue(self.driver.destroyed)
        self.assertFalse(self.decision(record).release_eligible)

    def authenticated_monitor(self):
        lease, _ = lease_and_binding()
        lease = lease.model_copy(
            update={
                "binding_digest": digest(self.dispatch.binding),
                "run_id": self.dispatch.binding.run_id,
                "attempt_id": self.dispatch.binding.attempt_id,
                "effective_policy_digest": self.dispatch.binding.effective_policy_digest,
                "component": lease.component.model_copy(update={"component_id": "loopback"}),
            }
        )
        ticks = [100.0]
        key = Ed25519PrivateKey.generate()
        monitor = MonitorSession(
            lease=lease,
            identity="synthetic-runtime-monitor",
            generation="monitor-generation-1",
            trusted_keys={"synthetic-runtime-monitor": key.public_key()},
            store=self.store,
            monotonic=lambda: ticks[0],
        )
        now = datetime.now(UTC)
        heartbeat = MonitorHeartbeat(
            request=monitor.request(),
            signer_identity="synthetic-runtime-monitor",
            generation="monitor-generation-1",
            sequence=1,
            state="healthy",
            issued_at=now,
            expires_at=now + timedelta(seconds=5),
        )
        self.assertTrue(
            monitor.accept(sign_heartbeat(heartbeat, key).model_dump_json().encode(), now=now)
        )
        return monitor, ticks

    def test_unknown_monitor_stops_before_capture_and_replay(self):
        self.control = AttemptControl()
        with (
            patch.object(self.capture, "start") as start,
            patch.object(self.driver, "replay") as replay,
        ):
            record = self.attempt()
        self.assertFalse(start.called)
        self.assertFalse(replay.called)
        self.assertTrue(self.driver.destroyed)
        self.assertEqual(record.result.run_status, "telemetry-loss")
        self.assertIsNone(record.result.invariant_held)
        self.assertEqual(self.decision(record).release_decision, "inconclusive")

    def test_authenticated_monitor_source_and_durable_refs_are_recorded(self):
        monitor, _ = self.authenticated_monitor()
        self.control = AttemptControl(monitor)
        record = self.attempt()
        source = next(
            source
            for source in record.evidence.sources
            if source.source_id == "containment-monitor"
        )
        self.assertEqual(source.identity, "synthetic-runtime-monitor")
        self.assertEqual(source.generation, "monitor-generation-1")
        self.assertTrue(source.ready_before_replay)
        packet = self.store.root / (source.artifact_digest.removeprefix("sha256:") + ".json")
        self.assertEqual(len(json.loads(packet.read_text())["heartbeat_refs"]), 1)
        self.assertEqual(self.decision(record).release_decision, "pass")
        self.assertFalse(self.decision(record).release_eligible)

    def test_heartbeat_expiry_preserves_proven_violation(self):
        monitor, ticks = self.authenticated_monitor()
        self.control = AttemptControl(monitor)
        self.driver.weakened = True
        original = self.driver.replay

        def expire_after_effect(action, *args, **kwargs):
            completed = original(action, *args, **kwargs)
            if action.receiver == "forbidden":
                ticks[0] += 5
            return completed

        with patch.object(self.driver, "replay", side_effect=expire_after_effect):
            record = self.attempt()
        self.assertEqual(record.result.run_status, "telemetry-loss")
        self.assertEqual(record.result.invariant_held, 0.0)
        self.assertTrue(record.evidence.observed_effect_refs)

    def test_monitor_adapter_exception_is_latched_and_signed_incomplete(self):
        with patch.object(
            self.control.monitor, "snapshot", side_effect=OSError("synthetic-monitor-loss")
        ):
            record = self.attempt()
        self.assertEqual(record.result.run_status, "telemetry-loss")
        self.assertIsNone(record.result.invariant_held)
        self.assertFalse(record.evidence.containment_monitor_healthy)

    def test_controller_lease_failure_stops_next_action_and_quiesces(self):
        class Registration:
            failed = Event()
            stopped = False
            quiesced = False

            def start(self, binding):
                pass

            def quiesce(self):
                self.quiesced = True

            def stop(self):
                self.stopped = True

        registration = Registration()
        original = self.driver.replay
        calls = []

        def fail_after_control(action, *args, **kwargs):
            calls.append(action.receiver)
            completed = original(action, *args, **kwargs)
            registration.failed.set()
            return completed

        with patch.object(self.driver, "replay", side_effect=fail_after_control):
            record = self.attempt(recovery=registration)
        self.assertEqual(calls, ["allowed"])
        self.assertTrue(registration.stopped)
        self.assertIn("controller-lease-lost", record.result.run_status_reasons)
        self.assertIsNone(record.result.invariant_held)
        self.assertEqual(self.decision(record).release_decision, "inconclusive")

    def test_leased_backend_requires_matching_recovery_and_authenticated_monitor(self):
        monitor, _ = self.authenticated_monitor()
        self.control = AttemptControl(monitor)
        self.driver.lease = monitor.lease
        with patch.object(self.driver, "replay") as replay:
            record = self.attempt()
        self.assertEqual(record.result.run_status, "unsupported-detector")
        self.assertFalse(replay.called)
        self.assertIsNone(record.result.invariant_held)

        class Registration:
            lease = monitor.lease
            failed = Event()
            started = False

            def start(self, binding):
                self.started = True

            def stop(self):
                pass

            def quiesce(self):
                pass

        registration = Registration()
        self.control = AttemptControl.for_fixture(self.dispatch.binding)
        with patch.object(self.capture, "start") as start:
            record = self.attempt(recovery=registration)
        self.assertTrue(registration.started)
        self.assertFalse(start.called)
        self.assertEqual(record.result.run_status, "unsupported-detector")

    def test_monitor_generation_change_cannot_restore_health(self):
        self.assertTrue(self.control.monitor_snapshot().healthy)
        with patch.object(
            self.control.monitor,
            "snapshot",
            return_value=MonitorSnapshot(
                "healthy", "local-fixture-monitor", "replacement-generation"
            ),
        ):
            self.assertFalse(self.control.monitor_snapshot().healthy)
        self.assertFalse(self.control.monitor_snapshot().healthy)

    def test_concurrent_snapshots_pin_first_generation_and_latch_change(self):
        first_entered, release_first = Event(), Event()
        calls = []

        def changing_source():
            generation = "first-generation" if not calls else "replacement-generation"
            calls.append(generation)
            if generation == "first-generation":
                first_entered.set()
                if not release_first.wait(2):
                    raise RuntimeError("synthetic-snapshot-timeout")
            return MonitorSnapshot("healthy", "local-fixture-monitor", generation)

        with patch.object(self.control.monitor, "snapshot", side_effect=changing_source):
            with ThreadPoolExecutor(max_workers=8) as pool:
                first = pool.submit(self.control.monitor_snapshot)
                self.assertTrue(first_entered.wait(1))
                others = [pool.submit(self.control.monitor_snapshot) for _ in range(7)]
                release_first.set()
                snapshots = [first.result(timeout=2)] + [
                    future.result(timeout=2) for future in others
                ]
        self.assertTrue(snapshots[0].healthy)
        self.assertEqual(snapshots[0].generation, "first-generation")
        self.assertTrue(all(not snapshot.healthy for snapshot in snapshots[1:]))
        self.assertEqual(
            self.control._monitor_identity, ("local-fixture-monitor", "first-generation")
        )
        self.assertFalse(self.control.monitor_snapshot().healthy)

    def test_unsupported_case_preserves_status_with_unknown_monitor(self):
        self.control = AttemptControl()
        self.case = self.case.model_copy(update={"required_capabilities": ("unimplemented-probe",)})
        instance = self.dispatch.instances[0].model_copy(
            update={"case_spec_digest": digest(self.case)}
        )
        self.dispatch = self.dispatch.model_copy(update={"instances": (instance,)})
        record = self.attempt()
        self.assertEqual(record.result.run_status, "unsupported-detector")
        self.assertIn("containment-monitor-loss", record.result.run_status_reasons)
        self.assertIn("adapter-or-capability-unsupported", record.result.run_status_reasons)
        self.assertIsNone(record.result.invariant_held)
        self.assertEqual(self.decision(record).release_decision, "inconclusive")

    def test_healthy_real_http_and_signed_terminal_record(self):
        record = self.attempt()
        self.assertEqual(self.capture.count("allowed"), 1)
        self.assertEqual(self.capture.count("forbidden"), 0)
        self.assertEqual(self.decision(record).release_decision, "pass")
        self.assertFalse(self.decision(record).release_eligible)
        self.assertTrue(authenticate(record, {"runtime-test-verifier": self.key.public_key()}))
        self.assertTrue(self.driver.destroyed)
        self.assertTrue(self.capture.drained)
        manifest_path = self.store.root / (record.result.evidence_manifest_digest[7:] + ".json")
        self.assertTrue(manifest_path.exists())
        self.assertGreaterEqual(len(list(self.store.root.glob("*.json"))), 4)

    def test_weakened_real_receiver_violation_is_persisted_before_cleanup(self):
        self.driver.weakened = True

        def cleanup(*, deadline):
            self.assertTrue(self.capture.effect_refs)
            for ref in self.capture.effect_refs:
                self.assertTrue((self.store.root / (ref[7:] + ".json")).exists())
            raise RuntimeError("synthetic-cleanup-error")

        self.driver.destroy = cleanup
        record = self.attempt()
        self.assertEqual(record.result.cleanup_status, "failed")
        self.assertEqual(record.result.invariant_held, 0.0)
        self.assertEqual(self.decision(record).release_decision, "criteria_failed")

    def test_incident_during_replay_stops_next_action(self):
        original = self.driver.replay
        actions = []

        def replay(action, url, attempt_id, **kwargs):
            actions.append(action.receiver)
            result = original(action, url, attempt_id, **kwargs)
            self.control.monitor.mark_incident()
            return result

        self.driver.replay = replay
        record = self.attempt()
        self.assertEqual(actions, ["allowed"])
        self.assertEqual(self.decision(record).release_decision, "incident")
        self.assertTrue(self.driver.destroyed)

    def test_monitor_loss_stops_without_claiming_incident(self):
        self.control.monitor.mark_lost()
        record = self.attempt()
        self.assertEqual(record.result.run_status, "telemetry-loss")
        self.assertFalse(record.result.containment_incident)
        self.assertEqual(self.capture.events, [])
        self.assertEqual(self.decision(record).release_decision, "inconclusive")

    def test_proven_violation_survives_later_monitor_loss(self):
        self.driver.weakened = True
        original = self.driver.replay

        def replay(action, url, attempt_id, **kwargs):
            result = original(action, url, attempt_id, **kwargs)
            if action.receiver == "forbidden":
                self.control.monitor.mark_lost()
            return result

        self.driver.replay = replay
        record = self.attempt()
        self.assertEqual(record.result.run_status, "telemetry-loss")
        self.assertEqual(record.result.invariant_held, 0.0)
        self.assertEqual(self.decision(record).release_decision, "criteria_failed")

    def test_readiness_failure_times_out_without_replay(self):
        self.driver.readiness = lambda **kwargs: Readiness((), self.driver.policy_digest, False)
        record = self.attempt(readiness_budget=0.04)
        self.assertEqual(record.result.run_status, "timeout")
        self.assertEqual(self.capture.events, [])
        self.assertTrue(self.driver.destroyed)
        self.assertEqual(self.decision(record).release_decision, "inconclusive")

    def test_cancellation_is_terminal_and_cleanup_runs(self):
        self.control.cancelled.set()
        record = self.attempt()
        self.assertEqual(record.result.run_status, "cancelled")
        self.assertTrue(self.driver.destroyed)
        self.assertEqual(self.decision(record).release_decision, "inconclusive")

    def test_unknown_replay_error_is_terminal(self):
        self.driver.replay = lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("sentinel-raw-payload")
        )
        record = self.attempt()
        self.assertEqual(record.result.run_status, "infra_error")
        self.assertNotIn("sentinel-raw-payload", record.model_dump_json())
        self.assertTrue(self.driver.destroyed)

    def test_receiver_drain_failure_blocks(self):
        original = self.capture.stop

        def stop():
            original()
            self.capture.drained = False

        self.capture.stop = stop
        record = self.attempt()
        self.assertEqual(self.decision(record).release_decision, "inconclusive")

    def test_terminal_storage_failure_blocks_and_returns_signed_record(self):
        original = self.store.persist

        def persist(data):
            if b'"signature":' in data:
                raise OSError("synthetic-store-outage")
            return original(data)

        self.store.persist = persist
        record = self.attempt()
        self.assertIn("terminal-record-not-persisted", record.result.run_status_reasons)
        self.assertEqual(self.decision(record).release_decision, "inconclusive")
        self.assertTrue(authenticate(record, {"runtime-test-verifier": self.key.public_key()}))

    def test_receiver_storage_loss_never_erases_violation(self):
        self.driver.weakened = True
        original = self.store.persist_json

        def persist(data):
            if isinstance(data, dict) and data.get("receiver") == "forbidden":
                raise OSError("synthetic-receiver-store-error")
            return original(data)

        self.store.persist_json = persist
        record = self.attempt()
        self.assertEqual(record.result.invariant_held, 0.0)
        self.assertEqual(record.result.run_status, "telemetry-loss")
        self.assertTrue(record.evidence.observed_effect_refs)
        self.assertEqual(self.decision(record).release_decision, "criteria_failed")

    def test_manifest_persistence_failure_withholds_approval(self):
        original = self.store.persist

        def persist(data):
            if "observer_outcome" in json.loads(data):
                raise OSError("synthetic-manifest-store-error")
            return original(data)

        self.store.persist = persist
        record = self.attempt()
        self.assertIn("manifest-not-persisted", record.result.run_status_reasons)
        self.assertEqual(self.decision(record).release_decision, "inconclusive")

    def test_policy_generation_changes_withhold_approval(self):
        original = self.driver.readiness
        checks = 0

        def readiness(**kwargs):
            nonlocal checks
            checks += 1
            ready = original(**kwargs)
            return (
                ready
                if checks == 1
                else Readiness(
                    (
                        ready.components[0].model_copy(
                            update={"generation": "replacement-generation"}
                        ),
                    ),
                    ready.effective_policy_digest,
                    True,
                )
            )

        self.driver.readiness = readiness
        record = self.attempt()
        self.assertIn("target-or-policy-generation-changed", record.result.run_status_reasons)
        self.assertEqual(self.capture.count("forbidden"), 0)
        self.assertEqual(self.decision(record).release_decision, "inconclusive")

    def test_incident_plus_cleanup_failure_remains_hard_stop(self):
        self.control.monitor.mark_incident()
        self.driver.destroy = lambda **kwargs: False
        record = self.attempt()
        self.assertEqual(record.result.cleanup_status, "failed")
        self.assertEqual(self.decision(record).release_decision, "incident")

    def test_cleanup_diagnostics_survive_signed_record_and_gate(self):
        for error in (
            AttemptStopped("backend-cleanup-cli-timeout"),
            BackendFailure("backend-cleanup-cli-exit-nonzero"),
            BackendFailure("backend-probe-delivery-rejected"),
        ):
            with (
                self.subTest(reason=error.reason),
                patch.object(self.driver, "destroy", side_effect=error),
            ):
                record = self.attempt()
            self.assertIn(error.reason, record.result.run_status_reasons)
            self.assertEqual(record.result.run_status, "incomplete")
            decision = self.decision(record)
            self.assertIn(error.reason, decision.decision_reasons)
            self.assertIn("cleanup-not-confirmed", decision.decision_reasons)
            self.assertEqual(decision.release_decision, "inconclusive")
            self.assertFalse(decision.release_eligible)

    def test_backend_nonzero_is_infrastructure_error_not_cancellation(self):
        with patch.object(
            self.driver, "replay", side_effect=BackendFailure("backend-replay-cli-exit-nonzero")
        ):
            record = self.attempt()
        self.assertEqual(record.result.run_status, "infra_error")
        self.assertIn("backend-replay-cli-exit-nonzero", self.decision(record).decision_reasons)

    def test_delivery_rejection_retains_violation_and_infrastructure_diagnostic(self):
        self.driver.weakened = True
        original = self.driver.replay

        def replay(*args, **kwargs):
            completed = original(*args, **kwargs)
            if args[0].receiver == "forbidden":
                raise BackendFailure("backend-probe-delivery-rejected")
            return completed

        with patch.object(self.driver, "replay", side_effect=replay):
            record = self.attempt()
        decision = self.decision(record)
        self.assertEqual(decision.release_decision, "criteria_failed")
        self.assertTrue(decision.confirmed_violations)
        self.assertIn("backend-probe-delivery-rejected", decision.decision_reasons)

    def test_diagnostic_cleanup_failure_retains_confirmed_violation(self):
        self.driver.weakened = True
        with patch.object(
            self.driver, "destroy", side_effect=AttemptStopped("backend-cleanup-cli-timeout")
        ):
            record = self.attempt()
        decision = self.decision(record)
        self.assertEqual(decision.release_decision, "criteria_failed")
        self.assertTrue(decision.confirmed_violations)
        self.assertIn("backend-cleanup-cli-timeout", decision.decision_reasons)

    def test_gate_copies_only_authenticated_allowlisted_diagnostics(self):
        record = self.attempt()
        result = record.result.model_copy(
            update={
                "run_status_reasons": (
                    "backend-cleanup-cli-timeout",
                    "operator-private-label",
                )
            }
        )
        trusted = sign(result, record.evidence, self.key)
        decision = self.decision(trusted)
        self.assertIn("backend-cleanup-cli-timeout", decision.decision_reasons)
        self.assertNotIn("operator-private-label", decision.decision_reasons)
        self.assertEqual(decision.release_decision, "inconclusive")
        rejected = trusted.model_copy(update={"signature": "0" * 128})
        self.assertNotIn("backend-cleanup-cli-timeout", self.decision(rejected).decision_reasons)

    def test_expired_dispatch_does_not_replay(self):
        self.dispatch = self.dispatch.model_copy(
            update={"deadline": datetime.now(UTC) - timedelta(seconds=1)}
        )
        record = self.attempt()
        self.assertEqual(record.result.run_status, "timeout")
        self.assertEqual(self.capture.events, [])
        self.assertTrue(self.driver.destroyed)

    def test_stdout_completion_without_positive_observation_never_passes(self):
        self.driver.replay = lambda *args, **kwargs: True
        record = self.attempt()
        self.assertEqual(record.result.positive_control_status, "failed")
        self.assertEqual(record.result.invariant_held, None)
        self.assertEqual(self.decision(record).release_decision, "inconclusive")

    def test_real_process_deadline_kills_child(self):
        started = time.monotonic()
        with self.assertRaises(AttemptStopped) as caught:
            bounded_process(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                deadline=time.monotonic() + 0.08,
                cancelled=Event(),
            )
        self.assertEqual(caught.exception.reason, "timeout")
        self.assertLess(time.monotonic() - started, 2)

    def test_real_process_output_limit(self):
        with self.assertRaises(AttemptStopped) as caught:
            bounded_process(
                [
                    sys.executable,
                    "-c",
                    "import time; print('x' * 10000, flush=True); time.sleep(60)",
                ],
                deadline=time.monotonic() + 2,
                cancelled=Event(),
                max_output=512,
            )
        self.assertEqual(caught.exception.reason, "output-limit")

    def test_process_group_cleanup_denial_is_reported(self):
        # Denial must occur in the separate command owner, not in the caller.
        supervisor = self.folder / "denied-supervisor.py"
        supervisor.write_text(
            "import sys\nfrom unittest.mock import patch\n"
            "from agent_boundary_gate.process_supervisor import supervise\n"
            "with patch('agent_boundary_gate.process_supervisor.os.killpg', "
            "side_effect=PermissionError):\n"
            "    sys.exit(supervise(int(sys.argv[1]), int(sys.argv[2]), "
            "int(sys.argv[3]), float(sys.argv[4]), sys.argv[5:]))\n"
        )
        with (
            patch("agent_boundary_gate.process._SUPERVISOR", supervisor),
            self.assertRaises(AttemptStopped) as caught,
        ):
            bounded_process(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                deadline=time.monotonic() + 0.5,
                cancelled=Event(),
            )
        self.assertEqual(caught.exception.reason, "process-group-cleanup-not-confirmed")

    def test_receiver_ignores_wrong_attempt_and_unrelated_path(self):
        self.capture.start()
        try:
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(self.capture.url("forbidden"), timeout=1)
            self.assertEqual(self.capture.count("forbidden"), 0)
        finally:
            self.capture.stop()

    def test_evidence_permissions_and_content_addressing(self):
        ref = self.store.persist_json({"effect": "controlled-http-request"})
        path = self.store.root / (ref[7:] + ".json")
        self.assertEqual(os.stat(self.store.root).st_mode & 0o777, 0o700)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(ref, self.store.persist(path.read_bytes()))

    def test_public_evidence_directory_rejected(self):
        path = self.folder / "public"
        path.mkdir(mode=0o755)
        with self.assertRaises(ValueError):
            EvidenceStore(path)

    def test_local_runner_healthy_and_weakened(self):
        for weakened, expected in ((False, "pass"), (True, "criteria_failed")):
            decision = local_run(
                ROOT / "examples/denied-egress-v1.json",
                self.folder / ("weakened" if weakened else "healthy"),
                weakened=weakened,
            )
            self.assertEqual(decision.release_decision, expected)
            self.assertFalse(decision.release_eligible)


class DirectDriverTests(unittest.TestCase):
    def driver(self, generation="supervisor-1", cleanup=False, probe_runtime="python3"):
        path = Path(sys.executable)
        lease, _ = lease_and_binding()
        broker = FakeReceiptBroker(generation=generation, cleanup=cleanup)
        return OpenShellBackend(
            executable=path,
            executable_digest=bytes_digest(path.read_bytes()),
            gateway="rig",
            sandbox="gate-attempt-1",
            sandbox_uid="sandbox-1",
            policy_digest=lease.effective_policy_digest,
            policy_revision=3,
            lease=lease,
            receipt_provider=broker,
            receipt_verifier=broker.verifier,
            probe_runtime=probe_runtime,
        )

    def test_unknown_probe_runtime_is_rejected(self):
        with self.assertRaises(ValueError):
            self.driver(probe_runtime="sh")

    def test_oversized_pinned_executable_is_rejected_bounded(self):
        # A read_bytes() with no size cap would instead load however many bytes a
        # swapped-in oversized file contains before ever comparing its digest.
        with (
            patch("agent_boundary_gate.backends.openshell._MAX_EXECUTABLE_BYTES", 4),
            tempfile.TemporaryDirectory() as root,
        ):
            oversized = Path(root) / "openshell"
            oversized.write_bytes(b"too-large-for-the-patched-limit")
            lease, _ = lease_and_binding()
            broker = FakeReceiptBroker()
            with self.assertRaises(ValueError):
                OpenShellBackend(
                    executable=oversized,
                    executable_digest=bytes_digest(oversized.read_bytes()),
                    gateway="rig",
                    sandbox="gate-1",
                    sandbox_uid="sandbox-1",
                    policy_digest=lease.effective_policy_digest,
                    policy_revision=1,
                    lease=lease,
                    receipt_provider=broker,
                    receipt_verifier=broker.verifier,
                )

    def test_command_executes_a_private_snapshot_not_the_original_path(self):
        driver = self.driver()
        captured = {}

        def fake_bounded_process(argv, **kwargs):
            captured["argv0"] = argv[0]
            captured["mode"] = Path(argv[0]).stat().st_mode & 0o777
            captured["exists_during_call"] = Path(argv[0]).is_file()
            return ProcessResult(0, b"")

        with patch(
            "agent_boundary_gate.backends.openshell.bounded_process",
            side_effect=fake_bounded_process,
        ):
            driver._command([], time.monotonic() + 1, Event(), phase="readiness")
        self.assertNotEqual(captured["argv0"], driver.executable)
        self.assertEqual(captured["mode"], 0o500)
        self.assertTrue(captured["exists_during_call"])
        # The private snapshot directory is cleaned up once the call returns.
        self.assertFalse(Path(captured["argv0"]).exists())

    def test_cli_errors_are_classified_without_private_output(self):
        driver = self.driver()
        for phase in ("readiness", "replay", "cleanup"):
            for error, suffix, exception in (
                (AttemptStopped("timeout"), "timeout", AttemptStopped),
                (AttemptStopped("output-limit"), "output-limit", BackendFailure),
                (
                    AttemptStopped("process-group-cleanup-not-confirmed"),
                    "group-cleanup-failed",
                    BackendFailure,
                ),
                (OSError("private configuration"), "start-failed", BackendFailure),
            ):
                with (
                    self.subTest(phase=phase, suffix=suffix),
                    patch(
                        "agent_boundary_gate.backends.openshell.bounded_process", side_effect=error
                    ),
                    self.assertRaises(exception) as caught,
                ):
                    driver._command([], time.monotonic() + 1, Event(), phase=phase)
                self.assertEqual(str(caught.exception), f"backend-{phase}-cli-{suffix}")
            with (
                patch(
                    "agent_boundary_gate.backends.openshell.bounded_process",
                    return_value=ProcessResult(127, b"private child output"),
                ),
                self.assertRaises(BackendFailure) as caught,
            ):
                driver._command([], time.monotonic() + 1, Event(), phase=phase)
            self.assertEqual(str(caught.exception), f"backend-{phase}-cli-exit-nonzero")

    def test_perl_replay_uses_fixed_argv_and_correlated_completion(self):
        driver = self.driver(probe_runtime="perl")
        _, binding = lease_and_binding()
        driver.require_binding(binding)
        with patch.object(driver, "_command", side_effect=self.responses()):
            self.assertTrue(
                driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
            )
        action = load_case(ROOT / "examples/denied-egress-v1.json").actions[0]
        with patch.object(
            driver,
            "_command",
            return_value=ProcessResult(
                0, ("agent-boundary-gate-probe-complete:" + binding.attempt_id).encode()
            ),
        ) as command:
            self.assertTrue(
                driver.replay(
                    action,
                    "http://receiver:80/probe",
                    binding.attempt_id,
                    deadline=time.monotonic() + 1,
                    cancelled=Event(),
                )
            )
        argv = command.call_args.args[0]
        self.assertEqual(argv[argv.index("--") + 1], "perl")
        self.assertEqual(argv[-4:-1], ["receiver", "80", binding.attempt_id])

    def test_probe_timeout_is_clamped_to_the_remaining_replay_deadline(self):
        # action.timeout_seconds (up to 30) must never exceed the deadline the
        # caller actually gives replay(): a short deadline should clamp the
        # probe's own internal budget down, not let the outer sandbox exec kill
        # it mid-flight while the probe still thinks it has the full 30s.
        for probe_runtime in ("python3", "perl"):
            with self.subTest(probe_runtime=probe_runtime):
                driver = self.driver(probe_runtime=probe_runtime)
                _, binding = lease_and_binding()
                driver.require_binding(binding)
                with patch.object(driver, "_command", side_effect=self.responses()):
                    self.assertTrue(
                        driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
                    )
                action = HttpGetAction(
                    operation="http_get", receiver="allowed", path="/probe", timeout_seconds=30
                )
                with patch.object(
                    driver,
                    "_command",
                    return_value=ProcessResult(
                        0, ("agent-boundary-gate-probe-complete:" + binding.attempt_id).encode()
                    ),
                ) as command:
                    driver.replay(
                        action,
                        "http://receiver:80/probe",
                        binding.attempt_id,
                        deadline=time.monotonic() + 1,
                        cancelled=Event(),
                    )
                argv = command.call_args.args[0]
                self.assertEqual(argv[-1], "1")
                self.assertEqual(argv[argv.index("--timeout") + 1], "1")

    def test_probe_input_prevalidation_rejects_a_malformed_attempt_id_before_any_subprocess_call(
        self,
    ):
        # attempt_id is always lease-validated upstream in practice, so this never
        # fires live; simulate the upstream invariant breaking (bypassing the
        # frozen contract's own validation, which would otherwise make this
        # unreachable) and confirm python3/perl now reject it in-process, before
        # ever spawning a subprocess -- parity with rust's own pre-existing check.
        for probe_runtime in ("python3", "perl"):
            with self.subTest(probe_runtime=probe_runtime):
                driver = self.driver(probe_runtime=probe_runtime)
                _, binding = lease_and_binding()
                driver.require_binding(binding)
                with patch.object(driver, "_command", side_effect=self.responses()):
                    self.assertTrue(
                        driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
                    )
                # Corrupt the already-validated lease only now, simulating the
                # upstream invariant breaking after every legitimate check (the
                # binding-digest match in require_binding, the lease/readiness
                # window) has already passed.
                malformed = "bad attempt id"
                object.__setattr__(driver.lease, "attempt_id", malformed)
                action = HttpGetAction(
                    operation="http_get", receiver="allowed", path="/probe", timeout_seconds=1
                )
                with patch.object(driver, "_command") as command:
                    with self.assertRaises(UnsupportedCapability) as caught:
                        driver.replay(
                            action,
                            "http://receiver:80/probe",
                            malformed,
                            deadline=time.monotonic() + 1,
                            cancelled=Event(),
                        )
                    self.assertEqual(str(caught.exception), "probe-input-unsupported")
                    command.assert_not_called()

    def responses(self, *, status="loaded", hash_value="a" * 64, active_version=3, uid="sandbox-1"):
        if hash_value == "a" * 64:
            hash_value = lease_and_binding()[0].effective_policy_digest.removeprefix("sha256:")
        return [
            ProcessResult(0, json.dumps({"id": uid, "phase": "Ready"}).encode()),
            ProcessResult(
                0,
                json.dumps(
                    {
                        "sandbox": "gate-attempt-1",
                        "status": status,
                        "hash": hash_value,
                        "version": 3,
                        "active_version": active_version,
                    }
                ).encode(),
            ),
        ]

    def test_loaded_revision_plus_supervisor_receipt_required(self):
        driver = self.driver()
        with patch.object(driver, "_command", side_effect=self.responses()):
            self.assertTrue(
                driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
            )
        for changes in (
            {"status": "effective"},
            {"status": "pending"},
            {"active_version": 2},
            {"hash_value": "b" * 64},
            {"uid": "replacement"},
        ):
            with (
                self.subTest(changes=changes),
                patch.object(driver, "_command", side_effect=self.responses(**changes)),
            ):
                self.assertFalse(
                    driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
                )
        driver = self.driver(generation=None)
        with patch.object(driver, "_command", side_effect=self.responses()):
            self.assertFalse(
                driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
            )

    def test_delete_acknowledgement_is_not_teardown(self):
        driver = self.driver()
        replies = [ProcessResult(0, b'{"id":"sandbox-1"}'), ProcessResult(0, b"")]
        with patch.object(driver, "_command", side_effect=replies):
            self.assertFalse(driver.destroy(deadline=time.monotonic() + 1))

    def test_same_name_replacement_not_deleted(self):
        driver = self.driver(cleanup=True)
        with patch.object(
            driver, "_command", return_value=ProcessResult(0, b'{"id":"replacement"}')
        ) as command:
            self.assertFalse(driver.destroy(deadline=time.monotonic() + 1))
            self.assertEqual(command.call_count, 1)

    def test_signed_cleanup_receipt_confirms_teardown(self):
        driver = self.driver(cleanup=True)
        replies = [ProcessResult(0, b'{"id":"sandbox-1"}'), ProcessResult(0, b"")]
        with patch.object(driver, "_command", side_effect=replies):
            self.assertTrue(driver.destroy(deadline=time.monotonic() + 1))
        self.assertEqual(driver.receipt_provider.requests[-1].purpose, "cleanup")

    def test_changed_generation_and_replayed_receipt_are_rejected(self):
        driver = self.driver(generation="other-generation")
        with patch.object(driver, "_command", side_effect=self.responses()):
            self.assertFalse(
                driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
            )
        driver = self.driver()
        original_fetch = driver.receipt_provider.fetch
        cached = []

        def replayed(request, **kwargs):
            if not cached:
                cached.append(original_fetch(request, **kwargs))
            return cached[0]

        with patch.object(driver.receipt_provider, "fetch", side_effect=replayed):
            with patch.object(driver, "_command", side_effect=self.responses()):
                self.assertTrue(
                    driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
                )
            with patch.object(driver, "_command", side_effect=self.responses()):
                self.assertFalse(
                    driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
                )

    def test_wrong_trust_anchor_and_legacy_boolean_receipt_are_rejected(self):
        for response in (True, b"{}"):
            driver = self.driver(cleanup=True)
            with patch.object(driver.receipt_provider, "fetch", return_value=response):
                with patch.object(driver, "_command", side_effect=self.responses()):
                    self.assertFalse(
                        driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
                    )
                replies = [ProcessResult(0, b'{"id":"sandbox-1"}'), ProcessResult(0, b"")]
                with patch.object(driver, "_command", side_effect=replies):
                    self.assertFalse(driver.destroy(deadline=time.monotonic() + 1))
        driver = self.driver()
        driver.receipt_provider.key = Ed25519PrivateKey.generate()
        with patch.object(driver, "_command", side_effect=self.responses()):
            self.assertFalse(
                driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
            )

    def test_receipt_fetch_honors_cancellation_and_elapsed_deadline(self):
        driver = self.driver()
        cancelled = Event()
        cancelled.set()
        with patch.object(driver.receipt_provider, "fetch") as fetch:
            self.assertIsNone(
                driver._receipt("readiness", deadline=time.monotonic() + 1, cancelled=cancelled)
            )
            self.assertFalse(fetch.called)
        cancelled.clear()
        with patch("agent_boundary_gate.backends.openshell.time.monotonic", side_effect=[1.0, 2.0]):
            self.assertIsNone(driver._receipt("readiness", deadline=1.5, cancelled=cancelled))
        original_fetch = driver.receipt_provider.fetch

        def cancel_during_fetch(request, **kwargs):
            raw = original_fetch(request, **kwargs)
            cancelled.set()
            return raw

        with patch.object(driver.receipt_provider, "fetch", side_effect=cancel_during_fetch):
            self.assertIsNone(
                driver._receipt("readiness", deadline=time.monotonic() + 1, cancelled=cancelled)
            )

    def test_dispatch_binding_and_attempt_must_match_before_replay(self):
        driver = self.driver()
        _, binding = lease_and_binding()
        action = load_case(ROOT / "examples/denied-egress-v1.json").actions[0]
        with patch.object(driver, "_command") as command:
            self.assertFalse(
                driver.replay(
                    action,
                    "http://receiver:80/probe",
                    binding.attempt_id,
                    deadline=time.monotonic() + 1,
                    cancelled=Event(),
                )
            )
            self.assertFalse(command.called)
        driver.require_binding(binding)
        with patch.object(driver, "_command", side_effect=self.responses()):
            self.assertTrue(
                driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
            )
        with patch.object(
            driver,
            "_command",
            return_value=ProcessResult(
                0, ("agent-boundary-gate-probe-complete:" + binding.attempt_id).encode()
            ),
        ):
            self.assertTrue(
                driver.replay(
                    action,
                    "http://receiver:80/probe",
                    binding.attempt_id,
                    deadline=time.monotonic() + 1,
                    cancelled=Event(),
                )
            )
        with patch.object(driver, "_command") as command:
            self.assertFalse(
                driver.replay(
                    action,
                    "http://receiver:80/probe",
                    "other-attempt",
                    deadline=time.monotonic() + 1,
                    cancelled=Event(),
                )
            )
            self.assertFalse(command.called)
        with self.assertRaises(UnsupportedCapability):
            driver.require_binding(
                binding.model_copy(update={"suite_digest": "sha256:" + "b" * 64})
            )
        self.assertFalse(driver._attempt_bound)

    def test_expired_receipt_blocks_replay_without_command(self):
        driver = self.driver()
        _, binding = lease_and_binding()
        driver.require_binding(binding)
        with patch.object(driver, "_command", side_effect=self.responses()):
            self.assertTrue(
                driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
            )
        driver._last_readiness = driver._last_readiness.model_copy(
            update={"expires_at": datetime.now(UTC)}
        )
        with patch.object(driver, "_command") as command:
            self.assertFalse(
                driver.replay(
                    load_case(ROOT / "examples/denied-egress-v1.json").actions[0],
                    "http://receiver:80/probe",
                    binding.attempt_id,
                    deadline=time.monotonic() + 1,
                    cancelled=Event(),
                )
            )
            self.assertFalse(command.called)

    def test_cleanup_and_rebinding_invalidate_cached_readiness(self):
        for transition in ("cleanup", "rebind"):
            driver = self.driver(cleanup=True)
            _, binding = lease_and_binding()
            driver.require_binding(binding)
            with patch.object(driver, "_command", side_effect=self.responses()):
                self.assertTrue(
                    driver.readiness(deadline=time.monotonic() + 1, cancelled=Event()).ready
                )
            if transition == "cleanup":
                replies = [ProcessResult(0, b'{"id":"sandbox-1"}'), ProcessResult(0, b"")]
                with patch.object(driver, "_command", side_effect=replies):
                    self.assertTrue(driver.destroy(deadline=time.monotonic() + 1))
            else:
                driver.require_binding(binding)
            self.assertIsNone(driver._last_readiness)
            with patch.object(driver, "_command") as command:
                self.assertFalse(
                    driver.replay(
                        load_case(ROOT / "examples/denied-egress-v1.json").actions[0],
                        "http://receiver:80/probe",
                        binding.attempt_id,
                        deadline=time.monotonic() + 1,
                        cancelled=Event(),
                    )
                )
                self.assertFalse(command.called)

    def test_unpinned_binary_rejected(self):
        lease, _ = lease_and_binding()
        broker = FakeReceiptBroker()
        with self.assertRaises(ValueError):
            OpenShellBackend(
                executable=Path(sys.executable),
                executable_digest="sha256:" + "0" * 64,
                gateway="rig",
                sandbox="gate-1",
                sandbox_uid="sandbox-1",
                policy_digest="sha256:" + "a" * 64,
                policy_revision=1,
                lease=lease,
                receipt_provider=broker,
                receipt_verifier=broker.verifier,
            )

    def test_receiver_url_rejects_redirect_style_and_credentials(self):
        for url in (
            "https://receiver:80/probe",
            "http://" + ":".join(("fixture-user", "fixture-password")) + "@receiver:80/probe",
            "http://receiver/probe",
            "http://receiver:80/probe?next=other",
            "http://receiver:80/other",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_receiver_url(url)


if __name__ == "__main__":
    unittest.main()
