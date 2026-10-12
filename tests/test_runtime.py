import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_boundary_gate.auth import authenticate, digest
from agent_boundary_gate.backends import Readiness
from agent_boundary_gate.backends.fixture import LoopbackBackend
from agent_boundary_gate.backends.openshell import OpenShellBackend, validate_receiver_url
from agent_boundary_gate.case_registry import load_case
from agent_boundary_gate.evidence import EvidenceStore, bytes_digest
from agent_boundary_gate.fixtures import fixture
from agent_boundary_gate.gate_policy import evaluate
from agent_boundary_gate.lifecycle import AttemptControl, run_attempt
from agent_boundary_gate.local_rig import local_run
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
        self.control = AttemptControl()
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
            self.control.incident.set()
            return result

        self.driver.replay = replay
        record = self.attempt()
        self.assertEqual(actions, ["allowed"])
        self.assertEqual(self.decision(record).release_decision, "incident")
        self.assertTrue(self.driver.destroyed)

    def test_monitor_loss_stops_without_claiming_incident(self):
        self.control.monitor_healthy.clear()
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
                self.control.monitor_healthy.clear()
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
        self.control.incident.set()
        self.driver.destroy = lambda **kwargs: False
        record = self.attempt()
        self.assertEqual(record.result.cleanup_status, "failed")
        self.assertEqual(self.decision(record).release_decision, "incident")

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
        with (
            patch("agent_boundary_gate.process.os.killpg", side_effect=PermissionError),
            self.assertRaises(AttemptStopped) as caught,
        ):
            bounded_process(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                deadline=time.monotonic() + 0.08,
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
    def driver(self, generation="supervisor-1", cleanup=False):
        path = Path(sys.executable)
        return OpenShellBackend(
            executable=path,
            executable_digest=bytes_digest(path.read_bytes()),
            gateway="rig",
            sandbox="gate-attempt-1",
            sandbox_uid="sandbox-1",
            policy_digest="sha256:" + "a" * 64,
            policy_revision=3,
            supervisor_receipt=lambda: generation,
            cleanup_receipt=lambda: cleanup,
        )

    def responses(self, *, status="loaded", hash_value="a" * 64, active_version=3, uid="sandbox-1"):
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

    def test_unpinned_binary_rejected(self):
        with self.assertRaises(ValueError):
            OpenShellBackend(
                executable=Path(sys.executable),
                executable_digest="sha256:" + "0" * 64,
                gateway="rig",
                sandbox="gate-1",
                sandbox_uid="sandbox-1",
                policy_digest="sha256:" + "a" * 64,
                policy_revision=1,
                supervisor_receipt=lambda: "generation-1",
                cleanup_receipt=lambda: True,
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
