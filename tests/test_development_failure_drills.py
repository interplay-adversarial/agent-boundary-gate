"""Real controller death/restart against an independently persisted synthetic backend.

No model, cluster or runtime qualification: only the operator controller is real.
The backend state survives SIGKILL separately from the controller's journal.
"""

import copy
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

import test_development_cell as cells
import test_development_run as fixtures

from agent_boundary_gate.development_run import DevelopmentRunConfig
from agent_boundary_gate.evidence import bytes_digest, write_json_atomic
from agent_boundary_gate.probe_delivery import PROBE_PATH


class PersistentCell(cells.CellRunner):
    """Independent synthetic receiver/runtime storage, not gate evidence."""

    fields = ("cell", "namespace", "receivers", "pods", "counts", "active")

    def __init__(self, config, output, *, backend, checkpoint=None, recover=False):
        self.backend = backend
        self.checkpoint = checkpoint
        super().__init__(config, output, recover=recover)
        if backend.exists():
            for name, value in json.loads(backend.read_text()).items():
                setattr(self, name, value)

    def persist_backend(self):
        write_json_atomic(self.backend, {name: getattr(self, name) for name in self.fields})

    def pause(self):
        print("checkpoint-ready", flush=True)
        # The parent kills this controller; no finally cleanup can run.
        while True:
            signal.pause()

    def save(self):
        allocations = self.state.get("allocations") or [{}]
        counts = allocations[-1].get("counts", {})
        if self.checkpoint == "uncommitted-journal" and counts.get("forbidden") == 1:
            uncommitted = copy.deepcopy(self.state)
            uncommitted["allocations"][0]["cell_uid"] = "uncommitted-uid"
            pending = self.output / "journal.pending"
            fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(uncommitted, stream)
                stream.flush()
                os.fsync(stream.fileno())
            self.pause()
        super().save()
        if self.checkpoint == "after-observation" and counts.get("forbidden") == 1:
            self.pause()

    def command(self, kind, args, **kwargs):
        result = super().command(kind, args, **kwargs)
        self.persist_backend()
        if (
            self.checkpoint == "after-effect"
            and kind == "openshell"
            and args[:2] == ["sandbox", "exec"]
            and args[-1] != PROBE_PATH
            and self.counts["forbidden"] == 1
        ):
            self.pause()
        if (
            self.checkpoint == "after-cell-delete"
            and kind == "kubernetes"
            and args[0] == "delete"
            and args[2].startswith("/api/v1/namespaces/gate-cell-")
        ):
            self.pause()
        if (
            self.checkpoint == "unregistered-cell"
            and kind == "kubernetes"
            and args[0] == "create"
            and kwargs.get("data", {}).get("kind") == "Namespace"
            and self.cell is not None
        ):
            self.pause()
        return result


def child(root, checkpoint):
    config = DevelopmentRunConfig.model_validate_json((root / "config.json").read_bytes())
    with PersistentCell(
        config, root / "campaign", backend=root / "backend.json", checkpoint=checkpoint
    ) as runner:
        runner.profile(True, Event())
    raise RuntimeError("checkpoint-not-reached")


class DevelopmentFailureDrills(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        source = self.root / "binary"
        source.write_bytes(b"synthetic-drill-helper")
        digest = bytes_digest(source.read_bytes())
        self.config = DevelopmentRunConfig(
            target_namespace="protected-target",
            receiver_image=fixtures.IMAGE,
            workload_image=fixtures.IMAGE,
            openshell_executable=source,
            kubernetes_executable=source,
            cell_bootstrap_executable=source,
            openshell_digest=digest,
            kubernetes_digest=digest,
            cell_bootstrap_digest=digest,
            probe_digest="sha256:" + "b" * 64,
            context="synthetic",
            gateway="protected-gateway",
        )
        (self.root / "config.json").write_text(self.config.model_dump_json())

    def recover(self):
        return PersistentCell(
            self.config, self.root / "campaign", backend=self.root / "backend.json", recover=True
        )

    def kill_at(self, checkpoint):
        repo = Path(__file__).resolve().parents[1]
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join((str(repo / "src"), str(repo / "tests")))
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), str(self.root), checkpoint],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            ready, _, _ = select.select([process.stdout], [], [], 20)
            self.assertTrue(ready, "controller-checkpoint-deadline")
            self.assertEqual(process.stdout.readline(), b"checkpoint-ready\n")
            # A second operator cannot race the still-live controller's journal.
            with self.assertRaises(BlockingIOError):
                self.recover()
            process.kill()
            process.wait(timeout=5)
            self.assertEqual(process.returncode, -signal.SIGKILL)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)

    def test_controller_death_before_effect_commit_recaptures_independent_effect(self):
        self.kill_at("after-effect")
        committed = json.loads((self.root / "campaign/journal.json").read_text())
        self.assertEqual(committed["allocations"][0]["counts"]["forbidden"], 0)
        self.assertEqual(
            json.loads((self.root / "backend.json").read_text())["counts"]["forbidden"], 1
        )
        with self.recover() as runner:
            self.assertTrue(runner.recover()["development_cleanup_complete"])
            allocation = runner.state["allocations"][0]
            self.assertEqual(allocation["counts"]["forbidden"], 1)
            self.assertTrue(allocation["final_capture"])
            self.assertFalse(runner.report(allocation)["expected_behavior_observed"])
            self.assertFalse(any(k in ("openshell", "cell-bootstrap") for k, _, _ in runner.calls))
            self.assertTrue(runner.recover()["development_cleanup_complete"])
        with self.recover() as restarted:
            self.assertEqual(restarted.state["allocations"][0]["counts"]["forbidden"], 1)
            self.assertTrue(restarted.recover()["development_cleanup_complete"])

    def test_committed_effect_survives_controller_restart_and_receiver_storage_loss(self):
        self.kill_at("after-observation")
        backend = json.loads((self.root / "backend.json").read_text())
        backend["counts"]["forbidden"] = 0
        write_json_atomic(self.root / "backend.json", backend)
        with self.recover() as runner:
            self.assertTrue(runner.recover()["development_cleanup_complete"])
            allocation = runner.state["allocations"][0]
            self.assertEqual(allocation["counts"]["forbidden"], 1)
            self.assertTrue(allocation["capture_lost"])
            self.assertFalse(runner.report(allocation)["expected_behavior_observed"])
            self.assertFalse(runner.recover()["release_eligible"])

    def test_target_effect_after_controller_death_is_included_in_final_capture(self):
        self.kill_at("after-effect")
        backend = json.loads((self.root / "backend.json").read_text())
        backend["counts"]["forbidden"] += 1
        write_json_atomic(self.root / "backend.json", backend)
        with self.recover() as runner:
            self.assertTrue(runner.recover()["development_cleanup_complete"])
            report = runner.report(runner.state["allocations"][0])
            self.assertEqual(report["forbidden_count"], 2)
            self.assertTrue(report["sampled_after_target_cleanup"])
            self.assertFalse(report["expected_behavior_observed"])

    def test_uncommitted_journal_is_ignored_after_real_writer_death(self):
        self.kill_at("uncommitted-journal")
        self.assertTrue((self.root / "campaign/journal.pending").exists())
        with self.recover() as runner:
            self.assertFalse((self.root / "campaign/journal.pending").exists())
            self.assertEqual(runner.state["allocations"][0]["cell_uid"], "cell-uid")
            self.assertTrue(runner.recover()["development_cleanup_complete"])
            self.assertEqual(runner.state["allocations"][0]["counts"]["forbidden"], 1)
            self.assertTrue(
                all(
                    data["preconditions"]["uid"] == "cell-uid"
                    for k, a, data in runner.calls
                    if k == "kubernetes" and a[0] == "delete" and "gate-cell-" in a[2]
                )
            )

    def test_death_after_delete_acceptance_reobserves_absence_before_final_capture(self):
        self.kill_at("after-cell-delete")
        with self.recover() as runner:
            allocation = runner.state["allocations"][0]
            self.assertFalse(allocation.get("cell_absent", False))
            self.assertTrue(runner.recover()["development_cleanup_complete"])
            self.assertTrue(allocation["cell_absent"])
            self.assertTrue(allocation["final_capture"])
            self.assertEqual(allocation["counts"]["forbidden"], 1)
            calls = runner.calls
            absent = next(
                i
                for i, (k, a, _) in enumerate(calls)
                if k == "kubernetes"
                and a[:2] == ["get", "namespace"]
                and a[2].startswith("gate-cell-")
            )
            capture = next(
                i for i, (k, a, _) in enumerate(calls) if k == "kubernetes" and a[0] == "exec"
            )
            self.assertLess(absent, capture)

    def test_death_in_namespace_registration_window_requires_operator_reconciliation(self):
        self.kill_at("unregistered-cell")
        with self.recover() as runner:
            self.assertFalse(runner.recover()["development_cleanup_complete"])
            self.assertIsNotNone(runner.cell)
            self.assertFalse(any(a[0] == "delete" for _, a, _ in runner.calls))
            self.assertFalse(
                runner.report(runner.state["allocations"][0])["expected_behavior_observed"]
            )

    def prepared(self):
        runner = cells.CellRunner(self.config, self.root / "campaign")
        self.addCleanup(runner.close)
        return runner

    def test_policy_mutation_after_effect_retains_effect_and_withholds_completion(self):
        runner = self.prepared()
        command = runner.command

        def mutate(kind, args, **kwargs):
            result = command(kind, args, **kwargs)
            if (
                kind == "openshell"
                and args[:2] == ["sandbox", "exec"]
                and runner.counts["forbidden"] == 1
            ):
                runner.active["hash"] = "mutated-policy"
            return result

        with patch.object(runner, "command", mutate):
            report = runner.profile(True, Event())
        self.assertFalse(report["expected_behavior_observed"])
        self.assertEqual(report["forbidden_count"], 1)
        self.assertTrue(report["cleanup_complete"])

    def test_supervisor_restart_after_effect_cannot_be_repaired_by_cleanup(self):
        runner = self.prepared()
        command = runner.command

        def restart(kind, args, **kwargs):
            result = command(kind, args, **kwargs)
            if (
                kind == "openshell"
                and args[:2] == ["sandbox", "exec"]
                and runner.counts["allowed"] == 1
            ):
                runner.pods[0]["status"]["containerStatuses"][0]["restartCount"] = 1
            return result

        with patch.object(runner, "command", restart):
            report = runner.profile(True, Event())
        self.assertFalse(report["expected_behavior_observed"])
        self.assertEqual(report["allowed_count"], 1)
        self.assertEqual(report["forbidden_count"], 0)
        self.assertTrue(report["cleanup_complete"])

    def test_receiver_replacement_latches_capture_loss_without_erasing_observed_violation(self):
        runner = self.prepared()
        with patch.object(runner, "cleanup"):
            runner.profile(True, Event())
        runner.receivers["forbidden"]["metadata"]["uid"] = "replacement-uid"
        result = runner.recover()
        allocation = runner.state["allocations"][0]
        self.assertTrue(result["development_cleanup_complete"])
        self.assertTrue(allocation["capture_lost"])
        self.assertEqual(allocation["counts"]["forbidden"], 1)
        self.assertFalse(runner.report(allocation)["expected_behavior_observed"])

    def test_journal_write_failure_after_effect_retains_violation_through_cleanup(self):
        runner = self.prepared()
        save = runner.save
        failed = False

        def fail_once():
            nonlocal failed
            counts = runner.state["allocations"][0].get("counts", {})
            if not failed and counts.get("forbidden") == 1:
                failed = True
                raise OSError("synthetic-storage-unavailable")
            save()

        with patch.object(runner, "save", fail_once):
            report = runner.profile(True, Event())
        self.assertTrue(failed)
        self.assertFalse(report["expected_behavior_observed"])
        self.assertEqual(report["forbidden_count"], 1)
        self.assertTrue(report["cleanup_complete"])
        committed = json.loads((runner.output / "journal.json").read_text())["allocations"][0]
        self.assertTrue(committed["failed"])
        self.assertEqual(committed["counts"]["forbidden"], 1)

    def test_persistent_journal_outage_cannot_return_success_and_requires_recovery(self):
        with PersistentCell(
            self.config, self.root / "campaign", backend=self.root / "backend.json"
        ) as runner:
            save = runner.save
            unavailable = False

            def storage_outage():
                nonlocal unavailable
                if runner.state["allocations"][0].get("counts", {}).get("forbidden") == 1:
                    unavailable = True
                if unavailable:
                    raise OSError("synthetic-storage-unavailable")
                save()

            with patch.object(runner, "save", storage_outage):
                with self.assertRaises(OSError):
                    runner.profile(True, Event())
            self.assertTrue(unavailable)
        with self.recover() as recovered:
            self.assertTrue(recovered.recover()["development_cleanup_complete"])
            report = recovered.report(recovered.state["allocations"][0])
            self.assertEqual(report["forbidden_count"], 1)
            self.assertFalse(report["expected_behavior_observed"])

    def test_cancellation_after_forbidden_effect_uses_fresh_cleanup_scope(self):
        runner = self.prepared()
        cancelled = Event()
        command = runner.command

        def cancel(kind, args, **kwargs):
            result = command(kind, args, **kwargs)
            if kind == "openshell" and runner.counts["forbidden"] == 1:
                cancelled.set()
            return result

        with patch.object(runner, "command", cancel):
            report = runner.profile(True, cancelled)
        self.assertTrue(cancelled.is_set())
        self.assertFalse(report["expected_behavior_observed"])
        self.assertEqual(report["forbidden_count"], 1)
        self.assertTrue(report["cleanup_complete"])
        self.assertTrue(
            all(not event.is_set() and event is not cancelled for event in runner.cleanup_events)
        )


if __name__ == "__main__":
    child(Path(sys.argv[1]), sys.argv[2])
