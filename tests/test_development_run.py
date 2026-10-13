"""Allocation faults, late effects and recovery of the development runner."""

import copy
import gc
import json
import os
import tempfile
import unittest
import weakref
from pathlib import Path
from threading import Event
from unittest.mock import Mock, patch

from agent_boundary_gate.development_run import DevelopmentRunConfig, DevelopmentRunner
from agent_boundary_gate.evidence import bytes_digest
from agent_boundary_gate.probe_delivery import PROBE_PATH
from agent_boundary_gate.process import AttemptStopped, ProcessResult

IMAGE = "example/owned@sha256:" + "a" * 64


class FakeRunner(DevelopmentRunner):
    def __init__(self, config, output, **kwargs):
        super().__init__(config, output, **kwargs)
        self.calls = []
        self.namespace = None
        self.pods = []
        self.receivers = {}
        self.counts = {"allowed": 0, "forbidden": 0}
        self.active = {}
        self.fault = None
        self.late = False

    def command(self, kind, args, *, deadline, cancelled, data=None, check=True):
        self.calls.append((kind, args, data))
        if cancelled.is_set():
            raise AttemptStopped("cancelled")
        if self.fault == "cleanup-failure" and kind == "cleanup":
            raise ValueError("synthetic-cleanup-failure")
        if (
            self.fault == "create-timeout"
            and kind == "openshell"
            and args[:2] == ["sandbox", "create"]
        ):
            raise AttemptStopped("timeout")
        result = {}
        if kind == "cleanup":
            if self.fault == "cleanup-response-mismatch":
                return ProcessResult(
                    0,
                    json.dumps(
                        {
                            **data,
                            "sandbox_id": "replacement",
                            "identity_preconditioned": True,
                            "cleanup_requested": True,
                        }
                    ).encode(),
                )
            self.pods = [
                p for p in self.pods if p["metadata"]["uid"] not in data["target_uids"].values()
            ]
            if self.late:
                self.counts["forbidden"] += 1
            result = {**data, "identity_preconditioned": True, "cleanup_requested": True}
        elif kind == "kubernetes":
            if args[0] == "create":
                if data["kind"] == "Namespace":
                    self.namespace = {"metadata": {**data["metadata"], "uid": "namespace-uid"}}
                    result = self.namespace
                    self.counts = {"allowed": 0, "forbidden": 0}
                else:
                    for pod in data["items"]:
                        if pod["kind"] == "Pod":
                            pod = copy.deepcopy(pod)
                            pod["metadata"]["uid"] = pod["metadata"]["name"] + "-uid"
                            pod["status"] = {
                                "phase": "Running",
                                "containerStatuses": [
                                    {
                                        "name": "receiver",
                                        "ready": True,
                                        "restartCount": 0,
                                        "imageID": IMAGE,
                                    }
                                ],
                            }
                            self.receivers[pod["metadata"]["name"]] = pod
            elif args[:2] == ["get", "pods"]:
                if "-l" in args:
                    items = self.pods
                    selector = args[args.index("-l") + 1]
                    key, value = selector.split("=", 1)
                    items = [p for p in items if p["metadata"]["labels"].get(key) == value]
                    result = {"items": items}
                else:
                    result = {"items": list(self.receivers.values())}
            elif args[:2] == ["get", "pod"]:
                result = self.receivers[args[2]]
            elif args[:2] == ["get", "services"]:
                result = {
                    "items": [
                        {"metadata": {"name": name}, "spec": {"clusterIP": ip}}
                        for name, ip in (("allowed", "127.0.0.1"), ("forbidden", "127.0.0.2"))
                    ]
                }
            elif args[0] == "exec":
                name = args[args.index("--") - 1]
                result = {
                    "attempt": self.state["allocations"][-1]["run"],
                    "count": self.counts[name],
                    "dropped": 1 if self.fault == "capture-loss" and name == "forbidden" else 0,
                }
            elif args[:2] == ["get", "namespace"]:
                result = self.namespace or {}
            elif args[0] == "delete":
                if self.namespace:
                    if data["preconditions"]["uid"] != self.namespace["metadata"]["uid"]:
                        raise ValueError("uid-precondition")
                    self.namespace = None
        else:
            if args[:2] == ["sandbox", "create"]:
                self.active = {
                    "status": "effective",
                    "version": 7,
                    "active_version": 7,
                    "hash": "policy-hash",
                    "policy": json.loads(Path(args[args.index("--policy") + 1]).read_bytes()),
                }
                self.pods = []
                for role in ("supervisor", "workload"):
                    labels = {
                        "openshell.ai/boundary-role": role,
                        "openshell.ai/boundary-pair": "pair-1",
                    }
                    if role == "supervisor":
                        labels["openshell.ai/sandbox-id"] = "sandbox-1"
                    self.pods.append(
                        {
                            "metadata": {
                                "name": role,
                                "namespace": self.config.target_namespace,
                                "uid": role + "-uid",
                                "labels": labels,
                            },
                            "spec": {"containers": [{"name": role, "image": IMAGE}]},
                            "status": {
                                "phase": "Running",
                                "containerStatuses": [
                                    {
                                        "name": role,
                                        "ready": True,
                                        "restartCount": 0,
                                        "imageID": IMAGE,
                                    }
                                ],
                            },
                        }
                    )
            elif args[:2] == ["sandbox", "get"]:
                result = {"id": "sandbox-1"}
            elif args[:2] == ["policy", "get"]:
                result = self.active
            elif args[:2] == ["sandbox", "exec"]:
                if PROBE_PATH == args[-1]:
                    return ProcessResult(
                        0, (self.config.probe_digest[7:] + "  " + PROBE_PATH).encode()
                    )
                name = "allowed" if args[-4] == "127.0.0.1" else "forbidden"
                if name == "allowed" or "forbidden" in self.active["policy"]["network_policies"]:
                    self.counts[name] += 1
                if self.fault == "restart":
                    self.receivers["allowed"]["status"]["containerStatuses"][0]["restartCount"] = 1
                if self.fault == "cancel-after-probe":
                    cancelled.set()
                return ProcessResult(0, ("agent-boundary-gate-probe-complete:" + args[-2]).encode())
            elif args[:2] == ["sandbox", "delete"]:
                raise AssertionError("name-based-delete-must-never-be-used")
        return ProcessResult(0, json.dumps(result).encode())


class DevelopmentRunTests(unittest.TestCase):
    def assert_closed(self, fd):
        with self.assertRaises(OSError):
            os.fstat(fd)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        source = self.root / "binary"
        source.write_bytes(b"synthetic-command")
        self.config = DevelopmentRunConfig(
            target_namespace="development-target",
            receiver_image=IMAGE,
            workload_image=IMAGE,
            openshell_executable=source,
            kubernetes_executable=source,
            openshell_digest=bytes_digest(source.read_bytes()),
            kubernetes_digest=bytes_digest(source.read_bytes()),
            cleanup_executable=source,
            cleanup_digest=bytes_digest(source.read_bytes()),
            probe_digest="sha256:" + "b" * 64,
            context="private-test",
            gateway="private-test",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def runner(self):
        runner = FakeRunner(self.config, self.root / "campaign")
        self.addCleanup(runner.close)
        return runner

    def test_pair_completes_with_private_journal_and_no_release_authority(self):
        runner = self.runner()
        result = runner.run(Event())
        self.assertTrue(result["development_campaign_completed"])
        self.assertEqual(
            [(p["allowed_count"], p["forbidden_count"]) for p in result["profiles"]],
            [(1, 0), (1, 1)],
        )
        self.assertFalse(result["release_eligible"])
        self.assertIsNone(runner.namespace)
        self.assertEqual(runner.pods, [])
        self.assertEqual((runner.output / "journal.json").stat().st_mode & 0o777, 0o600)
        deletes = [
            a for k, a, _ in runner.calls if k == "openshell" and a[:2] == ["sandbox", "delete"]
        ]
        self.assertEqual(deletes, [])
        cleanup = [data for kind, _, data in runner.calls if kind == "cleanup"]
        self.assertEqual(len(cleanup), 2)
        self.assertTrue(
            all(c["sandbox_id"] == "sandbox-1" and "sandbox_name" not in c for c in cleanup)
        )

    def test_missing_identity_bound_cleanup_stops_before_any_allocation(self):
        config = self.config.model_copy(update={"cleanup_executable": None, "cleanup_digest": None})
        with FakeRunner(config, self.root / "no-cleanup") as runner:
            result = runner.run(Event())
            self.assertFalse(result["development_campaign_completed"])
            self.assertEqual(result["error"], "identity-bound-cleanup-required")
            self.assertEqual(runner.calls, [])
            self.assertEqual(runner.state["allocations"], [])
            with self.assertRaisesRegex(ValueError, "identity-bound-cleanup-required"):
                runner.profile(False, Event())

    def test_cleanup_helper_requires_paired_and_matching_digest_pin(self):
        with self.assertRaises(ValueError):
            DevelopmentRunConfig.model_validate(
                {**self.config.model_dump(), "cleanup_digest": None}
            )
        with self.assertRaisesRegex(ValueError, "development-executable-digest-mismatch"):
            DevelopmentRunner(
                self.config.model_copy(update={"cleanup_digest": "sha256:" + "f" * 64}),
                self.root / "wrong-cleanup-pin",
            )

    def test_mismatched_cleanup_response_keeps_receivers_and_withholds_success(self):
        runner = self.runner()
        runner.fault = "cleanup-response-mismatch"
        result = runner.run(Event())
        self.assertFalse(result["development_campaign_completed"])
        self.assertFalse(result["profiles"][0]["cleanup_complete"])
        self.assertIsNotNone(runner.namespace)

    def test_same_name_replacement_is_not_selected_for_cleanup(self):
        runner = self.runner()
        command = runner.command
        replacement = {
            "metadata": {
                "uid": "replacement-uid",
                "labels": {"openshell.ai/boundary-pair": "different-pair"},
            }
        }

        def reuse_name(kind, args, **kwargs):
            if kind == "cleanup":
                # A different target now owns the old name. Deletion still selects
                # only the original registered ID/UIDs; the name is not a selector.
                runner.pods.append(replacement)
            return command(kind, args, **kwargs)

        with patch.object(runner, "command", reuse_name):
            report = runner.profile(False, Event())
        self.assertTrue(report["cleanup_complete"])
        self.assertEqual(runner.pods, [replacement])
        self.assertFalse(any(a[:2] == ["sandbox", "delete"] for _, a, _ in runner.calls))

    def test_late_forbidden_effect_survives_target_cleanup(self):
        runner = self.runner()
        runner.late = True
        result = runner.run(Event())
        self.assertFalse(result["development_campaign_completed"])
        self.assertEqual(result["profiles"][0]["forbidden_count"], 1)
        self.assertTrue(result["profiles"][0]["sampled_after_target_cleanup"])

    def test_capture_loss_and_restart_withhold_success(self):
        for fault in ("capture-loss", "restart"):
            with self.subTest(fault=fault):
                runner = FakeRunner(self.config, self.root / fault)
                try:
                    runner.fault = fault
                    result = runner.run(Event())
                    self.assertFalse(result["development_campaign_completed"])
                    self.assertTrue(result["profiles"][0]["cleanup_complete"])
                finally:
                    runner.close()

    def test_ambiguous_create_keeps_receivers_and_requires_reconciliation(self):
        runner = self.runner()
        runner.fault = "create-timeout"
        result = runner.run(Event())
        self.assertFalse(result["profiles"][0]["cleanup_complete"])
        self.assertIsNotNone(runner.namespace)
        self.assertFalse(any(a[0] == "delete" for _, a, _ in runner.calls))
        self.assertFalse(runner.recover()["development_cleanup_complete"])

    def test_recovery_is_idempotent_and_config_changes_rejected(self):
        runner = self.runner()
        runner.run(Event())
        runner.close()
        recovered = FakeRunner(self.config, self.root / "campaign", recover=True)
        try:
            self.assertTrue(recovered.recover()["development_cleanup_complete"])
            self.assertTrue(recovered.recover()["development_cleanup_complete"])
            self.assertFalse(any(a[0] == "delete" for _, a, _ in recovered.calls))
        finally:
            recovered.close()
        changed = self.config.model_copy(update={"gateway": "different"})
        with self.assertRaises(ValueError):
            FakeRunner(changed, self.root / "campaign", recover=True)

    def test_cancelled_profile_runs_cleanup_in_independent_scope(self):
        runner = self.runner()
        cancelled = Event()
        cancelled.set()
        report = runner.profile(False, cancelled)
        self.assertFalse(report["expected_behavior_observed"])
        # No identity was returned by create; no unsafe deletion is attempted.
        self.assertFalse(report["cleanup_complete"])

    def test_wrong_binary_pin_and_parallel_recovery_are_rejected(self):
        with self.assertRaises(ValueError):
            DevelopmentRunner(
                self.config.model_copy(update={"openshell_digest": "sha256:" + "f" * 64}),
                self.root / "wrong",
            )
        runner = self.runner()
        with self.assertRaises(BlockingIOError):
            DevelopmentRunner(self.config, runner.output, recover=True)

    def test_context_releases_lock_on_success_and_exception(self):
        output = self.root / "managed"
        with DevelopmentRunner(self.config, output) as runner:
            fd = runner.lock
        self.assert_closed(fd)
        with self.assertRaisesRegex(RuntimeError, "synthetic-body-failure"):
            with DevelopmentRunner(self.config, output, recover=True) as runner:
                fd = runner.lock
                raise RuntimeError("synthetic-body-failure")
        self.assert_closed(fd)
        with DevelopmentRunner(self.config, output, recover=True):
            pass

    def test_abandoned_runner_releases_lock_without_cluster_commands(self):
        output = self.root / "abandoned"
        runner = DevelopmentRunner(self.config, output)
        fd, reference = runner.lock, weakref.ref(runner)
        del runner
        gc.collect()
        self.assertIsNone(reference())
        self.assert_closed(fd)
        with DevelopmentRunner(self.config, output, recover=True):
            pass

    def test_failed_initialization_releases_acquired_lock(self):
        acquired = []

        def fail_after_lock(instance):
            acquired.append(instance.lock)
            raise ValueError("synthetic-initialization-failure")

        with patch.object(DevelopmentRunner, "save", fail_after_lock):
            with self.assertRaisesRegex(ValueError, "synthetic-initialization-failure"):
                DevelopmentRunner(self.config, self.root / "failed-init")
        self.assert_closed(acquired[0])

    def test_close_is_idempotent_and_does_not_close_reused_descriptor(self):
        runner = DevelopmentRunner(self.config, self.root / "closed")
        fd = runner.lock
        runner.close()
        self.assert_closed(fd)
        with (self.root / "binary").open("rb") as replacement:
            runner.close()
            os.fstat(replacement.fileno())
        with self.assertRaisesRegex(ValueError, "development-runner-closed"):
            with runner:
                pass

    def test_close_failure_does_not_mask_body_error_or_retry_descriptor(self):
        runner = DevelopmentRunner(self.config, self.root / "close-failure")
        fd = runner.lock
        runner._lock_finalizer.detach()
        failing_close = Mock(side_effect=OSError)
        try:
            with patch.object(runner, "_lock_finalizer", failing_close):
                with self.assertRaisesRegex(RuntimeError, "synthetic-body-failure") as raised:
                    with runner:
                        raise RuntimeError("synthetic-body-failure")
            self.assertEqual(raised.exception.__notes__, ["development-runner-lock-close-failed"])
            runner.close()
            failing_close.assert_called_once_with()
            self.assertIsNotNone(os.fstat(fd))
        finally:
            # The injected failure did not close the real descriptor.
            os.close(fd)

    def test_cancellation_after_execution_keeps_capture_and_cleans_registered_target(self):
        runner = self.runner()
        runner.fault = "cancel-after-probe"
        attempt_cancelled = Event()
        cleanup_events = []
        command = runner.command

        def inspect_cleanup_event(kind, args, **kwargs):
            if kind == "cleanup" or args[:1] == ["delete"]:
                cleanup_events.append(kwargs["cancelled"])
                self.assertTrue(attempt_cancelled.is_set())
                self.assertIsNot(kwargs["cancelled"], attempt_cancelled)
                self.assertFalse(kwargs["cancelled"].is_set())
            return command(kind, args, **kwargs)

        with patch.object(runner, "command", inspect_cleanup_event):
            result = runner.run(attempt_cancelled)
        self.assertTrue(attempt_cancelled.is_set())
        self.assertGreaterEqual(len(cleanup_events), 2)  # helper and Kubernetes deletion
        self.assertTrue(all(event is cleanup_events[0] for event in cleanup_events))
        self.assertFalse(result["development_campaign_completed"])
        self.assertTrue(result["profiles"][0]["cleanup_complete"])
        self.assertEqual(result["profiles"][0]["allowed_count"], 1)
        self.assertTrue(result["profiles"][0]["sampled_after_target_cleanup"])

    def test_killed_writer_pending_file_does_not_block_recovery(self):
        runner = self.runner()
        runner.run(Event())
        pending = runner.output / "journal.pending"
        pending.write_text('{"incomplete":')
        pending.chmod(0o600)
        runner.close()
        recovered = FakeRunner(self.config, runner.output, recover=True)
        try:
            self.assertFalse(pending.exists())
            self.assertTrue(recovered.recover()["development_cleanup_complete"])
        finally:
            recovered.close()

    def test_invalid_journal_is_rejected_before_running_commands(self):
        runner = self.runner()
        runner.close()
        (runner.output / "journal.json").write_text("[]")
        with self.assertRaises(ValueError):
            DevelopmentRunner(self.config, runner.output, recover=True)

    def test_recovery_does_not_upgrade_attempt_that_failed_cleanup(self):
        runner = self.runner()
        runner.fault = "cleanup-failure"
        result = runner.run(Event())
        self.assertFalse(result["profiles"][0]["cleanup_complete"])
        runner.fault = None
        self.assertTrue(runner.recover()["development_cleanup_complete"])
        allocation = runner.state["allocations"][0]
        self.assertEqual(allocation["counts"], {"allowed": 1, "forbidden": 0})
        self.assertFalse(runner.report(allocation)["expected_behavior_observed"])

    def test_replacement_namespace_is_never_deleted(self):
        runner = self.runner()
        runner.namespace = {"metadata": {"uid": "replacement"}}
        allocation = {
            "run": "gate-dev-0123456789abcdef",
            "profile": "healthy",
            "namespace_uid": "original",
            "receiver_uids": {},
        }
        runner.cleanup(allocation)
        self.assertFalse(allocation["cleanup_complete"])
        self.assertFalse(any(a[0] == "delete" for _, a, _ in runner.calls))
