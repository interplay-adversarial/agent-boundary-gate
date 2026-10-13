"""UID-conditioned cell retirement, controller loss and ambiguous inner creates."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

from test_development_run import IMAGE, FakeRunner

from agent_boundary_gate.development_run import DevelopmentRunConfig, DevelopmentRunner
from agent_boundary_gate.evidence import bytes_digest
from agent_boundary_gate.process import AttemptStopped, ProcessResult


class CellRunner(FakeRunner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cell = None
        self.cell_fault = None
        self.cleanup_events = []
        self.deletion_polls = None

    def command(
        self, kind, args, *, deadline, cancelled, data=None, check=True, allocation_context=None
    ):
        if kind == "cell-bootstrap":
            self.calls.append((kind, args, data))
            if self.cell_fault == "bootstrap-timeout":
                raise AttemptStopped("timeout")
            return ProcessResult(
                0, json.dumps({**data, "ready": self.cell_fault != "bad-bootstrap"}).encode()
            )
        if kind == "kubernetes":
            if (
                args[0] == "create"
                and data.get("kind") == "Namespace"
                and data["metadata"]["name"].startswith("gate-cell-")
            ):
                self.calls.append((kind, args, data))
                self.cell = {"metadata": {**data["metadata"], "uid": "cell-uid"}}
                if self.cell_fault == "namespace-timeout":
                    raise AttemptStopped("timeout")
                return ProcessResult(0, json.dumps(self.cell).encode())
            if args[:2] == ["get", "namespace"] and args[2].startswith("gate-cell-"):
                self.calls.append((kind, args, data))
                if self.deletion_polls is not None:
                    allocation = self.state["allocations"][-1]
                    assert allocation.get("cell_absent") is not True
                    assert allocation.get("target_absent") is not True
                    assert allocation.get("final_capture") is not True
                    self.deletion_polls -= 1
                    if self.deletion_polls == 0:
                        self.cell = None
                        self.pods = []
                        self.deletion_polls = None
                return ProcessResult(0, json.dumps(self.cell or {}).encode())
            if args[0] == "delete" and args[2].startswith("/api/v1/namespaces/gate-cell-"):
                self.calls.append((kind, args, data))
                self.cleanup_events.append(cancelled)
                if self.cell_fault == "delete-timeout":
                    raise AttemptStopped("timeout")
                if self.cell_fault == "reuse-at-delete":
                    self.cell["metadata"]["uid"] = "replacement-uid"
                if data["preconditions"]["uid"] != self.cell["metadata"]["uid"]:
                    raise ValueError("api-uid-conflict")
                if self.late:
                    self.counts["forbidden"] += 1
                if self.cell_fault == "delete-delayed":
                    self.cell["metadata"]["deletionTimestamp"] = "synthetic-termination"
                    self.deletion_polls = 2
                    return ProcessResult(0, b"{}")
                self.cell = None
                self.pods = []
                return ProcessResult(0, b"{}")
        result = super().command(
            kind,
            args,
            deadline=deadline,
            cancelled=cancelled,
            data=data,
            check=check,
            allocation_context=allocation_context,
        )
        if kind == "openshell" and args[:2] == ["sandbox", "create"]:
            for pod in self.pods:
                pod["metadata"]["namespace"] = self.state["allocations"][-1]["cell_name"]
        return result


class DevelopmentCellTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        source = self.root / "binary"
        source.write_bytes(b"synthetic-cell-bootstrap")
        digest = bytes_digest(source.read_bytes())
        self.config = DevelopmentRunConfig(
            target_namespace="protected-shared-target",
            receiver_image=IMAGE,
            workload_image=IMAGE,
            openshell_executable=source,
            openshell_digest=digest,
            kubernetes_executable=source,
            kubernetes_digest=digest,
            cell_bootstrap_executable=source,
            cell_bootstrap_digest=digest,
            probe_digest="sha256:" + "b" * 64,
            context="synthetic",
            gateway="protected-shared-gateway",
        )

    def runner(self):
        runner = CellRunner(self.config, self.root / "campaign")
        self.addCleanup(runner.close)
        return runner

    def test_fresh_cells_complete_pair_before_receivers_deleted(self):
        runner = self.runner()
        result = runner.run(Event())
        self.assertTrue(result["development_campaign_completed"])
        allocations = runner.state["allocations"]
        self.assertNotEqual(allocations[0]["cell_name"], allocations[1]["cell_name"])
        for allocation in allocations:
            self.assertTrue(allocation["cell_absent"])
            self.assertTrue(allocation["final_capture"])
            self.assertNotIn("target_absent", allocation)
        calls = runner.calls
        for i, (kind, args, data) in enumerate(calls):
            if kind == "kubernetes" and args[0] == "delete" and "gate-cell-" in args[2]:
                self.assertEqual(data["preconditions"], {"uid": "cell-uid"})
                self.assertTrue(
                    any(k == "kubernetes" and a[0] == "exec" for k, a, _ in calls[i + 1 :])
                )
        self.assertFalse(any(k == "cleanup" for k, _, _ in calls))
        self.assertFalse(result["release_eligible"])

    def test_name_reuse_at_mutation_rejected_and_receivers_retained(self):
        runner = self.runner()
        runner.cell_fault = "reuse-at-delete"
        result = runner.run(Event())
        self.assertFalse(result["development_campaign_completed"])
        self.assertEqual(runner.cell["metadata"]["uid"], "replacement-uid")
        self.assertIsNotNone(runner.namespace)
        self.assertFalse(runner.state["allocations"][0].get("final_capture", False))

    def test_ambiguous_sandbox_create_retires_registered_cell(self):
        runner = self.runner()
        runner.fault = "create-timeout"
        result = runner.run(Event())
        self.assertFalse(result["development_campaign_completed"])
        self.assertTrue(result["profiles"][0]["cleanup_complete"])
        self.assertIsNone(runner.cell)
        self.assertIsNone(runner.namespace)
        self.assertTrue(runner.state["allocations"][0]["failed"])
        self.assertEqual(runner.state["allocations"][0]["retired_pending"], "sandbox")
        self.assertIsNone(runner.state["allocations"][0]["pending"])
        self.assertTrue(result["profiles"][0]["sampled_after_target_cleanup"])
        self.assertEqual(runner.state["allocations"][0]["counts"], {"allowed": 0, "forbidden": 0})

    def test_delete_acceptance_does_not_claim_cell_absence_or_start_capture(self):
        runner = self.runner()
        runner.cell_fault = "delete-delayed"
        report = runner.profile(False, Event())
        self.assertTrue(report["expected_behavior_observed"])
        allocation = runner.state["allocations"][0]
        self.assertTrue(allocation["cell_absent"])
        self.assertNotIn("target_absent", allocation)
        self.assertTrue(allocation["final_capture"])

    def test_partial_receiver_registration_cannot_claim_complete_final_capture(self):
        runner = self.runner()
        with patch.object(runner, "cleanup"):
            runner.profile(False, Event())
        allocation = runner.state["allocations"][0]
        del allocation["receiver_uids"]["forbidden"]
        runner.cleanup(allocation)
        self.assertTrue(allocation["cell_absent"])
        self.assertTrue(allocation["capture_lost"])
        self.assertFalse(allocation.get("final_capture", False))
        self.assertFalse(runner.report(allocation)["expected_behavior_observed"])

    def test_uncertain_namespace_create_never_adopts_by_name(self):
        runner = self.runner()
        runner.cell_fault = "namespace-timeout"
        self.assertFalse(runner.run(Event())["development_campaign_completed"])
        self.assertFalse(runner.recover()["development_cleanup_complete"])
        self.assertIsNotNone(runner.cell)
        self.assertFalse(any(a[0] == "delete" for _, a, _ in runner.calls))

    def test_bootstrap_timeout_or_mismatch_retires_registered_namespace(self):
        for fault in ("bootstrap-timeout", "bad-bootstrap"):
            with self.subTest(fault=fault):
                with CellRunner(self.config, self.root / fault) as runner:
                    runner.cell_fault = fault
                    result = runner.run(Event())
                    self.assertFalse(result["development_campaign_completed"])
                    self.assertTrue(result["profiles"][0]["cleanup_complete"])
                    self.assertIsNone(runner.cell)
                    allocation = runner.state["allocations"][0]
                    self.assertEqual(allocation["retired_pending"], "cell-bootstrap")
                    self.assertIsNone(allocation["pending"])
                    self.assertTrue(allocation["failed"])

    def test_receiver_create_uncertainty_is_not_resolved_by_cell_retirement(self):
        runner = self.runner()
        command = runner.command

        def timeout(kind, args, **kwargs):
            result = command(kind, args, **kwargs)
            data = kwargs.get("data")
            if (
                kind == "kubernetes"
                and args[0] == "create"
                and data.get("kind") == "Namespace"
                and data["metadata"]["name"].startswith("gate-dev-")
            ):
                raise AttemptStopped("timeout")
            return result

        with patch.object(runner, "command", timeout):
            result = runner.run(Event())
        allocation = runner.state["allocations"][0]
        self.assertTrue(allocation["cell_absent"])
        self.assertEqual(allocation["pending"], "namespace")
        self.assertNotIn("retired_pending", allocation)
        self.assertFalse(result["profiles"][0]["cleanup_complete"])
        self.assertIsNotNone(runner.namespace)

    def test_controller_crash_recovery_retires_cell_without_rerunning_bootstrap(self):
        runner = self.runner()
        with patch.object(runner, "cleanup"):
            runner.profile(False, Event())
        state = (
            copy.deepcopy(runner.cell),
            copy.deepcopy(runner.namespace),
            copy.deepcopy(runner.receivers),
            copy.deepcopy(runner.pods),
            copy.deepcopy(runner.counts),
        )
        runner.close()
        with CellRunner(self.config, self.root / "campaign", recover=True) as recovered:
            (
                recovered.cell,
                recovered.namespace,
                recovered.receivers,
                recovered.pods,
                recovered.counts,
            ) = state
            self.assertTrue(recovered.recover()["development_cleanup_complete"])
            self.assertFalse(
                any(k == "cell-bootstrap" or k == "openshell" for k, _, _ in recovered.calls)
            )
            self.assertTrue(recovered.recover()["development_cleanup_complete"])

    def test_delete_timeout_recovery_keeps_failed_evaluation_latched(self):
        runner = self.runner()
        runner.cell_fault = "delete-timeout"
        self.assertFalse(runner.run(Event())["development_campaign_completed"])
        self.assertIsNotNone(runner.namespace)
        runner.cell_fault = None
        self.assertTrue(runner.recover()["development_cleanup_complete"])
        self.assertFalse(
            runner.report(runner.state["allocations"][0])["expected_behavior_observed"]
        )

    def test_cleanup_has_fresh_scope_after_attempt_cancelled(self):
        runner = self.runner()
        cancelled = Event()
        with patch.object(runner, "cleanup"):
            runner.profile(False, cancelled)
        cancelled.set()
        runner.cleanup(runner.state["allocations"][0])
        self.assertTrue(runner.state["allocations"][0]["cleanup_complete"])
        self.assertTrue(runner.cleanup_events)
        self.assertTrue(
            all(event is not cancelled and not event.is_set() for event in runner.cleanup_events)
        )

    def test_late_effect_preserved_after_cell_retirement(self):
        runner = self.runner()
        runner.late = True
        report = runner.profile(False, Event())
        self.assertEqual(report["forbidden_count"], 1)
        self.assertFalse(report["expected_behavior_observed"])
        self.assertTrue(report["sampled_after_target_cleanup"])

    def test_pins_mutually_exclusive_and_paired(self):
        raw = self.config.model_dump()
        with self.assertRaises(ValueError):
            DevelopmentRunConfig.model_validate({**raw, "cell_bootstrap_digest": None})
        with self.assertRaises(ValueError):
            DevelopmentRunConfig.model_validate(
                {
                    **raw,
                    "cleanup_executable": raw["cell_bootstrap_executable"],
                    "cleanup_digest": raw["cell_bootstrap_digest"],
                }
            )

    def test_openshell_commands_use_cell_gateway_alias(self):
        runner = self.runner()
        with patch.object(runner, "cleanup"):
            runner.profile(False, Event())
        with patch(
            "agent_boundary_gate.development_run.bounded_process",
            return_value=ProcessResult(0, b"{}"),
        ) as process:
            DevelopmentRunner.command(
                runner,
                "openshell",
                ["sandbox", "list"],
                deadline=1e20,
                cancelled=Event(),
                allocation_context=runner.state["allocations"][0],
            )
        self.assertEqual(
            process.call_args.args[0][1:3],
            ["--gateway", runner.state["allocations"][0]["cell_name"]],
        )

    def test_earlier_allocation_command_never_uses_latest_gateway(self):
        runner = self.runner()
        runner.run(Event())
        earlier, later = runner.state["allocations"]
        with patch(
            "agent_boundary_gate.development_run.bounded_process",
            return_value=ProcessResult(0, b"{}"),
        ) as process:
            DevelopmentRunner.command(
                runner,
                "openshell",
                ["sandbox", "list"],
                deadline=1e20,
                cancelled=Event(),
                allocation_context=earlier,
            )
        self.assertEqual(process.call_args.args[0][1:3], ["--gateway", earlier["cell_name"]])
        self.assertNotEqual(earlier["cell_name"], later["cell_name"])

    def test_cell_command_without_owned_allocation_context_fails_before_execution(self):
        runner = self.runner()
        runner.run(Event())
        with patch("agent_boundary_gate.development_run.bounded_process") as process:
            for allocation in (None, dict(runner.state["allocations"][0])):
                with self.assertRaisesRegex(ValueError, "development-allocation-context-required"):
                    DevelopmentRunner.command(
                        runner,
                        "openshell",
                        ["sandbox", "list"],
                        deadline=1e20,
                        cancelled=Event(),
                        allocation_context=allocation,
                    )
            process.assert_not_called()

    def test_protected_namespace_cannot_be_retired_even_with_registered_uid(self):
        runner = self.runner()
        allocation = {
            "run": "gate-dev-0123456789abcdef",
            "cell_name": self.config.target_namespace,
            "cell_uid": "cell-uid",
            "receiver_uids": {},
        }
        runner.state["allocations"].append(allocation)
        runner.cleanup(allocation)
        self.assertFalse(allocation["cleanup_complete"])
        self.assertEqual(runner.calls, [])

    def test_recovery_rejects_cell_names_outside_owned_prefix(self):
        runner = self.runner()
        runner.run(Event())
        runner.state["allocations"][0]["cell_name"] = self.config.target_namespace
        runner.save()
        runner.close()
        with self.assertRaisesRegex(ValueError, "development-recovery-cell-invalid"):
            CellRunner(self.config, self.root / "campaign", recover=True)

    def test_original_shared_gateway_config_digest_remains_recoverable(self):
        config = self.config.model_copy(
            update={
                "cell_bootstrap_executable": None,
                "cell_bootstrap_digest": None,
                "cleanup_executable": self.config.cell_bootstrap_executable,
                "cleanup_digest": self.config.cell_bootstrap_digest,
            }
        )
        output = self.root / "legacy-config"
        with FakeRunner(config, output) as runner:
            runner.run(Event())
            original_json = config.model_dump_json(
                exclude={"cell_bootstrap_executable", "cell_bootstrap_digest"}
            )
            runner.state["config_digest"] = bytes_digest(original_json.encode())
            runner.save()
        with FakeRunner(config, output, recover=True) as recovered:
            self.assertTrue(recovered.recover()["development_cleanup_complete"])
