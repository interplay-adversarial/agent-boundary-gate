"""Independent allocator UID retention and conservative runner reconciliation."""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

from test_development_cell import CellRunner
from test_development_run import IMAGE

from agent_boundary_gate.development_run import DevelopmentRunConfig, _config_digest, _write
from agent_boundary_gate.evidence import bytes_digest
from agent_boundary_gate.namespace_allocation import (
    AllocationCall,
    AllocationRecord,
    NamespaceAllocationClient,
    NamespaceAllocator,
    NamespaceAllocatorConfig,
    NamespaceIntent,
)
from agent_boundary_gate.process import ProcessResult

ROOT = Path(__file__).resolve().parents[1]


class LedgerRunner(CellRunner):
    """Synthetic runtime/receiver behavior with the actual private UID service."""

    def command(self, kind, args, **kwargs):
        if kind == "kubernetes" and (args[:2] == ["get", "namespace"] or args[0] == "delete"):
            self.calls.append((kind, args, kwargs.get("data")))
            state_path = self.output.parent / "api-state.json"
            state = json.loads(state_path.read_text()) if state_path.exists() else {}
            name = args[2] if args[0] == "get" else args[2].rsplit("/", 1)[1]
            if args[0] == "delete" and name in state:
                if state[name]["metadata"]["uid"] != kwargs["data"]["preconditions"]["uid"]:
                    raise ValueError("synthetic-api-uid-conflict")
                del state[name]
                _write(state_path, state)
                self.pods = []
            return ProcessResult(
                0, json.dumps(state.get(name, {}) if args[0] == "get" else {}).encode()
            )
        return super().command(kind, args, **kwargs)


def controller(root):
    config = DevelopmentRunConfig.model_validate_json((root / "runner.json").read_bytes())
    with LedgerRunner(config, root / "campaign") as runner:
        runner.profile(False, Event())


class NamespaceAllocationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gate-alloc-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.children = []
        self.addCleanup(self.stop_children)
        api = self.root / "api"
        api.write_bytes(
            f"#!{sys.executable}\n".encode()
            + (ROOT / "tests/namespace_allocator_api.py").read_bytes()
        )
        api.chmod(0o500)
        pin = bytes_digest(api.read_bytes())
        self.allocator_config = NamespaceAllocatorConfig(
            socket_path=self.root / "a.sock",
            ledger_directory=self.root / "ledger",
            kubernetes_executable=api,
            kubernetes_digest=pin,
            context="synthetic",
            protected_namespaces=("protected-target",),
            command_seconds=5,
        )
        self.runner_config = DevelopmentRunConfig(
            target_namespace="protected-target",
            receiver_image=IMAGE,
            workload_image=IMAGE,
            openshell_executable=api,
            openshell_digest=pin,
            kubernetes_executable=api,
            kubernetes_digest=pin,
            cell_bootstrap_executable=api,
            cell_bootstrap_digest=pin,
            namespace_allocator_socket=self.allocator_config.socket_path,
            context="synthetic",
            gateway="protected-gateway",
            probe_digest="sha256:" + "a" * 64,
        )
        self.client = NamespaceAllocationClient(self.allocator_config.socket_path)

    def wait(self, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.01)
        self.fail("allocation-fixture-checkpoint-timeout")

    def launch(self, argv):
        child = subprocess.Popen(
            [sys.executable, *argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=os.environ
            | {
                "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT / "tests"))),
                "GATE_ALLOCATOR_FIXTURE": str(self.root),
            },
        )
        self.children.append(child)
        return child

    def stop(self, child, abrupt=False):
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL if abrupt else signal.SIGTERM)
            child.wait(timeout=5)

    def stop_children(self):
        (self.root / "block-response").unlink(missing_ok=True)
        for child in reversed(self.children):
            self.stop(child)

    def service(self):
        path = self.root / "allocator.json"
        _write(path, self.allocator_config.model_dump(mode="json"))
        child = self.launch(
            ["-m", "agent_boundary_gate.cli", "development-allocation-serve", "--config", str(path)]
        )

        def ready():
            self.assertIsNone(child.poll(), "allocator-exited-before-admission")
            try:
                with socket.socket(socket.AF_UNIX) as connection:
                    connection.connect(str(self.allocator_config.socket_path))
                    return True
            except (FileNotFoundError, ConnectionRefusedError):
                return False

        self.wait(ready)
        return child

    def intent(self, operation_id="a" * 32):
        return NamespaceIntent(
            operation_id=operation_id,
            config_digest=_config_digest(self.runner_config),
            context="synthetic",
            run="gate-dev-" + "b" * 16,
            namespace="gate-cell-" + "c" * 24,
            role="cell",
        )

    def call(self, operation, intent):
        return self.client.call(operation, intent, deadline=time.monotonic() + 3, cancelled=Event())

    def committed(self, intent):
        path = self.allocator_config.ledger_directory / (intent.operation_id + ".json")
        return path.exists() and json.loads(path.read_text())["state"] == "created"

    def test_controller_sigkill_after_api_create_recovers_independent_uid_without_replay(self):
        service = self.service()
        (self.root / "block-response").touch()
        _write(self.root / "runner.json", self.runner_config.model_dump(mode="json"))
        child = self.launch([str(Path(__file__).resolve()), str(self.root)])
        self.wait((self.root / "api-entered.json").exists)
        journal = json.loads((self.root / "campaign/journal.json").read_text())
        allocation = journal["allocations"][0]
        self.assertNotIn("cell_uid", allocation)
        intent = NamespaceIntent.model_validate(allocation["namespace_intents"]["cell"])
        self.stop(child, abrupt=True)
        self.assertIsNone(service.poll())
        (self.root / "block-response").unlink()
        self.wait(lambda: self.committed(intent))
        with LedgerRunner(self.runner_config, self.root / "campaign", recover=True) as recovered:
            result = recovered.recover()
            self.assertTrue(result["development_cleanup_complete"])
            self.assertFalse(result["release_eligible"])
            self.assertFalse(
                recovered.report(recovered.state["allocations"][0])["expected_behavior_observed"]
            )
            self.assertTrue(all(kind == "kubernetes" for kind, _, _ in recovered.calls))
            deletes = [data for _, args, data in recovered.calls if args[0] == "delete"]
            self.assertEqual(
                [d["preconditions"]["uid"] for d in deletes], ["uid-" + intent.namespace]
            )
            self.assertEqual(json.loads((self.root / "api-state.json").read_text()), {})

    def test_api_response_lost_remains_unresolved_and_never_retries_or_adopts(self):
        self.service()
        (self.root / "drop-response").touch()
        intent = self.intent()
        with self.assertRaises(ValueError):
            self.call("create", intent)
        self.assertFalse(self.committed(intent))
        (self.root / "drop-response").unlink()
        for operation in ("lookup", "create"):
            with self.assertRaisesRegex(ValueError, "unresolved"):
                self.call(operation, intent)
        state = json.loads((self.root / "api-state.json").read_text())
        self.assertEqual(state[intent.namespace]["metadata"]["uid"], "uid-" + intent.namespace)

    def test_allocator_sigkill_before_commit_leaves_unknown_uid_after_restart(self):
        child = self.service()
        (self.root / "block-response").touch()
        intent = self.intent()
        caller_code = (
            "import sys,time;from pathlib import Path;from threading import Event;"
            "from agent_boundary_gate.namespace_allocation import "
            "NamespaceAllocationClient,NamespaceIntent;"
            f"NamespaceAllocationClient(Path({str(self.allocator_config.socket_path)!r})).call('create',"
            f"NamespaceIntent.model_validate_json({intent.model_dump_json()!r}),deadline=time.monotonic()+10,cancelled=Event())"
        )
        caller = self.launch(["-c", caller_code])
        self.wait((self.root / "api-entered.json").exists)
        self.stop(child, abrupt=True)
        caller.wait(timeout=5)
        # Stale-socket removal is fixture-owned, only after its service is reaped.
        self.allocator_config.socket_path.unlink()
        (self.root / "block-response").unlink()
        self.service()
        with self.assertRaisesRegex(ValueError, "unresolved"):
            self.call("lookup", intent)
        self.assertFalse(self.committed(intent))

    def prepared_lost_response(self, role):
        self.service()
        runner = LedgerRunner(self.runner_config, self.root / "campaign")
        self.addCleanup(runner.close)
        client_call = runner.namespace_allocator.call

        def lose(operation, intent, **bounds):
            record = client_call(operation, intent, **bounds)
            if operation == "create" and intent.role == role:
                raise ValueError("synthetic-lost-delivery")
            return record

        with (
            patch.object(runner.namespace_allocator, "call", lose),
            patch.object(runner, "cleanup"),
        ):
            runner.profile(False, Event())
        return runner

    def test_receiver_lost_delivery_reconciles_uid_but_retains_capture_loss(self):
        runner = self.prepared_lost_response("receiver")
        self.assertTrue(runner.recover()["development_cleanup_complete"])
        allocation = runner.state["allocations"][0]
        self.assertTrue(allocation["cell_absent"])
        self.assertTrue(allocation["namespace_absent"])
        self.assertTrue(allocation["capture_lost"])
        self.assertFalse(runner.report(allocation)["expected_behavior_observed"])

    def test_same_name_replacement_is_neither_registered_nor_deleted(self):
        runner = self.prepared_lost_response("cell")
        allocation = runner.state["allocations"][0]
        state_path = self.root / "api-state.json"
        state = json.loads(state_path.read_text())
        state[allocation["cell_name"]]["metadata"]["uid"] = "replacement-uid"
        _write(state_path, state)
        self.assertFalse(runner.recover()["development_cleanup_complete"])
        self.assertNotIn("cell_uid", allocation)
        self.assertFalse(any(args[0] == "delete" for _, args, _ in runner.calls))

    def test_replacement_between_lookup_and_delete_is_rejected_by_api_precondition(self):
        runner = self.prepared_lost_response("cell")
        command = runner.command

        def replace_before_delete(kind, args, **kwargs):
            if kind == "kubernetes" and args[0] == "delete":
                state_path = self.root / "api-state.json"
                state = json.loads(state_path.read_text())
                name = args[2].rsplit("/", 1)[1]
                state[name]["metadata"]["uid"] = "raced-replacement"
                _write(state_path, state)
            return command(kind, args, **kwargs)

        with patch.object(runner, "command", replace_before_delete):
            self.assertFalse(runner.recover()["development_cleanup_complete"])
        state = json.loads((self.root / "api-state.json").read_text())
        self.assertEqual(next(iter(state.values()))["metadata"]["uid"], "raced-replacement")

    def test_legacy_cell_journal_digest_and_new_intent_binding_are_validated(self):
        config = self.runner_config.model_copy(update={"namespace_allocator_socket": None})
        self.assertEqual(
            _config_digest(config),
            bytes_digest(config.model_dump_json(exclude={"namespace_allocator_socket"}).encode()),
        )
        runner = self.prepared_lost_response("cell")
        allocation = runner.state["allocations"][0]
        intent = allocation["namespace_intents"]["cell"]
        intent["config_digest"] = "sha256:" + "0" * 64
        runner.save()
        runner.close()
        with self.assertRaisesRegex(ValueError, "namespace-intent-invalid"):
            LedgerRunner(self.runner_config, self.root / "campaign", recover=True)

    def test_allocator_restart_config_pin_exclusion_and_partial_commit_fail_closed(self):
        allocator = NamespaceAllocator(self.allocator_config)
        with self.assertRaises(BlockingIOError):
            NamespaceAllocator(self.allocator_config)
        allocator.close()
        with self.assertRaisesRegex(ValueError, "config-changed"):
            NamespaceAllocator(
                self.allocator_config.model_copy(update={"context": "another-context"})
            )
        pending = self.allocator_config.ledger_directory / ("a" * 32 + ".pending")
        _write(
            self.allocator_config.ledger_directory / ("a" * 32 + ".json"),
            AllocationRecord(intent=self.intent(), state="unresolved").model_dump(mode="json"),
        )
        pending.write_text(json.dumps({"state": "created", "uid": "uncommitted-uid"}))
        pending.chmod(0o600)
        self.assertTrue(pending.exists())
        allocator = NamespaceAllocator(self.allocator_config)
        self.addCleanup(allocator.close)
        self.assertFalse(pending.exists())
        reply = AllocationRecord.model_validate_json(
            allocator.handle(
                AllocationCall(operation="lookup", intent=self.intent()).model_dump_json().encode(),
                time.monotonic() + 2,
                Event(),
            )
        )
        self.assertEqual(reply.state, "unresolved")

    def test_disappeared_original_is_reconciled_without_deleting_replacement_by_name(self):
        runner = self.prepared_lost_response("cell")
        _write(self.root / "api-state.json", {})
        self.assertTrue(runner.recover()["development_cleanup_complete"])
        self.assertFalse(any(args[0] == "delete" for _, args, _ in runner.calls))

    def test_operation_binding_conflict_and_unknown_lookup_fail_closed(self):
        self.service()
        intent = self.intent()
        self.call("create", intent)
        with self.assertRaises(ValueError):
            self.call("lookup", intent.model_copy(update={"config_digest": "sha256:" + "e" * 64}))
        with self.assertRaisesRegex(ValueError, "unresolved"):
            self.call("lookup", self.intent("d" * 32))

    def test_allocator_storage_commit_failure_and_capacity_do_not_repeat_create(self):
        config = self.allocator_config.model_copy(update={"max_operations": 1})
        allocator = NamespaceAllocator(config)
        self.addCleanup(allocator.close)
        intent = self.intent()
        raw = AllocationCall(operation="create", intent=intent).model_dump_json().encode()
        write = _write

        def failed_write(path, value):
            if value.get("state") == "created":
                raise OSError("synthetic-receipt-write-failure")
            write(path, value)

        with patch.object(
            allocator,
            "create",
            return_value=AllocationRecord(intent=intent, state="created", uid="original-uid"),
        ) as create:
            with (
                patch("agent_boundary_gate.development_run._write", failed_write),
                self.assertRaises(OSError),
            ):
                allocator.handle(raw, time.monotonic() + 2, Event())
            reply = AllocationRecord.model_validate_json(
                allocator.handle(raw, time.monotonic() + 2, Event())
            )
            self.assertEqual(reply.state, "unresolved")
            self.assertEqual(create.call_count, 1)
            other = (
                AllocationCall(operation="create", intent=self.intent("f" * 32))
                .model_dump_json()
                .encode()
            )
            with self.assertRaisesRegex(ValueError, "capacity"):
                allocator.handle(other, time.monotonic() + 2, Event())


if __name__ == "__main__":
    controller(Path(sys.argv[1]))
