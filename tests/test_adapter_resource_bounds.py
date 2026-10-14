"""Real blocked host commands and hostile HTTP clients; synthetic authority only."""

import json
import os
import socket
import sys
import tempfile
import time
import unittest
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Thread
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from receipt_support import FakeReceiptBroker, lease_and_binding

from agent_boundary_gate.auth import digest
from agent_boundary_gate.backends.fixture import LoopbackBackend
from agent_boundary_gate.backends.openshell import OpenShellBackend
from agent_boundary_gate.case_registry import load_case
from agent_boundary_gate.command_transport import CommandTransport
from agent_boundary_gate.evidence import EvidenceStore, bytes_digest
from agent_boundary_gate.fixtures import fixture
from agent_boundary_gate.gate_policy import evaluate
from agent_boundary_gate.lifecycle import AttemptControl, run_attempt
from agent_boundary_gate.observers.denied_egress import DeniedEgressObserver
from agent_boundary_gate.probe_delivery import (
    DeliveryVerifier,
    RustProbeArtifact,
    RustProbeDeployment,
)
from agent_boundary_gate.process import AttemptStopped, ProcessResult, bounded_process
from agent_boundary_gate.receipts import ReceiptRejected
from agent_boundary_gate.rig_authority import CommandAuthorityClient
from agent_boundary_gate.rig_receivers import ReceiverService

ROOT = Path(__file__).resolve().parents[1]


class AdapterResourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = EvidenceStore(self.root / "evidence")

    def command(self, script):
        path = self.root / "provider"
        path.write_text(f"#!{sys.executable}\n" + script)
        return CommandTransport(
            executable=str(path), executable_digest=bytes_digest(path.read_bytes())
        )

    def test_command_round_trip_retains_signed_receipt_and_verifies_independently(self):
        lease, _ = lease_and_binding()
        broker = FakeReceiptBroker(cleanup=True)
        request = broker.verifier.request("readiness", lease)
        raw = broker.fetch(request, deadline=time.monotonic() + 2, cancelled=Event())
        client = CommandAuthorityClient(
            self.command(
                f"import sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write({raw!r})\n"
            ),
            self.store,
        )
        result = client.fetch(request, deadline=time.monotonic() + 2, cancelled=Event())
        self.assertEqual(result, raw)
        self.assertEqual(
            broker.verifier.verify(result, request=request, now=datetime.now(UTC)).claim.state,
            "ready",
        )
        replacement = broker.verifier.request("readiness", lease)
        with self.assertRaises(ReceiptRejected):
            broker.verifier.verify(result, request=replacement, now=datetime.now(UTC))
        with self.assertRaisesRegex(ValueError, "cleanup-request-required"):
            client.destroy(request, deadline=time.monotonic() + 2, cancelled=Event())

    def test_blocked_command_times_out_without_callback_cooperation(self):
        command = self.command("import time\ntime.sleep(60)\n")
        started = time.monotonic()
        with self.assertRaises(AttemptStopped) as caught:
            command.call(b"{}", deadline=started + 0.15, cancelled=Event())
        self.assertEqual(caught.exception.reason, "timeout")
        self.assertLess(time.monotonic() - started, 2)

    def test_running_command_cancellation_reaps_process(self):
        marker = self.root / "started"
        command = self.command(
            f"import os,time\nopen({str(marker)!r},'w').write(str(os.getpid()))\ntime.sleep(60)\n"
        )
        cancelled, finished = Event(), Event()
        errors = []

        def invoke():
            try:
                command.call(b"{}", deadline=time.monotonic() + 5, cancelled=cancelled)
            except AttemptStopped as error:
                errors.append(error.reason)
            finally:
                finished.set()

        worker = Thread(target=invoke)
        worker.start()
        try:
            limit = time.monotonic() + 2
            while not marker.exists() and time.monotonic() < limit:
                finished.wait(0.01)
            self.assertTrue(marker.exists())
            cancelled.set()
            self.assertTrue(finished.wait(2))
            self.assertEqual(errors, ["cancelled"])
            with self.assertRaises(ProcessLookupError):
                os.kill(int(marker.read_text()), 0)
        finally:
            cancelled.set()
            worker.join(timeout=2)

    def test_openshell_readiness_cleanup_and_delivery_use_hard_provider_deadlines(self):
        lease, binding = lease_and_binding()
        broker = FakeReceiptBroker(cleanup=True)
        provider = CommandAuthorityClient(self.command("import time\ntime.sleep(60)\n"))
        pin = "sha256:" + "a" * 64
        deployment = RustProbeDeployment(
            artifact=RustProbeArtifact(
                target="x86_64-unknown-linux-musl",
                binary_digest=pin,
                source_digest=pin,
                manifest_digest=pin,
            ),
            workload_image_digest=pin,
        )
        replies = [
            ProcessResult(0, b'{"id":"sandbox-1","phase":"Ready"}'),
            ProcessResult(
                0,
                json.dumps(
                    {
                        "sandbox": "gate-attempt-1",
                        "status": "loaded",
                        "hash": lease.effective_policy_digest,
                        "version": 3,
                        "active_version": 3,
                    }
                ).encode(),
            ),
        ]
        for phase in ("readiness", "cleanup", "delivery"):
            with self.subTest(phase=phase):
                executable = Path(sys.executable)
                driver = OpenShellBackend(
                    executable=executable,
                    executable_digest=bytes_digest(executable.read_bytes()),
                    gateway="rig",
                    sandbox="gate-attempt-1",
                    sandbox_uid=lease.component.instance_uid,
                    policy_digest=lease.effective_policy_digest,
                    policy_revision=3,
                    lease=lease,
                    receipt_provider=broker,
                    receipt_verifier=broker.verifier,
                    **(
                        {
                            "probe_runtime": "rust",
                            "rust_deployment": deployment,
                            "delivery_provider": provider,
                            "delivery_verifier": DeliveryVerifier({}),
                        }
                        if phase == "delivery"
                        else {}
                    ),
                )
                driver.require_binding(binding)
                if phase == "delivery":
                    with patch.object(driver, "_command", side_effect=replies):
                        self.assertTrue(
                            driver.readiness(deadline=time.monotonic() + 2, cancelled=Event()).ready
                        )
                else:
                    driver.receipt_provider = provider
                started = time.monotonic()
                with (
                    patch.object(
                        driver,
                        "_command",
                        side_effect=replies
                        if phase == "readiness"
                        else [ProcessResult(0, b'{"id":"sandbox-1"}'), ProcessResult(0, b"")],
                    ) as command,
                    self.assertRaises(AttemptStopped) as caught,
                ):
                    if phase == "readiness":
                        driver.readiness(deadline=started + 0.15, cancelled=Event())
                    elif phase == "cleanup":
                        driver.destroy(deadline=started + 0.15)
                    else:
                        action = load_case(ROOT / "examples/denied-egress-v1.json").actions[0]
                        driver.replay(
                            action,
                            "http://127.0.0.1:80/probe",
                            binding.attempt_id,
                            deadline=started + 0.15,
                            cancelled=Event(),
                        )
                        self.fail("blocked delivery must not authorize replay")
                self.assertEqual(caught.exception.reason, "timeout")
                self.assertLess(time.monotonic() - started, 2)
                if phase == "delivery":
                    command.assert_not_called()

    def test_command_flood_nonzero_empty_and_pin_changes_are_rejected(self):
        for script, expected in (
            ("import os\nwhile True: os.write(1,b'x'*65536)\n", "output-limit"),
            ("import sys\nprint('private failure');sys.exit(7)\n", "command-exit-nonzero"),
            ("pass\n", "command-empty-response"),
        ):
            with (
                self.subTest(expected=expected),
                self.assertRaisesRegex((ValueError, AttemptStopped), expected),
            ):
                self.command(script).call(b"{}", deadline=time.monotonic() + 2, cancelled=Event())
        command = self.command("print('{}')\n")
        Path(command.executable).write_text("changed")
        with self.assertRaisesRegex(ValueError, "command-pin-mismatch"):
            command.call(b"{}", deadline=time.monotonic() + 2, cancelled=Event())

    def test_stdout_boundary_and_fast_exit_preserve_exact_bytes(self):
        for count in (1, 8192, 65536):
            with self.subTest(count=count):
                result = bounded_process(
                    [sys.executable, "-c", f"import os;os.write(1,b'x'*{count})"],
                    deadline=time.monotonic() + 2,
                    cancelled=Event(),
                )
                self.assertEqual(result.stdout, b"x" * count)
        for limit in (0, -1, True, 16 * 1024 * 1024 + 1):
            with (
                self.subTest(limit=limit),
                self.assertRaisesRegex(ValueError, "process-output-limit-invalid"),
            ):
                bounded_process(
                    [sys.executable],
                    deadline=time.monotonic() + 1,
                    cancelled=Event(),
                    max_output=limit,
                )

    def test_exited_command_descendant_cannot_keep_stdout_open_or_publish_late(self):
        ready, late = self.root / "ready", self.root / "late"
        child = (
            f"from pathlib import Path;import time;Path({str(ready)!r}).touch();"
            f"time.sleep(0.4);Path({str(late)!r}).touch();time.sleep(60)"
        )
        script = (
            "import subprocess,sys,time\nfrom pathlib import Path\n"
            f"subprocess.Popen([sys.executable,'-c',{child!r}])\n"
            f"while not Path({str(ready)!r}).exists(): time.sleep(0.005)\n"
            "print('{}',flush=True)\n"
        )
        started = time.monotonic()
        self.assertEqual(
            self.command(script).call(b"{}", deadline=started + 2, cancelled=Event()), b"{}\n"
        )
        self.assertLess(time.monotonic() - started, 1)
        time.sleep(0.45)
        self.assertFalse(late.exists())

    def receiver(self, remote):
        if not remote:
            capture = DeniedEgressObserver("attempt-1", self.store)
            capture.start()
            return capture, capture.servers["forbidden"], lambda: capture.dropped_events
        lease, _ = lease_and_binding()
        capture = ReceiverService(
            leases=(lease,),
            identity="receiver",
            generation="generation-1",
            key=Ed25519PrivateKey.generate(),
            store=self.store,
            addresses={"allowed": ("127.0.0.1", 0), "forbidden": ("127.0.0.1", 0)},
        )
        capture.active = lease
        capture.start()
        return capture, capture.servers["forbidden"], lambda: capture.dropped

    def test_slow_drip_headers_cannot_extend_receiver_close(self):
        for remote in (False, True):
            with self.subTest(remote=remote):
                capture, server, losses = self.receiver(remote)
                server.request_budget = 0.2
                connection = socket.create_connection(server.server_address, timeout=1)
                stopped = Event()

                def drip(connection=connection, stopped=stopped):
                    try:
                        connection.sendall(b"GET /probe HTTP/1.0\r\nX-Slow: ")
                        while not stopped.wait(0.025):
                            connection.sendall(b"a")
                    except OSError:
                        pass

                worker = Thread(target=drip)
                worker.start()
                try:
                    time.sleep(0.05)
                    started = time.monotonic()
                    capture.stop()
                    self.assertLess(time.monotonic() - started, 1)
                    self.assertGreater(losses(), 0)
                    self.assertEqual(
                        sum(capture.counts.values()) if remote else len(capture.events), 0
                    )
                finally:
                    stopped.set()
                    connection.close()
                    worker.join(timeout=1)
                    capture.stop()

    def test_connection_saturation_is_finite_and_records_capture_loss(self):
        for remote in (False, True):
            with self.subTest(remote=remote):
                capture, server, losses = self.receiver(remote)
                admitted, release = Event(), Event()
                count = 0
                original = server.finish_request

                def blocked(*args, admitted=admitted, release=release, original=original):
                    nonlocal count
                    count += 1
                    if count == 8:
                        admitted.set()
                    release.wait(2)
                    original(*args)

                connections = []
                try:
                    with patch.object(server, "finish_request", side_effect=blocked):
                        connections = [
                            socket.create_connection(server.server_address, timeout=1)
                            for _ in range(8)
                        ]
                        self.assertTrue(admitted.wait(1))
                        with socket.create_connection(server.server_address, timeout=1) as extra:
                            self.assertEqual(extra.recv(1), b"")
                        self.assertEqual(count, 8)
                        self.assertGreater(losses(), 0)
                        for connection in connections:
                            connection.close()
                        release.set()
                        capture.stop()
                finally:
                    release.set()
                    for connection in connections:
                        connection.close()
                    capture.stop()

    def test_oversized_aggregate_headers_fail_closed(self):
        for remote in (False, True):
            with self.subTest(remote=remote):
                capture, server, losses = self.receiver(remote)
                try:
                    with socket.create_connection(server.server_address, timeout=1) as connection:
                        try:
                            connection.sendall(
                                b"GET /probe HTTP/1.0\r\n"
                                + b"X-Padding: "
                                + b"x" * 8000
                                + b"\r\n"
                                + (b"X: " + b"x" * 8000 + b"\r\n") * 8
                                + b"\r\n"
                            )
                            connection.recv(1024)
                        except (ConnectionResetError, BrokenPipeError):
                            pass
                    capture.stop()
                    self.assertGreater(losses(), 0)
                finally:
                    capture.stop()

    def test_observed_violation_survives_blocked_adapter_timeout(self):
        case = load_case(ROOT / "examples/denied-egress-v1.json")
        dispatch, _, _ = fixture("healthy")
        dispatch = dispatch.model_copy(
            update={
                "instances": (
                    dispatch.instances[0].model_copy(update={"case_spec_digest": digest(case)}),
                )
            }
        )
        capture = DeniedEgressObserver(dispatch.binding.attempt_id, self.store)
        key = Ed25519PrivateKey.generate()
        command = self.command("import time\ntime.sleep(60)\n")

        class BlockedAdapter(LoopbackBackend):
            def replay(self, action, url, attempt_id, *, deadline, cancelled):
                request = urllib.request.Request(url, headers={"X-Gate-Attempt": attempt_id})
                with urllib.request.urlopen(request, timeout=1):
                    pass
                if action.receiver == "forbidden":
                    command.call(
                        b"{}", deadline=min(deadline, time.monotonic() + 0.15), cancelled=cancelled
                    )
                return True

        record = run_attempt(
            dispatch,
            case,
            BlockedAdapter(dispatch.binding.effective_policy_digest),
            capture,
            self.store,
            key,
            "test-verifier",
            AttemptControl.for_fixture(dispatch.binding),
        )
        self.assertEqual(record.result.run_status.value, "timeout")
        self.assertEqual(record.evidence.observer_outcome, "violation")
        self.assertTrue(record.evidence.observed_effect_refs)
        decision = evaluate(
            dispatch,
            [record],
            {"test-verifier": key.public_key()},
            now=datetime.now(UTC),
            job_complete=True,
            server_aggregate=record.result.invariant_held,
        )
        self.assertNotEqual(decision.release_decision.value, "pass")
        self.assertFalse(decision.release_eligible)
