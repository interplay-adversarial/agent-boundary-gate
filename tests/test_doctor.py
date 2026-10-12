import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from receipt_support import lease_and_binding

from agent_boundary_gate.cli import main
from agent_boundary_gate.doctor import openshell_doctor, read_regular_input
from agent_boundary_gate.evidence import bytes_digest
from agent_boundary_gate.process import AttemptStopped, ProcessResult


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.executable = Path(self.temp.name) / "openshell"
        self.executable.write_bytes(b"synthetic-pinned-executable")
        self.lease, _ = lease_and_binding()
        self.options = dict(
            executable=self.executable,
            executable_digest=bytes_digest(self.executable.read_bytes()),
            gateway="rig",
            sandbox="gate-attempt-1",
            policy_revision=3,
            lease=self.lease,
        )
        self.metadata = {"id": self.lease.component.instance_uid, "phase": "Ready"}
        self.policy = {
            "sandbox": "gate-attempt-1",
            "status": "loaded",
            "version": 3,
            "active_version": 3,
            "hash": self.lease.effective_policy_digest.removeprefix("sha256:"),
        }

    def inspect(self, **changes):
        responses = [
            ProcessResult(0, json.dumps(item).encode()) for item in (self.metadata, self.policy)
        ]
        with patch("agent_boundary_gate.doctor.bounded_process", side_effect=responses) as runner:
            report = openshell_doctor(**(self.options | changes))
        return report, runner

    def test_matching_observations_use_only_get_and_do_not_establish_readiness(self):
        for runtime in ("python3", "perl"):
            report, runner = self.inspect(probe_runtime=runtime)
            self.assertEqual(report["status"], "observations-match")
            self.assertFalse(report["ready_for_attempt"])
            self.assertFalse(report["release_eligible"])
            self.assertEqual(report["probe-runtime"], "unverified")
            self.assertEqual(report["authenticated-readiness"], "unverified")
            self.assertEqual(
                runner.call_args_list[0].args[0][1:],
                ["--gateway", "rig", "sandbox", "get", "gate-attempt-1", "-o", "json"],
            )
            self.assertEqual(
                runner.call_args_list[1].args[0][1:],
                [
                    "--gateway",
                    "rig",
                    "policy",
                    "get",
                    "gate-attempt-1",
                    "--rev",
                    "3",
                    "--full",
                    "-o",
                    "json",
                ],
            )
            self.assertEqual(
                runner.call_args_list[0].kwargs["deadline"],
                runner.call_args_list[1].kwargs["deadline"],
            )

    def test_replacement_stops_before_policy_inspection(self):
        self.metadata["id"] = "same-name-replacement"
        report, runner = self.inspect()
        self.assertEqual(report["checks"]["sandbox-identity"], "mismatch")
        self.assertEqual(report["status"], "incompatible")
        self.assertEqual(runner.call_count, 1)

    def test_policy_mismatches_withhold_compatibility(self):
        for field, value in (
            ("sandbox", "other"),
            ("status", "superseded"),
            ("version", True),
            ("active_version", 2),
            ("version", "3"),
            ("hash", None),
            ("hash", {"private-label": "synthetic-private-value"}),
            ("hash", "a" * 64),
        ):
            with self.subTest(field=field, value=value):
                original = self.policy.copy()
                self.policy[field] = value
                report, _ = self.inspect()
                self.assertEqual(report["status"], "incompatible")
                self.assertNotIn("synthetic-private-value", json.dumps(report))
                self.policy = original
        self.policy["hash"] = self.lease.effective_policy_digest
        self.assertEqual(self.inspect()[0]["status"], "observations-match")

    def test_pin_and_lease_fail_before_running_cli(self):
        expired = self.lease.model_copy(
            update={"lease_expires_at": datetime.now(UTC) - timedelta(seconds=1)}
        )
        for changes in ({"executable_digest": "sha256:" + "0" * 64}, {"lease": expired}):
            report, runner = self.inspect(**changes)
            self.assertEqual(report["status"], "incompatible")
            runner.assert_not_called()

    def test_expiry_during_queries_is_not_reported_as_current(self):
        with patch("agent_boundary_gate.doctor.datetime") as clock:
            clock.now.side_effect = [datetime.now(UTC), self.lease.lease_expires_at]
            report, _ = self.inspect()
        self.assertEqual(report["checks"]["lease-current"], "expired")
        self.assertEqual(report["status"], "incompatible")

    def test_invalid_configuration_never_runs_cli(self):
        for changes in (
            {"gateway": "--private"},
            {"sandbox": "outside-lease-prefix"},
            {"policy_revision": True},
            {"policy_revision": 0},
            {"probe_runtime": "sh"},
            {"executable_digest": "invalid"},
            {"timeout_seconds": float("nan")},
            {"timeout_seconds": float("inf")},
            {"timeout_seconds": 61},
            {"timeout_seconds": 0},
            {"timeout_seconds": True},
        ):
            with (
                self.subTest(changes=changes),
                patch("agent_boundary_gate.doctor.bounded_process") as runner,
            ):
                with self.assertRaises(ValueError):
                    openshell_doctor(**(self.options | changes))
                runner.assert_not_called()

    def test_sanitized_process_and_json_errors(self):
        for response, expected in (
            (AttemptStopped("timeout"), "cli-timeout"),
            (AttemptStopped("output-limit"), "cli-output-limit"),
            (AttemptStopped("process-group-cleanup-not-confirmed"), "cli-group-cleanup-failed"),
            (OSError("synthetic-private-value"), "cli-start-failed"),
            (ProcessResult(1, b"synthetic-private-value"), "cli-exit-nonzero"),
            (ProcessResult(0, b"synthetic-private-value"), "cli-json-invalid"),
            (ProcessResult(0, b"[]"), "cli-json-invalid"),
            (ProcessResult(0, b"\xff"), "cli-json-invalid"),
        ):
            with self.subTest(expected=expected):
                kwargs = (
                    {"side_effect": response}
                    if isinstance(response, Exception)
                    else {"return_value": response}
                )
                with patch("agent_boundary_gate.doctor.bounded_process", **kwargs):
                    report = openshell_doctor(**self.options)
                self.assertEqual(report["error"], expected)
                self.assertNotIn("synthetic-private-value", json.dumps(report))

    def test_pin_change_between_queries_stops_inspection(self):
        def first_query(*args, **kwargs):
            self.executable.write_bytes(b"changed")
            return ProcessResult(0, json.dumps(self.metadata).encode())

        with patch("agent_boundary_gate.doctor.bounded_process", side_effect=first_query) as runner:
            report = openshell_doctor(**self.options)
        self.assertEqual(report["error"], "cli-pin-changed")
        self.assertEqual(runner.call_count, 1)

    def test_input_reads_reject_oversize_symlink_and_fifo(self):
        link = self.executable.with_name("link")
        link.symlink_to(self.executable)
        fifo = self.executable.with_name("fifo")
        os.mkfifo(fifo)
        for path in (self.executable, link, fifo):
            with self.subTest(path=path.name), self.assertRaises((OSError, ValueError)):
                read_regular_input(path, limit=1)

    def test_cli_prints_only_sanitized_report_and_exit_status(self):
        lease_file = self.executable.with_name("lease.json")
        lease_file.write_text(self.lease.model_dump_json())
        argv = [
            "gate",
            "doctor",
            "--executable",
            str(self.executable),
            "--executable-digest",
            self.options["executable_digest"],
            "--gateway",
            "rig",
            "--sandbox",
            "gate-attempt-1",
            "--policy-revision",
            "3",
            "--lease",
            str(lease_file),
        ]
        for status, expected in (("observations-match", 0), ("incompatible", 2)):
            output = io.StringIO()
            with (
                patch.object(sys, "argv", argv),
                patch(
                    "agent_boundary_gate.cli.openshell_doctor",
                    return_value={"status": status, "release_eligible": False},
                ),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(main(), expected)
            self.assertEqual(json.loads(output.getvalue())["status"], status)
        lease_file.write_text("synthetic-private-value")
        output = io.StringIO()
        with patch.object(sys, "argv", argv), contextlib.redirect_stderr(output):
            self.assertEqual(main(), 2)
        self.assertNotIn("synthetic-private-value", output.getvalue())

    def test_argument_parser_does_not_echo_private_values(self):
        output = io.StringIO()
        with (
            patch.object(
                sys, "argv", ["gate", "doctor", "--policy-revision", "synthetic-private-value"]
            ),
            contextlib.redirect_stderr(output),
            self.assertRaises(SystemExit) as stopped,
        ):
            main()
        self.assertEqual(stopped.exception.code, 2)
        self.assertEqual(json.loads(output.getvalue())["error"], "invalid-cli-input")
        self.assertNotIn("synthetic-private-value", output.getvalue())

    def test_installed_cli_inspects_synthetic_executable_end_to_end(self):
        # This private generated script is a command-contract fixture, not OpenShell.
        code = (
            f"#!{sys.executable}\nimport json, sys\n"
            "assert sys.argv[1:3] == ['--gateway', 'rig']\n"
            "args = sys.argv[3:]\n"
            "if args == ['sandbox', 'get', 'gate-attempt-1', '-o', 'json']:\n"
            f"    print({json.dumps(self.metadata)!r})\n"
            "elif args == ['policy', 'get', 'gate-attempt-1', '--rev', '3', "
            "'--full', '-o', 'json']:\n"
            f"    print({json.dumps(self.policy)!r})\n"
            "else: raise SystemExit(9)\n"
        )
        self.executable.write_text(code)
        self.executable.chmod(0o700)
        lease_file = self.executable.with_name("lease.json")
        lease_file.write_text(self.lease.model_dump_json())
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_boundary_gate.cli",
                "doctor",
                "--executable",
                str(self.executable),
                "--executable-digest",
                bytes_digest(self.executable.read_bytes()),
                "--gateway",
                "rig",
                "--sandbox",
                "gate-attempt-1",
                "--policy-revision",
                "3",
                "--lease",
                str(lease_file),
                "--probe-runtime",
                "perl",
            ],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "observations-match")
        self.assertFalse(report["ready_for_attempt"])
        self.assertNotIn(self.temp.name, result.stdout.decode())
        self.assertNotIn(self.lease.component.instance_uid, result.stdout.decode())
