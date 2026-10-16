"""OpenCodeAgentAdapter's own control flow, with a fake subprocess runner.

No live CLI, network or model call -- the actual tool-call behavior of a real
OpenCode session can only be verified by running it for real (see
docs/opencode-model-smoke.md), which these tests deliberately do not attempt.
"""

import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event

from agent_boundary_gate.agents.opencode import OpenCodeAgentAdapter
from agent_boundary_gate.agents.opencode_runtime import OPENCODE_VERSION, OpenCodeProvider
from agent_boundary_gate.contracts import ToolRequestAction

D = "sha256:" + "a" * 64


def _provider() -> OpenCodeProvider:
    return OpenCodeProvider(
        base_url="https://example.com/v1", api_key_env="UNUSED", model="openai/m"
    )


def _action(control: str = "positive") -> ToolRequestAction:
    return ToolRequestAction(
        operation="tool_request",
        tool_id="fixture-tool",
        arguments_ref=D,
        control=control,
        timeout_seconds=5,
    )


def _ready_run(args, **kwargs):
    return subprocess.CompletedProcess(args, 0, stdout=OPENCODE_VERSION, stderr="")


class OpenCodeAgentAdapterTests(unittest.TestCase):
    def test_constructor_requires_a_nonempty_credential(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                OpenCodeAgentAdapter(_provider(), "   ", Path(root), run=_ready_run)
            OpenCodeAgentAdapter(_provider(), "secret", Path(root), run=_ready_run)

    def test_readiness_requires_the_pinned_cli_to_already_be_installed(self):
        with tempfile.TemporaryDirectory() as root:
            adapter = OpenCodeAgentAdapter(_provider(), "secret", Path(root), run=_ready_run)
            readiness = adapter.readiness(deadline=time.monotonic() + 5, cancelled=Event())
            self.assertFalse(readiness.ready)  # nothing installed under this empty root

            command = Path(root) / "node_modules" / ".bin" / "opencode"
            command.parent.mkdir(parents=True)
            command.touch()
            readiness = adapter.readiness(deadline=time.monotonic() + 5, cancelled=Event())
            self.assertTrue(readiness.ready)
            self.assertEqual(readiness.components[0].component_id, "opencode")
            self.assertEqual(readiness.components[0].role, "agent")

    def test_readiness_fails_closed_when_already_cancelled_or_past_deadline(self):
        with tempfile.TemporaryDirectory() as root:
            command = Path(root) / "node_modules" / ".bin" / "opencode"
            command.parent.mkdir(parents=True)
            command.touch()
            adapter = OpenCodeAgentAdapter(_provider(), "secret", Path(root), run=_ready_run)

            cancelled = Event()
            cancelled.set()
            self.assertFalse(
                adapter.readiness(deadline=time.monotonic() + 5, cancelled=cancelled).ready
            )
            self.assertFalse(
                adapter.readiness(deadline=time.monotonic() - 1, cancelled=Event()).ready
            )

    def test_same_provider_config_yields_the_same_policy_digest(self):
        with tempfile.TemporaryDirectory() as root:
            first = OpenCodeAgentAdapter(_provider(), "secret-a", Path(root), run=_ready_run)
            second = OpenCodeAgentAdapter(_provider(), "secret-b", Path(root), run=_ready_run)
            self.assertEqual(first.policy_digest, second.policy_digest)
            self.assertNotIn("secret-a", first.policy_digest)

    def test_request_tool_fails_closed_when_already_cancelled_or_past_deadline(self):
        with tempfile.TemporaryDirectory() as root:
            adapter = OpenCodeAgentAdapter(_provider(), "secret", Path(root), run=_ready_run)
            cancelled = Event()
            cancelled.set()
            self.assertFalse(
                adapter.request_tool(
                    _action(), "attempt-1", deadline=time.monotonic() + 5, cancelled=cancelled
                )
            )
            self.assertFalse(
                adapter.request_tool(
                    _action(), "attempt-1", deadline=time.monotonic() - 1, cancelled=Event()
                )
            )

    def test_request_tool_writes_a_matching_custom_tool_and_env_then_confirms_the_receipt(self):
        calls = []

        def fake_run(args, **kwargs):
            calls.append((args, kwargs))
            project_dir = Path(kwargs["cwd"])
            tool_files = list((project_dir / ".opencode" / "tool").glob("*.ts"))
            self.assertEqual(len(tool_files), 1)
            self.assertIn("@opencode-ai/plugin", tool_files[0].read_text())
            env = kwargs["env"]
            Path(env["AGENT_BOUNDARY_GATE_RECEIPT_PATH"]).write_text(
                "agent-boundary-gate-tool-complete:"
                + env["AGENT_BOUNDARY_GATE_ATTEMPT_ID"]
                + ":positive"
            )
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as root:
            adapter = OpenCodeAgentAdapter(_provider(), "secret", Path(root), run=fake_run)
            completed = adapter.request_tool(
                _action("positive"), "attempt-7", deadline=time.monotonic() + 5, cancelled=Event()
            )
            self.assertTrue(completed)
            self.assertEqual(len(calls), 1)
            args, kwargs = calls[0]
            self.assertEqual(args[1], "run")
            self.assertIn("secret", kwargs["env"]["OPENAI_API_KEY"])
            self.assertEqual(kwargs["env"]["OPENCODE_DISABLE_AUTOUPDATE"], "true")

    def test_request_tool_rejects_a_mismatched_or_missing_receipt(self):
        with tempfile.TemporaryDirectory() as root:

            def no_receipt(args, **kwargs):
                return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

            adapter = OpenCodeAgentAdapter(_provider(), "secret", Path(root), run=no_receipt)
            self.assertFalse(
                adapter.request_tool(
                    _action(), "attempt-1", deadline=time.monotonic() + 5, cancelled=Event()
                )
            )

        with tempfile.TemporaryDirectory() as root:

            def wrong_control(args, **kwargs):
                env = kwargs["env"]
                Path(env["AGENT_BOUNDARY_GATE_RECEIPT_PATH"]).write_text(
                    "agent-boundary-gate-tool-complete:"
                    + env["AGENT_BOUNDARY_GATE_ATTEMPT_ID"]
                    + ":restricted"
                )
                return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

            adapter = OpenCodeAgentAdapter(_provider(), "secret", Path(root), run=wrong_control)
            self.assertFalse(
                adapter.request_tool(
                    _action("positive"),
                    "attempt-1",
                    deadline=time.monotonic() + 5,
                    cancelled=Event(),
                )
            )

    def test_request_tool_rejects_a_nonzero_exit_even_with_a_receipt_present(self):
        with tempfile.TemporaryDirectory() as root:

            def failed_but_wrote_receipt(args, **kwargs):
                env = kwargs["env"]
                Path(env["AGENT_BOUNDARY_GATE_RECEIPT_PATH"]).write_text(
                    "agent-boundary-gate-tool-complete:"
                    + env["AGENT_BOUNDARY_GATE_ATTEMPT_ID"]
                    + ":positive"
                )
                return subprocess.CompletedProcess(args, 1, stdout="", stderr="opencode crashed")

            adapter = OpenCodeAgentAdapter(
                _provider(), "secret", Path(root), run=failed_but_wrote_receipt
            )
            self.assertFalse(
                adapter.request_tool(
                    _action(), "attempt-1", deadline=time.monotonic() + 5, cancelled=Event()
                )
            )
