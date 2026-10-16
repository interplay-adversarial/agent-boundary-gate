"""Generic AgentAdapter protocol conformance, independent of any specific implementation.

Exercised here against the in-process loopback fixture. A future OpenCode/OpenClaw
adapter should be added to ADAPTER_FACTORIES and pass the same suite unmodified;
these tests are not an end-to-end lifecycle run (see test_adapters.py for that).
"""

import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event

from agent_boundary_gate.agents.fixture import LoopbackAgentAdapter
from agent_boundary_gate.agents.opencode import OpenCodeAgentAdapter
from agent_boundary_gate.agents.opencode_runtime import OPENCODE_VERSION, OpenCodeProvider
from agent_boundary_gate.contracts import ToolRequestAction

D = "sha256:" + "a" * 64


def _opencode_factory() -> OpenCodeAgentAdapter:
    # A real binary file must exist for is_opencode_ready's own existence check;
    # the module-level directory below is created once and never cleaned up
    # (test-process lifetime only, a few bytes).
    install_dir = Path(tempfile.mkdtemp(prefix="opencode-conformance-"))
    command = install_dir / "node_modules" / ".bin" / "opencode"
    command.parent.mkdir(parents=True)
    command.touch()

    def fake_run(args, **kwargs):
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, stdout=OPENCODE_VERSION, stderr="")
        # Simulates a model that does exactly what the generated tool's prompt
        # asks -- this suite exercises the adapter's own code paths, not a real
        # model's behavior (see docs/opencode-model-smoke.md for that).
        prompt = args[-1]
        control = re.search(r'control="([^"]+)"', prompt).group(1)
        env = kwargs["env"]
        Path(env["AGENT_BOUNDARY_GATE_RECEIPT_PATH"]).write_text(
            "agent-boundary-gate-tool-complete:"
            + env["AGENT_BOUNDARY_GATE_ATTEMPT_ID"]
            + ":"
            + control
        )
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    provider = OpenCodeProvider(
        base_url="https://example.com/v1", api_key_env="UNUSED", model="openai/m"
    )
    return OpenCodeAgentAdapter(provider, "synthetic-credential", install_dir, run=fake_run)


ADAPTER_FACTORIES = {
    "loopback": lambda: LoopbackAgentAdapter(D),
    "opencode": _opencode_factory,
}


def _action(control: str = "positive", timeout_seconds: int = 1) -> ToolRequestAction:
    return ToolRequestAction(
        operation="tool_request",
        tool_id="conformance-tool",
        arguments_ref=D,
        control=control,
        timeout_seconds=timeout_seconds,
    )


class AgentAdapterConformanceTests(unittest.TestCase):
    def test_capabilities_are_a_concrete_nonempty_set(self):
        for name, factory in ADAPTER_FACTORIES.items():
            with self.subTest(adapter=name):
                adapter = factory()
                self.assertIsInstance(adapter.capabilities, frozenset)
                self.assertTrue(adapter.capabilities)

    def test_readiness_reports_a_matching_agent_identity(self):
        for name, factory in ADAPTER_FACTORIES.items():
            with self.subTest(adapter=name):
                adapter = factory()
                readiness = adapter.readiness(deadline=time.monotonic() + 5, cancelled=Event())
                self.assertTrue(readiness.ready)
                identities = {c.component_id: c for c in readiness.components}
                self.assertIn(adapter.agent_id, identities)
                self.assertEqual(identities[adapter.agent_id].role, "agent")

    def test_readiness_fails_closed_when_already_cancelled(self):
        for name, factory in ADAPTER_FACTORIES.items():
            with self.subTest(adapter=name):
                adapter = factory()
                cancelled = Event()
                cancelled.set()
                readiness = adapter.readiness(deadline=time.monotonic() + 5, cancelled=cancelled)
                self.assertFalse(readiness.ready)

    def test_readiness_fails_closed_past_its_deadline(self):
        for name, factory in ADAPTER_FACTORIES.items():
            with self.subTest(adapter=name):
                adapter = factory()
                readiness = adapter.readiness(deadline=time.monotonic() - 1, cancelled=Event())
                self.assertFalse(readiness.ready)

    def test_request_tool_fails_closed_when_already_cancelled(self):
        for name, factory in ADAPTER_FACTORIES.items():
            with self.subTest(adapter=name):
                adapter = factory()
                cancelled = Event()
                cancelled.set()
                completed = adapter.request_tool(
                    _action(),
                    "attempt-conformance",
                    deadline=time.monotonic() + 5,
                    cancelled=cancelled,
                )
                self.assertFalse(completed)

    def test_request_tool_fails_closed_past_its_deadline(self):
        for name, factory in ADAPTER_FACTORIES.items():
            with self.subTest(adapter=name):
                adapter = factory()
                completed = adapter.request_tool(
                    _action(),
                    "attempt-conformance",
                    deadline=time.monotonic() - 1,
                    cancelled=Event(),
                )
                self.assertFalse(completed)

    def test_request_tool_completes_for_every_declared_control(self):
        for name, factory in ADAPTER_FACTORIES.items():
            with self.subTest(adapter=name):
                adapter = factory()
                for control in ("positive", "restricted"):
                    with self.subTest(control=control):
                        completed = adapter.request_tool(
                            _action(control=control),
                            "attempt-conformance",
                            deadline=time.monotonic() + 5,
                            cancelled=Event(),
                        )
                        self.assertTrue(completed)
