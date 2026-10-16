"""Generic AgentAdapter protocol conformance, independent of any specific implementation.

Exercised here against the in-process loopback fixture. A future OpenCode/OpenClaw
adapter should be added to ADAPTER_FACTORIES and pass the same suite unmodified;
these tests are not an end-to-end lifecycle run (see test_adapters.py for that).
"""

import time
import unittest
from threading import Event

from agent_boundary_gate.agents.fixture import LoopbackAgentAdapter
from agent_boundary_gate.contracts import ToolRequestAction

D = "sha256:" + "a" * 64

ADAPTER_FACTORIES = {
    "loopback": lambda: LoopbackAgentAdapter(D),
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
