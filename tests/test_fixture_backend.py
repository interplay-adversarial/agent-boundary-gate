"""The fixture driver's own stand-ins, isolated from the full lifecycle harness."""

import time
import unittest
from threading import Event
from unittest.mock import patch

from agent_boundary_gate.backends.fixture import LoopbackBackend
from agent_boundary_gate.contracts import HttpGetAction
from agent_boundary_gate.probes import PROBE
from agent_boundary_gate.process import ProcessResult


class LoopbackForbiddenSimulationTests(unittest.TestCase):
    def setUp(self):
        self.driver = LoopbackBackend("policy-digest")
        self.action = HttpGetAction(
            operation="http_get", receiver="forbidden", path="/probe", timeout_seconds=5
        )
        self.captured_argv = None

    def fake_bounded_process(self, argv, *, deadline, cancelled):
        self.captured_argv = argv
        attempt_id = argv[-2]
        return ProcessResult(
            returncode=0,
            stdout=("agent-boundary-gate-probe-complete:" + attempt_id).encode(),
        )

    def replay(self):
        with patch(
            "agent_boundary_gate.backends.fixture.bounded_process", self.fake_bounded_process
        ):
            return self.driver.replay(
                self.action,
                "http://127.0.0.1:1/probe",
                "attempt-1",
                deadline=time.monotonic() + 5,
                cancelled=Event(),
            )

    def test_forbidden_not_weakened_never_runs_the_real_probe(self):
        # The "Explicitly simulated denial" stand-in (backends/fixture.py) must never
        # be mistaken for a real completed probe: assert the exact script it runs
        # instead of PROBE, not just the boolean outcome, so a future edit that
        # accidentally routes real traffic through this path is caught here rather
        # than only by a side effect (e.g. a receiver hit count) in a higher-level test.
        held = self.replay()
        self.assertTrue(held)
        script = self.captured_argv[2]
        self.assertNotEqual(script, PROBE)
        self.assertEqual(
            script, "import sys; print('agent-boundary-gate-probe-complete:' + sys.argv[2])"
        )

    def test_forbidden_weakened_runs_the_real_probe(self):
        self.driver.weakened = True
        held = self.replay()
        self.assertTrue(held)
        self.assertEqual(self.captured_argv[2], PROBE)

    def test_allowed_not_weakened_runs_the_real_probe(self):
        self.action = self.action.model_copy(update={"receiver": "allowed"})
        held = self.replay()
        self.assertTrue(held)
        self.assertEqual(self.captured_argv[2], PROBE)


if __name__ == "__main__":
    unittest.main()
