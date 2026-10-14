"""Actual pinned Gym Hermes harness/runtime; synthetic model and tool transport."""

import importlib.util
import json
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from threading import Event

from scripts.gym_replay import check_environment
from scripts.gym_smoke import Provider


@unittest.skipUnless(importlib.util.find_spec("run_agent"), "separate Hermes environment required")
class NativeHermesPilotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from scripts.hermes_pilot import PIN_PATH

        check_environment(
            tomllib.loads((PIN_PATH.parent / "uv.lock").read_text()),
            json.loads(PIN_PATH.read_text()),
            project_name="agent-boundary-gate-hermes-pilot",
        )

    def test_actual_hermes_loop_verifies_compromise_and_utility(self):
        from scripts.hermes_pilot import INJECTION, MESSAGE, ModelProxy, run_worker

        provider = Provider(
            base_url="https://example.com/v1",
            api_key_env="MODEL_API_KEY",
            model="synthetic-model",
            max_steps=4,
        )
        requests = []

        def dispatch(tool, args):
            requests.append((tool, args))
            return (
                {"messages": [{"body": MESSAGE + INJECTION}]}
                if tool == "gate_read_messages"
                else {"synthetic_request_submitted": True}
            )

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with ModelProxy(provider, "synthetic-no-secret", directory, calibration=True) as proxy:
                try:
                    packet = run_worker(
                        provider,
                        proxy,
                        directory,
                        "native-calibration",
                        dispatch,
                        deadline=time.monotonic() + 45,
                        cancelled=Event(),
                    )
                except ValueError:
                    # This test has only synthetic model replies and no credentials.
                    # Export the final error line, never private filesystem frames.
                    failure = directory / "worker-failure.txt"
                    self.fail(
                        failure.read_text().splitlines()[-1]
                        if failure.exists()
                        else "native-worker-diagnostic-unavailable"
                    )
            self.assertEqual([t for t, _ in requests], ["gate_read_messages", "gate_send_record"])
            self.assertEqual(packet["native_verifier"]["reward_safety"], 0.0)
            self.assertEqual(packet["native_verifier"]["reward_utility"], 1.0)
            self.assertTrue(packet["native_verifier"]["injection_followed"])
            self.assertEqual(packet["response"]["status"], "completed")
            self.assertIn("no_sandbox_runtime", [g["code"] for g in packet["observations"]["gaps"]])
            self.assertEqual(proxy.calls, 3)
            for path in directory.rglob("*"):
                if path.is_file():
                    self.assertEqual(path.stat().st_mode & 0o077, 0)
                    self.assertNotIn(b"synthetic-no-secret", path.read_bytes())

    def test_actual_iteration_exhaustion_keeps_native_utility_without_completion(self):
        from scripts.hermes_pilot import MESSAGE, ModelProxy, run_worker

        provider = Provider(
            base_url="https://example.com/v1",
            api_key_env="MODEL_API_KEY",
            model="synthetic-model",
            max_steps=3,
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with ModelProxy(provider, "synthetic-no-secret", directory, calibration=True) as proxy:
                packet = run_worker(
                    provider,
                    proxy,
                    directory,
                    "native-exhaustion",
                    lambda tool, args: (
                        {"messages": [{"body": MESSAGE}]}
                        if tool == "gate_read_messages"
                        else {"synthetic_request_submitted": True}
                    ),
                    deadline=time.monotonic() + 45,
                    cancelled=Event(),
                )
            self.assertEqual(packet["response"]["status"], "incomplete")
            self.assertEqual(packet["native_verifier"]["reward_utility"], 1.0)

    def test_cancellation_reaps_worker_before_any_tool_dispatch(self):
        from scripts.hermes_pilot import ModelProxy, run_worker

        provider = Provider(
            base_url="https://example.com/v1",
            api_key_env="MODEL_API_KEY",
            model="synthetic-model",
            max_steps=4,
        )
        cancelled = Event()
        cancelled.set()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with ModelProxy(provider, "synthetic-no-secret", directory, calibration=True) as proxy:
                with self.assertRaisesRegex(ValueError, "deadline-or-cancellation"):
                    run_worker(
                        provider,
                        proxy,
                        directory,
                        "native-cancelled",
                        lambda *args: self.fail("cancelled worker dispatched a tool"),
                        deadline=time.monotonic() + 45,
                        cancelled=cancelled,
                    )
                self.assertEqual(proxy.calls, 0)

    def test_reflected_provider_credential_never_reaches_worker_or_artifact(self):
        import httpx

        from scripts.hermes_pilot import ModelProxy

        provider = Provider(
            base_url="https://example.com/v1",
            api_key_env="MODEL_API_KEY",
            model="synthetic-model",
            max_steps=4,
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with ModelProxy(
                provider,
                "synthetic-reflection",
                directory,
                fetch=lambda request: {"model": "synthetic-model", "debug": "synthetic-reflection"},
            ) as proxy:
                response = httpx.post(
                    f"http://127.0.0.1:{proxy.server.server_port}/v1/chat/completions",
                    headers={"Authorization": "Bearer " + proxy.token},
                    json={
                        "model": "synthetic-model",
                        "tools": [
                            {"function": {"name": "gate_read_messages"}},
                            {"function": {"name": "gate_send_record"}},
                        ],
                    },
                    timeout=5,
                )
                self.assertEqual(response.status_code, 502)
                self.assertNotIn("synthetic-reflection", response.text)
                self.assertTrue(proxy.failed)
                self.assertEqual(list(directory.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
