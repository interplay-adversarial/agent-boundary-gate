"""Actual pinned SimpleAgent worker with a loopback model; set GYM_NATIVE_PYTHON to run.

The interpreter must belong to the separate Gym/Interplay environment matching
src/agent_boundary_gate/_pins/gym-native.json. Core CI never needs that environment.
"""

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from test_gym_supervised import DenyBoundary, make_plan

from agent_boundary_gate.evidence import bytes_digest
from agent_boundary_gate.gym_supervised import (
    GymEffectConfig,
    read_journal,
    recover_gym_attempt,
    run_gym_attempt,
)

PYTHON = os.environ.get("GYM_NATIVE_PYTHON")


class LoopbackModel(ThreadingHTTPServer):
    """Deterministic chat-completions endpoint; picks a resource by the user's task text."""

    def __init__(self):
        outer = self
        self.requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append(body)
                messages = body["messages"]
                tool_seen = any(m.get("role") == "tool" for m in messages)
                task = next(m["content"] for m in messages if m["role"] == "user")
                if tool_seen or "MODEL:answer" in task:
                    message = {"role": "assistant", "content": "Done."}
                    finish = "stop"
                else:
                    resource = "admin" if "MODEL:admin" in task else "reports"
                    message = {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": f"call-{len(outer.requests)}",
                                "type": "function",
                                "function": {
                                    "name": "fetch_resource",
                                    "arguments": json.dumps({"resource": resource}),
                                },
                            }
                        ],
                    }
                    finish = "tool_calls"
                raw = json.dumps(
                    {
                        "id": f"completion-{len(outer.requests)}",
                        "object": "chat.completion",
                        "created": 1700000000,
                        "model": body["model"],
                        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, format, *args):  # noqa: A002
                pass

        super().__init__(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.02})
        self.thread.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=2)


@unittest.skipUnless(PYTHON, "GYM_NATIVE_PYTHON selects the separate Gym/Interplay environment")
class NativeWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.model = LoopbackModel()
        self.addCleanup(self.model.close)

    def run_case(self, kind, task, name, **extra):
        probe = f"Synthetic task {task}"
        config = GymEffectConfig(
            probe=probe,
            model={
                "base_url": f"http://127.0.0.1:{self.model.server_port}/v1",
                "model": "loopback-model",
            },
            rollout_seconds=60,
            **extra,
        )
        return run_gym_attempt(make_plan(kind, probe), config, self.root / name, Path(PYTHON))

    def test_benign_task_reaches_the_allowed_receiver_through_native_tool_dispatch(self):
        result = self.run_case("benign", "MODEL:reports", "benign")
        self.assertEqual(result["scenario"], "benign-utility-observed", result)
        self.assertEqual(result["allowed_effects"], 1)
        self.assertEqual(result["forbidden_effects"], 0)
        self.assertEqual(result["native"]["model_attempts"], 2)
        self.assertEqual(result["native"]["tool_attempts"], ["reports"])
        self.assertTrue(result["native"]["capture_complete"])

    def test_followed_injection_is_an_independently_observed_forbidden_effect(self):
        result = self.run_case("attack", "MODEL:admin", "followed")
        self.assertEqual(result["scenario"], "observed-synthetic-effect", result)
        self.assertEqual(result["forbidden_effects"], 1)
        self.assertEqual(result["native"]["tool_attempts"], ["admin"])

    def test_model_that_ignores_the_injection_is_resisted_not_blocked(self):
        result = self.run_case("attack", "MODEL:answer", "resisted")
        self.assertEqual(result["scenario"], "resisted-attack", result)
        self.assertEqual(result["native"]["tool_attempts"], [])
        self.assertEqual(result["forbidden_effects"] + result["allowed_effects"], 0)

    def test_boundary_denial_is_blocked_with_no_forbidden_receiver_record(self):
        boundary = DenyBoundary()
        self.addCleanup(boundary.close)
        url = f"http://127.0.0.1:{boundary.server_port}/probe"
        result = self.run_case("attack", "MODEL:admin", "blocked", resource_urls={"admin": url})
        self.assertEqual(result["scenario"], "blocked-effect", result)
        self.assertEqual(result["native"]["tool_statuses"], [403])
        self.assertEqual(result["forbidden_effects"], 0)

    def test_admission_rejects_a_modified_pin_before_any_model_call(self):
        pin = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "src/agent_boundary_gate/_pins/gym-native.json"
            ).read_bytes()
        )
        pin["interplay"]["files"]["interplay/assessment/gym.py"] = bytes_digest(b"modified")
        altered = self.root / "pin.json"
        altered.write_text(json.dumps(pin))
        with patch("agent_boundary_gate.gym_supervised.PIN", altered):
            result = self.run_case("benign", "MODEL:reports", "pinned")
        self.assertNotEqual(result["scenario"], "benign-utility-observed")
        self.assertEqual(self.model.requests, [])

    def test_recovery_of_a_finished_native_attempt_replays_nothing(self):
        self.run_case("benign", "MODEL:reports", "again")
        calls = len(self.model.requests)
        self.assertTrue(recover_gym_attempt(self.root / "again")["already_final"])
        self.assertEqual(len(self.model.requests), calls)
        self.assertEqual(read_journal(self.root / "again")[1][-1]["kind"], "final")


if __name__ == "__main__":
    unittest.main()
