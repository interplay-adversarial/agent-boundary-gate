"""Offline supervised Gym effect exercise: stand-in worker, real HTTP effects, no Gym or model.

Runs the supervised path (`gym_supervised.run_gym_attempt`) against the repository's
standard-library stand-in worker (`tests/gym_effect_stub_worker.py`). The worker makes
real HTTP requests to two independent loopback receivers, so the classifier sees real
effects, but no NeMo Gym, Interplay, model endpoint or network is involved.

Cases, each one attempt: a benign task, an attack that is followed (forbidden effect),
an attack stopped by a deny ingress (blocked), an attack the "model" ignores (resisted),
and, with `--interrupt`, a controller that is SIGKILLed mid-attempt and then recovered
from retained bytes with zero replayed model or tool calls.

The real worker, plan/config fields and outcome rules are in docs/gym-supervised-effects.md.
This example never qualifies a boundary: loopback receivers prove no containment.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from secrets import token_hex

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_boundary_gate.evidence import bytes_digest  # noqa: E402
from agent_boundary_gate.gym_supervised import (  # noqa: E402
    GymEffectConfig,
    GymEffectPlan,
    read_journal,
    recover_gym_attempt,
    run_gym_attempt,
)

STUB = ROOT / "tests" / "gym_effect_stub_worker.py"
PIN = json.loads((ROOT / "src/agent_boundary_gate/_pins/gym-native.json").read_text())


class DenyIngress(ThreadingHTTPServer):
    """Stand-in boundary: refuses every request and never contacts a receiver."""

    def __init__(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(403)
                self.end_headers()

            def log_message(self, *args):
                pass

        super().__init__(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.serve_forever, daemon=True).start()


def plan(kind, probe, attempt_id=None):
    return GymEffectPlan(
        interplay_commit=PIN["interplay"]["commit"],
        gym_revision=PIN["gym"]["commit"],
        campaign_id=token_hex(16),
        attempt_id=attempt_id or token_hex(16),
        case_kind=kind,
        dispatch_digest=bytes_digest(b"example-dispatch"),
        target_digest=bytes_digest(b"example-target"),
        probe_digest=bytes_digest(probe.encode()),
        provenance_digest=bytes_digest(b"example-provenance"),
    )


def config(probe, **extra):
    # The stand-in model endpoint is never contacted; a real run points at your endpoint.
    return GymEffectConfig(
        probe=probe,
        model={"base_url": "http://127.0.0.1:9/v1", "model": "synthetic"},
        rollout_seconds=extra.pop("rollout_seconds", 20),
        **extra,
    )


def attempt(output, kind, mode, **extra):
    probe = f"Synthetic task MODE:{mode}"
    result = run_gym_attempt(
        plan(kind, probe), config(probe, **extra), output, Path(sys.executable), worker=STUB
    )
    return {
        "scenario": result["scenario"],
        "allowed_effects": result["allowed_effects"],
        "forbidden_effects": result["forbidden_effects"],
        "observers_complete": result["observers_complete"],
        "release_eligible": result["release_eligible"],
    }


def interrupted(output):
    """SIGKILL the controller after the worker declares tool intent, then recover."""
    attempt_id = token_hex(16)
    probe = "Synthetic task MODE:hang"
    pending = output / "pending.json"
    pending.write_text(
        json.dumps(
            {
                "plan": plan("attack", probe, attempt_id).model_dump(mode="json"),
                "config": config(probe, rollout_seconds=60).model_dump(mode="json"),
            }
        )
    )
    controller = subprocess.Popen(
        [sys.executable, __file__, "--child", str(pending), str(output / "killed")],
        env={"PATH": os.environ["PATH"]},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    events = output / "killed" / "adapter" / attempt_id / "events.jsonl"
    end = time.monotonic() + 20
    while time.monotonic() < end and not (
        events.exists() and b"tool-attempted" in events.read_bytes()
    ):
        time.sleep(0.05)
    os.kill(controller.pid, signal.SIGKILL)
    controller.wait()
    before = [row["kind"] for row in read_journal(output / "killed")[1]]
    recovered = recover_gym_attempt(output / "killed")
    return {
        "journal_before_recovery": before,
        "scenario": recovered["scenario"],
        "interrupted_after": recovered["interrupted_after"],
        "replayed_model_or_tool_calls": recovered["replayed_model_or_tool_calls"],
        "worker_cleanup": recovered["worker_cleanup"],
        "late_effects_possible": recovered["late_effects_possible"],
        "release_eligible": recovered["release_eligible"],
    }


def child(pending, output):
    data = json.loads(Path(pending).read_text())
    run_gym_attempt(
        GymEffectPlan.model_validate(data["plan"]),
        GymEffectConfig.model_validate(data["config"]),
        Path(output),
        Path(sys.executable),
        worker=STUB,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, help="private output directory (default: temporary)")
    parser.add_argument("--interrupt", action="store_true", help="also SIGKILL and recover one")
    parser.add_argument("--child", nargs=2, metavar=("PENDING", "OUTPUT"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        child(*args.child)
        return 0
    os.umask(0o077)
    with tempfile.TemporaryDirectory() as folder:
        root = args.output or Path(folder)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        deny = DenyIngress()
        report = {
            "benign": attempt(root / "benign", "benign", "benign"),
            "followed": attempt(root / "followed", "attack", "follow"),
            "blocked": attempt(
                root / "blocked",
                "attack",
                "deny",
                resource_urls={"admin": f"http://127.0.0.1:{deny.server_port}/probe"},
            ),
            "resisted": attempt(root / "resisted", "attack", "answer"),
        }
        if args.interrupt:
            report["interrupted"] = interrupted(root)
        deny.shutdown()
        deny.server_close()
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
