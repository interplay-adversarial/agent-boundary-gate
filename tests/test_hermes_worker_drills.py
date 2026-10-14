"""Real worker supervision with synthetic protocol peers, no native/model traffic."""

import fcntl
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest.mock import patch

from scripts.gym_smoke import Provider
from scripts.hermes_pilot import run_worker

PEER = """
import json, os, signal, subprocess, sys, time
from pathlib import Path
setup = json.loads(sys.stdin.readline())
root = Path(setup['output'])
for sequence, tool, arguments in (
    (1, 'gate_read_messages', {}),
    (2, 'gate_send_record', {'recipient':'attacker@example.invalid','body':'synthetic'}),
):
    print(json.dumps({'protocol':'gate-hermes-tool/1', 'sequence':sequence,
                      'tool':tool, 'arguments':arguments}), flush=True)
    reply = json.loads(sys.stdin.readline())
    assert reply['sequence'] == sequence and reply['ok'] is True
if MODE == 'verifier-failure':
    print('{"protocol":"gate-hermes-tool/1","complete":false}', flush=True)
    sys.exit(2)
if MODE in ('blocked', 'cancelled'):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    (root / 'waiting').write_text('ready')
    time.sleep(60)
else:
    descendant = '''import fcntl, signal, sys, time
from pathlib import Path
root = Path(sys.argv[1])
stream = (root / "descendant.lock").open("w")
fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
(root / "descendant-ready").write_text("ready")
time.sleep(60)
'''
    subprocess.Popen([sys.executable, '-c', descendant, str(root)],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
    until = time.monotonic() + 3
    while not (root / 'descendant-ready').exists():
        if time.monotonic() >= until:
            sys.exit(3)
        time.sleep(.01)
    (root / 'episode.json').write_text('{"synthetic":true}')
    (root / 'episode.json').chmod(0o600)
    print('{"protocol":"gate-hermes-tool/1","complete":true}', flush=True)
"""


class HermesWorkerDrills(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.provider = Provider(
            base_url="https://example.com/v1", api_key_env="MODEL_API_KEY", model="synthetic-model"
        )
        self.proxy = SimpleNamespace(
            server=SimpleNamespace(server_port=1), token="synthetic-token", failed=False
        )
        self.requests, self.processes = [], []

    def run_peer(self, mode, *, seconds=3, cancelled=None):
        spawn = subprocess.Popen

        def launch(argv, **kwargs):
            process = spawn([sys.executable, "-c", "MODE=" + repr(mode) + "\n" + PEER], **kwargs)
            self.processes.append(process)
            return process

        def dispatch(tool, arguments):
            self.requests.append((tool, arguments))
            if mode == "cancelled" and len(self.requests) == 2:
                cancelled.set()
            return {"synthetic": True}

        try:
            with patch("scripts.hermes_pilot.subprocess.Popen", side_effect=launch):
                return run_worker(
                    self.provider,
                    self.proxy,
                    self.directory,
                    "synthetic-drill",
                    dispatch,
                    deadline=time.monotonic() + seconds,
                    cancelled=cancelled or Event(),
                )
        finally:
            # Test containment is independent of the implementation under test.
            for process in self.processes:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)

    def assert_effect_requests_retained(self):
        self.assertEqual(
            [tool for tool, _ in self.requests], ["gate_read_messages", "gate_send_record"]
        )
        self.assertEqual(self.requests[-1][1]["recipient"], "attacker@example.invalid")

    def test_blocked_peer_after_effect_is_deadlined_and_direct_child_reaped(self):
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, "deadline-or-cancellation"):
            self.run_peer("blocked", seconds=0.6)
        self.assertLess(time.monotonic() - started, 4)
        self.assert_effect_requests_retained()
        self.assertIsNotNone(self.processes[0].returncode)
        self.assertFalse((self.directory / "episode.json").exists())

    def test_cancelled_peer_after_effect_is_reaped_without_success_artifact(self):
        cancelled = Event()
        with self.assertRaisesRegex(ValueError, "deadline-or-cancellation"):
            self.run_peer("cancelled", cancelled=cancelled)
        self.assertTrue(cancelled.is_set())
        self.assert_effect_requests_retained()
        self.assertIsNotNone(self.processes[0].returncode)
        self.assertFalse((self.directory / "episode.json").exists())

    def test_verifier_failure_after_effect_cannot_return_success(self):
        with self.assertRaisesRegex(ValueError, "worker-incomplete"):
            self.run_peer("verifier-failure")
        self.assert_effect_requests_retained()
        self.assertFalse((self.directory / "episode.json").exists())

    def test_worker_exit_cannot_leave_a_descendant_holding_its_execution_lease(self):
        # Assert before our independent finally cleanup, so it cannot mask a leak.
        spawn = subprocess.Popen
        lease = self.directory / "descendant.lock"

        def launch(argv, **kwargs):
            process = spawn([sys.executable, "-c", "MODE='descendant'\n" + PEER], **kwargs)
            self.processes.append(process)
            return process

        try:
            with patch("scripts.hermes_pilot.subprocess.Popen", side_effect=launch):
                packet = run_worker(
                    self.provider,
                    self.proxy,
                    self.directory,
                    "synthetic-descendant",
                    lambda *args: {"synthetic": True},
                    deadline=time.monotonic() + 5,
                    cancelled=Event(),
                )
            self.assertEqual(packet, {"synthetic": True})
            self.assertEqual(self.processes[0].returncode, 0)
            with lease.open("r+") as stream:
                until = time.monotonic() + 1
                while True:
                    try:
                        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= until:
                            self.fail("worker-descendant-lease-still-held")
                        time.sleep(0.01)
        finally:
            for process in self.processes:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
