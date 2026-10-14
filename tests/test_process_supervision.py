"""Caller death/suspension cannot leave cooperative local command groups active."""

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

from agent_boundary_gate.process import AttemptStopped, bounded_process

ROOT = Path(__file__).resolve().parents[1]


class ProcessSupervisionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gate-owner-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def wait(self, predicate, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail("owned-command-checkpoint-timeout")

    @staticmethod
    def alive(pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def launch_caller(self, *, budget=10):
        checkpoint, late = self.root / "started.json", self.root / "late"
        descendant = (
            "import time;from pathlib import Path;"
            f"time.sleep(0.5);Path({str(late)!r}).touch();time.sleep(60)"
        )
        command = (
            "import os,subprocess,sys,time,json;from pathlib import Path;"
            f"descendant=subprocess.Popen([sys.executable,'-c',{descendant!r}]);"
            f"Path({str(checkpoint)!r}).write_text(json.dumps({{'pid':os.getpid()}}));"
            "time.sleep(60)"
        )
        caller_code = (
            "import sys,time;from threading import Event;"
            "from agent_boundary_gate.process import bounded_process;"
            f"bounded_process([sys.executable,'-c',{command!r}],"
            f"deadline=time.monotonic()+{budget},cancelled=Event())"
        )
        caller = subprocess.Popen(
            [sys.executable, "-c", caller_code],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=os.environ | {"PYTHONPATH": str(ROOT / "src")},
        )

        def stop():
            if caller.poll() is None:
                os.killpg(caller.pid, signal.SIGCONT)
                os.killpg(caller.pid, signal.SIGKILL)
            caller.wait(timeout=3)

        self.addCleanup(stop)
        self.wait(checkpoint.exists)
        pid = json.loads(checkpoint.read_text())["pid"]

        def stop_command():
            if self.alive(pid):
                os.killpg(pid, signal.SIGKILL)

        self.addCleanup(stop_command)
        return caller, pid, late

    def test_caller_sigkill_terminates_command_and_same_group_descendant(self):
        for group in (False, True):
            with self.subTest(group=group):
                caller, pid, late = self.launch_caller()
                (os.killpg if group else os.kill)(caller.pid, signal.SIGKILL)
                caller.wait(timeout=3)
                self.wait(lambda pid=pid: not self.alive(pid))
                time.sleep(0.55)
                self.assertFalse(late.exists())
                (self.root / "started.json").unlink()

    def test_suspended_caller_does_not_suspend_command_deadline_owner(self):
        caller, pid, late = self.launch_caller(budget=0.35)
        os.killpg(caller.pid, signal.SIGSTOP)
        self.wait(lambda: not self.alive(pid))
        self.assertIsNone(caller.poll())
        time.sleep(0.55)
        self.assertFalse(late.exists())
        os.killpg(caller.pid, signal.SIGCONT)
        caller.wait(timeout=3)
        self.assertNotEqual(caller.returncode, 0)

    def test_dead_caller_before_supervisor_admission_starts_no_command(self):
        reader, writer = os.pipe()
        status_reader, status_writer = os.pipe()
        os.close(writer)
        marker = self.root / "should-not-start"
        try:
            with tempfile.TemporaryFile() as request:
                child = subprocess.Popen(
                    [
                        sys.executable,
                        str(ROOT / "src/agent_boundary_gate/process_supervisor.py"),
                        str(reader),
                        str(request.fileno()),
                        str(status_writer),
                        str(time.monotonic() + 2),
                        sys.executable,
                        "-c",
                        f"from pathlib import Path;Path({str(marker)!r}).touch()",
                    ],
                    pass_fds=(reader, request.fileno(), status_writer),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.assertEqual(child.wait(timeout=3), 125)
                self.assertEqual(os.read(status_reader, 1), b"0")
        finally:
            os.close(reader)
            os.close(status_reader)
            os.close(status_writer)
        self.assertFalse(marker.exists())

    def test_command_signal_returncodes_are_preserved(self):
        for number in (signal.SIGTERM, signal.SIGKILL):
            with self.subTest(number=number):
                result = bounded_process(
                    [sys.executable, "-c", f"import os;os.kill(os.getpid(),{int(number)})"],
                    deadline=time.monotonic() + 2,
                    cancelled=Event(),
                )
                self.assertEqual(result.returncode, -number)

    def test_owner_exit_without_cleanup_status_cannot_return_success(self):
        supervisor = self.root / "missing-status.py"
        supervisor.write_text("print('{}',flush=True)\n")
        with (
            patch("agent_boundary_gate.process._SUPERVISOR", supervisor),
            self.assertRaisesRegex(AttemptStopped, "process-group-cleanup-not-confirmed"),
        ):
            bounded_process([sys.executable], deadline=time.monotonic() + 2, cancelled=Event())
