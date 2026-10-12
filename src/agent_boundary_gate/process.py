"""Bounded subprocesses; cancellation terminates the local process group."""

import os
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from threading import Event


class AttemptStopped(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes


def bounded_process(
    argv: list[str], *, deadline: float, cancelled: Event, max_output: int = 65536
) -> ProcessResult:
    if cancelled.is_set():
        raise AttemptStopped("cancelled")
    if time.monotonic() >= deadline:
        raise AttemptStopped("timeout")
    # Child output is untrusted. Keep it off shared logs and cap the retained bytes.
    # Disk quotas still belong to the rig; this file is not a raw-log retention store.
    with tempfile.TemporaryFile() as output:
        child = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            while child.poll() is None:
                if cancelled.is_set():
                    raise AttemptStopped("cancelled")
                if time.monotonic() >= deadline:
                    raise AttemptStopped("timeout")
                if os.fstat(output.fileno()).st_size > max_output:
                    raise AttemptStopped("output-limit")
                cancelled.wait(min(0.02, max(0, deadline - time.monotonic())))
            if os.fstat(output.fileno()).st_size > max_output:
                raise AttemptStopped("output-limit")
            output.seek(0)
            return ProcessResult(child.returncode, output.read(max_output))
        finally:
            # A child may leave descendants after exiting; kill the whole group.
            cleanup_failed = False
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                cleanup_failed = True
                # Reap the direct child even if group cleanup could not be confirmed.
                if child.poll() is None:
                    try:
                        child.kill()
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        cleanup_failed = True
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cleanup_failed = True
            if cleanup_failed:
                raise AttemptStopped("process-group-cleanup-not-confirmed")
