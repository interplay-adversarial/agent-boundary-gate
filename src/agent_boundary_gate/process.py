"""Bounded subprocesses; cancellation terminates the local process group."""

import math
import os
import select
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
    argv: list[str],
    *,
    deadline: float,
    cancelled: Event,
    max_output: int = 65536,
    input_data: bytes | None = None,
    env: dict[str, str] | None = None,
) -> ProcessResult:
    if not math.isfinite(deadline):
        raise ValueError("process-deadline-invalid")
    if type(max_output) is not int or not 0 < max_output <= 16 * 1024 * 1024:
        raise ValueError("process-output-limit-invalid")
    if cancelled.is_set():
        raise AttemptStopped("cancelled")
    if time.monotonic() >= deadline:
        raise AttemptStopped("timeout")
    # Read stdout through a finite OS pipe, retaining at most max_output bytes.
    # An output flood cannot grow a temporary output file between polls.
    if input_data is not None and (not isinstance(input_data, bytes) or len(input_data) > 65536):
        raise ValueError("process-input-limit")
    with tempfile.TemporaryFile() as request:
        if input_data is not None:
            request.write(input_data)
            request.seek(0)
        child = subprocess.Popen(
            argv,
            stdin=request if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
        try:
            os.set_blocking(child.stdout.fileno(), False)
            output = bytearray()
            while True:
                if cancelled.is_set():
                    raise AttemptStopped("cancelled")
                if time.monotonic() >= deadline:
                    raise AttemptStopped("timeout")
                returncode = child.poll()
                try:
                    chunk = os.read(child.stdout.fileno(), min(65536, max_output - len(output) + 1))
                except BlockingIOError:
                    chunk = None
                if chunk:
                    if len(output) + len(chunk) > max_output:
                        raise AttemptStopped("output-limit")
                    output.extend(chunk)
                    continue
                if returncode is not None:
                    return ProcessResult(returncode, bytes(output))
                delay = min(0.02, max(0, deadline - time.monotonic()))
                if chunk == b"":
                    cancelled.wait(delay)
                else:
                    select.select([child.stdout], [], [], delay)
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
            child.stdout.close()
            if cleanup_failed:
                raise AttemptStopped("process-group-cleanup-not-confirmed")
