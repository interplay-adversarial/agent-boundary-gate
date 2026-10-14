"""Bounded commands with an independent pipe-liveness process owner."""

import math
import os
import select
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event

_SUPERVISOR = Path(__file__).with_name("process_supervisor.py")


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
        # A separate session survives caller/group SIGKILL. Only this caller
        # holds the writer; exec children cannot inherit it. EOF lets the owner
        # terminate the command's separate group even when our finally is lost.
        reader, writer = os.pipe()
        try:
            status_reader, status_writer = os.pipe()
        except BaseException:
            os.close(reader)
            os.close(writer)
            raise
        try:
            child = subprocess.Popen(
                [
                    sys.executable,
                    str(_SUPERVISOR),
                    str(reader),
                    str(request.fileno()),
                    str(status_writer),
                    str(deadline),
                    *argv,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                pass_fds=(reader, request.fileno(), status_writer),
                env=env,
            )
        except BaseException:
            os.close(writer)
            os.close(status_reader)
            raise
        finally:
            os.close(reader)
            os.close(status_writer)
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
            # Close ownership first, so cancellation lets the supervisor kill
            # and reap its command rather than killing the owner prematurely.
            os.close(writer)
            cleanup_failed = False
            try:
                child.wait(timeout=6)
            except subprocess.TimeoutExpired:
                cleanup_failed = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=1)
                except (ProcessLookupError, PermissionError, subprocess.TimeoutExpired):
                    pass
            child.stdout.close()
            os.set_blocking(status_reader, False)
            try:
                status = os.read(status_reader, 2)
            except BlockingIOError:
                status = b""
            finally:
                os.close(status_reader)
            cleanup_failed |= status != b"0"
            if cleanup_failed:
                raise AttemptStopped("process-group-cleanup-not-confirmed")
