"""Trusted POSIX command owner, outside the caller's process group.

The caller alone holds the pipe writer. EOF, deadline or command exit causes
group termination and direct-child reap. This is not a containment boundary for
commands which deliberately escape their group, nor a deployment supervisor.
"""

import math
import os
import select
import signal
import subprocess
import sys
import time


def supervise(control: int, request: int, status: int, deadline: float, argv: list[str]) -> int:
    if not math.isfinite(deadline) or not argv:
        os.write(status, b"0")
        return 125
    os.set_blocking(control, False)
    # Do not start work after a caller that died during interpreter startup.
    if select.select([control], [], [], 0)[0] or time.monotonic() >= deadline:
        os.write(status, b"0")
        return 125
    child = subprocess.Popen(
        argv,
        stdin=request,
        stdout=sys.stdout.buffer,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    os.close(request)
    result = 125
    cleanup_failed = False
    try:
        while True:
            # Caller death and deadlines take precedence over successful exit.
            if select.select([control], [], [], 0)[0] or time.monotonic() >= deadline:
                break
            code = child.poll()
            if code is not None:
                result = code
                break
            select.select([control], [], [], min(0.02, max(0, deadline - time.monotonic())))
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            cleanup_failed = True
            child.kill()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cleanup_failed = True
        os.close(control)
        # A dedicated status pipe distinguishes owner cleanup from a command's
        # exit code/output. Neither pipe descriptor is inherited by the command.
        os.write(status, b"1" if cleanup_failed else b"0")
        os.close(status)
    return result


if __name__ == "__main__":
    try:
        result = supervise(
            int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]), sys.argv[5:]
        )
    except Exception:
        # No command arguments, output or trusted environment values in errors.
        result = 125
    if result < 0:
        number = -result
        if number not in (signal.SIGKILL, signal.SIGSTOP):
            signal.signal(number, signal.SIG_DFL)
        os.kill(os.getpid(), number)
    sys.exit(result)
