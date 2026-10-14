"""Trusted pinned host command transport; responses remain untrusted bytes."""

import tempfile
import time
from pathlib import Path
from threading import Event

from agent_boundary_gate.contracts import Digest
from agent_boundary_gate.doctor import read_regular_input
from agent_boundary_gate.evidence import bytes_digest
from agent_boundary_gate.process import AttemptStopped, bounded_process
from agent_boundary_gate.receipts import ReceiptContract


class CommandTransport(ReceiptContract):
    """One bounded JSON stdin/stdout invocation per call, without a shell.

    The configured command belongs to the trusted host. Its interpreter,
    dependencies, environment and remote side effects are separate obligations.
    A child cannot extend the caller's deadline; same-group descendants are killed.
    """

    executable: str
    executable_digest: Digest

    def call(self, raw: bytes, *, deadline: float, cancelled: Event) -> bytes:
        if cancelled.is_set():
            raise AttemptStopped("cancelled")
        if time.monotonic() >= deadline:
            raise AttemptStopped("timeout")
        if not isinstance(raw, bytes) or not 0 < len(raw) <= 65536:
            raise ValueError("command-input-limit")
        executable_bytes = read_regular_input(Path(self.executable), limit=64 * 1024 * 1024)
        if bytes_digest(executable_bytes) != self.executable_digest:
            raise ValueError("command-pin-mismatch")
        with tempfile.TemporaryDirectory(prefix="gate-command-") as directory:
            executable = Path(directory) / "provider"
            executable.write_bytes(executable_bytes)
            executable.chmod(0o500)
            result = bounded_process(
                [str(executable)], input_data=raw, deadline=deadline, cancelled=cancelled
            )
        if result.returncode:
            raise ValueError("command-exit-nonzero")
        if not result.stdout:
            raise ValueError("command-empty-response")
        return result.stdout
