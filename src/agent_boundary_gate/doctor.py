"""Read-only CLI observations; never readiness, attestation or release authority."""

import hashlib
import json
import math
import os
import re
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Literal

from agent_boundary_gate.process import AttemptStopped, bounded_process
from agent_boundary_gate.receipts import LeaseBinding


def read_regular_input(path: Path, *, limit: int) -> bytes:
    """Reject symlinks/devices/FIFOs and bound private input allocation."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("invalid-doctor-input")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("invalid-doctor-input")
    return raw


def openshell_doctor(
    *,
    executable: Path,
    executable_digest: str,
    gateway: str,
    sandbox: str,
    policy_revision: int,
    lease: LeaseBinding,
    probe_runtime: Literal["python3", "perl"] = "python3",
    timeout_seconds: float = 10.0,
) -> dict:
    """Inspect trusted operator context with only sandbox get and policy get.

    Context must come from the operator, not CLI output. No broker is contacted,
    no workload code runs, and all output consists of fixed keys/status codes.
    """
    lease = LeaseBinding.model_validate(lease)
    if (
        not re.fullmatch(r"sha256:[0-9a-f]{64}", executable_digest)
        or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}", gateway)
        or not re.fullmatch(r"gate-[a-z0-9-]{1,80}", sandbox)
        or type(policy_revision) is not int
        or policy_revision <= 0
        or probe_runtime not in ("python3", "perl")
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= 60
        or lease.component.component_id != "openshell"
    ):
        raise ValueError("invalid-doctor-input")
    checks = {
        "cli-pin": "unverified",
        "lease-current": "unverified",
        "sandbox-identity": "unverified",
        "sandbox-ready-phase": "unverified",
        "policy-sandbox": "unverified",
        "policy-loaded": "unverified",
        "policy-revision-active": "unverified",
        "policy-digest": "unverified",
    }
    report = {
        "scope": "read-only-compatibility",
        "status": "incompatible",
        "checks": checks,
        "probe-prerequisites": ["python3", "urllib.request"]
        if probe_runtime == "python3"
        else ["perl", "IO::Socket::IP", "Socket"],
        "probe-runtime": "unverified",
        "authenticated-readiness": "unverified",
        "ready_for_attempt": False,
        "qualification": "m0-prototype",
        "release_eligible": False,
    }
    deadline = time.monotonic() + timeout_seconds
    try:
        raw = read_regular_input(executable, limit=64 * 1024 * 1024)
        matches = "sha256:" + hashlib.sha256(raw).hexdigest() == executable_digest
    except (OSError, ValueError):
        checks["cli-pin"] = "unreadable"
        return report
    checks["cli-pin"] = "match" if matches else "mismatch"
    if not matches:
        return report
    checks["lease-current"] = "match" if datetime.now(UTC) < lease.lease_expires_at else "expired"
    if checks["lease-current"] != "match":
        return report

    def query(args: list[str]) -> dict:
        current = read_regular_input(executable, limit=64 * 1024 * 1024)
        if "sha256:" + hashlib.sha256(current).hexdigest() != executable_digest:
            checks["cli-pin"] = "mismatch"
            raise ValueError("cli-pin-changed")
        result = bounded_process(
            [str(executable.resolve()), "--gateway", gateway, *args],
            deadline=deadline,
            cancelled=Event(),
        )
        if result.returncode:
            raise ValueError("cli-exit-nonzero")
        try:
            value = json.loads(result.stdout)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise ValueError("cli-json-invalid") from None
        if not isinstance(value, dict):
            raise ValueError("cli-json-invalid")
        return value

    try:
        metadata = query(["sandbox", "get", sandbox, "-o", "json"])
        checks["sandbox-identity"] = (
            "match" if metadata.get("id") == lease.component.instance_uid else "mismatch"
        )
        checks["sandbox-ready-phase"] = "match" if metadata.get("phase") == "Ready" else "mismatch"
        # A same-name replacement must not be inspected further as the leased target.
        if checks["sandbox-identity"] != "match":
            return report
        policy = query(
            ["policy", "get", sandbox, "--rev", str(policy_revision), "--full", "-o", "json"]
        )
        checks["policy-sandbox"] = "match" if policy.get("sandbox") == sandbox else "mismatch"
        checks["policy-loaded"] = "match" if policy.get("status") == "loaded" else "mismatch"
        checks["policy-revision-active"] = (
            "match"
            if type(policy.get("version")) is int
            and type(policy.get("active_version")) is int
            and policy["version"] == policy["active_version"] == policy_revision
            else "mismatch"
        )
        policy_hash = policy.get("hash")
        checks["policy-digest"] = (
            "match"
            if isinstance(policy_hash, str)
            and "sha256:" + policy_hash.removeprefix("sha256:") == lease.effective_policy_digest
            else "mismatch"
        )
    except AttemptStopped as stopped:
        report["error"] = {
            "timeout": "cli-timeout",
            "output-limit": "cli-output-limit",
            "process-group-cleanup-not-confirmed": "cli-group-cleanup-failed",
            "cancelled": "cli-cancelled",
        }.get(stopped.reason, "cli-stopped")
        return report
    except OSError:
        report["error"] = "cli-start-failed"
        return report
    except ValueError as error:
        # Only locally constructed codes; never include exception/CLI input text.
        report["error"] = (
            str(error)
            if str(error) in {"cli-exit-nonzero", "cli-json-invalid", "cli-pin-changed"}
            else "cli-invalid"
        )
        return report
    # Observe expiry again after both queries; a slow query cannot preserve currency.
    if datetime.now(UTC) >= lease.lease_expires_at:
        checks["lease-current"] = "expired"
    if all(value == "match" for value in checks.values()):
        report["status"] = "observations-match"
    return report
