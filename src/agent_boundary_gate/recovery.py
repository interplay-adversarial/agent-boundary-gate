"""Private durable lease journal and restartable, independently hosted recovery worker."""

import math
import os
import secrets
import sqlite3
import stat
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Literal, Protocol

from agent_boundary_gate.auth import digest
from agent_boundary_gate.contracts import Binding
from agent_boundary_gate.evidence import EvidenceStore
from agent_boundary_gate.receipts import LeaseBinding, ReceiptRequest, ReceiptVerifier


def utc_now() -> datetime:
    return datetime.now(UTC)


def stamp(value: datetime) -> str:
    if value.utcoffset() is None:
        raise ValueError("recovery clock must be timezone aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def bounded_seconds(value: float, *, maximum: float = 60) -> None:
    if isinstance(value, bool) or not math.isfinite(value) or not 0 < value <= maximum:
        raise ValueError("recovery budgets must be finite and bounded")


@dataclass(frozen=True)
class RecoveryClaim:
    lease: LeaseBinding
    token: str
    reason: Literal["lease-expired", "controller-lost", "worker-lost", "clock-regressed"]


class LeaseJournal:
    def __init__(self, root: Path):
        # This journal belongs to the provisioning/recovery authority, not the workload.
        self.store = EvidenceStore(root)
        self.path = self.store.root / "leases.sqlite3"
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                raise ValueError("recovery journal must be a private regular file")
        finally:
            os.close(fd)
        with self._transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise ValueError("unsupported recovery journal version")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS leases (
                    lease_id TEXT PRIMARY KEY, binding_json TEXT NOT NULL,
                    lease_expires_at TEXT NOT NULL, heartbeat_deadline TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','recovering','destroyed')),
                    claim_token TEXT, claim_until TEXT, retry_at TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0, receipt_ref TEXT,
                    updated_at TEXT NOT NULL
                )
            """)
            connection.execute("PRAGMA user_version=1")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        # Connections are never shared across threads or processes.
        connection = sqlite3.connect(self.path, timeout=1, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def register(self, lease: LeaseBinding, *, now: datetime, heartbeat_ttl: float = 10) -> None:
        bounded_seconds(heartbeat_ttl)
        current = stamp(now)
        if now >= lease.lease_expires_at:
            raise ValueError("cannot start an expired lease")
        body = lease.model_dump_json()
        deadline = stamp(min(now + timedelta(seconds=heartbeat_ttl), lease.lease_expires_at))
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT binding_json FROM leases WHERE lease_id=?", (lease.lease_id,)
            ).fetchone()
            if existing is not None:
                if LeaseBinding.model_validate_json(existing["binding_json"]) != lease:
                    raise ValueError("lease identifier cannot be reused for another binding")
                # Re-registering never renews or resurrects a lease.
                return
            connection.execute(
                "INSERT INTO leases (lease_id,binding_json,lease_expires_at,heartbeat_deadline,"
                "state,retry_at,updated_at) VALUES (?,?,?,?,'pending',?,?)",
                (lease.lease_id, body, stamp(lease.lease_expires_at), deadline, current, current),
            )

    def heartbeat(self, lease: LeaseBinding, *, now: datetime, heartbeat_ttl: float = 10) -> bool:
        bounded_seconds(heartbeat_ttl)
        current = stamp(now)
        deadline = stamp(min(now + timedelta(seconds=heartbeat_ttl), lease.lease_expires_at))
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM leases WHERE lease_id=?", (lease.lease_id,)
            ).fetchone()
            if row is None or LeaseBinding.model_validate_json(row["binding_json"]) != lease:
                return False
            if not (
                row["state"] == "pending"
                and row["updated_at"] <= current
                and current < row["heartbeat_deadline"]
                and current < row["lease_expires_at"]
            ):
                return False
            connection.execute(
                "UPDATE leases SET heartbeat_deadline=?, updated_at=? WHERE lease_id=?",
                (deadline, current, lease.lease_id),
            )
            return True

    def claim_due(self, *, now: datetime, claim_ttl: float = 30) -> RecoveryClaim | None:
        bounded_seconds(claim_ttl)
        current = stamp(now)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM leases WHERE "
                "(state='pending' AND (updated_at>? OR (retry_at<=? AND "
                "(lease_expires_at<=? OR heartbeat_deadline<=?)))) "
                "OR (state='recovering' AND (claim_until<=? OR updated_at>?)) "
                "ORDER BY lease_id LIMIT 1",
                (current, current, current, current, current, current),
            ).fetchone()
            if row is None:
                return None
            reason = (
                "clock-regressed"
                if row["updated_at"] > current
                else "worker-lost"
                if row["state"] == "recovering"
                else "lease-expired"
                if row["lease_expires_at"] <= current
                else "controller-lost"
            )
            token = secrets.token_hex(32)
            connection.execute(
                "UPDATE leases SET state='recovering', claim_token=?, claim_until=?, "
                "attempts=attempts+1, updated_at=? WHERE lease_id=?",
                (token, stamp(now + timedelta(seconds=claim_ttl)), current, row["lease_id"]),
            )
            return RecoveryClaim(
                LeaseBinding.model_validate_json(row["binding_json"]), token, reason
            )

    def _finish(
        self,
        claim: RecoveryClaim,
        *,
        now: datetime,
        receipt_ref: str | None,
        retry_delay: float = 5,
    ) -> bool:
        bounded_seconds(retry_delay)
        current = stamp(now)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM leases WHERE lease_id=?", (claim.lease.lease_id,)
            ).fetchone()
            if row is None or not (
                row["state"] == "recovering"
                and row["claim_token"] == claim.token
                and row["updated_at"] <= current < row["claim_until"]
                and LeaseBinding.model_validate_json(row["binding_json"]) == claim.lease
            ):
                return False
            if receipt_ref is not None:
                # Only RecoveryWorker supplies verified, durably retained proof references.
                connection.execute(
                    "UPDATE leases SET state='destroyed', receipt_ref=?, claim_token=NULL, "
                    "claim_until=NULL, updated_at=? WHERE lease_id=?",
                    (receipt_ref, current, claim.lease.lease_id),
                )
            else:
                connection.execute(
                    "UPDATE leases SET state='pending', claim_token=NULL, claim_until=NULL, "
                    "retry_at=?, updated_at=? WHERE lease_id=?",
                    (stamp(now + timedelta(seconds=retry_delay)), current, claim.lease.lease_id),
                )
            return True

    def inspect(self, lease_id: str) -> dict[str, object] | None:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT state,attempts,receipt_ref FROM leases WHERE lease_id=?", (lease_id,)
            ).fetchone()
            return dict(row) if row is not None else None


class CleanupBroker(Protocol):
    def destroy(
        self, request: ReceiptRequest, *, deadline: float, cancelled: Event
    ) -> bytes | None:
        """Idempotently destroy the exact leased cell UID; return a signed cleanup receipt."""
        ...


class RecoveryWorker:
    def __init__(
        self,
        journal: LeaseJournal,
        broker: CleanupBroker,
        verifier: ReceiptVerifier,
        *,
        clock: Callable[[], datetime] = utc_now,
        cleanup_budget: float = 10,
        claim_ttl: float = 30,
        retry_delay: float = 5,
    ):
        for value in (cleanup_budget, claim_ttl, retry_delay):
            bounded_seconds(value)
        if cleanup_budget >= claim_ttl:
            raise ValueError("cleanup budget must fit within the worker claim")
        self.journal, self.broker, self.verifier = journal, broker, verifier
        self.clock = clock
        self.cleanup_budget, self.claim_ttl, self.retry_delay = (
            cleanup_budget,
            claim_ttl,
            retry_delay,
        )

    def step(
        self, *, cancelled: Event | None = None
    ) -> Literal["idle", "destroyed", "retry", "claim-lost"]:
        cancelled = cancelled if cancelled is not None else Event()
        if cancelled.is_set():
            return "idle"
        claim = self.journal.claim_due(now=self.clock(), claim_ttl=self.claim_ttl)
        if claim is None:
            return "idle"
        deadline = time.monotonic() + self.cleanup_budget
        reference = None
        try:
            request = self.verifier.request("cleanup", claim.lease)
            raw = self.broker.destroy(request, deadline=deadline, cancelled=cancelled)
            if raw is None or cancelled.is_set() or time.monotonic() >= deadline:
                raise ValueError("cleanup-not-confirmed")
            self.verifier.verify(raw, request=request, now=self.clock())
            reference = self.journal.store.persist(raw)
            # Storage latency cannot extend the receipt or operation validity.
            self.verifier.verify(raw, request=request, now=self.clock())
            if cancelled.is_set() or time.monotonic() >= deadline:
                raise ValueError("cleanup-not-confirmed")
        except Exception:
            reference = None
        finished = self.journal._finish(
            claim, now=self.clock(), receipt_ref=reference, retry_delay=self.retry_delay
        )
        return "claim-lost" if not finished else "destroyed" if reference else "retry"

    def run(self, stop: Event, *, poll_interval: float = 1) -> None:
        bounded_seconds(poll_interval)
        while not stop.is_set():
            self.step(cancelled=stop)
            stop.wait(poll_interval)


class ControllerLease:
    """Controller-side liveness; never interprets a cleanup boolean as destruction."""

    def __init__(
        self,
        journal: LeaseJournal,
        lease: LeaseBinding,
        *,
        heartbeat_ttl: float = 10,
        heartbeat_interval: float = 2,
        clock: Callable[[], datetime] = utc_now,
    ):
        bounded_seconds(heartbeat_ttl)
        bounded_seconds(heartbeat_interval)
        if heartbeat_interval >= heartbeat_ttl / 2:
            raise ValueError("controller heartbeat interval must allow refresh margin")
        self.journal, self.lease, self.clock = journal, lease, clock
        self.heartbeat_ttl, self.interval = heartbeat_ttl, heartbeat_interval
        self._lifecycle_lock = Lock()
        self.failed, self._stop = Event(), Event()
        self._thread: Thread | None = None

    def start(self, binding: Binding) -> None:
        with self._lifecycle_lock:
            self._start_locked(binding)

    def _start_locked(self, binding: Binding) -> None:
        if self._thread is not None or self._stop.is_set():
            raise ValueError("controller lease cannot be restarted")
        if (
            digest(binding) != self.lease.binding_digest
            or binding.run_id != self.lease.run_id
            or binding.attempt_id != self.lease.attempt_id
            or binding.target_profile.boundary.id != self.lease.component.component_id
            or binding.effective_policy_digest != self.lease.effective_policy_digest
        ):
            raise ValueError("controller lease binding mismatch")
        self.journal.register(self.lease, now=self.clock(), heartbeat_ttl=self.heartbeat_ttl)
        if not self.journal.heartbeat(
            self.lease, now=self.clock(), heartbeat_ttl=self.heartbeat_ttl
        ):
            self.failed.set()
            raise ValueError("controller lease unavailable")
        if self._stop.is_set():
            self.failed.set()
            raise ValueError("controller lease stopped during startup")
        self._thread = Thread(target=self._refresh, name="controller-lease-heartbeat")
        self._thread.start()

    def _refresh(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                if self.journal.heartbeat(
                    self.lease, now=self.clock(), heartbeat_ttl=self.heartbeat_ttl
                ):
                    continue
            except Exception:
                pass
            self.failed.set()
            return

    def quiesce(self) -> None:
        """Stop renewing immediately; joining is left to terminal cleanup."""
        self._stop.set()

    def stop(self) -> None:
        self.quiesce()
        with self._lifecycle_lock:
            thread = self._thread
        if thread is not None:
            thread.join(timeout=2)
            if thread.is_alive():
                self.failed.set()
