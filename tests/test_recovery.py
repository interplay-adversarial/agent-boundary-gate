import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from receipt_support import lease_and_binding

from agent_boundary_gate.receipts import (
    CleanupClaim,
    LifecycleReceipt,
    ReceiptVerifier,
    sign_receipt,
)
from agent_boundary_gate.recovery import ControllerLease, LeaseJournal, RecoveryWorker


class SyntheticCleanupBroker:
    def __init__(self, clock):
        self.clock = clock
        self.key = Ed25519PrivateKey.generate()
        self.verifier = ReceiptVerifier(
            readiness_keys={}, cleanup_keys={"synthetic-recovery": self.key.public_key()}
        )
        self.cells = set()
        self.requests = []

    def destroy(self, request, *, deadline, cancelled):
        self.requests.append(request)
        self.cells.add(request.binding.cell_uid)
        now = self.clock()
        receipt = LifecycleReceipt(
            request=request,
            signer_identity="synthetic-recovery",
            issued_at=now,
            expires_at=now + timedelta(seconds=30),
            claim=CleanupClaim(state="destroyed", scope="whole-cell"),
        )
        return sign_receipt(receipt, self.key).model_dump_json().encode()


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "journal"
        self.journal = LeaseJournal(self.root)
        self.lease, self.binding = lease_and_binding()
        self.now = datetime.now(UTC)
        self.broker = SyntheticCleanupBroker(lambda: self.now)
        self.worker = RecoveryWorker(
            self.journal, self.broker, self.broker.verifier, clock=lambda: self.now
        )

    def register(self, ttl=10):
        self.journal.register(self.lease, now=self.now, heartbeat_ttl=ttl)

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)

    def test_controller_loss_recovers_only_with_signed_durable_proof(self):
        self.register()
        self.assertEqual(self.worker.step(), "idle")
        self.advance(10)
        self.assertEqual(self.worker.step(), "destroyed")
        state = self.journal.inspect(self.lease.lease_id)
        self.assertEqual(state["state"], "destroyed")
        self.assertEqual(state["attempts"], 1)
        self.assertEqual(self.broker.cells, {self.lease.cell_uid})
        blob = self.root / (state["receipt_ref"].removeprefix("sha256:") + ".json")
        self.assertTrue(blob.exists())
        self.assertEqual(self.worker.step(), "idle")
        self.assertFalse(self.journal.heartbeat(self.lease, now=self.now))

    def test_absolute_expiry_wins_over_controller_heartbeat(self):
        self.lease = self.lease.model_copy(
            update={"lease_expires_at": self.now + timedelta(seconds=4)}
        )
        self.register()
        self.advance(3)
        self.assertTrue(self.journal.heartbeat(self.lease, now=self.now))
        self.advance(1)
        self.assertFalse(self.journal.heartbeat(self.lease, now=self.now))
        claim = self.journal.claim_due(now=self.now)
        self.assertEqual(claim.reason, "lease-expired")
        self.assertEqual(claim.lease, self.lease)

    def test_late_heartbeat_or_reregistration_cannot_resurrect_lease(self):
        self.register()
        self.advance(10)
        self.register()
        self.assertFalse(self.journal.heartbeat(self.lease, now=self.now))
        self.assertEqual(self.worker.step(), "destroyed")
        self.register()
        self.assertEqual(self.worker.step(), "idle")
        self.assertEqual(self.journal.inspect(self.lease.lease_id)["state"], "destroyed")

    def test_mismatched_binding_cannot_replace_or_refresh_existing_lease(self):
        self.register()
        changed = self.lease.model_copy(update={"cell_uid": "replacement"})
        with self.assertRaises(ValueError):
            self.journal.register(changed, now=self.now)
        self.assertFalse(self.journal.heartbeat(changed, now=self.now))
        self.advance(10)
        self.assertEqual(self.journal.claim_due(now=self.now).lease, self.lease)

    def test_parallel_workers_obtain_one_claim(self):
        self.register()
        self.advance(10)
        with ThreadPoolExecutor(max_workers=4) as pool:
            claims = list(pool.map(lambda _: self.journal.claim_due(now=self.now), range(4)))
        self.assertEqual(sum(claim is not None for claim in claims), 1)

    def test_worker_crash_is_reclaimed_and_old_claim_cannot_commit(self):
        self.register()
        self.advance(10)
        old = self.journal.claim_due(now=self.now, claim_ttl=5)
        self.assertIsNone(self.journal.claim_due(now=self.now))
        self.advance(5)
        new = self.journal.claim_due(now=self.now)
        self.assertEqual(new.reason, "worker-lost")
        self.assertNotEqual(old.token, new.token)
        self.assertFalse(self.journal._finish(old, now=self.now, receipt_ref="sha256:" + "a" * 64))
        self.assertEqual(self.journal.inspect(self.lease.lease_id)["state"], "recovering")

    def test_interrupted_worker_can_restart_without_controller(self):
        self.register()
        self.advance(10)
        with patch.object(self.broker, "destroy", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.worker.step()
        self.advance(30)
        reopened = LeaseJournal(self.root)
        worker = RecoveryWorker(reopened, self.broker, self.broker.verifier, clock=lambda: self.now)
        self.assertEqual(worker.step(), "destroyed")
        self.assertEqual(reopened.inspect(self.lease.lease_id)["attempts"], 2)

    def test_cleanup_boolean_unknown_key_or_replayed_receipt_cannot_confirm(self):
        self.register()
        self.advance(10)
        with patch.object(self.broker, "destroy", return_value=True):
            self.assertEqual(self.worker.step(), "retry")
        self.assertIsNone(self.journal.inspect(self.lease.lease_id)["receipt_ref"])
        self.advance(5)
        real = self.broker.destroy
        cached = []

        def replay(request, **kwargs):
            if not cached:
                cached.append(real(request, **kwargs))
                raise OSError("synthetic-disconnected-response")
            return cached[0]

        with patch.object(self.broker, "destroy", side_effect=replay):
            self.assertEqual(self.worker.step(), "retry")
            self.advance(5)
            self.assertEqual(self.worker.step(), "retry")
        self.advance(5)
        self.broker.key = Ed25519PrivateKey.generate()
        self.assertEqual(self.worker.step(), "retry")
        self.assertIsNone(self.journal.inspect(self.lease.lease_id)["receipt_ref"])

    def test_storage_failure_retries_idempotent_cleanup(self):
        self.register()
        self.advance(10)
        with patch.object(
            self.journal.store, "persist", side_effect=OSError("synthetic-store-error")
        ):
            self.assertEqual(self.worker.step(), "retry")
        self.assertEqual(self.worker.step(), "idle")
        self.advance(5)
        self.assertEqual(self.worker.step(), "destroyed")
        self.assertEqual(len(self.broker.requests), 2)
        self.assertEqual(len(self.broker.cells), 1)

    def test_expired_receipt_after_storage_latency_cannot_confirm(self):
        self.register()
        self.advance(10)
        persist = self.journal.store.persist

        def delayed(data):
            self.advance(31)
            return persist(data)

        with patch.object(self.journal.store, "persist", side_effect=delayed):
            self.assertEqual(self.worker.step(), "claim-lost")
        self.assertIsNone(self.journal.inspect(self.lease.lease_id)["receipt_ref"])
        self.assertEqual(self.worker.step(), "destroyed")

    def test_exceeded_operation_deadline_cannot_confirm(self):
        self.register()
        self.advance(10)
        with patch("agent_boundary_gate.recovery.time.monotonic", side_effect=[0, 11]):
            self.assertEqual(self.worker.step(), "retry")
        self.assertIsNone(self.journal.inspect(self.lease.lease_id)["receipt_ref"])

    def test_clock_regression_refuses_heartbeat_and_forces_recovery(self):
        self.register()
        self.advance(-1)
        self.assertFalse(self.journal.heartbeat(self.lease, now=self.now))
        self.assertEqual(self.journal.claim_due(now=self.now).reason, "clock-regressed")

    def test_journal_reopens_after_abrupt_controller_process_exit(self):
        # The child persists a lease and exits without cleanup/finally handlers.
        script = """import json, os, sys
from datetime import datetime
from pathlib import Path
from agent_boundary_gate.receipts import LeaseBinding
from agent_boundary_gate.recovery import LeaseJournal
configuration = json.load(sys.stdin)
LeaseJournal(Path(configuration["root"])).register(
    LeaseBinding.model_validate_json(configuration["lease"]),
    now=datetime.fromisoformat(configuration["now"]), heartbeat_ttl=1)
os._exit(0)
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            input=json.dumps(
                {
                    "root": str(self.root),
                    "lease": self.lease.model_dump_json(),
                    "now": self.now.isoformat(),
                }
            ),
            text=True,
            capture_output=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.advance(1)
        journal = LeaseJournal(self.root)
        worker = RecoveryWorker(journal, self.broker, self.broker.verifier, clock=lambda: self.now)
        self.assertEqual(worker.step(), "destroyed")
        self.assertFalse(journal.path.stat().st_mode & 0o077)

    def test_private_directory_regular_file_and_journal_version_required(self):
        public = Path(self.temp.name) / "public"
        public.mkdir(mode=0o755)
        with self.assertRaises(ValueError):
            LeaseJournal(public)
        self.journal.path.chmod(0o644)
        with self.assertRaises(ValueError):
            LeaseJournal(self.root)
        self.journal.path.chmod(0o600)
        with sqlite3.connect(self.journal.path) as connection:
            connection.execute("PRAGMA user_version=2")
        with self.assertRaises(ValueError):
            LeaseJournal(self.root)

    def test_controller_refresh_stops_and_never_acknowledges_cleanup(self):
        controller = ControllerLease(
            self.journal,
            self.lease,
            heartbeat_ttl=1,
            heartbeat_interval=0.01,
            clock=lambda: self.now,
        )
        renewed = Event()
        calls = []
        original = self.journal.heartbeat

        def signal_renewal(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append(result)
            if len(calls) >= 2:
                renewed.set()
            return result

        with patch.object(self.journal, "heartbeat", side_effect=signal_renewal):
            controller.start(self.binding)
            self.addCleanup(controller.stop)
            self.assertTrue(renewed.wait(2))
            self.assertFalse(controller.failed.is_set())
            controller.stop()
        self.assertEqual(self.journal.inspect(self.lease.lease_id)["state"], "pending")
        self.advance(1)
        self.assertEqual(self.worker.step(), "destroyed")
        with self.assertRaises(ValueError):
            controller.start(self.binding)

    def test_controller_heartbeat_failure_is_latched(self):
        controller = ControllerLease(
            self.journal,
            self.lease,
            heartbeat_ttl=1,
            heartbeat_interval=0.01,
            clock=lambda: self.now,
        )
        controller.start(self.binding)
        self.addCleanup(controller.stop)
        with patch.object(self.journal, "heartbeat", side_effect=OSError("synthetic-journal-loss")):
            self.assertTrue(controller.failed.wait(1))
        self.assertEqual(self.journal.inspect(self.lease.lease_id)["state"], "pending")

    def test_invalid_budgets_naive_time_and_wrong_start_binding_rejected(self):
        for value in (0, -1, float("inf"), float("nan"), True, 61):
            with self.assertRaises(ValueError):
                RecoveryWorker(
                    self.journal, self.broker, self.broker.verifier, cleanup_budget=value
                )
        with self.assertRaises(ValueError):
            RecoveryWorker(
                self.journal, self.broker, self.broker.verifier, cleanup_budget=30, claim_ttl=30
            )
        with self.assertRaises(ValueError):
            self.journal.register(self.lease, now=datetime(2026, 1, 1))
        controller = ControllerLease(self.journal, self.lease)
        with self.assertRaises(ValueError):
            controller.start(self.binding.model_copy(update={"attempt_id": "other-attempt"}))
        self.assertIsNone(self.journal.inspect(self.lease.lease_id))

    def test_worker_cancellation_during_cleanup_never_confirms(self):
        self.register()
        self.advance(10)
        cancelled = Event()
        real = self.broker.destroy

        def cancel_after_destroy(request, **kwargs):
            raw = real(request, **kwargs)
            cancelled.set()
            return raw

        with patch.object(self.broker, "destroy", side_effect=cancel_after_destroy):
            self.assertEqual(self.worker.step(cancelled=cancelled), "retry")
        self.assertIsNone(self.journal.inspect(self.lease.lease_id)["receipt_ref"])

    def test_concurrent_controller_start_admits_exactly_one_caller(self):
        controller = ControllerLease(self.journal, self.lease, clock=lambda: self.now)
        self.addCleanup(controller.stop)

        def start_once(_):
            try:
                controller.start(self.binding)
                return True
            except ValueError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(start_once, range(8)))
        self.assertEqual(sum(results), 1)
        self.assertIsNotNone(controller._thread)
        self.assertFalse(controller.failed.is_set())
        self.assertEqual(self.journal.inspect(self.lease.lease_id)["state"], "pending")

    def test_sqlite_contention_during_stop_is_bounded_and_reports_failure(self):
        controller = ControllerLease(
            self.journal,
            self.lease,
            heartbeat_ttl=1,
            heartbeat_interval=0.01,
            clock=lambda: self.now,
        )
        controller.start(self.binding)
        self.addCleanup(controller.stop)
        refresh_entered = Event()
        original = self.journal.heartbeat

        def blocked_refresh(*args, **kwargs):
            refresh_entered.set()
            return original(*args, **kwargs)

        # Deliberately hold a private authority transaction across shutdown.
        # Even this unsupported call order must terminate at the SQLite timeout.
        with self.journal._transaction():
            with patch.object(self.journal, "heartbeat", side_effect=blocked_refresh):
                self.assertTrue(refresh_entered.wait(2))
                controller.stop()
        self.assertTrue(controller.failed.is_set())
        self.assertFalse(controller._thread.is_alive())
        self.assertEqual(self.journal.inspect(self.lease.lease_id)["state"], "pending")

    def test_stop_during_blocked_start_prevents_late_heartbeat_thread(self):
        controller = ControllerLease(self.journal, self.lease, clock=lambda: self.now)
        self.addCleanup(controller.stop)
        registering, release_registration = Event(), Event()
        original = self.journal.register

        def blocked_register(*args, **kwargs):
            registering.set()
            if not release_registration.wait(2):
                raise RuntimeError("synthetic-registration-timeout")
            return original(*args, **kwargs)

        with patch.object(self.journal, "register", side_effect=blocked_register):
            with ThreadPoolExecutor(max_workers=2) as pool:
                starting = pool.submit(controller.start, self.binding)
                self.assertTrue(registering.wait(1))
                stopping = pool.submit(controller.stop)
                self.assertTrue(controller._stop.wait(1))
                release_registration.set()
                with self.assertRaises(ValueError):
                    starting.result(timeout=2)
                stopping.result(timeout=2)
        self.assertIsNone(controller._thread)
        self.assertTrue(controller.failed.is_set())
        self.assertEqual(self.journal.inspect(self.lease.lease_id)["state"], "pending")

    def test_stopped_worker_does_not_claim_cleanup(self):
        self.register()
        self.advance(10)
        stop = Event()
        stop.set()
        self.worker.run(stop)
        self.assertEqual(self.journal.inspect(self.lease.lease_id)["attempts"], 0)
