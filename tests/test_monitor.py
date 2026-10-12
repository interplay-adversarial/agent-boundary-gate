import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from receipt_support import lease_and_binding

from agent_boundary_gate.evidence import EvidenceStore
from agent_boundary_gate.monitor import (
    MonitorHeartbeat,
    MonitorSession,
    SignedMonitorHeartbeat,
    sign_heartbeat,
)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = EvidenceStore(Path(self.temp.name) / "evidence")
        self.lease, self.binding = lease_and_binding()
        self.now = datetime.now(UTC)
        self.ticks = 100.0
        self.key = Ed25519PrivateKey.generate()
        self.keys = {"synthetic-monitor": self.key.public_key()}
        self.monitor = MonitorSession(
            lease=self.lease,
            identity="synthetic-monitor",
            generation="monitor-1",
            trusted_keys=self.keys,
            store=self.store,
            monotonic=lambda: self.ticks,
        )
        self.sequence = 0

    def wire(self, *, request=None, key=None, **changes):
        self.sequence += 1
        heartbeat = MonitorHeartbeat(
            **(
                {
                    "request": request or self.monitor.request(),
                    "signer_identity": "synthetic-monitor",
                    "generation": "monitor-1",
                    "sequence": self.sequence,
                    "state": "healthy",
                    "issued_at": self.now,
                    "expires_at": self.now + timedelta(seconds=5),
                }
                | changes
            )
        )
        return sign_heartbeat(heartbeat, key or self.key).model_dump_json().encode()

    def test_unknown_until_authenticated_durable_handshake(self):
        self.assertEqual(self.monitor.snapshot().state, "unknown")
        raw = self.wire()
        self.assertTrue(self.monitor.accept(raw, now=self.now))
        snapshot = self.monitor.snapshot()
        self.assertTrue(snapshot.healthy)
        self.assertTrue(self.monitor.require_binding(self.binding))
        self.assertEqual(len(snapshot.heartbeat_refs), 1)
        blob = self.store.root / (snapshot.heartbeat_refs[0].removeprefix("sha256:") + ".json")
        self.assertEqual(blob.read_bytes(), raw)
        self.assertFalse(blob.stat().st_mode & 0o077)

    def test_expiry_latches_loss_and_fresh_health_cannot_restore_it(self):
        self.assertTrue(self.monitor.accept(self.wire(), now=self.now))
        self.ticks += 5
        self.assertEqual(self.monitor.snapshot().state, "lost")
        self.now += timedelta(seconds=5)
        self.assertFalse(self.monitor.accept(self.wire(), now=self.now))
        self.assertFalse(self.monitor.snapshot().healthy)

    def test_storage_latency_cannot_extend_health(self):
        raw = self.wire()
        persist = self.store.persist

        def slow_storage(data):
            self.ticks += 6
            return persist(data)

        with patch.object(self.store, "persist", side_effect=slow_storage):
            self.assertFalse(self.monitor.accept(raw, now=self.now))
        self.assertEqual(self.monitor.snapshot().state, "lost")

    def test_incident_is_latched_even_if_storage_fails(self):
        raw = self.wire(state="incident")
        with patch.object(self.store, "persist", side_effect=OSError("synthetic-store-failure")):
            self.assertFalse(self.monitor.accept(raw, now=self.now))
        self.assertTrue(self.monitor.snapshot().incident)
        self.assertEqual(self.monitor.snapshot().state, "incident")
        self.assertFalse(self.monitor.accept(self.wire(), now=self.now))
        self.assertTrue(self.monitor.snapshot().incident)

    def test_signed_loss_cannot_be_healed_with_new_healthy_message(self):
        self.assertFalse(self.monitor.accept(self.wire(state="lost"), now=self.now))
        self.assertFalse(self.monitor.accept(self.wire(), now=self.now))
        self.assertEqual(self.monitor.snapshot().state, "lost")

    def test_replayed_or_unsolicited_response_latches_loss(self):
        raw = self.wire()
        self.assertTrue(self.monitor.accept(raw, now=self.now))
        self.monitor.request()
        self.assertFalse(self.monitor.accept(raw, now=self.now))
        self.assertFalse(self.monitor.snapshot().healthy)

    def test_nonincreasing_sequence_and_changed_generation_are_rejected(self):
        self.assertTrue(self.monitor.accept(self.wire(), now=self.now))
        self.assertFalse(self.monitor.accept(self.wire(sequence=1), now=self.now))
        fresh = MonitorSession(
            lease=self.lease,
            identity="synthetic-monitor",
            generation="monitor-1",
            trusted_keys=self.keys,
            store=self.store,
            monotonic=lambda: self.ticks,
        )
        request = fresh.request()
        self.assertFalse(
            fresh.accept(self.wire(request=request, generation="monitor-2"), now=self.now)
        )

    def test_wrong_attempt_context_or_controller_binding_is_rejected(self):
        request = self.monitor.request()
        other = request.model_copy(
            update={"binding": self.lease.model_copy(update={"cell_uid": "replacement"})}
        )
        self.assertFalse(self.monitor.accept(self.wire(request=other), now=self.now))
        self.assertFalse(
            self.monitor.require_binding(self.binding.model_copy(update={"attempt_id": "other"}))
        )
        self.assertEqual(self.monitor.snapshot().state, "lost")

    def test_future_expired_and_long_lived_messages_are_rejected(self):
        for changes in (
            {"issued_at": self.now + timedelta(seconds=1)},
            {"issued_at": self.now - timedelta(seconds=5), "expires_at": self.now},
            {"expires_at": self.now + timedelta(seconds=11)},
            {"expires_at": self.lease.lease_expires_at + timedelta(seconds=1)},
        ):
            monitor = MonitorSession(
                lease=self.lease,
                identity="synthetic-monitor",
                generation="monitor-1",
                trusted_keys=self.keys,
                store=self.store,
                monotonic=lambda: self.ticks,
            )
            with self.subTest(changes=changes):
                self.assertFalse(
                    monitor.accept(self.wire(request=monitor.request(), **changes), now=self.now)
                )

    def test_wrong_signer_and_key_are_rejected_but_registry_is_snapshotted(self):
        self.keys.clear()
        self.assertTrue(self.monitor.accept(self.wire(), now=self.now))
        self.assertFalse(
            self.monitor.accept(self.wire(key=Ed25519PrivateKey.generate()), now=self.now)
        )
        self.assertFalse(
            self.monitor.accept(self.wire(signer_identity="unknown-monitor"), now=self.now)
        )

    def test_malformed_oversized_and_tampered_messages_are_rejected(self):
        for raw in (b"{}", b" " * 65537, True):
            self.monitor.request()
            self.assertFalse(self.monitor.accept(raw, now=self.now))
        body = json.loads(self.wire())
        body["heartbeat"]["state"] = "incident"
        self.assertFalse(self.monitor.accept(json.dumps(body).encode(), now=self.now))
        self.assertFalse(self.monitor.snapshot().incident)

    def test_buffer_limit_withholds_health_and_preserves_verified_incident(self):
        with patch("agent_boundary_gate.monitor.MAX_HEARTBEAT_REFS", 1):
            self.assertTrue(self.monitor.accept(self.wire(), now=self.now))
            self.assertFalse(self.monitor.accept(self.wire(state="incident"), now=self.now))
        snapshot = self.monitor.snapshot()
        self.assertTrue(snapshot.incident)
        self.assertEqual(snapshot.dropped_events, 1)
        self.assertEqual(len(snapshot.heartbeat_refs), 1)

    def test_naive_times_and_bad_sequence_are_rejected(self):
        for changes in ({"issued_at": datetime(2026, 1, 1)}, {"sequence": True}, {"sequence": 0}):
            with self.assertRaises(ValidationError):
                self.wire(**changes)

    def test_invalid_monitor_identity_or_generation_fails_before_admission(self):
        for changes in ({"identity": "bad identity"}, {"generation": True}):
            values = {
                "lease": self.lease,
                "identity": "synthetic-monitor",
                "generation": "monitor-1",
                "trusted_keys": self.keys,
                "store": self.store,
            }
            with self.assertRaises(ValidationError):
                MonitorSession(**(values | changes))

    def test_wire_schema_matches_export(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "schemas/monitor/1.0/signed-monitor-heartbeat.json"
        )
        self.assertEqual(json.loads(path.read_text()), SignedMonitorHeartbeat.model_json_schema())
