import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from agent_boundary_gate.auth import canonical, digest, sign
from agent_boundary_gate.evidence import EvidenceStore, bytes_digest
from agent_boundary_gate.fixtures import fixture
from agent_boundary_gate.gate_policy import evaluate


class EvidenceReadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = EvidenceStore(Path(self.temporary.name) / "store")
        self.raw = b'{"synthetic":true}'
        self.reference = self.store.persist(self.raw)
        self.path = self.store.root / (self.reference[7:] + ".json")

    def test_restart_retrieves_exact_bytes(self):
        reopened = EvidenceStore(self.store.root, create=False)
        self.assertEqual(reopened.read(self.reference), self.raw)

    def test_missing_store_is_not_created(self):
        missing = self.store.root / "missing"
        with self.assertRaises(ValueError):
            EvidenceStore(missing, create=False)
        self.assertFalse(missing.exists())

    def test_invalid_refs_never_open_files(self):
        for reference in ("../outside", "sha256:" + "A" * 64, self.reference + "/../file", None):
            with self.subTest(reference=reference), patch("os.open") as opened:
                with self.assertRaises(ValueError):
                    self.store.read(reference)
                opened.assert_not_called()

    def test_tampered_missing_and_public_artifacts_are_rejected(self):
        self.path.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "digest-mismatch"):
            self.store.read(self.reference)
        self.path.write_bytes(self.raw)
        self.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "not-private-or-regular"):
            self.store.read(self.reference)
        self.path.unlink()
        with self.assertRaises(OSError):
            self.store.read(self.reference)

    def test_symlink_and_fifo_do_not_block_or_read(self):
        self.path.unlink()
        other = self.store.root / "other"
        other.write_bytes(self.raw)
        self.path.symlink_to(other)
        with self.assertRaises(OSError):
            self.store.read(self.reference)
        self.path.unlink()
        os.mkfifo(self.path, mode=0o600)
        with self.assertRaisesRegex(ValueError, "not-private-or-regular"):
            self.store.read(self.reference)

    def test_limit_and_changed_directory_permissions(self):
        with self.assertRaisesRegex(ValueError, "read-limit-exceeded"):
            self.store.read(self.reference, max_bytes=1)
        self.assertEqual(self.store.read(self.reference, max_bytes=len(self.raw)), self.raw)
        for limit in (True, 0, -1):
            with self.assertRaises(ValueError):
                self.store.read(self.reference, max_bytes=limit)
        self.store.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "directory-not-private"):
            self.store.read(self.reference)


class EvidenceEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = EvidenceStore(Path(self.temporary.name) / "store")
        self.now = datetime.now(UTC)

    def record(self, scenario="healthy", *, monitor_packet=None):
        self.dispatch, record, self.key = fixture(scenario, now=self.now)
        self.heartbeat = self.store.persist_json({"synthetic-heartbeat": True})
        sources = tuple(
            source.model_copy(
                update={
                    "artifact_digest": self.store.persist_json(
                        (
                            monitor_packet
                            if monitor_packet is not None
                            else {"heartbeat_refs": [self.heartbeat]}
                        )
                        if source.source_id == "containment-monitor"
                        else {"source": source.source_id}
                    )
                }
            )
            for source in record.evidence.sources
        )
        evidence = record.evidence.model_copy(
            update={
                "sources": sources,
                "observed_effect_refs": (self.store.persist_json({"synthetic-effect": True}),)
                if record.evidence.observed_effect_refs
                else (),
            }
        )
        self.manifest = self.store.persist(canonical(evidence))
        return sign(
            record.result.model_copy(update={"evidence_manifest_digest": digest(evidence)}),
            evidence,
            self.key,
        )

    def decision(self, record):
        return evaluate(
            self.dispatch,
            [record],
            {"fixture-verifier": self.key.public_key()},
            now=self.now,
            job_complete=True,
            server_aggregate=record.result.invariant_held,
            evidence_store=self.store,
        )

    def remove(self, reference):
        (self.store.root / (reference[7:] + ".json")).unlink()

    def test_complete_references_pass_without_release_authority(self):
        decision = self.decision(self.record())
        self.assertEqual(decision.release_decision, "pass")
        self.assertFalse(decision.release_eligible)

    def test_missing_required_or_manifest_or_heartbeat_withholds_pass(self):
        for kind in ("manifest", "source", "heartbeat"):
            with self.subTest(kind=kind):
                record = self.record()
                reference = (
                    self.manifest
                    if kind == "manifest"
                    else self.heartbeat
                    if (kind == "heartbeat")
                    else record.evidence.sources[0].artifact_digest
                )
                self.remove(reference)
                decision = self.decision(record)
                self.assertEqual(decision.release_decision, "inconclusive")
                self.assertIn("referenced-evidence-unavailable", decision.decision_reasons)

    def test_corruption_and_storage_failure_withhold_pass(self):
        record = self.record()
        path = self.store.root / (self.manifest[7:] + ".json")
        path.write_bytes(b"tampered")
        self.assertEqual(self.decision(record).release_decision, "inconclusive")
        with patch.object(self.store, "read", side_effect=OSError("synthetic-store-outage")):
            self.assertEqual(self.decision(record).release_decision, "inconclusive")

    def test_optional_artifact_loss_only_degrades_diagnostics(self):
        record = self.record()
        self.remove(record.evidence.sources[-1].artifact_digest)
        decision = self.decision(record)
        self.assertEqual(decision.release_decision, "pass")
        self.assertEqual(decision.degraded_diagnostics, ("denied-egress-v1",))

    def test_missing_effect_preserves_violation_and_incident_precedence(self):
        record = self.record("weakened")
        self.remove(record.evidence.observed_effect_refs[0])
        decision = self.decision(record)
        self.assertEqual(decision.release_decision, "criteria_failed")
        self.assertEqual(decision.confirmed_violations, ("denied-egress-v1",))
        record = self.record("incident")
        self.remove(self.manifest)
        self.assertEqual(self.decision(record).release_decision, "incident")

    def test_invalid_monitor_inventory_fails_closed(self):
        for packet in (
            [],
            {},
            {"heartbeat_refs": "invalid"},
            {"heartbeat_refs": ["../outside"]},
            {"heartbeat_refs": [self.now.isoformat()]},
        ):
            with self.subTest(packet=packet):
                self.assertEqual(
                    self.decision(self.record(monitor_packet=packet)).release_decision,
                    "inconclusive",
                )

    def test_untrusted_record_cannot_trigger_artifact_reads(self):
        record = self.record()
        record = record.model_copy(update={"signature": "0" * 128})
        with patch.object(self.store, "read") as read:
            self.assertEqual(self.decision(record).release_decision, "inconclusive")
            read.assert_not_called()

    def test_digest_is_exact_bytes_not_reformatted_json(self):
        raw = b'{ "synthetic": true }'
        ref = self.store.persist(raw)
        self.assertEqual(self.store.read(ref), raw)
        self.assertNotEqual(ref, bytes_digest(b'{"synthetic":true}'))

    def test_cli_verifies_existing_store_and_detects_missing_artifact(self):
        record = self.record()
        root = Path(self.temporary.name)
        dispatch_path, records_path, key_path = (
            root / "dispatch.json",
            root / "records.json",
            root / "key",
        )
        dispatch_path.write_text(self.dispatch.model_dump_json())
        records_path.write_text("[" + record.model_dump_json() + "]")
        key_path.write_bytes(self.key.public_key().public_bytes_raw())
        command = [
            sys.executable,
            "-m",
            "agent_boundary_gate.cli",
            "verify",
            "--dispatch",
            str(dispatch_path),
            "--records",
            str(records_path),
            "--signer",
            "fixture-verifier",
            "--public-key",
            str(key_path),
            "--evidence-directory",
            str(self.store.root),
            "--job-complete",
            "--server-aggregate",
            "1.0",
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["release_decision"], "pass")
        self.remove(self.heartbeat)
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "referenced-evidence-unavailable", json.loads(result.stdout)["decision_reasons"]
        )
