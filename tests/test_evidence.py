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

    def test_waived_violation_still_requires_effect_proof_even_if_optional_source_shares_it(self):
        record = self.record("waived-veto-aggregate-miss")
        self.dispatch = self.dispatch.model_copy(update={"aggregate_threshold": 0.0})
        effect = record.evidence.observed_effect_refs[0]
        sources = (
            *record.evidence.sources[:-1],
            record.evidence.sources[-1].model_copy(
                update={"artifact_digest": effect},
            ),
        )
        evidence = record.evidence.model_copy(update={"sources": sources})
        self.store.persist(canonical(evidence))
        record = sign(
            record.result.model_copy(update={"evidence_manifest_digest": digest(evidence)}),
            evidence,
            self.key,
        )
        self.assertEqual(self.decision(record).release_decision, "pass")
        self.remove(effect)
        decision = self.decision(record)
        self.assertEqual(decision.release_decision, "inconclusive")
        self.assertIn("referenced-evidence-unavailable", decision.decision_reasons)
        self.assertEqual(decision.confirmed_violations, ("denied-egress-v1",))
        self.assertEqual(decision.waived_vetoes, ("denied-egress-v1",))
        self.assertEqual(decision.degraded_diagnostics, ("denied-egress-v1",))
        self.assertEqual(decision.raw_aggregate, 0.0)

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

    def test_read_budget_is_shared_across_distinct_case_records(self):
        record = self.record()
        first = self.dispatch.instances[0]
        second = first.model_copy(update={"benchmark_index": 1, "case_id": "second-case"})
        self.dispatch = self.dispatch.model_copy(update={"instances": (first, second)})
        records = []
        for instance in self.dispatch.instances:
            evidence = record.evidence.model_copy(
                update={
                    "expected_instances": self.dispatch.instances,
                    "instance": instance,
                }
            )
            self.store.persist(canonical(evidence))
            records.append(
                sign(
                    record.result.model_copy(
                        update={
                            "instance": instance,
                            "evidence_manifest_digest": digest(evidence),
                        }
                    ),
                    evidence,
                    self.key,
                )
            )
        with (
            patch("agent_boundary_gate.gate_policy.MAX_EVIDENCE_READS", 6),
            patch.object(self.store, "read", wraps=self.store.read) as read,
        ):
            decision = evaluate(
                self.dispatch,
                records,
                {"fixture-verifier": self.key.public_key()},
                now=self.now,
                job_complete=True,
                server_aggregate=1.0,
                evidence_store=self.store,
            )
        self.assertEqual(read.call_count, 6)
        self.assertEqual(decision.release_decision, "inconclusive")
        self.assertIn("evidence-read-budget-exceeded", decision.decision_reasons)

    def test_repeated_nested_heartbeats_cannot_bypass_read_budget(self):
        heartbeat = self.store.persist_json({"synthetic-heartbeat": True})
        record = self.record(monitor_packet={"heartbeat_refs": [heartbeat] * 10})
        with (
            patch("agent_boundary_gate.gate_policy.MAX_EVIDENCE_READS", 5),
            patch.object(self.store, "read", wraps=self.store.read) as read,
        ):
            decision = self.decision(record)
        self.assertEqual(read.call_count, 5)
        self.assertEqual(decision.release_decision, "inconclusive")
        self.assertIn("evidence-read-budget-exceeded", decision.decision_reasons)

    def test_byte_budget_caps_store_reads_and_success_charges_actual_bytes(self):
        record = self.record()
        refs = [
            self.manifest,
            *(s.artifact_digest for s in record.evidence.sources),
            self.heartbeat,
        ]
        total = sum(len(self.store.read(ref)) for ref in refs)
        with patch("agent_boundary_gate.gate_policy.MAX_EVIDENCE_BYTES", total + 1):
            self.assertEqual(self.decision(record).release_decision, "pass")
        # A final optional read that consumes the remaining reservation must
        # still report byte-budget exhaustion, without requiring another read.
        with patch("agent_boundary_gate.gate_policy.MAX_EVIDENCE_BYTES", total):
            decision = self.decision(record)
        self.assertEqual(decision.release_decision, "inconclusive")
        self.assertIn("evidence-read-budget-exceeded", decision.decision_reasons)
        budget = len(self.store.read(self.manifest))
        with (
            patch("agent_boundary_gate.gate_policy.MAX_EVIDENCE_BYTES", budget),
            patch.object(self.store, "read", wraps=self.store.read) as read,
        ):
            decision = self.decision(record)
        self.assertEqual(read.call_count, 1)
        self.assertEqual(read.call_args.kwargs["max_bytes"], budget - 1)
        self.assertEqual(decision.release_decision, "inconclusive")
        self.assertIn("evidence-read-budget-exceeded", decision.decision_reasons)

    def test_failed_reads_retain_byte_reservation_and_stop_further_io(self):
        record = self.record()
        with (
            patch("agent_boundary_gate.gate_policy.MAX_EVIDENCE_BYTES", 9),
            patch.object(self.store, "read", side_effect=OSError("synthetic-read-failure")) as read,
        ):
            decision = self.decision(record)
        self.assertEqual(read.call_count, 1)
        self.assertEqual(read.call_args.kwargs["max_bytes"], 8)
        self.assertIn("evidence-read-budget-exceeded", decision.decision_reasons)

    def test_optional_budget_exhaustion_withholds_pass_and_resets_per_evaluation(self):
        record = self.record()
        # Four reads cover all required artifacts; the optional source is fifth.
        with patch("agent_boundary_gate.gate_policy.MAX_EVIDENCE_READS", 4):
            decision = self.decision(record)
        self.assertEqual(decision.release_decision, "inconclusive")
        self.assertIn("evidence-read-budget-exceeded", decision.decision_reasons)
        with patch("agent_boundary_gate.gate_policy.MAX_EVIDENCE_READS", 5):
            for _ in range(2):
                self.assertEqual(self.decision(record).release_decision, "pass")

    def test_budget_exhaustion_preserves_violation_and_incident_precedence(self):
        for scenario, expected in (("weakened", "criteria_failed"), ("incident", "incident")):
            with self.subTest(scenario=scenario):
                record = self.record(scenario)
                with patch("agent_boundary_gate.gate_policy.MAX_EVIDENCE_READS", 1):
                    decision = self.decision(record)
                self.assertEqual(decision.release_decision, expected)
                self.assertIn("evidence-read-budget-exceeded", decision.decision_reasons)
                if scenario == "weakened":
                    self.assertEqual(decision.confirmed_violations, ("denied-egress-v1",))
