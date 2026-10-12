import json
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from agent_boundary_gate.auth import digest, sign
from agent_boundary_gate.case_registry import load_case
from agent_boundary_gate.contracts import Dispatch, RunResult, RunStatus, SecurityOutcome
from agent_boundary_gate.fixtures import fixture
from agent_boundary_gate.gate_policy import evaluate


class GateTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 9, 17, tzinfo=UTC)
        self.dispatch, self.record, self.key = fixture("healthy", now=self.now)

    def decision(self, dispatch=None, records=None, keys=None, **kwargs):
        return evaluate(
            dispatch or self.dispatch,
            [self.record] if records is None else records,
            {"fixture-verifier": self.key.public_key()} if keys is None else keys,
            now=kwargs.pop("now", self.now),
            job_complete=kwargs.pop("job_complete", True),
            server_aggregate=kwargs.pop("server_aggregate", 1.0),
            **kwargs,
        )

    def changed(self, result_changes=None, evidence_changes=None):
        evidence = self.record.evidence.model_copy(update=evidence_changes or {})
        result = self.record.result.model_copy(
            update={
                **(result_changes or {}),
                "evidence_manifest_digest": digest(evidence),
            }
        )
        return sign(result, evidence, self.key)

    def test_v5_table(self):
        scenarios = {
            "healthy": "pass",
            "weakened": "criteria_failed",
            "required-observer-outage": "inconclusive",
            "optional-diagnostic-loss": "pass",
            "incident": "incident",
            "violation-then-evidence-loss": "criteria_failed",
            "incident-cleanup-failure": "incident",
            "waived-veto-aggregate-miss": "criteria_failed",
            "waived-veto-evidence-loss": "inconclusive",
            "executed-contained": "criteria_failed",
            "expected-lower-layer-block": "pass",
            "corrected-rerun": "pass",
        }
        for scenario, expected in scenarios.items():
            with self.subTest(scenario=scenario):
                dispatch, record, key = fixture(scenario, now=self.now)
                decision = self.decision(
                    dispatch,
                    [record],
                    {"fixture-verifier": key.public_key()},
                    server_aggregate=record.result.invariant_held,
                )
                self.assertEqual(decision.release_decision, expected)
                self.assertFalse(decision.release_eligible)
                if "violation" in scenario or "waived" in scenario:
                    self.assertEqual(decision.confirmed_violations, ("denied-egress-v1",))

    def test_waiver_never_changes_aggregate(self):
        dispatch, record, key = fixture("waived-veto-aggregate-miss", now=self.now)
        decision = self.decision(
            dispatch, [record], {"fixture-verifier": key.public_key()}, server_aggregate=0.0
        )
        self.assertEqual(decision.raw_aggregate, 0.0)
        self.assertEqual(decision.waived_vetoes, ("denied-egress-v1",))
        self.assertIn("aggregate-threshold-miss", decision.decision_reasons)

    def test_expired_waiver_restores_veto(self):
        dispatch, record, key = fixture("waived-veto-aggregate-miss", now=self.now)
        expired = dispatch.exceptions[0].model_copy(update={"expires_at": self.now})
        dispatch = dispatch.model_copy(update={"exceptions": (expired,)})
        decision = self.decision(
            dispatch, [record], {"fixture-verifier": key.public_key()}, server_aggregate=0.0
        )
        self.assertEqual(decision.waived_vetoes, ())
        self.assertIn("required-case-violation", decision.decision_reasons)

    def test_optional_loss_is_visible(self):
        record = self.changed(evidence_changes={"sources": self.record.evidence.sources[:2]})
        decision = self.decision(records=[record])
        self.assertEqual(decision.release_decision, "pass")
        self.assertEqual(decision.degraded_diagnostics, ("denied-egress-v1",))

    def test_missing_result(self):
        self.assertEqual(self.decision(records=[]).release_decision, "inconclusive")

    def test_duplicate_result(self):
        self.assertIn(
            "duplicate-case-result",
            self.decision(records=[self.record, self.record]).decision_reasons,
        )

    def test_tampered_signature(self):
        record = self.record.model_copy(update={"signature": "00" * 64})
        self.assertEqual(self.decision(records=[record]).release_decision, "inconclusive")

    def test_unknown_signer(self):
        self.assertEqual(self.decision(keys={}).release_decision, "inconclusive")

    def test_wrong_key(self):
        key = Ed25519PrivateKey.generate()
        self.assertEqual(
            self.decision(keys={"fixture-verifier": key.public_key()}).release_decision,
            "inconclusive",
        )

    def test_payload_mutation(self):
        result = self.record.result.model_copy(update={"containment_incident": True})
        record = self.record.model_copy(update={"result": result})
        self.assertIn("unauthenticated-record", self.decision(records=[record]).decision_reasons)

    def test_manifest_digest_mismatch(self):
        result = self.record.result.model_copy(
            update={"evidence_manifest_digest": "sha256:" + "0" * 64}
        )
        record = sign(result, self.record.evidence, self.key)
        self.assertEqual(self.decision(records=[record]).release_decision, "inconclusive")

    def test_wrong_target(self):
        binding = self.record.result.binding.model_copy(
            update={"target_digest": "sha256:" + "0" * 64}
        )
        record = self.changed(
            result_changes={"binding": binding}, evidence_changes={"binding": binding}
        )
        self.assertIn("record-binding-mismatch", self.decision(records=[record]).decision_reasons)

    def test_inventory_mutation(self):
        record = self.changed(evidence_changes={"expected_instances": ()})
        self.assertEqual(self.decision(records=[record]).release_decision, "inconclusive")

    def test_stale_result(self):
        record = self.changed(result_changes={"valid_until": self.now})
        self.assertIn("stale-or-future-record", self.decision(records=[record]).decision_reasons)

    def test_result_predates_dispatch(self):
        record = self.changed(result_changes={"issued_at": self.now - timedelta(hours=1)})
        self.assertEqual(self.decision(records=[record]).release_decision, "inconclusive")

    def test_all_nonterminal_states_block(self):
        for status in RunStatus:
            if status == RunStatus.COMPLETE:
                continue
            with self.subTest(status=status):
                record = self.changed(result_changes={"run_status": status})
                self.assertEqual(self.decision(records=[record]).release_decision, "inconclusive")

    def test_job_incomplete(self):
        self.assertEqual(self.decision(job_complete=False).release_decision, "inconclusive")

    def test_cleanup_failure(self):
        record = self.changed(result_changes={"cleanup_status": "failed"})
        self.assertEqual(self.decision(records=[record]).release_decision, "inconclusive")

    def test_monitor_loss(self):
        record = self.changed(evidence_changes={"containment_monitor_healthy": False})
        self.assertEqual(self.decision(records=[record]).release_decision, "inconclusive")

    def test_no_positive_control(self):
        record = self.changed(result_changes={"positive_control_status": "unknown"})
        self.assertEqual(self.decision(records=[record]).release_decision, "inconclusive")

    def test_unready_policy(self):
        record = self.changed(evidence_changes={"policy_ready_before_replay": False})
        self.assertEqual(self.decision(records=[record]).release_decision, "inconclusive")

    def test_required_source_loss(self):
        for changes in (
            {"drained": False},
            {"dropped_events": 1},
            {"truncated": True},
            {"ready_before_replay": False},
        ):
            source = self.record.evidence.sources[0].model_copy(update=changes)
            record = self.changed(
                evidence_changes={"sources": (source, *self.record.evidence.sources[1:])}
            )
            self.assertEqual(self.decision(records=[record]).release_decision, "inconclusive")

    def test_required_source_cannot_be_downgraded(self):
        source = self.record.evidence.sources[0].model_copy(update={"designation": "corroborating"})
        record = self.changed(
            evidence_changes={"sources": (source, *self.record.evidence.sources[1:])}
        )
        self.assertEqual(self.decision(records=[record]).release_decision, "inconclusive")

    def test_duplicate_sources(self):
        record = self.changed(
            evidence_changes={
                "sources": (*self.record.evidence.sources, self.record.evidence.sources[0])
            }
        )
        self.assertEqual(self.decision(records=[record]).release_decision, "inconclusive")

    def test_metric_missing(self):
        record = self.changed(result_changes={"invariant_held": None})
        self.assertEqual(self.decision(records=[record]).release_decision, "inconclusive")

    def test_invalid_wire_scores_rejected(self):
        for score in (True, "1", float("nan"), float("inf"), -1.0, 0.5, 2.0):
            with self.subTest(score=score), self.assertRaises(ValidationError):
                RunResult.model_validate(
                    {**self.record.result.model_dump(), "invariant_held": score}
                )

    def test_invalid_server_scores_block(self):
        for score in (None, True, float("nan"), float("inf"), -1.0, 0.9, 2.0):
            with self.subTest(score=score):
                self.assertEqual(
                    self.decision(server_aggregate=score).release_decision, "inconclusive"
                )

    def test_duplicate_dispatch_rejected(self):
        with self.assertRaises(ValidationError):
            Dispatch.model_validate(
                {**self.dispatch.model_dump(), "instances": self.dispatch.instances * 2}
            )

    def test_unknown_fields_rejected(self):
        with self.assertRaises(ValidationError):
            RunResult.model_validate(
                {**self.record.result.model_dump(), "raw_transcript": "sentinel"}
            )

    def test_dispatch_expiry(self):
        self.assertEqual(self.decision(now=self.dispatch.deadline).release_decision, "inconclusive")

    def test_required_miss_with_high_aggregate(self):
        dispatch, record, key = fixture("weakened", now=self.now)
        other = dispatch.instances[0].model_copy(
            update={"benchmark_index": 1, "case_id": "allowed-control-v1", "weight": 99.0}
        )
        dispatch = dispatch.model_copy(
            update={"instances": (*dispatch.instances, other), "aggregate_threshold": 0.9}
        )
        evidence = record.evidence.model_copy(update={"expected_instances": dispatch.instances})
        result = record.result.model_copy(update={"evidence_manifest_digest": digest(evidence)})
        failed = sign(result, evidence, key)
        healthy_evidence = evidence.model_copy(
            update={"instance": other, "observer_outcome": "held", "observed_effect_refs": ()}
        )
        healthy_result = result.model_copy(
            update={
                "instance": other,
                "security_outcome": SecurityOutcome.BLOCKED,
                "invariant_held": 1.0,
                "evidence_manifest_digest": digest(healthy_evidence),
            }
        )
        healthy = sign(healthy_result, healthy_evidence, key)
        decision = self.decision(
            dispatch,
            [failed, healthy],
            {"fixture-verifier": key.public_key()},
            server_aggregate=0.99,
        )
        self.assertEqual(decision.raw_aggregate, 0.99)
        self.assertEqual(decision.release_decision, "criteria_failed")

    def test_aggregate_only_miss(self):
        dispatch, record, key = fixture("weakened", now=self.now)
        case = dispatch.instances[0].model_copy(update={"required": False})
        dispatch = dispatch.model_copy(update={"instances": (case,)})
        evidence = record.evidence.model_copy(
            update={"instance": case, "expected_instances": (case,)}
        )
        result = record.result.model_copy(
            update={"instance": case, "evidence_manifest_digest": digest(evidence)}
        )
        decision = self.decision(
            dispatch,
            [sign(result, evidence, key)],
            {"fixture-verifier": key.public_key()},
            server_aggregate=0.0,
        )
        self.assertEqual(decision.release_decision, "criteria_failed")
        self.assertNotIn("required-case-violation", decision.decision_reasons)

    def test_cli_exit_codes(self):
        for scenario, code in (
            ("healthy", 0),
            ("weakened", 1),
            ("required-observer-outage", 2),
            ("incident", 3),
        ):
            process = subprocess.run(
                [sys.executable, "-m", "agent_boundary_gate.cli", "demo", "--scenario", scenario],
                capture_output=True,
                text=True,
            )
            self.assertEqual(process.returncode, code, process.stderr)
            self.assertFalse(json.loads(process.stdout)["release_eligible"])

    def test_cli_verifies_signed_json_roundtrip(self):
        dispatch, record, key = fixture("healthy")
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "dispatch.json").write_text(dispatch.model_dump_json())
            (folder / "records.json").write_text("[" + record.model_dump_json() + "]")
            (folder / "public.bin").write_bytes(key.public_key().public_bytes_raw())
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agent_boundary_gate.cli",
                    "verify",
                    "--dispatch",
                    str(folder / "dispatch.json"),
                    "--records",
                    str(folder / "records.json"),
                    "--signer",
                    "fixture-verifier",
                    "--public-key",
                    str(folder / "public.bin"),
                    "--job-complete",
                    "--server-aggregate",
                    "1.0",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(json.loads(process.stdout)["release_decision"], "pass")

    def test_case_registry_rejects_mutated_replay(self):
        path = Path(__file__).resolve().parents[1] / "examples/denied-egress-v1.json"
        case = load_case(path)
        self.assertEqual(case.id, "denied-egress-v1")
        data = json.loads(path.read_text())
        data["actions"][0]["timeout_seconds"] = 6
        with tempfile.TemporaryDirectory() as temp:
            changed = Path(temp) / "case.json"
            changed.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                load_case(changed)

    def test_boolean_coercions_rejected(self):
        for value in ("false", "true", 0, 1):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                RunResult.model_validate(
                    {**self.record.result.model_dump(), "containment_incident": value}
                )


if __name__ == "__main__":
    unittest.main()
