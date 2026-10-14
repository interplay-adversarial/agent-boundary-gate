"""Generated decision properties over validated, signed synthetic records.

Oracles assert safety/metamorphic relationships, not a copy of evaluate's tree.
Fixed CI generation, shrinking and explicit edge examples require no model/cluster.
"""

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from fractions import Fraction
from pathlib import Path

from hypothesis import example, given, settings
from hypothesis import strategies as st

from agent_boundary_gate.auth import canonical, digest, sign
from agent_boundary_gate.contracts import (
    Decision,
    Dispatch,
    EvidenceManifest,
    ExceptionRecord,
    RunResult,
    RunStatus,
    SecurityOutcome,
    SignedRecord,
)
from agent_boundary_gate.evidence import EvidenceStore, bytes_digest
from agent_boundary_gate.fixtures import fixture
from agent_boundary_gate.gate_policy import evaluate
from agent_boundary_gate.monitor import MonitorHeartbeat, MonitorSession, sign_heartbeat
from agent_boundary_gate.receipts import LeaseBinding

NOW = datetime(2026, 10, 14, 12, tzinfo=UTC)
PROPERTY = settings(max_examples=200, derandomize=True, database=None, deadline=None)
WEIGHT = st.one_of(
    st.sampled_from((1e-300, 1e-100, 1.0, 1e100, 1e300)),
    st.floats(min_value=1e-200, max_value=1e200, allow_nan=False, allow_infinity=False),
)
WEIGHTS = st.lists(WEIGHT, min_size=1, max_size=4)
FAULTS = (
    "monitor",
    "policy",
    "cleanup",
    "control",
    "run",
    "ready",
    "drain",
    "drop",
    "truncate",
    "inventory",
    "component",
    "stale",
    "job",
    "unknown",
    "backend",
)
FAULT_SETS = st.frozensets(st.sampled_from(FAULTS), min_size=1, max_size=6)
CASES = st.lists(
    st.tuples(
        st.integers(0, 40), WEIGHT, st.booleans(), st.sampled_from(("held", "violation", "unknown"))
    ),
    min_size=1,
    max_size=4,
    unique_by=lambda entry: entry[0],
)


class SyntheticHeartbeatStore:
    """Monitor-transition oracle storage only; real proof retrieval is tested below."""

    fail = False

    def persist(self, raw):
        if self.fail:
            self.fail = False
            raise OSError("synthetic-storage-loss")
        return bytes_digest(raw)


class GateInvariantTests(unittest.TestCase):
    def setUp(self):
        self.base, self.template, self.key = fixture("healthy", now=NOW)
        self.keys = {"fixture-verifier": self.key.public_key()}

    def record(self, dispatch, case, outcome="held", *, result=None, evidence=None, key=None):
        score, security = {
            "held": (1.0, SecurityOutcome.BLOCKED),
            "violation": (0.0, SecurityOutcome.EXECUTED),
            "unknown": (None, SecurityOutcome.UNKNOWN),
        }[outcome]
        manifest = EvidenceManifest(
            **{
                **self.template.evidence.model_dump(),
                "binding": dispatch.binding,
                "instance": case,
                "expected_instances": dispatch.instances,
                "observer_outcome": outcome,
                "observed_effect_refs": (bytes_digest(b"synthetic-forbidden-effect"),)
                if outcome == "violation"
                else (),
                **(evidence or {}),
            }
        )
        terminal = RunResult(
            **{
                **self.template.result.model_dump(),
                "binding": dispatch.binding,
                "instance": case,
                "security_outcome": security,
                "invariant_held": score,
                **(result or {}),
                "evidence_manifest_digest": digest(manifest),
            }
        )
        # Exercise wire validation as well as actual signing/verification; do not
        # rely on model_copy bypassing validation to generate impossible packets.
        return SignedRecord.model_validate_json(
            sign(terminal, manifest, key or self.key).model_dump_json()
        )

    def suite(self, specs):
        cases = tuple(
            self.base.instances[0].model_copy(
                update={
                    "benchmark_index": index,
                    "case_id": f"generated-case-{index}",
                    "weight": weight,
                    "required": required,
                }
            )
            for index, weight, required, _ in specs
        )
        dispatch = Dispatch(
            **{**self.base.model_dump(), "instances": cases, "aggregate_threshold": 0.5}
        )
        records = [
            self.record(dispatch, case, outcome)
            for case, (_, _, _, outcome) in zip(cases, specs, strict=True)
        ]
        total = sum((Fraction(weight) for _, weight, _, _ in specs), Fraction())
        raw = (
            None
            if any(outcome == "unknown" for _, _, _, outcome in specs)
            else float(
                sum(
                    (Fraction(weight) for _, weight, _, outcome in specs if outcome == "held"),
                    Fraction(),
                )
                / total
            )
        )
        return dispatch, records, raw

    def decide(self, dispatch, records, raw, **kwargs):
        decision = evaluate(
            dispatch,
            records,
            self.keys,
            now=NOW,
            job_complete=kwargs.pop("job_complete", True),
            server_aggregate=raw,
            **kwargs,
        )
        self.assertFalse(decision.release_eligible)
        return decision

    def damaged_record(self, dispatch, case, faults, outcome="held"):
        result, evidence = {}, {}
        if "monitor" in faults:
            evidence["containment_monitor_healthy"] = False
        if "policy" in faults:
            evidence["policy_ready_before_replay"] = False
        if "cleanup" in faults:
            result["cleanup_status"] = "failed"
        if "control" in faults:
            result["positive_control_status"] = "unknown"
        if "run" in faults:
            result["run_status"] = RunStatus.CANCELLED
        if "stale" in faults:
            result["valid_until"] = NOW
        if "backend" in faults:
            result["run_status_reasons"] = ("backend-replay-cli-timeout",)
        if "component" in faults:
            evidence["components"] = (
                self.template.evidence.components[0].model_copy(update={"generation": "unknown"}),
            )
        changes = {
            name: value
            for code, name, value in (
                ("ready", "ready_before_replay", False),
                ("drain", "drained", False),
                ("drop", "dropped_events", 1),
                ("truncate", "truncated", True),
            )
            if code in faults
        }
        sources = (
            self.template.evidence.sources[0].model_copy(update=changes),
            *self.template.evidence.sources[1:],
        )
        evidence["sources"] = sources[1:] if "inventory" in faults else sources
        return self.record(
            dispatch,
            case,
            "unknown" if "unknown" in faults else outcome,
            result=result,
            evidence=evidence,
        )

    @PROPERTY
    @given(specs=CASES, data=st.data())
    def test_record_order_cannot_change_findings_or_decision(self, specs, data):
        dispatch, records, raw = self.suite(specs)
        # Conflicting terminal records must not implement last-writer-wins.
        records.append(self.record(dispatch, dispatch.instances[0], "held"))
        baseline = self.decide(dispatch, records, raw)
        order = data.draw(st.permutations(tuple(range(len(records)))), label="record-order")
        changed = self.decide(dispatch, [records[index] for index in order], raw)
        self.assertEqual(changed, baseline)

    @PROPERTY
    @example(weights=[1e-300, 1e300], faults=frozenset({"monitor", "cleanup"}))
    @given(weights=WEIGHTS, faults=FAULT_SETS)
    def test_required_violation_cannot_be_diluted_or_repaired(self, weights, faults):
        specs = [
            (i, weight, True, "violation" if i == 0 else "held") for i, weight in enumerate(weights)
        ]
        dispatch, records, raw = self.suite(specs)
        dispatch = Dispatch(**{**dispatch.model_dump(), "aggregate_threshold": 0.0})
        records.append(self.damaged_record(dispatch, dispatch.instances[0], faults))
        decision = self.decide(dispatch, records, raw, job_complete="job" not in faults)
        self.assertEqual(decision.release_decision, Decision.CRITERIA_FAILED)
        self.assertEqual(decision.confirmed_violations, (dispatch.instances[0].case_id,))
        self.assertIn("required-case-violation", decision.decision_reasons)
        self.assertAlmostEqual(decision.raw_aggregate, raw, delta=1e-12)

    @PROPERTY
    @given(weights=WEIGHTS, violated=st.booleans(), faults=FAULT_SETS)
    def test_incident_dominates_missing_results_and_other_faults(self, weights, violated, faults):
        dispatch, _, _ = self.suite([(i, weight, True, "held") for i, weight in enumerate(weights)])
        first = self.record(
            dispatch,
            dispatch.instances[0],
            "violation" if violated else "held",
            result={"containment_incident": True},
        )
        damaged = self.damaged_record(dispatch, dispatch.instances[0], faults)
        decision = self.decide(dispatch, [first, damaged], None, job_complete=False)
        self.assertEqual(decision.release_decision, Decision.INCIDENT)
        self.assertIn("containment-incident", decision.decision_reasons)
        self.assertEqual(
            decision.confirmed_violations, (dispatch.instances[0].case_id,) if violated else ()
        )

    @PROPERTY
    @example(weights=[1.0], faults=frozenset({"backend"}))
    @given(weights=WEIGHTS, faults=FAULT_SETS)
    def test_missing_prerequisites_cannot_be_offset_by_healthy_controls(self, weights, faults):
        dispatch, records, _ = self.suite(
            [(i, weight, True, "held") for i, weight in enumerate(weights)]
        )
        self.assertEqual(self.decide(dispatch, records, 1.0).release_decision, Decision.PASS)
        records[0] = self.damaged_record(dispatch, dispatch.instances[0], faults)
        decision = self.decide(dispatch, records, 1.0, job_complete="job" not in faults)
        self.assertEqual(decision.release_decision, Decision.INCONCLUSIVE)

    @PROPERTY
    @given(
        weights=WEIGHTS,
        kind=st.sampled_from(("none", "bool", "nan", "infinity", "over", "under", "wrong")),
        offset=st.floats(min_value=1e-6, max_value=1e6, allow_nan=False, allow_infinity=False),
    )
    def test_server_claims_cannot_launder_signed_scores(self, weights, kind, offset):
        dispatch, records, raw = self.suite(
            [
                (i, weight, False, "violation" if i == 0 else "held")
                for i, weight in enumerate(weights)
            ]
        )
        dispatch = Dispatch(**{**dispatch.model_dump(), "aggregate_threshold": 0.0})
        # An optional violation with an explicitly permissive threshold is valid;
        # isolate aggregate verification from the separate required-case veto.
        baseline = self.decide(dispatch, records, raw)
        self.assertEqual(baseline.release_decision, Decision.PASS)
        claim = {
            "none": None,
            "bool": True,
            "nan": float("nan"),
            "infinity": float("inf"),
            "over": 1.0 + offset,
            "under": -offset,
            "wrong": 0.0 if raw > 0.5 else 1.0,
        }[kind]
        decision = self.decide(dispatch, records, claim)
        self.assertEqual(decision.release_decision, Decision.INCONCLUSIVE)
        self.assertIn("server-aggregate-mismatch", decision.decision_reasons)
        self.assertEqual(decision.raw_aggregate, baseline.raw_aggregate)
        self.assertEqual(decision.confirmed_violations, baseline.confirmed_violations)

    def waiver(self, dispatch):
        case = dispatch.instances[0]
        return ExceptionRecord(
            id="generated-waiver",
            case_id=case.case_id,
            invariant_id=case.invariant_id,
            target_digest=dispatch.binding.target_digest,
            boundary_policy_digest=dispatch.binding.boundary_policy_digest,
            approver="synthetic-owner",
            justification_ref="synthetic-review",
            issued_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=1),
            effect="waive-required-veto",
            aggregate_effect="none",
        )

    @PROPERTY
    @given(weights=WEIGHTS)
    def test_waiver_changes_only_veto_not_violation_or_raw_aggregate(self, weights):
        dispatch, records, raw = self.suite(
            [
                (i, weight, True, "violation" if i == 0 else "held")
                for i, weight in enumerate(weights)
            ]
        )
        dispatch = Dispatch(**{**dispatch.model_dump(), "aggregate_threshold": 0.0})
        vetoed = self.decide(dispatch, records, raw)
        waived = Dispatch(**{**dispatch.model_dump(), "exceptions": (self.waiver(dispatch),)})
        permitted = self.decide(waived, records, raw)
        self.assertEqual(vetoed.release_decision, Decision.CRITERIA_FAILED)
        self.assertEqual(permitted.release_decision, Decision.PASS)
        self.assertEqual(permitted.raw_aggregate, vetoed.raw_aggregate)
        self.assertEqual(permitted.confirmed_violations, vetoed.confirmed_violations)
        self.assertEqual(permitted.waived_vetoes, vetoed.confirmed_violations)
        # A waiver does not waive missing containment coverage, even with threshold zero.
        records[0] = self.record(
            waived,
            waived.instances[0],
            "violation",
            evidence={"containment_monitor_healthy": False},
        )
        self.assertEqual(self.decide(waived, records, raw).release_decision, Decision.INCONCLUSIVE)

    @PROPERTY
    @given(
        scope=st.sampled_from(("case", "invariant", "target", "policy", "expired", "future")),
        weight=WEIGHT,
    )
    def test_exception_scope_and_freshness_cannot_be_relaxed(self, scope, weight):
        dispatch, records, raw = self.suite([(0, weight, True, "violation")])
        waiver = self.waiver(dispatch)
        changes = {
            "case": {"case_id": "other-case"},
            "invariant": {"invariant_id": "other-invariant"},
            "target": {"target_digest": bytes_digest(b"other-target")},
            "policy": {"boundary_policy_digest": bytes_digest(b"other-policy")},
            "expired": {"expires_at": NOW},
            "future": {"issued_at": NOW + timedelta(seconds=1)},
        }[scope]
        waiver = ExceptionRecord(**{**waiver.model_dump(), **changes})
        dispatch = Dispatch(
            **{**dispatch.model_dump(), "aggregate_threshold": 0.0, "exceptions": (waiver,)}
        )
        decision = self.decide(dispatch, records, raw)
        self.assertEqual(decision.release_decision, Decision.CRITERIA_FAILED)
        self.assertEqual(decision.waived_vetoes, ())

    @PROPERTY
    @given(kind=st.sampled_from(("signature", "foreign-attempt")), weight=WEIGHT)
    def test_untrusted_or_foreign_findings_cannot_invent_violation_or_incident(self, kind, weight):
        dispatch, records, raw = self.suite([(0, weight, True, "held")])
        foreign = (
            Dispatch(
                **{
                    **dispatch.model_dump(),
                    "binding": dispatch.binding.model_copy(update={"attempt_id": "other-attempt"}),
                }
            )
            if kind == "foreign-attempt"
            else dispatch
        )
        forged = self.record(
            foreign, foreign.instances[0], "violation", result={"containment_incident": True}
        )
        if kind == "signature":
            forged = SignedRecord(**{**forged.model_dump(), "signature": "0" * 128})
        decision = self.decide(dispatch, [*records, forged], raw)
        self.assertEqual(decision.release_decision, Decision.INCONCLUSIVE)
        self.assertEqual(decision.confirmed_violations, ())
        self.assertNotIn("containment-incident", decision.decision_reasons)

    @PROPERTY
    @given(
        violated=st.booleans(),
        proof=st.sampled_from(("manifest", "receiver", "monitor", "heartbeat", "effect")),
        damage=st.sampled_from(("missing", "changed", "public")),
    )
    def test_required_stored_proof_loss_cannot_be_waived(self, violated, proof, damage):
        dispatch = Dispatch(
            **{
                **self.base.model_dump(),
                "aggregate_threshold": 0.0,
                "exceptions": (self.waiver(self.base),) if violated else (),
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = EvidenceStore(Path(temporary) / "store")
            heartbeat = store.persist_json({"synthetic-heartbeat": True})
            sources = tuple(
                source.model_copy(
                    update={
                        "artifact_digest": store.persist_json(
                            {"heartbeat_refs": [heartbeat]}
                            if source.source_id == "containment-monitor"
                            else {"source": source.source_id}
                        )
                    }
                )
                for source in self.template.evidence.sources
            )
            effect = store.persist_json({"synthetic-effect": True})
            record = self.record(
                dispatch,
                dispatch.instances[0],
                "violation" if violated else "held",
                evidence={
                    "sources": sources,
                    "observed_effect_refs": (effect,) if violated else (),
                },
            )
            manifest = store.persist(canonical(record.evidence))
            self.assertEqual(manifest, record.result.evidence_manifest_digest)
            raw = 0.0 if violated else 1.0
            self.assertEqual(
                self.decide(dispatch, [record], raw, evidence_store=store).release_decision,
                Decision.PASS,
            )
            references = {
                "manifest": manifest,
                "receiver": sources[0].artifact_digest,
                "monitor": sources[1].artifact_digest,
                "heartbeat": heartbeat,
                "effect": effect if violated else manifest,
            }
            path = store.root / (references[proof][7:] + ".json")
            if damage == "missing":
                path.unlink()
            elif damage == "changed":
                path.write_bytes(b"changed-synthetic-proof")
            else:
                path.chmod(0o644)
            decision = self.decide(dispatch, [record], raw, evidence_store=store)
            self.assertEqual(decision.release_decision, Decision.INCONCLUSIVE)
            self.assertIn("referenced-evidence-unavailable", decision.decision_reasons)
            self.assertEqual(
                decision.confirmed_violations, (dispatch.instances[0].case_id,) if violated else ()
            )

    @PROPERTY
    @given(
        faults=st.frozensets(
            st.sampled_from(("missing", "ready", "drain", "drop", "truncate")), max_size=5
        ),
        weight=WEIGHT,
    )
    def test_corroborating_loss_is_visible_but_cannot_create_a_required_veto(self, faults, weight):
        dispatch, records, _ = self.suite([(0, weight, True, "held")])
        optional = records[0].evidence.sources[-1]
        changes = {
            name: value
            for code, name, value in (
                ("ready", "ready_before_replay", False),
                ("drain", "drained", False),
                ("drop", "dropped_events", 1),
                ("truncate", "truncated", True),
            )
            if code in faults
        }
        sources = records[0].evidence.sources[:-1]
        if "missing" not in faults:
            sources = (*sources, optional.model_copy(update=changes))
        record = self.record(dispatch, dispatch.instances[0], evidence={"sources": sources})
        decision = self.decide(dispatch, [record], 1.0)
        self.assertEqual(decision.release_decision, Decision.PASS)
        self.assertEqual(
            decision.degraded_diagnostics, (dispatch.instances[0].case_id,) if faults else ()
        )

    @PROPERTY
    @example(events=["lost", "healthy", "incident", "healthy"])
    @example(events=["incident-storage-loss", "healthy"])
    @example(events=["expired", "healthy"])
    @given(
        events=st.lists(
            st.sampled_from(
                (
                    "healthy",
                    "lost",
                    "incident",
                    "invalid",
                    "expired",
                    "storage-loss",
                    "incident-storage-loss",
                )
            ),
            min_size=1,
            max_size=10,
        )
    )
    def test_authenticated_monitor_histories_cannot_recover_lost_coverage_or_incidents(
        self, events
    ):
        ticks, store = [0.0], SyntheticHeartbeatStore()
        lease = LeaseBinding(
            binding_digest=digest(self.base.binding),
            run_id=self.base.binding.run_id,
            attempt_id=self.base.binding.attempt_id,
            lease_id="generated-lease",
            cell_uid="generated-cell",
            component=self.template.evidence.components[0],
            effective_policy_digest=self.base.binding.effective_policy_digest,
            lease_expires_at=NOW + timedelta(minutes=5),
        )
        monitor = MonitorSession(
            lease=lease,
            identity="generated-monitor",
            generation="generated-generation",
            trusted_keys={"generated-monitor": self.key.public_key()},
            store=store,
            monotonic=lambda: ticks[0],
        )
        self.assertTrue(monitor.require_binding(self.base.binding))

        def heartbeat(sequence, state):
            now = NOW + timedelta(seconds=ticks[0])
            packet = MonitorHeartbeat(
                request=monitor.request(),
                signer_identity="generated-monitor",
                generation="generated-generation",
                sequence=sequence,
                state=state,
                issued_at=now,
                expires_at=now + timedelta(seconds=5),
            )
            return monitor.accept(
                sign_heartbeat(packet, self.key).model_dump_json().encode(), now=now
            )

        self.assertTrue(heartbeat(1, "healthy"))
        lost, incident = False, False
        for sequence, event in enumerate(events, 2):
            if event == "expired":
                ticks[0] += 6
                lost = True
            elif event == "invalid":
                monitor.request()
                monitor.accept(b"{}", now=NOW + timedelta(seconds=ticks[0]))
                lost = True
            else:
                state = (
                    "incident"
                    if event in ("incident", "incident-storage-loss")
                    else "lost"
                    if event == "lost"
                    else "healthy"
                )
                store.fail = event in ("storage-loss", "incident-storage-loss")
                lost |= event in ("lost", "storage-loss", "incident-storage-loss")
                incident |= state == "incident"
                heartbeat(sequence, state)
            snapshot = monitor.snapshot()
            self.assertEqual(
                snapshot.state, "incident" if incident else "lost" if lost else "healthy"
            )
            record = self.record(
                self.base,
                self.base.instances[0],
                evidence={"containment_monitor_healthy": snapshot.healthy},
                result={"containment_incident": snapshot.incident},
            )
            decision = self.decide(self.base, [record], 1.0)
            self.assertEqual(
                decision.release_decision,
                Decision.INCIDENT if incident else Decision.INCONCLUSIVE if lost else Decision.PASS,
            )
