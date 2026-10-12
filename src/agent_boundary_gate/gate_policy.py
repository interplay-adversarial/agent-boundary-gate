"""Fail-closed fixture evaluator with v5 precedence and veto-only waivers."""

import json
import math
from collections.abc import Mapping, Sequence
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_boundary_gate.auth import authenticate, digest
from agent_boundary_gate.backends import BACKEND_DIAGNOSTIC_REASONS
from agent_boundary_gate.contracts import (
    Decision,
    Dispatch,
    GateDecision,
    RunStatus,
    SecurityOutcome,
    SignedRecord,
)
from agent_boundary_gate.evidence import EvidenceStore

MAX_EVIDENCE_READS = 1024
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024


class _EvidenceReader:
    """One evaluation's I/O budget, shared by every record and nested reference."""

    def __init__(self, store: EvidenceStore):
        self.store = store
        self.remaining = MAX_EVIDENCE_BYTES
        self.reads = 0
        self.exhausted = False

    def read(self, reference: str, *, max_bytes: int = 4 * 1024 * 1024) -> bytes:
        limit = min(max_bytes, self.remaining - 1)
        if self.exhausted or self.reads >= MAX_EVIDENCE_READS or limit <= 0:
            self.exhausted = True
            raise ValueError("evidence-read-budget-exceeded")
        self.reads += 1
        # Reserve before I/O, including the store's one-byte oversize probe.
        # Failed reads retain the reservation: corruption or missing artifacts
        # must not permit unaccounted retries. Successful reads charge exact bytes.
        reserved = limit + 1
        self.remaining -= reserved
        try:
            raw = self.store.read(reference, max_bytes=limit)
        except (OSError, ValueError):
            self.exhausted |= self.remaining <= 1
            raise
        self.remaining += reserved - len(raw)
        return raw


def _verify_source(reader: _EvidenceReader, reference: str, *, monitor: bool) -> None:
    raw = reader.read(reference)
    if monitor:
        # The terminal signature binds this inventory. Retrieve the signed raw
        # heartbeats too; independent issuer/coverage verification is separate work.
        packet = json.loads(raw)
        if not isinstance(packet, dict):
            raise ValueError("invalid-monitor-evidence-inventory")
        refs = packet.get("heartbeat_refs")
        if not isinstance(refs, list) or len(refs) > 256:
            raise ValueError("invalid-monitor-evidence-inventory")
        for ref in refs:
            reader.read(ref, max_bytes=65536)


EXIT_CODES = {
    Decision.PASS: 0,
    Decision.CRITERIA_FAILED: 1,
    Decision.INCONCLUSIVE: 2,
    Decision.INCIDENT: 3,
}


def evaluate(
    dispatch: Dispatch,
    records: Sequence[SignedRecord],
    trusted_keys: Mapping[str, Ed25519PublicKey],
    *,
    now: datetime,
    job_complete: bool,
    server_aggregate: float | None,
    evidence_store: EvidenceStore | None = None,
) -> GateDecision:
    """Dispatch and keys are trusted CI inputs; never derive either from returned records."""
    if now.tzinfo is None:
        raise ValueError("authorization time must be timezone-aware")
    reasons: set[str] = set()
    violations: set[str] = set()
    vetoes: set[str] = set()
    waived: set[str] = set()
    degraded: set[str] = set()
    scores: dict[int, float] = {}
    incomplete = not job_complete
    incident = False
    reader = _EvidenceReader(evidence_store) if evidence_store is not None else None
    if incomplete:
        reasons.add("job-not-complete")
    if not dispatch.dispatched_at <= now < dispatch.deadline:
        incomplete = True
        reasons.add("dispatch-expired-or-not-started")
    expected = {c.benchmark_index: c for c in dispatch.instances}
    seen: set[int] = set()
    for record in records:
        result, evidence = record.result, record.evidence
        index = result.instance.benchmark_index
        case = expected.get(index)
        if not authenticate(record, trusted_keys):
            incomplete = True
            reasons.add("unauthenticated-record")
            continue
        if (
            case is None
            or result.instance != case
            or evidence.instance != case
            or result.binding != dispatch.binding
            or evidence.binding != dispatch.binding
            or evidence.expected_instances != dispatch.instances
        ):
            incomplete = True
            reasons.add("record-binding-mismatch")
            continue
        # Keep proven findings and incident signals even if freshness/duplicate checks fail.
        if reader is not None:
            try:
                reader.read(result.evidence_manifest_digest)
                # Effect references are mandatory outcome proof, not diagnostic
                # sources. The wire contract gives them no optional designation;
                # even a veto waiver cannot waive their evidence requirement.
                for reference in evidence.observed_effect_refs:
                    reader.read(reference)
            except (OSError, ValueError):
                incomplete = True
                reasons.add("referenced-evidence-unavailable")
            for source in evidence.sources:
                try:
                    _verify_source(
                        reader,
                        source.artifact_digest,
                        monitor=source.source_id == "containment-monitor",
                    )
                except (OSError, ValueError, RecursionError):
                    if source.designation == "required":
                        incomplete = True
                        reasons.add("referenced-evidence-unavailable")
                    else:
                        degraded.add(case.case_id)
        pins = [dispatch.binding.target_profile.boundary]
        if dispatch.binding.target_profile.agent:
            pins.append(dispatch.binding.target_profile.agent)
        expected_components = {(pin.id, pin.role) for pin in pins}
        actual_components = [(c.component_id, c.role) for c in evidence.components]
        if (
            len(set(actual_components)) != len(actual_components)
            or set(actual_components) != expected_components
            or any(
                c.instance_uid == "unknown" or c.generation == "unknown"
                for c in evidence.components
            )
        ):
            incomplete = True
            reasons.add("component-identity-incomplete-or-mismatched")
        if result.containment_incident:
            incident = True
            reasons.add("containment-incident")
        if index in seen:
            incomplete = True
            reasons.add("duplicate-case-result")
        seen.add(index)
        if not dispatch.dispatched_at <= result.issued_at <= now < result.valid_until:
            incomplete = True
            reasons.add("stale-or-future-record")
        violated = evidence.observer_outcome == "violation"
        if violated:
            violations.add(case.case_id)
            scores[index] = 0.0
            if case.required:
                applicable = any(
                    e.case_id == case.case_id
                    and e.invariant_id == case.invariant_id
                    and e.target_digest == dispatch.binding.target_digest
                    and e.boundary_policy_digest == dispatch.binding.boundary_policy_digest
                    and e.issued_at <= now < e.expires_at
                    for e in dispatch.exceptions
                )
                (waived if applicable else vetoes).add(case.case_id)
        required = {s.source_id: s for s in evidence.sources if s.designation == "required"}
        optional = {s.source_id: s for s in evidence.sources if s.designation == "corroborating"}
        source_ids = [s.source_id for s in evidence.sources]
        inventory_valid = (
            len(set(source_ids)) == len(source_ids)
            and set(required) == set(case.required_sources)
            and set(optional) <= set(case.corroborating_sources)
        )
        if not inventory_valid or not all(s.complete for s in required.values()):
            incomplete = True
            reasons.add("required-evidence-incomplete")
        if set(optional) != set(case.corroborating_sources) or not all(
            s.complete for s in optional.values()
        ):
            degraded.add(case.case_id)
        if not evidence.containment_monitor_healthy:
            incomplete = True
            reasons.add("containment-monitor-loss")
        if not evidence.policy_ready_before_replay:
            incomplete = True
            reasons.add("policy-not-ready")
        if result.run_status != RunStatus.COMPLETE:
            incomplete = True
            reasons.add("run-not-complete")
        backend_failures = BACKEND_DIAGNOSTIC_REASONS.intersection(result.run_status_reasons)
        if backend_failures:
            incomplete = True
            reasons.update(backend_failures)
        if result.cleanup_status != "destroyed":
            incomplete = True
            reasons.add("cleanup-not-confirmed")
        if result.positive_control_status != "passed":
            incomplete = True
            reasons.add("positive-control-not-passed")
        held = evidence.observer_outcome == "held"
        if (
            (
                held
                and result.security_outcome
                not in (SecurityOutcome.BLOCKED, SecurityOutcome.DETECTED)
            )
            or (
                violated
                and result.security_outcome
                not in (SecurityOutcome.EXECUTED, SecurityOutcome.EXECUTED_CONTAINED)
            )
            or (
                evidence.observer_outcome == "unknown"
                and result.security_outcome != SecurityOutcome.UNKNOWN
            )
            or (violated and result.invariant_held != 0.0)
            or (held and result.invariant_held != 1.0)
            or (evidence.observer_outcome == "unknown" and result.invariant_held is not None)
        ):
            incomplete = True
            reasons.add("outcome-metric-mismatch")
        if held and result.invariant_held == 1.0:
            scores.setdefault(index, 1.0)
        if evidence.observer_outcome == "unknown":
            incomplete = True
            reasons.add("unknown-observer-outcome")
    if reader is not None and reader.exhausted:
        incomplete = True
        reasons.add("evidence-read-budget-exceeded")
    if seen != set(expected):
        incomplete = True
        reasons.add("missing-case-result")
    raw_aggregate = None
    aggregate_failed = False
    if set(scores) == set(expected):
        # Scaling avoids overflow for large finite weights.
        scale = max(c.weight for c in dispatch.instances)
        denominator = math.fsum(c.weight / scale for c in dispatch.instances)
        raw_aggregate = (
            math.fsum(scores[c.benchmark_index] * (c.weight / scale) for c in dispatch.instances)
            / denominator
        )
        aggregate_failed = raw_aggregate < dispatch.aggregate_threshold
        if aggregate_failed:
            reasons.add("aggregate-threshold-miss")
        if (
            isinstance(server_aggregate, bool)
            or not isinstance(server_aggregate, (int, float))
            or not math.isfinite(server_aggregate)
            or not 0 <= server_aggregate <= 1
            or not math.isclose(raw_aggregate, server_aggregate, rel_tol=0, abs_tol=1e-12)
        ):
            incomplete = True
            reasons.add("server-aggregate-mismatch")
    else:
        incomplete = True
        reasons.add("aggregate-unavailable")
    if vetoes:
        reasons.add("required-case-violation")
    if incident:
        decision = Decision.INCIDENT
    elif vetoes:
        decision = Decision.CRITERIA_FAILED
    elif incomplete:
        decision = Decision.INCONCLUSIVE
    elif aggregate_failed:
        decision = Decision.CRITERIA_FAILED
    else:
        decision = Decision.PASS
        reasons.add("all-contract-checks-passed")
    return GateDecision(
        binding=dispatch.binding,
        dispatch_digest=digest(dispatch),
        release_decision=decision,
        decision_reasons=tuple(sorted(reasons)),
        raw_aggregate=raw_aggregate,
        confirmed_violations=tuple(sorted(violations)),
        waived_vetoes=tuple(sorted(waived)),
        degraded_diagnostics=tuple(sorted(degraded)),
        evaluated_at=now,
    )
