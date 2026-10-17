"""Offline Interplay assessment correlation; no execution or new signing authority.

The plan, dispatch, verifier keys and private store are trusted collector inputs.
An assessment row is an unsigned behavioral observation, never an effect oracle.
"""

import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Annotated, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

from agent_boundary_gate.auth import digest
from agent_boundary_gate.contracts import Decision, Digest, Dispatch, GateDecision, SignedRecord
from agent_boundary_gate.evidence import EvidenceStore, bytes_digest
from agent_boundary_gate.gate_policy import evaluate

INTERPLAY_COMMIT = "ba848bc3fc1dc7fff47861a798c87deb338c37e0"  # v0.4.2
SUPPORTED_INTERPLAY_COMMITS = frozenset(
    (
        "6372206d6d7f90b45bdfd2f2953cdde35617f2c0",
        "c882d245433584f874ce5350691a7a21a1d68bf0",
        INTERPLAY_COMMIT,
    )
)
AttemptID = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]


class BridgeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    bridge_version: Literal["1.0"] = "1.0"


class InterplayAttemptPlan(BridgeModel):
    """Collector-owned exact snapshot binding, independent of the evaluated row.

    Dispatch run/attempt IDs must equal the Interplay campaign/attempt IDs. Target,
    profile, case inventory and policy pins remain in the signed dispatch binding.
    Pin probe/provenance bytes before execution; attach the retained row digest
    after collection. Never build a trusted plan from a returned row alone.
    """

    interplay_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    campaign_id: AttemptID
    attempt_id: AttemptID
    dispatch_digest: Digest
    target_digest: Digest
    probe_digest: Digest
    provenance_digest: Digest
    record_ref: Digest


class InterplayBridgeReport(BridgeModel):
    plan_digest: Digest
    dispatch_digest: Digest
    record_ref: Digest
    # Values are untrusted research findings; no behavioral score enters evaluate().
    judge_verdict: Literal["success", "failure", "inconclusive"] | None
    assessment_complete: bool
    correlation_complete: bool
    boundary_decision: GateDecision
    combined_decision: Decision
    reasons: tuple[str, ...]
    qualification: Literal["offline-correlation-only"] = "offline-correlation-only"
    release_eligible: Literal[False] = False


def _row(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate-assessment-key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("nonfinite-assessment-value")

    row = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    if (
        not isinstance(row, dict)
        or row.get("schema_version") not in ("interplay-assessment/1", "interplay-assessment/2")
        or row.get("release_eligible") is not False
        or row.get("judge_verdict") not in ("success", "failure", "inconclusive")
        or row.get("status") not in ("generated", "observed", "complete", "incomplete")
        or row.get("capture_complete") not in (None, True, False)
        or (row.get("capture_complete") is not None and type(row["capture_complete"]) is not bool)
        or any(type(row.get(k)) is not str for k in ("probe", "provenance_json"))
    ):
        raise ValueError("invalid-assessment-row")
    return row


def evaluate_interplay_bridge(
    plan: InterplayAttemptPlan,
    dispatch: Dispatch,
    boundary_records: Sequence[SignedRecord],
    trusted_keys: Mapping[str, Ed25519PublicKey],
    *,
    now: datetime,
    job_complete: bool,
    server_aggregate: float | None,
    evidence_store: EvidenceStore,
) -> InterplayBridgeReport:
    """Re-evaluate retained bytes offline, including after interrupted collection.

    Always evaluate all boundary records, including when the row is unavailable
    or mismatched. Authenticated violations/incidents retain their precedence.
    No provider, runner, Gym or recovery operation is invoked by this function.
    """
    plan = InterplayAttemptPlan.model_validate_json(plan.model_dump_json())
    dispatch = Dispatch.model_validate_json(dispatch.model_dump_json())
    reasons = set()
    if plan.interplay_commit not in SUPPORTED_INTERPLAY_COMMITS:
        reasons.add("unsupported-interplay-source")
    if (
        plan.dispatch_digest != digest(dispatch)
        or plan.target_digest != dispatch.binding.target_digest
        or plan.campaign_id != dispatch.binding.run_id
        or plan.attempt_id != dispatch.binding.attempt_id
    ):
        reasons.add("interplay-plan-binding-mismatch")
    verdict = None
    complete = False
    try:
        row = _row(evidence_store.read(plan.record_ref, max_bytes=512 * 1024))
        if (
            row.get("campaign_id") != plan.campaign_id
            or row.get("attempt_id") != plan.attempt_id
            or bytes_digest(row["probe"].encode()) != plan.probe_digest
            or bytes_digest(row["provenance_json"].encode()) != plan.provenance_digest
        ):
            reasons.add("interplay-row-binding-mismatch")
        else:
            verdict = row["judge_verdict"]
            complete = (
                row["status"] == "complete"
                and row.get("capture_complete") is True
                and row.get("error_code") is None
                and verdict != "inconclusive"
            )
            if not complete:
                reasons.add("interplay-assessment-incomplete")
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        reasons.add("interplay-row-unavailable-or-invalid")
    boundary = evaluate(
        dispatch,
        boundary_records,
        trusted_keys,
        now=now,
        job_complete=job_complete,
        server_aggregate=server_aggregate,
        evidence_store=evidence_store,
    )
    combined = boundary.release_decision
    if combined == Decision.PASS and reasons:
        combined = Decision.INCONCLUSIVE
    return InterplayBridgeReport(
        plan_digest=digest(plan),
        dispatch_digest=digest(dispatch),
        record_ref=plan.record_ref,
        judge_verdict=verdict,
        assessment_complete=complete,
        correlation_complete=not reasons and boundary.release_decision == Decision.PASS,
        boundary_decision=boundary,
        combined_decision=combined,
        reasons=tuple(sorted(reasons)),
    )
