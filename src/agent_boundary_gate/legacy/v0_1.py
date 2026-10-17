"""Candidate 0.1 wire contracts. Unknown fields fail validation."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$")]
UnitFloat = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False, strict=True)]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_version: Literal["0.1"] = "0.1"


class RunStatus(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    INFRA_ERROR = "infra_error"
    UNSUPPORTED = "unsupported-detector"
    TELEMETRY_LOSS = "telemetry-loss"


class SecurityOutcome(StrEnum):
    BLOCKED = "blocked"
    DETECTED = "detected"
    EXECUTED_CONTAINED = "executed-contained"
    EXECUTED = "executed"
    UNKNOWN = "unknown"


class Decision(StrEnum):
    PASS = "pass"
    CRITERIA_FAILED = "criteria_failed"
    INCONCLUSIVE = "inconclusive"
    INCIDENT = "incident"


class Binding(Contract):
    run_id: Identifier
    attempt_id: Identifier
    target_digest: Digest
    suite_digest: Digest
    topology_digest: Digest
    boundary_policy_digest: Digest
    effective_policy_digest: Digest
    gate_policy_digest: Digest


class Action(Contract):
    operation: Literal["http_get"]
    receiver: Literal["allowed", "forbidden"]
    path: Literal["/probe"]
    timeout_seconds: Annotated[int, Field(gt=0, le=30, strict=True)]


class CaseSpec(Contract):
    id: Identifier
    version: Literal["1"]
    invariant_id: Identifier
    surface: Literal[4]
    evaluation_track: Literal["boundary"]
    required: bool
    severity: Literal["high"]
    expected_layer: Literal["openshell-egress"]
    expected_behavior: Literal["deny-forbidden-allow-control"]
    replay_digest: Digest
    fixture_digest: Digest
    detector_version: Identifier
    observer_version: Identifier
    required_sources: tuple[Identifier, ...]
    corroborating_sources: tuple[Identifier, ...]
    calibration_refs: tuple[Identifier, ...]
    prover: Literal["not-applicable-fixed-policy"]
    actions: tuple[Action, ...]

    @model_validator(mode="after")
    def check_sources(self) -> Self:
        if not self.required_sources or not self.calibration_refs:
            raise ValueError("required observers and calibration references must be declared")
        sources = self.required_sources + self.corroborating_sources
        if len(set(sources)) != len(sources):
            raise ValueError("source designations must be unique")
        if {a.receiver for a in self.actions} != {"allowed", "forbidden"}:
            raise ValueError("denied-egress requires both forbidden and allowed actions")
        return self


class CaseInstance(Contract):
    benchmark_index: Annotated[int, Field(ge=0, strict=True)]
    provider_id: Literal["openshell-boundary"]
    case_id: Identifier
    invariant_id: Identifier
    case_spec_digest: Digest
    detector_version: Identifier
    observer_version: Identifier
    required: bool
    weight: Annotated[float, Field(gt=0, allow_inf_nan=False, strict=True)]
    # Literal[] cannot hold a float (PEP 586); ge=le=1.0 on a strict float validates
    # exactly the same single value "1.0" without that restriction.
    threshold: Annotated[float, Field(ge=1.0, le=1.0, allow_inf_nan=False, strict=True)]
    required_sources: tuple[Identifier, ...]
    corroborating_sources: tuple[Identifier, ...]

    @model_validator(mode="after")
    def check_inventory(self) -> Self:
        sources = self.required_sources + self.corroborating_sources
        if not self.required_sources or len(set(sources)) != len(sources):
            raise ValueError("source inventory must be nonempty and unique")
        return self


class SourceEvidence(Contract):
    source_id: Identifier
    identity: Identifier
    generation: Identifier
    designation: Literal["required", "corroborating"]
    ready_before_replay: bool
    drained: bool
    dropped_events: Annotated[int, Field(ge=0, strict=True)]
    truncated: bool
    artifact_digest: Digest

    @property
    def complete(self) -> bool:
        return (
            self.ready_before_replay
            and self.drained
            and not self.dropped_events
            and not self.truncated
        )


class EvidenceManifest(Contract):
    binding: Binding
    expected_instances: tuple[CaseInstance, ...]
    instance: CaseInstance
    sandbox_uid: Identifier
    supervisor_generation: Identifier
    sources: tuple[SourceEvidence, ...]
    observer_outcome: Literal["held", "violation", "unknown"]
    observed_effect_refs: tuple[Digest, ...]
    policy_ready_before_replay: bool
    containment_monitor_healthy: bool

    @model_validator(mode="after")
    def violation_has_effect(self) -> Self:
        if self.observer_outcome == "violation" and not self.observed_effect_refs:
            raise ValueError("confirmed violation requires retained independent effect evidence")
        return self


class RunResult(Contract):
    binding: Binding
    instance: CaseInstance
    run_status: RunStatus
    run_status_reasons: tuple[Identifier, ...]
    security_outcome: SecurityOutcome
    positive_control_status: Literal["passed", "failed", "unknown"]
    cleanup_status: Literal["destroyed", "failed", "unknown"]
    containment_incident: bool
    evidence_manifest_digest: Digest
    invariant_held: UnitFloat | None
    signer_identity: Identifier
    issued_at: datetime
    valid_until: datetime

    @model_validator(mode="after")
    def freshness(self) -> Self:
        if self.issued_at.tzinfo is None or self.valid_until.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        if self.valid_until <= self.issued_at:
            raise ValueError("freshness interval must be positive")
        if self.invariant_held not in (None, 0.0, 1.0):
            raise ValueError("invariant_held is binary; progress belongs to discovery")
        return self


class SignedRecord(Contract):
    result: RunResult
    evidence: EvidenceManifest
    algorithm: Literal["Ed25519"]
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


class ExceptionRecord(Contract):
    id: Identifier
    case_id: Identifier
    invariant_id: Identifier
    target_digest: Digest
    boundary_policy_digest: Digest
    approver: Identifier
    justification_ref: Identifier
    issued_at: datetime
    expires_at: datetime
    effect: Literal["waive-required-veto"]
    aggregate_effect: Literal["none"]

    @model_validator(mode="after")
    def validity(self) -> Self:
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("exception times must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("exception expiry must follow issuance")
        return self


class Dispatch(Contract):
    binding: Binding
    collection_digest: Digest
    instances: tuple[CaseInstance, ...]
    aggregate_threshold: UnitFloat
    exceptions: tuple[ExceptionRecord, ...]
    dispatched_at: datetime
    deadline: datetime

    @model_validator(mode="after")
    def inventory(self) -> Self:
        if not self.instances:
            raise ValueError("suite must contain at least one case")
        for values in (
            [c.benchmark_index for c in self.instances],
            [c.case_id for c in self.instances],
            [e.id for e in self.exceptions],
        ):
            if len(values) != len(set(values)):
                raise ValueError("dispatch inventory must be unique")
        if self.dispatched_at.tzinfo is None or self.deadline.tzinfo is None:
            raise ValueError("dispatch times must be timezone-aware")
        if self.deadline <= self.dispatched_at:
            raise ValueError("deadline must follow dispatch")
        return self


class GateDecision(Contract):
    binding: Binding
    dispatch_digest: Digest
    release_decision: Decision
    # Phase 0 cannot authorize a release, even when the fixture policy is satisfied.
    release_eligible: Literal[False] = False
    qualification: Literal["m0-prototype"] = "m0-prototype"
    decision_reasons: tuple[Identifier, ...]
    raw_aggregate: UnitFloat | None
    confirmed_violations: tuple[Identifier, ...]
    waived_vetoes: tuple[Identifier, ...]
    degraded_diagnostics: tuple[Identifier, ...]
    evaluated_at: datetime
