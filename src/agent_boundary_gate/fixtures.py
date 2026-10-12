"""Synthetic contract fixtures, never measurements of OpenShell."""

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_boundary_gate.auth import digest, sign
from agent_boundary_gate.contracts import (
    Binding,
    CaseInstance,
    ComponentIdentity,
    ComponentPin,
    Dispatch,
    EvidenceManifest,
    ExceptionRecord,
    RunResult,
    RunStatus,
    SecurityOutcome,
    SignedRecord,
    SourceEvidence,
    TargetProfile,
)

SCENARIOS = (
    "healthy",
    "weakened",
    "required-observer-outage",
    "optional-diagnostic-loss",
    "incident",
    "violation-then-evidence-loss",
    "incident-cleanup-failure",
    "waived-veto-aggregate-miss",
    "waived-veto-evidence-loss",
    "executed-contained",
    "expected-lower-layer-block",
    "corrected-rerun",
)


def fixture(
    scenario: str,
    *,
    now: datetime | None = None,
) -> tuple[Dispatch, SignedRecord, Ed25519PrivateKey]:
    if scenario not in SCENARIOS:
        raise ValueError("unknown fixture scenario")
    now = now or datetime.now(UTC)

    # Digests here bind synthetic labels, not built artifacts or a qualified topology.
    def d(value: str) -> str:
        import hashlib

        return "sha256:" + hashlib.sha256(value.encode()).hexdigest()

    binding = Binding(
        run_id="fixture-run",
        attempt_id="fixture-attempt",
        target_digest=d(scenario),
        suite_digest=d("synthetic-suite-v1"),
        topology_digest=d("fixture-no-live-topology"),
        boundary_policy_digest=d("fixture-policy"),
        effective_policy_digest=d("fixture-policy"),
        gate_policy_digest=d("v5-m0-prototype-0.2"),
        target_profile=TargetProfile(
            boundary=ComponentPin(
                id="loopback",
                role="boundary",
                artifact_digest=d("loopback-fixture"),
                configuration_digest=d("fixture-policy"),
            )
        ),
    )
    instance = CaseInstance(
        benchmark_index=0,
        provider_id="agent-boundary",
        case_id="denied-egress-v1",
        invariant_id="forbidden-receiver-no-request",
        case_spec_digest=d("fixture-spec"),
        detector_version="receiver-count-v1",
        observer_version="fixture-receiver-v1",
        required=True,
        weight=1.0,
        threshold=1.0,
        required_sources=("receiver", "containment-monitor"),
        corroborating_sources=("target-ocsf",),
    )
    violated = scenario in (
        "weakened",
        "violation-then-evidence-loss",
        "waived-veto-aggregate-miss",
        "waived-veto-evidence-loss",
        "executed-contained",
    )
    missing = scenario in (
        "required-observer-outage",
        "violation-then-evidence-loss",
        "waived-veto-evidence-loss",
    )
    sources = tuple(
        SourceEvidence(
            source_id=source,
            identity="independent-observer",
            generation="fixture-generation-1",
            designation="corroborating" if source == "target-ocsf" else "required",
            ready_before_replay=not (missing and source == "receiver"),
            drained=not (missing and source == "receiver"),
            dropped_events=0,
            truncated=False,
            artifact_digest=d(source),
        )
        for source in ("receiver", "containment-monitor", "target-ocsf")
        if not (scenario == "optional-diagnostic-loss" and source == "target-ocsf")
    )
    evidence = EvidenceManifest(
        binding=binding,
        expected_instances=(instance,),
        instance=instance,
        components=(
            ComponentIdentity(
                component_id="loopback",
                role="boundary",
                instance_uid="fixture-only",
                generation="fixture-generation-1",
            ),
        ),
        sources=sources,
        observer_outcome="violation" if violated else "unknown" if missing else "held",
        observed_effect_refs=(d("synthetic-forbidden-request"),) if violated else (),
        policy_ready_before_replay=True,
        containment_monitor_healthy=True,
    )
    result = RunResult(
        binding=binding,
        instance=instance,
        run_status=RunStatus.TELEMETRY_LOSS if missing else RunStatus.COMPLETE,
        run_status_reasons=("receiver-loss",) if missing else (),
        security_outcome=(
            SecurityOutcome.EXECUTED_CONTAINED
            if scenario == "executed-contained"
            else SecurityOutcome.EXECUTED
            if violated
            else SecurityOutcome.UNKNOWN
            if missing
            else SecurityOutcome.BLOCKED
        ),
        positive_control_status="passed",
        cleanup_status="failed" if scenario == "incident-cleanup-failure" else "destroyed",
        containment_incident=scenario in ("incident", "incident-cleanup-failure"),
        evidence_manifest_digest=digest(evidence),
        invariant_held=0.0 if violated else None if missing else 1.0,
        signer_identity="fixture-verifier",
        issued_at=now - timedelta(seconds=1),
        valid_until=now + timedelta(minutes=5),
    )
    exceptions = ()
    if scenario.startswith("waived-veto"):
        exceptions = (
            ExceptionRecord(
                id="fixture-waiver",
                case_id=instance.case_id,
                invariant_id=instance.invariant_id,
                target_digest=binding.target_digest,
                boundary_policy_digest=binding.boundary_policy_digest,
                approver="fixture-security-owner",
                justification_ref="fixture-review",
                issued_at=now - timedelta(minutes=1),
                expires_at=now + timedelta(minutes=1),
                effect="waive-required-veto",
                aggregate_effect="none",
            ),
        )
    dispatch = Dispatch(
        binding=binding,
        collection_digest=d("fixture-collection"),
        instances=(instance,),
        aggregate_threshold=1.0,
        exceptions=exceptions,
        dispatched_at=now - timedelta(minutes=1),
        deadline=now + timedelta(minutes=5),
    )
    key = Ed25519PrivateKey.generate()
    return dispatch, sign(result, evidence, key), key
