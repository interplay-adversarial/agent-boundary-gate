"""One bounded attempt: start observer, verify readiness, replay, drain, destroy, sign."""

import time
from datetime import UTC, datetime, timedelta
from threading import Event, Thread

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_boundary_gate.agents import AgentAdapter
from agent_boundary_gate.auth import canonical, digest, sign
from agent_boundary_gate.backends import BoundaryBackend, Readiness, UnsupportedCapability
from agent_boundary_gate.case_registry import replay_digest
from agent_boundary_gate.contracts import (
    CaseSpec,
    Dispatch,
    EvidenceManifest,
    RunResult,
    RunStatus,
    SecurityOutcome,
    SignedRecord,
    SourceEvidence,
    ToolRequestAction,
)
from agent_boundary_gate.evidence import EvidenceStore
from agent_boundary_gate.observers import Observation, Observer
from agent_boundary_gate.process import AttemptStopped


class AttemptControl:
    """Independent monitor supplies these signals; local tests inject them explicitly."""

    def __init__(self):
        self.cancelled = Event()
        self.monitor_healthy = Event()
        self.monitor_healthy.set()
        self.incident = Event()


def run_attempt(
    dispatch: Dispatch,
    case: CaseSpec,
    driver: BoundaryBackend,
    observer: Observer,
    store: EvidenceStore,
    key: Ed25519PrivateKey,
    signer_identity: str,
    control: AttemptControl,
    *,
    agent: AgentAdapter | None = None,
    readiness_budget: float = 5.0,
    cleanup_budget: float = 5.0,
) -> SignedRecord:
    if len(dispatch.instances) != 1 or dispatch.instances[0].case_spec_digest != digest(case):
        raise ValueError("attempt requires one pinned CaseSpec")
    if replay_digest(case) != case.replay_digest:
        raise ValueError("case actions differ from their frozen replay digest")
    instance = dispatch.instances[0]
    if (
        instance.case_id != case.id
        or instance.invariant_id != case.invariant_id
        or instance.required != case.required
        or instance.required_sources != case.required_sources
        or instance.corroborating_sources != case.corroborating_sources
        or instance.observer_version != case.observer_version
        or instance.detector_version != case.detector_version
        or observer.attempt_id != dispatch.binding.attempt_id
    ):
        raise ValueError("case, observer and dispatch must match")
    if not 0 < readiness_budget <= 60 or not 0 < cleanup_budget <= 60:
        raise ValueError("lifecycle budgets must be bounded")
    duration = (dispatch.deadline - datetime.now(UTC)).total_seconds()
    deadline = time.monotonic() + max(0, duration)
    reasons: set[str] = set()
    status = RunStatus.COMPLETE
    ready = Readiness((), dispatch.binding.effective_policy_digest, False)
    replay_completed = False
    cleanup = "unknown"
    watch_done = Event()
    monitor_loss_seen = Event()
    monitor_ready_at_start = control.monitor_healthy.is_set()

    def watch() -> None:
        while not watch_done.wait(0.01):
            if not control.monitor_healthy.is_set():
                monitor_loss_seen.set()
            if control.incident.is_set() or not control.monitor_healthy.is_set():
                control.cancelled.set()

    profile = dispatch.binding.target_profile

    def current_state(*, deadline: float, cancelled: Event) -> Readiness:
        boundary = driver.readiness(deadline=deadline, cancelled=cancelled)
        components = boundary.components
        valid = boundary.ready
        if agent is not None:
            application = agent.readiness(deadline=deadline, cancelled=cancelled)
            components += application.components
            valid = (
                valid
                and application.ready
                and profile.agent is not None
                and application.effective_policy_digest == profile.agent.configuration_digest
            )
        pins = [profile.boundary] + ([profile.agent] if profile.agent else [])
        expected = {(pin.id, pin.role) for pin in pins}
        actual = [(c.component_id, c.role) for c in components]
        valid = valid and len(set(actual)) == len(actual) and set(actual) == expected
        return Readiness(
            tuple(sorted(components, key=lambda component: component.component_id)),
            boundary.effective_policy_digest,
            valid,
        )

    watcher = Thread(target=watch)
    watcher.start()
    try:
        observer.require_supported(case)
        if driver.backend_id != profile.boundary.id:
            raise UnsupportedCapability("boundary-backend-profile-mismatch")
        if (profile.agent is None) != (agent is None) or (
            agent is not None and agent.agent_id != profile.agent.id
        ):
            raise UnsupportedCapability("agent-adapter-unavailable-or-mismatched")
        capabilities = (
            agent.capabilities
            if case.enforcement_layer == "agent" and agent is not None
            else driver.capabilities
        )
        if not set(case.required_capabilities) <= capabilities:
            raise UnsupportedCapability("required-capability-unsupported")
        observer.start()
        if not control.monitor_healthy.is_set() or control.incident.is_set():
            raise AttemptStopped("containment-stop")
        if datetime.now(UTC) < dispatch.dispatched_at:
            raise AttemptStopped("dispatch-not-started")
        ready_deadline = min(deadline, time.monotonic() + readiness_budget)
        while True:
            ready = current_state(deadline=ready_deadline, cancelled=control.cancelled)
            if (
                ready.ready
                and ready.effective_policy_digest == dispatch.binding.effective_policy_digest
            ):
                break
            if control.cancelled.is_set():
                raise AttemptStopped("cancelled")
            if time.monotonic() >= ready_deadline:
                raise AttemptStopped("policy-readiness-timeout")
            control.cancelled.wait(min(0.02, max(0, ready_deadline - time.monotonic())))
        for action in case.actions:
            if (
                control.cancelled.is_set()
                or not control.monitor_healthy.is_set()
                or control.incident.is_set()
            ):
                raise AttemptStopped(
                    "containment-stop" if control.incident.is_set() else "cancelled"
                )
            action_deadline = min(deadline, time.monotonic() + action.timeout_seconds)
            if isinstance(action, ToolRequestAction):
                if agent is None:
                    raise UnsupportedCapability("tool-action-requires-agent-adapter")
                completed = agent.request_tool(
                    action,
                    dispatch.binding.attempt_id,
                    deadline=action_deadline,
                    cancelled=control.cancelled,
                )
            else:
                completed = driver.replay(
                    action,
                    observer.endpoint(action),
                    dispatch.binding.attempt_id,
                    deadline=action_deadline,
                    cancelled=control.cancelled,
                )
            if not completed:
                raise AttemptStopped("replay-not-complete")
            if not observer.positive_control_observed(action):
                raise AttemptStopped("positive-control-not-observed")
            after = current_state(deadline=action_deadline, cancelled=control.cancelled)
            if not after.ready or after != ready:
                raise AttemptStopped("target-or-policy-generation-changed")
        replay_completed = True
    except UnsupportedCapability:
        reasons.add("adapter-or-capability-unsupported")
        status = RunStatus.UNSUPPORTED
    except AttemptStopped as stopped:
        reasons.add(stopped.reason)
        status = RunStatus.TIMEOUT if "timeout" in stopped.reason else RunStatus.CANCELLED
    except KeyboardInterrupt:
        reasons.add("interrupted")
        control.cancelled.set()
        status = RunStatus.CANCELLED
    except Exception:
        reasons.add("driver-or-observer-error")
        status = RunStatus.INFRA_ERROR
    finally:
        try:
            observer.stop()
        except (Exception, KeyboardInterrupt):
            reasons.add("observer-drain-error")
            status = RunStatus.TELEMETRY_LOSS
        try:
            cleanup = (
                "destroyed"
                if driver.destroy(deadline=time.monotonic() + cleanup_budget)
                else "failed"
            )
        except (Exception, KeyboardInterrupt):
            cleanup = "failed"
        if cleanup != "destroyed":
            reasons.add("cleanup-not-confirmed")
            if status == RunStatus.COMPLETE:
                status = RunStatus.INCOMPLETE
        watch_done.set()
        watcher.join(timeout=2)
    monitor_healthy = control.monitor_healthy.is_set() and not monitor_loss_seen.is_set()
    if not monitor_healthy:
        reasons.add("containment-monitor-loss")
        status = RunStatus.TELEMETRY_LOSS
    try:
        observation = observer.observe(
            execution_valid=replay_completed
            and ready.ready
            and monitor_healthy
            and not control.incident.is_set()
        )
    except Exception:
        observation = Observation("unknown", "unknown", (), (), False)
        reasons.add("observer-finalization-error")
    if not observation.complete:
        reasons.add("required-observer-evidence-loss")
        if status == RunStatus.COMPLETE:
            status = RunStatus.TELEMETRY_LOSS
    try:
        monitor_ref = store.persist_json(
            {
                "attempt_id": dispatch.binding.attempt_id,
                "healthy": monitor_healthy,
                "incident": control.incident.is_set(),
                "source": "local-fixture-monitor",
            }
        )
    except (OSError, ValueError):
        reasons.add("evidence-store-error")
        status = RunStatus.INFRA_ERROR
        monitor_ref = "sha256:" + "0" * 64
    outcome = observation.outcome
    violation, held = outcome == "violation", outcome == "held"
    positive_control = observation.positive_control
    sources = observation.sources
    if "containment-monitor" in case.required_sources + case.corroborating_sources:
        sources += (
            SourceEvidence(
                source_id="containment-monitor",
                identity="local-fixture-monitor",
                generation=dispatch.binding.attempt_id,
                designation="required"
                if "containment-monitor" in case.required_sources
                else "corroborating",
                ready_before_replay=monitor_ready_at_start,
                drained=monitor_healthy and "evidence-store-error" not in reasons,
                dropped_events=0,
                truncated=not monitor_healthy or "evidence-store-error" in reasons,
                artifact_digest=monitor_ref,
            ),
        )
    evidence = EvidenceManifest(
        binding=dispatch.binding,
        expected_instances=dispatch.instances,
        instance=instance,
        components=ready.components,
        sources=sources,
        observer_outcome=outcome,
        observed_effect_refs=observation.effects,
        policy_ready_before_replay=ready.ready
        and ready.effective_policy_digest == dispatch.binding.effective_policy_digest,
        containment_monitor_healthy=monitor_healthy,
    )
    try:
        store.persist(canonical(evidence))
    except (OSError, ValueError):
        reasons.add("manifest-not-persisted")
        status = RunStatus.INFRA_ERROR
    now = datetime.now(UTC)
    result = RunResult(
        binding=dispatch.binding,
        instance=instance,
        run_status=status,
        run_status_reasons=tuple(sorted(reasons)),
        security_outcome=SecurityOutcome.EXECUTED
        if violation
        else SecurityOutcome.BLOCKED
        if held
        else SecurityOutcome.UNKNOWN,
        positive_control_status=positive_control,
        cleanup_status=cleanup,
        containment_incident=control.incident.is_set(),
        evidence_manifest_digest=digest(evidence),
        invariant_held=0.0 if violation else 1.0 if held else None,
        signer_identity=signer_identity,
        issued_at=now,
        valid_until=now + timedelta(minutes=5),
    )
    record = sign(result, evidence, key)
    try:
        store.persist(canonical(record))
    except (OSError, ValueError):
        # Return an authenticated error record if the last storage write fails.
        result = result.model_copy(
            update={
                "run_status": RunStatus.INFRA_ERROR,
                "run_status_reasons": tuple(sorted(reasons | {"terminal-record-not-persisted"})),
            }
        )
        record = sign(result, evidence, key)
    return record
