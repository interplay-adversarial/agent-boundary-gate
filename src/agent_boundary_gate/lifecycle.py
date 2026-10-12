"""One bounded attempt: start observer, verify readiness, replay, drain, destroy, sign."""

import time
from datetime import UTC, datetime, timedelta
from threading import Event, Lock, Thread

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_boundary_gate.agents import AgentAdapter
from agent_boundary_gate.auth import canonical, digest, sign
from agent_boundary_gate.backends import (
    BackendFailure,
    BoundaryBackend,
    Readiness,
    UnsupportedCapability,
)
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
from agent_boundary_gate.monitor import (
    ContainmentMonitor,
    FixtureMonitor,
    MonitorSession,
    MonitorSnapshot,
    UnknownMonitor,
)
from agent_boundary_gate.observers import Observation, Observer
from agent_boundary_gate.process import AttemptStopped
from agent_boundary_gate.recovery import ControllerLease


class AttemptControl:
    """Independent monitor supplies these signals; local tests inject them explicitly."""

    def __init__(self, monitor: ContainmentMonitor | None = None):
        self._monitor_lock = Lock()
        self._last_monitor = UnknownMonitor().snapshot()
        self._monitor_failed = Event()
        self._monitor_identity: tuple[str, str] | None = None
        self.cancelled = Event()
        self.monitor = monitor if monitor is not None else UnknownMonitor()
        self.incident = Event()

    @classmethod
    def for_fixture(cls, binding) -> "AttemptControl":
        """Opt into synthetic monitor health for local fixtures only."""
        return cls(FixtureMonitor(binding))

    def monitor_snapshot(self) -> MonitorSnapshot:
        # The watcher and attempt thread must pin identity and latch failure
        # against the same serialized snapshot history.
        with self._monitor_lock:
            return self._monitor_snapshot_locked()

    def _monitor_snapshot_locked(self) -> MonitorSnapshot:
        try:
            snapshot = self.monitor.snapshot()
            if not isinstance(snapshot, MonitorSnapshot):
                raise ValueError("invalid-monitor-snapshot")
        except Exception:
            self._monitor_failed.set()
            snapshot = self._last_monitor
        if snapshot.healthy:
            identity = (snapshot.identity, snapshot.generation)
            if self._monitor_identity is None:
                self._monitor_identity = identity
            elif identity != self._monitor_identity:
                self._monitor_failed.set()
        if self._monitor_failed.is_set():
            snapshot = MonitorSnapshot(
                "incident" if snapshot.incident else "lost",
                snapshot.identity,
                snapshot.generation,
                snapshot.incident,
                snapshot.heartbeat_refs,
                snapshot.dropped_events,
            )
        self._last_monitor = snapshot
        if snapshot.incident:
            self.incident.set()
        return snapshot


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
    recovery: ControllerLease | None = None,
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
    monitor_ready_at_start = False

    def watch() -> None:
        while not watch_done.wait(0.01):
            snapshot = control.monitor_snapshot()
            if not snapshot.healthy:
                monitor_loss_seen.set()
            if recovery is not None and recovery.failed.is_set():
                control.cancelled.set()
            if control.incident.is_set() or not snapshot.healthy:
                control.cancelled.set()
            if control.cancelled.is_set() and recovery is not None:
                recovery.quiesce()

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
        driver.require_binding(dispatch.binding)
        if driver.lease is not None and (recovery is None or recovery.lease != driver.lease):
            raise UnsupportedCapability("independent-recovery-lease-unavailable")
        if recovery is not None:
            recovery.start(dispatch.binding)
        if driver.lease is not None and (
            not isinstance(control.monitor, MonitorSession) or control.monitor.lease != driver.lease
        ):
            raise UnsupportedCapability("authenticated-monitor-lease-unavailable")
        if not control.monitor.require_binding(dispatch.binding):
            raise AttemptStopped("containment-monitor-binding-unavailable")
        monitor_ready_at_start = control.monitor_snapshot().healthy
        if not monitor_ready_at_start:
            raise AttemptStopped("containment-monitor-not-ready")
        observer.start()
        if not control.monitor_snapshot().healthy or control.incident.is_set():
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
                or not control.monitor_snapshot().healthy
                or control.incident.is_set()
                or (recovery is not None and recovery.failed.is_set())
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
    except BackendFailure as failed:
        reasons.add(failed.reason)
        status = RunStatus.INFRA_ERROR
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
        except (BackendFailure, AttemptStopped) as failed:
            reasons.add(failed.reason)
            cleanup = "failed"
        except (Exception, KeyboardInterrupt):
            cleanup = "failed"
        if cleanup != "destroyed":
            reasons.add("cleanup-not-confirmed")
            if status == RunStatus.COMPLETE:
                status = RunStatus.INCOMPLETE
        if recovery is not None:
            recovery.stop()
            if recovery.failed.is_set():
                reasons.add("controller-lease-lost")
                if status == RunStatus.COMPLETE:
                    status = RunStatus.INCOMPLETE
        watch_done.set()
        watcher.join(timeout=2)
    monitor_snapshot = control.monitor_snapshot()
    monitor_healthy = monitor_snapshot.healthy and not monitor_loss_seen.is_set()
    if not monitor_healthy:
        reasons.add("containment-monitor-loss")
        # Preserve unsupported admission; monitor loss explains interrupted or
        # incomplete runtime outcomes without erasing their diagnostic reasons.
        if status in (
            RunStatus.COMPLETE,
            RunStatus.INCOMPLETE,
            RunStatus.TIMEOUT,
            RunStatus.CANCELLED,
            RunStatus.INFRA_ERROR,
        ):
            status = RunStatus.TELEMETRY_LOSS
    try:
        observation = observer.observe(
            execution_valid=replay_completed
            and ready.ready
            and monitor_healthy
            and not control.incident.is_set()
            and (recovery is None or not recovery.failed.is_set())
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
                "source": monitor_snapshot.identity,
                "generation": monitor_snapshot.generation,
                "state": monitor_snapshot.state,
                "heartbeat_refs": monitor_snapshot.heartbeat_refs,
                "dropped_events": monitor_snapshot.dropped_events,
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
                identity=monitor_snapshot.identity,
                generation=monitor_snapshot.generation,
                designation="required"
                if "containment-monitor" in case.required_sources
                else "corroborating",
                ready_before_replay=monitor_ready_at_start,
                drained=monitor_healthy and "evidence-store-error" not in reasons,
                dropped_events=monitor_snapshot.dropped_events,
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
