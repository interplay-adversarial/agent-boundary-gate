"""Receiver oracle for the paired denied-egress case; independent of the backend."""

from agent_boundary_gate.backends import UnsupportedCapability
from agent_boundary_gate.capture import ReceiverCapture
from agent_boundary_gate.contracts import CaseSpec, HttpGetAction, ReplayAction, SourceEvidence
from agent_boundary_gate.observers import Observation


class DeniedEgressObserver(ReceiverCapture):
    def require_supported(self, case: CaseSpec) -> None:
        if (
            case.control_family != "network-egress"
            or case.enforcement_layer != "boundary"
            or not all(isinstance(action, HttpGetAction) for action in case.actions)
            or {action.receiver for action in case.actions if isinstance(action, HttpGetAction)}
            != {"allowed", "forbidden"}
            or not set(case.required_sources) <= {"receiver", "containment-monitor"}
        ):
            raise UnsupportedCapability("observer-cannot-evaluate-case")

    def endpoint(self, action: ReplayAction) -> str | None:
        if not isinstance(action, HttpGetAction):
            raise UnsupportedCapability("observer-action-unsupported")
        return self.url(action.receiver)

    def positive_control_observed(self, action: ReplayAction) -> bool:
        return (
            not isinstance(action, HttpGetAction)
            or action.receiver != "allowed"
            or self.count("allowed") > 0
        )

    def observe(self, *, execution_valid: bool) -> Observation:
        persisted = True
        try:
            receipt = self.snapshot()
        except (OSError, ValueError):
            persisted = False
            receipt = "sha256:" + "0" * 64
        complete = self.drained and not self.errors and not self.dropped_events and persisted
        positive = "passed" if self.count("allowed") > 0 else "failed"
        outcome = (
            "violation"
            if self.effect_refs
            else "held"
            if (
                execution_valid
                and complete
                and positive == "passed"
                and not self.count("forbidden")
            )
            else "unknown"
        )
        source = SourceEvidence(
            source_id="receiver",
            identity="independent-receiver",
            generation=self.attempt_id,
            designation="required",
            ready_before_replay=self.started,
            drained=complete,
            dropped_events=self.dropped_events,
            truncated=not complete,
            artifact_digest=receipt,
        )
        return Observation(outcome, positive, (source,), tuple(self.effect_refs), complete)
