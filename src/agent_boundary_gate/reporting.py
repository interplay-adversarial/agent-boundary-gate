"""Allowlisted operator reports, without deployment identity or key material."""

from agent_boundary_gate.contracts import GateDecision, SignedRecord

EXPLANATIONS = {
    "required-case-violation": "The forbidden receiver observed the attempted request.",
    "positive-control-not-observed": "The allowed receiver did not establish the positive control.",
    "containment-monitor-loss": "Independent containment coverage was lost; admission stopped.",
    "cleanup-not-confirmed": "Whole-cell cleanup was not confirmed by independent signed proof.",
    "target-or-policy-generation-changed": "The target or policy changed during the attempt.",
    "backend-probe-delivery-rejected": "Pinned immutable probe delivery could not be verified.",
    "required-observer-evidence-loss": "Required receiver evidence was incomplete.",
    "cancelled": "Execution was cancelled; findings remain retained.",
    "interrupted": "Execution was interrupted; findings remain retained.",
    "all-contract-checks-passed": "The prototype evidence checks passed.",
    "policy-readiness-timeout": "The pinned policy did not become ready within the budget.",
    "replay-not-complete": "The probe did not establish execution completion.",
    "controller-lease-lost": "Controller liveness could not be maintained.",
    "adapter-or-capability-unsupported": "The configured combination is unsupported.",
}


def operator_report(decision: GateDecision, record: SignedRecord) -> dict:
    # Never echo arbitrary signed identifiers, paths, URLs or supplied diagnostics.
    reasons = set(decision.decision_reasons) | set(record.result.run_status_reasons)
    # Only the allowlisted subset below -- never the raw reasons set, which may hold
    # reason strings this allowlist deliberately excludes.
    reason_codes = sorted(reason for reason in reasons if reason in EXPLANATIONS)
    explanations = [EXPLANATIONS[reason] for reason in reason_codes]
    if not explanations:
        explanations = ["Inspect the private authenticated evidence for additional diagnostics."]
    return {
        "schema_version": "1.0",
        "mode": "experimental-live-boundary-test",
        "test": "paired-denied-http-egress",
        "attempted": ["HTTP request to allowed receiver", "HTTP request to forbidden receiver"],
        "decision": decision.release_decision.value,
        "run_status": record.result.run_status.value,
        "observed_effect": record.evidence.observer_outcome,
        "positive_control": record.result.positive_control_status,
        "cleanup": record.result.cleanup_status,
        "containment_incident": record.result.containment_incident,
        "confirmed_violation_count": len(decision.confirmed_violations),
        "explanations": explanations,
        # Stable identifiers behind the rendered explanations above, for callers (e.g.
        # campaign.py) that need to match on the condition itself rather than its
        # English wording, which is free to change without signaling a contract break.
        "reason_codes": reason_codes,
        "qualification": "unqualified-live",
        "release_eligible": False,
    }
