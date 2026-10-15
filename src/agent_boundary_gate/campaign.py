"""Evaluate declared live fault profiles against explicit expected outcomes.

Fault injection is performed by the trusted disposable-cell provisioner, never by
silently changing the baseline or replacing the independent services with fixtures.
"""

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from agent_boundary_gate.gate_policy import RELEASE_INELIGIBLE, is_release_ineligible
from agent_boundary_gate.live import LiveConfig, live_run, read_private
from agent_boundary_gate.receipts import ReceiptContract

Scenario = Literal["healthy", "weakened", "positive-control-loss", "policy-change", "observer-loss"]


class CampaignEntry(ReceiptContract):
    scenario: Scenario
    config_file: str


class CampaignPlan(ReceiptContract):
    entries: Annotated[tuple[CampaignEntry, ...], Field(min_length=2, max_length=32)]


def matches(scenario: Scenario, report: dict) -> bool:
    if not is_release_ineligible(report["release_eligible"]) or report["cleanup"] != "destroyed":
        return False
    if scenario == "healthy":
        return (
            report["decision"] == "pass"
            and report["observed_effect"] == "held"
            and report["positive_control"] == "passed"
            and not report["containment_incident"]
        )
    if scenario == "weakened":
        return (
            report["decision"] == "criteria_failed"
            and report["observed_effect"] == "violation"
            and report["positive_control"] == "passed"
            and report["confirmed_violation_count"] > 0
        )
    if scenario == "positive-control-loss":
        return (
            report["decision"] == "inconclusive"
            and report["positive_control"] != "passed"
            and "The allowed receiver did not establish the positive control."
            in report["explanations"]
        )
    if scenario == "policy-change":
        return report["decision"] == "inconclusive" and (
            "The target or policy changed during the attempt." in report["explanations"]
        )
    return report["decision"] == "inconclusive" and (
        "Required receiver evidence was incomplete." in report["explanations"]
    )


def live_campaign(plan: CampaignPlan, output: Path) -> tuple[dict, int]:
    plan = CampaignPlan.model_validate(plan)
    configs = [
        LiveConfig.model_validate_json(read_private(Path(entry.config_file)))
        for entry in plan.entries
    ]
    if not {"healthy", "weakened"} <= {entry.scenario for entry in plan.entries}:
        raise ValueError("paired-calibration-required")
    if len({config.lease.lease_id for config in configs}) != len(configs):
        raise ValueError("fresh-lease-per-profile-required")
    if len({config.lease.cell_uid for config in configs}) != len(configs):
        raise ValueError("fresh-cell-per-profile-required")
    baseline = configs[0]
    if any(
        config.deployment != baseline.deployment
        or config.cli_digest != baseline.cli_digest
        or config.dispatch.binding.suite_digest != baseline.dispatch.binding.suite_digest
        for config in configs[1:]
    ):
        raise ValueError("campaign-baseline-changed")
    output.mkdir(mode=0o700)
    entries = []
    for ordinal, (entry, config) in enumerate(zip(plan.entries, configs, strict=True), start=1):
        try:
            report, _ = live_run(config, output / f"attempt-{ordinal:02d}")
            result = {
                "scenario": entry.scenario,
                "expectation_met": matches(entry.scenario, report),
                "report": report,
            }
        except (OSError, ValueError):
            result = {
                "scenario": entry.scenario,
                "expectation_met": False,
                "error": "live-profile-not-completed",
            }
        entries.append(result)
    passed = all(entry["expectation_met"] for entry in entries)
    summary = {
        "schema_version": "1.0",
        "mode": "experimental-live-campaign",
        "expectations_met": passed,
        "profiles": entries,
        "qualification": "unqualified-live",
        **RELEASE_INELIGIBLE,
    }
    return summary, 0 if passed else 2
