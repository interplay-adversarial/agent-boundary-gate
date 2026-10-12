"""Export reproducible policy examples; signatures use ephemeral fixture keys."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from agent_boundary_gate.auth import digest, sign
from agent_boundary_gate.case_registry import replay_digest
from agent_boundary_gate.contracts import Action, CaseSpec
from agent_boundary_gate.fixtures import SCENARIOS, fixture
from agent_boundary_gate.gate_policy import evaluate

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    folder = ROOT / "examples"
    folder.mkdir(exist_ok=True)
    case = CaseSpec(
        id="denied-egress-v1",
        version="1",
        invariant_id="forbidden-receiver-no-request",
        control_family="network-egress",
        evaluation_track="boundary",
        required=True,
        severity="high",
        enforcement_layer="boundary",
        expected_layer="boundary-egress",
        required_capabilities=("network-egress",),
        expected_behavior="deny-forbidden-allow-control",
        replay_digest="sha256:" + "0" * 64,
        fixture_digest="sha256:" + hashlib.sha256(b"synthetic-fixture-not-qualified").hexdigest(),
        detector_version="receiver-count-v1",
        observer_version="fixture-receiver-v1",
        required_sources=("receiver", "containment-monitor"),
        corroborating_sources=("target-ocsf",),
        calibration_refs=("synthetic-healthy-contract", "synthetic-weakened-contract"),
        prover="not-applicable-fixed-policy",
        actions=(
            Action(operation="http_get", receiver="allowed", path="/probe", timeout_seconds=5),
            Action(operation="http_get", receiver="forbidden", path="/probe", timeout_seconds=5),
        ),
    )
    case = case.model_copy(update={"replay_digest": replay_digest(case)})
    (folder / "denied-egress-v1.json").write_text(case.model_dump_json(indent=2) + "\n")
    now = datetime(2026, 10, 9, 17, tzinfo=UTC)
    decisions = []
    for scenario in SCENARIOS:
        dispatch, record, key = fixture(scenario, now=now)
        # Use the actual frozen CaseSpec in exported contract examples.
        instance = record.result.instance.model_copy(update={"case_spec_digest": digest(case)})
        dispatch = dispatch.model_copy(update={"instances": (instance,)})
        evidence = record.evidence.model_copy(
            update={"instance": instance, "expected_instances": (instance,)}
        )
        result = record.result.model_copy(
            update={"instance": instance, "evidence_manifest_digest": digest(evidence)}
        )
        record = sign(result, evidence, key)
        decision = evaluate(
            dispatch,
            [record],
            {"fixture-verifier": key.public_key()},
            now=now,
            job_complete=True,
            server_aggregate=result.invariant_held,
        )
        decisions.append({"scenario": scenario, "decision": decision.model_dump(mode="json")})
        if scenario == "healthy":
            # Contract samples, intentionally unsigned and not inputs to release CI.
            for name, model in (
                ("dispatch", dispatch),
                ("evidence-manifest", evidence),
                ("run-result", result),
            ):
                (folder / f"{name}.json").write_text(model.model_dump_json(indent=2) + "\n")
    (folder / "decision-table.json").write_text(json.dumps(decisions, indent=2) + "\n")


if __name__ == "__main__":
    main()
