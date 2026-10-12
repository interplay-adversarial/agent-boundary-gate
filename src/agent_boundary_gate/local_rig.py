"""Local HTTP integration path; synthetic policy and monitoring, never OpenShell evidence."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_boundary_gate.auth import digest
from agent_boundary_gate.backends.fixture import LoopbackBackend
from agent_boundary_gate.case_registry import load_case
from agent_boundary_gate.evidence import EvidenceStore, bytes_digest
from agent_boundary_gate.fixtures import fixture
from agent_boundary_gate.gate_policy import evaluate
from agent_boundary_gate.lifecycle import AttemptControl, run_attempt
from agent_boundary_gate.observers.denied_egress import DeniedEgressObserver


def local_run(case_path: Path, output: Path, *, weakened: bool = False):
    case = load_case(case_path)
    store = EvidenceStore(output)
    now = datetime.now(UTC)
    dispatch, _, _ = fixture("healthy", now=now)
    binding = dispatch.binding.model_copy(
        update={
            "run_id": "local-" + uuid4().hex,
            "attempt_id": "attempt-" + uuid4().hex,
            "target_digest": bytes_digest(
                b"local-simulated-denial-weakened" if weakened else b"local-simulated-denial"
            ),
            "suite_digest": digest(case),
            "topology_digest": bytes_digest(b"loopback-synthetic-monitor"),
        }
    )
    instance = dispatch.instances[0].model_copy(
        update={
            "case_spec_digest": digest(case),
            "case_id": case.id,
            "invariant_id": case.invariant_id,
            "observer_version": case.observer_version,
            "detector_version": case.detector_version,
            "required_sources": case.required_sources,
            "corroborating_sources": case.corroborating_sources,
        }
    )
    dispatch = dispatch.model_copy(update={"binding": binding, "instances": (instance,)})
    key = Ed25519PrivateKey.generate()
    driver = LoopbackBackend(binding.effective_policy_digest, weakened=weakened)
    capture = DeniedEgressObserver(binding.attempt_id, store)
    record = run_attempt(
        dispatch,
        case,
        driver,
        capture,
        store,
        key,
        "local-verifier",
        AttemptControl.for_fixture(binding),
    )
    decision = evaluate(
        dispatch,
        [record],
        {"local-verifier": key.public_key()},
        now=datetime.now(UTC),
        job_complete=True,
        server_aggregate=record.result.invariant_held,
        evidence_store=store,
    )
    # Ephemeral signing key is never persisted. This public key is an output for local inspection,
    # not a trusted key source for release CI.
    store.persist_json(
        {
            "mode": "loopback-integration",
            "dispatch": dispatch.model_dump(mode="json"),
            "record": record.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json"),
            "fixture_public_key": key.public_key().public_bytes_raw().hex(),
        }
    )
    return decision
