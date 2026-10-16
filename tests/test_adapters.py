import json
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from agent_boundary_gate.agents.fixture import LoopbackAgentAdapter
from agent_boundary_gate.auth import digest, sign
from agent_boundary_gate.backends import UnsupportedCapability
from agent_boundary_gate.backends.fixture import LoopbackBackend
from agent_boundary_gate.case_registry import load_case, replay_digest
from agent_boundary_gate.contracts import (
    ComponentPin,
    Dispatch,
    SignedRecord,
    TargetProfile,
    ToolRequestAction,
)
from agent_boundary_gate.evidence import EvidenceStore
from agent_boundary_gate.fixtures import fixture
from agent_boundary_gate.gate_policy import evaluate
from agent_boundary_gate.legacy.auth import authenticate_legacy
from agent_boundary_gate.legacy.v0_1 import SignedRecord as LegacyRecord
from agent_boundary_gate.lifecycle import AttemptControl, run_attempt
from agent_boundary_gate.observers import Observation
from agent_boundary_gate.observers.denied_egress import DeniedEgressObserver
from agent_boundary_gate.registry import inventory

ROOT = Path(__file__).resolve().parents[1]
D = "sha256:" + "a" * 64


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = EvidenceStore(Path(self.temp.name) / "evidence")
        self.case = load_case(ROOT / "examples/denied-egress-v1.json")
        self.dispatch, _, _ = fixture("healthy")
        case = self.dispatch.instances[0].model_copy(update={"case_spec_digest": digest(self.case)})
        self.dispatch = self.dispatch.model_copy(update={"instances": (case,)})
        self.key = Ed25519PrivateKey.generate()
        self.backend = LoopbackBackend(self.dispatch.binding.effective_policy_digest)
        self.observer = DeniedEgressObserver(self.dispatch.binding.attempt_id, self.store)

    def attempt(self, *, agent=None):
        return run_attempt(
            self.dispatch,
            self.case,
            self.backend,
            self.observer,
            self.store,
            self.key,
            "adapter-test",
            AttemptControl.for_fixture(self.dispatch.binding),
            agent=agent,
        )

    def verdict(self, record):
        return evaluate(
            self.dispatch,
            [record],
            {"adapter-test": self.key.public_key()},
            now=datetime.now(UTC),
            job_complete=True,
            server_aggregate=record.result.invariant_held,
        )

    def update_case(self, **changes):
        self.case = self.case.model_copy(update=changes)
        self.case = self.case.model_copy(update={"replay_digest": replay_digest(self.case)})
        instance = self.dispatch.instances[0].model_copy(
            update={"case_spec_digest": digest(self.case)}
        )
        self.dispatch = self.dispatch.model_copy(update={"instances": (instance,)})

    def test_boundary_contract_accepts_second_test_backend(self):
        # Same receiver oracle and core, independently selected boundary identity.
        self.backend.backend_id = "test-runtime"
        profile = self.dispatch.binding.target_profile
        profile = profile.model_copy(
            update={"boundary": profile.boundary.model_copy(update={"id": "test-runtime"})}
        )
        binding = self.dispatch.binding.model_copy(update={"target_profile": profile})
        self.dispatch = self.dispatch.model_copy(update={"binding": binding})
        record = self.attempt()
        self.assertEqual(record.evidence.components[0].component_id, "test-runtime")
        self.assertEqual(self.verdict(record).release_decision, "pass")
        self.assertFalse(self.verdict(record).release_eligible)

    def test_missing_capability_is_explicitly_unsupported(self):
        self.update_case(required_capabilities=("filesystem-read",))
        record = self.attempt()
        self.assertEqual(record.result.run_status, "unsupported-detector")
        self.assertIsNone(record.result.invariant_held)
        self.assertEqual(self.observer.events, [])
        self.assertEqual(self.verdict(record).release_decision, "inconclusive")

    def test_boundary_identity_mismatch_does_not_execute(self):
        self.backend.backend_id = "different-runtime"
        record = self.attempt()
        self.assertEqual(record.result.run_status, "unsupported-detector")
        self.assertEqual(self.observer.events, [])

    def test_agent_profile_requires_matching_adapter(self):
        profile = self.dispatch.binding.target_profile.model_copy(
            update={
                "agent": ComponentPin(
                    id="declared-agent", role="agent", artifact_digest=D, configuration_digest=D
                ),
            }
        )
        self.dispatch = self.dispatch.model_copy(
            update={"binding": self.dispatch.binding.model_copy(update={"target_profile": profile})}
        )
        record = self.attempt()
        self.assertEqual(record.result.run_status, "unsupported-detector")
        self.assertEqual(self.verdict(record).release_decision, "inconclusive")

    def test_observer_rejects_unknown_action_without_coercion(self):
        action = ToolRequestAction(
            operation="tool_request",
            tool_id="shell",
            arguments_ref=D,
            control="restricted",
            timeout_seconds=1,
        )
        self.update_case(actions=(action,))
        record = self.attempt()
        self.assertEqual(record.result.run_status, "unsupported-detector")
        self.assertIsNone(record.result.invariant_held)

    def test_signed_component_identity_mismatch_withholds_approval(self):
        record = self.attempt()
        evidence = record.evidence.model_copy(update={"components": ()})
        result = record.result.model_copy(update={"evidence_manifest_digest": digest(evidence)})
        decision = self.verdict(sign(result, evidence, self.key))
        self.assertEqual(decision.release_decision, "inconclusive")
        self.assertIn("component-identity-incomplete-or-mismatched", decision.decision_reasons)

    def test_profile_roles_rejected(self):
        with self.assertRaises(ValidationError):
            TargetProfile(
                boundary=ComponentPin(
                    id="agent", role="agent", artifact_digest=D, configuration_digest=D
                )
            )

    def test_planned_adapters_are_not_advertised_as_supported(self):
        agents = [entry for entry in inventory() if entry["role"] == "agent"]
        planned = [entry for entry in agents if entry["status"] == "planned"]
        self.assertEqual({entry["id"] for entry in planned}, {"opencode", "openclaw"})
        self.assertTrue(all(not entry["capabilities"] for entry in planned))
        simulated = [entry for entry in agents if entry["status"] != "planned"]
        self.assertEqual({entry["id"] for entry in simulated}, {"loopback"})
        self.assertTrue(all(entry["capabilities"] for entry in simulated))

    def test_current_schema_rejects_legacy_examples(self):
        with self.assertRaises(ValidationError):
            Dispatch.model_validate_json((ROOT / "examples/v0.1/dispatch.json").read_bytes())

    def test_cli_support_inventory(self):
        result = subprocess.run(
            [sys.executable, "-m", "agent_boundary_gate.cli", "adapters"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)), 5)

    def test_legacy_evidence_retains_original_signature(self):
        # Synthetic legacy record, constructed from the archived unsigned examples.
        import hashlib

        from agent_boundary_gate.legacy.v0_1 import EvidenceManifest, RunResult

        evidence = EvidenceManifest.model_validate_json(
            (ROOT / "examples/v0.1/evidence-manifest.json").read_bytes()
        )
        result = RunResult.model_validate_json(
            (ROOT / "examples/v0.1/run-result.json").read_bytes()
        )

        def canonical(obj):
            return json.dumps(
                obj.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()

        self.assertEqual(
            result.evidence_manifest_digest,
            "sha256:" + hashlib.sha256(canonical(evidence)).hexdigest(),
        )
        payload = (
            b"openshell-gate/terminal-record/0.1\0"
            + canonical(result)
            + b"\0"
            + canonical(evidence)
        )
        record = LegacyRecord(
            result=result,
            evidence=evidence,
            algorithm="Ed25519",
            signature=self.key.sign(payload).hex(),
        )
        self.assertTrue(
            authenticate_legacy(record, {result.signer_identity: self.key.public_key()})
        )
        self.assertFalse(authenticate_legacy(record, {}))
        with self.assertRaises(ValidationError):
            SignedRecord.model_validate_json(record.model_dump_json())

    def test_agent_and_boundary_are_composed_independently(self):
        # Protocol exercise only, not an OpenCode/OpenClaw implementation.
        store = self.store
        profile = self.dispatch.binding.target_profile.model_copy(
            update={
                "agent": ComponentPin(
                    id="test-agent", role="agent", artifact_digest=D, configuration_digest=D
                ),
            }
        )
        self.dispatch = self.dispatch.model_copy(
            update={"binding": self.dispatch.binding.model_copy(update={"target_profile": profile})}
        )
        actions = tuple(
            ToolRequestAction(
                operation="tool_request",
                tool_id="fixture-tool",
                arguments_ref=D,
                control=control,
                timeout_seconds=1,
            )
            for control in ("positive", "restricted")
        )
        self.update_case(
            control_family="tool-authorization",
            evaluation_track="agent-control",
            enforcement_layer="agent",
            required_capabilities=("tool-authorization",),
            actions=actions,
            required_sources=("tool-events", "containment-monitor"),
            corroborating_sources=(),
        )
        instance = self.dispatch.instances[0].model_copy(
            update={"required_sources": self.case.required_sources, "corroborating_sources": ()}
        )
        self.dispatch = self.dispatch.model_copy(update={"instances": (instance,)})

        agent = LoopbackAgentAdapter(D, agent_id="test-agent")

        class ToolObserver:
            attempt_id = self.dispatch.binding.attempt_id

            def require_supported(self, case):
                if case.control_family != "tool-authorization":
                    raise UnsupportedCapability()

            def start(self):
                pass

            def stop(self):
                pass

            def endpoint(self, action):
                return None

            def positive_control_observed(self, action):
                return "positive" in agent.calls

            def observe(self, *, execution_valid):
                from agent_boundary_gate.contracts import SourceEvidence

                receipt = store.persist_json({"fixture-tool-events": agent.calls})
                source = SourceEvidence(
                    source_id="tool-events",
                    identity="test-tool-observer",
                    generation="test-generation",
                    designation="required",
                    ready_before_replay=True,
                    drained=True,
                    dropped_events=0,
                    truncated=False,
                    artifact_digest=receipt,
                )
                held = execution_valid and agent.calls == ["positive", "restricted"]
                return Observation(
                    "held" if held else "unknown",
                    "passed" if held else "unknown",
                    (source,),
                    (),
                    held,
                )

        self.observer = ToolObserver()
        record = self.attempt(agent=agent)
        self.assertEqual(agent.calls, ["positive", "restricted"])
        self.assertEqual(
            {component.role for component in record.evidence.components}, {"agent", "boundary"}
        )
        self.assertEqual(self.verdict(record).release_decision, "pass")
