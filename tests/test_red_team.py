"""Optional-worker bounds and metadata cannot create gate authority."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_boundary_gate.process import AttemptStopped, ProcessResult
from agent_boundary_gate.red_team import _summary, red_team_run, worker_environment
from scripts.audit_publication import audit_blob


class RedTeamTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "config.json"
        self.config.write_text(
            json.dumps(
                {
                    "assessment": {
                        "description": "Synthetic assessment",
                        "success_criteria": "Synthetic criterion",
                    }
                }
            )
        )
        self.config.chmod(0o600)

    def test_only_declared_role_credentials_and_model_names_are_inherited(self):
        with patch.dict(
            os.environ,
            {
                "PATH": "/bin",
                "ROLE_KEY": "fake-value",
                "UNRELATED_KEY": "do-not-inherit",
                "PYTHONPATH": "/untrusted",
                "HTTPS_PROXY": "https://example.com",
                "JUDGE_MODEL": "judge-model",
            },
            clear=True,
        ):
            environment = worker_environment({"judge": {"api_key_env": "ROLE_KEY"}})
        self.assertEqual(environment["ROLE_KEY"], "fake-value")
        self.assertEqual(environment["JUDGE_MODEL"], "judge-model")
        self.assertNotIn("UNRELATED_KEY", environment)
        self.assertNotIn("PYTHONPATH", environment)
        self.assertNotIn("HTTPS_PROXY", environment)

    def test_invalid_or_unbounded_budget_rejected_before_worker_admission(self):
        for budget in (0, -1, True, 601, "60"):
            with (
                self.subTest(budget=budget),
                patch("agent_boundary_gate.red_team._invoke") as invoke,
            ):
                self.config.write_text(json.dumps({"assessment": {"campaign_seconds": budget}}))
                with self.assertRaisesRegex(ValueError, "budget-invalid"):
                    red_team_run(self.config, self.root / "campaign", Path("unused"))
                invoke.assert_not_called()

    def test_failed_environment_preflight_never_creates_an_output(self):
        with patch("agent_boundary_gate.red_team._invoke", return_value=ProcessResult(2, b"{}")):
            with self.assertRaisesRegex(ValueError, "environment-or-input-invalid"):
                red_team_run(self.config, self.root / "campaign", Path("unused"))
        self.assertFalse((self.root / "campaign").exists())

    def test_worker_timeout_retains_incomplete_control_and_config_references(self):
        config = json.loads(self.config.read_text())
        validation = ProcessResult(
            0, json.dumps({"config": config, "release_eligible": False}).encode()
        )
        with patch(
            "agent_boundary_gate.red_team._invoke",
            side_effect=[validation, AttemptStopped("timeout")],
        ):
            result = red_team_run(self.config, self.root / "campaign", Path("unused"))
        self.assertFalse(result["assessment_complete"])
        self.assertFalse(result["release_eligible"])
        self.assertTrue(result["start_ref"].startswith("sha256:"))
        self.assertTrue(result["summary_ref"].startswith("sha256:"))

    def test_worker_release_claim_or_contradictory_counts_are_rejected(self):
        for value in (
            {"assessment_complete": True, "release_eligible": True},
            {"assessment_complete": True, "release_eligible": False, "records": 0},
            {
                "assessment_complete": True,
                "release_eligible": False,
                "records": 1,
                "requested_probes": 2,
                "successes": 1,
            },
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _summary(json.dumps(value).encode(), 0)

    def test_raw_analytics_files_are_rejected_as_publication_inputs(self):
        for name in ("records.jsonl", "records.parquet", "records.arrow", "records.feather"):
            self.assertTrue(audit_blob(name, b"synthetic"))

    def test_adaptive_early_success_requires_valid_mode_reason_and_counts(self):
        value = {
            "assessment_complete": True,
            "release_eligible": False,
            "records": 2,
            "requested_probes": 5,
            "successes": 1,
            "failures": 1,
            "inconclusive": 0,
            "search_mode": "adaptive",
            "stop_reason": "success",
        }
        result = _summary(json.dumps(value).encode(), 0)
        self.assertTrue(result["assessment_complete"])
        self.assertEqual(result["stop_reason"], "success")
        for change in (
            {"search_mode": "batch"},
            {"stop_reason": "attempt-budget"},
            {"successes": 0, "failures": 2},
            {"records": 6},
            {"search_mode": "unknown"},
            {"stop_reason": "unknown"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                _summary(json.dumps(value | change).encode(), 0)
