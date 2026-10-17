import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class LibraryExampleTests(unittest.TestCase):
    def example(self, name, *args):
        result = subprocess.run(
            [sys.executable, str(ROOT / "examples" / name), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.stderr, "")
        return result.returncode, json.loads(result.stdout)

    def test_offline_example(self):
        code, decision = self.example("library_policy.py")
        self.assertEqual(code, 0)
        self.assertEqual(decision["release_decision"], "pass")
        self.assertFalse(decision["release_eligible"])

    def test_loopback_examples_capture_real_effect_and_check_artifacts(self):
        with tempfile.TemporaryDirectory() as folder:
            for weakened in (False, True):
                with self.subTest(weakened=weakened):
                    destination = Path(folder) / str(weakened)
                    args = ["--output", str(destination)]
                    if weakened:
                        args.append("--weakened")
                    code, decision = self.example("library_loopback.py", *args)
                    self.assertEqual(code, 1 if weakened else 0)
                    self.assertEqual(
                        decision["release_decision"], "criteria_failed" if weakened else "pass"
                    )
                    self.assertFalse(decision["release_eligible"])
                    self.assertTrue(list(destination.glob("*.json")))
                    self.assertEqual(destination.stat().st_mode & 0o077, 0)


class GymEffectExampleTests(unittest.TestCase):
    def example(self, *args):
        result = subprocess.run(
            [sys.executable, str(ROOT / "examples/library_gym_effect.py"), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.returncode, 0)
        return json.loads(result.stdout)

    def test_every_outcome_class_and_recovery_without_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            report = self.example("--output", str(Path(folder) / "out"), "--interrupt")
        self.assertEqual(
            {name: row["scenario"] for name, row in report.items()},
            {
                "benign": "benign-utility-observed",
                "followed": "observed-synthetic-effect",
                "blocked": "blocked-effect",
                "resisted": "resisted-attack",
                "interrupted": "incomplete",
            },
        )
        self.assertEqual(report["followed"]["forbidden_effects"], 1)
        self.assertEqual(report["interrupted"]["replayed_model_or_tool_calls"], 0)
        self.assertEqual(report["interrupted"]["worker_cleanup"], "unknown")
        self.assertTrue(all(row["release_eligible"] is False for row in report.values()))

    def test_interrupt_never_signals_a_dead_controller_or_misreports(self):
        import importlib.util
        from unittest.mock import patch

        sys.path.insert(0, str(ROOT / "src"))
        spec = importlib.util.spec_from_file_location(
            "library_gym_effect", ROOT / "examples" / "library_gym_effect.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        class Exited:
            pid = 2**22
            polled = 0

            def poll(self):
                return 1

            def wait(self):
                return 1

        with tempfile.TemporaryDirectory() as folder:
            with (
                patch.object(module.subprocess, "Popen", return_value=Exited()),
                patch.object(module.os, "kill") as kill,
                self.assertRaisesRegex(SystemExit, "interrupt-point-not-reached"),
            ):
                module.interrupted(Path(folder))
        kill.assert_not_called()

    def test_sample_cli_inputs_validate_against_the_pin_and_probe_digest(self):
        sys.path.insert(0, str(ROOT / "src"))
        from agent_boundary_gate.evidence import bytes_digest
        from agent_boundary_gate.gym_supervised import GymEffectConfig, GymEffectPlan

        pin = json.loads((ROOT / "src/agent_boundary_gate/_pins/gym-native.json").read_bytes())
        plan = GymEffectPlan.model_validate_json(
            (ROOT / "examples/gym-effect-plan.json").read_bytes()
        )
        config = GymEffectConfig.model_validate_json(
            (ROOT / "examples/gym-effect-config.json").read_bytes()
        )
        self.assertEqual(plan.interplay_commit, pin["interplay"]["commit"])
        self.assertEqual(plan.gym_revision, pin["gym"]["commit"])
        self.assertEqual(plan.probe_digest, bytes_digest(config.probe.encode()))
        self.assertTrue(config.model.api_key_env)
        self.assertNotIn("sk-", (ROOT / "examples/gym-effect-config.json").read_text())
