"""Unit tests for the adaptive-task-runner: mocked bounded_process, no real Gym/network."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

from pydantic import ValidationError

from agent_boundary_gate.adaptive_task_runner import (
    AdaptiveTaskRunnerConfig,
    AttemptRecord,
    StopDecision,
    _attempt_record,
    _build_adapted_instruction,
    _gym_eval_run,
    _is_stuck,
    _judge_progress,
    _materialize_attempt_task,
    adaptive_task_runner_run,
    fixed_budget_should_continue,
    load_env_file,
)
from agent_boundary_gate.evidence import EvidenceStore
from agent_boundary_gate.process import ProcessResult


def _config(**overrides) -> AdaptiveTaskRunnerConfig:
    fields = {
        "gym_executable": Path("/fake/gym"),
        "harbor_extra_root": Path("/fake/harbor_extra_root"),
        "task_folders": [Path("/fake/task-a")],
        "max_attempts_per_task": 3,
        "success_reward_threshold": 1.0,
    }
    fields.update(overrides)
    return AdaptiveTaskRunnerConfig(**fields)


def _record(
    reward: float,
    mask_sample: bool = False,
    attempt_number: int = 1,
    tests_passed: int | None = None,
    tests_total: int | None = None,
) -> AttemptRecord:
    return AttemptRecord(
        task_id="task-a",
        attempt_number=attempt_number,
        reward=reward,
        mask_sample=mask_sample,
        failure_kind=None,
        failure_reason=None,
        tests_passed=tests_passed,
        tests_total=tests_total,
        decision=StopDecision.RETRY,
        rollouts_ref="sha256:" + "0" * 64,
        reward_profile_ref="sha256:" + "0" * 64,
    )


class ConfigValidationTests(unittest.TestCase):
    def test_rejects_extra_fields(self):
        with self.assertRaises(ValidationError):
            _config(unexpected_field=True)

    def test_rejects_empty_task_folders(self):
        with self.assertRaises(ValidationError):
            _config(task_folders=[])

    def test_rejects_out_of_bounds_attempts(self):
        with self.assertRaises(ValidationError):
            _config(max_attempts_per_task=0)
        with self.assertRaises(ValidationError):
            _config(max_attempts_per_task=21)

    def test_forbids_mutation(self):
        config = _config()
        with self.assertRaises(ValidationError):
            config.model = "changed"  # type: ignore[misc]


class StopDecisionTests(unittest.TestCase):
    def test_retry_under_budget(self):
        config = _config(max_attempts_per_task=3)
        history = [_record(0.0)]
        self.assertEqual(fixed_budget_should_continue(history, config=config), StopDecision.RETRY)

    def test_advance_on_success(self):
        config = _config(success_reward_threshold=1.0)
        history = [_record(0.0), _record(1.0)]
        self.assertEqual(fixed_budget_should_continue(history, config=config), StopDecision.ADVANCE)

    def test_masked_success_does_not_count(self):
        config = _config(success_reward_threshold=1.0, max_attempts_per_task=1)
        history = [_record(1.0, mask_sample=True)]
        # budget exhausted, not all masked is false (it IS all masked here) -> abandon
        self.assertEqual(fixed_budget_should_continue(history, config=config), StopDecision.ABANDON)

    def test_advance_on_exhausted_non_masked_budget(self):
        config = _config(max_attempts_per_task=2, success_reward_threshold=1.0)
        history = [_record(0.0), _record(0.0)]
        self.assertEqual(fixed_budget_should_continue(history, config=config), StopDecision.ADVANCE)

    def test_abandon_on_all_masked_budget(self):
        config = _config(max_attempts_per_task=2, success_reward_threshold=1.0)
        history = [_record(0.0, mask_sample=True), _record(0.0, mask_sample=True)]
        self.assertEqual(fixed_budget_should_continue(history, config=config), StopDecision.ABANDON)


class IsStuckTests(unittest.TestCase):
    def test_not_stuck_with_fewer_than_two_attempts(self):
        history = [_record(0.33, tests_passed=1, tests_total=3)]
        self.assertFalse(_is_stuck(history, [None], config=_config()))

    def test_not_stuck_when_task_reports_no_structured_signal_and_no_judge(self):
        history = [_record(0.0), _record(0.0)]
        self.assertFalse(_is_stuck(history, [None, None], config=_config()))

    def test_not_stuck_when_either_attempt_is_masked(self):
        history = [
            _record(0.33, tests_passed=1, tests_total=3, mask_sample=True),
            _record(0.33, tests_passed=1, tests_total=3),
        ]
        self.assertFalse(_is_stuck(history, [None, None], config=_config()))

    def test_not_stuck_when_progress_differs(self):
        history = [
            _record(0.33, tests_passed=1, tests_total=3),
            _record(0.66, tests_passed=2, tests_total=3),
        ]
        self.assertFalse(_is_stuck(history, [None, None], config=_config()))

    def test_stuck_when_last_two_show_no_progress(self):
        history = [
            _record(0.0, tests_passed=0, tests_total=3),
            _record(0.33, tests_passed=1, tests_total=3),
            _record(0.33, tests_passed=1, tests_total=3),
        ]
        self.assertTrue(_is_stuck(history, [None, None, None], config=_config()))

    def test_structured_signal_wins_over_judge(self):
        # Numeric signal says "no progress", so the judge (which would say otherwise) must
        # never even be consulted -- the numeric path short-circuits before any network call.
        history = [
            _record(0.33, tests_passed=1, tests_total=3),
            _record(0.33, tests_passed=1, tests_total=3),
        ]
        config = _config(judge_model="judge-model", judge_url="http://localhost:9999")
        with patch("urllib.request.urlopen") as mocked:
            self.assertTrue(_is_stuck(history, [None, None], config=config))
            mocked.assert_not_called()

    def test_judge_fallback_when_no_structured_signal(self):
        history = [_record(0.0), _record(0.0)]
        raw_rows = [
            {"test_output": "AssertionError: expected 5, got -1"},
            {"test_output": "AssertionError: expected 5, got -1"},
        ]
        config = _config(judge_model="judge-model", judge_url="http://localhost:9999")
        with patch("urllib.request.urlopen") as mocked:
            mocked.return_value.__enter__.return_value.read.return_value = json.dumps(
                {"choices": [{"message": {"content": "same_failure"}}]}
            ).encode()
            self.assertTrue(_is_stuck(history, raw_rows, config=config))

    def test_judge_fallback_disabled_by_default(self):
        history = [_record(0.0), _record(0.0)]
        raw_rows = [{"test_output": "x"}, {"test_output": "x"}]
        with patch("urllib.request.urlopen") as mocked:
            self.assertFalse(_is_stuck(history, raw_rows, config=_config()))
            mocked.assert_not_called()


class JudgeProgressTests(unittest.TestCase):
    def test_unconfigured_returns_none_without_network_call(self):
        with patch("urllib.request.urlopen") as mocked:
            self.assertIsNone(_judge_progress("a", "b", config=_config()))
            mocked.assert_not_called()

    def test_empty_detail_returns_none_without_network_call(self):
        config = _config(judge_model="judge-model", judge_url="http://localhost:9999")
        with patch("urllib.request.urlopen") as mocked:
            self.assertIsNone(_judge_progress("", "b", config=config))
            mocked.assert_not_called()

    def test_classifies_from_response_content(self):
        config = _config(judge_model="judge-model", judge_url="http://localhost:9999")
        with patch("urllib.request.urlopen") as mocked:
            mocked.return_value.__enter__.return_value.read.return_value = json.dumps(
                {"choices": [{"message": {"content": "  Closer  "}}]}
            ).encode()
            self.assertEqual(_judge_progress("a", "b", config=config), "closer")

    def test_unparseable_response_returns_none(self):
        config = _config(judge_model="judge-model", judge_url="http://localhost:9999")
        with patch("urllib.request.urlopen") as mocked:
            mocked.return_value.__enter__.return_value.read.return_value = b"not json"
            self.assertIsNone(_judge_progress("a", "b", config=config))

    def test_network_error_returns_none(self):
        config = _config(judge_model="judge-model", judge_url="http://localhost:9999")
        with patch("urllib.request.urlopen", side_effect=OSError("unreachable")):
            self.assertIsNone(_judge_progress("a", "b", config=config))

    def test_unrecognized_classification_returns_none(self):
        config = _config(judge_model="judge-model", judge_url="http://localhost:9999")
        with patch("urllib.request.urlopen") as mocked:
            mocked.return_value.__enter__.return_value.read.return_value = json.dumps(
                {"choices": [{"message": {"content": "maybe?"}}]}
            ).encode()
            self.assertIsNone(_judge_progress("a", "b", config=config))


class BuildAdaptedInstructionTests(unittest.TestCase):
    def test_escalates_wording_when_stuck(self):
        with tempfile.TemporaryDirectory() as root:
            task_folder = Path(root)
            (task_folder / "instruction.md").write_text("fix the bug\n")
            not_stuck = _build_adapted_instruction(
                task_folder, {"reward": 0.33, "test_output": "assertion failed"}, stuck=False
            )
            stuck = _build_adapted_instruction(
                task_folder, {"reward": 0.33, "test_output": "assertion failed"}, stuck=True
            )
            self.assertNotIn("fundamentally different", not_stuck)
            self.assertIn("fundamentally different", stuck)
            self.assertIn("fix the bug", stuck)


class MaterializeAttemptTaskTests(unittest.TestCase):
    def test_original_untouched_and_instruction_adapted(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            task_folder = root_path / "task-a"
            task_folder.mkdir()
            (task_folder / "instruction.md").write_text("original instruction\n")
            original_bytes = (task_folder / "instruction.md").read_bytes()

            scratch_root = root_path / "attempts" / "task-a" / "1"
            scratch_root.mkdir(parents=True)
            target = _materialize_attempt_task(
                task_folder, "adapted instruction\n", scratch_root=scratch_root
            )

            self.assertEqual((task_folder / "instruction.md").read_bytes(), original_bytes)
            self.assertEqual((target / "instruction.md").read_text(), "adapted instruction\n")
            self.assertNotEqual(target, task_folder)

    def test_no_adaptation_keeps_original_instruction(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            task_folder = root_path / "task-a"
            task_folder.mkdir()
            (task_folder / "instruction.md").write_text("original instruction\n")

            scratch_root = root_path / "attempts" / "task-a" / "1"
            scratch_root.mkdir(parents=True)
            target = _materialize_attempt_task(task_folder, None, scratch_root=scratch_root)

            self.assertEqual((target / "instruction.md").read_text(), "original instruction\n")


class LoadEnvFileTests(unittest.TestCase):
    def test_parses_simple_and_quoted_values(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / ".env"
            path.write_text(
                "# a comment\n"
                "\n"
                "OPENSHELL_GATEWAY_ENDPOINT=example.internal:443\n"
                'OPENSHELL_GATEWAY_WORKSPACE="default"\n'
            )
            path.chmod(0o600)
            values = load_env_file(path)
            self.assertEqual(
                values,
                {
                    "OPENSHELL_GATEWAY_ENDPOINT": "example.internal:443",
                    "OPENSHELL_GATEWAY_WORKSPACE": "default",
                },
            )

    def test_rejects_malformed_line(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / ".env"
            path.write_text("not-a-valid-line\n")
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                load_env_file(path)


class GymEvalRunApiKeyTests(unittest.TestCase):
    """The model API key must never appear verbatim in the gym subprocess's own argv
    (visible to any local user via /proc/<pid>/cmdline for its lifetime)."""

    def test_api_key_is_interpolated_not_materialized_in_argv(self):
        with (
            tempfile.TemporaryDirectory() as root,
            patch.dict("os.environ", {"FAKE_MODEL_API_KEY": "sk-super-secret"}),
        ):
            root_path = Path(root)
            config = _config(model_api_key_env="FAKE_MODEL_API_KEY")
            captured = {}

            def fake_bounded_process(argv, **kwargs):
                captured["argv"] = argv
                captured["env"] = kwargs["env"]
                return ProcessResult(returncode=0, stdout=b"")

            with patch(
                "agent_boundary_gate.adaptive_task_runner.bounded_process",
                side_effect=fake_bounded_process,
            ):
                _gym_eval_run(
                    config, root_path / "task-a", root_path / "attempt", cancelled=Event()
                )

            self.assertNotIn("sk-super-secret", captured["argv"])
            key_index = captured["argv"].index("--model-api-key")
            self.assertEqual(captured["argv"][key_index + 1], "${oc.env:FAKE_MODEL_API_KEY}")
            # The subprocess's own environment still carries the real value, for
            # OmegaConf's oc.env resolver to read at Hydra config-resolution time.
            self.assertEqual(captured["env"]["FAKE_MODEL_API_KEY"], "sk-super-secret")

    def test_unset_env_var_fails_before_gym_launches(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            config = _config(model_api_key_env="DEFINITELY_UNSET_MODEL_KEY")
            with (
                patch.dict("os.environ", clear=False) as environment,
                patch("agent_boundary_gate.adaptive_task_runner.bounded_process") as launched,
                self.assertRaisesRegex(ValueError, "is not set"),
            ):
                environment.pop("DEFINITELY_UNSET_MODEL_KEY", None)
                _gym_eval_run(
                    config, root_path / "task-a", root_path / "attempt", cancelled=Event()
                )
            launched.assert_not_called()

    def test_rejects_malformed_env_var_name(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            config = _config(model_api_key_env="not valid; rm -rf /")
            with self.assertRaises(ValueError):
                _gym_eval_run(
                    config, root_path / "task-a", root_path / "attempt", cancelled=Event()
                )


class AttemptRecordMalformedRewardProfileTests(unittest.TestCase):
    """A malformed reward-profile row from Gym (an external, unvalidated contract) must
    mask the one attempt, not raise a raw TypeError/ValueError out of the whole run."""

    def _write_and_score(self, root_path: Path, rollout_info_overrides: dict) -> AttemptRecord:
        store = EvidenceStore(root_path / "evidence")
        rollouts_path = root_path / "rollouts.jsonl"
        profile_path = root_path / "rollouts_reward_profiling.jsonl"
        rollouts_path.write_text(json.dumps(_rollout_row(0.0)) + "\n")
        rollout_info = {"rollout_id": "0:0", "_ng_task_index": 0, "_ng_rollout_index": 0}
        rollout_info.update(rollout_info_overrides)
        profile_path.write_text(
            json.dumps({"_ng_task_index": 0, "rollout_infos": [rollout_info]}) + "\n"
        )
        record, _ = _attempt_record("task-a", 1, rollouts_path, profile_path, store)
        return record

    def test_null_reward_is_masked_not_raised(self):
        with tempfile.TemporaryDirectory() as root:
            record = self._write_and_score(Path(root), {"reward": None})
            self.assertTrue(record.mask_sample)
            self.assertEqual(record.reward, 0.0)
            self.assertEqual(record.failure_kind, "harbor:attempt_infra_error")

    def test_non_numeric_tests_passed_is_masked_not_raised(self):
        with tempfile.TemporaryDirectory() as root:
            record = self._write_and_score(
                Path(root), {"reward": 1.0, "tests_passed": "not-a-number"}
            )
            self.assertTrue(record.mask_sample)
            self.assertEqual(record.failure_kind, "harbor:attempt_infra_error")

    def test_well_formed_row_still_scores_normally(self):
        with tempfile.TemporaryDirectory() as root:
            record = self._write_and_score(
                Path(root), {"reward": 1.0, "tests_passed": 3, "tests_total": 3}
            )
            self.assertFalse(record.mask_sample)
            self.assertEqual(record.reward, 1.0)
            self.assertEqual(record.tests_passed, 3)
            self.assertEqual(record.tests_total, 3)


def _rollout_row(reward: float, mask_sample: bool = False, test_output: str = "") -> dict:
    return {
        "reward": reward,
        "mask_sample": mask_sample,
        "failure_kind": None,
        "failure_reason": None,
        "test_output": test_output,
    }


def _profile_row(
    reward: float, tests_passed: int | None = None, tests_total: int | None = None
) -> dict:
    rollout_info = {
        "rollout_id": "0:0",
        "_ng_task_index": 0,
        "_ng_rollout_index": 0,
        "reward": reward,
    }
    if tests_passed is not None:
        rollout_info["tests_passed"] = tests_passed
    if tests_total is not None:
        rollout_info["tests_total"] = tests_total
    return {"_ng_task_index": 0, "rollout_infos": [rollout_info]}


class AdaptiveTaskRunnerRunTests(unittest.TestCase):
    def test_fail_then_succeed_then_second_task_succeeds(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            task_a = root_path / "tasks" / "task-a"
            task_a.mkdir(parents=True)
            (task_a / "instruction.md").write_text("fix it\n")
            task_b = root_path / "tasks" / "task-b"
            task_b.mkdir(parents=True)
            (task_b / "instruction.md").write_text("fix it too\n")

            output = root_path / "output"
            config = _config(
                task_folders=[task_a, task_b],
                max_attempts_per_task=3,
                success_reward_threshold=1.0,
            )

            # Scripted per-call results, in call order: task-a attempt 1 (fail), attempt 2
            # (succeed), task-b attempt 1 (succeed). Each "gym eval run" call is immediately
            # followed by a "gym eval profile" call.
            script = iter(
                [
                    _rollout_row(0.0, test_output="assertion failed"),
                    _rollout_row(1.0),
                    _rollout_row(1.0),
                ]
            )
            rewards = iter([0.0, 1.0, 1.0])

            def fake_bounded_process(argv, **kwargs):
                if "run" in argv:
                    rollouts_path = Path(argv[argv.index("--output") + 1])
                    rollouts_path.parent.mkdir(parents=True, exist_ok=True)
                    row = next(script)
                    rollouts_path.write_text(json.dumps(row) + "\n")
                elif "profile" in argv:
                    rollouts_path = Path(argv[argv.index("--rollouts") + 1])
                    profile_path = rollouts_path.with_name(
                        rollouts_path.stem + "_reward_profiling.jsonl"
                    )
                    profile_path.write_text(json.dumps(_profile_row(next(rewards))) + "\n")
                else:
                    raise AssertionError(f"unexpected argv: {argv}")
                return ProcessResult(returncode=0, stdout=b"")

            with patch(
                "agent_boundary_gate.adaptive_task_runner.bounded_process",
                side_effect=fake_bounded_process,
            ) as mocked:
                report = adaptive_task_runner_run(config, output, cancelled=Event())

            self.assertTrue(report["completed"])
            self.assertEqual(len(report["tasks"]["task-a"]), 2)
            self.assertEqual(report["tasks"]["task-a"][0]["decision"], "retry")
            self.assertEqual(report["tasks"]["task-a"][1]["decision"], "advance")
            self.assertEqual(len(report["tasks"]["task-b"]), 1)
            self.assertEqual(report["tasks"]["task-b"][0]["decision"], "advance")
            self.assertEqual(mocked.call_count, 6)  # 3 attempts x (run + profile)

            # The adapted instruction for task-a's second attempt must reflect the first
            # attempt's failure detail.
            attempt_2_instruction = (
                output / "attempts" / "task-a" / "task-a-attempt-2" / "instruction.md"
            ).read_text()
            self.assertIn("assertion failed", attempt_2_instruction)
            self.assertIn("fix it", attempt_2_instruction)

            # report_ref resolves through EvidenceStore.
            from agent_boundary_gate.evidence import EvidenceStore

            store = EvidenceStore(output, create=False)
            resolved = json.loads(store.read(report["report_ref"]))
            self.assertEqual(resolved["tool"], "adaptive-task-runner")

    def test_all_masked_abandons_the_whole_run(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            task_a = root_path / "tasks" / "task-a"
            task_a.mkdir(parents=True)
            (task_a / "instruction.md").write_text("fix it\n")
            task_b = root_path / "tasks" / "task-b"
            task_b.mkdir(parents=True)
            (task_b / "instruction.md").write_text("never reached\n")

            output = root_path / "output"
            config = _config(task_folders=[task_a, task_b], max_attempts_per_task=1)

            def fake_bounded_process(argv, **kwargs):
                if "run" in argv:
                    rollouts_path = Path(argv[argv.index("--output") + 1])
                    rollouts_path.parent.mkdir(parents=True, exist_ok=True)
                    # No profile row written at all -> _attempt_record treats it as masked.
                    rollouts_path.write_text("")
                elif "profile" in argv:
                    pass
                else:
                    raise AssertionError(f"unexpected argv: {argv}")
                return ProcessResult(returncode=0, stdout=b"")

            with patch(
                "agent_boundary_gate.adaptive_task_runner.bounded_process",
                side_effect=fake_bounded_process,
            ):
                report = adaptive_task_runner_run(config, output, cancelled=Event())

            self.assertFalse(report["completed"])
            self.assertEqual(report["tasks"]["task-a"][0]["decision"], "abandon")
            self.assertNotIn("task-b", report["tasks"])  # the run stopped before reaching it

    def test_no_progress_escalates_the_third_attempts_instruction(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            task_a = root_path / "tasks" / "task-a"
            task_a.mkdir(parents=True)
            (task_a / "instruction.md").write_text("fix the bug\n")

            output = root_path / "output"
            config = _config(
                task_folders=[task_a], max_attempts_per_task=3, success_reward_threshold=1.0
            )

            # Same tests_passed/tests_total for attempts 1 and 2 -> stuck by attempt 3.
            rollout_script = iter(
                [
                    _rollout_row(0.33, test_output="still failing"),
                    _rollout_row(0.33, test_output="still failing"),
                    _rollout_row(0.33, test_output="still failing"),
                ]
            )
            profile_script = iter(
                [
                    _profile_row(0.33, tests_passed=1, tests_total=3),
                    _profile_row(0.33, tests_passed=1, tests_total=3),
                    _profile_row(0.33, tests_passed=1, tests_total=3),
                ]
            )

            def fake_bounded_process(argv, **kwargs):
                if "run" in argv:
                    rollouts_path = Path(argv[argv.index("--output") + 1])
                    rollouts_path.parent.mkdir(parents=True, exist_ok=True)
                    rollouts_path.write_text(json.dumps(next(rollout_script)) + "\n")
                elif "profile" in argv:
                    rollouts_path = Path(argv[argv.index("--rollouts") + 1])
                    profile_path = rollouts_path.with_name(
                        rollouts_path.stem + "_reward_profiling.jsonl"
                    )
                    profile_path.write_text(json.dumps(next(profile_script)) + "\n")
                else:
                    raise AssertionError(f"unexpected argv: {argv}")
                return ProcessResult(returncode=0, stdout=b"")

            with patch(
                "agent_boundary_gate.adaptive_task_runner.bounded_process",
                side_effect=fake_bounded_process,
            ):
                report = adaptive_task_runner_run(config, output, cancelled=Event())

            self.assertEqual(len(report["tasks"]["task-a"]), 3)
            # Budget exhausted on a real (non-masked) failure -> advance, not abandon.
            self.assertEqual(report["tasks"]["task-a"][-1]["decision"], "advance")

            attempt_2_instruction = (
                output / "attempts" / "task-a" / "task-a-attempt-2" / "instruction.md"
            ).read_text()
            attempt_3_instruction = (
                output / "attempts" / "task-a" / "task-a-attempt-3" / "instruction.md"
            ).read_text()
            # Attempt 2's retry follows attempt 1 alone -- nothing to be "stuck" against yet.
            self.assertNotIn("fundamentally different", attempt_2_instruction)
            # Attempt 3's retry follows two consecutive no-progress attempts -> escalated.
            self.assertIn("fundamentally different", attempt_3_instruction)


class CliDispatchTests(unittest.TestCase):
    def test_adaptive_task_run_subcommand_invokes_runner(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            config_path = root_path / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "gym_executable": str(root_path / "gym"),
                        "harbor_extra_root": str(root_path / "harbor_extra_root"),
                        "task_folders": [str(root_path / "task-a")],
                    }
                )
            )
            config_path.chmod(0o600)
            output = root_path / "output"

            fake_report = {"tool": "adaptive-task-runner", "completed": True, "tasks": {}}
            argv = [
                "agent-boundary-gate",
                "adaptive-task-run",
                "--config",
                str(config_path),
                "--output",
                str(output),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch(
                    "agent_boundary_gate.adaptive_task_runner.adaptive_task_runner_run",
                    return_value=fake_report,
                ) as mocked,
            ):
                from agent_boundary_gate.cli import main

                exit_code = main()

            self.assertEqual(exit_code, 0)
            self.assertEqual(mocked.call_count, 1)

    def test_env_file_is_loaded_without_overriding_existing(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            config_path = root_path / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "gym_executable": str(root_path / "gym"),
                        "harbor_extra_root": str(root_path / "harbor_extra_root"),
                        "task_folders": [str(root_path / "task-a")],
                    }
                )
            )
            config_path.chmod(0o600)
            env_path = root_path / ".env"
            env_path.write_text("ADAPTIVE_TASK_RUNNER_TEST_VAR=from-file\n")
            env_path.chmod(0o600)
            output = root_path / "output"

            argv = [
                "agent-boundary-gate",
                "adaptive-task-run",
                "--config",
                str(config_path),
                "--output",
                str(output),
                "--env-file",
                str(env_path),
            ]
            import os as os_module

            os_module.environ.pop("ADAPTIVE_TASK_RUNNER_TEST_VAR", None)
            fake_report = {"tool": "adaptive-task-runner", "completed": True, "tasks": {}}
            try:
                with (
                    patch.object(sys, "argv", argv),
                    patch(
                        "agent_boundary_gate.adaptive_task_runner.adaptive_task_runner_run",
                        return_value=fake_report,
                    ),
                ):
                    from agent_boundary_gate.cli import main

                    main()
                self.assertEqual(
                    os_module.environ.get("ADAPTIVE_TASK_RUNNER_TEST_VAR"), "from-file"
                )
            finally:
                os_module.environ.pop("ADAPTIVE_TASK_RUNNER_TEST_VAR", None)


if __name__ == "__main__":
    unittest.main()
