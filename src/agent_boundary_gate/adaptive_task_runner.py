"""Retry/advance/abandon loop over NeMo Gym's Harbor eval CLI; no gate authority.

Separate, unrelated capability from this repo's red-team/boundary-gate work: drives
an agent (OpenCode, via Gym's existing opencode_agent wrapper) through a Harbor
coding task, scores each attempt via Gym's reward-profiling output, and decides to
retry with an adapted instruction, advance to the next task, or abandon the whole
run. Gym itself holds no state across CLI invocations -- every `gym eval` command is
a one-shot call over files on disk -- so that decision loop lives here.

Does not import nemo_gym: it only shells out to the `gym` console script via
`agent_boundary_gate.process.bounded_process`, so it carries no heavy/optional
dependency of its own.
"""

import json
import os
import re
import shutil
import time
from enum import StrEnum
from pathlib import Path
from threading import Event
from typing import Annotated, Any

from pydantic import Field

from agent_boundary_gate.doctor import read_regular_input
from agent_boundary_gate.evidence import EvidenceStore
from agent_boundary_gate.process import AttemptStopped, bounded_process
from agent_boundary_gate.receipts import ReceiptContract

DEMO_INSTRUCTION_TAIL_CHARS = 4000
_ENV_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]{0,80})=(.*)$")


def load_env_file(path: Path) -> dict[str, str]:
    """Parse simple KEY=VALUE lines (no shell expansion, no command substitution).

    Blank lines and lines starting with '#' are skipped. A value may be wrapped in
    single or double quotes, stripped verbatim; nothing else is interpreted. This is
    deliberately not a general .env parser -- it exists so an operator can keep the
    OpenShell/model connection details this tool needs (OPENSHELL_GATEWAY_*, a model
    API key env var name's *value*) in one untracked file instead of exporting them
    by hand every run.
    """
    values: dict[str, str] = {}
    raw = read_regular_input(path, limit=65536, private=True)
    for line in raw.decode().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if not match:
            raise ValueError(f"invalid .env line: {line!r}")
        key, value = match.group(1), match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key] = value
    return values


class AdaptiveTaskRunnerConfig(ReceiptContract):
    gym_executable: Path
    harbor_extra_root: Path
    task_folders: Annotated[list[Path], Field(min_length=1)]
    agent: str = "opencode_agent"
    sandbox_provider: str = "openshell_remote"
    model: str | None = None
    model_url: str | None = None
    # Name of an env var holding the model API key; the value itself never lives in this config
    # or in any persisted evidence.
    model_api_key_env: str | None = None
    extra_config_paths: list[Path] = []
    max_attempts_per_task: Annotated[int, Field(ge=1, le=20)] = 3
    success_reward_threshold: float = 1.0
    attempt_seconds: Annotated[int, Field(ge=30, le=3600)] = 900
    profile_seconds: Annotated[int, Field(ge=10, le=600)] = 120


class StopDecision(StrEnum):
    RETRY = "retry"
    ADVANCE = "advance"
    ABANDON = "abandon"


class AttemptRecord(ReceiptContract):
    task_id: str
    attempt_number: int
    reward: float
    mask_sample: bool
    failure_kind: str | None
    failure_reason: str | None
    # Optional structured progress signal, only present when a task's test.sh reports it
    # (see onboarding/gym/harbor_extra_root/resources_servers/harbor/app.py's
    # TESTS_PASSED_KEY/TESTS_TOTAL_KEY). None for a task that only reports a bare reward.
    tests_passed: int | None = None
    tests_total: int | None = None
    decision: StopDecision
    rollouts_ref: str
    reward_profile_ref: str


def fixed_budget_should_continue(
    history: list[AttemptRecord], *, config: AdaptiveTaskRunnerConfig
) -> StopDecision:
    """v1 placeholder stop rule: a fixed attempt budget, not a no-progress check.

    Deliberately simple per an explicit decision to pick the real stop criterion only
    after seeing a working prototype. "Abandon" is reserved for every attempt in this
    task's history being a pure infra failure (mask_sample on all of them) -- that
    stops the whole multi-task run rather than burning the rest of its budget against
    what looks like a broken gateway. Plain budget exhaustion on a real (non-infra)
    failure still "advances" so a multi-task run finishes even if one task is simply
    too hard. This asymmetry is a judgment call, flagged for review once real data
    exists.
    """
    last = history[-1]
    if not last.mask_sample and last.reward >= config.success_reward_threshold:
        return StopDecision.ADVANCE
    if len(history) < config.max_attempts_per_task:
        return StopDecision.RETRY
    if all(record.mask_sample for record in history):
        return StopDecision.ABANDON
    return StopDecision.ADVANCE


def _gym_environment(config: AdaptiveTaskRunnerConfig) -> dict[str, str]:
    # Explicit allow-list, not a bare os.environ passthrough: bounded_process's env= replaces the
    # subprocess environment entirely, so an incomplete list breaks the child rather than leaking
    # anything into it.
    names = {"PATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR", "HOME"}
    names.update(
        name
        for name in os.environ
        if name.startswith("OPENSHELL_GATEWAY_") or name.startswith("NEMO_GYM_")
    )
    if config.model_api_key_env:
        names.add(config.model_api_key_env)
    return {name: os.environ[name] for name in names if name in os.environ}


def _materialize_attempt_task(
    task_folder: Path, adapted_instruction: str | None, *, scratch_root: Path
) -> Path:
    attempt_name = f"{task_folder.name}-attempt-{scratch_root.name}"
    target = scratch_root.parent / attempt_name
    shutil.copytree(task_folder, target)
    if adapted_instruction is not None:
        (target / "instruction.md").write_text(adapted_instruction)
    return target


def _is_stuck(history: list[AttemptRecord]) -> bool:
    """No progress between the last two attempts, by the task's own structured signal.

    Requires at least two attempts, neither masked (an infra failure is a different
    problem, already handled by fixed_budget_should_continue's all-masked check), and
    a task that actually reports tests_passed/tests_total -- a task that only reports
    a bare reward has no structured signal to compare, so this is never "stuck" for it
    (the existing reward-only retry behavior is unaffected). Comparing tests_passed
    rather than the reward float avoids false positives from floating-point noise and
    is meaningful even when reward is a derived ratio, as the demo task's is.
    """
    if len(history) < 2:
        return False
    previous, last = history[-2], history[-1]
    if previous.mask_sample or last.mask_sample:
        return False
    if previous.tests_passed is None or last.tests_passed is None:
        return False
    if previous.tests_total != last.tests_total:
        return False
    return previous.tests_passed == last.tests_passed


def _build_adapted_instruction(
    task_folder: Path, raw_rollout: dict[str, Any] | None, *, stuck: bool = False
) -> str:
    original = (task_folder / "instruction.md").read_text()
    if raw_rollout is None:
        return original
    reward = raw_rollout.get("reward")
    detail = raw_rollout.get("test_output") or raw_rollout.get("failure_reason") or ""
    detail = detail[-DEMO_INSTRUCTION_TAIL_CHARS:]
    feedback = (
        f"{original}\n\n---\n\nA previous attempt scored reward={reward!r}. "
        f"Its test output (most recent, possibly truncated) was:\n\n{detail}\n"
    )
    if stuck:
        feedback += (
            "\n---\n\nThe last two attempts made no further progress (the same number "
            "of checks passed both times). Making the same kind of change again is "
            "unlikely to help -- try a fundamentally different implementation "
            "approach, not a small variation on the previous one.\n"
        )
    return feedback


def _gym_eval_run(
    config: AdaptiveTaskRunnerConfig, target: Path, attempt_dir: Path, *, cancelled: Event
) -> Path:
    rollouts_path = attempt_dir / "rollouts.jsonl"
    argv = [
        str(config.gym_executable),
        "eval",
        "run",
        str(target),
        "--agent",
        config.agent,
        "--sandbox",
        config.sandbox_provider,
        "--search-dir",
        str(config.harbor_extra_root),
        "--output",
        str(rollouts_path),
        "--limit",
        "1",
        "--num-repeats",
        "1",
        "--no-health-check",
    ]
    for path in config.extra_config_paths:
        argv += ["--config", str(path)]
    if config.model:
        argv += ["--model", config.model]
    if config.model_url:
        argv += ["--model-url", config.model_url]
    if config.model_api_key_env:
        argv += ["--model-api-key", os.environ.get(config.model_api_key_env, "")]
    bounded_process(
        argv,
        deadline=time.monotonic() + config.attempt_seconds,
        cancelled=cancelled,
        max_output=1 << 20,
        env=_gym_environment(config),
    )
    return rollouts_path


def _gym_eval_profile(
    config: AdaptiveTaskRunnerConfig,
    attempt_target: Path,
    rollouts_path: Path,
    *,
    cancelled: Event,
) -> Path:
    # nemo_gym.tasks.harbor.cli.DEFAULT_OUTPUT_ROOT ("results/harbor") is relative to the
    # subprocess's own cwd; bounded_process never sets one, so every `gym` subprocess inherits
    # this orchestrator process's cwd, and this path assumes it hasn't changed since the eval
    # run call above (it hasn't -- no chdir happens between the two).
    inputs_path = Path.cwd() / "results" / "harbor" / attempt_target.name / "tasks.jsonl"
    argv = [
        str(config.gym_executable),
        "eval",
        "profile",
        "--inputs",
        str(inputs_path),
        "--rollouts",
        str(rollouts_path),
    ]
    bounded_process(
        argv,
        deadline=time.monotonic() + config.profile_seconds,
        cancelled=cancelled,
        max_output=1 << 20,
        env=_gym_environment(config),
    )
    return rollouts_path.with_name(rollouts_path.stem + "_reward_profiling.jsonl")


def _read_jsonl_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _attempt_record(
    task_id: str, attempt_number: int, rollouts_path: Path, profile_path: Path, store: EvidenceStore
) -> tuple[AttemptRecord, dict[str, Any] | None]:
    raw_rows = _read_jsonl_rows(rollouts_path)
    raw_row = raw_rows[0] if raw_rows else None
    profile_rows = _read_jsonl_rows(profile_path)

    rollouts_ref = store.persist_json(raw_row if raw_row is not None else {})
    reward_profile_ref = store.persist_json(profile_rows[0] if profile_rows else {})

    if not profile_rows or not profile_rows[0].get("rollout_infos"):
        # The run or the profiling step produced no scoreable result (crash, timeout, infra
        # failure). Treat it as a masked zero rather than raising out of the loop.
        return (
            AttemptRecord(
                task_id=task_id,
                attempt_number=attempt_number,
                reward=0.0,
                mask_sample=True,
                failure_kind="harbor:attempt_infra_error",
                failure_reason="no scoreable rollout_infos in the reward profile",
                decision=StopDecision.ABANDON,  # overwritten by the caller immediately after
                rollouts_ref=rollouts_ref,
                reward_profile_ref=reward_profile_ref,
            ),
            raw_row,
        )

    rollout_info = profile_rows[0]["rollout_infos"][0]
    reward = float(rollout_info.get("reward", 0.0))
    mask_sample = bool((raw_row or {}).get("mask_sample", False))
    tests_passed = rollout_info.get("tests_passed")
    tests_total = rollout_info.get("tests_total")
    return (
        AttemptRecord(
            task_id=task_id,
            attempt_number=attempt_number,
            reward=reward,
            mask_sample=mask_sample,
            failure_kind=(raw_row or {}).get("failure_kind"),
            failure_reason=(raw_row or {}).get("failure_reason"),
            tests_passed=int(tests_passed) if tests_passed is not None else None,
            tests_total=int(tests_total) if tests_total is not None else None,
            decision=StopDecision.ABANDON,  # overwritten by the caller immediately after
            rollouts_ref=rollouts_ref,
            reward_profile_ref=reward_profile_ref,
        ),
        raw_row,
    )


def adaptive_task_runner_run(
    config: AdaptiveTaskRunnerConfig, output: Path, *, cancelled: Event | None = None
) -> dict:
    cancelled = cancelled or Event()
    output.mkdir(mode=0o700, exist_ok=False)
    store = EvidenceStore(output, create=False)
    tasks: dict[str, list[dict[str, Any]]] = {}
    try:
        for task_folder in config.task_folders:
            task_id = task_folder.name
            history: list[AttemptRecord] = []
            adapted_instruction: str | None = None
            while True:
                attempt_dir = output / "attempts" / task_id / str(len(history) + 1)
                attempt_dir.mkdir(parents=True, exist_ok=False)
                attempt_target = _materialize_attempt_task(
                    task_folder, adapted_instruction, scratch_root=attempt_dir
                )
                rollouts_path = _gym_eval_run(
                    config, attempt_target, attempt_dir, cancelled=cancelled
                )
                profile_path = _gym_eval_profile(
                    config, attempt_target, rollouts_path, cancelled=cancelled
                )
                record, raw_row = _attempt_record(
                    task_id, len(history) + 1, rollouts_path, profile_path, store
                )
                candidate_history = [*history, record]
                decision = fixed_budget_should_continue(candidate_history, config=config)
                record = record.model_copy(update={"decision": decision})
                history.append(record)
                if decision != StopDecision.RETRY:
                    break
                adapted_instruction = _build_adapted_instruction(
                    task_folder, raw_row, stuck=_is_stuck(candidate_history)
                )
            tasks[task_id] = [record.model_dump(mode="json") for record in history]
            if history[-1].decision == StopDecision.ABANDON:
                break
    except (OSError, ValueError, AttemptStopped) as exc:
        report = {
            "tool": "adaptive-task-runner",
            "completed": False,
            "error_code": "interrupted-or-attempt-failed",
            "error_detail": str(exc)[:2000],
            "tasks": tasks,
        }
        report["report_ref"] = store.persist_json(report)
        return report
    report = {
        "tool": "adaptive-task-runner",
        "completed": all(
            history[-1]["decision"] != StopDecision.ABANDON.value for history in tasks.values()
        ),
        "tasks": tasks,
    }
    report["report_ref"] = store.persist_json(report)
    return report
