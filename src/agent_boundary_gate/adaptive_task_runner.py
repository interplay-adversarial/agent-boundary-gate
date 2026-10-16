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
import urllib.request
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
JUDGE_DETAIL_TAIL_CHARS = 2000
JUDGE_CLASSIFICATIONS = frozenset({"same_failure", "different_failure", "closer", "resolved"})
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
    # Point this at onboarding/gym/bin/gym-py314, not .venv/bin/gym directly: the wrapper
    # sets PYTHONPATH (for sitecustomize.py's compatibility patches, see _gym_environment)
    # via its own re-exec, independent of whatever environment this orchestrator itself
    # runs under. Pointing straight at .venv/bin/gym instead still works as long as this
    # process's own PYTHONPATH already includes onboarding/gym/bin.
    gym_executable: Path
    harbor_extra_root: Path
    task_folders: Annotated[list[Path], Field(min_length=1)]
    agent: str = "opencode_agent"
    # "docker" (via a local Docker/podman install), not "openshell_remote": confirmed this
    # session that OpenShell's Gym provider has no serialize_handle()/ConnectableProvider
    # support at all, which opencode_agent's sandboxed path requires for anything but
    # owns_sandbox -- a hard, unfixable-from-here upstream gap, not a config problem. See
    # docs/adaptive-task-runner.md's "Known limits" section. "openshell_remote" stays
    # available as a sandbox_provider value (its config still exists) for a future Gym
    # version that adds this support, or a different, owns_sandbox-based agent.
    sandbox_provider: str = "docker"
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
    # Optional fallback for tasks that report no structured tests_passed/tests_total: a judge
    # model classifies whether two consecutive raw failure texts show progress. Disabled
    # unless both judge_model and judge_url are set -- a task with a structured signal never
    # calls it (the numeric comparison always wins), and any call/parse failure just means
    # "not stuck" (today's behavior), never an error. A separate role from `model`/`model_url`
    # (the agent under test), matching red_team.py's own separate ADVERSARIAL/TARGET/JUDGE
    # model convention -- a classification judge doesn't need to be the same model.
    judge_model: str | None = None
    judge_url: str | None = None
    judge_api_key_env: str | None = None
    judge_timeout_seconds: Annotated[int, Field(ge=5, le=120)] = 30


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
    #
    # PYTHONPATH: required for onboarding/gym/bin/sitecustomize.py's Python-3.14/Gym
    # compatibility patches (see that file's own docstring for the full list) to reach
    # every one of Gym's spawned server subprocesses, not just this orchestrator's own
    # `gym eval` call -- those patches are what makes the docker/podman sandbox path (this
    # config's default) actually work at all on a machine without a real `docker` binary.
    # Pointing `gym_executable` at `onboarding/gym/bin/gym-py314` (recommended; see docs)
    # sets this up on its own via re-exec, independent of the orchestrator's own
    # environment -- allow-listing it here is defense in depth for a caller who points
    # `gym_executable` straight at the venv's own `gym` script instead.
    names = {"PATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR", "HOME", "PYTHONPATH"}
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


def _judge_progress(
    previous_detail: str, last_detail: str, *, config: AdaptiveTaskRunnerConfig
) -> str | None:
    """Classify two consecutive raw failure texts via a judge model call.

    Returns one of JUDGE_CLASSIFICATIONS, or None when judging isn't configured
    (judge_model/judge_url unset), either text is empty, or the call/parse fails for any
    reason. Never raises: a None here just means the caller's no-signal fallback applies,
    identical to today's behavior for a task with no judge configured at all. Uses stdlib
    urllib rather than an SDK/HTTP-client dependency -- this module deliberately carries no
    dependency beyond pydantic (it does not import nemo_gym or add an HTTP client just for
    one classification call).
    """
    if not config.judge_model or not config.judge_url:
        return None
    previous_detail = previous_detail.strip()[-JUDGE_DETAIL_TAIL_CHARS:]
    last_detail = last_detail.strip()[-JUDGE_DETAIL_TAIL_CHARS:]
    if not previous_detail or not last_detail:
        return None
    prompt = (
        "Two consecutive attempts at the same coding task failed. Classify the "
        "relationship between them as exactly one of these words, nothing else:\n"
        "same_failure - the two failures are essentially the same underlying problem\n"
        "different_failure - a different problem now, but no closer to passing overall\n"
        "closer - still failing, but visibly closer to passing than before\n"
        "resolved - the second attempt's output suggests it actually passed\n\n"
        f"First attempt's failure:\n{previous_detail}\n\n"
        f"Second attempt's failure:\n{last_detail}\n"
    )
    headers = {"Content-Type": "application/json"}
    if config.judge_api_key_env:
        key = os.environ.get(config.judge_api_key_env)
        if key:
            headers["Authorization"] = f"Bearer {key}"
    request = urllib.request.Request(
        config.judge_url.rstrip("/") + "/chat/completions",
        data=json.dumps(
            {
                "model": config.judge_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "max_tokens": 10,
            }
        ).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=config.judge_timeout_seconds) as response:
            payload = json.loads(response.read())
        text = payload["choices"][0]["message"]["content"].strip().lower()
    except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError):
        return None
    return text if text in JUDGE_CLASSIFICATIONS else None


def _is_stuck(
    history: list[AttemptRecord],
    raw_rows: list[dict[str, Any] | None],
    *,
    config: AdaptiveTaskRunnerConfig,
) -> bool:
    """No progress between the last two attempts.

    Requires at least two attempts, neither masked (an infra failure is a different
    problem, already handled by fixed_budget_should_continue's all-masked check). Two
    signal sources, structured first: when both attempts report tests_passed, that
    numeric comparison always wins (cheap, deterministic, no network call) -- comparing
    tests_passed rather than the reward float avoids false positives from floating-point
    noise and is meaningful even when reward is a derived ratio, as the demo task's is.
    Only when NEITHER attempt has a structured signal does this fall back to a judge
    classification of the raw test_output/failure_reason text (only if configured); a
    task that reports no structured signal and has no judge configured is simply never
    "stuck" (the original, pre-judge behavior, unaffected).
    """
    if len(history) < 2:
        return False
    previous, last = history[-2], history[-1]
    if previous.mask_sample or last.mask_sample:
        return False
    if previous.tests_passed is not None and last.tests_passed is not None:
        if previous.tests_total != last.tests_total:
            return False
        return previous.tests_passed == last.tests_passed
    previous_raw = raw_rows[-2] or {}
    last_raw = raw_rows[-1] or {}
    previous_detail = previous_raw.get("test_output") or previous_raw.get("failure_reason") or ""
    last_detail = last_raw.get("test_output") or last_raw.get("failure_reason") or ""
    return _judge_progress(previous_detail, last_detail, config=config) == "same_failure"


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
        # Every model this tool talks to is an OpenAI-compatible endpoint (model/model_url);
        # without this, Gym's run-config validation fails with "field 'model_server'
        # references responses_api_models/'policy_model', which is not defined" before a
        # single server even starts (confirmed empirically -- not documented anywhere in
        # Gym's own --help).
        "--model-type",
        "openai_model",
        "--output",
        str(rollouts_path),
        "--limit",
        "1",
        "--num-repeats",
        "1",
        "--no-health-check",
        # Reuse an already-populated per-server .venv (symlinked to onboarding/gym/.venv;
        # see docs/adaptive-task-runner.md's setup step) instead of re-running `uv pip
        # install` on every single attempt. Safe unconditionally: Gym's own
        # should_skip_venv_setup check (nemo_gym/cli/setup_command.py) only takes this
        # shortcut when that venv's bin/python and bin/activate already exist -- a first-
        # ever run with no symlinks yet falls through to the normal (full) setup path.
        "+skip_venv_if_present=true",
    ]
    if config.sandbox_provider == "docker":
        # The sandbox container otherwise has no network path back to this orchestrator's
        # own host-bound servers (policy_model, the resources/environment servers) at all --
        # confirmed empirically: a plain container-default network left OpenCode's model
        # calls to 127.0.0.1:<port> connection-refused, and with the agent's own HTTP client
        # retrying indefinitely (no timeout configured on that path), that *never* surfaces
        # as an error -- it just silently runs forever. `--network host` is the fix, not a
        # tuning knob. Conditional on "docker": sandbox.docker.create.network is only a valid
        # override when the docker provider's own config is loaded (via --sandbox docker
        # above); passing it with a different sandbox_provider would be an unknown-key error.
        argv.append("+sandbox.docker.create.network=host")
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
    rollouts_path: Path,
    *,
    cancelled: Event,
) -> Path:
    # Not results/harbor/<name>/tasks.jsonl (the pre-materialization dataset listing this
    # function originally used): confirmed empirically that its rows lack the _ng_task_index
    # key `reward_profile.py::profile_from_data` requires, so `gym eval profile` raised
    # KeyError('_ng_task_index') on every attempt -- a rollout that completed perfectly
    # (reward=1.0, mask_sample=False) still got reported as a masked
    # "harbor:attempt_infra_error" by _attempt_record below, purely because this step
    # produced no reward-profiling file at all. `gym eval run` itself writes a
    # fully-materialized version of its own input rows (with _ng_task_index already present)
    # right next to rollouts.jsonl, using this exact naming convention -- using that instead
    # also drops this function's fragile dependency on the orchestrator's own cwd and
    # Gym's "results/harbor" output-root default.
    inputs_path = rollouts_path.with_name(rollouts_path.stem + "_materialized_inputs.jsonl")
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
            raw_rows: list[dict[str, Any] | None] = []
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
                profile_path = _gym_eval_profile(config, rollouts_path, cancelled=cancelled)
                record, raw_row = _attempt_record(
                    task_id, len(history) + 1, rollouts_path, profile_path, store
                )
                candidate_history = [*history, record]
                candidate_raw_rows = [*raw_rows, raw_row]
                decision = fixed_budget_should_continue(candidate_history, config=config)
                record = record.model_copy(update={"decision": decision})
                history.append(record)
                raw_rows.append(raw_row)
                if decision != StopDecision.RETRY:
                    break
                stuck = _is_stuck(candidate_history, candidate_raw_rows, config=config)
                adapted_instruction = _build_adapted_instruction(task_folder, raw_row, stuck=stuck)
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
