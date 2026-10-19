"""Supervised optional research campaigns; no new gate/evidence authority."""

import json
import os
import re
import time
from pathlib import Path
from threading import Event

from agent_boundary_gate.doctor import read_regular_input
from agent_boundary_gate.evidence import EvidenceStore
from agent_boundary_gate.gate_policy import RELEASE_INELIGIBLE, is_release_ineligible
from agent_boundary_gate.process import AttemptStopped, bounded_process

PIN = Path(__file__).with_name("_pins") / "red-team.json"
WORKER = Path(__file__).with_name("red_team_worker.py")


def worker_environment(config):
    # Freeze only operator-declared role credentials/model names. No dotenv,
    # PYTHONPATH, proxy, unrelated provider, cluster or user-site inheritance.
    names = {"PATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR", "SYSTEMROOT"}
    names.update({"ADVERSARIAL_MODEL", "TARGET_MODEL", "JUDGE_MODEL"})
    for role in ("adversarial", "target", "judge"):
        endpoint = config.get(role, {})
        if not isinstance(endpoint, dict):
            raise ValueError("red-team-config-invalid")
        name = endpoint.get("api_key_env")
        if name is not None:
            if not isinstance(name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,80}", name):
                raise ValueError("red-team-credential-reference-invalid")
            names.add(name)
    return {name: os.environ[name] for name in names if name in os.environ} | {
        "NEMO_TELEMETRY_ENABLED": "false",
        "PYTHONNOUSERSITE": "1",
    }


def _invoke(
    python, operation, *, deadline, cancelled, environment, data=None, config=None, output=None
):
    argv = [str(python.absolute()), str(WORKER), operation, "--pin", str(PIN)]
    if config is not None:
        argv += ["--config", str(config)]
    if output is not None:
        argv += ["--output", str(output)]
    return bounded_process(
        argv, deadline=deadline, cancelled=cancelled, input_data=data, env=environment
    )


def _summary(raw, returncode):
    value = json.loads(raw)
    if not isinstance(value, dict) or not is_release_ineligible(value.get("release_eligible")):
        raise ValueError("red-team-summary-invalid")
    result = {
        "mode": "description-driven-red-team",
        "assessment_complete": returncode == 0 and value.get("assessment_complete") is True,
        "qualification": "research-only",
        **RELEASE_INELIGIBLE,
    }
    for name in ("records", "requested_probes", "successes", "failures", "inconclusive"):
        count = value.get(name)
        if count is not None:
            if type(count) is not int or not 0 <= count <= 50:
                raise ValueError("red-team-summary-invalid")
            result[name] = count
    if "search_mode" in value:
        if value["search_mode"] not in ("batch", "adaptive"):
            raise ValueError("red-team-summary-invalid")
        result["search_mode"] = value["search_mode"]
    if "stop_reason" in value:
        if value["stop_reason"] not in (
            "attempt-budget",
            "success",
            "inconclusive",
            "campaign-deadline",
            "probe-refinement-failed",
            "probe-generation-invalid",
            "probe-generation-failed",
            "probe-generation-incomplete",
        ):
            raise ValueError("red-team-summary-invalid")
        result["stop_reason"] = value["stop_reason"]
    if (
        result["assessment_complete"]
        and result.get("search_mode") == "adaptive"
        and (
            result.get("stop_reason") not in ("attempt-budget", "success")
            or result.get("inconclusive") != 0
        )
    ):
        raise ValueError("red-team-summary-invalid")
    early_success = (
        result.get("search_mode") == "adaptive"
        and result.get("stop_reason") == "success"
        and result.get("successes", 0) > 0
        and 0 < result.get("records", 0) <= result.get("requested_probes", 0)
    )
    if returncode != 0:
        result["error_code"] = "worker-incomplete"
    if result["assessment_complete"] and (
        result.get("records", 0) == 0
        or (result.get("records") != result.get("requested_probes") and not early_success)
        or sum(result.get(name, -100) for name in ("successes", "failures", "inconclusive"))
        != result["records"]
    ):
        raise ValueError("red-team-summary-invalid")
    if value.get("recovered") is True:
        result["recovered"] = True
        result.pop("error_code", None)
    return result


def red_team_run(
    config_path, output, python, *, cancelled=None, description=None, success_criteria=None
):
    cancelled = cancelled or Event()
    raw = read_regular_input(config_path, limit=65536, private=True)
    config = json.loads(raw)
    if not isinstance(config, dict):
        raise ValueError("red-team-config-invalid")
    if not isinstance(config.get("assessment", {}), dict):
        raise ValueError("red-team-config-invalid")
    if description is not None:
        config.setdefault("assessment", {})["description"] = description
        config["assessment"]["success_criteria"] = success_criteria or description
    elif success_criteria is not None:
        config.setdefault("assessment", {})["success_criteria"] = success_criteria
    assessment = config.get("assessment", {})
    if not isinstance(assessment, dict):
        raise ValueError("red-team-config-invalid")
    budget = assessment.get("campaign_seconds", 600)
    if type(budget) is not int or not 1 <= budget <= 600:
        raise ValueError("red-team-budget-invalid")
    environment = worker_environment(config)
    # Preflight validates the complete library schema, resolves model names and
    # redacts known credentials before any configuration is persisted or called.
    try:
        validation = _invoke(
            python,
            "validate",
            deadline=time.monotonic() + 20,
            cancelled=cancelled,
            environment=environment,
            data=json.dumps(config).encode(),
        )
    except (OSError, ValueError, AttemptStopped):
        raise ValueError("red-team-environment-or-input-invalid") from None
    if validation.returncode:
        raise ValueError("red-team-environment-or-input-invalid")
    validated = json.loads(validation.stdout)
    if not is_release_ineligible(validated.get("release_eligible")) or not isinstance(
        validated.get("config"), dict
    ):
        raise ValueError("red-team-validation-invalid")
    output.mkdir(mode=0o700, exist_ok=False)
    store = EvidenceStore(output, create=False)
    config_ref = store.persist_json(validated["config"])
    private_config = store.root / (config_ref.removeprefix("sha256:") + ".json")
    start_ref = store.persist_json(
        {
            "mode": "description-driven-red-team",
            "config_ref": config_ref,
            "assessment_complete": False,
            **RELEASE_INELIGIBLE,
        }
    )
    try:
        result = _invoke(
            python,
            "run",
            deadline=time.monotonic() + budget,
            cancelled=cancelled,
            environment=environment,
            config=private_config,
            output=store.root / "assessment",
        )
        summary = _summary(result.stdout, result.returncode)
    except (OSError, ValueError, AttemptStopped) as stopped:
        summary = {
            "mode": "description-driven-red-team",
            "assessment_complete": False,
            "error_code": "interrupted-or-worker-failed",
            **RELEASE_INELIGIBLE,
        }
        if isinstance(stopped, AttemptStopped):
            # A stop (deadline, cancel, output limit) SIGKILLs the worker group
            # before its clean-exit export, dropping every in-memory record. The
            # fsync'd stage journal survives, so re-export it with the native
            # recover op (no model calls) rather than reporting a blank failure.
            try:
                recovered = red_team_recover(output, python)
            except (OSError, ValueError):
                recovered = None
            if recovered is not None and recovered.get("recovered") is True:
                # Schema note: a recovered summary intentionally carries the
                # `recovered` flag instead of error_code — _summary drops
                # error_code for recovered: true, and red_team_recover runs
                # its output through that same validator.
                summary = recovered
    summary["start_ref"] = start_ref
    summary["config_ref"] = config_ref
    summary["summary_ref"] = store.persist_json(summary)
    return summary


def red_team_recover(output, python):
    store = EvidenceStore(output, create=False)
    try:
        result = _invoke(
            python,
            "recover",
            deadline=time.monotonic() + 30,
            cancelled=Event(),
            environment=worker_environment({}),
            output=store.root / "assessment",
        )
        summary = _summary(result.stdout, result.returncode)
    except (OSError, ValueError, AttemptStopped):
        summary = {
            "mode": "description-driven-red-team",
            "assessment_complete": False,
            "recovered": False,
            "error_code": "recovery-failed",
            **RELEASE_INELIGIBLE,
        }
    summary["summary_ref"] = store.persist_json(summary)
    return summary
