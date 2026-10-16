#!/bin/sh
# Creates the per-server .venv symlinks `gym eval run` expects at the repo root, all
# pointed at onboarding/gym's own already-synced .venv -- so Gym's `+skip_venv_if_present=true`
# (set unconditionally by adaptive_task_runner.py's _gym_eval_run) can skip its normal
# `uv pip install` step for each one. Without this, that install would try (and fail) to
# fetch `nemo-gym==<pinned version>` from PyPI -- our pin is a git-commit install, not a
# published release (see onboarding/gym/pyproject.toml).
#
# Scoped to this orchestrator's only supported combination today: the Harbor resources
# server and environment server are always named "harbor"/"single_agent_turn"
# (nemo_gym/tasks/harbor/materialize.py's RESOURCES_SERVER_IMPL/ENVIRONMENT_SERVER_IMPL),
# and adaptive_task_runner.py always passes --model-type openai_model. Pass a different
# agent name as $1 if your config's `agent` isn't the default opencode_agent.
#
# Run once from the repo root before the first `adaptive-task-run` (or manual `gym eval
# run`) invocation; re-running is a no-op (idempotent).
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
GYM_VENV="$REPO_ROOT/onboarding/gym/.venv"
AGENT_NAME="${1:-opencode_agent}"

if [ ! -x "$GYM_VENV/bin/python" ]; then
    echo "setup-server-venvs.sh: $GYM_VENV is not synced -- run" >&2
    echo "  uv sync --project onboarding/gym --frozen --no-editable" >&2
    echo "first." >&2
    exit 1
fi

for pair in \
    "resources_servers/harbor" \
    "responses_api_agents/$AGENT_NAME" \
    "environment_servers/single_agent_turn" \
    "responses_api_models/openai_model"; do
    mkdir -p "$REPO_ROOT/$pair"
    rm -rf "$REPO_ROOT/$pair/.venv"
    ln -s "$GYM_VENV" "$REPO_ROOT/$pair/.venv"
    echo "linked $pair/.venv -> onboarding/gym/.venv"
done
