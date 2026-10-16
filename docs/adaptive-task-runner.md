# Adaptive task runner

A retry/advance/abandon loop over [NeMo Gym](nemo-gym-adoption.md)'s Harbor
coding-task format: drive an agent (OpenCode, via Gym's existing
`opencode_agent` wrapper) through a task, score the attempt against Gym's own
reward-profiling output, and decide whether to retry with an adapted
instruction, advance to the next task, or abandon the run.

**This is a separate, unrelated capability from this repo's red-team/boundary-
gate work.** It carries no gate or release authority — its report is a plain
JSON summary, not a signed record. It does not touch `execute_probe`, OpenShell
policy enforcement, or any of the PORT-01 OpenCode red-team work; it only
happens to reuse the same OpenCode agent and, optionally, the same kind of
OpenShell sandbox gateway as a place to run an agent's generated code.

Gym itself holds no state across its own CLI invocations: `gym eval run` and
`gym eval profile` are one-shot calls over files on disk. The retry/advance/
abandon decision loop, and the resources server that actually executes a
Harbor task (`onboarding/gym/harbor_extra_root/resources_servers/harbor/`),
are both new code in this repo — Gym's own Harbor task-loading machinery
generates a run config that expects a resources server named `harbor`, but no
such implementation ships upstream (checked against both our pinned commit and
upstream's current `main`).

## Prerequisites

- `onboarding/gym`'s pinned environment synced: `uv sync --project onboarding/gym --frozen --no-editable`.
- An OpenShell gateway reachable from this machine, if you intend to run tasks
  against a real sandbox rather than just reading this doc. Any
  [NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) gateway works,
  including the local Docker-compose quickstart in NeMo Gym's own
  `nemo_gym/sandbox/providers/openshell/README.md`. **Do not check a real
  gateway hostname, workspace name or certificate path into this repo** — every
  example below uses placeholder values and expects the real ones to come from
  your own environment or an untracked `.env` file.
- A model endpoint OpenCode can call (any OpenAI-compatible endpoint; see
  [`responses_api_agents/opencode_agent`](../onboarding/gym/.venv/lib/python3.14/site-packages/responses_api_agents/opencode_agent/README.md)
  once `onboarding/gym` is synced).

## One-time setup

The new resources server and OpenShell provider config live under
`onboarding/gym/harbor_extra_root/`, discovered via Gym's `--search-dir` flag
(every invocation below passes `--search-dir onboarding/gym/harbor_extra_root`)
rather than being installed into the pinned `nemo-gym` package:

```
onboarding/gym/harbor_extra_root/
  resources_servers/harbor/app.py                         # the new resources server
  nemo_gym/sandbox/providers/openshell_remote/configs/openshell_remote.yaml   # provider config
```

The provider config (`openshell_remote.yaml`) reads every connection detail
from environment variables, with safe, non-identifying fallbacks (matching
Gym's own built-in `openshell` config's local-compose defaults):

| Variable | Default | Meaning |
| --- | --- | --- |
| `OPENSHELL_GATEWAY_ENDPOINT` | `localhost:8080` | `host:port` of the gateway's gRPC control plane |
| `OPENSHELL_GATEWAY_WORKSPACE` | `default` | gateway workspace that owns the sandboxes |
| `OPENSHELL_GATEWAY_BEARER_TOKEN` | unset (plaintext) | OIDC bearer token, for an authenticated gateway |
| `OPENSHELL_GATEWAY_TLS_CA_PATH` | unset (plaintext) | CA cert path, for an mTLS gateway |
| `OPENSHELL_GATEWAY_TLS_CERT_PATH` | unset (plaintext) | client cert path |
| `OPENSHELL_GATEWAY_TLS_KEY_PATH` | unset (plaintext) | client key path |

Set these to your own gateway's details before running anything for real. A
gateway may be shared with other workloads in your own environment —
`exec.concurrency: 4` in the provider config is a deliberately conservative
placeholder, not a tuned value; raise it only once you know what else the
gateway serves.

## The example task

`onboarding/gym/harbor-tasks/demo-add-fn/` is a minimal, fully working Harbor
task, small enough to read in one sitting:

- `task.toml` — declares a prebuilt `python:3.12-slim` image (no Dockerfile
  build: Gym's loader explicitly refuses to build one) and timeouts.
- `instruction.md` — tells the agent `/workspace/calc.py` has a one-line bug in
  `add(a, b)` and to make `bash tests/test.sh` pass.
- `tests/test.sh` — writes the buggy `calc.py` itself on first run (so the demo
  needs no custom published image), then runs three independent checks against
  `add()` and writes `{"reward": <passed>/<total>, "tests_passed": <passed>,
  "tests_total": <total>}` to `/logs/verifier/reward.json`. This project's own
  convention: prefer `reward.json`'s `"reward"` key over a bare float in
  `reward.txt` when both exist (Harbor's own docs specify the two file names
  but no JSON schema); `tests_passed`/`tests_total` are optional and drive the
  "no progress" detection described below.

## Running it by hand first

Prove the resources server and provider config work in isolation before
trying the full retry loop — this is the fastest way to tell "my gateway/model
setup is wrong" apart from "the orchestrator is wrong". Replace every
placeholder below (`openshell.example.internal:443`, `your-model-name`,
`http://localhost:8000/v1`, the cert paths) with your own gateway and model
details:

```sh
export OPENSHELL_GATEWAY_ENDPOINT=openshell.example.internal:443
export OPENSHELL_GATEWAY_TLS_CA_PATH=/path/to/your/ca.crt
export OPENSHELL_GATEWAY_TLS_CERT_PATH=/path/to/your/client.crt
export OPENSHELL_GATEWAY_TLS_KEY_PATH=/path/to/your/client.key

onboarding/gym/.venv/bin/gym eval run onboarding/gym/harbor-tasks/demo-add-fn \
  --agent opencode_agent --sandbox openshell_remote \
  --search-dir onboarding/gym/harbor_extra_root \
  --model your-model-name --model-url http://localhost:8000/v1 \
  --model-api-key "$YOUR_MODEL_API_KEY" \
  --output /tmp/demo-attempt-1/rollouts.jsonl -v

onboarding/gym/.venv/bin/gym eval profile \
  --inputs results/harbor/demo-add-fn/tasks.jsonl \
  --rollouts /tmp/demo-attempt-1/rollouts.jsonl
```

Check `/tmp/demo-attempt-1/rollouts.jsonl` for a `reward` field, and the
printed `gym eval profile` summary for a completion percentage. A `reward` of
`1.0` means OpenCode fixed `calc.py`; `0.0` means it didn't (or didn't get the
chance — check `test_output` in the rollout row first).

## Running the full retry loop

The orchestrator (`agent-boundary-gate adaptive-task-run`) takes a JSON config
and an output directory. Every value it needs can come from **three places**,
and you can mix them freely:

1. **A JSON config file** (`--config`) — everything that isn't a secret or a
   gateway connection detail: which task folders to run, the model, attempt
   budgets, thresholds.
2. **Exported environment variables** — the `OPENSHELL_GATEWAY_*` connection
   details above, and the model API key (named by `model_api_key_env` in the
   config, read by name so the key's *value* never appears in the config file
   or in any persisted evidence).
3. **An untracked `.env` file** (`--env-file`), as a convenience instead of
   exporting those same environment variables by hand every run. It only sets
   a variable that isn't already exported (`os.environ.setdefault`), so an
   explicit `export` always wins.

### 1. Write a config file

Replace `your-model-name` / `http://localhost:8000/v1` with your own model and
endpoint:

```json
{
  "gym_executable": "onboarding/gym/.venv/bin/gym",
  "harbor_extra_root": "onboarding/gym/harbor_extra_root",
  "task_folders": ["onboarding/gym/harbor-tasks/demo-add-fn"],
  "agent": "opencode_agent",
  "sandbox_provider": "openshell_remote",
  "model": "your-model-name",
  "model_url": "http://localhost:8000/v1",
  "model_api_key_env": "YOUR_MODEL_API_KEY",
  "max_attempts_per_task": 3,
  "success_reward_threshold": 1.0,
  "attempt_seconds": 900,
  "profile_seconds": 120
}
```

Save it somewhere private (mode `0600`) — `adaptive-task-run` refuses a
world/group-readable config file. `task_folders` can list more than one task;
they run in order, and the run stops early if a task's every attempt was a
pure infra failure (see "Interpreting results" below).

### 2a. Run it with exported environment variables

```sh
export OPENSHELL_GATEWAY_ENDPOINT=openshell.example.internal:443
export OPENSHELL_GATEWAY_TLS_CA_PATH=/path/to/your/ca.crt
export OPENSHELL_GATEWAY_TLS_CERT_PATH=/path/to/your/client.crt
export OPENSHELL_GATEWAY_TLS_KEY_PATH=/path/to/your/client.key
export YOUR_MODEL_API_KEY=...

agent-boundary-gate adaptive-task-run \
  --config adaptive-task-runner-config.json \
  --output /tmp/adaptive-run-1
```

### 2b. Or run it with a `.env` file instead

```sh
cat > .env.adaptive-task-runner <<'EOF'
OPENSHELL_GATEWAY_ENDPOINT=openshell.example.internal:443
OPENSHELL_GATEWAY_TLS_CA_PATH=/path/to/your/ca.crt
OPENSHELL_GATEWAY_TLS_CERT_PATH=/path/to/your/client.crt
OPENSHELL_GATEWAY_TLS_KEY_PATH=/path/to/your/client.key
YOUR_MODEL_API_KEY=...
EOF
chmod 600 .env.adaptive-task-runner

agent-boundary-gate adaptive-task-run \
  --config adaptive-task-runner-config.json \
  --output /tmp/adaptive-run-1 \
  --env-file .env.adaptive-task-runner
```

`.env.adaptive-task-runner` (or whatever you name it) should never be
committed — add it to your local `.gitignore` if it isn't already covered.
The parser is intentionally simple (`KEY=VALUE` lines, `#` comments, optional
quotes around the value) — no shell expansion, no command substitution.

### 2c. Force a retry, to see the adapted-instruction path

Set `success_reward_threshold` above `1.0` in the config once (so the first
attempt can never "succeed"), run it, and inspect
`/tmp/adaptive-run-1/attempts/demo-add-fn/demo-add-fn-attempt-2/instruction.md`
— it should contain the original instruction plus the first attempt's
reward and a tail of its test output.

## Interpreting results

The command prints a JSON report and exits `0` if every task reached
`advance` (never `abandon`), else `2`:

```json
{
  "tool": "adaptive-task-runner",
  "completed": true,
  "tasks": {
    "demo-add-fn": [
      {"attempt_number": 1, "reward": 0.33, "tests_passed": 1, "tests_total": 3, "mask_sample": false, "decision": "retry", "...": "..."},
      {"attempt_number": 2, "reward": 1.0, "tests_passed": 3, "tests_total": 3, "mask_sample": false, "decision": "advance", "...": "..."}
    ]
  },
  "report_ref": "sha256:..."
}
```

- `reward` — from Gym's own reward-profiling output (`gym eval profile`'s
  `rollout_infos[].reward`), not a raw pass/fail.
- `tests_passed` / `tests_total` — optional, only present when the task's
  `test.sh` reports them (see "Structured progress signal" below). `null` for
  a task that only reports a bare `reward`.
- `mask_sample: true` — the reward is **not** a valid measurement of the
  agent's attempt; something in the infrastructure failed (a lost sandbox
  session, a gateway error, a crashed `gym` subprocess), not the agent's code.
  `failure_kind` will start with `harbor:` for these.
- `decision` — `retry` (another attempt follows, with an adapted
  instruction), `advance` (success, or budget exhausted on a real failure —
  move to the next task), `abandon` (every attempt on this task was
  infra-masked — the whole run stops here rather than burning the rest of its
  budget against what looks like a broken gateway).
- `rollouts_ref` / `reward_profile_ref` / `report_ref` — `sha256:...`
  references into the output directory's `EvidenceStore`. Fetch the full
  underlying JSON with:
  ```python
  from pathlib import Path
  from agent_boundary_gate.evidence import EvidenceStore
  store = EvidenceStore(Path("/tmp/adaptive-run-1"), create=False)
  print(store.read("sha256:...").decode())
  ```

## Structured progress signal and escalation

By default, the retry/advance/abandon decision looks only at `reward` and
`mask_sample` — it never reads log/test-output text. But a task's `test.sh`
can optionally report `tests_passed`/`tests_total` alongside `reward` in
`reward.json` (as the example task does, splitting its check into three
independent assertions). Gym's own reward-profiling keeps every numeric field
of a verify response, not just `reward`, so these two integers flow through
to `rollout_infos[]` for free and land on each attempt's `AttemptRecord` —
no orchestrator change needed for a task author to opt in.

When a task does report them, the orchestrator compares `tests_passed`
across the last two (non-masked) attempts. If it's unchanged — the same
number of checks passing twice in a row — the next retry's instruction is
escalated: instead of just repeating "here's what failed, try again," it's
told the previous approach made no further progress and to try a
fundamentally different implementation strategy, not a small variation. This
only changes the retry's *instruction*; it does not change whether the loop
retries, advances, or abandons (budget and `success_reward_threshold` still
govern that) — it's purely about nudging *how* the agent tries next, which
is the thing a free-text log can't tell you reliably without reading it.

A task that only reports a bare `reward` (or a `reward.txt` float) and has no
judge configured (below) is completely unaffected: `tests_passed`/
`tests_total` stay `null`, `_is_stuck` always returns `False` for it, and
every retry gets the same plain feedback as before this feature existed.

One thing this still does **not** do, on purpose: it doesn't shorten the
attempt budget early just because the agent looks stuck. An "abandon this
task after two stuck attempts even with budget left" rule would be a small,
separate change to `fixed_budget_should_continue` — the stuck signal only
ever changes the next retry's *wording*, never the retry/advance/abandon
timing itself.

### Judge fallback, for tasks with no structured signal

A task that can't easily report `tests_passed`/`tests_total` (a single
pass/fail check, or a task you don't control the `test.sh` of) can instead
have the orchestrator classify progress from the raw `test_output`/
`failure_reason` text, via a judge model call. Opt in by setting
`judge_model` and `judge_url` in the config (plus `judge_api_key_env` if the
judge endpoint needs auth) — a separate role from `model`/`model_url` (the
agent under test), matching this project's existing convention of distinct
adversarial/target/judge model roles elsewhere:

```json
{
  "...": "... the rest of the config as above ...",
  "judge_model": "your-judge-model-name",
  "judge_url": "http://localhost:8000/v1",
  "judge_api_key_env": "YOUR_JUDGE_API_KEY"
}
```

When both attempts being compared have no structured signal, `_is_stuck`
sends their raw failure text to the judge and asks for exactly one
classification word: `same_failure`, `different_failure`, `closer`, or
`resolved`. Only `same_failure` counts as "stuck." The structured numeric
comparison always takes priority when both attempts report it — the judge is
a fallback for when there's nothing numeric to compare, never a second
opinion that could override the numeric signal. The call uses Python's
stdlib `urllib` (no new dependency, no `nemo_gym`/`openai` SDK import) and
never raises: a network error, a malformed response, or an unrecognized
classification word all just mean "no signal," identical to having no judge
configured at all.

## Writing your own Harbor task

Minimum required files: `task.toml` (at least `[environment] docker_image =
"..."`), `instruction.md`, `tests/test.sh`. `test.sh` must write a numeric
reward to `/logs/verifier/reward.json` (`{"reward": <float>}`, this project's
convention) or `/logs/verifier/reward.txt` (a bare float). There is no
Dockerfile **build** support — only a prebuilt `docker_image` — so a task
needing custom setup should do it at the top of `test.sh`, as the example task
does.

Optionally add `"tests_passed"`/`"tests_total"` integers alongside `"reward"`
in `reward.json` (only possible via the JSON form, not `reward.txt`) to get
the "no progress" escalation described above — worth doing whenever a task
has more than one independent sub-check, since a single pass/fail reward
can't distinguish "made partial progress" from "no progress at all."

## Known limits (v1)

- `[verifier] environment_mode = "separate"` (a second sandbox just for
  verification) is not supported — the resources server returns `422`.
- `HarborEnvironment`'s `mcp_servers`/`skills_dir` are not forwarded to the
  agent.
- The stop rule is a fixed attempt budget
  (`fixed_budget_should_continue` in `adaptive_task_runner.py`), not a
  no-progress check — a deliberate placeholder, isolated behind one function.
- No live-cluster CI job exercises this against a real OpenShell gateway (it
  would consume shared gateway capacity on every push/PR for an unrelated
  workload); the manual sequence above is the verification path for now.
- No crash-mid-attempt resume: a killed `adaptive-task-run` process is simply
  re-run with the same `--output` directory (each attempt's evidence is
  content-addressed and idempotent to re-persist).

## Troubleshooting

- **`failure_kind: "harbor:verifier_infra_error"` on every attempt** — the
  resources server itself is failing (sandbox never started, upload/exec
  failed, the reward file was never written). Check
  `/tmp/<attempt>/rollouts.jsonl`'s `failure_reason` field, and confirm the
  gateway is reachable independently of this tool first (the
  [NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) CLI's own
  `gateway list`/`sandbox list` commands are the quickest check — a healthy
  gateway should respond, even with zero sandboxes running).
- **`gym eval run` can't find `opencode_agent` or the `harbor` resources
  server** — confirm `--search-dir onboarding/gym/harbor_extra_root` is
  actually being passed (the orchestrator always passes it; a manual `gym`
  invocation must include it too).
- **A config file is rejected outright** — `adaptive-task-run` requires the
  config file to be a private regular file (mode `0600`, owned by you); loosen
  permissions and it will refuse to read it.
