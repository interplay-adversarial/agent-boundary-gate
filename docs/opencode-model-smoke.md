# OpenCode model-backed smoke

This optional workflow proves that the pinned OpenCode CLI installs, is
configured against an operator-selected model endpoint, completes one headless
local run and that its session database can be read back afterward. It is
plumbing verification for PORT-01/GYM-03, not an agent pairing: there is no
sandbox, no boundary backend, no tool-request routing and no case/observer
involvement. See the [improvement roadmap](improvement-roadmap.md)'s PORT-01
row for what remains before any of that exists.

OpenCode is pinned at `1.17.11` (`scripts/opencode_smoke.py`'s `OPENCODE_VERSION`,
chosen to match the same version NeMo Gym's own `opencode_agent` integration
pins independently; the two pins are tracked separately and are not required to
move together). It installs into a local, non-global npm prefix inside the
output directory rather than the system prefix, which is commonly read-only for
an unprivileged user.

Keep endpoint, credentials and reports outside the public repository, the same
as the [Gym model smoke](gym-model-smoke.md). The provider manifest must be a
regular, non-symlink file with private permissions. Do not put an API token in
the manifest. Supply it through the referenced environment variable.

Example **private** provider manifest (replace the reserved endpoint locally):

```json
{
  "base_url": "https://example.com/v1",
  "api_key_env": "MODEL_API_KEY",
  "model": "openai/operator-selected-model",
  "timeout_seconds": 120
}
```

```sh
chmod 600 "$PRIVATE_PROVIDER_MANIFEST"
uv run --no-sync python -m scripts.opencode_smoke \
  --provider "$PRIVATE_PROVIDER_MANIFEST" \
  --output "$NEW_PRIVATE_SMOKE_DIRECTORY"
```

`model` is OpenCode's own `<provider>/<model>` reference for its stock
`openai`-compatible provider (for example `openai/qwen38-27b`), not a bare model
name. No custom `opencode.json` is written; the run relies on OpenCode's stock
`OPENAI_BASE_URL`/`OPENAI_API_KEY` environment fallback, the same one Gym's own
agent uses when it is not routing through Gym's internal model server.
`OPENCODE_DISABLE_AUTOUPDATE`/`OPENCODE_DISABLE_PROJECT_CONFIG` are set so the
run cannot silently drift off the pinned version or pick up a stray local
project config; unlike Gym's own sandboxed session path this is not the
default for a local run, so the smoke script sets it explicitly.

The new directory is `0700`; `smoke.json`/`failure.json` are `0600`. A
successful run's `smoke.json` records the process exit code, whether the
session database exists and whether it contains at least one non-empty
assistant text part (`smoke_complete` requires both exit code zero and that
text). Raw session content, model output and the credential itself are never
written to the report. The install/config/parse logic is covered by
deterministic unit tests (`tests/test_opencode_smoke.py`) using an injected
fake subprocess runner; the live CLI call itself is exercised only by running
this script by hand, the same as `gym_smoke`'s live model traffic.

All reports explicitly say `boundary_evaluated: false`, `qualification:
development-only` and `release_eligible: false`. This smoke cannot and does not
attempt to establish any of PORT-01/GYM-03's real acceptance criteria: there is
still no `AgentAdapter` implementation that drives OpenCode (see
`agents/fixture.py`'s loopback fixture and `tests/test_agent_adapter_conformance.py`
for what a conforming adapter must satisfy), and no mechanism routes a case's
`tool_request` action through OpenCode's own tool-calling at all. That routing
is expected to need the `.opencode/tools/*.ts` custom-tool mechanism and is
unscoped, separate follow-up work.
