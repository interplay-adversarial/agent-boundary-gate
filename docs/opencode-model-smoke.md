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
  "model": "operator-selected-model",
  "timeout_seconds": 120
}
```

```sh
chmod 600 "$PRIVATE_PROVIDER_MANIFEST"
uv run --no-sync python -m scripts.opencode_smoke \
  --provider "$PRIVATE_PROVIDER_MANIFEST" \
  --output "$NEW_PRIVATE_SMOKE_DIRECTORY"
```

`model` is a bare model identifier exactly as the endpoint names it (for
example `qwen38-27b`), never a `"<provider>/<model>"` reference: the provider
half is always `agents.opencode_runtime.OPENCODE_PROVIDER_NAME` (`"gate"`), a
generated `@ai-sdk/openai-compatible` provider written to the run's own
`opencode.json`
(`agents.opencode_runtime.build_opencode_config`), authenticated with an
explicit `Authorization: Bearer {env:<api_key_env>}` header rather than the
SDK's own `apiKey` option. `{env:NAME}` is OpenCode's own config templating
syntax, substituted at run time, so the real credential is written to that
file only as a template reference, never as a literal value. The `apiKey`
option was tried first and confirmed, against a real self-hosted MaaS gateway
(2026-10-16), to produce an opaque server-side error regardless of model or
install/env state; an explicit header — a configuration already known to work
against the same endpoint — does not. `OPENCODE_DISABLE_AUTOUPDATE` is set so
the run cannot silently drift off the pinned version. Project-level config
loading is deliberately left enabled (not disabled, unlike an earlier version
of this script): it is how the generated `opencode.json` reaches OpenCode at
all.

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
attempt to establish any of PORT-01/GYM-03's real acceptance criteria on its
own: an `AgentAdapter` implementation that drives OpenCode through a case's
`tool_request` action does exist
([`OpenCodeAgentAdapter`](opencode-agent-adapter.md), sharing this script's
same install/config logic) but sandbox-native pairing and qualification
remain open regardless.
