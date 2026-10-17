# OpenCode agent adapter

`agent_boundary_gate.agents.opencode.OpenCodeAgentAdapter` is a real, unqualified
implementation of the `AgentAdapter` protocol (`agents/__init__.py`) that drives
a real local OpenCode CLI session for a case's `tool_request` action. It is the
first concrete step past the generic conformance work (`agents/fixture.py`,
`tests/test_agent_adapter_conformance.py`); PORT-01/GYM-03's actual sandbox-
native pairing and qualification remain open. See the
[improvement roadmap](improvement-roadmap.md) for what is and is not covered.

## Completion is proven by a receipt, not by parsing OpenCode's session database

`request_tool` writes one generated OpenCode custom tool
(`.opencode/tool/gate-tool-<digest>.ts`, named from a digest of `action.tool_id`
rather than the identifier itself, since the identifier pattern allows `/` and
`.` and would otherwise become an unsafe path component) into a fresh temporary
project directory, prompts a headless `opencode run` session to call that tool
with the case's `control` value, and afterward checks for an attempt-tagged
receipt file the tool's own `execute()` body writes — the same idiom this
repository already uses for its frozen probes (`probes.py`'s `PROBE` constant;
`backends/fixture.py`'s `"agent-boundary-gate-probe-complete:" + attempt_id`).

This is deliberate, not an oversight: OpenCode's own session SQLite schema
(tool-call part shape, `type` discriminator, whether a tool call is one row
updated in place or several) is not verifiable at the exact pinned CLI version.
Research on 2026-10-16 found the schema in OpenCode's public source
(`packages/schema/src/session-message.ts`), but that repository's own release
tags are `v2.x`, which do not align with the pinned npm `opencode-ai`
`1.17.11` — relying on undocumented internals at an unconfirmed version would
be exactly the kind of fragility this repository avoids everywhere else.
Depending instead on a receipt this adapter's own generated code writes means
correctness never depends on OpenCode's internal format at all.

What this does **not** prove: that OpenCode's underlying model reliably calls
the generated tool when prompted to. That is live model behavior, verified
only by actually running it (see below), never by these deterministic tests.

## Authentication is an explicit header, not the SDK's `apiKey` option

`request_tool` writes its own generated `opencode.json`
(`agents/opencode_runtime.build_opencode_config`) registering a custom
`@ai-sdk/openai-compatible` provider (`agents/opencode_runtime.OPENCODE_PROVIDER_NAME`,
`"gate"`) with `options.headers.Authorization` set to
`"Bearer {env:<api_key_env>}"` — OpenCode's own config templating syntax,
substituted at run time, so the real credential is written to that file only
as a template reference, never a literal value. `-m gate/<bare-model>`
(`opencode_model_reference`) selects it; `model` in `OpenCodeProvider` is
always a bare identifier (e.g. `qwen38-27b`), never a `"<provider>/<model>"`
reference into one of OpenCode's built-in providers.

This replaced an earlier version of this adapter that relied on OpenCode's
built-in provider via `OPENAI_BASE_URL`/`OPENAI_API_KEY` environment variables
and the SDK's own `apiKey` option. Confirmed by live testing against a real
self-hosted MaaS gateway (2026-10-16): `apiKey` produced an opaque
`UnknownError` server-side response regardless of model choice or
install/environment state, while an explicit `Authorization` header — a
configuration already confirmed working against the same endpoint by another
client — did not. The `{env:NAME}` substitution mechanism itself was verified
separately against a local synthetic mock endpoint with a fake credential
before relying on it against the real one. A corollary: project-level config
loading must stay enabled (earlier versions disabled it for a hermetic run,
before this adapter needed to deliver its own project-level `opencode.json`
at all) — it is how this generated config reaches OpenCode.

## Readiness is cheap and read-only

`readiness()` only checks that the pinned OpenCode binary
(`agents/opencode_runtime.OPENCODE_VERSION`) is already installed and reports
that exact version (`is_opencode_ready`) — it never installs. Installing is a
separate, explicit, potentially slow network operation
(`agents/opencode_runtime.ensure_opencode`, also used by
[the model smoke](opencode-model-smoke.md)); running it inside a readiness
check would risk blowing `lifecycle.run_attempt`'s short readiness budget
(seconds, not install time). Run `ensure_opencode` once, as separate operator
setup, before composing this adapter into a live attempt.

## Construction

```python
from pathlib import Path
from agent_boundary_gate.agents.opencode import OpenCodeAgentAdapter
from agent_boundary_gate.agents.opencode_runtime import OpenCodeProvider, ensure_opencode, OPENCODE_VERSION

provider = OpenCodeProvider(
    base_url="https://example.com/v1",
    api_key_env="MODEL_API_KEY",
    model="operator-selected-model",
)
install_dir = Path("/private/path/opencode-cli")
ensure_opencode(OPENCODE_VERSION, install_dir, timeout_seconds=120)  # once, out of band

import os
credential = os.environ[provider.api_key_env]
agent = OpenCodeAgentAdapter(provider, credential, install_dir)
```

The credential is resolved by the caller from the named environment variable
and passed explicitly, never read from `os.environ` deep inside the adapter —
the same discipline the model smoke's `main()` already follows, and it keeps
the adapter fully unit-testable without mutating process environment state.

## What is still unverified

- A real model has never actually been driven through this adapter's
  `request_tool` by this repository's own CI or by an automated agent — doing
  so needs a live, operator-held credential. Prove the CLI/config/session
  plumbing works first with [the model smoke](opencode-model-smoke.md); this
  adapter adds the tool-call-routing layer on top of exactly that plumbing
  (`opencode_runtime.py` is shared by both).
- Whether a given model reliably calls the generated tool, rather than
  refusing, calling something else, or answering in prose instead, is model
  behavior this adapter cannot and does not control for — a non-completion
  (`request_tool` returning `False`) is a legitimate, fail-closed outcome, not
  necessarily a bug.
- Sandbox-native pairing (running inside an operator-owned boundary backend's
  sandbox rather than a local temporary directory) is not implemented here at
  all.
