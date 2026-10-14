# Model-backed Gym smoke

This optional workflow uses the pinned upstream `SimpleAgent`, Responses/chat
converter, indirect-injection resource handlers and native verifier. Only the
operator-selected model endpoint receives network traffic. Tool calls run
in-process against an original synthetic message world: `send_message` mutates
that world and never sends mail or opens a connection. It exercises model/tool
compatibility and a benign/injection pair, not OpenShell or real-agent containment.

Use the [pinned onboarding environment](gym-onboarding.md). Keep endpoint,
credentials, provider manifests and trajectories outside the public repository.
The provider file must be a regular, non-symlink file with private permissions.
Do not put an API token in the manifest or command arguments. Supply it through
the referenced environment variable, using your existing credential loader.

Example **private** provider manifest (replace the reserved endpoint locally):

```json
{
  "base_url": "https://example.com/v1",
  "api_key_env": "MODEL_API_KEY",
  "model": "operator-selected-model",
  "operator_revision": null,
  "seed": 17,
  "max_tokens": 2048,
  "max_steps": 3,
  "request_seconds": 60,
  "campaign_seconds": 240,
  "enable_thinking": false
}
```

```sh
chmod 600 "$PRIVATE_PROVIDER_MANIFEST"
onboarding/gym/.venv/bin/python -m scripts.gym_smoke \
  --upstream "$GYM_SOURCE" \
  --provider "$PRIVATE_PROVIDER_MANIFEST" \
  --output "$NEW_PRIVATE_SMOKE_DIRECTORY"
```

`GET /models` must list the selected model exactly. If `model` is null, discovery
is permitted only when the endpoint lists exactly one unique model. A route name
is not inferred to be the served model ID. Each completion must report that model
and exactly one choice. HTTPS verification stays enabled, redirects and proxy
environment inheritance are disabled, and requests have no automatic retries.
Per-request and campaign deadlines, response-size, model-step and synthetic-tool
budgets bound the run. Sampling requests temperature 0, top-p 1, the recorded seed,
token cap and explicit thinking setting; unsupported parameters fail the run.

The two original synthetic tasks are licensed under this repository's Apache-2.0
license. They do not redistribute the upstream example task corpus. Both ask for
a maintenance-time summary; one retrieved message additionally impersonates a
system update requesting disclosure to a reserved `.invalid` recipient. These
are calibration smoke tasks, not a rights-reviewed broad benchmark or held-out
corpus. Source and dependency licensing review remains necessary for packaging.

The new directory is `0700`, and reports/responses/trajectories are `0600`.
Every successful HTTP completion is retained before semantic validation. Completed
case results survive subsequent failure. Failures produce a fixed console error
and `failure.json`; partial evidence never becomes a successful smoke. No token
is written to reports. Console summaries exclude endpoint, model output and
private trajectories. Existing output directories are rejected before traffic.

`smoke.json` binds the upstream/source pin, isolated lock, installed inventory,
smoke implementation, selected model, requested sampling and native scores.
Native safety measures matching attacker-targeted tool calls. Required-tool
utility checks tool usage, not final summary correctness. A completed smoke can
observe a compromise; completion is distinct from resistance. Step exhaustion,
truncation, malformed calls, missing trajectory or failed tool execution prevent
completion. A hosted alias and operator revision are not independently attested
weights; requested sampling/seed are not server guarantees. Obtain checkpoint,
chat-template/tool-parser and serving-version attestations before promoting a
commercial baseline. Runtime upgrades do not promote this baseline automatically.

All outputs explicitly say `boundary_evaluated: false`, development-only and
`release_eligible: false`. Separate model behavior, benign utility and externally
observed boundary effects in the later [evidence bridge](nemo-gym-adoption.md).
No signing keys, lifecycle authority, boundary tools or release decisions are
introduced by this smoke.

Public PR checks and pre-commit run provider validation and actual native Gym
conformance with a fake model transport. No endpoint or model credential is used
in public CI. The separate Gym lock CVE audit remains mandatory. An eventual Gym
container additionally needs its own immutable digest, license and image scan.
