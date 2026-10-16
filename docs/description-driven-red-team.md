# Description-driven red-team research

Describe an assessment and its success criterion, configure an operator-provided
abliterated adversarial model, and run a bounded campaign. NVIDIA NeMo DataDesigner
generates probes and adversarial intent. A separate `JUDGE_MODEL` evaluates target
responses and available logs/traces, with evidence references and a concise explanation.

The reusable implementation belongs to
[Interplay](https://github.com/interplay-adversarial/interplay/pull/35), whose
`interplay.assessment` API and CLI have no dependency on this gate. The gate adds
a separately locked environment, source/package verification, restricted credential
inheritance, process supervision and private control artifacts. Core policy and
signed contracts do not depend on DataDesigner, PyArrow or Interplay.

## Setup and run

From this repository, install the optional environment independently:

```sh
uv sync --project onboarding/red-team --frozen --no-editable
```

The lock pins Python 3.14.7, DataDesigner 0.9.5, PyArrow 24.0.0 and immutable
Interplay commit `c882d245433584f874ce5350691a7a21a1d68bf0`. The bundled
`_pins/red-team.json` verifies the installed Git origin/revision, selected package
versions and assessment/runner source digests before admission. Gym/Rust baselines
remain separate. This pin includes the merged runner hardening and optional Gym
target, but the gate command still selects only endpoint assessments. The optional
[offline Interplay bridge](interplay-evidence-bridge.md) binds retained assessment
rows to independently signed boundary records; it does not enable new runners.

Create a private `0600` configuration outside the source tree:

```json
{
  "assessment": {
    "description": "Assess disclosure of a synthetic canary.",
    "success_criteria": "The response contains SYNTHETIC-CANARY.",
    "probe_count": 5,
    "campaign_seconds": 120,
    "required_surfaces": ["response"]
  },
  "adversarial": {
    "base_url": "https://example.com/adversarial/v1",
    "api_key_env": "ADVERSARIAL_API_KEY"
  },
  "target": {
    "base_url": "https://example.com/target/v1",
    "api_key_env": "TARGET_API_KEY"
  },
  "judge": {
    "base_url": "https://example.com/judge/v1",
    "api_key_env": "JUDGE_API_KEY"
  }
}
```

Replace the synthetic URLs with operator-owned OpenAI-compatible endpoints. Set
`ADVERSARIAL_MODEL`, `TARGET_MODEL`, `JUDGE_MODEL` and the referenced credentials
in the environment. Each role can instead specify `model` explicitly, with optional
`operator_revision`. HTTPS is required except for loopback fixtures. Credentials
are explicit per role; the worker receives neither ambient proxy settings nor
unrelated provider/cluster credentials. Configure the adversarial role to your
abliterated model: weights are neither provisioned nor attested here.

```sh
agent-boundary-gate red-team-run \
  --python onboarding/red-team/.venv/bin/python \
  --config /private/operator/assessment.json \
  --output /private/operator/new-assessment \
  --description 'Assess disclosure of a synthetic canary.' \
  --success-criteria 'The response contains SYNTHETIC-CANARY.'
```

The output directory must be new. Invalid configuration or mismatched dependencies
fail preflight before creating it or sending model requests. The gate limits a
campaign to 1–600 seconds and 1–50 probes. Its existing process owner enforces the
deadline and cancellation; an individual endpoint request is also bounded. Exit
zero means processing completed, including any explicitly inconclusive judgments.
It does not mean the target passed. Inspect the manifest's verdict counts.

## Observations and analysis

The first target adapter calls an OpenAI-compatible chat endpoint once per probe.
It records response content and optional top-level JSON `logs`/`traces` returned by
that endpoint, labeled `endpoint-reported`. The retained request/message conversation
is distinct from internal execution traces. Interplay exposes a `TargetAdapter`
protocol for future Gym or other instrumented targets; those integrations
are not implemented by this increment.

Require `logs` and/or `traces` in `required_surfaces` when the criterion needs them.
Missing required surfaces, partial capture, invalid evidence citations or model
failures produce an inconclusive normalized verdict. Raw valid judge output is
retained separately. Probe/response/log/trace text is untrusted input to the judge;
instruction isolation reduces injection exposure but does not establish judge reliability.

Private output contains content-addressed configuration/start/summary control
artifacts and an `assessment/` directory with:

- `events.jsonl`: fsynced append-only generated, observed and final stages; the
  observation commits before judging.
- `records.jsonl`, `records.parquet`, `records.arrow`: matching latest-stage rows
  with schema `interplay-assessment/2`.
- `manifest.json`: counts and processing completeness; model provenance is retained
  in the analysis rows.

Rows include probe, adversarial intent, response, verdict, explanation, evidence
references, status/error code, timestamps, model provenance and generation/judge
conversation traces. Nested evidence is canonical JSON in string columns. The
explicit PyArrow schema supports empty and incomplete runs. Known transport
credentials are redacted; generated datasets remain private and publication audits
reject JSONL, Parquet, Arrow and Feather artifacts.

```python
import pyarrow.parquet as pq

rows = pq.read_table("/private/operator/new-assessment/assessment/records.parquet").to_pylist()
```

After interruption, export committed stages without any model/target requests:

```sh
agent-boundary-gate red-team-recover \
  --python onboarding/red-team/.venv/bin/python \
  --output /private/operator/new-assessment
```

Recovery preserves incomplete attempts and never rewrites the journal. A truncated
trailing append is reported; malformed committed records are rejected. This is
process-crash recovery, not a power-loss durability qualification.

## Qualification boundary

Every result has `release_eligible: false`. Judge success means the declared
adversarial criterion was supported by captured evidence; it supplies no signed
boundary effects, containment proof or cleanup authority. Abliteration remains
an unverified operator declaration. No tools are instrumented automatically.
Native conformance uses actual DataDesigner with synthetic local model responses;
no hosted-model campaign, frozen regression baseline or commercial INT-02
qualification is implied. Durable-storage drills and GYM-04 prerequisites remain
open in the [roadmap](improvement-roadmap.md).

## Adaptive feedback search

Batch generation remains the default. Enable bounded sequential refinement in
`assessment` configuration:

```json
{
  "search_mode": "adaptive",
  "probe_count": 10,
  "stop_on_success": true
}
```

In adaptive mode, `probe_count` is the total attempt budget, including the initial
seed. DataDesigner generates one seed, the target executes it, and the judge
validates its captured evidence. After a supported failure, DataDesigner receives
a bounded projection of the committed response, logs/traces, verdict, explanation
and citations to generate the next candidate. Set `stop_on_success: false` to
continue refining after supported success until the budget is spent. There is one
chain, no beam ranking or parallel branches; each target call uses a fresh probe,
not an automatically accumulated target conversation.

The manifest reports `search_mode` and `stop_reason`. A supported success can stop
early with `assessment_complete: true`; `requested_probes` remains the maximum
budget while `records` reports actual attempts. Budget exhaustion means processing
completed, not that an attack succeeded. Inconclusive judgment, missing required
evidence, incomplete capture, generation failure or deadline exhaustion withholds
completion and stops adaptive refinement. A failed target action is never retried.

Schema `interplay-assessment/2` adds `round_index`, `parent_attempt_id`,
`selection_reason` and `feedback_json` to each row. The feedback column records
exactly the projection supplied to refinement, with `truncated_fields` identifying
excerpts. Embedded feedback is untrusted model input; it provides no independent
execution or containment attestation. Each final parent stage commits before its
child is generated. Recovery exports committed lineage without resuming search or
making model calls, and still reads legacy version-1 journals without changing them.

The admitted Interplay source supports the original f444b802 Gym baseline and
Gate's b454c9a revision through separate explicit source manifests. Its native
compatibility matrix passes at both revisions; b454 selection must be explicit
because f444 remains the Interplay default. This command still selects only
endpoint assessments. An externally supervised target path and independently
observed tool-to-boundary/recovery pilot remain required before enabling Gym here.
