# Offline Interplay attempt and boundary evidence correlation

`agent_boundary_gate.interplay_bridge` pairs one retained Interplay assessment
snapshot with an independently supplied Gate dispatch and authenticated records.
It imports neither Interplay nor Gym, invokes no providers and executes no tools.
This is the first offline increment of
[Interplay BOUNDARY-01](https://github.com/interplay-adversarial/interplay/issues/64).
Gate-side [issue #56](https://github.com/interplay-adversarial/agent-boundary-gate/issues/56)
tracks implementation. The bounded live tool-to-boundary pilot remains pending.

## Trust and identity

The collector owns `InterplayAttemptPlan`, `Dispatch`, trusted verifier keys and
the private `EvidenceStore` outside the workload's identity. Before execution,
bind the Interplay campaign and attempt IDs to the dispatch's `run_id` and
`attempt_id`, respectively. Bind the exact target digest, dispatch digest
(including cases, policies and separate component pins), and SHA-256 digests of
the UTF-8 probe and `provenance_json` string. Do not normalize those strings.
After collection, persist exactly one final assessment row and attach its
content digest as `record_ref`. The trusted collector must select that snapshot;
do not silently choose among duplicate callbacks or latest-wins journal stages.

A plan inferred only from returned model/adapter output does not establish
identity. These bindings express the collector's association, not an attestation
of hosted model weights, causal attribution or observer deployment isolation.
Never turn endpoint-reported logs, target tool replies, Gym environment callbacks
or a judge verdict into a signed boundary record. The verifier must independently
observe effects, positive controls, containment and cleanup under existing Gate
contracts. Unchanged signed wire version 0.2 remains authoritative.

## Library call

```python
from agent_boundary_gate.interplay_bridge import evaluate_interplay_bridge

report = evaluate_interplay_bridge(
    trusted_plan,
    trusted_dispatch,
    independently_signed_records,
    trusted_verifier_keys,
    now=authorization_time,
    job_complete=collector_finished,
    server_aggregate=independent_boundary_aggregate,
    evidence_store=private_store,
)
```

The supported source is immutable Interplay
`6372206d6d7f90b45bdfd2f2953cdde35617f2c0`. The separate red-team lock
changes only that VCS source; package versions and the exact Python 3.14.7 pin
stay fixed. Admission verifies 24 assessment/runner/package files, including
the optional Gym source manifest. The gate's existing endpoint campaign command
remains the only enabled target path. Merely including other runners in the
reviewed source does not qualify or select them.

The offline reader accepts one JSON object up to 512 KiB with assessment schema
1 or 2. It validates the identity and selected completion/verdict fields needed
for correlation, rejects duplicate JSON keys and nonfinite constants, and reads
through private regular-file/digest checks. It is not a replacement for full
Interplay schema validation. Only the reference and selected verdict/completion
values enter the report; raw payloads and reasoning remain private.

## Outcomes and recovery

`judge_verdict` retains the unsigned research judgment. A `success` verdict does
not manufacture an effect; a `failure` verdict does not erase a violation.
`boundary_decision` is the ordinary independent Gate evaluation, including its
effect, containment, evidence-loss and cleanup diagnostics. No judge score enters
the boundary aggregate. `combined_decision` preserves boundary incidents and
criteria failures; otherwise missing, mismatched or incomplete research evidence
withholds a passing correlation. `correlation_complete` requires complete
assessment capture, all correlation bindings and a passing boundary evaluation.
It is deliberately false for violations as well as missing evidence.

Missing/corrupt/oversized rows, wrong source, campaign/attempt/probe/provenance or
target mismatches are incomplete. Duplicate, stale, unauthenticated or mismatched
signed records are handled by the existing Gate evaluator. It always runs, even
when every research artifact is unavailable. Authenticated violations and
incidents keep their existing precedence over missing evidence and cleanup loss.

Recovery reopens retained private evidence and calls the same function. It never
replays an attempt or repairs an incomplete row. The fixture test sends one
bounded HTTP request to an independent loopback receiver, stops/drains it, retains
the effect under a separately signed synthetic record, then repeats evaluation
after reopening storage. No second request occurs. Fixture signing and simulated
policy/cleanup do not qualify a real enforcement boundary or crash durability.

## Validation and remaining work

Nine bridge tests cover identity/replay, missing/corrupt/malformed data, duplicate
and stale boundary evidence, signature rejection, incomplete capture, preserved
violations/incidents and offline receiver-effect recovery. Native DataDesigner
conformance additionally correlates a real exported assessment row with a
separately signed fixture and tests generation, judging, analytics, timeout
recovery and changed-source rejection without provider traffic.

Gate now pins Gym `b454c9a6e9a5644564fac81064050094b237daaa`; Interplay's Gym
target was qualified against `f444b8020a3431fc820ef061cef400140bc7afb5`.
Neither baseline is changed by this increment. Reviewed native compatibility,
an externally supervised target path, independent tool-effect collection and a
bounded private live/recovery pilot remain prerequisites to enabling that
combination. Broad runner selection and frozen GYM-04 qualification remain open.
All reports remain release-ineligible; no new release authority is added.
