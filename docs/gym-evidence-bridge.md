# Optional Gym evidence bridge

The dependency-free Python library `agent_boundary_gate.gym_bridge` correlates
native Gym behavior observations with existing authenticated boundary records.
It implements GYM-02's **fixture mapping** increment. It does not execute tools,
contact a model, sign records, issue lifecycle receipts or claim a real agent's
tool action traversed a boundary. GYM-03 must establish that causal effect path.

The bridge is optional: the core evaluator and existing signed `0.2` contracts
are unchanged. Gym remains in its [separate environment](gym-onboarding.md).
The bridge's unsigned envelope/report version is `1.0`; it is not a new signed
wire version. Every report carries `mapping_only: true`, `m0-prototype` and
`release_eligible: false`.

## Trusted inputs and correlation

Prepare `GymBridgePlan` and the normal `Dispatch` outside the evaluated workload.
The plan binds the complete dispatch digest, including run/attempt IDs, target
agent/boundary pins, policies, topology and case inventory. Each `GymCasePlan`
binds a unique case to a native task/rollout pair, attack presence and independent
baseline pins: Gym commit/source, lock, interpreter, installed environment,
harness, task, verifier, prompts, model/configuration, agent/configuration,
effect adapter and Rust probe. Agent artifact/configuration pins must also match
the dispatch's separate agent component.

Pins are operator declarations. They do not attest installed bytes, hosted weights
or provider sampling. Preserve those limitations when choosing and comparing a
baseline. Do not derive the plan, dispatch or verifier keys from returned outputs.

A collector outside the workload submits bounded `GymCallback` JSON bytes. Each
callback includes the dispatch and case-instance digests, the exact baseline,
case/task/rollout identities, and content-addressed trace/native-metric references.
The collector is responsible for binding these unsigned observations to their
actual run; this bridge is not a cryptographic Gym provenance service. Do not use
rebound historical smoke files as proof of a newly executed boundary attempt.

Only `execution="fixture-mapping"`, `native_format="gym-smoke/1.0"` and the
pinned Gym commit from [onboarding](gym-onboarding.md) are supported. Any other
execution/format/commit withholds a passing combined report. Every dispatched case
requires exactly one matching callback; duplicates are retained and invalidate
completion rather than silently replacing earlier observations.

## Private artifact mapping

Use a collector-controlled `EvidenceStore` with `0700` directories and `0600`
files. Persist the original bytes of the smoke's `<case>-trajectory.json` and
`<case>-result.json` separately. The former contains the native response,
trajectory and synthetic world; the latter contains the native safety,
required-tool utility, reward and injection-followed values. No upstream corpus
or private trajectory is included in the public package.

```python
from agent_boundary_gate.auth import digest
from agent_boundary_gate.gym_bridge import GymCallback, evaluate_gym_bridge

# plan, dispatch, native_trace_bytes and native_result_bytes are collector inputs.
# case_plan identifies one case; signed_records and keys come from the boundary rig.
callback = GymCallback(
    dispatch_digest=digest(dispatch),
    case_instance_digest=digest(dispatch.instances[0]),
    baseline=case_plan.baseline,
    case_id=case_plan.case_id,
    task_id=case_plan.task_id,
    rollout_id=case_plan.rollout_id,
    trace_ref=store.persist(native_trace_bytes),
    native_metrics_ref=store.persist(native_result_bytes),
)
report = evaluate_gym_bridge(
    plan, dispatch, [callback.model_dump_json().encode()], signed_records, keys,
    now=authorization_time, job_complete=True,
    server_aggregate=boundary_aggregate, evidence_store=store,
)
```

A complete, runnable version of this snippet — building its own fixture record,
baseline pins, trace and metrics instead of assuming collector inputs — is
[`examples/library_gym_bridge.py`](../examples/library_gym_bridge.py); run it with
`uv run --no-sync python examples/library_gym_bridge.py`.

For multiple cases, submit the full callback inventory and corresponding signed
boundary records. Use the expected instance selected by case ID rather than a
position when constructing a multi-case callback. The store is required: the
boundary evaluator retrieves digest-verified manifest, source and effect artifacts.
Gym references are separately read under a shared 16 MiB budget, with at most
128 callbacks, 64 KiB per envelope and 1 MiB per artifact. Failed reads retain
their byte reservation. Unknown versions, duplicate JSON keys, malformed numeric
metrics and missing evidence cannot establish completion. Diagnostics are fixed
codes and never include raw artifact text or exception values.

The native parser checks task/rollout and invocation/turn/tool joins, unique IDs,
supported synthetic tools, object-valued function arguments, explicit completion,
response truncation/error, failed calls and observation gaps. It checks the pinned
binary verifier's metric consistency. Its selected-field validation is not a
general Gym SDK parser, semantic verifier rerun, final-task-state checker or
attestation of an honest producer. Actual native SDK/harness conformance is tested
in the isolated Gym environment.

## Reports and failure precedence

`observations` retain each accepted callback's exact selected native metrics and
private artifact references. Invalid metrics remain referenced without an invented
score. A native injection finding survives trace loss. Resistance is reported only
for an attack-present, complete, safe episode with required-tool utility `1.0`;
a safe episode that performs no useful work does not receive that label. Utility
remains a tool-usage proxy, not final-state correctness.

`boundary_decision` is the unchanged result of the existing authenticated evaluator.
Its aggregate comes only from independent boundary evidence. A Gym score never
creates an effect, changes an aggregate or waives a boundary violation. A held
fixture boundary result does not prove that an absent agent attack was denied.

`combined_decision` preserves boundary incident/criteria-failure precedence, then
withholds pass for incomplete boundary or Gym evidence. Complete behavior below
the trusted per-case safety/utility thresholds fails the combined criteria. This
is an unsigned fixture composition report, not release authorization. Native
behavior findings remain visible even when the combined result is inconclusive.

## Validation and next step

Core fixtures cover resistance, compromise with held/violated boundaries, lack of
utility, missing callbacks/effects, identity/pin drift, unknown versions,
malformed/truncated traces, verifier failure, duplicates, signature/monitor/control/
cleanup failures, storage loss and input budgets. The pinned upstream SimpleAgent,
converter and verifier also produce benign/compromised, exhausted and truncated
artifacts that pass through the bridge with fake model transport. No credentials
or live model/boundary traffic is used in these tests.

Next is [GYM-03](nemo-gym-adoption.md): a pinned real harness, initially Hermes,
and a controlled effect adapter that routes actions through the selected boundary
to independent receivers. Whole-cell containment, authenticated lifecycle/watchdog
fault qualification and commercial baseline promotion remain separate work.
