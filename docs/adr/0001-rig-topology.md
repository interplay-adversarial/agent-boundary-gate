# ADR-0001: Whole-target feasibility before live release gating

Status: proposed; empirical checks outstanding. Date: 2026-10-09.

The first case measures whether a forbidden synthetic HTTP receiver sees a
request, paired with an allowed receiver proving the workload and observation
path work. Both receivers are inside the research rig and outside OpenShell's
control boundary. OpenShell decision logs are corroborating evidence; the
independent receiver is the outcome oracle. No external destination is required.

## Candidate placement

Provision one disposable VM enclosing the OpenShell gateway, supervisor,
sandbox and required target services for the feasibility prototype. This is a
candidate fallback from the plan, not a demonstrated deployment. Use Kata only
after proving it encloses every target component without unsupported nesting.
An independently controlled outer firewall closes external paths, including
gateway, DNS, telemetry and model traffic. The deterministic case uses mock
endpoints and synthetic fixtures.

Run the controller, verifier, receiver collectors and signer outside the
adversarial target identity. Only the controller gets provisioning credentials.
The attacker cannot access observer storage or signing keys. An independent
watchdog owns the external deadline and orphan-cell cleanup. Every path records
teardown status; a failed teardown does not erase findings or incidents.

Capture must start before replay. Readiness is an observed effective policy
digest/generation plus successful positive control, never a fixed sleep. Final
drain markers and dropped-event counts determine required evidence validity.
The target's OCSF diagnostics remain optional for the first receiver invariant.
Containment monitoring is required: loss stops replay and withholds approval,
without implying a proven escape. The current prototype evaluates terminal
records only; it does not perform that runtime stop.

## Feasibility packet checklist

| Proof | Current state | Required handoff |
|---|---|---|
| Whole-target placement | Unproven | Reproducible deployment recipe and boundary diagram |
| External closure | Unproven | Gateway/workload/DNS/model/storage path checks |
| Effective policy readiness | Unproven | Observed generation/digest and activation probe |
| Allowed + weakened receiver controls | Loopback capture with simulated policy | Live OpenShell receiver evidence with layer attribution |
| Observer identity/tamper resistance | Signer contract only | Identity/RBAC and attacker-unreachable storage demonstration |
| Source generations and loss | Candidate schema only | Actual readiness/drain/loss fixtures per source |
| Incident monitoring | Synthetic injection only | Independent monitor and runtime hard stop |
| TTL/controller crash/cancellation | Local bounded execution/cancellation only | External lease/watchdog tests with no orphan cell |
| Restricted storage + export | Private local store implemented | Private MLflow/RustFS, receipts, retention and sentinel export test |
| EvalHub adapter fidelity | Not implemented | Pinned SDK/Contrib implementation and full-path examples |
| Signer trust/rotation | Local Ed25519 verifier only | CI key ownership, provisioning and rotation decision |
| Exception approval integrity | Trusted dispatch assumption | Authenticated approval register and authorization-time evaluation |

October 10 implementation details and observed host prerequisites are recorded in
[the live-rig handoff](../live-rig-handoff.md). Whole-target containment and live
detector qualification remain unproven.

The version matrix must pin OpenShell, guest kernel, runtime, policy schema,
prover, Server/SDK, provider and images by immutable IDs. See
`../../dependencies.json` for cached source snapshots; deployment pins are
deliberately unresolved. Do not substitute source commits for qualified images.

## Ownership and sequence

Platform: disposable-cell recipe, containment, independent watchdog, storage.
Harness: direct driver, lifecycle/capture, receiver observer, signer integration.
Security evaluation: invariants, calibration, exception approvals, qualification.
Contrib: custom provider; Server/SDK: native required-benchmark work.

Demonstrate healthy, weakened, required-observer outage, optional-diagnostic
loss and safely injected incident in that order with preserved attempt records.
Only after the full path qualifies should CI enable a protected release gate.
Do not conduct outer-runtime escape research as part of this packet.
