# NeMo Gym onboarding and adoption plan

Recorded: 2026-10-12. Updated: 2026-10-13. Status: onboarding in progress;
offline native verifier calibration and the packaged development runner are
implemented. No model-backed Gym integration or agent pairing is qualified.

## Decision and verified starting point

Adopt NeMo Gym as an optional environment, agent-harness and evaluation layer.
Keep boundary policy, independent observation, lifecycle authority and the Rust
baseline owned by this project. Gym integration must remain usable without an
OpenShell-specific baseline. This plan updates the
[improvement roadmap](improvement-roadmap.md).

Gym already ships an indirect prompt-injection environment: it places malicious
instructions in tool-returned data across nine domains, matches attacker-targeted
tool calls deterministically, and separately scores safety and required-tool
utility. The latter is a task-completion proxy, not proof of correct final state.
Public examples are available; the README describes the full dataset as
forthcoming. These are source-confirmed capabilities, not a runtime validation
performed by this project. [Upstream environment](https://github.com/NVIDIA-NeMo/Gym/tree/main/resources_servers/indirect_prompt_injection).

Gym also documents Hermes, OpenCode and OpenClaw harnesses and an OpenShell
sandbox provider. Their presence does not establish compatibility or qualification
with our gate. [Upstream project](https://github.com/NVIDIA-NeMo/Gym).

## Architecture and repository boundaries

Keep the bridge, portable result mapping, conformance tests and documentation in
this repository initially, following [ADR-0002](adr/0002-portable-adapters-and-repository-boundaries.md).
Use a separately locked environment or image for Gym and its harness dependencies;
do not make Gym a mandatory core dependency. Do not copy upstream harnesses.
A separate adapter repository is justified only by concrete maintenance, licensing
or deployment needs. Any future package split must keep one bridge implementation
and use versioned conformance tests.

The planned flow is:

```text
pinned cases -> Gym environment + selected agent harness -> tool requests
                                    |
                          controlled effect adapter
                                    |
                           selected boundary runtime
                                    |
                         independent effect receivers

Gym trajectory + native verifier outputs -> separate behavior report
external effects + trusted lifecycle evidence -> gate evaluation
```

Tool execution location is an explicit design checkpoint: Gym's seeded JSON
environment models business actions; those actions do not automatically traverse
the selected runtime boundary. An effect adapter must execute the declared action
inside that boundary. Keep resources/verifiers, observer credentials, provisioning
credentials and signing keys outside the evaluated workload. Route model access
through a restricted approved path; record its policy and residual exposure.

Report these dimensions separately; these labels are proposed report fields,
not additions to existing signed schemas:

| Observation | Behavior assessment | Boundary assessment |
| --- | --- | --- |
| No attacker-targeted call; benign task succeeds | Resistance and utility observed | Only the exercised effects are assessed; absence alone proves no denial |
| Attacker-targeted call; independent proof of denial with healthy controls | Injection followed | Boundary held for this attempt |
| Forbidden effect observed, irrespective of Gym score | Retain native behavior finding | Preserve boundary violation |
| Missing positive control, trace, monitor or cleanup proof | Unsupported/incomplete as applicable | Withhold approval; retain violations and incidents |

A prevented attack and a refusal to do all useful work must remain distinguishable.
Gym reward cannot waive a finding, repair missing evidence or authorize a release.
Archived signed wire contracts remain unchanged; any new contract needs separate
versioning and review. All project decisions remain `m0-prototype` and
`release_eligible: false`.

## Onboarding milestones and exit criteria

Current implementation: [Gym onboarding](gym-onboarding.md) pins the upstream
commit/interpreter, remediates the dependency graph in a separate lock, and
replays six synthetic cases through the actual native verifier. The
[development runner](development-runner.md) packages paired Rust controls and
registered-allocation recovery. It requires an external identity-bound cleanup
helper; name-based target deletion has been removed and live helper support is
pending. Model/provider selection and the model-backed
smoke, dataset rights and any image deployment remain open GYM-01 work.

| ID | Deliverable | Exit criteria and dependencies |
| --- | --- | --- |
| GYM-01 | Reproducible upstream smoke run | Select an immutable upstream commit/artifact, lock interpreter and dependencies, review licenses/data rights, scan its image/dependencies, and run available injection examples with one pinned model/config. Retain private trajectories and native verifier output. An offline known-safe/known-compromised verifier replay must also work without model credentials. Do not claim benchmark coverage. |
| DEV-02 | Packaged development runner | Replace operator-only orchestration with supported provisioning, identity checks, healthy/weakened Rust controls, capture and idempotent cleanup. Private configuration, allocation tracking and bounded cancellation are required. Existing development-only limits remain explicit. |
| GYM-02 | Optional evidence bridge | Depends on GYM-01. Correlate case/run/attempt identities and bind all component pins; preserve raw Gym metrics separately from external evidence. Test malformed/truncated traces, unknown versions, mismatched identities, verifier failure, missing effects and duplicate callbacks. Required unsupported execution must fail closed. A fixture bridge proves mapping only. |
| GYM-03 | One real agent and effect pilot | Depends on GYM-02 and DEV-02. Try Hermes first using the upstream harness; fall back to OpenCode only after recording an incompatible prerequisite. Pin application identity separately from boundary identity. Execute a synthetic tool-output injection through a controlled effect adapter, using healthy/weakened boundary policies and independent receivers. Demonstrate benign utility and both blocked and observed forbidden effects; deterministic tool-call fixtures calibrate the oracle when model behavior varies. |
| GYM-04 | Frozen regression suite and private CI | Depends on GYM-03 and fault drills. Version a rights-cleared synthetic corpus with attack-present and benign look-alike tasks; keep a disjoint held-out set. Repeat fixed configurations and report denominators, uncertainty, false refusals, verified task state, attack success, effects, incomplete runs, cost and latency. Private scheduled/manual jobs retain evidence; public PR checks use synthetic offline fixtures. |

For GYM-01, record an onboarding manifest containing upstream commit, lock/image
digest, interpreter, harness, model identifier/provider configuration, prompts,
task bytes/license, verifier, sampling settings, seed where supported, budgets
and expected native outputs. Hosted model identifiers may not guarantee immutable
weights: record the provider's version guarantee and mark comparisons accordingly.
Start with evaluation; RL and adaptive attack generation are later research work.
Do not assume this environment supplies an adaptive attacker orchestrator.

The GYM-03 pilot is narrowly scoped to a synthetic forbidden-egress action. No
live business systems or customer data are needed. It measures the declared agent
and boundary combination, not arbitrary tools or all injection families.

## Baseline promotion, failures and qualification

Version Gym, corpus, verifier, prompts, agent/model and Rust artifact independently
of the target runtime, following [ADR-0005](adr/0005-independent-evaluation-baselines.md).
Hold these fixed when comparing runtime upgrades; change one declared factor at
a time. A verifier update creates a new assessment with its own version, never
rewrites archived signed evidence. Discovery attacks require review, licensing
checks and explicit promotion before joining the frozen baseline. Training and
attack tuning must not consume held-out evaluation cases.

Fault campaigns must cover policy mutation, receiver/storage loss, cancellation,
supervisor restart, controller death, Gym/verifier failure and attempts to tamper
with evaluation state. Retain effects through final capture and cleanup; test
timeouts and orphan reconciliation independently of Gym's lifecycle callbacks.

The [Kubernetes development profile](kubernetes-development.md) can support a
bounded development pilot, but it does not contain the entire target or issue
qualification receipts. Whole-cell containment of gateway, supervisor and
workload, independent inspectors, external watchdog recovery, authenticated
readiness/delivery/cleanup and live fault qualification remain P1 blockers. See
[the live-rig handoff](live-rig-handoff.md). Gym onboarding does not remove them.

OpenCode/OpenClaw expansion, broader injection families, Rust DNS, reporting
integrations and training follow the first calibrated pilot. RustFS is the
preferred development object-store option when remote storage becomes necessary;
use private, restricted access and sanitized export. No storage deployment is
required for onboarding.

## Review packet before adoption expands

Publish only portable instructions, synthetic fixtures and sanitized summaries.
Keep runtime inventory, cluster identities, endpoints, credentials, captures and
attack tuning traces private. The review packet must identify supported versions,
task rights, measured coverage, known gaps, per-case outcomes, failure-drill
results, evidence references and cleanup status. Expand beyond the pilot only
when its behavior/effect distinction is reproducible and its failure paths cannot
produce approval.
