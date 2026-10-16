# Agent Boundary Gate improvement roadmap

Recorded: 2026-10-11. Reprioritized: 2026-10-12. Updated: 2026-10-13. Refreshed:
2026-10-15 (added RT-01/DEP-01, updated SEC-03/INT-02, dependency and pin
freshness audit). Cleaned up: 2026-10-15 (removed fully-closed items, trimmed
partial items to their remaining gap, added DEP-02). Scope: portable gate core,
built-in adapters and qualification.

The project remains an M0 prototype. All decisions retain
`qualification: m0-prototype` and `release_eligible: false`. Completing a local
implementation or CI run does not establish live qualification or release authority.
Built-in adapters remain in this repository under [ADR-0002](adr/0002-portable-adapters-and-repository-boundaries.md).

## Priorities and acceptance criteria

Each row's acceptance criteria describe the target; the status column states
only what remains open.

| ID | Priority | Improvement | Acceptance criteria | Remaining gap |
| --- | --- | --- | --- | --- |
| SEC-02 | P2 | Continuous security checks | Daily and manual audits, Python 3.12/3.13 PR validation, weekly uv/Actions update proposals and a stable aggregate check. | First scheduled daily audit run and weekly uv/Actions update proposal not yet observed in production. |
| SEC-03 | P2 | Merge enforcement and supply-chain coverage | Require the aggregate check in a repository ruleset; enable security updates and dependency review; audit build tools, supported platform markers and runtime images separately. | Dependabot security updates (`automated-security-fixes`) remain disabled; no `dependency-review` Action is configured; build-tool/platform-marker/runtime-image auditing remain unimplemented. (Ruleset `protect-main` requiring the `Required checks` aggregate is active.) |
| LIFE-01 | P1 | Authenticated lifecycle receipts | Verify trusted signer, freshness, attempt/lease identity, sandbox UID/generation and policy digest for readiness and cleanup; reject replayed or mismatched receipts. | Trusted lease issuance, broker transport and real independent attestations remain open (receipt verifier/backend merged in PR #8). |
| LIFE-02 | P1 | Independent monitoring and recovery | Monitoring begins unknown; an authenticated healthy handshake is required before execution; external watchdog and lease expiry reconcile controller crashes and confirm idempotent cleanup. | Live deployment, escaped-process/supervisor-failure handling and orphan-cell qualification remain open. [Drills](service-watchdog-failure-drills.md), [command ownership](command-parent-death-supervision.md) |
| QUAL-01 | P1 | Whole-cell containment and live OpenShell qualification | Independent allowed/forbidden receivers demonstrate positive controls and boundary effects; policy mutation, telemetry loss, cancellation, restart and cleanup faults cannot create approval; publish only sanitized qualification summaries. | Whole-cell containment, authenticated deployment and fault qualification remain open; depends on LIFE-01/LIFE-02. |
| COMPAT-01 | P1 | Live driver compatibility | Execute a selected frozen probe in the pinned workload image; discover the requested active policy revision; report CLI failure classes without private output; select measured lifecycle budgets. | Qualified delivery and measured lifecycle budgets remain open. |
| COMPAT-02 | P2 | Rig compatibility doctor | Read-only checks validate probe prerequisites, pinned CLI/policy JSON and lease context; destructive latency measurements require a separately designated disposable lease and authenticated cleanup. | Runtime prerequisites are reported but unverified; workload/image qualification and latency measurements remain open. |
| COMPAT-03 | P1 | Supported qualified live entry point | A live-run command composes trusted receipt/monitor/recovery providers and an independent observer; synthetic trust is explicitly segregated and cannot establish qualification. | Independent provisioning/inspection and authenticated live qualification remain open. |
| COMPAT-04 | P2 | Standalone Rust probe | A pinned binary passes shared receiver conformance, bounded DNS/deadline/resource tests and architecture-specific artifact/privacy checks; completion remains separate from outcome proof. | Hostname/DNS support, deployed artifact delivery, reproducible build-image/linker pins, signed release provenance and the live baseline/target qualification matrix remain open. |
| EVID-01 | P2 | Durable, verified evidence | Persist confirmed violations before finalization; retrieve and verify signed digest references; preserve findings through storage/observer/controller failure; isolate collector/storage authority from workloads. | Independent proof interpretation, issuer verification and remote authority remain open. |
| REL-01 | P2 | Adversarial reliability | Property-based decision tests, blocked-adapter fault injection, external timeout enforcement and bounded receiver connection/thread resources demonstrate incomplete outcomes under failures. | Escaped-process/supervisor-failure handling, power-loss durability and live whole-cell faults remain open. [Invariants](gate-decision-invariants.md), [controller drills](development-failure-drills.md), [adapter bounds](adapter-deadlines-and-resource-bounds.md), [service drills](service-watchdog-failure-drills.md), [command ownership](command-parent-death-supervision.md) |
| DEV-01 | P2 | Development and distribution checks | Add type checking, isolated wheel/sdist build and installed-package smoke checks; scan distribution contents for private data and secrets. | Planned; not started. |
| PORT-01 | P2 | First real agent pairing through Gym | One of Hermes/OpenCode/OpenClaw passes shared conformance tests with separate agent and boundary identity; unsupported combinations remain explicit. | Generic signed AgentAdapter conformance, sandbox-native pairing and qualification remain open; broader expansion follows the frozen pilot baseline. |
| DEV-02 | P2 | Packaged development runner | One supported workflow provisions owned resources, verifies identities/pins, runs healthy/weakened Rust controls, retains capture, and reconciles cancellation/orphans with idempotent cleanup; development limits remain explicit. | API response loss/allocator death before UID commit and authenticated whole-cell recovery remain open; shared-gateway mode still needs an independent cleanup helper. [Cell guide](disposable-development-cells.md), [allocator](development-namespace-allocation.md) |
| GYM-01 | P2 | Pinned NeMo Gym injection smoke | Immutable upstream pin and separate lock/image, rights review, audited dependencies, example evaluation plus offline verifier calibration, private traces; examples do not establish broad coverage. | Hosted weights/sampling remain unattested; commercial license review and any future image scan remain open. [Guide](gym-onboarding.md) |
| GYM-02 | P2 | Optional Gym evidence bridge | Case/attempt correlation, independent component pins and separate behavior/effect outcomes; unknown/malformed/missing evidence withholds approval; fixture and failure conformance. | Unsigned collector provenance and mapping-only scope are explicit; real effect routing follows in GYM-03. [Guide](gym-evidence-bridge.md) |
| GYM-03 | P2 | Real-agent prompt injection with boundary controls | One pinned harness routes a synthetic tool action through the selected boundary; independent receivers distinguish resisted, blocked and observed effects with benign-task checks. | Hermes process containment is not attested; no authenticated qualification is claimed. [Guide](hermes-effect-pilot.md) |
| GYM-04 | P2 | Frozen injection regression and private CI | Rights-cleared attack/benign corpus, disjoint held-out cases, repeated runs with separate utility/attack/effect/uncertainty reports; fault-calibrated private CI and offline public checks. | Planned; depends on GYM-03/REL-01. Not started. |
| INT-01 | P3 | EvalHub integration and reports | Stable result/status mapping, sanitized evidence references, explicit unsupported/incomplete outcomes and actionable explanations; no live qualification implied by integration. | Planned; not started. |
| INT-02 | P3 | Interplay attack campaign integration | Optional adapter for pinned `interplay-adversarial/interplay` campaigns; correlate campaign/case/run/attempt and component pins, retain original attack/judge findings separately from independent boundary effects, reject unsupported/missing/mismatched evidence, and exercise offline failure conformance plus one bounded private pilot. Endpoint attacks must not be presented as tool instrumentation or containment proof. | Planned at William's request; depends on the GYM-03 effect path and GYM-04 frozen baseline/fault reporting. [Interplay](https://github.com/interplay-adversarial/interplay) remains a separate optional dependency; no adapter is implemented. Upstream's `red_teaming` attack-runner module (TAP/GOAT/SLIP/Crescendo/Multimodal/PAIR, a configurable judge panel with IRR reporting) is a future dependency once started; see the [dependency freshness audit](#dependency-and-pin-freshness-audit-2026-10-15). |
| RT-01 | P2 | Description-driven DataDesigner research campaigns | Pinned Interplay+DataDesigner generation/judging via `red-team-run`/`red-team-recover`, with batch and adaptive search modes, evidence-dependent criteria, lineage/feedback export and interrupted-run recovery. | A future NeMo Gym `TargetAdapter` for stateful agent rollouts, an authorized adaptive provider pilot and instrumented target adapters remain open. [Guide](description-driven-red-team.md) |
| DEP-01 | P2 | Pinned dependency freshness | Core, dev-group and onboarding (`red-team`/`gym`/`hermes`) pins stay within a bounded distance of upstream; version/commit drift is reviewed on a schedule, not only when `pip-audit`/`cargo-audit` flag a CVE. | Onboarding `pyarrow` is blocked on an upstream `data-designer==0.9.5` constraint (no action possible until `data-designer` ships a newer stable release) and the `hermes-agent` pin (diverged from its fork's current `main`, needs commit-range inspection) remains open; see the [dependency freshness audit](#dependency-and-pin-freshness-audit-2026-10-15). |
| DEP-02 | P2 | Python 3.14 compatibility investigation | Confirm whether core (`pyproject.toml`'s `requires-python = ">=3.12"`) and onboarding pins (`onboarding/red-team`'s exact `3.13.14`, Gym, Hermes) can move to Python 3.14 without breaking pinned dependencies (`pydantic`, `cryptography`, `pyarrow`, `data-designer`, `uv` itself) or CI's musl Rust builds. | Planned; not started. No code should change until compatibility is verified. |

P1 marks qualification blockers. P2 marks reliability and engineering controls.
P3 marks expansion. P1 blockers remain mandatory for qualification while P2
onboarding brings useful agent-level red-teaming forward. The
[Gym adoption plan](nemo-gym-adoption.md) defines the milestones, dependency
isolation and behavior/effect reporting.

## Implementation order

1. GYM-01: retain offline calibration and the separate dependency baseline.
   Hosted-weights/sampling attestation and commercial license review remain
   open before baseline promotion. DEV-02's unresolved API-response/
   allocator-commit window and authenticated external watchdog/whole-cell
   fault qualification remain P1 work.
2. GYM-02/GYM-03: generic agent pairing support beyond the initial Hermes
   host-harness pilot remains separate. The pilot does not depend on, and
   cannot establish, commercial qualification.
3. REL-01/EVID-01: run further development failure drills (Gym/verifier
   faults, policy mutation, receiver/storage loss, cancellation, supervisor
   restart, controller death), building on the
   [existing suite](development-failure-drills.md). External watchdog and
   live qualification remain separate; namespace ownership without a
   retained API UID stays unresolved.
4. GYM-04: freeze a reviewed injection regression suite with benign controls
   and private CI reporting once all pilot and fault criteria are met. Not
   started.
5. Advance the P1 containment track throughout: independently contain the
   whole target, provision real inspectors/watchdog and authenticated
   lifecycle/delivery services, then run live fault qualification
   (LIFE-01/LIFE-02/QUAL-01/COMPAT-03). This remains the commercial
   qualification blocker even if Gym scores improve.
6. Extend to additional agent pairings, broader injection coverage, Rust DNS,
   supply-chain/distribution controls, EvalHub mapping and optional Interplay
   campaign integration as their prerequisites are met
   (COMPAT-04/SEC-03/DEV-01/INT-01/INT-02). SEC-03 merge enforcement remains
   valuable independent work once the hosted aggregate check is established.

INT-02 is recorded for later implementation; it does not replace the current
reliability drills or frozen regression work following the Hermes-first pilot. Pin
Interplay independently from Gym, agent/model, Rust and the selected boundary.
Keep attack discovery/tuning separate from held-out baseline cases. Interplay's
endpoint response/judge outcomes cannot substitute for tool-effect, positive-control,
monitoring or cleanup evidence. Initial integration should use a single supported
attack method and private synthetic tasks before expanding method coverage.

Training, adaptive attack discovery and broad harness expansion follow the frozen
pilot. New attacks require explicit baseline promotion; runtime upgrades never
silently change Gym, case, verifier, agent/model or Rust pins.

Release eligibility remains disabled until a separately reviewed qualification
policy, trusted qualification records and release-authorization contract exist.
No milestone in this roadmap silently enables it.

## Remaining gaps by area

Short pointers to what's open, grouped by the increment that introduced it.
Each links to its detailed guide/ADR rather than repeating implementation history.

**LIFE-01** (receipt verifier/backend merged in PR #8,
[ADR-0003](adr/0003-authenticated-lifecycle-receipts.md)): trusted lease
issuance, broker transport and real independent attestations remain pending.
Durable receipt references and independent terminal re-verification belong to
EVID-01; external watchdog/recovery belongs to LIFE-02.

**LIFE-02** (monitor/journal/recovery merged in PR #9,
[ADR-0004](adr/0004-monitor-and-lease-recovery.md)): authenticated service
transports, deployment/identity separation, provisioning-allocation intents and
real orphan-cell fault injection remain pending. Terminal re-verification of
referenced proof remains EVID-01's responsibility.

**EVID-01** (bounded private-file retrieval with exact digest verification
implemented; see the [library guide](library-usage.md) for usable APIs,
trusted verification inputs and storage/read-budget limits): independent proof
interpretation, independent observer semantics, monitor coverage and broker
issuer signatures remain pending. Live qualification still needs an
operator-selected disposable environment, pinned runtime stack, authenticated
service transports and independent deployment/fault tests.

**COMPAT-01/COMPAT-02**: explicit Python/Perl/Rust probe selection, direct
HTTP without proxy/redirect behavior and phase-scoped CLI failure reasons are
implemented. Qualified delivery and measured lifecycle budgets remain open.
COMPAT-02's
[CLI/library doctor](compatibility-doctor.md) covers read-only CLI/lease/policy
inspection; runtime/module availability is explicitly unverified (no workload
execution occurs), and authenticated readiness, image qualification and
separately authorized disposable latency experiments remain pending. No
deployment identifiers, endpoints, inventories or raw captures from any live
OpenShell test belong in this repository.

**COMPAT-04** (`gate-http-probe`, [usage guide](rust-probe-usage.md), no
third-party runtime crates or OpenShell dependency; digest-verified artifact
staging and experimental IP-only backend admission implemented,
[delivery guide](rust-probe-delivery.md), gated by a fresh Ed25519 delivery
receipt per action, [ADR-0005](adr/0005-independent-evaluation-baselines.md)):
hostname/DNS support, deployed artifact delivery, reproducible
build-image/linker pins, signed release provenance and the live baseline/target
qualification matrix remain pending. Compiler/stdlib, build/audit tooling and
runtime-image CVEs need separate SEC-03 coverage.

**GYM-03/REL-01** (Hermes host-harness pilot,
[drills](hermes-effect-pilot.md#worker-and-proxy-failure-drills): model-free
loopback shutdown/publication, blocked/cancelled worker supervision and
same-group descendant cleanup implemented): interrupted proxy work remains
incomplete (late responses cannot publish after closure). Live whole-cell/
watchdog faults and blocked adapters outside this worker path remain open;
GYM-04 freezing depends on them.

**REL-01** (eleven Hypothesis property groups,
[covered properties and limits](gate-decision-invariants.md); command/HTTP
bounds capping concurrent admission and header limits for both receiver
implementations, [scope and limits](adapter-deadlines-and-resource-bounds.md);
local commands terminating their process group after caller death,
[command ownership and limits](command-parent-death-supervision.md)): not
exhaustive and not live qualification. Broader blocked-adapter deadlines,
resource bounds and independent live failure criteria remain open. Arbitrary
Python callbacks and trusted host filesystem operations remain outside child
supervision. Escaped sessions, owner death/suspension, reboot/storage
durability, partitions and live whole-cell faults remain open; no stopping of
local commands can substitute for signed durable remote cleanup proof.

**DEV-02/EVID-01** (optional private allocation service,
[protocol and limits](development-namespace-allocation.md), closing the
controller delivery/registration gap when the allocator durably records the
API-returned UID): API response loss and allocator pre-commit death still need
independent operator provenance; grant-create windows, power-loss/partition
durability, controller/key isolation and authenticated live whole-cell recovery
remain open.

**RT-01** (reusable Interplay generation/judging/search API and the gate's
`onboarding/red-team` consumption implemented, including opt-in sequential
DataDesigner refinement with committed target evidence and validated judge
feedback; [guide](description-driven-red-team.md)): a future NeMo Gym
`TargetAdapter` for stateful agent rollouts, an authorized adaptive provider
pilot and instrumented target adapters remain open. EVID-01 durable-storage
interruption drills remain the next reliability-track item.

## Dependency and pin freshness audit (2026-10-15)

Checked every pinned package/commit against its upstream latest. Still open:

`onboarding/red-team`'s `pyarrow` pin (24.0.0 vs. latest 26.0.0) is **blocked**,
not just untried: `data-designer==0.9.5` (the latest stable release) hard-pins
`pyarrow>=24,<25`, and PyPI has no `24.x` release newer than `24.0.0` to move
to instead (confirmed 2026-10-15 — `uv lock` fails the bump with this exact
conflict). The only newer `data-designer` release is `1.0.0rc1`, a
prerelease; bumping `pyarrow` needs that line to ship stable first, or
`data-designer` to relax the constraint. `any-llm-sdk` (1.33.0 vs. 1.36.0) and
`openai` (3.28.0 vs. 3.31.0) have smaller version gaps still open.

`onboarding/gym` and `onboarding/hermes`'s NeMo Gym pin was bumped 2026-10-15
from `f444b802` to `b454c9a` (`NVIDIA-NeMo/Gym`'s `main` at the time, 70
commits ahead of the old pin). Five of the gate's hash-pinned files changed,
not just `responses_converter.py` as first scoped: upstream's `pyproject.toml`
moved `ray`/`jinja2` out of the unconditional core dependencies into an opt-in
`ray` extra (shrinking the resolved lock by ~20 packages since neither
onboarding project requests that extra), `responses_converter.py` gained a
backward-compatible opt-in `drop_unrepresentable_request_fields` parameter,
`indirect_prompt_injection/app.py` and `simple_agent/app.py` each dropped a
now-redundant `ray_enabled = False` class attribute, and `hermes_agent/app.py`
gained new agent-timeout-budget and model-rejection-status handling (both
opt-in/default-preserving). `src/agent_boundary_gate/gym_bridge.py`'s own
`GYM_COMMIT` constant was bumped alongside the pin. Verified by re-running
`scripts/gym_replay.py` against a fresh clone of the new commit and both
`test_gym_smoke_native.py` and `test_hermes_pilot_native.py` against the
regenerated `onboarding/gym`/`onboarding/hermes` locks; all pass, and
`scripts/audit_dependencies.py --gym`/`--hermes` report zero gaps. The
`hermes-agent` pin itself (below) was not touched.

`onboarding/hermes`'s `hermes-agent` pin (`cmunley1/hermes-agent@26bb847`,
dated 2026-05-07) is reported by GitHub's compare API as **diverged** from
that fork's current `main` (132 ahead, 9 behind), not a clean fast-forward
ancestor. Nine commits reachable from the pin are no longer reachable from
`main`, consistent with history having been rewritten on that personal fork at
some point since May. Re-pinning needs the commit range inspected by hash, not
just advanced to `main` HEAD.

None of these gaps is a known vulnerability; `scripts/audit_dependencies.py`
and the Rust/CVE audits stay green.
