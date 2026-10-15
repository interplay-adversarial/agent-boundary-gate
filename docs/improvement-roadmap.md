# Agent Boundary Gate improvement roadmap

Recorded: 2026-10-11. Reprioritized: 2026-10-12. Updated: 2026-10-13. Refreshed: 2026-10-15 (added RT-01/DEP-01, updated SEC-03/INT-02, dependency and pin freshness audit). Scope: portable gate core, built-in adapters and qualification.

The project remains an M0 prototype. All decisions retain
`qualification: m0-prototype` and `release_eligible: false`. Completing a local
implementation or CI run does not establish live qualification or release authority.
Built-in adapters remain in this repository under [ADR-0002](adr/0002-portable-adapters-and-repository-boundaries.md).

## Priorities and acceptance criteria

| ID | Priority | Improvement | Acceptance criteria | Status |
| --- | --- | --- | --- | --- |
| SEC-01 | P2, first implementation | Exact-version dependency auditing | Every applicable locked runtime/dev package name and version is audited; duplicates, extra packages, missing versions, mismatches and skipped entries fail closed; failures preserve reported advisories. | Merged in PR #2; regression tests pass |
| SEC-02 | P2, first implementation | Continuous security checks | Daily and manual audits, Python 3.12/3.13 PR validation, weekly uv/Actions update proposals and a stable aggregate check; automation becomes active after merge. | Merged in PR #2; hosted Python 3.12/3.13 checks pass; first scheduled runs/update proposals not yet observed |
| SEC-03 | P2 | Merge enforcement and supply-chain coverage | Require the aggregate check in a repository ruleset after confirming its hosted status; enable security updates and dependency review; audit build tools, supported platform markers and runtime images separately. | Ruleset `protect-main` (id 24908536, active since 2026-10-12) requires the `Required checks` aggregate status check, blocks deletion/force-push, and requires a PR with resolved threads; verified via the GitHub API on 2026-10-15. Dependabot security updates (`automated-security-fixes`) remain disabled, no `dependency-review` Action is configured, and build-tool/platform-marker/runtime-image auditing remain separate, unimplemented work. |
| LIFE-01 | P1 | Authenticated lifecycle receipts | Verify trusted signer, freshness, attempt/lease identity, sandbox UID/generation and policy digest for readiness and cleanup; reject replayed or mismatched receipts. | Receipt verifier/backend increment merged in PR #8; trusted issuance/transport and live attestation pending |
| LIFE-02 | P1 | Independent monitoring and recovery | Monitoring begins unknown; an authenticated healthy handshake is required before execution; external watchdog and lease expiry reconcile controller crashes and confirm idempotent cleanup. | Monitor/journal/recovery increment merged in PR #9; real host-service/watchdog death/restart drills and bounded configurable watchdog timers implemented with synthetic cell authority. Local command supervision now terminates active inspectors after authority SIGKILL. Live deployment, escaped-process/supervisor-failure handling and orphan-cell qualification pending. [Drills](service-watchdog-failure-drills.md), [command ownership](command-parent-death-supervision.md) |
| QUAL-01 | P1 | Whole-cell containment and live OpenShell qualification | Independent allowed/forbidden receivers demonstrate positive controls and boundary effects; policy mutation, telemetry loss, cancellation, restart and cleanup faults cannot create approval; publish only sanitized qualification summaries. | Development healthy/weakened Rust exercise completed in PR #19; whole-cell containment, authenticated deployment and fault qualification pending; depends on LIFE-01/LIFE-02 |
| COMPAT-01 | P1 | Live driver compatibility | Execute a selected frozen probe in the pinned workload image; discover the requested active policy revision; report CLI failure classes without private output; select measured lifecycle budgets. | Python/Perl selection and diagnostics implemented; independently pinned Rust image exercised against actual healthy/weakened policies in PR #19; qualified delivery and lifecycle budgets pending. The Python probe's fail-open timeout/attempt validation gap is fixed; see the [cohesion audit](#probe-and-gate-decision-cohesion-audit-2026-10-15). |
| COMPAT-02 | P2 | Rig compatibility doctor | Read-only checks validate probe prerequisites, pinned CLI/policy JSON and lease context; destructive latency measurements require a separately designated disposable lease and authenticated cleanup. | Read-only CLI/lease/policy inspection implemented; runtime prerequisites reported but unverified, workload/image qualification and latency measurements pending |
| COMPAT-03 | P1 | Supported qualified live entry point | A live-run command composes trusted receipt/monitor/recovery providers and an independent observer; synthetic trust is explicitly segregated and cannot establish qualification. | Host services and live-run/campaign composition implemented in PR #18; independent provisioning/inspection and authenticated live qualification pending |
| COMPAT-04 | P2 | Standalone Rust probe | A pinned binary passes shared receiver conformance, bounded DNS/deadline/resource tests and architecture-specific artifact/privacy checks; completion remains separate from outcome proof. | IP-literal prototype, native Linux CI, digest-verified staging and signed immutable-delivery backend admission implemented; hostname/DNS, live provisioning/issuer, release provenance and qualification pending |
| EVID-01 | P2 | Durable, verified evidence | Persist confirmed violations before finalization; retrieve and verify signed digest references; preserve findings through storage/observer/controller failure; isolate collector/storage authority from workloads. | Bounded local retrieval and signed-reference integrity increment implemented; independent proof interpretation/issuer verification and remote authority pending |
| REL-01 | P2 | Adversarial reliability | Property-based decision tests, blocked-adapter fault injection, external timeout enforcement and bounded receiver connection/thread resources demonstrate incomplete outcomes under failures. | Eleven generated decision properties, controller/worker drills and eleven command/HTTP bounds groups are implemented. Seventeen real host-service/watchdog groups cover death/suspension/restart, claim/UID authority, storage failures and signed violation retention. Five command-owner groups cover caller death/suspension, admission, signal outcomes and missing cleanup status. Escaped-process/supervisor-failure handling, power-loss durability and live whole-cell faults remain open. Three of six result-producing modules (`development_run.py`, `red_team.py`, `campaign.py`) still hand-write the release-ineligible convention instead of sharing `gate_policy.evaluate`/`GateDecision`; see the [cohesion audit](#probe-and-gate-decision-cohesion-audit-2026-10-15). [Invariants](gate-decision-invariants.md), [controller drills](development-failure-drills.md), [adapter bounds](adapter-deadlines-and-resource-bounds.md), [service drills](service-watchdog-failure-drills.md), [command ownership](command-parent-death-supervision.md) |
| DEV-01 | P2 | Development and distribution checks | Add type checking, isolated wheel/sdist build and installed-package smoke checks; scan distribution contents for private data and secrets. | Planned |
| PORT-01 | P2 | First real agent pairing through Gym | One of Hermes/OpenCode/OpenClaw passes shared conformance tests with separate agent and boundary identity; unsupported combinations remain explicit. | Hermes host-harness development pilot now routes synthetic remote effects through disposable boundaries. Generic signed AgentAdapter conformance, sandbox-native pairing and qualification remain pending; broader expansion follows the frozen pilot baseline. |
| DEV-02 | P2 | Packaged development runner | One supported workflow provisions owned resources, verifies identities/pins, runs healthy/weakened Rust controls, retains capture, and reconciles cancellation/orphans with idempotent cleanup; development limits remain explicit. | Disposable gateway namespace allocation/UID-conditioned cleanup implemented and live paired controls exercised; pinned operator bootstrap required. Optional independent namespace allocator retains API UIDs before delivery; eleven groups cover controller response loss, conservative unresolved creates, UID races and restart. API response loss/allocator death before UID commit and authenticated whole-cell recovery remain open. Shared-gateway mode still needs an independent cleanup helper. [Cell guide](disposable-development-cells.md), [allocator](development-namespace-allocation.md) |
| GYM-01 | P2, development onboarding complete | Pinned NeMo Gym injection smoke | Immutable upstream pin and separate lock/image, rights review, audited dependencies, example evaluation plus offline verifier calibration, private traces; examples do not establish broad coverage. | Pinned source/interpreter, separate remediated lock, six native offline replay cases and lock CVE audit implemented. Original Apache-2.0 attack/benign pair completed against a privately configured hosted model in four calls, with private trajectories and requested sampling/budget records. Hosted weights/sampling remain unattested; commercial license review and any future image scan remain open. [Guide](gym-onboarding.md) |
| GYM-02 | P2, fixture mapping implemented | Optional Gym evidence bridge | Case/attempt correlation, independent component pins and separate behavior/effect outcomes; unknown/malformed/missing evidence withholds approval; fixture and failure conformance. | Optional dependency-free library binds a trusted baseline/dispatch to native private artifacts and evaluates signed boundary evidence separately. Core fault fixtures and actual native Gym harness conformance pass without model traffic. Unsigned collector provenance and mapping-only scope are explicit; real effect routing follows in GYM-03. [Guide](gym-evidence-bridge.md) |
| GYM-03 | P2, development pilot implemented | Real-agent prompt injection with boundary controls | One pinned harness routes a synthetic tool action through the selected boundary; independent receivers distinguish resisted, blocked and observed effects with benign-task checks. | Actual pinned Gym Hermes host harness/runtime with two synthetic tools and remote fixed Rust execution completed healthy/weakened development profiles at allowed/forbidden counts 3/0 and 3/1. Native fake-model calibration preserves attempted injection separately from effects; hosted benign/injected cases retained utility and resisted this one task. Final capture, UID cleanup and independent owned-resource inspection passed. Hermes process containment is not attested; no authenticated qualification is claimed. [Guide](hermes-effect-pilot.md) |
| GYM-04 | P2, after pilot | Frozen injection regression and private CI | Rights-cleared attack/benign corpus, disjoint held-out cases, repeated runs with separate utility/attack/effect/uncertainty reports; fault-calibrated private CI and offline public checks. | Planned; depends on GYM-03/REL-01 |
| INT-01 | P3 | EvalHub integration and reports | Stable result/status mapping, sanitized evidence references, explicit unsupported/incomplete outcomes and actionable explanations; no live qualification implied by integration. | Planned |
| INT-02 | P3, after calibrated agent pilot | Interplay attack campaign integration | Optional adapter for pinned `interplay-adversarial/interplay` campaigns; correlate campaign/case/run/attempt and component pins, retain original attack/judge findings separately from independent boundary effects, reject unsupported/missing/mismatched evidence, and exercise offline failure conformance plus one bounded private pilot. Endpoint attacks must not be presented as tool instrumentation or containment proof. | Planned at William's request; depends on the GYM-03 effect path and GYM-04 frozen baseline/fault reporting. [Interplay](https://github.com/interplay-adversarial/interplay) remains a separate optional dependency; no adapter is implemented. Upstream now ships a `red_teaming` attack-runner module (TAP/GOAT/SLIP/Crescendo/Multimodal/PAIR, a configurable judge panel with IRR reporting) this adapter would build on once started; see the [dependency freshness audit](#dependency-and-pin-freshness-audit-2026-10-15). |
| RT-01 | P2, implemented | Description-driven DataDesigner research campaigns | Pinned Interplay+DataDesigner generation/judging via `red-team-run`/`red-team-recover`, with batch and adaptive search modes, evidence-dependent criteria, lineage/feedback export and interrupted-run recovery. | Merged in PR #33/#34 ([guide](description-driven-red-team.md)). Reusable Interplay generation/judging/search API and the gate's `onboarding/red-team` consumption are implemented; a future NeMo Gym `TargetAdapter` for stateful agent rollouts, an authorized adaptive provider pilot and instrumented target adapters remain open. The pinned Interplay commit was bumped 2026-10-15 to `v0.3.1`; see the [dependency freshness audit](#dependency-and-pin-freshness-audit-2026-10-15). |
| DEP-01 | P2 | Pinned dependency freshness | Core, dev-group and onboarding (`red-team`/`gym`/`hermes`) pins stay within a bounded distance of upstream; version/commit drift is reviewed on a schedule, not only when `pip-audit`/`cargo-audit` flag a CVE. | Identified 2026-10-15; core/dev-group patch bumps (pydantic/ruff/pre-commit/hypothesis) and the `interplay-adversarial` pin (to `v0.3.1`) landed the same day. Remaining onboarding pins (pyarrow, NeMo Gym, hermes-agent) are still open; see the [dependency freshness audit](#dependency-and-pin-freshness-audit-2026-10-15) for what each needs verified first. |

P1 marks qualification blockers. P2 marks reliability and engineering controls.
P3 marks expansion. SEC-01/SEC-02 were the first implementation. P1 blockers
remain mandatory for qualification while P2 onboarding brings useful agent-level
red-teaming forward. The [Gym adoption plan](nemo-gym-adoption.md) defines the
new milestones, dependency isolation and behavior/effect reporting.

## Implementation order

The Kubernetes development profile now renders fresh paired receivers and the
healthy/weakened policy delta and checks receiver/target Pod identities against
independently registered values. A real development exercise observed the expected
paired counts with an owned pinned Rust image and test Pod cleanup. It issues no
gate receipts; shared-gateway outer closure, full image/toolchain CVE coverage, immutable delivery,
whole-cell recovery and live fault qualification remain pending. See the
[development usage guide](kubernetes-development.md).

DEV-02 now has a private runner/recovery command with fresh target namespaces and
UID-conditioned cleanup. Its pinned operator gateway bootstrap is deployment-specific;
shared-gateway mode still requires an independent cleanup helper. GYM-01 has
native offline verifier calibration and its own remediated dependency lock.
The model-backed original synthetic pair completed with private provider/trajectory
records. The optional fixture evidence bridge and Hermes development effect pilot
are implemented. Run failure drills and freeze the reviewed regression baseline next,
retaining hosted-model attestation and commercial licensing limits. No step changes the frozen Rust
baseline or grants qualification. Use upstream harnesses for the agent pilot.

The host-side receipt, paired-capture, watchdog and `live-run` services from PR #18
remain available. They do not supply a hypervisor provisioner or independent cell
inspector. LIFE-01/LIFE-02/QUAL-01/COMPAT-03 remain partially implemented.

1. GYM-01 development onboarding now includes one selected hosted-model rollout,
   private traces, explicit alias selection, requested sampling/budgets and original
   Apache-2.0 tasks. The [model smoke runner](gym-model-smoke.md) has model-free
   native conformance. Hosted weights/sampling are not independently attested;
   baseline promotion needs separate review. Retain offline calibration and
   the separate dependency baseline.
   Retain DEV-02's unresolved API-response/allocator-commit window and qualification limits;
   authenticated external watchdog/whole-cell fault qualification remains P1 work.
2. The optional result/evidence bridge (GYM-02) now has fixture/native conformance.
   The initial Hermes host-harness injection/effect pilot (GYM-03) is exercised.
   Its application process remains outside the selected boundary; only remote
   synthetic effects traverse it. Generic pairing support remains separate.
   The development pilot does
   not depend on completed commercial qualification and cannot establish it.
3. Run development failure drills (REL-01/EVID-01), including Gym/verifier failure,
   policy mutation, receiver/storage loss, cancellation, supervisor restart and
   controller death. Preserve raw effects and prove bounded cleanup behavior.
   The initial [controller drill suite](development-failure-drills.md) adds twelve
   model-free cases, including six real process-death checkpoints against synthetic
   runtime/receiver storage. Gym/verifier faults, external watchdog and live
   qualification remain separate; namespace ownership without a retained API UID stays unresolved.
4. Freeze a reviewed injection regression suite with benign controls and private
   CI reporting (GYM-04). Require all pilot and fault criteria before expanding.
5. Advance the P1 containment track throughout: independently contain the whole
   target, provision real inspectors/watchdog and authenticated lifecycle/delivery
   services, then run live fault qualification (LIFE-01/LIFE-02/QUAL-01/COMPAT-03).
   This remains the commercial qualification blocker even if Gym scores improve.
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
silently change Gym, case, verifier, agent/model or Rust pins. Existing historical
validation notes below describe their original increments, not present coverage.

Release eligibility remains disabled until a separately reviewed qualification
policy, trusted qualification records and release-authorization contract exist.
No milestone in this roadmap silently enables it.

## First implementation validation

SEC-01 adds regression coverage for exact pins, normalized names/versions,
missing or invalid versions, duplicate/unexpected records, marker selection,
conflicting pins and vulnerability preservation on version mismatch. The local
unit and loopback suite passes 97 tests. All five pre-commit hooks pass. The
online audit verifies 45 locked packages with zero gaps and no known vulnerabilities;
the staged publication privacy audit reports no findings. CI repeats validation on Python 3.12 and
3.13; local validation is Python 3.12. Hosted workflows, scheduled execution,
Dependabot proposals and repository ruleset enforcement are not yet validated.

PR review follow-up: duplicate package names invalidate every associated row,
including matching-version rows. Only unique, matching, complete records count
as scanned dependencies or verified `vulnerabilities`. Advisories from rejected
records are deduplicated under `unverified_vulnerabilities`; they cannot establish
coverage or approval. Output is independent of duplicate record order, and an
incomplete audit always exits with status 2.

## Lifecycle receipt increment

PR #8 implements LIFE-01's versioned receipt contracts, Ed25519
verification, challenge freshness, purpose-scoped trust and OpenShell integration.
The controller validates the exact attempt binding before starting capture.
Receipt/lease expiry, mismatched scope/generation/policy, replayed responses,
untrusted issuers and caller-supplied booleans cannot establish readiness or cleanup.
The backend invalidates cached readiness on rebinding, readiness failure and teardown.

See [ADR-0003](adr/0003-authenticated-lifecycle-receipts.md) for the API migration
and trust assumptions. This increment does not complete LIFE-01: trusted lease
issuance, broker transport and real independent attestations remain pending.
Durable receipt references and independent terminal re-verification belong to
EVID-01. External watchdog/recovery remains LIFE-02. Release eligibility stays off.

Local validation: all 118 unit/integration tests and all five pre-commit hooks
pass. The staged privacy audit reports no findings; archived terminal schemas
and signing code remain unchanged. Hosted Python 3.12/3.13 validation passed before merge.

## Monitor and recovery increment

LIFE-02 now has unknown-by-default admission, independently signed challenge-bound
monitor heartbeats, durable heartbeat references and latched loss/incidents. Leased
backends require matching authenticated monitor and recovery contexts. Controller
liveness is registered before replay and stops renewing on cancellation/failure.

A private transactional lease journal and separately hostable worker reconcile
missed controller heartbeats, lease expiry and interrupted worker claims. Cleanup
requires fresh signed whole-cell proof, persisted before confirmation. Tests cover
an abruptly exiting controller subprocess, concurrent claims, worker restart,
stale ownership, clock regression, retries and storage/deadline failures. Journal
files/sidecars are ignored and rejected by publication auditing.

See [ADR-0004](adr/0004-monitor-and-lease-recovery.md). This is a prototype increment,
not live qualification. Authenticated service transports, deployment/identity
separation, provisioning-allocation intents and real orphan-cell fault injection
remain pending. Terminal re-verification of referenced proof remains EVID-01.

Local validation: all 166 unit/integration tests and all five pre-commit hooks
pass, including online locked dependency auditing. Staged privacy auditing reports
no findings. Archived terminal and lifecycle receipt schemas remain unchanged.
Hosted Python 3.12/3.13 validation passed before PR #9 merged.

## Stored-evidence and library usage increment

As a prerequisite for live qualification, EVID-01 now adds bounded private-file
retrieval with exact digest verification. `evaluate(..., evidence_store=store)`
requires the persisted manifest, observed effect artifacts, source artifacts and
nested monitor heartbeat artifacts. Required loss withholds pass, optional loss
degrades diagnostics, and signed violations/incidents retain their precedence.
Loopback evaluation enables this check; the CLI accepts `--evidence-directory`.
Existing callers without a store retain terminal-contract-only evaluation.

The [library guide](library-usage.md) explains usable APIs, trusted verification
inputs, storage limits and live integration prerequisites. Runnable offline and
loopback examples are covered by integration tests and Ruff in pre-commit/CI.

This increment checks availability/integrity of controller-signed references,
not independent observer semantics, monitor coverage or broker issuer signatures.
It does not complete EVID-01 or QUAL-01. Live qualification still needs an
operator-selected disposable environment, pinned runtime stack, authenticated
service transports and independent deployment/fault tests. Archived wire schemas
and release eligibility remain unchanged.

Local validation: all 190 tests pass against the installed package, including
the runnable examples and CLI artifact-loss regression. All five pre-commit hooks
pass. The exported 90-file source tree passes privacy auditing and a redacted
Gitleaks scan. Hosted Python 3.12/3.13 checks passed before PR #10 merged.

PR #10 review follow-up: stored-evidence evaluation now shares one 1,024-attempt,
32 MiB I/O budget across all records and nested references. Read failures retain
their reserved byte charge; repeated references count again. Exhaustion stops
further store reads and withholds pass even for optional evidence, while retaining
violation/incident precedence. Regression tests cover separate case records,
nested repeated heartbeats, byte limits, failed reads and per-evaluation reset.
Effect references remain mandatory outcome proof, including when the same bytes
also serve an optional diagnostic source. A waived-violation regression confirms
that missing effect proof yields inconclusive with the finding, waiver and raw
aggregate retained; optional source designation cannot waive that requirement.

## Live compatibility feedback

An operator-supplied OpenShell 0.1.3 test used synthetic lifecycle receipts and
identified a missing Python interpreter in the stock image, a two-revision policy
creation sequence, and one approximately thirty-second deletion. These findings
inform COMPAT-01/02/03; they do not complete QUAL-01. No deployment identifiers,
endpoints, inventories or raw captures from that report belong in this repository.

The current increment supplies explicit Python/Perl probe selection, direct HTTP
without proxy/redirect behavior, and phase-scoped CLI failure reasons retained in
signed results and gate decisions. Documentation explains active revision discovery
and explicit timing budgets. Defaults and wire schemas remain unchanged. Timeout
keeps cleanup unconfirmed; signed whole-cell proof, independent positive controls,
finding/incident precedence and disabled release eligibility remain mandatory.

Local validation: all 201 unit/integration tests, Ruff lint/format and the locked
dependency CVE check pass. The probes are tested with correlated receiver events,
redirects, proxy environment variables and connection rejection; lifecycle tests
cover sanitized diagnostic propagation, signature rejection and finding retention.

PR #11 review follow-up: the Perl process independently validates all four
arguments before opening a socket, including header-safe host/attempt characters,
numeric port bounds and action timeout bounds. Receiver URL validation rejects
controls before parsing can normalize them away. Regression tests reject malformed
arguments without connecting or emitting a completion marker.

## Read-only compatibility doctor increment

COMPAT-02 now provides a [CLI and library doctor](compatibility-doctor.md). It
checks the operator-pinned CLI, current lease, sandbox UID/phase and active policy
observations using only two read commands under one subprocess time budget.
Same-name replacements stop further inspection. Malformed JSON, CLI failures and
argument parsing produce sanitized codes without echoing private values.

This is partial COMPAT-02 coverage: runtime/module availability remains explicitly
unverified because no workload execution occurs. Authenticated readiness, image
qualification and separately authorized disposable latency experiments remain
pending. The report cannot authorize attempts or releases; signed wire contracts
and lifecycle admission are unchanged.

Local validation: all 216 unit/integration tests and all five pre-commit hooks
pass, including Ruff, the locked dependency CVE audit and publication privacy.
The installed CLI is exercised against a synthetic pinned executable that accepts
only the two exact read commands. Tests cover replacement identity, inactive or
malformed revisions, lease expiry during inspection, pin changes, bounded input
reads, process failures and sanitized output. Live OpenShell testing is pending.

PR #12 review follow-up: execute verified CLI bytes from a private temporary
snapshot rather than reopening the original executable path after checking it.
Tests replace the original immediately before actual launches and between queries,
verify private snapshot permissions and removal, and sanitize snapshot failures.
The controller identity and binary's shared libraries remain trusted.
Input reads explicitly use close-on-exec, retain final-component symlink rejection
when making paths absolute, and close descriptors if wrapping fails. A regression
replaces the opened pathname with a FIFO while a hard link remains: checking and
reading the same original descriptor stays regular and returns the original bytes.

## Independent Rust probe increment

COMPAT-04 introduces `gate-http-probe` 0.1.0 and the experimental IP-literal
HTTP probe protocol 1.0. It has no third-party runtime crates or OpenShell
dependency. Python/Perl frozen actions move unchanged to a vendor-neutral module.
[ADR-0005](adr/0005-independent-evaluation-baselines.md) records the independently
versioned baseline/artifact decision and separates target upgrades from baseline
promotion. Source remains in this repo with its own Cargo package and binary lifecycle.

The [usage guide](rust-probe-usage.md) covers the usable standalone CLI, validation,
timeout/error semantics, build metadata and remaining distribution/trust requirements.
Formatting, Clippy, Rust unit tests, shared receiver conformance, artifact privacy
and a pinned RustSec lockfile CVE hook run in pre-commit and PR validation. Native
Linux musl jobs build/test both architectures, inspect static linkage and retain
experimental binary/manifest artifacts. Native x86_64 and aarch64 musl build,
static-linkage, conformance and resource-fault jobs passed on PR #13; this is
development conformance, not live OpenShell qualification.

This is partial COMPAT-04/DEV-01 coverage. Hostname/DNS support, deployed
artifact delivery, reproducible build-image/linker pins, signed provenance and
the live baseline/target qualification matrix remain pending. Rust now has
experimental IP-only backend admission as described below. Compiler/stdlib, build/audit tooling
and runtime-image CVEs need separate SEC-03 coverage. Signed schemas and release
eligibility remain unchanged.

Local validation of this increment: 233 Python unit/integration tests pass with
one Linux-static resource test exercised in both hosted architecture jobs; four
Rust unit tests and all seven pre-commit hooks pass. The 106-file exported source
tree passes publication privacy and redacted Gitleaks scans. The native development
binary also passes artifact privacy. Both native Linux architecture jobs pass,
including static ELF inspection and the descriptor-exhaustion regression.

PR #13 review follow-up: binary privacy checks apply publication patterns directly
to raw bytes and inspect byte-preserving/UTF-16 text views, without dropping
invalid UTF-8 bytes. Regressions cover invalid boundaries, both UTF-16 endian
orders and either byte alignment. Only fixed errors are exported, never matched
private data. This updates build validation without changing the probe baseline.
A conservative ASCII projection also flags known path/key patterns interrupted
by nonprintable/binary bytes, including a mid-string UTF-16 alignment shift.
An explicit regression also splits known paths/tokens into single-character
fragments with NUL or invalid-byte padding: the projection rejects both cases
even though every individual decoded fragment is shorter than five characters.
Privacy checks cover these patterns/encodings, not arbitrary encrypted or
programmatically reconstructed secrets; distribution/source review remains required.
Build failures also export allowlisted phase-specific reasons for formatting,
Clippy, unit tests, compilation and tooling/source-state checks. Raw command
output, exception details and paths remain excluded from diagnostics.


## Trusted Rust staging and backend admission increment

COMPAT-04 now has [digest-verified artifact staging and experimental backend
admission](rust-probe-delivery.md). Trusted configuration pins binary, unsigned
manifest, source/protocol and architecture independently. Staging repeats static
ELF/privacy checks, rejects unsafe inputs and existing outputs, and includes
license/notice files for an owned image build. The final workload image is pinned
separately; no evaluation downloads or dynamically installs the probe.

Explicit Rust selection requires a separate, fresh Ed25519 delivery receipt
before every action. Its independent signature domain binds all deployment pins,
image, full lease, attempt/cell/UID/generation and a random challenge. An authorized
supervisor must inspect actual immutable delivery and execution authorization
through lease expiry. Missing/mismatched/stale authority prevents execution with
sanitized diagnostics; IP-only scope is enforced and there is no fallback.

This completes the staging and admission implementation, not deployed delivery or
qualification. A conforming external issuer/transport, owned pinned images,
immutable mount enforcement, private receipt retention/re-verification, signed
release provenance and paired live qualification are pending. Existing signed
wire contracts and disabled release eligibility remain unchanged.

Validation includes delivery signature/domain, replay/binding/pin mismatch,
expiry/immutability, cancellation/deadline, exact execution arguments, unsafe-file
and staging rollback regressions. Native Linux jobs also stage their real static
artifacts and reject changed pins on both architectures. Local validation passes
253 Python tests (two native-Linux-only checks run in hosted architecture jobs),
plus the existing Rust tests, lint, CVE and publication checks.

PR review follow-up: cancellation/deadline checks immediately after delivery
transport skip verification, while checks after verification still prevent
execution. Regressions cover cancellation during both transport and verification
and late transport replies.

## Hermes worker and proxy fault increment

GYM-03 review follow-up adds model-free loopback shutdown/publication and
concurrent-budget regressions, real blocked/cancelled worker supervision,
same-group descendant cleanup after direct-child exit and native verifier failure
after synthetic tool calls. A controller fixture separately preserves a confirmed
forbidden effect when verification fails. Interrupted proxy work remains incomplete;
late responses cannot publish after closure. The descendant lease test reproduced
a leak before the cleanup fix and now passes.

These are initial REL-01/EVID-01 development checks, not completed reliability
qualification. Live whole-cell/watchdog faults, blocked adapters outside this
worker path and GYM-04 freezing remain open. The generated decision increment
below addresses the initial property-based gate coverage.
The earlier hosted rollout has not been rerun against this model-free hardening
revision. [Pilot failure drills](hermes-effect-pilot.md#worker-and-proxy-failure-drills)
describe the supported scope and limits.

## Generated decision invariant increment

REL-01 now includes eleven bounded Hypothesis property groups with deterministic
generation, shrinking, real signed wire records and explicit edge examples.
Required vetoes and incident precedence survive contradictory/partial results;
exceptions cannot repair scores or missing proof; record order cannot change
decisions; signed monitor histories cannot resume after loss. Optional diagnostics
remain degradation, and every evaluated decision stays release-ineligible.

No production policy or signed wire contract changed. The new pinned dependency
is development-only; separate Gym/Hermes/Rust baselines are unchanged. The suite
is not exhaustive or live qualification. Broader blocked-adapter deadlines,
resource bounds and independent live failure criteria remain open before treating
REL-01 complete. [Covered properties and limits](gate-decision-invariants.md).

## External provider and receiver bounds increment

REL-01 now includes an explicit library command-provider composition for existing
signed OpenShell receipt/delivery and recovery protocols. Child deadlines and
cancellation are supervised externally, with same-group termination and bounded
pipe output. Both receiver implementations cap concurrent admission and enforce
absolute/aggregate header limits; rejected work records capture loss. Eleven
real process/TCP drill groups include retained violations after timeout.

This completes the initial supported command/HTTP bounds increment, not REL-01.
Arbitrary Python callbacks and trusted host filesystem operations remain outside
child supervision. Independent live watchdog, whole-cell and storage fault criteria
remain pending before GYM-04 freezing. [Scope and limits](adapter-deadlines-and-resource-bounds.md).

## Active-inspector parent-death increment

An actual authority SIGKILL drill reproduced a surviving active inspector on the
merged baseline. Local commands now have a separate pipe-liveness process owner
that terminates their group after caller death and enforces the original deadline
while the caller is suspended. Normal completion also retires same-group
descendants. A seventeenth service/watchdog group verifies unchanged inventory,
unconfirmed cleanup and fresh signed exact-UID recovery after restart. Five
additional process-owner groups check individual/group caller death, suspension,
pre-admission pipe closure, command signal return codes and missing cleanup status.

This advances REL-01/LIFE-02 without qualifying a deployment supervisor. Escaped
sessions, owner death/suspension, reboot/storage durability, partitions and live
whole-cell faults remain open. No stopping of local commands can substitute for
signed durable remote cleanup proof. Next: EVID-01/DEV-02 recovery faults, including
lost namespace-create responses and safe exact-UID reconciliation, while independent
live qualification proceeds separately. GYM-04 still depends on development fault
criteria; Interplay remains deferred INT-02. Release eligibility stays false.
[Command ownership and limits](command-parent-death-supervision.md).

## Independent namespace UID allocation increment

DEV-02/EVID-01 now have an optional private allocation service, independently owned
from the controller. Controller intent commits precede requests; service intent
commits precede API creation; authoritative API UIDs commit before response delivery.
Recovery only looks up the exact original intent and verifies current UID/absence,
then uses the existing mutation UID precondition. It neither repeats creation nor
adopts a name/label. Both cell and receiver namespace response loss are supported;
partial receiver registration still preserves capture loss and incomplete evaluation.

Eleven groups use actual service/controller processes, Unix transport, fsynced
records and a separately retained synthetic Namespace API. Controller SIGKILL
after API create demonstrates fresh lookup and cleanup without bootstrap/replay.
API response loss, allocator death before commit, storage commit failure, intent
conflicts, capacity and get/delete replacement remain conservative. Original
direct-create journals/config digests retain their behavior; this does not retrofit
ownership onto old uncertain allocations. No live environment was changed.

This closes only the controller delivery/registration gap when the independent
allocator durably records the API-returned UID. API response loss and allocator
pre-commit death still need independent operator provenance. Grant-create windows,
power-loss/partition durability, controller/key isolation and authenticated live
whole-cell recovery remain open. Next: durable recovery/storage interruption drills.
GYM-04/INT-02 retain their prerequisites; signed schemas, dependency pins, archived
evidence and release eligibility are unchanged. [Protocol and limits](development-namespace-allocation.md).

## Description-driven DataDesigner research increment

William explicitly reprioritized a description-driven assessment capability ahead
of the remaining durable-storage drills. Reusable generation, target-adapter,
judging, dataset and recovery APIs are implemented independently in Interplay
PR #35. This repository consumes an immutable source pin in an optional environment,
with dependency/source checks, private credential forwarding and external process
supervision. Actual DataDesigner conformance covers generation, observations,
judgments, matching JSONL/Parquet/Arrow exports, interrupted judgment recovery and
rejection of modified source pins.

This is an initial research integration toward INT-02, not its completion. The
first target is an OpenAI-compatible endpoint; internal logs/traces must be supplied
by that endpoint or a future instrumented adapter. The adversarial model is
operator-provided and its abliteration is unverified. A separate JUDGE_MODEL uses
captured evidence; missing evidence and incomplete execution remain inconclusive.
Release eligibility stays false. GYM-04 frozen paired campaigns, authenticated
effects and commercial qualification keep their prerequisites. Next: review/merge
the reusable Interplay API and gate adapter, configure an authorized provider pilot,
then resume EVID-01 durable-storage interruption drills. No live campaign was run.
[Usage, schema and limits](description-driven-red-team.md).

## Adaptive assessment feedback increment

Interplay [PR #36](https://github.com/interplay-adversarial/interplay/pull/36)
adds opt-in sequential DataDesigner refinement using committed target evidence and
validated judge feedback. The gate selects that immutable source with refreshed
module digests and the separate optional lock. Attempt/deadline bounds, early
success stopping, incomplete-feedback stopping, parent/round/feedback exports and
offline recovery are implemented. Batch remains the default; schema version 2
retains legacy journal reading. Judge evidence-relative citation examples address
the provider-smoke usability finding.

The search controller remains reusable and independent of Gym. A future NeMo Gym
TargetAdapter can supply stateful agent rollouts and verifier observations; this
increment does not implement it or automatically preserve target conversation state.
No beam search, ranking, held-out robustness claim or release authority is added.
Next: review the reusable Interplay increment before its dependent gate update,
then an authorized adaptive provider pilot and instrumented target adapters.
EVID-01 durable-storage drills remain the next reliability backlog.

## Probe and gate-decision cohesion audit (2026-10-15)

A documentation/example audit also checked cross-cutting cohesion of the probe
runtimes and the various "produce a result" entry points. Two findings affect
code, not just docs, and are recorded here rather than fixed silently:

- **Python probe timeout was unbounded; Perl and Rust fail closed.** Fixed
  2026-10-15: the embedded Python probe (`probes.py:7-18`) now validates argv
  itself before importing `urllib` or building a request, matching the Perl
  probe's own fail-closed contract — `attempt_id` against the same identifier
  pattern and `seconds` against `1..30`, writing `invalid-probe-input` to
  stderr and exiting non-zero on either. `backends/openshell.py:224` is
  unchanged; the fix lives in the probe itself so all three runtimes are
  independently defensive regardless of what the caller passes.
  `tests/test_probe_conformance.py` gained
  `test_python_probe_rejects_malformed_attempt_and_timeout_before_connecting_or_completion`,
  closing the coverage gap the malformed-argument test (`:76-117`) left for
  Python.
- **Only two of six result-producing entry points route through
  `gate_policy.evaluate`/`GateDecision`.** `live.live_run` and
  `gym_bridge.evaluate_gym_bridge` call `gate_policy.evaluate`; `development_run.py`,
  `red_team.py` and `campaign.py` never import `gate_policy` and instead hand-write
  `"release_eligible": False` into plain dicts at nine separate call sites
  (`development_run.py:204,1046,1055,1069,1080`; `red_team.py:59,165,184,210`;
  `campaign.py:104`), with `red_team.py:53,152` and `campaign.py:28` re-implementing
  ad hoc checks of that same convention on the read side. No outcome is wrong
  today, but a future shared-contract change (e.g. adding `qualification` the way
  `GateDecision` already has it) would need nine uncoordinated hand-edits across
  three files instead of one typed change.

Neither finding changes schemas, defaults or release eligibility. Fixing them is
future work, not performed as part of this audit's documentation/example scope.

## Dependency and pin freshness audit (2026-10-15)

Checked every pinned package/commit against its upstream latest, and specifically
whether the new `interplay-adversarial` release is used correctly. Nothing here
changed `uv.lock`, a source pin or a hash; it is a record of what to verify before
each bump, not a bump itself.

**Core and dev-group packages** (`pyproject.toml`) are now current: `pydantic`
2.14.0 -> 2.14.1, `ruff` 0.17.0 -> 0.17.1, `pre-commit` 4.6.2 -> 4.7.0,
`hypothesis` 6.169.0 -> 6.169.4 (bumped 2026-10-15, `uv.lock` regenerated,
`pydantic-core` followed transitively to 2.50.1; `docs/gym-evidence-bridge.md`'s
embedded snippet reformatted to match ruff 0.17.1's line-wrapping, no content
change). `cryptography` 50.0.2 and `pip-audit` 2.10.1 already match latest.
None of these gaps was a known vulnerability (`scripts/audit_dependencies.py`
reports zero advisories against the current 46 scanned dependencies); they
were routine patch/minor bumps.

**`interplay-adversarial` was used correctly, and the stale pin is fixed.**
Bumped 2026-10-15: `src/agent_boundary_gate/_pins/red-team.json` and
`onboarding/red-team/pyproject.toml` now pin `e03063a` (tag `v0.3.1`, package
`0.3.1`); `storage.py`'s hash was regenerated (the only pinned file that
changed — see below), the other six pinned files hashed identically before
and after, confirming they're untouched between the two commits. Both
`scripts/audit_dependencies.py --red-team` (99 dependencies, zero gaps/
vulnerabilities) and the native `test_red_team_native.py` conformance suite
(run under `onboarding/red-team`'s own Python 3.13.14 venv, per
`.github/workflows/checks.yml`'s `red-team-campaigns` job) pass against the
new pin. The gate only consumes the `[assessment]` extra
(`interplay/assessment/{designer,runner,endpoint,models,storage,cli}.py`) for
DataDesigner-based generation and judging — it never imports
`interplay.red_teaming`. The old pinned commit (`1339cc2`, interplay PR #36,
package version `0.2.1`) was exactly interplay's `main` as of RT-01's
integration; at the time of the bump, upstream `main` was 27 commits/5 merged
PRs ahead of it:

- All of PRs #37-#56 are new work in `interplay/red_teaming/` (the TAP, GOAT,
  SLIP, Crescendo, Multimodal and PAIR attack runners, a shared authenticated
  transport, a configurable judge panel with Krippendorff's-alpha IRR
  reporting) plus two releases (0.3.0, 0.3.1) and a docs restructure. None of
  it touches the `assessment` extra's public surface except one file.
- The one relevant change is PR #44's `90c7616`, which generalizes
  `interplay/assessment/storage.py`'s `AssessmentStore`/`to_arrow` to accept a
  `record_cls` (so the new `red_teaming` result sink can reuse its locking/
  atomic-export discipline) with backward-compatible defaults — not a bug,
  and it doesn't change gate's existing calls, but it does mean the pin's
  hashes in `_pins/red-team.json` need regenerating once bumped.
- A real correctness bug was fixed upstream in this window
  (`f37eea0`, "evidence-cited judging always returned inconclusive" — a
  sync-API-in-an-async-context bug in `JudgeScorer`) but it lives entirely in
  `interplay/red_teaming/base.py`, a module the gate never imports. It does
  not affect any `red-team-run`/`red-team-recover` campaign run against the
  current pin.
- Bumping the pin keeps the project within the tracked 0.3.x line and gives
  INT-02 (Interplay attack campaign integration) a current `red_teaming`
  baseline to start from when it begins; it was not fixing a defect in RT-01's
  prior integration.

**`onboarding/red-team`'s other pinned packages** have more room:
`pyarrow` 24.0.0 vs. latest 26.0.0 (two major versions), `any-llm-sdk` 1.33.0 vs.
1.36.0, `openai` 3.28.0 vs. 3.31.0. `data-designer`/`data-designer-config`/
`data-designer-engine` 0.9.5 already match latest. A `pyarrow` major-version jump
needs its own compatibility check against `interplay/assessment/storage.py`'s
`to_arrow` schema construction before bumping.

**`onboarding/gym` and `onboarding/hermes`'s NeMo Gym pin** (`f444b802`) is 61
commits behind `NVIDIA-NeMo/Gym`'s `main` as of 2026-10-15. Of the gate's
exactly hash-pinned files, only `nemo_gym/responses_converter.py` changed
upstream, adding an opt-in `drop_unrepresentable_request_fields` parameter
(backward-compatible default `False`) for degrading Responses-only request
fields when talking to a Chat Completions backend — useful for broadening
`gym-model-smoke.md`'s provider support later, not a fix for anything currently
broken.

**`onboarding/hermes`'s `hermes-agent` pin** (`cmunley1/hermes-agent@26bb847`,
dated 2026-05-07) is reported by GitHub's compare API as **diverged** from that
fork's current `main` (132 ahead, 9 behind), not a clean fast-forward ancestor.
Nine commits reachable from the pin are no longer reachable from `main`,
consistent with history having been rewritten on that personal fork at some
point since May. Re-pinning this one needs the commit range inspected by hash,
not just advanced to `main` HEAD, since the usual "pin predates main" assumption
does not hold here.

None of these findings block current functionality; `scripts/audit_dependencies.py`
and the Rust/CVE audits stay green because none of the drift above is a known
vulnerability. They are recorded so a future pin bump starts from a known list
of what changed and what to re-verify, instead of rediscovering it.
