# Agent Boundary Gate improvement roadmap

Recorded: 2026-10-11. Scope: portable gate core, built-in adapters and qualification.

The project remains an M0 prototype. All decisions retain
`qualification: m0-prototype` and `release_eligible: false`. Completing a local
implementation or CI run does not establish live qualification or release authority.
Built-in adapters remain in this repository under [ADR-0002](adr/0002-portable-adapters-and-repository-boundaries.md).

## Priorities and acceptance criteria

| ID | Priority | Improvement | Acceptance criteria | Status |
| --- | --- | --- | --- | --- |
| SEC-01 | P2, first implementation | Exact-version dependency auditing | Every applicable locked runtime/dev package name and version is audited; duplicates, extra packages, missing versions, mismatches and skipped entries fail closed; failures preserve reported advisories. | Merged in PR #2; regression tests pass |
| SEC-02 | P2, first implementation | Continuous security checks | Daily and manual audits, Python 3.12/3.13 PR validation, weekly uv/Actions update proposals and a stable aggregate check; automation becomes active after merge. | Merged in PR #2; hosted Python 3.12/3.13 checks pass; first scheduled runs/update proposals not yet observed |
| SEC-03 | P2 | Merge enforcement and supply-chain coverage | Require the aggregate check in a repository ruleset after confirming its hosted status; enable security updates and dependency review; audit build tools, supported platform markers and runtime images separately. | Planned |
| LIFE-01 | P1 | Authenticated lifecycle receipts | Verify trusted signer, freshness, attempt/lease identity, sandbox UID/generation and policy digest for readiness and cleanup; reject replayed or mismatched receipts. | Receipt verifier/backend increment merged in PR #8; trusted issuance/transport and live attestation pending |
| LIFE-02 | P1 | Independent monitoring and recovery | Monitoring begins unknown; an authenticated healthy handshake is required before execution; external watchdog and lease expiry reconcile controller crashes and confirm idempotent cleanup. | Monitor/journal/recovery increment merged in PR #9; live deployment and orphan-cell qualification pending |
| QUAL-01 | P1 | Live OpenShell qualification | Independent allowed/forbidden receivers demonstrate positive controls and boundary effects; policy mutation, telemetry loss, cancellation, restart and cleanup faults cannot create approval; publish only sanitized qualification summaries. | Planned; depends on LIFE-01/LIFE-02 |
| COMPAT-01 | P1 | Live driver compatibility | Execute a selected frozen probe in the pinned workload image; discover the requested active policy revision; report CLI failure classes without private output; select measured lifecycle budgets. | Python/Perl selection and sanitized diagnostics implemented locally; pinned-image testing and timing measurements pending |
| COMPAT-02 | P2 | Rig compatibility doctor | Read-only checks validate probe prerequisites, pinned CLI/policy JSON and lease context; destructive latency measurements require a separately designated disposable lease and authenticated cleanup. | Read-only CLI/lease/policy inspection implemented; runtime prerequisites reported but unverified, workload/image qualification and latency measurements pending |
| COMPAT-03 | P2 | Supported live entry point | A live-run command composes trusted receipt/monitor/recovery providers and an independent observer; synthetic trust is explicitly segregated and cannot establish qualification. | Planned; depends on authenticated transports and provisioning |
| COMPAT-04 | P2 | Standalone Rust probe | A pinned binary passes shared receiver conformance, bounded DNS/deadline/resource tests and architecture-specific artifact/privacy checks; completion remains separate from outcome proof. | IP-literal prototype, shared tests, build/privacy manifests and native Linux CI implemented; hostname/DNS, trusted delivery, release provenance and live qualification pending |
| EVID-01 | P2 | Durable, verified evidence | Persist confirmed violations before finalization; retrieve and verify signed digest references; preserve findings through storage/observer/controller failure; isolate collector/storage authority from workloads. | Bounded local retrieval and signed-reference integrity increment implemented; independent proof interpretation/issuer verification and remote authority pending |
| REL-01 | P2 | Adversarial reliability | Property-based decision tests, blocked-adapter fault injection, external timeout enforcement and bounded receiver connection/thread resources demonstrate incomplete outcomes under failures. | Planned |
| DEV-01 | P2 | Development and distribution checks | Add type checking, isolated wheel/sdist build and installed-package smoke checks; scan distribution contents for private data and secrets. | Planned |
| PORT-01 | P3 | Second real agent adapter | One of Hermes/OpenCode/OpenClaw passes shared conformance tests with separate agent and boundary identity; unsupported combinations remain explicit. | Planned; agent selection pending |
| INT-01 | P3 | EvalHub integration and reports | Stable result/status mapping, sanitized evidence references, explicit unsupported/incomplete outcomes and actionable explanations; no live qualification implied by integration. | Planned |

P1 marks qualification blockers. P2 marks reliability and engineering controls.
P3 marks expansion. The first implementation tackles SEC-01/SEC-02 because they
are bounded changes that strengthen validation before lifecycle work starts.

## Implementation order

1. Finish SEC-01/SEC-02 and review hosted CI; establish SEC-03 merge enforcement
   only after the aggregate status check exists on the default branch.
2. Define authenticated receipt contracts and trust configuration (LIFE-01),
   without modifying archived signed wire versions.
3. Implement unknown-to-healthy monitoring, external recovery and lease-bound
   cleanup (LIFE-02); add evidence durability and fault tests alongside this work.
4. Qualify a pinned OpenShell target and observer pair in a disposable isolated
   rig (QUAL-01), following the [live-rig handoff](live-rig-handoff.md).
5. Validate portability with one real agent adapter and deliver EvalHub mapping.

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

This is partial COMPAT-04/DEV-01 coverage. Hostname/DNS support, authenticated
artifact delivery, reproducible build-image/linker pins, signed provenance and
the live baseline/target qualification matrix remain pending. Rust is not yet a
supported `OpenShellBackend` runtime selector. Compiler/stdlib, build/audit tooling
and runtime-image CVEs need separate SEC-03 coverage. Signed schemas and release
eligibility remain unchanged.

Local validation of this increment: 229 Python unit/integration tests pass with
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
