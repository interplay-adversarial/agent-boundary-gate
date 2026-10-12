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

Local validation: all 183 tests pass against the installed package, including
the runnable examples and CLI artifact-loss regression. All five pre-commit hooks
pass. The exported 90-file source tree passes privacy auditing and a redacted
Gitleaks scan. Hosted checks are pending for this increment.
