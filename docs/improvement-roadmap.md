# Agent Boundary Gate improvement roadmap

Recorded: 2026-10-11. Scope: portable gate core, built-in adapters and qualification.

The project remains an M0 prototype. All decisions retain
`qualification: m0-prototype` and `release_eligible: false`. Completing a local
implementation or CI run does not establish live qualification or release authority.
Built-in adapters remain in this repository under [ADR-0002](adr/0002-portable-adapters-and-repository-boundaries.md).

## Priorities and acceptance criteria

| ID | Priority | Improvement | Acceptance criteria | Status |
| --- | --- | --- | --- | --- |
| SEC-01 | P2, first implementation | Exact-version dependency auditing | Every applicable locked runtime/dev package name and version is audited; duplicates, extra packages, missing versions, mismatches and skipped entries fail closed; failures preserve reported advisories. | Implemented on work branch; regression tests pass |
| SEC-02 | P2, first implementation | Continuous security checks | Daily and manual audits, Python 3.12/3.13 PR validation, weekly uv/Actions update proposals and a stable aggregate check; automation becomes active after merge. | Workflow/configuration implemented; hosted runs pending |
| SEC-03 | P2 | Merge enforcement and supply-chain coverage | Require the aggregate check in a repository ruleset after confirming its hosted status; enable security updates and dependency review; audit build tools, supported platform markers and runtime images separately. | Planned |
| LIFE-01 | P1 | Authenticated lifecycle receipts | Verify trusted signer, freshness, attempt/lease identity, sandbox UID/generation and policy digest for readiness and cleanup; reject replayed or mismatched receipts. | Planned; next milestone |
| LIFE-02 | P1 | Independent monitoring and recovery | Monitoring begins unknown; an authenticated healthy handshake is required before execution; external watchdog and lease expiry reconcile controller crashes and confirm idempotent cleanup. | Planned; depends on LIFE-01 |
| QUAL-01 | P1 | Live OpenShell qualification | Independent allowed/forbidden receivers demonstrate positive controls and boundary effects; policy mutation, telemetry loss, cancellation, restart and cleanup faults cannot create approval; publish only sanitized qualification summaries. | Planned; depends on LIFE-01/LIFE-02 |
| EVID-01 | P2 | Durable, verified evidence | Persist confirmed violations before finalization; retrieve and verify signed digest references; preserve findings through storage/observer/controller failure; isolate collector/storage authority from workloads. | Planned |
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
