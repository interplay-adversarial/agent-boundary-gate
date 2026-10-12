# Agent Boundary Gate

An evidence-based gate for agent application controls and runtime enforcement
boundaries. Agent adapters, boundary backends and independent observers compose
through signed, versioned contracts. OpenShell is the first implementation backend.

**Prototype:** release authorization remains disabled. OpenShell has not been
qualified against a live target. Hermes, OpenCode and OpenClaw adapters are planned.

Start with the [Python library guide](docs/library-usage.md) for supported APIs,
runnable offline/loopback examples, stored evidence verification and live integration prerequisites.

## Implemented

- Versioned CaseSpec, EvidenceManifest, RunResult, GateDecision and target profiles.
- Frozen replay, component identity/generation checks and positive controls.
- Independent denied-egress receiver observations and private evidence persistence.
- Ed25519 authentication using externally supplied trusted verifier keys.
- Incident precedence, retained violations, required-evidence checks and veto-only exceptions.
- Bounded execution, cancellation, teardown receipts and terminal records.
- An OpenShell CLI backend and a loopback simulation backend.
- Challenge-bound signed broker receipts with scoped trust and lease/attempt checks.
- Unknown-by-default monitoring, signed heartbeat freshness and latched loss/incidents.
- A private durable lease journal and restartable cleanup recovery worker.

All built-in backends and adapters live in this repository initially. See
[ADR-0002](docs/adr/0002-portable-adapters-and-repository-boundaries.md) for the
architecture and criteria for extracting independently maintained adapters.

## Develop and validate

Requires Python 3.12+ and [uv](https://github.com/astral-sh/uv).

```sh
uv sync --frozen --no-editable
uv run --no-sync pre-commit install
uv run --no-sync agent-boundary-gate adapters
uv run --no-sync agent-boundary-gate demo --scenario healthy
```

The pre-commit hooks and pull-request checks run:

- Unit and loopback integration tests.
- Ruff lint and formatting checks.
- A pip-audit CVE check for all applicable locked runtime and development dependencies.
- Publication privacy checks. PR checks also scan Git history with Gitleaks.

Run the same hooks manually:

```sh
uv run --no-sync pre-commit run --all-files
```

The CVE check requires access to public package advisory services. Vulnerabilities,
skipped dependencies, incomplete audit coverage and service failures block the check.
No vulnerabilities are suppressed by a repository allowlist.

Individual commands:

```sh
uv run --no-sync ruff check src tests scripts examples
uv run --no-sync ruff format --check src tests scripts examples
uv run --no-sync python -m unittest discover -s tests -q
uv run --no-sync python scripts/audit_dependencies.py
uv run --no-sync python scripts/audit_publication.py
```

The privacy audit reads the Git index; stage the intended changes before running
it. It emits only file names, line numbers and rule identifiers. A private operator
denylist can be supplied with `--deny-file`; keep that file outside the repository.

## Exercise the capture path

```sh
uv run --no-sync agent-boundary-gate local-run \
  --case examples/denied-egress-v1.json --output artifacts/healthy
uv run --no-sync agent-boundary-gate local-run \
  --case examples/denied-egress-v1.json --output artifacts/weakened --weakened
```

Both commands use real loopback HTTP receivers. The healthy fixture simulates
denial; the weakened fixture sends a request to the forbidden receiver. Policy
and containment monitoring are synthetic. This exercises capture, persistence
and authentication, not live OpenShell enforcement or observer tamper resistance.

Every decision has `qualification: m0-prototype` and `release_eligible: false`.
Prototype exit codes are pass `0`, criteria failure `1`, inconclusive `2`, incident `3`.
These exit codes do not authorize releases.

Captured packets, logs, credentials and key files are excluded from Git. Evidence
directories must be private (`0700`); artifacts use `0600`. Private fixture packets
contain ephemeral public keys for inspection; those keys are not CI trust anchors.
Signing private keys are generated in memory and are not persisted by the fixtures.

## Verify evidence

```sh
uv run --no-sync agent-boundary-gate verify \
  --dispatch dispatch.json --records records.json \
  --signer verifier-id --public-key verifier-public-key.bin \
  --evidence-directory artifacts/evidence --job-complete --server-aggregate 1.0
```

Supply the dispatch snapshot and 32-byte Ed25519 public key through trusted CI
configuration, independently of the returned records. The gate checks signed
bindings, source inventory, freshness, cleanup, raw aggregation and exceptions.
Exceptions waive only a named required-case veto; they never change the aggregate.
`--evidence-directory` also requires digest-checked retrieval of referenced private
artifacts. Without it, verification checks terminal contracts only. Artifact integrity
does not establish live observer qualification or independent issuer verification.

Schema `0.2` uses the signature domain `agent-boundary-gate/terminal-record/0.2`.
Canonicalization is project-specific sorted, compact UTF-8 JSON; it does not claim
RFC 8785 interoperability. Historical `0.1` schemas and unsigned synthetic examples
are retained. `verify-legacy` authenticates archived records using their original
schema and signature domain, without granting release authority.

## Layout and qualification

```text
src/agent_boundary_gate/
  contracts.py, auth.py, gate_policy.py, lifecycle.py
  backends/       runtime enforcement adapters
  agents/         application adapter protocol
  observers/      independent effect verification
  legacy/         read-only historical authentication
schemas/          versioned wire schemas
examples/         synthetic contract examples
 tests/           unit, integration and audit regression tests
```

[Dependency references](dependencies.json) contain only public upstream URLs and
the OpenShell source contract reference. They are not qualified runtime pins.
Whole-target containment, live broker/monitor transports, an independently deployed watchdog,
remote collectors, restricted RustFS/MLflow storage and EvalHub integration remain
qualification work. See [ADR-0001](docs/adr/0001-rig-topology.md) and the
[live-rig handoff](docs/live-rig-handoff.md).

The [lifecycle receipt ADR](docs/adr/0003-authenticated-lifecycle-receipts.md) documents
the broker protocol, backend API migration and remaining trust/transport work.
The [monitor/recovery ADR](docs/adr/0004-monitor-and-lease-recovery.md) documents
explicit monitor admission, lease recovery and deployment limits.

See the [prioritized improvement roadmap](docs/improvement-roadmap.md) for acceptance
criteria, implementation status and qualification blockers.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
