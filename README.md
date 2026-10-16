# Agent Boundary Gate

An evidence-based gate for agent application controls and runtime enforcement
boundaries. Agent adapters, boundary backends and independent observers compose
through signed, versioned contracts. OpenShell is the first implementation backend.

**Prototype:** release authorization remains disabled. OpenShell has not been
qualified against a live target. OpenCode and OpenClaw adapters are planned.

Start with the [tools, library APIs and use-case guide](docs/tools-and-use-cases.md)
for workflow selection across boundary evidence, adaptive assessments and native
agent testing. Use the [Python library guide](docs/library-usage.md) for supported APIs,
runnable offline/loopback examples, stored evidence verification and live integration prerequisites.

## Implemented

- [Description-driven red-team research](docs/description-driven-red-team.md)
  through separately pinned Interplay and NVIDIA NeMo DataDesigner: adversarial
  probe generation, separate model judging, private JSONL/Parquet/Arrow datasets
  and supervised interrupted-run recovery. Research verdicts grant no release authority.
- Versioned CaseSpec, EvidenceManifest, RunResult, GateDecision and target profiles.
- Frozen replay, component identity/generation checks and positive controls.
- Independent denied-egress receiver observations and private evidence persistence.
- Ed25519 authentication using externally supplied trusted verifier keys.
- Incident precedence, retained violations, required-evidence checks and veto-only exceptions.
- [Generated decision invariants](docs/gate-decision-invariants.md) for weighted
  results, incomplete evidence, veto-only exceptions and latched monitor histories.
- Bounded execution, cancellation, teardown receipts and terminal records.
- [Supervised command providers and receiver resource bounds](docs/adapter-deadlines-and-resource-bounds.md)
  with blocked-provider, output-flood, slow-header and admission-loss drills.
- An OpenShell CLI backend and a loopback simulation backend.
- Challenge-bound signed broker receipts with scoped trust and lease/attempt checks.
- Unknown-by-default monitoring, signed heartbeat freshness and latched loss/incidents.
- A private durable lease journal and restartable cleanup recovery worker.
- [Separate service and watchdog process drills](docs/service-watchdog-failure-drills.md)
  cover death/restart, stale claims, identity replacement and unconfirmed storage failures.
- [Command parent-death supervision](docs/command-parent-death-supervision.md)
  terminates active inspector groups after authority death and enforces deadlines
  while the caller is suspended; fresh signed recovery proof is still required.
- A [read-only OpenShell compatibility doctor](docs/compatibility-doctor.md) with sanitized reports.
- An [independently versioned experimental Rust HTTP probe](docs/rust-probe-usage.md),
  with shared Python/Perl/Rust conformance and no OpenShell runtime dependency.
- [Digest-verified Rust staging and authenticated delivery admission](docs/rust-probe-delivery.md)
  for experimental OpenShell execution (IP literal or sandbox-resolved hostname)
  in an operator-owned pinned image.
- An [experimental live workflow](docs/live-workflow.md): verified owned-image
  contexts, private receipt/receiver service transports, a separate watchdog entry
  point, `live-run`, declared fault campaigns and sanitized operator reports.
  Actual provisioning, an independent environment-specific inspector and live
  qualification remain required.
- A [Kubernetes development profile](docs/kubernetes-development.md) for fresh
  paired receivers, controlled policy pairs and independent API inventory checks.
  These development observations issue no gate receipts or release claims.
- A [packaged development runner](docs/development-runner.md) with private
  allocation journals, paired Rust controls, final capture and recovery;
  [disposable target allocation and UID-conditioned namespace cleanup](docs/disposable-development-cells.md),
  with [controller death, storage loss and recovery drills](docs/development-failure-drills.md).
  An optional [independent namespace allocator](docs/development-namespace-allocation.md)
  retains API-returned UIDs before delivery and reconciles controller response loss
  without name-based adoption or retrying uncertain creates.
  Cell execution requires an operator-owned pinned gateway bootstrap; shared-gateway
  execution requires a separately implemented identity-bound cleanup helper.
- [Separate pinned NeMo Gym onboarding](docs/gym-onboarding.md) with offline
  native verifier replay and an independently audited dependency lock.
  A [private model-backed smoke workflow](docs/gym-model-smoke.md) adds bounded
  provider discovery and native harness/tool conformance; one hosted-model smoke
  completed, with boundary evaluation and commercial baseline promotion pending.
- An [optional Gym evidence bridge](docs/gym-evidence-bridge.md) correlates private
  native observations with independently authenticated boundary records. Fixture
  mapping/fault conformance is implemented; authenticated real-agent mapping remains planned.
  A first real-agent effect pilot (initially Hermes, removed 2026-10-16 after its
  upstream dropped pip/uv installability; now being re-attempted with OpenCode)
  remains open — see the [NeMo Gym adoption plan](docs/nemo-gym-adoption.md).

All built-in backends and adapters live in this repository initially. See
[ADR-0002](docs/adr/0002-portable-adapters-and-repository-boundaries.md) for the
architecture and criteria for extracting independently maintained adapters.

## Also in this repository: adaptive task runner (unrelated capability)

An [adaptive task runner](docs/adaptive-task-runner.md) drives OpenCode
through NeMo Gym's Harbor coding-task format with a retry/advance/abandon
loop, scoring each attempt via Gym's own reward-profiling output and adapting
the next instruction from a failed attempt. It fills a gap in Gym itself:
Gym's Harbor task-loading machinery generates a run config expecting a
resources server that Gym does not ship (confirmed against both our pin and
upstream's current `main`), so this adds that missing resources server as
new code, discovered via Gym's `--search-dir` rather than vendored into the
installed package.

**This is a separate, unrelated capability — not part of the boundary/egress
gate above.** It carries no gate or release authority, issues no signed
records, and is unrelated to OpenShell policy enforcement; it only happens to
reuse the same OpenCode agent and, optionally, an OpenShell sandbox as a place
to run an agent's generated code. See the linked doc for prerequisites, a
runnable example task and three equivalent ways to configure a run.

## Develop and validate

Requires Python 3.12+, [uv](https://github.com/astral-sh/uv), and Rust/Cargo 1.98.1
with rustfmt and Clippy for source development. Python library consumers do not
need Rust to use the existing APIs. Install the pinned Rust CVE auditor:

```sh
uv sync --frozen --no-editable
cargo install cargo-audit --version 0.22.2 --locked
uv run --no-sync pre-commit install
uv run --no-sync agent-boundary-gate adapters
uv run --no-sync agent-boundary-gate demo --scenario healthy
```

The pre-commit hooks and pull-request checks run:

- Unit and loopback integration tests.
- Ruff lint and formatting checks.
- Rust fmt, Clippy, unit tests, shared probe conformance and binary privacy checks.
- A pinned Cargo/RustSec lockfile CVE audit; compiler/stdlib and images need separate coverage.
- A pip-audit CVE check for all applicable locked runtime and development dependencies.
- A separate CVE audit for the optional Gym onboarding lock and a model-free PR replay.
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
The [NeMo Gym adoption plan](docs/nemo-gym-adoption.md) brings optional
prompt-injection evaluation forward, with separate agent-behavior and boundary-effect
reports. Offline onboarding, model-backed smoke and optional fixture evidence mapping
are implemented. No real-agent effect pilot or Gym agent pairing is qualified.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
