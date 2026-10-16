# Standalone experimental Rust HTTP probe

`probes/http/` contains the independently versioned `gate-http-probe` Cargo package
(`0.2.0`), using protocol `agent-boundary-gate/http-probe/1.0`. It has no third-party
runtime crates and no OpenShell SDK/CLI dependency. Its source and conformance tests
live here; its compiler, protocol and binary are pinned separately from a boundary
distribution. See [ADR-0005](adr/0005-independent-evaluation-baselines.md).

## Build and use

From a source checkout, install Rust/Cargo **1.98.1**, with rustfmt and Clippy, then:

```sh
uv sync --frozen --no-editable
uv run --no-sync python -m scripts.rust_probe_build --check
probes/http/target/release/gate-http-probe --version
probes/http/target/release/gate-http-probe 127.0.0.1 8080 probe-test 1
```

The last example targets an operator-controlled loopback receiver; provide your
actual test receiver at runtime. Inputs are exactly four arguments: an IPv4/IPv6
literal without brackets or scope, or an unbracketed DNS name, matching
`[a-zA-Z0-9:][a-zA-Z0-9.:-]{0,252}` (the same character class as the Python/Perl
probes); decimal port 1–65535; header-safe attempt ID of 1–128 bytes; and integer
timeout 1–30 seconds. The first attempt character must be ASCII alphanumeric;
remaining characters can also be `_ . : / -`.

A hostname is resolved via the host's standard resolver (`getaddrinfo`, through
`std::net::ToSocketAddrs`) on a background thread bounded by the same deadline as
the rest of the attempt; only the first resolved address is tried. A name that
does not resolve, a resolver that never answers within budget and a resolved
address that refuses the connection are the same outcome as far as this probe is
concerned: the attempt still completes (see below), exactly like a direct
connection failure. This is still an experimental baseline distinct from the
first (`0.1.0`) IP-only release: do not compare `0.2.0` hostname/DNS results
against `0.1.0` IP-literal baseline results as equivalent coverage, per
[ADR-0005](adr/0005-independent-evaluation-baselines.md). `OpenShellBackend`
offers explicit, experimental `probe_runtime="rust"` selection for IP-literal or
hostname endpoints with authenticated immutable delivery. See the
[delivery guide](rust-probe-delivery.md). Python/Perl selection remains available;
there is no automatic fallback.

The fixed action sends `GET /probe` directly with `Host`, `X-Gate-Attempt` and
`Connection: close`. It reads at most one byte and closes the connection. There
are no proxy, redirect, TLS, arbitrary path/body or resolver options. A single
monotonic deadline covers connect and each write/read retry; remaining time is
recomputed for every operation. Retain external controller/sandbox termination:
OS scheduling and blocking syscall timeout behavior are not hard real-time guarantees.

Exit 0 and `agent-boundary-gate-probe-complete:<attempt>` mean the request attempt
completed, including network rejection or timeout. They never prove allowed or
denied egress. Independent correlated receivers and positive controls remain
mandatory. Invalid input exits 2 with fixed `invalid-probe-input` stderr and no
completion. Unexpected resource/runtime or socket-configuration failures exit 2
without completion; normal runtime errors use fixed `probe-runtime-failed` stderr.
External termination cannot establish completion or cleanup.

## Artifacts and baseline identity

The builder checks the exact Rust/Cargo version, rejects additional dependency
or lockfile entries, builds offline/locked, remaps checkout paths, strips release
symbols and applies publication patterns to raw bytes and UTF-16/byte-preserving
string views. A conservative printable-ASCII projection flags known path/key
patterns interrupted by binary padding or invalid bytes; URL inspection uses
separate strings to avoid inventing hostnames. These checks cover known patterns
and these encodings, not arbitrary encryption or programmatic secret reconstruction.
Suspicious patterns fail the build and require review. Generated
files stay under ignored `target/`; do not commit binaries or private captures.
It writes an **unsigned** `gate-http-probe.provenance.json` beside the binary with
protocol/source/binary digests, package/compiler versions, target and source commit.
A dirty checkout reports `source_commit: null` plus the actual source digest;
it cannot imply that its bytes match the parent commit.
Build/check failures exit 2 with a fixed phase-specific reason, such as
`rust-probe-format-failed` or `rust-probe-unit-tests-timeout`. Raw compiler output,
paths and exception details are excluded; input/artifact errors use a generic code.

This is build metadata, not authenticated supply-chain provenance. Supply expected
digests independently from trusted release configuration. Builds are not yet
claimed reproducible across build hosts: linker/OS/build-image identity and signed
release provenance still need qualification. A native macOS development artifact
is not a Linux delivery artifact.

CI builds and executes shared Python/Perl/Rust conformance on native Linux x86_64
and aarch64 runners using musl targets. The builder inspects ELF architecture,
rejects an interpreter and `DT_NEEDED` libraries, and requires privacy scanning
before retaining the experimental binary, manifest, Apache license and notice as
seven-day CI artifacts.
Cross-compilation alone does not establish runtime conformance. To build on a
matching native Linux host with the pinned toolchain and musl linker:

```sh
uv run --no-sync python -m scripts.rust_probe_build --check --target x86_64-unknown-linux-musl
```

Use the corresponding aarch64 target on that architecture. Install the verified
artifact through a controlled rig/image build before sandbox creation and pin
the final image separately. Do not depend on an OpenShell stock image including
the probe or dynamically install it from the network during an evaluation.
The [staging tool and delivery receipt contract](rust-probe-delivery.md) implement
digest verification and backend admission. Actual image provisioning, immutable
mount enforcement, independent receipt issuance and executable authorization
remain backend-specific deployment/qualification work.

## Validation and vulnerability coverage

Pre-commit and PR checks include Rust formatting, Clippy, unit tests, shared
receiver conformance and artifact privacy. Install the pinned vulnerability tool:

```sh
cargo install cargo-audit --version 0.22.2 --locked
uv run --no-sync python -m scripts.audit_rust_probe
uv run --no-sync pre-commit run --all-files
```

The RustSec hook requires a fresh advisory database, matching auditor version,
complete lockfile count and unfiltered results. Known vulnerabilities, warnings,
tool/service errors, stale data and incomplete reports fail closed. The probe
currently has **zero third-party crates**. Cargo auditing covers lockfile packages;
it does **not** establish Rust compiler/standard-library, linker, audit-tool or
runtime-image CVE coverage. Those remain separate SEC-03 maintenance/qualification
work, alongside compiler update review. The Python locked dependency CVE hook
continues to run as well.

Tests exercise IPv4/IPv6 correlated requests, hostname resolution and connection
(including across all three probe runtimes), proxy isolation, no redirects,
rejected connections, invalid inputs before networking, stalled responses and
external cancellation. Local validation does not establish live boundary enforcement
or commercial release readiness. `release_eligible` remains false.
