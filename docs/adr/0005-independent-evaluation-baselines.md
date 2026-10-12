# ADR-0005: Evaluation baselines independent of boundary distributions

Status: accepted for the prototype. Date: 2026-10-12.

The adversarial stack needs a consistent red-team baseline as boundary runtimes
change. Commercial product robustness requires explicit regression comparisons
and separately qualified target combinations. Availability of an interpreter or
probe in a vendor's stock image must not define our evaluation behavior.

## Decision

Own the probes, action protocols, case definitions, observer semantics and
conformance tests independently of OpenShell distribution releases. Keep source
in this repository initially, following [ADR-0002](0002-portable-adapters-and-repository-boundaries.md).
The Rust probe has its own Cargo package/version, immutable protocol descriptor,
toolchain pin, target artifacts and binary digests. It imports no boundary SDK.
Python/Perl frozen actions now live in `agent_boundary_gate.probes`; existing
OpenShell imports remain compatible without changing their action bytes.

Changing an OpenShell version changes a target qualification entry, not the
baseline automatically. Select baseline revisions explicitly. Record case/probe/
observer/policy revisions and expected artifact digests in trusted evaluation
configuration independently of boundary/runtime/image pins. Promote new baseline
versions through reviewed conformance and regression evidence; never substitute
an artifact or runtime automatically because a distribution added or removed it.
The full baseline bundle and promotion/release policy remain follow-up work;
this increment supplies the first independent Rust artifact component.

Protocol versions identify argument/request/completion semantics; package versions
identify implementation releases. Behavior changes require a reviewed baseline
revision; incompatible wire behavior requires a new protocol descriptor. Never
edit an archived signed case/result to migrate it. Completion is execution health,
while independent receiver observations establish effects. Existing signed wire
schemas, qualification and release eligibility are unchanged.

## Delivery and comparisons

A rig owns verified probe installation in a controlled workload image or supported
artifact-delivery path. Pin the probe and final image separately, and authorize its
exact executable path. Distribution independence does not imply compatibility
with every runtime ABI, executable policy or image delivery mechanism. Each pairing
needs its own test evidence and independent lifecycle/containment attestation.

Keep a matrix of baseline revision × boundary version × architecture × agent
adapter. Compare results only with matching case semantics and coverage. The first
Rust version is explicitly IP-only: hostname/DNS cases remain unsupported and
cannot inherit results from externally resolved IP cases. OpenShell execution of
the Rust binary is not yet an implemented backend option or a qualification claim.

Native Linux musl builds, static ELF inspection, artifact privacy and common
receiver tests reduce distribution dependencies. They do not establish deterministic
builds, signed provenance, independent service deployment or product release authority.
Those checks and authenticated release/promotion contracts remain required before
commercial release eligibility can be considered.

## Repository boundary

Keep `probes/http/` in this repo while core contributors maintain it and shared
conformance changes require coordinated review. Independent package/artifact
versions provide the needed lifecycle separation. Extract to a dedicated repo if
maintainers, consumers or release cadence require it; preserve the protocol,
artifact pins and cross-runtime conformance rather than duplicating gate policy.

See the [Rust usage guide](../rust-probe-usage.md), [exploration](../rust-probe-exploration.md)
and [roadmap](../improvement-roadmap.md).
