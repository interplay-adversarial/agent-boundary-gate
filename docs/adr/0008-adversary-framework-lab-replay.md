# ADR-0008: Replaying a real adversary framework is a gated lab mode

Status: proposed, design only. This ADR does not authorize running anything. Date: 2026-11-26.

Autonomous LLM penetration-testing frameworks, ARTEX and its forks being the first
case, are a realistic adversary class for the platforms this gate evaluates. Reading
their source yields claims about request identity, pacing and self-update behavior. A
run yields wire evidence: whether detection fires, whether boundary policy denies
callbacks, whether the claims hold. The same code is untrusted. Public reports describe
trojanized container images for this class, issue reports on forks allege malware
that is unsubstantiated rather than refuted, and at least one fork replaces its SDK with
a modified copy that has not been fully audited. A lab must be designed as if the code is hostile.

## Decision

**Synthetic by default.** Adversary emulation in the gate stays a gate-owned synthetic
component with no dependency on any third-party offensive framework. If an `adversary`
component role is added, it is synthetic.

**Real replay is a separate mode.** `adversary-lab` is never selected by default, by
CI, or by a campaign configuration alone. It requires the authorization record and the
preconditions below.

**Requirements for a run cell.**

- *Acquisition:* source only, at a pinned commit, from an inert mirror, with archive and
  tree digests recorded in the dispatch. Never a prebuilt image.
- *Build:* in an isolated builder with no credentials and no ambient network beyond a
  pinned module source, with module checksums verified. No generation steps, repository
  scripts, tests or install hooks run. The built binary's digest is pinned in the dispatch.
- *Run cell:* an OpenShell-backed disposable cell in a dedicated namespace on dedicated,
  tainted nodes (see the [disposable development cells](../disposable-development-cells.md)
  and [Kubernetes development profile](../kubernetes-development.md)). Non-root, restricted
  security context, no service account token, no host path mounts, no accelerator
  passthrough, filesystem confinement, dropped capabilities, resource limits and a hard
  wall-clock kill.
- *Network:* default-deny egress. Allowed destinations are the synthetic target namespace
  and an in-cluster stub model endpoint that holds no real credentials. DNS resolves only
  through a logging sinkhole so tunneling cannot leave the cell. Self-update endpoints are
  denied by policy, and each attempt is recorded as evidence.
- *Targets:* synthetic services with canary tokens in a separate namespace. Never a real
  third-party host.
- *Observers:* egress-deny and DNS logs, request logs at the synthetic target (client
  label, headers, timing), and the containment monitor. A positive control, a canary
  exfiltration attempt that policy must block, runs first. Monitor loss ends the run as an
  incident through the existing decision path.
- *Lifecycle:* the existing no-replay recovery and lifecycle receipts apply. The cell is
  destroyed and its cleanup confirmed.

**Authorization.** A signed dispatch names the operator, purpose, time window, targets,
framework commit and binary digest. Possession of the binary or of cluster access
authorizes nothing.

**Preconditions.** Live fault qualification evidence for the P1 containment track
(LIFE-01, LIFE-02, QUAL-01) on the cell used; a completed static audit of the exact
commit, including its SDK fork and any browser or extension component; and acceptance
of this ADR.

**Use of results.** Outputs are a wire-level inventory of request identity per fork,
detection hit rates, and boundary denial evidence for callbacks and self-update. They
feed findings under [ADR-0006](0006-findings-as-derived-records.md). A real-framework
result can never make a release eligible or substitute for a synthetic baseline case.
Which evaluation track carries them is deferred to the 0.3 schema decision.

## Out of scope

Any target not owned by the operator and not in a synthetic namespace; any internet
egress; keeping the binary after the run; sharing raw outputs outside the project
without review.

## Consequences

The design can be reviewed and refined before any execution exists, and the static
audit gap cannot be skipped silently because it is a stated precondition. The cost is
that no real-framework evidence exists until the P1 containment track has live
qualification evidence.

Proposed work item: LAB-00 (this review). Execution tickets are not to be opened until
the preconditions hold.
