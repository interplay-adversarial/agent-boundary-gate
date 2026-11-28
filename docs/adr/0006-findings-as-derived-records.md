# ADR-0006: Findings are derived records in the gate

Status: proposed. Date: 2026-11-26.

The gate decides pass, fail, inconclusive or incident for one signed dispatch, and
`GateDecision.confirmed_violations` names the violated case IDs. It has no object an
operator can follow across runs, no statement of how strong the evidence is, no link
from a violated invariant to a remediation, and no lifecycle. Recommending and
verifying mitigations needs that object. It lives here rather than in a sibling
repository: the observers, signed records and evidence store a finding must cite are
in this repository, and [ADR-0002](0002-portable-adapters-and-repository-boundaries.md)
keeps one repository until a concrete split need appears.

## Decision

**Derived, not decided.** A finding is computed by a pure function,
`derive_findings(dispatch, records, decision)`, over inputs `evaluate()` already
authenticated and bound. `evaluate()` does not import it and its output must be
identical whether or not findings are derived; a property test enforces this. Only an
observer outcome of `violation` yields a finding. Behavior and judge scores, including
Interplay judge verdicts, cannot create or confirm one. The Interplay bridge may attach
a research verdict that stays labeled untrusted.

**Own schema family.** Findings use a separate contract family (`finding/1`). Signed
0.1 and 0.2 wire versions and archived evidence are never edited. `release_eligible`
stays false. A finding never relaxes a veto or a waiver: a waived violation remains a
finding with `waived: true`.

**Identity.** `finding_id` is the digest of `invariant_id`, `case_spec_digest`,
`target_digest` and `boundary_policy_digest`. The same case on the same binding yields
the same ID across reruns. A mitigation changes the boundary policy digest, so the run
that verifies it is linked by a lifecycle event, never by reusing the identifier.

**Evidence tiers from fields that already exist.** E1: observer outcome only. E2: required
sources complete and every referenced digest readable (EVID-01). E3: positive control
passed, containment monitor healthy, run complete and cleanup confirmed, the same
conditions `evaluate()` requires before a run counts as complete. E4: E3 plus a
complete corroborating source. Tiers add no new trust input. `evaluate()` keeps a
violation from any authenticated, bound record even when those conditions fail, and
only the overall decision becomes inconclusive. E1 and E2 findings therefore exist,
are marked as such, and cannot be reported or claimed verified.

**Lifecycle is separate and append-only.** A signed `FindingEvent` log records
`confirmed`, `mitigation-proposed`, `mitigation-applied`, `verified`, `regressed`,
`risk-accepted` and `reported`. Findings themselves are immutable. Event signing reuses
the [ADR-0003](0003-authenticated-lifecycle-receipts.md) receipt approach if it fits,
to be confirmed in implementation. `risk-accepted` needs an expiring, signed exception
like the existing `ExceptionRecord`. `verified` is derived from a verification run's
result and is never written by hand.

**Invariant and control catalog as data.** `CaseSpec.invariant_id` and
`CaseSpec.control_family` are the join keys. The catalog holds invariant specs
(statement, control family, risk references) and control candidates (control ID,
backend kind, applicability over enforcement layer and capabilities, the invariants it
claims to restore, the cases that verify it). Selection is deterministic: filter, then
order by declared blast radius and ID. A model may draft explanatory text. It never
selects or ranks a control. A finding whose family has no installed backend gets an
explicit `no-candidate:<reason>`, never a guess. Candidates are advice, not evidence.

**Mitigation verification reuses `Binding`.** Verifying a mitigation is a new dispatch
whose `boundary_policy_digest` is the digest of the rendered policy, running the same
signed `CaseSpec`. A finding is `verified` only when the case holds, the positive
control passes and no other required case of the original dispatch regresses. This
needs no new `evaluation_track` value in 0.2. Tracks for detection and supply-chain
cases need a 0.3 schema decision and are deferred.

## Consequences

An operator can follow one violation through proposal, application, verification and
regression, and mitigation planning gets a stable subject without touching decision
logic. The cost is a second protected ledger and a hard dependency on authenticated
inputs: findings cannot be derived from unverified records.

Today's case registry covers denied-egress cases, plus agent-control tool requests.
Boundary egress and filesystem findings can receive candidates from an OpenShell policy
backend ([ADR-0007](0007-pluggable-mitigation-and-advisory-backends.md)). Agent-control
findings stay `no-candidate` until a guardrails backend exists.

Proposed work items: FIND-01 (derivation and contract), FIND-02 (event ledger), CTRL-01
(catalog and selector). They are not yet in the improvement roadmap.

Open: whether the receipt approach fits the event ledger; the source of risk reference
identifiers; the first catalog entries (denied egress is the obvious seed); retention
and privacy of the event log.
