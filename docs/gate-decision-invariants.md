# Generated gate decision invariants

REL-01 adds eleven property groups in
[test_gate_invariants.py](../tests/test_gate_invariants.py). They exercise the actual
`evaluate` function with validated wire records and real Ed25519 signatures.
Hypothesis is pinned to `6.169.0` in the **development** dependency group; runtime
dependencies, signed wire versions and the optional Gym lock are unchanged.

Run from the source checkout:

```sh
uv sync --frozen --no-editable
PYTHONPATH=src uv run --frozen --no-editable python -m unittest discover \
  -s tests -p test_gate_invariants.py -v
```

Normal unit discovery, pre-commit and both hosted Python validation jobs also run
these tests. Generation is bounded at 200 examples per property, with deterministic
settings for the pinned test environment, shrinking enabled and no saved example
database. Five explicit examples retain extreme weight dilution, the canonical
backend timeout diagnostic, and lost/expired/incident monitor histories followed
by healthy messages. Hypothesis cache files remain ignored.

## Properties

| Relationship | Assertion |
| --- | --- |
| Record permutation | In metadata-only fixture evaluation, reordering signed results, including conflicting duplicates, cannot change findings, reasons, aggregate or decision. |
| Required violation versus positive controls | An unwaived required violation remains a veto even when other cases have vastly larger weights, cleanup succeeds, or additional incomplete/conflicting results arrive. Its zero score and confirmed finding remain retained. |
| Incident precedence | A trusted, bound incident dominates missing cases, duplicate results and other incomplete evidence; violations remain visible alongside it. |
| Missing prerequisites | Healthy controls cannot offset required source loss, monitor loss, unready policy, uncertain cleanup/control status, cancellation, backend timeout, stale records, unknown outcomes or incomplete component identity. |
| Server aggregate claims | Missing, malformed, non-finite, out-of-range or inconsistent server values cannot launder signed scores or erase findings. |
| Veto-only exceptions | A valid exception may waive only the required-case veto. It preserves the violation and raw aggregate, cannot waive monitoring loss, and never grants release eligibility. |
| Exception scope/freshness | Wrong case, invariant, target, policy, expired or future exceptions cannot waive the veto. |
| Authentication/binding | Bad signatures and authentic records for a different attempt cannot invent confirmed violations or containment incidents for this dispatch. They still withhold a passing decision. |
| Referenced proof availability | Missing, corrupted or public-permission manifests, required sources, monitor inventories/heartbeats or effect proofs withhold a pass even with an otherwise valid exception and permissive aggregate threshold. Observed violations survive the proof loss. |
| Corroborating diagnostics | Optional diagnostic loss remains visible as degradation and cannot create a required-source veto. |
| Monitor histories | Authenticated loss, expiry, rejection or storage failure cannot be repaired by a later healthy heartbeat in the same session; authenticated incidents remain latched, including an incident received during storage loss. These snapshots feed the real gate. |

The properties assert safety and metamorphic relationships rather than copying
the evaluator's decision tree. Clean positive controls must pass before damage
is applied in the prerequisite, aggregate and stored-proof properties, preventing
an always-inconclusive evaluator from satisfying the suite. Weighted score checks
use an independent rational arithmetic calculation. Records are revalidated via
JSON after signing; impossible terminal packets are not introduced through
unchecked model copies.

## Covered domain and limits

Generated suites contain one to four cases, sparse benchmark indices, finite
positive weights including `1e-300` and `1e300`, required/optional cases, and
held/violated/unknown outcomes. Fault combinations contain up to six distinct
failures. Monitor histories contain up to ten events and use real authentication
and session transitions with synthetic in-memory storage; their wall and monotonic
clocks are controlled. Proof-availability properties separately use the actual
private filesystem evidence store and digest checks.
Permutation tests do not exercise evidence I/O budget exhaustion or filesystem
races; the stored-proof groups use one case and do not establish large-suite
retrieval behavior.

A **confirmed violation** is not synonymous with an unwaived required veto.
An explicitly optional or correctly waived violation may coexist with a passing
prototype decision when the aggregate threshold and every evidence requirement
are met. It must still retain its zero score and finding. Every evaluated result
in this suite asserts `release_eligible: false`.

These are bounded generated regressions, not formal verification or live boundary
qualification. The proof tests check local availability/integrity, not independent
issuer interpretation. They do not test large-suite capacity, distributed storage,
power loss, runtime containment or an authenticated watchdog. No model, provider
credential or cluster traffic is used, and archived evidence is not rewritten.

No production decision change was needed for this increment. REL-01 remains open
for broader blocked-adapter deadline enforcement, resource bounds and live fault
qualification. GYM-04 freezing follows its pilot/fault criteria; optional Interplay
integration remains deferred. See the [roadmap](improvement-roadmap.md) and
[controller drills](development-failure-drills.md).
