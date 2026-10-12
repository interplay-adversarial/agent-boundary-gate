# ADR-0003: Challenge-bound lifecycle receipts

Status: accepted for prototype implementation; live qualification pending.

Readiness generations and cleanup booleans supplied by callbacks do not establish
an independent broker's identity, freshness or scope. Replace them with signed,
challenge-bound lifecycle receipts. Keep this protocol separate from archived
terminal evidence versions.

## Contract and trust

`LeaseBinding` is trusted provisioning context supplied outside the workload and
outside the receipt response. It includes the canonical SHA-256 digest of the
controller's exact `Binding`, run/attempt IDs, lease ID, whole-cell UID, boundary
component UID/generation, effective policy digest and lease expiry. The controller
must authenticate this context through the provisioning authority; this increment
does not implement that transport or authenticate lease issuance itself.

Each request has a newly generated 256-bit challenge, a purpose (`readiness` or
`cleanup`) and the expected lease context. Broker responses must echo the complete
request exactly. A cached response cannot satisfy another request. Do not reuse
requests: verification is stateless and is not a global replay-consumption ledger.

Readiness claims assert `ready` and the expected effective policy digest. Cleanup
claims assert `destroyed` with scope `whole-cell`. A sandbox-delete acknowledgement
cannot substitute for destruction of the research cell. A signature authenticates
the issuer's assertion; live qualification must establish that the broker observes
and proves these facts independently of the target.

The verifier snapshots externally configured Ed25519 public keys separately for
readiness and cleanup authorization. Responses cannot introduce trust anchors.
An issuer authorized for one purpose has no authority for the other unless it is
explicitly configured in both registries. Prefer separate broker identities and
privileges. Rotate/revoke keys by replacing the verifier's trusted configuration.

## Wire authentication and time

Receipt schema `1.0` uses the signature domain
`agent-boundary-gate/lifecycle-receipt/1.0` followed by a NUL byte and sorted,
compact UTF-8 JSON of the receipt. All request, claim, issuer and time fields are
signed. This is project-specific canonicalization, not RFC 8785. Schema and
signature algorithms are literal values; undeclared fields are rejected. Times
must be timezone aware and normalize to UTC. The envelope contains no public key.

The verifier accepts at most 64 KiB of JSON. Issuance must not be in the future;
expiry is exclusive; age and signed lifetime cannot exceed 60 seconds. No clock
skew grace is granted. Maintain trusted controller/broker clocks; clock uncertainty
must withhold readiness. Readiness expires no later than the provisioning lease.
Fresh cleanup receipts may arrive after lease expiry so watchdog-triggered teardown
can still be confirmed.

The schema is exported independently by `scripts/export_receipt_schema.py` to
`schemas/receipts/1.0/`. Existing `0.1`/`0.2` terminal schemas, examples and signature
domains are unchanged. The nested boundary component uses its existing `0.2`
identity schema. Future incompatible receipt changes require a new receipt version.

## Backend integration

Boundary backends now implement `require_binding(binding)`. The controller calls
it before starting observation or replay. OpenShell compares the exact binding
digest and run/attempt IDs against the trusted lease. The loopback implementation
checks its simulated policy only and does not claim an authenticated lease.

OpenShell construction requires `lease`, `receipt_provider` and `receipt_verifier`;
the old generation-string and cleanup-boolean hooks are removed. Readiness still
requires CLI sandbox UID, phase, loaded revision, active revision and policy hash
checks, plus a verified broker receipt for the pinned generation. Replay requires
a matching attempt binding and an unexpired readiness receipt/lease. Its local
process deadline is capped by both expiries. Rebinding, failed readiness checks
and destruction invalidate cached readiness. Destruction checks the sandbox UID,
requests deletion and requires a fresh authenticated whole-cell cleanup receipt.

`ReceiptProvider.fetch(request, deadline=..., cancelled=...)` returns untrusted
wire bytes or `None`. Implementations must bound response reading, honor deadlines
and cancellation, avoid logging raw bodies and protect lease metadata in transit.
The adapter checks cancellation/time before and after fetch; it cannot interrupt a
provider that blocks indefinitely. External timeout enforcement and watchdog
recovery remain required before live use.

## Remaining qualification work

No live broker, authenticated transport, lease issuer, external watchdog or remote
collector is supplied by this increment. Tests use ephemeral in-memory signing
keys and synthetic broker assertions. Authenticated receipt bytes are not yet
retained/referenced in terminal evidence; independent re-verification from a
terminal record requires evidence retention and a separately versioned contract.
The current gate still authenticates controller-produced terminal assertions.

Release eligibility remains disabled. Implement trusted lease issuance/transport,
durable receipt retention, independent whole-cell destruction and crash recovery
before qualifying a live target. See the [roadmap](../improvement-roadmap.md) and
[live-rig handoff](../live-rig-handoff.md).
