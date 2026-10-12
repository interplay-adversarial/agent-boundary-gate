# ADR-0004: Authenticated monitor health and durable lease recovery

Status: accepted for prototype implementation; live services and qualification pending.

A controller-local Event initialized healthy cannot establish independent monitor
readiness. A controller's `finally` block cannot run after abrupt process death.
Use explicit authenticated monitor sessions and a durable lease journal that a
separately hosted recovery worker can read without the controller.

## Monitor admission and continuity

`AttemptControl()` starts with unknown health and cannot admit replay. Supply a
`MonitorSession` that has already received a verified healthy handshake. Local
loopback tests use `AttemptControl.for_fixture(binding)` explicitly; its health
is synthetic and it is never accepted as an authenticated monitor for a leased
backend. Boundary backends declare `lease` (`None` only for simulation). A leased
backend requires the same exact lease in its authenticated monitor and controller
recovery registration, in addition to validating the dispatch binding.

Monitor heartbeat schema `1.0` is independent of terminal and lifecycle receipt
schemas. Its signature domain is `agent-boundary-gate/monitor-heartbeat/1.0`, with
a NUL separator and project-specific sorted compact UTF-8 JSON. Each response
echoes a new 256-bit challenge and the full trusted lease context. Keep one
outstanding request per session; do not pipeline or reuse challenges. Consume the
challenge only after an authenticated response matches it. Rejected input makes
health uncertain and stops the attempt, but retains the challenge so a late valid
signed incident can still be captured; rejection is not a proven incident. The controller
pins monitor signer identity/generation and externally supplied Ed25519 public
keys. Responses cannot introduce keys. Sequence numbers must strictly increase;
unknown issuers, changed scope/generation, tampering and replays latch loss.

Heartbeat times must be timezone aware. Issuance cannot be in the future, expiry
is exclusive, lifetime is at most 10 seconds and expiry cannot exceed the lease.
After verification, a monotonic deadline enforces freshness without extending it
for storage latency. Authenticate and persist each heartbeat before establishing
health. Retain at most 256 heartbeat references per session; overflow records loss
and dropped evidence. Longer attempts need a qualified bounded collector/retention
design, not silent eviction of required proof.

Unknown health, expiry, adapter errors, authenticated loss and source generation
changes stop replay and withhold approval. Loss cannot be healed within an attempt.
Verified incidents remain latched even when persistence fails, preserving incident
precedence. The watcher cancels local bounded processes, but cannot force a blocked
plugin call to return. The lease mechanism provides a separate recovery path.

Monitor packets record real source identity/generation and signed heartbeat
references. Terminal schema `0.2` still authenticates controller-produced assertions;
independent verification of all referenced heartbeat/receipt blobs remains EVID-01.
Existing signed schemas, examples and signature domains are unchanged.

## Durable recovery state

`LeaseJournal` stores immutable trusted lease bindings in a private SQLite database.
The directory is mode `0700`, the database is a regular file mode `0600`, symlinks
are rejected, and writes use explicit immediate transactions with full synchronous
commit. Each operation uses its own connection for cross-thread/process access.
The journal and sidecars are ignored by Git and rejected by publication auditing.
No key material or deployment credentials belong in the journal.

The controller starts its `ControllerLease` before observation/replay. Controller
liveness refreshes a short heartbeat deadline without extending absolute lease
expiry. Cancellation, monitor stop or liveness failure quiesces renewal. Late
heartbeats cannot resurrect a due/recovering/destroyed lease; re-registration cannot
replace a binding or reset deadlines. Clock regression rejects renewal and makes
the lease due for conservative recovery. UTC clocks must be independently managed
and trustworthy before live use.

The provisioning authority must durably cover resources before returning a usable
cell. This increment recovers leases **after registration**. It does not implement
allocation intents or solve a crash during provisioning before the exact cell and
sandbox identities are known. The live broker must cover that earlier window.

## Independent cleanup reconciliation

Host `RecoveryWorker` in a separate supervised process/identity, outside the target
and controller failure domain. Its `run(stop)` loop claims due leases on absolute
expiry or missed controller heartbeats. Transactions assign unique expiring claim
tokens so concurrent workers do not both own a live claim. If a worker dies, another
can reclaim after claim expiry. Expired/replaced claim tokens cannot commit results.

`CleanupBroker.destroy(request, deadline=..., cancelled=...)` must idempotently
operate on the original leased whole-cell UID and return a fresh signed lifecycle
cleanup receipt. A cell-name match or deletion acknowledgement is insufficient.
The worker verifies the complete challenge/binding and purpose-authorized signature,
persists proof, then rechecks freshness/deadline before marking the journal destroyed.
Storage failure, missing/invalid/replayed proof, cancellation and timeouts retain an
unconfirmed state and schedule a retry. Repeated cleanup never selects a replacement
UID. Controller liveness updates never interpret a cleanup boolean as proof.

The journal is an authority-owned internal API, not an authorization boundary for
untrusted clients. The local controller helper shares direct journal access for
prototype tests; a live deployment must replace that with a narrow authenticated
liveness interface and worker-only cleanup mutation permissions. Workloads must
have no access to journal files, signing keys or monitor evidence. Broker transports
must obey deadline/cancellation; this worker cannot interrupt a broker call that
blocks indefinitely. Claim expiry enables another worker to retry, but qualifies
only when a real independent broker enforces idempotent teardown.

## Validation and remaining work

Tests use real durable SQLite transactions and an abruptly exiting controller
subprocess, plus synthetic monitor/broker assertions and in-memory signing keys.
They exercise expiry, cancellation, concurrent claims, worker interruption/restart,
stale claims, retry, storage loss and violation/incident retention. They do not
prove destruction of a real VM or OpenShell cell, identity isolation, service
availability, tamper resistance or controller-independent deployment.

LIFE-02 remains incomplete until authenticated live monitor/broker transports,
service deployment/permissions, allocation-intent recovery and orphan-cell fault
injection pass qualification. Retained lifecycle receipt references and independent
terminal re-verification remain EVID-01. Release eligibility remains disabled.
