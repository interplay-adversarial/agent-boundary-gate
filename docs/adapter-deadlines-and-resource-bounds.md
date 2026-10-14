# Adapter deadlines and receiver resource bounds

This REL-01 increment adds a supervised host-command provider path and finite
HTTP receiver admission. It does not complete live reliability qualification.
Signed contracts and decision policy are unchanged; release eligibility is false.

## Supervised external providers

Library callers can compose `CommandAuthorityClient` with `OpenShellBackend` as
its receipt and Rust delivery provider, or with the cleanup recovery worker.
It accepts a `CommandTransport` configured with an operator-owned executable
and its independently approved SHA-256 digest:

```python
from agent_boundary_gate.command_transport import CommandTransport
from agent_boundary_gate.rig_authority import CommandAuthorityClient

provider = CommandAuthorityClient(
    CommandTransport(executable=approved_path, executable_digest=approved_digest),
    evidence_store,
)
# Supply provider to OpenShellBackend.receipt_provider/delivery_provider,
# with independently configured ReceiptVerifier/DeliveryVerifier keys.
```

Every invocation checks and snapshots the executable, runs it without a shell,
and supplies one existing request JSON on stdin. The command must consult the
independent authority and return its signed receipt bytes on stdout. A separate
invocation has no retained process-local state. Request/response limits are
64 KiB; empty/nonzero responses and changed executable pins are rejected.
Challenge, purpose, lease, component, freshness and signature validation remain
the responsibility of the existing verifier. Completion alone is never proof.
The private evidence store retains bounded untrusted receipts as it does for
`AuthorityClient`. `live-run` still uses its configured Unix authority socket;
this alternate provider is an explicit library composition.

The parent enforces the caller's monotonic execution deadline and cancellation,
kills the local process group and reaps the direct child. Group cleanup failure
is reported rather than silently accepted. Cleanup receives the existing fresh
cleanup budget; an earlier replay cancellation cannot bypass cleanup.
Stdout now uses a finite OS pipe rather than a polling-limited temporary file.
Retained output defaults to 64 KiB; explicit limits must be positive integers
at most 16 MiB (the development runner uses 1 MiB). Stderr is discarded. Input
remains a bounded temporary file so a child refusing stdin cannot block the parent.

The configured executable, its interpreter, libraries, helpers and environment
are trusted host dependencies. Killing its local group does not cancel remote
infrastructure changes, contain a process that escapes the group, or establish
whole-cell destruction. CPU/process/disk quotas and independent watchdog recovery
remain rig obligations. Executable reading, snapshotting and evidence persistence
are trusted host filesystem operations, outside the child execution timer.

## Receiver admission and slow headers

Local fixture receivers and signed remote receivers share the same server:

- Eight active non-daemon handlers and a listen backlog of eight per listener.
- A one-second absolute header-read budget and a 0.5-second inactivity timeout.
- A 64 KiB aggregate request/header input limit, alongside stdlib parsing limits.
- Excess admission, malformed/oversized headers and header timeouts record loss.
- Listener closure joins admitted handlers before capture is considered drained.

Sending a byte before each inactivity timeout cannot extend the absolute budget.
The two listeners remain independent, with at most sixteen admitted handlers
across the pair. Capture loss withholds a held outcome; an already observed
forbidden effect remains a violation. No request bodies, headers or raw errors
are exported. Existing event-retention limits and final signed drain semantics
are preserved.

These limits bound client-driven header work. They do not interrupt a stuck
Python handler, evidence-store operation or lock holder. Arbitrary in-process
backend, agent, observer, monitor and Unix-service callbacks are cooperative;
adding a thread timeout would leave them running. Unix RPC bounds the client
wait, not an uncooperative server callback's execution. Such integrations need
an owned process/transport boundary and external supervision before qualification.

## Failure drills

`tests/test_adapter_resource_bounds.py` exercises real child processes and TCP
connections with synthetic authority and target behavior. Its eleven groups cover
signed receipt round-trip/challenge rejection, blocked command deadlines,
running-command cancellation/reaping, output floods and command failures,
OpenShell readiness/cleanup/delivery provider timeouts, exact output boundaries,
same-group descendants retaining stdout, receiver saturation, oversized aggregate
headers, slow-drip shutdown and retained violations after a blocked adapter timeout.
Existing gate, adapter, loopback, live-composition and recovery tests remain required.

REL-01 stays open for independently supervised service/whole-cell fault drills,
escaped-process and host-storage failure handling, live watchdog qualification
and other callback implementations. GYM-04 freezing follows its fault criteria;
direct Interplay integration remains deferred INT-02.
