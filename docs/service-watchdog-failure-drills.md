# Service and watchdog failure drills

This REL-01/EVID-01 increment runs actual `authority-serve`, `receiver-serve` and
`watchdog` entry points in separate owned processes. TCP/Unix transport, Ed25519
signatures, SQLite transactions, signals and restart recovery are real. The pinned
inspector and cell inventory are explicitly synthetic; no OpenShell, hypervisor,
model or provider traffic is used. Release eligibility stays false.

## Watchdog timing configuration

Trusted unsigned `WatchdogConfig` now exposes finite positive timers, each at most
sixty seconds. Existing configurations retain their previous defaults:

| Field | Default seconds | Purpose |
| --- | --- | --- |
| `heartbeat_ttl` | 60 | Initial controller-liveness window |
| `cleanup_budget` | 45 | Cleanup transport deadline |
| `claim_ttl` | 60 | Recovery ownership before another worker can reclaim |
| `retry_delay` | 5 | Delay before retrying unconfirmed cleanup |
| `poll_interval` | 1 | Delay between worker steps |

Cleanup budget must be strictly shorter than claim TTL. Invalid, boolean,
non-finite and excessive values are rejected before registration. Restart never
renews an existing lease. Operators must measure latency and leave room for
proof persistence and journal commit; short fixture timers are not qualified live
budgets. Receipt freshness and ownership checks still reject late results.

## Sixteen drill groups

`tests/test_service_watchdog_drills.py` owns each service process group, with
bounded admission, checkpoint and reap waits. Keys, configuration, synthetic
inventory, journal and evidence occupy a fresh private temporary tree. Inventory
survives separately from the recovery journal. The groups cover:

1. Timing defaults and rejection of invalid/unbounded claims.
2. Authority SIGKILL, stale-socket restart refusal and changed monitor generation.
3. Authority SIGSTOP and externally bounded client waits.
4. Signed heartbeat expiry and permanently latched coverage loss.
5. Receiver SIGSTOP: even resumed capture/drain cannot turn a gap into held.
6. Receiver death/restart: a new generation cannot replace old effects.
7. Watchdog cleanup without a controller or further controller heartbeats.
8. Absolute lease expiry despite a longer heartbeat window.
9. Watchdog SIGKILL during cleanup, claim expiry, fresh proof and stale-owner rejection.
10. Same-name replacement UID: no deletion or cleanup confirmation for the original.
11. Authority evidence-directory obstruction: no receipt confirmation until durable retry.
12. Watchdog receipt-write failure: no confirmation until proof is durably retained.
13. Journal-commit failure: worker exits with an unconfirmed claim; restart obtains fresh proof.
14. Blocked cleanup: independent monitor remains responsive; graceful authority SIGTERM
    terminates/reaps the pinned inspector without confirming cleanup.
15. Receiver death after a forbidden effect: a real signed terminal retains the
    violation and incomplete source; gate evaluation withholds pass.
16. Authority death after a forbidden effect: a signed terminal retains violation,
    monitor loss and unconfirmed cleanup; prior good evidence cannot create pass.

Terminal drills use a synthetic boundary driver. Actual OpenShell provider deadline
coverage remains in [adapter bounds](adapter-deadlines-and-resource-bounds.md).
Receipt/commit errors are narrow test-only injection switches in
`tests/service_drill_worker.py`; product commands do not accept them. Authority
storage obstruction is a real local filesystem failure. Heartbeat expiry advances
an injected session monotonic clock; watchdog lease/claim timers use real time.
These distinctions are part of the evidence interpretation.

The core pre-commit unit hook now sets `PYTHONPATH=src`, matching CI and native
hooks. Without it, `uv run --no-editable` reused an older installed project wheel
and tested stale runtime code; the new watchdog fields exposed that mismatch.

## Supervision and remaining limits

The fixture coordinator is the outside process owner. Teardown resumes suspended
children, cancels services and reaps them; abrupt injection kills only an owned
process group. Stale-socket reconciliation requires the original child to be
dead/reaped and the private socket inode to match the admitted instance. Product
services refuse existing sockets; this adds no automatic restart/socket deletion
or deployment supervisor to the CLI.

All processes share one host/OS identity. The inspector's containment, watchdog
and destruction claims come from fixture inventory. They do not prove whole-cell
destruction or key isolation from a live controller. Arbitrary Python handlers and
trusted host filesystem operations remain cooperative. Recovery and storage
restoration cannot repair interrupted evaluation or erase a prior violation.

Authority SIGKILL with an active inspector, escaped/new-session descendants,
host reboot/power-loss durability, node partitions and live orphan-cell/watchdog
qualification remain open. Deployment needs independently owned process-tree
supervision including inspector groups, authenticated narrow liveness authority
and an environment-specific inspector. These tests do not install or qualify that
supervisor. GYM-04 freezing follows remaining fault criteria; Interplay stays
deferred INT-02. Signed schemas, policy and archived evidence are unchanged.
