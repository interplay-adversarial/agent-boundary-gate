# Denied-egress live-rig handoff

Checkpoint: 2026-10-12. Direct driver implemented; live qualification pending.

## Available implementation

`src/agent_boundary_gate/backends/openshell.py` targets the CLI flags and JSON contract inspected in cached
OpenShell commit `f745aa4df4b1e63ca362cb4624d3952796a7c31c`. It requires a pinned
CLI binary digest and an explicitly leased `gate-*` sandbox name. It verifies
the sandbox UID, `Ready` phase, a `loaded` pinned policy revision, active revision,
policy hash and a signed, challenge-bound external supervisor-generation receipt. The effective-policy
view alone is insufficient. Generation/readiness is checked after each action.

Requests use a selected frozen Python or Perl HTTP probe with an attempt correlation header,
bounded request and process deadlines, no login shell, no TTY and no redirects.
Probe completion establishes execution health; independent receiver events
determine whether the forbidden operation occurred. The driver keeps child output
off shared logs and terminates its local process group on cancellation/deadline.
Remote execution still depends on the external cell lease and watchdog.

Deletion verifies the leased UID to avoid deleting a replacement. A delete
acknowledgement cannot establish whole-cell teardown: the driver requires an
independent, signed whole-cell cleanup receipt. Receipt authentication, freshness,
lease/attempt/generation binding and purpose-scoped trust are implemented under
[ADR-0003](adr/0003-authenticated-lifecycle-receipts.md). Trusted lease issuance,
authenticated broker transport, durable receipt retention and independent teardown
semantics still need live implementation/qualification. No provisioning credentials
are sent to the workload.

Select `probe_runtime="python3"` (the compatibility default) or
`probe_runtime="perl"` when constructing `OpenShellBackend`. There is no automatic
interpreter fallback: select it in trusted rig configuration, include the selection
in the boundary configuration pin, and allow the chosen executable in the policy.
Python requires its standard HTTP modules; Perl requires `IO::Socket::IP` and
`Socket`. Neither probe follows redirects or reads proxy environment settings.
Receiver URLs use ASCII DNS names or IP literals with an explicit port; use
punycode for internationalized names. Controls, whitespace and scoped IPv6 zone
identifiers are rejected. The Perl process independently validates host, port,
attempt identifier and its one-to-thirty-second timeout before opening a socket.
Missing interpreters/modules cause a CLI failure; completion is only execution
health and the independent allowed receiver must still establish the positive control.

An operator-supplied compatibility test against OpenShell 0.1.3 reported that its
stock sandbox image lacks Python 3 and includes Perl. Do not assume a stock image
can execute the default probe. The Perl probe has local receiver regression tests;
its modules, executable policy, and behavior in a pinned live image still require
qualification. The compatibility test used synthetic broker receipts, so it does
not establish supervisor-generation or whole-cell cleanup authority.

Perl is provided to exercise that image without installing Python or rebuilding
the workload image just for the probe. This keeps the tested image closer to the
selected runtime artifact and avoids adding an interpreter solely for the test.
Python remains the default for images that provide it. Choose explicitly and
verify prerequisites in the pinned image; both probes send the same fixed request
and independent receiver evidence determines the security outcome.

A [standalone Rust probe exploration](rust-probe-exploration.md) records a possible
interpreter-free follow-up, including deadline, DNS, artifact and policy requirements.
A pinned experimental Rust probe and signed-delivery admission are now shipped;
see [the delivery guide](rust-probe-delivery.md). The [live workflow](live-workflow.md)
adds host-side service transports, a runner and campaign reports. Actual independent
inspection/provisioning and live qualification remain pending.

## Active policy revision and timing

The same compatibility test observed two revisions after `sandbox create --policy`:
revision 1 was a default policy marked `superseded`; revision 2 was the requested
policy marked `loaded` and active. This is an observation from one runtime version,
not a contract that revision 2 is always correct. Provisioning must discover and
pin the requested policy's actual active revision and digest. Never hardcode
revision 1 or silently adopt whatever policy happens to be active. The backend
checks both `version` and `active_version` against its supplied revision and
requires an authenticated readiness receipt.

`run_attempt` retains five-second readiness and cleanup defaults and a sixty-second
ceiling for each explicit budget. Set them deliberately for a live rig. One sample
reported deletion near thirty seconds while a workload was still running; other
operations were much faster. These samples are not p99 estimates. A starting
measurement configuration could use `readiness_budget=15.0` and
`cleanup_budget=45.0`, then collect enough samples to select appropriate bounds.
Cleanup's budget covers UID lookup, deletion and receipt fetch/verification together.
Readiness is also bounded by the dispatch deadline; action deadlines and receipt,
monitor and controller lease lifetimes must be coordinated separately.

CLI timeouts are reported as `backend-<phase>-cli-timeout`; nonzero exits as
`backend-<phase>-cli-exit-nonzero`, where phase is `readiness`, `replay` or `cleanup`.
Launch, output-limit and process-group cleanup failures have separate allowlisted
codes. These sanitized codes appear in signed run reasons and gate decisions.
Child stdout/stderr, command arguments, gateway names and paths are never copied
into diagnostics. A nonzero exit does not identify the underlying cause; private
operator investigation is still needed.

A deletion timeout leaves cleanup unconfirmed even if the remote deletion later
succeeds. That is incomplete evidence at finalization, not proof of a boundary
violation or containment incident. A successful delete is still insufficient:
only the independent signed whole-cell receipt confirms cleanup. Recovery must
reconcile unconfirmed leases; a later success never rewrites the archived result.

## Local evidence

`local-run` exercises actual HTTP observation and signed-record persistence with
an explicitly simulated policy and monitor. Receivers bind `127.0.0.1` and are
not remote rig services. The lifecycle and recovery components are local reference implementations, not
a ready-to-deploy remote rig controller. Signing keys, monitor events and workload
processes share a local development host; this does not demonstrate tamper resistance.

Regression coverage includes complete/violating attempts, positive-control loss,
capture/drain loss, generation change, cancellation, timeout, storage outage,
finding retention before failing cleanup and injected containment incident.
All prototype outputs have `release_eligible: false`.

## Deployment prerequisites

Use a dedicated research environment whose whole-target containment and outer
network controls are independently verified. Select the infrastructure and pin
its runtime artifacts before provisioning. This repository contains no deployment
credentials, endpoint inventory or operator-specific environment configuration.

## Next executable deployment work

1. Select the location and pin the entire target stack, guest, image digests,
   CLI artifact, policy schema and prover. Source snapshots are not runtime pins.
2. Implement the provisioning/lease broker and independent whole-cell watchdog.
   Establish authentic supervisor-generation and teardown receipt transport.
3. Run collectors and allowed/forbidden receivers outside OpenShell but within
   the closed rig. Supply reachable receiver URLs and a receiver-capture client;
   remote sandboxes cannot use the current host-loopback receiver URLs.
4. Independently close external egress for gateway, supervisor, workload, DNS,
   model, telemetry and artifact paths while permitting both controlled receivers
   at the outer layer. This is necessary to attribute denial to OpenShell.
5. Qualify healthy and deliberately weakened target controls, effective-policy
   activation, receiver independence, monitor loss, deadline and orphan cleanup.
6. Wire restricted RustFS/MLflow storage and allowlisted export; then add the
   Contrib adapter and demonstrate the complete EvalHub/CI path.

This work follows [ADR-0001](adr/0001-rig-topology.md). M0/M1 still require live
proofs. The controller-local watcher cancels bounded processes; it cannot reconcile
controller death. A durable journal and separately hostable recovery worker now
recover registered leases after controller/worker exit in synthetic tests. See
[ADR-0004](adr/0004-monitor-and-lease-recovery.md). Actual whole-cell teardown,
independent deployment/permissions and pre-registration allocation recovery remain
unproven. Authenticated monitor sessions start unknown until a signed healthy
handshake; loopback opts explicitly into simulated monitor health.
