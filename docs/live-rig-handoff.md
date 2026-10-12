# Denied-egress live-rig handoff

Checkpoint: 2026-10-10. Direct driver implemented; live deployment not performed.

## Available implementation

`src/agent_boundary_gate/backends/openshell.py` targets the CLI flags and JSON contract inspected in cached
OpenShell commit `f745aa4df4b1e63ca362cb4624d3952796a7c31c`. It requires a pinned
CLI binary digest and an explicitly leased `gate-*` sandbox name. It verifies
the sandbox UID, `Ready` phase, a `loaded` pinned policy revision, active revision,
policy hash and an external supervisor-generation receipt. The effective-policy
view alone is insufficient. Generation/readiness is checked after each action.

Requests use the frozen Python HTTP probe with an attempt correlation header,
bounded request and process deadlines, no login shell, no TTY and no redirects.
Probe completion establishes execution health; independent receiver events
determine whether the forbidden operation occurred. The driver keeps child output
off shared logs and terminates its local process group on cancellation/deadline.
Remote execution still depends on the external cell lease and watchdog.

Deletion verifies the leased UID to avoid deleting a replacement. A delete
acknowledgement cannot establish whole-cell teardown: the driver requires an
independent cleanup receipt. Receipt hooks currently return caller-supplied
values; authenticated broker transport, freshness and generation semantics
must be implemented before live qualification. No provisioning credentials are
sent to the workload.

The probe assumes Python 3 exists in the pinned workload image. That binary
must be declared in the policy and its allowed receiver control must pass. This
has not been empirically validated on a live target.

## Local evidence

`local-run` exercises actual HTTP observation and signed-record persistence with
an explicitly simulated policy and monitor. Receivers bind `127.0.0.1` and are
not remote rig services. The lifecycle is a local reference implementation, not
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
proofs. The local watchdog thread cancels processes promptly; it cannot reconcile
controller death.
