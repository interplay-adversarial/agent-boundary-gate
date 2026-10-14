# Packaged OpenShell development runner

For controller death or lost namespace response delivery, the optional
[independent namespace allocator](development-namespace-allocation.md) records
API-returned UIDs outside the controller journal. Configure its private socket
before starting the campaign. Recovery uses exact-intent lookup and UID-conditioned
cleanup; missing API UID records remain unresolved, and interrupted evaluations
cannot become expected behavior merely because cleanup succeeds.

`development-run` provisions fresh paired receivers and runs healthy/weakened
Rust HTTP controls against a disposable target cell or an operator-selected
existing gateway. It snapshots
digest-checked CLI binaries, registers namespace/receiver/target Pod identities,
checks policy and probe pins, and retains private evidence through cleanup.
Use [disposable target cells](disposable-development-cells.md) for a fresh gateway
namespace with UID-conditioned cleanup and a separately pinned operator bootstrap.
The original shared-gateway mode requires a separately pinned identity-bound
cleanup helper. Without either path, the runner returns
`identity-bound-cleanup-required` before allocating any resources.
This repository does not ship a shared-gateway cleanup helper for the tested
OpenShell deployment; name-only CLI/SDK deletion is unsupported for automatic cleanup.
This is a `development-only` workflow with `release_eligible: false`; it issues
no gate receipts or release decisions. See [the development profile](kubernetes-development.md).

## Private configuration

Prepare the owned workload and receiver images using the
[image and probe guide](rust-probe-delivery.md). Supply immutable final image pins,
the exact probe digest, and scanned CLI binaries. Keep cluster credentials and
gateway metadata in the operator environment, outside the target. The workload
must have the pinned probe at its fixed path and `/usr/bin/sha256sum` for the
development byte check. This check is not immutable delivery attestation.

Create a mode `0600` JSON file outside this repository, using the strict library
configuration to avoid accidental extra fields:

```python
from agent_boundary_gate.development_run import DevelopmentRunConfig

config = DevelopmentRunConfig(
    target_namespace=operator_target_namespace,
    receiver_image=approved_receiver_image,
    workload_image=approved_workload_image,
    openshell_executable=operator_openshell_path.resolve(),
    openshell_digest=approved_openshell_digest,
    kubernetes_executable=operator_kubernetes_cli_path.resolve(),
    kubernetes_digest=approved_kubernetes_cli_digest,
    cleanup_executable=operator_identity_cleanup_path.resolve(),
    cleanup_digest=approved_identity_cleanup_digest,
    context=operator_context,
    gateway=operator_gateway,
    probe_digest=approved_probe_digest,
    xdg_config_home=operator_gateway_config_directory,
    command_seconds=120,
    profile_seconds=480,
    cleanup_seconds=240,
)
private_config.write_text(config.model_dump_json(indent=2))
private_config.chmod(0o600)
```

Optional `image_pull_namespace` creates a fresh, UID-tracked `system:image-puller`
RoleBinding for the receiver namespace in an operator-owned internal image
namespace. It is specific to an OpenShift-style registry; omit it for another
registry and arrange pull access separately. The runner never changes the target
namespace or gateway. Operator permissions must permit creating/deleting the
fresh test namespace and optional grant, inspecting target Pods, and reading
receiver snapshots through Kubernetes exec. No credentials or providers are
attached by the sandbox create command.

The configuration above describes shared-gateway mode. Disposable-cell mode creates
a separate target namespace and fresh gateway alias, preserving the configured
shared deployment; see its bootstrap contract and recovery limits in the
[cell guide](disposable-development-cells.md). Do not supply both helper modes.

## Identity-bound cleanup helper contract

The helper is an operator-owned executable snapshotted and digest-checked like
the CLIs. It receives one bounded JSON request on stdin, with protocol
`agent-boundary-gate/development-cleanup/1`, the configured context/gateway,
run and target namespace, registered `sandbox_id`, `boundary_pair` and
`target_uids` (`supervisor`/`workload`). The request contains no sandbox name.
Credentials/configuration must remain in its private operator environment.

Implement deletion by an immutable allocation ID, or enforce an atomic identity
precondition at the mutation authority. It must be idempotent for the same
allocation, reject replacements, and handle the complete target allocation,
including control-plane state that could recreate its Pods. A get followed by
name-based deletion, or deleting Pods while a controller can recreate them, does
not implement this contract. No boolean configuration flag can waive it.

On successful admission, stdout must exactly echo the request plus the booleans
`identity_preconditioned: true` and `cleanup_requested: true`, with exit code `0`.
Unsupported/precondition-failed/error outcomes must return a failure; malformed,
extra or mismatched response fields leave cleanup incomplete and keep receivers.
The runner still independently observes the registered Pod pair's absence and
captures final effects before deleting receiver resources with UID preconditions.

This response is a trusted helper's development contract, not a signed gate
receipt or independent proof of whole-cell destruction. The operator must review
the helper implementation and its mutation authority; a digest alone proves no
atomic semantics. Tests in this repo use a synthetic ID-selecting helper and
establish orchestration/conformance only. Live helper implementation and failure
qualification are required before another automated development pair is admitted.

## Run and recover

```sh
agent-boundary-gate development-run \
  --config "$PRIVATE_RUNNER_CONFIG" --output "$NEW_PRIVATE_CAMPAIGN_DIRECTORY"
```

The destination must not exist. It becomes mode `0700`; journals, policies and
content-addressed raw responses are `0600`, executable snapshots `0700`. Keep
the directory and its ancestors under operator control. Do not put it inside
the target filesystem or publish it. Console output contains only fixed profile
names, counts, completion/cleanup flags and the development qualification.
Exit `0` means both expected development controls completed with final capture
and cleanup; exit `2` means incomplete or unexpected development behavior. Neither
authorizes a release. A healthy forbidden hit remains visible even when a later
stage fails; missing capture never becomes a successful denial.

SIGINT/SIGTERM cancel bounded commands. Cleanup uses its own deadline and ignores
the attempt cancellation event, retaining receivers until registered target Pods
are absent. Cleanup then resamples receivers, deletes the receiver namespace
with a UID precondition, waits for absence, and removes the optional image grant
with its UID precondition. Cleanup failure prevents success and leaves a private
journal for operator reconciliation. The second profile starts only after the
first profile's expected observations and cleanup succeed.

```sh
agent-boundary-gate development-recover \
  --config "$PRIVATE_RUNNER_CONFIG" --output "$EXISTING_PRIVATE_CAMPAIGN_DIRECTORY"
```

Recovery is idempotent for registered completed allocations. It requires the same
configuration and binary pins, and an exclusive campaign lock. It does not rerun
probes or upgrade a failed attempt into a passing evaluation. A killed writer's
uncommitted temporary journal is discarded under that lock; committed allocation
records remain authoritative.

Library callers should use `with DevelopmentRunner(config, destination) as runner:`
and call `runner.run(cancelled)` or `runner.recover()` inside that scope. Context
exit releases the campaign lock even on exceptions; `close()` is also idempotent.
An abandoned instance has a descriptor finalizer as a fallback. Neither context
exit nor garbage collection deletes cluster resources: registered-allocation
cleanup stays in the explicit run/recovery workflow.

In shared-gateway mode, an allocation request that times out or loses its registration response is
explicitly unresolved. Recovery refuses to delete that target or its receivers
based on a name guess. Inspect the private allocation intent and actual API
inventory, reconcile ownership outside this automatic runner, and retain that
failure. Controller-death automation and ambiguous-create reconciliation require
a stronger allocation authority and remain qualification work.

## Cleanup limits and baseline ownership

The tested OpenShell CLI and checked public API accept names for sandbox deletion.
[API source](https://github.com/NVIDIA/OpenShell/blob/v0.1.3/proto/openshell.proto).
Their check-then-delete path has been removed from the runner. Automatic target
cleanup must use the identity-bound helper; there is no name-based fallback.
Without it, new shared-gateway campaigns stop before provisioning and existing uncleaned targets
remain unresolved. The read-only inventory checks cannot supply the missing
atomic mutation authority.

The earlier packaged live integration exercise completed healthy counts `1/0` and weakened
counts `1/1` (allowed/forbidden), with final capture and registered-resource cleanup
for both profiles. It used the now-removed name-based cleanup path; its observations
are retained as historical development evidence. An initial CLI cleanup incompatibility
was recovered before the repeat. No live identity-bound helper has been exercised,
and these observations are not a fault qualification packet.

The configured shared gateway and cluster survive each profile. Cell mode retires
only its newly allocated gateway namespace. Unsigned memory-backed
receivers, Kubernetes exec sampling and Pod absence do not establish whole-cell
closure, authenticated readiness/drain or watchdog recovery. This runner must
never substitute for the [live workflow](live-workflow.md) qualification packet.

Preserve Rust artifact/image pins when upgrading OpenShell. Rebuild or change
either baseline only through explicit promotion and repeat image/CVE and behavior
checks. [Gym onboarding](gym-onboarding.md) uses an independent dependency lock;
it neither changes these pins nor turns these controls into agent-injection tests.
