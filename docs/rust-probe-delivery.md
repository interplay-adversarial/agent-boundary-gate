# Pinned Rust staging and experimental backend execution

The Rust baseline stays independent of the OpenShell distribution. Operators
build an owned workload image containing the verified standalone binary, then
pin the **final image digest** separately. The library never downloads, compiles
or installs the probe during an evaluation. It never switches to another probe
when admission or execution fails. The probe remains IP-only and experimental;
completion is not proof of an allowed or denied effect.

## Stage an independently approved artifact

Obtain the Linux musl binary and its unsigned build manifest through your reviewed
build/release process. Review the baseline before promoting expected digests into
trusted configuration. CI artifacts and their accompanying manifest are untrusted
inputs until matched to those independent pins. Do not create the expected pins
by reading a downloaded manifest during an evaluation.

`RustProbeArtifact` is a strict library model for a trusted pins file. It contains
`schema_version: "1.0"`, `package_version: "0.1.0"`,
`protocol: "agent-boundary-gate/http-probe/1.0"`, the fixed protocol digest from
`probe_delivery.PROTOCOL_DIGEST`, `target` (either `x86_64-unknown-linux-musl` or
`aarch64-unknown-linux-musl`), and independent SHA-256 `binary_digest`,
`source_digest` and `manifest_digest` values. All digests include `sha256:`.
Keep deployment pins and private image references outside this repository.

From a source checkout with the Python environment installed:

```sh
uv run --no-sync python -m scripts.stage_rust_probe \
  --binary "$PROBE_BINARY" --manifest "$PROBE_BUILD_MANIFEST" \
  --pins "$APPROVED_PROBE_PINS" --destination "$NEW_IMAGE_CONTEXT_DIRECTORY"
```

These variables refer to operator-provided files and a new output directory.
The command performs bounded, regular-file reads, rejects final symlinks and
FIFOs, matches both binary and manifest digests, verifies manifest baseline fields,
inspects static ELF architecture/linkage, and repeats artifact privacy checks.
It never executes the supplied binary. Existing outputs, including symlinks, are
rejected. Failures emit fixed JSON and exit 2 without exporting input values.

The output contains the exact binary, manifest, pins, Apache license and notice.
Its directory is private (`0700`), binary mode is `0555`, and metadata is `0444`.
The image builder and output parent are trusted; processes with that same identity
can change these files. Staging does not establish immutable delivery, authenticated
build provenance, reproducibility, image CVE coverage or commercial readiness.

Use your owned image build to copy the probe to the fixed location
`/opt/agent-boundary-gate/probes/http/0.1.0/gate-http-probe`. Pin the resulting image
digest through trusted provisioning configuration. Do not rely on stock OpenShell
images or their bundled interpreters. Match the workload's actual CPU architecture.

## Compose the backend

The following is library composition, assuming the existing lease, lifecycle
receipt provider/verifier and trusted CLI configuration have already been obtained.
It intentionally requires an external delivery provider; none is shipped that
can independently inspect a real cell.

```python
from agent_boundary_gate.backends.openshell import OpenShellBackend
from agent_boundary_gate.probe_delivery import (
    DeliveryVerifier,
    RustProbeArtifact,
    RustProbeDeployment,
)

artifact = RustProbeArtifact.model_validate_json(approved_pins_bytes)
deployment = RustProbeDeployment(
    artifact=artifact,
    workload_image_digest=approved_workload_image_digest,
)
backend = OpenShellBackend(
    executable=pinned_cli_path,
    executable_digest=approved_cli_digest,
    gateway=operator_gateway,
    sandbox=operator_sandbox,
    sandbox_uid=lease.component.instance_uid,
    policy_digest=lease.effective_policy_digest,
    policy_revision=approved_active_revision,
    lease=lease,
    receipt_provider=lifecycle_provider,
    receipt_verifier=lifecycle_verifier,
    probe_runtime="rust",
    rust_deployment=deployment,
    delivery_provider=independent_delivery_provider,
    delivery_verifier=DeliveryVerifier(authorized_delivery_public_keys),
)
```

Use the existing `run_attempt` controller, authenticated monitor/recovery context
and independent paired receiver observer described in the
[library guide](library-usage.md). The read-only compatibility doctor still covers
Python/Perl prerequisite reporting; it does not inspect Rust delivery.

Before **every** Rust action, the backend creates a fresh random challenge and
requests a signed receipt. The request binds the complete lease (attempt, run,
cell, UID, generation, policy, expiry and dispatch binding digest) and exact
deployment pins. Trust keys are supplied independently and snapshotted; keys
returned with artifacts or workload output are never accepted.

The independent supervisor must inspect the actual cell and establish all of:

- The running workload image and architecture match the approved pins.
- The exact probe bytes are at the fixed executable location, without a mutable
  symlink, mount overlay or executable substitution available to the workload.
- That location, its ancestors and relevant mounts remain immutable to the
  workload and other untrusted writers through lease expiry.
- The selected executable is authorized by the active execution policy, and the
  supervisor's generation changes or containment monitoring stops admission if
  any of these guarantees can no longer hold.

It must not sign by echoing caller-supplied metadata. File modes alone do not
establish immutability. These are issuer obligations, not facts the Python
controller can discover through `sandbox exec`. Receipt service identity and
transport must remain outside the evaluated workload, obey shared deadline and
cancellation budgets, and cap replies at 64 KiB. Provisioning and a conforming
live issuer/transport are still pending.

`DeliveryReceipt` uses a separate signature domain
`agent-boundary-gate/probe-delivery-receipt/1.0` and
[immutable schema](../schemas/probe-delivery/1.0/signed-delivery-receipt.json).
It asserts `verified-immutable-delivery`, has timezone-aware issuance/expiry,
and supplies `immutable_until` at least as late as lease expiry. Receipts are
valid for at most 60 seconds and cannot outlive the lease. A lifecycle readiness
receipt cannot substitute for this delivery receipt. Existing signed terminal,
lifecycle and monitor versions remain unchanged.

Invalid, missing, stale, mismatched or unauthorized delivery withholds execution
with `backend-probe-delivery-rejected`; the fixed diagnostic survives authenticated
terminal records and gate decisions. Cancellation or expiry during transport also
prevents execution. The action deadline is reduced to receipt/lease/readiness
expiry and the existing controller externally bounds the CLI process. Each action
executes only the fixed absolute binary path with validated IP, port, attempt and
timeout arguments. Hostnames are explicitly unsupported; pre-resolving them would
not measure sandbox DNS. Probe stdout never serves as the delivery authority or
the security oracle.

This increment provides staging and admission primitives, not a live deployment.
Retain delivery receipts as private rig evidence: terminal evidence does not yet
independently reverify this separate receipt chain. Signed release provenance,
baseline promotion authorization, image/build-tool CVE checks and paired live
qualification remain outstanding. `release_eligible` stays false.
