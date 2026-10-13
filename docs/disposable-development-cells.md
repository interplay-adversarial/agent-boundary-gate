# Disposable development target cells

The runner allocates a fresh Kubernetes namespace for each profile, records its
actual UID before starting the gateway, and retires it with a UID-conditioned API
delete. Receivers stay in a separate namespace through target cleanup and final
capture. This path is independent of OpenShell's name-only sandbox deletion API.

The runner supplies allocation/cleanup authority. A reviewed, pinned operator
bootstrap supplies the deployment and private client connection. It must put the
gateway, writable state and every sandbox controller/resource inside the cell;
a gateway alias pointing at the shared deployment does not satisfy the contract.

## Configuration and bootstrap

Use [DevelopmentRunConfig](development-runner.md), replacing the shared-gateway
`cleanup_executable`/`cleanup_digest` fields with:

```python
config = DevelopmentRunConfig(
    **operator_runner_parameters,  # Other image, CLI, probe and private context pins.
    cell_bootstrap_executable=reviewed_bootstrap.resolve(),
    cell_bootstrap_digest=approved_bootstrap_digest,
)
```

Bootstrap pin fields must be paired; the two helper modes are mutually exclusive.
The configured `target_namespace`/`gateway` identify the protected shared deployment.
Cell commands use a fresh `gate-cell-<24 hex>` namespace and matching gateway alias.
The receiver and optional image registry namespaces are also protected from cell
retirement. Keep all operator inputs outside this public repository.

The helper receives a bounded stdin JSON object, no arguments:

```text
protocol: agent-boundary-gate/development-cell-bootstrap/1
context: private Kubernetes context
run: receiver/profile identity
namespace: allocated cell name
namespace_uid: registered immutable UID
gateway: cell name (the required fresh client alias)
```

Exit `0` and stdout exactly echoing those fields plus `ready: true` are required.
Extra/mismatched fields, non-boolean readiness and timeouts stop the profile.
The alias must work with the pinned OpenShell CLI in the configured private
`XDG_CONFIG_HOME`. Readiness is an operator bootstrap assertion followed by
namespace/Pod/policy checks, not an authenticated gate receipt.

The reviewed helper must check the namespace UID before deployment, pin and verify
all non-secret chart/manifest/configuration inputs and runtime images, use ephemeral
in-cell state and attach no providers or business credentials. An executable pin
alone does not attest other files it reads. Preserve Rust artifact/image pins when
changing OpenShell; deployment CVE/provenance checks are separate from package audits.
Per-cell PVCs require a reviewed storage reclaim policy and independent backing-PV
cleanup checks. The runner's `cleanup_complete` covers registered namespaces and
receivers; it does not attest storage-backend data erasure or ancillary-resource cleanup.

External databases, shared controllers, host mounts and target-created namespaces
are outside this cleanup authority. Necessary cluster-scoped RBAC must be uniquely
owned by the cell UID, grant no out-of-cell mutation rights, and be reconciled/verified
by the operator. Never modify shared grants. This namespace profile cannot safely
evaluate host escape or cluster-admin targets; use a stronger VM/cluster authority.

## Run and recover

Use the existing `development-run`/`development-recover` commands. The private journal
commits allocation intent, cell UID, delete intent and observed absence. Cleanup
submits `DeleteOptions.preconditions.uid`, then polls for namespace absence. A
replacement UID, API error, finalizer delay or timeout keeps cleanup incomplete and
receivers retained. There is no name-only fallback or finalizer removal. Kubernetes
UIDs identify recreated objects and the API enforces mutation preconditions.
[Object identities](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/),
[DeleteOptions](https://kubernetes.io/docs/reference/kubernetes-api/definitions/delete-options-v1-meta/).

A timed-out bootstrap or sandbox create can be retired because its enclosing cell
UID was already committed. If namespace creation itself loses its response before
registration, recovery refuses name-based adoption/deletion and needs operator
reconciliation. Resource labels cannot resolve that uncertain-create window.
Retired inner-create intents are preserved as `retired_pending` in the journal,
while receiver/grant create uncertainty remains pending outside the retired cell.
Retirement never clears the failed evaluation flag.

Cleanup has a fresh cancellation scope and deadline. Restart recovery never reruns
bootstrap/probes or promotes failed evaluation to passing. Final receiver sampling
preserves historical effects and loss before deleting receivers. Private client
aliases, credentials and operator-owned forwarding processes need operator-side
reconciliation; bounded bootstrap execution cannot manage detached helpers.

Results stay `development-only`, `release_eligible: false`. Namespace API absence
does not prove process termination on a partitioned node, whole-cell network
containment or authenticated watchdog recovery. Synthetic faults are not a live
qualification packet.

## Development validation

A private operator bootstrap using an explicitly pinned OpenShell gateway and
supervisor completed fresh healthy/weakened profiles with allowed/forbidden counts
`1/0` and `1/1`. Both target namespaces were retired by UID before final receiver
sampling and receiver cleanup. A separate live API check rejected a stale UID
after namespace name reuse and preserved the replacement. Early bootstrap and
sandbox readiness failures were retained as failed attempts and their registered
cells were retired; they were not promoted to passing results.
Independent post-cleanup inventory found no remaining cell-owned RBAC, backing
PVs referencing the retired cells or owned forwarding processes. The shared
gateway's UID/generation remained unchanged. Forwarding lifecycle and storage
reclamation checks are operator validation, not additional core cleanup receipts.

The bootstrap and deployment inventory are private operator inputs, not a portable
product deployment or authenticated qualification packet. The independent Rust
probe/workload baseline stayed unchanged. Gateway/supervisor image advisory and
provenance coverage still require a dedicated promotion review.
