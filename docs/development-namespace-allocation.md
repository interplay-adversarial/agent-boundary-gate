# Independent development namespace allocation

A namespace can be created successfully while the controller loses its response
or dies before registering the UID. Reading the name or run label later cannot
establish which creation produced the object. The default direct-create path
continues to leave that case unresolved.

The optional `development-allocation-serve` process owns a separate private ledger.
Before a controller requests creation, it commits a unique intent containing the
operation ID, config digest, context, run, namespace and role. The allocator
commits the same intent before invoking its pinned Kubernetes executable. Only
the successful API create response supplies the UID; the allocator durably
commits that UID before attempting delivery to the controller.

Recovery sends `lookup` for the original intent. It never sends another `create`,
reruns bootstrap/probes, or constructs ownership from inventory. A retained record
must match every intent field. Current inventory must either contain that exact
UID or show absence. Cleanup then uses the existing API UID precondition and
absence checks. A same-name replacement is neither adopted nor deleted; an
intervening replacement makes the delete precondition fail.

## Operator setup

Run the service independently of the controller, outside the target and its
process group. Keep its socket and ledger in operator-owned `0700` directories;
the ledger must be separate from controller output. Never mount either into the
workload. Credentials belong to the trusted allocator environment.

`NamespaceAllocatorConfig` has these unsigned development fields:

| Field | Purpose |
| --- | --- |
| `socket_path` | Private local Unix socket, created `0600`; existing sockets are refused |
| `ledger_directory` | Private independently retained intent/UID records and exclusive process lock |
| `kubernetes_executable`, `kubernetes_digest` | Operator-approved executable and exact SHA-256 pin; snapshotted privately |
| `context` | Exact Kubernetes context; mismatched requests are rejected |
| `protected_namespaces` | Nonempty denylist including shared targets, registry namespaces and infrastructure |
| `command_seconds` | Create-command budget, default 30 seconds, range 1–45 |
| `max_operations` | Ledger admission bound, default 128, range 1–1024; full ledgers reject new operations |

```sh
agent-boundary-gate development-allocation-serve --config allocator-config.json
```

Set `namespace_allocator_socket` in `DevelopmentRunConfig` to that socket.
Both cell and receiver namespace creation use the service. The protocol accepts
only fixed Namespace manifests: a cell uses a `gate-cell-<24 hex>` name, and a
receiver namespace exactly matches its `gate-dev-<16 characters>` run. It accepts
no arbitrary manifest, shell command, mutation path or delete operation.

Existing configurations with the new field omitted retain their previous config
digests and conservative recovery. Enabling/changing the allocator after a campaign
begins changes its config binding and is rejected. It cannot retrofit ownership
onto an old uncertain direct-create journal.

## Unresolved operations and trust limits

If the API response itself is lost, malformed or nonzero, the allocator dies
before committing the UID, or receipt persistence fails, only an unresolved intent
remains. Repeated `create` for that operation ID returns its unresolved state and
does not retry the API. Unknown lookups also remain unresolved. Labels, current
inventory and uncommitted `.pending` files cannot repair the missing record.
Operator reconciliation still needs independent authoritative provenance.

An allocator restart requires the same configuration/pins and exclusive ledger
ownership. A killed service can leave a stale socket; the CLI does not automatically
remove it. Operators must verify the original owner/inode before reconciliation.
Do not delete records or rotate a full ledger while allocations may remain live.
Create-request IDs are not security credentials; private directory/socket ownership
is the development transport authority. Records are unsigned, not gate receipts.

The interpreter, libraries, Kubernetes API and credentials remain trusted. A
local fsync is not demonstrated power-loss/partition durability. All fixtures
share one host identity; this increment does not qualify controller/key isolation,
whole-cell destruction, independent live watchdog deployment or actual Kubernetes
fault behavior. In-process filesystem work remains cooperative. Release eligibility
remains false, and cleanup cannot complete an interrupted evaluation or erase
violations/capture loss.

## Failure drills

`tests/test_namespace_allocation.py` contains eleven groups. Actual allocator and
controller processes exercise Unix transport, pinned command supervision, durable
files, SIGKILL and restart against a separately persisted synthetic Namespace API.
They cover controller death after create but before UID delivery; allocator death
before commit; API response loss; receiver response loss with capture degradation;
same-name and get/delete replacement; original absence; operation-binding/unknown
lookup failures; commit failure/capacity; exclusive restart/partial files; and
legacy config plus journal-intent validation. Existing direct-create controller
drills continue to require operator reconciliation.
