# OpenShell Kubernetes development profile

Exercise the independently pinned Rust HTTP probe against an existing OpenShell
gateway using fresh paired receivers and a controlled healthy/weakened policy
delta. This shared-gateway profile is `development-only`, with
`release_eligible: false`. It does not issue receipts, emit gate decisions or
implement the whole-cell inspector required by [`live-run`](live-workflow.md).

## Prepare private resources

Build the Linux musl probe using the [delivery guide](rust-probe-delivery.md) and
[owned-image workflow](live-workflow.md). Independently pin its artifact, base
image and final workload image. Preserve those baseline pins when updating
OpenShell. Pin a separate Python 3.13 image for receivers; the Rust probe has no
dependency on that interpreter. Scan both final images and retain scanner/database
identities privately. An image build or digest does not establish clean CVE coverage.

Create an owner-only `DevelopmentConfig` JSON file outside the repository:

```python
from pathlib import Path
from secrets import token_hex
from agent_boundary_gate.development import DevelopmentConfig

config = DevelopmentConfig(
    run="gate-dev-" + token_hex(8),
    target_namespace=operator_target_namespace,
    receiver_image=approved_receiver_image,  # immutable OCI reference
    workload_image=approved_workload_image,  # immutable OCI reference
)
private_config = Path(operator_private_directory) / "development.json"
private_config.write_text(config.model_dump_json(indent=2))
private_config.chmod(0o600)
```

```sh
agent-boundary-gate development-plan \
  --config "$PRIVATE_DEVELOPMENT_CONFIG" --output "$NEW_PRIVATE_PLAN_DIRECTORY"
kubectl --context "$PRIVATE_CONTEXT" create \
  -f "$NEW_PRIVATE_PLAN_DIRECTORY/resources.json"
```

The renderer creates a new run namespace, two receiver Pods and Services, an
immutable code ConfigMap and a NetworkPolicy. Receivers have no service account
tokens, no egress, read-only root filesystems, dropped capabilities, bounded
connections and memory-backed capture state. Both data ports permit TCP/8000
from OpenShell supervisors in the selected target namespace. The tested policy
determines which receiver is reachable. Rendering does not prove CNI enforcement.
The CLI prepares private files and prints only a fixed status; it never applies
resources or reads cluster credentials. It does not modify shared gateway resources.

Use fresh names and `create`. Capture the namespace and Pod UIDs in private
allocation records before executing anything. Multi-object CLI creation may emit
multiple JSON documents, so register objects individually or query the API after
creation. Reconcile partial creates and abandoned intents; this renderer is not
a provisioning transaction or watchdog. Discover the actual Service IPv4 addresses
and construct `http://<IP>:8000/probe` endpoints after both Pods become ready.

## Execute the policy pair

```python
from agent_boundary_gate.development import policy

healthy_policy = policy(receiver_endpoints, weakened=False)
weakened_policy = policy(receiver_endpoints, weakened=True)
```

These dictionaries are valid JSON/YAML policy inputs. Both permit the exact Rust
executable path; weakened adds only the forbidden endpoint. Use separate fresh
sandbox/receiver allocations for the profiles. Give sandboxes short `gate-*`
names: the tested CLI limits names to 19 characters, so do not reuse the longer
receiver run identifier as the sandbox name.

Create the sandbox from the pinned workload image and private policy file using
`--detach`, `--no-auto-providers`, explicit CPU/memory limits and a bounded idle
command such as `/bin/sleep 600`. Attach no production credentials or providers.
Discover the actual sandbox ID and active revision; never assume revision 1 or 2.
The default resolved policy view can report `effective`, while an explicit
revision reports `loaded`. Retain both views, verify the intended endpoint/binary
rules, and check policy hashes and revisions around each action.

Run the fixed Rust executable once against each receiver using `sandbox exec
--no-tty --no-login-shell --timeout`, literal IP, port, run token and bounded probe
timeout. Its completion marker is execution health, not a security outcome.
Read each receiver's `/tmp/capture.json` through trusted Kubernetes exec. Health
requests do not increment counts; effects require exactly one matching attempt
header. Duplicate/wrong headers, parser faults, overload or storage loss must not
be interpreted as successful denial. A failed snapshot write invalidates stale
data rather than exporting an old zero-loss count.

## Inspect and clean up

[`inspect_pod`](../src/agent_boundary_gate/development.py) checks independently
registered receiver UIDs, image reference/runtime digest, readiness, zero restarts
and basic process/network protections. [`inspect_target_pair`](../src/agent_boundary_gate/development.py)
checks both registered target Pod UIDs, boundary pair and the pinned workload
image. Supply actual API inventory and separately registered expectations, not
workload-generated JSON. Their allowlisted reports withhold whole-cell, immutable
delivery and release claims even when the checked inventory matches.

The tested driver labels only the supervisor with `openshell.ai/sandbox-id`.
Discover its `openshell.ai/boundary-pair`, then inspect both roles using that pair.
Checking only `sandbox-id` misses the workload. Recheck both UIDs and image state
around every action; a replacement or restart invalidates the attempt.

Keep receivers active through target cleanup and sample again afterward. Request
deletion only for the registered sandbox ID, then confirm both registered target
Pods are absent and no replacement exists under the pair. This is test-resource
cleanup, not whole-cell destruction. A name check followed by CLI deletion is not
atomic; stronger claims require independent allocation and prevention of name reuse.
Delete only the receiver namespace with a Kubernetes DeleteOptions UID precondition,
and verify its absence. Never delete the shared target namespace or gateway.

## Development evidence and limits

The initial real exercise used the same owned Rust image for both profiles:

| Profile | Allowed hits | Forbidden hits | Target Pod pair absent after cleanup |
| --- | ---: | ---: | --- |
| Healthy | 1 | 0 | Yes |
| Weakened | 1 | 1 | Yes |

This is one development integration exercise, not live gate qualification. The
shared gateway/cluster stay outside per-test teardown. Collector state is unsigned,
memory-backed, without a signed drain, and does not survive Pod loss. Whole-target
closure, immutable delivery, controller-crash recovery, full image/toolchain CVE coverage
and the live fault packet remain separate qualification work.

The initial development base failed its package CVE scan. A separately built
minimal base removed unused packaging tools and applied a specifically pinned OS
package fix, preserving the exact Rust probe bytes. The resulting pinned receiver
and owned workload images each returned zero detected package CVEs across all
severities, without suppressions. These are scanner/database snapshots, not proof
of complete vulnerability coverage or a qualified commercial baseline. Retain
both failed and remediated image identities and scan records privately; repeat
scanning and behavior checks when deliberately promoting a new image baseline.

The [packaged development runner](development-runner.md) now provisions these
resources, checks identities/pins, executes both controls and captures through
cleanup, with private journals and explicit recovery. There is no automatic public
live CI job, whole-cell provisioner or external watchdog for this profile.
Ambiguous creates require operator reconciliation; see the runner's cleanup limits.
Automatic execution now requires a pinned identity-bound cleanup helper, which
is not implemented for the tested deployment. The earlier name-based cleanup
exercise above is historical; it does not qualify the helper contract.
Retain allocation intents, policy state, inventories, captures and cleanup evidence.
Export only fixed profile names, counts and explicit development qualification.
No synthetic receipt may bridge this profile into the authenticated live gate.
