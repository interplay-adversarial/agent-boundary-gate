# Experimental live red-team workflow

This increment provides an owned-image context builder, private host-side receipt
and receiver services, a watchdog entry point, `live-run`, and a calibration/fault
campaign runner. It is an integration path, **not a qualified turnkey rig**.
The disposable environment, provisioner and independent cell inspector must be
supplied and tested by the operator. No live deployment has been exercised here.
All outputs retain `release_eligible: false`.

## Placement and trust

Use a dedicated Linux control host outside a disposable target VM. Put the entire
OpenShell gateway, supervisor, workload and target services inside that VM. Run
the receipt authority, watchdog, receiver pair and controller on the control
host. The target can reach only the two receiver data ports and approved mock
services. It cannot mount the host's files, use its admin sockets or access keys.
The independently controlled outer boundary permits **both** receivers so that
the tested OpenShell policy determines which request is blocked.

This placement is the first supported composition model, not an automatically
provisioned or demonstrated VM recipe. Namespace-only deployment and target-side
socket forwarding do not establish whole-target containment. An independently
reviewed environment-specific inspector is required before live execution.

Admin RPC uses owner-only Unix sockets in existing owner-only directories,
64 KiB framed packets, eight concurrent clients, bounded transport operations,
cancellation and fixed errors. There is no DNS, proxy, remote shell or network
admin listener. The controller and services share a trusted host identity; their
process separation does not isolate keys from a compromised controller host.
The evaluated target identity must remain outside that trusted host boundary.
Use short socket paths within the host platform's Unix-socket length limit.

## 1. Prepare the owned workload image

Build/review the existing Linux musl probe artifact and independently approve
its pins using [the delivery guide](rust-probe-delivery.md). Then create a fresh
private context:

```sh
uv run --no-sync python -m scripts.prepare_owned_image \
  --binary "$PROBE_BINARY" --manifest "$PROBE_BUILD_MANIFEST" \
  --pins "$APPROVED_PROBE_PINS" --base-image "$PINNED_BASE_IMAGE" \
  --destination "$NEW_PRIVATE_IMAGE_CONTEXT"
```

The base must be an OCI reference ending in `@sha256:<64 lowercase hex digits>`.
The builder repeats artifact verification, static architecture/privacy checks
and exclusive staging. The generated Dockerfile preserves the approved base's
user and entry point and copies the exact probe to its immutable protocol path.
It runs no installer and adds no interpreter. A `.dockerignore` limits build
inputs to the Dockerfile, binary, license and notice; private pins/metadata are
excluded. The context itself is private because its base reference is operator
configuration. Existing destinations are rejected, including symlinks.

Build that context with your controlled image builder on the correct architecture,
scan the **final image**, and independently pin its digest in `RustProbeDeployment`.
Image construction, registry transport, reproducible builds and image/toolchain
CVE coverage are not established by generating this context. The provisioner
must enforce immutable executable/ancestor/mount state, execution authorization
and the baseline pins for the full lease lifetime.

## 2. Supply the independent cell inspector and start services

The authority requires a pinned operator-owned executable implementing
`InspectionRequest -> CellInspection` as bounded JSON on stdin/stdout. The host
service hashes and snapshots the executable before every invocation, runs it
without a shell, and kills its process group on cancellation/deadline. Host
interpreters, dynamic libraries, helper programs and environment are additional
trusted dependencies; an executable digest does not pin those dependencies.

The executable must independently inspect the hypervisor/provisioning authority,
outer firewall and target supervisor. It must not return caller values without
checking actual inventory, use workload stdout as authority, or interpret
`sandbox delete` acceptance as whole-cell destruction. Required output:

| Field | Inspector obligation |
| --- | --- |
| `binding` | Match the provisioner's registered exact cell UID, sandbox UID, supervisor generation, policy and lease; reject same-name replacement |
| `observed_at` | Fresh UTC observation, at most five seconds old |
| `state` | Actual `ready`, safely `contained` during transitions, `lost`, `incident` or independently confirmed `destroyed` |
| `outer_boundary_closed` | Verify the whole-target outer closure, including non-workload services |
| `workload_cannot_access_authority` | Verify target isolation from sockets, keys, journal and evidence |
| `watchdog_active` | Verify independent watchdog supervision; a controller thread is insufficient |
| `deployment` | Inspect actual image, architecture and binary against separately approved pins |
| `immutable_until` | Establish immutable delivery through lease expiry |
| `executable_authorized` | Verify actual active execution authorization |

For `operation: destroy`, idempotently destroy the **exact registered whole cell**
and verify its resources are absent. An absent cell needs authoritative inventory
or a retained destruction tombstone, not a reused name. The service rejects unknown
or changed registrations before calling the inspector. Approved deployments are
loaded on the authority independently of controller requests. Readiness, cleanup,
delivery and monitoring use separately configured Ed25519 purpose keys.

`operation: monitor` must independently inspect outer containment while destruction
is in progress. It runs concurrently with cleanup so that a slow hypervisor deletion
cannot starve heartbeats. `contained` can establish monitor coverage during that
transition; it cannot authorize readiness or executable delivery. `AuthorityConfig`
requires both `inspector` and `monitor_inspector`, each with its own executable and
digest pin. The two configurations may name the same stateless executable: every
invocation uses a fresh private snapshot and subprocess. They must not share a
mutable socket/session or a blocking external lock that prevents monitoring during
destruction. Calls to each inspector instance are serialized separately with bounded
lock waits; the library rejects using one object for both paths. External inventory
and tool concurrency still require operator qualification. A real loss stops admission.

Generate the precise configuration and inspector JSON schemas:

```sh
uv run --no-sync agent-boundary-gate schemas --output "$PRIVATE_SCHEMA_DIRECTORY"
```

`AuthorityConfig`, `ReceiverConfig`, `WatchdogConfig` and `LiveConfig` define the
private input files. Use absolute file paths. Config files and raw 32-byte signing
key files must be owned by the service user with no group/other permissions.
Evidence and journal directories must be private. Never commit any of them.
Keys/public trust anchors must come from the operator's separate trusted setup;
there is no automatic trust in response-provided keys or generated fixtures.

Provision fresh cells and register allocation intents before resources can become
orphans. The current watchdog registers supplied leases before its loop, but it
does not implement a hypervisor's allocation-intent transaction. Start these as
independently supervised host services:

```sh
agent-boundary-gate authority-serve --config "$PRIVATE_AUTHORITY_CONFIG"
agent-boundary-gate receiver-serve --config "$PRIVATE_RECEIVER_CONFIG"
agent-boundary-gate watchdog --config "$PRIVATE_WATCHDOG_CONFIG"
```

Watchdog timing is explicit trusted configuration: `heartbeat_ttl` (60 seconds),
`cleanup_budget` (45), `claim_ttl` (60), `retry_delay` (5), and `poll_interval` (1).
Defaults preserve prior behavior; each value is finite, positive and at most 60,
and cleanup budget must fit strictly inside claim TTL. Restarting a watchdog
never renews an existing lease. Measure latency and leave room for proof
persistence/commit; short fixture timers are not qualified live budgets.
[Service/watchdog drills](service-watchdog-failure-drills.md) exercise actual
entry points with synthetic inventory, including process death and storage errors.

These are separate foreground commands, not one shell sequence. The authority
socket is also the watchdog cleanup transport. A target-side sandbox deletion
is followed by actual whole-cell cleanup through the inspector.

The receiver binds explicit IPv4 data ports. Set `advertise_host` to the controlled
host address reachable from the VM; never use loopback for a remote workload.
Both signed receiver endpoint URLs must exactly match the controller's trusted
configuration. Data requests are correlated by `X-Gate-Attempt`; that header is
a correlation token, not authentication of the sender. The closed rig must
exclude unrelated writers. Each capture supports one fresh lease, serializes
drain against admitted requests, caps concurrent connections and persists at
most 1,000 per-request events. Overflow/storage failures mark required evidence
incomplete while retaining a forbidden observation.

The remote observer samples before cleanup, then keeps capture active through
whole-cell destruction. Finalization stops listeners, drains queued/admitted
connections and joins their handlers before signing the final snapshot. Connection
capacity and parsing/timeouts are recorded as capture loss. The closed-rig timing
and drain path still need live qualification; a late or incomplete snapshot cannot
establish held enforcement. Controller-crash drills must also restart/reconcile
the collector with a new generation before its next capture.

Receiver lifecycle transitions are serialized independently of HTTP capture state.
Admin operations acquire the lifecycle lock before the capture lock, and release
the capture lock before closing/joining HTTP handlers. Public shutdown and drain
cannot close the same listeners concurrently. Admin lock waits respect deadline
and cancellation; incomplete shutdown cannot establish a complete signed drain.

## 3. Execute and inspect a live attempt

Supply the separately trusted dispatch, exact lease, active policy revision,
pinned CLI, Rust deployment, service sockets, purpose-specific public keys,
receiver URLs, journal and terminal-signing key through `LiveConfig`.
Dispatches support one frozen paired HTTP case without an agent or waivers.
`examples/denied-egress-live-v1.json` declares the signed receiver observer.
Its replay action bytes retain the existing IP-based baseline behavior.

```sh
agent-boundary-gate live-run \
  --config "$PRIVATE_LIVE_CONFIG" --output "$NEW_PRIVATE_EVIDENCE_DIRECTORY"
```

The runner snapshots the verified CLI, obtains an authenticated monitor handshake,
refreshes monitoring, starts signed receiver capture, verifies readiness and
fresh Rust delivery before each action, checks the positive control and generation,
drains capture, requests whole-cell cleanup, and evaluates persisted evidence.
There is no Python/Perl fallback. Missing services or inspection authority produce
incomplete/failed results; they are never replaced with fixture receipts.

Stdout contains only an allowlisted report: attempted operations, observed effect,
positive control, decision, cleanup, incident state and useful fixed explanations.
No binding identifiers, routes, paths, public/private keys or raw diagnostics are
exported. Full signed records, receipt bytes and dispatch stay in private storage.
Terminal verification still checks referenced artifact integrity; an independent
archival verifier for the full service receipt chain remains follow-up work.

Exit codes are pass `0`, criteria failure `1`, inconclusive `2`, incident `3`.
An exit-0 report is an experimental result, not commercial qualification or release
authorization. Startup/configuration failure exits 2 with a fixed error.

## 4. Calibrate, then test failures

Prepare separate disposable cells/leases for each profile. Keep probe deployment,
CLI and suite pins constant; vary only the deliberately declared target policy
or injected fault. A `CampaignPlan` contains `entries` with `scenario` and a private
`config_file`. Healthy and weakened profiles are mandatory. Optional supported
profiles are `positive-control-loss`, `policy-change`, and `observer-loss`.
The trusted provisioner must actually arrange each condition; scenario labels do
not induce or prove faults. Live fault injection is environment-specific.

```sh
agent-boundary-gate live-suite \
  --config "$PRIVATE_CAMPAIGN_PLAN" --output "$NEW_PRIVATE_CAMPAIGN_DIRECTORY"
```

Campaign success means the declared expectations matched: healthy denial passes,
weakened enforcement yields a positive control and retained violation, missing
positive control/policy change/observer loss yields the appropriate inconclusive
result, and cleanup is independently confirmed for every profile. A generic
inconclusive result is insufficient for a policy/observer fault expectation.
Reports stay explicitly unqualified. Never average away a violation or missing
coverage. Keep the paired policy delta and fault-injection proof in private
qualification evidence; this runner does not independently verify those proofs.

Cancellation and controller crash require separate fault drills, not a fabricated
terminal report. Interrupt an active disposable attempt and verify retained
findings, stopped execution and signed cleanup. Then terminate only its controller
while the independent watchdog continues. Verify the actual cell is absent and
the journal contains authenticated persisted cleanup proof after heartbeat expiry;
an absent terminal record must remain incomplete. Also restart the watchdog,
exercise stale registrations and same-name replacements, and test collector
storage loss. Local tests exercise these mechanisms with synthetic authorities;
they do not establish live orphan-cell qualification.

## 5. Use in private CI

Run `live-suite` on a dedicated trusted runner with the private configuration
supplied separately from source. Use its expectation exit code for **research
regression checks** and retain its sanitized stdout report. Do not expose the
private evidence directory as a public CI artifact. Restrict provisioning and
signing authority, and do not provide it to untrusted pull-request code.

Public PR/pre-commit checks exercise the IPC, HTTP, healthy/weakened composition,
signature/binding/deadline/storage failures and privacy regressions using synthetic
target behavior. They also retain the existing Rust, Ruff and dependency CVE checks.
They do not access live credentials or qualify a target. Live environment selection,
actual inspector/provisioner implementation and the paired/fault qualification
packet remain required to complete the top-five deployment milestone.
