# Using the Python library

The library is usable for offline signed-record policy evaluation, private local
evidence storage, and loopback integration exercises. The API is a prototype and
may change. Every decision carries `qualification: m0-prototype` and
`release_eligible: false`, including a `pass` decision.

| Use | Available today | What it establishes |
| --- | --- | --- |
| Offline policy evaluation | `gate_policy.evaluate` | Terminal signature, bindings, source inventory, freshness, aggregation and veto policy |
| Stored evidence verification | `evaluate(..., evidence_store=store)` | Also retrieves manifest, effect, source and nested monitor heartbeat bytes and checks their digests |
| Loopback integration | `local_rig.local_run` | Real local HTTP receiver observations with simulated enforcement and monitoring |
| Custom attempt orchestration | `lifecycle.run_attempt` | Composes backend, observer, optional agent, monitor and lease recovery interfaces |
| Read-only OpenShell inspection | `doctor.openshell_doctor` / CLI `doctor` | Pinned CLI, lease expiry, sandbox identity/phase and active policy observations; no authenticated readiness |
| Live OpenShell qualification | Pending | Requires a pinned isolated rig, independent services and fault qualification |

An [experimental live workflow](live-workflow.md) now provides a supported command
composition path and host-side services. It requires a real, independently owned
environment-specific inspector/provisioner; no synthetic fallback is supplied.
For library composition, load a trusted private `LiveConfig` and call
`live.live_run(config, new_private_output_directory)` to obtain a sanitized report
and prototype exit code. `live_run` does not provision a cell or grant qualification.

Hermes, OpenCode and OpenClaw adapters are planned. Typed tool-request contracts
do not imply an implemented agent adapter. Check support with
`agent-boundary-gate adapters`.

For a custom OpenShell integration, choose `probe_runtime="python3"` or `"perl"`
in the backend constructor. The default requires Python in the sandbox; Perl
requires `IO::Socket::IP` and `Socket`. Pin the selected runtime and its policy
configuration. Set `run_attempt(..., readiness_budget=15.0, cleanup_budget=45.0)`
explicitly if those bounds fit measured rig latency; these are starting examples,
not qualified defaults. Both remain bounded at sixty seconds, and readiness
cannot outlive dispatch. See the [live-rig handoff](live-rig-handoff.md) for active
policy revision discovery, sanitized diagnostics, and timing/trust requirements.
The [compatibility doctor guide](compatibility-doctor.md) provides CLI inputs,
report interpretation and limitations for read-only inspection.

## Install from source

Requires Python 3.12+. From a checkout:

```sh
uv sync --frozen --no-editable
uv run --no-sync python examples/library_policy.py
```

The package is installed as `agent_boundary_gate`. These examples run against the
installed wheel. They require no model endpoint, credentials or live OpenShell
target. Examples and case files are source-checkout resources, not wheel data.
There is no published PyPI installation requirement assumed by this guide.

## Run a loopback attempt

```sh
uv run --no-sync python examples/library_loopback.py --output artifacts/library-healthy
uv run --no-sync python examples/library_loopback.py --output artifacts/library-weakened --weakened
```

The first returns prototype `pass` with exit code 0. The weakened run sends the
forbidden request and returns `criteria_failed` with exit code 1. Inconclusive
runs return 2, containment incidents 3. Evidence directories are private and
ignored by Git. The example generates signing keys in memory and never persists
private keys.

The core call is:

```python
from pathlib import Path
from agent_boundary_gate.local_rig import local_run

decision = local_run(
    Path("examples/denied-egress-v1.json"),
    Path("artifacts/my-attempt"),
    weakened=False,
)
print(decision.release_decision, decision.raw_aggregate)
assert decision.release_eligible is False
```

`local_run` captures a complete bounded attempt, persists evidence, signs the
terminal record, then evaluates it with stored artifact verification enabled.
It returns a `GateDecision`. A private packet containing the dispatch, record and
decision is also written under its digest filename in the output store. The
packet's ephemeral public key is for fixture inspection; it is not a CI trust
anchor. This exercise does not test actual OpenShell denial or tamper resistance.

## Verify records with trusted inputs

For an integration, supply the dispatch snapshot and verifier keys from trusted
controller/CI configuration, independently of returned records. Use Pydantic's
JSON constructors for wire data; do not construct trusted input by copying values
from an untrusted result.

```python
from datetime import UTC, datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import TypeAdapter
from agent_boundary_gate.contracts import Dispatch, SignedRecord
from agent_boundary_gate.evidence import EvidenceStore
from agent_boundary_gate.gate_policy import evaluate

dispatch = Dispatch.model_validate_json(Path("dispatch.json").read_bytes())
records = TypeAdapter(list[SignedRecord]).validate_json(Path("records.json").read_bytes())
key = Ed25519PublicKey.from_public_bytes(Path("verifier-public-key.bin").read_bytes())
store = EvidenceStore(Path("artifacts/evidence"), create=False)
decision = evaluate(
    dispatch,
    records,
    {"verifier-id": key},
    now=datetime.now(UTC),
    job_complete=True,  # from the trusted job controller
    server_aggregate=1.0,  # replace with the actual server-reported aggregate
    evidence_store=store,
)
print(decision.model_dump_json(indent=2))
```

These paths are integration inputs, not files generated by the offline fixture
example. The public key file contains exactly 32 raw Ed25519 bytes. The signer ID
must match an identity authorized by your verifier configuration. The dispatch
deadline and signed record validity must still cover evaluation time.

Equivalent CLI:

```sh
uv run --no-sync agent-boundary-gate verify \
  --dispatch dispatch.json --records records.json \
  --signer verifier-id --public-key verifier-public-key.bin \
  --evidence-directory artifacts/evidence --job-complete --server-aggregate 1.0
```

With `evidence_store`, missing, changed, oversized, public, symlink or nonregular
required artifacts make the result incomplete. Optional artifact loss degrades
diagnostics. Already authenticated violation/incident assertions are retained;
storage failure cannot turn them into passing outcomes. Without `evidence_store`,
`evaluate` performs terminal contract checks only, preserving the existing API for
synthetic fixtures and callers that do not have stored evidence.

`observed_effect_refs` are mandatory outcome proof with no optional designation.
Only source artifacts marked `corroborating` can degrade diagnostics on loss.
An artifact used both as effect proof and as an optional source remains required
in its effect role. A veto waiver does not waive required proof or change the
raw aggregate.

Digest checks establish integrity and availability of bytes bound by the terminal
signature. They do not independently prove observer claims, replay monitor
coverage, or reauthenticate broker/monitor issuers. Those qualification steps
remain pending; an authenticated controller assertion is not a live proof.

## Store and retrieve evidence

```python
from pathlib import Path
from agent_boundary_gate.evidence import EvidenceStore

store = EvidenceStore(Path("artifacts/private-evidence"))
reference = store.persist_json({"kind": "synthetic-observation"})
raw = store.read(reference)
```

References are `sha256:` plus 64 lowercase hexadecimal digits. Retrieval hashes
exact stored bytes, not reformatted JSON. Reads default to at most 4 MiB per
artifact; monitor heartbeat reads are capped at 64 KiB. Larger required artifacts
fail closed under this prototype policy. Directory mode must be `0700`, artifact
mode private (`0600` when created by the store). `create=False` opens an existing
store without creating a missing directory. Reads do not follow artifact symlinks
or block on FIFOs. Keep the store and ancestor directories controlled by the
collector and inaccessible to the workload identity.

Stored-evidence evaluation also shares a budget of 1,024 read attempts and 32 MiB
across all records, manifests, sources, effects and nested heartbeat references.
Repeated references count again. Successful reads charge actual bytes; failed
reads conservatively charge their requested limit plus the one-byte oversize
probe. Once a budget is exhausted, no further store reads occur and
`evidence-read-budget-exceeded` withholds pass, even for an optional source.
Violation/incident precedence is preserved. This bounds artifact I/O; it does not
bound input JSON parsing, signature work or the runtime of a custom store.

Local storage does not establish remote replication, independent collector
authority or whole-cell durability. RustFS/MLflow integration is pending.

## Compose a custom attempt

`run_attempt` accepts a trusted `Dispatch`, frozen `CaseSpec`, boundary backend,
observer, `EvidenceStore`, signing key, signer identity and `AttemptControl`.
It returns a `SignedRecord`; evaluate that record separately. Read the protocols
in `backends/__init__.py`, `observers/__init__.py` and `agents/__init__.py` before
implementing an adapter. Backend execution success alone is not an outcome oracle.

`AttemptControl()` starts with unknown health and prevents replay. Only a local
simulation should opt into `AttemptControl.for_fixture(dispatch.binding)`.
A leased backend requires a matching `MonitorSession` and `ControllerLease` via
`run_attempt(..., recovery=controller_lease)`. Supply fresh signed healthy
heartbeats before execution and renew them throughout the attempt. Loss and
incidents latch for that attempt; a later healthy message cannot clear them.

OpenShell also requires a pinned CLI digest, trusted lease context and a
`ReceiptProvider` plus purpose-scoped `ReceiptVerifier`. Run the recovery worker
outside the workload and controller failure domain with an independent cleanup
broker. This repository does not yet ship a qualified remote broker, heartbeat
transport or provisioning deployment. See the [live-rig handoff](live-rig-handoff.md),
[receipt ADR](adr/0003-authenticated-lifecycle-receipts.md) and
[monitor/recovery ADR](adr/0004-monitor-and-lease-recovery.md) for requirements.
