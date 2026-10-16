# ADR-0002: Portable adapters in one repository

Status: accepted for the prototype. Date: 2026-10-11.

The project is `agent-boundary-gate`, with the organization home
`interplay-adversarial/agent-boundary-gate`.
OpenShell is its first boundary backend. Agent applications and their execution
boundaries are selected independently in the signed target profile.

## Decision

Keep the core, built-in boundary backends, agent adapters and independent
observers in the same repository and Python distribution initially. This lets
contract changes and their implementations be reviewed together, with one
compatibility matrix and regression suite. Keep backend-specific dependencies
optional and runtime images independently pinned. The core must not require a
live model, DataDesigner, or an agent SDK for deterministic boundary tests.

```text
src/agent_boundary_gate/
  contracts.py, auth.py, gate_policy.py, lifecycle.py
  backends/
    openshell.py          implemented, live qualification pending
    fixture.py            loopback simulation only
  agents/
    __init__.py           protocol; OpenCode/OpenClaw adapters planned
    fixture.py             loopback simulation only
  observers/
    denied_egress.py      paired receiver oracle
  legacy/
    v0_1.py, auth.py      historical authentication, no release authority
```

Application adapters submit agent tool requests and attest the application's
effective configuration and instance generation. Boundary backends check runtime
readiness, execute frozen actions and request cleanup. Independent observers
establish effects and positive controls. Backend or agent output cannot substitute
for an outcome oracle. A component configuration/generation change withholds
approval and preserves previously observed violations.

## Supported and planned scope

OpenShell is implemented for the denied-egress action path but remains unqualified.
Loopback exercises the software integration path with simulated policy/monitoring.
OpenCode and OpenClaw are planned **agent adapters**, not shipped backends.
No agent/backend pairing is qualified merely because its interfaces compose.

Schema `0.2` distinguishes an optional agent pin from a required boundary pin and
records role-tagged instance identities and generations. Case declarations name
the control family, enforcement layer and required capabilities. HTTP replay and
tool-request actions are distinct wire types; typed tool requests are supported
by the protocol, not by the existing OpenShell or loopback executor.

Unsupported required capabilities, absent/mismatched adapters and unsupported
observers produce an explicit unsupported run, no passing numeric value and no
release approval. The support registry labels planned adapters without capabilities.
Future target-only application tests still need a separately declared outer
research boundary; the selected agent's permissions are not assumed to contain
the research environment.

## When to split an adapter into a dedicated repository

Split when there is a concrete need for independent maintainers, release cadence,
licensing, a different implementation language, or a substantial separately
deployed service. Preserve the core's versioned protocol and require conformance
tests against supported core versions. Keep one implementation source for each
adapter. Separation alone does not justify another copy of gate policy.

An eventual external package might be named `agent-boundary-gate-<backend>`;
that is a naming option, not a package published or required now. Independently
deployed brokers/receiver services can have separate images while their source
still lives here.

## Migration and limits

The Python package is `agent_boundary_gate`, CLI `agent-boundary-gate`, version
`0.2.0`. Local deployment notes and captured run artifacts are excluded from the
public source tree.

Historical `0.1` schemas/examples and signed evidence remain unchanged. The new
signature domain is `agent-boundary-gate/terminal-record/0.2`. Do not rewrite a
signed record to migrate it. Read-only legacy verification uses its original
schema and signature domain and cannot grant release authority.

Release eligibility remains disabled. Whole-target containment, authenticated
broker receipts, external watchdog reconciliation, remote capture, RustFS/MLflow,
live OpenShell qualification and the EvalHub adapter remain outstanding.
