# ADR-0007: Mitigation and advisory backends are pluggable and pin-verified

Status: proposed. Date: 2026-11-26.

[ADR-0006](0006-findings-as-derived-records.md) gives the gate findings. Turning a
finding into a mitigation, or into a vulnerability advisory, depends on the platform
and technology involved, and those will change. The gate ships one default for each and
lets others be onboarded later without changing core policy. Two precedents apply: the
`BoundaryBackend` protocol, which separates execution from independent observation and
allowlists its diagnostics, and the red-team worker, which verifies the installed
Interplay distribution, version and source digests against a pinned manifest before
admission. Core policy and signed contracts import no optional dependency.

## Decision

**Two protocols, no apply or submit.** `MitigationBackend` and `AdvisoryBackend` expose
identity, version and the kinds or formats they support, plus pure operations.

```python
class MitigationBackend(Protocol):
    backend_id: str
    backend_version: str
    intent_kinds: frozenset[str]
    def applicability(self, finding, candidate, target_profile) -> Applicability: ...
    def render(self, intent: MitigationIntent) -> RenderedArtifact: ...
    def validate(self, artifact: RenderedArtifact) -> ValidationReport: ...

class AdvisoryBackend(Protocol):
    backend_id: str
    backend_version: str
    formats: frozenset[str]
    def eligible(self, finding, component) -> Reportability: ...
    def draft(self, finding, component, evidence_bundle) -> AdvisoryDraft: ...
    def validate(self, draft: AdvisoryDraft) -> ValidationReport: ...
```

`render`, `draft` and `validate` have no side effects and make no network calls.
Applying a mitigation and submitting an advisory are not protocol methods. Applying is
a reviewed change in a version-controlled configuration repository, merged by a person.
Submitting is a person-approved action outside the gate. `mitigation-applied` and
`reported` events record that person and the change or submission reference.

**A typed intermediate, not free-form output.** `MitigationIntent` is versioned and
names an intent kind from a closed vocabulary, typed parameters, the target binding and
the finding references. It carries no commands, scripts or code. A backend declares which
kinds it renders. Adding a kind is a reviewed schema change; adding a backend for an
existing kind is onboarding. The first kinds are an egress allowlist narrowing and a
filesystem deny, both OpenShell concepts.

**Output is untrusted data.** A `RenderedArtifact` is size-bounded, content-addressed and
labeled with the backend's identity and version. The gate never executes it. It becomes
usable only after `validate()` passes and a verification run succeeds
([ADR-0006](0006-findings-as-derived-records.md)).

**Pin-verified loading.** A backend is enabled only through a pinned manifest naming its
package, version and source digests, verified before admission. There is no entry-point
scanning and no import by name from configuration. A third-party backend runs in a
separately locked environment with restricted credential inheritance, as the red-team
worker does. Backend identity is recorded in every event it produces.

**Defaults and order.** The shipped mitigation backend renders OpenShell sandbox policy:
egress by destination, port, binary, method and path, and filesystem rules. `validate()`
uses the validation of the pinned OpenShell version, because policy file field names are
not the same as the protobuf names. Guardrail configuration comes second, and OVN-Kubernetes
network policy later; OVN-Kubernetes is the only network provider in scope. The shipped
advisory backend writes OSV-style JSON, a CSAF 2.0 draft and a Markdown advisory to a
private local directory. Nothing leaves the machine.

**Reportability is derived, not assumed.** A missing rule in our own deployment's policy
is a configuration finding, not a vulnerability. An advisory draft needs a
vendor-identifiable component (`ComponentIdentity`), an affected-version basis and
evidence tier E3 or higher. Drafts for third-party components are private, carry a
do-not-distribute marker, and are never sent automatically. Backends for specific
disclosure channels are onboarded like any other and are not assumed here.

**Failure is explicit.** A renderer error or failed validation drops that candidate and
records an allowlisted reason code, in the style of `BACKEND_DIAGNOSTIC_REASONS`. No
partial artifact is kept.

## Consequences

Platform- and technology-specific backends can be added without touching decision
logic, and a backend cannot widen what the gate trusts: its output is data that must
still pass validation and a verification run. The cost is a pin-management burden per
backend and a closed intent vocabulary that needs review to extend.

Proposed work items: MIT-01 (protocol, OpenShell renderer, verify-by-rerun), CVE-01
(advisory protocol and local drafts), GRD-01 and NET-01 (later renderers). They are not
yet in the improvement roadmap.

Open: the exact OpenShell policy validation entry point to call; whether third-party
backends need a stronger isolation tier than the red-team worker's; and where backend
pins are published.
