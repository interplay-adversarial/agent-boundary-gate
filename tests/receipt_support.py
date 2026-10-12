"""Synthetic in-memory broker for receipt tests; no transport or live attestation."""

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_boundary_gate.auth import digest
from agent_boundary_gate.contracts import ComponentIdentity
from agent_boundary_gate.fixtures import fixture
from agent_boundary_gate.receipts import (
    CleanupClaim,
    LeaseBinding,
    LifecycleReceipt,
    ReadinessClaim,
    ReceiptVerifier,
    sign_receipt,
)


def lease_and_binding():
    binding = fixture("healthy")[0].binding
    profile = binding.target_profile
    profile = profile.model_copy(
        update={"boundary": profile.boundary.model_copy(update={"id": "openshell"})}
    )
    binding = binding.model_copy(update={"target_profile": profile})
    lease = LeaseBinding(
        binding_digest=digest(binding),
        run_id=binding.run_id,
        attempt_id=binding.attempt_id,
        lease_id="synthetic-lease",
        cell_uid="synthetic-cell",
        component=ComponentIdentity(
            component_id="openshell",
            role="boundary",
            instance_uid="sandbox-1",
            generation="supervisor-1",
        ),
        effective_policy_digest=binding.effective_policy_digest,
        lease_expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    return lease, binding


class FakeReceiptBroker:
    def __init__(self, *, generation="supervisor-1", cleanup=False):
        self.key = Ed25519PrivateKey.generate()
        self.verifier = ReceiptVerifier(
            readiness_keys={"synthetic-broker": self.key.public_key()},
            cleanup_keys={"synthetic-broker": self.key.public_key()},
        )
        self.generation = generation
        self.cleanup = cleanup
        self.requests = []

    def fetch(self, request, *, deadline, cancelled):
        self.requests.append(request)
        if request.purpose == "readiness":
            if self.generation is None:
                return None
            component = request.binding.component.model_copy(update={"generation": self.generation})
            request = request.model_copy(
                update={"binding": request.binding.model_copy(update={"component": component})}
            )
            claim = ReadinessClaim(
                effective_policy_digest=request.binding.effective_policy_digest, state="ready"
            )
        else:
            if not self.cleanup:
                return None
            claim = CleanupClaim(state="destroyed", scope="whole-cell")
        now = datetime.now(UTC)
        receipt = LifecycleReceipt(
            signer_identity="synthetic-broker",
            request=request,
            issued_at=now,
            expires_at=now + timedelta(seconds=30),
            claim=claim,
        )
        return sign_receipt(receipt, self.key).model_dump_json().encode()
