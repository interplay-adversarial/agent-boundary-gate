import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from receipt_support import FakeReceiptBroker, lease_and_binding

from agent_boundary_gate.receipts import (
    CleanupClaim,
    LeaseBinding,
    LifecycleReceipt,
    ReadinessClaim,
    ReceiptRejected,
    ReceiptVerifier,
    SignedLifecycleReceipt,
    receipt_payload,
    sign_receipt,
)


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.lease, self.binding = lease_and_binding()
        self.broker = FakeReceiptBroker(cleanup=True)
        self.verifier = self.broker.verifier
        self.now = datetime.now(UTC)
        self.request = self.verifier.request("readiness", self.lease)

    def receipt(self, request=None, **changes):
        request = request or self.request
        values = {
            "signer_identity": "synthetic-broker",
            "request": request,
            "issued_at": self.now - timedelta(seconds=1),
            "expires_at": self.now + timedelta(seconds=29),
            "claim": ReadinessClaim(
                state="ready", effective_policy_digest=self.lease.effective_policy_digest
            )
            if request.purpose == "readiness"
            else CleanupClaim(state="destroyed", scope="whole-cell"),
        }
        return LifecycleReceipt(**(values | changes))

    def verify(self, receipt, *, request=None, verifier=None, key=None, now=None):
        raw = sign_receipt(receipt, key or self.broker.key).model_dump_json().encode()
        return (verifier or self.verifier).verify(
            raw, request=request or self.request, now=now or self.now
        )

    def test_valid_readiness_and_cleanup(self):
        receipt = self.receipt()
        self.assertEqual(self.verify(receipt), receipt)
        request = self.verifier.request("cleanup", self.lease)
        self.assertEqual(
            self.verify(self.receipt(request), request=request).claim.state, "destroyed"
        )

    def test_changed_context_or_challenge_is_rejected(self):
        for changes in (
            {"binding_digest": "sha256:" + "b" * 64},
            {"run_id": "other-run"},
            {"attempt_id": "other-attempt"},
            {"lease_id": "other-lease"},
            {"cell_uid": "other-cell"},
            {"effective_policy_digest": "sha256:" + "b" * 64},
            {"lease_expires_at": self.lease.lease_expires_at + timedelta(seconds=1)},
            {"component": self.lease.component.model_copy(update={"instance_uid": "replacement"})},
            {"component": self.lease.component.model_copy(update={"generation": "replacement"})},
        ):
            request = self.request.model_copy(
                update={"binding": self.lease.model_copy(update=changes)}
            )
            with self.subTest(changes=changes), self.assertRaises(ReceiptRejected):
                self.verify(self.receipt(request))
        new_request = self.verifier.request("readiness", self.lease)
        self.assertNotEqual(new_request.challenge, self.request.challenge)
        with self.assertRaises(ReceiptRejected):
            self.verify(self.receipt(), request=new_request)

    def test_expired_future_and_excessive_lifetime_are_rejected(self):
        for changes in (
            {"issued_at": self.now - timedelta(seconds=30), "expires_at": self.now},
            {"issued_at": self.now + timedelta(seconds=1)},
            {
                "issued_at": self.now - timedelta(seconds=61),
                "expires_at": self.now + timedelta(seconds=1),
            },
            {"expires_at": self.now + timedelta(seconds=60)},
        ):
            with self.subTest(changes=changes), self.assertRaises(ReceiptRejected):
                self.verify(self.receipt(**changes))

    def test_wrong_policy_claim_is_rejected(self):
        claim = ReadinessClaim(state="ready", effective_policy_digest="sha256:" + "b" * 64)
        with self.assertRaises(ReceiptRejected):
            self.verify(self.receipt(claim=claim))

    def test_readiness_cannot_outlive_lease(self):
        lease = self.lease.model_copy(update={"lease_expires_at": self.now + timedelta(seconds=10)})
        request = self.verifier.request("readiness", lease)
        with self.assertRaises(ReceiptRejected):
            self.verify(self.receipt(request), request=request)
        lease = self.lease.model_copy(update={"lease_expires_at": self.now})
        request = self.verifier.request("readiness", lease)
        with self.assertRaises(ReceiptRejected):
            self.verify(self.receipt(request), request=request)

    def test_fresh_cleanup_is_valid_after_lease_expiry(self):
        lease = self.lease.model_copy(update={"lease_expires_at": self.now - timedelta(seconds=10)})
        request = self.verifier.request("cleanup", lease)
        self.assertEqual(
            self.verify(self.receipt(request), request=request).claim.state, "destroyed"
        )

    def test_wrong_key_unknown_signer_and_wrong_purpose_authority_rejected(self):
        with self.assertRaises(ReceiptRejected):
            self.verify(self.receipt(), key=Ed25519PrivateKey.generate())
        with self.assertRaises(ReceiptRejected):
            self.verify(self.receipt(signer_identity="unknown-broker"))
        verifier = ReceiptVerifier(
            readiness_keys={}, cleanup_keys={"synthetic-broker": self.broker.key.public_key()}
        )
        with self.assertRaises(ReceiptRejected):
            self.verify(self.receipt(), verifier=verifier)
        verifier = ReceiptVerifier(
            readiness_keys={"synthetic-broker": self.broker.key.public_key()}, cleanup_keys={}
        )
        request = self.verifier.request("cleanup", self.lease)
        with self.assertRaises(ReceiptRejected):
            self.verify(self.receipt(request), request=request, verifier=verifier)

    def test_trust_registry_is_snapshotted(self):
        keys = {"synthetic-broker": self.broker.key.public_key()}
        verifier = ReceiptVerifier(readiness_keys=keys, cleanup_keys={})
        keys.clear()
        self.assertEqual(self.verify(self.receipt(), verifier=verifier), self.receipt())

    def test_tampering_and_signature_domain_confusion_are_rejected(self):
        signed = sign_receipt(self.receipt(), self.broker.key)
        raw = signed.model_dump(mode="json")
        raw["receipt"]["signer_identity"] = "other-broker"
        with self.assertRaises(ReceiptRejected):
            self.verifier.verify(json.dumps(raw).encode(), request=self.request, now=self.now)
        payload = receipt_payload(self.receipt()).replace(
            b"agent-boundary-gate/lifecycle-receipt/1.0", b"agent-boundary-gate/terminal-record/0.2"
        )
        signed = signed.model_copy(update={"signature": self.broker.key.sign(payload).hex()})
        with self.assertRaises(ReceiptRejected):
            self.verifier.verify(
                signed.model_dump_json().encode(), request=self.request, now=self.now
            )

    def test_malformed_oversized_or_nonbytes_receipts_are_rejected(self):
        for raw in (b"not-json", b"{}", b" " * 65537, "{}", True):
            with self.subTest(raw_type=type(raw)), self.assertRaises(ReceiptRejected):
                self.verifier.verify(raw, request=self.request, now=self.now)
        signed = sign_receipt(self.receipt(), self.broker.key).model_dump(mode="json")
        for changes in (
            {"algorithm": "none"},
            {"schema_version": "0.2"},
            {"signature": "invalid"},
            {"extra": True},
        ):
            with self.subTest(changes=changes), self.assertRaises(ReceiptRejected):
                self.verifier.verify(
                    json.dumps(signed | changes).encode(), request=self.request, now=self.now
                )

    def test_naive_times_bad_claim_scope_and_unknown_role_rejected(self):
        for field in ("issued_at", "expires_at"):
            with self.assertRaises(ValidationError):
                self.receipt(**{field: datetime(2026, 1, 1)})
        with self.assertRaises(ValidationError):
            LeaseBinding(**(self.lease.model_dump() | {"lease_expires_at": datetime(2026, 1, 1)}))
        with self.assertRaises(ValidationError):
            self.receipt(claim=CleanupClaim(state="destroyed", scope="whole-cell"))
        with self.assertRaises(ValidationError):
            CleanupClaim(state="destroyed", scope="sandbox")
        with self.assertRaises(ValidationError):
            LeaseBinding(
                **(
                    self.lease.model_dump()
                    | {"component": self.lease.component.model_copy(update={"role": "agent"})}
                )
            )
        with self.assertRaises(ReceiptRejected):
            self.verify(self.receipt(), now=datetime(2026, 1, 1))

    def test_provider_returns_wire_bytes_without_keys(self):
        raw = self.broker.fetch(self.request, deadline=1, cancelled=Event())
        receipt = self.verifier.verify(raw, request=self.request, now=datetime.now(UTC))
        self.assertEqual(receipt.request, self.request)
        self.assertNotIn("public_key", raw.decode())

    def test_receipt_schema_matches_exported_schema(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "schemas/receipts/1.0/signed-lifecycle-receipt.json"
        )
        self.assertEqual(json.loads(path.read_text()), SignedLifecycleReceipt.model_json_schema())
