"""Challenge-bound broker receipts, independent of terminal-record wire versions."""

import json
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from threading import Event
from types import MappingProxyType
from typing import Annotated, Literal, Protocol, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from agent_boundary_gate.contracts import ComponentIdentity, Digest, Identifier

Purpose = Literal["readiness", "cleanup"]
Challenge = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
DOMAIN = b"agent-boundary-gate/lifecycle-receipt/1.0\0"
MAX_RECEIPT_BYTES = 65536
MAX_RECEIPT_AGE = timedelta(seconds=60)


class ReceiptContract(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, revalidate_instances="always"
    )
    schema_version: Literal["1.0"] = "1.0"


class LeaseBinding(ReceiptContract):
    """Trusted provisioning context, never learned from a returned receipt."""

    binding_digest: Digest
    run_id: Identifier
    attempt_id: Identifier
    lease_id: Identifier
    cell_uid: Identifier
    component: ComponentIdentity
    effective_policy_digest: Digest
    lease_expires_at: datetime

    @field_validator("lease_expires_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("receipt times must be timezone aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def boundary_role(self) -> Self:
        if self.component.role != "boundary":
            raise ValueError("lease requires a boundary component")
        return self


class ReceiptRequest(ReceiptContract):
    purpose: Purpose
    challenge: Challenge
    binding: LeaseBinding


class ReadinessClaim(ReceiptContract):
    state: Literal["ready"]
    effective_policy_digest: Digest


class CleanupClaim(ReceiptContract):
    state: Literal["destroyed"]
    scope: Literal["whole-cell"]


class LifecycleReceipt(ReceiptContract):
    signer_identity: Identifier
    request: ReceiptRequest
    issued_at: datetime
    expires_at: datetime
    claim: Annotated[ReadinessClaim | CleanupClaim, Field(discriminator="state")]

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("receipt times must be timezone aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def scope_and_time(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("receipt expiry must follow issuance")
        if (self.request.purpose == "readiness") != isinstance(self.claim, ReadinessClaim):
            raise ValueError("receipt claim must match request purpose")
        return self


class SignedLifecycleReceipt(ReceiptContract):
    receipt: LifecycleReceipt
    algorithm: Literal["Ed25519"] = "Ed25519"
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


def receipt_payload(receipt: LifecycleReceipt) -> bytes:
    # Same project-specific JSON convention, with a separate signature domain.
    return DOMAIN + json.dumps(
        receipt.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def sign_receipt(receipt: LifecycleReceipt, key: Ed25519PrivateKey) -> SignedLifecycleReceipt:
    return SignedLifecycleReceipt(
        receipt=receipt, signature=key.sign(receipt_payload(receipt)).hex()
    )


class ReceiptRejected(ValueError):
    """A receipt cannot establish readiness or destruction; never expose raw data."""


class ReceiptVerifier:
    def __init__(
        self,
        *,
        readiness_keys: Mapping[str, Ed25519PublicKey],
        cleanup_keys: Mapping[str, Ed25519PublicKey],
    ):
        # Purpose-specific authorization and snapshots prevent caller mutation.
        self._keys = {
            "readiness": MappingProxyType(dict(readiness_keys)),
            "cleanup": MappingProxyType(dict(cleanup_keys)),
        }

    def request(self, purpose: Purpose, binding: LeaseBinding) -> ReceiptRequest:
        return ReceiptRequest(purpose=purpose, challenge=secrets.token_hex(32), binding=binding)

    def verify(self, raw: bytes, *, request: ReceiptRequest, now: datetime) -> LifecycleReceipt:
        if not isinstance(raw, bytes) or len(raw) > MAX_RECEIPT_BYTES or now.utcoffset() is None:
            raise ReceiptRejected("lifecycle-receipt-rejected")
        try:
            signed = SignedLifecycleReceipt.model_validate_json(raw)
            receipt = signed.receipt
            key = self._keys[request.purpose].get(receipt.signer_identity)
            if key is None:
                raise ReceiptRejected("lifecycle-receipt-rejected")
            key.verify(bytes.fromhex(signed.signature), receipt_payload(receipt))
            valid = (
                receipt.request == request
                and receipt.issued_at <= now < receipt.expires_at
                and now - receipt.issued_at <= MAX_RECEIPT_AGE
                and receipt.expires_at - receipt.issued_at <= MAX_RECEIPT_AGE
            )
            if isinstance(receipt.claim, ReadinessClaim):
                valid = (
                    valid
                    and receipt.claim.effective_policy_digest
                    == request.binding.effective_policy_digest
                    and now < request.binding.lease_expires_at
                    and receipt.expires_at <= request.binding.lease_expires_at
                )
            if not valid:
                raise ReceiptRejected("lifecycle-receipt-rejected")
            return receipt
        except (ValidationError, InvalidSignature, ValueError) as error:
            raise ReceiptRejected("lifecycle-receipt-rejected") from error


class ReceiptProvider(Protocol):
    def fetch(self, request: ReceiptRequest, *, deadline: float, cancelled: Event) -> bytes | None:
        """Return bounded untrusted JSON; transport must obey deadline/cancellation."""
        ...
