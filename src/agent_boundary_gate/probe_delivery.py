"""Independent artifact pins and challenge-bound immutable delivery attestations.

Only an authorized external supervisor can establish delivery. Workload output,
unsigned build metadata and controller-supplied booleans cannot establish it.
"""

import json
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime
from threading import Event
from types import MappingProxyType
from typing import Annotated, Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, ValidationError, field_validator, model_validator

from agent_boundary_gate.contracts import Digest, Identifier
from agent_boundary_gate.receipts import (
    MAX_RECEIPT_AGE,
    MAX_RECEIPT_BYTES,
    Challenge,
    LeaseBinding,
    ReceiptContract,
)

PROTOCOL_DIGEST: Literal[
    "sha256:7962045299568a25cd16d121203ae5dfd25dcda9eeea08288859e44b03dc4a4d"
] = "sha256:7962045299568a25cd16d121203ae5dfd25dcda9eeea08288859e44b03dc4a4d"
PROBE_PATH: Literal["/opt/agent-boundary-gate/probes/http/0.2.0/gate-http-probe"] = (
    "/opt/agent-boundary-gate/probes/http/0.2.0/gate-http-probe"
)
DOMAIN = b"agent-boundary-gate/probe-delivery-receipt/1.0\0"


class RustProbeArtifact(ReceiptContract):
    """Out-of-band baseline pins; never derive expected values from a download."""

    package_version: Literal["0.2.0"] = "0.2.0"
    protocol: Literal["agent-boundary-gate/http-probe/1.0"] = "agent-boundary-gate/http-probe/1.0"
    # Literal[] requires a literal value written directly, not a reference to
    # PROTOCOL_DIGEST, even though it's a module-level constant (PEP 586; mypy enforces
    # this literally). The assert below the two classes keeps this duplicated value
    # from silently drifting out of sync with that constant.
    protocol_digest: Literal[
        "sha256:7962045299568a25cd16d121203ae5dfd25dcda9eeea08288859e44b03dc4a4d"
    ] = PROTOCOL_DIGEST
    target: Literal["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"]
    binary_digest: Digest
    source_digest: Digest
    manifest_digest: Digest


class RustProbeDeployment(ReceiptContract):
    artifact: RustProbeArtifact
    workload_image_digest: Digest
    # Same Literal[]-requires-a-literal constraint as protocol_digest above.
    executable_path: Literal["/opt/agent-boundary-gate/probes/http/0.2.0/gate-http-probe"] = (
        PROBE_PATH
    )


# Explicit checks, not `assert`: this module's drift guard must still run under
# `python -O`, which strips assert statements.
if RustProbeArtifact.model_fields["protocol_digest"].default != PROTOCOL_DIGEST:
    raise RuntimeError("probe-delivery-protocol-digest-drift")
if RustProbeDeployment.model_fields["executable_path"].default != PROBE_PATH:
    raise RuntimeError("probe-delivery-executable-path-drift")


class DeliveryRequest(ReceiptContract):
    challenge: Challenge
    binding: LeaseBinding
    deployment: RustProbeDeployment


class DeliveryReceipt(ReceiptContract):
    signer_identity: Identifier
    request: DeliveryRequest
    issued_at: datetime
    expires_at: datetime
    # The supervisor must independently inspect the actual image, architecture,
    # executable bytes/location and mount/exec authorization. Echoing a request
    # without inspecting the cell is not a conforming issuer implementation.
    state: Literal["verified-immutable-delivery"]
    immutable_until: datetime

    @field_validator("issued_at", "expires_at", "immutable_until")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("delivery times must be timezone aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def lifetime(self):
        if self.expires_at <= self.issued_at:
            raise ValueError("delivery expiry must follow issuance")
        return self


class SignedDeliveryReceipt(ReceiptContract):
    receipt: DeliveryReceipt
    algorithm: Literal["Ed25519"] = "Ed25519"
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


def delivery_payload(receipt: DeliveryReceipt) -> bytes:
    return (
        DOMAIN
        + json.dumps(
            receipt.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    )


def sign_delivery(receipt: DeliveryReceipt, key: Ed25519PrivateKey) -> SignedDeliveryReceipt:
    return SignedDeliveryReceipt(
        receipt=receipt, signature=key.sign(delivery_payload(receipt)).hex()
    )


class DeliveryRejected(ValueError):
    pass


class DeliveryVerifier:
    def __init__(self, keys: Mapping[str, Ed25519PublicKey]):
        self._keys = MappingProxyType(dict(keys))

    def request(self, binding: LeaseBinding, deployment: RustProbeDeployment) -> DeliveryRequest:
        return DeliveryRequest(
            challenge=secrets.token_hex(32), binding=binding, deployment=deployment
        )

    def verify(self, raw: object, *, request: DeliveryRequest, now: datetime) -> DeliveryReceipt:
        # Typed as object, not bytes: the isinstance check below is the real guard, and
        # DeliveryProvider.fetch's own contract is bytes | None -- a provider that
        # returns nothing (deadline/cancellation/no delivery) must reject here, not
        # raise a raw TypeError from a str/bytes-only caller-side check beforehand.
        if not isinstance(raw, bytes) or len(raw) > MAX_RECEIPT_BYTES or now.utcoffset() is None:
            raise DeliveryRejected("probe-delivery-rejected")
        try:
            signed = SignedDeliveryReceipt.model_validate_json(raw)
            receipt = signed.receipt
            key = self._keys.get(receipt.signer_identity)
            if key is None:
                raise DeliveryRejected("probe-delivery-rejected")
            key.verify(bytes.fromhex(signed.signature), delivery_payload(receipt))
            if not (
                receipt.request == request
                and receipt.issued_at
                <= now
                < receipt.expires_at
                <= request.binding.lease_expires_at
                and now - receipt.issued_at <= MAX_RECEIPT_AGE
                and receipt.expires_at - receipt.issued_at <= MAX_RECEIPT_AGE
                and receipt.immutable_until >= request.binding.lease_expires_at
            ):
                raise DeliveryRejected("probe-delivery-rejected")
            return receipt
        except (ValidationError, InvalidSignature, ValueError) as error:
            raise DeliveryRejected("probe-delivery-rejected") from error


class DeliveryProvider(Protocol):
    def fetch(self, request: DeliveryRequest, *, deadline: float, cancelled: Event) -> bytes | None:
        """Inspect the cell independently; bounded transport/issuance remain deployment work."""
        ...
