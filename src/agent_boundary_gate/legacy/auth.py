"""Authenticate historical 0.1 records without changing them or granting release authority."""

import hashlib
import json
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_boundary_gate.legacy.v0_1 import Contract, SignedRecord


def _canonical(record: Contract) -> bytes:
    return json.dumps(
        record.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def authenticate_legacy(record: SignedRecord, trusted_keys: Mapping[str, Ed25519PublicKey]) -> bool:
    key = trusted_keys.get(record.result.signer_identity)
    if key is None:
        return False
    payload = (
        b"openshell-gate/terminal-record/0.1\0"
        + _canonical(record.result)
        + b"\0"
        + _canonical(record.evidence)
    )
    try:
        key.verify(bytes.fromhex(record.signature), payload)
    except (InvalidSignature, ValueError):
        return False
    return (
        "sha256:" + hashlib.sha256(_canonical(record.evidence)).hexdigest()
        == record.result.evidence_manifest_digest
    )
