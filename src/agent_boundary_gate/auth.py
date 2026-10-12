"""Authenticate terminal records with CI-owned, out-of-band public keys."""

import hashlib
import json
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agent_boundary_gate.contracts import Contract, EvidenceManifest, RunResult, SignedRecord


def canonical(record: Contract) -> bytes:
    """Project-specific canonical JSON; not a claim of RFC 8785 compliance."""
    return json.dumps(
        record.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def digest(record: Contract) -> str:
    return "sha256:" + hashlib.sha256(canonical(record)).hexdigest()


def payload(result: RunResult, evidence: EvidenceManifest) -> bytes:
    return (
        b"agent-boundary-gate/terminal-record/0.2\0"
        + canonical(result)
        + b"\0"
        + canonical(evidence)
    )


def sign(result: RunResult, evidence: EvidenceManifest, key: Ed25519PrivateKey) -> SignedRecord:
    return SignedRecord(
        result=result,
        evidence=evidence,
        algorithm="Ed25519",
        signature=key.sign(payload(result, evidence)).hex(),
    )


def authenticate(record: SignedRecord, trusted_keys: Mapping[str, Ed25519PublicKey]) -> bool:
    key = trusted_keys.get(record.result.signer_identity)
    if key is None:
        return False
    try:
        key.verify(bytes.fromhex(record.signature), payload(record.result, record.evidence))
    except (InvalidSignature, ValueError):
        return False
    return digest(record.evidence) == record.result.evidence_manifest_digest
