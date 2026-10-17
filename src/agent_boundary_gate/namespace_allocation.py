"""Independent development allocation ledger; no signed gate authority.

Only an API create response establishes the retained UID. Lookup never retries
creation and never adopts a namespace using a name, label or current inventory.
"""

import fcntl
import json
import os
import re
import time
from pathlib import Path
from threading import Event, Lock
from typing import Annotated, Literal

from pydantic import Field, model_validator

from agent_boundary_gate.development import RUN_LABEL, Namespace
from agent_boundary_gate.doctor import read_regular_input
from agent_boundary_gate.evidence import EvidenceStore, bytes_digest, write_json_atomic
from agent_boundary_gate.process import AttemptStopped, bounded_process
from agent_boundary_gate.receipts import ReceiptContract
from agent_boundary_gate.rig_transport import UnixClient, private_parent

Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
UID = Annotated[str, Field(pattern=r"^[A-Za-z0-9-]{1,128}$")]


class NamespaceIntent(ReceiptContract):
    protocol: Literal["agent-boundary-gate/development-namespace-allocation/1"] = (
        "agent-boundary-gate/development-namespace-allocation/1"
    )
    operation_id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    config_digest: Digest
    context: Annotated[str, Field(min_length=1, max_length=200)]
    run: Annotated[str, Field(pattern=r"^gate-dev-[a-z0-9]{16}$")]
    namespace: Namespace
    role: Literal["cell", "receiver"]

    @model_validator(mode="after")
    def namespace_scope(self):
        if (self.role == "receiver" and self.namespace != self.run) or (
            self.role == "cell" and not re.fullmatch(r"gate-cell-[0-9a-f]{24}", self.namespace)
        ):
            raise ValueError("namespace-intent-scope-invalid")
        return self


class AllocationCall(ReceiptContract):
    operation: Literal["create", "lookup"]
    intent: NamespaceIntent


class AllocationRecord(ReceiptContract):
    intent: NamespaceIntent
    state: Literal["unresolved", "created"]
    uid: UID | None = None

    @model_validator(mode="after")
    def uid_required(self):
        if (self.state == "created") != (self.uid is not None):
            raise ValueError("namespace-allocation-state-invalid")
        return self


class NamespaceAllocatorConfig(ReceiptContract):
    socket_path: Path
    ledger_directory: Path
    kubernetes_executable: Path
    kubernetes_digest: Digest
    context: Annotated[str, Field(min_length=1, max_length=200)]
    protected_namespaces: Annotated[tuple[Namespace, ...], Field(min_length=1, max_length=128)]
    command_seconds: Annotated[int, Field(ge=1, le=45)] = 30
    max_operations: Annotated[int, Field(ge=1, le=1024)] = 128


class NamespaceAllocator:
    def __init__(self, config: NamespaceAllocatorConfig):
        self.config = NamespaceAllocatorConfig.model_validate(config)
        config = self.config
        self.store = EvidenceStore(config.ledger_directory)
        private_parent(self.store.root / "allocator.lock")
        self.lock = os.open(
            self.store.root / "allocator.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Bind retained records to this exact operator-owned deployment.
            # Partial writes are never proof; only committed records count.
            for pending in self.store.root.glob("*.pending"):
                if pending.name == "allocator-config.pending" or re.fullmatch(
                    r"[0-9a-f]{32}\.pending", pending.name
                ):
                    read_regular_input(pending, limit=65536, private=True)
                    pending.unlink()
            binding = self.store.root / "allocator-config.json"
            config_digest = bytes_digest(config.model_dump_json().encode())
            if binding.exists() or binding.is_symlink():
                if json.loads(read_regular_input(binding, limit=65536, private=True)) != {
                    "digest": config_digest
                }:
                    raise ValueError("namespace-allocator-config-changed")
            else:
                write_json_atomic(binding, {"digest": config_digest})
            raw = read_regular_input(config.kubernetes_executable, limit=256 * 1024 * 1024)
            if bytes_digest(raw) != config.kubernetes_digest:
                raise ValueError("namespace-allocator-executable-changed")
            self.executable = self.store.root / "kubernetes-snapshot"
            if self.executable.exists() or self.executable.is_symlink():
                if (
                    bytes_digest(
                        read_regular_input(self.executable, limit=256 * 1024 * 1024, private=True)
                    )
                    != config.kubernetes_digest
                ):
                    raise ValueError("namespace-allocator-snapshot-changed")
            else:
                fd = os.open(
                    self.executable, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500
                )
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            self.serial = Lock()
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.lock is not None:
            fd, self.lock = self.lock, None
            os.close(fd)

    def create(self, intent: NamespaceIntent, *, deadline, cancelled):
        result = bounded_process(
            [
                str(self.executable),
                "--context",
                self.config.context,
                "create",
                "-f",
                "-",
                "-o",
                "json",
            ],
            input_data=json.dumps(
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {"name": intent.namespace, "labels": {RUN_LABEL: intent.run}},
                }
            ).encode(),
            deadline=min(deadline, time.monotonic() + self.config.command_seconds),
            cancelled=cancelled,
        )
        if result.returncode:
            raise ValueError("namespace-allocator-create-failed")
        value = json.loads(result.stdout)
        if (
            not isinstance(value, dict)
            or value.get("apiVersion") != "v1"
            or value.get("kind") != "Namespace"
            or not isinstance(value.get("metadata"), dict)
            or value["metadata"].get("name") != intent.namespace
        ):
            raise ValueError("namespace-allocator-response-invalid")
        return AllocationRecord(intent=intent, state="created", uid=value["metadata"].get("uid"))

    def handle(self, raw: bytes, deadline: float, cancelled: Event) -> bytes:
        call = AllocationCall.model_validate_json(raw)
        intent = call.intent
        if (
            intent.context != self.config.context
            or intent.namespace in self.config.protected_namespaces
        ):
            raise ValueError("namespace-allocator-scope-invalid")
        while not self.serial.acquire(timeout=0.02):
            if cancelled.is_set() or time.monotonic() >= deadline:
                raise AttemptStopped("allocation-lock-stopped")
        try:
            if self.lock is None or cancelled.is_set() or time.monotonic() >= deadline:
                raise AttemptStopped("allocation-stopped")
            path = self.store.root / (intent.operation_id + ".json")
            record = AllocationRecord(intent=intent, state="unresolved")
            if path.exists() or path.is_symlink():
                record = AllocationRecord.model_validate_json(
                    read_regular_input(path, limit=65536, private=True)
                )
                if record.intent != intent:
                    raise ValueError("namespace-allocation-intent-mismatch")
                # A pending attempt is never retried, even after service restart.
            elif call.operation == "create":
                if (
                    sum(
                        1
                        for p in self.store.root.glob("*.json")
                        if re.fullmatch(r"[0-9a-f]{32}\.json", p.name)
                    )
                    >= self.config.max_operations
                ):
                    raise ValueError("namespace-allocator-capacity-exceeded")
                write_json_atomic(path, record.model_dump(mode="json"))
                record = self.create(intent, deadline=deadline, cancelled=cancelled)
                write_json_atomic(path, record.model_dump(mode="json"))
            return record.model_dump_json().encode()
        finally:
            self.serial.release()


class NamespaceAllocationClient:
    def __init__(self, socket_path: Path):
        self.transport = UnixClient(socket_path)

    def call(self, operation, intent, *, deadline, cancelled):
        raw = self.transport.call(
            AllocationCall(operation=operation, intent=intent).model_dump_json().encode(),
            deadline=deadline,
            cancelled=cancelled,
        )
        record = AllocationRecord.model_validate_json(raw)
        if record.intent != intent or record.state != "created":
            raise ValueError("namespace-allocation-unresolved")
        return record
