"""Local restricted evidence persistence. Retention and remote storage are separate work."""

import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4


def bytes_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def json_bytes(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class EvidenceStore:
    def __init__(self, root: Path):
        if root.is_symlink():
            raise ValueError("evidence root cannot be a symlink")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if root.stat().st_mode & 0o077:
            raise ValueError("evidence root must be private (mode 0700)")
        self.root = root.resolve()

    def persist(self, data: bytes) -> str:
        digest = bytes_digest(data)
        destination = self.root / (digest.removeprefix("sha256:") + ".json")
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or destination.read_bytes() != data:
                raise ValueError("evidence content mismatch")
            return digest
        temporary = self.root / (".pending-" + uuid4().hex)
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            # The private directory is inaccessible to the workload identity in a real rig.
            os.replace(temporary, destination)
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
        return digest

    def persist_json(self, data: object) -> str:
        return self.persist(json_bytes(data))
