"""Local restricted evidence persistence. Retention and remote storage are separate work."""

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from uuid import uuid4


def bytes_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def json_bytes(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class EvidenceStore:
    def __init__(self, root: Path, *, create: bool = True):
        if root.is_symlink():
            raise ValueError("evidence root cannot be a symlink")
        if create:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not root.is_dir() or root.stat().st_mode & 0o077:
            raise ValueError("evidence root must be private (mode 0700)")
        self.root = root.resolve()

    def read(self, reference: str, *, max_bytes: int = 4 * 1024 * 1024) -> bytes:
        """Retrieve bounded private regular-file bytes and verify their exact digest.

        The store and its ancestor directories must be controlled by the collector,
        outside the workload identity. Errors never include artifact contents.
        """
        if not isinstance(reference, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", reference):
            raise ValueError("invalid-evidence-reference")
        if type(max_bytes) is not int or max_bytes <= 0:
            raise ValueError("invalid-evidence-read-limit")
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if os.fstat(directory).st_mode & 0o077:
                raise ValueError("evidence-directory-not-private")
            fd = os.open(
                reference.removeprefix("sha256:") + ".json",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory,
            )
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                    raise ValueError("evidence-file-not-private-or-regular")
                if info.st_size > max_bytes:
                    raise ValueError("evidence-read-limit-exceeded")
                data = stream.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise ValueError("evidence-read-limit-exceeded")
                if bytes_digest(data) != reference:
                    raise ValueError("evidence-digest-mismatch")
                return data
        finally:
            os.close(directory)

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
