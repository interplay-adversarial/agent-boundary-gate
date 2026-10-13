"""Private host-side RPC. Never expose these sockets inside the evaluated cell."""

import os
import select
import socket
import stat
import struct
import time
from collections.abc import Callable
from pathlib import Path
from threading import BoundedSemaphore, Event, Thread

from agent_boundary_gate.process import AttemptStopped

MAX_PACKET = 65536


def private_parent(path: Path) -> None:
    metadata = path.parent.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise ValueError("private-service-directory-required")


def _ready(connection: socket.socket, *, deadline: float, cancelled: Event, write=False):
    while True:
        if cancelled.is_set():
            raise AttemptStopped("cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AttemptStopped("timeout")
        reads, writes, _ = select.select(
            [] if write else [connection], [connection] if write else [], [], min(0.02, remaining)
        )
        if reads or writes:
            return


def send_packet(connection: socket.socket, raw: bytes, *, deadline: float, cancelled: Event):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PACKET:
        raise ValueError("service-packet-limit")
    data = memoryview(struct.pack("!I", len(raw)) + raw)
    while data:
        _ready(connection, deadline=deadline, cancelled=cancelled, write=True)
        try:
            count = connection.send(data)
        except BlockingIOError:
            continue
        if not count:
            raise ValueError("service-connection-closed")
        data = data[count:]


def receive_packet(connection: socket.socket, *, deadline: float, cancelled: Event) -> bytes:
    def read(length):
        data = bytearray()
        while len(data) < length:
            _ready(connection, deadline=deadline, cancelled=cancelled)
            try:
                part = connection.recv(length - len(data))
            except BlockingIOError:
                continue
            if not part:
                raise ValueError("service-connection-closed")
            data.extend(part)
        return bytes(data)

    length = struct.unpack("!I", read(4))[0]
    if not 0 < length <= MAX_PACKET:
        raise ValueError("service-packet-limit")
    return read(length)


class UnixClient:
    def __init__(self, path: Path):
        self.path = path.absolute()

    def call(self, raw: bytes, *, deadline: float, cancelled: Event) -> bytes:
        private_parent(self.path)
        metadata = self.path.lstat()
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise ValueError("private-service-socket-required")
        # Directory ownership is the transport authority; signed response keys
        # still come from separate trusted configuration. No network/DNS/proxy.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.setblocking(False)
            if cancelled.is_set():
                raise AttemptStopped("cancelled")
            if time.monotonic() >= deadline:
                raise AttemptStopped("timeout")
            result = connection.connect_ex(str(self.path))
            if result:
                import errno

                if result not in (errno.EINPROGRESS, errno.EAGAIN):
                    raise ValueError("service-connect-failed")
                _ready(connection, deadline=deadline, cancelled=cancelled, write=True)
                if connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
                    raise ValueError("service-connect-failed")
            send_packet(connection, raw, deadline=deadline, cancelled=cancelled)
            return receive_packet(connection, deadline=deadline, cancelled=cancelled)


class UnixService:
    """Bounded clients, one request each, private socket, no raw error/log output."""

    def __init__(
        self, path: Path, handler: Callable[[bytes, float, Event], bytes], *, budget: float = 5
    ):
        if not 0 < budget <= 60:
            raise ValueError("service-budget-invalid")
        self.path, self.handler, self.budget = path.absolute(), handler, budget
        self.stop = Event()
        self.slots = BoundedSemaphore(8)
        self.workers: list[Thread] = []
        self.socket: socket.socket | None = None
        self.identity = None

    def open(self):
        private_parent(self.path)
        if self.path.exists() or self.path.is_symlink():
            raise ValueError("service-socket-already-exists")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.bind(str(self.path))
            os.chmod(self.path, 0o600)
            metadata = self.path.lstat()
            self.identity = (metadata.st_dev, metadata.st_ino)
            connection.listen(8)
            connection.settimeout(0.1)
            self.socket = connection
        except BaseException:
            connection.close()
            raise

    def _serve(self, connection):
        deadline = time.monotonic() + self.budget
        with connection:
            connection.setblocking(False)
            try:
                raw = receive_packet(connection, deadline=deadline, cancelled=self.stop)
                reply = self.handler(raw, deadline, self.stop)
                send_packet(connection, reply, deadline=deadline, cancelled=self.stop)
            except Exception:
                # Neither exceptions nor caller input leave the private service.
                pass
            finally:
                self.slots.release()

    def run(self):
        if self.socket is None:
            self.open()
        try:
            while not self.stop.is_set():
                try:
                    connection, _ = self.socket.accept()
                except TimeoutError:
                    continue
                if not self.slots.acquire(blocking=False):
                    connection.close()
                    continue
                self.workers = [worker for worker in self.workers if worker.is_alive()]
                worker = Thread(target=self._serve, args=(connection,))
                self.workers.append(worker)
                worker.start()
        finally:
            self.stop.set()
            self.socket.close()
            for worker in self.workers:
                worker.join(timeout=self.budget + 1)
            if self.path.exists():
                metadata = self.path.lstat()
                if (metadata.st_dev, metadata.st_ino) == self.identity:
                    self.path.unlink()
