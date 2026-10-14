"""Finite receiver admission and absolute, byte-bounded HTTP header reads."""

import io
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class HeaderReader(io.RawIOBase):
    def __init__(self, connection, *, deadline, limit=65536):
        self.connection = connection
        self.raw = connection.makefile("rb", buffering=0)
        self.deadline, self.remaining = deadline, limit

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining_time = self.deadline - time.monotonic()
        if remaining_time <= 0:
            raise TimeoutError("receiver-header-timeout")
        if self.remaining <= 0:
            raise OSError("receiver-header-limit")
        self.connection.settimeout(min(0.5, remaining_time))
        count = self.raw.readinto(memoryview(buffer)[: self.remaining])
        self.remaining -= count
        return count

    def close(self):
        self.raw.close()
        super().close()


class ReceiverHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.rfile.close()
        self.rfile = io.BufferedReader(
            HeaderReader(self.connection, deadline=time.monotonic() + self.server.request_budget)
        )


class ReceiverServer(ThreadingHTTPServer):
    """Eight admitted handlers per listener; no detached handler on close."""

    daemon_threads = False
    block_on_close = True
    request_queue_size = 8
    request_budget = 1.0

    def __init__(self, address, handler, on_loss):
        self.slots = threading.BoundedSemaphore(8)
        self.on_loss = on_loss
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(0.5)
        return connection, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.on_loss()
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        self.on_loss()
