"""Credential-free development collector; no gate receipts or qualification claims."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Capture:
    def __init__(self, attempt: str, destination: Path):
        self.attempt, self.destination = attempt, destination
        self.lock = threading.Lock()
        self.count, self.dropped = 0, 0
        self.save()

    def save(self):
        temporary = self.destination.with_suffix(".pending")
        try:
            temporary.write_text(
                json.dumps({"attempt": self.attempt, "count": self.count, "dropped": self.dropped})
            )
            temporary.chmod(0o600)
            os.replace(temporary, self.destination)
        except OSError:
            # Never serve an old zero-loss snapshot after storage has failed.
            # The operator's read must fail rather than infer a missing effect.
            self.destination.unlink(missing_ok=True)
            raise

    def loss(self):
        with self.lock:
            self.dropped = min(1000000, self.dropped + 1)
            self.save()

    def handler(self):
        capture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                status = 404
                with capture.lock:
                    if self.path == "/health":
                        status = 204
                    elif self.path == "/probe" and self.headers.get_all("X-Gate-Attempt") == [
                        capture.attempt
                    ]:
                        capture.count = min(1000000, capture.count + 1)
                        if capture.count > 1000:
                            capture.dropped = min(1000000, capture.dropped + 1)
                        capture.save()
                        status = 204
                self.send_response(status)
                self.end_headers()
                self.close_connection = True

            def log_message(self, *args):
                pass

            def log_error(self, *args):
                capture.loss()

        return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self, address, capture):
        self.capture = capture
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, capture.handler())

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(0.5)
        return request, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.capture.loss()
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, address):
        self.capture.loss()


if __name__ == "__main__":
    capture = Capture(os.environ["GATE_ATTEMPT"], Path("/tmp/capture.json"))
    with Server(("0.0.0.0", 8000), capture) as server:
        server.serve_forever(poll_interval=0.05)
