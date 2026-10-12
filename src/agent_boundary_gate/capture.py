"""Controlled loopback HTTP receivers for local capture qualification tests."""

import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Literal

from agent_boundary_gate.evidence import EvidenceStore, bytes_digest, json_bytes


class BoundedHTTPServer(ThreadingHTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(0.5)
        return connection, address


class ReceiverCapture:
    """Two independent receivers; no raw request bodies, headers or payloads are exported."""

    def __init__(self, attempt_id: str, store: EvidenceStore):
        self.attempt_id = attempt_id
        self.store = store
        self.events: list[dict[str, str]] = []
        self.effect_refs: list[str] = []
        self.errors: list[str] = []
        self.dropped_events = 0
        self.lock = threading.Lock()
        self.servers: dict[str, ThreadingHTTPServer] = {}
        self.threads: list[threading.Thread] = []
        self.server_threads: dict[str, threading.Thread] = {}
        self.started = False
        self.drained = False

    def _handler(self, receiver: str) -> type[BaseHTTPRequestHandler]:
        capture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if (
                    self.path != "/probe"
                    or self.headers.get("X-Gate-Attempt") != capture.attempt_id
                ):
                    self.send_response(404)
                    self.end_headers()
                    return
                event = {
                    "attempt_id": capture.attempt_id,
                    "receiver": receiver,
                    "observed_at": datetime.now(UTC).isoformat(),
                    "effect": "http-request-received",
                }
                with capture.lock:
                    if len(capture.events) >= 1000:
                        capture.dropped_events += 1
                        self.send_response(503)
                        self.end_headers()
                        return
                    # Preserve the observation in memory even if storage fails afterwards.
                    capture.events.append(event)
                    if receiver == "forbidden":
                        capture.effect_refs.append(bytes_digest(json_bytes(event)))
                    try:
                        capture.store.persist_json(event)
                    except (OSError, ValueError):
                        capture.errors.append("receiver-persistence-error")
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args: object) -> None:
                pass

        return Handler

    def start(self) -> None:
        try:
            for name in ("allowed", "forbidden"):
                server = BoundedHTTPServer(("127.0.0.1", 0), self._handler(name))
                server.daemon_threads = False
                server.timeout = 0.2
                self.servers[name] = server
                thread = threading.Thread(
                    target=server.serve_forever, kwargs={"poll_interval": 0.02}
                )
                thread.start()
                self.threads.append(thread)
                self.server_threads[name] = thread
            self.started = True
        except BaseException:
            self.stop()
            raise

    def url(self, receiver: Literal["allowed", "forbidden"]) -> str:
        return f"http://127.0.0.1:{self.servers[receiver].server_port}/probe"

    def count(self, receiver: str) -> int:
        with self.lock:
            return sum(event["receiver"] == receiver for event in self.events)

    def stop(self) -> None:
        for name, server in self.servers.items():
            if name in self.server_threads and self.server_threads[name].is_alive():
                server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)
        self.drained = self.started and all(not thread.is_alive() for thread in self.threads)

    def snapshot(self) -> str:
        with self.lock:
            return self.store.persist_json(
                {
                    "attempt_id": self.attempt_id,
                    "events": self.events,
                    "drained": self.drained,
                    "errors": self.errors,
                    "dropped_events": self.dropped_events,
                }
            )
