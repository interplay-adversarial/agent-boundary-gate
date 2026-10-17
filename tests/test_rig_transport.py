"""Pins rig_transport.UnixService's intentional fail-closed exception swallow:
a malformed request (or any handler exception) must never leave the private
service loop or crash the worker thread -- see _serve's `except Exception: pass`.
"""

import contextlib
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event, Thread

from agent_boundary_gate.process import AttemptStopped
from agent_boundary_gate.rig_transport import UnixClient, UnixService


@contextlib.contextmanager
def running(service):
    service.open()
    thread = Thread(target=service.run)
    thread.start()
    try:
        yield service
    finally:
        service.stop.set()
        thread.join(timeout=6)
        if thread.is_alive():
            raise AssertionError("service thread did not stop")


class ServiceSurvivesMalformedRequestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_handler_exception_closes_that_call_without_stopping_the_service(self):
        def handler(raw, deadline, cancelled):
            if raw == b"malformed":
                raise ValueError("synthetic-malformed-request")
            return b"ok:" + raw

        with running(UnixService(self.root / "service.sock", handler)):
            client = UnixClient(self.root / "service.sock")
            # No reply is ever sent for the raised exception: the client sees the
            # connection close without data, never a raw error message or traceback.
            with self.assertRaises(ValueError) as caught:
                client.call(b"malformed", deadline=time.monotonic() + 2, cancelled=Event())
            self.assertEqual(str(caught.exception), "service-connection-closed")
            # The service thread and its listener are still accepting new
            # connections -- the one bad request did not take the loop down.
            self.assertEqual(
                client.call(b"next", deadline=time.monotonic() + 2, cancelled=Event()),
                b"ok:next",
            )

    def test_repeated_malformed_requests_never_accumulate_into_a_stopped_service(self):
        def handler(raw, deadline, cancelled):
            raise ValueError("synthetic-malformed-request")

        with running(UnixService(self.root / "service.sock", handler)):
            client = UnixClient(self.root / "service.sock")
            for _ in range(5):
                with self.assertRaises(ValueError):
                    client.call(b"malformed", deadline=time.monotonic() + 2, cancelled=Event())

    def test_slot_is_released_even_on_handler_exception(self):
        # UnixService.slots is a BoundedSemaphore(8); a leak on the exception path
        # would eventually make every further call hang until its own deadline.
        def handler(raw, deadline, cancelled):
            raise ValueError("synthetic-malformed-request")

        with running(UnixService(self.root / "service.sock", handler)) as service:
            client = UnixClient(self.root / "service.sock")
            for _ in range(len(service.workers) + 20):
                with self.assertRaises((ValueError, AttemptStopped)):
                    client.call(b"malformed", deadline=time.monotonic() + 2, cancelled=Event())
            self.assertTrue(service.slots.acquire(blocking=False))
            service.slots.release()


if __name__ == "__main__":
    unittest.main()
