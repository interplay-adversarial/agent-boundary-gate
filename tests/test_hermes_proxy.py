"""Actual loopback concurrency and shutdown; synthetic model transport only."""

import json
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from pathlib import Path
from threading import Event, Lock
from unittest.mock import patch

from scripts.gym_smoke import Provider, write_private
from scripts.hermes_pilot import ModelProxy


class HermesProxyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.provider = Provider(
            base_url="https://example.com/v1",
            api_key_env="MODEL_API_KEY",
            model="synthetic-model",
            max_steps=2,
        )

    def post(self, proxy):
        connection = HTTPConnection("127.0.0.1", proxy.server.server_port, timeout=5)
        try:
            connection.request(
                "POST",
                "/v1/chat/completions",
                body=json.dumps(
                    {
                        "model": self.provider.model,
                        "tools": [
                            {"function": {"name": "gate_read_messages"}},
                            {"function": {"name": "gate_send_record"}},
                        ],
                    }
                ),
                headers={"Authorization": "Bearer " + proxy.token},
            )
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_concurrent_requests_cannot_exceed_reserved_model_call_budget(self):
        entered, release = Event(), Event()
        counter, lock = 0, Lock()

        def fetch(request):
            nonlocal counter
            with lock:
                counter += 1
                if counter == 3:
                    entered.set()
            if not release.wait(5):
                raise ValueError("fixture-deadline")
            return {"model": self.provider.model}

        with ModelProxy(
            self.provider, "synthetic-credential", self.directory, fetch=fetch
        ) as proxy:
            with ThreadPoolExecutor(max_workers=6) as pool:
                requests = [pool.submit(self.post, proxy) for _ in range(6)]
                try:
                    self.assertTrue(entered.wait(3))
                finally:
                    release.set()
                responses = [request.result(timeout=5) for request in requests]
            self.assertEqual(sorted(status for status, _ in responses), [200] * 3 + [502] * 3)
            self.assertEqual(counter, 3)
            self.assertEqual(proxy.calls, 3)
            self.assertTrue(proxy.failed)
        self.assertEqual(len(list(self.directory.iterdir())), 6)

    def test_shutdown_fences_a_late_provider_response_without_blocking_on_fetch(self):
        entered, release = Event(), Event()

        def fetch(request):
            entered.set()
            if not release.wait(5):
                raise ValueError("fixture-deadline")
            return {"model": self.provider.model, "late": True}

        proxy = ModelProxy(self.provider, "synthetic-credential", self.directory, fetch=fetch)
        proxy.__enter__()
        with ThreadPoolExecutor(max_workers=1) as pool:
            request = pool.submit(self.post, proxy)
            try:
                self.assertTrue(entered.wait(3))
                started = time.monotonic()
                proxy.__exit__()
                self.assertLess(time.monotonic() - started, 2)
                self.assertTrue(proxy.closed)
                self.assertTrue(proxy.failed)
            finally:
                release.set()
                if not proxy.closed:
                    proxy.__exit__()
            status, response = request.result(timeout=5)
        self.assertEqual(status, 502)
        self.assertEqual(response, {"error": "model-proxy-incomplete"})
        self.assertTrue(proxy.failed)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_shutdown_waits_for_admitted_publication_before_setting_closed(self):
        publishing, release, closing = Event(), Event(), Event()
        proxy = ModelProxy(
            self.provider,
            "synthetic-credential",
            self.directory,
            fetch=lambda request: {"model": self.provider.model},
        )
        writes = []

        def persist(directory, name, value):
            publishing.set()
            if not release.wait(5):
                raise ValueError("fixture-deadline")
            writes.append(proxy.closed)
            write_private(directory, name, value)

        def close():
            closing.set()
            proxy.__exit__()

        proxy.__enter__()
        with patch("scripts.hermes_pilot.write_private", side_effect=persist):
            with ThreadPoolExecutor(max_workers=2) as pool:
                request = pool.submit(self.post, proxy)
                try:
                    self.assertTrue(publishing.wait(3))
                    shutdown = pool.submit(close)
                    self.assertTrue(closing.wait(3))
                    self.assertFalse(proxy.closed)
                    self.assertFalse(shutdown.done())
                finally:
                    release.set()
                self.assertEqual(request.result(timeout=5)[0], 200)
                shutdown.result(timeout=5)
        self.assertEqual(writes, [False, False])
        self.assertTrue(proxy.closed)

    def test_reflected_credential_is_rejected_before_persistence_and_publication(self):
        with ModelProxy(
            self.provider,
            "synthetic-credential",
            self.directory,
            fetch=lambda request: {"model": self.provider.model, "debug": "synthetic-credential"},
        ) as proxy:
            status, response = self.post(proxy)
            self.assertEqual(status, 502)
            self.assertEqual(response, {"error": "model-proxy-incomplete"})
            self.assertTrue(proxy.failed)
        self.assertEqual(list(self.directory.iterdir()), [])
