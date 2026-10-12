"""Execute the frozen probes against controlled HTTP receivers, without OpenShell."""

import os
import shutil
import subprocess
import sys
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from agent_boundary_gate.backends.openshell import PERL_PROBE, PROBE


class ProbeTests(unittest.TestCase):
    def test_probes_correlate_direct_request_and_do_not_follow_redirect_or_proxy(self):
        events = []

        class Receiver(BaseHTTPRequestHandler):
            def do_GET(self):
                events.append((self.path, self.headers.get("X-Gate-Attempt")))
                self.send_response(302)
                self.send_header("Location", "/redirect-target")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        host, port = server.server_address
        runtimes = [
            [sys.executable, "-c", PROBE, f"http://127.0.0.1:{port}/probe", "probe-test", "1"]
        ]
        # Perl is optional for library users but required in CI for this compatibility test.
        perl = shutil.which("perl")
        if perl:
            runtimes.append([perl, "-e", PERL_PROBE, "--", host, str(port), "probe-test", "1"])
        elif os.environ.get("CI"):
            self.fail("CI must exercise the Perl probe")
        for argv in runtimes:
            with self.subTest(runtime=argv[0]):
                events.clear()
                result = subprocess.run(
                    argv,
                    capture_output=True,
                    timeout=5,
                    env={
                        **os.environ,
                        "http_proxy": "http://127.0.0.1:1",
                        "HTTP_PROXY": "http://127.0.0.1:1",
                        "no_proxy": "",
                        "NO_PROXY": "",
                    },
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"agent-boundary-gate-probe-complete:probe-test\n")
                self.assertEqual(events, [("/probe", "probe-test")])

    @unittest.skipUnless(shutil.which("perl"), "Perl probe requires a local Perl installation")
    def test_perl_network_failure_completes_attempt_without_claiming_observation(self):
        # A bound but non-listening socket deterministically rejects a connection.
        import socket

        with socket.socket() as receiver:
            receiver.bind(("127.0.0.1", 0))
            result = subprocess.run(
                [
                    shutil.which("perl"),
                    "-e",
                    PERL_PROBE,
                    "--",
                    "127.0.0.1",
                    str(receiver.getsockname()[1]),
                    "probe-test",
                    "1",
                ],
                capture_output=True,
                timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"agent-boundary-gate-probe-complete:probe-test\n")
