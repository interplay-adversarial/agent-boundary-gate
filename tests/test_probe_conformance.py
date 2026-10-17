"""Execute the frozen probes against controlled HTTP receivers, without OpenShell."""

import os
import shutil
import socket
import subprocess
import sys
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from agent_boundary_gate.probes import PERL_PROBE, PROBE, validate_receiver_url


class ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        configured = os.environ.get("GATE_RUST_PROBE_BINARY")
        if configured:
            cls.rust = Path(configured)
        else:
            built = subprocess.run(
                [sys.executable, "-m", "scripts.rust_probe_build"],
                cwd=root,
                capture_output=True,
                timeout=180,
            )
            if built.returncode:
                raise AssertionError("Rust probe build is required for conformance tests")
            cls.rust = root / "probes/http/target/release/gate-http-probe"
        version = subprocess.run([str(cls.rust), "--version"], capture_output=True, timeout=5)
        if (
            version.returncode
            or version.stdout
            != b"gate-http-probe 0.2.0 agent-boundary-gate/http-probe/1.0 experimental-dns\n"
        ):
            raise AssertionError("unexpected Rust probe protocol/version")

    def runtimes(self, host, port, attempt="probe-test", seconds="1"):
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        commands = [
            [sys.executable, "-c", PROBE, "http://" + authority + "/probe", attempt, seconds]
        ]
        perl = shutil.which("perl")
        if perl:
            commands.append([perl, "-e", PERL_PROBE, "--", host, str(port), attempt, seconds])
        elif os.environ.get("CI"):
            self.fail("CI must exercise the Perl probe")
        commands.append([str(self.rust), host, str(port), attempt, seconds])
        return commands

    def test_receiver_url_rejects_controls_and_unsafe_authorities_before_normalization(self):
        endpoint = "http://receiver:80/probe"
        for url in (
            endpoint.replace("receiver", "receiver\r\nInjected:1"),
            "\n" + endpoint,
            endpoint + "\t",
            endpoint.replace("receiver", "receiver\x00"),
            endpoint.replace("receiver", "receiver bad"),
            endpoint.replace("receiver", "receiver%0d%0aInjected"),
            endpoint.replace("receiver", "[::1%zone]"),
            endpoint.replace("receiver", "receivér"),
        ):
            with self.subTest(url=repr(url)), self.assertRaises(ValueError):
                validate_receiver_url(url)
        # An out-of-range numeric port makes urlsplit's own `.port` property raise a
        # bare ValueError before this function's shape checks even run; confirm it's
        # normalized to this function's own message, not leaked from urllib.parse.
        with self.assertRaisesRegex(ValueError, "explicit HTTP /probe endpoint"):
            validate_receiver_url("http://receiver:99999/probe")
        for url in (
            endpoint,
            endpoint.replace("receiver", "127.0.0.1"),
            endpoint.replace("receiver", "[::1]"),
        ):
            validate_receiver_url(url)

    def test_native_probes_reject_malformed_arguments_before_connecting_or_completion(self):
        with socket.socket() as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.listen()
            receiver.setblocking(False)
            valid = ["127.0.0.1", str(receiver.getsockname()[1]), "probe-test", "1"]
            mutations = (
                (0, "127.0.0.1\r\nInjected: value"),
                (0, "host%0aInjected"),
                (0, "host name"),
                (0, ""),
                (1, "80\r\nInjected: value"),
                (1, "0"),
                (1, "65536"),
                (1, "-1"),
                (1, "service-name"),
                (2, "probe-test\r\nInjected: value"),
                (2, ""),
                (2, "a" * 129),
                (3, "0"),
                (3, "31"),
                (3, "1.5"),
                (3, "1\n"),
            )
            cases = []
            for index, value in mutations:
                arguments = valid.copy()
                arguments[index] = value
                cases.append(arguments)
            cases.extend((valid[:3], valid + ["extra"]))
            for arguments in cases:
                commands = [[str(self.rust), *arguments]]
                if shutil.which("perl"):
                    commands.append([shutil.which("perl"), "-e", PERL_PROBE, "--", *arguments])
                for argv in commands:
                    with self.subTest(runtime=argv[0], arguments=repr(arguments)):
                        result = subprocess.run(argv, capture_output=True, timeout=5)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, b"")
                        self.assertEqual(result.stderr, b"invalid-probe-input\n")
                        with self.assertRaises(BlockingIOError):
                            receiver.accept()

    def test_python_probe_rejects_malformed_attempt_and_timeout_before_connecting_or_completion(
        self,
    ):
        with socket.socket() as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.listen()
            receiver.setblocking(False)
            url = f"http://127.0.0.1:{receiver.getsockname()[1]}/probe"
            valid = [url, "probe-test", "1"]
            mutations = (
                (1, "probe-test\r\nInjected: value"),
                (1, ""),
                (1, "a" * 129),
                (2, "0"),
                (2, "31"),
                (2, "1.5"),
                (2, "1\n"),
            )
            for index, value in mutations:
                arguments = valid.copy()
                arguments[index] = value
                argv = [sys.executable, "-c", PROBE, *arguments]
                with self.subTest(arguments=repr(arguments)):
                    result = subprocess.run(argv, capture_output=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(result.stderr, b"invalid-probe-input\n")
                    with self.assertRaises(BlockingIOError):
                        receiver.accept()

    def test_python_probe_rejects_malformed_url_before_connecting_or_completion(self):
        # Unlike PERL_PROBE (which takes host/port as separate argv), the Python probe
        # takes a full URL in argv[1] -- it must validate scheme/host/path itself,
        # mirroring validate_receiver_url, rather than trusting urllib to only ever be
        # handed a URL already shaped like the fixed receiver's own probe endpoint.
        with socket.socket() as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.listen()
            receiver.setblocking(False)
            port = receiver.getsockname()[1]
            for url in (
                "file:///etc/passwd",
                f"ftp://127.0.0.1:{port}/probe",
                f"http://127.0.0.1:{port}/not-probe",
                f"http://127.0.0.1:{port}/probe?x=1",
                f"http://127.0.0.1:{port}/probe#frag",
                "http://" + "fixture-user:fixture-password" + f"@127.0.0.1:{port}/probe",
                "http://127.0.0.1/probe",
                "not-a-url",
            ):
                argv = [sys.executable, "-c", PROBE, url, "probe-test", "1"]
                with self.subTest(url=url):
                    result = subprocess.run(argv, capture_output=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(result.stderr, b"invalid-probe-input\n")
                    with self.assertRaises(BlockingIOError):
                        receiver.accept()

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
        for argv in self.runtimes(host, port):
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

    def test_network_failure_completes_attempt_without_claiming_observation(self):
        # A bound but non-listening socket deterministically rejects a connection.
        with socket.socket() as receiver:
            receiver.bind(("127.0.0.1", 0))
            for argv in self.runtimes("127.0.0.1", receiver.getsockname()[1]):
                result = subprocess.run(argv, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"agent-boundary-gate-probe-complete:probe-test\n")

    def test_rust_rejects_scoped_ips_nonutf8_and_unknown_protocol(self):
        cases = [
            [b"::1%zone", b"80", b"probe-test", b"1"],
            [b"[::1]", b"80", b"probe-test", b"1"],
            [b"127.0.0.1", b"80", b"\xff", b"1"],
            [b"--version", b"extra"],
        ]
        for args in cases:
            result = subprocess.run([os.fsencode(self.rust), *args], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"invalid-probe-input\n")

    def test_hostname_resolves_and_connects_across_runtimes(self):
        events = []

        class Receiver(BaseHTTPRequestHandler):
            def do_GET(self):
                events.append(
                    (self.path, self.headers.get("Host"), self.headers.get("X-Gate-Attempt"))
                )
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        family, *_, sockaddr = socket.getaddrinfo("localhost", 0, type=socket.SOCK_STREAM)[0]

        class LocalhostServer(ThreadingHTTPServer):
            address_family = family

        server = LocalhostServer((sockaddr[0], 0), Receiver)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        for argv in self.runtimes("localhost", port):
            with self.subTest(runtime=argv[0]):
                events.clear()
                result = subprocess.run(argv, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"agent-boundary-gate-probe-complete:probe-test\n")
                self.assertEqual(events, [("/probe", f"localhost:{port}", "probe-test")])

    def test_rust_unresolvable_hostname_completes_attempt_without_claiming_observation(self):
        # RFC 2606 reserves .invalid: it is guaranteed never to resolve.
        result = subprocess.run(
            [str(self.rust), "this-host-should-not-resolve.invalid", "80", "probe-test", "2"],
            capture_output=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"agent-boundary-gate-probe-complete:probe-test\n")

    def test_ipv6_direct_request_matches_across_runtimes(self):
        events = []

        class IPv6Server(ThreadingHTTPServer):
            address_family = socket.AF_INET6

        class Receiver(BaseHTTPRequestHandler):
            def do_GET(self):
                events.append(
                    (self.path, self.headers.get("Host"), self.headers.get("X-Gate-Attempt"))
                )
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = IPv6Server(("::1", 0), Receiver)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        for argv in self.runtimes("::1", port):
            events.clear()
            result = subprocess.run(argv, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(events, [("/probe", f"[::1]:{port}", "probe-test")])

    def test_rust_stalled_response_uses_one_budget_and_external_cancellation(self):
        for cancel in (False, True):
            with self.subTest(cancel=cancel), socket.socket() as receiver:
                receiver.bind(("127.0.0.1", 0))
                receiver.listen(1)
                receiver.settimeout(5)
                started = time.monotonic()
                process = subprocess.Popen(
                    [
                        str(self.rust),
                        "127.0.0.1",
                        str(receiver.getsockname()[1]),
                        "probe-test",
                        "1",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.addCleanup(lambda p=process: p.kill() if p.poll() is None else None)
                with receiver.accept()[0] as connection:
                    connection.settimeout(5)
                    request = b""
                    while b"\r\n\r\n" not in request and len(request) < 1024:
                        chunk = connection.recv(1024 - len(request))
                        if not chunk:
                            break
                        request += chunk
                    self.assertIn(b"X-Gate-Attempt: probe-test", request)
                    if cancel:
                        process.terminate()
                    output, error = process.communicate(timeout=3)
                self.assertLess(time.monotonic() - started, 2.5)
                if cancel:
                    self.assertNotEqual(process.returncode, 0)
                    self.assertEqual(output, b"")
                else:
                    self.assertEqual(process.returncode, 0, error)
                    self.assertEqual(output, b"agent-boundary-gate-probe-complete:probe-test\n")

    def test_static_linux_probe_resource_failure_cannot_emit_completion(self):
        if "linux-musl" not in str(self.rust):
            self.skipTest("resource fault is exercised by both static Linux architecture jobs")
        import resource

        result = subprocess.run(
            [str(self.rust), "127.0.0.1", "80", "probe-test", "1"],
            capture_output=True,
            timeout=5,
            preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (3, 3)),
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"probe-runtime-failed\n")
