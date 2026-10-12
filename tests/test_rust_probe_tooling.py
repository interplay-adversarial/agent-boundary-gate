import json
import struct
import subprocess
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from scripts import audit_rust_probe as audit
from scripts import rust_probe_build as build


class RustToolingTests(unittest.TestCase):
    def test_dependencies_and_foreign_lock_entries_require_review(self):
        manifest = {"package": {"name": "gate-http-probe", "version": "0.1.0"}}
        lock = {"package": [{"name": "gate-http-probe", "version": "0.1.0"}]}
        build.validate_dependency_scope(manifest, lock)
        for key in (
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
            "target",
            "workspace",
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                build.validate_dependency_scope(manifest | {key: {"unexpected": "1"}}, lock)
        for packages in (
            [],
            lock["package"] * 2,
            lock["package"] + [{"name": "unexpected", "version": "1"}],
        ):
            with self.assertRaises(ValueError):
                build.validate_dependency_scope(manifest, {"package": packages})

    def elf(self, *, kind=1, machine=62, needed=False):
        raw = bytearray(160)
        raw[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<H", raw, 16, 3)
        struct.pack_into("<H", raw, 18, machine)
        struct.pack_into("<Q", raw, 32, 64)
        struct.pack_into("<HH", raw, 54, 56, 1)
        struct.pack_into("<IIQQQQQQ", raw, 64, kind, 0, 128, 0, 0, 16, 16, 8)
        struct.pack_into("<qQ", raw, 128, 1 if needed else 0, 0)
        return bytes(raw)

    def test_static_elf_checks_architecture_loader_and_needed_libraries(self):
        target = "x86_64-unknown-linux-musl"
        build.inspect_static_elf(self.elf(), target)
        build.inspect_static_elf(self.elf(kind=2), target)
        for raw in (
            b"not-an-elf",
            self.elf(machine=183),
            self.elf(kind=3),
            self.elf(kind=2, needed=True),
            self.elf()[:120],
        ):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                build.inspect_static_elf(raw, target)

    def test_binary_privacy_rejects_build_paths_and_tokens_without_echo(self):
        sensitive = b"/" + b"Users/" + b"synthetic-operator/private-build/"
        with self.assertRaises(ValueError) as caught:
            build.artifact_privacy(b"\xff\x00" + sensitive)
        self.assertNotIn("synthetic-operator", str(caught.exception))
        build.artifact_privacy(b"\xff\x00/agent-boundary-gate/probes/http/src/main.rs")

    def report(self):
        return {
            "database": {
                "advisory-count": 1,
                "last-commit": "a" * 40,
                "last-updated": datetime.now(UTC).isoformat(),
            },
            "lockfile": {"dependency-count": 1},
            "settings": {
                "ignore": [],
                "target_arch": [],
                "target_os": [],
                "severity": None,
                "informational_warnings": ["unmaintained", "unsound", "notice"],
            },
            "vulnerabilities": {"found": False, "count": 0, "list": []},
            "warnings": {},
        }

    def run_audit(self, value, *, returncode=0, version="0.22.2"):
        responses = [
            subprocess.CompletedProcess([], 0, f"cargo-audit {version}".encode(), b""),
            subprocess.CompletedProcess(
                [], returncode, json.dumps(value).encode(), b"synthetic-private-value"
            ),
        ]
        with patch.object(audit.subprocess, "run", side_effect=responses):
            return audit.audit()

    def test_valid_rust_audit_does_not_claim_compiler_cve_coverage(self):
        report, code = self.run_audit(self.report())
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["compiler_stdlib_image_cve_coverage"])

    def test_incomplete_stale_filtered_or_inconsistent_audits_fail_closed(self):
        cases = [None, {}, self.report()]
        cases[-1]["lockfile"]["dependency-count"] = 0
        for section, key, value in (
            ("database", "advisory-count", 0),
            ("database", "last-updated", (datetime.now(UTC) - timedelta(days=8)).isoformat()),
            ("database", "last-updated", (datetime.now(UTC) + timedelta(days=1)).isoformat()),
            ("settings", "ignore", ["RUSTSEC-2026-0001"]),
            ("settings", "target_os", ["linux"]),
            ("settings", "severity", "high"),
            ("settings", "informational_warnings", []),
            ("vulnerabilities", "found", True),
            ("vulnerabilities", "count", 1),
        ):
            item = self.report()
            item[section][key] = value
            cases.append(item)
        for item in cases:
            with self.subTest(value=item):
                report, code = self.run_audit(item)
                self.assertEqual(code, 2)
                self.assertNotIn("synthetic-private-value", json.dumps(report))
        self.assertEqual(self.run_audit(self.report(), version="0.22.1")[1], 2)

    def test_vulnerabilities_and_warnings_cannot_pass(self):
        value = self.report()
        value["vulnerabilities"] = {
            "found": True,
            "count": 1,
            "list": [{"advisory": {"id": "RUSTSEC-2026-0001"}}],
        }
        report, code = self.run_audit(value, returncode=1)
        self.assertEqual(code, 1)
        self.assertEqual(report["advisories"], ["RUSTSEC-2026-0001"])
        value = self.report()
        value["warnings"] = {"unmaintained": [{"synthetic": "private"}]}
        self.assertEqual(self.run_audit(value)[1], 1)

    def test_auditor_network_failure_is_incomplete(self):
        with patch.object(audit.subprocess, "run", side_effect=OSError("synthetic-private-value")):
            report, code = audit.audit()
        self.assertEqual(code, 2)
        self.assertNotIn("synthetic-private-value", json.dumps(report))
