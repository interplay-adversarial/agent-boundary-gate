"""Unit tests for the pure extraction/scanning/validation helpers in
audit_distribution.py. The real build/export/smoke flow (uv build, git archive, an
isolated installed-wheel run) is exercised live by running the script itself, not by
this suite -- matching this repo's existing audit-script test convention
(test_cve_audit.py, test_rust_probe_tooling.py): mock subprocess, never spawn a real
build or network call from inside `python -m unittest discover`.
"""

import io
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts import audit_distribution as audit


def _zip_bytes(entries: dict[str, bytes], directories: tuple[str, ...] = ()) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in directories:
            archive.writestr(name, b"")
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _tar_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class ExtractWheelTests(unittest.TestCase):
    def test_directory_entries_are_excluded_files_are_not(self):
        data = _zip_bytes(
            {"pkg/module.py": b"x = 1\n", "pkg-0.1.dist-info/METADATA": b"Metadata-Version: 2.1\n"},
            directories=("pkg/",),
        )
        with tempfile.TemporaryDirectory() as root:
            wheel = Path(root) / "pkg.whl"
            wheel.write_bytes(data)
            contents = audit.extract_wheel(wheel)
        self.assertEqual(
            contents,
            {
                "pkg/module.py": b"x = 1\n",
                "pkg-0.1.dist-info/METADATA": b"Metadata-Version: 2.1\n",
            },
        )


class ExtractSdistTests(unittest.TestCase):
    def test_top_level_version_directory_is_stripped(self):
        data = _tar_bytes(
            {
                "pkg-0.1/pyproject.toml": b'[project]\nname = "pkg"\n',
                "pkg-0.1/src/pkg/__init__.py": b"",
            }
        )
        with tempfile.TemporaryDirectory() as root:
            sdist = Path(root) / "pkg.tar.gz"
            sdist.write_bytes(data)
            contents = audit.extract_sdist(sdist)
        self.assertEqual(
            contents,
            {
                "pyproject.toml": b'[project]\nname = "pkg"\n',
                "src/pkg/__init__.py": b"",
            },
        )


class ScanContentsTests(unittest.TestCase):
    def test_surfaces_audit_publication_findings_by_path_and_content(self):
        findings = audit.scan_contents(
            {
                "clean/module.py": b"print('hello')\n",
                "credentials.json": b"{}",
                # Built from separate literals, not one contiguous URL in this file's own
                # source text: audit_publication.py scanning this very test file (as part
                # of the repo's tracked tree) must not flag its own test fixture data.
                "notes.md": b"See " + b"https://" + b"not-a-public-host.example" + b"/docs\n",
            }
        )
        rules = {finding.rule for finding in findings}
        self.assertIn("private-or-credential-file", rules)
        self.assertIn("url-host-not-public-reference", rules)
        self.assertNotIn(
            "private-or-credential-file",
            {f.rule for f in findings if f.path == "clean/module.py"},
        )


class InstalledSmokeCheckTests(unittest.TestCase):
    def test_nonzero_exit_raises(self):
        with patch.object(
            audit.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, b"", b""),
        ):
            with self.assertRaises(ValueError):
                audit.installed_smoke_check(Path("/fake/wheel.whl"))

    def test_unexpected_decision_raises(self):
        with patch.object(
            audit.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 0, b'{"release_decision": "criteria_failed", "release_eligible": false}', b""
            ),
        ):
            with self.assertRaises(ValueError):
                audit.installed_smoke_check(Path("/fake/wheel.whl"))

    def test_release_eligible_true_is_rejected_even_with_a_pass_decision(self):
        # A packaging/environment bug that let release_eligible ever read true would be
        # far worse than a failed smoke check -- this must never be treated as success.
        with patch.object(
            audit.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 0, b'{"release_decision": "pass", "release_eligible": true}', b""
            ),
        ):
            with self.assertRaises(ValueError):
                audit.installed_smoke_check(Path("/fake/wheel.whl"))

    def test_clean_pass_result_is_returned(self):
        with patch.object(
            audit.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 0, b'{"release_decision": "pass", "release_eligible": false}', b""
            ),
        ):
            result = audit.installed_smoke_check(Path("/fake/wheel.whl"))
        self.assertEqual(result, {"release_decision": "pass"})


if __name__ == "__main__":
    unittest.main()
