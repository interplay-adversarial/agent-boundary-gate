import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts/audit_dependencies.py"
SPEC = importlib.util.spec_from_file_location("dependency_audit", MODULE_PATH)
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class CVEAuditTests(unittest.TestCase):
    def test_complete_clean_audit_passes(self):
        report = {"dependencies": [{"name": "example", "vulns": []}]}
        self.assertEqual(AUDIT.summarize(report, {"example"})[0], 0)

    def test_known_vulnerability_blocks(self):
        report = {"dependencies": [{"name": "example", "vulns": [{"id": "CVE-2026-0001"}]}]}
        code, summary = AUDIT.summarize(report, {"example"})
        self.assertEqual(code, 1)
        self.assertEqual(summary["vulnerabilities"][0]["advisory"], "CVE-2026-0001")

    def test_unscanned_dependency_blocks(self):
        report = {"dependencies": [{"name": "example", "vulns": []}]}
        self.assertEqual(AUDIT.summarize(report, {"example", "missing"})[0], 2)

    def test_skipped_dependency_blocks_without_echoing_reason(self):
        report = {"dependencies": [{"name": "example", "skip_reason": "fixture-private-index"}]}
        code, summary = AUDIT.summarize(report, {"example"})
        self.assertEqual(code, 2)
        self.assertNotIn("fixture-private-index", str(summary))

    def test_empty_or_malformed_audit_blocks(self):
        for report in ({}, None, {"dependencies": []}):
            self.assertEqual(AUDIT.summarize(report, {"example"})[0], 2)


if __name__ == "__main__":
    unittest.main()
