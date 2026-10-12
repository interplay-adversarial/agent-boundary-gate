import importlib.util
import sys
import unittest
from pathlib import Path

from packaging.version import Version

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts/audit_dependencies.py"
SPEC = importlib.util.spec_from_file_location("dependency_audit", MODULE_PATH)
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class CVEAuditTests(unittest.TestCase):
    def test_complete_clean_audit_passes(self):
        report = {"dependencies": [{"name": "example", "version": "1.2.3", "vulns": []}]}
        self.assertEqual(AUDIT.summarize(report, {"example": Version("1.2.3")})[0], 0)

    def test_known_vulnerability_blocks(self):
        report = {
            "dependencies": [
                {"name": "example", "version": "1.2.3", "vulns": [{"id": "CVE-2026-0001"}]}
            ]
        }
        code, summary = AUDIT.summarize(report, {"example": Version("1.2.3")})
        self.assertEqual(code, 1)
        self.assertEqual(summary["vulnerabilities"][0]["advisory"], "CVE-2026-0001")

    def test_unscanned_dependency_blocks(self):
        report = {"dependencies": [{"name": "example", "version": "1.2.3", "vulns": []}]}
        self.assertEqual(
            AUDIT.summarize(report, {"example": Version("1.2.3"), "missing": Version("2.0")})[0], 2
        )

    def test_skipped_dependency_blocks_without_echoing_reason(self):
        report = {
            "dependencies": [
                {"name": "example", "version": "1.2.3", "skip_reason": "fixture-private-index"}
            ]
        }
        code, summary = AUDIT.summarize(report, {"example": Version("1.2.3")})
        self.assertEqual(code, 2)
        self.assertNotIn("fixture-private-index", str(summary))

    def test_empty_or_malformed_audit_blocks(self):
        for report in ({}, None, {"dependencies": []}):
            self.assertEqual(AUDIT.summarize(report, {"example": Version("1.2.3")})[0], 2)

    def test_wrong_missing_or_invalid_version_blocks(self):
        for version in ("1.2.2", None, 123, "invalid"):
            report = {"dependencies": [{"name": "example", "version": version, "vulns": []}]}
            self.assertEqual(AUDIT.summarize(report, {"example": Version("1.2.3")})[0], 2)
        report = {"dependencies": [{"name": "example", "vulns": []}]}
        self.assertEqual(AUDIT.summarize(report, {"example": Version("1.2.3")})[0], 2)

    def test_duplicate_or_unexpected_dependency_blocks(self):
        valid = {"name": "example", "version": "1.2.3", "vulns": []}
        extra = {"name": "other", "version": "1.0", "vulns": []}
        wrong = {"name": "example", "version": "1.2.2", "vulns": []}
        for rows in ([valid, valid], [valid, extra], [valid, wrong], [wrong, valid]):
            self.assertEqual(
                AUDIT.summarize({"dependencies": rows}, {"example": Version("1.2.3")})[0], 2
            )

    def test_normalized_name_and_version_match(self):
        report = {"dependencies": [{"name": "Example_Package", "version": "1.0.0", "vulns": []}]}
        self.assertEqual(AUDIT.summarize(report, {"example-package": Version("1.0")})[0], 0)

    def test_malformed_dependency_blocks(self):
        for row in (None, {}, {"name": 123}, {"name": "bad/name"}):
            self.assertEqual(
                AUDIT.summarize({"dependencies": [row]}, {"example": Version("1.2.3")})[0], 2
            )

    def test_version_mismatch_preserves_vulnerability(self):
        report = {
            "dependencies": [
                {"name": "example", "version": "1.2.2", "vulns": [{"id": "CVE-2026-0001"}]}
            ]
        }
        code, summary = AUDIT.summarize(report, {"example": Version("1.2.3")})
        self.assertEqual(code, 2)
        self.assertEqual(len(summary["vulnerabilities"]), 1)

    def test_exact_inventory_honors_markers_and_normalization(self):
        export = "\n".join(
            [
                "# frozen export",
                "Example_Package==1.0",
                "example-package==1.0.0",
                'other==2.0; python_version < "1.0"',
            ]
        )
        self.assertEqual(AUDIT.locked_dependencies(export), {"example-package": Version("1.0")})

    def test_ambiguous_or_unpinned_inventory_blocks(self):
        for export in (
            "",
            "# empty",
            "example>=1.0",
            "example==1.*",
            "example @ https://example.com/package.whl",
            "example==1.0\nexample==2.0",
            "example>=1.0,<2.0",
        ):
            with self.subTest(export=export), self.assertRaises(ValueError):
                AUDIT.locked_dependencies(export)


if __name__ == "__main__":
    unittest.main()
