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
    def test_gym_markers_use_selected_interpreter_not_auditor_interpreter(self):
        export = "old==1.0 ; python_version < '3.13'\nnew==2.0 ; python_version >= '3.13'\n"
        expected = AUDIT.locked_dependencies(
            export, marker_environment={"python_version": "3.13", "python_full_version": "3.13.14"}
        )
        self.assertEqual(expected, {"new": Version("2.0")})

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
        self.assertEqual(summary["vulnerabilities"], [])
        self.assertEqual(len(summary["unverified_vulnerabilities"]), 1)

    def test_duplicate_findings_are_unverified_and_order_independent(self):
        clean = {"name": "example", "version": "1.2.3", "vulns": []}
        vulnerable = {
            "name": "Example",
            "version": "1.2.3",
            "vulns": [{"id": "CVE-2026-0001"}, {"id": "CVE-2026-0001"}],
        }
        summaries = []
        for rows in ([clean, vulnerable], [vulnerable, clean]):
            code, summary = AUDIT.summarize({"dependencies": rows}, {"example": Version("1.2.3")})
            self.assertEqual(code, 2)
            self.assertEqual(summary["dependencies_scanned"], 0)
            self.assertEqual(summary["vulnerabilities"], [])
            self.assertEqual(
                summary["unverified_vulnerabilities"],
                [{"package": "example", "advisory": "CVE-2026-0001"}],
            )
            summaries.append(summary)
        self.assertEqual(*summaries)

    def test_malformed_or_skipped_duplicate_invalidates_matching_row(self):
        valid = {"name": "example", "version": "1.2.3", "vulns": []}
        for extra in (
            {"name": "example", "vulns": []},
            {"name": "example", "version": "invalid", "vulns": []},
            {"name": "example", "skip_reason": "fixture-private-index"},
        ):
            results = [
                AUDIT.summarize({"dependencies": rows}, {"example": Version("1.2.3")})
                for rows in ([valid, extra], [extra, valid])
            ]
            self.assertEqual(results[0], results[1])
            self.assertEqual(results[0][0], 2)
            self.assertEqual(results[0][1]["dependencies_scanned"], 0)
            self.assertNotIn("fixture-private-index", str(results))

    def test_unexpected_and_invalid_version_advisories_are_unverified(self):
        for rejected in (
            {"name": "other", "version": "1.0"},
            {"name": "example"},
            {"name": "example", "version": "invalid"},
        ):
            rejected["vulns"] = [{"id": "CVE-2026-0001"}]
            code, summary = AUDIT.summarize(
                {"dependencies": [rejected]}, {"example": Version("1.2.3")}
            )
            self.assertEqual(code, 2)
            self.assertEqual(summary["vulnerabilities"], [])
            self.assertEqual(len(summary["unverified_vulnerabilities"]), 1)

    def test_malformed_advisory_identity_is_sanitized(self):
        row = {"name": "example", "version": "1.2.3", "vulns": [{"id": 123}, None]}
        code, summary = AUDIT.summarize({"dependencies": [row]}, {"example": Version("1.2.3")})
        self.assertEqual(code, 1)
        self.assertEqual(
            summary["vulnerabilities"],
            [{"package": "example", "advisory": "unclassified-advisory"}],
        )

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
