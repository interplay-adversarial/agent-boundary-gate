import importlib.util
import json
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts/audit_publication.py"
SPEC = importlib.util.spec_from_file_location("publication_audit", MODULE_PATH)
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class PublicationTests(unittest.TestCase):
    def test_private_key_material_is_flagged_without_echoing_it(self):
        value = "-----BEGIN" + " PRIVATE KEY-----\n" + "fixture-data\n"
        findings = AUDIT.audit_blob("data.txt", value.encode())
        self.assertIn("private-key-material", {finding.rule for finding in findings})
        self.assertNotIn("fixture-data", json.dumps([finding._asdict() for finding in findings]))

    def test_operator_specific_hosts_are_rejected(self):
        value = "https://" + "api." + "fixture-cluster" + ".example.invalid:6443"
        findings = AUDIT.audit_blob("config.txt", value.encode())
        self.assertIn("url-host-not-public-reference", {finding.rule for finding in findings})

    def test_private_artifacts_and_key_files_are_rejected(self):
        for path in (
            "artifacts/packet.json",
            ".env.production",
            "signer.key",
            "signer.pub",
            "kubeconfig",
        ):
            with self.subTest(path=path):
                self.assertIn(
                    "private-or-credential-file",
                    {finding.rule for finding in AUDIT.audit_blob(path, b"fixture")},
                )

    def test_public_upstreams_and_synthetic_hashes_are_allowed(self):
        content = (
            b"https://github.com/interplay-adversarial/agent-boundary-gate\nsha256:" + b"a" * 64
        )
        self.assertEqual(AUDIT.audit_blob("README.md", content), [])

    def test_private_denylist_is_applied_without_exporting_values(self):
        findings = AUDIT.audit_blob("notes.md", b"fixture-private-name", ("fixture-private-name",))
        self.assertEqual(findings[0].rule, "operator-denylist")
        self.assertNotIn("fixture-private-name", json.dumps(findings[0]._asdict()))

    def test_private_recovery_journals_and_sidecars_are_rejected(self):
        for name in ("leases.sqlite3", "leases.sqlite3-journal", "leases.db", "leases.db-wal"):
            findings = AUDIT.audit_blob(name, b"synthetic-private-journal")
            self.assertTrue(
                any(finding.rule == "private-or-credential-file" for finding in findings)
            )


if __name__ == "__main__":
    unittest.main()
