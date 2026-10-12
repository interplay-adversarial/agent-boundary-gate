import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class LibraryExampleTests(unittest.TestCase):
    def example(self, name, *args):
        result = subprocess.run(
            [sys.executable, str(ROOT / "examples" / name), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.stderr, "")
        return result.returncode, json.loads(result.stdout)

    def test_offline_example(self):
        code, decision = self.example("library_policy.py")
        self.assertEqual(code, 0)
        self.assertEqual(decision["release_decision"], "pass")
        self.assertFalse(decision["release_eligible"])

    def test_loopback_examples_capture_real_effect_and_check_artifacts(self):
        with tempfile.TemporaryDirectory() as folder:
            for weakened in (False, True):
                with self.subTest(weakened=weakened):
                    destination = Path(folder) / str(weakened)
                    args = ["--output", str(destination)]
                    if weakened:
                        args.append("--weakened")
                    code, decision = self.example("library_loopback.py", *args)
                    self.assertEqual(code, 1 if weakened else 0)
                    self.assertEqual(
                        decision["release_decision"], "criteria_failed" if weakened else "pass"
                    )
                    self.assertFalse(decision["release_eligible"])
                    self.assertTrue(list(destination.glob("*.json")))
                    self.assertEqual(destination.stat().st_mode & 0o077, 0)
