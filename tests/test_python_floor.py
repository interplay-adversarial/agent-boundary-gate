"""The declared Python floor stays consistent everywhere and is exercised by CI."""

import re
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/checks.yml").read_text()


def version(text):
    return tuple(int(part) for part in re.match(r"(\d+)\.(\d+)", text).groups())


def floor_of(specifier):
    match = re.fullmatch(r">=(\d+\.\d+)", specifier.strip())
    assert match, f"requires-python must be a single >=X.Y floor, got {specifier!r}"
    return version(match.group(1))


PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())
FLOOR = floor_of(PROJECT["project"]["requires-python"])


class PythonFloorTests(unittest.TestCase):
    def test_floor_is_at_least_3_13(self):
        self.assertGreaterEqual(FLOOR, (3, 13))

    def test_ruff_target_matches_the_floor(self):
        self.assertEqual(PROJECT["tool"]["ruff"]["target-version"], f"py{FLOOR[0]}{FLOOR[1]}")

    def test_default_interpreter_is_the_floor(self):
        pinned = (ROOT / ".python-version").read_text().strip()
        self.assertEqual(version(pinned), FLOOR)

    def test_lock_declares_the_same_floor(self):
        header = (ROOT / "uv.lock").read_text().split("\n[[package]]", 1)[0]
        declared = re.search(r'^requires-python = "(.+)"$', header, re.MULTILINE).group(1)
        self.assertEqual(floor_of(declared), FLOOR)

    def test_ci_matrix_tests_the_floor_and_nothing_below_it(self):
        matrix = re.search(r"python-version: \[(.+?)\]", WORKFLOW).group(1)
        versions = [version(item.strip(" '\"")) for item in matrix.split(",")]
        self.assertIn(FLOOR, versions)
        self.assertEqual(min(versions), FLOOR)

    def test_no_workflow_step_runs_below_the_floor(self):
        literals = re.findall(r"^\s*python-version: '(\d+\.\d+(?:\.\d+)?)'", WORKFLOW, re.MULTILINE)
        self.assertTrue(literals)
        for literal in literals:
            self.assertGreaterEqual(version(literal), FLOOR, literal)

    def test_optional_environments_never_fall_below_the_floor(self):
        for pyproject in sorted((ROOT / "onboarding").glob("*/pyproject.toml")):
            declared = tomllib.loads(pyproject.read_text())["project"]["requires-python"]
            minimum = re.search(r"(\d+\.\d+)", declared).group(1)
            self.assertGreaterEqual(version(minimum), FLOOR, str(pyproject.parent.name))

    def test_running_interpreter_satisfies_the_floor(self):
        self.assertGreaterEqual(sys.version_info[:2], FLOOR)


if __name__ == "__main__":
    unittest.main()
