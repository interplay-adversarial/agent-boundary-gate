"""Installed baseline identity rejects dependency drift before native imports."""

import copy
import importlib.util
import json
import unittest
from pathlib import Path
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location(
    "gym_replay", Path(__file__).resolve().parents[1] / "scripts/gym_replay.py"
)
REPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPLAY)
PIN = {"upstream": "https://github.com/NVIDIA-NeMo/Gym", "commit": "a" * 40}


class GymEnvironmentTests(unittest.TestCase):
    def lock(self):
        return {
            "package": [
                {
                    "name": "agent-boundary-gate-gym-onboarding",
                    "source": {"virtual": "."},
                    "dependencies": [{"name": "nemo-gym"}],
                },
                {
                    "name": "nemo-gym",
                    "version": "0.7.0rc0",
                    "source": {"git": PIN["upstream"]},
                    "dependencies": [
                        {"name": "packaging"},
                        {"name": "server", "extra": ["default"]},
                    ],
                },
                {
                    "name": "packaging",
                    "version": "26.3",
                    "source": {"registry": "https://pypi.org/simple"},
                },
                {
                    "name": "server",
                    "version": "1.0",
                    "source": {"registry": "https://pypi.org/simple"},
                    "optional-dependencies": {
                        "default": [
                            {"name": "collector"},
                            {"name": "unused", "marker": "python_version < '3.0'"},
                        ]
                    },
                },
                {
                    "name": "collector",
                    "version": "2.0",
                    "source": {"registry": "https://pypi.org/simple"},
                },
                {
                    "name": "unused",
                    "version": "3.0",
                    "source": {"registry": "https://pypi.org/simple"},
                },
            ]
        }

    def distribution(self, name, version, *, commit=PIN["commit"]):
        provenance = json.dumps(
            {"url": PIN["upstream"] + ".git", "vcs_info": {"vcs": "git", "commit_id": commit}}
        )
        return SimpleNamespace(
            metadata={"Name": name}, version=version, read_text=lambda _: provenance
        )

    def installed(self):
        return [
            self.distribution(name, version)
            for name, version in (
                ("nemo-gym", "0.7.0rc0"),
                ("packaging", "26.3"),
                ("server", "1.0"),
                ("collector", "2.0"),
            )
        ]

    def test_complete_baseline_includes_required_extras_and_skips_inapplicable_markers(self):
        actual = REPLAY.check_environment(self.lock(), PIN, distributions=self.installed())
        self.assertEqual(
            actual,
            {"nemo-gym": "0.7.0rc0", "packaging": "26.3", "server": "1.0", "collector": "2.0"},
        )

    def test_changed_missing_extra_or_duplicate_distribution_is_rejected(self):
        changed = self.installed()
        changed[-1].version = "1.9"
        for distributions in (
            changed,
            self.installed()[:-1],
            self.installed() + [self.distribution("foreign", "1.0")],
            self.installed() + [self.distribution("collector", "2.0")],
        ):
            with self.subTest(count=len(distributions)), self.assertRaises(ValueError):
                REPLAY.check_environment(self.lock(), PIN, distributions=distributions)

    def test_installed_gym_source_commit_must_match_pin(self):
        distributions = self.installed()
        distributions[0] = self.distribution("nemo-gym", "0.7.0rc0", commit="b" * 40)
        with self.assertRaisesRegex(ValueError, "gym-installed-source-mismatch"):
            REPLAY.check_environment(self.lock(), PIN, distributions=distributions)

    def test_ambiguous_future_lock_is_rejected(self):
        lock = self.lock()
        lock["package"].append(copy.deepcopy(lock["package"][-1]))
        with self.assertRaisesRegex(ValueError, "gym-ambiguous-lock-package"):
            REPLAY.check_environment(lock, PIN, distributions=self.installed())
