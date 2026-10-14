"""Provider admission and model identity ambiguity never create passing evidence."""

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts.gym_smoke import (
    Provider,
    episode_complete,
    private_json,
    reject_reflected_bytes,
    reject_reflected_credential,
    select_model,
    write_private,
)


class GymSmokeTests(unittest.TestCase):
    def test_private_provider_rejects_public_file_symlink_and_nonregular_input(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "provider.json"
            path.write_text("{}")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                private_json(path)
            path.chmod(0o600)
            self.assertEqual(private_json(path), {})
            link = Path(root) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                private_json(link)
            fifo = Path(root) / "fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(ValueError):
                private_json(fifo)

    def test_provider_requires_https_without_embedded_secrets_and_bounded_budgets(self):
        base = {"base_url": "https://example.com/v1", "api_key_env": "MODEL_API_KEY"}
        self.assertEqual(Provider.model_validate(base).max_steps, 3)
        for path in ("/v1", "/api/v1", "/tenant/model/v1", "/tenant/model/v1/"):
            url = "https://example.com" + path
            self.assertEqual(
                Provider.model_validate(base | {"base_url": url}).base_url, url.rstrip("/")
            )
        for change in (
            {"base_url": "http://example.com/v1"},
            {"base_url": "https://" + "user:token@example.com/v1"},
            {"base_url": "https://example.com/v1?token=secret"},
            {"base_url": "https://example.com/v1\n"},
            {"base_url": "https://example.com/v1/chat/completions"},
            {"base_url": "https://example.com/v1/chat"},
            {"max_steps": 0},
            {"campaign_seconds": 0},
            {"max_tokens": 99999},
            {"api_key": "synthetic-secret"},
            {"api_key_env": "bad name"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                Provider.model_validate(base | change)

    def test_model_discovery_requires_unique_exact_identity(self):
        inventory = {"data": [{"id": "model-a"}, {"id": "model-b"}]}
        self.assertEqual(select_model(inventory, "model-a"), "model-a")
        for value, requested in (
            (inventory, None),
            (inventory, "model-c"),
            ({"data": [{"id": "model-a"}, {"id": "model-a"}]}, "model-a"),
            ({"data": []}, None),
            ({"data": [{"id": "bad\nname"}]}, None),
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                select_model(value, requested)

    def test_saved_baseline_has_evaluation_parameters_without_credential_references(self):
        provider = Provider(base_url="https://example.com/v1", api_key_env="MODEL_API_KEY")
        baseline = provider.baseline()
        self.assertEqual(baseline["base_url"], provider.base_url)
        self.assertEqual(baseline["seed"], 17)
        self.assertEqual(baseline["max_tokens"], 2048)
        self.assertNotIn("api_key_env", baseline)
        self.assertNotIn("MODEL_API_KEY", str(baseline))

    def test_reflection_guard_inspects_nested_values_and_keys_without_echoing_secret(self):
        key = "synthetic-credential"
        for value in ({"debug": ["Bearer " + key]}, {key: "unused"}):
            with self.assertRaises(ValueError) as raised:
                reject_reflected_credential(value, key)
            self.assertNotIn(key, str(raised.exception))
        reject_reflected_credential({"data": [{"id": "model-a"}]}, key)
        with self.assertRaises(ValueError):
            reject_reflected_credential({"debug": 1700000000}, "1700000000")

    def test_non_json_reflection_is_rejected_without_echoing_body_or_credential(self):
        key = "synthetic-credential"
        with self.assertRaises(ValueError) as raised:
            reject_reflected_bytes(("<html>Bearer " + key + "</html>").encode(), key)
        self.assertEqual(str(raised.exception), "provider-credential-reflection")
        reject_reflected_bytes(b"malformed but credential-free", key)

    def test_private_output_does_not_overwrite_or_follow_links(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            write_private(directory, "report.json", {"release_eligible": False})
            self.assertEqual((directory / "report.json").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_private(directory, "report.json", {})

    def test_incomplete_invocation_or_failed_tool_cannot_complete_episode(self):
        response = SimpleNamespace(status="completed", incomplete_details=None)
        trajectory = SimpleNamespace(
            invocations=[SimpleNamespace(status="completed")], tool_calls=[], gaps=[]
        )
        self.assertTrue(episode_complete(response, trajectory))
        trajectory.invocations[0].status = "incomplete"
        self.assertFalse(episode_complete(response, trajectory))
        trajectory.invocations[0].status = "completed"
        trajectory.tool_calls = [SimpleNamespace(status="failed")]
        self.assertFalse(episode_complete(response, trajectory))
