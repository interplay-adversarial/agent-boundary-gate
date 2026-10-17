"""Shared OpenCode CLI pin/install/readiness logic: no live CLI or network."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from agent_boundary_gate.agents.opencode_runtime import (
    OPENCODE_PROVIDER_NAME,
    OPENCODE_VERSION,
    OpenCodeProvider,
    build_opencode_config,
    ensure_opencode,
    is_opencode_ready,
    opencode_model_reference,
)


class OpenCodeRuntimeTests(unittest.TestCase):
    def test_provider_requires_https_v1_suffix_and_valid_identity(self):
        base = {
            "base_url": "https://example.com/v1",
            "api_key_env": "MODEL_API_KEY",
            "model": "m",
        }
        self.assertEqual(OpenCodeProvider.model_validate(base).timeout_seconds, 120)
        for change in (
            {"base_url": "http://example.com/v1"},
            {"base_url": "https://" + "user:token@example.com/v1"},
            {"base_url": "https://example.com/v1?token=secret"},
            {"base_url": "https://example.com/v1/chat/completions"},
            {"api_key_env": "bad name"},
            {"model": ""},
            {"timeout_seconds": 0},
            {"timeout_seconds": 1000},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                OpenCodeProvider.model_validate(base | change)

    def test_saved_baseline_has_evaluation_parameters_without_credential_references(self):
        provider = OpenCodeProvider(
            base_url="https://example.com/v1", api_key_env="MODEL_API_KEY", model="m"
        )
        baseline = provider.baseline()
        self.assertEqual(baseline["base_url"], provider.base_url)
        self.assertEqual(baseline["model"], "m")
        self.assertNotIn("api_key_env", baseline)
        self.assertNotIn("MODEL_API_KEY", str(baseline))

    def test_opencode_model_reference_prefixes_the_bare_model_with_our_provider(self):
        provider = OpenCodeProvider(
            base_url="https://example.com/v1", api_key_env="MODEL_API_KEY", model="m"
        )
        self.assertEqual(opencode_model_reference(provider), f"{OPENCODE_PROVIDER_NAME}/m")

    def test_build_opencode_config_authenticates_via_header_template_not_apikey(self):
        provider = OpenCodeProvider(
            base_url="https://example.com/v1", api_key_env="MODEL_API_KEY", model="m"
        )
        config = build_opencode_config(provider)
        provider_config = config["provider"][OPENCODE_PROVIDER_NAME]
        self.assertEqual(provider_config["npm"], "@ai-sdk/openai-compatible")
        self.assertEqual(provider_config["options"]["baseURL"], provider.base_url)
        self.assertNotIn("apiKey", provider_config["options"])
        self.assertEqual(
            provider_config["options"]["headers"]["Authorization"], "Bearer {env:MODEL_API_KEY}"
        )
        self.assertIn("m", provider_config["models"])
        # The template references the env var name, never a literal secret value.
        self.assertNotIn("MODEL_API_KEY=", str(config))

    def test_is_opencode_ready_requires_a_present_and_pinned_binary(self):
        with tempfile.TemporaryDirectory() as root:
            install_dir = Path(root)
            self.assertFalse(is_opencode_ready(OPENCODE_VERSION, install_dir))

            command = install_dir / "node_modules" / ".bin" / "opencode"
            command.parent.mkdir(parents=True)
            command.touch()
            self.assertTrue(
                is_opencode_ready(
                    OPENCODE_VERSION,
                    install_dir,
                    run=lambda args, **kwargs: subprocess.CompletedProcess(
                        args, 0, stdout=OPENCODE_VERSION, stderr=""
                    ),
                )
            )
            self.assertFalse(
                is_opencode_ready(
                    OPENCODE_VERSION,
                    install_dir,
                    run=lambda args, **kwargs: subprocess.CompletedProcess(
                        args, 0, stdout="9.9.9", stderr=""
                    ),
                )
            )

    def test_is_opencode_ready_never_raises_on_a_broken_binary(self):
        with tempfile.TemporaryDirectory() as root:
            install_dir = Path(root)
            command = install_dir / "node_modules" / ".bin" / "opencode"
            command.parent.mkdir(parents=True)
            command.touch()

            def broken_run(args, **kwargs):
                raise OSError("not executable")

            self.assertFalse(is_opencode_ready(OPENCODE_VERSION, install_dir, run=broken_run))

    def test_ensure_opencode_skips_install_when_pinned_binary_already_present(self):
        with tempfile.TemporaryDirectory() as root:
            install_dir = Path(root)
            command = install_dir / "node_modules" / ".bin" / "opencode"
            command.parent.mkdir(parents=True)
            command.touch()
            calls = []

            def fake_run(args, **kwargs):
                calls.append(args)
                return subprocess.CompletedProcess(args, 0, stdout=OPENCODE_VERSION, stderr="")

            resolved = ensure_opencode(
                OPENCODE_VERSION, install_dir, timeout_seconds=5, run=fake_run
            )
            self.assertEqual(resolved, str(command))
            self.assertEqual(len(calls), 1)
            self.assertIn("--version", calls[0])

    def test_ensure_opencode_installs_into_a_local_prefix_when_missing(self):
        with tempfile.TemporaryDirectory() as root:
            install_dir = Path(root)
            command = install_dir / "node_modules" / ".bin" / "opencode"
            calls = []

            def fake_run(args, **kwargs):
                calls.append(args)
                if args[0] == "npm":
                    command.parent.mkdir(parents=True, exist_ok=True)
                    command.touch()
                    return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
                return subprocess.CompletedProcess(args, 0, stdout=OPENCODE_VERSION, stderr="")

            resolved = ensure_opencode(
                OPENCODE_VERSION, install_dir, timeout_seconds=5, run=fake_run
            )
            self.assertEqual(resolved, str(command))
            self.assertEqual(calls[0][0], "npm")
            self.assertIn("--prefix", calls[0])
            self.assertIn(str(install_dir), calls[0])
            self.assertIn(f"opencode-ai@{OPENCODE_VERSION}", calls[0])

    def test_ensure_opencode_wraps_a_missing_npm_in_a_clear_diagnostic(self):
        # A missing npm on PATH raised a raw, unwrapped FileNotFoundError
        # before this fix -- the same class of diagnostic gap the
        # --version check below already guards against for a missing
        # opencode binary.
        with tempfile.TemporaryDirectory() as root:
            install_dir = Path(root)

            def fake_run(args, **kwargs):
                raise FileNotFoundError(2, "No such file or directory", "npm")

            with self.assertRaises(RuntimeError) as caught:
                ensure_opencode(OPENCODE_VERSION, install_dir, timeout_seconds=5, run=fake_run)
            self.assertEqual(str(caught.exception), "opencode-install-failed")
            self.assertIsInstance(caught.exception.__cause__, FileNotFoundError)

    def test_ensure_opencode_rejects_an_unpinned_installed_version(self):
        with tempfile.TemporaryDirectory() as root:
            install_dir = Path(root)
            command = install_dir / "node_modules" / ".bin" / "opencode"
            command.parent.mkdir(parents=True)
            command.touch()

            def fake_run(args, **kwargs):
                return subprocess.CompletedProcess(args, 0, stdout="9.9.9", stderr="")

            with self.assertRaises(RuntimeError):
                ensure_opencode(OPENCODE_VERSION, install_dir, timeout_seconds=5, run=fake_run)
