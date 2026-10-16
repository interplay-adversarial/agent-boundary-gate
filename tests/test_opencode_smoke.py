"""Install/config/parse plumbing for the OpenCode smoke script, no live CLI or network."""

import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.opencode_smoke import (
    OPENCODE_VERSION,
    OpenCodeProvider,
    ensure_opencode,
    parse_assistant_text,
    private_json,
    reject_reflected_bytes,
    smoke,
    write_private,
)


def _session_db(
    path: Path, *, role: str = "assistant", part_type: str = "text", text: str = "READY"
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    try:
        con.execute("create table message (id text, data text)")
        con.execute("create table part (message_id text, data text)")
        con.execute("insert into message values ('m1', ?)", (json.dumps({"role": role}),))
        con.execute(
            "insert into part values ('m1', ?)", (json.dumps({"type": part_type, "text": text}),)
        )
        con.commit()
    finally:
        con.close()


class OpenCodeSmokeTests(unittest.TestCase):
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

    def test_provider_requires_https_v1_suffix_and_valid_identity(self):
        base = {
            "base_url": "https://example.com/v1",
            "api_key_env": "MODEL_API_KEY",
            "model": "openai/m",
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
            base_url="https://example.com/v1", api_key_env="MODEL_API_KEY", model="openai/m"
        )
        baseline = provider.baseline()
        self.assertEqual(baseline["base_url"], provider.base_url)
        self.assertEqual(baseline["model"], "openai/m")
        self.assertNotIn("api_key_env", baseline)
        self.assertNotIn("MODEL_API_KEY", str(baseline))

    def test_non_json_reflection_is_rejected_without_echoing_body_or_credential(self):
        key = "synthetic-credential"
        with self.assertRaises(ValueError) as raised:
            reject_reflected_bytes(("stderr: Bearer " + key).encode(), key)
        self.assertEqual(str(raised.exception), "provider-credential-reflection")
        reject_reflected_bytes(b"malformed but credential-free", key)

    def test_private_output_does_not_overwrite_or_follow_links(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            write_private(directory, "report.json", {"release_eligible": False})
            self.assertEqual((directory / "report.json").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_private(directory, "report.json", {})

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

    def test_parse_assistant_text_reads_the_session_database(self):
        with tempfile.TemporaryDirectory() as root:
            db_path = Path(root) / "opencode.db"
            self.assertFalse(parse_assistant_text(db_path))
            _session_db(db_path)
            self.assertTrue(parse_assistant_text(db_path))

    def test_parse_assistant_text_ignores_non_assistant_or_empty_text(self):
        with tempfile.TemporaryDirectory() as root:
            user_only = Path(root) / "user.db"
            _session_db(user_only, role="user")
            self.assertFalse(parse_assistant_text(user_only))

            empty_text = Path(root) / "empty.db"
            _session_db(empty_text, text="   ")
            self.assertFalse(parse_assistant_text(empty_text))

            other_part = Path(root) / "other.db"
            _session_db(other_part, part_type="step-finish")
            self.assertFalse(parse_assistant_text(other_part))

    def test_smoke_rejects_credential_reflected_in_opencode_output(self):
        provider = OpenCodeProvider(
            base_url="https://example.com/v1", api_key_env="MODEL_API_KEY", model="openai/m"
        )
        credential = "synthetic-credential"

        def fake_run(args, **kwargs):
            if args[0] == "npm" or "--version" in args:
                return subprocess.CompletedProcess(args, 0, stdout=OPENCODE_VERSION, stderr="")
            return subprocess.CompletedProcess(args, 0, stdout="Bearer " + credential, stderr="")

        with tempfile.TemporaryDirectory() as root:
            command = Path(root) / "opencode-cli" / "node_modules" / ".bin" / "opencode"
            command.parent.mkdir(parents=True)
            command.touch()
            with self.assertRaises(ValueError):
                smoke(provider, credential, Path(root), run=fake_run)

    def test_smoke_reports_completion_from_a_real_session_artifact(self):
        provider = OpenCodeProvider(
            base_url="https://example.com/v1", api_key_env="MODEL_API_KEY", model="openai/m"
        )

        def fake_run(args, **kwargs):
            if args[0] == "npm" or "--version" in args:
                return subprocess.CompletedProcess(args, 0, stdout=OPENCODE_VERSION, stderr="")
            data_home = Path(kwargs["env"]["XDG_DATA_HOME"])
            _session_db(data_home / "opencode" / "opencode.db")
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as root:
            command = Path(root) / "opencode-cli" / "node_modules" / ".bin" / "opencode"
            command.parent.mkdir(parents=True)
            command.touch()
            report = smoke(provider, "unused", Path(root), run=fake_run)
            self.assertTrue(report["smoke_complete"])
            self.assertTrue(report["session_artifact_present"])
            self.assertTrue(report["assistant_text_present"])
