"""Private model-backed OpenCode smoke: one headless local session, no sandbox/boundary claims.

Proves the pinned OpenCode CLI installs, is configured with an operator-selected
model endpoint, runs one real prompt and that its session artifact can be read
back -- nothing about PORT-01/GYM-03's case/action routing, boundary enforcement
or qualification. Run with the core interpreter: python -m scripts.opencode_smoke.
"""

import argparse
import json
import os
import sqlite3
import stat
import subprocess
from pathlib import Path

from agent_boundary_gate.agents.opencode_runtime import (
    OPENCODE_VERSION,
    OpenCodeProvider,
    ensure_opencode,
)

PROMPT = "Reply with exactly the single word READY and nothing else."


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, '{"error":"invalid-opencode-smoke-input","release_eligible":false}\n')


class CredentialReflectionError(ValueError):
    pass


def reject_reflected_bytes(value: bytes, credential: str) -> None:
    if credential.encode() in value:
        raise CredentialReflectionError("provider-credential-reflection")


def private_json(path: Path, *, max_bytes: int = 16384) -> dict:
    if type(max_bytes) is not int or not 0 < max_bytes <= 2 * 1024 * 1024:
        raise ValueError("invalid-private-json-limit")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > max_bytes:
            raise ValueError("private-provider-file-required")
        raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError("provider-file-too-large")
    return json.loads(raw)


def write_private(directory: Path, name: str, value: object) -> None:
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)


def parse_assistant_text(db_path: Path) -> bool:
    """Return whether the session database holds a non-empty assistant text part."""
    if not db_path.is_file():
        return False
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        roles = {
            row["id"]: json.loads(row["data"]).get("role")
            for row in con.execute("select id, data from message")
        }
        parts = con.execute("select message_id, data from part").fetchall()
    finally:
        con.close()
    for row in parts:
        part = json.loads(row["data"])
        if (
            roles.get(row["message_id"]) == "assistant"
            and part.get("type") == "text"
            and (part.get("text") or "").strip()
        ):
            return True
    return False


def smoke(
    provider: OpenCodeProvider,
    credential: str,
    directory: Path,
    *,
    opencode_version: str = OPENCODE_VERSION,
    run=subprocess.run,
) -> dict:
    command = ensure_opencode(
        opencode_version,
        directory / "opencode-cli",
        timeout_seconds=provider.timeout_seconds,
        run=run,
    )
    project_dir = directory / "project"
    project_dir.mkdir(mode=0o700)
    data_home = directory / "data"
    data_home.mkdir(mode=0o700)
    # No custom opencode.json: OpenCode's stock openai-compatible provider already
    # reads OPENAI_BASE_URL/OPENAI_API_KEY, the same fallback Gym's own agent uses
    # when it is not routing through its own internal model server.
    env = {
        **os.environ,
        "XDG_DATA_HOME": str(data_home),
        "OPENAI_BASE_URL": provider.base_url,
        "OPENAI_API_KEY": credential,  # pragma: allowlist secret
        # Protect the pinned version and keep the run hermetic; unlike Gym's own
        # sandbox session path this is not disabled by default locally.
        "OPENCODE_DISABLE_AUTOUPDATE": "true",
        "OPENCODE_DISABLE_PROJECT_CONFIG": "true",
    }
    result = run(
        [command, "run", "-m", provider.model, "--dir", str(project_dir), PROMPT],
        cwd=str(project_dir),
        env=env,
        capture_output=True,
        text=True,
        timeout=provider.timeout_seconds,
    )
    reject_reflected_bytes((result.stdout + result.stderr).encode(), credential)
    db_path = data_home / "opencode" / "opencode.db"
    assistant_text_present = parse_assistant_text(db_path)
    return {
        "exit_code": result.returncode,
        "session_artifact_present": db_path.is_file(),
        "assistant_text_present": assistant_text_present,
        "smoke_complete": result.returncode == 0 and assistant_text_present,
    }


def main() -> int:
    parser = PrivateParser(description=__doc__)
    parser.add_argument("--provider", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--opencode-version", default=OPENCODE_VERSION)
    args = parser.parse_args()
    created = False
    try:
        provider = OpenCodeProvider.model_validate(private_json(args.provider))
        credential = os.environ.get(provider.api_key_env, "")
        if not credential or any(ord(c) <= 32 or ord(c) >= 127 for c in credential):
            raise ValueError("model-credential-unavailable")
        args.output.mkdir(mode=0o700, exist_ok=False)
        created = True
        manifest = {
            "opencode_version": args.opencode_version,
            "provider": provider.baseline(),
            "scope": "opencode-local-cli-smoke-only",
            "boundary_evaluated": False,
            "qualification": "development-only",
            "release_eligible": False,
        }
        report = smoke(provider, credential, args.output, opencode_version=args.opencode_version)
        report.update(manifest)
        write_private(args.output, "smoke.json", report)
        print(
            json.dumps(
                {
                    "opencode_smoke_completed": report["smoke_complete"],
                    "boundary_evaluated": False,
                    "release_eligible": False,
                }
            )
        )
        return 0 if report["smoke_complete"] else 2
    except (Exception, KeyboardInterrupt) as error:
        failure = {"error": "opencode-smoke-incomplete", "release_eligible": False}
        if isinstance(error, CredentialReflectionError):
            failure["reason"] = "provider-credential-reflection"
        if created:
            try:
                write_private(args.output, "failure.json", failure)
            except (OSError, ValueError):
                pass
        print(json.dumps(failure))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
