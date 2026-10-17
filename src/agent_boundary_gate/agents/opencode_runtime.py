"""Shared OpenCode CLI pin/install/readiness logic, independent of any transport.

Used by both the manual model-backed smoke (scripts/opencode_smoke.py) and the
OpenCodeAgentAdapter. Installation is a separate, explicit, operator-run step
from readiness: readiness must stay cheap and read-only (no network, no
subprocess beyond a local --version call), matching COMPAT-02's doctor
philosophy, since lifecycle readiness budgets are seconds, not install time.
"""

import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

OPENCODE_VERSION = "1.17.11"

# Explicit allow-list, not a bare os.environ passthrough, for any subprocess that
# runs a real OpenCode session (talks to an external model endpoint and executes
# model-generated tool code): it gets only what it needs, never whatever else
# happens to be in the caller's process. Same discipline as
# adaptive_task_runner.py's _gym_environment. Does not apply to the cheaper
# install/--version check subprocesses (ensure_opencode/is_opencode_ready),
# which touch no external endpoint and run no generated code.
SESSION_INHERITED_ENV_NAMES = frozenset({"PATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"})

# The provider key this project's own generated opencode.json always registers
# the operator's endpoint under -- distinct from NeMo Gym's own "nemo" to avoid
# any confusion if the two ever appear side by side.
OPENCODE_PROVIDER_NAME = "gate"


class OpenCodeProvider(BaseModel):
    """An operator-selected model endpoint for OpenCode's stock openai-compatible provider.

    Shared by scripts/opencode_smoke.py and OpenCodeAgentAdapter so both validate
    and report the same way. The credential itself is never a field here: callers
    resolve it from the environment variable named by api_key_env at call time.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    base_url: str
    api_key_env: str
    # A bare model identifier as the endpoint itself names it (e.g. "qwen38-27b"),
    # not a "<provider>/<model>" reference -- the provider half is always
    # OPENCODE_PROVIDER_NAME, this project's own generated provider, never one
    # of OpenCode's built-in ones.
    model: str
    timeout_seconds: int = Field(default=120, ge=1, le=900)

    def baseline(self) -> dict[str, object]:
        # Credential loading is not part of the evaluation baseline.
        return self.model_dump(include={"base_url", "model", "timeout_seconds"})

    @field_validator("base_url")
    @classmethod
    def safe_url(cls, value: str) -> str:
        url = urlsplit(value)
        if (
            not value.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 for c in value)
            or url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
            or url.path.rstrip("/").split("/")[-1] != "v1"
        ):
            raise ValueError("invalid-provider-url")
        return value.rstrip("/")

    @field_validator("api_key_env")
    @classmethod
    def safe_env(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,80}", value):
            raise ValueError("invalid-credential-reference")
        return value

    @field_validator("model")
    @classmethod
    def safe_identity(cls, value: str) -> str:
        if not value or len(value) > 256 or not value.isprintable():
            raise ValueError("invalid-model-identity")
        return value


def opencode_command(install_dir: Path) -> Path:
    return install_dir / "node_modules" / ".bin" / "opencode"


def opencode_model_reference(provider: OpenCodeProvider) -> str:
    return f"{OPENCODE_PROVIDER_NAME}/{provider.model}"


def build_opencode_config(provider: OpenCodeProvider) -> dict:
    """An @ai-sdk/openai-compatible provider authenticated by an explicit header.

    Deliberately not the SDK's own `apiKey` option: confirmed empirically
    (2026-10-16, against a real self-hosted MaaS gateway) that `apiKey` alone
    produces an opaque server-side error regardless of model or install/env
    state, while an explicit `Authorization: Bearer <token>` header -- a
    known-working configuration for the same endpoint -- works. `{env:NAME}`
    is OpenCode's own config templating syntax; it substitutes the named
    environment variable at run time, so the real credential is written here
    only as a template reference, never as a literal value. Verified with a
    synthetic local mock endpoint and a fake credential before relying on it.
    """
    return {
        "provider": {
            OPENCODE_PROVIDER_NAME: {
                "npm": "@ai-sdk/openai-compatible",
                "options": {
                    "baseURL": provider.base_url,
                    "headers": {"Authorization": f"Bearer {{env:{provider.api_key_env}}}"},
                },
                "models": {provider.model: {"name": provider.model}},
            }
        }
    }


def is_opencode_ready(
    version: str, install_dir: Path, *, timeout_seconds: float = 10, run=subprocess.run
) -> bool:
    """Read-only: true only if the pinned binary is present and reports that version."""
    command = opencode_command(install_dir)
    if not command.is_file():
        return False
    try:
        check = run(
            [str(command), "--version"], capture_output=True, text=True, timeout=timeout_seconds
        )
    except OSError:
        return False
    return check.returncode == 0 and check.stdout.strip() == version


def ensure_opencode(
    version: str, install_dir: Path, *, timeout_seconds: float, run=subprocess.run
) -> str:
    """Return a path to the pinned OpenCode CLI, installing it locally if needed.

    Installs into ``install_dir`` (writable, non-global) rather than the
    system npm prefix, which is frequently read-only for an unprivileged user.
    This is a mutating, potentially slow (network) operation -- call it from
    explicit setup code, never from a readiness check.
    """
    command = opencode_command(install_dir)
    if not command.is_file():
        try:
            result = run(
                [
                    "npm",
                    "install",
                    "--no-save",
                    "--prefix",
                    str(install_dir),
                    f"opencode-ai@{version}",
                ],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except OSError as error:
            # Covers a missing npm on PATH the same way the --version check
            # below already covers a missing opencode binary: a clear, fixed,
            # secret-free diagnostic instead of a raw, unwrapped OSError.
            raise RuntimeError("opencode-install-failed") from error
        if result.returncode != 0:
            raise RuntimeError("opencode-install-failed")
    try:
        check = run([str(command), "--version"], capture_output=True, text=True, timeout=10)
    except OSError as error:
        # Covers a missing binary (install silently produced nothing runnable)
        # without a separate, redundant existence check beforehand.
        raise RuntimeError("opencode-install-failed") from error
    if check.returncode != 0 or check.stdout.strip() != version:
        # A pre-existing binary at the wrong version is a fatal mismatch, never
        # silently reinstalled over.
        raise RuntimeError("opencode-version-mismatch")
    return str(command)
