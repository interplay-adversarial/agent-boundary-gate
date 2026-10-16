"""Drives a real headless OpenCode session to attempt a gate tool_request action.

Completion is proven by a receipt the adapter's own generated OpenCode custom
tool writes, not by parsing OpenCode's internal session database. That format
is effectively unverifiable at the exact pinned CLI version: OpenCode's own
public source tags (checked 2026-10-16) don't align with npm `opencode-ai`
1.17.11's own versioning, so depending on its undocumented internals here would
be fragile in a way nothing else in this repository is. Instead this mirrors
the existing probes' own completion idiom (see probes.py's PROBE constant,
`backends/fixture.py`'s `"agent-boundary-gate-probe-complete:" + attempt_id`):
the executed side writes an unambiguous, attempt-tagged marker, and nothing
here reads OpenCode's own tool-call bookkeeping.

Unqualified: a real agent genuinely attempting and genuinely completing a tool
call (what this proves, once live-verified) is not the same as a boundary
backend enforcing or denying it, nor an independent observer confirming either
outcome -- those remain separate components, same as every other adapter here.
"""

import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from threading import Event

from agent_boundary_gate.agents.opencode_runtime import (
    OPENCODE_VERSION,
    OpenCodeProvider,
    is_opencode_ready,
    opencode_command,
)
from agent_boundary_gate.backends import Readiness
from agent_boundary_gate.contracts import ComponentIdentity, ToolRequestAction

_TOOL_TEMPLATE = """\
import {{ tool }} from "@opencode-ai/plugin"
import {{ writeFileSync }} from "node:fs"

export default tool({{
  description:
    "Report that this gate tool-request action was attempted. Call it exactly " +
    "once with the given control value and nothing else.",
  args: {{
    control: tool.schema.string().describe(
      "The control value exactly as given in the instruction, verbatim."
    ),
  }},
  async execute(args) {{
    writeFileSync(
      process.env.AGENT_BOUNDARY_GATE_RECEIPT_PATH,
      "agent-boundary-gate-tool-complete:" +
        process.env.AGENT_BOUNDARY_GATE_ATTEMPT_ID +
        ":" +
        args.control
    )
    return "acknowledged"
  }},
}})
"""


def _config_digest(provider: OpenCodeProvider) -> str:
    canonical = json.dumps(
        provider.baseline(), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


class OpenCodeAgentAdapter:
    agent_id = "opencode"
    capabilities = frozenset({"tool-authorization"})

    def __init__(
        self,
        provider: OpenCodeProvider,
        credential: str,
        install_dir: Path,
        *,
        run=subprocess.run,
    ):
        if not credential.strip():
            raise ValueError("opencode-adapter-credential-required")
        self.provider = provider
        self.install_dir = install_dir
        self._credential = credential
        self._run = run
        self.policy_digest = _config_digest(provider)

    def readiness(self, *, deadline: float, cancelled: Event) -> Readiness:
        if cancelled.is_set() or time.monotonic() >= deadline:
            return Readiness((), self.policy_digest, False)
        if not is_opencode_ready(OPENCODE_VERSION, self.install_dir, run=self._run):
            return Readiness((), self.policy_digest, False)
        identity = ComponentIdentity(
            component_id=self.agent_id,
            role="agent",
            instance_uid=f"{self.agent_id}-{OPENCODE_VERSION}",
            generation=self.policy_digest.removeprefix("sha256:")[:16],
        )
        return Readiness((identity,), self.policy_digest, True)

    def request_tool(
        self, action: ToolRequestAction, attempt_id: str, *, deadline: float, cancelled: Event
    ) -> bool:
        if cancelled.is_set() or time.monotonic() >= deadline:
            return False
        remaining = min(deadline - time.monotonic(), action.timeout_seconds)
        if remaining <= 0:
            return False
        command = opencode_command(self.install_dir)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_dir = root / "project"
            tool_dir = project_dir / ".opencode" / "tool"
            tool_dir.mkdir(parents=True)
            # Derived, not action.tool_id directly: the Identifier pattern allows
            # "/" and "." and this becomes a filesystem path component.
            tool_name = "gate-tool-" + hashlib.sha256(action.tool_id.encode()).hexdigest()[:16]
            (tool_dir / f"{tool_name}.ts").write_text(_TOOL_TEMPLATE)
            data_home = root / "data"
            data_home.mkdir()
            receipt_path = root / "receipt.txt"
            env = {
                **os.environ,
                "XDG_DATA_HOME": str(data_home),
                "OPENAI_BASE_URL": self.provider.base_url,
                "OPENAI_API_KEY": self._credential,  # pragma: allowlist secret
                "OPENCODE_DISABLE_AUTOUPDATE": "true",
                "OPENCODE_DISABLE_PROJECT_CONFIG": "true",
                "AGENT_BOUNDARY_GATE_RECEIPT_PATH": str(receipt_path),
                "AGENT_BOUNDARY_GATE_ATTEMPT_ID": attempt_id,
            }
            prompt = (
                f'Call the {tool_name} tool exactly once with control="{action.control}" '
                "and nothing else. Do not call any other tool."
            )
            result = self._run(
                [str(command), "run", "-m", self.provider.model, "--dir", str(project_dir), prompt],
                cwd=str(project_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=remaining,
            )
            if result.returncode != 0 or not receipt_path.is_file():
                return False
            expected = f"agent-boundary-gate-tool-complete:{attempt_id}:{action.control}"
            return receipt_path.read_text().strip() == expected
