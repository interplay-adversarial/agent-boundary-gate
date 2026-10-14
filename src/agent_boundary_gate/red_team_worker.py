"""Optional Interplay worker: standard-library bootstrap before pinned imports."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import sys
from pathlib import Path


def check_environment(pin_path):
    pin = json.loads(pin_path.read_text())
    if list(sys.version_info[:3]) != pin["python"]:
        raise ValueError("red-team-interpreter-mismatch")
    distribution = importlib.metadata.distribution("interplay-adversarial")
    direct = json.loads(distribution.read_text("direct_url.json") or "{}")
    if (
        direct.get("url") != pin["repository"]
        or direct.get("vcs_info", {}).get("commit_id") != pin["commit"]
        or direct.get("dir_info", {}).get("editable")
    ):
        raise ValueError("red-team-source-mismatch")
    for name, expected in pin["packages"].items():
        if importlib.metadata.version(name) != expected:
            raise ValueError("red-team-package-mismatch")
    for relative, expected in pin["files"].items():
        raw = Path(distribution.locate_file(relative)).read_bytes()
        if "sha256:" + hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("red-team-file-mismatch")


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("operation", choices=("validate", "run", "recover"))
    parser.add_argument("--pin", type=Path, required=True)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        check_environment(args.pin)
        if args.operation == "validate":
            from interplay.assessment.models import CampaignConfig
            from interplay.assessment.runner import redact

            raw = sys.stdin.buffer.read(65537)
            if len(raw) > 65536:
                raise ValueError("red-team-config-limit")
            config = CampaignConfig.model_validate_json(raw)
            values = config.model_dump(mode="json")
            secrets = []
            for role, env_role in (
                ("adversarial", "ADVERSARIAL"),
                ("target", "TARGET"),
                ("judge", "JUDGE"),
            ):
                endpoint, key = getattr(config, role).resolved(env_role)
                values[role] = endpoint.model_dump(mode="json")
                secrets.append(key)
            print(json.dumps({"config": redact(values, secrets), "release_eligible": False}))
            return 0
        from interplay.assessment.cli import main as assessment_main

        if args.operation == "recover":
            return assessment_main(["assessment-recover", "--output", str(args.output)])
        return assessment_main(
            ["assess", "--config", str(args.config), "--output", str(args.output)]
        )
    except Exception:
        print('{"error":"red-team-environment-or-input-invalid","release_eligible":false}')
        return 2


if __name__ == "__main__":
    os.environ["NEMO_TELEMETRY_ENABLED"] = "false"
    raise SystemExit(main())
