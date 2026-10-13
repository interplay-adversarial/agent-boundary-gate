"""Create a private, pinned image context from independently approved probe inputs."""

import json
import re
import shutil
from pathlib import Path

from agent_boundary_gate.doctor import read_regular_input
from agent_boundary_gate.probe_delivery import PROBE_PATH, RustProbeArtifact
from scripts.stage_rust_probe import Parser, stage


def prepare(
    *, binary: Path, manifest: Path, pins: RustProbeArtifact, base_image: str, destination: Path
) -> dict:
    # Require an immutable OCI reference; prohibit Dockerfile expansion/injection.
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]{0,240}@sha256:[0-9a-f]{64}", base_image):
        raise ValueError("owned-image-base-pin-required")
    destination.mkdir(mode=0o700)
    try:
        stage(binary=binary, manifest=manifest, pins=pins, destination=destination / "probe")
        # Preserve base-image entrypoint/user/runtime. No package manager,
        # downloads or implicit interpreter/runtime replacements.
        dockerfile = (
            f"FROM {base_image}\n"
            f"COPY --chmod=0555 probe/gate-http-probe {PROBE_PATH}\n"
            "COPY probe/LICENSE probe/NOTICE /opt/agent-boundary-gate/licenses/\n"
        )
        (destination / "Dockerfile").write_text(dockerfile)
        (destination / ".dockerignore").write_text(
            "*\n!Dockerfile\n!probe/\nprobe/*\n!probe/gate-http-probe\n!probe/LICENSE\n!probe/NOTICE\n"
        )
        # This remains private: final image identity must be pinned after build.
        (destination / "image-inputs.json").write_text(
            json.dumps(
                {
                    "base_image": base_image,
                    "probe": pins.model_dump(mode="json"),
                    "qualification": "unqualified-image-context",
                    "release_eligible": False,
                },
                indent=2,
            )
            + "\n"
        )
        for name in ("Dockerfile", ".dockerignore", "image-inputs.json"):
            (destination / name).chmod(0o600)
    except BaseException:
        shutil.rmtree(destination)
        raise
    return {
        "status": "verified-owned-image-context",
        "target": pins.target,
        "release_eligible": False,
    }


def main():
    parser = Parser(description=__doc__)
    for name in ("binary", "manifest", "pins", "destination"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--base-image", required=True)
    try:
        args = parser.parse_args()
        result = prepare(
            binary=args.binary,
            manifest=args.manifest,
            pins=RustProbeArtifact.model_validate_json(read_regular_input(args.pins, limit=65536)),
            base_image=args.base_image,
            destination=args.destination,
        )
    except (OSError, ValueError, RecursionError):
        result = {"error": "owned-image-context-rejected", "release_eligible": False}
        print(json.dumps(result))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
