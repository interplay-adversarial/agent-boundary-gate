"""Verify independent pins and stage a static probe for an operator-owned image build."""

import argparse
import json
import os
import shutil
import tempfile
from pathlib import Path

from agent_boundary_gate.doctor import read_regular_input
from agent_boundary_gate.evidence import bytes_digest
from agent_boundary_gate.probe_delivery import RustProbeArtifact
from scripts.audit_publication import audit_blob
from scripts.rust_probe_build import ROOT, artifact_privacy, inspect_static_elf


def stage(*, binary: Path, manifest: Path, pins: RustProbeArtifact, destination: Path) -> dict:
    """No downloads, execution, overwrite or implicit trust in build metadata.

    The output parent belongs to the trusted image builder. A staged directory is
    not an immutable deployed mount and cannot authorize backend execution.
    """
    pins = RustProbeArtifact.model_validate(pins)
    raw = read_regular_input(binary, limit=16 * 1024 * 1024)
    metadata = read_regular_input(manifest, limit=65536)
    if bytes_digest(raw) != pins.binary_digest or bytes_digest(metadata) != pins.manifest_digest:
        raise ValueError("rust-probe-stage-rejected")
    report = json.loads(metadata)
    expected = {
        "status": "experimental-build",
        "package_version": pins.package_version,
        "protocol": pins.protocol,
        "protocol_digest": pins.protocol_digest,
        "source_digest": pins.source_digest,
        "target": pins.target,
        "binary_digest": pins.binary_digest,
        "compiler_version": "1.98.1",
        "static_elf_verified": True,
        "artifact_privacy": "passed",
        "third_party_dependencies": 0,
        "live_qualified": False,
        "release_eligible": False,
    }
    if not isinstance(report, dict) or any(
        type(report.get(key)) is not type(value) or report[key] != value
        for key, value in expected.items()
    ):
        raise ValueError("rust-probe-stage-rejected")
    inspect_static_elf(raw, pins.target)
    artifact_privacy(raw)
    if audit_blob("gate-http-probe.provenance.json", metadata):
        raise ValueError("rust-probe-stage-rejected")
    licenses = {name: (ROOT / name).read_bytes() for name in ("LICENSE", "NOTICE")}
    if any(audit_blob(name, data) for name, data in licenses.items()):
        raise ValueError("rust-probe-stage-rejected")
    # Reserve the output name exclusively: never replace a file, directory or
    # symlink. Build privately, then publish inside the newly reserved directory.
    destination.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory(prefix="gate-probe-stage-", dir=destination) as private:
            folder = Path(private)
            files = {
                "gate-http-probe": raw,
                "gate-http-probe.provenance.json": metadata,
                "artifact-pins.json": (pins.model_dump_json(indent=2) + "\n").encode(),
                **licenses,
            }
            for name, data in files.items():
                path = folder / name
                with path.open("xb") as stream:
                    stream.write(data)
                path.chmod(0o555 if name == "gate-http-probe" else 0o444)
            for name in files:
                os.rename(folder / name, destination / name)
    except BaseException:
        shutil.rmtree(destination)
        raise
    return {"status": "verified-staging", "target": pins.target, "release_eligible": False}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("rust-probe-stage-rejected")


def main() -> int:
    parser = Parser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    try:
        args = parser.parse_args()
        pins = RustProbeArtifact.model_validate_json(read_regular_input(args.pins, limit=65536))
        report = stage(
            binary=args.binary, manifest=args.manifest, pins=pins, destination=args.destination
        )
    except (OSError, ValueError, RecursionError):
        print(json.dumps({"error": "rust-probe-stage-rejected", "release_eligible": False}))
        return 2
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
