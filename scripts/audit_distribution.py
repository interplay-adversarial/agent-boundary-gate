"""Build isolated sdist/wheel distributions from exactly the Git index's tree, scan both
archives' contents for private data and secrets, confirm the sdist is self-contained (it
builds into the same wheel file list on its own), and smoke-test the installed wheel in a
fresh environment with no dev dependencies or editable `src/` on its path.

Invoke as `python -m scripts.audit_distribution` (not the bare script path): it imports
audit_publication as a sibling module, which only resolves with the repo root on sys.path.
"""

import io
import json
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from scripts.audit_publication import Finding, audit_blob

BUILD_TIMEOUT = 180
SMOKE_TIMEOUT = 120
SMOKE_COMMAND = ["agent-boundary-gate", "demo", "--scenario", "healthy"]


def clean_export(root: Path, directory: Path) -> None:
    """Materialize exactly the Git index's tree into `directory` -- no untracked files.

    Building from the live working directory would let local, gitignored clutter (an
    editor swap file, a stray cache directory, anything not yet staged) leak into a
    distribution archive without ever being caught by scanning the Git index itself, the
    way audit_publication.py's own default mode does. Building from this export instead
    makes the published tree itself provably exactly what was checked.
    """
    tree = subprocess.check_output(["git", "write-tree"], cwd=root, text=True).strip()
    archive = subprocess.run(
        ["git", "archive", "--format=tar", tree],
        cwd=root,
        capture_output=True,
        check=True,
        timeout=BUILD_TIMEOUT,
    )
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
        tar.extractall(directory, filter="data")


def build_distributions(source_dir: Path, out_dir: Path) -> tuple[Path, Path]:
    subprocess.run(
        ["uv", "build", "--sdist", "--wheel", "-o", str(out_dir), str(source_dir)],
        capture_output=True,
        check=True,
        timeout=BUILD_TIMEOUT,
    )
    wheels = sorted(out_dir.glob("*.whl"))
    sdists = sorted(out_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError("unexpected-distribution-artifact-count")
    return wheels[0], sdists[0]


def build_wheel_from_sdist(sdist_path: Path, out_dir: Path) -> Path:
    subprocess.run(
        ["uv", "build", "--wheel", "-o", str(out_dir), str(sdist_path)],
        capture_output=True,
        check=True,
        timeout=BUILD_TIMEOUT,
    )
    wheels = sorted(out_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("unexpected-rebuilt-wheel-count")
    return wheels[0]


def extract_wheel(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}


def extract_sdist(path: Path) -> dict[str, bytes]:
    contents = {}
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            relative = PurePosixPath(member.name)
            # Every sdist wraps its content in one top-level "<name>-<version>/" directory;
            # strip it so sdist and wheel findings report comparable relative paths.
            trimmed = PurePosixPath(*relative.parts[1:]) if len(relative.parts) > 1 else relative
            data = archive.extractfile(member)
            contents[str(trimmed)] = data.read() if data else b""
    return contents


def scan_contents(contents: dict[str, bytes]) -> list[Finding]:
    return [finding for path, data in contents.items() for finding in audit_blob(path, data)]


def installed_smoke_check(wheel_path: Path) -> dict:
    """Run a self-contained command (no external files, no model/network traffic) against
    the wheel installed in a fresh, isolated environment -- no dev dependencies, no
    editable `src/` on sys.path, nothing but exactly what the wheel declares."""
    result = subprocess.run(
        [
            "uv",
            "run",
            "--isolated",
            "--no-project",
            "--with",
            str(wheel_path),
            "--",
            *SMOKE_COMMAND,
        ],
        capture_output=True,
        timeout=SMOKE_TIMEOUT,
    )
    if result.returncode != 0:
        raise ValueError("installed-package-smoke-failed")
    decision = json.loads(result.stdout)
    if decision.get("release_decision") != "pass" or decision.get("release_eligible") is not False:
        raise ValueError("installed-package-smoke-unexpected-result")
    return {"release_decision": decision["release_decision"]}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        with tempfile.TemporaryDirectory(prefix="gate-distribution-audit-") as scratch:
            scratch_path = Path(scratch)
            source_dir = scratch_path / "source"
            source_dir.mkdir()
            clean_export(root, source_dir)

            out_dir = scratch_path / "dist"
            out_dir.mkdir()
            wheel_path, sdist_path = build_distributions(source_dir, out_dir)
            wheel_contents = extract_wheel(wheel_path)
            sdist_contents = extract_sdist(sdist_path)
            findings = scan_contents(wheel_contents) + scan_contents(sdist_contents)

            rebuilt_dir = scratch_path / "from-sdist"
            rebuilt_dir.mkdir()
            rebuilt_wheel = build_wheel_from_sdist(sdist_path, rebuilt_dir)
            sdist_is_self_contained = set(wheel_contents) == set(extract_wheel(rebuilt_wheel))

            smoke = installed_smoke_check(wheel_path)

        report = {
            "wheel_files_scanned": len(wheel_contents),
            "sdist_files_scanned": len(sdist_contents),
            "findings": [finding._asdict() for finding in findings],
            "sdist_is_self_contained": sdist_is_self_contained,
            "installed_package_smoke": smoke,
        }
        print(json.dumps(report, indent=2))
        return 1 if findings or not sdist_is_self_contained else 0
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        # Never expose raw build/subprocess output, environment paths or archive contents.
        print(json.dumps({"error": "distribution-audit-could-not-complete"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
