"""Audit every applicable locked runtime/dev dependency; fail closed on audit gaps."""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


def locked_dependencies(export: str, *, marker_environment=None) -> dict[str, Version]:
    """Resolve applicable exact pins; reject ambiguous or unpinned audit inputs."""
    expected: dict[str, Version] = {}
    for line in export.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        if requirement.marker is not None and not requirement.marker.evaluate(marker_environment):
            continue
        pins = list(requirement.specifier)
        if requirement.url or len(pins) != 1 or pins[0].operator != "==":
            raise ValueError("audit requires exact locked versions")
        version = Version(pins[0].version)
        name = canonicalize_name(requirement.name)
        if name in expected and expected[name] != version:
            raise ValueError("conflicting applicable locked versions")
        expected[name] = version
    if not expected:
        raise ValueError("empty applicable dependency inventory")
    return expected


def summarize(report: object, expected: dict[str, Version]) -> tuple[int, dict[str, object]]:
    if (
        not isinstance(report, dict)
        or not isinstance(report.get("dependencies"), list)
        or not expected
    ):
        return 2, {"error": "dependency-audit-incomplete"}
    # Count names before validating rows: every record for a duplicated package
    # is untrusted, even if one row has the correct version or occurs first.
    name_counts = Counter(
        canonicalize_name(dependency["name"])
        for dependency in report["dependencies"]
        if isinstance(dependency, dict) and isinstance(dependency.get("name"), str)
    )
    scanned: set[str] = set()
    verified_advisories: set[tuple[str, str]] = set()
    unverified_advisories: set[tuple[str, str]] = set()
    gaps = 0
    for dependency in report["dependencies"]:
        if not isinstance(dependency, dict) or not isinstance(dependency.get("name"), str):
            gaps += 1
            continue
        name = canonicalize_name(dependency["name"])
        if not re.fullmatch(r"[a-z0-9_.-]+", name):
            gaps += 1
            continue
        try:
            version = Version(dependency["version"])
        except (KeyError, TypeError, InvalidVersion):
            version = None
        accepted = (
            name_counts[name] == 1
            and name in expected
            and version == expected[name]
            and not dependency.get("skip_reason")
            and isinstance(dependency.get("vulns"), list)
        )
        if accepted:
            scanned.add(name)
        else:
            gaps += 1
        if not isinstance(dependency.get("vulns"), list):
            continue
        # Keep rejected-record advisories visible without presenting them as
        # verified findings. Neither list can override an incomplete audit.
        advisories = verified_advisories if accepted else unverified_advisories
        for vulnerability in dependency["vulns"]:
            identity = vulnerability.get("id", "") if isinstance(vulnerability, dict) else ""
            if not isinstance(identity, str) or not re.fullmatch(
                r"(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+|PYSEC-[0-9-]+)", identity
            ):
                identity = "unclassified-advisory"
            advisories.add((name, identity))
    gaps += len(expected.keys() - scanned)
    summary = {
        "dependencies_scanned": len(scanned),
        "audit_gaps": gaps,
        "vulnerabilities": [
            {"package": name, "advisory": identity}
            for name, identity in sorted(verified_advisories)
        ],
        "unverified_vulnerabilities": [
            {"package": name, "advisory": identity}
            for name, identity in sorted(unverified_advisories)
        ],
    }
    return (2 if gaps else 1 if verified_advisories else 0), summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    optional = parser.add_mutually_exclusive_group()
    optional.add_argument("--gym", action="store_true", help="audit the separate pinned Gym lock")
    optional.add_argument(
        "--hermes", action="store_true", help="audit the separate Hermes pilot lock"
    )
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    if args.gym:
        project = project / "onboarding/gym"
    elif args.hermes:
        project = project / "onboarding/hermes"
    with tempfile.TemporaryDirectory(prefix="dependency-audit-") as temporary:
        requirements = Path(temporary) / "requirements.txt"
        report_path = Path(temporary) / "report.json"
        try:
            export = subprocess.run(
                [
                    "uv",
                    "export",
                    "--frozen",
                    "--all-groups",
                    "--no-emit-project",
                    "--no-hashes",
                    "--format",
                    "requirements-txt",
                ]
                + (["--no-emit-package", "nemo-gym"] if args.gym or args.hermes else [])
                + (["--no-emit-package", "hermes-agent"] if args.hermes else []),
                capture_output=True,
                text=True,
                timeout=120,
                cwd=project,
            )
            if export.returncode:
                raise ValueError("locked export failed")
            # Gym's selected interpreter differs from the core's supported range.
            # Filter marker branches for that interpreter before invoking an auditor
            # running in the core environment; otherwise it could scan wrong pins.
            environment = (
                {"python_version": "3.13", "python_full_version": "3.13.14"}
                if args.gym or args.hermes
                else None
            )
            expected = locked_dependencies(export.stdout, marker_environment=environment)
            requirements.write_text(
                "\n".join(f"{name}=={version}" for name, version in sorted(expected.items())) + "\n"
            )
            audit = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip_audit",
                    "--requirement",
                    str(requirements),
                    "--no-deps",
                    "--disable-pip",
                    "--strict",
                    "--progress-spinner",
                    "off",
                    "--format",
                    "json",
                    "--output",
                    str(report_path),
                    "--timeout",
                    "30",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if audit.returncode not in (0, 1) or not report_path.exists():
                raise ValueError("advisory audit did not complete")
            status, summary = summarize(json.loads(report_path.read_text()), expected)
            if audit.returncode and status == 0:
                raise ValueError("advisory audit returned inconsistent status")
            print(json.dumps(summary, indent=2))
            return status
        except (OSError, ValueError, subprocess.TimeoutExpired):
            # Do not expose raw CLI output, environment paths, private indexes or credentials.
            print(json.dumps({"error": "dependency-audit-could-not-complete"}))
            return 2


if __name__ == "__main__":
    raise SystemExit(main())
