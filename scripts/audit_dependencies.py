"""Audit every applicable locked runtime/dev dependency; fail closed on audit gaps."""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def summarize(report: object, expected: set[str]) -> tuple[int, dict[str, object]]:
    if (
        not isinstance(report, dict)
        or not isinstance(report.get("dependencies"), list)
        or not expected
    ):
        return 2, {"error": "dependency-audit-incomplete"}
    scanned = set()
    vulnerable = []
    gaps = 0
    for dependency in report["dependencies"]:
        if not isinstance(dependency, dict) or not isinstance(dependency.get("name"), str):
            gaps += 1
            continue
        name = canonicalize_name(dependency["name"])
        if not re.fullmatch(r"[a-z0-9_.-]+", name):
            gaps += 1
            continue
        if dependency.get("skip_reason") or not isinstance(dependency.get("vulns"), list):
            gaps += 1
            continue
        scanned.add(name)
        for vulnerability in dependency["vulns"]:
            identity = vulnerability.get("id", "") if isinstance(vulnerability, dict) else ""
            if not re.fullmatch(r"(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+|PYSEC-[0-9-]+)", identity):
                identity = "unclassified-advisory"
            vulnerable.append({"package": name, "advisory": identity})
    gaps += len(expected - scanned)
    summary = {
        "dependencies_scanned": len(scanned),
        "audit_gaps": gaps,
        "vulnerabilities": vulnerable,
    }
    return (2 if gaps else 1 if vulnerable else 0), summary


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="dependency-audit-") as temporary:
        requirements = Path(temporary) / "requirements.txt"
        report_path = Path(temporary) / "report.json"
        try:
            export = subprocess.run(
                [
                    "uv",
                    "export",
                    "--frozen",
                    "--no-emit-project",
                    "--no-hashes",
                    "--format",
                    "requirements-txt",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if export.returncode:
                raise ValueError("locked export failed")
            requirements.write_text(export.stdout)
            expected = set()
            for line in export.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                requirement = Requirement(line)
                if requirement.marker is None or requirement.marker.evaluate():
                    expected.add(canonicalize_name(requirement.name))
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
