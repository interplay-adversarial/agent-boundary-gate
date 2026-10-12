"""RustSec audit of the probe lockfile; compiler/stdlib/image CVEs are separate."""

import json
import re
import subprocess
import tomllib
from datetime import UTC, datetime, timedelta

from scripts.rust_probe_build import PROBE, ROOT, validate_dependency_scope

AUDITOR_VERSION = "0.22.2"


def validate_report(value: dict, *, now: datetime) -> None:
    database = value["database"]
    vulnerabilities = value["vulnerabilities"]
    settings = value["settings"]
    updated = datetime.fromisoformat(database["last-updated"])
    if (
        type(database["advisory-count"]) is not int
        or database["advisory-count"] <= 0
        or not re.fullmatch(r"[0-9a-f]{40}", database["last-commit"])
        or updated.utcoffset() is None
        or not timedelta(0) <= now - updated <= timedelta(days=7)
        or type(value["lockfile"]["dependency-count"]) is not int
        or value["lockfile"]["dependency-count"] != 1
        or settings["ignore"] != []
        or settings["target_arch"] != []
        or settings["target_os"] != []
        or settings["severity"] is not None
        or sorted(settings["informational_warnings"]) != ["notice", "unmaintained", "unsound"]
        or type(vulnerabilities["found"]) is not bool
        or type(vulnerabilities["count"]) is not int
        or not isinstance(vulnerabilities["list"], list)
        or vulnerabilities["count"] != len(vulnerabilities["list"])
        or vulnerabilities["found"] != bool(vulnerabilities["list"])
        or not isinstance(value["warnings"], dict)
    ):
        raise ValueError("rust-audit-coverage-invalid")


def audit() -> tuple[dict, int]:
    report = {
        "scope": "rust-lockfile-only",
        "third_party_dependencies": 0,
        "compiler_stdlib_image_cve_coverage": False,
        "release_eligible": False,
    }
    try:
        validate_dependency_scope(
            tomllib.loads((PROBE / "Cargo.toml").read_text()),
            tomllib.loads((PROBE / "Cargo.lock").read_text()),
        )
        version = subprocess.run(
            ["cargo", "audit", "--version"], cwd=ROOT, capture_output=True, timeout=10
        )
        tokens = version.stdout.decode().strip().split()
        if (
            version.returncode
            or len(tokens) != 2
            or tokens[0] not in {"cargo-audit", "cargo-audit-audit"}
            or tokens[1] != AUDITOR_VERSION
        ):
            raise ValueError("rust-auditor-pin-mismatch")
        result = subprocess.run(
            ["cargo", "audit", "--file", str(PROBE / "Cargo.lock"), "--json", "--deny", "warnings"],
            cwd=ROOT,
            capture_output=True,
            timeout=180,
        )
        if len(result.stdout) > 1024 * 1024:
            raise ValueError("rust-audit-output-limit")
        value = json.loads(result.stdout)
        validate_report(value, now=datetime.now(UTC))
        report["advisories"] = sorted(
            {
                item["advisory"]["id"]
                for item in value["vulnerabilities"]["list"]
                if re.fullmatch(r"RUSTSEC-[0-9]{4}-[0-9]{4}", item["advisory"]["id"])
            }
        )
        report["warning_categories"] = sorted(
            key for key in value["warnings"] if re.fullmatch(r"[a-z_-]{1,50}", key)
        )
        report["status"] = (
            "failed"
            if result.returncode or value["vulnerabilities"]["found"] or value["warnings"]
            else "passed"
        )
        return report, 1 if report["status"] == "failed" else 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        report["status"] = "incomplete"
        report["error"] = "rust-probe-audit-could-not-complete"
        return report, 2


def main() -> int:
    report, code = audit()
    print(json.dumps(report, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
