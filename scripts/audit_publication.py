"""Audit publication inputs without printing matched values. Complements Gitleaks."""

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit


class Finding(NamedTuple):
    path: str
    line: int
    rule: str


PUBLIC_HOSTS = {
    "github.com",
    "raw.githubusercontent.com",
    "api.github.com",
    "pypi.org",
    "files.pythonhosted.org",
    "www.apache.org",
    "doc.rust-lang.org",
    "apache.org",
    "localhost",
    "127.0.0.1",
    "::1",  # IPv6 loopback, like the synthetic IPv4 receiver above.
    "receiver",
    "example.com",
}
PATTERNS = {
    "absolute-user-path": re.compile(r"/(?:Users|home)/[A-Za-z0-9_.-]+/"),
    "workstation-temporary-path": re.compile(r"/(?:private/)?var/folders/"),
    "private-ip-address": re.compile(
        r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b"
    ),
    "private-key-material": re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    "ssh-public-key-material": re.compile(r"\bssh-(?:rsa|ed25519)\s+[A-Za-z0-9+/]{40,}"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "cloud-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "corporate-email": re.compile(r"\b[A-Za-z0-9._%+-]+@redhat\.com\b", re.I),
    "internal-issue-reference": re.compile(r"\b(?:RHAIRFE|RHAISTRAT)-\d+\b"),
    "internal-content-marker": re.compile(r"<!--\s*RHAI-INTERNAL\s*-->"),
}
URL = re.compile(r"https?://[^\s<>\"'`]+")
PRIVATE_PARTS = {".venv", "artifacts", ".aws", ".kube", ".private", "secrets", "results", "output"}
PRIVATE_SUFFIXES = {
    ".key",
    ".pem",
    ".pub",
    ".p12",
    ".pfx",
    ".keystore",
    ".bin",
    ".log",
    ".jsonl",
    ".db",
    ".sqlite3",
}


def audit_blob(path: str, data: bytes, denied_tokens: tuple[str, ...] = ()) -> list[Finding]:
    file = Path(path)
    findings = []
    if (
        set(file.parts) & PRIVATE_PARTS
        or file.suffix.lower() in PRIVATE_SUFFIXES
        or any(marker in file.name for marker in (".sqlite3-", ".db-"))
        or file.name.startswith((".env", "kubeconfig", "credentials", "id_rsa", "id_ed25519"))
    ):
        findings.append(Finding(path, 0, "private-or-credential-file"))
    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError:
        return findings + [Finding(path, 0, "non-text-publication-input")]
    for line_number, line in enumerate(content.splitlines(), 1):
        for rule, expression in PATTERNS.items():
            if expression.search(line):
                findings.append(Finding(path, line_number, rule))
        if any(token.lower() in line.lower() for token in denied_tokens):
            findings.append(Finding(path, line_number, "operator-denylist"))
        for match in URL.finditer(line):
            try:
                candidate = re.sub(r"\{[^}]*\}", "placeholder", match.group())
                parsed = urlsplit(candidate.rstrip(".,);"))
                if parsed.username or parsed.password:
                    findings.append(Finding(path, line_number, "embedded-url-credentials"))
                if parsed.hostname and parsed.hostname not in PUBLIC_HOSTS:
                    findings.append(Finding(path, line_number, "url-host-not-public-reference"))
            except ValueError:
                findings.append(Finding(path, line_number, "invalid-url-publication-input"))
    return findings


def index_inputs(root: Path) -> list[tuple[str, bytes]]:
    inventory = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=root)
    inputs = []
    for entry in inventory.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, object_id, stage = metadata.decode().split()
        relative = name.decode()
        if mode not in {"100644", "100755"} or stage != "0":
            raise ValueError("symlink, submodule or unmerged publication input")
        data = subprocess.check_output(["git", "cat-file", "blob", object_id], cwd=root)
        inputs.append((relative, data))
    if not inputs:
        raise ValueError("empty publication index")
    return inputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deny-file", type=Path, help="private operator denylist; never commit it")
    parser.add_argument("--directory", type=Path, help="audit an exported publication tree")
    args = parser.parse_args()
    try:
        denied = tuple(json.loads(args.deny_file.read_text())) if args.deny_file else ()
        if not all(isinstance(token, str) and token for token in denied):
            raise ValueError("invalid denylist")
        if args.directory:
            inputs = []
            for path in sorted(args.directory.rglob("*")):
                if path.is_symlink():
                    raise ValueError("symlink publication input")
                if path.is_file():
                    inputs.append((str(path.relative_to(args.directory)), path.read_bytes()))
            if not inputs:
                raise ValueError("empty publication tree")
        else:
            inputs = index_inputs(Path.cwd())
        findings = [finding for path, data in inputs for finding in audit_blob(path, data, denied)]
        print(
            json.dumps(
                {"files_scanned": len(inputs), "findings": [f._asdict() for f in findings]},
                indent=2,
            )
        )
        return 1 if findings else 0
    except (OSError, ValueError, subprocess.CalledProcessError):
        print(json.dumps({"error": "publication-audit-could-not-complete"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
