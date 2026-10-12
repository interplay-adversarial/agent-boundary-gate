"""Build/check an independently pinned experimental probe; never publish artifacts."""

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import tomllib
from pathlib import Path

from scripts.audit_publication import PATTERNS, audit_blob

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "probes/http"
TARGETS = {"x86_64-unknown-linux-musl": 62, "aarch64-unknown-linux-musl": 183}
SOURCE_FILES = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "protocol-v1.json",
    "src/main.rs",
)


def command(argv: list[str], *, env=None, limit=1024 * 1024) -> bytes:
    result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, timeout=180)
    if result.returncode or len(result.stdout) > limit or len(result.stderr) > limit:
        raise ValueError("rust-probe-command-failed")
    return result.stdout


def validate_dependency_scope(manifest: dict, lock: dict) -> None:
    if any(
        manifest.get(key)
        for key in ("dependencies", "dev-dependencies", "build-dependencies", "target", "workspace")
    ):
        raise ValueError("rust-probe-dependency-review-required")
    package = manifest["package"]
    if package["name"] != "gate-http-probe" or lock.get("package") != [
        {"name": package["name"], "version": package["version"]}
    ]:
        raise ValueError("rust-probe-dependency-review-required")


def inspect_static_elf(raw: bytes, target: str) -> None:
    """Reject foreign, malformed, interpreted or dynamically linked ELF artifacts."""
    if (
        len(raw) < 64
        or raw[:6] != b"\x7fELF\x02\x01"
        or raw[6] != 1
        or struct.unpack_from("<H", raw, 16)[0] not in (2, 3)
        or struct.unpack_from("<H", raw, 18)[0] != TARGETS[target]
    ):
        raise ValueError("rust-probe-elf-invalid")
    offset = struct.unpack_from("<Q", raw, 32)[0]
    size, count = struct.unpack_from("<HH", raw, 54)
    if size != 56 or not 0 < count <= 128 or offset + size * count > len(raw):
        raise ValueError("rust-probe-elf-invalid")
    for index in range(count):
        kind, _, _, _, _, length, _, _ = struct.unpack_from("<IIQQQQQQ", raw, offset + size * index)
        segment = struct.unpack_from("<Q", raw, offset + size * index + 8)[0]
        if segment + length > len(raw):
            raise ValueError("rust-probe-elf-invalid")
        if kind == 3:  # PT_INTERP
            raise ValueError("rust-probe-dynamic-linkage")
        if kind == 2:  # PT_DYNAMIC: static PIE can have a dynamic section, but no DT_NEEDED.
            if length % 16:
                raise ValueError("rust-probe-elf-invalid")
            for entry in range(segment, segment + length, 16):
                if struct.unpack_from("<q", raw, entry)[0] == 1:
                    raise ValueError("rust-probe-dynamic-linkage")


def artifact_privacy(raw: bytes) -> None:
    # Deliberately do not export matched strings or binary data.
    for pattern in PATTERNS.values():
        byte_pattern = re.compile(pattern.pattern.encode("ascii"), pattern.flags & ~re.UNICODE)
        if byte_pattern.search(raw):
            raise ValueError("rust-probe-artifact-privacy-failed")
    # Latin-1 preserves every byte. UTF-16 views cover either endian/alignment;
    # replacement characters retain invalid boundaries instead of deleting them.
    views = [raw.decode("latin-1"), raw.decode("utf-8", errors="replace")]
    for encoding in ("utf-16-le", "utf-16-be"):
        views.extend(raw[offset:].decode(encoding, errors="replace") for offset in (0, 1))
    for view in views:
        # NUL/control bytes separate binary strings; don't merge adjacent strings
        # into a fictitious URL hostname when applying the text publication rules.
        text = "\n".join(re.findall(r"[\x20-\x7e]{5,}", view)).encode()
        if audit_blob("probe-strings.txt", text):
            raise ValueError("rust-probe-artifact-privacy-failed")


def build(*, target: str | None = None, check: bool = False) -> dict:
    manifest = tomllib.loads((PROBE / "Cargo.toml").read_text())
    lock = tomllib.loads((PROBE / "Cargo.lock").read_text())
    validate_dependency_scope(manifest, lock)
    expected = tomllib.loads((PROBE / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    compiler = command(["rustc", "-vV"], limit=4096).decode()
    fields = dict(line.split(": ", 1) for line in compiler.splitlines() if ": " in line)
    if fields.get("release") != expected:
        raise ValueError("rust-probe-toolchain-pin-mismatch")
    if not re.fullmatch(r"[0-9a-f]{40}", fields.get("commit-hash", "")):
        raise ValueError("rust-probe-toolchain-invalid")
    host = fields["host"]
    if not re.fullmatch(r"[a-z0-9_-]{1,100}", host):
        raise ValueError("rust-probe-toolchain-invalid")
    cargo = command(["cargo", "--version"], limit=4096).decode().split()
    if len(cargo) < 2 or cargo[1] != expected:
        raise ValueError("rust-probe-toolchain-pin-mismatch")
    if target is not None and target not in TARGETS:
        raise ValueError("rust-probe-target-unsupported")
    env = dict(os.environ)
    for key in (
        "RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTC",
        "CARGO_BUILD_RUSTC",
    ):
        env.pop(key, None)
    flags = [f"--remap-path-prefix={ROOT}=/agent-boundary-gate"]
    if target:
        flags += ["-C", "target-feature=+crt-static"]
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
    env["CARGO_TARGET_DIR"] = str(PROBE / "target")
    args = ["--manifest-path", str(PROBE / "Cargo.toml"), "--locked", "--offline"]
    target_args = ["--target", target] if target else []
    if check:
        command(
            ["cargo", "fmt", "--manifest-path", str(PROBE / "Cargo.toml"), "--", "--check"], env=env
        )
        command(
            ["cargo", "clippy", *args, *target_args, "--all-targets", "--", "-D", "warnings"],
            env=env,
        )
        command(["cargo", "test", *args, *target_args, "--all-targets"], env=env)
    command(
        ["cargo", "build", *args, *target_args, "--release", "--bin", "gate-http-probe"], env=env
    )
    folder = PROBE / "target" / target / "release" if target else PROBE / "target/release"
    raw = (folder / "gate-http-probe").read_bytes()
    if not 0 < len(raw) <= 16 * 1024 * 1024:
        raise ValueError("rust-probe-artifact-size-invalid")
    if target:
        inspect_static_elf(raw, target)
    artifact_privacy(raw)
    for name in ("LICENSE", "NOTICE"):
        data = (ROOT / name).read_bytes()
        if audit_blob(name, data):
            raise ValueError("rust-probe-artifact-privacy-failed")
        (folder / name).write_bytes(data)
    source = hashlib.sha256()
    for name in SOURCE_FILES:
        data = (PROBE / name).read_bytes()
        source.update(name.encode() + b"\0" + len(data).to_bytes(8, "big") + data)
    dirty = bool(command(["git", "status", "--porcelain", "--untracked-files=normal"]))
    commit = command(["git", "rev-parse", "HEAD"]).decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("rust-probe-source-state-invalid")
    report = {
        "status": "experimental-build",
        "package_version": manifest["package"]["version"],
        "protocol": "agent-boundary-gate/http-probe/1.0",
        "protocol_digest": "sha256:"
        + hashlib.sha256((PROBE / "protocol-v1.json").read_bytes()).hexdigest(),
        "source_digest": "sha256:" + source.hexdigest(),
        "source_commit": None if dirty else commit,
        "source_dirty": dirty,
        "compiler_version": expected,
        "compiler_commit": fields["commit-hash"],
        "target": target or host,
        "static_elf_verified": target is not None,
        "binary_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "artifact_privacy": "passed",
        "third_party_dependencies": 0,
        "live_qualified": False,
        "release_eligible": False,
    }
    (folder / "gate-http-probe.provenance.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=sorted(TARGETS))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(build(target=args.target, check=args.check), indent=2))
        return 0
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        print(json.dumps({"error": "rust-probe-build-or-check-failed", "release_eligible": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
