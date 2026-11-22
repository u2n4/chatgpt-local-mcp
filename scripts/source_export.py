"""Select, refresh and hash the publishable Edge Project Bridge source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 5 * 1024 * 1024

# Machine-specific defaults, identities and historical references are revised in
# these export files. Review upstream changes to these paths separately.
OVERRIDES = frozenset({
    ".cargo/config.toml", ".gitignore", ".gitattributes", "AGENTS.md", "README.md",
    "adapters/hardware/telemetry_profile.py", "docs/BUILD_AND_TEST.md",
    "docs/adr/0001-rust-core-and-incremental-migration.md",
    "scripts/canary-v040-rehearsal.ps1", "scripts/run_v040_vertical_slice.py",
    "scripts/run_audit_security_and_mcp.py",
    "release/v0.4.0/SBOM-summary.json", "release/v0.4.0/THIRD_PARTY_NOTICES.txt",
})
EXPORT_ONLY = frozenset({
    "CHANGELOG.md", "docs/RELEASE_SCOPE.md", "docs/V0.5.0_ARCHITECTURE.md",
    "docs/REMOTE_EXECUTOR.md", "docs/KNOWN_LIMITATIONS.md", "scripts/source_export.py",
})
EXACT_SOURCE = frozenset({
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "pyproject.toml", "uv.lock",
    "LICENSE", "COPYING", "SECURITY_BOUNDARIES.md",
    "apps/bridgepulse/package.json", "apps/bridgepulse/package-lock.json",
    "apps/bridgepulse/index.html", "apps/bridgepulse/tsconfig.json",
    "apps/bridgepulse/vite.config.ts", "docs/ARCHITECTURE.md",
    "docs/SECURITY_AND_PERMISSIONS.md", "docs/TOOL_CAPABILITIES.md",
    "docs/adr/0002-dual-mcp-protocol-compatibility.md",
    "docs/adr/0003-verifiable-evidence-and-verdicts.md",
})

SKIP_LOCAL_DIRS = {
    ".git", ".venv", "__pycache__", ".pytest_cache", "target", "node_modules",
    "dist", "evidence-bundle", "raw", "runtime",
}
PRIVATE_TEXT = {
    "local Windows machine identifier": re.compile(r"\bDESKTOP-[A-Z0-9]{7}\b"),
    "user home path": re.compile(r"(?i)(?:[a-z]:[/\\]+users[/\\]+|(?:/home|/Users)/)[a-z0-9._-]+"),
    "private conversation": re.compile(r"(?i)chatgpt\.com/(?:c|share)/[0-9a-f-]{32,}"),
    "private remote host": re.compile(r"(?i)https?://[^\s/]+\.(?:ts\.net|trycloudflare\.com|ngrok(?:-free)?\.app)"),
    "dated local backup": re.compile(r"(?i)\bpre-v[0-9]+-baseline-\d+"),
}


def clean_relative(path: str) -> PurePosixPath:
    relative = PurePosixPath(path)
    if not relative.parts or str(relative) != path or relative.is_absolute() or any(
        part == ".." or not re.fullmatch(r"[A-Za-z0-9_.-]+", part)
        for part in relative.parts
    ):
        raise ValueError(f"Unexpected source path syntax: {path!r}")
    return relative


def in_scope(relative: PurePosixPath) -> bool:
    path = relative.as_posix()
    top = relative.parts[0]
    ext = relative.suffix.lower()
    if path in EXACT_SOURCE or path in OVERRIDES or path in EXPORT_ONLY:
        return True
    if any(part in SKIP_LOCAL_DIRS for part in relative.parts):
        return False
    if top == "crates":
        return ext in {".rs", ".py"} or relative.name == "Cargo.toml"
    if top in {"adapters", "benchmarks", "compat", "edge_bridge", "tests"}:
        return ext == ".py"
    if top == "examples":
        return ext == ".py" or path == "examples/bridgepulse-lab/fixtures/synthetic_airspeed_dataset.csv"
    if top == "scripts":
        return ext in {".py", ".ps1", ".mjs"}
    if top == "schemas":
        return ext == ".json" and relative.name != "v0.2.0-source-manifest.json"
    if top == "migrations":
        return ext == ".sql"
    if path.startswith("apps/bridgepulse/src/"):
        return ext in {".css", ".svelte", ".ts"}
    return False


def check_regular(path: Path, *, directory: bool = False) -> None:
    item = path.lstat()
    is_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not is_type(item.st_mode) or (
        getattr(item, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError(f"Nonregular source component: {path.name}")
    if not directory and (item.st_nlink != 1 or item.st_size > MAX_BYTES):
        raise ValueError(f"Hardlink or oversized source file: {path.name}")


def read_regular(root: Path, relative: PurePosixPath) -> bytes:
    item = root
    for index, part in enumerate(relative.parts):
        item = item / part
        check_regular(item, directory=index < len(relative.parts) - 1)
    return item.read_bytes()


def source_paths(source: Path) -> list[PurePosixPath]:
    result = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "--show-toplevel"],
        check=True, capture_output=True, encoding="utf-8",
    )
    if Path(result.stdout.strip()).resolve(strict=True) != source:
        raise ValueError("Refresh source must be the root of the development checkout.")
    result = subprocess.run(
        ["git", "-C", str(source), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        check=True, capture_output=True,
    )
    git_paths = set(result.stdout.decode("utf-8").split("\0")) - {""}
    return [p for name in sorted(git_paths) if in_scope(p := clean_relative(name))]


def refresh(source: Path) -> int:
    source = source.resolve(strict=True)
    if source == ROOT or source in ROOT.parents or ROOT in source.parents:
        raise ValueError("Source and export must be distinct, non-overlapping checkouts.")
    count = 0
    for relative in source_paths(source):
        name = relative.as_posix()
        if name in EXPORT_ONLY or name in OVERRIDES:
            continue
        destination = ROOT.joinpath(*relative.parts)
        payload = read_regular(source, relative)
        parent = ROOT
        for part in relative.parts[:-1]:
            parent = parent / part
            parent.mkdir(exist_ok=True)
            check_regular(parent, directory=True)
        if destination.exists() or destination.is_symlink():
            check_regular(destination)
            if destination.read_bytes() == payload:
                continue
        destination.write_bytes(payload)
        count += 1
    return count


def verify(markers: list[str]) -> list[dict[str, int | str]]:
    inventory = []
    findings = []
    for base, dirs, files in os.walk(ROOT):
        base_path = Path(base)
        for dirname in dirs[:]:
            if dirname in SKIP_LOCAL_DIRS:
                dirs.remove(dirname)
            else:
                check_regular(base_path / dirname, directory=True)
        for filename in files:
            relative = clean_relative((base_path / filename).relative_to(ROOT).as_posix())
            name = relative.as_posix()
            if not in_scope(relative):
                findings.append(f"{name}: path outside source allowlist")
                continue
            payload = read_regular(ROOT, relative)
            try:
                content = payload.decode("utf-8-sig")
            except UnicodeDecodeError:
                findings.append(f"{name}: not UTF-8 source")
                continue
            if "\0" in content:
                findings.append(f"{name}: binary content in source")
                continue
            for label, pattern in PRIVATE_TEXT.items():
                if match := pattern.search(content):
                    line = content.count("\n", 0, match.start()) + 1
                    findings.append(f"{name}:{line}: {label}")
            folded = content.casefold()
            for marker in markers:
                offset = folded.find(marker)
                if offset != -1:
                    line = folded.count("\n", 0, offset) + 1
                    findings.append(f"{name}:{line}: local deny marker")
            inventory.append({
                "path": name,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
    if findings:
        raise ValueError("Source scope findings:\n" + "\n".join(findings))
    return sorted(inventory, key=lambda item: item["path"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    refresher = sub.add_parser("refresh", help="copy allowlisted files from a development worktree")
    refresher.add_argument("source", type=Path)
    manifest = sub.add_parser("manifest", help="emit JSON with hashes after checking source scope")
    manifest.add_argument("--reject-markers", type=Path, help="local deny markers, one per line")
    args = parser.parse_args()
    try:
        if args.command == "refresh":
            refreshed = refresh(args.source)
            print(f"Refreshed {refreshed} files. Re-run manifest and secret scanning.")
        else:
            markers = args.reject_markers.read_text(encoding="utf-8-sig").splitlines() if args.reject_markers else []
            inventory = verify([value.strip().casefold() for value in markers if value.strip()])
            print(json.dumps({"file_count": len(inventory), "files": inventory}, indent=2))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
