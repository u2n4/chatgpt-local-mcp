"""Stage 9 Reproducible Canary Release Packager (§17, §20).
Creates checksums, SBOM summary from Cargo.lock + uv.lock + package-lock.json,
and release-manifest.json WITHOUT claiming production cutover or embedding secrets.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "release" / "v0.4.0"


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def git_head() -> str:
    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=True)
    return proc.stdout.strip()


def collect_sbom() -> dict:
    rust_pkgs = []
    cargo_lock = REPO / "Cargo.lock"
    if cargo_lock.is_file():
        data = tomllib.loads(cargo_lock.read_text(encoding="utf-8"))
        for pkg in data.get("package", []):
            rust_pkgs.append({
                "name": pkg.get("name"),
                "version": pkg.get("version"),
                "source": pkg.get("source", "workspace"),
            })
    py_pkgs = []
    uv_lock = REPO / "uv.lock"
    if uv_lock.is_file():
        data = tomllib.loads(uv_lock.read_text(encoding="utf-8"))
        for pkg in data.get("package", []):
            py_pkgs.append({"name": pkg.get("name"), "version": pkg.get("version")})

    npm_pkgs = []
    pkg_lock = REPO / "apps" / "bridgepulse" / "package-lock.json"
    if pkg_lock.is_file():
        data = json.loads(pkg_lock.read_text(encoding="utf-8"))
        for k, v in (data.get("packages") or {}).items():
            if k:
                npm_pkgs.append({"path": k, "version": v.get("version"), "license": v.get("license")})

    return {
        "sbom_format": "edge-bridge-sbom-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rust_crates_count": len(rust_pkgs),
        "python_packages_count": len(py_pkgs),
        "npm_dev_packages_count": len(npm_pkgs),
        "rust_crates": rust_pkgs,
        "python_packages": py_pkgs,
        "npm_dev_packages": npm_pkgs,
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    exe = REPO / "target" / "x86_64-pc-windows-gnullvm" / "release" / "edge-bridge.exe"
    if not exe.is_file():
        raise FileNotFoundError(f"Release binary missing: {exe}")

    files_to_hash: list[Path] = [
        exe,
        REPO / "Cargo.toml",
        REPO / "Cargo.lock",
        REPO / "rust-toolchain.toml",
        REPO / "pyproject.toml",
        REPO / "uv.lock",
    ]
    for sub in ("migrations", "schemas"):
        d = REPO / sub
        if d.is_dir():
            files_to_hash.extend(sorted(p for p in d.rglob("*") if p.is_file()))
    dist_dir = REPO / "apps" / "bridgepulse" / "dist"
    if dist_dir.is_dir():
        files_to_hash.extend(sorted(p for p in dist_dir.rglob("*") if p.is_file()))

    artifacts = []
    checksum_lines = []
    for f in files_to_hash:
        rel = f.relative_to(REPO).as_posix()
        digest = sha256_file(f)
        artifacts.append({"path": rel, "size_bytes": f.stat().st_size, "sha256": digest})
        checksum_lines.append(f"{digest}  {rel}")

    sbom = collect_sbom()
    sbom_path = OUT / "SBOM-summary.json"
    sbom_path.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")

    (OUT / "SHA256SUMS.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    (OUT / "THIRD_PARTY_NOTICES.txt").write_text(
        "Edge Project Bridge V0.4.0 Third-Party Dependency Summary\n"
        f"Rust crates (locked in Cargo.lock): {sbom['rust_crates_count']}\n"
        f"Python packages (locked in uv.lock): {sbom['python_packages_count']}\n"
        f"BridgePulse build packages (locked in apps/bridgepulse/package-lock.json): {sbom['npm_dev_packages_count']}\n"
        "See SBOM-summary.json for complete package names and versions.\n",
        encoding="utf-8",
    )

    manifest = {
        "release_version": "0.4.0-canary",
        "production_deployed": False,
        "cutover_status": "AWAITING_OWNER_AUTHORIZATION",
        "built_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_commit": git_head(),
        "rust_target": "x86_64-pc-windows-gnullvm",
        "rust_toolchain": "1.100.0",
        "binary": {
            "path": exe.relative_to(REPO).as_posix(),
            "size_bytes": exe.stat().st_size,
            "sha256": sha256_file(exe),
        },
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }
    (OUT / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "release_dir": str(OUT),
        "binary_size_mb": round(exe.stat().st_size / (1024 * 1024), 2),
        "binary_sha256": manifest["binary"]["sha256"],
        "artifact_count": len(artifacts),
        "rust_crates": sbom["rust_crates_count"],
    }, indent=2))


if __name__ == "__main__":
    main()
