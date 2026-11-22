"""Python transition compatibility wrapper delegating read/diagnostic/evidence parity checks
to the compiled Rust `edge-bridge.exe` binary without creating dual SQLite writers (§4.2, §17).
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any


def find_rust_binary(repo_root: Path | None = None) -> Path | None:
    root = repo_root or Path(__file__).resolve().parents[2]
    candidates = [
        root / "target" / "x86_64-pc-windows-gnullvm" / "release" / "edge-bridge.exe",
        root / "target" / "x86_64-pc-windows-gnullvm" / "debug" / "edge-bridge.exe",
        root / "target" / "release" / "edge-bridge.exe",
        root / "target" / "debug" / "edge-bridge.exe",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def invoke_rust_cli(
    args: list[str],
    *,
    state_dir: Path | None = None,
    repo_root: Path | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    binary = find_rust_binary(repo_root)
    if binary is None:
        raise FileNotFoundError("Compiled Rust edge-bridge.exe not found; build with cargo first.")
    cmd = [str(binary)]
    if state_dir is not None:
        cmd.extend(["--state-dir", str(state_dir)])
    cmd.extend(args)
    proc = subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        encoding="utf-8",
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"edge-bridge exited {proc.returncode}: {proc.stderr.strip() or proc.stdout.strip()}")
    return json.loads(proc.stdout)
