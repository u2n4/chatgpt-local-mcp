"""Stage 7 Browser Testing Adapter (§11):
Prefers Playwright with isolated test profiles against approved loopback URLs only.
Blocks personal profiles, ChatGPT/OpenAI automation, and unapproved external hosts.
Captures traces only on failure or explicit request; never treats a screenshot alone as backend test proof.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any
from urllib.parse import urlparse


FORBIDDEN_HOSTS = frozenset({
    "chatgpt.com",
    "www.chatgpt.com",
    "chat.openai.com",
    "openai.com",
    "www.openai.com",
    "auth.openai.com",
})


def probe_browser_capability() -> dict[str, Any]:
    py_pw = importlib.util.find_spec("playwright") is not None
    node_pw = shutil.which("playwright") is not None
    edge_paths = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft/Edge/Application/msedge.exe",
    ]
    edge_exe = next((str(p) for p in edge_paths if p.is_file()), None)
    return {
        "implemented": True,
        "authorized": False,
        "available": "true" if (py_pw or node_pw or edge_exe) else "false",
        "verified": False,
        "playwright_python_installed": py_pw,
        "playwright_cli_installed": node_pw,
        "msedge_executable": edge_exe,
        "trace_policy": "on_failure_or_explicit_request",
        "reason": (
            "Playwright available for real selector/assertion/trace runs."
            if (py_pw or node_pw)
            else "Microsoft Edge detected, but Playwright runtime is not installed in this venv/node env; HTTP loopback probe available, Playwright browser E2E marked NOT_TESTED until installed."
        ),
    }


def validate_loopback_target(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
    host = (parsed.hostname or "").casefold()
    if host in FORBIDDEN_HOSTS or host.endswith(".openai.com") or host.endswith(".chatgpt.com"):
        raise PermissionError("Automating ChatGPT/OpenAI web UI is strictly forbidden.")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise PermissionError(f"External host '{host}' blocked without explicit allowlist approval.")
    return url.strip()


if __name__ == "__main__":
    print(json.dumps(probe_browser_capability(), indent=2))
