"""Stage 7 Native Windows Desktop UI Automation Probe (§11 [S20]):
Explicitly checks interactive `WinSta0\\Default` desktop vs Session 0 / sandboxed `WinSta0\\exebox-*`.
Blocks credential/UAC/password windows and refuses silent fallback to blind screenshot clicking.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from edge_bridge import runner


def probe_windows_uia() -> dict[str, Any]:
    desktop = runner.thread_desktop_name()
    is_default_desktop = bool(desktop and desktop.casefold().endswith("\\default"))
    uia_assembly_ok = False
    uia_detail = ""
    if os.name == "nt":
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "try { Add-Type -AssemblyName UIAutomationClient; [System.Windows.Automation.AutomationElement]::RootElement.Current.Name } catch { Write-Error $_; exit 1 }",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            uia_assembly_ok = proc.returncode == 0
            uia_detail = (proc.stdout or proc.stderr).strip()[:200]
        except Exception as exc:
            uia_detail = str(exc)

    if not is_default_desktop:
        return {
            "implemented": True,
            "authorized": False,
            "available": "false",
            "verified": False,
            "desktop_name": desktop,
            "interactive_default_desktop": False,
            "uia_assembly_loadable": uia_assembly_ok,
            "uia_detail": uia_detail,
            "verdict": "BLOCKED",
            "reason": f"Current session desktop is '{desktop}', not interactive WinSta0\\Default; live UI Automation requires a user-session helper on WinSta0\\Default.",
        }

    return {
        "implemented": True,
        "authorized": False,
        "available": "true" if uia_assembly_ok else "unknown",
        "verified": uia_assembly_ok,
        "desktop_name": desktop,
        "interactive_default_desktop": True,
        "uia_assembly_loadable": uia_assembly_ok,
        "uia_detail": uia_detail,
        "verdict": "PASS" if uia_assembly_ok else "BLOCKED",
        "reason": "Microsoft UIAutomationClient probed on WinSta0\\Default; requires explicit per-window approval and DesktopSessionLock before any action.",
    }


if __name__ == "__main__":
    print(json.dumps(probe_windows_uia(), indent=2))
