"""Local MXC sandbox exposure probe for python_tests_work (not part of test suites).

Runs a small Python unittest payload inside the exact same pinned MXC sandbox
path that the queue worker uses (`edge_bridge.runner.prepare_recipe` and
`edge_bridge.runner.launch_recipe`, with the 50% Win32 Job Object CPU hard cap).

Safety invariant: this probe NEVER prints or stores environment variable values,
registry key/value names or values, directory entry names, or host user paths.
It records only yes/no flags, integer counts, and numeric Windows error codes.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import sys
import tempfile

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from edge_bridge import runner  # noqa: E402

MARKER = "WORK_SANDBOX_PROBE_JSON:"
ALLOWED_ENV_KEYS = ("USERNAME", "USERPROFILE", "APPDATA", "LOCALAPPDATA")
ALLOWED_REG_KEYS = (r"HKCU\Software", r"HKLM\Software", r"HKCU\Environment")


def _build_payload_test(profile_dir: str, outside_dir: str, loopback_port: int) -> str:
    return f"""\
import json
import os
import socket
import unittest
import winreg

MARKER = {MARKER!r}
PROFILE_DIR = {profile_dir!r}
OUTSIDE_DIR = {outside_dir!r}
LOOPBACK_PORT = {loopback_port!r}


def _probe_env():
    out = {{}}
    for key in {ALLOWED_ENV_KEYS!r}:
        value = os.environ.get(key)
        out[key] = "yes" if (value is not None and value != "") else "no"
    return out


def _probe_registry():
    targets = (
        (r"HKCU\\Software", winreg.HKEY_CURRENT_USER, "Software"),
        (r"HKLM\\Software", winreg.HKEY_LOCAL_MACHINE, "Software"),
        (r"HKCU\\Environment", winreg.HKEY_CURRENT_USER, "Environment"),
    )
    out = {{}}
    for label, hive, subkey in targets:
        item = {{"open": "no", "list": "no", "subkey_count": None, "value_count": None}}
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as handle:
                item["open"] = "yes"
                try:
                    subkeys = 0
                    while subkeys < 100000:
                        try:
                            winreg.EnumKey(handle, subkeys)
                            subkeys += 1
                        except OSError as exc:
                            if getattr(exc, "winerror", None) == 259:
                                break
                            raise
                    values = 0
                    while values < 100000:
                        try:
                            winreg.EnumValue(handle, values)
                            values += 1
                        except OSError as exc:
                            if getattr(exc, "winerror", None) == 259:
                                break
                            raise
                    item["list"] = "yes"
                    item["subkey_count"] = subkeys
                    item["value_count"] = values
                except OSError as exc:
                    item["list"] = "no"
                    item["list_winerror"] = getattr(exc, "winerror", None)
        except OSError as exc:
            item["open_winerror"] = getattr(exc, "winerror", None)
        out[label] = item
    return out


def _probe_tcp(host, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            err = sock.connect_ex((host, port))
            return ("yes", 0) if err == 0 else ("no", int(err))
    except OSError as exc:
        code = getattr(exc, "winerror", None)
        if code is None:
            code = getattr(exc, "errno", None)
        return ("no", int(code) if code is not None else -1)


def _probe_network():
    external_ok, external_code = _probe_tcp("1.1.1.1", 443, 2.0)
    loopback_ok, loopback_code = _probe_tcp("127.0.0.1", LOOPBACK_PORT, 1.0)
    return {{
        "outbound_works": "yes" if (external_ok == "yes" or loopback_ok == "yes") else "no",
        "external_tcp_443": external_ok,
        "external_error": external_code,
        "loopback_tcp": loopback_ok,
        "loopback_error": loopback_code,
    }}


def _probe_directory(path):
    if not path:
        return {{"listable": "no", "entry_count": None}}
    try:
        entries = os.listdir(path)
        return {{"listable": "yes", "entry_count": len(entries)}}
    except OSError as exc:
        return {{
            "listable": "no",
            "entry_count": None,
            "winerror": getattr(exc, "winerror", None),
        }}


class WorkSandboxProbe(unittest.TestCase):
    def test_probe(self):
        payload = {{
            "env_vars_present": _probe_env(),
            "registry": _probe_registry(),
            "network": _probe_network(),
            "outside_directories": {{
                "profile_folder": _probe_directory(PROFILE_DIR),
                "outside_sibling_folder": _probe_directory(OUTSIDE_DIR),
            }},
        }}
        print(MARKER + json.dumps(payload, sort_keys=True), flush=True)
"""


def _sanitize_yn(value: object) -> str:
    return "yes" if value == "yes" else "no"


def _sanitize_int_or_none(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _sanitize_payload(raw: dict) -> dict:
    env_in = raw.get("env_vars_present") if isinstance(raw.get("env_vars_present"), dict) else {}
    env_out = {key: _sanitize_yn(env_in.get(key)) for key in ALLOWED_ENV_KEYS}

    reg_in = raw.get("registry") if isinstance(raw.get("registry"), dict) else {}
    reg_out = {}
    for label in ALLOWED_REG_KEYS:
        item = reg_in.get(label) if isinstance(reg_in.get(label), dict) else {}
        clean = {
            "open": _sanitize_yn(item.get("open")),
            "list": _sanitize_yn(item.get("list")),
            "subkey_count": _sanitize_int_or_none(item.get("subkey_count")),
            "value_count": _sanitize_int_or_none(item.get("value_count")),
        }
        if item.get("open_winerror") is not None:
            clean["open_winerror"] = _sanitize_int_or_none(item.get("open_winerror"))
        if item.get("list_winerror") is not None:
            clean["list_winerror"] = _sanitize_int_or_none(item.get("list_winerror"))
        reg_out[label] = clean

    net_in = raw.get("network") if isinstance(raw.get("network"), dict) else {}
    net_out = {
        "outbound_works": _sanitize_yn(net_in.get("outbound_works")),
        "external_tcp_443": _sanitize_yn(net_in.get("external_tcp_443")),
        "external_error": _sanitize_int_or_none(net_in.get("external_error")),
        "loopback_tcp": _sanitize_yn(net_in.get("loopback_tcp")),
        "loopback_error": _sanitize_int_or_none(net_in.get("loopback_error")),
    }

    dirs_in = raw.get("outside_directories") if isinstance(raw.get("outside_directories"), dict) else {}
    dirs_out = {}
    for label in ("profile_folder", "outside_sibling_folder"):
        item = dirs_in.get(label) if isinstance(dirs_in.get(label), dict) else {}
        clean = {
            "listable": _sanitize_yn(item.get("listable")),
            "entry_count": _sanitize_int_or_none(item.get("entry_count")),
        }
        if item.get("winerror") is not None:
            clean["winerror"] = _sanitize_int_or_none(item.get("winerror"))
        dirs_out[label] = clean

    return {
        "env_vars_present": env_out,
        "registry": reg_out,
        "network": net_out,
        "outside_directories": dirs_out,
    }


def _looks_like_0xc0000142(text: str) -> bool:
    upper = text.upper()
    return ("0XC0000142" in upper) or ("3221225794" in upper) or ("-1073741502" in upper)


def run_probe(timeout_seconds: int = 30) -> tuple[int, dict]:
    diag = runner.diagnose()
    exec_info = diag.get("execution", {}) if isinstance(diag, dict) else {}
    session_info = {
        "desktop_name": exec_info.get("desktop_name"),
        "mxc_non_default_desktop_warning": bool(exec_info.get("mxc_non_default_desktop_warning")),
        "backend_available": bool(exec_info.get("vendor_executable_present")),
        "cpu_hard_cap_percent": runner.MAX_TEST_CPU_PERCENT,
    }
    job_limits = {
        "memory_bytes": runner.MAX_TEST_MEMORY,
        "processes": runner.MAX_TEST_PROCESSES,
        "log_bytes": runner.MAX_TEST_LOG_BYTES,
        "cpu_percent": runner.MAX_TEST_CPU_PERCENT,
    }

    with tempfile.TemporaryDirectory(prefix="epb-work-sandbox-probe-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        control = root / "control"
        outside = root / "outside"
        (workspace / "tests").mkdir(parents=True)
        control.mkdir(parents=True)
        outside.mkdir(parents=True)
        (outside / "marker.txt").write_text("outside\n", encoding="utf-8")
        (workspace / "tests" / "__init__.py").write_bytes(b"")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            loopback_port = listener.getsockname()[1]

            profile_dir = os.environ.get("USERPROFILE", "")
            test_code = _build_payload_test(profile_dir, str(outside), loopback_port)
            (workspace / "tests" / "test_probe.py").write_text(test_code, encoding="utf-8")

            log_path = control / "probe.log"
            try:
                runner.prepare_recipe(
                    workspace,
                    control,
                    "project_tests",
                    job_limits=job_limits,
                    test_target="tests.test_probe",
                )
                owned = runner.launch_recipe(
                    workspace,
                    control,
                    log_path,
                    "project_tests",
                    job_limits=job_limits,
                    test_target="tests.test_probe",
                )
                try:
                    exit_code = owned.wait(timeout_seconds)
                finally:
                    owned.close()
            except runner.RunnerBlocked as exc:
                raw_msg = str(exc)
                hit_142 = _looks_like_0xc0000142(raw_msg)
                return 2, {
                    "status": "sandbox_start_failed",
                    "code": exc.code,
                    "error_0xc0000142": hit_142,
                    "session": session_info,
                    "note": (
                        "MXC sandbox failed to start (0xC0000142 / non-Default desktop). "
                        "Run scripts/probe_work_sandbox.ps1 from an interactive WinSta0\\Default session; "
                        "no weaker fallback is used."
                        if hit_142
                        else "MXC sandbox refused to start; no weaker fallback is used."
                    ),
                }

            log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
            raw_payload = None
            for line in log_text.splitlines():
                idx = line.find(MARKER)
                if idx != -1:
                    raw_payload = json.loads(line[idx + len(MARKER):])
                    break

            if raw_payload is None:
                hit_142 = _looks_like_0xc0000142(log_text) or exit_code in (3221225794, -1073741502)
                return 2, {
                    "status": "probe_payload_missing",
                    "exit_code": int(exit_code),
                    "error_0xc0000142": hit_142,
                    "session": session_info,
                    "note": (
                        "MXC sandbox payload exited without emitting a probe record "
                        "(likely 0xC0000142 on a non-Default desktop). Run from WinSta0\\Default."
                        if hit_142
                        else "MXC sandbox payload exited without emitting a probe record."
                    ),
                }

            return 0, {
                "status": "ok",
                "exit_code": int(exit_code),
                "session": session_info,
                "probe": _sanitize_payload(raw_payload),
            }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Probe MXC sandbox isolation for python_tests_work (prints yes/no and counts only)."
    )
    parser.add_argument("--out", type=Path, default=None, help="Optional path to write the sanitized JSON report.")
    parser.add_argument("--timeout", type=int, default=30, help="Payload timeout in seconds (default: 30).")
    args = parser.parse_args(argv)

    status_code, report = run_probe(timeout_seconds=max(5, min(args.timeout, 60)))
    encoded = json.dumps(report, indent=2, sort_keys=True)
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return status_code


if __name__ == "__main__":
    raise SystemExit(main())
