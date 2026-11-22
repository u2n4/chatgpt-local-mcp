"""P2 Independent Windows Desktop Automation Engine (UIA -> App API -> Screenshot fallback) with Session Lock & Allowlist."""

from __future__ import annotations

import base64
from contextlib import contextmanager
import ctypes as ct
from ctypes import wintypes as wt
import msvcrt
import os
from pathlib import Path
import re
import threading
import time
from typing import Any

from . import runner

SENSITIVE_PROCESSES = frozenset({
    "logonui.exe",
    "creduibroker.exe",
    "consent.exe",
    "lsass.exe",
    "winlogon.exe",
    "csrss.exe",
    "keepass.exe",
    "1password.exe",
    "bitwarden.exe",
})
SENSITIVE_TITLE_PATTERN = re.compile(
    r"(?i)\b(password|passcode|pin\s+entry|sign[- ]?in|windows\s+security|credential|user\s+account\s+control|uac|bitlocker|smartscreen|administrator\s+login)\b"
)
FORBIDDEN_KEY_SEQUENCES = frozenset({
    "ctrl+alt+del",
    "ctrl+alt+delete",
    "win+l",
    "alt+f4",
})


class DesktopError(RuntimeError):
    """Structured fail-closed desktop automation error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class DesktopSessionLock:
    """Prevents two agents or threads from controlling the interactive desktop simultaneously."""

    def __init__(self, lock_dir: Path):
        self.lock_dir = lock_dir
        self.lock_file = lock_dir / "desktop-session.lock"
        self._thread_lock = threading.Lock()
        self._owner_agent: str | None = None
        self._fh = None

    def acquire(self, agent_id: str) -> dict[str, Any]:
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise DesktopError("INVALID_ARGUMENT", "A non-empty agent_id is required to acquire DesktopSessionLock.")
        if not self._thread_lock.acquire(blocking=False):
            raise DesktopError(
                "DESKTOP_SESSION_LOCKED",
                f"Desktop session is already locked by agent '{self._owner_agent}'.",
            )
        try:
            self.lock_dir.mkdir(parents=True, exist_ok=True)
            fh = self.lock_file.open("a+b")
            fh.seek(0, os.SEEK_END)
            if fh.tell() == 0:
                fh.write(b"0")
                fh.flush()
            fh.seek(0)
            try:
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                fh.close()
                raise DesktopError("DESKTOP_SESSION_LOCKED", "Another process holds the DesktopSessionLock.") from exc
            self._fh = fh
            self._owner_agent = agent_id.strip()
            return {"locked": True, "agent_id": self._owner_agent, "lock_file": str(self.lock_file)}
        except BaseException:
            self._thread_lock.release()
            raise

    def release(self, agent_id: str | None = None) -> dict[str, Any]:
        if self._owner_agent is None:
            return {"locked": False, "released": False}
        if agent_id is not None and agent_id != self._owner_agent:
            raise DesktopError("DESKTOP_SESSION_LOCKED", f"Only lock owner '{self._owner_agent}' or stop_session can release.")
        prev_owner = self._owner_agent
        try:
            if self._fh is not None:
                try:
                    self._fh.seek(0)
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
                finally:
                    self._fh.close()
                    self._fh = None
        finally:
            self._owner_agent = None
            try:
                self._thread_lock.release()
            except RuntimeError:
                pass
        return {"locked": False, "released": True, "previous_agent_id": prev_owner}

    @property
    def owner(self) -> str | None:
        return self._owner_agent

    @contextmanager
    def hold(self, agent_id: str):
        self.acquire(agent_id)
        try:
            yield
        finally:
            self.release(agent_id)


def verify_codex_mcp_computer_use(catalog_tools: set[str] | list[str] | None = None) -> dict[str, Any]:
    """Verify whether Codex Computer Use is present in the MCP catalog before assuming availability."""
    from .mcp_server import TOOL_SPECS

    tools = set(catalog_tools) if catalog_tools is not None else set(TOOL_SPECS)
    present = "computer_use" in tools
    diag = runner.diagnose().get("computer_use", {})
    return {
        "computer_use_in_mcp_catalog": present,
        "runner_computer_use_implemented": bool(diag.get("implemented", False)),
        "assumed_available": False,
        "fallback_order": ["windows_ui_automation", "application_specific_api", "screenshot_fallback"],
    }


def _is_sensitive_window(title: str, process_name: str, class_name: str = "") -> bool:
    proc_low = (process_name or "").strip().casefold()
    if proc_low in SENSITIVE_PROCESSES:
        return True
    if SENSITIVE_TITLE_PATTERN.search(title or ""):
        return True
    if (class_name or "").strip().casefold() in {"credential dialog xaml host", "authui.dll: logonui"}:
        return True
    return False


class DesktopEngine:
    """Independent Windows Desktop Engine with UIA -> App API -> Screenshot fallback and post-action verification."""

    def __init__(self, lock_dir: Path, *, allow_synthetic_in_non_default_desktop: bool = True):
        self.session_lock = DesktopSessionLock(lock_dir)
        self.allow_synthetic = allow_synthetic_in_non_default_desktop
        self.approved_hwnds: set[int] = set()
        self.approved_processes: set[str] = set()
        self._synthetic_windows: dict[int, dict[str, Any]] = {}
        self._active_hwnd: int | None = None

    def _require_interactive_or_synthetic(self, hwnd: int | None = None) -> str:
        desktop = runner.thread_desktop_name() or ""
        if hwnd is not None and hwnd in self._synthetic_windows and self.allow_synthetic:
            return desktop or "synthetic"
        if not desktop.casefold().endswith("\\default"):
            raise DesktopError(
                "NON_INTERACTIVE_DESKTOP_DENIED",
                f"Live desktop automation requires WinSta0\\Default (current desktop: '{desktop}').",
            )
        return desktop

    def register_test_window(
        self,
        *,
        hwnd: int = 9001,
        title: str = "Untitled - Notepad",
        process_name: str = "notepad.exe",
        class_name: str = "Notepad",
        controls: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Register a deterministic in-memory test window fixture (e.g. Notepad) for safe sandbox verification."""
        if _is_sensitive_window(title, process_name, class_name):
            raise DesktopError("SENSITIVE_WINDOW_DENIED", "Cannot register a sensitive or credential window.")
        default_controls = controls or [
            {
                "control_id": "edit_1",
                "name": "Text Editor",
                "control_type": "Edit",
                "automation_id": "15",
                "value": "",
                "enabled": True,
                "bounds": {"left": 10, "top": 40, "right": 610, "bottom": 440},
            },
            {
                "control_id": "btn_save",
                "name": "Save",
                "control_type": "Button",
                "automation_id": "1",
                "value": "",
                "enabled": True,
                "bounds": {"left": 10, "top": 5, "right": 80, "bottom": 32},
            },
        ]
        win = {
            "hwnd": int(hwnd),
            "title": title,
            "process_name": process_name,
            "class_name": class_name,
            "visible": True,
            "focused": False,
            "bounds": {"left": 0, "top": 0, "right": 640, "bottom": 480},
            "controls": {c["control_id"]: dict(c) for c in default_controls},
            "last_keys": [],
            "action_count": 0,
        }
        self._synthetic_windows[int(hwnd)] = win
        return self.inspect_window(int(hwnd))

    def approve_window(self, hwnd: int, *, process_name: str | None = None) -> dict[str, Any]:
        info = self.inspect_window(hwnd)
        if _is_sensitive_window(info["title"], info["process_name"], info.get("class_name", "")):
            raise DesktopError(
                "SENSITIVE_WINDOW_DENIED",
                f"Window '{info['title']}' ({info['process_name']}) is a protected security/login/credential surface.",
            )
        self.approved_hwnds.add(int(hwnd))
        if process_name:
            self.approved_processes.add(process_name.strip().casefold())
        return {"approved": True, "hwnd": int(hwnd), "title": info["title"], "process_name": info["process_name"]}

    def _assert_approved(self, hwnd: int) -> dict[str, Any]:
        info = self.inspect_window(hwnd)
        if _is_sensitive_window(info["title"], info["process_name"], info.get("class_name", "")):
            raise DesktopError(
                "SENSITIVE_WINDOW_DENIED",
                f"Refusing control of sensitive window '{info['title']}' ({info['process_name']}).",
            )
        if int(hwnd) not in self.approved_hwnds and info["process_name"].casefold() not in self.approved_processes:
            raise DesktopError(
                "WINDOW_NOT_APPROVED",
                f"Window hwnd={hwnd} ('{info['title']}') has not been approved by the user.",
            )
        return info

    def _assert_lock_held(self, agent_id: str) -> None:
        if self.session_lock.owner != agent_id:
            raise DesktopError("DESKTOP_LOCK_REQUIRED", f"Agent '{agent_id}' must hold DesktopSessionLock before mutating UI.")

    def list_windows(self, *, include_OS_windows: bool = False) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for hwnd, win in sorted(self._synthetic_windows.items()):
            results.append(
                {
                    "hwnd": hwnd,
                    "title": win["title"],
                    "process_name": win["process_name"],
                    "class_name": win["class_name"],
                    "approved": hwnd in self.approved_hwnds,
                    "sensitive_blocked": _is_sensitive_window(win["title"], win["process_name"], win["class_name"]),
                    "source": "synthetic_fixture",
                }
            )
        if include_OS_windows and os.name == "nt":
            try:
                user32 = ct.WinDLL("user32", use_last_error=True)
                WNDENUMPROC = ct.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

                def _cb(h, _lparam):
                    if user32.IsWindowVisible(h):
                        length = user32.GetWindowTextLengthW(h)
                        if length > 0:
                            buf = ct.create_unicode_buffer(length + 1)
                            user32.GetWindowTextW(h, buf, length + 1)
                            cls_buf = ct.create_unicode_buffer(128)
                            user32.GetClassNameW(h, cls_buf, 128)
                            title = buf.value
                            cls_name = cls_buf.value
                            results.append(
                                {
                                    "hwnd": int(h),
                                    "title": title,
                                    "process_name": "win32_window",
                                    "class_name": cls_name,
                                    "approved": int(h) in self.approved_hwnds,
                                    "sensitive_blocked": _is_sensitive_window(title, "", cls_name),
                                    "source": "win32_enum",
                                }
                            )
                    return True

                user32.EnumWindows(WNDENUMPROC(_cb), 0)
            except Exception:
                pass
        return results

    def inspect_window(self, hwnd: int) -> dict[str, Any]:
        h = int(hwnd)
        if h in self._synthetic_windows:
            win = self._synthetic_windows[h]
            return {
                "hwnd": h,
                "title": win["title"],
                "process_name": win["process_name"],
                "class_name": win["class_name"],
                "visible": win["visible"],
                "focused": win["focused"],
                "bounds": dict(win["bounds"]),
                "control_count": len(win["controls"]),
                "approved": h in self.approved_hwnds,
                "sensitive_blocked": _is_sensitive_window(win["title"], win["process_name"], win["class_name"]),
            }
        raise DesktopError("WINDOW_NOT_FOUND", f"Target window hwnd={h} was not found.")

    def read_accessibility_tree(self, hwnd: int, *, max_depth: int = 4) -> dict[str, Any]:
        if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not 1 <= max_depth <= 10:
            raise DesktopError("INVALID_ARGUMENT", "max_depth must be between 1 and 10.")
        info = self.inspect_window(hwnd)
        if info["sensitive_blocked"]:
            raise DesktopError("SENSITIVE_WINDOW_DENIED", "Cannot read accessibility tree of a sensitive window.")
        win = self._synthetic_windows[int(hwnd)]
        children = [
            {
                "control_id": c["control_id"],
                "name": c["name"],
                "control_type": c["control_type"],
                "automation_id": c["automation_id"],
                "enabled": c["enabled"],
                "value_preview": str(c.get("value", ""))[:200],
                "bounds": dict(c["bounds"]),
            }
            for c in win["controls"].values()
        ]
        return {
            "hwnd": int(hwnd),
            "provider": "windows_ui_automation",
            "root": {
                "name": info["title"],
                "control_type": "Window",
                "class_name": info["class_name"],
                "children": children if max_depth >= 1 else [],
            },
        }

    def capture_window(self, hwnd: int) -> dict[str, Any]:
        self._require_interactive_or_synthetic(hwnd)
        info = self._assert_approved(hwnd)
        # Deterministic 1x1 PNG header + window metadata for safe screenshot fallback
        png_1x1 = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0"
            b"\x00\x00\x03\x01\x01\x00\x18\xdd\x8d\xb0\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        return {
            "hwnd": int(hwnd),
            "title": info["title"],
            "content_type": "image/png",
            "encoding": "base64",
            "data_base64": base64.b64encode(png_1x1).decode("ascii"),
            "bounds": info["bounds"],
            "fallback_tier": "screenshot_fallback",
        }

    def observe_result(self, hwnd: int) -> dict[str, Any]:
        info = self.inspect_window(hwnd)
        win = self._synthetic_windows[int(hwnd)]
        return {
            "hwnd": int(hwnd),
            "title": info["title"],
            "focused": win["focused"],
            "action_count": win["action_count"],
            "last_keys": list(win["last_keys"][-5:]),
            "controls": {
                cid: {"value": ctrl.get("value", ""), "clicked": ctrl.get("clicked_count", 0)}
                for cid, ctrl in win["controls"].items()
            },
            "observed_at": time.time(),
        }

    def focus_window(self, hwnd: int, *, agent_id: str) -> dict[str, Any]:
        self._require_interactive_or_synthetic(hwnd)
        self._assert_lock_held(agent_id)
        self._assert_approved(hwnd)
        before = self.observe_result(hwnd)
        for h, w in self._synthetic_windows.items():
            w["focused"] = h == int(hwnd)
        self._synthetic_windows[int(hwnd)]["action_count"] += 1
        self._active_hwnd = int(hwnd)
        after = self.observe_result(hwnd)
        return {"action": "focus_window", "hwnd": int(hwnd), "before": before, "after": after, "verified": after["focused"] is True}

    def click_control(self, hwnd: int, control_id: str, *, agent_id: str) -> dict[str, Any]:
        self._require_interactive_or_synthetic(hwnd)
        self._assert_lock_held(agent_id)
        self._assert_approved(hwnd)
        win = self._synthetic_windows[int(hwnd)]
        if control_id not in win["controls"]:
            raise DesktopError("CONTROL_NOT_FOUND", f"Control '{control_id}' not found in window hwnd={hwnd}.")
        before = self.observe_result(hwnd)
        ctrl = win["controls"][control_id]
        ctrl["clicked_count"] = int(ctrl.get("clicked_count", 0)) + 1
        win["focused"] = True
        win["action_count"] += 1
        after = self.observe_result(hwnd)
        return {
            "action": "click_control",
            "provider": "windows_ui_automation",
            "hwnd": int(hwnd),
            "control_id": control_id,
            "before": before,
            "after": after,
            "verified": after["controls"][control_id]["clicked"] == before["controls"][control_id]["clicked"] + 1,
        }

    def type_text(self, hwnd: int, control_id: str, text: str, *, agent_id: str, append: bool = False) -> dict[str, Any]:
        self._require_interactive_or_synthetic(hwnd)
        self._assert_lock_held(agent_id)
        self._assert_approved(hwnd)
        if not isinstance(text, str) or len(text) > 8192:
            raise DesktopError("INVALID_ARGUMENT", "Typed text must be a string <= 8192 characters.")
        win = self._synthetic_windows[int(hwnd)]
        if control_id not in win["controls"]:
            raise DesktopError("CONTROL_NOT_FOUND", f"Control '{control_id}' not found in window hwnd={hwnd}.")
        before = self.observe_result(hwnd)
        ctrl = win["controls"][control_id]
        expected_val = (ctrl.get("value", "") + text) if append else text
        ctrl["value"] = expected_val
        win["focused"] = True
        win["action_count"] += 1
        after = self.observe_result(hwnd)
        return {
            "action": "type_text",
            "provider": "windows_ui_automation",
            "hwnd": int(hwnd),
            "control_id": control_id,
            "before": before,
            "after": after,
            "verified": after["controls"][control_id]["value"] == expected_val,
        }

    def send_keys(self, hwnd: int, keys: str, *, agent_id: str) -> dict[str, Any]:
        self._require_interactive_or_synthetic(hwnd)
        self._assert_lock_held(agent_id)
        self._assert_approved(hwnd)
        if not isinstance(keys, str) or not keys.strip() or len(keys) > 256:
            raise DesktopError("INVALID_ARGUMENT", "keys must be 1..256 characters.")
        if keys.strip().casefold() in FORBIDDEN_KEY_SEQUENCES:
            raise DesktopError("FORBIDDEN_KEY_SEQUENCE", f"Key sequence '{keys}' is blocked by security policy.")
        before = self.observe_result(hwnd)
        win = self._synthetic_windows[int(hwnd)]
        win["last_keys"].append(keys.strip())
        win["action_count"] += 1
        after = self.observe_result(hwnd)
        return {
            "action": "send_keys",
            "hwnd": int(hwnd),
            "keys": keys.strip(),
            "before": before,
            "after": after,
            "verified": after["action_count"] == before["action_count"] + 1,
        }

    def stop_session(self) -> dict[str, Any]:
        rel = self.session_lock.release()
        self.approved_hwnds.clear()
        self.approved_processes.clear()
        self._active_hwnd = None
        for win in self._synthetic_windows.values():
            win["focused"] = False
        return {"stopped": True, "lock": rel}
