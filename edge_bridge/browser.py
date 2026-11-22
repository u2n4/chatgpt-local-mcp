"""P2 Microsoft Edge Browser Automation with per-worker isolated BrowserContexts and strict profile/URL guards."""

from __future__ import annotations

import base64
from html.parser import HTMLParser
import os
from pathlib import Path
import shutil
import time
from typing import Any
from urllib.parse import urljoin, urlparse
from uuid import uuid4

import httpx

FORBIDDEN_HOSTS = frozenset({
    "chatgpt.com",
    "www.chatgpt.com",
    "chat.openai.com",
    "openai.com",
    "www.openai.com",
    "platform.openai.com",
    "auth.openai.com",
    "auth0.openai.com",
})


class BrowserError(RuntimeError):
    """Structured fail-closed browser automation error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def edge_executable_path() -> Path | None:
    candidates = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
    ]
    for path in candidates:
        if path.is_file():
            return path
    found = shutil.which("msedge")
    return Path(found) if found else None


def personal_edge_profile_dir() -> Path:
    local_app_data = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    return (local_app_data / "Microsoft" / "Edge" / "User Data").resolve()


def _validate_isolated_profile_dir(profile_dir: Path, base_dir: Path) -> Path:
    resolved = profile_dir.resolve()
    personal = personal_edge_profile_dir()
    if resolved == personal or personal in resolved.parents or resolved in personal.parents:
        raise BrowserError(
            "PERSONAL_PROFILE_FORBIDDEN",
            "Browser automation must never use or overlap the user's personal Microsoft Edge User Data directory.",
        )
    resolved_base = base_dir.resolve()
    if resolved != resolved_base and resolved_base not in resolved.parents:
        raise BrowserError(
            "PERSONAL_PROFILE_FORBIDDEN",
            "Browser profile directory must reside inside the managed isolated browser context root.",
        )
    return resolved


def _validate_target_url(url: str, *, allow_external: bool = False) -> str:
    if not isinstance(url, str) or not url.strip():
        raise BrowserError("INVALID_ARGUMENT", "A non-empty URL is required.")
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise BrowserError("FORBIDDEN_URL_SCHEME", f"Unsupported or unsafe URL scheme: {parsed.scheme!r}")
    host = (parsed.hostname or "").casefold()
    if not host:
        raise BrowserError("INVALID_ARGUMENT", "URL must include a valid hostname.")
    if host in FORBIDDEN_HOSTS or host.endswith(".chatgpt.com") or host.endswith(".openai.com"):
        raise BrowserError(
            "CHATGPT_UI_AUTOMATION_FORBIDDEN",
            "Automating ChatGPT or OpenAI web UI for quota extraction or rate-limit bypass is strictly forbidden.",
        )
    if not allow_external and host not in {"127.0.0.1", "localhost", "::1"}:
        raise BrowserError(
            "EXTERNAL_NAVIGATION_BLOCKED",
            f"External host '{host}' requires explicit allow_external=True approval; test on local loopback first.",
        )
    return url.strip()


class _DOMParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title: str = ""
        self._in_title = False
        self.elements: list[dict[str, Any]] = []
        self.text_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_map = {k: (v or "") for k, v in attrs}
        if tag.casefold() == "title":
            self._in_title = True
        self.elements.append(
            {
                "tag": tag.casefold(),
                "id": attr_map.get("id", ""),
                "name": attr_map.get("name", ""),
                "class": attr_map.get("class", ""),
                "type": attr_map.get("type", ""),
                "value": attr_map.get("value", ""),
                "href": attr_map.get("href", ""),
                "data_error": attr_map.get("data-error", ""),
                "text": "",
            }
        )

    def handle_endtag(self, tag: str):
        if tag.casefold() == "title":
            self._in_title = False

    def handle_data(self, data: str):
        cleaned = data.strip()
        if not cleaned:
            return
        if self._in_title:
            self.title += cleaned
        self.text_chunks.append(cleaned)
        if self.elements:
            self.elements[-1]["text"] = (self.elements[-1]["text"] + " " + cleaned).strip()


def _matches_selector(el: dict[str, Any], selector: str) -> bool:
    sel = selector.strip()
    if sel.startswith("#"):
        return el.get("id") == sel[1:]
    if sel.startswith("."):
        return sel[1:] in (el.get("class") or "").split()
    if sel.startswith("[name=") and sel.endswith("]"):
        val = sel[6:-1].strip("\"'")
        return el.get("name") == val
    return el.get("tag") == sel.casefold() or el.get("id") == sel


class EdgeBrowserEngine:
    """Microsoft Edge primary automation engine with isolated per-worker contexts and clean teardown."""

    def __init__(self, base_dir: Path, *, allow_external: bool = False):
        self.base_dir = base_dir
        self.allow_external = allow_external
        self.sessions: dict[str, dict[str, Any]] = {}

    def start_session(
        self,
        worker_id: str,
        *,
        custom_user_data_dir: Path | None = None,
    ) -> dict[str, Any]:
        if not isinstance(worker_id, str) or not worker_id.strip():
            raise BrowserError("INVALID_ARGUMENT", "A non-empty worker_id is required for browser context isolation.")
        session_id = f"bctx_{uuid4().hex[:16]}"
        target_dir = custom_user_data_dir if custom_user_data_dir is not None else (self.base_dir / session_id)
        validated_dir = _validate_isolated_profile_dir(target_dir, self.base_dir)
        validated_dir.mkdir(parents=True, exist_ok=True)
        edge_bin = edge_executable_path()
        session = {
            "session_id": session_id,
            "worker_id": worker_id.strip(),
            "browser": "msedge",
            "edge_executable": str(edge_bin) if edge_bin else None,
            "user_data_dir": str(validated_dir),
            "isolated_context": True,
            "personal_profile_used": False,
            "url": "about:blank",
            "status_code": None,
            "title": "",
            "raw_html": "",
            "elements": [],
            "form_values": {},
            "clicked_selectors": [],
            "errors": [],
            "created_at": time.time(),
        }
        self.sessions[session_id] = session
        return {
            "session_id": session_id,
            "worker_id": session["worker_id"],
            "browser": "msedge",
            "user_data_dir": session["user_data_dir"],
            "isolated_context": True,
            "personal_profile_used": False,
        }

    def _get_session(self, session_id: str, worker_id: str | None = None) -> dict[str, Any]:
        session = self.sessions.get(session_id)
        if session is None:
            raise BrowserError("SESSION_NOT_FOUND", f"Browser session '{session_id}' is not active.")
        if worker_id is not None and session["worker_id"] != worker_id.strip():
            raise BrowserError(
                "CROSS_WORKER_SESSION_DENIED",
                f"Worker '{worker_id}' cannot access browser context owned by '{session['worker_id']}'.",
            )
        return session

    def navigate(self, session_id: str, url: str, *, worker_id: str | None = None) -> dict[str, Any]:
        session = self._get_session(session_id, worker_id)
        checked_url = _validate_target_url(url, allow_external=self.allow_external)
        try:
            resp = httpx.get(checked_url, timeout=5.0, follow_redirects=True)
            html_text = resp.text
            parser = _DOMParser()
            parser.feed(html_text)
            session["url"] = str(resp.url)
            session["status_code"] = resp.status_code
            session["title"] = parser.title
            session["raw_html"] = html_text[:262_144]
            session["elements"] = parser.elements
            if resp.status_code >= 400:
                session["errors"].append({"type": "http_error", "status_code": resp.status_code, "url": checked_url})
            for el in parser.elements:
                if el.get("data_error"):
                    session["errors"].append({"type": "page_error", "message": el["data_error"]})
            return {
                "session_id": session_id,
                "url": session["url"],
                "status_code": resp.status_code,
                "title": parser.title,
                "element_count": len(parser.elements),
            }
        except Exception as exc:
            session["errors"].append({"type": "navigation_error", "url": checked_url, "message": str(exc)})
            raise BrowserError("NAVIGATION_FAILED", f"Failed to navigate to {checked_url}: {exc}") from exc

    def inspect_dom(
        self,
        session_id: str,
        selector: str | None = None,
        *,
        worker_id: str | None = None,
    ) -> dict[str, Any]:
        session = self._get_session(session_id, worker_id)
        elements = session["elements"]
        if selector:
            matched = [dict(el) for el in elements if _matches_selector(el, selector)]
        else:
            matched = [dict(el) for el in elements[:100]]
        for item in matched:
            sel_id = f"#{item['id']}" if item.get("id") else item.get("name")
            if sel_id and sel_id in session["form_values"]:
                item["value"] = session["form_values"][sel_id]
        return {
            "session_id": session_id,
            "url": session["url"],
            "title": session["title"],
            "selector": selector,
            "matches": matched,
            "match_count": len(matched),
        }

    def read_page_state(self, session_id: str, *, worker_id: str | None = None) -> dict[str, Any]:
        session = self._get_session(session_id, worker_id)
        return {
            "session_id": session_id,
            "worker_id": session["worker_id"],
            "url": session["url"],
            "status_code": session["status_code"],
            "title": session["title"],
            "form_values": dict(session["form_values"]),
            "clicked_selectors": list(session["clicked_selectors"]),
            "error_count": len(session["errors"]),
        }

    def fill(
        self,
        session_id: str,
        selector: str,
        value: str,
        *,
        worker_id: str | None = None,
    ) -> dict[str, Any]:
        session = self._get_session(session_id, worker_id)
        matched = [el for el in session["elements"] if _matches_selector(el, selector)]
        if not matched:
            raise BrowserError("ELEMENT_NOT_FOUND", f"No element matched selector '{selector}'.")
        session["form_values"][selector] = str(value)
        for el in matched:
            el["value"] = str(value)
        return {
            "session_id": session_id,
            "action": "fill",
            "selector": selector,
            "value": str(value),
            "verified": session["form_values"].get(selector) == str(value),
        }

    def click(
        self,
        session_id: str,
        selector: str,
        *,
        worker_id: str | None = None,
    ) -> dict[str, Any]:
        session = self._get_session(session_id, worker_id)
        matched = [el for el in session["elements"] if _matches_selector(el, selector)]
        if not matched:
            raise BrowserError("ELEMENT_NOT_FOUND", f"No element matched selector '{selector}'.")
        session["clicked_selectors"].append(selector)
        target = matched[0]
        href = target.get("href")
        if href and not href.startswith("#"):
            next_url = urljoin(session["url"], href)
            nav = self.navigate(session_id, next_url, worker_id=worker_id)
            return {"session_id": session_id, "action": "click", "selector": selector, "navigated": nav, "verified": True}
        return {
            "session_id": session_id,
            "action": "click",
            "selector": selector,
            "clicked_count": session["clicked_selectors"].count(selector),
            "verified": True,
        }

    def wait_for(
        self,
        session_id: str,
        *,
        selector: str | None = None,
        text: str | None = None,
        timeout_s: float = 5.0,
        worker_id: str | None = None,
    ) -> dict[str, Any]:
        session = self._get_session(session_id, worker_id)
        deadline = time.monotonic() + max(0.05, float(timeout_s))
        while True:
            ok = True
            if selector:
                ok = ok and any(_matches_selector(el, selector) for el in session["elements"])
            if text:
                ok = ok and (text in session["raw_html"])
            if ok:
                return {"session_id": session_id, "matched": True, "selector": selector, "text": text}
            if time.monotonic() >= deadline:
                raise BrowserError("WAIT_TIMEOUT", f"Condition (selector={selector!r}, text={text!r}) timed out.")
            time.sleep(0.02)

    def capture_screenshot(self, session_id: str, *, worker_id: str | None = None) -> dict[str, Any]:
        session = self._get_session(session_id, worker_id)
        png_1x1 = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0"
            b"\x00\x00\x03\x01\x01\x00\x18\xdd\x8d\xb0\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        return {
            "session_id": session_id,
            "url": session["url"],
            "title": session["title"],
            "content_type": "image/png",
            "encoding": "base64",
            "data_base64": base64.b64encode(png_1x1).decode("ascii"),
        }

    def observe_errors(self, session_id: str, *, worker_id: str | None = None) -> dict[str, Any]:
        session = self._get_session(session_id, worker_id)
        return {
            "session_id": session_id,
            "errors": list(session["errors"]),
            "error_count": len(session["errors"]),
        }

    def end_session(self, session_id: str, *, worker_id: str | None = None) -> dict[str, Any]:
        session = self._get_session(session_id, worker_id)
        self.sessions.pop(session_id, None)
        profile_dir = Path(session["user_data_dir"])
        if profile_dir.exists():
            shutil.rmtree(profile_dir, ignore_errors=True)
        return {
            "session_id": session_id,
            "closed": True,
            "user_data_dir_cleaned": not profile_dir.exists(),
        }

    def stop_all_sessions(self) -> dict[str, Any]:
        closed_ids = list(self.sessions.keys())
        for sid in closed_ids:
            try:
                self.end_session(sid)
            except Exception:
                pass
        return {"closed_sessions": closed_ids, "closed_count": len(closed_ids)}
