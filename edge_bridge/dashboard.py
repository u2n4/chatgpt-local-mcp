"""P3 Lightweight Loopback-Only Authenticated Dashboard backed by Broker APIs and live SQLite state."""

from __future__ import annotations

import hmac
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import threading
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import __version__, diagnostics, runner
from .broker import BridgeError, call_broker, read_token, verify_state_path
from .git_engine import GitEngine, GitEngineError
from .orchestrator import AgentOrchestrator
from .state import State
from .workers import sample_host_resources


class DashboardError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def collect_dashboard_overview(state_path: Path, principal: str = "local", project_id: str | None = None) -> dict[str, Any]:
    """Assemble live workstation state across all 12 dashboard sections using Broker IPC and State."""
    verify_state_path(state_path)
    broker_online = False
    broker_info: dict[str, Any] = {}
    try:
        broker_info = call_broker(state_path, principal, "bridge_info")
        broker_online = True
    except BridgeError as exc:
        broker_info = {"online": False, "code": exc.code, "message": str(exc)}

    db_file = state_path / "state.sqlite3"
    store = State(db_file) if db_file.is_file() else None
    diag = runner.diagnose()
    resources = sample_host_resources()

    projects: list[dict[str, Any]] = []
    if broker_online:
        projects = call_broker(state_path, principal, "project_list", {"cursor": 0, "limit": 50}).get("projects", [])
    elif store is not None:
        projects = [
            p if principal == "local" else {k: v for k, v in p.items() if k not in {"root", "root_identity"}}
            for p in store.list_projects(principal)
        ]

    selected_pid = project_id or (projects[0]["project_id"] if projects else None)
    active_agents: list[dict[str, Any]] = []
    worker_profiles: list[dict[str, Any]] = []
    task_queue: list[dict[str, Any]] = []
    running_jobs: list[dict[str, Any]] = []
    terminal_output: list[dict[str, Any]] = []
    git_changes: dict[str, Any] = {"available": False, "entries": []}
    tests_and_reports: list[dict[str, Any]] = []
    approvals: list[dict[str, Any]] = []
    session_history: list[dict[str, Any]] = []

    if store is not None:
        w_meta = store.list_workers(project_id=selected_pid, principal=principal)
        worker_profiles = w_meta["profiles"]
        active_agents = w_meta["workers"]
        task_queue = store.list_task_queue(project_id=selected_pid, principal=principal)
        session_history = diagnostics._redact_obj(store.list_incidents(limit=20))

        if selected_pid is not None:
            jobs = store.list_jobs(selected_pid, principal)
            running_jobs = [
                j if principal == "local" else {k: v for k, v in j.items() if k not in {"intent", "evidence"}}
                for j in jobs
            ]
            tests_and_reports = store.list_verification(selected_pid, principal)
            resumed = store.resume(selected_pid, principal)
            approvals = [
                {"job_id": jid, "status": "waiting_for_approval", "project_id": selected_pid}
                for jid in resumed.get("pending_approvals", [])
            ]
            if principal == "local" and broker_online:
                for j in jobs[:3]:
                    try:
                        out_page = call_broker(
                            state_path,
                            "local",
                            "job_output",
                            {"project_id": selected_pid, "job_id": j["job_id"], "cursor": 0, "limit": 4096},
                        )
                        terminal_output.append({"job_id": j["job_id"], "output": out_page.get("output", "")})
                    except Exception:
                        pass
            try:
                proj_full = store.get_project(selected_pid, "local")
                root_path = Path(proj_full["root"])
                if (root_path / ".git").exists():
                    git_changes = {"available": True, **GitEngine().status(root_path, max_entries=50)}
            except (GitEngineError, Exception):
                git_changes = {"available": False, "entries": []}

    system_health = {
        "broker": {
            "online": broker_online,
            "version": __version__,
            "info": broker_info,
        },
        "mcp": {
            "tool_count": 33,
            "stateless": True,
            "discover_32601": True,
        },
        "tunnel": {
            "mode": "loopback_or_user_authorized",
            "recent_incidents": len(session_history),
        },
        "sandbox": {
            "backend": diag["execution"]["backend"],
            "codex_version_pin": diag["execution"]["codex_version_pin"],
            "desktop_name": diag["execution"]["desktop_name"] if principal == "local" else None,
            "mxc_non_default_desktop_warning": diag["execution"]["mxc_non_default_desktop_warning"],
            "automatic_weaker_fallback": diag["execution"]["automatic_weaker_fallback"],
        },
    }

    return {
        "bridge_version": __version__,
        "principal": principal,
        "selected_project_id": selected_pid,
        "sections": {
            "system_health": system_health,
            "projects": projects,
            "active_agents": {"profiles": worker_profiles, "workers": active_agents},
            "task_queue": task_queue,
            "running_jobs": running_jobs,
            "resource_monitor": resources,
            "terminal_output": terminal_output,
            "git_changes": git_changes,
            "tests_and_reports": tests_and_reports,
            "approvals": approvals,
            "session_history": session_history,
            "emergency_stop_all": {"available": principal == "local", "endpoint": "/api/stop-all"},
        },
    }


def _html_json(value: Any) -> str:
    return html.escape(json.dumps(value, indent=2, ensure_ascii=False), quote=True)


def render_dashboard_html(overview: dict[str, Any]) -> str:
    sec = overview["sections"]
    health = sec["system_health"]
    res = sec["resource_monitor"]
    version_escaped = html.escape(str(overview["bridge_version"]), quote=True)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>EDGE PROJECT BRIDGE 2.0 — Workstation Dashboard</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 20px; background: #0f172a; color: #f8fafc; }}
h1 {{ color: #38bdf8; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }}
.card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 14px; }}
.card h2 {{ margin-top: 0; font-size: 16px; color: #93c5fd; }}
.stop-btn {{ background: #ef4444; color: white; border: none; padding: 10px 16px; border-radius: 6px; font-weight: bold; cursor: pointer; }}
pre {{ background: #020617; padding: 8px; border-radius: 4px; overflow-x: auto; font-size: 12px; }}
</style>
</head>
<body>
<h1>EDGE PROJECT BRIDGE ({version_escaped})</h1>
<div class="grid">
  <div class="card" id="system-health">
    <h2>System Health (Broker / MCP / Tunnel / Sandbox)</h2>
    <pre>{_html_json(health)}</pre>
  </div>
  <div class="card" id="projects">
    <h2>Projects ({len(sec["projects"])})</h2>
    <pre>{_html_json(sec["projects"])}</pre>
  </div>
  <div class="card" id="active-agents">
    <h2>Active Agents ({len(sec["active_agents"]["workers"])})</h2>
    <pre>{_html_json(sec["active_agents"])}</pre>
  </div>
  <div class="card" id="task-queue">
    <h2>Task Queue ({len(sec["task_queue"])})</h2>
    <pre>{_html_json(sec["task_queue"])}</pre>
  </div>
  <div class="card" id="running-jobs">
    <h2>Running Jobs ({len(sec["running_jobs"])})</h2>
    <pre>{_html_json(sec["running_jobs"])}</pre>
  </div>
  <div class="card" id="resource-monitor">
    <h2>Resource Monitor</h2>
    <pre>{_html_json(res)}</pre>
  </div>
  <div class="card" id="terminal-output">
    <h2>Terminal Output</h2>
    <pre>{_html_json(sec["terminal_output"])}</pre>
  </div>
  <div class="card" id="git-changes">
    <h2>Git Changes</h2>
    <pre>{_html_json(sec["git_changes"])}</pre>
  </div>
  <div class="card" id="tests-reports">
    <h2>Tests &amp; Reports</h2>
    <pre>{_html_json(sec["tests_and_reports"])}</pre>
  </div>
  <div class="card" id="approvals">
    <h2>Approvals</h2>
    <pre>{_html_json(sec["approvals"])}</pre>
  </div>
  <div class="card" id="session-history">
    <h2>Session History</h2>
    <pre>{_html_json(sec["session_history"])}</pre>
  </div>
  <div class="card" id="emergency-stop-all">
    <h2>Emergency Stop All</h2>
    <button class="stop-btn" id="btn-stop-all">STOP ALL JOBS &amp; WORKERS</button>
  </div>
</div>
</body>
</html>"""


class _DashboardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class _DashboardHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_args):
        return

    def _send_security_headers(self, *, is_html: bool = False) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if is_html:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
            )

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self._send_security_headers(is_html=False)
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, status: int, html_body: str) -> None:
        raw = html_body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self._send_security_headers(is_html=True)
        self.end_headers()
        self.wfile.write(raw)

    def _authenticate(self) -> str | None:
        expected_host = f"127.0.0.1:{self.server.server_port}"
        if self.headers.get_all("Host") != [expected_host]:
            self._send_json(403, {"ok": False, "code": "INVALID_HOST", "message": "Loopback Host header mismatch."})
            return None
        origins = self.headers.get_all("Origin") or []
        if len(origins) > 1 or (len(origins) == 1 and origins[0] != f"http://{expected_host}"):
            self._send_json(403, {"ok": False, "code": "FORBIDDEN_ORIGIN", "message": "Cross-origin requests are denied."})
            return None

        supplied = self.headers.get("X-Dashboard-Token") or ""
        if not supplied:
            auth_hdr = self.headers.get("Authorization") or ""
            if auth_hdr.lower().startswith("bearer "):
                supplied = auth_hdr[7:].strip()
        if not supplied:
            self._send_json(401, {"ok": False, "code": "AUTH_REQUIRED", "message": "Local dashboard authentication token required."})
            return None

        state_path: Path = self.server.state_path
        for principal in ("local", "edge"):
            try:
                tok = read_token(state_path, principal)
                if hmac.compare_digest(supplied, tok):
                    return principal
            except Exception:
                continue
        self._send_json(401, {"ok": False, "code": "AUTH_REQUIRED", "message": "Invalid dashboard authentication token."})
        return None

    def do_GET(self):
        principal = self._authenticate()
        if principal is None:
            return
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        pid = qs.get("project_id", [None])[0]
        try:
            overview = collect_dashboard_overview(self.server.state_path, principal=principal, project_id=pid)
        except Exception as exc:
            code = getattr(exc, "code", None)
            if isinstance(code, str):
                self._send_json(400, {"ok": False, "code": code, "message": str(exc)[:300]})
            else:
                self._send_json(400, {"ok": False, "code": "DASHBOARD_ERROR", "message": "Failed to assemble dashboard view."})
            return

        if parsed.path in {"/", "/index.html"}:
            self._send_html(200, render_dashboard_html(overview))
            return
        if parsed.path == "/api/overview":
            self._send_json(200, {"ok": True, "result": overview})
            return
        section_map = {
            "/api/health": "system_health",
            "/api/projects": "projects",
            "/api/agents": "active_agents",
            "/api/queue": "task_queue",
            "/api/jobs": "running_jobs",
            "/api/resources": "resource_monitor",
            "/api/terminal": "terminal_output",
            "/api/git": "git_changes",
            "/api/tests": "tests_and_reports",
            "/api/approvals": "approvals",
            "/api/history": "session_history",
        }
        if parsed.path in section_map:
            key = section_map[parsed.path]
            self._send_json(200, {"ok": True, "result": overview["sections"][key]})
            return
        self._send_json(404, {"ok": False, "code": "NOT_FOUND", "message": "Unknown dashboard endpoint."})

    def do_POST(self):
        principal = self._authenticate()
        if principal is None:
            return
        parsed = urlparse(self.path)
        if parsed.path in {"/api/exec", "/api/shell", "/api/command"}:
            self._send_json(
                403,
                {"ok": False, "code": "UNISOLATED_EXECUTION_FORBIDDEN", "message": "Dashboard never exposes arbitrary command execution."},
            )
            return
        if parsed.path == "/api/stop-all":
            if principal != "local":
                self._send_json(
                    403,
                    {"ok": False, "code": "PRINCIPAL_READ_ONLY", "message": "Only the local owner token can trigger Emergency Stop All."},
                )
                return
            state_path: Path = self.server.state_path
            try:
                broker_res = call_broker(state_path, "local", "owner_stop_all", {"reason": "dashboard_emergency_stop_all"})
            except BridgeError:
                broker_res = {"stopped": False, "broker_online": False}
            db_file = state_path / "state.sqlite3"
            orch_res = {}
            if db_file.is_file():
                orch = AgentOrchestrator(State(db_file), state_path)
                orch_res = orch.stop_all(reason="dashboard_emergency_stop_all")
            self._send_json(200, {"ok": True, "result": {"broker": broker_res, "orchestrator": orch_res}})
            return
        self._send_json(404, {"ok": False, "code": "NOT_FOUND", "message": "Unknown dashboard POST endpoint."})


class DashboardServer:
    """Lifecycle wrapper for the loopback-only Edge Project Bridge Dashboard."""

    def __init__(self, state_path: Path, *, host: str = "127.0.0.1", port: int = 0):
        if host != "127.0.0.1":
            raise DashboardError("INVALID_BIND_HOST", "Dashboard must bind exclusively to 127.0.0.1.")
        verify_state_path(state_path)
        self.state_path = state_path
        self.server = _DashboardHTTPServer(("127.0.0.1", port), _DashboardHandler)
        self.server.state_path = state_path
        self.port = self.server.server_port
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start_background(self) -> str:
        self._thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        return self.url

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=3)
