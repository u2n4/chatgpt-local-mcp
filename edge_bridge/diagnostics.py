"""Layered P0 connectivity diagnostics, host-error classification, and redacted support packets."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from . import __version__, capabilities, runner
from .state import State
from .worker_account import WorkerAccountBlocked, probe_provider_account
from .workers import sample_host_resources

RIYADH_TZ = timezone(timedelta(hours=3), name="Asia/Riyadh")
_SECRET_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-~+/=]+"),
    re.compile(r"(?i)(token|secret|password|passwd|authorization|cookie|set-cookie|api_key|apikey|x-api-key|private_key|credential)\s*[:=]\s*\S+"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
)
_REDACTED_KEYS = frozenset({
    "token",
    "secret",
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "x-api-key",
    "session",
    "bearer",
    "private_key",
    "credential",
    "email",
    "userid",
})


class DiagnosticError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def redact_text(value: str) -> str:
    cleaned = value
    cleaned = _SECRET_PATTERNS[0].sub(r"\1[REDACTED]", cleaned)
    cleaned = _SECRET_PATTERNS[1].sub(r"\1=[REDACTED]", cleaned)
    cleaned = _SECRET_PATTERNS[2].sub("[REDACTED_EMAIL]", cleaned)
    return cleaned


def _redact_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, list):
        return [_redact_obj(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _redact_obj(v) for k, v in obj.items() if str(k).casefold() not in _REDACTED_KEYS}
    return obj


def classify_host_error(message: str) -> dict[str, Any]:
    text = (message or "").strip()
    low = text.casefold()
    if "429" in low or "sse probe" in low:
        return {
            "category": "UPSTREAM_CONNECTOR_RATE_LIMIT_429",
            "location": "host_side_openai_org",
            "local_fixable": False,
            "http_status": 429,
            "reference": "https://github.com/openai/tunnel-client/issues/103",
            "summary": "ChatGPT's connector SSE probe received HTTP 429 from openai.org before/during request delivery.",
            "guidance": (
                "Do not rewrite local read tools or cycle tunnel keys. Verify local bridge via 'doctor --probe-mcp' "
                "and offline loopback smoke test, wait past Retry-After, or attach redacted support packet for OpenAI support."
            ),
        }
    if "session terminated" in low or "mcp-session-id" in low:
        return {
            "category": "MCP_SESSION_TERMINATED",
            "location": "connector_session_lifecycle",
            "local_fixable": "partial_stateless_hardening",
            "http_status": None,
            "reference": "https://github.com/openai/tunnel-client/issues/103",
            "summary": "Upstream MCP session terminated cleanly or dropped Mcp-Session-Id across reconnect/probe.",
            "guidance": (
                "Local stdio server now runs with stateless=True and clean -32601 handling for server/discover. "
                "If it recurs under live ChatGPT Pro without local crash, recreate only the chat connector session (not tunnel keys)."
            ),
        }
    if "server/discover" in low or "invalid request parameters" in low:
        return {
            "category": "MCP_DISCOVER_PROTOCOL_MISMATCH",
            "location": "mcp_handshake_compatibility",
            "local_fixable": True,
            "http_status": None,
            "reference": None,
            "summary": "Client sent MCP server/discover before or instead of initialize.",
            "guidance": "Local stdio wrapper handles server/discover with clean JSON-RPC -32601 and zero stderr Pydantic spam.",
        }
    if "-1073741502" in low or "0xc0000142" in low:
        return {
            "category": "MXC_NON_DEFAULT_DESKTOP_DLL_INIT",
            "location": "windows_desktop_acl",
            "local_fixable": "run_in_WinSta0_Default",
            "http_status": None,
            "reference": None,
            "summary": "Child binary failed Win32 DLL initialization (0xC0000142) inside MXC under a non-Default WindowStation desktop.",
            "guidance": "Execute Node/Blender/PowerShell MXC jobs from a normal interactive WinSta0\\Default PowerShell session.",
        }
    return {
        "category": "UNCLASSIFIED_INCIDENT",
        "location": "unknown",
        "local_fixable": None,
        "http_status": None,
        "reference": None,
        "summary": redact_text(text[:300]) or "No diagnostic note supplied.",
        "guidance": "Inspect layered doctor report and local job/tunnel logs.",
    }


def _extract_tool_result(reply: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    result = reply.get("result")
    if not isinstance(result, dict):
        return False, {}
    is_err = bool(result.get("isError"))
    structured = result.get("structuredContent")
    if not isinstance(structured, dict):
        return (not is_err), {}
    if is_err:
        return False, structured
    payload = structured.get("result")
    return True, payload if isinstance(payload, dict) else structured


def _probe_mcp_stdio(
    state: Path,
    principal: str = "edge",
    *,
    project_id: str | None = None,
    file_path: str | None = None,
    task_id: str | None = None,
    cwd: Path | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    requests: list[dict[str, Any]] = [
        {"jsonrpc": "2.0", "id": "openai-mcp-discover", "method": "server/discover"},
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "edge_bridge_doctor", "version": __version__},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "bridge_info", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "project_list", "arguments": {}}},
    ]
    if project_id is not None:
        if file_path is not None:
            requests.append({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "file_read", "arguments": {"project_id": project_id, "path": file_path, "offset": 0, "limit": 65536}},
            })
        resume_args: dict[str, Any] = {"project_id": project_id}
        if task_id is not None:
            resume_args["task_id"] = task_id
        requests.append({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "project_resume", "arguments": resume_args},
        })

    payload = "\n".join(json.dumps(item) for item in requests) + "\n"
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "mcp", "--principal", principal],
            input=payload.encode("utf-8"),
            capture_output=True,
            cwd=str(cwd) if cwd is not None else None,
            timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except Exception as exc:
        return {"status": "FAIL", "error": redact_text(str(exc))}

    elapsed_ms = round((time.monotonic() - started) * 1000.0, 2)
    stderr_text = proc.stderr.decode("utf-8", errors="replace")
    replies: dict[Any, dict[str, Any]] = {}
    stdout_noise = False
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            stdout_noise = True
            continue
        if not isinstance(msg, dict):
            stdout_noise = True
            continue
        if "id" in msg:
            replies[msg["id"]] = msg

    discover = replies.get("openai-mcp-discover", {})
    discover_clean = discover.get("error", {}).get("code") == -32601
    init_ok = "result" in replies.get(1, {})
    tools = replies.get(2, {}).get("result", {}).get("tools", [])
    info_reply = replies.get(3, {})
    info_ok, info_payload = _extract_tool_result(info_reply)
    broker_reachable = info_ok and isinstance(info_payload.get("instance_id"), str)
    broker_offline_structured = (
        not info_ok
        and info_reply.get("result", {}).get("isError") is True
        and info_payload.get("code") == "BROKER_OFFLINE"
    )
    info_handled = broker_reachable or broker_offline_structured
    mcp_instance_id = info_payload.get("instance_id") if broker_reachable else None

    proj_reply = replies.get(4, {})
    proj_ok_raw, proj_payload = _extract_tool_result(proj_reply)
    projects = proj_payload.get("projects") if proj_ok_raw else None
    project_identity = None
    project_list_ok = bool(proj_ok_raw and isinstance(projects, list))
    if project_list_ok and project_id is not None:
        matched = next((p for p in projects if p.get("project_id") == project_id), None)
        if matched is None:
            project_list_ok = False
        else:
            project_identity = {
                "project_id": matched.get("project_id"),
                "display_name": matched.get("display_name"),
                "policy_hash": matched.get("policy_hash"),
                "policy_revision": matched.get("policy_revision"),
            }

    file_read_ok: bool | None = None
    file_sha256: str | None = None
    if project_id is not None and file_path is not None:
        fr_ok, fr_payload = _extract_tool_result(replies.get(5, {}))
        content = fr_payload.get("content")
        digest = fr_payload.get("hash")
        file_read_ok = bool(
            fr_ok and isinstance(content, str) and fr_payload.get("truncated") is False
            and hashlib.sha256(content.encode("utf-8")).hexdigest() == digest
        )
        if file_read_ok:
            file_sha256 = digest

    project_resume_ok: bool | None = None
    resume_instance_id: str | None = None
    if project_id is not None:
        res_ok, res_payload = _extract_tool_result(replies.get(6, {}))
        resume_instance_id = res_payload.get("instance_id") if res_ok else None
        project_resume_ok = bool(
            res_ok
            and res_payload.get("handoff_ready") is True
            and mcp_instance_id is not None
            and resume_instance_id == mcp_instance_id
        )

    stderr_pydantic_spam = "validation error" in stderr_text.casefold()
    passed = (
        proc.returncode == 0
        and discover_clean
        and init_ok
        and len(tools) == 33
        and info_handled
        and not stdout_noise
        and not stderr_pydantic_spam
    )
    if broker_reachable and not project_list_ok:
        passed = False
    if project_id is not None:
        passed = bool(
            passed
            and broker_reachable
            and project_list_ok
            and (file_path is None or file_read_ok)
            and project_resume_ok
        )

    return {
        "status": "PASS" if passed else "FAIL",
        "returncode": proc.returncode,
        "latency_ms": elapsed_ms,
        "discover_clean_32601": discover_clean,
        "initialize_ok": init_ok,
        "tool_count": len(tools),
        "expected_tool_count_33": len(tools) == 33,
        "bridge_info_ok": broker_reachable,
        "broker_reachable": broker_reachable,
        "instance_id": mcp_instance_id,
        "project_list_ok": project_list_ok if broker_reachable else None,
        "file_read_ok": file_read_ok,
        "file_sha256": file_sha256,
        "project_resume_ok": project_resume_ok,
        "resume_instance_id": resume_instance_id,
        "project_identity": project_identity,
        "stdout_protocol_clean": not stdout_noise,
        "stderr_empty": not stderr_text.strip(),
        "stderr_validation_noise": stderr_pydantic_spam,
        "stderr_preview": redact_text(stderr_text.strip()[:400]) if not passed else "",
    }


def _check_tunnel_config(profile_path: Path | None) -> dict[str, Any]:
    if profile_path is None:
        return {"status": "NOT_CHECKED", "reason": "No profile path provided."}
    try:
        resolved = profile_path.resolve(strict=True)
    except OSError:
        return {"status": "FAIL", "reason": f"Profile file not found: {profile_path}"}
    raw = resolved.read_text(encoding="utf-8", errors="replace")
    has_loopback_target = "127.0.0.1" in raw or "localhost" in raw
    mentions_mcp = "mcp" in raw.casefold()
    return {
        "status": "PASS",
        "profile_path": str(resolved),
        "profile_sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
        "mentions_mcp": mentions_mcp,
        "mentions_local_bind": has_loopback_target,
    }


def _check_loopback_tunnel_health(url: str | None) -> dict[str, Any]:
    if not url:
        return {"status": "NOT_CHECKED", "reason": "No --tunnel-health-url supplied (external hosts are never probed)."}
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or (parsed.hostname or "").casefold() not in {"127.0.0.1", "localhost", "::1"}:
        raise DiagnosticError(
            "INVALID_ARGUMENT",
            "tunnel_health_url must be a local loopback http(s) URL (127.0.0.1, localhost, or ::1).",
        )
    try:
        resp = httpx.get(url, timeout=2.5, follow_redirects=False)
        return {
            "status": "PASS" if resp.status_code < 500 else "WARN",
            "url": url,
            "http_status": resp.status_code,
        }
    except Exception as exc:
        return {"status": "FAIL", "url": url, "error": redact_text(str(exc))}


def _read_state_readonly(db_file: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Inspect existing SQLite state strictly read-only without mutating or migrating rows."""
    uri = f"file:{db_file.resolve().as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        def _count(sql: str) -> int:
            try:
                return int(conn.execute(sql).fetchone()[0])
            except sqlite3.OperationalError:
                return 0

        inst = conn.execute("SELECT id, schema_version FROM instance WHERE slot = 1").fetchone()
        if inst is None:
            raise DiagnosticError("STATE_NOT_INITIALIZED", "SQLite instance row is missing.")
        snap = {
            "instance_id": inst["id"],
            "schema_version": int(inst["schema_version"]),
            "db_size_bytes": db_file.stat().st_size if db_file.exists() else 0,
            "projects": _count("SELECT COUNT(*) FROM projects"),
            "active_tasks": _count("SELECT COUNT(*) FROM tasks WHERE status='active'"),
            "active_jobs": _count("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running','cancelling')"),
            "active_workers": _count("SELECT COUNT(*) FROM workers WHERE status IN ('queued','starting','running')"),
            "connection_incidents": _count("SELECT COUNT(*) FROM connection_incidents"),
        }
        incidents: list[dict[str, Any]] = []
        try:
            rows = conn.execute(
                "SELECT id, source, category, http_status, summary, details, created_at "
                "FROM connection_incidents ORDER BY created_at DESC, id LIMIT 10"
            ).fetchall()
            incidents = [
                {
                    "incident_id": row["id"],
                    "source": row["source"],
                    "category": row["category"],
                    "http_status": row["http_status"],
                    "summary": row["summary"],
                    "details": json.loads(row["details"]),
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        except sqlite3.OperationalError:
            incidents = []
        observations: list[dict[str, Any]] = []
        try:
            obs_rows = conn.execute(
                "SELECT model_id, surface, capabilities_json, source, notes, observed_at "
                "FROM model_capabilities ORDER BY model_id, surface"
            ).fetchall()
            observations = [
                {
                    "model_id": row["model_id"],
                    "surface": row["surface"],
                    "capabilities": json.loads(row["capabilities_json"]),
                    "source": row["source"],
                    "notes": row["notes"],
                    "observed_at": row["observed_at"],
                }
                for row in obs_rows
            ]
        except sqlite3.OperationalError:
            observations = []
        return snap, incidents, observations
    finally:
        conn.close()


def run_doctor(
    state_path: Path,
    *,
    account: bool = False,
    probe_mcp: bool = False,
    profile_path: Path | None = None,
    tunnel_health_url: str | None = None,
    verify_acl_fn=None,
    e2e_project_id: str | None = None,
    e2e_file: str | None = None,
    e2e_task_id: str | None = None,
) -> dict[str, Any]:
    """Run layered P0 diagnostics across SQLite/ACL, local broker, MCP stdio, tunnel config, and host health."""
    from .broker import BridgeError, call_broker, verify_state_path

    now_utc = datetime.now(timezone.utc)
    layers: dict[str, Any] = {}

    # Layer 1: state_acl & SQLite (strictly read-only when DB exists)
    incidents: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    try:
        if not state_path.exists():
            layers["state_acl"] = {"status": "WARN", "reason": "State directory not initialized yet; run 'install'."}
        else:
            (verify_acl_fn or verify_state_path)(state_path)
            db_file = state_path / "state.sqlite3"
            if not db_file.is_file():
                layers["state_acl"] = {"status": "PASS", "state_db_initialized": False}
            else:
                snap, incidents, observations = _read_state_readonly(db_file)
                layers["state_acl"] = {"status": "PASS", "state_db_initialized": True, **snap}
    except Exception as exc:
        layers["state_acl"] = {"status": "FAIL", "error": redact_text(str(exc))}

    # Layer 2: local_broker / runner / host resources
    diag = runner.diagnose()
    res = sample_host_resources()
    git_ok = diag["execution"].get("git_executable_present", False)
    codex_ok = diag["execution"].get("vendor_executable_present", False)
    broker_info = {"code": "BROKER_BLOCKED_BY_STATE", "message": "Initialize or repair the protected state directory."}
    if layers["state_acl"]["status"] == "PASS":
        try:
            info = call_broker(state_path, "local", "bridge_info")
            state_id = layers["state_acl"].get("instance_id")
            if not isinstance(info, dict) or not state_id or info.get("instance_id") != state_id:
                raise BridgeError("BROKER_IDENTITY_MISMATCH", "The broker did not identify the current state database.")
            broker_info = info
        except (BridgeError, OSError, ValueError) as error:
            broker_info = {"code": getattr(error, "code", "BROKER_PROBE_FAILED"), "message": redact_text(str(error))}
    broker_reachable = "instance_id" in broker_info
    layers["local_broker"] = {
        "status": "PASS" if broker_reachable else "FAIL",
        "reachable": broker_reachable,
        "instance_id": broker_info.get("instance_id"),
        "error_code": broker_info.get("code"),
        "version": __version__,
        **diag,
        "resources": res,
        "git_ready": git_ok,
    }

    # Layer 3: mcp_stdio
    if probe_mcp:
        mcp_layer = _probe_mcp_stdio(
            state_path,
            principal="edge",
            project_id=e2e_project_id,
            file_path=e2e_file,
            task_id=e2e_task_id,
        )
        state_id = layers["state_acl"].get("instance_id")
        mcp_id = mcp_layer.get("instance_id")
        if state_id and mcp_id:
            mcp_layer["instance_id_matches_state"] = (state_id == mcp_id)
            if state_id != mcp_id:
                mcp_layer["status"] = "FAIL"
        layers["mcp_stdio"] = mcp_layer
    else:
        layers["mcp_stdio"] = {"status": "NOT_CHECKED", "reason": "Pass probe_mcp=True to run full stdio handshake probe."}

    # Layer 4 & 5: tunnel config & local loopback health
    layers["tunnel_config"] = _check_tunnel_config(profile_path)
    layers["tunnel_health"] = _check_loopback_tunnel_health(tunnel_health_url)

    # Layer 6: optional account metadata (zero LLM spend)
    account_summary = None
    if account:
        try:
            account_summary = probe_provider_account()
        except WorkerAccountBlocked as exc:
            account_summary = {"status": "BLOCKED", "code": exc.code}

    overall = "PASS"
    for key in ("state_acl", "local_broker", "mcp_stdio", "tunnel_config", "tunnel_health"):
        st = layers[key].get("status")
        if st == "FAIL":
            overall = "FAIL"
            break
        if st == "WARN":
            overall = "WARN"

    return {
        "overall_status": overall,
        "checked_at_utc": now_utc.isoformat(timespec="seconds"),
        "checked_at_riyadh": now_utc.astimezone(RIYADH_TZ).isoformat(timespec="seconds"),
        "bridge_version": __version__,
        "broker": broker_info,
        "layers": layers,
        "model_capabilities": capabilities.summarize_for_info(
            observations, principal="local", codex_present=codex_ok,
        ),
        "fallback_readiness": {
            "codex_present": codex_ok,
            "cli_module": "edge_bridge.cli",
            "model_agnostic": True,
        },
        "recent_incidents": _redact_obj(incidents),
        "account": _redact_obj(account_summary) if account_summary is not None else None,
        "known_upstream_reference": "https://github.com/openai/tunnel-client/issues/103",
    }


def run_isolated_e2e_probe(*, package_root: Path | None = None) -> dict[str, Any]:
    """Run an isolated local MCP-to-Broker E2E verification without touching live state or credentials."""
    from .broker import call_broker, setup_state, verify_state_path

    pkg_root = (package_root or Path(__file__).resolve().parents[1]).resolve()
    now_utc = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory(prefix="epb-e2e-") as tmp:
        temp_root = Path(tmp)
        temp_state = temp_root / "state"
        temp_proj = temp_root / "e2e-project"
        temp_proj.mkdir(parents=True, exist_ok=True)
        fixture_file = temp_proj / "README.txt"
        fixture_text = "Edge Project Bridge isolated E2E verification fixture\n"
        fixture_file.write_bytes(fixture_text.encode("utf-8"))
        expected_sha256 = hashlib.sha256(fixture_file.read_bytes()).hexdigest()

        setup_state(temp_state)
        discovery = temp_state / "broker.json"
        broker_proc = subprocess.Popen(
            [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(temp_state), "start", "--port", "0"],
            cwd=str(pkg_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        try:
            deadline = time.monotonic() + 15.0
            while not discovery.is_file() and time.monotonic() < deadline:
                if broker_proc.poll() is not None:
                    out, err = broker_proc.communicate(timeout=2)
                    raise DiagnosticError("BROKER_START_FAILED", redact_text(f"Broker exited early: {out} {err}"))
                time.sleep(0.05)
            if not discovery.is_file():
                raise DiagnosticError("BROKER_START_FAILED", "Timed out waiting for isolated broker.json.")

            reg = call_broker(temp_state, "local", "owner_register", {
                "root": str(temp_proj),
                "name": "E2E Probe Fixture",
            })
            project_id = reg["project_id"]
            call_broker(temp_state, "local", "owner_grant_edge", {"project_id": project_id})
            call_broker(temp_state, "local", "task_checkpoint", {
                "project_id": project_id,
                "task_id": "e2e-verify",
                "operation_id": "e2e-ckpt-1",
                "objective": "Verify isolated MCP to Broker E2E parity",
                "summary": "Isolated E2E verification checkpoint",
                "next_action": "Verify project_resume over Edge MCP",
            })
            local_info = call_broker(temp_state, "local", "bridge_info")
            local_proj_status = call_broker(temp_state, "local", "project_status", {"project_id": project_id})

            mcp_probe = _probe_mcp_stdio(
                temp_state,
                principal="edge",
                project_id=project_id,
                file_path="README.txt",
                task_id="e2e-verify",
                cwd=pkg_root,
            )

            verify_state_path(temp_state)
            state_acl = "PASS"
            broker_json_id = json.loads(discovery.read_text(encoding="utf-8")).get("instance_id")
            state_snap, _, _ = _read_state_readonly(temp_state / "state.sqlite3")
            state_id = state_snap["instance_id"]
            local_instance_id = local_info.get("instance_id")
            mcp_instance_id = mcp_probe.get("instance_id")
            resume_instance_id = mcp_probe.get("resume_instance_id")

            instance_ids = [state_id, broker_json_id, local_instance_id, mcp_instance_id, resume_instance_id]
            instance_id_match = all(isinstance(v, str) and v == state_id for v in instance_ids)

            mcp_proj = mcp_probe.get("project_identity") or {}
            project_identity_match = (
                mcp_proj.get("project_id") == project_id
                and mcp_proj.get("display_name") == "E2E Probe Fixture"
                and bool(mcp_proj.get("policy_hash"))
                and local_proj_status["project"].get("root_identity") == reg.get("root_identity")
            )
            file_sha256_match = mcp_probe.get("file_sha256") == expected_sha256

            passed = (
                state_acl == "PASS"
                and mcp_probe.get("status") == "PASS"
                and mcp_probe.get("tool_count") == 33
                and bool(mcp_probe.get("discover_clean_32601"))
                and bool(mcp_probe.get("bridge_info_ok"))
                and bool(mcp_probe.get("broker_reachable"))
                and bool(mcp_probe.get("project_list_ok"))
                and bool(mcp_probe.get("file_read_ok"))
                and bool(mcp_probe.get("project_resume_ok"))
                and file_sha256_match
                and instance_id_match
                and project_identity_match
            )
            return {
                "overall_status": "PASS" if passed else "FAIL",
                "isolated": True,
                "checked_at_utc": now_utc.isoformat(timespec="seconds"),
                "checked_at_riyadh": now_utc.astimezone(RIYADH_TZ).isoformat(timespec="seconds"),
                "bridge_version": __version__,
                "state_acl": state_acl,
                "tool_count": mcp_probe.get("tool_count"),
                "discover_clean_32601": mcp_probe.get("discover_clean_32601"),
                "bridge_info_ok": mcp_probe.get("bridge_info_ok"),
                "broker_reachable": mcp_probe.get("broker_reachable"),
                "project_list_ok": mcp_probe.get("project_list_ok"),
                "file_read_ok": mcp_probe.get("file_read_ok"),
                "project_resume_ok": mcp_probe.get("project_resume_ok"),
                "file_sha256_match": file_sha256_match,
                "instance_id": state_id,
                "instance_id_match": instance_id_match,
                "project_identity": {
                    "project_id": project_id,
                    "display_name": "E2E Probe Fixture",
                    "policy_hash": mcp_proj.get("policy_hash"),
                },
                "project_identity_match": project_identity_match,
                "mcp_stdio": mcp_probe,
            }
        finally:
            try:
                if broker_proc.poll() is None:
                    call_broker(temp_state, "local", "owner_stop")
                    broker_proc.wait(timeout=8)
            except Exception:
                pass
            if broker_proc.poll() is None:
                broker_proc.terminate()
                try:
                    broker_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    broker_proc.kill()
                    broker_proc.wait(timeout=5)
            for stream in (broker_proc.stdout, broker_proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass


def build_support_packet(
    state_path: Path,
    *,
    incident_note: str | None = None,
    probe_mcp: bool = True,
) -> dict[str, Any]:
    """Generate a non-secret, redacted diagnostic packet for upstream connector issues (e.g. HTTP 429)."""
    report = run_doctor(state_path, account=False, probe_mcp=probe_mcp)
    classification = classify_host_error(incident_note) if incident_note else None
    recent = report.get("recent_incidents", [])
    classified_recent = [
        {
            "incident_id": item["incident_id"],
            "created_at": item["created_at"],
            "source": item["source"],
            "category": item["category"],
            "http_status": item["http_status"],
            "summary": item["summary"],
            "classification": classify_host_error(item["summary"]),
        }
        for item in recent
    ]
    return {
        "packet_version": 1,
        "redacted": True,
        "generated_at_utc": report["checked_at_utc"],
        "generated_at_riyadh": report["checked_at_riyadh"],
        "bridge_version": report["bridge_version"],
        "instance_id": report["layers"].get("state_acl", {}).get("instance_id"),
        "symptom_classification": classification,
        "layers": report["layers"],
        "recent_incidents": classified_recent,
        "upstream_issue_reference": "https://github.com/openai/tunnel-client/issues/103",
        "note": "Secrets, auth tokens, cookies, emails, and userIds are excluded by policy.",
    }
