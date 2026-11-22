from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from edge_bridge.broker import Broker, call_broker, setup_state, verify_state_path
from edge_bridge.diagnostics import (
    DiagnosticError,
    _probe_mcp_stdio,
    build_support_packet,
    classify_host_error,
    redact_text,
    run_doctor,
    run_isolated_e2e_probe,
)
from edge_bridge.state import State


class _HealthHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class DiagnosticsTests(unittest.TestCase):
    def test_error_classification_redaction_loopback_and_doctor_mcp_probe(self):
        c429 = classify_host_error("MCP SSE probe returned 429 from openai.org")
        self.assertEqual(c429["category"], "UPSTREAM_CONNECTOR_RATE_LIMIT_429")
        self.assertFalse(c429["local_fixable"])
        self.assertEqual(c429["http_status"], 429)

        csess = classify_host_error("McpServerError: Session terminated")
        self.assertEqual(csess["category"], "MCP_SESSION_TERMINATED")

        cdisc = classify_host_error("server/discover returned Invalid request parameters")
        self.assertTrue(cdisc["local_fixable"])

        cdll = classify_host_error("exit_code=-1073741502 (0xC0000142)")
        self.assertEqual(cdll["category"], "MXC_NON_DEFAULT_DESKTOP_DLL_INIT")

        redacted = redact_text("Authorization: Bearer secret_abc123 user=alice@example.com api_key=xyz999")
        self.assertNotIn("secret_abc123", redacted)
        self.assertNotIn("alice@example.com", redacted)
        self.assertNotIn("xyz999", redacted)

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            setup_state(state)
            store = State(state / "state.sqlite3")
            store.record_incident("chatgpt", "http_429", "Bearer tok_123 -> 429 from openai.org", http_status=429)

            with self.assertRaises(DiagnosticError) as url_err:
                run_doctor(state, tunnel_health_url="https://openai.org/health")
            self.assertEqual(url_err.exception.code, "INVALID_ARGUMENT")

            server = HTTPServer(("127.0.0.1", 0), _HealthHandler)
            port = server.server_port
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            try:
                report = run_doctor(
                    state,
                    probe_mcp=True,
                    tunnel_health_url=f"http://127.0.0.1:{port}/healthz",
                    verify_acl_fn=verify_state_path,
                )
            finally:
                server.shutdown()
                server.server_close()
                t.join(2)

            self.assertEqual(report["layers"]["state_acl"]["status"], "PASS")
            self.assertEqual(report["overall_status"], "FAIL")
            self.assertEqual(report["layers"]["local_broker"]["status"], "FAIL")
            self.assertFalse(report["layers"]["local_broker"]["reachable"])
            self.assertEqual(report["layers"]["local_broker"]["error_code"], "BROKER_OFFLINE")
            self.assertEqual(report["layers"]["mcp_stdio"]["status"], "PASS")
            self.assertTrue(report["layers"]["mcp_stdio"]["stdout_protocol_clean"])
            self.assertTrue(report["layers"]["mcp_stdio"]["stderr_empty"])
            self.assertTrue(report["layers"]["mcp_stdio"]["discover_clean_32601"])
            self.assertFalse(report["layers"]["mcp_stdio"]["stderr_validation_noise"])
            self.assertGreaterEqual(report["layers"]["mcp_stdio"]["tool_count"], 30)
            self.assertEqual(report["layers"]["tunnel_health"]["status"], "PASS")

            packet = build_support_packet(state, incident_note="MCP SSE probe returned 429 from openai.org", probe_mcp=False)
            self.assertTrue(packet["redacted"])
            self.assertTrue(packet["generated_at_riyadh"].endswith("+03:00"))
            self.assertEqual(packet["symptom_classification"]["http_status"], 429)
            self.assertNotIn("tok_123", repr(packet))

    def test_stdio_does_not_verify_a_mismatched_file_hash(self):
        def response(identity, value):
            return {"id": identity, "result": {"structuredContent": {"result": value}}}

        replies = [
            {"id": "openai-mcp-discover", "error": {"code": -32601}},
            {"id": 1, "result": {}},
            {"id": 2, "result": {"tools": [{} for _ in range(33)]}},
            response(3, {"instance_id": "instance"}),
            response(4, {"projects": [{"project_id": "fixture"}]}),
            response(5, {"content": "sample", "hash": hashlib.sha256(b"not sample").hexdigest(), "truncated": False}),
            response(6, {"instance_id": "instance", "handoff_ready": True}),
        ]
        output = "\n".join(json.dumps(reply) for reply in replies).encode("utf-8")
        with patch("edge_bridge.diagnostics.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, output, b"")):
            report = _probe_mcp_stdio(Path("unused"), project_id="fixture", file_path="sample.txt")
        self.assertEqual(report["status"], "FAIL")
        self.assertFalse(report["file_read_ok"])
        self.assertIsNone(report["file_sha256"])

    def test_local_e2e_mcp_to_broker_handshake_and_identity_parity(self):
        report = run_isolated_e2e_probe()
        self.assertEqual(report["overall_status"], "PASS", report)
        self.assertTrue(report["isolated"])
        self.assertEqual(report["state_acl"], "PASS")
        self.assertEqual(report["tool_count"], 33)
        self.assertTrue(report["discover_clean_32601"])
        self.assertTrue(report["bridge_info_ok"])
        self.assertTrue(report["broker_reachable"])
        self.assertTrue(report["project_list_ok"])
        self.assertTrue(report["file_read_ok"])
        self.assertTrue(report["project_resume_ok"])
        self.assertTrue(report["file_sha256_match"])
        self.assertTrue(report["instance_id_match"])
        self.assertTrue(report["project_identity_match"])

    def test_doctor_e2e_isolated_cli_preserves_preexisting_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "existing-state"
            setup_state(state)
            store = State(state / "state.sqlite3")
            proj = Path(tmp) / "proj"
            proj.mkdir()
            store.register_project(str(proj), "Preexisting", "pre-id")
            (state / "owner.token").write_text("a" * 64, encoding="ascii")
            (state / "edge.token").write_text("b" * 64, encoding="ascii")
            (state / "ipc.pem").write_text("cert-fixture", encoding="ascii")
            (state / "ipc-key.pem").write_text("key-fixture", encoding="ascii")

            watched = ("state.sqlite3", "owner.token", "edge.token", "ipc.pem", "ipc-key.pem")
            before_hashes = {
                name: hashlib.sha256((state / name).read_bytes()).hexdigest()
                for name in watched
            }

            proc = subprocess.run(
                [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "doctor", "--json", "--e2e-isolated"],
                capture_output=True,
                text=True,
                timeout=45,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["overall_status"], "PASS")
            self.assertEqual(payload["tool_count"], 33)
            self.assertTrue(payload["instance_id_match"])

            after_hashes = {
                name: hashlib.sha256((state / name).read_bytes()).hexdigest()
                for name in watched
            }
            self.assertEqual(before_hashes, after_hashes)

    def test_doctor_and_owner_record_incident_redact_sensitive_dict_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            setup_state(state)
            store = State(state / "state.sqlite3")
            broker = Broker(store, state)

            # Record incident through broker.manage("owner_record_incident") with sensitive keys
            broker.manage(
                "owner_record_incident",
                {
                    "source": "chatgpt",
                    "category": "auth_probe",
                    "summary": "Header cookie=SECRET_HDR_1 password=SECRET_HDR_2 api_key=SECRET_HDR_3",
                    "http_status": 429,
                    "details": {
                        "cookie": "SENTINEL_COOKIE_VALUE",
                        "Set-Cookie": "SENTINEL_SET_COOKIE_VALUE",
                        "password": "SENTINEL_PASSWORD_VALUE",
                        "passwd": "SENTINEL_PASSWD_VALUE",
                        "api_key": "SENTINEL_API_KEY_VALUE",
                        "ApiKey": "SENTINEL_APIKEY_VALUE",
                        "X-API-Key": "SENTINEL_X_API_KEY_VALUE",
                        "session": "SENTINEL_SESSION_VALUE",
                        "bearer": "SENTINEL_BEARER_VALUE",
                        "private_key": "SENTINEL_PRIVKEY_VALUE",
                        "credential": "SENTINEL_CRED_VALUE",
                        "safe_note": "keep_this_visible",
                    },
                },
                "local",
            )
            # Also insert raw unredacted dict directly via State to verify doctor --json --probe-mcp redacts on read
            store.record_incident(
                "tunnel",
                "raw_test",
                "Diagnostic raw incident",
                details={
                    "cookie": "RAW_COOKIE_999",
                    "password": "RAW_PASS_888",
                    "api_key": "RAW_APIKEY_777",
                    "safe_field": "visible_raw",
                },
            )

            proc = subprocess.run(
                [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "doctor", "--json", "--probe-mcp"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
            incidents_dump = json.dumps(report["diagnostics"]["recent_incidents"])
            for sentinel in (
                "SENTINEL_COOKIE_VALUE",
                "SENTINEL_SET_COOKIE_VALUE",
                "SENTINEL_PASSWORD_VALUE",
                "SENTINEL_PASSWD_VALUE",
                "SENTINEL_API_KEY_VALUE",
                "SENTINEL_APIKEY_VALUE",
                "SENTINEL_X_API_KEY_VALUE",
                "SENTINEL_SESSION_VALUE",
                "SENTINEL_BEARER_VALUE",
                "SENTINEL_PRIVKEY_VALUE",
                "SENTINEL_CRED_VALUE",
                "RAW_COOKIE_999",
                "RAW_PASS_888",
                "RAW_APIKEY_777",
                "SECRET_HDR_1",
                "SECRET_HDR_2",
                "SECRET_HDR_3",
            ):
                self.assertNotIn(sentinel, incidents_dump)
                self.assertNotIn(sentinel, proc.stdout)
            self.assertIn("keep_this_visible", incidents_dump)
            self.assertIn("visible_raw", incidents_dump)

            # Verify persisted SQLite details from owner_record_incident were also redacted before storage
            persisted = json.dumps(store.list_incidents(limit=10))
            self.assertNotIn("SENTINEL_COOKIE_VALUE", persisted)
            self.assertNotIn("SENTINEL_PASSWORD_VALUE", persisted)
            self.assertNotIn("SENTINEL_API_KEY_VALUE", persisted)

    def test_mcp_interleaved_reinit_burst_never_raises_uninitialized_and_exposes_telemetry(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            state = base / "state"
            proj = base / "burst-proj"
            proj.mkdir()
            (proj / "alpha.py").write_text("burst_marker = 'OK_BURST'\n", encoding="utf-8")
            setup_state(state)

            broker_proc = subprocess.Popen(
                [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "start", "--port", "0"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertIn("Edge Project Bridge ready", broker_proc.stdout.readline())
                reg = call_broker(state, "local", "owner_register", {"root": str(proj), "name": "BurstProj"})
                pid = reg["project_id"]
                call_broker(state, "local", "owner_grant_edge", {"project_id": pid})

                # Interleave server/discover, multiple initialize calls, notifications/initialized,
                # concurrent file_search/file_read, and denied file_write in one stdio burst
                reqs: list[dict] = [
                    {"jsonrpc": "2.0", "id": "disc-0", "method": "server/discover"},
                    {"jsonrpc": "2.0", "id": "init-0", "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "burst", "version": "1.0"}}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                ]
                for i in range(1, 13):
                    reqs.append({"jsonrpc": "2.0", "id": f"search-{i}", "method": "tools/call", "params": {"name": "file_search", "arguments": {"project_id": pid, "query": "burst_marker"}}})
                    if i % 3 == 0:
                        # Inject concurrent re-initialize mid-burst (previously reset ServerSession to Initializing)
                        reqs.append({"jsonrpc": "2.0", "id": f"reinit-{i}", "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "burst-reinit", "version": "1.0"}}})
                        reqs.append({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
                    reqs.append({"jsonrpc": "2.0", "id": f"read-{i}", "method": "tools/call", "params": {"name": "file_read", "arguments": {"project_id": pid, "path": "alpha.py"}}})
                    if i % 4 == 0:
                        reqs.append({"jsonrpc": "2.0", "id": f"deny-{i}", "method": "tools/call", "params": {"name": "file_write", "arguments": {"project_id": pid, "operation_id": f"op-deny-{i}", "path": "alpha.py", "content": "x", "expected_hash": None}}})
                reqs.append({"jsonrpc": "2.0", "id": "info-final", "method": "tools/call", "params": {"name": "bridge_info", "arguments": {}}})
                reqs.append({"jsonrpc": "2.0", "id": "health-final", "method": "tools/call", "params": {"name": "bridge_health", "arguments": {}}})

                payload = "\n".join(json.dumps(r) for r in reqs) + "\n"
                proc = subprocess.run(
                    [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "mcp", "--principal", "edge"],
                    input=payload,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stderr, "")
                replies = {m["id"]: m for line in proc.stdout.splitlines() if line.strip() and "id" in (m := json.loads(line))}

                self.assertEqual(replies["disc-0"]["error"]["code"], -32601)
                self.assertEqual(replies["init-0"]["result"]["protocolVersion"], "2024-11-05")
                for i in (3, 6, 9, 12):
                    self.assertIn("result", replies[f"reinit-{i}"])
                    self.assertEqual(replies[f"reinit-{i}"]["result"]["protocolVersion"], "2025-11-25")

                for i in range(1, 13):
                    s_msg = replies[f"search-{i}"]
                    self.assertNotIn("error", s_msg, f"search-{i} failed: {s_msg}")
                    self.assertFalse(s_msg["result"].get("isError"), f"search-{i} isError: {s_msg}")
                    self.assertEqual(len(s_msg["result"]["structuredContent"]["result"]["matches"]), 1)

                    r_msg = replies[f"read-{i}"]
                    self.assertFalse(r_msg["result"].get("isError"), f"read-{i} isError: {r_msg}")
                    r_res = r_msg["result"]["structuredContent"]["result"]
                    self.assertIn("OK_BURST", r_res["content"])
                    self.assertFalse(r_res["principal_writable"])

                for i in (4, 8, 12):
                    d_sc = replies[f"deny-{i}"]["result"]["structuredContent"]
                    self.assertEqual(d_sc["code"], "BRIDGE_POLICY_DENIED")
                    self.assertEqual(d_sc["reason"], "PRINCIPAL_READ_ONLY")

                info_res = replies["info-final"]["result"]["structuredContent"]["result"]
                self.assertEqual(info_res["api_contract_version"], 1)
                self.assertEqual(info_res["sqlite_schema_version"], 3)

                health_res = replies["health-final"]["result"]["structuredContent"]["result"]
                self.assertEqual(health_res["sqlite_schema_version"], 3)
                tel = health_res["latency_telemetry"]
                self.assertGreaterEqual(tel["samples"], 20)
                self.assertIsNotNone(tel["p50_ms"])
                self.assertIsNotNone(tel["p95_ms"])
            finally:
                try:
                    call_broker(state, "local", "owner_stop")
                    broker_proc.wait(timeout=5)
                except Exception:
                    if broker_proc.poll() is None:
                        broker_proc.terminate()
                        broker_proc.wait(timeout=5)
                broker_proc.stdout.close()
                broker_proc.stderr.close()
