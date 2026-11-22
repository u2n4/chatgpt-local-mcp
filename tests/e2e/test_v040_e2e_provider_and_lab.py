"""Stage 3-5 E2E Acceptance Test:
Verifies primary programming connector probe (Codex), Claude --bare safety block,
AGY soft-denial truthfulness, and BridgePulse Lab before/after evidence bundle integrity.
"""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import closing

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from compat.python.rust_bridge import find_rust_binary, invoke_rust_cli


class TestV040E2EProviderAndLab(unittest.TestCase):
    def setUp(self):
        self.rust_bin = find_rust_binary(REPO)
        if self.rust_bin is None:
            self.skipTest("Rust edge-bridge.exe not built yet")

    def test_provider_probes_report_honest_versions_and_included_only(self):
        probes = invoke_rust_cli(["providers"], repo_root=REPO)
        by_name = {p["provider"]: p for p in probes}
        self.assertIn("codex", by_name)
        self.assertIn("claude_code", by_name)
        self.assertIn("antigravity_agy", by_name)
        for p in probes:
            self.assertEqual(p["billing_policy"], "INCLUDED_ONLY")
        self.assertTrue(by_name["codex"]["installed"])
        self.assertTrue(by_name["codex"]["included_only_compatible"])

    def test_modern_http_discovers_and_validates_metadata_without_changing_legacy_stdio(self):
        with tempfile.TemporaryDirectory(prefix="bridge-http-mcp-") as temp:
            state = Path(temp) / "state"
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            cli = [str(self.rust_bin), "--state-dir", str(state)]
            trace = []
            with subprocess.Popen(
                cli + ["serve", "--port", str(port)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ) as server:
                try:
                    for attempt in range(60):
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                                break
                        except OSError:
                            self.assertIsNone(server.poll(), "isolated MCP server exited")
                            time.sleep(0.05)
                    else:
                        self.fail("isolated MCP server did not start listening")
                    token = (state / "edge.token").read_text(encoding="ascii").strip()
                    version = "2026-07-28"
                    meta = {"io.modelcontextprotocol/protocolVersion": version,
                            "io.modelcontextprotocol/clientCapabilities": {}}

                    def post(method, params, *, request_id=None, tool=None):
                        request = {"jsonrpc": "2.0", "method": method, "params": params}
                        if request_id is not None:
                            request["id"] = request_id
                        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                   "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": version,
                                   "Mcp-Method": method}
                        if tool is not None:
                            headers["Mcp-Name"] = tool
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            connection.request("POST", "/mcp", json.dumps(request), headers)
                            response = connection.getresponse()
                            raw = response.read()
                            body = json.loads(raw) if raw else None
                            trace.append({"request": request, "status": response.status, "response": body,
                                          "rpc_headers": {key: val for key, val in headers.items()
                                                          if key.startswith(("MCP-", "Mcp-"))}})
                            return response.status, body
                        finally:
                            connection.close()

                    status, discovery = post("server/discover", {"_meta": meta}, request_id=1)
                    self.assertEqual(status, 200)
                    self.assertIn(version, discovery["result"]["supportedVersions"])
                    self.assertEqual(discovery["result"]["resultType"], "complete")
                    params = {"name": "bridge_info", "arguments": {}, "_meta": meta}
                    status, error = post("tools/call", params, request_id=2, tool="project_list")
                    self.assertEqual((status, error["error"]["code"]), (400, -32020))
                    status, info = post("tools/call", params, request_id=3, tool="bridge_info")
                    self.assertEqual((status, info["result"]["resultType"]), (200, "complete"))
                    self.assertFalse(info["result"]["isError"])
                    self.assertEqual(post("notifications/cancelled", {"requestId": 3, "_meta": meta}), (202, None))
                finally:
                    server.terminate()
                    server.wait(timeout=5)

            legacy = subprocess.run(
                cli + ["mcp", "--principal", "edge"],
                input='{"jsonrpc":"2.0","id":1,"method":"server/discover"}\n',
                encoding="utf-8", capture_output=True, check=True, timeout=10,
            )
            self.assertEqual(json.loads(legacy.stdout)["error"]["code"], -32601)
            self.assertEqual(legacy.stderr, "")
            if trace_path := os.environ.get("EPB_MODERN_MCP_TRACE"):
                evidence = {"transport": "isolated loopback", "modern_http": trace,
                            "legacy_discovery": json.loads(legacy.stdout), "legacy_stderr_empty": True}
                Path(trace_path).write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    @unittest.skipUnless(sys.platform == "win32", "Windows containment is required")
    def test_rust_mxc_prerequisites_do_not_authorize_process_launch(self):
        with tempfile.TemporaryDirectory(prefix="bridge-mxc-gate-") as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            state = root / "state"
            probe = invoke_rust_cli(["doctor"], state_dir=state, repo_root=REPO)["containment"]
            self.assertFalse(probe["status"]["verified"])
            self.assertFalse(probe["automatic_weaker_fallback"])

            project_id = invoke_rust_cli(
                ["register", str(project), "--name", "MXC admission fixture"],
                state_dir=state, repo_root=REPO,
            )["project_id"]
            marker = project / "process-started.txt"
            command = [
                str(self.rust_bin), "--state-dir", str(state), "run-job",
                "--project-id", project_id, "--task-id", "mxc-gate", "--operation-id", "mxc-gate",
                "--cwd", str(project), "--executable", sys.executable, "--arg=-c",
                "--arg=from pathlib import Path; Path('process-started.txt').touch()",
                "--require-mxc", "--synthetic-data",
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("IsolationNotVerified", result.stderr)
            self.assertFalse(marker.exists())
            with closing(sqlite3.connect(state / "state.sqlite3")) as database:
                self.assertEqual(database.execute("SELECT COUNT(*) FROM durable_runs").fetchone()[0], 0)

    def test_bridgepulse_lab_evidence_bundle_signatures_verify(self):
        configured_bundle = os.environ.get("EPB_ACCEPTANCE_LAB_BUNDLE")
        bundle = Path(configured_bundle) if configured_bundle else REPO / "examples" / "bridgepulse-lab" / "evidence-bundle"
        before_json = bundle / "01-before-fail-manifest.json"
        after_json = bundle / "03-after-pass-manifest.json"
        pk_file = bundle / "signing-public-key.hex"
        if not (before_json.is_file() and after_json.is_file() and pk_file.is_file()):
            self.skipTest("Run scripts/run_v040_vertical_slice.py first")

        trusted_pk = pk_file.read_text(encoding="utf-8").strip()
        vb = invoke_rust_cli([
            "verify-evidence", str(before_json),
            "--trusted-key", trusted_pk,
            "--artifacts-dir", str(bundle / "01-before-artifacts"),
        ], repo_root=REPO)
        va = invoke_rust_cli([
            "verify-evidence", str(after_json),
            "--trusted-key", trusted_pk,
            "--artifacts-dir", str(bundle / "03-after-artifacts"),
        ], repo_root=REPO)
        self.assertEqual(vb["reported_verdict"], "FAIL")
        self.assertTrue(vb["overall_verified"])
        self.assertTrue(vb["device_key_trusted"])
        self.assertTrue(vb["artifacts_hashes_verified"])
        self.assertEqual(va["reported_verdict"], "PASS")
        self.assertTrue(va["overall_verified"])
        self.assertTrue(va["device_key_trusted"])
        self.assertTrue(va["artifacts_hashes_verified"])


if __name__ == "__main__":
    unittest.main()
