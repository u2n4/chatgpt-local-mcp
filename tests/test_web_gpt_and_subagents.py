"""Security, concurrency, and subagent stress tests for scoped web GPT workspaces and high-concurrency MCP/Broker."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from edge_bridge.broker import BridgeError, call_broker, setup_state
from edge_bridge.report_engine import generate_project_audit_report


class WebGptAndSubagentConcurrencyTests(unittest.TestCase):
    def test_scoped_web_gpt_permissions_mxc_test_report_audit_and_16_subagent_burst(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            state = base / "state"
            prod = base / "prod-repo"
            web_gpt = base / "web GPT"
            prod.mkdir()
            (prod / "app.py").write_text("VALUE = 42\n", encoding="utf-8")
            (prod / ".env").write_text("API_KEY=SUPER_SECRET_DO_NOT_LEAK\n", encoding="utf-8")

            (web_gpt / "reports").mkdir(parents=True)
            (web_gpt / "subagents").mkdir(parents=True)
            (web_gpt / "scratch").mkdir(parents=True)
            (web_gpt / "tests").mkdir(parents=True)
            (web_gpt / "scratch" / "__init__.py").write_text("", encoding="utf-8")
            (web_gpt / "scratch" / "harness.py").write_text(
                "def ping():\n    return 'WEB_GPT_MXC_OK'\n", encoding="utf-8",
            )
            (web_gpt / "tests" / "__init__.py").write_text("", encoding="utf-8")
            (web_gpt / "tests" / "test_smoke.py").write_text(
                "import unittest\nfrom scratch.harness import ping\n\n"
                "class Smoke(unittest.TestCase):\n"
                "    def test_ping(self):\n"
                "        self.assertEqual(ping(), 'WEB_GPT_MXC_OK')\n",
                encoding="utf-8",
            )

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

                prod_reg = call_broker(state, "local", "owner_register", {"root": str(prod), "name": "Prod Repo"})
                prod_id = prod_reg["project_id"]
                call_broker(state, "local", "owner_grant_edge", {"project_id": prod_id})

                wg_reg = call_broker(state, "local", "owner_register", {"root": str(web_gpt), "name": "web GPT"})
                wg_id = wg_reg["project_id"]
                grant_res = call_broker(
                    state,
                    "local",
                    "owner_grant_edge_scoped",
                    {"project_id": wg_id, "capabilities": ["read", "write", "checkpoint", "execute"]},
                )
                self.assertEqual(sorted(grant_res["capabilities"]), ["checkpoint", "execute", "read", "write"])
                call_broker(
                    state,
                    "local",
                    "owner_grant_python_tests",
                    {
                        "project_id": wg_id,
                        "files": [
                            "scratch/__init__.py",
                            "scratch/harness.py",
                            "tests/__init__.py",
                            "tests/test_smoke.py",
                        ],
                    },
                )

                # 1. Verify worker capability is NEVER allowed for edge even via owner_grant_edge_scoped
                with self.assertRaises(BridgeError) as bad_cap:
                    call_broker(
                        state,
                        "local",
                        "owner_grant_edge_scoped",
                        {"project_id": wg_id, "capabilities": ["read", "worker"]},
                    )
                self.assertEqual(bad_cap.exception.code, "BRIDGE_POLICY_DENIED")

                # 2. Verify edge can write report + checkpoint inside web GPT, but NOT delete/move and NOT write prod-repo
                w1 = call_broker(
                    state,
                    "edge",
                    "file_write",
                    {
                        "project_id": wg_id,
                        "operation_id": "wg-rep-1",
                        "path": "reports/live_audit.md",
                        "content": "# Live Web GPT Report\nStatus: OK\n",
                        "expected_hash": None,
                    },
                )
                self.assertTrue((web_gpt / "reports" / "live_audit.md").is_file())
                read_wg = call_broker(state, "edge", "file_read", {"project_id": wg_id, "path": "reports/live_audit.md"})
                self.assertTrue(read_wg["principal_writable"])
                self.assertEqual(read_wg["hash"], w1["hash"])

                # file_delete remains denied for edge even inside web GPT
                with self.assertRaises(BridgeError) as del_err:
                    call_broker(
                        state,
                        "edge",
                        "file_delete",
                        {
                            "project_id": wg_id,
                            "operation_id": "wg-del-denied",
                            "path": "reports/live_audit.md",
                            "expected_hash": w1["hash"],
                        },
                    )
                self.assertEqual(del_err.exception.code, "BRIDGE_POLICY_DENIED")

                # prod-repo stays strictly read-only for edge
                read_prod = call_broker(state, "edge", "file_read", {"project_id": prod_id, "path": "app.py"})
                self.assertFalse(read_prod["principal_writable"])
                with self.assertRaises(BridgeError) as prod_write_err:
                    call_broker(
                        state,
                        "edge",
                        "file_write",
                        {
                            "project_id": prod_id,
                            "operation_id": "prod-write-denied",
                            "path": "app.py",
                            "content": "VALUE = 0\n",
                            "expected_hash": read_prod["hash"],
                        },
                    )
                self.assertEqual(prod_write_err.exception.code, "BRIDGE_POLICY_DENIED")
                self.assertEqual(prod_write_err.exception.details.get("reason"), "PRINCIPAL_READ_ONLY")

                # .env inside prod-repo remains blocked
                with self.assertRaises(BridgeError) as env_err:
                    call_broker(state, "edge", "file_read", {"project_id": prod_id, "path": ".env"})
                self.assertEqual(env_err.exception.code, "PATH_OUTSIDE_ROOT")

                # 3. Verify edge can run real MXC-sandboxed Python tests inside web GPT and read redacted job_output
                job = call_broker(
                    state,
                    "edge",
                    "process_start",
                    {
                        "project_id": wg_id,
                        "task_id": "wg-mxc-test",
                        "operation_id": "wg-exec-1",
                        "executable": "python",
                        "argv": ["-B", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
                        "cwd_relative": ".",
                        "timeout_seconds": 30,
                    },
                )
                jid = job["job_id"]
                deadline = time.monotonic() + 25.0
                jstate = job
                while time.monotonic() < deadline:
                    jstate = call_broker(state, "edge", "job_get", {"project_id": wg_id, "job_id": jid})
                    if jstate["status"] in {"succeeded", "failed", "timed_out", "cancelled"}:
                        break
                    time.sleep(0.1)
                self.assertEqual(jstate["status"], "succeeded", jstate)
                self.assertEqual(jstate["exit_code"], 0)
                jout = call_broker(state, "edge", "job_output", {"project_id": wg_id, "job_id": jid})
                self.assertTrue(jout.get("redacted"))
                self.assertIn("OK", jout["output"])

                # 4. 16-Subagent concurrent burst: simultaneous reads + per-subagent report writes + MCP stdio burst
                def _subagent_worker(idx: int) -> tuple[str, str]:
                    r_prod = call_broker(state, "edge", "file_read", {"project_id": prod_id, "path": "app.py"})
                    self.assertIn("42", r_prod["content"])
                    w_sub = call_broker(
                        state,
                        "edge",
                        "file_write",
                        {
                            "project_id": wg_id,
                            "operation_id": f"subagent-write-{idx}",
                            "path": f"subagents/agent_{idx}.md",
                            "content": f"# Subagent {idx}\nRead app.py hash={r_prod['hash']}\n",
                            "expected_hash": None,
                        },
                    )
                    fl = call_broker(state, "edge", "file_list", {"project_id": prod_id, "path": "."})
                    self.assertGreaterEqual(len(fl["entries"]), 1)
                    return w_sub["path"], w_sub["hash"]

                with ThreadPoolExecutor(max_workers=16) as pool:
                    results = list(pool.map(_subagent_worker, range(16)))
                self.assertEqual(len(results), 16)
                for idx in range(16):
                    self.assertTrue((web_gpt / "subagents" / f"agent_{idx}.md").is_file())

                # Verify Broker telemetry recorded high concurrency cleanly
                health = call_broker(state, "edge", "bridge_health")
                tel = health["latency_telemetry"]
                self.assertGreaterEqual(tel["total_requests"], 48)
                self.assertGreaterEqual(tel["peak_concurrent"], 2)
                self.assertIsNotNone(tel["p50_ms"])
                self.assertIsNotNone(tel["p95_ms"])

                # 5. Automated report-audit engine writes redacted Markdown + JSON reports into web GPT/reports/
                rep = generate_project_audit_report(
                    state,
                    prod_id,
                    wg_id,
                    notes="Automated audit check token=SECRET_SHOULD_REDACT",
                )
                self.assertTrue(rep["ok"])
                md_read = call_broker(state, "edge", "file_read", {"project_id": wg_id, "path": rep["markdown_report"]["path"]})
                self.assertIn("Prod Repo", md_read["content"])
                self.assertNotIn("SECRET_SHOULD_REDACT", md_read["content"])
                self.assertIn("[REDACTED]", md_read["content"])
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


if __name__ == "__main__":
    unittest.main()
