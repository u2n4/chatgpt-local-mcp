from pathlib import Path
import tempfile
import unittest

import httpx

from edge_bridge.broker import create_tokens, setup_state
from edge_bridge.context_packs import ContextPackManager
from edge_bridge.dashboard import DashboardError, DashboardServer
from edge_bridge.files import ProjectFiles
from edge_bridge.state import State


class DashboardAndContextPacksTests(unittest.TestCase):
    def test_context_packs_preserve_all_10_fields_and_skip_completed_steps_across_models(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            state_dir = base / "state"
            setup_state(state_dir)
            store = State(state_dir / "state.sqlite3")

            proj_dir = base / "proj"
            proj_dir.mkdir()
            (proj_dir / "mod.py").write_text("v = 1\n", encoding="utf-8")
            reg = store.register_project(str(proj_dir), "Continuity Proj", ProjectFiles.identity(proj_dir))
            pid = reg["project_id"]
            store.grant(pid, "edge", ["read"])

            store.ensure_task(pid, "dep-0", "Prerequisite task")
            store.checkpoint(
                pid,
                "local",
                "main-task",
                "Completed step A and verified mod.py",
                "op-cp-1",
                objective="Implement multi-model continuity",
                next_action="Run step B",
                changed_files=[{"path": "mod.py"}],
                test_evidence=[{"suite": "unit", "passed": True}],
                accepted_decisions=["Keep SQLite as source of truth"],
            )
            store.add_task_dependency(pid, "main-task", "dep-0")
            store.record_verification(pid, "chk-1", "PASS", "All unit checks passed", model="GPT-6 Pro")

            mgr = ContextPackManager(store)
            saved = mgr.build_and_save(
                pid,
                "main-task",
                principal="local",
                completed_steps=["Step A: initial implementation"],
                next_actions=["Step A: initial implementation", "Step B: integration test", "Step C: handoff"],
            )
            pack = saved["pack"]
            self.assertFalse(pack["hidden_reasoning_included"])
            self.assertEqual(pack["project_identity"]["project_id"], pid)
            self.assertEqual(pack["active_objective"], "Implement multi-model continuity")
            self.assertIn("Keep SQLite as source of truth", pack["accepted_decisions"])
            self.assertEqual(pack["task_dependencies"], ["dep-0"])
            self.assertEqual(len(pack["changed_file_hashes"]), 1)
            self.assertIsNotNone(pack["changed_file_hashes"][0]["sha256"])
            # Completed Step A is automatically filtered from next_actions
            self.assertEqual(pack["next_actions"], ["Step B: integration test", "Step C: handoff"])

            # Resume from Extra High and High models without repeating Step A
            res_xh = mgr.resume_from_pack(pid, "main-task", principal="edge", model_id="Extra High")
            self.assertEqual(res_xh["target_model"], "Extra High")
            self.assertIn("Step A: initial implementation", res_xh["skip_completed_steps"])
            self.assertNotIn("Step A: initial implementation", res_xh["next_actions"])

    def test_dashboard_loopback_auth_12_sections_and_emergency_stop_all(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            state_dir = base / "state"
            setup_state(state_dir)
            tokens = create_tokens(state_dir)
            store = State(state_dir / "state.sqlite3")

            proj_dir = base / "proj"
            proj_dir.mkdir()
            reg = store.register_project(str(proj_dir), "Dash <script>alert(1)</script> Proj", ProjectFiles.identity(proj_dir))
            pid = reg["project_id"]
            store.grant(pid, "edge", ["read"])

            with self.assertRaises(DashboardError) as bind_err:
                DashboardServer(state_dir, host="0.0.0.0")
            self.assertEqual(bind_err.exception.code, "INVALID_BIND_HOST")

            dash = DashboardServer(state_dir, host="127.0.0.1", port=0)
            url = dash.start_background()
            try:
                # 1. Unauthenticated request is rejected (401)
                r_unauth = httpx.get(f"{url}/api/overview", timeout=5.0)
                self.assertEqual(r_unauth.status_code, 401)

                # 2. Cross-origin request is rejected (403)
                r_origin = httpx.get(
                    f"{url}/api/overview",
                    headers={"X-Dashboard-Token": tokens["local"], "Origin": "http://evil.example.com"},
                    timeout=5.0,
                )
                self.assertEqual(r_origin.status_code, 403)

                # 3. Authenticated HTML and JSON overview contain all 12 required sections + XSS escaping + security headers
                r_html = httpx.get(f"{url}/", headers={"X-Dashboard-Token": tokens["local"]}, timeout=5.0)
                self.assertEqual(r_html.status_code, 200)
                self.assertIn("EDGE PROJECT BRIDGE", r_html.text)
                self.assertIn("Emergency Stop All", r_html.text)
                self.assertNotIn("<script>alert(1)</script>", r_html.text)
                self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", r_html.text)
                self.assertEqual(r_html.headers.get("x-content-type-options"), "nosniff")
                self.assertEqual(r_html.headers.get("x-frame-options"), "DENY")
                self.assertEqual(r_html.headers.get("referrer-policy"), "no-referrer")
                self.assertIn("default-src 'none'", r_html.headers.get("content-security-policy", ""))

                r_ov = httpx.get(f"{url}/api/overview", headers={"X-Dashboard-Token": tokens["local"]}, timeout=5.0)
                self.assertEqual(r_ov.status_code, 200)
                sections = r_ov.json()["result"]["sections"]
                expected_sections = {
                    "system_health",
                    "projects",
                    "active_agents",
                    "task_queue",
                    "running_jobs",
                    "resource_monitor",
                    "terminal_output",
                    "git_changes",
                    "tests_and_reports",
                    "approvals",
                    "session_history",
                    "emergency_stop_all",
                }
                self.assertEqual(set(sections.keys()), expected_sections)

                # 4. Arbitrary command execution endpoint is strictly forbidden (403)
                r_exec = httpx.post(f"{url}/api/exec", headers={"X-Dashboard-Token": tokens["local"]}, timeout=5.0)
                self.assertEqual(r_exec.status_code, 403)
                self.assertEqual(r_exec.json()["code"], "UNISOLATED_EXECUTION_FORBIDDEN")

                # 5. Edge token cannot trigger Emergency Stop All (403 PRINCIPAL_READ_ONLY)
                r_edge_stop = httpx.post(f"{url}/api/stop-all", headers={"X-Dashboard-Token": tokens["edge"]}, timeout=5.0)
                self.assertEqual(r_edge_stop.status_code, 403)
                self.assertEqual(r_edge_stop.json()["code"], "PRINCIPAL_READ_ONLY")

                # 6. Local owner token triggers Emergency Stop All cleanly (200)
                r_stop = httpx.post(f"{url}/api/stop-all", headers={"X-Dashboard-Token": tokens["local"]}, timeout=5.0)
                self.assertEqual(r_stop.status_code, 200)
                self.assertTrue(r_stop.json()["ok"])
            finally:
                dash.stop()
