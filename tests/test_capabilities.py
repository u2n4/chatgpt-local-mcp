"""Unit and integration tests for dynamic per-model capability detection, v2->v3 migration, and Codex fallback."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from edge_bridge import capabilities
from edge_bridge.broker import call_broker, setup_state
from edge_bridge.files import ProjectFiles
from edge_bridge.state import SCHEMA_VERSION, State, StateError


def _cli(state: Path, *args: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


class CapabilityTests(unittest.TestCase):
    def test_v1_and_v2_to_v3_migrations_preserve_data_and_worker_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            for source_version in (1, 2):
                with self.subTest(source_version=source_version):
                    sub = Path(tmp) / f"v{source_version}"
                    sub.mkdir()
                    db_path = sub / "state.sqlite3"
                    proj = sub / "proj"
                    proj.mkdir()
                    identity = ProjectFiles.identity(proj)

                    conn = sqlite3.connect(db_path)
                    conn.executescript(
                        """
                        CREATE TABLE instance (slot INTEGER PRIMARY KEY CHECK (slot = 1), id TEXT NOT NULL, schema_version INTEGER NOT NULL);
                        CREATE TABLE projects (id TEXT PRIMARY KEY, root TEXT NOT NULL, root_key TEXT NOT NULL UNIQUE, root_identity TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, policy_revision INTEGER NOT NULL DEFAULT 1);
                        CREATE TABLE grants (project_id TEXT NOT NULL, principal TEXT NOT NULL, capabilities TEXT NOT NULL, expires_at TEXT, revoked INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (project_id, principal));
                        CREATE TABLE python_test_scopes (project_id TEXT PRIMARY KEY, files TEXT NOT NULL);
                        CREATE TABLE node_test_scopes (project_id TEXT PRIMARY KEY, files TEXT NOT NULL);
                        CREATE TABLE tasks (project_id TEXT NOT NULL, id TEXT NOT NULL, objective TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', updated_at TEXT NOT NULL, PRIMARY KEY (project_id, id));
                        CREATE TABLE checkpoints (project_id TEXT NOT NULL, task_id TEXT NOT NULL, revision INTEGER NOT NULL, packet TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (project_id, task_id, revision));
                        CREATE TABLE operations (principal TEXT NOT NULL, project_id TEXT NOT NULL, id TEXT NOT NULL, request_hash TEXT NOT NULL, status TEXT NOT NULL, result TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (principal, project_id, id));
                        CREATE TABLE jobs (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, task_id TEXT NOT NULL, principal TEXT NOT NULL, operation_id TEXT NOT NULL, intent TEXT NOT NULL, status TEXT NOT NULL, exit_code INTEGER, evidence TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
                        CREATE TABLE events (sequence INTEGER PRIMARY KEY, project_id TEXT NOT NULL, job_id TEXT, kind TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL);
                        CREATE TABLE artifacts (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, task_id TEXT NOT NULL, storage_ref TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, media_type TEXT NOT NULL, created_at TEXT NOT NULL);
                        CREATE TABLE verification (sequence INTEGER PRIMARY KEY, project_id TEXT NOT NULL, check_id TEXT NOT NULL, verdict TEXT NOT NULL, evidence TEXT NOT NULL, model TEXT, created_at TEXT NOT NULL);
                        """
                    )
                    conn.execute("INSERT INTO instance VALUES (1, ?, ?)", (f"inst-v{source_version}", source_version))
                    conn.execute(
                        "INSERT INTO projects VALUES ('proj_legacy', ?, ?, ?, 'LegacyProj', 2)",
                        (str(proj), str(proj).casefold(), identity),
                    )
                    conn.execute(
                        "INSERT INTO tasks VALUES ('proj_legacy', 't-legacy', 'Keep v1/v2 data', 'active', '2026-11-18T00:00:00+00:00')"
                    )
                    conn.execute(
                        "INSERT INTO checkpoints VALUES ('proj_legacy', 't-legacy', 1, ?, '2026-11-18T00:00:00+00:00')",
                        (json.dumps({"summary": "Legacy summary", "next_action": "Continue", "changed_files": [], "test_evidence": [], "accepted_decisions": []}),),
                    )
                    conn.commit()
                    conn.close()

                    store = State(db_path)
                    self.assertEqual(SCHEMA_VERSION, 3)
                    self.assertEqual(store.instance_id, f"inst-v{source_version}")
                    self.assertEqual(store.health_snapshot()["schema_version"], 3)
                    self.assertGreaterEqual(len(store.list_workers()["profiles"]), 7)

                    resumed = store.resume("proj_legacy", "local", "t-legacy")
                    self.assertEqual(resumed["summary"], "Legacy summary")
                    self.assertTrue(resumed["handoff_ready"])
                    self.assertEqual(resumed["model_capabilities"]["preferred_default_model"], "GPT-6 Pro")
                    self.assertFalse(resumed["model_capabilities"]["allowlist_enforced"])

    def test_model_agnostic_observations_edge_enforcement_and_fallback_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "state.sqlite3"
            proj = root / "secret_local_project"
            proj.mkdir()
            store = State(db)
            p_rec = store.register_project(str(proj), "CapProj", ProjectFiles.identity(proj))
            pid = p_rec["project_id"]
            store.grant(pid, "edge", ["read"])
            store.checkpoint(pid, "local", "t-cap", "Check capabilities", "op-cap-1", objective="Preserve task")

            # Accept GPT-6 Pro, Extra High, High, Medium, AND any arbitrary future model without allowlist
            for model in ("GPT-6 Pro", "Extra High", "High", "Medium", "GPT-7.5-Nova-Preview"):
                obs = store.record_model_capability(
                    model,
                    "chatgpt_web_edge",
                    {"mcp_invoke": True, "mcp_read": True, "mcp_write": True, "file_write": True},
                    source="host_probe",
                    notes=f"Observed {model}",
                )
                self.assertEqual(obs["model_id"], model)

            # Merge additional observation for GPT-7.5-Nova-Preview
            merged = store.record_model_capability(
                "GPT-7.5-Nova-Preview",
                "chatgpt_web_edge",
                {"subagents": False},
                source="host_probe_2",
                merge=True,
            )
            self.assertTrue(merged["capabilities"]["mcp_read"])
            self.assertFalse(merged["capabilities"]["subagents"])

            # Verify unobserved capabilities remain None and edge enforces False on mutating caps even if host claimed True
            edge_agg = capabilities.aggregate_capabilities(store.list_model_capabilities(), principal="edge")
            nova_eff = next(m for m in edge_agg["by_model"] if m["model_id"] == "GPT-7.5-Nova-Preview")["effective_capabilities"]
            self.assertTrue(nova_eff["mcp_invoke"])
            self.assertTrue(nova_eff["mcp_read"])
            self.assertFalse(nova_eff["mcp_write"])
            self.assertFalse(nova_eff["file_write"])
            self.assertFalse(nova_eff["command_exec"])
            self.assertFalse(nova_eff["windows_control"])
            self.assertFalse(nova_eff["subagents"])

            pro_eff = next(m for m in edge_agg["by_model"] if m["model_id"] == "GPT-6 Pro")["effective_capabilities"]
            self.assertIsNone(pro_eff["subagents"])

            # Fallback plan masks local filesystem paths when principal == 'edge'
            fb_edge = capabilities.build_fallback_plan(
                project_id=pid,
                task_id="t-cap",
                operation_id="op-fb-1",
                principal="edge",
                required_capabilities=["file_write", "command_exec"],
                observations=store.list_model_capabilities(),
                model_id="GPT-6 Pro",
                state_dir_hint=str(root / "private_state_path"),
                project_root_hint=str(proj),
            )
            self.assertTrue(fb_edge["fallback_required"])
            self.assertTrue(fb_edge["task_preserved"])
            self.assertEqual(fb_edge["reason"], "EDGE_PRINCIPAL_READ_ONLY")
            self.assertEqual(fb_edge["missing_capabilities"], ["file_write", "command_exec"])
            self.assertNotIn("private_state_path", json.dumps(fb_edge))
            self.assertNotIn("secret_local_project", json.dumps(fb_edge))
            self.assertIn("op-fb-1", json.dumps(fb_edge))
            self.assertIn("edge_bridge.cli", json.dumps(fb_edge))
            self.assertIn("codex exec", json.dumps(fb_edge))

            # Deterministic State.resume() across reopen
            r1 = store.resume(pid, "edge", "t-cap")
            r2 = State(db).resume(pid, "edge", "t-cap")
            self.assertEqual(r1, r2)
            self.assertTrue(r1["fallback_plan"]["fallback_required"])

            # Invalid capability key fails closed
            with self.assertRaises(StateError):
                store.record_model_capability("GPT-6 Pro", "chatgpt_web_edge", {"unknown_cap": True}, source="test")

    def test_broker_and_cli_capability_endpoints(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            state = base / "state"
            proj = base / "proj"
            proj.mkdir()
            setup_state(state)

            # Offline CLI record + list
            rc, out, err = _cli(
                state,
                "model-capabilities",
                "--record",
                "--model",
                "Extra High",
                "--surface",
                "chatgpt_web_edge",
                "--caps-json",
                '{"mcp_invoke": true, "mcp_read": true, "file_write": false}',
                "--source",
                "offline_cli",
            )
            self.assertEqual(rc, 0, err)
            self.assertEqual(json.loads(out)["model_id"], "Extra High")

            proc = subprocess.Popen(
                [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "start", "--port", "0"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                ready = proc.stdout.readline()
                self.assertIn("Edge Project Bridge ready", ready)
                reg = call_broker(state, "local", "owner_register", {"root": str(proj), "name": "CapBroker"})
                pid = reg["project_id"]
                call_broker(state, "local", "owner_grant_edge", {"project_id": pid})

                info_edge = call_broker(state, "edge", "bridge_info")
                self.assertTrue(info_edge["model_capabilities"]["model_agnostic"])
                self.assertEqual(info_edge["model_capabilities"]["preferred_default_model"], "GPT-6 Pro")
                self.assertIn("Extra High", info_edge["model_capabilities"]["observed_models"])
                self.assertTrue(info_edge["local_codex_fallback"]["model_agnostic"])

                diag_edge = call_broker(state, "edge", "connection_diagnostics", {})
                self.assertIn("model_capabilities", diag_edge)
                self.assertIn("fallback_readiness", diag_edge)

                rc_fb, fb_out, fb_err = _cli(
                    state, "fallback-plan", pid, "--model", "Extra High", "--operation-id", "fb-cli-1",
                )
                self.assertEqual(rc_fb, 0, fb_err)
                fb_data = json.loads(fb_out)
                self.assertTrue(fb_data["fallback_required"])
                self.assertEqual(fb_data["operation_id"], "fb-cli-1")
            finally:
                try:
                    call_broker(state, "local", "owner_stop")
                    proc.wait(timeout=8)
                except Exception:
                    proc.terminate()
                    proc.wait(timeout=5)
                proc.stdout.close()
                proc.stderr.close()

    def test_128_char_task_id_end_to_end_checkpoint_and_mcp_project_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            state = base / "state"
            proj = base / "proj"
            proj.mkdir()
            setup_state(state)

            proc = subprocess.Popen(
                [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "start", "--port", "0"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertIn("Edge Project Bridge ready", proc.stdout.readline())
                reg = call_broker(state, "local", "owner_register", {"root": str(proj), "name": "LongTaskProj"})
                pid = reg["project_id"]
                call_broker(state, "local", "owner_grant_edge", {"project_id": pid})

                long_task_id = "task_" + ("a" * 123)
                self.assertEqual(len(long_task_id), 128)
                ckpt = call_broker(
                    state,
                    "local",
                    "task_checkpoint",
                    {
                        "project_id": pid,
                        "task_id": long_task_id,
                        "operation_id": "op-long-task-1",
                        "objective": "Survive 128-char task_id resume",
                        "summary": "Checkpoint with max 128-char task_id",
                        "next_action": "Resume via Edge MCP",
                    },
                )
                self.assertEqual(ckpt["task_id"], long_task_id)

                reqs = [
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "cap_128", "version": "1.0"}}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "project_resume", "arguments": {"project_id": pid, "task_id": long_task_id}}},
                ]
                mcp_proc = subprocess.run(
                    [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "mcp", "--principal", "edge"],
                    input="\n".join(json.dumps(r) for r in reqs) + "\n",
                    capture_output=True,
                    text=True,
                    timeout=25,
                )
                self.assertEqual(mcp_proc.returncode, 0, mcp_proc.stderr)
                replies = {json.loads(line)["id"]: json.loads(line) for line in mcp_proc.stdout.splitlines() if line.strip() and "id" in json.loads(line)}
                res = replies[2]["result"]
                self.assertFalse(res.get("isError"), res)
                payload = res["structuredContent"]["result"]
                self.assertEqual(payload["task_id"], long_task_id)
                self.assertTrue(payload["handoff_ready"])
                self.assertLessEqual(len(payload["fallback_plan"]["operation_id"]), 128)

                # Invalid task_id rejected in build_fallback_plan and JSON process_start command is valid JSON
                with self.assertRaises(ValueError):
                    capabilities.build_fallback_plan(
                        project_id=pid,
                        task_id='bad"task',
                        operation_id="op-valid-1",
                        principal="edge",
                        required_capabilities=["command_exec"],
                        observations=[],
                    )
                fb = capabilities.build_fallback_plan(
                    project_id=pid,
                    task_id=long_task_id,
                    operation_id="op-valid-2",
                    principal="edge",
                    required_capabilities=["command_exec"],
                    observations=[],
                )
                cmd_str = next(c["command"] for c in fb["commands"] if c["action"] == "run_local_tests")
                json_part = cmd_str.split("--json '", 1)[1][:-1]
                parsed_cmd_json = json.loads(json_part)
                self.assertEqual(parsed_cmd_json["task_id"], long_task_id)
            finally:
                try:
                    call_broker(state, "local", "owner_stop")
                    proc.wait(timeout=8)
                except Exception:
                    proc.terminate()
                    proc.wait(timeout=5)
                proc.stdout.close()
                proc.stderr.close()

    def test_cross_surface_capability_merge_is_order_independent(self):
        obs_web = {
            "model_id": "GPT-6 Pro",
            "surface": "chatgpt_web_edge",
            "capabilities": {"mcp_invoke": True, "file_write": False},
        }
        obs_cli = {
            "model_id": "GPT-6 Pro",
            "surface": "local_codex_cli",
            "capabilities": {"mcp_invoke": True, "file_write": True},
        }
        agg1 = capabilities.aggregate_capabilities([obs_web, obs_cli], principal="local")
        agg2 = capabilities.aggregate_capabilities([obs_cli, obs_web], principal="local")
        self.assertEqual(agg1["by_model"], agg2["by_model"])
        eff_local = agg1["by_model"][0]["effective_capabilities"]
        self.assertTrue(eff_local["file_write"])
        self.assertFalse(agg1["by_model"][0]["surfaces"]["chatgpt_web_edge"]["effective_capabilities"]["file_write"])
        self.assertTrue(agg1["by_model"][0]["surfaces"]["local_codex_cli"]["effective_capabilities"]["file_write"])

        # Reverse alphabetical surface names: a_local=True vs z_other=False and a_other=False vs z_local=True
        obs_a_false = {"model_id": "M", "surface": "a_surface", "capabilities": {"command_exec": False}}
        obs_z_true = {"model_id": "M", "surface": "z_surface", "capabilities": {"command_exec": True}}
        agg_az = capabilities.aggregate_capabilities([obs_a_false, obs_z_true], principal="local")
        self.assertTrue(agg_az["by_model"][0]["effective_capabilities"]["command_exec"])


if __name__ == "__main__":
    unittest.main()
