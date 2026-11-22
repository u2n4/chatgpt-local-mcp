import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from edge_bridge.files import FileBoundaryError, ProjectFiles
from edge_bridge.jobs import JobError, _recipe_spec, validate_project_test_files
from edge_bridge.state import SCHEMA_VERSION, State, StateError
from edge_bridge.worker_account import summarize_account


class P0FilesAndStateTests(unittest.TestCase):
    def test_large_file_read_lossy_utf8_and_binary_view_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            root.mkdir()
            (root / ".venv" / "lib").mkdir(parents=True)
            (root / ".venv" / "lib" / "ignored.py").write_text("SECRET_NEEDLE = 1\n", encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("SECRET_NEEDLE = 2\n", encoding="utf-8")

            # > 2 MiB and <= 32 MiB UTF-8 file
            big_text = ("alpha-line-1234567890\n" * 120_000)
            big_path = root / "big.log"
            big_path.write_bytes(big_text.encode("utf-8"))
            self.assertGreater(big_path.stat().st_size, 2 * 1024 * 1024)

            # Invalid UTF-8 file + binary file
            bad_bytes = b"hello\xff\xfebad\x00bytes"
            (root / "bad.txt").write_bytes(bad_bytes)
            (root / "blob.bin").write_bytes(b"\x7fELF\x00\x01\x02\x03")

            pf = ProjectFiles(root)
            page1 = pf.read("big.log", offset=0, limit=1000)
            self.assertTrue(page1["truncated"])
            self.assertTrue(page1["editable"])
            self.assertEqual(page1["encoding"], "utf-8")
            self.assertEqual(page1["hash"], hashlib.sha256(big_text.encode("utf-8")).hexdigest())

            with self.assertRaises(FileBoundaryError) as ctx:
                pf.read("bad.txt")
            self.assertEqual(ctx.exception.code, "UNSUPPORTED_FILE_ENCODING")
            self.assertIn("hint", ctx.exception.details)

            lossy = pf.read("bad.txt", lossy_utf8=True)
            self.assertEqual(lossy["encoding"], "utf-8-lossy")
            self.assertFalse(lossy["editable"])
            self.assertIn("hello", lossy["content"])

            bin_view = pf.view("blob.bin")
            self.assertEqual(bin_view["kind"], "binary")
            self.assertFalse(bin_view["previewable"])
            self.assertEqual(bin_view["header_hex"], "7f454c4600010203")

            rec = pf.list(".", recursive=True, max_depth=3, exclude_generated=True)
            listed_paths = [e["path"] for e in rec["entries"]]
            self.assertIn("src/app.py", listed_paths)
            self.assertNotIn(".venv/lib/ignored.py", listed_paths)

            hits = pf.search("SECRET_NEEDLE", exclude_generated=True)
            self.assertEqual([m["path"] for m in hits["matches"]], ["src/app.py"])
            self.assertGreaterEqual(hits["files_scanned"], 1)
            self.assertGreater(hits["bytes_scanned"], 0)

    def test_v1_to_v2_migration_dependencies_backup_and_plan_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "state.sqlite3"
            proj_root = Path(tmp) / "proj"
            proj_root.mkdir()
            identity = ProjectFiles.identity(proj_root)

            # Seed an authentic v1 DB first
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
            conn.execute("INSERT INTO instance VALUES (1, 'inst-v1-test', 1)")
            conn.execute(
                "INSERT INTO projects VALUES ('proj_1', ?, ?, ?, 'Proj1', 1)",
                (str(proj_root), str(proj_root).casefold(), identity),
            )
            conn.commit()
            conn.close()

            store = State(db_path)
            self.assertEqual(store.instance_id, "inst-v1-test")
            health = store.health_snapshot()
            self.assertEqual(health["schema_version"], SCHEMA_VERSION)
            self.assertEqual(health["projects"], 1)

            workers_meta = store.list_workers(project_id="proj_1", principal="local")
            self.assertGreaterEqual(len(workers_meta["profiles"]), 7)
            self.assertTrue(all(not p["enabled"] for p in workers_meta["profiles"]))

            store.checkpoint("proj_1", "local", "t1", "step 1", "op1", objective="Root task")
            store.checkpoint("proj_1", "local", "t2", "step 2", "op2", objective="Child task")
            dep = store.add_task_dependency("proj_1", "t2", "t1")
            self.assertEqual(dep["depends_on_task_id"], "t1")
            with self.assertRaises(StateError) as cycle_err:
                store.add_task_dependency("proj_1", "t1", "t2")
            self.assertEqual(cycle_err.exception.code, "INVALID_INPUT")

            policy = store.set_exec_policy("proj_1", max_files=64, max_total_bytes=1048576, allow_git=True)
            self.assertEqual(policy["max_files"], 64)
            task_info = store.get_task("proj_1", "local", "t2")
            self.assertEqual(task_info["depends_on"], ["t1"])

            inc = store.record_incident("chatgpt", "http_429", "MCP SSE probe returned 429 from openai.org", http_status=429)
            self.assertEqual(inc["http_status"], 429)
            self.assertEqual(len(store.list_incidents()), 1)

            backup_file = Path(tmp) / "backups" / "snap.sqlite3"
            b_info = store.backup_to(backup_file)
            self.assertEqual(b_info["integrity_check"], "ok")
            reopened = State(backup_file)
            self.assertEqual(reopened.instance_id, "inst-v1-test")

            for ptype in ("prolite", "promax", "ent26", "enterprise_cbp_automation", "sci_plus", "go"):
                rep = summarize_account(
                    {"account": {"type": "chatgpt", "planType": ptype, "email": "private@example.com"}},
                    {"rateLimits": {"credits": {"hasCredits": False}}},
                    {"data": [{"model": "gpt-5.4"}]},
                )
                self.assertEqual(rep["plan"], ptype)
                self.assertFalse(rep["workers_enabled"])
                self.assertNotIn("private@example.com", repr(rep))

    def test_powershell_recipe_policy_and_injection_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp) / "psproj"
            proj.mkdir()
            (proj / "check.ps1").write_text("Write-Output 'OK'\n", encoding="utf-8")
            project = {"project_id": "proj_ps", "root": str(proj), "root_identity": ProjectFiles.identity(proj)}

            approved = validate_project_test_files(project, "powershell", ["check.ps1"])
            self.assertEqual(approved, ["check.ps1"])

            with self.assertRaises(JobError):
                validate_project_test_files(project, "powershell", ["../escape.ps1"])

            recipe, entry = _recipe_spec(
                "powershell",
                ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "check.ps1"],
                ".",
            )
            self.assertEqual(recipe, "powershell_script")
            self.assertEqual(entry, "check.ps1")

            with self.assertRaises(JobError) as inj:
                _recipe_spec("powershell", ["-NoProfile", "-Command", "Get-Process"], ".")
            self.assertEqual(inj.exception.code, "EXECUTION_REQUEST_UNSUPPORTED")

            modern_recipe, modern_entry = _recipe_spec(
                "powershell",
                ["-NoProfile", "-NonInteractive", "-File", "check.ps1"],
                ".",
            )
            self.assertEqual(modern_recipe, "powershell_script")
            self.assertEqual(modern_entry, "check.ps1")
            self.assertEqual(modern_entry, entry)

            with self.assertRaises(JobError):
                _recipe_spec(
                    "powershell",
                    ["-NoProfile", "-NonInteractive", "-File", "check.ps1", "extra"],
                    ".",
                )

            from edge_bridge import runner as _ps_runner
            _payload_argv = _ps_runner._payload_command(proj, "powershell_script", "check.ps1")
            self.assertNotIn("-ExecutionPolicy", _payload_argv)
            self.assertNotIn("Bypass", _payload_argv)
            self.assertIn("-NoProfile", _payload_argv)
            self.assertIn("-NonInteractive", _payload_argv)
            self.assertIn("-File", _payload_argv)
