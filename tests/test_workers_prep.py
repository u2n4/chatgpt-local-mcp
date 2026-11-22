import tempfile
import unittest
from pathlib import Path

from edge_bridge.files import ProjectFiles
from edge_bridge.runner import RunnerBlocked
from edge_bridge.state import State
from edge_bridge.workers import (
    WorkerError,
    WorkerManager,
    build_worker_isolation_spec,
    check_resource_admission,
    sample_host_resources,
)


class WorkersPrepTests(unittest.TestCase):
    def test_host_resources_admission_isolation_and_fail_closed_gate(self):
        res = sample_host_resources(sample_cpu_window=True)
        self.assertGreater(res["ram_total_mb"], 0)
        self.assertGreaterEqual(res["ram_available_mb"], 0)
        self.assertTrue(0 <= res["ram_used_percent"] <= 100)
        if res["cpu_percent"] is not None:
            self.assertTrue(0.0 <= res["cpu_percent"] <= 100.0)

        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "state.sqlite3"
            proj = Path(tmp) / "proj"
            proj.mkdir()
            store = State(db)
            store.register_project(str(proj), "P1", ProjectFiles.identity(proj))
            store.checkpoint("proj_p1" if False else store.list_projects()[0]["project_id"], "local", "t1", "op1", "ok")
            pid = store.list_projects()[0]["project_id"]

            adm = check_resource_admission(store)
            self.assertIn("admitted", adm)
            self.assertEqual(adm["active_workers"], 0)

            mgr = WorkerManager(store)
            status = mgr.status(project_id=pid, principal="local", record_sample=True)
            self.assertFalse(status["enabled"])
            self.assertEqual(status["code"], "WORKER_CAPABILITY_NOT_VERIFIED")
            self.assertEqual(status["billing_policy"], "INCLUDED_ONLY")
            self.assertGreaterEqual(len(status["profiles"]), 7)

            profiles_by_name = {p["name"]: p for p in status["profiles"]}
            with self.assertRaises(WorkerError) as priv_err:
                build_worker_isolation_spec(
                    worker_id="w1",
                    project_id=pid,
                    task_id="t1",
                    profile=profiles_by_name["coder"],
                    parent_capabilities={"read"},
                    workspace_path=proj,
                )
            self.assertEqual(priv_err.exception.code, "PRIVILEGE_ESCALATION_DENIED")

            spec = build_worker_isolation_spec(
                worker_id="w2",
                project_id=pid,
                task_id="t1",
                profile=profiles_by_name["reviewer"],
                parent_capabilities={"read", "write"},
                workspace_path=proj,
            )
            self.assertFalse(spec["network_enabled"])
            self.assertFalse(spec["llm_spend_enabled"])

            with self.assertRaises(RunnerBlocked) as gate_err:
                mgr.start_worker(project_id=pid, principal="local", task_id="t1", profile_name="reviewer")
            self.assertEqual(gate_err.exception.code, "WORKER_CAPABILITY_NOT_VERIFIED")
