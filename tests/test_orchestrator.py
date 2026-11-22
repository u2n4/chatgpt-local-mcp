from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest

from edge_bridge.files import ProjectFiles
from edge_bridge.orchestrator import AgentOrchestrator, GlobalConcurrencyManager
from edge_bridge.runner import RunnerBlocked, git_path
from edge_bridge.state import State
from edge_bridge.workers import WorkerError, sample_host_resources


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        [str(git_path()), "-C", str(cwd), "-c", "user.name=Owner", "-c", "user.email=owner@localhost", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


class OrchestratorTests(unittest.TestCase):
    def test_dag_scheduling_adaptive_concurrency_isolation_conflict_and_stop_all(self):
        res = sample_host_resources(include_gpu=True)
        self.assertIn("disk_free_mb", res)
        self.assertIn("process_io_read_bytes", res)
        self.assertIn("gpu_available", res)

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            state_dir = base / "state"
            state_dir.mkdir()
            store = State(state_dir / "state.sqlite3")

            proj_dir = base / "repo"
            proj_dir.mkdir()
            (proj_dir / "a.py").write_text("x = 1\n", encoding="utf-8")
            (proj_dir / "b.py").write_text("y = 2\n", encoding="utf-8")
            _git(proj_dir, "init")
            _git(proj_dir, "add", ".")
            _git(proj_dir, "commit", "-m", "initial")

            reg = store.register_project(str(proj_dir), "Orch Repo", ProjectFiles.identity(proj_dir))
            pid = reg["project_id"]

            # Verify all 7 required roles exist
            profiles = {p["name"] for p in store.list_workers(project_id=pid)["profiles"]}
            self.assertTrue(
                {"planner", "explorer", "coder", "tester", "reviewer", "security_reviewer", "integrator"} <= profiles
            )

            conc = GlobalConcurrencyManager(initial_limit=1, max_limit=3, max_heavy_workers=1, max_queue_per_project=10)
            orch = AgentOrchestrator(store, state_dir, concurrency=conc)

            # Parallelization advisor checks overlapping vs disjoint file_scope
            self.assertFalse(orch.should_parallelize([{"task_id": "t1", "file_scope": ["a.py"]}])["parallel_recommended"])
            self.assertFalse(
                orch.should_parallelize(
                    [{"task_id": "t1", "file_scope": ["a.py"]}, {"task_id": "t2", "file_scope": ["a.py", "b.py"]}]
                )["parallel_recommended"]
            )
            self.assertTrue(
                orch.should_parallelize(
                    [{"task_id": "t1", "file_scope": ["a.py"]}, {"task_id": "t2", "file_scope": ["b.py"]}]
                )["parallel_recommended"]
            )

            # Privilege attenuation check at submission
            with self.assertRaises(WorkerError) as priv_err:
                orch.submit_task(
                    project_id=pid,
                    principal="local",
                    task_id="t-priv",
                    role="coder",
                    objective="Try write with read-only parent",
                    file_scope=["a.py"],
                    parent_capabilities={"read"},
                )
            self.assertEqual(priv_err.exception.code, "PRIVILEGE_ESCALATION_DENIED")

            # Enqueue DAG: t-plan -> (t-code-a, t-sec-review) -> t-integrate
            q_plan = orch.submit_task(
                project_id=pid,
                principal="local",
                task_id="t-plan",
                role="planner",
                objective="Plan module changes",
                file_scope=["a.py", "b.py"],
            )
            q_code_a = orch.submit_task(
                project_id=pid,
                principal="local",
                task_id="t-code-a",
                role="coder",
                objective="Update a.py",
                file_scope=["a.py"],
                depends_on=["t-plan"],
            )
            q_sec = orch.submit_task(
                project_id=pid,
                principal="local",
                task_id="t-sec-review",
                role="security_reviewer",
                objective="Audit b.py",
                file_scope=["b.py"],
                depends_on=["t-plan"],
            )

            # Only t-plan is initially runnable
            runnable1 = orch.resolve_runnable_tasks(pid)
            self.assertEqual([r["task_id"] for r in runnable1], ["t-plan"])

            # Execute t-plan (scales adaptive concurrency 1 -> 2)
            self.assertEqual(conc.current_limit, 1)
            res_plan = orch.execute_worker_item(q_plan)
            self.assertEqual(res_plan["status"], "succeeded")
            self.assertEqual(conc.current_limit, 2)

            # Now both t-code-a and t-sec-review are runnable
            runnable2 = {r["task_id"] for r in orch.resolve_runnable_tasks(pid)}
            self.assertEqual(runnable2, {"t-code-a", "t-sec-review"})

            # Read-only security_reviewer attempting file edit is rejected
            with self.assertRaises(WorkerError) as ro_err:
                orch.execute_worker_item(q_sec, mock_handler=lambda _ws, _q: {"b.py": "tampered\n"})
            self.assertEqual(ro_err.exception.code, "PRIVILEGE_ESCALATION_DENIED")

            # Scope violation by coder attempting to edit b.py outside ['a.py'] is rejected
            with self.assertRaises(WorkerError) as scope_err:
                orch.execute_worker_item(q_code_a, mock_handler=lambda _ws, _q: {"b.py": "outside scope\n"})
            self.assertEqual(scope_err.exception.code, "SCOPE_VIOLATION_DENIED")

            # Valid isolated coder execution in git worktree
            res_code_a = orch.execute_worker_item(
                q_code_a,
                prefer_worktree=True,
                mock_handler=lambda _ws, _q: {"a.py": "x = 42\n"},
            )
            self.assertEqual(res_code_a["status"], "succeeded")
            self.assertEqual(res_code_a["isolation_kind"], "git_worktree")
            # Main repo a.py is still untouched before serial integration
            self.assertEqual((proj_dir / "a.py").read_text(encoding="utf-8"), "x = 1\n")

            # Serial integration succeeds and creates durable checkpoint
            integrated = orch.integrate_worker_result(res_code_a)
            self.assertTrue(integrated["integrated"])
            self.assertEqual((proj_dir / "a.py").read_text(encoding="utf-8"), "x = 42\n")

            # Conflict detection: if user edits b.py after worker baseline, serial integration refuses to overwrite
            q_code_b = orch.submit_task(
                project_id=pid,
                principal="local",
                task_id="t-code-b",
                role="coder",
                objective="Update b.py",
                file_scope=["b.py"],
            )
            res_code_b = orch.execute_worker_item(
                q_code_b,
                mock_handler=lambda _ws, _q: {"b.py": "y = 99\n"},
            )
            # User modifies b.py directly on disk
            (proj_dir / "b.py").write_text("y = 777  # newer user edit\n", encoding="utf-8")
            with self.assertRaises(WorkerError) as conflict_err:
                orch.integrate_worker_result(res_code_b)
            self.assertEqual(conflict_err.exception.code, "MERGE_CONFLICT_NEWER_EDIT")
            self.assertIn("777", (proj_dir / "b.py").read_text(encoding="utf-8"))

            # Rate-limit backoff drops concurrency to 1 and blocks new slots until expiry
            conc.record_rate_limit(retry_after_seconds=1.5, reason="upstream_429")
            self.assertEqual(conc.current_limit, 1)
            q_explorer = orch.submit_task(
                project_id=pid,
                principal="local",
                task_id="t-explore",
                role="explorer",
                objective="Explore repo",
                file_scope=["a.py"],
            )
            with self.assertRaises(WorkerError) as rl_err:
                orch.execute_worker_item(q_explorer)
            self.assertEqual(rl_err.exception.code, "RATE_LIMIT_BACKOFF")
            conc.backoff_until = 0.0

            # Timeout enforcement
            q_timeout = orch.submit_task(
                project_id=pid,
                principal="local",
                task_id="t-timeout",
                role="explorer",
                objective="Slow task",
                file_scope=["a.py"],
                timeout_seconds=1,
            )
            q_timeout["timeout_seconds"] = 0.05
            with self.assertRaises(WorkerError) as to_err:
                orch.execute_worker_item(q_timeout, simulate_duration_s=0.3)
            self.assertEqual(to_err.exception.code, "WORKER_TIMEOUT")

            # Live worker cancellation + Global stop_all
            q_cancel = orch.submit_task(
                project_id=pid,
                principal="local",
                task_id="t-cancel",
                role="explorer",
                objective="Cancellable task",
                file_scope=["a.py"],
            )
            errors_seen: list[str] = []

            def _bg():
                try:
                    orch.execute_worker_item(q_cancel, simulate_duration_s=2.0)
                except WorkerError as exc:
                    errors_seen.append(exc.code)

            t = threading.Thread(target=_bg)
            t.start()
            deadline = time.monotonic() + 2.0
            while not orch.active_handles and time.monotonic() < deadline:
                time.sleep(0.02)
            stopped = orch.stop_all(reason="test_emergency_stop")
            t.join(timeout=3.0)
            self.assertGreaterEqual(stopped["stopped_count"], 1)
            self.assertEqual(errors_seen, ["WORKER_CANCELLED"])

            # Non-mock mode strictly enforces INCLUDED_ONLY / MXC gate (zero paid spend)
            q_mxc = orch.submit_task(
                project_id=pid,
                principal="local",
                task_id="t-mxc-blocked",
                role="reviewer",
                objective="Attempt live model worker",
                file_scope=["a.py"],
                mode="mxc",
            )
            with self.assertRaises(RunnerBlocked) as gate_err:
                orch.execute_worker_item(q_mxc)
            self.assertEqual(gate_err.exception.code, "WORKER_CAPABILITY_NOT_VERIFIED")
