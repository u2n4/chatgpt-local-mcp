"""Local tests use disposable SQLite databases and no provider credentials."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest

from edge_bridge.state import State, StateError


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "state.db"
        self.state = State(self.db)
        self.project = self.state.register_project(self.root / "workspace", "Fixture", "fixture-root")
        self.project_id = self.project["project_id"]

    def check_code(self, code, action, *args, **kwargs):
        with self.assertRaises(StateError) as raised:
            action(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)

    def test_reopen_preserves_project_and_instance_identity(self):
        state = State(self.db)
        self.assertEqual(self.state.instance_id, state.instance_id)
        self.assertEqual(self.project, state.get_project(self.project_id))
        self.assertEqual(self.project, state.register_project(self.root / "workspace", "New Name", "fixture-root"))
        self.check_code(
            "ROOT_IDENTITY_CHANGED", state.register_project, self.root / "workspace", "Fixture", "changed-root"
        )

    def test_remote_grant_is_project_specific_and_read_only(self):
        second = self.state.register_project(self.root / "other", "Other", "other-root")
        self.assertEqual([], self.state.list_projects("edge"))
        self.check_code("PROJECT_NOT_GRANTED", self.state.get_project, self.project_id, "edge")
        granted = self.state.grant(self.project_id, "edge", ["read"])
        self.assertEqual([granted], self.state.list_projects("edge"))
        self.check_code("PROJECT_NOT_GRANTED", self.state.get_project, second["project_id"], "edge")
        self.check_code("PROJECT_NOT_GRANTED", self.state.get_project, self.project_id, "edge", "write")
        self.check_code("PROJECT_NOT_GRANTED", self.state.checkpoint, self.project_id, "edge", "task", "Summary", "op")
        self.check_code("PROJECT_NOT_GRANTED", self.state.create_job, self.project_id, "edge", "task", "op", {})

    def test_grant_revision_and_revocation_survive_reopen(self):
        granted = self.state.grant(self.project_id, "edge", ["read"])
        self.assertEqual(granted, self.state.grant(self.project_id, "edge", ["read", "read"]))
        revoked = self.state.revoke(self.project_id, "edge")
        self.assertGreater(revoked["policy_revision"], granted["policy_revision"])
        self.assertNotEqual(revoked["policy_hash"], granted["policy_hash"])
        state = State(self.db)
        self.assertEqual([], state.list_projects("edge"))
        self.check_code("PROJECT_NOT_GRANTED", state.resume, self.project_id, "edge")

    def test_operations_dedup_conflict_and_principal_separation(self):
        state = self.state
        project = self.project_id
        state.grant(project, "agent", ["read", "write"])
        self.assertEqual("claimed", state.begin_operation(project, "local", "same", {"text": "one"}, "write")["status"])
        self.assertEqual("pending", state.begin_operation(project, "local", "same", {"text": "one"}, "write")["status"])
        self.check_code("VERSION_CONFLICT", state.begin_operation, project, "local", "same", {"text": "two"}, "write")
        state.finish_operation(project, "local", "same", {"hash": "value"})
        self.assertEqual(
            {"status": "succeeded", "result": {"hash": "value"}},
            state.begin_operation(project, "local", "same", {"text": "one"}, "write"),
        )
        self.assertEqual("claimed", state.begin_operation(project, "agent", "same", {"text": "two"}, "write")["status"])

    def test_concurrent_claims_have_one_winner(self):
        barrier = Barrier(6)

        def claim():
            barrier.wait(timeout=5)
            return self.state.begin_operation(self.project_id, "local", "concurrent", {"x": 1}, "write")["status"]

        with ThreadPoolExecutor(max_workers=6) as executor:
            statuses = [future.result(timeout=10) for future in [executor.submit(claim) for _ in range(6)]]
        self.assertEqual(1, statuses.count("claimed"))
        self.assertEqual(5, statuses.count("pending"))

    def test_checkpoint_packet_survives_database_restart(self):
        state = self.state
        project = self.project_id
        state.grant(project, "edge", ["read"])
        args = (project, "local", "task_example", "Fixed the fixture", "checkpoint-1")
        props = {"objective": "Fix calculator", "next_action": "Run tests", "changed_files": [{"path": "app.py", "sha256": "test"}]}
        first = state.checkpoint(*args, **props)
        self.assertEqual(first, state.checkpoint(*args, **props))
        self.check_code("VERSION_CONFLICT", state.checkpoint, *args, **{**props, "next_action": "Different"})
        before = state.resume(project, "edge", "task_example")
        after = State(self.db).resume(project, "edge", "task_example")
        self.assertEqual(before, after)
        self.assertEqual("Fix calculator", after["objective"])
        self.assertEqual(props["changed_files"], after["changed_files"])
        self.assertEqual(1, after["checkpoint_revision"])

    def test_pending_side_effect_and_running_job_require_reconciliation(self):
        state = self.state
        project = self.project_id
        state.begin_operation(project, "local", "file-1", "request", "write")
        job = state.create_job(project, "local", "task_example", "run-1", {"executable": "fixture"})
        state.update_job(job["job_id"], status="running")
        resumed = State(self.db)
        self.assertEqual("running", resumed.get_job(project, "local", job["job_id"])["status"])
        self.assertEqual({"operations": 1, "jobs": 1}, resumed.recover_orphans())
        self.assertEqual("unknown_after_restart", resumed.begin_operation(project, "local", "file-1", "request", "write")["status"])
        retry = resumed.create_job(project, "local", "task_example", "run-1", {"executable": "fixture"})
        self.assertFalse(retry["created"])
        self.assertEqual(job["job_id"], retry["job_id"])
        self.assertEqual("unknown_after_restart", retry["status"])
        self.assertEqual({"operations": 0, "jobs": 0}, resumed.recover_orphans())

    def test_job_detail_cannot_cross_project(self):
        job = self.state.create_job(self.project_id, "local", "example", "one", {"command": "fixture"})
        other = self.state.register_project(self.root / "other", "Other", "other")
        self.check_code("NOT_FOUND", self.state.get_job, other["project_id"], "local", job["job_id"])
        self.state.update_job(job["job_id"], status="running")
        self.state.update_job(job["job_id"], status="succeeded", exit_code=0, evidence={"bytes": 123})
        final = self.state.get_job(self.project_id, "local", job["job_id"])
        self.assertEqual(0, final["exit_code"])
        self.assertEqual({"bytes": 123}, final["evidence"])
        self.check_code("VERSION_CONFLICT", self.state.update_job, job["job_id"], status="running")

    def test_operation_failure_has_durable_receipt(self):
        state = self.state
        project = self.project_id
        state.begin_operation(project, "local", "write-failed", {"x": 3}, "write")
        state.finish_operation(project, "local", "write-failed", {"error": "VERSION_CONFLICT"}, failed=True)
        self.assertEqual(
            {"status": "failed", "result": {"error": "VERSION_CONFLICT"}},
            State(self.db).begin_operation(project, "local", "write-failed", {"x": 3}, "write"),
        )
        self.check_code("VERSION_CONFLICT", state.finish_operation, project, "local", "write-failed", {"x": 2})

    def test_artifact_record_is_bounded_and_project_scoped(self):
        project = self.project_id
        task = "fixture-task"
        self.state.checkpoint(project, "local", task, "Fixture test", "checkpoint-op")
        for path in (
            "../secret.txt", "C:/secret.txt", "\\\\host\\share", "job//log.txt", "job/./log.txt",
            "job/log.txt:stream", "job/NUL.txt", "job/log.txt.",
        ):
            with self.subTest(path=path):
                self.check_code(
                    "INVALID_INPUT", self.state.record_artifact, project, task, path, "a" * 64, 12, "text/plain",
                )
        args = (project, task, "job/log.txt", "a" * 64, 12, "text/plain")
        record = self.state.record_artifact(*args)
        self.assertEqual(record, self.state.record_artifact(*args))
        self.check_code(
            "VERSION_CONFLICT", self.state.record_artifact, *args[:-2], 14, "text/plain",
        )
        self.check_code("PROJECT_NOT_GRANTED", self.state.get_artifact, project, "edge", record["artifact_id"])
        self.state.grant(project, "edge", ["read"])
        self.assertEqual([record], State(self.db).list_artifacts(project, "edge", task))
        other = self.state.register_project(self.root / "other", "Other", "other")
        self.check_code("NOT_FOUND", self.state.get_artifact, other["project_id"], "local", record["artifact_id"])

    def test_verification_keeps_observed_model_separate_from_grants(self):
        self.state.grant(self.project_id, "edge", ["read"])
        original = self.state.get_project(self.project_id, "edge")
        record = self.state.record_verification(self.project_id, "A11", "BLOCKED", "No mutation entitlement.", "fixture")
        self.assertEqual([record], State(self.db).list_verification(self.project_id, "edge"))
        self.assertEqual(original, self.state.get_project(self.project_id, "edge"))
        self.check_code(
            "INVALID_INPUT", self.state.record_verification, self.project_id, "A11", "UNKNOWN", "No evidence.",
        )


if __name__ == "__main__":
    unittest.main()

