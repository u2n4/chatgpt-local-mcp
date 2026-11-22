import hashlib
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path


class ProReviewContractTest(unittest.TestCase):
    def test_reviewer_creates_reports_only_until_grant_is_revoked(self):
        override = os.environ.get("EPB_MCP_TEST_BINARY")
        repo = Path(__file__).resolve().parents[2]
        binary = Path(override) if override is not None else (
            repo / "target" / "x86_64-pc-windows-gnullvm" / "release" / "edge-bridge.exe"
        )
        if override is not None:
            self.assertTrue(binary.is_file(), f"explicit worker binary missing: {binary}")
        if not binary.is_file():
            self.skipTest(f"local worker binary not found: {binary}")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            project = temp / "project"
            project.mkdir()
            sentinel = project / "source.txt"
            original = b"owner's original work\n"
            sentinel.write_bytes(original)
            command = [
                str(binary), "--state-dir", str(temp / "state"),
                "--environment-kind", "canary",
            ]

            def cli(*args, check=True, stdin=None):
                return subprocess.run(
                    [*command, *args], check=check, input=stdin,
                    capture_output=True, encoding="utf-8", timeout=30,
                )

            registered = json.loads(cli("register", str(project), "--name", "Pro review fixture").stdout)
            project_id = registered["project_id"]
            for flag, value in [("--writable-path", "_pro/**"), ("--recipe", "python_tests")]:
                with self.subTest(flag=flag):
                    rejected = cli(
                        "grant-create", project_id, "--profile", "pro-review", flag, value, check=False,
                    )
                    self.assertEqual(rejected.returncode, 2, rejected.stderr)
                    self.assertIn(flag, rejected.stderr)
                    self.assertIn("--profile", rejected.stderr)

            grant_help = cli("grant-create", "--help").stdout
            self.assertIn("no writable paths", grant_help.lower())
            self.assertNotIn("src/**", grant_help)
            self.assertNotIn("!", grant_help)

            def grant_count():
                with closing(sqlite3.connect(temp / "state" / "state.sqlite3")) as db:
                    return db.execute("SELECT COUNT(*) FROM task_grants").fetchone()[0]

            before_bad_grants = grant_count()
            for bad_pattern in ("!x", "", r"a\b", "/x"):
                with self.subTest(bad_writable_path=bad_pattern):
                    rejected = cli(
                        "grant-create", project_id, "--writable-path", bad_pattern, check=False,
                    )
                    self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
                    self.assertIn("--writable-path", rejected.stderr)
            self.assertEqual(grant_count(), before_bad_grants)

            bare = json.loads(cli("grant-create", project_id, "--requester", "executor:bare").stdout)
            self.assertCountEqual(bare["permitted_categories"], ["read", "git_read", "execute_recipe"])
            self.assertEqual(bare["writable_paths"], [])
            self.assertEqual(bare["allowed_recipes"], ["python_tests"])

            bare_write = json.loads(cli(
                "mcp", "--principal", "executor:bare",
                stdin=json.dumps({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "file_write", "arguments": {
                        "project_id": project_id, "grant_id": bare["grant_id"],
                        "operation_id": "op_bare_write", "path": "src/new.py", "content": "denied",
                    }},
                }) + "\n",
            ).stdout)["result"]
            self.assertTrue(bare_write["isError"], bare_write)
            self.assertEqual(bare_write["structuredContent"]["code"], "BRIDGE_POLICY_DENIED")
            self.assertFalse((project / "src" / "new.py").exists())

            bare_submit = json.loads(cli(
                "mcp", "--principal", "executor:bare",
                stdin=json.dumps({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "task_submit", "arguments": {
                        "project_id": project_id, "grant_id": bare["grant_id"],
                        "task_id": "task_bare", "operation_id": "op_bare_submit", "recipe": "python_tests",
                    }},
                }) + "\n",
            ).stdout)["result"]
            self.assertFalse(bare_submit["isError"], bare_submit)

            explicit = json.loads(cli(
                "grant-create", project_id, "--requester", "executor:explicit",
                "--writable-path", "_pro/**",
            ).stdout)
            self.assertIn("patch", explicit["permitted_categories"])
            self.assertIn("checkpoint", explicit["permitted_categories"])
            self.assertEqual(explicit["writable_paths"], ["_pro/**"])
            self.assertEqual(explicit["allowed_recipes"], ["python_tests"])

            grant = json.loads(cli("grant-create", project_id, "--profile", "pro-review").stdout)
            grant_id = grant["grant_id"]
            self.assertEqual(grant["requester_principal"], "executor:default")
            self.assertCountEqual(grant["permitted_categories"], ["read", "git_read", "write", "execute_recipe"])
            self.assertEqual(grant["writable_paths"], ["_pro/**"])
            self.assertEqual(grant["allowed_recipes"], ["python_tests", "powershell_script"])
            self.assertEqual(
                datetime.fromisoformat(grant["expires_at"]) - datetime.fromisoformat(grant["created_at"]),
                timedelta(minutes=60),
            )

            def write(operation_id, path, content, **options):
                return {
                    "project_id": project_id, "grant_id": grant_id, "operation_id": operation_id,
                    "path": path, "content": content, **options,
                }

            def mcp_writes(*arguments):
                frames = [
                    {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized"},
                ]
                for rpc_id, args in enumerate(arguments, 1):
                    frames.append({
                        "jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
                        "params": {"name": "file_write", "arguments": args},
                    })
                output = cli(
                    "mcp", "--principal", "executor:default",
                    stdin="".join(json.dumps(frame) + "\n" for frame in frames),
                ).stdout
                responses = {frame["id"]: frame["result"] for frame in map(json.loads, output.splitlines())}
                self.assertEqual(set(responses), set(range(len(arguments) + 1)))
                self.assertIn("_pro/reports/", responses[0]["instructions"][:512])
                return [responses[rpc_id] for rpc_id in range(1, len(arguments) + 1)]

            def assert_error(result, code):
                self.assertTrue(result["isError"], result)
                self.assertEqual(result["structuredContent"]["code"], code)

            report_path = "_pro/reports/review.md"
            report = "Verified review — café\r\n"
            report_bytes = report.encode("utf-8")
            create = write("op_create", report_path, report, expected_hash=None)
            created, overwrite, duplicate, outside, existing, short_name, device = mcp_writes(
                create,
                write("op_overwrite", report_path, "changed", expected_hash=hashlib.sha256(report_bytes).hexdigest()),
                write("op_duplicate", report_path, "changed"),
                write("op_outside", "outside.md", "outside"),
                write("op_existing", "source.txt", "changed"),
                write("op_short", "_pro/CREDEN~1/report.md", "denied"),
                write("op_device", "_pro/com².txt", "denied"),
            )
            self.assertFalse(created["isError"], created)
            self.assertEqual(created["structuredContent"]["result"]["files_applied"], [report_path])
            self.assertEqual((project / report_path).read_bytes(), report_bytes)
            assert_error(overwrite, "BRIDGE_POLICY_DENIED")
            self.assertIn("choose a new file name", overwrite["structuredContent"]["next_action"])
            self.assertNotIn("owner grant", overwrite["structuredContent"]["next_action"])
            assert_error(duplicate, "VERSION_CONFLICT")
            self.assertNotIn("error_code", duplicate["structuredContent"])
            self.assertIn("Choose a new file name", duplicate["structuredContent"]["next_action"])
            self.assertNotIn("Re-read the latest file hash", duplicate["structuredContent"]["next_action"])
            assert_error(outside, "BRIDGE_POLICY_DENIED")
            assert_error(existing, "BRIDGE_POLICY_DENIED")
            assert_error(short_name, "BRIDGE_POLICY_DENIED")
            self.assertNotIn("owner grant", short_name["structuredContent"]["next_action"])
            assert_error(device, "UNSUPPORTED_PATH_TYPE")

            owner_only_tools = [
                "file_move", "file_delete", "process_start", "process_input", "job_changes",
                "task_checkpoint", "git_checkpoint", "git_integrate",
                "worker_start", "worker_steer", "worker_cancel",
            ]
            owner_only_frames = [
                {"jsonrpc": "2.0", "id": idx, "method": "tools/call",
                 "params": {"name": tool, "arguments": {"project_id": project_id, "grant_id": grant_id}}}
                for idx, tool in enumerate(owner_only_tools, 1)
            ]
            owner_only_output = cli(
                "mcp", "--principal", "executor:default",
                stdin="".join(json.dumps(frame) + "\n" for frame in owner_only_frames),
            ).stdout
            owner_only_responses = {frame["id"]: frame["result"] for frame in map(json.loads, owner_only_output.splitlines())}
            for idx, tool in enumerate(owner_only_tools, 1):
                with self.subTest(owner_only_tool=tool):
                    res = owner_only_responses[idx]
                    assert_error(res, "BRIDGE_POLICY_DENIED")
                    self.assertNotIn("error_code", res["structuredContent"])
                    hint = res["structuredContent"]["next_action"]
                    self.assertIn("owner-only", hint)
                    self.assertIn("locally", hint)
                    self.assertNotIn("Request an explicit owner grant", hint)

            local_conflict_frame = {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "file_write", "arguments": {
                    "project_id": project_id, "operation_id": "op_local_dup",
                    "path": report_path, "content": "owner duplicate",
                }},
            }
            local_conflict = json.loads(cli(
                "mcp", "--principal", "local", stdin=json.dumps(local_conflict_frame) + "\n",
            ).stdout)["result"]
            assert_error(local_conflict, "VERSION_CONFLICT")
            self.assertIn("Re-read the latest file hash", local_conflict["structuredContent"]["next_action"])
            invalid_operation, invalid_task, invalid_component = mcp_writes(
                write("folder/operation", "_pro/invalid-operation.md", "denied"),
                write("op_bad_task", "_pro/invalid-task.md", "denied", task_id="folder/task"),
                write("op_bad_component", f"_pro/{'a' * 256}", "denied"),
            )
            for result in [invalid_operation, invalid_task, invalid_component]:
                assert_error(result, "INVALID_ARGUMENT")
                self.assertNotIn(str(project), result["structuredContent"]["message"])
            self.assertFalse((project / "_pro/invalid-operation.md").exists())
            self.assertFalse((project / "_pro/invalid-task.md").exists())
            self.assertEqual(len(list((temp / "state/patch-journals").glob("pjr_*"))), 1)
            self.assertFalse((project / "outside.md").exists())
            self.assertEqual(sentinel.read_bytes(), original)

            inbox_dir = project / "_pro" / "inbox"
            inbox_dir.mkdir(parents=True, exist_ok=True)
            inbox_req = inbox_dir / "20261122T000000Z-codex-request.md"
            inbox_req.write_bytes(b"Please review.\n")

            inbox_read_frames = [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": "file_list", "arguments": {"project_id": project_id, "path": "_pro/inbox"}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "file_read", "arguments": {
                     "project_id": project_id, "path": "_pro/inbox/20261122T000000Z-codex-request.md",
                 }}},
            ]
            inbox_read_out = cli(
                "mcp", "--principal", "executor:default",
                stdin="".join(json.dumps(frame) + "\n" for frame in inbox_read_frames),
            ).stdout
            inbox_reads = {frame["id"]: frame["result"] for frame in map(json.loads, inbox_read_out.splitlines())}
            self.assertFalse(inbox_reads[1]["isError"], inbox_reads[1])
            self.assertFalse(inbox_reads[2]["isError"], inbox_reads[2])
            self.assertEqual(inbox_reads[2]["structuredContent"]["result"]["content"], "Please review.\n")

            inbox_denied_paths = [
                "_pro/inbox/forged.md",
                "_pro/INBOX/forged.md",
                "_PRO/Inbox/forged.md",
                "_pro/inbox/nested/forged.md",
                "_pro/inbox",
                "_pro/INBOX",
            ]
            inbox_hazard_paths = [
                "_pro/./inbox/x",
                "_pro//inbox/x",
                "_pro/inbox./x",
                "_pro/inbox /x",
                "_pro/inbox.",
                "_pro/inbox ",
                "_pro\\inbox\\x",
                "_pro/outbox/../inbox/x",
                "_pro/INBOX~1/x",
            ]
            outbox_ok, sibling_ok, *inbox_results = mcp_writes(
                write("op_outbox_ok", "_pro/outbox/reply.md", "RESULT: INFO\n"),
                write("op_inbox_notes_ok", "_pro/inbox_notes/ok.md", "allowed sibling\n"),
                *(write(f"op_inbox_{idx}", p, "forged") for idx, p in enumerate(inbox_denied_paths + inbox_hazard_paths)),
            )
            self.assertFalse(outbox_ok["isError"], outbox_ok)
            self.assertTrue((project / "_pro/outbox/reply.md").is_file())
            self.assertFalse(sibling_ok["isError"], sibling_ok)
            self.assertTrue((project / "_pro/inbox_notes/ok.md").is_file())
            expected_outbox_hint = (
                "The _pro/inbox/ folder holds requests from local agents and is read-only for delegated principals. "
                "Write under a path your grant allows; a pro-review grant allows _pro/outbox/ and _pro/reports/."
            )
            for path, res in zip(inbox_denied_paths, inbox_results[:len(inbox_denied_paths)]):
                with self.subTest(inbox_write=path):
                    assert_error(res, "BRIDGE_POLICY_DENIED")
                    self.assertEqual(res["structuredContent"]["next_action"], expected_outbox_hint)
            for path, res in zip(inbox_hazard_paths, inbox_results[len(inbox_denied_paths):]):
                with self.subTest(inbox_hazard=path):
                    self.assertTrue(res["isError"], res)

            # file_patch under a grant with Patch + ["_pro/**"] refuses inbox writes atomically.
            patch_frames = [
                {"jsonrpc": "2.0", "id": idx, "method": "tools/call",
                 "params": {"name": "file_patch", "arguments": {
                     "project_id": project_id, "grant_id": explicit["grant_id"],
                     "operation_id": f"op_patch_inbox_{idx}",
                     "edits": [
                         {"path": f"_pro/outbox/paired_{idx}.md", "content": "should not commit\n"},
                         {"path": path, "content": "forged"},
                     ],
                 }}}
                for idx, path in enumerate(inbox_denied_paths + inbox_hazard_paths, 1)
            ]
            patch_out = cli(
                "mcp", "--principal", "executor:explicit",
                stdin="".join(json.dumps(frame) + "\n" for frame in patch_frames),
            ).stdout
            patch_responses = {frame["id"]: frame["result"] for frame in map(json.loads, patch_out.splitlines())}
            for idx, path in enumerate(inbox_denied_paths, 1):
                with self.subTest(inbox_patch=path):
                    res = patch_responses[idx]
                    assert_error(res, "BRIDGE_POLICY_DENIED")
                    self.assertEqual(res["structuredContent"]["next_action"], expected_outbox_hint)
                    self.assertFalse((project / f"_pro/outbox/paired_{idx}.md").exists())
            for idx, path in enumerate(inbox_hazard_paths, len(inbox_denied_paths) + 1):
                with self.subTest(inbox_patch_hazard=path):
                    self.assertTrue(patch_responses[idx]["isError"], patch_responses[idx])
                    self.assertFalse((project / f"_pro/outbox/paired_{idx}.md").exists())
            self.assertEqual(sorted(p.name for p in inbox_dir.iterdir()), [inbox_req.name])

            # Broad "**", explicit "_pro/inbox/**", and non-pro-review "src/**" grants are all refused for _pro/inbox/.
            for requester, pattern, expect_outbox in (
                ("executor:wildcard", "**", True),
                ("executor:inboxonly", "_pro/inbox/**", False),
                ("executor:srconly", "src/**", False),
            ):
                with self.subTest(other_grant=pattern):
                    other_grant = json.loads(cli(
                        "grant-create", project_id, "--requester", requester,
                        "--writable-path", pattern,
                    ).stdout)
                    other_res = json.loads(cli(
                        "mcp", "--principal", requester,
                        stdin=json.dumps({
                            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "file_write", "arguments": {
                                "project_id": project_id, "grant_id": other_grant["grant_id"],
                                "operation_id": "op_other_inbox", "path": "_pro/inbox/forged.md", "content": "denied",
                            }},
                        }) + "\n",
                    ).stdout)["result"]
                    assert_error(other_res, "BRIDGE_POLICY_DENIED")
                    if expect_outbox:
                        self.assertEqual(other_res["structuredContent"]["next_action"], expected_outbox_hint)
                    else:
                        self.assertEqual(
                            other_res["structuredContent"]["next_action"],
                            expected_outbox_hint,
                        )

            policy_frame = {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "policy_view", "arguments": {"project_id": project_id, "grant_id": grant_id}},
            }
            policy_res = json.loads(cli(
                "mcp", "--principal", "executor:default", stdin=json.dumps(policy_frame) + "\n",
            ).stdout)["result"]
            self.assertFalse(policy_res["isError"], policy_res)
            view_grant = policy_res["structuredContent"]["result"]["grant"]
            self.assertEqual(view_grant["grant_id"], grant_id)
            self.assertCountEqual(view_grant["permitted_categories"], ["read", "git_read", "write", "execute_recipe"])
            self.assertEqual(view_grant["writable_paths"], ["_pro/**"])
            self.assertEqual(view_grant["denied_paths"], ["_pro/inbox/**"])
            self.assertEqual(view_grant["allowed_recipes"], ["python_tests", "powershell_script"])
            self.assertEqual(view_grant["export_scope"], "redacted_summary")
            self.assertIn("max_duration_seconds", view_grant["limits"])
            self.assertEqual(view_grant["expires_at"], grant["expires_at"])
            self.assertNotIn("granting_owner", view_grant)
            self.assertNotIn(str(project), json.dumps(policy_res))

            self.assertTrue(json.loads(cli("grant-revoke", grant_id).stdout)["revoked"])
            revoked_policy = json.loads(cli(
                "mcp", "--principal", "executor:default", stdin=json.dumps(policy_frame) + "\n",
            ).stdout)["result"]
            assert_error(revoked_policy, "PROJECT_NOT_GRANTED")
            same_create, fresh_create = mcp_writes(
                create, write("op_after_revoke", "_pro/reports/after.md", "denied"),
            )
            assert_error(same_create, "PROJECT_NOT_GRANTED")
            assert_error(fresh_create, "PROJECT_NOT_GRANTED")
            self.assertFalse((project / "_pro/reports/after.md").exists())
            self.assertEqual((project / report_path).read_bytes(), report_bytes)
            self.assertEqual(sentinel.read_bytes(), original)


class ProReviewEvidenceContractTest(unittest.TestCase):
    def setUp(self):
        repo = Path(__file__).resolve().parents[2]
        override = os.environ.get("EPB_MCP_TEST_BINARY")
        binary = Path(override) if override is not None else (
            repo / "target" / "x86_64-pc-windows-gnullvm" / "release" / "edge-bridge.exe"
        )
        if override is not None:
            self.assertTrue(binary.is_file(), f"explicit worker binary missing: {binary}")
        if not binary.is_file():
            self.skipTest(f"local worker binary not found: {binary}")
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / "state"
        self.command = [str(binary), "--state-dir", str(self.state), "--environment-kind", "canary"]
        self.project_id, self.grant_id, self.run_id = self.create_project_run("fixture")

    def cli(self, *args, stdin=None):
        completed = subprocess.run(
            [*self.command, *args], input=stdin, capture_output=True, encoding="utf-8", timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def mcp(self, principal, tool, **arguments):
        frame = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": tool, "arguments": arguments}}
        return self.cli("mcp", "--principal", principal, stdin=json.dumps(frame) + "\n")["result"]

    def create_project_run(self, name):
        root = self.root / name
        root.mkdir()
        project = self.cli("register", str(root), "--name", name, "--grant-edge")["project_id"]
        grant = self.cli("grant-create", project, "--profile", "pro-review")["grant_id"]
        submission = self.mcp(
            "executor:default", "task_submit", project_id=project, grant_id=grant,
            task_id="task_fixture", operation_id="op_fixture",
        )
        self.assertFalse(submission["isError"], submission)
        return project, grant, submission["structuredContent"]["result"]["run_id"]

    def save_manifest(self, artifact_id, project_id, run_id, raw, *, linked=False):
        with closing(sqlite3.connect(self.state / "state.sqlite3")) as db, db:
            db.execute(
                """INSERT INTO evidence_manifests
                   (manifest_id, run_id, project_id, host_id, evidence_class, verdict,
                    manifest_sha256, manifest_json, created_at)
                   SELECT ?, run_id, ?, host_id, 'software_unit', 'NOT_TESTED', ?, ?, created_at
                     FROM durable_runs WHERE run_id = ?""",
                (artifact_id, project_id, "a" * 64, raw, run_id),
            )
            if linked:
                db.execute("UPDATE durable_runs SET evidence_manifest_id = ? WHERE run_id = ?",
                           (artifact_id, run_id))

    def error_fields(self, response):
        self.assertTrue(response["isError"], response)
        error = response["structuredContent"].copy()
        error.pop("correlation_id")
        return error

    def test_remote_absent_and_cross_project_artifacts_have_the_same_denial(self):
        other_project, _, other_run = self.create_project_run("foreign")
        self.save_manifest("evid_foreign", other_project, other_run,
                           self.valid_manifest("evid_foreign", other_project, other_run, "local", None))
        self.save_manifest("evid_corrupt_foreign", other_project, other_run,
                           '{"identity":"PRIVATE_FOREIGN_PARSE_TEXT"}')
        for principal in ("edge", "executor:default"):
            args = {"project_id": self.project_id, "grant_id": self.grant_id}
            absent = self.error_fields(self.mcp(principal, "artifact_read", artifact_id="evid_absent", **args))
            self.assertEqual(absent["code"], "BRIDGE_POLICY_DENIED")
            for foreign_id in ("evid_foreign", "evid_corrupt_foreign"):
                with self.subTest(principal=principal, artifact_id=foreign_id):
                    foreign = self.error_fields(self.mcp(principal, "artifact_read", artifact_id=foreign_id, **args))
                    self.assertEqual(foreign, absent)
        owner_absent = self.error_fields(self.mcp(
            "local", "artifact_read", project_id=self.project_id, artifact_id="evid_absent",
        ))
        owner_foreign = self.error_fields(self.mcp(
            "local", "artifact_read", project_id=self.project_id, artifact_id="evid_foreign",
        ))
        self.assertEqual(owner_absent["code"], "NOT_FOUND")
        self.assertEqual(owner_foreign["code"], "BRIDGE_POLICY_DENIED")

    def test_corrupt_evidence_keeps_parser_text_in_owner_diagnostics(self):
        artifact = "evid_corrupt"
        marker = "PRIVATE_CORRUPT_TYPE_VALUE"
        self.save_manifest(artifact, self.project_id, self.run_id, json.dumps({
            "identity": marker,
            "authorization": {"requester_principal": "executor:default", "grant_id": self.grant_id},
        }), linked=True)
        for tool, ids in (("artifact_read", {"artifact_id": artifact}), ("job_get", {"job_id": self.run_id})):
            for principal in ("local", "edge", "executor:default"):
                with self.subTest(tool=tool, principal=principal):
                    result = self.mcp(principal, tool, project_id=self.project_id, grant_id=self.grant_id, **ids)
                    error = self.error_fields(result)
                    self.assertEqual(error["code"], "INTERNAL_ERROR")
                    if principal == "local":
                        self.assertIn(marker, error["message"])
                    else:
                        self.assertEqual(error["message"], "Corrupt evidence manifest JSON.")
                        self.assertNotIn(marker, json.dumps(result))

    def test_foreign_manifest_linked_to_a_visible_run_has_no_workload_report(self):
        artifact = "evid_foreign_link"
        self.save_manifest(artifact, self.project_id, self.run_id, self.valid_manifest(
            artifact, self.project_id, self.run_id, "executor:other", self.grant_id,
        ), linked=True)
        for principal in ("local", "edge", "executor:default"):
            with self.subTest(principal=principal):
                response = self.mcp(principal, "job_get", project_id=self.project_id,
                                    grant_id=self.grant_id, job_id=self.run_id)
                self.assertFalse(response["isError"], response)
                result = response["structuredContent"]["result"]
                self.assertEqual(result["run_id"], self.run_id)
                self.assertNotIn("workload_report", result)

    def test_artifact_list_outcomes_and_tool_schemas(self):
        fail_manifest = json.loads(self.valid_manifest(
            "evid_fail_exec", self.project_id, self.run_id, "executor:default", self.grant_id,
        ))
        fail_manifest["execution"]["exit_code"] = 1
        fail_manifest["execution"]["outcome_triad"]["execution_outcome"] = "FAIL"
        fail_manifest["execution"]["outcome_triad"]["agent_outcome"] = "BLOCKED"
        fail_manifest["execution"]["outcome_triad"]["verification_outcome"] = "NOT_TESTED"
        fail_manifest["conclusions"]["overall_verdict"] = "PARTIAL"
        self.save_manifest("evid_fail_exec", self.project_id, self.run_id, json.dumps(fail_manifest))

        listed = self.mcp("executor:default", "artifact_list", project_id=self.project_id, grant_id=self.grant_id)
        self.assertFalse(listed["isError"], listed)
        items = listed["structuredContent"]["result"]["artifacts"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["manifest_id"], "evid_fail_exec")
        self.assertEqual(items[0]["verdict"], "PARTIAL")
        self.assertEqual(items[0]["execution_outcome"], "FAIL")
        self.assertEqual(items[0]["agent_outcome"], "BLOCKED")
        self.assertEqual(items[0]["verification_outcome"], "NOT_TESTED")

        by_artifact_id = self.mcp(
            "executor:default", "artifact_read",
            project_id=self.project_id, grant_id=self.grant_id, artifact_id="evid_fail_exec",
        )
        self.assertFalse(by_artifact_id["isError"], by_artifact_id)

        only_manifest_id = self.mcp(
            "executor:default", "artifact_read",
            project_id=self.project_id, grant_id=self.grant_id, manifest_id="evid_fail_exec",
        )
        self.assertTrue(only_manifest_id["isError"])
        self.assertEqual(only_manifest_id["structuredContent"]["code"], "INVALID_ARGUMENT")

        tools_frame = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        tools = {
            t["name"]: t
            for t in self.cli("mcp", "--principal", "executor:default", stdin=json.dumps(tools_frame) + "\n")["result"]["tools"]
        }
        self.assertIn("manifest_id", tools["artifact_read"]["description"])
        self.assertIn("artifact_list", tools["artifact_read"]["description"])
        self.assertNotIn("alias", tools["artifact_read"]["description"])
        self.assertNotIn("manifest_id", tools["artifact_read"]["inputSchema"]["properties"])
        self.assertIn("manifest_id", tools["artifact_read"]["inputSchema"]["properties"]["artifact_id"]["description"])
        for tool in ("file_read", "file_view"):
            self.assertIn("offset and limit are measured in characters, not lines or bytes", tools[tool]["description"])
            props = tools[tool]["inputSchema"]["properties"]
            self.assertEqual(props["offset"]["description"], "Start offset in characters (not lines or bytes).")
            self.assertEqual(props["limit"]["description"], "Maximum number of characters to return (not lines or bytes; max 65536).")
        self.assertIn("grant", tools["policy_view"]["description"])
        self.assertIn("denied_paths", tools["policy_view"]["description"])
        self.assertIn(
            "denied_paths",
            tools["policy_view"]["outputSchema"]["properties"]["result"]["properties"]["grant"]["properties"],
        )

    def test_omitted_grant_id_uses_newest_valid_grant_when_newer_grant_expired_or_revoked(self):
        # Set up a fresh project with an older valid grant, then newer expired and revoked grants.
        root = self.root / "grant_fallback"
        root.mkdir()
        (root / "note.txt").write_text("hello\n", encoding="utf-8")
        project_id = self.cli("register", str(root), "--name", "grant_fallback")["project_id"]
        older_valid = self.cli("grant-create", project_id, "--profile", "pro-review")
        newer_expired = self.cli("grant-create", project_id, "--profile", "pro-review")
        newer_revoked = self.cli("grant-create", project_id, "--profile", "pro-review")

        with closing(sqlite3.connect(self.state / "state.sqlite3")) as db, db:
            db.execute(
                "UPDATE task_grants SET created_at = '2026-01-01T00:01:00+00:00' WHERE grant_id = ?",
                (older_valid["grant_id"],),
            )
            db.execute(
                "UPDATE task_grants SET created_at = '2026-01-01T00:02:00+00:00', expires_at = '2020-01-01T00:00:00+00:00' WHERE grant_id = ?",
                (newer_expired["grant_id"],),
            )
            db.execute(
                "UPDATE task_grants SET created_at = '2026-01-01T00:03:00+00:00', revoked = 1, revoked_at = '2026-01-01T00:03:01+00:00' WHERE grant_id = ?",
                (newer_revoked["grant_id"],),
            )

        # Calling policy_view and file_write without grant_id succeeds via older_valid.
        view = self.mcp("executor:default", "policy_view", project_id=project_id)
        self.assertFalse(view["isError"], view)
        self.assertEqual(view["structuredContent"]["result"]["grant"]["grant_id"], older_valid["grant_id"])

        write = self.mcp(
            "executor:default", "file_write",
            project_id=project_id, operation_id="op_no_gid_write",
            path="_pro/reports/no-gid.md", content="ok\n",
        )
        self.assertFalse(write["isError"], write)
        self.assertEqual((root / "_pro/reports/no-gid.md").read_text(encoding="utf-8"), "ok\n")

        # Explicit expired grant_id is still refused as before.
        explicit_expired = self.mcp(
            "executor:default", "policy_view", project_id=project_id, grant_id=newer_expired["grant_id"],
        )
        self.assertTrue(explicit_expired["isError"])
        self.assertEqual(explicit_expired["structuredContent"]["code"], "BRIDGE_POLICY_DENIED")

        # Once no valid grant remains, omitted grant_id refuses with PROJECT_NOT_GRANTED and leaks no grant_id.
        with closing(sqlite3.connect(self.state / "state.sqlite3")) as db, db:
            db.execute(
                "UPDATE task_grants SET expires_at = '2020-01-01T00:00:00+00:00' WHERE grant_id = ?",
                (older_valid["grant_id"],),
            )
        none_left = self.mcp("executor:default", "policy_view", project_id=project_id)
        self.assertTrue(none_left["isError"])
        self.assertEqual(none_left["structuredContent"]["code"], "PROJECT_NOT_GRANTED")
        serialized = json.dumps(none_left)
        for gid in (older_valid["grant_id"], newer_expired["grant_id"], newer_revoked["grant_id"]):
            self.assertNotIn(gid, serialized)

    def test_worker_refuses_zero_grant_limit_and_runner_validates_job_limits(self):
        # Set up an isolated single-project state so the worker reaches grant limit validation without spawning MXC.
        repo = Path(__file__).resolve().parents[2]
        isolated = self.root / "zero_limit_worker"
        state = isolated / "state"
        project_dir = isolated / "project"
        (project_dir / "tests").mkdir(parents=True)
        (project_dir / "tests" / "__init__.py").write_text("", encoding="utf-8")
        (project_dir / "tests" / "test_ok.py").write_text(
            "import unittest\nclass T(unittest.TestCase):\n    def test_ok(self): self.assertTrue(True)\n",
            encoding="utf-8",
        )
        cmd = [self.command[0], "--state-dir", str(state), "--environment-kind", "canary"]

        def run_cli(*args, stdin=None):
            done = subprocess.run([*cmd, *args], input=stdin, capture_output=True, encoding="utf-8", timeout=30)
            self.assertEqual(done.returncode, 0, done.stderr)
            return done.stdout

        pid = json.loads(run_cli("register", str(project_dir), "--name", "zero_limit"))["project_id"]
        grant = json.loads(run_cli("grant-create", pid, "--profile", "pro-review"))
        limits = dict(grant["limits"])
        limits["max_duration_seconds"] = 0
        with closing(sqlite3.connect(state / "state.sqlite3")) as db, db:
            db.execute("UPDATE task_grants SET limits_json = ? WHERE grant_id = ?",
                       (json.dumps(limits), grant["grant_id"]))

        submit = json.loads(run_cli(
            "mcp", "--principal", "executor:default",
            stdin=json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "task_submit", "arguments": {
                    "project_id": pid, "grant_id": grant["grant_id"],
                    "task_id": "task_zero_limit", "operation_id": "op_zero_limit",
                }},
            }) + "\n",
        ))["result"]
        self.assertFalse(submit["isError"], submit)
        run_id = submit["structuredContent"]["result"]["run_id"]

        worker_out = run_cli("worker", "--runtime-root", str(repo), "--once", "--allow-environment-credentials")
        receipt = json.loads(worker_out.strip().splitlines()[-1])
        self.assertEqual(receipt["run"]["run_id"], run_id)
        self.assertEqual(receipt["run"]["state"], "failed")
        self.assertEqual(receipt["verification"], "BLOCKED")
        self.assertTrue(receipt["failure_code"].startswith("INVALID_GRANT_LIMITS:"), receipt)
        self.assertFalse((state / "runs" / run_id).exists())

        output = json.loads(run_cli(
            "mcp", "--principal", "executor:default",
            stdin=json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "job_output", "arguments": {
                    "project_id": pid, "grant_id": grant["grant_id"], "job_id": run_id,
                }},
            }) + "\n",
        ))["result"]
        self.assertFalse(output["isError"], output)
        chunks = output["structuredContent"]["result"]["chunks"]
        self.assertTrue(any(c["stream"] == "stderr" and "INVALID_GRANT_LIMITS" in c["content"] for c in chunks))

        # Python runner limit helper accepts stricter limits and rejects 0 or values above recipe caps.
        from edge_bridge import runner
        stricter = runner.resolve_job_limits({"memory_bytes": 128 * 1024 * 1024, "processes": 3, "log_bytes": 4096})
        self.assertEqual(stricter, {"memory_bytes": 128 * 1024 * 1024, "processes": 3, "log_bytes": 4096})
        for bad in (
            {"memory_bytes": 0},
            {"processes": 0},
            {"log_bytes": 0},
            {"memory_bytes": runner.MAX_TEST_MEMORY + 1},
            {"processes": runner.MAX_TEST_PROCESSES + 1},
            {"log_bytes": runner.MAX_TEST_LOG_BYTES + 1},
        ):
            with self.subTest(bad_limits=bad), self.assertRaises(runner.RunnerBlocked) as err:
                runner.resolve_job_limits(bad)
            self.assertEqual(err.exception.code, "INVALID_GRANT_LIMITS")

    @staticmethod
    def valid_manifest(artifact_id, project_id, run_id, requester, grant_id):
        now = "2026-01-01T00:00:00Z"
        return json.dumps({
            "identity": {"manifest_id": artifact_id, "project_id": project_id, "run_id": run_id,
                         "task_id": "task_fixture", "host_id": "host_fixture", "workspace_id": "ws_fixture",
                         "report_format_version": "fixture", "broker_version": "fixture",
                         "runner_version": "fixture", "adapter_version": "fixture",
                         "evidence_class": "software_unit"},
            "authorization": {"grant_id": grant_id, "requester_principal": requester,
                              "executor_identity": "fixture", "policy_revision": 1, "effective_scope": [],
                              "containment_probe_result": "fixture"},
            "source": {"dirty_input_manifest_sha256": "", "source_hash_before": "", "source_hash_after": "",
                       "test_suite_manifest_sha256": "", "test_suite_modified": False},
            "inputs": {"config_hashes": {}, "declared_units": {}, "synthetic_data": True},
            "environment": {"os_build": "", "architecture": "", "host_name": "", "toolchain_versions": {},
                            "resolved_executable": "", "resolved_executable_sha256": "", "isolation_backend": ""},
            "command": {"executable": "", "argv": [], "cwd": "", "redacted_env_keys": [],
                        "process_start_recorded_outside_job": True},
            "time": {"started_at_utc": now, "finished_at_utc": now, "monotonic_duration_ms": 1,
                     "clock_uncertainty_note": ""},
            "execution": {"exit_code": 0, "timed_out": False, "cancelled": False, "policy_denied": False,
                          "partial_output": False, "cleanup_confirmed": True, "outcome_triad": {
                              "agent_outcome": "NOT_TESTED", "execution_outcome": "PASS",
                              "verification_outcome": "NOT_TESTED",
                          }},
            "tests": {"parser_name": "python_unittest", "parser_version": "fixture", "discovered": 1,
                      "executed": 1, "passed": 1, "failed": 0, "skipped": 0, "results_artifact_sha256": "",
                      "fresh_for_run": True, "cases": []},
            "artifacts": [],
            "conclusions": {"overall_verdict": "NOT_TESTED", "claims": [], "untested_areas": [],
                            "reproduction_command": "", "provenance_disclaimer": ""},
        })
