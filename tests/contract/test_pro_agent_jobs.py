import concurrent.futures
import hashlib
import hmac
import http.client
import json
import os
import secrets
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path


def _binary_path() -> Path:
    override = os.environ.get("EPB_MCP_TEST_BINARY")
    if override:
        return Path(override)
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "target" / "x86_64-pc-windows-gnullvm" / "release" / "edge-bridge.exe"


def _hmac_headers(principal: str, token_hex: str, host: str, body: bytes) -> dict[str, str]:
    nonce = secrets.token_hex(16)
    stamp = str(int(time.time()))
    prefix = f"edge-project-bridge/v1|request|{principal}|{nonce}|{stamp}|".encode("utf-8")
    sig = hmac.new(bytes.fromhex(token_hex), prefix + body, hashlib.sha256).hexdigest()
    return {
        "Host": host,
        "Content-Type": "application/json",
        "X-Bridge-Principal": principal,
        "X-Bridge-Nonce": nonce,
        "X-Bridge-Timestamp": stamp,
        "X-Bridge-Signature": sig,
    }


def _http_mcp(port: int, principal: str, token_hex: str, frame: dict, timeout: float = 15.0) -> dict:
    host = f"127.0.0.1:{port}"
    body = json.dumps(frame).encode("utf-8")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("POST", "/mcp", body=body, headers=_hmac_headers(principal, token_hex, host, body))
        resp = conn.getresponse()
        raw = resp.read()
        return json.loads(raw.decode("utf-8"))
    finally:
        conn.close()


class ProAgentJobsContractTest(unittest.TestCase):
    def setUp(self):
        self.binary = _binary_path()
        if os.environ.get("EPB_MCP_TEST_BINARY"):
            self.assertTrue(self.binary.is_file(), f"explicit worker binary missing: {self.binary}")
        if not self.binary.is_file():
            self.skipTest(f"local worker binary not found: {self.binary}")
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.state_dir = self.tmp / "state"
        self.project = self.tmp / "project"
        self.project.mkdir()
        (self.project / "hello.txt").write_text("hello\n", encoding="utf-8")
        self.base_cmd = [
            str(self.binary),
            "--state-dir",
            str(self.state_dir),
            "--environment-kind",
            "canary",
        ]

    def cli(self, *args, stdin=None, check=True):
        return subprocess.run(
            [*self.base_cmd, *args],
            input=stdin,
            check=check,
            capture_output=True,
            encoding="utf-8",
            timeout=30,
        )

    def mcp_calls(self, principal: str, calls: list[tuple[str, dict]]) -> list[dict]:
        frames = [
            {"jsonrpc": "2.0", "id": idx, "method": "tools/call", "params": {"name": name, "arguments": args}}
            for idx, (name, args) in enumerate(calls, 1)
        ]
        out = self.cli(
            "mcp",
            "--principal",
            principal,
            stdin="".join(json.dumps(f) + "\n" for f in frames),
        ).stdout
        by_id = {frame["id"]: frame["result"] for frame in map(json.loads, out.splitlines())}
        return [by_id[idx] for idx in range(1, len(calls) + 1)]

    def test_job_wait_task_get_workload_report_grant_cap_and_edge_denial(self):
        reg = json.loads(self.cli("register", str(self.project), "--name", "WP5 fixture", "--grant-edge").stdout)
        project_id = reg["project_id"]

        grant = json.loads(self.cli("grant-create", project_id, "--profile", "pro-review").stdout)
        grant_id = grant["grant_id"]

        foreign_grant = json.loads(
            self.cli("grant-create", project_id, "--requester", "executor:foreign", "--profile", "pro-review").stdout
        )
        foreign_grant_id = foreign_grant["grant_id"]

        # Submit 8 runs -> all 8 succeed; idempotent replay of #8 succeeds; 9th fails with RESOURCE_BUDGET_EXCEEDED.
        submit_calls = [
            (
                "task_submit",
                {
                    "project_id": project_id,
                    "grant_id": grant_id,
                    "task_id": "t_wp5",
                    "operation_id": f"op_wp5_{i}",
                    "recipe": "python_tests",
                },
            )
            for i in range(8)
        ]
        submit_calls.append(submit_calls[-1])  # replay #8
        submit_calls.append(
            (
                "task_submit",
                {
                    "project_id": project_id,
                    "grant_id": grant_id,
                    "task_id": "t_wp5",
                    "operation_id": "op_wp5_9th",
                    "recipe": "python_tests",
                },
            )
        )
        results = self.mcp_calls("executor:default", submit_calls)
        run_ids = []
        for idx in range(8):
            self.assertFalse(results[idx]["isError"], results[idx])
            run_ids.append(results[idx]["structuredContent"]["result"]["run_id"])
        # Replay of #8 succeeded.
        self.assertFalse(results[8]["isError"], results[8])
        self.assertTrue(results[8]["structuredContent"]["result"]["idempotent_replay"])
        self.assertEqual(results[8]["structuredContent"]["result"]["run_id"], run_ids[7])
        # 9th run rejected.
        self.assertTrue(results[9]["isError"], results[9])
        self.assertEqual(results[9]["structuredContent"]["code"], "RESOURCE_BUDGET_EXCEEDED")

        # task_get includes workload_report on each delegated run.
        task_res = self.mcp_calls(
            "executor:default",
            [("task_get", {"project_id": project_id, "task_id": "t_wp5", "grant_id": grant_id})],
        )[0]
        self.assertFalse(task_res["isError"], task_res)
        task_runs = task_res["structuredContent"]["result"]["runs"]
        self.assertEqual(len(task_runs), 8)
        for item in task_runs:
            self.assertIn("workload_report", item)
            self.assertEqual(item["workload_report"]["source"], "workload")

        # edge is denied job_wait.
        edge_res = self.mcp_calls(
            "edge",
            [("job_wait", {"project_id": project_id, "job_ids": [run_ids[0]], "timeout_seconds": 0})],
        )[0]
        self.assertTrue(edge_res["isError"], edge_res)
        self.assertEqual(edge_res["structuredContent"]["code"], "BRIDGE_POLICY_DENIED")

        # Foreign run and nonexistent run return identical BRIDGE_POLICY_DENIED errors (no oracle).
        foreign_submit = self.mcp_calls(
            "executor:foreign",
            [
                (
                    "task_submit",
                    {
                        "project_id": project_id,
                        "grant_id": foreign_grant_id,
                        "task_id": "t_foreign",
                        "operation_id": "op_foreign_1",
                        "recipe": "python_tests",
                    },
                )
            ],
        )[0]
        foreign_run_id = foreign_submit["structuredContent"]["result"]["run_id"]
        missing_res, foreign_res = self.mcp_calls(
            "executor:default",
            [
                (
                    "job_wait",
                    {
                        "project_id": project_id,
                        "grant_id": grant_id,
                        "job_ids": [run_ids[0], "run_does_not_exist_12345"],
                        "timeout_seconds": 0,
                    },
                ),
                (
                    "job_wait",
                    {
                        "project_id": project_id,
                        "grant_id": grant_id,
                        "job_ids": [run_ids[0], foreign_run_id],
                        "timeout_seconds": 0,
                    },
                ),
            ],
        )
        self.assertTrue(missing_res["isError"])
        self.assertTrue(foreign_res["isError"])
        self.assertEqual(missing_res["structuredContent"]["code"], "BRIDGE_POLICY_DENIED")
        self.assertEqual(
            (foreign_res["structuredContent"]["code"], foreign_res["structuredContent"]["message"]),
            (missing_res["structuredContent"]["code"], missing_res["structuredContent"]["message"]),
        )

        # Cancel run 0 and seed output chunks directly in SQLite to verify inline bounded output on job_wait.
        self.mcp_calls(
            "executor:default",
            [("job_cancel", {"project_id": project_id, "grant_id": grant_id, "job_id": run_ids[0]})],
        )
        with closing(sqlite3.connect(self.state_dir / "state.sqlite3")) as db:
            db.execute(
                "INSERT INTO run_output_chunks(run_id, seq, stream, content, created_at) VALUES (?, 1, 'stdout', ?, '2026-01-01T00:00:00Z')",
                (run_ids[0], "hello-chunk-1\n"),
            )
            db.execute("UPDATE durable_runs SET output_seq = 1 WHERE run_id = ?", (run_ids[0],))
            db.commit()

        wait_res = self.mcp_calls(
            "executor:default",
            [
                (
                    "job_wait",
                    {
                        "project_id": project_id,
                        "grant_id": grant_id,
                        "job_ids": [run_ids[0], run_ids[1]],
                        "timeout_seconds": 0,
                        "wait_for": "any",
                        "include_output": True,
                    },
                )
            ],
        )[0]
        self.assertFalse(wait_res["isError"], wait_res)
        payload = wait_res["structuredContent"]["result"]
        self.assertTrue(payload["completed"])
        self.assertFalse(payload["timed_out"])
        self.assertEqual(payload["runs"][0]["state"], "cancelled")
        self.assertEqual(payload["runs"][0]["output"]["chunks"][0]["content"], "hello-chunk-1\n")
        self.assertEqual(payload["runs"][0]["output"]["next_seq"], 1)
        self.assertNotIn("output", payload["runs"][1])

    def test_http_admission_enforces_two_concurrent_waits_while_job_cancel_stays_instant(self):
        reg = json.loads(self.cli("register", str(self.project), "--name", "WP5 HTTP fixture").stdout)
        project_id = reg["project_id"]
        grant = json.loads(self.cli("grant-create", project_id, "--profile", "pro-review").stdout)
        grant_id = grant["grant_id"]
        submit = self.mcp_calls(
            "executor:default",
            [
                (
                    "task_submit",
                    {
                        "project_id": project_id,
                        "grant_id": grant_id,
                        "task_id": "t_http",
                        "operation_id": "op_http_1",
                        "recipe": "python_tests",
                    },
                )
            ],
        )[0]
        run_id = submit["structuredContent"]["result"]["run_id"]

        proc = subprocess.Popen(
            [*self.base_cmd, "serve", "--port", "0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(lambda: (proc.terminate(), proc.wait(timeout=10)))

        discovery = self.state_dir / "rust-broker.json"
        deadline = time.monotonic() + 10.0
        while not discovery.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(discovery.is_file(), "rust-broker.json did not appear")
        port = json.loads(discovery.read_text(encoding="utf-8"))["port"]
        exec_token = (self.state_dir / "executor.token").read_text(encoding="utf-8").strip()

        wait_frame = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "job_wait",
                "arguments": {
                    "project_id": project_id,
                    "grant_id": grant_id,
                    "job_ids": [run_id],
                    "timeout_seconds": 10,
                    "include_output": False,
                },
            },
        }
        cancel_frame = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "job_cancel",
                "arguments": {
                    "project_id": project_id,
                    "grant_id": grant_id,
                    "job_id": run_id,
                },
            },
        }

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            f1 = pool.submit(_http_mcp, port, "executor", exec_token, wait_frame)
            f2 = pool.submit(_http_mcp, port, "executor", exec_token, wait_frame)
            time.sleep(0.35)

            # 3rd concurrent job_wait gets RESOURCE_BUSY from Admission's wait_limit.
            third = _http_mcp(port, "executor", exec_token, wait_frame)
            self.assertTrue(third["result"]["isError"], third)
            self.assertEqual(third["result"]["structuredContent"]["code"], "RESOURCE_BUSY")
            self.assertEqual(third["result"]["structuredContent"]["details"]["reason"], "wait_limit")

            # Meanwhile job_cancel on Control lane stays instant and wakes both waiting job_wait calls!
            t0 = time.monotonic()
            cancelled = _http_mcp(port, "executor", exec_token, cancel_frame)
            cancel_elapsed = time.monotonic() - t0
            self.assertFalse(cancelled["result"]["isError"], cancelled)
            self.assertEqual(cancelled["result"]["structuredContent"]["result"]["state"], "cancelled")
            self.assertLess(cancel_elapsed, 2.0)

            r1 = f1.result(timeout=5)
            r2 = f2.result(timeout=5)
            for res in (r1, r2):
                self.assertFalse(res["result"]["isError"], res)
                body = res["result"]["structuredContent"]["result"]
                self.assertTrue(body["completed"])
                self.assertEqual(body["runs"][0]["state"], "cancelled")

    def test_python_tests_work_double_opt_in_grants_selectors_and_powershell_work_refusal(self):
        (self.project / "tests").mkdir()
        (self.project / "tests" / "__init__.py").write_text("", encoding="utf-8")
        (self.project / "tests" / "test_calc.py").write_text(
            "import unittest\nclass CalcTests(unittest.TestCase):\n    def test_add(self): self.assertEqual(1+1, 2)\n",
            encoding="utf-8",
        )
        reg = json.loads(self.cli("register", str(self.project), "--name", "WP6 contract", "--grant-edge").stdout)
        pid = reg["project_id"]

        # 1. powershell_script_work cannot be granted via CLI (--allow-work-powershell removed, --recipe rejected).
        bad_flag = self.cli("grant-create", pid, "--profile", "pro-agent", "--allow-work-powershell", check=False)
        self.assertEqual(bad_flag.returncode, 2, bad_flag.stderr)
        bad_recipe = self.cli("grant-create", pid, "--recipe", "powershell_script_work", check=False)
        self.assertNotEqual(bad_recipe.returncode, 0, bad_recipe.stdout)

        agent_grant = json.loads(self.cli("grant-create", pid, "--profile", "pro-agent").stdout)
        agent_gid = agent_grant["grant_id"]
        self.assertEqual(agent_grant["allowed_recipes"], ["python_tests", "powershell_script", "python_tests_work"])
        self.assertNotIn("powershell_script_work", agent_grant["allowed_recipes"])

        review_gid = json.loads(
            self.cli("grant-create", pid, "--requester", "executor:review", "--profile", "pro-review").stdout
        )["grant_id"]
        legacy_gid = json.loads(
            self.cli("grant-create", pid, "--requester", "executor:legacy", "--writable-path", "_pro/**").stdout
        )["grant_id"]

        # Create workspace fix-1 via work_copy.
        copy_res = self.mcp_calls(
            "executor:default",
            [("work_copy", {"project_id": pid, "grant_id": agent_gid, "workspace": "fix-1", "paths": ["tests"]})],
        )[0]
        self.assertFalse(copy_res["isError"], copy_res)

        # 2. task_submit refuses python_tests_work under pro-review, legacy grant, and edge.
        for label, principal, gid in (
            ("edge", "edge", None),
            ("review", "executor:review", review_gid),
            ("legacy", "executor:legacy", legacy_gid),
        ):
            args = {
                "project_id": pid,
                "task_id": "t_deny",
                "operation_id": f"op_deny_{label}",
                "recipe": "python_tests_work",
                "args": ["fix-1"],
            }
            if gid is not None:
                args["grant_id"] = gid
            res = self.mcp_calls(principal, [("task_submit", args)])[0]
            self.assertTrue(res["isError"], f"{principal}: {res}")
            self.assertEqual(res["structuredContent"]["code"], "BRIDGE_POLICY_DENIED")

        # 3. task_submit refuses powershell_script_work even under pro-agent, and refuses invalid work args/selectors.
        invalid_calls = [
            ("powershell_script_work", ["fix-1", "a.ps1"], "BRIDGE_POLICY_DENIED", "POWERSHELL_SCRIPT_WORK_UNSUPPORTED"),
            ("python_tests_work", [], "INVALID_ARGUMENT", ""),
            ("python_tests_work", ["../escape"], "INVALID_ARGUMENT", ""),
            ("python_tests_work", ["FIX-1"], "INVALID_ARGUMENT", ""),
            ("python_tests_work", ["con"], "INVALID_ARGUMENT", ""),
            ("python_tests_work", ["fix-1", "-c"], "INVALID_ARGUMENT", ""),
            ("python_tests_work", ["fix-1", "tests/../secret.py"], "INVALID_ARGUMENT", ""),
            ("python_tests_work", ["fix-1", "tests/helper.py"], "INVALID_ARGUMENT", ""),
            ("python_tests_work", ["fix-1", "tests.test_calc", "extra"], "INVALID_ARGUMENT", ""),
        ]
        invalid_results = self.mcp_calls(
            "executor:default",
            [
                (
                    "task_submit",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "task_id": "t_bad",
                        "operation_id": f"op_bad_{idx}",
                        "recipe": recipe,
                        "args": rargs,
                    },
                )
                for idx, (recipe, rargs, _, _) in enumerate(invalid_calls)
            ],
        )
        for idx, (res, (_, _, expected_code, expected_substr)) in enumerate(zip(invalid_results, invalid_calls)):
            self.assertTrue(res["isError"], f"case {idx}: {res}")
            self.assertEqual(res["structuredContent"]["code"], expected_code, f"case {idx}: {res}")
            if expected_substr:
                self.assertIn(expected_substr, res["structuredContent"]["message"])

        # 4. Valid python_tests_work submissions (workspace only, file selector, dotted selector) queue cleanly.
        valid_results = self.mcp_calls(
            "executor:default",
            [
                (
                    "task_submit",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "task_id": "t_wp6",
                        "operation_id": "op_wp6_all",
                        "recipe": "python_tests_work",
                        "args": ["fix-1"],
                    },
                ),
                (
                    "task_submit",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "task_id": "t_wp6",
                        "operation_id": "op_wp6_file",
                        "recipe": "python_tests_work",
                        "args": ["fix-1", "tests/test_calc.py"],
                    },
                ),
                (
                    "task_submit",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "task_id": "t_wp6",
                        "operation_id": "op_wp6_dotted",
                        "recipe": "python_tests_work",
                        "args": ["fix-1", "tests.test_calc.CalcTests.test_add"],
                    },
                ),
            ],
        )
        run_ids = []
        for res in valid_results:
            self.assertFalse(res["isError"], res)
            self.assertEqual(res["structuredContent"]["result"]["state"], "queued")
            run_ids.append(res["structuredContent"]["result"]["run_id"])

        # 5. Worker WITHOUT --allow-work-exec refuses every python_tests_work run with WORK_EXEC_NOT_ENABLED
        #    and prepares no snapshot / runs/<run_id> directory (even with --allow-environment-credentials).
        repo_root = Path(__file__).resolve().parents[2]
        worker_out = self.cli(
            "worker", "--runtime-root", str(repo_root), "--once", "--allow-environment-credentials"
        ).stdout
        receipts = [json.loads(line) for line in worker_out.splitlines() if line.strip()]
        self.assertEqual(len(receipts), 3)
        for rec, rid in zip(receipts, run_ids):
            self.assertEqual(rec["run"]["run_id"], rid)
            self.assertEqual(rec["run"]["state"], "failed")
            self.assertEqual(rec["failure_code"], "WORK_EXEC_NOT_ENABLED", rec)
            self.assertFalse((self.state_dir / "runs" / rid).exists())

        # 6. If persistent environment holds credentials on this host, --allow-work-exec +
        #    --allow-environment-credentials STILL refuses python_tests_work with PERSISTENT_ENVIRONMENT_HOLDS_CREDENTIALS.
        env_check = json.loads(self.cli("environment-check").stdout)
        if env_check["credential_like_count"] > 0:
            cred_submit = self.mcp_calls(
                "executor:default",
                [
                    (
                        "task_submit",
                        {
                            "project_id": pid,
                            "grant_id": agent_gid,
                            "task_id": "t_wp6_cred",
                            "operation_id": "op_wp6_cred",
                            "recipe": "python_tests_work",
                            "args": ["fix-1"],
                        },
                    )
                ],
            )[0]
            cred_rid = cred_submit["structuredContent"]["result"]["run_id"]
            cred_out = self.cli(
                "worker",
                "--runtime-root",
                str(repo_root),
                "--once",
                "--allow-work-exec",
                "--allow-environment-credentials",
            ).stdout
            cred_rec = json.loads(cred_out.strip().splitlines()[-1])
            self.assertEqual(cred_rec["run"]["run_id"], cred_rid)
            self.assertEqual(cred_rec["run"]["state"], "failed")
            self.assertTrue(
                cred_rec["failure_code"].startswith("PERSISTENT_ENVIRONMENT_HOLDS_CREDENTIALS:"),
                "Expected persistent credential refusal for python_tests_work even with --allow-environment-credentials",
            )
            self.assertFalse((self.state_dir / "runs" / cred_rid).exists())


if __name__ == "__main__":
    unittest.main()
