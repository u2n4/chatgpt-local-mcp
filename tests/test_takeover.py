import hashlib
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from edge_bridge.broker import MUTATION_TOOLS, call_broker
from edge_bridge.runner import git_path


def _cli(state: Path, *args: str, stdin_text: str | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), *args],
        input=stdin_text,
        stdin=subprocess.DEVNULL if stdin_text is None else None,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        [str(git_path()), "-C", str(cwd), "-c", "user.name=Owner", "-c", "user.email=owner@localhost", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def _mcp_exchange(state: Path, principal: str, calls: list[tuple[str, dict]]) -> tuple[list[dict], str]:
    messages = [
        {"jsonrpc": "2.0", "id": "openai-mcp-discover", "method": "server/discover"},
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "chatgpt-pro-takeover-test", "version": "1.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
    ]
    for idx, (tool_name, args) in enumerate(calls, start=10):
        messages.append({"jsonrpc": "2.0", "id": idx, "method": "tools/call", "params": {"name": tool_name, "arguments": args}})
    payload = "\n".join(json.dumps(m) for m in messages) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "mcp", "--principal", principal],
        input=payload,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise AssertionError(f"mcp failed rc={proc.returncode}: {proc.stderr}")
    replies = []
    for line in proc.stdout.splitlines():
        if line.strip():
            replies.append(json.loads(line))
    return replies, proc.stderr


class EndToEndTakeoverTests(unittest.TestCase):
    def test_10_step_chatgpt_takeover_workflow(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            state = base / "state"
            proj = base / "calc-repo"
            proj.mkdir()
            (proj / "tests").mkdir()
            (proj / "tests" / "__init__.py").write_text("", encoding="utf-8")
            (proj / "calculator.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
            (proj / "tests" / "test_calculator.py").write_text(
                "import unittest\nfrom calculator import add\n\n"
                "class CalcTest(unittest.TestCase):\n"
                "    def test_add(self):\n"
                "        self.assertEqual(add(2, 3), 5)\n",
                encoding="utf-8",
            )
            (proj / "check.ps1").write_text("Write-Output 'PS_OK'\n", encoding="utf-8")
            _git(proj, "init")
            _git(proj, "add", ".")
            _git(proj, "commit", "-m", "initial broken calc")

            rc, out, err = _cli(state, "install")
            self.assertEqual(rc, 0, err)

            def start_broker():
                proc = subprocess.Popen(
                    [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "start"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                ready = proc.stdout.readline()
                self.assertIn("Edge Project Bridge ready on 127.0.0.1:", ready)
                return proc

            broker_proc = start_broker()
            try:
                # Step 1: Owner registers repo and sets narrow grants
                rc, out, err = _cli(state, "register", str(proj), "--name", "Calc Repo")
                self.assertEqual(rc, 0, err)
                project_id = json.loads(out)["project_id"]

                self.assertEqual(_cli(state, "grant-edge", project_id)[0], 0)
                self.assertEqual(
                    _cli(state, "grant-python-tests", project_id, "calculator.py", "tests/__init__.py", "tests/test_calculator.py")[0],
                    0,
                )
                self.assertEqual(_cli(state, "grant-powershell", project_id, "check.ps1")[0], 0)
                self.assertEqual(_cli(state, "set-exec-policy", project_id, "--max-files", "48")[0], 0)

                # Step 2 & 3: ChatGPT Edge principal reads via real MCP stdio and fails closed on mutations
                calc_read_req = {"project_id": project_id, "path": "calculator.py"}
                edge_replies, edge_stderr = _mcp_exchange(
                    state,
                    "edge",
                    [
                        ("bridge_info", {}),
                        ("bridge_health", {}),
                        ("connection_diagnostics", {"symptom": "MCP SSE probe returned 429 from openai.org"}),
                        ("project_list", {}),
                        ("file_read", calc_read_req),
                        ("policy_view", {"project_id": project_id}),
                        ("git_status", {"project_id": project_id}),
                        ("git_diff", {"project_id": project_id}),
                        (
                            "file_write",
                            {
                                "project_id": project_id,
                                "operation_id": "edge-write-denied",
                                "path": "calculator.py",
                                "content": "nope",
                                "expected_hash": None,
                            },
                        ),
                        (
                            "git_checkpoint",
                            {
                                "project_id": project_id,
                                "operation_id": "edge-ckpt-denied",
                                "task_id": "t-calc",
                                "checkpoint_id": "cp-denied",
                            },
                        ),
                        (
                            "process_start",
                            {
                                "project_id": project_id,
                                "operation_id": "edge-exec-denied",
                                "task_id": "t-calc",
                                "executable": "python",
                                "argv": ["-B", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
                                "cwd_relative": ".",
                            },
                        ),
                    ],
                )
                self.assertNotIn("validation error", edge_stderr.casefold())
                by_id = {r["id"]: r for r in edge_replies if "id" in r}
                self.assertEqual(by_id["openai-mcp-discover"]["error"]["code"], -32601)

                info_res = by_id[10]["result"]["structuredContent"]["result"]
                self.assertFalse(info_res["capability_matrix"]["file_mutations"]["callable_by_chatgpt_connector"])
                diag_res = by_id[12]["result"]["structuredContent"]["result"]
                self.assertEqual(diag_res["symptom_classification"]["http_status"], 429)
                self.assertIsNone(diag_res["desktop_name"])

                calc_read = by_id[14]["result"]["structuredContent"]["result"]
                orig_hash = calc_read["hash"]
                policy_res = by_id[15]["result"]["structuredContent"]["result"]
                self.assertNotIn("root", policy_res)
                self.assertEqual(policy_res["exec_policy"]["max_files"], 48)
                self.assertTrue(by_id[16]["result"]["structuredContent"]["result"]["clean"])

                for blocked_id in (18, 19, 20):
                    err_block = by_id[blocked_id]["result"]["structuredContent"]
                    self.assertEqual(err_block["code"], "BRIDGE_POLICY_DENIED")
                    self.assertEqual(err_block["reason"], "PRINCIPAL_READ_ONLY")

                # Step 4: Fix bug locally via owner apply-patch-plan (idempotent operation_id)
                fixed_code = "def add(a, b):\n    return a + b\n"
                patch_payload = json.dumps(
                    [{"path": "calculator.py", "content": fixed_code, "expected_hash": orig_hash}]
                )
                rc, p_out, p_err = _cli(
                    state,
                    "apply-patch-plan",
                    project_id,
                    "--operation-id",
                    "local-fix-1",
                    "--json",
                    patch_payload,
                    "--confirm",
                )
                self.assertEqual(rc, 0, p_err)
                # Replay idempotency returns same receipt
                rc2, p_out2, p_err2 = _cli(
                    state,
                    "apply-patch-plan",
                    project_id,
                    "--operation-id",
                    "local-fix-1",
                    "--json",
                    patch_payload,
                    "--confirm",
                )
                self.assertEqual(rc2, 0, p_err2)
                self.assertEqual(json.loads(p_out), json.loads(p_out2))

                # Step 5: Run real Python MXC project_tests job
                job_resp = call_broker(
                    state,
                    "local",
                    "process_start",
                    {
                        "project_id": project_id,
                        "task_id": "t-calc-fix",
                        "operation_id": "run-calc-tests",
                        "executable": "python",
                        "argv": ["-B", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
                        "cwd_relative": ".",
                        "timeout_seconds": 30,
                    },
                )
                job_id = job_resp["job_id"]
                deadline = time.monotonic() + 20
                job_state = None
                while time.monotonic() < deadline:
                    job_state = call_broker(state, "local", "job_get", {"project_id": project_id, "job_id": job_id})
                    if job_state["status"] in {"succeeded", "failed", "timed_out", "cancelled"}:
                        break
                    time.sleep(0.1)
                self.assertIsNotNone(job_state)
                self.assertEqual(job_state["status"], "succeeded", job_state)
                self.assertEqual(job_state["exit_code"], 0)
                job_log = call_broker(state, "local", "job_output", {"project_id": project_id, "job_id": job_id})
                self.assertIn("OK", job_log["output"])

                # Step 6: Non-destructive git checkpoint + task checkpoint + record incident
                ckpt = call_broker(
                    state,
                    "local",
                    "git_checkpoint",
                    {
                        "project_id": project_id,
                        "operation_id": "ckpt-calc-1",
                        "task_id": "t-calc-fix",
                        "checkpoint_id": "cp-fixed",
                        "message": "calc bug fixed and tested",
                    },
                )
                self.assertTrue(ckpt["non_destructive"])
                call_broker(
                    state,
                    "local",
                    "task_checkpoint",
                    {
                        "project_id": project_id,
                        "operation_id": "task-ckpt-1",
                        "task_id": "t-calc-fix",
                        "objective": "Fix add() in calculator.py",
                        "summary": "Fixed add() operator from '-' to '+' and verified unittest inside MXC.",
                        "next_action": "Hand off to ChatGPT GPT-6 Pro for review.",
                        "changed_files": [{"path": "calculator.py"}],
                        "test_evidence": [{"job_id": job_id, "exit_code": 0}],
                        "accepted_decisions": ["Use MXC snapshot for project_tests"],
                    },
                )
                rc_inc, _, err_inc = _cli(
                    state,
                    "record-incident",
                    "--source",
                    "chatgpt",
                    "--category",
                    "http_429",
                    "--summary",
                    "MCP SSE probe returned 429 from openai.org",
                    "--http-status",
                    "429",
                )
                self.assertEqual(rc_inc, 0, err_inc)

                # Step 7 & 8: Emergency stop-all & SQLite backup
                rc_sa, sa_out, sa_err = _cli(state, "stop-all")
                self.assertEqual(rc_sa, 0, sa_err)
                self.assertFalse(json.loads(sa_out)["workers"]["enabled"])

                # Reject backup inside project root
                rc_bad_bk, _, _ = _cli(state, "backup", str(proj / "bad.sqlite3"))
                self.assertNotEqual(rc_bad_bk, 0)

                good_backup = base / "backups" / "takeover.sqlite3"
                rc_bk, bk_out, bk_err = _cli(state, "backup", str(good_backup))
                self.assertEqual(rc_bk, 0, bk_err)
                self.assertEqual(json.loads(bk_out)["integrity_check"], "ok")

                # Step 9: Stop broker, restart fresh broker, verify seamless Edge MCP resume
                self.assertEqual(_cli(state, "stop")[0], 0)
                broker_proc.wait(timeout=10)
                broker_proc.stdout.close()
                broker_proc.stderr.close()
                broker_proc = start_broker()

                resumed_replies, _ = _mcp_exchange(
                    state,
                    "edge",
                    [
                        ("project_resume", {"project_id": project_id, "task_id": "t-calc-fix"}),
                        ("task_get", {"project_id": project_id, "task_id": "t-calc-fix"}),
                        ("git_status", {"project_id": project_id}),
                    ],
                )
                res_map = {
                    r["id"]: r["result"]["structuredContent"]["result"]
                    for r in resumed_replies
                    if isinstance(r.get("id"), int) and r["id"] >= 10
                }
                self.assertTrue(res_map[10]["handoff_ready"])
                self.assertIn("Fixed add()", res_map[10]["summary"])
                self.assertEqual(res_map[11]["checkpoint_revision"], 1)
                self.assertEqual(res_map[12]["entries"][0]["path"], "calculator.py")

                # Step 10: Run CLI doctor --json --probe-mcp --support-bundle
                rc_doc, doc_out, doc_err = _cli(
                    state,
                    "doctor",
                    "--json",
                    "--probe-mcp",
                    "--support-bundle",
                    "--symptom",
                    "MCP SSE probe returned 429 from openai.org",
                )
                self.assertEqual(rc_doc, 0, doc_err)
                bundle = json.loads(doc_out)
                self.assertEqual(bundle["layers"]["mcp_stdio"]["status"], "PASS")
                self.assertEqual(bundle["symptom_classification"]["category"], "UPSTREAM_CONNECTOR_RATE_LIMIT_429")
                self.assertFalse(bundle["symptom_classification"]["local_fixable"])
            finally:
                try:
                    _cli(state, "stop")
                except Exception:
                    pass
                if broker_proc.poll() is None:
                    broker_proc.terminate()
                broker_proc.wait(timeout=10)
                broker_proc.stdout.close()
                broker_proc.stderr.close()

    def test_apply_patch_plan_requires_confirmation_in_non_tty_mode(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            state = base / "state"
            proj = base / "proj"
            proj.mkdir()
            target = proj / "app.py"
            target.write_text("VALUE = 1\n", encoding="utf-8")
            orig_hash = hashlib.sha256(target.read_bytes()).hexdigest()

            self.assertEqual(_cli(state, "install")[0], 0)
            broker_proc = subprocess.Popen(
                [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "start"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertIn("Edge Project Bridge ready", broker_proc.stdout.readline())
                reg = call_broker(state, "local", "owner_register", {"root": str(proj), "name": "ConfirmGate"})
                pid = reg["project_id"]
                plan = json.dumps([{"path": "app.py", "content": "VALUE = 2\n", "expected_hash": orig_hash}])
                rc, _, err = _cli(state, "apply-patch-plan", pid, "--operation-id", "no-confirm-1", "--json", plan)
                self.assertNotEqual(rc, 0)
                self.assertIn("CONFIRMATION_REQUIRED", err)
                self.assertIn("[patch-preview]", err)
                self.assertIn("-VALUE = 1", err)
                self.assertIn("+VALUE = 2", err)
                self.assertEqual(target.read_text(encoding="utf-8"), "VALUE = 1\n")
            finally:
                try:
                    _cli(state, "stop")
                    broker_proc.wait(timeout=5)
                except Exception:
                    if broker_proc.poll() is None:
                        broker_proc.terminate()
                        broker_proc.wait(timeout=5)
                broker_proc.stdout.close()
                broker_proc.stderr.close()

    def test_hybrid_self_dev_10_step_round_trip_with_failure_recovery(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            state = base / "state"
            proj = base / "isolated-git-repo"
            proj.mkdir()
            (proj / "tests").mkdir()
            (proj / "tests" / "__init__.py").write_text("", encoding="utf-8")
            (proj / "calculator.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
            (proj / "tests" / "test_calculator.py").write_text(
                "import unittest\nfrom calculator import add\n\n"
                "class CalcTest(unittest.TestCase):\n"
                "    def test_add(self):\n"
                "        self.assertEqual(add(2, 3), 5)\n",
                encoding="utf-8",
            )
            _git(proj, "init")
            _git(proj, "add", ".")
            _git(proj, "commit", "-m", "baseline broken calculator")

            self.assertEqual(_cli(state, "install")[0], 0)

            def start_broker():
                proc = subprocess.Popen(
                    [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "start"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                ready = proc.stdout.readline()
                self.assertIn("Edge Project Bridge ready on 127.0.0.1:", ready)
                return proc

            broker_proc = start_broker()
            try:
                rc, reg_out, reg_err = _cli(state, "register", str(proj), "--name", "SelfDev Hybrid Repo")
                self.assertEqual(rc, 0, reg_err)
                project_id = json.loads(reg_out)["project_id"]
                self.assertEqual(_cli(state, "grant-edge", project_id)[0], 0)
                self.assertEqual(
                    _cli(state, "grant-python-tests", project_id, "calculator.py", "tests/__init__.py", "tests/test_calculator.py")[0],
                    0,
                )

                # Step 1: Connect to MCP & record dynamic capabilities (GPT-6 Pro, Extra High, future model)
                self.assertEqual(
                    _cli(
                        state, "model-capabilities", "--record",
                        "--model", "GPT-6 Pro", "--surface", "chatgpt_web_edge",
                        "--caps-json", '{"mcp_invoke": true, "mcp_read": true}', "--source", "round_trip",
                    )[0],
                    0,
                )
                self.assertEqual(
                    _cli(
                        state, "model-capabilities", "--record",
                        "--model", "GPT-7-Future", "--surface", "chatgpt_web_edge",
                        "--caps-json", '{"mcp_invoke": true, "mcp_read": true}', "--source", "round_trip",
                    )[0],
                    0,
                )
                s1_replies, _ = _mcp_exchange(state, "edge", [("bridge_info", {}), ("project_list", {})])
                s1_map = {r["id"]: r["result"]["structuredContent"]["result"] for r in s1_replies if isinstance(r.get("id"), int) and r["id"] >= 10}
                orig_instance_id = s1_map[10]["instance_id"]
                self.assertEqual(s1_map[10]["model_capabilities"]["preferred_default_model"], "GPT-6 Pro")
                self.assertIn("GPT-7-Future", s1_map[10]["model_capabilities"]["observed_models"])

                # Step 2: Read existing project file + Git status via Edge MCP
                s2_replies, _ = _mcp_exchange(
                    state, "edge",
                    [("file_read", {"project_id": project_id, "path": "calculator.py"}), ("git_status", {"project_id": project_id})],
                )
                s2_map = {r["id"]: r["result"]["structuredContent"]["result"] for r in s2_replies if isinstance(r.get("id"), int) and r["id"] >= 10}
                orig_hash = s2_map[10]["hash"]
                self.assertTrue(s2_map[11]["clean"])

                # Step 3: Seed initial checkpoint & retrieve via project_resume (with fallback plan)
                call_broker(
                    state, "local", "task_checkpoint",
                    {
                        "project_id": project_id,
                        "task_id": "t-roundtrip",
                        "operation_id": "rt-ckpt-0",
                        "objective": "Fix add() via hybrid ChatGPT + Owner CLI round trip",
                        "summary": "Initial failing baseline inspected",
                        "next_action": "Prepare hash-checked edit proposal",
                    },
                )
                s3_replies, _ = _mcp_exchange(state, "edge", [("project_resume", {"project_id": project_id, "task_id": "t-roundtrip"})])
                s3_res = {r["id"]: r["result"]["structuredContent"]["result"] for r in s3_replies if isinstance(r.get("id"), int) and r["id"] >= 10}[10]
                self.assertTrue(s3_res["handoff_ready"])
                self.assertTrue(s3_res["fallback_plan"]["fallback_required"])

                # Step 4 & 5: Prepare hash-checked patch plan JSON file with intentional bug -> reject without --confirm -> apply with --confirm --verify
                bad_plan_file = base / "bad_plan.json"
                bad_plan_file.write_text(
                    json.dumps({
                        "project_id": project_id,
                        "task_id": "t-roundtrip",
                        "operation_id": "rt-patch-bad",
                        "model_id": "GPT-6 Pro",
                        "summary": "Intentional multiplication bug to exercise Step 8 failure recovery",
                        "edits": [{"path": "calculator.py", "content": "def add(a, b):\n    return a * b\n", "expected_hash": orig_hash}],
                    }),
                    encoding="utf-8",
                )
                rc_no, _, err_no = _cli(state, "apply-patch-plan", project_id, "--json", str(bad_plan_file))
                self.assertNotEqual(rc_no, 0)
                self.assertIn("CONFIRMATION_REQUIRED", err_no)
                self.assertIn("a - b", (proj / "calculator.py").read_text(encoding="utf-8"))

                rc_bad, out_bad, err_bad = _cli(
                    state, "apply-patch-plan", project_id, "--json", str(bad_plan_file), "--confirm", "--verify",
                )
                self.assertEqual(rc_bad, 0, err_bad)
                self.assertIn("[patch-preview]", err_bad)
                self.assertIn("status=MATCH", err_bad)
                bad_receipt = json.loads(out_bad)

                # Step 6: Intentional test failure recorded in artifacts & checkpoint
                self.assertEqual(bad_receipt["verification"]["verdict"], "FAIL")
                self.assertNotEqual(bad_receipt["verification"]["exit_code"], 0)
                fail_art_id = bad_receipt["artifacts"]["test"]["artifact_id"]

                # Step 7: ChatGPT Edge reads failure outcome & artifacts (job_output remains denied)
                s7_replies, _ = _mcp_exchange(
                    state, "edge",
                    [
                        ("project_resume", {"project_id": project_id, "task_id": "t-roundtrip"}),
                        ("artifact_read", {"project_id": project_id, "artifact_id": fail_art_id}),
                        ("file_read", {"project_id": project_id, "path": "calculator.py"}),
                        ("git_diff", {"project_id": project_id}),
                        ("job_output", {"project_id": project_id, "job_id": bad_receipt["verification"]["job_id"]}),
                    ],
                )
                s7_by_id = {r["id"]: r for r in s7_replies if isinstance(r.get("id"), int) and r["id"] >= 10}
                s7_resume = s7_by_id[10]["result"]["structuredContent"]["result"]
                s7_art = s7_by_id[11]["result"]["structuredContent"]["result"]
                s7_calc = s7_by_id[12]["result"]["structuredContent"]["result"]
                s7_diff = s7_by_id[13]["result"]["structuredContent"]["result"]
                self.assertIn("FAIL", s7_resume["summary"])
                self.assertIn("FAIL", s7_art["content"])
                self.assertIn("a * b", s7_calc["content"])
                self.assertIn("+    return a * b", s7_diff["content"])
                self.assertEqual(s7_by_id[14]["result"]["structuredContent"]["code"], "BRIDGE_POLICY_DENIED")

                # Step 8: Adjust proposal on failure -> paste via --paste + EOF sentinel -> re-apply -> re-test PASS
                adjusted_plan = json.dumps({
                    "project_id": project_id,
                    "task_id": "t-roundtrip",
                    "operation_id": "rt-patch-good",
                    "model_id": "Extra High",
                    "summary": "Adjusted proposal fixing add() to return a + b",
                    "edits": [{"path": "calculator.py", "content": "def add(a, b):\n    return a + b\n", "expected_hash": s7_calc["hash"]}],
                })
                rc_good, out_good, err_good = _cli(
                    state, "apply-patch-plan", project_id, "--paste", "--confirm", "--verify",
                    stdin_text=adjusted_plan + "\nEOF\n",
                )
                self.assertEqual(rc_good, 0, err_good)
                good_receipt = json.loads(out_good)
                self.assertEqual(good_receipt["verification"]["verdict"], "PASS")
                self.assertEqual(good_receipt["verification"]["exit_code"], 0)
                pass_art_id = good_receipt["artifacts"]["test"]["artifact_id"]
                diff_art_id = good_receipt["artifacts"]["git_diff"]["artifact_id"]

                # Replay apply-patch-plan --confirm --verify with identical operation_id succeeds idempotently
                rc_replay, out_replay, err_replay = _cli(
                    state, "apply-patch-plan", project_id, "--paste", "--confirm", "--verify",
                    stdin_text=adjusted_plan + "\nEOF\n",
                )
                self.assertEqual(rc_replay, 0, err_replay)
                replay_receipt = json.loads(out_replay)
                self.assertEqual(replay_receipt["artifacts"]["test"]["artifact_id"], pass_art_id)
                self.assertEqual(replay_receipt["artifacts"]["git_diff"]["artifact_id"], diff_art_id)

                # Step 9: Verify Git Diff & Artifacts from Edge MCP
                s9_replies, _ = _mcp_exchange(
                    state, "edge",
                    [
                        ("git_diff", {"project_id": project_id}),
                        ("artifact_read", {"project_id": project_id, "artifact_id": diff_art_id}),
                        ("artifact_read", {"project_id": project_id, "artifact_id": pass_art_id}),
                    ],
                )
                s9_map = {r["id"]: r["result"]["structuredContent"]["result"] for r in s9_replies if isinstance(r.get("id"), int) and r["id"] >= 10}
                self.assertIn("+    return a + b", s9_map[10]["content"])
                self.assertIn("+    return a + b", s9_map[11]["content"])
                self.assertIn("OK", s9_map[12]["content"])

                # Step 10: Model switch + Broker restart + New Edge MCP session resume
                self.assertEqual(
                    _cli(
                        state, "model-capabilities", "--record",
                        "--model", "Extra High", "--surface", "chatgpt_web_edge",
                        "--caps-json", '{"mcp_invoke": true, "mcp_read": true}', "--source", "model_switch",
                    )[0],
                    0,
                )
                self.assertEqual(_cli(state, "stop")[0], 0)
                broker_proc.wait(timeout=10)
                broker_proc.stdout.close()
                broker_proc.stderr.close()
                broker_proc = start_broker()

                s10_replies, _ = _mcp_exchange(
                    state, "edge",
                    [
                        ("bridge_info", {}),
                        ("project_resume", {"project_id": project_id, "task_id": "t-roundtrip"}),
                        ("task_get", {"project_id": project_id, "task_id": "t-roundtrip"}),
                        ("artifact_list", {"project_id": project_id, "task_id": "t-roundtrip"}),
                    ],
                )
                s10_map = {r["id"]: r["result"]["structuredContent"]["result"] for r in s10_replies if isinstance(r.get("id"), int) and r["id"] >= 10}
                self.assertEqual(s10_map[10]["instance_id"], orig_instance_id)
                self.assertIn("Extra High", s10_map[10]["model_capabilities"]["observed_models"])
                self.assertTrue(s10_map[11]["handoff_ready"])
                self.assertIn("PASS", s10_map[11]["summary"])
                self.assertEqual(s10_map[12]["task_id"], "t-roundtrip")
                self.assertGreaterEqual(s10_map[13]["artifacts"].__len__(), 4)
            finally:
                try:
                    _cli(state, "stop")
                except Exception:
                    pass
                if broker_proc.poll() is None:
                    broker_proc.terminate()
                broker_proc.wait(timeout=10)
                broker_proc.stdout.close()
                broker_proc.stderr.close()

    def test_apply_patch_plan_verification_command_preview_and_allow_host_verify_gates(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            state = base / "state"
            proj = base / "proj"
            proj.mkdir()
            target = proj / "app.py"
            target.write_text("VALUE = 1\n", encoding="utf-8")
            hash1 = hashlib.sha256(target.read_bytes()).hexdigest()
            side_effect_file = proj / "host_verify_ran.txt"

            self.assertEqual(_cli(state, "install")[0], 0)
            broker_proc = subprocess.Popen(
                [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "start"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertIn("Edge Project Bridge ready", broker_proc.stdout.readline())
                reg = call_broker(state, "local", "owner_register", {"root": str(proj), "name": "HostVerifyGate"})
                pid = reg["project_id"]

                plan_obj = {
                    "project_id": pid,
                    "task_id": "t-host-gate",
                    "operation_id": "op-gate-1",
                    "summary": "Update VALUE with verification_command",
                    "verification_command": [
                        sys.executable,
                        "-c",
                        "from pathlib import Path; Path('host_verify_ran.txt').write_text('EXECUTED', encoding='utf-8'); print('HOST_VERIFY_OK')",
                    ],
                    "edits": [{"path": "app.py", "content": "VALUE = 2\n", "expected_hash": hash1}],
                }
                plan_path = base / "plan.json"
                plan_path.write_text(json.dumps(plan_obj), encoding="utf-8")

                # (a) Without --verify, previews verification_command as skipped and does NOT execute it
                rc_skip, out_skip, err_skip = _cli(
                    state, "apply-patch-plan", pid, "--json", str(plan_path), "--confirm",
                )
                self.assertEqual(rc_skip, 0, err_skip)
                self.assertIn("verification_command=", err_skip)
                self.assertIn("skipped (pass --verify to run)", err_skip)
                self.assertFalse(side_effect_file.exists())
                self.assertEqual(target.read_text(encoding="utf-8"), "VALUE = 2\n")
                self.assertNotIn("verification", json.loads(out_skip))

                # Prepare second patch for (b) and (c)
                hash2 = hashlib.sha256(target.read_bytes()).hexdigest()
                plan_obj2 = {
                    **plan_obj,
                    "operation_id": "op-gate-2",
                    "edits": [{"path": "app.py", "content": "VALUE = 3\n", "expected_hash": hash2}],
                }
                plan_path2 = base / "plan2.json"
                plan_path2.write_text(json.dumps(plan_obj2), encoding="utf-8")

                # (b) --verify with unsandboxed plan_verification_command fails closed without --allow-host-verify before mutating files
                rc_blk, _, err_blk = _cli(
                    state, "apply-patch-plan", pid, "--json", str(plan_path2), "--confirm", "--verify",
                )
                self.assertNotEqual(rc_blk, 0)
                self.assertIn("CONFIRMATION_REQUIRED", err_blk)
                self.assertIn("--allow-host-verify", err_blk)
                self.assertIn("verification_command=", err_blk)
                self.assertIn("unsandboxed host", err_blk)
                self.assertEqual(target.read_text(encoding="utf-8"), "VALUE = 2\n")
                self.assertFalse(side_effect_file.exists())

                # Negative preflight tests: bad --artifact-dir or invalid task_id fails closed BEFORE mutating target files
                for extra_args in (
                    ["--artifact-dir", "../escape"],
                    ["--artifact-dir", ".git"],
                    ["--task-id", "bad:task"],
                ):
                    rc_bad, _, _ = _cli(
                        state,
                        "apply-patch-plan",
                        pid,
                        "--json",
                        str(plan_path2),
                        "--confirm",
                        "--verify",
                        "--allow-host-verify",
                        *extra_args,
                    )
                    self.assertNotEqual(rc_bad, 0)
                    self.assertEqual(target.read_text(encoding="utf-8"), "VALUE = 2\n")
                    self.assertFalse(side_effect_file.exists())

                # (c) --verify --allow-host-verify previews and executes cleanly
                rc_ok, out_ok, err_ok = _cli(
                    state,
                    "apply-patch-plan",
                    pid,
                    "--json",
                    str(plan_path2),
                    "--confirm",
                    "--verify",
                    "--allow-host-verify",
                )
                self.assertEqual(rc_ok, 0, err_ok)
                self.assertIn("verification_command=", err_ok)
                self.assertIn("unsandboxed host (plan_verification_command)", err_ok)
                res_ok = json.loads(out_ok)
                self.assertEqual(res_ok["verification"]["mode"], "plan_verification_command")
                self.assertEqual(res_ok["verification"]["verdict"], "PASS")
                self.assertEqual(target.read_text(encoding="utf-8"), "VALUE = 3\n")
                self.assertEqual(side_effect_file.read_text(encoding="utf-8"), "EXECUTED")
            finally:
                try:
                    _cli(state, "stop")
                except Exception:
                    pass
                if broker_proc.poll() is None:
                    broker_proc.terminate()
                broker_proc.wait(timeout=10)
                broker_proc.stdout.close()
                broker_proc.stderr.close()
