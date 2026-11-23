import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


def _binary_path() -> Path:
    override = os.environ.get("EPB_MCP_TEST_BINARY")
    if override:
        return Path(override)
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "target" / "x86_64-pc-windows-gnullvm" / "release" / "edge-bridge.exe"


def _mk_junction(link: Path, target: Path) -> None:
    if os.name == "nt":
        proc = subprocess.run(
            ["cmd.exe", "/D", "/C", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"mklink /J failed: {proc.stdout} {proc.stderr}")
    else:
        os.symlink(target, link)


def _rm_junction(link: Path) -> None:
    if not link.exists() and not link.is_symlink():
        return
    if os.name == "nt":
        os.rmdir(link)
    else:
        os.unlink(link)


class ProAgentWorkContractTest(unittest.TestCase):
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
        self.outside = self.tmp / "outside"
        self.project.mkdir()
        self.outside.mkdir()
        (self.project / "src").mkdir()
        (self.project / "tests").mkdir()
        (self.project / "_pro" / "inbox").mkdir(parents=True)
        (self.project / "src" / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
        (self.project / "tests" / "test_calc.py").write_text("assert True\n", encoding="utf-8")
        (self.project / ".env").write_text("SECRET_TOKEN=topsecret\n", encoding="utf-8")
        (self.project / "src" / "auth.json").write_text('{"token":"topsecret"}\n', encoding="utf-8")
        (self.project / "_pro" / "inbox" / "request.md").write_text("Fix calc.py\n", encoding="utf-8")
        (self.outside / "outside.txt").write_text("OUTSIDE_UNTOUCHED\n", encoding="utf-8")
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

    def test_pro_agent_work_area_end_to_end_and_boundaries(self):
        reg = json.loads(self.cli("register", str(self.project), "--name", "WP3 fixture", "--grant-edge").stdout)
        pid = reg["project_id"]

        agent_grant = json.loads(self.cli("grant-create", pid, "--profile", "pro-agent").stdout)
        agent_gid = agent_grant["grant_id"]
        review_grant = json.loads(
            self.cli("grant-create", pid, "--requester", "executor:review", "--profile", "pro-review").stdout
        )
        review_gid = review_grant["grant_id"]
        legacy_grant = json.loads(
            self.cli("grant-create", pid, "--requester", "executor:legacy", "--writable-path", "_pro/**").stdout
        )
        legacy_gid = legacy_grant["grant_id"]

        # 1. work_copy copies src + tests, hides .env / auth.json / _pro, creates bridge manifest, shows in policy_view.
        copy_res, pv_res = self.mcp_calls(
            "executor:default",
            [
                ("work_copy", {"project_id": pid, "grant_id": agent_gid, "workspace": "fix-1", "paths": ["."]}),
                ("policy_view", {"project_id": pid, "grant_id": agent_gid}),
            ],
        )
        self.assertFalse(copy_res["isError"], copy_res)
        copied = copy_res["structuredContent"]["result"]
        self.assertEqual(copied["files_copied"], ["_pro/work/fix-1/src/calc.py", "_pro/work/fix-1/tests/test_calc.py"])
        self.assertNotIn(".env", json.dumps(copy_res))
        self.assertNotIn("auth.json", json.dumps(copy_res))
        self.assertNotIn("request.md", json.dumps(copy_res))
        self.assertFalse((self.project / "_pro" / "work" / "fix-1" / ".env").exists())
        self.assertFalse((self.project / "_pro" / "work" / "fix-1" / "_pro").exists())
        self.assertTrue((self.state_dir / "work-manifests" / pid / "fix-1.json").is_file())
        self.assertEqual(pv_res["structuredContent"]["result"]["work_area"]["workspaces"], ["fix-1"])

        # 2. work_edit atomic failure leaves files unchanged, then valid edit succeeds while live src/calc.py stays untouched.
        fail_edit, ok_edit = self.mcp_calls(
            "executor:default",
            [
                (
                    "work_edit",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "workspace": "fix-1",
                        "operation_id": "op_e_fail",
                        "edits": [
                            {"path": "src/calc.py", "replacements": [{"old_text": "a - b", "new_text": "a + b"}]},
                            {"path": "tests/test_calc.py", "replacements": [{"old_text": "MISSING", "new_text": "X"}]},
                        ],
                    },
                ),
                (
                    "work_edit",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "workspace": "fix-1",
                        "operation_id": "op_e_ok",
                        "edits": [
                            {"path": "src/calc.py", "replacements": [{"old_text": "a - b", "new_text": "a + b"}]},
                        ],
                    },
                ),
            ],
        )
        self.assertTrue(fail_edit["isError"])
        self.assertEqual(fail_edit["structuredContent"]["code"], "VERSION_CONFLICT")
        self.assertFalse(ok_edit["isError"], ok_edit)
        self.assertEqual((self.project / "src" / "calc.py").read_text(encoding="utf-8"), "def add(a, b):\n    return a - b\n")
        self.assertEqual(
            (self.project / "_pro" / "work" / "fix-1" / "src" / "calc.py").read_text(encoding="utf-8"),
            "def add(a, b):\n    return a + b\n",
        )

        # 3. file_write / file_patch overwrite inside _pro/work/fix-1/** with expected_hash;
        #    _pro/outbox and _pro/reports stay create-only; _pro/inbox stays refused.
        cur_hash = ok_edit["structuredContent"]["result"]["postimage_hashes"]["_pro/work/fix-1/src/calc.py"]
        fw_ow, outbox_create, outbox_ow, inbox_deny = self.mcp_calls(
            "executor:default",
            [
                (
                    "file_write",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "operation_id": "op_fw_ow",
                        "path": "_pro/work/fix-1/src/calc.py",
                        "content": "def add(a, b):\n    return int(a + b)\n",
                        "expected_hash": cur_hash,
                    },
                ),
                (
                    "file_write",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "operation_id": "op_outbox_new",
                        "path": "_pro/outbox/reply.md",
                        "content": "done\n",
                    },
                ),
                (
                    "file_write",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "operation_id": "op_outbox_ow",
                        "path": "_pro/outbox/reply.md",
                        "content": "overwritten\n",
                        "expected_hash": hashlib.sha256(b"done\n").hexdigest(),
                    },
                ),
                (
                    "file_write",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "operation_id": "op_inbox_forged",
                        "path": "_pro/inbox/forged.md",
                        "content": "forged\n",
                    },
                ),
            ],
        )
        self.assertFalse(fw_ow["isError"], fw_ow)
        self.assertFalse(outbox_create["isError"], outbox_create)
        self.assertTrue(outbox_ow["isError"])
        self.assertEqual(outbox_ow["structuredContent"]["code"], "BRIDGE_POLICY_DENIED")
        self.assertTrue(inbox_deny["isError"])
        self.assertEqual(inbox_deny["structuredContent"]["code"], "BRIDGE_POLICY_DENIED")

        # 4. pro-review, legacy grant, and edge are refused on every new tool and work-area overwrite.
        new_hash = fw_ow["structuredContent"]["result"]["postimage_hashes"]["_pro/work/fix-1/src/calc.py"]
        for principal, gid in [
            ("edge", None),
            ("executor:review", review_gid),
            ("executor:legacy", legacy_gid),
        ]:
            extra = {"grant_id": gid} if gid else {}
            res_list = self.mcp_calls(
                principal,
                [
                    ("work_copy", {"project_id": pid, "workspace": "fix-2", "paths": ["src/calc.py"], **extra}),
                    (
                        "work_edit",
                        {
                            "project_id": pid,
                            "workspace": "fix-1",
                            "operation_id": "op_deny_e",
                            "edits": [{"path": "src/calc.py", "replacements": [{"old_text": "int", "new_text": "str"}]}],
                            **extra,
                        },
                    ),
                    (
                        "work_move",
                        {
                            "project_id": pid,
                            "workspace": "fix-1",
                            "operation_id": "op_deny_m",
                            "from": "src/calc.py",
                            "to": "src/calc2.py",
                            **extra,
                        },
                    ),
                    (
                        "work_delete",
                        {
                            "project_id": pid,
                            "workspace": "fix-1",
                            "operation_id": "op_deny_d",
                            "paths": ["src/calc.py"],
                            **extra,
                        },
                    ),
                    (
                        "file_write",
                        {
                            "project_id": pid,
                            "operation_id": "op_deny_fw",
                            "path": "_pro/work/fix-1/src/calc.py",
                            "content": "denied\n",
                            "expected_hash": new_hash,
                            **extra,
                        },
                    ),
                ],
            )
            for idx, res in enumerate(res_list):
                self.assertTrue(res["isError"], f"{principal} call {idx}: {res}")
                self.assertEqual(res["structuredContent"]["code"], "BRIDGE_POLICY_DENIED", f"{principal} call {idx}")

        # 5. Hardlink inside workspace to live file is refused; junction inside workspace blocks delete_workspace.
        hl = self.project / "_pro" / "work" / "fix-1" / "hard.py"
        os.link(self.project / "src" / "calc.py", hl)
        hl_res = self.mcp_calls(
            "executor:default",
            [
                (
                    "file_write",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "operation_id": "op_hl_fw",
                        "path": "_pro/work/fix-1/hard.py",
                        "content": "PWN\n",
                        "expected_hash": hashlib.sha256(b"def add(a, b):\n    return a - b\n").hexdigest(),
                    },
                )
            ],
        )[0]
        self.assertTrue(hl_res["isError"])
        self.assertEqual(hl_res["structuredContent"]["code"], "UNSUPPORTED_PATH_TYPE")
        self.assertEqual((self.project / "src" / "calc.py").read_text(encoding="utf-8"), "def add(a, b):\n    return a - b\n")
        hl.unlink()

        junc = self.project / "_pro" / "work" / "fix-1" / "link_out"
        _mk_junction(junc, self.outside)
        junc_del = self.mcp_calls(
            "executor:default",
            [
                (
                    "work_delete",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "workspace": "fix-1",
                        "operation_id": "op_del_junc",
                        "delete_workspace": True,
                    },
                )
            ],
        )[0]
        self.assertTrue(junc_del["isError"])
        self.assertEqual(junc_del["structuredContent"]["code"], "UNSUPPORTED_PATH_TYPE")
        self.assertEqual((self.outside / "outside.txt").read_text(encoding="utf-8"), "OUTSIDE_UNTOUCHED\n")
        _rm_junction(junc)

        # 6. work_move + work_delete(delete_workspace=true) clean up workspace and manifest only.
        mv_res, del_ws_res = self.mcp_calls(
            "executor:default",
            [
                (
                    "work_move",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "workspace": "fix-1",
                        "operation_id": "op_mv_ok",
                        "from": "src/calc.py",
                        "to": "src/calc_new.py",
                    },
                ),
                (
                    "work_delete",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "workspace": "fix-1",
                        "operation_id": "op_del_ok",
                        "delete_workspace": True,
                    },
                ),
            ],
        )
        self.assertFalse(mv_res["isError"], mv_res)
        self.assertFalse(del_ws_res["isError"], del_ws_res)
        self.assertTrue(del_ws_res["structuredContent"]["result"]["deleted_workspace"])
        self.assertFalse((self.project / "_pro" / "work" / "fix-1").exists())
        self.assertFalse((self.state_dir / "work-manifests" / pid / "fix-1.json").exists())
        self.assertTrue((self.project / "_pro" / "outbox" / "reply.md").is_file())

    def test_work_diff_export_git_apply_and_owner_work_apply_with_rollback(self):
        # Initialize project as a real temporary Git repository so we can run `git apply --check`.
        def git(*args):
            return subprocess.run(
                ["git", *args],
                cwd=self.project,
                capture_output=True,
                encoding="utf-8",
                timeout=20,
            )

        self.assertEqual(git("init").returncode, 0)
        self.assertEqual(git("config", "user.name", "Contract Test").returncode, 0)
        self.assertEqual(git("config", "user.email", "test@example.com").returncode, 0)
        self.assertEqual(git("config", "core.autocrlf", "false").returncode, 0)
        (self.project / "src" / "remove_me.py").write_text("OLD = 1\n", encoding="utf-8")
        (self.project / "src" / "rename_me.py").write_text("def keep():\n    return 7\n", encoding="utf-8")
        (self.project / "src" / "no_nl.txt").write_bytes(b"line1\nline2")
        (self.project / "src" / "untouched.py").write_text("UNCOPIED = True\n", encoding="utf-8")
        self.assertEqual(git("add", "src", "tests").returncode, 0)
        self.assertEqual(git("commit", "-m", "initial").returncode, 0)

        reg = json.loads(self.cli("register", str(self.project), "--name", "WP4 fixture", "--grant-edge").stdout)
        pid = reg["project_id"]
        agent_gid = json.loads(self.cli("grant-create", pid, "--profile", "pro-agent").stdout)["grant_id"]
        review_gid = json.loads(
            self.cli("grant-create", pid, "--requester", "executor:review", "--profile", "pro-review").stdout
        )["grant_id"]
        legacy_gid = json.loads(
            self.cli("grant-create", pid, "--requester", "executor:legacy", "--writable-path", "_pro/**").stdout
        )["grant_id"]

        # Copy specific files, modify, rename, delete, and add (including no-final-newline files).
        copy_res, edit_res, mv_res, del_res, add_res = self.mcp_calls(
            "executor:default",
            [
                (
                    "work_copy",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "workspace": "wp4",
                        "paths": [
                            "src/calc.py",
                            "src/remove_me.py",
                            "src/rename_me.py",
                            "src/no_nl.txt",
                        ],
                    },
                ),
                (
                    "work_edit",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "workspace": "wp4",
                        "operation_id": "op_wp4_edit",
                        "edits": [
                            {"path": "src/calc.py", "replacements": [{"old_text": "a - b", "new_text": "a + b"}]},
                            {"path": "src/no_nl.txt", "replacements": [{"old_text": "line2", "new_text": "line2_mod"}]},
                        ],
                    },
                ),
                (
                    "work_move",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "workspace": "wp4",
                        "operation_id": "op_wp4_mv",
                        "from": "src/rename_me.py",
                        "to": "src/renamed.py",
                    },
                ),
                (
                    "work_delete",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "workspace": "wp4",
                        "operation_id": "op_wp4_del",
                        "paths": ["src/remove_me.py"],
                    },
                ),
                (
                    "file_write",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "operation_id": "op_wp4_add",
                        "path": "_pro/work/wp4/src/added_no_nl.txt",
                        "content": "added_without_newline",
                    },
                ),
            ],
        )
        for r in (copy_res, edit_res, mv_res, del_res, add_res):
            self.assertFalse(r["isError"], r)

        # 1. work_diff paginates, hides .env/auth.json/untouched.py, and writes nothing on disk.
        d1 = self.mcp_calls(
            "executor:default",
            [("work_diff", {"project_id": pid, "grant_id": agent_gid, "workspace": "wp4", "limit": 100})],
        )[0]
        self.assertFalse(d1["isError"], d1)
        p1 = d1["structuredContent"]["result"]
        self.assertFalse(p1["has_drift"])
        self.assertTrue(p1["truncated"])
        self.assertIsNotNone(p1["next_offset"])
        self.assertNotIn(".env", json.dumps(p1))
        self.assertNotIn("auth.json", json.dumps(p1))
        self.assertNotIn("untouched.py", json.dumps(p1))
        self.assertFalse((self.project / "_pro" / "outbox").exists())

        # 2. work_export_diff writes one create-only .diff under `_pro/outbox/` that passes `git apply --check`.
        exp1, exp_dup = self.mcp_calls(
            "executor:default",
            [
                (
                    "work_export_diff",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "workspace": "wp4",
                        "operation_id": "op_wp4_exp1",
                        "path": "_pro/outbox/wp4.diff",
                    },
                ),
                (
                    "work_export_diff",
                    {
                        "project_id": pid,
                        "grant_id": agent_gid,
                        "workspace": "wp4",
                        "operation_id": "op_wp4_exp2",
                        "path": "_pro/outbox/wp4.diff",
                    },
                ),
            ],
        )
        self.assertFalse(exp1["isError"], exp1)
        self.assertTrue(exp_dup["isError"])
        self.assertEqual(exp_dup["structuredContent"]["code"], "VERSION_CONFLICT")
        self.assertEqual(sorted(p.name for p in (self.project / "_pro" / "outbox").iterdir()), ["wp4.diff"])

        git_check = git("apply", "--check", "_pro/outbox/wp4.diff")
        self.assertEqual(git_check.returncode, 0, git_check.stderr)

        # 3. pro-review, legacy grant, and edge are refused on work_diff and work_export_diff.
        for principal, gid in [
            ("edge", None),
            ("executor:review", review_gid),
            ("executor:legacy", legacy_gid),
        ]:
            extra = {"grant_id": gid} if gid else {}
            r_diff, r_exp = self.mcp_calls(
                principal,
                [
                    ("work_diff", {"project_id": pid, "workspace": "wp4", **extra}),
                    (
                        "work_export_diff",
                        {
                            "project_id": pid,
                            "workspace": "wp4",
                            "operation_id": "op_deny_exp",
                            "path": "_pro/outbox/denied.diff",
                            **extra,
                        },
                    ),
                ],
            )
            self.assertTrue(r_diff["isError"], f"{principal} work_diff")
            self.assertEqual(r_diff["structuredContent"]["code"], "BRIDGE_POLICY_DENIED")
            self.assertTrue(r_exp["isError"], f"{principal} work_export_diff")
            self.assertEqual(r_exp["structuredContent"]["code"], "BRIDGE_POLICY_DENIED")

        # 4. Owner CLI `edge-bridge work-apply` dry-run changes nothing, detects drift on `--confirm`,
        #    applies cleanly when clean, and `rollback-patch` reverts modify + add + delete + rename!
        dry = json.loads(self.cli("work-apply", pid, "wp4").stdout)
        self.assertFalse(dry["applied"])
        self.assertTrue(dry["confirm_required"])
        self.assertTrue(dry["safe_to_apply"])
        self.assertEqual((self.project / "src" / "calc.py").read_text(encoding="utf-8"), "def add(a, b):\n    return a - b\n")

        # Drift live src/calc.py -> `work-apply --confirm` refuses and touches NOTHING.
        (self.project / "src" / "calc.py").write_text("def add(a, b):\n    return a * b\n", encoding="utf-8")
        drifted = self.cli("work-apply", pid, "wp4", "--confirm", check=False)
        self.assertNotEqual(drifted.returncode, 0)
        self.assertIn("VersionConflict", drifted.stderr)
        self.assertTrue((self.project / "src" / "remove_me.py").exists())
        self.assertFalse((self.project / "src" / "added_no_nl.txt").exists())

        # Restore live src/calc.py -> `work-apply --confirm` applies atomically and writes rollback journal.
        (self.project / "src" / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
        applied = json.loads(self.cli("work-apply", pid, "wp4", "--confirm").stdout)
        self.assertTrue(applied["applied"])
        jid = applied["journal_id"]
        self.assertTrue(jid.startswith("pjr_"))
        self.assertEqual((self.project / "src" / "calc.py").read_text(encoding="utf-8"), "def add(a, b):\n    return a + b\n")
        self.assertEqual((self.project / "src" / "no_nl.txt").read_bytes(), b"line1\nline2_mod")
        self.assertEqual((self.project / "src" / "added_no_nl.txt").read_bytes(), b"added_without_newline")
        self.assertEqual((self.project / "src" / "renamed.py").read_text(encoding="utf-8"), "def keep():\n    return 7\n")
        self.assertFalse((self.project / "src" / "remove_me.py").exists())
        self.assertFalse((self.project / "src" / "rename_me.py").exists())

        # Existing `rollback-patch` reverts every applied change cleanly.
        rb = json.loads(self.cli("rollback-patch", "--project-root", str(self.project), "--journal-id", jid).stdout)
        self.assertEqual(len(rb["restored_files"]), 6)
        self.assertEqual((self.project / "src" / "calc.py").read_text(encoding="utf-8"), "def add(a, b):\n    return a - b\n")
        self.assertEqual((self.project / "src" / "no_nl.txt").read_bytes(), b"line1\nline2")
        self.assertEqual((self.project / "src" / "remove_me.py").read_text(encoding="utf-8"), "OLD = 1\n")
        self.assertEqual((self.project / "src" / "rename_me.py").read_text(encoding="utf-8"), "def keep():\n    return 7\n")
        self.assertFalse((self.project / "src" / "added_no_nl.txt").exists())
        self.assertFalse((self.project / "src" / "renamed.py").exists())

        # 5. Junction in workspace or at live target refused by work-apply.
        junc = self.project / "_pro" / "work" / "wp4" / "junc"
        _mk_junction(junc, self.outside)
        junc_apply = self.cli("work-apply", pid, "wp4", "--confirm", check=False)
        self.assertNotEqual(junc_apply.returncode, 0)
        self.assertIn("UnsupportedPathType", junc_apply.stderr)
        _rm_junction(junc)


if __name__ == "__main__":
    unittest.main()
