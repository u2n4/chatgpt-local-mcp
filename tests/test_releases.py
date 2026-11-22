"""Failure-path and security tests for versioned releases, rollback, and independent PowerShell recovery."""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from edge_bridge import releases
from edge_bridge.broker import call_broker, setup_state, verify_state_path
from edge_bridge.state import State

REPO_ROOT = Path(__file__).resolve().parents[1]
RECOVER_PS1 = REPO_ROOT / "scripts" / "recover-bridge.ps1"


def _copy_package_fixture(dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    shutil.copytree(REPO_ROOT / "edge_bridge", dst / "edge_bridge", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copytree(REPO_ROOT / "scripts", dst / "scripts", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(REPO_ROOT / "pyproject.toml", dst / "pyproject.toml")
    shutil.copy2(REPO_ROOT / "uv.lock", dst / "uv.lock")


def _mcp_handshake(pkg_root: Path, state: Path) -> tuple[int, dict, str]:
    reqs = [
        {"jsonrpc": "2.0", "id": "openai-mcp-discover", "method": "server/discover"},
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "rel_test", "version": "1.0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "bridge_info", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "project_list", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "project_resume", "arguments": {"project_id": "__PLACEHOLDER__"}}},
    ]
    return _mcp_raw(pkg_root, state, reqs[:4] + [reqs[4], reqs[5]])


def _mcp_raw(pkg_root: Path, state: Path, reqs: list[dict]) -> tuple[int, dict[object, dict], str]:
    payload = "\n".join(json.dumps(r) for r in reqs) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "mcp", "--principal", "edge"],
        cwd=str(pkg_root),
        input=payload,
        capture_output=True,
        text=True,
        timeout=25,
    )
    replies: dict[object, dict] = {}
    for line in proc.stdout.splitlines():
        if line.strip():
            try:
                msg = json.loads(line)
                if "id" in msg:
                    replies[msg["id"]] = msg
            except ValueError:
                pass
    return proc.returncode, replies, proc.stderr


class ReleaseAndRollbackTests(unittest.TestCase):
    def test_release_snapshot_layout_avoids_state_dir_and_excludes_secrets(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            state = base / "state"
            pkg = base / "repo"
            _copy_package_fixture(pkg)
            setup_state(state)
            (state / "owner.token").write_text("1" * 64, encoding="ascii")
            (state / "edge.token").write_text("2" * 64, encoding="ascii")
            (state / "ipc.pem").write_text("CERT-SECRET-CANARY", encoding="ascii")
            (state / "ipc-key.pem").write_text("KEY-SECRET-CANARY", encoding="ascii")
            store = State(state / "state.sqlite3")
            proj = base / "proj"
            proj.mkdir()
            store.register_project(str(proj), "RelProj", "rel-root-1")

            rel = releases.create_release(state, pkg, notes="baseline-good")
            releases_dir = Path(rel["releases_dir"])
            self.assertEqual(releases_dir, state.parent / f"{state.name}-releases")
            # state_dir remains strictly pure for verify_state_path
            verify_state_path(state)

            snap_dir = Path(rel["snapshot_dir"])
            manifest_text = (snap_dir / "manifest.json").read_text(encoding="utf-8")
            self.assertNotIn("1" * 64, manifest_text)
            self.assertNotIn("2" * 64, manifest_text)
            self.assertNotIn("KEY-SECRET-CANARY", manifest_text)
            self.assertTrue(rel["credential_presence"]["owner_token_present"])
            self.assertTrue(rel["credential_presence"]["edge_token_present"])

            with closing(sqlite3.connect(snap_dir / "state-backup.sqlite3")) as conn:
                check = conn.execute("PRAGMA integrity_check").fetchone()
                self.assertEqual(check[0], "ok")

            # Inside state_dir releases path is forbidden
            with self.assertRaises(releases.ReleaseError) as bad_dir:
                releases.create_release(state, pkg, releases_dir=state / "nested-releases")
            self.assertEqual(bad_dir.exception.code, "RELEASE_PATH_UNSAFE")

    def test_broken_mcp_update_independent_recovery_restores_33_tools_broker_and_state(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            state = base / "state"
            pkg = base / "repo"
            proj = base / "proj"
            proj.mkdir()
            (proj / "hello.txt").write_text("release recovery fixture\n", encoding="utf-8")
            _copy_package_fixture(pkg)
            setup_state(state)

            # Start broker from isolated repo copy, populate state, credentials, and checkpoint
            broker = subprocess.Popen(
                [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "start", "--port", "0"],
                cwd=str(pkg),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertIn("Edge Project Bridge ready", broker.stdout.readline())
                reg = call_broker(state, "local", "owner_register", {"root": str(proj), "name": "RecoverProj"})
                pid = reg["project_id"]
                call_broker(state, "local", "owner_grant_edge", {"project_id": pid})
                call_broker(
                    state, "local", "task_checkpoint",
                    {
                        "project_id": pid,
                        "task_id": "t-recover",
                        "operation_id": "ckpt-recover-1",
                        "objective": "Survive broken MCP update",
                        "summary": "Pre-update checkpoint intact",
                        "next_action": "Verify post-recovery resume",
                    },
                )
                orig_instance_id = call_broker(state, "local", "bridge_info")["instance_id"]
                call_broker(state, "local", "owner_stop")
                broker.wait(timeout=10)
            finally:
                if broker.poll() is None:
                    broker.terminate()
                    broker.wait(timeout=5)
                broker.stdout.close()
                broker.stderr.close()

            cred_files = ("owner.token", "edge.token", "ipc.pem", "ipc-key.pem")
            before_cred_hashes = {
                name: hashlib.sha256((state / name).read_bytes()).hexdigest()
                for name in cred_files
            }

            rel = releases.create_release(state, pkg, notes="good-before-broken-mcp")
            releases_dir = Path(rel["releases_dir"])

            # Break mcp_server.py AND corrupt pointers.json AND add an unexpected file
            (pkg / "edge_bridge" / "mcp_server.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
            (pkg / "edge_bridge" / "rogue_broken.py").write_text("raise RuntimeError('broken')\n", encoding="utf-8")
            (releases_dir / "pointers.json").write_text("{corrupt json", encoding="utf-8")

            rc_broken, _, _ = _mcp_handshake(pkg, state)
            self.assertNotEqual(rc_broken, 0)

            # Run independent pure PowerShell 5.1 recovery script (even with PS 7.7 PSModulePath pollution)
            ps7_polluted_env = {
                **os.environ,
                "PSModulePath": r"C:\Program Files\PowerShell\7-preview\Modules;C:\Program Files\PowerShell\7\Modules",
            }
            ps_proc = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(RECOVER_PS1),
                    "-StateDir",
                    str(state),
                    "-ReleasesDir",
                    str(releases_dir),
                    "-PackageRoot",
                    str(pkg),
                    "-PythonExe",
                    sys.executable,
                ],
                env=ps7_polluted_env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=45,
            )
            self.assertEqual(ps_proc.returncode, 0, f"stdout={ps_proc.stdout}\nstderr={ps_proc.stderr}")
            ps_report = json.loads(ps_proc.stdout)
            self.assertEqual(ps_report["status"], "RECOVERED")
            self.assertEqual(ps_report["tool_count"], 33)
            self.assertTrue(ps_report["discover_32601"])
            self.assertFalse((pkg / "edge_bridge" / "rogue_broken.py").exists())

            # Assert BOM-less pointers.json, list_releases readability, and create_release history preservation
            ptr_bytes = (releases_dir / "pointers.json").read_bytes()
            self.assertFalse(ptr_bytes.startswith(b"\xef\xbb\xbf"))
            listed = releases.list_releases(state, releases_dir=releases_dir)
            self.assertIsNone(listed["pointers_error"])
            self.assertEqual(listed["pointers"]["current"], rel["release_id"])
            self.assertEqual(listed["pointers"]["last_known_good"], rel["release_id"])

            rel_after = releases.create_release(state, pkg, releases_dir=releases_dir, notes="post-ps-recover")
            self.assertEqual(rel_after["pointers"]["previous"], rel["release_id"])
            self.assertEqual(len(rel_after["pointers"]["history"]), 1)

            # Start Broker from recovered repo & verify full Edge MCP sequence + preserved identity/state/credentials
            broker2 = subprocess.Popen(
                [sys.executable, "-m", "edge_bridge.cli", "--state-dir", str(state), "start", "--port", "0"],
                cwd=str(pkg),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertIn("Edge Project Bridge ready", broker2.stdout.readline())
                reqs = [
                    {"jsonrpc": "2.0", "id": "openai-mcp-discover", "method": "server/discover"},
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "post_rec", "version": "1.0"}}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                    {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "bridge_info", "arguments": {}}},
                    {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "project_list", "arguments": {}}},
                    {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "project_resume", "arguments": {"project_id": pid, "task_id": "t-recover"}}},
                ]
                rc_ok, replies, err_ok = _mcp_raw(pkg, state, reqs)
                self.assertEqual(rc_ok, 0, err_ok)
                self.assertEqual(replies["openai-mcp-discover"]["error"]["code"], -32601)
                self.assertEqual(len(replies[2]["result"]["tools"]), 33)
                info = replies[3]["result"]["structuredContent"]["result"]
                self.assertEqual(info["instance_id"], orig_instance_id)
                resume = replies[5]["result"]["structuredContent"]["result"]
                self.assertTrue(resume["handoff_ready"])
                self.assertEqual(resume["summary"], "Pre-update checkpoint intact")

                after_cred_hashes = {
                    name: hashlib.sha256((state / name).read_bytes()).hexdigest()
                    for name in cred_files
                }
                self.assertEqual(before_cred_hashes, after_cred_hashes)
            finally:
                try:
                    call_broker(state, "local", "owner_stop")
                    broker2.wait(timeout=10)
                except Exception:
                    broker2.terminate()
                    broker2.wait(timeout=5)
                broker2.stdout.close()
                broker2.stderr.close()

    def test_upgrade_auto_rollback_and_corrupt_db_restore(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            state = base / "state"
            pkg = base / "repo"
            bad_src = base / "bad_candidate"
            proj = base / "proj"
            proj.mkdir()
            _copy_package_fixture(pkg)
            _copy_package_fixture(bad_src)
            setup_state(state)

            store = State(state / "state.sqlite3")
            orig_id = store.instance_id
            p_rec = store.register_project(str(proj), "UpProj", "up-id")
            store.checkpoint(p_rec["project_id"], "local", "t-up", "Before upgrade", "op-up-1")

            # Candidate breaks mcp_server.py
            (bad_src / "edge_bridge" / "mcp_server.py").write_text("import nonexistent_broken_module_xyz\n", encoding="utf-8")

            up_res = releases.upgrade_from_directory(state, pkg, bad_src, run_probe=True, auto_rollback=True)
            self.assertEqual(up_res["status"], "ROLLED_BACK")
            self.assertTrue(up_res["rolled_back"])
            self.assertEqual(up_res["rollback"]["verification"]["tool_count"], 33)

            # Now simulate corrupt/incompatible DB + broken cli.py -> recover via PowerShell script
            (pkg / "edge_bridge" / "cli.py").write_text("syntax error (\n", encoding="utf-8")
            with closing(sqlite3.connect(state / "state.sqlite3")) as conn:
                conn.execute("UPDATE instance SET schema_version = 999 WHERE slot = 1")
                conn.commit()

            ps_proc = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(RECOVER_PS1),
                    "-StateDir",
                    str(state),
                    "-PackageRoot",
                    str(pkg),
                    "-PythonExe",
                    sys.executable,
                ],
                env={
                    **os.environ,
                    "PSModulePath": r"C:\Program Files\PowerShell\7-preview\Modules;C:\Program Files\PowerShell\7\Modules",
                },
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=45,
            )
            self.assertEqual(ps_proc.returncode, 0, f"stdout={ps_proc.stdout}\nstderr={ps_proc.stderr}")
            ps_report = json.loads(ps_proc.stdout)
            self.assertTrue(ps_report["db_restored"])
            self.assertEqual(ps_report["tool_count"], 33)

            restored_store = State(state / "state.sqlite3")
            self.assertEqual(restored_store.instance_id, orig_id)
            self.assertEqual(restored_store.resume(p_rec["project_id"], "local", "t-up")["summary"], "Before upgrade")

    def test_tampered_snapshot_rejected_fail_closed(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            state = base / "state"
            pkg = base / "repo"
            _copy_package_fixture(pkg)
            setup_state(state)
            State(state / "state.sqlite3")

            rel = releases.create_release(state, pkg, notes="tamper-test")
            snap_dir = Path(rel["snapshot_dir"])
            target_mcp = snap_dir / "code" / "edge_bridge" / "mcp_server.py"
            orig_bytes = target_mcp.read_bytes()
            target_mcp.write_bytes(orig_bytes + b"\n# tampered\n")

            with self.assertRaises(releases.ReleaseError) as err:
                releases.rollback_release(state, pkg, target_release_id=rel["release_id"], verify=False)
            self.assertEqual(err.exception.code, "RELEASE_HASH_MISMATCH")
            # Independent recover-bridge.ps1 also rejects tampered snapshot via .NET SHA-256 verification
            ps_tampered = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(RECOVER_PS1),
                    "-StateDir",
                    str(state),
                    "-PackageRoot",
                    str(pkg),
                    "-ReleaseId",
                    rel["release_id"],
                    "-PythonExe",
                    sys.executable,
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(ps_tampered.returncode, 0)
            self.assertIn("RELEASE_HASH_MISMATCH", ps_tampered.stderr + ps_tampered.stdout)
            # Package file untouched
            self.assertEqual((pkg / "edge_bridge" / "mcp_server.py").read_bytes(), orig_bytes)

    def test_windows_path_traversal_vectors_fail_closed_in_manifest_and_recovery(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            state = base / "state"
            pkg = base / "repo"
            _copy_package_fixture(pkg)
            setup_state(state)
            State(state / "state.sqlite3")

            rel = releases.create_release(state, pkg, notes="traversal-baseline")
            snap_dir = Path(rel["snapshot_dir"])
            outside_victim = base / "evil.txt"
            outside_victim_abs = base / "victim_outside.txt"
            outside_victim_abs.write_text("SAFE_ORIGINAL", encoding="utf-8")

            bad_vectors = [
                r"..\..\evil.txt",
                r"..\evil.txt",
                str(outside_victim_abs),
                str(outside_victim_abs).replace("\\", "/"),
                r"\\server\share\evil.txt",
                "C:rel_drive.txt",
                "/abs/posix.txt",
                "a/./b.txt",
                "a//b.txt",
            ]
            for vec in bad_vectors:
                with self.subTest(vector=vec):
                    with self.assertRaises(releases.ReleaseError) as err:
                        releases._safe_rel_posix(vec)
                    self.assertEqual(err.exception.code, "RELEASE_CORRUPT")

            # Tamper snapshot manifest with backslash traversal matching a file in snapshot code/
            evil_payload = b"PWNED"
            evil_hash = hashlib.sha256(evil_payload).hexdigest()
            (snap_dir / "code" / "evil.txt").write_bytes(evil_payload)
            manifest_path = snap_dir / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"].append({"path": r"..\evil.txt", "sha256": evil_hash, "size": len(evil_payload)})
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaises(releases.ReleaseError) as verify_err:
                releases.verify_release_snapshot(snap_dir)
            self.assertEqual(verify_err.exception.code, "RELEASE_CORRUPT")

            with self.assertRaises(releases.ReleaseError) as rb_err:
                releases.rollback_release(state, pkg, target_release_id=rel["release_id"], verify=False)
            self.assertEqual(rb_err.exception.code, "RELEASE_CORRUPT")
            self.assertFalse(outside_victim.exists())
            self.assertFalse((base / "evil.txt").exists())
            self.assertEqual(outside_victim_abs.read_text(encoding="utf-8"), "SAFE_ORIGINAL")

    def test_recover_ps1_does_not_promote_unverified_release_to_last_known_good(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            state = base / "state"
            pkg = base / "repo"
            _copy_package_fixture(pkg)
            setup_state(state)
            State(state / "state.sqlite3")

            good_rel = releases.create_release(state, pkg, notes="good-baseline", mark_good=True)
            unverified_rel = releases.create_release(state, pkg, notes="unverified-cand", mark_good=False)
            releases_dir = Path(good_rel["releases_dir"])

            ps_proc = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(RECOVER_PS1),
                    "-StateDir",
                    str(state),
                    "-ReleasesDir",
                    str(releases_dir),
                    "-PackageRoot",
                    str(pkg),
                    "-ReleaseId",
                    unverified_rel["release_id"],
                    "-PythonExe",
                    sys.executable,
                ],
                env={
                    **os.environ,
                    "PSModulePath": r"C:\Program Files\PowerShell\7-preview\Modules;C:\Program Files\PowerShell\7\Modules",
                },
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=45,
            )
            self.assertEqual(ps_proc.returncode, 0, f"stdout={ps_proc.stdout}\nstderr={ps_proc.stderr}")
            listed = releases.list_releases(state, releases_dir=releases_dir)
            self.assertIsNone(listed["pointers_error"])
            self.assertEqual(listed["pointers"]["current"], unverified_rel["release_id"])
            self.assertEqual(listed["pointers"]["last_known_good"], good_rel["release_id"])
            self.assertEqual(len(listed["pointers"]["history"]), 2)
            rel3 = releases.create_release(state, pkg, releases_dir=releases_dir, notes="post-unverified-recover")
            self.assertEqual(rel3["pointers"]["previous"], unverified_rel["release_id"])
            self.assertEqual(len(rel3["pointers"]["history"]), 3)


if __name__ == "__main__":
    unittest.main()
