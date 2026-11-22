"""Audit Sections 5, 6, 7, 10 — Security, Windows Containment, NTFS Junctions, MCP Dual Transcripts,
Idempotency/Restart Reconciliation, and 5-Dimension Evidence Negative Attack Suite.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any

REPO = Path(__file__).resolve().parents[1]
AUDIT_DIR = REPO / "audit-v0.4.0-20261119"
BUNDLE_DIR = AUDIT_DIR / "evidence-bundle"
sys.path.insert(0, str(REPO))
from compat.python.rust_bridge import find_rust_binary, invoke_rust_cli


def run_security_and_mcp_audit() -> dict[str, Any]:
    BUNDLE_DIR.mkdir(parents=True, exist_ok=True)
    rust_bin = find_rust_binary(REPO)
    assert rust_bin is not None
    python_exe = REPO / ".venv" / "Scripts" / "python.exe"

    results: dict[str, Any] = {"host": os.environ.get("COMPUTERNAME", "unknown")}
    tmp = Path(tempfile.mkdtemp(prefix="eb_audit_sec_"))
    try:
        state_dir = tmp / "state"
        proj = tmp / "proj"
        outside = tmp / "outside_secret_dir"
        proj.mkdir()
        outside.mkdir()
        (outside / "outside_canary.txt").write_text("OUTSIDE_CANARY_DATA\n", encoding="utf-8")
        (proj / "hello.txt").write_bytes(b"hello audit\n")
        (proj / "tests").mkdir()
        (proj / "tests" / "__init__.py").write_text("", encoding="utf-8")
        (proj / "tests" / "test_ok.py").write_text(
            "import unittest\nclass T(unittest.TestCase):\n    def test_one(self): self.assertEqual(2+2, 4)\n",
            encoding="utf-8",
        )

        # Create real Windows NTFS directory Junction inside project pointing OUTSIDE root!
        junction_path = proj / "escape_junction"
        mk_j = subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(junction_path), str(outside)],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        junction_created = mk_j.returncode == 0 and junction_path.exists()

        reg = invoke_rust_cli(["register", str(proj), "--name", "AuditSecProj", "--grant-edge"], state_dir=state_dir, repo_root=REPO)
        pid = reg["project_id"]

        # --- 1. NTFS Junction Read & Patch Denial Test (Section 5) ---
        junc_read_denied = False
        junc_patch_denied = False
        if junction_created:
            mcp_j = subprocess.run(
                [str(rust_bin), "--state-dir", str(state_dir), "mcp", "--principal", "edge"],
                input=json.dumps({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "file_read", "arguments": {"project_id": pid, "path": "escape_junction/outside_canary.txt"}},
                }) + "\n",
                capture_output=True, text=True, timeout=15, check=True,
            )
            jr = json.loads(mcp_j.stdout.strip())["result"]
            junc_read_denied = jr["isError"] is True and jr["structuredContent"]["code"] == "UNSUPPORTED_PATH_TYPE"

            bad_plan = tmp / "junc_plan.json"
            bad_plan.write_text(json.dumps({
                "patch_plan_version": "0.4.0",
                "project_id": pid,
                "operation_id": "op-junc-escape",
                "edits": [{"path": "escape_junction/pwn.txt", "content": "x", "expected_hash": None}],
            }), encoding="utf-8")
            jp = subprocess.run(
                [str(rust_bin), "--state-dir", str(state_dir), "apply-patch", "--project-root", str(proj), "--plan-json", str(bad_plan)],
                capture_output=True, text=True, stdin=subprocess.DEVNULL,
            )
            junc_patch_denied = jp.returncode != 0 and not (outside / "pwn.txt").exists()

        # --- 2. Windows Containment: Timeout Kill, MXC Fail-Closed, & Supervisor Key/Log Isolation (Section 5) ---
        # 2a. Timeout kill of child + grandchild tree under Win32 Job Object
        t0 = time.monotonic()
        timeout_run = invoke_rust_cli([
            "run-job", "--project-id", pid, "--task-id", "containment_timeout", "--operation-id", "op-timeout-tree",
            "--cwd", str(proj), "--executable", str(python_exe),
            "--arg", "-c", "--arg", "import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); time.sleep(30)",
            "--timeout-seconds", "2",
        ], state_dir=state_dir, repo_root=REPO)
        timeout_dt = round(time.monotonic() - t0, 2)
        assert timeout_run["job"]["state"] == "timed_out"
        assert timeout_run["manifest"]["execution"]["timed_out"] is True
        assert timeout_run["manifest"]["conclusions"]["overall_verdict"] == "FAIL"

        # 2b. MXC require_mxc=true fails closed (NO silent weaker fallback!) when desktop != WinSta0\Default
        mxc_probe = subprocess.run([
            str(rust_bin), "--state-dir", str(state_dir),
            "run-job", "--project-id", pid, "--task-id", "mxc_check", "--operation-id", "op-mxc-failclosed",
            "--cwd", str(proj), "--executable", str(python_exe),
            "--arg", "-m", "--arg", "unittest",
            "--require-mxc",
        ], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        mxc_fail_closed = (mxc_probe.returncode != 0 and "IsolationNotVerified" in mxc_probe.stderr)

        # 2c. Honest negative probe: under Win32 Job Object ONLY (without MXC), can a child read outside_canary.txt?
        # YES — this proves why Win32 Job Object alone is process/resource supervision and NOT filesystem/network containment!
        job_obj_escape = invoke_rust_cli([
            "run-job", "--project-id", pid, "--task-id", "jobobj_truth", "--operation-id", "op-jobobj-boundary-check",
            "--cwd", str(proj), "--executable", str(python_exe),
            "--arg", "-c", "--arg", f"from pathlib import Path; print('CAN_READ_OUTSIDE=' + str(Path(r'{outside / 'outside_canary.txt'}').is_file()))",
        ], state_dir=state_dir, repo_root=REPO)
        job_obj_log = (Path(job_obj_escape["manifest_json_path"]).parent / "combined-redacted.log").read_text(encoding="utf-8")
        job_obj_allows_outside_read = "CAN_READ_OUTSIDE=True" in job_obj_log

        results["windows_containment"] = {
            "ntfs_junction_created": junction_created,
            "ntfs_junction_read_denied": junc_read_denied,
            "ntfs_junction_patch_denied": junc_patch_denied,
            "win32_job_object_timeout_tree_kill_ok": timeout_run["job"]["state"] == "timed_out" and timeout_dt < 10.0,
            "timeout_wall_seconds": timeout_dt,
            "mxc_require_flag_fails_closed_no_weaker_fallback": mxc_fail_closed,
            "mxc_fail_closed_message": mxc_probe.stderr.strip()[:250],
            "win32_job_object_alone_allows_outside_fs_read_proven": job_obj_allows_outside_read,
            "note": "Proves empirically that Win32 Job Objects enforce process-tree/memory/timeout supervision ONLY; full filesystem+network containment requires MXC in WinSta0\\Default.",
        }

        # --- 3. MCP Dual Compatibility Transcripts + Idempotency + Restart Reconciliation (Section 6) ---
        # 3a. Legacy Stdio Transcript
        legacy_reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "server/discover"},
            {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "audit-legacy", "version": "1.0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "bridge_info", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "file_write", "arguments": {"project_id": pid, "operation_id": "op-deny", "path": "hello.txt", "content": "x"}}},
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3, "reason": "client_timeout"}},
        ]
        p_leg = subprocess.run(
            [str(rust_bin), "--state-dir", str(state_dir), "mcp", "--principal", "edge"],
            input="\n".join(json.dumps(r) for r in legacy_reqs) + "\n",
            capture_output=True, text=True, timeout=20, check=True,
        )
        legacy_resps = [json.loads(ln) for ln in p_leg.stdout.splitlines() if ln.strip()]
        (BUNDLE_DIR / "mcp-legacy-stdio-transcript.json").write_text(
            json.dumps({"transport": "stdio", "principal": "edge", "requests": legacy_reqs, "responses": legacy_resps, "stderr": p_leg.stderr}, indent=2) + "\n",
            encoding="utf-8",
        )

        # 3b. Modern 2026-07-28 Streamable HTTP (`/mcp`) + Lost-Response Idempotency + Restart Orphan -> `unknown`
        srv = subprocess.Popen(
            [str(rust_bin), "--state-dir", str(state_dir), "serve", "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL,
        )
        try:
            disc = state_dir / "rust-broker.json"
            t_end = time.monotonic() + 10.0
            while not disc.is_file() and time.monotonic() < t_end:
                time.sleep(0.05)
            port = json.loads(disc.read_text(encoding="utf-8"))["port"]
            owner_tok = (state_dir / "owner.token").read_text(encoding="utf-8").strip()

            def post_mcp(frame: dict, proto: str = "2026-07-28", extra_headers: dict | None = None) -> tuple[int, dict]:
                hdrs = {
                    "Host": f"127.0.0.1:{port}",
                    "Content-Type": "application/json",
                    "X-Bridge-Token": owner_tok,
                    "MCP-Protocol-Version": proto,
                }
                if extra_headers:
                    hdrs.update(extra_headers)
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                try:
                    conn.request("POST", "/mcp", body=json.dumps(frame).encode(), headers=hdrs)
                    r = conn.getresponse()
                    raw = r.read().decode("utf-8")
                    return r.status, (json.loads(raw) if raw.strip() else {})
                finally:
                    conn.close()

            st_init, r_init = post_mcp({"jsonrpc": "2.0", "id": 10, "method": "initialize", "params": {"protocolVersion": "2026-07-28", "capabilities": {"experimental": {"tasks": {}}}}})
            st_bad_proto, r_bad_proto = post_mcp({"jsonrpc": "2.0", "id": 11, "method": "ping"}, proto="2099-01-01")
            st_last_ev, r_last_ev = post_mcp({"jsonrpc": "2.0", "id": 12, "method": "ping"}, proto="2026-07-28", extra_headers={"Last-Event-ID": "ev-1"})
            # Lost-response idempotency test: submit same operation_id twice via task_submit
            submit_frame = {
                "jsonrpc": "2.0", "id": 13, "method": "tools/call",
                "params": {"name": "task_submit", "arguments": {"project_id": pid, "task_id": "t_idem", "operation_id": "op-lost-resp-1", "recipe": "python_tests"}},
            }
            st_sub1, r_sub1 = post_mcp(submit_frame)
            st_sub2, r_sub2 = post_mcp({**submit_frame, "id": 14})
            run1_id = r_sub1["result"]["structuredContent"]["result"]["run_id"]
            run2_id = r_sub2["result"]["structuredContent"]["result"]["run_id"]
            assert run1_id == run2_id
            assert r_sub1["result"]["structuredContent"]["result"]["created"] is True
            assert r_sub2["result"]["structuredContent"]["result"]["idempotent_replay"] is True

            # Cancel durable job cleanly via MCP job_cancel
            st_can, r_can = post_mcp({
                "jsonrpc": "2.0", "id": 15, "method": "tools/call",
                "params": {"name": "job_cancel", "arguments": {"project_id": pid, "job_id": run1_id, "operation_id": "op-cancel-1"}},
            })
            assert r_can["result"]["structuredContent"]["result"]["state"] == "cancelling"

            # Submit a second durable run that remains non-terminal across a simulated broker crash/restart
            orphan_frame = {
                "jsonrpc": "2.0", "id": 16, "method": "tools/call",
                "params": {"name": "task_submit", "arguments": {"project_id": pid, "task_id": "t_orphan", "operation_id": "op-orphan-crash-1", "recipe": "python_tests"}},
            }
            st_orph_sub, r_orph_sub = post_mcp(orphan_frame)
            orphan_run_id = r_orph_sub["result"]["structuredContent"]["result"]["run_id"]
            assert st_orph_sub == 200 and r_orph_sub["result"]["structuredContent"]["result"]["state"] == "queued"

            # Save modern Streamable HTTP transcript (part 1 before restart)
            modern_transcript = {
                "transport": "streamable_http_post",
                "endpoint": "/mcp",
                "init": {"status": st_init, "response": r_init},
                "unsupported_protocol_header": {"status": st_bad_proto, "response": r_bad_proto},
                "last_event_id_rejected": {"status": st_last_ev, "response": r_last_ev},
                "task_submit_first": {"status": st_sub1, "response": r_sub1},
                "task_submit_lost_response_retry": {"status": st_sub2, "response": r_sub2},
                "job_cancel": {"status": st_can, "response": r_can},
                "orphan_submit_before_restart": {"status": st_orph_sub, "response": r_orph_sub},
            }
        finally:
            srv.terminate()
            srv.wait(timeout=5)
            if (state_dir / "rust-broker.json").exists():
                (state_dir / "rust-broker.json").unlink()

        # Restart broker on same state_dir -> MUST reconcile orphaned non-terminal runs to `unknown` (never falsely running/replayed)
        srv2 = subprocess.Popen(
            [str(rust_bin), "--state-dir", str(state_dir), "serve", "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL,
        )
        try:
            disc = state_dir / "rust-broker.json"
            t_end = time.monotonic() + 10.0
            while not disc.is_file() and time.monotonic() < t_end:
                time.sleep(0.05)
            port2 = json.loads(disc.read_text(encoding="utf-8"))["port"]
            owner_tok = (state_dir / "owner.token").read_text(encoding="utf-8").strip()

            def post_mcp2(frame: dict) -> tuple[int, dict]:
                hdrs = {
                    "Host": f"127.0.0.1:{port2}",
                    "Content-Type": "application/json",
                    "X-Bridge-Token": owner_tok,
                    "MCP-Protocol-Version": "2026-07-28",
                }
                conn = http.client.HTTPConnection("127.0.0.1", port2, timeout=10)
                try:
                    conn.request("POST", "/mcp", body=json.dumps(frame).encode(), headers=hdrs)
                    r = conn.getresponse()
                    raw = r.read().decode("utf-8")
                    return r.status, (json.loads(raw) if raw.strip() else {})
                finally:
                    conn.close()

            st_after_get, r_after_get = post_mcp2({
                "jsonrpc": "2.0", "id": 17, "method": "tools/call",
                "params": {"name": "job_get", "arguments": {"project_id": pid, "job_id": orphan_run_id}},
            })
            st_after_retry, r_after_retry = post_mcp2({
                "jsonrpc": "2.0", "id": 18, "method": "tools/call",
                "params": {"name": "task_submit", "arguments": {"project_id": pid, "task_id": "t_orphan", "operation_id": "op-orphan-crash-1", "recipe": "python_tests"}},
            })
            orphan_state_after = r_after_get["result"]["structuredContent"]["result"]["state"]
            retry_run_after = r_after_retry["result"]["structuredContent"]["result"]["run_id"]
            retry_state_after = r_after_retry["result"]["structuredContent"]["result"]["state"]
            assert orphan_state_after == "unknown", f"Expected unknown after restart, got {orphan_state_after}"
            assert retry_run_after == orphan_run_id and retry_state_after == "unknown"

            modern_transcript["orphan_job_get_after_restart"] = {"status": st_after_get, "response": r_after_get}
            modern_transcript["orphan_retry_after_restart_no_replay"] = {"status": st_after_retry, "response": r_after_retry}
            (BUNDLE_DIR / "mcp-modern-2026-07-28-http-transcript.json").write_text(
                json.dumps(modern_transcript, indent=2) + "\n", encoding="utf-8"
            )
            results["mcp_dual_and_idempotency"] = {
                "legacy_discover_32601": legacy_resps[0]["error"]["code"] == -32601,
                "legacy_edge_write_denied": legacy_resps[3]["result"]["structuredContent"]["code"] == "BRIDGE_POLICY_DENIED",
                "modern_2026_07_28_init_ok": st_init == 200 and r_init["result"]["protocolVersion"] == "2026-07-28",
                "unsupported_protocol_rejected_400": st_bad_proto == 400 and r_bad_proto["code"] == "PROTOCOL_MISMATCH",
                "last_event_id_rejected_400": st_last_ev == 400 and r_last_ev["code"] == "PROTOCOL_MISMATCH",
                "lost_response_retry_same_run_id": run1_id == run2_id,
                "job_cancel_state_cancelling": r_can["result"]["structuredContent"]["result"]["state"] == "cancelling",
                "restart_orphan_reconciled_to_unknown": orphan_state_after == "unknown",
                "restart_orphan_retry_preserves_unknown_no_replay": retry_run_after == orphan_run_id and retry_state_after == "unknown",
            }
        finally:
            srv2.terminate()
            srv2.wait(timeout=5)

        # --- 4. Evidence 5-Dimension Negative Attacks via CLI (Section 7) ---
        good_run = invoke_rust_cli([
            "run-job", "--project-id", pid, "--task-id", "ev_test", "--operation-id", "op-ev-good",
            "--cwd", str(proj), "--executable", str(python_exe),
            "--arg", "-B", "--arg", "-m", "--arg", "unittest", "--arg", "discover", "--arg", "-s", "--arg", "tests", "--arg", "-t", "--arg", ".", "--arg", "-v",
        ], state_dir=state_dir, repo_root=REPO)
        m_path = Path(good_run["manifest_json_path"])
        art_dir = m_path.parent
        trusted_pk = good_run["manifest"]["signer_public_key_hex"]

        # 4a. Valid verification passes all 5 checks
        v_ok = invoke_rust_cli(["verify-evidence", str(m_path), "--trusted-key", trusted_pk, "--artifacts-dir", str(art_dir)], state_dir=state_dir, repo_root=REPO)
        assert v_ok["overall_verified"] is True

        # 4b. Tamper signed field -> FAILS
        tampered_m = tmp / "tampered_field.json"
        m_obj = json.loads(m_path.read_text(encoding="utf-8"))
        m_obj["tests"]["passed"] = 99
        tampered_m.write_text(json.dumps(m_obj), encoding="utf-8")
        p_t1 = subprocess.run([str(rust_bin), "--state-dir", str(state_dir), "verify-evidence", str(tampered_m), "--trusted-key", trusted_pk, "--artifacts-dir", str(art_dir)], capture_output=True, text=True)
        r_t1 = json.loads(p_t1.stdout)
        assert p_t1.returncode != 0 and r_t1["signature_cryptographically_valid"] is False

        # 4c. Substitute trusted key (simulate rogue key) -> FAILS device_key_trusted
        p_t2 = subprocess.run([str(rust_bin), "--state-dir", str(state_dir), "verify-evidence", str(m_path), "--trusted-key", "00" * 32, "--artifacts-dir", str(art_dir)], capture_output=True, text=True)
        r_t2 = json.loads(p_t2.stdout)
        assert p_t2.returncode != 0 and r_t2["signature_cryptographically_valid"] is True and r_t2["device_key_trusted"] is False

        # 4d. Tamper artifact file on disk -> FAILS artifacts_hashes_verified
        tampered_art_dir = tmp / "tampered_arts"
        shutil.copytree(art_dir, tampered_art_dir)
        (tampered_art_dir / "combined-redacted.log").write_text("ATTACKER TAMPERED LOG\n", encoding="utf-8")
        p_t3 = subprocess.run([str(rust_bin), "--state-dir", str(state_dir), "verify-evidence", str(m_path), "--trusted-key", trusted_pk, "--artifacts-dir", str(tampered_art_dir)], capture_output=True, text=True)
        r_t3 = json.loads(p_t3.stdout)
        assert p_t3.returncode != 0 and r_t3["artifacts_hashes_verified"] is False

        # 4e. Zero-test run (exit 0 with Ran 0 tests) -> verdict NOT_TESTED (never PASS!)
        zero_run = invoke_rust_cli([
            "run-job", "--project-id", pid, "--task-id", "zero_test", "--operation-id", "op-zero-tests",
            "--cwd", str(proj), "--executable", str(python_exe),
            "--arg", "-c", "--arg", "print('Ran 0 tests in 0.000s\\n\\nOK')",
        ], state_dir=state_dir, repo_root=REPO)
        assert zero_run["manifest"]["execution"]["exit_code"] == 0
        assert zero_run["manifest"]["conclusions"]["overall_verdict"] == "NOT_TESTED"

        # 4f. Migrate-verify refuses silent overwrite of existing DB (Section 9)
        fixture_backup = tmp / "fixture-backup.sqlite3"
        invoke_rust_cli(["backup", str(fixture_backup)], state_dir=state_dir, repo_root=REPO)
        existing_db = tmp / "already_exists.sqlite3"
        existing_db.write_bytes(b"placeholder")
        p_ow = subprocess.run(
            [str(rust_bin), "--state-dir", str(state_dir), "migrate-verify", str(fixture_backup), str(existing_db)],
            capture_output=True, text=True,
        )
        assert p_ow.returncode != 0 and "Refusing to silently overwrite" in p_ow.stderr

        # 4g. Doctor on uninitialized dir does NOT create an empty state.sqlite3 (Section 9)
        empty_dir = tmp / "uninit_canary"
        doc_uninit = invoke_rust_cli(["doctor"], state_dir=empty_dir, repo_root=REPO)
        assert doc_uninit["state_db_initialized"] is False
        assert not (empty_dir / "state.sqlite3").exists()

        results["evidence_and_migration_negative_gates"] = {
            "valid_5dim_pass": v_ok["overall_verified"],
            "signed_field_tamper_rejected": p_t1.returncode != 0 and not r_t1["signature_cryptographically_valid"],
            "rogue_device_key_rejected": p_t2.returncode != 0 and not r_t2["device_key_trusted"],
            "disk_artifact_tamper_rejected": p_t3.returncode != 0 and r_t3["artifacts_hashes_verified"] is False,
            "zero_tests_exit_0_verdict": zero_run["manifest"]["conclusions"]["overall_verdict"],
            "migrate_verify_refuses_silent_overwrite": True,
            "doctor_readonly_does_not_create_empty_db": True,
        }

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    (BUNDLE_DIR / "security-mcp-evidence-audit.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return results


if __name__ == "__main__":
    print(json.dumps(run_security_and_mcp_audit(), indent=2))
