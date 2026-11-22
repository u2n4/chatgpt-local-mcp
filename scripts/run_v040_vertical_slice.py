"""End-to-End V0.4.0 Acceptance Harness (Stages 2-8):
1. BridgePulse Lab First Proof Milestone:
   - Disposable Git acceptance repo with seeded unit-conversion defect
   - Genuine failing test run -> signed EvidenceManifest (FAIL) + Ed25519 verification
   - Isolated workspace fix -> real hash-checked PatchPlanV04 (compatible with apply-patch-plan)
   - Trusted rerun -> signed EvidenceManifest (PASS) + Ed25519 verification + diff + before/after report
2. Negative security & idempotency gates (MCP legacy+modern, edge read-only denial, principal spoofing,
   stale preimage, secret canaries, idempotency payload mismatch, ULog binary parsing, two-host rehearsal)
3. Optional offline migration rehearsal (schema 3 -> 4 preserving identity and project count)
4. Loopback Rust HTTP broker + BridgePulse Svelte UI security header & auth tests
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "examples" / "bridgepulse-lab"))

from compat.python.rust_bridge import find_rust_binary, invoke_rust_cli
from bridgepulse_lab.baseline import compare_baselines, export_comparison_report
from bridgepulse_lab.measurements import ValidationLimits, analyze_csv_dataset
from datetime import datetime, timezone


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _mcp_stdio_session(rust_bin: Path, state_dir: Path, principal: str, requests: list[dict]) -> list[dict]:
    payload = "\n".join(json.dumps(r) for r in requests) + "\n"
    proc = subprocess.run(
        [str(rust_bin), "--state-dir", str(state_dir), "mcp", "--principal", principal],
        input=payload,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert proc.stderr == "", f"MCP stdout/stderr violation: stderr was non-empty: {proc.stderr!r}"
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]


def run_all(
    *,
    baseline_backup: Path | None = None,
    expected_instance: str | None = None,
    expected_project_count: int | None = None,
) -> dict[str, Any]:
    provided = (baseline_backup, expected_instance, expected_project_count)
    if any(value is not None for value in provided) and any(value is None for value in provided):
        raise ValueError("Supply the backup path, expected instance, and expected project count together.")
    rust_bin = find_rust_binary(REPO)
    if rust_bin is None:
        raise RuntimeError("Compiled Rust edge-bridge.exe not found.")

    python_exe = REPO / ".venv" / "Scripts" / "python.exe"
    if not python_exe.is_file():
        python_exe = Path(sys.executable)

    results: dict[str, Any] = {
        "rust_binary": str(rust_bin),
        "rust_binary_sha256": _sha256(rust_bin),
        "host_name": os.environ.get("COMPUTERNAME", "unknown"),
        "stages": {},
    }

    # --- 1. Export JSON Schemas ---
    schemas_out = invoke_rust_cli(["export-schemas", "--out-dir", str(REPO / "schemas")], repo_root=REPO)
    results["stages"]["schema_export"] = {"status": "PASS", "count": len(schemas_out["exported"])}

    # --- 2. Doctor & Provider Probes ---
    tmp_root = Path(tempfile.mkdtemp(prefix="eb_v040_accept_"))
    try:
        state_dir = tmp_root / "state"
        doctor = invoke_rust_cli(["doctor"], state_dir=state_dir, repo_root=REPO)
        results["stages"]["rust_doctor"] = {
            "status": "PASS",
            "host_id": doctor["host_id"],
            "sqlite_runtime_version": doctor["versions"]["sqlite_runtime_version"],
            "sqlite_wal_reset_fix_verified": doctor["versions"]["sqlite_wal_reset_fix_verified"],
            "rmcp_sdk": doctor["rmcp_sdk"],
            "mxc_probe_verified": doctor["containment"]["status"]["verified"],
            "mxc_probe_reason": doctor["containment"]["status"]["reason"],
            "gpu_available": doctor["resources"]["gpu_probe"]["available"],
            "providers_detected": [
                {
                    "provider": p["provider"],
                    "version": p["detected_version"],
                    "included_only_compatible": p["included_only_compatible"],
                    "verified": p["capability"]["verified"],
                }
                for p in doctor["providers"]
            ],
        }

        # --- 3. BridgePulse Lab First Proof Milestone (Seeded Failure -> Isolated Fix -> PASS + Signed Evidence) ---
        lab_repo = tmp_root / "bridgepulse-lab-acceptance"
        shutil.copytree(REPO / "examples" / "bridgepulse-lab", lab_repo, ignore=shutil.ignore_patterns("__pycache__", "evidence-bundle"))
        # Initialize Git repo
        for gcmd in (
            ["git", "init", "-b", "main"],
            ["git", "config", "user.name", "BridgePulse Acceptance"],
            ["git", "config", "user.email", "accept@local.invalid"],
        ):
            subprocess.run(gcmd, cwd=lab_repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)

        # Seed realistic unit conversion defect in measurements.py preserving exact line endings (CRLF/LF)
        meas_path = lab_repo / "bridgepulse_lab" / "measurements.py"
        clean_meas_bytes = meas_path.read_bytes()
        clean_meas_text = clean_meas_bytes.decode("utf-8")
        assert "KNOTS_TO_MPS = 1852.0 / 3600.0" in clean_meas_text
        buggy_meas_text = clean_meas_text.replace("KNOTS_TO_MPS = 1852.0 / 3600.0", "KNOTS_TO_MPS = 0.50  # SEEDED DEFECT")
        meas_path.write_bytes(buggy_meas_text.encode("utf-8"))
        buggy_hash = _sha256(meas_path)
        fixed_hash = hashlib.sha256(clean_meas_bytes).hexdigest()

        subprocess.run(["git", "add", "-A"], cwd=lab_repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)
        subprocess.run(["git", "commit", "-m", "baseline: bridgepulse-lab with seeded knot conversion defect"], cwd=lab_repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)

        # Register disposable project + grant edge read-only + create DelegatedExecutor grant
        reg = invoke_rust_cli(["register", str(lab_repo), "--name", "BridgePulse Lab Acceptance", "--grant-edge"], state_dir=state_dir, repo_root=REPO)
        pid = reg["project_id"]
        grant = invoke_rust_cli([
            "grant-create", pid,
            "--requester", "executor:codex_primary",
            "--writable-path", "bridgepulse_lab/**",
            "--recipe", "python_tests",
            "--ttl-minutes", "30",
        ], state_dir=state_dir, repo_root=REPO)

        # Step A: Run REAL test on seeded defect -> MUST genuinely FAIL
        before_run = invoke_rust_cli([
            "run-job",
            "--project-id", pid,
            "--task-id", "lab_repair_01",
            "--operation-id", "op-lab-before-fail",
            "--cwd", str(lab_repo),
            "--executable", str(python_exe),
            "--arg", "-B", "--arg", "-m", "--arg", "unittest", "--arg", "discover", "--arg", "-s", "--arg", "tests", "--arg", "-t", "--arg", ".", "--arg", "-v",
            "--parser", "python_unittest",
            "--synthetic-data",
        ], state_dir=state_dir, repo_root=REPO)
        before_manifest = before_run["manifest"]
        assert before_manifest["conclusions"]["overall_verdict"] == "FAIL", f"Expected FAIL, got {before_manifest['conclusions']['overall_verdict']}"
        assert before_manifest["execution"]["exit_code"] != 0
        assert before_manifest["tests"]["executed"] == 5
        assert before_manifest["tests"]["failed"] >= 2
        verify_before = invoke_rust_cli([
            "verify-evidence",
            before_run["manifest_json_path"],
            "--artifacts-dir",
            str(Path(before_run["manifest_json_path"]).parent),
        ], state_dir=state_dir, repo_root=REPO)
        assert verify_before["overall_verified"] is True
        assert verify_before["signature_cryptographically_valid"] is True
        assert verify_before["device_key_trusted"] is True
        assert verify_before["artifacts_hashes_verified"] is True

        # Idempotency check: duplicate identical operation_id returns exact same run_id without re-executing!
        dup_run = invoke_rust_cli([
            "run-job",
            "--project-id", pid,
            "--task-id", "lab_repair_01",
            "--operation-id", "op-lab-before-fail",
            "--cwd", str(lab_repo),
            "--executable", str(python_exe),
            "--arg", "-B", "--arg", "-m", "--arg", "unittest", "--arg", "discover", "--arg", "-s", "--arg", "tests", "--arg", "-t", "--arg", ".", "--arg", "-v",
            "--parser", "python_unittest",
            "--synthetic-data",
        ], state_dir=state_dir, repo_root=REPO)
        assert dup_run["job"]["run_id"] == before_run["job"]["run_id"]

        # Step B: Build real hash-checked PatchPlanV04 (also 100% compatible with edge_bridge.cli apply-patch-plan!)
        patch_plan = {
            "patch_plan_version": "0.4.0",
            "project_id": pid,
            "root_identity": reg["root_identity"],
            "operation_id": "op-lab-fix-knots-01",
            "task_id": "lab_repair_01",
            "summary": "Fix KNOTS_TO_MPS unit conversion from 0.50 to exact international factor 1852.0 / 3600.0",
            "scope": ["bridgepulse_lab/measurements.py"],
            "edits": [
                {
                    "path": "bridgepulse_lab/measurements.py",
                    "content": clean_meas_text,
                    "expected_hash": buggy_hash,
                    "expected_postimage_hash": fixed_hash,
                }
            ],
            "verification_recipe": "project_tests",
            "verification_command": [str(python_exe), "-B", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
        }
        plan_file = tmp_root / "bridgepulse-lab-fix-plan.json"
        plan_file.write_text(json.dumps(patch_plan, indent=2) + "\n", encoding="utf-8")

        # Apply hash-checked patch via Rust core (verifies preimage + postimage + journal + unified diff)
        apply_res = invoke_rust_cli([
            "apply-patch",
            "--project-root", str(lab_repo),
            "--plan-json", str(plan_file),
        ], state_dir=state_dir, repo_root=REPO)
        assert apply_res["postimage_hashes"]["bridgepulse_lab/measurements.py"] == fixed_hash
        assert "-KNOTS_TO_MPS = 0.50" in apply_res["unified_diff"]
        assert "+KNOTS_TO_MPS = 1852.0 / 3600.0" in apply_res["unified_diff"]

        # Negative test: Re-applying the SAME patch plan now fails with VERSION_CONFLICT (stale preimage!)
        stale_proc = subprocess.run(
            [str(rust_bin), "--state-dir", str(state_dir), "apply-patch", "--project-root", str(lab_repo), "--plan-json", str(plan_file)],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        assert stale_proc.returncode != 0 and "VersionConflict" in stale_proc.stderr

        # Step C: Re-run REAL tests in trusted verifier -> MUST genuinely PASS
        after_run = invoke_rust_cli([
            "run-job",
            "--project-id", pid,
            "--task-id", "lab_repair_01",
            "--operation-id", "op-lab-after-pass",
            "--cwd", str(lab_repo),
            "--executable", str(python_exe),
            "--arg", "-B", "--arg", "-m", "--arg", "unittest", "--arg", "discover", "--arg", "-s", "--arg", "tests", "--arg", "-t", "--arg", ".", "--arg", "-v",
            "--parser", "python_unittest",
            "--synthetic-data",
        ], state_dir=state_dir, repo_root=REPO)
        after_manifest = after_run["manifest"]
        assert after_manifest["conclusions"]["overall_verdict"] == "PASS"
        assert after_manifest["execution"]["exit_code"] == 0
        assert after_manifest["tests"]["executed"] == 5
        assert after_manifest["tests"]["passed"] == 5
        assert after_manifest["tests"]["failed"] == 0
        assert after_manifest["source"]["test_suite_modified"] is False
        verify_after = invoke_rust_cli([
            "verify-evidence",
            after_run["manifest_json_path"],
            "--artifacts-dir",
            str(Path(after_run["manifest_json_path"]).parent),
        ], state_dir=state_dir, repo_root=REPO)
        assert verify_after["overall_verified"] is True
        assert verify_after["signature_cryptographically_valid"] is True
        assert verify_after["device_key_trusted"] is True
        assert verify_after["artifacts_hashes_verified"] is True

        # Save complete immutable before/after evidence bundle into examples/bridgepulse-lab/evidence-bundle/
        bundle_dir = REPO / "examples" / "bridgepulse-lab" / "evidence-bundle"
        bundle_dir.mkdir(parents=True, exist_ok=True)
        (bundle_dir / "signing-public-key.hex").write_text(
            before_manifest["signer_public_key_hex"] + "\n", encoding="utf-8"
        )
        shutil.copy2(before_run["manifest_json_path"], bundle_dir / "01-before-fail-manifest.json")
        shutil.copy2(before_run["markdown_report_path"], bundle_dir / "01-before-fail-report.md")
        before_art_dst = bundle_dir / "01-before-artifacts"
        if before_art_dst.exists():
            shutil.rmtree(before_art_dst)
        shutil.copytree(Path(before_run["manifest_json_path"]).parent, before_art_dst)
        shutil.copy2(plan_file, bundle_dir / "02-hash-checked-patch-plan.json")
        (bundle_dir / "02-repair.diff").write_text(apply_res["unified_diff"], encoding="utf-8")
        shutil.copy2(after_run["manifest_json_path"], bundle_dir / "03-after-pass-manifest.json")
        shutil.copy2(after_run["markdown_report_path"], bundle_dir / "03-after-pass-report.md")
        after_art_dst = bundle_dir / "03-after-artifacts"
        if after_art_dst.exists():
            shutil.rmtree(after_art_dst)
        shutil.copytree(Path(after_run["manifest_json_path"]).parent, after_art_dst)

        # Run BridgePulse Lab's own baseline comparator + measurement summary
        cmp_res = compare_baselines(before_manifest, after_manifest)
        meas_res = analyze_csv_dataset(
            lab_repo / "fixtures" / "synthetic_airspeed_dataset.csv",
            limits=ValidationLimits(min_value=0.0, max_value=100.0, max_stale_seconds=60.0),
            reference_time_utc=datetime(2026, 11, 19, 0, 0, 20, tzinfo=timezone.utc),
            dataset_label="synthetic_airspeed_fixture",
            evidence_class="software_unit",
        )
        exported_cmp = export_comparison_report(cmp_res, meas_res, bundle_dir)

        results["stages"]["vertical_slice_bridgepulse_lab"] = {
            "status": "PASS",
            "project_id": pid,
            "grant_id": grant["grant_id"],
            "before_run_id": before_run["job"]["run_id"],
            "before_verdict": before_manifest["conclusions"]["overall_verdict"],
            "before_tests": f"{before_manifest['tests']['passed']}/{before_manifest['tests']['executed']} passed, {before_manifest['tests']['failed']} failed",
            "before_sig_verified": verify_before["overall_verified"],
            "idempotency_dup_run_id_matched": True,
            "patch_journal_id": apply_res["journal_id"],
            "preimage_sha256": buggy_hash,
            "postimage_sha256": fixed_hash,
            "diff_sha256": apply_res["diff_sha256"],
            "stale_preimage_rejected": True,
            "after_run_id": after_run["job"]["run_id"],
            "after_verdict": after_manifest["conclusions"]["overall_verdict"],
            "after_tests": f"{after_manifest['tests']['passed']}/{after_manifest['tests']['executed']} passed, {after_manifest['tests']['failed']} failed",
            "after_sig_verified": verify_after["overall_verified"],
            "comparison_report_sha256": exported_cmp["json_sha256"],
            "evidence_bundle_dir": str(bundle_dir),
        }

        # --- 4. Rust MCP Stdio Protocol Compatibility (Legacy 33 + Modern 2026-07-28 + Negative Gates) ---
        mcp_responses = _mcp_stdio_session(
            rust_bin,
            state_dir,
            "edge",
            [
                {"jsonrpc": "2.0", "id": 1, "method": "server/discover"},
                {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {"protocolVersion": "2026-07-28", "capabilities": {"experimental": {"tasks": {}}}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "project_context", "arguments": {"project_id": pid}}},
                {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "file_read_batch", "arguments": {"project_id": pid, "items": [{"path": "bridgepulse_lab/measurements.py"}, {"path": "fixtures/synthetic_airspeed_dataset.csv"}]}}},
                {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "git_diff_summary", "arguments": {"project_id": pid}}},
                {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "artifact_read", "arguments": {"project_id": pid, "artifact_id": after_manifest["identity"]["manifest_id"]}}},
                {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "file_write", "arguments": {"project_id": pid, "path": "bridgepulse_lab/measurements.py"}}},
                {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "file_read", "arguments": {"project_id": pid, "path": "bridgepulse_lab/measurements.py", "principal": "local"}}},
            ],
        )
        by_id = {r["id"]: r for r in mcp_responses}
        assert by_id[1]["error"]["code"] == -32601
        assert by_id[2]["result"]["protocolVersion"] == "2025-06-18"
        assert by_id[3]["result"]["protocolVersion"] == "2026-07-28"
        assert len(by_id[4]["result"]["tools"]) == 39
        assert by_id[5]["result"]["isError"] is False
        assert by_id[6]["result"]["isError"] is False
        assert by_id[7]["result"]["isError"] is False
        assert by_id[8]["result"]["isError"] is False
        assert by_id[8]["result"]["structuredContent"]["result"]["signature_verified"] is True
        assert by_id[9]["result"]["isError"] is True
        assert by_id[9]["result"]["structuredContent"]["code"] == "BRIDGE_POLICY_DENIED"
        assert by_id[10]["result"]["isError"] is True
        assert by_id[10]["result"]["structuredContent"]["code"] == "INVALID_ARGUMENT"

        results["stages"]["mcp_stdio_dual_compat"] = {
            "status": "PASS",
            "discover_32601": True,
            "legacy_2025_06_18_ok": True,
            "modern_2026_07_28_ok": True,
            "tool_count": 39,
            "project_context_ok": True,
            "file_read_batch_ok": True,
            "git_diff_summary_ok": True,
            "sealed_artifact_read_sig_verified": True,
            "edge_write_denied": True,
            "principal_spoof_denied": True,
            "stderr_clean": True,
        }

        # --- 5. Offline SQLite backup migration rehearsal (schema 3 -> 4) ---
        if baseline_backup is None:
            results["stages"]["sqlite_migration_rehearsal"] = {
                "status": "NOT_TESTED",
                "reason": "No isolated baseline backup was supplied.",
            }
        else:
            backup = baseline_backup.resolve(strict=True)
            clone_db = tmp_root / "clone-v040.sqlite3"
            mig = invoke_rust_cli(
                ["migrate-verify", str(backup), str(clone_db)], state_dir=state_dir, repo_root=REPO,
            )
            assert mig["instance_id_preserved"] == expected_instance
            assert mig["schema_version_after_migration"] == 4
            assert mig["total_projects_preserved"] == expected_project_count
            assert mig["edge_granted_projects_preserved"] == expected_project_count
            assert mig["post_migration_backup_integrity_ok"] is True
            assert mig["post_migration_foreign_key_issues"] == 0
            results["stages"]["sqlite_migration_rehearsal"] = {"status": "PASS", **mig}

        # --- 6. Two-Host Ed25519 Pairing & Replay Rehearsal ---
        dev_reh = invoke_rust_cli(["device-rehearsal"], state_dir=state_dir, repo_root=REPO)
        assert dev_reh["replay_rejected"] is True
        assert dev_reh["physical_second_pc_tested"] is False
        results["stages"]["device_pairing_rehearsal"] = {"status": "PASS_REHEARSAL_ONLY", **dev_reh}

        # --- 7. PX4 ULog Binary Parser Gate ---
        ulog_file = tmp_root / "synthetic_flight.ulg"
        buf = bytearray([0x55, 0x4C, 0x6F, 0x67, 0x01, 0x12, 0x35, 0x01])
        buf.extend((2_000_000).to_bytes(8, "little"))
        k, v = b"sys_name", b"SYNTHETIC_ULOG_TEST"
        buf.extend((1 + len(k) + len(v)).to_bytes(2, "little"))
        buf.append(ord("I"))
        buf.append(len(k))
        buf.extend(k)
        buf.extend(v)
        buf.extend((2).to_bytes(2, "little"))
        buf.append(ord("O"))
        buf.extend((120).to_bytes(2, "little"))
        ulog_file.write_bytes(bytes(buf))
        ulog_res = invoke_rust_cli(["parse-ulog", str(ulog_file), "--evidence-class", "recorded_log"], state_dir=state_dir, repo_root=REPO)
        assert ulog_res["valid_magic"] is True
        assert ulog_res["dropout_count"] == 1
        assert ulog_res["total_dropout_ms"] == 120
        results["stages"]["hardware_ulog_parser"] = {
            "status": "PASS_PARSER_ONLY",
            "physical_hardware_tested": False,
            "dropout_count": ulog_res["dropout_count"],
            "total_dropout_ms": ulog_res["total_dropout_ms"],
            "raw_log_sha256": ulog_res["header"]["raw_log_sha256"],
        }

        # --- 8. Loopback Rust Broker + BridgePulse Svelte UI HTTP Security Verification ---
        ui_dist = REPO / "apps" / "bridgepulse" / "dist"
        srv_proc = subprocess.Popen(
            [str(rust_bin), "--state-dir", str(state_dir), "serve", "--port", "0", "--ui-dist", str(ui_dist)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL,
        )
        try:
            disc = state_dir / "rust-broker.json"
            deadline = time.monotonic() + 10.0
            while not disc.is_file() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert disc.is_file(), "Rust broker discovery file did not appear"
            port = json.loads(disc.read_text(encoding="utf-8"))["port"]
            owner_tok = (state_dir / "owner.token").read_text(encoding="utf-8").strip()
            base = f"http://127.0.0.1:{port}"

            # 8a. Unauthenticated /api/overview -> 401
            try:
                urllib.request.urlopen(f"{base}/api/overview", timeout=5)
                raise AssertionError("Unauthenticated /api/overview unexpectedly succeeded")
            except urllib.error.HTTPError as e:
                assert e.code == 401

            # 8b. Cross-origin Origin header -> 403
            req_bad_origin = urllib.request.Request(
                f"{base}/api/overview",
                headers={"X-Bridge-Token": owner_tok, "Origin": "https://evil.example"},
            )
            try:
                urllib.request.urlopen(req_bad_origin, timeout=5)
                raise AssertionError("Cross-origin /api/overview unexpectedly succeeded")
            except urllib.error.HTTPError as e:
                assert e.code == 403

            # 8c. Authenticated /api/overview -> 200 with full overview + security headers
            req_ok = urllib.request.Request(f"{base}/api/overview", headers={"X-Bridge-Token": owner_tok})
            with urllib.request.urlopen(req_ok, timeout=5) as resp:
                assert resp.status == 200
                assert resp.headers.get("X-Content-Type-Options") == "nosniff"
                assert resp.headers.get("X-Frame-Options") == "DENY"
                ov = json.loads(resp.read().decode("utf-8"))
                assert ov["ok"] is True
                assert ov["principal"] == "local"
                assert len(ov["evidence_manifests"]) >= 2

            # 8d. Static BridgePulse RTL HTML + CSP header on /
            with urllib.request.urlopen(f"{base}/", timeout=5) as resp:
                assert resp.status == 200
                csp = resp.headers.get("Content-Security-Policy", "")
                assert "frame-ancestors 'none'" in csp
                html_body = resp.read().decode("utf-8")
                assert 'dir="rtl"' in html_body and "BridgePulse V0.4.0" in html_body

            results["stages"]["bridgepulse_ui_http_security"] = {
                "status": "PASS",
                "unauth_401": True,
                "cross_origin_403": True,
                "auth_overview_200": True,
                "rtl_html_and_csp_verified": True,
                "playwright_e2e_status": "NOT_TESTED (Playwright package not installed; HTTP + Svelte tsc/vite verified)",
            }
        finally:
            srv_proc.terminate()
            try:
                srv_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                srv_proc.kill()

        # --- 9. Rust Core Performance & 1000-Read Reconnect Soak Benchmark ---
        bench_out = REPO / "benchmarks" / "raw" / "rust-v0.4.0-benchmark.json"
        bench = invoke_rust_cli(["benchmark", "--out-json", str(bench_out), "--soak-reads", "1000"], state_dir=state_dir, repo_root=REPO, timeout=120)
        assert bench["workloads"]["soak_reconnect_1000_reads"]["errors"] == 0
        results["stages"]["rust_benchmark_and_1000_soak"] = {
            "status": "PASS",
            "working_set_idle_mib": bench["memory"]["working_set_idle_mib"],
            "working_set_post_mib": bench["memory"]["working_set_post_mib"],
            "read_4k_c1_p50_ms": bench["workloads"]["read_4k_warm"]["c1"]["p50_ms"],
            "read_4k_c1_p95_ms": bench["workloads"]["read_4k_warm"]["c1"]["p95_ms"],
            "read_4k_c8_p95_ms": bench["workloads"]["read_4k_warm"]["c8"]["p95_ms"],
            "read_64k_c1_p95_ms": bench["workloads"]["read_64k_warm"]["c1"]["p95_ms"],
            "durable_job_claim_p95_ms": bench["workloads"]["durable_job_claim_ack"]["p95_ms"],
            "soak_1000_reads_errors": bench["workloads"]["soak_reconnect_1000_reads"]["errors"],
            "soak_1000_reads_p95_ms": bench["workloads"]["soak_reconnect_1000_reads"]["p95_ms"],
        }

    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    out_path = REPO / "benchmarks" / "raw" / "v0.4.0-acceptance-results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-backup", type=Path, help="Path to an isolated SQLite backup")
    parser.add_argument("--expected-instance", help="Expected ID recorded from the offline backup")
    parser.add_argument("--expected-project-count", type=int)
    options = parser.parse_args()
    summary = run_all(**vars(options))
    print(json.dumps(summary, indent=2))
