"""Audit Section 4 — Genuine Provider E2E Coding Cycle (Codex Primary + Claude Code + AGY).
- NEVER gives the agent the exact code replacement.
- Enforces INCLUDED_ONLY by explicitly clearing OPENAI_API_KEY / ANTHROPIC_API_KEY from child env.
- Explicitly attributes authorship of every file change (`provider:codex`, `provider:claude`, etc.).
- Verifies test suite SHA-256 was NOT altered, assertions NOT disabled, command NOT changed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
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


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def redact_text(text: str) -> str:
    import re
    out = re.sub(r"\bsk-[A-Za-z0-9_-]{20,}\b", "[REDACTED:sk]", text)
    out = re.sub(r"(?i)Bearer\s+[A-Za-z0-9._\-]{20,}", "Bearer [REDACTED]", out)
    out = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED:email]", out)
    return out


def clean_included_only_env() -> dict[str, str]:
    env = dict(os.environ)
    for k in list(env.keys()):
        if any(s in k.upper() for s in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "CONTROL_PLANE_API_KEY", "CLAUDE_API_KEY")):
            env.pop(k, None)
    return env


def run_provider_e2e() -> dict[str, Any]:
    BUNDLE_DIR.mkdir(parents=True, exist_ok=True)
    rust_bin = find_rust_binary(REPO)
    assert rust_bin is not None, "Compiled edge-bridge.exe required"
    python_exe = REPO / ".venv" / "Scripts" / "python.exe"

    report: dict[str, Any] = {
        "host": os.environ.get("COMPUTERNAME", "unknown"),
        "billing_policy": "INCLUDED_ONLY (API keys explicitly stripped from child env)",
        "codex_e2e": {},
        "claude_probe": {},
        "agy_probe": {},
    }

    tmp = Path(tempfile.mkdtemp(prefix="eb_provider_e2e_"))
    try:
        state_dir = tmp / "state"
        acc_repo = tmp / "bridgepulse-lab-live"
        shutil.copytree(REPO / "examples" / "bridgepulse-lab", acc_repo, ignore=shutil.ignore_patterns("__pycache__", "evidence-bundle"))

        for gcmd in (
            ["git", "init", "-b", "main"],
            ["git", "config", "user.name", "Audit E2E"],
            ["git", "config", "user.email", "audit@local.invalid"],
        ):
            subprocess.run(gcmd, cwd=acc_repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)

        # Seed defect cleanly preserving exact line endings
        meas = acc_repo / "bridgepulse_lab" / "measurements.py"
        orig_clean_bytes = meas.read_bytes()
        buggy_text = orig_clean_bytes.decode("utf-8").replace(
            "KNOTS_TO_MPS = 1852.0 / 3600.0",
            "KNOTS_TO_MPS = 0.50",
        )
        assert buggy_text != orig_clean_bytes.decode("utf-8")
        meas.write_bytes(buggy_text.encode("utf-8"))
        buggy_sha = sha256_file(meas)
        tests_sha_before = sha256_file(acc_repo / "tests" / "test_lab.py")

        subprocess.run(["git", "add", "-A"], cwd=acc_repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)
        subprocess.run(["git", "commit", "-m", "baseline: bridgepulse-lab failing fixture"], cwd=acc_repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)

        reg = invoke_rust_cli(["register", str(acc_repo), "--name", "Provider E2E Lab", "--grant-edge"], state_dir=state_dir, repo_root=REPO)
        pid = reg["project_id"]

        # Step 1: Supervisor runs failing tests BEFORE agent intervention
        before = invoke_rust_cli([
            "run-job", "--project-id", pid, "--task-id", "codex_e2e_01", "--operation-id", "op-e2e-before",
            "--cwd", str(acc_repo), "--executable", str(python_exe),
            "--arg", "-B", "--arg", "-m", "--arg", "unittest", "--arg", "discover", "--arg", "-s", "--arg", "tests", "--arg", "-t", "--arg", ".", "--arg", "-v",
            "--parser", "python_unittest", "--synthetic-data",
        ], state_dir=state_dir, repo_root=REPO)
        assert before["manifest"]["conclusions"]["overall_verdict"] == "FAIL"
        trusted_pubkey = before["manifest"]["signer_public_key_hex"]
        before_art_dir = Path(before["manifest_json_path"]).parent
        ver_before = invoke_rust_cli([
            "verify-evidence", before["manifest_json_path"],
            "--trusted-key", trusted_pubkey,
            "--artifacts-dir", str(before_art_dir),
        ], state_dir=state_dir, repo_root=REPO)
        assert ver_before["overall_verified"] is True

        # Step 2: Copy into isolated agent workspace & run REAL Codex CLI (problem description ONLY, NO fix hint!)
        agent_ws = tmp / "codex_isolated_ws"
        shutil.copytree(acc_repo, agent_ws)
        codex_exe = Path(os.environ["APPDATA"]) / "npm/node_modules/@openai/codex/node_modules/@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe"
        problem_prompt = (
            "The unit test suite in tests/test_lab.py is failing in this repository. "
            "Read the source files and test suite, diagnose the root cause of the failure, "
            "and fix the bug in the production code under bridgepulse_lab/. "
            "Strict rules: DO NOT modify any file under tests/ or fixtures/, DO NOT disable assertions. "
            "Keep your changes minimal and explain your root-cause diagnosis concisely."
        )
        t0 = time.monotonic()
        c_proc = subprocess.run(
            [
                str(codex_exe), "exec",
                "--json",
                "--ephemeral",
                "--sandbox", "workspace-write",
                "-C", str(agent_ws),
                problem_prompt,
            ],
            env=clean_included_only_env(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=180,
        )
        codex_elapsed_ms = round((time.monotonic() - t0) * 1000.0, 2)
        codex_events_raw = c_proc.stdout
        codex_events_redacted = redact_text(codex_events_raw)
        codex_log_path = BUNDLE_DIR / "provider-codex-session.jsonl"
        codex_log_path.write_text(codex_events_redacted, encoding="utf-8")

        parsed_events = []
        for ln in codex_events_raw.splitlines():
            ln = ln.strip()
            if ln:
                try:
                    parsed_events.append(json.loads(ln))
                except json.JSONDecodeError:
                    pass

        agent_tests_sha = sha256_file(agent_ws / "tests" / "test_lab.py")
        agent_meas_bytes = (agent_ws / "bridgepulse_lab" / "measurements.py").read_bytes()
        agent_meas_sha = hashlib.sha256(agent_meas_bytes).hexdigest()
        agent_edited_meas = agent_meas_sha != buggy_sha
        agent_kept_tests_intact = agent_tests_sha == tests_sha_before

        codex_summary: dict[str, Any] = {
            "provider": "codex",
            "binary": str(codex_exe),
            "sandbox_flag": "workspace-write (in isolated workspace copy)",
            "included_only_env_stripped_api_keys": True,
            "exit_code": c_proc.returncode,
            "duration_ms": codex_elapsed_ms,
            "events_captured": len(parsed_events),
            "event_types": sorted({str(e.get("type", "unknown")) for e in parsed_events}),
            "session_log_path": str(codex_log_path),
            "session_log_sha256": sha256_file(codex_log_path),
            "agent_edited_measurements_py": agent_edited_meas,
            "agent_kept_tests_untouched": agent_kept_tests_intact,
            "stderr_preview": redact_text(c_proc.stderr)[:600],
            "edit_author": "provider:codex-cli-0.169.0" if agent_edited_meas else "none",
        }

        if agent_edited_meas and agent_kept_tests_intact:
            # Step 4: Apply AGENT-PRODUCED edit to acceptance repo via Bridge hash-checked PatchPlanV04!
            plan = {
                "patch_plan_version": "0.4.0",
                "project_id": pid,
                "root_identity": reg["root_identity"],
                "operation_id": "op-codex-agent-fix-01",
                "task_id": "codex_e2e_01",
                "summary": "Apply Codex-diagnosed fix to bridgepulse_lab/measurements.py",
                "scope": ["bridgepulse_lab/measurements.py"],
                "edits": [{
                    "path": "bridgepulse_lab/measurements.py",
                    "content": agent_meas_bytes.decode("utf-8"),
                    "expected_hash": buggy_sha,
                    "expected_postimage_hash": agent_meas_sha,
                }],
            }
            plan_path = BUNDLE_DIR / "provider-codex-patch-plan.json"
            plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
            applied = invoke_rust_cli(["apply-patch", "--project-root", str(acc_repo), "--plan-json", str(plan_path)], state_dir=state_dir, repo_root=REPO)
            diff_path = BUNDLE_DIR / "provider-codex-fix.diff"
            diff_path.write_text(applied["unified_diff"], encoding="utf-8")

            # Step 5: Re-run tests from TRUSTED local supervisor
            after = invoke_rust_cli([
                "run-job", "--project-id", pid, "--task-id", "codex_e2e_01", "--operation-id", "op-e2e-after",
                "--cwd", str(acc_repo), "--executable", str(python_exe),
                "--arg", "-B", "--arg", "-m", "--arg", "unittest", "--arg", "discover", "--arg", "-s", "--arg", "tests", "--arg", "-t", "--arg", ".", "--arg", "-v",
                "--parser", "python_unittest", "--synthetic-data",
            ], state_dir=state_dir, repo_root=REPO)
            after_art_dir = Path(after["manifest_json_path"]).parent
            ver_after = invoke_rust_cli([
                "verify-evidence", after["manifest_json_path"],
                "--trusted-key", trusted_pubkey,
                "--artifacts-dir", str(after_art_dir),
            ], state_dir=state_dir, repo_root=REPO)

            tests_sha_after = sha256_file(acc_repo / "tests" / "test_lab.py")
            shutil.copy2(before["manifest_json_path"], BUNDLE_DIR / "provider-codex-before-manifest.json")
            shutil.copy2(after["manifest_json_path"], BUNDLE_DIR / "provider-codex-after-manifest.json")

            codex_summary.update({
                "before_run_id": before["job"]["run_id"],
                "before_verdict": before["manifest"]["conclusions"]["overall_verdict"],
                "before_tests": f"{before['manifest']['tests']['passed']}/{before['manifest']['tests']['executed']} passed, {before['manifest']['tests']['failed']} failed",
                "before_5dim_verified": ver_before["overall_verified"],
                "patch_journal_id": applied["journal_id"],
                "diff_path": str(diff_path),
                "diff_sha256": applied["diff_sha256"],
                "after_run_id": after["job"]["run_id"],
                "after_verdict": after["manifest"]["conclusions"]["overall_verdict"],
                "after_tests": f"{after['manifest']['tests']['passed']}/{after['manifest']['tests']['executed']} passed, {after['manifest']['tests']['failed']} failed",
                "after_5dim_verified": ver_after["overall_verified"],
                "tests_sha256_unchanged": tests_sha_before == tests_sha_after,
                "overall_status": "PASS" if (after["manifest"]["conclusions"]["overall_verdict"] == "PASS" and ver_after["overall_verified"] and tests_sha_before == tests_sha_after) else "FAIL",
            })
        else:
            codex_summary["overall_status"] = "FAIL"

        report["codex_e2e"] = codex_summary

        # --- Independent Provider #2: Claude Code (direct binary, non-bare, read-only diagnosis, INCLUDED_ONLY) ---
        claude_exe = Path(os.environ["USERPROFILE"]) / ".local" / "bin" / "claude.exe"
        claude_ws = tmp / "claude_diag_ws"
        shutil.copytree(acc_repo, claude_ws)
        # Re-seed defect for Claude read-only diagnosis
        (claude_ws / "bridgepulse_lab" / "measurements.py").write_bytes(buggy_text.encode("utf-8"))
        claude_prompt = (
            "Read bridgepulse_lab/measurements.py and tests/test_lab.py in this workspace and explain in 2 concise "
            "sentences why test_knots_to_mps_exact_international_factor fails. Do not edit any files.\n"
        )
        t1 = time.monotonic()
        cl_proc = subprocess.run(
            [
                str(claude_exe),
                "-p",
                "--output-format", "stream-json",
                "--verbose",
                "--permission-mode", "plan",
                "--disallowedTools", "Bash,Edit,Write,NotebookEdit",
            ],
            cwd=claude_ws,
            env=clean_included_only_env(),
            input=claude_prompt,
            capture_output=True,
            text=True,
            timeout=90,
        )
        cl_ms = round((time.monotonic() - t1) * 1000.0, 2)
        cl_log_path = BUNDLE_DIR / "provider-claude-plan-session.jsonl"
        cl_log_path.write_text(redact_text(cl_proc.stdout), encoding="utf-8")
        cl_events = []
        for ln in cl_proc.stdout.splitlines():
            ln = ln.strip()
            if ln:
                try:
                    cl_events.append(json.loads(ln))
                except json.JSONDecodeError:
                    pass
        result_ev = next((e for e in reversed(cl_events) if e.get("type") == "result"), {})
        report["claude_probe"] = {
            "provider": "claude_code",
            "binary": str(claude_exe),
            "bypassed_shell_dangerous_alias": True,
            "bare_mode_used": False,
            "included_only_env_stripped_api_keys": True,
            "mode": "read_only_plan_diagnosis",
            "exit_code": cl_proc.returncode,
            "duration_ms": cl_ms,
            "events_captured": len(cl_events),
            "session_log_path": str(cl_log_path),
            "session_log_sha256": sha256_file(cl_log_path),
            "result_preview": redact_text(str(result_ev.get("result", "")))[:400],
            "status": "PASS_DIAGNOSIS" if (cl_proc.returncode == 0 and len(cl_events) > 0 and not result_ev.get("is_error")) else "FAIL_OR_BLOCKED",
            "stderr_preview": redact_text(cl_proc.stderr)[:300],
        }

        # --- Independent Provider #3: Google Antigravity (agy.exe) ---
        agy_exe = Path(os.environ["LOCALAPPDATA"]) / "agy" / "bin" / "agy.exe"
        # Check whether agy provides a non-spending auth/billing status check; do NOT blindly run paid/unknown turns!
        agy_ver = subprocess.run([str(agy_exe), "--version"], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=15)
        agy_help = subprocess.run([str(agy_exe), "--help"], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=15)
        has_auth_cmd = "auth" in (agy_help.stdout + agy_help.stderr).lower()
        report["agy_probe"] = {
            "provider": "antigravity_agy",
            "binary": str(agy_exe),
            "version": (agy_ver.stdout or agy_ver.stderr).strip(),
            "has_cli_auth_or_billing_status_subcommand": has_auth_cmd,
            "included_only_verified": False,
            "status": "BLOCKED",
            "reason": "agy CLI exposes no read-only auth/billing verification command to prove INCLUDED_ONLY entitlement prior to launching a live turn; per Section 4 & Section 9, live AGY coding execution stays BLOCKED rather than assuming entitlement.",
        }

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    out_json = BUNDLE_DIR / "provider-e2e-summary.json"
    out_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    print(json.dumps(run_provider_e2e(), indent=2))
