from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

from . import capabilities, diagnostics, releases, runner
from .broker import BridgeError, MUTATION_TOOLS, READ_TOOLS, call_broker, error_payload, run_broker, setup_state, verify_state_path
from .files import ProjectFiles
from .state import State
from .workers import WorkerManager


def default_state() -> Path:
    return Path(os.environ["LOCALAPPDATA"]) / "EdgeProjectBridge"


def _broker_read_full(state: Path, project_id: str, rel_path: str, max_bytes: int = 2 * 1024 * 1024) -> tuple[str | None, str]:
    offset = 0
    chunks: list[str] = []
    file_hash: str | None = None
    while True:
        try:
            page = call_broker(
                state,
                "local",
                "file_read",
                {"project_id": project_id, "path": rel_path, "offset": offset, "limit": 65536},
            )
        except BridgeError as exc:
            if exc.code == "FILE_NOT_FOUND":
                return None, ""
            raise
        file_hash = page.get("hash")
        chunks.append(page.get("content", ""))
        next_offset = page.get("next_offset")
        if next_offset is None or sum(len(c) for c in chunks) >= max_bytes:
            break
        offset = int(next_offset)
    return file_hash, "".join(chunks)


def _broker_write_and_record_artifact(
    state: Path,
    project_id: str,
    task_id: str,
    rel_path: str,
    content: str,
    op_prefix: str,
) -> dict:
    bounded = content[:262_144]
    content_digest = hashlib.sha256(bounded.encode("utf-8")).hexdigest()
    existing_hash, _ = _broker_read_full(state, project_id, rel_path)
    if existing_hash != content_digest:
        call_broker(
            state,
            "local",
            "file_write",
            {
                "project_id": project_id,
                "operation_id": f"{op_prefix}-{content_digest[:8]}",
                "path": rel_path,
                "content": bounded,
                "expected_hash": existing_hash,
            },
        )
    return call_broker(
        state,
        "local",
        "owner_record_artifact",
        {"project_id": project_id, "task_id": task_id, "path": rel_path},
    )


def _run_model_capabilities(state: Path, args: argparse.Namespace) -> dict:
    if args.record:
        if not args.model or not args.surface or not args.caps_json:
            raise BridgeError("INVALID_ARGUMENT", "--record requires --model, --surface, and --caps-json.")
        caps_obj = json.loads(args.caps_json)
        payload = {
            "model_id": args.model,
            "surface": args.surface,
            "capabilities": caps_obj,
            "source": args.source,
            "notes": args.notes,
            "merge": not args.no_merge,
        }
        try:
            return call_broker(state, "local", "owner_record_model_capability", payload)
        except BridgeError as exc:
            if exc.code != "BROKER_OFFLINE":
                raise
            verify_state_path(state)
            return State(state / "state.sqlite3").record_model_capability(
                args.model,
                args.surface,
                caps_obj,
                source=args.source,
                notes=args.notes,
                merge=not args.no_merge,
            )

    params = {"target_principal": args.principal}
    if args.model is not None:
        params["model_id"] = args.model
    if args.surface is not None:
        params["surface"] = args.surface
    try:
        return call_broker(state, "local", "owner_list_model_capabilities", params)
    except BridgeError as exc:
        if exc.code != "BROKER_OFFLINE":
            raise
        verify_state_path(state)
        rows = State(state / "state.sqlite3").list_model_capabilities(
            model_id=args.model,
            surface=args.surface,
        )
        return capabilities.aggregate_capabilities(rows, principal=args.principal)


def _run_fallback_plan(state: Path, args: argparse.Namespace) -> dict:
    req_caps = [item.strip() for item in args.require.split(",") if item.strip()]
    params: dict = {
        "project_id": args.project_id,
        "operation_id": args.operation_id,
        "required_capabilities": req_caps,
        "target_principal": args.principal,
    }
    if args.task_id is not None:
        params["task_id"] = args.task_id
    if args.model is not None:
        params["model_id"] = args.model
    if args.surface is not None:
        params["surface"] = args.surface
    try:
        return call_broker(state, "local", "owner_fallback_plan", params)
    except BridgeError as exc:
        if exc.code != "BROKER_OFFLINE":
            raise
        verify_state_path(state)
        store = State(state / "state.sqlite3")
        project = store.get_project(args.project_id, "local")
        try:
            return capabilities.build_fallback_plan(
                project_id=args.project_id,
                task_id=args.task_id,
                operation_id=args.operation_id,
                principal=args.principal,
                required_capabilities=req_caps,
                observations=store.list_model_capabilities(),
                model_id=args.model,
                surface=args.surface,
                state_dir_hint=str(state),
                project_root_hint=project["root"],
            )
        except ValueError as exc:
            raise BridgeError("INVALID_ARGUMENT", str(exc)) from exc


def _load_patch_plan_text(args: argparse.Namespace) -> str:
    if args.json is not None:
        candidate = args.json
        if candidate.lstrip().startswith(("{", "[")):
            return candidate
        path = Path(candidate)
        if not path.is_file():
            raise BridgeError("INVALID_ARGUMENT", f"Patch plan file not found: {candidate}")
        if path.stat().st_size > 1_572_864:
            raise BridgeError("INVALID_ARGUMENT", "Patch plan file exceeds 1.5 MiB limit.")
        return path.read_text(encoding="utf-8")

    if args.paste:
        if sys.stdin.isatty() and sys.stderr.isatty():
            print("Paste patch plan JSON (end with a line containing only EOF):", file=sys.stderr, flush=True)
        lines: list[str] = []
        total = 0
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            if line.rstrip("\r\n") == "EOF":
                break
            total += len(line.encode("utf-8", errors="replace"))
            if total > 1_572_864:
                raise BridgeError("INVALID_ARGUMENT", "Pasted patch plan exceeds 1.5 MiB limit.")
            lines.append(line)
        return "".join(lines)

    if sys.stdin.isatty():
        raise BridgeError("INVALID_ARGUMENT", "Provide --json <file_or_inline> or --paste to supply a patch plan.")

    return sys.stdin.read(1_572_865)


def _resolve_mxc_recipe(status: dict, recipe: str) -> tuple[str, list[str]] | None:
    if recipe == "project_tests" and status.get("python_test_scope"):
        return "python", ["-B", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"]
    if recipe == "calculator":
        return "python", ["-B", "-m", "unittest", "-v"]
    if recipe == "node_tests" and status.get("node_test_scope"):
        return "node", ["--test", "--test-concurrency=1", "tests/*.test.mjs"]
    if recipe == "powershell_script" and status.get("powershell_test_scope"):
        ps_files = status["powershell_test_scope"].get("files") or []
        if ps_files:
            return "powershell", ["-NoProfile", "-NonInteractive", "-File", ps_files[0]]
    return None


def _parse_plan_verification_argv(plan_cmd: str | list[str]) -> list[str]:
    if isinstance(plan_cmd, list):
        argv = plan_cmd
    elif isinstance(plan_cmd, str) and plan_cmd.strip():
        stripped = plan_cmd.strip()
        argv = json.loads(stripped) if stripped.startswith("[") else shlex.split(stripped, posix=(os.name != "nt"))
    else:
        raise BridgeError("INVALID_ARGUMENT", "Invalid verification_command in patch plan.")
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
        raise BridgeError("INVALID_ARGUMENT", "verification_command must be a non-empty command or string argv list.")
    return argv


def _run_verification_for_patch(
    state: Path,
    project_id: str,
    project_root: Path,
    task_id: str,
    operation_id: str,
    *,
    recipe: str,
    verify_cmd: str | None,
    plan_cmd: str | list[str] | None,
    allow_host_verify: bool = False,
) -> dict:
    if verify_cmd is not None:
        stripped = verify_cmd.strip()
        argv = json.loads(stripped) if stripped.startswith("[") else shlex.split(stripped, posix=(os.name != "nt"))
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
            raise BridgeError("INVALID_ARGUMENT", "--verify-cmd must be a non-empty command or JSON argv array.")
        proc = subprocess.run(
            argv,
            cwd=str(project_root),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
        )
        combined = f"$ {' '.join(argv)}\n{proc.stdout}{proc.stderr}".strip()
        return {
            "mode": "local_owner_cmd",
            "exit_code": int(proc.returncode),
            "verdict": "PASS" if proc.returncode == 0 else "FAIL",
            "job_id": None,
            "output": combined,
        }

    status = call_broker(state, "local", "project_status", {"project_id": project_id})
    mxc_spec = _resolve_mxc_recipe(status, recipe)

    if mxc_spec is not None:
        mxc_exe, mxc_argv = mxc_spec
        job_resp = call_broker(
            state,
            "local",
            "process_start",
            {
                "project_id": project_id,
                "task_id": task_id,
                "operation_id": f"{operation_id}-verify-{hashlib.sha256(' '.join(mxc_argv).encode()).hexdigest()[:6]}",
                "executable": mxc_exe,
                "argv": mxc_argv,
                "cwd_relative": ".",
                "timeout_seconds": 60,
            },
        )
        job_id = job_resp["job_id"]
        deadline = time.monotonic() + 65.0
        job_state = job_resp
        while time.monotonic() < deadline:
            job_state = call_broker(state, "local", "job_get", {"project_id": project_id, "job_id": job_id})
            if job_state["status"] in {"succeeded", "failed", "timed_out", "cancelled"}:
                break
            time.sleep(0.1)
        log_resp = call_broker(state, "local", "job_output", {"project_id": project_id, "job_id": job_id})
        exit_code = job_state.get("exit_code")
        verdict = "PASS" if job_state["status"] == "succeeded" and exit_code == 0 else "FAIL"
        return {
            "mode": f"mxc:{recipe}",
            "exit_code": int(exit_code) if exit_code is not None else 1,
            "status": job_state["status"],
            "verdict": verdict,
            "job_id": job_id,
            "output": log_resp.get("output", ""),
        }

    if plan_cmd is not None:
        if not allow_host_verify:
            raise BridgeError(
                "CONFIRMATION_REQUIRED",
                "Executing plan verification_command on the unsandboxed host requires --allow-host-verify.",
            )
        argv = _parse_plan_verification_argv(plan_cmd)
        proc = subprocess.run(
            argv,
            cwd=str(project_root),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
        )
        combined = f"$ {' '.join(argv)}\n{proc.stdout}{proc.stderr}".strip()
        return {
            "mode": "plan_verification_command",
            "exit_code": int(proc.returncode),
            "verdict": "PASS" if proc.returncode == 0 else "FAIL",
            "job_id": None,
            "output": combined,
        }

    raise BridgeError(
        "EXECUTION_REQUEST_UNSUPPORTED",
        "No granted MXC test scope or verification command is available for --verify.",
    )


def _run_apply_patch_plan(state: Path, args: argparse.Namespace) -> dict:
    raw = _load_patch_plan_text(args)
    parsed = json.loads(raw or "{}")
    if isinstance(parsed, list):
        edits = parsed
        plan_meta: dict = {}
    elif isinstance(parsed, dict):
        edits = parsed.get("edits")
        plan_meta = parsed
    else:
        raise BridgeError("INVALID_ARGUMENT", "Patch plan JSON must be an array of edits or an object with 'edits'.")

    if plan_meta.get("project_id") is not None and plan_meta.get("project_id") != args.project_id:
        raise BridgeError("INVALID_ARGUMENT", "Patch plan project_id does not match CLI project_id.")
    plan_op = plan_meta.get("operation_id")
    if args.operation_id and plan_op and args.operation_id != plan_op:
        raise BridgeError("INVALID_ARGUMENT", "CLI --operation-id does not match patch plan operation_id.")
    operation_id = args.operation_id or plan_op
    if not isinstance(operation_id, str) or not operation_id.strip():
        raise BridgeError("INVALID_ARGUMENT", "Provide --operation-id or include operation_id in the patch plan JSON.")

    if not isinstance(edits, list) or not edits:
        raise BridgeError("INVALID_ARGUMENT", "Patch plan must contain a non-empty 'edits' list.")

    plan_verif_cmd = plan_meta.get("verification_command")
    should_verify = False if args.no_verify else bool(args.verify or args.verify_cmd)

    proj_status = call_broker(state, "local", "project_status", {"project_id": args.project_id})
    mxc_spec = _resolve_mxc_recipe(proj_status, args.verify_recipe) if should_verify and args.verify_cmd is None else None
    would_run_host_plan_cmd = bool(
        should_verify and args.verify_cmd is None and mxc_spec is None and plan_verif_cmd is not None
    )
    if not should_verify:
        preview_mode = "skipped (--no-verify)" if args.no_verify else "skipped (pass --verify to run)"
    elif args.verify_cmd is not None:
        preview_mode = "unsandboxed host (--verify-cmd)"
    elif mxc_spec is not None:
        preview_mode = f"MXC {args.verify_recipe}"
    elif plan_verif_cmd is not None:
        preview_mode = (
            "unsandboxed host (plan_verification_command)"
            if args.allow_host_verify
            else "unsandboxed host (blocked without --allow-host-verify)"
        )
    else:
        preview_mode = "unavailable (no MXC scope or verification_command)"

    # Pre-apply preview to stderr via Broker file_read (respects NTFS containment & _DENIED)
    print(f"[patch-preview] project={args.project_id} operation_id={operation_id} edits={len(edits)}", file=sys.stderr)
    for edit in edits:
        if not isinstance(edit, dict) or not isinstance(edit.get("path"), str) or not isinstance(edit.get("content"), str):
            raise BridgeError("INVALID_ARGUMENT", "Each edit must include string 'path', 'content', and 'expected_hash'.")
        rel_path = edit["path"]
        exp_hash = edit.get("expected_hash")
        cur_hash, old_text = _broker_read_full(state, args.project_id, rel_path)
        if cur_hash is None:
            hash_status = "NEW_FILE" if exp_hash is None else "MISMATCH(missing)"
        elif cur_hash == exp_hash:
            hash_status = "MATCH"
        else:
            hash_status = "MISMATCH"
        print(
            f"[patch-preview] file={rel_path} expected_hash={exp_hash} current_hash={cur_hash} status={hash_status}",
            file=sys.stderr,
        )
        diff_lines = list(
            difflib.unified_diff(
                old_text.splitlines(keepends=True),
                edit["content"].splitlines(keepends=True),
                fromfile="/dev/null" if cur_hash is None else f"a/{rel_path}",
                tofile=f"b/{rel_path}",
            )
        )
        for line in diff_lines[:400]:
            sys.stderr.write(line if line.endswith("\n") else line + "\n")
        if len(diff_lines) > 400:
            print(f"... ({len(diff_lines) - 400} more diff lines truncated in preview)", file=sys.stderr)

    if plan_verif_cmd is not None or should_verify:
        cmd_display = (
            json.dumps(plan_verif_cmd, ensure_ascii=True)
            if plan_verif_cmd is not None
            else (args.verify_cmd if args.verify_cmd is not None else f"<recipe:{args.verify_recipe}>")
        )
        print(
            f"[patch-preview] verification_command={cmd_display} mode={preview_mode}",
            file=sys.stderr,
        )
    sys.stderr.flush()

    if would_run_host_plan_cmd and not args.allow_host_verify:
        raise BridgeError(
            "CONFIRMATION_REQUIRED",
            "Executing plan verification_command on the unsandboxed host requires --allow-host-verify.",
        )
    if should_verify and args.verify_cmd is None and mxc_spec is None and plan_verif_cmd is None:
        raise BridgeError(
            "EXECUTION_REQUEST_UNSUPPORTED",
            "No granted MXC test scope or verification command is available for --verify.",
        )

    if not args.confirm:
        raise BridgeError(
            "CONFIRMATION_REQUIRED",
            "Explicit confirmation required (--confirm) after reviewing [patch-preview].",
        )

    artifact_dir = ""
    proj_info = proj_status["project"]
    proj_root = Path(proj_info["root"])
    task_id = args.task_id or plan_meta.get("task_id") or f"patch-{operation_id}"[:128]
    summary = str(plan_meta.get("summary") or f"Applied patch plan {operation_id}")
    changed_files = [{"path": e["path"]} for e in edits]

    if should_verify:
        if not isinstance(task_id, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}", task_id):
            raise BridgeError("INVALID_ARGUMENT", "task_id must be 1-128 safe identifier characters.")
        if ":" in task_id:
            raise BridgeError("INVALID_ARGUMENT", "task_id cannot contain ':' when recording verification artifacts.")
        artifact_dir = args.artifact_dir.strip("/")
        if not artifact_dir or artifact_dir.startswith("/") or "\\" in artifact_dir or ".." in artifact_dir.split("/"):
            raise BridgeError("INVALID_ARGUMENT", "--artifact-dir must be a clean relative POSIX path.")
        if would_run_host_plan_cmd:
            _parse_plan_verification_argv(plan_verif_cmd)
        ProjectFiles(proj_info["root"], proj_info["root_identity"]).ensure_directory(f"{artifact_dir}/{task_id}")

    apply_result = call_broker(
        state,
        "local",
        "owner_apply_patch_plan",
        {
            "project_id": args.project_id,
            "operation_id": operation_id,
            "edits": edits,
        },
    )

    if not should_verify:
        return apply_result

    # Ensure task row exists before owner_record_artifact
    call_broker(
        state,
        "local",
        "task_checkpoint",
        {
            "project_id": args.project_id,
            "task_id": task_id,
            "operation_id": f"{operation_id}-ckpt-init",
            "objective": summary,
            "summary": f"Applied patch plan {operation_id}; running verification",
            "next_action": "Await post-apply test verification",
            "changed_files": changed_files,
        },
    )

    verif = _run_verification_for_patch(
        state,
        args.project_id,
        proj_root,
        task_id,
        operation_id,
        recipe=args.verify_recipe,
        verify_cmd=args.verify_cmd,
        plan_cmd=plan_verif_cmd,
        allow_host_verify=args.allow_host_verify,
    )

    git_diff_data = None
    if (proj_root / ".git").exists():
        try:
            git_diff_data = call_broker(
                state,
                "local",
                "git_diff",
                {"project_id": args.project_id, "offset": 0, "limit": 65536},
            )
        except BridgeError:
            git_diff_data = None

    test_rel = f"{artifact_dir}/{task_id}/{operation_id}-test.txt"
    test_artifact = _broker_write_and_record_artifact(
        state,
        args.project_id,
        task_id,
        test_rel,
        verif["output"] or f"exit_code={verif['exit_code']}\n",
        f"{operation_id}-art-test",
    )

    diff_artifact = None
    if git_diff_data is not None:
        diff_rel = f"{artifact_dir}/{task_id}/{operation_id}-git.diff"
        diff_text = git_diff_data.get("content") or "(empty diff)\n"
        diff_artifact = _broker_write_and_record_artifact(
            state,
            args.project_id,
            task_id,
            diff_rel,
            diff_text,
            f"{operation_id}-art-diff",
        )

    evidence_text = (
        f"verdict={verif['verdict']} exit_code={verif['exit_code']} mode={verif['mode']} "
        f"test_artifact={test_artifact['artifact_id']}"
    )[:4000]
    call_broker(
        state,
        "local",
        "owner_record_verification",
        {
            "project_id": args.project_id,
            "check_id": f"patch-{operation_id}",
            "verdict": verif["verdict"],
            "evidence": evidence_text,
            "model": plan_meta.get("model_id"),
        },
    )

    digest_tag = hashlib.sha256(evidence_text.encode("utf-8")).hexdigest()[:8]
    final_ckpt = call_broker(
        state,
        "local",
        "task_checkpoint",
        {
            "project_id": args.project_id,
            "task_id": task_id,
            "operation_id": f"{operation_id}-ckpt-{digest_tag}",
            "objective": summary,
            "summary": f"Patch {operation_id} applied; verification {verif['verdict']} (exit_code={verif['exit_code']}).",
            "next_action": (
                "Review saved test and git_diff artifacts via Edge MCP."
                if verif["verdict"] == "PASS"
                else "Inspect failure artifact and prepare an adjusted hash-checked patch proposal."
            ),
            "changed_files": changed_files,
            "test_evidence": [
                {
                    "operation_id": operation_id,
                    "mode": verif["mode"],
                    "exit_code": verif["exit_code"],
                    "verdict": verif["verdict"],
                    "job_id": verif.get("job_id"),
                    "test_artifact_id": test_artifact["artifact_id"],
                    "diff_artifact_id": diff_artifact["artifact_id"] if diff_artifact else None,
                    "diff_sha256": git_diff_data.get("diff_sha256") if git_diff_data else None,
                }
            ],
            "accepted_decisions": [f"Verification {verif['verdict']} for {operation_id}"],
        },
    )

    return {
        **apply_result,
        "confirmed": True,
        "task_id": task_id,
        "verification": {
            "mode": verif["mode"],
            "exit_code": verif["exit_code"],
            "verdict": verif["verdict"],
            "job_id": verif.get("job_id"),
        },
        "artifacts": {
            "test": test_artifact,
            "git_diff": diff_artifact,
        },
        "git_diff_sha256": git_diff_data.get("diff_sha256") if git_diff_data else None,
        "checkpoint": final_ckpt,
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="edge_project_bridge")
    parser.add_argument("--state-dir", type=Path, default=default_state())
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("install", help="Initialize the owner-protected control directory.")
    broker = commands.add_parser("start", help="Start the authenticated loopback broker in the foreground.")
    broker.add_argument("--port", type=int, default=0, choices=range(0, 65536), metavar="PORT")
    commands.add_parser("stop", help="Stop the authenticated instance without terminating by PID.")
    diagnose = commands.add_parser("doctor", help="Report layered runner, ACL, MCP, and tunnel diagnostics without starting jobs.")
    diagnose.add_argument("--account", action="store_true", help="Read subscription, usage flags and model metadata.")
    diagnose.add_argument("--json", action="store_true", help="Output JSON report (default).")
    diagnose.add_argument("--probe-mcp", action="store_true", help="Run a local MCP stdio handshake + bridge_info probe.")
    diagnose.add_argument("--profile", type=Path, help="Inspect a tunnel profile YAML/script without revealing secrets.")
    diagnose.add_argument("--tunnel-health-url", help="Probe a loopback HTTP(S) tunnel health URL (127.0.0.1/localhost only).")
    diagnose.add_argument("--support-bundle", action="store_true", help="Build a redacted support packet for upstream errors.")
    diagnose.add_argument("--symptom", help="Classify a host or connector error message in the diagnostic output.")
    diagnose.add_argument("--e2e-isolated", action="store_true", help="Run an isolated local MCP-to-Broker E2E verification without touching live state.")
    diagnose.add_argument("--e2e-project-id", help="Optional granted project ID for read-only E2E probe with --probe-mcp.")
    diagnose.add_argument("--e2e-file", help="Optional relative file path for read-only file_read probe with --probe-mcp.")
    diagnose.add_argument("--e2e-task-id", help="Optional task ID for project_resume probe with --probe-mcp.")
    commands.add_parser("uninstall", help="Stop the user-started process, preserving all local files and state.")
    commands.add_parser("catalog", help="Print current MCP tool descriptions and schemas.")
    for name in ("grant-edge", "revoke-edge"):
        command = commands.add_parser(name)
        command.add_argument("project_id")
    edge_ws = commands.add_parser(
        "grant-edge-workspace",
        help="Explicitly grant scoped write/checkpoint/MXC-execute capabilities to edge on a dedicated sandbox workspace (e.g., web GPT).",
    )
    edge_ws.add_argument("project_id")
    edge_ws.add_argument("--allow-write", action="store_true", help="Permit hash-checked file_write/file_patch strictly inside this workspace.")
    edge_ws.add_argument("--allow-checkpoint", action="store_true", help="Permit task_checkpoint inside this workspace.")
    edge_ws.add_argument("--allow-execute", action="store_true", help="Permit approved MXC sandboxed test jobs and redacted job_output inside this workspace.")
    edge_ws.add_argument("--expires-at", help="Optional UTC ISO-8601 expiration timestamp for this grant.")
    rep_audit = commands.add_parser(
        "report-audit",
        help="Generate a redacted Markdown + JSON audit report for an approved project and save it into the web GPT workspace.",
    )
    rep_audit.add_argument("project_id", help="Target project ID to inspect/audit.")
    rep_audit.add_argument("--report-workspace", required=True, help="Project ID of the dedicated web GPT report workspace.")
    rep_audit.add_argument("--subdir", default="reports", help="Subdirectory inside the report workspace (default: reports).")
    rep_audit.add_argument("--run-tests", action="store_true", help="Run owner-granted MXC tests on the target project.")
    rep_audit.add_argument("--recipe", default="project_tests", choices=("project_tests", "node_tests", "calculator"))
    rep_audit.add_argument("--notes", default="")
    for runtime in ("python", "node", "powershell"):
        test_grant = commands.add_parser(f"grant-{runtime}-tests", help="Approve specific files for local offline jobs.")
        test_grant.add_argument("project_id")
        test_grant.add_argument("files", nargs="+")
        commands.add_parser(f"revoke-{runtime}-tests", help="Revoke a local runtime grant.").add_argument("project_id")
    ps_grant = commands.add_parser("grant-powershell", help="Approve specific .ps1 files for isolated PowerShell runs.")
    ps_grant.add_argument("project_id")
    ps_grant.add_argument("files", nargs="+")
    commands.add_parser("revoke-powershell", help="Revoke approved PowerShell files.").add_argument("project_id")
    exec_policy = commands.add_parser("set-exec-policy", help="Adjust project execution limits (max_files, max_total_bytes, allow_git).")
    exec_policy.add_argument("project_id")
    exec_policy.add_argument("--max-files", type=int, default=32)
    exec_policy.add_argument("--max-total-bytes", type=int, default=524_288)
    exec_policy.add_argument("--disable-git", action="store_true")
    project = commands.add_parser("register", help="Approve a specific existing project folder.")
    project.add_argument("root", type=Path)
    project.add_argument("--name", required=True)
    artifact = commands.add_parser("record-artifact", help="Register a hash-checked reference to an existing project file.")
    artifact.add_argument("project_id")
    artifact.add_argument("task_id")
    artifact.add_argument("path")
    recovery = commands.add_parser("patch-recovery", help="Inspect a local patch receipt or restore a displaced original.")
    recovery.add_argument("project_id")
    recovery.add_argument("receipt_id")
    recovery.add_argument("--restore", action="store_true")
    apply_job = commands.add_parser("apply-job-changes", help="Approve selected sealed changes by SHA-256.")
    apply_job.add_argument("project_id")
    apply_job.add_argument("job_id")
    apply_job.add_argument("--operation-id", required=True)
    apply_job.add_argument("--select", action="append", nargs=2, metavar=("PATH", "SHA256"), required=True)
    patch_plan = commands.add_parser("apply-patch-plan", help="Preview, confirm, apply, and optionally verify a hash-checked patch plan as local owner.")
    patch_plan.add_argument("project_id")
    patch_plan.add_argument("--operation-id", help="Unique operation ID (can also be supplied inside the JSON patch plan).")
    patch_plan.add_argument("--task-id", help="Optional task ID for checkpoint and verification artifacts.")
    patch_plan.add_argument("--json", help="Inline JSON string or path to a JSON patch plan file.")
    patch_plan.add_argument("--paste", action="store_true", help="Interactively paste patch plan JSON on stdin (terminate with EOF line).")
    patch_plan.add_argument("--confirm", action="store_true", help="Explicitly confirm applying the previewed patch plan (required for non-TTY).")
    patch_plan.add_argument("--verify", action="store_true", help="Run post-apply verification tests and record test + git_diff artifacts.")
    patch_plan.add_argument("--no-verify", action="store_true", help="Skip verification even if the patch plan specifies verification_command.")
    patch_plan.add_argument(
        "--verify-recipe",
        choices=("project_tests", "calculator", "node_tests", "powershell_script"),
        default="project_tests",
        help="MXC recipe to use when --verify runs against an approved test scope.",
    )
    patch_plan.add_argument("--verify-cmd", help="Explicit local owner verification command (JSON argv list or command string).")
    patch_plan.add_argument(
        "--allow-host-verify",
        action="store_true",
        help="Allow unsandboxed host execution of a plan verification_command when no MXC scope applies.",
    )
    patch_plan.add_argument("--artifact-dir", default="bridge_artifacts", help="Project-relative directory for verification artifacts.")

    mcaps = commands.add_parser("model-capabilities", help="Inspect or record dynamic per-model/surface capabilities.")
    mcaps.add_argument("--model", help="Filter by or record for a specific model ID (e.g. 'GPT-6 Pro', 'Extra High').")
    mcaps.add_argument("--surface", help="Filter by or record for a surface (e.g. 'chatgpt_web_edge', 'local_codex_cli').")
    mcaps.add_argument("--record", action="store_true", help="Record an observed capability map into SQLite.")
    mcaps.add_argument("--caps-json", help="JSON object of capability booleans for --record.")
    mcaps.add_argument("--source", default="cli_observation", help="Observation source label for --record.")
    mcaps.add_argument("--notes", default="", help="Optional observation notes for --record.")
    mcaps.add_argument("--no-merge", action="store_true", help="Replace existing capability keys instead of merging.")
    mcaps.add_argument("--principal", choices=("local", "edge"), default="local", help="Effective principal view when listing.")

    fb = commands.add_parser("fallback-plan", help="Compute an authorized local Codex/CLI fallback plan for a project/model.")
    fb.add_argument("project_id")
    fb.add_argument("--task-id")
    fb.add_argument("--model")
    fb.add_argument("--surface")
    fb.add_argument("--operation-id", default="fallback-op-1")
    fb.add_argument("--require", default="file_write,command_exec", help="Comma-separated required capabilities.")
    fb.add_argument("--principal", choices=("edge", "local"), default="edge")

    rel_create = commands.add_parser("release-create", help="Create a verified code + SQLite snapshot in the sibling releases directory.")
    rel_create.add_argument("--releases-dir", type=Path)
    rel_create.add_argument("--package-root", type=Path, default=Path(__file__).resolve().parents[1])
    rel_create.add_argument("--profile", type=Path)
    rel_create.add_argument("--notes", default="")

    rel_list = commands.add_parser("release-list", help="List recorded release snapshots and pointers.")
    rel_list.add_argument("--releases-dir", type=Path)

    rel_up = commands.add_parser("upgrade", help="Snapshot current state, apply code from source_dir, verify, or auto-rollback.")
    rel_up.add_argument("source_dir", type=Path)
    rel_up.add_argument("--releases-dir", type=Path)
    rel_up.add_argument("--package-root", type=Path, default=Path(__file__).resolve().parents[1])
    rel_up.add_argument("--profile", type=Path)
    rel_up.add_argument("--no-auto-rollback", action="store_true")
    rel_up.add_argument("--no-probe", action="store_true")

    rel_rb = commands.add_parser("rollback", help="Roll back code (and corrupt/incompatible DB) to a verified release snapshot.")
    rel_rb.add_argument("--release-id")
    rel_rb.add_argument("--releases-dir", type=Path)
    rel_rb.add_argument("--package-root", type=Path, default=Path(__file__).resolve().parents[1])
    rel_rb.add_argument("--restore-db", action="store_true")
    rel_rb.add_argument("--no-verify", action="store_true")

    rel_rec = commands.add_parser("recover", help="Recover from broken MCP/pointers using the latest verified good snapshot.")
    rel_rec.add_argument("--releases-dir", type=Path)
    rel_rec.add_argument("--package-root", type=Path, default=Path(__file__).resolve().parents[1])
    rel_rec.add_argument("--restore-db", action="store_true")
    rel_rec.add_argument("--no-verify", action="store_true")
    stop_all = commands.add_parser("stop-all", help="Immediately cancel any running job and inspect worker readiness.")
    stop_all.add_argument("--reason", default="operator_stop_all")
    backup = commands.add_parser("backup", help="Create a verified SQLite backup outside the state directory and projects.")
    backup.add_argument("target_path", type=Path)
    incident = commands.add_parser("record-incident", help="Record and classify an upstream connector or host incident.")
    incident.add_argument("--source", required=True)
    incident.add_argument("--category", required=True)
    incident.add_argument("--summary", required=True)
    incident.add_argument("--http-status", type=int)
    incident.add_argument("--details-json")
    wstatus = commands.add_parser("worker-status", help="Inspect P1 worker profiles, host resource admission, and readiness.")
    wstatus.add_argument("--project-id")
    wstatus.add_argument("--record-sample", action="store_true")
    dash = commands.add_parser("dashboard", help="Run the loopback-only authenticated Workstation Dashboard (127.0.0.1).")
    dash.add_argument("--port", type=int, default=8765, choices=range(0, 65536), metavar="PORT")
    cpack = commands.add_parser("context-pack", help="Build or resume a compact model-agnostic Context Pack for a task.")
    cpack.add_argument("project_id")
    cpack.add_argument("task_id")
    cpack.add_argument("--model", default="GPT-6 Pro")
    cpack.add_argument("--build", action="store_true", help="Force building and saving a new Context Pack revision.")
    cpack.add_argument("--completed-step", action="append", default=[], help="Mark a step as completed in the Context Pack.")
    cpack.add_argument("--next-action", action="append", default=[], help="Specify remaining next action(s).")
    cli = commands.add_parser("call", help="Invoke a bridge tool through the local owner IPC.")
    cli.add_argument("tool", choices=sorted(READ_TOOLS | MUTATION_TOOLS))
    cli.add_argument("--json", help="Arguments as JSON. If omitted and piped, reads JSON on stdin.")
    mcp = commands.add_parser("mcp", help="Run a stdio MCP adapter against the existing broker.")
    mcp.add_argument("--principal", choices=("local", "edge"), required=True)
    args = parser.parse_args()
    state: Path = args.state_dir.absolute()

    try:
        if args.command == "install":
            setup_state(state)
            result = {"state_directory": str(state), "service_registered": False}
        elif args.command == "start":
            run_broker(state, args.port)
            return 0
        elif args.command == "mcp":
            import anyio
            from .mcp_server import serve_stdio

            anyio.run(serve_stdio, state, args.principal)
            return 0
        elif args.command == "doctor":
            if args.e2e_isolated:
                result = diagnostics.run_isolated_e2e_probe()
                print(json.dumps(result, ensure_ascii=True, indent=2))
                return 0 if result.get("overall_status") == "PASS" else 1
            if args.support_bundle:
                result = diagnostics.build_support_packet(
                    state,
                    incident_note=args.symptom,
                    probe_mcp=args.probe_mcp,
                )
            else:
                layered = diagnostics.run_doctor(
                    state,
                    account=args.account,
                    probe_mcp=args.probe_mcp,
                    profile_path=args.profile,
                    tunnel_health_url=args.tunnel_health_url,
                    verify_acl_fn=verify_state_path,
                    e2e_project_id=args.e2e_project_id,
                    e2e_file=args.e2e_file,
                    e2e_task_id=args.e2e_task_id,
                )
                result = {
                    "state_directory": str(state),
                    "runner": runner.diagnose(),
                    "broker": layered["broker"],
                    "diagnostics": layered,
                }
                if layered.get("account") is not None:
                    result["account"] = layered["account"]
                if args.symptom:
                    result["symptom_classification"] = diagnostics.classify_host_error(args.symptom)
        elif args.command == "catalog":
            from .mcp_server import TOOL_SPECS

            result = {name: spec.schema(name).model_dump(exclude_none=True) for name, spec in TOOL_SPECS.items()}
        elif args.command == "register":
            result = call_broker(state, "local", "owner_register", {"root": str(args.root), "name": args.name})
        elif args.command in {"grant-edge", "revoke-edge"}:
            action = "owner_grant_edge" if args.command == "grant-edge" else "owner_revoke_edge"
            result = call_broker(state, "local", action, {"project_id": args.project_id})
        elif args.command == "grant-edge-workspace":
            caps = ["read"]
            if args.allow_write:
                caps.append("write")
            if args.allow_checkpoint:
                caps.append("checkpoint")
            if args.allow_execute:
                caps.append("execute")
            payload = {"project_id": args.project_id, "capabilities": caps}
            if args.expires_at:
                payload["expires_at"] = args.expires_at
            result = call_broker(state, "local", "owner_grant_edge_scoped", payload)
        elif args.command == "report-audit":
            from .report_engine import generate_project_audit_report

            result = generate_project_audit_report(
                state,
                args.project_id,
                args.report_workspace,
                report_subdir=args.subdir,
                run_tests=args.run_tests,
                test_recipe=args.recipe,
                notes=args.notes,
            )
        elif args.command in {"grant-python-tests", "grant-node-tests", "grant-powershell-tests", "grant-powershell"}:
            action = "owner_grant_powershell_tests" if args.command == "grant-powershell" else "owner_" + args.command.replace("-", "_")
            result = call_broker(state, "local", action, {
                "project_id": args.project_id, "files": args.files,
            })
        elif args.command in {"revoke-python-tests", "revoke-node-tests", "revoke-powershell-tests", "revoke-powershell"}:
            action = "owner_revoke_powershell_tests" if args.command == "revoke-powershell" else "owner_" + args.command.replace("-", "_")
            result = call_broker(state, "local", action, {"project_id": args.project_id})
        elif args.command == "set-exec-policy":
            result = call_broker(state, "local", "owner_set_exec_policy", {
                "project_id": args.project_id,
                "max_files": args.max_files,
                "max_total_bytes": args.max_total_bytes,
                "allow_git": not args.disable_git,
            })
        elif args.command == "record-artifact":
            result = call_broker(state, "local", "owner_record_artifact", {
                "project_id": args.project_id, "task_id": args.task_id, "path": args.path,
            })
        elif args.command == "patch-recovery":
            result = call_broker(state, "local", "owner_patch_recovery", {
                "project_id": args.project_id, "receipt_id": args.receipt_id, "restore": args.restore,
            })
        elif args.command == "apply-job-changes":
            result = call_broker(state, "local", "owner_apply_job_changes", {
                "project_id": args.project_id, "job_id": args.job_id, "operation_id": args.operation_id,
                "selection": [{"path": path, "output_sha256": digest} for path, digest in args.select],
            })
        elif args.command == "apply-patch-plan":
            result = _run_apply_patch_plan(state, args)
        elif args.command == "model-capabilities":
            result = _run_model_capabilities(state, args)
        elif args.command == "fallback-plan":
            result = _run_fallback_plan(state, args)
        elif args.command == "release-create":
            result = releases.create_release(
                state,
                args.package_root,
                releases_dir=args.releases_dir,
                profile_path=args.profile,
                notes=args.notes,
            )
        elif args.command == "release-list":
            result = releases.list_releases(state, releases_dir=args.releases_dir)
        elif args.command == "upgrade":
            result = releases.upgrade_from_directory(
                state,
                args.package_root,
                args.source_dir,
                releases_dir=args.releases_dir,
                profile_path=args.profile,
                run_probe=not args.no_probe,
                auto_rollback=not args.no_auto_rollback,
            )
            print(json.dumps(result, ensure_ascii=True, indent=2))
            return 0 if result.get("upgraded") else 1
        elif args.command == "rollback":
            result = releases.rollback_release(
                state,
                args.package_root,
                target_release_id=args.release_id,
                releases_dir=args.releases_dir,
                restore_db=args.restore_db,
                verify=not args.no_verify,
            )
        elif args.command == "recover":
            result = releases.recover_bridge(
                state,
                args.package_root,
                releases_dir=args.releases_dir,
                restore_db=args.restore_db,
                verify=not args.no_verify,
            )
        elif args.command == "stop-all":
            result = call_broker(state, "local", "owner_stop_all", {"reason": args.reason})
        elif args.command == "backup":
            result = call_broker(state, "local", "owner_backup", {"target_path": str(args.target_path.absolute())})
        elif args.command == "record-incident":
            details = json.loads(args.details_json) if args.details_json else None
            result = call_broker(state, "local", "owner_record_incident", {
                "source": args.source,
                "category": args.category,
                "summary": args.summary,
                "http_status": args.http_status,
                "details": details,
            })
        elif args.command == "worker-status":
            if args.project_id and not args.record_sample:
                result = call_broker(state, "local", "worker_list", {"project_id": args.project_id})
            else:
                verify_state_path(state)
                store = State(state / "state.sqlite3")
                result = WorkerManager(store).status(
                    project_id=args.project_id, principal="local", record_sample=args.record_sample,
                )
        elif args.command == "dashboard":
            from .dashboard import DashboardServer
            srv = DashboardServer(state, host="127.0.0.1", port=args.port)
            print(f"Edge Project Bridge Dashboard ready on {srv.url}", flush=True)
            try:
                srv.server.serve_forever(poll_interval=0.1)
            finally:
                srv.stop()
            return 0
        elif args.command == "context-pack":
            from .context_packs import ContextPackManager
            verify_state_path(state)
            store = State(state / "state.sqlite3")
            mgr = ContextPackManager(store)
            if args.build or args.completed_step or args.next_action:
                mgr.build_and_save(
                    args.project_id,
                    args.task_id,
                    principal="local",
                    completed_steps=args.completed_step or None,
                    next_actions=args.next_action or None,
                )
            result = mgr.resume_from_pack(args.project_id, args.task_id, principal="local", model_id=args.model)
        elif args.command in {"stop", "uninstall"}:
            try:
                result = call_broker(state, "local", "owner_stop")
            except BridgeError as failure:
                if args.command != "uninstall" or failure.code != "BROKER_OFFLINE":
                    raise
                result = {"stopping": False}
            if args.command == "uninstall":
                result["retained_state"] = str(state)
        else:
            raw = args.json if args.json is not None else ("{}" if sys.stdin.isatty() else sys.stdin.read(1_572_865))
            values = json.loads(raw or "{}")
            if not isinstance(values, dict):
                raise BridgeError("INVALID_ARGUMENT", "Tool arguments must be a JSON object.")
            result = call_broker(state, "local", args.tool, values)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(json.dumps(error_payload(error), ensure_ascii=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

