"""Automated, secret-redacted project audit and report generator targeting the dedicated web GPT workspace."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any

from . import diagnostics
from .broker import BridgeError, call_broker


_SAFE_SLUG = re.compile(r"[^a-zA-Z0-9._-]+")


def _slug(value: str) -> str:
    cleaned = _SAFE_SLUG.sub("-", value.strip()).strip("-._")
    return (cleaned or "project")[:48]


def _utc_stamp() -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y%m%dT%H%M%SZ"), now.isoformat(timespec="seconds")


def generate_project_audit_report(
    state: Path,
    target_project_id: str,
    report_workspace_project_id: str,
    *,
    report_subdir: str = "reports",
    run_tests: bool = False,
    test_recipe: str = "project_tests",
    notes: str = "",
) -> dict[str, Any]:
    """Collect live Git/file/test evidence for target_project_id and write a redacted report into web GPT."""
    stamp_compact, stamp_iso = _utc_stamp()
    t0 = time.perf_counter()

    target_status = call_broker(state, "local", "project_status", {"project_id": target_project_id})
    proj_meta = target_status["project"]
    display_name = str(proj_meta.get("display_name") or target_project_id)
    slug = _slug(display_name)

    listing = call_broker(
        state,
        "local",
        "file_list",
        {"project_id": target_project_id, "path": ".", "recursive": True, "max_depth": 3, "limit": 100},
    )
    entries = listing.get("entries", [])
    dir_count = sum(1 for e in entries if e.get("type") == "directory")
    file_count = sum(1 for e in entries if e.get("type") == "file")

    git_status: dict[str, Any] | None = None
    git_diff_meta: dict[str, Any] | None = None
    try:
        git_status = call_broker(state, "local", "git_status", {"project_id": target_project_id, "max_entries": 100})
        diff_res = call_broker(state, "local", "git_diff", {"project_id": target_project_id, "offset": 0, "limit": 8192})
        git_diff_meta = {
            "total_bytes": diff_res.get("total_bytes", 0),
            "total_chars": diff_res.get("total_chars", 0),
            "diff_sha256": diff_res.get("diff_sha256"),
            "truncated": diff_res.get("truncated", False),
            "preview": diagnostics.redact_text(str(diff_res.get("content") or ""))[:3000],
        }
    except BridgeError as exc:
        git_status = {"available": False, "reason": exc.code}

    test_evidence: dict[str, Any] | None = None
    if run_tests:
        recipe_map = {
            "project_tests": ("python", ["-B", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"], "python_test_scope"),
            "node_tests": ("node", ["--test", "--test-concurrency=1", "tests/*.test.mjs"], "node_test_scope"),
            "calculator": ("python", ["-B", "-m", "unittest", "-v"], None),
        }
        spec = recipe_map.get(test_recipe)
        if spec is None:
            raise BridgeError("INVALID_ARGUMENT", f"Unsupported report test_recipe: {test_recipe}")
        exe, argv, scope_key = spec
        if scope_key is not None and not target_status.get(scope_key):
            test_evidence = {
                "ran": False,
                "verdict": "SKIPPED_NO_TEST_SCOPE",
                "recipe": test_recipe,
                "reason": f"No owner-granted {scope_key} configured on {target_project_id}.",
            }
        else:
            op_id = f"audit-test-{stamp_compact}-{hashlib.sha256(target_project_id.encode()).hexdigest()[:6]}"
            job_resp = call_broker(
                state,
                "local",
                "process_start",
                {
                    "project_id": target_project_id,
                    "task_id": f"audit-{slug}"[:64],
                    "operation_id": op_id,
                    "executable": exe,
                    "argv": argv,
                    "cwd_relative": ".",
                    "timeout_seconds": 60,
                },
            )
            job_id = job_resp["job_id"]
            deadline = time.monotonic() + 65.0
            jstate = job_resp
            while time.monotonic() < deadline:
                jstate = call_broker(state, "local", "job_get", {"project_id": target_project_id, "job_id": job_id})
                if jstate["status"] in {"succeeded", "failed", "timed_out", "cancelled"}:
                    break
                time.sleep(0.1)
            jout = call_broker(
                state, "local", "job_output", {"project_id": target_project_id, "job_id": job_id, "cursor": 0, "limit": 8192},
            )
            test_evidence = {
                "ran": True,
                "recipe": test_recipe,
                "job_id": job_id,
                "status": jstate.get("status"),
                "exit_code": jstate.get("exit_code"),
                "verdict": "PASS" if jstate.get("status") == "succeeded" and jstate.get("exit_code") == 0 else "FAIL",
                "output_redacted": diagnostics.redact_text(str(jout.get("output") or ""))[:4000],
            }

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    report_obj = {
        "report_type": "edge_project_bridge_audit",
        "generated_at_utc": stamp_iso,
        "duration_ms": elapsed_ms,
        "target_project": {
            "project_id": target_project_id,
            "display_name": display_name,
            "policy_revision": proj_meta.get("policy_revision"),
            "policy_hash": proj_meta.get("policy_hash"),
        },
        "inventory_sample": {
            "directories_listed": dir_count,
            "files_listed": file_count,
            "scan_truncated": bool(listing.get("scan_truncated")),
            "top_entries": [e.get("name") for e in entries[:25]],
        },
        "git_status": git_status,
        "git_diff_summary": git_diff_meta,
        "test_evidence": test_evidence,
        "notes": diagnostics.redact_text(notes)[:1000] if notes else "",
    }

    md_lines = [
        f"# Project Audit Report — {display_name}",
        "",
        f"- **Generated (UTC):** `{stamp_iso}`",
        f"- **Target Project ID:** `{target_project_id}`",
        f"- **Audit Duration:** `{elapsed_ms} ms`",
        f"- **Inventory Sample (depth<=3):** `{file_count}` files, `{dir_count}` directories (`truncated={bool(listing.get('scan_truncated'))}`)",
    ]
    if isinstance(git_status, dict) and git_status.get("available", True) is not False:
        md_lines.extend([
            f"- **Git Branch:** `{git_status.get('branch')}` (`head={git_status.get('head')}`)",
            f"- **Git Clean:** `{git_status.get('clean')}` (`entries={git_status.get('entry_count', 0)}`)",
        ])
    else:
        md_lines.append(f"- **Git:** `{git_status.get('reason') if isinstance(git_status, dict) else 'unavailable'}`")
    if test_evidence is not None:
        md_lines.extend([
            "",
            "## Sandboxed MXC Test Verification",
            f"- **Recipe:** `{test_evidence.get('recipe')}`",
            f"- **Verdict:** `{test_evidence.get('verdict')}` (`exit_code={test_evidence.get('exit_code')}`)",
        ])
        if test_evidence.get("output_redacted"):
            md_lines.extend(["```text", test_evidence["output_redacted"], "```"])
    if git_diff_meta and git_diff_meta.get("preview"):
        md_lines.extend([
            "",
            f"## Git Diff Preview (`total_bytes={git_diff_meta['total_bytes']}`, `sha256={git_diff_meta['diff_sha256']}`)",
            "```diff",
            git_diff_meta["preview"],
            "```",
        ])
    if report_obj["notes"]:
        md_lines.extend(["", "## Notes", report_obj["notes"]])

    md_text = "\n".join(md_lines).strip() + "\n"
    json_text = json.dumps(report_obj, ensure_ascii=False, indent=2) + "\n"

    clean_sub = report_subdir.strip("/\\") or "reports"
    base_name = f"{stamp_compact}_{slug}_audit"
    md_rel = f"{clean_sub}/{base_name}.md"
    json_rel = f"{clean_sub}/{base_name}.json"

    md_write = call_broker(
        state,
        "local",
        "file_write",
        {
            "project_id": report_workspace_project_id,
            "operation_id": f"rep-md-{stamp_compact}-{hashlib.sha256(md_rel.encode()).hexdigest()[:6]}",
            "path": md_rel,
            "content": md_text,
            "expected_hash": None,
        },
    )
    json_write = call_broker(
        state,
        "local",
        "file_write",
        {
            "project_id": report_workspace_project_id,
            "operation_id": f"rep-js-{stamp_compact}-{hashlib.sha256(json_rel.encode()).hexdigest()[:6]}",
            "path": json_rel,
            "content": json_text,
            "expected_hash": None,
        },
    )
    return {
        "ok": True,
        "target_project_id": target_project_id,
        "report_workspace_project_id": report_workspace_project_id,
        "markdown_report": {"path": md_rel, "hash": md_write["hash"], "size": md_write["size"]},
        "json_report": {"path": json_rel, "hash": json_write["hash"], "size": json_write["size"]},
        "test_verdict": test_evidence.get("verdict") if test_evidence else None,
        "duration_ms": elapsed_ms,
    }
