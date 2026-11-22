"""P3 Model-Agnostic Compact Context Packs backed by SQLite and live project file hashes."""

from __future__ import annotations

import json
from typing import Any

from .files import FileBoundaryError, ProjectFiles
from .state import State

MAX_CONTEXT_PACK_BYTES = 16_384


class ContextPackManager:
    """Builds and resumes compact, model-agnostic Context Packs without hidden reasoning or step repetition."""

    def __init__(self, store: State):
        self.store = store

    def build_and_save(
        self,
        project_id: str,
        task_id: str,
        *,
        principal: str = "local",
        completed_steps: list[str] | None = None,
        next_actions: list[str] | None = None,
        failure_evidence: list[dict[str, Any]] | None = None,
        recovery_instructions: list[str] | None = None,
    ) -> dict[str, Any]:
        project = self.store.get_project(project_id, principal, "read")
        resumed = self.store.resume(project_id, principal, task_id)
        task_detail = self.store.get_task(project_id, principal, task_id)
        deps = self.store.list_task_dependencies(project_id, principal, task_id)
        queue_items = [
            q for q in self.store.list_task_queue(project_id=project_id, principal=principal)
            if q["task_id"] == task_id or q["task_id"] in deps
        ]
        verifications = self.store.list_verification(project_id, principal)[:10]

        # Re-verify changed file hashes directly from project files on disk
        changed_file_hashes: list[dict[str, Any]] = []
        if "root" in project and "root_identity" in project:
            pf = ProjectFiles(project["root"], project["root_identity"])
            for entry in resumed.get("changed_files") or []:
                rel_path = entry.get("path") if isinstance(entry, dict) else str(entry)
                if not rel_path:
                    continue
                try:
                    info = pf.read(rel_path, limit=1)
                    changed_file_hashes.append({"path": rel_path, "sha256": info["hash"], "size": info["size"]})
                except FileBoundaryError as exc:
                    changed_file_hashes.append({"path": rel_path, "sha256": None, "status": exc.code})
        else:
            for entry in resumed.get("changed_files") or []:
                if isinstance(entry, dict) and entry.get("path"):
                    changed_file_hashes.append({"path": entry["path"], "sha256": entry.get("sha256")})

        prev_pack = self.store.get_latest_context_pack(project_id, principal, task_id)
        prior_completed = (prev_pack["pack"].get("completed_steps") if prev_pack else []) or []
        merged_completed: list[str] = list(dict.fromkeys([*prior_completed, *(completed_steps or [])]))

        raw_next = next_actions if next_actions is not None else (
            [resumed["next_action"]] if resumed.get("next_action") else []
        )
        # Filter out any step already in merged_completed so resumed sessions never repeat completed work
        remaining_actions = [step for step in raw_next if step and step not in merged_completed]

        worker_progress = [
            {
                "queue_id": q["queue_id"],
                "task_id": q["task_id"],
                "role": q["role"],
                "status": q["status"],
                "worker_id": q["worker_id"],
            }
            for q in queue_items[:20]
        ]

        test_results = [
            {
                "check_id": v["check_id"],
                "verdict": v["verdict"],
                "evidence": str(v["evidence"])[:240],
                "model": v.get("model"),
                "created_at": v["created_at"],
            }
            for v in verifications
        ]
        for ev in resumed.get("test_evidence") or []:
            if isinstance(ev, dict):
                test_results.append(ev)

        failures = list(failure_evidence or [])
        for job in task_detail.get("jobs") or []:
            if job.get("status") in {"failed", "timed_out", "unknown_after_restart"}:
                failures.append(
                    {
                        "job_id": job["id"],
                        "status": job["status"],
                        "exit_code": job.get("exit_code"),
                    }
                )

        default_recovery = recovery_instructions or [
            "Call project_resume and task_get to inspect latest checkpoint_revision and changed_file_hashes.",
            "If the current ChatGPT model lacks write/exec tools, run fallback-plan and apply-patch-plan locally.",
            "If an MCP update broke stdio connectivity, run scripts/recover-bridge.ps1 or cli rollback.",
        ]

        pack = {
            "pack_format": "edge-context-pack/v1",
            "model_agnostic": True,
            "hidden_reasoning_included": False,
            "project_identity": {
                "instance_id": resumed["instance_id"],
                "project_id": project_id,
                "display_name": project["display_name"],
                "policy_revision": project["policy_revision"],
                "policy_hash": project["policy_hash"],
            },
            "task_id": task_id,
            "active_objective": resumed.get("objective") or task_detail.get("objective") or "",
            "accepted_decisions": list(resumed.get("accepted_decisions") or [])[:25],
            "task_dependencies": deps,
            "worker_progress": worker_progress,
            "changed_file_hashes": changed_file_hashes,
            "test_results": test_results[:15],
            "failure_evidence": failures[:10],
            "recovery_instructions": default_recovery[:10],
            "completed_steps": merged_completed,
            "next_actions": remaining_actions,
            "checkpoint_revision": resumed.get("checkpoint_revision", 0),
        }

        encoded = json.dumps(pack, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_CONTEXT_PACK_BYTES:
            pack["test_results"] = pack["test_results"][:5]
            pack["worker_progress"] = pack["worker_progress"][:8]

        saved = self.store.save_context_pack(project_id, principal, task_id, pack)
        if principal != "local":
            saved["pack"]["project_identity"].pop("root", None)
        return saved

    def resume_from_pack(
        self,
        project_id: str,
        task_id: str,
        *,
        principal: str = "local",
        model_id: str | None = None,
    ) -> dict[str, Any]:
        latest = self.store.get_latest_context_pack(project_id, principal, task_id)
        if latest is None:
            latest = self.build_and_save(project_id, task_id, principal=principal)
        pack = latest["pack"]
        return {
            "resumed": True,
            "target_model": model_id or "GPT-6 Pro",
            "revision": latest["revision"],
            "pack_sha256": latest["pack_sha256"],
            "skip_completed_steps": pack.get("completed_steps", []),
            "next_actions": pack.get("next_actions", []),
            "context_pack": pack,
        }
