"""P1 Multi-Agent Orchestrator: DAG scheduler, adaptive concurrency, isolated workspaces, mock/MXC lifecycle, and serial integration."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import shutil
import threading
import time
from typing import Any, Callable
from uuid import uuid4

from . import runner
from .files import FileBoundaryError, ProjectFiles
from .git_engine import GitEngine, GitEngineError
from .state import State, StateError
from .worker_account import AccountObservation, IncludedOnlyPolicy, evaluate_included_only
from .workers import (
    WorkerError,
    build_worker_isolation_spec,
    check_resource_admission,
    sample_host_resources,
)

HEAVY_ROLES = frozenset({"tester", "integrator"})
VALID_ROLES = frozenset({
    "planner",
    "explorer",
    "coder",
    "tester",
    "reviewer",
    "security_reviewer",
    "researcher",
    "integrator",
})


@dataclass
class ActiveWorkerHandle:
    worker_id: str
    queue_id: str
    project_id: str
    task_id: str
    role: str
    workspace_path: Path
    cancel_event: threading.Event = field(default_factory=threading.Event)
    stop_reason: str | None = None


class GlobalConcurrencyManager:
    """Adaptive concurrency controller (1 -> 2 -> gradual scale) with heavy-build cap and rate-limit backoff."""

    def __init__(
        self,
        *,
        initial_limit: int = 1,
        max_limit: int = 4,
        max_heavy_workers: int = 1,
        max_queue_per_project: int = 32,
    ):
        self.lock = threading.RLock()
        self.current_limit = max(1, initial_limit)
        self.max_limit = max(self.current_limit, max_limit)
        self.max_heavy_workers = max(1, max_heavy_workers)
        self.max_queue_per_project = max(1, max_queue_per_project)
        self.consecutive_successes = 0
        self.backoff_until: float = 0.0
        self.last_backoff_reason: str | None = None

    def record_rate_limit(self, retry_after_seconds: float = 10.0, reason: str = "rate_limit_429") -> dict[str, Any]:
        with self.lock:
            now = time.monotonic()
            self.backoff_until = max(self.backoff_until, now + max(1.0, float(retry_after_seconds)))
            self.current_limit = 1
            self.consecutive_successes = 0
            self.last_backoff_reason = reason
            return {
                "current_limit": self.current_limit,
                "backoff_active": True,
                "retry_after_seconds": round(self.backoff_until - now, 2),
                "reason": reason,
            }

    def record_completion(self, *, succeeded: bool, resources: dict[str, Any] | None = None) -> int:
        with self.lock:
            if not succeeded:
                self.consecutive_successes = 0
                self.current_limit = max(1, self.current_limit - 1)
                return self.current_limit
            res = resources or sample_host_resources()
            ram_ok = res.get("ram_used_percent", 0) < 80
            cpu_val = res.get("cpu_percent")
            cpu_ok = cpu_val is None or cpu_val < 80.0
            if ram_ok and cpu_ok and time.monotonic() >= self.backoff_until:
                self.consecutive_successes += 1
                # Step 1 -> 2 on first clean completion, then gradual +1 every 2 completions
                if self.current_limit == 1 and self.consecutive_successes >= 1:
                    self.current_limit = min(self.max_limit, 2)
                elif self.consecutive_successes >= 2 and self.current_limit < self.max_limit:
                    self.current_limit = min(self.max_limit, self.current_limit + 1)
                    self.consecutive_successes = 0
            return self.current_limit

    def evaluate_slot(
        self,
        store: State,
        *,
        role: str,
        active_workers: list[ActiveWorkerHandle],
    ) -> dict[str, Any]:
        with self.lock:
            now = time.monotonic()
            if now < self.backoff_until:
                return {
                    "admitted": False,
                    "code": "RATE_LIMIT_BACKOFF",
                    "reason": f"Rate-limit backoff active for {round(self.backoff_until - now, 2)}s ({self.last_backoff_reason}).",
                    "current_limit": self.current_limit,
                }
            if len(active_workers) >= self.current_limit:
                return {
                    "admitted": False,
                    "code": "CONCURRENCY_LIMIT_REACHED",
                    "reason": f"Active workers ({len(active_workers)}) reached adaptive limit ({self.current_limit}).",
                    "current_limit": self.current_limit,
                }
            if role in HEAVY_ROLES:
                heavy_count = sum(1 for w in active_workers if w.role in HEAVY_ROLES)
                if heavy_count >= self.max_heavy_workers:
                    return {
                        "admitted": False,
                        "code": "HEAVY_BUILD_LIMIT_REACHED",
                        "reason": f"Heavy worker role '{role}' capped at {self.max_heavy_workers} concurrent instance.",
                        "current_limit": self.current_limit,
                    }
            adm = check_resource_admission(store, max_concurrent_workers=self.current_limit)
            if not adm["admitted"]:
                return {
                    "admitted": False,
                    "code": "RESOURCE_PRESSURE",
                    "reason": "; ".join(adm["reasons"]),
                    "current_limit": self.current_limit,
                    "resources": adm["resources"],
                }
            return {
                "admitted": True,
                "code": "ADMITTED",
                "current_limit": self.current_limit,
                "resources": adm["resources"],
            }


class IsolatedWorkspaceManager:
    """Manages per-worker isolated workspaces (Git worktree or regular-file snapshot copy)."""

    def __init__(self, base_dir: Path, git_engine: GitEngine | None = None):
        self.base_dir = base_dir
        self.git = git_engine or GitEngine()

    def prepare_workspace(
        self,
        *,
        worker_id: str,
        project: dict[str, Any],
        file_scope: list[str],
        prefer_worktree: bool = False,
    ) -> dict[str, Any]:
        root = Path(project["root"]).resolve(strict=True)
        worker_dir = (self.base_dir / worker_id).resolve()
        try:
            worker_dir.relative_to(root)
        except ValueError:
            pass
        else:
            raise WorkerError("WORKSPACE_UNSAFE", "Worker workspace must reside outside the project root.")

        if worker_dir.exists():
            shutil.rmtree(worker_dir, ignore_errors=True)
        ws_path = worker_dir / "workspace"

        source_files = ProjectFiles(project["root"], project["root_identity"])
        baseline_hashes: dict[str, str | None] = {}
        file_contents: dict[str, str] = {}
        for rel_path in file_scope:
            try:
                read_item = source_files.read(rel_path, limit=65536)
                if read_item["truncated"]:
                    raise WorkerError("RESOURCE_BUDGET_EXCEEDED", f"Scoped file {rel_path} exceeds 64 KiB worker cap.")
                baseline_hashes[rel_path] = read_item["hash"]
                file_contents[rel_path] = read_item["content"]
            except FileBoundaryError as exc:
                if exc.code == "FILE_NOT_FOUND":
                    baseline_hashes[rel_path] = None
                else:
                    raise WorkerError(exc.code, str(exc)) from exc

        kind = "isolated_copy"
        branch_name = None
        if prefer_worktree and (root / ".git").exists():
            try:
                branch_name = f"edge-worker/{worker_id}"
                self.git.create_isolated_worktree(root, ws_path, branch_name, base_ref="HEAD")
                kind = "git_worktree"
            except GitEngineError:
                if ws_path.exists():
                    shutil.rmtree(ws_path, ignore_errors=True)
                kind = "isolated_copy"
                branch_name = None

        if kind == "isolated_copy":
            ws_path.mkdir(parents=True, exist_ok=True)
            ws_files = ProjectFiles(ws_path)
            dirs: set[str] = set()
            for rel_path in file_scope:
                parts = rel_path.split("/")[:-1]
                for idx in range(1, len(parts) + 1):
                    dirs.add("/".join(parts[:idx]))
            for d in sorted(dirs, key=lambda s: (s.count("/"), s)):
                ws_files.make_snapshot_directory(d)
            for rel_path, content in file_contents.items():
                written = ws_files.write(rel_path, content, None)
                if written["hash"] != baseline_hashes[rel_path]:
                    raise WorkerError("SNAPSHOT_MISMATCH", f"Isolated copy hash mismatch on {rel_path}.")

        return {
            "worker_id": worker_id,
            "workspace_path": str(ws_path),
            "workspace_identity": ProjectFiles.identity(ws_path),
            "isolation_kind": kind,
            "branch": branch_name,
            "file_scope": list(file_scope),
            "baseline_hashes": baseline_hashes,
        }


class AgentOrchestrator:
    """SQLite-backed multi-agent orchestrator with DAG scheduling, mock/MXC lifecycle, and serial integration."""

    def __init__(
        self,
        store: State,
        state_path: Path,
        *,
        concurrency: GlobalConcurrencyManager | None = None,
    ):
        self.store = store
        self.state_path = state_path
        self.workspaces_Root = state_path.parent / f"{state_path.name}-workers"
        self.git = GitEngine()
        self.workspace_mgr = IsolatedWorkspaceManager(self.workspaces_Root, self.git)
        self.concurrency = concurrency or GlobalConcurrencyManager()
        self.lock = threading.RLock()
        self.active_handles: dict[str, ActiveWorkerHandle] = {}

    @staticmethod
    def should_parallelize(tasks: list[dict[str, Any]]) -> dict[str, Any]:
        """Decide whether a set of candidate tasks benefits from parallel workers vs serial execution."""
        if len(tasks) <= 1:
            return {"parallel_recommended": False, "reason": "Single task does not benefit from extra agents."}
        scopes = [set(t.get("file_scope") or []) for t in tasks]
        for i in range(len(scopes)):
            for j in range(i + 1, len(scopes)):
                if scopes[i] & scopes[j]:
                    return {
                        "parallel_recommended": False,
                        "reason": f"Overlapping file_scope between tasks {tasks[i].get('task_id')} and {tasks[j].get('task_id')}.",
                    }
        return {"parallel_recommended": True, "reason": "Independent non-overlapping file scopes."}

    def submit_task(
        self,
        *,
        project_id: str,
        principal: str,
        task_id: str,
        role: str,
        objective: str,
        file_scope: list[str],
        depends_on: list[str] | None = None,
        mode: str = "mock",
        priority: int = 100,
        timeout_seconds: int = 60,
        parent_capabilities: set[str] | None = None,
    ) -> dict[str, Any]:
        if role not in VALID_ROLES:
            raise WorkerError("INVALID_ROLE", f"Unsupported worker role: {role}")
        queued = self.store.list_task_queue(project_id=project_id, principal=principal, status="queued")
        if len(queued) >= self.concurrency.max_queue_per_project:
            raise WorkerError("QUEUE_BACKPRESSURE", "Project task queue reached backpressure limit.")

        profiles = {p["name"]: p for p in self.store.list_workers(project_id=project_id, principal=principal)["profiles"]}
        profile = profiles.get(role)
        if profile is None:
            raise WorkerError("INVALID_ROLE", f"Profile '{role}' is not registered.")

        effective_parent = parent_capabilities if parent_capabilities is not None else {"read", "write", "checkpoint", "execute"}
        # Validate worker_caps <= parent_caps immediately at submission
        build_worker_isolation_spec(
            worker_id="preflight",
            project_id=project_id,
            task_id=task_id,
            profile=profile,
            parent_capabilities=effective_parent,
            workspace_path=self.workspaces_Root,
        )

        self.store.ensure_task(project_id, task_id, objective)
        for dep_id in depends_on or []:
            self.store.ensure_task(project_id, dep_id)
            self.store.add_task_dependency(project_id, task_id, dep_id)

        return self.store.enqueue_worker_task(
            project_id=project_id,
            principal=principal,
            task_id=task_id,
            role=role,
            objective=objective,
            file_scope=file_scope,
            mode=mode,
            priority=priority,
            timeout_seconds=timeout_seconds,
        )

    def resolve_runnable_tasks(self, project_id: str, principal: str = "local") -> list[dict[str, Any]]:
        """Return queued tasks whose DAG dependencies are all completed."""
        queued = self.store.list_task_queue(project_id=project_id, principal=principal, status="queued")
        all_queue = self.store.list_task_queue(project_id=project_id, principal=principal)
        succeeded_tasks = {item["task_id"] for item in all_queue if item["status"] == "succeeded"}

        runnable: list[dict[str, Any]] = []
        for item in queued:
            deps = self.store.list_task_dependencies(project_id, principal, item["task_id"])
            if all(dep in succeeded_tasks or self.store.get_task(project_id, principal, dep)["status"] == "completed" for dep in deps):
                runnable.append(item)
        return runnable

    def execute_worker_item(
        self,
        queue_item: dict[str, Any],
        *,
        principal: str = "local",
        parent_capabilities: set[str] | None = None,
        mock_handler: Callable[[Path, dict[str, Any]], dict[str, str]] | None = None,
        prefer_worktree: bool = False,
        policy: IncludedOnlyPolicy | None = None,
        observed: AccountObservation | None = None,
        now: float | None = None,
        simulate_duration_s: float = 0.0,
    ) -> dict[str, Any]:
        project_id = queue_item["project_id"]
        task_id = queue_item["task_id"]
        role = queue_item["role"]
        mode = queue_item["mode"]
        queue_id = queue_item["queue_id"]
        file_scope = queue_item["file_scope"]

        # Enforce strict INCLUDED_ONLY & MXC gate if non-mock mode is requested
        if mode != "mock":
            runner.require_workers()
            if policy is None or observed is None or now is None:
                raise WorkerError("ACCOUNT_USAGE_UNVERIFIED", "Fresh included-only account observation is required.")
            decision = evaluate_included_only(policy, observed, now=now)
            if not decision.allowed:
                raise WorkerError(decision.code, f"Blocked by INCLUDED_ONLY policy: {decision.code}")
            raise WorkerError("WORKER_CAPABILITY_NOT_VERIFIED", "Real model worker inference remains fail-closed.")

        with self.lock:
            slot = self.concurrency.evaluate_slot(
                self.store,
                role=role,
                active_workers=list(self.active_handles.values()),
            )
            if not slot["admitted"]:
                raise WorkerError(slot["code"], slot["reason"])

            project = self.store.get_project(project_id, principal, "execute")
            profiles = {p["name"]: p for p in self.store.list_workers(project_id=project_id, principal=principal)["profiles"]}
            profile = profiles[role]
            worker_id = f"worker_{uuid4().hex[:16]}"
            ws_meta = self.workspace_mgr.prepare_workspace(
                worker_id=worker_id,
                project=project,
                file_scope=file_scope,
                prefer_worktree=prefer_worktree,
            )
            ws_path = Path(ws_meta["workspace_path"])
            iso_spec = build_worker_isolation_spec(
                worker_id=worker_id,
                project_id=project_id,
                task_id=task_id,
                profile=profile,
                parent_capabilities=parent_capabilities or {"read", "write", "checkpoint", "execute"},
                workspace_path=ws_path,
            )
            handle = ActiveWorkerHandle(
                worker_id=worker_id,
                queue_id=queue_id,
                project_id=project_id,
                task_id=task_id,
                role=role,
                workspace_path=ws_path,
            )
            self.active_handles[worker_id] = handle
            self.store.create_worker_record(
                worker_id=worker_id,
                project_id=project_id,
                task_id=task_id,
                profile_name=role,
                principal=principal,
                status="running",
                workspace_ref=str(ws_path),
                verification_reason="mock_isolated_workspace",
            )
            self.store.update_queue_item(queue_id, status="running", worker_id=worker_id, increment_attempt=True)
            self.store.record_worker_event(
                worker_id,
                project_id,
                task_id,
                "started",
                {"isolation": iso_spec, "workspace": ws_meta},
            )

        started_at = time.monotonic()
        timeout_s = float(queue_item.get("timeout_seconds") or 60)
        try:
            if simulate_duration_s > 0:
                step = 0.02
                elapsed = 0.0
                while elapsed < simulate_duration_s:
                    if handle.cancel_event.is_set():
                        raise WorkerError("WORKER_CANCELLED", handle.stop_reason or "cancelled")
                    if (time.monotonic() - started_at) > timeout_s:
                        raise WorkerError("WORKER_TIMEOUT", "Worker exceeded timeout_seconds.")
                    time.sleep(min(step, simulate_duration_s - elapsed))
                    elapsed += step

            if handle.cancel_event.is_set():
                raise WorkerError("WORKER_CANCELLED", handle.stop_reason or "cancelled")
            if (time.monotonic() - started_at) > timeout_s:
                raise WorkerError("WORKER_TIMEOUT", "Worker exceeded timeout_seconds.")

            ws_files = ProjectFiles(ws_path, ws_meta["workspace_identity"])
            changed_files: list[dict[str, Any]] = []
            if mock_handler is not None:
                proposed_edits = mock_handler(ws_path, queue_item) or {}
                if proposed_edits and "write" not in iso_spec["effective_capabilities"]:
                    raise WorkerError("PRIVILEGE_ESCALATION_DENIED", f"Role '{role}' is read-only and cannot modify files.")
                for rel_path, new_content in proposed_edits.items():
                    if rel_path not in file_scope:
                        raise WorkerError(
                            "SCOPE_VIOLATION_DENIED",
                            f"Worker attempted to modify '{rel_path}' outside approved file_scope {file_scope}.",
                        )
                    expected = ws_meta["baseline_hashes"].get(rel_path)
                    written = ws_files.write(rel_path, new_content, expected)
                    changed_files.append(
                        {
                            "path": rel_path,
                            "baseline_sha256": expected,
                            "output_sha256": written["hash"],
                        }
                    )

            result_payload = {
                "worker_id": worker_id,
                "queue_id": queue_id,
                "project_id": project_id,
                "task_id": task_id,
                "role": role,
                "mode": "mock",
                "status": "succeeded",
                "workspace_path": str(ws_path),
                "workspace_identity": ws_meta["workspace_identity"],
                "isolation_kind": ws_meta["isolation_kind"],
                "branch": ws_meta["branch"],
                "baseline_hashes": ws_meta["baseline_hashes"],
                "changed_files": changed_files,
                "summary": f"Mock {role} completed task '{task_id}' ({len(changed_files)} file(s) updated).",
            }
            self.store.record_worker_event(worker_id, project_id, task_id, "completed", result_payload)
            self.store.update_worker_record(worker_id, status="succeeded")
            self.store.update_queue_item(queue_id, status="succeeded", worker_id=worker_id, result=result_payload)
            self.concurrency.record_completion(succeeded=True)
            return result_payload
        except WorkerError as exc:
            final_status = "cancelled" if exc.code == "WORKER_CANCELLED" else ("timed_out" if exc.code == "WORKER_TIMEOUT" else "failed")
            err_payload = {"code": exc.code, "message": str(exc)}
            self.store.record_worker_event(worker_id, project_id, task_id, final_status, err_payload)
            self.store.update_worker_record(worker_id, status=final_status, verification_reason=exc.code)
            self.store.update_queue_item(queue_id, status=final_status, worker_id=worker_id, error=err_payload)
            self.concurrency.record_completion(succeeded=False)
            raise
        finally:
            with self.lock:
                self.active_handles.pop(worker_id, None)

    def integrate_worker_result(
        self,
        worker_result: dict[str, Any],
        *,
        principal: str = "local",
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        """Serial integration pipeline with conflict detection against newer user edits and durable checkpointing."""
        project_id = worker_result["project_id"]
        task_id = worker_result["task_id"]
        worker_id = worker_result["worker_id"]
        op_id = operation_id or f"integrate-{worker_id}"

        project = self.store.get_project(project_id, principal, "write")
        source_files = ProjectFiles(project["root"], project["root_identity"])
        ws_path = Path(worker_result["workspace_path"])
        ws_files = ProjectFiles(ws_path, worker_result["workspace_identity"])

        edits_to_apply: list[dict[str, Any]] = []
        for change in worker_result.get("changed_files") or []:
            rel_path = change["path"]
            baseline_hash = change["baseline_sha256"]
            output_hash = change["output_sha256"]

            # Verify current source file has NOT been edited by user since worker baseline
            try:
                cur_source = source_files.read(rel_path, limit=65536)
                cur_hash = cur_source["hash"]
            except FileBoundaryError as exc:
                if exc.code == "FILE_NOT_FOUND":
                    cur_hash = None
                else:
                    raise WorkerError(exc.code, str(exc)) from exc

            if cur_hash != baseline_hash:
                raise WorkerError(
                    "MERGE_CONFLICT_NEWER_EDIT",
                    f"Refusing to overwrite newer user edit on '{rel_path}' (expected {baseline_hash}, found {cur_hash}).",
                )

            candidate = ws_files.read(rel_path, limit=65536)
            if candidate["hash"] != output_hash:
                raise WorkerError("VERSION_CONFLICT", f"Worker output for '{rel_path}' changed after completion.")
            edits_to_apply.append(
                {
                    "path": rel_path,
                    "content": candidate["content"],
                    "expected_hash": baseline_hash,
                }
            )

        applied_files: list[dict[str, Any]] = []
        if edits_to_apply:
            patch_res = source_files.patch(edits_to_apply)
            applied_files = patch_res.get("files", [])

        ckpt = self.store.checkpoint(
            project_id,
            principal,
            task_id,
            f"Integrated worker {worker_id} ({len(applied_files)} file(s)).",
            op_id,
            objective=worker_result.get("summary", ""),
            next_action="Verify integrated changes or continue next DAG task.",
            changed_files=[{"path": e["path"], "sha256": e["output_sha256"]} for e in worker_result.get("changed_files", [])],
            accepted_decisions=[f"Serial integration from {worker_id} ({worker_result.get('role')})"],
        )
        return {
            "integrated": True,
            "worker_id": worker_id,
            "project_id": project_id,
            "task_id": task_id,
            "applied_files": applied_files,
            "checkpoint_revision": ckpt["checkpoint_revision"],
        }

    def cancel_worker(self, worker_id: str, principal: str = "local", reason: str = "operator_cancel") -> dict[str, Any]:
        with self.lock:
            handle = self.active_handles.get(worker_id)
            if handle is not None:
                handle.stop_reason = reason
                handle.cancel_event.set()
        return self.store.cancel_worker_record(worker_id, principal)

    def stop_all(self, reason: str = "operator_stop_all") -> dict[str, Any]:
        cancelled_ids: list[str] = []
        with self.lock:
            for w_id, handle in list(self.active_handles.items()):
                handle.stop_reason = reason
                handle.cancel_event.set()
                cancelled_ids.append(w_id)
        for item in self.store.list_task_queue(principal="local", status="queued"):
            self.store.update_queue_item(item["queue_id"], status="cancelled", error={"code": "STOP_ALL", "message": reason})
        for w in self.store.list_workers(principal="local")["workers"]:
            if w["status"] in {"queued", "starting", "running"}:
                self.store.update_worker_record(w["id"], status="cancelled", verification_reason=reason)
                if w["id"] not in cancelled_ids:
                    cancelled_ids.append(w["id"])
        return {
            "stopped_workers": cancelled_ids,
            "stopped_count": len(cancelled_ids),
            "reason": reason,
        }
