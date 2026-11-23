"""One locally requested job in an independent snapshot of a bundled fixture."""
from __future__ import annotations

from dataclasses import dataclass, field
from difflib import unified_diff
import hashlib
from itertools import islice
import json
import logging
from pathlib import Path
import re
import threading
from typing import Callable

from . import runner
from .files import FileBoundaryError, ProjectFiles
from .state import State

LOGGER = logging.getLogger(__name__)
FIXTURES = Path(__file__).resolve().parents[1] / "examples"
COMMAND = ("-B", "-m", "unittest", "-v")
PROJECT_TEST_COMMAND = ("-B", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v")
NODE_TEST_COMMAND = ("--test", "--test-concurrency=1", "tests/*.test.mjs")
POWERSHELL_PREFIX = ("-NoProfile", "-NonInteractive", "-File")
POWERSHELL_LEGACY_PREFIX = ("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File")
TEST_RECIPES = {"project_tests": "python", "node_tests": "node", "powershell_script": "powershell"}
BLENDER_COMMAND = ("--background", "--factory-startup", "--disable-autoexec", "--python", "build_knot.py")
_ACTIVE = {"queued", "running", "cancelling"}
_JOB_ID = re.compile(r"job_[a-f0-9]{32}\Z")
_PS_PATH = re.compile(r"(?:[A-Za-z0-9_][A-Za-z0-9_.-]*/){0,5}[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:ps1|psd1|psm1|json)\Z")
_TEST_TARGET = re.compile(r"tests\.test_[A-Za-z0-9_]+(?:\.[A-Za-z_][A-Za-z0-9_]*){0,2}\Z")
PYTHON_SNAPSHOT_MAX_FILES = 128
PYTHON_SNAPSHOT_MAX_FILE_BYTES = 256 * 1024
PYTHON_SNAPSHOT_MAX_TOTAL_BYTES = 4 * 1024 * 1024
POWERSHELL_SNAPSHOT_MAX_FILES = 32
POWERSHELL_SNAPSHOT_MAX_FILE_BYTES = 65_536
POWERSHELL_SNAPSHOT_MAX_TOTAL_BYTES = 524_288
_REVIEW_LIMIT = 65_536
_MAX_WORK_FILE_BYTES = PYTHON_SNAPSHOT_MAX_FILE_BYTES
_DIFF_BUDGET = 24_000


class JobError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class ActiveJob:
    job_id: str
    project_id: str
    recipe: str
    signal: threading.Event = field(default_factory=threading.Event)
    signal_lock: threading.Lock = field(default_factory=threading.Lock)
    stop_reason: str | None = None
    thread: threading.Thread | None = None

    def stop(self, reason: str) -> None:
        with self.signal_lock:
            if self.stop_reason is None:
                self.stop_reason = reason
                self.signal.set()


def _expected_file(fixture: Path, name: str, text: str) -> bool:
    expected = (fixture / name).read_text(encoding="utf-8")
    normalized = text.replace("\r\n", "\n")
    if name == "calculator.py":
        return normalized in (expected, expected.replace("return a - b", "return a + b"))
    return normalized == expected


def _recipe_details(executable: str, argv: list[str], cwd_relative: str) -> tuple[str, str | None, str | None]:
    if cwd_relative == ".":
        if executable == "python" and tuple(argv) == COMMAND:
            return "calculator", None, None
        if executable == "python" and tuple(argv) == PROJECT_TEST_COMMAND:
            return "project_tests", None, None
        if executable == "python" and len(argv) == 5 and tuple(argv[:4]) == COMMAND:
            target = argv[4]
            if isinstance(target, str) and len(target) <= 128 and _TEST_TARGET.fullmatch(target):
                return "project_tests", None, target
        if executable == "node" and tuple(argv) == NODE_TEST_COMMAND:
            return "node_tests", None, None
        if executable == "powershell" and ((len(argv) == 4 and tuple(argv[:3]) == POWERSHELL_PREFIX) or (len(argv) == 6 and tuple(argv[:5]) == POWERSHELL_LEGACY_PREFIX)):
            script = argv[-1]
            if isinstance(script, str) and script.casefold().endswith(".ps1") and _PS_PATH.fullmatch(script):
                return "powershell_script", script, None
        if executable == "blender" and tuple(argv) == BLENDER_COMMAND:
            return "blender_knot", None, None
    raise JobError("EXECUTION_REQUEST_UNSUPPORTED", "Use a supported recipe with its documented arguments.")


def _recipe_spec(executable: str, argv: list[str], cwd_relative: str) -> tuple[str, str | None]:
    recipe, entry_script, test_target = _recipe_details(executable, argv, cwd_relative)
    return recipe, entry_script if entry_script is not None else test_target


def _recipe(executable: str, argv: list[str], cwd_relative: str) -> str:
    return _recipe_details(executable, argv, cwd_relative)[0]


def validate_project_test_files(
    project: dict,
    runtime: str,
    files: list[str],
    *,
    max_files: int | None = None,
    max_total_bytes: int | None = None,
    max_file_bytes: int | None = None,
    source_allowlist: frozenset[str] | None = None,
) -> list[str]:
    """Validate the owner-approved selection without copying or starting code."""
    if max_files is None:
        max_files = PYTHON_SNAPSHOT_MAX_FILES if runtime == "python" else POWERSHELL_SNAPSHOT_MAX_FILES
    if max_total_bytes is None:
        max_total_bytes = PYTHON_SNAPSHOT_MAX_TOTAL_BYTES if runtime == "python" else POWERSHELL_SNAPSHOT_MAX_TOTAL_BYTES
    if max_file_bytes is None:
        max_file_bytes = PYTHON_SNAPSHOT_MAX_FILE_BYTES if runtime == "python" else POWERSHELL_SNAPSHOT_MAX_FILE_BYTES
    if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int) or not 1 <= max_file_bytes <= _MAX_WORK_FILE_BYTES:
        raise JobError("INVALID_TEST_SCOPE", "Invalid per-file size limit for test snapshot.")
    min_files = 1 if runtime in ("powershell", "python") else 2
    if not isinstance(files, list) or not min_files <= len(files) <= max_files:
        if isinstance(files, list) and len(files) > max_files:
            raise JobError(
                "INVALID_TEST_SCOPE",
                f"snapshot file count {len(files)} exceeds {max_files} (choose between {min_files} and {max_files} supported files).",
            )
        raise JobError("INVALID_TEST_SCOPE", f"Choose between {min_files} and {max_files} supported files.")
    if runtime == "powershell":
        if any(not isinstance(path, str) or len(path) > 180 or not _PS_PATH.fullmatch(path) or ".." in path for path in files):
            raise JobError("INVALID_TEST_SCOPE", "Use canonical relative files for the selected test runtime.")
        if not any(path.casefold().endswith(".ps1") for path in files):
            raise JobError("INVALID_TEST_SCOPE", "Include at least one .ps1 script file.")
    else:
        suffix = r"\.(?:py|json)" if runtime == "python" else r"(?:\.test)?\.(?:mjs|js|cjs|json)"
        pattern = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_]*/){0,5}[A-Za-z_][A-Za-z0-9_]*" + suffix + r"\Z")
        if any(not isinstance(path, str) or len(path) > 180 or not pattern.fullmatch(path) for path in files):
            raise JobError("INVALID_TEST_SCOPE", "Use canonical relative files for the selected test runtime.")
    if len({path.casefold() for path in files}) != len(files):
        raise JobError("INVALID_TEST_SCOPE", "Duplicate file paths are not allowed.")
    if runtime == "python" and not any(re.fullmatch(r"tests/test_[A-Za-z0-9_]+\.py", path) for path in files):
        raise JobError("INVALID_TEST_SCOPE", "Include at least one tests/test_*.py.")
    if runtime == "node" and not any(re.fullmatch(r"tests/[A-Za-z_][A-Za-z0-9_]*\.test\.mjs", path) for path in files):
        raise JobError("INVALID_TEST_SCOPE", "Include at least one tests/*.test.mjs file.")
    source = ProjectFiles(project["root"], project["root_identity"])
    _read_project_test_files(
        source, files, max_total_bytes=max_total_bytes, max_file_bytes=max_file_bytes, source_allowlist=source_allowlist,
    )
    return sorted(files)


def _read_project_test_files(
    source: ProjectFiles,
    files: list[str],
    *,
    max_total_bytes: int = PYTHON_SNAPSHOT_MAX_TOTAL_BYTES,
    max_file_bytes: int = PYTHON_SNAPSHOT_MAX_FILE_BYTES,
    source_allowlist: frozenset[str] | None = None,
) -> list[dict]:
    items = []
    total = 0
    for path in files:
        if source_allowlist is not None and path not in source_allowlist:
            raise JobError("BRIDGE_POLICY_DENIED", "The source path is outside the broker-approved snapshot list.")
        try:
            if max_file_bytes <= 65_536:
                item = source.read(path, limit=max_file_bytes)
            else:
                item = source.read_snapshot_file(path, max_bytes=max_file_bytes)
        except FileBoundaryError as exc:
            if exc.code == "RESOURCE_BUDGET_EXCEEDED":
                size = exc.details.get("size")
                if isinstance(size, int):
                    raise JobError(
                        "RESOURCE_BUDGET_EXCEEDED",
                        f"snapshot file '{path}' size {size} bytes exceeds {max_file_bytes} bytes.",
                    ) from exc
                raise JobError("RESOURCE_BUDGET_EXCEEDED", str(exc)) from exc
            raise
        if item["truncated"] or item["size"] > max_file_bytes:
            raise JobError(
                "RESOURCE_BUDGET_EXCEEDED",
                f"snapshot file '{path}' size {item['size']} bytes exceeds {max_file_bytes} bytes.",
            )
        total += item["size"]
        if total > max_total_bytes:
            raise JobError(
                "RESOURCE_BUDGET_EXCEEDED",
                f"snapshot total size {total} bytes exceeds {max_total_bytes} bytes.",
            )
        items.append(item)
    return items


def _blender_artifacts(workspace: Path) -> dict:
    files = ProjectFiles(workspace)
    geometry = json.loads(files.read("geometry.json")["content"])
    expected = {"vertices": 17280, "edges": 34560, "quads": 17280, "euler": 0, "manifold": True}
    if geometry != expected:
        raise JobError("ARTIFACT_VERIFICATION_FAILED", "The Blender geometry statistics did not match.")
    blend, glb = (files.binary_evidence(name) for name in ("knot.blend", "knot.glb"))
    if not blend["header"].startswith((b"BLENDER", bytes.fromhex("28b52ffd"))):
        raise JobError("ARTIFACT_VERIFICATION_FAILED", "The Blender scene header did not match.")
    header = glb.pop("header")
    if header[:8] != b"glTF\x02\x00\x00\x00" or int.from_bytes(header[8:12], "little") != glb["size"]:
        raise JobError("ARTIFACT_VERIFICATION_FAILED", "The GLB version or file length did not match.")
    blend.pop("header")
    return {"geometry": geometry, "files": [blend, glb]}


def _review_text(files: ProjectFiles, path: str, *, max_bytes: int = _REVIEW_LIMIT) -> dict:
    if max_bytes <= _REVIEW_LIMIT:
        item = files.read(path, limit=max_bytes)
    else:
        item = files.read_snapshot_file(path, max_bytes=max_bytes)
    if item["truncated"] or item["size"] > max_bytes:
        raise JobError("RESOURCE_BUDGET_EXCEEDED", f"Reviewed text cannot exceed {max_bytes} bytes.")
    return item


def _seal_snapshot(workspace: Path, root_identity: str, baseline: list[dict], *, max_file_bytes: int = _REVIEW_LIMIT) -> list[dict]:
    snapshot = ProjectFiles(workspace, root_identity)
    sealed = []
    for existing in baseline:
        path = existing["path"]
        try:
            item = _review_text(snapshot, path, max_bytes=max_file_bytes)
        except (FileBoundaryError, JobError) as failure:
            sealed.append({"path": path, "unavailable": failure.code})
        else:
            sealed.append({"path": path, "sha256": item["hash"]})
    return sealed


class Jobs:
    def __init__(self, store: State, state_path: Path, protected_path: Callable[[Path], None], *,
                 source_allowlist: frozenset[str] | None = None,
                 before_create: Callable[[], None] | None = None,
                 workspace_limit: int | None = None,
                 job_limits: dict[str, int] | None = None,
                 max_file_bytes: int = _REVIEW_LIMIT,
                 workspace_poll_interval: float = 0.05):
        if workspace_limit is not None and (
            isinstance(workspace_limit, bool) or not isinstance(workspace_limit, int)
            or not 1 <= workspace_limit <= runner.MAX_WORKSPACE_BYTES
        ):
            raise runner.RunnerBlocked("INVALID_GRANT_LIMITS", "The requested workspace_limit cannot be applied.")
        if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int) or not 1 <= max_file_bytes <= _MAX_WORK_FILE_BYTES:
            raise runner.RunnerBlocked("INVALID_GRANT_LIMITS", "The requested max_file_bytes cannot be applied.")
        self.store = store
        self.base = state_path / "jobs"
        self.protected_path = protected_path
        self.source_allowlist = source_allowlist
        self.before_create = before_create
        self.workspace_limit = workspace_limit
        self.job_limits = runner.resolve_job_limits(job_limits) if job_limits is not None else None
        self.max_file_bytes = max_file_bytes
        self.workspace_poll_interval = max(0.01, min(float(workspace_poll_interval), 0.5))
        self.lock = threading.RLock()
        self.active: ActiveJob | None = None
        self.unconfirmed_exit = False

    def start(self, project: dict, principal: str, task_id: str, operation_id: str,
              executable: str, argv: list[str], cwd_relative: str, timeout_seconds: int) -> dict:
        recipe, entry_script, test_target = _recipe_details(executable, argv, cwd_relative)
        runner.require_execution()
        with self.lock:
            if self.unconfirmed_exit:
                raise JobError("ISOLATION_NOT_VERIFIED", "A previous job's process-group termination could not be confirmed.")
            scope = None
            exec_policy = self.store.get_exec_policy(project["project_id"])
            runtime = TEST_RECIPES.get(recipe)
            if runtime is not None:
                if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds < 1:
                    raise JobError("INVALID_GRANT_LIMITS", "Project tests require a timeout of at least 1 second.")
                if timeout_seconds > 120:
                    raise JobError("RESOURCE_BUDGET_EXCEEDED", "Project tests have a 120-second time cap.")
                scope = self.store.get_test_scope(project["project_id"], principal, runtime)
                if scope is None:
                    raise JobError(f"{runtime.upper()}_TEST_SCOPE_REQUIRED", "The local operator must approve the test file list.")
                if entry_script is not None and entry_script not in scope["files"]:
                    raise JobError(f"{runtime.upper()}_TEST_SCOPE_REQUIRED", "The requested script is outside the approved file list.")
                if test_target is not None:
                    target_parts = test_target.split(".")
                    target_file = f"{target_parts[0]}/{target_parts[1]}.py"
                    if target_file not in scope["files"]:
                        raise JobError("INVALID_TEST_SCOPE", "The requested test target is outside the approved file list.")
                if len(scope["files"]) > exec_policy["max_files"]:
                    raise JobError(
                        "RESOURCE_BUDGET_EXCEEDED",
                        f"snapshot file count {len(scope['files'])} exceeds {exec_policy['max_files']}.",
                    )
            job = self.store.create_job(project["project_id"], principal, task_id, operation_id, {
                "executable": executable, "argv": argv, "cwd_relative": cwd_relative,
                "timeout_seconds": timeout_seconds,
            }, active_limit=1)
            if not job["created"]:
                return job
            entry = ActiveJob(job["job_id"], project["project_id"], recipe)
            thread = threading.Thread(
                name=f"edge-bridge-{entry.job_id}", target=self._run,
                args=(entry, project, timeout_seconds, scope, exec_policy["max_total_bytes"], entry_script, test_target),
                daemon=False,
            )
            entry.thread = thread
            self.active = entry
            try:
                thread.start()
            except RuntimeError:
                self.active = None
                self.store.update_job(entry.job_id, status="failed", evidence={"reason": "SUPERVISOR_START_FAILED"})
                raise
            return job

    def _job_dir(self, job_id: str) -> Path:
        if not _JOB_ID.fullmatch(job_id):
            raise JobError("NOT_FOUND", "Job is not available.")
        return self.base / job_id

    def _dirs(self, job_id: str) -> tuple[Path, Path]:
        self.base.mkdir(exist_ok=True)
        self.protected_path(self.base)
        target = self._job_dir(job_id)
        target.mkdir()
        self.protected_path(target)
        workspace, control = target / "workspace", target / "control"
        workspace.mkdir()
        control.mkdir()
        self.protected_path(control)
        return workspace, control

    @staticmethod
    def _snapshot(
        project: dict,
        workspace: Path,
        recipe: str,
        scope: dict | None,
        *,
        max_total_bytes: int = 524_288,
        max_file_bytes: int = _REVIEW_LIMIT,
        source_allowlist: frozenset[str] | None = None,
    ) -> list[dict]:
        source = ProjectFiles(project["root"], project["root_identity"])
        copy = ProjectFiles(workspace)
        records = []
        if scope is not None:
            items = _read_project_test_files(
                source,
                scope["files"],
                max_total_bytes=max_total_bytes,
                max_file_bytes=max_file_bytes,
                source_allowlist=source_allowlist,
            )
            directories = set()
            for item in items:
                components = item["path"].split("/")[:-1]
                directories.update("/".join(components[:index]) for index in range(1, len(components) + 1))
            for directory in sorted(directories, key=lambda name: (name.count("/"), name)):
                copy.make_snapshot_directory(directory)
        else:
            fixture = FIXTURES / ("blender" if recipe == "blender_knot" else "calculator")
            names = ("build_knot.py",) if recipe == "blender_knot" else ("calculator.py", "test_calculator.py")
            items = [source.read(name, limit=32768) for name in names]
            if any(item["truncated"] or not _expected_file(fixture, item["path"], item["content"]) for item in items):
                raise JobError("FIXTURE_NOT_APPROVED", "The file does not match the approved bundled fixture.")
        for item in items:
            name = item["path"]
            raw = item["content"].encode("utf-8")
            if hashlib.sha256(raw).hexdigest() != item["hash"]:
                raise JobError("FIXTURE_NOT_APPROVED", "Snapshot text did not match its raw source digest.")
            written = copy.write(name, item["content"], None)
            if written["hash"] != item["hash"]:
                raise JobError("SNAPSHOT_MISMATCH", "The new regular file did not match the source hash.")
            records.append({"path": name, "source_sha256": item["hash"], "snapshot_sha256": written["hash"]})
        return records

    def _run(
        self,
        entry: ActiveJob,
        project: dict,
        timeout: int,
        scope: dict | None,
        max_total_bytes: int = 524_288,
        entry_script: str | None = None,
        test_target: str | None = None,
    ) -> None:
        child = None
        exit_code = None
        evidence = {}
        failure = None
        uncertain = False
        timer = threading.Timer(timeout, entry.stop, args=("timeout",))
        timer.start()
        recipe = entry.recipe
        try:
            if entry.signal.is_set():
                return
            workspace, control = self._dirs(entry.job_id)
            snapshot_kwargs = {
                "max_total_bytes": max_total_bytes,
                "source_allowlist": self.source_allowlist,
            }
            if self.max_file_bytes != _REVIEW_LIMIT:
                snapshot_kwargs["max_file_bytes"] = self.max_file_bytes
            evidence["snapshot"] = self._snapshot(
                project, workspace, recipe, scope, **snapshot_kwargs,
            )
            if scope is not None:
                evidence["test_scope_revision"] = scope["policy_revision"]
                evidence["workspace_identity"] = ProjectFiles.identity(workspace)
            if entry.signal.is_set():
                return
            prepare_options = {"job_limits": self.job_limits} if self.job_limits is not None else {}
            if test_target is not None:
                prepare_options["test_target"] = test_target
            evidence["policy"] = runner.prepare_recipe(
                workspace, control, recipe, cancelled=entry.signal, entry_script=entry_script,
                **prepare_options,
            )
            if entry.signal.is_set():
                return
            options = {"before_create": self.before_create} if self.before_create is not None else {}
            if self.job_limits is not None:
                options["job_limits"] = self.job_limits
            if test_target is not None:
                options["test_target"] = test_target
            child = runner.launch_recipe(
                workspace, control, control / "job.log", recipe,
                cancelled=entry.signal, entry_script=entry_script, **options,
            )
            evidence["workload_started"] = True
            with self.lock:
                if not entry.signal.is_set():
                    self.store.update_job(entry.job_id, status="running", evidence=evidence)
            while not entry.signal.is_set():
                if self.workspace_limit is not None and runner.workspace_over_limit(
                    workspace, self.workspace_limit, entry.signal,
                ):
                    failure = "JOB_WORKSPACE_LIMIT_EXCEEDED"
                    evidence["failure_code"] = failure
                    child.cancel()
                    exit_code = child.wait(5)
                    break
                exit_code = child.poll()
                if exit_code is not None:
                    break
                entry.signal.wait(self.workspace_poll_interval)
            if entry.signal.is_set() and exit_code is None:
                child.cancel()
                exit_code = child.wait(5)
            if exit_code == 0 and failure is None and (recipe == "blender_knot" or scope is not None) and not entry.signal.is_set():
                completed, child = child, None
                completed.close()
                if completed.capture_error:
                    failure = completed.capture_error
                    evidence["failure_code"] = failure
                elif scope is not None:
                    evidence["sealed_files"] = _seal_snapshot(
                        workspace, evidence["workspace_identity"], evidence["snapshot"],
                        max_file_bytes=self.max_file_bytes,
                    )
                else:
                    evidence["artifacts"] = _blender_artifacts(workspace)
        except Exception as error:
            failure = getattr(error, "code", "SUPERVISOR_FAILURE")
            evidence["failure_code"] = failure
            if failure in {"ISOLATION_NOT_VERIFIED", "RESOURCE_BUDGET_EXCEEDED", "INVALID_TEST_SCOPE"}:
                evidence["diagnostic_hint"] = str(error)
            if failure in {"PROCESS_OWNERSHIP_UNCONFIRMED", "JOB_EXIT_UNCONFIRMED"}:
                uncertain = True
            if failure == "SUPERVISOR_FAILURE":
                LOGGER.error("Job supervisor interrupted: %s", type(error).__name__)
        finally:
            timer.cancel()
            if child is not None:
                try:
                    child.close()
                    if child.capture_error:
                        failure = child.capture_error
                        evidence["failure_code"] = failure
                except Exception as error:
                    uncertain = True
                    evidence["cleanup_type"] = type(error).__name__
            if self.workspace_limit is not None and exit_code is not None and not uncertain and failure is None:
                try:
                    if runner.workspace_over_limit(workspace, self.workspace_limit, entry.signal):
                        failure = "JOB_WORKSPACE_LIMIT_EXCEEDED"
                        evidence["failure_code"] = failure
                except OSError:
                    failure = "JOB_WORKSPACE_SCAN_FAILED"
                    evidence["failure_code"] = failure
            # A cancelled startup may never obtain a process handle. The launcher
            # contract requires cleanup before surfacing that condition.
            timer.join()
            with self.lock:
                if uncertain:
                    self.unconfirmed_exit = True
                    status = "unknown_after_restart"
                elif entry.stop_reason == "timeout":
                    status = "timed_out"
                elif entry.stop_reason is not None:
                    status = "cancelled"
                elif failure is not None or exit_code != 0:
                    status = "failed"
                else:
                    status = "succeeded"
                if exit_code in (-1073741502, 3221225794):
                    desktop = runner.thread_desktop_name()
                    if desktop and not desktop.casefold().endswith("\\default"):
                        evidence["diagnostic_hint"] = (
                            f"Process exited with 0xC0000142 (STATUS_DLL_INIT_FAILED) inside MXC under non-Default "
                            f"desktop '{desktop}'. Run from a normal WinSta0\\Default session for interactive Win32 DLL initialization."
                        )
                    else:
                        evidence["diagnostic_hint"] = (
                            "Process exited with 0xC0000142 (STATUS_DLL_INIT_FAILED) inside MXC."
                        )
                if entry.stop_reason is not None:
                    evidence["stop_reason"] = entry.stop_reason
                try:
                    self.store.update_job(entry.job_id, status=status, exit_code=exit_code, evidence=evidence)
                finally:
                    self.active = None

    def output(self, job_id: str, cursor: int, limit: int) -> dict:
        target = self._job_dir(job_id) / "control" / "job.log"
        try:
            for path in (self.base, target.parent.parent, target.parent, target):
                self.protected_path(path)
            if target.lstat().st_nlink != 1:
                raise JobError("STATE_PATH_UNSAFE", "Log output may not reference an aliased file.")
            with target.open("rb") as log:
                log.seek(cursor)
                page = log.read(limit + 1)
        except FileNotFoundError:
            page = b""
        raw = page[:limit]
        return {"job_id": job_id, "cursor": cursor, "next_cursor": cursor + len(raw),
                "has_more": len(page) > limit, "output": raw.decode("utf-8", errors="replace")}

    def _review_files(self, project: dict, job: dict) -> tuple[ProjectFiles, ProjectFiles, dict, dict]:
        evidence = job["evidence"] or {}
        recipe = evidence.get("policy", {}).get("recipe")
        if (job["status"] != "succeeded" or recipe not in TEST_RECIPES
                or not evidence.get("workspace_identity") or "sealed_files" not in evidence):
            raise JobError(
                "JOB_REVIEW_UNAVAILABLE",
                "A successful and sealed Python, Node, or PowerShell project job is required.",
            )
        old_hashes = {item["path"]: item["source_sha256"] for item in evidence["snapshot"]}
        sealed = {item["path"]: item for item in evidence["sealed_files"]}
        source = ProjectFiles(project["root"], project["root_identity"])
        snapshot = ProjectFiles(self._job_dir(job["job_id"]) / "workspace", evidence["workspace_identity"])
        return source, snapshot, old_hashes, sealed

    def review(self, project: dict, job: dict) -> dict:
        source, snapshot, old_hashes, sealed = self._review_files(project, job)
        changes = []
        remaining = _DIFF_BUDGET
        for path, baseline in old_hashes.items():
            outcome = sealed[path]
            new_hash = outcome.get("sha256")
            if new_hash == baseline:
                continue
            change = {"path": path, "source_sha256": baseline, "output_sha256": new_hash}
            if new_hash is None:
                changes.append({**change, "status": "unavailable", "reason": outcome["unavailable"]})
                continue
            try:
                current_output = _review_text(snapshot, path)
                current_source = _review_text(source, path)
            except (FileBoundaryError, JobError) as failure:
                changes.append({**change, "status": "unavailable", "reason": failure.code})
                continue
            if current_output["hash"] != new_hash or current_source["hash"] != baseline:
                status = "output_changed" if current_output["hash"] != new_hash else "source_changed"
                changes.append({**change, "status": status})
                continue
            old_lines = current_source["content"].splitlines(keepends=True)
            new_lines = current_output["content"].splitlines(keepends=True)
            diff = ""
            truncated = True
            if remaining and max(len(old_lines), len(new_lines)) <= 2_048:
                lines = list(islice(unified_diff(old_lines, new_lines, f"source/{path}", f"job/{path}"), 401))
                raw = "".join(lines[:400])
                diff = raw[:remaining]
                truncated = len(lines) > 400 or len(raw) > remaining
                remaining -= len(diff)
            changes.append({**change, "status": "ready", "diff": diff, "diff_truncated": truncated})
        return {"job_id": job["job_id"], "changes": changes}

    def prepare_apply(self, project: dict, job: dict, selection: list[dict]) -> tuple[ProjectFiles, list[dict]]:
        source, snapshot, old_hashes, sealed = self._review_files(project, job)
        runtime = TEST_RECIPES[job["evidence"]["policy"]["recipe"]]
        active_scope = self.store.get_test_scope(project["project_id"], "local", runtime)
        if active_scope is None:
            raise JobError("TEST_SCOPE_REVOKED", "Reapplying files requires a current local project test grant.")
        edits = []
        for item in selection:
            path = item["path"]
            outcome = sealed.get(path)
            if path not in active_scope["files"] or outcome is None:
                raise JobError("JOB_FILE_NOT_GRANTED", "The file is outside the current approved snapshot file list.")
            approved_hash = item["output_sha256"]
            if outcome.get("sha256") != approved_hash or old_hashes[path] == approved_hash:
                raise JobError("VERSION_CONFLICT", "The approved digest does not identify a changed sealed file.")
            candidate, current = _review_text(snapshot, path), _review_text(source, path)
            if candidate["hash"] != approved_hash or current["hash"] != old_hashes[path]:
                raise JobError("VERSION_CONFLICT", "The source or job output has changed since the reviewed version.")
            edits.append({"path": path, "expected_hash": old_hashes[path], "content": candidate["content"]})
        return source, edits

    def cancel(self, project_id: str, principal: str, job_id: str, operation_id: str) -> dict:
        with self.lock:
            job = self.store.get_job(project_id, principal, job_id)
            request = self.store.begin_operation(project_id, principal, operation_id, {"cancel_job": job_id}, "execute")
            if request["status"] == "succeeded":
                return request["result"]
            if request["status"] != "claimed":
                raise JobError("UNKNOWN_AFTER_RESTART", "The prior cancellation needs reconciliation.")
            entry = self.active
            requested = entry is not None and entry.job_id == job_id and job["status"] in _ACTIVE
            if requested:
                self.store.update_job(job_id, status="cancelling")
                entry.stop("operator_cancel")
            result = {"job_id": job_id, "status": "cancelling" if requested else job["status"],
                      "cancellation_requested": requested}
            self.store.finish_operation(project_id, principal, operation_id, result)
            return result

    def shutdown(self) -> None:
        with self.lock:
            entry = self.active
            if entry is not None:
                entry.stop("broker_shutdown")
        if entry is not None:
            entry.thread.join()

    def stop_project_tests(self, project_id: str, runtime: str, reason: str) -> bool:
        with self.lock:
            entry = self.active
            if entry is None or entry.project_id != project_id or TEST_RECIPES.get(entry.recipe) != runtime:
                return False
            self.store.update_job(entry.job_id, status="cancelling")
            entry.stop(reason)
            return True

    def stop_all(self, reason: str = "operator_stop_all") -> dict:
        with self.lock:
            entry = self.active
            if entry is not None:
                self.store.update_job(entry.job_id, status="cancelling")
                entry.stop(reason)
        joined = True
        if entry is not None and entry.thread is not None:
            entry.thread.join(timeout=10)
            joined = not entry.thread.is_alive()
        return {
            "stopped": entry is not None,
            "job_id": entry.job_id if entry is not None else None,
            "thread_joined": joined,
        }

