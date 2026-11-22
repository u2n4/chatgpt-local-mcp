"""Boundary-checked, non-destructive Git operations via pinned local git.exe."""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time

import pywintypes
import win32con
import win32event
import win32file
import win32job
import win32process
import win32security

from .files import FileBoundaryError, _part as _check_file_part
from .runner import GIT_SHA256, git_path

_SAFE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@^~-]{0,127}\Z")
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_SAFE_BRANCH = re.compile(r"edge-worker/[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_MAX_OUTPUT_BYTES = 2 * 1024 * 1024
_GIT_VERIFY_LOCK = threading.Lock()
_GIT_VERIFY_CACHE: tuple[str, int, int, int] | None = None
_DIFF_SECRET_EXCLUDES = (
    ":(exclude,icase,glob)**/.env",
    ":(exclude,icase,glob)**/.env.*",
    ":(exclude,icase,glob)**/*.pem",
    ":(exclude,icase,glob)**/*.key",
    ":(exclude,icase,glob)**/*.pfx",
    ":(exclude,icase,glob)**/*.p12",
    ":(exclude,icase,glob)**/*.token",
    ":(exclude,icase,glob)**/credentials.json",
    ":(exclude,icase,glob)**/secrets.json",
    ":(exclude,icase,glob)**/secrets.js",
    ":(exclude,icase,glob)**/secrets.ts",
    ":(exclude,icase,glob)**/auth.json",
)


class GitEngineError(Exception):
    """Structured boundary or git execution error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _verify_git_executable() -> Path:
    global _GIT_VERIFY_CACHE
    exe = git_path()
    try:
        st = exe.stat()
    except OSError as exc:
        raise GitEngineError("RUNNER_BLOCKED", "Pinned git.exe executable is not installed.") from exc
    if not exe.is_file():
        raise GitEngineError("RUNNER_BLOCKED", "Pinned git.exe executable is not installed.")
    sig = (str(exe), st.st_mtime_ns, st.st_size, st.st_ino)
    with _GIT_VERIFY_LOCK:
        if _GIT_VERIFY_CACHE == sig:
            return exe
    with exe.open("rb") as fh:
        digest = hashlib.file_digest(fh, "sha256").hexdigest()
    if digest != GIT_SHA256:
        raise GitEngineError("RUNNER_BLOCKED", "Pinned git.exe executable hash changed; review required.")
    with _GIT_VERIFY_LOCK:
        _GIT_VERIFY_CACHE = sig
    return exe


def _safe_env(root: Path, extra_env: dict[str, str] | None = None) -> dict[str, str]:
    keys = (
        "SYSTEMROOT",
        "WINDIR",
        "SYSTEMDRIVE",
        "COMSPEC",
        "PROCESSOR_ARCHITECTURE",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "TEMP",
        "TMP",
    )
    env = {k: os.environ[k] for k in keys if k in os.environ}
    env.update(
        {
            "PATH": str(git_path().parent) + ";" + str(Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_GLOBAL": "NUL",
            "GIT_ASKPASS": "",
            "SSH_ASKPASS": "",
            "GIT_CEILING_DIRECTORIES": str(root.parent),
        }
    )
    if extra_env:
        env.update(extra_env)
    return env


def _base_command(exe: Path, root: Path, args: list[str]) -> list[str]:
    return [
        str(exe),
        "-C",
        str(root),
        "-c",
        "core.hooksPath=NUL",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "diff.external=",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "core.quotePath=false",
        *args,
    ]


def _validate_ref(ref: str, *, allow_head: bool = True) -> str:
    if not isinstance(ref, str) or not _SAFE_REF.fullmatch(ref):
        raise GitEngineError("INVALID_ARGUMENT", "Invalid git reference name.")
    if ref.startswith("-") or ".." in ref or ref.endswith(".lock") or "@{" in ref:
        raise GitEngineError("INVALID_ARGUMENT", "Disallowed syntax in git reference.")
    if not allow_head and ref == "HEAD":
        raise GitEngineError("INVALID_ARGUMENT", "Expected a named reference.")
    return ref


def _validate_rel_paths(paths: list[str] | None) -> list[str]:
    if paths is None:
        return []
    if not isinstance(paths, list) or len(paths) > 100:
        raise GitEngineError("INVALID_ARGUMENT", "paths must be a list of at most 100 relative paths.")
    validated: list[str] = []
    for item in paths:
        if not isinstance(item, str) or not item or item.startswith("-") or "\\" in item or item.startswith("/"):
            raise GitEngineError("INVALID_ARGUMENT", f"Invalid relative git path: {item!r}")
        parts = Path(item).parts
        if ".." in parts or ".git" in {p.casefold() for p in parts}:
            raise GitEngineError("INVALID_ARGUMENT", f"Disallowed path segment in {item!r}")
        for seg in parts:
            try:
                _check_file_part(seg)
            except FileBoundaryError as exc:
                raise GitEngineError("INVALID_ARGUMENT", f"Disallowed secret or reserved path segment in {item!r}") from exc
        validated.append(item)
    return validated


def _run_git(
    root: Path,
    args: list[str],
    *,
    extra_env: dict[str, str] | None = None,
    timeout_s: float = 15.0,
) -> tuple[int, bytes, bytes]:
    exe = _verify_git_executable()
    cmd = _base_command(exe, root, args)
    env = _safe_env(root, extra_env)
    if os.name != "nt":
        proc = subprocess.run(cmd, cwd=str(root), env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout_s)
        return proc.returncode, proc.stdout[:_MAX_OUTPUT_BYTES], proc.stderr[:_MAX_OUTPUT_BYTES]

    with tempfile.TemporaryDirectory(prefix="edge-git-") as tmpdir:
        out_path = Path(tmpdir) / "stdout.bin"
        err_path = Path(tmpdir) / "stderr.bin"
        sa = win32security.SECURITY_ATTRIBUTES()
        sa.bInheritHandle = True
        flags = win32file.FILE_ATTRIBUTE_NORMAL
        share = win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE
        null_h = out_h = err_h = None
        proc = thread = job = None
        try:
            null_h = win32file.CreateFile("NUL", win32file.GENERIC_READ, share, sa, win32file.OPEN_EXISTING, flags, None)
            out_h = win32file.CreateFile(str(out_path), win32file.GENERIC_WRITE, share, sa, win32file.CREATE_ALWAYS, flags, None)
            err_h = win32file.CreateFile(str(err_path), win32file.GENERIC_WRITE, share, sa, win32file.CREATE_ALWAYS, flags, None)

            startup = win32process.STARTUPINFO()
            startup.dwFlags = win32con.STARTF_USESTDHANDLES | win32con.STARTF_USESHOWWINDOW
            startup.hStdInput = null_h
            startup.hStdOutput = out_h
            startup.hStdError = err_h
            startup.wShowWindow = win32con.SW_HIDE

            job = win32job.CreateJobObject(None, "")
            info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
            info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)

            creation = win32con.CREATE_SUSPENDED | win32con.CREATE_NEW_PROCESS_GROUP | win32con.CREATE_NO_WINDOW
            proc, thread, _, _ = win32process.CreateProcess(
                str(exe),
                subprocess.list2cmdline(cmd),
                None,
                None,
                True,
                creation,
                env,
                str(root),
                startup,
            )
            win32job.AssignProcessToJobObject(job, proc)
            win32process.ResumeThread(thread)

            wait_ms = int(max(1000, timeout_s * 1000))
            res = win32event.WaitForSingleObject(proc, wait_ms)
            if res != win32event.WAIT_OBJECT_0:
                win32job.TerminateJobObject(job, 124)
                win32event.WaitForSingleObject(proc, 5000)
                raise GitEngineError("GIT_TIMEOUT", "Git operation timed out and was terminated cleanly.")
            code = win32process.GetExitCodeProcess(proc)
        except GitEngineError:
            raise
        except pywintypes.error as exc:
            raise GitEngineError("GIT_EXECUTION_FAILED", f"Failed to execute pinned git.exe: {exc}") from exc
        finally:
            for handle in (thread, proc, job, null_h, out_h, err_h):
                if handle is not None:
                    try:
                        handle.Close()
                    except Exception:
                        pass

        with out_path.open("rb") as fh:
            stdout_bytes = fh.read(_MAX_OUTPUT_BYTES + 1)
        with err_path.open("rb") as fh:
            stderr_bytes = fh.read(65_536)
        if len(stdout_bytes) > _MAX_OUTPUT_BYTES:
            raise GitEngineError("RESOURCE_BUDGET_EXCEEDED", "Git command output exceeded 2 MiB safety cap.")
        return int(code), stdout_bytes, stderr_bytes


class GitEngine:
    """Isolated Git operations confined strictly to approved local project roots."""

    @staticmethod
    def assert_repo_root(root: Path) -> Path:
        resolved = root.resolve(strict=True)
        if not (resolved / ".git").exists():
            raise GitEngineError("GIT_NOT_A_REPOSITORY", "Project root is not a Git repository root (.git missing).")
        code, out, err = _run_git(resolved, ["rev-parse", "--show-toplevel"])
        if code != 0:
            msg = err.decode("utf-8", errors="replace").strip() or "Failed to verify git toplevel."
            raise GitEngineError("GIT_NOT_A_REPOSITORY", msg)
        toplevel = Path(out.decode("utf-8", errors="replace").strip()).resolve()
        if os.path.normcase(str(toplevel)) != os.path.normcase(str(resolved)):
            raise GitEngineError(
                "GIT_BOUNDARY_MISMATCH",
                "Git repository top-level escapes or differs from the approved project root.",
            )
        return resolved

    def _resolve_head(self, root: Path) -> tuple[str | None, str | None]:
        code_ref, out_ref, _ = _run_git(root, ["symbolic-ref", "--short", "HEAD"])
        branch = out_ref.decode("utf-8", errors="replace").strip() if code_ref == 0 else None
        code_sha, out_sha, _ = _run_git(root, ["rev-parse", "--verify", "HEAD"])
        head_sha = out_sha.decode("utf-8", errors="replace").strip() if code_sha == 0 else None
        return branch, head_sha

    def status(self, root: Path, *, max_entries: int = 200) -> dict:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or not 1 <= max_entries <= 1000:
            raise GitEngineError("INVALID_ARGUMENT", "max_entries must be between 1 and 1000.")
        resolved = self.assert_repo_root(root)
        # Single git status --porcelain=v2 call returns branch, HEAD oid, upstream, and working tree entries
        code, out, err = _run_git(resolved, ["status", "--porcelain=v2", "--branch", "-z", "--untracked-files=all"])
        if code != 0:
            raise GitEngineError("GIT_COMMAND_FAILED", err.decode("utf-8", errors="replace").strip() or "git status failed.")
        tokens = out.split(b"\x00")
        branch: str | None = None
        head_sha: str | None = None
        upstream: str | None = None
        ab_suffix = ""
        entries: list[dict[str, str]] = []
        idx = 0
        truncated = False
        while idx < len(tokens):
            tok = tokens[idx]
            idx += 1
            if not tok:
                continue
            line = tok.decode("utf-8", errors="replace")
            if line.startswith("# "):
                if line.startswith("# branch.oid "):
                    val = line[13:].strip()
                    head_sha = None if val == "(initial)" else val
                elif line.startswith("# branch.head "):
                    val = line[14:].strip()
                    branch = None if val == "(detached)" else val
                elif line.startswith("# branch.upstream "):
                    upstream = line[18:].strip()
                elif line.startswith("# branch.ab "):
                    ab_suffix = f" [{line[12:].strip()}]"
                continue
            entry: dict[str, str] | None = None
            if line.startswith("1 "):
                parts = line.split(" ", 8)
                if len(parts) == 9:
                    entry = {"xy": parts[1].replace(".", " "), "path": parts[8]}
            elif line.startswith("2 "):
                parts = line.split(" ", 9)
                if len(parts) == 10:
                    orig_path = tokens[idx].decode("utf-8", errors="replace") if idx < len(tokens) else ""
                    if idx < len(tokens):
                        idx += 1
                    entry = {"xy": parts[1].replace(".", " "), "path": parts[9], "orig_path": orig_path}
            elif line.startswith("u "):
                parts = line.split(" ", 10)
                if len(parts) == 11:
                    entry = {"xy": parts[1].replace(".", " "), "path": parts[10]}
            elif line.startswith("? "):
                entry = {"xy": "??", "path": line[2:]}
            if entry is not None:
                if len(entries) >= max_entries:
                    truncated = True
                    break
                entries.append(entry)
        if head_sha is None and branch:
            branch_header = f"No commits yet on {branch}"
        elif branch and upstream:
            branch_header = f"{branch}...{upstream}{ab_suffix}"
        elif branch:
            branch_header = branch
        else:
            branch_header = "HEAD (no branch)"
        return {
            "branch": branch,
            "head": head_sha,
            "branch_header": branch_header,
            "clean": len(entries) == 0,
            "entries": entries,
            "entry_count": len(entries),
            "truncated": truncated,
        }

    def diff(
        self,
        root: Path,
        *,
        base_ref: str | None = None,
        staged: bool = False,
        paths: list[str] | None = None,
        offset: int = 0,
        limit: int = 32768,
    ) -> dict:
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise GitEngineError("INVALID_ARGUMENT", "offset must be non-negative.")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 65536:
            raise GitEngineError("INVALID_ARGUMENT", "limit must be between 1 and 65536.")
        if not isinstance(staged, bool):
            raise GitEngineError("INVALID_ARGUMENT", "staged must be a boolean.")
        resolved = self.assert_repo_root(root)
        cmd = ["diff", "--no-ext-diff", "--no-textconv"]
        if staged:
            cmd.append("--cached")
        if base_ref is not None:
            checked_ref = _validate_ref(base_ref)
            code_v, _, err_v = _run_git(resolved, ["rev-parse", "--verify", "--end-of-options", checked_ref])
            if code_v != 0:
                raise GitEngineError(
                    "INVALID_ARGUMENT",
                    err_v.decode("utf-8", errors="replace").strip() or "base_ref could not be resolved.",
                )
            cmd.append(checked_ref)
        checked_paths = _validate_rel_paths(paths)
        if checked_paths:
            cmd.append("--")
            cmd.extend(checked_paths)
        else:
            cmd.append("--")
            cmd.append(".")
            cmd.extend(_DIFF_SECRET_EXCLUDES)
        code, out, err = _run_git(resolved, cmd)
        if code != 0:
            raise GitEngineError("GIT_COMMAND_FAILED", err.decode("utf-8", errors="replace").strip() or "git diff failed.")
        text = out.decode("utf-8", errors="replace")
        end = offset + limit
        return {
            "base_ref": base_ref,
            "staged": staged,
            "content": text[offset:end],
            "diff_sha256": hashlib.sha256(out).hexdigest(),
            "total_bytes": len(out),
            "total_chars": len(text),
            "offset": offset,
            "next_offset": end if end < len(text) else None,
            "truncated": end < len(text),
        }

    def checkpoint(
        self,
        root: Path,
        task_id: str,
        checkpoint_id: str,
        message: str = "",
    ) -> dict:
        if not isinstance(task_id, str) or not _SAFE_ID.fullmatch(task_id):
            raise GitEngineError("INVALID_ARGUMENT", "Invalid task_id for git checkpoint.")
        if not isinstance(checkpoint_id, str) or not _SAFE_ID.fullmatch(checkpoint_id):
            raise GitEngineError("INVALID_ARGUMENT", "Invalid checkpoint_id for git checkpoint.")
        if not isinstance(message, str) or len(message) > 2000:
            raise GitEngineError("INVALID_ARGUMENT", "Checkpoint message must be <= 2000 characters.")
        resolved = self.assert_repo_root(root)
        _, head_sha = self._resolve_head(resolved)
        ref_name = f"refs/edge-bridge/checkpoints/{task_id}/{checkpoint_id}"
        commit_msg = message.strip() or f"Edge Bridge checkpoint {task_id}/{checkpoint_id}"

        with tempfile.TemporaryDirectory(prefix="edge-git-idx-") as tmpdir:
            temp_index = Path(tmpdir) / "index"
            real_index = resolved / ".git" / "index"
            if real_index.is_file():
                shutil.copy2(real_index, temp_index)
            idx_env = {
                "GIT_INDEX_FILE": str(temp_index),
                "GIT_AUTHOR_NAME": "Edge Project Bridge",
                "GIT_AUTHOR_EMAIL": "bridge@localhost",
                "GIT_COMMITTER_NAME": "Edge Project Bridge",
                "GIT_COMMITTER_EMAIL": "bridge@localhost",
            }
            c_add, _, e_add = _run_git(
                resolved,
                ["add", "--all", "--", ".", ":(exclude).edge-project-bridge"],
                extra_env=idx_env,
            )
            if c_add != 0:
                raise GitEngineError("GIT_COMMAND_FAILED", e_add.decode("utf-8", errors="replace").strip() or "git add failed.")
            c_tree, out_tree, e_tree = _run_git(resolved, ["write-tree"], extra_env=idx_env)
            if c_tree != 0:
                raise GitEngineError("GIT_COMMAND_FAILED", e_tree.decode("utf-8", errors="replace").strip() or "git write-tree failed.")
            tree_sha = out_tree.decode("utf-8", errors="replace").strip()
            commit_args = ["commit-tree", tree_sha]
            if head_sha:
                commit_args.extend(["-p", head_sha])
            commit_args.extend(["-m", commit_msg])
            c_com, out_com, e_com = _run_git(resolved, commit_args, extra_env=idx_env)
            if c_com != 0:
                raise GitEngineError("GIT_COMMAND_FAILED", e_com.decode("utf-8", errors="replace").strip() or "git commit-tree failed.")
            commit_sha = out_com.decode("utf-8", errors="replace").strip()
            c_ref, _, e_ref = _run_git(resolved, ["update-ref", ref_name, commit_sha])
            if c_ref != 0:
                raise GitEngineError("GIT_COMMAND_FAILED", e_ref.decode("utf-8", errors="replace").strip() or "git update-ref failed.")
        return {
            "ref": ref_name,
            "commit_sha": commit_sha,
            "tree_sha": tree_sha,
            "parent_head": head_sha,
            "non_destructive": True,
        }

    def create_isolated_worktree(
        self,
        root: Path,
        worktree_path: Path,
        branch_name: str,
        *,
        base_ref: str = "HEAD",
    ) -> dict:
        if not isinstance(branch_name, str) or not _SAFE_BRANCH.fullmatch(branch_name):
            raise GitEngineError("INVALID_ARGUMENT", "branch_name must match edge-worker/<id>.")
        checked_base = _validate_ref(base_ref)
        resolved = self.assert_repo_root(root)
        target = worktree_path.resolve()
        try:
            target.relative_to(resolved)
        except ValueError:
            pass
        else:
            raise GitEngineError("INVALID_ARGUMENT", "Isolated worktree must live outside the project root.")
        if target.exists():
            raise GitEngineError("VERSION_CONFLICT", "Target isolated worktree path already exists.")
        target.parent.mkdir(parents=True, exist_ok=True)
        code, _, err = _run_git(resolved, ["worktree", "add", "-b", branch_name, str(target), checked_base])
        if code != 0:
            raise GitEngineError("GIT_COMMAND_FAILED", err.decode("utf-8", errors="replace").strip() or "git worktree add failed.")
        return {"worktree": str(target), "branch": branch_name, "base_ref": checked_base}

    def integrate_ref(
        self,
        root: Path,
        source_ref: str,
        *,
        dry_run: bool = True,
        expected_head: str | None = None,
    ) -> dict:
        if not isinstance(dry_run, bool):
            raise GitEngineError("INVALID_ARGUMENT", "dry_run must be a boolean.")
        checked_ref = _validate_ref(source_ref, allow_head=False)
        resolved = self.assert_repo_root(root)
        _, head_sha = self._resolve_head(resolved)
        if expected_head is not None:
            if not head_sha or head_sha.casefold() != expected_head.strip().casefold():
                raise GitEngineError("VERSION_CONFLICT", "Repository HEAD changed before integration.")
        code_src, out_src, err_src = _run_git(resolved, ["rev-parse", "--verify", "--end-of-options", checked_ref])
        if code_src != 0:
            raise GitEngineError("NOT_FOUND", err_src.decode("utf-8", errors="replace").strip() or "Source ref not found.")
        source_sha = out_src.decode("utf-8", errors="replace").strip()
        status_info = self.status(resolved, max_entries=50)
        if not status_info["clean"]:
            raise GitEngineError("VERSION_CONFLICT", "Working tree must be clean before integrating a branch or ref.")
        can_ff = False
        if head_sha:
            c_anc, _, _ = _run_git(resolved, ["merge-base", "--is-ancestor", head_sha, source_sha])
            can_ff = c_anc == 0
        if dry_run:
            return {
                "dry_run": True,
                "source_ref": checked_ref,
                "source_sha": source_sha,
                "head_sha": head_sha,
                "fast_forward_possible": can_ff,
                "working_tree_clean": True,
                "applied": False,
            }
        if not can_ff and head_sha is not None:
            raise GitEngineError(
                "MERGE_REQUIRES_FAST_FORWARD",
                "Only clean fast-forward integration is enabled automatically; resolve divergence locally first.",
            )
        c_m, _, e_m = _run_git(resolved, ["merge", "--ff-only", "--", source_sha])
        if c_m != 0:
            raise GitEngineError("GIT_COMMAND_FAILED", e_m.decode("utf-8", errors="replace").strip() or "git merge failed.")
        _, new_head = self._resolve_head(resolved)
        return {
            "dry_run": False,
            "source_ref": checked_ref,
            "source_sha": source_sha,
            "previous_head": head_sha,
            "new_head": new_head,
            "applied": True,
        }
