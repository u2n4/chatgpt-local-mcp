"""Pinned Windows MXC launch paths for the bundled local recipes."""
from __future__ import annotations

import ctypes as ct
from ctypes import wintypes as wt
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import Callable
from uuid import uuid4

import ntsecuritycon
import pywintypes
import win32con
import win32event
import win32file
import win32job
import win32pipe
import win32process

VERSION = "0.171.0"
CODEX_SHA256 = "cefea4ffee1fff04983a99c0dda99944d8b380e891e740a28b32f4b815a6e0b7"
PYTHON_ARGS = ("-I", "-S", "-B", "-m", "unittest", "-v")
PROJECT_TEST_ARGS = ("-I", "-S", "-B", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v")
MAX_TEST_PROCESSES = 8
MAX_TEST_MEMORY = 768 * 1024 * 1024
MAX_TEST_LOG_BYTES = 256 * 1024
MAX_WORKSPACE_BYTES = 256 * 1024 * 1024
MAX_WORKSPACE_ENTRIES = 16_384
BLENDER_SHA256 = "739a8167f81fc3dbcabaa448bb5335923b04c91f9a2408fd979c778e14d3d642"
NODE_SHA256 = "14319838b3f355e0398c13569a90270bce4fc68f25189f58c59b03dadae0e6d5"
POWERSHELL_SHA256 = "e94166ed9f376559c1359bafb08bc49e463a494c330f67644ec1d9f1ffeb5ee5"
GIT_SHA256 = "20d0dde30a65afb6e5810a883700a94dcd77fbf3b44b32868d45bf7c9b30137c"
NODE_TEST_ARGS = ("--preserve-symlinks", "--preserve-symlinks-main", "--test", "--test-concurrency=1",
                  "tests/*.test.mjs")
PROJECT_RECIPES = {"project_tests", "node_tests", "powershell_script"}
CANARY = '''
from pathlib import Path
import os, socket, sys
outside, created, port = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
assert Path(sys.argv[4]).exists()
probe = Path("contained-write.txt")
probe.write_text("inside")
assert probe.read_text() == "inside"
probe.unlink()
for label, attempt in (
    ("read", outside.read_bytes),
    ("write", lambda: created.write_bytes(b"synthetic")),
    ("hardlink", lambda: os.link(outside, "forbidden-external-link")),
):
    try:
        attempt()
    except PermissionError:
        print(label + ": denied", flush=True)
    else:
        raise RuntimeError(label + ": external path unexpectedly accessible")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.settimeout(1)
    assert client.connect_ex(("127.0.0.1", port)) == 10013, "loopback not denied"
print("EDGE_BRIDGE_CONTAINMENT_OK", flush=True)
'''
PROJECT_TEST_CANARY = '''
import subprocess
from pathlib import Path

readonly, ipv6_port, local_pipe = Path(sys.argv[5]), int(sys.argv[6]), sys.argv[7]
assert readonly.read_bytes() == b"read-only canary"
assert os.getenv("CONTROL_PLANE_API_KEY") is None and os.getenv("OPENAI_API_KEY") is None
for label, operation in (
    ("runtime_write", lambda: readonly.write_bytes(b"attempted canary write")),
    ("runtime_link", lambda: os.link(readonly, "forbidden-runtime-link")),
    ("ipc", lambda: os.open(local_pipe, os.O_RDWR | os.O_BINARY)),
):
    try:
        operation()
    except PermissionError:
        print(label + ": denied", flush=True)
    else:
        raise RuntimeError(label + ": unexpected access")
with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as ipv6:
    ipv6.settimeout(1)
    assert ipv6.connect_ex(("::1", ipv6_port)) == 10013
child_code = "from pathlib import Path; import sys; Path(sys.argv[1]).read_bytes()"
child = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", child_code, str(outside)],
                       capture_output=True, timeout=5)
assert child.returncode and b"PermissionError" in child.stderr
print("EDGE_BRIDGE_PROJECT_TEST_SCOPE_OK", flush=True)
'''


class RunnerBlocked(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _blocked(message: str) -> RunnerBlocked:
    return RunnerBlocked("ISOLATION_NOT_VERIFIED", message)


def _codex_path() -> Path:
    return Path(os.environ["APPDATA"]) / (
        "npm/node_modules/@openai/codex/node_modules/@openai/codex-win32-x64/"
        "vendor/x86_64-pc-windows-msvc/bin/codex.exe"
    )


def _python_path() -> Path:
    return Path(sys._base_executable).resolve(strict=True)


def _blender_path() -> Path:
    return Path(os.environ["ProgramFiles"]) / "Blender Foundation" / "Blender 5.3" / "blender.exe"


def _node_path() -> Path:
    return Path(os.environ["ProgramFiles"]) / "nodejs" / "node.exe"


def _powershell_path() -> Path:
    return Path(os.environ["ProgramFiles"]) / "PowerShell" / "7" / "pwsh.exe"


def git_path() -> Path:
    return Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "cmd" / "git.exe"


def thread_desktop_name() -> str | None:
    """Return the active WinSta\\Desktop name for MXC desktop-ACL diagnostics."""
    if os.name != "nt":
        return None
    try:
        user32 = ct.WinDLL("user32", use_last_error=True)
        kernel32 = ct.WinDLL("kernel32", use_last_error=True)
        user32.GetUserObjectInformationW.argtypes = [wt.HANDLE, ct.c_int, wt.LPVOID, wt.DWORD, ct.POINTER(wt.DWORD)]
        user32.GetUserObjectInformationW.restype = wt.BOOL
        user32.GetThreadDesktop.argtypes = [wt.DWORD]
        user32.GetThreadDesktop.restype = wt.HANDLE
        user32.GetProcessWindowStation.argtypes = []
        user32.GetProcessWindowStation.restype = wt.HANDLE
        kernel32.GetCurrentThreadId.argtypes = []
        kernel32.GetCurrentThreadId.restype = wt.DWORD

        def _obj_name(handle) -> str | None:
            if not handle:
                return None
            buf = ct.create_unicode_buffer(256)
            needed = wt.DWORD()
            if user32.GetUserObjectInformationW(handle, 2, buf, ct.sizeof(buf), ct.byref(needed)):
                return buf.value
            return None

        winsta = _obj_name(user32.GetProcessWindowStation())
        desk = _obj_name(user32.GetThreadDesktop(kernel32.GetCurrentThreadId()))
        if winsta and desk:
            return f"{winsta}\\{desk}"
        return desk or winsta
    except Exception:
        return None


def _verify_pinned_binary(path: Path, expected_sha256: str, label: str) -> str:
    if not path.is_file():
        raise _blocked(f"The pinned {label} executable is not installed.")
    with path.open("rb") as executable:
        digest = hashlib.file_digest(executable, "sha256").hexdigest()
    if digest != expected_sha256:
        raise _blocked(f"The pinned {label} executable changed.")
    return digest


@contextmanager
def _locked_pinned_binary(path: Path, expected_sha256: str, label: str = "Codex"):
    """Hold the exact image and its resolved path in place through process creation."""
    with ExitStack() as handles:
        try:
            resolved = path.resolve(strict=True)
            # Disallow directory renames while CreateProcessW resolves the same path.
            for ancestor in reversed(resolved.parents):
                if ancestor == Path(resolved.anchor):
                    continue
                directory = win32file.CreateFile(
                    str(ancestor), ntsecuritycon.FILE_LIST_DIRECTORY,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
                    win32con.OPEN_EXISTING,
                    win32con.FILE_FLAG_BACKUP_SEMANTICS | win32file.FILE_FLAG_OPEN_REPARSE_POINT, None,
                )
                handles.callback(directory.Close)
                if win32file.GetFileInformationByHandle(directory)[0] & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise _blocked(f"The resolved {label} executable path changed.")
            executable = win32file.CreateFile(
                str(resolved), win32con.GENERIC_READ, win32con.FILE_SHARE_READ, None,
                win32con.OPEN_EXISTING, win32file.FILE_FLAG_OPEN_REPARSE_POINT, None,
            )
            handles.callback(executable.Close)
            attributes = win32file.GetFileInformationByHandle(executable)[0]
            if attributes & (win32con.FILE_ATTRIBUTE_REPARSE_POINT | win32con.FILE_ATTRIBUTE_DIRECTORY):
                raise _blocked(f"The resolved {label} executable is not a regular file.")
            final_path = Path(win32file.GetFinalPathNameByHandle(executable, 0))
            if final_path != Path("\\\\?\\" + str(resolved)):
                raise _blocked(f"The resolved {label} executable path changed.")
            digest = hashlib.sha256()
            while data := win32file.ReadFile(executable, 1024 * 1024)[1]:
                digest.update(data)
            if digest.hexdigest() != expected_sha256:
                raise _blocked(f"{label} executable hash changed. A new build requires containment review.")
        except (OSError, pywintypes.error) as error:
            raise _blocked(f"The pinned {label} executable could not be locked and verified.") from error
        yield str(resolved)


def workspace_over_limit(workspace: Path, limit: int, cancelled: threading.Event) -> bool:
    """Bound each scan and count regular file bytes without traversing reparse points."""
    entries = total = 0

    pending = [workspace]
    while pending and not cancelled.is_set():
        directory = pending.pop()
        try:
            info = directory.lstat()
            if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                return True
            with os.scandir(directory) as listing:
                for entry in listing:
                    if cancelled.is_set():
                        return False
                    entries += 1
                    if entries > MAX_WORKSPACE_ENTRIES:
                        return True
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                        return True
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(Path(entry.path))
                    else:
                        total += info.st_size
                        if total > limit:
                            return True
        except FileNotFoundError:
            if directory == workspace:
                raise
    return False


def _validate_entry_script(workspace: Path, entry_script: str | None) -> Path:
    if not isinstance(entry_script, str) or not entry_script or "\\" in entry_script:
        raise _blocked("PowerShell recipe requires a relative forward-slash .ps1 entry_script.")
    if Path(entry_script).is_absolute() or ".." in Path(entry_script).parts:
        raise _blocked("PowerShell entry_script must remain inside the workspace.")
    if not entry_script.casefold().endswith(".ps1"):
        raise _blocked("PowerShell entry_script must end with .ps1.")
    candidate = workspace / entry_script
    if not candidate.is_file():
        raise _blocked("The requested PowerShell entry_script is missing from the job snapshot.")
    return candidate


def diagnose() -> dict:
    desktop = thread_desktop_name()
    non_default_desktop = bool(desktop and not desktop.casefold().endswith("\\default"))
    return {
        "execution": {
            "implemented": True, "scope": "local_bundled_recipes_and_owner_granted_project_tests",
            "recipes": ["calculator", "blender_knot", "project_tests", "node_tests", "powershell_script"],
            "condition": "pinned_mxc_and_per_job_containment_probe",
            "backend": "codex-sandbox-mxc", "codex_version_pin": VERSION,
            "vendor_executable_present": _codex_path().is_file(),
            "powershell_executable_present": _powershell_path().is_file(),
            "node_executable_present": _node_path().is_file(),
            "git_executable_present": git_path().is_file(),
            "desktop_name": desktop,
            "mxc_non_default_desktop_warning": non_default_desktop,
            "automatic_weaker_fallback": False,
        },
        "workers": {
            "enabled": False, "status": "BLOCKED", "code": "WORKER_CAPABILITY_NOT_VERIFIED",
            "whole_worker_isolation_verified": False, "included_usage_only_verified": False,
            "billing_policy": "INCLUDED_ONLY",
        },
        "computer_use": {"implemented": False, "attempted": False},
        "billing": {"model_api_enabled": False, "paid_fallback_enabled": False, "automatic_purchase_enabled": False},
    }


def require_execution() -> None:
    if os.name != "nt" or not _codex_path().is_file():
        raise _blocked("The pinned Windows MXC executable is not installed.")


def require_workers() -> None:
    raise RunnerBlocked("WORKER_CAPABILITY_NOT_VERIFIED", "Worker tool isolation and included-only use are unverified.")


def _profile(workspace: Path, python: Path, extra_runtime: Path | None = None,
             readonly_probe: Path | None = None) -> str:
    runtime, work = json.dumps(python.parent.as_posix()), json.dumps(workspace.as_posix())
    additional_read = "".join(json.dumps(path.as_posix()) + ' = "read"\n'
                              for path in (extra_runtime, readonly_probe) if path is not None)
    return f"""default_permissions = "bridge-task"
[windows]
sandbox = "mxc"
[permissions.bridge-task]
extends = ":workspace"
[permissions.bridge-task.workspace_roots]
{work} = true
[permissions.bridge-task.filesystem]
":root" = "deny"
":minimal" = "read"
":workspace_roots" = "write"
":tmpdir" = "deny"
":slash_tmp" = "deny"
{runtime} = "read"
{additional_read}[permissions.bridge-task.network]
enabled = false
"""


def _environment(control: Path) -> dict[str, str]:
    keys = ("SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "USERPROFILE",
            "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "USERNAME",
            "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "OS")
    clean = {key: os.environ[key] for key in keys if key in os.environ}
    clean["CODEX_HOME"] = str(control / "codex-home")
    clean["TEMP"] = clean["TMP"] = str(control / "tmp")
    clean["PATH"] = str(Path(clean["SYSTEMROOT"]) / "System32")
    return clean


def _command(workspace: Path, args: tuple[str, ...], executable: Path | None = None) -> list[str]:
    return [str(_codex_path()), "-c", "windows.sandbox=mxc", "sandbox", "--include-managed-config",
            "--permission-profile", "bridge-task", "-C", str(workspace), "--",
            str(executable or _python_path()), *args]


def _payload_command(workspace: Path, recipe: str, entry_script: str | None = None) -> list[str]:
    if recipe == "calculator":
        return _command(workspace, PYTHON_ARGS)
    if recipe == "project_tests":
        return _command(workspace, PROJECT_TEST_ARGS)
    if recipe == "node_tests":
        return _command(workspace, NODE_TEST_ARGS, _node_path())
    if recipe == "powershell_script":
        script_path = _validate_entry_script(workspace, entry_script)
        ps_args = ("-NoProfile", "-NonInteractive", "-File", str(script_path))
        return _command(workspace, ps_args, _powershell_path())
    if recipe == "blender_knot":
        blender_args = ("--background", "--factory-startup", "--disable-autoexec", "--threads", "1",
                        "--python-exit-code", "9", "--python", str(workspace / "build_knot.py"))
        return _command(workspace, blender_args, _blender_path())
    raise _blocked("Unknown local recipe.")


def resolve_job_limits(job_limits: dict[str, int] | None = None) -> dict[str, int]:
    defaults = {
        "memory_bytes": MAX_TEST_MEMORY,
        "processes": MAX_TEST_PROCESSES,
        "log_bytes": MAX_TEST_LOG_BYTES,
    }
    if job_limits is None:
        return defaults
    if not isinstance(job_limits, dict):
        raise RunnerBlocked("INVALID_GRANT_LIMITS", "Job limits must be a mapping.")
    unknown = set(job_limits) - set(defaults)
    if unknown:
        raise RunnerBlocked("INVALID_GRANT_LIMITS", f"Unknown job limits: {', '.join(sorted(unknown))}.")
    resolved = {}
    for key, maximum in defaults.items():
        value = job_limits.get(key, maximum)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise RunnerBlocked("INVALID_GRANT_LIMITS", f"Job limit '{key}' must be a positive integer.")
        if value > maximum:
            raise RunnerBlocked("INVALID_GRANT_LIMITS", f"Job limit '{key}' exceeds the recipe cap.")
        resolved[key] = value
    return resolved


class OwnedProcess:
    def __init__(self, process, job, *, log_limit: int = MAX_TEST_LOG_BYTES):
        self.process = process
        self.job = job
        self.log_limit = log_limit
        self.image_locks = ExitStack()
        self.capture_thread: threading.Thread | None = None
        self.capture_error: str | None = None

    def capture(self, reader, path: Path) -> None:
        self.capture_thread = threading.Thread(target=self._drain, args=(reader, path), daemon=True)
        self.capture_thread.start()

    def _drain(self, reader, path: Path) -> None:
        try:
            with path.open("xb") as output:
                remaining = self.log_limit
                while True:
                    try:
                        _, data = win32file.ReadFile(reader, 8192)
                    except pywintypes.error as error:
                        if error.winerror == 109:  # ERROR_BROKEN_PIPE at end of stream
                            break
                        raise
                    if not data:
                        break
                    output.write(data[:remaining])
                    if len(data) > remaining:
                        self.capture_error = "JOB_LOG_LIMIT_EXCEEDED"
                        self.cancel()
                        break
                    remaining -= len(data)
        except (OSError, pywintypes.error):
            self.capture_error = "JOB_LOG_CAPTURE_FAILED"
            self.cancel()
        finally:
            reader.Close()

    def poll(self) -> int | None:
        if win32event.WaitForSingleObject(self.process, 0) == win32con.WAIT_TIMEOUT:
            return None
        return win32process.GetExitCodeProcess(self.process)

    def wait(self, timeout: float | None = None) -> int:
        milliseconds = win32event.INFINITE if timeout is None else max(0, int(timeout * 1000))
        if win32event.WaitForSingleObject(self.process, milliseconds) == win32con.WAIT_TIMEOUT:
            raise TimeoutError("Owned Windows process is still running.")
        return win32process.GetExitCodeProcess(self.process)

    def cancel(self) -> None:
        win32job.TerminateJobObject(self.job, 1)

    def close(self) -> None:
        try:
            end = time.monotonic() + 5
            while win32job.QueryInformationJobObject(self.job, win32job.JobObjectBasicAccountingInformation)["ActiveProcesses"]:
                if time.monotonic() >= end:
                    raise RunnerBlocked("JOB_EXIT_UNCONFIRMED", "Windows did not confirm job-tree termination.")
                self.cancel()
                time.sleep(0.025)
            if self.capture_thread is not None:
                self.capture_thread.join(5)
                if self.capture_thread.is_alive():
                    raise RunnerBlocked("JOB_EXIT_UNCONFIRMED", "The owned output pipe did not close.")
        finally:
            try:
                self.job.Close()
                self.process.Close()
            finally:
                self.image_locks.close()


class _StartupInfo(ct.Structure):
    _fields_ = [("cb", wt.DWORD), ("reserved", wt.LPWSTR), ("desktop", wt.LPWSTR),
                ("title", wt.LPWSTR), ("x", wt.DWORD), ("y", wt.DWORD), ("x_size", wt.DWORD),
                ("y_size", wt.DWORD), ("x_chars", wt.DWORD), ("y_chars", wt.DWORD),
                ("fill", wt.DWORD), ("flags", wt.DWORD), ("show", wt.WORD),
                ("reserved_size", wt.WORD), ("reserved_bytes", ct.c_void_p),
                ("stdin", wt.HANDLE), ("stdout", wt.HANDLE), ("stderr", wt.HANDLE)]


class _StartupInfoEx(ct.Structure):
    _fields_ = [("startup", _StartupInfo), ("attributes", ct.c_void_p)]


class _ProcessInfo(ct.Structure):
    _fields_ = [("process", wt.HANDLE), ("thread", wt.HANDLE),
                ("process_id", wt.DWORD), ("thread_id", wt.DWORD)]


def _create_contained_process(argv, workspace, control, job, stdin, output, before_create=None):
    # Windows assigns the Job Object during creation. A broker crash cannot leave
    # a newly created suspended process outside the job.
    kernel = ct.WinDLL("kernel32", use_last_error=True)
    size_type = ct.c_size_t
    kernel.InitializeProcThreadAttributeList.argtypes = [ct.c_void_p, wt.DWORD, wt.DWORD, ct.POINTER(size_type)]
    kernel.InitializeProcThreadAttributeList.restype = wt.BOOL
    kernel.UpdateProcThreadAttribute.argtypes = [
        ct.c_void_p, wt.DWORD, size_type, ct.c_void_p, size_type, ct.c_void_p, ct.c_void_p,
    ]
    kernel.UpdateProcThreadAttribute.restype = wt.BOOL
    kernel.DeleteProcThreadAttributeList.argtypes = [ct.c_void_p]
    kernel.DeleteProcThreadAttributeList.restype = None
    kernel.CreateProcessW.argtypes = [
        wt.LPCWSTR, wt.LPWSTR, ct.c_void_p, ct.c_void_p, wt.BOOL, wt.DWORD,
        ct.c_void_p, wt.LPCWSTR, ct.POINTER(_StartupInfoEx), ct.POINTER(_ProcessInfo),
    ]
    kernel.CreateProcessW.restype = wt.BOOL
    size = size_type()
    kernel.InitializeProcThreadAttributeList(None, 2, 0, ct.byref(size))
    if not size.value:
        raise ct.WinError(ct.get_last_error())
    attributes = ct.create_string_buffer(size.value)
    if not kernel.InitializeProcThreadAttributeList(attributes, 2, 0, ct.byref(size)):
        raise ct.WinError(ct.get_last_error())
    try:
        job_list = (wt.HANDLE * 1)(int(job))
        handle_list = (wt.HANDLE * 2)(int(stdin), int(output))
        for attribute, handles in (
            (0x0002000D, job_list),  # PROC_THREAD_ATTRIBUTE_JOB_LIST
            (0x00020002, handle_list),  # PROC_THREAD_ATTRIBUTE_HANDLE_LIST
        ):
            if not kernel.UpdateProcThreadAttribute(attributes, 0, attribute, handles, ct.sizeof(handles), None, None):
                raise ct.WinError(ct.get_last_error())
        startup = _StartupInfoEx()
        startup.startup.cb = ct.sizeof(startup)
        startup.startup.flags = win32con.STARTF_USESTDHANDLES
        startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = int(stdin), int(output), int(output)
        startup.attributes = ct.addressof(attributes)
        details = _ProcessInfo()
        values = _environment(control)
        environment = ct.create_unicode_buffer("\0".join(f"{k}={v}" for k, v in sorted(values.items())) + "\0\0")
        extended_startup = 0x00080000
        flags = win32con.CREATE_SUSPENDED | win32process.CREATE_NO_WINDOW | win32con.CREATE_UNICODE_ENVIRONMENT
        with ExitStack() as image:
            if Path(argv[0]) == _codex_path():
                executable = image.enter_context(_locked_pinned_binary(Path(argv[0]), CODEX_SHA256))
                argv = [executable, *argv[1:]]
            command_line = ct.create_unicode_buffer(subprocess.list2cmdline(argv))
            if before_create is not None:
                before_create()
            if not kernel.CreateProcessW(argv[0], command_line, None, None, True, flags | extended_startup,
                                         environment, str(workspace), ct.byref(startup), ct.byref(details)):
                error = ct.get_last_error()
                raise ct.WinError(error)
        return pywintypes.HANDLE(details.process), pywintypes.HANDLE(details.thread)
    finally:
        kernel.DeleteProcThreadAttributeList(attributes)


def _launch(argv: list[str], workspace: Path, control: Path, log_file: Path,
            cancelled: threading.Event | None, *, limited: bool = False,
            before_create: Callable[[], None] | None = None,
            job_limits: dict[str, int] | None = None) -> OwnedProcess:
    if cancelled is not None and cancelled.is_set():
        raise RunnerBlocked("START_CANCELLED", "Job cancelled before process creation.")
    limits = resolve_job_limits(job_limits) if limited else None
    job = win32job.CreateJobObject(None, "")
    process = thread = output = stdin = reader = None
    try:
        config = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        config["BasicLimitInformation"]["LimitFlags"] = win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if limited:
            flags = win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | win32job.JOB_OBJECT_LIMIT_JOB_MEMORY
            config["BasicLimitInformation"]["LimitFlags"] |= flags
            config["BasicLimitInformation"]["ActiveProcessLimit"] = limits["processes"]
            config["JobMemoryLimit"] = limits["memory_bytes"]
        try:
            win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, config)
        except pywintypes.error as error:
            raise RunnerBlocked("INVALID_GRANT_LIMITS", "Windows rejected the requested job limits.") from error
        inherit = pywintypes.SECURITY_ATTRIBUTES()
        inherit.bInheritHandle = True
        if limited:
            reader, output = win32pipe.CreatePipe(inherit, 65536)
        else:
            output = win32file.CreateFile(str(log_file), win32con.GENERIC_WRITE, win32con.FILE_SHARE_READ,
                                          inherit, win32con.CREATE_NEW, win32con.FILE_ATTRIBUTE_NORMAL, None)
        stdin = win32file.CreateFile("NUL", win32con.GENERIC_READ, win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                                    inherit, win32con.OPEN_EXISTING, 0, None)
        def gate():
            if cancelled is not None and cancelled.is_set():
                raise RunnerBlocked("START_CANCELLED", "Job cancelled before process creation.")
            if before_create is not None:
                before_create()
            if cancelled is not None and cancelled.is_set():
                raise RunnerBlocked("START_CANCELLED", "Job cancelled before process creation.")

        process, thread = _create_contained_process(argv, workspace, control, job, stdin, output, gate)
        if not win32job.IsProcessInJob(process, job):
            raise _blocked("Windows did not confirm process ownership before resume.")
        if cancelled is not None and cancelled.is_set():
            raise RunnerBlocked("START_CANCELLED", "Job cancelled before process resume.")
        win32process.ResumeThread(thread)
        owned = OwnedProcess(process, job, log_limit=limits["log_bytes"] if limited else MAX_TEST_LOG_BYTES)
        if reader is not None:
            owned.capture(reader, log_file)
            reader = None
        return owned
    except BaseException:
        try:
            if process is not None:
                win32job.TerminateJobObject(job, 1)
                if win32event.WaitForSingleObject(process, 5000) != win32con.WAIT_OBJECT_0:
                    raise TimeoutError("Suspended process did not stop.")
        except Exception as error:
            raise RunnerBlocked("PROCESS_OWNERSHIP_UNCONFIRMED", "Could not verify failed startup cleanup.") from error
        finally:
            if process is not None:
                process.Close()
            job.Close()
        raise
    finally:
        for handle in (thread, output, stdin, reader):
            if handle is not None:
                handle.Close()


def prepare_recipe(workspace: Path, control: Path, recipe: str,
                   cancelled: threading.Event | None = None,
                   entry_script: str | None = None,
                   job_limits: dict[str, int] | None = None) -> dict:
    require_execution()
    if not workspace.is_absolute() or not control.is_absolute() or workspace.parent != control.parent or workspace == control:
        raise _blocked("Job workspace and controller must be isolated siblings.")
    if cancelled is not None and cancelled.is_set():
        raise RunnerBlocked("START_CANCELLED", "Job cancelled before containment preflight.")
    effective_limits = resolve_job_limits(job_limits) if (recipe in PROJECT_RECIPES or job_limits is not None) else None
    python = _python_path()
    payload = _payload_command(workspace, recipe, entry_script=entry_script)
    extra_runtime = None
    blender_digest = None
    node_digest = None
    powershell_digest = None
    if recipe == "blender_knot":
        blender = _blender_path()
        blender_digest = _verify_pinned_binary(blender, BLENDER_SHA256, "headless Blender")
        extra_runtime = blender.parent
    elif recipe == "node_tests":
        node = _node_path()
        node_digest = _verify_pinned_binary(node, NODE_SHA256, "Node")
        extra_runtime = node.parent
    elif recipe == "powershell_script":
        ps = _powershell_path()
        powershell_digest = _verify_pinned_binary(ps, POWERSHELL_SHA256, "PowerShell 7")
        extra_runtime = ps.parent
    profile_dir = control / "codex-home"
    profile_dir.mkdir()
    (control / "tmp").mkdir()
    config = profile_dir / "config.toml"
    strict_project = recipe in PROJECT_RECIPES
    readonly_probe = control / "read-only-canary.txt" if strict_project else None
    if readonly_probe:
        readonly_probe.write_bytes(b"read-only canary")
    config.write_text(_profile(workspace, python, extra_runtime, readonly_probe), encoding="utf-8")
    outside, outside_write = control / "outside-canary.txt", control / "outside-write-canary.txt"
    outside.write_bytes(b"outside synthetic fixture")
    probe_path = control / "containment.log"
    with ExitStack() as stack:
        listener = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        probe_file = "build_knot.py" if recipe == "blender_knot" else "calculator.py"
        if recipe == "project_tests":
            probe_file = "tests/__init__.py"
        elif recipe == "node_tests":
            probe_file = "tests"
        elif recipe == "powershell_script":
            probe_file = entry_script or "run.ps1"
        args = ("-I", "-S", "-B", "-c", CANARY + (PROJECT_TEST_CANARY if strict_project else ""),
                str(outside), str(outside_write),
                str(listener.getsockname()[1]), probe_file)
        if strict_project:
            ipv6 = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_STREAM))
            ipv6.bind(("::1", 0))
            ipv6.listen()
            synthetic_pipe = r"\\.\pipe\EdgeBridgeCanary-" + uuid4().hex
            pipe = win32pipe.CreateNamedPipe(synthetic_pipe, win32pipe.PIPE_ACCESS_DUPLEX,
                                           win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_WAIT, 1, 1024, 1024, 0, None)
            stack.callback(pipe.Close)
            args += (str(readonly_probe), str(ipv6.getsockname()[1]), synthetic_pipe)
        probe = _launch(_command(workspace, args), workspace, control, probe_path, cancelled, limited=strict_project)
        deadline = time.monotonic() + 20
        try:
            while probe.poll() is None:
                if cancelled is not None and cancelled.is_set():
                    raise RunnerBlocked("START_CANCELLED", "Job cancelled during containment preflight.")
                if time.monotonic() > deadline:
                    raise _blocked("MXC containment preflight timed out.")
                time.sleep(0.05)
            result = probe.wait(0)
        finally:
            probe.close()
    proof = probe_path.read_text(encoding="utf-8", errors="replace")
    if result != 0 or "EDGE_BRIDGE_CONTAINMENT_OK" not in proof.splitlines() or outside_write.exists():
        detail = proof.strip()[-1200:]
        raise _blocked(f"MXC containment preflight did not pass. Exit code: {result}. {detail}".rstrip())
    if strict_project and ("EDGE_BRIDGE_PROJECT_TEST_SCOPE_OK" not in proof.splitlines()
                           or readonly_probe.read_bytes() != b"read-only canary"):
        raise _blocked("The extended project-test preflight did not pass.")
    receipt = {
        "backend": "codex-sandbox-mxc", "codex_version": VERSION, "codex_sha256": CODEX_SHA256,
        "cwd": str(workspace), "writable_roots": [str(workspace)],
        "read_only_runtime": [str(python.parent), ":minimal"], "default_filesystem": "deny", "network": "disabled",
        "profile_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "managed_config_requested": True, "isolated_codex_home": True,
        "ownership": "windows_job_list_at_create_kill_on_close",
        "canaries": {"outside_read": "denied", "outside_write": "denied", "external_hardlink": "denied", "loopback": "denied"},
        "command": payload, "recipe": recipe,
    }
    if entry_script is not None:
        receipt["entry_script"] = entry_script
    if extra_runtime is not None:
        receipt["read_only_runtime"].append(str(extra_runtime))
    if blender_digest is not None:
        receipt["blender_sha256"] = blender_digest
    if node_digest is not None:
        receipt["node_sha256"] = node_digest
    if powershell_digest is not None:
        receipt["powershell_sha256"] = powershell_digest
    if strict_project:
        receipt["read_only_runtime"].append(str(readonly_probe))
        receipt["canaries"].update({"runtime_write": "denied", "runtime_hardlink": "denied",
                                   "ipv6_loopback": "denied", "host_named_pipe": "denied",
                                   "child_outside_read": "denied", "credential_environment": "absent"})
        receipt["job_limits"] = effective_limits
    (control / "verified-policy.json").write_text(json.dumps(receipt), encoding="utf-8")
    return receipt


def launch_recipe(workspace: Path, control: Path, log_file: Path, recipe: str,
                  cancelled: threading.Event | None = None,
                  entry_script: str | None = None,
                  before_create: Callable[[], None] | None = None,
                  job_limits: dict[str, int] | None = None) -> OwnedProcess:
    try:
        receipt = json.loads((control / "verified-policy.json").read_text(encoding="utf-8"))
        current = hashlib.sha256((control / "codex-home" / "config.toml").read_bytes()).hexdigest()
    except (OSError, ValueError) as error:
        raise _blocked("The job has no completed containment preflight.") from error
    expected_entry = entry_script if entry_script is not None else receipt.get("entry_script")
    if receipt.get("profile_sha256") != current or receipt.get("command") != _payload_command(workspace, recipe, entry_script=expected_entry):
        raise _blocked("The job policy changed after preflight.")
    limited = recipe in PROJECT_RECIPES
    effective_limits = None
    if limited:
        effective_limits = resolve_job_limits(job_limits if job_limits is not None else receipt.get("job_limits"))
        if job_limits is not None and "job_limits" in receipt and receipt["job_limits"] != effective_limits:
            raise _blocked("The job limits changed after preflight.")
    argv = receipt["command"]
    with ExitStack() as image:
        if recipe == "powershell_script":
            executable = image.enter_context(
                _locked_pinned_binary(_powershell_path(), POWERSHELL_SHA256, "PowerShell 7")
            )
            payload = argv.index("--") + 1
            argv = [*argv[:payload], executable, *argv[payload + 1:]]
        launch_options = {"job_limits": effective_limits} if effective_limits is not None else {}
        owned = _launch(argv, workspace, control, log_file, cancelled,
                        limited=limited, before_create=before_create, **launch_options)
        # Codex creates the PowerShell child asynchronously. Hold the pin until
        # the job tree exits so the resolved image cannot change before that launch.
        owned.image_locks = image.pop_all()
        return owned


def prepare_python_unittest(workspace: Path, control: Path) -> dict:
    return prepare_recipe(workspace, control, "calculator")

