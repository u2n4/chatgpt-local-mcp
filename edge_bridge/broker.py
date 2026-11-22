from __future__ import annotations

import hmac
import http.client
import ipaddress
import json
import logging
import msvcrt
import os
import secrets
import socket
import ssl
import stat
import threading
import time
from collections import deque
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pywintypes
import win32api
import win32con
import win32file
import win32security
from winerror import ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS

from . import __version__
from . import capabilities
from . import diagnostics
from . import runner
from .files import ProjectFiles
from .git_engine import GitEngine, GitEngineError
from .jobs import Jobs, validate_project_test_files
from .state import State
from .workers import WorkerError, WorkerManager, sample_host_resources

LOGGER = logging.getLogger(__name__)
MAX_REQUEST = 1_572_864
MAX_RESPONSE = 2_097_152
TOKEN_NAMES = {"local": "owner.token", "edge": "edge.token"}
API_VERSION = 1
EDGE_READ = "edge_read"
MAX_CLOCK_SKEW = 30
MAX_RECENT_NONCES = 32768
EDGE_SCOPED_ALLOWED_CAPS = frozenset({"read", "write", "checkpoint", "execute"})
EDGE_TOOL_REQUIRED_CAP = {
    "file_write": "write",
    "file_patch": "write",
    "task_checkpoint": "checkpoint",
    "process_start": "execute",
    "job_cancel": "execute",
    "job_output": "execute",
}
READ_TOOLS = frozenset({
    "bridge_info", "bridge_health", "connection_diagnostics",
    "project_list", "project_status", "project_resume", "task_get", "policy_view",
    "file_list", "file_read", "file_search", "file_view",
    "artifact_list", "artifact_read", "job_get", "job_output", "job_changes",
    "git_status", "git_diff", "worker_list",
})
MUTATION_TOOLS = frozenset({
    "file_write", "file_patch", "file_move", "file_delete", "task_checkpoint",
    "process_start", "process_input", "job_cancel",
    "git_checkpoint", "git_integrate",
    "worker_start", "worker_steer", "worker_cancel",
})


class BridgeError(RuntimeError):
    def __init__(self, code: str, message: str, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


def signature(token: str, purpose: str, principal: str, nonce: str, stamp: str,
              content: bytes) -> str:
    header = f"edge-project-bridge/v1|{purpose}|{principal}|{nonce}|{stamp}|".encode("ascii")
    return hmac.digest(bytes.fromhex(token), header + content, "sha256").hex()


def error_payload(error: Exception) -> dict:
    code = getattr(error, "code", None)
    if isinstance(code, str):
        return {"ok": False, "code": code, "message": str(error)[:500], **getattr(error, "details", {})}
    LOGGER.error("Bridge operation interrupted: %s", type(error).__name__)
    return {"ok": False, "code": "OPERATION_INTERRUPTED", "message": "Check local state before retrying."}


_SID_CACHE_LOCK = threading.Lock()
_CACHED_OWNER_SID = None
_CACHED_SYSTEM_SID = None
_CLIENT_TLS_LOCK = threading.Lock()
_CLIENT_TLS_CACHE: dict[str, tuple[tuple[int, int, int], ssl.SSLContext]] = {}


def _token_owner_information(info_class):
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        return win32security.GetTokenInformation(token, info_class)
    finally:
        token.Close()


def owner_sid():
    global _CACHED_OWNER_SID
    if _CACHED_OWNER_SID is None:
        with _SID_CACHE_LOCK:
            if _CACHED_OWNER_SID is None:
                _CACHED_OWNER_SID = _token_owner_information(win32security.TokenUser)[0]
    return _CACHED_OWNER_SID


def _system_sid():
    global _CACHED_SYSTEM_SID
    if _CACHED_SYSTEM_SID is None:
        with _SID_CACHE_LOCK:
            if _CACHED_SYSTEM_SID is None:
                _CACHED_SYSTEM_SID = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
    return _CACHED_SYSTEM_SID


def require_state_writer_token() -> None:
    if _token_owner_information(win32security.TokenOwner) != owner_sid():
        raise BridgeError(
            "STATE_TOKEN_OWNER_MISMATCH",
            "Open a standard PowerShell session for the owning account before starting the broker.",
        )


def protected_path(path: Path) -> None:
    attrs = path.lstat()
    if attrs.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise BridgeError("STATE_PATH_UNSAFE", "The control path is a Windows reparse point.")
    owner = owner_sid()
    system = _system_sid()
    descriptor = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
    )
    if descriptor.GetSecurityDescriptorOwner() != owner:
        raise BridgeError("STATE_ACL_UNSAFE", "The control path must be owned by this Windows account.")
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None or not 1 <= acl.GetAceCount() <= 2:
        raise BridgeError("STATE_ACL_UNSAFE", "The control ACL must allow only the owner and SYSTEM.")
    authorized = set()
    for index in range(acl.GetAceCount()):
        (kind, _flags), _rights, sid = acl.GetAce(index)
        if kind != win32security.ACCESS_ALLOWED_ACE_TYPE or sid not in (owner, system):
            raise BridgeError("STATE_ACL_UNSAFE", "Unexpected permission on the control path.")
        authorized.add(win32security.ConvertSidToStringSid(sid))
    if win32security.ConvertSidToStringSid(owner) not in authorized:
        raise BridgeError("STATE_ACL_UNSAFE", "The control ACL must explicitly allow the owner.")


def verify_state_path(state: Path) -> None:
    if not state.is_absolute() or not state.is_dir():
        raise BridgeError("STATE_NOT_INITIALIZED", "Initialize an absolute state directory with the installer.")
    for parent in state.parents:
        if parent.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise BridgeError("STATE_PATH_UNSAFE", "The control directory cannot use a reparse ancestor.")
    protected_path(state)
    for entry in state.iterdir():
        if entry.name == "jobs" and entry.is_dir():
            protected_path(entry)
            continue
        if not entry.is_file() or entry.lstat().st_nlink != 1:
            raise BridgeError("STATE_PATH_UNSAFE", "Unexpected entry in the dedicated state directory.")
        protected_path(entry)


def setup_state(state: Path) -> None:
    if not state.is_absolute() or not state.parent.is_dir():
        raise BridgeError("STATE_PATH_UNSAFE", "Use an absolute state path inside an existing parent.")
    for parent in (state.parent, *state.parent.parents):
        if parent.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise BridgeError("STATE_PATH_UNSAFE", "The control directory cannot use a reparse ancestor.")
    if state.exists():
        verify_state_path(state)
        return
    owner = win32security.ConvertSidToStringSid(owner_sid())
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"O:{owner}D:P(A;OICI;FA;;;{owner})(A;OICI;FA;;;SY)", win32security.SDDL_REVISION_1,
    )
    try:
        win32file.CreateDirectory(str(state), attributes)
    except pywintypes.error as error:
        if error.winerror not in {ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS}:
            raise
    verify_state_path(state)


@contextmanager
def exclusive_broker(state: Path):
    path = state / "broker.lock"
    with path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise BridgeError("BROKER_ALREADY_RUNNING", "Another broker owns this state.") from error
        try:
            yield
        finally:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def read_token(state: Path, principal: str) -> str:
    path = state / TOKEN_NAMES[principal]
    protected_path(path)
    if path.lstat().st_nlink != 1:
        raise BridgeError("AUTH_REQUIRED", "The token file must not be hard-linked.")
    token = path.read_text(encoding="ascii").strip()
    if len(token) != 64 or any(value not in "0123456789abcdef" for value in token):
        raise BridgeError("AUTH_REQUIRED", "The broker token is invalid.")
    return token


def create_tokens(state: Path) -> dict[str, str]:
    for name in TOKEN_NAMES.values():
        path = state / name
        if not path.exists():
            with path.open("x", encoding="ascii") as output:
                output.write(secrets.token_hex(32))
    tokens = {principal: read_token(state, principal) for principal in TOKEN_NAMES}
    if tokens["local"] == tokens["edge"]:
        raise BridgeError("STATE_ACL_UNSAFE", "Local and Edge credentials must be independent.")
    return tokens


def make_server_tls(state: Path) -> ssl.SSLContext:
    cert_file, key_file = state / "ipc.pem", state / "ipc-key.pem"
    if not cert_file.exists() and not key_file.exists():
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Edge Project Bridge local IPC")])
        now = datetime.now(UTC)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                .sign(key, hashes.SHA256()))
        with key_file.open("xb") as output:
            output.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        with cert_file.open("xb") as output:
            output.write(cert.public_bytes(serialization.Encoding.PEM))
    if not cert_file.is_file() or not key_file.is_file():
        raise BridgeError("STATE_TLS_INCOMPLETE", "The broker certificate and its key must both be present.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)
    return context


class Broker:
    def __init__(self, store: State, state_path: Path):
        self.store = store
        self.state_path = state_path
        self.lock = threading.RLock()
        self._telemetry_lock = threading.Lock()
        self._latency_samples: deque[tuple[str, str, bool, float]] = deque(maxlen=512)
        self._in_flight = 0
        self._peak_concurrent = 0
        self._total_requests = 0
        self.stopping = False
        self.jobs = Jobs(store, state_path, protected_path)
        self.git = GitEngine()
        self.workers = WorkerManager(store)

    def _enter_request(self) -> None:
        with self._telemetry_lock:
            self._in_flight += 1
            self._total_requests += 1
            if self._in_flight > self._peak_concurrent:
                self._peak_concurrent = self._in_flight

    def _exit_request(self, method: str, principal: str, ok: bool, duration_ms: float) -> None:
        with self._telemetry_lock:
            self._in_flight = max(0, self._in_flight - 1)
            self._latency_samples.append((method, principal, ok, round(duration_ms, 2)))

    def latency_summary(self) -> dict:
        with self._telemetry_lock:
            items = list(self._latency_samples)
            in_flight = self._in_flight
            peak = self._peak_concurrent
            total = self._total_requests
        if not items:
            return {
                "samples": 0, "total_requests": total,
                "in_flight": in_flight, "peak_concurrent": peak,
                "p50_ms": None, "p95_ms": None, "max_ms": None, "error_count": 0,
            }
        durations = sorted(row[3] for row in items)
        n = len(durations)
        p50 = durations[min(n - 1, (n - 1) // 2)]
        p95 = durations[min(n - 1, int((n - 1) * 0.95))]
        errors = sum(1 for row in items if not row[2])
        return {
            "samples": n,
            "total_requests": total,
            "in_flight": in_flight,
            "peak_concurrent": peak,
            "p50_ms": p50,
            "p95_ms": p95,
            "max_ms": durations[-1],
            "error_count": errors,
        }

    def root_for_registration(self, value: str) -> tuple[Path, str]:
        root = Path(value)
        if not root.is_absolute() or not root.is_dir():
            raise BridgeError("PROJECT_ROOT_INVALID", "Choose an existing absolute folder.")
        identity = ProjectFiles.identity(root)
        root = root.resolve(strict=True)
        for protected in (self.state_path.resolve(), Path(__file__).resolve().parents[1], Path.home()):
            if root == protected or root in protected.parents:
                raise BridgeError("PROJECT_ROOT_INVALID", "Choose a narrower project folder.")
        for protected in (self.state_path.resolve(), Path(__file__).resolve().parents[1]):
            if protected in root.parents:
                raise BridgeError("PROJECT_ROOT_INVALID", "The project overlaps the bridge control files.")
        if identity != ProjectFiles.identity(root):
            raise BridgeError("PROJECT_ROOT_INVALID", "The selected root identity changed.")
        return root, identity

    def info(self, principal: str) -> dict:
        desktop = runner.thread_desktop_name()
        non_default_desktop = bool(desktop and not desktop.casefold().endswith("\\default"))
        is_local = principal == "local"
        codex_present = runner._codex_path().is_file()
        observations = self.store.list_model_capabilities()
        return {
            "instance_id": self.store.instance_id, "bridge_version": __version__,
            "schema_version": API_VERSION,
            "api_contract_version": API_VERSION,
            "sqlite_schema_version": self.store.schema_version,
            "principal": principal,
            "model_api": False, "paid_fallback": False, "remote_mode": EDGE_READ,
            "desktop_name": desktop if is_local else None,
            "mxc_non_default_desktop_warning": non_default_desktop,
            "model_capabilities": capabilities.summarize_for_info(
                observations, principal=principal, codex_present=codex_present,
            ),
            "local_codex_fallback": {
                "available": codex_present,
                "preferred_default_model": capabilities.PREFERRED_DEFAULT_MODEL,
                "model_agnostic": True,
                "requires_local_owner_authorization": True,
            },
            "capabilities": {
                "file_read": {"implemented": True, "allowed": True, "requires_project_grant": True},
                "file_write": {"implemented": True, "allowed": is_local, "edge_host": "not_tested"},
                "command_execution": {"implemented": True, "allowed": is_local,
                                      "condition": "pinned_recipe_and_per_job_isolation_probe",
                                      "custom_python_node_powershell_tests_require_owner_grant": True,
                                      "edge_host": "not_tested"},
                "git_read": {"implemented": True, "allowed": True, "requires_project_grant": True},
                "git_checkpoint": {"implemented": True, "allowed": is_local, "edge_host": "not_tested"},
                "model_workers": {"implemented": False, "allowed": False, "prep_ready": True},
                "computer_use": {"implemented": False, "allowed": False, "edge_host": "not_tested"},
                "project_resume": {"implemented": True, "allowed": True, "requires_project_grant": True},
            },
            "capability_matrix": {
                "inspection_reads": {"tool_exists": True, "authorized_for_principal": True, "callable_by_chatgpt_connector": True, "local_cli_available": True},
                "git_read": {"tool_exists": True, "authorized_for_principal": True, "callable_by_chatgpt_connector": True, "local_cli_available": True},
                "file_mutations": {"tool_exists": True, "authorized_for_principal": is_local, "callable_by_chatgpt_connector": False, "local_cli_available": True},
                "process_execution": {"tool_exists": True, "authorized_for_principal": is_local, "callable_by_chatgpt_connector": False, "local_cli_available": True},
                "git_mutations": {"tool_exists": True, "authorized_for_principal": is_local, "callable_by_chatgpt_connector": False, "local_cli_available": True},
                "parallel_workers": {"tool_exists": False, "authorized_for_principal": False, "callable_by_chatgpt_connector": False, "local_cli_available": False},
            },
        }

    def manage(self, method: str, values: dict, principal: str):
        if principal != "local":
            raise BridgeError("AUTH_REQUIRED", "Local owner authentication is required.")
        if method == "owner_register":
            if set(values) != {"root", "name"}:
                raise BridgeError("INVALID_ARGUMENT", "Root and display name are required.")
            if not isinstance(values["root"], str) or not isinstance(values["name"], str):
                raise BridgeError("INVALID_ARGUMENT", "Root and name must be strings.")
            root, identity = self.root_for_registration(values["root"])
            return self.store.register_project(str(root), values["name"], identity)
        if method == "owner_record_artifact":
            if set(values) != {"project_id", "task_id", "path"} or not all(isinstance(item, str) for item in values.values()):
                raise BridgeError("INVALID_ARGUMENT", "Project ID, task ID and relative path are required.")
            project = self.store.get_project(values["project_id"], principal)
            observed = ProjectFiles(project["root"], project["root_identity"]).read(values["path"], limit=1)
            return self.store.record_artifact(values["project_id"], values["task_id"], observed["path"],
                                              observed["hash"], observed["size"], "text/plain")
        if method == "owner_patch_recovery":
            if set(values) != {"project_id", "receipt_id", "restore"} or type(values["restore"]) is not bool:
                raise BridgeError("INVALID_ARGUMENT", "Project ID, patch receipt ID and restore flag are required.")
            project = self.store.get_project(values["project_id"], principal, "write")
            files = ProjectFiles(project["root"], project["root_identity"])
            return files.patch_recovery(values["receipt_id"], restore=values["restore"])
        if method == "owner_apply_job_changes":
            return self.apply_job_changes(values, principal)
        if method == "owner_apply_patch_plan":
            from .mcp_server import Patch
            request = Patch.model_validate(values).model_dump()
            project_id = request["project_id"]
            operation_id = request["operation_id"]
            edits = request["edits"]
            project = self.store.get_project(project_id, principal, "write")
            decision = self.store.begin_operation(project_id, principal, operation_id,
                                                  {"apply_patch_plan": edits}, "write")
            if decision["status"] in {"succeeded", "failed"}:
                cached = decision["result"]
                if decision["status"] == "failed":
                    raise BridgeError(cached["code"], cached["message"])
                return cached
            if decision["status"] != "claimed":
                raise BridgeError("UNKNOWN_AFTER_RESTART", "Review the recovery journal before retrying.")
            try:
                result = ProjectFiles(project["root"], project["root_identity"]).patch(edits)
            except Exception as error:
                if getattr(error, "code", None) in {"VERSION_CONFLICT", "PATH_OUTSIDE_ROOT", "UNSUPPORTED_PATH_TYPE", "INVALID_ARGUMENT"}:
                    self.store.finish_operation(project_id, principal, operation_id, error_payload(error), failed=True)
                raise
            self.store.finish_operation(project_id, principal, operation_id, result)
            return result
        if method in {"owner_grant_python_tests", "owner_grant_node_tests", "owner_grant_powershell_tests"}:
            if set(values) != {"project_id", "files"}:
                raise BridgeError("INVALID_ARGUMENT", "Project ID and an explicit file list are required.")
            project = self.store.get_project(values["project_id"], principal, "execute")
            runtime = method.split("_")[2]
            exec_policy = self.store.get_exec_policy(values["project_id"])
            files = validate_project_test_files(
                project, runtime, values["files"],
                max_files=exec_policy["max_files"], max_total_bytes=exec_policy["max_total_bytes"],
            )
            scope = self.store.set_test_scope(values["project_id"], runtime, files)
            return {**scope, "cancellation_requested": scope["changed"] and
                    self.jobs.stop_project_tests(values["project_id"], runtime, "test_scope_changed")}
        if method in {"owner_revoke_python_tests", "owner_revoke_node_tests", "owner_revoke_powershell_tests"}:
            if set(values) != {"project_id"}:
                raise BridgeError("INVALID_ARGUMENT", "A project ID is required.")
            project_id = values["project_id"]
            runtime = method.split("_")[2]
            result = self.store.set_test_scope(project_id, runtime, None)
            return {**result, "cancellation_requested": self.jobs.stop_project_tests(project_id, runtime, "test_scope_revoked")}
        if method == "owner_set_exec_policy":
            if not isinstance(values.get("project_id"), str) or not set(values) <= {"project_id", "max_files", "max_total_bytes", "allow_git"}:
                raise BridgeError("INVALID_ARGUMENT", "Provide project_id and policy limits.")
            return self.store.set_exec_policy(
                values["project_id"],
                max_files=values.get("max_files", 32),
                max_total_bytes=values.get("max_total_bytes", 524_288),
                allow_git=values.get("allow_git", True),
            )
        if method == "owner_backup":
            if set(values) != {"target_path"} or not isinstance(values["target_path"], str):
                raise BridgeError("INVALID_ARGUMENT", "An absolute target_path is required for SQLite backup.")
            dest = Path(values["target_path"])
            if not dest.is_absolute():
                raise BridgeError("INVALID_ARGUMENT", "Backup target_path must be absolute.")
            resolved_dest = dest.resolve()
            resolved_state = self.state_path.resolve()
            if resolved_dest == resolved_state or resolved_state in resolved_dest.parents:
                raise BridgeError("STATE_PATH_UNSAFE", "Store SQLite backups outside the dedicated state directory.")
            for proj in self.store.list_projects("local"):
                proj_root = Path(proj["root"]).resolve()
                if resolved_dest == proj_root or proj_root in resolved_dest.parents:
                    raise BridgeError("INVALID_ARGUMENT", "Backup destination cannot be inside a registered project root.")
            return self.store.backup_to(resolved_dest)
        if method == "owner_record_incident":
            if not {"source", "category", "summary"} <= set(values):
                raise BridgeError("INVALID_ARGUMENT", "source, category, and summary are required.")
            summary = str(values["summary"])
            classification = diagnostics.classify_host_error(summary)
            merged_details = {**(values.get("details") or {}), "classification": classification}
            return self.store.record_incident(
                str(values["source"]),
                str(values["category"]),
                summary,
                http_status=values.get("http_status"),
                details=diagnostics._redact_obj(merged_details),
            )
        if method == "owner_stop_all":
            reason = str(values.get("reason") or "operator_stop_all")
            stopped = self.jobs.stop_all(reason=reason)
            return {**stopped, "workers": self.workers.status(principal="local")}
        if method == "owner_record_model_capability":
            required = {"model_id", "surface", "capabilities", "source"}
            allowed = required | {"notes", "merge"}
            if not required <= set(values) or not set(values) <= allowed:
                raise BridgeError("INVALID_ARGUMENT", "model_id, surface, capabilities, and source are required.")
            return self.store.record_model_capability(
                values["model_id"],
                values["surface"],
                values["capabilities"],
                source=values["source"],
                notes=values.get("notes", ""),
                merge=values.get("merge", True),
            )
        if method == "owner_list_model_capabilities":
            if not set(values) <= {"model_id", "surface", "target_principal"}:
                raise BridgeError("INVALID_ARGUMENT", "Unexpected filter arguments for owner_list_model_capabilities.")
            target_principal = values.get("target_principal", "local")
            if target_principal not in {"local", "edge"}:
                raise BridgeError("INVALID_ARGUMENT", "target_principal must be 'local' or 'edge'.")
            rows = self.store.list_model_capabilities(
                model_id=values.get("model_id"),
                surface=values.get("surface"),
            )
            return capabilities.aggregate_capabilities(rows, principal=target_principal)
        if method == "owner_fallback_plan":
            if "project_id" not in values or not set(values) <= {
                "project_id", "task_id", "operation_id", "model_id", "surface",
                "required_capabilities", "target_principal",
            }:
                raise BridgeError("INVALID_ARGUMENT", "Invalid parameters for owner_fallback_plan.")
            target_principal = values.get("target_principal", "edge")
            if target_principal not in {"local", "edge"}:
                raise BridgeError("INVALID_ARGUMENT", "target_principal must be 'local' or 'edge'.")
            project = self.store.get_project(values["project_id"], "local")
            req_caps = values.get("required_capabilities") or ["file_write", "command_exec"]
            try:
                return capabilities.build_fallback_plan(
                    project_id=values["project_id"],
                    task_id=values.get("task_id"),
                    operation_id=values.get("operation_id") or "fallback-op-1",
                    principal=target_principal,
                    required_capabilities=req_caps,
                    observations=self.store.list_model_capabilities(),
                    model_id=values.get("model_id"),
                    surface=values.get("surface"),
                    state_dir_hint=str(self.state_path),
                    project_root_hint=project["root"],
                )
            except ValueError as exc:
                raise BridgeError("INVALID_ARGUMENT", str(exc)) from exc
        if method == "owner_record_verification":
            required = {"project_id", "check_id", "verdict", "evidence"}
            allowed = required | {"model"}
            if not required <= set(values) or not set(values) <= allowed:
                raise BridgeError("INVALID_ARGUMENT", "project_id, check_id, verdict, and evidence are required.")
            return self.store.record_verification(
                values["project_id"],
                values["check_id"],
                values["verdict"],
                values["evidence"],
                model=values.get("model"),
            )
        if method in {"owner_grant_edge", "owner_revoke_edge"}:
            if set(values) != {"project_id"} or not isinstance(values["project_id"], str):
                raise BridgeError("INVALID_ARGUMENT", "A project ID is required.")
            if method == "owner_grant_edge":
                return self.store.grant(values["project_id"], "edge", ["read"])
            return self.store.revoke(values["project_id"], "edge")
        if method == "owner_grant_edge_scoped":
            allowed = {"project_id", "capabilities", "expires_at"}
            if "project_id" not in values or "capabilities" not in values or not set(values) <= allowed:
                raise BridgeError("INVALID_ARGUMENT", "project_id and capabilities are required.")
            caps = values["capabilities"]
            if not isinstance(caps, list) or not caps or not all(isinstance(c, str) for c in caps):
                raise BridgeError("INVALID_ARGUMENT", "capabilities must be a non-empty list of strings.")
            cap_set = set(caps) | {"read"}
            if not cap_set <= EDGE_SCOPED_ALLOWED_CAPS:
                raise BridgeError(
                    "BRIDGE_POLICY_DENIED",
                    f"Unsupported edge capabilities; allowed: {sorted(EDGE_SCOPED_ALLOWED_CAPS)}.",
                )
            return self.store.grant(
                values["project_id"],
                "edge",
                sorted(cap_set),
                expires_at=values.get("expires_at"),
            )
        if method == "owner_diagnose" and not values:
            return runner.diagnose()
        if method == "owner_stop" and not values:
            self.stopping = True
            return {"stopping": True}
        raise BridgeError("METHOD_NOT_FOUND", "Unknown management action.")

    def apply_job_changes(self, values: dict, principal: str) -> dict:
        from .mcp_server import JobApply

        request = JobApply.model_validate(values).model_dump()
        project_id, job_id = request["project_id"], request["job_id"]
        operation_id, selection = request["operation_id"], request["selection"]
        if len({item["path"].casefold() for item in selection}) != len(selection):
            raise BridgeError("INVALID_ARGUMENT", "Select each file once.")
        project = self.store.get_project(project_id, principal, "write")
        job = self.store.get_job(project_id, principal, job_id)
        if job["status"] != "succeeded":
            raise BridgeError("JOB_REVIEW_UNAVAILABLE", "Apply requires a successful and sealed job.")
        decision = self.store.begin_operation(project_id, principal, operation_id,
                                              {"apply_job": job_id, "selection": selection}, "write")
        if decision["status"] in {"succeeded", "failed"}:
            cached = decision["result"]
            if decision["status"] == "failed":
                raise BridgeError(cached["code"], cached["message"])
            return cached
        if decision["status"] != "claimed":
            raise BridgeError("UNKNOWN_AFTER_RESTART", "Review the recovery journal before retrying.")
        try:
            source, edits = self.jobs.prepare_apply(project, job, selection)
        except Exception as error:
            self.store.finish_operation(project_id, principal, operation_id, error_payload(error), failed=True)
            raise
        # An interruption in patch() can leave a recovery journal. Leave the
        # operation pending until the operator reconciles it.
        result = {"job_id": job_id, **source.patch(edits)}
        self.store.finish_operation(project_id, principal, operation_id, result)
        return result

    @staticmethod
    def visible_project(project: dict, principal: str) -> dict:
        if principal == "local":
            return project
        return {name: value for name, value in project.items() if name not in {"root", "root_identity"}}

    @staticmethod
    def visible_job(job: dict, principal: str) -> dict:
        if principal == "local":
            return job
        return {name: value for name, value in job.items() if name not in {"intent", "evidence"}}

    def dispatch(self, method: str, values: dict, principal: str):
        t0 = time.perf_counter()
        ok = False
        self._enter_request()
        try:
            result = self._dispatch_inner(method, values, principal)
            ok = True
            return result
        finally:
            self._exit_request(method, principal, ok, (time.perf_counter() - t0) * 1000.0)

    def _dispatch_inner(self, method: str, values: dict, principal: str):
        from .mcp_server import TOOL_SPECS

        if self.stopping:
            raise BridgeError("BROKER_STOPPING", "The local broker is draining requests.")
        if method.startswith("owner_"):
            with self.lock:
                if self.stopping:
                    raise BridgeError("BROKER_STOPPING", "The local broker is draining requests.")
                return self.manage(method, values, principal)
        if method not in TOOL_SPECS:
            raise BridgeError("METHOD_NOT_FOUND", "Unknown bridge tool.")
        if principal == "edge" and (method in MUTATION_TOOLS or method in {"job_output", "job_changes"}):
            req_cap = EDGE_TOOL_REQUIRED_CAP.get(method)
            pid_hint = values.get("project_id") if isinstance(values, dict) else None
            allowed_by_scope = (
                req_cap is not None
                and isinstance(pid_hint, str)
                and req_cap in self.store.project_capabilities(pid_hint, "edge")
            )
            if not allowed_by_scope:
                if method in MUTATION_TOOLS:
                    reason = "PRINCIPAL_READ_ONLY"
                else:
                    reason = "LOCAL_JOB_LOG_ONLY" if method == "job_output" else "LOCAL_JOB_REVIEW_ONLY"
                raise BridgeError("BRIDGE_POLICY_DENIED", "This Edge credential does not allow this action.",
                                  {"reason": reason, "rejection_layer": "bridge", "host_capability": "not_tested"})
        values = TOOL_SPECS[method].model.model_validate(values).model_dump()

        # Concurrent read-only fast paths (SQLite WAL + handle-relative disk/git I/O run lock-free)
        if method == "bridge_info":
            return self.info(principal)
        if method == "bridge_health":
            desktop = runner.thread_desktop_name()
            health = self.store.health_snapshot()
            return {
                "bridge_version": __version__,
                "principal": principal,
                **health,
                "sqlite_schema_version": health["schema_version"],
                "resources": sample_host_resources(),
                "latency_telemetry": self.latency_summary(),
                "desktop_name": desktop if principal == "local" else None,
                "mxc_non_default_desktop_warning": bool(desktop and not desktop.casefold().endswith("\\default")),
                "workers_enabled": False,
            }
        if method == "project_list":
            projects = self.store.list_projects(principal)
            cursor, limit = values["cursor"], values["limit"]
            batch = projects[cursor:cursor + limit]
            return {"projects": [self.visible_project(p, principal) for p in batch],
                    "next_cursor": cursor + len(batch) if cursor + len(batch) < len(projects) else None}
        if method in {"file_list", "file_read", "file_search", "file_view", "artifact_read", "git_status", "git_diff"}:
            project_id = values.pop("project_id")
            project = self.store.get_project(project_id, principal)
            artifact = (
                self.store.get_artifact(project_id, principal, values["artifact_id"])
                if method == "artifact_read"
                else None
            )
            if method in {"git_status", "git_diff"}:
                exec_policy = self.store.get_exec_policy(project_id)
                if not exec_policy["allow_git"]:
                    raise BridgeError("BRIDGE_POLICY_DENIED", "Git tools are disabled by project policy.")
                root_path = Path(project["root"])
                try:
                    if method == "git_status":
                        return self.git.status(root_path, **values)
                    return self.git.diff(root_path, **values)
                except GitEngineError as git_err:
                    raise BridgeError(git_err.code, str(git_err)) from git_err
            files = ProjectFiles(project["root"], project["root_identity"])
            is_writable = principal == "local" or "write" in project.get("capabilities", [])
            if method == "artifact_read":
                observed = files.read(artifact["storage_ref"], values["offset"], values["limit"])
                if observed["hash"] != artifact["sha256"].removeprefix("sha256:"):
                    raise BridgeError("VERSION_CONFLICT", "The referenced file has changed since artifact registration.")
                return {**observed, "artifact_id": values["artifact_id"], "principal_writable": is_writable}
            action = {"file_list": files.list, "file_read": files.read,
                      "file_search": files.search, "file_view": files.view}[method]
            out = action(**values)
            if method in {"file_read", "file_view"}:
                out["principal_writable"] = is_writable
            return out

        with self.lock:
            if self.stopping:
                raise BridgeError("BROKER_STOPPING", "The local broker is draining requests.")
            if method == "connection_diagnostics":
                incidents = self.store.list_incidents(limit=10) if values["include_incidents"] else []
                symptom_report = diagnostics.classify_host_error(values["symptom"]) if values["symptom"] else None
                desktop = runner.thread_desktop_name()
                diag = runner.diagnose()
                codex_present = diag["execution"].get("vendor_executable_present", False)
                observations = self.store.list_model_capabilities()
                return {
                    "bridge_version": __version__,
                    "principal": principal,
                    "local_broker": "PASS",
                    "health": self.store.health_snapshot(),
                    "latency_telemetry": self.latency_summary(),
                    "desktop_name": desktop if principal == "local" else None,
                    "mxc_non_default_desktop_warning": diag["execution"].get("mxc_non_default_desktop_warning", False),
                    "symptom_classification": symptom_report,
                    "recent_incidents": diagnostics._redact_obj(incidents),
                    "model_capabilities": capabilities.summarize_for_info(
                        observations, principal=principal, codex_present=codex_present,
                    ),
                    "fallback_readiness": {
                        "codex_present": codex_present,
                        "cli_module": "edge_bridge.cli",
                        "model_agnostic": True,
                    },
                    "known_upstream_reference": "https://github.com/openai/tunnel-client/issues/103",
                }
            project_id = values.pop("project_id")
            project = self.store.get_project(project_id, principal)
            if method == "project_status":
                status = {
                    "project": self.visible_project(project, principal),
                    "jobs": [self.visible_job(job, principal) for job in self.store.list_jobs(project_id, principal)],
                    "verification": self.store.list_verification(project_id, principal),
                }
                if principal == "local":
                    for runtime in ("python", "node", "powershell"):
                        status[f"{runtime}_test_scope"] = self.store.get_test_scope(project_id, principal, runtime)
                    status["exec_policy"] = self.store.get_exec_policy(project_id)
                return status
            if method == "project_resume":
                return self.store.resume(project_id, principal, values["task_id"])
            if method == "task_get":
                return self.store.get_task(project_id, principal, values["task_id"])
            if method == "policy_view":
                summary = self.store.get_policy_summary(project_id, principal)
                if principal != "local":
                    summary = {k: v for k, v in summary.items() if k not in {"root", "root_identity"}}
                return summary
            if method == "job_get":
                return self.visible_job(self.store.get_job(project_id, principal, values["job_id"]), principal)
            if method == "job_output":
                self.store.get_job(project_id, principal, values["job_id"])
                out = self.jobs.output(**values)
                if principal != "local" and isinstance(out.get("output"), str):
                    out = {**out, "output": diagnostics.redact_text(out["output"]), "redacted": True}
                return out
            if method == "job_changes":
                job = self.store.get_job(project_id, principal, values["job_id"])
                return self.jobs.review(project, job)
            if method == "worker_list":
                return self.workers.status(project_id=project_id, principal=principal)
            if method == "worker_cancel":
                return self.workers.cancel_worker(values["worker_id"], principal)
            if method in {"git_checkpoint", "git_integrate"}:
                exec_policy = self.store.get_exec_policy(project_id)
                if not exec_policy["allow_git"]:
                    raise BridgeError("BRIDGE_POLICY_DENIED", "Git tools are disabled by project policy.")
                root_path = Path(project["root"])
                try:
                    cap = "checkpoint" if method == "git_checkpoint" else "write"
                    self.store.get_project(project_id, principal, cap)
                    operation_id = values.pop("operation_id")
                    decision = self.store.begin_operation(
                        project_id, principal, operation_id, {"method": method, "parameters": values}, cap,
                    )
                    if decision["status"] in {"succeeded", "failed"}:
                        cached = decision["result"]
                        if decision["status"] == "failed":
                            raise BridgeError(cached["code"], cached["message"])
                        return cached
                    if decision["status"] != "claimed":
                        raise BridgeError("UNKNOWN_AFTER_RESTART", "Git operation needs reconciliation before retrying.")
                    try:
                        if method == "git_checkpoint":
                            res = self.git.checkpoint(root_path, **values)
                        else:
                            res = self.git.integrate_ref(root_path, **values)
                    except GitEngineError as git_err:
                        if git_err.code in {"INVALID_ARGUMENT", "VERSION_CONFLICT", "MERGE_REQUIRES_FAST_FORWARD", "NOT_FOUND"}:
                            self.store.finish_operation(project_id, principal, operation_id, error_payload(git_err), failed=True)
                        raise BridgeError(git_err.code, str(git_err)) from git_err
                    self.store.finish_operation(project_id, principal, operation_id, res)
                    return res
                except GitEngineError as git_err:
                    raise BridgeError(git_err.code, str(git_err)) from git_err
            if method == "artifact_list":
                return {"artifacts": self.store.list_artifacts(project_id, principal, values["task_id"])}
            if method == "task_checkpoint":
                return self.store.checkpoint(project_id, principal, **values)
            if method == "process_start":
                self.store.get_project(project_id, principal, "execute")
                return self.jobs.start(project, principal, **values)
            if method == "job_cancel":
                return self.jobs.cancel(project_id, principal, **values)
            if method == "process_input":
                raise BridgeError("EXECUTION_REQUEST_UNSUPPORTED", "Bundled jobs use closed stdin.")
            if method.startswith("worker_"):
                runner.require_workers()
                raise BridgeError("ISOLATION_NOT_VERIFIED", "No worker adapter is wired to this broker.")

            files = ProjectFiles(project["root"], project["root_identity"])
            operation_id = values.pop("operation_id")
            decision = self.store.begin_operation(project_id, principal, operation_id,
                                                  {"method": method, "parameters": values}, "write")
            if decision["status"] in {"succeeded", "failed"}:
                cached = decision["result"]
                if decision["status"] == "failed":
                    raise BridgeError(cached["code"], cached["message"])
                return cached
            if decision["status"] != "claimed":
                raise BridgeError("UNKNOWN_AFTER_RESTART", "Operation is pending or its effect needs reconciliation.")
            try:
                action = {"file_write": files.write, "file_patch": files.patch,
                          "file_move": files.move, "file_delete": files.delete}[method]
                result = action(**values)
            except Exception as error:
                if method != "file_patch" and getattr(error, "code", None) in {
                    "VERSION_CONFLICT", "PATH_OUTSIDE_ROOT", "UNSUPPORTED_PATH_TYPE", "INVALID_ARGUMENT",
                }:
                    self.store.finish_operation(project_id, principal, operation_id, error_payload(error), failed=True)
                raise
            self.store.finish_operation(project_id, principal, operation_id, result)
            return result


class LoopbackServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 128

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def accept_nonce(self, principal: str, nonce: str, stamp: int) -> bool:
        with self.nonce_lock:
            now = time.time()
            if abs(now - stamp) > MAX_CLOCK_SKEW:
                return False
            last_prune = getattr(self, "_last_nonce_prune", 0.0)
            if len(self.nonces) >= 2048 or (now - last_prune) >= 5.0:
                stale = [key for key, until in self.nonces.items() if until < now]
                for key in stale:
                    del self.nonces[key]
                self._last_nonce_prune = now
            key = (principal, nonce)
            if key in self.nonces or len(self.nonces) >= MAX_RECENT_NONCES:
                return False
            self.nonces[key] = stamp + MAX_CLOCK_SKEW
            return True


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        self.proof = None

    def log_message(self, *_args):
        return

    def reply(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(raw) > MAX_RESPONSE:
            status, raw = 413, b'{"ok":false,"code":"PAYLOAD_TOO_LARGE","message":"Use a smaller query."}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if self.proof is not None:
            principal, token, nonce, stamp = self.proof
            self.send_header("X-Bridge-Signature", signature(token, f"response:{status}", principal, nonce, stamp, raw))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        host = f"127.0.0.1:{self.server.server_port}"
        if self.path != "/v1/call" or self.headers.get_all("Host") != [host] or self.headers.get_all("Origin"):
            self.reply(403, {"ok": False, "code": "IPC_REQUEST_DENIED", "message": "Invalid local IPC origin."})
            return
        def header(name):
            found = self.headers.get_all(name) or []
            return found[0] if len(found) == 1 and found[0].isascii() else ""

        def hex_value(value, length):
            return len(value) == length and all(char in "0123456789abcdef" for char in value)

        principal = header("X-Bridge-Principal")
        nonce = header("X-Bridge-Nonce")
        stamp = header("X-Bridge-Timestamp")
        supplied = header("X-Bridge-Signature")
        token = self.server.tokens.get(principal)
        if (token is None or not hex_value(nonce, 32) or not hex_value(supplied, 64)
                or not stamp.isdigit() or len(stamp) > 12 or abs(time.time() - int(stamp)) > MAX_CLOCK_SKEW):
            self.reply(401, {"ok": False, "code": "AUTH_REQUIRED", "message": "A signed broker request is required."})
            return
        lengths = self.headers.get_all("Content-Length") or []
        if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                or len(lengths[0]) > 7 or not 0 < int(lengths[0]) <= MAX_REQUEST
                or self.headers.get_all("Transfer-Encoding")
                or self.headers.get_content_type() != "application/json"):
            self.reply(400, {"ok": False, "code": "INVALID_REQUEST", "message": "Expected a bounded JSON request."})
            return
        try:
            raw = self.rfile.read(int(lengths[0]))
            expected = signature(token, "request", principal, nonce, stamp, raw)
            if (not hmac.compare_digest(supplied, expected)
                    or not self.server.accept_nonce(principal, nonce, int(stamp))):
                self.reply(401, {"ok": False, "code": "AUTH_REQUIRED", "message": "Invalid or replayed request."})
                return
            self.proof = (principal, token, nonce, stamp)
            call = json.loads(raw)
            if (not isinstance(call, dict) or set(call) != {"method", "params"}
                    or not isinstance(call["method"], str) or not isinstance(call["params"], dict)):
                raise BridgeError("INVALID_REQUEST", "Invalid local request envelope.")
            result = self.server.broker.dispatch(call["method"], call["params"], principal)
            self.reply(200, {"ok": True, "result": result})
            if call["method"] == "owner_stop":
                threading.Thread(target=self.server.shutdown, daemon=True).start()
        except (BrokenPipeError, ConnectionResetError):
            return
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.reply(400, {"ok": False, "code": "INVALID_ARGUMENT", "message": "Tool input did not match its schema."})
        except Exception as error:
            if type(error).__name__ == "ValidationError":
                self.reply(400, {"ok": False, "code": "INVALID_ARGUMENT", "message": "Tool input did not match its schema."})
            else:
                self.reply(400, error_payload(error))


def run_broker(state_path: Path, port: int = 0) -> None:
    verify_state_path(state_path)
    # SQLite and other child objects use the Windows token's default owner.
    require_state_writer_token()
    with exclusive_broker(state_path):
        store = State(state_path / "state.sqlite3")
        store.recover_orphans()
        with LoopbackServer(("127.0.0.1", port), Handler) as server:
            server.socket = make_server_tls(state_path).wrap_socket(
                server.socket, server_side=True, do_handshake_on_connect=False,
            )
            server.tokens = create_tokens(state_path)
            server.broker = Broker(store, state_path)
            server.nonce_lock = threading.Lock()
            server.nonces = {}
            discovery = state_path / "broker.json"
            temporary = state_path / "broker.tmp"
            temporary.write_text(json.dumps({"port": server.server_port, "instance_id": store.instance_id}), encoding="utf-8")
            os.replace(temporary, discovery)
            print(f"Edge Project Bridge ready on 127.0.0.1:{server.server_port}", flush=True)
            try:
                server.serve_forever(poll_interval=0.1)
            finally:
                with server.broker.lock:
                    server.broker.stopping = True
                server.broker.jobs.shutdown()
                discovery.unlink(missing_ok=True)


def _client_tls_context(trusted_cert: Path) -> ssl.SSLContext:
    protected_path(trusted_cert)
    st = trusted_cert.lstat()
    key = str(trusted_cert)
    sig = (st.st_mtime_ns, st.st_size, st.st_ino)
    with _CLIENT_TLS_LOCK:
        cached = _CLIENT_TLS_CACHE.get(key)
        if cached is not None and cached[0] == sig:
            return cached[1]
    tls = ssl.create_default_context(cafile=key)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    with _CLIENT_TLS_LOCK:
        if len(_CLIENT_TLS_CACHE) >= 32:
            _CLIENT_TLS_CACHE.clear()
        _CLIENT_TLS_CACHE[key] = (sig, tls)
    return tls


def _post_loopback_https(
    port: int,
    tls: ssl.SSLContext,
    raw: bytes,
    headers: dict[str, str],
) -> tuple[int, http.client.HTTPMessage, bytes]:
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=15, context=tls)
    try:
        conn.connect()
        if conn.sock is not None:
            try:
                conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
        conn.request("POST", "/v1/call", body=raw, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        resp_headers = resp.headers
        body = resp.read(MAX_RESPONSE + 1)
        return status, resp_headers, body
    finally:
        conn.close()


def call_broker(state: Path, principal: str, method: str, params: dict | None = None) -> object:
    discovery = state / "broker.json"
    try:
        protected_path(discovery)
        address = json.loads(discovery.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise BridgeError("BROKER_OFFLINE", "Start the local broker using the CLI.") from error
    port = address.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        raise BridgeError("BROKER_OFFLINE", "Invalid broker discovery file.")
    token = read_token(state, principal)
    trusted_cert = state / "ipc.pem"
    tls = _client_tls_context(trusted_cert)
    raw = json.dumps({"method": method, "params": params or {}}, allow_nan=False).encode("utf-8")
    attempts = 2 if method in READ_TOOLS else 1
    status = 0
    headers = None
    body = b""
    nonce = ""
    stamp = ""
    for attempt in range(attempts):
        nonce, stamp = secrets.token_hex(16), str(int(time.time()))
        req_headers = {
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/json",
            "Content-Length": str(len(raw)),
            "X-Bridge-Principal": principal,
            "X-Bridge-Nonce": nonce,
            "X-Bridge-Timestamp": stamp,
            "X-Bridge-Signature": signature(token, "request", principal, nonce, stamp, raw),
        }
        try:
            status, headers, body = _post_loopback_https(port, tls, raw, req_headers)
            break
        except (ConnectionResetError, http.client.RemoteDisconnected) as error:
            if attempt + 1 < attempts:
                time.sleep(0.02)
                continue
            raise BridgeError("BROKER_OFFLINE", "The authenticated local broker did not answer.") from error
        except (OSError, http.client.HTTPException) as error:
            raise BridgeError("BROKER_OFFLINE", "The authenticated local broker did not answer.") from error
    proof = headers.get_all("X-Bridge-Signature") or []
    if (len(body) > MAX_RESPONSE or len(proof) != 1 or not proof[0].isascii()
            or not hmac.compare_digest(proof[0], signature(token, f"response:{status}", principal, nonce, stamp, body))):
        raise BridgeError("BROKER_OFFLINE", "The local broker did not prove its identity.")
    output = json.loads(body)
    if not output.get("ok"):
        details = {name: output[name] for name in ("reason", "rejection_layer", "host_capability") if name in output}
        raise BridgeError(output["code"], output["message"], details)
    return output["result"]

