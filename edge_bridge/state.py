"""Durable, principal-scoped bridge data. The broker owns execution and IPC."""

from __future__ import annotations

from contextlib import closing, contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
from typing import Any, Iterator
from uuid import uuid4

from . import capabilities


SCHEMA_VERSION = 3
_CAPABILITIES = frozenset({"read", "write", "checkpoint", "execute", "worker"})
_TEST_SCOPE_TABLES = {
    "python": "python_test_scopes",
    "node": "node_test_scopes",
    "powershell": "powershell_test_scopes",
}
_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}\Z")
_WINDOWS_DEVICE = re.compile(r"(?:AUX|CON|NUL|PRN|COM[1-9]|LPT[1-9])\Z", re.IGNORECASE)
_ACTIVE = ("queued", "running", "cancelling")
_TRANSITIONS = {
    "queued": {"running", "failed", "cancelled", "cancelling", "waiting_for_approval", "timed_out", "unknown_after_restart"},
    "waiting_for_approval": {"queued", "failed", "cancelled"},
    "running": {"succeeded", "failed", "cancelling", "cancelled", "timed_out", "unknown_after_restart"},
    "cancelling": {"cancelled", "failed", "succeeded", "timed_out", "unknown_after_restart"},
    "unknown_after_restart": {"needs_review", "succeeded", "failed", "cancelled"},
    "needs_review": {"succeeded", "failed", "cancelled"},
}
_SCHEMA = """
CREATE TABLE IF NOT EXISTS instance (
    slot INTEGER PRIMARY KEY CHECK (slot = 1), id TEXT NOT NULL, schema_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY, root TEXT NOT NULL, root_key TEXT NOT NULL UNIQUE,
    root_identity TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
    policy_revision INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS grants (
    project_id TEXT NOT NULL REFERENCES projects(id), principal TEXT NOT NULL,
    capabilities TEXT NOT NULL, expires_at TEXT, revoked INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, principal)
);
CREATE TABLE IF NOT EXISTS python_test_scopes (
    project_id TEXT PRIMARY KEY REFERENCES projects(id), files TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_test_scopes (
    project_id TEXT PRIMARY KEY REFERENCES projects(id), files TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS powershell_test_scopes (
    project_id TEXT PRIMARY KEY REFERENCES projects(id), files TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS project_exec_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id),
    max_files INTEGER NOT NULL DEFAULT 32,
    max_total_bytes INTEGER NOT NULL DEFAULT 524288,
    allow_git INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    project_id TEXT NOT NULL REFERENCES projects(id), id TEXT NOT NULL,
    objective TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, id)
);
CREATE TABLE IF NOT EXISTS task_dependencies (
    project_id TEXT NOT NULL, task_id TEXT NOT NULL, depends_on_task_id TEXT NOT NULL, created_at TEXT NOT NULL,
    FOREIGN KEY (project_id, task_id) REFERENCES tasks(project_id, id),
    FOREIGN KEY (project_id, depends_on_task_id) REFERENCES tasks(project_id, id),
    PRIMARY KEY (project_id, task_id, depends_on_task_id)
);
CREATE TABLE IF NOT EXISTS checkpoints (
    project_id TEXT NOT NULL, task_id TEXT NOT NULL, revision INTEGER NOT NULL,
    packet TEXT NOT NULL, created_at TEXT NOT NULL,
    FOREIGN KEY (project_id, task_id) REFERENCES tasks(project_id, id),
    PRIMARY KEY (project_id, task_id, revision)
);
CREATE TABLE IF NOT EXISTS operations (
    principal TEXT NOT NULL, project_id TEXT NOT NULL REFERENCES projects(id),
    id TEXT NOT NULL, request_hash TEXT NOT NULL, status TEXT NOT NULL,
    result TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    PRIMARY KEY (principal, project_id, id)
);
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL, task_id TEXT NOT NULL,
    principal TEXT NOT NULL, operation_id TEXT NOT NULL, intent TEXT NOT NULL,
    status TEXT NOT NULL, exit_code INTEGER, evidence TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id, task_id) REFERENCES tasks(project_id, id)
);
CREATE INDEX IF NOT EXISTS jobs_by_project_task ON jobs(project_id, task_id, created_at);
CREATE TABLE IF NOT EXISTS events (
    sequence INTEGER PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
    job_id TEXT REFERENCES jobs(id), kind TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_by_project ON events(project_id, sequence);
CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL, task_id TEXT NOT NULL, storage_ref TEXT NOT NULL,
    sha256 TEXT NOT NULL, size INTEGER NOT NULL, media_type TEXT NOT NULL, created_at TEXT NOT NULL,
    FOREIGN KEY (project_id, task_id) REFERENCES tasks(project_id, id),
    UNIQUE (project_id, task_id, storage_ref, sha256)
);
CREATE INDEX IF NOT EXISTS artifacts_by_project_task ON artifacts(project_id, task_id, created_at);
CREATE TABLE IF NOT EXISTS verification (
    sequence INTEGER PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
    check_id TEXT NOT NULL, verdict TEXT NOT NULL, evidence TEXT NOT NULL, model TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS verification_by_project ON verification(project_id, sequence);
CREATE TABLE IF NOT EXISTS connection_incidents (
    id TEXT PRIMARY KEY, source TEXT NOT NULL, category TEXT NOT NULL,
    http_status INTEGER, summary TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_by_time ON connection_incidents(created_at DESC);
CREATE TABLE IF NOT EXISTS worker_profiles (
    name TEXT PRIMARY KEY, role_description TEXT NOT NULL, allowed_capabilities TEXT NOT NULL,
    max_memory_mb INTEGER NOT NULL, max_cpu_pct INTEGER NOT NULL,
    isolation_mode TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS workers (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), task_id TEXT NOT NULL,
    profile_name TEXT NOT NULL REFERENCES worker_profiles(name), principal TEXT NOT NULL,
    status TEXT NOT NULL, workspace_ref TEXT, pid INTEGER, verification_reason TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id, task_id) REFERENCES tasks(project_id, id)
);
CREATE INDEX IF NOT EXISTS workers_by_project ON workers(project_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS resource_samples (
    sequence INTEGER PRIMARY KEY, cpu_percent REAL,
    ram_total_mb INTEGER NOT NULL, ram_available_mb INTEGER NOT NULL, ram_used_percent INTEGER NOT NULL,
    active_jobs INTEGER NOT NULL, active_workers INTEGER NOT NULL,
    sample_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS model_capabilities (
    model_id TEXT NOT NULL,
    surface TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    source TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL,
    PRIMARY KEY (model_id, surface)
);
CREATE INDEX IF NOT EXISTS model_capabilities_by_time ON model_capabilities(observed_at DESC);
CREATE TABLE IF NOT EXISTS task_queue (
    queue_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    task_id TEXT NOT NULL,
    role TEXT NOT NULL REFERENCES worker_profiles(name),
    objective TEXT NOT NULL,
    file_scope_json TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'mock',
    priority INTEGER NOT NULL DEFAULT 100,
    status TEXT NOT NULL DEFAULT 'queued',
    worker_id TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 2,
    timeout_seconds INTEGER NOT NULL DEFAULT 60,
    result_json TEXT,
    error_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id, task_id) REFERENCES tasks(project_id, id)
);
CREATE INDEX IF NOT EXISTS task_queue_by_project_status ON task_queue(project_id, status, priority, created_at);
CREATE TABLE IF NOT EXISTS worker_events (
    sequence INTEGER PRIMARY KEY,
    worker_id TEXT NOT NULL REFERENCES workers(id),
    project_id TEXT NOT NULL REFERENCES projects(id),
    task_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS worker_events_by_worker ON worker_events(worker_id, sequence);
CREATE TABLE IF NOT EXISTS context_packs (
    project_id TEXT NOT NULL REFERENCES projects(id),
    task_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    pack_sha256 TEXT NOT NULL,
    pack_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id, task_id) REFERENCES tasks(project_id, id),
    PRIMARY KEY (project_id, task_id, revision)
);
"""
_DEFAULT_WORKER_PROFILES = (
    ("planner", "Task decomposition and architecture handoff planning (read-only)", '["read","checkpoint"]', 512, 25, "codex-sandbox-mxc", 0),
    ("explorer", "Fast codebase exploration and dependency mapping (read-only)", '["read"]', 512, 25, "codex-sandbox-mxc", 0),
    ("coder", "Scoped code edits inside isolated workspace copy or git worktree", '["read","write","checkpoint"]', 1024, 50, "codex-sandbox-mxc", 0),
    ("reviewer", "Diff audit and regression review against acceptance checks", '["read"]', 512, 25, "codex-sandbox-mxc", 0),
    ("security_reviewer", "Boundary, ACL, sandbox, and secret-hygiene security audit (read-only)", '["read"]', 512, 25, "codex-sandbox-mxc", 0),
    ("tester", "MXC verification runner for granted test suites", '["read","execute"]', 1024, 50, "codex-sandbox-mxc", 0),
    ("researcher", "Repository and documentation search (read-only, offline)", '["read"]', 512, 25, "codex-sandbox-mxc", 0),
    ("integrator", "Serial merge and checkpoint creation inside owner workspace", '["read","write","checkpoint"]', 768, 35, "codex-sandbox-mxc", 0),
)


class StateError(Exception):
    """An expected error that can cross the bridge as a structured error code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _id(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise StateError("INVALID_INPUT", "Invalid state identifier.")
    return value


def _json(value: Any, cap: int = 65_536) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise StateError("INVALID_INPUT", "Expected a finite JSON value.") from exc
    if len(encoded) > cap:
        raise StateError("INVALID_INPUT", "State payload exceeds the size limit.")
    return encoded


def _hash(value: Any, cap: int = 65_536) -> str:
    return "sha256:" + hashlib.sha256(_json(value, cap).encode()).hexdigest()


class State:
    """One database with transactional receipts and fresh authorization per request.

    The caller must authenticate each principal and keep this database outside project
    roots. Only the exclusive broker may call recover_orphans as part of startup.
    """

    schema_version = SCHEMA_VERSION

    def __init__(self, db_path: str | os.PathLike[str]):
        self.path = Path(db_path)
        with closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript("BEGIN IMMEDIATE;\n" + _SCHEMA)
            version = db.execute("SELECT schema_version FROM instance WHERE slot = 1").fetchone()
            if version is None:
                db.execute("INSERT INTO instance VALUES (1, ?, ?)", (str(uuid4()), SCHEMA_VERSION))
            elif version[0] in (1, 2):
                db.execute("UPDATE instance SET schema_version = ? WHERE slot = 1", (SCHEMA_VERSION,))
            elif version[0] != SCHEMA_VERSION:
                raise StateError("SCHEMA_UNSUPPORTED", "Use a compatible bridge database schema.")
            db.executemany(
                "INSERT OR IGNORE INTO worker_profiles VALUES (?,?,?,?,?,?,?)",
                _DEFAULT_WORKER_PROFILES,
            )
            row = db.execute("SELECT id FROM instance WHERE slot = 1").fetchone()
            self.instance_id = row[0]
            db.commit()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout = 15000")
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA synchronous = NORMAL")
        db.execute("PRAGMA temp_store = MEMORY")
        db.execute("PRAGMA cache_size = -16000")
        return db

    @contextmanager
    def _transaction(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield db
            except BaseException:
                db.rollback()
                raise
            else:
                db.commit()

    @staticmethod
    def _project_row(db: sqlite3.Connection, project_id: str) -> sqlite3.Row:
        row = db.execute("SELECT * FROM projects WHERE id = ?", (_id(project_id),)).fetchone()
        if row is None:
            raise StateError("PROJECT_NOT_GRANTED", "Project is not available to this principal.")
        return row

    @staticmethod
    def _capabilities(db: sqlite3.Connection, project_id: str, principal: str) -> list[str]:
        if _id(principal) == "local":
            return sorted(_CAPABILITIES)
        grant = db.execute(
            "SELECT * FROM grants WHERE project_id = ? AND principal = ? AND revoked = 0",
            (project_id, principal),
        ).fetchone()
        if grant is None or (grant["expires_at"] and grant["expires_at"] <= _now()):
            return []
        return json.loads(grant["capabilities"])

    def _authorize(
        self, db: sqlite3.Connection, project_id: str, principal: str, capability: str
    ) -> tuple[sqlite3.Row, list[str]]:
        row = self._project_row(db, project_id)
        caps = self._capabilities(db, project_id, principal)
        if capability not in caps:
            raise StateError("PROJECT_NOT_GRANTED", "Project capability is not granted to this principal.")
        return row, caps

    @staticmethod
    def _public_project(row: sqlite3.Row, caps: list[str]) -> dict[str, Any]:
        policy = {
            "project_id": row["id"],
            "root_identity": row["root_identity"],
            "policy_revision": row["policy_revision"],
            "capabilities": caps,
        }
        return {
            **policy,
            "policy_hash": _hash(policy),
            "root": row["root"],
            "display_name": row["display_name"],
        }

    def register_project(self, root: str, display_name: str, root_identity: str) -> dict[str, Any]:
        root = os.fspath(root)
        if not os.path.isabs(root) or not root_identity or not display_name.strip():
            raise StateError("INVALID_INPUT", "An approved absolute root, identity, and name are required.")
        if len(root) > 1024 or len(display_name) > 200 or len(root_identity) > 512:
            raise StateError("INVALID_INPUT", "Project registration exceeds size limits.")
        key = os.path.normcase(os.path.normpath(root))
        with self._transaction(write=True) as db:
            existing = db.execute("SELECT * FROM projects WHERE root_key = ?", (key,)).fetchone()
            if existing:
                if existing["root_identity"] != root_identity:
                    raise StateError("ROOT_IDENTITY_CHANGED", "The approved root has been replaced.")
                return self._public_project(existing, sorted(_CAPABILITIES))
            project_id = f"project_{uuid4().hex}"
            try:
                db.execute(
                    "INSERT INTO projects(id,root,root_key,root_identity,display_name) VALUES (?,?,?,?,?)",
                    (project_id, root, key, root_identity, display_name),
                )
            except sqlite3.IntegrityError as exc:
                raise StateError("VERSION_CONFLICT", "That filesystem root is already registered.") from exc
            self._event(db, project_id, "project_registered", {"project_id": project_id})
            return self._public_project(self._project_row(db, project_id), sorted(_CAPABILITIES))

    def get_project(
        self, project_id: str, principal: str = "local", capability: str = "read"
    ) -> dict[str, Any]:
        with self._transaction() as db:
            return self._public_project(*self._authorize(db, project_id, principal, capability))

    def project_capabilities(self, project_id: str, principal: str) -> list[str]:
        with self._transaction() as db:
            row = db.execute("SELECT id FROM projects WHERE id = ?", (project_id,)).fetchone()
            if row is None:
                return []
            return self._capabilities(db, project_id, principal)

    def list_projects(self, principal: str = "local") -> list[dict[str, Any]]:
        with self._transaction() as db:
            found = []
            for row in db.execute("SELECT * FROM projects ORDER BY display_name, id"):
                caps = self._capabilities(db, row["id"], principal)
                if "read" in caps:
                    found.append(self._public_project(row, caps))
            return found

    def set_test_scope(self, project_id: str, runtime: str, files: list[str] | None) -> dict:
        """Store the paths approved by the local operator. None revokes them."""
        table = _TEST_SCOPE_TABLES[runtime]
        with self._transaction(write=True) as db:
            project = self._project_row(db, project_id)
            previous = db.execute(
                f"SELECT files FROM {table} WHERE project_id=?", (project_id,),
            ).fetchone()
            encoded = _json(files, 32_768) if files is not None else None
            changed = (previous["files"] if previous is not None else None) != encoded
            if changed:
                if encoded is None:
                    db.execute(f"DELETE FROM {table} WHERE project_id=?", (project_id,))
                else:
                    db.execute(
                        f"""INSERT INTO {table} VALUES (?,?)
                           ON CONFLICT(project_id) DO UPDATE SET files=excluded.files""",
                        (project_id, encoded),
                    )
                db.execute("UPDATE projects SET policy_revision=policy_revision+1 WHERE id=?", (project_id,))
                self._event(db, project_id, "test_scope_updated", {"runtime": runtime, "enabled": files is not None})
                project = self._project_row(db, project_id)
            return {"project_id": project_id, "policy_revision": project["policy_revision"], "runtime": runtime,
                    "files": files, "enabled": files is not None, "changed": changed}

    def get_test_scope(self, project_id: str, principal: str, runtime: str) -> dict | None:
        table = _TEST_SCOPE_TABLES[runtime]
        with self._transaction() as db:
            project, _ = self._authorize(db, project_id, principal, "execute")
            row = db.execute(f"SELECT files FROM {table} WHERE project_id=?", (project_id,)).fetchone()
            if row is None:
                return None
            return {"files": json.loads(row["files"]), "policy_revision": project["policy_revision"]}

    def grant(
        self, project_id: str, principal: str, capabilities: list[str], expires_at: str | None = None
    ) -> dict[str, Any]:
        if _id(principal) == "local":
            raise StateError("INVALID_INPUT", "Only a remote principal needs an explicit grant.")
        if (
            not isinstance(capabilities, list) or any(not isinstance(capability, str) for capability in capabilities)
            or "read" not in capabilities or not set(capabilities) <= _CAPABILITIES
        ):
            raise StateError("INVALID_INPUT", "Grant must include read and use recognized capabilities.")
        caps = sorted(set(capabilities))
        if expires_at is not None:
            try:
                expiration = datetime.fromisoformat(expires_at)
                if expiration.tzinfo is None or expiration <= datetime.now(timezone.utc):
                    raise ValueError
                expires_at = expiration.astimezone(timezone.utc).isoformat(timespec="microseconds")
            except (TypeError, ValueError) as exc:
                raise StateError("INVALID_INPUT", "Use an expiration in the future with a timezone.") from exc
        with self._transaction(write=True) as db:
            self._project_row(db, project_id)
            stored = db.execute(
                "SELECT * FROM grants WHERE project_id = ? AND principal = ?", (project_id, principal),
            ).fetchone()
            encoded_caps = _json(caps)
            if not stored or stored["revoked"] or (stored["capabilities"], stored["expires_at"]) != (
                encoded_caps, expires_at
            ):
                db.execute(
                    """INSERT INTO grants(project_id, principal, capabilities, expires_at) VALUES (?,?,?,?)
                       ON CONFLICT(project_id,principal) DO UPDATE SET capabilities=excluded.capabilities,
                       expires_at=excluded.expires_at, revoked=0""",
                    (project_id, principal, encoded_caps, expires_at),
                )
                db.execute("UPDATE projects SET policy_revision=policy_revision+1 WHERE id=?", (project_id,))
                self._event(db, project_id, "grant_updated", {"principal": principal, "capabilities": caps})
            return self._public_project(self._project_row(db, project_id), caps)

    def revoke(self, project_id: str, principal: str) -> dict[str, Any]:
        if _id(principal) == "local":
            raise StateError("INVALID_INPUT", "The local human control plane owns project grants.")
        with self._transaction(write=True) as db:
            self._project_row(db, project_id)
            changed = db.execute(
                "UPDATE grants SET revoked=1 WHERE project_id=? AND principal=? AND revoked=0",
                (project_id, principal),
            ).rowcount
            if changed:
                db.execute("UPDATE projects SET policy_revision=policy_revision+1 WHERE id=?", (project_id,))
                self._event(db, project_id, "grant_revoked", {"principal": principal})
            return self._public_project(self._project_row(db, project_id), [])

    @staticmethod
    def _event(
        db: sqlite3.Connection, project_id: str, kind: str, detail: dict[str, Any], job_id: str | None = None
    ) -> None:
        event = db.execute(
            "INSERT INTO events(project_id,job_id,kind,detail,created_at) VALUES (?,?,?,?,?)",
            (project_id, job_id, kind, _json(detail, 8192), _now()),
        )
        if event.lastrowid % 256 == 0:
            db.execute("DELETE FROM events WHERE sequence <= ?", (event.lastrowid - 10_000,))

    @staticmethod
    def _begin(
        db: sqlite3.Connection, project_id: str, principal: str, operation_id: str, payload: Any
    ) -> dict[str, Any]:
        args = (principal, project_id, _id(operation_id))
        digest = _hash(payload, 2_500_000)
        row = db.execute(
            "SELECT * FROM operations WHERE principal=? AND project_id=? AND id=?", args
        ).fetchone()
        if row:
            if row["request_hash"] != digest:
                raise StateError("VERSION_CONFLICT", "Operation ID was already used for a different request.")
            return {"status": row["status"], "result": json.loads(row["result"]) if row["result"] else None}
        now = _now()
        db.execute(
            """INSERT INTO operations(principal,project_id,id,request_hash,status,created_at,updated_at)
               VALUES (?,?,?,?,'pending',?,?)""",
            (*args, digest, now, now),
        )
        return {"status": "claimed", "result": None}

    def begin_operation(
        self, project_id: str, principal: str, operation_id: str, payload: Any, capability: str
    ) -> dict[str, Any]:
        with self._transaction(write=True) as db:
            self._authorize(db, project_id, principal, capability)
            return self._begin(db, project_id, principal, operation_id, payload)

    @staticmethod
    def _finish(
        db: sqlite3.Connection, project_id: str, principal: str, operation_id: str,
        result: Any, *, failed: bool = False,
    ) -> None:
        changed = db.execute(
            """UPDATE operations SET status=?,result=?,updated_at=?
               WHERE principal=? AND project_id=? AND id=? AND status='pending'""",
            ("failed" if failed else "succeeded", _json(result), _now(), principal, project_id, _id(operation_id)),
        ).rowcount
        if changed != 1:
            raise StateError("VERSION_CONFLICT", "Operation is missing or no longer pending.")

    def finish_operation(
        self, project_id: str, principal: str, operation_id: str, result: Any, *, failed: bool = False
    ) -> None:
        # Controller-only reporting. A revocation cannot erase the effect of an already authorized operation.
        with self._transaction(write=True) as db:
            self._finish(db, project_id, principal, operation_id, result, failed=failed)

    def checkpoint(
        self, project_id: str, principal: str, task_id: str, summary: str, operation_id: str,
        objective: str = "", next_action: str = "", changed_files: list | None = None,
        test_evidence: list | None = None, accepted_decisions: list | None = None,
    ) -> dict[str, Any]:
        _id(task_id)
        if not all(isinstance(field, str) for field in (summary, objective, next_action)) or not summary.strip():
            raise StateError("INVALID_INPUT", "Provide a visible checkpoint summary.")
        if any(
            field is not None and not isinstance(field, list)
            for field in (changed_files, test_evidence, accepted_decisions)
        ):
            raise StateError("INVALID_INPUT", "Checkpoint collections must be lists.")
        packet = {
            "summary": summary, "objective": objective, "next_action": next_action,
            "changed_files": changed_files or [], "test_evidence": test_evidence or [],
            "accepted_decisions": accepted_decisions or [],
        }
        _json(packet, 32_768)
        with self._transaction(write=True) as db:
            project, caps = self._authorize(db, project_id, principal, "checkpoint")
            result = self._begin(db, project_id, principal, operation_id, {"checkpoint": packet, "task_id": task_id})
            if result["status"] == "succeeded":
                return result["result"]
            if result["status"] != "claimed":
                raise StateError("UNKNOWN_AFTER_RESTART", "Checkpoint needs reconciliation.")
            now = _now()
            db.execute(
                """INSERT INTO tasks(project_id,id,objective,updated_at) VALUES (?,?,?,?)
                   ON CONFLICT(project_id,id) DO UPDATE SET updated_at=excluded.updated_at,
                   objective=CASE WHEN excluded.objective='' THEN tasks.objective ELSE excluded.objective END""",
                (project_id, task_id, objective, now),
            )
            revision = db.execute(
                "SELECT COALESCE(MAX(revision),0)+1 FROM checkpoints WHERE project_id=? AND task_id=?",
                (project_id, task_id),
            ).fetchone()[0]
            db.execute(
                "INSERT INTO checkpoints VALUES (?,?,?,?,?)",
                (project_id, task_id, revision, _json(packet), now),
            )
            reply = {
                "project_id": project_id, "task_id": task_id, "checkpoint_revision": revision,
                "policy_revision": project["policy_revision"], "policy_hash": self._public_project(project, caps)["policy_hash"],
            }
            self._finish(db, project_id, principal, operation_id, reply)
            self._event(db, project_id, "checkpoint_saved", {"task_id": task_id, "revision": revision})
            return reply

    def resume(self, project_id: str, principal: str = "local", task_id: str | None = None) -> dict[str, Any]:
        with self._transaction() as db:
            row, caps = self._authorize(db, project_id, principal, "read")
            if task_id is None:
                task = db.execute(
                    "SELECT * FROM tasks WHERE project_id=? ORDER BY updated_at DESC, id LIMIT 1", (project_id,)
                ).fetchone()
            else:
                task = db.execute(
                    "SELECT * FROM tasks WHERE project_id=? AND id=?", (project_id, _id(task_id))
                ).fetchone()
                if task is None:
                    raise StateError("NOT_FOUND", "The selected task does not exist in this project.")
            task_id = task["id"] if task is not None else None
            checkpoint = db.execute(
                """SELECT * FROM checkpoints WHERE project_id=? AND task_id=?
                   ORDER BY revision DESC LIMIT 1""",
                (project_id, task_id),
            ).fetchone()
            packet: dict[str, Any] = {
                "summary": "", "next_action": "", "changed_files": [], "test_evidence": [],
                "accepted_decisions": [],
            }
            if checkpoint:
                packet = json.loads(checkpoint["packet"])
            task_jobs = db.execute(
                """SELECT id,status FROM jobs WHERE project_id=? AND task_id=?
                   ORDER BY updated_at DESC,id LIMIT 50""", (project_id, task_id),
            ).fetchall()
            open_tasks = db.execute(
                """SELECT id,objective,status,updated_at FROM tasks WHERE project_id=? AND status='active'
                   ORDER BY updated_at DESC, id LIMIT 20""", (project_id,),
            ).fetchall()
            observations = self._list_model_capabilities_rows(db)
            ckpt_rev = checkpoint["revision"] if checkpoint else 0
            tid = task_id or "project"
            bounded_tid = (
                f"{tid[:71]}-{hashlib.sha256(tid.encode('utf-8')).hexdigest()[:8]}"
                if len(tid) > 80
                else tid
            )
            fallback_op_id = f"fallback-{bounded_tid}-rev{ckpt_rev}"
            if len(fallback_op_id) > 128:
                fallback_op_id = f"fallback-{hashlib.sha256(fallback_op_id.encode('utf-8')).hexdigest()[:16]}-rev{ckpt_rev}"[:128]
            fallback_plan = capabilities.build_fallback_plan(
                project_id=project_id,
                task_id=task_id,
                operation_id=fallback_op_id,
                principal=principal,
                required_capabilities=("file_write", "command_exec"),
                observations=observations,
                project_root_hint=row["root"] if principal == "local" else None,
            )
            return {
                **packet, "instance_id": self.instance_id, "project_id": project_id, "task_id": task_id,
                "task_status": task["status"] if task is not None else None,
                "objective": task["objective"] if task is not None else "",
                "checkpoint_revision": ckpt_rev,
                "policy_revision": row["policy_revision"], "policy_hash": self._public_project(row, caps)["policy_hash"],
                "running_job_ids": [job["id"] for job in task_jobs if job["status"] in _ACTIVE],
                "pending_approvals": [job["id"] for job in task_jobs if job["status"] == "waiting_for_approval"],
                "recent_jobs": [{"job_id": job["id"], "status": job["status"]} for job in task_jobs],
                "open_tasks": [
                    {"task_id": item["id"], "objective": item["objective"], "status": item["status"], "updated_at": item["updated_at"]}
                    for item in open_tasks
                ],
                "model_capabilities": capabilities.aggregate_capabilities(observations, principal=principal),
                "fallback_plan": fallback_plan,
                "handoff_ready": True,
                "client_capability_note": "Recheck host tool availability after switching models.",
            }

    @staticmethod
    def _job_row(db: sqlite3.Connection, job_id: str) -> sqlite3.Row:
        row = db.execute("SELECT * FROM jobs WHERE id=?", (_id(job_id),)).fetchone()
        if row is None:
            raise StateError("NOT_FOUND", "Job is not available.")
        return row

    @staticmethod
    def _job(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        value["job_id"] = value.pop("id")
        value["intent"] = json.loads(value["intent"])
        value["evidence"] = json.loads(value["evidence"]) if value["evidence"] else None
        return value

    def create_job(
        self, project_id: str, principal: str, task_id: str, operation_id: str, intent: dict[str, Any],
        *, active_limit: int = 50,
    ) -> dict[str, Any]:
        _id(task_id)
        encoded_intent = _json(intent, 32_768)
        with self._transaction(write=True) as db:
            self._authorize(db, project_id, principal, "execute")
            op = self._begin(db, project_id, principal, operation_id, {"task_id": task_id, "job": intent})
            if op["status"] == "succeeded":
                job = self._job_row(db, op["result"]["job_id"])
                return {**self._job(job), "created": False}
            if op["status"] != "claimed":
                raise StateError("UNKNOWN_AFTER_RESTART", "Existing job launch needs reconciliation.")
            admitted = db.execute(
                "SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running','cancelling','waiting_for_approval')"
            ).fetchone()[0]
            if admitted >= active_limit:
                raise StateError("RESOURCE_BUDGET_EXCEEDED", "The shared job admission limit was reached.")
            now, job_id = _now(), f"job_{uuid4().hex}"
            db.execute(
                """INSERT INTO tasks(project_id,id,objective,updated_at) VALUES (?,?,'',?)
                   ON CONFLICT(project_id,id) DO UPDATE SET updated_at=excluded.updated_at""",
                (project_id, task_id, now),
            )
            db.execute(
                """INSERT INTO jobs(id,project_id,task_id,principal,operation_id,intent,status,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,'queued',?,?)""",
                (job_id, project_id, task_id, principal, operation_id, encoded_intent, now, now),
            )
            self._finish(db, project_id, principal, operation_id, {"job_id": job_id})
            self._event(db, project_id, "job_created", {"status": "queued"}, job_id)
            return {**self._job(self._job_row(db, job_id)), "created": True}

    def get_job(self, project_id: str, principal: str, job_id: str) -> dict[str, Any]:
        with self._transaction() as db:
            self._authorize(db, project_id, principal, "read")
            row = self._job_row(db, job_id)
            if row["project_id"] != project_id:
                raise StateError("NOT_FOUND", "Job is not available in this project.")
            return self._job(row)

    def list_jobs(self, project_id: str, principal: str, task_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction() as db:
            self._authorize(db, project_id, principal, "read")
            if task_id is None:
                rows = db.execute(
                    "SELECT * FROM jobs WHERE project_id=? ORDER BY updated_at DESC,id LIMIT 50", (project_id,),
                )
            else:
                rows = db.execute(
                    "SELECT * FROM jobs WHERE project_id=? AND task_id=? ORDER BY updated_at DESC,id LIMIT 50",
                    (project_id, _id(task_id)),
                )
            return [self._job(row) for row in rows]

    def update_job(
        self, job_id: str, *, status: str, exit_code: int | None = None, evidence: dict | None = None,
    ) -> dict[str, Any]:
        """Accept state changes from the trusted execution supervisor, never model IPC."""
        with self._transaction(write=True) as db:
            row = self._job_row(db, job_id)
            if status != row["status"] and status not in _TRANSITIONS.get(row["status"], set()):
                raise StateError("VERSION_CONFLICT", "Illegal job status transition.")
            db.execute(
                """UPDATE jobs SET status=?,exit_code=COALESCE(?,exit_code),
                   evidence=COALESCE(?,evidence),updated_at=? WHERE id=?""",
                (status, exit_code, _json(evidence, 131_072) if evidence is not None else None, _now(), job_id),
            )
            self._event(db, row["project_id"], "job_status", {"status": status, "exit_code": exit_code}, job_id)
            return self._job(self._job_row(db, job_id))

    @staticmethod
    def _artifact(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        value["artifact_id"] = value.pop("id")
        return value

    def record_artifact(
        self, project_id: str, task_id: str, storage_ref: str, sha256: str, size: int, media_type: str,
    ) -> dict[str, Any]:
        """Record a controller-owned file reference. The caller must enforce read containment."""
        if not all(isinstance(value, str) for value in (storage_ref, sha256, media_type)):
            raise StateError("INVALID_INPUT", "Artifact metadata must use strings.")
        relative = PurePosixPath(storage_ref)
        if (
            relative.is_absolute() or not relative.parts or ".." in relative.parts
            or relative.as_posix() != storage_ref or len(storage_ref) > 512
            or any(
                not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", part)
                or part.endswith(".") or _WINDOWS_DEVICE.fullmatch(part.split(".")[0])
                for part in relative.parts
            )
        ):
            raise StateError("INVALID_INPUT", "Artifact storage reference must be a canonical relative path.")
        digest = sha256.removeprefix("sha256:")
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise StateError("INVALID_INPUT", "Artifact requires a SHA-256 digest.")
        if type(size) is not int or not 0 <= size <= 2**63 - 1 or not re.fullmatch(
            r"[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+", media_type,
        ):
            raise StateError("INVALID_INPUT", "Artifact size and MIME type are invalid.")
        with self._transaction(write=True) as db:
            self._project_row(db, project_id)
            task = db.execute(
                "SELECT 1 FROM tasks WHERE project_id=? AND id=?", (project_id, _id(task_id)),
            ).fetchone()
            if task is None:
                raise StateError("NOT_FOUND", "Task is not available in this project.")
            lookup = (project_id, task_id, storage_ref, f"sha256:{digest}")
            row = db.execute(
                "SELECT * FROM artifacts WHERE project_id=? AND task_id=? AND storage_ref=? AND sha256=?", lookup,
            ).fetchone()
            if row is not None:
                if row["size"] != size or row["media_type"] != media_type:
                    raise StateError("VERSION_CONFLICT", "Artifact metadata does not match the recorded reference.")
                return self._artifact(row)
            artifact_id = f"artifact_{uuid4().hex}"
            db.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?)", (artifact_id, *lookup, size, media_type, _now()))
            self._event(db, project_id, "artifact_recorded", {"artifact_id": artifact_id, "task_id": task_id})
            return self._artifact(db.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone())

    def get_artifact(self, project_id: str, principal: str, artifact_id: str) -> dict[str, Any]:
        with self._transaction() as db:
            self._authorize(db, project_id, principal, "read")
            row = db.execute(
                "SELECT * FROM artifacts WHERE project_id=? AND id=?", (project_id, _id(artifact_id)),
            ).fetchone()
            if row is None:
                raise StateError("NOT_FOUND", "Artifact is not available in this project.")
            return self._artifact(row)

    def list_artifacts(
        self, project_id: str, principal: str, task_id: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._transaction() as db:
            self._authorize(db, project_id, principal, "read")
            rows = db.execute(
                """SELECT * FROM artifacts WHERE project_id=? AND (? IS NULL OR task_id=?)
                   ORDER BY created_at DESC,id LIMIT 50""",
                (project_id, task_id, _id(task_id) if task_id is not None else None),
            )
            return [self._artifact(row) for row in rows]

    def record_verification(
        self, project_id: str, check_id: str, verdict: str, evidence: str, model: str | None = None,
    ) -> dict[str, Any]:
        if verdict not in {"PASS", "FAIL", "BLOCKED", "NOT_RUN"}:
            raise StateError("INVALID_INPUT", "Unknown verification verdict.")
        if not isinstance(evidence, str) or not evidence.strip() or len(evidence) > 4000:
            raise StateError("INVALID_INPUT", "Verification evidence must be between 1 and 4000 characters.")
        if model is not None and (not isinstance(model, str) or len(model) > 100):
            raise StateError("INVALID_INPUT", "Invalid observed model label.")
        with self._transaction(write=True) as db:
            self._project_row(db, project_id)
            now = _now()
            new = db.execute(
                """INSERT INTO verification(project_id,check_id,verdict,evidence,model,created_at)
                   VALUES (?,?,?,?,?,?)""",
                (project_id, _id(check_id), verdict, evidence, model, now),
            )
            return dict(db.execute("SELECT * FROM verification WHERE sequence=?", (new.lastrowid,)).fetchone())

    def list_verification(self, project_id: str, principal: str) -> list[dict[str, Any]]:
        with self._transaction() as db:
            self._authorize(db, project_id, principal, "read")
            rows = db.execute(
                "SELECT * FROM verification WHERE project_id=? ORDER BY sequence DESC LIMIT 50", (project_id,),
            )
            return [dict(row) for row in rows]

    def recover_orphans(self) -> dict[str, int]:
        """Journal uncertain operations after a verified exclusive broker replacement."""
        with self._transaction(write=True) as db:
            now = _now()
            operations = db.execute(
                "UPDATE operations SET status='unknown_after_restart',updated_at=? WHERE status='pending'", (now,)
            ).rowcount
            jobs = db.execute(
                """SELECT id,project_id FROM jobs
                   WHERE status IN ('queued','running','cancelling','waiting_for_approval')"""
            ).fetchall()
            db.execute(
                """UPDATE jobs SET status='unknown_after_restart',updated_at=?
                   WHERE status IN ('queued','running','cancelling','waiting_for_approval')""", (now,),
            )
            for job in jobs:
                self._event(db, job["project_id"], "job_recovery_required", {}, job["id"])
            return {"operations": operations, "jobs": len(jobs)}

    @staticmethod
    def _read_exec_policy_row(db: sqlite3.Connection, project_id: str) -> dict[str, Any]:
        row = db.execute("SELECT * FROM project_exec_policies WHERE project_id=?", (project_id,)).fetchone()
        if row is None:
            return {"max_files": 32, "max_total_bytes": 524_288, "allow_git": True, "updated_at": None}
        return {
            "max_files": int(row["max_files"]),
            "max_total_bytes": int(row["max_total_bytes"]),
            "allow_git": bool(row["allow_git"]),
            "updated_at": row["updated_at"],
        }

    def get_exec_policy(self, project_id: str) -> dict[str, Any]:
        with self._transaction() as db:
            project = self._project_row(db, project_id)
            return {
                "project_id": project_id,
                "policy_revision": project["policy_revision"],
                **self._read_exec_policy_row(db, project_id),
            }

    def set_exec_policy(
        self,
        project_id: str,
        *,
        max_files: int = 32,
        max_total_bytes: int = 524_288,
        allow_git: bool = True,
    ) -> dict[str, Any]:
        if isinstance(max_files, bool) or not isinstance(max_files, int) or not 1 <= max_files <= 256:
            raise StateError("INVALID_INPUT", "max_files must be an integer between 1 and 256.")
        if (
            isinstance(max_total_bytes, bool)
            or not isinstance(max_total_bytes, int)
            or not 4096 <= max_total_bytes <= 8 * 1024 * 1024
        ):
            raise StateError("INVALID_INPUT", "max_total_bytes must be between 4096 and 8388608 bytes.")
        if not isinstance(allow_git, bool):
            raise StateError("INVALID_INPUT", "allow_git must be a boolean.")
        with self._transaction(write=True) as db:
            self._project_row(db, project_id)
            now = _now()
            db.execute(
                """INSERT INTO project_exec_policies VALUES (?,?,?,?,?)
                   ON CONFLICT(project_id) DO UPDATE SET
                   max_files=excluded.max_files, max_total_bytes=excluded.max_total_bytes,
                   allow_git=excluded.allow_git, updated_at=excluded.updated_at""",
                (project_id, max_files, max_total_bytes, int(allow_git), now),
            )
            db.execute("UPDATE projects SET policy_revision=policy_revision+1 WHERE id=?", (project_id,))
            self._event(
                db,
                project_id,
                "exec_policy_updated",
                {"max_files": max_files, "max_total_bytes": max_total_bytes, "allow_git": allow_git},
            )
            project = self._project_row(db, project_id)
            return {
                "project_id": project_id,
                "policy_revision": project["policy_revision"],
                "max_files": max_files,
                "max_total_bytes": max_total_bytes,
                "allow_git": allow_git,
                "updated_at": now,
            }

    def get_task(self, project_id: str, principal: str, task_id: str) -> dict[str, Any]:
        with self._transaction() as db:
            row, _ = self._authorize(db, project_id, principal, "read")
            task = db.execute(
                "SELECT * FROM tasks WHERE project_id=? AND id=?", (project_id, _id(task_id)),
            ).fetchone()
            if task is None:
                raise StateError("NOT_FOUND", "The selected task does not exist in this project.")
            checkpoint = db.execute(
                "SELECT * FROM checkpoints WHERE project_id=? AND task_id=? ORDER BY revision DESC LIMIT 1",
                (project_id, task_id),
            ).fetchone()
            deps = db.execute(
                "SELECT depends_on_task_id FROM task_dependencies WHERE project_id=? AND task_id=? ORDER BY depends_on_task_id",
                (project_id, task_id),
            ).fetchall()
            jobs = db.execute(
                "SELECT id,status,exit_code,created_at,updated_at FROM jobs WHERE project_id=? AND task_id=? ORDER BY updated_at DESC, id LIMIT 50",
                (project_id, task_id),
            ).fetchall()
            artifact_count = db.execute(
                "SELECT COUNT(*) FROM artifacts WHERE project_id=? AND task_id=?", (project_id, task_id),
            ).fetchone()[0]
            packet = json.loads(checkpoint["packet"]) if checkpoint else {
                "summary": "", "next_action": "", "changed_files": [], "test_evidence": [], "accepted_decisions": [],
            }
            return {
                "project_id": project_id,
                "task_id": task["id"],
                "objective": task["objective"],
                "status": task["status"],
                "updated_at": task["updated_at"],
                "policy_revision": row["policy_revision"],
                "checkpoint_revision": checkpoint["revision"] if checkpoint else 0,
                "checkpoint": packet,
                "depends_on": [item["depends_on_task_id"] for item in deps],
                "artifact_count": int(artifact_count),
                "jobs": [dict(item) for item in jobs],
            }

    def get_policy_summary(self, project_id: str, principal: str) -> dict[str, Any]:
        with self._transaction() as db:
            row, caps = self._authorize(db, project_id, principal, "read")
            scopes = {}
            for runtime, table in _TEST_SCOPE_TABLES.items():
                scope_row = db.execute(f"SELECT files FROM {table} WHERE project_id=?", (project_id,)).fetchone()
                files = json.loads(scope_row["files"]) if scope_row else []
                scopes[runtime] = {"enabled": scope_row is not None, "file_count": len(files), "files": files}
            grant_rows = db.execute(
                "SELECT principal,capabilities,expires_at,revoked FROM grants WHERE project_id=? ORDER BY principal",
                (project_id,),
            ).fetchall()
            grants = [
                {
                    "principal": g["principal"],
                    "capabilities": sorted(json.loads(g["capabilities"])),
                    "expires_at": g["expires_at"],
                    "revoked": bool(g["revoked"]),
                }
                for g in grant_rows
                if principal == "local" or g["principal"] == principal
            ]
            return {
                **self._public_project(row, caps),
                "exec_policy": self._read_exec_policy_row(db, project_id),
                "test_scopes": scopes,
                "grants": grants,
            }

    def add_task_dependency(self, project_id: str, task_id: str, depends_on_task_id: str) -> dict[str, Any]:
        _id(task_id)
        _id(depends_on_task_id)
        if task_id == depends_on_task_id:
            raise StateError("INVALID_INPUT", "A task cannot depend on itself.")
        with self._transaction(write=True) as db:
            self._project_row(db, project_id)
            for tid in (task_id, depends_on_task_id):
                if db.execute("SELECT 1 FROM tasks WHERE project_id=? AND id=?", (project_id, tid)).fetchone() is None:
                    raise StateError("NOT_FOUND", f"Task '{tid}' does not exist in this project.")
            visited = set()
            pending = [depends_on_task_id]
            while pending:
                current = pending.pop()
                if current == task_id:
                    raise StateError("INVALID_INPUT", "Adding this dependency would create a cycle.")
                if current in visited:
                    continue
                visited.add(current)
                for row in db.execute(
                    "SELECT depends_on_task_id FROM task_dependencies WHERE project_id=? AND task_id=?",
                    (project_id, current),
                ):
                    pending.append(row["depends_on_task_id"])
            now = _now()
            db.execute(
                "INSERT OR IGNORE INTO task_dependencies VALUES (?,?,?,?)",
                (project_id, task_id, depends_on_task_id, now),
            )
            return {"project_id": project_id, "task_id": task_id, "depends_on_task_id": depends_on_task_id, "created_at": now}

    def list_task_dependencies(self, project_id: str, principal: str, task_id: str) -> list[str]:
        with self._transaction() as db:
            self._authorize(db, project_id, principal, "read")
            rows = db.execute(
                "SELECT depends_on_task_id FROM task_dependencies WHERE project_id=? AND task_id=? ORDER BY depends_on_task_id",
                (project_id, _id(task_id)),
            ).fetchall()
            return [row["depends_on_task_id"] for row in rows]

    def record_incident(
        self,
        source: str,
        category: str,
        summary: str,
        *,
        http_status: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(source, str) or not source.strip() or len(source) > 100:
            raise StateError("INVALID_INPUT", "Incident source must be 1..100 characters.")
        if not isinstance(category, str) or not category.strip() or len(category) > 100:
            raise StateError("INVALID_INPUT", "Incident category must be 1..100 characters.")
        if not isinstance(summary, str) or not summary.strip() or len(summary) > 1000:
            raise StateError("INVALID_INPUT", "Incident summary must be 1..1000 characters.")
        incident_id = "inc-" + uuid4().hex[:16]
        now = _now()
        encoded_details = _json(details or {}, 32_768)
        with self._transaction(write=True) as db:
            db.execute(
                "INSERT INTO connection_incidents VALUES (?,?,?,?,?,?,?)",
                (incident_id, source.strip(), category.strip(), http_status, summary.strip(), encoded_details, now),
            )
            return {
                "incident_id": incident_id,
                "source": source.strip(),
                "category": category.strip(),
                "http_status": http_status,
                "summary": summary.strip(),
                "details": details or {},
                "created_at": now,
            }

    def list_incidents(self, limit: int = 20) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise StateError("INVALID_INPUT", "Incident limit must be between 1 and 100.")
        with self._transaction() as db:
            rows = db.execute(
                "SELECT * FROM connection_incidents ORDER BY created_at DESC, id LIMIT ?", (limit,),
            ).fetchall()
            return [
                {
                    "incident_id": row["id"],
                    "source": row["source"],
                    "category": row["category"],
                    "http_status": row["http_status"],
                    "summary": row["summary"],
                    "details": json.loads(row["details"]),
                    "created_at": row["created_at"],
                }
                for row in rows
            ]

    def list_workers(self, project_id: str | None = None, principal: str = "local") -> dict[str, Any]:
        with self._transaction() as db:
            profiles = [
                {
                    "name": row["name"],
                    "role_description": row["role_description"],
                    "allowed_capabilities": json.loads(row["allowed_capabilities"]),
                    "max_memory_mb": int(row["max_memory_mb"]),
                    "max_cpu_pct": int(row["max_cpu_pct"]),
                    "isolation_mode": row["isolation_mode"],
                    "enabled": bool(row["enabled"]),
                }
                for row in db.execute("SELECT * FROM worker_profiles ORDER BY name")
            ]
            workers: list[dict[str, Any]] = []
            if project_id is not None:
                self._authorize(db, project_id, principal, "read")
                rows = db.execute(
                    "SELECT * FROM workers WHERE project_id=? ORDER BY updated_at DESC, id LIMIT 50", (project_id,),
                ).fetchall()
            else:
                rows = db.execute("SELECT * FROM workers ORDER BY updated_at DESC, id LIMIT 50").fetchall()
            for row in rows:
                if principal == "local" or "read" in self._capabilities(db, row["project_id"], principal):
                    workers.append(dict(row))
            return {"profiles": profiles, "workers": workers}

    def cancel_worker_record(self, worker_id: str, principal: str) -> dict[str, Any]:
        with self._transaction(write=True) as db:
            row = db.execute("SELECT * FROM workers WHERE id=?", (_id(worker_id),)).fetchone()
            if row is None:
                raise StateError("NOT_FOUND", "Worker record not found.")
            self._authorize(db, row["project_id"], principal, "execute")
            now = _now()
            if row["status"] in {"queued", "starting", "running"}:
                db.execute(
                    "UPDATE workers SET status='cancelled', updated_at=? WHERE id=?", (now, worker_id),
                )
            updated = db.execute("SELECT * FROM workers WHERE id=?", (worker_id,)).fetchone()
            return dict(updated)

    def record_resource_sample(
        self,
        *,
        cpu_percent: float | None,
        ram_total_mb: int,
        ram_available_mb: int,
        ram_used_percent: int,
        active_jobs: int,
        active_workers: int,
        sample_json: dict[str, Any],
    ) -> dict[str, Any]:
        now = _now()
        encoded = _json(sample_json, 16_384)
        with self._transaction(write=True) as db:
            cursor = db.execute(
                "INSERT INTO resource_samples(cpu_percent,ram_total_mb,ram_available_mb,ram_used_percent,active_jobs,active_workers,sample_json,created_at) VALUES (?,?,?,?,?,?,?,?)",
                (cpu_percent, ram_total_mb, ram_available_mb, ram_used_percent, active_jobs, active_workers, encoded, now),
            )
            return {
                "sequence": int(cursor.lastrowid),
                "cpu_percent": cpu_percent,
                "ram_total_mb": ram_total_mb,
                "ram_available_mb": ram_available_mb,
                "ram_used_percent": ram_used_percent,
                "active_jobs": active_jobs,
                "active_workers": active_workers,
                "created_at": now,
            }

    def health_snapshot(self) -> dict[str, Any]:
        with self._transaction() as db:
            project_count = int(db.execute("SELECT COUNT(*) FROM projects").fetchone()[0])
            task_count = int(db.execute("SELECT COUNT(*) FROM tasks WHERE status='active'").fetchone()[0])
            active_jobs = int(
                db.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running','cancelling')").fetchone()[0]
            )
            incidents_count = int(db.execute("SELECT COUNT(*) FROM connection_incidents").fetchone()[0])
            worker_count = int(
                db.execute("SELECT COUNT(*) FROM workers WHERE status IN ('queued','starting','running')").fetchone()[0]
            )
        db_size = self.path.stat().st_size if self.path.exists() else 0
        return {
            "instance_id": self.instance_id,
            "schema_version": SCHEMA_VERSION,
            "db_size_bytes": db_size,
            "projects": project_count,
            "active_tasks": task_count,
            "active_jobs": active_jobs,
            "active_workers": worker_count,
            "connection_incidents": incidents_count,
        }

    def backup_to(self, target_path: str | os.PathLike[str]) -> dict[str, Any]:
        dest = Path(target_path).resolve()
        src_resolved = self.path.resolve()
        if dest == src_resolved:
            raise StateError("INVALID_INPUT", "Backup destination must differ from the live state database.")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as src, closing(sqlite3.connect(dest, timeout=5)) as dst:
            src.backup(dst)
            check = dst.execute("PRAGMA integrity_check").fetchone()
        if not check or str(check[0]).lower() != "ok":
            raise StateError("BACKUP_FAILED", "SQLite integrity check failed on backup copy.")
        with dest.open("rb") as fh:
            digest = hashlib.file_digest(fh, "sha256").hexdigest()
        return {
            "path": str(dest),
            "size_bytes": dest.stat().st_size,
            "sha256": digest,
            "integrity_check": "ok",
        }

    @staticmethod
    def _list_model_capabilities_rows(
        db: sqlite3.Connection,
        *,
        model_id: str | None = None,
        surface: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT model_id, surface, capabilities_json, source, notes, observed_at FROM model_capabilities"
        clauses: list[str] = []
        params: list[Any] = []
        if model_id is not None:
            clauses.append("model_id = ?")
            params.append(model_id)
        if surface is not None:
            clauses.append("surface = ?")
            params.append(surface)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY model_id, surface"
        rows = db.execute(query, params).fetchall()
        return [
            {
                "model_id": row["model_id"],
                "surface": row["surface"],
                "capabilities": json.loads(row["capabilities_json"]),
                "source": row["source"],
                "notes": row["notes"],
                "observed_at": row["observed_at"],
            }
            for row in rows
        ]

    def record_model_capability(
        self,
        model_id: str,
        surface: str,
        observed_capabilities: dict[str, bool],
        *,
        source: str,
        notes: str = "",
        merge: bool = True,
    ) -> dict[str, Any]:
        try:
            norm_model = capabilities.normalize_model_id(model_id)
            norm_surface = capabilities.validate_surface(surface)
            norm_caps = capabilities.validate_capability_map(observed_capabilities)
        except ValueError as exc:
            raise StateError("INVALID_INPUT", str(exc)) from exc
        if not isinstance(source, str) or not source.strip() or len(source.strip()) > 64:
            raise StateError("INVALID_INPUT", "Capability observation source must be 1..64 characters.")
        if not isinstance(notes, str) or len(notes) > 1000:
            raise StateError("INVALID_INPUT", "Capability observation notes must be <= 1000 characters.")
        if not isinstance(merge, bool):
            raise StateError("INVALID_INPUT", "merge must be a boolean.")
        clean_source = source.strip()
        with self._transaction(write=True) as db:
            if merge:
                existing = db.execute(
                    "SELECT capabilities_json FROM model_capabilities WHERE model_id=? AND surface=?",
                    (norm_model, norm_surface),
                ).fetchone()
                if existing is not None:
                    merged = {**json.loads(existing["capabilities_json"]), **norm_caps}
                    norm_caps = capabilities.validate_capability_map(merged)
            now = _now()
            encoded = _json(norm_caps, 8192)
            db.execute(
                """INSERT INTO model_capabilities(model_id, surface, capabilities_json, source, notes, observed_at)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(model_id, surface) DO UPDATE SET
                   capabilities_json=excluded.capabilities_json,
                   source=excluded.source,
                   notes=excluded.notes,
                   observed_at=excluded.observed_at""",
                (norm_model, norm_surface, encoded, clean_source, notes, now),
            )
            return {
                "model_id": norm_model,
                "surface": norm_surface,
                "capabilities": norm_caps,
                "source": clean_source,
                "notes": notes,
                "observed_at": now,
            }

    def list_model_capabilities(
        self,
        *,
        model_id: str | None = None,
        surface: str | None = None,
    ) -> list[dict[str, Any]]:
        try:
            norm_model = capabilities.normalize_model_id(model_id) if model_id is not None else None
            norm_surface = capabilities.validate_surface(surface) if surface is not None else None
        except ValueError as exc:
            raise StateError("INVALID_INPUT", str(exc)) from exc
        with self._transaction() as db:
            return self._list_model_capabilities_rows(db, model_id=norm_model, surface=norm_surface)

    def ensure_task(self, project_id: str, task_id: str, objective: str = "") -> dict[str, Any]:
        _id(task_id)
        if not isinstance(objective, str) or len(objective) > 4096:
            raise StateError("INVALID_INPUT", "Task objective must be <= 4096 characters.")
        with self._transaction(write=True) as db:
            self._project_row(db, project_id)
            now = _now()
            db.execute(
                """INSERT INTO tasks(project_id,id,objective,updated_at) VALUES (?,?,?,?)
                   ON CONFLICT(project_id,id) DO UPDATE SET updated_at=excluded.updated_at,
                   objective=CASE WHEN excluded.objective='' THEN tasks.objective ELSE excluded.objective END""",
                (project_id, task_id, objective, now),
            )
            row = db.execute("SELECT * FROM tasks WHERE project_id=? AND id=?", (project_id, task_id)).fetchone()
            return dict(row)

    def enqueue_worker_task(
        self,
        *,
        project_id: str,
        principal: str,
        task_id: str,
        role: str,
        objective: str,
        file_scope: list[str],
        mode: str = "mock",
        priority: int = 100,
        timeout_seconds: int = 60,
        max_attempts: int = 2,
    ) -> dict[str, Any]:
        _id(task_id)
        _id(role)
        if mode not in {"mock", "mxc"}:
            raise StateError("INVALID_INPUT", "Worker mode must be 'mock' or 'mxc'.")
        if not isinstance(objective, str) or not objective.strip() or len(objective) > 8192:
            raise StateError("INVALID_INPUT", "Worker objective must be 1..8192 characters.")
        if not isinstance(file_scope, list) or len(file_scope) > 50 or any(not isinstance(p, str) or not p for p in file_scope):
            raise StateError("INVALID_INPUT", "file_scope must be a list of up to 50 relative paths.")
        if isinstance(priority, bool) or not isinstance(priority, int) or not 1 <= priority <= 1000:
            raise StateError("INVALID_INPUT", "priority must be an integer between 1 and 1000.")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 900:
            raise StateError("INVALID_INPUT", "timeout_seconds must be between 1 and 900.")
        queue_id = "q_" + uuid4().hex[:24]
        now = _now()
        encoded_scope = _json(sorted(set(file_scope)), 16_384)
        with self._transaction(write=True) as db:
            self._authorize(db, project_id, principal, "execute")
            prof = db.execute("SELECT * FROM worker_profiles WHERE name=?", (role,)).fetchone()
            if prof is None:
                raise StateError("INVALID_INPUT", f"Unknown worker profile: {role}")
            db.execute(
                """INSERT INTO tasks(project_id,id,objective,updated_at) VALUES (?,?,?,?)
                   ON CONFLICT(project_id,id) DO UPDATE SET updated_at=excluded.updated_at,
                   objective=CASE WHEN tasks.objective='' THEN excluded.objective ELSE tasks.objective END""",
                (project_id, task_id, objective.strip(), now),
            )
            db.execute(
                """INSERT INTO task_queue(queue_id,project_id,task_id,role,objective,file_scope_json,mode,priority,
                   status,worker_id,attempt_count,max_attempts,timeout_seconds,result_json,error_json,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,'queued',NULL,0,?,?,NULL,NULL,?,?)""",
                (queue_id, project_id, task_id, role, objective.strip(), encoded_scope, mode, priority, max_attempts, timeout_seconds, now, now),
            )
            row = db.execute("SELECT * FROM task_queue WHERE queue_id=?", (queue_id,)).fetchone()
            return self._decode_queue_row(row)

    @staticmethod
    def _decode_queue_row(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["file_scope"] = json.loads(data.pop("file_scope_json"))
        data["result"] = json.loads(data.pop("result_json")) if data.get("result_json") else None
        data["error"] = json.loads(data.pop("error_json")) if data.get("error_json") else None
        return data

    def list_task_queue(self, project_id: str | None = None, principal: str = "local", status: str | None = None) -> list[dict[str, Any]]:
        with self._transaction() as db:
            if project_id is not None:
                self._authorize(db, project_id, principal, "read")
                if status is not None:
                    rows = db.execute(
                        "SELECT * FROM task_queue WHERE project_id=? AND status=? ORDER BY priority ASC, created_at ASC LIMIT 100",
                        (project_id, status),
                    ).fetchall()
                else:
                    rows = db.execute(
                        "SELECT * FROM task_queue WHERE project_id=? ORDER BY priority ASC, created_at ASC LIMIT 100",
                        (project_id,),
                    ).fetchall()
            else:
                rows = db.execute("SELECT * FROM task_queue ORDER BY priority ASC, created_at ASC LIMIT 100").fetchall()
            out = []
            for r in rows:
                if principal == "local" or "read" in self._capabilities(db, r["project_id"], principal):
                    out.append(self._decode_queue_row(r))
            return out

    def update_queue_item(
        self,
        queue_id: str,
        *,
        status: str,
        worker_id: str | None = None,
        increment_attempt: bool = False,
        result: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._transaction(write=True) as db:
            row = db.execute("SELECT * FROM task_queue WHERE queue_id=?", (_id(queue_id),)).fetchone()
            if row is None:
                raise StateError("NOT_FOUND", "Queue item not found.")
            attempts = int(row["attempt_count"]) + (1 if increment_attempt else 0)
            w_id = worker_id if worker_id is not None else row["worker_id"]
            res_json = _json(result, 32_768) if result is not None else row["result_json"]
            err_json = _json(error, 16_384) if error is not None else row["error_json"]
            db.execute(
                """UPDATE task_queue SET status=?, worker_id=?, attempt_count=?, result_json=?, error_json=?, updated_at=?
                   WHERE queue_id=?""",
                (status, w_id, attempts, res_json, err_json, now, queue_id),
            )
            if status == "succeeded":
                db.execute("UPDATE tasks SET status='completed', updated_at=? WHERE project_id=? AND id=?", (now, row["project_id"], row["task_id"]))
            updated = db.execute("SELECT * FROM task_queue WHERE queue_id=?", (queue_id,)).fetchone()
            return self._decode_queue_row(updated)

    def create_worker_record(
        self,
        *,
        worker_id: str,
        project_id: str,
        task_id: str,
        profile_name: str,
        principal: str,
        status: str,
        workspace_ref: str | None = None,
        pid: int | None = None,
        verification_reason: str | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._transaction(write=True) as db:
            db.execute(
                """INSERT INTO workers(id,project_id,task_id,profile_name,principal,status,workspace_ref,pid,verification_reason,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (_id(worker_id), project_id, _id(task_id), _id(profile_name), principal, status, workspace_ref, pid, verification_reason, now, now),
            )
            row = db.execute("SELECT * FROM workers WHERE id=?", (worker_id,)).fetchone()
            return dict(row)

    def update_worker_record(
        self,
        worker_id: str,
        *,
        status: str,
        pid: int | None = None,
        verification_reason: str | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._transaction(write=True) as db:
            row = db.execute("SELECT * FROM workers WHERE id=?", (_id(worker_id),)).fetchone()
            if row is None:
                raise StateError("NOT_FOUND", "Worker record not found.")
            new_pid = pid if pid is not None else row["pid"]
            new_reason = verification_reason if verification_reason is not None else row["verification_reason"]
            db.execute(
                "UPDATE workers SET status=?, pid=?, verification_reason=?, updated_at=? WHERE id=?",
                (status, new_pid, new_reason, now, worker_id),
            )
            return dict(db.execute("SELECT * FROM workers WHERE id=?", (worker_id,)).fetchone())

    def record_worker_event(
        self,
        worker_id: str,
        project_id: str,
        task_id: str,
        event_type: str,
        detail: dict[str, Any],
    ) -> dict[str, Any]:
        now = _now()
        encoded = _json(detail, 16_384)
        with self._transaction(write=True) as db:
            cur = db.execute(
                "INSERT INTO worker_events(worker_id,project_id,task_id,event_type,detail_json,created_at) VALUES (?,?,?,?,?,?)",
                (_id(worker_id), project_id, _id(task_id), event_type, encoded, now),
            )
            return {
                "sequence": int(cur.lastrowid),
                "worker_id": worker_id,
                "project_id": project_id,
                "task_id": task_id,
                "event_type": event_type,
                "detail": detail,
                "created_at": now,
            }

    def list_worker_events(self, worker_id: str, principal: str = "local") -> list[dict[str, Any]]:
        with self._transaction() as db:
            w = db.execute("SELECT * FROM workers WHERE id=?", (_id(worker_id),)).fetchone()
            if w is None:
                raise StateError("NOT_FOUND", "Worker record not found.")
            self._authorize(db, w["project_id"], principal, "read")
            rows = db.execute(
                "SELECT * FROM worker_events WHERE worker_id=? ORDER BY sequence ASC LIMIT 200", (worker_id,),
            ).fetchall()
            return [
                {
                    "sequence": int(r["sequence"]),
                    "worker_id": r["worker_id"],
                    "project_id": r["project_id"],
                    "task_id": r["task_id"],
                    "event_type": r["event_type"],
                    "detail": json.loads(r["detail_json"]),
                    "created_at": r["created_at"],
                }
                for r in rows
            ]

    def save_context_pack(self, project_id: str, principal: str, task_id: str, pack: dict[str, Any]) -> dict[str, Any]:
        _id(task_id)
        encoded = _json(pack, 65_536)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        now = _now()
        with self._transaction(write=True) as db:
            self._authorize(db, project_id, principal, "checkpoint")
            db.execute(
                """INSERT INTO tasks(project_id,id,objective,updated_at) VALUES (?,?,?,?)
                   ON CONFLICT(project_id,id) DO UPDATE SET updated_at=excluded.updated_at""",
                (project_id, task_id, str(pack.get("active_objective") or ""), now),
            )
            rev = int(
                db.execute(
                    "SELECT COALESCE(MAX(revision), 0) + 1 FROM context_packs WHERE project_id=? AND task_id=?",
                    (project_id, task_id),
                ).fetchone()[0]
            )
            db.execute(
                "INSERT INTO context_packs VALUES (?,?,?,?,?,?)",
                (project_id, task_id, rev, digest, encoded, now),
            )
            return {
                "project_id": project_id,
                "task_id": task_id,
                "revision": rev,
                "pack_sha256": digest,
                "created_at": now,
                "pack": pack,
            }

    def get_latest_context_pack(self, project_id: str, principal: str, task_id: str) -> dict[str, Any] | None:
        with self._transaction() as db:
            self._authorize(db, project_id, principal, "read")
            row = db.execute(
                "SELECT * FROM context_packs WHERE project_id=? AND task_id=? ORDER BY revision DESC LIMIT 1",
                (project_id, _id(task_id)),
            ).fetchone()
            if row is None:
                return None
            return {
                "project_id": project_id,
                "task_id": task_id,
                "revision": int(row["revision"]),
                "pack_sha256": row["pack_sha256"],
                "created_at": row["created_at"],
                "pack": json.loads(row["pack_json"]),
            }

