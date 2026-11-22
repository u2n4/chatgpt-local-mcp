-- Migration 0001: Preserve full compatibility with Edge Project Bridge v0.2.0 SQLite SCHEMA_VERSION = 3
-- Safe to run against both fresh V0.4.0 databases and migrated clones of live v0.2.0 state.sqlite3.

CREATE TABLE IF NOT EXISTS instance (
    slot INTEGER PRIMARY KEY CHECK (slot = 1),
    id TEXT NOT NULL,
    schema_version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    root TEXT NOT NULL,
    root_key TEXT NOT NULL UNIQUE,
    root_identity TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    policy_revision INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS grants (
    project_id TEXT NOT NULL REFERENCES projects(id),
    principal TEXT NOT NULL,
    capabilities TEXT NOT NULL,
    expires_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, principal)
);

CREATE TABLE IF NOT EXISTS python_test_scopes (
    project_id TEXT PRIMARY KEY REFERENCES projects(id),
    files TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS node_test_scopes (
    project_id TEXT PRIMARY KEY REFERENCES projects(id),
    files TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS powershell_test_scopes (
    project_id TEXT PRIMARY KEY REFERENCES projects(id),
    files TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS project_exec_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id),
    max_files INTEGER NOT NULL DEFAULT 32,
    max_total_bytes INTEGER NOT NULL DEFAULT 524288,
    allow_git INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    project_id TEXT NOT NULL REFERENCES projects(id),
    id TEXT NOT NULL,
    objective TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, id)
);

CREATE TABLE IF NOT EXISTS checkpoints (
    project_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    packet TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id, task_id) REFERENCES tasks(project_id, id),
    PRIMARY KEY (project_id, task_id, revision)
);

CREATE TABLE IF NOT EXISTS operations (
    principal TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id),
    id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (principal, project_id, id)
);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    principal TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    intent TEXT NOT NULL,
    status TEXT NOT NULL,
    exit_code INTEGER,
    evidence TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id, task_id) REFERENCES tasks(project_id, id)
);

CREATE TABLE IF NOT EXISTS events (
    sequence INTEGER PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    job_id TEXT REFERENCES jobs(id),
    kind TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    storage_ref TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    media_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id, task_id) REFERENCES tasks(project_id, id),
    UNIQUE (project_id, task_id, storage_ref, sha256)
);

CREATE TABLE IF NOT EXISTS verification (
    sequence INTEGER PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    check_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    evidence TEXT NOT NULL,
    model TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS connection_incidents (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    http_status INTEGER,
    summary TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL
);
