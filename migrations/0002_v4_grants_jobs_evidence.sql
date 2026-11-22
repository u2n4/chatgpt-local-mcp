-- Migration 0002: V0.4.0 Scoped Task Grants, Durable Runs, Idempotency Ledger, Evidence Manifests, Patch Journals
-- Schema version transitions cleanly 3 -> 4 while preserving all v0.2.0 rows and instance_id.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_grants (
    grant_id TEXT PRIMARY KEY,
    requester_principal TEXT NOT NULL,
    granting_owner TEXT NOT NULL,
    host_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id),
    workspace_id TEXT NOT NULL,
    baseline_hash TEXT NOT NULL,
    policy_revision INTEGER NOT NULL,
    categories_json TEXT NOT NULL,
    writable_paths_json TEXT NOT NULL,
    allowed_recipes_json TEXT NOT NULL,
    network_destinations_json TEXT NOT NULL,
    export_scope TEXT NOT NULL,
    integration_mode TEXT NOT NULL,
    limits_json TEXT NOT NULL,
    offline_policy TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_grants_project ON task_grants(project_id, requester_principal, revoked);

CREATE TABLE IF NOT EXISTS durable_runs (
    run_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id),
    workspace_id TEXT NOT NULL,
    grant_id TEXT,
    requester_principal TEXT NOT NULL,
    executor_identity TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    dedup_key TEXT NOT NULL UNIQUE,
    payload_digest TEXT NOT NULL,
    state TEXT NOT NULL,
    pid INTEGER,
    process_start_time_100ns INTEGER,
    exit_code INTEGER,
    agent_outcome TEXT,
    execution_outcome TEXT,
    verification_outcome TEXT,
    evidence_manifest_id TEXT,
    output_seq INTEGER NOT NULL DEFAULT 0,
    output_truncated INTEGER NOT NULL DEFAULT 0,
    output_dir TEXT NOT NULL,
    command_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_durable_runs_project_state ON durable_runs(project_id, state, updated_at DESC);

CREATE TABLE IF NOT EXISTS run_output_chunks (
    run_id TEXT NOT NULL REFERENCES durable_runs(run_id),
    seq INTEGER NOT NULL,
    stream TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (run_id, seq)
);

CREATE TABLE IF NOT EXISTS evidence_manifests (
    manifest_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES durable_runs(run_id),
    project_id TEXT NOT NULL REFERENCES projects(id),
    host_id TEXT NOT NULL,
    evidence_class TEXT NOT NULL,
    verdict TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    signature_ed25519 TEXT,
    signer_key_id TEXT,
    manifest_json TEXT NOT NULL,
    export_redacted_json TEXT,
    export_sha256 TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_project ON evidence_manifests(project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS patch_journals (
    journal_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    operation_id TEXT NOT NULL,
    state TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL,
    journal_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_patch_journals_project ON patch_journals(project_id, created_at DESC);
