-- Migration 0003: Paired Devices, Pairing Tokens, Provider Sessions & Capability Probes

CREATE TABLE IF NOT EXISTS paired_devices (
    host_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    public_key_hex TEXT NOT NULL UNIQUE,
    endpoint_url TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    status TEXT NOT NULL,
    last_heartbeat_at TEXT,
    paired_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pairing_tokens (
    token_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    target_host_id TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_sessions (
    session_id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    provider_session_ref TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id),
    workspace_id TEXT NOT NULL,
    baseline_hash TEXT NOT NULL,
    grant_id TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_provider_sessions_project ON provider_sessions(project_id, provider_id, updated_at DESC);
