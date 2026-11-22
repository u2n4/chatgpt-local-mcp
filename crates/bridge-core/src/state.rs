use bridge_platform::sha256_bytes;
use bridge_types::*;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MIGRATION_0001: &str = include_str!("../../../migrations/0001_v3_compat.sql");
const MIGRATION_0002: &str = include_str!("../../../migrations/0002_v4_grants_jobs_evidence.sql");
const MIGRATION_0003: &str = include_str!("../../../migrations/0003_v4_devices_providers.sql");

/// Parse SQLite runtime version `major.minor.patch` and check the SQLite WAL-reset fix gate (§4.1 [S14]):
/// 3.51.3+ or documented backports 3.44.6+ (in 3.44.x) / 3.50.7+ (in 3.50.x).
pub fn sqlite_runtime_version() -> String {
    rusqlite::version().to_string()
}

pub fn sqlite_wal_reset_fix_verified(version_str: &str) -> bool {
    let parts: Vec<u32> = version_str
        .split('.')
        .filter_map(|p| p.parse::<u32>().ok())
        .collect();
    if parts.len() < 3 {
        return false;
    }
    let (maj, min, pat) = (parts[0], parts[1], parts[2]);
    if maj > 3 {
        return true;
    }
    if maj < 3 {
        return false;
    }
    if min > 51 || (min == 51 && pat >= 3) {
        return true;
    }
    if min == 50 && pat >= 7 {
        return true;
    }
    if min == 44 && pat >= 6 {
        return true;
    }
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectRow {
    pub project_id: String,
    pub root: String,
    pub root_key: String,
    pub root_identity: String,
    pub display_name: String,
    pub policy_revision: u64,
    pub capabilities: Vec<String>,
    pub policy_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupReport {
    pub backup_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub sqlite_runtime_version: String,
    pub wal_reset_fix_verified: bool,
    pub integrity_ok: bool,
    pub foreign_key_issues: usize,
    pub instance_id: String,
    pub schema_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbHealthSnapshot {
    pub instance_id: String,
    pub sqlite_schema_version: u32,
    pub sqlite_runtime_version: String,
    pub sqlite_wal_reset_fix_verified: bool,
    pub projects: u64,
    pub active_grants: u64,
    pub active_runs: u64,
    pub evidence_manifests: u64,
    pub paired_devices: u64,
    pub db_size_bytes: u64,
}

#[derive(Clone)]
pub struct StateStore {
    path: PathBuf,
    conn: Arc<Mutex<Connection>>,
    instance_id: String,
}

impl StateStore {
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self, BridgeError> {
        Self::open_database(db_path.as_ref(), true)
    }

    /// Open the current state for execution without creating or migrating a database.
    pub fn open_current(db_path: impl AsRef<Path>) -> Result<Self, BridgeError> {
        Self::open_database(db_path.as_ref(), false)
    }

    fn open_database(db_path: &Path, migrate: bool) -> Result<Self, BridgeError> {
        let path = db_path.to_path_buf();
        if migrate && let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                BridgeError::new(
                    ErrorCode::StateAclUnsafe,
                    format!("Cannot create state directory: {e}"),
                    OriginLayer::StateStore,
                )
            })?;
        }
        let flags = if migrate { OpenFlags::default() } else { OpenFlags::SQLITE_OPEN_READ_WRITE };
        let conn = Connection::open_with_flags(&path, flags).map_err(|e| {
            BridgeError::new(
                ErrorCode::InternalError,
                format!("Failed to open SQLite database: {e}"),
                OriginLayer::StateStore,
            )
        })?;
        if !migrate {
            let version: u32 = conn.query_row("SELECT schema_version FROM instance WHERE slot = 1", [], |r| r.get(0)).map_err(db_err)?;
            if version != SQLITE_SCHEMA_VERSION {
                return Err(BridgeError::new(ErrorCode::SchemaUnsupported,
                    "Queued execution requires an existing v0.4 state; choose the development database.",
                    OriginLayer::StateStore));
            }
        }
        conn.pragma_update(None, "journal_mode", "WAL").map_err(db_err)?;
        conn.pragma_update(None, "busy_timeout", 75).map_err(db_err)?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(db_err)?;
        conn.pragma_update(None, "synchronous", "FULL").map_err(db_err)?;
        conn.pragma_update(None, "temp_store", "MEMORY").map_err(db_err)?;
        conn.pragma_update(None, "cache_size", -16000).map_err(db_err)?;

        if migrate {
            Self::run_migrations(&conn)?;
        }

        let instance_id: String = conn
            .query_row("SELECT id FROM instance WHERE slot = 1", [], |r| r.get(0))
            .map_err(db_err)?;

        Ok(Self {
            path,
            conn: Arc::new(Mutex::new(conn)),
            instance_id,
        })
    }

    fn run_migrations(conn: &Connection) -> Result<(), BridgeError> {
        conn.execute_batch(MIGRATION_0001).map_err(db_err)?;

        let current_ver: Option<u32> = conn
            .query_row(
                "SELECT schema_version FROM instance WHERE slot = 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;

        match current_ver {
            None => {
                let id = uuid::Uuid::new_v4().to_string();
                conn.execute(
                    "INSERT INTO instance(slot, id, schema_version) VALUES (1, ?1, ?2)",
                    params![id, SQLITE_SCHEMA_VERSION],
                )
                .map_err(db_err)?;
            }
            Some(v) if v <= SQLITE_SCHEMA_VERSION => {
                if v < SQLITE_SCHEMA_VERSION {
                    conn.execute(
                        "UPDATE instance SET schema_version = ?1 WHERE slot = 1",
                        params![SQLITE_SCHEMA_VERSION],
                    )
                    .map_err(db_err)?;
                }
            }
            Some(v) => {
                return Err(BridgeError::new(
                    ErrorCode::SchemaUnsupported,
                    format!(
                        "Database schema version {v} is newer than supported version {SQLITE_SCHEMA_VERSION}; do not silently downgrade."
                    ),
                    OriginLayer::StateStore,
                ));
            }
        }

        conn.execute_batch(MIGRATION_0002).map_err(db_err)?;
        conn.execute_batch(MIGRATION_0003).map_err(db_err)?;

        let now = Utc::now().to_rfc3339();
        for (ver, name, sql) in [
            (1i64, "0001_v3_compat", MIGRATION_0001),
            (2i64, "0002_v4_grants_jobs_evidence", MIGRATION_0002),
            (3i64, "0003_v4_devices_providers", MIGRATION_0003),
        ] {
            let sum = sha256_bytes(sql.as_bytes());
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, name, applied_at, checksum_sha256) VALUES (?1, ?2, ?3, ?4)",
                params![ver, name, now, sum],
            )
            .map_err(db_err)?;
        }
        Ok(())
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn db_path(&self) -> &Path {
        &self.path
    }

    pub fn version_contract(&self) -> VersionContract {
        let rt = sqlite_runtime_version();
        let mut mcp_vers = vec![MCP_MODERN_PROTOCOL_VERSION.to_string()];
        mcp_vers.extend(MCP_LEGACY_PROTOCOL_VERSIONS.iter().map(|s| s.to_string()));
        VersionContract {
            bridge_version: BRIDGE_VERSION.to_string(),
            bridge_contract_version: BRIDGE_CONTRACT_VERSION.to_string(),
            legacy_api_contract_version: LEGACY_API_CONTRACT_VERSION,
            sqlite_schema_version: SQLITE_SCHEMA_VERSION,
            sqlite_runtime_version: rt.clone(),
            sqlite_wal_reset_fix_verified: sqlite_wal_reset_fix_verified(&rt),
            mcp_protocol_versions_supported: mcp_vers,
            provider_adapter_schema_version: PROVIDER_ADAPTER_SCHEMA_VERSION.to_string(),
            report_format_version: REPORT_FORMAT_VERSION.to_string(),
        }
    }

    pub fn health_snapshot(&self) -> Result<DbHealthSnapshot, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let projects: u64 = db
            .query_row("SELECT COUNT(*) FROM projects", [], |r| Ok(r.get::<_, i64>(0)? as u64))
            .map_err(db_err)?;
        let active_grants: u64 = db
            .query_row(
                "SELECT COUNT(*) FROM task_grants WHERE revoked = 0",
                [],
                |r| Ok(r.get::<_, i64>(0)? as u64),
            )
            .map_err(db_err)?;
        let active_runs: u64 = db
            .query_row(
                "SELECT COUNT(*) FROM durable_runs WHERE state IN ('queued','admitted','running','cancelling','input_required')",
                [],
                |r| Ok(r.get::<_, i64>(0)? as u64),
            )
            .map_err(db_err)?;
        let evidence_manifests: u64 = db
            .query_row("SELECT COUNT(*) FROM evidence_manifests", [], |r| Ok(r.get::<_, i64>(0)? as u64))
            .map_err(db_err)?;
        let paired_devices: u64 = db
            .query_row(
                "SELECT COUNT(*) FROM paired_devices WHERE revoked = 0",
                [],
                |r| Ok(r.get::<_, i64>(0)? as u64),
            )
            .map_err(db_err)?;
        let schema_ver: u32 = db
            .query_row(
                "SELECT schema_version FROM instance WHERE slot = 1",
                [],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        let db_size_bytes = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let rt = sqlite_runtime_version();
        Ok(DbHealthSnapshot {
            instance_id: self.instance_id.clone(),
            sqlite_schema_version: schema_ver,
            sqlite_runtime_version: rt.clone(),
            sqlite_wal_reset_fix_verified: sqlite_wal_reset_fix_verified(&rt),
            projects,
            active_grants,
            active_runs,
            evidence_manifests,
            paired_devices,
            db_size_bytes,
        })
    }

    /// Perform a consistent SQLite online backup (safe under WAL) and verify integrity & foreign keys on the target.
    pub fn backup_to(&self, target: impl AsRef<Path>) -> Result<BackupReport, BridgeError> {
        let target_path = target.as_ref();
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                BridgeError::new(
                    ErrorCode::InternalError,
                    format!("Cannot create backup parent directory: {e}"),
                    OriginLayer::StateStore,
                )
            })?;
        }
        {
            let src = self.conn.lock().map_err(lock_err)?;
            let mut dst = Connection::open(target_path).map_err(db_err)?;
            let backup = rusqlite::backup::Backup::new(&src, &mut dst).map_err(db_err)?;
            backup
                .run_to_completion(100, std::time::Duration::from_millis(10), None)
                .map_err(db_err)?;
        }
        let verify_conn = Connection::open(target_path).map_err(db_err)?;
        let integrity: String = verify_conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(db_err)?;
        let mut fk_stmt = verify_conn.prepare("PRAGMA foreign_key_check").map_err(db_err)?;
        let fk_count = fk_stmt.query_map([], |_| Ok(())).map_err(db_err)?.count();
        let (inst_id, schema_ver): (String, u32) = verify_conn
            .query_row("SELECT id, schema_version FROM instance WHERE slot = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .map_err(db_err)?;
        drop(fk_stmt);
        drop(verify_conn);

        let bytes = std::fs::read(target_path).map_err(|e| {
            BridgeError::new(
                ErrorCode::InternalError,
                format!("Failed reading backup for digest: {e}"),
                OriginLayer::StateStore,
            )
        })?;
        let rt = sqlite_runtime_version();
        Ok(BackupReport {
            backup_path: target_path.display().to_string(),
            size_bytes: bytes.len() as u64,
            sha256: sha256_bytes(&bytes),
            sqlite_runtime_version: rt.clone(),
            wal_reset_fix_verified: sqlite_wal_reset_fix_verified(&rt),
            integrity_ok: integrity.eq_ignore_ascii_case("ok"),
            foreign_key_issues: fk_count,
            instance_id: inst_id,
            schema_version: schema_ver,
        })
    }

    pub fn register_project(
        &self,
        root: &Path,
        display_name: &str,
        root_identity: &str,
    ) -> Result<ProjectRow, BridgeError> {
        let root_str = root.to_string_lossy().to_string();
        if !root.is_absolute() || display_name.trim().is_empty() || root_identity.is_empty() {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                "Absolute project root, non-empty display name, and root identity are required.",
                OriginLayer::Validation,
            ));
        }
        let root_key = root_str.to_ascii_lowercase();
        let db = self.conn.lock().map_err(lock_err)?;
        let existing: Option<(String, String, String, String, u64)> = db
            .query_row(
                "SELECT id, root, root_identity, display_name, policy_revision FROM projects WHERE root_key = ?1",
                params![root_key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, i64>(4)? as u64)),
            )
            .optional()
            .map_err(db_err)?;

        if let Some((id, r, rid, name, rev)) = existing {
            if rid != root_identity {
                return Err(BridgeError::new(
                    ErrorCode::StalePrecondition,
                    "Registered root filesystem identity changed unexpectedly.",
                    OriginLayer::Policy,
                ));
            }
            return Ok(build_project_row(
                id,
                r,
                root_key,
                rid,
                name,
                rev,
                vec!["checkpoint".into(), "execute".into(), "read".into(), "worker".into(), "write".into()],
            ));
        }

        let pid = ProjectId::new_random().0;
        db.execute(
            "INSERT INTO projects(id, root, root_key, root_identity, display_name, policy_revision) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![pid, root_str, root_key, root_identity, display_name],
        )
        .map_err(db_err)?;

        Ok(build_project_row(
            pid,
            root_str,
            root_key,
            root_identity.to_string(),
            display_name.to_string(),
            1,
            vec!["checkpoint".into(), "execute".into(), "read".into(), "worker".into(), "write".into()],
        ))
    }

    pub fn grant_edge_readonly(&self, project_id: &str) -> Result<ProjectRow, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let caps = serde_json::to_string(&vec!["read"]).unwrap();
        db.execute(
            "INSERT INTO grants(project_id, principal, capabilities, expires_at, revoked) VALUES (?1, 'edge', ?2, NULL, 0)
             ON CONFLICT(project_id, principal) DO UPDATE SET capabilities = excluded.capabilities, revoked = 0",
            params![project_id, caps],
        )
        .map_err(db_err)?;
        db.execute(
            "UPDATE projects SET policy_revision = policy_revision + 1 WHERE id = ?1",
            params![project_id],
        )
        .map_err(db_err)?;
        drop(db);
        self.get_project(project_id, &Principal::Edge)
    }

    pub fn revoke_edge(&self, project_id: &str) -> Result<(), BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        db.execute(
            "UPDATE grants SET revoked = 1 WHERE project_id = ?1 AND principal = 'edge'",
            params![project_id],
        )
        .map_err(db_err)?;
        db.execute(
            "UPDATE projects SET policy_revision = policy_revision + 1 WHERE id = ?1",
            params![project_id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn list_projects(&self, principal: &Principal) -> Result<Vec<ProjectRow>, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let mut stmt = db
            .prepare("SELECT id, root, root_key, root_identity, display_name, policy_revision FROM projects ORDER BY display_name, id")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)? as u64,
                ))
            })
            .map_err(db_err)?;

        let mut out = Vec::new();
        for item in rows {
            let (id, root, root_key, root_identity, display_name, rev) = item.map_err(db_err)?;
            let caps = self.caps_for_conn(&db, &id, principal)?;
            if caps.iter().any(|c| c == "read") {
                out.push(build_project_row(
                    id,
                    root,
                    root_key,
                    root_identity,
                    display_name,
                    rev,
                    caps,
                ));
            }
        }
        Ok(out)
    }

    pub fn get_project(&self, project_id: &str, principal: &Principal) -> Result<ProjectRow, BridgeError> {
        validate_safe_id(project_id)?;
        let db = self.conn.lock().map_err(lock_err)?;
        let row: Option<(String, String, String, String, String, u64)> = db
            .query_row(
                "SELECT id, root, root_key, root_identity, display_name, policy_revision FROM projects WHERE id = ?1",
                params![project_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get::<_, i64>(5)? as u64)),
            )
            .optional()
            .map_err(db_err)?;
        let (id, root, root_key, root_identity, display_name, rev) = row.ok_or_else(|| {
            BridgeError::new(
                ErrorCode::ProjectNotGranted,
                "Project is not available to this principal.",
                OriginLayer::Policy,
            )
        })?;
        let caps = self.caps_for_conn(&db, &id, principal)?;
        if !caps.iter().any(|c| c == "read") {
            return Err(BridgeError::new(
                ErrorCode::ProjectNotGranted,
                "Project read capability is not granted to this principal.",
                OriginLayer::Policy,
            ));
        }
        Ok(build_project_row(
            id,
            root,
            root_key,
            root_identity,
            display_name,
            rev,
            caps,
        ))
    }

    fn caps_for_conn(
        &self,
        db: &Connection,
        project_id: &str,
        principal: &Principal,
    ) -> Result<Vec<String>, BridgeError> {
        match principal {
            Principal::Local => Ok(vec![
                "checkpoint".into(),
                "execute".into(),
                "read".into(),
                "worker".into(),
                "write".into(),
            ]),
            Principal::Edge => {
                let row: Option<(String, Option<String>)> = db
                    .query_row(
                        "SELECT capabilities, expires_at FROM grants WHERE project_id = ?1 AND principal = 'edge' AND revoked = 0",
                        params![project_id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()
                    .map_err(db_err)?;
                let Some((caps_json, exp)) = row else {
                    return Ok(Vec::new());
                };
                if let Some(exp_str) = exp {
                    if let Ok(dt) = DateTime::parse_from_rfc3339(&exp_str) {
                        if dt.with_timezone(&Utc) <= Utc::now() {
                            return Ok(Vec::new());
                        }
                    }
                }
                let caps: Vec<String> = serde_json::from_str(&caps_json).unwrap_or_default();
                // Strict V0.4 invariant (§6): `edge` read connector remains strictly read-only here;
                // delegated execution uses a distinct DelegatedExecutor principal + TaskGrantEnvelope.
                if caps.iter().any(|c| c == "read") {
                    Ok(vec!["read".to_string()])
                } else {
                    Ok(Vec::new())
                }
            }
            Principal::DelegatedExecutor(_) | Principal::PairedHost(_) => {
                let key = principal.as_db_key();
                let now = Utc::now().to_rfc3339();
                let found: Option<String> = db
                    .query_row(
                        "SELECT categories_json FROM task_grants WHERE project_id = ?1 AND requester_principal = ?2 AND revoked = 0 AND expires_at > ?3 ORDER BY created_at DESC LIMIT 1",
                        params![project_id, key, now],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(db_err)?;
                let Some(cat_json) = found else {
                    return Ok(Vec::new());
                };
                let cats: Vec<OperationCategory> = serde_json::from_str(&cat_json).unwrap_or_default();
                let mut caps = Vec::new();
                if cats.contains(&OperationCategory::Read) || cats.contains(&OperationCategory::GitRead) {
                    caps.push("read".to_string());
                }
                if cats.contains(&OperationCategory::Write) || cats.contains(&OperationCategory::Patch) {
                    caps.push("write".to_string());
                }
                if cats.contains(&OperationCategory::Checkpoint) {
                    caps.push("checkpoint".to_string());
                }
                if cats.contains(&OperationCategory::ExecuteRecipe) {
                    caps.push("execute".to_string());
                }
                caps.sort();
                caps.dedup();
                Ok(caps)
            }
        }
    }

    pub fn create_task_grant(&self, grant: &TaskGrantEnvelope) -> Result<(), BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        db.execute(
            "INSERT INTO task_grants(
                grant_id, requester_principal, granting_owner, host_id, project_id, workspace_id,
                baseline_hash, policy_revision, categories_json, writable_paths_json, allowed_recipes_json,
                network_destinations_json, export_scope, integration_mode, limits_json, offline_policy,
                expires_at, revoked, revoked_at, created_at
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,0,NULL,?18)",
            params![
                grant.grant_id.0,
                grant.requester_principal,
                grant.granting_owner,
                grant.host_id.0,
                grant.project_id.0,
                grant.workspace_id.0,
                grant.baseline_hash,
                grant.policy_revision as i64,
                serde_json::to_string(&grant.permitted_categories).unwrap(),
                serde_json::to_string(&grant.writable_paths).unwrap(),
                serde_json::to_string(&grant.allowed_recipes).unwrap(),
                serde_json::to_string(&grant.network_destinations).unwrap(),
                grant.export_scope,
                serde_json::to_string(&grant.integration_mode).unwrap(),
                serde_json::to_string(&grant.limits).unwrap(),
                serde_json::to_string(&grant.offline_policy).unwrap(),
                grant.expires_at.to_rfc3339(),
                grant.created_at.to_rfc3339(),
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn get_task_grant(&self, grant_id: &str) -> Result<Option<TaskGrantEnvelope>, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        db.query_row(
            "SELECT grant_id, requester_principal, granting_owner, host_id, project_id, workspace_id,
                    baseline_hash, policy_revision, categories_json, writable_paths_json, allowed_recipes_json,
                    network_destinations_json, export_scope, integration_mode, limits_json, offline_policy,
                    expires_at, revoked, revoked_at, created_at
             FROM task_grants WHERE grant_id = ?1",
            params![grant_id],
            row_to_task_grant,
        )
        .optional()
        .map_err(db_err)
    }

    pub fn list_task_grants(&self, project_id: Option<&str>) -> Result<Vec<TaskGrantEnvelope>, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let mut out = Vec::new();
        if let Some(pid) = project_id {
            let mut stmt = db
                .prepare(
                    "SELECT grant_id, requester_principal, granting_owner, host_id, project_id, workspace_id,
                            baseline_hash, policy_revision, categories_json, writable_paths_json, allowed_recipes_json,
                            network_destinations_json, export_scope, integration_mode, limits_json, offline_policy,
                            expires_at, revoked, revoked_at, created_at
                     FROM task_grants WHERE project_id = ?1 ORDER BY created_at DESC",
                )
                .map_err(db_err)?;
            let rows = stmt.query_map(params![pid], row_to_task_grant).map_err(db_err)?;
            for r in rows {
                out.push(r.map_err(db_err)?);
            }
        } else {
            let mut stmt = db
                .prepare(
                    "SELECT grant_id, requester_principal, granting_owner, host_id, project_id, workspace_id,
                            baseline_hash, policy_revision, categories_json, writable_paths_json, allowed_recipes_json,
                            network_destinations_json, export_scope, integration_mode, limits_json, offline_policy,
                            expires_at, revoked, revoked_at, created_at
                     FROM task_grants ORDER BY created_at DESC",
                )
                .map_err(db_err)?;
            let rows = stmt.query_map([], row_to_task_grant).map_err(db_err)?;
            for r in rows {
                out.push(r.map_err(db_err)?);
            }
        }
        Ok(out)
    }

    pub fn revoke_task_grant(&self, grant_id: &str) -> Result<bool, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let now = Utc::now().to_rfc3339();
        let pid: Option<String> = db
            .query_row(
                "SELECT project_id FROM task_grants WHERE grant_id = ?1",
                params![grant_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        let changed = db
            .execute(
                "UPDATE task_grants SET revoked = 1, revoked_at = ?2 WHERE grant_id = ?1 AND revoked = 0",
                params![grant_id, now],
            )
            .map_err(db_err)?;
        if let Some(p) = pid {
            db.execute(
                "UPDATE projects SET policy_revision = policy_revision + 1 WHERE id = ?1",
                params![p],
            )
            .map_err(db_err)?;
        }
        Ok(changed > 0)
    }

    /// Persist a durable run atomically before dispatching side effects (dedup-checked).
    /// Returns `Ok((record, created_new))`. Rejects key reuse with a mismatched payload digest!
    pub fn claim_durable_run(
        &self,
        record: &DurableJobRecord,
        command_json: &str,
    ) -> Result<(DurableJobRecord, bool), BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let state_str = serde_json::to_value(record.state).unwrap().as_str().unwrap().to_string();
        // The unique index arbitrates admission across separate connections and processes.
        let inserted = db.execute(
            "INSERT INTO durable_runs(
                run_id, task_id, host_id, project_id, workspace_id, grant_id,
                requester_principal, executor_identity, operation_id, dedup_key, payload_digest,
                state, pid, process_start_time_100ns, exit_code, agent_outcome, execution_outcome,
                verification_outcome, evidence_manifest_id, output_seq, output_truncated,
                output_dir, command_json, created_at, updated_at
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,0,0,?20,?21,?22,?23)
            ON CONFLICT(dedup_key) DO NOTHING",
            params![
                record.run_id.0,
                record.task_id.0,
                record.host_id.0,
                record.project_id.0,
                record.workspace_id.0,
                record.grant_id.as_ref().map(|g| g.0.as_str()),
                record.requester_principal,
                record.executor_identity,
                record.operation_id.0,
                record.dedup_key,
                record.payload_digest,
                state_str,
                record.pid,
                record.process_start_time_100ns.map(|v| v as i64),
                record.exit_code,
                record.outcome.as_ref().map(|o| serde_json::to_string(&o.agent_outcome).unwrap()),
                record.outcome.as_ref().map(|o| serde_json::to_string(&o.execution_outcome).unwrap()),
                record.outcome.as_ref().map(|o| serde_json::to_string(&o.verification_outcome).unwrap()),
                record.evidence_manifest_id.as_ref().map(|m| m.0.as_str()),
                record.output_dir,
                command_json,
                record.created_at.to_rfc3339(),
                record.updated_at.to_rfc3339(),
            ],
        )
        .map_err(db_err)?;
        if inserted == 1 {
            return Ok((record.clone(), true));
        }

        let winner_id: String = db.query_row(
            "SELECT run_id FROM durable_runs WHERE dedup_key = ?1",
            params![record.dedup_key],
            |r| r.get(0),
        ).map_err(db_err)?;
        drop(db);
        let winner = self.get_durable_run(&winner_id)?.ok_or_else(|| {
            BridgeError::new(ErrorCode::NotFound, "Existing run vanished.", OriginLayer::StateStore)
        })?;
        if winner.payload_digest != record.payload_digest
            || winner.task_id != record.task_id
            || winner.workspace_id != record.workspace_id
            || winner.grant_id != record.grant_id
            || winner.executor_identity != record.executor_identity
        {
            return Err(BridgeError::new(
                ErrorCode::IdempotencyPayloadMismatch,
                "Duplicate operation_id supplied with a different payload or run context.",
                OriginLayer::JobRunner,
            ));
        }
        Ok((winner, false))
    }

    /// Only the interactive owner command calls this admission gate. The recipe must
    /// come from a queued local MCP request with no supplied command arguments.
    pub fn admit_local_python_tests(&self, run_id: &RunId, host_id: &HostId) -> Result<(), BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let changed = db.execute(
            "UPDATE durable_runs SET state = 'admitted', updated_at = ?3
             WHERE run_id = ?1 AND host_id = ?2 AND state = 'queued'
                 AND requester_principal = 'local' AND grant_id IS NULL
                 AND executor_identity = 'mcp_task_submit'
                 AND CASE WHEN json_valid(command_json) THEN
                     json_extract(command_json, '$.recipe') = 'python_tests'
                     AND json_type(command_json, '$.args') = 'array'
                     AND json_array_length(command_json, '$.args') = 0
                     AND json_extract(command_json, '$.project_id') = project_id
                     AND json_extract(command_json, '$.task_id') = task_id
                 ELSE 0 END",
            params![run_id.0, host_id.0, Utc::now().to_rfc3339()],
        ).map_err(db_err)?;
        if changed != 1 {
            return Err(BridgeError::new(
                ErrorCode::BridgePolicyDenied,
                "Expected an unclaimed local Python test request with no arguments on this host.",
                OriginLayer::Policy,
            ));
        }
        Ok(())
    }

    /// Atomically take one queued delegated request. Cancellation and admission
    /// compete for the same row, and an admitted request is never queued again.
    pub fn take_delegated_queue_run(
        &self,
        host_id: &HostId,
    ) -> Result<Option<(DurableJobRecord, String)>, BridgeError> {
        let mut db = self.conn.lock().map_err(lock_err)?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(db_err)?;
        let claimed: Option<(String, String)> = tx.query_row(
            "UPDATE durable_runs SET state = 'admitted', updated_at = ?2
             WHERE run_id = (SELECT run_id FROM durable_runs
                 WHERE state = 'queued' AND host_id = ?1
                   AND executor_identity = 'mcp_task_submit' AND requester_principal LIKE 'executor:%'
                 ORDER BY created_at, run_id LIMIT 1)
             RETURNING run_id, command_json",
            params![host_id.0, Utc::now().to_rfc3339()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(db_err)?;
        let Some((id, request)) = claimed else { return Ok(None) };
        let record = Self::read_durable_run(&tx, &id)?.ok_or_else(|| {
            BridgeError::new(ErrorCode::NotFound, "Admitted queue run disappeared.", OriginLayer::StateStore)
        })?;
        tx.commit().map_err(db_err)?;
        Ok(Some((record, request)))
    }

    /// Called only while holding the owner queue worker lease for this state directory.
    pub fn reconcile_delegated_queue_runs(&self, host_id: &HostId) -> Result<usize, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        db.execute(
            "UPDATE durable_runs SET state = 'unknown', updated_at = ?2
             WHERE host_id = ?1 AND executor_identity = 'mcp_task_submit'
               AND requester_principal LIKE 'executor:%'
               AND state IN ('admitted','running','cancelling')",
            params![host_id.0, Utc::now().to_rfc3339()],
        ).map_err(db_err)
    }

    /// How many grants and projects exist. Both only grow, and together they decide which folders
    /// a requester may have written, so an unchanged pair means that set is unchanged.
    pub fn write_scope_marker(&self) -> Result<(u64, u64), BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        db.query_row("SELECT (SELECT COUNT(*) FROM task_grants), (SELECT COUNT(*) FROM projects)", [],
            |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64))).map_err(db_err)
    }

    /// Linearize launch with cancellation, expiry and grant revocation. The policy
    /// engine checked recipe and category before preparation under this revision, and the
    /// files were chosen under this write scope; a grant or project added since refuses the launch.
    pub fn start_delegated_queue_run(
        &self, run: &DurableJobRecord, revision: u64, write_scope: (u64, u64), pid: u32, start_time: Option<u64>,
    ) -> Result<bool, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let changed = db.execute(
            "UPDATE durable_runs SET state = 'running', pid = ?3,
                 process_start_time_100ns = ?4, updated_at = ?5
             WHERE run_id = ?1 AND state = 'admitted' AND EXISTS (
                 SELECT 1 FROM task_grants g JOIN projects p ON p.id = g.project_id
                 WHERE g.grant_id = durable_runs.grant_id AND p.id = durable_runs.project_id
                   AND g.host_id = durable_runs.host_id AND g.requester_principal = durable_runs.requester_principal
                   AND g.revoked = 0 AND g.policy_revision = ?2 AND p.policy_revision = ?2
                   AND julianday(g.expires_at) > julianday('now')
             ) AND (SELECT COUNT(*) FROM task_grants) = ?6 AND (SELECT COUNT(*) FROM projects) = ?7",
            params![run.run_id.0, revision as i64, pid, start_time.map(|v| v as i64), Utc::now().to_rfc3339(),
                write_scope.0 as i64, write_scope.1 as i64],
        ).map_err(db_err)?;
        Ok(changed == 1)
    }

    pub fn transition_durable_run(
        &self,
        run_id: &str,
        next_state: JobState,
        pid: Option<u32>,
        start_time_100ns: Option<u64>,
        exit_code: Option<i32>,
        outcome: Option<&OutcomeTriad>,
        manifest_id: Option<&str>,
    ) -> Result<DurableJobRecord, BridgeError> {
        self.transition_durable_run_from(run_id, None, next_state, pid, start_time_100ns,
            exit_code, outcome, manifest_id)
    }

    pub fn transition_durable_run_from(
        &self,
        run_id: &str,
        expected_state: Option<JobState>,
        next_state: JobState,
        pid: Option<u32>,
        start_time_100ns: Option<u64>,
        exit_code: Option<i32>,
        outcome: Option<&OutcomeTriad>,
        manifest_id: Option<&str>,
    ) -> Result<DurableJobRecord, BridgeError> {
        let mut db = self.conn.lock().map_err(lock_err)?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(db_err)?;
        let cur_str: String = tx
            .query_row(
                "SELECT state FROM durable_runs WHERE run_id = ?1",
                params![run_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?
            .ok_or_else(|| {
                BridgeError::new(ErrorCode::NotFound, "Durable run not found.", OriginLayer::JobRunner)
            })?;
        let cur: JobState = serde_json::from_value(serde_json::Value::String(cur_str.clone())).map_err(|_| {
            BridgeError::new(ErrorCode::InternalError, "Corrupt job state in DB.", OriginLayer::StateStore)
        })?;
        if expected_state.is_some_and(|expected| expected != cur) {
            return Err(BridgeError::new(
                ErrorCode::VersionConflict,
                "The run changed before the requested transition.",
                OriginLayer::JobRunner,
            ));
        }
        if cur != next_state && !cur.can_transition_to(next_state) {
            return Err(BridgeError::new(
                ErrorCode::VersionConflict,
                format!("Invalid job state transition {cur:?} -> {next_state:?}."),
                OriginLayer::JobRunner,
            ));
        }
        let next_str = serde_json::to_value(next_state).unwrap().as_str().unwrap().to_string();
        let now = Utc::now().to_rfc3339();
        let changed = tx.execute(
            "UPDATE durable_runs
             SET state = ?2,
                 pid = COALESCE(?3, pid),
                 process_start_time_100ns = COALESCE(?4, process_start_time_100ns),
                 exit_code = COALESCE(?5, exit_code),
                 agent_outcome = COALESCE(?6, agent_outcome),
                 execution_outcome = COALESCE(?7, execution_outcome),
                 verification_outcome = COALESCE(?8, verification_outcome),
                 evidence_manifest_id = COALESCE(?9, evidence_manifest_id),
                 updated_at = ?10
             WHERE run_id = ?1 AND state = ?11",
            params![
                run_id,
                next_str,
                pid,
                start_time_100ns.map(|v| v as i64),
                exit_code,
                outcome.map(|o| serde_json::to_string(&o.agent_outcome).unwrap()),
                outcome.map(|o| serde_json::to_string(&o.execution_outcome).unwrap()),
                outcome.map(|o| serde_json::to_string(&o.verification_outcome).unwrap()),
                manifest_id,
                now,
                cur_str,
            ],
        )
        .map_err(db_err)?;
        if changed != 1 {
            return Err(BridgeError::new(
                ErrorCode::VersionConflict,
                "The run changed concurrently; reload its current state before proceeding.",
                OriginLayer::JobRunner,
            ));
        }
        let run = Self::read_durable_run(&tx, run_id)?.ok_or_else(|| {
            BridgeError::new(ErrorCode::NotFound, "Run missing after transition.", OriginLayer::StateStore)
        })?;
        tx.commit().map_err(db_err)?;
        Ok(run)
    }

    pub fn append_run_output(
        &self,
        run_id: &str,
        stream: &str,
        content: &str,
        truncated: bool,
    ) -> Result<u64, BridgeError> {
        self.append_run_output_batch(run_id, &[(stream, content)], truncated)
    }

    pub fn append_run_output_batch(
        &self,
        run_id: &str,
        chunks: &[(&str, &str)],
        truncated: bool,
    ) -> Result<u64, BridgeError> {
        let mut db = self.conn.lock().map_err(lock_err)?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(db_err)?;
        let cur_seq: u64 = tx
            .query_row(
                "SELECT output_seq FROM durable_runs WHERE run_id = ?1",
                params![run_id],
                |r| Ok(r.get::<_, i64>(0)? as u64),
            )
            .map_err(db_err)?;
        let mut next_seq = cur_seq;
        let now = Utc::now().to_rfc3339();
        {
            let mut insert = tx.prepare(
                "INSERT INTO run_output_chunks(run_id, seq, stream, content, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            ).map_err(db_err)?;
            for (stream, content) in chunks {
                next_seq += 1;
                insert.execute(params![run_id, next_seq as i64, stream, content, now]).map_err(db_err)?;
            }
        }
        tx.execute(
            "UPDATE durable_runs SET output_seq = ?2, output_truncated = MAX(output_truncated, ?3), updated_at = ?4 WHERE run_id = ?1",
            params![run_id, next_seq as i64, if truncated { 1 } else { 0 }, now],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(next_seq)
    }

    pub fn read_run_output(&self, run_id: &str, after_seq: u64, limit: usize) -> Result<Vec<(u64, String, String)>, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let mut stmt = db
            .prepare(
                "SELECT seq, stream, content FROM run_output_chunks WHERE run_id = ?1 AND seq > ?2 ORDER BY seq ASC LIMIT ?3",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![run_id, after_seq as i64, limit as i64], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
            })
            .map_err(db_err)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(db_err)?);
        }
        Ok(out)
    }

    pub fn get_run_command(&self, run_id: &str) -> Result<Option<String>, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        db.query_row(
            "SELECT command_json FROM durable_runs WHERE run_id = ?1",
            params![run_id],
            |row| row.get(0),
        ).optional().map_err(db_err)
    }

    pub fn get_durable_run(&self, run_id: &str) -> Result<Option<DurableJobRecord>, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        Self::read_durable_run(&db, run_id)
    }

    fn read_durable_run(db: &Connection, run_id: &str) -> Result<Option<DurableJobRecord>, BridgeError> {
        db.query_row(
            "SELECT run_id, task_id, host_id, project_id, workspace_id, grant_id,
                    requester_principal, executor_identity, operation_id, dedup_key, payload_digest,
                    state, pid, process_start_time_100ns, exit_code, agent_outcome, execution_outcome,
                    verification_outcome, evidence_manifest_id, output_seq, output_truncated,
                    output_dir, created_at, updated_at
             FROM durable_runs WHERE run_id = ?1",
            params![run_id],
            row_to_durable_run,
        )
        .optional()
        .map_err(db_err)
    }

    pub fn list_durable_runs(&self, project_id: Option<&str>, limit: usize) -> Result<Vec<DurableJobRecord>, BridgeError> {
        self.list_scoped_durable_runs(project_id, None, None, limit)
    }

    pub fn list_scoped_durable_runs(
        &self,
        project_id: Option<&str>,
        owner: Option<(&str, Option<&str>)>,
        task_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<DurableJobRecord>, BridgeError> {
        let (requester, grant) = owner.map_or((None, None), |(requester, grant)| (Some(requester), grant));
        let db = self.conn.lock().map_err(lock_err)?;
        let mut stmt = db.prepare(
            "SELECT run_id, task_id, host_id, project_id, workspace_id, grant_id,
                    requester_principal, executor_identity, operation_id, dedup_key, payload_digest,
                    state, pid, process_start_time_100ns, exit_code, agent_outcome, execution_outcome,
                    verification_outcome, evidence_manifest_id, output_seq, output_truncated,
                    output_dir, created_at, updated_at
             FROM durable_runs
             WHERE (?1 IS NULL OR project_id = ?1)
               AND (?2 IS NULL OR (requester_principal = ?2 AND grant_id IS ?3))
               AND (?4 IS NULL OR task_id = ?4)
             ORDER BY updated_at DESC, run_id DESC LIMIT ?5",
        ).map_err(db_err)?;
        let rows = stmt.query_map(params![project_id, requester, grant, task_id, limit as i64], row_to_durable_run)
            .map_err(db_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
    }

    /// Queued work has no external effects and remains available for owner admission.
    /// A run that may have started is fenced from automatic repeat and reconciled as unknown.
    pub fn mark_orphaned_runs_unknown(&self) -> Result<usize, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let now = Utc::now().to_rfc3339();
        let n = db
            .execute(
                "UPDATE durable_runs SET state = 'unknown', updated_at = ?1
                 WHERE state IN ('admitted','running','cancelling','input_required')
                   AND NOT (executor_identity = 'mcp_task_submit' AND requester_principal LIKE 'executor:%')",
                params![now],
            )
            .map_err(db_err)?;
        Ok(n)
    }

    pub fn request_run_cancel(&self, run_id: &str) -> Result<DurableJobRecord, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        db.execute(
            "UPDATE durable_runs
                SET state = CASE WHEN state = 'queued' THEN 'cancelled' ELSE 'cancelling' END,
                    updated_at = ?2
              WHERE run_id = ?1 AND state IN ('queued', 'admitted', 'running', 'input_required')",
            params![run_id, Utc::now().to_rfc3339()],
        ).map_err(db_err)?;
        drop(db);
        self.get_durable_run(run_id)?.ok_or_else(|| {
            BridgeError::new(ErrorCode::NotFound, "Durable run not found.", OriginLayer::JobRunner)
        })
    }

    pub fn save_evidence_manifest(
        &self,
        manifest: &EvidenceManifest,
        export_redacted_json: Option<&str>,
        export_sha256: Option<&str>,
    ) -> Result<(), BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let raw = serde_json::to_string(manifest).unwrap();
        let sha = manifest
            .manifest_sha256
            .clone()
            .unwrap_or_else(|| sha256_bytes(raw.as_bytes()));
        let now = Utc::now().to_rfc3339();
        db.execute(
            "INSERT OR REPLACE INTO evidence_manifests(
                manifest_id, run_id, project_id, host_id, evidence_class, verdict,
                manifest_sha256, signature_ed25519, signer_key_id, manifest_json,
                export_redacted_json, export_sha256, created_at
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                manifest.identity.manifest_id.0,
                manifest.identity.run_id.0,
                manifest.identity.project_id.0,
                manifest.identity.host_id.0,
                serde_json::to_value(manifest.identity.evidence_class).unwrap().as_str().unwrap(),
                serde_json::to_value(manifest.conclusions.overall_verdict).unwrap().as_str().unwrap(),
                sha,
                manifest.signature_ed25519_hex,
                manifest.signer_public_key_hex,
                raw,
                export_redacted_json,
                export_sha256,
                now,
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn get_evidence_manifest(&self, manifest_id: &str) -> Result<Option<EvidenceManifest>, BridgeError> {
        self.get_scoped_evidence_manifest(manifest_id, None, None, None, true)
    }

    pub fn get_scoped_evidence_manifest(
        &self,
        manifest_id: &str,
        project_id: Option<&str>,
        owner: Option<(&str, Option<&str>)>,
        run_id: Option<&str>,
        owner_diagnostics: bool,
    ) -> Result<Option<EvidenceManifest>, BridgeError> {
        let (requester, grant) = owner.map_or((None, None), |(requester, grant)| (Some(requester), grant));
        let db = self.conn.lock().map_err(lock_err)?;
        let raw: Option<String> = db.query_row(
            "SELECT manifest_json FROM evidence_manifests
             WHERE manifest_id = ?1 AND (?2 IS NULL OR project_id = ?2) AND (?5 IS NULL OR run_id = ?5)
               AND CASE WHEN ?3 IS NULL THEN 1 WHEN json_valid(manifest_json) THEN
                   json_extract(manifest_json, '$.authorization.requester_principal') = ?3
                   AND json_extract(manifest_json, '$.authorization.grant_id') IS ?4
               ELSE 0 END",
            params![manifest_id, project_id, requester, grant, run_id],
            |r| r.get(0),
        ).optional().map_err(db_err)?;
        raw.map(|s| serde_json::from_str(&s).map_err(|e| {
            let message = if owner_diagnostics {
                format!("Corrupt evidence manifest JSON: {e}")
            } else {
                "Corrupt evidence manifest JSON.".into()
            };
            BridgeError::new(ErrorCode::InternalError, message, OriginLayer::Evidence)
        })).transpose()
    }

    pub fn list_evidence_manifests(&self, project_id: Option<&str>, limit: usize) -> Result<Vec<EvidenceManifest>, BridgeError> {
        self.list_scoped_evidence_manifests(project_id, None, limit)
    }

    pub fn list_scoped_evidence_manifests(
        &self,
        project_id: Option<&str>,
        owner: Option<(&str, Option<&str>)>,
        limit: usize,
    ) -> Result<Vec<EvidenceManifest>, BridgeError> {
        let (requester, grant) = owner.map_or((None, None), |(requester, grant)| (Some(requester), grant));
        let db = self.conn.lock().map_err(lock_err)?;
        let mut stmt = db.prepare(
            "SELECT manifest_json FROM evidence_manifests
             WHERE (?1 IS NULL OR project_id = ?1)
               AND CASE WHEN ?2 IS NULL THEN 1 WHEN json_valid(manifest_json) THEN
                   json_extract(manifest_json, '$.authorization.requester_principal') = ?2
                   AND json_extract(manifest_json, '$.authorization.grant_id') IS ?3
               ELSE 0 END
             ORDER BY created_at DESC, manifest_id DESC LIMIT ?4",
        ).map_err(db_err)?;
        let rows = stmt.query_map(params![project_id, requester, grant, limit as i64], |r| r.get::<_, String>(0))
            .map_err(db_err)?;
        let mut out = Vec::new();
        for raw in rows {
            if let Ok(manifest) = serde_json::from_str(&raw.map_err(db_err)?) {
                out.push(manifest);
            }
        }
        Ok(out)
    }

    pub fn save_patch_journal(
        &self,
        journal_id: &str,
        project_id: &str,
        operation_id: &str,
        state: &str,
        plan_sha256: &str,
        journal_json: &str,
    ) -> Result<(), BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let now = Utc::now().to_rfc3339();
        db.execute(
            "INSERT OR REPLACE INTO patch_journals(journal_id, project_id, operation_id, state, plan_sha256, journal_json, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?7)",
            params![journal_id, project_id, operation_id, state, plan_sha256, journal_json, now],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn upsert_paired_device(&self, dev: &DeviceRecord) -> Result<(), BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        db.execute(
            "INSERT OR REPLACE INTO paired_devices(
                host_id, display_name, public_key_hex, endpoint_url, scopes_json,
                capabilities_json, status, last_heartbeat_at, paired_at, revoked
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                dev.host_id.0,
                dev.display_name,
                dev.public_key_hex,
                dev.endpoint_url,
                serde_json::to_string(&dev.approved_scopes).unwrap(),
                serde_json::to_string(&dev.capabilities).unwrap(),
                dev.status,
                dev.last_heartbeat_at.map(|t| t.to_rfc3339()),
                dev.paired_at.to_rfc3339(),
                if dev.revoked { 1 } else { 0 },
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn list_paired_devices(&self) -> Result<Vec<DeviceRecord>, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let mut stmt = db
            .prepare(
                "SELECT host_id, display_name, public_key_hex, endpoint_url, scopes_json,
                        capabilities_json, status, last_heartbeat_at, paired_at, revoked
                 FROM paired_devices ORDER BY paired_at DESC",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| {
                let scopes_s: String = r.get(4)?;
                let caps_s: String = r.get(5)?;
                let hb: Option<String> = r.get(7)?;
                let paired: String = r.get(8)?;
                Ok(DeviceRecord {
                    host_id: HostId(r.get(0)?),
                    display_name: r.get(1)?,
                    public_key_hex: r.get(2)?,
                    endpoint_url: r.get(3)?,
                    approved_scopes: serde_json::from_str(&scopes_s).unwrap_or_default(),
                    capabilities: serde_json::from_str(&caps_s).unwrap_or_default(),
                    status: r.get(6)?,
                    last_heartbeat_at: hb
                        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                        .map(|d| d.with_timezone(&Utc)),
                    paired_at: DateTime::parse_from_rfc3339(&paired)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    revoked: r.get::<_, i64>(9)? != 0,
                })
            })
            .map_err(db_err)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(db_err)?);
        }
        Ok(out)
    }

    pub fn create_pairing_token(
        &self,
        token_id: &str,
        token_hash: &str,
        target_host_id: &str,
        scopes: &[String],
        expires_at: DateTime<Utc>,
    ) -> Result<(), BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        db.execute(
            "INSERT INTO pairing_tokens(token_id, token_hash, target_host_id, scopes_json, expires_at, consumed, created_at)
             VALUES (?1,?2,?3,?4,?5,0,?6)",
            params![
                token_id,
                token_hash,
                target_host_id,
                serde_json::to_string(scopes).unwrap(),
                expires_at.to_rfc3339(),
                Utc::now().to_rfc3339(),
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn consume_pairing_token(&self, token_hash: &str, target_host_id: &str) -> Result<Vec<String>, BridgeError> {
        let db = self.conn.lock().map_err(lock_err)?;
        let row: Option<(String, String, String, i64)> = db
            .query_row(
                "SELECT token_id, target_host_id, scopes_json, consumed FROM pairing_tokens WHERE token_hash = ?1 AND expires_at > ?2",
                params![token_hash, Utc::now().to_rfc3339()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(db_err)?;
        let Some((tid, expected_host, scopes_json, consumed)) = row else {
            return Err(BridgeError::new(
                ErrorCode::AuthRequired,
                "Pairing token is missing, invalid, or expired.",
                OriginLayer::DeviceChannel,
            ));
        };
        if consumed != 0 {
            return Err(BridgeError::new(
                ErrorCode::AuthRequired,
                "One-time pairing token has already been consumed.",
                OriginLayer::DeviceChannel,
            ));
        }
        if expected_host != target_host_id {
            return Err(BridgeError::new(
                ErrorCode::BridgePolicyDenied,
                "Pairing token target host_id does not match presenting host identity.",
                OriginLayer::DeviceChannel,
            ));
        }
        db.execute("UPDATE pairing_tokens SET consumed = 1 WHERE token_id = ?1", params![tid])
            .map_err(db_err)?;
        Ok(serde_json::from_str(&scopes_json).unwrap_or_default())
    }

    /// Decide cancellation under the writer lock and commit the signed manifest with the run.
    pub fn finalize_queued_run_with_evidence<E>(
        &self,
        run_id: &str,
        terminal: JobState,
        exit_code: Option<i32>,
        sign: impl FnOnce(JobState) -> Result<(EvidenceManifest, String), E>,
    ) -> Result<Result<(DurableJobRecord, EvidenceManifest, String), E>, BridgeError> {
        let mut db = self.conn.lock().map_err(lock_err)?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(db_err)?;
        let run = Self::read_durable_run(&tx, run_id)?.ok_or_else(|| {
            BridgeError::new(ErrorCode::NotFound, "Run missing before evidence finalization.", OriginLayer::StateStore)
        })?;
        let terminal = if run.state == JobState::Cancelling { JobState::Cancelled } else { terminal };
        if !matches!(run.state, JobState::Running | JobState::Cancelling)
            || !terminal.is_terminal() || !run.state.can_transition_to(terminal)
            || run.evidence_manifest_id.is_some()
        {
            return Err(BridgeError::new(
                ErrorCode::VersionConflict, "Run is not eligible for evidence finalization.", OriginLayer::StateStore,
            ));
        }
        let (manifest, json) = match sign(terminal) {
            Ok(signed) => signed,
            Err(rejection) => return Ok(Err(rejection)),
        };
        if manifest.identity.run_id != run.run_id || manifest.identity.project_id != run.project_id
            || manifest.identity.host_id != run.host_id || manifest.execution.exit_code != exit_code
            || manifest.execution.cancelled != (terminal == JobState::Cancelled)
            || manifest.execution.timed_out != (terminal == JobState::TimedOut)
        {
            return Err(BridgeError::new(
                ErrorCode::VersionConflict, "Signed evidence does not match the selected run result.", OriginLayer::StateStore,
            ));
        }
        let manifest_id = &manifest.identity.manifest_id.0;
        let outcome = &manifest.execution.outcome_triad;
        tx.execute(
            "INSERT INTO evidence_manifests(
                manifest_id, run_id, project_id, host_id, evidence_class, verdict,
                manifest_sha256, signature_ed25519, signer_key_id, manifest_json,
                export_redacted_json, export_sha256, created_at
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10,?11,?12)",
            params![
                manifest_id, run_id, manifest.identity.project_id.0, manifest.identity.host_id.0,
                serde_json::to_value(manifest.identity.evidence_class).unwrap().as_str().unwrap(),
                serde_json::to_value(manifest.conclusions.overall_verdict).unwrap().as_str().unwrap(),
                manifest.manifest_sha256, manifest.signature_ed25519_hex, manifest.signer_public_key_hex,
                json, sha256_bytes(json.as_bytes()), Utc::now().to_rfc3339(),
            ],
        ).map_err(db_err)?;
        let changed = tx.execute(
            "UPDATE durable_runs
             SET state = ?2, exit_code = ?3, agent_outcome = ?4, execution_outcome = ?5,
                 verification_outcome = ?6, evidence_manifest_id = ?7, updated_at = ?8
             WHERE run_id = ?1",
            params![
                run_id, serde_json::to_value(terminal).unwrap().as_str().unwrap(), exit_code,
                serde_json::to_string(&outcome.agent_outcome).unwrap(),
                serde_json::to_string(&outcome.execution_outcome).unwrap(),
                serde_json::to_string(&outcome.verification_outcome).unwrap(),
                manifest_id, Utc::now().to_rfc3339(),
            ],
        ).map_err(db_err)?;
        if changed != 1 {
            return Err(BridgeError::new(
                ErrorCode::VersionConflict, "Run was not updated during evidence finalization.", OriginLayer::StateStore,
            ));
        }
        let record = Self::read_durable_run(&tx, run_id)?.ok_or_else(|| {
            BridgeError::new(ErrorCode::NotFound, "Run missing after evidence finalization.", OriginLayer::StateStore)
        })?;
        tx.commit().map_err(db_err)?;
        Ok(Ok((record, manifest, json)))
    }
}

fn build_project_row(
    project_id: String,
    root: String,
    root_key: String,
    root_identity: String,
    display_name: String,
    policy_revision: u64,
    capabilities: Vec<String>,
) -> ProjectRow {
    let policy_val = serde_json::json!({
        "project_id": project_id,
        "root_identity": root_identity,
        "policy_revision": policy_revision,
        "capabilities": capabilities,
    });
    let policy_hash = format!("sha256:{}", sha256_bytes(policy_val.to_string().as_bytes()));
    ProjectRow {
        project_id,
        root,
        root_key,
        root_identity,
        display_name,
        policy_revision,
        capabilities,
        policy_hash,
    }
}

fn row_to_task_grant(r: &rusqlite::Row<'_>) -> rusqlite::Result<TaskGrantEnvelope> {
    let cats: String = r.get(8)?;
    let paths: String = r.get(9)?;
    let recipes: String = r.get(10)?;
    let net: String = r.get(11)?;
    let int_mode: String = r.get(13)?;
    let limits: String = r.get(14)?;
    let offline: String = r.get(15)?;
    let exp: String = r.get(16)?;
    let rev_at: Option<String> = r.get(18)?;
    let created: String = r.get(19)?;
    Ok(TaskGrantEnvelope {
        grant_id: GrantId(r.get(0)?),
        requester_principal: r.get(1)?,
        granting_owner: r.get(2)?,
        host_id: HostId(r.get(3)?),
        project_id: ProjectId(r.get(4)?),
        workspace_id: WorkspaceId(r.get(5)?),
        baseline_hash: r.get(6)?,
        policy_revision: r.get::<_, i64>(7)? as u64,
        permitted_categories: serde_json::from_str(&cats).unwrap_or_default(),
        writable_paths: serde_json::from_str(&paths).unwrap_or_default(),
        allowed_recipes: serde_json::from_str(&recipes).unwrap_or_default(),
        network_destinations: serde_json::from_str(&net).unwrap_or_default(),
        export_scope: r.get(12)?,
        integration_mode: serde_json::from_str(&int_mode)
            .unwrap_or(IntegrationMode::AwaitOwnerReview),
        // Limits that cannot be read become zero, and the worker refuses a zero limit.
        limits: serde_json::from_str(&limits).unwrap_or(ResourceLimits {
            max_duration_seconds: 0,
            max_cpu_percent: 0,
            max_memory_mb: 0,
            max_processes: 0,
            max_output_bytes: 0,
            max_storage_bytes: 0,
        }),
        offline_policy: serde_json::from_str(&offline)
            .unwrap_or(OfflineGrantPolicy::DenyNewAllowRunningDeterministic),
        expires_at: DateTime::parse_from_rfc3339(&exp)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        revoked: r.get::<_, i64>(17)? != 0,
        revoked_at: rev_at
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|d| d.with_timezone(&Utc)),
        created_at: DateTime::parse_from_rfc3339(&created)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    })
}

fn row_to_durable_run(r: &rusqlite::Row<'_>) -> rusqlite::Result<DurableJobRecord> {
    let state_s: String = r.get(11)?;
    let state: JobState = serde_json::from_value(serde_json::Value::String(state_s))
        .unwrap_or(JobState::Unknown);
    let ao: Option<String> = r.get(15)?;
    let eo: Option<String> = r.get(16)?;
    let vo: Option<String> = r.get(17)?;
    let mut outcome = match (ao, eo, vo) {
        (Some(a), Some(e), Some(v)) => Some(OutcomeTriad {
            agent_outcome: serde_json::from_str(&a).unwrap_or(Verdict::NotTested),
            execution_outcome: serde_json::from_str(&e).unwrap_or(Verdict::NotTested),
            verification_outcome: serde_json::from_str(&v).unwrap_or(Verdict::NotTested),
            soft_denied_tools: Vec::new(),
        }),
        _ => None,
    };
    let requester_principal: String = r.get(6)?;
    let executor_identity: String = r.get(7)?;
    let evidence_manifest_id = r.get::<_, Option<String>>(18)?.map(ManifestId);
    if executor_identity == "mcp_task_submit" && requester_principal.starts_with("executor:")
        && evidence_manifest_id.is_some() && let Some(result) = &mut outcome
    {
        // Older captures may have persisted a verdict based on workload output.
        result.verification_outcome = crate::evidence::delegated_workload_verdict(
            state == JobState::TimedOut, state == JobState::Cancelled,
        );
    }
    let created_s: String = r.get(22)?;
    let updated_s: String = r.get(23)?;
    Ok(DurableJobRecord {
        run_id: RunId(r.get(0)?),
        task_id: TaskId(r.get(1)?),
        host_id: HostId(r.get(2)?),
        project_id: ProjectId(r.get(3)?),
        workspace_id: WorkspaceId(r.get(4)?),
        grant_id: r.get::<_, Option<String>>(5)?.map(GrantId),
        requester_principal,
        executor_identity,
        operation_id: OperationId(r.get(8)?),
        dedup_key: r.get(9)?,
        payload_digest: r.get(10)?,
        state,
        pid: r.get(12)?,
        process_start_time_100ns: r.get::<_, Option<i64>>(13)?.map(|v| v as u64),
        exit_code: r.get(14)?,
        outcome,
        evidence_manifest_id,
        output_seq: r.get::<_, i64>(19)? as u64,
        output_truncated: r.get::<_, i64>(20)? != 0,
        output_dir: r.get(21)?,
        created_at: DateTime::parse_from_rfc3339(&created_s)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        updated_at: DateTime::parse_from_rfc3339(&updated_s)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    })
}

fn db_err(e: rusqlite::Error) -> BridgeError {
    if let rusqlite::Error::SqliteFailure(ref failure, _) = e
        && matches!(failure.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    {
        return BridgeError::new(
            ErrorCode::ResourceBusy,
            "SQLite write capacity is temporarily unavailable.",
            OriginLayer::StateStore,
        ).with_details(serde_json::json!({"retry_after_ms": 150, "reason": "sqlite_busy"}));
    }
    BridgeError::new(
        ErrorCode::InternalError,
        format!("SQLite error: {e}"),
        OriginLayer::StateStore,
    )
}

fn lock_err<T>(_: std::sync::PoisonError<T>) -> BridgeError {
    BridgeError::new(
        ErrorCode::InternalError,
        "StateStore mutex poisoned.",
        OriginLayer::StateStore,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_wal_reset_gate_parses_versions_accurately() {
        assert!(!sqlite_wal_reset_fix_verified("3.50.4"));
        assert!(sqlite_wal_reset_fix_verified("3.50.7"));
        assert!(sqlite_wal_reset_fix_verified("3.44.6"));
        assert!(!sqlite_wal_reset_fix_verified("3.51.2"));
        assert!(sqlite_wal_reset_fix_verified("3.51.3"));
        assert!(sqlite_wal_reset_fix_verified("3.52.0"));
    }

    #[test]
    fn bundled_sqlite_opens_migrates_and_backs_up() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.sqlite3");
        let store = StateStore::open(&db_path).unwrap();
        let health = store.health_snapshot().unwrap();
        assert_eq!(health.sqlite_schema_version, SQLITE_SCHEMA_VERSION);

        let backup_path = dir.path().join("backup.sqlite3");
        let rep = store.backup_to(&backup_path).unwrap();
        assert!(rep.integrity_ok);
        assert_eq!(rep.foreign_key_issues, 0);
        assert_eq!(rep.instance_id, store.instance_id());
    }

    #[test]
    fn execution_open_preserves_an_older_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE instance (slot INTEGER PRIMARY KEY, id TEXT NOT NULL, schema_version INTEGER NOT NULL);
            INSERT INTO instance VALUES (1, 'legacy-fixture', 3);").unwrap();
        drop(conn);
        let before = std::fs::read(&path).unwrap();
        let error = StateStore::open_current(&path).err().unwrap();
        assert_eq!(error.code, ErrorCode::SchemaUnsupported);
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    fn queued_executor_fixture() -> (tempfile::TempDir, StateStore, DurableJobRecord, TaskGrantEnvelope) {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(dir.path().join("state.sqlite3")).unwrap();
        let project = store.register_project(dir.path(), "Queue fixture", "queue-fixture-root").unwrap();
        let now = Utc::now();
        let grant = TaskGrantEnvelope {
            grant_id: GrantId::new_random(),
            requester_principal: "executor:default".into(),
            granting_owner: "fixture-owner".into(),
            host_id: HostId("fixture-host".into()),
            project_id: ProjectId(project.project_id),
            workspace_id: WorkspaceId("fixture-workspace".into()),
            baseline_hash: "fixture-baseline".into(),
            policy_revision: project.policy_revision,
            permitted_categories: vec![OperationCategory::Read, OperationCategory::ExecuteRecipe],
            writable_paths: vec!["_pro/**".into()],
            allowed_recipes: vec!["python_tests".into()],
            network_destinations: vec![],
            export_scope: "redacted_summary".into(),
            integration_mode: IntegrationMode::AwaitOwnerReview,
            limits: ResourceLimits::default(),
            offline_policy: OfflineGrantPolicy::DenyNewAllowRunningDeterministic,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            revoked: false,
            revoked_at: None,
        };
        let run = DurableJobRecord {
            run_id: RunId::new_random(),
            task_id: TaskId("queue-fixture".into()),
            host_id: grant.host_id.clone(),
            project_id: grant.project_id.clone(),
            workspace_id: grant.workspace_id.clone(),
            grant_id: Some(grant.grant_id.clone()),
            requester_principal: grant.requester_principal.clone(),
            executor_identity: "mcp_task_submit".into(),
            operation_id: OperationId("queue-fixture".into()),
            dedup_key: sha256_bytes(b"queue-fixture"),
            payload_digest: sha256_bytes(b"{}"),
            state: JobState::Queued,
            pid: None,
            process_start_time_100ns: None,
            exit_code: None,
            outcome: None,
            evidence_manifest_id: None,
            output_seq: 0,
            output_truncated: false,
            output_dir: dir.path().join("runs").display().to_string(),
            created_at: now,
            updated_at: now,
        };
        (dir, store, run, grant)
    }

    #[test]
    fn delegated_queue_rechecks_grant_and_recipe() {
        use crate::jobs::authorize_delegated_queue_recipe;
        let (_dir, store, run, grant) = queued_executor_fixture();
        let check = |run: &DurableJobRecord, recipe| authorize_delegated_queue_recipe(&store, &run.host_id, run, recipe);
        assert!(check(&run, "python_tests").is_err(), "Missing grant must fail");
        store.create_task_grant(&grant).unwrap();
        assert!(check(&run, "python_tests").is_ok());
        assert!(check(&run, "powershell_script").is_err(), "Grant does not allow this recipe");

        let mut expired_grant = grant.clone();
        expired_grant.grant_id = GrantId::new_random();
        expired_grant.expires_at = Utc::now() - chrono::Duration::minutes(1);
        store.create_task_grant(&expired_grant).unwrap();
        let mut expired_run = run.clone();
        expired_run.grant_id = Some(expired_grant.grant_id);
        assert!(check(&expired_run, "python_tests").unwrap_err().message.contains("expired"));

        let mut stale_grant = grant.clone();
        stale_grant.grant_id = GrantId::new_random();
        store.create_task_grant(&stale_grant).unwrap();
        store.revoke_task_grant(&grant.grant_id.0).unwrap();
        assert!(check(&run, "python_tests").unwrap_err().message.contains("revoked"));
        let mut stale_run = run.clone();
        stale_run.grant_id = Some(stale_grant.grant_id);
        assert_eq!(check(&stale_run, "python_tests").unwrap_err().code, ErrorCode::StalePrecondition);
    }

    #[test]
    fn delegated_queue_claim_cancel_start_and_recovery_are_fenced() {
        let (_dir, store, run, grant) = queued_executor_fixture();
        store.create_task_grant(&grant).unwrap();
        store.claim_durable_run(&run, "{}").unwrap();
        assert_eq!(store.request_run_cancel(&run.run_id.0).unwrap().state, JobState::Cancelled);
        assert!(store.take_delegated_queue_run(&run.host_id).unwrap().is_none());

        let mut next = run.clone();
        next.run_id = RunId::new_random();
        next.operation_id = OperationId("second-fixture".into());
        next.dedup_key = sha256_bytes(b"second-fixture");
        store.claim_durable_run(&next, "{}").unwrap();
        let (admitted, _) = store.take_delegated_queue_run(&run.host_id).unwrap().unwrap();
        assert_eq!(admitted.run_id, next.run_id);
        assert_eq!(admitted.state, JobState::Admitted);
        assert!(store.take_delegated_queue_run(&run.host_id).unwrap().is_none());
        assert!(store.start_delegated_queue_run(&admitted, grant.policy_revision, store.write_scope_marker().unwrap(), 1, Some(2)).unwrap());
        assert_eq!(store.mark_orphaned_runs_unknown().unwrap(), 0, "The HTTP broker does not own the worker queue");
        assert_eq!(store.request_run_cancel(&next.run_id.0).unwrap().state, JobState::Cancelling);
        assert_eq!(store.transition_durable_run_from(&next.run_id.0, Some(JobState::Running), JobState::Succeeded,
            None, None, None, None, None).unwrap_err().code, ErrorCode::VersionConflict);
        assert_eq!(store.reconcile_delegated_queue_runs(&run.host_id).unwrap(), 1);
        assert_eq!(store.get_durable_run(&next.run_id.0).unwrap().unwrap().state, JobState::Unknown);
        assert!(store.take_delegated_queue_run(&run.host_id).unwrap().is_none());
    }

    #[test]
    fn delegated_launch_refuses_cancelling_run_with_live_grant() {
        let (_dir, store, run, grant) = queued_executor_fixture();
        store.create_task_grant(&grant).unwrap();
        store.claim_durable_run(&run, "{}").unwrap();
        let (admitted, _) = store.take_delegated_queue_run(&run.host_id).unwrap().unwrap();
        assert_eq!(store.request_run_cancel(&run.run_id.0).unwrap().state, JobState::Cancelling);
        assert!(!store.start_delegated_queue_run(&admitted, grant.policy_revision, store.write_scope_marker().unwrap(), 1, Some(2)).unwrap());
        let current = store.get_durable_run(&run.run_id.0).unwrap().unwrap();
        assert_eq!(current.state, JobState::Cancelling);
        assert!(current.pid.is_none());
        assert!(current.evidence_manifest_id.is_none());
    }

    #[test]
    fn run_output_batch_rolls_back_if_a_later_chunk_fails() {
        let (_dir, store, run, grant) = queued_executor_fixture();
        store.create_task_grant(&grant).unwrap();
        store.claim_durable_run(&run, "{}").unwrap();
        store.conn.lock().unwrap().execute_batch(
            "CREATE TRIGGER fixture_fail_chunk BEFORE INSERT ON run_output_chunks
             WHEN NEW.seq = 2 BEGIN SELECT RAISE(ABORT, 'fixture'); END;",
        ).unwrap();
        let chunks = [("combined", "first"), ("stderr", "second")];
        assert!(store.append_run_output_batch(&run.run_id.0, &chunks, true).is_err());
        assert!(store.read_run_output(&run.run_id.0, 0, 10).unwrap().is_empty());
        let current = store.get_durable_run(&run.run_id.0).unwrap().unwrap();
        assert_eq!(current.output_seq, 0);
        assert!(!current.output_truncated);
        store.conn.lock().unwrap().execute_batch("DROP TRIGGER fixture_fail_chunk").unwrap();
        assert_eq!(store.append_run_output_batch(&run.run_id.0, &chunks, true).unwrap(), 2);
        assert_eq!(store.read_run_output(&run.run_id.0, 0, 10).unwrap(),
            vec![(1, "combined".into(), "first".into()), (2, "stderr".into(), "second".into())]);
        assert!(store.get_durable_run(&run.run_id.0).unwrap().unwrap().output_truncated);
    }

    #[test]
    fn delegated_launch_refuses_grant_that_expired_during_preparation() {
        let (_dir, store, run, grant) = queued_executor_fixture();
        store.create_task_grant(&grant).unwrap();
        store.claim_durable_run(&run, "{}").unwrap();
        let (admitted, _) = store.take_delegated_queue_run(&run.host_id).unwrap().unwrap();
        crate::jobs::authorize_delegated_queue_recipe(&store, &run.host_id, &admitted, "python_tests").unwrap();
        let expired_at = (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339();
        store.conn.lock().unwrap().execute(
            "UPDATE task_grants SET expires_at = ?1 WHERE grant_id = ?2",
            params![expired_at, grant.grant_id.0],
        ).unwrap();
        assert!(!store.start_delegated_queue_run(&admitted, grant.policy_revision, store.write_scope_marker().unwrap(), 1, Some(2)).unwrap());
        let current = store.get_durable_run(&run.run_id.0).unwrap().unwrap();
        assert_eq!(current.state, JobState::Admitted);
        assert!(current.pid.is_none());
    }

    #[test]
    fn delegated_launch_refuses_when_a_grant_was_added_after_the_files_were_chosen() {
        let (_dir, store, run, grant) = queued_executor_fixture();
        store.create_task_grant(&grant).unwrap();
        store.claim_durable_run(&run, "{}").unwrap();
        let (admitted, _) = store.take_delegated_queue_run(&run.host_id).unwrap().unwrap();
        let chosen_under = store.write_scope_marker().unwrap();
        let mut later = grant.clone();
        later.grant_id = GrantId::new_random();
        later.writable_paths = vec!["notes/**".into()];
        store.create_task_grant(&later).unwrap();
        assert!(!store.start_delegated_queue_run(&admitted, grant.policy_revision, chosen_under, 1, Some(2)).unwrap());
        assert_eq!(store.get_durable_run(&run.run_id.0).unwrap().unwrap().state, JobState::Admitted);
        assert!(store.start_delegated_queue_run(&admitted, grant.policy_revision, store.write_scope_marker().unwrap(), 1, Some(2)).unwrap());
    }

    #[test]
    fn legacy_delegated_workload_success_has_no_verified_verdict() {
        let (_dir, store, run, grant) = queued_executor_fixture();
        store.create_task_grant(&grant).unwrap();
        store.claim_durable_run(&run, "{}").unwrap();
        let (admitted, _) = store.take_delegated_queue_run(&run.host_id).unwrap().unwrap();
        assert!(store.start_delegated_queue_run(&admitted, grant.policy_revision, store.write_scope_marker().unwrap(), 1, Some(2)).unwrap());
        let old = OutcomeTriad {
            agent_outcome: Verdict::NotTested,
            execution_outcome: Verdict::Pass,
            verification_outcome: Verdict::Pass,
            soft_denied_tools: vec![],
        };
        let manifest_id = ManifestId::new_random();
        let current = store.transition_durable_run(
            &run.run_id.0, JobState::Succeeded, None, None, Some(0), Some(&old), Some(&manifest_id.0),
        ).unwrap();
        let outcome = current.outcome.unwrap();
        assert_eq!(outcome.execution_outcome, Verdict::Pass);
        assert_eq!(outcome.verification_outcome, Verdict::NotTested);
    }

    #[test]
    fn concurrent_connections_claim_one_run_and_reject_changed_context() {
        const CALLERS: usize = 8;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.sqlite3");
        let store = StateStore::open(&db_path).unwrap();
        let project = store.register_project(dir.path(), "Claim fixture", "fixture-root").unwrap();
        let now = Utc::now();
        let request = DurableJobRecord {
            run_id: RunId::new_random(),
            task_id: TaskId("claim-task".into()),
            host_id: HostId("fixture-host".into()),
            project_id: ProjectId(project.project_id.clone()),
            workspace_id: WorkspaceId("fixture-workspace".into()),
            grant_id: None,
            requester_principal: "local".into(),
            executor_identity: "fixture-executor".into(),
            operation_id: OperationId("one-operation".into()),
            dedup_key: sha256_bytes(b"fixture-dedup-key"),
            payload_digest: sha256_bytes(b"fixture-payload"),
            state: JobState::Queued,
            pid: None,
            process_start_time_100ns: None,
            exit_code: None,
            outcome: None,
            evidence_manifest_id: None,
            output_seq: 0,
            output_truncated: false,
            output_dir: dir.path().join("runs").display().to_string(),
            created_at: now,
            updated_at: now,
        };
        let connections: Vec<_> = (0..CALLERS).map(|_| StateStore::open(&db_path).unwrap()).collect();
        let gate = std::sync::Barrier::new(CALLERS);
        let responses = std::thread::scope(|scope| {
            let handles: Vec<_> = connections.into_iter().map(|connection| {
                let mut candidate = request.clone();
                candidate.run_id = RunId::new_random();
                let gate = &gate;
                scope.spawn(move || {
                    gate.wait();
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                    loop {
                        match connection.claim_durable_run(&candidate, "{}") {
                            Ok(claim) => break claim,
                            Err(error) if error.code == ErrorCode::ResourceBusy
                                && error.details.as_ref().and_then(|details| details["reason"].as_str()) == Some("sqlite_busy")
                                && std::time::Instant::now() < deadline =>
                            {
                                std::thread::sleep(std::time::Duration::from_millis(150));
                            }
                            Err(error) => panic!("Concurrent durable claim failed: {error:?}"),
                        }
                    }
                })
            }).collect();
            handles.into_iter().map(|thread| thread.join().unwrap()).collect::<Vec<_>>()
        });
        let winner = &responses[0].0.run_id;
        assert_eq!(responses.iter().filter(|(_, created)| *created).count(), 1);
        assert!(responses.iter().all(|(run, _)| &run.run_id == winner));

        let mut changed = request.clone();
        changed.payload_digest = sha256_bytes(b"changed-fixture-payload");
        let mut changed_task = request.clone();
        changed_task.task_id = TaskId("another-task".into());
        let mut changed_grant = request;
        changed_grant.grant_id = Some(GrantId("grant-different".into()));
        for attempt in [changed, changed_task, changed_grant] {
            assert_eq!(
                store.claim_durable_run(&attempt, "{}").unwrap_err().code,
                ErrorCode::IdempotencyPayloadMismatch,
            );
        }
        let saved = store.list_durable_runs(Some(&project.project_id), 10).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(&saved[0].run_id, winner);
    }

    #[test]
    fn a_stored_limit_set_that_cannot_be_read_becomes_zero_limits() {
        let (_dir, store, _run, mut grant) = queued_executor_fixture();
        grant.grant_id = GrantId::new_random();
        store.create_task_grant(&grant).unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE task_grants SET limits_json = ?1 WHERE grant_id = ?2",
                params![r#"{"max_storage_bytes":1048576,"max_processes":"2"}"#, grant.grant_id.0],
            )
            .unwrap();
        let limits = store.get_task_grant(&grant.grant_id.0).unwrap().unwrap().limits;
        assert_eq!(
            (limits.max_duration_seconds, limits.max_memory_mb, limits.max_processes, limits.max_output_bytes, limits.max_storage_bytes),
            (0, 0, 0, 0, 0)
        );
    }
}
