//! Native Rust CLI for Edge Project Bridge V0.4.0 (`edge-bridge.exe`).

mod admission;
mod server;
#[cfg(windows)]
mod queued_mxc;
#[cfg(windows)]
mod queued_mxc_evidence;

use anyhow::Result;
use bridge_adapters::devices::{DeviceChannel, LocalHostIdentity};
use bridge_adapters::hardware::parse_ulog_bytes;
use bridge_adapters::mcp::{McpAdapterConfig, McpDispatcher, TextContentMode};
use bridge_adapters::providers::probe_all_providers;
use bridge_core::evidence::{load_or_create_device_signing_key, verify_evidence_full};
use bridge_core::files::ScopedFiles;
use bridge_core::jobs::{DurableRunner, RunSpec};
use bridge_core::state::{StateStore, sqlite_runtime_version, sqlite_wal_reset_fix_verified};
use bridge_platform::{host_resources, linux::probe_wsl_readonly, sha256_bytes};
#[cfg(windows)]
use bridge_platform::windows::probe_mxc_backend;
use bridge_types::*;
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "edge-bridge", version = BRIDGE_VERSION, about = "Edge Project Bridge V0.4.0 Rust Core CLI")]
struct Cli {
    #[arg(long, env = "EDGE_BRIDGE_STATE_DIR")]
    state_dir: Option<PathBuf>,

    #[arg(long, env = "EDGE_BRIDGE_ENVIRONMENT_KIND", value_parser = ["synthetic", "development", "canary", "production"])]
    environment_kind: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print layered diagnostics: versions, SQLite WAL-reset gate, MXC containment, WSL, GPU, providers.
    Doctor,
    /// Export versioned V0.4.0 JSON Schemas into a target directory.
    ExportSchemas {
        #[arg(long, default_value = "schemas")]
        out_dir: PathBuf,
    },
    /// Run native Rust stdio MCP compatibility adapter (`edge`, `local`, or `executor:<id>`).
    Mcp {
        #[arg(long, default_value = "edge")]
        principal: String,
        /// `summary` sends a one-line text block and keeps the result in `structuredContent` only.
        #[arg(long, default_value = "full", value_parser = ["full", "summary"])]
        text_content: String,
    },
    /// Start the authenticated loopback Rust broker + BridgePulse UI server.
    Serve {
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long)]
        ui_dist: Option<PathBuf>,
    },
    /// Register an approved project root into SQLite state.
    Register {
        root: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        grant_edge: bool,
    },
    /// Perform a consistent SQLite online backup with integrity & foreign-key verification.
    Backup {
        target: PathBuf,
    },
    /// Rehearse database migration on a cloned SQLite database without touching live state.
    /// Refuses to silently overwrite an existing destination database unless `--allow-overwrite` is explicitly passed.
    MigrateVerify {
        source_db: PathBuf,
        clone_db: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_overwrite: bool,
    },
    /// Create a scoped DelegatedExecutor TaskGrantEnvelope.
    /// Without --profile or --writable-path, grants read access and the default recipe only (no writable paths).
    GrantCreate {
        project_id: String,
        #[arg(long, default_value = "executor:default")]
        requester: String,
        /// Named profile (`pro-review`: read, git_read, create-only under `_pro/**`, and `python_tests`/`powershell_script`; `_pro/inbox/` is always read-only for delegated principals).
        #[arg(long, value_parser = ["pro-review"], conflicts_with_all = ["writable_path", "recipe"])]
        profile: Option<String>,
        /// Project-relative writable path allow pattern (repeatable). Omit for no writable paths (read and recipes only).
        #[arg(long)]
        writable_path: Vec<String>,
        /// Allowed execution recipe (repeatable; defaults to `python_tests`).
        #[arg(long, default_value = "python_tests")]
        recipe: Vec<String>,
        #[arg(long, default_value_t = 60)]
        ttl_minutes: i64,
    },
    /// Revoke a task grant immediately.
    GrantRevoke {
        grant_id: String,
    },
    /// Run a verifiable durable test/command job with signed evidence manifest.
    RunJob {
        #[arg(long)]
        project_id: String,
        #[arg(long)]
        task_id: String,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        cwd: PathBuf,
        #[arg(long)]
        executable: String,
        #[arg(long, allow_hyphen_values = true)]
        arg: Vec<String>,
        #[arg(long, default_value = "python_unittest")]
        parser: String,
        #[arg(long, default_value_t = false)]
        require_mxc: bool,
        #[arg(long, default_value_t = 60)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = false)]
        synthetic_data: bool,
    },
    /// Run an already queued local Python test request in MXC, using an explicit owner file list.
    #[cfg(windows)]
    RunQueuedPythonTests {
        run_id: String,
        /// Trusted Bridge checkout containing edge_bridge and its existing Python environment.
        #[arg(long)]
        runtime_root: PathBuf,
        #[arg(long, required = true)]
        file: Vec<String>,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=120), default_value_t = 60)]
        timeout_seconds: u64,
    },
    /// Execute delegated queue requests using the trusted Windows MXC runtime.
    #[cfg(windows)]
    Worker {
        /// Trusted Bridge checkout containing edge_bridge and its existing Python environment.
        #[arg(long)]
        runtime_root: PathBuf,
        /// Drain the current queue and exit when no more requests can be claimed.
        #[arg(long)]
        once: bool,
        /// Run delegated requests although the persistent user or machine environment holds
        /// entries that look like credentials. A run can read them and return them to the requester.
        #[arg(long)]
        allow_environment_credentials: bool,
    },
    /// List the persistent environment entries that look like credentials (names only).
    #[cfg(windows)]
    EnvironmentCheck,
    /// Apply a hash-checked PatchPlanV04 JSON file with journaled backup & postimage verification.
    ApplyPatch {
        #[arg(long)]
        project_root: PathBuf,
        #[arg(long)]
        plan_json: PathBuf,
    },
    /// Roll back a journaled patch (refuses to overwrite later user edits).
    RollbackPatch {
        #[arg(long)]
        project_root: PathBuf,
        #[arg(long)]
        journal_id: String,
    },
    /// Verify an EvidenceManifest JSON file across 5 separated dimensions:
    /// signature validity, trusted device public key, disk artifact SHA-256 hashes, completeness, and verdict truthfulness.
    VerifyEvidence {
        manifest_json: PathBuf,
        #[arg(long)]
        trusted_key: Option<String>,
        #[arg(long)]
        artifacts_dir: Option<PathBuf>,
    },
    /// Inspect installed programming providers (Codex, Claude Code, AGY) safely.
    Providers,
    /// Inspect a pinned Muse Code JSONL trace without launching inference.
    InspectMuseEvents {
        events: PathBuf,
        #[arg(long)]
        cli_version: String,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        model: String,
        #[arg(long)]
        exit_code: i32,
    },
    /// Parse and validate a PX4 ULog binary file with dropout/truncation reporting.
    ParseUlog {
        ulog_file: PathBuf,
        #[arg(long, default_value = "recorded_log")]
        evidence_class: String,
    },
    /// Run a reproducible local Rust core benchmark on disposable fixtures (c=1,2,4,8).
    Benchmark {
        #[arg(long, default_value = "benchmarks/raw/rust-v0.4.0-benchmark.json")]
        out_json: PathBuf,
        #[arg(long, default_value_t = 1000)]
        soak_reads: usize,
    },
    /// Rehearse local host-to-host Ed25519 pairing + replay rejection on two isolated host stores.
    DeviceRehearsal,
}

fn default_state_dir() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(local).join("EdgeProjectBridge-v04-dev")
    } else {
        std::env::temp_dir().join("EdgeProjectBridge-v04-dev")
    }
}

fn resolve_host_id(store: &StateStore, state_dir: &PathBuf) -> Result<HostId> {
    let chan = DeviceChannel::init(
        store.clone(),
        state_dir,
        &std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows-host".into()),
    )?;
    Ok(chan.local_identity().host_id.clone())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let state_dir = cli.state_dir.unwrap_or_else(default_state_dir);

    match cli.command {
        Commands::ExportSchemas { out_dir } => {
            std::fs::create_dir_all(&out_dir)?;
            let mut exported = Vec::new();
            for (name, schema) in export_contract_schemas() {
                let p = out_dir.join(name);
                std::fs::write(&p, serde_json::to_string_pretty(&schema)? + "\n")?;
                exported.push(p.display().to_string());
            }
            println!("{}", serde_json::to_string_pretty(&json!({"exported": exported}))?);
        }
        Commands::Doctor => {
            // Read-only semantics (§9): NEVER create an empty state.sqlite3 or signing key in an uninitialized directory!
            let db_file = state_dir.join("state.sqlite3");
            let rt = sqlite_runtime_version();
            let mut mcp_vers = vec![MCP_MODERN_PROTOCOL_VERSION.to_string()];
            mcp_vers.extend(MCP_LEGACY_PROTOCOL_VERSIONS.iter().map(|s| s.to_string()));
            let (host_id_opt, health_val, versions) = if db_file.is_file() {
                let store = StateStore::open(&db_file)?;
                let hid = resolve_host_id(&store, &state_dir)?;
                let h = store.health_snapshot()?;
                let vc = store.version_contract();
                (Some(hid.0), serde_json::to_value(h)?, vc)
            } else {
                (
                    None,
                    json!({
                        "state_db_initialized": false,
                        "sqlite_runtime_version": rt,
                        "sqlite_wal_reset_fix_verified": sqlite_wal_reset_fix_verified(&rt),
                    }),
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
                    },
                )
            };
            let resources = host_resources();
            let wsl = probe_wsl_readonly();
            let providers = probe_all_providers();
            #[cfg(windows)]
            let mxc = probe_mxc_backend();
            #[cfg(not(windows))]
            let mxc = json!({"backend": "posix"});

            let out = json!({
                "checked_at_utc": Utc::now().to_rfc3339(),
                "state_dir": state_dir.display().to_string(),
                "state_db_initialized": db_file.is_file(),
                "host_id": host_id_opt,
                "versions": versions,
                "database": health_val,
                "resources": resources,
                "containment": mxc,
                "queued_python_tests": {
                    "implemented": cfg!(windows),
                    "requires_local_owner_file_approval": true,
                    "requires_per_job_mxc_verification": true,
                    "automatic_weaker_fallback": false,
                },
                "wsl_probe": wsl,
                "providers": providers,
                "rmcp_sdk": McpDispatcher::rmcp_sdk_version(),
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Commands::Mcp { principal, text_content } => {
            std::fs::create_dir_all(&state_dir)?;
            let store = StateStore::open(state_dir.join("state.sqlite3"))?;
            let host_id = resolve_host_id(&store, &state_dir)?;
            let princ = Principal::from_db_key(&principal)?;
            let text_content = if text_content == "summary" {
                TextContentMode::Summary
            } else {
                TextContentMode::Full
            };
            let config = McpAdapterConfig::new(princ, host_id)
                .with_environment(cli.environment_kind)
                .with_text_content(text_content);
            let dispatcher = McpDispatcher::new(store, config);
            // Child processes such as Git must not outlive this server. They join a
            // kill-on-close job that ends when this process does.
            #[cfg(windows)]
            let _children = bridge_platform::windows::WinJobObject::kill_on_close()
            .and_then(|job| job.assign_pid(std::process::id()).map(|()| job))
            .inspect_err(|error| {
                eprintln!("warning: child processes are not tied to this server: {error:?}")
            });
            let served = dispatcher.serve_stdio().await;
            // Releasing the store lets SQLite checkpoint and close before the exit below.
            drop(dispatcher);
            // Tokio reads stdin on a blocking thread that would otherwise keep the
            // process alive after a write to the peer has failed.
            if let Err(error) = &served {
                eprintln!("Error: {error:?}");
            }
            std::process::exit(if served.is_ok() { 0 } else { 1 });
        }
        Commands::Serve { port, ui_dist } => {
            std::fs::create_dir_all(&state_dir)?;
            let lease = std::fs::OpenOptions::new()
                .read(true).write(true).create(true).truncate(false)
                .open(state_dir.join("rust-broker.lock"))?;
            lease.try_lock().map_err(|err| {
                anyhow::anyhow!("Cannot hold the exclusive HTTP broker lease for this state directory: {err}")
            })?;
            let store = StateStore::open(state_dir.join("state.sqlite3"))?;
            let orphaned = store.mark_orphaned_runs_unknown()?;
            if orphaned > 0 {
                eprintln!("Reconciled {orphaned} orphaned non-terminal durable run(s) to state 'unknown' on startup.");
            }
            let host_id = resolve_host_id(&store, &state_dir)?;
            server::run_http_broker(store, state_dir, host_id, port, ui_dist, cli.environment_kind).await?;
        }
        Commands::Register { root, name, grant_edge } => {
            std::fs::create_dir_all(&state_dir)?;
            let store = StateStore::open(state_dir.join("state.sqlite3"))?;
            let sf = ScopedFiles::new(&root, None)?;
            let rid = sf.current_root_identity()?;
            let mut row = store.register_project(&root, &name, &rid)?;
            if grant_edge {
                row = store.grant_edge_readonly(&row.project_id)?;
            }
            println!("{}", serde_json::to_string_pretty(&row)?);
        }
        Commands::Backup { target } => {
            let store = StateStore::open(state_dir.join("state.sqlite3"))?;
            let rep = store.backup_to(&target)?;
            println!("{}", serde_json::to_string_pretty(&rep)?);
        }
        Commands::MigrateVerify {
            source_db,
            clone_db,
            allow_overwrite,
        } => {
            if !source_db.is_file() {
                anyhow::bail!("Source SQLite backup not found: {}", source_db.display());
            }
            if clone_db.exists() && !allow_overwrite {
                anyhow::bail!(
                    "Refusing to silently overwrite existing destination database '{}'. Use a fresh Canary directory or pass --allow-overwrite explicitly.",
                    clone_db.display()
                );
            }
            if let Some(p) = clone_db.parent() {
                std::fs::create_dir_all(p)?;
            }
            std::fs::copy(&source_db, &clone_db)?;
            let store = StateStore::open(&clone_db)?;
            let health = store.health_snapshot()?;
            let projects = store.list_projects(&Principal::Edge)?;
            let verified_backup = clone_db.with_extension("migrated-backup.sqlite3");
            if verified_backup.exists() && !allow_overwrite {
                anyhow::bail!(
                    "Refusing to overwrite existing migrated backup '{}'.",
                    verified_backup.display()
                );
            }
            let brep = store.backup_to(&verified_backup)?;
            let out = json!({
                "source_db": source_db.display().to_string(),
                "clone_db": clone_db.display().to_string(),
                "migrated_backup_db": verified_backup.display().to_string(),
                "instance_id_preserved": health.instance_id,
                "schema_version_after_migration": health.sqlite_schema_version,
                "sqlite_runtime_version": health.sqlite_runtime_version,
                "sqlite_wal_reset_fix_verified": health.sqlite_wal_reset_fix_verified,
                "total_projects_preserved": health.projects,
                "edge_granted_projects_preserved": projects.len(),
                "post_migration_backup_integrity_ok": brep.integrity_ok,
                "post_migration_foreign_key_issues": brep.foreign_key_issues,
                "post_migration_backup_sha256": brep.sha256,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Commands::GrantCreate {
            project_id,
            requester,
            profile,
            writable_path,
            recipe,
            ttl_minutes,
        } => {
            for pattern in &writable_path {
                validate_writable_path_arg(pattern)?;
            }
            for name in &recipe {
                validate_recipe_arg(name)?;
            }
            let store = StateStore::open(state_dir.join("state.sqlite3"))?;
            let host_id = resolve_host_id(&store, &state_dir)?;
            let proj = store.get_project(&project_id, &Principal::Local)?;
            let sf = ScopedFiles::new(&proj.root, Some(proj.root_identity.clone()))?;
            let manifest = sf.build_manifest(true)?;
            let (permitted_categories, writable_paths, allowed_recipes) = if profile.is_some() {
                use bridge_core::policy::{PRO_REVIEW_CATEGORIES, PRO_REVIEW_RECIPES, PRO_REVIEW_WRITABLE_PATH};
                (
                    PRO_REVIEW_CATEGORIES.to_vec(),
                    vec![PRO_REVIEW_WRITABLE_PATH.to_owned()],
                    PRO_REVIEW_RECIPES.map(str::to_owned).to_vec(),
                )
            } else if writable_path.is_empty() {
                (
                    vec![
                        OperationCategory::Read,
                        OperationCategory::GitRead,
                        OperationCategory::ExecuteRecipe,
                    ],
                    Vec::new(),
                    recipe,
                )
            } else {
                (
                    vec![
                        OperationCategory::Read,
                        OperationCategory::Write,
                        OperationCategory::Patch,
                        OperationCategory::Checkpoint,
                        OperationCategory::ExecuteRecipe,
                        OperationCategory::GitRead,
                    ],
                    writable_path,
                    recipe,
                )
            };
            let now = Utc::now();
            let grant = TaskGrantEnvelope {
                grant_id: GrantId::new_random(),
                requester_principal: requester,
                granting_owner: std::env::var("USERNAME").unwrap_or_else(|_| "local_owner".into()),
                host_id,
                project_id: ProjectId::parse(project_id)?,
                workspace_id: WorkspaceId::new_random(),
                baseline_hash: manifest.manifest_sha256,
                policy_revision: proj.policy_revision,
                permitted_categories,
                writable_paths,
                allowed_recipes,
                network_destinations: Vec::new(),
                export_scope: "redacted_summary".into(),
                integration_mode: IntegrationMode::AwaitOwnerReview,
                limits: ResourceLimits::default(),
                offline_policy: OfflineGrantPolicy::DenyNewAllowRunningDeterministic,
                expires_at: now + Duration::minutes(ttl_minutes.clamp(1, 1440)),
                revoked: false,
                revoked_at: None,
                created_at: now,
            };
            store.create_task_grant(&grant)?;
            println!("{}", serde_json::to_string_pretty(&grant)?);
        }
        Commands::GrantRevoke { grant_id } => {
            let store = StateStore::open(state_dir.join("state.sqlite3"))?;
            let changed = store.revoke_task_grant(&grant_id)?;
            println!("{}", serde_json::to_string_pretty(&json!({"grant_id": grant_id, "revoked": changed}))?);
        }
        Commands::RunJob {
            project_id,
            task_id,
            operation_id,
            workspace_id,
            cwd,
            executable,
            arg,
            parser,
            require_mxc,
            timeout_seconds,
            synthetic_data,
        } => {
            std::fs::create_dir_all(&state_dir)?;
            let store = StateStore::open(state_dir.join("state.sqlite3"))?;
            let host_id = resolve_host_id(&store, &state_dir)?;
            let runner = DurableRunner::new(store, &state_dir, host_id);
            let mut limits = ResourceLimits::default();
            limits.max_duration_seconds = timeout_seconds;
            let ws_id = workspace_id.unwrap_or_else(|| {
                let d = sha256_bytes(cwd.to_string_lossy().as_bytes());
                format!("ws_{}", &d[..16])
            });
            let comp = runner.submit_sync(RunSpec {
                task_id,
                project_id,
                workspace_id: ws_id,
                grant_id: None,
                requester_principal: "local".into(),
                executor_identity: "edge-bridge-rust-runner".into(),
                operation_id,
                executable,
                argv: arg,
                cwd,
                parser,
                evidence_class: EvidenceClass::SoftwareUnit,
                require_mxc,
                limits,
                synthetic_data,
                declared_units: BTreeMap::new(),
                junit_xml_rel_path: None,
                base_commit: None,
                patch_digest: None,
                expected_test_suite_sha256: None,
            })?;
            println!("{}", serde_json::to_string_pretty(&comp)?);
        }
        #[cfg(windows)]
        Commands::RunQueuedPythonTests { run_id, runtime_root, file, timeout_seconds } => {
            let state_dir = std::path::absolute(state_dir)?;
            let store = StateStore::open_current(state_dir.join("state.sqlite3"))?;
            let host = resolve_host_id(&store, &state_dir)?;
            let result = queued_mxc::run(&store, &state_dir, &host, RunId::parse(run_id)?, &runtime_root, file, timeout_seconds)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        #[cfg(windows)]
        Commands::EnvironmentCheck => {
            let entries = bridge_platform::windows::persistent_environment();
            let names = entries.as_deref().map(bridge_core::evidence::credential_like_environment_names);
            println!("{}", serde_json::to_string_pretty(&json!({
                "readable": names.is_some(),
                "credential_like_count": names.as_ref().map(Vec::len),
                "credential_like_names": names,
                "delegated_runs": match names.as_ref().map(Vec::len) {
                    Some(0) => "allowed",
                    _ => "refused unless the worker is started with --allow-environment-credentials",
                },
            }))?);
        }
        #[cfg(windows)]
        Commands::Worker { runtime_root, once, allow_environment_credentials } => {
            let state_dir = std::path::absolute(state_dir)?;
            let store = queued_mxc::retry_busy(|| StateStore::open_current(state_dir.join("state.sqlite3")))?;
            let host = resolve_host_id(&store, &state_dir)?;
            queued_mxc::worker(&store, &state_dir, &host, &runtime_root, once, allow_environment_credentials)?;
        }
        Commands::ApplyPatch { project_root, plan_json } => {
            let raw = std::fs::read_to_string(&plan_json)?;
            let plan: PatchPlanV04 = serde_json::from_str(&raw)?;
            let sf = ScopedFiles::new(&project_root, None)?;
            let jdir = state_dir.join("patch-journals");
            let (res, journal) = sf.apply_patch_plan(&plan, &jdir, None)?;
            if state_dir.join("state.sqlite3").is_file() {
                if let Ok(store) = StateStore::open(state_dir.join("state.sqlite3")) {
                    let _ = store.save_patch_journal(
                        &journal.journal_id,
                        &journal.project_id,
                        &journal.operation_id,
                        &journal.state,
                        &journal.plan_sha256,
                        &serde_json::to_string(&journal)?,
                    );
                }
            }
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        Commands::RollbackPatch { project_root, journal_id } => {
            let sf = ScopedFiles::new(&project_root, None)?;
            let jdir = state_dir.join("patch-journals");
            let restored = sf.rollback_patch_journal(&jdir, &journal_id)?;
            println!("{}", serde_json::to_string_pretty(&json!({"journal_id": journal_id, "restored_files": restored}))?);
        }
        Commands::VerifyEvidence {
            manifest_json,
            trusted_key,
            artifacts_dir,
        } => {
            let raw = std::fs::read_to_string(&manifest_json)?;
            let manifest: EvidenceManifest = serde_json::from_str(&raw)?;
            let resolved_trusted_key = if let Some(k) = trusted_key {
                Some(k)
            } else if state_dir.join("device-signing-ed25519.key").is_file() {
                load_or_create_device_signing_key(&state_dir).ok().map(|(_, pk)| pk)
            } else {
                None
            };
            let report = verify_evidence_full(
                &manifest,
                resolved_trusted_key.as_deref(),
                artifacts_dir.as_deref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.overall_verified {
                std::process::exit(1);
            }
        }
        Commands::Providers => {
            let reps = probe_all_providers();
            println!("{}", serde_json::to_string_pretty(&reps)?);
        }
        Commands::InspectMuseEvents { events, cli_version, session_id, model, exit_code } => {
            let events = std::io::BufReader::new(std::fs::File::open(events)?);
            let report = bridge_adapters::muse::inspect_muse_events(
                events, &cli_version, &session_id, &model, exit_code,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Commands::ParseUlog { ulog_file, evidence_class } => {
            let raw = std::fs::read(&ulog_file)?;
            let ec = match evidence_class.as_str() {
                "sitl" => EvidenceClass::Sitl,
                "flight_observation" => EvidenceClass::FlightObservation,
                _ => EvidenceClass::RecordedLog,
            };
            let summary = parse_ulog_bytes(&raw, &ulog_file.display().to_string(), ec)?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Commands::Benchmark { out_json, soak_reads } => {
            let report = run_rust_benchmark(soak_reads)?;
            if let Some(p) = out_json.parent() {
                std::fs::create_dir_all(p)?;
            }
            std::fs::write(&out_json, serde_json::to_string_pretty(&report)? + "\n")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Commands::DeviceRehearsal => {
            let tmp = std::env::temp_dir().join(format!("eb_dev_rehearsal_{}", uuid::Uuid::new_v4().simple()));
            let dir_a = tmp.join("host_a");
            let dir_b = tmp.join("host_b");
            std::fs::create_dir_all(&dir_a)?;
            std::fs::create_dir_all(&dir_b)?;
            let store_a = StateStore::open(dir_a.join("state.sqlite3"))?;
            let store_b = StateStore::open(dir_b.join("state.sqlite3"))?;
            let chan_a = DeviceChannel::init(store_a, &dir_a, "Owner-Host-A")?;
            let chan_b = DeviceChannel::init(store_b, &dir_b, "Simulated-Host-B-LocalRehearsal")?;
            let offer = chan_a.create_pairing_offer(
                chan_b.local_identity().host_id.clone(),
                vec!["bridgepulse-lab:read".into(), "bridgepulse-lab:test".into()],
                120,
            )?;
            let paired = chan_a.complete_pairing(
                &offer.one_time_secret,
                &LocalHostIdentity {
                    host_id: chan_b.local_identity().host_id.clone(),
                    display_name: chan_b.local_identity().display_name.clone(),
                    public_key_hex: chan_b.local_identity().public_key_hex.clone(),
                },
                "http://127.0.0.1:0",
                BTreeMap::new(),
            )?;
            let env = chan_b.sign_envelope(json!({"action":"heartbeat","rehearsal":true}).to_string());
            let verified = chan_a.verify_incoming_envelope(&env)?;
            let replay_rejected = chan_a.verify_incoming_envelope(&env).is_err();
            let _ = std::fs::remove_dir_all(&tmp);
            println!("{}", serde_json::to_string_pretty(&json!({
                "rehearsal_only": true,
                "physical_second_pc_tested": false,
                "host_a_id": chan_a.local_identity().host_id,
                "host_b_id": paired.host_id,
                "verified_peer_id": verified.host_id,
                "replay_rejected": replay_rejected,
            }))?);
        }
    }
    Ok(())
}

fn percentiles_ms(samples: &mut [f64]) -> serde_json::Value {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = samples.len();
    if n == 0 {
        return json!({"n": 0});
    }
    let mean = samples.iter().sum::<f64>() / (n as f64);
    let idx = |q: f64| ((n - 1) as f64 * q).floor() as usize;
    json!({
        "n": n,
        "min_ms": (samples[0] * 1000.0).round() / 1000.0,
        "p50_ms": (samples[idx(0.50)] * 1000.0).round() / 1000.0,
        "p95_ms": (samples[idx(0.95)] * 1000.0).round() / 1000.0,
        "p99_ms": (samples[idx(0.99)] * 1000.0).round() / 1000.0,
        "max_ms": (samples[n - 1] * 1000.0).round() / 1000.0,
        "mean_ms": (mean * 1000.0).round() / 1000.0,
    })
}

fn run_rust_benchmark(soak_reads: usize) -> Result<serde_json::Value> {
    let tmp = std::env::temp_dir().join(format!("eb_bench_rust_{}", uuid::Uuid::new_v4().simple()));
    let state_dir = tmp.join("state");
    let proj_dir = tmp.join("fixture_project");
    std::fs::create_dir_all(&state_dir)?;
    std::fs::create_dir_all(&proj_dir)?;

    let content_4k = "alpha beta gamma delta 0123456789\n".repeat(128);
    let content_64k = "telemetry_row,2026-11-19T00:00:00Z,10.5,m/s\n".repeat(1600);
    std::fs::write(proj_dir.join("small_4k.txt"), &content_4k[..4096])?;
    std::fs::write(proj_dir.join("medium_64k.txt"), &content_64k[..65536])?;
    for i in 0..40 {
        std::fs::write(proj_dir.join(format!("mod_{i:02}.py")), format!("def fn_{i}(x):\n    return x + {i}\n"))?;
    }

    let store = StateStore::open(state_dir.join("state.sqlite3"))?;
    let sf = ScopedFiles::new(&proj_dir, None)?;
    let rid = sf.current_root_identity()?;
    let proj = store.register_project(&proj_dir, "Bench Fixture", &rid)?;
    let proj = store.grant_edge_readonly(&proj.project_id)?;
    let host_id = resolve_host_id(&store, &state_dir)?;

    let idle_ws = host_resources().process_working_set_bytes;
    let disp = std::sync::Arc::new(McpDispatcher::new(
        store.clone(),
        McpAdapterConfig::new(Principal::Edge, host_id.clone()),
    ));

    // Warmup
    for _ in 0..10 {
        let _ = disp.dispatch_tool("file_read", &json!({"project_id": proj.project_id, "path": "small_4k.txt", "limit": 65536}));
    }

    let mut workloads = serde_json::Map::new();
    for (label, fname) in [("read_4k_warm", "small_4k.txt"), ("read_64k_warm", "medium_64k.txt")] {
        let mut conc_map = serde_json::Map::new();
        for conc in [1usize, 2, 4, 8] {
            let total_reqs = 200usize;
            let per_thread = total_reqs / conc;
            let t_batch0 = Instant::now();
            let mut handles = Vec::new();
            for _ in 0..conc {
                let d = disp.clone();
                let pid = proj.project_id.clone();
                let f = fname.to_string();
                handles.push(std::thread::spawn(move || {
                    let mut v = Vec::with_capacity(per_thread);
                    let mut errs = 0usize;
                    for _ in 0..per_thread {
                        let t0 = Instant::now();
                        match d.dispatch_tool("file_read", &json!({"project_id": pid, "path": f, "limit": 65536})) {
                            Ok(_) => v.push(t0.elapsed().as_secs_f64() * 1000.0),
                            Err(_) => errs += 1,
                        }
                    }
                    (v, errs)
                }));
            }
            let mut all = Vec::new();
            let mut errs = 0usize;
            for h in handles {
                let (v, e) = h.join().unwrap();
                all.extend(v);
                errs += e;
            }
            let batch_s = t_batch0.elapsed().as_secs_f64();
            let mut stat = percentiles_ms(&mut all);
            stat["errors"] = json!(errs);
            stat["throughput_rps"] = json!(((all.len() as f64 / batch_s.max(1e-6)) * 100.0).round() / 100.0);
            conc_map.insert(format!("c{conc}"), stat);
        }
        workloads.insert(label.into(), json!(conc_map));
    }

    // file_list 42 files
    let mut list_samples = Vec::new();
    for _ in 0..100 {
        let t0 = Instant::now();
        let _ = disp.dispatch_tool("file_list", &json!({"project_id": proj.project_id, "path": ".", "limit": 100}))?;
        list_samples.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    workloads.insert("file_list_42files".into(), percentiles_ms(&mut list_samples));

    // Durable job claim ack latency (SQLite WAL write commit)
    let mut claim_samples = Vec::new();
    for i in 0..60 {
        let t0 = Instant::now();
        let rec = DurableJobRecord {
            run_id: RunId::new_random(),
            task_id: TaskId("bench_task".into()),
            host_id: host_id.clone(),
            project_id: ProjectId(proj.project_id.clone()),
            workspace_id: WorkspaceId("ws_bench".into()),
            grant_id: None,
            requester_principal: "local".into(),
            executor_identity: "bench".into(),
            operation_id: OperationId(format!("bench-op-{i}")),
            dedup_key: sha256_bytes(format!("bench-dedup-{i}").as_bytes()),
            payload_digest: sha256_bytes(b"bench"),
            state: JobState::Queued,
            pid: None,
            process_start_time_100ns: None,
            exit_code: None,
            outcome: None,
            evidence_manifest_id: None,
            output_seq: 0,
            output_truncated: false,
            output_dir: tmp.join("runs").display().to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let _ = store.claim_durable_run(&rec, "{}")?;
        claim_samples.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    workloads.insert("durable_job_claim_ack".into(), percentiles_ms(&mut claim_samples));

    // Bounded local reconnect/concurrency soak (default 1,000 fixture reads across re-initialized dispatchers §18!)
    let mut soak_samples = Vec::with_capacity(soak_reads);
    let mut soak_errors = 0usize;
    let t_soak = Instant::now();
    for i in 0..soak_reads {
        let d = if i % 100 == 0 {
            // Simulate reconnect + idempotent initialize every 100 reads
            let fresh = McpDispatcher::new(store.clone(), McpAdapterConfig::new(Principal::Edge, host_id.clone()));
            let _ = fresh.handle_jsonrpc(&json!({"jsonrpc":"2.0","id":i,"method":"initialize","params":{"protocolVersion":"2026-07-28"}}));
            fresh
        } else {
            McpDispatcher::new(store.clone(), McpAdapterConfig::new(Principal::Edge, host_id.clone()))
        };
        let t0 = Instant::now();
        match d.dispatch_tool("file_read", &json!({"project_id": proj.project_id, "path": "small_4k.txt", "limit": 65536})) {
            Ok(_) => soak_samples.push(t0.elapsed().as_secs_f64() * 1000.0),
            Err(_) => soak_errors += 1,
        }
    }
    let soak_s = t_soak.elapsed().as_secs_f64();
    let mut soak_stats = percentiles_ms(&mut soak_samples);
    soak_stats["errors"] = json!(soak_errors);
    soak_stats["reset_cycles"] = json!(soak_reads / 100);
    soak_stats["duration_s"] = json!((soak_s * 1000.0).round() / 1000.0);
    workloads.insert("soak_reconnect_1000_reads".into(), soak_stats);

    let post_ws = host_resources().process_working_set_bytes;
    let _ = std::fs::remove_dir_all(&tmp);
    let rt = sqlite_runtime_version();

    Ok(json!({
        "captured_at_utc": Utc::now().to_rfc3339(),
        "subject": "edge-project-bridge-rust-v0.4.0",
        "environment": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "sqlite_runtime": rt,
            "sqlite_wal_reset_fix_verified": sqlite_wal_reset_fix_verified(&rt),
            "rmcp_sdk": McpDispatcher::rmcp_sdk_version(),
        },
        "memory": {
            "working_set_idle_mib": idle_ws.map(|b| ((b as f64 / 1048576.0) * 100.0).round() / 100.0),
            "working_set_post_mib": post_ws.map(|b| ((b as f64 / 1048576.0) * 100.0).round() / 100.0),
            "budget_target_mib": 100.0,
        },
        "workloads": workloads,
    }))
}

/// A recipe is a name such as `python_tests`, never a path.
fn validate_recipe_arg(name: &str) -> Result<()> {
    if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_') {
        anyhow::bail!("Invalid --recipe: a recipe name has only lowercase letters, digits and '_'.");
    }
    Ok(())
}

fn validate_writable_path_arg(pattern: &str) -> Result<()> {
    if pattern.is_empty() {
        anyhow::bail!("Invalid --writable-path: pattern cannot be empty.");
    }
    if pattern.as_bytes().first() == Some(&b'!') {
        anyhow::bail!(
            "Invalid --writable-path '{pattern}': deny patterns are not supported; pass allow patterns only."
        );
    }
    if pattern.contains('\\') {
        anyhow::bail!(
            "Invalid --writable-path '{pattern}': use forward slashes ('/'), not backslashes ('\\')."
        );
    }
    if pattern.starts_with('/') || pattern.contains(':') || pattern.split('/').any(|part| part == "..") {
        anyhow::bail!(
            "Invalid --writable-path '{pattern}': must be project-relative, without a leading '/', a ':' or a '..' part."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_create_writable_path_validation_rejects_invalid_patterns() {
        for bad in ["!x", "!_pro/inbox/**", "", r"a\b", "/x", "C:/x/**", "../x", "_pro/../src/**"] {
            assert!(validate_writable_path_arg(bad).is_err(), "expected rejection for {bad:?}");
        }
        for good in ["_pro/**", "src/app.py", "**"] {
            assert!(validate_writable_path_arg(good).is_ok(), "expected acceptance for {good:?}");
        }
        for bad in ["", "C:/owner/check.ps1", "python tests", "Python_Tests", "a-b"] {
            assert!(validate_recipe_arg(bad).is_err(), "expected rejection for {bad:?}");
        }
        for good in ["python_tests", "powershell_script", "read_output"] {
            assert!(validate_recipe_arg(good).is_ok(), "expected acceptance for {good:?}");
        }
    }
}
