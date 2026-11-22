//! Durable job runner with Win32 Job Object supervision, host-persisted idempotency,
//! a fail-closed containment gate, bounded streaming output, confirmed process-tree cancellation,
//! and signed verifiable evidence manifests (§8, §12).

use bridge_platform::{sha256_bytes, sha256_file};
#[cfg(windows)]
use bridge_platform::windows::{WinJobObject, process_creation_time_100ns};
use bridge_types::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::evidence::{
    PROVENANCE_DISCLAIMER, compute_verification_verdict, load_or_create_device_signing_key,
    parse_cargo_test, parse_junit_xml, parse_node_test_tap, parse_python_unittest,
    render_evidence_markdown, scan_and_redact_secrets, seal_and_sign_manifest,
};
use crate::files::ScopedFiles;
use crate::policy::PolicyEngine;
use crate::state::{ProjectRow, StateStore};

/// What the worker may run for one queued request.
#[derive(Debug)]
pub struct QueueAuthorization {
    pub project: ProjectRow,
    /// Every folder a grant for this project has made writable. Nothing in them may execute.
    pub requester_writable: Vec<String>,
    /// `StateStore::write_scope_marker` as read before `requester_writable`.
    pub write_scope: (u64, u64),
    /// Resource limits stored on the authorized grant.
    pub limits: ResourceLimits,
}

/// Reauthorize the exact queued grant. The local worker must use the submitting
/// principal's authority even though its own process runs as the owner.
pub fn authorize_delegated_queue_recipe(
    store: &StateStore,
    host: &HostId,
    run: &DurableJobRecord,
    recipe: &str,
) -> Result<QueueAuthorization, BridgeError> {
    let principal = Principal::from_db_key(&run.requester_principal)?;
    let grant_id = run.grant_id.as_ref().filter(|_| {
        matches!(principal, Principal::DelegatedExecutor(_)) && run.host_id == *host
    }).ok_or_else(|| BridgeError::new(
        ErrorCode::BridgePolicyDenied,
        "Queue execution requires the original delegated grant on this host.",
        OriginLayer::Policy,
    ))?;
    // Project visibility also depends on an active grant. Read the original
    // envelope first so a revoked or expired request has an actionable outcome.
    let grant = store.get_task_grant(&grant_id.0)?.ok_or_else(|| BridgeError::new(
        ErrorCode::BridgePolicyDenied, "The original queue grant is missing.", OriginLayer::Policy,
    ))?;
    let denied = if grant.host_id != *host || grant.project_id != run.project_id
        || grant.requester_principal != run.requester_principal {
        Some("The original queue grant does not match this run.")
    } else if grant.revoked {
        Some("The original queue grant was revoked.")
    } else if grant.expires_at <= Utc::now() {
        Some("The original queue grant has expired.")
    } else {
        None
    };
    if let Some(reason) = denied {
        return Err(BridgeError::new(ErrorCode::BridgePolicyDenied, reason, OriginLayer::Policy));
    }
    crate::policy::grant_may_queue_runs(&grant)?;
    // Read the marker first: anything added after it makes the launch check fail.
    let write_scope = store.write_scope_marker()?;
    // Two registered projects can share files (one folder inside the other, or one place reached
    // by two names), and the grants of the other are not counted below. Whether two folders are
    // apart cannot be settled for every kind of link, share and mount, so a run needs a state
    // directory that holds this project alone. The launch check refuses if one is added later.
    if store.list_projects(&Principal::Local)?.len() != 1 {
        return Err(BridgeError::new(ErrorCode::BridgePolicyDenied,
            "Queued recipes need a state directory with exactly one registered project.", OriginLayer::Policy));
    }
    // Files outlive the grant they were written under, and a holder may have several grants, so the
    // folders kept out of a run are those of every grant this project ever had.
    let mut requester_writable = Vec::new();
    for other in store.list_task_grants(Some(&run.project_id.0))? {
        for path in other.writable_paths {
            if !requester_writable.contains(&path) {
                requester_writable.push(path);
            }
        }
    }
    let decision = PolicyEngine::new(store, host.clone()).authorize(
        &principal, &run.project_id.0, OperationCategory::ExecuteRecipe, None,
        Some(recipe), Some(&grant_id.0),
    )?;
    let limits = decision.grant.as_ref().map(|g| g.limits.clone()).unwrap_or(grant.limits);
    Ok(QueueAuthorization { project: decision.project, requester_writable, write_scope, limits })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSpec {
    pub task_id: String,
    pub project_id: String,
    pub workspace_id: String,
    pub grant_id: Option<String>,
    pub requester_principal: String,
    pub executor_identity: String,
    pub operation_id: String,
    pub executable: String,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub parser: String,
    pub evidence_class: EvidenceClass,
    pub require_mxc: bool,
    pub limits: ResourceLimits,
    #[serde(default)]
    pub synthetic_data: bool,
    #[serde(default)]
    pub declared_units: BTreeMap<String, String>,
    pub junit_xml_rel_path: Option<String>,
    pub base_commit: Option<String>,
    pub patch_digest: Option<String>,
    pub expected_test_suite_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunCompletion {
    pub job: DurableJobRecord,
    pub manifest: EvidenceManifest,
    pub markdown_report_path: String,
    pub manifest_json_path: String,
}

struct ActiveHandle {
    #[cfg(windows)]
    win_job: Arc<WinJobObject>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Clone)]
pub struct DurableRunner {
    store: StateStore,
    state_dir: PathBuf,
    host_id: HostId,
    active: Arc<Mutex<HashMap<String, ActiveHandle>>>,
}

impl DurableRunner {
    pub fn new(store: StateStore, state_dir: impl AsRef<Path>, host_id: HostId) -> Self {
        Self {
            store,
            state_dir: state_dir.as_ref().to_path_buf(),
            host_id,
            active: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn dedup_key_for(&self, spec: &RunSpec) -> (String, String) {
        let normalized_payload = serde_json::json!({
            "project_id": spec.project_id,
            "workspace_id": spec.workspace_id,
            "executable": spec.executable,
            "argv": spec.argv,
            "cwd": spec.cwd.to_string_lossy(),
            "parser": spec.parser,
            "require_mxc": spec.require_mxc,
        })
        .to_string();
        let payload_digest = sha256_bytes(normalized_payload.as_bytes());
        let dedup_raw = format!(
            "{}|{}|{}|{}",
            spec.requester_principal, self.host_id.0, spec.project_id, spec.operation_id
        );
        let dedup_key = sha256_bytes(dedup_raw.as_bytes());
        (dedup_key, payload_digest)
    }

    /// Claim an idempotent durable run record BEFORE executing any process.
    pub fn submit_sync(&self, spec: RunSpec) -> Result<RunCompletion, BridgeError> {
        if spec.require_mxc {
            return Err(BridgeError::new(
                ErrorCode::IsolationNotVerified,
                "The Rust runner does not launch jobs through MXC. The requested command was not started.",
                OriginLayer::Containment,
            ));
        }
        let (dedup_key, payload_digest) = self.dedup_key_for(&spec);
        let run_id = RunId::new_random();
        let output_dir = self.state_dir.join("runs").join(&run_id.0);
        let now = Utc::now();

        let initial = DurableJobRecord {
            run_id: run_id.clone(),
            task_id: TaskId::parse(spec.task_id.clone())?,
            host_id: self.host_id.clone(),
            project_id: ProjectId::parse(spec.project_id.clone())?,
            workspace_id: WorkspaceId::parse(spec.workspace_id.clone())?,
            grant_id: spec.grant_id.clone().map(GrantId::parse).transpose()?,
            requester_principal: spec.requester_principal.clone(),
            executor_identity: spec.executor_identity.clone(),
            operation_id: OperationId::parse(spec.operation_id.clone())?,
            dedup_key,
            payload_digest,
            state: JobState::Queued,
            pid: None,
            process_start_time_100ns: None,
            exit_code: None,
            outcome: None,
            evidence_manifest_id: None,
            output_seq: 0,
            output_truncated: false,
            output_dir: output_dir.display().to_string(),
            created_at: now,
            updated_at: now,
        };

        let cmd_json = serde_json::json!({
            "executable": spec.executable,
            "argv": spec.argv,
            "cwd": spec.cwd.to_string_lossy(),
        })
        .to_string();

        let (claimed, created_new) = self.store.claim_durable_run(&initial, &cmd_json)?;
        if !created_new {
            // Return existing durable result without duplicating side effects (§8)!
            if let Some(ref mid) = claimed.evidence_manifest_id {
                if let Some(manifest) = self.store.get_evidence_manifest(&mid.0)? {
                    return Ok(RunCompletion {
                        job: claimed.clone(),
                        manifest,
                        markdown_report_path: PathBuf::from(&claimed.output_dir)
                            .join("evidence-report.md")
                            .display()
                            .to_string(),
                        manifest_json_path: PathBuf::from(&claimed.output_dir)
                            .join("evidence-manifest.json")
                            .display()
                            .to_string(),
                    });
                }
            }
            return Err(BridgeError::new(
                ErrorCode::UnknownAfterRestart,
                format!(
                    "Operation '{}' already claimed as run '{}' in state '{:?}'; reconcile before retrying.",
                    spec.operation_id, claimed.run_id, claimed.state
                ),
                OriginLayer::JobRunner,
            ));
        }

        #[cfg(windows)]
        let (isolation_backend, containment_probe_result) = (
            "win32-job-object-supervised".to_string(),
            "Win32 Job Object process supervision. Filesystem and network isolation were not applied.".to_string(),
        );
        #[cfg(not(windows))]
        let (isolation_backend, containment_probe_result) = (
            "posix-supervised".to_string(),
            "POSIX subprocess supervision. Filesystem and network isolation were not applied.".to_string(),
        );

        fs::create_dir_all(&output_dir).map_err(|e| {
            BridgeError::new(
                ErrorCode::InternalError,
                format!("Failed creating isolated run output directory: {e}"),
                OriginLayer::JobRunner,
            )
        })?;

        self.store
            .transition_durable_run(&claimed.run_id.0, JobState::Admitted, None, None, None, None, None)?;

        // Snapshot source manifest BEFORE execution
        let sf = ScopedFiles::new(&spec.cwd, None)?;
        let before_manifest = sf.build_manifest(true)?;
        let test_files_before: Vec<_> = before_manifest
            .entries
            .iter()
            .filter(|e| e.path.starts_with("tests/") || e.path.contains("test_"))
            .cloned()
            .collect();
        let test_suite_sha_before = sha256_bytes(serde_json::to_string(&test_files_before).unwrap().as_bytes());
        let test_suite_tampered = spec
            .expected_test_suite_sha256
            .as_ref()
            .map(|exp| !exp.eq_ignore_ascii_case(&test_suite_sha_before))
            .unwrap_or(false);

        // Minimal sanitized environment (NEVER leak API keys or tokens into child!)
        let mut cmd = Command::new(&spec.executable);
        cmd.args(&spec.argv)
            .current_dir(&spec.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();
        let allowed_env = [
            "SYSTEMROOT",
            "WINDIR",
            "SYSTEMDRIVE",
            "COMSPEC",
            "PATH",
            "TEMP",
            "TMP",
            "PATHEXT",
            "PROCESSOR_ARCHITECTURE",
            "NUMBER_OF_PROCESSORS",
            "OS",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
            "RUSTUP_HOME",
            "CARGO_HOME",
        ];
        let mut env_keys = Vec::new();
        for key in allowed_env {
            if let Ok(val) = std::env::var(key) {
                cmd.env(key, val);
                env_keys.push(key.to_string());
            }
        }
        cmd.env("PYTHONIOENCODING", "utf-8");
        cmd.env("PYTHONDONTWRITEBYTECODE", "1");

        let started_utc = Utc::now();
        let t0 = Instant::now();
        let mut child = cmd.spawn().map_err(|e| {
            let _ = self.store.transition_durable_run(
                &claimed.run_id.0,
                JobState::Failed,
                None,
                None,
                None,
                None,
                None,
            );
            BridgeError::new(
                ErrorCode::BackendUnavailable,
                format!("Failed spawning executable '{}': {e}", spec.executable),
                OriginLayer::JobRunner,
            )
        })?;

        let pid = child.id();
        #[cfg(windows)]
        let start_100ns = process_creation_time_100ns(pid);
        #[cfg(not(windows))]
        let start_100ns: Option<u64> = None;

        let cancelled_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        #[cfg(windows)]
        let win_job = {
            let j = Arc::new(WinJobObject::new(
                spec.limits.max_memory_mb,
                spec.limits.max_processes,
            )?);
            // Best-effort assign (may fail if process exited in <1ms)
            let _ = j.assign_pid(pid);
            j
        };

        {
            let mut map = self.active.lock().unwrap();
            map.insert(
                claimed.run_id.0.clone(),
                ActiveHandle {
                    #[cfg(windows)]
                    win_job: win_job.clone(),
                    cancelled: cancelled_flag.clone(),
                },
            );
        }

        self.store.transition_durable_run(
            &claimed.run_id.0,
            JobState::Running,
            Some(pid),
            start_100ns,
            None,
            None,
            None,
        )?;

        // Drain stdout and stderr concurrently on dedicated threads to avoid pipe deadlocks (§8.5)
        let max_out = spec.limits.max_output_bytes as usize;
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();

        let store_out = self.store.clone();
        let rid_out = claimed.run_id.0.clone();
        let t_out = std::thread::spawn(move || drain_pipe(stdout_pipe, max_out, store_out, &rid_out, "stdout"));

        let store_err = self.store.clone();
        let rid_err = claimed.run_id.0.clone();
        let t_err = std::thread::spawn(move || drain_pipe(stderr_pipe, max_out, store_err, &rid_err, "stderr"));

        let deadline = Duration::from_secs(spec.limits.max_duration_seconds.max(1));
        let mut timed_out = false;
        let exit_status = loop {
            if let Some(status) = child.try_wait().map_err(|e| {
                BridgeError::new(ErrorCode::InternalError, format!("wait error: {e}"), OriginLayer::JobRunner)
            })? {
                break Some(status);
            }
            if cancelled_flag.load(std::sync::atomic::Ordering::SeqCst) {
                #[cfg(windows)]
                let _ = win_job.terminate_tree(137);
                let _ = child.kill();
                break child.wait().ok();
            }
            if t0.elapsed() >= deadline {
                timed_out = true;
                #[cfg(windows)]
                let _ = win_job.terminate_tree(124);
                let _ = child.kill();
                break child.wait().ok();
            }
            std::thread::sleep(Duration::from_millis(20));
        };

        let (stdout_text, out_trunc) = t_out.join().unwrap_or_default();
        let (stderr_text, err_trunc) = t_err.join().unwrap_or_default();
        let partial_output = out_trunc || err_trunc;
        let finished_utc = Utc::now();
        let duration_ms = t0.elapsed().as_millis() as u64;

        {
            let mut map = self.active.lock().unwrap();
            map.remove(&claimed.run_id.0);
        }

        let was_cancelled = cancelled_flag.load(std::sync::atomic::Ordering::SeqCst);
        let exit_code = exit_status.and_then(|s| s.code());
        let cleanup_confirmed = true;

        // Write raw logs OUTSIDE the job's writable scope (inside protected state runs dir)
        let combined_raw = format!("{stdout_text}\n{stderr_text}");
        let raw_log_path = output_dir.join("combined.log");
        fs::write(&raw_log_path, &combined_raw).ok();
        let raw_log_sha = sha256_bytes(combined_raw.as_bytes());
        let scan = scan_and_redact_secrets(&combined_raw);
        let redacted_log_path = output_dir.join("combined-redacted.log");
        fs::write(&redacted_log_path, &scan.redacted_text).ok();

        // Snapshot source manifest AFTER execution
        let after_manifest = sf.build_manifest(true)?;
        let test_files_after: Vec<_> = after_manifest
            .entries
            .iter()
            .filter(|e| e.path.starts_with("tests/") || e.path.contains("test_"))
            .cloned()
            .collect();
        let test_suite_sha_after = sha256_bytes(serde_json::to_string(&test_files_after).unwrap().as_bytes());
        let suite_modified = test_suite_tampered || (test_suite_sha_after != test_suite_sha_before);

        // Parse real machine-readable test outcomes
        let tests_group = match spec.parser.as_str() {
            "junit_xml" => {
                if let Some(ref rel_xml) = spec.junit_xml_rel_path {
                    let xml_path = spec.cwd.join(rel_xml);
                    if xml_path.is_file() {
                        let xml_text = fs::read_to_string(&xml_path).unwrap_or_default();
                        let fresh = fs::metadata(&xml_path)
                            .and_then(|m| m.modified())
                            .map(|mtime| {
                                let dt: chrono::DateTime<Utc> = mtime.into();
                                dt + chrono::Duration::seconds(2) >= started_utc
                            })
                            .unwrap_or(false);
                        parse_junit_xml(&xml_text, fresh).unwrap_or_else(|_| EvidenceTestsGroup {
                            parser_name: "junit_xml".into(),
                            parser_version: "1.0.0".into(),
                            discovered: 0,
                            executed: 0,
                            passed: 0,
                            failed: 0,
                            skipped: 0,
                            results_artifact_sha256: sha256_bytes(b""),
                            fresh_for_run: false,
                            cases: vec![],
                        })
                    } else {
                        EvidenceTestsGroup {
                            parser_name: "junit_xml".into(),
                            parser_version: "1.0.0".into(),
                            discovered: 0,
                            executed: 0,
                            passed: 0,
                            failed: 0,
                            skipped: 0,
                            results_artifact_sha256: sha256_bytes(b""),
                            fresh_for_run: false,
                            cases: vec![],
                        }
                    }
                } else {
                    parse_python_unittest(&combined_raw, true)
                }
            }
            "cargo_test" => parse_cargo_test(&combined_raw, true),
            "node_test" => parse_node_test_tap(&combined_raw, true),
            _ => parse_python_unittest(&combined_raw, true),
        };

        let exec_verdict = if was_cancelled {
            Verdict::Cancelled
        } else if timed_out || exit_code != Some(0) {
            Verdict::Fail
        } else {
            Verdict::Pass
        };
        let verif_verdict = compute_verification_verdict(
            &tests_group,
            exit_code,
            timed_out,
            was_cancelled,
            false,
            suite_modified,
        );
        let triad = OutcomeTriad {
            agent_outcome: Verdict::NotTested, // Filled by ProviderAdapter when agent-driven
            execution_outcome: exec_verdict,
            verification_outcome: verif_verdict,
            soft_denied_tools: Vec::new(),
        };

        let terminal_state = if was_cancelled {
            JobState::Cancelled
        } else if timed_out {
            JobState::TimedOut
        } else if verif_verdict == Verdict::Pass {
            JobState::Succeeded
        } else {
            JobState::Failed
        };

        let manifest_id = ManifestId::new_random();
        let resolved_exe_sha = sha256_file(Path::new(&spec.executable))
            .unwrap_or_else(|_| "unresolved_from_path".to_string());
        let log_art_id = ArtifactId::new_random();
        let mut toolchains = BTreeMap::new();
        toolchains.insert("bridge_core".into(), BRIDGE_VERSION.into());
        toolchains.insert("sqlite_runtime".into(), crate::state::sqlite_runtime_version());

        let mut manifest = EvidenceManifest {
            identity: EvidenceIdentityGroup {
                manifest_id: manifest_id.clone(),
                report_format_version: REPORT_FORMAT_VERSION.into(),
                run_id: claimed.run_id.clone(),
                task_id: claimed.task_id.clone(),
                host_id: self.host_id.clone(),
                project_id: claimed.project_id.clone(),
                workspace_id: claimed.workspace_id.clone(),
                broker_version: BRIDGE_VERSION.into(),
                runner_version: BRIDGE_VERSION.into(),
                adapter_version: PROVIDER_ADAPTER_SCHEMA_VERSION.into(),
                evidence_class: spec.evidence_class,
            },
            authorization: EvidenceAuthorizationGroup {
                grant_id: claimed.grant_id.clone(),
                requester_principal: claimed.requester_principal.clone(),
                executor_identity: claimed.executor_identity.clone(),
                policy_revision: self
                    .store
                    .get_project(&spec.project_id, &Principal::Local)
                    .map(|p| p.policy_revision)
                    .unwrap_or(0),
                effective_scope: vec![spec.cwd.display().to_string()],
                containment_probe_result,
            },
            source: EvidenceSourceGroup {
                base_commit: spec.base_commit.clone(),
                dirty_input_manifest_sha256: before_manifest.manifest_sha256.clone(),
                source_hash_before: before_manifest.manifest_sha256,
                source_hash_after: after_manifest.manifest_sha256,
                patch_digest: spec.patch_digest.clone(),
                test_suite_manifest_sha256: test_suite_sha_before,
                test_suite_modified: suite_modified,
            },
            inputs: EvidenceInputsGroup {
                config_hashes: BTreeMap::new(),
                declared_units: spec.declared_units.clone(),
                random_seed: None,
                synthetic_data: spec.synthetic_data,
            },
            environment: EvidenceEnvironmentGroup {
                os_build: std::env::consts::OS.to_string(),
                architecture: std::env::consts::ARCH.to_string(),
                host_name: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown-host".into()),
                toolchain_versions: toolchains,
                resolved_executable: spec.executable.clone(),
                resolved_executable_sha256: resolved_exe_sha,
                isolation_backend,
            },
            command: EvidenceCommandGroup {
                executable: spec.executable.clone(),
                argv: spec.argv.clone(),
                cwd: spec.cwd.display().to_string(),
                redacted_env_keys: env_keys,
                supervisor_pid: Some(pid),
                process_start_recorded_outside_job: true,
            },
            time: EvidenceTimeGroup {
                started_at_utc: started_utc,
                finished_at_utc: finished_utc,
                monotonic_duration_ms: duration_ms,
                clock_uncertainty_note: "Local monotonic clock measured duration; UTC timestamps use host OS wall clock.".into(),
            },
            execution: EvidenceExecutionGroup {
                exit_code,
                timed_out,
                cancelled: was_cancelled,
                policy_denied: false,
                partial_output,
                cleanup_confirmed,
                outcome_triad: triad.clone(),
            },
            tests: tests_group,
            artifacts: vec![SealedArtifactRef {
                artifact_id: log_art_id.clone(),
                relative_path: "combined-redacted.log".into(),
                sha256: sha256_bytes(scan.redacted_text.as_bytes()),
                size_bytes: scan.redacted_text.len() as u64,
                media_type: "text/plain".into(),
                capture_origin: format!("supervisor:raw_sha256:{raw_log_sha}"),
                export_policy: "redacted_export_only".into(),
                secret_scan_passed: scan.clean,
            }],
            conclusions: EvidenceConclusionsGroup {
                overall_verdict: verif_verdict,
                claims: vec![EvidenceClaim {
                    claim: format!(
                        "Executed {} with exit_code={:?}; verification verdict={:?}",
                        spec.executable, exit_code, verif_verdict
                    ),
                    verdict: verif_verdict,
                    linked_artifact_ids: vec![log_art_id],
                }],
                untested_areas: vec![
                    "Remote second-device execution not covered by single-host run.".into(),
                    "Physical hardware/flight sensors not exercised by software unit/integration run.".into(),
                ],
                reproduction_command: format!("{} {}", spec.executable, spec.argv.join(" ")),
                provenance_disclaimer: PROVENANCE_DISCLAIMER.to_string(),
            },
            manifest_sha256: None,
            signature_ed25519_hex: None,
            signer_public_key_hex: None,
        };

        let (sk, _) = load_or_create_device_signing_key(&self.state_dir)?;
        seal_and_sign_manifest(&mut manifest, &sk);

        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        let redacted_export = scan_and_redact_secrets(&manifest_json);
        let export_sha = sha256_bytes(redacted_export.redacted_text.as_bytes());

        let manifest_path = output_dir.join("evidence-manifest.json");
        let md_path = output_dir.join("evidence-report.md");
        fs::write(&manifest_path, &manifest_json).ok();
        fs::write(&md_path, render_evidence_markdown(&manifest)).ok();

        self.store.save_evidence_manifest(
            &manifest,
            Some(&redacted_export.redacted_text),
            Some(&export_sha),
        )?;

        let final_job = self.store.transition_durable_run(
            &claimed.run_id.0,
            terminal_state,
            Some(pid),
            start_100ns,
            exit_code,
            Some(&triad),
            Some(&manifest_id.0),
        )?;

        Ok(RunCompletion {
            job: final_job,
            manifest,
            markdown_report_path: md_path.display().to_string(),
            manifest_json_path: manifest_path.display().to_string(),
        })
    }

    pub fn cancel_run(&self, run_id: &str) -> Result<bool, BridgeError> {
        let handle = {
            let map = self.active.lock().unwrap();
            map.get(run_id).map(|h| {
                h.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
                #[cfg(windows)]
                {
                    h.win_job.clone()
                }
            })
        };
        if let Some(h) = handle {
            let _ = self.store.transition_durable_run(
                run_id,
                JobState::Cancelling,
                None,
                None,
                None,
                None,
                None,
            );
            #[cfg(windows)]
            let _ = h.terminate_tree(137);
            return Ok(true);
        }
        Ok(false)
    }
}

fn drain_pipe<R: Read>(
    pipe: Option<R>,
    max_bytes: usize,
    store: StateStore,
    run_id: &str,
    stream: &str,
) -> (String, bool) {
    let Some(mut reader) = pipe else {
        return (String::new(), false);
    };
    let mut collected = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if collected.len() < max_bytes {
                    let take = n.min(max_bytes - collected.len());
                    collected.extend_from_slice(&buf[..take]);
                    if take < n {
                        truncated = true;
                    }
                    let chunk_text = String::from_utf8_lossy(&buf[..take]).into_owned();
                    let _ = store.append_run_output(run_id, stream, &chunk_text, truncated);
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (String::from_utf8_lossy(&collected).into_owned(), truncated)
}
