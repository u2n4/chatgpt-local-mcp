//! Seal evidence only when the verified MXC supervisor supplies both snapshot digests.
use anyhow::{Context, Result, ensure};
use bridge_core::evidence::{
    DELEGATED_WORK_COPY_EXECUTOR, DELEGATED_WORK_COPY_NOTE, DELEGATED_WORKLOAD_REPORT_EXECUTOR,
    DELEGATED_WORKLOAD_REPORT_NOTE, PROVENANCE_DISCLAIMER, load_or_create_device_signing_key,
    render_evidence_markdown, scan_and_redact_secrets, seal_and_sign_manifest,
};
use bridge_core::state::{StateStore, sqlite_runtime_version};
use bridge_platform::sha256_bytes;
use bridge_types::*;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub struct QueuedRunEvidence<'a> {
    pub run: &'a DurableJobRecord,
    pub receipt: &'a Value,
    pub policy_revision: u64,
    pub test_log: &'a str,
    pub recipe: &'a str,
    pub delegated: bool,
    pub work_workspace: Option<&'a str>,
    pub terminal: JobState,
    pub partial_output: bool,
    pub cleanup_confirmed: bool,
    pub tests: EvidenceTestsGroup,
    pub outcome: OutcomeTriad,
    pub exit_code: Option<i32>,
    pub started: DateTime<Utc>,
    pub elapsed_ms: u64,
}

fn read_string<'a>(object: &'a Value, field: &str) -> Result<&'a str> {
    object[field]
        .as_str()
        .with_context(|| format!("Missing MXC evidence field {field}"))
}

fn digest<'a>(object: &'a Value, field: &str) -> Result<&'a str> {
    let value = read_string(object, field)?;
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Invalid MXC evidence digest {field}"
    );
    Ok(value)
}

const LOG_NAME: &str = "test-results-redacted.log";
const REPORT_NAME: &str = "evidence-report.md";
pub const MANIFEST_NAME: &str = "evidence-manifest.json";

#[derive(Debug)]
pub enum EvidenceError {
    Rejected(anyhow::Error),
    Store(BridgeError),
    Prepare(anyhow::Error),
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::create_new(path)?;
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = result {
        match std::fs::remove_file(path) {
            Ok(()) => return Err(error.into()),
            Err(cleanup) => return Err(anyhow::anyhow!("{error}. Could not remove incomplete export: {cleanup}")),
        }
    }
    Ok(())
}

pub fn finalize(
    store: &StateStore,
    state: &Path,
    output: &Path,
    input: QueuedRunEvidence<'_>,
) -> std::result::Result<(DurableJobRecord, bool), EvidenceError> {
    for name in [LOG_NAME, MANIFEST_NAME, REPORT_NAME] {
        if output.join(name).try_exists().map_err(|error| EvidenceError::Prepare(error.into()))? {
            return Err(EvidenceError::Rejected(anyhow::anyhow!("Evidence export path already exists: {name}")));
        }
    }
    let (key, _) = load_or_create_device_signing_key(state)
        .map_err(|error| EvidenceError::Prepare(error.into()))?;
    // The callback has no filesystem writes. A busy transaction can retry safely.
    let (record, manifest, json) = persist(|| {
        store.finalize_queued_run_with_evidence(&input.run.run_id.0, input.terminal, input.exit_code, |terminal| {
            let mut manifest = prepare(&input, terminal)?;
            seal_and_sign_manifest(&mut manifest, &key);
            let json = serde_json::to_string_pretty(&manifest)?;
            ensure!(scan_and_redact_secrets(&json).clean, "Signed evidence contains non-exportable text");
            Ok::<_, anyhow::Error>((manifest, json))
        })
    })?;

    // The database is authoritative. Publish the signed file last and never publish it before commit.
    let exported = (|| -> Result<()> {
        write_new(&output.join(LOG_NAME), input.test_log.as_bytes())?;
        write_new(&output.join(REPORT_NAME), render_evidence_markdown(&manifest).as_bytes())?;
        write_new(&output.join(MANIFEST_NAME), json.as_bytes())
    })();
    if let Err(error) = &exported {
        eprintln!("Queue run {} could not publish local evidence files: {error:#}", input.run.run_id.0);
    }
    Ok((record, exported.is_ok()))
}

fn persist<T>(
    operation: impl FnMut() -> std::result::Result<Result<T>, BridgeError>,
) -> std::result::Result<T, EvidenceError> {
    crate::queued_mxc::retry_busy(operation).map_err(EvidenceError::Store)?.map_err(EvidenceError::Rejected)
}

fn prepare(input: &QueuedRunEvidence<'_>, terminal: JobState) -> Result<EvidenceManifest> {
    let run = input.run;
    let receipt = input.receipt;
    let provenance = &receipt["provenance"];
    let before = digest(provenance, "snapshot_before_sha256")?;
    let after = digest(provenance, "snapshot_after_sha256")?;
    let unchanged = receipt["test_snapshot_unchanged"] == true;
    ensure!(
        (before == after) == unchanged,
        "The snapshot seal and receipt disagree"
    );
    let policy = digest(receipt, "policy_sha256")?;
    let executable = read_string(provenance, "executable")?.to_owned();
    let executable_sha256 = digest(provenance, "executable_sha256")?.to_owned();
    let argv: Vec<String> = serde_json::from_value(provenance["argv"].clone())?;
    let mut outcome = input.outcome.clone();
    if terminal == JobState::Cancelled {
        outcome.execution_outcome = Verdict::Cancelled;
        outcome.verification_outcome = Verdict::Cancelled;
    }
    let verdict = outcome.verification_outcome;
    let is_work_copy = input.work_workspace.is_some();
    let executor = if is_work_copy {
        DELEGATED_WORK_COPY_EXECUTOR
    } else if input.delegated {
        DELEGATED_WORKLOAD_REPORT_EXECUTOR
    } else {
        "local-owner-queued-python-mxc"
    };
    let claim = if is_work_copy {
        DELEGATED_WORK_COPY_NOTE
    } else if input.delegated {
        DELEGATED_WORKLOAD_REPORT_NOTE
    } else if input.recipe == "powershell_script" {
        "Verified MXC process execution. The script's own assertions were not independently parsed."
    } else {
        "Verified MXC snapshot test results"
    };
    let reproduce = if let Some(workspace) = input.work_workspace {
        format!(
            "Submit {} for workspace '{workspace}' with an active pro-agent grant and process it with the owner worker started with --allow-work-exec.",
            input.recipe
        )
    } else if input.delegated {
        format!("Submit {} with an active delegated grant and process it with the owner worker.", input.recipe)
    } else {
        "Submit python_tests to the local queue, then approve the file list with run-queued-python-tests.".into()
    };
    let raw_scope: Vec<String> = serde_json::from_value(receipt["approved_files"].clone())?;
    let effective_scope = if let Some(workspace) = input.work_workspace {
        raw_scope
            .into_iter()
            .map(|file| format!("_pro/work/{workspace}/{file}"))
            .collect()
    } else {
        raw_scope
    };
    let mut declared_units = BTreeMap::new();
    if let Some(workspace) = input.work_workspace {
        declared_units.insert("work_copy".into(), format!("_pro/work/{workspace}"));
    }
    let cwd = if let Some(workspace) = input.work_workspace {
        format!("disposable work-copy snapshot (_pro/work/{workspace})")
    } else {
        "disposable project snapshot".into()
    };
    let untested_areas = if let Some(workspace) = input.work_workspace {
        vec![
            format!("Executed remote-modified work copy '_pro/work/{workspace}'; live project files were not tested or modified."),
            "Files and behavior outside the work-copy snapshot scope.".into(),
        ]
    } else {
        vec!["Files and behavior outside the recipe's snapshot scope.".into()]
    };
    let manifest_id = ManifestId::new_random();
    let artifact_id = ArtifactId::new_random();
    let log_hash = sha256_bytes(input.test_log.as_bytes());
    ensure!(
        input.tests.results_artifact_sha256 == log_hash,
        "Test parser and artifact digests differ"
    );
    ensure!(
        scan_and_redact_secrets(input.test_log).clean,
        "Test evidence contains non-exportable text"
    );

    Ok(EvidenceManifest {
        identity: EvidenceIdentityGroup {
            manifest_id: manifest_id.clone(), report_format_version: REPORT_FORMAT_VERSION.into(),
            run_id: run.run_id.clone(), task_id: run.task_id.clone(), project_id: run.project_id.clone(),
            host_id: run.host_id.clone(), workspace_id: run.workspace_id.clone(),
            broker_version: BRIDGE_VERSION.into(), runner_version: BRIDGE_VERSION.into(),
            adapter_version: PROVIDER_ADAPTER_SCHEMA_VERSION.into(), evidence_class: EvidenceClass::SoftwareUnit,
        },
        authorization: EvidenceAuthorizationGroup {
            grant_id: run.grant_id.clone(), requester_principal: run.requester_principal.clone(),
            executor_identity: executor.into(), policy_revision: input.policy_revision,
            effective_scope, containment_probe_result: format!("Per-job canaries verified for MXC policy {policy}."),
        },
        source: EvidenceSourceGroup {
            base_commit: None, dirty_input_manifest_sha256: before.into(), source_hash_before: before.into(),
            source_hash_after: after.into(), patch_digest: None, test_suite_manifest_sha256: before.into(),
            test_suite_modified: !unchanged,
        },
        inputs: EvidenceInputsGroup {
            config_hashes: BTreeMap::from([("mxc_policy".into(), policy.into())]),
            declared_units, random_seed: None, synthetic_data: false,
        },
        environment: EvidenceEnvironmentGroup {
            os_build: std::env::consts::OS.into(), architecture: std::env::consts::ARCH.into(),
            host_name: run.host_id.0.clone(),
            toolchain_versions: BTreeMap::from([
                ("bridge_core".into(), BRIDGE_VERSION.into()),
                ("sqlite_runtime".into(), sqlite_runtime_version()),
                ("codex".into(), read_string(provenance, "codex_version")?.into()),
                ("codex_sha256".into(), digest(provenance, "codex_sha256")?.into()),
            ]),
            resolved_executable: executable.clone(), resolved_executable_sha256: executable_sha256,
            isolation_backend: "codex-sandbox-mxc".into(),
        },
        command: EvidenceCommandGroup {
            executable, argv, cwd, redacted_env_keys: vec![],
            supervisor_pid: run.pid, process_start_recorded_outside_job: run.process_start_time_100ns.is_some(),
        },
        time: EvidenceTimeGroup {
            started_at_utc: input.started, finished_at_utc: Utc::now(), monotonic_duration_ms: input.elapsed_ms,
            clock_uncertainty_note: "The host measures UTC and monotonic time. Duration includes per-job preflight.".into(),
        },
        execution: EvidenceExecutionGroup {
            exit_code: input.exit_code, cancelled: terminal == JobState::Cancelled,
            timed_out: terminal == JobState::TimedOut, policy_denied: false,
            partial_output: input.partial_output, cleanup_confirmed: input.cleanup_confirmed, outcome_triad: outcome,
        },
        tests: input.tests.clone(),
        artifacts: vec![SealedArtifactRef {
            artifact_id: artifact_id.clone(), relative_path: LOG_NAME.into(), sha256: log_hash,
            size_bytes: input.test_log.len() as u64, media_type: "text/plain".into(),
            capture_origin: if is_work_copy {
                "Work-copy workload output captured and redacted by the owner MXC supervisor"
            } else if input.delegated {
                "Workload-reported output captured and redacted by the owner MXC supervisor"
            } else {
                "Owner MXC supervisor output redacted before evidence export"
            }.into(),
            export_policy: "redacted_export_only".into(), secret_scan_passed: true,
        }],
        conclusions: EvidenceConclusionsGroup {
            overall_verdict: verdict,
            claims: vec![EvidenceClaim { claim: claim.into(), verdict, linked_artifact_ids: vec![artifact_id] }],
            untested_areas,
            reproduction_command: reproduce,
            provenance_disclaimer: if is_work_copy {
                format!("{PROVENANCE_DISCLAIMER} {DELEGATED_WORK_COPY_NOTE}")
            } else if input.delegated {
                format!("{PROVENANCE_DISCLAIMER} {DELEGATED_WORKLOAD_REPORT_NOTE}")
            } else {
                PROVENANCE_DISCLAIMER.into()
            },
        },
        manifest_sha256: None, signature_ed25519_hex: None, signer_public_key_hex: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_evidence_retries_remain_a_store_error() {
        let mut attempts = 0;
        let result = persist::<()>(|| {
            attempts += 1;
            Err(BridgeError::new(ErrorCode::ResourceBusy, "fixture write lock", OriginLayer::StateStore))
        });
        assert_eq!(attempts, 11);
        assert!(matches!(result, Err(EvidenceError::Store(error)) if error.code == ErrorCode::ResourceBusy));

        let result = persist::<()>(|| Ok(Err(anyhow::anyhow!("fixture manifest validation error"))));
        assert!(matches!(result, Err(EvidenceError::Rejected(_))));
    }

    #[test]
    fn work_copy_evidence_manifest_marks_work_copy_executor_and_never_claims_project_tested() {
        let now = Utc::now();
        let run = DurableJobRecord {
            run_id: RunId::new_random(),
            task_id: TaskId("task_work_ev".into()),
            host_id: HostId("host_ev".into()),
            project_id: ProjectId("project_ev".into()),
            workspace_id: WorkspaceId("ws_ev".into()),
            grant_id: Some(GrantId::new_random()),
            requester_principal: "executor:default".into(),
            executor_identity: "mcp_task_submit".into(),
            operation_id: OperationId("op_work_ev".into()),
            dedup_key: "a".repeat(64),
            payload_digest: "b".repeat(64),
            state: JobState::Running,
            pid: Some(42),
            process_start_time_100ns: Some(100),
            exit_code: None,
            outcome: None,
            evidence_manifest_id: None,
            output_seq: 0,
            output_truncated: false,
            output_dir: "runs/run_ev".into(),
            created_at: now,
            updated_at: now,
        };
        let log = "test_add (tests.test_calc.CalcTests) ... ok\n\nRan 1 test in 0.001s\n\nOK\n";
        let tests = bridge_core::evidence::parse_python_unittest(log, true);
        let receipt = serde_json::json!({
            "policy_sha256": "1".repeat(64),
            "test_snapshot_unchanged": true,
            "approved_files": ["calc.py", "tests/__init__.py", "tests/test_calc.py"],
            "provenance": {
                "snapshot_before_sha256": "2".repeat(64),
                "snapshot_after_sha256": "2".repeat(64),
                "executable": "python.exe",
                "executable_sha256": "3".repeat(64),
                "argv": ["-I", "-S", "-B", "-m", "unittest", "-v", "tests.test_calc"],
                "codex_version": "0.171.0",
                "codex_sha256": "4".repeat(64),
            },
        });
        let outcome = OutcomeTriad {
            agent_outcome: Verdict::NotTested,
            execution_outcome: Verdict::Pass,
            verification_outcome: Verdict::NotTested,
            soft_denied_tools: vec![],
        };
        let mut manifest = prepare(
            &QueuedRunEvidence {
                run: &run,
                receipt: &receipt,
                policy_revision: 1,
                test_log: log,
                recipe: "python_tests_work",
                delegated: true,
                work_workspace: Some("fix-1"),
                terminal: JobState::Succeeded,
                partial_output: false,
                cleanup_confirmed: true,
                tests,
                outcome,
                exit_code: Some(0),
                started: now,
                elapsed_ms: 50,
            },
            JobState::Succeeded,
        )
        .unwrap();

        assert_eq!(manifest.authorization.executor_identity, DELEGATED_WORK_COPY_EXECUTOR);
        assert_eq!(manifest.conclusions.overall_verdict, Verdict::NotTested);
        assert_eq!(
            manifest.inputs.declared_units.get("work_copy").map(String::as_str),
            Some("_pro/work/fix-1")
        );
        assert_eq!(manifest.command.cwd, "disposable work-copy snapshot (_pro/work/fix-1)");
        assert_eq!(
            manifest.authorization.effective_scope,
            vec![
                "_pro/work/fix-1/calc.py",
                "_pro/work/fix-1/tests/__init__.py",
                "_pro/work/fix-1/tests/test_calc.py",
            ]
        );
        assert!(
            manifest.conclusions.untested_areas.iter().any(|note| {
                note.contains("_pro/work/fix-1") && note.contains("live project files were not tested")
            }),
            "{:?}",
            manifest.conclusions.untested_areas
        );
        assert!(!manifest.conclusions.claims[0].claim.contains("Verified MXC snapshot test results"));
        assert!(manifest.conclusions.claims[0].claim.contains("live project files were neither tested nor modified"));

        let dir = std::env::temp_dir().join(format!(
            "epb-work-evid-{}-{}",
            std::process::id(),
            manifest.identity.manifest_id
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (sk, pk) = load_or_create_device_signing_key(&dir).unwrap();
        seal_and_sign_manifest(&mut manifest, &sk);
        let rep = bridge_core::evidence::verify_evidence_full(&manifest, Some(&pk), None).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(rep.overall_verified, "{rep:?}");
        assert_eq!(rep.reported_verdict, Verdict::NotTested);
    }
}
