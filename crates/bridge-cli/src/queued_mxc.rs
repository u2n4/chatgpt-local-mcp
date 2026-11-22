//! Local owner handoff from durable queue admission to the existing Python MXC supervisor.
use anyhow::{Context, Result, bail, ensure};
use bridge_core::evidence::{
    compute_verification_verdict, credential_like_environment_names, delegated_workload_verdict, parse_python_unittest,
    scan_and_redact_secrets,
};
use bridge_core::files::{ScopedFiles, is_denied_secret_path, is_hidden_from_remote};
use bridge_core::jobs::authorize_delegated_queue_recipe;
use bridge_core::policy::{folder_is_grant_writable, path_is_grant_writable};
use bridge_core::state::{ProjectRow, StateStore};
use bridge_platform::windows::{WinJobObject, process_creation_time_100ns};
use bridge_types::{BridgeError, DurableJobRecord, ErrorCode, EvidenceTestsGroup, HostId, JobState, OutcomeTriad, Principal, RunId, Verdict};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::queued_mxc_evidence::{self, EvidenceError, QueuedRunEvidence};

// Keep these in sync with the Python supervisor's request and scope validation.
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_SNAPSHOT_FILES: usize = 32;
const MAX_LOG_BYTES: usize = 256 * 1024;
const MAX_CHUNK_BYTES: usize = 4096;
const WORKER_TIMEOUT_SECS: u64 = 60;
const WORKER_MAX_MEMORY_MB: u64 = 768;
const WORKER_MAX_PROCESSES: u32 = 8;
const WORKER_MAX_WORKSPACE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EffectiveRunLimits {
    timeout_secs: u64,
    memory_bytes: u64,
    max_processes: u32,
    max_output_bytes: usize,
    workspace_bytes: Option<u64>,
}

impl EffectiveRunLimits {
    fn from_grant(limits: &bridge_types::ResourceLimits) -> Result<Self, &'static str> {
        if limits.max_duration_seconds == 0 {
            return Err("INVALID_GRANT_LIMITS: max_duration_seconds must be at least 1.");
        }
        if limits.max_cpu_percent == 0 {
            return Err("INVALID_GRANT_LIMITS: max_cpu_percent must be at least 1.");
        }
        if limits.max_memory_mb == 0 {
            return Err("INVALID_GRANT_LIMITS: max_memory_mb must be at least 1.");
        }
        if limits.max_processes == 0 {
            return Err("INVALID_GRANT_LIMITS: max_processes must be at least 1.");
        }
        if limits.max_output_bytes == 0 {
            return Err("INVALID_GRANT_LIMITS: max_output_bytes must be at least 1.");
        }
        if limits.max_storage_bytes == 0 {
            return Err("INVALID_GRANT_LIMITS: max_storage_bytes must be at least 1.");
        }
        let timeout_secs = WORKER_TIMEOUT_SECS.min(limits.max_duration_seconds);
        let memory_mb = WORKER_MAX_MEMORY_MB.min(limits.max_memory_mb);
        let memory_bytes = memory_mb
            .checked_mul(1024 * 1024)
            .ok_or("INVALID_GRANT_LIMITS: max_memory_mb cannot be applied.")?;
        let max_processes = WORKER_MAX_PROCESSES.min(limits.max_processes);
        let max_output_bytes = usize::try_from((MAX_LOG_BYTES as u64).min(limits.max_output_bytes))
            .map_err(|_| "INVALID_GRANT_LIMITS: max_output_bytes cannot be applied.")?;
        let workspace_bytes = Some(WORKER_MAX_WORKSPACE_BYTES.min(limits.max_storage_bytes));
        Ok(Self {
            timeout_secs,
            memory_bytes,
            max_processes,
            max_output_bytes,
            workspace_bytes,
        })
    }

    fn for_local(timeout_secs: u64) -> Self {
        Self {
            timeout_secs,
            memory_bytes: WORKER_MAX_MEMORY_MB * 1024 * 1024,
            max_processes: WORKER_MAX_PROCESSES,
            max_output_bytes: MAX_LOG_BYTES,
            workspace_bytes: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueRequest {
    project_id: String,
    task_id: String,
    recipe: String,
    args: Vec<String>,
}

struct Recipe<'a> {
    name: &'a str,
    files: Vec<String>,
    delegated: bool,
    /// The grants and projects seen when the files were chosen; checked again at launch.
    write_scope: (u64, u64),
}

pub(crate) fn retry_busy<T>(mut operation: impl FnMut() -> Result<T, BridgeError>) -> Result<T, BridgeError> {
    for delay in [25, 50, 75, 100, 125, 150, 175, 200, 225, 250] {
        match operation() {
            Err(error) if error.code == ErrorCode::ResourceBusy => {
                std::thread::sleep(Duration::from_millis(delay));
            }
            result => return result,
        }
    }
    operation()
}

pub fn worker(
    store: &StateStore, state: &Path, host: &HostId, runtime: &Path, once: bool, allow_environment_credentials: bool,
) -> Result<()> {
    let (runtime, python) = trusted_runtime(state, runtime)?;
    let lease = OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .open(state.join("rust-queue-worker.lock"))?;
    lease.try_lock().context("A queue worker already holds this state directory's lease")?;
    sweep_delegated_raw_state(store, state, host)?;
    let reconciled = retry_busy(|| store.reconcile_delegated_queue_runs(host))?;
    if reconciled > 0 {
        eprintln!("Reconciled {reconciled} interrupted delegated run(s) to unknown.");
    }
    while let Some((run, payload)) = next_request(store, host, once)? {
        let result = process_request(store, state, host, &run, &payload, &runtime, &python, allow_environment_credentials);
        let result = match result {
            Ok(receipt) => receipt,
            Err(error) => {
                eprintln!("Queue run {} has no valid final receipt: {}", run.run_id.0,
                    scan_and_redact_secrets(&format!("{error:#}")).redacted_text);
                let record = mark_unknown_without_receipt(store, &run.run_id)?;
                json!({"run": record, "verification": "NOT_TESTED"})
            }
        };
        println!("{}", serde_json::to_string(&result)?);
        ensure!(result["run"]["state"] != "unknown", "Worker stopped after losing a verifiable run receipt");
    }
    Ok(())
}

fn next_request(store: &StateStore, host: &HostId, once: bool) -> Result<Option<(DurableJobRecord, String)>> {
    loop {
        match retry_busy(|| store.take_delegated_queue_run(host)) {
            Ok(None) if !once => std::thread::sleep(Duration::from_millis(250)),
            Err(error) if error.code == ErrorCode::ResourceBusy && !once => {
                std::thread::sleep(Duration::from_millis(250));
            }
            result => return Ok(result?),
        }
    }
}

fn process_request(
    store: &StateStore, state: &Path, host: &HostId, run: &DurableJobRecord, payload: &str,
    runtime: &Path, python: &Path, allow_environment_credentials: bool,
) -> Result<Value> {
    let run_id = &run.run_id;
    if run.state == JobState::Cancelling {
        return cancel_before_start(store, run_id);
    }
    let request: QueueRequest = match serde_json::from_str(payload) {
        Ok(request) if bridge_platform::sha256_bytes(payload.as_bytes()) == run.payload_digest => request,
        _ => return deny_request(store, run_id, "INVALID_QUEUED_REQUEST"),
    };
    if request.project_id != run.project_id.0 || request.task_id != run.task_id.0 {
        return deny_request(store, run_id, "QUEUED_REQUEST_CONTEXT_MISMATCH");
    }
    if !exportable_metadata(run, &request.args) {
        return deny_request(store, run_id, "QUEUE_METADATA_NOT_EXPORTABLE");
    }
    let files = match (request.recipe.as_str(), request.args.as_slice()) {
        ("python_tests", []) => None,
        ("python_tests", _) => return deny_request(store, run_id, "PYTHON_TESTS_DO_NOT_ACCEPT_ARGUMENTS"),
        ("powershell_script", [path]) if bridge_platform::validate_relative_path(path).is_ok()
            && path.to_ascii_lowercase().ends_with(".ps1") => Some(vec![path.clone()]),
        ("powershell_script", [_, _, ..]) => return deny_request(store, run_id, "POWERSHELL_SCRIPT_ARGUMENTS_UNSUPPORTED"),
        ("powershell_script", _) => return deny_request(store, run_id, "INVALID_POWERSHELL_SCRIPT_PATH"),
        _ => return deny_request(store, run_id, "UNKNOWN_QUEUED_RECIPE"),
    };
    let authorized = match retry_busy(|| authorize_delegated_queue_recipe(store, host, run, &request.recipe)) {
        Ok(authorized) => authorized,
        Err(error) => return reject_authorization(store, run_id, error),
    };
    let (project, reviewer_paths, write_scope, grant_limits) =
        (authorized.project, authorized.requester_writable, authorized.write_scope, authorized.limits);
    let limits = match EffectiveRunLimits::from_grant(&grant_limits) {
        Ok(limits) => limits,
        Err(reason) => return deny_request(store, run_id, reason),
    };
    if !allow_environment_credentials && let Some(reason) = environment_exposure() {
        return deny_request(store, run_id, &reason);
    }
    // The requester can create files inside its grant's writable paths. Nothing from there may
    // execute: a named script is refused, and discovered test files leave them out.
    let reviewer_file = |path: &String| path_is_grant_writable(path, &reviewer_paths);
    if files.as_ref().is_some_and(|files| files.iter().any(reviewer_file)) {
        return deny_request(store, run_id, "SCRIPT_INSIDE_REQUESTER_WRITABLE_PATH");
    }
    if let Err(error) = verify_project_roots(&project, state, runtime) {
        eprintln!("Queue run {} rejected an unsafe project root: {error:#}", run_id.0);
        return deny_request(store, run_id, "QUEUE_PROJECT_ROOT_UNSAFE");
    }
    let files = match ScopedFiles::new(Path::new(&project.root), Some(project.root_identity.clone()))
        .and_then(|source| files.map_or_else(|| discover_python_scope(&source, &reviewer_paths), Ok))
        .and_then(|files| check_snapshot_paths(files, true))
    {
        Ok(files) => files,
        Err(error) => return reject_authorization(store, run_id, error),
    };
    if !exportable_metadata(run, &files) {
        return deny_request(store, run_id, "QUEUE_METADATA_NOT_EXPORTABLE");
    }
    supervise(store, state, run, runtime, python, &project,
        Recipe { name: &request.recipe, files, delegated: true, write_scope }, limits)
}

/// Why a run for a remote requester must not start: the sandbox clears the process environment
/// but cannot stop a run from reading the variables Windows keeps in the registry, and what a run
/// prints goes back to the requester. The count is reported, never the names. The check is made
/// once, before the files are chosen; a variable added while the run is prepared is not seen.
fn environment_exposure() -> Option<String> {
    let Some(entries) = bridge_platform::windows::persistent_environment() else {
        return Some("PERSISTENT_ENVIRONMENT_UNREADABLE: the user and machine environment could not be checked for \
            credentials, so the run was not started.".into());
    };
    let found = credential_like_environment_names(&entries).len();
    (found > 0).then(|| format!(
        "PERSISTENT_ENVIRONMENT_HOLDS_CREDENTIALS: {found} entries in the user or machine environment look like \
        credentials, and a run can read them. The owner can list them with `edge-bridge environment-check`, then move \
        them out of the persistent environment or start the worker with --allow-environment-credentials."))
}

fn exportable_metadata(run: &DurableJobRecord, files: &[String]) -> bool {
    [&run.task_id.0, &run.operation_id.0, &run.requester_principal].into_iter().chain(files)
        .all(|value| scan_and_redact_secrets(value).clean)
}

/// Collect the test inputs: `.py` and `.json` files up to six folders deep, at most 200 entries.
/// A folder the requester can write into is neither entered nor counted, so nothing placed there
/// can run or use up the budget.
fn discover_python_scope(source: &ScopedFiles, requester_writable: &[String]) -> Result<Vec<String>, BridgeError> {
    let mut files = Vec::new();
    let mut seen = 0;
    let mut pending = vec![(".".to_string(), 1)];
    while let Some((folder, depth)) = pending.pop() {
        // A folder whose path is not a valid project path (too long, or a name Windows treats
        // specially) cannot hold a file with a valid one, so it is passed over. Any other
        // failure to list a folder stops the run.
        if folder != "." && bridge_platform::validate_relative_path(&folder).is_err() {
            continue;
        }
        let mut cursor = 0;
        loop {
            let (entries, next) = source.list(&folder, false, 1, true, cursor, 100)?;
            for entry in entries {
                let parts: Vec<String> = entry.path.split('/').map(str::to_owned).collect();
                if is_hidden_from_remote(&parts) {
                    continue;
                }
                let is_folder = entry.kind == "dir";
                let excluded = if is_folder {
                    folder_is_grant_writable(&entry.path, requester_writable)
                } else {
                    path_is_grant_writable(&entry.path, requester_writable)
                };
                if excluded {
                    continue;
                }
                seen += 1;
                if seen > 200 {
                    return Err(BridgeError::new(ErrorCode::ResourceBudgetExceeded,
                        "Python discovery exceeded 200 project entries.", bridge_types::OriginLayer::JobRunner));
                }
                let hidden = entry.path.split('/').any(|part| part.starts_with('.'));
                if is_folder {
                    if depth < 6 {
                        pending.push((entry.path, depth + 1));
                    }
                } else if !hidden && (entry.path.ends_with(".py") || entry.path.ends_with(".json")) {
                    files.push(entry.path);
                }
            }
            match next {
                Some(more) => cursor = more,
                None => break,
            }
        }
    }
    files.sort();
    Ok(files)
}

/// A run for a remote requester may not copy what that requester may not read.
fn check_snapshot_paths(files: Vec<String>, delegated: bool) -> Result<Vec<String>, BridgeError> {
    for path in &files {
        let parts = bridge_platform::validate_relative_path(path)?;
        if if delegated { is_hidden_from_remote(&parts) } else { is_denied_secret_path(&parts) } {
            return Err(BridgeError::new(ErrorCode::BridgePolicyDenied,
                "Access to a protected snapshot source path was denied.", bridge_types::OriginLayer::FileService));
        }
    }
    Ok(files)
}

fn reject_authorization(store: &StateStore, run_id: &RunId, error: BridgeError) -> Result<Value> {
    match error.code {
        ErrorCode::BridgePolicyDenied | ErrorCode::StalePrecondition | ErrorCode::NotFound
        | ErrorCode::ProjectNotGranted | ErrorCode::InvalidArgument | ErrorCode::AuthRequired
        | ErrorCode::UnsupportedPathType | ErrorCode::FileNotFound => {
            deny_request(store, run_id, &error.to_string())
        }
        ErrorCode::ResourceBudgetExceeded => deny_request(store, run_id, "RESOURCE_BUDGET_EXCEEDED"),
        _ => Err(error.into()),
    }
}

fn deny_request(store: &StateStore, run_id: &RunId, reason: &str) -> Result<Value> {
    let reason = scan_and_redact_secrets(reason).redacted_text;
    let outcome = OutcomeTriad {
        agent_outcome: Verdict::NotTested,
        execution_outcome: Verdict::Blocked,
        verification_outcome: Verdict::Blocked,
        soft_denied_tools: vec![],
    };
    append_output(store, run_id, &[("stderr", &reason)], false)?;
    let record = finish(store, run_id, JobState::Failed, None, &outcome)?;
    let mut record = serde_json::to_value(record)?;
    for field in ["task_id", "operation_id", "requester_principal"] {
        if let Some(value) = record[field].as_str() {
            record[field] = json!(scan_and_redact_secrets(value).redacted_text);
        }
    }
    Ok(json!({"run": record, "failure_code": reason, "verification": "BLOCKED"}))
}

fn mark_unknown_without_receipt(store: &StateStore, run_id: &RunId) -> Result<DurableJobRecord> {
    let current = retry_busy(|| store.get_durable_run(&run_id.0))?.context("Admitted run disappeared")?;
    if matches!(current.state, JobState::Admitted | JobState::Running | JobState::Cancelling) {
        return Ok(retry_busy(|| store.transition_durable_run(&run_id.0, JobState::Unknown, None, None, None, None, None))?);
    }
    Ok(current)
}

pub fn run(
    store: &StateStore,
    state: &Path,
    host: &HostId,
    run_id: RunId,
    runtime: &Path,
    files: Vec<String>,
    timeout_secs: u64,
) -> Result<Value> {
    let existing = retry_busy(|| store.get_durable_run(&run_id.0))?.context("Queued run not found")?;
    let project = store.get_project(&existing.project_id.0, &Principal::Local)?;
    let (runtime, python) = trusted_runtime(state, runtime)?;
    verify_project_roots(&project, state, &runtime)?;
    ensure!((2..=32).contains(&files.len()), "Supply between two and 32 approved test files");
    let files = check_snapshot_paths(files, false)?;
    retry_busy(|| store.admit_local_python_tests(&run_id, host))?;
    let result = supervise(store, state, &existing, &runtime, &python, &project,
        Recipe { name: "python_tests", files, delegated: false, write_scope: (0, 0) },
        EffectiveRunLimits::for_local(timeout_secs));
    if result.is_err() {
        mark_unknown_without_receipt(store, &run_id)?;
    }
    result
}

fn trusted_runtime(state: &Path, runtime: &Path) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let runtime = std::path::absolute(runtime)?;
    ScopedFiles::new(&runtime, None)?;
    ScopedFiles::new(state, None)?;
    let python = runtime.join(".venv").join("Scripts").join("python.exe");
    ensure!(python.is_file() && runtime.join("edge_bridge").join("runner.py").is_file(),
        "The trusted checkout must contain the Bridge Python runtime");
    Ok((runtime, python))
}

fn verify_project_roots(project: &ProjectRow, state: &Path, runtime: &Path) -> Result<()> {
    let root = Path::new(&project.root);
    ScopedFiles::new(root, Some(project.root_identity.clone()))?;
    let canonical_project = fs::canonicalize(root)?;
    ensure!(!paths_overlap(&canonical_project, &fs::canonicalize(runtime)?)
        && !paths_overlap(&canonical_project, &fs::canonicalize(state)?),
        "The trusted runtime and controller state must be outside the selected project");
    Ok(())
}

fn paths_overlap(a: &Path, b: &Path) -> bool {
    // Native path components avoid matching sibling names with common text prefixes.
    let a = a.to_string_lossy().to_lowercase();
    let b = b.to_string_lossy().to_lowercase();
    Path::new(&a).starts_with(&b) || Path::new(&b).starts_with(&a)
}

#[allow(clippy::too_many_arguments)]
fn supervise(
    store: &StateStore, state: &Path, run: &DurableJobRecord, runtime: &Path, python: &Path,
    project: &ProjectRow, recipe: Recipe<'_>, limits: EffectiveRunLimits,
) -> Result<Value> {
    let run_id = &run.run_id;
    let runs = state.join("runs");
    fs::create_dir_all(&runs)?;
    ScopedFiles::new(&runs, None)?;
    let output = runs.join(&run_id.0);
    fs::create_dir(&output)?;
    let job = WinJobObject::new(1024, 12)?;
    let result = supervise_in_job(store, state, run, runtime, python, project, recipe, limits, &output, &job);
    if result.is_err() {
        if job.active_processes()? != 0 {
            job.terminate_tree(1)?;
            wait_for_empty(&job)?;
        }
        cleanup_raw_state(&output);
    }
    result
}

/// Replace the host location of the job in captured output. A traceback prints the
/// directory the workload ran in, which names the owner's account and state directory
/// and is of no use to a remote reader. The workspace becomes `<workspace>` and anything
/// else under the run directory `<run>`, with either path separator.
fn hide_host_paths(text: &str, workspace: &Path, run_dir: &Path) -> String {
    let mut out = text.to_string();
    for (path, label) in [(workspace, "<workspace>"), (run_dir, "<run>")] {
        let native = path.to_string_lossy();
        let native = native.strip_prefix(r"\\?\").unwrap_or(&native);
        for form in [native.to_string(), native.replace('\\', "/"), native.replace('\\', r"\\")] {
            if !form.is_empty() {
                out = out.replace(&form, label);
            }
        }
    }
    out
}

fn frame_request(request: &Value) -> Result<Option<Vec<u8>>> {
    let mut bytes = serde_json::to_vec(request)?;
    if bytes.len() >= MAX_REQUEST_BYTES {
        return Ok(None);
    }
    bytes.push(b'\n');
    Ok(Some(bytes))
}

#[allow(clippy::too_many_arguments)]
fn build_supervisor_request(
    backend_state: &Path,
    project: &ProjectRow,
    recipe: &Recipe<'_>,
    cancel_path: &Path,
    run_id: &RunId,
    launch_ready: &Path,
    limits: EffectiveRunLimits,
) -> Value {
    json!({
        "state": backend_state, "root": project.root, "root_identity": project.root_identity,
        "recipe": recipe.name, "files": recipe.files, "cancel": cancel_path,
        "run_id": run_id.0, "timeout_seconds": limits.timeout_secs, "launch_ready": launch_ready,
        "delegated": recipe.delegated,
        "max_memory_bytes": limits.memory_bytes,
        "max_processes": limits.max_processes,
        "max_output_bytes": limits.max_output_bytes,
        "workspace_limit": limits.workspace_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
fn supervise_in_job(
    store: &StateStore, state: &Path, run: &DurableJobRecord, runtime: &Path, python: &Path,
    project: &ProjectRow, recipe: Recipe<'_>, limits: EffectiveRunLimits, output: &Path, job: &WinJobObject,
) -> Result<Value> {
    let run_id = &run.run_id;
    let backend_state = output.join("mxc-state");
    let receipt_path = output.join("mxc-receipt.json");
    let ready_path = output.join("mxc-supervisor.pid");
    let cancel_path = output.join("mxc-cancel");
    let launch_ready = output.join("mxc-launch-ready");
    if recipe.files.len() > MAX_SNAPSHOT_FILES {
        return deny_request(store, run_id, "RESOURCE_BUDGET_EXCEEDED");
    }
    let request = build_supervisor_request(&backend_state, project, &recipe, &cancel_path, run_id, &launch_ready, limits);
    let Some(request) = frame_request(&request)? else {
        return deny_request(store, run_id, "RESOURCE_BUDGET_EXCEEDED");
    };
    let mut command = Command::new(python);
    command.args(["-I", "-B", "-c", include_str!("queued_mxc.py")])
        .arg(runtime).arg(&ready_path).current_dir(runtime).env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::from(File::create_new(&receipt_path)?))
        .stderr(Stdio::from(File::create_new(output.join("mxc-supervisor.stderr.log"))?));
    for name in ["SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "USERPROFILE", "APPDATA",
        "LOCALAPPDATA", "PROGRAMDATA", "ProgramFiles", "USERNAME", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "OS"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let system_root = std::env::var_os("SYSTEMROOT").context("SYSTEMROOT is missing")?;
    command.env("PATH", Path::new(&system_root).join("System32"));
    let mut helper = command.spawn().context("Failed to start the trusted Python supervisor")?;
    if let Err(error) = job.assign_pid(helper.id()) {
        helper.kill()?;
        helper.wait()?;
        return Err(error.into());
    }
    let ready_deadline = Instant::now() + Duration::from_secs(8);
    let supervisor_pid = loop {
        if let Some(pid) = fs::read_to_string(&ready_path).ok().and_then(|value| value.parse::<u32>().ok()) {
            break pid;
        }
        ensure!(helper.try_wait()?.is_none() && Instant::now() < ready_deadline,
            "The Python supervisor did not complete its readiness handshake");
        std::thread::sleep(Duration::from_millis(30));
    };
    // Windows venv launchers can start the interpreter before they themselves are
    // assigned. Verify the real interpreter is owned while it still waits on stdin.
    if !job.contains_pid(supervisor_pid)? {
        job.assign_pid(supervisor_pid)?;
    }
    ensure!(job.contains_pid(supervisor_pid)?, "Supervisor is outside its Job Object");
    let process_start = process_creation_time_100ns(supervisor_pid);
    let current = retry_busy(|| store.get_durable_run(&run_id.0))?.context("Admitted run disappeared")?;
    if current.state == JobState::Cancelling {
        stop_helper(job, &mut helper)?;
        cleanup_raw_state(output);
        return cancel_before_start(store, run_id);
    }
    ensure!(current.state == JobState::Admitted, "Run left preparation before supervisor handoff");
    let started = Utc::now();
    let start = Instant::now();
    let mut input = Some(helper.stdin.take().context("Missing supervisor input pipe")?);
    if let Err(error) = input.as_mut().unwrap().write_all(&request) {
        return if error.kind() == ErrorKind::BrokenPipe {
            fail_supervisor(store, run_id, output, job, &mut helper)
        } else {
            Err(error.into())
        };
    }

    let mut launch_authorized = None;
    let mut cancel_deadline = None;
    let status = loop {
        let current = retry_busy(|| store.get_durable_run(&run_id.0))?.context("Running job disappeared")?.state;
        if current == JobState::Cancelling && cancel_deadline.is_none() {
            File::create_new(&cancel_path)?;
            cancel_deadline = Some(Instant::now() + Duration::from_secs(8));
        }
        if cancel_deadline.is_some_and(|deadline| Instant::now() > deadline)
            || start.elapsed() > Duration::from_secs(limits.timeout_secs.saturating_add(15))
        {
            drop(input.take());
            stop_helper(job, &mut helper)?;
            cleanup_raw_state(output);
            if current == JobState::Admitted {
                return deny_request(store, run_id, "QUEUE_PREPARATION_TIMED_OUT");
            }
            let terminal = if current == JobState::Cancelling { JobState::Cancelled } else { JobState::TimedOut };
            let verdict = if terminal == JobState::Cancelled { Verdict::Cancelled } else { Verdict::Fail };
            let record = finish(store, run_id, terminal, None, &unverified_outcome(verdict))?;
            return Ok(json!({"run": record, "verified": false, "verification": "NOT_TESTED"}));
        }
        ensure!(matches!(current, JobState::Admitted | JobState::Running | JobState::Cancelling),
            "Run left worker supervision unexpectedly");
        if let Some(status) = helper.try_wait()? {
            break status;
        }
        if launch_ready.try_exists()? && let Some(mut pipe) = input.take() {
            // The helper is blocked at CreateProcessW with the pinned image locked.
            // Commit the launch decision before granting its single-use reply.
            let authorized = authorize_launch(store, run, project, recipe.delegated.then_some(recipe.write_scope), supervisor_pid, process_start)?;
            launch_authorized = Some(authorized);
            if authorized && let Err(error) = pipe.write_all(b"start\n") {
                return if error.kind() == ErrorKind::BrokenPipe {
                    fail_supervisor(store, run_id, output, job, &mut helper)
                } else {
                    Err(error.into())
                };
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    if !status.success() && launch_authorized != Some(true) {
        return fail_supervisor(store, run_id, output, job, &mut helper);
    }
    ensure!(status.success(), "MXC supervisor exited without a valid result: {status}");
    wait_for_empty(job)?;
    let running = retry_busy(|| store.get_durable_run(&run_id.0))?.context("Queue run disappeared after supervisor exit")?;
    if launch_authorized == Some(false) {
        cleanup_raw_state(output);
        return if running.state == JobState::Cancelling {
            cancel_before_start(store, run_id)
        } else {
            deny_request(store, run_id, "QUEUE_GRANT_OR_STATE_CHANGED_BEFORE_START")
        };
    }

    let mut receipt: Value = serde_json::from_reader(File::open(&receipt_path)?.take(32 * 1024))?;
    if let Some(diagnostic) = receipt["diagnostic"].as_str() {
        receipt["diagnostic"] = json!(scan_and_redact_secrets(diagnostic).redacted_text);
    }
    let backend_status = receipt["status"].as_str().context("Supervisor receipt has no status")?;
    let exit_code = receipt["exit_code"].as_i64().and_then(|code| {
        i32::try_from(code).ok().or_else(|| u32::try_from(code).ok().map(|raw| raw as i32))
    });
    let verified = receipt["mxc_verified"] == true;
    let mut truncated = receipt["failure_code"] == "JOB_LOG_LIMIT_EXCEEDED";
    let mut log = String::new();
    if let Some(id) = receipt["job_id"].as_str() {
        ensure!(id.strip_prefix("job_").is_some_and(|suffix| suffix.len() == 32
            && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())), "Invalid backend job ID");
        let log_path = backend_state.join("jobs").join(id).join("control").join("job.log");
        match File::open(log_path) {
            Ok(file) => {
                let max_log_bytes = limits.max_output_bytes;
                let mut raw = Vec::new();
                file.take((max_log_bytes + 1) as u64).read_to_end(&mut raw)?;
                truncated |= raw.len() > max_log_bytes;
                // The capture limit may split a credential. Discard the last
                // incomplete line before redaction when any text was lost.
                if truncated {
                    raw.truncate(raw[..raw.len().min(max_log_bytes)].iter().rposition(|b| *b == b'\n')
                        .map_or(0, |index| index + 1));
                }
                log = scan_and_redact_secrets(&String::from_utf8_lossy(&raw)).redacted_text;
                log = hide_host_paths(&log, &backend_state.join("jobs").join(id).join("workspace"), output);
                if let Some((offset, _)) = log.match_indices("-----BEGIN ")
                    .find(|(start, _)| log[*start..].lines().next().is_some_and(|line| line.ends_with("PRIVATE KEY-----")))
                {
                    log.truncate(offset);
                    log.push_str("[REDACTED:incomplete_pem_private_key]");
                }
                if log.len() > max_log_bytes {
                    truncated = true;
                    log.truncate(log.as_bytes()[..max_log_bytes].iter().rposition(|b| *b == b'\n')
                        .map_or(0, |index| index + 1));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && backend_status != "succeeded" => {}
            Err(error) => return Err(error.into()),
        }
    }
    let cleanup_confirmed = cleanup_raw_state(output);
    let failure_reason = receipt["failure_code"].as_str().map(|reason| scan_and_redact_secrets(reason).redacted_text);
    let mut output_streams = vec![("combined", log.as_str())];
    if let Some(reason) = failure_reason.as_deref() {
        output_streams.push(("stderr", reason));
    }
    let workload_started = launch_authorized == Some(true) && receipt["workload_started"] == true;
    let failure_reported = !receipt["failure_code"].is_null();
    let fresh_capture = verified && !failure_reported && !truncated;
    let (parsed, tests) = if recipe.name == "python_tests" {
        let parsed = parse_python_unittest(&log, fresh_capture);
        let counts = (parsed.parser_name != "none").then(|| json!({
            "executed": parsed.executed, "passed": parsed.passed, "failed": parsed.failed, "skipped": parsed.skipped,
        }));
        (parsed, counts)
    } else {
        (EvidenceTestsGroup {
            parser_name: "none".into(), parser_version: "none".into(), discovered: 0, executed: 0,
            passed: 0, failed: 0, skipped: 0, results_artifact_sha256: bridge_platform::sha256_bytes(log.as_bytes()),
            fresh_for_run: fresh_capture, cases: vec![],
        }, None)
    };
    let test_verdict = if verified {
        compute_verification_verdict(&parsed, exit_code, false, false, false,
            receipt["test_snapshot_unchanged"] != true)
    } else {
        Verdict::Blocked
    };
    let terminal = match backend_status {
        "unknown_after_restart" => JobState::Unknown,
        "timed_out" if running.state == JobState::Admitted => JobState::Failed,
        "timed_out" => JobState::TimedOut,
        "cancelled" => JobState::Cancelled,
        "succeeded" if workload_started && verified && !failure_reported && !truncated && exit_code == Some(0)
            && (test_verdict == Verdict::Pass || recipe.name == "powershell_script") => JobState::Succeeded,
        "succeeded" | "failed" => JobState::Failed,
        _ => bail!("MXC supervisor returned an invalid terminal state"),
    };
    let verification = match terminal {
        JobState::Unknown => Verdict::NotTested,
        JobState::Cancelled => Verdict::Cancelled,
        JobState::TimedOut => Verdict::Fail,
        _ if recipe.delegated && verified => delegated_workload_verdict(false, false),
        _ => test_verdict,
    };
    let outcome = OutcomeTriad {
        agent_outcome: Verdict::NotTested,
        execution_outcome: match terminal {
            JobState::Unknown | JobState::Cancelled | JobState::TimedOut => verification,
            _ if !verified => Verdict::Blocked,
            _ if exit_code == Some(0) && fresh_capture => Verdict::Pass,
            _ => Verdict::Fail,
        },
        verification_outcome: verification,
        soft_denied_tools: vec![],
    };
    append_output(store, run_id, &output_streams, truncated)?;
    let (record, manifest_path) = if workload_started && verified && receipt["provenance"].is_object()
        && terminal != JobState::Unknown
    {
        match queued_mxc_evidence::finalize(store, state, output, QueuedRunEvidence {
            run: &running, receipt: &receipt,
            policy_revision: project.policy_revision, test_log: &log, recipe: recipe.name, delegated: recipe.delegated,
            terminal, partial_output: truncated, cleanup_confirmed,
            tests: parsed, outcome, exit_code, started, elapsed_ms: start.elapsed().as_millis() as u64,
        }) {
            Ok((record, exported)) => (record, exported.then(|| output.join(queued_mxc_evidence::MANIFEST_NAME))),
            Err(EvidenceError::Rejected(error)) if recipe.delegated => {
                eprintln!("Queue run {} evidence rejected: {}", run_id.0,
                    scan_and_redact_secrets(&format!("{error:#}")).redacted_text);
                let code = "QUEUE_EVIDENCE_REJECTED";
                append_output(store, run_id, &[("stderr", code)], truncated)?;
                let failed = OutcomeTriad {
                    verification_outcome: Verdict::NotTested,
                    ..unverified_outcome(Verdict::Fail)
                };
                let record = finish(store, run_id, JobState::Failed, exit_code, &failed)?;
                return Ok(json!({"run": record, "failure_code": code, "verification": "NOT_TESTED"}));
            }
            Err(EvidenceError::Rejected(error) | EvidenceError::Prepare(error)) => return Err(error),
            Err(EvidenceError::Store(error)) => return Err(anyhow::Error::new(error).context("Queue evidence store write failed")),
        }
    } else {
        ensure!(terminal != JobState::Succeeded, "Verified success requires sealed MXC test evidence");
        (finish(store, run_id, terminal, exit_code, &outcome)?, None)
    };
    let verification = if record.state == JobState::Cancelled { json!("NOT_TESTED") } else { json!(verification) };
    Ok(json!({"run": record, "mxc_receipt": receipt, "test_counts": tests, "evidence_manifest_path": manifest_path,
        "workload_report": recipe.delegated.then(|| json!({"source": "workload", "exit_code": exit_code, "test_counts": tests})),
        "verification": verification}))
}

fn authorize_launch(
    store: &StateStore, run: &DurableJobRecord, project: &ProjectRow, delegated: Option<(u64, u64)>,
    pid: u32, process_start: Option<u64>,
) -> Result<bool> {
    if let Some(write_scope) = delegated {
        return Ok(retry_busy(|| store.start_delegated_queue_run(run, project.policy_revision, write_scope, pid, process_start))?);
    }
    match retry_busy(|| store.transition_durable_run_from(&run.run_id.0, Some(JobState::Admitted), JobState::Running,
        Some(pid), process_start, None, None, None))
    {
        Ok(_) => Ok(true),
        Err(error) if error.code == ErrorCode::VersionConflict => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn sweep_delegated_raw_state(store: &StateStore, state: &Path, host: &HostId) -> Result<()> {
    let runs = state.join("runs");
    if !runs.try_exists()? {
        return Ok(());
    }
    ScopedFiles::new(&runs, None)?;
    for entry in fs::read_dir(runs)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name.to_str() else { continue };
        if !id.strip_prefix("run_").is_some_and(|suffix| suffix.len() == 32
            && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())) {
            continue;
        }
        let Some(run) = retry_busy(|| store.get_durable_run(id))? else { continue };
        if run.host_id == *host && run.executor_identity == "mcp_task_submit"
            && run.requester_principal.starts_with("executor:") && ScopedFiles::new(&entry.path(), None).is_ok() {
            // The old worker held the exclusive lease and its kill-on-close job handle.
            // Windows can still be releasing files. Leave them for the next sweep if busy.
            cleanup_raw_state(&entry.path());
        }
    }
    Ok(())
}

fn cleanup_raw_state(output: &Path) -> bool {
    let mut confirmed = true;
    for name in ["mxc-state", "mxc-receipt.json", "mxc-supervisor.stderr.log", "mxc-supervisor.pid",
        "mxc-cancel", "mxc-launch-ready"] {
        let path = output.join(name);
        // Rust's Windows remove_dir_all removes junctions themselves without following them.
        let result = if name == "mxc-state" { fs::remove_dir_all(&path) } else { fs::remove_file(&path) };
        if let Err(error) = result
            && error.kind() != std::io::ErrorKind::NotFound
        {
            confirmed = false;
            eprintln!("Queue raw cleanup deferred for {} ({name}): {error}", output.file_name().unwrap_or_default().to_string_lossy());
        }
    }
    confirmed
}

fn append_output(store: &StateStore, run_id: &RunId, streams: &[(&str, &str)], truncated: bool) -> Result<()> {
    let mut chunks = Vec::new();
    for &(stream, mut remaining) in streams {
        if truncated && remaining.is_empty() && stream == "combined" {
            chunks.push((stream, ""));
        }
        while !remaining.is_empty() {
            let mut length = remaining.len().min(MAX_CHUNK_BYTES);
            while !remaining.is_char_boundary(length) {
                length -= 1;
            }
            let (chunk, tail) = remaining.split_at(length);
            chunks.push((stream, chunk));
            remaining = tail;
        }
    }
    if !chunks.is_empty() {
        retry_busy(|| store.append_run_output_batch(&run_id.0, &chunks, truncated))?;
    }
    Ok(())
}

fn unverified_outcome(verdict: Verdict) -> OutcomeTriad {
    OutcomeTriad { agent_outcome: Verdict::NotTested, execution_outcome: verdict,
        verification_outcome: verdict, soft_denied_tools: vec![] }
}

fn cancel_before_start(store: &StateStore, run_id: &RunId) -> Result<Value> {
    let record = finish(store, run_id, JobState::Cancelled, None, &unverified_outcome(Verdict::Cancelled))?;
    Ok(json!({"run": record, "verification": "NOT_TESTED"}))
}

fn finish(store: &StateStore, run_id: &RunId, terminal: JobState, exit_code: Option<i32>,
    outcome: &OutcomeTriad) -> Result<DurableJobRecord> {
    let current = retry_busy(|| store.get_durable_run(&run_id.0))?.context("Queue run disappeared before finalization")?;
    if current.state == JobState::Cancelling && !matches!(terminal, JobState::Cancelled | JobState::Unknown) {
        return finish(store, run_id, JobState::Cancelled, exit_code, &unverified_outcome(Verdict::Cancelled));
    }
    match retry_busy(|| store.transition_durable_run_from(&run_id.0, Some(current.state), terminal, None, None,
        exit_code, Some(outcome), None))
    {
        Err(error) if error.code == ErrorCode::VersionConflict && matches!(current.state, JobState::Admitted | JobState::Running)
            && retry_busy(|| store.get_durable_run(&run_id.0))?.is_some_and(|run| run.state == JobState::Cancelling) => {
            finish(store, run_id, terminal, exit_code, outcome)
        }
        result => Ok(result?),
    }
}

fn fail_supervisor(store: &StateStore, run_id: &RunId, output: &Path, job: &WinJobObject, helper: &mut Child) -> Result<Value> {
    stop_helper(job, helper)?;
    cleanup_raw_state(output);
    deny_request(store, run_id, "QUEUE_SUPERVISOR_EXITED_EARLY")
}

fn stop_helper(job: &WinJobObject, helper: &mut Child) -> Result<()> {
    if job.active_processes()? != 0 {
        job.terminate_tree(1)?;
        wait_for_empty(job)?;
    }
    helper.wait()?;
    Ok(())
}

fn wait_for_empty(job: &WinJobObject) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while job.active_processes()? != 0 {
        if Instant::now() >= deadline {
            bail!("Windows did not confirm that the supervised process tree exited");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_output_does_not_name_the_host_directories() {
        let run = Path::new(r"C:\Users\owner\state\runs\run_1");
        let workspace = run.join("mxc-state").join("jobs").join("job_1").join("workspace");
        let text = concat!(
            "  File \"C:\\Users\\owner\\state\\runs\\run_1\\mxc-state\\jobs\\job_1\\workspace\\tests\\test_a.py\", line 3\n",
            "cwd C:/Users/owner/state/runs/run_1/mxc-state/jobs/job_1/workspace\n",
            "json \"C:\\\\Users\\\\owner\\\\state\\\\runs\\\\run_1\\\\mxc-state\\\\jobs\\\\job_1\\\\control\"\n",
            "other C:\\Users\\owner\\state\\runs\\run_1\\mxc-state\n",
            "unrelated C:\\Windows\\System32\n",
        );
        assert_eq!(
            hide_host_paths(text, &workspace, run),
            concat!(
                "  File \"<workspace>\\tests\\test_a.py\", line 3\n",
                "cwd <workspace>\n",
                "json \"<run>\\\\mxc-state\\\\jobs\\\\job_1\\\\control\"\n",
                "other <run>\\mxc-state\n",
                "unrelated C:\\Windows\\System32\n",
            )
        );
    }

    #[test]
    fn supervisor_request_includes_newline_in_byte_budget() {
        let sample = json!("x".repeat(MAX_REQUEST_BYTES - 3));
        let line = frame_request(&sample).unwrap().unwrap();
        assert_eq!(line.len(), MAX_REQUEST_BYTES);
        assert_eq!(line.last(), Some(&b'\n'));
        let too_long = json!("x".repeat(MAX_REQUEST_BYTES - 2));
        assert!(frame_request(&too_long).unwrap().is_none());
    }

    #[test]
    fn python_discovery_skips_root_auth_json_and_other_remote_hidden_files() {
        struct TempCleanup(std::path::PathBuf);
        impl Drop for TempCleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let temp = TempCleanup(std::env::temp_dir().join(format!(
            "eb_queued_mxc_test_{}",
            uuid::Uuid::new_v4().simple()
        )));
        let root = temp.0.join("project");
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::create_dir_all(root.join("kubeconfig")).unwrap();
        fs::create_dir_all(root.join("_pro").join("reports")).unwrap();
        fs::write(root.join("tests").join("__init__.py"), "").unwrap();
        fs::write(root.join("tests").join("test_ok.py"), "import unittest\n").unwrap();
        fs::write(root.join("app.py"), "VALUE = 1\n").unwrap();
        fs::write(root.join("config.json"), "{\"ok\": true}\n").unwrap();
        // Credential-style and remote-hidden files must be skipped, not abort discovery.
        fs::write(root.join("auth.json"), "{\"token\": \"dummy\"}\n").unwrap();
        fs::write(root.join("sub").join("AUTH.JSON"), "{\"token\": \"dummy\"}\n").unwrap();
        fs::write(root.join("auth.yaml"), "token: dummy\n").unwrap();
        fs::write(root.join("credentials.json"), "{\"secret\": \"dummy\"}\n").unwrap();
        fs::write(root.join("secrets.json"), "{\"secret\": \"dummy\"}\n").unwrap();
        fs::write(root.join(".env"), "SECRET=dummy\n").unwrap();
        fs::write(root.join("kubeconfig").join("nested.py"), "X = 1\n").unwrap();
        fs::write(root.join(".edge-bridge-tmp-1234.json"), "{}\n").unwrap();
        fs::write(root.join("_pro").join("reports").join("note.json"), "{}\n").unwrap();

        let expected = vec![
            "app.py".to_string(),
            "config.json".to_string(),
            "tests/__init__.py".to_string(),
            "tests/test_ok.py".to_string(),
        ];
        let reviewer_paths = vec![bridge_core::policy::PRO_REVIEW_WRITABLE_PATH.to_owned()];

        // Both remote_read and regular ScopedFiles skip remote-hidden paths and pass check_snapshot_paths.
        let remote_source = ScopedFiles::new_remote_read(&root, None).unwrap();
        let discovered_remote = discover_python_scope(&remote_source, &reviewer_paths).unwrap();
        assert_eq!(discovered_remote, expected);
        assert_eq!(check_snapshot_paths(discovered_remote, true).unwrap(), expected);

        let local_source = ScopedFiles::new(&root, None).unwrap();
        let discovered_local = discover_python_scope(&local_source, &reviewer_paths).unwrap();
        assert_eq!(discovered_local, expected);
        assert_eq!(check_snapshot_paths(discovered_local, true).unwrap(), expected);

        // Explicit snapshot checks still refuse remote-hidden files (e.g. a named script path).
        let explicit_err = check_snapshot_paths(vec!["auth.json".into()], true).unwrap_err();
        assert_eq!(explicit_err.code, ErrorCode::BridgePolicyDenied);
    }

    fn make_delegated_run_fixture(
        root: &Path,
        limits: bridge_types::ResourceLimits,
    ) -> (StateStore, HostId, DurableJobRecord, String) {
        let store = StateStore::open(root.join("state").join("state.sqlite3")).unwrap();
        let project_dir = root.join("project");
        fs::create_dir_all(project_dir.join("tests")).unwrap();
        fs::write(project_dir.join("tests").join("__init__.py"), "").unwrap();
        fs::write(project_dir.join("tests").join("test_ok.py"), "import unittest\n").unwrap();
        let root_id = ScopedFiles::new(&project_dir, None).unwrap().current_root_identity().unwrap();
        let project = store.register_project(&project_dir, "LimitFixture", &root_id).unwrap();
        let host = HostId::parse("host_limit_test").unwrap();
        let now = Utc::now();
        let grant = bridge_types::TaskGrantEnvelope {
            grant_id: bridge_types::GrantId::new_random(),
            requester_principal: "executor:default".into(),
            granting_owner: "local_owner".into(),
            host_id: host.clone(),
            project_id: bridge_types::ProjectId(project.project_id.clone()),
            workspace_id: bridge_types::WorkspaceId::new_random(),
            baseline_hash: "sha256:0000".into(),
            policy_revision: project.policy_revision,
            permitted_categories: bridge_core::policy::PRO_REVIEW_CATEGORIES.to_vec(),
            writable_paths: vec![bridge_core::policy::PRO_REVIEW_WRITABLE_PATH.to_owned()],
            allowed_recipes: vec!["python_tests".into()],
            network_destinations: vec![],
            export_scope: "redacted_summary".into(),
            integration_mode: bridge_types::IntegrationMode::AwaitOwnerReview,
            limits,
            offline_policy: bridge_types::OfflineGrantPolicy::DenyNewAllowRunningDeterministic,
            expires_at: now + chrono::Duration::minutes(30),
            revoked: false,
            revoked_at: None,
            created_at: now,
        };
        store.create_task_grant(&grant).unwrap();
        let payload = json!({
            "project_id": project.project_id,
            "task_id": "task_limits",
            "recipe": "python_tests",
            "args": [],
        })
        .to_string();
        let run = DurableJobRecord {
            run_id: RunId::new_random(),
            task_id: bridge_types::TaskId("task_limits".into()),
            host_id: host.clone(),
            project_id: bridge_types::ProjectId(project.project_id),
            workspace_id: grant.workspace_id.clone(),
            grant_id: Some(grant.grant_id),
            requester_principal: "executor:default".into(),
            executor_identity: "mcp_task_submit".into(),
            operation_id: bridge_types::OperationId("op_limits".into()),
            dedup_key: bridge_platform::sha256_bytes(b"op_limits"),
            payload_digest: bridge_platform::sha256_bytes(payload.as_bytes()),
            state: JobState::Queued,
            pid: None,
            process_start_time_100ns: None,
            exit_code: None,
            outcome: None,
            evidence_manifest_id: None,
            output_seq: 0,
            output_truncated: false,
            output_dir: root.join("state").join("runs").display().to_string(),
            created_at: now,
            updated_at: now,
        };
        store.claim_durable_run(&run, &payload).unwrap();
        let (admitted, payload) = store.take_delegated_queue_run(&host).unwrap().unwrap();
        (store, host, admitted, payload)
    }

    #[test]
    fn grant_limits_tighten_applied_worker_limits_never_loosen_and_reject_zero() {
        let base = std::env::temp_dir().join(format!("eb_limits_test_{}", uuid::Uuid::new_v4().simple()));
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(base.clone());

        // 1. Grant with stricter limits created through the store propagates to authorization and supervisor request.
        let strict = bridge_types::ResourceLimits {
            max_duration_seconds: 12,
            max_cpu_percent: 25,
            max_memory_mb: 256,
            max_processes: 3,
            max_output_bytes: 4096,
            max_storage_bytes: 1_048_576,
        };
        let (store, host, run, _) = make_delegated_run_fixture(&base.join("strict"), strict);
        let auth = authorize_delegated_queue_recipe(&store, &host, &run, "python_tests").unwrap();
        let effective = EffectiveRunLimits::from_grant(&auth.limits).unwrap();
        assert_eq!(effective, EffectiveRunLimits {
            timeout_secs: 12,
            memory_bytes: 256 * 1024 * 1024,
            max_processes: 3,
            max_output_bytes: 4096,
            workspace_bytes: Some(1_048_576),
        });
        let req = build_supervisor_request(
            Path::new("state"),
            &auth.project,
            &Recipe { name: "python_tests", files: vec!["tests/__init__.py".into()], delegated: true, write_scope: auth.write_scope },
            Path::new("cancel"),
            &run.run_id,
            Path::new("ready"),
            effective,
        );
        assert_eq!(req["timeout_seconds"], 12);
        assert_eq!(req["max_memory_bytes"], 256 * 1024 * 1024);
        assert_eq!(req["max_processes"], 3);
        assert_eq!(req["max_output_bytes"], 4096);
        assert_eq!(req["workspace_limit"], 1_048_576);

        // 2. Grant values above fixed recipe caps never loosen the recipe caps.
        let loose = bridge_types::ResourceLimits {
            max_duration_seconds: 600,
            max_cpu_percent: 100,
            max_memory_mb: 4096,
            max_processes: 64,
            max_output_bytes: 10 * 1024 * 1024,
            max_storage_bytes: 1024 * 1024 * 1024,
        };
        assert_eq!(EffectiveRunLimits::from_grant(&loose).unwrap(), EffectiveRunLimits {
            timeout_secs: WORKER_TIMEOUT_SECS,
            memory_bytes: WORKER_MAX_MEMORY_MB * 1024 * 1024,
            max_processes: WORKER_MAX_PROCESSES,
            max_output_bytes: MAX_LOG_BYTES,
            workspace_bytes: Some(WORKER_MAX_WORKSPACE_BYTES),
        });

        // 3. Default ResourceLimits applies 60s cap and 32 MiB workspace cap (lower than 256 MiB fixed cap).
        let default_effective = EffectiveRunLimits::from_grant(&bridge_types::ResourceLimits::default()).unwrap();
        assert_eq!(default_effective.timeout_secs, WORKER_TIMEOUT_SECS);
        assert_eq!(default_effective.memory_bytes, WORKER_MAX_MEMORY_MB * 1024 * 1024);
        assert_eq!(default_effective.max_processes, WORKER_MAX_PROCESSES);
        assert_eq!(default_effective.max_output_bytes, MAX_LOG_BYTES);
        assert_eq!(default_effective.workspace_bytes, Some(33_554_432));

        // 4. Any zero limit is refused with INVALID_GRANT_LIMITS (never runs unlimited).
        let mut zero_cases = Vec::new();
        let base_limits = bridge_types::ResourceLimits::default();
        zero_cases.push(bridge_types::ResourceLimits { max_duration_seconds: 0, ..base_limits.clone() });
        zero_cases.push(bridge_types::ResourceLimits { max_cpu_percent: 0, ..base_limits.clone() });
        zero_cases.push(bridge_types::ResourceLimits { max_memory_mb: 0, ..base_limits.clone() });
        zero_cases.push(bridge_types::ResourceLimits { max_processes: 0, ..base_limits.clone() });
        zero_cases.push(bridge_types::ResourceLimits { max_output_bytes: 0, ..base_limits.clone() });
        zero_cases.push(bridge_types::ResourceLimits { max_storage_bytes: 0, ..base_limits });
        for bad in zero_cases {
            let reason = EffectiveRunLimits::from_grant(&bad).unwrap_err();
            assert!(reason.starts_with("INVALID_GRANT_LIMITS:"), "{reason}");
        }
    }

    #[test]
    fn process_request_refuses_zero_duration_grant_without_spawning_supervisor() {
        let base = std::env::temp_dir().join(format!("eb_zero_limit_test_{}", uuid::Uuid::new_v4().simple()));
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(base.clone());
        let zero_duration = bridge_types::ResourceLimits {
            max_duration_seconds: 0,
            ..bridge_types::ResourceLimits::default()
        };
        let (store, host, run, payload) = make_delegated_run_fixture(&base, zero_duration);
        let state_dir = base.join("state");
        let missing_runtime = base.join("nonexistent-runtime");
        let result = process_request(
            &store, &state_dir, &host, &run, &payload, &missing_runtime, &missing_runtime, true,
        ).unwrap();
        assert_eq!(result["run"]["state"], "failed");
        assert_eq!(result["verification"], "BLOCKED");
        let failure_code = result["failure_code"].as_str().unwrap();
        assert!(failure_code.starts_with("INVALID_GRANT_LIMITS:"), "{failure_code}");
        let chunks = store.read_run_output(&run.run_id.0, 0, 10).unwrap();
        assert!(chunks.iter().any(|(_, stream, text)| stream == "stderr" && text.contains("INVALID_GRANT_LIMITS")));
        assert!(!state_dir.join("runs").join(&run.run_id.0).exists());
    }
}
