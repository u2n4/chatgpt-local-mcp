use crate::mcp::McpDispatcher;
use bridge_core::policy::PolicyEngine;
use bridge_types::*;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub const DELEGATED_MAX_ACTIVE_RUNS_PER_GRANT: u64 = 8;
pub const JOB_WAIT_MAX_CONCURRENT: usize = 2;
pub const JOB_WAIT_MAX_IDS: usize = 16;
pub const JOB_WAIT_MAX_TIMEOUT_SECS: u64 = 20;
pub const JOB_WAIT_DEFAULT_TIMEOUT_SECS: u64 = 15;
pub const JOB_WAIT_MAX_OUTPUT_BYTES: usize = 32_768;
pub const JOB_WAIT_DEFAULT_OUTPUT_BYTES: usize = 16_384;
const JOB_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(200);
const JOB_WAIT_READ_CHUNK_LIMIT: usize = 500;

/// Cooperative cancellation signal for in-flight `job_wait` polls (for HTTP disconnect
/// or request cancellation). Wakes sleeping waits immediately without busy-looping.
#[derive(Clone, Default)]
pub struct WaitCancel {
    inner: Arc<(Mutex<bool>, Condvar)>,
}

impl WaitCancel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        let (lock, cvar) = &*self.inner;
        let mut cancelled = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *cancelled = true;
        cvar.notify_all();
    }

    pub fn is_cancelled(&self) -> bool {
        let (lock, _) = &*self.inner;
        *lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Sleep for up to `duration`, returning `true` if cancelled before the timer elapsed.
    pub fn sleep_until_cancelled(&self, duration: Duration) -> bool {
        let (lock, cvar) = &*self.inner;
        let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if *guard {
            return true;
        }
        let (guard, _) = cvar
            .wait_timeout_while(guard, duration, |cancelled| !*cancelled)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard
    }
}

thread_local! {
    static CURRENT_WAIT_CANCEL: RefCell<Option<WaitCancel>> = const { RefCell::new(None) };
}

struct ResetWaitCancel(Option<WaitCancel>);

impl Drop for ResetWaitCancel {
    fn drop(&mut self) {
        let prev = self.0.take();
        CURRENT_WAIT_CANCEL.with(|slot| {
            *slot.borrow_mut() = prev;
        });
    }
}

/// Bind a `WaitCancel` signal to the current thread while `f` executes.
pub fn with_wait_cancel<T>(cancel: WaitCancel, f: impl FnOnce() -> T) -> T {
    let prev = CURRENT_WAIT_CANCEL.with(|slot| slot.borrow_mut().replace(cancel));
    let _reset = ResetWaitCancel(prev);
    f()
}

fn current_wait_cancel() -> Option<WaitCancel> {
    CURRENT_WAIT_CANCEL.with(|slot| slot.borrow().clone())
}

fn is_wait_cancelled() -> bool {
    current_wait_cancel().is_some_and(|cancel| cancel.is_cancelled())
}

fn sleep_or_cancel(duration: Duration) -> bool {
    if let Some(cancel) = current_wait_cancel() {
        cancel.sleep_until_cancelled(duration)
    } else {
        std::thread::sleep(duration);
        false
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WaitFor {
    Any,
    All,
}

impl WaitFor {
    fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::All => "all",
        }
    }
}

fn invalid_arg(message: impl Into<String>) -> BridgeError {
    BridgeError::new(ErrorCode::InvalidArgument, message, OriginLayer::Validation)
}

fn wait_cancelled_error() -> BridgeError {
    BridgeError::new(
        ErrorCode::TransientDisconnect,
        "job_wait stopped because the request was cancelled or the connection closed.",
        OriginLayer::Transport,
    )
}

fn truncate_utf8_bytes(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}

fn is_wait_done(run: &DurableJobRecord) -> bool {
    run.state.is_terminal() || run.state == JobState::Unknown
}

fn parse_job_ids(args: &Value) -> Result<Vec<String>, BridgeError> {
    let items = args
        .get("job_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_arg("Required array argument 'job_ids' (1 to 16 unique run_ids) is missing."))?;
    if items.is_empty() || items.len() > JOB_WAIT_MAX_IDS {
        return Err(invalid_arg(format!(
            "'job_ids' must contain between 1 and {JOB_WAIT_MAX_IDS} unique run_ids."
        )));
    }
    let mut out = Vec::with_capacity(items.len());
    let mut seen = HashSet::with_capacity(items.len());
    for item in items {
        let id = item
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_arg("Every entry in 'job_ids' must be a non-empty string."))?;
        if !seen.insert(id) {
            return Err(invalid_arg(format!("Duplicate job_id '{id}' in 'job_ids'.")));
        }
        out.push(id.to_owned());
    }
    Ok(out)
}

fn parse_timeout_seconds(args: &Value) -> Result<u64, BridgeError> {
    let Some(val) = args.get("timeout_seconds") else {
        return Ok(JOB_WAIT_DEFAULT_TIMEOUT_SECS);
    };
    let secs = val
        .as_u64()
        .ok_or_else(|| invalid_arg(format!("'timeout_seconds' must be an integer between 0 and {JOB_WAIT_MAX_TIMEOUT_SECS}.")))?;
    if secs > JOB_WAIT_MAX_TIMEOUT_SECS {
        return Err(invalid_arg(format!(
            "'timeout_seconds' must be between 0 and {JOB_WAIT_MAX_TIMEOUT_SECS}."
        )));
    }
    Ok(secs)
}

fn parse_wait_for(args: &Value) -> Result<WaitFor, BridgeError> {
    let Some(val) = args.get("wait_for") else {
        return Ok(WaitFor::Any);
    };
    match val.as_str() {
        Some("any") => Ok(WaitFor::Any),
        Some("all") => Ok(WaitFor::All),
        _ => Err(invalid_arg("'wait_for' must be either 'any' or 'all'.")),
    }
}

fn parse_include_output(args: &Value) -> Result<bool, BridgeError> {
    let Some(val) = args.get("include_output") else {
        return Ok(true);
    };
    val.as_bool()
        .ok_or_else(|| invalid_arg("'include_output' must be a boolean."))
}

fn parse_output_limit_bytes(args: &Value) -> Result<usize, BridgeError> {
    let Some(val) = args.get("output_limit_bytes") else {
        return Ok(JOB_WAIT_DEFAULT_OUTPUT_BYTES);
    };
    let limit = val
        .as_u64()
        .ok_or_else(|| invalid_arg(format!("'output_limit_bytes' must be an integer between 1 and {JOB_WAIT_MAX_OUTPUT_BYTES}.")))?;
    if limit == 0 || limit > JOB_WAIT_MAX_OUTPUT_BYTES as u64 {
        return Err(invalid_arg(format!(
            "'output_limit_bytes' must be between 1 and {JOB_WAIT_MAX_OUTPUT_BYTES}."
        )));
    }
    Ok(limit as usize)
}

fn parse_grant_hint(args: &Value) -> Result<Option<&str>, BridgeError> {
    match args.get("grant_id") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(invalid_arg("'grant_id' must be a string when provided.")),
    }
}

fn bounded_run_output(
    dispatcher: &McpDispatcher,
    run: &DurableJobRecord,
    limit_bytes: usize,
) -> Result<Value, BridgeError> {
    let chunks = dispatcher
        .store()
        .read_run_output(run.run_id.as_str(), 0, JOB_WAIT_READ_CHUNK_LIMIT)?;
    let fetched = chunks.len();
    let mut selected = Vec::new();
    let mut used_bytes = 0usize;
    let mut next_seq = 0u64;
    let mut hit_limit = false;

    for (seq, stream, content) in chunks {
        if used_bytes.saturating_add(content.len()) <= limit_bytes {
            used_bytes += content.len();
            next_seq = seq;
            selected.push(json!({"seq": seq, "stream": stream, "content": content}));
        } else if selected.is_empty() {
            let prefix = truncate_utf8_bytes(&content, limit_bytes);
            selected.push(json!({"seq": seq, "stream": stream, "content": prefix}));
            hit_limit = true;
            break;
        } else {
            hit_limit = true;
            break;
        }
    }

    if !hit_limit && fetched == JOB_WAIT_READ_CHUNK_LIMIT {
        let more = dispatcher
            .store()
            .read_run_output(run.run_id.as_str(), next_seq, 1)?;
        if !more.is_empty() {
            hit_limit = true;
        }
    }

    Ok(json!({
        "chunks": selected,
        "next_seq": next_seq,
        "truncated": run.output_truncated || hit_limit,
    }))
}

pub(crate) fn dispatch_job_wait(
    dispatcher: &McpDispatcher,
    policy: &PolicyEngine<'_>,
    args: &Value,
) -> Result<Value, BridgeError> {
    if dispatcher.principal().is_edge() {
        return Err(BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            "Principal 'edge' is strictly read-only and cannot invoke 'job_wait'.",
            OriginLayer::Policy,
        ));
    }

    let pid = args
        .get("project_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid_arg("Required string argument 'project_id' is missing."))?;
    let job_ids = parse_job_ids(args)?;
    let timeout_seconds = parse_timeout_seconds(args)?;
    let wait_for = parse_wait_for(args)?;
    let include_output = parse_include_output(args)?;
    let output_limit_bytes = parse_output_limit_bytes(args)?;
    let grant_hint = parse_grant_hint(args)?;

    let authorize = |hint: Option<&str>| -> Result<Option<GrantId>, BridgeError> {
        let read_dec = policy.authorize(
            dispatcher.principal(),
            pid,
            OperationCategory::Read,
            None,
            None,
            hint,
        )?;
        if include_output {
            let pinned_grant = read_dec.grant_id.as_ref().map(|g| g.0.as_str()).or(hint);
            policy.authorize_run_output(dispatcher.principal(), pid, pinned_grant)?;
        }
        Ok(read_dec.grant_id)
    };

    let grant_id = authorize(grant_hint)?;
    let _wait_permit = dispatcher.try_acquire_wait_slot()?;

    let fetch_runs = |grant: Option<&GrantId>| -> Result<Vec<DurableJobRecord>, BridgeError> {
        let mut runs = Vec::with_capacity(job_ids.len());
        for jid in &job_ids {
            runs.push(dispatcher.get_visible_run(pid, jid, grant)?);
        }
        Ok(runs)
    };

    let started_at = Instant::now();
    let deadline = started_at + Duration::from_secs(timeout_seconds);

    let mut current_runs = fetch_runs(grant_id.as_ref())?;
    let mut completed = false;
    let mut timed_out = false;

    loop {
        let done = match wait_for {
            WaitFor::Any => current_runs.iter().any(is_wait_done),
            WaitFor::All => current_runs.iter().all(is_wait_done),
        };
        if done {
            completed = true;
            break;
        }
        if timeout_seconds == 0 {
            break;
        }
        if is_wait_cancelled() {
            return Err(wait_cancelled_error());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            timed_out = true;
            break;
        }
        let sleep_dur = remaining.min(JOB_WAIT_POLL_INTERVAL);
        if sleep_or_cancel(sleep_dur) {
            return Err(wait_cancelled_error());
        }
        // Re-check grant validity on every poll so a revoked/expired grant stops waiting immediately.
        let pinned_hint = grant_id.as_ref().map(|g| g.0.as_str()).or(grant_hint);
        let refreshed_grant = authorize(pinned_hint)?;
        current_runs = fetch_runs(refreshed_grant.as_ref())?;
    }

    let mut run_values = Vec::with_capacity(current_runs.len());
    for run in current_runs {
        let attach_output = include_output && run.state.is_terminal();
        let output = if attach_output {
            Some(bounded_run_output(dispatcher, &run, output_limit_bytes)?)
        } else {
            None
        };
        let mut value = dispatcher.run_value_with_workload_report(run)?;
        if let Some(output) = output {
            value["output"] = output;
        }
        run_values.push(value);
    }

    Ok(json!({
        "project_id": pid,
        "wait_for": wait_for.as_str(),
        "completed": completed,
        "timed_out": timed_out,
        "elapsed_ms": started_at.elapsed().as_millis() as u64,
        "runs": run_values,
    }))
}
