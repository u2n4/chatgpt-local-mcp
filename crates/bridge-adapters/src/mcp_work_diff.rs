//! MCP adapter handlers, schemas, and descriptions for `work_diff` and `work_export_diff`.

use crate::mcp::{McpDispatcher, req_str, validate_delegated_label};
use bridge_core::policy::{PRO_REVIEW_WRITABLE_PATH, PolicyEngine};
use bridge_core::work_diff::{
    WORK_DIFF_DEFAULT_LIMIT, WORK_DIFF_MAX_LIMIT, WORK_DIFF_MAX_PATHS, WorkDiffRequest,
    WorkExportDiffRequest, compute_work_diff, export_work_diff_to_outbox,
    validate_outbox_diff_path,
};
use bridge_types::*;
use serde_json::{Value, json};
use std::path::Path;

fn invalid_arg(message: impl Into<String>) -> BridgeError {
    BridgeError::new(ErrorCode::InvalidArgument, message, OriginLayer::Validation)
}

fn edge_denied(tool: &str) -> BridgeError {
    BridgeError::new(
        ErrorCode::BridgePolicyDenied,
        format!(
            "Principal 'edge' is strictly read-only and cannot invoke '{tool}'. Use an owner-approved pro-agent grant or local owner CLI."
        ),
        OriginLayer::Policy,
    )
}

fn parse_grant_hint(args: &Value) -> Result<Option<&str>, BridgeError> {
    match args.get("grant_id") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.is_empty() => Ok(Some(s.as_str())),
        Some(_) => Err(invalid_arg("'grant_id' must be a non-empty string when provided.")),
    }
}

fn parse_opt_bool(args: &Value, key: &str, default: bool) -> Result<bool, BridgeError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(invalid_arg(format!("'{key}' must be a boolean."))),
    }
}

fn parse_opt_string(args: &Value, key: &str) -> Result<Option<String>, BridgeError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
        Some(_) => Err(invalid_arg(format!("'{key}' must be a non-empty string or null."))),
    }
}

fn parse_opt_usize(args: &Value, key: &str, default: usize) -> Result<usize, BridgeError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => v
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| invalid_arg(format!("'{key}' must be a non-negative integer."))),
    }
}

fn parse_opt_paths_filter(args: &Value) -> Result<Option<Vec<String>>, BridgeError> {
    let Some(val) = args.get("paths") else {
        return Ok(None);
    };
    if val.is_null() {
        return Ok(None);
    }
    let items = val
        .as_array()
        .ok_or_else(|| invalid_arg("'paths' must be an array of 1 to 64 path strings or null."))?;
    if items.is_empty() || items.len() > WORK_DIFF_MAX_PATHS {
        return Err(invalid_arg(format!(
            "'paths' must contain between 1 and {WORK_DIFF_MAX_PATHS} path strings."
        )));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let s = item
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_arg("Every entry in 'paths' must be a non-empty string."))?;
        out.push(s.to_owned());
    }
    Ok(Some(out))
}

fn state_dir_of(dispatcher: &McpDispatcher) -> &Path {
    dispatcher.store().db_path().parent().unwrap_or(Path::new("."))
}

fn effective_work_scope(principal: &Principal, decision_scope: Vec<String>) -> Vec<String> {
    if principal.is_local() {
        vec![PRO_REVIEW_WRITABLE_PATH.to_owned()]
    } else {
        decision_scope
    }
}

fn commit_auth_error(error: BridgeError) -> BridgeError {
    match error.code {
        ErrorCode::ProjectNotGranted | ErrorCode::StalePrecondition | ErrorCode::BridgePolicyDenied => {
            BridgeError::new(
                ErrorCode::BridgePolicyDenied,
                "The delegated write grant is no longer valid at commit.",
                OriginLayer::Policy,
            )
        }
        _ => error,
    }
}

pub(crate) fn dispatch_work_diff(
    dispatcher: &McpDispatcher,
    policy: &PolicyEngine<'_>,
    args: &Value,
) -> Result<Value, BridgeError> {
    if dispatcher.principal().is_edge() {
        return Err(edge_denied("work_diff"));
    }
    let pid = req_str(args, "project_id")?;
    let workspace = req_str(args, "workspace")?;
    let grant_hint = parse_grant_hint(args)?;
    let paths = parse_opt_paths_filter(args)?;
    let summary_only = parse_opt_bool(args, "summary_only", false)?;
    let expected_diff_sha256 = parse_opt_string(args, "expected_diff_sha256")?;
    let offset = parse_opt_usize(args, "offset", 0)?;
    let limit = parse_opt_usize(args, "limit", WORK_DIFF_DEFAULT_LIMIT)?;

    // Requires OperationCategory::WorkArea (refuses pro-review, older grants without WorkArea, and edge).
    let ws_dec = policy.authorize_work_mutation(dispatcher.principal(), pid, workspace, None, grant_hint)?;
    let state_dir = state_dir_of(dispatcher);
    let req = WorkDiffRequest {
        workspace: workspace.to_owned(),
        paths,
        summary_only,
        expected_diff_sha256,
        offset,
        limit,
    };

    let res = compute_work_diff(
        Path::new(&ws_dec.project.root),
        &ws_dec.project.root_identity,
        state_dir,
        pid,
        &req,
    )?;

    Ok(serde_json::to_value(res).unwrap())
}

pub(crate) fn dispatch_work_export_diff(
    dispatcher: &McpDispatcher,
    policy: &PolicyEngine<'_>,
    args: &Value,
) -> Result<Value, BridgeError> {
    if dispatcher.principal().is_edge() {
        return Err(edge_denied("work_export_diff"));
    }
    let pid = req_str(args, "project_id")?;
    let workspace = req_str(args, "workspace")?;
    let operation_id = req_str(args, "operation_id")?;
    let raw_path = req_str(args, "path")?;
    let grant_hint = parse_grant_hint(args)?;
    let paths = parse_opt_paths_filter(args)?;
    let allow_drifted = parse_opt_bool(args, "allow_drifted", false)?;
    let task_id = parse_opt_string(args, "task_id")?;

    if !dispatcher.principal().is_local() {
        validate_delegated_label("operation_id", operation_id)?;
        if let Some(ref tid) = task_id {
            validate_delegated_label("task_id", tid)?;
        }
    }

    // 1. Authorize WorkArea on the workspace (denies pro-review, older grants, revoked/expired).
    let ws_dec = policy.authorize_work_mutation(dispatcher.principal(), pid, workspace, None, grant_hint)?;
    let pinned_grant = ws_dec.grant_id.as_ref().map(|g| g.0.clone());

    // 2. Validate exact-case flat `_pro/outbox/*.diff` destination path.
    let outbox_path = validate_outbox_diff_path(raw_path)?;

    // 3. Authorize OperationCategory::Write for the exact outbox destination under the same pinned grant.
    let write_dec = policy.authorize(
        dispatcher.principal(),
        pid,
        OperationCategory::Write,
        Some(&outbox_path),
        None,
        pinned_grant.as_deref(),
    )?;
    let scope = effective_work_scope(dispatcher.principal(), write_dec.effective_scope);
    let state_dir = state_dir_of(dispatcher);

    let req = WorkExportDiffRequest {
        workspace: workspace.to_owned(),
        operation_id: operation_id.to_owned(),
        path: outbox_path,
        paths,
        allow_drifted,
        task_id,
    };

    let (res, journal) = export_work_diff_to_outbox(
        Path::new(&ws_dec.project.root),
        &ws_dec.project.root_identity,
        state_dir,
        pid,
        &req,
        &scope,
        |target_path| {
            #[cfg(test)]
            dispatcher.run_before_delegated_commit();
            if let Some(ref gid) = pinned_grant {
                policy.authorize_write_commit(
                    dispatcher.principal(),
                    pid,
                    OperationCategory::Write,
                    target_path,
                    gid,
                )?;
                policy
                    .authorize_work_mutation(dispatcher.principal(), pid, workspace, None, Some(gid))
                    .map(|_| ())
                    .map_err(commit_auth_error)
            } else {
                Ok(())
            }
        },
    )?;

    let _ = dispatcher.store().save_patch_journal(
        &journal.journal_id,
        &journal.project_id,
        &journal.operation_id,
        &journal.state,
        &journal.plan_sha256,
        &serde_json::to_string(&journal).unwrap_or_default(),
    );

    Ok(serde_json::to_value(res).unwrap())
}

pub(crate) fn work_diff_tool_description(name: &str) -> Option<&'static str> {
    match name {
        "work_diff" => Some(
            "Read-only unified diff (max 4 MiB) and per-file stats comparing _pro/work/<workspace>/ against live project files using the bridge-side manifest. Flags baseline drift, hides remote-protected paths, omits binary or >1 MiB file bodies, and paginates by character offset/limit (max 65536). Requires work_area permission (pro-agent grant).",
        ),
        "work_export_diff" => Some(
            "Create one new git-apply-compatible .diff file directly under _pro/outbox/ from _pro/work/<workspace>/ (create-only, max 1 MiB, refuses drift unless allow_drifted=true and refuses binary or >1 MiB changes). The owner applies changes locally with edge-bridge work-apply. Requires work_area and write permissions (pro-agent grant).",
        ),
        _ => None,
    }
}

pub(crate) fn work_diff_tool_input_schema(name: &str) -> Option<Value> {
    let s = || json!({"type": "string"});
    let s_id = |d: &str| json!({"type": "string", "description": d});
    let sn = || json!({"type": ["string", "null"]});
    let grant = || s_id("Owner-issued grant hint; may be omitted to auto-select the newest valid grant.");
    let workspace = || json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 40,
        "pattern": "^[a-z0-9][a-z0-9_-]{0,39}$",
        "description": "Workspace label under _pro/work/<workspace>/ (1-40 lowercase ASCII chars [a-z0-9_-])."
    });
    let paths_filter = || json!({
        "type": ["array", "null"],
        "minItems": 1,
        "maxItems": WORK_DIFF_MAX_PATHS,
        "items": {"type": "string", "minLength": 1},
        "description": "Optional list of 1 to 64 project-relative file or directory paths to include."
    });
    match name {
        "work_diff" => Some(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["project_id", "workspace"],
            "properties": {
                "project_id": s(),
                "workspace": workspace(),
                "paths": paths_filter(),
                "summary_only": {"type": "boolean", "default": false, "description": "When true, return per-file stats and diff_sha256 without diff body text."},
                "expected_diff_sha256": sn(),
                "offset": {"type": "integer", "minimum": 0, "default": 0, "description": "Start offset in characters (not lines or bytes)."},
                "limit": {"type": "integer", "minimum": 1, "maximum": WORK_DIFF_MAX_LIMIT, "default": WORK_DIFF_DEFAULT_LIMIT, "description": "Maximum number of characters to return (default 32768, max 65536)."},
                "grant_id": grant()
            }
        })),
        "work_export_diff" => Some(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["project_id", "workspace", "operation_id", "path"],
            "properties": {
                "project_id": s(),
                "workspace": workspace(),
                "operation_id": s_id("Stable operation label for audit and journaling."),
                "path": {
                    "type": "string",
                    "minLength": 18,
                    "maxLength": 138,
                    "pattern": "^_pro/outbox/[a-zA-Z0-9][a-zA-Z0-9._-]{0,120}\\.diff$",
                    "description": "Create-only destination path directly under exact-case '_pro/outbox/' ending in '.diff'."
                },
                "paths": paths_filter(),
                "allow_drifted": {"type": "boolean", "default": false, "description": "Allow exporting even if a live project file changed since work_copy."},
                "task_id": s(),
                "grant_id": grant()
            }
        })),
        _ => None,
    }
}

pub(crate) fn work_diff_tool_output_schema(name: &str) -> Option<Value> {
    let envelope = |result: Value| {
        json!({
            "type": "object",
            "properties": {"result": result},
            "required": ["result"],
            "additionalProperties": true
        })
    };
    let st = || json!({"type": "string"});
    let stn = || json!({"type": ["string", "null"]});
    let it = || json!({"type": "integer"});
    let itn = || json!({"type": ["integer", "null"]});
    let bl = || json!({"type": "boolean"});
    let quota_schema = json!({
        "type": "object",
        "properties": {
            "files_used": it(),
            "max_files": it(),
            "bytes_used": it(),
            "max_bytes": it(),
            "workspaces_used": it(),
            "max_workspaces": it()
        },
        "required": ["files_used", "max_files", "bytes_used", "max_bytes", "workspaces_used", "max_workspaces"],
        "additionalProperties": true
    });
    let file_stat_schema = json!({
        "type": "object",
        "properties": {
            "path": st(),
            "old_path": stn(),
            "status": st(),
            "insertions": it(),
            "deletions": it(),
            "binary": bl(),
            "oversized": bl(),
            "content_omitted": bl(),
            "baseline_sha256": stn(),
            "live_sha256": stn(),
            "work_sha256": stn(),
            "drifted_from_baseline": bl(),
            "missing_in_live": bl(),
            "conflict_exists_in_project": bl()
        },
        "required": [
            "path", "status", "insertions", "deletions", "binary", "oversized",
            "content_omitted", "drifted_from_baseline", "missing_in_live",
            "conflict_exists_in_project"
        ],
        "additionalProperties": true
    });
    match name {
        "work_diff" => Some(envelope(json!({
            "type": "object",
            "properties": {
                "workspace": st(),
                "diff_sha256": st(),
                "files_changed": it(),
                "total_insertions": it(),
                "total_deletions": it(),
                "has_drift": bl(),
                "drifted_files": {"type": "array", "items": st()},
                "conflict_files": {"type": "array", "items": st()},
                "binary_or_oversized_files": {"type": "array", "items": st()},
                "files": {"type": "array", "items": file_stat_schema},
                "content": st(),
                "offset": it(),
                "next_offset": itn(),
                "total_bytes": it(),
                "truncated": bl()
            },
            "required": [
                "workspace", "diff_sha256", "files_changed", "total_insertions",
                "total_deletions", "has_drift", "drifted_files", "conflict_files",
                "binary_or_oversized_files", "files", "content", "offset",
                "next_offset", "total_bytes", "truncated"
            ],
            "additionalProperties": true
        }))),
        "work_export_diff" => Some(envelope(json!({
            "type": "object",
            "properties": {
                "workspace": st(),
                "path": st(),
                "operation_id": st(),
                "journal_id": st(),
                "diff_sha256": st(),
                "bytes_written": it(),
                "files_changed": it(),
                "total_insertions": it(),
                "total_deletions": it(),
                "drifted_files": {"type": "array", "items": st()},
                "quota": quota_schema
            },
            "required": [
                "workspace", "path", "operation_id", "journal_id", "diff_sha256",
                "bytes_written", "files_changed", "total_insertions", "total_deletions",
                "drifted_files", "quota"
            ],
            "additionalProperties": true
        }))),
        _ => None,
    }
}
