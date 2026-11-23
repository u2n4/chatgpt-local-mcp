//! MCP adapter handlers, schemas, and descriptions for workspace-scoped mutation tools:
//! `work_copy`, `work_edit`, `work_move`, and `work_delete`.

use crate::mcp::{McpDispatcher, req_str, validate_delegated_label};
use bridge_core::policy::{PRO_REVIEW_WRITABLE_PATH, PolicyEngine};
use bridge_core::work::{
    WORK_COPY_MAX_PATHS, WORK_DELETE_MAX_PATHS, WorkCopyMode, WorkCopyRequest, WorkDeleteRequest,
    WorkDeleteTarget, WorkEditRequest, WorkFileEdit, WorkMoveRequest, work_copy, work_delete,
    work_edit, work_move,
};
use bridge_types::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
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

fn parse_string_array(args: &Value, key: &str, min_items: usize, max_items: usize) -> Result<Vec<String>, BridgeError> {
    let items = args
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_arg(format!("Required array argument '{key}' is missing.")))?;
    if items.len() < min_items || items.len() > max_items {
        return Err(invalid_arg(format!(
            "'{key}' must contain between {min_items} and {max_items} path strings."
        )));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let s = item
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_arg(format!("Every entry in '{key}' must be a non-empty string.")))?;
        out.push(s.to_owned());
    }
    Ok(out)
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

pub(crate) fn dispatch_work_copy(
    dispatcher: &McpDispatcher,
    policy: &PolicyEngine<'_>,
    args: &Value,
) -> Result<Value, BridgeError> {
    if dispatcher.principal().is_edge() {
        return Err(edge_denied("work_copy"));
    }
    let pid = req_str(args, "project_id")?;
    let workspace = req_str(args, "workspace")?;
    let grant_hint = parse_grant_hint(args)?;
    let within_workspace = parse_opt_bool(args, "within_workspace", false)?;
    let overwrite_existing = parse_opt_bool(args, "overwrite_existing", false)?;

    let mode = if within_workspace {
        if args.get("paths").is_some_and(|v| !v.is_null()) {
            return Err(invalid_arg("Cannot pass 'paths' when 'within_workspace' is true; use 'from' and 'to'."));
        }
        let from = req_str(args, "from")?.to_owned();
        let to = req_str(args, "to")?.to_owned();
        WorkCopyMode::WithinWorkspace { from, to }
    } else {
        if args.get("from").is_some_and(|v| !v.is_null()) || args.get("to").is_some_and(|v| !v.is_null()) {
            return Err(invalid_arg("Cannot pass 'from' or 'to' when 'within_workspace' is false; pass 'paths' or set within_workspace=true."));
        }
        let paths = parse_string_array(args, "paths", 1, WORK_COPY_MAX_PATHS)?;
        let exclude_generated = parse_opt_bool(args, "exclude_generated", true)?;
        WorkCopyMode::FromProject {
            paths,
            exclude_generated,
        }
    };

    let ws_dec = policy.authorize_work_mutation(dispatcher.principal(), pid, workspace, None, grant_hint)?;
    let pinned_grant = ws_dec.grant_id.as_ref().map(|g| g.0.clone());
    let scope = effective_work_scope(dispatcher.principal(), ws_dec.effective_scope);
    let state_dir = state_dir_of(dispatcher);
    let req = WorkCopyRequest {
        workspace: workspace.to_owned(),
        mode,
        overwrite_existing,
    };

    let res = work_copy(
        Path::new(&ws_dec.project.root),
        &ws_dec.project.root_identity,
        state_dir,
        pid,
        &req,
        &scope,
        |subpath| {
            let dec = policy.authorize_work_mutation(
                dispatcher.principal(),
                pid,
                workspace,
                Some(subpath),
                pinned_grant.as_deref(),
            )?;
            dec.normalized_write_path.ok_or_else(|| {
                BridgeError::new(
                    ErrorCode::BridgePolicyDenied,
                    "Work-area authorization did not return a normalized target path.",
                    OriginLayer::Policy,
                )
            })
        },
        |target_path| {
            #[cfg(test)]
            dispatcher.run_before_delegated_commit();
            if let Some(ref gid) = pinned_grant {
                policy.authorize_write_commit(
                    dispatcher.principal(),
                    pid,
                    OperationCategory::WorkArea,
                    target_path,
                    gid,
                )
            } else {
                Ok(())
            }
        },
    )?;

    Ok(serde_json::to_value(res).unwrap())
}

pub(crate) fn dispatch_work_edit(
    dispatcher: &McpDispatcher,
    policy: &PolicyEngine<'_>,
    args: &Value,
) -> Result<Value, BridgeError> {
    if dispatcher.principal().is_edge() {
        return Err(edge_denied("work_edit"));
    }
    let pid = req_str(args, "project_id")?;
    let workspace = req_str(args, "workspace")?;
    let operation_id = req_str(args, "operation_id")?;
    let grant_hint = parse_grant_hint(args)?;
    let task_id = parse_opt_string(args, "task_id")?;

    if !dispatcher.principal().is_local() {
        validate_delegated_label("operation_id", operation_id)?;
        if let Some(ref tid) = task_id {
            validate_delegated_label("task_id", tid)?;
        }
    }

    let edits_val = args
        .get("edits")
        .cloned()
        .ok_or_else(|| invalid_arg("Required array argument 'edits' is missing."))?;
    let edits: Vec<WorkFileEdit> = serde_json::from_value(edits_val)
        .map_err(|e| invalid_arg(format!("Invalid 'edits' array: {e}")))?;

    let ws_dec = policy.authorize_work_mutation(dispatcher.principal(), pid, workspace, None, grant_hint)?;
    let pinned_grant = ws_dec.grant_id.as_ref().map(|g| g.0.clone());
    let scope = effective_work_scope(dispatcher.principal(), ws_dec.effective_scope);
    let state_dir = state_dir_of(dispatcher);
    let req = WorkEditRequest {
        workspace: workspace.to_owned(),
        operation_id: operation_id.to_owned(),
        task_id,
        edits,
    };

    let (res, journal) = work_edit(
        Path::new(&ws_dec.project.root),
        &ws_dec.project.root_identity,
        state_dir,
        pid,
        &req,
        &scope,
        |subpath| {
            let dec = policy.authorize_work_mutation(
                dispatcher.principal(),
                pid,
                workspace,
                Some(subpath),
                pinned_grant.as_deref(),
            )?;
            dec.normalized_write_path.ok_or_else(|| {
                BridgeError::new(
                    ErrorCode::BridgePolicyDenied,
                    "Work-area authorization did not return a normalized target path.",
                    OriginLayer::Policy,
                )
            })
        },
        |target_path| {
            #[cfg(test)]
            dispatcher.run_before_delegated_commit();
            if let Some(ref gid) = pinned_grant {
                policy.authorize_write_commit(
                    dispatcher.principal(),
                    pid,
                    OperationCategory::WorkArea,
                    target_path,
                    gid,
                )
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

pub(crate) fn dispatch_work_move(
    dispatcher: &McpDispatcher,
    policy: &PolicyEngine<'_>,
    args: &Value,
) -> Result<Value, BridgeError> {
    if dispatcher.principal().is_edge() {
        return Err(edge_denied("work_move"));
    }
    let pid = req_str(args, "project_id")?;
    let workspace = req_str(args, "workspace")?;
    let operation_id = req_str(args, "operation_id")?;
    let from = req_str(args, "from")?;
    let to = req_str(args, "to")?;
    let grant_hint = parse_grant_hint(args)?;
    let expected_from_hash = parse_opt_string(args, "expected_from_hash")?;
    let overwrite = parse_opt_bool(args, "overwrite", false)?;
    let expected_to_hash = parse_opt_string(args, "expected_to_hash")?;

    if !dispatcher.principal().is_local() {
        validate_delegated_label("operation_id", operation_id)?;
    }

    let ws_dec = policy.authorize_work_mutation(dispatcher.principal(), pid, workspace, None, grant_hint)?;
    let pinned_grant = ws_dec.grant_id.as_ref().map(|g| g.0.clone());
    let scope = effective_work_scope(dispatcher.principal(), ws_dec.effective_scope);
    let state_dir = state_dir_of(dispatcher);
    let req = WorkMoveRequest {
        workspace: workspace.to_owned(),
        operation_id: operation_id.to_owned(),
        from: from.to_owned(),
        to: to.to_owned(),
        expected_from_hash,
        overwrite,
        expected_to_hash,
    };

    let res = work_move(
        Path::new(&ws_dec.project.root),
        &ws_dec.project.root_identity,
        state_dir,
        pid,
        &req,
        &scope,
        |subpath| {
            let dec = policy.authorize_work_mutation(
                dispatcher.principal(),
                pid,
                workspace,
                Some(subpath),
                pinned_grant.as_deref(),
            )?;
            dec.normalized_write_path.ok_or_else(|| {
                BridgeError::new(
                    ErrorCode::BridgePolicyDenied,
                    "Work-area authorization did not return a normalized target path.",
                    OriginLayer::Policy,
                )
            })
        },
        |target_path| {
            #[cfg(test)]
            dispatcher.run_before_delegated_commit();
            if let Some(ref gid) = pinned_grant {
                policy.authorize_write_commit(
                    dispatcher.principal(),
                    pid,
                    OperationCategory::WorkArea,
                    target_path,
                    gid,
                )
            } else {
                Ok(())
            }
        },
    )?;

    Ok(serde_json::to_value(res).unwrap())
}

pub(crate) fn dispatch_work_delete(
    dispatcher: &McpDispatcher,
    policy: &PolicyEngine<'_>,
    args: &Value,
) -> Result<Value, BridgeError> {
    if dispatcher.principal().is_edge() {
        return Err(edge_denied("work_delete"));
    }
    let pid = req_str(args, "project_id")?;
    let workspace = req_str(args, "workspace")?;
    let operation_id = req_str(args, "operation_id")?;
    let grant_hint = parse_grant_hint(args)?;
    let delete_workspace = parse_opt_bool(args, "delete_workspace", false)?;

    if !dispatcher.principal().is_local() {
        validate_delegated_label("operation_id", operation_id)?;
    }

    let target = if delete_workspace {
        let has_paths = args
            .get("paths")
            .is_some_and(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()));
        let has_hashes = args
            .get("expected_hashes")
            .is_some_and(|v| !v.is_null() && v.as_object().is_none_or(|m| !m.is_empty()));
        if has_paths || has_hashes {
            return Err(invalid_arg(
                "Cannot combine 'delete_workspace=true' with 'paths' or 'expected_hashes'.",
            ));
        }
        WorkDeleteTarget::WholeWorkspace
    } else {
        let paths = parse_string_array(args, "paths", 1, WORK_DELETE_MAX_PATHS)?;
        let expected_hashes = match args.get("expected_hashes") {
            None | Some(Value::Null) => BTreeMap::new(),
            Some(Value::Object(map)) => {
                let mut out = BTreeMap::new();
                for (k, v) in map {
                    let h = v
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .ok_or_else(|| invalid_arg("Every value in 'expected_hashes' must be a non-empty SHA-256 string."))?;
                    out.insert(k.clone(), h.to_owned());
                }
                out
            }
            Some(_) => return Err(invalid_arg("'expected_hashes' must be an object mapping paths to SHA-256 strings.")),
        };
        WorkDeleteTarget::Files {
            paths,
            expected_hashes,
        }
    };

    let ws_dec = policy.authorize_work_mutation(dispatcher.principal(), pid, workspace, None, grant_hint)?;
    let pinned_grant = ws_dec.grant_id.as_ref().map(|g| g.0.clone());
    let state_dir = state_dir_of(dispatcher);
    let req = WorkDeleteRequest {
        workspace: workspace.to_owned(),
        operation_id: operation_id.to_owned(),
        target,
    };

    let res = work_delete(
        Path::new(&ws_dec.project.root),
        &ws_dec.project.root_identity,
        state_dir,
        pid,
        &req,
        |subpath| {
            let dec = policy.authorize_work_mutation(
                dispatcher.principal(),
                pid,
                workspace,
                subpath,
                pinned_grant.as_deref(),
            )?;
            dec.normalized_write_path.ok_or_else(|| {
                BridgeError::new(
                    ErrorCode::BridgePolicyDenied,
                    "Work-area authorization did not return a normalized target path.",
                    OriginLayer::Policy,
                )
            })
        },
        |target_path| {
            #[cfg(test)]
            dispatcher.run_before_delegated_commit();
            if let Some(ref gid) = pinned_grant {
                if delete_workspace {
                    policy
                        .authorize_work_mutation(dispatcher.principal(), pid, workspace, None, Some(gid))
                        .map(|_| ())
                        .map_err(commit_auth_error)
                } else {
                    policy.authorize_write_commit(
                        dispatcher.principal(),
                        pid,
                        OperationCategory::WorkArea,
                        target_path,
                        gid,
                    )
                }
            } else {
                Ok(())
            }
        },
    )?;

    Ok(serde_json::to_value(res).unwrap())
}

pub(crate) fn work_tool_description(name: &str) -> Option<&'static str> {
    match name {
        "work_copy" => Some(
            "Copy 1 to 64 project files/subtrees (up to 500 files, 4 MiB/file, 32 MiB/call; or 1 file within the same workspace when within_workspace=true) into _pro/work/<workspace>/ inside the bridge with remote hidden-file filtering and a bridge-side baseline manifest. Requires work_area permission (pro-agent grant; max 16 workspaces).",
        ),
        "work_edit" => Some(
            "Apply atomic multi-file, multi-hunk search-and-replace across 1 to 32 files (up to 64 hunks, 1 MiB/file, 4 MiB/call) strictly inside _pro/work/<workspace>/. All edits succeed or nothing changes. Requires work_area permission (pro-agent grant).",
        ),
        "work_move" => Some(
            "Rename or move one regular file strictly inside _pro/work/<workspace>/ using handle-verified checks and updating the bridge-side manifest. Requires work_area permission (pro-agent grant).",
        ),
        "work_delete" => Some(
            "Delete 1 to 64 files strictly inside _pro/work/<workspace>/, or remove an entire workspace and its bridge-side manifest with delete_workspace=true to free _pro/ quota (2000 files, 256 MiB). Refuses any link. Requires work_area permission (pro-agent grant).",
        ),
        _ => None,
    }
}

pub(crate) fn work_tool_input_schema(name: &str) -> Option<Value> {
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
    match name {
        "work_copy" => Some(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["project_id", "workspace"],
            "properties": {
                "project_id": s(),
                "workspace": workspace(),
                "paths": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 64,
                    "items": {"type": "string", "minLength": 1},
                    "description": "1 to 64 project-relative files or subtrees to copy (used when within_workspace=false)."
                },
                "exclude_generated": {"type": "boolean", "default": true},
                "overwrite_existing": {"type": "boolean", "default": false},
                "within_workspace": {
                    "type": "boolean",
                    "default": false,
                    "description": "When true, copy one file from 'from' to 'to' inside the same _pro/work/<workspace>/."
                },
                "from": {"type": "string", "minLength": 1, "description": "Workspace-relative source file when within_workspace=true."},
                "to": {"type": "string", "minLength": 1, "description": "Workspace-relative destination file when within_workspace=true."},
                "grant_id": grant()
            }
        })),
        "work_edit" => Some(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["project_id", "workspace", "operation_id", "edits"],
            "properties": {
                "project_id": s(),
                "workspace": workspace(),
                "operation_id": s_id("Stable operation label for audit and journaling."),
                "task_id": s(),
                "edits": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 32,
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["path", "replacements"],
                        "properties": {
                            "path": {"type": "string", "minLength": 1, "description": "Workspace-relative file path inside _pro/work/<workspace>/."},
                            "expected_hash": sn(),
                            "replacements": {
                                "type": "array",
                                "minItems": 1,
                                "maxItems": 64,
                                "items": {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["old_text", "new_text"],
                                    "properties": {
                                        "old_text": {"type": "string", "minLength": 1},
                                        "new_text": {"type": "string"},
                                        "replace_all": {"type": "boolean", "default": false}
                                    }
                                }
                            }
                        }
                    }
                },
                "grant_id": grant()
            }
        })),
        "work_move" => Some(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["project_id", "workspace", "operation_id", "from", "to"],
            "properties": {
                "project_id": s(),
                "workspace": workspace(),
                "operation_id": s_id("Stable operation label."),
                "from": {"type": "string", "minLength": 1, "description": "Workspace-relative source file path."},
                "to": {"type": "string", "minLength": 1, "description": "Workspace-relative destination file path."},
                "expected_from_hash": sn(),
                "overwrite": {"type": "boolean", "default": false},
                "expected_to_hash": sn(),
                "grant_id": grant()
            }
        })),
        "work_delete" => Some(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["project_id", "workspace", "operation_id"],
            "properties": {
                "project_id": s(),
                "workspace": workspace(),
                "operation_id": s_id("Stable operation label."),
                "paths": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 64,
                    "items": {"type": "string", "minLength": 1},
                    "description": "1 to 64 workspace-relative file paths to delete (omit when delete_workspace=true)."
                },
                "expected_hashes": {
                    "type": "object",
                    "additionalProperties": {"type": "string", "minLength": 1},
                    "description": "Optional map of workspace-relative paths to expected SHA-256 digests."
                },
                "delete_workspace": {
                    "type": "boolean",
                    "default": false,
                    "description": "When true, remove the entire _pro/work/<workspace>/ folder and its manifest."
                },
                "grant_id": grant()
            }
        })),
        _ => None,
    }
}

pub(crate) fn work_tool_output_schema(name: &str) -> Option<Value> {
    let envelope = |result: Value| {
        json!({
            "type": "object",
            "properties": {"result": result},
            "required": ["result"],
            "additionalProperties": true
        })
    };
    let st = || json!({"type": "string"});
    let it = || json!({"type": "integer"});
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
    match name {
        "work_copy" => Some(envelope(json!({
            "type": "object",
            "properties": {
                "workspace": st(),
                "work_root": st(),
                "within_workspace": bl(),
                "files_copied": {"type": "array", "items": st()},
                "copied_count": it(),
                "total_bytes": it(),
                "hashes": {"type": "object", "additionalProperties": st()},
                "skipped_generated_dirs": it(),
                "skipped_non_secret": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"path": st(), "reason": st()},
                        "required": ["path", "reason"],
                        "additionalProperties": true
                    }
                },
                "quota": quota_schema
            },
            "required": [
                "workspace", "work_root", "within_workspace", "files_copied",
                "copied_count", "total_bytes", "hashes", "skipped_generated_dirs",
                "skipped_non_secret", "quota"
            ],
            "additionalProperties": true
        }))),
        "work_edit" => Some(envelope(json!({
            "type": "object",
            "properties": {
                "workspace": st(),
                "journal_id": st(),
                "operation_id": st(),
                "files_applied": {"type": "array", "items": st()},
                "replacements_applied": it(),
                "postimage_hashes": {"type": "object", "additionalProperties": st()},
                "unified_diff": st(),
                "diff_sha256": st(),
                "quota": quota_schema
            },
            "required": [
                "workspace", "journal_id", "operation_id", "files_applied",
                "replacements_applied", "postimage_hashes", "unified_diff",
                "diff_sha256", "quota"
            ],
            "additionalProperties": true
        }))),
        "work_move" => Some(envelope(json!({
            "type": "object",
            "properties": {
                "workspace": st(),
                "operation_id": st(),
                "from": st(),
                "to": st(),
                "sha256": st(),
                "overwritten": bl(),
                "quota": quota_schema
            },
            "required": ["workspace", "operation_id", "from", "to", "sha256", "overwritten", "quota"],
            "additionalProperties": true
        }))),
        "work_delete" => Some(envelope(json!({
            "type": "object",
            "properties": {
                "workspace": st(),
                "operation_id": st(),
                "deleted_workspace": bl(),
                "deleted_files": {"type": "array", "items": st()},
                "freed_files": it(),
                "freed_bytes": it(),
                "quota": quota_schema
            },
            "required": [
                "workspace", "operation_id", "deleted_workspace",
                "deleted_files", "freed_files", "freed_bytes", "quota"
            ],
            "additionalProperties": true
        }))),
        _ => None,
    }
}
