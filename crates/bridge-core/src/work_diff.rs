//! Workspace diffing (`work_diff`), create-only `.diff` export to `_pro/outbox/`
//! (`work_export_diff`), and local owner journaled apply (`edge-bridge work-apply`).
//!
//! Security invariants:
//! - `compute_work_diff` performs zero writes on disk.
//! - Paths are never trusted from the workspace or any diff file without full
//!   `validate_remote_relative_path`, `!is_hidden_from_remote`, non-`_pro`, no-reparse,
//!   single-link (`n_links == 1`), and exact-case NTFS handle checks.
//! - Baseline hashes are loaded strictly from `<state_dir>/work-manifests/<project_id>/<workspace>.json`
//!   (owner-controlled state directory), never from inside `_pro/work/`.
//! - `apply_work_to_project` verifies every target before mutating any project file,
//!   applies all changes atomically (all-or-none), and writes a `PatchJournal` compatible
//!   with `ScopedFiles::rollback_patch_journal` (`edge-bridge rollback-patch`).

use crate::files::{
    DELEGATED_WRITE_MAX_SCOPE_BYTES, DELEGATED_WRITE_MAX_SCOPE_FILES,
    DELEGATED_WRITE_MAX_WALK_ENTRIES, MAX_PAGE_BYTES, MAX_READ_FILE_BYTES, PatchJournal,
    PatchJournalFileStep, ScopedFiles, char_page, is_hidden_from_remote, is_quota_link,
    lock_patch_root, patch_commit_conflict, patch_io_error, persist_patch_journal,
    read_delegated_work_file_verified, write_synced_new,
};
#[cfg(windows)]
use crate::files::{PatchParent, verify_opened_name, verify_work_preimage_handle};
use crate::policy::{
    PRO_WORK_PREFIX, has_windows_short_name, is_patch_stage_name, validate_remote_relative_path,
    validate_work_name,
};
use crate::work::{WorkManifest, WorkQuotaTelemetry, load_work_manifest, work_quota_telemetry};
#[cfg(windows)]
use bridge_platform::windows::{
    commit_patch_stage, create_patch_stage, file_identity_from_handle, file_path_from_handle,
    open_patch_directory, open_path_metadata_no_follow, open_read_no_follow,
};
use bridge_platform::sha256_bytes;
use bridge_types::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use similar::{ChangeTag, TextDiff};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const WORK_DIFF_MAX_PATHS: usize = 64;
pub const WORK_DIFF_MAX_WORKSPACE_FILES: usize = DELEGATED_WRITE_MAX_SCOPE_FILES;
/// Files above 1 MiB are hashed via streaming and listed in `work_diff` without diff text.
pub const WORK_DIFF_MAX_FILE_BYTES: u64 = 1024 * 1024;
pub const WORK_DIFF_MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;
pub const WORK_DIFF_DEFAULT_LIMIT: usize = 32_768;
pub const WORK_DIFF_MAX_LIMIT: usize = MAX_PAGE_BYTES;
pub const WORK_EXPORT_DIFF_MAX_BYTES: usize = 1024 * 1024;
pub const WORK_APPLY_MAX_FILE_BYTES: u64 = MAX_READ_FILE_BYTES;
const STREAM_HASH_CAP_BYTES: u64 = DELEGATED_WRITE_MAX_SCOPE_BYTES;

#[derive(Debug, Clone)]
pub struct WorkDiffRequest {
    pub workspace: String,
    pub paths: Option<Vec<String>>,
    pub summary_only: bool,
    pub expected_diff_sha256: Option<String>,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkDiffFileStat {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    pub status: String,
    pub insertions: u64,
    pub deletions: u64,
    pub binary: bool,
    pub oversized: bool,
    pub content_omitted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_sha256: Option<String>,
    pub drifted_from_baseline: bool,
    pub missing_in_live: bool,
    pub conflict_exists_in_project: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkDiffResult {
    pub workspace: String,
    pub diff_sha256: String,
    pub files_changed: usize,
    pub total_insertions: u64,
    pub total_deletions: u64,
    pub has_drift: bool,
    pub drifted_files: Vec<String>,
    pub conflict_files: Vec<String>,
    pub binary_or_oversized_files: Vec<String>,
    pub files: Vec<WorkDiffFileStat>,
    pub content: String,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub total_bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct WorkExportDiffRequest {
    pub workspace: String,
    pub operation_id: String,
    pub path: String,
    pub paths: Option<Vec<String>>,
    pub allow_drifted: bool,
    pub task_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkExportDiffResult {
    pub workspace: String,
    pub path: String,
    pub operation_id: String,
    pub journal_id: String,
    pub diff_sha256: String,
    pub bytes_written: usize,
    pub files_changed: usize,
    pub total_insertions: u64,
    pub total_deletions: u64,
    pub drifted_files: Vec<String>,
    pub quota: WorkQuotaTelemetry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkApplyFileChange {
    pub path: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postimage_sha256: Option<String>,
    pub binary: bool,
    pub oversized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkApplyResult {
    pub project_id: String,
    pub workspace: String,
    pub applied: bool,
    pub confirm_required: bool,
    pub safe_to_apply: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_id: Option<String>,
    pub files_changed: usize,
    pub files_modified: Vec<String>,
    pub files_added: Vec<String>,
    pub files_deleted: Vec<String>,
    pub drifted_files: Vec<String>,
    pub conflict_files: Vec<String>,
    pub postimage_hashes: BTreeMap<String, String>,
    pub changes: Vec<WorkApplyFileChange>,
    pub unified_diff: String,
    pub diff_sha256: String,
}

/// Validate that `raw_path` is strictly an exact-case flat `.diff` filename under `_pro/outbox/`:
/// `_pro/outbox/[a-zA-Z0-9][a-zA-Z0-9._-]{0,120}\.diff` with no subdirectories, `..`, short names,
/// hidden names, or case variation.
pub fn validate_outbox_diff_path(raw_path: &str) -> Result<String, BridgeError> {
    let parts = validate_remote_relative_path(raw_path)?;
    if is_hidden_from_remote(&parts) {
        return Err(BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            "Access to protected secret/credential path is denied.",
            OriginLayer::Policy,
        ));
    }
    if parts.len() != 3 || parts[0] != "_pro" || parts[1] != "outbox" {
        return Err(BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            "work_export_diff may only create a single '.diff' file directly under exact-case '_pro/outbox/'.",
            OriginLayer::Policy,
        )
        .with_next_action(
            "Use a flat path like '_pro/outbox/fix-1.diff' with exact lowercase '_pro/outbox/' and a '.diff' suffix.",
        ));
    }
    let filename = &parts[2];
    let Some(stem) = filename.strip_suffix(".diff") else {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "Export path filename must end with lowercase '.diff'.",
            OriginLayer::Validation,
        ));
    };
    let stem_bytes = stem.as_bytes();
    let valid_stem = !stem_bytes.is_empty()
        && stem_bytes.len() <= 121
        && stem_bytes[0].is_ascii_alphanumeric()
        && stem_bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !filename.contains("..");
    if !valid_stem {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "Export filename must match '[a-zA-Z0-9][a-zA-Z0-9._-]{0,120}.diff' without '..'.",
            OriginLayer::Validation,
        ));
    }
    Ok(parts.join("/"))
}

fn hidden_denied() -> BridgeError {
    BridgeError::new(
        ErrorCode::BridgePolicyDenied,
        "Access to protected secret/credential path is denied.",
        OriginLayer::FileService,
    )
    .with_next_action(
        "Protected secret and credential paths cannot be accessed remotely even with a grant; choose a non-protected project path.",
    )
}

fn validate_project_target_rel(raw: &str, require_canonical: bool) -> Result<String, BridgeError> {
    let parts = validate_remote_relative_path(raw)?;
    if parts.is_empty() {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "Target path cannot be empty or '.'.",
            OriginLayer::Validation,
        ));
    }
    if is_hidden_from_remote(&parts) {
        return Err(hidden_denied());
    }
    if parts[0].eq_ignore_ascii_case("_pro") {
        return Err(BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            "Paths under '_pro' cannot be targeted as live project files.",
            OriginLayer::Policy,
        ));
    }
    let canonical = parts.join("/");
    if require_canonical && canonical != raw {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            format!("Non-canonical manifest path '{raw}' refused."),
            OriginLayer::Validation,
        ));
    }
    Ok(canonical)
}

fn normalize_paths_filter(paths: Option<&[String]>) -> Result<Option<Vec<String>>, BridgeError> {
    let Some(raw_paths) = paths else {
        return Ok(None);
    };
    if raw_paths.is_empty() || raw_paths.len() > WORK_DIFF_MAX_PATHS {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            format!("'paths' filter must contain between 1 and {WORK_DIFF_MAX_PATHS} entries when provided."),
            OriginLayer::Validation,
        ));
    }
    let mut out = Vec::with_capacity(raw_paths.len());
    for raw in raw_paths {
        out.push(validate_project_target_rel(raw, false)?);
    }
    Ok(Some(out))
}

fn matches_filter(rel: &str, filters: Option<&[String]>) -> bool {
    let Some(filters) = filters else {
        return true;
    };
    filters.iter().any(|f| {
        rel == f
            || rel
                .strip_prefix(f.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

#[cfg(windows)]
fn open_verified_root(root: &Path, cur_rid: &str) -> Result<(File, PathBuf), BridgeError> {
    let handle = open_patch_directory(root).map_err(patch_io_error)?;
    let id = file_identity_from_handle(&handle)?;
    if !id.is_directory || id.is_reparse_point || id.canonical_id() != cur_rid {
        return Err(BridgeError::new(
            ErrorCode::StalePrecondition,
            "Project root identity changed or became a reparse point.",
            OriginLayer::FileService,
        ));
    }
    let path = file_path_from_handle(&handle)?;
    Ok((handle, path))
}

#[cfg(windows)]
fn open_delete_handle_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const GENERIC_READ: u32 = 0x8000_0000;
    const DELETE: u32 = 0x0001_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ | DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

#[cfg(not(windows))]
fn check_no_symlink_prefix(root: &Path, rel: &str) -> Result<(), BridgeError> {
    let parts = validate_remote_relative_path(rel)?;
    let mut cur = root.to_path_buf();
    for (idx, seg) in parts.iter().enumerate() {
        cur.push(seg);
        let is_last = idx + 1 == parts.len();
        match fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(BridgeError::new(
                        ErrorCode::UnsupportedPathType,
                        format!("Symlink denied at segment '{seg}'."),
                        OriginLayer::FileService,
                    ));
                }
                if !is_last && !meta.is_dir() {
                    return Err(BridgeError::new(
                        ErrorCode::UnsupportedPathType,
                        "Intermediate path component is not a directory.",
                        OriginLayer::FileService,
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(patch_io_error(error)),
        }
    }
    Ok(())
}

/// Verified metadata & optional UTF-8 text of a file read through a single no-follow handle.
struct InspectedFile {
    sha256: String,
    #[allow(dead_code)]
    size_bytes: u64,
    binary: bool,
    oversized: bool,
    text: Option<String>,
}

/// Inspect a file for diffing strictly without following links, verifying exact long name
/// on NTFS and `n_links == 1`. Returns `Ok(None)` when the file does not exist.
/// Files larger than `WORK_DIFF_MAX_FILE_BYTES` are hashed via streaming without buffering
/// their content in memory.
fn inspect_file_for_diff(
    project_root: &Path,
    cur_rid: &str,
    root_path_opt: Option<&Path>,
    rel: &str,
    read_content: bool,
) -> Result<Option<InspectedFile>, BridgeError> {
    #[cfg(windows)]
    let _parent = PatchParent::pin(project_root, cur_rid, rel, true, false, None)?;
    #[cfg(not(windows))]
    {
        let _ = cur_rid;
        check_no_symlink_prefix(project_root, rel)?;
    }

    let full = project_root.join(rel);
    #[cfg(windows)]
    let (mut file, size_hint) = {
        let meta_handle = match open_path_metadata_no_follow(&full) {
            Ok(h) => h,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(patch_io_error(e)),
        };
        let pre_id = file_identity_from_handle(&meta_handle)?;
        if pre_id.is_reparse_point || pre_id.is_directory || pre_id.n_links != 1 {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("Target '{rel}' must be a regular single-link non-reparse file."),
                OriginLayer::FileService,
            ));
        }
        let file = match open_read_no_follow(&full) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(patch_io_error(e)),
        };
        let open_id = file_identity_from_handle(&file)?;
        if open_id.is_reparse_point || open_id.is_directory || open_id.n_links != 1 {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("Target '{rel}' must be a regular single-link non-reparse file."),
                OriginLayer::FileService,
            ));
        }
        if open_id.canonical_id() != pre_id.canonical_id() {
            return Err(BridgeError::new(
                ErrorCode::StalePrecondition,
                "File identity changed concurrently while inspecting.",
                OriginLayer::FileService,
            ));
        }
        if let Some(root_path) = root_path_opt {
            verify_opened_name(root_path, Path::new(rel), &file_path_from_handle(&file)?)?;
        }
        (file, open_id.size_bytes)
    };
    #[cfg(not(windows))]
    let (mut file, size_hint) = {
        let _ = root_path_opt;
        let meta = match fs::symlink_metadata(&full) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(patch_io_error(e)),
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("Target '{rel}' must be a regular single-link non-reparse file."),
                OriginLayer::FileService,
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.nlink() != 1 {
                return Err(BridgeError::new(
                    ErrorCode::UnsupportedPathType,
                    format!("Target '{rel}' must be a regular single-link non-reparse file."),
                    OriginLayer::FileService,
                ));
            }
        }
        let file = match File::open(&full) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(patch_io_error(e)),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let om = file.metadata().map_err(patch_io_error)?;
            if om.dev() != meta.dev() || om.ino() != meta.ino() || om.nlink() != 1 {
                return Err(BridgeError::new(
                    ErrorCode::UnsupportedPathType,
                    format!("Target '{rel}' changed or has multiple links."),
                    OriginLayer::FileService,
                ));
            }
        }
        (file, meta.len())
    };

    if !read_content {
        return Ok(Some(InspectedFile {
            sha256: String::new(),
            size_bytes: size_hint,
            binary: false,
            oversized: size_hint > WORK_DIFF_MAX_FILE_BYTES,
            text: None,
        }));
    }

    let mut hasher = Sha256::new();
    let mut total_len: u64 = 0;
    let mut oversized = size_hint > WORK_DIFF_MAX_FILE_BYTES;
    let mut first_8k = Vec::with_capacity(8192);
    let mut buffered = if oversized {
        Vec::new()
    } else {
        Vec::with_capacity((size_hint as usize).min(WORK_DIFF_MAX_FILE_BYTES as usize))
    };
    let mut chunk = [0u8; 65536];
    loop {
        let n = file.read(&mut chunk).map_err(patch_io_error)?;
        if n == 0 {
            break;
        }
        let slice = &chunk[..n];
        hasher.update(slice);
        if first_8k.len() < 8192 {
            let need = (8192 - first_8k.len()).min(n);
            first_8k.extend_from_slice(&slice[..need]);
        }
        total_len = total_len.saturating_add(n as u64);
        if total_len > STREAM_HASH_CAP_BYTES {
            return Err(BridgeError::new(
                ErrorCode::ResourceBudgetExceeded,
                format!("File '{rel}' exceeds maximum inspectable size."),
                OriginLayer::FileService,
            ));
        }
        if !oversized {
            if total_len > WORK_DIFF_MAX_FILE_BYTES {
                oversized = true;
                buffered.clear();
                buffered.shrink_to_fit();
            } else {
                buffered.extend_from_slice(slice);
            }
        }
    }

    let sha256 = hex::encode(hasher.finalize());
    let has_nul = first_8k.contains(&0);
    if oversized {
        return Ok(Some(InspectedFile {
            sha256,
            size_bytes: total_len,
            binary: has_nul,
            oversized: true,
            text: None,
        }));
    }
    if has_nul {
        return Ok(Some(InspectedFile {
            sha256,
            size_bytes: total_len,
            binary: true,
            oversized: false,
            text: None,
        }));
    }
    match String::from_utf8(buffered) {
        Ok(text) => Ok(Some(InspectedFile {
            sha256,
            size_bytes: total_len,
            binary: false,
            oversized: false,
            text: Some(text),
        })),
        Err(_) => Ok(Some(InspectedFile {
            sha256,
            size_bytes: total_len,
            binary: true,
            oversized: false,
            text: None,
        })),
    }
}

/// Pin `_pro/work/<workspace>`, load & verify `<state_dir>/work-manifests/<project_id>/<workspace>.json`,
/// validate all manifest keys, and collect all workspace-relative file paths inside `_pro/work/<workspace>/`.
///
/// Refuses any junction/symlink, hardlink (`n_links != 1`), wrong case on NTFS, short name,
/// hidden/secret path, or `_pro` subpath. Skips `.eb_stage_*` staging files.
fn load_verified_workspace(
    project_root: &Path,
    cur_rid: &str,
    root_path_opt: Option<&Path>,
    state_dir: &Path,
    project_id: &str,
    workspace: &str,
) -> Result<(WorkManifest, BTreeSet<String>), BridgeError> {
    let ws_rel = format!("{PRO_WORK_PREFIX}{workspace}");
    #[cfg(windows)]
    let ws_pin = PatchParent::pin_dir_existing(project_root, cur_rid, &ws_rel, true)?;
    #[cfg(not(windows))]
    let ws_pin: Option<PathBuf> = {
        check_no_symlink_prefix(project_root, &ws_rel)?;
        let p = project_root.join(&ws_rel);
        match fs::symlink_metadata(&p) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err(BridgeError::new(
                        ErrorCode::UnsupportedPathType,
                        format!("Workspace path '{ws_rel}' is a link or non-directory."),
                        OriginLayer::FileService,
                    ));
                }
                Some(p)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(patch_io_error(e)),
        }
    };

    let manifest = load_work_manifest(state_dir, project_id, workspace)?.ok_or_else(|| {
        BridgeError::new(
            ErrorCode::NotFound,
            format!("Work manifest for workspace '{workspace}' does not exist."),
            OriginLayer::FileService,
        )
    })?;
    if manifest.project_id != project_id
        || manifest.workspace != workspace
        || (cur_rid.starts_with("ntfs:") && manifest.root_identity != cur_rid)
    {
        return Err(BridgeError::new(
            ErrorCode::StalePrecondition,
            format!("Work manifest for workspace '{workspace}' does not match this project root identity."),
            OriginLayer::FileService,
        ));
    }

    let ws_pin = ws_pin.ok_or_else(|| {
        BridgeError::new(
            ErrorCode::NotFound,
            format!("Workspace directory '{ws_rel}' does not exist."),
            OriginLayer::FileService,
        )
    })?;

    // Validate EVERY key recorded in the bridge manifest through the exact file-service path rules.
    let mut manifest_case_keys = HashSet::with_capacity(manifest.entries.len());
    for key in manifest.entries.keys() {
        validate_project_target_rel(key, true)?;
        if !manifest_case_keys.insert(key.to_ascii_lowercase()) {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                "Work manifest contains case-colliding paths.",
                OriginLayer::Validation,
            ));
        }
    }

    #[cfg(windows)]
    let ws_dir_path = ws_pin.path.clone();
    #[cfg(not(windows))]
    let ws_dir_path = ws_pin;

    let mut work_files = BTreeSet::new();
    let mut seen_case = HashSet::new();
    let mut walked_entries: usize = 0;
    let mut stack: Vec<(PathBuf, Vec<String>)> = vec![(ws_dir_path.clone(), Vec::new())];

    while let Some((cur_dir, rel_parts)) = stack.pop() {
        let reader = fs::read_dir(&cur_dir).map_err(patch_io_error)?;
        let mut children = Vec::new();
        for entry in reader {
            let entry = entry.map_err(patch_io_error)?;
            walked_entries += 1;
            if walked_entries > DELEGATED_WRITE_MAX_WALK_ENTRIES {
                return Err(BridgeError::new(
                    ErrorCode::ResourceBudgetExceeded,
                    format!(
                        "Workspace '{workspace}' exceeds the {DELEGATED_WRITE_MAX_WALK_ENTRIES}-entry scan limit."
                    ),
                    OriginLayer::FileService,
                ));
            }
            children.push(entry);
        }
        children.sort_by_key(|e| e.file_name());

        let mut subdirs = Vec::new();
        for entry in children {
            let child_path = entry.path();
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return Err(BridgeError::new(
                    ErrorCode::UnsupportedPathType,
                    "Workspace contains a non-UTF-8 path name.",
                    OriginLayer::FileService,
                ));
            };
            if is_patch_stage_name(&name) {
                continue;
            }
            let mut child_parts = rel_parts.clone();
            child_parts.push(name.clone());
            let sub_rel = child_parts.join("/");
            // Validate every path inside `_pro/work/<workspace>/` before inspecting or naming it.
            let validated_sub = validate_project_target_rel(&sub_rel, true)?;
            if has_windows_short_name(&child_parts) {
                return Err(BridgeError::new(
                    ErrorCode::BridgePolicyDenied,
                    "Windows short-name components are not allowed.",
                    OriginLayer::FileService,
                ));
            }
            let full_work_rel = format!("{ws_rel}/{validated_sub}");

            #[cfg(windows)]
            {
                let h = open_path_metadata_no_follow(&child_path).map_err(patch_io_error)?;
                let id = file_identity_from_handle(&h)?;
                if id.is_reparse_point {
                    return Err(BridgeError::new(
                        ErrorCode::UnsupportedPathType,
                        format!("Reparse point / junction denied inside workspace at '{full_work_rel}'."),
                        OriginLayer::FileService,
                    ));
                }
                let obs = file_path_from_handle(&h)?;
                if let Some(rp) = root_path_opt {
                    verify_opened_name(rp, Path::new(&full_work_rel), &obs)?;
                }
                if id.is_directory {
                    subdirs.push((child_path, child_parts));
                } else {
                    if id.n_links != 1 {
                        return Err(BridgeError::new(
                            ErrorCode::UnsupportedPathType,
                            format!("Hardlinked file denied inside workspace at '{full_work_rel}'."),
                            OriginLayer::FileService,
                        ));
                    }
                    if !seen_case.insert(validated_sub.to_ascii_lowercase()) {
                        return Err(BridgeError::new(
                            ErrorCode::InvalidArgument,
                            "Workspace contains case-colliding filenames.",
                            OriginLayer::Validation,
                        ));
                    }
                    if work_files.len() + 1 > WORK_DIFF_MAX_WORKSPACE_FILES {
                        return Err(BridgeError::new(
                            ErrorCode::ResourceBudgetExceeded,
                            format!(
                                "Workspace '{workspace}' exceeds the {WORK_DIFF_MAX_WORKSPACE_FILES}-file diff limit."
                            ),
                            OriginLayer::FileService,
                        ));
                    }
                    work_files.insert(validated_sub);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (root_path_opt, &full_work_rel);
                let meta = fs::symlink_metadata(&child_path).map_err(patch_io_error)?;
                if meta.file_type().is_symlink() {
                    return Err(BridgeError::new(
                        ErrorCode::UnsupportedPathType,
                        format!("Symlink denied inside workspace at '{full_work_rel}'."),
                        OriginLayer::FileService,
                    ));
                }
                if meta.is_dir() {
                    subdirs.push((child_path, child_parts));
                } else if meta.is_file() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        if meta.nlink() != 1 {
                            return Err(BridgeError::new(
                                ErrorCode::UnsupportedPathType,
                                format!("Hardlinked file denied inside workspace at '{full_work_rel}'."),
                                OriginLayer::FileService,
                            ));
                        }
                    }
                    if !seen_case.insert(validated_sub.to_ascii_lowercase()) {
                        return Err(BridgeError::new(
                            ErrorCode::InvalidArgument,
                            "Workspace contains case-colliding filenames.",
                            OriginLayer::Validation,
                        ));
                    }
                    if work_files.len() + 1 > WORK_DIFF_MAX_WORKSPACE_FILES {
                        return Err(BridgeError::new(
                            ErrorCode::ResourceBudgetExceeded,
                            format!(
                                "Workspace '{workspace}' exceeds the {WORK_DIFF_MAX_WORKSPACE_FILES}-file diff limit."
                            ),
                            OriginLayer::FileService,
                        ));
                    }
                    work_files.insert(validated_sub);
                } else {
                    return Err(BridgeError::new(
                        ErrorCode::UnsupportedPathType,
                        format!("Unsupported file type inside workspace at '{full_work_rel}'."),
                        OriginLayer::FileService,
                    ));
                }
            }
        }
        for sub in subdirs.into_iter().rev() {
            stack.push(sub);
        }
    }

    Ok((manifest, work_files))
}

/// Format a path token for Git unified diff headers (`a/<rel>`, `b/<rel>`, or `<rel>`).
/// Quotes with Git C-style escapes when spaces, quotes, backslashes, control bytes, or
/// non-ASCII UTF-8 bytes are present so `git apply` parses every path unambiguously.
fn git_format_path(path: &str) -> String {
    let needs_quote = path
        .bytes()
        .any(|b| b <= 0x20 || b >= 0x7f || b == b'"' || b == b'\\');
    if !needs_quote {
        return path.to_owned();
    }
    let mut out = String::with_capacity(path.len() + 4);
    out.push('"');
    for b in path.bytes() {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            other => {
                out.push_str(&format!("\\{:03o}", other));
            }
        }
    }
    out.push('"');
    out
}

/// Emit `git apply`-compatible unified diff hunks and return `(diff_section, insertions, deletions)`.
fn format_unified_text_hunks(old_text: &str, new_text: &str) -> (String, u64, u64) {
    let diff = TextDiff::from_lines(old_text, new_text);
    let mut out = String::new();
    let mut insertions = 0u64;
    let mut deletions = 0u64;
    for group in diff.grouped_ops(3) {
        if group.is_empty() {
            continue;
        }
        let old_start_idx = group[0].old_range().start;
        let old_end_idx = group.last().unwrap().old_range().end;
        let new_start_idx = group[0].new_range().start;
        let new_end_idx = group.last().unwrap().new_range().end;
        let old_len = old_end_idx - old_start_idx;
        let new_len = new_end_idx - new_start_idx;
        let old_start = if old_len == 0 {
            old_start_idx
        } else {
            old_start_idx + 1
        };
        let new_start = if new_len == 0 {
            new_start_idx
        } else {
            new_start_idx + 1
        };
        out.push_str(&format!(
            "@@ -{old_start},{old_len} +{new_start},{new_len} @@\n"
        ));
        for op in group {
            for change in diff.iter_changes(&op) {
                let sign = match change.tag() {
                    ChangeTag::Equal => ' ',
                    ChangeTag::Delete => {
                        deletions += 1;
                        '-'
                    }
                    ChangeTag::Insert => {
                        insertions += 1;
                        '+'
                    }
                };
                out.push(sign);
                let val = change.value();
                out.push_str(val);
                if !val.ends_with('\n') {
                    out.push_str("\n\\ No newline at end of file\n");
                }
            }
        }
    }
    (out, insertions, deletions)
}

fn format_modified_section(rel: &str, old_text: &str, new_text: &str) -> (String, u64, u64) {
    let (hunks, ins, dels) = format_unified_text_hunks(old_text, new_text);
    if hunks.is_empty() {
        return (String::new(), 0, 0);
    }
    let a = git_format_path(&format!("a/{rel}"));
    let b = git_format_path(&format!("b/{rel}"));
    let mut out = String::with_capacity(hunks.len() + a.len() * 2 + 48);
    out.push_str(&format!("diff --git {a} {b}\n--- {a}\n+++ {b}\n"));
    out.push_str(&hunks);
    (out, ins, dels)
}

fn format_added_section(rel: &str, new_text: &str) -> (String, u64, u64) {
    let a = git_format_path(&format!("a/{rel}"));
    let b = git_format_path(&format!("b/{rel}"));
    if new_text.is_empty() {
        return (
            format!("diff --git {a} {b}\nnew file mode 100644\n"),
            0,
            0,
        );
    }
    let (hunks, ins, dels) = format_unified_text_hunks("", new_text);
    let mut out = String::with_capacity(hunks.len() + a.len() * 2 + 72);
    out.push_str(&format!(
        "diff --git {a} {b}\nnew file mode 100644\n--- /dev/null\n+++ {b}\n"
    ));
    out.push_str(&hunks);
    (out, ins, dels)
}

fn format_deleted_section(rel: &str, old_text: &str) -> (String, u64, u64) {
    let a = git_format_path(&format!("a/{rel}"));
    let b = git_format_path(&format!("b/{rel}"));
    if old_text.is_empty() {
        return (
            format!("diff --git {a} {b}\ndeleted file mode 100644\n"),
            0,
            0,
        );
    }
    let (hunks, ins, dels) = format_unified_text_hunks(old_text, "");
    let mut out = String::with_capacity(hunks.len() + a.len() * 2 + 72);
    out.push_str(&format!(
        "diff --git {a} {b}\ndeleted file mode 100644\n--- {a}\n+++ /dev/null\n"
    ));
    out.push_str(&hunks);
    (out, ins, dels)
}

fn format_exact_rename_section(old_rel: &str, new_rel: &str) -> String {
    let a = git_format_path(&format!("a/{old_rel}"));
    let b = git_format_path(&format!("b/{new_rel}"));
    let from = git_format_path(old_rel);
    let to = git_format_path(new_rel);
    format!(
        "diff --git {a} {b}\nsimilarity index 100%\nrename from {from}\nrename to {to}\n"
    )
}

struct FullDiffComputed {
    full_diff: String,
    diff_sha256: String,
    files_changed: usize,
    total_insertions: u64,
    total_deletions: u64,
    drifted_files: Vec<String>,
    conflict_files: Vec<String>,
    binary_or_oversized_files: Vec<String>,
    files: Vec<WorkDiffFileStat>,
}

enum RawCandidate {
    Modified {
        rel: String,
        baseline_sha256: String,
        live: InspectedFile,
        work: InspectedFile,
        drifted: bool,
    },
    AddedFromMissingLive {
        rel: String,
        baseline_sha256: String,
        work: InspectedFile,
    },
    Deleted {
        rel: String,
        baseline_sha256: String,
        live: InspectedFile,
        drifted: bool,
    },
    DeletedMissingInLive {
        rel: String,
        baseline_sha256: String,
    },
    Added {
        rel: String,
        work: InspectedFile,
        conflict_exists_in_project: bool,
    },
    UnchangedDrifted {
        rel: String,
        baseline_sha256: String,
        live_sha256: String,
        work_sha256: String,
        binary: bool,
        oversized: bool,
    },
}

fn compute_full_diff_internal(
    project_root: &Path,
    cur_rid: &str,
    root_path_opt: Option<&Path>,
    state_dir: &Path,
    project_id: &str,
    workspace: &str,
    paths_filter: Option<&[String]>,
    max_diff_bytes: usize,
) -> Result<FullDiffComputed, BridgeError> {
    let (manifest, work_files) = load_verified_workspace(
        project_root,
        cur_rid,
        root_path_opt,
        state_dir,
        project_id,
        workspace,
    )?;

    let mut all_paths = BTreeSet::new();
    for k in manifest.entries.keys() {
        if matches_filter(k, paths_filter) {
            all_paths.insert(k.clone());
        }
    }
    for k in &work_files {
        if matches_filter(k, paths_filter) {
            all_paths.insert(k.clone());
        }
    }

    let ws_rel = format!("{PRO_WORK_PREFIX}{workspace}");
    let mut candidates = Vec::new();

    for rel in all_paths {
        let in_manifest = manifest.entries.get(&rel);
        let in_work = work_files.contains(&rel);
        match (in_manifest, in_work) {
            (Some(entry), true) => {
                let work_path = format!("{ws_rel}/{rel}");
                let Some(work_info) =
                    inspect_file_for_diff(project_root, cur_rid, root_path_opt, &work_path, true)?
                else {
                    continue;
                };
                let live_opt =
                    inspect_file_for_diff(project_root, cur_rid, root_path_opt, &rel, true)?;
                match live_opt {
                    Some(live_info) => {
                        let drifted = !live_info
                            .sha256
                            .eq_ignore_ascii_case(&entry.baseline_sha256);
                        if live_info.sha256.eq_ignore_ascii_case(&work_info.sha256) {
                            if drifted {
                                candidates.push(RawCandidate::UnchangedDrifted {
                                    rel,
                                    baseline_sha256: entry.baseline_sha256.clone(),
                                    live_sha256: live_info.sha256,
                                    work_sha256: work_info.sha256,
                                    binary: live_info.binary || work_info.binary,
                                    oversized: live_info.oversized || work_info.oversized,
                                });
                            }
                        } else {
                            candidates.push(RawCandidate::Modified {
                                rel,
                                baseline_sha256: entry.baseline_sha256.clone(),
                                live: live_info,
                                work: work_info,
                                drifted,
                            });
                        }
                    }
                    None => {
                        candidates.push(RawCandidate::AddedFromMissingLive {
                            rel,
                            baseline_sha256: entry.baseline_sha256.clone(),
                            work: work_info,
                        });
                    }
                }
            }
            (Some(entry), false) => {
                let live_opt =
                    inspect_file_for_diff(project_root, cur_rid, root_path_opt, &rel, true)?;
                match live_opt {
                    Some(live_info) => {
                        let drifted = !live_info
                            .sha256
                            .eq_ignore_ascii_case(&entry.baseline_sha256);
                        candidates.push(RawCandidate::Deleted {
                            rel,
                            baseline_sha256: entry.baseline_sha256.clone(),
                            live: live_info,
                            drifted,
                        });
                    }
                    None => {
                        candidates.push(RawCandidate::DeletedMissingInLive {
                            rel,
                            baseline_sha256: entry.baseline_sha256.clone(),
                        });
                    }
                }
            }
            (None, true) => {
                let work_path = format!("{ws_rel}/{rel}");
                let Some(work_info) =
                    inspect_file_for_diff(project_root, cur_rid, root_path_opt, &work_path, true)?
                else {
                    continue;
                };
                // Check live path safety (no junction/link/wrong case) without reading live content.
                let live_exists = inspect_file_for_diff(
                    project_root,
                    cur_rid,
                    root_path_opt,
                    &rel,
                    false,
                )?
                .is_some();
                candidates.push(RawCandidate::Added {
                    rel,
                    work: work_info,
                    conflict_exists_in_project: live_exists,
                });
            }
            (None, false) => {}
        }
    }

    // Detect exact-content 1-to-1 renames between Deleted and non-conflicting Added text files
    // (e.g. created by `work_move`) so `git apply` sees clean Git rename headers.
    let mut deleted_by_sha: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut added_by_sha: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (idx, cand) in candidates.iter().enumerate() {
        match cand {
            RawCandidate::Deleted {
                live,
                drifted: false,
                ..
            } if !live.binary && !live.oversized => {
                deleted_by_sha
                    .entry(live.sha256.clone())
                    .or_default()
                    .push(idx);
            }
            RawCandidate::Added {
                work,
                conflict_exists_in_project: false,
                ..
            } if !work.binary && !work.oversized => {
                added_by_sha
                    .entry(work.sha256.clone())
                    .or_default()
                    .push(idx);
            }
            _ => {}
        }
    }
    let mut rename_from_for_add: BTreeMap<usize, usize> = BTreeMap::new();
    let mut consumed_deletes: HashSet<usize> = HashSet::new();
    for (sha, del_idxs) in &deleted_by_sha {
        if let Some(add_idxs) = added_by_sha.get(sha) {
            for (&del_idx, &add_idx) in del_idxs.iter().zip(add_idxs.iter()) {
                rename_from_for_add.insert(add_idx, del_idx);
                consumed_deletes.insert(del_idx);
            }
        }
    }

    let mut full_diff = String::new();
    let mut total_insertions: u64 = 0;
    let mut total_deletions: u64 = 0;
    let mut files_changed: usize = 0;
    let mut drifted_files = Vec::new();
    let mut conflict_files = Vec::new();
    let mut binary_or_oversized_files = Vec::new();
    let mut stats = Vec::new();

    let push_section = |buf: &mut String, section: &str| -> Result<(), BridgeError> {
        if buf.len().saturating_add(section.len()) > max_diff_bytes {
            return Err(BridgeError::new(
                ErrorCode::ResourceBudgetExceeded,
                format!(
                    "Generated diff exceeds the {} MiB limit; narrow with 'paths' or inspect files individually.",
                    max_diff_bytes / (1024 * 1024)
                ),
                OriginLayer::FileService,
            ));
        }
        buf.push_str(section);
        Ok(())
    };

    for (idx, cand) in candidates.iter().enumerate() {
        if consumed_deletes.contains(&idx) {
            continue;
        }
        if let Some(&del_idx) = rename_from_for_add.get(&idx) {
            if let (
                RawCandidate::Deleted {
                    rel: old_rel,
                    baseline_sha256,
                    live,
                    ..
                },
                RawCandidate::Added {
                    rel: new_rel,
                    work,
                    ..
                },
            ) = (&candidates[del_idx], cand)
            {
                let section = format_exact_rename_section(old_rel, new_rel);
                push_section(&mut full_diff, &section)?;
                files_changed += 1;
                stats.push(WorkDiffFileStat {
                    path: new_rel.clone(),
                    old_path: Some(old_rel.clone()),
                    status: "renamed".to_owned(),
                    insertions: 0,
                    deletions: 0,
                    binary: false,
                    oversized: false,
                    content_omitted: false,
                    baseline_sha256: Some(baseline_sha256.clone()),
                    live_sha256: Some(live.sha256.clone()),
                    work_sha256: Some(work.sha256.clone()),
                    drifted_from_baseline: false,
                    missing_in_live: false,
                    conflict_exists_in_project: false,
                });
                continue;
            }
        }

        match cand {
            RawCandidate::Modified {
                rel,
                baseline_sha256,
                live,
                work,
                drifted,
            } => {
                if *drifted {
                    drifted_files.push(rel.clone());
                }
                let is_oversized = live.oversized || work.oversized;
                let is_binary = live.binary || work.binary;
                files_changed += 1;
                if is_oversized || is_binary {
                    binary_or_oversized_files.push(rel.clone());
                    let status = if is_oversized {
                        "oversized_modified"
                    } else {
                        "binary_modified"
                    };
                    stats.push(WorkDiffFileStat {
                        path: rel.clone(),
                        old_path: None,
                        status: status.to_owned(),
                        insertions: 0,
                        deletions: 0,
                        binary: is_binary,
                        oversized: is_oversized,
                        content_omitted: true,
                        baseline_sha256: Some(baseline_sha256.clone()),
                        live_sha256: Some(live.sha256.clone()),
                        work_sha256: Some(work.sha256.clone()),
                        drifted_from_baseline: *drifted,
                        missing_in_live: false,
                        conflict_exists_in_project: false,
                    });
                } else {
                    let old_t = live.text.as_deref().unwrap_or("");
                    let new_t = work.text.as_deref().unwrap_or("");
                    let (section, ins, dels) = format_modified_section(rel, old_t, new_t);
                    push_section(&mut full_diff, &section)?;
                    total_insertions += ins;
                    total_deletions += dels;
                    stats.push(WorkDiffFileStat {
                        path: rel.clone(),
                        old_path: None,
                        status: "modified".to_owned(),
                        insertions: ins,
                        deletions: dels,
                        binary: false,
                        oversized: false,
                        content_omitted: false,
                        baseline_sha256: Some(baseline_sha256.clone()),
                        live_sha256: Some(live.sha256.clone()),
                        work_sha256: Some(work.sha256.clone()),
                        drifted_from_baseline: *drifted,
                        missing_in_live: false,
                        conflict_exists_in_project: false,
                    });
                }
            }
            RawCandidate::AddedFromMissingLive {
                rel,
                baseline_sha256,
                work,
            } => {
                drifted_files.push(rel.clone());
                files_changed += 1;
                if work.oversized || work.binary {
                    binary_or_oversized_files.push(rel.clone());
                    let status = if work.oversized {
                        "oversized_added"
                    } else {
                        "binary_added"
                    };
                    stats.push(WorkDiffFileStat {
                        path: rel.clone(),
                        old_path: None,
                        status: status.to_owned(),
                        insertions: 0,
                        deletions: 0,
                        binary: work.binary,
                        oversized: work.oversized,
                        content_omitted: true,
                        baseline_sha256: Some(baseline_sha256.clone()),
                        live_sha256: None,
                        work_sha256: Some(work.sha256.clone()),
                        drifted_from_baseline: true,
                        missing_in_live: true,
                        conflict_exists_in_project: false,
                    });
                } else {
                    let new_t = work.text.as_deref().unwrap_or("");
                    let (section, ins, dels) = format_added_section(rel, new_t);
                    push_section(&mut full_diff, &section)?;
                    total_insertions += ins;
                    total_deletions += dels;
                    stats.push(WorkDiffFileStat {
                        path: rel.clone(),
                        old_path: None,
                        status: "added".to_owned(),
                        insertions: ins,
                        deletions: dels,
                        binary: false,
                        oversized: false,
                        content_omitted: false,
                        baseline_sha256: Some(baseline_sha256.clone()),
                        live_sha256: None,
                        work_sha256: Some(work.sha256.clone()),
                        drifted_from_baseline: true,
                        missing_in_live: true,
                        conflict_exists_in_project: false,
                    });
                }
            }
            RawCandidate::Deleted {
                rel,
                baseline_sha256,
                live,
                drifted,
            } => {
                if *drifted {
                    drifted_files.push(rel.clone());
                }
                files_changed += 1;
                if live.oversized || live.binary {
                    binary_or_oversized_files.push(rel.clone());
                    let status = if live.oversized {
                        "oversized_deleted"
                    } else {
                        "binary_deleted"
                    };
                    stats.push(WorkDiffFileStat {
                        path: rel.clone(),
                        old_path: None,
                        status: status.to_owned(),
                        insertions: 0,
                        deletions: 0,
                        binary: live.binary,
                        oversized: live.oversized,
                        content_omitted: true,
                        baseline_sha256: Some(baseline_sha256.clone()),
                        live_sha256: Some(live.sha256.clone()),
                        work_sha256: None,
                        drifted_from_baseline: *drifted,
                        missing_in_live: false,
                        conflict_exists_in_project: false,
                    });
                } else {
                    let old_t = live.text.as_deref().unwrap_or("");
                    let (section, ins, dels) = format_deleted_section(rel, old_t);
                    push_section(&mut full_diff, &section)?;
                    total_insertions += ins;
                    total_deletions += dels;
                    stats.push(WorkDiffFileStat {
                        path: rel.clone(),
                        old_path: None,
                        status: "deleted".to_owned(),
                        insertions: ins,
                        deletions: dels,
                        binary: false,
                        oversized: false,
                        content_omitted: false,
                        baseline_sha256: Some(baseline_sha256.clone()),
                        live_sha256: Some(live.sha256.clone()),
                        work_sha256: None,
                        drifted_from_baseline: *drifted,
                        missing_in_live: false,
                        conflict_exists_in_project: false,
                    });
                }
            }
            RawCandidate::DeletedMissingInLive {
                rel,
                baseline_sha256,
            } => {
                drifted_files.push(rel.clone());
                stats.push(WorkDiffFileStat {
                    path: rel.clone(),
                    old_path: None,
                    status: "unchanged".to_owned(),
                    insertions: 0,
                    deletions: 0,
                    binary: false,
                    oversized: false,
                    content_omitted: false,
                    baseline_sha256: Some(baseline_sha256.clone()),
                    live_sha256: None,
                    work_sha256: None,
                    drifted_from_baseline: true,
                    missing_in_live: true,
                    conflict_exists_in_project: false,
                });
            }
            RawCandidate::Added {
                rel,
                work,
                conflict_exists_in_project,
            } => {
                if *conflict_exists_in_project {
                    conflict_files.push(rel.clone());
                }
                files_changed += 1;
                if work.oversized || work.binary {
                    binary_or_oversized_files.push(rel.clone());
                    let status = if work.oversized {
                        "oversized_added"
                    } else {
                        "binary_added"
                    };
                    stats.push(WorkDiffFileStat {
                        path: rel.clone(),
                        old_path: None,
                        status: status.to_owned(),
                        insertions: 0,
                        deletions: 0,
                        binary: work.binary,
                        oversized: work.oversized,
                        content_omitted: true,
                        baseline_sha256: None,
                        live_sha256: None,
                        work_sha256: Some(work.sha256.clone()),
                        drifted_from_baseline: false,
                        missing_in_live: false,
                        conflict_exists_in_project: *conflict_exists_in_project,
                    });
                } else {
                    let new_t = work.text.as_deref().unwrap_or("");
                    let (section, ins, dels) = format_added_section(rel, new_t);
                    push_section(&mut full_diff, &section)?;
                    total_insertions += ins;
                    total_deletions += dels;
                    stats.push(WorkDiffFileStat {
                        path: rel.clone(),
                        old_path: None,
                        status: "added".to_owned(),
                        insertions: ins,
                        deletions: dels,
                        binary: false,
                        oversized: false,
                        content_omitted: false,
                        baseline_sha256: None,
                        live_sha256: None,
                        work_sha256: Some(work.sha256.clone()),
                        drifted_from_baseline: false,
                        missing_in_live: false,
                        conflict_exists_in_project: *conflict_exists_in_project,
                    });
                }
            }
            RawCandidate::UnchangedDrifted {
                rel,
                baseline_sha256,
                live_sha256,
                work_sha256,
                binary,
                oversized,
            } => {
                drifted_files.push(rel.clone());
                stats.push(WorkDiffFileStat {
                    path: rel.clone(),
                    old_path: None,
                    status: "unchanged".to_owned(),
                    insertions: 0,
                    deletions: 0,
                    binary: *binary,
                    oversized: *oversized,
                    content_omitted: false,
                    baseline_sha256: Some(baseline_sha256.clone()),
                    live_sha256: Some(live_sha256.clone()),
                    work_sha256: Some(work_sha256.clone()),
                    drifted_from_baseline: true,
                    missing_in_live: false,
                    conflict_exists_in_project: false,
                });
            }
        }
    }

    let diff_sha256 = sha256_bytes(full_diff.as_bytes());
    Ok(FullDiffComputed {
        full_diff,
        diff_sha256,
        files_changed,
        total_insertions,
        total_deletions,
        drifted_files,
        conflict_files,
        binary_or_oversized_files,
        files: stats,
    })
}

/// Compute a paginated, read-only unified diff between `_pro/work/<workspace>/` and the
/// live project files tracked by the bridge manifest. Writes nothing on disk.
pub fn compute_work_diff(
    project_root: &Path,
    root_identity: &str,
    state_dir: &Path,
    project_id: &str,
    req: &WorkDiffRequest,
) -> Result<WorkDiffResult, BridgeError> {
    validate_safe_id(project_id)?;
    validate_work_name(&req.workspace)?;
    if req.limit == 0 || req.limit > WORK_DIFF_MAX_LIMIT {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            format!("'limit' must be between 1 and {WORK_DIFF_MAX_LIMIT} characters."),
            OriginLayer::Validation,
        ));
    }
    if req.summary_only && req.offset > 0 {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "Cannot combine 'summary_only=true' with 'offset' > 0.",
            OriginLayer::Validation,
        ));
    }
    let normalized_filter = normalize_paths_filter(req.paths.as_deref())?;

    let remote_reader = ScopedFiles::new_remote_read(project_root, Some(root_identity.to_owned()))?;
    let cur_rid = remote_reader.current_root_identity()?;
    if root_identity.starts_with("ntfs:") && cur_rid != root_identity {
        return Err(BridgeError::new(
            ErrorCode::StalePrecondition,
            "Project root identity mismatch.",
            OriginLayer::FileService,
        ));
    }
    #[cfg(windows)]
    let (_root_pin, root_path_buf) = open_verified_root(project_root, &cur_rid)?;
    #[cfg(windows)]
    let root_path_opt = Some(root_path_buf.as_path());
    #[cfg(not(windows))]
    let root_path_opt: Option<&Path> = None;

    let computed = compute_full_diff_internal(
        project_root,
        &cur_rid,
        root_path_opt,
        state_dir,
        project_id,
        &req.workspace,
        normalized_filter.as_deref(),
        WORK_DIFF_MAX_TOTAL_BYTES,
    )?;

    if let Some(ref exp_sha) = req.expected_diff_sha256 {
        if !exp_sha.eq_ignore_ascii_case(&computed.diff_sha256) {
            return Err(BridgeError::new(
                ErrorCode::VersionConflict,
                format!(
                    "Workspace or live project changed since expected_diff_sha256 ({exp_sha} != {}); restart paging from offset 0.",
                    computed.diff_sha256
                ),
                OriginLayer::FileService,
            ));
        }
    }

    let total_bytes = computed.full_diff.len();
    let (content, start, next_offset, truncated) = if req.summary_only {
        (String::new(), 0, None, false)
    } else {
        let (slice, start, end, has_more) = char_page(&computed.full_diff, req.offset, req.limit);
        (
            slice.to_owned(),
            start,
            has_more.then_some(end),
            has_more,
        )
    };

    Ok(WorkDiffResult {
        workspace: req.workspace.clone(),
        diff_sha256: computed.diff_sha256,
        files_changed: computed.files_changed,
        total_insertions: computed.total_insertions,
        total_deletions: computed.total_deletions,
        has_drift: !computed.drifted_files.is_empty(),
        drifted_files: computed.drifted_files,
        conflict_files: computed.conflict_files,
        binary_or_oversized_files: computed.binary_or_oversized_files,
        files: computed.files,
        content,
        offset: start,
        next_offset,
        total_bytes,
        truncated,
    })
}

/// Export the workspace unified diff create-only to a single new `.diff` file directly under
/// `_pro/outbox/` using `ScopedFiles::apply_delegated_creates`.
#[allow(clippy::too_many_arguments)]
pub fn export_work_diff_to_outbox(
    project_root: &Path,
    root_identity: &str,
    state_dir: &Path,
    project_id: &str,
    req: &WorkExportDiffRequest,
    writable_scope: &[String],
    authorize_commit: impl Fn(&str) -> Result<(), BridgeError>,
) -> Result<(WorkExportDiffResult, PatchJournal), BridgeError> {
    validate_safe_id(project_id)?;
    validate_work_name(&req.workspace)?;
    let outbox_path = validate_outbox_diff_path(&req.path)?;
    let normalized_filter = normalize_paths_filter(req.paths.as_deref())?;

    let remote_reader = ScopedFiles::new_remote_read(project_root, Some(root_identity.to_owned()))?;
    let cur_rid = remote_reader.current_root_identity()?;
    if root_identity.starts_with("ntfs:") && cur_rid != root_identity {
        return Err(BridgeError::new(
            ErrorCode::StalePrecondition,
            "Project root identity mismatch.",
            OriginLayer::FileService,
        ));
    }
    #[cfg(windows)]
    let (_root_pin, root_path_buf) = open_verified_root(project_root, &cur_rid)?;
    #[cfg(windows)]
    let root_path_opt = Some(root_path_buf.as_path());
    #[cfg(not(windows))]
    let root_path_opt: Option<&Path> = None;

    let computed = compute_full_diff_internal(
        project_root,
        &cur_rid,
        root_path_opt,
        state_dir,
        project_id,
        &req.workspace,
        normalized_filter.as_deref(),
        WORK_EXPORT_DIFF_MAX_BYTES,
    )?;

    if !computed.binary_or_oversized_files.is_empty() {
        return Err(BridgeError::new(
            ErrorCode::UnsupportedPathType,
            format!(
                "Workspace '{}' contains binary or over-size file changes ({}) that cannot be exported into a plain-text .diff; ask the owner to review and apply with `edge-bridge work-apply`.",
                req.workspace,
                computed.binary_or_oversized_files.join(", ")
            ),
            OriginLayer::FileService,
        )
        .with_details(serde_json::json!({
            "binary_or_oversized_files": computed.binary_or_oversized_files,
        })));
    }
    if !req.allow_drifted && !computed.drifted_files.is_empty() {
        return Err(BridgeError::new(
            ErrorCode::VersionConflict,
            format!(
                "Live project files changed since work_copy ({}); re-copy or pass allow_drifted=true to export anyway.",
                computed.drifted_files.join(", ")
            ),
            OriginLayer::FileService,
        )
        .with_details(serde_json::json!({
            "drifted_files": computed.drifted_files,
        })));
    }
    if !req.allow_drifted && !computed.conflict_files.is_empty() {
        return Err(BridgeError::new(
            ErrorCode::VersionConflict,
            format!(
                "Added workspace files already exist in the live project ({}); remove conflicts or pass allow_drifted=true.",
                computed.conflict_files.join(", ")
            ),
            OriginLayer::FileService,
        )
        .with_details(serde_json::json!({
            "conflict_files": computed.conflict_files,
        })));
    }
    if computed.full_diff.is_empty() {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            format!("Workspace '{}' has no exportable changes; diff is empty.", req.workspace),
            OriginLayer::Validation,
        ));
    }
    if computed.full_diff.len() > WORK_EXPORT_DIFF_MAX_BYTES {
        return Err(BridgeError::new(
            ErrorCode::ResourceBudgetExceeded,
            "Exported diff exceeds the 1 MiB delegated file limit.",
            OriginLayer::FileService,
        ));
    }

    let bytes_written = computed.full_diff.len();
    let plan = PatchPlanV04 {
        patch_plan_version: BRIDGE_CONTRACT_VERSION.into(),
        project_id: project_id.to_owned(),
        root_identity: Some(cur_rid),
        operation_id: req.operation_id.clone(),
        task_id: req.task_id.clone(),
        summary: Some(format!("MCP work_export_diff ({})", req.workspace)),
        baseline_manifest_sha256: None,
        scope: vec![outbox_path.clone()],
        edits: vec![PatchEditV04 {
            path: outbox_path.clone(),
            content: computed.full_diff,
            expected_hash: None,
            expected_postimage_hash: Some(computed.diff_sha256.clone()),
        }],
        verification_recipe: None,
        verification_command: None,
    };

    let sf = ScopedFiles::new(project_root, Some(root_identity.to_owned()))?;
    let journal_dir = state_dir.join("patch-journals");
    let (apply_res, journal) =
        sf.apply_delegated_creates(&plan, &journal_dir, writable_scope, authorize_commit)?;
    let quota = work_quota_telemetry(project_root, state_dir, project_id)?;

    Ok((
        WorkExportDiffResult {
            workspace: req.workspace.clone(),
            path: outbox_path,
            operation_id: apply_res.operation_id,
            journal_id: apply_res.journal_id,
            diff_sha256: computed.diff_sha256,
            bytes_written,
            files_changed: computed.files_changed,
            total_insertions: computed.total_insertions,
            total_deletions: computed.total_deletions,
            drifted_files: computed.drifted_files,
            quota,
        },
        journal,
    ))
}

enum PlannedApplyOp {
    Modify {
        rel: String,
        baseline_sha256: String,
        old_bytes: Vec<u8>,
        live_ntfs_id: Option<String>,
        new_bytes: Vec<u8>,
        new_sha256: String,
        binary: bool,
        oversized: bool,
    },
    Add {
        rel: String,
        new_bytes: Vec<u8>,
        new_sha256: String,
        binary: bool,
        oversized: bool,
    },
    Delete {
        rel: String,
        baseline_sha256: String,
        old_bytes: Vec<u8>,
        live_ntfs_id: Option<String>,
        binary: bool,
        oversized: bool,
    },
}

enum StagedApplyStep {
    Write {
        rel: String,
        is_replace: bool,
        old_bytes: Option<Vec<u8>>,
        expected_preimage: Option<String>,
        expected_ntfs_id: Option<String>,
        new_bytes: Vec<u8>,
        post_sha256: String,
        file: Option<File>,
        #[cfg(windows)]
        parent: PatchParent,
        destination: PathBuf,
        temp: PathBuf,
        committed: bool,
        temp_exists: bool,
    },
    Delete {
        rel: String,
        expected_preimage: String,
        #[cfg(windows)]
        parent: PatchParent,
        #[cfg(windows)]
        file: Option<File>,
        #[cfg(windows)]
        orig_name: std::ffi::OsString,
        #[cfg(windows)]
        staged_name: Option<std::ffi::OsString>,
        #[cfg(not(windows))]
        destination: PathBuf,
        #[cfg(not(windows))]
        staged_path: PathBuf,
        committed: bool,
    },
}

fn is_binary_bytes(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|&b| b == 0) || std::str::from_utf8(bytes).is_err()
}

/// Preview (`confirm = false`) or atomically apply (`confirm = true`) changes from
/// `_pro/work/<workspace>/` to live project files using ONLY the bridge-side manifest in
/// `<state_dir>/work-manifests/<project_id>/<workspace>.json`.
///
/// Local owner-only operation (never exposed as an MCP tool).
pub fn apply_work_to_project(
    project_root: &Path,
    root_identity: &str,
    state_dir: &Path,
    journal_dir: &Path,
    project_id: &str,
    workspace: &str,
    confirm: bool,
) -> Result<(WorkApplyResult, Option<PatchJournal>), BridgeError> {
    apply_work_to_project_inner(
        project_root,
        root_identity,
        state_dir,
        journal_dir,
        project_id,
        workspace,
        confirm,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_work_to_project_inner(
    project_root: &Path,
    root_identity: &str,
    state_dir: &Path,
    journal_dir: &Path,
    project_id: &str,
    workspace: &str,
    confirm: bool,
    simulate_fail_after_step: Option<usize>,
) -> Result<(WorkApplyResult, Option<PatchJournal>), BridgeError> {
    validate_safe_id(project_id)?;
    validate_work_name(workspace)?;

    let remote_reader = ScopedFiles::new_remote_read(project_root, Some(root_identity.to_owned()))?;
    let cur_rid = remote_reader.current_root_identity()?;
    if root_identity.starts_with("ntfs:") && cur_rid != root_identity {
        return Err(BridgeError::new(
            ErrorCode::StalePrecondition,
            "Project root identity mismatch.",
            OriginLayer::FileService,
        ));
    }

    // Dry-run writes NOTHING on disk (does not create `root-locks` or journals).
    let _writer_lock = if confirm {
        Some(lock_patch_root(journal_dir, &cur_rid)?)
    } else {
        None
    };

    #[cfg(windows)]
    let (_root_pin, root_path_buf) = open_verified_root(project_root, &cur_rid)?;
    #[cfg(windows)]
    let root_path_opt = Some(root_path_buf.as_path());
    #[cfg(not(windows))]
    let root_path_opt: Option<&Path> = None;

    let (manifest, work_files) = load_verified_workspace(
        project_root,
        &cur_rid,
        root_path_opt,
        state_dir,
        project_id,
        workspace,
    )?;

    let ws_rel = format!("{PRO_WORK_PREFIX}{workspace}");
    let mut all_paths = BTreeSet::new();
    for k in manifest.entries.keys() {
        all_paths.insert(k.clone());
    }
    for k in &work_files {
        all_paths.insert(k.clone());
    }

    let mut actions: Vec<PlannedApplyOp> = Vec::new();
    let mut files_modified = Vec::new();
    let mut files_added = Vec::new();
    let mut files_deleted = Vec::new();
    let mut drifted_files = Vec::new();
    let mut conflict_files = Vec::new();
    let mut changes = Vec::new();
    let mut seen_target_case = HashSet::new();
    let mut total_apply_bytes: u64 = 0;

    // Phase 1: Validate EVERY target path, link/casing safety, and baseline SHA-256 BEFORE any write.
    for rel in all_paths {
        let validated = validate_project_target_rel(&rel, true)?;
        let in_manifest = manifest.entries.get(&validated);
        let in_work = work_files.contains(&validated);

        match (in_manifest, in_work) {
            (Some(entry), true) => {
                let work_rel = format!("{ws_rel}/{validated}");
                let work_full = project_root.join(&work_rel);
                #[cfg(windows)]
                PatchParent::pin(project_root, &cur_rid, &work_rel, true, false, None)?;
                #[cfg(not(windows))]
                check_no_symlink_prefix(project_root, &work_rel)?;
                let (work_bytes, _) = read_delegated_work_file_verified(
                    project_root,
                    root_path_opt,
                    &work_full,
                    &work_rel,
                    WORK_APPLY_MAX_FILE_BYTES,
                )?;
                let work_sha = sha256_bytes(&work_bytes);
                if work_sha.eq_ignore_ascii_case(&entry.baseline_sha256) {
                    // Unchanged relative to copy baseline; do not touch live project file.
                    continue;
                }
                if !seen_target_case.insert(validated.to_ascii_lowercase()) {
                    return Err(BridgeError::new(
                        ErrorCode::VersionConflict,
                        format!("Case-colliding target path '{validated}' cannot be applied safely."),
                        OriginLayer::FileService,
                    ));
                }

                // Target must pass the exact file-service path/link/casing/single-link checks.
                #[cfg(windows)]
                PatchParent::pin(project_root, &cur_rid, &validated, true, false, None)?;
                #[cfg(not(windows))]
                check_no_symlink_prefix(project_root, &validated)?;
                let live_full = project_root.join(&validated);
                let live_read = match read_delegated_work_file_verified(
                    project_root,
                    root_path_opt,
                    &live_full,
                    &validated,
                    WORK_APPLY_MAX_FILE_BYTES,
                ) {
                    Ok(v) => Some(v),
                    Err(e) if e.code == ErrorCode::FileNotFound => None,
                    Err(e) => return Err(e),
                };
                let binary = is_binary_bytes(&work_bytes)
                    || live_read
                        .as_ref()
                        .is_some_and(|(b, _)| is_binary_bytes(b));
                let oversized = work_bytes.len() as u64 > WORK_DIFF_MAX_FILE_BYTES
                    || live_read
                        .as_ref()
                        .is_some_and(|(b, _)| b.len() as u64 > WORK_DIFF_MAX_FILE_BYTES);

                files_modified.push(validated.clone());
                changes.push(WorkApplyFileChange {
                    path: validated.clone(),
                    action: "modify".to_owned(),
                    baseline_sha256: Some(entry.baseline_sha256.clone()),
                    postimage_sha256: Some(work_sha.clone()),
                    binary,
                    oversized,
                });

                match live_read {
                    Some((live_bytes, live_fid)) => {
                        let live_sha = sha256_bytes(&live_bytes);
                        if !live_sha.eq_ignore_ascii_case(&entry.baseline_sha256) {
                            drifted_files.push(validated);
                        } else {
                            total_apply_bytes =
                                total_apply_bytes.saturating_add(work_bytes.len() as u64);
                            if total_apply_bytes > DELEGATED_WRITE_MAX_SCOPE_BYTES {
                                return Err(BridgeError::new(
                                    ErrorCode::ResourceBudgetExceeded,
                                    "Total workspace apply size exceeds 256 MiB limit.",
                                    OriginLayer::FileService,
                                ));
                            }
                            actions.push(PlannedApplyOp::Modify {
                                rel: validated,
                                baseline_sha256: entry.baseline_sha256.clone(),
                                old_bytes: live_bytes,
                                live_ntfs_id: live_fid,
                                new_bytes: work_bytes,
                                new_sha256: work_sha,
                                binary,
                                oversized,
                            });
                        }
                    }
                    None => {
                        drifted_files.push(validated);
                    }
                }
            }
            (Some(entry), false) => {
                if !seen_target_case.insert(validated.to_ascii_lowercase()) {
                    return Err(BridgeError::new(
                        ErrorCode::VersionConflict,
                        format!("Case-colliding target path '{validated}' cannot be applied safely."),
                        OriginLayer::FileService,
                    ));
                }
                #[cfg(windows)]
                PatchParent::pin(project_root, &cur_rid, &validated, true, false, None)?;
                #[cfg(not(windows))]
                check_no_symlink_prefix(project_root, &validated)?;
                let live_full = project_root.join(&validated);
                let live_read = match read_delegated_work_file_verified(
                    project_root,
                    root_path_opt,
                    &live_full,
                    &validated,
                    WORK_APPLY_MAX_FILE_BYTES,
                ) {
                    Ok(v) => Some(v),
                    Err(e) if e.code == ErrorCode::FileNotFound => None,
                    Err(e) => return Err(e),
                };
                let binary = live_read
                    .as_ref()
                    .is_some_and(|(b, _)| is_binary_bytes(b));
                let oversized = live_read
                    .as_ref()
                    .is_some_and(|(b, _)| b.len() as u64 > WORK_DIFF_MAX_FILE_BYTES);

                files_deleted.push(validated.clone());
                changes.push(WorkApplyFileChange {
                    path: validated.clone(),
                    action: "delete".to_owned(),
                    baseline_sha256: Some(entry.baseline_sha256.clone()),
                    postimage_sha256: None,
                    binary,
                    oversized,
                });

                match live_read {
                    Some((live_bytes, live_fid)) => {
                        let live_sha = sha256_bytes(&live_bytes);
                        if !live_sha.eq_ignore_ascii_case(&entry.baseline_sha256) {
                            drifted_files.push(validated);
                        } else {
                            actions.push(PlannedApplyOp::Delete {
                                rel: validated,
                                baseline_sha256: entry.baseline_sha256.clone(),
                                old_bytes: live_bytes,
                                live_ntfs_id: live_fid,
                                binary,
                                oversized,
                            });
                        }
                    }
                    None => {
                        drifted_files.push(validated);
                    }
                }
            }
            (None, true) => {
                if !seen_target_case.insert(validated.to_ascii_lowercase()) {
                    return Err(BridgeError::new(
                        ErrorCode::VersionConflict,
                        format!("Case-colliding target path '{validated}' cannot be applied safely."),
                        OriginLayer::FileService,
                    ));
                }
                let work_rel = format!("{ws_rel}/{validated}");
                let work_full = project_root.join(&work_rel);
                #[cfg(windows)]
                PatchParent::pin(project_root, &cur_rid, &work_rel, true, false, None)?;
                #[cfg(not(windows))]
                check_no_symlink_prefix(project_root, &work_rel)?;
                let (work_bytes, _) = read_delegated_work_file_verified(
                    project_root,
                    root_path_opt,
                    &work_full,
                    &work_rel,
                    WORK_APPLY_MAX_FILE_BYTES,
                )?;
                let work_sha = sha256_bytes(&work_bytes);
                let binary = is_binary_bytes(&work_bytes);
                let oversized = work_bytes.len() as u64 > WORK_DIFF_MAX_FILE_BYTES;

                // Validate existing live ancestor dirs (refusing junctions/symlinks/wrong case!).
                #[cfg(windows)]
                PatchParent::pin(project_root, &cur_rid, &validated, true, false, None)?;
                #[cfg(not(windows))]
                check_no_symlink_prefix(project_root, &validated)?;
                let live_full = project_root.join(&validated);
                let live_exists = match fs::symlink_metadata(&live_full) {
                    Ok(meta) => {
                        if is_quota_link(&meta) {
                            return Err(BridgeError::new(
                                ErrorCode::UnsupportedPathType,
                                format!("Target '{validated}' is a symlink or NTFS junction."),
                                OriginLayer::FileService,
                            ));
                        }
                        true
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                    Err(e) => return Err(patch_io_error(e)),
                };

                files_added.push(validated.clone());
                changes.push(WorkApplyFileChange {
                    path: validated.clone(),
                    action: "add".to_owned(),
                    baseline_sha256: None,
                    postimage_sha256: Some(work_sha.clone()),
                    binary,
                    oversized,
                });

                if live_exists {
                    conflict_files.push(validated);
                } else {
                    total_apply_bytes = total_apply_bytes.saturating_add(work_bytes.len() as u64);
                    if total_apply_bytes > DELEGATED_WRITE_MAX_SCOPE_BYTES {
                        return Err(BridgeError::new(
                            ErrorCode::ResourceBudgetExceeded,
                            "Total workspace apply size exceeds 256 MiB limit.",
                            OriginLayer::FileService,
                        ));
                    }
                    actions.push(PlannedApplyOp::Add {
                        rel: validated,
                        new_bytes: work_bytes,
                        new_sha256: work_sha,
                        binary,
                        oversized,
                    });
                }
            }
            (None, false) => {}
        }
    }

    // Build unified diff preview (capped at 4 MiB; binary/oversized files omitted from text).
    let mut unified_diff = String::new();
    for op in &actions {
        match op {
            PlannedApplyOp::Modify {
                rel,
                old_bytes,
                new_bytes,
                binary: false,
                oversized: false,
                ..
            } => {
                let (sec, _, _) = format_modified_section(
                    rel,
                    std::str::from_utf8(old_bytes).unwrap_or(""),
                    std::str::from_utf8(new_bytes).unwrap_or(""),
                );
                if unified_diff.len() + sec.len() <= WORK_DIFF_MAX_TOTAL_BYTES {
                    unified_diff.push_str(&sec);
                }
            }
            PlannedApplyOp::Add {
                rel,
                new_bytes,
                binary: false,
                oversized: false,
                ..
            } => {
                let (sec, _, _) =
                    format_added_section(rel, std::str::from_utf8(new_bytes).unwrap_or(""));
                if unified_diff.len() + sec.len() <= WORK_DIFF_MAX_TOTAL_BYTES {
                    unified_diff.push_str(&sec);
                }
            }
            PlannedApplyOp::Delete {
                rel,
                old_bytes,
                binary: false,
                oversized: false,
                ..
            } => {
                let (sec, _, _) =
                    format_deleted_section(rel, std::str::from_utf8(old_bytes).unwrap_or(""));
                if unified_diff.len() + sec.len() <= WORK_DIFF_MAX_TOTAL_BYTES {
                    unified_diff.push_str(&sec);
                }
            }
            _ => {}
        }
    }
    let diff_sha256 = sha256_bytes(unified_diff.as_bytes());
    let safe_to_apply = drifted_files.is_empty() && conflict_files.is_empty();
    let files_changed = files_modified.len() + files_added.len() + files_deleted.len();

    if !confirm {
        return Ok((
            WorkApplyResult {
                project_id: project_id.to_owned(),
                workspace: workspace.to_owned(),
                applied: false,
                confirm_required: true,
                safe_to_apply,
                journal_id: None,
                files_changed,
                files_modified,
                files_added,
                files_deleted,
                drifted_files,
                conflict_files,
                postimage_hashes: BTreeMap::new(),
                changes,
                unified_diff,
                diff_sha256,
            },
            None,
        ));
    }

    if !drifted_files.is_empty() || !conflict_files.is_empty() {
        let mut reasons = Vec::new();
        if !drifted_files.is_empty() {
            reasons.push(format!(
                "target file(s) changed since copy: {}",
                drifted_files.join(", ")
            ));
        }
        if !conflict_files.is_empty() {
            reasons.push(format!(
                "added file(s) already exist in project: {}",
                conflict_files.join(", ")
            ));
        }
        return Err(BridgeError::new(
            ErrorCode::VersionConflict,
            format!("Refusing work-apply: {}.", reasons.join("; ")),
            OriginLayer::FileService,
        )
        .with_details(serde_json::json!({
            "drifted_files": drifted_files,
            "conflict_files": conflict_files,
        })));
    }
    if actions.is_empty() {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            format!("Workspace '{workspace}' has no changes to apply."),
            OriginLayer::Validation,
        ));
    }

    // Phase 2: Create durable rollback journal & backups BEFORE touching any project file.
    let journal_id = format!("pjr_{}", uuid::Uuid::new_v4().simple());
    let j_root = journal_dir.join(&journal_id);
    let backups_dir = j_root.join("backups");
    fs::create_dir_all(&backups_dir).map_err(patch_io_error)?;

    let mut steps = Vec::with_capacity(actions.len());
    let mut plan_hasher = Sha256::new();
    for (idx, op) in actions.iter().enumerate() {
        match op {
            PlannedApplyOp::Modify {
                rel,
                baseline_sha256,
                old_bytes,
                new_sha256,
                ..
            } => {
                let bname = format!("step_{idx:03}.bak");
                write_synced_new(&backups_dir.join(&bname), old_bytes)?;
                plan_hasher.update(format!("M|{rel}|{baseline_sha256}|{new_sha256}\n").as_bytes());
                steps.push(PatchJournalFileStep {
                    path: rel.clone(),
                    expected_preimage: Some(baseline_sha256.clone()),
                    actual_preimage: Some(baseline_sha256.clone()),
                    backup_rel_path: Some(format!("backups/{bname}")),
                    postimage_sha256: new_sha256.clone(),
                    committed: false,
                    deleted: false,
                });
            }
            PlannedApplyOp::Add {
                rel, new_sha256, ..
            } => {
                plan_hasher.update(format!("A|{rel}|{new_sha256}\n").as_bytes());
                steps.push(PatchJournalFileStep {
                    path: rel.clone(),
                    expected_preimage: None,
                    actual_preimage: None,
                    backup_rel_path: None,
                    postimage_sha256: new_sha256.clone(),
                    committed: false,
                    deleted: false,
                });
            }
            PlannedApplyOp::Delete {
                rel,
                baseline_sha256,
                old_bytes,
                ..
            } => {
                let bname = format!("step_{idx:03}.bak");
                write_synced_new(&backups_dir.join(&bname), old_bytes)?;
                plan_hasher.update(format!("D|{rel}|{baseline_sha256}\n").as_bytes());
                steps.push(PatchJournalFileStep {
                    path: rel.clone(),
                    expected_preimage: Some(baseline_sha256.clone()),
                    actual_preimage: Some(baseline_sha256.clone()),
                    backup_rel_path: Some(format!("backups/{bname}")),
                    postimage_sha256: String::new(),
                    committed: false,
                    deleted: true,
                });
            }
        }
    }

    let mut journal = PatchJournal {
        journal_id: journal_id.clone(),
        project_id: project_id.to_owned(),
        root_identity: Some(cur_rid.clone()),
        operation_id: format!("work-apply:{workspace}"),
        state: "applying".to_owned(),
        plan_sha256: hex::encode(plan_hasher.finalize()),
        created_at: Utc::now().to_rfc3339(),
        steps,
        stage_cleanup_failed: Vec::new(),
        directory_cleanup_failed: Vec::new(),
    };
    let journal_file = j_root.join("journal.json");

    // Phase 3: Stage ALL writes and pin/open ALL deletes BEFORE committing a single file,
    // then commit all-or-none with automatic full rollback on any failure.
    let mut staged: Vec<StagedApplyStep> = Vec::with_capacity(actions.len());
    let mut created_dirs: Vec<PathBuf> = Vec::new();
    let mut postimage_hashes = BTreeMap::new();

    let commit_res: Result<(), BridgeError> = (|| {
        persist_patch_journal(&journal_file, &journal)?;

        // 3a. Stage every write & open+verify every delete handle.
        for (idx, op) in actions.into_iter().enumerate() {
            match op {
                PlannedApplyOp::Modify {
                    rel,
                    baseline_sha256,
                    old_bytes,
                    live_ntfs_id,
                    new_bytes,
                    new_sha256,
                    ..
                } => {
                    let temp_name = format!(".eb_stage_{journal_id}_{idx}.tmp");
                    let step = create_staged_write(
                        project_root,
                        &cur_rid,
                        &rel,
                        &temp_name,
                        true,
                        Some(old_bytes),
                        Some(baseline_sha256),
                        live_ntfs_id,
                        new_bytes,
                        new_sha256,
                        &mut created_dirs,
                    )?;
                    staged.push(step);
                }
                PlannedApplyOp::Add {
                    rel,
                    new_bytes,
                    new_sha256,
                    ..
                } => {
                    let temp_name = format!(".eb_stage_{journal_id}_{idx}.tmp");
                    let step = create_staged_write(
                        project_root,
                        &cur_rid,
                        &rel,
                        &temp_name,
                        false,
                        None,
                        None,
                        None,
                        new_bytes,
                        new_sha256,
                        &mut created_dirs,
                    )?;
                    staged.push(step);
                }
                PlannedApplyOp::Delete {
                    rel,
                    baseline_sha256,
                    live_ntfs_id,
                    ..
                } => {
                    let step = prepare_staged_delete(
                        project_root,
                        &cur_rid,
                        &rel,
                        &journal_id,
                        idx,
                        baseline_sha256,
                        live_ntfs_id.as_deref(),
                    )?;
                    staged.push(step);
                }
            }
        }

        // 3b. Commit every step with handle-pinned verification.
        for (idx, step) in staged.iter_mut().enumerate() {
            match step {
                StagedApplyStep::Write {
                    rel,
                    is_replace,
                    old_bytes,
                    expected_preimage,
                    expected_ntfs_id,
                    new_bytes,
                    post_sha256,
                    file,
                    #[cfg(windows)]
                    parent,
                    destination,
                    #[cfg(not(windows))]
                    temp,
                    committed,
                    ..
                } => {
                    if *is_replace {
                        let exp_hash = expected_preimage.as_deref().unwrap();
                        #[cfg(windows)]
                        {
                            let old_len = old_bytes.as_ref().map_or(0, Vec::len);
                            let preimage_guard = verify_work_preimage_handle(
                                &parent.root_path,
                                destination,
                                rel,
                                expected_ntfs_id.as_deref(),
                                exp_hash,
                                old_len,
                            )?;
                            parent.verify_location(rel)?;
                            commit_patch_stage(
                                file.as_ref().unwrap(),
                                parent.directories.last().unwrap(),
                                destination.file_name().unwrap(),
                                true,
                            )?;
                            drop(preimage_guard);
                        }
                        #[cfg(not(windows))]
                        {
                            let _ = (old_bytes, expected_ntfs_id);
                            let (cur, _) = read_delegated_work_file_verified(
                                project_root,
                                None,
                                destination,
                                rel,
                                WORK_APPLY_MAX_FILE_BYTES,
                            )?;
                            if sha256_bytes(&cur) != exp_hash {
                                return Err(patch_commit_conflict(rel));
                            }
                            fs::rename(temp, destination).map_err(patch_io_error)?;
                        }
                    } else {
                        #[cfg(windows)]
                        {
                            parent.verify_location(rel)?;
                            commit_patch_stage(
                                file.as_ref().unwrap(),
                                parent.directories.last().unwrap(),
                                destination.file_name().unwrap(),
                                false,
                            )?;
                        }
                        #[cfg(not(windows))]
                        {
                            fs::hard_link(temp, destination).map_err(|e| {
                                if e.kind() == std::io::ErrorKind::AlreadyExists {
                                    patch_commit_conflict(rel)
                                } else {
                                    patch_io_error(e)
                                }
                            })?;
                        }
                    }
                    *committed = true;
                    journal.steps[idx].committed = true;
                    verify_committed_write(
                        file.as_mut(),
                        destination,
                        rel,
                        new_bytes.len(),
                        post_sha256,
                    )?;
                    postimage_hashes.insert(rel.clone(), post_sha256.clone());
                }
                StagedApplyStep::Delete {
                    rel,
                    expected_preimage,
                    #[cfg(windows)]
                    parent,
                    #[cfg(windows)]
                    file,
                    #[cfg(windows)]
                    staged_name,
                    #[cfg(not(windows))]
                    destination,
                    #[cfg(not(windows))]
                    staged_path,
                    committed,
                    ..
                } => {
                    #[cfg(windows)]
                    {
                        let _ = expected_preimage;
                        parent.verify_location(rel)?;
                        let tmp_name =
                            std::ffi::OsString::from(format!(".eb_stage_del_{journal_id}_{idx}.tmp"));
                        commit_patch_stage(
                            file.as_ref().unwrap(),
                            parent.directories.last().unwrap(),
                            &tmp_name,
                            false,
                        )?;
                        *staged_name = Some(tmp_name);
                    }
                    #[cfg(not(windows))]
                    {
                        let (cur, _) = read_delegated_work_file_verified(
                            project_root,
                            None,
                            destination,
                            rel,
                            WORK_APPLY_MAX_FILE_BYTES,
                        )?;
                        if !sha256_bytes(&cur).eq_ignore_ascii_case(expected_preimage) {
                            return Err(patch_commit_conflict(rel));
                        }
                        fs::rename(destination, staged_path).map_err(patch_io_error)?;
                    }
                    *committed = true;
                    journal.steps[idx].committed = true;
                }
            }
            persist_patch_journal(&journal_file, &journal)?;

            if simulate_fail_after_step == Some(idx) {
                return Err(BridgeError::new(
                    ErrorCode::InternalError,
                    format!("Simulated mid-apply failure after step {idx}."),
                    OriginLayer::FileService,
                ));
            }
        }

        // 3c. All steps succeeded! Close write handles, remove staged delete files, mark committed.
        for step in &mut staged {
            match step {
                StagedApplyStep::Write {
                    file,
                    temp,
                    committed,
                    temp_exists,
                    ..
                } => {
                    file.take();
                    if *temp_exists && !(cfg!(windows) && *committed) {
                        let _ = fs::remove_file(temp);
                    }
                    *temp_exists = false;
                }
                StagedApplyStep::Delete {
                    #[cfg(windows)]
                    parent,
                    #[cfg(windows)]
                    file,
                    #[cfg(windows)]
                    staged_name,
                    #[cfg(not(windows))]
                    staged_path,
                    ..
                } => {
                    #[cfg(windows)]
                    {
                        file.take();
                        if let Some(tmp_name) = staged_name.as_ref() {
                            fs::remove_file(parent.path.join(tmp_name)).map_err(patch_io_error)?;
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        fs::remove_file(staged_path).map_err(patch_io_error)?;
                    }
                }
            }
        }
        journal.state = "committed".to_owned();
        persist_patch_journal(&journal_file, &journal)?;
        Ok(())
    })();

    if let Err(mut error) = commit_res {
        let mut rollback_failed = Vec::new();
        for (idx, step) in staged.iter_mut().enumerate().rev() {
            match step {
                StagedApplyStep::Write {
                    rel,
                    old_bytes,
                    file,
                    #[cfg(windows)]
                    parent,
                    destination,
                    temp,
                    committed,
                    temp_exists,
                    ..
                } => {
                    if *committed {
                        if let Some(old) = old_bytes.as_deref() {
                            file.take();
                            let restored = (|| -> Result<(), BridgeError> {
                                #[cfg(windows)]
                                {
                                    parent.verify_location(rel)?;
                                    let rb_path = parent
                                        .path
                                        .join(format!(".eb_stage_{journal_id}_{idx}_rb.tmp"));
                                    let res = (|| -> Result<(), BridgeError> {
                                        let mut f =
                                            create_patch_stage(&rb_path).map_err(patch_io_error)?;
                                        f.write_all(old).map_err(patch_io_error)?;
                                        f.sync_all().map_err(patch_io_error)?;
                                        commit_patch_stage(
                                            &f,
                                            parent.directories.last().unwrap(),
                                            destination.file_name().unwrap(),
                                            true,
                                        )?;
                                        Ok(())
                                    })();
                                    if res.is_err() {
                                        let _ = fs::remove_file(&rb_path);
                                    }
                                    res
                                }
                                #[cfg(not(windows))]
                                {
                                    let rb_path = destination.with_file_name(format!(
                                        ".eb_stage_{journal_id}_{idx}_rb.tmp"
                                    ));
                                    let res = (|| -> Result<(), BridgeError> {
                                        write_synced_new(&rb_path, old)?;
                                        fs::rename(&rb_path, destination).map_err(patch_io_error)
                                    })();
                                    if res.is_err() {
                                        let _ = fs::remove_file(&rb_path);
                                    }
                                    res
                                }
                            })();
                            if restored.is_ok() {
                                *committed = false;
                                journal.steps[idx].committed = false;
                            } else {
                                rollback_failed.push(rel.clone());
                            }
                        } else {
                            #[cfg(windows)]
                            let undone = commit_patch_stage(
                                file.as_ref().unwrap(),
                                parent.directories.last().unwrap(),
                                temp.file_name().unwrap(),
                                false,
                            );
                            #[cfg(not(windows))]
                            let undone = fs::remove_file(destination).map_err(patch_io_error);
                            if undone.is_ok() {
                                *committed = false;
                                journal.steps[idx].committed = false;
                            } else {
                                rollback_failed.push(rel.clone());
                            }
                        }
                    }
                    file.take();
                    if *temp_exists && !(cfg!(windows) && *committed) {
                        if let Err(e) = fs::remove_file(temp) {
                            if e.kind() != std::io::ErrorKind::NotFound {
                                journal.stage_cleanup_failed.push(rel.clone());
                            }
                        }
                    }
                    *temp_exists = false;
                }
                StagedApplyStep::Delete {
                    rel,
                    #[cfg(windows)]
                    parent,
                    #[cfg(windows)]
                    file,
                    #[cfg(windows)]
                    orig_name,
                    #[cfg(windows)]
                    staged_name,
                    #[cfg(not(windows))]
                    destination,
                    #[cfg(not(windows))]
                    staged_path,
                    committed,
                    ..
                } => {
                    if *committed {
                        #[cfg(windows)]
                        let undone = if staged_name.is_some() {
                            commit_patch_stage(
                                file.as_ref().unwrap(),
                                parent.directories.last().unwrap(),
                                orig_name,
                                false,
                            )
                        } else {
                            Ok(())
                        };
                        #[cfg(not(windows))]
                        let undone = fs::rename(staged_path, destination).map_err(patch_io_error);
                        if undone.is_ok() {
                            *committed = false;
                            journal.steps[idx].committed = false;
                        } else {
                            rollback_failed.push(rel.clone());
                        }
                    }
                    #[cfg(windows)]
                    file.take();
                }
            }
        }
        drop(staged);
        for rel_dir in created_dirs.iter().rev() {
            match fs::remove_dir(project_root.join(rel_dir)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => journal
                    .directory_cleanup_failed
                    .push(rel_dir.to_string_lossy().replace('\\', "/")),
            }
        }
        let residue = !rollback_failed.is_empty()
            || !journal.stage_cleanup_failed.is_empty()
            || !journal.directory_cleanup_failed.is_empty();
        let journal_update_failed = if residue {
            journal.state = "rollback_incomplete".to_owned();
            persist_patch_journal(&journal_file, &journal).is_err()
        } else {
            fs::remove_dir_all(&j_root).is_err()
        };
        if residue || journal_update_failed {
            let mut details = serde_json::json!({
                "original_details": error.details,
                "rollback_failed": rollback_failed,
                "stage_cleanup_failed": journal.stage_cleanup_failed,
                "directory_cleanup_failed": journal.directory_cleanup_failed,
                "journal_update_failed": journal_update_failed,
            });
            if journal_file.is_file() {
                details["journal_id"] = serde_json::json!(journal_id);
            }
            error.details = Some(details);
        }
        return Err(error);
    }

    Ok((
        WorkApplyResult {
            project_id: project_id.to_owned(),
            workspace: workspace.to_owned(),
            applied: true,
            confirm_required: false,
            safe_to_apply: true,
            journal_id: Some(journal_id),
            files_changed,
            files_modified,
            files_added,
            files_deleted,
            drifted_files: Vec::new(),
            conflict_files: Vec::new(),
            postimage_hashes,
            changes,
            unified_diff,
            diff_sha256,
        },
        Some(journal),
    ))
}

#[allow(clippy::too_many_arguments)]
fn create_staged_write(
    root: &Path,
    cur_rid: &str,
    rel: &str,
    temp_name: &str,
    is_replace: bool,
    old_bytes: Option<Vec<u8>>,
    expected_preimage: Option<String>,
    expected_ntfs_id: Option<String>,
    new_bytes: Vec<u8>,
    post_sha256: String,
    created_dirs: &mut Vec<PathBuf>,
) -> Result<StagedApplyStep, BridgeError> {
    #[cfg(windows)]
    let parent = PatchParent::pin(root, cur_rid, rel, true, true, Some(created_dirs))?;
    let parts = validate_remote_relative_path(rel)?;
    let file_name = parts.last().ok_or_else(|| patch_commit_conflict(rel))?;
    #[cfg(windows)]
    let destination = parent.path.join(file_name);
    #[cfg(not(windows))]
    let destination = {
        let _ = cur_rid;
        let mut dir = PathBuf::new();
        for seg in &parts[..parts.len() - 1] {
            dir.push(seg);
            let full_dir = root.join(&dir);
            match fs::symlink_metadata(&full_dir) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() || !meta.is_dir() {
                        return Err(BridgeError::new(
                            ErrorCode::UnsupportedPathType,
                            format!("Symlink or non-directory denied at parent of '{rel}'."),
                            OriginLayer::FileService,
                        ));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    match fs::create_dir(&full_dir) {
                        Ok(()) => created_dirs.push(dir.clone()),
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(patch_io_error(e)),
                    }
                }
                Err(e) => return Err(patch_io_error(e)),
            }
        }
        root.join(rel)
    };
    let temp = destination.with_file_name(temp_name);
    #[cfg(windows)]
    let mut file = create_patch_stage(&temp).map_err(patch_io_error)?;
    #[cfg(not(windows))]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(patch_io_error)?;
    #[cfg(windows)]
    if file_path_from_handle(&file)?.parent() != Some(parent.path.as_path()) {
        let _ = fs::remove_file(&temp);
        return Err(patch_commit_conflict(rel));
    }
    if let Err(e) = file.write_all(&new_bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(patch_io_error(e));
    }
    Ok(StagedApplyStep::Write {
        rel: rel.to_owned(),
        is_replace,
        old_bytes,
        expected_preimage,
        expected_ntfs_id,
        new_bytes,
        post_sha256,
        file: Some(file),
        #[cfg(windows)]
        parent,
        destination,
        temp,
        committed: false,
        temp_exists: true,
    })
}

fn prepare_staged_delete(
    root: &Path,
    cur_rid: &str,
    rel: &str,
    journal_id: &str,
    idx: usize,
    expected_preimage: String,
    expected_ntfs_id: Option<&str>,
) -> Result<StagedApplyStep, BridgeError> {
    #[cfg(windows)]
    {
        let _ = (journal_id, idx);
        let parent = PatchParent::pin(root, cur_rid, rel, true, false, None)?;
        let orig_name = Path::new(rel)
            .file_name()
            .ok_or_else(|| patch_commit_conflict(rel))?
            .to_os_string();
        let full = parent.path.join(&orig_name);
        let mut file = open_delete_handle_no_follow(&full).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                patch_commit_conflict(rel)
            } else {
                patch_io_error(e)
            }
        })?;
        let id = file_identity_from_handle(&file)?;
        if id.is_reparse_point || id.is_directory || id.n_links != 1 {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("Delete target '{rel}' is not a regular single-link non-reparse file."),
                OriginLayer::FileService,
            ));
        }
        verify_opened_name(&parent.root_path, Path::new(rel), &file_path_from_handle(&file)?)?;
        if expected_ntfs_id.is_some() && Some(id.canonical_id().as_str()) != expected_ntfs_id {
            return Err(patch_commit_conflict(rel));
        }
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = file.read(&mut buf).map_err(patch_io_error)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        if !hex::encode(hasher.finalize()).eq_ignore_ascii_case(&expected_preimage) {
            return Err(patch_commit_conflict(rel));
        }
        Ok(StagedApplyStep::Delete {
            rel: rel.to_owned(),
            expected_preimage,
            parent,
            file: Some(file),
            orig_name,
            staged_name: None,
            committed: false,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (cur_rid, expected_ntfs_id);
        check_no_symlink_prefix(root, rel)?;
        let destination = root.join(rel);
        let staged_path =
            destination.with_file_name(format!(".eb_stage_del_{journal_id}_{idx}.tmp"));
        Ok(StagedApplyStep::Delete {
            rel: rel.to_owned(),
            expected_preimage,
            destination,
            staged_path,
            committed: false,
        })
    }
}

fn verify_committed_write(
    file: Option<&mut File>,
    destination: &Path,
    rel: &str,
    expected_len: usize,
    expected_hash: &str,
) -> Result<(), BridgeError> {
    #[cfg(windows)]
    let written = {
        let f = file.ok_or_else(|| patch_commit_conflict(rel))?;
        let id = file_identity_from_handle(f)?;
        if id.size_bytes != expected_len as u64
            || file_path_from_handle(f)?.as_os_str() != destination.as_os_str()
        {
            return Err(patch_commit_conflict(rel));
        }
        f.seek(SeekFrom::Start(0)).map_err(patch_io_error)?;
        let mut buf = Vec::with_capacity(expected_len);
        f.take(expected_len as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(patch_io_error)?;
        buf
    };
    #[cfg(not(windows))]
    let written = {
        let _ = file;
        fs::read(destination).map_err(patch_io_error)?
    };
    if written.len() != expected_len || !sha256_bytes(&written).eq_ignore_ascii_case(expected_hash) {
        return Err(BridgeError::new(
            ErrorCode::StalePrecondition,
            format!("Postimage verification failed for '{rel}'."),
            OriginLayer::FileService,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PRO_REVIEW_WRITABLE_PATH;
    use crate::work::{
        WorkCopyMode, WorkCopyRequest, WorkDeleteRequest, WorkDeleteTarget, WorkEditRequest,
        WorkFileEdit, WorkMoveRequest, WorkReplacement, work_copy, work_delete, work_edit,
        work_move,
    };
    use std::process::Command;

    fn scope() -> Vec<String> {
        vec![PRO_REVIEW_WRITABLE_PATH.to_owned()]
    }

    fn auth_target(workspace: &str) -> impl FnMut(&str) -> Result<String, BridgeError> + '_ {
        move |sub| {
            validate_work_name(workspace)?;
            let parts = validate_remote_relative_path(sub)?;
            if parts.is_empty() {
                return Err(BridgeError::new(
                    ErrorCode::InvalidArgument,
                    "empty subpath",
                    OriginLayer::Policy,
                ));
            }
            if is_hidden_from_remote(&parts) {
                return Err(hidden_denied());
            }
            Ok(format!("{PRO_WORK_PREFIX}{workspace}/{}", parts.join("/")))
        }
    }

    fn auth_delete_target(
        workspace: &str,
    ) -> impl FnMut(Option<&str>) -> Result<String, BridgeError> + '_ {
        move |sub| match sub {
            Some(s) => auth_target(workspace)(s),
            None => {
                validate_work_name(workspace)?;
                Ok(format!("{PRO_WORK_PREFIX}{workspace}"))
            }
        }
    }

    fn git_bin() -> PathBuf {
        let candidate = PathBuf::from(r"C:\Program Files\Git\cmd\git.exe");
        if candidate.is_file() {
            candidate
        } else {
            PathBuf::from("git")
        }
    }

    fn run_git(repo: &Path, args: &[&str]) -> std::process::Output {
        Command::new(git_bin())
            .args(args)
            .current_dir(repo)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git must be installed")
    }

    fn mk_junction(link: &Path, target: &Path) {
        #[cfg(windows)]
        {
            let win_link = link.to_string_lossy().replace('/', "\\");
            let win_target = target.to_string_lossy().replace('/', "\\");
            let out = Command::new("cmd.exe")
                .args(["/D", "/C", "mklink", "/J", &win_link, &win_target])
                .output()
                .unwrap();
            assert!(out.status.success(), "{out:?}");
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    fn rm_junction(link: &Path) {
        #[cfg(windows)]
        let _ = fs::remove_dir(link);
        #[cfg(unix)]
        let _ = fs::remove_file(link);
    }

    #[test]
    fn work_diff_and_export_apply_with_real_git_apply_for_modify_add_delete_rename_and_no_newline() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().join("state");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(repo.join("src")).unwrap();

        // Initialize real temporary Git repository.
        assert!(run_git(&repo, &["init"]).status.success());
        assert!(run_git(&repo, &["config", "user.name", "Test"]).status.success());
        assert!(run_git(&repo, &["config", "user.email", "test@example.com"]).status.success());
        assert!(run_git(&repo, &["config", "core.autocrlf", "false"]).status.success());

        // Seed project files covering every case + hidden files + untouched file.
        fs::write(repo.join("src/app.py"), "line1\nline2\nline3\n").unwrap();
        fs::write(repo.join("src/obsolete.py"), "old_a\nold_b\n").unwrap();
        fs::write(repo.join("src/old_name.py"), "def keep():\n    return 42\n").unwrap();
        fs::write(repo.join("src/move_and_edit.py"), "VAL = 1\n").unwrap();
        fs::write(repo.join("src/no_nl.txt"), "alpha\nbeta").unwrap(); // NO final newline!
        fs::write(repo.join("src/del_no_nl.txt"), "gone_without_nl").unwrap(); // NO final newline!
        fs::write(repo.join("src/untouched.py"), "NEVER_COPIED = True\n").unwrap();
        fs::write(repo.join(".env"), "SECRET=never_diffed\n").unwrap();
        fs::write(repo.join("src/auth.json"), "{\"secret\":true}\n").unwrap();

        assert!(run_git(&repo, &["add", "."]).status.success());
        assert!(run_git(&repo, &["commit", "-m", "initial"]).status.success());

        let sf = ScopedFiles::new(&repo, None).unwrap();
        let rid = sf.current_root_identity().unwrap();

        // Copy only the selected files (NOT src/untouched.py, NOT .env, NOT auth.json).
        work_copy(
            &repo,
            &rid,
            &state_dir,
            "proj1",
            &WorkCopyRequest {
                workspace: "fix-1".into(),
                mode: WorkCopyMode::FromProject {
                    paths: vec![
                        "src/app.py".into(),
                        "src/obsolete.py".into(),
                        "src/old_name.py".into(),
                        "src/move_and_edit.py".into(),
                        "src/no_nl.txt".into(),
                        "src/del_no_nl.txt".into(),
                    ],
                    exclude_generated: true,
                },
                overwrite_existing: false,
            },
            &scope(),
            auth_target("fix-1"),
            |_| Ok(()),
        )
        .unwrap();

        // 1. Modify src/app.py and src/no_nl.txt (keeping no final newline!).
        work_edit(
            &repo,
            &rid,
            &state_dir,
            "proj1",
            &WorkEditRequest {
                workspace: "fix-1".into(),
                operation_id: "op_e1".into(),
                task_id: None,
                edits: vec![
                    WorkFileEdit {
                        path: "src/app.py".into(),
                        expected_hash: None,
                        replacements: vec![WorkReplacement {
                            old_text: "line2".into(),
                            new_text: "line2_fixed\nline2_extra".into(),
                            replace_all: false,
                        }],
                    },
                    WorkFileEdit {
                        path: "src/no_nl.txt".into(),
                        expected_hash: None,
                        replacements: vec![WorkReplacement {
                            old_text: "beta".into(),
                            new_text: "gamma".into(),
                            replace_all: false,
                        }],
                    },
                ],
            },
            &scope(),
            auth_target("fix-1"),
            |_| Ok(()),
        )
        .unwrap();

        // 2. Delete src/obsolete.py and src/del_no_nl.txt.
        work_delete(
            &repo,
            &rid,
            &state_dir,
            "proj1",
            &WorkDeleteRequest {
                workspace: "fix-1".into(),
                operation_id: "op_d1".into(),
                target: WorkDeleteTarget::Files {
                    paths: vec!["src/obsolete.py".into(), "src/del_no_nl.txt".into()],
                    expected_hashes: BTreeMap::new(),
                },
            },
            auth_delete_target("fix-1"),
            |_| Ok(()),
        )
        .unwrap();

        // 3. Exact rename: src/old_name.py -> src/new_name.py.
        work_move(
            &repo,
            &rid,
            &state_dir,
            "proj1",
            &WorkMoveRequest {
                workspace: "fix-1".into(),
                operation_id: "op_m1".into(),
                from: "src/old_name.py".into(),
                to: "src/new_name.py".into(),
                expected_from_hash: None,
                overwrite: false,
                expected_to_hash: None,
            },
            &scope(),
            auth_target("fix-1"),
            |_| Ok(()),
        )
        .unwrap();

        // 4. Move + edit: src/move_and_edit.py -> src/moved_edited.py then edit.
        work_move(
            &repo,
            &rid,
            &state_dir,
            "proj1",
            &WorkMoveRequest {
                workspace: "fix-1".into(),
                operation_id: "op_m2".into(),
                from: "src/move_and_edit.py".into(),
                to: "src/moved_edited.py".into(),
                expected_from_hash: None,
                overwrite: false,
                expected_to_hash: None,
            },
            &scope(),
            auth_target("fix-1"),
            |_| Ok(()),
        )
        .unwrap();
        work_edit(
            &repo,
            &rid,
            &state_dir,
            "proj1",
            &WorkEditRequest {
                workspace: "fix-1".into(),
                operation_id: "op_e2".into(),
                task_id: None,
                edits: vec![WorkFileEdit {
                    path: "src/moved_edited.py".into(),
                    expected_hash: None,
                    replacements: vec![WorkReplacement {
                        old_text: "VAL = 1".into(),
                        new_text: "VAL = 2".into(),
                        replace_all: false,
                    }],
                }],
            },
            &scope(),
            auth_target("fix-1"),
            |_| Ok(()),
        )
        .unwrap();

        // 5. Add new files (one with final newline in new subdir, one without final newline).
        fs::create_dir_all(repo.join("_pro/work/fix-1/src/sub")).unwrap();
        fs::write(repo.join("_pro/work/fix-1/src/sub/added.py"), "NEW = 1\n").unwrap();
        fs::write(repo.join("_pro/work/fix-1/src/added_no_nl.txt"), "no_newline_here").unwrap();

        // Verify work_diff changes NOTHING on disk (no root-locks created if removed, no outbox created).
        let locks_dir = state_dir.join("patch-journals/root-locks");
        let _ = fs::remove_dir_all(&locks_dir);

        let page1 = compute_work_diff(
            &repo,
            &rid,
            &state_dir,
            "proj1",
            &WorkDiffRequest {
                workspace: "fix-1".into(),
                paths: None,
                summary_only: false,
                expected_diff_sha256: None,
                offset: 0,
                limit: 120,
            },
        )
        .unwrap();
        assert!(!locks_dir.exists(), "work_diff must not write anything to disk");
        assert!(!repo.join("_pro/outbox").exists());
        assert!(!page1.has_drift);
        assert!(page1.truncated);
        assert!(page1.next_offset.is_some());

        // Untouched project files and hidden files NEVER appear in work_diff.
        let serialized_diff = serde_json::to_string(&page1).unwrap();
        assert!(!serialized_diff.contains("untouched.py"));
        assert!(!serialized_diff.contains(".env"));
        assert!(!serialized_diff.contains("auth.json"));
        assert!(!serialized_diff.contains("never_diffed"));

        // Verify pagination reconstructs the exact full diff with expected_diff_sha256.
        let mut assembled = page1.content.clone();
        let mut cursor = page1.next_offset;
        while let Some(off) = cursor {
            let p = compute_work_diff(
                &repo,
                &rid,
                &state_dir,
                "proj1",
                &WorkDiffRequest {
                    workspace: "fix-1".into(),
                    paths: None,
                    summary_only: false,
                    expected_diff_sha256: Some(page1.diff_sha256.clone()),
                    offset: off,
                    limit: 120,
                },
            )
            .unwrap();
            assembled.push_str(&p.content);
            cursor = p.next_offset;
        }
        assert_eq!(sha256_bytes(assembled.as_bytes()), page1.diff_sha256);
        assert!(assembled.contains("rename from src/old_name.py"));
        assert!(assembled.contains("rename to src/new_name.py"));
        assert!(assembled.contains("\\ No newline at end of file"));

        // Export diff to `_pro/outbox/fix-1.diff` (create-only!).
        let (exported, _journal) = export_work_diff_to_outbox(
            &repo,
            &rid,
            &state_dir,
            "proj1",
            &WorkExportDiffRequest {
                workspace: "fix-1".into(),
                operation_id: "op_exp1".into(),
                path: "_pro/outbox/fix-1.diff".into(),
                paths: None,
                allow_drifted: false,
                task_id: None,
            },
            &scope(),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(exported.path, "_pro/outbox/fix-1.diff");
        assert_eq!(exported.diff_sha256, page1.diff_sha256);
        // Only ONE file under `_pro/outbox/`.
        let outbox_entries: Vec<_> = fs::read_dir(repo.join("_pro/outbox"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(outbox_entries, vec!["fix-1.diff"]);

        // Re-exporting to existing name is refused with VERSION_CONFLICT.
        let dup_err = export_work_diff_to_outbox(
            &repo,
            &rid,
            &state_dir,
            "proj1",
            &WorkExportDiffRequest {
                workspace: "fix-1".into(),
                operation_id: "op_exp2".into(),
                path: "_pro/outbox/fix-1.diff".into(),
                paths: None,
                allow_drifted: false,
                task_id: None,
            },
            &scope(),
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(dup_err.code, ErrorCode::VersionConflict);

        // REAL `git apply --check` AND `git apply` in the temporary Git repository!
        let check_out = run_git(&repo, &["apply", "--check", "_pro/outbox/fix-1.diff"]);
        assert!(
            check_out.status.success(),
            "git apply --check failed: {}\nDIFF:\n{}",
            String::from_utf8_lossy(&check_out.stderr),
            assembled
        );
        let apply_out = run_git(&repo, &["apply", "_pro/outbox/fix-1.diff"]);
        assert!(
            apply_out.status.success(),
            "git apply failed: {}",
            String::from_utf8_lossy(&apply_out.stderr)
        );
        assert_eq!(fs::read_to_string(repo.join("src/app.py")).unwrap(), "line1\nline2_fixed\nline2_extra\nline3\n");
        assert!(!repo.join("src/obsolete.py").exists());
        assert!(!repo.join("src/del_no_nl.txt").exists());
        assert!(!repo.join("src/old_name.py").exists());
        assert_eq!(fs::read_to_string(repo.join("src/new_name.py")).unwrap(), "def keep():\n    return 42\n");
        assert!(!repo.join("src/move_and_edit.py").exists());
        assert_eq!(fs::read_to_string(repo.join("src/moved_edited.py")).unwrap(), "VAL = 2\n");
        assert_eq!(fs::read_to_string(repo.join("src/sub/added.py")).unwrap(), "NEW = 1\n");
        assert_eq!(fs::read(repo.join("src/no_nl.txt")).unwrap(), b"alpha\ngamma");
        assert_eq!(fs::read(repo.join("src/added_no_nl.txt")).unwrap(), b"no_newline_here");
        assert_eq!(fs::read_to_string(repo.join("src/untouched.py")).unwrap(), "NEVER_COPIED = True\n");
    }

    #[test]
    fn work_diff_reports_drift_and_lists_binary_and_oversized_without_content() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().join("state");
        let root = tmp.path().join("proj");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();

        fs::write(root.join("src/drift.py"), "v1\n").unwrap();
        fs::write(root.join("src/img.bin"), b"\x00\x01\x02BINARY_OLD").unwrap();
        let big_old = "A".repeat(WORK_DIFF_MAX_FILE_BYTES as usize + 64);
        fs::write(root.join("src/big.txt"), &big_old).unwrap();

        let sf = ScopedFiles::new(&root, None).unwrap();
        let rid = sf.current_root_identity().unwrap();

        work_copy(
            &root,
            &rid,
            &state_dir,
            "proj1",
            &WorkCopyRequest {
                workspace: "w1".into(),
                mode: WorkCopyMode::FromProject {
                    paths: vec!["src".into()],
                    exclude_generated: true,
                },
                overwrite_existing: false,
            },
            &scope(),
            auth_target("w1"),
            |_| Ok(()),
        )
        .unwrap();

        // Owner edits live drift.py AFTER work_copy -> triggers baseline drift!
        fs::write(root.join("src/drift.py"), "v2_owner\n").unwrap();
        // Workspace edits drift.py, img.bin, and big.txt.
        fs::write(root.join("_pro/work/w1/src/drift.py"), "v2_agent\n").unwrap();
        fs::write(root.join("_pro/work/w1/src/img.bin"), b"\x00\x01\x02BINARY_NEW_SECRET").unwrap();
        let big_new = format!("B{}", &big_old[1..]);
        fs::write(root.join("_pro/work/w1/src/big.txt"), &big_new).unwrap();

        let diff = compute_work_diff(
            &root,
            &rid,
            &state_dir,
            "proj1",
            &WorkDiffRequest {
                workspace: "w1".into(),
                paths: None,
                summary_only: false,
                expected_diff_sha256: None,
                offset: 0,
                limit: WORK_DIFF_DEFAULT_LIMIT,
            },
        )
        .unwrap();
        assert!(diff.has_drift);
        assert_eq!(diff.drifted_files, vec!["src/drift.py"]);
        assert_eq!(diff.binary_or_oversized_files, vec!["src/big.txt", "src/img.bin"]);

        let by_path: BTreeMap<_, _> = diff.files.iter().map(|f| (f.path.as_str(), f)).collect();
        assert!(by_path["src/drift.py"].drifted_from_baseline);
        assert_eq!(by_path["src/img.bin"].status, "binary_modified");
        assert!(by_path["src/img.bin"].binary && by_path["src/img.bin"].content_omitted);
        assert_eq!(by_path["src/big.txt"].status, "oversized_modified");
        assert!(by_path["src/big.txt"].oversized && by_path["src/big.txt"].content_omitted);
        // Binary and over-size file contents MUST NOT appear in diff.content.
        assert!(!diff.content.contains("BINARY_NEW_SECRET"));
        assert!(!diff.content.contains("AAAAAAAA"));

        // work_export_diff refuses binary/oversized changes with UNSUPPORTED_PATH_TYPE.
        let err = export_work_diff_to_outbox(
            &root,
            &rid,
            &state_dir,
            "proj1",
            &WorkExportDiffRequest {
                workspace: "w1".into(),
                operation_id: "op_bin".into(),
                path: "_pro/outbox/bin.diff".into(),
                paths: None,
                allow_drifted: true,
                task_id: None,
            },
            &scope(),
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedPathType);

        // With paths filtered to only src/drift.py, allow_drifted=false refuses with VERSION_CONFLICT.
        let drift_err = export_work_diff_to_outbox(
            &root,
            &rid,
            &state_dir,
            "proj1",
            &WorkExportDiffRequest {
                workspace: "w1".into(),
                operation_id: "op_drift".into(),
                path: "_pro/outbox/drift.diff".into(),
                paths: Some(vec!["src/drift.py".into()]),
                allow_drifted: false,
                task_id: None,
            },
            &scope(),
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(drift_err.code, ErrorCode::VersionConflict);
        assert!(!root.join("_pro/outbox/drift.diff").exists());
    }

    #[test]
    fn work_apply_dry_run_confirm_atomic_rollback_and_patch_journal_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().join("state");
        let jdir = state_dir.join("patch-journals");
        let root = tmp.path().join("proj");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();

        fs::write(root.join("src/a.py"), "a = 1\n").unwrap();
        fs::write(root.join("src/del.py"), "remove_me = True\n").unwrap();
        fs::write(root.join("src/data.bin"), b"\x00\x01old").unwrap();

        let sf = ScopedFiles::new(&root, None).unwrap();
        let rid = sf.current_root_identity().unwrap();

        work_copy(
            &root,
            &rid,
            &state_dir,
            "proj1",
            &WorkCopyRequest {
                workspace: "w1".into(),
                mode: WorkCopyMode::FromProject {
                    paths: vec!["src".into()],
                    exclude_generated: true,
                },
                overwrite_existing: false,
            },
            &scope(),
            auth_target("w1"),
            |_| Ok(()),
        )
        .unwrap();

        // Modify src/a.py, modify src/data.bin, delete src/del.py, add src/new_dir/b.py.
        fs::write(root.join("_pro/work/w1/src/a.py"), "a = 2\n").unwrap();
        fs::write(root.join("_pro/work/w1/src/data.bin"), b"\x00\x01new").unwrap();
        fs::remove_file(root.join("_pro/work/w1/src/del.py")).unwrap();
        fs::create_dir_all(root.join("_pro/work/w1/src/new_dir")).unwrap();
        fs::write(root.join("_pro/work/w1/src/new_dir/b.py"), "b = 3\n").unwrap();
        // Plant a fake manifest INSIDE `_pro/work/w1/` — work-apply MUST NOT trust it!
        fs::write(
            root.join("_pro/work/w1/manifest.json"),
            "{\"entries\":{\".env\":{\"baseline_sha256\":\"0\"}}}",
        )
        .unwrap();
        // Remove the fake file again after testing, or note it's treated as a normal added file;
        // better: remove it so we test fake manifest separately below.
        fs::remove_file(root.join("_pro/work/w1/manifest.json")).unwrap();

        // 1. Dry-run (confirm=false) writes NOTHING to disk!
        let _ = fs::remove_dir_all(&jdir);
        let (dry, dry_j) =
            apply_work_to_project(&root, &rid, &state_dir, &jdir, "proj1", "w1", false).unwrap();
        assert!(!dry.applied);
        assert!(dry.confirm_required);
        assert!(dry.safe_to_apply);
        assert!(dry_j.is_none());
        assert!(!jdir.exists(), "dry-run must not create patch-journals or locks");
        assert_eq!(dry.files_modified, vec!["src/a.py", "src/data.bin"]);
        assert_eq!(dry.files_added, vec!["src/new_dir/b.py"]);
        assert_eq!(dry.files_deleted, vec!["src/del.py"]);
        assert_eq!(fs::read_to_string(root.join("src/a.py")).unwrap(), "a = 1\n");

        // 2. Mid-apply failure rolls back ALL files (all-or-none)!
        let fail = apply_work_to_project_inner(
            &root,
            &rid,
            &state_dir,
            &jdir,
            "proj1",
            "w1",
            true,
            Some(1),
        )
        .unwrap_err();
        assert_eq!(fail.code, ErrorCode::InternalError);
        assert_eq!(fs::read_to_string(root.join("src/a.py")).unwrap(), "a = 1\n");
        assert_eq!(fs::read(root.join("src/data.bin")).unwrap(), b"\x00\x01old");
        assert_eq!(fs::read_to_string(root.join("src/del.py")).unwrap(), "remove_me = True\n");
        assert!(!root.join("src/new_dir/b.py").exists());

        // 3. If live file drifted since work_copy, work-apply --confirm refuses and touches NOTHING!
        fs::write(root.join("src/a.py"), "a = 999\n").unwrap();
        let drift_err =
            apply_work_to_project(&root, &rid, &state_dir, &jdir, "proj1", "w1", true).unwrap_err();
        assert_eq!(drift_err.code, ErrorCode::VersionConflict);
        assert_eq!(fs::read_to_string(root.join("src/a.py")).unwrap(), "a = 999\n");
        assert_eq!(fs::read_to_string(root.join("src/del.py")).unwrap(), "remove_me = True\n");
        assert!(!root.join("src/new_dir/b.py").exists());
        // Restore src/a.py to baseline.
        fs::write(root.join("src/a.py"), "a = 1\n").unwrap();

        // 4. Real work-apply --confirm applies all files and writes a working rollback-patch journal!
        let (applied, journal_opt) =
            apply_work_to_project(&root, &rid, &state_dir, &jdir, "proj1", "w1", true).unwrap();
        assert!(applied.applied);
        let jid = applied.journal_id.clone().unwrap();
        assert_eq!(journal_opt.unwrap().state, "committed");
        assert_eq!(fs::read_to_string(root.join("src/a.py")).unwrap(), "a = 2\n");
        assert_eq!(fs::read(root.join("src/data.bin")).unwrap(), b"\x00\x01new");
        assert!(!root.join("src/del.py").exists());
        assert_eq!(fs::read_to_string(root.join("src/new_dir/b.py")).unwrap(), "b = 3\n");

        // 5. Existing `rollback_patch_journal` reverts modify, add, delete, and binary changes!
        let restored = sf.rollback_patch_journal(&jdir, &jid).unwrap();
        assert_eq!(restored.len(), 4);
        assert_eq!(fs::read_to_string(root.join("src/a.py")).unwrap(), "a = 1\n");
        assert_eq!(fs::read(root.join("src/data.bin")).unwrap(), b"\x00\x01old");
        assert_eq!(fs::read_to_string(root.join("src/del.py")).unwrap(), "remove_me = True\n");
        assert!(!root.join("src/new_dir/b.py").exists());
    }

    #[test]
    fn work_diff_export_and_apply_refuse_hidden_pro_path_hazards_case_and_junctions() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().join("state");
        let jdir = state_dir.join("patch-journals");
        let root = tmp.path().join("proj");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("src/App.py"), "X = 1\n").unwrap();
        fs::write(root.join(".env"), "SECRET=1\n").unwrap();
        fs::write(outside.join("out.txt"), "OUTSIDE\n").unwrap();

        let sf = ScopedFiles::new(&root, None).unwrap();
        let rid = sf.current_root_identity().unwrap();

        work_copy(
            &root,
            &rid,
            &state_dir,
            "proj1",
            &WorkCopyRequest {
                workspace: "w1".into(),
                mode: WorkCopyMode::FromProject {
                    paths: vec!["src/App.py".into()],
                    exclude_generated: true,
                },
                overwrite_existing: false,
            },
            &scope(),
            auth_target("w1"),
            |_| Ok(()),
        )
        .unwrap();
        fs::write(root.join("_pro/work/w1/src/App.py"), "X = 2\n").unwrap();

        // 1. Outbox path validation hazards.
        for (bad, expected) in [
            ("_pro/inbox/a.diff", ErrorCode::BridgePolicyDenied),
            ("_pro/reports/a.diff", ErrorCode::BridgePolicyDenied),
            ("_pro/outbox/sub/a.diff", ErrorCode::BridgePolicyDenied),
            ("_PRO/outbox/a.diff", ErrorCode::BridgePolicyDenied),
            ("_pro/OUTBOX/a.diff", ErrorCode::BridgePolicyDenied),
            ("_pro/OUTBOX~1/a.diff", ErrorCode::BridgePolicyDenied),
            ("_pro/outbox/.env.diff", ErrorCode::BridgePolicyDenied),
            ("_pro/outbox/../a.diff", ErrorCode::PathOutsideRoot),
            (r"_pro\outbox\a.diff", ErrorCode::PathOutsideRoot),
            ("_pro/outbox/a:b.diff", ErrorCode::PathOutsideRoot),
            ("/_pro/outbox/a.diff", ErrorCode::PathOutsideRoot),
            ("_pro/outbox/a.txt", ErrorCode::InvalidArgument),
        ] {
            assert_eq!(validate_outbox_diff_path(bad).unwrap_err().code, expected, "{bad}");
        }

        // 2. Hidden file planted inside workspace -> refused without naming `.env`.
        fs::write(root.join("_pro/work/w1/.env"), "SECRET=hacked\n").unwrap();
        let hidden_diff_err = compute_work_diff(
            &root,
            &rid,
            &state_dir,
            "proj1",
            &WorkDiffRequest {
                workspace: "w1".into(),
                paths: None,
                summary_only: false,
                expected_diff_sha256: None,
                offset: 0,
                limit: WORK_DIFF_DEFAULT_LIMIT,
            },
        )
        .unwrap_err();
        assert_eq!(hidden_diff_err.code, ErrorCode::BridgePolicyDenied);
        assert!(!hidden_diff_err.message.contains(".env"));
        let hidden_apply_err =
            apply_work_to_project(&root, &rid, &state_dir, &jdir, "proj1", "w1", true).unwrap_err();
        assert_eq!(hidden_apply_err.code, ErrorCode::BridgePolicyDenied);
        assert_eq!(fs::read_to_string(root.join(".env")).unwrap(), "SECRET=1\n");
        fs::remove_file(root.join("_pro/work/w1/.env")).unwrap();

        // 3. `_pro` target planted inside workspace -> refused for diff & work-apply.
        fs::create_dir_all(root.join("_pro/work/w1/_pro/outbox")).unwrap();
        fs::write(root.join("_pro/work/w1/_pro/outbox/sneak.txt"), "x").unwrap();
        assert_eq!(
            apply_work_to_project(&root, &rid, &state_dir, &jdir, "proj1", "w1", true)
                .unwrap_err()
                .code,
            ErrorCode::BridgePolicyDenied
        );
        fs::remove_dir_all(root.join("_pro/work/w1/_pro")).unwrap();

        // 4. Junction inside workspace -> refused with UNSUPPORTED_PATH_TYPE.
        let ws_junc = root.join("_pro/work/w1/junc");
        mk_junction(&ws_junc, &outside);
        assert_eq!(
            compute_work_diff(
                &root,
                &rid,
                &state_dir,
                "proj1",
                &WorkDiffRequest {
                    workspace: "w1".into(),
                    paths: None,
                    summary_only: false,
                    expected_diff_sha256: None,
                    offset: 0,
                    limit: WORK_DIFF_DEFAULT_LIMIT,
                },
            )
            .unwrap_err()
            .code,
            ErrorCode::UnsupportedPathType
        );
        assert_eq!(
            apply_work_to_project(&root, &rid, &state_dir, &jdir, "proj1", "w1", true)
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedPathType
        );
        rm_junction(&ws_junc);

        // 5. Junction at live project target -> refused with UNSUPPORTED_PATH_TYPE.
        let live_junc = root.join("linked_dir");
        mk_junction(&live_junc, &outside);
        fs::create_dir_all(root.join("_pro/work/w1/linked_dir")).unwrap();
        fs::write(root.join("_pro/work/w1/linked_dir/pwn.txt"), "NO\n").unwrap();
        assert_eq!(
            apply_work_to_project(&root, &rid, &state_dir, &jdir, "proj1", "w1", true)
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedPathType
        );
        assert!(!outside.join("pwn.txt").exists());
        fs::remove_dir_all(root.join("_pro/work/w1/linked_dir")).unwrap();
        rm_junction(&live_junc);

        // 6. Manifest in state_dir tampered with unsafe paths (.., \, :, /, ~1, .env, _pro) -> refused!
        let mpath = state_dir.join("work-manifests/proj1/w1.json");
        let orig_manifest = fs::read(&mpath).unwrap();
        for (bad_key, expected) in [
            ("../outside/out.txt", ErrorCode::PathOutsideRoot),
            (r"src\App.py", ErrorCode::PathOutsideRoot),
            ("C:App.py", ErrorCode::PathOutsideRoot),
            ("/etc/passwd", ErrorCode::PathOutsideRoot),
            ("SRC~1/App.py", ErrorCode::BridgePolicyDenied),
            (".env", ErrorCode::BridgePolicyDenied),
            ("_pro/outbox/x.txt", ErrorCode::BridgePolicyDenied),
        ] {
            let mut m: WorkManifest = serde_json::from_slice(&orig_manifest).unwrap();
            m.entries.insert(
                bad_key.to_owned(),
                crate::work::WorkManifestEntry {
                    baseline_sha256: "0".repeat(64),
                    size_bytes: 1,
                    copied_at: Utc::now().to_rfc3339(),
                    deleted_in_work: false,
                },
            );
            fs::write(&mpath, serde_json::to_vec(&m).unwrap()).unwrap();
            assert_eq!(
                apply_work_to_project(&root, &rid, &state_dir, &jdir, "proj1", "w1", true)
                    .unwrap_err()
                    .code,
                expected,
                "tampered manifest key {bad_key}"
            );
        }
        fs::write(&mpath, &orig_manifest).unwrap();
    }
}
