//! Workspace-scoped copy, multi-file edit, move, delete, and bridge-side manifests
//! strictly confined to `_pro/work/<workspace>/**`.

use crate::files::{
    DELEGATED_WRITE_MAX_SCOPE_BYTES, DELEGATED_WRITE_MAX_SCOPE_FILES,
    DELEGATED_WRITE_MAX_WALK_ENTRIES, GENERATED_DIRS, ScopedFiles, check_delegated_write_quota,
    is_hidden_from_remote, is_quota_link, lock_patch_root, measure_delegated_folder_quota,
    patch_commit_conflict, patch_io_error, read_delegated_work_file_verified, write_synced_new,
};
#[cfg(windows)]
use crate::files::{PatchParent, verify_opened_name, verify_work_preimage_handle};
use crate::policy::{
    MAX_WORKSPACES_PER_PROJECT, PRO_WORK_PREFIX, has_windows_short_name, is_patch_stage_name,
    is_pro_work_file_path, validate_remote_relative_path, validate_work_name,
    validate_work_test_selector,
};
#[cfg(windows)]
use bridge_platform::windows::{
    atomic_replace_file, commit_patch_stage, create_patch_stage, file_identity_from_handle,
    file_path_from_handle, open_patch_directory, open_path_metadata_no_follow, open_read_no_follow,
};
use bridge_platform::sha256_bytes;
use bridge_types::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const WORK_COPY_MAX_PATHS: usize = 64;
pub const WORK_COPY_MAX_FILES: usize = 500;
pub const WORK_COPY_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
pub const WORK_COPY_MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
pub const WORK_COPY_MAX_WALK_ENTRIES: usize = 20_000;

pub const WORK_EDIT_MAX_FILES: usize = 32;
pub const WORK_EDIT_MAX_HUNKS: usize = 64;
pub const WORK_EDIT_MAX_FILE_BYTES: usize = 1024 * 1024;
pub const WORK_EDIT_MAX_CALL_BYTES: usize = 4 * 1024 * 1024;

pub const WORK_DELETE_MAX_PATHS: usize = 64;

pub const WORK_EXEC_MAX_SNAPSHOT_FILES: usize = 128;
pub const WORK_EXEC_MAX_FILE_BYTES: u64 = 256 * 1024;
pub const WORK_EXEC_MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024;
pub const WORK_EXEC_MAX_DISCOVERY_ENTRIES: usize = 1_000;
pub const WORK_EXEC_MAX_DEPTH: usize = 6;

const WORK_MANIFEST_VERSION: u32 = 1;
const WORK_MANIFEST_DIR_SCAN_CAP: usize = 512;
const WORK_COPY_RAW_WALK_SAFETY_CAP: usize = 200_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkManifestEntry {
    pub baseline_sha256: String,
    pub size_bytes: u64,
    pub copied_at: String,
    #[serde(default)]
    pub deleted_in_work: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkManifest {
    pub version: u32,
    pub project_id: String,
    pub root_identity: String,
    pub workspace: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub entries: BTreeMap<String, WorkManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkQuotaTelemetry {
    pub files_used: usize,
    pub max_files: usize,
    pub bytes_used: u64,
    pub max_bytes: u64,
    pub workspaces_used: usize,
    pub max_workspaces: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkCopySkipped {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub enum WorkCopyMode {
    FromProject {
        paths: Vec<String>,
        exclude_generated: bool,
    },
    WithinWorkspace {
        from: String,
        to: String,
    },
}

#[derive(Debug, Clone)]
pub struct WorkCopyRequest {
    pub workspace: String,
    pub mode: WorkCopyMode,
    pub overwrite_existing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkCopyResult {
    pub workspace: String,
    pub work_root: String,
    pub within_workspace: bool,
    pub files_copied: Vec<String>,
    pub copied_count: usize,
    pub total_bytes: u64,
    pub hashes: BTreeMap<String, String>,
    pub skipped_generated_dirs: usize,
    pub skipped_non_secret: Vec<WorkCopySkipped>,
    pub quota: WorkQuotaTelemetry,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkReplacement {
    pub old_text: String,
    pub new_text: String,
    #[serde(default)]
    pub replace_all: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkFileEdit {
    pub path: String,
    #[serde(default)]
    pub expected_hash: Option<String>,
    pub replacements: Vec<WorkReplacement>,
}

#[derive(Debug, Clone)]
pub struct WorkEditRequest {
    pub workspace: String,
    pub operation_id: String,
    pub task_id: Option<String>,
    pub edits: Vec<WorkFileEdit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkEditResult {
    pub workspace: String,
    pub journal_id: String,
    pub operation_id: String,
    pub files_applied: Vec<String>,
    pub replacements_applied: usize,
    pub postimage_hashes: BTreeMap<String, String>,
    pub unified_diff: String,
    pub diff_sha256: String,
    pub quota: WorkQuotaTelemetry,
}

#[derive(Debug, Clone)]
pub struct WorkMoveRequest {
    pub workspace: String,
    pub operation_id: String,
    pub from: String,
    pub to: String,
    pub expected_from_hash: Option<String>,
    pub overwrite: bool,
    pub expected_to_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkMoveResult {
    pub workspace: String,
    pub operation_id: String,
    pub from: String,
    pub to: String,
    pub sha256: String,
    pub overwritten: bool,
    pub quota: WorkQuotaTelemetry,
}

#[derive(Debug, Clone)]
pub enum WorkDeleteTarget {
    Files {
        paths: Vec<String>,
        expected_hashes: BTreeMap<String, String>,
    },
    WholeWorkspace,
}

#[derive(Debug, Clone)]
pub struct WorkDeleteRequest {
    pub workspace: String,
    pub operation_id: String,
    pub target: WorkDeleteTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkDeleteResult {
    pub workspace: String,
    pub operation_id: String,
    pub deleted_workspace: bool,
    pub deleted_files: Vec<String>,
    pub freed_files: usize,
    pub freed_bytes: u64,
    pub quota: WorkQuotaTelemetry,
}

pub fn work_manifest_path(state_dir: &Path, project_id: &str, workspace: &str) -> Result<PathBuf, BridgeError> {
    validate_safe_id(project_id)?;
    validate_work_name(workspace)?;
    Ok(state_dir
        .join("work-manifests")
        .join(project_id)
        .join(format!("{workspace}.json")))
}

fn ensure_safe_manifest_dir(state_dir: &Path, project_id: &str, create: bool) -> Result<Option<PathBuf>, BridgeError> {
    validate_safe_id(project_id)?;
    let root = state_dir.join("work-manifests");
    let proj_dir = root.join(project_id);
    for dir in [&root, &proj_dir] {
        match fs::symlink_metadata(dir) {
            Ok(meta) => {
                if is_quota_link(&meta) || !meta.is_dir() {
                    return Err(BridgeError::new(
                        ErrorCode::UnsupportedPathType,
                        "Work manifest directory is a link or non-directory.",
                        OriginLayer::FileService,
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !create {
                    return Ok(None);
                }
                fs::create_dir(dir).map_err(patch_io_error)?;
            }
            Err(error) => return Err(patch_io_error(error)),
        }
    }
    Ok(Some(proj_dir))
}

pub fn load_work_manifest(
    state_dir: &Path,
    project_id: &str,
    workspace: &str,
) -> Result<Option<WorkManifest>, BridgeError> {
    let Some(dir) = ensure_safe_manifest_dir(state_dir, project_id, false)? else {
        return Ok(None);
    };
    validate_work_name(workspace)?;
    let path = dir.join(format!("{workspace}.json"));
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(patch_io_error(error)),
    };
    if is_quota_link(&meta) || !meta.is_file() {
        return Err(BridgeError::new(
            ErrorCode::UnsupportedPathType,
            "Work manifest path is a link or non-file.",
            OriginLayer::FileService,
        ));
    }
    let raw = fs::read(&path).map_err(patch_io_error)?;
    let manifest: WorkManifest = serde_json::from_slice(&raw).map_err(|e| {
        BridgeError::new(
            ErrorCode::InternalError,
            format!("Corrupt work manifest for workspace '{workspace}': {e}"),
            OriginLayer::FileService,
        )
    })?;
    Ok(Some(manifest))
}

fn save_work_manifest(state_dir: &Path, manifest: &WorkManifest) -> Result<(), BridgeError> {
    let dir = ensure_safe_manifest_dir(state_dir, &manifest.project_id, true)?
        .ok_or_else(|| BridgeError::new(ErrorCode::InternalError, "Manifest directory missing.", OriginLayer::FileService))?;
    validate_work_name(&manifest.workspace)?;
    let path = dir.join(format!("{}.json", manifest.workspace));
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if is_quota_link(&meta) || !meta.is_file() {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                "Work manifest path is a link or non-file.",
                OriginLayer::FileService,
            ));
        }
    }
    let data = serde_json::to_vec_pretty(manifest).map_err(|e| {
        BridgeError::new(
            ErrorCode::InternalError,
            format!("Work manifest serialization failed: {e}"),
            OriginLayer::FileService,
        )
    })?;
    let staged = dir.join(format!(".manifest_{}.tmp", uuid::Uuid::new_v4().simple()));
    write_synced_new(&staged, &data)?;
    #[cfg(windows)]
    let replace_res = atomic_replace_file(&staged, &path, "work-manifest.json");
    #[cfg(not(windows))]
    let replace_res = fs::rename(&staged, &path).map_err(patch_io_error);
    if replace_res.is_err() {
        let _ = fs::remove_file(&staged);
    }
    replace_res
}

fn remove_work_manifest(state_dir: &Path, project_id: &str, workspace: &str) -> Result<bool, BridgeError> {
    let Some(dir) = ensure_safe_manifest_dir(state_dir, project_id, false)? else {
        return Ok(false);
    };
    validate_work_name(workspace)?;
    let path = dir.join(format!("{workspace}.json"));
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(patch_io_error(error)),
    };
    if is_quota_link(&meta) || !meta.is_file() {
        return Err(BridgeError::new(
            ErrorCode::UnsupportedPathType,
            "Work manifest path is a link or non-file.",
            OriginLayer::FileService,
        ));
    }
    fs::remove_file(&path).map_err(patch_io_error)?;
    Ok(true)
}

/// Clear `deleted_in_work` in an existing manifest when a previously deleted baseline file
/// is recreated inside `_pro/work/<workspace>/` (e.g., via `file_write` or `file_patch`).
pub fn clear_manifest_deleted_flags(
    state_dir: &Path,
    project_id: &str,
    work_paths: &[String],
) -> Result<(), BridgeError> {
    let mut by_workspace: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in work_paths {
        if let Some((ws, subpath)) = split_pro_work_path(path) {
            by_workspace.entry(ws.to_owned()).or_default().push(subpath.to_owned());
        }
    }
    for (ws, subpaths) in by_workspace {
        let Some(mut manifest) = load_work_manifest(state_dir, project_id, &ws)? else {
            continue;
        };
        let mut changed = false;
        for sub in subpaths {
            if let Some(entry) = manifest.entries.get_mut(&sub) {
                if entry.deleted_in_work {
                    entry.deleted_in_work = false;
                    changed = true;
                }
            }
        }
        if changed {
            manifest.updated_at = Utc::now().to_rfc3339();
            save_work_manifest(state_dir, &manifest)?;
        }
    }
    Ok(())
}

/// Split exact-case `_pro/work/<workspace>/<subpath>` into `(workspace, subpath)`.
pub fn split_pro_work_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix(PRO_WORK_PREFIX)?;
    let (ws, sub) = rest.split_once('/')?;
    if validate_work_name(ws).is_ok() && !sub.is_empty() {
        Some((ws, sub))
    } else {
        None
    }
}

/// Collect all existing workspace names from both bridge manifests and `_pro/work/*`.
pub fn list_existing_workspaces(project_root: &Path, state_dir: &Path, project_id: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if validate_safe_id(project_id).is_ok() {
        let mdir = state_dir.join("work-manifests").join(project_id);
        if fs::symlink_metadata(&mdir).is_ok_and(|m| m.is_dir() && !is_quota_link(&m)) {
            if let Ok(entries) = fs::read_dir(&mdir) {
                for entry in entries.take(WORK_MANIFEST_DIR_SCAN_CAP).flatten() {
                    if let Ok(ft) = entry.file_type() {
                        if ft.is_file() {
                            if let Some(stem) = entry.file_name().to_str().and_then(|s| s.strip_suffix(".json")) {
                                if validate_work_name(stem).is_ok() {
                                    names.insert(stem.to_owned());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let work_dir = project_root.join("_pro").join("work");
    if fs::symlink_metadata(&work_dir).is_ok_and(|m| m.is_dir() && !is_quota_link(&m)) {
        if let Ok(entries) = fs::read_dir(&work_dir) {
            for entry in entries.take(WORK_MANIFEST_DIR_SCAN_CAP).flatten() {
                if let Ok(meta) = fs::symlink_metadata(entry.path()) {
                    if meta.is_dir() && !is_quota_link(&meta) {
                        if let Some(name) = entry.file_name().to_str() {
                            if validate_work_name(name).is_ok() {
                                names.insert(name.to_owned());
                            }
                        }
                    }
                }
            }
        }
    }
    names
}

/// Enforce `MAX_WORKSPACES_PER_PROJECT` before creating files in any workspace(s).
pub fn check_workspace_limit(
    project_root: &Path,
    state_dir: &Path,
    project_id: &str,
    workspaces: &[&str],
) -> Result<(), BridgeError> {
    let mut all = list_existing_workspaces(project_root, state_dir, project_id);
    for ws in workspaces {
        all.insert((*ws).to_owned());
    }
    if all.len() > MAX_WORKSPACES_PER_PROJECT {
        return Err(BridgeError::new(
            ErrorCode::ResourceBudgetExceeded,
            format!(
                "Project already has the maximum of {MAX_WORKSPACES_PER_PROJECT} workspaces; remove an old workspace with work_delete(delete_workspace=true) first."
            ),
            OriginLayer::FileService,
        ));
    }
    Ok(())
}

pub fn work_quota_telemetry(
    project_root: &Path,
    state_dir: &Path,
    project_id: &str,
) -> Result<WorkQuotaTelemetry, BridgeError> {
    let usage = measure_delegated_folder_quota(project_root, "_pro")?;
    let workspaces_used = list_existing_workspaces(project_root, state_dir, project_id).len();
    Ok(WorkQuotaTelemetry {
        files_used: usage.files,
        max_files: DELEGATED_WRITE_MAX_SCOPE_FILES,
        bytes_used: usage.bytes,
        max_bytes: DELEGATED_WRITE_MAX_SCOPE_BYTES,
        workspaces_used,
        max_workspaces: MAX_WORKSPACES_PER_PROJECT,
    })
}

#[cfg(windows)]
fn open_move_source_no_follow(path: &Path) -> std::io::Result<File> {
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

/// Verify no reparse points or non-directories along an existing relative prefix on non-Windows.
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

/// Verify `_pro`, `_pro/work`, and `_pro/work/<workspace>` (whichever already exist) are real
/// non-reparse directories with exact lowercase names.
fn verify_existing_work_prefix(project_root: &Path, cur_rid: &str, workspace: &str) -> Result<(), BridgeError> {
    let ws_rel = format!("{PRO_WORK_PREFIX}{workspace}");
    #[cfg(windows)]
    {
        PatchParent::pin_dir_existing(project_root, cur_rid, &ws_rel, true)?;
    }
    #[cfg(not(windows))]
    {
        let _ = cur_rid;
        check_no_symlink_prefix(project_root, &ws_rel)?;
        let ws_path = project_root.join(&ws_rel);
        if let Ok(meta) = fs::symlink_metadata(&ws_path) {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(BridgeError::new(
                    ErrorCode::UnsupportedPathType,
                    format!("Workspace path '{ws_rel}' is a link or non-directory."),
                    OriginLayer::FileService,
                ));
            }
        }
    }
    Ok(())
}

struct CopyItem {
    subpath: String,
    dst_rel: String,
    bytes: Vec<u8>,
    sha256: String,
    old_bytes: Option<Vec<u8>>,
    old_hash: Option<String>,
    old_ntfs_id: Option<String>,
}

struct StagedCopy {
    file: Option<File>,
    #[cfg(windows)]
    parent: PatchParent,
    destination: PathBuf,
    temp: PathBuf,
    committed: bool,
    temp_exists: bool,
}

impl StagedCopy {
    fn create(
        root: &Path,
        root_id: &str,
        relative: &str,
        temp_name: &str,
        created_dirs: &mut Vec<PathBuf>,
    ) -> Result<Self, BridgeError> {
        #[cfg(windows)]
        let parent = PatchParent::pin(root, root_id, relative, true, true, Some(created_dirs))?;
        let parts = validate_remote_relative_path(relative)?;
        let file_name = parts
            .last()
            .ok_or_else(|| patch_commit_conflict(relative))?;
        #[cfg(windows)]
        let destination = parent.path.join(file_name);
        #[cfg(not(windows))]
        let destination = {
            let _ = root_id;
            let mut dir = PathBuf::new();
            for name in &parts[..parts.len() - 1] {
                dir.push(name);
                let full_dir = root.join(&dir);
                match fs::symlink_metadata(&full_dir) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() || !meta.is_dir() {
                            return Err(BridgeError::new(
                                ErrorCode::UnsupportedPathType,
                                format!("Reparse point or non-directory denied while creating parent of '{relative}'."),
                                OriginLayer::FileService,
                            ));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        match fs::create_dir(&full_dir) {
                            Ok(()) => created_dirs.push(dir.clone()),
                            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                            Err(error) => return Err(patch_io_error(error)),
                        }
                    }
                    Err(error) => return Err(patch_io_error(error)),
                }
            }
            root.join(relative)
        };
        let temp = destination.with_file_name(temp_name);
        #[cfg(windows)]
        let file = create_patch_stage(&temp).map_err(patch_io_error)?;
        #[cfg(not(windows))]
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(patch_io_error)?;
        Ok(Self {
            file: Some(file),
            #[cfg(windows)]
            parent,
            destination,
            temp,
            committed: false,
            temp_exists: true,
        })
    }

    fn write_all(&mut self, relative: &str, bytes: &[u8]) -> Result<(), BridgeError> {
        let file = self.file.as_mut().unwrap();
        #[cfg(windows)]
        if file_path_from_handle(file)?.parent() != Some(self.parent.path.as_path()) {
            return Err(patch_commit_conflict(relative));
        }
        let _ = relative;
        file.write_all(bytes).map_err(patch_io_error)?;
        file.sync_all().map_err(patch_io_error)
    }

    fn verify_postimage(&mut self, relative: &str, expected_len: usize, expected_hash: &str) -> Result<(), BridgeError> {
        #[cfg(windows)]
        let written = {
            let file = self.file.as_mut().unwrap();
            let id = file_identity_from_handle(file)?;
            if id.size_bytes != expected_len as u64
                || file_path_from_handle(file)?.as_os_str() != self.destination.as_os_str()
            {
                return Err(patch_commit_conflict(relative));
            }
            file.seek(SeekFrom::Start(0)).map_err(patch_io_error)?;
            let mut buf = Vec::with_capacity(expected_len);
            file.take(expected_len as u64 + 1)
                .read_to_end(&mut buf)
                .map_err(patch_io_error)?;
            buf
        };
        #[cfg(not(windows))]
        let written = fs::read(&self.destination).map_err(patch_io_error)?;
        if written.len() != expected_len || sha256_bytes(&written) != expected_hash {
            return Err(BridgeError::new(
                ErrorCode::StalePrecondition,
                format!("Postimage verification failed for '{relative}'."),
                OriginLayer::FileService,
            ));
        }
        Ok(())
    }

    fn undo_create(&mut self) -> Result<(), BridgeError> {
        #[cfg(windows)]
        commit_patch_stage(
            self.file.as_ref().unwrap(),
            self.parent.directories.last().unwrap(),
            self.temp.file_name().unwrap(),
            false,
        )?;
        #[cfg(not(windows))]
        fs::remove_file(&self.destination).map_err(patch_io_error)?;
        self.committed = false;
        Ok(())
    }

    fn close(&mut self) {
        self.file.take();
        if self.temp_exists && !(cfg!(windows) && self.committed) {
            let _ = fs::remove_file(&self.temp);
        }
        self.temp_exists = false;
    }
}

/// Copy project files/subtrees (Mode A) or a single intra-workspace file (Mode B) strictly into
/// `_pro/work/<workspace>/**`, updating `<state_dir>/work-manifests/<project_id>/<workspace>.json`.
///
/// - `authorize_target`: invoked once per target workspace-relative subpath (`rel_subpath`); must
///   call `PolicyEngine::authorize_work_mutation` and return its `normalized_write_path`.
/// - `authorize_commit`: invoked right before each file is committed to re-verify grant validity.
#[allow(clippy::too_many_arguments)]
pub fn work_copy(
    project_root: &Path,
    root_identity: &str,
    state_dir: &Path,
    project_id: &str,
    req: &WorkCopyRequest,
    writable_scope: &[String],
    mut authorize_target: impl FnMut(&str) -> Result<String, BridgeError>,
    authorize_commit: impl Fn(&str) -> Result<(), BridgeError>,
) -> Result<WorkCopyResult, BridgeError> {
    validate_safe_id(project_id)?;
    validate_work_name(&req.workspace)?;

    match &req.mode {
        WorkCopyMode::FromProject { paths, .. } => {
            if paths.is_empty() || paths.len() > WORK_COPY_MAX_PATHS {
                return Err(BridgeError::new(
                    ErrorCode::InvalidArgument,
                    format!("work_copy 'paths' must contain between 1 and {WORK_COPY_MAX_PATHS} entries."),
                    OriginLayer::Validation,
                ));
            }
        }
        WorkCopyMode::WithinWorkspace { from, to } => {
            if from.is_empty() || to.is_empty() {
                return Err(BridgeError::new(
                    ErrorCode::InvalidArgument,
                    "work_copy within_workspace requires non-empty 'from' and 'to' paths.",
                    OriginLayer::Validation,
                ));
            }
        }
    }

    let remote_reader = ScopedFiles::new_remote_read(project_root, Some(root_identity.to_owned()))?;
    let cur_rid = remote_reader.current_root_identity()?;
    if root_identity.starts_with("ntfs:") && cur_rid != root_identity {
        return Err(BridgeError::new(
            ErrorCode::StalePrecondition,
            "Project root identity mismatch.",
            OriginLayer::FileService,
        ));
    }

    let journal_dir = state_dir.join("patch-journals");
    let _writer = lock_patch_root(&journal_dir, &cur_rid)?;

    // Verify `_pro`, `_pro/work`, and `_pro/work/<workspace>` (if existing) are non-reparse exact-case dirs
    // and enforce workspace count limit BEFORE writing anything.
    verify_existing_work_prefix(project_root, &cur_rid, &req.workspace)?;
    check_workspace_limit(project_root, state_dir, project_id, &[req.workspace.as_str()])?;

    #[cfg(windows)]
    let (_root_pin, root_path_buf) = open_verified_root(project_root, &cur_rid)?;
    #[cfg(windows)]
    let root_path_opt = Some(root_path_buf.as_path());
    #[cfg(not(windows))]
    let root_path_opt: Option<&Path> = None;

    let mut discovered: BTreeMap<String, (Vec<u8>, String)> = BTreeMap::new();
    let mut total_copy_bytes: u64 = 0;
    let mut skipped_generated_dirs: usize = 0;
    let mut skipped_non_secret: Vec<WorkCopySkipped> = Vec::new();
    let within_workspace = matches!(req.mode, WorkCopyMode::WithinWorkspace { .. });

    match &req.mode {
        WorkCopyMode::WithinWorkspace { from, to } => {
            let src_rel = authorize_target(from)?;
            let dst_rel = authorize_target(to)?;
            if src_rel.eq_ignore_ascii_case(&dst_rel) {
                return Err(BridgeError::new(
                    ErrorCode::InvalidArgument,
                    "work_copy within_workspace 'from' and 'to' must be different paths.",
                    OriginLayer::Validation,
                ));
            }
            if !is_pro_work_file_path(&src_rel) || !is_pro_work_file_path(&dst_rel) {
                return Err(BridgeError::new(
                    ErrorCode::BridgePolicyDenied,
                    "work_copy within_workspace paths must stay strictly inside '_pro/work/<workspace>/**'.",
                    OriginLayer::Policy,
                ));
            }
            #[cfg(windows)]
            PatchParent::pin(project_root, &cur_rid, &src_rel, true, false, None)?;
            #[cfg(not(windows))]
            check_no_symlink_prefix(project_root, &src_rel)?;

            let src_full = project_root.join(&src_rel);
            let (bytes, _) = read_delegated_work_file_verified(
                project_root,
                root_path_opt,
                &src_full,
                &src_rel,
                WORK_COPY_MAX_FILE_BYTES,
            )?;
            let sha = sha256_bytes(&bytes);
            total_copy_bytes = bytes.len() as u64;
            let dst_subpath = split_pro_work_path(&dst_rel)
                .map(|(_, s)| s.to_owned())
                .ok_or_else(|| BridgeError::new(ErrorCode::BridgePolicyDenied, "Invalid work destination.", OriginLayer::Policy))?;
            discovered.insert(dst_subpath, (bytes, sha));
        }
        WorkCopyMode::FromProject {
            paths,
            exclude_generated,
        } => {
            let mut visible_walked: usize = 0;
            let mut raw_walked: usize = 0;
            for raw_path in paths {
                let parts = validate_remote_relative_path(raw_path)?;
                if is_hidden_from_remote(&parts) {
                    return Err(BridgeError::new(
                        ErrorCode::BridgePolicyDenied,
                        "Access to protected secret/credential path is denied.",
                        OriginLayer::FileService,
                    )
                    .with_next_action(
                        "Protected secret and credential paths cannot be accessed remotely even with a grant; choose a non-protected project path.",
                    ));
                }
                if parts.first().is_some_and(|p| p.eq_ignore_ascii_case("_pro")) {
                    return Err(BridgeError::new(
                        ErrorCode::InvalidArgument,
                        "Cannot copy from '_pro' in project mode; use within_workspace=true to copy inside the same workspace.",
                        OriginLayer::Validation,
                    ));
                }
                let canonical_rel = if parts.is_empty() {
                    ".".to_owned()
                } else {
                    parts.join("/")
                };
                // Verify every intermediate hop from project_root is a real non-reparse directory with exact casing.
                let full_target = if parts.is_empty() {
                    project_root.to_path_buf()
                } else {
                    #[cfg(windows)]
                    {
                        PatchParent::pin(project_root, &cur_rid, &canonical_rel, true, false, None)?;
                    }
                    #[cfg(not(windows))]
                    {
                        check_no_symlink_prefix(project_root, &canonical_rel)?;
                    }
                    project_root.join(&canonical_rel)
                };

                #[cfg(windows)]
                let is_dir = {
                    let meta_handle = match open_path_metadata_no_follow(&full_target) {
                        Ok(h) => h,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            return Err(BridgeError::new(
                                ErrorCode::FileNotFound,
                                format!("Source path not found: {canonical_rel}"),
                                OriginLayer::FileService,
                            ));
                        }
                        Err(e) => return Err(patch_io_error(e)),
                    };
                    let id = file_identity_from_handle(&meta_handle)?;
                    if id.is_reparse_point {
                        return Err(BridgeError::new(
                            ErrorCode::UnsupportedPathType,
                            format!("Reparse point / junction denied at '{canonical_rel}'."),
                            OriginLayer::FileService,
                        ));
                    }
                    let req_rel = if canonical_rel == "." {
                        Path::new("")
                    } else {
                        Path::new(&canonical_rel)
                    };
                    verify_opened_name(&root_path_buf, req_rel, &file_path_from_handle(&meta_handle)?)?;
                    id.is_directory
                };
                #[cfg(not(windows))]
                let is_dir = {
                    let meta = match fs::symlink_metadata(&full_target) {
                        Ok(m) => m,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            return Err(BridgeError::new(
                                ErrorCode::FileNotFound,
                                format!("Source path not found: {canonical_rel}"),
                                OriginLayer::FileService,
                            ));
                        }
                        Err(e) => return Err(patch_io_error(e)),
                    };
                    if meta.file_type().is_symlink() {
                        return Err(BridgeError::new(
                            ErrorCode::UnsupportedPathType,
                            format!("Symlink denied at '{canonical_rel}'."),
                            OriginLayer::FileService,
                        ));
                    }
                    meta.is_dir()
                };

                if !is_dir {
                    // Explicit single file: hardlinks, oversized files, and bad links are refused.
                    let (bytes, _) = read_delegated_work_file_verified(
                        project_root,
                        root_path_opt,
                        &full_target,
                        &canonical_rel,
                        WORK_COPY_MAX_FILE_BYTES,
                    )?;
                    if !discovered.contains_key(&canonical_rel) {
                        if discovered.len() + 1 > WORK_COPY_MAX_FILES {
                            return Err(BridgeError::new(
                                ErrorCode::ResourceBudgetExceeded,
                                format!("work_copy exceeds the per-call limit of {WORK_COPY_MAX_FILES} files."),
                                OriginLayer::FileService,
                            ));
                        }
                        let next_total = total_copy_bytes.saturating_add(bytes.len() as u64);
                        if next_total > WORK_COPY_MAX_TOTAL_BYTES {
                            return Err(BridgeError::new(
                                ErrorCode::ResourceBudgetExceeded,
                                format!(
                                    "work_copy exceeds the per-call limit of {} MiB.",
                                    WORK_COPY_MAX_TOTAL_BYTES / (1024 * 1024)
                                ),
                                OriginLayer::FileService,
                            ));
                        }
                        total_copy_bytes = next_total;
                        let sha = sha256_bytes(&bytes);
                        discovered.insert(canonical_rel, (bytes, sha));
                    }
                } else {
                    // Directory subtree walk: silently skip hidden/secret, _pro, short names, stage files, and links.
                    let mut dir_stack: Vec<(PathBuf, Vec<String>)> = vec![(full_target, parts)];
                    while let Some((dir_path, dir_parts)) = dir_stack.pop() {
                        #[cfg(windows)]
                        let _dir_guard = {
                            let Ok(guard) = open_patch_directory(&dir_path) else {
                                continue;
                            };
                            let Ok(id) = file_identity_from_handle(&guard) else {
                                continue;
                            };
                            let rel_check = if dir_parts.is_empty() {
                                PathBuf::new()
                            } else {
                                PathBuf::from(dir_parts.join("/"))
                            };
                            if !id.is_directory
                                || id.is_reparse_point
                                || file_path_from_handle(&guard)
                                    .and_then(|obs| verify_opened_name(&root_path_buf, &rel_check, &obs))
                                    .is_err()
                            {
                                continue;
                            }
                            guard
                        };
                        let Ok(reader) = fs::read_dir(&dir_path) else {
                            continue;
                        };
                        let mut children: Vec<(String, PathBuf)> = Vec::new();
                        for item in reader {
                            raw_walked += 1;
                            if raw_walked > WORK_COPY_RAW_WALK_SAFETY_CAP {
                                return Err(BridgeError::new(
                                    ErrorCode::ResourceBudgetExceeded,
                                    "work_copy source tree exceeded maximum directory scan safety cap.",
                                    OriginLayer::FileService,
                                ));
                            }
                            let Ok(item) = item else { continue };
                            let Some(name_str) = item.file_name().to_str().map(str::to_owned) else {
                                continue;
                            };
                            // Unconditionally and silently skip staging, hidden/secret, short-name, and `_pro` entries
                            // BEFORE counting, hashing, or naming them anywhere.
                            if is_patch_stage_name(&name_str) {
                                continue;
                            }
                            let mut child_parts = dir_parts.clone();
                            child_parts.push(name_str.clone());
                            if child_parts.first().is_some_and(|p| p.eq_ignore_ascii_case("_pro"))
                                || is_hidden_from_remote(&child_parts)
                                || has_windows_short_name(&child_parts)
                            {
                                continue;
                            }
                            children.push((name_str, item.path()));
                        }
                        children.sort_by(|a, b| a.0.cmp(&b.0));

                        // Push subdirs in reverse so DFS pops them in sorted order.
                        let mut subdirs_to_push: Vec<(PathBuf, Vec<String>)> = Vec::new();
                        for (name_str, child_path) in children {
                            let mut child_parts = dir_parts.clone();
                            child_parts.push(name_str.clone());
                            let child_rel = child_parts.join("/");
                            if validate_remote_relative_path(&child_rel).is_err() {
                                continue;
                            }
                            let Ok(meta) = fs::symlink_metadata(&child_path) else {
                                continue;
                            };
                            if is_quota_link(&meta) {
                                // Never follow symlinks or NTFS junctions; silently skip.
                                continue;
                            }
                            visible_walked += 1;
                            if visible_walked > WORK_COPY_MAX_WALK_ENTRIES {
                                return Err(BridgeError::new(
                                    ErrorCode::ResourceBudgetExceeded,
                                    format!(
                                        "work_copy walk exceeded the per-call cap of {WORK_COPY_MAX_WALK_ENTRIES} entries."
                                    ),
                                    OriginLayer::FileService,
                                ));
                            }
                            if meta.is_dir() {
                                if *exclude_generated
                                    && GENERATED_DIRS.iter().any(|g| g.eq_ignore_ascii_case(&name_str))
                                {
                                    skipped_generated_dirs += 1;
                                    continue;
                                }
                                subdirs_to_push.push((child_path, child_parts));
                                continue;
                            }
                            if !meta.is_file() {
                                continue;
                            }
                            if discovered.contains_key(&child_rel) {
                                continue;
                            }
                            // Open source strictly without following links and verify handle identity & exact name.
                            #[cfg(windows)]
                            let open_res = (|| -> Result<Option<Vec<u8>>, BridgeError> {
                                let Ok(mut f) = open_read_no_follow(&child_path) else {
                                    return Ok(None);
                                };
                                let Ok(id) = file_identity_from_handle(&f) else {
                                    return Ok(None);
                                };
                                if id.is_reparse_point || id.is_directory {
                                    return Ok(None);
                                }
                                if file_path_from_handle(&f)
                                    .and_then(|obs| verify_opened_name(&root_path_buf, Path::new(&child_rel), &obs))
                                    .is_err()
                                {
                                    return Ok(None);
                                }
                                if id.n_links != 1 {
                                    skipped_non_secret.push(WorkCopySkipped {
                                        path: child_rel.clone(),
                                        reason: "hardlinked".into(),
                                    });
                                    return Ok(None);
                                }
                                if id.size_bytes > WORK_COPY_MAX_FILE_BYTES {
                                    skipped_non_secret.push(WorkCopySkipped {
                                        path: child_rel.clone(),
                                        reason: "too_large".into(),
                                    });
                                    return Ok(None);
                                }
                                let mut buf = Vec::with_capacity(id.size_bytes as usize);
                                if (&mut f)
                                    .take(WORK_COPY_MAX_FILE_BYTES + 1)
                                    .read_to_end(&mut buf)
                                    .is_err()
                                {
                                    return Ok(None);
                                }
                                if buf.len() as u64 > WORK_COPY_MAX_FILE_BYTES {
                                    skipped_non_secret.push(WorkCopySkipped {
                                        path: child_rel.clone(),
                                        reason: "too_large".into(),
                                    });
                                    return Ok(None);
                                }
                                Ok(Some(buf))
                            })()?;
                            #[cfg(not(windows))]
                            let open_res = (|| -> Result<Option<Vec<u8>>, BridgeError> {
                                #[cfg(unix)]
                                {
                                    use std::os::unix::fs::MetadataExt;
                                    if meta.nlink() != 1 {
                                        skipped_non_secret.push(WorkCopySkipped {
                                            path: child_rel.clone(),
                                            reason: "hardlinked".into(),
                                        });
                                        return Ok(None);
                                    }
                                }
                                if meta.len() > WORK_COPY_MAX_FILE_BYTES {
                                    skipped_non_secret.push(WorkCopySkipped {
                                        path: child_rel.clone(),
                                        reason: "too_large".into(),
                                    });
                                    return Ok(None);
                                }
                                let Ok(mut f) = File::open(&child_path) else {
                                    return Ok(None);
                                };
                                #[cfg(unix)]
                                {
                                    use std::os::unix::fs::MetadataExt;
                                    let Ok(om) = f.metadata() else { return Ok(None) };
                                    if om.dev() != meta.dev() || om.ino() != meta.ino() || om.nlink() != 1 {
                                        skipped_non_secret.push(WorkCopySkipped {
                                            path: child_rel.clone(),
                                            reason: "hardlinked".into(),
                                        });
                                        return Ok(None);
                                    }
                                }
                                let mut buf = Vec::with_capacity(meta.len() as usize);
                                if (&mut f)
                                    .take(WORK_COPY_MAX_FILE_BYTES + 1)
                                    .read_to_end(&mut buf)
                                    .is_err()
                                {
                                    return Ok(None);
                                }
                                if buf.len() as u64 > WORK_COPY_MAX_FILE_BYTES {
                                    skipped_non_secret.push(WorkCopySkipped {
                                        path: child_rel.clone(),
                                        reason: "too_large".into(),
                                    });
                                    return Ok(None);
                                }
                                Ok(Some(buf))
                            })()?;

                            let Some(bytes) = open_res else {
                                continue;
                            };
                            if discovered.len() + 1 > WORK_COPY_MAX_FILES {
                                return Err(BridgeError::new(
                                    ErrorCode::ResourceBudgetExceeded,
                                    format!("work_copy exceeds the per-call limit of {WORK_COPY_MAX_FILES} files."),
                                    OriginLayer::FileService,
                                ));
                            }
                            let next_total = total_copy_bytes.saturating_add(bytes.len() as u64);
                            if next_total > WORK_COPY_MAX_TOTAL_BYTES {
                                return Err(BridgeError::new(
                                    ErrorCode::ResourceBudgetExceeded,
                                    format!(
                                        "work_copy exceeds the per-call limit of {} MiB.",
                                        WORK_COPY_MAX_TOTAL_BYTES / (1024 * 1024)
                                    ),
                                    OriginLayer::FileService,
                                ));
                            }
                            total_copy_bytes = next_total;
                            let sha = sha256_bytes(&bytes);
                            discovered.insert(child_rel, (bytes, sha));
                        }
                        for subdir in subdirs_to_push.into_iter().rev() {
                            dir_stack.push(subdir);
                        }
                    }
                }
            }
        }
    }

    // Phase 2: Authorize every target path via PolicyEngine::authorize_work_mutation, validate
    // destinations, and check `_pro/` quota BEFORE writing a single byte.
    let mut items = Vec::with_capacity(discovered.len());
    let mut quota_deltas = BTreeMap::<String, (usize, i128)>::new();
    let mut missing_dirs = BTreeSet::new();

    for (subpath, (bytes, sha)) in discovered {
        let dst_rel = if within_workspace {
            // Already authorized via authorize_target(to) above; construct exact verified path.
            format!("{PRO_WORK_PREFIX}{}/{subpath}", req.workspace)
        } else {
            authorize_target(&subpath)?
        };
        if !is_pro_work_file_path(&dst_rel) {
            return Err(BridgeError::new(
                ErrorCode::BridgePolicyDenied,
                format!("Destination '{dst_rel}' is outside exact-case '_pro/work/<workspace>/**'."),
                OriginLayer::FileService,
            ));
        }
        let folder = crate::policy::delegated_write_quota_scope(&dst_rel, writable_scope)
            .ok_or_else(|| BridgeError::new(
                ErrorCode::BridgePolicyDenied,
                "Work copy target has no authorized folder.",
                OriginLayer::FileService,
            ))?
            .to_owned();
        #[cfg(windows)]
        PatchParent::pin(project_root, &cur_rid, &dst_rel, true, false, None)?;
        #[cfg(not(windows))]
        check_no_symlink_prefix(project_root, &dst_rel)?;

        let dst_full = project_root.join(&dst_rel);
        for parent in dst_full.ancestors().skip(1) {
            if parent == project_root {
                break;
            }
            match fs::symlink_metadata(parent) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing_dirs.insert(parent.to_owned());
                }
                Err(e) => return Err(patch_io_error(e)),
            }
        }

        let dst_exists = match fs::symlink_metadata(&dst_full) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(patch_io_error(e)),
        };
        let (old_bytes, old_hash, old_ntfs_id) = if dst_exists {
            if !req.overwrite_existing {
                return Err(BridgeError::new(
                    ErrorCode::VersionConflict,
                    format!(
                        "Destination '{dst_rel}' already exists in workspace '{}'; set overwrite_existing=true to replace it.",
                        req.workspace
                    ),
                    OriginLayer::FileService,
                ));
            }
            let (old, fid) = read_delegated_work_file_verified(
                project_root,
                root_path_opt,
                &dst_full,
                &dst_rel,
                DELEGATED_WRITE_MAX_SCOPE_BYTES,
            )?;
            let oh = sha256_bytes(&old);
            (Some(old), Some(oh), fid)
        } else {
            (None, None, None)
        };

        let delta = quota_deltas.entry(folder).or_insert((0, 0));
        if let Some(ref old) = old_bytes {
            delta.1 += (bytes.len() as i128) - (old.len() as i128);
        } else {
            delta.0 += 1;
            delta.1 += bytes.len() as i128;
        }
        items.push(CopyItem {
            subpath,
            dst_rel,
            bytes,
            sha256: sha,
            old_bytes,
            old_hash,
            old_ntfs_id,
        });
    }

    let quota_folders: BTreeMap<&str, (usize, u64)> = quota_deltas
        .iter()
        .map(|(f, (files, net_bytes))| (f.as_str(), (*files, (*net_bytes).max(0) as u64)))
        .collect();
    check_delegated_write_quota(project_root, quota_folders, &missing_dirs)?;

    // Phase 3: Stage all copies, re-authorize before each commit, verify postimage, and rollback on failure.
    let copy_id = uuid::Uuid::new_v4().simple().to_string();
    let mut staged = Vec::with_capacity(items.len());
    let mut created_dirs = Vec::new();
    let commit_res: Result<(), BridgeError> = (|| {
        for (idx, item) in items.iter().enumerate() {
            let temp_name = format!(".eb_stage_wc_{copy_id}_{idx}.tmp");
            let stage = StagedCopy::create(project_root, &cur_rid, &item.dst_rel, &temp_name, &mut created_dirs)?;
            staged.push(stage);
            staged.last_mut().unwrap().write_all(&item.dst_rel, &item.bytes)?;
        }
        for (idx, stage) in staged.iter_mut().enumerate() {
            let item = &items[idx];
            #[cfg(windows)]
            stage.parent.verify_location(&item.dst_rel)?;
            authorize_commit(&item.dst_rel)?;
            if let Some(ref old) = item.old_bytes {
                let old_hash = item.old_hash.as_deref().unwrap();
                #[cfg(windows)]
                {
                    let preimage_guard = verify_work_preimage_handle(
                        &stage.parent.root_path,
                        &stage.destination,
                        &item.dst_rel,
                        item.old_ntfs_id.as_deref(),
                        old_hash,
                        old.len(),
                    )?;
                    stage.parent.verify_location(&item.dst_rel)?;
                    commit_patch_stage(
                        stage.file.as_ref().unwrap(),
                        stage.parent.directories.last().unwrap(),
                        stage.destination.file_name().unwrap(),
                        true,
                    )?;
                    drop(preimage_guard);
                }
                #[cfg(not(windows))]
                {
                    let _ = old;
                    let (current, _) = read_delegated_work_file_verified(
                        project_root,
                        None,
                        &stage.destination,
                        &item.dst_rel,
                        DELEGATED_WRITE_MAX_SCOPE_BYTES,
                    )?;
                    if sha256_bytes(&current) != old_hash {
                        return Err(patch_commit_conflict(&item.dst_rel));
                    }
                    fs::rename(&stage.temp, &stage.destination).map_err(patch_io_error)?;
                }
            } else {
                #[cfg(windows)]
                {
                    stage.parent.verify_location(&item.dst_rel)?;
                    commit_patch_stage(
                        stage.file.as_ref().unwrap(),
                        stage.parent.directories.last().unwrap(),
                        stage.destination.file_name().unwrap(),
                        false,
                    )?;
                }
                #[cfg(not(windows))]
                fs::hard_link(&stage.temp, &stage.destination).map_err(|error| {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        BridgeError::new(
                            ErrorCode::VersionConflict,
                            format!("Destination '{}' appeared before commit.", item.dst_rel),
                            OriginLayer::FileService,
                        )
                    } else {
                        patch_io_error(error)
                    }
                })?;
            }
            stage.committed = true;
            stage.verify_postimage(&item.dst_rel, item.bytes.len(), &item.sha256)?;
        }
        for stage in &mut staged {
            stage.close();
        }
        Ok(())
    })();

    if let Err(error) = commit_res {
        for (idx, stage) in staged.iter_mut().enumerate().rev() {
            if stage.committed {
                if let Some(ref old) = items[idx].old_bytes {
                    stage.file.take();
                    #[cfg(windows)]
                    {
                        let rb_path = stage.parent.path.join(format!(".eb_stage_wc_{copy_id}_{idx}_rb.tmp"));
                        let res = (|| -> Result<(), BridgeError> {
                            stage.parent.verify_location(&items[idx].dst_rel)?;
                            let mut f = create_patch_stage(&rb_path).map_err(patch_io_error)?;
                            f.write_all(old).map_err(patch_io_error)?;
                            f.sync_all().map_err(patch_io_error)?;
                            commit_patch_stage(
                                &f,
                                stage.parent.directories.last().unwrap(),
                                stage.destination.file_name().unwrap(),
                                true,
                            )?;
                            Ok(())
                        })();
                        if res.is_err() {
                            let _ = fs::remove_file(&rb_path);
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        let rb_path = stage.destination.with_file_name(format!(".eb_stage_wc_{copy_id}_{idx}_rb.tmp"));
                        if write_synced_new(&rb_path, old).is_ok() {
                            let _ = fs::rename(&rb_path, &stage.destination);
                        }
                        let _ = fs::remove_file(&rb_path);
                    }
                } else {
                    let _ = stage.undo_create();
                }
            }
            stage.close();
        }
        drop(staged);
        for relative in created_dirs.iter().rev() {
            let _ = fs::remove_dir(project_root.join(relative));
        }
        return Err(error);
    }

    // Phase 4: Atomically persist bridge-side work manifest under `<state_dir>/work-manifests/<project_id>/<workspace>.json`.
    let now = Utc::now().to_rfc3339();
    let mut manifest = match load_work_manifest(state_dir, project_id, &req.workspace)? {
        Some(existing) => {
            if existing.project_id != project_id || existing.root_identity != cur_rid {
                return Err(BridgeError::new(
                    ErrorCode::StalePrecondition,
                    "Existing work manifest does not match this project root identity.",
                    OriginLayer::FileService,
                ));
            }
            existing
        }
        None => WorkManifest {
            version: WORK_MANIFEST_VERSION,
            project_id: project_id.to_owned(),
            root_identity: cur_rid.clone(),
            workspace: req.workspace.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
            entries: BTreeMap::new(),
        },
    };
    manifest.updated_at = now.clone();

    let mut files_copied = Vec::with_capacity(items.len());
    let mut hashes = BTreeMap::new();
    for item in &items {
        if !within_workspace {
            manifest.entries.insert(
                item.subpath.clone(),
                WorkManifestEntry {
                    baseline_sha256: item.sha256.clone(),
                    size_bytes: item.bytes.len() as u64,
                    copied_at: now.clone(),
                    deleted_in_work: false,
                },
            );
        } else if let Some(entry) = manifest.entries.get_mut(&item.subpath) {
            // Do NOT add a new project baseline entry on intra-workspace copy; only clear deleted_in_work if overwriting an existing baseline path.
            entry.deleted_in_work = false;
        }
        files_copied.push(item.dst_rel.clone());
        hashes.insert(item.dst_rel.clone(), item.sha256.clone());
    }
    if !items.is_empty() || load_work_manifest(state_dir, project_id, &req.workspace)?.is_some() {
        save_work_manifest(state_dir, &manifest)?;
    }

    let quota = work_quota_telemetry(project_root, state_dir, project_id)?;
    Ok(WorkCopyResult {
        workspace: req.workspace.clone(),
        work_root: format!("{PRO_WORK_PREFIX}{}/", req.workspace),
        within_workspace,
        copied_count: files_copied.len(),
        files_copied,
        total_bytes: total_copy_bytes,
        hashes,
        skipped_generated_dirs,
        skipped_non_secret,
        quota,
    })
}

/// Apply atomic multi-file, multi-hunk search-and-replace strictly inside `_pro/work/<workspace>/**`.
///
/// - `authorize_target`: invoked once per workspace-relative file path; must call
///   `PolicyEngine::authorize_work_mutation` and return its `normalized_write_path`.
/// - `authorize_commit`: invoked before each file commit to re-verify grant validity.
#[allow(clippy::too_many_arguments)]
pub fn work_edit(
    project_root: &Path,
    root_identity: &str,
    state_dir: &Path,
    project_id: &str,
    req: &WorkEditRequest,
    writable_scope: &[String],
    mut authorize_target: impl FnMut(&str) -> Result<String, BridgeError>,
    authorize_commit: impl Fn(&str) -> Result<(), BridgeError>,
) -> Result<(WorkEditResult, crate::files::PatchJournal), BridgeError> {
    validate_safe_id(project_id)?;
    validate_work_name(&req.workspace)?;
    if req.edits.is_empty() {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "work_edit 'edits' must contain between 1 and 32 file edits.",
            OriginLayer::Validation,
        ));
    }
    if req.edits.len() > WORK_EDIT_MAX_FILES {
        return Err(BridgeError::new(
            ErrorCode::ResourceBudgetExceeded,
            format!("work_edit allows at most {WORK_EDIT_MAX_FILES} files per call."),
            OriginLayer::Validation,
        ));
    }
    let mut total_hunks: usize = 0;
    for file_edit in &req.edits {
        if file_edit.replacements.is_empty() {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                format!("work_edit file '{}' must have at least one replacement.", file_edit.path),
                OriginLayer::Validation,
            ));
        }
        total_hunks = total_hunks.saturating_add(file_edit.replacements.len());
        if total_hunks > WORK_EDIT_MAX_HUNKS {
            return Err(BridgeError::new(
                ErrorCode::ResourceBudgetExceeded,
                format!("work_edit allows at most {WORK_EDIT_MAX_HUNKS} total replacement hunks per call."),
                OriginLayer::Validation,
            ));
        }
        for rep in &file_edit.replacements {
            if rep.old_text.is_empty() {
                return Err(BridgeError::new(
                    ErrorCode::InvalidArgument,
                    format!("work_edit 'old_text' must be non-empty for '{}'.", file_edit.path),
                    OriginLayer::Validation,
                ));
            }
        }
    }

    let remote_reader = ScopedFiles::new_remote_read(project_root, Some(root_identity.to_owned()))?;
    let cur_rid = remote_reader.current_root_identity()?;
    #[cfg(windows)]
    let (_root_pin, root_path_buf) = open_verified_root(project_root, &cur_rid)?;
    #[cfg(windows)]
    let root_path_opt = Some(root_path_buf.as_path());
    #[cfg(not(windows))]
    let root_path_opt: Option<&Path> = None;

    let mut seen = HashSet::with_capacity(req.edits.len());
    let mut patch_edits = Vec::with_capacity(req.edits.len());
    let mut total_result_bytes: usize = 0;
    let mut replacements_applied: usize = 0;

    for file_edit in &req.edits {
        let normalized_work_path = authorize_target(&file_edit.path)?;
        if !is_pro_work_file_path(&normalized_work_path) {
            return Err(BridgeError::new(
                ErrorCode::BridgePolicyDenied,
                format!("Target '{normalized_work_path}' is outside exact-case '_pro/work/<workspace>/**'."),
                OriginLayer::Policy,
            ));
        }
        if !seen.insert(normalized_work_path.to_ascii_lowercase()) {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                format!("Duplicate target path in work_edit: '{normalized_work_path}'."),
                OriginLayer::Validation,
            ));
        }
        #[cfg(windows)]
        PatchParent::pin(project_root, &cur_rid, &normalized_work_path, true, false, None)?;
        #[cfg(not(windows))]
        check_no_symlink_prefix(project_root, &normalized_work_path)?;

        let full = project_root.join(&normalized_work_path);
        let (raw, _) = read_delegated_work_file_verified(
            project_root,
            root_path_opt,
            &full,
            &normalized_work_path,
            WORK_EDIT_MAX_FILE_BYTES as u64,
        )?;
        if raw.iter().take(8192).any(|&b| b == 0) {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("Binary file detected (NUL byte present) at '{normalized_work_path}'; work_edit only edits UTF-8 text files."),
                OriginLayer::FileService,
            ));
        }
        let actual_hash = sha256_bytes(&raw);
        if let Some(ref exp) = file_edit.expected_hash {
            if !exp.eq_ignore_ascii_case(&actual_hash) {
                return Err(BridgeError::new(
                    ErrorCode::VersionConflict,
                    format!(
                        "Preimage SHA-256 mismatch for '{normalized_work_path}': expected {exp}, actual {actual_hash}."
                    ),
                    OriginLayer::FileService,
                ));
            }
        }
        let mut text = String::from_utf8(raw).map_err(|_| {
            BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("File '{normalized_work_path}' is not valid UTF-8."),
                OriginLayer::FileService,
            )
        })?;

        for rep in &file_edit.replacements {
            let matches = text.matches(&rep.old_text).count();
            if matches == 0 {
                return Err(BridgeError::new(
                    ErrorCode::VersionConflict,
                    format!("old_text not found in '{normalized_work_path}'."),
                    OriginLayer::FileService,
                ));
            }
            if !rep.replace_all && matches > 1 {
                return Err(BridgeError::new(
                    ErrorCode::VersionConflict,
                    format!(
                        "old_text matched {matches} times in '{normalized_work_path}'; include more surrounding context or set replace_all=true."
                    ),
                    OriginLayer::FileService,
                ));
            }
            if rep.replace_all {
                text = text.replace(&rep.old_text, &rep.new_text);
                replacements_applied += matches;
            } else {
                text = text.replacen(&rep.old_text, &rep.new_text, 1);
                replacements_applied += 1;
            }
        }

        if text.len() > WORK_EDIT_MAX_FILE_BYTES {
            return Err(BridgeError::new(
                ErrorCode::ResourceBudgetExceeded,
                format!("Resulting file '{normalized_work_path}' exceeds the 1 MiB work_edit limit."),
                OriginLayer::FileService,
            ));
        }
        total_result_bytes = total_result_bytes.saturating_add(text.len());
        if total_result_bytes > WORK_EDIT_MAX_CALL_BYTES {
            return Err(BridgeError::new(
                ErrorCode::ResourceBudgetExceeded,
                "Total resulting bytes in work_edit exceed the 4 MiB per-call limit.",
                OriginLayer::FileService,
            ));
        }
        patch_edits.push(PatchEditV04 {
            path: normalized_work_path,
            content: text,
            expected_hash: Some(actual_hash),
            expected_postimage_hash: None,
        });
    }

    let plan = PatchPlanV04 {
        patch_plan_version: BRIDGE_CONTRACT_VERSION.into(),
        project_id: project_id.to_owned(),
        root_identity: Some(cur_rid),
        operation_id: req.operation_id.clone(),
        task_id: req.task_id.clone(),
        summary: Some(format!("MCP work_edit ({})", req.operation_id)),
        baseline_manifest_sha256: None,
        scope: patch_edits.iter().map(|e| e.path.clone()).collect(),
        edits: patch_edits,
        verification_recipe: None,
        verification_command: None,
    };

    let sf = ScopedFiles::new(project_root, Some(root_identity.to_owned()))?;
    let jdir = state_dir.join("patch-journals");
    let (apply_res, journal) = sf.apply_delegated_work_edits(&plan, &jdir, writable_scope, authorize_commit)?;
    let quota = work_quota_telemetry(project_root, state_dir, project_id)?;

    Ok((
        WorkEditResult {
            workspace: req.workspace.clone(),
            journal_id: apply_res.journal_id,
            operation_id: apply_res.operation_id,
            files_applied: apply_res.files_applied,
            replacements_applied,
            postimage_hashes: apply_res.postimage_hashes,
            unified_diff: apply_res.unified_diff,
            diff_sha256: apply_res.diff_sha256,
            quota,
        },
        journal,
    ))
}

/// Prune empty parent directories strictly inside `_pro/work/<workspace>/` (never touching
/// `_pro/work/<workspace>`, `_pro/work`, or `_pro`, and never following a reparse point).
fn prune_empty_work_subdirs(project_root: &Path, workspace: &str, removed_rel: &str) {
    let ws_root = project_root.join("_pro").join("work").join(workspace);
    let mut current = project_root.join(removed_rel).parent().map(Path::to_path_buf);
    while let Some(dir) = current {
        if dir == ws_root || !dir.starts_with(&ws_root) {
            break;
        }
        let Ok(meta) = fs::symlink_metadata(&dir) else {
            break;
        };
        if is_quota_link(&meta) || !meta.is_dir() {
            break;
        }
        if fs::remove_dir(&dir).is_err() {
            break;
        }
        current = dir.parent().map(Path::to_path_buf);
    }
}

/// Handle-pinned rename/move of a single regular file strictly inside `_pro/work/<workspace>/**`.
///
/// - `authorize_target`: invoked once for `from` and once for `to`; must call
///   `PolicyEngine::authorize_work_mutation` and return its `normalized_write_path`.
/// - `authorize_commit`: invoked right before the rename to re-verify grant validity.
#[allow(clippy::too_many_arguments)]
pub fn work_move(
    project_root: &Path,
    root_identity: &str,
    state_dir: &Path,
    project_id: &str,
    req: &WorkMoveRequest,
    writable_scope: &[String],
    mut authorize_target: impl FnMut(&str) -> Result<String, BridgeError>,
    authorize_commit: impl Fn(&str) -> Result<(), BridgeError>,
) -> Result<WorkMoveResult, BridgeError> {
    validate_safe_id(project_id)?;
    validate_work_name(&req.workspace)?;

    let from_rel = authorize_target(&req.from)?;
    let to_rel = authorize_target(&req.to)?;
    if !is_pro_work_file_path(&from_rel) || !is_pro_work_file_path(&to_rel) {
        return Err(BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            "work_move source and destination must stay strictly inside exact-case '_pro/work/<workspace>/**'.",
            OriginLayer::Policy,
        ));
    }
    if from_rel.eq_ignore_ascii_case(&to_rel) {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "work_move 'from' and 'to' must be different paths.",
            OriginLayer::Validation,
        ));
    }

    let sf = ScopedFiles::new(project_root, Some(root_identity.to_owned()))?;
    let cur_rid = sf.current_root_identity()?;
    let journal_dir = state_dir.join("patch-journals");
    let _writer = lock_patch_root(&journal_dir, &cur_rid)?;

    verify_existing_work_prefix(project_root, &cur_rid, &req.workspace)?;

    #[cfg(windows)]
    let src_parent = PatchParent::pin(project_root, &cur_rid, &from_rel, true, false, None)?;
    #[cfg(not(windows))]
    check_no_symlink_prefix(project_root, &from_rel)?;

    let src_full = project_root.join(&from_rel);
    #[cfg(windows)]
    let (src_file, from_hash) = {
        let meta_handle = match open_path_metadata_no_follow(&src_full) {
            Ok(h) => h,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BridgeError::new(
                    ErrorCode::FileNotFound,
                    format!("Source file not found: {from_rel}"),
                    OriginLayer::FileService,
                ));
            }
            Err(e) => return Err(patch_io_error(e)),
        };
        let pre_id = file_identity_from_handle(&meta_handle)?;
        if pre_id.is_reparse_point || pre_id.is_directory || pre_id.n_links != 1 {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("work_move source '{from_rel}' must be a regular single-link non-reparse file."),
                OriginLayer::FileService,
            ));
        }
        let mut file = open_move_source_no_follow(&src_full).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BridgeError::new(ErrorCode::FileNotFound, format!("Source file not found: {from_rel}"), OriginLayer::FileService)
            } else {
                patch_io_error(e)
            }
        })?;
        let id = file_identity_from_handle(&file)?;
        if id.is_reparse_point || id.is_directory || id.n_links != 1 {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("work_move source '{from_rel}' must be a regular single-link non-reparse file."),
                OriginLayer::FileService,
            ));
        }
        if id.canonical_id() != pre_id.canonical_id() {
            return Err(BridgeError::new(
                ErrorCode::StalePrecondition,
                "Source file identity changed while opening.",
                OriginLayer::FileService,
            ));
        }
        verify_opened_name(&src_parent.root_path, Path::new(&from_rel), &file_path_from_handle(&file)?)?;
        let mut hasher = sha2::Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = file.read(&mut buf).map_err(patch_io_error)?;
            if n == 0 {
                break;
            }
            use sha2::Digest;
            hasher.update(&buf[..n]);
        }
        use sha2::Digest;
        let hash = hex::encode(hasher.finalize());
        (file, hash)
    };
    #[cfg(not(windows))]
    let from_hash = {
        let (bytes, _) = read_delegated_work_file_verified(
            project_root,
            None,
            &src_full,
            &from_rel,
            DELEGATED_WRITE_MAX_SCOPE_BYTES,
        )?;
        sha256_bytes(&bytes)
    };

    if let Some(ref exp) = req.expected_from_hash {
        if !exp.eq_ignore_ascii_case(&from_hash) {
            return Err(BridgeError::new(
                ErrorCode::VersionConflict,
                format!("Preimage SHA-256 mismatch for source '{from_rel}': expected {exp}, actual {from_hash}."),
                OriginLayer::FileService,
            ));
        }
    }

    // Validate destination prefix & existing target BEFORE creating any missing directories.
    #[cfg(windows)]
    let dst_existing_parent = PatchParent::pin(project_root, &cur_rid, &to_rel, true, false, None)?;
    #[cfg(not(windows))]
    check_no_symlink_prefix(project_root, &to_rel)?;

    let dst_full = project_root.join(&to_rel);
    let dst_exists = match fs::symlink_metadata(&dst_full) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(patch_io_error(e)),
    };

    let mut overwritten = false;
    #[cfg(windows)]
    let mut dst_preimage_info: Option<(String, Option<String>, usize)> = None;
    #[cfg(not(windows))]
    let mut dst_preimage_hash: Option<String> = None;

    if dst_exists {
        if !req.overwrite {
            return Err(BridgeError::new(
                ErrorCode::VersionConflict,
                format!("Destination '{to_rel}' already exists; pass overwrite=true to replace it."),
                OriginLayer::FileService,
            ));
        }
        #[cfg(windows)]
        let root_path_opt = Some(dst_existing_parent.root_path.as_path());
        #[cfg(not(windows))]
        let root_path_opt: Option<&Path> = None;

        let (dst_bytes, dst_fid) = read_delegated_work_file_verified(
            project_root,
            root_path_opt,
            &dst_full,
            &to_rel,
            DELEGATED_WRITE_MAX_SCOPE_BYTES,
        )?;
        let actual_to_hash = sha256_bytes(&dst_bytes);
        if let Some(ref exp_to) = req.expected_to_hash {
            if !exp_to.eq_ignore_ascii_case(&actual_to_hash) {
                return Err(BridgeError::new(
                    ErrorCode::VersionConflict,
                    format!("Destination SHA-256 mismatch for '{to_rel}': expected {exp_to}, actual {actual_to_hash}."),
                    OriginLayer::FileService,
                ));
            }
        }
        overwritten = true;
        #[cfg(windows)]
        {
            dst_preimage_info = Some((actual_to_hash, dst_fid, dst_bytes.len()));
        }
        #[cfg(not(windows))]
        {
            let _ = dst_fid;
            dst_preimage_hash = Some(actual_to_hash);
        }
    } else if req.expected_to_hash.is_some() {
        return Err(BridgeError::new(
            ErrorCode::VersionConflict,
            format!("Expected existing destination '{to_rel}' is missing (stale preimage)."),
            OriginLayer::FileService,
        ));
    }

    let folder = crate::policy::delegated_write_quota_scope(&to_rel, writable_scope)
        .ok_or_else(|| BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            "work_move destination has no authorized folder.",
            OriginLayer::FileService,
        ))?;
    let mut missing_dirs = BTreeSet::new();
    for parent in dst_full.ancestors().skip(1) {
        if parent == project_root {
            break;
        }
        match fs::symlink_metadata(parent) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing_dirs.insert(parent.to_owned());
            }
            Err(e) => return Err(patch_io_error(e)),
        }
    }
    check_delegated_write_quota(project_root, BTreeMap::from([(folder, (0usize, 0u64))]), &missing_dirs)?;

    #[cfg(windows)]
    drop(dst_existing_parent);

    let mut created_dirs = Vec::new();
    let move_res: Result<(), BridgeError> = (|| {
        #[cfg(windows)]
        let dst_parent = PatchParent::pin(project_root, &cur_rid, &to_rel, true, true, Some(&mut created_dirs))?;
        #[cfg(not(windows))]
        {
            let parts = validate_remote_relative_path(&to_rel)?;
            let mut dir = PathBuf::new();
            for name in &parts[..parts.len() - 1] {
                dir.push(name);
                let full_dir = project_root.join(&dir);
                if fs::symlink_metadata(&full_dir).is_err() {
                    match fs::create_dir(&full_dir) {
                        Ok(()) => created_dirs.push(dir.clone()),
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(patch_io_error(e)),
                    }
                }
            }
        }

        authorize_commit(&from_rel)?;
        authorize_commit(&to_rel)?;

        #[cfg(windows)]
        {
            src_parent.verify_location(&from_rel)?;
            dst_parent.verify_location(&to_rel)?;
            let dst_name = Path::new(&to_rel)
                .file_name()
                .ok_or_else(|| patch_commit_conflict(&to_rel))?;
            let dst_pinned_path = dst_parent.path.join(dst_name);
            let preimage_guard = if let Some((ref exp_hash, ref exp_id, exp_len)) = dst_preimage_info {
                Some(verify_work_preimage_handle(
                    &dst_parent.root_path,
                    &dst_pinned_path,
                    &to_rel,
                    exp_id.as_deref(),
                    exp_hash,
                    exp_len,
                )?)
            } else {
                // If overwrite=true and target appeared concurrently right before rename, verify it is not a link!
                if req.overwrite {
                    if let Ok(h) = open_path_metadata_no_follow(&dst_pinned_path) {
                        let id = file_identity_from_handle(&h)?;
                        if id.is_reparse_point || id.is_directory || id.n_links != 1 {
                            return Err(BridgeError::new(
                                ErrorCode::UnsupportedPathType,
                                format!("Destination '{to_rel}' became a link or directory before commit."),
                                OriginLayer::FileService,
                            ));
                        }
                    }
                }
                None
            };
            dst_parent.verify_location(&to_rel)?;
            commit_patch_stage(&src_file, dst_parent.directories.last().unwrap(), dst_name, req.overwrite)?;
            drop(preimage_guard);
            drop(src_file);
        }
        #[cfg(not(windows))]
        {
            if let Some(ref exp_hash) = dst_preimage_hash {
                let (cur, _) = read_delegated_work_file_verified(
                    project_root,
                    None,
                    &dst_full,
                    &to_rel,
                    DELEGATED_WRITE_MAX_SCOPE_BYTES,
                )?;
                if sha256_bytes(&cur) != *exp_hash {
                    return Err(patch_commit_conflict(&to_rel));
                }
                fs::rename(&src_full, &dst_full).map_err(patch_io_error)?;
            } else if req.overwrite {
                if let Ok(meta) = fs::symlink_metadata(&dst_full) {
                    if meta.file_type().is_symlink() || !meta.is_file() {
                        return Err(BridgeError::new(
                            ErrorCode::UnsupportedPathType,
                            format!("Destination '{to_rel}' is a link or non-file."),
                            OriginLayer::FileService,
                        ));
                    }
                }
                fs::rename(&src_full, &dst_full).map_err(patch_io_error)?;
            } else {
                fs::hard_link(&src_full, &dst_full).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        BridgeError::new(
                            ErrorCode::VersionConflict,
                            format!("Destination '{to_rel}' already exists; pass overwrite=true to replace it."),
                            OriginLayer::FileService,
                        )
                    } else {
                        patch_io_error(e)
                    }
                })?;
                fs::remove_file(&src_full).map_err(patch_io_error)?;
            }
        }
        Ok(())
    })();

    if let Err(error) = move_res {
        #[cfg(windows)]
        drop(src_parent);
        for rel in created_dirs.iter().rev() {
            let _ = fs::remove_dir(project_root.join(rel));
        }
        return Err(error);
    }

    #[cfg(windows)]
    drop(src_parent);
    prune_empty_work_subdirs(project_root, &req.workspace, &from_rel);

    // Update bridge manifest: mark `from` deleted_in_work if it was a baseline file; clear on `to` if present.
    if let Some(mut manifest) = load_work_manifest(state_dir, project_id, &req.workspace)? {
        let mut changed = false;
        if let Some((_, from_sub)) = split_pro_work_path(&from_rel) {
            if let Some(entry) = manifest.entries.get_mut(from_sub) {
                entry.deleted_in_work = true;
                changed = true;
            }
        }
        if let Some((_, to_sub)) = split_pro_work_path(&to_rel) {
            if let Some(entry) = manifest.entries.get_mut(to_sub) {
                entry.deleted_in_work = false;
                changed = true;
            }
        }
        if changed {
            manifest.updated_at = Utc::now().to_rfc3339();
            save_work_manifest(state_dir, &manifest)?;
        }
    }

    let quota = work_quota_telemetry(project_root, state_dir, project_id)?;
    Ok(WorkMoveResult {
        workspace: req.workspace.clone(),
        operation_id: req.operation_id.clone(),
        from: from_rel,
        to: to_rel,
        sha256: from_hash,
        overwritten,
        quota,
    })
}

/// Delete 1..=64 files strictly inside `_pro/work/<workspace>/**`, OR remove an entire workspace
/// (`delete_workspace: true`) and its bridge manifest after verifying nothing inside it is a link.
///
/// - `authorize_target`: invoked once per target file path in file mode (or once with `None` in
///   whole-workspace mode); must call `PolicyEngine::authorize_work_mutation` and return its
///   `normalized_write_path`.
/// - `authorize_commit`: invoked right before each file unlink (or workspace deletion) to re-verify grant validity.
#[allow(clippy::too_many_arguments)]
pub fn work_delete(
    project_root: &Path,
    root_identity: &str,
    state_dir: &Path,
    project_id: &str,
    req: &WorkDeleteRequest,
    mut authorize_target: impl FnMut(Option<&str>) -> Result<String, BridgeError>,
    authorize_commit: impl Fn(&str) -> Result<(), BridgeError>,
) -> Result<WorkDeleteResult, BridgeError> {
    validate_safe_id(project_id)?;
    validate_work_name(&req.workspace)?;

    let sf = ScopedFiles::new(project_root, Some(root_identity.to_owned()))?;
    let cur_rid = sf.current_root_identity()?;
    let journal_dir = state_dir.join("patch-journals");
    let _writer = lock_patch_root(&journal_dir, &cur_rid)?;

    match &req.target {
        WorkDeleteTarget::Files {
            paths,
            expected_hashes,
        } => {
            if paths.is_empty() || paths.len() > WORK_DELETE_MAX_PATHS {
                return Err(BridgeError::new(
                    ErrorCode::InvalidArgument,
                    format!("work_delete 'paths' must contain between 1 and {WORK_DELETE_MAX_PATHS} file paths."),
                    OriginLayer::Validation,
                ));
            }
            verify_existing_work_prefix(project_root, &cur_rid, &req.workspace)?;

            // Authorize every path and normalize expected_hashes keys.
            let mut normalized_expected: BTreeMap<String, String> = BTreeMap::new();
            for (raw_key, hash) in expected_hashes {
                let parts = validate_remote_relative_path(raw_key)?;
                if parts.is_empty() {
                    return Err(BridgeError::new(
                        ErrorCode::InvalidArgument,
                        "expected_hashes keys cannot be empty or '.'.",
                        OriginLayer::Validation,
                    ));
                }
                let full_key = format!("{PRO_WORK_PREFIX}{}/{}", req.workspace, parts.join("/"));
                normalized_expected.insert(full_key, hash.clone());
            }

            let mut target_rels = Vec::with_capacity(paths.len());
            let mut seen = HashSet::with_capacity(paths.len());
            for raw in paths {
                let norm = authorize_target(Some(raw))?;
                if !is_pro_work_file_path(&norm) {
                    return Err(BridgeError::new(
                        ErrorCode::BridgePolicyDenied,
                        format!("Delete target '{norm}' is outside exact-case '_pro/work/<workspace>/**'."),
                        OriginLayer::Policy,
                    ));
                }
                if !seen.insert(norm.to_ascii_lowercase()) {
                    return Err(BridgeError::new(
                        ErrorCode::InvalidArgument,
                        format!("Duplicate target path in work_delete: '{norm}'."),
                        OriginLayer::Validation,
                    ));
                }
                target_rels.push(norm);
            }
            for key in normalized_expected.keys() {
                if !seen.contains(&key.to_ascii_lowercase()) {
                    return Err(BridgeError::new(
                        ErrorCode::InvalidArgument,
                        format!("expected_hashes contains key '{key}' not present in 'paths'."),
                        OriginLayer::Validation,
                    ));
                }
            }

            // Phase 1: Pin parent and open & verify EVERY target handle before deleting any file.
            struct PreparedDelete {
                rel: String,
                size: u64,
                #[cfg(windows)]
                parent: PatchParent,
                #[cfg(windows)]
                file: Option<File>,
                #[cfg(windows)]
                orig_name: std::ffi::OsString,
                #[cfg(windows)]
                staged_name: Option<std::ffi::OsString>,
                #[cfg(not(windows))]
                full: PathBuf,
            }

            let mut prepared = Vec::with_capacity(target_rels.len());
            for rel in &target_rels {
                #[cfg(windows)]
                let parent = PatchParent::pin(project_root, &cur_rid, rel, true, false, None)?;
                #[cfg(not(windows))]
                check_no_symlink_prefix(project_root, rel)?;

                let full = project_root.join(rel);
                #[cfg(windows)]
                let (file, size, orig_name) = {
                    let meta_handle = match open_path_metadata_no_follow(&full) {
                        Ok(h) => h,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            return Err(BridgeError::new(
                                ErrorCode::FileNotFound,
                                format!("File not found: {rel}"),
                                OriginLayer::FileService,
                            ));
                        }
                        Err(e) => return Err(patch_io_error(e)),
                    };
                    let pre_id = file_identity_from_handle(&meta_handle)?;
                    if pre_id.is_reparse_point || pre_id.is_directory || pre_id.n_links != 1 {
                        return Err(BridgeError::new(
                            ErrorCode::UnsupportedPathType,
                            format!("work_delete target '{rel}' must be a regular single-link non-reparse file."),
                            OriginLayer::FileService,
                        ));
                    }
                    let mut file = open_move_source_no_follow(&full).map_err(|e| {
                        if e.kind() == std::io::ErrorKind::NotFound {
                            BridgeError::new(ErrorCode::FileNotFound, format!("File not found: {rel}"), OriginLayer::FileService)
                        } else {
                            patch_io_error(e)
                        }
                    })?;
                    let id = file_identity_from_handle(&file)?;
                    if id.is_reparse_point || id.is_directory || id.n_links != 1 {
                        return Err(BridgeError::new(
                            ErrorCode::UnsupportedPathType,
                            format!("work_delete target '{rel}' must be a regular single-link non-reparse file."),
                            OriginLayer::FileService,
                        ));
                    }
                    if id.canonical_id() != pre_id.canonical_id() {
                        return Err(BridgeError::new(
                            ErrorCode::StalePrecondition,
                            "File identity changed while opening for deletion.",
                            OriginLayer::FileService,
                        ));
                    }
                    verify_opened_name(&parent.root_path, Path::new(rel), &file_path_from_handle(&file)?)?;
                    if let Some(expected_hash) = normalized_expected.get(rel) {
                        let mut hasher = sha2::Sha256::new();
                        let mut buf = [0u8; 65536];
                        loop {
                            let n = file.read(&mut buf).map_err(patch_io_error)?;
                            if n == 0 {
                                break;
                            }
                            use sha2::Digest;
                            hasher.update(&buf[..n]);
                        }
                        use sha2::Digest;
                        let actual = hex::encode(hasher.finalize());
                        if !expected_hash.eq_ignore_ascii_case(&actual) {
                            return Err(BridgeError::new(
                                ErrorCode::VersionConflict,
                                format!("Preimage SHA-256 mismatch for '{rel}': expected {expected_hash}, actual {actual}."),
                                OriginLayer::FileService,
                            ));
                        }
                    }
                    let orig_name = Path::new(rel)
                        .file_name()
                        .ok_or_else(|| patch_commit_conflict(rel))?
                        .to_os_string();
                    (file, id.size_bytes, orig_name)
                };
                #[cfg(not(windows))]
                let size = {
                    let (bytes, _) = read_delegated_work_file_verified(
                        project_root,
                        None,
                        &full,
                        rel,
                        DELEGATED_WRITE_MAX_SCOPE_BYTES,
                    )?;
                    if let Some(expected_hash) = normalized_expected.get(rel) {
                        let actual = sha256_bytes(&bytes);
                        if !expected_hash.eq_ignore_ascii_case(&actual) {
                            return Err(BridgeError::new(
                                ErrorCode::VersionConflict,
                                format!("Preimage SHA-256 mismatch for '{rel}': expected {expected_hash}, actual {actual}."),
                                OriginLayer::FileService,
                            ));
                        }
                    }
                    bytes.len() as u64
                };

                prepared.push(PreparedDelete {
                    rel: rel.clone(),
                    size,
                    #[cfg(windows)]
                    parent,
                    #[cfg(windows)]
                    file: Some(file),
                    #[cfg(windows)]
                    orig_name,
                    #[cfg(windows)]
                    staged_name: None,
                    #[cfg(not(windows))]
                    full,
                });
            }

            // Phase 2: Re-authorize each delete before unlinking; on Windows stage via handle-relative rename
            // so a mid-batch revocation rolls back earlier renames atomically!
            let del_id = uuid::Uuid::new_v4().simple().to_string();
            let mut freed_bytes: u64 = 0;
            let mut deleted_files = Vec::with_capacity(prepared.len());

            #[cfg(windows)]
            {
                let stage_res: Result<(), BridgeError> = (|| {
                    for (idx, item) in prepared.iter_mut().enumerate() {
                        item.parent.verify_location(&item.rel)?;
                        authorize_commit(&item.rel)?;
                        let tmp = std::ffi::OsString::from(format!(".eb_stage_del_{del_id}_{idx}.tmp"));
                        commit_patch_stage(
                            item.file.as_ref().unwrap(),
                            item.parent.directories.last().unwrap(),
                            &tmp,
                            false,
                        )?;
                        item.staged_name = Some(tmp);
                    }
                    Ok(())
                })();
                if let Err(error) = stage_res {
                    for item in prepared.iter_mut().rev() {
                        if item.staged_name.is_some() {
                            let _ = commit_patch_stage(
                                item.file.as_ref().unwrap(),
                                item.parent.directories.last().unwrap(),
                                &item.orig_name,
                                false,
                            );
                        }
                        item.file.take();
                    }
                    return Err(error);
                }
                for item in &mut prepared {
                    item.file.take();
                    let staged_path = item.parent.path.join(item.staged_name.as_ref().unwrap());
                    fs::remove_file(&staged_path).map_err(patch_io_error)?;
                    freed_bytes = freed_bytes.saturating_add(item.size);
                    deleted_files.push(item.rel.clone());
                }
                drop(prepared);
            }
            #[cfg(not(windows))]
            {
                let _ = del_id;
                for item in &prepared {
                    authorize_commit(&item.rel)?;
                }
                for item in &prepared {
                    fs::remove_file(&item.full).map_err(patch_io_error)?;
                    freed_bytes = freed_bytes.saturating_add(item.size);
                    deleted_files.push(item.rel.clone());
                }
            }

            for rel in &deleted_files {
                prune_empty_work_subdirs(project_root, &req.workspace, rel);
            }

            if let Some(mut manifest) = load_work_manifest(state_dir, project_id, &req.workspace)? {
                let mut changed = false;
                for rel in &deleted_files {
                    if let Some((_, sub)) = split_pro_work_path(rel) {
                        if let Some(entry) = manifest.entries.get_mut(sub) {
                            entry.deleted_in_work = true;
                            changed = true;
                        }
                    }
                }
                if changed {
                    manifest.updated_at = Utc::now().to_rfc3339();
                    save_work_manifest(state_dir, &manifest)?;
                }
            }

            let quota = work_quota_telemetry(project_root, state_dir, project_id)?;
            Ok(WorkDeleteResult {
                workspace: req.workspace.clone(),
                operation_id: req.operation_id.clone(),
                deleted_workspace: false,
                freed_files: deleted_files.len(),
                deleted_files,
                freed_bytes,
                quota,
            })
        }
        WorkDeleteTarget::WholeWorkspace => {
            let ws_rel = authorize_target(None)?;
            let expected_ws_rel = format!("{PRO_WORK_PREFIX}{}", req.workspace);
            if ws_rel != expected_ws_rel {
                return Err(BridgeError::new(
                    ErrorCode::BridgePolicyDenied,
                    format!("Workspace delete target '{ws_rel}' does not match '{expected_ws_rel}'."),
                    OriginLayer::Policy,
                ));
            }

            // Pin `_pro`, `_pro/work`, and `_pro/work/<workspace>` (verifying no reparse point and exact casing).
            #[cfg(windows)]
            let ws_pin = PatchParent::pin_dir_existing(project_root, &cur_rid, &ws_rel, true)?;
            #[cfg(not(windows))]
            let ws_pin: Option<PathBuf> = {
                verify_existing_work_prefix(project_root, &cur_rid, &req.workspace)?;
                let p = project_root.join(&ws_rel);
                if fs::symlink_metadata(&p).is_ok() { Some(p) } else { None }
            };

            let manifest_exists = load_work_manifest(state_dir, project_id, &req.workspace)?.is_some();
            if ws_pin.is_none() && !manifest_exists {
                return Err(BridgeError::new(
                    ErrorCode::NotFound,
                    format!("Workspace '{}' does not exist.", req.workspace),
                    OriginLayer::FileService,
                ));
            }

            let mut files_to_delete: Vec<(String, PathBuf, u64)> = Vec::new();
            let mut dirs_bottom_up: Vec<PathBuf> = Vec::new();

            if let Some(pin) = ws_pin {
                #[cfg(windows)]
                let (root_path_buf, ws_dir_path) = (pin.root_path.clone(), pin.path.clone());
                #[cfg(not(windows))]
                let ws_dir_path = pin.clone();

                // Pass 1: Complete pre-scan of the workspace BEFORE deleting anything.
                // Any symlink, NTFS junction, or hardlink (`n_links != 1`) aborts the entire operation!
                let mut seen_entries: usize = 0;
                let mut walk_stack: Vec<(PathBuf, String)> = vec![(ws_dir_path.clone(), ws_rel.clone())];
                while let Some((cur_dir, cur_rel)) = walk_stack.pop() {
                    let entries = fs::read_dir(&cur_dir).map_err(patch_io_error)?;
                    let mut children = Vec::new();
                    for entry in entries {
                        let entry = entry.map_err(patch_io_error)?;
                        seen_entries += 1;
                        if seen_entries > DELEGATED_WRITE_MAX_WALK_ENTRIES {
                            return Err(BridgeError::new(
                                ErrorCode::ResourceBudgetExceeded,
                                format!(
                                    "Workspace '{}' exceeds the {DELEGATED_WRITE_MAX_WALK_ENTRIES}-entry delete scan limit.",
                                    req.workspace
                                ),
                                OriginLayer::FileService,
                            ));
                        }
                        children.push(entry);
                    }
                    children.sort_by_key(|e| e.file_name());

                    for entry in children {
                        let child_path = entry.path();
                        let name = entry.file_name().to_string_lossy().to_string();
                        let child_rel = format!("{cur_rel}/{name}");
                        #[cfg(windows)]
                        {
                            let h = open_path_metadata_no_follow(&child_path).map_err(patch_io_error)?;
                            let id = file_identity_from_handle(&h)?;
                            if id.is_reparse_point {
                                return Err(BridgeError::new(
                                    ErrorCode::UnsupportedPathType,
                                    format!("Refusing workspace delete: reparse point/junction found at '{child_rel}'."),
                                    OriginLayer::FileService,
                                ));
                            }
                            if !id.is_directory && id.n_links != 1 {
                                return Err(BridgeError::new(
                                    ErrorCode::UnsupportedPathType,
                                    format!("Refusing workspace delete: hardlinked file found at '{child_rel}'."),
                                    OriginLayer::FileService,
                                ));
                            }
                            let obs = file_path_from_handle(&h)?;
                            if !obs.starts_with(&ws_dir_path) {
                                return Err(BridgeError::new(
                                    ErrorCode::UnsupportedPathType,
                                    format!("Refusing workspace delete: path escaped workspace at '{child_rel}'."),
                                    OriginLayer::FileService,
                                ));
                            }
                            if id.is_directory {
                                dirs_bottom_up.push(child_path.clone());
                                walk_stack.push((child_path, child_rel));
                            } else {
                                files_to_delete.push((child_rel, child_path, id.size_bytes));
                            }
                        }
                        #[cfg(not(windows))]
                        {
                            let meta = fs::symlink_metadata(&child_path).map_err(patch_io_error)?;
                            if meta.file_type().is_symlink() {
                                return Err(BridgeError::new(
                                    ErrorCode::UnsupportedPathType,
                                    format!("Refusing workspace delete: symlink found at '{child_rel}'."),
                                    OriginLayer::FileService,
                                ));
                            }
                            #[cfg(unix)]
                            if meta.is_file() {
                                use std::os::unix::fs::MetadataExt;
                                if meta.nlink() != 1 {
                                    return Err(BridgeError::new(
                                        ErrorCode::UnsupportedPathType,
                                        format!("Refusing workspace delete: hardlinked file found at '{child_rel}'."),
                                        OriginLayer::FileService,
                                    ));
                                }
                            }
                            if meta.is_dir() {
                                dirs_bottom_up.push(child_path.clone());
                                walk_stack.push((child_path, child_rel));
                            } else if meta.is_file() {
                                files_to_delete.push((child_rel, child_path, meta.len()));
                            } else {
                                return Err(BridgeError::new(
                                    ErrorCode::UnsupportedPathType,
                                    format!("Refusing workspace delete: unsupported entry at '{child_rel}'."),
                                    OriginLayer::FileService,
                                ));
                            }
                        }
                    }
                }

                // Re-authorize right before deletion.
                authorize_commit(&ws_rel)?;
                #[cfg(windows)]
                pin.verify_location(&ws_rel)?;

                // Pass 2: Delete verified regular files, then subdirectories deepest-first, then the workspace folder itself.
                let mut deleted_files = Vec::with_capacity(files_to_delete.len());
                let mut freed_bytes: u64 = 0;
                for (child_rel, child_path, size) in files_to_delete {
                    #[cfg(windows)]
                    {
                        let h = open_path_metadata_no_follow(&child_path).map_err(patch_io_error)?;
                        let id = file_identity_from_handle(&h)?;
                        if id.is_reparse_point || id.is_directory || id.n_links != 1 {
                            return Err(BridgeError::new(
                                ErrorCode::UnsupportedPathType,
                                format!("Refusing workspace delete: '{child_rel}' changed to a link or directory."),
                                OriginLayer::FileService,
                            ));
                        }
                        if !file_path_from_handle(&h)?.starts_with(&root_path_buf) {
                            return Err(BridgeError::new(
                                ErrorCode::UnsupportedPathType,
                                format!("Refusing workspace delete: '{child_rel}' escaped project root."),
                                OriginLayer::FileService,
                            ));
                        }
                        drop(h);
                    }
                    fs::remove_file(&child_path).map_err(patch_io_error)?;
                    freed_bytes = freed_bytes.saturating_add(size);
                    deleted_files.push(child_rel);
                }

                for dir in dirs_bottom_up.into_iter().rev() {
                    #[cfg(windows)]
                    {
                        let h = open_path_metadata_no_follow(&dir).map_err(patch_io_error)?;
                        let id = file_identity_from_handle(&h)?;
                        if id.is_reparse_point || !id.is_directory {
                            return Err(BridgeError::new(
                                ErrorCode::UnsupportedPathType,
                                "Refusing workspace delete: subdirectory became a link.",
                                OriginLayer::FileService,
                            ));
                        }
                        drop(h);
                    }
                    fs::remove_dir(&dir).map_err(patch_io_error)?;
                }

                // Release handle on `_pro/work/<workspace>` while keeping `_pro/work` checked, then remove only `<workspace>`.
                #[cfg(windows)]
                {
                    let mut dirs = pin.directories;
                    let _ws_handle = dirs.pop();
                    drop(_ws_handle);
                    let h = open_path_metadata_no_follow(&ws_dir_path).map_err(patch_io_error)?;
                    let id = file_identity_from_handle(&h)?;
                    if id.is_reparse_point || !id.is_directory {
                        return Err(BridgeError::new(
                            ErrorCode::UnsupportedPathType,
                            "Refusing workspace delete: workspace root became a link.",
                            OriginLayer::FileService,
                        ));
                    }
                    drop(h);
                    fs::remove_dir(&ws_dir_path).map_err(patch_io_error)?;
                    drop(dirs);
                }
                #[cfg(not(windows))]
                fs::remove_dir(&ws_dir_path).map_err(patch_io_error)?;

                remove_work_manifest(state_dir, project_id, &req.workspace)?;
                let quota = work_quota_telemetry(project_root, state_dir, project_id)?;
                return Ok(WorkDeleteResult {
                    workspace: req.workspace.clone(),
                    operation_id: req.operation_id.clone(),
                    deleted_workspace: true,
                    freed_files: deleted_files.len(),
                    deleted_files,
                    freed_bytes,
                    quota,
                });
            }

            // Only manifest existed (workspace folder already absent): re-authorize and remove manifest.
            authorize_commit(&ws_rel)?;
            remove_work_manifest(state_dir, project_id, &req.workspace)?;
            let quota = work_quota_telemetry(project_root, state_dir, project_id)?;
            Ok(WorkDeleteResult {
                workspace: req.workspace.clone(),
                operation_id: req.operation_id.clone(),
                deleted_workspace: true,
                deleted_files: Vec::new(),
                freed_files: 0,
                freed_bytes: 0,
                quota,
            })
        }
    }
}

/// Verified work-copy snapshot source for `python_tests_work`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkPythonSnapshotScope {
    pub workspace: String,
    pub work_root: String,
    pub work_root_identity: String,
    pub files: Vec<String>,
    pub total_bytes: u64,
    pub entries_scanned: usize,
}

fn is_work_test_module_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("tests/test_") else {
        return false;
    };
    let Some(stem) = rest.strip_suffix(".py") else {
        return false;
    };
    !stem.is_empty() && stem.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Discover and verify `.py` and `.json` snapshot inputs strictly inside `_pro/work/<workspace>/`.
///
/// Enforces:
/// - bridge-side manifest existence and `(project_id, workspace, root_identity)` match,
/// - exact-case, non-reparse directory handles along `_pro/work/<workspace>`,
/// - refusal of any reparse point / junction / symlink anywhere inside the workspace,
/// - refusal of any non-hidden file with `n_links != 1` (hard links),
/// - silent exclusion of files/folders hidden from remote callers (`is_hidden_from_remote`),
/// - limits: 128 files, 256 KiB per file, 4 MiB total, 1,000 entries, depth <= 6,
/// - presence of `tests/__init__.py`, at least one `tests/test_*.py`, and any requested selector module.
pub fn discover_work_python_scope(
    project_root: &Path,
    project_root_identity: &str,
    state_dir: &Path,
    project_id: &str,
    workspace: &str,
    test_target: Option<&str>,
) -> Result<WorkPythonSnapshotScope, BridgeError> {
    validate_safe_id(project_id)?;
    validate_work_name(workspace)?;
    let canonical_target = test_target.map(validate_work_test_selector).transpose()?;

    let remote_reader = ScopedFiles::new_remote_read(project_root, Some(project_root_identity.to_owned()))?;
    let cur_rid = remote_reader.current_root_identity()?;
    if project_root_identity.starts_with("ntfs:") && cur_rid != project_root_identity {
        return Err(BridgeError::new(
            ErrorCode::StalePrecondition,
            "Project root identity mismatch.",
            OriginLayer::FileService,
        ));
    }

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

    let ws_rel = format!("{PRO_WORK_PREFIX}{workspace}");
    #[cfg(windows)]
    let (ws_pin, ws_verbatim, work_root, work_root_identity) = {
        let ws_pin = PatchParent::pin_dir_existing(project_root, &cur_rid, &ws_rel, true)?.ok_or_else(|| {
            BridgeError::new(
                ErrorCode::NotFound,
                format!("Workspace directory '{ws_rel}' does not exist."),
                OriginLayer::FileService,
            )
        })?;
        let ws_handle = ws_pin.directories.last().unwrap();
        let ws_id = file_identity_from_handle(ws_handle)?;
        if !ws_id.is_directory || ws_id.is_reparse_point {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("Workspace path '{ws_rel}' is a link or non-directory."),
                OriginLayer::FileService,
            ));
        }
        let ws_verbatim = ws_pin.path.clone();
        let raw_str = ws_verbatim.to_string_lossy();
        let work_root = raw_str.strip_prefix(r"\\?\").unwrap_or(&raw_str).to_owned();
        (ws_pin, ws_verbatim, work_root, ws_id.canonical_id())
    };
    #[cfg(windows)]
    let _keep_ws_pin = ws_pin;
    #[cfg(not(windows))]
    let (ws_verbatim, work_root, work_root_identity) = {
        check_no_symlink_prefix(project_root, &ws_rel)?;
        let ws_verbatim = project_root.join(&ws_rel);
        let meta = fs::symlink_metadata(&ws_verbatim).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BridgeError::new(
                    ErrorCode::NotFound,
                    format!("Workspace directory '{ws_rel}' does not exist."),
                    OriginLayer::FileService,
                )
            } else {
                patch_io_error(e)
            }
        })?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("Workspace path '{ws_rel}' is a link or non-directory."),
                OriginLayer::FileService,
            ));
        }
        let work_root = ws_verbatim.to_string_lossy().into_owned();
        let work_root_identity = format!("posix:{work_root}");
        (ws_verbatim, work_root, work_root_identity)
    };

    let mut files = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut entries_scanned: usize = 0;
    let mut stack: Vec<(PathBuf, Vec<String>, usize)> = vec![(ws_verbatim.clone(), Vec::new(), 1)];

    while let Some((cur_dir, rel_parts, depth)) = stack.pop() {
        let reader = fs::read_dir(&cur_dir).map_err(patch_io_error)?;
        let mut children = Vec::new();
        for entry in reader {
            children.push(entry.map_err(patch_io_error)?);
        }
        children.sort_by_key(|e| e.file_name());

        let mut subdirs = Vec::new();
        for entry in children {
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
            let child_path = entry.path();
            #[cfg(windows)]
            let (is_dir, n_links, size_bytes, observed_path) = {
                let h = open_path_metadata_no_follow(&child_path).map_err(patch_io_error)?;
                let id = file_identity_from_handle(&h)?;
                if id.is_reparse_point {
                    return Err(BridgeError::new(
                        ErrorCode::UnsupportedPathType,
                        "Reparse point or junction is denied inside work-copy workspace.",
                        OriginLayer::FileService,
                    ));
                }
                let obs = file_path_from_handle(&h)?;
                (id.is_directory, id.n_links, id.size_bytes, obs)
            };
            #[cfg(not(windows))]
            let (is_dir, n_links, size_bytes) = {
                let meta = fs::symlink_metadata(&child_path).map_err(patch_io_error)?;
                if meta.file_type().is_symlink() {
                    return Err(BridgeError::new(
                        ErrorCode::UnsupportedPathType,
                        "Symlink is denied inside work-copy workspace.",
                        OriginLayer::FileService,
                    ));
                }
                #[cfg(unix)]
                let n_links = {
                    use std::os::unix::fs::MetadataExt;
                    meta.nlink() as u32
                };
                #[cfg(not(unix))]
                let n_links = 1u32;
                (meta.is_dir(), n_links, meta.len())
            };

            let mut child_parts = rel_parts.clone();
            child_parts.push(name.clone());
            // Files/folders hidden from remote callers never enter the snapshot and are not leaked.
            if is_hidden_from_remote(&child_parts) {
                continue;
            }
            if is_dir && GENERATED_DIRS.iter().any(|g| g.eq_ignore_ascii_case(&name)) {
                continue;
            }

            entries_scanned += 1;
            if entries_scanned > WORK_EXEC_MAX_DISCOVERY_ENTRIES {
                return Err(BridgeError::new(
                    ErrorCode::ResourceBudgetExceeded,
                    format!(
                        "Work-copy discovery exceeded {WORK_EXEC_MAX_DISCOVERY_ENTRIES} workspace entries."
                    ),
                    OriginLayer::JobRunner,
                ));
            }

            let sub_rel = child_parts.join("/");
            let validated_parts = validate_remote_relative_path(&sub_rel)?;
            let canonical_sub = validated_parts.join("/");
            #[cfg(windows)]
            verify_opened_name(&ws_verbatim, Path::new(&canonical_sub), &observed_path)?;

            if is_dir {
                if depth < WORK_EXEC_MAX_DEPTH {
                    subdirs.push((child_path, child_parts, depth + 1));
                }
            } else {
                if n_links != 1 {
                    return Err(BridgeError::new(
                        ErrorCode::UnsupportedPathType,
                        "Hardlinked file is denied inside work-copy workspace.",
                        OriginLayer::FileService,
                    ));
                }
                let dot_hidden = child_parts.iter().any(|part| part.starts_with('.'));
                if !dot_hidden && (canonical_sub.ends_with(".py") || canonical_sub.ends_with(".json")) {
                    if size_bytes > WORK_EXEC_MAX_FILE_BYTES {
                        return Err(BridgeError::new(
                            ErrorCode::ResourceBudgetExceeded,
                            format!(
                                "Work-copy snapshot file exceeds {WORK_EXEC_MAX_FILE_BYTES} bytes limit."
                            ),
                            OriginLayer::JobRunner,
                        ));
                    }
                    total_bytes = total_bytes.saturating_add(size_bytes);
                    if total_bytes > WORK_EXEC_MAX_TOTAL_BYTES {
                        return Err(BridgeError::new(
                            ErrorCode::ResourceBudgetExceeded,
                            format!(
                                "Work-copy snapshot exceeds {WORK_EXEC_MAX_TOTAL_BYTES} bytes total limit."
                            ),
                            OriginLayer::JobRunner,
                        ));
                    }
                    if files.len() + 1 > WORK_EXEC_MAX_SNAPSHOT_FILES {
                        return Err(BridgeError::new(
                            ErrorCode::ResourceBudgetExceeded,
                            format!(
                                "Work-copy snapshot exceeds {WORK_EXEC_MAX_SNAPSHOT_FILES} files limit."
                            ),
                            OriginLayer::JobRunner,
                        ));
                    }
                    files.push(canonical_sub);
                }
            }
        }
        for sub in subdirs.into_iter().rev() {
            stack.push(sub);
        }
    }

    files.sort();
    let has_init = files.iter().any(|f| f == "tests/__init__.py");
    let has_test_mod = files.iter().any(|f| is_work_test_module_path(f));
    if files.len() < 2 || !has_init || !has_test_mod {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "INVALID_TEST_SCOPE: work copy must include tests/__init__.py and at least one tests/test_*.py.",
            OriginLayer::Validation,
        ));
    }
    if let Some(ref target) = canonical_target {
        let mut parts = target.split('.');
        let pkg = parts.next().unwrap_or("");
        let module = parts.next().unwrap_or("");
        let expected_file = format!("{pkg}/{module}.py");
        if !files.iter().any(|f| f == &expected_file) {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                format!("INVALID_TEST_SCOPE: selected test module '{expected_file}' is absent from the work-copy snapshot."),
                OriginLayer::Validation,
            ));
        }
    }

    Ok(WorkPythonSnapshotScope {
        workspace: workspace.to_owned(),
        work_root,
        work_root_identity,
        files,
        total_bytes,
        entries_scanned,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PRO_REVIEW_WRITABLE_PATH, validate_work_name};

    fn make_scope() -> Vec<String> {
        vec![PRO_REVIEW_WRITABLE_PATH.to_owned()]
    }

    fn auth_target_for(workspace: &str) -> impl FnMut(&str) -> Result<String, BridgeError> + '_ {
        move |sub| {
            validate_work_name(workspace)?;
            let parts = validate_remote_relative_path(sub)?;
            if parts.is_empty() {
                return Err(BridgeError::new(ErrorCode::InvalidArgument, "empty subpath", OriginLayer::Policy));
            }
            if is_hidden_from_remote(&parts) {
                return Err(BridgeError::new(ErrorCode::BridgePolicyDenied, "hidden", OriginLayer::Policy));
            }
            Ok(format!("{PRO_WORK_PREFIX}{workspace}/{}", parts.join("/")))
        }
    }

    fn create_junction(link: &Path, target: &Path) {
        #[cfg(windows)]
        {
            let win_link = link.to_string_lossy().replace('/', "\\");
            let win_target = target.to_string_lossy().replace('/', "\\");
            let out = std::process::Command::new("cmd.exe")
                .args(["/D", "/C", "mklink", "/J", &win_link, &win_target])
                .output()
                .unwrap();
            assert!(out.status.success(), "{out:?}");
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    fn remove_junction(link: &Path) {
        #[cfg(windows)]
        let _ = fs::remove_dir(link);
        #[cfg(unix)]
        let _ = fs::remove_file(link);
    }

    #[test]
    fn work_copy_copies_files_and_subtrees_filters_hidden_and_pro_and_writes_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let state = dir.path().join("state");
        let outside = dir.path().join("outside");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join(".ssh")).unwrap();
        fs::create_dir_all(root.join("__pycache__")).unwrap();
        fs::create_dir_all(root.join("_pro/inbox")).unwrap();
        fs::create_dir_all(&outside).unwrap();

        fs::write(root.join("src/app.py"), "def add(a, b):\n    return a - b\n").unwrap();
        fs::write(root.join("tests/test_app.py"), "assert True\n").unwrap();
        fs::write(root.join(".env"), "SECRET=1\n").unwrap();
        fs::write(root.join("src/auth.json"), "{\"tok\":\"x\"}\n").unwrap();
        fs::write(root.join(".git/config"), "[core]\n").unwrap();
        fs::write(root.join(".ssh/id_rsa"), "PRIVATE\n").unwrap();
        fs::write(root.join("__pycache__/app.pyc"), b"\x00\x01").unwrap();
        fs::write(root.join("_pro/inbox/req.md"), "owner prompt\n").unwrap();
        fs::write(outside.join("leak.py"), "OUTSIDE\n").unwrap();
        create_junction(&root.join("src/linked"), &outside);

        let sf = ScopedFiles::new(&root, None).unwrap();
        let rid = sf.current_root_identity().unwrap();

        // Copy "." -> copies src/app.py & tests/test_app.py, silently skips .env, auth.json, .git, .ssh, _pro, junction, __pycache__.
        let res = work_copy(
            &root,
            &rid,
            &state,
            "proj_1",
            &WorkCopyRequest {
                workspace: "fix-1".into(),
                mode: WorkCopyMode::FromProject {
                    paths: vec![".".into()],
                    exclude_generated: true,
                },
                overwrite_existing: false,
            },
            &make_scope(),
            auth_target_for("fix-1"),
            |_| Ok(()),
        )
        .unwrap();

        assert_eq!(res.files_copied, vec!["_pro/work/fix-1/src/app.py", "_pro/work/fix-1/tests/test_app.py"]);
        assert_eq!(res.copied_count, 2);
        assert_eq!(res.skipped_generated_dirs, 1);
        assert!(res.skipped_non_secret.is_empty());
        let serialized = serde_json::to_string(&res).unwrap();
        for secret in [".env", "auth.json", ".git", "id_rsa", "leak.py", "req.md"] {
            assert!(!serialized.contains(secret), "leaked {secret}: {serialized}");
        }
        assert!(!root.join("_pro/work/fix-1/.env").exists());
        assert!(!root.join("_pro/work/fix-1/src/auth.json").exists());
        assert!(!root.join("_pro/work/fix-1/.git").exists());
        assert!(!root.join("_pro/work/fix-1/_pro").exists());
        assert!(!root.join("_pro/work/fix-1/src/linked").exists());

        // Manifest written outside `_pro/work/` with baseline hashes.
        let manifest = load_work_manifest(&state, "proj_1", "fix-1").unwrap().unwrap();
        assert_eq!(manifest.project_id, "proj_1");
        assert_eq!(manifest.root_identity, rid);
        assert_eq!(manifest.entries.len(), 2);
        assert_eq!(
            manifest.entries["src/app.py"].baseline_sha256,
            sha256_bytes(b"def add(a, b):\n    return a - b\n")
        );
        assert!(!manifest.entries["src/app.py"].deleted_in_work);

        // Copying again with overwrite_existing=false fails VersionConflict; true succeeds.
        let conflict = work_copy(
            &root,
            &rid,
            &state,
            "proj_1",
            &WorkCopyRequest {
                workspace: "fix-1".into(),
                mode: WorkCopyMode::FromProject {
                    paths: vec!["src/app.py".into()],
                    exclude_generated: true,
                },
                overwrite_existing: false,
            },
            &make_scope(),
            auth_target_for("fix-1"),
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(conflict.code, ErrorCode::VersionConflict);

        // within_workspace copy does NOT add destination as a baseline manifest entry.
        let intra = work_copy(
            &root,
            &rid,
            &state,
            "proj_1",
            &WorkCopyRequest {
                workspace: "fix-1".into(),
                mode: WorkCopyMode::WithinWorkspace {
                    from: "src/app.py".into(),
                    to: "src/app_copy.py".into(),
                },
                overwrite_existing: false,
            },
            &make_scope(),
            auth_target_for("fix-1"),
            |_| Ok(()),
        )
        .unwrap();
        assert!(intra.within_workspace);
        assert_eq!(intra.files_copied, vec!["_pro/work/fix-1/src/app_copy.py"]);
        let manifest_after = load_work_manifest(&state, "proj_1", "fix-1").unwrap().unwrap();
        assert!(!manifest_after.entries.contains_key("src/app_copy.py"));

        // Explicit _pro source refused with InvalidArgument; explicit hidden source refused with BridgePolicyDenied.
        assert_eq!(
            work_copy(
                &root, &rid, &state, "proj_1",
                &WorkCopyRequest {
                    workspace: "fix-1".into(),
                    mode: WorkCopyMode::FromProject { paths: vec!["_pro".into()], exclude_generated: true },
                    overwrite_existing: false,
                },
                &make_scope(), auth_target_for("fix-1"), |_| Ok(()),
            ).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            work_copy(
                &root, &rid, &state, "proj_1",
                &WorkCopyRequest {
                    workspace: "fix-1".into(),
                    mode: WorkCopyMode::FromProject { paths: vec![".env".into()], exclude_generated: true },
                    overwrite_existing: false,
                },
                &make_scope(), auth_target_for("fix-1"), |_| Ok(()),
            ).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );

        remove_junction(&root.join("src/linked"));
    }

    #[test]
    fn work_copy_hardlink_and_limits_enforced_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let state = dir.path().join("state");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/normal.py"), "ok\n").unwrap();
        fs::write(root.join("src/linked.py"), "linked\n").unwrap();
        fs::hard_link(root.join("src/linked.py"), root.join("src/linked_alias.py")).unwrap();

        let sf = ScopedFiles::new(&root, None).unwrap();
        let rid = sf.current_root_identity().unwrap();

        // Explicit hardlinked source refused with UnsupportedPathType.
        assert_eq!(
            work_copy(
                &root, &rid, &state, "proj_hl",
                &WorkCopyRequest {
                    workspace: "w1".into(),
                    mode: WorkCopyMode::FromProject { paths: vec!["src/linked.py".into()], exclude_generated: true },
                    overwrite_existing: false,
                },
                &make_scope(), auth_target_for("w1"), |_| Ok(()),
            ).unwrap_err().code,
            ErrorCode::UnsupportedPathType
        );
        assert!(!root.join("_pro").exists());

        // Directory walk skips hardlinked files into skipped_non_secret with reason "hardlinked".
        let walked = work_copy(
            &root, &rid, &state, "proj_hl",
            &WorkCopyRequest {
                workspace: "w1".into(),
                mode: WorkCopyMode::FromProject { paths: vec!["src".into()], exclude_generated: true },
                overwrite_existing: false,
            },
            &make_scope(), auth_target_for("w1"), |_| Ok(()),
        ).unwrap();
        assert_eq!(walked.files_copied, vec!["_pro/work/w1/src/normal.py"]);
        assert_eq!(walked.skipped_non_secret.len(), 2);
        assert!(walked.skipped_non_secret.iter().all(|s| s.reason == "hardlinked"));

        // Explicit >4 MiB file refused with ResourceBudgetExceeded.
        File::create(root.join("src/huge.bin")).unwrap().set_len(WORK_COPY_MAX_FILE_BYTES + 1).unwrap();
        assert_eq!(
            work_copy(
                &root, &rid, &state, "proj_hl",
                &WorkCopyRequest {
                    workspace: "w2".into(),
                    mode: WorkCopyMode::FromProject { paths: vec!["src/huge.bin".into()], exclude_generated: true },
                    overwrite_existing: false,
                },
                &make_scope(), auth_target_for("w2"), |_| Ok(()),
            ).unwrap_err().code,
            ErrorCode::ResourceBudgetExceeded
        );
        assert!(!root.join("_pro/work/w2").exists());

        // >16 workspaces refused before writing.
        for i in 2..=MAX_WORKSPACES_PER_PROJECT {
            let ws = format!("ws-{i:02}");
            work_copy(
                &root, &rid, &state, "proj_hl",
                &WorkCopyRequest {
                    workspace: ws.clone(),
                    mode: WorkCopyMode::FromProject { paths: vec!["src/normal.py".into()], exclude_generated: true },
                    overwrite_existing: false,
                },
                &make_scope(), auth_target_for(&ws), |_| Ok(()),
            ).unwrap();
        }
        assert_eq!(
            work_copy(
                &root, &rid, &state, "proj_hl",
                &WorkCopyRequest {
                    workspace: "ws-overflow".into(),
                    mode: WorkCopyMode::FromProject { paths: vec!["src/normal.py".into()], exclude_generated: true },
                    overwrite_existing: false,
                },
                &make_scope(), auth_target_for("ws-overflow"), |_| Ok(()),
            ).unwrap_err().code,
            ErrorCode::ResourceBudgetExceeded
        );
        assert!(!root.join("_pro/work/ws-overflow").exists());

        // >500 files per call in work_copy refused before writing any byte.
        let many_dir = root.join("many501");
        fs::create_dir_all(&many_dir).unwrap();
        for i in 0..=WORK_COPY_MAX_FILES {
            fs::write(many_dir.join(format!("f_{i:04}.txt")), "x").unwrap();
        }
        assert_eq!(
            work_copy(
                &root, &rid, &state, "proj_hl",
                &WorkCopyRequest {
                    workspace: "w1".into(),
                    mode: WorkCopyMode::FromProject { paths: vec!["many501".into()], exclude_generated: true },
                    overwrite_existing: false,
                },
                &make_scope(), auth_target_for("w1"), |_| Ok(()),
            ).unwrap_err().code,
            ErrorCode::ResourceBudgetExceeded
        );
        assert!(!root.join("_pro/work/w1/many501").exists());
        fs::remove_dir_all(&many_dir).unwrap();

        // >32 MiB total bytes per call in work_copy refused before writing any byte (9 x 4 MiB = 36 MiB).
        let big_dir = root.join("big36");
        fs::create_dir_all(&big_dir).unwrap();
        for i in 0..9 {
            File::create(big_dir.join(format!("b_{i}.bin")))
                .unwrap()
                .set_len(WORK_COPY_MAX_FILE_BYTES)
                .unwrap();
        }
        assert_eq!(
            work_copy(
                &root, &rid, &state, "proj_hl",
                &WorkCopyRequest {
                    workspace: "w1".into(),
                    mode: WorkCopyMode::FromProject { paths: vec!["big36".into()], exclude_generated: true },
                    overwrite_existing: false,
                },
                &make_scope(), auth_target_for("w1"), |_| Ok(()),
            ).unwrap_err().code,
            ErrorCode::ResourceBudgetExceeded
        );
        assert!(!root.join("_pro/work/w1/big36").exists());
        fs::remove_dir_all(&big_dir).unwrap();

        // 256 MiB `_pro/` folder limit refused before writing any byte.
        let used = measure_delegated_folder_quota(&root, "_pro").unwrap().bytes;
        fs::create_dir_all(root.join("_pro/inbox")).unwrap();
        File::create(root.join("_pro/inbox/fill.bin"))
            .unwrap()
            .set_len(DELEGATED_WRITE_MAX_SCOPE_BYTES - used - 2)
            .unwrap();
        fs::write(root.join("src/ten.txt"), "0123456789").unwrap();
        assert_eq!(
            work_copy(
                &root, &rid, &state, "proj_hl",
                &WorkCopyRequest {
                    workspace: "w1".into(),
                    mode: WorkCopyMode::FromProject { paths: vec!["src/ten.txt".into()], exclude_generated: true },
                    overwrite_existing: false,
                },
                &make_scope(), auth_target_for("w1"), |_| Ok(()),
            ).unwrap_err().code,
            ErrorCode::ResourceBudgetExceeded
        );
        assert!(!root.join("_pro/work/w1/src/ten.txt").exists());
    }

    #[test]
    fn work_edit_atomic_all_or_nothing_and_commit_time_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let state = dir.path().join("state");
        fs::create_dir_all(root.join("_pro/work/w1")).unwrap();
        fs::write(root.join("_pro/work/w1/a.py"), "x = 1\ny = 2\n").unwrap();
        fs::write(root.join("_pro/work/w1/b.py"), "dup\ndup\n").unwrap();

        let sf = ScopedFiles::new(&root, None).unwrap();
        let rid = sf.current_root_identity().unwrap();

        // Ambiguous match on file 2 leaves file 1 completely untouched.
        let err = work_edit(
            &root, &rid, &state, "proj_e",
            &WorkEditRequest {
                workspace: "w1".into(),
                operation_id: "op_ambig".into(),
                task_id: None,
                edits: vec![
                    WorkFileEdit {
                        path: "a.py".into(),
                        expected_hash: None,
                        replacements: vec![WorkReplacement { old_text: "x = 1".into(), new_text: "x = 9".into(), replace_all: false }],
                    },
                    WorkFileEdit {
                        path: "b.py".into(),
                        expected_hash: None,
                        replacements: vec![WorkReplacement { old_text: "dup".into(), new_text: "one".into(), replace_all: false }],
                    },
                ],
            },
            &make_scope(), auth_target_for("w1"), |_| Ok(()),
        ).unwrap_err();
        assert_eq!(err.code, ErrorCode::VersionConflict);
        assert_eq!(fs::read_to_string(root.join("_pro/work/w1/a.py")).unwrap(), "x = 1\ny = 2\n");
        assert_eq!(fs::read_to_string(root.join("_pro/work/w1/b.py")).unwrap(), "dup\ndup\n");

        // Commit-time failure on file 2 rolls back file 1 back to original bytes!
        let revoked = work_edit(
            &root, &rid, &state, "proj_e",
            &WorkEditRequest {
                workspace: "w1".into(),
                operation_id: "op_revoke".into(),
                task_id: None,
                edits: vec![
                    WorkFileEdit {
                        path: "a.py".into(),
                        expected_hash: None,
                        replacements: vec![WorkReplacement { old_text: "x = 1".into(), new_text: "x = 9".into(), replace_all: false }],
                    },
                    WorkFileEdit {
                        path: "b.py".into(),
                        expected_hash: None,
                        replacements: vec![WorkReplacement { old_text: "dup".into(), new_text: "one".into(), replace_all: true }],
                    },
                ],
            },
            &make_scope(),
            auth_target_for("w1"),
            |path| {
                if path.ends_with("b.py") {
                    Err(BridgeError::new(ErrorCode::BridgePolicyDenied, "revoked mid-commit", OriginLayer::Policy))
                } else {
                    Ok(())
                }
            },
        ).unwrap_err();
        assert_eq!(revoked.code, ErrorCode::BridgePolicyDenied);
        assert_eq!(fs::read_to_string(root.join("_pro/work/w1/a.py")).unwrap(), "x = 1\ny = 2\n");
        assert_eq!(fs::read_to_string(root.join("_pro/work/w1/b.py")).unwrap(), "dup\ndup\n");

        // Succeeds atomically with replace_all=true.
        let (ok, _) = work_edit(
            &root, &rid, &state, "proj_e",
            &WorkEditRequest {
                workspace: "w1".into(),
                operation_id: "op_ok".into(),
                task_id: None,
                edits: vec![
                    WorkFileEdit {
                        path: "a.py".into(),
                        expected_hash: Some(sha256_bytes(b"x = 1\ny = 2\n")),
                        replacements: vec![WorkReplacement { old_text: "x = 1".into(), new_text: "x = 9".into(), replace_all: false }],
                    },
                    WorkFileEdit {
                        path: "b.py".into(),
                        expected_hash: None,
                        replacements: vec![WorkReplacement { old_text: "dup".into(), new_text: "one".into(), replace_all: true }],
                    },
                ],
            },
            &make_scope(), auth_target_for("w1"), |_| Ok(()),
        ).unwrap();
        assert_eq!(ok.replacements_applied, 3);
        assert_eq!(fs::read_to_string(root.join("_pro/work/w1/a.py")).unwrap(), "x = 9\ny = 2\n");
        assert_eq!(fs::read_to_string(root.join("_pro/work/w1/b.py")).unwrap(), "one\none\n");
    }

    #[test]
    fn work_move_and_work_delete_refuse_links_and_hardlinks_and_update_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let state = dir.path().join("state");
        let outside = dir.path().join("outside");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("src/live.py"), "LIVE_ORIGINAL\n").unwrap();
        fs::write(outside.join("precious.txt"), "OUTSIDE_PRECIOUS\n").unwrap();

        let sf = ScopedFiles::new(&root, None).unwrap();
        let rid = sf.current_root_identity().unwrap();

        work_copy(
            &root, &rid, &state, "proj_md",
            &WorkCopyRequest {
                workspace: "w1".into(),
                mode: WorkCopyMode::FromProject { paths: vec!["src/live.py".into()], exclude_generated: true },
                overwrite_existing: false,
            },
            &make_scope(), auth_target_for("w1"), |_| Ok(()),
        ).unwrap();

        // Move src/live.py -> src/renamed.py inside w1; manifest marks src/live.py as deleted_in_work.
        let moved = work_move(
            &root, &rid, &state, "proj_md",
            &WorkMoveRequest {
                workspace: "w1".into(),
                operation_id: "op_mv1".into(),
                from: "src/live.py".into(),
                to: "src/renamed.py".into(),
                expected_from_hash: Some(sha256_bytes(b"LIVE_ORIGINAL\n")),
                overwrite: false,
                expected_to_hash: None,
            },
            &make_scope(), auth_target_for("w1"), |_| Ok(()),
        ).unwrap();
        assert_eq!(moved.to, "_pro/work/w1/src/renamed.py");
        assert!(!root.join("_pro/work/w1/src/live.py").exists());
        assert_eq!(fs::read_to_string(root.join("_pro/work/w1/src/renamed.py")).unwrap(), "LIVE_ORIGINAL\n");
        let m = load_work_manifest(&state, "proj_md", "w1").unwrap().unwrap();
        assert!(m.entries["src/live.py"].deleted_in_work);

        // Plant a hardlink to src/live.py inside w1 -> work_edit, work_move, work_delete(file & workspace) all refuse!
        let hl_path = root.join("_pro/work/w1/hard.py");
        fs::hard_link(root.join("src/live.py"), &hl_path).unwrap();

        assert_eq!(
            work_edit(
                &root, &rid, &state, "proj_md",
                &WorkEditRequest {
                    workspace: "w1".into(),
                    operation_id: "op_hl_edit".into(),
                    task_id: None,
                    edits: vec![WorkFileEdit {
                        path: "hard.py".into(),
                        expected_hash: None,
                        replacements: vec![WorkReplacement { old_text: "LIVE".into(), new_text: "PWN".into(), replace_all: false }],
                    }],
                },
                &make_scope(), auth_target_for("w1"), |_| Ok(()),
            ).unwrap_err().code,
            ErrorCode::UnsupportedPathType
        );
        assert_eq!(
            work_move(
                &root, &rid, &state, "proj_md",
                &WorkMoveRequest {
                    workspace: "w1".into(),
                    operation_id: "op_hl_mv".into(),
                    from: "src/renamed.py".into(),
                    to: "hard.py".into(),
                    expected_from_hash: None,
                    overwrite: true,
                    expected_to_hash: None,
                },
                &make_scope(), auth_target_for("w1"), |_| Ok(()),
            ).unwrap_err().code,
            ErrorCode::UnsupportedPathType
        );
        assert_eq!(
            work_delete(
                &root, &rid, &state, "proj_md",
                &WorkDeleteRequest {
                    workspace: "w1".into(),
                    operation_id: "op_hl_del_ws".into(),
                    target: WorkDeleteTarget::WholeWorkspace,
                },
                |_| Ok("_pro/work/w1".into()),
                |_| Ok(()),
            ).unwrap_err().code,
            ErrorCode::UnsupportedPathType
        );
        assert_eq!(fs::read_to_string(root.join("src/live.py")).unwrap(), "LIVE_ORIGINAL\n");
        fs::remove_file(&hl_path).unwrap();

        // Plant a junction inside w1 -> delete_workspace refuses BEFORE deleting src/renamed.py or outside!
        let link_in_ws = root.join("_pro/work/w1/link");
        create_junction(&link_in_ws, &outside);
        assert_eq!(
            work_delete(
                &root, &rid, &state, "proj_md",
                &WorkDeleteRequest {
                    workspace: "w1".into(),
                    operation_id: "op_junc_del".into(),
                    target: WorkDeleteTarget::WholeWorkspace,
                },
                |_| Ok("_pro/work/w1".into()),
                |_| Ok(()),
            ).unwrap_err().code,
            ErrorCode::UnsupportedPathType
        );
        assert!(root.join("_pro/work/w1/src/renamed.py").exists());
        assert_eq!(fs::read_to_string(outside.join("precious.txt")).unwrap(), "OUTSIDE_PRECIOUS\n");
        remove_junction(&link_in_ws);

        // Create sibling workspace w2 and outbox file to ensure whole-workspace delete removes ONLY w1.
        fs::create_dir_all(root.join("_pro/work/w2")).unwrap();
        fs::write(root.join("_pro/work/w2/keep.py"), "keep\n").unwrap();
        fs::create_dir_all(root.join("_pro/outbox")).unwrap();
        fs::write(root.join("_pro/outbox/keep.md"), "keep\n").unwrap();

        let deleted = work_delete(
            &root, &rid, &state, "proj_md",
            &WorkDeleteRequest {
                workspace: "w1".into(),
                operation_id: "op_del_ws".into(),
                target: WorkDeleteTarget::WholeWorkspace,
            },
            |_| Ok("_pro/work/w1".into()),
            |_| Ok(()),
        ).unwrap();
        assert!(deleted.deleted_workspace);
        assert_eq!(deleted.freed_files, 1);
        assert!(!root.join("_pro/work/w1").exists());
        assert!(load_work_manifest(&state, "proj_md", "w1").unwrap().is_none());
        assert!(root.join("_pro/work/w2/keep.py").is_file());
        assert!(root.join("_pro/outbox/keep.md").is_file());
        assert_eq!(fs::read_to_string(root.join("src/live.py")).unwrap(), "LIVE_ORIGINAL\n");
    }

    #[test]
    fn toctou_target_swapped_for_link_between_check_and_write_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let state = dir.path().join("state");
        let outside = dir.path().join("outside");
        fs::create_dir_all(root.join("_pro/work/w1")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("_pro/work/w1/target.py"), "before\n").unwrap();
        fs::write(root.join("live.py"), "LIVE_UNTOUCHED\n").unwrap();
        fs::write(outside.join("outside.txt"), "OUTSIDE\n").unwrap();

        let sf = ScopedFiles::new(&root, None).unwrap();
        let rid = sf.current_root_identity().unwrap();
        let jdir = state.join("patch-journals");
        fs::create_dir_all(&jdir).unwrap();

        // Swap target.py for a directory junction between Phase 1 check and Phase 3 commit!
        let plan = PatchPlanV04 {
            patch_plan_version: BRIDGE_CONTRACT_VERSION.into(),
            project_id: "proj_toctou".into(),
            root_identity: Some(rid.clone()),
            operation_id: "op_toctou_junc".into(),
            task_id: None,
            summary: None,
            baseline_manifest_sha256: None,
            scope: vec!["_pro/work/w1/target.py".into()],
            edits: vec![PatchEditV04 {
                path: "_pro/work/w1/target.py".into(),
                content: "after\n".into(),
                expected_hash: Some(sha256_bytes(b"before\n")),
                expected_postimage_hash: None,
            }],
            verification_recipe: None,
            verification_command: None,
        };
        let target_path = root.join("_pro/work/w1/target.py");
        let err = sf.apply_delegated_work_edits(&plan, &jdir, &make_scope(), |_| {
            fs::remove_file(&target_path).unwrap();
            create_junction(&target_path, &outside);
            Ok(())
        }).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedPathType, "{err:?}");
        assert_eq!(fs::read_to_string(outside.join("outside.txt")).unwrap(), "OUTSIDE\n");
        remove_junction(&target_path);

        // Swap target.py for a hard link to project's live.py between Phase 1 check and Phase 3 commit!
        fs::write(&target_path, "before\n").unwrap();
        let live_path = root.join("live.py");
        let err_hl = sf.apply_delegated_work_edits(&plan, &jdir, &make_scope(), |_| {
            fs::remove_file(&target_path).unwrap();
            fs::hard_link(&live_path, &target_path).unwrap();
            Ok(())
        }).unwrap_err();
        assert_eq!(err_hl.code, ErrorCode::UnsupportedPathType, "{err_hl:?}");
        assert_eq!(fs::read_to_string(&live_path).unwrap(), "LIVE_UNTOUCHED\n");
    }

    #[test]
    fn discover_work_python_scope_skips_hidden_and_refuses_links_hardlinks_case_and_limits() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        let state = dir.path().join("state");
        let outside = dir.path().join("outside");
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("calc.py"), "def add(a, b): return a + b\n").unwrap();
        fs::write(root.join("tests/__init__.py"), "").unwrap();
        fs::write(root.join("tests/test_calc.py"), "import unittest\n").unwrap();
        fs::write(outside.join("secret.py"), "SECRET = 1\n").unwrap();

        let sf = ScopedFiles::new(&root, None).unwrap();
        let rid = sf.current_root_identity().unwrap();
        let pid = "proj_work_exec_scope";

        let copy_req = WorkCopyRequest {
            workspace: "fix-1".into(),
            mode: WorkCopyMode::FromProject {
                paths: vec!["calc.py".into(), "tests".into()],
                exclude_generated: true,
            },
            overwrite_existing: false,
        };
        work_copy(
            &root,
            &rid,
            &state,
            pid,
            &copy_req,
            &make_scope(),
            auth_target_for("fix-1"),
            |_| Ok(()),
        )
        .unwrap();

        // Plant hidden files in workspace: must be silently absent from the discovered snapshot.
        let ws = root.join("_pro/work/fix-1");
        fs::write(ws.join(".env"), "API_KEY=dummy\n").unwrap();
        fs::write(ws.join("auth.json"), "{\"token\":\"dummy\"}\n").unwrap();
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(ws.join(".git/config.py"), "X = 1\n").unwrap();

        let scope = discover_work_python_scope(&root, &rid, &state, pid, "fix-1", None).unwrap();
        assert_eq!(scope.files, vec!["calc.py", "tests/__init__.py", "tests/test_calc.py"]);
        assert!(discover_work_python_scope(&root, &rid, &state, pid, "fix-1", Some("tests/test_calc.py")).is_ok());
        assert!(discover_work_python_scope(&root, &rid, &state, pid, "fix-1", Some("tests.test_calc.T.test_a")).is_ok());
        assert_eq!(
            discover_work_python_scope(&root, &rid, &state, pid, "fix-1", Some("tests/test_missing.py"))
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );

        // Missing manifest is refused.
        fs::create_dir_all(root.join("_pro/work/nomanifest/tests")).unwrap();
        fs::write(root.join("_pro/work/nomanifest/tests/__init__.py"), "").unwrap();
        fs::write(root.join("_pro/work/nomanifest/tests/test_a.py"), "").unwrap();
        assert_eq!(
            discover_work_python_scope(&root, &rid, &state, pid, "nomanifest", None).unwrap_err().code,
            ErrorCode::NotFound
        );

        // Hard link inside workspace is refused.
        let hl_path = ws.join("hardlinked.py");
        fs::hard_link(root.join("calc.py"), &hl_path).unwrap();
        assert_eq!(
            discover_work_python_scope(&root, &rid, &state, pid, "fix-1", None).unwrap_err().code,
            ErrorCode::UnsupportedPathType
        );
        fs::remove_file(&hl_path).unwrap();

        // Junction inside workspace is refused.
        #[cfg(windows)]
        {
            let inner_junc = ws.join("linked_dir");
            create_junction(&inner_junc, &outside);
            assert_eq!(
                discover_work_python_scope(&root, &rid, &state, pid, "fix-1", None).unwrap_err().code,
                ErrorCode::UnsupportedPathType
            );
            remove_junction(&inner_junc);

            // Junction at the workspace directory itself is refused.
            let junc_ws = root.join("_pro/work/juncws");
            let junc_manifest = WorkManifest {
                version: WORK_MANIFEST_VERSION,
                project_id: pid.into(),
                root_identity: rid.clone(),
                workspace: "juncws".into(),
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
                entries: BTreeMap::new(),
            };
            save_work_manifest(&state, &junc_manifest).unwrap();
            create_junction(&junc_ws, &outside);
            assert_eq!(
                discover_work_python_scope(&root, &rid, &state, pid, "juncws", None).unwrap_err().code,
                ErrorCode::UnsupportedPathType
            );
            remove_junction(&junc_ws);

            // Wrong letter case on disk for workspace directory is refused.
            let wrong_case_dir = root.join("_pro/work/WrongCase");
            fs::create_dir_all(wrong_case_dir.join("tests")).unwrap();
            fs::write(wrong_case_dir.join("tests/__init__.py"), "").unwrap();
            fs::write(wrong_case_dir.join("tests/test_a.py"), "").unwrap();
            let wrong_case_manifest = WorkManifest {
                version: WORK_MANIFEST_VERSION,
                project_id: pid.into(),
                root_identity: rid.clone(),
                workspace: "wrongcase".into(),
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
                entries: BTreeMap::new(),
            };
            save_work_manifest(&state, &wrong_case_manifest).unwrap();
            assert_eq!(
                discover_work_python_scope(&root, &rid, &state, pid, "wrongcase", None).unwrap_err().code,
                ErrorCode::BridgePolicyDenied
            );
        }

        // Limit 1: Per-file size > 256 KiB refused.
        let big_file = ws.join("too_big.py");
        fs::write(&big_file, vec![b'a'; (WORK_EXEC_MAX_FILE_BYTES as usize) + 1]).unwrap();
        assert_eq!(
            discover_work_python_scope(&root, &rid, &state, pid, "fix-1", None).unwrap_err().code,
            ErrorCode::ResourceBudgetExceeded
        );
        fs::remove_file(&big_file).unwrap();

        // Limit 2: Total snapshot bytes > 4 MiB refused (17 files * 250 KiB = 4.25 MiB, <= 128 files).
        let bulk_dir = ws.join("bulk_bytes");
        fs::create_dir_all(&bulk_dir).unwrap();
        let chunk_250k = vec![b'b'; 250 * 1024];
        for i in 0..17 {
            fs::write(bulk_dir.join(format!("m_{i:02}.py")), &chunk_250k).unwrap();
        }
        assert_eq!(
            discover_work_python_scope(&root, &rid, &state, pid, "fix-1", None).unwrap_err().code,
            ErrorCode::ResourceBudgetExceeded
        );
        fs::remove_dir_all(&bulk_dir).unwrap();

        // Limit 3: Snapshot file count > 128 refused (3 existing + 126 new = 129).
        let many_py = ws.join("many_py");
        fs::create_dir_all(&many_py).unwrap();
        for i in 0..126 {
            fs::write(many_py.join(format!("f_{i:03}.py")), "X = 1\n").unwrap();
        }
        assert_eq!(
            discover_work_python_scope(&root, &rid, &state, pid, "fix-1", None).unwrap_err().code,
            ErrorCode::ResourceBudgetExceeded
        );
        fs::remove_dir_all(&many_py).unwrap();

        // Limit 4: Discovery entry count > 1,000 refused (non-.py files still count as entries).
        let many_entries = ws.join("many_entries");
        fs::create_dir_all(&many_entries).unwrap();
        for i in 0..1_001 {
            fs::write(many_entries.join(format!("e_{i:04}.txt")), "x").unwrap();
        }
        assert_eq!(
            discover_work_python_scope(&root, &rid, &state, pid, "fix-1", None).unwrap_err().code,
            ErrorCode::ResourceBudgetExceeded
        );
        fs::remove_dir_all(&many_entries).unwrap();
    }
}
