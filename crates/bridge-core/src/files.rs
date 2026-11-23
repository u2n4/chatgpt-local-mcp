//! Root-bound, NTFS-identity-verified file service and recoverable hash-checked patch applier (§7).

use bridge_platform::{sha256_bytes, validate_relative_path};
use crate::policy::{has_windows_short_name, is_patch_stage_name, validate_remote_relative_path};
#[cfg(windows)]
use bridge_platform::windows::{atomic_replace_file, commit_patch_stage, create_patch_stage, file_identity_from_handle, file_identity_no_follow_named, file_path_from_handle, open_patch_directory, open_patch_preimage, open_read_no_follow, open_stable_read};
use bridge_types::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use similar::TextDiff;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Write};
#[cfg(windows)]
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const MAX_READ_FILE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_PAGE_BYTES: usize = 65_536;
/// Most entries one listing, search or manifest walk may read from disk before it is refused.
pub const MAX_WALK_ENTRIES: usize = 200_000;

fn within_walk_budget(seen: usize, what: &str) -> Result<(), BridgeError> {
    if seen < MAX_WALK_ENTRIES {
        return Ok(());
    }
    Err(BridgeError::new(
        ErrorCode::ResourceBudgetExceeded,
        format!("{what} has more than {MAX_WALK_ENTRIES} entries; use a narrower path."),
        OriginLayer::FileService,
    ))
}

/// One entry of a [`SortedWalk`].
struct Walked {
    path: PathBuf,
    file_type: fs::FileType,
}

/// Depth-first walk below `start` in file-name order, a directory before its content.
/// A `start` that is a regular file is returned as the only entry.
/// It never follows a link. Generated directories (when excluded) and secret paths are
/// skipped with everything below them. Every entry read from disk counts against
/// `MAX_WALK_ENTRIES` before it is kept, filtered or sorted, so a directory with more
/// entries than the budget is refused instead of held in memory.
struct SortedWalk<'a> {
    root: &'a Path,
    start: Option<PathBuf>,
    max_depth: usize,
    exclude_generated: bool,
    what: &'static str,
    seen: usize,
    stack: Vec<std::vec::IntoIter<Walked>>,
    remote_read: bool,
    #[cfg(windows)]
    remote_root: Option<&'a Path>,
}

impl<'a> SortedWalk<'a> {
    /// `root` is the project root that secret paths are judged against. Entries directly
    /// in `start` have depth 1; `max_depth` is the deepest level returned.
    fn new(root: &'a Path, start: &Path, max_depth: usize, exclude_generated: bool, what: &'static str) -> Self {
        Self {
            root,
            start: Some(start.to_path_buf()),
            max_depth,
            exclude_generated,
            what,
            seen: 0,
            stack: Vec::new(),
            remote_read: false,
            #[cfg(windows)]
            remote_root: None,
        }
    }

    fn read_sorted(&mut self, dir: &Path, _verify_directory: bool) -> Result<std::vec::IntoIter<Walked>, BridgeError> {
        let mut found = Vec::new();
        #[cfg(windows)]
        let _guard = if let Some(root) = self.remote_root.filter(|_| _verify_directory) {
            let relative = dir.strip_prefix(self.root).map_err(|_| unexpected_opened_name())?;
            let Ok(guard) = open_patch_directory(dir) else { return Ok(found.into_iter()) };
            let identity = file_identity_from_handle(&guard)?;
            if !identity.is_directory || identity.is_reparse_point
                || verify_opened_name(root, relative, &file_path_from_handle(&guard)?).is_err()
            {
                return Ok(found.into_iter());
            }
            Some(guard)
        } else {
            None
        };
        // A directory that cannot be read is skipped, as an unreadable entry is.
        let Ok(reader) = fs::read_dir(dir) else { return Ok(found.into_iter()) };
        for item in reader {
            if self.remote_read && item.as_ref().is_ok_and(|item| is_patch_stage_name(&item.file_name().to_string_lossy())) {
                continue;
            }
            within_walk_budget(self.seen, self.what)?;
            self.seen += 1;
            let Ok(item) = item else { continue };
            let Ok(file_type) = item.file_type() else { continue };
            found.push(Walked { path: item.path(), file_type });
        }
        found.sort_by(|a, b| a.path.file_name().cmp(&b.path.file_name()));
        Ok(found.into_iter())
    }

    fn skipped(&self, entry: &Walked) -> bool {
        if self.exclude_generated && entry.file_type.is_dir() {
            let name = entry.path.file_name().unwrap_or_default().to_string_lossy();
            if GENERATED_DIRS.iter().any(|g| g.eq_ignore_ascii_case(&name)) {
                return true;
            }
        }
        let Ok(rel) = entry.path.strip_prefix(self.root) else { return false };
        let parts: Vec<String> = rel.components().map(|c| c.as_os_str().to_string_lossy().to_string()).collect();
        if self.remote_read {
            is_hidden_from_remote(&parts) || has_windows_short_name(&parts)
        } else {
            is_denied_secret_path(&parts)
        }
    }

    fn step(&mut self) -> Result<Option<Walked>, BridgeError> {
        if let Some(start) = self.start.take() {
            if self.max_depth == 0 {
                return Ok(None);
            }
            // `symlink_metadata` does not follow a link, so a link is neither case below.
            match fs::symlink_metadata(&start) {
                Ok(meta) if meta.is_file() => {
                    within_walk_budget(self.seen, self.what)?;
                    self.seen += 1;
                    return Ok(Some(Walked { path: start, file_type: meta.file_type() }));
                }
                _ => {
                    let level = self.read_sorted(&start, false)?;
                    self.stack.push(level);
                }
            }
        }
        loop {
            let Some(level) = self.stack.last_mut() else { return Ok(None) };
            let Some(entry) = level.next() else {
                self.stack.pop();
                continue;
            };
            if self.skipped(&entry) {
                continue;
            }
            // `is_dir` is false for a link or junction, so the walk stays inside the tree.
            if entry.file_type.is_dir() && self.stack.len() < self.max_depth {
                let level = self.read_sorted(&entry.path, true)?;
                self.stack.push(level);
            }
            return Ok(Some(entry));
        }
    }
}

impl Iterator for SortedWalk<'_> {
    type Item = Result<Walked, BridgeError>;

    fn next(&mut self) -> Option<Self::Item> {
        let step = self.step();
        if step.is_err() {
            self.stack.clear();
        }
        step.transpose()
    }
}

/// Larger files are skipped by `search`.
pub const MAX_SEARCH_FILE_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_BATCH_ITEMS: usize = 32;
pub const MAX_READ_LINES: usize = 2_000;
pub const MAX_SEARCH_CONTEXT_LINES: usize = 5;
pub const MAX_FILE_GLOB_BYTES: usize = 64;
const SEARCH_REGEX_SIZE_LIMIT: usize = 256 * 1024;

pub(crate) const GENERATED_DIRS: &[&str] = &[
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "target",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".next",
    ".nuxt",
    "dist",
    "build",
    ".edge-project-bridge",
    ".edge-bridge-journal",
];

/// Deny known secret/credential filenames and extensions (matched case-insensitively).
/// One page of `text` counted in characters: the slice, its first and one-past-last
/// character index, and whether text remains after it. An offset past the end gives
/// an empty page at the end. The text is walked by character boundaries and is never
/// expanded into a per-character buffer, so a small page of a large file stays small.
pub fn char_page(text: &str, offset: usize, limit: usize) -> (&str, usize, usize, bool) {
    let (start, start_byte) = match text.char_indices().nth(offset) {
        Some((byte, _)) => (offset, byte),
        None => (text.chars().count(), text.len()),
    };
    let rest = &text[start_byte..];
    let (page_chars, page_bytes) = match rest.char_indices().nth(limit) {
        Some((byte, _)) => (limit, byte),
        None => (rest.chars().count(), rest.len()),
    };
    (&rest[..page_bytes], start, start + page_chars, page_bytes < rest.len())
}

fn validate_file_glob(glob: &str) -> Result<(), BridgeError> {
    if glob.is_empty()
        || glob.len() > MAX_FILE_GLOB_BYTES
        || !glob.is_ascii()
        || glob.bytes().any(|b| b < 0x20 || b == 0x7f)
        || glob.contains(['/', '\\', ':'])
        || glob.contains("..")
    {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "file_glob must be 1..=64 printable ASCII characters without '/', '\\', ':' or '..'.",
            OriginLayer::Validation,
        ));
    }
    Ok(())
}

fn matches_file_glob(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = name.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;
    while ti < txt.len() {
        if pi < pat.len() && (pat[pi] == '?' || pat[pi].eq_ignore_ascii_case(&txt[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == '*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

/// Folders and files that hold credentials or tool state whatever the project is, which a
/// remote principal may neither see nor write. The owner keeps access to them, so patches and
/// journal recovery that touch them still work. Keep this list and
/// `git::SECRET_NAME_PATTERNS` together.
const REMOTE_HIDDEN_NAMES: &[&str] = &[
    ".git", ".hg", ".svn", ".ssh", ".aws", ".azure", ".gnupg", ".kube", ".codex", ".claude", ".agents",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".terraform", ".htpasswd", ".pgpass", ".my.cnf",
    "id_dsa", "id_ecdsa_sk", "id_ed25519_sk", "kubeconfig",
    "auth.json", "auth.yaml", "auth.yml", "auth.toml", "api-token", "api-unit-token",
    "cookies-journal", "login data-journal", "login data for account", "login data for account-journal",
    "trust tokens-journal", "web data-journal", "account web data", "account web data-journal",
    ".edge-project-bridge", ".edge-bridge-journal",
];

/// Prefix of the files the legacy Python file service stages beside a patch target.
const LEGACY_STAGE_PREFIX: &str = ".edge-bridge-tmp-";

/// What a remote principal may not see or write: every secret path, and the names in
/// [`REMOTE_HIDDEN_NAMES`], key stores, and leftover staging files.
pub fn is_hidden_from_remote(rel_parts: &[String]) -> bool {
    is_denied_secret_path(rel_parts) || rel_parts.iter().any(|part| {
        let low = part.to_ascii_lowercase();
        REMOTE_HIDDEN_NAMES.contains(&low.as_str()) || low.ends_with(".jks") || low.ends_with(".keystore")
            || low.starts_with(LEGACY_STAGE_PREFIX)
    })
}

pub fn is_denied_secret_path(rel_parts: &[String]) -> bool {
    for part in rel_parts {
        let low = part.to_ascii_lowercase();
        if low == ".env"
            || low.starts_with(".env.")
            || low.ends_with(".env")
            || low == "cookies"
            || low == "login data"
            || low == "trust tokens"
            || low == "web data"
            || low == ".install-token"
            || low == "id_rsa"
            || low == "id_ed25519"
            || low == "id_ecdsa"
            || low == "owner.token"
            || low == "edge.token"
            || low == "tunnel-runtime.key"
            || low == "ipc-key.pem"
            || low.starts_with("secrets.")
            || low.starts_with("credentials.")
            || low.ends_with(".pem")
            || low.ends_with(".key")
            || low.ends_with(".pfx")
            || low.ends_with(".p12")
            || low.ends_with(".kdbx")
            || low.ends_with(".ppk")
            || low.ends_with(".ovpn")
            || low.ends_with(".token")
            || low.ends_with(".secret")
            || low.ends_with(".sqlite3")
        {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub kind: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReadResult {
    pub path: String,
    pub content: String,
    pub size: u64,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub truncated: bool,
    pub lossy_utf8: bool,
    pub has_utf8_bom: bool,
    pub line_ending: String,
    /// Full-file SHA-256 across complete bytes on disk (NEVER just the returned slice).
    pub hash: String,
    /// SHA-256 of the returned page slice only.
    pub page_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_lines: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchReadItemRequest {
    pub path: String,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_batch_limit")]
    pub limit: usize,
    #[serde(default)]
    pub lossy_utf8: bool,
    #[serde(default)]
    pub start_line: Option<usize>,
    #[serde(default)]
    pub end_line: Option<usize>,
}

fn default_batch_limit() -> usize {
    32_768
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchReadItemResult {
    pub path: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<FileReadResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<StructuredError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub path: String,
    pub line: usize,
    pub preview: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_before: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_after: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectManifest {
    pub file_count: usize,
    pub total_bytes: u64,
    pub manifest_sha256: String,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchJournalFileStep {
    pub path: String,
    pub expected_preimage: Option<String>,
    pub actual_preimage: Option<String>,
    pub backup_rel_path: Option<String>,
    pub postimage_sha256: String,
    pub committed: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchJournal {
    pub journal_id: String,
    pub project_id: String,
    #[serde(default)]
    pub root_identity: Option<String>,
    pub operation_id: String,
    pub state: String,
    pub plan_sha256: String,
    pub created_at: String,
    pub steps: Vec<PatchJournalFileStep>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stage_cleanup_failed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directory_cleanup_failed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchApplyResult {
    pub journal_id: String,
    pub operation_id: String,
    pub files_applied: Vec<String>,
    pub postimage_hashes: BTreeMap<String, String>,
    pub unified_diff: String,
    pub diff_sha256: String,
}

pub struct ScopedFiles {
    root: PathBuf,
    expected_root_identity: Option<String>,
    remote_read: bool,
    #[cfg(windows)]
    remote_root: Option<(File, PathBuf)>,
}

pub const DELEGATED_WRITE_MAX_SCOPE_FILES: usize = 2_000;
pub const DELEGATED_WRITE_MAX_SCOPE_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const DELEGATED_WRITE_MAX_WALK_ENTRIES: usize = 8_192;
const DELEGATED_CREATE_ONLY_NEXT_ACTION: &str =
    "Choose a new file name inside the granted writable path; delegated writes are create-only and cannot overwrite existing files.";

struct DelegatedPatch<'a> {
    scope: &'a [String],
    authorize_commit: &'a dyn Fn(&str) -> Result<(), BridgeError>,
    remove_stage: fn(&Path) -> std::io::Result<()>,
}

#[cfg(windows)]
pub(crate) struct PatchParent {
    pub(crate) directories: Vec<File>,
    pub(crate) root_path: PathBuf,
    pub(crate) path: PathBuf,
}

#[cfg(windows)]
impl PatchParent {
    pub(crate) fn pin(
        root: &Path,
        root_identity: &str,
        path: &str,
        delegated: bool,
        create_missing: bool,
        mut created: Option<&mut Vec<PathBuf>>,
    ) -> Result<Self, BridgeError> {
        let parts = validate_relative_path(path)?;
        let Some((_, parents)) = parts.split_last() else {
            return Err(patch_commit_conflict(path));
        };
        let root = open_patch_directory(root).map_err(patch_io_error)?;
        let identity = file_identity_from_handle(&root)?;
        if !identity.is_directory || identity.is_reparse_point || identity.canonical_id() != root_identity {
            return Err(patch_commit_conflict(path));
        }
        let root_path = file_path_from_handle(&root)?;
        let mut current = root_path.clone();
        let mut directories = vec![root];
        for segment in parents {
            let requested = current.join(segment);
            let exists = match fs::symlink_metadata(&requested) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(patch_io_error(error)),
            };
            if !exists {
                if !create_missing {
                    break;
                }
                match fs::create_dir(&requested) {
                    Ok(()) => {
                        if let Some(created) = created.as_deref_mut() {
                            created.push(requested.strip_prefix(&root_path).unwrap().to_owned());
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(patch_io_error(error)),
                }
            }
            let pinned = open_patch_directory(&requested).map_err(patch_io_error)?;
            let identity = file_identity_from_handle(&pinned)?;
            let observed = file_path_from_handle(&pinned)?;
            if !identity.is_directory || identity.is_reparse_point {
                return Err(BridgeError::new(
                    ErrorCode::UnsupportedPathType,
                    format!("Reparse point or non-directory denied while pinning parent of '{path}'."),
                    OriginLayer::FileService,
                ));
            }
            if observed.parent() != Some(current.as_path()) {
                return Err(patch_commit_conflict(path));
            }
            if delegated {
                verify_delegated_parent_name(&root_path, &requested, &observed)?;
            }
            current = observed;
            directories.push(pinned);
        }
        Ok(Self { directories, root_path, path: current })
    }

    /// Pin an existing directory and every ancestor up to `root`, verifying non-reparse directory
    /// identity and exact on-disk casing at every hop. Returns `Ok(None)` if any segment along
    /// `dir_rel` does not exist on disk (after validating all existing prefix segments).
    pub(crate) fn pin_dir_existing(
        root: &Path,
        root_identity: &str,
        dir_rel: &str,
        delegated: bool,
    ) -> Result<Option<Self>, BridgeError> {
        let parts = validate_relative_path(dir_rel)?;
        let root_handle = open_patch_directory(root).map_err(patch_io_error)?;
        let identity = file_identity_from_handle(&root_handle)?;
        if !identity.is_directory || identity.is_reparse_point || identity.canonical_id() != root_identity {
            return Err(patch_commit_conflict(dir_rel));
        }
        let root_path = file_path_from_handle(&root_handle)?;
        let mut current = root_path.clone();
        let mut directories = vec![root_handle];
        for segment in &parts {
            let requested = current.join(segment);
            match fs::symlink_metadata(&requested) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(patch_io_error(error)),
            }
            let pinned = open_patch_directory(&requested).map_err(patch_io_error)?;
            let identity = file_identity_from_handle(&pinned)?;
            let observed = file_path_from_handle(&pinned)?;
            if !identity.is_directory || identity.is_reparse_point {
                return Err(BridgeError::new(
                    ErrorCode::UnsupportedPathType,
                    format!("Reparse point or non-directory denied at '{dir_rel}'."),
                    OriginLayer::FileService,
                ));
            }
            if observed.parent() != Some(current.as_path()) {
                return Err(patch_commit_conflict(dir_rel));
            }
            if delegated {
                verify_delegated_parent_name(&root_path, &requested, &observed)?;
            }
            current = observed;
            directories.push(pinned);
        }
        Ok(Some(Self { directories, root_path, path: current }))
    }

    pub(crate) fn verify_location(&self, relative: &str) -> Result<(), BridgeError> {
        if file_path_from_handle(&self.directories[0])? != self.root_path
            || file_path_from_handle(self.directories.last().unwrap())? != self.path {
            return Err(patch_commit_conflict(relative));
        }
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn unexpected_opened_name() -> BridgeError {
    BridgeError::new(
        ErrorCode::BridgePolicyDenied,
        "Opened path has a different or protected name. Use its exact long name.",
        OriginLayer::FileService,
    )
    .with_next_action(
        "Use the exact on-disk long path name; protected or mismatched paths cannot be accessed remotely.",
    )
}

#[cfg(windows)]
pub(crate) fn verify_opened_name(root: &Path, requested_relative: &Path, observed: &Path) -> Result<(), BridgeError> {
    let relative = observed.strip_prefix(root).map_err(|_| unexpected_opened_name())?;
    let parts = relative.components().map(|part| {
        part.as_os_str().to_str().map(str::to_owned).ok_or_else(unexpected_opened_name)
    }).collect::<Result<Vec<_>, _>>()?;
    if is_hidden_from_remote(&parts) || !relative.components().eq(requested_relative.components()) {
        return Err(unexpected_opened_name());
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn verify_delegated_parent_name(root: &Path, requested: &Path, observed: &Path) -> Result<(), BridgeError> {
    let relative = requested.strip_prefix(root).map_err(|_| unexpected_opened_name())?;
    verify_opened_name(root, relative, observed)
}

#[cfg(windows)]
pub(crate) fn verify_remote_file(root: &Path, relative: &Path, file: &File, identity: &bridge_platform::FileIdentity) -> Result<(), BridgeError> {
    if identity.is_directory || identity.is_reparse_point || identity.n_links != 1 {
        return Err(unexpected_opened_name());
    }
    verify_opened_name(root, relative, &file_path_from_handle(file)?)
}

struct DelegatedStage {
    file: Option<File>,
    #[cfg(windows)]
    parent: PatchParent,
    destination: PathBuf,
    temp: PathBuf,
    committed: bool,
    temp_exists: bool,
}

impl DelegatedStage {
    fn create(
        root: &Path,
        root_id: &str,
        relative: &str,
        destination: &Path,
        temp_name: &str,
        created_dirs: &mut Vec<PathBuf>,
    ) -> Result<Self, BridgeError> {
        #[cfg(windows)]
        let parent = PatchParent::pin(root, root_id, relative, true, true, Some(created_dirs))?;
        #[cfg(windows)]
        let destination = parent.path.join(destination.file_name().ok_or_else(|| patch_commit_conflict(relative))?);
        #[cfg(not(windows))]
        let destination = {
            let _ = root_id;
            let parts = validate_relative_path(relative)?;
            let mut dir = PathBuf::new();
            for name in &parts[..parts.len() - 1] {
                dir.push(name);
                if root.join(&dir).try_exists().map_err(patch_io_error)? {
                    continue;
                }
                match fs::create_dir(root.join(&dir)) {
                    Ok(()) => created_dirs.push(dir.clone()),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(patch_io_error(error)),
                }
            }
            destination.to_owned()
        };
        let temp = destination.with_file_name(temp_name);
        #[cfg(windows)]
        let file = create_patch_stage(&temp).map_err(patch_io_error)?;
        #[cfg(not(windows))]
        let file = OpenOptions::new().write(true).create_new(true).open(&temp).map_err(patch_io_error)?;
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

    fn write(&mut self, _relative: &str, bytes: &[u8]) -> Result<(), BridgeError> {
        let file = self.file.as_mut().unwrap();
        #[cfg(windows)]
        if file_path_from_handle(file)?.parent() != Some(self.parent.path.as_path()) {
            return Err(patch_commit_conflict(_relative));
        }
        file.write_all(bytes).map_err(patch_io_error)?;
        file.sync_all().map_err(patch_io_error)
    }

    fn commit(&mut self, relative: &str, authorize: &dyn Fn(&str) -> Result<(), BridgeError>) -> Result<(), BridgeError> {
        #[cfg(windows)]
        self.parent.verify_location(relative)?;
        authorize(relative)?;
        #[cfg(windows)]
        commit_patch_stage(self.file.as_ref().unwrap(), self.parent.directories.last().unwrap(), self.destination.file_name().unwrap(), false)
            .map_err(|error| {
                if error.code == ErrorCode::VersionConflict {
                    error.with_next_action(DELEGATED_CREATE_ONLY_NEXT_ACTION)
                } else {
                    error
                }
            })?;
        #[cfg(not(windows))]
        fs::hard_link(&self.temp, &self.destination).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                BridgeError::new(
                    ErrorCode::VersionConflict,
                    format!("Create-only edit rejected because '{relative}' already exists."),
                    OriginLayer::FileService,
                )
                .with_next_action(DELEGATED_CREATE_ONLY_NEXT_ACTION)
            } else {
                patch_io_error(error)
            }
        })?;
        self.committed = true;
        Ok(())
    }

    fn verify_postimage(&mut self, relative: &str, size: usize, expected: &str) -> Result<(), BridgeError> {
        #[cfg(windows)]
        let written = {
            let file = self.file.as_mut().unwrap();
            let identity = file_identity_from_handle(file)?;
            if identity.size_bytes != size as u64
                || file_path_from_handle(file)?.as_os_str() != self.destination.as_os_str()
            {
                return Err(patch_commit_conflict(relative));
            }
            file.seek(SeekFrom::Start(0)).map_err(patch_io_error)?;
            let mut written = Vec::with_capacity(size);
            file.take(size as u64 + 1).read_to_end(&mut written).map_err(patch_io_error)?;
            written
        };
        #[cfg(not(windows))]
        let (written, _) = read_handle_verified(&self.destination, relative)?;
        if written.len() != size || sha256_bytes(&written) != expected {
            return Err(BridgeError::new(
                ErrorCode::StalePrecondition,
                format!("Postimage verification failed for '{relative}'."),
                OriginLayer::FileService,
            ));
        }
        Ok(())
    }

    fn undo_commit(&mut self) -> Result<(), BridgeError> {
        #[cfg(windows)]
        commit_patch_stage(self.file.as_ref().unwrap(), self.parent.directories.last().unwrap(), self.temp.file_name().unwrap(), false)?;
        #[cfg(not(windows))]
        fs::remove_file(&self.destination).map_err(patch_io_error)?;
        self.committed = false;
        Ok(())
    }

    fn close(&mut self, remove_stage: fn(&Path) -> std::io::Result<()>) -> Result<(), BridgeError> {
        self.file.take();
        if self.temp_exists && !(cfg!(windows) && self.committed) {
            match remove_stage(&self.temp) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(patch_io_error(error)),
            }
        }
        self.temp_exists = false;
        Ok(())
    }
}

pub(crate) fn is_quota_link(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    meta.file_type().is_symlink()
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DelegatedQuotaUsage {
    pub files: usize,
    pub bytes: u64,
    pub walk_entries: usize,
}

pub(crate) fn measure_delegated_folder_quota(root: &Path, folder: &str) -> Result<DelegatedQuotaUsage, BridgeError> {
    let start = root.join(folder);
    let mut usage = DelegatedQuotaUsage::default();
    let mut pending = vec![start.clone()];
    while let Some(directory) = pending.pop() {
        let meta = match fs::symlink_metadata(&directory) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && directory == start => continue,
            Err(error) => return Err(patch_io_error(error)),
        };
        if is_quota_link(&meta) || !meta.is_dir() {
            continue;
        }
        let entries = fs::read_dir(&directory).map_err(patch_io_error)?;
        for entry in entries {
            let entry = entry.map_err(patch_io_error)?;
            usage.walk_entries += 1;
            if usage.walk_entries > DELEGATED_WRITE_MAX_WALK_ENTRIES {
                return Err(BridgeError::new(
                    ErrorCode::ResourceBudgetExceeded,
                    "Delegated write quota or scan limit exceeded. Ask the owner to clear old files and empty directories from the granted folder.",
                    OriginLayer::FileService,
                ));
            }
            let meta = fs::symlink_metadata(entry.path()).map_err(patch_io_error)?;
            if meta.is_dir() && !is_quota_link(&meta) {
                pending.push(entry.path());
            } else {
                usage.files += 1;
                usage.bytes = usage.bytes.saturating_add(meta.len());
            }
        }
    }
    Ok(usage)
}

pub(crate) fn check_delegated_write_quota(
    root: &Path,
    folders: BTreeMap<&str, (usize, u64)>,
    missing_dirs: &BTreeSet<PathBuf>,
) -> Result<(), BridgeError> {
    let quota_exceeded = || BridgeError::new(
        ErrorCode::ResourceBudgetExceeded,
        "Delegated write quota or scan limit exceeded. Ask the owner to clear old files and empty directories from the granted folder.",
        OriginLayer::FileService,
    );
    let exceeds_quota = |files, bytes| files > DELEGATED_WRITE_MAX_SCOPE_FILES || bytes > DELEGATED_WRITE_MAX_SCOPE_BYTES;
    let mut visited = 0;
    for (folder, (mut files, mut bytes)) in folders {
        if exceeds_quota(files, bytes) {
            return Err(quota_exceeded());
        }
        let start = root.join(folder);
        // The scan counts children of the quota root. A new quota root itself is outside that count.
        visited += files + missing_dirs.iter().filter(|dir| dir.starts_with(&start) && **dir != start).count();
        if visited > DELEGATED_WRITE_MAX_WALK_ENTRIES {
            return Err(quota_exceeded());
        }
        let mut pending = vec![start.clone()];
        while let Some(directory) = pending.pop() {
            let meta = match fs::symlink_metadata(&directory) {
                Ok(meta) => meta,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && directory == start => continue,
                Err(error) => return Err(patch_io_error(error)),
            };
            if is_quota_link(&meta) {
                continue;
            }
            let entries = fs::read_dir(&directory).map_err(patch_io_error)?;
            for entry in entries {
                let entry = entry.map_err(patch_io_error)?;
                visited += 1;
                if visited > DELEGATED_WRITE_MAX_WALK_ENTRIES {
                    return Err(quota_exceeded());
                }
                let meta = entry.metadata().map_err(patch_io_error)?;
                if meta.is_dir() && !is_quota_link(&meta) {
                    pending.push(entry.path());
                } else {
                    files += 1;
                    bytes = bytes.saturating_add(meta.len());
                    if exceeds_quota(files, bytes) {
                        return Err(quota_exceeded());
                    }
                }
            }
        }
    }
    Ok(())
}

impl ScopedFiles {
    pub fn new(root: impl AsRef<Path>, expected_root_identity: Option<String>) -> Result<Self, BridgeError> {
        Self::open_scope(root.as_ref(), expected_root_identity, false)
    }

    pub fn new_remote_read(root: impl AsRef<Path>, expected_root_identity: Option<String>) -> Result<Self, BridgeError> {
        Self::open_scope(root.as_ref(), expected_root_identity, true)
    }

    fn open_scope(root: &Path, expected_root_identity: Option<String>, remote_read: bool) -> Result<Self, BridgeError> {
        let root_path = root.to_path_buf();
        if !root_path.is_absolute() || !root_path.is_dir() {
            return Err(BridgeError::new(
                ErrorCode::PathOutsideRoot,
                "Project root must be an existing absolute directory.",
                OriginLayer::FileService,
            ));
        }
        #[cfg(windows)]
        let remote_root = {
            let guard = if remote_read {
                Some(open_patch_directory(&root_path).map_err(|error| BridgeError::new(
                    ErrorCode::FileNotFound,
                    format!("Cannot open the project directory '.': {error}"),
                    OriginLayer::FileService,
                ))?)
            } else {
                None
            };
            let id = if let Some(file) = &guard {
                file_identity_from_handle(file)?
            } else {
                file_identity_no_follow_named(&root_path, ".")?
            };
            if id.is_reparse_point || !id.is_directory {
                return Err(BridgeError::new(
                    ErrorCode::UnsupportedPathType,
                    "Project root cannot be a Windows reparse point/junction.",
                    OriginLayer::FileService,
                ));
            }
            if let Some(ref exp) = expected_root_identity {
                if !exp.is_empty() && exp.starts_with("ntfs:") && id.canonical_id() != *exp {
                    return Err(BridgeError::new(
                        ErrorCode::StalePrecondition,
                        "Project root NTFS identity changed since registration.",
                        OriginLayer::FileService,
                    ));
                }
            }
            guard.map(|file| file_path_from_handle(&file).map(|path| (file, path))).transpose()?
        };
        Ok(Self {
            root: root_path,
            expected_root_identity,
            remote_read,
            #[cfg(windows)]
            remote_root,
        })
    }

    pub fn current_root_identity(&self) -> Result<String, BridgeError> {
        #[cfg(windows)]
        {
            let identity = file_identity_no_follow_named(&self.root, ".")?;
            if !identity.is_directory || identity.is_reparse_point {
                return Err(BridgeError::new(
                    ErrorCode::UnsupportedPathType,
                    "Project root is no longer a regular directory.",
                    OriginLayer::FileService,
                ));
            }
            Ok(identity.canonical_id())
        }
        #[cfg(not(windows))]
        {
            Ok(format!("posix:{}", self.root.display()))
        }
    }

    /// Resolve relative path component-by-component, rejecting reparse points/junctions at every hop.
    fn resolve_checked(&self, raw_rel: &str, must_exist: bool) -> Result<(String, PathBuf), BridgeError> {
        let parts = if self.remote_read {
            validate_remote_relative_path(raw_rel)?
        } else {
            validate_relative_path(raw_rel)?
        };
        if if self.remote_read { is_hidden_from_remote(&parts) } else { is_denied_secret_path(&parts) } {
            let mut err = BridgeError::new(
                ErrorCode::BridgePolicyDenied,
                "Access to protected secret/credential path is denied.",
                OriginLayer::FileService,
            );
            if self.remote_read {
                err = err.with_next_action(
                    "Protected secret and credential paths cannot be accessed remotely even with a grant; choose a non-protected project path.",
                );
            }
            return Err(err);
        }
        #[cfg(windows)]
        if let Some(ref exp) = self.expected_root_identity {
            let cur = if let Some((guard, _)) = &self.remote_root {
                file_identity_from_handle(guard)?
            } else {
                file_identity_no_follow_named(&self.root, ".")?
            };
            if cur.is_reparse_point {
                return Err(BridgeError::new(
                    ErrorCode::UnsupportedPathType,
                    "Project root became a reparse point.",
                    OriginLayer::FileService,
                ));
            }
            if exp.starts_with("ntfs:") && cur.canonical_id() != *exp {
                return Err(BridgeError::new(
                    ErrorCode::StalePrecondition,
                    "Project root identity mismatch.",
                    OriginLayer::FileService,
                ));
            }
        }

        let mut cur = self.root.clone();
        for (idx, seg) in parts.iter().enumerate() {
            cur.push(seg);
            let is_last = idx + 1 == parts.len();
            if cur.exists() || cur.symlink_metadata().is_ok() {
                #[cfg(windows)]
                {
                    let id = file_identity_no_follow_named(&cur, raw_rel)?;
                    if id.is_reparse_point {
                        return Err(BridgeError::new(
                            ErrorCode::UnsupportedPathType,
                            format!("Reparse point / junction denied at segment '{seg}'."),
                            OriginLayer::FileService,
                        ));
                    }
                    if !is_last && !id.is_directory {
                        return Err(BridgeError::new(
                            ErrorCode::UnsupportedPathType,
                            "Intermediate path component is not a directory.",
                            OriginLayer::FileService,
                        ));
                    }
                }
                #[cfg(not(windows))]
                {
                    if let Ok(meta) = fs::symlink_metadata(&cur) {
                        if meta.file_type().is_symlink() {
                            return Err(BridgeError::new(
                                ErrorCode::UnsupportedPathType,
                                "Symlink traversal is denied.",
                                OriginLayer::FileService,
                            ));
                        }
                    }
                }
            } else if must_exist {
                return Err(BridgeError::new(
                    ErrorCode::FileNotFound,
                    format!("File or directory not found: {raw_rel}"),
                    OriginLayer::FileService,
                ));
            }
        }
        let canonical_rel = if parts.is_empty() {
            ".".to_string()
        } else {
            parts.join("/")
        };
        Ok((canonical_rel, cur))
    }

    pub(crate) fn verify_artifact_digest(&self, relative: &str, size: u64, expected_hash: &str) -> Result<bool, BridgeError> {
        let root_identity = self.current_root_identity()?;
        let canonical_root = fs::canonicalize(&self.root).map_err(artifact_io_error)?;
        let (_, path) = self.resolve_checked(relative, true)?;
        #[cfg(windows)]
        let file = {
            let expected = file_identity_no_follow_named(&path, relative)?;
            if expected.is_reparse_point || expected.is_directory || expected.n_links != 1 {
                return Err(unsafe_artifact());
            }
            let file = open_stable_read(&path).map_err(artifact_io_error)?;
            let opened = file_identity_from_handle(&file)?;
            if opened.canonical_id() != expected.canonical_id() || opened.is_directory
                || opened.is_reparse_point || opened.n_links != 1
                || file_identity_no_follow_named(&canonical_root, ".")?.canonical_id() != root_identity
                || self.current_root_identity()? != root_identity
                || !file_path_from_handle(&file)?.starts_with(&canonical_root) {
                return Err(unsafe_artifact());
            }
            file
        };
        #[cfg(not(windows))]
        let file = {
            let observed = fs::symlink_metadata(&path).map_err(artifact_io_error)?;
            if !observed.is_file() || !fs::canonicalize(&path).map_err(artifact_io_error)?.starts_with(&canonical_root)
                || self.current_root_identity()? != root_identity {
                return Err(unsafe_artifact());
            }
            let file = File::open(&path).map_err(artifact_io_error)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let opened = file.metadata().map_err(artifact_io_error)?;
                if observed.dev() != opened.dev() || observed.ino() != opened.ino() || opened.nlink() != 1 {
                    return Err(unsafe_artifact());
                }
            }
            file
        };
        let metadata = file.metadata().map_err(artifact_io_error)?;
        if !metadata.is_file() {
            return Err(unsafe_artifact());
        }
        if metadata.len() != size {
            return Ok(false);
        }

        let mut digest = Sha256::new();
        let mut count = 0u64;
        let mut limited = file.take(size.saturating_add(1));
        let mut buffer = [0u8; 32 * 1024];
        loop {
            let n = limited.read(&mut buffer).map_err(artifact_io_error)?;
            if n == 0 {
                break;
            }
            count += n as u64;
            digest.update(&buffer[..n]);
        }
        Ok(count == size && hex::encode(digest.finalize()).eq_ignore_ascii_case(expected_hash))
    }

    fn walk(&self, start: &Path, depth: usize, exclude_generated: bool, what: &'static str) -> SortedWalk<'_> {
        let mut walk = SortedWalk::new(&self.root, start, depth, exclude_generated, what);
        walk.remote_read = self.remote_read;
        #[cfg(windows)]
        {
            walk.remote_root = self.remote_root.as_ref().map(|(_, root)| root.as_path());
        }
        walk
    }

    #[cfg(windows)]
    fn pin_read_start(&self, path: &Path, relative: &str) -> Result<Option<File>, BridgeError> {
        let Some((_, root)) = &self.remote_root else { return Ok(None) };
        let guard = open_patch_directory(path).map_err(|error| BridgeError::new(
            ErrorCode::FileNotFound,
            format!("Cannot open '{relative}': {error}"),
            OriginLayer::FileService,
        ))?;
        let identity = file_identity_from_handle(&guard)?;
        if identity.is_reparse_point || (!identity.is_directory && identity.n_links != 1) {
            return Err(unexpected_opened_name());
        }
        let requested = if relative == "." { Path::new("") } else { Path::new(relative) };
        verify_opened_name(root, requested, &file_path_from_handle(&guard)?)?;
        Ok(Some(guard))
    }

    fn open_walked_file(&self, path: &Path, _relative: &Path) -> Option<File> {
        #[cfg(windows)]
        if let Some((_, root)) = &self.remote_root {
            let file = open_read_no_follow(path).ok()?;
            let identity = file_identity_from_handle(&file).ok()?;
            verify_remote_file(root, _relative, &file, &identity).ok()?;
            return Some(file);
        }
        File::open(path).ok()
    }

    pub fn list(
        &self,
        rel: &str,
        recursive: bool,
        max_depth: usize,
        exclude_generated: bool,
        cursor: usize,
        limit: usize,
    ) -> Result<(Vec<FileEntry>, Option<usize>), BridgeError> {
        self.list_with_max_limit(rel, recursive, max_depth, exclude_generated, cursor, limit, 100)
    }

    pub fn list_with_max_limit(
        &self,
        rel: &str,
        recursive: bool,
        max_depth: usize,
        exclude_generated: bool,
        cursor: usize,
        limit: usize,
        max_limit: usize,
    ) -> Result<(Vec<FileEntry>, Option<usize>), BridgeError> {
        let (_, dir_path) = self.resolve_checked(rel, true)?;
        #[cfg(windows)]
        let _guard = self.pin_read_start(&dir_path, rel)?;
        if !dir_path.is_dir() {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                "Target path for file_list must be a directory.",
                OriginLayer::FileService,
            ));
        }
        let depth = if recursive { max_depth.clamp(1, 8) } else { 1 };
        let mut items = Vec::new();
        for entry in self.walk(&dir_path, depth, exclude_generated, "The listed directory") {
            let ent = entry?;
            let Ok(rel_p) = ent.path.strip_prefix(&self.root) else { continue };
            let rel_posix = rel_p.to_string_lossy().replace('\\', "/");
            #[cfg(windows)]
            let remote_identity = if let Some((_, root)) = &self.remote_root {
                let Ok(handle) = bridge_platform::windows::open_path_metadata_no_follow(&ent.path) else { continue };
                let Ok(id) = file_identity_from_handle(&handle) else { continue };
                let Ok(observed) = file_path_from_handle(&handle) else { continue };
                if id.is_reparse_point || id.is_directory != ent.file_type.is_dir()
                    || (!id.is_directory && id.n_links != 1)
                    || verify_opened_name(root, rel_p, &observed).is_err()
                {
                    continue;
                }
                Some(id)
            } else {
                if file_identity_no_follow_named(&ent.path, &rel_posix).is_ok_and(|id| id.is_reparse_point) {
                    continue;
                }
                None
            };
            let kind = if ent.file_type.is_dir() { "dir" } else { "file" };
            let size = || fs::symlink_metadata(&ent.path).map(|m| if m.is_file() { m.len() } else { 0 }).unwrap_or(0);
            #[cfg(windows)]
            let size = remote_identity.map_or_else(size, |id| if id.is_directory { 0 } else { id.size_bytes });
            #[cfg(not(windows))]
            let size = size();
            items.push(FileEntry {
                path: rel_posix,
                kind: kind.to_string(),
                size,
            });
        }
        let cap = limit.clamp(1, max_limit.max(1));
        let total = items.len();
        let slice: Vec<FileEntry> = items.into_iter().skip(cursor).take(cap).collect();
        let next = if cursor + slice.len() < total {
            Some(cursor + slice.len())
        } else {
            None
        };
        Ok((slice, next))
    }

    pub fn read(
        &self,
        rel: &str,
        offset: usize,
        limit: usize,
        lossy_utf8: bool,
    ) -> Result<FileReadResult, BridgeError> {
        self.read_with_options(rel, offset, limit, lossy_utf8, None, None)
    }

    pub fn read_with_options(
        &self,
        rel: &str,
        offset: usize,
        limit: usize,
        lossy_utf8: bool,
        start_line: Option<usize>,
        end_line: Option<usize>,
    ) -> Result<FileReadResult, BridgeError> {
        let line_range = match (start_line, end_line) {
            (None, None) => None,
            (s, e) => {
                if offset > 0 {
                    return Err(BridgeError::new(
                        ErrorCode::InvalidArgument,
                        "Cannot combine 'offset' > 0 with 'start_line' or 'end_line'.",
                        OriginLayer::Validation,
                    ));
                }
                if s == Some(0) || e == Some(0) {
                    return Err(BridgeError::new(
                        ErrorCode::InvalidArgument,
                        "Line numbers are 1-based; 'start_line' and 'end_line' must be >= 1.",
                        OriginLayer::Validation,
                    ));
                }
                let start = s.unwrap_or(1);
                if let Some(end) = e {
                    if end < start {
                        return Err(BridgeError::new(
                            ErrorCode::InvalidArgument,
                            "'end_line' must be >= 'start_line'.",
                            OriginLayer::Validation,
                        ));
                    }
                    if end - start >= MAX_READ_LINES {
                        return Err(BridgeError::new(
                            ErrorCode::InvalidArgument,
                            format!(
                                "Line range may span at most {MAX_READ_LINES} lines (end_line - start_line < {MAX_READ_LINES})."
                            ),
                            OriginLayer::Validation,
                        ));
                    }
                }
                Some((start, e))
            }
        };
        let (canonical_rel, full_path) = self.resolve_checked(rel, true)?;
        #[cfg(windows)]
        let pre_id = file_identity_no_follow_named(&full_path, &canonical_rel)?;
        #[cfg(windows)]
        if pre_id.is_reparse_point || pre_id.is_directory {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                "Target must be a regular non-reparse file.",
                OriginLayer::FileService,
            ));
        }

        #[cfg(windows)]
        let opened = if self.remote_read { open_read_no_follow(&full_path) } else { File::open(&full_path) };
        #[cfg(not(windows))]
        let opened = File::open(&full_path);
        let mut file = opened.map_err(|e| {
            BridgeError::new(
                ErrorCode::FileNotFound,
                format!("Cannot open '{canonical_rel}': {e}"),
                OriginLayer::FileService,
            )
        })?;
        // Post-open handle identity check eliminates TOCTOU rename/junction swap race!
        #[cfg(windows)]
        {
            let open_id = file_identity_from_handle(&file)?;
            if open_id.is_reparse_point || open_id.canonical_id() != pre_id.canonical_id() {
                return Err(BridgeError::new(
                    ErrorCode::StalePrecondition,
                    "File identity changed concurrently while opening.",
                    OriginLayer::FileService,
                ));
            }
            if let Some((_, root)) = &self.remote_root {
                verify_remote_file(root, Path::new(&canonical_rel), &file, &open_id)?;
            }
            if open_id.size_bytes > MAX_READ_FILE_BYTES {
                return Err(BridgeError::new(
                    ErrorCode::ResourceBudgetExceeded,
                    "File exceeds 32 MiB bounded read limit.",
                    OriginLayer::FileService,
                ));
            }
        }
        // Sized from the file so the buffer is allocated once, as a plain whole-file read would.
        let expected = file.metadata().map(|m| m.len()).unwrap_or(0).min(MAX_READ_FILE_BYTES + 1);
        let mut raw = Vec::with_capacity(expected as usize);
        // One byte past the limit is enough to reject a file that grew after the size check.
        (&mut file).take(MAX_READ_FILE_BYTES + 1).read_to_end(&mut raw).map_err(|e| {
            BridgeError::new(
                ErrorCode::InternalError,
                format!("Read error: {e}"),
                OriginLayer::FileService,
            )
        })?;
        if raw.len() as u64 > MAX_READ_FILE_BYTES {
            return Err(BridgeError::new(
                ErrorCode::ResourceBudgetExceeded,
                "File exceeds 32 MiB bounded read limit.",
                OriginLayer::FileService,
            ));
        }
        if raw.iter().take(8192).any(|&b| b == 0) {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                "Binary file detected (NUL byte present); use metadata inspection instead of text read.",
                OriginLayer::FileService,
            ));
        }
        let full_hash = sha256_bytes(&raw);
        let has_utf8_bom = raw.starts_with(&[0xEF, 0xBB, 0xBF]);
        let has_crlf = raw.windows(2).any(|w| w == b"\r\n");
        let has_lf = raw.contains(&b'\n');
        let line_ending = if has_crlf {
            "CRLF"
        } else if has_lf {
            "LF"
        } else {
            "NONE"
        };

        let (text, decoded_lossy) = match std::str::from_utf8(&raw) {
            Ok(s) => (s.to_string(), false),
            Err(_) if lossy_utf8 => (String::from_utf8_lossy(&raw).into_owned(), true),
            Err(_) => {
                return Err(BridgeError::new(
                    ErrorCode::UnsupportedPathType,
                    "File is not valid UTF-8; pass lossy_utf8=true to decode lossily.",
                    OriginLayer::FileService,
                ));
            }
        };

        let cap_chars = limit.clamp(1, MAX_PAGE_BYTES);
        let (page, start, next_offset, truncated, res_total_lines, res_start_line, res_end_line) =
            if let Some((req_start, req_end)) = line_range {
                let mut total_lines = 0usize;
                let mut range_start_byte: Option<usize> = None;
                let mut range_end_byte: usize = 0;
                let max_end_line = req_end.unwrap_or_else(|| req_start.saturating_add(MAX_READ_LINES - 1));
                let mut byte_pos = 0usize;
                for line in text.split_inclusive('\n') {
                    total_lines += 1;
                    let line_end = byte_pos + line.len();
                    if total_lines == req_start {
                        range_start_byte = Some(byte_pos);
                    }
                    if total_lines >= req_start && total_lines <= max_end_line {
                        range_end_byte = line_end;
                    }
                    byte_pos = line_end;
                }
                if let Some(start_byte) = range_start_byte {
                    let start_char = text[..start_byte].chars().count();
                    let range_slice = &text[start_byte..range_end_byte];
                    let (sliced, _, page_chars, cut_by_chars) = char_page(range_slice, 0, cap_chars);
                    let cut_by_line_cap = req_end.is_none() && total_lines > max_end_line;
                    let truncated = cut_by_chars || cut_by_line_cap;
                    let next_offset = if truncated {
                        Some(start_char + page_chars)
                    } else {
                        None
                    };
                    let returned_lines = sliced.split_inclusive('\n').count();
                    let actual_end_line = if returned_lines > 0 {
                        Some(req_start + returned_lines - 1)
                    } else {
                        None
                    };
                    let actual_start_line = actual_end_line.map(|_| req_start);
                    (
                        sliced.to_string(),
                        start_char,
                        next_offset,
                        truncated,
                        Some(total_lines),
                        actual_start_line,
                        actual_end_line,
                    )
                } else {
                    (
                        String::new(),
                        text.chars().count(),
                        None,
                        false,
                        Some(total_lines),
                        None,
                        None,
                    )
                }
            } else {
                let (page, start, end, truncated) = char_page(&text, offset, cap_chars);
                let next_offset = if truncated { Some(end) } else { None };
                (page.to_string(), start, next_offset, truncated, None, None, None)
            };
        let page_hash = sha256_bytes(page.as_bytes());

        Ok(FileReadResult {
            path: canonical_rel,
            content: page,
            size: raw.len() as u64,
            offset: start,
            next_offset,
            truncated,
            lossy_utf8: decoded_lossy,
            has_utf8_bom,
            line_ending: line_ending.to_string(),
            hash: full_hash,
            page_hash,
            total_lines: res_total_lines,
            start_line: res_start_line,
            end_line: res_end_line,
        })
    }

    /// Bounded read-only batch (`file_read_batch`): independent items with per-item status and digests;
    /// zero mutations allowed.
    pub fn read_batch(&self, items: &[BatchReadItemRequest]) -> Result<Vec<BatchReadItemResult>, BridgeError> {
        if items.is_empty() || items.len() > MAX_BATCH_ITEMS {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                format!("file_read_batch requires between 1 and {MAX_BATCH_ITEMS} items."),
                OriginLayer::Validation,
            ));
        }
        let mut results = Vec::with_capacity(items.len());
        for req in items {
            match self.read_with_options(&req.path, req.offset, req.limit, req.lossy_utf8, req.start_line, req.end_line) {
                Ok(r) => results.push(BatchReadItemResult {
                    path: req.path.clone(),
                    ok: true,
                    result: Some(r),
                    error: None,
                }),
                Err(e) => results.push(BatchReadItemResult {
                    path: req.path.clone(),
                    ok: false,
                    result: None,
                    error: Some(e.to_structured()),
                }),
            }
        }
        Ok(results)
    }

    pub fn search(
        &self,
        rel: &str,
        query: &str,
        limit: usize,
        exclude_generated: bool,
        case_sensitive: bool,
    ) -> Result<Vec<SearchHit>, BridgeError> {
        self.search_with_options(rel, query, limit, exclude_generated, case_sensitive, 0, None, false)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn search_with_options(
        &self,
        rel: &str,
        query: &str,
        limit: usize,
        exclude_generated: bool,
        case_sensitive: bool,
        context_lines: usize,
        file_glob: Option<&str>,
        use_regex: bool,
    ) -> Result<Vec<SearchHit>, BridgeError> {
        if query.is_empty() || query.len() > 200 {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                "Search query must be 1..=200 characters.",
                OriginLayer::Validation,
            ));
        }
        if context_lines > MAX_SEARCH_CONTEXT_LINES {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                format!("context_lines must be between 0 and {MAX_SEARCH_CONTEXT_LINES}."),
                OriginLayer::Validation,
            ));
        }
        if let Some(glob) = file_glob {
            validate_file_glob(glob)?;
        }
        let compiled_regex = if use_regex {
            let re = regex::RegexBuilder::new(query)
                .case_insensitive(!case_sensitive)
                .size_limit(SEARCH_REGEX_SIZE_LIMIT)
                .dfa_size_limit(SEARCH_REGEX_SIZE_LIMIT)
                .build()
                .map_err(|e| {
                    BridgeError::new(
                        ErrorCode::InvalidArgument,
                        format!("Invalid or oversized regex pattern: {e}"),
                        OriginLayer::Validation,
                    )
                })?;
            Some(re)
        } else {
            None
        };
        let (_, base_dir) = self.resolve_checked(rel, true)?;
        #[cfg(windows)]
        let mut start_guard = self.pin_read_start(&base_dir, rel)?;
        let cap = limit.clamp(1, 100);
        let needle = if compiled_regex.is_some() {
            String::new()
        } else if case_sensitive {
            query.to_string()
        } else {
            query.to_ascii_lowercase()
        };
        let mut hits = Vec::new();
        // A search that names a generated directory finds nothing while those are excluded.
        let names_generated = base_dir != self.root
            && base_dir.is_dir()
            && base_dir
                .file_name()
                .is_some_and(|n| GENERATED_DIRS.iter().any(|g| g.eq_ignore_ascii_case(&n.to_string_lossy())));
        if exclude_generated && names_generated {
            return Ok(hits);
        }
        for entry in self.walk(&base_dir, usize::MAX, exclude_generated, "The searched directory") {
            let ent = entry?;
            if !ent.file_type.is_file() {
                continue;
            }
            if let Some(glob) = file_glob {
                let matches_name = ent
                    .path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| matches_file_glob(glob, name));
                if !matches_name {
                    continue;
                }
            }
            if fs::symlink_metadata(&ent.path).map(|m| m.len()).unwrap_or(0) > MAX_SEARCH_FILE_BYTES {
                continue;
            }
            // The read is capped as well: a file may grow after its size was checked.
            let Ok(rel_p) = ent.path.strip_prefix(&self.root) else { continue };
            #[cfg(windows)]
            let file = start_guard.take_if(|_| ent.path == base_dir)
                .or_else(|| self.open_walked_file(&ent.path, rel_p));
            #[cfg(not(windows))]
            let file = self.open_walked_file(&ent.path, rel_p);
            let Some(file) = file else { continue };
            let expected = file.metadata().map(|m| m.len()).unwrap_or(0).min(MAX_SEARCH_FILE_BYTES + 1);
            let mut raw = Vec::with_capacity(expected as usize);
            if file.take(MAX_SEARCH_FILE_BYTES + 1).read_to_end(&mut raw).is_err()
                || raw.len() as u64 > MAX_SEARCH_FILE_BYTES
            {
                continue;
            }
            if raw.iter().take(4096).any(|&b| b == 0) {
                continue;
            }
            let Ok(text) = std::str::from_utf8(&raw) else { continue };
            let rel_posix = rel_p.to_string_lossy().replace('\\', "/");
            let line_matches = |line: &str| -> bool {
                if let Some(ref re) = compiled_regex {
                    re.is_match(line)
                } else if case_sensitive {
                    line.contains(&needle)
                } else {
                    line.to_ascii_lowercase().contains(&needle)
                }
            };
            if context_lines == 0 {
                for (idx, line) in text.lines().enumerate() {
                    if line_matches(line) {
                        hits.push(SearchHit {
                            path: rel_posix.clone(),
                            line: idx + 1,
                            preview: line.chars().take(240).collect(),
                            context_before: Vec::new(),
                            context_after: Vec::new(),
                        });
                        if hits.len() >= cap {
                            break;
                        }
                    }
                }
            } else {
                let lines: Vec<&str> = text.lines().collect();
                for (idx, line) in lines.iter().enumerate() {
                    if line_matches(line) {
                        let before_start = idx.saturating_sub(context_lines);
                        let after_end = (idx + 1 + context_lines).min(lines.len());
                        hits.push(SearchHit {
                            path: rel_posix.clone(),
                            line: idx + 1,
                            preview: line.chars().take(240).collect(),
                            context_before: lines[before_start..idx]
                                .iter()
                                .map(|l| l.chars().take(240).collect())
                                .collect(),
                            context_after: lines[(idx + 1)..after_end]
                                .iter()
                                .map(|l| l.chars().take(240).collect())
                                .collect(),
                        });
                        if hits.len() >= cap {
                            break;
                        }
                    }
                }
            }
            // Checked here, not at the top, so the walk does not read one more directory.
            if hits.len() >= cap {
                break;
            }
        }
        Ok(hits)
    }

    pub fn build_manifest(&self, exclude_generated: bool) -> Result<ProjectManifest, BridgeError> {
        let mut entries = Vec::new();
        let mut total_bytes: u64 = 0;
        for entry in self.walk(&self.root, usize::MAX, exclude_generated, "The project") {
            let ent = entry?;
            if !ent.file_type.is_file() {
                continue;
            }
            let Ok(rel_p) = ent.path.strip_prefix(&self.root) else { continue };
            let rel_posix = rel_p.to_string_lossy().replace('\\', "/");
            // Hashed as a stream: a large asset must not be held in memory, least of
            // all once per agent that asks for the project context at the same time.
            let Some(file) = self.open_walked_file(&ent.path, rel_p) else { continue };
            let Ok((sha256, size)) = bridge_platform::sha256_handle_with_len(file) else { continue };
            total_bytes += size;
            entries.push(ManifestEntry { path: rel_posix, size, sha256 });
        }
        let manifest_json = serde_json::to_string(&entries).unwrap();
        let manifest_sha256 = sha256_bytes(manifest_json.as_bytes());
        Ok(ProjectManifest {
            file_count: entries.len(),
            total_bytes,
            manifest_sha256,
            entries,
        })
    }

    /// Validate entire `PatchPlanV04` upfront, record a durable recovery journal + exact backups,
    /// apply changes, verify every postimage SHA-256, and return unified diff + journal metadata (§7.2).
    pub fn apply_patch_plan(
        &self,
        plan: &PatchPlanV04,
        journal_dir: &Path,
        simulate_crash_after_step: Option<usize>,
    ) -> Result<(PatchApplyResult, PatchJournal), BridgeError> {
        self.apply_patch_plan_inner(plan, journal_dir, simulate_crash_after_step, None)
    }

    pub fn apply_delegated_creates(
        &self,
        plan: &PatchPlanV04,
        journal_dir: &Path,
        scope: &[String],
        authorize_commit: impl Fn(&str) -> Result<(), BridgeError>,
    ) -> Result<(PatchApplyResult, PatchJournal), BridgeError> {
        self.apply_patch_plan_inner(plan, journal_dir, None, Some(DelegatedPatch {
            scope,
            authorize_commit: &authorize_commit,
            remove_stage: |path| fs::remove_file(path),
        }))
    }

    /// Apply create or hash-checked overwrite edits strictly inside exact-case `_pro/work/<workspace>/**`.
    ///
    /// Enforces defense-in-depth path checks (`is_pro_work_file_path`), handle-pinned parents with exact
    /// casing and reparse-point refusal, single-link preimage checks (`n_links == 1`), net positive quota
    /// delta accounting against the `_pro/` folder limits, per-file commit-time re-authorization, and
    /// atomic rollback restoring original bytes on failure.
    pub fn apply_delegated_work_edits(
        &self,
        plan: &PatchPlanV04,
        journal_dir: &Path,
        scope: &[String],
        authorize_commit: impl Fn(&str) -> Result<(), BridgeError>,
    ) -> Result<(PatchApplyResult, PatchJournal), BridgeError> {
        if plan.edits.is_empty() || plan.edits.len() > 64 {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                "Patch plan must contain between 1 and 64 edits.",
                OriginLayer::FileService,
            ));
        }
        // Defense-in-depth: never mutate anything outside exact-case `_pro/work/<workspace>/**`.
        for edit in &plan.edits {
            if !crate::policy::is_pro_work_file_path(&edit.path) {
                return Err(BridgeError::new(
                    ErrorCode::BridgePolicyDenied,
                    format!(
                        "Work-area edit target '{}' is outside exact-case '_pro/work/<workspace>/**'.",
                        edit.path
                    ),
                    OriginLayer::FileService,
                ));
            }
        }
        let cur_rid = self.current_root_identity()?;
        if let Some(ref exp_rid) = plan.root_identity {
            if exp_rid.starts_with("ntfs:") && *exp_rid != cur_rid {
                return Err(BridgeError::new(
                    ErrorCode::StalePrecondition,
                    "Patch plan root_identity does not match current filesystem root.",
                    OriginLayer::FileService,
                ));
            }
        }

        let _writer = lock_patch_root(journal_dir, &cur_rid)?;
        #[cfg(windows)]
        let (_root_pin, root_path_buf) = {
            let root_handle = open_patch_directory(&self.root).map_err(patch_io_error)?;
            let id = file_identity_from_handle(&root_handle)?;
            if !id.is_directory || id.is_reparse_point || id.canonical_id() != cur_rid {
                return Err(BridgeError::new(
                    ErrorCode::StalePrecondition,
                    "Project root identity changed before applying work edits.",
                    OriginLayer::FileService,
                ));
            }
            let rp = file_path_from_handle(&root_handle)?;
            (root_handle, rp)
        };
        #[cfg(windows)]
        let root_path_opt = Some(root_path_buf.as_path());
        #[cfg(not(windows))]
        let root_path_opt: Option<&Path> = None;

        // Phase 1: Validate all paths, parents, preimages, and net quota BEFORE writing a single byte.
        let mut prepared = Vec::with_capacity(plan.edits.len());
        let mut seen = std::collections::HashSet::new();
        let mut quota_deltas = BTreeMap::<String, (usize, i128)>::new();
        let mut missing_dirs = BTreeSet::new();

        for edit in &plan.edits {
            let (rel, full) = self.resolve_checked(&edit.path, false)?;
            if !seen.insert(rel.to_ascii_lowercase()) {
                return Err(BridgeError::new(
                    ErrorCode::InvalidArgument,
                    format!("Duplicate target path in patch plan: {rel}"),
                    OriginLayer::FileService,
                ));
            }
            let folder = crate::policy::delegated_write_quota_scope(&rel, scope)
                .ok_or_else(|| BridgeError::new(
                    ErrorCode::BridgePolicyDenied,
                    "Work-area edit has no authorized folder.",
                    OriginLayer::FileService,
                ))?
                .to_owned();
            #[cfg(windows)]
            PatchParent::pin(&self.root, &cur_rid, &rel, true, false, None)?;
            for parent in full.ancestors().skip(1) {
                if parent == self.root {
                    break;
                }
                match fs::symlink_metadata(parent) {
                    Ok(_) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        missing_dirs.insert(parent.to_owned());
                    }
                    Err(error) => return Err(patch_io_error(error)),
                }
            }
            let target_exists = match fs::symlink_metadata(&full) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(patch_io_error(error)),
            };
            let (actual_hash, old_bytes, pre_ntfs_id) = if target_exists {
                let (bytes, fid) = read_delegated_work_file_verified(
                    &self.root,
                    root_path_opt,
                    &full,
                    &rel,
                    DELEGATED_WRITE_MAX_SCOPE_BYTES,
                )?;
                (Some(sha256_bytes(&bytes)), Some(bytes), fid)
            } else {
                (None, None, None)
            };
            match (&edit.expected_hash, &actual_hash) {
                (None, Some(_)) => {
                    return Err(BridgeError::new(
                        ErrorCode::VersionConflict,
                        format!(
                            "Target '{rel}' already exists; pass expected_hash of current bytes to overwrite inside _pro/work/."
                        ),
                        OriginLayer::FileService,
                    ));
                }
                (Some(_), None) => {
                    return Err(BridgeError::new(
                        ErrorCode::VersionConflict,
                        format!("Expected existing file '{rel}' is missing (stale preimage)."),
                        OriginLayer::FileService,
                    ));
                }
                (Some(exp), Some(act)) if !exp.eq_ignore_ascii_case(act) => {
                    return Err(BridgeError::new(
                        ErrorCode::VersionConflict,
                        format!("Preimage SHA-256 mismatch for '{rel}': expected {exp}, actual {act}."),
                        OriginLayer::FileService,
                    ));
                }
                _ => {}
            }
            let new_bytes = edit.content.as_bytes().to_vec();
            let post_hash = sha256_bytes(&new_bytes);
            if let Some(ref exp_post) = edit.expected_postimage_hash {
                if !exp_post.eq_ignore_ascii_case(&post_hash) {
                    return Err(BridgeError::new(
                        ErrorCode::InvalidArgument,
                        format!("Plan expected_postimage_hash does not match content bytes for '{rel}'."),
                        OriginLayer::Validation,
                    ));
                }
            }
            let delta = quota_deltas.entry(folder).or_insert((0, 0));
            if let Some(ref old) = old_bytes {
                delta.1 += (new_bytes.len() as i128) - (old.len() as i128);
            } else {
                delta.0 += 1;
                delta.1 += new_bytes.len() as i128;
            }
            prepared.push((
                rel,
                full,
                edit.expected_hash.clone(),
                actual_hash,
                old_bytes,
                new_bytes,
                post_hash,
                pre_ntfs_id,
            ));
        }

        let quota_folders: BTreeMap<&str, (usize, u64)> = quota_deltas
            .iter()
            .map(|(folder, (added_files, net_bytes))| {
                (folder.as_str(), (*added_files, (*net_bytes).max(0) as u64))
            })
            .collect();
        check_delegated_write_quota(&self.root, quota_folders, &missing_dirs)?;

        // Phase 2: Create recovery journal & backups outside target files.
        let journal_id = format!("pjr_{}", uuid::Uuid::new_v4().simple());
        let j_root = journal_dir.join(&journal_id);
        let backups_dir = j_root.join("backups");
        fs::create_dir(&j_root).map_err(patch_io_error)?;
        let has_overwrites = prepared.iter().any(|item| item.4.is_some());
        if has_overwrites {
            fs::create_dir(&backups_dir).map_err(patch_io_error)?;
        }
        let plan_sha = sha256_bytes(serde_json::to_string(plan).unwrap().as_bytes());
        let mut steps = Vec::with_capacity(prepared.len());
        for (idx, (rel, _, exp_pre, act_pre, old_bytes, _, post_hash, _)) in prepared.iter().enumerate() {
            let backup_rel = if let Some(bytes) = old_bytes {
                let bname = format!("step_{idx:03}.bak");
                write_synced_new(&backups_dir.join(&bname), bytes)?;
                Some(format!("backups/{bname}"))
            } else {
                None
            };
            steps.push(PatchJournalFileStep {
                path: rel.clone(),
                expected_preimage: exp_pre.clone(),
                actual_preimage: act_pre.clone(),
                backup_rel_path: backup_rel,
                postimage_sha256: post_hash.clone(),
                committed: false,
                deleted: false,
            });
        }
        let mut journal = PatchJournal {
            journal_id: journal_id.clone(),
            project_id: plan.project_id.clone(),
            root_identity: Some(cur_rid.clone()),
            operation_id: plan.operation_id.clone(),
            state: "applying".to_string(),
            plan_sha256: plan_sha,
            created_at: Utc::now().to_rfc3339(),
            steps,
            stage_cleanup_failed: Vec::new(),
            directory_cleanup_failed: Vec::new(),
        };
        let journal_file = j_root.join("journal.json");

        // Phase 3: Stage all files, then commit each with live preimage & grant checks, rolling back on any failure.
        let mut staged = Vec::with_capacity(prepared.len());
        let mut created_dirs = Vec::new();
        let remove_stage: fn(&Path) -> std::io::Result<()> = |path| fs::remove_file(path);
        let commit_result: Result<(), BridgeError> = (|| {
            persist_patch_journal(&journal_file, &journal)?;
            for (idx, (rel, full, _, _, _, bytes, _, _)) in prepared.iter().enumerate() {
                let temp_name = format!(".eb_stage_{journal_id}_{idx}.tmp");
                let stage = DelegatedStage::create(&self.root, &cur_rid, rel, full, &temp_name, &mut created_dirs)?;
                staged.push(stage);
                staged.last_mut().unwrap().write(rel, bytes)?;
            }
            for (idx, stage) in staged.iter_mut().enumerate() {
                let (rel, _, _, actual_pre, old_bytes, bytes, post_hash, pre_ntfs_id) = &prepared[idx];
                #[cfg(windows)]
                stage.parent.verify_location(rel)?;
                authorize_commit(rel)?;
                if let Some(old) = old_bytes.as_deref() {
                    let expected_pre = actual_pre.as_deref().unwrap();
                    #[cfg(windows)]
                    {
                        let preimage_guard = verify_work_preimage_handle(
                            &stage.parent.root_path,
                            &stage.destination,
                            rel,
                            pre_ntfs_id.as_deref(),
                            expected_pre,
                            old.len(),
                        )?;
                        stage.parent.verify_location(rel)?;
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
                        let _ = (pre_ntfs_id, old);
                        let (current, _) = read_delegated_work_file_verified(
                            &self.root,
                            None,
                            &stage.destination,
                            rel,
                            DELEGATED_WRITE_MAX_SCOPE_BYTES,
                        )?;
                        if sha256_bytes(&current) != expected_pre || self.current_root_identity()? != cur_rid {
                            return Err(patch_commit_conflict(rel));
                        }
                        fs::rename(&stage.temp, &stage.destination).map_err(patch_io_error)?;
                    }
                } else {
                    #[cfg(windows)]
                    {
                        stage.parent.verify_location(rel)?;
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
                                format!("Target '{rel}' already exists; pass expected_hash to overwrite inside _pro/work/."),
                                OriginLayer::FileService,
                            )
                        } else {
                            patch_io_error(error)
                        }
                    })?;
                }
                stage.committed = true;
                journal.steps[idx].committed = true;
                persist_patch_journal(&journal_file, &journal)?;
                stage.verify_postimage(rel, bytes.len(), post_hash)?;
            }
            journal.state = "committed".into();
            persist_patch_journal(&journal_file, &journal)?;
            for stage in &mut staged {
                stage.close(remove_stage)?;
            }
            Ok(())
        })();

        if let Err(mut error) = commit_result {
            let mut rollback_failed = Vec::new();
            for (idx, stage) in staged.iter_mut().enumerate().rev() {
                if stage.committed {
                    if let Some(ref old) = prepared[idx].4 {
                        // Drop our open handle to the newly committed target before replacing it with backup bytes.
                        stage.file.take();
                        let restore_ok = (|| -> Result<(), BridgeError> {
                            #[cfg(windows)]
                            {
                                stage.parent.verify_location(&journal.steps[idx].path)?;
                                let rb_name = format!(".eb_stage_{journal_id}_{idx}_rb.tmp");
                                let rb_path = stage.parent.path.join(&rb_name);
                                let res = (|| -> Result<(), BridgeError> {
                                    let mut rb_file = create_patch_stage(&rb_path).map_err(patch_io_error)?;
                                    rb_file.write_all(old).map_err(patch_io_error)?;
                                    rb_file.sync_all().map_err(patch_io_error)?;
                                    commit_patch_stage(
                                        &rb_file,
                                        stage.parent.directories.last().unwrap(),
                                        stage.destination.file_name().unwrap(),
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
                                let rb_path = stage.destination.with_file_name(format!(".eb_stage_{journal_id}_{idx}_rb.tmp"));
                                let res = (|| -> Result<(), BridgeError> {
                                    write_synced_new(&rb_path, old)?;
                                    fs::rename(&rb_path, &stage.destination).map_err(patch_io_error)?;
                                    Ok(())
                                })();
                                if res.is_err() {
                                    let _ = fs::remove_file(&rb_path);
                                }
                                res
                            }
                        })().is_ok();
                        if restore_ok {
                            journal.steps[idx].committed = false;
                        } else {
                            rollback_failed.push(journal.steps[idx].path.clone());
                        }
                    } else if stage.undo_commit().is_ok() {
                        journal.steps[idx].committed = false;
                    } else {
                        rollback_failed.push(journal.steps[idx].path.clone());
                    }
                }
                if stage.close(remove_stage).is_err() {
                    let relative = Path::new(&journal.steps[idx].path).with_file_name(stage.temp.file_name().unwrap());
                    journal.stage_cleanup_failed.push(relative.to_string_lossy().replace('\\', "/"));
                }
            }
            drop(staged);
            for relative in created_dirs.iter().rev() {
                match fs::remove_dir(self.root.join(relative)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => journal.directory_cleanup_failed.push(relative.to_string_lossy().replace('\\', "/")),
                }
            }
            let residue = !rollback_failed.is_empty()
                || !journal.stage_cleanup_failed.is_empty()
                || !journal.directory_cleanup_failed.is_empty();
            let journal_update_failed = if residue {
                journal.state = "rollback_incomplete".into();
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

        let mut diff_out = String::new();
        let mut post_hashes = BTreeMap::new();
        let mut applied_files = Vec::with_capacity(prepared.len());
        for (rel, _, _, _, old_bytes, new_bytes, expected_post, _) in prepared {
            let old_text = old_bytes
                .as_deref()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default();
            let new_text = String::from_utf8_lossy(&new_bytes).into_owned();
            let diff = TextDiff::from_lines(&old_text, &new_text);
            diff_out.push_str(&format!(
                "{}",
                diff.unified_diff()
                    .context_radius(3)
                    .header(&format!("a/{rel}"), &format!("b/{rel}"))
            ));
            post_hashes.insert(rel.clone(), expected_post);
            applied_files.push(rel);
        }
        let diff_sha = sha256_bytes(diff_out.as_bytes());
        Ok((
            PatchApplyResult {
                journal_id,
                operation_id: plan.operation_id.clone(),
                files_applied: applied_files,
                postimage_hashes: post_hashes,
                unified_diff: diff_out,
                diff_sha256: diff_sha,
            },
            journal,
        ))
    }

    fn apply_patch_plan_inner(
        &self,
        plan: &PatchPlanV04,
        journal_dir: &Path,
        simulate_crash_after_step: Option<usize>,
        delegated: Option<DelegatedPatch<'_>>,
    ) -> Result<(PatchApplyResult, PatchJournal), BridgeError> {
        if plan.edits.is_empty() || plan.edits.len() > 64 {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                "Patch plan must contain between 1 and 64 edits.",
                OriginLayer::FileService,
            ));
        }
        let cur_rid = self.current_root_identity()?;
        if let Some(ref exp_rid) = plan.root_identity {
            if exp_rid.starts_with("ntfs:") && *exp_rid != cur_rid {
                return Err(BridgeError::new(
                    ErrorCode::StalePrecondition,
                    "Patch plan root_identity does not match current filesystem root.",
                    OriginLayer::FileService,
                ));
            }
        }

        let _writer = lock_patch_root(journal_dir, &cur_rid)?;
        // Phase 1: Validate ALL paths, handle identities (TOCTOU-checked), and preimages BEFORE mutating any file!
        let mut prepared = Vec::with_capacity(plan.edits.len());
        let mut seen = std::collections::HashSet::new();
        let mut quota_folders = BTreeMap::<&str, (usize, u64)>::new();
        let mut missing_dirs = BTreeSet::new();
        for edit in &plan.edits {
            let (rel, full) = self.resolve_checked(&edit.path, false)?;
            if !seen.insert(rel.to_ascii_lowercase()) {
                return Err(BridgeError::new(
                    ErrorCode::InvalidArgument,
                    format!("Duplicate target path in patch plan: {rel}"),
                    OriginLayer::FileService,
                ));
            }
            if let Some(ref delegated) = delegated {
                if edit.expected_hash.is_some() {
                    return Err(BridgeError::new(
                        ErrorCode::BridgePolicyDenied,
                        "Delegated writes can only create files.",
                        OriginLayer::FileService,
                    )
                    .with_next_action(
                        "Omit expected_hash (or set it to null) and choose a new file name inside the granted writable path; delegated writes are create-only.",
                    ));
                }
                let folder = crate::policy::delegated_write_quota_scope(&edit.path, delegated.scope)
                    .ok_or_else(|| BridgeError::new(
                        ErrorCode::BridgePolicyDenied,
                        "Delegated write has no authorized folder.",
                        OriginLayer::FileService,
                    ))?;
                #[cfg(windows)]
                PatchParent::pin(&self.root, &cur_rid, &rel, true, false, None)?;
                for parent in full.ancestors().skip(1) {
                    if parent == self.root || parent.try_exists().map_err(patch_io_error)? {
                        break;
                    }
                    missing_dirs.insert(parent.to_owned());
                }
                let totals = quota_folders.entry(folder).or_default();
                totals.0 += 1;
                totals.1 += edit.content.len() as u64;
            }
            let exists = full.exists();
            if delegated.is_some() && exists {
                return Err(BridgeError::new(
                    ErrorCode::VersionConflict,
                    format!("Create-only edit rejected because '{rel}' already exists."),
                    OriginLayer::FileService,
                )
                .with_next_action(DELEGATED_CREATE_ONLY_NEXT_ACTION));
            }
            let (actual_hash, old_bytes, pre_ntfs_id) = if exists {
                let (b, fid) = read_handle_verified(&full, &rel)?;
                (Some(sha256_bytes(&b)), Some(b), fid)
            } else {
                (None, None, None)
            };
            match (&edit.expected_hash, &actual_hash) {
                (None, Some(_)) => {
                    return Err(BridgeError::new(
                        ErrorCode::VersionConflict,
                        format!("Create-only edit rejected because '{rel}' already exists."),
                        OriginLayer::FileService,
                    ));
                }
                (Some(_), None) => {
                    return Err(BridgeError::new(
                        ErrorCode::VersionConflict,
                        format!("Expected existing file '{rel}' is missing (stale preimage)."),
                        OriginLayer::FileService,
                    ));
                }
                (Some(exp), Some(act)) if !exp.eq_ignore_ascii_case(act) => {
                    return Err(BridgeError::new(
                        ErrorCode::VersionConflict,
                        format!("Preimage SHA-256 mismatch for '{rel}': expected {exp}, actual {act}."),
                        OriginLayer::FileService,
                    ));
                }
                _ => {}
            }
            let new_bytes = edit.content.as_bytes().to_vec();
            let post_hash = sha256_bytes(&new_bytes);
            if let Some(ref exp_post) = edit.expected_postimage_hash {
                if !exp_post.eq_ignore_ascii_case(&post_hash) {
                    return Err(BridgeError::new(
                        ErrorCode::InvalidArgument,
                        format!("Plan expected_postimage_hash does not match content bytes for '{rel}'."),
                        OriginLayer::Validation,
                    ));
                }
            }
            prepared.push((rel, full, edit.expected_hash.clone(), actual_hash, old_bytes, new_bytes, post_hash, pre_ntfs_id));
        }
        check_delegated_write_quota(&self.root, quota_folders, &missing_dirs)?;

        // Phase 2: Write recovery journal & exact backups outside target files before committing.
        let journal_id = format!("pjr_{}", uuid::Uuid::new_v4().simple());
        let j_root = journal_dir.join(&journal_id);
        let backups_dir = j_root.join("backups");
        if delegated.is_some() {
            // Claim the exact directory before any failure can trigger its cleanup.
            fs::create_dir(&j_root).map_err(patch_io_error)?;
        } else {
            fs::create_dir_all(&backups_dir).map_err(patch_io_error)?;
        }
        let plan_sha = sha256_bytes(serde_json::to_string(plan).unwrap().as_bytes());
        let mut steps = Vec::new();
        for (idx, (rel, _, exp_pre, act_pre, old_bytes, _, post_hash, _)) in prepared.iter().enumerate() {
            let backup_rel = if let Some(bytes) = old_bytes {
                let bname = format!("step_{idx:03}.bak");
                write_synced_new(&backups_dir.join(&bname), bytes)?;
                Some(format!("backups/{bname}"))
            } else {
                None
            };
            steps.push(PatchJournalFileStep {
                path: rel.clone(),
                expected_preimage: exp_pre.clone(),
                actual_preimage: act_pre.clone(),
                backup_rel_path: backup_rel,
                postimage_sha256: post_hash.clone(),
                committed: false,
                deleted: false,
            });
        }
        let mut journal = PatchJournal {
            journal_id: journal_id.clone(),
            project_id: plan.project_id.clone(),
            root_identity: Some(cur_rid.clone()),
            operation_id: plan.operation_id.clone(),
            state: "applying".to_string(),
            plan_sha256: plan_sha,
            created_at: Utc::now().to_rfc3339(),
            steps,
            stage_cleanup_failed: Vec::new(),
            directory_cleanup_failed: Vec::new(),
        };
        let journal_file = j_root.join("journal.json");
        if let Some(ref delegated) = delegated {
            let mut staged = Vec::with_capacity(prepared.len());
            let mut created_dirs = Vec::new();
            let result: Result<(), BridgeError> = (|| {
                persist_patch_journal(&journal_file, &journal)?;
                for (idx, (rel, full, _, _, _, bytes, _, _)) in prepared.iter().enumerate() {
                    let temp_name = format!(".eb_stage_{journal_id}_{idx}.tmp");
                    let stage = DelegatedStage::create(&self.root, &cur_rid, rel, full, &temp_name, &mut created_dirs)?;
                    staged.push(stage);
                    staged.last_mut().unwrap().write(rel, bytes)?;
                }
                for (idx, stage) in staged.iter_mut().enumerate() {
                    let (rel, _, _, _, _, bytes, post_hash, _) = &prepared[idx];
                    stage.commit(rel, delegated.authorize_commit)?;
                    journal.steps[idx].committed = true;
                    persist_patch_journal(&journal_file, &journal)?;
                    stage.verify_postimage(rel, bytes.len(), post_hash)?;
                }
                journal.state = "committed".into();
                persist_patch_journal(&journal_file, &journal)?;
                for stage in &mut staged {
                    stage.close(delegated.remove_stage)?;
                }
                Ok(())
            })();
            if let Err(mut error) = result {
                let mut rollback_failed = Vec::new();
                for (idx, stage) in staged.iter_mut().enumerate().rev() {
                    if stage.committed {
                        if stage.undo_commit().is_ok() {
                            journal.steps[idx].committed = false;
                        } else {
                            rollback_failed.push(journal.steps[idx].path.clone());
                        }
                    }
                    if stage.close(delegated.remove_stage).is_err() {
                        let relative = Path::new(&journal.steps[idx].path).with_file_name(stage.temp.file_name().unwrap());
                        journal.stage_cleanup_failed.push(relative.to_string_lossy().replace('\\', "/"));
                    }
                }
                // Closing the stages also releases the Windows parent directory pins.
                drop(staged);
                for relative in created_dirs.iter().rev() {
                    match fs::remove_dir(self.root.join(relative)) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(_) => journal.directory_cleanup_failed.push(relative.to_string_lossy().replace('\\', "/")),
                    }
                }
                let residue = !rollback_failed.is_empty() || !journal.stage_cleanup_failed.is_empty()
                    || !journal.directory_cleanup_failed.is_empty();
                let journal_update_failed = if residue {
                    journal.state = "rollback_incomplete".into();
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
        } else {
            persist_patch_journal(&journal_file, &journal)?;
        }

        // Phase 3: Stage & commit each file atomically (zero delete-before-rename window!), verifying handle identity & postimage hash.
        let mut diff_out = String::new();
        let mut post_hashes = BTreeMap::new();
        let mut applied_files = Vec::new();
        for (idx, (rel, full, _, preimage, old_bytes, new_bytes, expected_post, _pre_ntfs_id)) in prepared.into_iter().enumerate() {
            if delegated.is_none() {
                self.resolve_checked(&rel, false)?;
                #[cfg(windows)]
                let parent = PatchParent::pin(&self.root, &cur_rid, &rel, false, true, None)?;
                #[cfg(windows)]
                let full = parent.path.join(full.file_name().ok_or_else(|| patch_commit_conflict(&rel))?);
                #[cfg(not(windows))]
                if let Some(parent) = full.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        BridgeError::new(ErrorCode::InternalError, format!("Create parent failed: {e}"), OriginLayer::FileService)
                    })?;
                }
                let tmp_path = full.with_file_name(format!(
                    ".eb_stage_{}_{}.tmp",
                    journal_id, idx
                ));
                #[cfg(windows)]
                let stage = {
                    let mut stage = create_patch_stage(&tmp_path).map_err(patch_io_error)?;
                    if file_path_from_handle(&stage)?.parent() != Some(parent.path.as_path()) {
                        return Err(patch_commit_conflict(&rel));
                    }
                    stage.write_all(&new_bytes).map_err(patch_io_error)?;
                    stage.sync_all().map_err(patch_io_error)?;
                    parent.verify_location(&rel)?;
                    stage
                };
                #[cfg(not(windows))]
                write_synced_new(&tmp_path, &new_bytes)?;
                if let Some(expected) = preimage.as_deref() {
                    #[cfg(windows)]
                    {
                        let preimage_guard = verify_patch_preimage(&full, &rel, _pre_ntfs_id.as_deref(), expected,
                            old_bytes.as_ref().map_or(0, Vec::len))?;
                        parent.verify_location(&rel)?;
                        commit_patch_stage(&stage, parent.directories.last().unwrap(), full.file_name().unwrap(), true)?;
                        drop(preimage_guard);
                    }
                    #[cfg(not(windows))]
                    {
                        let (current, _) = read_handle_verified(&full, &rel)?;
                        if sha256_bytes(&current) != expected || self.current_root_identity()? != cur_rid {
                            return Err(patch_commit_conflict(&rel));
                        }
                        fs::rename(&tmp_path, &full).map_err(patch_io_error)?;
                    }
                } else {
                    #[cfg(windows)]
                    commit_patch_stage(&stage, parent.directories.last().unwrap(), full.file_name().unwrap(), false)?;
                    #[cfg(not(windows))]
                    commit_new_patch_file(&tmp_path, &full)?;
                }
                #[cfg(windows)]
                drop(stage);
                journal.steps[idx].committed = true;
                persist_patch_journal(&journal_file, &journal)?;
            }

            let actual_post = if delegated.is_some() {
                // Delegated postimages were already verified with their stage handles open.
                expected_post
            } else {
                let (written, _) = read_handle_verified(&full, &rel)?;
                let actual_post = sha256_bytes(&written);
                if actual_post != expected_post {
                    return Err(BridgeError::new(
                        ErrorCode::StalePrecondition,
                        format!("Postimage verification failed for '{rel}'."),
                        OriginLayer::FileService,
                    ));
                }
                actual_post
            };

            let old_text = old_bytes
                .as_deref()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default();
            let new_text = String::from_utf8_lossy(&new_bytes).into_owned();
            let diff = TextDiff::from_lines(&old_text, &new_text);
            diff_out.push_str(&format!(
                "{}",
                diff.unified_diff()
                    .context_radius(3)
                    .header(&format!("a/{rel}"), &format!("b/{rel}"))
            ));

            post_hashes.insert(rel.clone(), actual_post);
            applied_files.push(rel);

            if simulate_crash_after_step == Some(idx) {
                journal.state = "interrupted_mid_apply".to_string();
                persist_patch_journal(&journal_file, &journal)?;
                return Err(BridgeError::new(
                    ErrorCode::UnknownAfterRestart,
                    format!("Simulated crash after step {idx}; recover using journal '{journal_id}'."),
                    OriginLayer::FileService,
                ));
            }
        }

        if delegated.is_none() {
            journal.state = "committed".to_string();
            persist_patch_journal(&journal_file, &journal)?;
        }
        let diff_sha = sha256_bytes(diff_out.as_bytes());
        Ok((
            PatchApplyResult {
                journal_id,
                operation_id: plan.operation_id.clone(),
                files_applied: applied_files,
                postimage_hashes: post_hashes,
                unified_diff: diff_out,
                diff_sha256: diff_sha,
            },
            journal,
        ))
    }

    /// Safe rollback from a patch journal: restores backups ONLY for files whose current disk hash
    /// still matches the journal's `postimage_sha256`. REFUSES to overwrite later user edits! (§7.2)
    pub fn rollback_patch_journal(
        &self,
        journal_dir: &Path,
        journal_id: &str,
    ) -> Result<Vec<String>, BridgeError> {
        if !journal_id.strip_prefix("pjr_").is_some_and(|id| {
            id.len() == 32 && id.as_bytes().iter().all(u8::is_ascii_hexdigit)
        }) {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                "Invalid patch journal ID.",
                OriginLayer::FileService,
            ));
        }
        let journal_dir = std::path::absolute(journal_dir).map_err(|e| BridgeError::new(
            ErrorCode::InvalidArgument, format!("Cannot resolve the patch journal directory: {e}"), OriginLayer::FileService,
        ))?;
        let root_identity = self.current_root_identity()?;
        let _writer = lock_patch_root(&journal_dir, &root_identity)?;
        let journal_files = ScopedFiles::new(&journal_dir, None)?;
        let (_, journal_file) = journal_files.resolve_checked(&format!("{journal_id}/journal.json"), true)?;
        let (raw, _) = read_handle_verified(&journal_file, "journal.json")?;
        let mut journal: PatchJournal = serde_json::from_slice(&raw).map_err(|e| {
            BridgeError::new(ErrorCode::InternalError, format!("Corrupt journal: {e}"), OriginLayer::FileService)
        })?;
        if journal.journal_id != journal_id || journal.root_identity.as_deref() != Some(root_identity.as_str()) {
            return Err(BridgeError::new(
                ErrorCode::StalePrecondition,
                "Patch journal does not identify this project root. Review the retained backup manually.",
                OriginLayer::FileService,
            ));
        }
        if journal.state == "rolled_back" {
            return Ok(vec![]);
        }

        // Check every target and backup before touching the first project file.
        let mut verified_steps = Vec::new();
        for (idx, step) in journal.steps.iter().enumerate() {
            if !step.committed {
                continue;
            }
            let (_, full) = self.resolve_checked(&step.path, false)?;
            let expected_backup = format!("backups/step_{idx:03}.bak");
            if step.deleted {
                let (hash, bytes) = match (&step.actual_preimage, &step.backup_rel_path) {
                    (Some(hash), Some(rel)) if rel == &expected_backup => {
                        let (_, path) = journal_files.resolve_checked(&format!("{journal_id}/{expected_backup}"), true)?;
                        let (bytes, _) = read_handle_verified(&path, &expected_backup)?;
                        if sha256_bytes(&bytes) != *hash {
                            return Err(invalid_rollback_backup(&step.path));
                        }
                        (hash, bytes)
                    }
                    _ => return Err(invalid_rollback_backup(&step.path)),
                };
                match fs::symlink_metadata(&full) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        verified_steps.push((step, full, None, Some(bytes)));
                    }
                    Ok(_) => {
                        let (current, _) = read_handle_verified(&full, &step.path)?;
                        if sha256_bytes(&current) == *hash {
                            continue; // A previous rollback already restored this file.
                        }
                        return Err(rollback_target_conflict(&step.path));
                    }
                    Err(e) => {
                        return Err(BridgeError::new(
                            ErrorCode::InternalError,
                            format!("Cannot inspect rollback target: {e}"),
                            OriginLayer::FileService,
                        ));
                    }
                }
                continue;
            }
            if !full.try_exists().map_err(|e| BridgeError::new(
                ErrorCode::InternalError, format!("Cannot inspect rollback target: {e}"), OriginLayer::FileService,
            ))? {
                if step.actual_preimage.is_none() && step.backup_rel_path.is_none() {
                    continue; // A create-only target is already absent.
                }
                return Err(rollback_target_conflict(&step.path));
            }
            let (current, identity) = read_handle_verified(&full, &step.path)?;
            let current_hash = sha256_bytes(&current);
            if step.actual_preimage.as_deref() == Some(current_hash.as_str()) {
                continue; // A previous rollback already restored this file.
            }
            if current_hash != step.postimage_sha256 {
                return Err(rollback_target_conflict(&step.path));
            }
            let backup = match (&step.actual_preimage, &step.backup_rel_path) {
                (None, None) => None,
                (Some(hash), Some(rel)) if rel == &expected_backup => {
                    let (_, path) = journal_files.resolve_checked(&format!("{journal_id}/{expected_backup}"), true)?;
                    let (bytes, _) = read_handle_verified(&path, &expected_backup)?;
                    if sha256_bytes(&bytes) != *hash {
                        return Err(invalid_rollback_backup(&step.path));
                    }
                    Some(bytes)
                }
                _ => return Err(invalid_rollback_backup(&step.path)),
            };
            verified_steps.push((step, full, identity, backup));
        }

        let mut restored = Vec::new();
        for (step, full, expected_fid, backup) in verified_steps.into_iter().rev() {
            if step.deleted {
                if self.current_root_identity()? != root_identity {
                    return Err(rollback_target_conflict(&step.path));
                }
                self.resolve_checked(&step.path, false)?;
                match fs::symlink_metadata(&full) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => return Err(rollback_target_conflict(&step.path)),
                    Err(e) => {
                        return Err(BridgeError::new(
                            ErrorCode::InternalError,
                            format!("Cannot inspect rollback target: {e}"),
                            OriginLayer::FileService,
                        ));
                    }
                }
                let backup_bytes = backup.ok_or_else(|| invalid_rollback_backup(&step.path))?;
                #[cfg(windows)]
                {
                    let parent = PatchParent::pin(&self.root, &root_identity, &step.path, false, true, None)?;
                    let file_name = full.file_name().ok_or_else(|| rollback_target_conflict(&step.path))?;
                    let tmp = parent.path.join(format!(".eb_rb_{}.tmp", uuid::Uuid::new_v4().simple()));
                    let res = (|| -> Result<(), BridgeError> {
                        let mut f = create_patch_stage(&tmp).map_err(patch_io_error)?;
                        f.write_all(&backup_bytes).map_err(patch_io_error)?;
                        f.sync_all().map_err(patch_io_error)?;
                        parent.verify_location(&step.path)?;
                        commit_patch_stage(&f, parent.directories.last().unwrap(), file_name, false).map_err(|err| {
                            if err.code == ErrorCode::VersionConflict {
                                rollback_target_conflict(&step.path)
                            } else {
                                err
                            }
                        })?;
                        Ok(())
                    })();
                    if res.is_err() {
                        let _ = fs::remove_file(&tmp);
                    }
                    res?;
                }
                #[cfg(not(windows))]
                {
                    if let Some(parent_dir) = full.parent() {
                        fs::create_dir_all(parent_dir).map_err(patch_io_error)?;
                    }
                    let tmp = full.with_file_name(format!(".eb_rb_{}.tmp", uuid::Uuid::new_v4().simple()));
                    let res = (|| -> Result<(), BridgeError> {
                        write_synced_new(&tmp, &backup_bytes)?;
                        commit_new_patch_file(&tmp, &full)
                    })();
                    if res.is_err() {
                        let _ = fs::remove_file(&tmp);
                    }
                    res?;
                }
                restored.push(step.path.clone());
                continue;
            }
            let verify_target = || {
                if self.current_root_identity()? != root_identity {
                    return Err(rollback_target_conflict(&step.path));
                }
                self.resolve_checked(&step.path, true)?;
                let (current, identity) = read_handle_verified(&full, &step.path)?;
                if identity != expected_fid || sha256_bytes(&current) != step.postimage_sha256 {
                    return Err(rollback_target_conflict(&step.path));
                }
                Ok(())
            };
            verify_target()?;
            let staged = if let Some(backup_bytes) = backup {
                let tmp = full.with_file_name(format!(".eb_rb_{}.tmp", uuid::Uuid::new_v4().simple()));
                {
                    let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(|e| {
                        BridgeError::new(ErrorCode::InternalError, format!("Rollback stage failed: {e}"), OriginLayer::FileService)
                    })?;
                    f.write_all(&backup_bytes).map_err(|e| {
                        BridgeError::new(ErrorCode::InternalError, format!("Rollback write failed: {e}"), OriginLayer::FileService)
                    })?;
                    f.sync_all().map_err(|e| {
                        BridgeError::new(ErrorCode::InternalError, format!("Rollback sync failed: {e}"), OriginLayer::FileService)
                    })?;
                }
                Some(tmp)
            } else {
                None
            };
            if let Some(tmp) = staged {
                verify_target()?;
                #[cfg(windows)]
                atomic_replace_file(&tmp, &full, &step.path)?;
                #[cfg(not(windows))]
                fs::rename(&tmp, &full).map_err(|e| {
                    BridgeError::new(ErrorCode::InternalError, format!("Rollback rename failed: {e}"), OriginLayer::FileService)
                })?;
            } else {
                fs::remove_file(&full).map_err(|e| {
                    BridgeError::new(ErrorCode::InternalError, format!("Remove created file failed: {e}"), OriginLayer::FileService)
                })?;
            }
            restored.push(step.path.clone());
        }
        journal.state = "rolled_back".to_string();
        persist_patch_journal(&journal_file, &journal)?;
        Ok(restored)
    }
}

pub(crate) fn write_synced_new(path: &Path, data: &[u8]) -> Result<(), BridgeError> {
    let mut file = File::create_new(path).map_err(patch_io_error)?;
    file.write_all(data).map_err(patch_io_error)?;
    file.sync_all().map_err(patch_io_error)
}

pub(crate) fn persist_patch_journal(path: &Path, journal: &PatchJournal) -> Result<(), BridgeError> {
    let staged = path.with_file_name(format!("journal-{}.tmp", uuid::Uuid::new_v4().simple()));
    let data = serde_json::to_vec_pretty(journal).map_err(|error| {
        BridgeError::new(ErrorCode::InternalError, format!("Patch journal serialization failed: {error}"), OriginLayer::FileService)
    })?;
    write_synced_new(&staged, &data)?;
    #[cfg(windows)]
    atomic_replace_file(&staged, path, "journal.json")?;
    #[cfg(not(windows))]
    fs::rename(&staged, path).map_err(patch_io_error)?;
    Ok(())
}

#[cfg(not(windows))]
fn commit_new_patch_file(staged: &Path, destination: &Path) -> Result<(), BridgeError> {
        fs::hard_link(staged, destination).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                patch_commit_conflict("create-only target")
            } else {
                patch_io_error(error)
            }
        })?;
        fs::remove_file(staged).map_err(patch_io_error)?;
    Ok(())
}

#[cfg(windows)]
fn verify_patch_preimage(path: &Path, relative: &str, expected_id: Option<&str>, expected_hash: &str, expected_size: usize) -> Result<File, BridgeError> {
    let mut file = open_patch_preimage(path).map_err(patch_io_error)?;
    let identity = file_identity_from_handle(&file)?;
    if identity.is_directory || identity.is_reparse_point || identity.n_links != 1
        || Some(identity.canonical_id().as_str()) != expected_id
        || identity.size_bytes != expected_size as u64
        || file_path_from_handle(&file)?.parent() != path.parent() {
        return Err(patch_commit_conflict(relative));
    }
    let mut content = Vec::new();
    (&mut file).take((expected_size as u64).saturating_add(1)).read_to_end(&mut content).map_err(patch_io_error)?;
    if content.len() != expected_size || sha256_bytes(&content) != expected_hash
        || file_identity_no_follow_named(path, relative)?.canonical_id() != identity.canonical_id() {
        return Err(patch_commit_conflict(relative));
    }
    Ok(file)
}

/// Open an existing delegated work-area target for commit-time preimage verification without following
/// reparse points, verifying exact casing, single-link identity (`n_links == 1`), and SHA-256 while
/// holding the handle open across replacement.
#[cfg(windows)]
pub(crate) fn verify_work_preimage_handle(
    root_path: &Path,
    path: &Path,
    relative: &str,
    expected_id: Option<&str>,
    expected_hash: &str,
    expected_size: usize,
) -> Result<File, BridgeError> {
    let mut file = match open_patch_preimage(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(patch_commit_conflict(relative));
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            // Opening a directory or NTFS junction without BACKUP_SEMANTICS fails with AccessDenied.
            if let Ok(meta_handle) = bridge_platform::windows::open_path_metadata_no_follow(path) {
                if let Ok(meta_id) = file_identity_from_handle(&meta_handle) {
                    if meta_id.is_reparse_point || meta_id.is_directory {
                        return Err(BridgeError::new(
                            ErrorCode::UnsupportedPathType,
                            format!("Target '{relative}' is a reparse point or directory and cannot be overwritten."),
                            OriginLayer::FileService,
                        ));
                    }
                }
            }
            return Err(patch_io_error(error));
        }
        Err(error) => return Err(patch_io_error(error)),
    };
    let identity = file_identity_from_handle(&file)?;
    if identity.is_directory || identity.is_reparse_point || identity.n_links != 1 {
        return Err(BridgeError::new(
            ErrorCode::UnsupportedPathType,
            format!("Target '{relative}' is not a regular single-link non-reparse file."),
            OriginLayer::FileService,
        ));
    }
    verify_opened_name(root_path, Path::new(relative), &file_path_from_handle(&file)?)?;
    if expected_id.is_some() && Some(identity.canonical_id().as_str()) != expected_id
        || identity.size_bytes != expected_size as u64
    {
        return Err(patch_commit_conflict(relative));
    }
    let mut content = Vec::with_capacity(expected_size);
    (&mut file)
        .take((expected_size as u64).saturating_add(1))
        .read_to_end(&mut content)
        .map_err(patch_io_error)?;
    if content.len() != expected_size
        || sha256_bytes(&content) != expected_hash
        || file_identity_no_follow_named(path, relative)?.canonical_id() != identity.canonical_id()
    {
        return Err(patch_commit_conflict(relative));
    }
    Ok(file)
}

/// Read an existing delegated work-area or remote-source file strictly through a no-follow handle,
/// refusing reparse points, directories, and multi-link files (`n_links != 1`) with `UnsupportedPathType`,
/// and refusing exact-casing / hidden mismatches with `BridgePolicyDenied`.
pub(crate) fn read_delegated_work_file_verified(
    _root: &Path,
    root_path_opt: Option<&Path>,
    full: &Path,
    relative: &str,
    max_bytes: u64,
) -> Result<(Vec<u8>, Option<String>), BridgeError> {
    #[cfg(windows)]
    let (mut file, canonical) = {
        let pre = match bridge_platform::windows::open_path_metadata_no_follow(full) {
            Ok(meta_handle) => file_identity_from_handle(&meta_handle)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(BridgeError::new(
                    ErrorCode::FileNotFound,
                    format!("File not found: {relative}"),
                    OriginLayer::FileService,
                ));
            }
            Err(error) => return Err(patch_io_error(error)),
        };
        if pre.is_reparse_point || pre.is_directory || pre.n_links != 1 {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("Target '{relative}' must be a regular single-link non-reparse file."),
                OriginLayer::FileService,
            ));
        }
        let file = open_read_no_follow(full).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                BridgeError::new(
                    ErrorCode::FileNotFound,
                    format!("File not found: {relative}"),
                    OriginLayer::FileService,
                )
            } else {
                patch_io_error(error)
            }
        })?;
        let open_id = file_identity_from_handle(&file)?;
        if open_id.is_reparse_point || open_id.is_directory || open_id.n_links != 1 {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("Target '{relative}' must be a regular single-link non-reparse file."),
                OriginLayer::FileService,
            ));
        }
        if open_id.canonical_id() != pre.canonical_id() {
            return Err(BridgeError::new(
                ErrorCode::StalePrecondition,
                "File identity changed concurrently between path check and handle open.",
                OriginLayer::FileService,
            ));
        }
        if let Some(root_path) = root_path_opt {
            verify_opened_name(root_path, Path::new(relative), &file_path_from_handle(&file)?)?;
        }
        if open_id.size_bytes > max_bytes {
            return Err(BridgeError::new(
                ErrorCode::ResourceBudgetExceeded,
                format!("File '{relative}' exceeds size limit of {max_bytes} bytes."),
                OriginLayer::FileService,
            ));
        }
        (file, Some(open_id.canonical_id()))
    };
    #[cfg(not(windows))]
    let (mut file, canonical) = {
        let _ = root_path_opt;
        let meta = fs::symlink_metadata(full).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                BridgeError::new(
                    ErrorCode::FileNotFound,
                    format!("File not found: {relative}"),
                    OriginLayer::FileService,
                )
            } else {
                patch_io_error(error)
            }
        })?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                format!("Target '{relative}' must be a regular single-link non-reparse file."),
                OriginLayer::FileService,
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.nlink() != 1 {
                return Err(BridgeError::new(
                    ErrorCode::UnsupportedPathType,
                    format!("Target '{relative}' must be a regular single-link non-reparse file."),
                    OriginLayer::FileService,
                ));
            }
        }
        if meta.len() > max_bytes {
            return Err(BridgeError::new(
                ErrorCode::ResourceBudgetExceeded,
                format!("File '{relative}' exceeds size limit of {max_bytes} bytes."),
                OriginLayer::FileService,
            ));
        }
        let file = File::open(full).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                BridgeError::new(
                    ErrorCode::FileNotFound,
                    format!("File not found: {relative}"),
                    OriginLayer::FileService,
                )
            } else {
                patch_io_error(error)
            }
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let opened = file.metadata().map_err(patch_io_error)?;
            if opened.dev() != meta.dev() || opened.ino() != meta.ino() || opened.nlink() != 1 {
                return Err(BridgeError::new(
                    ErrorCode::UnsupportedPathType,
                    format!("Target '{relative}' changed or has multiple links."),
                    OriginLayer::FileService,
                ));
            }
        }
        (file, None::<String>)
    };

    let expected = file.metadata().map(|m| m.len()).unwrap_or(0).min(max_bytes.saturating_add(1));
    let mut raw = Vec::with_capacity(expected as usize);
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(patch_io_error)?;
    if raw.len() as u64 > max_bytes {
        return Err(BridgeError::new(
            ErrorCode::ResourceBudgetExceeded,
            format!("File '{relative}' exceeds size limit of {max_bytes} bytes."),
            OriginLayer::FileService,
        ));
    }
    Ok((raw, canonical))
}

pub(crate) fn lock_patch_root(journal_dir: &Path, root_identity: &str) -> Result<File, BridgeError> {
    // Every CLI/HTTP patch and recovery operation sharing a state directory
    // takes the same OS lock before validating any file in this root.
    let directory = journal_dir.join("root-locks");
    fs::create_dir_all(&directory).map_err(patch_io_error)?;
    let scope = ScopedFiles::new(&directory, None)?;
    let name = format!("{}.lock", sha256_bytes(root_identity.as_bytes()));
    let (_, path) = scope.resolve_checked(&name, false)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(patch_io_error)?;
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(TryLockError::WouldBlock) => {
                return Err(BridgeError::new(
                    ErrorCode::ResourceBusy,
                    "A patch or recovery operation is already using this project root.",
                    OriginLayer::FileService,
                ).with_details(serde_json::json!({"retry_after_ms": 150, "reason": "patch_root_busy"})));
            }
            Err(TryLockError::Error(error)) => return Err(patch_io_error(error)),
        }
    }
}

pub(crate) fn patch_io_error(error: std::io::Error) -> BridgeError {
    BridgeError::new(ErrorCode::InternalError, format!("Patch I/O failed: {error}"), OriginLayer::FileService)
}

pub(crate) fn patch_commit_conflict(path: &str) -> BridgeError {
    BridgeError::new(ErrorCode::VersionConflict, format!("Patch target '{path}' changed before commit."), OriginLayer::FileService)
}

fn rollback_target_conflict(path: &str) -> BridgeError {
    BridgeError::new(
        ErrorCode::VersionConflict,
        format!("Refusing rollback: '{path}' changed after patch application."),
        OriginLayer::FileService,
    )
}

fn artifact_io_error(error: std::io::Error) -> BridgeError {
    BridgeError::new(ErrorCode::InternalError, format!("Artifact I/O failed: {error}"), OriginLayer::FileService)
}

fn unsafe_artifact() -> BridgeError {
    BridgeError::new(ErrorCode::PathOutsideRoot, "Artifact is outside the approved file scope or is not a regular single-link file.", OriginLayer::FileService)
}

fn invalid_rollback_backup(path: &str) -> BridgeError {
    BridgeError::new(
        ErrorCode::StalePrecondition,
        format!("Refusing rollback: no verified backup matches '{path}'."),
        OriginLayer::FileService,
    )
}

/// Open a file and verify its NTFS handle identity matches its pre-open no-follow identity,
/// preventing TOCTOU junction/reparse swaps between metadata check and read.
fn read_handle_verified(full: &Path, relative: &str) -> Result<(Vec<u8>, Option<String>), BridgeError> {
    #[cfg(windows)]
    let pre_id = {
        let id = file_identity_no_follow_named(full, relative)?;
        if id.is_reparse_point || id.is_directory {
            return Err(BridgeError::new(
                ErrorCode::UnsupportedPathType,
                "Target must be a regular non-reparse file.",
                OriginLayer::FileService,
            ));
        }
        id
    };
    let mut f = File::open(full).map_err(|e| {
        BridgeError::new(
            ErrorCode::FileNotFound,
            format!("Failed opening target '{relative}': {e}"),
            OriginLayer::FileService,
        )
    })?;
    #[cfg(windows)]
    let canonical = {
        let open_id = file_identity_from_handle(&f)?;
        if open_id.is_reparse_point || open_id.canonical_id() != pre_id.canonical_id() {
            return Err(BridgeError::new(
                ErrorCode::StalePrecondition,
                "File identity changed concurrently between path check and handle open.",
                OriginLayer::FileService,
            ));
        }
        Some(open_id.canonical_id())
    };
    #[cfg(not(windows))]
    let canonical: Option<String> = None;

    let mut raw = Vec::new();
    f.read_to_end(&mut raw).map_err(|e| {
        BridgeError::new(
            ErrorCode::InternalError,
            format!("Failed reading verified handle: {e}"),
            OriginLayer::FileService,
        )
    })?;
    Ok((raw, canonical))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_plan_preimage_crash_recovery_and_user_edit_protection() {
        let dir = tempfile::tempdir().unwrap();
        let proj = dir.path().join("proj");
        let journals = dir.path().join("journals");
        fs::create_dir_all(&proj).unwrap();
        fs::write(proj.join("a.txt"), "old_a\n").unwrap();
        fs::write(proj.join("b.txt"), "old_b\n").unwrap();

        let sf = ScopedFiles::new(&proj, None).unwrap();
        let ha = sf.read("a.txt", 0, 1024, false).unwrap().hash;
        let hb = sf.read("b.txt", 0, 1024, false).unwrap().hash;

        // 1. Stale preimage rejected with zero writes
        let bad = PatchPlanV04 {
            patch_plan_version: "0.4.0".into(),
            project_id: "project_1".into(),
            root_identity: None,
            operation_id: "op_bad".into(),
            task_id: None,
            summary: None,
            baseline_manifest_sha256: None,
            scope: vec![],
            edits: vec![PatchEditV04 {
                path: "a.txt".into(),
                content: "hacked\n".into(),
                expected_hash: Some("0".repeat(64)),
                expected_postimage_hash: None,
            }],
            verification_recipe: None,
            verification_command: None,
        };
        assert_eq!(
            sf.apply_patch_plan(&bad, &journals, None).unwrap_err().code,
            ErrorCode::VersionConflict
        );
        assert_eq!(fs::read_to_string(proj.join("a.txt")).unwrap(), "old_a\n");

        // 2. Crash mid-apply -> rollback cleanly restores step 0
        let plan = PatchPlanV04 {
            patch_plan_version: "0.4.0".into(),
            project_id: "project_1".into(),
            root_identity: None,
            operation_id: "op_crash".into(),
            task_id: None,
            summary: None,
            baseline_manifest_sha256: None,
            scope: vec![],
            edits: vec![
                PatchEditV04 {
                    path: "a.txt".into(),
                    content: "new_a\n".into(),
                    expected_hash: Some(ha.clone()),
                    expected_postimage_hash: None,
                },
                PatchEditV04 {
                    path: "b.txt".into(),
                    content: "new_b\n".into(),
                    expected_hash: Some(hb.clone()),
                    expected_postimage_hash: None,
                },
            ],
            verification_recipe: None,
            verification_command: None,
        };
        let interrupted = sf.apply_patch_plan(&plan, &journals, Some(0)).unwrap_err();
        assert_eq!(interrupted.code, ErrorCode::UnknownAfterRestart, "{interrupted:?}");
        let jid = fs::read_dir(&journals)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .file_name()
            .to_string_lossy()
            .to_string();
        assert_eq!(fs::read_to_string(proj.join("a.txt")).unwrap(), "new_a\n");
        let restored = sf.rollback_patch_journal(&journals, &jid).unwrap();
        assert_eq!(restored, vec!["a.txt"]);
        assert_eq!(fs::read_to_string(proj.join("a.txt")).unwrap(), "old_a\n");
        assert!(sf.rollback_patch_journal(&journals, &jid).unwrap().is_empty());

        let (res, journal) = sf.apply_patch_plan(&plan, &journals, None).unwrap();
        let record_path = journals.join(&res.journal_id).join("journal.json");
        let backup = journals.join(&res.journal_id).join("backups/step_000.bak");

        // Another directory has matching postimages, but it did not receive this patch.
        let other = dir.path().join("other");
        fs::create_dir(&other).unwrap();
        fs::write(other.join("a.txt"), "new_a\n").unwrap();
        fs::write(other.join("b.txt"), "new_b\n").unwrap();
        let other_files = ScopedFiles::new(&other, None).unwrap();
        assert_eq!(
            other_files.rollback_patch_journal(&journals, &res.journal_id).unwrap_err().code,
            ErrorCode::StalePrecondition
        );
        assert_eq!(fs::read_to_string(other.join("b.txt")).unwrap(), "new_b\n");

        // Old journals without root identity remain readable but require manual review.
        let mut legacy = serde_json::to_value(&journal).unwrap();
        legacy.as_object_mut().unwrap().remove("root_identity");
        fs::write(&record_path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(
            sf.rollback_patch_journal(&journals, &res.journal_id).unwrap_err().code,
            ErrorCode::StalePrecondition
        );
        fs::write(&record_path, serde_json::to_vec(&journal).unwrap()).unwrap();

        // A damaged first backup must not allow the valid second step to be rolled back.
        fs::write(&backup, "damaged backup\n").unwrap();
        assert_eq!(
            sf.rollback_patch_journal(&journals, &res.journal_id).unwrap_err().code,
            ErrorCode::StalePrecondition
        );
        assert_eq!(fs::read_to_string(proj.join("b.txt")).unwrap(), "new_b\n");
        fs::write(&backup, "old_a\n").unwrap();

        // A later deletion is a user change too.
        fs::remove_file(proj.join("a.txt")).unwrap();
        assert_eq!(
            sf.rollback_patch_journal(&journals, &res.journal_id).unwrap_err().code,
            ErrorCode::VersionConflict
        );
        assert!(!proj.join("a.txt").exists());
        assert_eq!(fs::read_to_string(proj.join("b.txt")).unwrap(), "new_b\n");

        // Apply cleanly, then simulate user edit -> rollback MUST REFUSE!
        fs::write(proj.join("a.txt"), "new_a\n").unwrap();
        assert_eq!(fs::read_to_string(proj.join("a.txt")).unwrap(), "new_a\n");
        fs::write(proj.join("a.txt"), "user_later_edit\n").unwrap();
        assert_eq!(
            sf.rollback_patch_journal(&journals, &res.journal_id).unwrap_err().code,
            ErrorCode::VersionConflict
        );
        assert_eq!(fs::read_to_string(proj.join("a.txt")).unwrap(), "user_later_edit\n");
    }

    #[test]
    fn sorted_walk_orders_by_name_and_skips_generated_and_secret_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for sub in ["b/inner", "a", ".git/objects", "node_modules/pkg", "empty"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        for file in ["z.txt", "b/2.txt", "b/inner/deep.txt", "a/1.txt", ".git/objects/x", "node_modules/pkg/x", ".env", "B.txt"] {
            fs::write(root.join(file), b"x").unwrap();
        }
        let names = |max_depth: usize, exclude_generated: bool| -> Vec<String> {
            SortedWalk::new(root, root, max_depth, exclude_generated, "x")
                .map(|e| e.unwrap().path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"))
                .collect()
        };
        assert_eq!(
            names(usize::MAX, true),
            ["B.txt", "a", "a/1.txt", "b", "b/2.txt", "b/inner", "b/inner/deep.txt", "empty", "z.txt"]
        );
        assert_eq!(names(1, true), ["B.txt", "a", "b", "empty", "z.txt"]);
        assert_eq!(names(2, true), ["B.txt", "a", "a/1.txt", "b", "b/2.txt", "b/inner", "empty", "z.txt"]);
        assert_eq!(names(1, false), [".git", "B.txt", "a", "b", "empty", "node_modules", "z.txt"]);
    }

    #[test]
    fn credential_folders_are_hidden_from_remote_principals_and_left_to_the_owner() {
        let parts = |path: &str| path.split('/').map(str::to_owned).collect::<Vec<_>>();
        for path in [".git/config", "sub/.GIT/HEAD", ".ssh/config", "home/.aws/credentials", ".claude/settings.json",
            "auth.json", "conf/Auth.YAML", "kubeconfig", "android/release.JKS", "src/.edge-bridge-tmp-1f2e"] {
            assert!(is_hidden_from_remote(&parts(path)), "{path}");
            assert!(!is_denied_secret_path(&parts(path)), "{path}");
        }
        for path in [".env", "certs/site.pem", "credentials.json"] {
            assert!(is_hidden_from_remote(&parts(path)) && is_denied_secret_path(&parts(path)), "{path}");
        }
        for path in ["src/auth.rs", "docs/git.md", "authors.json", "gitconfig.md", "tools/ssh/readme.md"] {
            assert!(!is_hidden_from_remote(&parts(path)), "{path}");
        }
    }

    #[test]
    fn search_takes_a_single_file_and_skips_a_named_generated_directory() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/pkg")).unwrap();
        fs::write(dir.path().join("src/lib.rs"), "one needle\ntwo needle\n").unwrap();
        fs::write(dir.path().join("src/other.rs"), "needle\n").unwrap();
        fs::write(dir.path().join("node_modules/pkg/index.js"), "needle\n").unwrap();
        let files = ScopedFiles::new(dir.path(), None).unwrap();
        let paths = |rel: &str, limit: usize, exclude: bool| -> Vec<(String, usize)> {
            files.search(rel, "needle", limit, exclude, true).unwrap().into_iter().map(|h| (h.path, h.line)).collect()
        };
        assert_eq!(paths("src/lib.rs", 10, true), [("src/lib.rs".to_string(), 1), ("src/lib.rs".to_string(), 2)]);
        assert_eq!(paths("src", 1, true), [("src/lib.rs".to_string(), 1)]);
        assert!(paths("node_modules", 10, true).is_empty());
        assert_eq!(paths("node_modules", 10, false), [("node_modules/pkg/index.js".to_string(), 1)]);
        assert_eq!(paths(".", 10, true).len(), 3);
        assert_eq!(SortedWalk::new(dir.path(), dir.path(), 0, true, "x").count(), 0);
    }

    #[test]
    fn sorted_walk_counts_every_entry_read_and_stops_after_a_refusal() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("only/dirs")).unwrap();
        fs::write(dir.path().join("f.txt"), b"x").unwrap();
        let mut walk = SortedWalk::new(dir.path(), dir.path(), usize::MAX, true, "The project");
        assert_eq!(walk.by_ref().count(), 3);
        // Directories count too, so a tree without files cannot be walked for free.
        assert_eq!(walk.seen, 3);

        let mut full = SortedWalk::new(dir.path(), dir.path(), usize::MAX, true, "The project");
        full.seen = MAX_WALK_ENTRIES;
        assert_eq!(full.next().unwrap().err().unwrap().code, ErrorCode::ResourceBudgetExceeded);
        assert!(full.next().is_none());
    }

    #[test]
    fn walk_budget_refuses_at_the_limit() {
        assert!(within_walk_budget(MAX_WALK_ENTRIES - 1, "x").is_ok());
        let refused = within_walk_budget(MAX_WALK_ENTRIES, "The project").unwrap_err();
        assert_eq!(refused.code, ErrorCode::ResourceBudgetExceeded);
    }

    #[test]
    fn manifest_hashes_and_sizes_match_the_file_bytes() {
        let dir = tempfile::tempdir().unwrap();
        // Larger than the hashing buffer, so several reads feed one digest.
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(dir.path().join("big.bin"), &big).unwrap();
        fs::write(dir.path().join("empty.txt"), b"").unwrap();
        let manifest = ScopedFiles::new(dir.path(), None).unwrap().build_manifest(true).unwrap();
        let found: Vec<(&str, u64, &str)> = manifest
            .entries
            .iter()
            .map(|e| (e.path.as_str(), e.size, e.sha256.as_str()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("big.bin", 200_000, sha256_bytes(&big).as_str()),
                ("empty.txt", 0, sha256_bytes(b"").as_str()),
            ]
        );
        assert_eq!(manifest.total_bytes, 200_000);
    }

    #[test]
    fn char_page_matches_a_per_character_slice() {
        // One, two, three and four byte characters, and right-to-left text.
        let text = "aé日😀b عربي z";
        let chars: Vec<char> = text.chars().collect();
        for offset in 0..chars.len() + 3 {
            for limit in 1..chars.len() + 3 {
                let start = offset.min(chars.len());
                let end = (start + limit).min(chars.len());
                let expected: String = chars[start..end].iter().collect();
                assert_eq!(
                    char_page(text, offset, limit),
                    (expected.as_str(), start, end, end < chars.len()),
                    "offset {offset} limit {limit}"
                );
            }
        }
        assert_eq!(char_page("", 0, 5), ("", 0, 0, false));
    }

    #[test]
    fn secret_canaries_are_denied() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env"), "SYNTHETIC_CANARY=1").unwrap();
        fs::write(dir.path().join("secrets.js"), "module.exports = {}").unwrap();
        let sf = ScopedFiles::new(dir.path(), None).unwrap();
        assert_eq!(
            sf.read(".env", 0, 1024, false).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );
        assert_eq!(
            sf.read("secrets.js", 0, 1024, false).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );
    }

    #[test]
    fn create_only_commit_never_replaces_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("stage.tmp");
        let destination = dir.path().join("new.txt");
        fs::write(&destination, b"user saved first").unwrap();
        #[cfg(windows)]
        let error = {
            let parent = open_patch_directory(dir.path()).unwrap();
            let mut file = create_patch_stage(&staged).unwrap();
            file.write_all(b"proposed").unwrap();
            file.sync_all().unwrap();
            commit_patch_stage(&file, &parent, destination.file_name().unwrap(), false).unwrap_err()
        };
        #[cfg(not(windows))]
        let error = {
            fs::write(&staged, b"proposed").unwrap();
            commit_new_patch_file(&staged, &destination).unwrap_err()
        };
        assert_eq!(error.code, ErrorCode::VersionConflict, "{error:?}");
        assert_eq!(fs::read(&destination).unwrap(), b"user saved first");
        assert_eq!(fs::read(&staged).unwrap(), b"proposed");
    }

    #[cfg(windows)]
    #[test]
    fn delegated_parent_name_must_match_exactly_and_pass_secret_check() {
        let root = Path::new(r"C:\project");
        let normal = root.join(r"_pro\Reports");
        verify_delegated_parent_name(root, &normal, &normal).unwrap();
        // Exercise the observed-name comparison without requiring NTFS short-name creation.
        for (requested, observed) in [
            (root.join(r"_pro\REPORT~1"), normal.clone()),
            (root.join(r"_pro\reports"), normal),
            (root.join(r"_pro\credentials.backup"), root.join(r"_pro\credentials.backup")),
        ] {
            let err = verify_delegated_parent_name(root, &requested, &observed).unwrap_err();
            assert_eq!(err.code, ErrorCode::BridgePolicyDenied);
            assert_eq!(
                err.next_action,
                "Use the exact on-disk long path name; protected or mismatched paths cannot be accessed remotely.",
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn scoped_identity_error_includes_only_the_relative_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reports").join("missing.txt");
        let error = file_identity_no_follow_named(&path, "reports/missing.txt").unwrap_err();
        assert_eq!(error.code, ErrorCode::FileNotFound);
        assert!(error.message.contains("reports/missing.txt"));
        assert!(!error.message.contains(&*dir.path().to_string_lossy()));
    }

    #[cfg(windows)]
    #[test]
    fn remote_read_compares_every_observed_component_and_checks_secret_names() {
        let root = Path::new(r"\\?\C:\project");
        for (requested, observed) in [
            ("Notes/summary.txt", r"Notes\Summary.txt"),
            ("Notes/Summary.txt", r"Other\Summary.txt"),
            ("Notes/Summary.txt", r"Notes\Other.txt"),
            ("credentials.json", "credentials.json"),
            ("secrets.data/summary.txt", r"secrets.data\summary.txt"),
        ] {
            let err = verify_opened_name(root, Path::new(requested), &root.join(observed)).unwrap_err();
            assert_eq!(err.code, ErrorCode::BridgePolicyDenied);
            assert_eq!(
                err.next_action,
                "Use the exact on-disk long path name; protected or mismatched paths cannot be accessed remotely.",
            );
        }
        verify_opened_name(root, Path::new("Notes/Summary.txt"), &root.join(r"Notes\Summary.txt")).unwrap();
    }

    #[test]
    fn delegated_quota_checks_call_totals_on_empty_and_missing_folders() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("empty")).unwrap();
        for folder in ["empty", "missing"] {
            for totals in [
                (DELEGATED_WRITE_MAX_SCOPE_FILES + 1, 0),
                (0, DELEGATED_WRITE_MAX_SCOPE_BYTES + 1),
            ] {
                let error = check_delegated_write_quota(dir.path(), BTreeMap::from([(folder, totals)]), &BTreeSet::new()).unwrap_err();
                assert_eq!(error.code, ErrorCode::ResourceBudgetExceeded);
            }
            check_delegated_write_quota(dir.path(), BTreeMap::from([(
                folder, (DELEGATED_WRITE_MAX_SCOPE_FILES, DELEGATED_WRITE_MAX_SCOPE_BYTES),
            )]), &BTreeSet::new()).unwrap();
        }
    }

    #[test]
    fn delegated_quota_bounds_directory_entries_even_without_files() {
        let dir = tempfile::tempdir().unwrap();
        let scope = dir.path().join("_pro");
        fs::create_dir(&scope).unwrap();
        for index in 0..DELEGATED_WRITE_MAX_WALK_ENTRIES {
            fs::create_dir(scope.join(index.to_string())).unwrap();
        }
        let check = || check_delegated_write_quota(dir.path(), BTreeMap::from([("_pro", (0, 0))]), &BTreeSet::new());
        check().unwrap();
        fs::create_dir(scope.join("over-budget")).unwrap();
        assert_eq!(check().unwrap_err().code, ErrorCode::ResourceBudgetExceeded);
    }

    #[test]
    fn delegated_quota_reserves_unique_missing_parents_and_new_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let mailbox = root.join("_pro");
        let journals = dir.path().join("journals");
        fs::create_dir_all(&mailbox).unwrap();
        for index in 0..DELEGATED_WRITE_MAX_WALK_ENTRIES - 4 {
            fs::create_dir(mailbox.join(index.to_string())).unwrap();
        }
        let scope = ScopedFiles::new(&root, None).unwrap();
        let plan: PatchPlanV04 = serde_json::from_value(serde_json::json!({
            "project_id": "project_fixture", "operation_id": "op_quota",
            "edits": [
                {"path": "_pro/new/deep/one.md", "content": "one"},
                {"path": "_pro/new/deep/two.md", "content": "two"},
            ],
        })).unwrap();
        let scoped = ["_pro/**".into()];
        fs::create_dir(mailbox.join("over-budget")).unwrap();
        let error = scope.apply_delegated_creates(&plan, &journals, &scoped, |_| Ok(())).unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceBudgetExceeded);
        assert!(!mailbox.join("new").exists());
        assert!(!fs::read_dir(&journals).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with("pjr_")));

        fs::remove_dir(mailbox.join("over-budget")).unwrap();
        let (applied, _) = scope.apply_delegated_creates(&plan, &journals, &scoped, |_| Ok(())).unwrap();
        assert_eq!(applied.files_applied.len(), 2);
        assert_eq!(fs::read_to_string(mailbox.join("new/deep/two.md")).unwrap(), "two");
    }

    #[test]
    fn delegated_quota_does_not_follow_directory_links() {
        let dir = tempfile::tempdir().unwrap();
        let scope = dir.path().join("_pro");
        let outside = dir.path().join("outside");
        fs::create_dir(&scope).unwrap();
        fs::create_dir(&outside).unwrap();
        File::create(outside.join("large-file")).unwrap()
            .set_len(DELEGATED_WRITE_MAX_SCOPE_BYTES).unwrap();
        let link = scope.join("linked-directory");
        #[cfg(windows)]
        {
            let result = std::process::Command::new("cmd.exe")
                .args(["/D", "/C", "mklink", "/J"])
                .arg(&link).arg(&outside).output().unwrap();
            assert!(result.status.success(), "{result:?}");
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        check_delegated_write_quota(dir.path(), BTreeMap::from([("_pro", (1, 1))]), &BTreeSet::new()).unwrap();
        #[cfg(windows)]
        fs::remove_dir(link).unwrap();
        #[cfg(unix)]
        fs::remove_file(link).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn delegated_rollback_keeps_original_denial_and_undoes_unblocked_steps() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let journals = dir.path().join("journals");
        fs::create_dir(&root).unwrap();
        let scope = ScopedFiles::new(&root, None).unwrap();
        let plan: PatchPlanV04 = serde_json::from_value(serde_json::json!({
            "project_id": "project_fixture", "operation_id": "op_rollback",
            "edits": [
                {"path": "_pro/first.md", "content": "first"},
                {"path": "_pro/second.md", "content": "second"},
                {"path": "_pro/third.md", "content": "third"},
            ],
        })).unwrap();
        let error = scope.apply_delegated_creates(&plan, &journals, &["_pro/**".into()], |path| {
            if path != "_pro/third.md" {
                return Ok(());
            }
            let journal_id = fs::read_dir(&journals).unwrap().filter_map(Result::ok)
                .find(|entry| entry.file_name().to_string_lossy().starts_with("pjr_")).unwrap().file_name();
            // Occupy the second stage's old name to make only its undo fail.
            let stage = format!(".eb_stage_{}_1.tmp", journal_id.to_string_lossy());
            fs::write(root.join("_pro").join(stage), "unrelated test fixture").unwrap();
            Err(BridgeError::new(ErrorCode::BridgePolicyDenied, "Fixture denial.", OriginLayer::Policy))
        }).unwrap_err();
        assert_eq!(error.code, ErrorCode::BridgePolicyDenied);
        assert_eq!(error.message, "Fixture denial.");
        let details = error.details.unwrap();
        assert_eq!(details["rollback_failed"], serde_json::json!(["_pro/second.md"]));
        assert_eq!(details["stage_cleanup_failed"], serde_json::json!([]));
        assert_eq!(details["journal_update_failed"], false);
        assert!(!root.join("_pro/first.md").exists());
        assert_eq!(fs::read_to_string(root.join("_pro/second.md")).unwrap(), "second");
        assert!(!root.join("_pro/third.md").exists());
        let journal = journals.join(details["journal_id"].as_str().unwrap()).join("journal.json");
        let journal: PatchJournal = serde_json::from_slice(&fs::read(journal).unwrap()).unwrap();
        assert_eq!(journal.state, "rollback_incomplete");
        assert_eq!(journal.steps.iter().map(|step| step.committed).collect::<Vec<_>>(), [false, true, false]);
    }

    #[test]
    fn delegated_stage_cleanup_failure_keeps_a_recovery_journal() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let journals = dir.path().join("journals");
        let mailbox = root.join("_pro");
        fs::create_dir_all(&mailbox).unwrap();
        let scope = ScopedFiles::new(&root, None).unwrap();
        let plan: PatchPlanV04 = serde_json::from_value(serde_json::json!({
            "project_id": "project_fixture", "operation_id": "op_cleanup",
            "edits": [
                {"path": "_pro/first.md", "content": "first"},
                {"path": "_pro/second.md", "content": "second"},
            ],
        })).unwrap();
        let error = scope.apply_patch_plan_inner(&plan, &journals, None, Some(DelegatedPatch {
            scope: &["_pro/**".into()],
            authorize_commit: &|path| {
                if path == "_pro/first.md" {
                    Ok(())
                } else {
                    Err(BridgeError::new(ErrorCode::BridgePolicyDenied, "Fixture denial.", OriginLayer::Policy))
                }
            },
            remove_stage: |path| {
                if path.file_name().unwrap().to_string_lossy().ends_with("_1.tmp") {
                    Err(std::io::ErrorKind::PermissionDenied.into())
                } else {
                    fs::remove_file(path)
                }
            },
        })).unwrap_err();
        assert_eq!(error.code, ErrorCode::BridgePolicyDenied);
        assert!(!mailbox.join("first.md").exists());
        assert!(!mailbox.join("second.md").exists());
        let details = error.details.unwrap();
        assert_eq!(details["rollback_failed"], serde_json::json!([]));
        let journal_id = details["journal_id"].as_str().unwrap();
        let stage = format!("_pro/.eb_stage_{journal_id}_1.tmp");
        assert_eq!(details["stage_cleanup_failed"], serde_json::json!([stage]));
        let journal = journals.join(journal_id).join("journal.json");
        let journal: PatchJournal = serde_json::from_slice(&fs::read(journal).unwrap()).unwrap();
        assert_eq!(journal.state, "rollback_incomplete");
        assert_eq!(journal.stage_cleanup_failed, [stage.clone()]);
        assert!(journal.steps.iter().all(|step| !step.committed));
        assert!(root.join(stage).is_file());
    }

    #[cfg(windows)]
    #[test]
    fn patch_preimage_guard_checks_edit_with_same_identity_and_pins_parent() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let source = root.join("nested");
        fs::create_dir_all(&source).unwrap();
        let scope = ScopedFiles::new(&root, None).unwrap();
        let root_id = scope.current_root_identity().unwrap();
        let location = PatchParent::pin(&root, &root_id, "nested/doc.txt", false, true, None).unwrap();
        let path = location.path.join("doc.txt");
        fs::write(&path, b"before").unwrap();
        let original = file_identity_no_follow_named(&path, "file").unwrap().canonical_id();
        fs::write(&path, b"edited").unwrap();
        assert_eq!(file_identity_no_follow_named(&path, "file").unwrap().canonical_id(), original);
        assert_eq!(
            verify_patch_preimage(&path, "nested/doc.txt", Some(&original), &sha256_bytes(b"before"), 6).unwrap_err().code,
            ErrorCode::VersionConflict,
        );
        assert_eq!(fs::read(&path).unwrap(), b"edited");
        assert!(fs::rename(&source, root.join("moved")).is_err());
        drop(location);
        fs::rename(source, root.join("moved")).unwrap();
    }

    #[test]
    fn artifact_digest_supports_binary_contents_and_rejects_multiple_links() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("reports");
        fs::create_dir(&nested).unwrap();
        let artifact = nested.join("fixture.bin");
        let data = [0u8, 7, 0, 128, 255];
        fs::write(&artifact, data).unwrap();
        let scope = ScopedFiles::new(dir.path(), None).unwrap();
        let digest = sha256_bytes(&data);
        assert!(scope.verify_artifact_digest("reports/fixture.bin", data.len() as u64, &digest).unwrap());
        assert!(!scope.verify_artifact_digest("reports/fixture.bin", data.len() as u64 + 1, &digest).unwrap());
        #[cfg(any(windows, unix))]
        {
            fs::hard_link(&artifact, nested.join("alias.bin")).unwrap();
            assert!(scope.verify_artifact_digest("reports/fixture.bin", data.len() as u64, &digest).is_err());
        }
    }

    #[test]
    fn delegated_patch_plan_expected_hash_and_commit_time_conflict_return_actionable_next_action() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let journals = dir.path().join("journals");
        fs::create_dir_all(root.join("_pro").join("reports")).unwrap();
        fs::create_dir_all(&journals).unwrap();
        let scope = ScopedFiles::new(&root, None).unwrap();
        let granted = ["_pro/**".to_string()];

        // 1. Delegated expected_hash refusal inside apply_patch_plan_inner.
        let with_hash: PatchPlanV04 = serde_json::from_value(serde_json::json!({
            "project_id": "project_fixture",
            "operation_id": "op_delegated_expected_hash",
            "edits": [{
                "path": "_pro/reports/with_hash.md",
                "content": "denied",
                "expected_hash": sha256_bytes(b"old"),
            }],
        })).unwrap();
        let hash_err = scope.apply_delegated_creates(&with_hash, &journals, &granted, |_| Ok(())).unwrap_err();
        assert_eq!(hash_err.code, ErrorCode::BridgePolicyDenied);
        assert_eq!(
            hash_err.next_action,
            "Omit expected_hash (or set it to null) and choose a new file name inside the granted writable path; delegated writes are create-only.",
        );

        // 2. Delegated create-only conflict at commit time (file appears between staging and commit, deterministically via authorize_commit).
        let commit_plan: PatchPlanV04 = serde_json::from_value(serde_json::json!({
            "project_id": "project_fixture",
            "operation_id": "op_commit_conflict",
            "edits": [{
                "path": "_pro/reports/raced.md",
                "content": "proposed",
            }],
        })).unwrap();
        let conflict_err = scope.apply_delegated_creates(&commit_plan, &journals, &granted, |rel| {
            fs::write(root.join(rel), b"created before commit").unwrap();
            Ok(())
        }).unwrap_err();
        assert_eq!(conflict_err.code, ErrorCode::VersionConflict);
        assert_eq!(conflict_err.next_action, DELEGATED_CREATE_ONLY_NEXT_ACTION);
        assert_eq!(fs::read(root.join("_pro/reports/raced.md")).unwrap(), b"created before commit");
    }

    #[test]
    fn read_with_options_line_ranges_lf_crlf_utf8_and_validation() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("lf.txt"), "line1\nline2\nline3\nline4\n").unwrap();
        fs::write(root.join("crlf.txt"), "one\r\ntwo\r\nthree\r\n").unwrap();
        fs::write(root.join("utf8.txt"), "héllo\n世界\n😀end").unwrap();
        fs::write(root.join("empty.txt"), "").unwrap();
        let long_content: String = (1..=2005).map(|i| format!("L{i}\n")).collect();
        fs::write(root.join("long.txt"), &long_content).unwrap();

        let sf = ScopedFiles::new(root, None).unwrap();

        // Standard offset read omits optional line fields in JSON.
        let plain = sf.read("lf.txt", 0, 1024, false).unwrap();
        let plain_json = serde_json::to_value(&plain).unwrap();
        assert!(plain_json.get("total_lines").is_none());
        assert!(plain_json.get("start_line").is_none());
        assert!(plain_json.get("end_line").is_none());

        // LF line range preserves full-file hash and reports exact char offset and line bounds.
        let lf = sf.read_with_options("lf.txt", 0, 1024, false, Some(2), Some(3)).unwrap();
        assert_eq!(lf.content, "line2\nline3\n");
        assert_eq!(lf.offset, 6);
        assert_eq!(lf.next_offset, None);
        assert!(!lf.truncated);
        assert_eq!(lf.line_ending, "LF");
        assert_eq!(lf.hash, plain.hash);
        assert_eq!(lf.page_hash, sha256_bytes(b"line2\nline3\n"));
        assert_eq!(lf.total_lines, Some(4));
        assert_eq!(lf.start_line, Some(2));
        assert_eq!(lf.end_line, Some(3));

        // CRLF line range preserves \r\n.
        let crlf = sf.read_with_options("crlf.txt", 0, 1024, false, Some(2), Some(2)).unwrap();
        assert_eq!(crlf.content, "two\r\n");
        assert_eq!(crlf.offset, 5);
        assert_eq!(crlf.line_ending, "CRLF");
        assert_eq!(crlf.total_lines, Some(3));
        assert_eq!(crlf.start_line, Some(2));
        assert_eq!(crlf.end_line, Some(2));

        // UTF-8 multibyte chars count characters for offset and preserve exact bytes.
        let utf8 = sf.read_with_options("utf8.txt", 0, 1024, false, Some(2), Some(3)).unwrap();
        assert_eq!(utf8.content, "世界\n😀end");
        assert_eq!(utf8.offset, "héllo\n".chars().count());
        assert_eq!(utf8.total_lines, Some(3));
        assert_eq!(utf8.start_line, Some(2));
        assert_eq!(utf8.end_line, Some(3));

        // end_line only starts at line 1; start_line past EOF returns empty slice; empty file has 0 lines.
        let head = sf.read_with_options("lf.txt", 0, 1024, false, None, Some(2)).unwrap();
        assert_eq!(head.content, "line1\nline2\n");
        assert_eq!((head.start_line, head.end_line, head.total_lines), (Some(1), Some(2), Some(4)));

        let past = sf.read_with_options("lf.txt", 0, 1024, false, Some(10), Some(20)).unwrap();
        assert_eq!(past.content, "");
        assert_eq!((past.start_line, past.end_line, past.total_lines), (None, None, Some(4)));

        let empty = sf.read_with_options("empty.txt", 0, 1024, false, Some(1), Some(5)).unwrap();
        assert_eq!(empty.content, "");
        assert_eq!((empty.start_line, empty.end_line, empty.total_lines), (None, None, Some(0)));

        // Character limit truncation inside line range sets truncated and next_offset cleanly.
        let trunc = sf.read_with_options("lf.txt", 0, 8, false, Some(2), Some(4)).unwrap();
        assert_eq!(trunc.content, "line2\nli");
        assert_eq!(trunc.offset, 6);
        assert!(trunc.truncated);
        assert_eq!(trunc.next_offset, Some(14));
        assert_eq!((trunc.start_line, trunc.end_line), (Some(2), Some(3)));

        // Open-ended start_line caps at MAX_READ_LINES (2000) and reports truncated.
        let capped = sf.read_with_options("long.txt", 0, MAX_PAGE_BYTES, false, Some(1), None).unwrap();
        assert!(capped.truncated);
        assert!(capped.next_offset.is_some());
        assert_eq!(capped.total_lines, Some(2005));
        assert_eq!(capped.start_line, Some(1));
        assert_eq!(capped.end_line, Some(MAX_READ_LINES));

        // Exact boundary 1..=2000 succeeds; 1..=2001 fails.
        assert!(sf.read_with_options("long.txt", 0, MAX_PAGE_BYTES, false, Some(1), Some(2000)).is_ok());

        // Batch read mixes line ranges and character offsets in one call.
        let batch = sf.read_batch(&[
            BatchReadItemRequest {
                path: "lf.txt".into(),
                offset: 0,
                limit: 1024,
                lossy_utf8: false,
                start_line: Some(2),
                end_line: Some(2),
            },
            BatchReadItemRequest {
                path: "crlf.txt".into(),
                offset: 5,
                limit: 5,
                lossy_utf8: false,
                start_line: None,
                end_line: None,
            },
        ]).unwrap();
        assert!(batch[0].ok);
        assert_eq!(batch[0].result.as_ref().unwrap().content, "line2\n");
        assert_eq!(batch[0].result.as_ref().unwrap().start_line, Some(2));
        assert!(batch[1].ok);
        assert_eq!(batch[1].result.as_ref().unwrap().content, "two\r\n");
        assert_eq!(batch[1].result.as_ref().unwrap().start_line, None);

        // Negative validation cases.
        for (offset, s, e) in [
            (0, Some(0), Some(1)),
            (0, Some(1), Some(0)),
            (0, Some(3), Some(2)),
            (0, Some(1), Some(2001)),
            (1, Some(1), Some(2)),
            (5, None, Some(2)),
        ] {
            let err = sf.read_with_options("lf.txt", offset, 1024, false, s, e).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "offset={offset} s={s:?} e={e:?}");
        }
    }

    #[test]
    fn search_with_options_context_glob_regex_and_validation() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("src")).unwrap();
        let long_ctx = "x".repeat(300);
        fs::write(
            root.join("src/app.py"),
            format!("l1\n{long_ctx}\ndef compute_42():\n    return 42\nl5\n"),
        ).unwrap();
        fs::write(root.join("src/readme.md"), "def compute_42(): docs\n").unwrap();

        let sf = ScopedFiles::new(root, None).unwrap();

        // Context lines + file_glob + regex.
        let hits = sf
            .search_with_options(".", r"def\s+compute_\d+", 10, true, false, 2, Some("*.py"), true)
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "src/app.py");
        assert_eq!(hits[0].line, 3);
        assert_eq!(hits[0].preview, "def compute_42():");
        assert_eq!(hits[0].context_before.len(), 2);
        assert_eq!(hits[0].context_before[0], "l1");
        assert_eq!(hits[0].context_before[1].chars().count(), 240);
        assert_eq!(hits[0].context_after, vec!["    return 42", "l5"]);

        // Case sensitivity with regex.
        assert!(sf.search_with_options(".", "DEF\\s+COMPUTE", 10, true, true, 0, Some("*.py"), true).unwrap().is_empty());
        assert_eq!(sf.search_with_options(".", "DEF\\s+COMPUTE", 10, true, false, 0, Some("*.py"), true).unwrap().len(), 1);

        // context_lines == 0 omits context fields from JSON.
        let plain_hits = sf.search("src/app.py", "compute_42", 10, true, false).unwrap();
        let hit_json = serde_json::to_value(&plain_hits[0]).unwrap();
        assert!(hit_json.get("context_before").is_none());
        assert!(hit_json.get("context_after").is_none());

        // Single-file search respects file_glob.
        assert!(sf.search_with_options("src/app.py", "compute_42", 10, true, false, 0, Some("*.rs"), false).unwrap().is_empty());

        // Validation failures.
        assert_eq!(
            sf.search_with_options(".", "compute", 10, true, false, 6, None, false).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            sf.search_with_options(".", "[unclosed", 10, true, false, 0, None, true).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            sf.search_with_options(".", "a{50000}", 10, true, false, 0, None, true).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        let too_long = "a".repeat(MAX_FILE_GLOB_BYTES + 1);
        for bad_glob in ["", too_long.as_str(), "src/*.py", r"src\*.py", "..*.py", "a:b", "é*.py"] {
            let err = sf.search_with_options(".", "compute", 10, true, false, 0, Some(bad_glob), false).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "glob={bad_glob}");
        }
    }

    #[test]
    fn list_with_max_limit_supports_500_while_list_stays_capped_at_100() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..250 {
            fs::write(dir.path().join(format!("f_{i:03}.txt")), "x").unwrap();
        }
        let sf = ScopedFiles::new(dir.path(), None).unwrap();
        let (capped, next) = sf.list(".", false, 1, true, 0, 250).unwrap();
        assert_eq!(capped.len(), 100);
        assert_eq!(next, Some(100));

        let (wide, next_wide) = sf.list_with_max_limit(".", false, 1, true, 0, 250, 500).unwrap();
        assert_eq!(wide.len(), 250);
        assert_eq!(next_wide, None);
    }

    #[test]
    fn remote_read_options_enforce_hidden_traversal_junction_shortname_and_case_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let outside = dir.path().join("outside");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("src/App.py"), "SECRET_TOKEN_XYZ=visible\n").unwrap();
        fs::write(root.join(".env"), "SECRET_TOKEN_XYZ=hidden_env\n").unwrap();
        fs::write(root.join(".git/config"), "SECRET_TOKEN_XYZ=hidden_git\n").unwrap();
        fs::write(root.join("auth.json"), "{\"tok\":\"SECRET_TOKEN_XYZ\"}\n").unwrap();
        fs::write(outside.join("leak.py"), "SECRET_TOKEN_XYZ=outside\n").unwrap();

        let link = root.join("src").join("linked");
        #[cfg(windows)]
        {
            let out = std::process::Command::new("cmd.exe")
                .args(["/D", "/C", "mklink", "/J"])
                .arg(&link)
                .arg(&outside)
                .output()
                .unwrap();
            assert!(out.status.success(), "{out:?}");
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let remote = ScopedFiles::new_remote_read(&root, None).unwrap();

        // Regex search never surfaces hidden files or junction targets.
        let hits = remote
            .search_with_options(".", "SECRET_TOKEN_.*", 50, false, false, 1, None, true)
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "src/App.py");

        // Hidden files refused with BridgePolicyDenied even with start_line.
        for secret in [".env", ".git/config", "auth.json"] {
            assert_eq!(
                remote.read_with_options(secret, 0, 1024, false, Some(1), Some(1)).unwrap_err().code,
                ErrorCode::BridgePolicyDenied,
                "{secret}"
            );
        }

        // Traversal refused with PathOutsideRoot.
        assert_eq!(
            remote.read_with_options("../outside/leak.py", 0, 1024, false, Some(1), Some(1)).unwrap_err().code,
            ErrorCode::PathOutsideRoot
        );

        // Junction parent and target refused with UnsupportedPathType.
        assert_eq!(
            remote.read_with_options("src/linked/leak.py", 0, 1024, false, Some(1), Some(1)).unwrap_err().code,
            ErrorCode::UnsupportedPathType
        );
        assert_eq!(
            remote.search_with_options("src/linked", "SECRET", 10, false, false, 0, None, true).unwrap_err().code,
            ErrorCode::UnsupportedPathType
        );

        // Short name component refused with BridgePolicyDenied.
        assert_eq!(
            remote.read_with_options("SRC~1/App.py", 0, 1024, false, Some(1), Some(1)).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );

        // Case mismatch on Windows NTFS refused with BridgePolicyDenied.
        #[cfg(windows)]
        assert_eq!(
            remote.read_with_options("Src/App.py", 0, 1024, false, Some(1), Some(1)).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );

        #[cfg(windows)]
        fs::remove_dir(link).unwrap();
        #[cfg(unix)]
        fs::remove_file(link).unwrap();
    }

    #[test]
    fn apply_delegated_work_edits_enforces_work_scope_net_quota_hardlinks_and_overwrite_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let journals = dir.path().join("journals");
        fs::create_dir_all(root.join("_pro/work/w1")).unwrap();
        fs::create_dir_all(root.join("_pro/outbox")).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(&journals).unwrap();

        fs::write(root.join("src/live.py"), "LIVE_DATA\n").unwrap();
        fs::write(root.join("_pro/work/w1/a.py"), "alpha\n").unwrap();
        fs::write(root.join("_pro/work/w1/b.py"), "beta\n").unwrap();
        fs::write(root.join("_pro/outbox/msg.md"), "outbox\n").unwrap();

        let sf = ScopedFiles::new(&root, None).unwrap();
        let scope = vec!["_pro/**".to_string()];

        // 1. Defense-in-depth refuses anything outside exact-case `_pro/work/<workspace>/**`.
        for bad_path in [
            "_pro/outbox/msg.md",
            "_pro/reports/r.md",
            "_pro/inbox/req.md",
            "_PRO/work/w1/a.py",
            "_pro/Work/w1/a.py",
            "src/live.py",
        ] {
            let plan = PatchPlanV04 {
                patch_plan_version: "0.4.0".into(),
                project_id: "proj_1".into(),
                root_identity: None,
                operation_id: "op_bad_scope".into(),
                task_id: None,
                summary: None,
                baseline_manifest_sha256: None,
                scope: vec![bad_path.into()],
                edits: vec![PatchEditV04 {
                    path: bad_path.into(),
                    content: "changed\n".into(),
                    expected_hash: None,
                    expected_postimage_hash: None,
                }],
                verification_recipe: None,
                verification_command: None,
            };
            assert_eq!(
                sf.apply_delegated_work_edits(&plan, &journals, &scope, |_| Ok(())).unwrap_err().code,
                ErrorCode::BridgePolicyDenied,
                "{bad_path}"
            );
        }

        // 2. Hardlink inside workspace to live project file is refused without altering live.py.
        let hl = root.join("_pro/work/w1/hard.py");
        fs::hard_link(root.join("src/live.py"), &hl).unwrap();
        let hl_plan = PatchPlanV04 {
            patch_plan_version: "0.4.0".into(),
            project_id: "proj_1".into(),
            root_identity: None,
            operation_id: "op_hl".into(),
            task_id: None,
            summary: None,
            baseline_manifest_sha256: None,
            scope: vec!["_pro/work/w1/hard.py".into()],
            edits: vec![PatchEditV04 {
                path: "_pro/work/w1/hard.py".into(),
                content: "HACKED\n".into(),
                expected_hash: Some(sha256_bytes(b"LIVE_DATA\n")),
                expected_postimage_hash: None,
            }],
            verification_recipe: None,
            verification_command: None,
        };
        assert_eq!(
            sf.apply_delegated_work_edits(&hl_plan, &journals, &scope, |_| Ok(())).unwrap_err().code,
            ErrorCode::UnsupportedPathType
        );
        assert_eq!(fs::read_to_string(root.join("src/live.py")).unwrap(), "LIVE_DATA\n");
        fs::remove_file(&hl).unwrap();

        // 3. Overwrite without expected_hash fails VersionConflict; with matching expected_hash rolls back step 0 when step 1 fails at commit.
        let no_hash_plan = PatchPlanV04 {
            patch_plan_version: "0.4.0".into(),
            project_id: "proj_1".into(),
            root_identity: None,
            operation_id: "op_nohash".into(),
            task_id: None,
            summary: None,
            baseline_manifest_sha256: None,
            scope: vec!["_pro/work/w1/a.py".into()],
            edits: vec![PatchEditV04 {
                path: "_pro/work/w1/a.py".into(),
                content: "new\n".into(),
                expected_hash: None,
                expected_postimage_hash: None,
            }],
            verification_recipe: None,
            verification_command: None,
        };
        assert_eq!(
            sf.apply_delegated_work_edits(&no_hash_plan, &journals, &scope, |_| Ok(())).unwrap_err().code,
            ErrorCode::VersionConflict
        );

        let multi_plan = PatchPlanV04 {
            patch_plan_version: "0.4.0".into(),
            project_id: "proj_1".into(),
            root_identity: None,
            operation_id: "op_rollback_ow".into(),
            task_id: None,
            summary: None,
            baseline_manifest_sha256: None,
            scope: vec!["_pro/work/w1/a.py".into(), "_pro/work/w1/b.py".into()],
            edits: vec![
                PatchEditV04 {
                    path: "_pro/work/w1/a.py".into(),
                    content: "alpha_new\n".into(),
                    expected_hash: Some(sha256_bytes(b"alpha\n")),
                    expected_postimage_hash: None,
                },
                PatchEditV04 {
                    path: "_pro/work/w1/b.py".into(),
                    content: "beta_new\n".into(),
                    expected_hash: Some(sha256_bytes(b"beta\n")),
                    expected_postimage_hash: None,
                },
            ],
            verification_recipe: None,
            verification_command: None,
        };
        let err = sf.apply_delegated_work_edits(&multi_plan, &journals, &scope, |path| {
            if path.ends_with("b.py") {
                Err(BridgeError::new(ErrorCode::BridgePolicyDenied, "revoked", OriginLayer::Policy))
            } else {
                Ok(())
            }
        }).unwrap_err();
        assert_eq!(err.code, ErrorCode::BridgePolicyDenied);
        assert_eq!(fs::read_to_string(root.join("_pro/work/w1/a.py")).unwrap(), "alpha\n");
        assert_eq!(fs::read_to_string(root.join("_pro/work/w1/b.py")).unwrap(), "beta\n");

        // 4. Net positive quota delta: overwriting an existing file at the 256 MiB boundary succeeds when size does not grow,
        //    and fails ResourceBudgetExceeded when size grows by 1 byte.
        let used_so_far = measure_delegated_folder_quota(&root, "_pro").unwrap().bytes;
        File::create(root.join("_pro/outbox/filler.bin"))
            .unwrap()
            .set_len(DELEGATED_WRITE_MAX_SCOPE_BYTES - used_so_far)
            .unwrap();
        let same_size_plan = PatchPlanV04 {
            patch_plan_version: "0.4.0".into(),
            project_id: "proj_1".into(),
            root_identity: None,
            operation_id: "op_same_size".into(),
            task_id: None,
            summary: None,
            baseline_manifest_sha256: None,
            scope: vec!["_pro/work/w1/a.py".into()],
            edits: vec![PatchEditV04 {
                path: "_pro/work/w1/a.py".into(),
                content: "ALPHA\n".into(),
                expected_hash: Some(sha256_bytes(b"alpha\n")),
                expected_postimage_hash: None,
            }],
            verification_recipe: None,
            verification_command: None,
        };
        sf.apply_delegated_work_edits(&same_size_plan, &journals, &scope, |_| Ok(())).unwrap();
        assert_eq!(fs::read_to_string(root.join("_pro/work/w1/a.py")).unwrap(), "ALPHA\n");

        let grow_plan = PatchPlanV04 {
            patch_plan_version: "0.4.0".into(),
            project_id: "proj_1".into(),
            root_identity: None,
            operation_id: "op_grow".into(),
            task_id: None,
            summary: None,
            baseline_manifest_sha256: None,
            scope: vec!["_pro/work/w1/a.py".into()],
            edits: vec![PatchEditV04 {
                path: "_pro/work/w1/a.py".into(),
                content: "ALPHA!\n".into(),
                expected_hash: Some(sha256_bytes(b"ALPHA\n")),
                expected_postimage_hash: None,
            }],
            verification_recipe: None,
            verification_command: None,
        };
        assert_eq!(
            sf.apply_delegated_work_edits(&grow_plan, &journals, &scope, |_| Ok(())).unwrap_err().code,
            ErrorCode::ResourceBudgetExceeded
        );
        assert_eq!(fs::read_to_string(root.join("_pro/work/w1/a.py")).unwrap(), "ALPHA\n");
    }
}
