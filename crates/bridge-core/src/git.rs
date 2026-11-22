//! Structured Git CLI engine (§7.3): status, bounded diff with immutable diff digest,
//! diff summary, isolated worktrees preserving parent dirty work, and serialized fast-forward integration.
//!
//! Broker read containment: `status`, `diff_summary`, and `diff_page` fail closed
//! unless the approved root is the canonical repository top level and the
//! discovered `git-dir`/`common-dir` both resolve to the physical local
//! `<root>/.git` directory. Linked worktrees (a `.git` file pointer and/or a
//! redirected `git-dir`/`common-dir`) are unsupported and refused; only
//! standalone repositories (including nested standalone repositories) are readable.
//! No protection is claimed against concurrent hostile rewrites of `.git`
//! metadata or against arbitrary Git repository configuration.

use bridge_platform::{sha256_bytes, validate_relative_path};
use bridge_types::{BridgeError, ErrorCode, OriginLayer};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Largest output a Git read may produce. A status or diff beyond it is refused
/// instead of being held in memory, once per call that runs at the same time.
pub const GIT_READ_OUTPUT_LIMIT: u64 = 64 * 1024 * 1024;

/// Read at most `limit` bytes. `None` means the source had more than that.
fn read_capped(source: impl Read, limit: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    source.take(limit + 1).read_to_end(&mut out)?;
    Ok((out.len() as u64 <= limit).then_some(out))
}

/// Windows reparse-point bit; junctions surface through file attributes.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

#[cfg(windows)]
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_meta: &std::fs::Metadata) -> bool {
    false
}

/// File-name patterns a diff must leave out: the names `is_denied_secret_path` in the
/// file service refuses, rule for rule, so a diff hides what a read refuses and nothing
/// else. A test changes one tracked file for each rule and requires the diff to leave
/// all of them out; add a pattern here and a name there when a rule is added.
const SECRET_NAME_PATTERNS: &[&str] = &[
    ".env",
    ".env.*",
    "*.env",
    "secrets.*",
    "*.secret",
    "cookies",
    "login data",
    "trust tokens",
    "web data",
    ".install-token",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials.*",
    "*.pem",
    "*.key",
    "*.pfx",
    "*.p12",
    "*.kdbx",
    "*.ppk",
    "*.ovpn",
    "*.token",
    "*.sqlite3",
];

/// Further names a remote principal may not see: the patterns for
/// `files::is_hidden_from_remote` beyond the secret names above. The owner's diff keeps them.
const REMOTE_HIDDEN_PATTERNS: &[&str] = &[
    "*.jks",
    "*.keystore",
    ".edge-bridge-tmp-*",
    ".git",
    ".hg",
    ".svn",
    ".ssh",
    ".aws",
    ".azure",
    ".gnupg",
    ".kube",
    ".codex",
    ".claude",
    ".agents",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".terraform",
    ".htpasswd",
    ".pgpass",
    ".my.cnf",
    "id_dsa",
    "id_ecdsa_sk",
    "id_ed25519_sk",
    "kubeconfig",
    "auth.json",
    "auth.yaml",
    "auth.yml",
    "auth.toml",
    "api-token",
    "api-unit-token",
    "cookies-journal",
    "login data-journal",
    "login data for account",
    "login data for account-journal",
    "trust tokens-journal",
    "web data-journal",
    "account web data",
    "account web data-journal",
    ".edge-project-bridge",
    ".edge-bridge-journal",
];

/// Exclusion pathspecs for [`SECRET_NAME_PATTERNS`], and for a remote view also
/// [`REMOTE_HIDDEN_PATTERNS`]. With `glob`, `*` stops at `/`, so each pattern is given once
/// for a file at any depth and once for everything below a directory of that name.
fn secret_exclude_pathspecs(remote_view: bool) -> Vec<String> {
    SECRET_NAME_PATTERNS
        .iter()
        .chain(REMOTE_HIDDEN_PATTERNS.iter().filter(|_| remote_view))
        .flat_map(|name| {
            [
                format!(":(exclude,icase,glob)**/{name}"),
                format!(":(exclude,icase,glob)**/{name}/**"),
            ]
        })
        .collect()
}

/// Largest repository configuration file the include check reads.
const GIT_CONFIG_SCAN_LIMIT: u64 = 1024 * 1024;

/// Refuse a repository whose own configuration files have an `[include]` or
/// `[includeIf]` section, by reading the files directly, before any Git process runs.
/// Git would open the named file, which may be outside the approved root or on a path
/// that never answers, as soon as it reads the configuration.
fn refuse_config_includes(dotgit: &Path) -> Result<(), BridgeError> {
    let refused = |why: &str| {
        containment_fail(format!(
            "Refusing git read: {why} An included file could add a content filter command and may lie outside the approved root."
        ))
    };
    for name in ["config", "config.worktree"] {
        let path = dotgit.join(name);
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if !meta.is_file() || is_reparse_point(&meta) {
            return Err(refused("a repository configuration file is not a regular file."));
        }
        let file = std::fs::File::open(&path)
            .map_err(|_| refused("a repository configuration file could not be read."))?;
        let Ok(Some(raw)) = read_capped(file, GIT_CONFIG_SCAN_LIMIT) else {
            return Err(refused("a repository configuration file is too large to check."));
        };
        if String::from_utf8_lossy(&raw).lines().any(line_opens_include_section) {
            return Err(refused("the repository configuration includes another configuration file."));
        }
    }
    Ok(())
}

/// Whether a line of a Git configuration file opens an `include` or `includeIf` section.
///
/// Git skips a byte order mark at the start of the file and accepts a section header after
/// another on one line (`[core] [include]`), so every header at the start of the line is read.
/// A comment line, and text after the headers (a key, a value, a trailing comment), are not
/// headers. A line that continues a value from the line before is read as if it stood alone,
/// which can refuse a repository Git would accept and cannot accept one it would refuse.
fn line_opens_include_section(line: &str) -> bool {
    let mut rest = line.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    while let Some(header) = rest.strip_prefix('[') {
        let name: String = header.trim_start().chars()
            .take_while(|c| !c.is_whitespace() && !matches!(c, '"' | '.' | ']')).collect();
        if name.eq_ignore_ascii_case("include") || name.eq_ignore_ascii_case("includeif") {
            return true;
        }
        // Step past this header. A `]` inside the quoted subsection does not end it.
        let mut quoted = false;
        let mut escaped = false;
        let Some(end) = header.char_indices().find_map(|(at, c)| {
            if escaped {
                escaped = false;
            } else if quoted && c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = !quoted;
            } else if c == ']' && !quoted {
                return Some(at);
            }
            None
        }) else {
            return false;
        };
        rest = header[end + 1..].trim_start();
    }
    false
}

fn containment_fail(msg: String) -> BridgeError {
    BridgeError::new(ErrorCode::VersionConflict, msg, OriginLayer::GitEngine)
}

/// No-follow guard: reject missing paths, symlinks, and reparse points.
fn require_physical_dir(path: &Path, what: &str) -> Result<std::fs::Metadata, BridgeError> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| containment_fail(format!("Refusing git read: {what} is not a local directory.")))?;
    if meta.file_type().is_symlink() || is_reparse_point(&meta) {
        return Err(containment_fail(format!(
            "Refusing git read: {what} is a link or reparse point."
        )));
    }
    if !meta.is_dir() {
        return Err(containment_fail(format!(
            "Refusing git read: {what} is not a self-contained `.git` directory."
        )));
    }
    Ok(meta)
}

fn canonicalize_for_read(path: &Path, what: &str) -> Result<PathBuf, BridgeError> {
    std::fs::canonicalize(path)
        .map_err(|_| containment_fail(format!("Refusing git read: cannot canonicalize {what}.")))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitStatusEntry {
    pub path: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitStatusResult {
    pub branch: String,
    pub head_commit: Option<String>,
    pub dirty: bool,
    pub entries: Vec<GitStatusEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitDiffFileStat {
    pub path: String,
    pub insertions: u64,
    pub deletions: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitDiffSummaryResult {
    pub diff_sha256: String,
    pub base_ref: Option<String>,
    pub staged: bool,
    pub files_changed: usize,
    pub total_insertions: u64,
    pub total_deletions: u64,
    pub files: Vec<GitDiffFileStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitDiffPage {
    pub diff_sha256: String,
    pub content: String,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub total_bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorktreeHandle {
    pub branch: String,
    pub base_commit: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrateResult {
    pub dry_run: bool,
    pub head_before: String,
    pub head_after: String,
    pub source_ref: String,
    pub fast_forward_possible: bool,
    pub integrated: bool,
}

pub struct GitEngine {
    git_bin: PathBuf,
    /// Reads are for a remote principal: hide what the file service hides from one.
    remote_view: bool,
}

impl Default for GitEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl GitEngine {
    /// Status and diff as a remote principal may see them (`true`) or as the owner does.
    pub fn for_remote(mut self, remote_view: bool) -> Self {
        self.remote_view = remote_view;
        self
    }

    pub fn new() -> Self {
        let candidate = PathBuf::from(r"C:\Program Files\Git\cmd\git.exe");
        let git_bin = if candidate.is_file() {
            candidate
        } else {
            PathBuf::from("git")
        };
        Self { git_bin, remote_view: false }
    }

    fn run_git(&self, repo_root: &Path, args: &[&str]) -> Result<Vec<u8>, BridgeError> {
        let output = Command::new(&self.git_bin)
            .args(args)
            .current_dir(repo_root)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                BridgeError::new(
                    ErrorCode::BackendUnavailable,
                    format!("Failed invoking git CLI: {e}"),
                    OriginLayer::GitEngine,
                )
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BridgeError::new(
                ErrorCode::InternalError,
                format!("git {:?} failed: {}", args.first().unwrap_or(&""), stderr.trim()),
                OriginLayer::GitEngine,
            ));
        }
        Ok(output.stdout)
    }

    fn git_command(&self, root: &Path) -> Command {
        let null_sink = if cfg!(windows) { "NUL" } else { "/dev/null" };
        let mut cmd = Command::new(&self.git_bin);
        cmd.arg("--no-optional-locks").args([
            "-c",
            "credential.helper=",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "diff.external=",
            "-c",
            "core.pager=cat",
            // A read never descends into a nested repository: Git would run `status` or
            // `diff` there with that repository's own configuration.
            "-c",
            "diff.submodule=short",
            "-c",
            "status.submoduleSummary=false",
        ]);
        cmd.current_dir(root).stdin(Stdio::null());
        for (key, _) in std::env::vars_os() {
            if key
                .to_string_lossy()
                .to_ascii_uppercase()
                .starts_with("GIT_")
            {
                cmd.env_remove(&key);
            }
        }
        cmd.env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null_sink)
            .env("GIT_CONFIG_SYSTEM", null_sink)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_LAZY_FETCH", "1");
        cmd
    }

    /// Resolve the physical repository root before running read commands.
    fn broker_repo_context(&self, repo_root: &Path) -> Result<PathBuf, BridgeError> {
        require_physical_dir(repo_root, "repository root")?;
        let dotgit = repo_root.join(".git");
        require_physical_dir(&dotgit, "`.git`")?;
        refuse_config_includes(&dotgit)?;
        let canonical_root = canonicalize_for_read(repo_root, "repository root")?;
        let canonical_dotgit = canonicalize_for_read(&dotgit, "`.git`")?;
        let output = self
            .git_command(&canonical_root)
            .args([
                "rev-parse",
                "--path-format=absolute",
                "--show-toplevel",
                "--absolute-git-dir",
                "--git-common-dir",
            ])
            .output()
            .map_err(|e| {
                BridgeError::new(
                    ErrorCode::BackendUnavailable,
                    format!("Failed invoking git CLI: {e}"),
                    OriginLayer::GitEngine,
                )
            })?;
        if !output.status.success() {
            return Err(containment_fail(
                "Refusing git read: repository discovery failed.".to_string(),
            ));
        }
        let text = String::from_utf8(output.stdout).map_err(|_| {
            containment_fail("Refusing git read: malformed discovery output.".to_string())
        })?;
        if text.is_empty() || !text.ends_with('\n') || text.contains('\0') {
            return Err(containment_fail(
                "Refusing git read: malformed discovery output.".to_string(),
            ));
        }
        let lines: Vec<&str> = text.lines().collect();
        if lines.len() != 3 || lines.iter().any(|l| l.is_empty() || l.starts_with("--")) {
            return Err(containment_fail(
                "Refusing git read: unexpected discovery output.".to_string(),
            ));
        }
        let resolve = |line: &str, label: &'static str| -> Result<PathBuf, BridgeError> {
            let path = Path::new(line);
            let joined = if path.is_absolute() {
                path.to_path_buf()
            } else {
                canonical_root.join(path)
            };
            canonicalize_for_read(&joined, label)
        };
        let toplevel = resolve(lines[0], "top level")?;
        let git_dir = resolve(lines[1], "git directory")?;
        let common_dir = resolve(lines[2], "common directory")?;
        if toplevel != canonical_root {
            return Err(containment_fail(
                "Refusing git read: approved root is not the repository top level.".to_string(),
            ));
        }
        if git_dir != canonical_dotgit || common_dir != canonical_dotgit {
            return Err(containment_fail(
                "Refusing git read: git metadata is redirected outside `<root>/.git`.".to_string(),
            ));
        }
        if !git_dir.starts_with(&canonical_root) || !common_dir.starts_with(&canonical_root) {
            return Err(containment_fail(
                "Refusing git read: git metadata is outside the approved root.".to_string(),
            ));
        }
        Ok(canonical_root)
    }

    /// Refuse a repository whose configuration names a content filter command. Git runs
    /// a `clean` or `process` filter while it compares changed files for `status` and
    /// `diff`, with this process's permissions, so a read would execute a command taken
    /// from the repository. There is no switch that turns every filter off; the read is
    /// refused instead. A configuration that includes another file is refused as well:
    /// the included file may be missing now and appear, with a filter, before the read.
    /// Anything other than a clean "no such key" answer also refuses.
    fn refuse_content_filters(&self, root: &Path) -> Result<(), BridgeError> {
        let refused = |why: &str| {
            containment_fail(format!(
                "Refusing git read: {why} Git would run a content filter command from the repository configuration (filter.<name>.clean, smudge or process, or a file named by include.path). Remove it from the repository configuration to read this repository through the bridge."
            ))
        };
        let output = self
            .git_command(root)
            .args(["config", "--includes", "--name-only", "--get-regexp", r"^(filter\..*\.(clean|smudge|process)|include\.path|includeif\..*\.path)$"])
            .env("GIT_CEILING_DIRECTORIES", root)
            .env("GIT_DIR", ".git")
            .env("GIT_WORK_TREE", ".")
            .env("GIT_COMMON_DIR", ".git")
            .stderr(Stdio::null())
            .output()
            .map_err(|e| {
                BridgeError::new(
                    ErrorCode::BackendUnavailable,
                    format!("Failed invoking git CLI: {e}"),
                    OriginLayer::GitEngine,
                )
            })?;
        // `git config --get-regexp` exits 1 with no output when no key matches.
        match (output.status.code(), output.stdout.is_empty()) {
            (Some(1), true) => Ok(()),
            (Some(0), false) => Err(refused("it has a content filter or includes another configuration file.")),
            _ => Err(refused("its content filter settings could not be read.")),
        }
    }

    /// Resolve a caller's base ref to a commit id. `git diff` accepts any tree, and a
    /// tree named as `HEAD:dir` or by its object id drops the directory prefix from every
    /// path, which would carry the files of a secret directory past the exclusions. Only
    /// the resolved commit id is ever passed on.
    fn resolve_commit(&self, root: &Path, base_ref: &str) -> Result<String, BridgeError> {
        validate_git_ref(base_ref)?;
        let not_a_commit = || {
            BridgeError::new(
                ErrorCode::InvalidArgument,
                "base_ref must name a commit in this repository.",
                OriginLayer::GitEngine,
            )
        };
        let spec = format!("{base_ref}^{{commit}}");
        let out = self
            .run_git_read(root, &["rev-parse", "--verify", "--quiet", "--end-of-options", &spec])
            // A refusal of the repository itself is reported as such, not as a bad ref.
            .map_err(|e| if e.code == ErrorCode::InternalError { not_a_commit() } else { e })?;
        let oid = String::from_utf8(out).map_err(|_| not_a_commit())?.trim().to_string();
        if !matches!(oid.len(), 40 | 64) || !oid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(not_a_commit());
        }
        Ok(oid)
    }

    /// Pinned read-only invocation without inherited `GIT_*` or helpers.
    fn run_git_read(&self, root: &Path, args: &[&str]) -> Result<Vec<u8>, BridgeError> {
        self.refuse_content_filters(root)?;
        let failed = || {
            BridgeError::new(
                ErrorCode::InternalError,
                format!("git {:?} failed for the approved repository.", args.first().unwrap_or(&"")),
                OriginLayer::GitEngine,
            )
        };
        let mut child = self
            .git_command(root)
            .args(args)
            .env("GIT_CEILING_DIRECTORIES", root)
            .env("GIT_DIR", ".git")
            .env("GIT_WORK_TREE", ".")
            .env("GIT_COMMON_DIR", ".git")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                BridgeError::new(
                    ErrorCode::BackendUnavailable,
                    format!("Failed invoking git CLI: {e}"),
                    OriginLayer::GitEngine,
                )
            })?;
        let stdout = child.stdout.take().ok_or_else(failed)?;
        let captured = read_capped(stdout, GIT_READ_OUTPUT_LIMIT);
        let Ok(Some(output)) = captured else {
            // Closing the pipe above lets Git stop; do not leave it running.
            let _ = child.kill();
            let _ = child.wait();
            return Err(match captured {
                Ok(None) => BridgeError::new(
                    ErrorCode::ResourceBudgetExceeded,
                    format!(
                        "git {:?} output exceeds the {} MiB read limit; narrow the request.",
                        args.first().unwrap_or(&""),
                        GIT_READ_OUTPUT_LIMIT / (1024 * 1024)
                    ),
                    OriginLayer::GitEngine,
                ),
                _ => failed(),
            });
        };
        if !child.wait().map_err(|_| failed())?.success() {
            return Err(failed());
        }
        Ok(output)
    }

    /// With `hide_secret_paths`, a changed path the file service refuses to list is left
    /// out of `entries`; it still makes the result `dirty`. `remote_view` hides what the file
    /// service hides from a remote principal, which is more than it refuses the owner.
    fn parse_status_porcelain_v2(raw: &[u8], max_entries: usize, hide_secret_paths: bool, remote_view: bool) -> GitStatusResult {
        let mut branch = "HEAD".to_string();
        let mut head_commit = None;
        let mut entries = Vec::new();
        let mut dirty = false;
        let hidden = |path: &str| {
            let parts: Vec<String> = path.split('/').map(str::to_string).collect();
            hide_secret_paths && if remote_view {
                crate::files::is_hidden_from_remote(&parts)
            } else {
                crate::files::is_denied_secret_path(&parts)
            }
        };
        // A file the bridge is staging for a write in flight is not a change of the tree.
        let internal =
            |path: &str| hide_secret_paths && path.split('/').any(crate::policy::is_patch_stage_name);
        let cap = max_entries.clamp(1, 1000);
        let mut chunks = raw.split(|&b| b == 0);
        while let Some(chunk) = chunks.next() {
            if chunk.is_empty() {
                continue;
            }
            let s = String::from_utf8_lossy(chunk);
            if let Some(rest) = s.strip_prefix("# branch.head ") {
                branch = rest.trim().to_string();
                continue;
            }
            if let Some(rest) = s.strip_prefix("# branch.oid ") {
                let oid = rest.trim();
                if oid != "(initial)" {
                    head_commit = Some(oid.to_string());
                }
                continue;
            }
            // Fields before the path, by record type: ordinary `1` has 8, renamed or
            // copied `2` has 9 (a score precedes the path) and is followed by the
            // original path as its own NUL-terminated field, unmerged `u` has 10.
            let (status, path, original) = if let Some(rest) = s.strip_prefix("? ") {
                ("untracked".to_string(), rest.to_string(), None)
            } else {
                let fields_before_path = match s.as_bytes().first() {
                    Some(b'1') => 8,
                    Some(b'2') => 9,
                    Some(b'u') => 10,
                    _ => continue,
                };
                let parts: Vec<&str> = s.splitn(fields_before_path + 1, ' ').collect();
                let original = (fields_before_path == 9)
                    .then(|| chunks.next().map(|o| String::from_utf8_lossy(o).into_owned()))
                    .flatten();
                if parts.len() <= fields_before_path {
                    continue;
                }
                (parts[1].to_string(), parts[fields_before_path].to_string(), original)
            };
            let names = || std::iter::once(path.as_str()).chain(original.as_deref());
            if names().any(internal) {
                continue;
            }
            dirty = true;
            if entries.len() < cap && !names().any(hidden) {
                entries.push(GitStatusEntry { path, status });
            }
        }
        GitStatusResult {
            branch,
            head_commit,
            dirty,
            entries,
        }
    }

    pub fn status(&self, repo_root: &Path, max_entries: usize) -> Result<GitStatusResult, BridgeError> {
        let ctx = self.broker_repo_context(repo_root)?;
        let raw = self.run_git_read(&ctx, &["status", "--porcelain=v2", "--branch", "-z", "--ignore-submodules=all"])?;
        Ok(Self::parse_status_porcelain_v2(&raw, max_entries, true, self.remote_view))
    }

    fn status_local(&self, repo_root: &Path, max_entries: usize) -> Result<GitStatusResult, BridgeError> {
        let raw = self.run_git(repo_root, &["status", "--porcelain=v2", "--branch", "-z"])?;
        Ok(Self::parse_status_porcelain_v2(&raw, max_entries, false, false))
    }

    pub fn diff_summary(
        &self,
        repo_root: &Path,
        base_ref: Option<&str>,
        staged: bool,
    ) -> Result<GitDiffSummaryResult, BridgeError> {
        let ctx = self.broker_repo_context(repo_root)?;
        let full_diff = self.raw_diff_bytes_in(&ctx, base_ref, staged, None)?;
        let diff_sha256 = sha256_bytes(&full_diff);

        let mut args = vec!["diff", "--numstat", "--no-color", "--no-ext-diff", "--no-textconv", "--ignore-submodules=all"];
        if staged {
            args.push("--cached");
        }
        let base_commit = base_ref.map(|br| self.resolve_commit(&ctx, br)).transpose()?;
        if let Some(oid) = &base_commit {
            args.push(oid);
        }
        args.push("--");
        let excluded = secret_exclude_pathspecs(self.remote_view);
        args.extend(excluded.iter().map(String::as_str));

        let numstat = self.run_git_read(&ctx, &args)?;
        let mut files = Vec::new();
        let mut total_ins = 0u64;
        let mut total_del = 0u64;
        for line in String::from_utf8_lossy(&numstat).lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                let ins = parts[0].parse::<u64>().unwrap_or(0);
                let del = parts[1].parse::<u64>().unwrap_or(0);
                total_ins += ins;
                total_del += del;
                files.push(GitDiffFileStat {
                    path: parts[2].to_string(),
                    insertions: ins,
                    deletions: del,
                    status: "modified".to_string(),
                });
            }
        }
        Ok(GitDiffSummaryResult {
            diff_sha256,
            base_ref: base_ref.map(|s| s.to_string()),
            staged,
            files_changed: files.len(),
            total_insertions: total_ins,
            total_deletions: total_del,
            files,
        })
    }

    pub fn diff_page(
        &self,
        repo_root: &Path,
        base_ref: Option<&str>,
        staged: bool,
        paths: Option<&[String]>,
        expected_diff_sha256: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<GitDiffPage, BridgeError> {
        let raw = self.raw_diff_bytes(repo_root, base_ref, staged, paths)?;
        let diff_sha256 = sha256_bytes(&raw);
        if let Some(exp) = expected_diff_sha256 {
            if !exp.eq_ignore_ascii_case(&diff_sha256) {
                return Err(BridgeError::new(
                    ErrorCode::StalePrecondition,
                    "Diff snapshot digest changed during pagination; restart from git_diff_summary.",
                    OriginLayer::GitEngine,
                ));
            }
        }
        let text = String::from_utf8_lossy(&raw).into_owned();
        let total_bytes = text.len();
        let (page, start, end, truncated) =
            crate::files::char_page(&text, offset, limit.clamp(1, 65_536));
        let page = page.to_string();
        Ok(GitDiffPage {
            diff_sha256,
            content: page,
            offset: start,
            next_offset: if truncated { Some(end) } else { None },
            total_bytes,
            truncated,
        })
    }

    fn raw_diff_bytes(
        &self,
        repo_root: &Path,
        base_ref: Option<&str>,
        staged: bool,
        paths: Option<&[String]>,
    ) -> Result<Vec<u8>, BridgeError> {
        let ctx = self.broker_repo_context(repo_root)?;
        self.raw_diff_bytes_in(&ctx, base_ref, staged, paths)
    }

    fn raw_diff_bytes_in(
        &self,
        ctx: &Path,
        base_ref: Option<&str>,
        staged: bool,
        paths: Option<&[String]>,
    ) -> Result<Vec<u8>, BridgeError> {
        let mut owned: Vec<String> = vec![
            "diff".into(),
            "--no-color".into(),
            "--no-ext-diff".into(),
            "--no-textconv".into(),
            "--ignore-submodules=all".into(),
        ];
        if staged {
            owned.push("--cached".into());
        }
        if let Some(br) = base_ref {
            owned.push(self.resolve_commit(ctx, br)?);
        }
        owned.push("--".into());
        owned.extend(secret_exclude_pathspecs(self.remote_view));
        if let Some(ps) = paths {
            for p in ps {
                validate_relative_path(p)?;
                owned.push(p.clone());
            }
        }
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        self.run_git_read(ctx, &refs)
    }

    /// Create an isolated Git worktree anchored at explicit `base_commit` without touching parent dirty work (§7.3).
    pub fn create_worktree(
        &self,
        repo_root: &Path,
        worktree_path: &Path,
        branch_name: &str,
        base_ref: &str,
    ) -> Result<WorktreeHandle, BridgeError> {
        validate_git_ref(branch_name)?;
        validate_git_ref(base_ref)?;
        let base_oid_bytes = self.run_git(repo_root, &["rev-parse", base_ref])?;
        let base_commit = String::from_utf8_lossy(&base_oid_bytes).trim().to_string();
        let wt_str = worktree_path.to_string_lossy().to_string();
        self.run_git(
            repo_root,
            &["worktree", "add", "-b", branch_name, &wt_str, &base_commit],
        )?;
        Ok(WorktreeHandle {
            branch: branch_name.to_string(),
            base_commit,
            path: wt_str,
        })
    }

    pub fn remove_worktree(&self, repo_root: &Path, worktree_path: &Path) -> Result<(), BridgeError> {
        let wt_str = worktree_path.to_string_lossy().to_string();
        self.run_git(repo_root, &["worktree", "remove", "--force", &wt_str])?;
        Ok(())
    }

    /// Serialized fast-forward integration checking `expected_head` and clean working tree preconditions.
    pub fn integrate_fast_forward(
        &self,
        repo_root: &Path,
        source_ref: &str,
        expected_head: Option<&str>,
        dry_run: bool,
    ) -> Result<IntegrateResult, BridgeError> {
        validate_git_ref(source_ref)?;
        let st = self.status_local(repo_root, 10)?;
        let head_before = st.head_commit.ok_or_else(|| {
            BridgeError::new(ErrorCode::StalePrecondition, "Repository has no HEAD commit.", OriginLayer::GitEngine)
        })?;
        if let Some(exp) = expected_head {
            if !head_before.starts_with(exp) {
                return Err(BridgeError::new(
                    ErrorCode::StalePrecondition,
                    format!("HEAD mismatch: expected {exp}, actual {head_before}."),
                    OriginLayer::GitEngine,
                ));
            }
        }
        if st.dirty {
            return Err(BridgeError::new(
                ErrorCode::VersionConflict,
                "Refusing integration: parent working tree has uncommitted user changes.",
                OriginLayer::GitEngine,
            ));
        }
        let ff_check = Command::new(&self.git_bin)
            .args(["merge-base", "--is-ancestor", &head_before, source_ref])
            .current_dir(repo_root)
            .stdin(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if dry_run || !ff_check {
            return Ok(IntegrateResult {
                dry_run,
                head_before: head_before.clone(),
                head_after: head_before,
                source_ref: source_ref.to_string(),
                fast_forward_possible: ff_check,
                integrated: false,
            });
        }
        self.run_git(repo_root, &["merge", "--ff-only", source_ref])?;
        let head_after = String::from_utf8_lossy(&self.run_git(repo_root, &["rev-parse", "HEAD"])?)
            .trim()
            .to_string();
        Ok(IntegrateResult {
            dry_run: false,
            head_before,
            head_after,
            source_ref: source_ref.to_string(),
            fast_forward_possible: true,
            integrated: true,
        })
    }
}

fn validate_git_ref(r: &str) -> Result<(), BridgeError> {
    if r.is_empty()
        || r.len() > 128
        || r.starts_with('-')
        || r.contains("..")
        || r.contains(' ')
        || r.contains(':')
        || r.contains('\\')
        || r.contains('\0')
    {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            format!("Invalid or unsafe git ref: '{r}'."),
            OriginLayer::GitEngine,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    fn git_in(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::null())
            .status()
            .expect("git invocation");
        assert!(status.success(), "git {args:?} failed");
    }

    fn init_standalone_repo(dir: &Path) {
        git_in(dir, &["init", "-q"]);
        git_in(dir, &["config", "user.email", "test@example.com"]);
        git_in(dir, &["config", "user.name", "Test"]);
        std::fs::write(dir.join("README.md"), "hello\n").unwrap();
        git_in(dir, &["add", "README.md"]);
        git_in(dir, &["commit", "-qm", "init"]);
    }

    #[test]
    fn read_capped_refuses_only_what_is_over_the_limit() {
        assert_eq!(read_capped(&b"abcd"[..], 4).unwrap(), Some(b"abcd".to_vec()));
        assert_eq!(read_capped(&b"abcde"[..], 4).unwrap(), None);
        assert_eq!(read_capped(&b""[..], 0).unwrap(), Some(Vec::new()));
        // An endless source is cut off after one byte past the limit.
        assert_eq!(read_capped(std::io::repeat(b'x'), 1024).unwrap(), None);
    }

    #[test]
    fn broker_status_and_diff_standalone() {
        let tmp = tempfile::tempdir().unwrap();
        init_standalone_repo(tmp.path());
        let engine = GitEngine::new();
        let st = engine.status(tmp.path(), 100).unwrap();
        assert!(!st.dirty);
        assert!(st.head_commit.is_some());
        std::fs::write(tmp.path().join("README.md"), "hello changed\n").unwrap();
        let st2 = engine.status(tmp.path(), 100).unwrap();
        assert!(st2.dirty);
        let summary = engine.diff_summary(tmp.path(), None, false).unwrap();
        assert_eq!(summary.files_changed, 1);
        let page = engine
            .diff_page(tmp.path(), None, false, None, None, 0, 1024)
            .unwrap();
        assert_eq!(page.diff_sha256, summary.diff_sha256);
        assert!(!page.content.is_empty());
    }

    #[test]
    fn broker_refuses_a_repository_with_a_content_filter() {
        let repo = tempfile::tempdir().unwrap();
        init_standalone_repo(repo.path());
        let engine = GitEngine::new();
        assert!(engine.status(repo.path(), 10).is_ok());

        // A clean filter that leaves a marker when Git runs it, on a changed tracked file.
        let outside = tempfile::tempdir().unwrap();
        let marker = outside.path().join("filter-ran");
        let command = format!("touch '{}'; cat", marker.display().to_string().replace('\\', "/"));
        git_in(repo.path(), &["config", "filter.probe.clean", &command]);
        std::fs::write(repo.path().join(".gitattributes"), "README.md filter=probe\n").unwrap();
        std::fs::write(repo.path().join("README.md"), "changed by the test\n").unwrap();

        let status = engine.status(repo.path(), 10);
        let summary = engine.diff_summary(repo.path(), None, false);
        let page = engine.diff_page(repo.path(), None, false, None, None, 0, 1024);
        assert!(!marker.exists(), "a Git read ran the repository's filter command");
        for refused in [status.err(), summary.err(), page.err()] {
            let refused = refused.expect("a Git read was served despite a configured filter");
            assert!(refused.message.contains("content filter"), "{}", refused.message);
        }

        // Without the filter the same repository is readable again.
        git_in(repo.path(), &["config", "--unset", "filter.probe.clean"]);
        assert!(engine.status(repo.path(), 10).unwrap().dirty);
    }

    #[test]
    fn broker_diff_leaves_out_every_path_the_file_service_refuses() {
        let repo = tempfile::tempdir().unwrap();
        init_standalone_repo(repo.path());
        // Each name is hidden from remote principals by the file service, at the top level and nested.
        let secret = [
            "credentials.json",
            "sub/.env",
            "sub/deep/id_rsa",
            "keys/store.pfx",
            "owner.token",
            "db/state.sqlite3",
            "secrets.d/inner.txt",
            "sub/Credentials.YAML",
            "notes.secret",
            // One name for every remaining rule of the file service.
            ".env.local",
            "prod.env",
            "profile/Cookies",
            "profile/Login Data",
            "profile/Trust Tokens",
            "profile/Web Data",
            ".install-token",
            "ssh/id_ed25519",
            "ssh/id_ecdsa",
            "edge.token",
            "tunnel-runtime.key",
            "ipc-key.pem",
            "secrets.yaml",
            "certs/site.pem",
            "certs/site.key",
            "certs/site.p12",
            "vault.kdbx",
            "ssh/putty.ppk",
            "vpn/office.ovpn",
            // Credential folders and files of common tools.
            ".ssh/config",
            "home/.aws/credentials",
            ".azure/profile.txt",
            ".gnupg/pubring.txt",
            ".kube/config",
            ".codex/config.toml",
            ".claude/settings.json",
            ".agents/notes.md",
            ".npmrc",
            "pkg/.pypirc",
            ".netrc",
            ".git-credentials",
            ".terraform/state.txt",
            "web/.htpasswd",
            ".pgpass",
            ".my.cnf",
            "ssh/id_dsa",
            "ssh/id_ecdsa_sk",
            "ssh/id_ed25519_sk",
            "kubeconfig",
            "auth.json",
            "conf/Auth.YAML",
            "auth.yml",
            "auth.toml",
            "api-token",
            "api-unit-token",
            "profile/Cookies-journal",
            "profile/Login Data-journal",
            "profile/Login Data For Account",
            "profile/Login Data For Account-journal",
            "profile/Trust Tokens-journal",
            "profile/Web Data-journal",
            "profile/Account Web Data",
            "profile/Account Web Data-journal",
            ".edge-project-bridge/state.txt",
            ".edge-bridge-journal/entry.txt",
            "android/release.jks",
            "android/upload.keystore",
            ".hg/hgrc",
            ".svn/entries",
            "src/.edge-bridge-tmp-1f2e3d",
        ];
        let write_all = |tag: &str| {
            for (i, rel) in secret.iter().enumerate() {
                let path = repo.path().join(rel);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, format!("{tag}-SECRET-{i}\n")).unwrap();
            }
            // Ordinary names that only resemble a secret name stay visible.
            for rel in ["sub/plain.txt", "src/secret_scanner.rs", "src/app.environment.ts"] {
                let path = repo.path().join(rel);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, format!("{tag}-PLAIN\n")).unwrap();
            }
        };
        for rel in secret {
            let parts: Vec<String> = rel.split('/').map(str::to_string).collect();
            assert!(crate::files::is_hidden_from_remote(&parts), "{rel}");
        }
        write_all("old");
        git_in(repo.path(), &["add", "-A"]);
        git_in(repo.path(), &["commit", "-qm", "tracked"]);
        write_all("new");

        // The owner still sees the names that are hidden only from remote principals, and
        // no secret path.
        let owner = GitEngine::new();
        let page = owner.diff_page(repo.path(), None, false, None, None, 0, 1_048_576).unwrap();
        for shown in ["b/auth.json", "b/.ssh/config", "b/kubeconfig", "b/.claude/settings.json"] {
            assert!(page.content.contains(shown), "{shown}");
        }
        for hidden in ["b/credentials.json", "b/sub/.env", "b/certs/site.pem"] {
            assert!(!page.content.contains(hidden), "{hidden}");
        }
        let status = owner.status(repo.path(), 1000).unwrap();
        assert!(status.entries.iter().any(|e| e.path == "auth.json"));
        assert!(!status.entries.iter().any(|e| e.path == "credentials.json"));

        let engine = GitEngine::new().for_remote(true);
        let page = engine.diff_page(repo.path(), None, false, None, None, 0, 65_536).unwrap();
        assert_eq!(page.content.matches("+new-PLAIN").count(), 3);
        assert!(!page.content.contains("SECRET"), "{}", page.content);
        let summary = engine.diff_summary(repo.path(), None, false).unwrap();
        assert_eq!(summary.files_changed, 3);

        // Status names the ordinary files only, and still reports the tree as changed.
        std::fs::write(repo.path().join("untracked.key"), "x\n").unwrap();
        std::fs::write(repo.path().join("sub/.eb_stage_pjr_test_0.tmp"), "staged\n").unwrap();
        let status = engine.status(repo.path(), 1000).unwrap();
        let mut names: Vec<&str> = status.entries.iter().map(|e| e.path.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["src/app.environment.ts", "src/secret_scanner.rs", "sub/plain.txt"]);
        assert!(status.dirty);
        std::fs::remove_file(repo.path().join("sub/.eb_stage_pjr_test_0.tmp")).unwrap();

        // A stage file alone does not make a clean repository dirty.
        let clean = tempfile::tempdir().unwrap();
        init_standalone_repo(clean.path());
        std::fs::write(clean.path().join(".eb_stage_pjr_test_0.tmp"), "staged\n").unwrap();
        let staged_only = engine.status(clean.path(), 10).unwrap();
        assert!(!staged_only.dirty && staged_only.entries.is_empty());

        // A base ref must be a commit. A tree drops the directory prefix from its paths,
        // which would carry a secret directory past the exclusions.
        git_in(repo.path(), &["add", "-A"]);
        git_in(repo.path(), &["commit", "-qm", "second"]);
        let tree = String::from_utf8(
            Command::new("git").args(["rev-parse", "HEAD:secrets.d"]).current_dir(repo.path()).output().unwrap().stdout,
        )
        .unwrap();
        for base in ["HEAD:secrets.d", "HEAD:", tree.trim(), "HEAD^{tree}", "no-such-ref"] {
            let page = engine.diff_page(repo.path(), Some(base), false, None, None, 0, 65_536);
            assert_eq!(page.unwrap_err().code, ErrorCode::InvalidArgument, "{base}");
            let summary = engine.diff_summary(repo.path(), Some(base), false);
            assert_eq!(summary.unwrap_err().code, ErrorCode::InvalidArgument, "{base}");
        }
        let page = engine.diff_page(repo.path(), Some("HEAD~1"), false, None, None, 0, 65_536).unwrap();
        assert_eq!(page.content.matches("+new-PLAIN").count(), 3);
        assert!(!page.content.contains("SECRET"), "{}", page.content);
        assert_eq!(engine.diff_summary(repo.path(), Some("HEAD~1"), false).unwrap().files_changed, 3);
    }

    #[test]
    fn status_parser_reads_each_record_type_and_hides_by_every_path() {
        let zeros = "0000000000000000000000000000000000000000";
        let record = |kind: &str, xy: &str, modes: usize, hashes: usize, tail: &str| {
            let mut fields = vec![kind.to_string(), xy.to_string(), "N...".to_string()];
            fields.extend(std::iter::repeat("100644".to_string()).take(modes));
            fields.extend(std::iter::repeat(zeros.to_string()).take(hashes));
            format!("{} {tail}\0", fields.join(" "))
        };
        let raw = [
            "# branch.oid abc\0".to_string(),
            "# branch.head main\0".to_string(),
            record("1", ".M", 3, 2, "src/a b.rs"),
            record("2", "R.", 3, 2, "R100 src/new.rs") + "src/old.rs\0",
            record("2", "R.", 3, 2, "R100 .env") + "plain.txt\0",
            record("2", "R.", 3, 2, "R100 moved.txt") + "keys/id_rsa\0",
            record("u", "UU", 4, 3, "src/conflict.rs"),
            record("u", "UU", 4, 3, "sub/credentials.json"),
            record("1", "A.", 3, 2, "_pro/.eb_stage_pjr_x_0.tmp"),
            "? untracked.txt\0".to_string(),
            "? owner.token\0".to_string(),
        ]
        .concat();
        let shown = |hide: bool| -> Vec<(String, String)> {
            GitEngine::parse_status_porcelain_v2(raw.as_bytes(), 1000, hide, false)
                .entries
                .into_iter()
                .map(|e| (e.status, e.path))
                .collect()
        };
        let pair = |s: &str, p: &str| (s.to_string(), p.to_string());
        assert_eq!(
            shown(true),
            [
                pair(".M", "src/a b.rs"),
                pair("R.", "src/new.rs"),
                pair("UU", "src/conflict.rs"),
                pair("untracked", "untracked.txt"),
            ]
        );
        // The owner sees every record, with the path and not the rename score.
        let all = shown(false);
        assert_eq!(all.len(), 9);
        assert!(all.contains(&pair("R.", ".env")) && all.contains(&pair("UU", "sub/credentials.json")));

        // Conflicts alone make the tree dirty; a staged bridge file alone does not.
        let conflict = record("u", "UU", 4, 3, "src/conflict.rs");
        assert!(GitEngine::parse_status_porcelain_v2(conflict.as_bytes(), 10, true, false).dirty);
        let staged = record("1", "A.", 3, 2, "_pro/.eb_stage_pjr_x_0.tmp");
        assert!(!GitEngine::parse_status_porcelain_v2(staged.as_bytes(), 10, true, false).dirty);
    }

    #[test]
    fn config_includes_are_refused_from_the_file_itself() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        for body in ["\u{feff}[include]\n\tpath = x\n", "[core] [include]\n\tpath = x\n", "[include]\n\tpath = //unreachable/share/x\n","[core]\n\tbare = false\n  [IncludeIf \"gitdir:/\"]\n\tpath = x\n"] {
            std::fs::write(&config, body).unwrap();
            assert!(refuse_config_includes(dir.path()).is_err(), "{body}");
        }
        for body in [
            "[remote \"a]b\"] [include]\n\tpath = x\n",
            "[core][includeIf \"gitdir:/\"]\n\tpath = x\n",
            "[ include ]\n\tpath = x\n",
            "[Include.sub]\n\tpath = x\n",
        ] {
            std::fs::write(&config, body).unwrap();
            assert!(refuse_config_includes(dir.path()).is_err(), "{body}");
        }
        // The word in a comment, a value, a subsection or another section name is not an include.
        for body in [
            "[core]\n\tbare = false\n[remote \"include\"]\n\turl = x\n",
            "# see [include] below\n; [include]\n[core]\n\tbare = false\n",
            "[core] # [include]\n\tbare = false\n",
            "[alias]\n\tnote = \"[include] is refused\"\n\tother = x [include]\n",
            "[includes]\n\tpath = x\n[included \"x\"]\n\tpath = y\n",
        ] {
            std::fs::write(&config, body).unwrap();
            assert!(refuse_config_includes(dir.path()).is_ok(), "{body}");
        }
        std::fs::remove_file(&config).unwrap();
        assert!(refuse_config_includes(dir.path()).is_ok());
    }

    #[test]
    fn broker_reads_do_not_enter_a_nested_repository() {
        let repo = tempfile::tempdir().unwrap();
        init_standalone_repo(repo.path());
        let nested = repo.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        init_standalone_repo(&nested);
        // Recorded as a gitlink, which Git treats as a submodule.
        git_in(repo.path(), &["add", "nested"]);
        git_in(repo.path(), &["commit", "-qm", "add nested"]);
        git_in(repo.path(), &["config", "diff.submodule", "diff"]);

        // The nested repository has its own filter; the outer configuration has none.
        let outside = tempfile::tempdir().unwrap();
        let marker = outside.path().join("filter-ran");
        let command = format!("touch '{}'; cat", marker.display().to_string().replace('\\', "/"));
        git_in(&nested, &["config", "filter.probe.clean", &command]);
        std::fs::write(nested.join(".gitattributes"), "README.md filter=probe\n").unwrap();
        std::fs::write(nested.join("README.md"), "changed by the test\n").unwrap();

        let engine = GitEngine::new();
        assert!(engine.status(repo.path(), 10).is_ok());
        assert!(engine.diff_summary(repo.path(), None, false).is_ok());
        assert!(engine.diff_page(repo.path(), None, false, None, None, 0, 1024).is_ok());
        assert!(!marker.exists(), "a Git read ran a command configured in a nested repository");
    }

    #[test]
    fn broker_refuses_a_repository_that_includes_other_configuration() {
        let repo = tempfile::tempdir().unwrap();
        init_standalone_repo(repo.path());
        let engine = GitEngine::new();
        // The included file does not exist yet; it could appear after the check.
        git_in(repo.path(), &["config", "include.path", "../later.cfg"]);
        assert!(engine.status(repo.path(), 10).unwrap_err().message.contains("content filter"));
        // The refusal comes from reading the file, before Git is asked anything.
        assert!(refuse_config_includes(&repo.path().join(".git")).is_err());
        git_in(repo.path(), &["config", "--unset", "include.path"]);
        git_in(repo.path(), &["config", "includeIf.gitdir:/.path", "../later.cfg"]);
        assert!(engine.status(repo.path(), 10).is_err());
    }

    #[test]
    fn broker_refuses_metadata_redirected_after_a_passed_read() {
        let repo = tempfile::tempdir().unwrap();
        init_standalone_repo(repo.path());
        let engine = GitEngine::new();
        assert!(engine.status(repo.path(), 10).is_ok());
        assert!(engine.status(repo.path(), 10).is_ok());

        // A linked-worktree marker appears inside a real `.git` directory.
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(
            repo.path().join(".git").join("commondir"),
            elsewhere.path().display().to_string(),
        )
        .unwrap();
        assert!(engine.status(repo.path(), 10).is_err());

        // `.git` is replaced by a pointer file after a passed read.
        let pointer = tempfile::tempdir().unwrap();
        init_standalone_repo(pointer.path());
        assert!(engine.status(pointer.path(), 10).is_ok());
        let dotgit = pointer.path().join(".git");
        std::fs::remove_dir_all(&dotgit).unwrap();
        std::fs::write(&dotgit, format!("gitdir: {}", elsewhere.path().display())).unwrap();
        assert!(engine.status(pointer.path(), 10).is_err());
    }

    #[test]
    fn broker_refuses_without_self_contained_metadata() {
        let engine = GitEngine::new();
        let bare = tempfile::tempdir().unwrap();
        assert!(engine.status(bare.path(), 10).is_err());
        assert!(engine.diff_summary(bare.path(), None, false).is_err());
        let linked = tempfile::tempdir().unwrap();
        init_standalone_repo(linked.path());
        let dotgit = linked.path().join(".git");
        let target = tempfile::tempdir().unwrap();
        std::fs::remove_dir_all(&dotgit).unwrap();
        std::fs::write(&dotgit, format!("gitdir: {}", target.path().display())).unwrap();
        assert!(engine.status(linked.path(), 10).is_err());
        assert!(engine.diff_summary(linked.path(), None, false).is_err());
    }
}
