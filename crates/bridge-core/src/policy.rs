//! Strict broker- and host-side authorization policy engine (§6).
//! Enforces:
//! - `edge` principal stays strictly read-only.
//! - `delegated_executor` and `paired_host` actions require a valid, non-revoked, non-expired
//!   `TaskGrantEnvelope` matching host, project, policy_revision, category, path, and recipe.
//! - Cache keys partition strictly by `(principal, host_id, project_id, policy_revision, digest)`.

use bridge_platform::validate_relative_path;
use bridge_types::*;
use chrono::Utc;

use crate::files::is_hidden_from_remote;
use crate::state::{ProjectRow, StateStore};

pub const PRO_REVIEW_CATEGORIES: [OperationCategory; 4] = [
    OperationCategory::Read,
    OperationCategory::GitRead,
    OperationCategory::Write,
    OperationCategory::ExecuteRecipe,
];
pub const PRO_REVIEW_WRITABLE_PATH: &str = "_pro/**";
pub const DELEGATED_DENIED_PATHS: [&str; 1] = ["_pro/inbox/**"];
pub const PRO_REVIEW_RECIPES: [&str; 2] = ["python_tests", "powershell_script"];

#[derive(Debug, Clone)]
pub struct AuthorizationDecision {
    pub project: ProjectRow,
    pub grant_id: Option<GrantId>,
    pub effective_scope: Vec<String>,
    pub normalized_write_path: Option<String>,
    pub grant: Option<TaskGrantEnvelope>,
}

enum RecipePermission<'a> {
    Execute(Option<&'a str>),
    RunOutput,
    CancelGrant,
}

pub struct PolicyEngine<'a> {
    store: &'a StateStore,
    local_host_id: HostId,
}

impl<'a> PolicyEngine<'a> {
    pub fn new(store: &'a StateStore, local_host_id: HostId) -> Self {
        Self {
            store,
            local_host_id,
        }
    }

    /// Authorize an operation on a specific project. Re-validated fresh from SQLite on every call.
    pub fn authorize(
        &self,
        principal: &Principal,
        project_id: &str,
        category: OperationCategory,
        target_path: Option<&str>,
        recipe: Option<&str>,
        grant_id_hint: Option<&str>,
    ) -> Result<AuthorizationDecision, BridgeError> {
        self.authorize_action(
            principal, project_id, category, target_path, RecipePermission::Execute(recipe),
            grant_id_hint,
        )
    }

    /// The caller must also verify that the run belongs to this principal and grant.
    pub fn authorize_run_output(
        &self,
        principal: &Principal,
        project_id: &str,
        grant_id_hint: Option<&str>,
    ) -> Result<AuthorizationDecision, BridgeError> {
        self.authorize_action(
            principal, project_id, OperationCategory::ExecuteRecipe, None,
            RecipePermission::RunOutput, grant_id_hint,
        )
    }

    /// Select the caller's cancellation grant before looking up a run or its recipe.
    pub fn authorize_run_cancel_grant(
        &self,
        principal: &Principal,
        project_id: &str,
        grant_id_hint: Option<&str>,
    ) -> Result<AuthorizationDecision, BridgeError> {
        self.authorize_action(
            principal, project_id, OperationCategory::ExecuteRecipe, None,
            RecipePermission::CancelGrant, grant_id_hint,
        )
    }

    /// Re-check the same grant after staging and just before a delegated file is installed.
    pub fn authorize_write_commit(
        &self,
        principal: &Principal,
        project_id: &str,
        category: OperationCategory,
        target_path: &str,
        grant_id: &str,
    ) -> Result<(), BridgeError> {
        self.authorize(principal, project_id, category, Some(target_path), None, Some(grant_id))
            .map(|_| ())
            .map_err(|error| match error.code {
                ErrorCode::ProjectNotGranted | ErrorCode::StalePrecondition | ErrorCode::BridgePolicyDenied => {
                    BridgeError::new(
                        ErrorCode::BridgePolicyDenied,
                        "The delegated write grant is no longer valid at commit.",
                        OriginLayer::Policy,
                    )
                }
                _ => error,
            })
    }

    fn authorize_action(
        &self,
        principal: &Principal,
        project_id: &str,
        category: OperationCategory,
        target_path: Option<&str>,
        recipe_permission: RecipePermission<'_>,
        grant_id_hint: Option<&str>,
    ) -> Result<AuthorizationDecision, BridgeError> {
        let path_parts = if !principal.is_local() {
            target_path.map(validate_remote_relative_path).transpose()?
        } else {
            None
        };
        let project = self.store.get_project(project_id, principal)?;

        match principal {
            Principal::Local => Ok(AuthorizationDecision {
                project,
                grant_id: None,
                effective_scope: vec!["local_owner".to_string()],
                normalized_write_path: None,
                grant: None,
            }),
            Principal::Edge => {
                // Non-negotiable V0.4.0 rule (§6): `edge` principal remains strictly read-only.
                if matches!(category, OperationCategory::Read | OperationCategory::GitRead) {
                    Ok(AuthorizationDecision {
                        project,
                        grant_id: None,
                        effective_scope: vec!["edge_read".to_string()],
                        normalized_write_path: None,
                        grant: None,
                    })
                } else {
                    Err(BridgeError::new(
                        ErrorCode::BridgePolicyDenied,
                        format!(
                            "Principal 'edge' is strictly read-only; operation '{category:?}' requires an authorized DelegatedExecutor grant or Local owner action."
                        ),
                        OriginLayer::Policy,
                    ))
                }
            }
            Principal::DelegatedExecutor(_) | Principal::PairedHost(_) => {
                let cancel_grant = matches!(recipe_permission, RecipePermission::CancelGrant);
                let grant = self.resolve_active_grant(principal, &project, grant_id_hint)?;
                if grant.host_id != self.local_host_id {
                    return Err(BridgeError::new(
                        ErrorCode::BridgePolicyDenied,
                        "Grant host_id does not match this target host identity.",
                        OriginLayer::Policy,
                    ));
                }
                if grant.revoked {
                    return Err(BridgeError::new(
                        ErrorCode::BridgePolicyDenied,
                        "Task grant has been revoked.",
                        OriginLayer::Policy,
                    ));
                }
                if grant.expires_at <= Utc::now() {
                    return Err(BridgeError::new(
                        ErrorCode::BridgePolicyDenied,
                        "Task grant has expired.",
                        OriginLayer::Policy,
                    ));
                }
                if grant.policy_revision != project.policy_revision {
                    return Err(BridgeError::new(
                        ErrorCode::StalePrecondition,
                        format!(
                            "Task grant policy_revision ({}) is stale vs project policy_revision ({}).",
                            grant.policy_revision, project.policy_revision
                        ),
                        OriginLayer::Policy,
                    )
                    .with_next_action("Request a new owner grant for the current project policy revision."));
                }
                if !grant.permitted_categories.contains(&category) {
                    return Err(BridgeError::new(
                        ErrorCode::BridgePolicyDenied,
                        format!("Operation category '{category:?}' is outside grant '{}'.", grant.grant_id),
                        OriginLayer::Policy,
                    ));
                }
                let normalized_write_path = if matches!(category, OperationCategory::Write | OperationCategory::Patch) {
                    let parts = path_parts.ok_or_else(|| {
                        BridgeError::new(
                            ErrorCode::InvalidArgument,
                            "A file path is required for a delegated write.",
                            OriginLayer::Policy,
                        )
                    })?;
                    if parts.is_empty() {
                        return Err(BridgeError::new(
                            ErrorCode::InvalidArgument,
                            "A delegated write cannot target the project root.",
                            OriginLayer::Policy,
                        ));
                    }
                    if is_hidden_from_remote(&parts) {
                        return Err(BridgeError::new(
                            ErrorCode::BridgePolicyDenied,
                            "Access to protected secret/credential path is denied.",
                            OriginLayer::Policy,
                        )
                        .with_next_action(
                            "Protected secret and credential paths cannot be accessed remotely even with a grant; choose a non-protected project path.",
                        ));
                    }
                    let path = parts.join("/");
                    if is_pro_inbox_path(&path) {
                        return Err(BridgeError::new(
                            ErrorCode::BridgePolicyDenied,
                            format!("Writable path '{path}' is denied because _pro/inbox/ is read-only for delegated principals."),
                            OriginLayer::Policy,
                        )
                        .with_next_action(
                            "The _pro/inbox/ folder holds requests from local agents and is read-only for delegated principals. Write under a path your grant allows; a pro-review grant allows _pro/outbox/ and _pro/reports/.",
                        ));
                    }
                    if !path_allowed_by_grant(&path, &grant.writable_paths) {
                        return Err(BridgeError::new(
                            ErrorCode::BridgePolicyDenied,
                            format!("Writable path '{path}' is outside grant writable_paths."),
                            OriginLayer::Policy,
                        ));
                    }
                    Some(path)
                } else {
                    None
                };
                if category == OperationCategory::ExecuteRecipe && !cancel_grant {
                    let recipe = match recipe_permission {
                        RecipePermission::Execute(recipe) => recipe,
                        RecipePermission::RunOutput => Some("read_output"),
                        RecipePermission::CancelGrant => unreachable!(),
                    };
                    let req_recipe = recipe.ok_or_else(|| {
                        BridgeError::new(
                            ErrorCode::InvalidArgument,
                            "Recipe name is required for ExecuteRecipe authorization.",
                            OriginLayer::Policy,
                        )
                    })?;
                    let pro_review_output = matches!(recipe_permission, RecipePermission::RunOutput)
                        && grant.permitted_categories == PRO_REVIEW_CATEGORIES
                        && grant.writable_paths == [PRO_REVIEW_WRITABLE_PATH]
                        && grant.allowed_recipes == PRO_REVIEW_RECIPES;
                    if !pro_review_output && !grant.allowed_recipes.iter().any(|r| r == req_recipe) {
                        return Err(BridgeError::new(
                            ErrorCode::BridgePolicyDenied,
                            format!("Recipe '{req_recipe}' is not allowed by grant '{}'.", grant.grant_id),
                            OriginLayer::Policy,
                        ));
                    }
                }
                Ok(AuthorizationDecision {
                    project,
                    grant_id: Some(grant.grant_id.clone()),
                    effective_scope: grant.writable_paths.clone(),
                    normalized_write_path,
                    grant: Some(grant),
                })
            }
        }
    }

    fn resolve_active_grant(
        &self,
        principal: &Principal,
        project: &ProjectRow,
        grant_id_hint: Option<&str>,
    ) -> Result<TaskGrantEnvelope, BridgeError> {
        let key = principal.as_db_key();
        if let Some(gid) = grant_id_hint {
            let g = self.store.get_task_grant(gid)?.ok_or_else(|| {
                BridgeError::new(
                    ErrorCode::BridgePolicyDenied,
                    "Specified grant_id does not exist.",
                    OriginLayer::Policy,
                )
            })?;
            if g.requester_principal != key || g.project_id.0 != project.project_id {
                return Err(BridgeError::new(
                    ErrorCode::BridgePolicyDenied,
                    "Grant principal or project_id does not match authenticated request.",
                    OriginLayer::Policy,
                ));
            }
            return Ok(g);
        }
        // The store lists the newest grant first. The first one that is valid for this call is used.
        // An expiry that cannot be read is decoded as the time of loading, so the clock is read afterwards.
        let grants = self.store.list_task_grants(Some(&project.project_id))?;
        let now = Utc::now();
        let selected = grants.into_iter().find(|g| {
            g.requester_principal == key
                && g.project_id.0 == project.project_id
                && g.host_id == self.local_host_id
                && !g.revoked
                && g.expires_at > now
                && g.policy_revision == project.policy_revision
        });
        selected.ok_or_else(|| {
            BridgeError::new(
                ErrorCode::ProjectNotGranted,
                "No active task grant found for this principal and project.",
                OriginLayer::Policy,
            )
        })
    }
}

/// Reject internal stage names and Windows short names before resolving a remote path.
pub fn validate_remote_relative_path(path: &str) -> Result<Vec<String>, BridgeError> {
    let parts = validate_relative_path(path)?;
    if parts.iter().any(|part| is_patch_stage_name(part)) {
        return Err(BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            "Internal patch staging paths are unavailable on remote connections.",
            OriginLayer::Policy,
        )
        .with_next_action("Internal staging paths cannot be accessed remotely; choose a regular project path."));
    }
    if has_windows_short_name(&parts) {
        return Err(BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            "Windows short-name components are not allowed on remote connections.",
            OriginLayer::Policy,
        )
        .with_next_action("Use the exact long path name without Windows 8.3 short-name components."));
    }
    Ok(parts)
}

pub(crate) fn is_patch_stage_name(name: &str) -> bool {
    const PREFIX: &str = ".eb_stage_";
    name.as_bytes().get(..PREFIX.len()).is_some_and(|start| start.eq_ignore_ascii_case(PREFIX.as_bytes()))
}

pub(crate) fn has_windows_short_name(parts: &[String]) -> bool {
    parts.iter().any(|part| {
        part.as_bytes().windows(2).any(|pair| pair[0] == b'~' && pair[1].is_ascii_digit())
    })
}

/// Find the broadest granted folder containing this validated target. A literal file
/// permission uses its containing folder for accounting.
pub(crate) fn delegated_write_quota_scope<'a>(path: &'a str, patterns: &'a [String]) -> Option<&'a str> {
    if is_pro_inbox_path(path) {
        return None;
    }
    patterns.iter().filter_map(|pattern| grant_folder_for_path(path, pattern)).min_by_key(|path| path.len())
}

/// No non-ASCII character folds to an ASCII letter on NTFS, so ASCII case folding is exact here.
fn is_pro_inbox_path(normalized_path: &str) -> bool {
    let lower = normalized_path.to_ascii_lowercase();
    lower == "_pro/inbox" || lower.starts_with("_pro/inbox/")
}

/// Match validated slash-delimited paths case-sensitively on every filesystem.
fn path_allowed_by_grant(normalized_path: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| grant_folder_for_path(normalized_path, pattern).is_some())
}

/// Whether the holder of a grant with these writable paths could have created the file at `path`.
///
/// Used to keep a requester's own files out of anything that executes. Unlike the write check this
/// folds case, because Windows opens `_PRO/x` for a file created as `_pro/x`. A component holding
/// `~` and a digit also counts, because such a short name can stand for any folder.
pub fn path_is_grant_writable(normalized_path: &str, patterns: &[String]) -> bool {
    let path = normalized_path.to_lowercase();
    let parts: Vec<String> = path.split('/').map(str::to_owned).collect();
    has_windows_short_name(&parts)
        || patterns.iter().any(|pattern| grant_folder_for_path(&path, &pattern.to_lowercase()).is_some())
}

/// Whether those writable paths cover everything inside `folder`. A pattern that names one file
/// does not make its folder writable.
pub fn folder_is_grant_writable(normalized_folder: &str, patterns: &[String]) -> bool {
    let folder = normalized_folder.to_lowercase();
    let parts: Vec<String> = folder.split('/').map(str::to_owned).collect();
    has_windows_short_name(&parts) || patterns.iter().any(|pattern| {
        let pattern = pattern.to_lowercase();
        let pattern = pattern.trim_start_matches("./");
        if matches!(pattern, "." | "*" | "**") {
            return true;
        }
        pattern.strip_suffix("/**").or_else(|| pattern.strip_suffix('/')).is_some_and(|prefix| {
            folder == prefix || folder.strip_prefix(prefix).is_some_and(|tail| tail.starts_with('/'))
        })
    })
}

/// A run executes project files, so a grant that may also write project files could run what its
/// holder wrote. Only a grant with no write access, or one confined to the review folder, may queue.
pub fn grant_may_queue_runs(grant: &TaskGrantEnvelope) -> Result<(), BridgeError> {
    let writes = grant.permitted_categories.iter()
        .any(|category| matches!(category, OperationCategory::Write | OperationCategory::Patch));
    if writes && grant.writable_paths != [PRO_REVIEW_WRITABLE_PATH] {
        return Err(BridgeError::new(ErrorCode::BridgePolicyDenied,
            "This grant can write project files, so it cannot queue a run. Use a grant whose only writable path is the review folder.",
            OriginLayer::Policy));
    }
    Ok(())
}

fn grant_folder_for_path<'a>(path: &'a str, pattern: &'a str) -> Option<&'a str> {
    let pattern = pattern.trim_start_matches("./");
    if matches!(pattern, "." | "*" | "**") {
        return Some("");
    }
    if let Some(prefix) = pattern.strip_suffix("/**").or_else(|| pattern.strip_suffix('/')) {
        return path.strip_prefix(prefix).filter(|tail| tail.starts_with('/')).map(|_| prefix);
    }
    (path == pattern).then(|| path.rsplit_once('/').map_or("", |(folder, _)| folder))
}

/// Partitioned cache key preventing cross-principal, cross-host, or post-revocation cache leaks (§10, §14).
pub fn partitioned_cache_key(
    principal: &Principal,
    host_id: &HostId,
    project_id: &str,
    policy_revision: PolicyRevision,
    content_digest: &str,
) -> String {
    format!(
        "{}|{}|{}|rev:{}|{}",
        principal.as_db_key(),
        host_id.0,
        project_id,
        policy_revision,
        content_digest
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn a_file_the_grant_holder_could_have_written_is_recognised_by_any_spelling() {
        let granted = ["_pro/**".to_string()];
        for path in ["_pro/reports/run.ps1", "_PRO/reports/run.ps1", "_Pro/Reports/RUN.PS1", "_pro/__init__.py",
            "_PRO~1/reports/run.ps1", "tools/REPORT~1/run.ps1"] {
            assert!(path_is_grant_writable(path, &granted), "{path}");
        }
        for path in ["check.ps1", "tests/test_calc.py", "_project/run.ps1", "src/_pro/run.ps1", "notes~/run.ps1", "_pro"] {
            assert!(!path_is_grant_writable(path, &granted), "{path}");
        }
        assert!(path_is_grant_writable("anything/at/all.ps1", &["**".to_string()]));
        for (folder, pattern, whole) in [("_pro", "_pro/**", true), ("_PRO/reports", "_pro/**", true), ("_pro", "_pro/", true),
            ("_pro", "./_pro/**", true), ("anything", "**", true), ("tests", "tests/_", false), ("tests", "tests/test_a.py", false),
            ("_project", "_pro/**", false), ("src", "src/app/**", false), ("REPORT~1", "_pro/**", true)] {
            assert_eq!(folder_is_grant_writable(folder, &[pattern.to_string()]), whole, "{folder} under {pattern}");
        }
        assert!(path_is_grant_writable("Docs/Plan.ps1", &["docs/plan.ps1".to_string()]));
    }

    #[test]
    fn edge_stays_strictly_readonly_and_executor_respects_revocation_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(dir.path().join("state.sqlite3")).unwrap();
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        let proj = store.register_project(&root, "TestProj", "ntfs:1:2").unwrap();
        let proj = store.grant_edge_readonly(&proj.project_id).unwrap();
        let host = HostId::parse("host_local01").unwrap();
        let policy = PolicyEngine::new(&store, host.clone());

        // Edge can read, cannot write or execute
        assert!(policy
            .authorize(&Principal::Edge, &proj.project_id, OperationCategory::Read, None, None, None)
            .is_ok());
        assert!(policy
            .authorize(&Principal::Edge, &proj.project_id, OperationCategory::Write, Some("a.py"), None, None)
            .is_err());
        assert!(policy
            .authorize(&Principal::Edge, &proj.project_id, OperationCategory::ExecuteRecipe, None, Some("python_tests"), None)
            .is_err());

        // Scoped DelegatedExecutor succeeds within bounds, fails outside writable_paths, fails after revoke
        let exec = Principal::DelegatedExecutor("codex_lab".to_string());
        let grant = TaskGrantEnvelope {
            grant_id: GrantId::new_random(),
            requester_principal: exec.as_db_key(),
            granting_owner: "local_owner".to_string(),
            host_id: host.clone(),
            project_id: ProjectId(proj.project_id.clone()),
            workspace_id: WorkspaceId::new_random(),
            baseline_hash: "sha256:0000".to_string(),
            policy_revision: proj.policy_revision,
            permitted_categories: vec![
                OperationCategory::Read,
                OperationCategory::Write,
                OperationCategory::ExecuteRecipe,
            ],
            writable_paths: vec!["src/**".to_string()],
            allowed_recipes: vec!["python_tests".to_string()],
            network_destinations: Vec::new(),
            export_scope: "redacted_summary".to_string(),
            integration_mode: IntegrationMode::AwaitOwnerReview,
            limits: ResourceLimits::default(),
            offline_policy: OfflineGrantPolicy::DenyNewAllowRunningDeterministic,
            expires_at: Utc::now() + Duration::minutes(30),
            revoked: false,
            revoked_at: None,
            created_at: Utc::now(),
        };
        store.create_task_grant(&grant).unwrap();

        let decision = policy
            .authorize(&exec, &proj.project_id, OperationCategory::Write, Some("src/app.py"), None, Some(&grant.grant_id.0))
            .unwrap();
        assert_eq!(decision.normalized_write_path.as_deref(), Some("src/app.py"));
        assert!(policy
            .authorize(&exec, &proj.project_id, OperationCategory::Write, None, None, Some(&grant.grant_id.0))
            .is_err());
        assert!(policy
            .authorize(&exec, &proj.project_id, OperationCategory::Write, Some("secrets.py"), None, Some(&grant.grant_id.0))
            .is_err());
        assert!(policy
            .authorize(&exec, &proj.project_id, OperationCategory::ExecuteRecipe, None, Some("python_tests"), Some(&grant.grant_id.0))
            .is_ok());
        assert!(policy
            .authorize(&exec, &proj.project_id, OperationCategory::ExecuteRecipe, None, Some("firmware_flash"), Some(&grant.grant_id.0))
            .is_err());

        // Revoke immediately blocks
        store.revoke_task_grant(&grant.grant_id.0).unwrap();
        assert!(policy
            .authorize(&exec, &proj.project_id, OperationCategory::Write, Some("src/app.py"), None, Some(&grant.grant_id.0))
            .is_err());
    }

    #[test]
    fn delegated_principals_cannot_write_or_patch_pro_inbox_under_any_grant() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(dir.path().join("state.sqlite3")).unwrap();
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        let proj = store.register_project(&root, "ReviewProj", "ntfs:1:3").unwrap();
        let host = HostId::parse("host_local02").unwrap();
        let policy = PolicyEngine::new(&store, host.clone());
        let exec = Principal::DelegatedExecutor("default".to_string());
        let paired = Principal::PairedHost("peer_01".to_string());

        let make_grant = |principal: &Principal, writable_paths: Vec<String>| {
            let g = TaskGrantEnvelope {
                grant_id: GrantId::new_random(),
                requester_principal: principal.as_db_key(),
                granting_owner: "local_owner".to_string(),
                host_id: host.clone(),
                project_id: ProjectId(proj.project_id.clone()),
                workspace_id: WorkspaceId::new_random(),
                baseline_hash: "sha256:0000".to_string(),
                policy_revision: proj.policy_revision,
                permitted_categories: vec![
                    OperationCategory::Read,
                    OperationCategory::GitRead,
                    OperationCategory::Write,
                    OperationCategory::Patch,
                    OperationCategory::ExecuteRecipe,
                ],
                writable_paths,
                allowed_recipes: PRO_REVIEW_RECIPES.map(str::to_owned).to_vec(),
                network_destinations: Vec::new(),
                export_scope: "redacted_summary".to_string(),
                integration_mode: IntegrationMode::AwaitOwnerReview,
                limits: ResourceLimits::default(),
                offline_policy: OfflineGrantPolicy::DenyNewAllowRunningDeterministic,
                expires_at: Utc::now() + Duration::minutes(30),
                revoked: false,
                revoked_at: None,
                created_at: Utc::now(),
            };
            store.create_task_grant(&g).unwrap();
            g
        };

        let grant = make_grant(&exec, vec![PRO_REVIEW_WRITABLE_PATH.to_owned()]);
        assert!(grant_may_queue_runs(&grant).is_ok());

        for category in [OperationCategory::Write, OperationCategory::Patch] {
            for denied in [
                "_pro/inbox/msg.md",
                "_pro/inbox/sub/msg.md",
                "_pro/inbox",
                "_pro/INBOX",
                "_pro/INBOX/msg.md",
                "_pro/Inbox/Msg.md",
                "_PRO/inbox/msg.md",
                "_PRO/INBOX/msg.md",
            ] {
                let err = policy
                    .authorize(&exec, &proj.project_id, category, Some(denied), None, Some(&grant.grant_id.0))
                    .unwrap_err();
                assert_eq!(err.code, ErrorCode::BridgePolicyDenied, "{category:?} {denied}");
                assert_eq!(
                    err.next_action,
                    "The _pro/inbox/ folder holds requests from local agents and is read-only for delegated principals. Write under a path your grant allows; a pro-review grant allows _pro/outbox/ and _pro/reports/.",
                    "{category:?} {denied}"
                );
            }
            for hazard in [
                "_pro/./inbox/x",
                "_pro//inbox/x",
                "_pro/inbox./x",
                "_pro/inbox /x",
                "_pro/inbox.",
                "_pro/inbox ",
                r"_pro\inbox\x",
                "_pro/outbox/../inbox/x",
                "_pro/INBOX~1/x",
            ] {
                assert!(
                    policy
                        .authorize(&exec, &proj.project_id, category, Some(hazard), None, Some(&grant.grant_id.0))
                        .is_err(),
                    "{category:?} {hazard}"
                );
            }
            for allowed in [
                "_pro/outbox/reply.md",
                "_pro/reports/review.md",
                "_pro/notes.md",
                "_pro/inbox_notes/ok.md",
            ] {
                assert!(
                    policy
                        .authorize(&exec, &proj.project_id, category, Some(allowed), None, Some(&grant.grant_id.0))
                        .is_ok(),
                    "{category:?} {allowed}"
                );
            }
        }

        // Broad "**", explicit "_pro/inbox/**", and non-pro-review "src/**" grants are all refused for _pro/inbox/.
        let wildcard_grant = make_grant(&exec, vec!["**".to_owned()]);
        let inbox_only_grant = make_grant(&exec, vec!["_pro/inbox/**".to_owned()]);
        let src_grant = make_grant(&exec, vec!["src/**".to_owned()]);
        let outbox_only_grant = make_grant(&exec, vec!["_pro/outbox/**".to_owned()]);
        let paired_grant = make_grant(&paired, vec!["**".to_owned()]);

        for category in [OperationCategory::Write, OperationCategory::Patch] {
            let wc_err = policy
                .authorize(&exec, &proj.project_id, category, Some("_pro/inbox/msg.md"), None, Some(&wildcard_grant.grant_id.0))
                .unwrap_err();
            assert_eq!(wc_err.code, ErrorCode::BridgePolicyDenied);
            assert!(wc_err.next_action.contains("_pro/outbox/") && wc_err.next_action.contains("_pro/reports/"));

            let paired_err = policy
                .authorize(&paired, &proj.project_id, category, Some("_pro/INBOX/msg.md"), None, Some(&paired_grant.grant_id.0))
                .unwrap_err();
            assert_eq!(paired_err.code, ErrorCode::BridgePolicyDenied);

            for g in [&inbox_only_grant, &src_grant, &outbox_only_grant] {
                let err = policy
                    .authorize(&exec, &proj.project_id, category, Some("_pro/inbox/msg.md"), None, Some(&g.grant_id.0))
                    .unwrap_err();
                assert_eq!(err.code, ErrorCode::BridgePolicyDenied);
                assert_eq!(err.next_action, "The _pro/inbox/ folder holds requests from local agents and is read-only for delegated principals. Write under a path your grant allows; a pro-review grant allows _pro/outbox/ and _pro/reports/.");
            }
        }

        // Reading _pro/inbox/ still succeeds.
        for readable in ["_pro/inbox", "_pro/inbox/request.md"] {
            assert!(
                policy
                    .authorize(&exec, &proj.project_id, OperationCategory::Read, Some(readable), None, Some(&grant.grant_id.0))
                    .is_ok(),
                "read {readable}"
            );
        }

        // Quota scope denies inbox paths under any pattern and accounts other _pro/** files under "_pro".
        let patterns = vec![PRO_REVIEW_WRITABLE_PATH.to_owned()];
        assert_eq!(delegated_write_quota_scope("_pro/inbox/msg.md", &patterns), None);
        assert_eq!(delegated_write_quota_scope("_pro/INBOX/msg.md", &["**".to_owned()]), None);
        assert_eq!(delegated_write_quota_scope("_pro/inbox", &["_pro/inbox/**".to_owned()]), None);
        assert_eq!(delegated_write_quota_scope("_pro/outbox/msg.md", &patterns), Some("_pro"));
        assert_eq!(delegated_write_quota_scope("_pro/inbox_notes/ok.md", &patterns), Some("_pro"));

        // Execution exclusion still treats all of _pro/ (including _pro/inbox/) as non-executable.
        assert!(folder_is_grant_writable("_pro", &patterns));
        assert!(folder_is_grant_writable("_pro/inbox", &patterns));
        assert!(path_is_grant_writable("_pro/inbox/script.ps1", &patterns));
    }

    #[test]
    fn omitted_grant_id_chooses_newest_valid_grant_without_being_hidden_by_expired_or_invalid_ones() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(dir.path().join("state.sqlite3")).unwrap();
        let root = dir.path().join("proj");
        let other_root = dir.path().join("other_proj");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&other_root).unwrap();
        let proj = store.register_project(&root, "ProjA", "ntfs:1:10").unwrap();
        let other_proj = store.register_project(&other_root, "ProjB", "ntfs:1:11").unwrap();
        let host = HostId::parse("host_local10").unwrap();
        let other_host = HostId::parse("host_remote99").unwrap();
        let policy = PolicyEngine::new(&store, host.clone());
        let exec = Principal::DelegatedExecutor("default".to_string());
        let other_exec = Principal::DelegatedExecutor("other".to_string());
        let now = Utc::now();

        let make_grant = |principal: &Principal,
                          project_id: &str,
                          host_id: &HostId,
                          policy_revision: u64,
                          created_offset_secs: i64,
                          expires_offset_secs: i64,
                          revoked: bool| {
            let mut g = TaskGrantEnvelope {
                grant_id: GrantId::new_random(),
                requester_principal: principal.as_db_key(),
                granting_owner: "local_owner".to_string(),
                host_id: host_id.clone(),
                project_id: ProjectId(project_id.to_string()),
                workspace_id: WorkspaceId::new_random(),
                baseline_hash: "sha256:0000".to_string(),
                policy_revision,
                permitted_categories: PRO_REVIEW_CATEGORIES.to_vec(),
                writable_paths: vec![PRO_REVIEW_WRITABLE_PATH.to_owned()],
                allowed_recipes: PRO_REVIEW_RECIPES.map(str::to_owned).to_vec(),
                network_destinations: Vec::new(),
                export_scope: "redacted_summary".to_string(),
                integration_mode: IntegrationMode::AwaitOwnerReview,
                limits: ResourceLimits::default(),
                offline_policy: OfflineGrantPolicy::DenyNewAllowRunningDeterministic,
                expires_at: now + Duration::seconds(expires_offset_secs),
                revoked: false,
                revoked_at: None,
                created_at: now + Duration::seconds(created_offset_secs),
            };
            store.create_task_grant(&g).unwrap();
            if revoked {
                // Mark revoked without bumping policy_revision so older grants stay on current revision.
                let conn = rusqlite::Connection::open(store.db_path()).unwrap();
                conn.execute(
                    "UPDATE task_grants SET revoked = 1, revoked_at = ?2 WHERE grant_id = ?1",
                    rusqlite::params![g.grant_id.0, now.to_rfc3339()],
                )
                .unwrap();
                g.revoked = true;
            }
            g
        };

        // Older valid grant, plus newer valid grant -> must pick newer valid grant.
        let older_valid = make_grant(&exec, &proj.project_id, &host, proj.policy_revision, -120, 1800, false);
        let newer_valid = make_grant(&exec, &proj.project_id, &host, proj.policy_revision, -60, 1800, false);
        // Newer invalid grants for the same principal and project that must NOT hide newer_valid:
        let expired_newer = make_grant(&exec, &proj.project_id, &host, proj.policy_revision, -30, -5, false);
        let revoked_newer = make_grant(&exec, &proj.project_id, &host, proj.policy_revision, -20, 1800, true);
        let wrong_host_newer = make_grant(&exec, &proj.project_id, &other_host, proj.policy_revision, -10, 1800, false);
        let stale_rev_newer = make_grant(&exec, &proj.project_id, &host, proj.policy_revision + 99, -5, 1800, false);
        // Even newer valid grants for OTHER principal / OTHER project must NEVER be selected:
        let _other_principal = make_grant(&other_exec, &proj.project_id, &host, proj.policy_revision, 0, 1800, false);
        let _other_project = make_grant(&exec, &other_proj.project_id, &host, other_proj.policy_revision, 0, 1800, false);

        for (cat, path, recipe) in [
            (OperationCategory::Read, None, None),
            (OperationCategory::Write, Some("_pro/reports/ok.md"), None),
            (OperationCategory::ExecuteRecipe, None, Some("python_tests")),
        ] {
            let dec = policy.authorize(&exec, &proj.project_id, cat, path, recipe, None).unwrap();
            assert_eq!(dec.grant_id.as_ref(), Some(&newer_valid.grant_id), "category {cat:?}");
        }

        // Explicit grant_id behavior is unchanged: each invalid grant is still refused with its specific reason.
        let exp_err = policy
            .authorize(&exec, &proj.project_id, OperationCategory::Read, None, None, Some(&expired_newer.grant_id.0))
            .unwrap_err();
        assert_eq!(exp_err.code, ErrorCode::BridgePolicyDenied);
        assert!(exp_err.message.contains("expired"));

        let rev_err = policy
            .authorize(&exec, &proj.project_id, OperationCategory::Read, None, None, Some(&revoked_newer.grant_id.0))
            .unwrap_err();
        assert_eq!(rev_err.code, ErrorCode::BridgePolicyDenied);
        assert!(rev_err.message.contains("revoked"));

        let host_err = policy
            .authorize(&exec, &proj.project_id, OperationCategory::Read, None, None, Some(&wrong_host_newer.grant_id.0))
            .unwrap_err();
        assert_eq!(host_err.code, ErrorCode::BridgePolicyDenied);
        assert!(host_err.message.contains("host_id"));

        let stale_err = policy
            .authorize(&exec, &proj.project_id, OperationCategory::Read, None, None, Some(&stale_rev_newer.grant_id.0))
            .unwrap_err();
        assert_eq!(stale_err.code, ErrorCode::StalePrecondition);

        // Once newer_valid is revoked (without bumping revision), older_valid is chosen.
        {
            let conn = rusqlite::Connection::open(store.db_path()).unwrap();
            conn.execute(
                "UPDATE task_grants SET revoked = 1, revoked_at = ?2 WHERE grant_id = ?1",
                rusqlite::params![newer_valid.grant_id.0, now.to_rfc3339()],
            )
            .unwrap();
        }
        let fallback = policy
            .authorize(&exec, &proj.project_id, OperationCategory::Read, None, None, None)
            .unwrap();
        assert_eq!(fallback.grant_id.as_ref(), Some(&older_valid.grant_id));

        // When no valid grant remains for this principal/project/host/revision, omitted grant_id refuses
        // with ProjectNotGranted and does not leak any grant ids.
        store.revoke_task_grant(&older_valid.grant_id.0).unwrap();
        let none_err = policy
            .authorize(&exec, &proj.project_id, OperationCategory::Read, None, None, None)
            .unwrap_err();
        assert_eq!(none_err.code, ErrorCode::ProjectNotGranted);
        for gid in [
            &older_valid.grant_id.0,
            &newer_valid.grant_id.0,
            &expired_newer.grant_id.0,
            &wrong_host_newer.grant_id.0,
            &stale_rev_newer.grant_id.0,
        ] {
            assert!(!none_err.message.contains(gid), "error leaked grant id {gid}");
        }
    }
}
