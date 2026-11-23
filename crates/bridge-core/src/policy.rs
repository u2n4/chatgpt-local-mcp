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

pub const PYTHON_TESTS_WORK_RECIPE: &str = "python_tests_work";
pub const POWERSHELL_SCRIPT_WORK_RECIPE: &str = "powershell_script_work";

pub const PRO_AGENT_CATEGORIES: [OperationCategory; 6] = [
    OperationCategory::Read,
    OperationCategory::GitRead,
    OperationCategory::Write,
    OperationCategory::Patch,
    OperationCategory::WorkArea,
    OperationCategory::ExecuteRecipe,
];
pub const PRO_AGENT_RECIPES: [&str; 3] = [
    "python_tests",
    "powershell_script",
    PYTHON_TESTS_WORK_RECIPE,
];
pub const PRO_WORK_PREFIX: &str = "_pro/work/";
pub const MAX_WORKSPACES_PER_PROJECT: usize = 16;

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
            grant_id_hint, false,
        )
    }

    /// Authorize a work-area mutation or workspace-scoped operation strictly inside exact-case
    /// `_pro/work/<work_name>[/<rel_subpath>]`.
    ///
    /// Pass `rel_subpath = Some(path)` for file-level overwrite, patch, copy, move, or delete,
    /// and `rel_subpath = None` for workspace-level operations (such as workspace diff or
    /// whole-workspace delete).
    pub fn authorize_work_mutation(
        &self,
        principal: &Principal,
        project_id: &str,
        work_name: &str,
        rel_subpath: Option<&str>,
        grant_id_hint: Option<&str>,
    ) -> Result<AuthorizationDecision, BridgeError> {
        if principal.is_edge() {
            return Err(BridgeError::new(
                ErrorCode::BridgePolicyDenied,
                "Principal 'edge' is strictly read-only; operation 'WorkArea' requires an authorized DelegatedExecutor grant or Local owner action.",
                OriginLayer::Policy,
            ));
        }
        validate_work_name(work_name)?;
        let (target, allow_workspace_root) = match rel_subpath {
            Some(subpath) => {
                let sub_parts = validate_remote_relative_path(subpath)?;
                if sub_parts.is_empty() {
                    return Err(BridgeError::new(
                        ErrorCode::InvalidArgument,
                        "A work-area file path cannot be empty or '.'.",
                        OriginLayer::Policy,
                    ));
                }
                (format!("{PRO_WORK_PREFIX}{work_name}/{}", sub_parts.join("/")), false)
            }
            None => (format!("{PRO_WORK_PREFIX}{work_name}"), true),
        };
        self.authorize_action(
            principal,
            project_id,
            OperationCategory::WorkArea,
            Some(&target),
            RecipePermission::Execute(None),
            grant_id_hint,
            allow_workspace_root,
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
            RecipePermission::RunOutput, grant_id_hint, false,
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
            RecipePermission::CancelGrant, grant_id_hint, false,
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
        allow_workspace_root: bool,
    ) -> Result<AuthorizationDecision, BridgeError> {
        let path_parts = if !principal.is_local() || category == OperationCategory::WorkArea {
            target_path.map(validate_remote_relative_path).transpose()?
        } else {
            None
        };
        let project = self.store.get_project(project_id, principal)?;

        match principal {
            Principal::Local => {
                let normalized_write_path = if category == OperationCategory::WorkArea {
                    let parts = path_parts.ok_or_else(|| {
                        BridgeError::new(
                            ErrorCode::InvalidArgument,
                            "A target path under '_pro/work/<workspace>/' is required for a WorkArea operation.",
                            OriginLayer::Policy,
                        )
                    })?;
                    Some(validate_work_area_parts(&parts, allow_workspace_root)?)
                } else {
                    None
                };
                Ok(AuthorizationDecision {
                    project,
                    grant_id: None,
                    effective_scope: vec!["local_owner".to_string()],
                    normalized_write_path,
                    grant: None,
                })
            }
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
                } else if category == OperationCategory::WorkArea {
                    if grant.writable_paths != [PRO_REVIEW_WRITABLE_PATH] {
                        return Err(BridgeError::new(
                            ErrorCode::BridgePolicyDenied,
                            "WorkArea operations require a grant whose writable_paths is strictly [\"_pro/**\"].",
                            OriginLayer::Policy,
                        ));
                    }
                    let parts = path_parts.ok_or_else(|| {
                        BridgeError::new(
                            ErrorCode::InvalidArgument,
                            "A target path under '_pro/work/<workspace>/' is required for a WorkArea operation.",
                            OriginLayer::Policy,
                        )
                    })?;
                    let path = validate_work_area_parts(&parts, allow_workspace_root)?;
                    if !path_allowed_by_grant(&path, &grant.writable_paths) {
                        return Err(BridgeError::new(
                            ErrorCode::BridgePolicyDenied,
                            format!("WorkArea path '{path}' is outside grant writable_paths."),
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
                    if req_recipe == POWERSHELL_SCRIPT_WORK_RECIPE {
                        return Err(BridgeError::new(
                            ErrorCode::BridgePolicyDenied,
                            "POWERSHELL_SCRIPT_WORK_UNSUPPORTED: recipe 'powershell_script_work' is not supported.",
                            OriginLayer::Policy,
                        ));
                    }
                    let pro_review_output = matches!(recipe_permission, RecipePermission::RunOutput)
                        && grant.permitted_categories == PRO_REVIEW_CATEGORIES
                        && grant.writable_paths == [PRO_REVIEW_WRITABLE_PATH]
                        && grant.allowed_recipes == PRO_REVIEW_RECIPES;
                    let pro_agent_output = matches!(recipe_permission, RecipePermission::RunOutput)
                        && grant.permitted_categories == PRO_AGENT_CATEGORIES
                        && grant.writable_paths == [PRO_REVIEW_WRITABLE_PATH]
                        && grant.allowed_recipes == PRO_AGENT_RECIPES;
                    let pro_profile_output = pro_review_output || pro_agent_output;
                    if !pro_profile_output && !grant.allowed_recipes.iter().any(|r| r == req_recipe) {
                        return Err(BridgeError::new(
                            ErrorCode::BridgePolicyDenied,
                            format!("Recipe '{req_recipe}' is not allowed by grant '{}'.", grant.grant_id),
                            OriginLayer::Policy,
                        ));
                    }
                    if req_recipe == PYTHON_TESTS_WORK_RECIPE
                        && !matches!(recipe_permission, RecipePermission::RunOutput)
                        && (!grant.permitted_categories.contains(&OperationCategory::WorkArea)
                            || grant.writable_paths != [PRO_REVIEW_WRITABLE_PATH])
                    {
                        return Err(BridgeError::new(
                            ErrorCode::BridgePolicyDenied,
                            "Recipe 'python_tests_work' requires a grant with OperationCategory::WorkArea and writable_paths == [\"_pro/**\"].",
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

/// Validate a workspace name under `_pro/work/<workspace>/`.
///
/// Must match `^[a-z0-9][a-z0-9_-]{0,39}$`, pass `validate_remote_relative_path`
/// (blocking traversal, backslashes, colons, reserved Windows device names, and short names),
/// and not be a hidden/secret name or internal patch staging name.
pub fn validate_work_name(name: &str) -> Result<(), BridgeError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 40 {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "Workspace name must be 1 to 40 ASCII characters matching ^[a-z0-9][a-z0-9_-]{0,39}$.",
            OriginLayer::Policy,
        ));
    }
    let first_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
    let rest_ok = bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'_');
    if !first_ok || !rest_ok {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "Workspace name must start with a lowercase ASCII letter or digit and contain only [a-z0-9_-].",
            OriginLayer::Policy,
        ));
    }
    let parts = validate_remote_relative_path(name).map_err(|_| {
        BridgeError::new(
            ErrorCode::InvalidArgument,
            format!("Workspace name '{name}' is not a permitted path component."),
            OriginLayer::Policy,
        )
    })?;
    if parts.len() != 1 || parts[0] != name {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            format!("Workspace name '{name}' must be a single path component."),
            OriginLayer::Policy,
        ));
    }
    if is_patch_stage_name(name) || is_hidden_from_remote(&parts) {
        return Err(BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            format!("Workspace name '{name}' is reserved or hidden from remote principals."),
            OriginLayer::Policy,
        ));
    }
    Ok(())
}

/// Strictly validate an optional single-test selector for `python_tests_work` and return its
/// canonical dotted Python unittest target (`tests.test_<name>[.<Class>[.<method>]]`).
///
/// Allowed input forms:
/// - `tests/test_<name>.py` (single forward slash, exact lowercase `tests/` and `.py`, ASCII `[A-Za-z0-9_]+` after `test_`)
/// - `tests.test_<name>[.<Class>[.<method>]]` (2..=4 dot-separated ASCII identifier parts)
///
/// Rejects option-like values starting with `-`, `..`, backslashes, extra path separators,
/// whitespace, short names, non-ASCII characters, and overly long selectors (>128 bytes).
pub fn validate_work_test_selector(selector: &str) -> Result<String, BridgeError> {
    let invalid = || {
        BridgeError::new(
            ErrorCode::InvalidArgument,
            "Invalid python_tests_work test selector; expected 'tests/test_<name>.py' or 'tests.test_<name>[.<Class>[.<method>]]'.",
            OriginLayer::Validation,
        )
    };
    if selector.is_empty()
        || selector.len() > 128
        || !selector.is_ascii()
        || selector.starts_with('-')
        || selector.contains("..")
        || selector.contains('\\')
        || selector.contains(':')
        || selector.contains('~')
        || selector.bytes().any(|b| b <= 0x20 || b == 0x7f)
    {
        return Err(invalid());
    }
    let valid_test_stem = |stem: &str| -> bool {
        stem.strip_prefix("test_").is_some_and(|rest| {
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    };
    let valid_ident = |ident: &str| -> bool {
        let bytes = ident.as_bytes();
        bytes.first().is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
            && bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
    };

    if selector.contains('/') {
        let parts: Vec<&str> = selector.split('/').collect();
        if parts.len() != 2 || parts[0] != "tests" {
            return Err(invalid());
        }
        let Some(stem) = parts[1].strip_suffix(".py") else {
            return Err(invalid());
        };
        if !valid_test_stem(stem) {
            return Err(invalid());
        }
        let path_parts = vec!["tests".to_string(), parts[1].to_string()];
        if is_hidden_from_remote(&path_parts) {
            return Err(BridgeError::new(
                ErrorCode::BridgePolicyDenied,
                "Access to protected secret/credential path is denied.",
                OriginLayer::Policy,
            ));
        }
        return Ok(format!("tests.{stem}"));
    }

    let parts: Vec<&str> = selector.split('.').collect();
    if !(2..=4).contains(&parts.len()) || parts[0] != "tests" || !valid_test_stem(parts[1]) {
        return Err(invalid());
    }
    for ident in &parts[2..] {
        if !valid_ident(ident) {
            return Err(invalid());
        }
    }
    let mod_file = format!("{}.py", parts[1]);
    if is_hidden_from_remote(&["tests".to_string(), mod_file]) {
        return Err(BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            "Access to protected secret/credential path is denied.",
            OriginLayer::Policy,
        ));
    }
    Ok(selector.to_string())
}

/// Validate `python_tests_work` arguments: `[workspace]` or `[workspace, selector]`.
/// Returns `(workspace, Option<canonical_dotted_test_target>)`.
pub fn validate_work_exec_args(args: &[String]) -> Result<(String, Option<String>), BridgeError> {
    match args {
        [workspace] => {
            validate_work_name(workspace)?;
            Ok((workspace.clone(), None))
        }
        [workspace, selector] => {
            validate_work_name(workspace)?;
            let canonical = validate_work_test_selector(selector)?;
            Ok((workspace.clone(), Some(canonical)))
        }
        _ => Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "Recipe 'python_tests_work' requires [workspace] or [workspace, test_selector].",
            OriginLayer::Validation,
        )),
    }
}

/// Returns true iff `normalized_path` is a valid, non-hidden remote relative file path strictly
/// inside exact-case `_pro/work/<workspace>/<subpath>`. Never folds case: any non-lowercase
/// `_pro` or `work` component is refused.
pub fn is_pro_work_file_path(normalized_path: &str) -> bool {
    let Ok(parts) = validate_remote_relative_path(normalized_path) else {
        return false;
    };
    parts.len() >= 4
        && parts[0] == "_pro"
        && parts[1] == "work"
        && validate_work_name(&parts[2]).is_ok()
        && !is_hidden_from_remote(&parts)
}

fn validate_work_area_parts(
    parts: &[String],
    allow_workspace_root: bool,
) -> Result<String, BridgeError> {
    if parts.is_empty() {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "A WorkArea operation cannot target the project root.",
            OriginLayer::Policy,
        ));
    }
    if is_hidden_from_remote(parts) {
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
            format!("WorkArea path '{path}' is denied because _pro/inbox/ is read-only for delegated principals."),
            OriginLayer::Policy,
        )
        .with_next_action(
            "The _pro/inbox/ folder holds requests from local agents and is read-only for delegated principals. Work-area mutations are permitted only inside exact-case _pro/work/<workspace>/**.",
        ));
    }
    // Exact-case rule: refuse any non-lowercase `_pro` or `work` spelling; never fold case.
    if parts.len() < 3 || parts[0] != "_pro" || parts[1] != "work" {
        return Err(BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            format!("WorkArea path '{path}' is denied; mutations are permitted only inside exact-case '_pro/work/<workspace>/**'."),
            OriginLayer::Policy,
        ));
    }
    validate_work_name(&parts[2])?;
    if !allow_workspace_root && parts.len() < 4 {
        return Err(BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            format!("WorkArea path '{path}' must target a file strictly inside '_pro/work/{}/'.", parts[2]),
            OriginLayer::Policy,
        ));
    }
    if !allow_workspace_root && !is_pro_work_file_path(&path) {
        return Err(BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            format!("WorkArea path '{path}' is outside '_pro/work/<workspace>/**'."),
            OriginLayer::Policy,
        ));
    }
    Ok(path)
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
    let writes = grant.permitted_categories.iter().any(|category| {
        matches!(
            category,
            OperationCategory::Write | OperationCategory::Patch | OperationCategory::WorkArea
        )
    });
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

    #[test]
    fn validate_work_name_and_is_pro_work_file_path_enforce_exact_case_and_block_hazards() {
        let max_len = "a".repeat(40);
        let over_len = "a".repeat(41);
        for valid in ["a", "0", "fix-1", "ws_01", "a0-b_9", max_len.as_str()] {
            assert!(validate_work_name(valid).is_ok(), "expected valid workspace name {valid:?}");
        }

        // Empty, over-long, uppercase, bad leading/inner characters, traversal, short names, device names.
        for invalid in [
            "",
            over_len.as_str(),
            "FIX",
            "Fix-1",
            "aB",
            "-fix",
            "_fix",
            "fix.1",
            "fix 1",
            "fix/1",
            r"fix\1",
            "fix:1",
            "..",
            ".",
            "work~1",
            "WORK~1",
            "café",
            "con",
            "nul",
            "prn",
            "aux",
            "com1",
            "lpt9",
        ] {
            let err = validate_work_name(invalid).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "workspace {invalid:?}");
        }

        // Hidden/secret names matching the character set are refused with BridgePolicyDenied.
        for hidden in ["id_rsa", "id_ed25519", "cookies", "kubeconfig", "api-token"] {
            let err = validate_work_name(hidden).unwrap_err();
            assert_eq!(err.code, ErrorCode::BridgePolicyDenied, "hidden workspace {hidden:?}");
        }

        // Valid exact-case file paths inside _pro/work/<workspace>/**.
        for ok_path in [
            "_pro/work/fix-1/a.py",
            "_pro/work/ws_01/src/sub/mod.rs",
            "_pro/work/0/README.md",
            &format!("_pro/work/{max_len}/file.txt"),
        ] {
            assert!(is_pro_work_file_path(ok_path), "expected valid work file path {ok_path:?}");
        }

        // Denied paths: workspace root itself, non-work _pro paths, live project paths,
        // traversal, backslash, colon/ADS, leading slash, 8.3 short names, wrong case of `_pro` or `work`,
        // bad workspace names, hidden/staging files, and Windows device names.
        let over_len_path = format!("_pro/work/{over_len}/a.py");
        for bad_path in [
            "_pro/work/fix-1",
            "_pro/work/fix-1/",
            "_pro/work",
            "_pro",
            "_pro/inbox/a.md",
            "_pro/outbox/a.md",
            "_pro/reports/a.md",
            "_pro/notes.md",
            "src/a.py",
            "_pro/work/fix-1/../outbox/a.py",
            "_pro/work/../src/a.py",
            "_pro/work/fix-1/a/../b.py",
            r"_pro\work\fix-1\a.py",
            r"_pro/work/fix-1/a\b.py",
            "_pro/work/fix-1/a.py:stream",
            "C:_pro/work/fix-1/a.py",
            "_pro/work/fix:1/a.py",
            "/_pro/work/fix-1/a.py",
            "_PRO~1/work/fix-1/a.py",
            "_pro/WORK~1/fix-1/a.py",
            "_pro/work/WORK~1/a.py",
            "_pro/work/fix-1/SUB~1/a.py",
            "_PRO/work/fix-1/a.py",
            "_Pro/work/fix-1/a.py",
            "_pro/WORK/fix-1/a.py",
            "_pro/Work/fix-1/a.py",
            "_PRO/WORK/fix-1/a.py",
            "_pro/work//a.py",
            over_len_path.as_str(),
            "_pro/work/FIX/a.py",
            "_pro/work/-bad/a.py",
            "_pro/work/con/a.py",
            "_pro/work/id_rsa/a.py",
            "_pro/work/fix-1/.env",
            "_pro/work/fix-1/.git/config",
            "_pro/work/fix-1/auth.json",
            "_pro/work/fix-1/.eb_stage_123",
            "_pro/work/fix-1/con.py",
            "_pro/work/fix-1/nul",
        ] {
            assert!(!is_pro_work_file_path(bad_path), "expected rejection for {bad_path:?}");
        }
    }

    #[test]
    fn pro_agent_work_area_policy_rules_preserve_pro_review_and_edge_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(dir.path().join("state.sqlite3")).unwrap();
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        let proj = store.register_project(&root, "AgentProj", "ntfs:2:1").unwrap();
        let proj = store.grant_edge_readonly(&proj.project_id).unwrap();
        let host = HostId::parse("host_local20").unwrap();
        let other_host = HostId::parse("host_other99").unwrap();
        let policy = PolicyEngine::new(&store, host.clone());
        let exec = Principal::DelegatedExecutor("default".to_string());

        let create_grant = |cats: Vec<OperationCategory>,
                            writable_paths: Vec<String>,
                            recipes: Vec<String>,
                            host_id: HostId,
                            rev: u64,
                            expires_offset_mins: i64| {
            let g = TaskGrantEnvelope {
                grant_id: GrantId::new_random(),
                requester_principal: exec.as_db_key(),
                granting_owner: "local_owner".to_string(),
                host_id,
                project_id: ProjectId(proj.project_id.clone()),
                workspace_id: WorkspaceId::new_random(),
                baseline_hash: "sha256:0000".to_string(),
                policy_revision: rev,
                permitted_categories: cats,
                writable_paths,
                allowed_recipes: recipes,
                network_destinations: Vec::new(),
                export_scope: "redacted_summary".to_string(),
                integration_mode: IntegrationMode::AwaitOwnerReview,
                limits: ResourceLimits::default(),
                offline_policy: OfflineGrantPolicy::DenyNewAllowRunningDeterministic,
                expires_at: Utc::now() + Duration::minutes(expires_offset_mins),
                revoked: false,
                revoked_at: None,
                created_at: Utc::now(),
            };
            store.create_task_grant(&g).unwrap();
            g
        };

        let review_grant = create_grant(
            PRO_REVIEW_CATEGORIES.to_vec(),
            vec![PRO_REVIEW_WRITABLE_PATH.to_owned()],
            PRO_REVIEW_RECIPES.map(str::to_owned).to_vec(),
            host.clone(),
            proj.policy_revision,
            30,
        );
        let agent_grant = create_grant(
            PRO_AGENT_CATEGORIES.to_vec(),
            vec![PRO_REVIEW_WRITABLE_PATH.to_owned()],
            PRO_AGENT_RECIPES.map(str::to_owned).to_vec(),
            host.clone(),
            proj.policy_revision,
            30,
        );
        let legacy_ps_grant = create_grant(
            PRO_AGENT_CATEGORIES.to_vec(),
            vec![PRO_REVIEW_WRITABLE_PATH.to_owned()],
            vec![
                "python_tests".to_owned(),
                "powershell_script".to_owned(),
                PYTHON_TESTS_WORK_RECIPE.to_owned(),
                POWERSHELL_SCRIPT_WORK_RECIPE.to_owned(),
            ],
            host.clone(),
            proj.policy_revision,
            30,
        );
        let work_recipe_without_work_area = create_grant(
            vec![
                OperationCategory::Read,
                OperationCategory::GitRead,
                OperationCategory::ExecuteRecipe,
            ],
            Vec::new(),
            vec![PYTHON_TESTS_WORK_RECIPE.to_owned()],
            host.clone(),
            proj.policy_revision,
            30,
        );
        let legacy_patch_grant = create_grant(
            vec![
                OperationCategory::Read,
                OperationCategory::GitRead,
                OperationCategory::Write,
                OperationCategory::Patch,
                OperationCategory::ExecuteRecipe,
            ],
            vec![PRO_REVIEW_WRITABLE_PATH.to_owned()],
            PRO_REVIEW_RECIPES.map(str::to_owned).to_vec(),
            host.clone(),
            proj.policy_revision,
            30,
        );
        let broad_work_grant = create_grant(
            PRO_AGENT_CATEGORIES.to_vec(),
            vec!["**".to_owned()],
            PRO_AGENT_RECIPES.map(str::to_owned).to_vec(),
            host.clone(),
            proj.policy_revision,
            30,
        );
        let src_work_grant = create_grant(
            vec![OperationCategory::Read, OperationCategory::WorkArea],
            vec!["src/**".to_owned()],
            vec!["python_tests".to_owned()],
            host.clone(),
            proj.policy_revision,
            30,
        );
        let expired_agent = create_grant(
            PRO_AGENT_CATEGORIES.to_vec(),
            vec![PRO_REVIEW_WRITABLE_PATH.to_owned()],
            PRO_AGENT_RECIPES.map(str::to_owned).to_vec(),
            host.clone(),
            proj.policy_revision,
            -5,
        );
        let wrong_host_agent = create_grant(
            PRO_AGENT_CATEGORIES.to_vec(),
            vec![PRO_REVIEW_WRITABLE_PATH.to_owned()],
            PRO_AGENT_RECIPES.map(str::to_owned).to_vec(),
            other_host,
            proj.policy_revision,
            30,
        );
        let stale_rev_agent = create_grant(
            PRO_AGENT_CATEGORIES.to_vec(),
            vec![PRO_REVIEW_WRITABLE_PATH.to_owned()],
            PRO_AGENT_RECIPES.map(str::to_owned).to_vec(),
            host.clone(),
            proj.policy_revision + 1,
            30,
        );

        // Positive: pro-agent authorizes work-area file and workspace mutations, commit re-check,
        // python_tests_work recipe, and job_output.
        let file_dec = policy
            .authorize_work_mutation(&exec, &proj.project_id, "fix-1", Some("src/a.py"), Some(&agent_grant.grant_id.0))
            .unwrap();
        assert_eq!(file_dec.normalized_write_path.as_deref(), Some("_pro/work/fix-1/src/a.py"));
        assert_eq!(file_dec.grant_id.as_ref(), Some(&agent_grant.grant_id));

        let ws_dec = policy
            .authorize_work_mutation(&exec, &proj.project_id, "fix-1", None, Some(&agent_grant.grant_id.0))
            .unwrap();
        assert_eq!(ws_dec.normalized_write_path.as_deref(), Some("_pro/work/fix-1"));

        policy
            .authorize_write_commit(&exec, &proj.project_id, OperationCategory::WorkArea, "_pro/work/fix-1/src/a.py", &agent_grant.grant_id.0)
            .unwrap();
        policy
            .authorize(&exec, &proj.project_id, OperationCategory::ExecuteRecipe, None, Some("python_tests_work"), Some(&agent_grant.grant_id.0))
            .unwrap();
        assert_eq!(
            policy
                .authorize(&exec, &proj.project_id, OperationCategory::ExecuteRecipe, None, Some("powershell_script_work"), Some(&agent_grant.grant_id.0))
                .unwrap_err()
                .code,
            ErrorCode::BridgePolicyDenied
        );
        // Even if a stored grant lists powershell_script_work, it is always refused.
        let ps_err = policy
            .authorize(&exec, &proj.project_id, OperationCategory::ExecuteRecipe, None, Some("powershell_script_work"), Some(&legacy_ps_grant.grant_id.0))
            .unwrap_err();
        assert_eq!(ps_err.code, ErrorCode::BridgePolicyDenied);
        assert!(ps_err.message.contains("POWERSHELL_SCRIPT_WORK_UNSUPPORTED"));
        // A grant listing python_tests_work without OperationCategory::WorkArea and writable_paths == ["_pro/**"] is refused.
        assert_eq!(
            policy
                .authorize(&exec, &proj.project_id, OperationCategory::ExecuteRecipe, None, Some("python_tests_work"), Some(&work_recipe_without_work_area.grant_id.0))
                .unwrap_err()
                .code,
            ErrorCode::BridgePolicyDenied
        );
        policy.authorize_run_output(&exec, &proj.project_id, Some(&agent_grant.grant_id.0)).unwrap();
        assert_eq!(
            policy
                .authorize_run_output(&exec, &proj.project_id, Some(&legacy_ps_grant.grant_id.0))
                .unwrap_err()
                .code,
            ErrorCode::BridgePolicyDenied
        );
        assert_eq!(
            policy
                .authorize(&exec, &proj.project_id, OperationCategory::ExecuteRecipe, None, Some("read_output"), Some(&agent_grant.grant_id.0))
                .unwrap_err()
                .code,
            ErrorCode::BridgePolicyDenied
        );
        assert!(grant_may_queue_runs(&agent_grant).is_ok());
        assert!(grant_may_queue_runs(&legacy_ps_grant).is_ok());

        // Negative: edge gains nothing.
        assert_eq!(
            policy.authorize_work_mutation(&Principal::Edge, &proj.project_id, "fix-1", Some("a.py"), None).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );
        assert_eq!(
            policy.authorize_work_mutation(&Principal::Edge, &proj.project_id, "BAD!", Some("a.py"), None).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );
        assert_eq!(
            policy.authorize(&Principal::Edge, &proj.project_id, OperationCategory::WorkArea, Some("_pro/work/fix-1/a.py"), None, None).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );
        assert_eq!(
            policy.authorize(&Principal::Edge, &proj.project_id, OperationCategory::ExecuteRecipe, None, Some("python_tests_work"), None).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );

        // Negative: pro-review and legacy grants behave strictly as before.
        assert_eq!(
            policy.authorize_work_mutation(&exec, &proj.project_id, "fix-1", Some("a.py"), Some(&review_grant.grant_id.0)).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );
        assert_eq!(
            policy.authorize(&exec, &proj.project_id, OperationCategory::ExecuteRecipe, None, Some("python_tests_work"), Some(&review_grant.grant_id.0)).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );
        policy.authorize_run_output(&exec, &proj.project_id, Some(&review_grant.grant_id.0)).unwrap();
        assert_eq!(
            policy.authorize_run_output(&exec, &proj.project_id, Some(&legacy_patch_grant.grant_id.0)).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );

        // Negative: WorkArea requires writable_paths == ["_pro/**"], and grant_may_queue_runs rejects broader WorkArea grants.
        for bad_grant in [&broad_work_grant, &src_work_grant] {
            assert_eq!(
                policy.authorize_work_mutation(&exec, &proj.project_id, "fix-1", Some("a.py"), Some(&bad_grant.grant_id.0)).unwrap_err().code,
                ErrorCode::BridgePolicyDenied
            );
            assert_eq!(grant_may_queue_runs(bad_grant).unwrap_err().code, ErrorCode::BridgePolicyDenied);
            assert_eq!(
                policy.authorize_run_output(&exec, &proj.project_id, Some(&bad_grant.grant_id.0)).unwrap_err().code,
                ErrorCode::BridgePolicyDenied
            );
        }

        // Negative: expired, wrong host, stale policy_revision.
        assert_eq!(
            policy.authorize_work_mutation(&exec, &proj.project_id, "fix-1", Some("a.py"), Some(&expired_agent.grant_id.0)).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );
        assert_eq!(
            policy.authorize_work_mutation(&exec, &proj.project_id, "fix-1", Some("a.py"), Some(&wrong_host_agent.grant_id.0)).unwrap_err().code,
            ErrorCode::BridgePolicyDenied
        );
        assert_eq!(
            policy.authorize_work_mutation(&exec, &proj.project_id, "fix-1", Some("a.py"), Some(&stale_rev_agent.grant_id.0)).unwrap_err().code,
            ErrorCode::StalePrecondition
        );

        // Negative: pro-agent still refuses _pro/inbox and outside-_pro paths for Write and Patch.
        for cat in [OperationCategory::Write, OperationCategory::Patch] {
            for denied in ["_pro/inbox/a.md", "_pro/INBOX/a.md", "src/a.py", "outside.txt", "_PRO/work/fix-1/a.py"] {
                assert_eq!(
                    policy.authorize(&exec, &proj.project_id, cat, Some(denied), None, Some(&agent_grant.grant_id.0)).unwrap_err().code,
                    ErrorCode::BridgePolicyDenied,
                    "{cat:?} {denied}"
                );
            }
        }

        // Negative: direct WorkArea authorization refuses everything outside exact-case _pro/work/<valid>/<file>.
        for denied in [
            "_pro/inbox/a.md",
            "_pro/outbox/a.md",
            "_pro/reports/a.md",
            "_pro/notes.md",
            "_pro/work/fix-1",
            "_PRO/work/fix-1/a.py",
            "_pro/WORK/fix-1/a.py",
            "_pro/Work/fix-1/a.py",
            "src/a.py",
            "_pro/work/fix-1/.env",
            "_pro/work/fix-1/.git/config",
            "_pro/work/WORK~1/a.py",
            "_pro/work/fix-1/SUB~1/a.py",
        ] {
            assert_eq!(
                policy
                    .authorize(&exec, &proj.project_id, OperationCategory::WorkArea, Some(denied), None, Some(&agent_grant.grant_id.0))
                    .unwrap_err()
                    .code,
                ErrorCode::BridgePolicyDenied,
                "WorkArea {denied}"
            );
        }
        for traversal in [
            "_pro/work/fix-1/../outbox/a.py",
            "_pro/work/../src/a.py",
            r"_pro\work\fix-1\a.py",
            "_pro/work/fix-1/a.py:stream",
            "/_pro/work/fix-1/a.py",
        ] {
            assert_eq!(
                policy
                    .authorize(&exec, &proj.project_id, OperationCategory::WorkArea, Some(traversal), None, Some(&agent_grant.grant_id.0))
                    .unwrap_err()
                    .code,
                ErrorCode::PathOutsideRoot,
                "WorkArea {traversal}"
            );
        }
        assert_eq!(
            policy
                .authorize(&exec, &proj.project_id, OperationCategory::WorkArea, Some("_pro/work/FIX/a.py"), None, Some(&agent_grant.grant_id.0))
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            policy
                .authorize(&exec, &proj.project_id, OperationCategory::WorkArea, Some("_pro/work/con/a.py"), None, Some(&agent_grant.grant_id.0))
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedPathType
        );

        // Negative: authorize_work_mutation rejects bad workspace names and bad subpaths.
        for bad_ws in ["", &"a".repeat(41), "FIX", "-bad", "_bad", "con", "nul", "com1", "..", "a/b", r"a\b", "a:b", "WORK~1"] {
            assert_eq!(
                policy
                    .authorize_work_mutation(&exec, &proj.project_id, bad_ws, Some("a.py"), Some(&agent_grant.grant_id.0))
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidArgument,
                "bad_ws {bad_ws:?}"
            );
        }
        for bad_sub in ["", "."] {
            assert_eq!(
                policy
                    .authorize_work_mutation(&exec, &proj.project_id, "fix-1", Some(bad_sub), Some(&agent_grant.grant_id.0))
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidArgument,
                "bad_sub {bad_sub:?}"
            );
        }
        for bad_sub_path in ["../outbox/a.py", r"a\b.py", "a.py:stream", "/a.py"] {
            assert_eq!(
                policy
                    .authorize_work_mutation(&exec, &proj.project_id, "fix-1", Some(bad_sub_path), Some(&agent_grant.grant_id.0))
                    .unwrap_err()
                    .code,
                ErrorCode::PathOutsideRoot,
                "bad_sub_path {bad_sub_path:?}"
            );
        }
        for denied_sub in ["SUB~1/a.py", ".env", ".git/config", ".eb_stage_1"] {
            assert_eq!(
                policy
                    .authorize_work_mutation(&exec, &proj.project_id, "fix-1", Some(denied_sub), Some(&agent_grant.grant_id.0))
                    .unwrap_err()
                    .code,
                ErrorCode::BridgePolicyDenied,
                "denied_sub {denied_sub:?}"
            );
        }

        // Revoking the pro-agent grant immediately blocks both authorize_work_mutation and commit re-check.
        store.revoke_task_grant(&agent_grant.grant_id.0).unwrap();
        assert_eq!(
            policy
                .authorize_work_mutation(&exec, &proj.project_id, "fix-1", Some("src/a.py"), Some(&agent_grant.grant_id.0))
                .unwrap_err()
                .code,
            ErrorCode::BridgePolicyDenied
        );
        assert_eq!(
            policy
                .authorize_write_commit(&exec, &proj.project_id, OperationCategory::WorkArea, "_pro/work/fix-1/src/a.py", &agent_grant.grant_id.0)
                .unwrap_err()
                .code,
            ErrorCode::BridgePolicyDenied
        );
    }

    #[test]
    fn work_test_selector_accepts_canonical_forms_and_rejects_injection_and_traversal() {
        for (raw, expected) in [
            ("tests/test_calc.py", "tests.test_calc"),
            ("tests/test_123_abc.py", "tests.test_123_abc"),
            ("tests.test_calc", "tests.test_calc"),
            ("tests.test_calc.CalcTests", "tests.test_calc.CalcTests"),
            ("tests.test_calc.CalcTests.test_add", "tests.test_calc.CalcTests.test_add"),
        ] {
            assert_eq!(validate_work_test_selector(raw).unwrap(), expected, "{raw}");
        }
        for bad in [
            "",
            "-c",
            "-v",
            "--help",
            "-m",
            "tests/test_.py",
            "tests/calc.py",
            "tests/TEST_calc.py",
            "tests/test_calc.PY",
            "TESTS/test_calc.py",
            "tests/sub/test_calc.py",
            "tests/../test_calc.py",
            "../tests/test_calc.py",
            "/tests/test_calc.py",
            r"tests\test_calc.py",
            "tests/test_calc.py ",
            "tests/test_calc.py;id",
            "tests/test~1.py",
            "tests/test_calc.py:ads",
            "tests.test_",
            "tests..test_calc",
            "tests.test_calc.",
            ".tests.test_calc",
            "os.system",
            "tests.calc",
            "tests.test_calc.1BadClass",
            "tests.test_calc.Class.method.extra",
            "tests.test_calc.-flag",
            &format!("tests.test_{}", "a".repeat(120)),
        ] {
            assert_eq!(
                validate_work_test_selector(bad).unwrap_err().code,
                ErrorCode::InvalidArgument,
                "expected InvalidArgument for {bad:?}"
            );
        }
        assert_eq!(
            validate_work_exec_args(&["fix-1".into(), "tests/test_a.py".into()]).unwrap(),
            ("fix-1".into(), Some("tests.test_a".into()))
        );
        assert_eq!(
            validate_work_exec_args(&["fix-1".into()]).unwrap(),
            ("fix-1".into(), None)
        );
        assert!(validate_work_exec_args(&[]).is_err());
        assert!(validate_work_exec_args(&["fix-1".into(), "tests/test_a.py".into(), "extra".into()]).is_err());
    }
}
