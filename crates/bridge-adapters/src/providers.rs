//! Versioned Provider Adapters for Codex (primary), Claude Code, and Google Antigravity (agy) (§9).
//! Enforces:
//! - `INCLUDED_ONLY` billing default (no silent API-key/paid fallback).
//! - Claude `--bare` is explicitly BLOCKED under `INCLUDED_ONLY` (skips subscription OAuth).
//! - Direct executable invocation (never inherits user shell `--dangerously-skip-permissions` aliases).
//! - AGY soft-denied tools recorded explicitly so exit 0 NEVER maps to PASS when an action was denied.
//! - Separate `agent_outcome`, `execution_outcome`, and `verification_outcome`.

use bridge_types::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Codex,
    ClaudeCode,
    AntigravityAgy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderProbeReport {
    pub provider: ProviderKind,
    pub adapter_schema_version: String,
    pub installed: bool,
    pub executable_path: Option<String>,
    pub detected_version: Option<String>,
    pub auth_mode: String,
    pub billing_policy: String,
    pub included_only_compatible: bool,
    pub supported_modes: Vec<String>,
    pub disabled_reasons: Vec<String>,
    pub capability: CapabilityStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderParsedStream {
    pub provider: ProviderKind,
    pub exit_code: Option<i32>,
    pub final_message: String,
    pub soft_denied_tools: Vec<String>,
    pub parsed_events_count: usize,
    pub malformed_lines: usize,
    pub outcome: OutcomeTriad,
}

/// Resolve actual binary paths directly (avoiding PowerShell function aliases like `--dangerously-skip-permissions`).
pub fn resolve_provider_binary(kind: ProviderKind) -> Option<PathBuf> {
    match kind {
        ProviderKind::Codex => {
            if let Some(appdata) = std::env::var_os("APPDATA") {
                let vendor = PathBuf::from(&appdata)
                    .join("npm/node_modules/@openai/codex/node_modules/@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe");
                if vendor.is_file() {
                    return Some(vendor);
                }
                let cmd = PathBuf::from(&appdata).join("npm/codex.cmd");
                if cmd.is_file() {
                    return Some(cmd);
                }
            }
            None
        }
        ProviderKind::ClaudeCode => {
            // Directly invoke real claude.exe binary — NEVER shell alias!
            if let Some(profile) = std::env::var_os("USERPROFILE") {
                let exe = PathBuf::from(profile).join(".local/bin/claude.exe");
                if exe.is_file() {
                    return Some(exe);
                }
            }
            None
        }
        ProviderKind::AntigravityAgy => {
            if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                let exe = PathBuf::from(local).join("agy/bin/agy.exe");
                if exe.is_file() {
                    return Some(exe);
                }
            }
            None
        }
    }
}

/// Probe all installed providers safely (read-only version & non-secret auth status only).
pub fn probe_provider(kind: ProviderKind) -> ProviderProbeReport {
    let now = Utc::now();
    let bin = resolve_provider_binary(kind);
    let Some(path) = bin else {
        return ProviderProbeReport {
            provider: kind,
            adapter_schema_version: PROVIDER_ADAPTER_SCHEMA_VERSION.into(),
            installed: false,
            executable_path: None,
            detected_version: None,
            auth_mode: "unknown".into(),
            billing_policy: "INCLUDED_ONLY".into(),
            included_only_compatible: false,
            supported_modes: Vec::new(),
            disabled_reasons: vec!["Executable not found on host.".into()],
            capability: CapabilityStatus {
                implemented: true,
                authorized: false,
                available: AvailableState::False,
                verified: false,
                last_verified_at: Some(now),
                reason: "Provider binary not installed.".into(),
            },
        };
    };

    let version_out = Command::new(&path)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .ok();
    let version_str = version_out
        .filter(|o| o.status.success())
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            let t = s.trim();
            if t.is_empty() {
                String::from_utf8_lossy(&o.stderr).trim().to_string()
            } else {
                t.to_string()
            }
        })
        .filter(|s| !s.is_empty());

    match kind {
        ProviderKind::Codex => {
            let login_out = Command::new(&path)
                .args(["login", "status"])
                .stdin(Stdio::null())
                .output()
                .ok();
            let login_text = login_out
                .map(|o| format!("{} {}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
                .unwrap_or_default();
            let chatgpt_auth = login_text.to_ascii_lowercase().contains("chatgpt");
            let mut disabled = Vec::new();
            if !chatgpt_auth {
                disabled.push("ChatGPT subscription login not confirmed; API key fallback disabled under INCLUDED_ONLY.".into());
            }
            ProviderProbeReport {
                provider: kind,
                adapter_schema_version: PROVIDER_ADAPTER_SCHEMA_VERSION.into(),
                installed: true,
                executable_path: Some(path.display().to_string()),
                detected_version: version_str,
                auth_mode: if chatgpt_auth { "chatgpt_subscription_native".into() } else { "unverified".into() },
                billing_policy: "INCLUDED_ONLY".into(),
                included_only_compatible: chatgpt_auth,
                supported_modes: vec!["app-server-stdio".into(), "exec-json".into()],
                disabled_reasons: disabled,
                capability: CapabilityStatus {
                    implemented: true,
                    authorized: chatgpt_auth,
                    available: AvailableState::True,
                    verified: chatgpt_auth,
                    last_verified_at: Some(now),
                    reason: if chatgpt_auth {
                        "Codex CLI detected with ChatGPT subscription login (INCLUDED_ONLY); app-server stdio & exec-json supported."
                            .into()
                    } else {
                        "Codex CLI detected but subscription login unverified.".into()
                    },
                },
            }
        }
        ProviderKind::ClaudeCode => {
            let auth_out = Command::new(&path)
                .args(["auth", "status"])
                .stdin(Stdio::null())
                .output()
                .ok();
            let mut auth_mode = "unknown".to_string();
            let mut included_ok = false;
            if let Some(o) = auth_out {
                if o.status.success() {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&o.stdout) {
                        let logged = v.get("loggedIn").and_then(|b| b.as_bool()).unwrap_or(false);
                        let method = v.get("authMethod").and_then(|s| s.as_str()).unwrap_or("unknown");
                        let sub = v.get("subscriptionType").and_then(|s| s.as_str()).unwrap_or("");
                        if logged && method == "claude.ai" {
                            auth_mode = format!("claude.ai_subscription({sub})");
                            included_ok = true;
                        }
                    }
                }
            }
            let disabled = vec![
                "--bare mode explicitly blocked under INCLUDED_ONLY (skips subscription OAuth per Anthropic docs [S08-S09]).".into(),
                "Native Windows shell sandboxing has documented platform limits [S10]; whole-worker containment required for autonomous edits.".into(),
            ];
            ProviderProbeReport {
                provider: kind,
                adapter_schema_version: PROVIDER_ADAPTER_SCHEMA_VERSION.into(),
                installed: true,
                executable_path: Some(path.display().to_string()),
                detected_version: version_str,
                auth_mode,
                billing_policy: "INCLUDED_ONLY".into(),
                included_only_compatible: included_ok,
                supported_modes: vec!["print-stream-json-direct-binary".into()],
                disabled_reasons: disabled,
                capability: CapabilityStatus {
                    implemented: true,
                    authorized: included_ok,
                    available: AvailableState::True,
                    verified: included_ok,
                    last_verified_at: Some(now),
                    reason: if included_ok {
                        "Direct claude.exe detected with claude.ai subscription login; --bare blocked; alias --dangerously-skip-permissions bypassed."
                            .into()
                    } else {
                        "claude.exe detected but claude.ai subscription login unverified.".into()
                    },
                },
            }
        }
        ProviderKind::AntigravityAgy => {
            ProviderProbeReport {
                provider: kind,
                adapter_schema_version: PROVIDER_ADAPTER_SCHEMA_VERSION.into(),
                installed: true,
                executable_path: Some(path.display().to_string()),
                detected_version: version_str,
                auth_mode: "native_agy_session_unknown_entitlement".into(),
                billing_policy: "INCLUDED_ONLY".into(),
                included_only_compatible: false, // Entitlement not locally verified via CLI without executing a live turn
                supported_modes: vec!["print-stream-json".into(), "print-json".into()],
                disabled_reasons: vec![
                    "Subscription/billing entitlement cannot be proven from `--version` alone; marked unknown under INCLUDED_ONLY until verified.".into(),
                    "Headless soft-denied tool calls can exit 0 [S11]; parser maps soft-denials to PARTIAL/BLOCKED, never PASS.".into(),
                ],
                capability: CapabilityStatus {
                    implemented: true,
                    authorized: false,
                    available: AvailableState::True,
                    verified: false,
                    last_verified_at: Some(now),
                    reason: "agy.exe detected; stream-json soft-denial parser implemented; billing/sandbox verification remains gated."
                        .into(),
                },
            }
        }
    }
}

pub fn probe_all_providers() -> Vec<ProviderProbeReport> {
    vec![
        probe_provider(ProviderKind::Codex),
        probe_provider(ProviderKind::ClaudeCode),
        probe_provider(ProviderKind::AntigravityAgy),
    ]
}

/// Validate Claude Code launch options under `INCLUDED_ONLY` and check repository hooks/MCP configs (§9).
pub fn validate_claude_launch_safety(
    repo_root: &Path,
    use_bare: bool,
    billing_policy: &str,
) -> Result<Vec<String>, BridgeError> {
    if use_bare && billing_policy == "INCLUDED_ONLY" {
        return Err(BridgeError::new(
            ErrorCode::BridgePolicyDenied,
            "Claude `--bare` skips subscription OAuth/keychain credentials and requires API-key billing; blocked under INCLUDED_ONLY.",
            OriginLayer::ProviderAdapter,
        ));
    }
    let mut warnings = Vec::new();
    for suspicious in [".claude/settings.json", ".claude/settings.local.json", ".mcp.json"] {
        let p = repo_root.join(suspicious);
        if p.is_file() {
            warnings.push(format!(
                "Untrusted repository provider config present at '{suspicious}'; must be constrained/reviewed before headless startup."
            ));
        }
    }
    Ok(warnings)
}

/// Parse provider NDJSON stream output (Codex exec JSON, Claude stream-json, or AGY stream-json).
/// Enforces §9 invariant: soft-denied tools NEVER map to PASS even if process exit_code == 0!
pub fn parse_provider_ndjson(
    provider: ProviderKind,
    ndjson: &str,
    exit_code: Option<i32>,
) -> ProviderParsedStream {
    let mut parsed_events = 0usize;
    let mut malformed = 0usize;
    let mut soft_denied = Vec::new();
    let mut final_msg = String::new();
    let mut saw_error_event = false;

    for line in ndjson.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(t) {
            Ok(v) => {
                parsed_events += 1;
                let typ = v.get("type").and_then(|s| s.as_str()).unwrap_or("");
                let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
                let decision = v.get("decision").and_then(|s| s.as_str()).unwrap_or("");
                if status.eq_ignore_ascii_case("denied")
                    || status.eq_ignore_ascii_case("approval_required")
                    || decision.eq_ignore_ascii_case("denied")
                    || typ.eq_ignore_ascii_case("tool_denied")
                    || v.get("permission_denials").and_then(|a| a.as_array()).map(|a| !a.is_empty()).unwrap_or(false)
                {
                    let tool_name = v
                        .get("tool")
                        .or_else(|| v.get("tool_name"))
                        .and_then(|s| s.as_str())
                        .unwrap_or("unspecified_tool");
                    soft_denied.push(tool_name.to_string());
                }
                if typ.contains("error") || v.get("is_error").and_then(|b| b.as_bool()).unwrap_or(false) {
                    saw_error_event = true;
                }
                if let Some(msg) = v.get("result").or_else(|| v.get("message")).and_then(|s| s.as_str()) {
                    final_msg = msg.to_string();
                }
            }
            Err(_) => {
                malformed += 1;
            }
        }
    }

    let exec_outcome = if exit_code == Some(0) {
        Verdict::Pass
    } else {
        Verdict::Fail
    };

    let agent_outcome = if !soft_denied.is_empty() {
        Verdict::Blocked
    } else if saw_error_event || exit_code != Some(0) {
        Verdict::Fail
    } else if parsed_events == 0 {
        Verdict::EnvironmentError
    } else {
        Verdict::Pass
    };

    // Verification outcome ALWAYS remains NotTested until the independent deterministic verifier runs!
    ProviderParsedStream {
        provider,
        exit_code,
        final_message: final_msg,
        soft_denied_tools: soft_denied.clone(),
        parsed_events_count: parsed_events,
        malformed_lines: malformed,
        outcome: OutcomeTriad {
            agent_outcome,
            execution_outcome: exec_outcome,
            verification_outcome: Verdict::NotTested,
            soft_denied_tools: soft_denied,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_bare_blocked_under_included_only() {
        let dir = tempfile::tempdir().unwrap();
        let err = validate_claude_launch_safety(dir.path(), true, "INCLUDED_ONLY").unwrap_err();
        assert_eq!(err.code, ErrorCode::BridgePolicyDenied);
        assert!(validate_claude_launch_safety(dir.path(), false, "INCLUDED_ONLY").is_ok());
    }

    #[test]
    fn agy_soft_denied_tool_with_exit_zero_never_maps_to_pass() {
        let stream = r#"{"type":"tool_call","tool":"file_write","status":"approval_required"}
{"type":"result","result":"Completed with skipped write"}"#;
        let parsed = parse_provider_ndjson(ProviderKind::AntigravityAgy, stream, Some(0));
        assert_eq!(parsed.outcome.execution_outcome, Verdict::Pass);
        assert_eq!(parsed.outcome.agent_outcome, Verdict::Blocked);
        assert_eq!(parsed.outcome.verification_outcome, Verdict::NotTested);
        assert_eq!(parsed.soft_denied_tools, vec!["file_write"]);
    }

    #[test]
    fn malformed_stream_is_handled_safely_without_pass() {
        let parsed = parse_provider_ndjson(ProviderKind::Codex, "not json\ntruncated{", Some(0));
        assert_eq!(parsed.malformed_lines, 2);
        assert_eq!(parsed.outcome.agent_outcome, Verdict::EnvironmentError);
        assert_eq!(parsed.outcome.verification_outcome, Verdict::NotTested);
    }
}
