use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::ids::*;

/// Distinct version contracts — never conflated into a single ambiguous `schema_version`.
pub const BRIDGE_VERSION: &str = "0.4.0";
pub const BRIDGE_CONTRACT_VERSION: &str = "0.4.0";
pub const LEGACY_API_CONTRACT_VERSION: u32 = 1;
pub const SQLITE_SCHEMA_VERSION: u32 = 4;
pub const PROVIDER_ADAPTER_SCHEMA_VERSION: &str = "1.0.0";
pub const REPORT_FORMAT_VERSION: &str = "1.0.0";
pub const MCP_MODERN_PROTOCOL_VERSION: &str = "2026-07-28";
pub const MCP_LEGACY_PROTOCOL_VERSIONS: &[&str] = &[
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VersionContract {
    pub bridge_version: String,
    pub bridge_contract_version: String,
    pub legacy_api_contract_version: u32,
    pub sqlite_schema_version: u32,
    pub sqlite_runtime_version: String,
    pub sqlite_wal_reset_fix_verified: bool,
    pub mcp_protocol_versions_supported: Vec<String>,
    pub provider_adapter_schema_version: String,
    pub report_format_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AvailableState {
    True,
    False,
    Unknown,
}

/// Truthful capability state separating implementation, authorization, availability, and verification.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CapabilityStatus {
    pub implemented: bool,
    pub authorized: bool,
    pub available: AvailableState,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<DateTime<Utc>>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Pass,
    Fail,
    Partial,
    Blocked,
    NotTested,
    Stale,
    Cancelled,
    EnvironmentError,
}

/// Explicit separation of agent completion, command execution, and independent test verification.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OutcomeTriad {
    pub agent_outcome: Verdict,
    pub execution_outcome: Verdict,
    pub verification_outcome: Verdict,
    #[serde(default)]
    pub soft_denied_tools: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    SoftwareUnit,
    SoftwareIntegration,
    RecordedLog,
    Sitl,
    Hitl,
    Sih,
    HardwareBench,
    FlightObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationCategory {
    Read,
    Write,
    Patch,
    Checkpoint,
    ExecuteRecipe,
    GitRead,
    GitWorktree,
    GitIntegrate,
    ArtifactExport,
    BrowserTest,
    DesktopInspect,
    TelemetryReadOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationMode {
    AwaitOwnerReview,
    PreAuthorizedAfterVerifiedPass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OfflineGrantPolicy {
    DenyNewAllowRunningDeterministic,
    DenyAllWhenUnreachable,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResourceLimits {
    pub max_duration_seconds: u64,
    pub max_cpu_percent: u8,
    pub max_memory_mb: u64,
    pub max_processes: u32,
    pub max_output_bytes: u64,
    pub max_storage_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_duration_seconds: 120,
            max_cpu_percent: 50,
            max_memory_mb: 768,
            max_processes: 8,
            max_output_bytes: 262_144,
            max_storage_bytes: 33_554_432,
        }
    }
}

/// Concrete owner-approved scoped task grant envelope (§6).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TaskGrantEnvelope {
    pub grant_id: GrantId,
    pub requester_principal: String,
    pub granting_owner: String,
    pub host_id: HostId,
    pub project_id: ProjectId,
    pub workspace_id: WorkspaceId,
    pub baseline_hash: String,
    pub policy_revision: PolicyRevision,
    pub permitted_categories: Vec<OperationCategory>,
    pub writable_paths: Vec<String>,
    pub allowed_recipes: Vec<String>,
    pub network_destinations: Vec<String>,
    pub export_scope: String,
    pub integration_mode: IntegrationMode,
    pub limits: ResourceLimits,
    pub offline_policy: OfflineGrantPolicy,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Admitted,
    Running,
    InputRequired,
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Interrupted,
    Unknown,
}

impl JobState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            JobState::Succeeded
                | JobState::Failed
                | JobState::Cancelled
                | JobState::TimedOut
                | JobState::Interrupted
        )
    }

    pub fn can_transition_to(self, next: JobState) -> bool {
        use JobState::*;
        match self {
            Queued => matches!(next, Admitted | Cancelling | Cancelled | Failed | Unknown),
            Admitted => matches!(next, Running | Cancelling | Cancelled | Failed | Interrupted | Unknown),
            Running => matches!(
                next,
                InputRequired | Cancelling | Succeeded | Failed | Cancelled | TimedOut | Interrupted | Unknown
            ),
            InputRequired => matches!(next, Running | Cancelling | Cancelled | TimedOut | Failed | Unknown),
            Cancelling => matches!(next, Cancelled | Succeeded | Failed | TimedOut | Interrupted | Unknown),
            Unknown => matches!(next, Succeeded | Failed | Cancelled | Interrupted),
            Succeeded | Failed | Cancelled | TimedOut | Interrupted => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DurableJobRecord {
    pub run_id: RunId,
    pub task_id: TaskId,
    pub host_id: HostId,
    pub project_id: ProjectId,
    pub workspace_id: WorkspaceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<GrantId>,
    pub requester_principal: String,
    pub executor_identity: String,
    pub operation_id: OperationId,
    pub dedup_key: String,
    pub payload_digest: String,
    pub state: JobState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_start_time_100ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<OutcomeTriad>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_manifest_id: Option<ManifestId>,
    pub output_seq: u64,
    pub output_truncated: bool,
    pub output_dir: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// V0.4 hash-checked patch plan — backward-compatible with v0.2.0 `apply-patch-plan`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PatchEditV04 {
    pub path: String,
    pub content: String,
    /// `None` asserts file absence (create-only); `Some(sha256)` asserts exact preimage bytes.
    pub expected_hash: Option<String>,
    /// Expected postimage SHA-256 verified immediately after write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_postimage_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PatchPlanV04 {
    #[serde(default = "default_patch_schema_version")]
    pub patch_plan_version: String,
    pub project_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_identity: Option<String>,
    pub operation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_manifest_sha256: Option<String>,
    #[serde(default)]
    pub scope: Vec<String>,
    pub edits: Vec<PatchEditV04>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_recipe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_command: Option<Vec<String>>,
}

fn default_patch_schema_version() -> String {
    "0.4.0".to_string()
}

/// All 11 required evidence manifest groups per Master Prompt §12.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceIdentityGroup {
    pub manifest_id: ManifestId,
    pub report_format_version: String,
    pub run_id: RunId,
    pub task_id: TaskId,
    pub host_id: HostId,
    pub project_id: ProjectId,
    pub workspace_id: WorkspaceId,
    pub broker_version: String,
    pub runner_version: String,
    pub adapter_version: String,
    pub evidence_class: EvidenceClass,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceAuthorizationGroup {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<GrantId>,
    pub requester_principal: String,
    pub executor_identity: String,
    pub policy_revision: PolicyRevision,
    pub effective_scope: Vec<String>,
    pub containment_probe_result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceSourceGroup {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_commit: Option<String>,
    pub dirty_input_manifest_sha256: String,
    pub source_hash_before: String,
    pub source_hash_after: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_digest: Option<String>,
    pub test_suite_manifest_sha256: String,
    pub test_suite_modified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceInputsGroup {
    pub config_hashes: BTreeMap<String, String>,
    pub declared_units: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub random_seed: Option<u64>,
    pub synthetic_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceEnvironmentGroup {
    pub os_build: String,
    pub architecture: String,
    pub host_name: String,
    pub toolchain_versions: BTreeMap<String, String>,
    pub resolved_executable: String,
    pub resolved_executable_sha256: String,
    pub isolation_backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceCommandGroup {
    pub executable: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub redacted_env_keys: Vec<String>,
    pub supervisor_pid: Option<u32>,
    pub process_start_recorded_outside_job: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceTimeGroup {
    pub started_at_utc: DateTime<Utc>,
    pub finished_at_utc: DateTime<Utc>,
    pub monotonic_duration_ms: u64,
    pub clock_uncertainty_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceExecutionGroup {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub policy_denied: bool,
    pub partial_output: bool,
    pub cleanup_confirmed: bool,
    pub outcome_triad: OutcomeTriad,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TestCaseOutcome {
    pub name: String,
    pub status: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceTestsGroup {
    pub parser_name: String,
    pub parser_version: String,
    pub discovered: u32,
    pub executed: u32,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub results_artifact_sha256: String,
    pub fresh_for_run: bool,
    pub cases: Vec<TestCaseOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SealedArtifactRef {
    pub artifact_id: ArtifactId,
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub media_type: String,
    pub capture_origin: String,
    pub export_policy: String,
    pub secret_scan_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceClaim {
    pub claim: String,
    pub verdict: Verdict,
    pub linked_artifact_ids: Vec<ArtifactId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceConclusionsGroup {
    pub overall_verdict: Verdict,
    pub claims: Vec<EvidenceClaim>,
    pub untested_areas: Vec<String>,
    pub reproduction_command: String,
    pub provenance_disclaimer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceManifest {
    pub identity: EvidenceIdentityGroup,
    pub authorization: EvidenceAuthorizationGroup,
    pub source: EvidenceSourceGroup,
    pub inputs: EvidenceInputsGroup,
    pub environment: EvidenceEnvironmentGroup,
    pub command: EvidenceCommandGroup,
    pub time: EvidenceTimeGroup,
    pub execution: EvidenceExecutionGroup,
    pub tests: EvidenceTestsGroup,
    pub artifacts: Vec<SealedArtifactRef>,
    pub conclusions: EvidenceConclusionsGroup,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_ed25519_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_public_key_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DeviceRecord {
    pub host_id: HostId,
    pub display_name: String,
    pub public_key_hex: String,
    pub endpoint_url: String,
    pub approved_scopes: Vec<String>,
    pub capabilities: BTreeMap<String, CapabilityStatus>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub paired_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TelemetryStreamHeader {
    pub device_identity: String,
    pub firmware_version: String,
    pub stream_source: String,
    pub evidence_class: EvidenceClass,
    pub units: BTreeMap<String, String>,
    pub source_timestamp_utc: DateTime<Utc>,
    pub receive_timestamp_utc: DateTime<Utc>,
    pub freshness_threshold_ms: u64,
    pub sequence_gaps: u64,
    pub dropouts_detected: u64,
    pub truncated_records: u64,
    pub parser_version: String,
    pub raw_log_sha256: String,
    pub allowed_outgoing_messages: Vec<String>,
    pub denied_outgoing_messages: Vec<String>,
}
