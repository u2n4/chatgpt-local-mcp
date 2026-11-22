use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    BridgePolicyDenied,
    ProjectNotGranted,
    AuthRequired,
    ProtocolMismatch,
    TransientDisconnect,
    DeadlineExceeded,
    BackendUnavailable,
    StalePrecondition,
    VersionConflict,
    InvalidArgument,
    MethodNotFound,
    PathOutsideRoot,
    UnsupportedPathType,
    FileNotFound,
    NotFound,
    IsolationNotVerified,
    WorkerCapabilityNotVerified,
    ResourceBudgetExceeded,
    ResourceBusy,
    IdempotencyPayloadMismatch,
    UnknownAfterRestart,
    ConfirmationRequired,
    HardwareActionDenied,
    DeviceNotPaired,
    StateAclUnsafe,
    SchemaUnsupported,
    InternalError,
}

impl ErrorCode {
    pub fn retryable(self) -> bool {
        matches!(
            self,
            ErrorCode::TransientDisconnect
                | ErrorCode::DeadlineExceeded
                | ErrorCode::BackendUnavailable
                | ErrorCode::ResourceBusy
        )
    }

    pub fn default_next_action(self) -> &'static str {
        match self {
            ErrorCode::BridgePolicyDenied | ErrorCode::ProjectNotGranted => {
                "Request an explicit owner grant via local CLI or BridgePulse Approvals view."
            }
            ErrorCode::AuthRequired => {
                "Authenticate with a valid local, edge, executor, or paired-device credential."
            }
            ErrorCode::ProtocolMismatch => {
                "Check negotiated MCP protocol revision and retry with a supported version."
            }
            ErrorCode::TransientDisconnect => {
                "Reconnect and query the existing run_id/operation_id before retrying any mutation."
            }
            ErrorCode::DeadlineExceeded => {
                "Query durable run_id status; do not blindly replay side effects."
            }
            ErrorCode::BackendUnavailable => {
                "Run `edge-bridge doctor` to verify broker, containment, or provider readiness."
            }
            ErrorCode::ResourceBusy => "Retry after the advertised delay and reduce concurrency.",
            ErrorCode::StalePrecondition | ErrorCode::VersionConflict => {
                "Re-read the latest file hash or git HEAD and rebuild the patch plan."
            }
            ErrorCode::IdempotencyPayloadMismatch => {
                "Use a new unique operation_id for a different payload, or inspect the existing operation."
            }
            ErrorCode::UnknownAfterRestart => {
                "Inspect the recovery journal and process state before retrying."
            }
            ErrorCode::IsolationNotVerified => {
                "Verify pinned MXC binary and WinSta0\\Default interactive desktop before executing."
            }
            ErrorCode::WorkerCapabilityNotVerified => {
                "Verify whole-worker isolation and INCLUDED_ONLY entitlement before enabling workers."
            }
            ErrorCode::HardwareActionDenied => {
                "Physical actuation requires an explicit supervised hardware setup outside unattended coding grants."
            }
            ErrorCode::DeviceNotPaired => {
                "Complete one-time owner pairing on the target device with explicit scope approval."
            }
            ErrorCode::StateAclUnsafe => {
                "Repair state directory ownership/DACL from a standard non-elevated owner PowerShell session."
            }
            _ => "Inspect diagnostics and structured error details before retrying.",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginLayer {
    Transport,
    McpAdapter,
    Auth,
    Policy,
    Validation,
    FileService,
    GitEngine,
    JobRunner,
    Containment,
    Evidence,
    ProviderAdapter,
    DeviceChannel,
    StateStore,
    HardwareAdapter,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StructuredError {
    pub ok: bool,
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    pub origin_layer: OriginLayer,
    pub correlation_id: String,
    pub next_action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Error)]
#[error("{code:?}: {message}")]
pub struct BridgeError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    pub origin_layer: OriginLayer,
    pub correlation_id: String,
    pub next_action: String,
    pub details: Option<serde_json::Value>,
}

impl BridgeError {
    pub fn new(
        code: ErrorCode,
        message: impl Into<String>,
        origin_layer: OriginLayer,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: code.retryable(),
            origin_layer,
            correlation_id: format!("corr_{}", Uuid::new_v4().simple()),
            next_action: code.default_next_action().to_string(),
            details: None,
        }
    }

    pub fn with_next_action(mut self, action: impl Into<String>) -> Self {
        self.next_action = action.into();
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn to_structured(&self) -> StructuredError {
        StructuredError {
            ok: false,
            code: self.code,
            message: self.message.chars().take(500).collect(),
            retryable: self.retryable,
            origin_layer: self.origin_layer,
            correlation_id: self.correlation_id.clone(),
            next_action: self.next_action.clone(),
            details: self.details.clone(),
        }
    }
}
