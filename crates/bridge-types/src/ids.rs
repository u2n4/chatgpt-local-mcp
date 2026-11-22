use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::{BridgeError, ErrorCode, OriginLayer};

/// Validate an opaque bridge identifier (1..=128 safe ASCII characters, never path separators).
pub fn validate_safe_id(value: &str) -> Result<(), BridgeError> {
    if value.is_empty() || value.len() > 128 {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "Identifier length must be between 1 and 128 characters.",
            OriginLayer::Validation,
        ));
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "Identifier must start with an ASCII alphanumeric character.",
            OriginLayer::Validation,
        ));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'.' | b':' | b'-'))
    {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "Identifier contains disallowed characters.",
            OriginLayer::Validation,
        ));
    }
    if value.contains("..") {
        return Err(BridgeError::new(
            ErrorCode::InvalidArgument,
            "Identifier cannot contain '..' segments.",
            OriginLayer::Validation,
        ));
    }
    Ok(())
}

macro_rules! opaque_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new_random() -> Self {
                Self(format!("{}_{}", $prefix, Uuid::new_v4().simple()))
            }

            pub fn parse(raw: impl Into<String>) -> Result<Self, BridgeError> {
                let s = raw.into();
                validate_safe_id(&s)?;
                Ok(Self(s))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

opaque_id!(InstanceId, "inst");
opaque_id!(HostId, "host");
opaque_id!(ProjectId, "project");
opaque_id!(WorkspaceId, "ws");
opaque_id!(TaskId, "task");
opaque_id!(RunId, "run");
opaque_id!(ArtifactId, "art");
opaque_id!(GrantId, "grant");
opaque_id!(OperationId, "op");
opaque_id!(ManifestId, "evid");

/// Monotonic policy revision counter bound to every project grant and cached response.
pub type PolicyRevision = u64;

/// Authenticated requester principal derived strictly from transport/IPC authentication,
/// NEVER from caller-supplied JSON fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Principal {
    /// Local owner control plane (full local authority, separate trust boundary).
    Local,
    /// Existing ChatGPT Edge connector principal — strictly read-only by default.
    Edge,
    /// Distinct owner-approved scoped execution profile bound to a `TaskGrantEnvelope`.
    DelegatedExecutor(String),
    /// Authenticated peer device host-agent identity.
    PairedHost(String),
}

impl Principal {
    pub fn as_db_key(&self) -> String {
        match self {
            Principal::Local => "local".to_string(),
            Principal::Edge => "edge".to_string(),
            Principal::DelegatedExecutor(id) => format!("executor:{id}"),
            Principal::PairedHost(host) => format!("host:{host}"),
        }
    }

    pub fn from_db_key(raw: &str) -> Result<Self, BridgeError> {
        if raw == "local" {
            Ok(Principal::Local)
        } else if raw == "edge" {
            Ok(Principal::Edge)
        } else if let Some(rest) = raw.strip_prefix("executor:") {
            validate_safe_id(rest)?;
            Ok(Principal::DelegatedExecutor(rest.to_string()))
        } else if let Some(rest) = raw.strip_prefix("host:") {
            validate_safe_id(rest)?;
            Ok(Principal::PairedHost(rest.to_string()))
        } else {
            Err(BridgeError::new(
                ErrorCode::AuthRequired,
                "Unrecognized authenticated principal.",
                OriginLayer::Auth,
            ))
        }
    }

    pub fn is_local(&self) -> bool {
        matches!(self, Principal::Local)
    }

    pub fn is_edge(&self) -> bool {
        matches!(self, Principal::Edge)
    }
}
