//! Versioned typed contracts, separate identities, error taxonomy, and JSON schema export
//! for Edge Project Bridge V0.4.0.

pub mod contracts;
pub mod errors;
pub mod ids;

pub use contracts::*;
pub use errors::*;
pub use ids::*;

use schemars::schema_for;
use serde_json::Value;

/// Export all versioned V0.4.0 contract JSON Schemas for `schemas/` artifacts and contract tests.
pub fn export_contract_schemas() -> Vec<(&'static str, Value)> {
    vec![
        (
            "v0.4.0-task-grant.schema.json",
            serde_json::to_value(schema_for!(TaskGrantEnvelope)).expect("schema serialize"),
        ),
        (
            "v0.4.0-durable-job.schema.json",
            serde_json::to_value(schema_for!(DurableJobRecord)).expect("schema serialize"),
        ),
        (
            "v0.4.0-patch-plan.schema.json",
            serde_json::to_value(schema_for!(PatchPlanV04)).expect("schema serialize"),
        ),
        (
            "v0.4.0-evidence-manifest.schema.json",
            serde_json::to_value(schema_for!(EvidenceManifest)).expect("schema serialize"),
        ),
        (
            "v0.4.0-structured-error.schema.json",
            serde_json::to_value(schema_for!(StructuredError)).expect("schema serialize"),
        ),
        (
            "v0.4.0-device-identity.schema.json",
            serde_json::to_value(schema_for!(DeviceRecord)).expect("schema serialize"),
        ),
        (
            "v0.4.0-telemetry-header.schema.json",
            serde_json::to_value(schema_for!(TelemetryStreamHeader)).expect("schema serialize"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_reject_traversal_and_whitespace() {
        assert!(validate_safe_id("project_abc123").is_ok());
        assert!(validate_safe_id("../escape").is_err());
        assert!(validate_safe_id("").is_err());
        assert!(validate_safe_id("bad id").is_err());
        assert!(validate_safe_id("a\\b").is_err());
    }

    #[test]
    fn contracts_export_valid_json_schemas() {
        let schemas = export_contract_schemas();
        assert_eq!(schemas.len(), 7);
        for (name, val) in schemas {
            assert!(val.is_object(), "schema {name} must be a JSON object");
        }
    }

    #[test]
    fn job_state_transitions_enforce_terminal_invariants() {
        assert!(JobState::Queued.can_transition_to(JobState::Admitted));
        assert!(JobState::Admitted.can_transition_to(JobState::Running));
        assert!(JobState::Running.can_transition_to(JobState::Cancelling));
        assert!(JobState::Cancelling.can_transition_to(JobState::Cancelled));
        assert!(!JobState::Succeeded.can_transition_to(JobState::Running));
        assert!(!JobState::Failed.can_transition_to(JobState::Succeeded));
        assert!(!JobState::Cancelled.can_transition_to(JobState::Running));
        assert!(JobState::Unknown.can_transition_to(JobState::Succeeded));
        assert!(JobState::Unknown.can_transition_to(JobState::Failed));
    }
}
