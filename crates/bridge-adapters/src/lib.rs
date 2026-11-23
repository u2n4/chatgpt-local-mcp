//! Protocol, provider, multi-device, and conditional hardware/telemetry adapters
//! backed by `bridge-core` without duplicating business authority.

pub mod devices;
pub mod hardware;
pub mod mcp;
mod mcp_jobs;
mod mcp_work;
mod mcp_work_diff;
pub mod muse;
pub mod providers;
