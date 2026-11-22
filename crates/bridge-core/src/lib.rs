//! Core Rust control plane for Edge Project Bridge V0.4.0:
//! SQLite state & migrations, principal/grant policy engine, NTFS-verified file service,
//! recoverable hash-checked patch plans, Git worktree/diff engine, durable job runner,
//! and signed verifiable test evidence.

pub mod evidence;
pub mod files;
pub mod git;
pub mod jobs;
pub mod policy;
pub mod state;
