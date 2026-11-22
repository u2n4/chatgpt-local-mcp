# ADR-0001: Rust Core Control Plane & Incremental Migration

- **Status:** Accepted (V0.4.0)
- **Date:** 2026-11-19
- **Context:** Edge Project Bridge `v0.2.0` runs on Python 3.13 (`uv`) with SQLite `3.50.4` (predating the SQLite WAL-reset fix gate `3.51.3` / `3.50.7`), Windows MXC containment, and 33 MCP tools. V0.4.0 requires a fast, low-memory (<100 MiB idle), strongly typed control plane with native Win32 handle/Job Object supervision, Ed25519 manifest signing, and bundled modern SQLite while preserving 100% live compatibility during incremental transition.
- **Decision:**
  1. Introduce a 5-crate Rust 2024 workspace (`bridge-types`, `bridge-platform`, `bridge-core`, `bridge-adapters`, `bridge-cli`) pinned via `rust-toolchain.toml` (`1.100.0`) and `Cargo.lock`, targeting `x86_64-pc-windows-gnullvm` with SHA-256-verified portable LLVM-MinGW UCRT.
  2. Link SQLite via `rusqlite` `bundled` + `backup` features and verify `sqlite_runtime_version()` dynamically at runtime against the WAL-reset gate (`>= 3.51.3` or fixed backport).
  3. Preserve the existing v0.2.0 installation and production state during development. Run Rust builds with an explicitly selected isolated state directory and rehearse migrations using verified copies.
  4. Never allow two independent writers (Python + Rust brokers) to write concurrently to the same production `state.sqlite3`.
- **Consequences:** Native Rust execution, sub-millisecond scoped file reads, compile-time contract enforcement, and safe canary rehearsal before any owner-authorized production cutover.
