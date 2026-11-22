# Edge Project Bridge 2.0 — Model-Agnostic Takeover Guide (`AGENTS.md`)

This repository contains the native Rust Edge Project Bridge and its legacy Python implementation. The legacy bridge uses Python 3.13, `uv`, SQLite WAL schema 3, Windows MXC, and Win32 Job Objects. The Rust broker uses its own isolated state during canary development.

## 1. Non-Negotiable Rules
1. **Model-Agnostic by Design (`GPT-6 Pro` Preferred Default):**
   - Maintain one shared Bridge instance, SQLite `state.sqlite3`, project registry, permissions, task history, checkpoints, and Context Packs across `GPT-6 Pro`, `Extra High`, `High`, `Medium`, and any future compatible model.
   - Treat unobserved capabilities as unknown (`null`) and detect capabilities dynamically (`edge_bridge/capabilities.py`).
2. **Enforce Strict Principal Isolation (`edge` vs `local`):**
   - `edge` (ChatGPT Web connector over tunnel): **strictly read-only**. `Broker.dispatch` independently rejects every `MUTATION_TOOLS` call as well as `job_output` and `job_changes` with `BRIDGE_POLICY_DENIED`.
   - `local` (Local Codex CLI / Owner CLI): owns file mutations, `apply-patch-plan`, `git_checkpoint` / `git_integrate`, MXC `process_start`, release/rollback/recovery, orchestrator controls, and `stop-all`.
   - Never hide writes or execution inside read tools, and never claim direct MCP write access when using the hybrid `Read -> Patch Plan -> Local Apply` workflow.
3. **Never Disable Windows Isolation & Preserve `INCLUDED_ONLY` Billing:**
   - Keep `automatic_weaker_fallback = False`, `model_api = False`, `paid_fallback = False`, and `billing_policy = "INCLUDED_ONLY"`.
   - Live LLM worker inference (`mode="mxc"`) remains fail-closed (`WORKER_CAPABILITY_NOT_VERIFIED`) until MXC whole-worker isolation and non-credit auto-reload disablement are verified; use `mode="mock"` for local orchestrator verification.
4. **Recoverable Self-Development:**
   - Before upgrading Bridge code, create a versioned snapshot (`cli release-create` or `cli upgrade`); if an MCP update breaks connectivity, restore via `scripts/recover-bridge.ps1` or `cli recover` / `cli rollback`.

## 2. Module Map (`edge_bridge/`)
- Control Plane & IPC: `broker.py`, `mcp_server.py`, `state.py`, `cli.py`, `capabilities.py`, `releases.py`, `diagnostics.py`, `context_packs.py`
- Files, Sandbox & Git: `files.py`, `jobs.py`, `runner.py`, `git_engine.py`
- P1 Multi-Agent Orchestrator: `orchestrator.py`, `workers.py`, `worker_account.py`
- P2 Desktop & Edge Automation: `desktop.py`, `browser.py`
- P3 Local Loopback Dashboard: `dashboard.py`
