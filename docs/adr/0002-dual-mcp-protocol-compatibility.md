# ADR-0002: Dual-Path MCP Compatibility (Legacy + Modern 2026-07-28)

- **Status:** Accepted (V0.4.0)
- **Date:** 2026-11-19
- **Context:** Official MCP revision `2026-07-28` updates initialization, session, discovery, and Streamable HTTP cancellation semantics, while the deployed OpenAI `tunnel-client.exe` (`0.0.21`) and existing ChatGPT connector use legacy `initialize` / `notifications/initialized` and emit `server/discover`. Furthermore, ChatGPT's live audit recorded a transient initialization race (`HTTP 409` / `MCP server is not initialized`) under concurrent reads.
- **Decision:**
  1. Preserve all 33 original tool names and error semantics alongside 6 V0.4.0 task-oriented tools (`project_context`, `file_read_batch`, `git_diff_summary`, `task_submit`, `device_list`, `device_capabilities`).
  2. Support both legacy (`2024-11-05`..`2025-11-25`) and modern (`2026-07-28`) protocol negotiation.
  3. Answer `initialize` idempotently so mid-burst re-initialization never reverts an active session to `Initializing`, and return clean JSON-RPC `-32601` for `server/discover`.
  4. Keep `stdout` strictly protocol-only on stdio transports, disable `stale-on-error` caching for diagnostics/evidence (`cache_stale_on_error = false`), negotiate MCP Tasks only when both peers advertise it, and return durable `run_id` handles promptly well within the 120s tunnel deadline.
  5. Keep Codex `app-server` JSON-RPC lifecycle completely separate from MCP.
- **Consequences:** Existing ChatGPT connectors remain compatible while modern `2026-07-28` clients gain negotiated task handles and per-request metadata without concurrent initialization failures.
