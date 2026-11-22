# System Architecture — Edge Project Bridge 2.0 (`v0.2.0`, `SCHEMA_VERSION = 3`)

## Layered Architecture (P0–P3 Complete)

```text
+-----------------------------------------------------------------------+
| 1. Connectivity Layer (edge_bridge/mcp_server.py, diagnostics.py)     |
|  - 33 strict Pydantic tools, stateless=True, EOF pending-ID drain     |
|  - server/discover pre-init filter (-32601, zero stderr noise)        |
|  - Layered doctor + isolated E2E probe + redacted Support Bundles     |
|  - Official OpenAI tunnel-client (loopback dev proxy / user-approved) |
+-----------------------------------------------------------------------+
                                   |
                         HMAC-SHA256 + ECDSA P-256 TLS
                         https://127.0.0.1:<port>/v1/call
                                   v
+-----------------------------------------------------------------------+
| 2. Control Plane & Continuity (broker.py, state.py, capabilities.py,  |
|    releases.py, context_packs.py, scripts/recover-bridge.ps1)         |
|  - Exclusive broker lock, separate owner.token vs edge.token          |
|  - Model-agnostic dynamic capability detection & FallbackPlan         |
|  - SQLite WAL v3 DB: projects, grants, scopes, exec_policies, tasks,  |
|    task_dependencies, task_queue, checkpoints, context_packs, ops,    |
|    jobs, events, artifacts, verification, connection_incidents,       |
|    model_capabilities, worker_profiles (8), workers, worker_events,   |
|    resource_samples                                                   |
|  - Versioned releases, auto-rollback & pure-PowerShell recovery       |
+-----------------------------------------------------------------------+
                                   |
        +--------------------------+--------------------------+
        v                          v                          v
+-------------------+    +-------------------+    +-------------------+
| 3a. NTFS Files    |    | 3b. Sandbox Jobs  |    | 3c. Git Engine    |
| files.py          |    | jobs.py / runner  |    | git_engine.py     |
| Handle-relative   |    | Codex CLI 0.169.0 |    | Pinned git.exe    |
| 32 MiB chunked    |    | MXC + Job Object  |    | Temp GIT_INDEX    |
| NUL-safe + lossy  |    | Python/Node/PS1/  |    | Worktrees &       |
| Binary fallback   |    | Blender/Calc      |    | --ff-only merge   |
+-------------------+    +-------------------+    +-------------------+
                                   |
        +--------------------------+--------------------------+
        v                          v                          v
+-------------------+    +-------------------+    +-------------------+
| 4. P1 Multi-Agent |    | 5. P2 Desktop &   |    | 6. P3 Loopback    |
| Orchestrator      |    | Edge Automation   |    | Dashboard         |
| orchestrator.py   |    | desktop.py        |    | dashboard.py      |
| workers.py        |    | browser.py        |    | 127.0.0.1 only    |
| DAG + Queue       |    | DesktopSessionLock|    | Token-authed      |
| Adaptive 1->2->N  |    | UIA -> API -> PNG |    | 12 live sections  |
| CPU/RAM/Disk/GPU  |    | Edge isolated ctx |    | Emergency StopAll |
| Serial Integrate  |    | No personal prof  |    | Zero raw shell    |
+-------------------+    +-------------------+    +-------------------+
```

## Key Architectural Guarantees
1. **Model-Agnostic Continuity (`capabilities.py`, `context_packs.py`):** One shared Bridge instance and SQLite `state.sqlite3` serves `GPT-6 Pro` (preferred default), `Extra High`, `High`, `Medium`, and any future compatible model. Unobserved capabilities default to `null`, `edge` enforces read-only policy regardless of host claims, and `ContextPackManager` skips already-completed steps across model switches or new conversations.
2. **Recoverable Self-Development (`releases.py`, `scripts/recover-bridge.ps1`):** Versioned release snapshots reside in sibling `<state_dir>-releases` with Owner+`SYSTEM` ACLs, integrity-checked `state-backup.sqlite3`, and pure PowerShell 5.1 recovery that restores the last known working Broker, MCP server, and SQLite state even if `mcp_server.py` or `cli.py` is broken.
3. **Multi-Agent Isolation & Conflict Protection (`orchestrator.py`):** Every worker runs inside an isolated Git worktree or regular-file snapshot copy with `worker_capabilities <= parent_capabilities`, adaptive concurrency (`1 -> 2 -> N`), heavy-build cap (`1`), rate-limit backoff, strict `INCLUDED_ONLY` billing guardrail, and serial integration that verifies baseline hashes so newer user edits are never overwritten.
