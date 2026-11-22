# Tool Capabilities Matrix (`v0.2.0` / M1)

Every MCP tool and local owner action explicitly separates:
- **`tool_exists`**: Defined and schema-validated in `mcp_server.py` / `broker.py` (`ConfigDict(extra="forbid", strict=True)`).
- **`authorized_for_local`**: Callable via owner IPC / `--principal local` when project grant + runtime scopes permit.
- **`callable_by_chatgpt_edge`**: Callable through `--principal edge` (ChatGPT Web connector) on granted projects (`grant-edge`).
- **`status_notes`**: Exact verified behavior or block reason.

## MCP Catalog (33 Tools — Schemas Preserved)

| Tool | Read-Only (`Edge`) | Local Authorized | ChatGPT Connector Callable | Notes |
|---|---|---|---|---|
| `bridge_info` | Yes | Yes | Yes | Returns 4-state capability flags, dynamic `model_capabilities`, and `local_codex_fallback` |
| `bridge_health` | Yes | Yes | Yes | SQLite health, host RAM/CPU, desktop warning (`desktop_name` masked for Edge) |
| `connection_diagnostics` | Yes | Yes | Yes | Redacted layer summary, upstream classifier, dynamic `model_capabilities`, and `fallback_readiness` |
| `project_list` | Yes | Yes | Yes | Strips local filesystem `root`/`root_identity` for Edge |
| `project_status` | Yes | Yes | Yes | Includes `exec_policy` & runtime scopes for `local` |
| `project_resume` | Yes | Yes | Yes | Latest checkpoint + `open_tasks` + `model_capabilities` + deterministic `fallback_plan` + `handoff_ready` |
| `task_get` | Yes | Yes | Yes | Task metadata, DAG `depends_on`, latest checkpoint, job history |
| `policy_view` | Yes | Yes | Yes | Sanitized grant/policy summary (`root` masked for Edge) |
| `file_list` | Yes | Yes | Yes | Supports bounded pagination + `recursive`, `max_depth`, `exclude_generated` |
| `file_read` | Yes | Yes | Yes | Streaming SHA-256 + UTF-8 chunks up to 32 MiB; NUL-safe error hints; `lossy_utf8` preview |
| `file_search` | Yes | Yes | Yes | Bounded literal search; skips `.venv`/`node_modules`/etc. by default; `files_scanned`/`bytes_scanned` |
| `file_view` | Yes | Yes | Yes | Image base64 (`.png`/`.jpg` <= 256 KiB), text slice, or binary metadata fallback (`kind="binary"`) |
| `artifact_list` | Yes | Yes | Yes | Registered text artifact references |
| `artifact_read` | Yes | Yes | Yes | Hash-verified artifact content |
| `git_status` | Yes | Yes | Yes | Porcelain-z branch/HEAD/dirty status within repo root |
| `git_diff` | Yes | Yes | Yes | Validated refs/paths (`--no-ext-diff --no-textconv`), paginated output + SHA-256 |
| `worker_list` | Yes | Yes | Yes | Returns `enabled=False`, 6 seeded profiles, and RAM/CPU admission metrics |
| `job_get` | Yes | Yes | Yes | `intent` and `evidence` hidden from Edge |
| `job_output` | **Denied to Edge** | Yes | No | Rejected with `BRIDGE_POLICY_DENIED` (`LOCAL_JOB_LOG_ONLY`) |
| `job_changes` | **Denied to Edge** | Yes | No | Rejected with `BRIDGE_POLICY_DENIED` (`LOCAL_JOB_REVIEW_ONLY`) |
| `file_write` | No | Yes | No | Rejected for Edge (`PRINCIPAL_READ_ONLY`); expected hash + `operation_id` |
| `file_patch` | No | Yes | No | Rejected for Edge; reversible quarantine receipt |
| `file_move` | No | Yes | No | Rejected for Edge; handle-relative move + hash check |
| `file_delete` | No | Yes | No | Rejected for Edge; reversible quarantine delete |
| `task_checkpoint` | No | Yes | No | Rejected for Edge; durable checkpoint packet in SQLite |
| `process_start` | No | Yes | No | Rejected for Edge; MXC recipes: `calculator`, `blender_knot`, `project_tests`, `node_tests`, `powershell_script` |
| `process_input` | No | Unsupported | No | Bundled recipes use closed stdin (`EXECUTION_REQUEST_UNSUPPORTED`) |
| `job_cancel` | No | Yes | No | Rejected for Edge; Win32 Job Object termination |
| `git_checkpoint` | No | Yes | No | Rejected for Edge; non-destructive ref `refs/edge-bridge/checkpoints/...` |
| `git_integrate` | No | Yes | No | Rejected for Edge; `dry_run` preview or clean `--ff-only` merge |
| `worker_start` | No | Blocked | No | Fail-closed: `WORKER_CAPABILITY_NOT_VERIFIED` |
| `worker_steer` | No | Blocked | No | Fail-closed: `WORKER_CAPABILITY_NOT_VERIFIED` |
| `worker_cancel` | No | Yes (records) | No | Rejected for Edge; local cancels queued/running record if present |

## CLI Owner-Only Commands (`cli.py`)
- State & daemon lifecycle: `install`, `start`, `stop`, `uninstall`, `stop-all`, `backup <target.sqlite3>`
- Diagnostics & incidents: `doctor [--account --probe-mcp --e2e-isolated --e2e-project-id --e2e-file --e2e-task-id --profile --tunnel-health-url --support-bundle --symptom]`, `record-incident`, `catalog`, `worker-status [--project-id --record-sample]`
- Dynamic model capabilities & fallback: `model-capabilities [--model --surface --record --caps-json --source --notes --no-merge --principal]`, `fallback-plan <project_id> [--task-id --model --surface --operation-id --require --principal]`
- Project & grant administration: `register`, `grant-edge`, `revoke-edge`, `grant-python-tests`, `revoke-python-tests`, `grant-node-tests`, `revoke-node-tests`, `grant-powershell` / `grant-powershell-tests`, `revoke-powershell`, `set-exec-policy`
- Local patch review/apply & artifacts: `apply-patch-plan <project_id> [--operation-id --task-id --json <file_or_inline> --paste --confirm --verify --no-verify --verify-recipe --verify-cmd --allow-host-verify --artifact-dir]`, `apply-job-changes`, `patch-recovery`, `record-artifact`, `call <tool> --json ...`
- Versioned releases & rollback/recovery: `release-create`, `release-list`, `upgrade <source_dir>`, `rollback`, `recover` (plus independent `scripts/recover-bridge.ps1`)
