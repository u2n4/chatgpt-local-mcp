# Tool Capabilities Matrix (46 MCP Tools)

The Rust MCP server (`edge-bridge mcp` / `edge-bridge serve`) exposes **46 tools**: 33 legacy v0.2.0 tools, 6 v0.4.0 tools, and 7 v0.5.0 coding-agent workflow tools. Identity is derived strictly from the transport (`edge`, `executor:<id>`, `paired_host`, or `local`), never from tool arguments.

- **`Edge` (read-only):** Only the 23 tools in `READ_ONLY_TOOLS` are callable on projects granted with `--grant-edge`. `edge` gains none of the v0.5.0 tools or new read/search options.
- **`Delegated (pro-review)`:** `edge-bridge grant-create <project_id> --profile pro-review` grants `read`, `git_read`, `write` (create-only under `_pro/**`, never `_pro/inbox/**`), and `execute_recipe` (`python_tests`, `powershell_script`). None of the `work_*` tools is permitted.
- **`Delegated (pro-agent)`:** `edge-bridge grant-create <project_id> --profile pro-agent` adds `patch`, `work_area` (mutable strictly under exact-case `_pro/work/<workspace>/**`), and `python_tests_work` (requires worker `--allow-work-exec`). Live project files stay read-only; `_pro/inbox/**` stays read-only; `_pro/outbox/` and `_pro/reports/` stay create-only.
- **`Local`:** Local owner CLI / `--principal local`.

## Legacy 33 Tools

| Tool | `Edge` | `pro-review` | `pro-agent` | `Local` | Notes and Limits |
| --- | --- | --- | --- | --- | --- |
| `bridge_info` | Yes | Yes | Yes | Yes | Version, principal, access mode, and `tool_count_total` (46). `desktop_name` omitted for remote callers. |
| `bridge_health` | Yes | Yes | Yes | Yes | SQLite health and host resource status. |
| `connection_diagnostics` | Yes | Yes | Yes | Yes | Supported MCP protocol versions and transport facts. |
| `project_list` | Yes | Yes | Yes | Yes | Lists authorized projects (`root` and `root_identity` omitted for remote callers). Paged (`limit` 1–100, default 50). |
| `project_status` | Yes | Yes | Yes | Yes | Policy revision, capabilities, and recent runs (grant-scoped for delegated callers). |
| `policy_view` | Yes | Yes | Yes | Yes | Same as `project_status`, plus `grant` terms (`grant_id`, `permitted_categories`, `writable_paths`, `denied_paths`, `allowed_recipes`, `export_scope`, `limits`, `expires_at`) for delegated callers, and `work_area` (`root`, `workspaces`) when `work_area` is granted. `grant_id` may be omitted. |
| `project_resume` | Yes | Yes | Yes | Yes | Same data as `project_context` (kept under original v0.2.0 name): source manifest SHA-256, file count (walk cap 200,000 entries), recent runs, and recent evidence. |
| `task_get` | Yes | Yes | Yes | Yes | Up to 50 recent authorized runs for one `task_id`, including `workload_report` on delegated runs. |
| `file_list` | Yes | Yes | Yes | Yes | Lists `{path, kind, size}` entries; `recursive`, `max_depth` (up to 8), `exclude_generated` (default `true`), walk cap 200,000 entries. `limit` default 50, max 500 for non-`edge` (capped at 100 on `edge`). |
| `file_read` | Yes | Yes | Yes | Yes | Text file up to 32 MiB; character `offset`/`limit` (default 32,768, max 65,536). Non-`edge` may pass 1-based `start_line`/`end_line` (up to 2,000 lines, mutually exclusive with `offset > 0`). Refuses hidden/secret paths, links, and NUL bytes. |
| `file_view` | Yes | Yes | Yes | Yes | Alias of `file_read` with the same character and non-`edge` line-range limits. |
| `file_search` | Yes | Yes | Yes | Yes | Searches UTF-8 files <= 2 MiB (query 1–200 bytes, up to 100 hits, walk cap 200,000 entries). Non-`edge` may pass `context_lines` (0–5), `file_glob` (1–64 ASCII chars, no `/`, `\`, `..`), and linear-time `regex` (256 KiB compile/DFA cap). |
| `artifact_list` | Yes | Yes | Yes | Yes | Lists sealed evidence manifests (`manifest_id`, `run_id`, `verdict`, `execution_outcome`, `agent_outcome`, `verification_outcome`, `manifest_sha256`). Scoped by caller and grant for delegated principals. |
| `artifact_read` | Yes | Yes | Yes | Yes | Reads one sealed manifest (`artifact_id` takes `manifest_id` from `artifact_list`). Verifies Ed25519 signature server-side; returns allowlisted view to remote callers. |
| `git_status` | Yes | Yes | Yes | Yes | Branch, HEAD, dirty flag, and changed entries (hidden paths omitted; 64 MiB Git output cap; refuses repo content filters and `include`/`includeIf`). |
| `git_diff` | Yes | Yes | Yes | Yes | Paginated unified diff (64 MiB Git output cap, commit-only `base_ref`, `expected_diff_sha256`, hidden paths omitted). |
| `job_get` | Yes | Yes | Yes | Yes | State and outcome of one run (`run_id`), with `workload_report` on delegated runs. Grant-scoped for delegated callers. |
| `worker_list` | Yes | Yes | Yes | Yes | Reports remote model worker status (`workers_enabled: false`, `WORKER_CAPABILITY_NOT_VERIFIED`). |
| `file_write` | Denied | Create-only (`_pro/**`, not `_pro/inbox/**`) | Create-only outside `_pro/work/`; hash-checked overwrite inside `_pro/work/<workspace>/**` | Yes | Delegated writes: max 1 MiB/file, 4 MiB/call; `_pro/` quota 2,000 files, 256 MiB, 8,192 walk entries. |
| `file_patch` | Denied | Denied (no `patch`) | Hash-checked edits inside `_pro/work/<workspace>/**` (or create-only under `_pro/**`, not `_pro/inbox/**`) | Yes | 1–64 edits checked before authorization; max 1 MiB/file, 4 MiB/call for delegated callers. |
| `job_output` | Denied | Yes (own grant) | Yes (own grant) | Yes | Paged redacted output chunks (`cursor` = `next_seq`, `limit` 1–500, default 100). Output capture capped at `min(256 KiB, grant.limits.max_output_bytes)`; stored chunks pruned to the most recent 200 terminal runs. |
| `job_cancel` | Denied | Yes (own grant) | Yes (own grant) | Yes | Requests cancellation of a run; re-authorizes against the stored recipe for delegated callers. |
| `file_move` | Denied | Denied (owner-only) | Denied (owner-only) | CLI/Owner | Owner-only (`BRIDGE_POLICY_DENIED` for delegated principals). Use `work_move` under `pro-agent`. |
| `file_delete` | Denied | Denied (owner-only) | Denied (owner-only) | CLI/Owner | Owner-only (`BRIDGE_POLICY_DENIED` for delegated principals). Use `work_delete` under `pro-agent`. |
| `task_checkpoint` | Denied | Denied (owner-only) | Denied (owner-only) | CLI/Owner | Owner-only. |
| `process_start` | Denied | Denied (owner-only) | Denied (owner-only) | CLI/Owner | Owner-only. Delegated callers use `task_submit`. |
| `process_input` | Denied | Denied (owner-only) | Denied (owner-only) | CLI/Owner | Owner-only. |
| `job_changes` | Denied | Denied (owner-only) | Denied (owner-only) | CLI/Owner | Owner-only. |
| `git_checkpoint` | Denied | Denied (owner-only) | Denied (owner-only) | CLI/Owner | Owner-only. |
| `git_integrate` | Denied | Denied (owner-only) | Denied (owner-only) | CLI/Owner | Owner-only. |
| `worker_start` | Denied | Blocked | Blocked | Blocked | Fail-closed: `WORKER_CAPABILITY_NOT_VERIFIED`. |
| `worker_steer` | Denied | Blocked | Blocked | Blocked | Fail-closed: `WORKER_CAPABILITY_NOT_VERIFIED`. |
| `worker_cancel` | Denied | Blocked | Blocked | Blocked | Fail-closed: `WORKER_CAPABILITY_NOT_VERIFIED`. |

## V0.4.0 Additions (6 Tools)

| Tool | `Edge` | `pro-review` | `pro-agent` | `Local` | Notes and Limits |
| --- | --- | --- | --- | --- | --- |
| `project_context` | Yes | Yes | Yes | Yes | One-call orientation: source manifest SHA-256, file count (walk cap 200,000 entries), recent runs, and recent evidence. |
| `file_read_batch` | Yes | Yes | Yes | Yes | Reads 1–32 files in one call; per-item character `offset`/`limit` or (non-`edge`) `start_line`/`end_line` (up to 2,000 lines). |
| `git_diff_summary` | Yes | Yes | Yes | Yes | Per-file insertions/deletions and `diff_sha256` (two Git calls, up to 128 MiB combined cap). |
| `task_submit` | Denied | Yes (`python_tests`, `powershell_script`) | Yes (`python_tests`, `powershell_script`, `python_tests_work`) | Yes | Queues a background run (`queue_only`, max 60 s) and returns `run_id` immediately. Up to 8 active/queued runs per grant (reusing `operation_id` + payload replays idempotently). Up to 32 string args (1,024 bytes each, 16 KiB total). `powershell_script_work` is refused everywhere. |
| `device_list` | Yes | Yes | Yes | Yes | Local host id and paired devices. |
| `device_capabilities` | Yes | Yes | Yes | Yes | Alias of `device_list`. |

## V0.5.0 Coding-Agent Additions (7 Tools)

None of these 7 tools is in `READ_ONLY_TOOLS`; all 7 are denied to `edge` with `BRIDGE_POLICY_DENIED`.

| Tool | `Edge` | `pro-review` | `pro-agent` | `Local` | Notes and Limits |
| --- | --- | --- | --- | --- | --- |
| `job_wait` | Denied | Yes | Yes | Yes | Waits 0–20 s (default 15 s; `0` checks immediately) for 1–16 unique `job_ids` (`wait_for`: `any` or `all`). Attaches `workload_report` and optional terminal output (`include_output` default `true`, `output_limit_bytes` 1–32,768, default 16,384). Max 2 concurrent waits per caller (`RESOURCE_BUSY`, `retry_after_ms: 500`). |
| `work_copy` | Denied | Denied | Yes | Yes | Copies 1–64 project files/subtrees (`from_project`: up to 500 files, 4 MiB/file, 32 MiB/call, 20,000 walked entries; silently skips hidden files, `_pro/`, links, hardlinks) or 1 file within the same workspace (`within_workspace: true`) into `_pro/work/<workspace>/`. Max 16 workspaces per project; records bridge-side baseline manifest in `<state>/work-manifests/`. |
| `work_edit` | Denied | Denied | Yes | Yes | Atomic multi-file search-and-replace strictly inside `_pro/work/<workspace>/`: 1–32 files, 1–64 total hunks, max 1 MiB/file, max 4 MiB/call, optional `expected_hash`, `replace_all` (default `false` requires exact single match). |
| `work_move` | Denied | Denied | Yes | Yes | Handle-verified move/rename of 1 regular file strictly inside `_pro/work/<workspace>/`; optional `expected_from_hash`, `overwrite`, `expected_to_hash`; updates manifest. |
| `work_delete` | Denied | Denied | Yes | Yes | Deletes 1–64 files strictly inside `_pro/work/<workspace>/` (optional `expected_hashes`), or removes the entire workspace and its manifest (`delete_workspace: true`, walk cap 8,192 entries, refuses links) to free `_pro/` quota (2,000 files, 256 MiB). |
| `work_diff` | Denied | Denied | Yes | Yes | Read-only unified diff (max 4 MiB) and per-file stats comparing `_pro/work/<workspace>/` against live project files using the bridge manifest. Optional `paths` (1–64), `summary_only`, `expected_diff_sha256`, character `offset`/`limit` (default 32,768, max 65,536). Flags baseline drift and omits binary or >1 MiB file bodies. |
| `work_export_diff` | Denied | Denied | Yes | Yes | Create-only export of one `git apply`-compatible `.diff` file directly under exact-case `_pro/outbox/` (max 1 MiB). Refuses empty diffs, drifted baselines unless `allow_drifted: true`, and binary or >1 MiB changes. |

## Owner-Only CLI Commands (`edge-bridge`)

These commands run locally only and are never exposed as MCP tools:

- Project & state administration: `register <root> --name <name> [--grant-edge]`, `doctor`, `serve [--port <p>]`, `mcp --principal <edge|local|executor:<id>> [--text-content <full|summary>]`, `backup <target>`, `migrate-verify <source_db> <clone_db> [--allow-overwrite]`, `export-schemas [--out-dir <dir>]`
- Grants: `grant-create <project_id> [--requester <id>] [--profile <pro-review|pro-agent> | --writable-path <glob>... --recipe <name>...] [--ttl-minutes <1..=1440>]`, `grant-revoke <grant_id>`
- Queue worker & environment: `environment-check`, `worker --runtime-root <dir> [--once] [--allow-environment-credentials] [--allow-work-exec]`, `run-queued-python-tests <run_id> --runtime-root <dir> --file <path>... [--timeout-seconds <1..=120>]`, `run-job`
- Patch apply & rollback: `work-apply <project_id> <workspace> [--confirm]`, `apply-patch --project-root <dir> --plan-json <file>`, `rollback-patch --project-root <dir> --journal-id <id>`
- Evidence & diagnostics: `verify-evidence <manifest_json> [--trusted-key <hex>] [--artifacts-dir <dir>]`, `providers`, `inspect-muse-events`, `parse-ulog`, `benchmark`, `device-rehearsal`
