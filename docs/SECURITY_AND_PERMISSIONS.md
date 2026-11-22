# Security and Permissions Model

## 1. Control Plane & State Directory (`broker.py`, `state.py`)
- **Strict State ACL (`verify_state_path`):** The state directory (`%LOCALAPPDATA%\EdgeProjectBridge`) and every child file (`state.sqlite3`, `ipc.pem`, `ipc-key.pem`, `owner.token`, `edge.token`, `broker.json`, `broker.lock`) must be regular non-hardlinked files (`st_nlink == 1`, no reparse points) with DACLs permitting **only** the current Windows user SID and `SYSTEM`.
- **Backup Boundary:** SQLite backups (`owner_backup` / `cli backup`) MUST target a path outside `state_dir` (so `verify_state_path` never sees foreign subdirs/files inside `state_dir`) and outside every registered project root.
- **Authenticated Loopback IPC:** `127.0.0.1` only (`SO_EXCLUSIVEADDRUSE`), self-signed ECDSA P-256 TLS (`ipc.pem`), empty `Origin` enforcement, host-header validation, 64-hex per-principal tokens, HMAC-SHA256 request/response signatures, `+-30s` clock skew check, and replay-blocking nonce window (`MAX_RECENT_NONCES = 8192`).

## 2. File Containment (`files.py`)
- Handle-relative directory traversal using Win32 `CreateFileW` / `FILE_FLAG_OPEN_REPARSE_POINT`, rejecting symlinks, junctions, ADS (`:`), UNC prefixes, drive-relative paths, `..`, reserved DOS device names, and sensitive files/dirs (`.git`, `.ssh`, `.aws`, `.azure`, `.codex`, `.claude`, `.git-credentials`, `.terraform`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `.env` secrets rules via `_DENIED`).
- `file_read` rejects NUL bytes in strict UTF-8 mode (`UNSUPPORTED_FILE_ENCODING`), offers explicit opt-in `lossy_utf8=True` (marking `editable=False`), and caps file inspection at 32 MiB with chunked SHA-256 calculation.
- Writes use staging temp files + Win32 `SetFileInformationByHandle` atomic replacement with expected SHA-256 precondition (`VERSION_CONFLICT`) and reversible delete quarantine under `.edge-project-bridge`.

## 3. Process & Sandbox Isolation (`runner.py`, `jobs.py`)
- Pinned `codex.exe` (`0.169.0`, SHA-256 checked on every launch) executes `-c windows.sandbox=mxc sandbox --include-managed-config`.
- `:root = "deny"`, `:minimal = "read"`, `:workspace_roots = "write"` pointed solely at a fresh regular-file job snapshot copy, `network.enabled = false`.
- **No weaker fallback:** Missing binary, hash mismatch, failed preflight canary (`outside_read`, `outside_write`, `external_hardlink`, IPv4/IPv6 loopback, host named pipe, child outside read, credential env), or unconfirmed Job Object assignment (`CREATE_SUSPENDED` + `PROC_THREAD_ATTRIBUTE_JOB_LIST` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) blocks execution fail-closed.
- `powershell_script` executes explicitly owner-granted `.ps1` files from a job snapshot using the pinned PowerShell 7 binary with `-NoProfile -NonInteractive -File`. The runner keeps the host execution policy in effect. Legacy request arrays are normalized into the scoped recipe. Inline commands and extra arguments are rejected with `EXECUTION_REQUEST_UNSUPPORTED`.

## 4. Git Engine Hardening (`git_engine.py`)
- Uses pinned `git.exe` (`GIT_SHA256` verified via `hashlib.file_digest`), launched inside a Win32 Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), `GIT_CEILING_DIRECTORIES` set to `root.parent`, and `rev-parse --show-toplevel` normalized equality check so parent repos outside project root are never touched.
- Every call overrides repo/global dangers: `GIT_TERMINAL_PROMPT=0`, `GIT_CONFIG_GLOBAL=NUL`, `-c core.hooksPath=NUL -c core.fsmonitor=false -c diff.external= -c protocol.file.allow=never -c core.quotePath=false`. System config is kept intact so Windows `core.autocrlf` matches the repository's normal Git behavior.
- Rejects leading `-` flags in `base_ref` and `paths`, uses temporary `GIT_INDEX_FILE` outside repo for non-destructive checkpoints, and restricts automated merges to clean working trees + `--ff-only`.

## 5. Worker Fail-Closed Gates (`workers.py`, `worker_account.py`)
- `worker_start` and `worker_steer` refuse execution (`WORKER_CAPABILITY_NOT_VERIFIED`).
- `build_worker_isolation_spec` enforces `worker_capabilities <= parent_capabilities` (`PRIVILEGE_ESCALATION_DENIED`).
- `summarize_account` supports all 20 OpenAI `PlanType` values while stripping PII (`email`, `userId`) and preserving `auto_reload_verified=False`, `workers_enabled=False`, and `worker_policy="INCLUDED_ONLY"`.
