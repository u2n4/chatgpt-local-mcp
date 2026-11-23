# Installing ChatGPT Local MCP (Edge Project Bridge) on Windows

Edge Project Bridge lets a remote AI model read one local project folder, create new files only under `_pro\`, and queue sandboxed test runs that a local worker executes on your PC.

## Quick install

Open **PowerShell 7** (`pwsh`), replace `<VERSION>` with the release version (for example `0.6.0-pre1`), and run these three steps.

### 1. Download `install.ps1` and `SHA256SUMS.txt`

Public release:

```powershell
$version = '<VERSION>'
$base = "https://github.com/u2n4/chatgpt-local-mcp/releases/download/v$version"
Invoke-WebRequest -Uri "$base/install.ps1" -OutFile '.\install.ps1'
Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile '.\SHA256SUMS.txt'
```

Private repository (requires [GitHub CLI](https://cli.github.com/) signed in with `gh auth login`):

```powershell
$version = '<VERSION>'
gh release download "v$version" --repo u2n4/chatgpt-local-mcp --pattern 'install.ps1' --pattern 'SHA256SUMS.txt'
```

### 2. Verify `install.ps1` before running it

```powershell
(Get-FileHash -LiteralPath '.\install.ps1' -Algorithm SHA256).Hash.ToLowerInvariant()
Select-String -Path '.\SHA256SUMS.txt' -Pattern 'install\.ps1$'
```

Confirm both 64-character hex hashes match exactly.

> **Verification limit:** `SHA256SUMS.txt` from the same GitHub Release only detects a corrupted or swapped download; it does **not** protect against a compromised release or GitHub account. To trust `install.ps1` itself, compare its hash with a value from another channel or read the script before running it. The `-Sha256` option checks the release `.zip` only—it cannot check the script that is already running.

### 3. Run the installer

If you downloaded `install.ps1` in a web browser, unblock it first:

```powershell
Unblock-File -LiteralPath '.\install.ps1'
```

Start the interactive installer (it asks for the install folder and project folder, shows the resolved paths, and asks `y/N` before writing anything):

```powershell
pwsh -ExecutionPolicy Bypass -File .\install.ps1 -Version $version
```

`-ExecutionPolicy Bypass` applies only to this single run; it does not change your system PowerShell policy. (If your policy already allows local scripts, `pwsh -File .\install.ps1 -Version $version` also works.)

---

## Two install levels

| Level | What works | What your PC needs |
| --- | --- | --- |
| **Core** | The remote model reads your project and creates new files under `_pro\` | PowerShell 7 to run the installer. Git for Windows if you want the Git read tools. |
| **Test runs** | The local worker runs queued Python tests (`python_tests`) and PowerShell scripts (`powershell_script`) inside a sandbox | `uv`, Python 3.13, and the two exact pinned builds below |

The installer always installs the core level. It does not install software for you—if anything for test runs is missing, it finishes the core install and prints what to install next. After installing missing tools, open a **new** PowerShell 7 window and run `.\setup-worker.ps1` in the install folder.

> **Exact pinned builds:** The worker checks the exact SHA-256 hash of both PowerShell `7.7.0` x64 (`%ProgramFiles%\PowerShell\7\pwsh.exe`) and `@openai/codex@0.171.0`. If Windows, `winget`, or `npm` updates either tool to a newer build, test runs fail until Edge Project Bridge updates its pins. The core level is not affected.

## What the remote model can and cannot do

`new-grant.ps1` supports two grant profiles (`pro-review` is the default):

- **`pro-review` (`.\new-grant.ps1`):** reads project files (excluding secret/credential files), creates **new** files only under `_pro\outbox\` and `_pro\reports\`, and can queue `python_tests` and `powershell_script` against live project files. None of the `work_*` tools is available.
- **`pro-agent` (`.\new-grant.ps1 -Profile pro-agent`):** adds mutable workspaces strictly under `_pro\work\<workspace>\` (`work_copy`, `work_edit`, `work_move`, `work_delete`, `work_diff`, `work_export_diff`) and the `python_tests_work` recipe. Live project files outside `_pro\work\` remain read-only; apply reviewed changes locally with `edge-bridge work-apply`.
- Under **both** profiles, the model **cannot** write under `_pro\inbox\`, and it **cannot** change, move, or delete live project files.

> Tip: keep `_pro/` out of Git by adding `_pro/` to `.git/info/exclude` in your project.

## Unattended and local-zip installs

To skip prompts, pass `-InstallDir` and `-ProjectPath` on the command line.

From GitHub Releases (with optional `-Sha256` for the **release `.zip`**, not `install.ps1`—ideally obtained from another channel; if omitted, the installer reads the `.zip` hash from the release's `SHA256SUMS.txt`):

```powershell
pwsh -ExecutionPolicy Bypass -File .\install.ps1 `
  -Version '<VERSION>' `
  -Sha256 '<64-char-zip-sha256>' `
  -InstallDir "$env:LOCALAPPDATA\EdgeProjectBridge" `
  -ProjectPath 'C:\path\to\your\project'
```

From an already downloaded local `.zip` (skips downloading the `.zip` only; `uv sync --locked` still downloads locked Python packages from PyPI unless they are already in `uv`'s cache):

```powershell
pwsh -ExecutionPolicy Bypass -File .\install.ps1 `
  -ZipPath '.\edge-project-bridge-<VERSION>-windows-x64.zip' `
  -Sha256 '<64-char-zip-sha256>' `
  -InstallDir "$env:LOCALAPPDATA\EdgeProjectBridge" `
  -ProjectPath 'C:\path\to\your\project'
```

If `SHA256SUMS.txt` is in the same folder as `-ZipPath`, you may omit `-Sha256` and the installer reads the `.zip` hash from `SHA256SUMS.txt` (subject to the verification limit above).

## First use

Open PowerShell 7 in your install folder (default: `$env:LOCALAPPDATA\EdgeProjectBridge`). If your PowerShell policy blocks local scripts, run each script with `pwsh -ExecutionPolicy Bypass -File .\<script>.ps1`.

1. **Check Windows environment variables:**

   ```powershell
   .\environment-check.ps1
   ```

   Sandboxed runs can read persistent user and machine environment variables stored in the Windows registry. While any entry looks like a credential, the worker refuses test runs with `PERSISTENT_ENVIRONMENT_HOLDS_CREDENTIALS`. Remove those entries from the persistent Windows environment, or start `edge-bridge.exe` manually with `--allow-environment-credentials` only if you explicitly accept that test runs can read them.

2. **Create a temporary permission pass (valid for 60 minutes by default):**

   ```powershell
   # Review-only (default: pro-review)
   .\new-grant.ps1

   # Workspace editing under _pro\work\<workspace>\ (pro-agent)
   .\new-grant.ps1 -Profile pro-agent
   ```

   This prints `profile`, `grant_id`, `expires_at`, and `project_id`.

3. **Start the local test worker** (from a normal interactive Windows desktop session—not a background service or headless session):

   If the installer listed missing test-run tools, install them, open a new PowerShell 7 window, and run `.\setup-worker.ps1` first. Then run:

   ```powershell
   .\start-worker.ps1
   ```

   Leave this window open while you want queued test runs executed (press `Ctrl+C` to stop it). Pass `--once` (`.\start-worker.ps1 --once`) to drain the current queue and exit (it exits quietly with no output when the queue is empty).

   **`--allow-work-exec` is off by default** (and `start-worker.ps1` does not pass it). Without it, `python_tests_work` is refused with `WORK_EXEC_NOT_ENABLED`, while a `pro-agent` model can still copy, edit, diff, and export patches in `_pro\work\` and run the project's own `python_tests`. Only pass `.\start-worker.ps1 --allow-work-exec` if you explicitly accept the sandbox registry risk documented in `docs/KNOWN_LIMITATIONS.md` (measured on one PC: no network and no folder outside the snapshot, but Windows user name, profile paths, `HKCU\Software`, `HKLM\Software`, and `HKCU\Environment` are reachable by remote-authored code). `powershell_script_work` is refused everywhere.

4. **Apply a `pro-agent` workspace locally (owner CLI):**

   ```powershell
   # Dry run (shows planned changes and diff without modifying project files)
   .\bin\edge-bridge.exe --state-dir=.\state work-apply <project_id> <workspace>

   # Apply atomically (all files or none) and save a rollback journal
   .\bin\edge-bridge.exe --state-dir=.\state work-apply <project_id> <workspace> --confirm

   # Roll back if needed (refuses to overwrite later edits)
   .\bin\edge-bridge.exe --state-dir=.\state rollback-patch --project-root <project> --journal-id <journal_id>
   ```

5. **Connect an MCP client:**

   For a local MCP client that launches a command over standard input/output (stdio), configure the exact **Program** and **Arguments** printed by the installer:

   - Program: `<InstallDir>\bin\edge-bridge.exe`
   - Arguments: `--state-dir=<InstallDir>\state`, `mcp`, `--principal=executor:default`

   ChatGPT web cannot start a local program. It needs a tunnel and connector that you set up yourself; this installer does not set them up.

## Prerequisites details

### Required for test runs (checked by the installer)

| Tool | Exact version / location | How to install |
| --- | --- | --- |
| `uv` | `uv` on `PATH` (builds `<InstallDir>\runtime\.venv`) | `winget install --id astral-sh.uv` or [uv docs](https://docs.astral.sh/uv/getting-started/installation/) |
| Python 3.13 | Local Python `>=3.13,<3.14` | `winget install --id Python.Python.3.13` or [python.org](https://www.python.org/downloads/) |
| Pinned PowerShell 7.7.0 x64 | `%ProgramFiles%\PowerShell\7\pwsh.exe` with SHA-256 `e94166ed9f376559c1359bafb08bc49e463a494c330f67644ec1d9f1ffeb5ee5` (for `powershell_script` runs) | Install `PowerShell-7.7.0-win-x64.msi` (not the Microsoft Store app) from the [PowerShell 7.7.0 release](https://github.com/PowerShell/PowerShell/releases/tag/v7.7.0) |
| Pinned Codex sandbox binary | `@openai/codex@0.171.0` at `%APPDATA%\npm\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe` with SHA-256 `cefea4ffee1fff04983a99c0dda99944d8b380e891e740a28b32f4b815a6e0b7` (for every sandboxed run) | `npm install -g @openai/codex@0.171.0` (requires [Node.js / npm](https://nodejs.org/)) |

### Optional and runtime requirements

- **Git for Windows** (optional, for core Git read tools; not needed for test runs): `C:\Program Files\Git\cmd\git.exe` or `git` on `PATH` (`winget install --id Git.Git` or [git-scm.com](https://git-scm.com/download/win)).
- **Windows x64 on NTFS + interactive desktop (`WinSta0\Default`)** (checked when runs execute, not by the installer): start `start-worker.ps1` from a normal signed-in Windows desktop session.
- **GitHub CLI (`gh`)** (optional): only needed to download from a private GitHub repository without `-ZipPath` (`winget install --id GitHub.cli`).

## Install folder and path rules

- **New or empty folder only:** `<InstallDir>` must not exist or must be empty. The installer never replaces an existing install.
- **One project per install folder:** for a second project, or for a newer version, install into a new folder.
- **Ordinary local paths only:** paths starting with `~` or `\\` (network/device paths), drive roots, `%USERPROFILE%`, `%WINDIR%`, overlapping install/project folders, and paths containing junctions or symlinks are refused. The overlap check compares path text (it does not detect `subst` aliases), so use ordinary paths.
- **Avoid background writes during install:** do not install into a folder actively modified by a sync client while the installer runs.

## What the installer writes and does not change

**Writes:**

- `<InstallDir>\bin\edge-bridge.exe` — main program.
- `<InstallDir>\runtime\` — Python worker files and (when `uv` and Python 3.13 are present) `<InstallDir>\runtime\.venv\`, built with `uv --no-config sync --locked --no-python-downloads` after clearing shell `UV_*`/`VIRTUAL_ENV` overrides (`uv` still uses its own cache outside `<InstallDir>`).
- `<InstallDir>\state\state.sqlite3` (and SQLite journal files) — state database with your project registered.
- `<InstallDir>\install.json` — saved install paths and `project_id`. Helper scripts run the binary recorded here, so keep `<InstallDir>` writable only by you.
- `<InstallDir>\environment-check.ps1`, `new-grant.ps1`, `setup-worker.ps1`, `start-worker.ps1` — helper scripts (`new-grant.ps1` accepts `-Profile pro-review` [default] or `-Profile pro-agent`; `start-worker.ps1` does not pass `--allow-work-exec` by default; `setup-worker.ps1` builds `<InstallDir>\runtime\.venv` with `uv` and Python 3.13 without checking pinned PowerShell/Codex hashes).
- Documentation and license files from the release zip (`LICENSE`, `README.md`, `SECURITY_BOUNDARIES.md`, `docs\`).
- `<ProjectPath>\_pro\`, `_pro\inbox\`, `_pro\outbox\`, `_pro\reports\` — created only if missing; existing project files are never modified.
- Temporary folders deleted on exit (`%TEMP%\epb-install-<id>\` and staging folders inside `<InstallDir>`).

**Does not change:**

- No administrator rights required.
- Does not change `PATH`, the Windows registry, environment variables, or PowerShell execution policy.
- Does not install missing prerequisites.
- Does not modify, move, or delete existing project files.
- Does not set up a tunnel or ChatGPT web connector.
- Rolls back directories and files it created if any step fails.

## Newer version

The installer does not upgrade in place. Install the newer version into a new folder, then delete the old folder (grants and run history in the old `state` folder are not carried over).

## Uninstall

1. Stop any running worker (`start-worker.ps1`) and disconnect any MCP client using `edge-bridge.exe`.
2. Delete `<InstallDir>`:

   ```powershell
   Remove-Item -LiteralPath "$env:LOCALAPPDATA\EdgeProjectBridge" -Recurse
   ```

   This removes the registered project, grants, and run history. Your project's `_pro\` folders stay untouched; delete them manually if you no longer need them.

## Troubleshooting

| Symptom or message | Cause | What to do |
| --- | --- | --- |
| `#Requires -Version 7` error | Opened Windows PowerShell 5.1 instead of PowerShell 7 | Run `pwsh -ExecutionPolicy Bypass -File .\install.ps1 ...` |
| Script blocked by execution policy or Windows download warning | Downloaded script is blocked or policy is `Restricted` / `AllSigned` | Run `Unblock-File -LiteralPath .\install.ps1` and launch with `pwsh -ExecutionPolicy Bypass -File .\install.ps1 ...` |
| `Queued test runs do NOT work yet on this PC` | Missing or wrong-version `uv`, Python 3.13, PowerShell 7.7.0 x64 MSI, or `@openai/codex@0.171.0` (core install succeeded) | Install the listed items, open a new PowerShell 7 window, and run `.\setup-worker.ps1` |
| `The worker runtime is not built yet` | `start-worker.ps1` ran before `runtime\.venv` existed | Run `.\setup-worker.ps1` |
| `Refusing to install: the install folder is not empty` | `<InstallDir>` already has files | Choose a new or empty folder |
| `Refusing path ... reparse point` / `starting with '~'` / `UNC` | Path uses `~`, `\\`, or passes through a junction/symlink | Use a regular local path (for example `C:\Projects\MyApp`) |
| `Install folder cannot be inside the project folder` (or vice versa) | `<InstallDir>` and `<ProjectPath>` overlap | Keep them in separate folders |
| `Release download failed with HTTP 404` or `gh release download failed` | Wrong `-Version` or private repo without signed-in `gh` | Verify `-Version`; for a private repo run `gh auth login`, or download the `.zip` manually and pass `-ZipPath` |
| `SHA-256 verification is required` / `SHA-256 mismatch` | Missing checksum, wrong hash passed to `-Sha256` (remember it takes the `.zip` hash, not `install.ps1`), or corrupted zip | Check you passed the `.zip` hash from `SHA256SUMS.txt` or re-download; never extract a mismatched zip |
| `uv sync` fails | No network access to PyPI (packages not cached) or Python 3.13 missing | Verify network access and that Python 3.13 is installed, then re-run `.\setup-worker.ps1` in a new PowerShell 7 window |
| Worker refuses run with `PERSISTENT_ENVIRONMENT_HOLDS_CREDENTIALS` | Persistent Windows environment variables look like credentials | Run `.\environment-check.ps1` to see the variable names and remove them from persistent Windows environment variables |
| Worker fails with `ISOLATION_NOT_VERIFIED` | Not on interactive desktop (`WinSta0\Default`), or pinned PowerShell 7.7.0 / Codex 0.171.0 changed | Start `.\start-worker.ps1` from a normal desktop session and restore the exact pinned builds |
