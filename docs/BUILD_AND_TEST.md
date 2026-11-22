# Build and Test

Use PowerShell on Windows, Git, Rustup, LLVM-MinGW UCRT, Python 3.13 with `uv`, and Node.js with npm. Use `rust-toolchain.toml` and the workspace lockfiles to resolve dependencies. Put the `bin` directory of LLVM-MinGW on `PATH` so Cargo can find `x86_64-w64-mingw32-clang` and `llvm-ar`.

Run the build commands from the repository root. The build script resolves GNU-host build-script linking from the pinned Rust sysroot while LLVM-MinGW links the application. Pass the installed LLVM-MinGW bin directory via `-LlvmMingwBin` if it is missing from PATH. Pass `-Offline` when the locked dependencies are already cached.

```powershell
.\scripts\build-windows.ps1 -Test
uv sync --locked
uv run --locked --no-sync python -m unittest discover -s tests -p 'test_*.py' -v
Push-Location -LiteralPath 'apps/bridgepulse'
npm ci
npm run check
npm run build
Pop-Location
```

## Isolated canary

The following starts only the loopback server in a new state directory. The registration example grants Edge read access to the bundled synthetic calculator fixture.

```powershell
$bridge = (Resolve-Path -LiteralPath 'target/x86_64-pc-windows-gnullvm/release/edge-bridge.exe').Path
$state = Join-Path ([System.IO.Path]::GetTempPath()) ('edge-bridge-canary-' + [guid]::NewGuid().ToString('N'))
& $bridge --state-dir $state --environment-kind canary register (Resolve-Path -LiteralPath 'examples/calculator').Path --name 'Calculator fixture' --grant-edge
& $bridge --state-dir $state --environment-kind canary serve --port 0 --ui-dist (Resolve-Path -LiteralPath 'apps/bridgepulse/dist').Path
```

Open the localhost URL printed by the broker. Load the owner credential locally for the BridgePulse administrative view. Give an isolated read client the separate read credential. Both files are generated under the state directory.

## MCP and acceptance

```powershell
$bridge = (Resolve-Path -LiteralPath 'target/x86_64-pc-windows-gnullvm/release/edge-bridge.exe').Path
$evidence = Join-Path ([System.IO.Path]::GetTempPath()) ('edge-bridge-mcp-' + [guid]::NewGuid().ToString('N'))
uv run --locked --no-sync python benchmarks/bench_mcp_concurrency.py --binary $bridge --output-dir $evidence --soak-seconds 1800
```

The harness starts a broker with isolated synthetic state, starts distinct MCP client processes, and writes request and resource samples outside the checkout. Read its JSON summary together with the process exit status. The durations and client counts can be adjusted through its `--help` options.

Run the Rust/Python parity, security and end-to-end tests in `tests/integration`, `tests/security`, `tests/contract`, and `tests/e2e` using the matching Windows toolchain and built binary. The default `unittest discover -s tests` includes the top-level Python tests. These additional test directories can be discovered individually. Run queued MXC integration tests from a supported desktop with the pinned Codex executable available and the test Python environment installed by `uv sync --locked`.

`scripts/run_v040_vertical_slice.py` can regenerate the synthetic BridgePulse Lab evidence bundle. Keep generated evidence local. Its optional migration step accepts three arguments together: an isolated SQLite backup, the recorded instance ID and the expected project count. `scripts/canary-v040-rehearsal.ps1` likewise takes explicit offline backup and expectation parameters. Rehearsal output describes the supplied copy.

Real provider runner and browser harnesses are explicit opt-in commands. Confirm the installed provider and its included-only account route before running a real model job. The local benchmark and source export scanner require no provider calls.

## Source verification

Run `python -B scripts/source_export.py manifest` before Gitleaks. Save the manifest outside the checkout. It emits each in-scope file's path, size, and SHA-256 digest. The optional `--reject-markers` file lets a local operator check known private identifiers without committing them. Run Gitleaks on the exact outgoing source and any outgoing commits.
