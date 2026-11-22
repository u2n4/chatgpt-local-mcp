<#
.SYNOPSIS
    Repeatable, fail-fast Canary Migration & Restore Rehearsal Script for Edge Project Bridge V0.4.0.
.DESCRIPTION
    Safely rehearses migrating the v0.2.0 SQLite baseline backup into a BRAND-NEW isolated Canary directory
    and rehearses backup/restore into a separate restore directory.
    - NEVER touches live `%LOCALAPPDATA%\EdgeProjectBridge` or existing Canary directories.
    - Checks `$LASTEXITCODE` on every single command.
    - Proves `doctor` is strictly read-only on an uninitialized directory (creates no empty DB).
    - Proves `migrate-verify` refuses silent overwrite of an existing destination database.
    - Verifies the expected instance, schema version, project count, and strictly read-only `edge` grants,
      MCP `edge` read-only enforcement, and full backup+restore integrity.
#>
[CmdletBinding()]
param(
    [string]$BridgeExe = "$PSScriptRoot\..\target\x86_64-pc-windows-gnullvm\release\edge-bridge.exe",
    [Parameter(Mandatory)][string]$BackupDb,
    [Parameter(Mandatory)][guid]$ExpectedInstanceId,
    [Parameter(Mandatory)][ValidateRange(1, 50)][int]$ExpectedProjectCount,
    [string]$OutReport = "$PSScriptRoot\..\audit-v0.4.0-20261119\evidence-bundle\canary-rehearsal-result.json",
    [switch]$KeepTempDirs
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $BridgeExe)) {
    throw "edge-bridge.exe not found at: $BridgeExe"
}
if (-not (Test-Path -LiteralPath $BackupDb)) {
    throw "Baseline backup SQLite file not found at: $BackupDb"
}

$BridgeExe = (Resolve-Path -LiteralPath $BridgeExe).Path
$BackupDb = (Resolve-Path -LiteralPath $BackupDb).Path
$ExpectedInstanceId = $ExpectedInstanceId.ToString()
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$canaryDir = Join-Path $env:LOCALAPPDATA "EdgeProjectBridge-v04-canary-rehearsal-$stamp"
$restoreDir = Join-Path $env:LOCALAPPDATA "EdgeProjectBridge-v04-restore-rehearsal-$stamp"

if ((Test-Path -LiteralPath $canaryDir) -or (Test-Path -LiteralPath $restoreDir)) {
    throw "Destination rehearsal directory already exists; refusing to proceed."
}

$backupSha = (Get-FileHash -LiteralPath $BackupDb -Algorithm SHA256).Hash.ToLowerInvariant()
$steps = [System.Collections.Generic.List[object]]::new()

try {
    # Step 1: Verify doctor is strictly read-only on an uninitialized directory
    Write-Host "[1/7] Running doctor on uninitialized Canary directory (must NOT create state.sqlite3)..."
    $docBeforeRaw = & $BridgeExe --state-dir $canaryDir doctor
    if ($LASTEXITCODE -ne 0) { throw "doctor (before) failed with exit code $LASTEXITCODE" }
    $docBefore = $docBeforeRaw | ConvertFrom-Json
    $dbCreatedPrematurely = Test-Path -LiteralPath (Join-Path $canaryDir "state.sqlite3")
    if ($docBefore.state_db_initialized -ne $false -or $dbCreatedPrematurely) {
        throw "DEFECT: doctor created or reported initialized DB on fresh directory!"
    }
    $steps.Add([ordered]@{ step = "doctor_before_migration"; ok = $true; state_db_initialized = $false; created_empty_db = $false })

    # Step 2: Migrate baseline backup into fresh Canary state.sqlite3
    Write-Host "[2/7] Running migrate-verify into fresh Canary destination..."
    $canaryDb = Join-Path $canaryDir "state.sqlite3"
    $migRaw = & $BridgeExe --state-dir $canaryDir migrate-verify $BackupDb $canaryDb
    if ($LASTEXITCODE -ne 0) { throw "migrate-verify failed with exit code $LASTEXITCODE" }
    $mig = $migRaw | ConvertFrom-Json
    if ($mig.instance_id_preserved -ne $ExpectedInstanceId) {
        throw "instance_id mismatch: got $($mig.instance_id_preserved), expected $ExpectedInstanceId"
    }
    if ([int]$mig.schema_version_after_migration -ne 4) {
        throw "schema_version mismatch: got $($mig.schema_version_after_migration), expected 4"
    }
    if ([int]$mig.total_projects_preserved -ne $ExpectedProjectCount -or [int]$mig.edge_granted_projects_preserved -ne $ExpectedProjectCount) {
        throw "project count mismatch: total=$($mig.total_projects_preserved) edge=$($mig.edge_granted_projects_preserved) expected=$ExpectedProjectCount"
    }
    if (-not $mig.post_migration_backup_integrity_ok -or [int]$mig.post_migration_foreign_key_issues -ne 0) {
        throw "post-migration backup integrity check failed!"
    }
    $steps.Add([ordered]@{
        step = "migrate_verify_fresh"
        ok = $true
        instance_id = $mig.instance_id_preserved
        schema_version = $mig.schema_version_after_migration
        total_projects = $mig.total_projects_preserved
        edge_projects = $mig.edge_granted_projects_preserved
        backup_integrity_ok = $mig.post_migration_backup_integrity_ok
        foreign_key_issues = $mig.post_migration_foreign_key_issues
        migrated_backup_sha256 = $mig.post_migration_backup_sha256
    })

    # Step 3: Negative safety check — second migrate-verify MUST refuse silent overwrite
    Write-Host "[3/7] Verifying migrate-verify refuses silent overwrite of existing Canary DB..."
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $overwriteOut = & $BridgeExe --state-dir $canaryDir migrate-verify $BackupDb $canaryDb 2>&1
    $overwriteCode = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    if ($overwriteCode -eq 0) {
        throw "DEFECT: migrate-verify silently overwrote an existing database!"
    }
    $steps.Add([ordered]@{
        step = "migrate_verify_refuses_overwrite"
        ok = $true
        exit_code = $overwriteCode
        message = (($overwriteOut | Out-String).Trim())
    })

    # Step 4: Run doctor after migration and confirm migrated state
    Write-Host "[4/7] Running doctor on migrated Canary directory..."
    $docAfterRaw = & $BridgeExe --state-dir $canaryDir doctor
    if ($LASTEXITCODE -ne 0) { throw "doctor (after) failed with exit code $LASTEXITCODE" }
    $docAfter = $docAfterRaw | ConvertFrom-Json
    if ($docAfter.state_db_initialized -ne $true -or $docAfter.database.instance_id -ne $ExpectedInstanceId -or [int]$docAfter.database.sqlite_schema_version -ne 4) {
        throw "doctor (after) did not confirm migrated state!"
    }
    $steps.Add([ordered]@{
        step = "doctor_after_migration"
        ok = $true
        instance_id = $docAfter.database.instance_id
        schema_version = $docAfter.database.sqlite_schema_version
        projects = $docAfter.database.projects
        sqlite_runtime = $docAfter.versions.sqlite_runtime_version
        wal_reset_fix_verified = $docAfter.versions.sqlite_wal_reset_fix_verified
    })

    # Step 5: Verify the migrated MCP principal sees only read grants.
    Write-Host "[5/7] Verifying MCP stdio principal=edge read-only enforcement on migrated Canary DB..."
    $mcpInput = @(
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}'
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"project_list","arguments":{}}}'
    ) -join "`n"
    $mcpOut = $mcpInput | & $BridgeExe --state-dir $canaryDir mcp --principal edge
    if ($LASTEXITCODE -ne 0) { throw "mcp stdio check failed with exit code $LASTEXITCODE" }
    $mcpLines = @($mcpOut | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_ | ConvertFrom-Json })
    $projList = $mcpLines[1].result.structuredContent.result.projects
    if ($projList.Count -ne $ExpectedProjectCount) {
        throw "MCP edge project_list returned $($projList.Count) projects, expected $ExpectedProjectCount"
    }
    $nonReadOnly = @($projList | Where-Object { ($_.capabilities -join ",") -ne "read" })
    if ($nonReadOnly.Count -ne 0) {
        throw "SECURITY DEFECT: Found non-read-only edge grant in Canary DB!"
    }
    $firstPid = $projList[0].project_id
    $denyInput = "{`"jsonrpc`":`"2.0`",`"id`":3,`"method`":`"tools/call`",`"params`":{`"name`":`"file_write`",`"arguments`":{`"project_id`":`"$firstPid`",`"operation_id`":`"op-deny`",`"path`":`"test.txt`",`"content`":`"x`"}}}"
    $denyOut = ($denyInput | & $BridgeExe --state-dir $canaryDir mcp --principal edge) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $denyOut.result.isError -or $denyOut.result.structuredContent.code -ne "BRIDGE_POLICY_DENIED") {
        throw "SECURITY DEFECT: edge file_write was not denied with BRIDGE_POLICY_DENIED!"
    }
    $steps.Add([ordered]@{
        step = "mcp_edge_readonly_verified"
        ok = $true
        edge_visible_projects = $projList.Count
        non_readonly_edge_grants = $nonReadOnly.Count
        edge_file_write_denied = $true
    })

    # Step 6: Backup & Restore Rehearsal into a completely separate directory
    Write-Host "[6/7] Executing online SQLite backup & separate restore rehearsal..."
    New-Item -ItemType Directory -Path $restoreDir -Force | Out-Null
    $restoredDb = Join-Path $restoreDir "state.sqlite3"
    $bakRaw = & $BridgeExe --state-dir $canaryDir backup $restoredDb
    if ($LASTEXITCODE -ne 0) { throw "backup failed with exit code $LASTEXITCODE" }
    $bak = $bakRaw | ConvertFrom-Json
    if (-not $bak.integrity_ok -or [int]$bak.foreign_key_issues -ne 0) {
        throw "Restored backup failed integrity/FK check!"
    }
    $docRestoredRaw = & $BridgeExe --state-dir $restoreDir doctor
    if ($LASTEXITCODE -ne 0) { throw "doctor on restored directory failed with exit code $LASTEXITCODE" }
    $docRestored = $docRestoredRaw | ConvertFrom-Json
    if ($docRestored.database.instance_id -ne $ExpectedInstanceId -or [int]$docRestored.database.projects -ne $ExpectedProjectCount) {
        throw "Restored DB metadata mismatch!"
    }
    $steps.Add([ordered]@{
        step = "backup_and_restore_rehearsal"
        ok = $true
        restored_sha256 = $bak.sha256
        integrity_ok = $bak.integrity_ok
        foreign_key_issues = $bak.foreign_key_issues
        restored_instance_id = $docRestored.database.instance_id
        restored_projects = $docRestored.database.projects
    })

    # Step 7: Recheck the input backup bytes.
    Write-Host "[7/7] Checking the supplied backup against its starting digest..."
    $backupAfterSha = (Get-FileHash -LiteralPath $BackupDb -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($backupAfterSha -ne $backupSha) {
        throw "Input backup changed during rehearsal."
    }
    $steps.Add([ordered]@{ step = "input_backup_unchanged"; ok = $true })

    $report = [ordered]@{
        captured_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        status = "PASS"
        baseline_backup_sha256 = $backupSha
        canary_dir_used = $canaryDir
        restore_dir_used = $restoreDir
        kept_temp_dirs = [bool]$KeepTempDirs
        steps = $steps
    }

    $outParent = Split-Path -Path $OutReport -Parent
    if ($outParent -and -not (Test-Path -LiteralPath $outParent)) {
        New-Item -ItemType Directory -Path $outParent -Force | Out-Null
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutReport -Encoding UTF8
    Write-Host "Canary rehearsal PASSED. Report written to: $OutReport"
    $report | ConvertTo-Json -Depth 8
}
finally {
    if (-not $KeepTempDirs) {
        Remove-Item -LiteralPath $canaryDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $restoreDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
