[CmdletBinding()]
param(
    [string]$StateDir = $(Join-Path $env:LOCALAPPDATA "EdgeProjectBridge"),
    [string]$ReleasesDir = "",
    [string]$PackageRoot = $(Split-Path -Parent $PSScriptRoot),
    [string]$ReleaseId = "",
    [switch]$RestoreDb,
    [switch]$RestartBroker,
    [string]$PythonExe = ""
)

$ErrorActionPreference = "Stop"

# Ensure Windows PowerShell 5.1 resolves its own system modules even when spawned from PowerShell 7.x (pwsh)
if ($PSHome) {
    $psHomeModules = Join-Path $PSHome "Modules"
    $existingModulePaths = @()
    if (-not [string]::IsNullOrWhiteSpace($env:PSModulePath)) {
        $existingModulePaths = $env:PSModulePath -split [IO.Path]::PathSeparator | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and
            (-not ($PSVersionTable.PSEdition -eq "Desktop" -and $_ -match '[\\/]PowerShell[\\/]7'))
        }
    }
    $env:PSModulePath = (@($psHomeModules) + $existingModulePaths | Select-Object -Unique) -join [IO.Path]::PathSeparator
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "RELEASE_HASH_MISMATCH: File not found for SHA-256 verification: $LiteralPath"
    }
    $fullPath = (Resolve-Path -LiteralPath $LiteralPath).ProviderPath
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::Open(
            $fullPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )
        try {
            $hashBytes = $sha256.ComputeHash($stream)
        } finally {
            $stream.Dispose()
        }
        return [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Assert-NoReparsePoint {
    param([string]$TargetPath)
    if ([string]::IsNullOrWhiteSpace($TargetPath)) {
        throw "Path cannot be empty."
    }
    $cur = $TargetPath
    while (-not [string]::IsNullOrWhiteSpace($cur)) {
        if (Test-Path -LiteralPath $cur) {
            $item = Get-Item -LiteralPath $cur -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "RELEASE_PATH_UNSAFE: Reparse point detected at $cur"
            }
        }
        $parent = Split-Path -Parent $cur
        if ($parent -eq $cur) { break }
        $cur = $parent
    }
}

function Resolve-PythonExe {
    param([string]$Root, [string]$Explicit)
    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        if (-not (Test-Path -LiteralPath $Explicit)) {
            throw "Python executable not found at $Explicit"
        }
        return (Resolve-Path -LiteralPath $Explicit).Path
    }
    $venvPy = Join-Path (Join-Path $Root ".venv") "Scripts\python.exe"
    if (Test-Path -LiteralPath $venvPy) {
        return $venvPy
    }
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return $cmd.Source
    }
    throw "Unable to locate Python executable."
}

$StateDirAbs = [IO.Path]::GetFullPath($StateDir)
$PackageRootAbs = [IO.Path]::GetFullPath($PackageRoot)
if ([string]::IsNullOrWhiteSpace($ReleasesDir)) {
    $stateParent = Split-Path -Parent $StateDirAbs
    $stateName = Split-Path -Leaf $StateDirAbs
    $ReleasesDirAbs = Join-Path $stateParent ($stateName + "-releases")
} else {
    $ReleasesDirAbs = [IO.Path]::GetFullPath($ReleasesDir)
}

Assert-NoReparsePoint -TargetPath $StateDirAbs
Assert-NoReparsePoint -TargetPath $ReleasesDirAbs
Assert-NoReparsePoint -TargetPath $PackageRootAbs

if (-not (Test-Path -LiteralPath $ReleasesDirAbs)) {
    throw "RELEASE_NOT_FOUND: Releases directory does not exist: $ReleasesDirAbs"
}

$SnapshotsRoot = Join-Path $ReleasesDirAbs "snapshots"
if (-not (Test-Path -LiteralPath $SnapshotsRoot)) {
    throw "RELEASE_NOT_FOUND: Snapshots directory does not exist: $SnapshotsRoot"
}

$PyExe = Resolve-PythonExe -Root $PackageRootAbs -Explicit $PythonExe

# 1. Resolve candidate release snapshot(s)
$PointersPath = Join-Path $ReleasesDirAbs "pointers.json"
$Candidates = New-Object System.Collections.Generic.List[string]
$PointersObj = $null
if (Test-Path -LiteralPath $PointersPath) {
    try {
        $PointersObj = Get-Content -LiteralPath $PointersPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        $PointersObj = $null
    }
}
if (-not [string]::IsNullOrWhiteSpace($ReleaseId)) {
    $Candidates.Add($ReleaseId)
} else {
    if ($null -ne $PointersObj) {
        foreach ($prop in @("last_known_good", "previous", "current")) {
            $val = $PointersObj.$prop
            if ($val -is [string] -and -not [string]::IsNullOrWhiteSpace($val) -and -not $Candidates.Contains($val)) {
                $Candidates.Add($val)
            }
        }
    }
    $dirs = Get-ChildItem -LiteralPath $SnapshotsRoot -Directory | Sort-Object Name -Descending
    foreach ($d in $dirs) {
        if (-not $Candidates.Contains($d.Name)) {
            $Candidates.Add($d.Name)
        }
    }
}

function Test-SnapshotIntegrity {
    param([string]$SnapDir, [switch]$RequireVerifiedGood)
    $mPath = Join-Path $SnapDir "manifest.json"
    if (-not (Test-Path -LiteralPath $mPath)) {
        return $null
    }
    try {
        $manifest = Get-Content -LiteralPath $mPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        return $null
    }
    if ($RequireVerifiedGood -and -not [bool]$manifest.verified_good) {
        return $null
    }
    $codeDir = Join-Path $SnapDir "code"
    if (-not (Test-Path -LiteralPath $codeDir)) {
        return $null
    }
    foreach ($entry in $manifest.files) {
        $rel = [string]$entry.path
        if ([string]::IsNullOrWhiteSpace($rel) -or $rel.Contains("..") -or $rel.Contains("\") -or $rel.Contains(":") -or $rel.StartsWith("/") -or [IO.Path]::IsPathRooted($rel)) {
            throw "RELEASE_CORRUPT: Unsafe relative path in manifest: $rel"
        }
        $relWin = $rel.Replace("/", "\")
        $fPath = Join-Path $codeDir $relWin
        if (-not (Test-Path -LiteralPath $fPath)) {
            throw "RELEASE_HASH_MISMATCH: Missing snapshot file $rel"
        }
        $item = Get-Item -LiteralPath $fPath
        if ($item.Length -ne [int64]$entry.size) {
            throw "RELEASE_HASH_MISMATCH: Size mismatch for $rel"
        }
        $actualHash = Get-Sha256Hex -LiteralPath $fPath
        if ($actualHash -ne ([string]$entry.sha256).ToLowerInvariant()) {
            throw "RELEASE_HASH_MISMATCH: SHA-256 mismatch for $rel"
        }
    }
    if ($null -ne $manifest.db_backup) {
        $bakFile = Join-Path $SnapDir "state-backup.sqlite3"
        if (-not (Test-Path -LiteralPath $bakFile)) {
            throw "RELEASE_CORRUPT: Missing state-backup.sqlite3 in $SnapDir"
        }
        $bakHash = Get-Sha256Hex -LiteralPath $bakFile
        if ($bakHash -ne ([string]$manifest.db_backup.sha256).ToLowerInvariant()) {
            throw "RELEASE_HASH_MISMATCH: SHA-256 mismatch for state-backup.sqlite3"
        }
    }
    return $manifest
}

$SelectedId = $null
$SelectedManifest = $null
$SelectedSnapDir = $null
$requireGood = [string]::IsNullOrWhiteSpace($ReleaseId)

foreach ($cid in $Candidates) {
    $cDir = Join-Path $SnapshotsRoot $cid
    if (-not (Test-Path -LiteralPath $cDir)) { continue }
    $m = Test-SnapshotIntegrity -SnapDir $cDir -RequireVerifiedGood:$requireGood
    if ($null -ne $m) {
        $SelectedId = $cid
        $SelectedManifest = $m
        $SelectedSnapDir = $cDir
        break
    }
}

if ($null -eq $SelectedManifest) {
    throw "RELEASE_NOT_FOUND: No verified release snapshot found under $SnapshotsRoot"
}

# 2. Best-effort stop broker bound strictly to $StateDirAbs
$stoppedBrokers = 0
$BrokerJsonPath = Join-Path $StateDirAbs "broker.json"
if (Test-Path -LiteralPath $BrokerJsonPath) {
    try {
        $prevPref = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        Push-Location $PackageRootAbs
        try {
            & $PyExe -m edge_bridge.cli --state-dir $StateDirAbs stop 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $stoppedBrokers += 1
            }
        } finally {
            Pop-Location
            $ErrorActionPreference = $prevPref
        }
    } catch {
    }
}
$DefaultStateDirAbs = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "EdgeProjectBridge"))
$IsDefaultStateDir = [string]::Equals($StateDirAbs, $DefaultStateDirAbs, [System.StringComparison]::OrdinalIgnoreCase)
try {
    $procs = Get-CimInstance Win32_Process | Where-Object {
        $cmd = $_.CommandLine
        if (-not $cmd -or -not ($cmd -like "*edge_bridge.cli*") -or -not ($cmd -like "*start*")) {
            return $false
        }
        if ($cmd.Contains($StateDirAbs)) {
            return $true
        }
        if ($IsDefaultStateDir -and -not ($cmd -like "*--state-dir*")) {
            return $true
        }
        return $false
    }
    foreach ($p in $procs) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        $stoppedBrokers += 1
    }
} catch {
}

# 3. Restore code files into $PackageRootAbs (never touching .venv, .git, or credentials)
$ExpectedRelSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $SelectedManifest.files) {
    [void]$ExpectedRelSet.Add(([string]$entry.path).Replace("\", "/"))
}

foreach ($sub in @("edge_bridge", "scripts")) {
    $subPath = Join-Path $PackageRootAbs $sub
    if (Test-Path -LiteralPath $subPath) {
        $pyCaches = Get-ChildItem -LiteralPath $subPath -Directory -Recurse -Filter "__pycache__" -ErrorAction SilentlyContinue
        foreach ($pc in $pyCaches) {
            Remove-Item -LiteralPath $pc.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
        $existingFiles = Get-ChildItem -LiteralPath $subPath -File -Recurse -ErrorAction SilentlyContinue
        foreach ($ef in $existingFiles) {
            $relPosix = $ef.FullName.Substring($PackageRootAbs.Length).TrimStart("\", "/").Replace("\", "/")
            if (-not $ExpectedRelSet.Contains($relPosix)) {
                Remove-Item -LiteralPath $ef.FullName -Force
            }
        }
    }
}

$CodeDir = Join-Path $SelectedSnapDir "code"
foreach ($entry in $SelectedManifest.files) {
    $relWin = ([string]$entry.path).Replace("/", "\")
    $srcFile = Join-Path $CodeDir $relWin
    $dstFile = Join-Path $PackageRootAbs $relWin
    $dstParent = Split-Path -Parent $dstFile
    if (-not (Test-Path -LiteralPath $dstParent)) {
        New-Item -ItemType Directory -Path $dstParent -Force | Out-Null
    }
    Copy-Item -LiteralPath $srcFile -Destination $dstFile -Force
}

# 4. Check live SQLite DB integrity & schema compatibility (never touch tokens/certs)
$LiveDb = Join-Path $StateDirAbs "state.sqlite3"
$DbRestored = $false
$DbStatus = "preserved"
$TargetSchema = if ($null -ne $SelectedManifest.schema_version) { [int]$SelectedManifest.schema_version } else { -1 }

$NeedDbRestore = [bool]$RestoreDb
if (-not $NeedDbRestore) {
    if (-not (Test-Path -LiteralPath $LiveDb)) {
        $NeedDbRestore = $true
        $DbStatus = "missing"
    } else {
        $checkScript = "import sqlite3, sys`ntry:`n    c=sqlite3.connect(sys.argv[1], timeout=5)`n    r=c.execute('PRAGMA integrity_check').fetchone()`n    row=c.execute('SELECT schema_version FROM instance WHERE slot=1').fetchone()`n    t=int(sys.argv[2])`n    ok = bool(r and str(r[0]).lower()=='ok' and row is not None and (t < 0 or int(row[0]) <= t))`n    c.close()`n    sys.exit(0 if ok else 2)`nexcept Exception:`n    sys.exit(3)"
        $prevPref = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & $PyExe -c $checkScript $LiveDb "$TargetSchema" 2>$null | Out-Null
        $dbCheckCode = $LASTEXITCODE
        $ErrorActionPreference = $prevPref
        if ($dbCheckCode -ne 0) {
            $NeedDbRestore = $true
            $DbStatus = "corrupt_or_incompatible"
        }
    }
}

if ($NeedDbRestore -and ($null -ne $SelectedManifest.db_backup)) {
    $BackupSrc = Join-Path $SelectedSnapDir "state-backup.sqlite3"
    $QuarantineDir = Join-Path $ReleasesDirAbs "quarantine"
    if (-not (Test-Path -LiteralPath $QuarantineDir)) {
        New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
    }
    $Stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    foreach ($suffix in @("", "-wal", "-shm")) {
        $cand = $LiveDb + $suffix
        if (Test-Path -LiteralPath $cand) {
            $qDest = Join-Path $QuarantineDir ("state-" + $Stamp + ".sqlite3" + $suffix)
            Move-Item -LiteralPath $cand -Destination $qDest -Force
        }
    }
    $restoreScript = "import sqlite3, sys; s=sqlite3.connect(sys.argv[1], timeout=5); d=sqlite3.connect(sys.argv[2], timeout=5); s.backup(d); r=d.execute('PRAGMA integrity_check').fetchone(); assert r and str(r[0]).lower()=='ok'; s.close(); d.close()"
    & $PyExe -c $restoreScript $BackupSrc $LiveDb
    if ($LASTEXITCODE -ne 0) {
        throw "RELEASE_CORRUPT: Failed to restore SQLite backup."
    }
    $DbRestored = $true
    $DbStatus = "restored_from_snapshot"
}

# 5. Atomically update pointers.json (BOM-less UTF-8)
$ExistingLastGood = if ($null -ne $PointersObj) { $PointersObj.last_known_good } else { $null }
$NewLastGood = if ([bool]$SelectedManifest.verified_good) { $SelectedId } else { $ExistingLastGood }
$PrevPointer = if ($null -ne $PointersObj -and $PointersObj.current -ne $SelectedId) {
    $PointersObj.current
} elseif ($null -ne $PointersObj) {
    $PointersObj.previous
} else {
    $null
}
$NewPointers = [ordered]@{
    current         = $SelectedId
    previous        = $PrevPointer
    last_known_good = $NewLastGood
    history         = if ($null -ne $PointersObj -and $null -ne $PointersObj.history) { @($PointersObj.history) } else { @() }
}
$TmpPtr = Join-Path $ReleasesDirAbs (".pointers." + [guid]::NewGuid().ToString("N").Substring(0, 8) + ".tmp")
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($TmpPtr, ($NewPointers | ConvertTo-Json -Depth 8), $Utf8NoBom)
Move-Item -LiteralPath $TmpPtr -Destination $PointersPath -Force

# 6. Post-recovery verification
Push-Location $PackageRootAbs
try {
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $PyExe -m compileall -q edge_bridge scripts 2>$null
    $compileCode = $LASTEXITCODE
    $ErrorActionPreference = $prevPref
    if ($compileCode -ne 0) {
        throw "Post-recovery compileall failed."
    }

    $discoverReq = '{"jsonrpc":"2.0","id":"openai-mcp-discover","method":"server/discover"}'
    $initReq = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"recover_ps1","version":"1.0"}}}'
    $notifReq = '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
    $listReq = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
    $infoReq = '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bridge_info","arguments":{}}}'
    $mcpInput = "$discoverReq`n$initReq`n$notifReq`n$listReq`n$infoReq"

    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $mcpOut = $mcpInput | & $PyExe -m edge_bridge.cli --state-dir $StateDirAbs mcp --principal edge 2>$null
    $mcpCode = $LASTEXITCODE
    $ErrorActionPreference = $prevPref
    if ($mcpCode -ne 0) {
        throw "Post-recovery MCP stdio handshake failed."
    }

    $toolCount = 0
    $discover32601 = $false
    foreach ($line in $mcpOut) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $msg = $line | ConvertFrom-Json
        if ($msg.id -eq "openai-mcp-discover" -and $null -ne $msg.error -and $msg.error.code -eq -32601) {
            $discover32601 = $true
        }
        if ($msg.id -eq 2 -and $null -ne $msg.result -and $null -ne $msg.result.tools) {
            $toolCount = @($msg.result.tools).Count
        }
    }
    if (-not $discover32601 -or $toolCount -ne 33) {
        throw "Post-recovery MCP verification failed (discover32601=$discover32601, toolCount=$toolCount)."
    }

    $brokerPid = $null
    $doctorReport = $null
    if ($RestartBroker) {
        $brokerProc = Start-Process -FilePath $PyExe -ArgumentList @("-m", "edge_bridge.cli", "--state-dir", $StateDirAbs, "start", "--port", "0") -WorkingDirectory $PackageRootAbs -WindowStyle Hidden -PassThru
        $brokerPid = $brokerProc.Id
        $brokerJson = Join-Path $StateDirAbs "broker.json"
        $deadline = (Get-Date).AddSeconds(15)
        while (-not (Test-Path -LiteralPath $brokerJson) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $brokerJson)) {
            throw "Restarted broker did not publish broker.json within 15s."
        }
        $docRaw = & $PyExe -m edge_bridge.cli --state-dir $StateDirAbs doctor --json --probe-mcp
        if ($LASTEXITCODE -ne 0) {
            throw "Post-recovery doctor --probe-mcp failed."
        }
        $doctorReport = $docRaw | ConvertFrom-Json
    }

    $summary = [ordered]@{
        status            = "RECOVERED"
        release_id        = $SelectedId
        bridge_version    = $SelectedManifest.bridge_version
        state_dir         = $StateDirAbs
        releases_dir      = $ReleasesDirAbs
        package_root      = $PackageRootAbs
        stopped_brokers   = $stoppedBrokers
        db_restored       = $DbRestored
        db_status         = $DbStatus
        discover_32601    = $discover32601
        tool_count        = $toolCount
        restarted_pid     = $brokerPid
        doctor_status     = if ($null -ne $doctorReport) { $doctorReport.diagnostics.overall_status } else { $null }
    }
    Write-Output ($summary | ConvertTo-Json -Depth 8)
    exit 0
} finally {
    Pop-Location
}
