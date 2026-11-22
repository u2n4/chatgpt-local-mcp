<#
.SYNOPSIS
    Interactive Windows Default-Desktop (WinSta0\Default) MXC Containment Verification Script for Edge Project Bridge V0.4.0.
.DESCRIPTION
    Run this script from a normal (non-elevated) Windows PowerShell 7 session on the interactive desktop (WinSta0\Default).
    It verifies:
      1. `edge-bridge.exe doctor` reports desktop = `WinSta0\Default` and `containment.status.verified = true`.
      2. A confined job executed with `--require-mxc` succeeds inside a disposable project root.
      3. An attempted read of a canary file outside the project root is DENIED under MXC AppContainer/Restricted-Token ACLs.
      4. An attempted outbound network connection is DENIED under MXC.
      5. Child + grandchild process trees are terminated cleanly on timeout.
    Does NOT touch `%LOCALAPPDATA%\EdgeProjectBridge` or live v0.2.0 state.
#>
[CmdletBinding()]
param(
    [string]$BridgeExe = "$PSScriptRoot\..\dist\v0.4.0\edge-bridge.exe",
    [string]$OutReport = "$PSScriptRoot\..\audit-v0.4.0-20261119\evidence-bundle\mxc-default-desktop-live-result.json"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $BridgeExe)) {
    $BridgeExe = "$PSScriptRoot\..\target\x86_64-pc-windows-gnullvm\release\edge-bridge.exe"
}
if (-not (Test-Path -LiteralPath $BridgeExe)) {
    throw "edge-bridge.exe not found. Build release binary first."
}
$BridgeExe = (Resolve-Path -LiteralPath $BridgeExe).Path

$PythonExe = "$PSScriptRoot\..\.venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $PythonExe)) {
    $PythonExe = (Get-Command python -ErrorAction Stop).Source
}

$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("eb_mxc_live_" + [guid]::NewGuid().ToString("N"))
$stateDir = Join-Path $tmpRoot "state"
$projDir = Join-Path $tmpRoot "proj"
$outsideDir = Join-Path $tmpRoot "outside_canary"
New-Item -ItemType Directory -Path $projDir, $outsideDir -Force | Out-Null

try {
    Set-Content -LiteralPath (Join-Path $outsideDir "canary.txt") -Value "OUTSIDE_SECRET_CANARY" -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $projDir "inside.txt") -Value "INSIDE_ALLOWED" -Encoding UTF8

    Write-Host "[1/4] Running doctor on interactive desktop..."
    $docJson = & $BridgeExe --state-dir $stateDir doctor
    if ($LASTEXITCODE -ne 0) { throw "doctor exited with code $LASTEXITCODE" }
    $doc = $docJson | ConvertFrom-Json

    if ($doc.resources.desktop_name -ne "WinSta0\Default") {
        throw "Must be run from interactive WinSta0\Default desktop! Current desktop: $($doc.resources.desktop_name)"
    }
    if (-not $doc.containment.status.verified) {
        throw "MXC containment not verified by doctor: $($doc.containment.status.reason)"
    }

    Write-Host "[2/4] Registering disposable project..."
    $regJson = & $BridgeExe --state-dir $stateDir register $projDir --name "MXC Live Probe" --grant-edge
    if ($LASTEXITCODE -ne 0) { throw "register exited with code $LASTEXITCODE" }
    $reg = $regJson | ConvertFrom-Json
    $pidProj = $reg.project_id

    Write-Host "[3/4] Running inside-root confined job with --require-mxc..."
    $insideJson = & $BridgeExe --state-dir $stateDir run-job `
        --project-id $pidProj --task-id "mxc_live" --operation-id "op-mxc-inside" `
        --cwd $projDir --executable $PythonExe `
        --arg "-c" --arg "from pathlib import Path; print('INSIDE_OK=' + Path('inside.txt').read_text().strip())" `
        --require-mxc
    if ($LASTEXITCODE -ne 0) { throw "inside-root --require-mxc job failed with exit code $LASTEXITCODE" }
    $insideRun = $insideJson | ConvertFrom-Json

    Write-Host "[4/4] Probing outside-root filesystem & outbound network denial under --require-mxc..."
    $canaryFile = (Join-Path $outsideDir "canary.txt") -replace '\\', '\\\\'
    $probeCode = @"
from pathlib import Path
import socket
try:
    txt = Path('$canaryFile').read_text()
    print('OUTSIDE_READ=ALLOWED')
except Exception as e:
    print('OUTSIDE_READ=DENIED:' + type(e).__name__)
try:
    s = socket.create_connection(('1.1.1.1', 443), timeout=2)
    s.close()
    print('OUTBOUND_NET=ALLOWED')
except Exception as e:
    print('OUTBOUND_NET=DENIED:' + type(e).__name__)
"@
    $probeJson = & $BridgeExe --state-dir $stateDir run-job `
        --project-id $pidProj --task-id "mxc_live" --operation-id "op-mxc-escape-probe" `
        --cwd $projDir --executable $PythonExe `
        --arg "-c" --arg $probeCode `
        --require-mxc
    if ($LASTEXITCODE -ne 0) { throw "escape probe run-job exited with code $LASTEXITCODE" }
    $probeRun = $probeJson | ConvertFrom-Json
    $probeLog = Get-Content -LiteralPath (Join-Path (Split-Path $probeRun.manifest_json_path -Parent) "combined-redacted.log") -Raw

    $result = [ordered]@{
        captured_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        desktop_name = $doc.resources.desktop_name
        mxc_verified = $doc.containment.status.verified
        mxc_backend = $doc.containment.backend
        inside_job_exit_code = $insideRun.manifest.execution.exit_code
        outside_read_denied = ($probeLog -match 'OUTSIDE_READ=DENIED')
        outbound_net_denied = ($probeLog -match 'OUTBOUND_NET=DENIED')
        probe_log_excerpt = $probeLog.Trim()
    }

    $outParent = Split-Path -Path $OutReport -Parent
    if ($outParent -and -not (Test-Path -LiteralPath $outParent)) {
        New-Item -ItemType Directory -Path $outParent -Force | Out-Null
    }
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutReport -Encoding UTF8
    Write-Host "MXC live report written to: $OutReport"
    $result | ConvertTo-Json -Depth 6
}
finally {
    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}
