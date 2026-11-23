#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutFile,

    [Parameter()]
    [ValidateRange(5, 60)]
    [int]$TimeoutSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$probeScript = Join-Path $PSScriptRoot 'probe_work_sandbox.py'
if (-not (Test-Path -LiteralPath $probeScript -PathType Leaf)) {
    throw "Probe helper script not found: $probeScript"
}

$venvPython = Join-Path $repoRoot '.venv\Scripts\python.exe'
$probeArgs = @($probeScript, '--timeout', "$TimeoutSeconds")
if ($PSBoundParameters.ContainsKey('OutFile') -and -not [string]::IsNullOrWhiteSpace($OutFile)) {
    $probeArgs += @('--out', $OutFile)
}

if (Test-Path -LiteralPath $venvPython -PathType Leaf) {
    & $venvPython @probeArgs
    exit $LASTEXITCODE
}

$uvCmd = Get-Command uv -ErrorAction SilentlyContinue
if ($null -ne $uvCmd) {
    Push-Location $repoRoot
    try {
        & $uvCmd.Source run --locked --no-sync python @probeArgs
        exit $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
}

throw "Neither repo .venv\Scripts\python.exe nor 'uv' is available."
