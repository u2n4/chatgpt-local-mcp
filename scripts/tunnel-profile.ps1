[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TunnelClient,
    [Parameter(Mandatory)][ValidatePattern('^tunnel_[a-zA-Z0-9_-]+$')][string]$TunnelId,
    [Parameter(Mandatory)][string]$ProfileDir,
    [string]$StateDir = (Join-Path $env:LOCALAPPDATA 'EdgeProjectBridge')
)

$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
$client = (Resolve-Path -LiteralPath $TunnelClient).Path
$uv = (Get-Command uv.exe -CommandType Application | Select-Object -First 1).Source
$state = [IO.Path]::GetFullPath($StateDir)
$destination = [IO.Path]::GetFullPath($ProfileDir)
if (-not (Test-Path -LiteralPath $state -PathType Container)) {
    throw 'Initialize the protected state directory first with scripts/install.ps1.'
}
if (-not (Test-Path -LiteralPath (Join-Path $project '.venv/Scripts/python.exe') -PathType Leaf)) {
    throw 'Install the pinned environment first with scripts/install.ps1.'
}

function Format-CommandPath([string]$Path) {
    $SafePath = $Path.Replace('\', '/')
    if ($SafePath.Contains("'") -or $SafePath.Contains('"')) {
        throw 'Quoted paths are unsupported by this template.'
    }
    return "'$SafePath'"
}

$ProjectPath = Format-CommandPath $project
$UvExecutable = Format-CommandPath $uv
$StatePath = Format-CommandPath $state
$SecretReference = 'file:' + (Join-Path $state 'tunnel-runtime.key').Replace('\', '/')
$command = "$UvExecutable run --directory $ProjectPath --locked --no-sync python -m edge_bridge.cli --state-dir $StatePath mcp --principal edge"
$initArgs = @(
    'init', '--sample', 'sample_mcp_stdio_local', '--profile', 'edge-project-bridge'
    '--profile-dir', $destination, '--health-listen-addr', '127.0.0.1:0'
    '--tunnel-id', $TunnelId, '--control-plane-api-key-ref', $SecretReference
    '--mcp-command', $command
)
& $client @initArgs
if ($LASTEXITCODE -ne 0) { throw 'Tunnel profile generation failed.' }
Write-Output 'Profile generated locally. No tunnel or inference was started.'

