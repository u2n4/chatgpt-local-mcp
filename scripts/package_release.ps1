#Requires -Version 7
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ExePath,

    [Parameter(Mandatory)]
    [string]$Version,

    [string]$OutDir
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Normalize-PathString {
    param([Parameter(Mandatory)][string]$FullPath)
    $root = [System.IO.Path]::GetPathRoot($FullPath)
    if ($FullPath.Length -gt $root.Length) {
        return $FullPath.TrimEnd('\', '/')
    }
    return $FullPath
}

function Resolve-FromPsLocation {
    param(
        [Parameter(Mandatory)][string]$PathValue,
        [Parameter(Mandatory)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($PathValue) -or $PathValue.IndexOf([char]0) -ge 0) {
        throw "Invalid $Label`: path cannot be empty."
    }
    $trimmed = $PathValue.Trim()
    if ($trimmed.StartsWith('~')) {
        throw "Refusing $Label starting with '~': $PathValue"
    }
    if ($trimmed -match '\A[\\/]{2}') {
        throw "Refusing $Label with UNC or device-path prefix ('\\'): $PathValue"
    }
    if ($trimmed -match '\A[A-Za-z]:(?![\\/])') {
        throw "Refusing drive-relative $Label '$PathValue'."
    }
    $psCwd = $ExecutionContext.SessionState.Path.CurrentFileSystemLocation.ProviderPath
    if ([System.IO.Path]::IsPathFullyQualified($trimmed)) {
        $full = [System.IO.Path]::GetFullPath($trimmed)
    } elseif ($trimmed -match '\A[\\/]') {
        $driveRoot = [System.IO.Path]::GetPathRoot($psCwd)
        $full = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($driveRoot, $trimmed.TrimStart('\', '/')))
    } else {
        $full = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($psCwd, $trimmed))
    }
    return Normalize-PathString $full
}

function Assert-RegularFileNotReparse {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$Label
    )
    try {
        $attrs = [System.IO.File]::GetAttributes($FilePath)
    } catch {
        throw "$Label not found: $FilePath"
    }
    if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing $Label because it is a reparse point (symlink or junction): $FilePath"
    }
    if (($attrs -band [System.IO.FileAttributes]::Directory) -ne 0) {
        throw "Refusing $Label because it is a directory, not a regular file: $FilePath"
    }
}

function Assert-RepoPathSafe {
    param(
        [Parameter(Mandatory)][string]$PathToCheck,
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$RepoRootPrefix,
        [switch]$AllowMissingLeaf
    )
    $normalized = Normalize-PathString ([System.IO.Path]::GetFullPath($PathToCheck))
    if (-not $normalized.StartsWith($RepoRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing source path outside repository root: $normalized"
    }

    $current = $normalized
    $isLeaf = $true
    while (-not [string]::IsNullOrEmpty($current)) {
        if ($current.Equals($RepoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            $rootAttrs = [System.IO.File]::GetAttributes($current)
            if (($rootAttrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing repository root because it is a reparse point: $current"
            }
            break
        }
        try {
            $attrs = [System.IO.File]::GetAttributes($current)
            if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing source path because '$current' is a reparse point (symlink or junction): $normalized"
            }
        } catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
            if (-not $AllowMissingLeaf) {
                throw "Required path not found: $current"
            }
        }
        $isLeaf = $false
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current) {
            break
        }
        $current = $parent
    }
    return $normalized
}

$repoRoot = Normalize-PathString ([System.IO.Path]::GetFullPath([System.IO.Path]::GetDirectoryName($PSScriptRoot)))
$repoRootPrefix = $repoRoot.TrimEnd('\', '/') + '\'

if ([string]::IsNullOrEmpty($Version) -or -not [regex]::IsMatch($Version, '\A[0-9A-Za-z][0-9A-Za-z.+-]*\z')) {
    throw "Invalid -Version '$Version'. Use letters, digits, '.', '+' or '-' starting with a letter or digit."
}
# install.ps1 removes a leading 'v' before it builds the asset name, so the asset name never has one.
if ($Version.StartsWith('v', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Invalid -Version '$Version'. Give the version without a leading 'v' (the release tag is 'v' plus this version)."
}

$resolvedExe = Resolve-FromPsLocation -PathValue $ExePath -Label '-ExePath'
Assert-RegularFileNotReparse -FilePath $resolvedExe -Label '-ExePath'

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $resolvedOutDir = Normalize-PathString ([System.IO.Path]::GetFullPath((Join-Path $repoRoot (Join-Path 'release' $Version))))
} else {
    $resolvedOutDir = Resolve-FromPsLocation -PathValue $OutDir -Label '-OutDir'
}

$zipName = "edge-project-bridge-$Version-windows-x64.zip"
$zipPath = Join-Path $resolvedOutDir $zipName
$checksumsPath = Join-Path $resolvedOutDir 'SHA256SUMS.txt'
$releaseInstallScriptPath = Join-Path $resolvedOutDir 'install.ps1'

foreach ($outPath in @($zipPath, $checksumsPath, $releaseInstallScriptPath)) {
    if (Test-Path -LiteralPath $outPath) {
        throw "Refusing to overwrite existing release output: $outPath"
    }
}

# Secret and hidden filename rules from crates/bridge-core/src/files.rs (is_denied_secret_path + REMOTE_HIDDEN_NAMES)
$deniedExactNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($name in @(
    '.env', 'cookies', 'login data', 'trust tokens', 'web data', '.install-token',
    'id_rsa', 'id_ed25519', 'id_ecdsa', 'owner.token', 'edge.token',
    'tunnel-runtime.key', 'ipc-key.pem',
    '.git', '.hg', '.svn', '.ssh', '.aws', '.azure', '.gnupg', '.kube',
    '.codex', '.claude', '.agents', '.npmrc', '.pypirc', '.netrc',
    '.git-credentials', '.terraform', '.htpasswd', '.pgpass', '.my.cnf',
    'id_dsa', 'id_ecdsa_sk', 'id_ed25519_sk', 'kubeconfig',
    'auth.json', 'auth.yaml', 'auth.yml', 'auth.toml', 'api-token', 'api-unit-token',
    'cookies-journal', 'login data-journal', 'login data for account',
    'login data for account-journal', 'trust tokens-journal', 'web data-journal',
    'account web data', 'account web data-journal',
    '.edge-project-bridge', '.edge-bridge-journal',
    '.venv', '__pycache__', 'tests', 'state'
)) {
    [void]$deniedExactNames.Add($name)
}

$deniedSuffixes = @(
    '.env', '.pem', '.key', '.pfx', '.p12', '.kdbx', '.ppk', '.ovpn',
    '.token', '.secret', '.sqlite3', '.jks', '.keystore', '.pyc', '.pyo'
)

$deniedPrefixes = @(
    '.env.', 'secrets.', 'credentials.', '.edge-bridge-tmp-'
)

function Test-ForbiddenReleasePath {
    param([Parameter(Mandatory)][string]$RelativePath)

    $segments = $RelativePath -split '[/\\]'
    foreach ($segment in $segments) {
        if ([string]::IsNullOrEmpty($segment)) {
            continue
        }
        $low = $segment.ToLowerInvariant()
        if ($deniedExactNames.Contains($low)) {
            return "matches forbidden name '$segment'"
        }
        foreach ($prefix in $deniedPrefixes) {
            if ($low.StartsWith($prefix, [System.StringComparison]::Ordinal)) {
                return "matches forbidden prefix '$prefix'"
            }
        }
        foreach ($suffix in $deniedSuffixes) {
            if ($low.EndsWith($suffix, [System.StringComparison]::Ordinal)) {
                return "matches forbidden suffix '$suffix'"
            }
        }
    }
    return $null
}

$requiredRepoFiles = @(
    @{ Source = Join-Path $repoRoot 'scripts\install.ps1'; Dest = 'install.ps1' },
    @{ Source = Join-Path $repoRoot 'pyproject.toml'; Dest = 'runtime/pyproject.toml' },
    @{ Source = Join-Path $repoRoot 'uv.lock'; Dest = 'runtime/uv.lock' }
)

foreach ($item in $requiredRepoFiles) {
    $safeSrc = Assert-RepoPathSafe -PathToCheck $item.Source -RepoRoot $repoRoot -RepoRootPrefix $repoRootPrefix
    Assert-RegularFileNotReparse -FilePath $safeSrc -Label 'Required release input'
    $item.Source = $safeSrc
}

$edgeBridgeDir = Assert-RepoPathSafe -PathToCheck (Join-Path $repoRoot 'edge_bridge') -RepoRoot $repoRoot -RepoRootPrefix $repoRootPrefix
$runnerPyPath = Assert-RepoPathSafe -PathToCheck (Join-Path $edgeBridgeDir 'runner.py') -RepoRoot $repoRoot -RepoRootPrefix $repoRootPrefix
Assert-RegularFileNotReparse -FilePath $runnerPyPath -Label 'Required runtime file'

$optionalRepoFiles = @(
    @{ Source = Join-Path $repoRoot 'LICENSE'; Dest = 'LICENSE' },
    @{ Source = Join-Path $repoRoot 'COPYING'; Dest = 'COPYING' },
    @{ Source = Join-Path $repoRoot 'README.md'; Dest = 'README.md' },
    @{ Source = Join-Path $repoRoot 'SECURITY_BOUNDARIES.md'; Dest = 'SECURITY_BOUNDARIES.md' },
    @{ Source = Join-Path $repoRoot 'docs\INSTALL.md'; Dest = 'docs/INSTALL.md' },
    @{ Source = Join-Path $repoRoot 'docs\REMOTE_EXECUTOR.md'; Dest = 'docs/REMOTE_EXECUTOR.md' },
    @{ Source = Join-Path $repoRoot 'docs\PRO_AGENT_MAILBOX.md'; Dest = 'docs/PRO_AGENT_MAILBOX.md' },
    @{ Source = Join-Path $repoRoot 'docs\KNOWN_LIMITATIONS.md'; Dest = 'docs/KNOWN_LIMITATIONS.md' }
)

$entries = [System.Collections.Generic.List[hashtable]]::new()
$entries.Add(@{ Source = $resolvedExe; Dest = 'edge-bridge.exe' })

foreach ($item in $requiredRepoFiles) {
    $entries.Add($item)
}

# Walk edge_bridge explicitly so directory junctions/symlinks are detected and refused rather than skipped
$dirStack = [System.Collections.Generic.Stack[string]]::new()
$dirStack.Push($edgeBridgeDir)
while ($dirStack.Count -gt 0) {
    $currentDir = $dirStack.Pop()
    $childEntries = [System.IO.Directory]::GetFileSystemEntries($currentDir)
    [System.Array]::Sort($childEntries, [System.StringComparer]::Ordinal)
    foreach ($childPath in $childEntries) {
        $safeChild = Assert-RepoPathSafe -PathToCheck $childPath -RepoRoot $repoRoot -RepoRootPrefix $repoRootPrefix
        $attrs = [System.IO.File]::GetAttributes($safeChild)
        $leafName = [System.IO.Path]::GetFileName($safeChild)
        if (($attrs -band [System.IO.FileAttributes]::Directory) -ne 0) {
            if ($leafName.Equals('__pycache__', [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
            $dirStack.Push($safeChild)
        } else {
            $ext = [System.IO.Path]::GetExtension($safeChild)
            if ($ext.Equals('.pyc', [System.StringComparison]::OrdinalIgnoreCase) -or
                $ext.Equals('.pyo', [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
            if (-not $ext.Equals('.py', [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
            $relFromEdgeBridge = [System.IO.Path]::GetRelativePath($edgeBridgeDir, $safeChild).Replace('\', '/')
            $entries.Add(@{
                Source = $safeChild
                Dest   = "runtime/edge_bridge/$relFromEdgeBridge"
            })
        }
    }
}

foreach ($item in $optionalRepoFiles) {
    $safeOpt = Assert-RepoPathSafe -PathToCheck $item.Source -RepoRoot $repoRoot -RepoRootPrefix $repoRootPrefix -AllowMissingLeaf
    if (Test-Path -LiteralPath $safeOpt -PathType Leaf) {
        Assert-RegularFileNotReparse -FilePath $safeOpt -Label 'Optional release input'
        $entries.Add(@{ Source = $safeOpt; Dest = $item.Dest })
    }
}

# Validate every entry against forbidden secret/test/cache/state names before packaging
foreach ($entry in $entries) {
    $reason = Test-ForbiddenReleasePath -RelativePath $entry.Dest
    if ($null -ne $reason) {
        throw "Refusing to package '$($entry.Dest)': $reason."
    }
    $sourceLeaf = [System.IO.Path]::GetFileName($entry.Source)
    $sourceReason = Test-ForbiddenReleasePath -RelativePath $sourceLeaf
    if ($null -ne $sourceReason) {
        throw "Refusing to package source '$($entry.Source)': $sourceReason."
    }
}

# Reproducible ordinal sort and fixed UTC timestamp (1980-01-01T00:00:00Z)
$entries.Sort([System.Comparison[hashtable]]{
    param($a, $b)
    return [string]::Compare($a.Dest, $b.Dest, [System.StringComparison]::Ordinal)
})
$fixedTimestamp = [System.DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [System.TimeSpan]::Zero)

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("epb-pkg-" + [guid]::NewGuid().ToString('N'))
$tempZip = Join-Path $tempDir $zipName

try {
    [void][System.IO.Directory]::CreateDirectory($tempDir)

    $zipStream = [System.IO.File]::Open($tempZip, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new($zipStream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($entry in $entries) {
                $zipEntry = $archive.CreateEntry($entry.Dest, [System.IO.Compression.CompressionLevel]::Optimal)
                $zipEntry.LastWriteTime = $fixedTimestamp
                $inStream = [System.IO.File]::OpenRead($entry.Source)
                try {
                    $outStream = $zipEntry.Open()
                    try {
                        $inStream.CopyTo($outStream)
                    } finally {
                        $outStream.Dispose()
                    }
                } finally {
                    $inStream.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $zipStream.Dispose()
    }

    if (-not (Test-Path -LiteralPath $resolvedOutDir)) {
        [void][System.IO.Directory]::CreateDirectory($resolvedOutDir)
    }

    foreach ($outPath in @($zipPath, $checksumsPath, $releaseInstallScriptPath)) {
        if (Test-Path -LiteralPath $outPath) {
            throw "Refusing to overwrite existing release output: $outPath"
        }
    }

    $installSource = Assert-RepoPathSafe -PathToCheck (Join-Path $repoRoot 'scripts\install.ps1') -RepoRoot $repoRoot -RepoRootPrefix $repoRootPrefix
    Assert-RegularFileNotReparse -FilePath $installSource -Label 'Release install.ps1'

    Copy-Item -LiteralPath $tempZip -Destination $zipPath
    Copy-Item -LiteralPath $installSource -Destination $releaseInstallScriptPath

    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $installHash = (Get-FileHash -LiteralPath $releaseInstallScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $checksumLines = @(
        "$zipHash  $zipName"
        "$installHash  install.ps1"
    )
    $checksumBytes = $utf8NoBom.GetBytes(($checksumLines -join "`n") + "`n")
    $csStream = [System.IO.File]::Open($checksumsPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $csStream.Write($checksumBytes, 0, $checksumBytes.Length)
    } finally {
        $csStream.Dispose()
    }

    Write-Output "Created release archive: $zipPath"
    Write-Output "SHA256 ($zipName): $zipHash"
    Write-Output "SHA256 (install.ps1): $installHash"
    Write-Output "Checksums file: $checksumsPath"
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
