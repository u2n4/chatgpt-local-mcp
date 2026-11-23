#Requires -Version 7
[CmdletBinding()]
param(
    [string]$InstallDir,
    [string]$ProjectPath,
    [string]$ZipPath,
    [string]$Version,
    [string]$Repo = 'u2n4/chatgpt-local-mcp',
    [string]$Sha256
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Pinned executable hashes traced to edge_bridge/runner.py and crates/bridge-platform/src/windows.rs
$PINNED_CODEX_VERSION = '0.171.0'
$PINNED_CODEX_SHA256 = 'cefea4ffee1fff04983a99c0dda99944d8b380e891e740a28b32f4b815a6e0b7'
$PINNED_POWERSHELL_SHA256 = 'e94166ed9f376559c1359bafb08bc49e463a494c330f67644ec1d9f1ffeb5ee5'

$MAX_ZIP_ENTRIES = 400
$MAX_ZIP_UNCOMPRESSED_BYTES = [int64](300 * 1024 * 1024)
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Write-Utf8NoBom([string]$Path, [string]$Content) {
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

# Runs uv without the settings of the calling shell that would point it at another project or environment.
function Invoke-Uv([string]$UvPath, [string[]]$UvArgs) {
    $saved = @{}
    foreach ($name in @('UV_PROJECT', 'UV_PROJECT_ENVIRONMENT', 'UV_WORKING_DIRECTORY', 'UV_CONFIG_FILE', 'VIRTUAL_ENV')) {
        if (Test-Path -LiteralPath "Env:$name") {
            $saved[$name] = (Get-Item -LiteralPath "Env:$name").Value
            Remove-Item -LiteralPath "Env:$name"
        }
    }
    try {
        & $UvPath --no-config @UvArgs
    } finally {
        foreach ($name in $saved.Keys) { Set-Item -LiteralPath "Env:$name" -Value $saved[$name] }
    }
}

function Normalize-PathString([string]$FullPath) {
    $root = [System.IO.Path]::GetPathRoot($FullPath)
    if ($FullPath.Length -gt $root.Length) { return $FullPath.TrimEnd('\', '/') }
    return $FullPath
}

function Get-PathWithTrailingSeparator([string]$FullPath) {
    return $FullPath.TrimEnd('\', '/') + '\'
}

function Test-PathsEqual([string]$PathA, [string]$PathB) {
    return (Get-PathWithTrailingSeparator $PathA).Equals(
        (Get-PathWithTrailingSeparator $PathB), [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Test-IsDriveRoot([string]$FullPath) {
    return Test-PathsEqual $FullPath ([System.IO.Path]::GetPathRoot($FullPath))
}

function Assert-NoReparsePointInPath([string]$FullPath) {
    $current = $FullPath
    while (-not [string]::IsNullOrEmpty($current)) {
        try {
            $attrs = [System.IO.File]::GetAttributes($current)
            if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing path because '$current' is a reparse point (junction or symlink): $FullPath"
            }
        } catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
        }
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current) { break }
        $current = $parent
    }
}

function Resolve-SafePath([string]$PathValue, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($PathValue) -or $PathValue.IndexOf([char]0) -ge 0) {
        throw "Invalid ${Label}: path cannot be empty or contain NUL characters."
    }
    $trimmed = $PathValue.Trim()
    if ($trimmed.StartsWith('~')) {
        throw "Refusing $Label starting with '~': $PathValue"
    }
    if ($trimmed -match '\A[\\/]{2}') {
        throw "Refusing $Label with UNC or device-path prefix ('\\'): $PathValue"
    }
    if ($trimmed -match '\A[A-Za-z]:(?![\\/])') {
        throw "Refusing drive-relative $Label '$PathValue'. Supply a full path or a path relative to the current location."
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

    if ($full.StartsWith('\\') -or -not [regex]::IsMatch($full, '\A[A-Za-z]:\\')) {
        throw "Refusing unsupported ${Label}: $PathValue"
    }
    $normalized = Normalize-PathString $full
    Assert-NoReparsePointInPath $normalized
    return $normalized
}

function Assert-NotProtectedFolder([string]$FullPath, [string]$Role, [string]$UserProfileFull, [string]$WindowsDirFull) {
    if (Test-IsDriveRoot $FullPath) {
        throw "Refusing to use a drive root as the $Role`: $FullPath"
    }
    if (-not [string]::IsNullOrEmpty($UserProfileFull) -and (Test-PathsEqual $FullPath $UserProfileFull)) {
        throw "Refusing to use the user profile folder as the $Role`: $FullPath"
    }
    if (Test-PathsEqual $FullPath $WindowsDirFull) {
        throw "Refusing to use the Windows folder as the $Role`: $FullPath"
    }
}

function Ensure-DirectoryTracked([string]$DirPath, [System.Collections.Generic.List[string]]$CreatedList) {
    $missing = [System.Collections.Generic.List[string]]::new()
    $cur = $DirPath
    while (-not [string]::IsNullOrEmpty($cur) -and -not (Test-Path -LiteralPath $cur)) {
        $missing.Add($cur)
        $parent = [System.IO.Path]::GetDirectoryName($cur)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cur) { break }
        $cur = $parent
    }
    for ($i = $missing.Count - 1; $i -ge 0; $i--) {
        [void][System.IO.Directory]::CreateDirectory($missing[$i])
        $CreatedList.Add($missing[$i])
    }
}

function Remove-EmptyDirsDeepestFirst([System.Collections.Generic.List[string]]$DirList, [System.Collections.Generic.List[string]]$Errors) {
    for ($i = $DirList.Count - 1; $i -ge 0; $i--) {
        $d = $DirList[$i]
        try {
            if (Test-Path -LiteralPath $d -PathType Container) {
                $children = @(Get-ChildItem -LiteralPath $d -Force)
                if ($children.Count -eq 0) {
                    Remove-Item -LiteralPath $d -Force
                }
            }
        } catch {
            $Errors.Add("Failed removing created directory '$d': $($_.Exception.Message)")
        }
    }
}

function Rename-DirectoryNoOverwrite([string]$Source, [string]$Destination) {
    if (Test-Path -LiteralPath $Destination) {
        throw "Refusing to rename '$Source' onto existing destination '$Destination'."
    }
    [System.IO.Directory]::Move($Source, $Destination)
}

function Parse-ExpectedSha256FromFile([string]$ChecksumsFile, [string]$TargetFileName) {
    $foundHash = $null
    foreach ($line in (Get-Content -LiteralPath $ChecksumsFile -Encoding utf8)) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }
        if ($trimmed -match '\A([0-9A-Fa-f]{64})\s+\*?(.+)\z') {
            $hash = $Matches[1].ToLowerInvariant()
            $fileName = $Matches[2].Trim()
            if ($fileName.Equals($TargetFileName, [System.StringComparison]::OrdinalIgnoreCase)) {
                if ($null -ne $foundHash -and $foundHash -ne $hash) {
                    throw "SHA256SUMS.txt contains conflicting SHA-256 hashes for '$TargetFileName'."
                }
                $foundHash = $hash
            }
        }
    }
    return $foundHash
}

function Invoke-GitHubReleaseDownload([string]$Uri, [string]$OutFile) {
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.SslProtocols = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13
    $handler.AllowAutoRedirect = $true
    $handler.MaxAutomaticRedirections = 10
    $client = [System.Net.Http.HttpClient]::new($handler)
    try {
        $client.DefaultRequestHeaders.UserAgent.ParseAdd('EdgeProjectBridge-Installer/1')
        $response = $client.GetAsync($Uri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        try {
            if (-not $response.IsSuccessStatusCode) {
                throw [System.Net.Http.HttpRequestException]::new("HTTP $([int]$response.StatusCode) downloading $Uri", $null, $response.StatusCode)
            }
            $finalUri = $response.RequestMessage.RequestUri
            $hostName = $finalUri.Host
            $allowedHost = $hostName.Equals('github.com', [System.StringComparison]::OrdinalIgnoreCase) -or
                $hostName.EndsWith('.githubusercontent.com', [System.StringComparison]::OrdinalIgnoreCase)
            if (-not $finalUri.Scheme.Equals('https', [System.StringComparison]::OrdinalIgnoreCase) -or -not $allowedHost) {
                throw "Refusing download from unexpected final URL: $($finalUri.AbsoluteUri)"
            }
            $inStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            try {
                $outStream = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                try { $inStream.CopyTo($outStream) } finally { $outStream.Dispose() }
            } finally { $inStream.Dispose() }
        } finally { $response.Dispose() }
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

function Extract-ZipSafely([string]$ArchivePath, [string]$DestinationDir) {
    $destFull = Normalize-PathString ([System.IO.Path]::GetFullPath($DestinationDir))
    $destPrefix = Get-PathWithTrailingSeparator $destFull
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        if ($archive.Entries.Count -gt $MAX_ZIP_ENTRIES) {
            throw "Refusing archive: entry count ($($archive.Entries.Count)) exceeds limit of $MAX_ZIP_ENTRIES."
        }

        [int64]$declaredTotalBytes = 0
        $seenEntries = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $filePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $dirPrefixes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $planned = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($entry in $archive.Entries) {
            $rawName = $entry.FullName
            if ([string]::IsNullOrEmpty($rawName) -or $rawName.IndexOf([char]0) -ge 0) {
                throw 'Archive contains an invalid entry name.'
            }
            if ($rawName.StartsWith('/') -or $rawName.StartsWith('\') -or $rawName -match '\A[A-Za-z]:') {
                throw "Archive entry uses an absolute or drive-rooted path: $rawName"
            }
            if ((($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000) {
                throw "Archive contains a symlink entry: $rawName"
            }
            $entryLen = [int64]$entry.Length
            if ($entryLen -lt 0 -or $entryLen -gt $MAX_ZIP_UNCOMPRESSED_BYTES -or ($declaredTotalBytes + $entryLen) -gt $MAX_ZIP_UNCOMPRESSED_BYTES) {
                throw 'Refusing archive: declared uncompressed size exceeds limit of 300 MiB.'
            }
            $declaredTotalBytes += $entryLen

            $isDirectory = $rawName.EndsWith('/') -or $rawName.EndsWith('\')
            $cleanSegments = [System.Collections.Generic.List[string]]::new()
            foreach ($seg in ($rawName -split '[/\\]')) {
                if ($seg -eq '') { continue }
                if ($seg -eq '..' -or $seg -eq '.') { throw "Archive entry attempts directory traversal: $rawName" }
                if ($seg.Contains(':')) { throw "Archive entry contains an invalid colon character: $rawName" }
                if ($seg.EndsWith('.') -or $seg.EndsWith(' ')) { throw "Archive entry segment ends with a dot or space: $rawName" }
                $dotIdx = $seg.IndexOf('.')
                $baseName = if ($dotIdx -ge 0) { $seg.Substring(0, $dotIdx) } else { $seg }
                $baseName = $baseName.TrimEnd(' ')
                if ([regex]::IsMatch($baseName, '\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])\z', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
                    throw "Archive entry uses a Windows reserved device name: $rawName"
                }
                $cleanSegments.Add($seg)
            }
            if ($cleanSegments.Count -eq 0) {
                if ($isDirectory) { continue }
                throw "Archive contains an empty file entry: $rawName"
            }

            $relNative = [string]::Join('\', $cleanSegments)
            if (-not $seenEntries.Add($relNative)) {
                throw "Archive contains duplicate or case-colliding entries: $rawName"
            }
            for ($idx = 0; $idx -lt ($cleanSegments.Count - 1); $idx++) {
                [void]$dirPrefixes.Add([string]::Join('\', $cleanSegments.GetRange(0, $idx + 1)))
            }
            if ($isDirectory) { [void]$dirPrefixes.Add($relNative) } else { [void]$filePaths.Add($relNative) }

            $targetPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($destFull, $relNative))
            if (-not $targetPath.StartsWith($destPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Archive entry escapes the extraction directory: $rawName"
            }
            $planned.Add(@{ Entry = $entry; TargetPath = $targetPath; IsDirectory = $isDirectory })
        }

        foreach ($fp in $filePaths) {
            if ($dirPrefixes.Contains($fp)) {
                throw "Archive entry conflicts as both a file and a folder prefix: $fp"
            }
        }

        [int64]$actualTotalBytes = 0
        $buffer = [byte[]]::new(65536)
        foreach ($item in $planned) {
            if ($item.IsDirectory) {
                [void][System.IO.Directory]::CreateDirectory($item.TargetPath)
            } else {
                $parent = [System.IO.Path]::GetDirectoryName($item.TargetPath)
                if (-not [string]::IsNullOrEmpty($parent)) { [void][System.IO.Directory]::CreateDirectory($parent) }
                $inStream = $item.Entry.Open()
                try {
                    $outStream = [System.IO.File]::Open($item.TargetPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                    try {
                        while (($read = $inStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                            $actualTotalBytes += $read
                            if ($actualTotalBytes -gt $MAX_ZIP_UNCOMPRESSED_BYTES) {
                                throw 'Refusing archive: extracted byte count exceeds limit of 300 MiB.'
                            }
                            $outStream.Write($buffer, 0, $read)
                        }
                    } finally { $outStream.Dispose() }
                } finally { $inStream.Dispose() }
            }
        }
    } finally { $archive.Dispose() }
}

function Remove-OuterQuotes([string]$Text) {
    if ($null -eq $Text) { return '' }
    $t = $Text.Trim()
    if ($t.Length -ge 2) {
        if (($t.StartsWith('"') -and $t.EndsWith('"')) -or ($t.StartsWith("'") -and $t.EndsWith("'"))) {
            return $t.Substring(1, $t.Length - 2).Trim()
        }
    }
    return $t
}

# 1. Resolve missing inputs (interactive prompt when interactive, otherwise require parameters)
$interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
$promptedUser = $false
$defaultInstallDir = Join-Path $env:LOCALAPPDATA 'EdgeProjectBridge'

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    if (-not $interactive) { throw 'Missing required parameter -InstallDir in non-interactive mode.' }
    $answer = Read-Host "Where should Edge Project Bridge be installed? [$defaultInstallDir]"
    $cleaned = Remove-OuterQuotes $answer
    $InstallDir = if ([string]::IsNullOrWhiteSpace($cleaned)) { $defaultInstallDir } else { $cleaned }
    $promptedUser = $true
}

$resolvedInstallDir = Resolve-SafePath $InstallDir '-InstallDir'
$existingInstallJsonPath = Join-Path $resolvedInstallDir 'install.json'
$userProfileFull = if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) { '' } else { Normalize-PathString ([System.IO.Path]::GetFullPath($env:USERPROFILE)) }
$windowsDirFull = Normalize-PathString ([System.IO.Path]::GetFullPath([Environment]::GetFolderPath('Windows')))

# 2. Validate the install folder and the paths BEFORE changing anything
if (Test-Path -LiteralPath $resolvedInstallDir -PathType Leaf) {
    throw "Install path points to an existing file, not a folder: $resolvedInstallDir"
}
Assert-NotProtectedFolder $resolvedInstallDir 'install folder' $userProfileFull $windowsDirFull

if (Test-Path -LiteralPath $resolvedInstallDir -PathType Container) {
    if (@(Get-ChildItem -LiteralPath $resolvedInstallDir -Force).Count -gt 0) {
        throw "Refusing to install: the install folder is not empty: $resolvedInstallDir. Choose a new or empty folder."
    }
}
if ([string]::IsNullOrWhiteSpace($ProjectPath)) {
    if (-not $interactive) { throw 'Missing required parameter -ProjectPath in non-interactive mode.' }
    $answer = Read-Host 'Which project folder should it work on?'
    $cleaned = Remove-OuterQuotes $answer
    if ([string]::IsNullOrWhiteSpace($cleaned)) { throw 'A project folder path is required.' }
    $ProjectPath = $cleaned
    $promptedUser = $true
}
$resolvedProjectPath = Resolve-SafePath $ProjectPath '-ProjectPath'
if (-not (Test-Path -LiteralPath $resolvedProjectPath -PathType Container)) {
    throw "Project path does not exist or is not a folder: $resolvedProjectPath"
}

Assert-NotProtectedFolder $resolvedProjectPath 'project folder' $userProfileFull $windowsDirFull

$installWithSlash = Get-PathWithTrailingSeparator $resolvedInstallDir
$projectWithSlash = Get-PathWithTrailingSeparator $resolvedProjectPath
if ($installWithSlash.Equals($projectWithSlash, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Install folder and project folder cannot be the same: $resolvedInstallDir"
}
if ($installWithSlash.StartsWith($projectWithSlash, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Install folder ($resolvedInstallDir) cannot be inside the project folder ($resolvedProjectPath)."
}
if ($projectWithSlash.StartsWith($installWithSlash, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Project folder ($resolvedProjectPath) cannot be inside the install folder ($resolvedInstallDir)."
}

if ([string]::IsNullOrWhiteSpace($ZipPath) -and [string]::IsNullOrWhiteSpace($Version)) {
    if (-not $interactive) {
        throw 'Provide either -ZipPath (local release archive) or -Version (GitHub Release version, e.g. 0.6.0-pre2).'
    }
    $answer = Read-Host 'Which release version should be downloaded (e.g. 0.6.0-pre2)?'
    $cleaned = Remove-OuterQuotes $answer
    if ([string]::IsNullOrWhiteSpace($cleaned)) { throw 'A release version is required when -ZipPath is not supplied.' }
    $Version = $cleaned
    $promptedUser = $true
}

$proRoot = Join-Path $resolvedProjectPath '_pro'
$proSubdirs = @($proRoot, (Join-Path $proRoot 'inbox'), (Join-Path $proRoot 'outbox'), (Join-Path $proRoot 'reports'))
foreach ($dirPath in $proSubdirs) {
    Assert-NoReparsePointInPath $dirPath
    if (Test-Path -LiteralPath $dirPath -PathType Leaf) {
        throw "Cannot create mailbox folder because a file already exists at: $dirPath"
    }
}

# Validate -Version, -Repo, -Sha256, -ZipPath strictly
$cleanVersion = $null
if ($PSBoundParameters.ContainsKey('Version') -or -not [string]::IsNullOrEmpty($Version)) {
    if ([string]::IsNullOrEmpty($Version) -or -not [regex]::IsMatch($Version, '\A[0-9A-Za-z][0-9A-Za-z.+-]*\z')) {
        throw "Invalid -Version '$Version'."
    }
    $cleanVersion = if ($Version.StartsWith('v', [System.StringComparison]::OrdinalIgnoreCase)) { $Version.Substring(1) } else { $Version }
    if ([string]::IsNullOrEmpty($cleanVersion) -or -not [regex]::IsMatch($cleanVersion, '\A[0-9A-Za-z][0-9A-Za-z.+-]*\z')) {
        throw "Invalid -Version '$Version'."
    }
}

if ($PSBoundParameters.ContainsKey('Repo') -or [string]::IsNullOrWhiteSpace($ZipPath)) {
    if ([string]::IsNullOrEmpty($Repo) -or -not [regex]::IsMatch($Repo, '\A[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+\z')) {
        throw "Invalid -Repo '$Repo'. Expected '<owner>/<name>'."
    }
    $repoParts = $Repo.Split('/')
    if ($repoParts[0] -in @('.', '..') -or $repoParts[1] -in @('.', '..')) {
        throw "Invalid -Repo '$Repo'. Expected '<owner>/<name>'."
    }
}

$expectedSha256 = $null
if ($PSBoundParameters.ContainsKey('Sha256') -or -not [string]::IsNullOrEmpty($Sha256)) {
    if ([string]::IsNullOrEmpty($Sha256) -or -not [regex]::IsMatch($Sha256, '\A[0-9A-Fa-f]{64}\z')) {
        throw "Invalid -Sha256 '$Sha256'. Expected a 64-character hexadecimal SHA-256 digest."
    }
    $expectedSha256 = $Sha256.ToLowerInvariant()
}

$resolvedZipPath = $null
if (-not [string]::IsNullOrWhiteSpace($ZipPath)) {
    $resolvedZipPath = Resolve-SafePath $ZipPath '-ZipPath'
    if (-not (Test-Path -LiteralPath $resolvedZipPath -PathType Leaf)) {
        throw "Release zip not found: $resolvedZipPath"
    }
}

# 3. Interactive final confirmation before doing any work
if ($promptedUser) {
    Write-Host ''
    Write-Host 'Planned installation:'
    Write-Host "  Install folder : $resolvedInstallDir"
    Write-Host "  Project folder : $resolvedProjectPath"
    if ($null -ne $resolvedZipPath) { Write-Host "  Release zip    : $resolvedZipPath" }
    else { Write-Host "  Release        : $Repo v$cleanVersion" }
    Write-Host ''
    $confirm = Read-Host 'Proceed with installation? [y/N]'
    if ($confirm.Trim().ToLowerInvariant() -notin @('y', 'yes')) {
        Write-Host 'Installation cancelled. No changes were made.'
        return
    }
}

# 4. Check what a test run needs. Nothing here stops the install: reading the project and writing under _pro\
#    need only the binary. Missing items are listed at the end.
$missingTestRunPrereqs = [System.Collections.Generic.List[string]]::new()

$uvCmd = Get-Command -Name 'uv' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $uvCmd) {
    $missingTestRunPrereqs.Add('uv: not found on PATH (needed to build the local worker Python environment). Install: winget install --id astral-sh.uv  (https://docs.astral.sh/uv/getting-started/installation/)')
}

$python313Path = $null
if ($null -ne $uvCmd) {
    Push-Location -LiteralPath ([System.IO.Path]::GetTempPath())
    try {
        $found = Invoke-Uv $uvCmd.Source @('python', 'find', '--system', '--no-python-downloads', '>=3.13,<3.14') 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($found)) {
            $candidate = ($found | Select-Object -First 1).Trim()
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $python313Path = $candidate }
        }
    } finally { Pop-Location }
} else {
    $pyLauncher = Get-Command -Name 'py' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $pyLauncher) {
        $found = & $pyLauncher.Source -3.13 -c 'import sys; print(sys.executable)' 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($found)) {
            $candidate = ($found | Select-Object -First 1).Trim()
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $python313Path = $candidate }
        }
    }
}
if ($null -eq $python313Path) {
    $missingTestRunPrereqs.Add('Python 3.13 (>=3.13,<3.14): not found (needed by the local worker). Install: winget install --id Python.Python.3.13  (https://www.python.org/downloads/)')
}

$pwshPinnedPath = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
if (-not (Test-Path -LiteralPath $pwshPinnedPath -PathType Leaf)) {
    $missingTestRunPrereqs.Add("Pinned PowerShell 7.7.0 x64 ($pwshPinnedPath): not found (needed for PowerShell script runs; install PowerShell-7.7.0-win-x64.msi, not the Microsoft Store app): https://github.com/PowerShell/PowerShell/releases/tag/v7.7.0")
} else {
    $pwshHash = (Get-FileHash -LiteralPath $pwshPinnedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($pwshHash -ne $PINNED_POWERSHELL_SHA256) {
        $missingTestRunPrereqs.Add("Pinned PowerShell 7.7.0 x64 ($pwshPinnedPath): SHA-256 mismatch (found $pwshHash, expected $PINNED_POWERSHELL_SHA256). Install PowerShell-7.7.0-win-x64.msi: https://github.com/PowerShell/PowerShell/releases/tag/v7.7.0")
    }
}

$codexPinnedPath = Join-Path $env:APPDATA 'npm\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe'
if (-not (Test-Path -LiteralPath $codexPinnedPath -PathType Leaf)) {
    $missingTestRunPrereqs.Add("Pinned Codex sandbox binary (@openai/codex $PINNED_CODEX_VERSION at $codexPinnedPath): not found (needed for every sandboxed test run). Install with npm: npm install -g @openai/codex@$PINNED_CODEX_VERSION  (Node.js/npm: https://nodejs.org/)")
} else {
    $codexHash = (Get-FileHash -LiteralPath $codexPinnedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($codexHash -ne $PINNED_CODEX_SHA256) {
        $missingTestRunPrereqs.Add("Pinned Codex sandbox binary ($codexPinnedPath): SHA-256 mismatch (found $codexHash, expected $PINNED_CODEX_SHA256 for @openai/codex $PINNED_CODEX_VERSION). Install exact version: npm install -g @openai/codex@$PINNED_CODEX_VERSION")
    }
}

$gitStandardPath = Join-Path $env:ProgramFiles 'Git\cmd\git.exe'
$gitCmd = Get-Command -Name 'git' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$gitMissing = (-not (Test-Path -LiteralPath $gitStandardPath -PathType Leaf) -and $null -eq $gitCmd)

$canBuildRuntime = ($null -ne $uvCmd) -and ($null -ne $python313Path)

# 5. Isolated work folder (created inside try so partial folders are removed) and rollback tracking
$runId = [guid]::NewGuid().ToString('N')
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) "epb-install-$runId"
$downloadDir = Join-Path $workDir 'download'
$extractDir = Join-Path $workDir 'extract'

$createdDirs = [System.Collections.Generic.List[string]]::new()
$createdFreshItems = [System.Collections.Generic.List[string]]::new()
$createdProDirs = [System.Collections.Generic.List[string]]::new()
$movedToFinal = [System.Collections.Generic.List[hashtable]]::new()
$stageBin = Join-Path $resolvedInstallDir "bin.new-$runId"
$stageRuntime = Join-Path $resolvedInstallDir "runtime.new-$runId"
$installCommitted = $false

try {
    [void][System.IO.Directory]::CreateDirectory($downloadDir)
    [void][System.IO.Directory]::CreateDirectory($extractDir)

    # 5a. Acquire zip and expected SHA-256
    $localZipPath = $null
    $downloadedZip = $false

    if ($null -ne $resolvedZipPath) {
        $zipFileName = [System.IO.Path]::GetFileName($resolvedZipPath)
        if ($null -eq $expectedSha256) {
            $siblingChecksums = Join-Path ([System.IO.Path]::GetDirectoryName($resolvedZipPath)) 'SHA256SUMS.txt'
            Assert-NoReparsePointInPath $siblingChecksums
            if (-not (Test-Path -LiteralPath $siblingChecksums -PathType Leaf)) {
                throw "SHA-256 verification is required. Pass -Sha256 or place SHA256SUMS.txt beside $resolvedZipPath."
            }
            $expectedSha256 = Parse-ExpectedSha256FromFile $siblingChecksums $zipFileName
            if ($null -eq $expectedSha256) {
                throw "SHA256SUMS.txt beside $resolvedZipPath does not contain an entry for $zipFileName."
            }
        }
        # The copy in the private work folder is the one that is hashed and extracted.
        $localZipPath = Join-Path $downloadDir 'release.zip'
        Copy-Item -LiteralPath $resolvedZipPath -Destination $localZipPath
    } else {
        $zipFileName = "edge-project-bridge-$cleanVersion-windows-x64.zip"
        $tag = "v$cleanVersion"
        $baseUrl = "https://github.com/$Repo/releases/download/$tag"
        $zipUrl = "$baseUrl/$zipFileName"
        $sumsUrl = "$baseUrl/SHA256SUMS.txt"
        $localZipPath = Join-Path $downloadDir $zipFileName
        $localSumsPath = Join-Path $downloadDir 'SHA256SUMS.txt'

        try {
            Write-Host "Downloading $zipUrl ..."
            Invoke-GitHubReleaseDownload $zipUrl $localZipPath
            $downloadedZip = $true
            if ($null -eq $expectedSha256) { Invoke-GitHubReleaseDownload $sumsUrl $localSumsPath }
        } catch {
            $statusCode = if ($_.Exception -is [System.Net.Http.HttpRequestException] -and $null -ne $_.Exception.StatusCode) {
                [int]$_.Exception.StatusCode
            } else { $null }
            $ghCmd = Get-Command -Name 'gh' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($statusCode -eq 404 -and $null -ne $ghCmd) {
                Write-Host 'Direct download returned 404 (private repository). Falling back to gh release download...'
                if (Test-Path -LiteralPath $localZipPath) { Remove-Item -LiteralPath $localZipPath -Force }
                if (Test-Path -LiteralPath $localSumsPath) { Remove-Item -LiteralPath $localSumsPath -Force }
                & $ghCmd.Source release download $tag "--repo=$Repo" "--pattern=$zipFileName" "--dir=$downloadDir"
                if ($LASTEXITCODE -ne 0) { throw "gh release download failed for $Repo $tag ($zipFileName). Sign in with 'gh auth login' and verify -Version, or download the zip manually and pass -ZipPath." }
                $downloadedZip = $true
                if ($null -eq $expectedSha256) {
                    & $ghCmd.Source release download $tag "--repo=$Repo" '--pattern=SHA256SUMS.txt' "--dir=$downloadDir"
                    if ($LASTEXITCODE -ne 0) { throw "gh release download failed for $Repo $tag (SHA256SUMS.txt). Sign in with 'gh auth login' and verify -Version, or download the zip manually and pass -ZipPath." }
                }
            } else {
                if ($statusCode -eq 404) {
                    throw "Release download failed with HTTP 404 ($zipUrl). If '$Repo' is private, install and sign in to GitHub CLI (gh), or download the zip and pass -ZipPath."
                }
                throw "Release download failed ($zipUrl): $($_.Exception.Message)"
            }
        }

        if ($null -eq $expectedSha256) {
            if (-not (Test-Path -LiteralPath $localSumsPath -PathType Leaf)) {
                throw 'SHA256SUMS.txt was not downloaded from the release.'
            }
            $expectedSha256 = Parse-ExpectedSha256FromFile $localSumsPath $zipFileName
            if ($null -eq $expectedSha256) {
                throw "SHA256SUMS.txt from release $tag does not contain an entry for $zipFileName."
            }
        }
    }

    # 5b. Verify SHA-256 BEFORE extracting
    $actualSha256 = (Get-FileHash -LiteralPath $localZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "Archive SHA-256: $actualSha256"
    if ($actualSha256 -ne $expectedSha256) {
        if ($downloadedZip -and (Test-Path -LiteralPath $localZipPath)) { Remove-Item -LiteralPath $localZipPath -Force }
        throw "SHA-256 mismatch for $localZipPath. Expected $expectedSha256, got $actualSha256."
    }

    # 5c. Safely extract archive into temp directory (validates every entry first)
    Extract-ZipSafely $localZipPath $extractDir

    $extractedExe = Join-Path $extractDir 'edge-bridge.exe'
    $extractedRuntime = Join-Path $extractDir 'runtime'
    if (-not (Test-Path -LiteralPath $extractedExe -PathType Leaf)) {
        throw 'Release archive is missing edge-bridge.exe.'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $extractedRuntime 'pyproject.toml') -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $extractedRuntime 'uv.lock') -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $extractedRuntime 'edge_bridge\runner.py') -PathType Leaf)) {
        throw 'Release archive is missing required runtime files (pyproject.toml, uv.lock, or edge_bridge\runner.py).'
    }

    # 5d. Stage bin.new-<id> and runtime.new-<id> inside InstallDir (same volume) and run uv sync there
    Ensure-DirectoryTracked $resolvedInstallDir $createdDirs
    if ((Test-Path -LiteralPath $stageBin) -or (Test-Path -LiteralPath $stageRuntime)) {
        throw "Staging paths already exist in $resolvedInstallDir."
    }

    [void][System.IO.Directory]::CreateDirectory($stageBin)
    Copy-Item -LiteralPath $extractedExe -Destination (Join-Path $stageBin 'edge-bridge.exe')
    Copy-Item -LiteralPath $extractedRuntime -Destination $stageRuntime -Recurse

    if ($canBuildRuntime) {
        Write-Host 'Building Python runtime environment with uv sync --locked ...'
        Push-Location -LiteralPath $stageRuntime
        try {
            Invoke-Uv $uvCmd.Source @('sync', '--locked', '--no-python-downloads', "--project=$stageRuntime", "--python=$python313Path")
            if ($LASTEXITCODE -ne 0) { throw "uv sync --locked failed with exit code $LASTEXITCODE." }
        } finally { Pop-Location }

        $stagedVenvDir = Join-Path $stageRuntime '.venv'
        $stagedVenvPython = Join-Path $stagedVenvDir 'Scripts\python.exe'
        Assert-NoReparsePointInPath $stagedVenvPython
        if (-not (Test-Path -LiteralPath $stagedVenvDir -PathType Container) -or
            -not (Test-Path -LiteralPath $stagedVenvPython -PathType Leaf)) {
            throw "uv sync --locked did not create a local .venv inside $stageRuntime."
        }
    }

    # 5e. Rename the staged bin and runtime into place (same volume)
    $targetBin = Join-Path $resolvedInstallDir 'bin'
    $targetRuntime = Join-Path $resolvedInstallDir 'runtime'
    $targetState = Join-Path $resolvedInstallDir 'state'

    $swapPairs = @(
        @{ New = $stageBin; Final = $targetBin },
        @{ New = $stageRuntime; Final = $targetRuntime }
    )
    foreach ($pair in $swapPairs) {
        Rename-DirectoryNoOverwrite $pair.New $pair.Final
        $movedToFinal.Add($pair)
    }

    # Verify the installed venv python can import the supervisor modules from the final path (no code interpolation)
    if ($canBuildRuntime) {
        $installedVenvPython = Join-Path $targetRuntime '.venv\Scripts\python.exe'
        Push-Location -LiteralPath $targetRuntime
        try {
            & $installedVenvPython -I -B -c 'import sys; sys.path.insert(0, sys.argv[1]); import edge_bridge.broker, edge_bridge.jobs, edge_bridge.runner, edge_bridge.state' $targetRuntime
            if ($LASTEXITCODE -ne 0) { throw 'Installed Python runtime failed import verification for edge_bridge.' }
        } finally { Pop-Location }
    }

    $installedExe = Join-Path $targetBin 'edge-bridge.exe'

    foreach ($itemName in @('LICENSE', 'COPYING', 'README.md', 'SECURITY_BOUNDARIES.md', 'docs')) {
        $srcItem = Join-Path $extractDir $itemName
        if (Test-Path -LiteralPath $srcItem) {
            $dstItem = Join-Path $resolvedInstallDir $itemName
            Copy-Item -LiteralPath $srcItem -Destination $dstItem -Recurse
            $createdFreshItems.Add($dstItem)
        }
    }

    [void][System.IO.Directory]::CreateDirectory($targetState)
    $createdFreshItems.Add($targetState)

    $projectName = [System.IO.Path]::GetFileName($resolvedProjectPath)
    $registerRaw = & $installedExe "--state-dir=$targetState" register "--name=$projectName" -- $resolvedProjectPath
    if ($LASTEXITCODE -ne 0) { throw "edge-bridge register failed with exit code $LASTEXITCODE." }
    $registerJson = ($registerRaw -join "`n") | ConvertFrom-Json
    $projectId = $registerJson.project_id
    if ([string]::IsNullOrWhiteSpace($projectId)) { throw 'edge-bridge register did not return a project_id.' }

    $installedVersion = if (-not [string]::IsNullOrWhiteSpace($cleanVersion)) {
        $cleanVersion
    } elseif ($zipFileName -match '\Aedge-project-bridge-(.+)-windows-x64\.zip\z') {
        $Matches[1]
    } else { 'local-zip' }

    $installConfig = [ordered]@{
        schema_version   = 1
        installed_at_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        version          = $installedVersion
        archive_sha256   = $actualSha256
        install_dir      = $resolvedInstallDir
        exe_path         = $installedExe
        runtime_dir      = $targetRuntime
        state_dir        = $targetState
        project_path     = $resolvedProjectPath
        project_id       = $projectId
        project_name     = $projectName
    }

    $startWorkerContent = @'
#Requires -Version 7
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments)]
    [string[]]$WorkerArgs
)

$ErrorActionPreference = 'Stop'
$configPath = Join-Path $PSScriptRoot 'install.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Missing installation config: $configPath" }
$config = Get-Content -LiteralPath $configPath -Raw -Encoding utf8 | ConvertFrom-Json
if (-not (Test-Path -LiteralPath (Join-Path $config.runtime_dir '.venv\Scripts\python.exe') -PathType Leaf)) {
    throw 'The worker runtime is not built yet. Run .\setup-worker.ps1 first.'
}
& $config.exe_path "--state-dir=$($config.state_dir)" worker "--runtime-root=$($config.runtime_dir)" @WorkerArgs
exit $LASTEXITCODE
'@

    $setupWorkerContent = @'
#Requires -Version 7
[CmdletBinding()]
param()

# Builds the Python environment of the worker. Run it after uv and Python 3.13 are installed.
$ErrorActionPreference = 'Stop'
$configPath = Join-Path $PSScriptRoot 'install.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Missing installation config: $configPath" }
$config = Get-Content -LiteralPath $configPath -Raw -Encoding utf8 | ConvertFrom-Json
$uv = Get-Command -Name 'uv' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $uv) {
    throw 'uv was not found on PATH. Install it (winget install --id astral-sh.uv), open a new PowerShell 7 window and run this script again.'
}
$saved = @{}
foreach ($name in @('UV_PROJECT', 'UV_PROJECT_ENVIRONMENT', 'UV_WORKING_DIRECTORY', 'UV_CONFIG_FILE', 'VIRTUAL_ENV')) {
    if (Test-Path -LiteralPath "Env:$name") {
        $saved[$name] = (Get-Item -LiteralPath "Env:$name").Value
        Remove-Item -LiteralPath "Env:$name"
    }
}
Push-Location -LiteralPath $config.runtime_dir
try {
    $found = & $uv.Source --no-config python find --system --no-python-downloads '>=3.13,<3.14' 2>$null
    $pyPath = if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($found)) { ($found | Select-Object -First 1).Trim() } else { $null }
    if ([string]::IsNullOrWhiteSpace($pyPath) -or -not (Test-Path -LiteralPath $pyPath -PathType Leaf)) {
        throw 'Python 3.13 (>=3.13,<3.14) was not found. Install it (winget install --id Python.Python.3.13), open a new PowerShell 7 window and run this script again.'
    }
    & $uv.Source --no-config sync --locked --no-python-downloads "--project=$($config.runtime_dir)" "--python=$pyPath"
    $code = $LASTEXITCODE
} finally {
    Pop-Location
    foreach ($name in $saved.Keys) { Set-Item -LiteralPath "Env:$name" -Value $saved[$name] }
}
if ($code -ne 0) {
    throw "uv sync failed with exit code $code. Check network access to PyPI (or the uv cache) and verify Python 3.13 is installed."
}
if (-not (Test-Path -LiteralPath (Join-Path $config.runtime_dir '.venv\Scripts\python.exe') -PathType Leaf)) {
    throw 'uv sync did not create the environment inside the runtime folder.'
}
Write-Output 'The worker runtime is built. Run .\start-worker.ps1.'
Write-Output 'A test run also needs the exact PowerShell 7.7.0 and Codex 0.171.0 builds listed in docs\INSTALL.md.'
'@

    $newGrantContent = @'
#Requires -Version 7
[CmdletBinding()]
param(
    [Alias('Profile')]
    [ValidateSet('pro-review', 'pro-agent')]
    [string]$GrantProfile = 'pro-review',

    [ValidateRange(1, 1440)]
    [int]$Minutes = 60
)

$ErrorActionPreference = 'Stop'
$configPath = Join-Path $PSScriptRoot 'install.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Missing installation config: $configPath" }
$config = Get-Content -LiteralPath $configPath -Raw -Encoding utf8 | ConvertFrom-Json
$raw = & $config.exe_path "--state-dir=$($config.state_dir)" grant-create "--profile=$GrantProfile" "--ttl-minutes=$Minutes" -- $config.project_id
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$grant = ($raw -join "`n") | ConvertFrom-Json
$expiresText = if ($grant.expires_at -is [datetime]) { $grant.expires_at.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { [string]$grant.expires_at }
Write-Output "profile: $GrantProfile"
Write-Output "grant_id: $($grant.grant_id)"
Write-Output "expires_at: $expiresText"
Write-Output "project_id: $($grant.project_id)"
'@

    $envCheckContent = @'
#Requires -Version 7
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$configPath = Join-Path $PSScriptRoot 'install.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Missing installation config: $configPath" }
$config = Get-Content -LiteralPath $configPath -Raw -Encoding utf8 | ConvertFrom-Json
& $config.exe_path "--state-dir=$($config.state_dir)" environment-check
exit $LASTEXITCODE
'@

    $startContent = @'
#Requires -Version 7
[CmdletBinding(PositionalBinding = $false)]
param(
    [Alias('Profile')]
    [ValidateSet('pro-review', 'pro-agent')]
    [string]$GrantProfile = 'pro-agent',

    [ValidateRange(1, 1440)]
    [int]$Minutes = 240,

    [switch]$AllowWorkExec,

    [Parameter(ValueFromRemainingArguments)]
    [string[]]$WorkerArgs
)

$ErrorActionPreference = 'Stop'
if ($null -ne $WorkerArgs) {
    foreach ($arg in $WorkerArgs) {
        if ($arg -ieq '--allow-work-exec' -or $arg.StartsWith('--allow-work-exec=', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Use the -AllowWorkExec switch instead of passing --allow-work-exec directly.'
        }
    }
}

$configPath = Join-Path $PSScriptRoot 'install.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Missing installation config: $configPath" }
$config = Get-Content -LiteralPath $configPath -Raw -Encoding utf8 | ConvertFrom-Json

$envRaw = & $config.exe_path "--state-dir=$($config.state_dir)" environment-check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$envCheck = ($envRaw -join "`n") | ConvertFrom-Json
if (-not $envCheck.readable) {
    Write-Output 'Stopped: could not read persistent Windows environment variables.'
    Write-Output 'Test runs are refused when persistent environment variables cannot be checked. Run .\environment-check.ps1 for details.'
    exit 1
}
if ($null -ne $envCheck.credential_like_count -and [int]$envCheck.credential_like_count -gt 0) {
    Write-Output "Stopped: found $($envCheck.credential_like_count) credential-like entry(ies) in your persistent Windows environment:"
    foreach ($name in @($envCheck.credential_like_names)) {
        Write-Output "  - $name"
    }
    Write-Output 'Test runs are refused while these exist because sandboxed code can read persistent environment keys.'
    Write-Output 'Remove those entries from your persistent Windows environment variables, open a new PowerShell 7 window, and run .\start.ps1 again.'
    exit 1
}

if ($AllowWorkExec) {
    Write-Output 'Warning: -AllowWorkExec lets code written by the model run inside the sandbox on this PC.'
    Write-Output 'That code can read your Windows user name, profile paths, and the registry keys HKCU\Software, HKLM\Software, and HKCU\Environment.'
    Write-Output 'Enable this only if you accept that exposure.'
    $confirm = Read-Host 'Continue with -AllowWorkExec? [y/N]'
    if ($null -eq $confirm -or $confirm.Trim().ToLowerInvariant() -notin @('y', 'yes')) {
        Write-Output 'Cancelled. Run .\start.ps1 without -AllowWorkExec to start with work execution off.'
        exit 1
    }
}

$grantRaw = & $config.exe_path "--state-dir=$($config.state_dir)" grant-create "--profile=$GrantProfile" "--ttl-minutes=$Minutes" -- $config.project_id
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$grant = ($grantRaw -join "`n") | ConvertFrom-Json
$expiresText = if ($grant.expires_at -is [datetime]) { $grant.expires_at.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { [string]$grant.expires_at }
Write-Output "profile: $GrantProfile"
Write-Output "grant_id: $($grant.grant_id)"
Write-Output "expires_at: $expiresText"
Write-Output "project_id: $($grant.project_id)"
if ($GrantProfile -eq 'pro-agent') {
    Write-Output 'Model access: read project and Git, create under _pro\outbox\ and _pro\reports\, edit copies under _pro\work\, and queue tests (project files stay read-only until .\apply.ps1).'
} else {
    Write-Output 'Model access: read project and Git, create new files under _pro\outbox\ and _pro\reports\, and queue tests (project files stay read-only).'
}

if (-not (Test-Path -LiteralPath (Join-Path $config.runtime_dir '.venv\Scripts\python.exe') -PathType Leaf)) {
    Write-Output ''
    Write-Output 'The worker runtime is not built yet, so queued test runs will not start.'
    Write-Output 'Reading, copying, editing, and diffing work now with the grant above.'
    Write-Output 'To enable test runs, install any missing prerequisites (see .\status.ps1) and run .\setup-worker.ps1.'
    exit 0
}

$workerCmdArgs = [System.Collections.Generic.List[string]]::new()
$workerCmdArgs.Add("--state-dir=$($config.state_dir)")
$workerCmdArgs.Add('worker')
$workerCmdArgs.Add("--runtime-root=$($config.runtime_dir)")
if ($AllowWorkExec) { $workerCmdArgs.Add('--allow-work-exec') }
if ($null -ne $WorkerArgs) {
    foreach ($arg in $WorkerArgs) { $workerCmdArgs.Add($arg) }
}

Write-Output 'Starting local worker (press Ctrl+C to stop)...'
& $config.exe_path @workerCmdArgs
exit $LASTEXITCODE
'@

    $applyContent = @'
#Requires -Version 7
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Workspace
)

$ErrorActionPreference = 'Stop'
if ($Workspace -cnotmatch '\A[a-z0-9][a-z0-9_-]{0,39}\z') {
    throw "Invalid workspace name '$Workspace'. Expected 1 to 40 lowercase letters, digits, '_' or '-', starting with a letter or digit."
}

$configPath = Join-Path $PSScriptRoot 'install.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Missing installation config: $configPath" }
$config = Get-Content -LiteralPath $configPath -Raw -Encoding utf8 | ConvertFrom-Json

$dryRaw = & $config.exe_path "--state-dir=$($config.state_dir)" work-apply -- $config.project_id $Workspace
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$dry = ($dryRaw -join "`n") | ConvertFrom-Json

Write-Output "Workspace: $($dry.workspace)"
Write-Output "Files changed: $($dry.files_changed)"
if (@($dry.files_added).Count -gt 0) {
    Write-Output 'Added:'
    foreach ($p in @($dry.files_added)) { Write-Output "  + $p" }
}
if (@($dry.files_modified).Count -gt 0) {
    Write-Output 'Modified:'
    foreach ($p in @($dry.files_modified)) { Write-Output "  ~ $p" }
}
if (@($dry.files_deleted).Count -gt 0) {
    Write-Output 'Deleted:'
    foreach ($p in @($dry.files_deleted)) { Write-Output "  - $p" }
}
if (@($dry.drifted_files).Count -gt 0) {
    Write-Output 'Drifted (project file changed after copy):'
    foreach ($p in @($dry.drifted_files)) { Write-Output "  ! $p" }
}
if (@($dry.conflict_files).Count -gt 0) {
    Write-Output 'Conflicts (target already exists in project):'
    foreach ($p in @($dry.conflict_files)) { Write-Output "  ! $p" }
}
if (-not [string]::IsNullOrEmpty($dry.unified_diff)) {
    Write-Output ''
    Write-Output $dry.unified_diff
}
if (-not $dry.safe_to_apply) {
    Write-Output 'Cannot apply because of drift or conflicts above. No project files were changed.'
    exit 1
}
if ([int]$dry.files_changed -eq 0) {
    Write-Output 'No changes to apply.'
    exit 0
}

$confirm = Read-Host 'Apply these changes to the project? [y/N]'
if ($null -eq $confirm -or $confirm.Trim().ToLowerInvariant() -notin @('y', 'yes')) {
    Write-Output 'Cancelled. No project files were changed.'
    exit 0
}

$applyRaw = & $config.exe_path "--state-dir=$($config.state_dir)" work-apply --confirm -- $config.project_id $Workspace
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$applied = ($applyRaw -join "`n") | ConvertFrom-Json
$journalId = [string]$applied.journal_id
Write-Output "Applied workspace '$Workspace' ($($applied.files_changed) file(s))."
Write-Output "journal_id: $journalId"
if ($journalId -cmatch '\Apjr_[0-9a-fA-F]{32}\z') {
    Write-Output "To roll back: .\rollback.ps1 $journalId"
}
'@

    $rollbackContent = @'
#Requires -Version 7
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$JournalId
)

$ErrorActionPreference = 'Stop'
if ($JournalId -cnotmatch '\Apjr_[0-9a-fA-F]{32}\z') {
    throw "Invalid journal ID '$JournalId'. Expected 'pjr_' followed by 32 hexadecimal characters."
}

$configPath = Join-Path $PSScriptRoot 'install.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Missing installation config: $configPath" }
$config = Get-Content -LiteralPath $configPath -Raw -Encoding utf8 | ConvertFrom-Json

$raw = & $config.exe_path "--state-dir=$($config.state_dir)" rollback-patch "--project-root=$($config.project_path)" "--journal-id=$JournalId"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$res = ($raw -join "`n") | ConvertFrom-Json
Write-Output "Rolled back journal: $($res.journal_id)"
$restored = @($res.restored_files)
if ($restored.Count -eq 0) {
    Write-Output '  (no files reported)'
} else {
    foreach ($p in $restored) { Write-Output "  restored: $p" }
}
'@

    $statusContent = (@'
#Requires -Version 7
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$PINNED_CODEX_VERSION = '__PINNED_CODEX_VERSION__'
$PINNED_CODEX_SHA256 = '__PINNED_CODEX_SHA256__'
$PINNED_POWERSHELL_SHA256 = '__PINNED_POWERSHELL_SHA256__'

$configPath = Join-Path $PSScriptRoot 'install.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Missing installation config: $configPath" }
$config = Get-Content -LiteralPath $configPath -Raw -Encoding utf8 | ConvertFrom-Json

$binVersion = $null
if (Test-Path -LiteralPath $config.exe_path -PathType Leaf) {
    $vOut = & $config.exe_path --version 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace(($vOut -join ''))) {
        $binVersion = ($vOut | Select-Object -First 1).Trim()
    }
}
if ([string]::IsNullOrWhiteSpace($binVersion)) { $binVersion = '(unknown)' }

$runtimeBuilt = Test-Path -LiteralPath (Join-Path $config.runtime_dir '.venv\Scripts\python.exe') -PathType Leaf

$missingPrereqs = [System.Collections.Generic.List[string]]::new()
$uvCmd = Get-Command -Name 'uv' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $uvCmd) {
    $missingPrereqs.Add('uv: not found on PATH')
}

$python313Path = $null
if ($null -ne $uvCmd) {
    $saved = @{}
    foreach ($name in @('UV_PROJECT', 'UV_PROJECT_ENVIRONMENT', 'UV_WORKING_DIRECTORY', 'UV_CONFIG_FILE', 'VIRTUAL_ENV')) {
        if (Test-Path -LiteralPath "Env:$name") {
            $saved[$name] = (Get-Item -LiteralPath "Env:$name").Value
            Remove-Item -LiteralPath "Env:$name"
        }
    }
    Push-Location -LiteralPath ([System.IO.Path]::GetTempPath())
    try {
        $found = & $uvCmd.Source --no-config python find --system --no-python-downloads '>=3.13,<3.14' 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($found)) {
            $candidate = ($found | Select-Object -First 1).Trim()
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $python313Path = $candidate }
        }
    } finally {
        Pop-Location
        foreach ($name in $saved.Keys) { Set-Item -LiteralPath "Env:$name" -Value $saved[$name] }
    }
} else {
    $pyLauncher = Get-Command -Name 'py' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $pyLauncher) {
        $found = & $pyLauncher.Source -3.13 -c 'import sys; print(sys.executable)' 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($found)) {
            $candidate = ($found | Select-Object -First 1).Trim()
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $python313Path = $candidate }
        }
    }
}
if ($null -eq $python313Path) {
    $missingPrereqs.Add('Python 3.13 (>=3.13,<3.14): not found')
}

$pwshPinnedPath = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
if (-not (Test-Path -LiteralPath $pwshPinnedPath -PathType Leaf)) {
    $missingPrereqs.Add("Pinned PowerShell 7.7.0 x64 ($pwshPinnedPath): not found")
} else {
    $pwshHash = (Get-FileHash -LiteralPath $pwshPinnedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($pwshHash -ne $PINNED_POWERSHELL_SHA256) {
        $missingPrereqs.Add("Pinned PowerShell 7.7.0 x64 ($pwshPinnedPath): SHA-256 mismatch")
    }
}

$codexPinnedPath = Join-Path $env:APPDATA 'npm\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe'
if (-not (Test-Path -LiteralPath $codexPinnedPath -PathType Leaf)) {
    $missingPrereqs.Add("Pinned Codex sandbox binary (@openai/codex $PINNED_CODEX_VERSION): not found")
} else {
    $codexHash = (Get-FileHash -LiteralPath $codexPinnedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($codexHash -ne $PINNED_CODEX_SHA256) {
        $missingPrereqs.Add("Pinned Codex sandbox binary (@openai/codex $PINNED_CODEX_VERSION): SHA-256 mismatch")
    }
}

Write-Output "Binary version : $binVersion"
if (-not [string]::IsNullOrWhiteSpace($config.version)) {
    Write-Output "Release version: $($config.version)"
}
Write-Output "Project path   : $($config.project_path)"
Write-Output "Project ID     : $($config.project_id)"
Write-Output ("Worker runtime : " + $(if ($runtimeBuilt) { 'built' } else { 'not built (run .\setup-worker.ps1)' }))

if ($missingPrereqs.Count -eq 0) {
    Write-Output 'Missing test-run prerequisites: none'
} else {
    Write-Output 'Missing test-run prerequisites:'
    foreach ($item in $missingPrereqs) { Write-Output "  - $item" }
}

$workRoot = Join-Path $config.project_path '_pro\work'
Write-Output 'Workspaces (_pro\work\):'
if (Test-Path -LiteralPath $workRoot -PathType Container) {
    $wsDirs = @(Get-ChildItem -LiteralPath $workRoot -Directory | Sort-Object Name)
    if ($wsDirs.Count -eq 0) {
        Write-Output '  (none)'
    } else {
        foreach ($d in $wsDirs) {
            $count = @(Get-ChildItem -LiteralPath $d.FullName -File -Recurse -ErrorAction SilentlyContinue).Count
            Write-Output "  - $($d.Name) ($count file(s))"
        }
    }
} else {
    Write-Output '  (none)'
}

foreach ($box in @(@{ Label = 'Outbox (_pro\outbox\)'; Rel = '_pro\outbox' }, @{ Label = 'Reports (_pro\reports\)'; Rel = '_pro\reports' })) {
    $dir = Join-Path $config.project_path $box.Rel
    Write-Output "$($box.Label):"
    if (Test-Path -LiteralPath $dir -PathType Container) {
        $files = @(Get-ChildItem -LiteralPath $dir -File -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName)
        if ($files.Count -eq 0) {
            Write-Output '  (none)'
        } else {
            foreach ($f in $files) {
                $rel = [System.IO.Path]::GetRelativePath($dir, $f.FullName)
                Write-Output "  - $rel"
            }
        }
    } else {
        Write-Output '  (none)'
    }
}
'@).Replace('__PINNED_CODEX_VERSION__', $PINNED_CODEX_VERSION).Replace('__PINNED_CODEX_SHA256__', $PINNED_CODEX_SHA256).Replace('__PINNED_POWERSHELL_SHA256__', $PINNED_POWERSHELL_SHA256)

    $setupTunnelContent = @'
#Requires -Version 7
[CmdletBinding()]
param(
    [string]$TunnelClientPath,

    [Alias('Profile')]
    [string]$TunnelProfile = 'chatgpt-local-mcp',

    [string]$ProfileDir,

    [switch]$Force
)

$ErrorActionPreference = 'Stop'
if ($TunnelProfile -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z') {
    throw "Invalid tunnel profile name '$TunnelProfile'. Use 1 to 64 letters, digits, '.', '_' or '-'."
}

$configPath = Join-Path $PSScriptRoot 'install.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Missing installation config: $configPath" }
$config = Get-Content -LiteralPath $configPath -Raw -Encoding utf8 | ConvertFrom-Json

function Show-MissingTunnelClient {
    Write-Output 'tunnel-client was not found.'
    Write-Output 'tunnel-client is OpenAI''s daemon that connects a local MCP server to the OpenAI control plane over an outbound tunnel so ChatGPT web can reach it.'
    Write-Output 'Install tunnel-client and put it on PATH, or run .\setup-tunnel.ps1 -TunnelClientPath <path-to-tunnel-client.exe>.'
    Write-Output ''
    Write-Output 'Setup URLs:'
    Write-Output '  Tunnels management        : https://platform.openai.com/settings/organization/tunnels'
    Write-Output '  Runtime API keys          : https://platform.openai.com/settings/organization/api-keys'
    Write-Output '  ChatGPT connector settings: https://chatgpt.com/#settings/Connectors'
}

$tcExe = $null
if (-not [string]::IsNullOrWhiteSpace($TunnelClientPath)) {
    if ($TunnelClientPath.IndexOf([char]0) -ge 0) { throw 'Invalid -TunnelClientPath.' }
    $trimmed = $TunnelClientPath.Trim()
    if ($trimmed.StartsWith('~') -or $trimmed -match '\A[\\/]{2}' -or $trimmed -match '\A[A-Za-z]:(?![\\/])') {
        throw "Refusing unsupported -TunnelClientPath: $TunnelClientPath"
    }
    $psCwd = $ExecutionContext.SessionState.Path.CurrentFileSystemLocation.ProviderPath
    $fullTc = if ([System.IO.Path]::IsPathFullyQualified($trimmed)) {
        [System.IO.Path]::GetFullPath($trimmed)
    } else {
        [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($psCwd, $trimmed))
    }
    if (-not (Test-Path -LiteralPath $fullTc -PathType Leaf)) {
        Show-MissingTunnelClient
        Write-Output ''
        Write-Output "File not found: $fullTc"
        exit 1
    }
    $tcExe = $fullTc
} else {
    $cmd = Get-Command -Name 'tunnel-client' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $cmd) {
        Show-MissingTunnelClient
        exit 1
    }
    $tcExe = $cmd.Source
}

$resolvedProfileDir = $null
if (-not [string]::IsNullOrWhiteSpace($ProfileDir)) {
    if ($ProfileDir.IndexOf([char]0) -ge 0) { throw 'Invalid -ProfileDir.' }
    $trimmedDir = $ProfileDir.Trim()
    if ($trimmedDir.StartsWith('~') -or $trimmedDir -match '\A[\\/]{2}' -or $trimmedDir -match '\A[A-Za-z]:(?![\\/])') {
        throw "Refusing unsupported -ProfileDir: $ProfileDir"
    }
    $psCwd = $ExecutionContext.SessionState.Path.CurrentFileSystemLocation.ProviderPath
    $resolvedProfileDir = if ([System.IO.Path]::IsPathFullyQualified($trimmedDir)) {
        [System.IO.Path]::GetFullPath($trimmedDir)
    } else {
        [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($psCwd, $trimmedDir))
    }
    if (Test-Path -LiteralPath $resolvedProfileDir -PathType Leaf) {
        throw "Profile directory path points to an existing file: $resolvedProfileDir"
    }
}

foreach ($checkPath in @([string]$config.exe_path, [string]$config.state_dir)) {
    if ([string]::IsNullOrWhiteSpace($checkPath) -or $checkPath -match "['`"`r`n\0]") {
        throw 'Cannot build tunnel MCP command because an install path contains quotes or control characters.'
    }
}

Write-Output 'Create or inspect a tunnel at: https://platform.openai.com/settings/organization/tunnels'
$rawTunnelId = Read-Host 'Tunnel ID (tunnel_ followed by 32 lowercase hex characters)'
if ($null -eq $rawTunnelId) { $rawTunnelId = '' }
$tunnelId = $rawTunnelId.Trim().Trim('"', "'")
if ($tunnelId -cnotmatch '\Atunnel_[0-9a-f]{32}\z') {
    Write-Output "Invalid tunnel ID. Expected 'tunnel_' followed by 32 lowercase hexadecimal characters."
    exit 1
}

Write-Output 'Create a runtime API key (Tunnels Read + Use; not an Admin key) at: https://platform.openai.com/settings/organization/api-keys'
if ([Console]::IsInputRedirected) {
    $stdinKey = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($stdinKey)) {
        Write-Output 'Runtime API key cannot be empty.'
        exit 1
    }
    $secureKey = [System.Security.SecureString]::new()
    foreach ($ch in $stdinKey.Trim().ToCharArray()) { $secureKey.AppendChar($ch) }
    $secureKey.MakeReadOnly()
    $stdinKey = $null
} else {
    $secureKey = Read-Host -Prompt 'Runtime API key (input is hidden)' -AsSecureString
}

$keyFilePath = Join-Path $config.state_dir 'tunnel-runtime.key'
if ($keyFilePath -match "['`"`r`n\0]") {
    throw 'Cannot store runtime API key because state_dir contains quotes or control characters.'
}
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
try {
    $plainKey = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    if ([string]::IsNullOrWhiteSpace($plainKey)) {
        Write-Output 'Runtime API key cannot be empty.'
        exit 1
    }
    $plainKey = $plainKey.Trim()
    if ($plainKey -match '[\r\n\0]') {
        Write-Output 'Runtime API key must be a single line.'
        exit 1
    }
    [System.IO.File]::WriteAllText($keyFilePath, $plainKey, $utf8NoBom)
    $plainKey = $null
} finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $secureKey.Dispose()
}

try {
    $acl = Get-Acl -LiteralPath $keyFilePath
    $acl.SetAccessRuleProtection($true, $false)
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $currentSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.SetAccessRule($rule)
    Set-Acl -LiteralPath $keyFilePath -AclObject $acl
} catch {
    Write-Output "Note: could not tighten ACL on $keyFilePath; keep your install folder private."
}

$exeFwd = ([string]$config.exe_path).Replace('\', '/')
$stateFwd = ([string]$config.state_dir).Replace('\', '/')
$mcpCommand = "'$exeFwd' --state-dir '$stateFwd' mcp --principal executor:default"
$keyRef = 'file:' + $keyFilePath.Replace('\', '/')

$initArgs = [System.Collections.Generic.List[string]]::new()
$initArgs.Add('init')
$initArgs.Add('--sample')
$initArgs.Add('sample_mcp_stdio_local')
$initArgs.Add('--profile')
$initArgs.Add($TunnelProfile)
$initArgs.Add('--tunnel-id')
$initArgs.Add($tunnelId)
$initArgs.Add('--control-plane-api-key-ref')
$initArgs.Add($keyRef)
$initArgs.Add('--mcp-command')
$initArgs.Add($mcpCommand)
if (-not [string]::IsNullOrWhiteSpace($resolvedProfileDir)) {
    $initArgs.Add('--profile-dir')
    $initArgs.Add($resolvedProfileDir)
}
if ($Force) { $initArgs.Add('--force') }

& $tcExe @initArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$tunnelConfig = [ordered]@{
    schema_version     = 1
    profile_name       = $TunnelProfile
    tunnel_client_path = $tcExe
}
if (-not [string]::IsNullOrWhiteSpace($resolvedProfileDir)) {
    $tunnelConfig.profile_dir = $resolvedProfileDir
}
$tunnelConfigPath = Join-Path $PSScriptRoot 'tunnel.json'
[System.IO.File]::WriteAllText($tunnelConfigPath, ($tunnelConfig | ConvertTo-Json -Depth 4) + "`n", $utf8NoBom)

$doctorArgs = [System.Collections.Generic.List[string]]::new()
$doctorArgs.Add('doctor')
$doctorArgs.Add('--profile')
$doctorArgs.Add($TunnelProfile)
$doctorArgs.Add('--explain')
if (-not [string]::IsNullOrWhiteSpace($resolvedProfileDir)) {
    $doctorArgs.Add('--profile-dir')
    $doctorArgs.Add($resolvedProfileDir)
}

& $tcExe @doctorArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output ''
Write-Output 'Tunnel profile is ready. Two steps left:'
Write-Output '  1. Start the tunnel and leave the window open:'
Write-Output '       .\start-tunnel.ps1'
Write-Output '  2. While the tunnel is running, open https://chatgpt.com/#settings/Connectors, add the tunnel as a connector (or refresh it) - the connector must show 46 tools.'
'@

    $startTunnelContent = @'
#Requires -Version 7
[CmdletBinding()]
param(
    [Alias('Profile')]
    [string]$TunnelProfile,

    [string]$TunnelClientPath,

    [string]$ProfileDir
)

$ErrorActionPreference = 'Stop'
$configPath = Join-Path $PSScriptRoot 'install.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Missing installation config: $configPath" }

$tunnelConfigPath = Join-Path $PSScriptRoot 'tunnel.json'
$tunnelConfig = $null
if (Test-Path -LiteralPath $tunnelConfigPath -PathType Leaf) {
    $tunnelConfig = Get-Content -LiteralPath $tunnelConfigPath -Raw -Encoding utf8 | ConvertFrom-Json
} elseif ([string]::IsNullOrWhiteSpace($TunnelProfile)) {
    throw 'Tunnel is not configured yet. Run .\setup-tunnel.ps1 first.'
}

$effectiveProfile = if (-not [string]::IsNullOrWhiteSpace($TunnelProfile)) { $TunnelProfile } else { [string]$tunnelConfig.profile_name }
if ([string]::IsNullOrWhiteSpace($effectiveProfile) -or $effectiveProfile -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z') {
    throw "Invalid tunnel profile name '$effectiveProfile'."
}

$effectiveProfileDir = $null
if (-not [string]::IsNullOrWhiteSpace($ProfileDir)) {
    if ($ProfileDir.IndexOf([char]0) -ge 0) { throw 'Invalid -ProfileDir.' }
    $trimmedDir = $ProfileDir.Trim()
    if ($trimmedDir.StartsWith('~') -or $trimmedDir -match '\A[\\/]{2}' -or $trimmedDir -match '\A[A-Za-z]:(?![\\/])') {
        throw "Refusing unsupported -ProfileDir: $ProfileDir"
    }
    $psCwd = $ExecutionContext.SessionState.Path.CurrentFileSystemLocation.ProviderPath
    $effectiveProfileDir = if ([System.IO.Path]::IsPathFullyQualified($trimmedDir)) {
        [System.IO.Path]::GetFullPath($trimmedDir)
    } else {
        [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($psCwd, $trimmedDir))
    }
} elseif ($null -ne $tunnelConfig -and $null -ne $tunnelConfig.PSObject.Properties['profile_dir'] -and -not [string]::IsNullOrWhiteSpace([string]$tunnelConfig.profile_dir)) {
    $effectiveProfileDir = [string]$tunnelConfig.profile_dir
}

$tcExe = $null
if (-not [string]::IsNullOrWhiteSpace($TunnelClientPath)) {
    if ($TunnelClientPath.IndexOf([char]0) -ge 0) { throw 'Invalid -TunnelClientPath.' }
    $trimmed = $TunnelClientPath.Trim()
    if ($trimmed.StartsWith('~') -or $trimmed -match '\A[\\/]{2}' -or $trimmed -match '\A[A-Za-z]:(?![\\/])') {
        throw "Refusing unsupported -TunnelClientPath: $TunnelClientPath"
    }
    $psCwd = $ExecutionContext.SessionState.Path.CurrentFileSystemLocation.ProviderPath
    $tcExe = if ([System.IO.Path]::IsPathFullyQualified($trimmed)) {
        [System.IO.Path]::GetFullPath($trimmed)
    } else {
        [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($psCwd, $trimmed))
    }
    if (-not (Test-Path -LiteralPath $tcExe -PathType Leaf)) {
        throw "tunnel-client not found: $tcExe"
    }
} elseif ($null -ne $tunnelConfig -and $null -ne $tunnelConfig.PSObject.Properties['tunnel_client_path'] -and (Test-Path -LiteralPath ([string]$tunnelConfig.tunnel_client_path) -PathType Leaf)) {
    $tcExe = [string]$tunnelConfig.tunnel_client_path
} else {
    $cmd = Get-Command -Name 'tunnel-client' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $cmd) {
        throw 'tunnel-client was not found on PATH. Pass -TunnelClientPath or re-run .\setup-tunnel.ps1.'
    }
    $tcExe = $cmd.Source
}

$runArgs = [System.Collections.Generic.List[string]]::new()
$runArgs.Add('run')
$runArgs.Add('--profile')
$runArgs.Add($effectiveProfile)
if (-not [string]::IsNullOrWhiteSpace($effectiveProfileDir)) {
    $runArgs.Add('--profile-dir')
    $runArgs.Add($effectiveProfileDir)
}

& $tcExe @runArgs
exit $LASTEXITCODE
'@

    $generatedFiles = @(
        @{ Path = $existingInstallJsonPath; Content = ($installConfig | ConvertTo-Json -Depth 4) + "`n" },
        @{ Path = (Join-Path $resolvedInstallDir 'start.ps1'); Content = $startContent + "`n" },
        @{ Path = (Join-Path $resolvedInstallDir 'status.ps1'); Content = $statusContent + "`n" },
        @{ Path = (Join-Path $resolvedInstallDir 'apply.ps1'); Content = $applyContent + "`n" },
        @{ Path = (Join-Path $resolvedInstallDir 'rollback.ps1'); Content = $rollbackContent + "`n" },
        @{ Path = (Join-Path $resolvedInstallDir 'setup-tunnel.ps1'); Content = $setupTunnelContent + "`n" },
        @{ Path = (Join-Path $resolvedInstallDir 'start-tunnel.ps1'); Content = $startTunnelContent + "`n" },
        @{ Path = (Join-Path $resolvedInstallDir 'start-worker.ps1'); Content = $startWorkerContent + "`n" },
        @{ Path = (Join-Path $resolvedInstallDir 'setup-worker.ps1'); Content = $setupWorkerContent + "`n" },
        @{ Path = (Join-Path $resolvedInstallDir 'new-grant.ps1'); Content = $newGrantContent + "`n" },
        @{ Path = (Join-Path $resolvedInstallDir 'environment-check.ps1'); Content = $envCheckContent + "`n" }
    )
    foreach ($file in $generatedFiles) {
        Write-Utf8NoBom $file.Path $file.Content
        $createdFreshItems.Add($file.Path)
    }

    foreach ($dirPath in $proSubdirs) { Ensure-DirectoryTracked $dirPath $createdProDirs }

    $installCommitted = $true

    # 6. Print the summary. No path is printed inside a command: a path can hold characters that end a quoted string.

    Write-Output ''
    Write-Output "Installed to: $resolvedInstallDir"
    Write-Output "  Binary : $installedExe"
    Write-Output "  Runtime: $targetRuntime"
    Write-Output "  State  : $targetState"
    Write-Output ''
    Write-Output "Project: $resolvedProjectPath"
    Write-Output "Project ID: $projectId"
    if ($missingTestRunPrereqs.Count -gt 0) {
        Write-Output ''
        Write-Output 'Installed. Reading the project and writing reports under _pro\ work now.'
        Write-Output 'Queued test runs do NOT work yet on this PC. Missing:'
        foreach ($item in $missingTestRunPrereqs) { Write-Output "  - $item" }
    }
    if ($gitMissing) {
        Write-Output ''
        Write-Output 'Optional: Git for Windows was not found at C:\Program Files\Git\cmd\git.exe or on PATH (needed only for the Git read tools; test runs do not require it). Install: winget install --id Git.Git  (https://git-scm.com/download/win)'
    }
    Write-Output ''
    Write-Output 'Next: open PowerShell 7 in the install folder:'
    if (-not $canBuildRuntime) {
        Write-Output '  1. .\start.ps1             (checks environment and creates a 4-hour pro-agent grant; run .\setup-worker.ps1 after installing the missing items above to enable test runs)'
    } elseif ($missingTestRunPrereqs.Count -gt 0) {
        Write-Output '  1. .\start.ps1             (checks environment, creates a 4-hour pro-agent grant, and starts the worker; install the missing items above before running tests)'
    } else {
        Write-Output '  1. .\start.ps1             (checks environment, creates a 4-hour pro-agent grant, and starts the local worker; --allow-work-exec is off by default)'
    }
    Write-Output '  2. .\setup-tunnel.ps1      (for ChatGPT web: creates and checks the tunnel-client profile, then start it with .\start-tunnel.ps1)'
    Write-Output '  3. .\apply.ps1 <workspace> (previews a workspace diff, asks y/N, applies atomically, and prints the .\rollback.ps1 command)'
    Write-Output ''
    Write-Output 'Run .\status.ps1 at any time to check versions, prerequisites, and _pro\ workspaces/outputs.'
    Write-Output ''
    Write-Output 'For an MCP client that starts a local program (stdio), configure:'
    Write-Output "  Program  : $installedExe"
    Write-Output "  Arguments: --state-dir=$targetState"
    Write-Output '             mcp'
    Write-Output '             --principal=executor:default'
    Write-Output ''
    Write-Output 'Boundary rule: under pro-review, the remote model creates new files only under _pro\ (never _pro\inbox\). Under pro-agent, it can also edit copies inside _pro\work\<workspace>\ and export diffs; project files stay read-only until you run .\apply.ps1 <workspace>.'
} catch {
    $originalError = $_
    if (-not $installCommitted) {
        $rollbackErrors = [System.Collections.Generic.List[string]]::new()
        Remove-EmptyDirsDeepestFirst $createdProDirs $rollbackErrors

        for ($i = $createdFreshItems.Count - 1; $i -ge 0; $i--) {
            $p = $createdFreshItems[$i]
            try { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force } }
            catch { $rollbackErrors.Add("Failed removing created path '$p': $($_.Exception.Message)") }
        }
        for ($i = $movedToFinal.Count - 1; $i -ge 0; $i--) {
            $pair = $movedToFinal[$i]
            try { if (Test-Path -LiteralPath $pair.Final) { Rename-DirectoryNoOverwrite $pair.Final $pair.New } }
            catch { $rollbackErrors.Add("Failed rolling back '$($pair.Final)' to '$($pair.New)': $($_.Exception.Message)") }
        }
        foreach ($stagedPath in @($stageRuntime, $stageBin)) {
            try { if (Test-Path -LiteralPath $stagedPath) { Remove-Item -LiteralPath $stagedPath -Recurse -Force } }
            catch { $rollbackErrors.Add("Failed removing staging directory '$stagedPath': $($_.Exception.Message)") }
        }
        Remove-EmptyDirsDeepestFirst $createdDirs $rollbackErrors

        if ($rollbackErrors.Count -gt 0) {
            throw ("Installation failed: $($originalError.Exception.Message)`nRollback also encountered errors:`n  - " + ($rollbackErrors -join "`n  - "))
        }
    }
    throw
} finally {
    if (Test-Path -LiteralPath $workDir) {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
