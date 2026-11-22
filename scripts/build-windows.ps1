# Build the pinned Windows target with the matching host linker.
[CmdletBinding()]
param(
    [string]$SourceRoot = (Join-Path $PSScriptRoot '..'),
    [string]$LlvmMingwBin,
    [switch]$Offline,
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$previousPath = $env:PATH
$previousGnuLinker = $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER
Push-Location -LiteralPath (Resolve-Path -LiteralPath $SourceRoot).Path
try {
    if ($LlvmMingwBin) {
        $llvmBin = (Resolve-Path -LiteralPath $LlvmMingwBin).Path
        $env:PATH = $llvmBin + [IO.Path]::PathSeparator + $env:PATH
    }

    if (!(Get-Command 'x86_64-w64-mingw32-clang' -ErrorAction SilentlyContinue) -or
        !(Get-Command 'llvm-ar' -ErrorAction SilentlyContinue)) {
        throw 'Put LLVM-MinGW UCRT on PATH or specify -LlvmMingwBin.'
    }

    $version = & rustc -vV
    if ($LASTEXITCODE) { throw 'Could not inspect the pinned Rust toolchain.' }
    if ($version -contains 'host: x86_64-pc-windows-gnu' -and !$previousGnuLinker) {
        $sysroot = & rustc --print sysroot
        if ($LASTEXITCODE) { throw 'Could not resolve the pinned Rust sysroot.' }
        $bundled = Join-Path $sysroot 'lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/x86_64-w64-mingw32-gcc.exe'
        if (!(Test-Path -LiteralPath $bundled -PathType Leaf)) {
            throw 'The GNU host compiler requires its bundled GCC or an explicit CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER.'
        }
        # Cargo builds proc macros for the host and the application for gnullvm.
        $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = $bundled
    }

    $options = @('--workspace', '--locked', '--release')
    if ($Offline) { $options += '--offline' }
    & cargo build @options
    if ($LASTEXITCODE) { throw "cargo build failed ($LASTEXITCODE)." }
    if ($Test) {
        & cargo test @options
        if ($LASTEXITCODE) { throw "cargo test failed ($LASTEXITCODE)." }
    }
}
finally {
    Pop-Location
    $env:PATH = $previousPath
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = $previousGnuLinker
}
