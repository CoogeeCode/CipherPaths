<#
.SYNOPSIS
    Builds the cipherpaths CLI for Windows, x64 and ARM64 (64-bit only).

.DESCRIPTION
    Uses the Visual Studio generator bundled with the installed Visual
    Studio, so no vcvars/Developer Prompt setup is required. Produces:
        CommandLine\windows\x64\cipherpaths.exe
        CommandLine\windows\arm64\cipherpaths.exe

.PARAMETER Arch
    "x64", "arm64", or "all" (default).

.PARAMETER Config
    Build configuration, default "Release".
#>
param(
    [ValidateSet("x64", "arm64", "all")]
    [string]$Arch = "all",
    [string]$Config = "Release",
    [string]$Generator = "Visual Studio 18 2026"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$CommandLineDir = Join-Path $RepoRoot "CommandLine"

# Fall back to the CMake/Ninja bundled with Visual Studio if `cmake` isn't
# already on PATH (a standalone CMake install is not required).
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    $vsCMakeBin = "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
    $vsNinjaBin = "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
    if (Test-Path $vsCMakeBin) {
        $env:Path = "$vsCMakeBin;$vsNinjaBin;$env:Path"
    } else {
        throw "cmake not found on PATH and no bundled CMake found under Visual Studio 18. Install CMake or adjust this script's path."
    }
}

function Build-Arch([string]$arch) {
    $vsPlatform = if ($arch -eq "arm64") { "ARM64" } else { "x64" }
    $buildDir = Join-Path $RepoRoot "build-windows-$arch"
    $outSubdir = "windows/$arch"

    Write-Host "==> Configuring Windows/$arch ($Generator, platform $vsPlatform)" -ForegroundColor Cyan
    cmake -S "$RepoRoot" -B "$buildDir" -G $Generator -A $vsPlatform `
        "-DCIPHERPATHS_OUTPUT_SUBDIR=$outSubdir"
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed for $arch" }

    Write-Host "==> Building Windows/$arch ($Config)" -ForegroundColor Cyan
    cmake --build "$buildDir" --config $Config --target cipherpaths
    if ($LASTEXITCODE -ne 0) { throw "CMake build failed for $arch" }

    $exe = Join-Path $CommandLineDir "$outSubdir\cipherpaths.exe"
    if (-not (Test-Path $exe)) { throw "Expected output not found: $exe" }
    Write-Host "==> Built $exe" -ForegroundColor Green
}

$targets = if ($Arch -eq "all") { @("x64", "arm64") } else { @($Arch) }
foreach ($a in $targets) { Build-Arch $a }
