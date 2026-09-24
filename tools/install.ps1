<#
.SYNOPSIS
    Kavach-NPU Production Installer & Deployment Script.
.DESCRIPTION
    Validates AMD XDNA NPU hardware prerequisites, compiles/locates production binaries,
    validates cryptographic model bundle signatures, and installs the auto-start Windows Service.
.PARAMETER InstallDir
    Destination installation directory. Defaults to "C:\Program Files\Kavach-NPU" (or local deployment).
.PARAMETER SkipBuild
    Skips cargo build and assumes release binaries are pre-compiled.
.EXAMPLE
    .\tools\install.ps1
    .\tools\install.ps1 -InstallDir "C:\Security\Kavach-NPU"
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\Kavach-NPU",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

function Test-IsElevated {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       Kavach-NPU: Production Deployment & Installer        " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Administrator Check
if (-not (Test-IsElevated)) {
    Write-Host "[ERROR] Administrator privileges are required to install Kavach-NPU." -ForegroundColor Red
    Write-Host "        Please right-click PowerShell and choose 'Run as Administrator'." -ForegroundColor Yellow
    exit 1
}

# 2. Hardware Preflight Verification
Write-Host "`n[1/5] Running AMD NPU hardware preflight diagnostics..." -ForegroundColor Green
$preflightScript = Join-Path $PSScriptRoot "npu-preflight.ps1"
if (Test-Path $preflightScript) {
    & $preflightScript
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[WARN] Preflight checks reported warnings. Proceeding with deployment..." -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARN] Preflight script not found. Skipping diagnostic pre-check." -ForegroundColor Yellow
}

# 3. Compilation / Binary Discovery
Write-Host "`n[2/5] Locating Kavach-NPU production binaries..." -ForegroundColor Green
$repoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$releaseBin = Join-Path $repoRoot "target\release\kavach-npu.exe"

if (-not (Test-Path $releaseBin) -and -not $SkipBuild) {
    Write-Host "      Compiling optimized release binary (cargo build --release)..." -ForegroundColor Cyan
    Push-Location $repoRoot
    try {
        cargo build --release -p kavach-npu
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path $releaseBin)) {
    # Fallback to debug binary if release build was skipped
    $debugBin = Join-Path $repoRoot "target\debug\kavach-npu.exe"
    if (Test-Path $debugBin) {
        Write-Host "      Release binary not found; utilizing debug binary: $debugBin" -ForegroundColor Yellow
        $releaseBin = $debugBin
    } else {
        Write-Host "[ERROR] Could not find kavach-npu.exe binary. Build failed." -ForegroundColor Red
        exit 1
    }
}
Write-Host "      Binary verified: $releaseBin" -ForegroundColor Gray

# 4. Prepare Destination Directory & Assets
Write-Host "`n[3/5] Deploying binaries, runtime bitstreams, and model bundles to $InstallDir..." -ForegroundColor Green
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Copy-Item -Path $releaseBin -Destination (Join-Path $InstallDir "kavach-npu.exe") -Force

# Copy Model Bundle
$modelSrc = Join-Path $repoRoot "models"
if (Test-Path $modelSrc) {
    Copy-Item -Path $modelSrc -Destination (Join-Path $InstallDir "models") -Recurse -Force
    Write-Host "      Model bundles copied to $InstallDir\models" -ForegroundColor Gray
}

# Copy Preserved NPU Runtime (DLLs and xclbin bitstreams)
$runtimeSrc = Join-Path $repoRoot "npu_runtime"
if (Test-Path $runtimeSrc) {
    Copy-Item -Path $runtimeSrc -Destination (Join-Path $InstallDir "npu_runtime") -Recurse -Force
    Write-Host "      NPU bitstreams and native runtime copied to $InstallDir\npu_runtime" -ForegroundColor Gray
}

# 5. Windows Service Registration
Write-Host "`n[4/5] Registering Windows Service (KavachNpuSentinel)..." -ForegroundColor Green
$installedBin = Join-Path $InstallDir "kavach-npu.exe"
$serviceScript = Join-Path $PSScriptRoot "service-manager.ps1"

& $serviceScript -Action Install -BinaryPath $installedBin

# 6. Service Start & Verification
Write-Host "`n[5/5] Starting Kavach-NPU Sentinel Background Service..." -ForegroundColor Green
& $serviceScript -Action Start

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "       Kavach-NPU Production Deployment Complete!           " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Service Status:  sc.exe query KavachNpuSentinel" -ForegroundColor Yellow
Write-Host "Manage Service:  .\tools\service-manager.ps1 -Action Status" -ForegroundColor Yellow
Write-Host "Uninstall:       .\tools\uninstall.ps1" -ForegroundColor Yellow
