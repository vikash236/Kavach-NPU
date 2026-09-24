<#
.SYNOPSIS
    Kavach-NPU Production Uninstaller Script.
.DESCRIPTION
    Safely stops and unregisters the Kavach-NPU Windows Service, flushes dynamic WFP
    firewall rules, and removes the deployed files.
.PARAMETER InstallDir
    Target directory to remove. Defaults to "C:\Program Files\Kavach-NPU".
.EXAMPLE
    .\tools\uninstall.ps1
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\Kavach-NPU"
)

$ErrorActionPreference = "Stop"

function Test-IsElevated {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "        Kavach-NPU: Production Uninstallation Tool          " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if (-not (Test-IsElevated)) {
    Write-Host "[ERROR] Administrator privileges are required to uninstall Kavach-NPU." -ForegroundColor Red
    Write-Host "        Please right-click PowerShell and choose 'Run as Administrator'." -ForegroundColor Yellow
    exit 1
}

# 1. Stop and Delete Service via service-manager.ps1
Write-Host "`n[1/2] Stopping and removing Windows Service..." -ForegroundColor Green
$serviceScript = Join-Path $PSScriptRoot "service-manager.ps1"
if (Test-Path $serviceScript) {
    & $serviceScript -Action Uninstall
} else {
    sc.exe stop KavachNpuSentinel | Out-Null
    Start-Sleep -Seconds 2
    sc.exe delete KavachNpuSentinel | Out-Null
}

# 2. Clean Up Installation Directory
Write-Host "`n[2/2] Removing installed files from $InstallDir..." -ForegroundColor Green
if (Test-Path $InstallDir) {
    try {
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-Host "      Successfully removed $InstallDir." -ForegroundColor Gray
    } catch {
        Write-Host "[WARN] Could not remove some files in $InstallDir (in use). Please reboot or remove manually." -ForegroundColor Yellow
    }
} else {
    Write-Host "      Installation directory does not exist. Nothing to remove." -ForegroundColor Gray
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "         Kavach-NPU Successfully Uninstalled!               " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
