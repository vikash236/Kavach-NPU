<#
.SYNOPSIS
    Kavach-NPU Windows Service Management Utility.
.DESCRIPTION
    Automates the installation, uninstallation, lifecycle management,
    and diagnostic inspection of the Kavach-NPU background Windows Service.
.PARAMETER Action
    The service management operation: Install, Uninstall, Start, Stop, Restart, Status, Logs.
.PARAMETER BinaryPath
    Optional explicit path to the kavach-npu.exe binary.
.EXAMPLE
    .\tools\service-manager.ps1 -Action Install
    .\tools\service-manager.ps1 -Action Start
    .\tools\service-manager.ps1 -Action Status
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("Install", "Uninstall", "Start", "Stop", "Restart", "Status", "Logs")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$BinaryPath
)

$ServiceName = "KavachNpuSentinel"
$ServiceDisplayName = "Kavach-NPU (कवच) Hardware-Enforced EDR Sentinel"
$ServiceDescription = "Hardware-accelerated Zero-Trust EDR utilizing AMD XDNA NPU for real-time ransomware, C2, and cross-boundary threat containment."

function Test-IsElevated {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-KavachBinary {
    if ($BinaryPath -and (Test-Path $BinaryPath)) {
        return (Resolve-Path $BinaryPath).Path
    }

    $releaseBin = Join-Path $PSScriptRoot "..\target\release\kavach-npu.exe"
    if (Test-Path $releaseBin) {
        return (Resolve-Path $releaseBin).Path
    }

    $debugBin = Join-Path $PSScriptRoot "..\target\debug\kavach-npu.exe"
    if (Test-Path $debugBin) {
        return (Resolve-Path $debugBin).Path
    }

    return $null
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         Kavach-NPU Windows Service Management Tool         " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if (-not (Test-IsElevated) -and ($Action -in @("Install", "Uninstall", "Start", "Stop", "Restart"))) {
    Write-Host "[ERROR] Administrator privileges are required to manage Windows Services." -ForegroundColor Red
    Write-Host "        Please re-run this script in an elevated PowerShell terminal (Run as Administrator)." -ForegroundColor Yellow
    exit 1
}

switch ($Action) {
    "Install" {
        $bin = Find-KavachBinary
        if (-not $bin) {
            Write-Host "[ERROR] Could not find kavach-npu.exe binary in target/release or target/debug." -ForegroundColor Red
            Write-Host "        Please build the workspace first: cargo build --release" -ForegroundColor Yellow
            exit 1
        }

        Write-Host "[1/4] Validating binary: $bin" -ForegroundColor Green
        
        # Verify model bundle presence
        $bundlePath = Join-Path $PSScriptRoot "..\models\active\kavach_multitask_int8.onnx"
        if (Test-Path $bundlePath) {
            Write-Host "[2/4] Active model bundle found: $bundlePath" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Model bundle not found at $bundlePath. Verify bundle configuration." -ForegroundColor Yellow
        }

        # Check if already installed
        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Host "[3/4] Service '$ServiceName' is already installed. Stopping and updating..." -ForegroundColor Yellow
            sc.exe stop $ServiceName | Out-Null
            Start-Sleep -Seconds 2
            sc.exe delete $ServiceName | Out-Null
            Start-Sleep -Seconds 1
        }

        Write-Host "[4/4] Creating Windows Service via SCM..." -ForegroundColor Green
        $binCmd = "`"$bin`" service run"
        $createRes = sc.exe create $ServiceName binPath= $binCmd start= auto DisplayName= $ServiceDisplayName
        Write-Host $createRes -ForegroundColor Gray

        # Set Description
        sc.exe description $ServiceName $ServiceDescription | Out-Null

        # Configure Recovery: Restart on failure (after 5s, 10s, 60s)
        sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/60000 | Out-Null

        Write-Host "`n[SUCCESS] Service '$ServiceName' successfully installed with Auto-Start!" -ForegroundColor Green
        Write-Host "          Run: .\tools\service-manager.ps1 -Action Start" -ForegroundColor Cyan
    }

    "Uninstall" {
        Write-Host "Stopping service if running..." -ForegroundColor Yellow
        sc.exe stop $ServiceName | Out-Null
        Start-Sleep -Seconds 2

        Write-Host "Deleting service '$ServiceName' from SCM..." -ForegroundColor Yellow
        $delRes = sc.exe delete $ServiceName
        Write-Host $delRes -ForegroundColor Gray
        Write-Host "`n[SUCCESS] Service '$ServiceName' uninstalled." -ForegroundColor Green
    }

    "Start" {
        Write-Host "Starting Windows Service '$ServiceName'..." -ForegroundColor Green
        $startRes = sc.exe start $ServiceName
        Write-Host $startRes -ForegroundColor Gray
        Start-Sleep -Seconds 2
        Get-Service -Name $ServiceName -ErrorAction SilentlyContinue | Format-Table -AutoSize
    }

    "Stop" {
        Write-Host "Stopping Windows Service '$ServiceName'..." -ForegroundColor Yellow
        $stopRes = sc.exe stop $ServiceName
        Write-Host $stopRes -ForegroundColor Gray
        Start-Sleep -Seconds 2
        Get-Service -Name $ServiceName -ErrorAction SilentlyContinue | Format-Table -AutoSize
    }

    "Restart" {
        Write-Host "Restarting Windows Service '$ServiceName'..." -ForegroundColor Yellow
        sc.exe stop $ServiceName | Out-Null
        Start-Sleep -Seconds 2
        sc.exe start $ServiceName | Out-Null
        Start-Sleep -Seconds 2
        Get-Service -Name $ServiceName -ErrorAction SilentlyContinue | Format-Table -AutoSize
    }

    "Status" {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host "Service Found:" -ForegroundColor Green
            $svc | Select-Object Name, DisplayName, Status, StartType | Format-List
            
            Write-Host "Detailed SCM Query:" -ForegroundColor Cyan
            sc.exe query $ServiceName
        } else {
            Write-Host "Service '$ServiceName' is NOT installed." -ForegroundColor Yellow
            Write-Host "To install, run: .\tools\service-manager.ps1 -Action Install" -ForegroundColor Cyan
        }
    }

    "Logs" {
        Write-Host "Querying Windows Event Log for recent Kavach events..." -ForegroundColor Cyan
        Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'} -MaxEvents 10 -ErrorAction SilentlyContinue | 
            Where-Object { $_.Message -like "*$ServiceName*" } | 
            Format-Table TimeCreated, Id, Message -Wrap
    }
}
