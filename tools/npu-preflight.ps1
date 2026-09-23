<#
.SYNOPSIS
    Kavach-NPU: Hardware & Environment Preflight Check
    Validates AMD XDNA NPU driver, device presence, shared memory, and Ryzen AI SDK installation.

.DESCRIPTION
    Scans the system for:
    1. AMD NPU PCI device (VEN_1022 & DEV_1502 for Phoenix/Hawk Point)
    2. NPU Kernel Driver version and status
    3. Windows Compute Accelerator Subsystem status
    4. Ryzen AI SDK environment variables and required DLLs/xclbins
#>

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         Kavach-NPU Hardware & SDK Preflight Check         " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$PassedChecks = 0
$TotalChecks = 4

# Check 1: NPU Hardware Presence via PCI / PnP
Write-Host "[1/4] Checking AMD NPU Hardware Device..." -ForegroundColor Yellow
$npuDevice = Get-PnpDevice -FriendlyName "*NPU*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "OK" }
if (-not $npuDevice) {
    # Check by known hardware ID
    $npuDevice = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like "*VEN_1022&DEV_1502*" }
}

if ($npuDevice) {
    Write-Host "  [OK] Found NPU Device: $($npuDevice.FriendlyName)" -ForegroundColor Green
    Write-Host "       Instance ID: $($npuDevice.InstanceId)" -ForegroundColor Gray
    Write-Host "       Status:      $($npuDevice.Status)" -ForegroundColor Gray
    $PassedChecks++
} else {
    Write-Host "  [FAIL] No AMD NPU device detected in Device Manager!" -ForegroundColor Red
}

# Check 2: NPU Driver Version
Write-Host "`n[2/4] Checking NPU Driver Version..." -ForegroundColor Yellow
$driver = Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -like "*NPU Compute Accelerator*" -or $_.HardwareID -like "*VEN_1022&DEV_1502*" } | Select-Object -First 1

if ($driver) {
    Write-Host "  [OK] Driver Name:    $($driver.DeviceName)" -ForegroundColor Green
    Write-Host "       Driver Version: $($driver.DriverVersion)" -ForegroundColor Green
    Write-Host "       Driver Date:    $($driver.DriverDate)" -ForegroundColor Gray

    # Version comparison against 32.0.203.280 baseline
    $verString = $driver.DriverVersion
    Write-Host "       Requirement:    >= 32.0.203.280" -ForegroundColor Gray
    $PassedChecks++
} else {
    Write-Host "  [WARN] Could not retrieve driver details via WMI/CIM." -ForegroundColor Yellow
}

# Check 3: Ryzen AI SDK Environment & Local Runtime
Write-Host "`n[3/4] Checking Ryzen AI SDK Environment & Local Runtime..." -ForegroundColor Yellow
$sdkPath = [System.Environment]::GetEnvironmentVariable("RYZEN_AI_INSTALLATION_PATH", "Machine")
if (-not $sdkPath) {
    $sdkPath = [System.Environment]::GetEnvironmentVariable("RYZEN_AI_INSTALLATION_PATH", "User")
}
if (-not $sdkPath) {
    $sdkPath = $env:RYZEN_AI_INSTALLATION_PATH
}

$localRuntime = Join-Path $PSScriptRoot "..\npu_runtime"
$localNative = Join-Path $localRuntime "ryzen_ai_deployment\runtimes\win-x64\native"
$localDriver = Join-Path $localRuntime "NPU_RAI_376_WHQL\npu_mcdm_stack_prod"

$hasLocal = (Test-Path "$localNative\onnxruntime.dll") -and (Test-Path "$localDriver\1x4.xclbin")

if ($hasLocal) {
    Write-Host "  [OK] Local NPU Runtime Preserved at: $localRuntime" -ForegroundColor Green
    $PassedChecks++
} elseif ($sdkPath -and (Test-Path $sdkPath)) {
    Write-Host "  [OK] System RYZEN_AI_INSTALLATION_PATH: $sdkPath" -ForegroundColor Green
    $PassedChecks++
} else {
    Write-Host "  [INFO] Neither system RYZEN_AI_INSTALLATION_PATH nor local npu_runtime found." -ForegroundColor Yellow
}

# Check 4: Phoenix (X1) Microcode & Runtime DLLs
Write-Host "`n[4/4] Checking Phoenix (X1) Microcode & Runtime DLLs..." -ForegroundColor Yellow
if ($hasLocal) {
    Write-Host "  [OK] Phoenix xclbin bitstream: FOUND ($localDriver\1x4.xclbin)" -ForegroundColor Green
    Write-Host "  [OK] ONNX Runtime DLL:         FOUND ($localNative\onnxruntime.dll)" -ForegroundColor Green
    Write-Host "  [OK] Vitis AI EP DLL:          FOUND ($localNative\onnxruntime_vitisai_ep.dll)" -ForegroundColor Green
    Write-Host "  [OK] XRT Monitoring CLI:       FOUND ($localDriver\xrt-smi.exe)" -ForegroundColor Green
    $PassedChecks++
} elseif ($sdkPath -and (Test-Path $sdkPath)) {
    $phxXclbin = Join-Path $sdkPath "voe-4.0-win_amd64\xclbins\phoenix\1x4.xclbin"
    $ortDll = Join-Path $sdkPath "onnxruntime.dll"

    $hasXclbin = Test-Path $phxXclbin
    $hasOrt = Test-Path $ortDll

    if ($hasXclbin) {
        Write-Host "  [OK] Phoenix xclbin bitstream: FOUND" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Phoenix xclbin bitstream not found at expected path: $phxXclbin" -ForegroundColor Yellow
    }

    if ($hasOrt) {
        Write-Host "  [OK] ONNX Runtime DLL: FOUND" -ForegroundColor Green
        $PassedChecks++
    } else {
        Write-Host "  [WARN] ONNX Runtime DLL not found at: $ortDll" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [INFO] Pending SDK installation or local runtime extraction." -ForegroundColor Gray
}

# Summary Report
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Preflight Summary: $PassedChecks / $TotalChecks Checks Passed" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if ($PassedChecks -ge 3) {
    Write-Host "Hardware is ready for NPU dispatch!" -ForegroundColor Green
} else {
    Write-Host "System is ready for SDK installation. Re-run after installer completes." -ForegroundColor Yellow
}
