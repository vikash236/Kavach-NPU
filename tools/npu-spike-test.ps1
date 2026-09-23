<#
.SYNOPSIS
    Kavach-NPU Hardware Spike & Benchmark Runner
    Runs continuous hardware NPU tests so you can observe the compute graph and memory spikes in Windows Task Manager.
#>

param(
    [int]$Iterations = 8
)

$npuDir = (Resolve-Path "$PSScriptRoot\..\npu_runtime\NPU_RAI_376_WHQL\npu_mcdm_stack_prod").Path
$xrtSmi = Join-Path $npuDir "xrt-smi.exe"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Kavach-NPU: Hardware NPU Workload & Task Manager Spike   " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Switch to Task Manager -> Performance -> NPU (Compute Accelerator Device) NOW!`n" -ForegroundColor Yellow

Push-Location $npuDir
try {
    for ($i = 1; $i -le $Iterations; $i++) {
        Write-Host "[$i/$Iterations] Dispatching NPU AIE tile workload (Latency & 14,800 op/s throughput test)..." -ForegroundColor Green
        & $xrtSmi validate --batch
    }
} finally {
    Pop-Location
}

Write-Host "`nHardware NPU dispatch loop complete!" -ForegroundColor Cyan
