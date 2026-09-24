<#
.SYNOPSIS
    Kavach-NPU Release Packaging Script.
.DESCRIPTION
    Packages optimized release binaries, signed models, tools, and runtime bitstreams
    into a distribution zip file for GitHub Releases.
#>

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$distBase = Join-Path $repoRoot "dist"
$distDir = Join-Path $distBase "Kavach-NPU-v1.0.0-win-x64"
$zipPath = Join-Path $distBase "Kavach-NPU-v1.0.0-win-x64.zip"

Write-Host "Creating clean distribution folder: $distDir..." -ForegroundColor Cyan
if (Test-Path $distBase) {
    Remove-Item -Recurse -Force $distBase
}
New-Item -ItemType Directory -Path $distDir -Force | Out-Null

Write-Host "Copying optimized release binaries..." -ForegroundColor Green
Copy-Item (Join-Path $repoRoot "target\release\kavach-npu.exe") -Destination $distDir
Copy-Item (Join-Path $repoRoot "target\release\threat-injector.exe") -Destination $distDir
Copy-Item (Join-Path $repoRoot "target\release\kavach-pack.exe") -Destination $distDir
Copy-Item (Join-Path $repoRoot "README.md") -Destination $distDir
Copy-Item (Join-Path $repoRoot "LICENSE") -Destination $distDir

Write-Host "Copying model bundles..." -ForegroundColor Green
Copy-Item (Join-Path $repoRoot "models") -Destination $distDir -Recurse

Write-Host "Copying NPU runtime bitstreams and DLLs..." -ForegroundColor Green
Copy-Item (Join-Path $repoRoot "npu_runtime") -Destination $distDir -Recurse

Write-Host "Copying deployment and testing tools..." -ForegroundColor Green
Copy-Item (Join-Path $repoRoot "tools") -Destination $distDir -Recurse

Write-Host "Compressing distribution zip: $zipPath..." -ForegroundColor Cyan
Compress-Archive -Path $distDir -DestinationPath $zipPath -Force

$sizeMb = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
Write-Host "`n[SUCCESS] Package created successfully!" -ForegroundColor Green
Write-Host "          File: $zipPath" -ForegroundColor Yellow
Write-Host "          Size: $sizeMb MB" -ForegroundColor Yellow
