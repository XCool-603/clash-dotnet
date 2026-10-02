<#
.SYNOPSIS
    Builds the backend and the Vue dashboard into src/Clash.Server/wwwroot.

.EXAMPLE
    powershell -File scripts/build.ps1
    powershell -File scripts/build.ps1 -Configuration Release -SkipFrontend
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Debug',
    [switch]$SkipFrontend,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

Write-Host '=== backend ===' -ForegroundColor Cyan
& dotnet build (Join-Path $root 'Clash.slnx') -c $Configuration --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet build failed with exit code $LASTEXITCODE" }

if (-not $SkipTests) {
    Write-Host '=== tests ===' -ForegroundColor Cyan
    & dotnet test (Join-Path $root 'Clash.slnx') -c $Configuration --nologo --no-build
    if ($LASTEXITCODE -ne 0) { throw "dotnet test failed with exit code $LASTEXITCODE" }
}

if (-not $SkipFrontend) {
    Write-Host '=== dashboard ===' -ForegroundColor Cyan
    $web = Join-Path $root 'web'

    if (-not (Test-Path (Join-Path $web 'node_modules'))) {
        Write-Host 'installing npm dependencies...'
        & npm --prefix $web install
        if ($LASTEXITCODE -ne 0) { throw "npm install failed with exit code $LASTEXITCODE" }
    }

    & npm --prefix $web run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build failed with exit code $LASTEXITCODE" }

    $index = Join-Path $root 'src\Clash.Server\wwwroot\index.html'
    if (-not (Test-Path $index)) { throw "the dashboard build did not emit $index" }
    Write-Host "dashboard emitted to src/Clash.Server/wwwroot"
}

Write-Host ''
Write-Host 'build complete' -ForegroundColor Green
Write-Host '  run:      dotnet run --project src/Clash.Server'
Write-Host '  desktop:  dotnet run --project src/Clash.Desktop'
Write-Host '  smoke:    powershell -File scripts/smoke-test.ps1'
