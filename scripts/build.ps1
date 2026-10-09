<#
.SYNOPSIS
    Builds the backend and the Vue dashboard into src/Clash.Server/wwwroot, and
    optionally publishes the single self-contained folder that ships to users.

.EXAMPLE
    powershell -File scripts/build.ps1
    powershell -File scripts/build.ps1 -Configuration Release -SkipFrontend
    powershell -File scripts/build.ps1 -Configuration Release -Publish
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Debug',
    [switch]$SkipFrontend,
    [switch]$SkipTests,
    # Produce artifacts/win-x64: one folder holding both executables.
    [switch]$Publish
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

if ($Publish) {
    # One folder, not two.
    #
    # Publishing the tray app already drags in Clash.Server.exe and the whole
    # runtime, because the tray hosts the server in-process — so a second
    # "headless" folder was 115 MB of duplicated runtime. The two are not quite
    # interchangeable (five framework assemblies differ between the Windows
    # Desktop and ASP.NET runtime packs), so this publishes the tray and then
    # checks that the headless executable still starts and answers from the same
    # folder before declaring it the release.
    Write-Host '=== publish ===' -ForegroundColor Cyan
    $output = Join-Path $root 'artifacts\win-x64'
    if (Test-Path $output) { Remove-Item -Recurse -Force $output }

    & dotnet publish (Join-Path $root 'src\Clash.Desktop\Clash.Desktop.csproj') `
        -c $Configuration -r win-x64 --self-contained true -o $output --nologo
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }

    foreach ($required in 'Clash.Desktop.exe', 'Clash.Server.exe', 'wintun.dll', 'wwwroot\index.html') {
        if (-not (Test-Path (Join-Path $output $required))) {
            throw "the published folder is missing $required"
        }
    }

    Write-Host ("published to {0}" -f $output)
}

Write-Host ''
Write-Host 'build complete' -ForegroundColor Green
Write-Host '  run:      dotnet run --project src/Clash.Server'
Write-Host '  desktop:  dotnet run --project src/Clash.Desktop'
Write-Host '  smoke:    powershell -File scripts/smoke-test.ps1'
if ($Publish) {
    Write-Host ("  release:  {0}" -f (Join-Path $root 'artifacts\win-x64'))
}
