<#
.SYNOPSIS
    One-click upgrade of the container deployment.

.DESCRIPTION
    Pulls the published image (or rebuilds it from this checkout), recreates the
    container against the existing data volume, and reports the version that
    ended up running. The data volume is never touched, so profiles, the config
    and the fake-IP store survive.

.EXAMPLE
    powershell -File scripts/docker-update.ps1

.EXAMPLE
    powershell -File scripts/docker-update.ps1 -Build     # from this checkout
#>
[CmdletBinding()]
param(
    # Rebuild from the local checkout instead of pulling the published image.
    [switch]$Build,

    # Keep the replaced image instead of pruning it.
    [switch]$KeepOldImage,

    # Where the compose file lives; defaults to the one in the repository root.
    [string]$ComposeFile
)

$ErrorActionPreference = 'Stop'

if (-not $ComposeFile) {
    $ComposeFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'docker-compose.yml'
}

function Write-Step([string]$Text) {
    Write-Host "==> $Text" -ForegroundColor Cyan
}

function Invoke-Compose {
    param([string[]]$Arguments)
    & $script:ComposeExe @($script:ComposeArgs + $Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw ("compose " + ($Arguments -join ' ') + " failed with exit code $LASTEXITCODE")
    }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'docker was not found on PATH. Install Docker Desktop (or the Docker engine) first.'
}

if (-not (Test-Path $ComposeFile)) {
    throw "no compose file at $ComposeFile"
}

# Compose v2 ships as a docker subcommand; v1 is a separate binary. Support both.
$script:ComposeExe = 'docker'
$script:ComposeArgs = @('compose')
& docker compose version *> $null
if ($LASTEXITCODE -ne 0) {
    if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
        Write-Host 'docker compose v2 not available; falling back to docker-compose' -ForegroundColor Yellow
        $script:ComposeExe = 'docker-compose'
        $script:ComposeArgs = @()
    } else {
        throw 'neither "docker compose" nor "docker-compose" is available'
    }
}

$composeFileArgs = @('-f', (Resolve-Path $ComposeFile).Path)

Write-Step 'current state'
Invoke-Compose ($composeFileArgs + @('ps'))

if ($Build) {
    Write-Step 'building the image from this checkout'
    Invoke-Compose ($composeFileArgs + @('build', '--pull'))
} else {
    Write-Step 'pulling the published image'
    Invoke-Compose ($composeFileArgs + @('pull'))
}

Write-Step 'recreating the container'
# `up -d` only recreates what changed, and leaves the volume alone.
Invoke-Compose ($composeFileArgs + @('up', '-d', '--remove-orphans'))

if (-not $KeepOldImage) {
    Write-Step 'removing the image that is no longer referenced'
    # Dangling images only: a running or tagged image is never touched.
    & docker image prune --force --filter 'dangling=true' | Out-Null
}

Write-Step 'waiting for the core to answer'
$port = 9090
$deadline = (Get-Date).AddSeconds(60)
$version = $null
while ((Get-Date) -lt $deadline) {
    try {
        $version = Invoke-RestMethod -Uri "http://127.0.0.1:$port/version" -TimeoutSec 3
        break
    } catch {
        Start-Sleep -Milliseconds 750
    }
}

if ($version) {
    Write-Host ''
    Write-Host ("upgraded: core version {0} is answering on port {1}" -f $version.version, $port) -ForegroundColor Green
    Write-Host ("dashboard: http://127.0.0.1:{0}/ui" -f $port)
} else {
    Write-Host ''
    Write-Host 'the container started but the core is not answering yet.' -ForegroundColor Yellow
    Write-Host "check the logs: $($script:ComposeExe) $($script:ComposeArgs -join ' ') -f $ComposeFile logs --tail 50"
    exit 1
}
