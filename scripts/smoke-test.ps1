<#
.SYNOPSIS
    End-to-end smoke test for Clash for .NET.

.DESCRIPTION
    Starts the server with a generated configuration, exercises the Clash control
    API, then pushes real traffic through the mixed HTTP/SOCKS5 inbound to a local
    origin server. Reports a PASS/FAIL summary and always cleans up.

.EXAMPLE
    powershell -File scripts/smoke-test.ps1
#>
[CmdletBinding()]
param(
    [int]$ApiPort = 19090,
    [int]$MixedPort = 17890,
    [int]$TargetPort = 18080,
    [string]$Configuration = 'Debug',
    [switch]$KeepRunning
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$results = New-Object System.Collections.ArrayList
$serverProcess = $null
$targetJob = $null
$homeDir = Join-Path ([System.IO.Path]::GetTempPath()) ("clash-smoke-" + [Guid]::NewGuid().ToString('n').Substring(0, 8))

function Add-Result {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    $null = $results.Add([pscustomobject]@{ Name = $Name; Ok = $Ok; Detail = $Detail })
    $tag = if ($Ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("[{0}] {1}{2}" -f $tag, $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor $(if ($Ok) { 'Green' } else { 'Red' })
}

function Wait-ForHttp {
    param([string]$Url, [int]$TimeoutSeconds = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -TimeoutSec 3 -UseBasicParsing
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) { return $true }
        } catch {
            Start-Sleep -Milliseconds 400
        }
    }
    return $false
}

function Get-Api {
    param([string]$Path)
    return Invoke-RestMethod -Uri ("http://127.0.0.1:{0}{1}" -f $ApiPort, $Path) -TimeoutSec 10 -UseBasicParsing
}

try {
    # ── Prepare a home directory and configuration ───────────────────────────
    New-Item -ItemType Directory -Force -Path $homeDir | Out-Null
    $config = @"
mixed-port: $MixedPort
allow-lan: false
bind-address: '127.0.0.1'
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:$ApiPort
secret: ''
unified-delay: true
tcp-concurrent: true

dns:
  enable: false

proxies: []

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - DIRECT

rules:
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - MATCH,PROXY
"@
    $configPath = Join-Path $homeDir 'config.yaml'
    Set-Content -Path $configPath -Value $config -Encoding UTF8
    Write-Host "home: $homeDir"

    # ── Local origin server ─────────────────────────────────────────────────
    $targetJob = Start-Job -ScriptBlock {
        param($Port)
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://127.0.0.1:$Port/")
        $listener.Start()
        while ($listener.IsListening) {
            try {
                $context = $listener.GetContext()
                $bytes = [System.Text.Encoding]::UTF8.GetBytes("clash-smoke-ok")
                $context.Response.StatusCode = 200
                $context.Response.ContentType = 'text/plain'
                $context.Response.ContentLength64 = $bytes.Length
                $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $context.Response.OutputStream.Close()
            } catch {
                break
            }
        }
        $listener.Stop()
    } -ArgumentList $TargetPort

    if (-not (Wait-ForHttp -Url ("http://127.0.0.1:{0}/" -f $TargetPort) -TimeoutSeconds 30)) {
        Add-Result 'origin server reachable' $false 'the local origin server never came up'
    } else {
        Add-Result 'origin server reachable' $true ("http://127.0.0.1:$TargetPort/")
    }

    # ── Start the core ──────────────────────────────────────────────────────
    $dll = Join-Path $root "src\Clash.Server\bin\$Configuration\net10.0\Clash.Server.dll"
    $stdout = Join-Path $homeDir 'server.out.log'
    $stderr = Join-Path $homeDir 'server.err.log'

    if (Test-Path $dll) {
        $serverProcess = Start-Process -FilePath 'dotnet' `
            -ArgumentList @($dll, '--home', $homeDir) `
            -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    } else {
        $serverProcess = Start-Process -FilePath 'dotnet' `
            -ArgumentList @('run', '--project', (Join-Path $root 'src\Clash.Server'), '--', '--home', $homeDir) `
            -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    }

    if (-not (Wait-ForHttp -Url ("http://127.0.0.1:{0}/version" -f $ApiPort) -TimeoutSeconds 90)) {
        Add-Result 'core started' $false ("no response from /version; see {0}" -f $stderr)
        throw 'the core did not start'
    }
    Add-Result 'core started' $true ("pid {0}" -f $serverProcess.Id)

    # ── Control API ─────────────────────────────────────────────────────────
    $version = Get-Api '/version'
    Add-Result 'GET /version' ($null -ne $version.version) ("version=" + $version.version + " meta=" + $version.meta)

    $hello = Get-Api '/'
    Add-Result 'GET /' ($null -ne $hello) (($hello | ConvertTo-Json -Compress))

    $configs = Get-Api '/configs'
    Add-Result 'GET /configs' ($configs.mode -eq 'rule' -and $configs.'mixed-port' -eq $MixedPort) ("mode=" + $configs.mode + " mixed-port=" + $configs.'mixed-port')

    $proxies = Get-Api '/proxies'
    $names = @($proxies.proxies.PSObject.Properties.Name)
    $hasBuiltins = ($names -contains 'DIRECT') -and ($names -contains 'REJECT') -and ($names -contains 'GLOBAL') -and ($names -contains 'PROXY')
    Add-Result 'GET /proxies' $hasBuiltins ("adapters: " + ($names -join ', '))

    $rules = Get-Api '/rules'
    Add-Result 'GET /rules' (@($rules.rules).Count -ge 2) ("count=" + @($rules.rules).Count + " first=" + $rules.rules[0].type)

    $connections = Get-Api '/connections'
    Add-Result 'GET /connections' ($null -ne $connections.connections) ("uploadTotal=" + $connections.uploadTotal + " active=" + @($connections.connections).Count)

    # PATCH /configs must hot-swap the mode.
    Invoke-RestMethod -Uri ("http://127.0.0.1:{0}/configs" -f $ApiPort) -Method Patch -TimeoutSec 10 `
        -ContentType 'application/json' -Body '{"mode":"direct"}' | Out-Null
    $afterPatch = Get-Api '/configs'
    Add-Result 'PATCH /configs (mode)' ($afterPatch.mode -eq 'direct') ("mode=" + $afterPatch.mode)
    Invoke-RestMethod -Uri ("http://127.0.0.1:{0}/configs" -f $ApiPort) -Method Patch -TimeoutSec 10 `
        -ContentType 'application/json' -Body '{"mode":"rule"}' | Out-Null

    # Group selection.
    try {
        Invoke-RestMethod -Uri ("http://127.0.0.1:{0}/proxies/PROXY" -f $ApiPort) -Method Put -TimeoutSec 10 `
            -ContentType 'application/json' -Body '{"name":"DIRECT"}' | Out-Null
        $group = Get-Api '/proxies/PROXY'
        Add-Result 'PUT /proxies/:group' ($group.now -eq 'DIRECT') ("now=" + $group.now)
    } catch {
        Add-Result 'PUT /proxies/:group' $false $_.Exception.Message
    }

    # ── Real traffic through the proxy ──────────────────────────────────────
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (-not (Test-Path $curl)) { $curl = 'curl.exe' }
    $targetUrl = "http://127.0.0.1:$TargetPort/"

    $httpBody = & $curl -s -x ("http://127.0.0.1:{0}" -f $MixedPort) $targetUrl 2>&1
    Add-Result 'HTTP proxy (CONNECT-free absolute URI)' ($httpBody -eq 'clash-smoke-ok') ("body='" + ($httpBody -join '') + "'")

    $socksBody = & $curl -s --socks5-hostname ("127.0.0.1:{0}" -f $MixedPort) $targetUrl 2>&1
    Add-Result 'SOCKS5 inbound' ($socksBody -eq 'clash-smoke-ok') ("body='" + ($socksBody -join '') + "'")

    Start-Sleep -Milliseconds 700
    $afterTraffic = Get-Api '/connections'
    Add-Result 'traffic accounted' ([int64]$afterTraffic.uploadTotal -gt 0) ("uploadTotal=" + $afterTraffic.uploadTotal + " downloadTotal=" + $afterTraffic.downloadTotal)

    $stats = Get-Api '/version'
    Add-Result 'core still healthy after traffic' ($null -ne $stats.version) ''
}
catch {
    Add-Result 'smoke test' $false $_.Exception.Message
    if (Test-Path (Join-Path $homeDir 'server.err.log')) {
        Write-Host '--- server stderr (tail) ---' -ForegroundColor Yellow
        Get-Content (Join-Path $homeDir 'server.err.log') -Tail 30 | Write-Host
    }
    if (Test-Path (Join-Path $homeDir 'server.out.log')) {
        Write-Host '--- server stdout (tail) ---' -ForegroundColor Yellow
        Get-Content (Join-Path $homeDir 'server.out.log') -Tail 30 | Write-Host
    }
}
finally {
    if ($KeepRunning) {
        Write-Host "leaving the core running on api:$ApiPort mixed:$MixedPort (home: $homeDir)" -ForegroundColor Yellow
    } else {
        if ($serverProcess -and -not $serverProcess.HasExited) {
            try { Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue } catch { }
        }
        if ($targetJob) {
            try { Stop-Job $targetJob -ErrorAction SilentlyContinue; Remove-Job $targetJob -Force -ErrorAction SilentlyContinue } catch { }
        }
        # `dotnet run` leaves a child process behind; clear anything still holding the ports.
        foreach ($port in @($ApiPort, $MixedPort)) {
            try {
                Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty OwningProcess -Unique |
                    ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
            } catch { }
        }
        if (-not $KeepRunning -and (Test-Path $homeDir)) {
            try { Remove-Item -Recurse -Force $homeDir -ErrorAction SilentlyContinue } catch { }
        }
    }

    $failed = @($results | Where-Object { -not $_.Ok })
    Write-Host ''
    Write-Host ("=== {0} passed, {1} failed ===" -f (@($results | Where-Object { $_.Ok }).Count), $failed.Count) `
        -ForegroundColor $(if ($failed.Count -eq 0) { 'Green' } else { 'Red' })
    if ($failed.Count -gt 0) { exit 1 }
}
