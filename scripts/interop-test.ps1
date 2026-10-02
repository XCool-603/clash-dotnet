<#
.SYNOPSIS
    Interoperability test: drives this core's outbound protocols against a real
    reference server (Xray-core) instead of a fake one.

.DESCRIPTION
    The unit tests in tests/Clash.Tests assert wire framing against hand-written
    fake servers. That proves the framing is self-consistent, not that another
    implementation accepts it. This script closes that gap: it starts a real
    Xray-core with one inbound per protocol, points a Clash configuration at
    those inbounds, and pushes HTTP traffic through the mixed inbound for every
    protocol in turn.

    Traffic path per protocol:
        curl -> mixed inbound -> <protocol> adapter -> Xray inbound
             -> freedom outbound -> local origin server

    A protocol whose adapter does not exist yet is reported as SKIP (the core
    logs "skipping proxy" and the group has no such member).

.PARAMETER Protocol
    Which adapters to exercise. Each name maps to an Xray inbound declared below.

.PARAMETER XrayDir
    Directory holding xray.exe and the generated server.json. Defaults to
    %TEMP%\clash-interop; pass -Download to fetch Xray-core there first.

.EXAMPLE
    pwsh -File scripts/interop-test.ps1 -Download
    pwsh -File scripts/interop-test.ps1 -Protocol vmess,vless
#>
[CmdletBinding()]
param(
    [string[]]$Protocol = @('trojan', 'vmess', 'vmess-ws', 'vless'),
    [int]$ApiPort = 19190,
    [int]$MixedPort = 17990,
    [int]$OriginPort = 18081,
    [string]$XrayDir = (Join-Path $env:TEMP 'clash-interop'),
    [string]$SingBoxDir = (Join-Path $env:TEMP 'clash-interop-sb'),
    [string]$Configuration = 'Debug',
    [switch]$Download,
    [switch]$KeepLogs,
    [switch]$KeepRunning
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$results = New-Object System.Collections.ArrayList
$core = $null
$originJob = $null
$udpEchoJob = $null

# Protocols whose adapters are required to carry datagrams. A protocol missing
# from this list is allowed to advertise udp=false (and is then skipped by the
# datagram probe); a protocol on it that stops advertising UDP fails the run.
$UdpExpected = @(
    'trojan',
    'vmess', 'vmess-ws', 'vmess-tls',
    'vless', 'vless-ws', 'vless-tls'
)
$xray = $null
$singbox = $null
$homeDir = Join-Path ([System.IO.Path]::GetTempPath()) ("clash-interop-" + [Guid]::NewGuid().ToString('n').Substring(0, 8))

# A fixed UUID/password keeps the Xray config and the Clash config in step.
$uuid = 'b831381d-6324-4d53-ad4f-8cda48b30811'
$password = 'test-password'

# name -> which reference server hosts it, and the inbound port.
# Xray-core covers the v2ray family; sing-box covers the newer protocols
# (anytls, hysteria2, tuic) that Xray does not implement as an inbound.
$inbounds = [ordered]@{
    'trojan'    = @{ Port = 20004; Server = 'xray' }
    'vmess'     = @{ Port = 20002; Server = 'xray' }
    'vmess-ws'  = @{ Port = 20003; Server = 'xray' }
    'vmess-tls' = @{ Port = 20007; Server = 'xray' }
    'vless'     = @{ Port = 20001; Server = 'xray' }
    'vless-ws'  = @{ Port = 20006; Server = 'xray' }
    'vless-tls' = @{ Port = 20005; Server = 'xray' }
    'anytls'    = @{ Port = 21001; Server = 'singbox' }
    'hysteria2' = @{ Port = 21002; Server = 'singbox' }
    'tuic'      = @{ Port = 21003; Server = 'singbox' }
}

function Add-Result {
    param([string]$Name, [string]$Status, [string]$Detail)
    $null = $results.Add([pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail })
    $color = switch ($Status) { 'PASS' { 'Green' } 'SKIP' { 'Yellow' } default { 'Red' } }
    Write-Host ("[{0}] {1}{2}" -f $Status, $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor $color
}

function Wait-ForHttp {
    param([string]$Url, [int]$TimeoutSeconds = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -TimeoutSec 3 -UseBasicParsing
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) { return $true }
        } catch {
            Start-Sleep -Milliseconds 300
        }
    }
    return $false
}

function Get-Api {
    param([string]$Path)
    return Invoke-RestMethod -Uri ("http://127.0.0.1:{0}{1}" -f $ApiPort, $Path) -TimeoutSec 10 -UseBasicParsing
}

# -- UDP probe -----------------------------------------------------------------
# A loopback UDP echo server plus a SOCKS5 UDP ASSOCIATE client. The HTTP probe
# above only proves the stream path; this proves the datagram path, which is what
# `udp: true` on a node actually promises. Xray's freedom outbound relays the
# datagram to the echo server, so a reply can only come back through the adapter
# under test.
function Start-UdpEcho {
    param([int]$Port)
    return Start-Job -ScriptBlock {
        param($p)
        $u = New-Object System.Net.Sockets.UdpClient($p)
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $deadline = (Get-Date).AddSeconds(300)
        while ((Get-Date) -lt $deadline) {
            try {
                $u.Client.ReceiveTimeout = 2000
                $data = $u.Receive([ref]$ep)
                $reply = [Text.Encoding]::ASCII.GetBytes('udp:' + [Text.Encoding]::ASCII.GetString($data))
                $u.Send($reply, $reply.Length, $ep) | Out-Null
            } catch { }
        }
        $u.Close()
    } -ArgumentList $Port
}

function Invoke-Socks5UdpProbe {
    param([int]$ProxyPort, [string]$TargetHost, [int]$TargetPort, [string]$Payload)
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect('127.0.0.1', $ProxyPort)
    $s = $tcp.GetStream()
    # greeting: version 5, one method, no-auth
    $s.Write([byte[]]@(5, 1, 0), 0, 3); $s.Flush()
    $greet = New-Object byte[] 2; $s.Read($greet, 0, 2) | Out-Null
    # UDP ASSOCIATE with address 0.0.0.0:0 - the client will send from anywhere
    $s.Write([byte[]]@(5, 3, 0, 1, 0, 0, 0, 0, 0, 0), 0, 10); $s.Flush()
    $reply = New-Object byte[] 10; $s.Read($reply, 0, 10) | Out-Null
    if ($reply[1] -ne 0) { throw ("UDP ASSOCIATE refused with reply code " + $reply[1]) }
    $relayIp = [string]::Join('.', $reply[4..7])
    $relayPort = $reply[8] * 256 + $reply[9]
    $ip = ([System.Net.IPAddress]::Parse($TargetHost)).GetAddressBytes()
    $packet = [byte[]]@(0, 0, 0, 1) + $ip +
        [byte[]]@([byte]($TargetPort -shr 8), [byte]($TargetPort -band 0xFF)) +
        [Text.Encoding]::ASCII.GetBytes($Payload)
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = 10000
    try {
        $udp.Send($packet, $packet.Length, $relayIp, $relayPort) | Out-Null
        $from = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$from)
    } finally {
        $udp.Close(); $tcp.Close()
    }
    # strip the 10-byte SOCKS5 UDP header (RSV, FRAG, ATYP=1, IPv4, port)
    return [Text.Encoding]::ASCII.GetString($resp[10..($resp.Length - 1)])
}

try {
    # ── Xray-core: the reference server ─────────────────────────────────────
    $xrayExe = Join-Path $XrayDir 'xray.exe'
    if ($Download -or -not (Test-Path $xrayExe)) {
        New-Item -ItemType Directory -Force -Path $XrayDir | Out-Null
        $zip = Join-Path $XrayDir 'xray.zip'
        Write-Host 'downloading Xray-core...'
        Invoke-WebRequest -Uri 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip' -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $XrayDir -Force
    }

    # Trojan rides TLS, so the reference inbound needs a certificate. Xray can
    # mint a throwaway one, which keeps this script free of any secret material.
    $certPath = Join-Path $XrayDir 'interop-cert.pem'
    $keyPath = Join-Path $XrayDir 'interop-key.pem'
    if (-not (Test-Path $certPath) -or -not (Test-Path $keyPath)) {
        $pem = (& $xrayExe tls cert -domain=127.0.0.1 2>&1 | Out-String) | ConvertFrom-Json
        [System.IO.File]::WriteAllText($certPath, ($pem.certificate -join "`n"))
        [System.IO.File]::WriteAllText($keyPath, ($pem.key -join "`n"))
    }

    $serverConfig = [ordered]@{
        log      = @{ loglevel = 'warning' }
        inbounds = @(
            @{ tag = 'vless-tcp'; listen = '127.0.0.1'; port = $inbounds['vless'].Port; protocol = 'vless'
               settings = @{ clients = @(@{ id = $uuid; flow = '' }); decryption = 'none' }
               streamSettings = @{ network = 'tcp'; security = 'none' } },
            @{ tag = 'vmess-tcp'; listen = '127.0.0.1'; port = $inbounds['vmess'].Port; protocol = 'vmess'
               settings = @{ clients = @(@{ id = $uuid; alterId = 0; security = 'auto' }) }
               streamSettings = @{ network = 'tcp'; security = 'none' } },
            @{ tag = 'vmess-ws'; listen = '127.0.0.1'; port = $inbounds['vmess-ws'].Port; protocol = 'vmess'
               settings = @{ clients = @(@{ id = $uuid; alterId = 0; security = 'auto' }) }
               streamSettings = @{ network = 'ws'; security = 'none'; wsSettings = @{ path = '/ws' } } },
            # The TLS and WebSocket variants exercise the transport stack, not the
            # protocol: same inbound protocol, a different composition underneath.
            @{ tag = 'vmess-tls'; listen = '127.0.0.1'; port = $inbounds['vmess-tls'].Port; protocol = 'vmess'
               settings = @{ clients = @(@{ id = $uuid; alterId = 0; security = 'auto' }) }
               streamSettings = @{ network = 'tcp'; security = 'tls'
                   tlsSettings = @{ certificates = @(@{ certificateFile = $certPath; keyFile = $keyPath }) } } },
            @{ tag = 'vless-ws'; listen = '127.0.0.1'; port = $inbounds['vless-ws'].Port; protocol = 'vless'
               settings = @{ clients = @(@{ id = $uuid; flow = '' }); decryption = 'none' }
               streamSettings = @{ network = 'ws'; security = 'none'; wsSettings = @{ path = '/ws' } } },
            @{ tag = 'vless-tls'; listen = '127.0.0.1'; port = $inbounds['vless-tls'].Port; protocol = 'vless'
               settings = @{ clients = @(@{ id = $uuid; flow = '' }); decryption = 'none' }
               streamSettings = @{ network = 'tcp'; security = 'tls'
                   tlsSettings = @{ certificates = @(@{ certificateFile = $certPath; keyFile = $keyPath }) } } },
            # Trojan is a TLS-only protocol, so this inbound must present a
            # certificate even though the peer is loopback.
            @{ tag = 'trojan-tls'; listen = '127.0.0.1'; port = $inbounds['trojan'].Port; protocol = 'trojan'
               settings = @{ clients = @(@{ password = $password }) }
               streamSettings = @{ network = 'tcp'; security = 'tls'
                   tlsSettings = @{ certificates = @(@{ certificateFile = $certPath; keyFile = $keyPath }) } } }
        )
        outbounds = @(@{ protocol = 'freedom'; tag = 'direct' })
    }
    $serverJson = Join-Path $XrayDir 'server.json'
    [System.IO.File]::WriteAllText($serverJson, ($serverConfig | ConvertTo-Json -Depth 12))
    $xray = Start-Process -FilePath $xrayExe -ArgumentList @('run', '-c', $serverJson) -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $XrayDir 'xray.out.log') -RedirectStandardError (Join-Path $XrayDir 'xray.err.log')

    # ── sing-box: the reference for anytls / hysteria2 / tuic ───────────────
    $singBoxExe = Join-Path $SingBoxDir 'sing-box.exe'
    if (-not (Test-Path $singBoxExe)) {
        $found = Get-ChildItem $SingBoxDir -Recurse -Filter 'sing-box.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $singBoxExe = $found.FullName }
    }
    if (-not (Test-Path $singBoxExe)) {
        New-Item -ItemType Directory -Force -Path $SingBoxDir | Out-Null
        $sbZip = Join-Path $SingBoxDir 'sing-box.zip'
        Write-Host 'downloading sing-box...'
        # The asset name carries the version, so resolve the latest release first.
        $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/SagerNet/sing-box/releases/latest' -UseBasicParsing `
            -Headers @{ 'User-Agent' = 'clash-dotnet-interop' }
        $asset = $release.assets | Where-Object { $_.name -like '*windows-amd64.zip' } | Select-Object -First 1
        if (-not $asset) { throw 'no sing-box windows-amd64 asset in the latest release' }
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $sbZip -UseBasicParsing
        Expand-Archive -Path $sbZip -DestinationPath $SingBoxDir -Force
        $found = Get-ChildItem $SingBoxDir -Recurse -Filter 'sing-box.exe' | Select-Object -First 1
        $singBoxExe = $found.FullName
    }

    $tlsBlock = @{ enabled = $true; certificate_path = $certPath; key_path = $keyPath }
    $singBoxConfig = [ordered]@{
        log      = @{ level = 'warn' }
        inbounds = @(
            @{ type = 'anytls'; tag = 'anytls-in'; listen = '127.0.0.1'; listen_port = $inbounds['anytls'].Port
               users = @(@{ password = $password }); tls = $tlsBlock },
            @{ type = 'hysteria2'; tag = 'hysteria2-in'; listen = '127.0.0.1'; listen_port = $inbounds['hysteria2'].Port
               users = @(@{ password = $password }); tls = $tlsBlock },
            @{ type = 'tuic'; tag = 'tuic-in'; listen = '127.0.0.1'; listen_port = $inbounds['tuic'].Port
               users = @(@{ uuid = $uuid; password = $password }); tls = $tlsBlock }
        )
        outbounds = @(@{ type = 'direct'; tag = 'direct' })
    }
    $singBoxJson = Join-Path $SingBoxDir 'server.json'
    [System.IO.File]::WriteAllText($singBoxJson, ($singBoxConfig | ConvertTo-Json -Depth 12))
    $singbox = Start-Process -FilePath $singBoxExe -ArgumentList @('run', '-c', $singBoxJson) -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $SingBoxDir 'singbox.out.log') -RedirectStandardError (Join-Path $SingBoxDir 'singbox.err.log')

    $started = @()
    foreach ($name in $Protocol) {
        if (-not $inbounds.Contains($name)) { throw "unknown protocol [$name]; known: $(($inbounds.Keys) -join ', ')" }
        $port = $inbounds[$name].Port
        $ready = $false
        $deadline = (Get-Date).AddSeconds(25)
        while ((Get-Date) -lt $deadline) {
            # Hysteria2's inbound is QUIC: it never opens a TCP listener, so a
            # TCP probe would report the server as missing while it is healthy.
            if ($inbounds[$name].Server -eq 'singbox' -and $name -eq 'hysteria2') {
                if (Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue) { $ready = $true; break }
            } elseif (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
                $ready = $true; break
            }
            Start-Sleep -Milliseconds 300
        }
        if (-not $ready) { throw "the $($inbounds[$name].Server) inbound for $name never listened on $port" }
        $started += "$name/$port"
    }
    Add-Result 'reference servers' 'PASS' ("inbounds: " + ($started -join ', '))

    # ── Local origin server ─────────────────────────────────────────────────
    $originJob = Start-Job -ScriptBlock {
        param($Port)
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://127.0.0.1:$Port/")
        $listener.Start()
        while ($listener.IsListening) {
            try {
                $context = $listener.GetContext()
                $bytes = [System.Text.Encoding]::UTF8.GetBytes('clash-interop-ok')
                $context.Response.StatusCode = 200
                $context.Response.ContentType = 'text/plain'
                $context.Response.ContentLength64 = $bytes.Length
                $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $context.Response.OutputStream.Close()
            } catch { break }
        }
        $listener.Stop()
    } -ArgumentList $OriginPort

    if (-not (Wait-ForHttp -Url ("http://127.0.0.1:{0}/" -f $OriginPort) -TimeoutSeconds 30)) {
        throw 'the local origin server never came up'
    }

    # -- Local UDP echo server, for the datagram probe -----------------------
    $udpEchoPort = $OriginPort + 1
    $udpEchoJob = Start-UdpEcho -Port $udpEchoPort
    Start-Sleep -Seconds 2
    if (-not (Get-NetUDPEndpoint -LocalPort $udpEchoPort -ErrorAction SilentlyContinue)) {
        throw 'the local UDP echo server never came up'
    }

    # ── Clash configuration: one proxy per protocol under test ──────────────
    New-Item -ItemType Directory -Force -Path $homeDir | Out-Null
    $proxyEntries = New-Object System.Collections.ArrayList
    $proxyNames = New-Object System.Collections.ArrayList
    foreach ($name in $Protocol) {
        if (-not $inbounds.Contains($name)) { throw "unknown protocol [$name]; known: $($inbounds.Keys -join ', ')" }
        $port = $inbounds[$name].Port
        $entry = switch ($name) {
            'vmess' {
                @"
  - name: $name
    type: vmess
    server: 127.0.0.1
    port: $port
    uuid: $uuid
    alterId: 0
    cipher: auto
    udp: true
"@
            }
            'vmess-ws' {
                @"
  - name: $name
    type: vmess
    server: 127.0.0.1
    port: $port
    uuid: $uuid
    alterId: 0
    cipher: auto
    network: ws
    ws-opts:
      path: /ws
    udp: true
"@
            }
            'vless' {
                @"
  - name: $name
    type: vless
    server: 127.0.0.1
    port: $port
    uuid: $uuid
    udp: true
"@
            }
            'vless-ws' {
                @"
  - name: $name
    type: vless
    server: 127.0.0.1
    port: $port
    uuid: $uuid
    network: ws
    ws-opts:
      path: /ws
    udp: true
"@
            }
            'vless-tls' {
                @"
  - name: $name
    type: vless
    server: 127.0.0.1
    port: $port
    uuid: $uuid
    tls: true
    sni: 127.0.0.1
    skip-cert-verify: true
    udp: true
"@
            }
            'vmess-tls' {
                @"
  - name: $name
    type: vmess
    server: 127.0.0.1
    port: $port
    uuid: $uuid
    alterId: 0
    cipher: auto
    tls: true
    sni: 127.0.0.1
    skip-cert-verify: true
    udp: true
"@
            }
            'trojan' {
                @"
  - name: $name
    type: trojan
    server: 127.0.0.1
    port: $port
    password: $password
    sni: 127.0.0.1
    skip-cert-verify: true
    udp: true
"@
            }
            'anytls' {
                @"
  - name: $name
    type: anytls
    server: 127.0.0.1
    port: $port
    password: $password
    sni: 127.0.0.1
    skip-cert-verify: true
"@
            }
            'hysteria2' {
                @"
  - name: $name
    type: hysteria2
    server: 127.0.0.1
    port: $port
    password: $password
    sni: 127.0.0.1
    skip-cert-verify: true
"@
            }
            'tuic' {
                @"
  - name: $name
    type: tuic
    server: 127.0.0.1
    port: $port
    uuid: $uuid
    password: $password
    sni: 127.0.0.1
    skip-cert-verify: true
"@
            }
        }
        $null = $proxyEntries.Add($entry.TrimEnd())
        $null = $proxyNames.Add($name)
    }

    $groupMembers = ($proxyNames | ForEach-Object { "      - $_" }) -join "`n"
    $config = @"
mixed-port: $MixedPort
allow-lan: false
bind-address: '127.0.0.1'
mode: rule
log-level: info
external-controller: 127.0.0.1:$ApiPort
secret: ''
dns:
  enable: false
proxies:
$($proxyEntries -join "`n")
proxy-groups:
  - name: INTEROP
    type: select
    proxies:
$groupMembers
      - DIRECT
rules:
  - IP-CIDR,127.0.0.0/8,INTEROP,no-resolve
  - MATCH,INTEROP
"@
    $configPath = Join-Path $homeDir 'config.yaml'
    Set-Content -Path $configPath -Value $config -Encoding UTF8

    # ── Start this core ─────────────────────────────────────────────────────
    $dll = Join-Path $root "src\Clash.Server\bin\$Configuration\net10.0\Clash.Server.dll"
    $core = Start-Process -FilePath 'dotnet' -ArgumentList @($dll, '--home', $homeDir) -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $homeDir 'core.out.log') -RedirectStandardError (Join-Path $homeDir 'core.err.log')

    if (-not (Wait-ForHttp -Url ("http://127.0.0.1:{0}/version" -f $ApiPort) -TimeoutSeconds 90)) {
        throw "the core did not start; see $(Join-Path $homeDir 'core.err.log')"
    }

    $available = @((Get-Api '/proxies').proxies.PSObject.Properties.Name)
    Add-Result 'core started' 'PASS' ("adapters: " + ($available -join ', '))

    # ── Exercise every protocol through the mixed inbound ───────────────────
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (-not (Test-Path $curl)) { $curl = 'curl.exe' }
    $targetUrl = "http://127.0.0.1:$OriginPort/"

    foreach ($name in $proxyNames) {
        if ($available -notcontains $name) {
            Add-Result $name 'SKIP' 'the core did not register this adapter (unsupported type?)'
            continue
        }

        Invoke-RestMethod -Uri ("http://127.0.0.1:{0}/proxies/INTEROP" -f $ApiPort) -Method Put -TimeoutSec 10 `
            -ContentType 'application/json' -Body (@{ name = $name } | ConvertTo-Json) | Out-Null

        $body = & $curl -s -x ("http://127.0.0.1:{0}" -f $MixedPort) $targetUrl 2>&1
        $text = ($body -join '')

        if ($text -eq 'clash-interop-ok') {
            Add-Result $name 'PASS' 'HTTP through the adapter reached the origin'
        } else {
            Add-Result $name 'FAIL' ("body='" + $text + "'")
        }

        # A second request proves the connection path is repeatable, not a fluke.
        $again = & $curl -s -x ("http://127.0.0.1:{0}" -f $MixedPort) $targetUrl 2>&1
        if (($again -join '') -ne 'clash-interop-ok') {
            Add-Result "$name (second request)" 'FAIL' ("body='" + ($again -join '') + "'")
        }

        # Datagram path: the same selected node, a UDP association instead of a
        # stream. The adapter advertises whether it carries datagrams at all, so a
        # protocol that does not is reported as skipped rather than failed - but a
        # protocol that *does* advertise UDP must actually relay, and one that
        # should support UDP is not allowed to quietly stop advertising it.
        $udpAdvertised = $false
        try {
            $nodeInfo = Get-Api ("/proxies/" + [uri]::EscapeDataString($name))
            $udpAdvertised = [bool]$nodeInfo.udp
        } catch { }

        if (-not $udpAdvertised) {
            if ($UdpExpected -contains $name) {
                Add-Result "$name (udp)" 'FAIL' 'this protocol is expected to carry UDP but the adapter advertises udp=false'
            } else {
                Add-Result "$name (udp)" 'SKIP' 'the adapter does not carry datagrams'
            }
            continue
        }

        $udpPayload = "udp-" + $name
        try {
            $echo = Invoke-Socks5UdpProbe -ProxyPort $MixedPort -TargetHost '127.0.0.1' `
                -TargetPort $udpEchoPort -Payload $udpPayload
            if ($echo -eq ("udp:" + $udpPayload)) {
                Add-Result "$name (udp)" 'PASS' 'a datagram reached the echo server and came back'
            } else {
                Add-Result "$name (udp)" 'FAIL' ("reply='" + $echo + "'")
            }
        } catch {
            Add-Result "$name (udp)" 'FAIL' $_.Exception.Message
        }
    }

    $traffic = Get-Api '/connections'
    Add-Result 'traffic accounted' $(if ([int64]$traffic.uploadTotal -gt 0) { 'PASS' } else { 'FAIL' }) `
        ("uploadTotal=" + $traffic.uploadTotal + " downloadTotal=" + $traffic.downloadTotal)
}
catch {
    Add-Result 'interop test' 'FAIL' $_.Exception.Message
    foreach ($log in 'core.err.log', 'core.out.log') {
        $path = Join-Path $homeDir $log
        if (Test-Path $path) {
            Write-Host "--- $log (tail) ---" -ForegroundColor Yellow
            Get-Content $path -Tail 25 | Write-Host
        }
    }
}
finally {
    if ($KeepRunning) {
        Write-Host "leaving the core running (api:$ApiPort mixed:$MixedPort, home: $homeDir)" -ForegroundColor Yellow
        Write-Host "leaving xray running (pid $($xray.Id))" -ForegroundColor Yellow
    } else {
        foreach ($process in @($core, $xray, $singbox)) {
            if ($process -and -not $process.HasExited) {
                try { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } catch { }
            }
        }
        if ($originJob) {
            try { Stop-Job $originJob -ErrorAction SilentlyContinue; Remove-Job $originJob -Force -ErrorAction SilentlyContinue } catch { }
        }
        if ($udpEchoJob) {
            try { Stop-Job $udpEchoJob -ErrorAction SilentlyContinue; Remove-Job $udpEchoJob -Force -ErrorAction SilentlyContinue } catch { }
        }
        foreach ($port in @($ApiPort, $MixedPort, $OriginPort) + @($inbounds.Values | ForEach-Object { $_.Port })) {
            try {
                Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty OwningProcess -Unique |
                    ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
            } catch { }
        }
        if ((Test-Path $homeDir) -and -not $KeepLogs) { Remove-Item -Recurse -Force $homeDir -ErrorAction SilentlyContinue }
        if ($KeepLogs) { Write-Host "logs kept: $homeDir (core.out.log / core.err.log)" -ForegroundColor Yellow }
    }

    $passed = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
    $skipped = @($results | Where-Object { $_.Status -eq 'SKIP' }).Count
    $failed = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
    Write-Host ''
    Write-Host ("=== {0} passed, {1} skipped, {2} failed ===" -f $passed, $skipped, $failed) `
        -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Red' })
    if ($failed -gt 0) { exit 1 }
}
