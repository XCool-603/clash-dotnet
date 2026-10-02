# Clash for .NET

A reimplementation of the [Clash](https://github.com/Dreamacro/clash) /
[mihomo (Clash.Meta)](https://github.com/MetaCubeX/mihomo) rule-based tunnel in
**C# / .NET 10**, with a **Vue 3** management dashboard.

It speaks the same configuration format, the same RESTful control API and the same
WebSocket streams as Clash, so existing profiles, subscription links and third-party
dashboards work against it unchanged.

> **Provenance.** `Dreamacro/clash` and `Dreamacro/clash-dashboard` were removed from
> GitHub in late 2023, so there is no original repository left to mirror. The living
> reference implementation is **[MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)**
> (the Go core is on the **`Alpha`** branch — the default branch is an unrelated project),
> and it is the source of truth for the API surface and configuration schema implemented here.

---

## Quick start

```powershell
# 1. Build everything (the Vue dashboard is built separately, see below)
dotnet build Clash.slnx

# 2. Build the dashboard into src/Clash.Server/wwwroot
cd web; npm install; npm run build; cd ..

# 3. Run the core + dashboard
dotnet run --project src/Clash.Server -- --home "$env:USERPROFILE\.config\clash"
```

Then open the dashboard at <http://127.0.0.1:9090/ui> (the `external-controller`
address from your configuration). The bare `/` path answers the API greeting
(`{"hello":"clash"}`), exactly as Clash does, so the dashboard lives under `/ui`.

On first run a working starter configuration is written to
`%USERPROFILE%\.config\clash\config.yaml` if none exists, so the core comes up with
a usable rule set and no nodes. Add nodes by importing a subscription from the
**Profiles** page, or by editing `proxies:` directly.

To run the headless core in a container instead, see [Docker](#docker-headless) —
it is a single `docker compose up -d`.

### Desktop tray app

```powershell
dotnet run --project src/Clash.Desktop
```

Hosts the same core in-process and adds a tray icon, system-proxy integration,
autostart and single-instance handling.

### Smoke test

```powershell
powershell -File scripts/smoke-test.ps1
```

Starts the core with a generated configuration, exercises the control API, then
pushes real HTTP and SOCKS5 traffic through the mixed inbound to a local origin
server and checks that the bytes are accounted for.

### Interoperability test

```powershell
powershell -File scripts/interop-test.ps1 -Download            # every protocol
powershell -File scripts/interop-test.ps1 -Protocol vmess,vless
```

Unit tests assert wire framing against hand-written fake servers, which proves
the framing is self-consistent but not that another implementation accepts it.
This script closes that gap: it downloads two real reference servers —
[Xray-core](https://github.com/XTLS/Xray-core) (MPL-2.0) for the v2ray family and
[sing-box](https://github.com/SagerNet/sing-box) (GPL-3.0, used as a binary peer
only) for anytls/hysteria2/tuic — starts one inbound per protocol, points a Clash
configuration at those inbounds and drives real HTTP traffic through each adapter
in turn:

```
curl -> mixed inbound -> <protocol> adapter -> reference inbound -> origin
```

A protocol whose adapter is missing is reported as `SKIP`; a protocol that
connects but does not deliver a response is a `FAIL`. This is the test that
caught the Trojan adapter consuming a server "response header" that Trojan does
not have.

Every protocol is probed twice: once with an HTTP request through the mixed
inbound, and once with a **UDP datagram** through a SOCKS5 `UDP ASSOCIATE` to a
loopback echo server. The second probe is what makes `udp: true` mean something —
it fails unless the datagram reaches the echo server and comes back. A protocol
that does not carry datagrams is reported as skipped, and one that is expected to
carry them but stops advertising UDP fails the run.

Results on the reference machines used to develop this repository:

| Protocol | Interop result |
|---|---|
| `trojan`, `vmess` (tcp/ws/tls), `vless` (tcp/ws/tls) | ✅ verified against Xray-core, TCP and UDP |
| `anytls` | ✅ verified against sing-box (TCP; it carries no datagrams) |
| `mieru` | implemented, unit-tested; not yet interoperability-tested — the reference server (`mita`) ships Linux packages only, and this machine has no Linux environment |
| `hysteria2` | ❌ blocked (see below) |
| `wireguard` | not interoperability-tested: terminating a real WireGuard peer requires a TUN device or a purpose-built userspace responder |

**Platform note (hysteria2 / tuic).** A minimal, 20-line `System.Net.Quic` client
fails the TLS handshake against *both* sing-box and the official hysteria2 server
with `TLS alert: InternalError`, while the official hysteria2 client connects to
the same servers successfully. The QUIC stack behind `System.Net.Quic` (MsQuic)
and quic-go — which every hysteria2/tuic server uses — do not interoperate on
this build, independent of this project's adapter code. hysteria2's UDP and
Salamander obfuscation are additionally out of reach because `System.Net.Quic`
exposes no QUIC datagrams and no raw socket underneath.

---

## Docker (headless)

The image carries the core and the dashboard; only the Windows tray shell is left
out (it targets `net10.0-windows` and cannot build on Linux, so **TUN mode is not
available in this image**).

### Deploy

```sh
docker compose up -d
```

That is the whole deployment. The container writes a starter configuration to its
data volume on first run, so the dashboard is live immediately:

| what | where |
|---|---|
| Dashboard | <http://127.0.0.1:9090/ui> |
| Control API | `http://127.0.0.1:9090` |
| HTTP + SOCKS5 proxy | `127.0.0.1:7890` |
| DNS | `127.0.0.1:1053` |
| Configuration and cache | `./data` on the host (`docker compose` creates it) |

The first thing to do is open the dashboard and import a subscription, or edit
`./data/config.yaml` and run `docker compose restart`.

To build from a local checkout instead of the published image, comment out
`image:` in `docker-compose.yml` and uncomment `build: .`, then use
`docker compose up -d --build`.

### Upgrade

```sh
# Linux / macOS / WSL
./scripts/docker-update.sh

# Windows
powershell -File scripts/docker-update.ps1
```

Either script pulls the new image, recreates the container against the same data
volume, prunes the image it replaced, and then waits for the core to answer and
prints the version it ended up running. Add `-Build` (PowerShell) or `--build`
(sh) to rebuild from the checkout instead of pulling.

The equivalent by hand:

```sh
docker compose pull
docker compose up -d
```

Upgrading never touches `./data`, so profiles, the configuration and the fake-IP
store survive. The image is published to
`ghcr.io/xcool-603/clash-dotnet` by
[.github/workflows/docker.yml](.github/workflows/docker.yml) on every push to
`main` and on every `v*` tag; that workflow also runs the image and checks that
`/version` answers, so a Dockerfile that no longer works fails there rather than
on your machine.

### Before exposing it

The starter configuration leaves the control API on `0.0.0.0:9090` with an empty
`secret`, because a loopback listener inside a container is unreachable from the
host. On a machine reachable by others, set a `secret` in `data/config.yaml` and
the same value in the dashboard's settings — otherwise anything that can reach
port 9090 can reconfigure the core. Publishing the ports only on the loopback
interface is the other half of that:

```yaml
ports:
  - "127.0.0.1:9090:9090/tcp"
  - "127.0.0.1:7890:7890/tcp"
```

---

## Features

### Inbound (client-facing)

| Feature | Status |
|---|---|
| HTTP proxy (`CONNECT` + absolute-URI) with `Proxy-Authorization` | ✅ |
| SOCKS5 (CONNECT + UDP ASSOCIATE, username/password auth) | ✅ |
| SOCKS4 / SOCKS4a | ✅ |
| `mixed-port` protocol auto-detection | ✅ |
| `redir` (Linux `SO_ORIGINAL_DST`) | ✅ platform-gated |
| `tproxy` (Linux `IP_RECVORIGDSTADDR`) | ✅ platform-gated |
| TUN (Windows wintun) | ❌ not implemented — the `tun:` section is parsed and reported, but nothing acts on it |
| DNS listener (UDP + TCP) | ✅ |
| `listeners:` custom inbound definitions | ✅ |
| Inbound authentication (`authentication:`) | ✅ |

### Outbound (server-facing)

| Protocol | Status |
|---|---|
| `direct`, `reject`, `reject-drop`, `dns` | ✅ |
| `ss` (Shadowsocks — AEAD, stream and 2022 ciphers, plugins) | ✅ |
| `ssr` (ShadowsocksR) | ✅ |
| `vmess` (VMess, AEAD — TCP, plus UDP over the same connection when `udp: true`) | ✅ interop-verified against Xray-core, TCP **and** UDP, over `tcp`, `ws` and `tls` |
| `vless` (VLESS — `flow: xtls-rprx-vision` padding, plus UDP over the same connection when `udp: true`) | ✅ interop-verified against Xray-core, TCP **and** UDP, over `tcp`, `ws` and `tls` — but `REALITY` is ❌ (see below) and the vision *direct/splice* switch cannot be reproduced over `SslStream` |
| `trojan` | ✅ interop-verified against Xray-core, TCP and UDP |
| `http` / `https` | ✅ |
| `socks5` (TCP + UDP) | ✅ |
| `snell` | ✅ |
| `wireguard` | ✅ Noise_IK handshake, transport messages, keepalive, and TCP carried over the bundled userspace TCP/IP stack (`Clash.Core.Netstack`); verified only against an in-process reference peer |
| `hysteria2` | ✅ implemented and unit-tested at the byte level (QUIC varint, QPACK subset, HTTP/3 auth, TCP stream framing) — but **not interoperability-verified**: see the platform note below. UDP and Salamander obfuscation are refused rather than silently unsupported |
| `hysteria` (v1) | ❌ not implemented |
| `tuic` | ❌ **blocked by the platform**: TUIC v5 authentication needs an RFC 5705 TLS keying-material export, and neither `System.Net.Quic` nor `System.Net.Security` exposes one |
| `ssh` | ✅ |
| `anytls` | ✅ interop-verified against sing-box; TCP only — it does not carry datagrams, and the interop harness reports that as skipped rather than passed |
| `mieru` | implemented and unit-tested (key exchange, SOCKS5 handshake); not interoperability-tested — the reference server (`mita`) ships Linux packages only, and this machine has no Linux environment. UDP is refused |
| Datagram support by protocol | `ss`, `ssr`, `socks5`, `trojan`, `vmess`, `vless` and `wireguard` carry UDP; `anytls`, `snell`, `ssh` and `http` do not, and `hysteria2`/`mieru` refuse it for platform reasons |
| Transports: `tcp`, `tls`, `ws`, `grpc`, `h2`, `http` | ✅ |

**`REALITY`.** VLESS with `reality-opts` is refused with a clear error rather than
silently downgraded: REALITY works by authoring a specific TLS `ClientHello`
(the X25519 key and short id are smuggled into the session id) and .NET's
`SslStream` cannot emit a custom `ClientHello`. Supporting it means implementing
a TLS 1.3 client on top of BouncyCastle, which is a project of its own.

### Routing

| Feature | Status |
|---|---|
| Rule engine, first-match-wins, `no-resolve` | ✅ |
| All rule types (`DOMAIN*`, `GEOIP`, `GEOSITE`, `IP-CIDR*`, `IP-ASN`, `SRC-*`, `DST-PORT`, `IN-*`, `PROCESS-*`, `NETWORK`, `DSCP`, `UID`, `RULE-SET`, `SUB-RULE`, `AND`/`OR`/`NOT`, `MATCH`) | ✅ |
| `rule-providers` (`http`/`file`/`inline`, `yaml`/`text`/`mrs`) | ✅ |
| `proxy-providers` (`http`/`file`/`inline`, filters, `override`) | ✅ |
| Proxy groups: `select`, `url-test`, `fallback`, `load-balance`, `relay`, `smart` | ✅ |
| Group `filter`/`exclude-filter`/`exclude-type`, `include-all*`, `icon`, `hidden` | ✅ |
| Modes: `rule`, `global`, `direct` | ✅ |
| Sniffing (TLS SNI, HTTP `Host`, QUIC) with `override-destination` | ✅ |
| `dialer-proxy` | ✅ |
| Subscription import and share-link parsing (`ss`, `ssr`, `vmess`, `vless`, `trojan`, `hysteria2`, `tuic`, `socks`, `http`, …) | ✅ |

### DNS

| Feature | Status |
|---|---|
| Upstreams: UDP, TCP, DoT, DoH | ✅ |
| `hosts` overrides (exact + wildcard) and `use-system-hosts` | ✅ |
| `nameserver-policy` | ✅ |
| `fallback` + `fallback-filter` (GeoIP / IP-CIDR / domain) | ✅ |
| `enhanced-mode: fake-ip` with a bounded pool and `fake-ip-filter` | ✅ |
| `default-nameserver` bootstrapping | ✅ |
| Positive/negative caching with TTL clamping | ✅ |
| `dns-hijack` from TUN | ❌ no TUN in this build |

### Control plane

| Feature | Status |
|---|---|
| Full Clash RESTful API (`/configs`, `/proxies`, `/rules`, `/connections`, `/providers/*`, `/group`, `/dns/query`, `/cache/*`) | ✅ |
| WebSocket streams: `/traffic`, `/memory`, `/logs` | ✅ |
| `Authorization: Bearer` and `?token=` authentication | ✅ |
| Profile / subscription management API (`/profiles`, `/subscription/parse`) | ✅ |
| Hot configuration reload (`PATCH`/`PUT /configs`) | ✅ |

### Dashboard

| Page | Status |
|---|---|
| Overview — live traffic + memory charts, counters, mode switch | ✅ |
| Proxies — group cards, delay testing, node selection | ✅ |
| Profiles — import/update/edit/activate subscriptions | ✅ |
| Connections — live virtualised table, per-flow close | ✅ |
| Rules — rule list, enable/disable, rule providers | ✅ |
| Logs — streaming, level filter, search | ✅ |
| Settings — config editor with hot-reload hints | ✅ |

---

## Configuration

The configuration format is Clash's. See
[`docs/reference/clash-api-and-config.md`](docs/reference/clash-api-and-config.md)
for the full schema and
[`docs/reference/dashboard-ux.md`](docs/reference/dashboard-ux.md) for the API and
UI behaviour the dashboard relies on.

Minimal example:

```yaml
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
secret: ''

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query

proxies:
  - name: example-ss
    type: ss
    server: 192.0.2.10
    port: 8388
    cipher: aes-256-gcm
    password: 'your-password'
    udp: true

proxy-groups:
  - name: PROXY
    type: select
    proxies: [example-ss, DIRECT]
  - name: AUTO
    type: url-test
    use: [my-provider]
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

proxy-providers:
  my-provider:
    type: http
    url: 'https://example.com/subscription'
    path: ./providers/my-provider.yaml
    interval: 3600
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300

rules:
  - DOMAIN-SUFFIX,local,DIRECT
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
```

---

## Repository layout

```
src/Clash.Core/       the engine (no ASP.NET dependency)
src/Clash.Server/     ASP.NET Core host: Clash REST API, WebSocket, static dashboard
src/Clash.Desktop/    Windows tray shell hosting the same host in-process
tests/Clash.Tests/    xunit
web/                  Vue 3 + Vite + TypeScript dashboard
docs/                 architecture and API/UX reference
scripts/              smoke test, interop harness and the container upgrade scripts
docker/               the container's starter configuration and entrypoint
third_party/wintun/   the prebuilt TUN driver, with its licence and provenance
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design and the
connection path end to end.

---

## Development

```powershell
# Backend
dotnet build Clash.slnx
dotnet test  Clash.slnx

# Frontend, with hot reload against a running core on 127.0.0.1:9090
cd web
npm install
npm run dev          # http://127.0.0.1:5173
npm run typecheck
npm run build        # emits into src/Clash.Server/wwwroot
```

---

## Platform support

The core runs anywhere .NET 10 does. Two subsystems are platform-specific:

| Subsystem | Windows | Linux | macOS |
|---|---|---|---|
| `mixed` / HTTP / SOCKS5 / DNS inbounds | ✅ | ✅ | ✅ |
| TUN (wintun) | ❌ | ❌ | ❌ |
| `redir` / `tproxy` inbounds | — | ✅ | partial |
| System proxy + tray shell | ✅ | — | — |

The `redir` and `tproxy` inbounds are Linux-only; the desktop tray shell is
Windows-only. TUN is **not usable yet**: the Windows driver session, the
elevation check and the route handling are in place (`src/Clash.Core/Tun`), but
the accept side of the userspace TCP stack, the datagram path and the `tun:`
configuration are still missing, so nothing is wired up. See the inbound table.

---

## Licence

MIT — see [LICENSE](LICENSE).

This is an independent reimplementation. Clash and mihomo are separate projects by
their own authors; this codebase shares no code with them. The protocol formats it
implements were written from the specifications and from reading the reference
implementations as documentation; [docs/reference/protocol-sources.md](docs/reference/protocol-sources.md)
lists every source consulted, with its licence.

One component is not covered by the MIT grant: `third_party/wintun/amd64/wintun.dll`
is WireGuard LLC's prebuilt Wintun binary, redistributed under the Prebuilt Binaries
License that ships with it (kept verbatim beside the DLL, and reproduced in
[LICENSE](LICENSE)).

