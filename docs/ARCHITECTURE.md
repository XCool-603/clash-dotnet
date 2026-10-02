# Architecture

Clash for .NET is a reimplementation of the [Clash](https://github.com/Dreamacro/clash) /
[mihomo (Clash.Meta)](https://github.com/MetaCubeX/mihomo) rule-based tunnel in
**C# / .NET 10**, with a **Vue 3** management dashboard. It speaks the same
configuration format, the same RESTful control API and the same WebSocket streams,
so existing Clash dashboards and profiles work against it unchanged.

> **Provenance note.** `Dreamacro/clash` and `Dreamacro/clash-dashboard` were removed
> from GitHub in late 2023. `MetaCubeX/mihomo` is the living reference implementation
> and the source of truth for the API surface and configuration schema used here.
> `MetaCubeX/mihomo`'s default branch is not the Go core — it lives on the `Alpha` branch.

## Solution layout

```
Clash.slnx
Directory.Build.props            shared C# settings (net10.0, nullable, implicit usings)
src/
  Clash.Core/                    the engine — no ASP.NET dependency
  Clash.Server/                  ASP.NET Core host: Clash REST API + WebSocket + static dashboard
  Clash.Desktop/                 Windows tray shell hosting Clash.Server in-process
tests/
  Clash.Tests/                   xunit
web/                             Vue 3 + Vite + TypeScript dashboard (builds into Clash.Server/wwwroot)
docs/reference/                  research: Clash API/config reference, dashboard UX study
```

## `Clash.Core` layering

The dependency direction is strictly inward; nothing in `Clash.Core` knows about
ASP.NET Core.

```
                    ┌───────────────────────────────────────────┐
   inbound          │              Clash.Core                   │        outbound
 ┌──────────┐       │                                           │       ┌──────────┐
 │ HTTP     │       │   Listeners ──▶ Tunnel ──▶ Rules          │       │ DIRECT   │
 │ SOCKS5   │──────▶│                   │         │             │──────▶│ REJECT   │
 │ mixed    │       │                   │         ▼             │       │ Shadowsocks
 │ redir    │       │                   │      ProxyManager     │       │ VMess    │
 │ tproxy   │       │                   │         │             │       │ VLESS    │
 │ TUN      │       │                   ▼         ▼             │       │ Trojan   │
 │ DNS      │       │              ConnectionManager  Groups    │       │ …        │
 └──────────┘       │                   │                       │       └──────────┘
                    │                   ▼                       │
                    │            DNS · GeoData · TrafficTracker │
                    └───────────────────────────────────────────┘
```

| Namespace | Responsibility |
|---|---|
| `Clash.Core.Common` | `Metadata` (the flow), `ProxyStream`, `IPacketConnection`, `YamlMap`, primitives |
| `Clash.Core.Configuration` | `ClashConfig`, YAML parse/serialise, `ProfileManager` (subscriptions + merges) |
| `Clash.Core.Adapter` | `IProxy` contract, `ProxyAdapter` base, built-ins, proxy groups, `ProxyManager`, `ProxyFactory` |
| `Clash.Core.Proxies.Outbound` | the wire protocols; each self-registers with `AdapterRegistry` |
| `Clash.Core.Transport` | composable layers: `tcp` → `tls` → `ws`/`grpc`/`h2`/`http` |
| `Clash.Core.Crypto` | AEAD and stream ciphers, Shadowsocks/VMess/VLESS/Trojan crypto |
| `Clash.Core.Rules` | rule parsing, domain trie, CIDR trie, rule sets, GeoIP/GeoSite/ASN |
| `Clash.Core.Dns` | wire codec, upstreams (UDP/TCP/DoT/DoH), fake-IP pool, hosts, DNS listener |
| `Clash.Core.Listeners` | inbound servers and `ListenerManager` |
| `Clash.Core.Tunnel` | `Tunnel` (the router), `ConnectionManager`, sniffing, delay testing |
| `Clash.Core.Runtime` | `ClashRuntime` — the composition root that wires everything |

> There is no `Clash.Core.Tun` project in this build: the `tun:` configuration
> section is parsed and reported by the API, but no wintun binding or userspace
> TCP/IP stack exists yet, so `tun.enable` has no runtime effect.

### Key contracts

- **`IProxy`** — anything that can carry a flow. `DialTcpAsync(metadata, upstream, ct)`
  takes an optional `upstream` stream, which is what makes `relay` chains and
  `dialer-proxy` work: a hop tunnels *over* the previous hop's stream.
- **`ITunnel`** — the router. Listeners call `HandleTcpAsync`/`HandleUdpAsync`; the
  tunnel enriches metadata (fake-IP reversal, sniffing), matches a rule, picks an
  adapter, relays with byte accounting and records the flow for `/connections`.
- **`ITransportComposer`** — builds the layer stack for an outbound from its
  configuration map, so protocol adapters never deal with TLS/WebSocket/gRPC
  framing themselves.
- **`AdapterRegistry`** — protocol adapters register themselves from a
  `[ModuleInitializer]`, so `Clash.Core` has no compile-time dependency on any
  protocol. Adding a protocol means adding a file, not editing a switch.

### The connection path, end to end

1. An inbound listener accepts a client, decodes its protocol, and builds a
   `Metadata` (`network`, source, destination, `inboundType`, …).
2. `Tunnel.HandleTcpAsync` wraps the client stream in a `PeekableStream` and
   **sniffs** the first bytes (TLS ClientHello SNI, HTTP `Host`) when the
   destination arrived as a bare IP. Sniffed bytes are replayed exactly once.
3. `Tunnel.MatchAsync` normalises the metadata (a fake-IP destination is mapped
   back to its domain) and evaluates the rule list, first match wins. `mode:
   direct` and `mode: global` bypass the list; a special-proxy rule short-circuits
   it entirely.
4. `ProxyManager` resolves the target adapter — a concrete protocol, or a group
   that picks one of its members.
5. The adapter dials through the transport stack. `DIRECT` connects with a
   `SocketStream` (which supports half-close); proxied adapters speak their
   protocol over the composed stream.
6. `Tunnel.RelayAsync` pumps both directions with pooled buffers, counts bytes
   into the `TrackedConnection` and the `TrafficTracker`, and **half-closes** the
   peer when one direction ends so a request/response flow is never truncated.
7. The flow is removed from `ConnectionManager` and the totals are reported by
   `GET /connections` and the `/traffic` WebSocket.

### Design decisions worth knowing

- **`upstream` on `DialTcpAsync`** replaces Clash's global `dialer` indirection.
  It makes relay chains, `dialer-proxy` and protocol nesting a plain recursive
  composition instead of a special case.
- **Metadata is mutable and passed by reference** through the dial path, so a
  group can append itself to `metadata.Chain` and the API reports the real chain
  without any bookkeeping in the tunnel.
- **`PeekableStream` + `Sniffer`** keep sniffing out of the listeners. Any inbound
  that produces a stream gets sniffing for free.
- **Half-close (`IHalfCloseable`)** exists because `NetworkStream` cannot express
  "I am done sending but still reading", and getting this wrong silently truncates
  every HTTP response.
- **`YamlMap`** is the single typed view over heterogeneous YAML. Real
  subscriptions quote numbers and write `"true"`, so every read is coercing.
- **Unknown configuration keys are preserved** in `ClashConfig.Raw`, which is what
  lets `PATCH /configs` merge a partial update and lets a newer profile load in an
  older build.

## `Clash.Server`

`ClashHost.Build(args, configure)` returns a configured `WebApplication` without
starting it, so both `Clash.Server` (its own `Program.cs`) and `Clash.Desktop` (the
tray app) can host the identical stack. `ClashService` owns the `ClashRuntime`
lifetime; the API degrades to reporting the startup error rather than crashing, so
a broken configuration is fixable from the UI.

Authentication mirrors Clash: `Authorization: Bearer <secret>` for REST, and
`?token=<secret>` for WebSockets (browsers cannot set headers on a WebSocket
handshake). Static dashboard assets and `OPTIONS` stay unauthenticated.

## `web/`

Vue 3 + Vite + TypeScript + Pinia + Element Plus + ECharts. It builds straight into
`src/Clash.Server/wwwroot` (`build.outDir`), so `dotnet run` serves the dashboard
with no extra steps. In development, `npm run dev` talks to a running core at
`http://127.0.0.1:9090`; the API enables permissive CORS for exactly that.

The dashboard is a pure API client — it holds no privileged state — which is why it
can also be pointed at a remote mihomo core.

## `Clash.Desktop`

A WinForms tray application that starts `ClashHost` in-process. It adds what a
headless core cannot do for itself: a tray icon and menu (mode, group selection,
system proxy, restart), system-proxy configuration via WinINet, autostart,
single-instance enforcement and a dashboard link. The system-proxy state is
snapshotted to disk before the first change, so exiting the app restores what the
machine actually had rather than leaving it pointed at a proxy that is gone.

## Testing strategy

- **Pure logic is unit tested directly**: configuration parsing, the rule parser
  and matchers (domain trie, CIDR trie), the DNS wire codec, fake-IP allocation,
  ciphers against published vectors, packet parsing/checksums, the TCP state
  machine, group selection and relay chaining.
- **Protocol adapters are tested against in-process fake servers** built from the
  same primitives, asserting exact wire framing.
- **The tunnel is tested with a real loopback echo server**, asserting that bytes
  are relayed in both directions and accounted correctly.
- **The API is tested through the real ASP.NET pipeline** with an inline
  configuration and listeners disabled.
