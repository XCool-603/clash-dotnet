# Clash API and configuration reference

This document describes the configuration schema and the control API that **this
implementation** accepts and answers. Where it differs from the reference
implementation, the difference is called out explicitly, because a profile that
loads here must behave the same way it does under
[mihomo](https://github.com/MetaCubeX/mihomo) (Go core on the **`Alpha`**
branch).

> Status markers used below: **✅** implemented and covered by tests,
> **🚧** parsed and reported but not acted on, **❌** not implemented — the
> configuration key is preserved but ignored.

---

## 1. Running the core

```powershell
dotnet run --project src/Clash.Server -- --home "$env:USERPROFILE\.config\clash"
```

| Option | Meaning |
|---|---|
| `--home <dir>`, `-d <dir>` | Home directory holding the configuration, profiles and provider caches. |
| `--config <path>`, `-f <path>`, `--config-file <path>` | Explicit configuration file. |
| `--key=value` | Any option may also be written with `=`. |
| `--urls <url>` | Standard ASP.NET Core override for the listen address; wins over `external-controller`. |

The home directory defaults to `%USERPROFILE%\.config\clash` on Windows and
`~/.config/clash` elsewhere. The configuration file is looked for in this order:

1. the explicit `--config` path,
2. `<home>/config.yaml`, then `<home>/config.yml`,
3. `<application base directory>/config.yaml`,
4. `<current directory>/config.yaml`.

When none exists, a working starter configuration (rule mode, DNS enabled,
`external-controller: 127.0.0.1:9090`, no nodes) is written to
`<home>/config.yaml`, so the core always comes up in a usable state.

### Files under the home directory

| Path | Written by |
|---|---|
| `config.yaml` | the starter configuration, and `PUT /configs` |
| `profiles.json` | the profile (subscription) index — `ProfileManager` |
| `profiles/<id>.yaml` | imported or downloaded profiles |
| `providers/rules/<name>.yaml` | `rule-providers` with a `file`/`http` vehicle |
| `providers/proxies/<name>.yaml` | `proxy-providers` with a `file`/`http` vehicle |
| `cache/selections.json` | group selections, when `profile.store-selected` is on |

### The dashboard

The Vue dashboard is built into `src/Clash.Server/wwwroot` and served by the
same host. It lives at **`http://127.0.0.1:9090/ui`** — `/` itself answers the
API greeting (`{"hello":"clash"}`), exactly as Clash does, so browsers must use
the `/ui` path (or any non-API path, which falls back to the SPA shell).

---

## 2. Configuration schema

The file is YAML. Unknown keys are **preserved** in `ClashConfig.Raw` rather
than rejected, which is what lets a newer profile load in an older build and
lets `PATCH /configs` merge a partial update.

### 2.1 General

| Key | Type | Default | Notes |
|---|---|---|---|
| `port` | int | `0` | HTTP inbound. `0` disables it. |
| `socks-port` | int | `0` | SOCKS5 inbound. |
| `mixed-port` | int | `0` | HTTP + SOCKS5 auto-detected on one port. |
| `redir-port` | int | `0` | Linux `SO_ORIGINAL_DST` redirect inbound. |
| `tproxy-port` | int | `0` | Linux `IP_RECVORIGDSTADDR` transparent inbound. |
| `allow-lan` | bool | `false` | Bind the inbounds to `bind-address` instead of loopback. |
| `bind-address` | string | `*` | `*`, an IP literal, or a resolvable name. |
| `mode` | `rule` \| `global` \| `direct` | `rule` | Hot-swappable with `PATCH /configs`. |
| `log-level` | `debug` \| `info` \| `warning` \| `error` \| `silent` | `info` | Also the `/logs` stream default. |
| `ipv6` | bool | `false` | Allow AAAA results and IPv6 dialling. |
| `interface-name` | string | — | Bind outbound sockets to this interface (Linux). |
| `routing-mark` | int | `0` | `SO_MARK` for outbound sockets (Linux). |
| `unified-delay` | bool | `false` | Report one delay figure per node in `/proxies`. |
| `tcp-concurrent` | bool | `false` | Dial several addresses in parallel. |
| `find-process-mode` | `off` \| `strict` \| `always` | `strict` | Process attribution for `PROCESS-*` rules. |
| `global-client-fingerprint` | `chrome` \| `firefox` \| `safari` \| `ios` \| `android` \| `edge` \| `360` \| `qq` \| `random` | — | TLS ClientHello fingerprint for outbound TLS. |
| `keep-alive-interval`, `keep-alive-idle` | int (s) | `30`, `15` | TCP keep-alive tuning. |
| `disable-keep-alive` | bool | `false` | Turn keep-alive off entirely. |
| `external-controller` | `host:port` | `127.0.0.1:9090` | Control API address; `:9090` means every interface. |
| `external-controller-cors` | object | permissive | `allow-origins`, `allow-private-network`. |
| `external-ui`, `external-ui-name`, `external-ui-url` | string | — | Accepted for compatibility; the bundled dashboard is always served at `/ui`. |
| `secret` | string | `''` | Bearer token for the control API. Empty means "no authentication". |
| `authentication` | list of `user:pass` | — | Inbound proxy authentication. |
| `hosts` | map | — | DNS overrides; exact names and `*.wildcard` patterns. |
| `tunnels` | list | — | Accepted for compatibility; 🚧 not acted on. |

### 2.2 TUN

The whole `tun:` section is **parsed and reported** by `GET /configs`
(`enable`, `stack`, `device`, `auto-route`, `auto-detect-interface`,
`auto-redirect`, `dns-hijack`, `mtu`, `gso`, `gso-max-size`, `strict-route`,
`endpoint-independent-nat`, `inet4-address`, `inet6-address`, `udp-timeout`,
`route-address`, `route-exclude-address`, `include-interface`,
`exclude-interface`, `file-descriptor`, `interface-name`,
`redirect-to-tun`) — but ❌ **there is no TUN implementation in this build**:
no wintun binding, no userspace TCP/IP stack. Enabling it changes nothing at
runtime.

### 2.3 DNS

| Key | Notes |
|---|---|
| `enable` | ✅ |
| `listen` | UDP + TCP listener address, default `0.0.0.0:1053`. |
| `ipv6` | Allow AAAA upstream queries. |
| `enhanced-mode` | `normal` \| `fake-ip` \| `redir-host`. |
| `fake-ip-range`, `fake-ip-range-v6`, `fake-ip-filter` | ✅ bounded pool. |
| `default-nameserver` | Bootstrap resolvers (plain IPs only). |
| `nameserver`, `fallback`, `fallback-filter`, `nameserver-policy`, `proxy-server-nameserver` | ✅ |
| `use-hosts`, `use-system-hosts` | ✅ |
| `cache-algorithm`, `prefer-h3`, `respect-rules`, `direct-nameserver`, `nameserver-policy` | ✅ where meaningful; unknown values fall back to the default algorithm. |

Upstream forms accepted in every resolver list: `1.1.1.1`, `1.1.1.1:53` (UDP),
`tcp://8.8.8.8`, `tls://dns.google:853`, `https://dns.example/dns-query`,
`h3://dns.google/dns-query` (also spelled `quic://`), `dhcp://en0` and
`hosts://`. The `#interface` and `#proxy-name` suffixes mihomo accepts are ❌
not parsed here — an entry carrying one is treated as a hostname and fails to
resolve.

`dns-hijack` is 🚧: it is parsed, but hijacking only has meaning for TUN, which
this build does not implement.

### 2.4 Sniffing

```yaml
sniffer:
  enable: true
  override-destination: false
  sniff:
    TLS:  { ports: [443, 8443] }
    HTTP: { ports: [80, 8080-8880], override-destination: true }
    QUIC: { ports: [443] }
  skip-domain: ['Mijia Cloud', '+.push.apple.com']
  force-domain: ['+.google.com']
  sniffing-timeout: 200
```

TLS SNI, HTTP `Host` and QUIC SNI are recognised ✅. Sniffing only runs when the
destination arrived as a bare address, and the sniffing window is bounded by
`sniffing-timeout` (ms).

### 2.5 Profiles, providers and rules

```yaml
profile:
  store-selected: true     # persist group choices in cache/selections.json
  store-fake-ip: true
  tracing: false           # ❌ ignored

proxy-providers:
  my-provider:
    type: http             # http | file | inline
    url: https://example.com/subscription
    path: ./providers/proxies/my-provider.yaml
    interval: 3600
    filter: 'HK|SG'
    exclude-filter: 'expire'
    exclude-type: 'ss|vmess'
    health-check: { enable: true, url: ..., interval: 300 }
    override: { udp: true }

rule-providers:
  reject:
    type: http             # http | file | inline
    behavior: domain       # domain | ipcidr | classical
    format: yaml           # yaml | text | mrs
    url: https://example.com/reject.yaml
    path: ./providers/rules/reject.yaml
    interval: 86400

rules:
  - DOMAIN-SUFFIX,example.com,PROXY
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - RULE-SET,reject,REJECT
  - MATCH,PROXY
```

### 2.6 Listeners

`listeners:` declares extra inbounds beyond the fixed ports:

```yaml
listeners:
  - name: socks-in
    type: socks
    port: 1080
    listen: 127.0.0.1
    proxy: PROXY          # optional forced outbound
    udp: true
```

Supported `type` values: `http`, `socks`, `mixed`, `redir`, `tproxy`, `tun`
(❌ not implemented), `dns`.

---

## 3. Rule syntax

Rules are evaluated in order, first match wins. The adapter is any name from
`/proxies` — a node, a group, or one of `DIRECT`, `REJECT`, `REJECT-DROP`.

| Type | Payload | Notes |
|---|---|---|
| `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-REGEX` | name / pattern | |
| `GEOSITE` | geosite code | |
| `GEOIP` | country code | `no-resolve` skips DNS. |
| `IP-CIDR`, `IP-CIDR6`, `IP-SUFFIX` | CIDR / suffix | |
| `IP-ASN` | AS number | |
| `SRC-IP-CIDR`, `SRC-IP-ASN`, `SRC-GEOIP`, `SRC-PORT`, `DST-PORT` | as above | |
| `IN-TYPE`, `IN-NAME`, `IN-PORT`, `IN-USER` | inbound identity | |
| `PROCESS-NAME`, `PROCESS-NAME-REGEX`, `PROCESS-PATH`, `PROCESS-PATH-REGEX` | process | Needs `find-process-mode`. |
| `NETWORK` | `tcp` \| `udp` | |
| `DSCP` | number | |
| `UID` | number | |
| `RULE-SET` | provider name | `behavior` decides the payload form. |
| `SUB-RULE` | `(sub-rules-name, <inner rule>)` | |
| `AND`, `OR`, `NOT` | `((<rule>), (<rule>))` | |
| `MATCH` | — | Always matches; conventionally last. |

Modifiers: `no-resolve` (skip DNS for IP rules), `src` (match the source
address), and the `src` variant of `IP-CIDR`/`GEOIP`/`IP-ASN`.

---

## 4. Proxies and groups

### 4.1 Outbound types

| `type` | Status |
|---|---|
| `direct`, `reject`, `reject-drop`, `dns` | ✅ built in |
| `ss` / `shadowsocks` — AEAD, `2022-blake3-*`, `obfs`/`v2ray-plugin` | ✅ |
| `ssr` / `shadowsocksr` | ✅ |
| `trojan` | ✅ |
| `http`, `https` | ✅ |
| `socks5` / `socks` | ✅ TCP and UDP |
| `snell` | ✅ |
| `ssh` | ✅ |
| `vmess`, `vless` | ❌ adapter not written (the crypto primitives and share-link parsing exist) |
| `hysteria`, `hysteria2`, `tuic`, `wireguard`, `anytls`, `mieru` | ❌ adapter not written |

A proxy whose `type` is not registered is **skipped with a warning**; the rest
of the configuration still loads.

Transports available to the protocols that take them: `tcp`, `tls`, `ws`,
`grpc`, `h2`, `http` (obfuscation) — selected by `network`/`*-opts`, and
composed in that order.

### 4.2 Groups

| `type` | Behaviour |
|---|---|
| `select` | The user (or `PUT /proxies/:name`) picks the member. |
| `url-test` | Fastest member wins; `tolerance` (ms) keeps the incumbent unless a challenger beats it by more. |
| `fallback` | First member that answers a health check, in configuration order. |
| `load-balance` | `strategy: consistent-hashing` (per destination host) or `round-robin`. |
| `relay` | Chains every member in order. |
| `smart` | Adaptive: `url-test` ordering plus per-domain stickiness. |

Membership keys: `proxies`, `use` (providers), `include-all`,
`include-all-proxies`, `include-all-providers`, `filter`, `exclude-filter`,
`exclude-type`. `GLOBAL` is a live selector over every registered outbound
except the built-in adapters.

---

## 5. Control API

### 5.1 Authentication

- `Authorization: Bearer <secret>` for REST calls, or `?token=<secret>` on the
  URL. Both are accepted; an empty `secret` disables authentication entirely.
- WebSockets authenticate with `?token=` only, because browsers cannot set
  headers on a handshake.
- Static dashboard assets, the SPA shell and `OPTIONS` preflights stay
  reachable without a token, so the UI can load and then prompt for the secret.

A rejected call answers `401` with an empty body. A rejected WebSocket upgrade
answers `401` before the handshake completes.

### 5.2 Errors

Every failing API call answers a JSON object with a single `message` field:

```json
{ "message": "the requested rule was not found" }
```

An unhandled exception is reported the same way with status `500`, never as an
HTML error page.

### 5.3 Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | `{"hello":"clash"}` |
| `GET` | `/version` | Version banner (`version`, `meta: true`, plus `error` when startup failed) |
| `GET`, `POST` | `/restart` | Restart the core |
| `GET`, `POST` | `/cache/fakeip/flush` | Drop the fake-IP pool |
| `GET`, `POST` | `/cache/dns/flush` | Drop the DNS answer cache |
| `GET` | `/dns/query?name=&type=` | Resolve through the live resolver |
| `GET` | `/configs`, `/configs/general` | The general configuration object |
| `PATCH` | `/configs` | Merge a partial update and hot-reload |
| `PUT` | `/configs` | Load a profile from disk (`{"path": …}`) or inline YAML (`{"payload": …}`) |
| `GET` | `/proxies` | Every adapter, grouped |
| `GET`, `PUT` | `/proxies/:name` | Inspect an adapter; select a group member (`{"name": …}`) |
| `GET` | `/proxies/:name/delay` | Probe one node (`url`, `timeout`) |
| `GET` | `/group`, `/group/:name/delay` | Group metadata; probe every member |
| `GET` | `/rules` | The ordered rule list |
| `PATCH` | `/rules` | Enable/disable a rule (`{type, payload, disabled}`) |
| `GET` | `/connections` | Snapshot: totals plus every active flow |
| `DELETE` | `/connections`, `/connections/:id` | Close one flow or all of them |
| `GET`, `PUT` | `/providers/proxies` | List providers; update one |
| `GET` | `/providers/proxies/:name` | One provider and its nodes |
| `GET` | `/providers/proxies/:name/healthcheck` | Probe every node in a provider |
| `GET`, `PUT` | `/providers/rules` | List rule providers; update one |
| `GET`, `POST` | `/profiles` | List profiles; import one |
| `PUT`, `DELETE` | `/profiles/:id` | Update metadata; delete |
| `PUT` | `/profiles/:id/select` | Activate a profile |
| `PUT` | `/profiles/:id/update` | Re-download a subscription |
| `GET` | `/profiles/:id/preview` | Render a profile as YAML |
| `PUT` | `/profiles/:id/content` | Replace a profile body |
| `POST` | `/profiles/import-url` | Import from a subscription URL |
| `POST` | `/subscription/parse` | Parse share links into proxy entries |

Not implemented, and answered with `404`: `POST /configs/geo`,
`DELETE /proxies/:name` (un-fix an automatic group), and
`/providers/proxies/:provider/:node/healthcheck`. The dashboard treats a `404`
on these as "this core does not support it" rather than an error.

### 5.4 WebSocket streams

| Path | Frame |
|---|---|
| `/traffic` | `{"up": <bytes/s>, "down": <bytes/s>}` once per second |
| `/memory` | `{"inuse": <bytes>, "oslimit": <bytes>}` once per second |
| `/logs?level=<level>` | `{"type": "<level>", "payload": "<line>"}`, new lines only |

Only new log lines are streamed: there is no backlog, matching Clash.

---

## 6. Behaviour notes

- **Hot reload.** `PATCH`/`PUT /configs` rebuilds the rule engine, the rule
  sets and the proxy registry, then swaps them into the running tunnel. In-flight
  flows keep the adapters they already hold; only new flows see the new
  configuration. The previous registry is disposed in the background.
- **Unknown keys survive.** `ClashConfig.Raw` keeps everything the parser did not
  understand, and `PATCH /configs` merges into it, so a partial update never
  drops unrelated settings.
- **A broken configuration is fixable from the UI.** The host starts even when
  the runtime fails; `GET /version` then carries an `error` field with the
  startup failure and the dashboard offers to repair the file.
- **Profiles are ordinary files.** `PUT /profiles/:id/select` records the choice
  in `profiles.json`; the runtime then loads that profile's YAML as its active
  configuration and reloads, so anything that watches the home directory sees the
  change.
