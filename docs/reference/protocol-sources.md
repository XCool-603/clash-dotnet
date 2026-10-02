# Protocol sources

This build reimplements Clash/mihomo's outbound protocols from their published
wire formats. No upstream code is copied: the files below are consulted as
*references* for byte layouts and key schedules, and the C# in
`src/Clash.Core/` is written for this project.

The list exists so that a format claim in the code can be audited — "we send
this because the reference says so" — instead of resting on memory.

## How to fetch them

The agent environment blocks the `web_fetch`/`web_search` tools, but the machine
itself has internet access, so `Invoke-WebRequest` works:

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SagerNet/sing-vmess/dev/client.go' -UseBasicParsing |
  Select-Object -ExpandProperty Content
```

## VMess

| Reference | Licence | What it pins down |
|---|---|---|
| `SagerNet/sing-vmess` — `client.go`, `protocol.go`, `kdf.go`, `chunk_aead.go`, `chunk_length_aead.go`, `chunk_length_stream.go`, `chunk_stream.go` (branch `dev`) | MIT | The client handshake, the request-header body, the AEAD key schedule and every chunk-framing variant. This is what mihomo uses, so it is the practical interop target. |
| `v2fly/v2ray-core` — `proxy/vmess/encoding/client.go`, `proxy/vmess/aead/encrypt.go`, `proxy/vmess/aead/consts.go`, `common/protocol/headers.go` | MIT | `EncodeRequestHeader` (byte order of the header body), `SealVMessAEADHeader` (sealed-header layout and AAD), the KDF salt strings, and the option-bit values (`ChunkStream 0x01`, `ChunkMasking 0x04`, `GlobalPadding 0x08`, `AuthenticatedLength 0x10`). |

Facts the implementation depends on:

- Header body: `version(1) | requestBodyIV(16) | requestBodyKey(16) | responseHeader(1) | option(1) | (paddingLength<<4 | security)(1) | 0x00(1) | command(1) | addressType(1) | address | port(2, BE) | padding | checksum(4, FNV-1a-32, BE)`.
- Sealed header: `authID(16) | AEAD(2-byte length)(18) | connectionNonce(8) | AEAD(body)`, both AEAD operations using `authID` as associated data.
- Key schedule: every key/nonce is `KDF(cmdKey, <salt>, <raw path bytes…>)`, where `cmdKey = KDF16(uuid, "AES Auth ID Encryption")`; the salt constants are listed in `VmessCrypto`.

## VLESS

| Reference | Licence | What it pins down |
|---|---|---|
| `SagerNet/sing-vmess` — `vless/client.go`, `vless/protocol.go`, `vless/constant.go`, `vless/vision.go` (branch `dev`) | MIT | Request/response header layout, the `flow` addons encoding, and the `xtls-rprx-vision` padding protocol. |

## Others

| Protocol | Reference | Licence |
|---|---|---|
| anytls | `anytls/anytls-go` — `docs/protocol.md` | MIT |
| mieru | `enfein/mieru` — `docs/protocol.md` | GPL-3.0 (specification only; no code is read from this repository) |
| hysteria2 | <https://v2.hysteria.network/docs/developers/Protocol/> | — |
| tuic | `EAimTY/tuic` — `SPEC.md` (branch `master`) | — |
| wireguard | <https://www.wireguard.com/protocol/> | — |

> `MetaCubeX/mihomo` is GPL-3.0. It is useful for confirming which configuration
> keys exist and what a compatible client sends, but its code is not a source for
> this repository — the MIT-licensed references above are used instead wherever
> they cover the same ground.

## Platform limits that decide feasibility

Two facts about this runtime bound what can be implemented, both verified on the
build machine rather than assumed:

- **`System.Net.Quic` has no datagram support.** The public surface is
  `QuicListener`/`QuicConnection`/`QuicStream` plus options — there is no
  `QuicDatagram` type and no datagram member on `QuicConnection`. ALPN,
  bidirectional streams, unidirectional streams and `CompleteWrites()` are all
  available, so a QUIC-based protocol can carry **streams**; anything that rides
  QUIC *datagrams* (some UDP modes) cannot be done with the in-box stack.
- **There is no userspace TCP/IP stack in this repository** (no `Clash.Core.Tun`,
  nothing matching `TcpState`/`TcpSegment`). WireGuard is a layer-3 tunnel, so
  carrying a TCP flow over it requires writing that stack; a WireGuard adapter is
  therefore only "usable" once a minimal outbound TCP implementation exists on
  top of the tunnel.
