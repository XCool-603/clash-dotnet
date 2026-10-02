# wintun

`amd64/wintun.dll` is the **prebuilt binary** of [Wintun](https://www.wintun.net/),
the layer-3 TUN driver used by TUN mode. It is redistributed here under the
*Prebuilt Binaries License* that ships inside `wintun-0.14.1.zip` (kept verbatim
as `LICENSE.txt` next to this file).

Two points of that licence matter to this repository:

- Redistribution is granted **only** when the DLL is distributed alongside other
  software that uses it **solely through the API in `wintun.h`**. This project
  does exactly that: `Clash.Core/Tun/WintunInterop.cs` declares the documented
  entry points and nothing else. The `wintun.h` header is included here purely as
  the API reference the licence refers to.
- The proprietary notices must not be removed, so `LICENSE.txt` is copied to the
  build output next to the DLL.

The Wintun source is GPLv2; only the prebuilt binaries carry the permissive
licence. Do not replace this file with a locally built DLL.

| file | provenance |
|---|---|
| `amd64/wintun.dll` | `wintun-0.14.1.zip` → `bin/amd64/wintun.dll` from <https://www.wintun.net/builds/wintun-0.14.1.zip> |
| `LICENSE.txt` | the same archive, unmodified |
| `wintun.h` | the same archive, unmodified |

SHA-256 of `amd64/wintun.dll`:
`E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE`
