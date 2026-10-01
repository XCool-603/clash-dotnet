# Clash / Mihomo Dashboard UX Reference

A source-level study of five Clash/Mihomo front-ends, written to be used directly as the
specification for a Vue 3 + TypeScript rebuild.

**Method.** Every claim below was read out of the actual project source, not from prose docs.
The repositories were cloned and inspected file by file; file paths are given so any statement
can be re-verified. Where a detail could not be verified, it is marked **unverified**.

---

## 0. The corpus, and how the projects relate

| Project | Version studied | Stack | Role |
| --- | --- | --- | --- |
| [haishanh/yacd](https://github.com/haishanh/yacd) | 0.3.8 | React 18 + TS + Vite 4, SCSS Modules, Chart.js 4, react-query 4, TanStack Table 8, jotai 2 | The classic reference dashboard. Still the most-copied layout. |
| [MetaCubeX/metacubexd](https://github.com/MetaCubeX/metacubexd) | 1.273.1 | **Nuxt 4.5 + Vue 3.5 + Pinia 4 + Tailwind 4 + daisyUI 5 + Highcharts 13 + ky 2** | The modern successor — and, as of this revision, **already a Vue 3 app**. |
| `Dreamacro/clash-dashboard` | 0.1.0 | React 18 + TS + Vite + UnoCSS + jotai + SWR + axios | The original. **Deleted from GitHub ~Nov 2023.** |
| [clash-verge-rev/clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev) | 2.5.7 | Tauri 2 + React 19 + MUI 9 + Emotion + react-router 8 + SWR 2 + Monaco | Desktop GUI. The only one with real profile/config management. |
| [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) | `Alpha` branch | Go | The core. Defines every API the UI consumes. |

### 0.1 The fate of `Dreamacro/clash-dashboard`

`https://github.com/Dreamacro/clash-dashboard` returns **HTTP 404** from the GitHub API, as does
`Dreamacro/clash`. Both were removed together in the November 2023 takedown. The name now
redirects: `MetaCubeX/clash-dashboard` → `MetaCubeX/Razord-meta` (a fork of `noahss/clash-dashboard`,
70 stars, last push 2023-07-02), which is **not** the original — `noahss/clash-dashboard` is a
2018-era "web port of clash" with 14 stars and a last push of 2018-09-17.

The usable backups found by GitHub search:

- **`chmod777john/clash-dashboard`** — 74 stars, last push 2023-11-04. Description: *"clash-dashboard
  最新备份，原仓库删库前一天克隆的，包含绝大部分提交记录"* ("latest backup of clash-dashboard, cloned
  the day before the original repo was deleted; contains most of the commit history"). **This is the
  copy analysed below.**
- `ayanamist/clash-dashboard` — 19 stars, last push 2024-01-06, described as *"fork of
  https://github.com/Dreamacro/clash-dashboard"*.
- `petraklux/clash-dashboard` — 46 stars, last push 2023-11-10.

The package.json in the backup still declares `"author": "Dreamacro"` and
`"repository": "git+https://github.com/Dreamacro/clash-dashboard.git"`, confirming provenance.

yacd's README describes itself as *"Yet Another [Clash](https://github.com/Dreamacro/clash)
[Dashboard](https://github.com/Dreamacro/clash-dashboard)"* — yacd is a from-scratch replacement for
it, not a fork.

### 0.2 A note on `MetaCubeX/mihomo`

`MetaCubeX/mihomo`'s **default branch `main` currently serves an unrelated Python project** — a
pydantic model for *Honkai: Star Rail* parsed data. The real Go core is on the **`Alpha`** branch
(`raw.githubusercontent.com/MetaCubeX/mihomo/Alpha/hub/route/server.go` returns the Go router;
`/main/hub/route/server.go` returns 404). All mihomo facts below were read from `Alpha`.

### 0.3 The single most important finding for this rebuild

**metacubexd — the designated "modern successor" — has already been rewritten in Vue 3.** It is a
pnpm monorepo (`packages/ui`, `packages/agent`, `packages/config-editor`, `apps/desktop`,
`apps/server`) whose UI package is **Nuxt 4.5.2 + Vue 3.5.41 + Pinia 4 + Tailwind 4.3 + daisyUI 5.7 +
`@tabler/icons-vue` + Highcharts 13 + ky 2 + `@tanstack/vue-query` 5 + `@tanstack/vue-virtual` 3 +
Monaco 0.52.2**.

Its `nuxt.config.ts` sets `ssr: false` and `router.options.hashMode: true`. Its directory layout is
the **legacy root layout** (`pages/`, `components/`, `stores/`, `composables/` at package root, no
`app/` dir), pinned with `srcDir: '.'`.

This means the rebuild has a working, production-grade Vue 3 reference implementation to copy
*architecturally* — including its Pinia store breakdown and composable naming. Section 9 draws on it
heavily, and deliberately departs from it where a non-Nuxt SPA is a better fit.

---

## 1. Page inventory

### 1.1 yacd — `src/components/Root.tsx`

Router: `HashRouter` (`react-router-dom` 6.16). Two shells: `/backend` sits outside the sidebar shell;
everything else is inside it.

| Route | Component | Notes |
| --- | --- | --- |
| `/` | `Home` | Overview / traffic |
| `/connections` | `Connections` | wrapped in `MutableConnRefCtx.Provider` |
| `/configs` | `Config` | Settings |
| `/logs` | `Logs` | |
| `/proxies` | `Proxies` | |
| `/rules` | `Rules` | |
| `/about` | `About` | fetches `GET /version` |
| `/style` | `StyleGuide` | dev only (`process.env.NODE_ENV === 'development'`) |
| `/backend` | `Backend` | external-controller endpoint picker; rendered *without* the sidebar shell |

Sidebar order and icons (`src/components/SideBar.tsx`, `react-icons/fc`):

```
/            activity  FcAreaChart   Overview
/proxies     globe     FcGlobe       Proxies
/rules       command   FcRuler       Rules
/connections link      FcLink        Conns
/configs     settings  FcSettings    Config
/logs        file      FcDocument    Logs
```

Footer: `<ThemeSwitcher />` (Radix Menubar: Auto / Dark / Light) and an `Info` link to `/about`.

**yacd has no Profiles page, no subscription import, and no config editing beyond the runtime config
fields.** It is a pure remote-control panel for a running core.

### 1.2 metacubexd — Nuxt file-based routes (`packages/ui/pages/`)

Hash-mode routing, `ssr: false`.

| Route | File | Notes |
| --- | --- | --- |
| `/` | `pages/index.vue` | redirects to `configStore.defaultPage` (default `overview`) |
| `/overview` | `pages/overview.vue` | 674 lines; the dashboard |
| `/proxies` | `pages/proxies.vue` | 1350 lines; the biggest page |
| `/rules` | `pages/rules.vue` | 806 lines |
| `/connections` | `pages/connections.vue` | 840 lines |
| `/traffic` | `pages/traffic.vue` | 500 lines — "Data Usage" (historical stats from IndexedDB) |
| `/logs` | `pages/logs.vue` | 512 lines |
| `/config` | `pages/config.vue` | 1728 lines — Core Config / XD Config / DNS Query tabs |
| `/profiles` | `pages/profiles.vue` | 786 lines — **agent/desktop only** |
| `/profiles/[id]/edit` | `pages/profiles/[id]/edit.vue` | profile editor |
| `/control` | `pages/control.vue` | 141 lines — Control Center, **agent only** |
| `/setup` | `pages/setup.vue` | 148 lines — connect form (also `layouts/blank.vue`) |

`constants/index.ts` also defines a partial enum, used for programmatic navigation:

```ts
export enum ROUTES {
  Overview = '/overview', Proxies = '/proxies', Rules = '/rules',
  Conns = '/connections', Log = '/logs', Config = '/config', Setup = '/setup',
}
```

Sidebar (`components/Sidebar.vue`), with `@tabler/icons-vue`:

```
/overview     IconHome           overview
/proxies      IconGlobe          proxies
/rules        IconRuler          rules
/connections  IconNetwork        connections
/traffic      IconChartAreaLine  dataUsage
/logs         IconFileStack      logs
/config       IconSettings       config
/profiles     IconFileCode       profiles        (pushed only when hasFeature('profiles'))
(Control Center group)  IconServerCog                    (agent only)
```

Mobile: `components/MobileBottomNav.vue` (308 lines) is a **first-class bottom nav**, not a hamburger.
`configStore.useMobileBottomNav` (default `true`) switches between bottom nav and side drawer.
`configStore.sidebarExpanded` (default `false`) persists desktop expansion.

Capability gating is a core architectural idea: `useControlInfo().hasFeature('profiles' | 'tun' |
'kernel-control' | ...)`. The remote web panel stays fully useful without an agent; agent-only
surfaces appear progressively.

### 1.3 clash-dashboard — `src/containers/App.tsx`

| Route | Component | Notes |
| --- | --- | --- |
| `/` | → `Navigate` to `/proxies` | preserves `location.search` |
| `/proxies` | `Proxies` | |
| `/logs` | `Logs` | |
| `/rules` | `Rules` | `noMobile: true` |
| `/connections` | `Connections` | `noMobile: true` |
| `/settings` | `Settings` | |

**There is no Overview page.** `containers/Overview/index.tsx` exists but is 20 lines of
`"Coming Soon..."` placeholder, and its route is commented out in `App.tsx`:

```tsx
// { path: '/', name: 'Overview', component: Overview, exact: true },
```

Also present: `containers/ExternalControllerDrawer/` — the endpoint picker, mounted in the layout
rather than as a route.

### 1.4 clash-verge-rev — `src/pages/_navigation-meta.ts`

`react-router` 8 `createBrowserRouter`; `_routers.tsx` maps `navItems` straight into child routes of
`_layout`.

| Route | Page file | Label key |
| --- | --- | --- |
| `/` | `pages/home.tsx` | `layout.components.navigation.tabs.home` |
| `/proxies` | `pages/proxies.tsx` | `...tabs.proxies` |
| `/profile` | `pages/profiles.tsx` | `...tabs.profiles` (note: **singular** `/profile`) |
| `/connections` | `pages/connections.tsx` | `...tabs.connections` |
| `/rules` | `pages/rules.tsx` | `...tabs.rules` |
| `/logs` | `pages/logs.tsx` | `...tabs.logs` |
| `/unlock` | `pages/unlock.tsx` | `...tabs.unlock` — media-unlock / connectivity test |
| `/settings` | `pages/settings.tsx` | `...tabs.settings` |

`/unlock` is unique to Verge and has no equivalent in the web dashboards. Layout is
`components/layout/layout-sidebar.tsx`; nav items are **drag-reorderable**
(`use-nav-menu-order.ts`) and each carries two icons — an MUI icon and a custom SVG — so the sidebar
can switch icon style.

---

## 2. Per-page detail

### 2.0 Endpoint and poll-interval summary across all projects

| Data | yacd | metacubexd | clash-dashboard | clash-verge-rev |
| --- | --- | --- | --- | --- |
| Traffic | `WS /traffic` | `WS /traffic` | `WS /traffic` (`StreamReader`) | Tauri plugin + `use-traffic-data.ts` |
| Memory | not consumed | `WS /memory` | not consumed | `use-memory-data.ts` |
| Connections | `WS /connections` | `WS /connections` | `WS /connections` | `use-connection-data.ts` |
| Logs | `WS /logs?level=` w/ fetch-stream fallback | `WS /logs?token=&level=` | `useLogsStreamReader` | `use-clash-log.ts` |
| Proxies | `GET /proxies` — **on mount + on window focus if >30 s stale** | `GET /proxies` + `GET /providers/proxies` | SWR `['/proxies']` | plugin |
| Configs | `GET /configs` via react-query, no interval | `GET /configs` | SWR `['/configs']` | plugin |
| Rules | `GET /rules` + `GET /providers/rules` | same | same | plugin |

**No project polls on a fixed timer for the primary live data.** All four use WebSockets for
traffic/memory/connections/logs and REST for proxies/rules/configs. yacd is the only one with an
explicit staleness rule, in `src/components/proxies/Proxies.tsx`:

```ts
const fn = () => {
  if (refFetchedTimestamp.current.startAt &&
      Date.now() - refFetchedTimestamp.current.startAt > 3e4) { // 30s
    fetchProxiesHooked();
  }
};
window.addEventListener('focus', fn, false);
```

There is **no `refetchInterval` anywhere in yacd** — a grep for `refetchInterval|setInterval|
staleTime|cacheTime` across `src/` returns no matches.

---

### 2.1 yacd — Overview (`/`, `src/components/Home.tsx`)

Layout: `ContentHeader title="Overview"`, then a two-part flex: `TrafficNow` (the stat row) above
`TrafficChart`, with `Suspense fallback={<Loading height="200px" />}` around the chart.

**API:** `WS /traffic` (for the two live speed readouts and the chart) and `WS /connections` (for the
totals and the active-connection count). No REST calls at all.

**UI elements**

`TrafficNow` (`src/components/TrafficNow.tsx`) — five label/value pairs in a row, no cards, no icons:

| Label | Source | Format |
| --- | --- | --- |
| Upload | `traffic.up` (live) | `prettyBytes(up) + '/s'` |
| Download | `traffic.down` (live) | `prettyBytes(down) + '/s'` |
| Upload Total | `connections.uploadTotal` | `prettyBytes(...)` |
| Download Total | `connections.downloadTotal` | `prettyBytes(...)` |
| Active Connections | `connections.length` | integer |

The two readouts come from two *different* sockets — speed from `/traffic`, totals from
`/connections`. Initial state is `'0 B/s'` / `'0 B'` / `0`, so the page never shows a spinner here.

**Loading / empty / error:** the chart is behind a `Suspense` with a `Loading height="200px"`
fallback (Chart.js is lazy-loaded via `use-asset`'s `createAsset`). There is no empty state and no
error state on this page — if the sockets never connect the numbers simply sit at `0 B/s`. A
top-level `ErrorBoundary` with `ErrorFallback` wraps the whole app (`Root.tsx`).

---

### 2.2 yacd — Proxies (`/proxies`)

**API**

| Call | When |
| --- | --- |
| `GET /proxies` and `GET /providers/proxies` (in `Promise.all`) | on mount; on `window` focus if last fetch started >30 s ago |
| `PUT /proxies/{group}` body `{"name": "<node>"}` | selecting a node |
| `GET /proxies/{name}/delay?timeout=5000&url=<encoded>` | single-node delay test |
| `GET /providers/proxies/{name}/healthcheck` | provider health check (used to test all nodes in a provider) |
| `PUT /providers/proxies/{name}` | update provider (re-download) |
| `GET /connections`, then `DELETE /connections/{id}` × N | "auto close old connections" after a switch |

Default latency URL, from `src/store/app.ts`: `http://www.gstatic.com/generate_204`. The per-call
default in `src/api/proxies.ts` is the same string. Timeout is hard-coded `timeout=5000`.
`fetchProviderProxies` treats **HTTP 404 as `{ providers: {} }`** for old-core compatibility.

**UI elements**

- Top bar: `ContentHeader "Proxies"`, a `TextFilter` (proxy name filter), and a settings icon button
  that opens a `BaseModal` containing the Proxies settings.
- One collapsible section per proxy group, then a `ContentHeader "Proxy Provider"` + one section per
  provider (only rendered when `items.length > 0`).
- A floating action button group (`react-tiny-fab`) bottom-right, `fabgrp { right:20px; bottom:20px }`:
  - main button: **Test Latency** (zap icon; spins while testing) → tests *all* dangling proxies and
    then health-checks every provider one by one.
  - child action: **update all proxy provider** (only when providers exist).
- Two modals: the Proxies Settings modal, and `ModalClosePrevConns`.

**Group header** (`ProxyGroup.tsx` → `CollapsibleSectionHeader`): name, `type`, node count `qty`, and
a chevron that toggles collapse. Collapse state lives in a jotai atom keyed `proxyGroup:${name}`.
Right side: a circular **Test latency** button that tests every node in that group.

**Node rendering** — a **CSS grid of cards**, not a list. Expanded groups use `ProxyList` →
`Proxy` (full card); collapsed groups use `ProxyListSummaryView` → `ProxySmall` (a coloured dot).

- `Proxy` card: node name (tooltip on hover, positioned above the trigger), then a row with the proxy
  type at `opacity: 0.2` (`0.6` when selected) and the latency text.
- `ProxySmall`: a bare `<div>` whose `background` is the latency band colour, `title` = `"<name> <n> ms"`,
  `border: 1px dotted #777` for non-proxy types (groups/DIRECT/REJECT/Relay/Unknown).
- Selection: `s0.now` class on the card whose name `=== group.now`. Only `type === 'Selector'` groups
  are selectable (`isSelectable`); clicking any other group type is a no-op.
- Keyboard: `role="menuitem"` and `Enter` triggers selection.

**Delay colour coding** (`src/components/proxies/Proxy.tsx`) — the exact thresholds:

```ts
const colorMap = {
  good:   '#67c23a', // green
  normal: '#d4b75c', // yellow
  bad:    '#e67f3c', // orange
  na:     '#909399', // grey
};
// number === 0  -> na
// number <  200 -> good
// number <  400 -> normal
// otherwise     -> bad
```

Latency text (`ProxyLatency.tsx`): `Testing` and `Error` render `- ms`; a `Result` of `0` renders
`- ms`, otherwise `"<n> ms"`. `NonProxyTypes` get the dotted-grey border instead of a fill:

```ts
['Direct','Reject','Relay','Selector','Fallback','URLTest','LoadBalance','Unknown']
```

**Sorting and filtering** (`src/components/proxies/hooks.tsx`):
`Natural | LatencyAsc | LatencyDesc | NameAsc | NameDesc`. `getSortDelay` returns `-1` for
non-proxy types and `999999` for untested nodes, so groups float to the top of a latency sort and
untested nodes sink. `hideUnavailableProxies` drops nodes whose delay is exactly `0`. The name filter
splits the query on spaces and matches **any** segment (OR, not AND).

**Group ordering** (`retrieveGroupNamesFrom`): any proxy with an `all` array is a group. Groups are
re-ordered by their index inside the `GLOBAL` group, and `GLOBAL` is pushed to the end.

**Providers** (`ProxyProviderList` / `ProxyProvider`): each provider renders as a section with its
name, `type`, `vehicleType`, `updatedAt`, and a refresh button. Providers named `default`, or with
`vehicleType === 'Compatible'`, are skipped. Provider nodes are merged into the global proxy map with
a `__provider` marker so a node's provider can be found later.

**Empty/loading/error:** `getProxyProviders` returns `[]` when absent, so the provider section is
simply omitted. There is no dedicated empty state — an empty proxy list renders an empty page. Errors
bubble to the app-level `ErrorBoundary`; `ErrorFallback` offers a reset that invalidates `['/configs']`.

---

### 2.3 yacd — Connections (`/connections`)

**API:** `WS /connections` for the live feed; `GET /connections` + `DELETE /connections/{id}` when
"auto close old connections" is on; `DELETE /connections` for Close All.

The socket is a module-level singleton with a **subscriber list** rather than a React hook, and it
handles the Page Lifecycle API: on `freeze` it closes the socket, on `resume` it reopens and resets.

**UI elements**

- `ContentHeader "Connections"`.
- `react-tabs` with two tabs, each with a count badge: **Active** and **Closed**. Counts are capped
  for display: `qty < 100 ? String(qty) : '99+'`.
- A plain `<input placeholder="Filter">` in the tab strip's right side.
- A `Fab` with **Pause Refresh** / **Resume Refresh** (turns `#e74c3c` red when paused) and a child
  action **Close All Connections** (opens a confirmation modal).
- `ModalCloseAllConnections` — a confirm dialog before `DELETE /connections`.

**Table columns** (`src/components/ConnectionTable.tsx`), rendered with TanStack Table v8:

| # | Header | accessorKey | Render |
| --- | --- | --- | --- |
| 1 | Id | `id` | **hidden** via `columnVisibility: { id: false }` |
| 2 | Host | `host` | `host:port` |
| 3 | Process | `process` | basename of `processPath` — **column omitted entirely when the core never reports `processPath`** |
| 4 | DL | `download` | `prettyBytes` |
| 5 | UL | `upload` | `prettyBytes` |
| 6 | DL Speed | `downloadSpeedCurr` | `prettyBytes + '/s'` |
| 7 | UL Speed | `uploadSpeedCurr` | `prettyBytes + '/s'` |
| 8 | Chains | `chains` | reversed, joined `' / '` |
| 9 | Rule | `rule` | `rule` or `` `${rule}(${rulePayload})` `` |
| 10 | Time | `start` | `date-fns formatDistance(now - start)` |
| 11 | Source | `source` | `sourceIP:sourcePort` |
| 12 | Destination IP | `destinationIP` | raw |
| 13 | Type | `type` | `` `${type}(${network})` `` |

Default sort: `[{ id: 'id', desc: true }]`. Sorting is client-side (`getSortedRowModel`); every
sortable header shows a `ChevronDown` rotated 180° for ascending.

**Derived fields** (`fmtConnItem`) — the client computes speeds by diffing against the previous
frame: `downloadSpeedCurr = download - prev.download`, same for upload. `host` falls back to
`destinationIP` when the core sends an empty host (direct-IP connections).

**Closed-connection retention:** connections present in the previous frame but absent from the
current one are moved to a "closed" list, **capped at 101 entries** (`slice(0, 101)`).

**Filtering** is a client-side substring match (case-insensitive) over
`host, sourceIP, sourcePort, destinationIP, chains, rule, type, network, processPath` — any one match
keeps the row.

**Pause:** when paused, the state update is skipped but `prevConnsRef` still advances, so resuming
does not produce a burst of phantom "closed" rows. An explicit optimisation skips the state update
when both the previous and current arrays are empty.

**There is no detail panel/drawer in yacd** — all fields are in the table. The `Id` column is
available but hidden by default.

**Empty state:** `renderTableOrPlaceholder` shows the `SvgYacd` mascot at 200×200 when the list is
empty. No loading state (the socket just fills in).

---

### 2.4 yacd — Logs (`/logs`)

**API:** `WS /logs` first; on socket `error` it falls back to `fetch('/logs?level=' + logLevel)` and
pumps the `ReadableStream` by splitting on `\n` (a `TextDecoder` with `{ stream: !done }` and a
carry-over buffer for partial lines). The level comes from the *core* config's `log-level`, read via
`useClashConfig()` — not from local state.

**Log level filter:** there is no in-page level selector. Changing the level happens on the Config
page; the Logs page reads it and, on change, calls `reconnect()` to reopen the socket with the new
level.

**UI elements**

- `ContentHeader "Logs"`.
- `LogSearch` — a text input bound to `store.logs.searchText` (lower-cased on write).
- A `Fab` toggling **Pause Refresh** / **Resume Refresh** (`#e74c3c` red when paused). Pausing closes
  the stream; resuming calls `reconnect`.

**Rendering:** `react-window` `FixedSizeList`, `itemSize={80}`, `width="100%"`, height from
`useRemainingViewPortHeight()`. Rows are `memo`'d with `areEqual` and keyed by `item.id`. Each row is a
two-line block: `time` | coloured `type` tag | `payload`.

**Colour coding** (`src/components/Logs.tsx`) — note these are the *core's* level strings:

```ts
const colors = {
  debug:   '#28792c',            // dark green
  info:    'var(--bg-log-info-tag)', // #454545 dark / #888 light
  warning: '#b99105',            // amber
  error:   '#c11c1c',            // red
};
```

**Buffer:** `const LogSize = 300` in `src/store/logs.ts`. It is a **circular buffer**: `appendLog`
writes at `tail` and wraps to `0` at 299, so the array is only reallocated for the first 300 entries.
`getLogsForDisplay` (a `reselect` selector) reconstructs chronological order from `tail` and then
applies the search filter over `payload` only. Alternating `even` parity gives zebra striping.

**Empty state:** when `logs.length === 0` the page renders the `SvgYacd` mascot at 200×200 plus the
translated string `no_logs`.

---

### 2.5 yacd — Config (`/configs`)

**API:** `GET /configs` (react-query, key `['/configs', apiConfig]`); `PATCH /configs` on change.

The PATCH body is post-processed by `configsPatchWorkaround`: if `socks-port` is present it also sets
`socket-port` to the same value, for backwards compatibility with older cores.

**Fields exposed** (`src/components/Config.tsx`) — deliberately minimal:

| Field | Widget | Notes |
| --- | --- | --- |
| HTTP Proxy Port (`port`) | text input | rendered only if the key exists in the response |
| SOCKS5 Proxy Port (`socks-port`) | text input | |
| Mixed Port (`mixed-port`) | text input | |
| Redir Port (`redir-port`) | text input | |
| Mode (`mode`) | `<select>` | `Global / Rule / Direct` — capitalised for display |
| Log Level (`log-level`) | `<select>` | `debug, info, warning, error, silent`; on change it also calls `logsApi.reconnect` |
| Allow LAN (`allow-lan`) | toggle switch | fires immediately |

Port inputs are validated `0..65535` on both `onChange` (state only) and `onBlur` (PATCH) — invalid
values are silently rejected. Ports PATCH on blur; mode/log-level PATCH immediately.

**Client-only settings** on the same page (not sent to the core):

- **Latency test URL** — text input, `latencyTestUrlAtom`.
- **Language** — `zh` / `en` select, `i18n.changeLanguage`.
- **Chart style** — a 4-option visual picker (`Selection2` + `TrafficChartSample`), selecting one of
  four `chartStyles` palettes.
- **Current backend** — displays `apiConfig.baseURL` and a "Switch backend" button → `/backend`.
- **Dark mode pure black** — toggle, persisted under `yacd_darkModePureBlackToggle`.

**Note the `ClashGeneralConfig` type** in `src/store/types.ts` — the full set yacd knows about, of
which only the above are surfaced:

```ts
{ port, 'socks-port', 'redir-port', 'allow-lan', mode, 'log-level',
  authentication?, 'bind-address'?, ipv6?, 'mixed-port'?, 'tproxy-port'? }
```

`// TODO support PUT /configs` is an acknowledged gap — yacd cannot reload a config file.

---

### 2.6 yacd — Rules (`/rules`)

**API:** `GET /rules` and `GET /providers/rules` (react-query). Rule providers get
`PUT /providers/rules/{name}` for refresh.

**UI:** `ContentHeader "Rules"` + `TextFilter placeholder="Filter"`. Below that, a single
`react-window` `VariableSizeList` whose item source is **providers first, then rules** —
`itemCount = rules.length + provider.names.length`. Row heights are variable: **110 px for a provider
row, 80 px for a rule row**.

Each row is not a table row but a card:

- **Rule**: index on the left; `payload` in bold on top; below it the `type` and the `proxy`. `proxy`
  is colour-coded: default `#59caf9` (blue), `DIRECT` `#f5bc41` (amber), `REJECT` `#cb3166` (pink).
- **Rule provider**: index, name, `"<vehicleType> / <behavior>"` subtitle, `"N rules"`, a refresh
  button with a rotating icon, and `Updated <timeAgo> ago` (date-fns `formatDistance`).

A `RulesPageFab` renders only when at least one rule provider exists; it updates all providers.

**Empty state:** none — an empty rules list renders an empty virtual list.

---

### 2.7 yacd — About (`/about`) and Backend (`/backend`)

`About` fetches `GET /version` via `useQuery(['/version', apiConfig], fetchVersion)` and displays the
version. `Backend` (`src/components/backend/Backend.tsx` + `BackendForm`/`BackendList`) is the
external-controller manager: a list of saved `{baseURL, secret, metaLabel, addedAt}` entries plus a
form to add one. Endpoint config can also be seeded from the query string —
`CONFIG_QUERY_PARAMS = ['hostname', 'port', 'secret', 'theme']` — and yacd then **strips those
parameters from the address bar** via `history.replaceState` so the secret does not linger in the URL.

---

### 2.8 metacubexd — Overview (`/overview`)

**API:** no direct REST calls in the page body. It reads the WebSocket-fed stores, and calls
`proxiesStore.fetchProxies()` on mount *only if* `proxies.length === 0` (needed so the "top proxies"
chart can filter out groups).

**Layout**, top to bottom:

1. `<OnboardingEmptyState context="overview" />` — self-gating first-run nudge (agent mode only).
2. **Stat grid** — `grid-cols-2 sm:grid-cols-3 xl:grid-cols-6`, six cards with staggered
   `animation-delay` (0/50/100/150/200/250 ms) and a `fade-slide-in` keyframe. Each card is a 10×10
   rounded icon tile (`bg-<role>/15 text-<role>`) plus a label/value stack. Values use
   `tabular-nums`.

   | Label | Value | Icon | Role |
   | --- | --- | --- | --- |
   | Upload | `formatBytes(latestTraffic.up) + '/s'` | `IconArrowUpRight` | `success` |
   | Download | `formatBytes(latestTraffic.down) + '/s'` | `IconArrowDownRight` | `info` |
   | Upload Total | `formatBytes(latestConnectionMsg.uploadTotal)` | `IconCloud` | `secondary` |
   | Download Total | `formatBytes(latestConnectionMsg.downloadTotal)` | `IconCloud` | `secondary` |
   | Active Connections | `latestConnectionMsg.connections.length` | `IconPlugConnected` | `warning` |
   | Memory Usage | `formatBytes(latestMemory.inuse)` | `IconCpu` | `error` |

   `formatBytes` is `byteSize(bytes).toString()` from the `byte-size` package.
3. **Endpoint banner** — `IconServer` + "Connected to:" + the endpoint URL in a monospace font.
4. **Charts grid** — `grid-cols-1 lg:grid-cols-2 xl:grid-cols-3`, each cell `h-72 lg:h-80`:
   - Traffic (`RealtimeLineChart`, `is-rate`, two series down/up)
   - Flow (Highcharts **pie**: Download Total vs Upload Total)
   - Memory (`RealtimeLineChart`, one series)
   - Connections count (`RealtimeLineChart`, `value-mode="number"`)
   - Network types (Highcharts **pie**: TCP / UDP / other)
   - Top proxies (Highcharts **bar**, top 5 by download speed, groups excluded)
5. **Network info** — `IPInfoCard` + `LatencyCard` in `md:grid-cols-2`.
6. **Network topology** — a collapsible section (`configStore.showNetworkTopology`) wrapping
   `NetworkTopology.vue` (717 lines).

**Loading state:** every chart receives `:is-loading="!store.latestX"`. `RealtimeLineChart` renders an
inline SVG `mask-image` three-dot pulse spinner centred over the chart and fades the canvas to
`opacity-0` while loading. There is no page-level empty or error state here; errors are handled
globally by `ConnectionErrorBanner` and the endpoint middleware.

**Duplicate-point guard:** the page keeps `prevTrafficTime` / `prevMemoryTime` /
`prevConnectionsTime` module-level refs initialised from the last history point, and only appends when
`Date.now() > prev`. This prevents a remount from duplicating a point.

---

### 2.9 metacubexd — Proxies (`/proxies`, 1350 lines)

**API**

| Call | Purpose |
| --- | --- |
| `GET proxies` | the proxy map |
| `GET providers/proxies` | provider sections |
| `PUT proxies/{group}` body `{"name": node}` | select |
| `DELETE proxies/{group}` | **unfix** a manual pin on a url-test/fallback/load-balance group |
| `GET proxies/{name}/delay?url=&timeout=` | single node |
| `GET providers/proxies/{provider}/{node}/healthcheck?url=&timeout=` | single node, provider-scoped |
| `GET group/{group}/delay?url=&timeout=` | **whole group in one request** |
| `PUT providers/proxies/{provider}` | update (re-download) |
| `GET providers/proxies/{provider}/healthcheck` | health-check a provider (204, async) |

Two details worth copying verbatim:

1. **Provider nodes are tested through the provider-scoped endpoint**, because a provider node may be
   absent from the global `/proxies` map or collide with another provider's node name:
   ```ts
   const path = provider
     ? `providers/proxies/${encodeURIComponent(provider)}/${encodeURIComponent(proxyName)}/healthcheck`
     : `proxies/${encodeURIComponent(proxyName)}/delay`
   ```
2. **Client timeouts are deliberately larger than the backend budget.** ky's 5 s default equalled the
   default backend timeout, so slow-but-valid nodes were aborted client-side and always showed as
   failed. The fix:
   ```ts
   timeout: Math.max(20_000, timeout + 10_000)   // single node
   timeout: Math.max(30_000, timeout * 2 + 10_000) // whole group
   ```

**Latency test URL resolution** — `configStore.resolveLatencyTestUrl(groupTestUrl)`:

```ts
latencyTestUrlSource === 'dashboard'
  ? urlForLatencyTest.value              // one uniform URL for every group
  : groupTestUrl || urlForLatencyTest.value  // each group probes its own kernel testUrl
```

Default `urlForLatencyTest` = `https://www.gstatic.com/generate_204`; default source = `'core'`;
default timeout = `5000` ms. This is a genuine improvement over yacd and worth carrying over: two
groups over the same nodes can legitimately need different probe URLs.

**Display modes** (`PROXIES_DISPLAY_MODE`, switched by `ProxiesDisplayModeSwitcher.vue`):

| Mode | Enum | Body |
| --- | --- | --- |
| Card | `cardMode` (default) | auto-fill grid of `ProxyNodeCard` |
| List | `listMode` | `ProxyNodeListItem` rows |
| Table | `tableMode` | `ProxyNodeTableRow` |
| Master–detail | `masterDetailMode` | `ProxyMasterDetail` |

The switcher is driven by `PROXIES_DISPLAY_MODE_ORDER` (a single source of truth so a mode can never
be silently missing), and `configStore` **repairs a retired/unknown persisted mode back to `CARD`**:

```ts
if (!validProxiesDisplayModes.has(proxiesDisplayMode.value))
  proxiesDisplayMode.value = PROXIES_DISPLAY_MODE.CARD
```

**Card density** (`PROXIES_CARD_SIZE`) — the grid track minimum and gap per preset:

| Preset | min card width | gap |
| --- | --- | --- |
| Comfortable (default) | 180 px | 8 px |
| Compact | 132 px | 6 px |
| Tight | 104 px | 4 px |

**Group preview** (`PROXIES_PREVIEW_TYPE`): `OFF`, `DOTS` (`ProxyPreviewDots`), `BAR`
(`ProxyPreviewBar`), `Auto` (default) — `Auto` picks dots/bar from node count, using
`proxiesPreviewAutoThreshold` (default `10`). This is how a collapsed group still communicates its
nodes' health in one line — better than yacd's collapsed dots because it is explicit.

**Sorting** (`PROXIES_ORDERING_TYPE`): `orderNatural`, `orderLatency_asc`, `orderLatency_desc`,
`orderQuality_asc`, `orderQuality_desc`, `orderName_asc`, `orderName_desc`. Default is
**`orderQuality_desc`** (not natural), and the two `QUALITY_*` modes sort by a **historical quality
score** from `utils/nodeScoring.ts` rather than the current sample, so a stale good run cannot
outrank a currently-good node.

**Latency colour coding** — thresholds are **protocol-dependent** and user-overridable
(`constants/index.ts`, `stores/config.ts`):

```ts
export enum LATENCY_QUALITY_MAP_HTTP  { NOT_CONNECTED = 0, MEDIUM = 200, HIGH = 500 }
export enum LATENCY_QUALITY_MAP_HTTPS { NOT_CONNECTED = 0, MEDIUM = 800, HIGH = 1500 }
```

```ts
const isLatencyTestByHttps = computed(() => urlForLatencyTest.value.startsWith('https'))
const latencyQualityMap = computed(() => {
  const defaults = isLatencyTestByHttps.value ? LATENCY_QUALITY_MAP_HTTPS : LATENCY_QUALITY_MAP_HTTP
  return {
    NOT_CONNECTED: defaults.NOT_CONNECTED,
    MEDIUM: latencyMediumThreshold.value > 0 ? latencyMediumThreshold.value : defaults.MEDIUM,
    HIGH:   latencyHighThreshold.value   > 0 ? latencyHighThreshold.value   : defaults.HIGH,
  }
})
```

Classification and colours (`utils/index.ts`) — note the strict `>` comparisons, so exactly `200`
is still "good":

```ts
const classifyLatency = (latency, map) => {
  if (latency > map.HIGH)          return 'slow'
  if (latency > map.MEDIUM)        return 'medium'
  if (latency === map.NOT_CONNECTED) return 'not-connected'
  return 'good'
}
const LATENCY_BAND_TEXT_CLASS = {
  slow: 'text-red-500',
  medium: 'text-yellow-500',
  'not-connected': 'text-gray',
  good: 'text-green-600',
}
```

`DESIGN.md` explicitly flags these raw Tailwind hues as **debt** and instructs migrating to the
semantic `error/warning/success` roles.

**The latency pill** (`components/Latency.vue`) is the signature component: a fixed-width `w-11`,
`rounded-md`, `text-xs font-semibold`, `tabular-nums` pill. It shows the number or `---`; while
testing it swaps in a spinning ring; the value flips in with a `latency-flip` transition
(`translateY(±6px) scale(0.85)`, `out-in` mode). It carries a full `aria-label` (`"<Test latency>, 88 ms"`)
and is only a real control when `interactive` is passed — display-only call sites (the preview bar)
stay out of the tab order. Background is
`color-mix(in oklab, currentColor 12%, transparent)`, so one colour token drives text and fill.

**Selected node indication:** `proxy-card--selected bg-primary/15 text-base-content` plus
`border border-primary`; the card is lifted above its neighbours (z-index) and has its own hover/active
transform. The card also shows `IconCircleCheckFilled` for the current selection and `IconStar` for a
recommended node.

**Node icons / flags — three distinct mechanisms, worth not conflating:**

1. **Leading emoji flag in the node name.** `ProxyNodeName.vue` calls `splitLeadingFlag(name)`
   (`utils/index.ts`), which splits a leading regional-indicator pair *or any leading emoji sequence*
   off the name and renders it in its own `<span class="mr-1.5">` so the gap is consistent. The
   provider's own trailing space is stripped to avoid a double gap.
2. **Per-connection GeoIP flags** — `useGeoLookup()` resolves the destination IP through a third-party
   IP API (`configStore.connectionGeoIPProvider`, default `ipwho.is`), gated behind
   `showConnectionGeoIP` (default **false**, because it makes outbound requests).
3. **The API's `icon` field is not used for nodes by metacubexd.** Grepping the proxy components shows
   no `icon` consumption; the flag font (`assets/fonts/TwemojiMozilla-flags.woff2`) is scoped by
   `unicode-range` to regional-indicator codepoints only.

**Provider rendering** (`ProxyProvider` / `SubscriptionInfo` / `SubscriptionUsageCard`): name,
`vehicleType`, `updatedAt`, and — when the core returns `subscriptionInfo` — upload/download/total/expiry
usage. `update` and `healthcheck` are separate actions.

**Empty / loading / error:** `ProxiesRenderWrapper` handles the layout; `ProxyEmptyState` +
`proxy-empty-state-model.ts` render the no-proxies case; `ConnectionErrorBanner` (84 lines) is the
shared "cannot reach the core" banner with a retry and a "switch endpoint" action.

---

### 2.10 metacubexd — Connections (`/connections`)

**API:** `WS /connections` (live); `DELETE connections` (close all); `DELETE connections/{id}` (close one).

**Store behaviour** (`stores/connections.ts`) — the important engineering:

- `allConnections`, `activeConnections`, `closedConnections`, `latestConnectionMsg` are all
  **`shallowRef`**, deliberately: a deep `ref` would proxy every connection and every nested metadata
  field on every per-second message. Only `.value` is ever reassigned.
- Speeds are diffed against the previous frame (`restructRawMsgToConnection`).
- **Service-restart detection:** if `uploadTotal` or `downloadTotal` *decreases*, the store treats it as
  a kernel restart and calls `resetConnectionTracking()`, `clearDataUsage()` and
  `globalStore.clearChartHistory()`.
- Closed connections are the diff between the active id set and the merged list, trimmed to
  `CONNECTIONS_TABLE_MAX_CLOSED_ROWS = 200`.
- A `watch` on `endpointStore.selectedEndpoint` resets only the restart-detection baselines, so
  switching backends does not look like a restart and wipe history.

**Columns** — `CONNECTIONS_TABLE_ACCESSOR_KEY` in `constants/index.ts` defines **21** columns, and the
user can reorder and show/hide all of them (`ConnectionsSettingsModal.vue`, persisted in
`configStore.connectionsTableColumnOrder` / `...ColumnVisibility`):

```
details, close, ID, type, process, host, sniffHost, rule, chains,
dlSpeed, ulSpeed, dl, ul, connectTime, sourceIP, sourcePort, destination,
inboundUser, hostProcess, ruleChains, traffic, flow
```

The last four are **composite, two-line cells** that aggregate atomic fields. Default visibility is
exactly **6 columns**:

```
Action (details + close) | HostProcess | RuleChains | Traffic | Flow | ConnectTime
```

The two-line cell helper is `renderTwoLineCell(primary, aux, primaryTitle?, auxTitle?)`
(`utils/connectionCells.ts`) rendering `.conn-primary` / `.conn-aux` inside `.conn-cell-stack`; when
`aux` is empty the primary line is vertically centred instead of pinned to the top.

`chains` renders **reversed and joined with `' → '`** (`[...conn.chains].reverse().join(' → ')`), so
the outermost outbound is leftmost — the opposite of yacd's `' / '`.

**Live updating:** the socket pushes roughly once per second. `CellRenderer` in
`ConnectionsTable.vue` exists specifically to keep the vnode type **stable** — passing an inline
`() => render(...)` to `<component :is>` produced a new component type each render, so Vue unmounted
and remounted every cell on every update instead of patching it:

```ts
const CellRenderer: FunctionalComponent<{ render: () => VNode | string | null }> =
  (props) => props.render() as VNode
CellRenderer.props = ['render']
```

**Toolbar** (`components/connections/ConnectionsToolbar.vue`), row 1:

1. Active / Closed tab pair with count pills.
2. Quick-filter toggle (`IconFilter`) — a literal pipe-separated term list, default
   `'DIRECT|direct|dns-out'` (`configStore.quickFilterText`, legacy storage key `quickFilterRegex`).
3. Source-IP filter (`IconMenuSelect` + `IconDeviceDesktop`) built from the unique source IPs present.
4. Sort column picker (`IconArrowsSort`) + ascending/descending toggle button.
5. Search input with a focus-within ring, then Pause/Resume, **Close** (`IconX`, turns red on hover,
   shows a spinner while closing), and Settings.

Row 2 appears **only in card mode**: a Group-by picker (`IconStack2`).

**Display modes:** `connectionsDisplayMode: 'auto' | 'table' | 'card'` (default `auto`), with a
one-time migration from the retired boolean `useMobileConnectionsTable`. In card mode the visible
columns are split: `close`, `host`, `process`, `hostProcess` form the main row, and every other
visible column is concatenated into a single ` · `-separated aux line via `buildAuxLine`.

**Copy affordance:** hovering host/hostProcess/destination/process/chains/ruleChains reveals a copy
button (`COPYABLE_COLUMN_IDS`), copying e.g. the reversed `' → '`-joined chain.

**Grouping:** any column with `groupValue` can be grouped; `toggleGrouping` sets the column and clears
`expandedGroups`; group header rows are full-width `bg-primary/5` rows with an expand/collapse icon
and a `(count)`.

**Detail modal** (`components/connections/ConnectionDetailsModal.vue`) — a `Modal` with
`max-h-[70vh]` scrolling, grouped into labelled sections:

- **Basic**: ID (monospace, `break-all`), Start (`HH:mm:ss` via dayjs), Rule, RulePayload
- **Traffic**: Download, Upload, DL Speed, UL Speed (all `byteSize`, speeds `/s`)
- **Metadata**: network, type, host, sniffHost, dnsMode
- **Source & Destination**: source `IP:port` (+ reverse-DNS hostname when
  `configStore.resolveClientHostname`), destination `IP:port` (falls back to `host:port`),
  remoteDestination, and — when GeoIP is on — geoLocation (`country · city`) and geoASN
  (`AS<n> · org`)
- **Inbound**: inboundName, inboundIP:inboundPort, inboundUser
- **Process**: process, processPath, uid
- **Chains**: one chip per chain element (`bg-neutral text-neutral-content`)
- **Special** (only when present): specialProxy, specialRules

---

### 2.11 metacubexd — Logs (`/logs`)

**API:** `WS /logs?token=<secret>&level=<logLevel>`. The level is a **query parameter on the socket
URL**, so changing it requires `reconnectLogs()` — which is exactly what the composable exposes.

**Toolbar:** search input (matches payload OR level OR the extracted `[type]` tag), Copy
(`IconCopy` → `IconCheck` for 1s), Download (Blob → `mihomo-logs-<ISO>.log`), Pause/Resume (turns
`border-warning/30 bg-warning/15 text-warning` when paused), Settings.

**Columns** (a hand-rolled column model with `render` / `sortValue` / `groupValue`):

| id | label | sortable | groupable | render |
| --- | --- | --- | --- | --- |
| `seq` | Sequence | yes | no | `String(log.seq)` |
| `level` | Level | yes | **yes** | `[<type>]` in the level colour |
| `type` | Type | yes | **yes** | the `[xxx]` prefix extracted from the payload, in `text-base-content/60` |
| `payload` | Payload | no | no | raw payload |

**`extractType`** parses a leading `[tag]` out of the payload — e.g. `"[dns] ..."` → `"dns"`. This is
how mihomo's subsystem tags (dns, tcp, udp, …) become a filterable/sortable/groupable column, which
yacd completely lacks.

**Colour coding** (`getLevelClass`) — bound to daisyUI roles, not hexes:

```ts
error   -> 'text-error font-semibold'
warning -> 'text-warning font-semibold'
info    -> 'text-info font-semibold'
debug   -> 'text-success font-semibold'
default -> ''
```

**Sorting:** 3-state cycle per column — `desc → asc → unsorted`. Persisted in
`logsTableSortColumn` / `logsTableSortDesc` (default `seq`, descending).

**Grouping:** `logsTableGrouping` (default `null`), rendered as expandable group header rows.

**Settings modal:** Table size (`xs|sm|md|lg`), Log level
(`info|error|warning|debug|silent`), Max rows.

**Buffer:** `LOGS_TABLE_MAX_ROWS_LIST = [200, 300, 500, 800, 1000]`, default **200**
(`DEFAULT_LOGS_TABLE_MAX_ROWS`). Substantially smaller than yacd's 300, but user-adjustable up to 1000.

**Virtual scrolling:** the table is **not** virtualised — it renders every row of the capped list
directly, with a `sticky top-0` header and a per-row `animate-fade-in` staggered by
`(index % 20) * 15 ms`. `@tanstack/vue-virtual` is a dependency but is used elsewhere (rules,
profiles), not here. The cap is what keeps it viable.

**Empty state:** `IconFileStack` at 48 px, `opacity-50`, plus `t('noData')`.

---

### 2.12 metacubexd — Rules (`/rules`, 806 lines)

**API:** `GET rules`, `GET providers/rules`, `PUT providers/rules/{provider}`,
`PATCH rules/disable` body `{ [index]: boolean }` — **per-rule enable/disable, which yacd cannot do.**

**Sorting** (`RULES_ORDERING_TYPE`, ordered by `RULES_ORDERING_TYPE_ORDER`): `orderNatural`,
`orderRuleType_asc/desc`, `orderName_asc/desc` (payload A–Z), `orderHitCount_desc/asc`,
`orderHitAt_desc` (recently matched first). `NATURAL` reuses the existing key so a stored preference
migrates in place.

**Filters** (persisted, with a single `resetRulesFilters()`): `rulesTypeFilter: string[]`,
`rulesPolicyFilter: string[]`, `rulesStatusFilter: 'all' | 'enabled' | 'disabled'`. Empty arrays plus
`'all'` mean "no constraint".

**Rule provider actions:** update (re-download) and health-check, matching yacd.

---

### 2.13 metacubexd — Traffic / Data Usage (`/traffic`, 500 lines)

A feature with no equivalent in yacd or clash-dashboard: **historical per-minute traffic attribution**.

`configStore.enableDataUsageTracking` (default **true**) makes the *global* connections socket diff
every connection each second and buffer the deltas into **IndexedDB** (`utils/db.ts`), flushed on a
30-second boundary aligned to the wall clock:

```ts
const delay = 30000 - (Date.now() % 30000) || 30000
```

Each buffered row is keyed by a `\x1f`-joined composite (chosen because `JSON.stringify` showed up in
profiles, and `\x1f` cannot appear in hosts/IPs/process names):

```
`${timestamp}\x1F${sourceIP}\x1F${host}\x1F${outbound}\x1F${process}\x1F${inboundUser}`
```

`outbound` is `conn.chains[0] ?? 'DIRECT'`. Retention is `traffic_data_retention` (default `-1` =
keep forever). Because it runs on *every* page, it is the largest per-second background cost, which is
why it is toggleable.

Supporting components: `TrafficDetailsTable` (367 lines), `TrafficRankings`, `TrafficTrendChart`,
`TrafficWidget`, `useDataUsage`.

---

### 2.14 metacubexd — Config (`/config`, 1728 lines)

Three top-level tabs: **Core Config**, **XD Config**, **DNS Query**. On mobile these become a tab
strip (`activeSection`).

**Core Config** — the runtime core, via `PATCH configs` / `GET configs`:

| Field | Widget | Key |
| --- | --- | --- |
| Allow LAN | switch | `allow-lan` |
| Running Mode | select | `mode` |
| Unified Delay | switch | `unified-delay` |
| Outbound Interface Name | text | `interface-name` |
| Enable TUN Device | switch | `tun.enable` |
| TUN stack | select | `tun.stack` |
| TUN device name | text | `tun.device` |

TUN is **capability-gated** and has real UX around it: `tunNeedsProfile`, `tunInstallNote`,
`tunRecoverNetwork`, `tunUninstallHelper` — because flipping TUN on a desktop app can strand the
user's network. The comment in the source says explicitly that on desktop (capability `tun`) flipping
TUN cannot simply be a `PATCH`.

**Core Config — Actions:**

| Action | Call |
| --- | --- |
| Fetch remote config (subscription URL) | with agent: `importProfile(url)` then `activateProfile(id)`; without agent: `ky.get(url)` then `PUT configs?force=true` with `{path:'', payload}` |
| Reload config | `PUT configs?force=true` `{path:'', payload:''}` |
| Restart core | `POST restart` |
| Flush FakeIP | `POST cache/fakeip/flush` |
| Flush DNS cache | `POST cache/dns/flush` |
| Update GEO databases | `POST configs/geo` (also `POST upgrade/geo`) |
| Upgrade backend | `POST upgrade` |
| Upgrade UI | `POST upgrade/ui` |

The subscription-import comment is important product logic: with an agent, importing a URL as a
persisted profile survives a restart, whereas `PUT /configs` only loads it into the running kernel and
loses it on the next restart.

**DNS Settings** (a sub-panel, `useDnsSettings`): `dns.enhanced-mode`, `dns.fake-ip-range`,
`dns.nameserver`, `dns.fallback`, `dns.use-hosts`.

**DNS Query:** an interactive `GET dns/query` tool (`useReverseDns` also uses this endpoint for PTR).

**XD Config** — dashboard-only preferences: enable Twemoji, resolve client hostname, mobile bottom
nav, default page, auto switch endpoint, auto switch theme.

**Appearance:** font family, background image (`none | custom | url`) with blur and overlay opacity,
custom daisyUI theme colour overrides (`enableCustomThemeColors` + `customThemeColors`), custom CSS.

**Settings backup:** export / import / reset, plus endpoint switch and `resetXdConfig()` /
`resetProxiesSettings()`.

---

### 2.15 metacubexd — Setup (`/setup`) and Profiles (`/profiles`)

`/setup` is the connect form (`ConnectForm.vue`, 221 lines): endpoint URL + secret, with
`checkEndpointAPI(url, secret)` returning a typed `EndpointCheckError`:

```ts
'mixed_content' | 'auth_error' | 'network_error' | null
```

- HTTP 401/403 → `auth_error` ("check the secret", not "check the URL")
- HTTPS page + `http://` endpoint → `mixed_content`
- everything else → `network_error`

The check is `ky.get(url + '/version', { timeout: 5000 })`. `FALLBACK_BACKEND_URL` is
`http://127.0.0.1:9090`. Endpoint config can be pre-filled at deploy time via
`window.__METACUBEXD_CONFIG__ = { defaultBackendURL, githubToken }` from a non-precached `config.js`.

`/profiles` (agent/desktop only): a `ProfileImportHero`, profile list with `ProfileImportHero` /
`profile-item` / `profile-more`, editor via Monaco (`MonacoYamlEditor.client.vue`), QR sharing
(`useShareQr`), `SubscriptionInfo`, and drag reordering via `sortablejs`. Types include local / remote /
merge / script, and `DEFAULT_SCRIPT_CONTENT` documents the required
`export default (config) => config` contract — explicitly **not** the Clash Verge / FlClash `main()`
convention, which is a real interop footgun.

---

### 2.16 clash-dashboard

**Overview:** none (see §1.3).

**Proxies (`/proxies`):** `containers/Proxies/` with `components/{Group,Provider,Proxy}`. Group
components support collapse. Nodes render with a delay tag; `TagColors` maps a threshold to a colour
and the code picks the *first* key whose threshold is `>= (meanDelay || delay)` — so the mapping is
ordered ascending. `alive === false` or a last-history `delay === 0` marks a node unavailable.
`config.udp && <p className="rounded bg-gray-200 p-[3px] text-gray-600">UDP</p>` renders a UDP badge.
Delay text is `delay === 0 ? '-' : `${delay}ms``. Sort is `(delayB || MAX_SAFE_INTEGER) -
(delayA || MAX_SAFE_INTEGER)`, i.e. fastest first with untested last.

**Connections (`/connections`):** `containers/Connections/` with `Devices/` and `Info/` sub-views —
the `Info` panel is the detail view. Uses `react-window` + `react-virtualized-auto-sizer`.

**Logs (`/logs`):** `containers/Logs/`.

**Rules (`/rules`):** `containers/Rules/` + `Rules/Provider/`.

**Settings (`/settings`):** two cards.

- Card 1: **Start at login** (switch, disabled unless ClashX), **Language**
  (`ButtonSelect`: 中文 / English), **Set as system proxy** (switch, disabled unless ClashX),
  **Allow connect from LAN** (switch → `allow-lan`).
- Card 2: **Proxy mode** (`ButtonSelect`: global / rule / direct, plus **script** when
  `useVersion().premium`), **SOCKS5 proxy port** (input → `socks-port`), **HTTP proxy port**
  (input → `port`), **Mixed proxy port** (input → `mixed-port`), **External controller** (a `Select`
  over saved hosts, or a read-only span under ClashX).
  Ports PATCH on blur via `client.updateConfig({...})` then re-fetch.

A commented-out "clash-version" card remains in the source.

**API client (`src/lib/request.ts`)** — axios with `baseURL: url` and
`Authorization: Bearer <secret>`:

```
GET   configs | PATCH configs | GET rules | GET providers/proxies (404 -> {providers:{}})
GET   providers/rules | PUT providers/proxies/{name} | PUT providers/rules/{name}
GET   providers/proxies/{name}/healthcheck | GET proxies | GET proxies/{name}
GET   version | GET proxies/{name}/delay?timeout=5000&url=http://www.gstatic.com/generate_204
DELETE connections | DELETE connections/{id} | GET connections
PUT   proxies/{name}  body { name }
```

Note: **`PUT proxies/{name}` is the only way to change a selection** — clash-dashboard never calls
`/group/{name}/delay`, so whole-group testing is client-side fan-out.

**Streaming (`src/lib/streamer.ts`)** — a generic `StreamReader<T>` over `eventemitter3` with
`bufferLength`, `retryInterval` (default **5000 ms**), an internal ring buffer, and reconnect-on-error.
Note the `error` handler calls `setTimeout(this.connectWebsocket, retryInterval)` **without binding
`this`** — a latent bug in the original.

---

### 2.17 clash-verge-rev

**Home (`/`)** — the richest home page of the five. Components under `src/components/home/`:
`clash-info-card`, `clash-mode-card`, `current-proxy-card`, `enhanced-canvas-traffic-graph`,
`enhanced-card`, `enhanced-traffic-stats`, `home-profile-card`, `ip-info-card`, `proxy-tun-card`,
`system-info-card`, `test-card`. So: traffic graph + traffic stats, current proxy, mode, TUN/system-proxy
state, profile, IP info, system info, and a connectivity test card.

**Proxies (`/proxies`)** — `components/proxy/`, and the most sophisticated proxy UI of the five:

- `proxy-groups.tsx` (scroll-position persistence throttled at 500 ms), `proxy-render.tsx`,
  `proxy-item.tsx`, `proxy-item-mini.tsx`, `proxy-chain.tsx`, `proxy-groups-chain.tsx`,
  `proxy-group-header-block.tsx`, `proxy-head.tsx`, `proxy-group-tools.tsx`,
  `proxy-group-navigator.tsx` (hover-jump navigator with a configurable `hoverDelay`),
  `provider-button.tsx`, `use-filter-sort.ts`, `use-render-list.ts`, `use-window-width.ts`.
- Group icons come from the API's `icon` field and are handled three ways (`proxy-render.tsx`):
  `icon?.trim().startsWith('http')` → cached to a local file via `useIconCache` and rendered as an
  `<img>`; `startsWith('data')` → data URI; `startsWith('<svg')` → inline SVG. All gated behind
  `enable_group_icon`.
- Group header colour: `alpha(theme.palette.primary.main, 0.12)` background, `bgcolor:
  'background.paper'` while dragging (groups are reorderable with `@dnd-kit`).

**Delay model — the best-designed of the five** (`src/utils/delay.ts` + `src/services/delay.ts`).

Normalisation into an explicit state machine, with sentinels that cannot be confused with
measurements:

```ts
export const DEFAULT_DELAY_TIMEOUT = 10000
const TESTING = -2
const IMPLAUSIBLE_DELAY = 1e5

classifyDelay(delay, timeout = DEFAULT_DELAY_TIMEOUT): DelayState {
  if (!Number.isFinite(delay))        return 'untested'
  if (delay === TESTING)              return 'testing'
  if (delay < 0)                      return 'untested'
  if (delay > IMPLAUSIBLE_DELAY)      return 'error'
  if (delay === 0 || delay >= timeout) return 'timeout'
  return 'measured'
}
```

Sorting ranks by state first so sentinel magnitudes cannot outrank real measurements:
`measured(0) < timeout(1) < error(2) < testing(3) < untested(4)`.

Colour and label:

```ts
formatDelay(delay, timeout) -> '-' | 'testing' | 'Timeout' | 'Error' | `${delay}`
formatDelayColor(delay, timeout) {
  untested | testing -> ''
  timeout  | error   -> 'error.main'
  measured -> delay >= 400 ? 'warning.main'
            : delay >= 250 ? 'primary.main'
            : 'success.main'
}
```

`proxy-chain.tsx` independently uses `< 200` for success and `< 800` for warning — the source comments
this: *"Colour and signal bars intentionally use different grading thresholds."*

Other delay-manager behaviour worth stealing:

- **30-minute cache TTL** (`CACHE_TTL = 30 * 60 * 1000`), falling back to the node's own
  `history[last].delay` when nothing is cached.
- **Per-group test URL map**; default when unset is `http://cp.cloudflare.com/generate_204`, and an
  invalid URL is rejected (`isValidUrl`) rather than stored.
- **Batched group testing** (`checkListDelay`) with `concurrency = 36` capped to
  `min(concurrency, names.length, 10)`, a **random 0–200 ms stagger** per request so the core is not
  hit all at once, and notification suppression until the whole batch settles
  (`activeBatches`) — explicitly so the list does not reorder around the user's pointer mid-batch.
- A **500 ms floor** per measurement so the UI never flickers a result in instantly.
- Timeouts are enforced client-side by racing a `{ delay: 0 }` promise against the API call.
- Updates are flushed on `requestAnimationFrame`, and snapshot identity is preserved
  (`groupSnapshots` / `groupSetSnapshots`) for `useSyncExternalStore` consumers.

**Connections (`/connections`)** — `components/connection/`: `connection-table.tsx` (897 lines),
`connection-row-item.tsx`, `connection-row-view.ts`, `connection-detail.tsx`,
`connection-column-manager.tsx`, `connection-relative-time.tsx`.

Base columns with explicit widths and `minWidth`s, plus a persisted `connection-table-widths` key for
user resizing and a **drag-reorder column manager**:

| field | header | width | min | align |
| --- | --- | --- | --- | --- |
| `host` | Host | 180 | 140 | |
| `download` | Downloaded | 76 | 60 | right |
| `upload` | Uploaded | 76 | 60 | right |
| `dlSpeed` | DL Speed | 76 | 60 | right |
| `ulSpeed` | UL Speed | 76 | 60 | right |
| `chains` | Chains | 280 | 160 | |
| `rule` | Rule | 220 | 160 | |
| `process` | Process | 180 | 140 | |
| `time` | Time | 100 | 80 | right |
| `source` | Source | 160 | 120 | |
| `remoteDestination` | Destination | 160 | 120 | |
| `type` | Type | 120 | 80 | |

The detail panel shows host, downloaded, uploaded, dlSpeed, ulSpeed, chains, rule, process, time,
source, destination, destinationPort, type. Row-level close uses an `IconButton` with
`aria-label={t('connections.components.actions.closeConnection')}`.

**Logs (`/logs`)** — `components/log/log-item.tsx`. The `.type` element carries
`data-type={value.type.toLowerCase()}` and is styled by attribute selector, which makes the colour
mapping robust to both `warning`/`warn` and `error`/`err` spellings:

```ts
'& .type[data-type="error"], & .type[data-type="err"]'   { color: palette.error.main }
'& .type[data-type="warning"], & .type[data-type="warn"]' { color: palette.warning.main }
'& .type[data-type="info"], & .type[data-type="inf"]'     { color: palette.info.main }
// default: palette.text.primary
```

Search hits are highlighted with `backgroundColor: mode === 'dark' ? '#ffeb3b40' : '#ffeb3b90'`.

**Profiles (`/profile`)** — the standout feature. `components/profile/`: `profile-box`, `profile-item`,
`profile-more`, `profile-viewer`, `editor-viewer`, `enhance-hint`, `file-input`, `group-item`,
`grouped-virtual-list`, `groups-editor-viewer`, `log-viewer`, `proxies-editor-viewer`,
`proxies-editor-viewer`, `proxy-item`, `qr-viewer`, `rule-item`, `rules-editor-viewer`.
Editing is Monaco-based (`components/base/monaco-editor.tsx`, `services/monaco.ts`,
`utils/yaml.worker.ts`), with `meta-json-schema` driving YAML validation. QR viewing via
`qrcode.react`. Groups are reorderable (`sortable-item.tsx` + `@dnd-kit`).

**Rules (`/rules`)** — `components/rule/rule-item.tsx` + `provider-button.tsx`.

**Unlock (`/unlock`)** — `components/test/`: `test-viewer`, `test-box`, `test-item`. Each test item has
a name, an `icon`, a `url` and a `uid`; the icon is fetched and cached through `useIconCache({ icon,
cacheKey: uid })`. This is a media-unlock / connectivity checker, not present in any web dashboard.

**Settings (`/settings`)** — five sections, from `src/locales/en/settings.json`:

| Section | Fields | Widgets |
| --- | --- | --- |
| **System Setting** (`setting-system.tsx`) | Auto Launch, Silent Start | `Switch` ×2 |
| **Proxy Control** (`proxy-control-switches.tsx`) | System Proxy, Tun Mode | `Switch` ×2, plus service install/uninstall actions |
| **Clash Setting** (`setting-clash.tsx`) | Allow LAN, IPv6, Unified Delay, DNS Overwrite | `Switch` ×4 |
| | Log Level | `Select` (debug/info/warning/error/silent) |
| | Port Config | `TextField` → `clash-port-viewer.tsx` dialog |
| | External Controller + Core Secret | `controller-viewer.tsx` dialog (`Switch` + 2 `TextField`) |
| | External Cors Configuration | `external-controller-cors.tsx` (`Switch` + origin `TextField` list) |
| | Tunnels | `tunnels-viewer.tsx` (local addr/port, target addr/port, proxy group/node `Select`s) |
| | Web UI, Clash Core, Open UWP tool, Update GeoData | dialogs / buttons |
| **Verge Basic** (`setting-verge-basic.tsx`) | Language, Theme Mode, Tray Click Event, Copy Env Type, Start Page | `Select` + `ThemeModeSwitch` |
| | Theme Setting, Layout Setting, Misc, Hotkey Setting | `theme-viewer`, `layout-viewer`, `misc-viewer`, `hotkey-viewer` dialogs |
| **Verge Advanced** (`setting-verge-advanced.tsx`) | Backup Setting, Runtime Config, Open Conf Dir, Open Core Dir, Lite Mode, Hotkey, Network Interface | dialogs (`auto-backup-settings`, `backup-config-viewer`, `backup-webdav-dialog`, `lite-mode-viewer`, `network-interface-viewer`) |

The `misc-viewer.tsx` dialog alone contains ~11 controls (`Select` ×4, `TextField` ×4, `Switch` ×3).
`dns-viewer.tsx` is ~1000 lines of DNS configuration (enhanced mode, fake-ip range, nameservers,
fallback, use-hosts, and many switches). `sysproxy-viewer.tsx` covers system-proxy bypass and PAC.

---

## 3. The Overview / Dashboard page in detail

### 3.1 yacd's traffic chart

**Data source.** `WS /traffic`, emitting `{up, down}` once per second. `src/api/traffic.ts` keeps a
module-level ring of fixed size:

```ts
const Size = 150;
const traffic = {
  labels: Array(Size).fill(0),
  up:   Array(Size),
  down: Array(Size),
  size: Size,
  appendData(o) { this.up.shift(); this.down.shift(); this.labels.shift();
                  this.up.push(o.up); this.down.push(o.down); this.labels.push(Date.now()); ... }
}
```

So **150 points at 1 Hz = a 2.5-minute sliding window**. `labels` are epoch milliseconds pushed on the
client, not values from the core.

**Chart.** Chart.js 4 line chart, canvas `id="trafficChart"`, inside a
`{ position: 'relative', maxWidth: 1000 }` wrapper. Options (`src/misc/chart.ts`):

```ts
commonDataSetProps = { borderWidth: 1, pointRadius: 0, tension: 0.2, fill: true }
commonChartOptions = {
  responsive: true,
  maintainAspectRatio: true,
  plugins: { legend: { labels: { boxWidth: 20 } } },
  scales: {
    x: { display: false, type: 'category' },   // <-- the x axis is HIDDEN
    y: { type: 'linear', display: true,
         grid: { display: true, color: '#555', drawTicks: false },
         border: { display: false, dash: [3, 6] },
         ticks: { callback: (value) => prettyBytes(value) + '/s ' } },
  },
}
```

**Key point: the x axis is not rendered at all.** There is no time axis, no tick labels, no gridlines
on x — it is a pure sparkline-style area chart with a legend. Two datasets, `Up` and `Down`.

**Unit formatting** — `prettyBytes` (`src/misc/pretty-bytes.ts`) is a hand-copied port of
sindresorhus's:

```ts
const UNITS = ['B','KB','MB','GB','TB','PB','EB','ZB','YB'];
if (n < 1000) return n + ' B';
const exponent = Math.min(Math.floor(Math.log10(n) / 3), UNITS.length - 1);
n = Number((n / Math.pow(1000, exponent)).toPrecision(3));
return n + ' ' + UNITS[exponent];
```

Decimal (1000-based), 3 significant digits, always a space before the unit. The y-axis tick callback
appends `'/s '` (note the trailing space). The two live readouts append `/s` without a space.

**Four selectable palettes** (`chartStyles`), chosen on the Config page:

| # | Up | Down |
| --- | --- | --- |
| 0 (default) | `rgba(181,220,231,0.8)` / `rgb(181,220,231)` | `rgba(176,209,132,0.8)` / `rgb(176,209,132)` |
| 1 | `rgb(98,190,100)` / `rgb(78,146,79)` | `rgb(160,230,66)` / `rgb(110,156,44)` |
| 2 | `rgba(94,175,223,0.3)` / `rgb(94,175,223)` | `rgba(139,227,195,0.3)` / `rgb(139,227,195)` |
| 3 | `rgba(242,174,62,0.3)` / `rgb(242,174,62)` | `rgba(69,154,248,0.3)` / `rgb(69,154,248)` |

**Rendering path.** `useLineChart(chart, elementId, data, subscription, extraChartOptions)` creates the
chart in a `useEffect` and subscribes to the traffic singleton; every message calls `c.update()` — a
**full chart update per second**, which is fine at 150 points. Chart.js itself is lazy-loaded through
`use-asset`'s `createAsset(() => import('$src/misc/chart-lib'))`, and the chart is wrapped in
`Suspense` with a `Loading height="200px"` fallback.

### 3.2 yacd — memory chart

**There is none.** yacd never calls `/memory` — a grep of `src/` for `memory` finds nothing outside
`node_modules`. Memory is a metacubexd and Verge feature only.

### 3.3 yacd — connection counters and total traffic

Five values, described in §2.1. Totals come from the `/connections` socket's `uploadTotal` /
`downloadTotal`, so they are cumulative since kernel start, not per-session. There is no memory tile
and no uptime tile.

### 3.4 metacubexd's Overview

Six stat tiles (see §2.8 for the exact table). Differences that matter:

- It has a **Memory Usage** tile: `formatBytes(latestMemory.inuse)` from `WS /memory` → `{inuse, oslimit}`.
- It has an **Active Connections** tile and a **Connections count chart** (a time series, not just a
  number).
- `formatBytes` is `byte-size`'s `byteSize(bytes).toString()` — decimal units, and by default
  `byte-size` renders `"1.5 MB"` style output, matching yacd's presentation closely enough.

**The traffic chart** (`components/RealtimeLineChart.vue`) — a different design from yacd's:

```ts
chart: { type: 'areaspline', animation: { duration: 800, easing: 'linear' },
         backgroundColor: themeColors.backgroundColor }
xAxis: { type: 'datetime', tickPixelInterval: 100,
         labels: { formatter() { return `${MM}:${SS}` } } }
yAxis: { labels: { formatter() { return formatValue(this.value) } }, min: 0 }
tooltip: { shared: true, formatter() { /* "<b>MM:SS</b><br/>● name: <b>value/s</b>" */ } }
plotOptions: { areaspline: { fillOpacity: 0.3, marker: { enabled: false },
                             lineWidth: 2, states: { hover: { lineWidth: 3 } },
                             threshold: null } }
```

- **A real `datetime` x axis with `MM:SS` labels** and a `tickPixelInterval` of 100 px — a genuine
  improvement on yacd's hidden axis.
- `areaspline` with `threshold: null` so the fill reaches zero rather than being clipped.
- `fillOpacity: 0.3`, `lineWidth: 2` → `3` on hover, markers off.
- Shared tooltip, `●` colour dots, `<b>` values.
- `formatValue(value, withSuffix)`: for `valueMode: 'bytes'` it is `byteSize(value).toString()`, with
  `/s` appended only when `isRate` and `withSuffix`. `valueMode: 'number'` returns `String(value)` for
  the connection-count chart.
- **Window:** `CHART_MAX_XAXIS = 30` points, and `addPoint` passes `shift = series.data.length >= 30`.
  At the core's 1 Hz emit rate that is a **30-second window** — much shorter than yacd's 150 s, chosen
  so the 800 ms linear animation stays smooth.
- **Incremental updates:** `chart.series[i].addPoint([time, value], true, shift, { duration: 800,
  easing: 'linear' })`; the batched `addPoints` groups by series, adds with redraw disabled, then calls
  `chart.redraw({ duration: 800, easing: 'linear' })` once.
- **Theme reactivity:** a `watch` on `configStore.curTheme` waits one `requestAnimationFrame` (so the
  DOM has the new CSS variables) and then `chart.update({...}, true, false, false)` with the new
  `backgroundColor`, label colours, `lineColor`, `tickColor` and `gridLineColor`.
- **Sizing:** a `ResizeObserver` calls `chart.setSize(clientWidth, clientHeight, true)`; it is
  disconnected and the chart destroyed on unmount, and the `chart` variable is nulled so a queued rAF
  cannot call `.update()` on a destroyed instance.
- **Loading:** an inline SVG three-dot pulse rendered via `mask-image` with `currentColor`, centred
  absolutely, while the canvas fades to `opacity-0`.

**Memory chart:** the same `RealtimeLineChart` with one series, `seriesColors[2]`, and
`globalStore.memoryChartHistory`.

**Flow pie:** `Download Total` vs `Upload Total`, `animation: false`, `dataLabels.enabled: false`,
`showInLegend: true`, `allowPointSelect: true`, tooltip
`` `${name}<br/>${byteSize(value)} (${percent.toFixed(1)}%)` ``.

**Network types pie:** counts TCP / UDP / other from `activeConnections`, with the `other` slice
appended only when non-zero.

**Top proxies bar:** `Object.entries(speedGroupByName)`, filtered by `!proxiesStore.isProxyGroup(name)`,
sorted descending, `slice(0, 5)`. Y axis labels `byteSize(value)/s`, `min: 0`, legend disabled.

`speedGroupByName` (in the connections store) sums each active connection's `downloadSpeed` into
**every** name in its `chains` array, so a byte is attributed to all hops it traversed.

### 3.5 clash-dashboard and Verge

- **clash-dashboard: no Overview page at all** (§1.3). It has no traffic chart, no memory chart, no
  counters.
- **clash-verge-rev Home** has the most complete set: `enhanced-canvas-traffic-graph.tsx` +
  `enhanced-traffic-stats.tsx` for traffic, `clash-info-card`, `clash-mode-card`,
  `current-proxy-card`, `proxy-tun-card`, `home-profile-card`, `ip-info-card`, `system-info-card`,
  `test-card`. It also puts a persistent mini traffic graph in the **sidebar**
  (`components/layout/traffic-graph.tsx` / `layout-traffic.tsx`), and has a dedicated traffic sampler
  (`utils/traffic-sampler.ts`, `services/traffic-monitor-worker.ts`) — a **Web Worker**, so sampling
  continues without janking the UI. `parse-traffic.ts` handles unit formatting.

---

## 4. Proxies page

### 4.1 Card grid vs list

| Project | Default | Alternatives |
| --- | --- | --- |
| yacd | **Card grid** (`Proxy` cards in a wrapping flex/grid); collapsed groups show a row of dots | none |
| metacubexd | **Card grid** (`cardMode`) with three density presets | `listMode`, `tableMode`, `masterDetailMode` |
| clash-dashboard | List of node chips | none |
| clash-verge-rev | List of node rows (`proxy-item`), plus `proxy-item-mini` for compact contexts and `proxy-groups-chain` for a chain view | — |

yacd's collapsed "summary" view is worth copying in spirit: `ProxyListSummaryView` renders one
`ProxySmall` per node — a bare coloured square with `title="<name> <n> ms"`. It gives an at-a-glance
health bar for a group without expanding it. metacubexd generalises this into
`PROXIES_PREVIEW_TYPE = OFF | DOTS | BAR | Auto`, with `Auto` switching on node count against
`proxiesPreviewAutoThreshold` (10).

### 4.2 Group collapse

- **yacd:** state in a jotai atom `collapsibleIsOpen`, keyed `proxyGroup:${name}`. Collapsed renders
  `ProxyListSummaryView`, expanded renders `ProxyList`. The group header's chevron toggles it.
- **metacubexd:** `Collapse.vue`; group state also persisted.
- **Verge:** group header blocks with scroll-position persistence throttled at 500 ms, so returning to
  a long group restores your place.

### 4.3 Indicating the currently selected node

- **yacd:** the card whose `name === group.now` gets the `s0.now` class; the proxy-type label's opacity
  changes from `0.2` to `0.6`.
- **metacubexd:** `proxy-card--selected bg-primary/15 text-base-content` + `border border-primary`,
  card lifted in z-order, plus an explicit `IconCircleCheckFilled`. A recommendation is marked with
  `IconStar`.
- **Verge:** `proxy-item` renders a check affordance; a manual pin on an automatic group can be cleared
  with `DELETE /proxies/{group}` (surfaced only when the group reports a non-empty `fixed`, because
  Selector groups return 400).

### 4.4 Delay colour coding — thresholds side by side

This is the single most important table in this document, because the four projects disagree.

| Project | Green / good | Yellow / medium | Orange / high | Red / bad | Grey / N-A |
| --- | --- | --- | --- | --- | --- |
| **yacd** | `< 200` `#67c23a` | `< 400` `#d4b75c` | `>= 400` `#e67f3c` | — | `0` or non-result `#909399` |
| **metacubexd (HTTP probe)** | `<= 200` `text-green-600` | `> 200` `text-yellow-500` | `> 500` `text-red-500` | — | `=== 0` `text-gray` |
| **metacubexd (HTTPS probe)** | `<= 800` | `> 800` | `> 1500` | — | `=== 0` |
| **clash-dashboard** | first ascending `TagColors` key `>= delay` | " | " | — | `delay === 0` → `#E5E7EB` |
| **clash-verge-rev (colour)** | `< 250` `success.main` | — | `>= 250` `primary.main`, `>= 400` `warning.main` | timeout/error `error.main` | untested/testing `''` |
| **clash-verge-rev (chain bars)** | `< 200` `success.main` | `< 800` `warning.main` | — | else `error.main` | — |

**Recommendation for the rebuild:** adopt metacubexd's protocol-dependent, user-overridable scheme
(HTTP 200/500, HTTPS 800/1500, with `latencyMediumThreshold` / `latencyHighThreshold` overrides where
`0` means "auto"), because HTTPS probes genuinely carry ~600 ms more handshake cost and a single
threshold set produces false alarms. Borrow Verge's **explicit state machine** for the non-measurement
cases (`testing`, `untested`, `timeout`, `error`, `measured`) and its **state-first sort rank**, which
is what stops a `1e6` error sentinel from sorting as "slowest node" instead of "failed node". And
follow `DESIGN.md`'s own advice: bind the bands to semantic `success`/`warning`/`error` roles rather
than raw Tailwind hues, and pair colour with a shape or icon so the signal survives colour-blindness.

### 4.5 Node icons and the `icon` field

Only **clash-verge-rev** consumes the API's `icon` field, and it supports three encodings:

```tsx
{enable_group_icon && group.icon?.trim().startsWith('http') && ( /* cached to a local file, <img> */ )}
{enable_group_icon && group.icon?.trim().startsWith('data') && ( /* data URI */ )}
{enable_group_icon && group.icon?.trim().startsWith('<svg')  && ( /* inline SVG */ )}
```

`useIconCache({ icon, cacheKey: uid })` (`src/hooks/use-icon-cache.ts`) downloads and caches remote
icons so the UI does not hit the network on every render. The same hook is used by `test-item.tsx`
(unlock tests) and `profile/group-item.tsx`.

- **yacd** never reads `icon`. It loads `country-flag-emoji-polyfill` (`TwemojiCountryFlags.woff2`) in
  `app.tsx` and calls `polyfillCountryFlagEmojis('Twemoji Country Flags', flagfont)` after a
  `setTimeout(..., 1)`, so flag emoji inside node names render on platforms without a flag font.
- **metacubexd** does not read `icon` either; it uses `splitLeadingFlag(name)` to pull a leading emoji
  flag (or any leading emoji sequence) out of the node name and render it in a separate span with a
  consistent margin, stripping the provider's own trailing space. It ships
  `assets/fonts/TwemojiMozilla-flags.woff2` scoped by `unicode-range` to regional-indicator codepoints
  only. Separately, `useGeoLookup` renders per-connection country flags from a third-party IP API.
- **clash-dashboard** has no icon support.

**Recommendation:** support all three `icon` encodings with a cache keyed on the icon string (Verge's
approach is the correct one), *and* keep the leading-flag heuristic (metacubexd's) as a zero-cost
fallback, since most subscription providers encode the country as a flag emoji in the node name rather
than as an `icon` URL.

### 4.6 Group types

- yacd treats any proxy with an `all` array as a group, and only `type === 'Selector'` as selectable.
  `NonProxyTypes = ['Direct','Reject','Relay','Selector','Fallback','URLTest','LoadBalance','Unknown']`.
- metacubexd additionally supports **unfixing** an automatic group (`DELETE /proxies/{group}`) and
  **whole-group delay testing** (`GET /group/{group}/delay`, returning `Record<string, number>`), which
  yacd cannot do.
- clash-dashboard's `Group` type lists only `'Selector' | 'URLTest' | 'Fallback'` — no LoadBalance, no
  Relay.
- Verge supports group reordering (drag) and a hover-jump navigator for long group lists.

### 4.7 The URL used for delay tests

| Project | Default probe URL | Timeout |
| --- | --- | --- |
| yacd | `http://www.gstatic.com/generate_204` (user-editable on Config) | `5000` |
| metacubexd | `https://www.gstatic.com/generate_204`; per-group kernel `testUrl` wins in `'core'` mode | `5000` (editable) |
| clash-dashboard | `http://www.gstatic.com/generate_204` | `5000` |
| clash-verge-rev | `http://cp.cloudflare.com/generate_204` | `10000` (`DEFAULT_DELAY_TIMEOUT`) |
| metacubexd connectivity board | Google `https://www.google.com/generate_204`, Cloudflare `https://cp.cloudflare.com/generate_204`, GitHub `https://github.com` | 5000 |

metacubexd's source carries a useful warning about probe choice: Cloudflare's `cdn-cgi/trace` is
GET-only and 404s on HEAD, which made a Cloudflare probe report a false "timeout";
`cp.cloudflare.com/generate_204` is the correct captive-portal endpoint for a HEAD probe.

---

## 5. Connections page

### 5.1 Column lists, side by side

**yacd** (13 defined, 1 hidden by default):

`Id` (hidden) · `Host` · `Process` (conditionally omitted) · `DL` · `UL` · `DL Speed` · `UL Speed` ·
`Chains` · `Rule` · `Time` · `Source` · `Destination IP` · `Type`

**metacubexd** (21 defined, 6 visible by default):

Visible: `Action (Details + Close)` · `HostProcess` · `RuleChains` · `Traffic` · `Flow` · `ConnectTime`

Available: `details`, `close`, `ID`, `type`, `process`, `host`, `sniffHost`, `rule`, `chains`,
`dlSpeed`, `ulSpeed`, `dl`, `ul`, `connectTime`, `sourceIP`, `sourcePort`, `destination`,
`inboundUser`, `hostProcess`, `ruleChains`, `traffic`, `flow`

**clash-verge-rev** (12, all with explicit widths, resizable and drag-reorderable):

`Host`(180) · `Downloaded`(76, right) · `Uploaded`(76, right) · `DL Speed`(76, right) ·
`UL Speed`(76, right) · `Chains`(280) · `Rule`(220) · `Process`(180) · `Time`(100, right) ·
`Source`(160) · `Destination`(160) · `Type`(120)

**clash-dashboard:** the `Info/` sub-view is the detail panel; columns are the `Connections` interface
fields (`id`, `metadata.{network,type,host,processPath,sourceIP,sourcePort,destinationPort,destinationIP}`,
`upload`, `download`, `start`, `chains`, `rule`, `rulePayload`).

### 5.2 Live-updating behaviour

All four use `WS /connections`. mihomo pushes roughly once per second. The engineering that matters:

- **Speed derivation is client-side.** All three web dashboards diff each connection against the
  previous frame: `speed = current - previous`. mihomo does not send a speed.
- **yacd** keeps a `prevConnsRef` and, when paused, still advances it so resuming does not produce a
  burst of phantom "closed" rows.
- **metacubexd** uses `shallowRef` for the connection arrays and documents why (deep proxying of
  thousands of nested metadata objects per second). It also detects kernel restart by a *decrease* in
  `uploadTotal`/`downloadTotal`.
- **Verge** keeps column widths in `connection-table-widths` and renders through a memoised
  `ConnectionRow` with a custom comparator (`prev.columns === next.columns && ...`), plus a
  `connection-relative-time` component so relative times re-render on a shared tick instead of
  per row.
- **clash-dashboard** has a `Devices` sub-view that groups connections by `metadata.sourceIP` — a nice
  affordance none of the others have.

### 5.3 Close / reject actions

- **Close one:** `DELETE /connections/{id}` — all projects.
- **Close all:** `DELETE /connections` — yacd (behind `ModalCloseAllConnections`), metacubexd
  (`closeAllConnectionsAPI`), clash-dashboard.
- **Confirmation:** only yacd confirms. metacubexd's Close button is immediate but shows an in-button
  spinner (`isClosingConnections`) and is disabled while running.
- **"Reject" is not a distinct API action in any of the four.** mihomo exposes only
  `DELETE /connections/{id}`; "reject" is expressed by routing a connection to the `REJECT` policy, not
  by a connection-level call. Any UI that offers a "Reject" button must implement it as a
  rule/policy action, not a connection action.
- **The closest thing to a bulk-targeted close** is yacd's *auto close old connections*: after a proxy
  switch it fetches `/connections` and closes every connection whose `chains` contains the group name
  but not the newly selected node name — and **excluding** the new node's own chain:
  ```ts
  if (conn.chains.indexOf(groupName) > -1 && conn.chains.indexOf(exceptionItemName) < 0)
    idsToClose.push(conn.id);
  ```

### 5.4 Sorting and searching

- **yacd:** TanStack Table v8 client-side sorting on every column; default `id desc`; 3-state header
  toggle with a rotating chevron. Search is a plain substring across
  `host, sourceIP, sourcePort, destinationIP, chains, rule, type, network, processPath` (OR semantics).
- **metacubexd:** explicit sort-column picker + asc/desc toggle (rather than per-header clicks), a
  quick-filter term list (default `DIRECT|direct|dns-out`), a source-IP filter built from observed IPs,
  a free-text global filter, and optional grouping by any groupable column.
- **Verge:** a column manager dialog for order + visibility, plus drag-resizable columns whose widths
  persist.
- **clash-dashboard:** `@tanstack/react-table` client-side.

**Recommendation:** metacubexd's combination is the most usable under load — a quick-filter term list
for the "hide the noise" case (DIRECT / dns-out), a source-IP facet for the "which device" case, and
free text for the long tail. Per-header click sorting (yacd) is more discoverable than a sort picker,
so implement both: clickable headers *and* the picker.

### 5.5 Per-connection chain display

| Project | Rendering |
| --- | --- |
| yacd | `chains.reverse().join(' / ')` in a table cell |
| metacubexd | `[...chains].reverse().join(' → ')` in the cell; one chip per element in the detail modal (`bg-neutral text-neutral-content`) |
| clash-verge-rev | `Chains` column, 280 px; chain view components (`proxy-chain.tsx`, `proxy-groups-chain.tsx`) for the topology view |
| clash-dashboard | raw `chains` array |

The reversal matters: mihomo sends `chains` innermost-first, so reversing puts the outermost outbound
leftmost, which reads as the path traffic actually took. **All projects that format it reverse it.**

### 5.6 The detail panel

Only metacubexd and Verge have one; yacd puts everything in the table.

- **metacubexd** — a modal with six labelled sections: Basic (ID, Start, Rule, RulePayload); Traffic
  (Download, Upload, DL/UL Speed); Metadata (network, type, host, sniffHost, dnsMode); Source &
  Destination (source `IP:port` + optional reverse-DNS hostname, destination `IP:port`, remoteDestination,
  optional GeoIP country/city and ASN/org); Inbound (inboundName, inboundIP:port, inboundUser);
  Process (process, processPath, uid); Chains (chips); Special (specialProxy, specialRules). It is
  `max-h-[70vh]` and scrollable, and it triggers a GeoIP lookup and (optionally) a reverse-DNS lookup
  when it opens.
- **clash-verge-rev** — an inline detail region with host, downloaded, uploaded, dlSpeed, ulSpeed,
  chains, rule, process, time, source, destination, destinationPort, type.

**Recommendation:** copy metacubexd's section grouping and Verge's inline placement. A modal is right
for a dense table on desktop, but on mobile a bottom sheet or the card-mode expansion is better.

---

## 6. Logs page

### 6.1 Level filter

| Project | Where the level lives | Values |
| --- | --- | --- |
| yacd | **the core config's `log-level`**, read via `useClashConfig()`; changing it on Config reconnects the socket | debug, info, warning, error, silent |
| metacubexd | `configStore.logLevel` (localStorage, default `info`), sent as `?level=` on the socket | info, error, warning, debug, silent |
| clash-verge-rev | core `log-level` via the Clash Setting section | debug, info, warning, error, silent |

**The socket is level-scoped.** In metacubexd the level is a query parameter on the WebSocket URL, so
changing it requires `reconnectLogs()` — which closes and reopens the socket. In yacd the level is
passed to the fetch fallback as `?level=` and the socket is reconnected on change. A rebuild must treat
"change log level" as a *stream restart*, not a client-side filter.

### 6.2 Colour coding

**yacd** — hex, applied as the background of a small type tag:

```ts
debug: '#28792c'   info: 'var(--bg-log-info-tag)'   warning: '#b99105'   error: '#c11c1c'
```
where `--bg-log-info-tag` is `#454545` (dark) / `#888` (light).

**metacubexd** — daisyUI semantic roles, applied as text colour on `[type]`:

```ts
error   -> 'text-error font-semibold'
warning -> 'text-warning font-semibold'
info    -> 'text-info font-semibold'
debug   -> 'text-success font-semibold'
default -> ''
```

**clash-verge-rev** — MUI palette roles selected by a `data-type` attribute, tolerant of both long and
short spellings (`error`/`err`, `warning`/`warn`, `info`/`inf`).

**Note the inconsistency worth fixing:** yacd renders the level as a filled tag (background), the other
two as coloured text. Filled tags are more scannable in a dense list; coloured text is calmer. Pick
one and apply it everywhere — `DESIGN.md`'s "Consistent-Affordance Rule" applies.

### 6.3 Search

- **yacd:** filters on `payload` only, lower-cased at write time, via a reselect selector.
- **metacubexd:** filters on `payload` OR `type` OR the `[subsystem]` tag extracted from the payload —
  which is why its search is genuinely useful (you can type `dns` and get every DNS line, even though
  `dns` only ever appears inside the payload).
- **Verge:** a shared `SearchState` with hit highlighting (`#ffeb3b40` dark / `#ffeb3b90` light).

**Recommendation:** implement metacubexd's `extractType` — parse a leading `[tag]` out of the payload
into its own column, then make it sortable, groupable and searchable. It is a small amount of code for
a large usability gain.

### 6.4 Pause / auto-scroll

- **yacd:** a FAB toggling Pause Refresh / Resume Refresh; pausing calls `stop()` (closes the socket),
  resuming calls `reconnect()`. The button turns `#e74c3c` red when paused.
- **metacubexd:** `logsStore.togglePaused()`; the button turns
  `border-warning/30 bg-warning/15 text-warning` when paused. The store keeps buffering and simply stops
  publishing to the view.
- **Verge:** pause plus explicit search-hit highlighting.

**Auto-scroll is implicit rather than implemented in both web dashboards.** yacd renders newest-first
(`getLogsForDisplay` walks backwards from `tail`), so new lines appear at the *top* and no scroll
management is needed. metacubexd defaults `sortColumn = 'seq'` with `sortDesc = true`, i.e. also
newest-first. **Newest-first is the pragmatic answer**: it avoids the classic "stick to bottom unless
the user scrolled up" state machine entirely. If chronological order is required, implement an explicit
`isPinnedToBottom` flag driven by a scroll listener, and only auto-scroll while it is true.

### 6.5 Virtual scrolling

| Project | Approach | Buffer |
| --- | --- | --- |
| yacd | `react-window` `FixedSizeList`, `itemSize={80}`, memoised rows, `areEqual` | circular buffer, `LogSize = 300` |
| metacubexd | **not virtualised** — plain table over a capped list | `logMaxRows` ∈ {200, 300, 500, 800, 1000}, default 200 |
| clash-dashboard | `react-window` | — |
| clash-verge-rev | `@tanstack/react-virtual` | — |

yacd's circular buffer is the nicest implementation: the array is allocated once and `tail` wraps at
299, so appending 10 000 logs causes zero array growth:

```ts
const LogSize = 300;
const tail = tailCurr >= LogSize - 1 ? 0 : tailCurr + 1;
logs[tail] = log;   // mutate intentionally for performance
```

**Recommendation:** use a **fixed-capacity ring buffer** (yacd's) with a user-selectable capacity
(metacubexd's `logMaxRows`), and virtualise with `@tanstack/vue-virtual`. Rows are uniform-height if
you clamp payload length, which keeps virtualisation trivial — but variable-height rows (wrapping long
payloads) are the reason yacd's `FixedSizeList` at 80 px occasionally clips. Prefer a virtualiser that
supports dynamic measurement, or make the row height explicitly configurable and document the clamp.

---

## 7. Settings page — every config field, grouped, with widget and hot-reload status

### 7.1 What mihomo actually accepts at runtime

This is the ground truth, read from `hub/route/configs.go` on the `Alpha` branch.

**`GET /configs`** returns the full running config.

**`PATCH /configs`** decodes into `configSchema` and applies only the non-nil fields. The complete
accepted set is:

```go
type configSchema struct {
    Port              *int                     `json:"port"`
    SocksPort         *int                     `json:"socks-port"`
    RedirPort         *int                     `json:"redir-port"`
    TProxyPort        *int                     `json:"tproxy-port"`
    MixedPort         *int                     `json:"mixed-port"`
    Tun               *tunSchema               `json:"tun"`
    TuicServer        *tuicServerSchema        `json:"tuic-server"`
    ShadowSocksConfig *string                  `json:"ss-config"`
    VmessConfig       *string                  `json:"vmess-config"`
    TcptunConfig      *string                  `json:"tcptun-config"`
    UdptunConfig      *string                  `json:"udptun-config"`
    AllowLan          *bool                    `json:"allow-lan"`
    SkipAuthPrefixes  *[]netip.Prefix          `json:"skip-auth-prefixes"`
    LanAllowedIPs     *[]netip.Prefix          `json:"lan-allowed-ips"`
    LanDisAllowedIPs  *[]netip.Prefix          `json:"lan-disallowed-ips"`
    BindAddress       *string                  `json:"bind-address"`
    Mode              *tunnel.TunnelMode       `json:"mode"`
    LogLevel          *log.LogLevel            `json:"log-level"`
    IPv6              *bool                    `json:"ipv6"`
    Sniffing          *bool                    `json:"sniffing"`
    TcpConcurrent     *bool                    `json:"tcp-concurrent"`
    FindProcessMode   *process.FindProcessMode `json:"find-process-mode"`
    InterfaceName     *string                  `json:"interface-name"`
}
```

The handler then calls, in order: `listener.SetAllowLan`, `inbound.SetSkipAuthPrefixes`,
`inbound.SetAllowedIPs`, `inbound.SetDisAllowedIPs`, `listener.SetBindAddress`, `tunnel.SetSniffing`,
`dialer.SetTcpConcurrent`, `dialer.DefaultInterface.Store`, then
`listener.ReCreate{HTTP,Socks,Redir,TProxy,Mixed,Tun,ShadowSocks,Vmess,Tuic}`, then
`tunnel.SetMode`, `tunnel.SetFindProcessMode`, `log.SetLevel`, and
`resolver.DisableIPv6 = !*IPv6`. It responds **`204 No Content`** — not a config body. A client that
expects a JSON response from `PATCH /configs` will break.

**`tunSchema`** (the `tun` object) — `enable`, `device`, `stack`, `dns-hijack`, `auto-route`,
`auto-detect-interface`, `mtu`, `gso`, `gso-max-size`, `inet6-address`, `iproute2-table-index`,
`iproute2-rule-index`, `auto-redirect`, `auto-redirect-input-mark`, `auto-redirect-output-mark`,
`auto-redirect-iproute2-fallback-rule-index`, `loopback-address`, `strict-route`, `route-address`,
`route-address-set`, `route-exclude-address`, `route-exclude-address-set`, `include-interface`,
`exclude-interface`, `include-uid`, `include-uid-range`, `exclude-uid`, `exclude-uid-range`,
`include-android-user`, `include-package`, `exclude-package`, `include-mac-address`,
`exclude-mac-address`, `endpoint-independent-nat`, `udp-timeout`, `icmp-timeout`,
`congestion-controller`, `file-descriptor`, `inet4-route-address`, `inet6-route-address`,
`inet4-route-exclude-address`, `inet6-route-exclude-address`, `recvmsgx`, `sendmsgx`.

**`PUT /configs`** takes `{ "path": string, "payload": string }` and reloads a config. Both empty
strings plus `?force=true` means "reload the current file" — which is how metacubexd implements
Reload Config.

**`POST /configs/geo`** updates the geo databases.

**Crucially, the following are NOT in `configSchema` and therefore NOT hot-reloadable via PATCH:**
`dns` (the entire block — enhanced-mode, fake-ip-range, nameserver, fallback, use-hosts, …),
`unified-delay`, `tcp-concurrent`… *(note: `tcp-concurrent` **is** accepted)*, `external-controller`,
`secret`, `external-controller-cors`, `profile` (`store-selected`, `store-fake-ip`), `geodata`,
`experimental`, `ntp`, `hosts`, `proxies`, `proxy-groups`, `proxy-providers`, `rule-providers`,
`rules`, `sub-rules`, `listeners`, `tunnels`, `authentication`, `keep-alive-*`,
`global-client-fingerprint`, `etag-support`, `sniffer`.

**Consequence for the UI:** a DNS settings panel cannot use `PATCH /configs`. metacubexd's DNS panel
therefore writes to the *agent's* profile/config layer (`useDnsSettings`), not to the running kernel —
and it labels the panel accordingly (`dnsSettingsNote`). Any rebuild must do the same, or the toggle
will appear to work and silently do nothing.

### 7.2 The exposed-field matrix

Grouped as a rebuild should group them. "Hot" = applies immediately via `PATCH /configs`.

#### Group A — Network ports (hot)

| Field | Key | Widget | Validation |
| --- | --- | --- | --- |
| HTTP proxy port | `port` | number input | 0–65535 |
| SOCKS5 proxy port | `socks-port` | number input | 0–65535 |
| Mixed port | `mixed-port` | number input | 0–65535 |
| Redir port | `redir-port` | number input | 0–65535 |
| TProxy port | `tproxy-port` | number input | 0–65535 |

yacd renders each **only if the key is present in the GET response** (`configState[f.key] !== undefined`),
which is a neat way to degrade gracefully against older cores. yacd PATCHes on blur; metacubexd uses a
dialog (`clash-port-viewer.tsx`) with a `Switch` per port plus a `TextField`.

#### Group B — Core behaviour (hot)

| Field | Key | Widget | Notes |
| --- | --- | --- | --- |
| Mode | `mode` | select | `rule` / `global` / `direct` (mihomo also accepts `script`) |
| Log level | `log-level` | select | `debug` / `info` / `warning` / `error` / `silent`. **Changing it must restart the log stream.** |
| Allow LAN | `allow-lan` | switch | |
| IPv6 | `ipv6` | switch | sets `resolver.DisableIPv6 = !value` |
| Bind address | `bind-address` | text | |
| Outbound interface name | `interface-name` | text | |
| Sniffing | `sniffing` | switch | |
| TCP concurrent | `tcp-concurrent` | switch | |
| Find process mode | `find-process-mode` | select | `always` / `strict` / `off` |
| Unified delay | `unified-delay` | switch | **NOT in configSchema — not hot.** Verge exposes it; a restart or config reload is required. |
| Skip auth prefixes | `skip-auth-prefixes` | chip list | CIDR |
| LAN allowed IPs | `lan-allowed-ips` | chip list | CIDR |
| LAN disallowed IPs | `lan-disallowed-ips` | chip list | CIDR |
| TUN enable | `tun.enable` | switch | |
| TUN stack | `tun.stack` | select | `system` / `gvisor` / `mixed` |
| TUN device | `tun.device` | text | |
| TUN auto-route | `tun.auto-route` | switch | |
| TUN auto-detect-interface | `tun.auto-detect-interface` | switch | |
| TUN DNS hijack | `tun.dns-hijack` | chip list | |
| TUN MTU | `tun.mtu` | number | |
| TUN strict route | `tun.strict-route` | switch | |
| TUN GSO | `tun.gso` | switch | |
| TUN endpoint-independent NAT | `tun.endpoint-independent-nat` | switch | |

Verge's `stack-mode-switch.tsx` is a dedicated three-way segmented control for `tun.stack`, which is
the right widget for a 3-value enum.

#### Group C — External controller (not hot; needs restart)

| Field | Key | Widget |
| --- | --- | --- |
| Enable external controller | — | switch (Verge-local) |
| Controller address | `external-controller` | text |
| Core secret | `secret` | text |
| CORS: allow private network | `external-controller-cors.allow-private-network` | switch |
| CORS: allowed origins | `external-controller-cors.allowed-origins` | chip list |

Verge's `controller-viewer.tsx` adds a copy-to-clipboard action for both the address and the secret,
with success toasts — a small touch that a rebuild should keep.

#### Group D — DNS (not hot; agent/profile only)

| Field | Key | Widget |
| --- | --- | --- |
| Enable | `dns.enable` | switch |
| Listen | `dns.listen` | text |
| IPv6 | `dns.ipv6` | switch |
| Enhanced mode | `dns.enhanced-mode` | select (`fake-ip` / `redir-host` / `normal`) |
| Fake IP range | `dns.fake-ip-range` | text |
| Fake IP filter | `dns.fake-ip-filter` | chip list |
| Default nameserver | `dns.default-nameserver` | chip list |
| Nameserver | `dns.nameserver` | chip list |
| Fallback | `dns.fallback` | chip list |
| Nameserver policy | `dns.nameserver-policy` | key/value editor |
| Fallback filter | `dns.fallback-filter` | nested object editor |
| Use hosts | `dns.use-hosts` | switch |
| Use system hosts | `dns.use-system-hosts` | switch |
| Respect rules | `dns.respect-rules` | switch |
| Proxy server nameserver | `dns.proxy-server-nameserver` | chip list |

Verge's `dns-viewer.tsx` is the reference implementation (~1000 lines, ~11 switches, ~14 text fields,
3 selects) and is worth reading before designing this panel.

#### Group E — Geo data (hot via a separate endpoint)

| Field | Key | Widget |
| --- | --- | --- |
| Geo mode | `geodata.mode` | switch/select |
| GeoData mode | `geodata.geodata-mode` | switch |
| Auto update | `geodata.geo-auto-update` | switch |
| Update interval | `geodata.geo-update-interval` | number |
| GeoX URLs | `geodata.geox-url` | 4 text fields |

Actions: **Update GeoData** → `POST /configs/geo` or `POST /upgrade/geo`.

#### Group F — Cache and lifecycle actions

| Action | Call |
| --- | --- |
| Flush FakeIP | `POST /cache/fakeip/flush` |
| Flush DNS cache | `POST /cache/dns/flush` |
| Reload config file | `PUT /configs?force=true` `{path:'', payload:''}` |
| Load a config payload | `PUT /configs?force=true` `{path:'', payload:<yaml>}` |
| Restart core | `POST /restart` |
| Upgrade core | `POST /upgrade` |
| Upgrade UI | `POST /upgrade/ui` |
| Debug GC | `PUT /debug/gc` (only when the server runs with `isDebug`) |

#### Group G — Dashboard-only preferences (never sent to the core)

These belong in a separate "Appearance / Preferences" section, clearly not mixed with core config.

| Preference | Storage key (metacubexd) | Default | Widget |
| --- | --- | --- | --- |
| Theme | `theme` | `sunset` | theme picker (32 themes) |
| Auto-switch theme | `autoSwitchTheme` | `false` | switch |
| Favourite day theme | `favDayTheme` | `nord` | select |
| Favourite night theme | `favNightTheme` | `sunset` | select |
| Proxies display mode | `proxiesDisplayMode` | `cardMode` | segmented |
| Proxies card size | `proxiesCardSize` | `comfortable` | segmented |
| Proxies ordering | `proxiesOrderingType` | `orderQuality_desc` | select |
| Proxies preview | `proxiesPreviewType` | `Auto` | segmented |
| Preview auto threshold | `proxiesPreviewAutoThreshold` | `10` | number |
| Two-column proxies | `renderProxiesInTwoColumns` | `true` | switch |
| Hide unavailable proxies | `hideUnAvailableProxies` | `false` | switch |
| Latency test URL | `urlForLatencyTest` | `https://www.gstatic.com/generate_204` | text |
| Latency URL source | `latencyTestUrlSource` | `core` | select (`core` / `dashboard`) |
| Latency timeout | `latencyTestTimeoutDuration` | `5000` | number |
| Latency medium threshold | `latencyMediumThreshold` | `0` (auto) | number |
| Latency high threshold | `latencyHighThreshold` | `0` (auto) | number |
| Auto close connections | `autoCloseConns` | `true` | switch |
| Icon height / margin | `iconHeight` / `iconMarginRight` | `24` / `8` | number |
| Sidebar expanded | `sidebarExpanded` | `false` | switch |
| Mobile bottom nav | `useMobileBottomNav` | `true` | switch |
| Default page | `defaultPage` | `overview` | select |
| Auto switch endpoint | `autoSwitchEndpoint` | `false` | switch |
| Enable Twemoji | `enableTwemoji` | `false` | switch |
| Connections table size | `connectionsTableSize` | `xs` | select |
| Connections column order/visibility | `connectionsTableColumnOrder` / `…Visibility` | see §2.10 | column manager |
| Connections display mode | `connectionsDisplayMode` | `auto` | select |
| Quick filter terms | `quickFilterRegex` | `DIRECT\|direct\|dns-out` | text |
| Logs table size | `logsTableSize` | `xs` | select |
| Log level | `logLevel` | `info` | select |
| Log max rows | `logMaxRows` | `200` | select |
| Data usage tracking | `enableDataUsageTracking` | `true` | switch |
| Data retention | `traffic_data_retention` | `-1` | number |
| Connection GeoIP | `showConnectionGeoIP` | `false` | switch |
| GeoIP provider | `connectionGeoIPProvider` | `ipwho.is` | select |
| Reverse-DNS hostnames | `resolveClientHostname` | `false` | switch |
| Background image type/URL/blur/opacity | `backgroundImage*` / `backgroundBlur` / `backgroundOverlayOpacity` | `none` / `''` / `0` / `70` | select + upload + sliders |
| Custom theme colours | `enableCustomThemeColors` / `customThemeColors` | `false` / `{}` | colour pickers |
| Font family | `fontFamily` | `''` | text |
| Custom CSS | `customCss` | `''` | textarea |
| Client source-IP tags | `clientSourceIPTags` | `[]` | key/value list |
| Rules ordering + filters | `rulesOrderingType` / `rulesTypeFilter` / `rulesPolicyFilter` / `rulesStatusFilter` | `orderNatural` / `[]` / `[]` / `all` | selects |

Verge's equivalent group adds things a desktop app needs and a web panel does not: tray click event,
start page, startup script, hotkeys, lite mode, WebDAV backup, service install/uninstall, and
"open conf dir / open core dir".

**Verge's `misc-viewer.tsx`** is a good example of a "Miscellaneous" escape hatch: ~11 controls in one
dialog, which keeps the main settings page scannable. Consider the same for the long tail above.

---

## 8. Design language

### 8.1 Layout shell

| Project | Shell |
| --- | --- |
| yacd | **Left icon sidebar**, fixed, with icon + label rows; footer holds the theme switcher and About. Content area scrolls. `.app { display: flex }`. The `/backend` route renders *outside* this shell. |
| metacubexd | **Desktop: persistent daisyUI `drawer` sidebar** (expandable, `sidebarExpanded`). **Mobile: a first-class bottom nav** (`MobileBottomNav`, 308 lines) — explicitly "not a hamburger afterthought", with parity of capability. A `TitleBar` and `GlobalTrafficIndicator` (590 lines) sit in the shell. |
| clash-dashboard | Left sidebar; `noMobile: true` on Rules and Connections, i.e. those two are hidden on mobile. |
| clash-verge-rev | Left sidebar with drag-reorderable nav items, each with an MUI icon *and* a custom SVG so the user can switch icon style; a persistent mini traffic graph in the sidebar; a custom titlebar/window-controller (Tauri). |

### 8.2 Dark/light theme

- **yacd:** `data-theme` on `<html>` with three values — `auto`, `dark`, `light` — set by `setTheme()`.
  `auto` resolves through `@media (prefers-color-scheme)`. It also maintains
  `<meta name="theme-color">`: `#eeeeee` for light, `#202020` for dark, and both with `media`
  attributes in auto mode. A "pure black" dark variant (`#000000`) is available behind a toggle stored
  in `localStorage` under `yacd_darkModePureBlackToggle`. Theme can be forced from the query string
  (`?theme=dark`), and the parameter is then stripped from the URL.
- **metacubexd:** **32 selectable daisyUI themes** (`constants/index.ts`: acid, aqua, autumn, black,
  bumblebee, business, cmyk, coffee, corporate, cupcake, cyberpunk, dark, dim, dracula, emerald,
  fantasy, forest, garden, halloween, lemonade, light, lofi, luxury, night, nord, pastel, retro,
  **sunset** (default), synthwave, valentine, winter, wireframe). Plus `autoSwitchTheme` with separate
  day/night favourites, **custom colour overrides** (`customThemeColors` maps daisyUI tokens to CSS
  values), a custom font family, and arbitrary custom CSS.
- **clash-dashboard:** `styles/variables.scss` + a theme toggle in the sidebar.
- **clash-verge-rev:** MUI `mode` (`light` | `dark` | `system`) via `ThemeModeSwitch`; a `ThemeViewer`
  dialog for custom colours; MUI's `CssBaseline`.

### 8.3 Colour palettes

**metacubexd's reference `sunset` palette** (from `DESIGN.md` front matter, oklch):

```
primary         oklch(74.703% 0.158 39.947)   "Terracotta Signal"
primary-content oklch(14.94%  0.031 39.947)   "Ember Ink"
secondary       oklch(72.537% 0.177 2.72)     "Console Rose"
accent          oklch(71.294% 0.166 299.844)  "Signal Violet"
neutral         oklch(26%     0.019 237.69)
base-100        oklch(22%     0.019 237.69)   app canvas
base-200        oklch(20%     0.019 237.69)   panels / cards
base-300        oklch(18%     0.019 237.69)   recessed / toolbars
base-content    oklch(77.383% 0.043 245.096)  "Panel Text"
info            oklch(85.559% 0.085 206.015)  "Info Cyan"
success         oklch(85.56%  0.085 144.778)  "Success Green"
warning         oklch(85.569% 0.084 74.427)   "Warning Amber"
error           oklch(85.511% 0.078 16.886)   "Error Salmon"
```

Named rules from the same document, both worth enforcing in review:

- **"The Role-Is-The-Contract Rule."** Never hardcode a hex or a raw Tailwind colour for a themeable
  surface; bind to the semantic role so it re-resolves under all 32 themes and honours user overrides.
  Raw palette colours are "a bug the moment the theme changes."
- **"The One Signal Rule."** Terracotta marks the *one* primary action or current selection per
  surface. Two terracotta primaries on one screen means one is wrong.
- **"The Flat-By-Default Rule."** Surfaces carry no shadow at rest; depth appears only on hover, drag
  and float layers, using `--lift-1/2/3` derived in `oklab` from `--color-base-content`.

**yacd's palette** (`src/components/Root.scss`) — a full CSS-variable set per theme. Dark:
`--color-background:#202020`, `--color-bg-card:#2d2d2d`, `--color-bg-sidebar:#2d2d30`,
`--color-text:#ddd`, `--color-input-bg:#2d2d30`, `--color-input-border:#3f3f3f`,
`--color-separator:#333`, `--color-row-odd:#333`, `--bg-log-info-tag:#454545`, `--bg-modal:#1f1f20`.
Light: `--color-background:#eee`, `--color-bg-card:#fafafa`, `--color-bg-sidebar:#f8f8f8`,
`--color-text:#222`, `--color-text-secondary:#646464`, `--color-row-odd:#e1e1e1`.
Plus `--color-focus-blue:#1a73e8` and `--btn-bg:#387cec`.

**clash-verge-rev's palette** (`src/pages/_theme.tsx`) — Apple/iOS system colours, which is why the app
reads as native:

| Token | Light | Dark |
| --- | --- | --- |
| primary | `#007AFF` | `#0A84FF` |
| secondary | `#FC9B76` | `#FF9F0A` |
| primary text | `#000000` | `#FFFFFF` |
| secondary text | `#3C3C4399` | `#EBEBF599` |
| info | `#007AFF` | `#0A84FF` |
| error | `#FF3B30` | `#FF453A` |
| warning | `#FF9500` | `#FF9F0A` |
| success | `#06943D` | `#30D158` |
| background | `#F5F5F5` | `#2E303D` |

Verge also uses `#24252f` as the dark card background and `#282A36` (Dracula) as the dark proxy-item
background, with `#ffffff` for light.

**yacd's semantic accents:** rule proxy colours `#59caf9` default / `#f5bc41` DIRECT / `#cb3166` REJECT;
latency bands `#67c23a` / `#d4b75c` / `#e67f3c` / `#909399`; log levels `#28792c` / `#454545` /
`#b99105` / `#c11c1c`.

### 8.4 Typography

- **metacubexd:** one family for everything — **Ubuntu** (weights 300/400/500/700), loaded via
  `@nuxt/fonts` from Google, with CJK + system fallbacks:
  `Ubuntu, 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', 'Noto Sans CJK SC', system-ui, sans-serif`.
  Flag glyphs come from `Twemoji Mozilla`, scoped by `unicode-range` to regional-indicator codepoints
  only — never the body family. The scale:

  | Role | Size | Weight | Line height | Tracking |
  | --- | --- | --- | --- | --- |
  | Display | 1.5rem / 24px | 700 | 1.2 | −0.01em |
  | Headline | 1.25rem / 20px | 700 | 1.25 | — |
  | Title | 1rem / 16px | 500 | 1.4 | — |
  | Body | 0.875rem / 14px | 400 | 1.5 | — |
  | Label | 0.75rem / 12px | 600 | 1.3 | — |

  The document is explicit that UI does not need a display/body pairing — "contrast comes from weight
  and size on a tight scale". And it mandates **`font-variant-numeric: tabular-nums` on every live
  figure** (speeds, latency, connection counts) so columns do not twitch.

- **yacd:** `--font-normal: Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica,
  Apple Color Emoji, Twemoji Country Flags, Segoe UI Emoji, Segoe UI Symbol, 'PingFang SC',
  'Microsoft YaHei', '微软雅黑', Arial, sans-serif` and
  `--font-mono: 'Roboto Mono', Menlo, monospace`. Both loaded from `@fontsource` with `<link rel=preload>`
  injection for the woff2 files.

- **clash-verge-rev:** `utils/font-family.ts` + `assets/styles/font.scss`; MUI's default Roboto stack
  with a Twemoji fallback (`assets/fonts/Twemoji.Mozilla.ttf`).

### 8.5 Spacing

- **metacubexd:** `xs 0.25rem`, `sm 0.5rem`, `md 1rem`, `lg 1.5rem`; card padding `1rem`; corner radii
  **field 0.5rem / 8px**, **box 1rem / 16px**, **pill 9999px**. `rounded-lg` is the workhorse,
  `rounded-2xl` for cards, `rounded-full` for pills.
- **yacd:** SCSS modules with local scales; a consistent `padding: 30px` on page containers
  (`Connections.tsx` uses `padding: 30, paddingBottom: 30, paddingTop: 0`) and `paddingBottom = 30`
  reserved for the FAB.
- **Verge:** MUI's default 8 px base with `sx` overrides (`px-8 py-3`-equivalent rows in settings).

### 8.6 Icon sets

| Project | Library |
| --- | --- |
| yacd | `react-feather` (UI icons: ChevronDown, Pause, Play, X, Info, Zap, Check, LogOut) + `react-icons/fc` (coloured sidebar icons: FcAreaChart, FcGlobe, FcRuler, FcDocument, FcSettings, FcLink) + hand-written SVGs (`SvgYacd`, `Equalizer`, `ZapAnimated`) |
| metacubexd | **`@tabler/icons-vue`** exclusively — IconHome, IconGlobe, IconRuler, IconNetwork, IconChartAreaLine, IconFileStack, IconSettings, IconServerCog, IconFileCode, IconArrowUpRight, IconArrowDownRight, IconCloud, IconCpu, IconPlugConnected, IconPlayerPause, IconPlayerPlay, IconSearch, IconCopy, IconDownload, IconCheck, IconSortAscending, IconSortDescending, IconZoomInFilled, IconZoomOutFilled, IconFilter, IconDeviceDesktop, IconArrowsSort, IconStack2, IconX, IconChevronDown, IconServer, IconCircleCheckFilled, IconStar |
| clash-dashboard | a custom icon font (`styles/iconfont.scss`) + `src/components/Icon` |
| clash-verge-rev | `@mui/icons-material` (outlined variants) **plus** a parallel custom SVG set in `src/assets/image/itemicon/` (home, proxies, profiles, connections, rules, logs, settings, unlock) — the user picks which set the sidebar uses |

metacubexd's `DESIGN.md` states the rule: **"one icon family"** — if "test latency" looks different on
two screens, one is wrong.

### 8.7 Responsive breakpoints

- **metacubexd (Tailwind):** `sm:` 640 px, `md:` 768 px, `lg:` 1024 px, `xl:` 1280 px. Concrete usage:
  the stat grid is `grid-cols-2 sm:grid-cols-3 xl:grid-cols-6`; the chart grid is
  `grid-cols-1 lg:grid-cols-2 xl:grid-cols-3`; charts are `h-72 lg:h-80`. Mobile gets the bottom nav and
  responsive tables — "the design, not a downgrade".
- **yacd:** SCSS media queries; the sidebar collapses to icons on narrow viewports.
- **clash-dashboard:** `md:w-1/2` two-column settings rows; `noMobile` routes are hidden entirely.
- **clash-verge-rev:** `use-window-width.ts` + `use-proxy-group-header-layout.ts` for adaptive group
  headers; desktop-only by nature.

### 8.8 Component libraries, summarised

| Project | Component library | Charting | Styling |
| --- | --- | --- | --- |
| yacd | none — hand-rolled + Radix Menubar + Reach Tooltip + react-modal + react-tabs + react-tiny-fab + sonner | **Chart.js 4.4** | SCSS Modules + CSS custom properties; Tailwind 3 present but the config is empty and it is effectively unused |
| metacubexd | **daisyUI 5** on Tailwind 4 + `@floating-ui/vue` + `vue-sonner` + `@kobalte`-style hand-rolled `Modal`/`Collapse` | **Highcharts 13** (+ `d3` for the topology view) | Tailwind 4 utility-first + daisyUI semantic roles + scoped CSS for motion |
| clash-dashboard | hand-rolled components (`Button`, `Card`, `Switch`, `Select`, `Modal`, `Drawer`, `Tag`, `Tags`, `Alert`, `Message`, `Loading`) | none (no Overview) | UnoCSS (`uno.config.ts`) + SCSS |
| clash-verge-rev | **MUI 9** (`@mui/material` + `@mui/icons-material`) + Emotion, with a `components/base/*` wrapper layer (`base-switch`, `base-styled-select`, `base-styled-text-field`, `base-dialog`, `base-page`, `base-empty`, `base-error-boundary`, `base-loading`) | custom canvas (`enhanced-canvas-traffic-graph`) + a traffic Web Worker | Emotion `styled` + `sx` + SCSS |

Note the **wrapper-layer pattern** in both metacubexd and Verge: neither uses the library's components
directly everywhere. Verge wraps MUI in `components/base/*` so the design system has a single seam;
metacubexd wraps `Modal`, `Collapse`, `Button`, `DataTable`. A rebuild should do the same.

---

## 9. A concrete Vue 3 + TypeScript implementation plan

### 9.1 Stack decision

```
Vue 3.5 (script setup, TS strict)   Vite 6+          vue-router 4 (createWebHashHistory)
Pinia 3                              VueUse            vue-sonner (toasts)
Tailwind CSS 4                       daisyUI 5 (or Naive UI — see 9.9)
ECharts 5 via vue-echarts            @tanstack/vue-virtual
ky (or axios)                        i18next / vue-i18n
@tabler/icons-vue                    byte-size, dayjs
Monaco (only if profiles are in scope)
```

Keep `createWebHashHistory`: every one of the four web dashboards uses hash routing, and it is what
makes a static bundle servable from any path behind any reverse proxy without rewrite rules.

### 9.2 Route table

```ts
// src/router/index.ts
export const routes: RouteRecordRaw[] = [
  { path: '/', redirect: () => `/overview` },                 // or configStore.defaultPage
  { path: '/setup', name: 'setup', component: () => import('@/views/SetupView.vue'),
    meta: { layout: 'blank', public: true } },

  { path: '/', component: AppShell, children: [
    { path: 'overview',    name: 'overview',    component: () => import('@/views/OverviewView.vue'),
      meta: { title: 'overview',    icon: 'IconHome' } },
    { path: 'proxies',     name: 'proxies',     component: () => import('@/views/ProxiesView.vue'),
      meta: { title: 'proxies',     icon: 'IconGlobe' } },
    { path: 'rules',       name: 'rules',       component: () => import('@/views/RulesView.vue'),
      meta: { title: 'rules',       icon: 'IconRuler' } },
    { path: 'connections', name: 'connections', component: () => import('@/views/ConnectionsView.vue'),
      meta: { title: 'connections', icon: 'IconNetwork' } },
    { path: 'traffic',     name: 'traffic',     component: () => import('@/views/TrafficView.vue'),
      meta: { title: 'dataUsage',   icon: 'IconChartAreaLine' } },
    { path: 'logs',        name: 'logs',        component: () => import('@/views/LogsView.vue'),
      meta: { title: 'logs',        icon: 'IconFileStack' } },
    { path: 'settings',    name: 'settings',    component: () => import('@/views/SettingsView.vue'),
      meta: { title: 'settings',    icon: 'IconSettings' } },

    // capability-gated; the router guard drops them when hasFeature() is false
    { path: 'profiles',    name: 'profiles',    component: () => import('@/views/ProfilesView.vue'),
      meta: { title: 'profiles', icon: 'IconFileCode', feature: 'profiles' } },
    { path: 'profiles/:id/edit', name: 'profile-edit',
      component: () => import('@/views/ProfileEditView.vue'), meta: { feature: 'profiles' } },
    { path: 'control',     name: 'control',     component: () => import('@/views/ControlView.vue'),
      meta: { title: 'controlCenter', icon: 'IconServerCog', feature: 'kernel-control' } },
  ]},

  { path: '/:pathMatch(.*)*', name: 'not-found', component: () => import('@/views/NotFoundView.vue') },
]
```

Notes:

- `/` should resolve `configStore.defaultPage` (metacubexd's behaviour) rather than hard-redirecting,
  so a returning user lands where they left off.
- `AppShell` renders `AppSidebar` (desktop drawer) **or** `AppBottomNav` (mobile), plus
  `GlobalTrafficIndicator`, `TitleBar` and `<RouterView>` inside a `<KeepAlive>` for
  overview/proxies/connections.
- A global `beforeEach` guard reads the persisted endpoint; if none is configured (or
  `checkEndpoint` fails) it redirects to `/setup` — this is metacubexd's `middleware/auth.global.ts`
  pattern.
- Feature-gated routes are filtered in the guard, and the sidebar reads the same
  `controlStore.features` set so the two can never disagree.

### 9.3 Pinia store breakdown

Nine stores. The "WS-backed" column is the important one — those stores are written to by the socket
layer and never fetched.

| Store | Holds | Source | WS-backed |
| --- | --- | --- | --- |
| `useEndpointStore` | `endpoints: Endpoint[]`, `selectedEndpointId`, `currentEndpoint`, `wsEndpointURL` (derived), `checkError` | localStorage + `GET /version` probe | no |
| `useGlobalStore` | `latestTraffic`, `latestMemory`, `trafficChartHistory`, `memoryChartHistory`, `connectionCountHistory` | `/traffic`, `/memory`, `/connections` | **yes** |
| `useConnectionsStore` | `allConnections`, `activeConnections`, `closedConnections`, `latestConnectionMsg`, `paused`, `speedGroupByName` | `/connections` | **yes** |
| `useLogsStore` | `logs` (ring buffer), `tail`, `seq`, `paused`, `searchText` | `/logs` | **yes** |
| `useProxiesStore` | `proxies`, `groupNames`, `providers`, `latency` map, `latencyHistory`, `testing` set, `selected` | `GET /proxies`, `GET /providers/proxies` + delay endpoints | no (REST + manual refresh) |
| `useRulesStore` | `rules`, `ruleProviders`, `disabled` map | `GET /rules`, `GET /providers/rules` | no |
| `useConfigStore` | core config snapshot + **all** dashboard preferences (the Group G table in §7.2) | `GET /configs` + localStorage | no |
| `useKernelStore` | `version`, `meta`, `uptime`, `kernelStatus`, `features` | `GET /version`, agent IPC | no |
| `useUiStore` | `theme`, `sidebarExpanded`, `useMobileBottomNav`, `defaultPage`, toasts, modals | localStorage | no |

**Which stores are WebSocket-backed: `global`, `connections`, `logs`.** Everything else is REST plus
explicit refresh. Do **not** put live socket data in `useConfigStore` or `useProxiesStore`.

Concrete store-shape guidance, learned from the reference implementations:

```ts
// stores/global.ts — non-reactive chart buffers
export const useGlobalStore = defineStore('global', () => {
  const latestTraffic = ref<TrafficData | null>(null)
  const latestMemory  = ref<MemoryData  | null>(null)

  // markRaw: charts read a snapshot on mount and are then updated imperatively.
  // Deep reactivity here proxies every [time, value] pair on every per-second push
  // for zero rendering benefit. (metacubexd measured this.)
  const trafficChartHistory = markRaw<{ download: Point[]; upload: Point[] }>({ download: [], upload: [] })
  const memoryChartHistory  = markRaw<Point[]>([])
  const connectionCountHistory = markRaw<Point[]>([])

  const CHART_MAX_XAXIS = 30

  function addTrafficPoint(time: number, down: number, up: number) {
    trafficChartHistory.download.push([time, down])
    trafficChartHistory.upload.push([time, up])
    if (trafficChartHistory.download.length > CHART_MAX_XAXIS) trafficChartHistory.download.shift()
    if (trafficChartHistory.upload.length   > CHART_MAX_XAXIS) trafficChartHistory.upload.shift()
  }
  // …setLatestTraffic / setLatestMemory / addMemoryPoint / addConnectionCountPoint / clearChartHistory
})
```

```ts
// stores/connections.ts — shallowRef is mandatory at this scale
const allConnections    = shallowRef<Connection[]>([])
const activeConnections = shallowRef<Connection[]>([])
const closedConnections = shallowRef<Connection[]>([])
const latestConnectionMsg = shallowRef<ConnectionsWsMsg | null>(null)
const paused = ref(false)
```

`useConnectionsStore` must also own: the speed diff against the previous frame, the kernel-restart
detection (`uploadTotal`/`downloadTotal` decreased → `globalStore.clearChartHistory()`), the
`CONNECTIONS_TABLE_MAX_CLOSED_ROWS = 200` trim, and the endpoint-change watch that resets only the
restart baselines.

`useProxiesStore` should hold a **`Map`-shaped** latency cache keyed `` `${group}\0${name}` `` with a
30-minute TTL (Verge's `CACHE_TTL`), plus a `testing: Set<string>` for the spinner state, plus a
`latencyHistory` ring per node for the sparkline in the latency pill's tooltip.

### 9.4 Composables

```
composables/
  useApi.ts                // ky instance, baseURL + Authorization: Bearer <secret>, one function per endpoint
  useWebSocket.ts          // owns the 4 sockets, reconnect, teardown  ← see below
  useTrafficStream.ts      // thin: subscribes to the traffic socket → globalStore
  useMemoryStream.ts       // thin: → globalStore
  useConnectionsStream.ts  // thin: → connectionsStore
  useLogsStream.ts         // level-aware; exposes reconnect()
  useLatencyTest.ts        // single node
  useBatchLatencyTest.ts   // group / all, with concurrency + stagger + settle-notify
  useProxies.ts            // fetch + select + unfix
  useProviders.ts          // update + healthcheck
  useRules.ts              // fetch + toggle disabled
  useConfig.ts             // GET/PATCH /configs + action wrappers
  useEndpoint.ts           // checkEndpoint(url, secret) → 'mixed_content'|'auth_error'|'network_error'|null
  useControlInfo.ts        // hasFeature('profiles'|'tun'|'kernel-control')
  useAppearance.ts         // theme, custom colours, background, custom CSS
  useKeyboardShortcuts.ts  // g d, g p, /, ?, Esc
  useVirtualList.ts        // @tanstack/vue-virtual wrapper
  useByteSize.ts           // formatBytes + formatRate
  useLatencyBands.ts       // classifyLatency + band → semantic class
```

**`useWebSocket.ts` is the single owner of the sockets.** Four sockets, one reconnect policy, one
teardown. Key behaviours to carry over verbatim from metacubexd:

```ts
const RECONNECT_DELAY = 3000

// Close WITHOUT triggering auto-reconnect — used for intentional teardown,
// so we don't reconnect a socket we closed on purpose.
const closeWs = (ws: WebSocket | null) => { if (!ws) return; ws.onclose = null; ws.close() }

// Debounced reconnect: a core restart drops all four sockets at once, so
// coalesce into ONE attempt. Each failed attempt's socket fires onclose again,
// so this keeps retrying until the backend is back.
let reconnectTimer: ReturnType<typeof setTimeout> | null = null
const scheduleReconnect = () => {
  if (reconnectTimer) return
  if (!endpointStore.currentEndpoint) return
  reconnectTimer = setTimeout(() => { reconnectTimer = null; connect() }, RECONNECT_DELAY)
}
```

Three more details that are easy to get wrong:

1. **Auth on WebSockets is a query parameter, not a header.** Browsers cannot set headers on
   `new WebSocket()`. mihomo accepts `?token=<secret>` (see the `Upgrade == "websocket" &&
   r.URL.Query().Get("token") != ""` branch in `hub/route/server.go`). REST uses
   `Authorization: Bearer <secret>`. Build the WS URL from the REST base URL by swapping the protocol:
   `http:` → `ws:`, `https:` → `wss:`.
2. **The logs socket is level-scoped.** `useLogsStream()` must expose `reconnect()` and the Settings
   page must call it whenever `log-level` changes, or the user will change the level and see no
   difference.
3. **Tear down on unmount and on endpoint change.** `onScopeDispose(disconnect)` plus a `watch` on
   `currentEndpoint` that calls `disconnect()` then `connect()`.

**`useLatencyTest.ts` / `useBatchLatencyTest.ts`** should implement Verge's model:

- Normalise to `DelayState = 'testing' | 'untested' | 'timeout' | 'error' | 'measured'` with
  `TESTING = -2`, `IMPLAUSIBLE_DELAY = 1e5`, and `delay === 0 || delay >= timeout → 'timeout'`.
- Sort by state rank first, then by value.
- Batch with `concurrency = min(36, n, 10)`, a random 0–200 ms stagger, a 500 ms floor per measurement,
  and **notify only when the whole batch settles** so the list does not reorder under the user's cursor.
- Test through the provider-scoped endpoint when the node came from a provider.
- Resolve the probe URL through `resolveLatencyTestUrl(group.testUrl)`.

**`useApi.ts`** should be a flat, typed function list mirroring mihomo's surface — no classes:

```ts
// core
getConfigs(): Promise<Config>                       // GET  configs
patchConfigs(key, value): Promise<void>             // PATCH configs   -> 204, no body
reloadConfig(): Promise<void>                       // PUT  configs?force=true {path:'',payload:''}
loadConfigPayload(yaml): Promise<void>              // PUT  configs?force=true {path:'',payload}
updateGeo(): Promise<void>                          // POST configs/geo
restartCore(): Promise<void>                        // POST restart
upgradeCore(): Promise<void>                        // POST upgrade
upgradeUI(): Promise<void>                          // POST upgrade/ui
flushFakeIp(): Promise<void>                        // POST cache/fakeip/flush
flushDns(): Promise<void>                           // POST cache/dns/flush
queryDns(name, type): Promise<DnsAnswer>            // GET  dns/query
getVersion(): Promise<VersionInfo>                  // GET  version

// proxies
getProxies(): Promise<{ proxies: Record<string, Proxy> }>
getProxyProviders(): Promise<{ providers: Record<string, ProxyProvider> }>
selectProxy(group, node): Promise<void>             // PUT  proxies/{group}   {name}
unfixProxy(group): Promise<void>                    // DELETE proxies/{group}
testProxyDelay(name, url, timeout, provider?): Promise<{ delay: number }>
testGroupDelay(group, url, timeout): Promise<Record<string, number>>
updateProxyProvider(name): Promise<void>            // PUT  providers/proxies/{name}
healthcheckProvider(name): Promise<void>            // GET  providers/proxies/{name}/healthcheck

// rules
getRules(): Promise<{ rules: Record<string, Rule> }>
getRuleProviders(): Promise<{ providers: Record<string, RuleProvider> }>
updateRuleProvider(name): Promise<void>             // PUT  providers/rules/{name}
toggleRuleDisabled(index, disabled): Promise<void>  // PATCH rules/disable {[index]: disabled}

// connections
closeAllConnections(): Promise<void>                // DELETE connections
closeConnection(id): Promise<void>                  // DELETE connections/{id}
```

Plus the agent-only calls behind `hasFeature()`: `importProfile(url)`, `activateProfile(id)`,
`updateProfile(id)`, `deleteProfile(id)`, `getProfiles()`, and the kernel-control calls
(`startKernel`, `stopKernel`, `restartKernel`).

### 9.5 Component tree per page

```
App.vue
└─ AppShell.vue
   ├─ TitleBar.vue
   ├─ AppSidebar.vue  |  AppBottomNav.vue        (v-if configStore.useMobileBottomNav)
   │  └─ NavItem.vue (icon + label + active state + optional drag reorder)
   ├─ GlobalTrafficIndicator.vue                  (always-on mini sparkline + speeds)
   ├─ ConnectionErrorBanner.vue                   (shared failure surface)
   ├─ <RouterView>  (KeepAlive for overview/proxies/connections)
   └─ ToastHost.vue (vue-sonner)
```

**OverviewView.vue**

```
OverviewView
├─ OnboardingEmptyState.vue                      (agent + no profile only)
├─ StatGrid
│  └─ StatCard.vue ×6                            (icon tile + label + value, tabular-nums)
├─ EndpointBanner.vue
├─ ChartGrid
│  ├─ TrafficChartCard
│  │  └─ RealtimeChart.vue                       (2 series, isRate)
│  ├─ FlowPieCard        → RealtimeChart (pie mode) | BaseChart.vue
│  ├─ MemoryChartCard    → RealtimeChart.vue     (1 series)
│  ├─ ConnsChartCard     → RealtimeChart.vue     (valueMode="number")
│  ├─ NetworkTypesCard   → BaseChart.vue         (pie)
│  └─ TopProxiesCard     → BaseChart.vue         (bar, top 5)
├─ InfoRow
│  ├─ IpInfoCard.vue
│  └─ LatencyCard.vue                            (client-side reachability probe)
└─ NetworkTopologySection.vue                    (collapsible; d3 or an ECharts graph)
```

**ProxiesView.vue**

```
ProxiesView
├─ ProxiesToolbar.vue
│  ├─ SearchInput.vue
│  ├─ DisplayModeSwitcher.vue                    (card | list | table | masterDetail)
│  ├─ CardSizeSelect.vue                         (comfortable | compact | tight)
│  ├─ SortSelect.vue                             (7 orderings; default quality_desc)
│  ├─ PreviewTypeSelect.vue                      (off | dots | bar | auto)
│  ├─ HideUnavailableToggle.vue
│  ├─ AlphabetIndexToggle.vue
│  └─ ProxiesSettingsButton.vue → ProxiesSettingsModal.vue
├─ TestAllFab.vue                                (test all + update all providers)
├─ ProxyGroupSection.vue ×N
│  ├─ ProxyGroupHeader.vue                       (name, type, count, chevron, test-group button)
│  ├─ ProxyPreviewBar.vue | ProxyPreviewDots.vue (collapsed)
│  └─ ProxyNodeGrid.vue                          (expanded; auto-fill, min-width by density)
│     └─ ProxyNodeCard.vue ×N
│        ├─ ProxyNodeIcon.vue                    (icon field: http | data | svg, else flag emoji)
│        ├─ ProxyNodeName.vue                    (splitLeadingFlag)
│        ├─ LatencyPill.vue                      (fixed width, tabular-nums, spinner, flip)
│        └─ SelectedIndicator.vue                (check icon + primary border/ring)
├─ ProxyProviderSection.vue ×N
│  ├─ ProviderHeader.vue (name, vehicleType, updatedAt, update + healthcheck buttons)
│  └─ SubscriptionUsageCard.vue                  (when subscriptionInfo is present)
├─ ProxyEmptyState.vue
└─ Modals: ProxySettingsModal, UnfixConfirmModal, ClosePrevConnsModal
```

**ConnectionsView.vue**

```
ConnectionsView
├─ ConnectionsToolbar.vue
│  ├─ TabSwitcher.vue                            (Active | Closed, with count pills)
│  ├─ QuickFilterToggle.vue
│  ├─ SourceIpFilter.vue
│  ├─ SortControl.vue (column picker + asc/desc)
│  ├─ SearchInput.vue
│  ├─ PauseToggle.vue
│  ├─ CloseAllButton.vue                         (spinner + disabled while closing)
│  └─ SettingsButton.vue → ConnectionsSettingsModal.vue   (columns, sizes, GeoIP, display mode)
├─ ConnectionsTable.vue                          (virtualised)
│  ├─ ConnectionsTableHeader.vue                 (sticky; sort + group affordances)
│  ├─ ConnectionGroupRow.vue                     (when grouping)
│  └─ ConnectionRow.vue ×N
│     └─ ConnectionCell.vue                      (stable-identity renderer — see below)
├─ ConnectionsCardList.vue                       (card mode; ConnectionCard.vue)
├─ ConnectionsPagination.vue
└─ ConnectionDetailsModal.vue                    (6 labelled sections)
```

The stable-cell renderer is not optional. In Vue, `<component :is="() => render(row)" />` creates a new
component type every render, so Vue **unmounts and remounts every cell** on each WebSocket tick:

```ts
// components/connections/ConnectionCell.vue — constant vnode type, changing prop
export default defineComponent({
  props: { render: { type: Function, required: true } },
  setup: (props) => () => props.render(),
})
```

**LogsView.vue**

```
LogsView
├─ LogsToolbar.vue
│  ├─ SearchInput.vue
│  ├─ CopyButton.vue / DownloadButton.vue
│  ├─ PauseToggle.vue
│  └─ SettingsButton.vue → LogsSettingsModal.vue (table size, level, max rows)
├─ LogsTable.vue
│  ├─ LogsTableHeader.vue                        (sort + group toggles per column)
│  ├─ LogGroupRow.vue
│  └─ LogRow.vue ×N                              (virtualised; seq | level | type | payload)
└─ EmptyState.vue
```

**RulesView.vue**

```
RulesView
├─ RulesToolbar.vue (search, type filter, policy filter, status filter, sort, reset)
├─ RuleProviderList.vue → RuleProviderCard.vue ×N   (name, vehicleType/behavior, ruleCount,
│                                                     updatedAt, update + healthcheck)
├─ RulesVirtualList.vue
│  └─ RuleRow.vue ×N   (index, payload, type, policy colour-coded; enable/disable switch)
└─ EmptyState.vue
```

**SettingsView.vue**

```
SettingsView
├─ SettingsTabs.vue  (Core | DNS | Appearance | Proxies | Connections | Logs | Advanced)
├─ CoreConfigPanel.vue
│  ├─ PortsPanel.vue            (5 number inputs, validated 0–65535, PATCH on blur)
│  ├─ ModeLogPanel.vue          (mode select, log-level select → restart log stream)
│  ├─ TogglesPanel.vue          (allow-lan, ipv6, sniffing, tcp-concurrent, unified-delay)
│  ├─ TunPanel.vue              (switch + stack segmented + device + auto-route + mtu + …)
│  ├─ ControllerPanel.vue       (address, secret, CORS; copy buttons)
│  └─ ActionsPanel.vue          (reload, restart, upgrade, flush DNS/FakeIP, update geo)
├─ DnsSettingsPanel.vue         (disabled + explained when no agent — see §7.1)
├─ AppearancePanel.vue          (theme, day/night, custom colours, font, background, custom CSS)
├─ ProxiesSettingsPanel.vue     (display mode, card size, ordering, preview, latency URL/thresholds)
├─ ConnectionsSettingsPanel.vue (columns + order, table size, display mode, GeoIP, reverse DNS)
├─ LogsSettingsPanel.vue        (table size, level, max rows)
├─ AdvancedPanel.vue            (export/import/reset settings, endpoint switch, data usage, retention)
└─ EndpointManagerPanel.vue     (list + add + test endpoints)
```

**Shared primitives** (build these first — they are the design system's seam):

```
components/base/
  BaseButton.vue        (primary | ghost | icon; press/hover motion; loading state)
  BaseSwitch.vue        (wraps the UI lib switch; single accessible name convention)
  BaseSelect.vue
  BaseNumberField.vue   (with min/max/step + blur commit)
  BaseTextField.vue
  BaseChipList.vue      (CIDR / domain lists — used by DNS, CORS, TUN, LAN)
  BaseModal.vue         (focus trap, Esc, backdrop click, portal)
  BaseDrawer.vue        (mobile equivalent)
  BaseDataTable.vue     (header, sticky, column resize/reorder, virtual body slot)
  BaseEmptyState.vue
  BaseErrorState.vue    (message + retry + suggested next action)
  BaseSkeleton.vue
  BaseTooltip.vue
  LatencyPill.vue
  StatCard.vue
```

### 9.6 State and data-flow rules

1. **Sockets write to stores; stores never fetch.** `useWebSocket` owns the four sockets and pushes
   into `global` / `connections` / `logs`. Everything else calls `useApi`.
2. **Never poll what a socket already gives you.** Traffic, memory, connections and logs are pushed.
   Proxies, rules and configs are pulled, on mount and on explicit user action (yacd's 30-second
   focus-refresh is a reasonable extra).
3. **`shallowRef` for large replaced-wholesale arrays**; `markRaw` for chart history buffers.
4. **Diff for speed.** mihomo sends cumulative per-connection bytes, never a rate.
5. **One owner per socket.** Never let two components open `/traffic`.
6. **Persist UI preferences in localStorage under stable keys** (the §7.2 Group G names are a
   reasonable, already-proven set) and version them: metacubexd needed a one-time migration from a
   retired `useMobileConnectionsTable` boolean and a repair for retired display modes. Plan for it.

### 9.7 Accessibility and correctness checklist

- `tabular-nums` on every live-updating figure.
- Latency/health/success never signalled by hue alone — pair colour with a shape, icon or number
  (`DESIGN.md` calls green-vs-red "not an accessible status system").
- Every icon-only button gets an `aria-label`; `LatencyPill` carries
  `"<Test latency>, 88 ms"` and only enters the tab order when `interactive`.
- Visible focus rings (`2px` primary at `2px` offset) on every control, including custom ones.
- `prefers-reduced-motion` disables the fade-slide-in, latency-flip, and press animations globally.
- Modals trap focus and close on Esc; the close button is reachable first.
- Error surfaces name the failed operation, keep the diagnostic detail, and offer a concrete next
  action (`PRODUCT.md`: *"Explain failure"*).
- Support RTL — metacubexd ships a Persian locale, so bidirectional layout is a real requirement, not
  a hypothetical.

### 9.8 Performance guardrails

- Cap the log buffer (200–1000, ring buffer) and virtualise the list.
- Cap closed connections at 200 and the chart window at 30 points.
- Add connections to the table **before** the traffic chart — a 60 fps chart is not worth a 5 fps table.
- Throttle connection-table re-renders to the socket rate, and never re-render a cell whose value did
  not change (stable component identity + `v-memo` on the row keyed by
  `id + download + upload + chains`).
- Do the data-usage diffing in a Web Worker if you implement `/traffic` (Verge's
  `traffic-monitor-worker.ts` is the precedent).
- `markRaw` the chart history; a `ResizeObserver` per chart, disconnected on unmount; destroy the
  chart instance and null the ref so a queued rAF cannot touch it.

### 9.9 UI component library: comparison and recommendation

| | Element Plus | Naive UI | Ant Design Vue | shadcn-vue |
| --- | --- | --- | --- | --- |
| **Nature** | Full component library | Full component library | Full component library | Copy-in components on Reka UI + Tailwind |
| **TS quality** | Good; types generated, occasionally loose | **Best in class — written in TS, fully typed props/slots/emits** | Good | Good (you own the code) |
| **Theming** | SCSS variables + CSS vars; dark theme via a `dark` class | **JS theme objects with deep overrides (`themeOverrides`), plus CSS vars** | ConfigProvider design tokens | Tailwind + CSS vars |
| **Density** | `size="small"`; base components are visually chunky | `size="small"`, and `n-data-table` has explicit density + `flex-height` | `size="small"`; compact algorithm available | Whatever you build |
| **Data table** | `el-table` — featureful, **not virtualised by default** | `n-data-table` — **built-in virtual scroll**, fixed columns, resizable, `render`/`renderSorter` | `a-table` — very complete, virtual scroll available | You assemble TanStack Table + `@tanstack/vue-virtual` |
| **Virtual list** | `el-virtual-list` (Elite) | `n-virtual-list` (built in) | `a-list` virtual (via `vue-virtual-scroller`) | `@tanstack/vue-virtual` |
| **Bundle (tree-shaken)** | ~250–350 KB gz | ~200–300 KB gz | ~350–450 KB gz | ~0 (you add only what you copy, on Reka UI + Tailwind) |
| **Dark/custom "instrument" look** | Fights you; opinionated visual language | Easy — semantic roles + JS overrides | Fights you harder; strong Ant identity | Total freedom |
| **Maintenance / activity** | Very active | Active | Active | Very active |
| **RTL** | Partial | Good | Good | Good (logical properties via Tailwind) |

**Recommendation: Naive UI**, with **shadcn-vue as the alternative** if the team wants to own the
design system outright.

Why Naive UI for *this* app:

1. **It is the only full library whose theming model matches the requirement.** The design brief is a
   dense dark "instrument console" with user-selectable themes and custom colour overrides
   (metacubexd ships 32 themes plus per-token overrides). Naive UI's `themeOverrides` is a typed
   object of exactly those tokens, so a theme switcher becomes "swap one object", not "rewrite SCSS".
2. **It ships the two hard components.** `n-data-table` has built-in virtual scrolling, fixed columns
   and resizable columns — that is the Connections table and the Rules table, the two places where a
   rebuild most often stalls. `n-virtual-list` covers Logs. Element Plus and Ant Design Vue both need
   extra work or a third-party virtualiser for the same result.
3. **Best TypeScript ergonomics**, which matters for a `strict: true` codebase — props, slots and
   emits are all typed, so the compiler catches the mistakes that a hand-rolled `DataTable` would not.
4. **No global CSS reset to fight.** Naive UI is style-injection based, so it composes cleanly with
   Tailwind utilities for the bespoke parts (the latency pill, the proxy card grid, the stat cards) —
   which is exactly the hybrid the reference implementations use (metacubexd: daisyUI + Tailwind
   utilities + scoped CSS; Verge: MUI + a `components/base` wrapper layer).

Why *not* the others:

- **Element Plus** is the safest "nobody gets fired" choice and has the largest ecosystem, but its
  visual language is chunky and its dark theme is a CSS-variable patch rather than a first-class theme
  object. Making it feel like a precision instrument means overriding a lot of it, at which point the
  library's value drops.
- **Ant Design Vue** is the most complete for enterprise forms and its table is excellent, but it
  carries the heaviest bundle and the strongest built-in identity, and it is the hardest of the four to
  bend into a bespoke dark dashboard. Choose it only if the team already standardises on Ant.
- **shadcn-vue** gives the best possible *result* — full control, no bundle tax, Tailwind-native, and
  it is closest in spirit to what metacubexd already does. But it is **not a library**: you own the
  data table, the virtual list, the column manager, the column resizing and the drag-reorder, all of
  which the Connections and Rules pages require. That is real, non-trivial work. Pick it if there is a
  designer-led effort and time to build the table layer; otherwise it is a schedule risk.

**Pragmatic hybrid, and the one I would actually ship:** Naive UI for the *hard* components
(`n-data-table`, `n-virtual-list`, `n-modal`, `n-select`, `n-form`, `n-date-picker`, `n-tree`) and
Tailwind + hand-rolled components for the *bespoke* ones (`LatencyPill`, `ProxyNodeCard`, `StatCard`,
`ProxyPreviewBar`, `GlobalTrafficIndicator`, `NavItem`). Wrap every Naive component used more than
twice in a `components/base/*` component so the library is swappable and the design tokens live in one
place — the wrapper-layer pattern both metacubexd and Verge independently arrived at.

### 9.10 Charting library: comparison and recommendation

| | ECharts 5 (`vue-echarts`) | Chart.js 4 (`vue-chartjs`) | uPlot |
| --- | --- | --- | --- |
| **Bundle (tree-shaken)** | ~150–350 KB gz depending on the modules you register | ~70 KB gz | **~45 KB gz** |
| **Chart types** | line, area, bar, pie, scatter, radar, heatmap, graph/topology, gauge, candlestick, sankey | line, bar, pie, doughnut, radar, scatter, bubble | **line / area / bars only** |
| **Streaming / append** | `appendData` for large data; incremental `setOption` with `notMerge:false` | `chart.update()` — full dataset redraw; `addPoint` for a single point | **Designed for it** — ring buffers, redraws only the shifted region |
| **Max comfortable points** | 10⁵–10⁶ (canvas) | ~10³–10⁴ before it stutters | 10⁶+ at 60 fps |
| **Time axis** | Built in (`type: 'time'`), with `dataZoom`, brush, markLine | Needs `chartjs-adapter-date-fns` + a date lib | Numeric only — you format the axis yourself |
| **Tooltips / legend / zoom** | Richest in class, built in | Built in, simpler | Minimal; you build tooltips |
| **Theming** | Full option tree + registered themes; can be driven from CSS variables | Options object; yacd drives colours from a 4-entry palette table | Options object; very small surface |
| **Reference precedent** | **metacubexd** (Highcharts 13 — same tier) | **yacd** (4.4) | — |
| **Learning curve** | Steep (huge API surface) | Gentle | Gentle but low-level |

**Recommendation: ECharts 5 via `vue-echarts`, with manual module registration.**

Why:

1. **One library covers every chart in the spec.** The Overview page needs two multi-series
   line/area charts, a memory line chart, a connection-count line chart, two pie charts and a bar
   chart; the Traffic page adds a trend chart and rankings. ECharts does all of it. Chart.js covers the
   line/pie/bar set too, but uPlot covers only the line charts and would force a second library for the
   three pies and the bar — which is worse than the 100 KB you saved.
2. **It has the best time-series axes**, which is where Chart.js and uPlot are weakest. yacd's chart
   **hides the x axis entirely** (`x: { display: false }`) — a real usability loss. metacubexd's
   Highcharts chart shows `MM:SS` labels with `tickPixelInterval: 100`. ECharts gives you a proper
   `type: 'time'` axis, formatted ticks, `dataZoom`, and a shared tooltip out of the box.
3. **Its option tree maps cleanly onto a theme object**, so the same mechanism that themes the UI
   (`themeOverrides`) can drive `backgroundColor`, `textStyle.color`, `axisLine.lineStyle.color`,
   `splitLine.lineStyle.color` and the series palette — one source of truth for both.
4. **`appendData` / incremental `setOption` scale past the 30-point window** if the window is ever
   widened, so the choice does not paint us into a corner. Chart.js's `update()` is a full redraw; at
   150 points (yacd's window) that is fine, but it is a ceiling.
5. **Precedent.** metacubexd, the project we are most closely following, chose a comparable
   high-feature library (Highcharts 13). ECharts is the better-licensed, better-tree-shaken equivalent.

Caveats to plan for:

- **Register only the modules you use.** `use([CanvasRenderer, LineChart, BarChart, PieChart,
  GridComponent, TooltipComponent, LegendComponent, TitleComponent, DataZoomComponent,
  DatasetComponent, TransformComponent])`. A naive `import * as echarts` pulls in ~1 MB.
- **Set `animation: false` on the pies and bars.** metacubexd does this explicitly; animated pies
  redrawing every second are a CPU sink.
- **Use the imperative instance API, not a reactive option object.** The reference implementations all
  drive charts imperatively (`chart.series[i].addPoint(...)`, `chart.redraw(...)`) and read a
  `markRaw` snapshot once on mount, precisely because deep-reactively rebuilding an options object
  every second is the expensive path. Expose an imperative `ChartHandle { addPoint, addPoints,
  setSeriesData }` from the chart component, exactly as `RealtimeLineChart.vue` does.
- **Guard against the remount-duplicate-point bug.** Keep the last-appended timestamp and only append
  when it advances.
- **Keep uPlot in your back pocket.** If the traffic chart ever needs to show minutes-to-hours at
  1 Hz (thousands of points) rather than a 30-second window, uPlot is the right tool and can replace
  only the traffic chart without touching the pies.

### 9.11 Build order

1. **Shell + endpoint.** `AppShell`, `AppSidebar`/`AppBottomNav`, router with the auth guard,
   `useEndpoint`, `SetupView`, `ConnectionErrorBanner`. Without a working endpoint nothing else is
   testable.
2. **`useWebSocket` + `useGlobalStore` + Overview.** Four sockets, reconnect, and the six stat tiles.
   This proves the live-data path end to end.
3. **`components/base/*`.** Button, Switch, Select, NumberField, TextField, ChipList, Modal, Drawer,
   DataTable, EmptyState, ErrorState, Skeleton, Tooltip, LatencyPill, StatCard. Everything else
   depends on these.
4. **Proxies.** `useProxiesStore`, `useLatencyTest`, `useBatchLatencyTest`, the card grid, the latency
   pill, group collapse, providers. This is the page users live in.
5. **Connections.** `useConnectionsStore`, the virtualised table, the column manager, the detail modal,
   close/close-all, grouping.
6. **Logs.** `useLogsStore` with the ring buffer, `useLogsStream` with level-aware reconnect, the
   virtualised list, `extractType`.
7. **Rules.** Store, filters, sort, per-rule disable, provider actions.
8. **Settings.** Core panel first (ports, mode, log-level, toggles, TUN), then the action panel, then
   Appearance, then the per-page preference panels, then DNS (gated on an agent).
9. **Polish.** Keyboard shortcuts, `prefers-reduced-motion`, RTL pass, the `defaultPage` redirect,
   settings export/import, and the capability-gated `/profiles` + `/control` views.

---

## Appendix A — Complete mihomo REST surface (from `Alpha`)

Route tree, from `hub/route/server.go` `router()`:

```
/                          GET    hello
/logs                      GET    WebSocket or chunked stream
/traffic                   GET    WebSocket, 1 Hz
/memory                    GET    WebSocket, 1 Hz
/version                   GET
/configs                   GET    getConfigs
                           PATCH  patchConfigs        (204 No Content)
                           PUT    updateConfigs       {path, payload}
                           POST   /geo   updateGeoDatabases
/proxies                   GET    /            getProxies
                           GET    /{name}      getProxy
                           PUT    /{name}      updateProxy       {name}
                           DELETE /{name}      unfixedProxy
                           GET    /{name}/delay?url=&timeout=     {delay}
/group                     GET    /{name}/delay?url=&timeout=     map[name]delay
/rules                     GET    /
                           PATCH  /disable    {index: bool}
/connections               GET    /            {downloadTotal, uploadTotal, memory, connections[]}
                           DELETE /            closeAllConnections
                           DELETE /{id}        closeConnection
/providers/proxies         GET    /            {providers}
                           PUT    /{name}      update
                           GET    /{name}/healthcheck   (204)
                           GET    /{name}/{node}/healthcheck  {delay}
/providers/rules           GET    /            {providers}
                           PUT    /{name}      update
/cache                     POST   /dns/flush
                           POST   /fakeip/flush
/dns                       GET    /query?name=&type=
/storage                   GET    /            (agent/profile storage)
/restart                   POST   /            (not mounted in embed mode)
/upgrade                   POST   /            upgradeCore
                           POST   /geo         updateGeoDatabases
                           POST   /ui          updateUI
/ui                        GET    /            static dashboard assets
/debug                     PUT    /gc          (only when isDebug)
/debug                     *      /*           pprof (only when isDebug)
<dohServer>                *      /*           DoH, when external-controller-doh-prefix is set
```

**WebSocket auth:** `if r.Header.Get("Upgrade") == "websocket" && r.URL.Query().Get("token") != ""`
— a WS client may pass the secret as `?token=`, which is how the browser clients do it (a browser
cannot set an `Authorization` header on a `WebSocket`). REST uses
`Authorization: Bearer <secret>` via the `authentication(secret)` middleware, which uses a
constant-time comparison.

**Emit interval:** both `traffic` and `memory` use `time.NewTicker(time.Second)` — **1 Hz**.

**`/connections` message shape** (`connections.go` + the clients' types):

```jsonc
{
  "downloadTotal": 0,
  "uploadTotal": 0,
  "memory": 0,
  "connections": [{
    "id": "uuid",
    "metadata": {
      "network": "tcp" | "udp",
      "type": "HTTP" | "HTTP Connect" | "Socks5" | "Redir" | "TUN" | "Unknown",
      "sourceIP": "", "destinationIP": "", "sourcePort": "", "destinationPort": "",
      "host": "", "dnsMode": "", "processPath": "", "process": "",
      "specialProxy": "", "specialRules": "", "remoteDestination": "",
      "dscp": 0, "sniffHost": "", "inboundName": "", "inboundUser": "",
      "inboundIP": "", "inboundPort": "", "uid": 0
    },
    "upload": 0, "download": 0,
    "start": "2019-11-30T22:48:13.416668+08:00",
    "chains": ["..."],
    "rule": "Match", "rulePayload": ""
  }]
}
```

Field availability is core-version dependent — yacd probes for `processPath` and hides the Process
column when it never appears; metacubexd and Verge show `-` for missing fields. A rebuild should do the
former (probe, then hide) rather than the latter.

---

## Appendix B — Cross-project feature matrix

| Capability | yacd | metacubexd | clash-dashboard | Verge |
| --- | --- | --- | --- | --- |
| Overview / traffic chart | ✅ Chart.js, 150 pts, hidden x axis | ✅ Highcharts areaspline, 30 pts, datetime axis | ❌ "Coming Soon" | ✅ custom canvas + Web Worker |
| Memory chart | ❌ | ✅ | ❌ | ✅ |
| Connection-count chart | ❌ | ✅ | ❌ | ✅ |
| Flow / network-type pies | ❌ | ✅ | ❌ | ❌ |
| Proxies card grid | ✅ | ✅ (4 display modes) | chip list | list |
| Whole-group delay test | ❌ (client fan-out) | ✅ `GET /group/{n}/delay` | ❌ | ✅ client fan-out, 10-way |
| Provider health check | ✅ | ✅ | ✅ | ✅ |
| Provider subscription usage | ❌ | ✅ | ❌ | ✅ |
| Unfix an automatic group | ❌ | ✅ `DELETE /proxies/{g}` | ❌ | ❌ |
| Node `icon` field | ❌ | ❌ (flag emoji only) | ❌ | ✅ (http/data/svg + cache) |
| Connection detail panel | ❌ (columns only) | ✅ modal, 6 sections | ✅ `Info/` view | ✅ inline |
| Per-rule enable/disable | ❌ | ✅ `PATCH /rules/disable` | ❌ | ❌ |
| Rule hit counts | ❌ | ✅ | ❌ | ❌ |
| Log subsystem `[type]` column | ❌ | ✅ | ❌ | partial |
| Log grouping | ❌ | ✅ | ❌ | ❌ |
| Log export (copy/download) | ❌ | ✅ | ❌ | ❌ |
| Historical data usage | ❌ | ✅ (IndexedDB) | ❌ | ✅ (worker) |
| Profile management | ❌ | agent only | ❌ | ✅ (the core feature) |
| Subscription import | ❌ | ✅ (agent) / `PUT /configs` (remote) | ❌ | ✅ |
| Config file editing | ❌ (`TODO support PUT /configs`) | ✅ Monaco (agent) | ❌ | ✅ Monaco + JSON schema |
| DNS settings panel | ❌ | ✅ (agent) | ❌ | ✅ |
| TUN / system proxy control | ❌ | agent only | ✅ (ClashX bridge) | ✅ |
| WebDAV backup | ❌ | ❌ | ❌ | ✅ |
| Unlock / connectivity tests | ❌ | ✅ `ConnectivityBoard` | ❌ | ✅ `/unlock` |
| Theme count | 3 (auto/dark/light) | **32** + overrides | 2 + SCSS vars | light/dark/system + custom |
| i18n locales | 2 | 7 | 2 | **17** |
| PWA | ✅ workbox | ✅ `@vite-pwa/nuxt` | ✅ `vite-plugin-pwa` | n/a (desktop) |
| Mobile support | responsive | **first-class bottom nav** | Rules/Connections hidden | desktop only |

---

## Appendix C — Reproducing this research

The repositories were cloned to a temporary directory and read directly. Nothing in this document
depends on network access at build time.

```
%TEMP%\clash-ux-research\
  yacd\              # github.com/haishanh/yacd
  metacubexd\        # github.com/MetaCubeX/metacubexd  (packages/ui is the app)
  clash-dashboard\   # github.com/chmod777john/clash-dashboard  (backup of the deleted original)
  clash-verge-rev\   # github.com/clash-verge-rev/clash-verge-rev
  mihomo-core\       # hub/route/*.go from MetaCubeX/mihomo @ Alpha
```

Key files, for anyone verifying a claim:

| Claim | File |
| --- | --- |
| yacd routes, lazy loading, error boundary | `yacd/src/components/Root.tsx` |
| yacd API endpoints | `yacd/src/api/*.ts` |
| yacd latency thresholds and colours | `yacd/src/components/proxies/Proxy.tsx` |
| yacd traffic ring buffer (150) | `yacd/src/api/traffic.ts` |
| yacd chart options (hidden x axis) | `yacd/src/misc/chart.ts` |
| yacd log ring buffer (300) and level colours | `yacd/src/store/logs.ts`, `yacd/src/components/Logs.tsx` |
| yacd connection columns | `yacd/src/components/ConnectionTable.tsx` |
| yacd theme variables | `yacd/src/components/Root.scss` |
| metacubexd design system and palette | `metacubexd/packages/ui/DESIGN.md` |
| metacubexd product principles | `metacubexd/packages/ui/PRODUCT.md` |
| metacubexd latency thresholds | `metacubexd/packages/ui/constants/index.ts` |
| metacubexd latency band classes | `metacubexd/packages/ui/utils/index.ts` |
| metacubexd WS architecture and reconnect | `metacubexd/packages/ui/composables/useWebSocket.ts` |
| metacubexd endpoints and timeouts | `metacubexd/packages/ui/composables/useApi.ts` |
| metacubexd preferences (the Group G table) | `metacubexd/packages/ui/stores/config.ts` |
| metacubexd connection columns | `metacubexd/packages/ui/constants/index.ts`, `pages/connections.vue` |
| metacubexd chart implementation | `metacubexd/packages/ui/components/RealtimeLineChart.vue` |
| metacubexd store reactivity notes | `metacubexd/packages/ui/stores/connections.ts`, `stores/global.ts` |
| Verge delay state machine | `clash-verge-rev/src/utils/delay.ts`, `src/services/delay.ts` |
| Verge palette | `clash-verge-rev/src/pages/_theme.tsx` |
| Verge routes and nav | `clash-verge-rev/src/pages/_navigation-meta.ts`, `_navigation.tsx` |
| Verge connection columns and widths | `clash-verge-rev/src/components/connection/connection-table.tsx` |
| Verge log level colours | `clash-verge-rev/src/components/log/log-item.tsx` |
| Verge settings field inventory | `clash-verge-rev/src/locales/en/settings.json`, `src/components/setting/**` |
| mihomo route tree | `mihomo/hub/route/server.go` @ `Alpha` |
| mihomo PATCH-able config fields | `mihomo/hub/route/configs.go` @ `Alpha` |
| mihomo WS tick interval | `mihomo/hub/route/server.go` @ `Alpha` (`time.NewTicker(time.Second)`) |
| clash-dashboard endpoints | `clash-dashboard/src/lib/request.ts` |
| clash-dashboard stream reader | `clash-dashboard/src/lib/streamer.ts` |

---

## Appendix D — Reconciling this plan with the existing `web/` scaffold

Sections 9.1–9.10 were written as a greenfield recommendation. **A scaffold already exists at
`C:\Work\Clash\web`**, and it has already made several of the decisions above. This appendix records
the deltas so the plan can be applied to the code that is actually there rather than to a blank slate.

### D.1 What the scaffold already gets right — do not re-litigate these

| Existing | Verdict against this research |
| --- | --- |
| `element-plus` 2.11 + `@element-plus/icons-vue` | Element Plus was the *third* of four picks in §9.9 (behind Naive UI and shadcn-vue), but it is a defensible choice and it is already installed. **Keep it.** See D.3 for the one gap it creates. |
| `echarts` 6 + `vue-echarts` 8 | **Exactly the §9.10 recommendation.** No change. |
| `pinia` 3 + `vue-router` 4 + `vue` 3.5 + `@vueuse/core` | Matches §9.1. |
| `axios` 1.13 rather than ky | Equivalent for this purpose. Keep it. |
| `src/utils/ws.ts` — `ReconnectingStream` | **Better than the metacubexd baseline in one respect:** exponential backoff with jitter (`min 500 ms`, `max 15 s`, `min(minDelay, 500)` jitter) instead of a flat 3 s retry. Keep it. |
| `buildWebSocketUrl` passes the secret as `?token=` | Correct — matches mihomo's WS auth branch and §9.4. The comment in the file already explains why (browsers cannot set `Authorization` on a WebSocket handshake). |
| `src/api/client.ts` — `ApiResult<T>` union + typed `ApiError.kind` | Better than any of the four reference dashboards: `'network' \| 'timeout' \| 'unauthorized' \| 'not-found' \| 'bad-request' \| 'server' \| 'unknown'`, with `needsSecret` and `isMissing` getters. This directly satisfies `PRODUCT.md`'s "Explain failure" principle. Keep it and make every store action funnel through it. |
| `Authorization: Bearer <secret>` on REST, `?token=` on WS | Correct split — §9.4, item 1. |
| Stores: `config`, `connections`, `logs`, `profiles`, `proxies`, `rules`, `settings`, `traffic` | Close to the §9.3 nine-store breakdown. `traffic` maps to `global`; `settings` holds the endpoint + preferences. See D.2. |

### D.2 Store-mapping deltas

| §9.3 store | Existing file | Action |
| --- | --- | --- |
| `useEndpointStore` | `src/stores/settings.ts` | Merged with preferences. Fine — but ensure `currentEndpoint` / `wsEndpointURL` are derived, and that the WS layer watches the endpoint so a switch tears down and reopens the sockets. |
| `useGlobalStore` | `src/stores/traffic.ts` | **Must also hold the memory series and the connection-count series**, not just traffic — the Overview page needs all three, and the connection-count series is written by the *connections* socket, not the traffic socket. |
| `useConnectionsStore` | `src/stores/connections.ts` | Needs: `shallowRef` for the three arrays, client-side speed diffing, kernel-restart detection (`uploadTotal`/`downloadTotal` decreased), the 200-row closed trim, and a `watch` on the endpoint that resets only the restart baselines. |
| `useLogsStore` | `src/stores/logs.ts` | Needs a **fixed-capacity ring buffer** (§6.5) rather than an append+slice. |
| `useProxiesStore` | `src/stores/proxies.ts` | Needs the latency cache keyed `` `${group}\0${name}` `` with a 30-minute TTL, a `testing: Set<string>`, and per-node latency history. |
| `useConfigStore` | `src/stores/config.ts` | Split conceptually: core config (from `GET /configs`) vs dashboard preferences (localStorage). §7.2 Group A–F vs Group G. |
| `useKernelStore` | **missing** | Add it: `GET /version` → `{version, meta, premium}`, uptime, and the `hasFeature()` capability set that gates `/profiles` and `/control`. |
| `useRulesStore` | `src/stores/rules.ts` | Add per-rule disable (`PATCH /rules/disable`) and rule-provider update. |

### D.3 The one real gap: virtualised, resizable data tables

Element Plus's `el-table` is **not virtualised by default**. The Connections page (hundreds to
thousands of rows, re-rendered roughly once per second) and the Rules page (thousands of rules) are
exactly where this bites. Options, in order of preference:

1. **`el-table-v2`** — Element Plus ships a virtualised table (`ElTableV2`). Use it for Connections
   and Rules. Caveat: its API differs from `el-table` (you supply `columns` and `data` as props, and
   cells via `cellRenderer`), and it is less well documented. It supports fixed columns, column
   widths and row height, which is what §5.1 and §2.17 require.
2. **TanStack Table + `@tanstack/vue-virtual`** for Connections only, keeping `el-table` elsewhere.
   This is the shadcn-vue path from §9.9 and gives full control over column resize/reorder (Verge's
   `connection-column-manager` is the model), at the cost of hand-building the header.
3. **`el-table` with a hard cap.** Acceptable only if closed connections are capped low (metacubexd
   uses 200) *and* the active list is expected to stay in the low hundreds. Do not ship this without
   measuring.

Whichever is chosen, apply the §9.5 rule that is not optional: **wrap the cell renderer in a
component with a constant identity** (`ConnectionCell.vue` taking a `render` function prop).
`<component :is="() => render(row)" />` creates a new component type per render, so Vue unmounts and
remounts every cell on every WebSocket tick.

### D.4 Missing pieces to add, in build order

1. **Router + shell.** `src/main.ts` currently mounts `App.vue` with no router and no Pinia
   registration. Add `createPinia()`, the §9.2 route table, and the app shell
   (sidebar / bottom-nav / `GlobalTrafficIndicator` / `ConnectionErrorBanner`).
2. **`composables/`** — the scaffold has none. Add at minimum `useWebSocket` (owning all four
   `ReconnectingStream` instances), `useLatencyTest`, `useBatchLatencyTest`, `useControlInfo`.
3. **`components/base/`** — the §9.5 shared primitives. Element Plus supplies Switch/Select/Input/
   Modal/Dialog; the bespoke ones (`LatencyPill`, `StatCard`, `ProxyNodeCard`, `ProxyPreviewBar`,
   `EmptyState`, `ErrorState`) still need building, and wrapping the Element Plus components used
   more than twice keeps the library swappable.
4. **`GET /version` capability probe** and the `hasFeature()` gate — without it, `/profiles` and
   `/control` will render broken against a plain remote core.
5. **The 30-point chart window + imperative chart handles.** Do not drive ECharts from a reactive
   options object that is rebuilt every second; expose
   `ChartHandle { addPoint, addPoints, setSeriesData }` and read a `markRaw` snapshot on mount
   (§9.10, caveat 3).
6. **`markRaw` the chart history buffers** in `stores/traffic.ts` and keep the
   last-appended-timestamp guard so a remount cannot duplicate a point.

### D.5 Two correctness traps specific to the scaffold

- **`buildWebSocketUrl` falls back to `window.location.origin` when `apiBase` is empty.** That is the
  right default for a same-origin deployment (the core serving the UI), but it means a user who has
  not configured an endpoint will silently open sockets against the static host and get 404s rather
  than a clear "not configured" state. Add an explicit "no endpoint configured" gate in
  `useWebSocket` and route to the setup view, mirroring metacubexd's auth middleware.
- **`ReconnectingStream.stop()` is a hard stop, and `start()` resets `attempt` to 0.** That is correct
  for an intentional teardown, but the **log stream is level-scoped** (§6.1): changing `log-level`
  must `stop()` and `start()` the logs stream so the new `?level=` takes effect. Wire that into the
  settings action, or the user will change the level and see nothing happen.

