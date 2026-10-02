/**
 * Shared domain types for the Clash RESTful API and the app-level
 * profile/subscription endpoints exposed by the .NET backend.
 *
 * These mirror the wire format exactly (kebab-case keys included) so the
 * API layer stays a thin, honest mapping over the backend.
 */

/* ------------------------------------------------------------------ */
/* Core enums (as string unions — `erasableSyntaxOnly` forbids enums)  */
/* ------------------------------------------------------------------ */

export type ClashMode = 'rule' | 'global' | 'direct'

export type LogLevel = 'debug' | 'info' | 'warning' | 'error'

export type ProxyGroupType = 'Selector' | 'URLTest' | 'Fallback' | 'LoadBalance' | 'Relay'

export type ThemeMode = 'dark' | 'light'

export const CLASH_MODES: readonly ClashMode[] = ['rule', 'global', 'direct']

export const LOG_LEVELS: readonly LogLevel[] = ['debug', 'info', 'warning', 'error']

export const PROXY_GROUP_TYPES: readonly ProxyGroupType[] = [
  'Selector',
  'URLTest',
  'Fallback',
  'LoadBalance',
  'Relay',
]

export const FIND_PROCESS_MODES = ['always', 'strict', 'off'] as const
export type FindProcessMode = (typeof FIND_PROCESS_MODES)[number]

export const DNS_ENHANCED_MODES = ['fake-ip', 'redir-host', 'normal'] as const
export type DnsEnhancedMode = (typeof DNS_ENHANCED_MODES)[number]

export const TUN_STACKS = ['system', 'gvisor', 'mixed'] as const
export type TunStack = (typeof TUN_STACKS)[number]

export function isProxyGroupType(value: string): value is ProxyGroupType {
  return (PROXY_GROUP_TYPES as readonly string[]).includes(value)
}

/* ------------------------------------------------------------------ */
/* Version                                                             */
/* ------------------------------------------------------------------ */

export interface VersionInfo {
  version: string
  meta?: boolean
}

/* ------------------------------------------------------------------ */
/* Config                                                              */
/* ------------------------------------------------------------------ */

export interface TunConfig {
  enable?: boolean
  stack?: TunStack | string
  device?: string
  'auto-route'?: boolean
  'auto-detect-interface'?: boolean
  'auto-redirect'?: boolean
  'strict-route'?: boolean
  mtu?: number
  'dns-hijack'?: string[]
  'endpoint-independent-nat'?: boolean
  [key: string]: unknown
}

export interface DnsConfig {
  enable?: boolean
  listen?: string
  ipv6?: boolean
  'enhanced-mode'?: DnsEnhancedMode | string
  'fake-ip-range'?: string
  'fake-ip-filter'?: string[]
  nameserver?: string[]
  fallback?: string[]
  'default-nameserver'?: string[]
  'use-hosts'?: boolean
  'use-system-hosts'?: boolean
  'respect-rules'?: boolean
  [key: string]: unknown
}

export interface ProfileConfig {
  'store-selected'?: boolean
  'store-fake-ip'?: boolean
  [key: string]: unknown
}

export interface ClashConfig {
  port?: number
  'socks-port'?: number
  'redir-port'?: number
  'tproxy-port'?: number
  'mixed-port'?: number
  'allow-lan'?: boolean
  'bind-address'?: string
  mode?: ClashMode | string
  'log-level'?: LogLevel | string
  ipv6?: boolean
  'external-controller'?: string
  'external-ui'?: string
  'external-ui-name'?: string
  'external-ui-url'?: string
  secret?: string
  'interface-name'?: string
  'routing-mark'?: number
  'unified-delay'?: boolean
  'tcp-concurrent'?: boolean
  'find-process-mode'?: FindProcessMode | string
  'global-client-fingerprint'?: string
  'keep-alive-interval'?: number
  'geodata-mode'?: boolean
  'geodata-loader'?: string
  tun?: TunConfig
  dns?: DnsConfig
  profile?: ProfileConfig
  [key: string]: unknown
}

/* ------------------------------------------------------------------ */
/* Proxies                                                             */
/* ------------------------------------------------------------------ */

export interface ProxyHistory {
  time: string
  delay: number
}

export interface ProxyObject {
  type: string
  name: string
  /** Currently selected member — only present on group types. */
  now?: string
  /** Group members — only present on group types. */
  all?: string[]
  history: ProxyHistory[]
  udp?: boolean
  testUrl?: string
  expectedStatus?: string
  hidden?: boolean
  icon?: string
  alive?: boolean
  /** Provider-supplied decoration (node id, fingerprint, …). */
  extra?: Record<string, unknown>
  xudp?: boolean
  tfo?: boolean
  id?: string
  [key: string]: unknown
}

export interface ProxiesResponse {
  proxies: Record<string, ProxyObject>
}

export interface DelayResponse {
  delay: number
  meanDelay?: number
}

export interface GroupDelayResponse {
  [proxyName: string]: number
}

export interface SubscriptionInfo {
  Upload?: number
  Download?: number
  Total?: number
  Expire?: number
  [key: string]: unknown
}

export interface ProxyProvider {
  name: string
  type: string
  vehicleType: string
  proxies: ProxyObject[]
  updatedAt?: string
  subscriptionInfo?: SubscriptionInfo
}

export interface ProxyProvidersResponse {
  providers: Record<string, ProxyProvider>
}

/* ------------------------------------------------------------------ */
/* Rules                                                               */
/* ------------------------------------------------------------------ */

export interface Rule {
  type: string
  payload: string
  proxy: string
  size?: number
  disabled?: boolean
}

export interface RulesResponse {
  rules: Rule[]
}

export interface RuleProvider {
  name: string
  type: string
  vehicleType: string
  behavior: string
  ruleCount: number
  format?: string
  updatedAt?: string
}

export interface RuleProvidersResponse {
  providers: Record<string, RuleProvider>
}

/* ------------------------------------------------------------------ */
/* Connections                                                         */
/* ------------------------------------------------------------------ */

export interface ConnectionMetadata {
  network: string
  type: string
  sourceIP: string
  destinationIP: string
  sourcePort: string
  destinationPort: string
  host: string
  dnsMode: string
  processPath: string
  /** Name of the process that owns the flow, when the core could resolve it. */
  process: string
  /** Inbound listener that accepted the flow: its name, port and authenticated user. */
  inboundName: string
  inboundPort: string
  inboundUser: string
  specialProxy: string
  specialRules: string
  remoteDestination: string
  sniffHost: string
  uid?: number
  [key: string]: unknown
}

export interface Connection {
  id: string
  metadata: ConnectionMetadata
  upload: number
  download: number
  /** ISO-8601 timestamp of when the connection was opened. */
  start: string
  chains: string[]
  rule: string
  rulePayload: string
}

export interface ConnectionsSnapshot {
  downloadTotal: number
  uploadTotal: number
  memory: number
  connections: Connection[] | null
}

/* ------------------------------------------------------------------ */
/* WebSocket streams                                                   */
/* ------------------------------------------------------------------ */

export interface TrafficMessage {
  up: number
  down: number
}

export interface MemoryMessage {
  inuse: number
  oslimit: number
}

export interface LogMessage {
  type: string
  payload: string
}

export interface LogEntry extends LogMessage {
  /** Monotonic client-side id, used as a stable `key`. */
  id: number
  /** Client receive time (epoch ms) — the API does not send one. */
  time: number
}

/* ------------------------------------------------------------------ */
/* Profiles (app-level endpoints)                                      */
/* ------------------------------------------------------------------ */

export type ProfileType = 'local' | 'remote' | 'merge'

export interface ProfileSubscriptionInfo {
  upload?: number
  download?: number
  total?: number
  expire?: number
  [key: string]: unknown
}

export interface Profile {
  id: string
  name: string
  type: ProfileType
  url?: string
  path: string
  updatedAt: string
  selected: boolean
  description?: string
  subscriptionInfo?: ProfileSubscriptionInfo
}

export interface ProfilesResponse {
  profiles: Profile[]
}

export interface CreateProfileInput {
  name: string
  type: ProfileType
  url?: string
  content?: string
}

export interface UpdateProfileInput {
  name?: string
  url?: string
  description?: string
}

export interface ProfilePreview {
  id: string
  name: string
  content: string
}

export interface ParsedSubscriptionNode {
  name: string
  type: string
  server?: string
  port?: number
  [key: string]: unknown
}

export interface ParsedSubscription {
  nodes: ParsedSubscriptionNode[]
  count?: number
  [key: string]: unknown
}

/* ------------------------------------------------------------------ */
/* DNS query                                                           */
/* ------------------------------------------------------------------ */

export interface DnsQueryAnswer {
  [key: string]: unknown
}

/* ------------------------------------------------------------------ */
/* Proxy node classification helpers                                   */
/* ------------------------------------------------------------------ */

const GROUP_TYPE_SET: ReadonlySet<string> = new Set<string>(PROXY_GROUP_TYPES)

export function isGroup(proxy: ProxyObject | undefined | null): boolean {
  if (!proxy) return false
  return GROUP_TYPE_SET.has(proxy.type)
}

export function isSelector(proxy: ProxyObject | undefined | null): boolean {
  return !!proxy && proxy.type === 'Selector'
}
