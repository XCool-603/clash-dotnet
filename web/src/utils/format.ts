/** Byte / rate / duration / timestamp formatting helpers. */

const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'] as const

/**
 * Format a byte count with an auto-selected unit.
 * `formatBytes(1536)` → `"1.50 KB"`.
 */
export function formatBytes(bytes: number | null | undefined, decimals = 2): string {
  const value = typeof bytes === 'number' && Number.isFinite(bytes) ? bytes : 0
  if (value <= 0) return '0 B'
  const exponent = Math.min(Math.floor(Math.log(value) / Math.log(1024)), BYTE_UNITS.length - 1)
  const scaled = value / 1024 ** exponent
  const unit = BYTE_UNITS[exponent] ?? 'B'
  const digits = exponent === 0 ? 0 : decimals
  return `${scaled.toFixed(digits)} ${unit}`
}

/** Format a bytes-per-second rate, e.g. `"2.40 MB/s"`. */
export function formatRate(bytesPerSecond: number | null | undefined): string {
  return `${formatBytes(bytesPerSecond, 2)}/s`
}

/** Compact rate for chart axis labels (no space, 1 decimal above KB). */
export function formatRateCompact(bytesPerSecond: number | null | undefined): string {
  const value = typeof bytesPerSecond === 'number' && Number.isFinite(bytesPerSecond) ? bytesPerSecond : 0
  if (value <= 0) return '0'
  const exponent = Math.min(Math.floor(Math.log(value) / Math.log(1024)), BYTE_UNITS.length - 1)
  const scaled = value / 1024 ** exponent
  const unit = BYTE_UNITS[exponent] ?? 'B'
  if (exponent === 0) return `${Math.round(scaled)}${unit}`
  return `${scaled.toFixed(scaled >= 100 ? 0 : 1)}${unit}`
}

/** Format a millisecond duration as `1h 02m 03s`, `12m 05s` or `42s`. */
export function formatDuration(ms: number | null | undefined): string {
  const total = Math.max(0, Math.floor((typeof ms === 'number' && Number.isFinite(ms) ? ms : 0) / 1000))
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  const seconds = total % 60
  const pad = (n: number): string => String(n).padStart(2, '0')
  if (hours > 0) return `${hours}h ${pad(minutes)}m ${pad(seconds)}s`
  if (minutes > 0) return `${minutes}m ${pad(seconds)}s`
  return `${seconds}s`
}

/** Format an ISO timestamp (or epoch ms) as a local `HH:mm:ss` clock time. */
export function formatClock(value: string | number | Date | null | undefined): string {
  const date = toDate(value)
  if (!date) return '—'
  return date.toLocaleTimeString(undefined, { hour12: false })
}

/** Format an ISO timestamp as a local `YYYY-MM-DD HH:mm:ss`. */
export function formatDateTime(value: string | number | Date | null | undefined): string {
  const date = toDate(value)
  if (!date) return '—'
  const y = date.getFullYear()
  const mo = String(date.getMonth() + 1).padStart(2, '0')
  const d = String(date.getDate()).padStart(2, '0')
  const h = String(date.getHours()).padStart(2, '0')
  const mi = String(date.getMinutes()).padStart(2, '0')
  const s = String(date.getSeconds()).padStart(2, '0')
  return `${y}-${mo}-${d} ${h}:${mi}:${s}`
}

/** Human "3 minutes ago" style relative time. */
export function formatRelative(value: string | number | Date | null | undefined): string {
  const date = toDate(value)
  if (!date) return '—'
  const diff = Date.now() - date.getTime()
  if (diff < 0) return 'just now'
  const seconds = Math.floor(diff / 1000)
  if (seconds < 45) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} h ago`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days} d ago`
  return formatDateTime(date)
}

/** Format an epoch-seconds expiry as `YYYY-MM-DD` (or `—`). */
export function formatExpiry(epochSeconds: number | null | undefined): string {
  if (!epochSeconds || !Number.isFinite(epochSeconds) || epochSeconds <= 0) return '—'
  return formatDateTime(new Date(epochSeconds * 1000))
}

function toDate(value: string | number | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null
  const date = value instanceof Date ? value : new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

/* ------------------------------------------------------------------ */
/* Delay helpers                                                       */
/* ------------------------------------------------------------------ */

export type DelayLevel = 'good' | 'fair' | 'poor' | 'bad' | 'failed' | 'unknown'

/**
 * Classify a delay for colour coding:
 * green ≤ 200ms, yellow ≤ 500ms, orange ≤ 1000ms, red above / failed.
 */
export function delayLevel(delay: number | null | undefined): DelayLevel {
  if (delay === null || delay === undefined || !Number.isFinite(delay)) return 'unknown'
  if (delay <= 0) return 'failed'
  if (delay <= 200) return 'good'
  if (delay <= 500) return 'fair'
  if (delay <= 1000) return 'poor'
  return 'bad'
}

const DELAY_COLORS: Record<DelayLevel, string> = {
  good: '#22c55e',
  fair: '#eab308',
  poor: '#f97316',
  bad: '#ef4444',
  failed: '#ef4444',
  unknown: '#94a3b8',
}

export function delayColor(delay: number | null | undefined): string {
  return DELAY_COLORS[delayLevel(delay)]
}

/** Turn `#rrggbb` into `rgba(r, g, b, a)`. */
export function withAlpha(hex: string, alpha: number): string {
  const match = /^#?([0-9a-f]{6})$/i.exec(hex.trim())
  if (!match || !match[1]) return hex
  const value = Number.parseInt(match[1], 16)
  const r = (value >> 16) & 0xff
  const g = (value >> 8) & 0xff
  const b = value & 0xff
  return `rgba(${r}, ${g}, ${b}, ${alpha})`
}

/** Render a delay value as a short human label. */
export function formatDelay(delay: number | null | undefined): string {
  if (delay === null || delay === undefined || !Number.isFinite(delay)) return '—'
  if (delay <= 0) return 'failed'
  return `${Math.round(delay)} ms`
}

/** The most recent delay recorded for a proxy (0 means the last test failed). */
export function latestDelay(history: { delay: number }[] | undefined | null): number | null {
  if (!history || history.length === 0) return null
  const last = history[history.length - 1]
  if (!last) return null
  return typeof last.delay === 'number' ? last.delay : null
}

/* ------------------------------------------------------------------ */
/* Misc                                                                */
/* ------------------------------------------------------------------ */

/** True when an `icon` value should be rendered as an `<img src>`. */
export function isImageIcon(icon: string | undefined | null): boolean {
  if (!icon) return false
  return (
    /^https?:\/\//i.test(icon) ||
    /^data:image\//i.test(icon) ||
    /^\.{0,2}\//.test(icon) ||
    /\.(png|jpe?g|svg|webp|gif|avif)(\?.*)?$/i.test(icon)
  )
}

/** Join host and port for display, collapsing default ports. */
export function formatEndpoint(host: string, port: string | number, ip?: string): string {
  const target = host && host.length > 0 ? host : ip ?? ''
  if (!target) return '—'
  const p = String(port ?? '')
  return p ? `${target}:${p}` : target
}

/** Truncate a long path from the left, keeping the tail readable. */
export function truncateMiddle(value: string, max = 48): string {
  if (value.length <= max) return value
  const half = Math.floor((max - 1) / 2)
  return `${value.slice(0, half)}…${value.slice(value.length - half)}`
}

/** Percentage (0-100) of `used` against `total`, or null when unknown. */
export function percentage(used: number, total: number): number | null {
  if (!Number.isFinite(used) || !Number.isFinite(total) || total <= 0) return null
  return Math.min(100, Math.max(0, (used / total) * 100))
}
