/**
 * Latency is modelled as a **state first and a number second**.
 *
 * Clash reports `0` for a probe that failed, which — if treated as a plain
 * number — sorts as "the fastest node in the list". Modelling the outcome as
 * `testing | untested | timeout | error | measured` and sorting by state rank
 * before value is what keeps a dead node out of the green band.
 */

export type DelayState = 'testing' | 'untested' | 'timeout' | 'error' | 'measured'

/**
 * State-first sort rank. Lower sorts first:
 * nodes being tested float to the top (the user just asked for them),
 * measured nodes follow fastest-first, then unknowns, then failures.
 */
export const DELAY_STATE_RANK: Record<DelayState, number> = {
  testing: 0,
  measured: 1,
  untested: 2,
  timeout: 3,
  error: 4,
}

/** Clash's own "the probe failed" sentinel. */
export const FAILED_DELAY = 0

/** Anything at or above this is not a plausible round-trip time. */
export const IMPLAUSIBLE_DELAY = 100_000

/** The core's default health-check budget, in milliseconds. */
export const DEFAULT_DELAY_TIMEOUT = 5000

export interface DelayInfo {
  state: DelayState
  /** Rounded milliseconds — only present when `state === 'measured'`. */
  value: number | null
  /** The raw value the core reported (0 = the probe failed). */
  raw: number | null
}

export interface DelayStateOptions {
  /** A health check for this node is in flight. */
  testing?: boolean
  /** The core explicitly marked the node as down. */
  alive?: boolean
  /** Probe budget; a measurement at or above it is a timeout. */
  timeoutMs?: number
}

/**
 * Classify a raw delay value into a state. The order of the checks matters:
 * "currently testing" wins over everything, and a stale number never
 * outranks a known failure.
 */
export function delayStateOf(
  delay: number | null | undefined,
  options: DelayStateOptions = {},
): DelayInfo {
  if (options.testing === true) {
    return { state: 'testing', value: null, raw: null }
  }

  if (delay === null || delay === undefined || !Number.isFinite(delay)) {
    return { state: options.alive === false ? 'error' : 'untested', value: null, raw: null }
  }

  const timeoutMs = options.timeoutMs ?? DEFAULT_DELAY_TIMEOUT
  if (delay <= FAILED_DELAY || delay >= IMPLAUSIBLE_DELAY || delay >= timeoutMs) {
    return { state: 'timeout', value: null, raw: delay }
  }

  return { state: 'measured', value: Math.round(delay), raw: delay }
}

/** A single comparable number: state rank dominates, the value breaks ties. */
export function delaySortRank(info: DelayInfo): number {
  return DELAY_STATE_RANK[info.state] * 1_000_000 + (info.value ?? 0)
}

export function compareDelay(a: DelayInfo, b: DelayInfo): number {
  return delaySortRank(a) - delaySortRank(b)
}

/** Short human label for a state — never rely on colour alone. */
export const DELAY_STATE_LABEL: Record<DelayState, string> = {
  testing: 'testing',
  untested: 'untested',
  timeout: 'timed out',
  error: 'unavailable',
  measured: 'measured',
}

/* ------------------------------------------------------------------ */
/* Protocol-aware thresholds                                           */
/* ------------------------------------------------------------------ */

export interface LatencyThresholds {
  /** Green ceiling, inclusive. */
  good: number
  /** Yellow ceiling, inclusive — anything above is red. */
  fair: number
}

/** Plain-HTTP probes: green ≤ 200 ms, yellow ≤ 500 ms, red above. */
export const HTTP_LATENCY_THRESHOLDS: LatencyThresholds = { good: 200, fair: 500 }

/** TLS probes pay a handshake, so they get a wider budget. */
export const HTTPS_LATENCY_THRESHOLDS: LatencyThresholds = { good: 800, fair: 1500 }

export function isHttpsProbe(url: string | null | undefined): boolean {
  return typeof url === 'string' && /^https:/i.test(url.trim())
}

/** Pick the threshold pair that matches the probe URL's protocol. */
export function latencyThresholds(url: string | null | undefined): LatencyThresholds {
  return isHttpsProbe(url) ? HTTPS_LATENCY_THRESHOLDS : HTTP_LATENCY_THRESHOLDS
}

export type LatencyBand = 'good' | 'fair' | 'bad' | 'failed' | 'unknown'

/**
 * Bucket a delay using the thresholds for `probeUrl`'s protocol.
 * `null`/`undefined` is `unknown`; `0` (or less) is `failed`.
 */
export function latencyBand(delay: number | null | undefined, probeUrl?: string | null): LatencyBand {
  if (delay === null || delay === undefined || !Number.isFinite(delay)) return 'unknown'
  if (delay <= FAILED_DELAY) return 'failed'
  const thresholds = latencyThresholds(probeUrl)
  if (delay <= thresholds.good) return 'good'
  if (delay <= thresholds.fair) return 'fair'
  return 'bad'
}

export const LATENCY_BAND_COLORS: Record<LatencyBand, string> = {
  good: '#22c55e',
  fair: '#eab308',
  bad: '#ef4444',
  failed: '#ef4444',
  unknown: '#94a3b8',
}

/** Human-readable band name, for `title`/`aria-label` text. */
export const LATENCY_BAND_LABELS: Record<LatencyBand, string> = {
  good: 'fast',
  fair: 'acceptable',
  bad: 'slow',
  failed: 'failed',
  unknown: 'not measured',
}

export function latencyBandColor(band: LatencyBand): string {
  return LATENCY_BAND_COLORS[band]
}

export function latencyBandLabel(band: LatencyBand): string {
  return LATENCY_BAND_LABELS[band]
}
