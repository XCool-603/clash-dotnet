/** Tolerant JSON parsing for stream payloads — never throws. */
export function safeJson<T>(raw: string): T | null {
  try {
    const parsed: unknown = JSON.parse(raw)
    if (parsed === null || parsed === undefined) return null
    return parsed as T
  } catch {
    return null
  }
}

/** Coerce an unknown JSON value to a finite number (0 when not numeric). */
export function toNumber(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string') {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return 0
}

/** Coerce an unknown JSON value to a string. */
export function toString(value: unknown): string {
  if (typeof value === 'string') return value
  if (value === null || value === undefined) return ''
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return ''
  }
}
