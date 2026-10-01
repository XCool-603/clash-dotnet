/** Plain-object helpers used when merging partial config updates. */

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Recursively merge `patch` into `target`, returning a new object.
 * Arrays and scalars from `patch` replace the target wholesale, which is the
 * behaviour we want for things like `dns.nameserver` and `tun.dns-hijack`.
 */
export function deepMerge<T extends Record<string, unknown>>(
  target: T,
  patch: Record<string, unknown>,
): T {
  const output: Record<string, unknown> = { ...target }
  for (const [key, value] of Object.entries(patch)) {
    const current = output[key]
    if (isPlainObject(value) && isPlainObject(current)) {
      output[key] = deepMerge(current, value)
    } else {
      output[key] = value
    }
  }
  return output as T
}

/** Deep clone that is safe for the plain JSON shapes used by this app. */
export function deepClone<T>(value: T): T {
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map((item) => deepClone(item)) as unknown as T
  const source = value as Record<string, unknown>
  const output: Record<string, unknown> = {}
  for (const [key, item] of Object.entries(source)) {
    output[key] = deepClone(item)
  }
  return output as T
}
