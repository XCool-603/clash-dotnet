/** Small async/concurrency helpers used by the stores. */

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Run `worker` over `items` with at most `limit` promises in flight.
 * Never rejects: failures are reported through the `onError` callback so a
 * single bad node cannot abort a whole health-check sweep.
 */
export async function mapLimit<T>(
  items: readonly T[],
  limit: number,
  worker: (item: T, index: number) => Promise<void>,
  onError?: (error: unknown, item: T, index: number) => void,
): Promise<void> {
  const queue = items.slice()
  const size = Math.max(1, Math.min(limit, queue.length))
  let cursor = 0

  const runners: Promise<void>[] = []
  for (let i = 0; i < size; i += 1) {
    runners.push(
      (async (): Promise<void> => {
        for (;;) {
          const index = cursor
          cursor += 1
          if (index >= queue.length) return
          const item = queue[index] as T
          try {
            await worker(item, index)
          } catch (error) {
            onError?.(error, item, index)
          }
        }
      })(),
    )
  }
  await Promise.all(runners)
}

/** Best-effort human message from an unknown thrown value. */
export function messageOf(error: unknown): string {
  if (error instanceof Error) return error.message
  if (typeof error === 'string') return error
  if (error && typeof error === 'object' && 'message' in error) {
    const message = (error as { message?: unknown }).message
    if (typeof message === 'string') return message
  }
  return String(error)
}
