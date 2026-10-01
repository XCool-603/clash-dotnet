import { ref, watch } from 'vue'
import type { Ref } from 'vue'
import { tryOnMounted, tryOnScopeDispose } from '@vueuse/core'

import { useSettingsStore } from '@/stores/settings'
import { buildWebSocketUrl, ReconnectingStream } from '@/utils/ws'
import type { StreamStatus } from '@/utils/ws'

export interface StreamHandle {
  /** Live socket status — drives the "connected" indicators. */
  status: Ref<StreamStatus>
  start: () => void
  stop: () => void
  restart: () => void
}

export interface StreamOptions {
  /** Resolved on every connect attempt, e.g. `() => '/logs?level=info'`. */
  path: () => string
  onMessage: (raw: string) => void
  onStatus?: (status: StreamStatus) => void
  /** Delay before the first retry. Defaults to 500ms. */
  minDelayMs?: number
  /** Retry ceiling. Defaults to 15s. */
  maxDelayMs?: number
}

/**
 * Shared plumbing for the Clash WebSocket streams.
 *
 * - connects on mount, disconnects on scope dispose
 * - reconnects with exponential backoff + jitter
 * - reconnects immediately when the API base URL or secret changes
 */
export function useStream(options: StreamOptions): StreamHandle {
  const settings = useSettingsStore()
  const status = ref<StreamStatus>('idle')

  const stream = new ReconnectingStream({
    url: () => buildWebSocketUrl(options.path()),
    onMessage: options.onMessage,
    onStatus: (next) => {
      status.value = next
      options.onStatus?.(next)
    },
    minDelayMs: options.minDelayMs ?? 500,
    maxDelayMs: options.maxDelayMs ?? 15_000,
  })

  function start(): void {
    stream.start()
  }

  function stop(): void {
    stream.stop()
  }

  function restart(): void {
    const wasRunning = stream.isRunning
    stream.stop()
    if (wasRunning) stream.start()
  }

  watch(
    () => [settings.apiBase, settings.secret] as const,
    () => restart(),
  )

  tryOnMounted(start)
  tryOnScopeDispose(stop)

  return { status, start, stop, restart }
}
