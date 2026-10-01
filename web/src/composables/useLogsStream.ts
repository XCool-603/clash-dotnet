import { watch } from 'vue'

import { useLogsStore } from '@/stores/logs'
import type { LogMessage } from '@/types'
import { safeJson, toString } from '@/utils/json'

import { useStream } from './useStream'
import type { StreamHandle } from './useStream'

/**
 * Subscribes to `/logs?level=…`.
 *
 * The level is part of the request URL, so changing it in the UI restarts the
 * socket (the watcher below) rather than filtering client-side only.
 */
export function useLogsStream(): StreamHandle {
  const logs = useLogsStore()

  const handle = useStream({
    path: () => `/logs?level=${encodeURIComponent(logs.level)}`,
    onMessage: (raw) => {
      const message = safeJson<LogMessage>(raw)
      if (!message) {
        // Some builds emit bare strings; keep them rather than dropping them.
        const text = raw.trim()
        if (text.length > 0) logs.append('info', text)
        return
      }
      logs.append(toString(message.type) || 'info', toString(message.payload))
    },
    onStatus: (status) => logs.setStatus(status),
    minDelayMs: 800,
    maxDelayMs: 20_000,
  })

  watch(
    () => logs.level,
    () => handle.restart(),
  )

  return handle
}
