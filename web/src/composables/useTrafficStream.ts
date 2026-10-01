import { useTrafficStore } from '@/stores/traffic'
import type { TrafficMessage } from '@/types'
import { safeJson, toNumber } from '@/utils/json'

import { useStream } from './useStream'
import type { StreamHandle } from './useStream'

/**
 * Subscribes to `/traffic` and feeds the rolling up/down series.
 * Automatically reconnects and cleans up with the owning scope.
 */
export function useTrafficStream(): StreamHandle {
  const traffic = useTrafficStore()

  return useStream({
    path: () => '/traffic',
    onMessage: (raw) => {
      const message = safeJson<TrafficMessage>(raw)
      if (!message) return
      traffic.pushTraffic(toNumber(message.up), toNumber(message.down))
    },
    onStatus: (status) => traffic.setTrafficStatus(status),
    minDelayMs: 500,
    maxDelayMs: 15_000,
  })
}
