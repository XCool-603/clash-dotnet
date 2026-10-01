import { useTrafficStore } from '@/stores/traffic'
import type { MemoryMessage } from '@/types'
import { safeJson, toNumber } from '@/utils/json'

import { useStream } from './useStream'
import type { StreamHandle } from './useStream'

/**
 * Subscribes to `/memory` and feeds the rolling memory series plus the
 * current in-use / OS-limit values.
 */
export function useMemoryStream(): StreamHandle {
  const traffic = useTrafficStore()

  return useStream({
    path: () => '/memory',
    onMessage: (raw) => {
      const message = safeJson<MemoryMessage>(raw)
      if (!message) return
      traffic.pushMemory(toNumber(message.inuse), toNumber(message.oslimit))
    },
    onStatus: (status) => traffic.setMemoryStatus(status),
    minDelayMs: 1000,
    maxDelayMs: 20_000,
  })
}
