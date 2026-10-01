import { computed, ref, watch } from 'vue'
import { defineStore } from 'pinia'

import type { LogEntry, LogLevel } from '@/types'
import { LOG_LEVELS } from '@/types'
import type { StreamStatus } from '@/utils/ws'

/** Hard cap on buffered log lines. */
export const LOG_BUFFER_LIMIT = 2000

const LEVEL_RANK: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warning: 2,
  error: 3,
}

/** Normalize the various spellings Clash has used for log levels. */
export function normalizeLogLevel(type: string): LogLevel {
  const value = type.toLowerCase()
  if (value === 'debug') return 'debug'
  if (value === 'warning' || value === 'warn') return 'warning'
  if (value === 'error' || value === 'err' || value === 'fatal') return 'error'
  return 'info'
}

/**
 * WebSocket log buffer. Pausing freezes the rendered list while new lines keep
 * accumulating (still capped), so resuming never loses the interval.
 */
export const useLogsStore = defineStore('logs', () => {
  const entries = ref<LogEntry[]>([])
  const frozen = ref<LogEntry[]>([])

  const paused = ref(false)
  const level = ref<LogLevel>('info')
  const search = ref('')
  const autoScroll = ref(true)

  const connected = ref(false)
  const status = ref<StreamStatus>('idle')
  const lastError = ref<string | null>(null)
  const droppedCount = ref(0)

  let sequence = 0

  /** Lines currently rendered (frozen while paused). */
  const source = computed<LogEntry[]>(() => (paused.value ? frozen.value : entries.value))

  const filtered = computed<LogEntry[]>(() => {
    const minimum = LEVEL_RANK[level.value]
    const needle = search.value.trim().toLowerCase()
    return source.value.filter((entry) => {
      if (LEVEL_RANK[normalizeLogLevel(entry.type)] < minimum) return false
      if (needle.length === 0) return true
      return entry.payload.toLowerCase().includes(needle)
    })
  })

  const bufferedCount = computed<number>(() => entries.value.length)
  const visibleCount = computed<number>(() => filtered.value.length)

  const countsByLevel = computed<Record<LogLevel, number>>(() => {
    const counts: Record<LogLevel, number> = { debug: 0, info: 0, warning: 0, error: 0 }
    for (const entry of source.value) {
      counts[normalizeLogLevel(entry.type)] += 1
    }
    return counts
  })

  function append(type: string, payload: string): void {
    sequence += 1
    const list = entries.value
    list.push({ id: sequence, type, payload, time: Date.now() })

    const overflow = list.length - LOG_BUFFER_LIMIT
    if (overflow > 0) {
      list.splice(0, overflow)
      droppedCount.value += overflow
    }
  }

  function clear(): void {
    entries.value = []
    frozen.value = []
    droppedCount.value = 0
  }

  function setPaused(value: boolean): void {
    paused.value = value
  }

  function togglePause(): void {
    paused.value = !paused.value
  }

  function setLevel(value: LogLevel): void {
    if ((LOG_LEVELS as readonly string[]).includes(value)) level.value = value
  }

  function setConnected(value: boolean): void {
    connected.value = value
  }

  function setStatus(value: StreamStatus): void {
    status.value = value
    connected.value = value === 'open'
  }

  watch(paused, (value) => {
    if (value) frozen.value = entries.value.slice()
  })

  return {
    // state
    entries,
    frozen,
    paused,
    level,
    search,
    autoScroll,
    connected,
    status,
    lastError,
    droppedCount,
    // getters
    source,
    filtered,
    bufferedCount,
    visibleCount,
    countsByLevel,
    // actions
    append,
    clear,
    setPaused,
    togglePause,
    setLevel,
    setConnected,
    setStatus,
  }
})
