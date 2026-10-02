import { computed, ref, shallowRef } from 'vue'
import { defineStore } from 'pinia'

import { clashApi } from '@/api/clash'
import type { ApiError, ApiResult } from '@/api/client'
import type { Connection } from '@/types'

/** Poll interval while the connections page is open. */
export const CONNECTIONS_FAST_INTERVAL = 1000
/** Poll interval everywhere else (the shell keeps counters warm). */
export const CONNECTIONS_IDLE_INTERVAL = 3000
/** How many retired connections the history view keeps. */
export const CONNECTIONS_HISTORY_LIMIT = 500

/**
 * Live connection table state. Totals and memory keep updating while the
 * table itself is paused, so the dashboard counters never freeze.
 *
 * The three connection arrays are `shallowRef`s on purpose: a deep `ref` would
 * proxy every connection and every nested metadata field on every one-second
 * frame, which is the single biggest source of UI stalls at this scale. Only
 * `.value` is ever reassigned.
 */
export const useConnectionsStore = defineStore('connections', () => {
  const connections = shallowRef<Connection[]>([])
  /** Connections that were open on a previous frame and are now gone. */
  const closedConnections = shallowRef<Connection[]>([])
  const downloadTotal = ref(0)
  const uploadTotal = ref(0)
  const memory = ref(0)

  const loading = ref(false)
  const error = ref<ApiError | null>(null)
  const paused = ref(false)
  const lastUpdated = ref(0)
  const closedCount = ref(0)

  let timer: ReturnType<typeof setInterval> | null = null
  let intervalMs = 0
  let inFlight = false

  const activeCount = computed<number>(() => connections.value.length)
  const totalCount = computed<number>(() => connections.value.length)
  const isPolling = computed<boolean>(() => timer !== null)
  const pollingInterval = computed<number>(() => intervalMs)
  const closedVisible = computed<Connection[]>(() =>
    closedConnections.value.slice(0, CONNECTIONS_HISTORY_LIMIT),
  )

  /** Retire the rows that disappeared between two frames, newest first. */
  function retire(previous: Connection[], current: Connection[]): void {
    if (previous.length === 0) return
    const alive = new Set<string>()
    for (const item of current) alive.add(item.id)

    const gone = previous.filter((item) => !alive.has(item.id))
    if (gone.length === 0) return

    closedCount.value += gone.length
    const merged = gone.reverse().concat(closedConnections.value)
    closedConnections.value = merged.slice(0, CONNECTIONS_HISTORY_LIMIT)
  }

  async function load(): Promise<void> {
    if (inFlight) return
    inFlight = true
    if (connections.value.length === 0) loading.value = true

    const result = await clashApi.connections()

    inFlight = false
    loading.value = false

    if (result.ok) {
      const snapshot = result.data
      downloadTotal.value = snapshot.downloadTotal ?? 0
      uploadTotal.value = snapshot.uploadTotal ?? 0
      memory.value = snapshot.memory ?? 0

      // Totals keep updating while the table is paused; only the rows freeze.
      if (!paused.value) {
        const next = snapshot.connections ?? []
        retire(connections.value, next)
        connections.value = next
      }
      lastUpdated.value = Date.now()
      error.value = null
    } else {
      error.value = result.error
    }
  }

  function startPolling(ms: number = CONNECTIONS_FAST_INTERVAL): void {
    if (timer !== null && intervalMs === ms) return
    stopPolling()
    intervalMs = ms
    void load()
    timer = setInterval(() => {
      void load()
    }, ms)
  }

  function stopPolling(): void {
    if (timer !== null) {
      clearInterval(timer)
      timer = null
      intervalMs = 0
    }
  }

  function setPaused(value: boolean): void {
    paused.value = value
    if (!value) void load()
  }

  function togglePause(): void {
    setPaused(!paused.value)
  }

  function clearClosed(): void {
    closedConnections.value = []
  }

  function clear(): void {
    connections.value = []
    closedConnections.value = []
    closedCount.value = 0
  }

  async function close(id: string): Promise<ApiResult<unknown>> {
    const target = connections.value.find((item) => item.id === id) ?? null
    const result = await clashApi.closeConnection(id)
    if (result.ok) {
      connections.value = connections.value.filter((item) => item.id !== id)
      if (target) {
        closedConnections.value = [target].concat(closedConnections.value).slice(0, CONNECTIONS_HISTORY_LIMIT)
      }
      closedCount.value += 1
      error.value = null
    } else {
      error.value = result.error
    }
    return result
  }

  async function closeAll(): Promise<ApiResult<unknown>> {
    const result = await clashApi.closeAllConnections()
    if (result.ok) {
      closedCount.value += connections.value.length
      closedConnections.value = connections.value
        .slice()
        .reverse()
        .concat(closedConnections.value)
        .slice(0, CONNECTIONS_HISTORY_LIMIT)
      connections.value = []
      error.value = null
    } else {
      error.value = result.error
    }
    return result
  }

  return {
    // state
    connections,
    closedConnections,
    downloadTotal,
    uploadTotal,
    memory,
    loading,
    error,
    paused,
    lastUpdated,
    closedCount,
    // getters
    activeCount,
    totalCount,
    isPolling,
    pollingInterval,
    closedVisible,
    // actions
    load,
    startPolling,
    stopPolling,
    setPaused,
    togglePause,
    clearClosed,
    clear,
    close,
    closeAll,
  }
})
