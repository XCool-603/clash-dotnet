import { computed, ref } from 'vue'
import { defineStore } from 'pinia'

import { clashApi } from '@/api/clash'
import type { ApiError, ApiResult } from '@/api/client'
import type { Connection } from '@/types'

/** Poll interval while the connections page is open. */
export const CONNECTIONS_FAST_INTERVAL = 1000
/** Poll interval everywhere else (the shell keeps counters warm). */
export const CONNECTIONS_IDLE_INTERVAL = 3000

/**
 * Live connection table state. Totals and memory keep updating while the
 * table itself is paused, so the dashboard counters never freeze.
 */
export const useConnectionsStore = defineStore('connections', () => {
  const connections = ref<Connection[]>([])
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
      if (!paused.value) {
        connections.value = snapshot.connections ?? []
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

  async function close(id: string): Promise<ApiResult<unknown>> {
    const result = await clashApi.closeConnection(id)
    if (result.ok) {
      connections.value = connections.value.filter((item) => item.id !== id)
      closedCount.value += 1
    } else {
      error.value = result.error
    }
    return result
  }

  async function closeAll(): Promise<ApiResult<unknown>> {
    const result = await clashApi.closeAllConnections()
    if (result.ok) {
      closedCount.value += connections.value.length
      connections.value = []
    } else {
      error.value = result.error
    }
    return result
  }

  return {
    // state
    connections,
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
    // actions
    load,
    startPolling,
    stopPolling,
    setPaused,
    togglePause,
    close,
    closeAll,
  }
})
