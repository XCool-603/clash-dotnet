import { computed, ref } from 'vue'
import { defineStore } from 'pinia'

import { clashApi } from '@/api/clash'
import type { ApiError, ApiResult } from '@/api/client'
import type { ClashConfig, ClashMode, LogLevel, VersionInfo } from '@/types'
import { CLASH_MODES, LOG_LEVELS } from '@/types'
import { deepMerge } from '@/utils/object'

function normalizeMode(value: unknown): ClashMode {
  return typeof value === 'string' && (CLASH_MODES as readonly string[]).includes(value)
    ? (value as ClashMode)
    : 'rule'
}

function normalizeLogLevel(value: unknown): LogLevel {
  return typeof value === 'string' && (LOG_LEVELS as readonly string[]).includes(value)
    ? (value as LogLevel)
    : 'info'
}

/**
 * Backend connectivity, `/version` metadata and the live Clash configuration.
 * Also owns the "is the backend reachable / is the secret right" status that
 * drives the shell's status pill.
 */
export const useConfigStore = defineStore('config', () => {
  const version = ref<VersionInfo | null>(null)
  const config = ref<ClashConfig | null>(null)

  const loading = ref(false)
  const saving = ref(false)

  const online = ref(false)
  const unauthorized = ref(false)
  const error = ref<ApiError | null>(null)
  const lastSync = ref(0)

  let pollTimer: ReturnType<typeof setInterval> | null = null
  let inFlight = false

  const mode = computed<ClashMode>(() => normalizeMode(config.value?.mode))
  const logLevel = computed<LogLevel>(() => normalizeLogLevel(config.value?.['log-level']))
  const connected = computed<boolean>(() => online.value)
  const versionLabel = computed<string>(() => version.value?.version ?? 'unknown')
  const secretConfigured = computed<boolean>(
    () => typeof config.value?.secret === 'string' && config.value.secret.length > 0,
  )
  const tunEnabled = computed<boolean>(() => config.value?.tun?.enable === true)
  const dnsEnabled = computed<boolean>(() => config.value?.dns?.enable === true)

  function applyFailure(failure: ApiError): void {
    error.value = failure
    unauthorized.value = failure.kind === 'unauthorized'
    if (failure.kind === 'network' || failure.kind === 'timeout' || failure.kind === 'unauthorized') {
      online.value = false
    }
  }

  /** Full refresh: `/version` + `/configs`. */
  async function load(): Promise<void> {
    if (inFlight) return
    inFlight = true
    loading.value = true
    try {
      const [versionResult, configResult] = await Promise.all([clashApi.version(), clashApi.configs()])

      if (versionResult.ok) version.value = versionResult.data

      if (configResult.ok) {
        config.value = configResult.data
        online.value = true
        unauthorized.value = false
        error.value = null
        lastSync.value = Date.now()
      } else {
        applyFailure(configResult.error)
      }
    } finally {
      inFlight = false
      loading.value = false
    }
  }

  /** Cheap liveness probe used by the status poller. */
  async function ping(): Promise<boolean> {
    const result = await clashApi.version()
    if (result.ok) {
      version.value = result.data
      online.value = true
      unauthorized.value = false
      if (error.value && (error.value.kind === 'network' || error.value.kind === 'timeout')) {
        error.value = null
      }
      return true
    }
    applyFailure(result.error)
    return false
  }

  /** Partial update via `PATCH /configs`, merged into the local snapshot. */
  async function patch(partial: Partial<ClashConfig>): Promise<ApiResult<unknown>> {
    saving.value = true
    const result = await clashApi.patchConfigs(partial)
    saving.value = false

    if (result.ok) {
      const base: ClashConfig = config.value ?? {}
      config.value = deepMerge(base, partial as Record<string, unknown>)
      error.value = null
      online.value = true
      lastSync.value = Date.now()
    } else {
      applyFailure(result.error)
    }
    return result
  }

  async function setMode(next: ClashMode): Promise<ApiResult<unknown>> {
    return patch({ mode: next })
  }

  async function setLogLevel(next: LogLevel): Promise<ApiResult<unknown>> {
    return patch({ 'log-level': next })
  }

  /** Reload a profile from disk via `PUT /configs { path }`. */
  async function reloadProfile(path: string, force = true): Promise<ApiResult<unknown>> {
    saving.value = true
    const result = await clashApi.reloadConfig(path, force)
    saving.value = false
    if (result.ok) {
      await load()
    } else {
      applyFailure(result.error)
    }
    return result
  }

  async function flushFakeIp(): Promise<ApiResult<unknown>> {
    const result = await clashApi.flushFakeIp()
    if (!result.ok) applyFailure(result.error)
    return result
  }

  function startPolling(intervalMs = 5000): void {
    if (pollTimer !== null) return
    pollTimer = setInterval(() => {
      void ping()
    }, intervalMs)
  }

  function stopPolling(): void {
    if (pollTimer !== null) {
      clearInterval(pollTimer)
      pollTimer = null
    }
  }

  return {
    // state
    version,
    config,
    loading,
    saving,
    online,
    unauthorized,
    error,
    lastSync,
    // getters
    mode,
    logLevel,
    connected,
    versionLabel,
    secretConfigured,
    tunEnabled,
    dnsEnabled,
    // actions
    load,
    ping,
    patch,
    setMode,
    setLogLevel,
    reloadProfile,
    flushFakeIp,
    startPolling,
    stopPolling,
  }
})
