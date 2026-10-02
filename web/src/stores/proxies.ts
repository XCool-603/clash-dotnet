import { computed, ref } from 'vue'
import { defineStore } from 'pinia'

import { DEFAULT_TEST_URL, clashApi } from '@/api/clash'
import type { DelayOptions } from '@/api/clash'
import type { ApiError, ApiResult } from '@/api/client'
import type { ProxyObject, ProxyProvider } from '@/types'
import { isGroup } from '@/types'
import { mapLimit } from '@/utils/async'
import { latestDelay } from '@/utils/format'

const HISTORY_LIMIT = 20

/** How long a cached measurement stays usable before it is considered stale. */
export const DELAY_CACHE_TTL = 30 * 60 * 1000

/**
 * Proxy tree, provider subscriptions and health-check orchestration.
 *
 * Groups of type `URLTest` / `Fallback` / `LoadBalance` / `Relay` are
 * read-only; only `Selector` groups accept a manual choice.
 */
export const useProxiesStore = defineStore('proxies', () => {
  const proxies = ref<Record<string, ProxyObject>>({})
  const providers = ref<Record<string, ProxyProvider>>({})

  const loading = ref(false)
  const error = ref<ApiError | null>(null)
  const providerError = ref<ApiError | null>(null)
  const providersAvailable = ref(true)

  /** Per-name "health check in flight" flags (groups and nodes share the map). */
  const testing = ref<Record<string, boolean>>({})
  const lastUpdated = ref(0)

  const allProxies = computed<ProxyObject[]>(() => Object.values(proxies.value))
  const groups = computed<ProxyObject[]>(() => allProxies.value.filter((proxy) => isGroup(proxy)))
  const nodes = computed<ProxyObject[]>(() => allProxies.value.filter((proxy) => !isGroup(proxy)))
  const selectorGroups = computed<ProxyObject[]>(() =>
    groups.value.filter((proxy) => proxy.type === 'Selector'),
  )
  const providerList = computed<ProxyProvider[]>(() => Object.values(providers.value))
  const hasData = computed<boolean>(() => allProxies.value.length > 0)

  /** The group the dashboard's quick selector should drive. */
  const primaryGroup = computed<ProxyObject | null>(() => {
    const list = groups.value
    return (
      list.find((group) => group.name === 'GLOBAL') ??
      list.find((group) => group.name === 'PROXY') ??
      list.find((group) => group.type === 'Selector') ??
      null
    )
  })

  const isTesting = computed<boolean>(() => Object.values(testing.value).some(Boolean))

  /**
   * The URL a group's health checks should probe. A group may declare its own
   * `testUrl` in the core config; otherwise the core's default is used. The
   * protocol of this URL decides which latency thresholds apply.
   */
  function probeUrlOf(groupName?: string | null): string {
    if (groupName) {
      const group = proxies.value[groupName]
      const url = group ? group.testUrl : undefined
      if (typeof url === 'string' && url.length > 0) return url
    }
    return DEFAULT_TEST_URL
  }

  /** The provider a node came from, when it is not in the global proxy map. */
  function providerOf(nodeName: string): string | null {
    for (const provider of Object.values(providers.value)) {
      for (const node of provider.proxies ?? []) {
        if (node.name === nodeName) return provider.name
      }
    }
    return null
  }

  function getProxy(name: string): ProxyObject | undefined {
    return proxies.value[name]
  }

  function membersOf(group: ProxyObject | string | null | undefined): ProxyObject[] {
    if (!group) return []
    const resolved = typeof group === 'string' ? proxies.value[group] : group
    if (!resolved?.all) return []
    const output: ProxyObject[] = []
    for (const name of resolved.all) {
      const member = proxies.value[name]
      if (member) output.push(member)
    }
    return output
  }

  function memberNames(group: ProxyObject | string | null | undefined): string[] {
    if (!group) return []
    const resolved = typeof group === 'string' ? proxies.value[group] : group
    return resolved?.all ? resolved.all.slice() : []
  }

  /** Latest measured delay for a proxy (0 = the last probe failed). */
  function delayOf(name: string): number | null {
    const proxy = proxies.value[name]
    if (!proxy) return null
    return latestDelay(proxy.history)
  }

  /** Delay of the member a group currently points at. */
  function selectedDelayOf(group: ProxyObject | string | null | undefined): number | null {
    if (!group) return null
    const resolved = typeof group === 'string' ? proxies.value[group] : group
    if (!resolved) return null
    const current = resolved.now ?? resolved.all?.[0]
    if (!current) return null
    return delayOf(current)
  }

  function isSelectable(group: ProxyObject | null | undefined): boolean {
    return !!group && group.type === 'Selector'
  }

  function recordDelay(name: string, delay: number): void {
    const proxy = proxies.value[name]
    if (!proxy) return
    const history = Array.isArray(proxy.history) ? proxy.history.slice() : []
    history.push({ time: new Date().toISOString(), delay })
    while (history.length > HISTORY_LIMIT) history.shift()
    proxy.history = history
  }

  async function load(): Promise<void> {
    loading.value = true
    const result = await clashApi.proxies()
    loading.value = false
    if (result.ok) {
      proxies.value = result.data.proxies ?? {}
      error.value = null
      lastUpdated.value = Date.now()
    } else {
      error.value = result.error
    }
  }

  async function loadProviders(): Promise<void> {
    const result = await clashApi.proxyProviders()
    if (result.ok) {
      providers.value = result.data.providers ?? {}
      providerError.value = null
      providersAvailable.value = true
    } else if (result.error.isMissing) {
      // Stock Clash without providers configured — an empty section, not an error.
      providers.value = {}
      providerError.value = null
      providersAvailable.value = false
    } else {
      providerError.value = result.error
    }
  }

  async function refresh(): Promise<void> {
    await Promise.all([load(), loadProviders()])
  }

  /** Select a member of a `Selector` group. */
  async function select(groupName: string, nodeName: string): Promise<ApiResult<unknown>> {
    const result = await clashApi.selectProxy(groupName, nodeName)
    if (result.ok) {
      const group = proxies.value[groupName]
      if (group) group.now = nodeName
      lastUpdated.value = Date.now()
    }
    return result
  }

  /** Probe a single node and record the result in its history. */
  async function testDelay(name: string, options?: DelayOptions): Promise<number | null> {
    testing.value[name] = true
    try {
      const provider = proxies.value[name] ? null : providerOf(name)
      const result = provider
        ? await clashApi.providerNodeDelay(provider, name, options)
        : await clashApi.proxyDelay(name, options)

      if (result.ok) {
        const delay = typeof result.data?.delay === 'number' ? result.data.delay : 0
        recordDelay(name, delay)
        lastUpdated.value = Date.now()
        return delay
      }
      // A hard transport failure should not be recorded as "node failed".
      if (result.error.kind !== 'network' && result.error.kind !== 'timeout') {
        recordDelay(name, 0)
      }
      return null
    } finally {
      testing.value[name] = false
    }
  }

  /** Probe many nodes with bounded concurrency. */
  async function testNodes(
    names: readonly string[],
    limit = 8,
    options?: DelayOptions,
  ): Promise<void> {
    await mapLimit(names, limit, async (name) => {
      await testDelay(name, options)
    })
  }

  /**
   * Health-check a whole group in **one** server-side request via
   * `GET /group/:name/delay`.
   *
   * Every member is flagged as testing for the duration so the UI can show a
   * per-node spinner. Only a 404 (a core that does not implement the bulk
   * endpoint) falls back to a bounded client-side fan-out — a transport
   * failure is reported rather than masked by 40 extra requests.
   */
  async function testGroup(name: string): Promise<void> {
    const group = proxies.value[name]
    if (!group) return

    const members = memberNames(group)
    testing.value[name] = true
    for (const member of members) testing.value[member] = true

    try {
      const options: DelayOptions = { url: probeUrlOf(name) }
      const result = await clashApi.groupDelay(name, options)

      if (result.ok) {
        let recorded = 0
        for (const [member, delay] of Object.entries(result.data)) {
          if (typeof delay === 'number' && proxies.value[member]) {
            recordDelay(member, delay)
            recorded += 1
          }
        }
        lastUpdated.value = Date.now()
        if (recorded > 0) return
      }

      if (result.ok || result.error.isMissing) {
        await testNodes(members, 8, options)
        lastUpdated.value = Date.now()
      } else {
        error.value = result.error
      }
    } finally {
      testing.value[name] = false
      for (const member of members) testing.value[member] = false
    }
  }

  /** Health-check every group plus any node that belongs to no group. */
  async function testAll(): Promise<void> {
    const groupNames = groups.value.map((group) => group.name)

    const grouped = new Set<string>()
    for (const group of groups.value) {
      for (const member of group.all ?? []) grouped.add(member)
    }
    const orphans = nodes.value.filter((node) => !grouped.has(node.name)).map((node) => node.name)

    await mapLimit(groupNames, 2, async (name) => {
      await testGroup(name)
    })
    await testNodes(orphans, 8)
    lastUpdated.value = Date.now()
  }

  /** Drop a manual pin from an automatic group (`DELETE /proxies/:name`). */
  async function unfix(name: string): Promise<ApiResult<unknown>> {
    const result = await clashApi.unfixProxy(name)
    if (result.ok) {
      await load()
    } else if (!result.error.isMissing) {
      error.value = result.error
    }
    return result
  }

  async function updateProvider(name: string): Promise<ApiResult<unknown>> {
    const result = await clashApi.updateProxyProvider(name)
    if (result.ok) {
      await Promise.all([load(), loadProviders()])
    } else {
      providerError.value = result.error
    }
    return result
  }

  async function healthCheckProvider(name: string): Promise<ApiResult<unknown>> {
    const result = await clashApi.healthCheckProvider(name)
    if (result.ok) {
      await load()
    } else {
      providerError.value = result.error
    }
    return result
  }

  return {
    // state
    proxies,
    providers,
    loading,
    error,
    providerError,
    providersAvailable,
    testing,
    lastUpdated,
    // getters
    allProxies,
    groups,
    nodes,
    selectorGroups,
    providerList,
    hasData,
    primaryGroup,
    isTesting,
    // lookups
    getProxy,
    providerOf,
    probeUrlOf,
    membersOf,
    memberNames,
    delayOf,
    selectedDelayOf,
    isSelectable,
    // actions
    load,
    loadProviders,
    refresh,
    select,
    unfix,
    testDelay,
    testNodes,
    testGroup,
    testAll,
    updateProvider,
    healthCheckProvider,
  }
})
