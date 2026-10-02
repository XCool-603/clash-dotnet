import { computed, ref } from 'vue'
import { defineStore } from 'pinia'

import { clashApi } from '@/api/clash'
import type { ApiError, ApiResult } from '@/api/client'
import type { Rule, RuleProvider } from '@/types'

/** Stable identity for a rule across `PATCH` round-trips. */
export function ruleKey(rule: Rule, index: number): string {
  return `${index}::${rule.type}::${rule.payload}`
}

/**
 * Rule list plus rule-provider subscriptions. Rule enable/disable is applied
 * optimistically and rolled back when the backend rejects the patch.
 */
export const useRulesStore = defineStore('rules', () => {
  const rules = ref<Rule[]>([])
  const providers = ref<Record<string, RuleProvider>>({})

  const loading = ref(false)
  const error = ref<ApiError | null>(null)
  const providerError = ref<ApiError | null>(null)
  const providersAvailable = ref(true)
  const saving = ref<Record<string, boolean>>({})
  const lastUpdated = ref(0)

  const providerList = computed<RuleProvider[]>(() => Object.values(providers.value))
  const totalCount = computed<number>(() => rules.value.length)
  const disabledCount = computed<number>(() => rules.value.filter((rule) => rule.disabled).length)

  async function load(): Promise<void> {
    loading.value = true
    const result = await clashApi.rules()
    loading.value = false
    if (result.ok) {
      rules.value = (result.data.rules ?? []).map((rule) => ({
        ...rule,
        disabled: rule.disabled === true,
      }))
      error.value = null
      lastUpdated.value = Date.now()
    } else {
      error.value = result.error
    }
  }

  async function loadProviders(): Promise<void> {
    const result = await clashApi.ruleProviders()
    if (result.ok) {
      providers.value = result.data.providers ?? {}
      providerError.value = null
      providersAvailable.value = true
    } else if (result.error.isMissing) {
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

  /**
   * Enable/disable one rule.
   *
   * `PATCH /rules` (body `{type, payload, disabled}`) is the modern shape; a
   * core that does not implement it answers 404, in which case the
   * index-addressed `PATCH /rules/disable` (`{"<index>": disabled}`) is tried
   * before the change is rolled back.
   */
  async function setDisabled(rule: Rule, disabled: boolean, index: number): Promise<ApiResult<unknown>> {
    const previous = rule.disabled === true
    const key = ruleKey(rule, index)
    rule.disabled = disabled
    saving.value[key] = true

    let result = await clashApi.patchRule({ type: rule.type, payload: rule.payload, disabled })

    if (!result.ok && result.error.isMissing) {
      result = await clashApi.patchRuleDisabled(index, disabled)
    }

    saving.value[key] = false
    if (!result.ok) {
      rule.disabled = previous
      error.value = result.error
    } else {
      error.value = null
      lastUpdated.value = Date.now()
    }
    return result
  }

  async function updateProvider(name: string): Promise<ApiResult<unknown>> {
    saving.value[`provider:${name}`] = true
    const result = await clashApi.updateRuleProvider(name)
    saving.value[`provider:${name}`] = false

    if (result.ok) {
      await loadProviders()
      providerError.value = null
    } else {
      providerError.value = result.error
    }
    return result
  }

  async function updateAllProviders(): Promise<void> {
    const names = providerList.value.map((provider) => provider.name)
    for (const name of names) {
      await updateProvider(name)
    }
  }

  return {
    // state
    rules,
    providers,
    loading,
    error,
    providerError,
    providersAvailable,
    saving,
    lastUpdated,
    // getters
    providerList,
    totalCount,
    disabledCount,
    // actions
    load,
    loadProviders,
    refresh,
    setDisabled,
    updateProvider,
    updateAllProviders,
  }
})
