import { apiDelete, apiGet, apiPatch, apiPut, encodeName } from './client'
import type { ApiResult } from './client'
import type {
  ClashConfig,
  ConnectionsSnapshot,
  DelayResponse,
  DnsQueryAnswer,
  GroupDelayResponse,
  ProxyObject,
  ProxyProvider,
  ProxyProvidersResponse,
  ProxiesResponse,
  RuleProvider,
  RuleProvidersResponse,
  RulesResponse,
  VersionInfo,
} from '@/types'

/** Clash's own default health-check endpoint. */
export const DEFAULT_TEST_URL = 'http://www.gstatic.com/generate_204'

export interface DelayOptions {
  timeout?: number
  url?: string
}

function delayParams(options?: DelayOptions): Record<string, string | number> {
  return {
    timeout: options?.timeout ?? 5000,
    url: options?.url && options.url.length > 0 ? options.url : DEFAULT_TEST_URL,
  }
}

/**
 * Thin, typed wrapper over the Clash RESTful API.
 * Every method resolves to an `ApiResult` and never rejects.
 */
export const clashApi = {
  /* ---- version ---------------------------------------------------- */
  version: (): Promise<ApiResult<VersionInfo>> => apiGet<VersionInfo>('/version'),

  /* ---- configs ---------------------------------------------------- */
  configs: (): Promise<ApiResult<ClashConfig>> => apiGet<ClashConfig>('/configs'),

  patchConfigs: (payload: Partial<ClashConfig>): Promise<ApiResult<unknown>> =>
    apiPatch<unknown>('/configs', payload),

  /** Load a profile from disk. `force` reloads even if the file is unchanged. */
  reloadConfig: (path: string, force = false): Promise<ApiResult<unknown>> =>
    apiPut<unknown>('/configs', { path }, { params: { force: force ? 'true' : undefined } }),

  /** Load an inline YAML payload. */
  loadConfigPayload: (payload: string, force = false): Promise<ApiResult<unknown>> =>
    apiPut<unknown>('/configs', { payload }, { params: { force: force ? 'true' : undefined } }),

  flushFakeIp: (): Promise<ApiResult<unknown>> => apiGet<unknown>('/cache/fakeip/flush'),

  /* ---- proxies ---------------------------------------------------- */
  proxies: (): Promise<ApiResult<ProxiesResponse>> => apiGet<ProxiesResponse>('/proxies'),

  proxy: (name: string): Promise<ApiResult<ProxyObject>> =>
    apiGet<ProxyObject>(`/proxies/${encodeName(name)}`),

  /** Select a member of a `Selector` group. */
  selectProxy: (group: string, name: string): Promise<ApiResult<unknown>> =>
    apiPut<unknown>(`/proxies/${encodeName(group)}`, { name }),

  proxyDelay: (name: string, options?: DelayOptions): Promise<ApiResult<DelayResponse>> =>
    apiGet<DelayResponse>(`/proxies/${encodeName(name)}/delay`, { params: delayParams(options) }),

  groupDelay: (name: string, options?: DelayOptions): Promise<ApiResult<GroupDelayResponse>> =>
    apiGet<GroupDelayResponse>(`/group/${encodeName(name)}/delay`, { params: delayParams(options) }),

  /* ---- rules ------------------------------------------------------ */
  rules: (): Promise<ApiResult<RulesResponse>> => apiGet<RulesResponse>('/rules'),

  patchRule: (rule: {
    type: string
    payload: string
    disabled: boolean
  }): Promise<ApiResult<unknown>> => apiPatch<unknown>('/rules', rule),

  ruleProviders: (): Promise<ApiResult<RuleProvidersResponse>> =>
    apiGet<RuleProvidersResponse>('/providers/rules'),

  updateRuleProvider: (name: string): Promise<ApiResult<unknown>> =>
    apiPut<unknown>(`/providers/rules/${encodeName(name)}`),

  /* ---- connections ------------------------------------------------ */
  connections: (): Promise<ApiResult<ConnectionsSnapshot>> =>
    apiGet<ConnectionsSnapshot>('/connections'),

  closeConnection: (id: string): Promise<ApiResult<unknown>> =>
    apiDelete<unknown>(`/connections/${encodeName(id)}`),

  closeAllConnections: (): Promise<ApiResult<unknown>> => apiDelete<unknown>('/connections'),

  /* ---- providers -------------------------------------------------- */
  proxyProviders: (): Promise<ApiResult<ProxyProvidersResponse>> =>
    apiGet<ProxyProvidersResponse>('/providers/proxies'),

  proxyProvider: (name: string): Promise<ApiResult<ProxyProvider>> =>
    apiGet<ProxyProvider>(`/providers/proxies/${encodeName(name)}`),

  updateProxyProvider: (name: string): Promise<ApiResult<unknown>> =>
    apiPut<unknown>(`/providers/proxies/${encodeName(name)}`),

  healthCheckProvider: (name: string, options?: DelayOptions): Promise<ApiResult<unknown>> =>
    apiGet<unknown>(`/providers/proxies/${encodeName(name)}/healthcheck`, {
      params: delayParams(options),
    }),

  /* ---- dns -------------------------------------------------------- */
  dnsQuery: (name: string, type = 'A'): Promise<ApiResult<DnsQueryAnswer>> =>
    apiGet<DnsQueryAnswer>('/dns/query', { params: { name, type } }),
}

export type ClashApi = typeof clashApi
