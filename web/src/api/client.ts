import axios from 'axios'
import type { AxiosError, AxiosInstance, AxiosRequestConfig } from 'axios'

import { useSettingsStore } from '@/stores/settings'
import { messageOf } from '@/utils/async'

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

export type ApiErrorKind =
  | 'network'
  | 'timeout'
  | 'unauthorized'
  | 'not-found'
  | 'bad-request'
  | 'server'
  | 'unknown'

export interface ApiErrorInit {
  kind: ApiErrorKind
  message: string
  status: number | null
  method: string
  url: string
  detail?: string | null
}

/** A normalized, always-thrown-by-nobody transport error. */
export class ApiError extends Error {
  readonly kind: ApiErrorKind
  readonly status: number | null
  readonly method: string
  readonly url: string
  readonly detail: string | null

  constructor(init: ApiErrorInit) {
    super(init.message)
    this.name = 'ApiError'
    this.kind = init.kind
    this.status = init.status
    this.method = init.method
    this.url = init.url
    this.detail = init.detail ?? null
  }

  /** True when the caller should ask the user for a secret. */
  get needsSecret(): boolean {
    return this.kind === 'unauthorized'
  }

  /** True when the backend simply does not implement the endpoint. */
  get isMissing(): boolean {
    return this.kind === 'not-found'
  }
}

/**
 * Result of an API call. Every store action funnels through this union, so a
 * dead backend or a 401 can never surface as an unhandled rejection.
 */
export type ApiResult<T> = { ok: true; data: T } | { ok: false; error: ApiError }

export function apiOk<T>(data: T): ApiResult<T> {
  return { ok: true, data }
}

export function apiFail<T>(error: ApiError): ApiResult<T> {
  return { ok: false, error }
}

/* ------------------------------------------------------------------ */
/* Transport                                                           */
/* ------------------------------------------------------------------ */

const http: AxiosInstance = axios.create({
  timeout: 20_000,
  // The Clash API is a plain JSON API; let axios do the parsing.
  responseType: 'json',
})

http.interceptors.request.use((config) => {
  const settings = useSettingsStore()
  const base = settings.apiBase
  // Empty base => same origin (relative URLs resolve against the page).
  config.baseURL = base.length > 0 ? base : undefined

  const secret = settings.secret.trim()
  if (secret.length > 0) {
    config.headers.set('Authorization', `Bearer ${secret}`)
  }
  return config
})

function requestUrl(config: AxiosRequestConfig): string {
  const base = config.baseURL ?? ''
  const url = config.url ?? ''
  return `${base}${url}`
}

function extractDetail(data: unknown): string | null {
  if (data === null || data === undefined) return null
  if (typeof data === 'string') return data.slice(0, 500)
  if (typeof data === 'object') {
    const record = data as Record<string, unknown>
    for (const key of ['message', 'error', 'detail', 'title']) {
      const value = record[key]
      if (typeof value === 'string' && value.length > 0) return value.slice(0, 500)
    }
    try {
      return JSON.stringify(data).slice(0, 500)
    } catch {
      return null
    }
  }
  return String(data)
}

function toApiError(error: unknown, config: AxiosRequestConfig): ApiError {
  const method = (config.method ?? 'get').toUpperCase()
  const url = requestUrl(config)

  if (error instanceof ApiError) return error

  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError<unknown>
    const status = axiosError.response?.status ?? null
    const detail = extractDetail(axiosError.response?.data)

    if (axiosError.code === 'ECONNABORTED' || axiosError.code === 'ETIMEDOUT') {
      return new ApiError({
        kind: 'timeout',
        status,
        method,
        url,
        detail,
        message: `The request to ${url} timed out.`,
      })
    }

    if (status === null) {
      return new ApiError({
        kind: 'network',
        status: null,
        method,
        url,
        detail,
        message: `Cannot reach the Clash API at ${url}. Check the API address and that the backend is running.`,
      })
    }

    if (status === 401 || status === 403) {
      return new ApiError({
        kind: 'unauthorized',
        status,
        method,
        url,
        detail,
        message: 'Unauthorized — the API secret is missing or incorrect.',
      })
    }

    if (status === 404) {
      return new ApiError({
        kind: 'not-found',
        status,
        method,
        url,
        detail,
        message: `The endpoint ${url} is not available on this backend.`,
      })
    }

    if (status >= 500) {
      return new ApiError({
        kind: 'server',
        status,
        method,
        url,
        detail,
        message: detail ?? `The backend returned ${status} for ${url}.`,
      })
    }

    if (status >= 400) {
      return new ApiError({
        kind: 'bad-request',
        status,
        method,
        url,
        detail,
        message: detail ?? `The request to ${url} was rejected (${status}).`,
      })
    }

    return new ApiError({
      kind: 'unknown',
      status,
      method,
      url,
      detail,
      message: axiosError.message,
    })
  }

  return new ApiError({
    kind: 'unknown',
    status: null,
    method,
    url,
    message: messageOf(error),
  })
}

/** Perform a request and normalize every outcome into an `ApiResult`. */
export async function apiRequest<T>(config: AxiosRequestConfig): Promise<ApiResult<T>> {
  try {
    const response = await http.request<T>(config)
    return apiOk(response.data)
  } catch (error) {
    return apiFail(toApiError(error, config))
  }
}

/**
 * Perform a request whose body is raw text (e.g. a YAML preview that may be
 * returned as `text/plain` or wrapped in a JSON envelope).
 */
export async function apiTextRequest(
  config: AxiosRequestConfig,
): Promise<ApiResult<{ text: string; json: unknown }>> {
  try {
    const response = await http.request<unknown>({ ...config, responseType: 'text' })
    const raw = response.data
    if (typeof raw === 'string') {
      let json: unknown = null
      const trimmed = raw.trim()
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        try {
          json = JSON.parse(trimmed)
        } catch {
          json = null
        }
      }
      return apiOk({ text: raw, json })
    }
    return apiOk({ text: raw === null || raw === undefined ? '' : String(raw), json: raw })
  } catch (error) {
    return apiFail(toApiError(error, config))
  }
}

export function apiGet<T>(url: string, config?: AxiosRequestConfig): Promise<ApiResult<T>> {
  return apiRequest<T>({ ...config, method: 'get', url })
}

export function apiPost<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<ApiResult<T>> {
  return apiRequest<T>({ ...config, method: 'post', url, data })
}

export function apiPut<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<ApiResult<T>> {
  return apiRequest<T>({ ...config, method: 'put', url, data })
}

export function apiPatch<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<ApiResult<T>> {
  return apiRequest<T>({ ...config, method: 'patch', url, data })
}

export function apiDelete<T>(url: string, config?: AxiosRequestConfig): Promise<ApiResult<T>> {
  return apiRequest<T>({ ...config, method: 'delete', url })
}

/** URL-encode a proxy / connection / provider name for use in a path. */
export function encodeName(name: string): string {
  return encodeURIComponent(name)
}
