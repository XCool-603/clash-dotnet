import { apiDelete, apiGet, apiPost, apiPut, apiTextRequest, encodeName } from './client'
import type { ApiResult } from './client'
import type {
  CreateProfileInput,
  ParsedSubscription,
  Profile,
  ProfilePreview,
  ProfilesResponse,
  UpdateProfileInput,
} from '@/types'

/**
 * App-level profile / subscription endpoints. These live beyond stock Clash,
 * so callers must treat a 404 as "feature unavailable" rather than an error.
 */
export const profilesApi = {
  list: (): Promise<ApiResult<ProfilesResponse>> => apiGet<ProfilesResponse>('/profiles'),

  create: (input: CreateProfileInput): Promise<ApiResult<Profile>> =>
    apiPost<Profile>('/profiles', input),

  update: (id: string, input: UpdateProfileInput): Promise<ApiResult<Profile>> =>
    apiPut<Profile>(`/profiles/${encodeName(id)}`, input),

  remove: (id: string): Promise<ApiResult<unknown>> => apiDelete<unknown>(`/profiles/${encodeName(id)}`),

  select: (id: string): Promise<ApiResult<unknown>> =>
    apiPut<unknown>(`/profiles/${encodeName(id)}/select`),

  updateRemote: (id: string): Promise<ApiResult<Profile>> =>
    apiPut<Profile>(`/profiles/${encodeName(id)}/update`),

  importUrl: (url: string, name?: string): Promise<ApiResult<Profile>> =>
    apiPost<Profile>('/profiles/import-url', name ? { url, name } : { url }),

  /**
   * Fetch the raw YAML for a profile. The backend may answer with plain text
   * or with a JSON envelope such as `{ "content": "..." }` — both are handled.
   */
  preview: async (id: string): Promise<ApiResult<ProfilePreview>> => {
    const result = await apiTextRequest({ method: 'get', url: `/profiles/${encodeName(id)}/preview` })
    if (!result.ok) return result

    const { text, json } = result.data
    let content = text
    let name = ''

    if (json && typeof json === 'object') {
      const record = json as Record<string, unknown>
      if (typeof record.content === 'string') content = record.content
      else if (typeof record.yaml === 'string') content = record.yaml
      else if (typeof record.data === 'string') content = record.data
      if (typeof record.name === 'string') name = record.name
    }

    return { ok: true, data: { id, name, content } }
  },

  saveContent: (id: string, content: string): Promise<ApiResult<unknown>> =>
    apiPut<unknown>(`/profiles/${encodeName(id)}/content`, { content }),

  parseSubscription: (url: string): Promise<ApiResult<ParsedSubscription>> =>
    apiPost<ParsedSubscription>('/subscription/parse', { url }),
}

export type ProfilesApi = typeof profilesApi
