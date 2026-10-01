import { computed, ref } from 'vue'
import { defineStore } from 'pinia'

import { profilesApi } from '@/api/profiles'
import type { ApiError, ApiResult } from '@/api/client'
import type {
  CreateProfileInput,
  ParsedSubscription,
  Profile,
  ProfilePreview,
  UpdateProfileInput,
} from '@/types'

/**
 * Profile / subscription manager.
 *
 * The `/profiles` endpoints are app-level additions, so a 404 flips
 * `available` to false and the UI shows an empty state instead of an error.
 */
export const useProfilesStore = defineStore('profiles', () => {
  const profiles = ref<Profile[]>([])
  const available = ref(true)
  const loading = ref(false)
  const error = ref<ApiError | null>(null)

  const selectedId = ref<string | null>(null)
  const busyId = ref<string | null>(null)
  const importing = ref(false)
  const saving = ref(false)
  const lastUpdated = ref(0)

  const preview = ref<ProfilePreview | null>(null)
  const previewLoading = ref(false)
  const previewError = ref<ApiError | null>(null)

  const parsedSubscription = ref<ParsedSubscription | null>(null)
  const parseError = ref<ApiError | null>(null)
  const parsing = ref(false)

  const selectedProfile = computed<Profile | null>(() => {
    const active = profiles.value.find((profile) => profile.selected)
    if (active) return active
    if (selectedId.value) {
      return profiles.value.find((profile) => profile.id === selectedId.value) ?? null
    }
    return profiles.value[0] ?? null
  })

  const hasProfiles = computed<boolean>(() => profiles.value.length > 0)

  const remoteProfiles = computed<Profile[]>(() =>
    profiles.value.filter((profile) => profile.type === 'remote'),
  )

  function applyFailure(failure: ApiError): void {
    if (failure.isMissing) {
      // The backend does not expose the profile API at all.
      available.value = false
      error.value = null
      return
    }
    error.value = failure
  }

  async function load(): Promise<void> {
    loading.value = true
    const result = await profilesApi.list()
    loading.value = false

    if (result.ok) {
      profiles.value = result.data.profiles ?? []
      const active = profiles.value.find((profile) => profile.selected)
      selectedId.value = active?.id ?? profiles.value[0]?.id ?? null
      available.value = true
      error.value = null
      lastUpdated.value = Date.now()
    } else {
      applyFailure(result.error)
    }
  }

  async function create(input: CreateProfileInput): Promise<ApiResult<Profile>> {
    saving.value = true
    const result = await profilesApi.create(input)
    saving.value = false
    if (result.ok) {
      await load()
      if (result.data?.id) selectedId.value = result.data.id
    } else {
      applyFailure(result.error)
    }
    return result
  }

  async function update(id: string, input: UpdateProfileInput): Promise<ApiResult<Profile>> {
    saving.value = true
    const result = await profilesApi.update(id, input)
    saving.value = false
    if (result.ok) {
      await load()
    } else {
      applyFailure(result.error)
    }
    return result
  }

  async function remove(id: string): Promise<ApiResult<unknown>> {
    busyId.value = id
    const result = await profilesApi.remove(id)
    busyId.value = null
    if (result.ok) {
      if (selectedId.value === id) selectedId.value = null
      if (preview.value?.id === id) preview.value = null
      await load()
    } else {
      applyFailure(result.error)
    }
    return result
  }

  async function select(id: string): Promise<ApiResult<unknown>> {
    busyId.value = id
    const result = await profilesApi.select(id)
    busyId.value = null
    if (result.ok) {
      selectedId.value = id
      profiles.value = profiles.value.map((profile) => ({ ...profile, selected: profile.id === id }))
      await load()
    } else {
      applyFailure(result.error)
    }
    return result
  }

  async function updateRemote(id: string): Promise<ApiResult<Profile>> {
    busyId.value = id
    const result = await profilesApi.updateRemote(id)
    busyId.value = null
    if (result.ok) {
      await load()
    } else {
      applyFailure(result.error)
    }
    return result
  }

  async function importUrl(url: string, name?: string): Promise<ApiResult<Profile>> {
    importing.value = true
    const result = await profilesApi.importUrl(url, name)
    importing.value = false
    if (result.ok) {
      await load()
      if (result.data?.id) selectedId.value = result.data.id
    } else {
      applyFailure(result.error)
    }
    return result
  }

  async function loadPreview(id: string): Promise<ApiResult<ProfilePreview>> {
    previewLoading.value = true
    const result = await profilesApi.preview(id)
    previewLoading.value = false
    if (result.ok) {
      preview.value = result.data
      previewError.value = null
    } else {
      previewError.value = result.error
    }
    return result
  }

  function closePreview(): void {
    preview.value = null
    previewError.value = null
  }

  async function saveContent(id: string, content: string): Promise<ApiResult<unknown>> {
    saving.value = true
    const result = await profilesApi.saveContent(id, content)
    saving.value = false
    if (result.ok) {
      await load()
      if (preview.value?.id === id) preview.value = { ...preview.value, content }
    } else {
      applyFailure(result.error)
    }
    return result
  }

  async function parseSubscription(url: string): Promise<ApiResult<ParsedSubscription>> {
    parsing.value = true
    const result = await profilesApi.parseSubscription(url)
    parsing.value = false
    if (result.ok) {
      parsedSubscription.value = result.data
      parseError.value = null
    } else {
      parseError.value = result.error
    }
    return result
  }

  function clearParse(): void {
    parsedSubscription.value = null
    parseError.value = null
  }

  return {
    // state
    profiles,
    available,
    loading,
    error,
    selectedId,
    busyId,
    importing,
    saving,
    lastUpdated,
    preview,
    previewLoading,
    previewError,
    parsedSubscription,
    parseError,
    parsing,
    // getters
    selectedProfile,
    hasProfiles,
    remoteProfiles,
    // actions
    load,
    create,
    update,
    remove,
    select,
    updateRemote,
    importUrl,
    loadPreview,
    closePreview,
    saveContent,
    parseSubscription,
    clearParse,
  }
})
