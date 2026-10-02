import { computed, ref, watch } from 'vue'
import { defineStore } from 'pinia'

import { setLocale as i18nSetLocale, type Locale } from '@/i18n'
import type { ThemeMode } from '@/types'

function isLocale(value: unknown): value is Locale {
  return value === 'en' || value === 'zh-CN'
}

/**
 * The language to use before the user has ever chosen one: follow the browser.
 * A Chinese Windows reports `zh-CN`, so the dashboard opens in Chinese for the
 * people most likely to want it, and in English everywhere else.
 */
function detectLocale(): Locale {
  if (typeof navigator === 'undefined') return 'en'
  const candidates = navigator.languages?.length ? navigator.languages : [navigator.language]
  return candidates.some((tag) => tag?.toLowerCase().startsWith('zh')) ? 'zh-CN' : 'en'
}

const STORAGE_KEY = 'clash-dashboard:settings'

/** Where the dashboard points by default when nothing has been persisted. */
const DEV_API_BASE = 'http://127.0.0.1:9090'

interface PersistedSettings {
  sameOrigin?: boolean
  apiBaseUrl?: string
  secret?: string
  theme?: ThemeMode
  locale?: string
  sidebarCollapsed?: boolean
}

function readPersisted(): PersistedSettings {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (!raw) return {}
    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object') return {}
    return parsed as PersistedSettings
  } catch {
    return {}
  }
}

function normalizeBase(value: string): string {
  return value.trim().replace(/\/+$/, '')
}

function applyTheme(theme: ThemeMode): void {
  const root = document.documentElement
  root.classList.toggle('dark', theme === 'dark')
  root.dataset.theme = theme
  root.style.colorScheme = theme
}

/**
 * Connection + appearance preferences.
 *
 * The API base URL and secret are the single source of truth for every
 * HTTP call (see `@/api/client`) and every WebSocket URL (see `@/utils/ws`).
 * Both are persisted to `localStorage`.
 */
export const useSettingsStore = defineStore('settings', () => {
  const persisted = readPersisted()

  // Default to same-origin in production builds (the .NET host serves the
  // bundle from wwwroot). In `vite dev` we default to the standalone
  // Clash API so the dashboard is usable without the backend running.
  const sameOrigin = ref<boolean>(persisted.sameOrigin ?? !import.meta.env.DEV)
  const apiBaseUrl = ref<string>(persisted.apiBaseUrl ?? DEV_API_BASE)
  const secret = ref<string>(persisted.secret ?? '')
  const theme = ref<ThemeMode>(persisted.theme === 'light' ? 'light' : 'dark')
  const sidebarCollapsed = ref<boolean>(persisted.sidebarCollapsed ?? false)

  // The i18n module owns the active catalogue; this store only remembers the
  // choice, so a reload comes back in the language the user picked.
  const locale = ref<Locale>(isLocale(persisted.locale) ? persisted.locale : detectLocale())

  /** Effective HTTP base URL — empty string means "same origin". */
  const apiBase = computed<string>(() => (sameOrigin.value ? '' : normalizeBase(apiBaseUrl.value)))

  const hasSecret = computed<boolean>(() => secret.value.trim().length > 0)

  /** Human-readable description of the current target, for the UI. */
  const targetLabel = computed<string>(() => {
    if (sameOrigin.value) return window.location.origin
    return normalizeBase(apiBaseUrl.value) || DEV_API_BASE
  })

  function setSameOrigin(value: boolean): void {
    sameOrigin.value = value
  }

  function setApiBaseUrl(value: string): void {
    apiBaseUrl.value = value
  }

  function setSecret(value: string): void {
    secret.value = value
  }

  function setTheme(value: ThemeMode): void {
    theme.value = value
  }

  function toggleTheme(): void {
    theme.value = theme.value === 'dark' ? 'light' : 'dark'
  }

  /** Switches the interface language and applies it to the i18n module. */
  function setLocale(next: Locale): void {
    locale.value = next
    i18nSetLocale(next)
  }

  function toggleSidebar(): void {
    sidebarCollapsed.value = !sidebarCollapsed.value
  }

  function resetConnection(): void {
    sameOrigin.value = !import.meta.env.DEV
    apiBaseUrl.value = DEV_API_BASE
    secret.value = ''
  }

  watch(
    [sameOrigin, apiBaseUrl, secret, theme, locale, sidebarCollapsed],
    () => {
      const payload: PersistedSettings = {
        sameOrigin: sameOrigin.value,
        apiBaseUrl: apiBaseUrl.value,
        secret: secret.value,
        theme: theme.value,
        locale: locale.value,
        sidebarCollapsed: sidebarCollapsed.value,
      }
      try {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(payload))
      } catch {
        // Storage may be unavailable (private mode / quota) — the app still works.
      }
    },
    { deep: false },
  )

  watch(theme, applyTheme, { immediate: true })

  // Adopt the remembered language for the very first render, before any view
  // reads a message key.
  i18nSetLocale(locale.value)

  return {
    // state
    sameOrigin,
    apiBaseUrl,
    secret,
    theme,
    locale,
    sidebarCollapsed,
    // getters
    apiBase,
    hasSecret,
    targetLabel,
    // actions
    setSameOrigin,
    setApiBaseUrl,
    setSecret,
    setTheme,
    toggleTheme,
    setLocale,
    toggleSidebar,
    resetConnection,
  }
})
