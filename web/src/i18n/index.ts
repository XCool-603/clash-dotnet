import { computed, ref } from 'vue'

import { en } from './locales/en'
import { zhCN } from './locales/zh-CN'

/**
 * A message is either one string or an English-style plural pair. The plural
 * form is only consulted when the caller passes a `count`, so a language that
 * does not inflect (Chinese) simply repeats the same string in both slots.
 */
export type Message = string | { one: string; other: string }

/** Every message key, derived from the English catalogue. */
export type MessageKey = keyof typeof en

export type Locale = 'en' | 'zh-CN'

export interface LocaleInfo {
  value: Locale
  /** Shown in the switcher, in the language's own script. */
  label: string
  /** BCP 47 tag written to <html lang>. */
  htmlLang: string
}

export const LOCALES: readonly LocaleInfo[] = [
  { value: 'en', label: 'English', htmlLang: 'en' },
  { value: 'zh-CN', label: '简体中文', htmlLang: 'zh-CN' },
]

/**
 * The catalogues are keyed identically: `zh-CN` is declared as `typeof en`, so a
 * missing or misspelled key in the Chinese catalogue is a compile error rather
 * than a silent fallback to English at runtime.
 */
const catalogues: Record<Locale, Record<MessageKey, Message>> = {
  en,
  'zh-CN': zhCN,
}

const current = ref<Locale>('en')

function isLocale(value: unknown): value is Locale {
  return value === 'en' || value === 'zh-CN'
}

/** The active locale. */
export const locale = computed<Locale>(() => current.value)

/** The active locale's metadata, for the switcher and <html lang>. */
export const localeInfo = computed<LocaleInfo>(
  () => LOCALES.find((entry) => entry.value === current.value) ?? LOCALES[0]!,
)

/**
 * Switches the active locale and mirrors it onto the document, so `:lang()`
 * selectors, spell checkers and screen readers follow the choice.
 */
export function setLocale(next: Locale): void {
  current.value = next
  if (typeof document !== 'undefined') {
    document.documentElement.lang = localeInfo.value.htmlLang
  }
}

/** Restores a persisted choice; ignores anything unrecognised. */
export function initLocale(saved: string | null | undefined): void {
  if (isLocale(saved)) setLocale(saved)
  else setLocale(current.value)
}

function interpolate(message: string, params?: Record<string, string | number>): string {
  if (!params) return message
  return message.replace(/\{(\w+)\}/g, (match, name: string) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match,
  )
}

/**
 * Translates a key. `count` selects the plural form and is also available to the
 * message as `{count}`; any other entry of `params` is substituted by name.
 */
export function t(
  key: MessageKey,
  params?: Record<string, string | number> & { count?: number },
): string {
  const message: Message | undefined = catalogues[current.value][key]
  if (message === undefined) return key

  if (typeof message === 'string') return interpolate(message, params)

  const count = params?.count
  const chosen = count === 1 ? message.one : message.other
  return interpolate(chosen, params)
}

/** The translation function plus the current locale, for use inside setup(). */
export function useI18n(): {
  t: typeof t
  locale: typeof locale
  localeInfo: typeof localeInfo
  setLocale: typeof setLocale
  locales: readonly LocaleInfo[]
} {
  return { t, locale, localeInfo, setLocale, locales: LOCALES }
}
