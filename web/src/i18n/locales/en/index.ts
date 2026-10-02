import { common } from './common'
import { connections } from './connections'
import { dashboard } from './dashboard'
import { logs } from './logs'
import { profiles } from './profiles'
import { proxies } from './proxies'
import { rules } from './rules'
import { settings } from './settings'
import { shell } from './shell'

/**
 * The English catalogue. Its inferred type is the contract every other locale
 * must satisfy — see `zh-CN/index.ts`.
 *
 * Each page owns one fragment file, so a page's strings can be edited without
 * touching the shared vocabulary or another page's keys.
 */
export const en = {
  ...common,
  ...shell,
  ...dashboard,
  ...proxies,
  ...profiles,
  ...connections,
  ...rules,
  ...logs,
  ...settings,
}

/** The shape every other locale must satisfy, key for key. */
export type Catalogue = typeof en
