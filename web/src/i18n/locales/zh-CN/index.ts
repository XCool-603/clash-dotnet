import type { Catalogue } from '../en'

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
 * The Chinese catalogue.
 *
 * Typed as `Catalogue`, so it must carry exactly the same keys as English: a
 * missing translation is a compile error, and a stray key that no longer exists
 * in English is one too.
 */
export const zhCN: Catalogue = {
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
