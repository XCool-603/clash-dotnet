import { createRouter, createWebHashHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'

import { t, type MessageKey } from '@/i18n'
import DashboardView from '@/views/DashboardView.vue'

/**
 * Hash history on purpose: the .NET host serves this bundle straight out of
 * `wwwroot` behind a static-file fallback, and a hash router is immune to
 * base-path and rewrite surprises. Every one of the reference dashboards
 * (yacd, metacubexd, clash-dashboard) does the same.
 *
 * Routes carry a message *key* rather than a title, so the shell and the
 * document title follow the language switcher.
 */
export const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'dashboard',
    // The dashboard is the landing page, so it is the one eager route.
    component: DashboardView,
    meta: { titleKey: 'nav.dashboard' },
  },
  {
    path: '/proxies',
    name: 'proxies',
    component: () => import('@/views/ProxiesView.vue'),
    meta: { titleKey: 'nav.proxies' },
  },
  {
    path: '/profiles',
    name: 'profiles',
    component: () => import('@/views/ProfilesView.vue'),
    meta: { titleKey: 'nav.profiles' },
  },
  {
    path: '/connections',
    name: 'connections',
    component: () => import('@/views/ConnectionsView.vue'),
    meta: { titleKey: 'nav.connections' },
  },
  {
    path: '/rules',
    name: 'rules',
    component: () => import('@/views/RulesView.vue'),
    meta: { titleKey: 'nav.rules' },
  },
  {
    path: '/logs',
    name: 'logs',
    component: () => import('@/views/LogsView.vue'),
    meta: { titleKey: 'nav.logs' },
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('@/views/SettingsView.vue'),
    meta: { titleKey: 'nav.settings' },
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    redirect: '/',
  },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 }),
})

/** The message key a route declares for its title, when it declares one. */
export function titleKeyOf(meta: Record<string, unknown>): MessageKey | null {
  const key = meta.titleKey
  return typeof key === 'string' ? (key as MessageKey) : null
}

router.afterEach((to) => {
  const key = titleKeyOf(to.meta)
  document.title = key ? `${t(key)} · Clash Dashboard` : 'Clash Dashboard'
})

export default router
