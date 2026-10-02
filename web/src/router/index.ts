import { createRouter, createWebHashHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'

import DashboardView from '@/views/DashboardView.vue'

/**
 * Hash history on purpose: the .NET host serves this bundle straight out of
 * `wwwroot` behind a static-file fallback, and a hash router is immune to
 * base-path and rewrite surprises. Every one of the reference dashboards
 * (yacd, metacubexd, clash-dashboard) does the same.
 */
export const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'dashboard',
    // The dashboard is the landing page, so it is the one eager route.
    component: DashboardView,
    meta: { title: 'Dashboard' },
  },
  {
    path: '/proxies',
    name: 'proxies',
    component: () => import('@/views/ProxiesView.vue'),
    meta: { title: 'Proxies' },
  },
  {
    path: '/profiles',
    name: 'profiles',
    component: () => import('@/views/ProfilesView.vue'),
    meta: { title: 'Profiles' },
  },
  {
    path: '/connections',
    name: 'connections',
    component: () => import('@/views/ConnectionsView.vue'),
    meta: { title: 'Connections' },
  },
  {
    path: '/rules',
    name: 'rules',
    component: () => import('@/views/RulesView.vue'),
    meta: { title: 'Rules' },
  },
  {
    path: '/logs',
    name: 'logs',
    component: () => import('@/views/LogsView.vue'),
    meta: { title: 'Logs' },
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('@/views/SettingsView.vue'),
    meta: { title: 'Settings' },
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

router.afterEach((to) => {
  const title = to.meta.title
  document.title = typeof title === 'string' && title.length > 0 ? `${title} · Clash Dashboard` : 'Clash Dashboard'
})

export default router
