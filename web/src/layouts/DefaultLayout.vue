<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'
import type { Component } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import {
  Connection,
  Document,
  Expand,
  Files,
  Fold,
  Guide,
  Link,
  Moon,
  Odometer,
  Setting,
  Sunny,
} from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'

import ModeSwitcher from '@/components/ModeSwitcher.vue'
import StatusPill from '@/components/StatusPill.vue'
import { useMemoryStream } from '@/composables/useMemoryStream'
import { useTrafficStream } from '@/composables/useTrafficStream'
import { CONNECTIONS_IDLE_INTERVAL, useConnectionsStore } from '@/stores/connections'
import { useConfigStore } from '@/stores/config'
import { useSettingsStore } from '@/stores/settings'
import type { ClashMode } from '@/types'

interface NavItem {
  to: string
  label: string
  icon: Component
}

const settings = useSettingsStore()
const config = useConfigStore()
const connections = useConnectionsStore()
const route = useRoute()

const navItems: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: Odometer },
  { to: '/proxies', label: 'Proxies', icon: Connection },
  { to: '/profiles', label: 'Profiles', icon: Files },
  { to: '/connections', label: 'Connections', icon: Link },
  { to: '/rules', label: 'Rules', icon: Guide },
  { to: '/logs', label: 'Logs', icon: Document },
  { to: '/settings', label: 'Settings', icon: Setting },
]

const collapsed = computed<boolean>(() => settings.sidebarCollapsed)
const themeIcon = computed<Component>(() => (settings.theme === 'dark' ? Sunny : Moon))
const themeLabel = computed<string>(() =>
  settings.theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme',
)
const pageTitle = computed<string>(() => {
  const title = route.meta.title
  return typeof title === 'string' && title.length > 0 ? title : 'Clash'
})
const coreLabel = computed<string>(() => (config.hasMeta ? 'mihomo' : 'core'))
const statusLabel = computed<string>(() => {
  if (config.unauthorized) return 'Secret required'
  if (config.online) return 'Connected'
  return 'Disconnected'
})

/**
 * The traffic and memory sockets are owned here, once, for the whole session:
 * they feed the dashboard, the shell counters and every stat card, so opening
 * a second socket from a page would double the traffic for no benefit
 * ("one owner per socket").
 */
useTrafficStream()
useMemoryStream()

onMounted(() => {
  // Keep the active-connection count warm on every page; the connections view
  // raises this to 1 Hz while it is open.
  connections.startPolling(CONNECTIONS_IDLE_INTERVAL)
})

onUnmounted(() => {
  connections.stopPolling()
})

async function onModeChange(mode: ClashMode): Promise<void> {
  const result = await config.setMode(mode)
  if (!result.ok) ElMessage.error(result.error.message)
}
</script>

<template>
  <div class="layout" :class="{ 'is-collapsed': collapsed }">
    <aside class="layout__sidebar">
      <div class="brand">
        <span class="brand__mark">C</span>
        <span v-if="!collapsed" class="brand__text">
          <strong>Clash</strong>
          <small>dashboard</small>
        </span>
      </div>

      <nav class="nav">
        <RouterLink
          v-for="item in navItems"
          :key="item.to"
          :to="item.to"
          class="nav__item"
          :title="collapsed ? item.label : undefined"
        >
          <el-icon class="nav__icon"><component :is="item.icon" /></el-icon>
          <span v-if="!collapsed" class="nav__label">{{ item.label }}</span>
        </RouterLink>
      </nav>

      <div class="sidebar-footer">
        <StatusPill :online="config.online" :label="statusLabel" :pulse="!collapsed" />
        <ModeSwitcher
          v-if="!collapsed"
          :mode="config.mode"
          :loading="config.saving"
          size="small"
          @change="onModeChange"
        />
      </div>
    </aside>

    <div class="layout__main">
      <header class="topbar">
        <el-button
          class="topbar__collapse"
          text
          :icon="collapsed ? Expand : Fold"
          :aria-label="collapsed ? 'Expand sidebar' : 'Collapse sidebar'"
          @click="settings.toggleSidebar()"
        />
        <h1 class="topbar__title">{{ pageTitle }}</h1>

        <div class="topbar__meta">
          <el-tooltip :content="`Core version: ${config.versionLabel}`" placement="bottom">
            <el-tag class="mono" size="small" type="info" effect="plain">
              {{ config.versionLabel }}
            </el-tag>
          </el-tooltip>
          <el-tooltip
            :content="
              config.hasMeta
                ? 'MetaCubeX (mihomo) core — profiles and rule toggles are available'
                : 'Stock core — profiles and per-rule toggles are not available'
            "
            placement="bottom"
          >
            <el-tag size="small" :type="config.hasMeta ? 'success' : 'warning'" effect="plain">
              {{ coreLabel }}
            </el-tag>
          </el-tooltip>
          <el-button
            text
            :icon="themeIcon"
            :aria-label="themeLabel"
            :title="themeLabel"
            @click="settings.toggleTheme()"
          />
        </div>
      </header>

      <main class="layout__content">
        <slot />
      </main>
    </div>
  </div>
</template>

<style scoped lang="scss">
.layout {
  display: flex;
  height: 100%;
  min-height: 0;
  background: var(--app-bg);
}

.layout__sidebar {
  flex: none;
  width: var(--app-sidebar-width);
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px 10px;
  background: var(--app-surface);
  border-right: 1px solid var(--app-border);
  transition: width 0.16s ease;
  overflow: hidden;
}

.layout.is-collapsed .layout__sidebar {
  width: var(--app-sidebar-width-collapsed);
  align-items: center;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 4px 6px 10px;
  border-bottom: 1px solid var(--app-border);
  width: 100%;
}

.brand__mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  flex: none;
  border-radius: 8px;
  background: var(--app-accent);
  color: #fff;
  font-weight: 700;
}

.brand__text {
  display: flex;
  flex-direction: column;
  line-height: 1.1;
  min-width: 0;

  strong {
    font-size: 14px;
  }

  small {
    font-size: 11px;
    color: var(--app-text-faint);
  }
}

.nav {
  display: flex;
  flex-direction: column;
  gap: 2px;
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
  width: 100%;
}

.nav__item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: 8px;
  color: var(--app-text-muted);
  font-size: 13px;
  font-weight: 550;
  white-space: nowrap;

  &:hover {
    background: var(--app-surface-2);
    color: var(--app-text);
  }

  &.router-link-exact-active {
    background: var(--app-accent-soft);
    color: var(--app-accent);
  }
}

.layout.is-collapsed .nav__item {
  justify-content: center;
  padding: 8px;
}

.nav__icon {
  font-size: 16px;
  flex: none;
}

.sidebar-footer {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding-top: 10px;
  border-top: 1px solid var(--app-border);
  width: 100%;
  align-items: flex-start;
}

.layout__main {
  flex: 1 1 auto;
  min-width: 0;
  display: flex;
  flex-direction: column;
  min-height: 0;
}

.topbar {
  flex: none;
  height: var(--app-header-height);
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 16px;
  background: var(--app-surface);
  border-bottom: 1px solid var(--app-border);
}

.topbar__title {
  font-size: 16px;
  font-weight: 650;
  margin: 0;
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.topbar__meta {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: none;
}

.layout__content {
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
}

@media (max-width: 720px) {
  .layout__sidebar {
    width: var(--app-sidebar-width-collapsed);
    align-items: center;
  }
}
</style>
