<script setup lang="ts">
import { computed, defineAsyncComponent, onMounted, ref } from 'vue'
import {
  Cpu,
  Delete,
  Download,
  Link,
  Refresh,
  SwitchButton,
  Upload,
} from '@element-plus/icons-vue'

// Loaded after the first paint.
//
// The charts are the only thing in the dashboard that needs ECharts, which is
// by far the largest dependency in the bundle and sits below the stat cards
// rather than beside them. Importing them statically made every visit wait for
// the charting library before rendering anything at all; this way the cards and
// the mode switcher appear first and the charts fill in a moment later.
const MemoryChart = defineAsyncComponent(() => import('@/components/charts/MemoryChart.vue'))
const TrafficChart = defineAsyncComponent(() => import('@/components/charts/TrafficChart.vue'))
import EmptyState from '@/components/EmptyState.vue'
import ErrorState from '@/components/ErrorState.vue'
import ModeSwitcher from '@/components/ModeSwitcher.vue'
import NodeIcon from '@/components/NodeIcon.vue'
import StatCard from '@/components/StatCard.vue'
import StatusPill from '@/components/StatusPill.vue'
import { useI18n } from '@/i18n'
import { useConfigStore } from '@/stores/config'
import { useConnectionsStore } from '@/stores/connections'
import { useProxiesStore } from '@/stores/proxies'
import { useTrafficStore } from '@/stores/traffic'
import type { ClashMode } from '@/types'
import { delayStateOf } from '@/utils/delay'
import { formatBytes, formatRate } from '@/utils/format'

const traffic = useTrafficStore()
const connections = useConnectionsStore()
const proxies = useProxiesStore()
const config = useConfigStore()
const { t } = useI18n()

const busy = ref<string>('')

const memoryHint = computed<string>(() => {
  if (traffic.memoryLimit > 0) {
    return t('dashboard.memoryLimit', { size: formatBytes(traffic.memoryLimit) })
  }
  return t('dashboard.sampleCount', { count: traffic.sampleCount })
})

const memoryValue = computed<string>(() =>
  traffic.memoryInuse > 0 ? formatBytes(traffic.memoryInuse) : '—',
)

/* ---- quick proxy selector ---------------------------------------- */

const quickGroup = computed(() => proxies.primaryGroup)
const quickMembers = computed(() => proxies.membersOf(quickGroup.value))
const quickProbeUrl = computed<string>(() => proxies.probeUrlOf(quickGroup.value?.name ?? null))
const quickSelectable = computed<boolean>(() => proxies.isSelectable(quickGroup.value))

const quickSelection = computed<string>({
  get: () => quickGroup.value?.now ?? '',
  set: (value: string) => {
    if (!value) return
    void applySelection(value)
  },
})

const selectedNodeInfo = computed(() => {
  const group = quickGroup.value
  if (!group) return null
  const current = group.now ?? group.all?.[0] ?? ''
  const node = current ? proxies.getProxy(current) : undefined
  const delay = current ? proxies.delayOf(current) : null
  return {
    name: current,
    icon: node?.icon ?? '',
    delay,
    state: delayStateOf(delay, {
      testing: current ? proxies.testing[current] === true : false,
      alive: node?.alive,
    }),
  }
})

async function applySelection(name: string): Promise<void> {
  const group = quickGroup.value
  if (!group) return
  const result = await proxies.select(group.name, name)
  if (!result.ok) ElMessage.error(result.error.message)
}

async function testSelected(): Promise<void> {
  const group = quickGroup.value
  if (!group) return
  busy.value = 'test'
  await proxies.testGroup(group.name)
  busy.value = ''
}

/* ---- actions ------------------------------------------------------ */

async function flushFakeIp(): Promise<void> {
  busy.value = 'fakeip'
  const result = await config.flushFakeIp()
  busy.value = ''
  if (result.ok) {
    ElMessage.success(t('dashboard.fakeIpFlushed'))
  } else if (result.error.isMissing) {
    ElMessage.warning(t('dashboard.fakeIpUnsupported'))
  } else {
    ElMessage.error(result.error.message)
  }
}

async function restartCore(): Promise<void> {
  try {
    await ElMessageBox.confirm(
      t('dashboard.restartConfirm'),
      t('dashboard.restartCore'),
      {
        type: 'warning',
        confirmButtonText: t('dashboard.restart'),
        cancelButtonText: t('action.cancel'),
      },
    )
  } catch {
    return
  }

  busy.value = 'restart'
  const result = await config.restartCore()
  busy.value = ''
  if (result.ok) {
    ElMessage.success(t('dashboard.restartRequested'))
  } else if (result.error.isMissing) {
    ElMessage.warning(t('dashboard.restartUnsupported'))
  } else {
    ElMessage.error(result.error.message)
  }
}

async function onModeChange(mode: ClashMode): Promise<void> {
  const result = await config.setMode(mode)
  if (!result.ok) ElMessage.error(result.error.message)
}

async function refreshProxies(): Promise<void> {
  busy.value = 'proxies'
  await proxies.refresh()
  busy.value = ''
}

onMounted(() => {
  if (!proxies.hasData) void proxies.refresh()
})
</script>

<template>
  <div class="app-page">
    <div class="app-page__head">
      <div>
        <h2 class="app-page__title">{{ t('nav.dashboard') }}</h2>
        <p class="app-page__subtitle">{{ t('dashboard.subtitle') }}</p>
      </div>
      <StatusPill
        :online="config.online"
        :label="config.unauthorized ? t('status.secretRequired') : undefined"
      />
    </div>

    <section class="stat-grid">
      <StatCard
        :label="t('dashboard.upload')"
        tone="up"
        :value="formatRate(traffic.currentUp)"
        :hint="t('dashboard.peak', { rate: formatRate(traffic.peakUp) })"
      >
        <template #icon><el-icon><Upload /></el-icon></template>
      </StatCard>

      <StatCard
        :label="t('dashboard.download')"
        tone="down"
        :value="formatRate(traffic.currentDown)"
        :hint="t('dashboard.peak', { rate: formatRate(traffic.peakDown) })"
      >
        <template #icon><el-icon><Download /></el-icon></template>
      </StatCard>

      <StatCard
        :label="t('dashboard.uploadTotal')"
        :value="formatBytes(connections.uploadTotal)"
        :hint="t('dashboard.sinceCoreStart')"
      >
        <template #icon><el-icon><Upload /></el-icon></template>
      </StatCard>

      <StatCard
        :label="t('dashboard.downloadTotal')"
        :value="formatBytes(connections.downloadTotal)"
        :hint="t('dashboard.sinceCoreStart')"
      >
        <template #icon><el-icon><Download /></el-icon></template>
      </StatCard>

      <StatCard
        :label="t('dashboard.activeConnections')"
        tone="accent"
        :value="String(connections.activeCount)"
        :hint="t('dashboard.closedThisSession', { count: connections.closedCount })"
      >
        <template #icon><el-icon><Link /></el-icon></template>
      </StatCard>

      <StatCard
        :label="t('dashboard.memoryInUse')"
        tone="memory"
        :value="memoryValue"
        :hint="memoryHint"
      >
        <template #icon><el-icon><Cpu /></el-icon></template>
      </StatCard>
    </section>

    <section class="app-panel app-panel--pad chart-panel">
      <header class="panel-head">
        <h3 class="app-section-title">{{ t('dashboard.traffic') }}</h3>
        <span class="text-faint panel-head__note">
          {{ t('dashboard.sampleCount', { count: traffic.sampleCount }) }} ·
          {{ t('dashboard.trafficWindow') }}
        </span>
      </header>
      <TrafficChart
        :labels="traffic.labels"
        :timestamps="traffic.timestamps"
        :down="traffic.downSeries"
        :up="traffic.upSeries"
        :height="280"
      />
    </section>

    <section class="dash-cols">
      <div class="app-panel app-panel--pad">
        <header class="panel-head">
          <h3 class="app-section-title">{{ t('dashboard.memory') }}</h3>
          <span class="text-faint panel-head__note">{{ formatBytes(traffic.memoryInuse) }}</span>
        </header>
        <MemoryChart
          :labels="traffic.memoryLabels"
          :timestamps="traffic.memoryTimestamps"
          :values="traffic.memorySeries"
          :limit="traffic.memoryLimit"
          :height="220"
        />
      </div>

      <div class="app-panel app-panel--pad side-panel">
        <header class="panel-head">
          <h3 class="app-section-title">{{ t('mode.label') }}</h3>
          <span class="text-faint panel-head__note">{{ config.versionLabel }}</span>
        </header>
        <ModeSwitcher
          :mode="config.mode"
          :loading="config.saving"
          @change="onModeChange"
        />

        <h3 class="app-section-title mt-16">{{ t('dashboard.quickProxy') }}</h3>
        <template v-if="quickGroup && quickMembers.length > 0">
          <div class="quick-row">
            <NodeIcon
              :name="selectedNodeInfo?.name ?? ''"
              :icon="selectedNodeInfo?.icon ?? ''"
              :size="22"
            />
            <el-select
              v-model="quickSelection"
              class="grow"
              size="default"
              filterable
              :disabled="!quickSelectable"
              :placeholder="quickGroup.name"
            >
              <el-option
                v-for="node in quickMembers"
                :key="node.name"
                :label="node.name"
                :value="node.name"
              />
            </el-select>
            <el-button
              :icon="Refresh"
              :loading="busy === 'test'"
              :aria-label="t('dashboard.testGroup')"
              :title="t('dashboard.testGroupTitle', { url: quickProbeUrl })"
              @click="testSelected"
            />
          </div>
          <p class="text-faint quick-note">
            {{ t('dashboard.groupLabel') }}
            <strong>{{ quickGroup.name }}</strong>
            ({{ quickGroup.type }})<template v-if="!quickSelectable"> {{ t('dashboard.groupReadOnly') }}</template>
          </p>
        </template>
        <EmptyState
          v-else
          :title="t('dashboard.emptyTitle')"
          :description="t('dashboard.emptyDescription')"
        >
          <template #actions>
            <el-button :icon="Refresh" :loading="busy === 'proxies'" @click="refreshProxies">
              {{ t('dashboard.loadProxies') }}
            </el-button>
          </template>
        </EmptyState>

        <ErrorState
          v-if="proxies.error"
          class="mt-12"
          inline
          :error="proxies.error"
          @retry="refreshProxies"
        />

        <h3 class="app-section-title mt-16">{{ t('dashboard.actions') }}</h3>
        <div class="action-row">
          <el-button
            :icon="Delete"
            :loading="busy === 'fakeip'"
            @click="flushFakeIp"
          >
            {{ t('dashboard.flushFakeIp') }}
          </el-button>
          <el-button
            :icon="SwitchButton"
            :loading="busy === 'restart'"
            @click="restartCore"
          >
            {{ t('dashboard.restartCore') }}
          </el-button>
        </div>
        <p class="text-faint quick-note">
          {{ t('dashboard.actionsNoteBefore') }}
          <code>POST /restart</code>{{ t('dashboard.actionsNoteAfter') }}
        </p>
      </div>
    </section>
  </div>
</template>

<style scoped lang="scss">
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}

.chart-panel {
  margin-bottom: 16px;
}

.dash-cols {
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(280px, 1fr);
  gap: 16px;
  align-items: start;
}

@media (max-width: 1080px) {
  .dash-cols {
    grid-template-columns: minmax(0, 1fr);
  }
}

.panel-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 8px;
}

.panel-head__note {
  font-size: 12px;
}

.side-panel {
  display: flex;
  flex-direction: column;
}

.quick-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 8px;
}

.quick-note {
  font-size: 12px;
  margin: 8px 0 0;
  line-height: 1.45;
}

.action-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 8px;
}

code {
  font-family: 'JetBrains Mono', Consolas, monospace;
  font-size: 11.5px;
  background: var(--app-surface-3);
  padding: 1px 4px;
  border-radius: 4px;
}
</style>
