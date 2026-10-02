<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  Cpu,
  Delete,
  Download,
  Link,
  Refresh,
  SwitchButton,
  Upload,
} from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'

import MemoryChart from '@/components/charts/MemoryChart.vue'
import TrafficChart from '@/components/charts/TrafficChart.vue'
import EmptyState from '@/components/EmptyState.vue'
import ErrorState from '@/components/ErrorState.vue'
import ModeSwitcher from '@/components/ModeSwitcher.vue'
import NodeIcon from '@/components/NodeIcon.vue'
import StatCard from '@/components/StatCard.vue'
import StatusPill from '@/components/StatusPill.vue'
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

const busy = ref<string>('')

const memoryHint = computed<string>(() => {
  if (traffic.memoryLimit > 0) return `limit ${formatBytes(traffic.memoryLimit)}`
  return `${traffic.sampleCount} samples`
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
    ElMessage.success('Fake-IP cache flushed')
  } else if (result.error.isMissing) {
    ElMessage.warning('This core does not expose POST /cache/fakeip/flush')
  } else {
    ElMessage.error(result.error.message)
  }
}

async function restartCore(): Promise<void> {
  try {
    await ElMessageBox.confirm(
      'Restart the Clash core process? Active connections will be dropped.',
      'Restart core',
      { type: 'warning', confirmButtonText: 'Restart', cancelButtonText: 'Cancel' },
    )
  } catch {
    return
  }

  busy.value = 'restart'
  const result = await config.restartCore()
  busy.value = ''
  if (result.ok) {
    ElMessage.success('Restart requested')
  } else if (result.error.isMissing) {
    ElMessage.warning('This core does not expose POST /restart (embed mode omits it)')
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
        <h2 class="app-page__title">Overview</h2>
        <p class="app-page__subtitle">
          Live throughput, memory and the current routing mode.
        </p>
      </div>
      <StatusPill
        :online="config.online"
        :label="config.unauthorized ? 'Secret required' : undefined"
      />
    </div>

    <section class="stat-grid">
      <StatCard
        label="Upload"
        tone="up"
        :value="formatRate(traffic.currentUp)"
        :hint="`peak ${formatRate(traffic.peakUp)}`"
      >
        <template #icon><el-icon><Upload /></el-icon></template>
      </StatCard>

      <StatCard
        label="Download"
        tone="down"
        :value="formatRate(traffic.currentDown)"
        :hint="`peak ${formatRate(traffic.peakDown)}`"
      >
        <template #icon><el-icon><Download /></el-icon></template>
      </StatCard>

      <StatCard
        label="Upload total"
        :value="formatBytes(connections.uploadTotal)"
        hint="since the core started"
      >
        <template #icon><el-icon><Upload /></el-icon></template>
      </StatCard>

      <StatCard
        label="Download total"
        :value="formatBytes(connections.downloadTotal)"
        hint="since the core started"
      >
        <template #icon><el-icon><Download /></el-icon></template>
      </StatCard>

      <StatCard
        label="Active connections"
        tone="accent"
        :value="String(connections.activeCount)"
        :hint="`${connections.closedCount} closed this session`"
      >
        <template #icon><el-icon><Link /></el-icon></template>
      </StatCard>

      <StatCard label="Memory in use" tone="memory" :value="memoryValue" :hint="memoryHint">
        <template #icon><el-icon><Cpu /></el-icon></template>
      </StatCard>
    </section>

    <section class="app-panel app-panel--pad chart-panel">
      <header class="panel-head">
        <h3 class="app-section-title">Traffic</h3>
        <span class="text-faint panel-head__note">
          {{ traffic.sampleCount }} samples · 1 Hz · 2.5 min window
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
          <h3 class="app-section-title">Memory</h3>
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
          <h3 class="app-section-title">Mode</h3>
          <span class="text-faint panel-head__note">{{ config.versionLabel }}</span>
        </header>
        <ModeSwitcher
          :mode="config.mode"
          :loading="config.saving"
          @change="onModeChange"
        />

        <h3 class="app-section-title mt-16">Quick proxy</h3>
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
              aria-label="Test this group"
              :title="`Test this group against ${quickProbeUrl}`"
              @click="testSelected"
            />
          </div>
          <p class="text-faint quick-note">
            Group <strong>{{ quickGroup.name }}</strong>
            ({{ quickGroup.type }})<template v-if="!quickSelectable">
              — read-only, the core picks the member automatically.</template>
          </p>
        </template>
        <EmptyState
          v-else
          title="No proxy groups"
          description="The core has not reported any proxy groups yet."
        >
          <template #actions>
            <el-button :icon="Refresh" :loading="busy === 'proxies'" @click="refreshProxies">
              Load proxies
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

        <h3 class="app-section-title mt-16">Actions</h3>
        <div class="action-row">
          <el-button
            :icon="Delete"
            :loading="busy === 'fakeip'"
            @click="flushFakeIp"
          >
            Flush fake-IP
          </el-button>
          <el-button
            :icon="SwitchButton"
            :loading="busy === 'restart'"
            @click="restartCore"
          >
            Restart core
          </el-button>
        </div>
        <p class="text-faint quick-note">
          Both actions are core-dependent: a stock build may not mount
          <code>POST /restart</code>, in which case the dashboard says so instead of failing
          silently.
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
