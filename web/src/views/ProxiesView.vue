<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ArrowDown, Loading, Refresh, Search } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'

import DelayBadge from '@/components/DelayBadge.vue'
import EmptyState from '@/components/EmptyState.vue'
import ErrorState from '@/components/ErrorState.vue'
import NodeIcon from '@/components/NodeIcon.vue'
import { useProxiesStore } from '@/stores/proxies'
import { useSettingsStore } from '@/stores/settings'
import type { ProxyProvider } from '@/types'
import { compareDelay, delayStateOf } from '@/utils/delay'
import type { DelayInfo } from '@/utils/delay'
import { formatBytes, formatExpiry, formatRelative } from '@/utils/format'

const proxies = useProxiesStore()
const settings = useSettingsStore()

type SortMode = 'natural' | 'latency'

interface NodeRow {
  /** Position inside the group's own `all` list — the stable tiebreaker. */
  index: number
  name: string
  icon: string
  type: string
  selected: boolean
  testing: boolean
  delayInfo: DelayInfo
}

interface GroupCard {
  name: string
  type: string
  icon: string
  now: string
  testing: boolean
  selectable: boolean
  probeUrl: string
  nodeCount: number
  selectedDelay: number | null
  nodes: NodeRow[]
}

const search = ref('')
const sortMode = ref<SortMode>('natural')
const collapsed = ref<Record<string, boolean>>({})
const testingAll = ref(false)
const busyProvider = ref('')

/** GLOBAL is a container for every other group, so it belongs at the end. */
function orderGroups<T extends { name: string }>(list: T[]): T[] {
  return list.slice().sort((a, b) => {
    if (a.name === 'GLOBAL') return 1
    if (b.name === 'GLOBAL') return -1
    return 0
  })
}

const groupCards = computed<GroupCard[]>(() => {
  const needle = search.value.trim().toLowerCase()
  const cards: GroupCard[] = []

  for (const group of orderGroups(proxies.groups)) {
    const probeUrl = proxies.probeUrlOf(group.name)
    const groupTesting = proxies.testing[group.name] === true
    const names = proxies.memberNames(group)

    const nodes: NodeRow[] = names.map((name, index) => {
      const node = proxies.getProxy(name)
      const testing = groupTesting || proxies.testing[name] === true
      const delay = node ? proxies.delayOf(name) : null
      return {
        index,
        name,
        icon: typeof node?.icon === 'string' ? node.icon : '',
        type: node?.type ?? 'Unknown',
        selected: group.now === name,
        testing,
        delayInfo: delayStateOf(delay, { testing, alive: node?.alive }),
      }
    })

    const filtered = needle.length > 0 ? nodes.filter((node) => node.name.toLowerCase().includes(needle)) : nodes
    if (needle.length > 0 && filtered.length === 0) continue

    if (sortMode.value === 'latency') {
      // State rank first, then the value; the original index keeps the order
      // stable so the grid does not reshuffle while results stream in.
      filtered.sort((a, b) => compareDelay(a.delayInfo, b.delayInfo) || a.index - b.index)
    }

    cards.push({
      name: group.name,
      type: group.type,
      icon: typeof group.icon === 'string' ? group.icon : '',
      now: group.now ?? '',
      testing: groupTesting,
      selectable: proxies.isSelectable(group),
      probeUrl,
      nodeCount: names.length,
      selectedDelay: proxies.selectedDelayOf(group),
      nodes: filtered,
    })
  }

  return cards
})

const totalNodes = computed<number>(() => proxies.nodes.length)
const isSearching = computed<boolean>(() => search.value.trim().length > 0)
const providers = computed<ProxyProvider[]>(() =>
  proxies.providerList.filter((provider) => provider.name !== 'default'),
)

function isCollapsed(name: string): boolean {
  if (isSearching.value) return false
  return collapsed.value[name] === true
}

function toggleCollapse(name: string): void {
  collapsed.value = { ...collapsed.value, [name]: !collapsed.value[name] }
}

/** The number DelayBadge should render for a given state. */
function displayDelay(info: DelayInfo): number | null {
  if (info.state === 'measured') return info.value
  if (info.state === 'timeout' || info.state === 'error') return 0
  return null
}

const TYPE_TAG: Record<string, 'primary' | 'success' | 'warning' | 'info' | 'danger'> = {
  Selector: 'primary',
  URLTest: 'success',
  Fallback: 'warning',
  LoadBalance: 'info',
  Relay: 'info',
}

function typeTag(type: string): 'primary' | 'success' | 'warning' | 'info' | 'danger' {
  return TYPE_TAG[type] ?? 'info'
}

async function selectNode(card: GroupCard, node: NodeRow): Promise<void> {
  if (!card.selectable || node.selected) return
  const result = await proxies.select(card.name, node.name)
  if (!result.ok) ElMessage.error(result.error.message)
}

async function testGroup(name: string): Promise<void> {
  await proxies.testGroup(name)
}

async function testAll(): Promise<void> {
  testingAll.value = true
  await proxies.testAll()
  testingAll.value = false
}

async function refresh(): Promise<void> {
  await proxies.refresh()
}

async function updateProvider(name: string): Promise<void> {
  busyProvider.value = name
  const result = await proxies.updateProvider(name)
  busyProvider.value = ''
  if (result.ok) ElMessage.success(`Updated provider ${name}`)
  else ElMessage.error(result.error.message)
}

function providerUsage(provider: ProxyProvider): string {
  const info = provider.subscriptionInfo
  if (!info) return ''
  const used = (info.Upload ?? 0) + (info.Download ?? 0)
  const total = info.Total ?? 0
  if (total > 0) return `${formatBytes(used)} / ${formatBytes(total)}`
  return formatBytes(used)
}

onMounted(() => {
  if (proxies.hasData) void proxies.loadProviders()
  else void proxies.refresh()
})
</script>

<template>
  <div class="app-page">
    <div class="app-page__head">
      <div>
        <h2 class="app-page__title">Proxies</h2>
        <p class="app-page__subtitle">
          {{ proxies.groups.length }} groups · {{ totalNodes }} nodes ·
          {{ settings.targetLabel }}
        </p>
      </div>

      <div class="toolbar">
        <el-input
          v-model="search"
          class="toolbar__search"
          :prefix-icon="Search"
          placeholder="Filter nodes…"
          clearable
        />
        <el-select v-model="sortMode" class="toolbar__sort" size="default">
          <el-option label="Group order" value="natural" />
          <el-option label="Fastest first" value="latency" />
        </el-select>
        <el-button :icon="Refresh" :loading="proxies.loading" @click="refresh">Refresh</el-button>
        <el-button type="primary" :icon="Loading" :loading="testingAll" @click="testAll">
          Test all groups
        </el-button>
      </div>
    </div>

    <ErrorState v-if="proxies.error" class="mb-16" :error="proxies.error" @retry="refresh" />

    <EmptyState
      v-if="!proxies.hasData && !proxies.loading"
      title="No proxies reported"
      description="The core returned an empty proxy map. Load a profile or check the backend connection."
    >
      <template #actions>
        <el-button type="primary" :icon="Refresh" @click="refresh">Reload proxies</el-button>
      </template>
    </EmptyState>

    <template v-else>
      <section v-for="card in groupCards" :key="card.name" class="group-card app-panel">
        <header class="group-card__head" @click="toggleCollapse(card.name)">
          <el-icon class="group-card__chevron" :class="{ 'is-collapsed': isCollapsed(card.name) }">
            <ArrowDown />
          </el-icon>
          <NodeIcon :name="card.name" :icon="card.icon" :size="22" />
          <span class="group-card__name ellipsis">{{ card.name }}</span>
          <el-tag size="small" :type="typeTag(card.type)" effect="plain">{{ card.type }}</el-tag>
          <span class="text-faint group-card__count">{{ card.nodeCount }}</span>

          <span class="grow" />

          <template v-if="card.selectable">
            <span class="text-faint group-card__now ellipsis">{{ card.now || '—' }}</span>
          </template>
          <span v-else class="text-faint group-card__now">auto</span>
          <DelayBadge
            :delay="card.selectedDelay"
            :probe-url="card.probeUrl"
            compact
            :loading="card.testing"
          />

          <el-button
            class="group-card__test"
            size="small"
            :icon="Loading"
            :loading="card.testing"
            :aria-label="`Test every node in ${card.name}`"
            @click.stop="testGroup(card.name)"
          >
            Test all
          </el-button>
        </header>

        <div v-show="!isCollapsed(card.name)" class="group-card__body">
          <p v-if="card.nodes.length === 0" class="text-faint group-card__empty">
            No node matches “{{ search }}”.
          </p>

          <div v-else class="node-grid">
            <button
              v-for="node in card.nodes"
              :key="node.name"
              type="button"
              class="node"
              :class="{
                'is-selected': node.selected,
                'is-static': !card.selectable,
                'is-testing': node.testing,
              }"
              :disabled="!card.selectable"
              :title="
                card.selectable
                  ? `${node.name} — click to select`
                  : `${node.name} — ${card.type} groups pick their member automatically`
              "
              @click="selectNode(card, node)"
            >
              <NodeIcon :name="node.name" :icon="node.icon" :size="20" />
              <span class="node__name ellipsis">{{ node.name }}</span>
              <el-icon v-if="node.testing" class="node__spinner is-loading"><Loading /></el-icon>
              <DelayBadge
                :delay="displayDelay(node.delayInfo)"
                :probe-url="card.probeUrl"
                compact
                :loading="node.testing"
                :show-dot="false"
              />
            </button>
          </div>
        </div>
      </section>

      <section v-if="providers.length > 0" class="provider-section">
        <h3 class="app-section-title mb-8">Proxy providers</h3>
        <ErrorState
          v-if="proxies.providerError"
          class="mb-12"
          inline
          :error="proxies.providerError"
          @retry="proxies.loadProviders"
        />
        <div class="provider-grid">
          <div v-for="provider in providers" :key="provider.name" class="app-panel provider-card">
            <div class="row-between gap-8">
              <span class="provider-card__name ellipsis">{{ provider.name }}</span>
              <el-button
                size="small"
                :icon="Refresh"
                :loading="busyProvider === provider.name"
                @click="updateProvider(provider.name)"
              >
                Update
              </el-button>
            </div>
            <p class="text-faint provider-card__meta">
              {{ provider.vehicleType || provider.type }} ·
              {{ (provider.proxies ?? []).length }} nodes
              <template v-if="provider.updatedAt">
                · updated {{ formatRelative(provider.updatedAt) }}
              </template>
            </p>
            <p v-if="provider.subscriptionInfo" class="provider-card__usage mono">
              {{ providerUsage(provider) }}
              <template v-if="provider.subscriptionInfo.Expire">
                · expires {{ formatExpiry(provider.subscriptionInfo.Expire) }}
              </template>
            </p>
          </div>
        </div>
      </section>
    </template>
  </div>
</template>

<style scoped lang="scss">
.toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.toolbar__search {
  width: 220px;
}

.toolbar__sort {
  width: 150px;
}

.group-card {
  margin-bottom: 12px;
  overflow: hidden;
}

.group-card__head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  cursor: pointer;
  user-select: none;

  &:hover {
    background: var(--app-surface-2);
  }
}

.group-card__chevron {
  transition: transform 0.15s ease;
  color: var(--app-text-faint);

  &.is-collapsed {
    transform: rotate(-90deg);
  }
}

.group-card__name {
  font-weight: 600;
  font-size: 14px;
  max-width: 280px;
}

.group-card__count {
  font-size: 12px;
}

.group-card__now {
  font-size: 12px;
  max-width: 220px;
}

.group-card__test {
  flex: none;
}

.group-card__body {
  border-top: 1px solid var(--app-border);
  padding: 12px;
}

.group-card__empty {
  margin: 0;
  font-size: 13px;
}

.node-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
  gap: 8px;
}

.node {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  border-radius: 8px;
  border: 1px solid var(--app-border);
  background: var(--app-surface-2);
  color: var(--app-text);
  font: inherit;
  font-size: 12.5px;
  text-align: left;
  cursor: pointer;
  min-width: 0;

  &:hover:not(:disabled) {
    border-color: var(--app-border-strong);
    background: var(--app-surface-3);
  }

  &:disabled {
    cursor: default;
  }

  &.is-static {
    opacity: 0.92;
  }

  &.is-selected {
    border-color: var(--app-accent);
    background: var(--app-accent-soft);
    color: var(--app-accent);
  }

  &.is-testing {
    border-style: dashed;
  }
}

.node__name {
  flex: 1 1 auto;
  min-width: 0;
}

.node__spinner {
  color: var(--app-accent);
  flex: none;
}

.provider-section {
  margin-top: 20px;
}

.provider-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
}

.provider-card {
  padding: 12px;
}

.provider-card__name {
  font-weight: 600;
  font-size: 13.5px;
}

.provider-card__meta,
.provider-card__usage {
  margin: 6px 0 0;
  font-size: 12px;
}
</style>
