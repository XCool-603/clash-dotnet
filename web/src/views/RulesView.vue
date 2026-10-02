<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Refresh, Search } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'

import EmptyState from '@/components/EmptyState.vue'
import ErrorState from '@/components/ErrorState.vue'
import { ruleKey, useRulesStore } from '@/stores/rules'
import type { Rule, RuleProvider } from '@/types'
import { formatRelative } from '@/utils/format'

/** The list never renders more than this many rows at once. */
const RENDER_LIMIT = 500

/** Trailing tokens Clash allows on an IP-family rule, e.g. `IP-CIDR,10.0.0.0/8,DIRECT,no-resolve`. */
const MODIFIERS: readonly string[] = ['no-resolve', 'src']

interface RuleRow {
  /** Position in the core's ordered list — `PATCH /rules/disable` is index-addressed. */
  index: number
  /** Stable identity across `PATCH` round-trips; also the `saving` key. */
  key: string
  rule: Rule
  /** The payload with its trailing modifiers stripped. */
  payload: string
  modifiers: string[]
}

const rules = useRulesStore()

const search = ref('')
const onlyDisabled = ref(false)
const updatingAll = ref(false)

const TYPE_TAG: Record<string, 'primary' | 'success' | 'warning' | 'info' | 'danger'> = {
  DOMAIN: 'primary',
  'DOMAIN-SUFFIX': 'primary',
  'DOMAIN-KEYWORD': 'primary',
  'DOMAIN-REGEX': 'primary',
  GEOSITE: 'success',
  'RULE-SET': 'success',
  GEOIP: 'warning',
  'IP-CIDR': 'warning',
  'IP-CIDR6': 'warning',
  'IP-SUFFIX': 'warning',
  'IP-ASN': 'warning',
  'SRC-IP-CIDR': 'warning',
  'SRC-IP-ASN': 'warning',
  'SRC-GEOIP': 'warning',
  MATCH: 'danger',
}

function typeTag(type: string): 'primary' | 'success' | 'warning' | 'info' | 'danger' {
  return TYPE_TAG[type] ?? 'info'
}

/** `DIRECT` and `REJECT*` are coloured apart from the proxy groups they route to. */
function targetClass(proxy: string): string {
  const value = proxy.toUpperCase()
  if (value === 'DIRECT') return 'is-direct'
  if (value.startsWith('REJECT')) return 'is-reject'
  return ''
}

/**
 * Cores report the trailing `no-resolve` / `src` tokens as part of the payload.
 * Split them out so the list can render the value and its modifiers separately.
 */
function splitModifiers(rule: Rule): { payload: string; modifiers: string[] } {
  const parts = rule.payload.split(',').map((part) => part.trim())
  if (parts.length < 2) return { payload: rule.payload, modifiers: [] }

  const modifiers: string[] = []
  while (parts.length > 1) {
    const tail = parts[parts.length - 1] ?? ''
    if (!MODIFIERS.includes(tail.toLowerCase())) break
    modifiers.unshift(tail)
    parts.pop()
  }

  return { payload: parts.join(','), modifiers }
}

const allRows = computed<RuleRow[]>(() =>
  rules.rules.map((rule, index) => {
    const { payload, modifiers } = splitModifiers(rule)
    return { index, key: ruleKey(rule, index), rule, payload, modifiers }
  }),
)

const rows = computed<RuleRow[]>(() => {
  const needle = search.value.trim().toLowerCase()
  return allRows.value.filter((row) => {
    if (onlyDisabled.value && row.rule.disabled !== true) return false
    if (needle.length === 0) return true
    return [row.rule.type, row.payload, row.rule.proxy, row.modifiers.join(' ')]
      .join('\u0000')
      .toLowerCase()
      .includes(needle)
  })
})

const visibleRows = computed<RuleRow[]>(() => rows.value.slice(0, RENDER_LIMIT))
const truncated = computed<number>(() => Math.max(0, rows.value.length - RENDER_LIMIT))
const providers = computed<RuleProvider[]>(() => rules.providerList)
const isFiltered = computed<boolean>(() => search.value.trim().length > 0 || onlyDisabled.value)

function providerSaving(name: string): boolean {
  return rules.saving[`provider:${name}`] === true
}

function ruleSaving(row: RuleRow): boolean {
  return rules.saving[row.key] === true
}

async function refresh(): Promise<void> {
  await rules.refresh()
}

async function toggleRule(row: RuleRow, disabled: boolean): Promise<void> {
  const result = await rules.setDisabled(row.rule, disabled, row.index)
  if (!result.ok) ElMessage.error(result.error.message)
}

async function updateProvider(name: string): Promise<void> {
  const result = await rules.updateProvider(name)
  if (result.ok) ElMessage.success(`Updated provider ${name}`)
  else ElMessage.error(result.error.message)
}

async function updateAll(): Promise<void> {
  updatingAll.value = true
  await rules.updateAllProviders()
  updatingAll.value = false

  const failure = rules.providerError
  if (failure) ElMessage.error(failure.message)
  else ElMessage.success('Rule providers updated')
}

onMounted(() => {
  void rules.refresh()
})
</script>

<template>
  <div class="app-page">
    <div class="app-page__head">
      <div>
        <h2 class="app-page__title">Rules</h2>
        <p class="app-page__subtitle">
          {{ rules.totalCount }} rule(s) in evaluation order ·
          {{ rules.disabledCount }} disabled
          <template v-if="rules.lastUpdated > 0">
            · updated {{ formatRelative(rules.lastUpdated) }}
          </template>
        </p>
      </div>

      <div class="toolbar">
        <el-input
          v-model="search"
          class="toolbar__search"
          :prefix-icon="Search"
          placeholder="Filter by type, payload or target…"
          clearable
        />
        <el-checkbox v-model="onlyDisabled">Only disabled</el-checkbox>
        <el-button :icon="Refresh" :loading="rules.loading" @click="refresh">Refresh</el-button>
      </div>
    </div>

    <ErrorState
      v-if="rules.error"
      class="mb-12"
      inline
      :error="rules.error"
      @retry="refresh"
    />

    <EmptyState
      v-if="!rules.loading && rules.totalCount === 0"
      title="No rules reported"
      description="The core returned an empty rule list. Load a profile that has rules, or check the backend connection."
    >
      <template #actions>
        <el-button type="primary" :icon="Refresh" @click="refresh">Reload rules</el-button>
      </template>
    </EmptyState>

    <template v-else>
      <div class="list-toolbar">
        <span class="text-faint">
          {{ rows.length }} of {{ rules.totalCount }} rule(s)
          <template v-if="truncated > 0"> · rendering the first {{ RENDER_LIMIT }}</template>
          <template v-if="isFiltered"> · filtered</template>
        </span>
        <span class="grow" />
        <span class="text-faint">
          toggling a rule is process-local: the core keeps it until the next reload
        </span>
      </div>

      <section class="app-panel rule-list">
        <p v-if="rules.loading && rules.totalCount === 0" class="rule-note text-muted">
          Loading rules…
        </p>
        <p v-else-if="visibleRows.length === 0" class="rule-note text-faint">
          No rule matches the current filter.
        </p>

        <div
          v-for="row in visibleRows"
          :key="row.key"
          class="rule-row"
          :class="{ 'is-disabled': row.rule.disabled === true }"
        >
          <span class="rule-row__index mono">{{ row.index }}</span>
          <el-tag class="rule-row__type" size="small" effect="plain" :type="typeTag(row.rule.type)">
            {{ row.rule.type }}
          </el-tag>
          <span class="rule-row__payload mono ellipsis" :title="row.rule.payload">
            {{ row.payload || '—' }}
          </span>
          <span class="rule-row__mods">
            <el-tag
              v-for="modifier in row.modifiers"
              :key="modifier"
              size="small"
              type="info"
              effect="plain"
            >
              {{ modifier }}
            </el-tag>
          </span>
          <span class="grow" />
          <span
            class="rule-row__target mono ellipsis"
            :class="targetClass(row.rule.proxy)"
            :title="row.rule.proxy"
          >
            {{ row.rule.proxy || '—' }}
          </span>
          <span
            v-if="typeof row.rule.size === 'number' && row.rule.size >= 0"
            class="rule-row__size text-faint"
            :title="`${row.rule.size} entries in this rule set`"
          >
            {{ row.rule.size }}
          </span>
          <el-switch
            class="rule-row__switch"
            :model-value="row.rule.disabled === true"
            :loading="ruleSaving(row)"
            :aria-label="`Enable or disable rule ${row.index}`"
            @change="toggleRule(row, $event === true)"
          />
        </div>
      </section>

      <section class="provider-section">
        <div class="provider-head">
          <h3 class="app-section-title">Rule providers</h3>
          <span class="grow" />
          <el-button
            v-if="providers.length > 0"
            size="small"
            :icon="Refresh"
            :loading="updatingAll"
            @click="updateAll"
          >
            Update all
          </el-button>
        </div>

        <p v-if="!rules.providersAvailable" class="text-faint provider-note">
          This core does not expose <code>GET /providers/rules</code>, so rule providers cannot be
          listed or refreshed here. The rule list above is unaffected.
        </p>

        <template v-else>
          <ErrorState
            v-if="rules.providerError"
            class="mb-12"
            inline
            :error="rules.providerError"
            @retry="rules.loadProviders"
          />

          <p v-if="providers.length === 0" class="text-faint provider-note">
            No rule providers are configured — every rule is inline.
          </p>

          <div v-else class="provider-grid">
            <div v-for="provider in providers" :key="provider.name" class="app-panel provider-card">
              <div class="row-between gap-8">
                <span class="provider-card__name ellipsis">{{ provider.name }}</span>
                <el-button
                  size="small"
                  :icon="Refresh"
                  :loading="providerSaving(provider.name)"
                  @click="updateProvider(provider.name)"
                >
                  Update
                </el-button>
              </div>
              <p class="text-faint provider-card__meta">
                {{ provider.vehicleType || provider.type }} ·
                {{ provider.behavior || 'unknown behaviour' }} ·
                {{ provider.ruleCount }} rules
                <template v-if="provider.updatedAt">
                  · updated {{ formatRelative(provider.updatedAt) }}
                </template>
              </p>
              <p v-if="provider.format" class="text-faint provider-card__meta mono">
                format {{ provider.format }}
              </p>
            </div>
          </div>
        </template>
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
  width: 260px;
}

.list-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  margin-bottom: 6px;
}

.rule-list {
  max-height: min(70vh, 900px);
  overflow-y: auto;
}

.rule-note {
  margin: 0;
  padding: 24px 16px;
  font-size: 13px;
  text-align: center;
}

.rule-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 6px 12px;
  border-bottom: 1px solid var(--app-border);
  font-size: 12.5px;
  min-width: 0;

  &:last-child {
    border-bottom: 0;
  }

  &:hover {
    background: var(--app-surface-2);
  }

  &.is-disabled {
    opacity: 0.55;
  }
}

.rule-row__index {
  flex: none;
  width: 48px;
  text-align: right;
  color: var(--app-text-faint);
  font-size: 11.5px;
}

.rule-row__type {
  flex: none;
  width: 130px;
  justify-content: center;
}

.rule-row__payload {
  flex: 1 1 260px;
  min-width: 0;
}

.rule-row__mods {
  flex: none;
  display: flex;
  gap: 4px;
}

.rule-row__target {
  flex: 0 1 200px;
  text-align: right;
  color: var(--app-accent);

  &.is-direct {
    color: var(--app-orange);
  }

  &.is-reject {
    color: var(--app-danger);
  }
}

.rule-row__size {
  flex: none;
  font-size: 11.5px;
}

.rule-row__switch {
  flex: none;
}

.provider-section {
  margin-top: 20px;
}

.provider-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.provider-note {
  margin: 0 0 8px;
  font-size: 12px;
  line-height: 1.5;
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

.provider-card__meta {
  margin: 6px 0 0;
  font-size: 12px;
}

code {
  font-family: 'JetBrains Mono', Consolas, monospace;
  font-size: 11.5px;
  background: var(--app-surface-3);
  padding: 1px 4px;
  border-radius: 4px;
}
</style>
