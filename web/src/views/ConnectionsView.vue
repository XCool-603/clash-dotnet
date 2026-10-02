<script setup lang="ts">
import { computed, h, onMounted, onUnmounted, ref } from 'vue'
import type { VNode, VNodeChild } from 'vue'
import { useElementSize } from '@vueuse/core'
import {
  Close,
  Delete,
  Refresh,
  Search,
  VideoPause,
  VideoPlay,
} from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox, ElTableV2 } from 'element-plus'
import type { Column } from 'element-plus'

/**
 * The renderer parameter shapes, derived from `Column` rather than imported:
 * element-plus does not re-export them from its root entry, and deriving them
 * keeps the renderers in step with whatever the installed version declares.
 */
type CellRendererParams<T> = Parameters<NonNullable<Column<T>['cellRenderer']>>[0]
type HeaderCellRendererParams<T> = Parameters<NonNullable<Column<T>['headerCellRenderer']>>[0]

import ConnectionCell from '@/components/ConnectionCell.vue'
import EmptyState from '@/components/EmptyState.vue'
import ErrorState from '@/components/ErrorState.vue'
import { useI18n, type MessageKey } from '@/i18n'
import { CONNECTIONS_FAST_INTERVAL, CONNECTIONS_IDLE_INTERVAL, useConnectionsStore } from '@/stores/connections'
import type { Connection, ConnectionMetadata } from '@/types'
import { formatBytes, formatDuration, truncateMiddle } from '@/utils/format'

/** The table never renders more than this many rows at once. */
const RENDER_LIMIT = 500

type Tab = 'active' | 'closed' | 'all'
type SortDirection = 'asc' | 'desc'
type SortKey =
  | 'host'
  | 'network'
  | 'type'
  | 'chains'
  | 'rule'
  | 'upload'
  | 'download'
  | 'durationMs'
  | 'source'
  | 'destination'
  | 'process'

interface ConnectionRow {
  id: string
  closed: boolean
  host: string
  network: string
  type: string
  chains: string
  rule: string
  upload: number
  download: number
  durationMs: number
  source: string
  destination: string
  process: string
  connection: Connection
}

const connections = useConnectionsStore()
const { t } = useI18n()

const tab = ref<Tab>('active')
const search = ref('')
const sortKey = ref<SortKey>('download')
const sortDir = ref<SortDirection>('desc')
const detail = ref<ConnectionRow | null>(null)
const detailOpen = ref(false)

const tableHost = ref<HTMLElement | null>(null)
const { width: hostWidth, height: hostHeight } = useElementSize(tableHost)
const tableWidth = computed<number>(() => Math.max(360, Math.floor(hostWidth.value)))
const tableHeight = computed<number>(() => Math.max(260, Math.floor(hostHeight.value)))

function basename(path: string): string {
  if (!path) return ''
  const parts = path.split(/[\\/]/)
  return parts[parts.length - 1] ?? path
}

function toRow(connection: Connection, closed: boolean): ConnectionRow {
  const md = (connection.metadata ?? {}) as Partial<ConnectionMetadata>
  const host = md.host && md.host.length > 0 ? md.host : md.destinationIP ?? ''
  const startMs = Date.parse(connection.start)
  return {
    id: connection.id,
    closed,
    host: md.destinationPort ? `${host}:${md.destinationPort}` : host,
    network: md.network ?? '',
    type: md.type ?? '',
    // Outermost outbound first, matching the reference dashboards.
    chains: [...(connection.chains ?? [])].reverse().join(' → '),
    rule: connection.rulePayload ? `${connection.rule}(${connection.rulePayload})` : connection.rule,
    upload: connection.upload ?? 0,
    download: connection.download ?? 0,
    durationMs: Number.isFinite(startMs) ? Date.now() - startMs : 0,
    source: `${md.sourceIP ?? ''}:${md.sourcePort ?? ''}`,
    destination: md.destinationIP ?? '',
    process: md.process || basename(md.processPath ?? ''),
    connection,
  }
}

const baseRows = computed<ConnectionRow[]>(() => {
  const active = connections.connections.map((item) => toRow(item, false))
  const closed = connections.closedVisible.map((item) => toRow(item, true))
  if (tab.value === 'active') return active
  if (tab.value === 'closed') return closed
  return active.concat(closed)
})

const filteredRows = computed<ConnectionRow[]>(() => {
  const needle = search.value.trim().toLowerCase()
  if (needle.length === 0) return baseRows.value
  return baseRows.value.filter((row) =>
    [
      row.host,
      row.network,
      row.type,
      row.chains,
      row.rule,
      row.source,
      row.destination,
      row.process,
    ]
      .join('\u0000')
      .toLowerCase()
      .includes(needle),
  )
})

const sortedRows = computed<ConnectionRow[]>(() => {
  const key = sortKey.value
  const direction = sortDir.value === 'asc' ? 1 : -1
  const list = filteredRows.value.slice()

  list.sort((a, b) => {
    const left = a[key]
    const right = b[key]
    let comparison: number
    if (typeof left === 'number' && typeof right === 'number') {
      comparison = left - right
    } else {
      comparison = String(left).localeCompare(String(right), undefined, { numeric: true })
    }
    if (comparison === 0) return a.id.localeCompare(b.id)
    return comparison * direction
  })

  return list
})

const visibleRows = computed<ConnectionRow[]>(() => sortedRows.value.slice(0, RENDER_LIMIT))
const truncated = computed<number>(() => Math.max(0, sortedRows.value.length - RENDER_LIMIT))

function defaultDirection(key: SortKey): SortDirection {
  return key === 'upload' || key === 'download' || key === 'durationMs' ? 'desc' : 'asc'
}

function toggleSort(key: SortKey): void {
  if (sortKey.value === key) {
    sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
  } else {
    sortKey.value = key
    sortDir.value = defaultDirection(key)
  }
}

/** Stable-identity header renderer with a sort affordance. */
function headerRenderer(
  labelKey: MessageKey,
  key: SortKey,
  activeKey: SortKey,
  direction: SortDirection,
) {
  const label = t(labelKey)
  return (_params: HeaderCellRendererParams<ConnectionRow>): VNode =>
    h(
      'div',
      {
        class: 'th',
        role: 'button',
        tabindex: 0,
        title: t('connections.sortBy', { column: label }),
        onClick: () => toggleSort(key),
        onKeydown: (event: KeyboardEvent) => {
          if (event.key === 'Enter' || event.key === ' ') toggleSort(key)
        },
      },
      [
        h('span', label),
        activeKey === key ? h('span', { class: 'th__arrow' }, direction === 'asc' ? '▲' : '▼') : null,
      ],
    )
}

/**
 * Wrap a per-row render function in the constant-identity `ConnectionCell`.
 * Without it Vue would unmount and remount every cell on every tick.
 */
function cell(render: (row: ConnectionRow) => VNodeChild) {
  return (params: CellRendererParams<ConnectionRow>): VNode =>
    h(ConnectionCell, { render: () => render(params.rowData as ConnectionRow) }) as VNode
}

function text(value: string, rightAligned = false): VNodeChild {
  return h(
    'span',
    { class: ['cell-text', rightAligned ? 'is-right' : ''], title: value },
    value || '—',
  )
}

const columns = computed<Column<ConnectionRow>[]>(() => {
  // Reading the sort state here makes the column list (and therefore the
  // header) recompute when the sort changes.
  const activeKey = sortKey.value
  const direction = sortDir.value

  const column = (
    key: SortKey,
    labelKey: MessageKey,
    width: number,
    render: (row: ConnectionRow) => VNodeChild,
  ): Column<ConnectionRow> => ({
    key,
    dataKey: key,
    title: t(labelKey),
    width,
    headerCellRenderer: headerRenderer(labelKey, key, activeKey, direction),
    cellRenderer: cell(render),
  })

  return [
    column('host', 'connections.column.host', 200, (row) => text(row.host)),
    column('network', 'connections.column.network', 70, (row) =>
      h('span', { class: ['pill', `pill--${row.network}`] }, row.network || '—'),
    ),
    column('type', 'connections.column.type', 100, (row) => text(row.type)),
    column('chains', 'connections.column.chains', 170, (row) => text(row.chains)),
    column('rule', 'connections.column.rule', 150, (row) => text(row.rule)),
    column('upload', 'connections.column.upload', 90, (row) => text(formatBytes(row.upload), true)),
    column('download', 'connections.column.download', 100, (row) => text(formatBytes(row.download), true)),
    column('durationMs', 'connections.column.duration', 90, (row) => text(formatDuration(row.durationMs), true)),
    column('source', 'connections.column.source', 140, (row) => text(row.source)),
    column('destination', 'connections.column.destination', 140, (row) => text(row.destination)),
    column('process', 'connections.column.process', 150, (row) => text(truncateMiddle(row.process, 26))),
    {
      key: 'actions',
      width: 104,
      title: '',
      headerCellRenderer: () => h('div', { class: 'th th--plain' }, ''),
      cellRenderer: cell((row) =>
        h('div', { class: 'row-actions' }, [
          h(
            'button',
            {
              type: 'button',
              class: 'row-action',
              title: t('action.details'),
              'aria-label': t('connections.detailsFor', { host: row.host }),
              onClick: () => {
                detail.value = row
                detailOpen.value = true
              },
            },
            '⋯',
          ),
          row.closed
            ? null
            : h(
                'button',
                {
                  type: 'button',
                  class: 'row-action row-action--danger',
                  title: t('connections.closeConnection'),
                  'aria-label': t('connections.closeConnectionTo', { host: row.host }),
                  onClick: () => void closeRow(row),
                },
                '✕',
              ),
        ]),
      ),
    },
  ]
})

const detailRows = computed<{ labelKey: MessageKey; value: string }[]>(() => {
  const row = detail.value
  if (!row) return []
  const md = (row.connection.metadata ?? {}) as Partial<ConnectionMetadata>
  const entries: [MessageKey, string][] = [
    ['connections.detail.id', row.connection.id],
    ['connections.column.host', row.host],
    ['connections.detail.network', row.network],
    ['connections.column.type', row.type],
    ['connections.column.chains', row.chains],
    ['connections.column.rule', row.rule],
    ['connections.detail.rulePayload', row.connection.rulePayload || '—'],
    ['connections.column.upload', formatBytes(row.upload)],
    ['connections.column.download', formatBytes(row.download)],
    ['connections.column.duration', formatDuration(row.durationMs)],
    ['connections.detail.started', row.connection.start],
    ['connections.column.source', row.source],
    ['connections.column.destination', row.destination],
    ['connections.detail.destinationPort', md.destinationPort ?? '—'],
    ['connections.detail.dnsMode', md.dnsMode ?? '—'],
    ['connections.detail.sniffHost', md.sniffHost ?? '—'],
    ['connections.column.process', md.process ?? '—'],
    ['connections.detail.processPath', md.processPath ?? '—'],
    ['connections.detail.remoteDestination', md.remoteDestination ?? '—'],
    ['connections.detail.specialProxy', md.specialProxy ?? '—'],
    ['connections.detail.specialRules', md.specialRules ?? '—'],
    ['connections.detail.inbound', md.inboundName ?? '—'],
    ['connections.detail.inboundUser', md.inboundUser ?? '—'],
  ]
  return entries
    .filter(([, value]) => value !== undefined && value !== null && String(value).length > 0)
    .map(([labelKey, value]) => ({ labelKey, value: String(value) }))
})

async function closeRow(row: ConnectionRow): Promise<void> {
  const result = await connections.close(row.id)
  if (!result.ok) ElMessage.error(result.error.message)
}

async function closeAll(): Promise<void> {
  try {
    await ElMessageBox.confirm(
      t('connections.closeAllConfirm', { count: connections.activeCount }),
      t('connections.closeAllTitle'),
      {
        type: 'warning',
        confirmButtonText: t('connections.closeAll'),
        cancelButtonText: t('action.cancel'),
      },
    )
  } catch {
    return
  }
  const result = await connections.closeAll()
  if (result.ok) ElMessage.success(t('connections.closeAllDone'))
  else ElMessage.error(result.error.message)
}

function togglePause(): void {
  connections.togglePause()
}

function clearHistory(): void {
  connections.clearClosed()
}

onMounted(() => {
  connections.startPolling(CONNECTIONS_FAST_INTERVAL)
})

onUnmounted(() => {
  connections.startPolling(CONNECTIONS_IDLE_INTERVAL)
})
</script>

<template>
  <div class="app-page connections-page">
    <div class="app-page__head">
      <div>
        <h2 class="app-page__title">{{ t('nav.connections') }}</h2>
        <p class="app-page__subtitle">
          {{ t('connections.active', { count: connections.activeCount }) }} ·
          {{ t('connections.history', { count: connections.closedVisible.length }) }} ·
          {{
            t('connections.totalTraffic', {
              down: formatBytes(connections.downloadTotal),
              up: formatBytes(connections.uploadTotal),
            })
          }}
        </p>
      </div>

      <div class="toolbar">
        <el-radio-group v-model="tab" size="default">
          <el-radio-button value="active">
            {{ t('connections.tabActive', { count: connections.activeCount }) }}
          </el-radio-button>
          <el-radio-button value="closed">
            {{ t('connections.tabClosed', { count: connections.closedVisible.length }) }}
          </el-radio-button>
          <el-radio-button value="all">{{ t('connections.tabAll') }}</el-radio-button>
        </el-radio-group>

        <el-input
          v-model="search"
          class="toolbar__search"
          :prefix-icon="Search"
          :placeholder="t('connections.searchPlaceholder')"
          clearable
        />

        <el-button
          :icon="connections.paused ? VideoPlay : VideoPause"
          :type="connections.paused ? 'warning' : 'default'"
          @click="togglePause"
        >
          {{ connections.paused ? t('connections.resume') : t('connections.pause') }}
        </el-button>
        <el-button
          :icon="Delete"
          :disabled="connections.activeCount === 0"
          @click="closeAll"
        >
          {{ t('connections.closeAll') }}
        </el-button>
        <el-button :icon="Refresh" @click="connections.load()">{{ t('action.refresh') }}</el-button>
      </div>
    </div>

    <ErrorState
      v-if="connections.error"
      class="mb-12"
      inline
      :error="connections.error"
      @retry="connections.load()"
    />

    <div class="table-toolbar">
      <span class="text-faint">
        {{ t('count.lines', { count: sortedRows.length }) }}
        <template v-if="truncated > 0"> · {{ t('connections.showingFirst', { limit: RENDER_LIMIT }) }}</template>
        ·
        {{
          connections.paused
            ? t('connections.paused')
            : t('connections.liveAt', { interval: connections.pollingInterval })
        }}
      </span>
      <span class="grow" />
      <el-button v-if="tab !== 'active'" size="small" text @click="clearHistory">
        {{ t('connections.clearHistory') }}
      </el-button>
    </div>

    <div ref="tableHost" class="table-host">
      <ElTableV2
        v-if="visibleRows.length > 0"
        class="conn-table"
        :columns="columns"
        :data="visibleRows"
        :width="tableWidth"
        :height="tableHeight"
        :row-height="34"
        :header-height="34"
        :row-key="'id'"
        :cache="8"
        :h-scrollbar-size="8"
        :v-scrollbar-size="8"
      />
      <EmptyState
        v-else
        :title="t('connections.emptyTitle')"
        :description="
          connections.paused
            ? t('connections.emptyPaused')
            : t('connections.emptyDescription')
        "
      />
    </div>

    <el-drawer v-model="detailOpen" size="520px" :title="t('connections.detailTitle')" append-to-body>
      <el-descriptions v-if="detail" :column="1" border size="small">
        <el-descriptions-item v-for="entry in detailRows" :key="entry.labelKey" :label="t(entry.labelKey)">
          <span class="mono detail-value">{{ entry.value }}</span>
        </el-descriptions-item>
      </el-descriptions>
      <template #footer>
        <el-button
          v-if="detail && !detail.closed"
          type="danger"
          plain
          :icon="Close"
          @click="detail && closeRow(detail)"
        >
          {{ t('connections.closeConnection') }}
        </el-button>
        <el-button @click="detailOpen = false">{{ t('action.close') }}</el-button>
      </template>
    </el-drawer>
  </div>
</template>

<style scoped lang="scss">
.connections-page {
  display: flex;
  flex-direction: column;
  min-height: 0;
}

.toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.toolbar__search {
  width: 260px;
}

.table-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  margin-bottom: 6px;
}

.table-host {
  flex: 1 1 auto;
  min-height: 320px;
  height: calc(100vh - 290px);
  border: 1px solid var(--app-border);
  border-radius: var(--app-radius);
  background: var(--app-surface);
  overflow: hidden;
}

.visually-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
}

.detail-value {
  word-break: break-all;
  font-size: 12px;
}
</style>

<style lang="scss">
/* table-v2 renders outside the scoped-style attribute, so these live global. */
.conn-table {
  --el-table-v2-header-bg-color: var(--app-surface-2);
  --el-table-v2-row-bg-color: transparent;
  --el-table-v2-border-color: var(--app-border);
  color: var(--app-text);
  font-size: 12.5px;
}

.conn-table .el-table-v2__header-cell,
.conn-table .el-table-v2__row-cell {
  padding: 0 8px;
  border-right: 1px solid var(--app-border);
}

.conn-table .el-table-v2__row-cell {
  overflow: hidden;
}

.conn-table .cell-text {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.conn-table .th {
  display: flex;
  align-items: center;
  gap: 4px;
  width: 100%;
  height: 100%;
  cursor: pointer;
  font-weight: 600;
  color: var(--app-text-muted);
  text-transform: uppercase;
  font-size: 11px;
  letter-spacing: 0.03em;
  user-select: none;
}

.conn-table .th--plain {
  cursor: default;
}

.conn-table .th__arrow {
  font-size: 9px;
  color: var(--app-accent);
}

.conn-table .pill {
  display: inline-block;
  padding: 0 6px;
  border-radius: 999px;
  background: var(--app-surface-3);
  color: var(--app-text-muted);
  font-size: 11px;
  line-height: 17px;
}

.conn-table .pill--tcp {
  color: var(--app-accent);
}

.conn-table .pill--udp {
  color: var(--app-orange);
}

.conn-table .row-actions {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 4px;
}

.conn-table .row-action {
  width: 22px;
  height: 22px;
  border-radius: 6px;
  border: 1px solid var(--app-border);
  background: var(--app-surface-2);
  color: var(--app-text-muted);
  cursor: pointer;
  font-size: 11px;
  line-height: 1;
  padding: 0;
}

.conn-table .row-action:hover {
  border-color: var(--app-border-strong);
  color: var(--app-text);
}

.conn-table .row-action--danger:hover {
  border-color: var(--app-danger);
  color: var(--app-danger);
}
</style>
