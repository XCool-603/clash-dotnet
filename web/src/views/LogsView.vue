<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { Delete, Search, SwitchButton, VideoPause, VideoPlay } from '@element-plus/icons-vue'

import EmptyState from '@/components/EmptyState.vue'
import StatusPill from '@/components/StatusPill.vue'
import { useLogsStream } from '@/composables/useLogsStream'
import { LOG_BUFFER_LIMIT, normalizeLogLevel, useLogsStore } from '@/stores/logs'
import type { LogEntry, LogLevel } from '@/types'
import { LOG_LEVELS } from '@/types'
import { formatClock } from '@/utils/format'
import type { StreamStatus } from '@/utils/ws'

/** The viewport never renders more than this many lines at once. */
const RENDER_LIMIT = 500

const STATUS_LABEL: Record<StreamStatus, string> = {
  idle: 'Stream idle',
  connecting: 'Connecting…',
  open: 'Streaming',
  reconnecting: 'Reconnecting…',
  stopped: 'Stopped',
}

const logs = useLogsStore()
const stream = useLogsStream()

const viewport = ref<HTMLDivElement | null>(null)

const statusLabel = computed<string>(() => STATUS_LABEL[logs.status])
const streaming = computed<boolean>(() => logs.status !== 'stopped')

/** Only the tail of the filtered buffer is rendered, so the DOM stays bounded. */
const entries = computed<LogEntry[]>(() => {
  const list = logs.filtered
  return list.length > RENDER_LIMIT ? list.slice(list.length - RENDER_LIMIT) : list
})

const truncated = computed<number>(() => Math.max(0, logs.visibleCount - entries.value.length))

/**
 * Watching the rendered length alone would stop firing once the cap is reached
 * (the length stays at `RENDER_LIMIT` while the tail keeps moving), so the
 * auto-scroll follows the id of the newest rendered line instead.
 */
const newestId = computed<number>(() => entries.value[entries.value.length - 1]?.id ?? 0)

const emptyDescription = computed<string>(() => {
  if (logs.paused) return 'Live updates are paused. Resume to follow new lines.'
  if (logs.bufferedCount > 0) return 'No buffered line matches the current level and search filter.'
  if (logs.connected) return 'Connected — waiting for the core to emit a log line.'
  return 'The log stream is not connected. Start it, or check the API address in Settings.'
})

function levelClass(type: string): string {
  return `is-${normalizeLogLevel(type)}`
}

function levelLabel(type: string): string {
  return normalizeLogLevel(type).toUpperCase()
}

function isLogLevel(value: unknown): value is LogLevel {
  return typeof value === 'string' && (LOG_LEVELS as readonly string[]).includes(value)
}

/** Changing the level re-opens the socket: the level is a query parameter on `/logs`. */
function onLevelChange(value: unknown): void {
  if (isLogLevel(value)) logs.setLevel(value)
}

function togglePause(): void {
  logs.togglePause()
}

function toggleStream(): void {
  if (streaming.value) stream.stop()
  else stream.start()
}

async function scrollToBottom(): Promise<void> {
  await nextTick()
  const element = viewport.value
  if (element) element.scrollTop = element.scrollHeight
}

watch(newestId, () => {
  if (logs.autoScroll && !logs.paused) void scrollToBottom()
})

watch(
  () => [logs.autoScroll, logs.paused] as const,
  ([autoScroll, paused]) => {
    if (autoScroll && !paused) void scrollToBottom()
  },
)

onMounted(() => {
  void scrollToBottom()
})
</script>

<template>
  <div class="app-page logs-page">
    <div class="app-page__head">
      <div>
        <h2 class="app-page__title">Logs</h2>
        <p class="app-page__subtitle">
          Live core log over <code>WS /logs?level={{ logs.level }}</code> ·
          {{ logs.bufferedCount }} buffered · {{ logs.visibleCount }} matching
        </p>
      </div>

      <div class="toolbar">
        <StatusPill :online="logs.connected" :label="statusLabel" />

        <el-select
          class="toolbar__level"
          :model-value="logs.level"
          aria-label="Log level"
          @change="onLevelChange"
        >
          <el-option v-for="level in LOG_LEVELS" :key="level" :label="level" :value="level" />
        </el-select>

        <el-input
          v-model="logs.search"
          class="toolbar__search"
          :prefix-icon="Search"
          placeholder="Search payload…"
          clearable
        />

        <el-button
          :icon="logs.paused ? VideoPlay : VideoPause"
          :type="logs.paused ? 'warning' : 'default'"
          @click="togglePause"
        >
          {{ logs.paused ? 'Resume' : 'Pause' }}
        </el-button>
        <el-button :icon="SwitchButton" @click="toggleStream">
          {{ streaming ? 'Stop stream' : 'Start stream' }}
        </el-button>
        <el-button :icon="Delete" :disabled="logs.bufferedCount === 0" @click="logs.clear()">
          Clear
        </el-button>
      </div>
    </div>

    <div class="log-toolbar">
      <el-checkbox v-model="logs.autoScroll">Auto-scroll</el-checkbox>
      <span class="text-faint">
        {{ entries.length }} of {{ logs.visibleCount }} line(s) rendered
        <template v-if="truncated > 0"> · showing the last {{ RENDER_LIMIT }}</template>
        · buffer {{ logs.bufferedCount }} / {{ LOG_BUFFER_LIMIT }}
        <template v-if="logs.droppedCount > 0">
          · {{ logs.droppedCount }} oldest line(s) dropped
        </template>
        <template v-if="logs.paused"> · paused, new lines keep buffering</template>
      </span>
      <span class="grow" />
      <span class="text-faint">{{ logs.level }} and above</span>
    </div>

    <div ref="viewport" class="log-viewport">
      <EmptyState v-if="entries.length === 0" title="No log lines" :description="emptyDescription" />

      <div
        v-for="entry in entries"
        :key="entry.id"
        class="log-line"
        :class="levelClass(entry.type)"
      >
        <span class="log-line__time mono">{{ formatClock(entry.time) }}</span>
        <span class="log-line__level mono">{{ levelLabel(entry.type) }}</span>
        <span class="log-line__payload mono">{{ entry.payload }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
.logs-page {
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

.toolbar__level {
  width: 130px;
}

.toolbar__search {
  width: 240px;
}

.log-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  margin-bottom: 6px;
}

.log-viewport {
  flex: 1 1 auto;
  min-height: 320px;
  height: calc(100vh - 300px);
  overflow-y: auto;
  padding: 6px 0;
  border: 1px solid var(--app-border);
  border-radius: var(--app-radius);
  background: var(--app-surface);
}

.log-line {
  display: flex;
  align-items: baseline;
  gap: 10px;
  padding: 1px 12px;
  font-size: 12.5px;
  line-height: 1.55;

  &:hover {
    background: var(--app-surface-2);
  }

  &.is-debug {
    color: var(--app-success);
  }

  &.is-info {
    color: var(--app-text);
  }

  &.is-warning {
    color: var(--app-warning);
  }

  &.is-error {
    color: var(--app-danger);
  }
}

.log-line__time {
  flex: none;
  color: var(--app-text-faint);
  font-size: 11.5px;
}

.log-line__level {
  flex: none;
  width: 62px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.03em;
  opacity: 0.85;
}

.log-line__payload {
  flex: 1 1 auto;
  min-width: 0;
  white-space: pre-wrap;
  word-break: break-word;
}

code {
  font-family: 'JetBrains Mono', Consolas, monospace;
  font-size: 11.5px;
  background: var(--app-surface-3);
  padding: 1px 4px;
  border-radius: 4px;
}
</style>
