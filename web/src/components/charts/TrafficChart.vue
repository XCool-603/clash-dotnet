<script setup lang="ts">
import { computed } from 'vue'

import LineChartSvg from '@/components/charts/LineChartSvg.vue'
import type { ChartSeries } from '@/components/charts/types'
import { useI18n, type MessageKey } from '@/i18n'
import { formatRate, formatRateCompact } from '@/utils/format'

const props = withDefaults(
  defineProps<{
    /** X-axis labels (one per sample). Used when `timestamps` is absent. */
    labels: string[]
    /** Download samples, bytes/second. */
    down: number[]
    /** Upload samples, bytes/second. */
    up: number[]
    /** Epoch-ms sample times; preferred over `labels` when present. */
    timestamps?: number[]
    height?: number
  }>(),
  { timestamps: () => [], height: 250 },
)

const DOWN_COLOR = '#3b82f6'
const UP_COLOR = '#f59e0b'

/**
 * Legend and readout labels are catalogue keys, translated at render time, so
 * both follow the active locale.
 */
const SERIES_LABELS: Record<'down' | 'up', MessageKey> = {
  down: 'dashboard.download',
  up: 'dashboard.upload',
}

const { t } = useI18n()

const series = computed<ChartSeries[]>(() => [
  { name: t(SERIES_LABELS.down), color: DOWN_COLOR, values: props.down, area: true },
  { name: t(SERIES_LABELS.up), color: UP_COLOR, values: props.up, area: true },
])
</script>

<template>
  <LineChartSvg
    class="traffic-chart"
    :series="series"
    :timestamps="timestamps"
    :labels="labels"
    :height="height"
    :value-formatter="formatRate"
    :axis-formatter="formatRateCompact"
    :aria-label="t('dashboard.traffic')"
  />
</template>

<style scoped>
.traffic-chart {
  width: 100%;
}
</style>
