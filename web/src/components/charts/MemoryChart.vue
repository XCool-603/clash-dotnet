<script setup lang="ts">
import { computed } from 'vue'

import LineChartSvg from '@/components/charts/LineChartSvg.vue'
import type { ChartSeries } from '@/components/charts/types'
import { useI18n, type MessageKey } from '@/i18n'
import { formatBytes } from '@/utils/format'

const props = withDefaults(
  defineProps<{
    labels: string[]
    /** In-use memory samples, bytes. */
    values: number[]
    /** Epoch-ms sample times; preferred over `labels` when present. */
    timestamps?: number[]
    /** OS limit, bytes (0 when unknown). */
    limit?: number
    height?: number
  }>(),
  { timestamps: () => [], limit: 0, height: 200 },
)

const MEMORY_COLOR = '#14b8a6'

/** The chart's own labels are catalogue keys, translated at render time. */
const LABELS: Record<'series' | 'limit', MessageKey> = {
  series: 'dashboard.memory',
  limit: 'dashboard.osLimit',
}

const { t } = useI18n()

const series = computed<ChartSeries[]>(() => [
  { name: t(LABELS.series), color: MEMORY_COLOR, values: props.values, area: true },
])

/** The OS limit is a marker rather than a series, so it never joins the legend. */
const reference = computed(() =>
  props.limit > 0 ? { value: props.limit, label: t(LABELS.limit) } : null,
)
</script>

<template>
  <LineChartSvg
    class="memory-chart"
    :series="series"
    :timestamps="timestamps"
    :labels="labels"
    :height="height"
    :reference="reference"
    :value-formatter="formatBytes"
    :axis-formatter="formatBytes"
    :aria-label="t('dashboard.memory')"
  />
</template>

<style scoped>
.memory-chart {
  width: 100%;
}
</style>
