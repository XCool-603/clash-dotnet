<script setup lang="ts">
import { computed } from 'vue'
import VChart from 'vue-echarts'
import { LineChart } from 'echarts/charts'
import type { LineSeriesOption } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import type {
  GridComponentOption,
  LegendComponentOption,
  TooltipComponentOption,
} from 'echarts/components'
import { use, type ComposeOption } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'

import { useSettingsStore } from '@/stores/settings'
import { formatRate, formatRateCompact } from '@/utils/format'

use([CanvasRenderer, LineChart, GridComponent, TooltipComponent, LegendComponent])

type TrafficChartOption = ComposeOption<
  LineSeriesOption | GridComponentOption | LegendComponentOption | TooltipComponentOption
>

const props = withDefaults(
  defineProps<{
    /** X-axis labels (one per sample). Used when `timestamps` is absent. */
    labels: string[]
    /** Download samples, bytes/second. */
    down: number[]
    /** Upload samples, bytes/second. */
    up: number[]
    /**
     * Epoch-ms sample times. When supplied (and aligned with the series) the
     * chart switches to a real `type: 'time'` axis with a fixed window
     * instead of a category axis of pre-formatted labels.
     */
    timestamps?: number[]
    height?: number
  }>(),
  { timestamps: () => [], height: 250 },
)

const DOWN_COLOR = '#3b82f6'
const UP_COLOR = '#f59e0b'

const settings = useSettingsStore()
const isDark = computed<boolean>(() => settings.theme === 'dark')

/** Only use the time axis when the sample times actually line up. */
const hasTimeAxis = computed<boolean>(
  () => props.timestamps.length > 0 && props.timestamps.length === props.down.length,
)

const windowStart = computed<number | undefined>(() =>
  hasTimeAxis.value ? props.timestamps[0] : undefined,
)
const windowEnd = computed<number | undefined>(() =>
  hasTimeAxis.value ? props.timestamps[props.timestamps.length - 1] : undefined,
)

/** Pair each value with its timestamp when the time axis is active. */
function seriesData(values: number[]): number[] | [number, number][] {
  if (!hasTimeAxis.value) return values
  return values.map((value, index) => [props.timestamps[index] ?? 0, value] as [number, number])
}

const axisColor = computed<string>(() => (isDark.value ? '#6b7280' : '#98a2b3'))
const splitColor = computed<string>(() =>
  isDark.value ? 'rgba(148, 163, 184, 0.13)' : 'rgba(16, 24, 40, 0.07)',
)
const legendColor = computed<string>(() => (isDark.value ? '#8b949e' : '#667085'))

function areaGradient(color: string): LineSeriesOption['areaStyle'] {
  return {
    color: {
      type: 'linear',
      x: 0,
      y: 0,
      x2: 0,
      y2: 1,
      colorStops: [
        { offset: 0, color: `${color}66` },
        { offset: 1, color: `${color}05` },
      ],
      global: false,
    },
  }
}

const option = computed<TrafficChartOption>(() => ({
  animation: false,
  grid: { left: 62, right: 18, top: 34, bottom: 26 },
  legend: {
    top: 0,
    right: 4,
    icon: 'roundRect',
    itemWidth: 10,
    itemHeight: 10,
    textStyle: { color: legendColor.value, fontSize: 12 },
    data: ['Download', 'Upload'],
  },
  tooltip: {
    trigger: 'axis',
    confine: true,
    backgroundColor: isDark.value ? '#1c232c' : '#ffffff',
    borderColor: isDark.value ? '#2a323d' : '#e0e4ea',
    textStyle: { color: isDark.value ? '#e6edf3' : '#1f2329', fontSize: 12 },
    valueFormatter: (value: unknown) => formatRate(Number(value)),
  },
  xAxis: hasTimeAxis.value
    ? {
        type: 'time',
        // A time axis takes no boolean `boundaryGap`; the window is fixed by
        // `min`/`max` instead.
        min: windowStart.value,
        max: windowEnd.value,
        axisLine: { lineStyle: { color: splitColor.value } },
        axisTick: { show: false },
        axisLabel: {
          color: axisColor.value,
          fontSize: 11,
          hideOverlap: true,
          formatter: '{HH}:{mm}:{ss}',
        },
        splitLine: { show: false },
      }
    : {
        type: 'category',
        boundaryGap: false,
        data: props.labels,
        axisLine: { lineStyle: { color: splitColor.value } },
        axisTick: { show: false },
        axisLabel: { color: axisColor.value, fontSize: 11, hideOverlap: true },
      },
  yAxis: {
    type: 'value',
    axisLine: { show: false },
    axisTick: { show: false },
    axisLabel: {
      color: axisColor.value,
      fontSize: 11,
      formatter: (value: number) => formatRateCompact(value),
    },
    splitLine: { lineStyle: { color: splitColor.value } },
  },
  series: [
    {
      name: 'Download',
      type: 'line',
      smooth: true,
      showSymbol: false,
      sampling: 'lttb',
      data: seriesData(props.down),
      lineStyle: { width: 2, color: DOWN_COLOR },
      itemStyle: { color: DOWN_COLOR },
      areaStyle: areaGradient(DOWN_COLOR),
    },
    {
      name: 'Upload',
      type: 'line',
      smooth: true,
      showSymbol: false,
      sampling: 'lttb',
      data: seriesData(props.up),
      lineStyle: { width: 2, color: UP_COLOR },
      itemStyle: { color: UP_COLOR },
      areaStyle: areaGradient(UP_COLOR),
    },
  ],
}))
</script>

<template>
  <VChart class="traffic-chart" :option="option" :style="{ height: `${height}px` }" autoresize />
</template>

<style scoped>
.traffic-chart {
  width: 100%;
}
</style>
