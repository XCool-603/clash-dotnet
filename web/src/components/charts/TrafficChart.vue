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
    /** X-axis labels (one per sample). */
    labels: string[]
    /** Download samples, bytes/second. */
    down: number[]
    /** Upload samples, bytes/second. */
    up: number[]
    height?: number
  }>(),
  { height: 250 },
)

const DOWN_COLOR = '#3b82f6'
const UP_COLOR = '#f59e0b'

const settings = useSettingsStore()
const isDark = computed<boolean>(() => settings.theme === 'dark')

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
  xAxis: {
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
      data: props.down,
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
      data: props.up,
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
