<script setup lang="ts">
import { computed } from 'vue'
import VChart from 'vue-echarts'
import { LineChart } from 'echarts/charts'
import type { LineSeriesOption } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import type { GridComponentOption, TooltipComponentOption } from 'echarts/components'
import { use, type ComposeOption } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'

import { useSettingsStore } from '@/stores/settings'
import { formatBytes } from '@/utils/format'

use([CanvasRenderer, LineChart, GridComponent, TooltipComponent])

type MemoryChartOption = ComposeOption<LineSeriesOption | GridComponentOption | TooltipComponentOption>

const props = withDefaults(
  defineProps<{
    labels: string[]
    /** In-use memory samples, bytes. */
    values: number[]
    /** Epoch-ms sample times — switches the chart to a real datetime axis. */
    timestamps?: number[]
    /** OS limit, bytes (0 when unknown). */
    limit?: number
    height?: number
  }>(),
  { timestamps: () => [], limit: 0, height: 200 },
)

const MEMORY_COLOR = '#14b8a6'

const settings = useSettingsStore()
const isDark = computed<boolean>(() => settings.theme === 'dark')

const hasTimeAxis = computed<boolean>(
  () => props.timestamps.length > 0 && props.timestamps.length === props.values.length,
)

const windowStart = computed<number | undefined>(() =>
  hasTimeAxis.value ? props.timestamps[0] : undefined,
)
const windowEnd = computed<number | undefined>(() =>
  hasTimeAxis.value ? props.timestamps[props.timestamps.length - 1] : undefined,
)

function seriesData(): number[] | [number, number][] {
  if (!hasTimeAxis.value) return props.values
  return props.values.map((value, index) => [props.timestamps[index] ?? 0, value] as [number, number])
}

const axisColor = computed<string>(() => (isDark.value ? '#6b7280' : '#98a2b3'))
const splitColor = computed<string>(() =>
  isDark.value ? 'rgba(148, 163, 184, 0.13)' : 'rgba(16, 24, 40, 0.07)',
)

const option = computed<MemoryChartOption>(() => ({
  animation: false,
  grid: { left: 62, right: 18, top: 16, bottom: 26 },
  tooltip: {
    trigger: 'axis',
    confine: true,
    backgroundColor: isDark.value ? '#1c232c' : '#ffffff',
    borderColor: isDark.value ? '#2a323d' : '#e0e4ea',
    textStyle: { color: isDark.value ? '#e6edf3' : '#1f2329', fontSize: 12 },
    valueFormatter: (value: unknown) => formatBytes(Number(value)),
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
      formatter: (value: number) => formatBytes(value, 0),
    },
    splitLine: { lineStyle: { color: splitColor.value } },
  },
  series: [
    {
      name: 'Memory',
      type: 'line',
      smooth: true,
      showSymbol: false,
      data: seriesData(),
      lineStyle: { width: 2, color: MEMORY_COLOR },
      itemStyle: { color: MEMORY_COLOR },
      areaStyle: {
        color: {
          type: 'linear',
          x: 0,
          y: 0,
          x2: 0,
          y2: 1,
          colorStops: [
            { offset: 0, color: `${MEMORY_COLOR}59` },
            { offset: 1, color: `${MEMORY_COLOR}05` },
          ],
          global: false,
        },
      },
      markLine:
        props.limit > 0
          ? {
              silent: true,
              symbol: 'none',
              label: { formatter: 'OS limit', color: axisColor.value, fontSize: 10 },
              lineStyle: { color: '#f97316', type: 'dashed', width: 1 },
              data: [{ yAxis: props.limit }],
            }
          : undefined,
    },
  ],
}))
</script>

<template>
  <VChart class="memory-chart" :option="option" :style="{ height: `${height}px` }" autoresize />
</template>

<style scoped>
.memory-chart {
  width: 100%;
}
</style>
