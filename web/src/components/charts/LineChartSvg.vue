<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, useId } from 'vue'

import type { ChartSeries } from '@/components/charts/types'

/**
 * A line chart drawn as SVG.
 *
 * This replaces ECharts, which was the largest dependency in the bundle — more
 * than half the JavaScript the dashboard shipped — for two simple time series.
 * What is needed here is a polyline, a grid, a hover readout and a legend, and
 * that is a few hundred lines rather than half a megabyte.
 *
 * Deliberately not a general charting library: it draws line series against a
 * zero-based value axis, which is what both charts on the dashboard are. The
 * shape of the API says so.
 */

const props = withDefaults(
  defineProps<{
    series: ChartSeries[]
    /** Epoch-ms sample times, one per point. */
    timestamps?: number[]
    /** Pre-formatted x labels, used when `timestamps` is absent. */
    labels?: string[]
    height?: number
    /** Full precision, for the hover readout. */
    valueFormatter: (value: number) => string
    /** Compact, for the value-axis ticks. */
    axisFormatter: (value: number) => string
    /** A dashed horizontal marker, e.g. the OS memory limit. */
    reference?: { value: number; label: string } | null
    ariaLabel?: string
  }>(),
  {
    timestamps: () => [],
    labels: () => [],
    height: 250,
    reference: null,
    ariaLabel: '',
  },
)

/** Room for the value-axis labels, the legend and the time labels. */
const PAD = { left: 62, right: 18, top: 34, bottom: 26 }

/** The value axis is drawn with this many intervals, so one more grid line. */
const TICKS = 4

const uid = useId()
const host = ref<HTMLElement | null>(null)
const width = ref(600)
const hoverIndex = ref<number | null>(null)

/** Series the legend has switched off, by name. */
const hidden = ref<Record<string, boolean>>({})

let observer: ResizeObserver | null = null

onMounted(() => {
  const element = host.value
  if (!element) return

  // The SVG is drawn in real pixels rather than scaled from a viewBox: a
  // non-uniform scale would stretch the stroke widths and the text with it.
  observer = new ResizeObserver((entries) => {
    const measured = entries[0]?.contentRect.width ?? 0
    if (measured > 0) width.value = measured
  })
  observer.observe(element)
  width.value = element.clientWidth || width.value
})

onBeforeUnmount(() => {
  observer?.disconnect()
  observer = null
})

const plot = computed(() => ({
  x: PAD.left,
  y: PAD.top,
  width: Math.max(1, width.value - PAD.left - PAD.right),
  height: Math.max(1, props.height - PAD.top - PAD.bottom),
}))

const visible = computed(() => props.series.filter((entry) => !hidden.value[entry.name]))

/** The longest series wins: a short one simply stops early. */
const count = computed(() =>
  props.series.reduce((longest, entry) => Math.max(longest, entry.values.length), 0),
)

/**
 * Rounds the axis maximum up to a readable number so the ticks land on values
 * a person would choose.
 */
function niceMax(value: number): number {
  if (!Number.isFinite(value) || value <= 0) return 1
  const magnitude = 10 ** Math.floor(Math.log10(value))
  const normalised = value / magnitude
  const step = normalised <= 1 ? 1 : normalised <= 2 ? 2 : normalised <= 5 ? 5 : 10
  return step * magnitude
}

const maxValue = computed(() => {
  let peak = props.reference?.value ?? 0
  for (const entry of visible.value) {
    for (const value of entry.values) {
      if (value > peak) peak = value
    }
  }
  return niceMax(peak)
})

const xAt = (index: number): number => {
  const { x, width: w } = plot.value
  if (count.value <= 1) return x + w
  return x + (index / (count.value - 1)) * w
}

const yAt = (value: number): number => {
  const { y, height: h } = plot.value
  const ratio = maxValue.value > 0 ? value / maxValue.value : 0
  return y + h - Math.min(1, Math.max(0, ratio)) * h
}

/**
 * A cubic through the midpoints of each segment: the standard way to soften a
 * polyline without the overshoot a naive spline produces on spiky data.
 */
function linePath(values: number[]): string {
  if (values.length === 0) return ''
  let path = `M ${xAt(0).toFixed(2)} ${yAt(values[0] ?? 0).toFixed(2)}`

  for (let index = 1; index < values.length; index++) {
    const previousX = xAt(index - 1)
    const previousY = yAt(values[index - 1] ?? 0)
    const currentX = xAt(index)
    const currentY = yAt(values[index] ?? 0)
    const controlX = (previousX + currentX) / 2
    path += ` C ${controlX.toFixed(2)} ${previousY.toFixed(2)}, ${controlX.toFixed(2)} ${currentY.toFixed(2)}, ${currentX.toFixed(2)} ${currentY.toFixed(2)}`
  }

  return path
}

function areaPath(values: number[]): string {
  const line = linePath(values)
  if (!line) return ''
  const base = plot.value.y + plot.value.height
  return `${line} L ${xAt(values.length - 1).toFixed(2)} ${base.toFixed(2)} L ${xAt(0).toFixed(2)} ${base.toFixed(2)} Z`
}

const lines = computed(() =>
  visible.value.map((entry) => ({
    name: entry.name,
    color: entry.color,
    d: linePath(entry.values),
    area: entry.area ? areaPath(entry.values) : '',
  })),
)

const gridLines = computed(() =>
  Array.from({ length: TICKS + 1 }, (_, index) => {
    const value = (maxValue.value / TICKS) * index
    return { value, y: yAt(value), label: props.axisFormatter(value) }
  }),
)

/** At most six time labels, so they never crowd the axis. */
const timeLabels = computed(() => {
  if (count.value === 0) return []
  const wanted = Math.min(6, count.value)
  const step = Math.max(1, Math.round((count.value - 1) / Math.max(1, wanted - 1)))
  const result: { x: number; text: string }[] = []

  for (let index = 0; index < count.value; index += step) {
    result.push({ x: xAt(index), text: labelAt(index) })
  }

  return result
})

function labelAt(index: number): string {
  const stamp = props.timestamps[index]
  if (stamp) {
    const date = new Date(stamp)
    const pad = (value: number) => String(value).padStart(2, '0')
    return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  }
  return props.labels[index] ?? ''
}

const referenceY = computed<number | null>(() => {
  const reference = props.reference
  if (!reference || reference.value <= 0) return null
  return yAt(reference.value)
})

const hovered = computed(() => {
  const index = hoverIndex.value
  if (index === null || count.value === 0) return null

  return {
    index,
    x: xAt(index),
    time: labelAt(index),
    rows: visible.value.map((entry) => ({
      name: entry.name,
      color: entry.color,
      value: props.valueFormatter(entry.values[index] ?? 0),
    })),
  }
})

/** The readout follows the pointer but stays inside the plot. */
const tooltipStyle = computed(() => {
  const point = hovered.value
  if (!point) return {}
  const flip = point.x > plot.value.x + plot.value.width * 0.6
  return {
    left: `${point.x}px`,
    transform: flip ? 'translate(calc(-100% - 12px), 0)' : 'translate(12px, 0)',
  }
})

function onMove(event: MouseEvent): void {
  if (count.value === 0) return
  const bounds = (event.currentTarget as SVGSVGElement).getBoundingClientRect()
  const x = event.clientX - bounds.left
  const ratio = (x - plot.value.x) / plot.value.width
  const index = Math.round(ratio * (count.value - 1))
  hoverIndex.value = Math.min(count.value - 1, Math.max(0, index))
}

function onLeave(): void {
  hoverIndex.value = null
}

function toggle(name: string): void {
  hidden.value = { ...hidden.value, [name]: !hidden.value[name] }
}
</script>

<template>
  <div ref="host" class="line-chart" :style="{ height: `${height}px` }">
    <svg
      class="line-chart__svg"
      :width="width"
      :height="height"
      :viewBox="`0 0 ${width} ${height}`"
      role="img"
      :aria-label="ariaLabel"
      @mousemove="onMove"
      @mouseleave="onLeave"
    >
      <defs>
        <linearGradient v-for="line in lines" :id="`${uid}-${line.name}`" :key="line.name" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" :stop-color="line.color" stop-opacity="0.4" />
          <stop offset="100%" :stop-color="line.color" stop-opacity="0.02" />
        </linearGradient>
      </defs>

      <!-- value axis -->
      <g class="line-chart__grid">
        <template v-for="tick in gridLines" :key="tick.value">
          <line :x1="plot.x" :y1="tick.y" :x2="plot.x + plot.width" :y2="tick.y" />
          <text class="line-chart__axis" :x="plot.x - 8" :y="tick.y + 4" text-anchor="end">
            {{ tick.label }}
          </text>
        </template>
      </g>

      <!-- time axis -->
      <g class="line-chart__grid">
        <text
          v-for="label in timeLabels"
          :key="label.x"
          class="line-chart__axis"
          :x="label.x"
          :y="plot.y + plot.height + 16"
          text-anchor="middle"
        >
          {{ label.text }}
        </text>
      </g>

      <!-- reference marker, e.g. the OS memory limit -->
      <g v-if="referenceY !== null">
        <line
          class="line-chart__reference"
          :x1="plot.x"
          :y1="referenceY"
          :x2="plot.x + plot.width"
          :y2="referenceY"
        />
        <text class="line-chart__axis" :x="plot.x + plot.width" :y="referenceY - 5" text-anchor="end">
          {{ reference?.label }}
        </text>
      </g>

      <!-- series -->
      <g>
        <template v-for="line in lines" :key="line.name">
          <path v-if="line.area" :d="line.area" :fill="`url(#${uid}-${line.name})`" stroke="none" />
          <path :d="line.d" fill="none" :stroke="line.color" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />
        </template>
      </g>

      <!-- hover guide -->
      <line
        v-if="hovered"
        class="line-chart__guide"
        :x1="hovered.x"
        :y1="plot.y"
        :x2="hovered.x"
        :y2="plot.y + plot.height"
      />
    </svg>

    <!-- legend: click to hide a series, as the chart library allowed -->
    <div class="line-chart__legend">
      <button
        v-for="entry in series"
        :key="entry.name"
        type="button"
        class="line-chart__legend-item"
        :class="{ 'is-off': hidden[entry.name] }"
        @click="toggle(entry.name)"
      >
        <span class="line-chart__swatch" :style="{ background: entry.color }" />
        {{ entry.name }}
      </button>
    </div>

    <div v-if="hovered" class="line-chart__tooltip" :style="tooltipStyle">
      <div class="line-chart__tooltip-time">{{ hovered.time }}</div>
      <div v-for="row in hovered.rows" :key="row.name" class="line-chart__tooltip-row">
        <span class="line-chart__swatch" :style="{ background: row.color }" />
        <span class="line-chart__tooltip-name">{{ row.name }}</span>
        <span class="line-chart__tooltip-value mono">{{ row.value }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.line-chart {
  position: relative;
  width: 100%;
}

.line-chart__svg {
  display: block;
  overflow: visible;
}

.line-chart__grid line {
  stroke: var(--app-border);
  stroke-width: 1;
}

.line-chart__axis {
  fill: var(--app-text-faint);
  font-size: 11px;
}

.line-chart__reference {
  stroke: var(--app-text-faint);
  stroke-width: 1;
  stroke-dasharray: 4 4;
}

.line-chart__guide {
  stroke: var(--app-border-strong);
  stroke-width: 1;
}

.line-chart__legend {
  position: absolute;
  top: 0;
  right: 0;
  display: flex;
  gap: 12px;
}

.line-chart__legend-item {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 0;
  border: 0;
  background: none;
  color: var(--app-text-muted);
  font: inherit;
  font-size: 12px;
  cursor: pointer;
}

.line-chart__legend-item.is-off {
  opacity: 0.45;
}

.line-chart__swatch {
  width: 10px;
  height: 10px;
  border-radius: 3px;
  flex: none;
}

.line-chart__tooltip {
  position: absolute;
  top: 34px;
  z-index: 2;
  min-width: 128px;
  padding: 8px 10px;
  border-radius: var(--app-radius);
  border: 1px solid var(--app-border);
  background: var(--app-surface-2);
  box-shadow: var(--app-shadow);
  pointer-events: none;
  font-size: 12px;
}

.line-chart__tooltip-time {
  color: var(--app-text-muted);
  margin-bottom: 4px;
}

.line-chart__tooltip-row {
  display: flex;
  align-items: center;
  gap: 6px;
  line-height: 1.6;
}

.line-chart__tooltip-name {
  color: var(--app-text-muted);
}

.line-chart__tooltip-value {
  margin-left: auto;
  color: var(--app-text);
}
</style>
