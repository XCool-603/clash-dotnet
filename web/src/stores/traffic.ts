import { computed, ref } from 'vue'
import { defineStore } from 'pinia'

import type { StreamStatus } from '@/utils/ws'

/** Number of one-second samples kept in the sliding window (~120s). */
export const TRAFFIC_WINDOW = 120

function pad(value: number): string {
  return String(value).padStart(2, '0')
}

function clockLabel(date: Date): string {
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

/**
 * Rolling traffic / memory series fed by the `/traffic` and `/memory`
 * WebSocket streams. Kept free of any transport concerns so the charts and
 * cards can simply read it.
 */
export const useTrafficStore = defineStore('traffic', () => {
  const downSeries = ref<number[]>([])
  const upSeries = ref<number[]>([])
  const labels = ref<string[]>([])

  const currentUp = ref(0)
  const currentDown = ref(0)

  const memorySeries = ref<number[]>([])
  const memoryLabels = ref<string[]>([])
  const memoryInuse = ref(0)
  const memoryLimit = ref(0)

  const trafficConnected = ref(false)
  const memoryConnected = ref(false)
  const trafficStatus = ref<StreamStatus>('idle')
  const memoryStatus = ref<StreamStatus>('idle')

  const peakUp = computed<number>(() => (upSeries.value.length > 0 ? Math.max(...upSeries.value) : 0))
  const peakDown = computed<number>(() =>
    downSeries.value.length > 0 ? Math.max(...downSeries.value) : 0,
  )
  const sampleCount = computed<number>(() => downSeries.value.length)

  function pushTraffic(up: number, down: number): void {
    currentUp.value = up
    currentDown.value = down

    const label = clockLabel(new Date())

    const nextUp = upSeries.value.concat(up)
    const nextDown = downSeries.value.concat(down)
    const nextLabels = labels.value.concat(label)

    while (nextUp.length > TRAFFIC_WINDOW) nextUp.shift()
    while (nextDown.length > TRAFFIC_WINDOW) nextDown.shift()
    while (nextLabels.length > TRAFFIC_WINDOW) nextLabels.shift()

    upSeries.value = nextUp
    downSeries.value = nextDown
    labels.value = nextLabels
  }

  function pushMemory(inuse: number, oslimit: number): void {
    memoryInuse.value = inuse
    memoryLimit.value = oslimit

    const next = memorySeries.value.concat(inuse)
    const nextLabels = memoryLabels.value.concat(clockLabel(new Date()))
    while (next.length > TRAFFIC_WINDOW) next.shift()
    while (nextLabels.length > TRAFFIC_WINDOW) nextLabels.shift()

    memorySeries.value = next
    memoryLabels.value = nextLabels
  }

  function setTrafficStatus(status: StreamStatus): void {
    trafficStatus.value = status
    trafficConnected.value = status === 'open'
  }

  function setMemoryStatus(status: StreamStatus): void {
    memoryStatus.value = status
    memoryConnected.value = status === 'open'
  }

  function reset(): void {
    downSeries.value = []
    upSeries.value = []
    labels.value = []
    memorySeries.value = []
    memoryLabels.value = []
    currentUp.value = 0
    currentDown.value = 0
    memoryInuse.value = 0
    memoryLimit.value = 0
  }

  return {
    // state
    downSeries,
    upSeries,
    labels,
    currentUp,
    currentDown,
    memorySeries,
    memoryLabels,
    memoryInuse,
    memoryLimit,
    trafficConnected,
    memoryConnected,
    trafficStatus,
    memoryStatus,
    // getters
    peakUp,
    peakDown,
    sampleCount,
    // actions
    pushTraffic,
    pushMemory,
    setTrafficStatus,
    setMemoryStatus,
    reset,
  }
})
