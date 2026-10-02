<script setup lang="ts">
import { computed } from 'vue'
import type { CSSProperties } from 'vue'

import { delayColor, delayLevel, formatDelay, withAlpha } from '@/utils/format'
import { latencyBand, type LatencyBand } from '@/utils/delay'
import { useI18n, type MessageKey } from '@/i18n'

const props = withDefaults(
  defineProps<{
    delay: number | null | undefined
    /** Renders "testing…" with a pulsing dot. */
    loading?: boolean
    showDot?: boolean
    /** Tighter padding, for use inside node grids. */
    compact?: boolean
    /** Hide the unit suffix. */
    bare?: boolean
    /**
     * The health-check URL the measurement came from. Drives the
     * protocol-aware thresholds: HTTPS probes get a wider green/yellow band
     * than plain-HTTP ones.
     */
    probeUrl?: string
  }>(),
  {
    loading: false,
    showDot: true,
    compact: false,
    bare: false,
    probeUrl: '',
  },
)

const { t } = useI18n()

const BAND_KEYS: Record<LatencyBand, MessageKey> = {
  good: 'delay.band.good',
  fair: 'delay.band.fair',
  bad: 'delay.band.bad',
  failed: 'delay.band.failed',
  unknown: 'delay.band.unknown',
}

const level = computed<string>(() => delayLevel(props.delay, props.probeUrl))
const color = computed<string>(() => delayColor(props.delay, props.probeUrl))
const band = computed(() => latencyBand(props.delay, props.probeUrl))

const text = computed<string>(() => {
  if (props.loading) return t('delay.testing')
  if (props.bare) {
    const value = props.delay
    if (value === null || value === undefined || !Number.isFinite(value)) return '—'
    if (value <= 0) return t('delay.failed')
    return String(Math.round(value))
  }
  return formatDelay(props.delay)
})

const style = computed<CSSProperties>(() => {
  const plain = level.value === 'unknown'
  return {
    '--delay-color': color.value,
    '--delay-bg': plain ? 'transparent' : withAlpha(color.value, 0.14),
    '--delay-border': plain ? 'var(--app-border)' : withAlpha(color.value, 0.34),
  }
})

const title = computed<string>(() => {
  if (props.loading) return t('delay.inProgress')
  if (props.delay === null || props.delay === undefined) return t('delay.noMeasurement')
  return `${text.value} · ${t(BAND_KEYS[band.value])}`
})
</script>

<template>
  <span
    class="delay-badge"
    :class="[`is-${level}`, { 'is-compact': compact, 'is-loading': loading }]"
    :style="style"
    :title="title"
  >
    <span v-if="showDot" class="delay-badge__dot" />
    <span class="delay-badge__text mono">{{ text }}</span>
  </span>
</template>

<style scoped lang="scss">
.delay-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 1px 8px;
  border-radius: 999px;
  font-size: 12px;
  line-height: 18px;
  font-weight: 550;
  white-space: nowrap;
  color: var(--delay-color);
  background: var(--delay-bg);
  border: 1px solid var(--delay-border);

  &.is-compact {
    padding: 0 6px;
    font-size: 11px;
    line-height: 16px;
    gap: 4px;
  }
}

.delay-badge__dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  flex: none;
}

.delay-badge.is-loading .delay-badge__dot {
  animation: delay-blink 0.9s ease-in-out infinite;
}

.delay-badge__text {
  font-size: inherit;
}

@keyframes delay-blink {
  0%,
  100% {
    opacity: 1;
  }
  50% {
    opacity: 0.2;
  }
}
</style>
