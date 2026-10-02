<script setup lang="ts">
import { computed } from 'vue'

import { useI18n } from '@/i18n'

const props = withDefaults(
  defineProps<{
    online: boolean
    /** Overrides the derived text entirely. */
    label?: string
    onlineText?: string
    offlineText?: string
    /** Show a pulsing halo while connected. */
    pulse?: boolean
  }>(),
  {
    label: '',
    onlineText: '',
    offlineText: '',
    pulse: true,
  },
)

const { t } = useI18n()

const text = computed<string>(() => {
  if (props.label) return props.label
  if (props.online) return props.onlineText || t('status.connected')
  return props.offlineText || t('status.disconnected')
})
</script>

<template>
  <span class="status-pill" :class="online ? 'is-online' : 'is-offline'">
    <span class="status-pill__dot" :class="{ 'is-pulsing': online && pulse }" />
    <span class="status-pill__text">{{ text }}</span>
  </span>
</template>

<style scoped lang="scss">
.status-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 10px 3px 8px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 550;
  line-height: 18px;
  border: 1px solid transparent;
  white-space: nowrap;

  &.is-online {
    color: var(--app-success);
    background: rgba(34, 197, 94, 0.12);
    border-color: rgba(34, 197, 94, 0.35);
  }

  &.is-offline {
    color: var(--app-danger);
    background: rgba(239, 68, 68, 0.12);
    border-color: rgba(239, 68, 68, 0.35);
  }
}

.status-pill__dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: currentColor;
  flex: none;
}

.status-pill__dot.is-pulsing {
  animation: status-pulse 2s ease-in-out infinite;
}

@keyframes status-pulse {
  0%,
  100% {
    box-shadow: 0 0 0 0 currentColor;
    opacity: 1;
  }
  50% {
    box-shadow: 0 0 0 4px transparent;
    opacity: 0.55;
  }
}
</style>
