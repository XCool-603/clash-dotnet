<script setup lang="ts">
import { computed } from 'vue'
import { Refresh, WarningFilled } from '@element-plus/icons-vue'

import type { ApiError } from '@/api/client'
import { useI18n } from '@/i18n'

const props = withDefaults(
  defineProps<{
    error: ApiError | null
    title?: string
    /** Hide the retry button. */
    hideRetry?: boolean
    /** Render as a compact inline banner instead of a block. */
    inline?: boolean
  }>(),
  {
    title: '',
    hideRetry: false,
    inline: false,
  },
)

const emit = defineEmits<{ retry: [] }>()
const { t } = useI18n()

const heading = computed<string>(() => {
  if (props.title) return props.title
  const error = props.error
  if (!error) return t('error.generic')
  switch (error.kind) {
    case 'unauthorized':
      return t('error.unauthorized')
    case 'network':
      return t('error.network')
    case 'timeout':
      return t('error.timeout')
    case 'not-found':
      return t('error.notFound')
    case 'server':
      return t('error.server')
    default:
      return t('error.failed')
  }
})

const detail = computed<string | null>(() => {
  const error = props.error
  if (!error) return null
  const parts: string[] = []
  if (error.status !== null) parts.push(`HTTP ${error.status}`)
  parts.push(`${error.method} ${error.url}`)
  if (error.detail && error.detail !== error.message) parts.push(error.detail)
  return parts.join(' · ')
})
</script>

<template>
  <div v-if="error" class="error-state" :class="{ 'is-inline': inline }">
    <el-icon class="error-state__icon"><WarningFilled /></el-icon>
    <div class="error-state__body">
      <p class="error-state__title">{{ heading }}</p>
      <p class="error-state__message">{{ error.message }}</p>
      <p v-if="detail" class="error-state__detail mono">{{ detail }}</p>
    </div>
    <el-button
      v-if="!hideRetry"
      class="error-state__retry"
      size="small"
      :icon="Refresh"
      @click="emit('retry')"
    >
      {{ t('action.retry') }}
    </el-button>
  </div>
</template>

<style scoped lang="scss">
.error-state {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 16px;
  border-radius: var(--app-radius);
  border: 1px solid rgba(239, 68, 68, 0.35);
  background: rgba(239, 68, 68, 0.08);
  color: var(--app-text);

  &.is-inline {
    padding: 10px 12px;
    align-items: center;
  }
}

.error-state__icon {
  color: var(--app-danger);
  font-size: 18px;
  margin-top: 2px;
  flex: none;
}

.error-state__body {
  flex: 1 1 auto;
  min-width: 0;
}

.error-state__title {
  margin: 0;
  font-weight: 600;
  font-size: 13px;
}

.error-state__message {
  margin: 2px 0 0;
  font-size: 13px;
  color: var(--app-text-muted);
}

.error-state__detail {
  margin: 4px 0 0;
  font-size: 11px;
  color: var(--app-text-faint);
  word-break: break-all;
}

.error-state__retry {
  flex: none;
}
</style>
