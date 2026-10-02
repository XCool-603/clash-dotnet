<script setup lang="ts">
import { computed } from 'vue'

import { useI18n, type MessageKey } from '@/i18n'
import type { ClashMode } from '@/types'
import { CLASH_MODES } from '@/types'

const props = withDefaults(
  defineProps<{
    mode: ClashMode
    loading?: boolean
    disabled?: boolean
    size?: 'small' | 'default' | 'large'
  }>(),
  {
    loading: false,
    disabled: false,
    size: 'default',
  },
)

const emit = defineEmits<{ change: [mode: ClashMode] }>()
const { t } = useI18n()

const MODE_LABELS: Record<ClashMode, MessageKey> = {
  rule: 'mode.rule',
  global: 'mode.global',
  direct: 'mode.direct',
}

const MODE_HINTS: Record<ClashMode, MessageKey> = {
  rule: 'mode.ruleHint',
  global: 'mode.globalHint',
  direct: 'mode.directHint',
}

const modes = computed(() =>
  CLASH_MODES.map((mode) => ({ value: mode, label: t(MODE_LABELS[mode]), hint: t(MODE_HINTS[mode]) })),
)

function onChange(value: string | number | boolean | undefined): void {
  emit('change', value as ClashMode)
}
</script>

<template>
  <el-radio-group
    :model-value="mode"
    :size="size"
    :disabled="disabled || loading"
    class="mode-switcher"
    @change="onChange"
  >
    <el-tooltip v-for="item in modes" :key="item.value" :content="item.hint" placement="bottom">
      <el-radio-button :value="item.value">{{ item.label }}</el-radio-button>
    </el-tooltip>
  </el-radio-group>
</template>

<style scoped lang="scss">
.mode-switcher {
  flex-wrap: nowrap;
}
</style>
