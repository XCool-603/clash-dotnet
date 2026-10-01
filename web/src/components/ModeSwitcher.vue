<script setup lang="ts">
import { computed } from 'vue'

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

const MODE_LABELS: Record<ClashMode, string> = {
  rule: 'Rule',
  global: 'Global',
  direct: 'Direct',
}

const MODE_HINTS: Record<ClashMode, string> = {
  rule: 'Route traffic by the rule set',
  global: 'Send everything through the selected proxy',
  direct: 'Bypass all proxies',
}

const modes = computed(() => CLASH_MODES.map((mode) => ({ value: mode, label: MODE_LABELS[mode] })))

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
    <el-tooltip
      v-for="item in modes"
      :key="item.value"
      :content="MODE_HINTS[item.value]"
      placement="bottom"
    >
      <el-radio-button :value="item.value">{{ item.label }}</el-radio-button>
    </el-tooltip>
  </el-radio-group>
</template>

<style scoped lang="scss">
.mode-switcher {
  flex-wrap: nowrap;
}
</style>
