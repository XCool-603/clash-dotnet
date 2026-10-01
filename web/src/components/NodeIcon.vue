<script setup lang="ts">
import { computed, ref } from 'vue'

import { isImageIcon } from '@/utils/format'

const props = withDefaults(
  defineProps<{
    /** The `icon` field from a ProxyObject — usually a URL, sometimes an emoji. */
    icon?: string
    name: string
    size?: number
  }>(),
  {
    icon: '',
    size: 18,
  },
)

const failed = ref(false)

const asImage = computed<boolean>(() => !failed.value && isImageIcon(props.icon))
const initial = computed<string>(() => {
  const trimmed = props.name.trim()
  return trimmed.length > 0 ? trimmed.charAt(0).toUpperCase() : '?'
})

function onImageError(): void {
  failed.value = true
}
</script>

<template>
  <span
    class="node-icon"
    :style="{ width: `${size}px`, height: `${size}px`, fontSize: `${Math.max(9, size - 6)}px` }"
  >
    <img v-if="asImage" :src="icon" :alt="name" loading="lazy" @error="onImageError" />
    <template v-else-if="icon">{{ icon }}</template>
    <template v-else>{{ initial }}</template>
  </span>
</template>

<style scoped lang="scss">
.node-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: none;
  border-radius: 4px;
  background: var(--app-surface-3);
  border: 1px solid var(--app-border);
  overflow: hidden;
  font-weight: 600;
  color: var(--app-text-muted);
  line-height: 1;
  user-select: none;

  img {
    width: 100%;
    height: 100%;
    object-fit: cover;
    display: block;
  }
}
</style>
