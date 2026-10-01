<script setup lang="ts">
import { computed, ref } from 'vue'

const props = withDefaults(
  defineProps<{
    modelValue: string
    readonly?: boolean
    minHeight?: number
    placeholder?: string
  }>(),
  {
    readonly: false,
    minHeight: 360,
    placeholder: '',
  },
)

const emit = defineEmits<{ 'update:modelValue': [value: string] }>()

const gutter = ref<HTMLDivElement | null>(null)

/** One entry per logical line, used to render the gutter. */
const lineNumbers = computed<number[]>(() => {
  const count = props.modelValue.split('\n').length
  return Array.from({ length: Math.max(count, 1) }, (_, index) => index + 1)
})

function onInput(event: Event): void {
  const target = event.target
  if (target instanceof HTMLTextAreaElement) emit('update:modelValue', target.value)
}

/** Keep the gutter glued to the textarea's vertical scroll position. */
function onScroll(event: Event): void {
  const target = event.target
  if (target instanceof HTMLTextAreaElement && gutter.value) {
    gutter.value.scrollTop = target.scrollTop
  }
}
</script>

<template>
  <div class="yaml-editor" :style="{ minHeight: `${minHeight}px` }">
    <div ref="gutter" class="yaml-editor__gutter mono" aria-hidden="true">
      <span v-for="line in lineNumbers" :key="line" class="yaml-editor__line">{{ line }}</span>
    </div>
    <textarea
      class="yaml-editor__area mono"
      :value="modelValue"
      :readonly="readonly"
      :placeholder="placeholder"
      spellcheck="false"
      autocomplete="off"
      autocapitalize="off"
      wrap="off"
      @input="onInput"
      @scroll="onScroll"
    />
  </div>
</template>

<style scoped lang="scss">
.yaml-editor {
  display: flex;
  align-items: stretch;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-surface-2);
  overflow: hidden;
  height: 100%;
  min-height: 200px;
}

.yaml-editor__gutter {
  flex: none;
  width: 52px;
  padding: 10px 8px 10px 0;
  text-align: right;
  color: var(--app-text-faint);
  background: var(--app-surface-3);
  border-right: 1px solid var(--app-border);
  overflow: hidden;
  user-select: none;
  font-size: 12.5px;
  line-height: 20px;
}

.yaml-editor__line {
  display: block;
  height: 20px;
}

.yaml-editor__area {
  flex: 1 1 auto;
  min-width: 0;
  padding: 10px 12px;
  border: 0;
  outline: none;
  resize: none;
  background: transparent;
  color: var(--app-text);
  font-size: 12.5px;
  line-height: 20px;
  white-space: pre;
  overflow: auto;
  tab-size: 2;

  &::placeholder {
    color: var(--app-text-faint);
  }

  &:read-only {
    color: var(--app-text-muted);
  }
}
</style>
