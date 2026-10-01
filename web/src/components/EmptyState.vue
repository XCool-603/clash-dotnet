<script setup lang="ts">
withDefaults(
  defineProps<{
    title: string
    description?: string
    /** Small hint line rendered under the description. */
    hint?: string
  }>(),
  {
    description: '',
    hint: '',
  },
)
</script>

<template>
  <div class="empty-state">
    <div class="empty-state__glyph">
      <slot name="icon">◍</slot>
    </div>
    <p class="empty-state__title">{{ title }}</p>
    <p v-if="description" class="empty-state__description">{{ description }}</p>
    <p v-if="hint" class="empty-state__hint mono">{{ hint }}</p>
    <div v-if="$slots.actions" class="empty-state__actions">
      <slot name="actions" />
    </div>
  </div>
</template>

<style scoped lang="scss">
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 40px 20px;
  gap: 4px;
  color: var(--app-text-muted);
}

.empty-state__glyph {
  font-size: 30px;
  line-height: 1;
  opacity: 0.45;
  margin-bottom: 6px;
}

.empty-state__title {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
  color: var(--app-text);
}

.empty-state__description {
  margin: 0;
  font-size: 13px;
  max-width: 520px;
}

.empty-state__hint {
  margin: 4px 0 0;
  font-size: 12px;
  color: var(--app-text-faint);
  max-width: 520px;
  word-break: break-all;
}

.empty-state__actions {
  margin-top: 12px;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: center;
}
</style>
