<script setup lang="ts">
withDefaults(
  defineProps<{
    label: string
    value: string
    hint?: string
    tone?: 'default' | 'up' | 'down' | 'accent' | 'memory'
    /** Shows a subtle shimmer while the first value is pending. */
    loading?: boolean
  }>(),
  {
    hint: '',
    tone: 'default',
    loading: false,
  },
)
</script>

<template>
  <div class="stat-card" :class="[`tone-${tone}`, { 'is-loading': loading }]">
    <div class="stat-card__head">
      <span v-if="$slots.icon" class="stat-card__icon">
        <slot name="icon" />
      </span>
      <span class="stat-card__label">{{ label }}</span>
    </div>
    <div class="stat-card__value mono">{{ value }}</div>
    <div v-if="hint || $slots.hint" class="stat-card__hint">
      <slot name="hint">{{ hint }}</slot>
    </div>
  </div>
</template>

<style scoped lang="scss">
.stat-card {
  position: relative;
  background: var(--app-surface);
  border: 1px solid var(--app-border);
  border-radius: var(--app-radius);
  padding: 14px 16px;
  overflow: hidden;
  min-width: 0;

  &::before {
    content: '';
    position: absolute;
    inset: 0 auto 0 0;
    width: 3px;
    background: var(--card-accent, var(--app-border-strong));
  }

  &.tone-up {
    --card-accent: #f59e0b;
  }

  &.tone-down {
    --card-accent: #3b82f6;
  }

  &.tone-accent {
    --card-accent: #8b5cf6;
  }

  &.tone-memory {
    --card-accent: #14b8a6;
  }
}

.stat-card__head {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--app-text-muted);
  font-size: 12px;
  font-weight: 550;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.stat-card__icon {
  display: inline-flex;
  align-items: center;
  font-size: 14px;
  color: var(--card-accent, var(--app-text-muted));
}

.stat-card__value {
  margin-top: 6px;
  font-size: 22px;
  font-weight: 600;
  line-height: 1.15;
  color: var(--app-text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.stat-card__hint {
  margin-top: 3px;
  font-size: 12px;
  color: var(--app-text-faint);
  min-height: 16px;
}

.stat-card.is-loading .stat-card__value {
  opacity: 0.5;
}
</style>
