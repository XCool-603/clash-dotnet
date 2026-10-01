<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Key, Refresh } from '@element-plus/icons-vue'

import { useSettingsStore } from '@/stores/settings'

const props = withDefaults(
  defineProps<{
    /** Rendered when the backend rejected the current credentials. */
    unauthorized: boolean
    /** Rendered when the backend could not be reached at all. */
    offline?: boolean
  }>(),
  { offline: false },
)

const emit = defineEmits<{ retry: [] }>()

const settings = useSettingsStore()
const draft = ref<string>(settings.secret)

watch(
  () => settings.secret,
  (value) => {
    draft.value = value
  },
)

const visible = computed<boolean>(() => props.unauthorized || props.offline)

const title = computed<string>(() => {
  if (props.unauthorized) return 'The API secret is missing or incorrect'
  return 'Cannot reach the Clash API'
})

const description = computed<string>(() => {
  if (props.unauthorized) {
    return 'This Clash instance requires a secret. Enter it below — it is stored locally in your browser and sent as an Authorization header (and as ?token= for WebSockets).'
  }
  return `The dashboard could not connect to ${settings.targetLabel}. Check that the backend is running and that the API address is right.`
})

function save(): void {
  settings.setSecret(draft.value.trim())
  emit('retry')
}

function retry(): void {
  emit('retry')
}
</script>

<template>
  <div v-if="visible" class="secret-prompt">
    <div class="secret-prompt__body">
      <p class="secret-prompt__title">
        <el-icon><Key /></el-icon>
        <span>{{ title }}</span>
      </p>
      <p class="secret-prompt__description">{{ description }}</p>
    </div>

    <div class="secret-prompt__actions">
      <el-input
        v-model="draft"
        class="secret-prompt__input"
        type="password"
        show-password
        clearable
        placeholder="API secret"
        @keyup.enter="save"
      />
      <el-button type="primary" :icon="Key" @click="save">Save secret</el-button>
      <el-button :icon="Refresh" @click="retry">Retry</el-button>
    </div>
  </div>
</template>

<style scoped lang="scss">
.secret-prompt {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
  padding: 12px 16px;
  border-radius: var(--app-radius);
  border: 1px solid rgba(234, 179, 8, 0.4);
  background: rgba(234, 179, 8, 0.09);
  margin-bottom: 16px;
}

.secret-prompt__body {
  flex: 1 1 380px;
  min-width: 0;
}

.secret-prompt__title {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 0;
  font-weight: 600;
  font-size: 13px;
  color: var(--app-warning);
}

.secret-prompt__description {
  margin: 3px 0 0;
  font-size: 12.5px;
  color: var(--app-text-muted);
}

.secret-prompt__actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.secret-prompt__input {
  width: 220px;
}
</style>
