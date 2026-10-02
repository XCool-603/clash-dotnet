<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'
import { RouterView } from 'vue-router'
import en from 'element-plus/es/locale/lang/en'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import type { Language } from 'element-plus/es/locale'

import ErrorState from '@/components/ErrorState.vue'
import SecretPrompt from '@/components/SecretPrompt.vue'
import { useI18n } from '@/i18n'
import DefaultLayout from '@/layouts/DefaultLayout.vue'
import { useConfigStore } from '@/stores/config'

const config = useConfigStore()
const { locale } = useI18n()

/**
 * Element Plus ships its own strings (pagination, date pickers, the table empty
 * text, dialog buttons). Without this the page would be Chinese and its widgets
 * English, so the switcher drives both.
 */
const elementLocale = computed<Language>(() => (locale.value === 'zh-CN' ? zhCn : en))

/**
 * A transport-level failure (the core is down, or on the wrong address) is
 * distinct from an auth failure: one needs a retry, the other needs a secret.
 * `SecretPrompt` owns the 401 case; this owns everything else.
 */
const showTransportError = computed<boolean>(() => {
  const error = config.error
  if (!error) return false
  return error.kind === 'network' || error.kind === 'timeout' || error.kind === 'server'
})

function retry(): void {
  void config.load()
}

onMounted(() => {
  void config.load()
  config.startPolling(5000)
})

onUnmounted(() => {
  config.stopPolling()
})
</script>

<template>
  <el-config-provider :locale="elementLocale">
    <DefaultLayout>
      <div class="app-shell">
        <div class="app-shell__banners">
          <SecretPrompt :unauthorized="config.unauthorized" @retry="retry" />
          <ErrorState
            v-if="showTransportError"
            class="mb-16"
            inline
            :error="config.error"
            @retry="retry"
          />
        </div>

        <RouterView v-slot="{ Component }">
          <component :is="Component" />
        </RouterView>
      </div>
    </DefaultLayout>
  </el-config-provider>
</template>

<style scoped lang="scss">
.app-shell {
  display: flex;
  flex-direction: column;
  min-height: 100%;
}

.app-shell__banners {
  padding: 12px 20px 0;
  max-width: 1800px;
  margin: 0 auto;
  width: 100%;
}

.app-shell__banners:empty {
  display: none;
}
</style>
