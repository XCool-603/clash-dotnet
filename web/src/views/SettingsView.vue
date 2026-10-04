<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Check, Delete, Moon, Refresh, Sunny, SwitchButton } from '@element-plus/icons-vue'

import ErrorState from '@/components/ErrorState.vue'
import StatusPill from '@/components/StatusPill.vue'
import YamlEditor from '@/components/YamlEditor.vue'
import { useI18n, type Locale, type MessageKey } from '@/i18n'
import { useConfigStore } from '@/stores/config'
import { useSettingsStore } from '@/stores/settings'
import type { ClashMode } from '@/types'
import { messageOf } from '@/utils/async'
import { formatRelative } from '@/utils/format'

type DraftParse = { ok: true; value: Record<string, unknown> } | { ok: false; message: string }

/** The core reports the routing mode as a token; the shell owns its wording. */
const MODE_LABELS: Record<ClashMode, MessageKey> = {
  rule: 'mode.rule',
  global: 'mode.global',
  direct: 'mode.direct',
}

const settings = useSettingsStore()
const config = useConfigStore()
const { t, locale, locales, setLocale } = useI18n()

const modeLabel = computed<string>(() => t(MODE_LABELS[config.mode]))

/** The editable general object, and the file the "reload from disk" action reads. */
const draft = ref('')
const reloadPath = ref('')
const busy = ref('')

/* ---- connection --------------------------------------------------- */

// The base URL and secret are committed on blur/enter rather than per keystroke:
// both are watched by the stream composables, which would otherwise tear down and
// reopen every WebSocket on each character.
function onSameOriginChange(value: unknown): void {
  settings.setSameOrigin(value === true)
}

function onApiBaseChange(value: unknown): void {
  if (typeof value === 'string') settings.setApiBaseUrl(value)
}

function onSecretChange(value: unknown): void {
  if (typeof value === 'string') settings.setSecret(value)
}

function resetConnection(): void {
  settings.resetConnection()
  ElMessage.success(t('settings.connection.resetDone'))
}

/* ---- appearance --------------------------------------------------- */

function onThemeChange(value: unknown): void {
  settings.setTheme(value === 'light' ? 'light' : 'dark')
}

/**
 * The language control drives the i18n module (immediate switch) *and* the
 * store (persistence), exactly as the shell's switcher does.
 */
function onLocaleChange(value: unknown): void {
  if (value !== 'en' && value !== 'zh-CN') return
  const next: Locale = value
  setLocale(next)
  settings.setLocale(next)
}

/* ---- configuration ------------------------------------------------ */

/** Re-read the store's snapshot into the editor. */
function seedDraft(): void {
  const current = config.config
  draft.value = current ? JSON.stringify(current, null, 2) : ''

  const path = current?.['profile-path']
  if (typeof path === 'string' && path.length > 0) reloadPath.value = path
}

async function loadConfig(): Promise<void> {
  await config.load()
  seedDraft()
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function sameValue(left: unknown, right: unknown): boolean {
  if (left === right) return true
  try {
    return JSON.stringify(left) === JSON.stringify(right)
  } catch {
    return false
  }
}

/**
 * Only the keys the user actually changed: `PATCH /configs` deep-merges the
 * document, so re-sending the whole snapshot would push the core's own
 * read-only projection fields back into the configuration.
 */
function changedEntries(
  base: Record<string, unknown>,
  next: Record<string, unknown>,
): Record<string, unknown> {
  const patch: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(next)) {
    const before = base[key]
    if (isPlainObject(value) && isPlainObject(before)) {
      const nested = changedEntries(before, value)
      if (Object.keys(nested).length > 0) patch[key] = nested
      continue
    }
    if (!sameValue(value, before)) patch[key] = value
  }
  return patch
}

function countKeys(patch: Record<string, unknown>): number {
  let total = 0
  for (const value of Object.values(patch)) {
    total += isPlainObject(value) ? countKeys(value) : 1
  }
  return total
}

const parsed = computed<DraftParse>(() => {
  const text = draft.value.trim()
  if (text.length === 0) return { ok: false, message: t('settings.config.errorEmpty') }
  try {
    const value: unknown = JSON.parse(text)
    if (!isPlainObject(value)) return { ok: false, message: t('settings.config.errorNotObject') }
    return { ok: true, value }
  } catch (error) {
    return { ok: false, message: t('settings.config.errorInvalid', { message: messageOf(error) }) }
  }
})

const parseError = computed<string>(() => {
  const result = parsed.value
  return result.ok ? '' : result.message
})

const changes = computed<Record<string, unknown>>(() => {
  const result = parsed.value
  if (!result.ok) return {}
  return changedEntries(config.config ?? {}, result.value)
})

const changeCount = computed<number>(() => countKeys(changes.value))

async function applyConfig(): Promise<void> {
  const result = parsed.value
  if (!result.ok) {
    ElMessage.error(result.message)
    return
  }

  const patch = changes.value
  if (Object.keys(patch).length === 0) {
    ElMessage.info(t('settings.config.nothingToApply'))
    return
  }

  busy.value = 'apply'
  const applied = await config.patch(patch)
  busy.value = ''

  if (applied.ok) {
    ElMessage.success(t('settings.config.applied'))
    seedDraft()
  } else {
    ElMessage.error(applied.error.message)
  }
}

async function reloadFromFile(): Promise<void> {
  const path = reloadPath.value.trim()
  if (path.length === 0) {
    ElMessage.warning(t('settings.config.pathRequired'))
    return
  }

  busy.value = 'reload'
  const result = await config.reloadProfile(path, true)
  busy.value = ''

  if (result.ok) {
    ElMessage.success(t('settings.config.reloaded'))
    seedDraft()
  } else {
    ElMessage.error(result.error.message)
  }
}

/* ---- maintenance -------------------------------------------------- */

async function flushFakeIp(): Promise<void> {
  busy.value = 'fakeip'
  const result = await config.flushFakeIp()
  busy.value = ''

  if (result.ok) ElMessage.success(t('settings.maintenance.fakeIpFlushed'))
  else if (result.error.isMissing) ElMessage.warning(t('settings.maintenance.fakeIpUnsupported'))
  else ElMessage.error(result.error.message)
}

async function flushDns(): Promise<void> {
  busy.value = 'dns'
  const result = await config.flushDns()
  busy.value = ''

  if (result.ok) ElMessage.success(t('settings.maintenance.dnsFlushed'))
  else if (result.error.isMissing) ElMessage.warning(t('settings.maintenance.dnsUnsupported'))
  else ElMessage.error(result.error.message)
}

async function restartCore(): Promise<void> {
  try {
    await ElMessageBox.confirm(
      t('settings.maintenance.restartConfirm'),
      t('settings.maintenance.restartCore'),
      {
        type: 'warning',
        confirmButtonText: t('settings.maintenance.restart'),
        cancelButtonText: t('action.cancel'),
      },
    )
  } catch {
    return
  }

  busy.value = 'restart'
  const result = await config.restartCore()
  busy.value = ''

  if (result.ok) ElMessage.success(t('settings.maintenance.restartRequested'))
  else if (result.error.isMissing) ElMessage.warning(t('settings.maintenance.restartUnsupported'))
  else ElMessage.error(result.error.message)
}

onMounted(() => {
  seedDraft()
  void loadConfig()
})
</script>

<template>
  <div class="app-page">
    <div class="app-page__head">
      <div>
        <h2 class="app-page__title">{{ t('nav.settings') }}</h2>
        <p class="app-page__subtitle">
          {{ t('settings.subtitle', { mode: modeLabel, core: config.versionLabel }) }}
        </p>
      </div>
      <StatusPill
        :online="config.online"
        :label="config.unauthorized ? t('status.secretRequired') : undefined"
      />
    </div>

    <!-- connection -->
    <section class="app-panel app-panel--pad settings-section">
      <header class="panel-head">
        <h3 class="app-section-title">{{ t('settings.connection.title') }}</h3>
        <span class="text-faint panel-head__note">
          <template v-if="config.lastSync > 0">
            {{ t('settings.connection.syncedAt', { time: formatRelative(config.lastSync) }) }}
          </template>
          <template v-else>{{ t('settings.connection.neverSynced') }}</template>
        </span>
      </header>

      <el-form label-position="top">
        <div class="form-grid">
          <el-form-item :label="t('settings.connection.sameOrigin')">
            <div class="field-row">
              <el-switch :model-value="settings.sameOrigin" @change="onSameOriginChange" />
              <span class="text-faint field-note">{{ t('settings.connection.sameOriginHint') }}</span>
            </div>
          </el-form-item>

          <el-form-item :label="t('settings.connection.apiBaseUrl')">
            <el-input
              :model-value="settings.apiBaseUrl"
              :disabled="settings.sameOrigin"
              placeholder="http://127.0.0.1:9090"
              @change="onApiBaseChange"
            />
          </el-form-item>

          <el-form-item :label="t('settings.connection.secret')">
            <el-input
              :model-value="settings.secret"
              type="password"
              show-password
              :placeholder="t('settings.connection.secretPlaceholder')"
              @change="onSecretChange"
            />
          </el-form-item>

          <el-form-item :label="t('settings.connection.target')">
            <span class="target mono ellipsis" :title="settings.targetLabel">
              {{ settings.targetLabel }}
            </span>
          </el-form-item>
        </div>
      </el-form>

      <div class="action-row">
        <el-button :icon="Refresh" @click="resetConnection">
          {{ t('settings.connection.reset') }}
        </el-button>
        <span class="text-faint field-note">
          {{ t('settings.connection.secretNotePrefix') }}
          <code>Authorization: Bearer …</code>
          {{ t('settings.connection.secretNoteMiddle') }}
          <code>?token=</code>
          {{ t('settings.connection.secretNoteSuffix') }}
        </span>
      </div>
    </section>

    <!-- appearance -->
    <section class="app-panel app-panel--pad settings-section mt-16">
      <h3 class="app-section-title">{{ t('settings.appearance.title') }}</h3>
      <div class="action-row">
        <el-radio-group :model-value="settings.theme" @change="onThemeChange">
          <el-radio-button value="dark">
            <el-icon><Moon /></el-icon>
            {{ t('settings.appearance.dark') }}
          </el-radio-button>
          <el-radio-button value="light">
            <el-icon><Sunny /></el-icon>
            {{ t('settings.appearance.light') }}
          </el-radio-button>
        </el-radio-group>
        <el-button text @click="settings.toggleTheme()">
          {{ t('settings.appearance.toggleTheme') }}
        </el-button>
      </div>
      <p class="text-faint section-note">{{ t('settings.appearance.themeNote') }}</p>

      <!-- Language: each entry is written in its own language, which is how a
           reader who cannot read the current one finds theirs. -->
      <div class="action-row">
        <span class="text-faint field-note">{{ t('topbar.language') }}</span>
        <el-radio-group :model-value="locale" @change="onLocaleChange">
          <el-radio-button v-for="entry in locales" :key="entry.value" :value="entry.value">
            {{ entry.label }}
          </el-radio-button>
        </el-radio-group>
        <span class="text-faint field-note">{{ t('settings.appearance.languageNote') }}</span>
      </div>
    </section>

    <!-- configuration -->
    <section class="app-panel app-panel--pad settings-section mt-16">
      <header class="panel-head">
        <h3 class="app-section-title">{{ t('settings.config.title') }}</h3>
        <span class="text-faint panel-head__note">
          <code>GET /configs</code>
          <template v-if="config.configAvailable"> · {{ t('settings.config.loaded') }}</template>
        </span>
      </header>

      <ErrorState
        v-if="config.error"
        class="mb-12"
        inline
        :error="config.error"
        @retry="loadConfig"
      />

      <p class="text-faint section-note">
        {{ t('settings.config.descriptionPrefix') }}
        <code>PATCH /configs</code>{{ t('settings.config.descriptionSuffix') }}
      </p>

      <div class="editor-host">
        <YamlEditor
          v-model="draft"
          :min-height="380"
          :placeholder="t('settings.config.loadingPlaceholder')"
        />
      </div>

      <div class="action-row">
        <el-button
          type="primary"
          :icon="Check"
          :loading="busy === 'apply'"
          :disabled="parseError.length > 0"
          @click="applyConfig"
        >
          {{ t('settings.config.apply') }}
        </el-button>
        <el-button :icon="Refresh" :loading="config.loading" @click="loadConfig">
          {{ t('settings.config.reloadFromCore') }}
        </el-button>
        <span class="grow" />
        <span v-if="parseError" class="text-danger field-note">{{ parseError }}</span>
        <span v-else-if="changeCount === 0" class="text-faint field-note">
          {{ t('settings.config.noChanges') }}
        </span>
        <span v-else class="text-faint field-note">
          {{ t('settings.config.changedKeys', { count: changeCount }) }}
        </span>
      </div>

      <h4 class="app-section-title mt-16 sub-title">{{ t('settings.config.reloadFromFile') }}</h4>
      <div class="reload-row">
        <el-input v-model="reloadPath" class="grow" placeholder="config.yaml" />
        <el-button :icon="Refresh" :loading="busy === 'reload'" @click="reloadFromFile">
          {{ t('action.reload') }}
        </el-button>
      </div>
      <p class="text-faint section-note">
        <code>PUT /configs?force=true</code>
        {{ t('settings.config.reloadFileNote') }}
      </p>
    </section>

    <!-- maintenance -->
    <section class="app-panel app-panel--pad settings-section mt-16">
      <h3 class="app-section-title">{{ t('settings.maintenance.title') }}</h3>
      <p class="text-faint section-note">
        {{ t('settings.maintenance.notePrefix') }}
        <code>404</code>{{ t('settings.maintenance.noteSuffix') }}
      </p>

      <div class="action-row">
        <el-button :icon="Delete" :loading="busy === 'fakeip'" @click="flushFakeIp">
          {{ t('settings.maintenance.flushFakeIp') }}
        </el-button>
        <el-button :icon="Refresh" :loading="busy === 'dns'" @click="flushDns">
          {{ t('settings.maintenance.flushDns') }}
        </el-button>
        <el-button :icon="SwitchButton" :loading="busy === 'restart'" @click="restartCore">
          {{ t('settings.maintenance.restartCore') }}
        </el-button>
      </div>

      <h4 class="app-section-title mt-16 sub-title">{{ t('settings.maintenance.core') }}</h4>
      <div class="core-row">
        <el-tag class="mono" size="small" type="info" effect="plain">{{ config.versionLabel }}</el-tag>
        <el-tag size="small" :type="config.hasMeta ? 'success' : 'warning'" effect="plain">
          {{ config.hasMeta ? 'mihomo' : 'core' }}
        </el-tag>
        <span class="text-faint field-note">
          {{
            t('settings.maintenance.coreNote', {
              mode: modeLabel,
              logLevel: config.logLevel,
              dns: t(config.dnsEnabled ? 'state.on' : 'state.off'),
              tun: t(config.tunEnabled ? 'state.on' : 'state.off'),
            })
          }}
        </span>
      </div>
    </section>
  </div>
</template>

<style scoped lang="scss">
.settings-section {
  max-width: 1100px;
}

.panel-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 8px;
}

.panel-head__note {
  font-size: 12px;
}

.sub-title {
  font-size: 13.5px;
}

.field-row {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.field-note {
  font-size: 12px;
  line-height: 1.5;
}

.target {
  display: inline-block;
  max-width: 100%;
  padding: 2px 8px;
  border-radius: 6px;
  background: var(--app-surface-3);
  color: var(--app-text-muted);
  font-size: 12px;
}

.section-note {
  margin: 0 0 10px;
  font-size: 12px;
  line-height: 1.55;
}

.action-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 10px;
}

.editor-host {
  max-height: 56vh;
  overflow: auto;
}

.reload-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 6px;
}

.core-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 6px;
}

code {
  font-family: 'JetBrains Mono', Consolas, monospace;
  font-size: 11.5px;
  background: var(--app-surface-3);
  padding: 1px 4px;
  border-radius: 4px;
}
</style>
