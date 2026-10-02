<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Check, Delete, Moon, Refresh, Sunny, SwitchButton } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'

import ErrorState from '@/components/ErrorState.vue'
import StatusPill from '@/components/StatusPill.vue'
import YamlEditor from '@/components/YamlEditor.vue'
import { useConfigStore } from '@/stores/config'
import { useSettingsStore } from '@/stores/settings'
import { messageOf } from '@/utils/async'
import { formatRelative } from '@/utils/format'

type DraftParse = { ok: true; value: Record<string, unknown> } | { ok: false; message: string }

const settings = useSettingsStore()
const config = useConfigStore()

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
  ElMessage.success('Connection settings reset to their defaults')
}

/* ---- appearance --------------------------------------------------- */

function onThemeChange(value: unknown): void {
  settings.setTheme(value === 'light' ? 'light' : 'dark')
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
  if (text.length === 0) return { ok: false, message: 'The editor is empty.' }
  try {
    const value: unknown = JSON.parse(text)
    if (!isPlainObject(value)) return { ok: false, message: 'The document must be a JSON object.' }
    return { ok: true, value }
  } catch (error) {
    return { ok: false, message: `Invalid JSON — ${messageOf(error)}` }
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
    ElMessage.info('Nothing to apply — the document matches the running configuration.')
    return
  }

  busy.value = 'apply'
  const applied = await config.patch(patch)
  busy.value = ''

  if (applied.ok) {
    ElMessage.success('Configuration applied — hot reload, the core was not restarted')
    seedDraft()
  } else {
    ElMessage.error(applied.error.message)
  }
}

async function reloadFromFile(): Promise<void> {
  const path = reloadPath.value.trim()
  if (path.length === 0) {
    ElMessage.warning('A configuration path is required')
    return
  }

  busy.value = 'reload'
  const result = await config.reloadProfile(path, true)
  busy.value = ''

  if (result.ok) {
    ElMessage.success('Configuration reloaded from disk')
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

  if (result.ok) ElMessage.success('Fake-IP cache flushed')
  else if (result.error.isMissing) ElMessage.warning('This core does not expose POST /cache/fakeip/flush')
  else ElMessage.error(result.error.message)
}

async function flushDns(): Promise<void> {
  busy.value = 'dns'
  const result = await config.flushDns()
  busy.value = ''

  if (result.ok) ElMessage.success('DNS cache flushed')
  else if (result.error.isMissing) ElMessage.warning('This core does not expose POST /cache/dns/flush')
  else ElMessage.error(result.error.message)
}

async function restartCore(): Promise<void> {
  try {
    await ElMessageBox.confirm(
      'Restart the Clash core process? Active connections will be dropped.',
      'Restart core',
      { type: 'warning', confirmButtonText: 'Restart', cancelButtonText: 'Cancel' },
    )
  } catch {
    return
  }

  busy.value = 'restart'
  const result = await config.restartCore()
  busy.value = ''

  if (result.ok) ElMessage.success('Restart requested')
  else if (result.error.isMissing) ElMessage.warning('This core does not expose POST /restart (embed mode omits it)')
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
        <h2 class="app-page__title">Settings</h2>
        <p class="app-page__subtitle">
          Connection, appearance and the running configuration · mode {{ config.mode }} ·
          core {{ config.versionLabel }}
        </p>
      </div>
      <StatusPill
        :online="config.online"
        :label="config.unauthorized ? 'Secret required' : undefined"
      />
    </div>

    <!-- connection -->
    <section class="app-panel app-panel--pad settings-section">
      <header class="panel-head">
        <h3 class="app-section-title">Connection</h3>
        <span class="text-faint panel-head__note">
          <template v-if="config.lastSync > 0">synced {{ formatRelative(config.lastSync) }}</template>
          <template v-else>not synced yet</template>
        </span>
      </header>

      <el-form label-position="top">
        <div class="form-grid">
          <el-form-item label="Same origin">
            <div class="field-row">
              <el-switch :model-value="settings.sameOrigin" @change="onSameOriginChange" />
              <span class="text-faint field-note">Talk to the origin that served this page.</span>
            </div>
          </el-form-item>

          <el-form-item label="API base URL">
            <el-input
              :model-value="settings.apiBaseUrl"
              :disabled="settings.sameOrigin"
              placeholder="http://127.0.0.1:9090"
              @change="onApiBaseChange"
            />
          </el-form-item>

          <el-form-item label="Secret">
            <el-input
              :model-value="settings.secret"
              type="password"
              show-password
              placeholder="external-controller secret"
              @change="onSecretChange"
            />
          </el-form-item>

          <el-form-item label="Effective target">
            <span class="target mono ellipsis" :title="settings.targetLabel">
              {{ settings.targetLabel }}
            </span>
          </el-form-item>
        </div>
      </el-form>

      <div class="action-row">
        <el-button :icon="Refresh" @click="resetConnection">Reset connection</el-button>
        <span class="text-faint field-note">
          The secret is sent as <code>Authorization: Bearer …</code> on REST and as
          <code>?token=</code> on WebSockets. Both values live in this browser's local storage.
        </span>
      </div>
    </section>

    <!-- appearance -->
    <section class="app-panel app-panel--pad settings-section mt-16">
      <h3 class="app-section-title">Appearance</h3>
      <div class="action-row">
        <el-radio-group :model-value="settings.theme" @change="onThemeChange">
          <el-radio-button value="dark">
            <el-icon><Moon /></el-icon>
            Dark
          </el-radio-button>
          <el-radio-button value="light">
            <el-icon><Sunny /></el-icon>
            Light
          </el-radio-button>
        </el-radio-group>
        <el-button text @click="settings.toggleTheme()">Toggle theme</el-button>
      </div>
      <p class="text-faint section-note">The theme is stored in this browser only.</p>
    </section>

    <!-- configuration -->
    <section class="app-panel app-panel--pad settings-section mt-16">
      <header class="panel-head">
        <h3 class="app-section-title">Configuration</h3>
        <span class="text-faint panel-head__note">
          <code>GET /configs</code>
          <template v-if="config.configAvailable"> · loaded</template>
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
        The editor holds the general configuration object as JSON. Applying sends only the keys you
        changed to <code>PATCH /configs</code>, which the core merges into the running document and
        applies in place: the reload is hot, so the process keeps running and active connections are
        not dropped.
      </p>

      <div class="editor-host">
        <YamlEditor v-model="draft" :min-height="380" placeholder="Loading configuration…" />
      </div>

      <div class="action-row">
        <el-button
          type="primary"
          :icon="Check"
          :loading="busy === 'apply'"
          :disabled="parseError.length > 0"
          @click="applyConfig"
        >
          Apply changes
        </el-button>
        <el-button :icon="Refresh" :loading="config.loading" @click="loadConfig">
          Reload from core
        </el-button>
        <span class="grow" />
        <span v-if="parseError" class="text-danger field-note">{{ parseError }}</span>
        <span v-else-if="changeCount === 0" class="text-faint field-note">no changes</span>
        <span v-else class="text-faint field-note">{{ changeCount }} key(s) changed</span>
      </div>

      <h4 class="app-section-title mt-16 sub-title">Reload from a file</h4>
      <div class="reload-row">
        <el-input v-model="reloadPath" class="grow" placeholder="config.yaml" />
        <el-button :icon="Refresh" :loading="busy === 'reload'" @click="reloadFromFile">
          Reload
        </el-button>
      </div>
      <p class="text-faint section-note">
        <code>PUT /configs?force=true</code> re-reads the whole document from disk. This is a hot
        reload too: listeners, rules and providers are rebuilt in place without restarting the core.
      </p>
    </section>

    <!-- maintenance -->
    <section class="app-panel app-panel--pad settings-section mt-16">
      <h3 class="app-section-title">Maintenance</h3>
      <p class="text-faint section-note">
        Cache flushes are safe to repeat; restarting the core drops every active connection, so it
        asks first. An action this core does not implement answers <code>404</code>, which is
        reported as "not supported" rather than as a failure.
      </p>

      <div class="action-row">
        <el-button :icon="Delete" :loading="busy === 'fakeip'" @click="flushFakeIp">
          Flush fake-IP cache
        </el-button>
        <el-button :icon="Refresh" :loading="busy === 'dns'" @click="flushDns">
          Flush DNS cache
        </el-button>
        <el-button :icon="SwitchButton" :loading="busy === 'restart'" @click="restartCore">
          Restart core
        </el-button>
      </div>

      <h4 class="app-section-title mt-16 sub-title">Core</h4>
      <div class="core-row">
        <el-tag class="mono" size="small" type="info" effect="plain">{{ config.versionLabel }}</el-tag>
        <el-tag size="small" :type="config.hasMeta ? 'success' : 'warning'" effect="plain">
          {{ config.hasMeta ? 'mihomo' : 'core' }}
        </el-tag>
        <span class="text-faint field-note">
          mode {{ config.mode }} · log level {{ config.logLevel }} ·
          DNS {{ config.dnsEnabled ? 'on' : 'off' }} · TUN {{ config.tunEnabled ? 'on' : 'off' }}
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
