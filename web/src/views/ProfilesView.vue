<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  Check,
  Delete,
  DocumentAdd,
  Edit,
  Plus,
  Refresh,
  Search,
  Upload,
  View,
} from '@element-plus/icons-vue'

import EmptyState from '@/components/EmptyState.vue'
import ErrorState from '@/components/ErrorState.vue'
import YamlEditor from '@/components/YamlEditor.vue'
import { useI18n, type MessageKey } from '@/i18n'
import { useConfigStore } from '@/stores/config'
import { useProfilesStore } from '@/stores/profiles'
import type { Profile } from '@/types'
import { formatBytes, formatExpiry, formatRelative, percentage } from '@/utils/format'

const profiles = useProfilesStore()
const config = useConfigStore()
const { t } = useI18n()

/** Preview and edit share one dialog; only the heading and the lock differ. */
type EditorMode = 'preview' | 'edit'

const EDITOR_TITLES: Record<EditorMode, MessageKey> = {
  preview: 'profiles.previewTitle',
  edit: 'profiles.editTitle',
}

const createOpen = ref(false)
const createName = ref('')
const createContent = ref('')

const importOpen = ref(false)
const importUrl = ref('')
const importName = ref('')

const editorOpen = ref(false)
const editorMode = ref<EditorMode>('preview')
const editorProfileName = ref('')
const editorProfileId = ref('')
const editorDraft = ref('')

const editorReadonly = computed<boolean>(() => editorMode.value === 'preview')
const editorTitle = computed<string>(() =>
  t(EDITOR_TITLES[editorMode.value], { name: editorProfileName.value }),
)

/** The page needs both the app-level endpoints *and* a meta-capable core. */
const supported = computed<boolean>(() => config.hasMeta && profiles.available)

const profilesByAge = computed<Profile[]>(() =>
  profiles.profiles.slice().sort((a, b) => {
    if (a.selected !== b.selected) return a.selected ? -1 : 1
    return (b.updatedAt ?? '').localeCompare(a.updatedAt ?? '')
  }),
)

function usageText(profile: Profile): string {
  const info = profile.subscriptionInfo
  if (!info) return ''
  const used = (info.upload ?? 0) + (info.download ?? 0)
  const total = info.total ?? 0
  if (total > 0) return t('profiles.usageOf', { used: formatBytes(used), total: formatBytes(total) })
  return t('profiles.usageUsed', { used: formatBytes(used) })
}

function usagePercent(profile: Profile): number | null {
  const info = profile.subscriptionInfo
  if (!info) return null
  return percentage((info.upload ?? 0) + (info.download ?? 0), info.total ?? 0)
}

async function load(): Promise<void> {
  if (!supported.value) return
  await profiles.load()
}

/* ---- activate / update / delete ---------------------------------- */

async function activate(profile: Profile): Promise<void> {
  const result = await profiles.select(profile.id)
  if (result.ok) ElMessage.success(t('profiles.activatedToast', { name: profile.name }))
  else ElMessage.error(result.error.message)
}

async function updateRemote(profile: Profile): Promise<void> {
  const result = await profiles.updateRemote(profile.id)
  if (result.ok) ElMessage.success(t('profiles.updatedToast', { name: profile.name }))
  else ElMessage.error(result.error.message)
}

async function remove(profile: Profile): Promise<void> {
  try {
    await ElMessageBox.confirm(
      t('profiles.deleteConfirm', { name: profile.name }),
      t('profiles.deleteTitle'),
      {
        type: 'warning',
        confirmButtonText: t('action.delete'),
        cancelButtonText: t('action.cancel'),
      },
    )
  } catch {
    return
  }
  const result = await profiles.remove(profile.id)
  if (result.ok) ElMessage.success(t('profiles.deletedToast', { name: profile.name }))
  else ElMessage.error(result.error.message)
}

/* ---- create ------------------------------------------------------ */

function openCreate(): void {
  createName.value = ''
  createContent.value = 'mixed-port: 7890\nmode: rule\n'
  createOpen.value = true
}

async function submitCreate(): Promise<void> {
  const name = createName.value.trim()
  if (name.length === 0) {
    ElMessage.warning(t('profiles.nameRequired'))
    return
  }
  const result = await profiles.create({ name, type: 'local', content: createContent.value })
  if (result.ok) {
    createOpen.value = false
    ElMessage.success(t('profiles.createdToast', { name }))
  } else {
    ElMessage.error(result.error.message)
  }
}

/* ---- import ------------------------------------------------------ */

function openImport(): void {
  importUrl.value = ''
  importName.value = ''
  profiles.clearParse()
  importOpen.value = true
}

async function checkSubscription(): Promise<void> {
  const url = importUrl.value.trim()
  if (url.length === 0) return
  const result = await profiles.parseSubscription(url)
  if (result.ok) {
    const count = result.data.count ?? result.data.nodes?.length ?? 0
    ElMessage.success(t('profiles.parsedToast', { count }))
  } else {
    ElMessage.error(result.error.message)
  }
}

async function submitImport(): Promise<void> {
  const url = importUrl.value.trim()
  if (url.length === 0) {
    ElMessage.warning(t('profiles.urlRequired'))
    return
  }
  const name = importName.value.trim()
  const result = await profiles.importUrl(url, name.length > 0 ? name : undefined)
  if (result.ok) {
    importOpen.value = false
    ElMessage.success(t('profiles.importedToast'))
  } else {
    ElMessage.error(result.error.message)
  }
}

/* ---- YAML editor / preview --------------------------------------- */

async function openEditor(profile: Profile, readonly: boolean): Promise<void> {
  editorMode.value = readonly ? 'preview' : 'edit'
  editorProfileName.value = profile.name
  editorProfileId.value = profile.id
  editorDraft.value = ''
  editorOpen.value = true

  const result = await profiles.loadPreview(profile.id)
  if (result.ok) editorDraft.value = result.data.content
}

async function saveEditor(): Promise<void> {
  const id = editorProfileId.value
  if (id.length === 0) return
  const result = await profiles.saveContent(id, editorDraft.value)
  if (result.ok) {
    editorOpen.value = false
    ElMessage.success(t('profiles.savedToast'))
  } else {
    ElMessage.error(result.error.message)
  }
}

onMounted(() => {
  void load()
})
</script>

<template>
  <div class="app-page">
    <div class="app-page__head">
      <div>
        <h2 class="app-page__title">{{ t('nav.profiles') }}</h2>
        <p class="app-page__subtitle">{{ t('profiles.subtitle') }}</p>
      </div>

      <div v-if="supported" class="toolbar">
        <el-button :icon="Refresh" :loading="profiles.loading" @click="load">
          {{ t('action.refresh') }}
        </el-button>
        <el-button :icon="Upload" @click="openImport">{{ t('profiles.importUrl') }}</el-button>
        <el-button type="primary" :icon="Plus" @click="openCreate">{{ t('profiles.new') }}</el-button>
      </div>
    </div>

    <!-- Capability gate: a stock core (or a backend without the profile API)
         gets an explanation, not a broken page. -->
    <EmptyState
      v-if="!supported"
      :title="t('profiles.unavailable.title')"
      :description="
        config.hasMeta
          ? t('profiles.unavailable.metaCore')
          : t('profiles.unavailable.stockCore')
      "
      :hint="
        t('profiles.unavailable.hint', {
          version: config.versionLabel,
          meta: String(config.hasMeta),
        })
      "
    />

    <template v-else>
      <ErrorState v-if="profiles.error" class="mb-16" :error="profiles.error" @retry="load" />

      <EmptyState
        v-if="profilesByAge.length === 0 && !profiles.loading"
        :title="t('profiles.empty.title')"
        :description="t('profiles.empty.description')"
      >
        <template #actions>
          <el-button :icon="Upload" @click="openImport">{{ t('profiles.importUrl') }}</el-button>
          <el-button type="primary" :icon="Plus" @click="openCreate">{{ t('profiles.new') }}</el-button>
        </template>
      </EmptyState>

      <div v-else class="profile-grid">
        <article
          v-for="profile in profilesByAge"
          :key="profile.id"
          class="app-panel profile-card"
          :class="{ 'is-selected': profile.selected }"
        >
          <header class="profile-card__head">
            <span class="profile-card__name ellipsis">{{ profile.name }}</span>
            <el-tag size="small" effect="plain" :type="profile.type === 'remote' ? 'success' : 'info'">
              {{ profile.type }}
            </el-tag>
            <el-tag v-if="profile.selected" size="small" type="primary" effect="dark">
              <el-icon><Check /></el-icon>
              {{ t('profiles.active') }}
            </el-tag>
          </header>

          <p class="text-faint profile-card__meta">
            {{ t('profiles.updated', { time: formatRelative(profile.updatedAt) }) }}
          </p>
          <p v-if="profile.url" class="text-faint profile-card__meta mono ellipsis">
            {{ profile.url }}
          </p>

          <div v-if="profile.subscriptionInfo" class="profile-card__usage">
            <el-progress
              v-if="usagePercent(profile) !== null"
              :percentage="Math.round(usagePercent(profile) ?? 0)"
              :stroke-width="6"
              :show-text="false"
            />
            <p class="text-faint profile-card__meta">
              {{ usageText(profile) }}
              <template v-if="profile.subscriptionInfo.expire">
                · {{ t('profiles.expires', { date: formatExpiry(profile.subscriptionInfo.expire) }) }}
              </template>
            </p>
          </div>

          <div class="profile-card__actions">
            <el-button
              size="small"
              type="primary"
              :icon="Check"
              :disabled="profile.selected"
              :loading="profiles.busyId === profile.id"
              @click="activate(profile)"
            >
              {{ t('profiles.activate') }}
            </el-button>
            <el-button size="small" :icon="View" @click="openEditor(profile, true)">{{ t('profiles.preview') }}</el-button>
            <el-button size="small" :icon="Edit" @click="openEditor(profile, false)">{{ t('action.edit') }}</el-button>
            <el-button
              v-if="profile.type === 'remote'"
              size="small"
              :icon="Refresh"
              :loading="profiles.busyId === profile.id"
              @click="updateRemote(profile)"
            >
              {{ t('action.update') }}
            </el-button>
            <el-button
              size="small"
              type="danger"
              plain
              :icon="Delete"
              :loading="profiles.busyId === profile.id"
              @click="remove(profile)"
            >
              {{ t('action.delete') }}
            </el-button>
          </div>
        </article>
      </div>
    </template>

    <!-- create -->
    <el-dialog v-model="createOpen" :title="t('profiles.create.title')" width="720px" append-to-body>
      <el-form label-position="top">
        <el-form-item :label="t('profiles.create.name')">
          <el-input v-model="createName" :placeholder="t('profiles.create.namePlaceholder')" />
        </el-form-item>
        <el-form-item :label="t('profiles.create.content')">
          <YamlEditor v-model="createContent" :min-height="320" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createOpen = false">{{ t('action.cancel') }}</el-button>
        <el-button type="primary" :loading="profiles.saving" @click="submitCreate">{{ t('profiles.create.submit') }}</el-button>
      </template>
    </el-dialog>

    <!-- import -->
    <el-dialog v-model="importOpen" :title="t('profiles.import.title')" width="560px" append-to-body>
      <el-form label-position="top">
        <el-form-item :label="t('profiles.import.url')">
          <el-input v-model="importUrl" :placeholder="t('profiles.import.urlPlaceholder')" clearable />
        </el-form-item>
        <el-form-item :label="t('profiles.import.name')">
          <el-input v-model="importName" :placeholder="t('profiles.import.namePlaceholder')" clearable />
        </el-form-item>
      </el-form>

      <el-alert
        v-if="profiles.parsedSubscription"
        type="success"
        :closable="false"
        show-icon
        :title="t('profiles.import.parsed', { count: profiles.parsedSubscription.count ?? profiles.parsedSubscription.nodes?.length ?? 0 })"
      />
      <ErrorState
        v-if="profiles.parseError"
        inline
        :error="profiles.parseError"
        @retry="checkSubscription"
      />

      <template #footer>
        <el-button :icon="Search" :loading="profiles.parsing" @click="checkSubscription">
          {{ t('profiles.import.check') }}
        </el-button>
        <el-button @click="importOpen = false">{{ t('action.cancel') }}</el-button>
        <el-button type="primary" :loading="profiles.importing" @click="submitImport">
          {{ t('action.import') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- preview / edit -->
    <el-dialog v-model="editorOpen" :title="editorTitle" width="900px" append-to-body>
      <div class="editor-host">
        <ErrorState
          v-if="profiles.previewError"
          class="mb-12"
          inline
          hide-retry
          :error="profiles.previewError"
        />
        <div v-else-if="profiles.previewLoading" class="editor-loading text-muted">
          {{ t('profiles.loading') }}
        </div>
        <YamlEditor v-else v-model="editorDraft" :readonly="editorReadonly" :min-height="440" />
      </div>
      <template #footer>
        <el-button @click="editorOpen = false">{{ t('action.close') }}</el-button>
        <el-button
          v-if="!editorReadonly"
          type="primary"
          :icon="DocumentAdd"
          :loading="profiles.saving"
          @click="saveEditor"
        >
          {{ t('action.save') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped lang="scss">
.toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.profile-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 12px;
}

.profile-card {
  padding: 14px;
  display: flex;
  flex-direction: column;
  gap: 6px;

  &.is-selected {
    border-color: var(--app-accent);
    box-shadow: inset 3px 0 0 var(--app-accent);
  }
}

.profile-card__head {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.profile-card__name {
  font-weight: 600;
  font-size: 14px;
  flex: 1 1 auto;
  min-width: 0;
}

.profile-card__meta {
  margin: 0;
  font-size: 12px;
}

.profile-card__usage {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin: 2px 0;
}

.profile-card__actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 8px;
}

.editor-host {
  max-height: 60vh;
  overflow: auto;
}

.editor-loading {
  padding: 24px;
  text-align: center;
  font-size: 13px;
}
</style>
