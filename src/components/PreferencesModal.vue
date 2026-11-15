<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 ui-modal-backdrop">
    <div class="w-full max-w-3xl max-h-[85vh] ui-modal-surface rounded-3xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
      <span class="lens-edge-lip" aria-hidden="true"></span>
      
      <!-- 顶栏 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-6 py-4 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-700 dark:text-sky-300 shrink-0">
            <AppIcon name="settings" :size="18" />
          </div>
          <div>
            <h3 class="text-sm font-bold flex items-center gap-2" style="color: var(--text-primary)">
              <span>{{ t('preferences.modalTitle') }}</span>
              <span class="text-[11px] ui-num px-2 py-0.5 rounded-full bg-sky-500/12 text-sky-700 dark:text-sky-300 border border-sky-500/25 font-bold">
                {{ APP_VERSION }}
              </span>
            </h3>
            <div class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">
              {{ t('preferences.modalSubtitle') }}
            </div>
          </div>
        </div>

        <button @click="$emit('close')" class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer" :title="t('common.close')">
          <AppIcon name="close" :size="15" />
        </button>
      </header>

      <!-- 分组导航与主体内容 -->
      <div class="flex-1 flex flex-col sm:flex-row overflow-hidden min-h-0">
        
        <aside class="w-full sm:w-48 border-b sm:border-b-0 sm:border-r p-3 flex sm:flex-col gap-1.5 shrink-0 text-xs overflow-x-auto" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
          <button v-for="tab in preferenceTabs" :key="tab.id" @click="activeTab = tab.id"
            :class="[
              'px-3 py-2 rounded-xl font-semibold flex items-center gap-2.5 transition-colors text-left cursor-pointer shrink-0',
              activeTab === tab.id ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300 font-bold border border-sky-500/30' : 'hover:bg-black/5 dark:hover:bg-white/5'
            ]"
            :style="activeTab !== tab.id ? { color: 'var(--text-secondary)' } : undefined">
            <AppIcon :name="tab.icon" :size="14" />
            <span>{{ tab.label }}</span>
          </button>
        </aside>

        <div class="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-5" style="background: var(--surface-content)">

          <!-- 1. 运行环境与多轨自愈设置 -->
          <div v-show="activeTab === 'environment'" class="space-y-4">
            <div class="border-b pb-2" style="border-color: var(--border-subtle)">
              <h4 class="text-xs font-bold" style="color: var(--text-primary)">{{ t('preferences.environment.title') }}</h4>
              <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">{{ t('preferences.environment.subtitle') }}</p>
            </div>

            <div class="p-3.5 ui-sub-card flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">{{ t('preferences.environment.startupReminder') }}</div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">{{ t('preferences.environment.startupReminderDesc') }}</div>
              </div>
              <label class="relative inline-flex items-center cursor-pointer shrink-0">
                <input type="checkbox" :checked="notifyOnDegradedStartup" @change="toggleStartupEnvReminder" class="sr-only peer">
                <div class="w-11 h-6 bg-slate-300 dark:bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-sky-500"></div>
              </label>
            </div>

            <div class="p-4 ui-sub-card bg-sky-500/8 border-sky-500/25 flex items-center justify-between gap-3 flex-wrap">
              <div>
                <div class="text-xs font-bold text-sky-700 dark:text-sky-300">
                  {{ t('preferences.environment.statusScore', { score: envScore ?? '--' }) }}
                </div>
                <div class="text-[11px] mt-1 ui-num" style="color: var(--text-secondary)">
                  {{ missingCount === 0 ? t('preferences.environment.statusReady') : t('preferences.environment.statusMissing', { count: missingCount }) }}
                </div>
              </div>
              <button @click.stop="$emit('openDiagnostic')" class="ui-btn-primary px-3.5 py-1.5 rounded-xl font-bold text-xs shrink-0">
                <AppIcon name="shield" :size="13" />
                <span>{{ t('preferences.environment.openInspector') }}</span>
              </button>
            </div>
          </div>

          <!-- 2. 版本更新 -->
          <div v-show="activeTab === 'updates'" class="space-y-4">
            <div class="border-b pb-2" style="border-color: var(--border-subtle)">
              <h4 class="text-xs font-bold" style="color: var(--text-primary)">{{ t('preferences.updates.title') }}</h4>
              <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">{{ t('preferences.updates.subtitle') }}</p>
            </div>

            <div class="p-4 ui-sub-card flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div>
                <div class="flex items-center gap-2">
                  <span class="text-xs font-bold" style="color: var(--text-primary)">{{ t('preferences.updates.currentVersion') }}</span>
                  <span class="text-xs ui-num font-bold" style="color: var(--accent-primary-text)">{{ APP_VERSION }}</span>
                  <span class="text-[11px] px-2 py-0.5 rounded-full bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 font-bold border border-emerald-500/25">v{{ APP_VERSION }} Latest</span>
                </div>
                <div class="text-[11px] mt-1" style="color: var(--text-muted)">{{ t('preferences.updates.officialRepo') }}</div>
              </div>

              <button @click="checkForUpdates" :disabled="isCheckingUpdate" class="ui-btn-primary px-4 py-2 rounded-xl font-bold text-xs shrink-0">
                <AppIcon name="refresh" :size="13" :class="isCheckingUpdate ? 'animate-spin' : ''" />
                <span>{{ isCheckingUpdate ? t('preferences.updates.checking') : t('preferences.updates.checkNow') }}</span>
              </button>
            </div>

            <div class="p-3.5 ui-sub-card flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">{{ t('preferences.updates.autoCheck') }}</div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">{{ t('preferences.updates.autoCheckDesc') }}</div>
              </div>
              <label class="relative inline-flex items-center cursor-pointer shrink-0">
                <input type="checkbox" v-model="autoCheckUpdate" @change="saveAutoCheckUpdate" class="sr-only peer">
                <div class="w-11 h-6 bg-slate-300 dark:bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-sky-500"></div>
              </label>
            </div>

            <div v-if="updateResult" class="p-4 rounded-2xl border"
              :class="updateResult.has_update ? 'bg-emerald-500/10 border-emerald-500/30' : 'ui-sub-card'">
              
              <div v-if="updateResult.has_update" class="space-y-3">
                <div class="flex items-center justify-between flex-wrap gap-2">
                  <div class="flex items-center gap-2">
                    <span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                    <span class="text-xs font-bold text-emerald-700 dark:text-emerald-300">
                      {{ t('preferences.updates.newVersionTitle', { version: updateResult.latest_version }) }}
                    </span>
                    <span class="text-[11px] ui-num" style="color: var(--text-muted)">({{ updateResult.published_at.substring(0, 10) }})</span>
                  </div>
                  <div class="flex items-center gap-2">
                    <button @click="openLink(updateResult.download_url)" class="ui-btn-primary px-3 py-1.5 rounded-xl font-bold text-xs">
                      <AppIcon name="download" :size="12" />
                      <span>{{ t('preferences.updates.downloadPackage') }}</span>
                    </button>
                    <button @click="openLink(updateResult.html_url)" class="ui-btn-secondary px-3 py-1.5 rounded-xl text-xs font-semibold">
                      {{ t('preferences.updates.viewRelease') }}
                    </button>
                  </div>
                </div>

                <div class="p-3 ui-content-card text-xs ui-num space-y-1 select-text">
                  <div class="font-bold" style="color: var(--text-primary)">{{ updateResult.release_name }}</div>
                  <div class="text-[11px] whitespace-pre-wrap max-h-36 overflow-y-auto custom-scrollbar" style="color: var(--text-secondary)">{{ updateResult.release_notes }}</div>
                </div>
              </div>

              <div v-else class="flex items-center justify-between text-xs" style="color: var(--text-secondary)">
                <div class="flex items-center gap-2">
                  <AppIcon name="check" :size="14" class="text-emerald-600 dark:text-emerald-400" />
                  <span>{{ t('preferences.updates.latestVersionDesc', { version: updateResult.current_version }) }}</span>
                </div>
                <span class="text-[11px] ui-num" style="color: var(--text-muted)">GitHub Releases</span>
              </div>
            </div>
          </div>

          <!-- 3. 视觉与桌面布局偏好 -->
          <div v-show="activeTab === 'appearance'" class="space-y-4">
            <div class="border-b pb-2" style="border-color: var(--border-subtle)">
              <h4 class="text-xs font-bold" style="color: var(--text-primary)">{{ t('preferences.appearance.title') }}</h4>
              <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">{{ t('preferences.appearance.subtitle') }}</p>
            </div>

            <div class="p-3.5 ui-sub-card flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">{{ t('preferences.appearance.themeMode') }}</div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">{{ t('preferences.appearance.themeModeDesc') }}</div>
              </div>
              <button @click="$emit('toggleTheme')" class="ui-btn-secondary px-3.5 py-1.5 rounded-xl text-xs font-semibold shrink-0">
                <AppIcon :name="isLight ? 'sun' : 'moon'" :size="14" />
                <span>{{ isLight ? t('preferences.appearance.themeLight') : t('preferences.appearance.themeDark') }}</span>
              </button>
            </div>

            <div class="p-3.5 ui-sub-card flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">{{ t('preferences.appearance.sidebarLayout') }}</div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">{{ t('preferences.appearance.sidebarLayoutDesc') }}</div>
              </div>
              <button @click="$emit('toggleDock')" class="ui-btn-secondary px-3.5 py-1.5 rounded-xl text-xs font-semibold shrink-0">
                <span>{{ isDockExpanded ? t('preferences.appearance.sidebarExpanded') : t('preferences.appearance.sidebarCollapsed') }}</span>
              </button>
            </div>
          </div>

          <!-- 4. 存储与数据引擎 -->
          <div v-show="activeTab === 'storage'" class="space-y-4">
            <div class="border-b pb-2" style="border-color: var(--border-subtle)">
              <h4 class="text-xs font-bold" style="color: var(--text-primary)">{{ t('preferences.storage.title') }}</h4>
              <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">{{ t('preferences.storage.subtitle') }}</p>
            </div>

            <div class="p-3.5 ui-sub-card flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">{{ t('preferences.storage.sealPeriod') }}</div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">{{ t('preferences.storage.sealPeriodDesc') }}</div>
              </div>
              <span class="text-xs ui-num font-bold text-sky-700 dark:text-sky-300 bg-sky-500/12 px-2.5 py-1 rounded-xl border border-sky-500/25 shrink-0">
                {{ t('preferences.storage.sealPeriodValue') }}
              </span>
            </div>

            <!-- 抓包截断策略 (SnaplenMode) -->
            <div class="p-3.5 ui-sub-card space-y-2.5">
              <div class="flex items-center justify-between gap-3">
                <div>
                  <div class="text-xs font-bold" style="color: var(--text-primary)">{{ t('preferences.storage.snaplenTitle') }}</div>
                  <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">{{ t('preferences.storage.snaplenDesc') }}</div>
                </div>
                <div class="flex items-center gap-1.5 p-1 rounded-xl bg-black/5 dark:bg-white/5 border border-[var(--border-subtle)] shrink-0 text-xs">
                  <button @click="saveSnaplenMode('full')"
                    class="px-3 py-1 rounded-lg font-semibold transition-colors cursor-pointer"
                    :class="snaplenMode === 'full' ? 'bg-sky-500 text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'">
                    {{ locale === 'en-US' ? 'Full Packet (Full)' : '全量完整包 (Full)' }}
                  </button>
                  <button @click="saveSnaplenMode('header_only')"
                    class="px-3 py-1 rounded-lg font-semibold transition-colors cursor-pointer"
                    :class="snaplenMode === 'header_only' ? 'bg-sky-500 text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'">
                    {{ locale === 'en-US' ? 'Header Only (96B)' : '仅抓头 (96B)' }}
                  </button>
                </div>
              </div>
            </div>

            <!-- 滚动切卷落盘配置 -->
            <div class="p-4 ui-sub-card space-y-3">
              <div class="flex items-center justify-between gap-3">
                <div>
                  <div class="text-xs font-bold" style="color: var(--text-primary)">{{ locale === 'en-US' ? 'Rolling PCAP & Disk Quotas' : '自动切卷与磁盘配额 (Rolling PCAP)' }}</div>
                  <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Automatically rotate dumps based on volume size and disk capacity limits.' : '按单卷体积与总磁盘容量配额自动轮转落盘。' }}</div>
                </div>
                <label class="relative inline-flex items-center cursor-pointer shrink-0">
                  <input type="checkbox" v-model="rollingCfg.enabled" class="sr-only peer">
                  <div class="w-11 h-6 bg-slate-300 dark:bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-sky-500"></div>
                </label>
              </div>

              <div v-if="rollingCfg.enabled" class="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs">
                <div>
                  <div class="text-[10px] mb-1" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Dump Directory' : '输出存储目录' }}</div>
                  <input v-model.trim="rollingCfg.output_dir" type="text" class="ui-input w-full px-2 py-1 text-xs" />
                </div>
                <div>
                  <div class="text-[10px] mb-1" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Volume Max (MB)' : '单卷上限 (MB)' }}</div>
                  <input v-model.number="rollingCfg.max_size_mb" type="number" min="1" max="4096" class="ui-input w-full px-2 py-1 text-xs" />
                </div>
                <div>
                  <div class="text-[10px] mb-1" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Total Disk Quota (GB)' : '总磁盘配额 (GB)' }}</div>
                  <input v-model.number="rollingCfg.max_quota_gb" type="number" min="1" max="1024" class="ui-input w-full px-2 py-1 text-xs" />
                </div>
              </div>
              <div class="flex justify-end">
                <button @click="saveRollingPcapConfig" class="ui-btn-primary px-3 py-1 rounded-xl text-xs font-semibold">
                  {{ t('common.save') }}
                </button>
              </div>
            </div>

            <div class="p-3.5 rounded-2xl bg-rose-500/8 border border-rose-500/25 flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold text-rose-700 dark:text-rose-300">{{ locale === 'en-US' ? 'Flush Buffer Pool & Kernel Logs' : '清空捕获缓冲池与内核日志' }}</div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-secondary)">{{ locale === 'en-US' ? 'Releases in-memory decoded frames and log buffers without affecting disk PCAPs.' : '释放内存中已解码报文与日志缓存，不影响磁盘持久化 PCAP。' }}</div>
              </div>
              <button @click="$emit('clearData')" class="ui-btn-danger px-3.5 py-1.5 rounded-xl font-bold text-xs shrink-0">
                {{ t('common.clear') }}
              </button>
            </div>
          </div>

          <!-- 5. 语言偏好设置中心 (i18n Multi-Language) -->
          <div v-show="activeTab === 'language'" class="space-y-4">
            <div class="border-b pb-2" style="border-color: var(--border-subtle)">
              <h4 class="text-xs font-bold" style="color: var(--text-primary)">{{ t('preferences.language.title') }}</h4>
              <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">{{ t('preferences.language.subtitle') }}</p>
            </div>

            <div class="p-4 ui-sub-card space-y-3">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">{{ t('preferences.language.currentLanguage') }}</div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">{{ t('preferences.language.currentLanguageDesc') }}</div>
              </div>

              <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                <button
                  type="button"
                  @click="setLocale('zh-CN')"
                  class="p-3.5 rounded-2xl border text-left transition-all cursor-pointer flex items-center justify-between"
                  :class="locale === 'zh-CN' ? 'bg-sky-500/15 border-sky-500/50 shadow-xs' : 'ui-sub-card hover:bg-black/5 dark:hover:bg-white/5'">
                  <div class="space-y-1">
                    <div class="text-xs font-bold" :class="locale === 'zh-CN' ? 'text-sky-700 dark:text-sky-300' : 'text-[var(--text-primary)]'">
                      {{ t('preferences.language.zhCN') }}
                    </div>
                    <div class="text-[11px]" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Standard industrial technical vocabulary' : '工业级标准技术词汇 · 符合公文规约' }}</div>
                  </div>
                  <span v-if="locale === 'zh-CN'" class="w-2.5 h-2.5 rounded-full bg-sky-500 shrink-0"></span>
                </button>

                <button
                  type="button"
                  @click="setLocale('en-US')"
                  class="p-3.5 rounded-2xl border text-left transition-all cursor-pointer flex items-center justify-between"
                  :class="locale === 'en-US' ? 'bg-sky-500/15 border-sky-500/50 shadow-xs' : 'ui-sub-card hover:bg-black/5 dark:hover:bg-white/5'">
                  <div class="space-y-1">
                    <div class="text-xs font-bold" :class="locale === 'en-US' ? 'text-sky-700 dark:text-sky-300' : 'text-[var(--text-primary)]'">
                      {{ t('preferences.language.enUS') }}
                    </div>
                    <div class="text-[11px]" style="color: var(--text-muted)">RFC / IEEE / ISO Standardized Terminology</div>
                  </div>
                  <span v-if="locale === 'en-US'" class="w-2.5 h-2.5 rounded-full bg-sky-500 shrink-0"></span>
                </button>
              </div>

              <div class="text-[11px] flex items-center gap-1.5 pt-1 text-emerald-600 dark:text-emerald-400">
                <AppIcon name="check" :size="12" />
                <span>{{ t('preferences.language.effectiveImmediately') }}</span>
              </div>
            </div>
          </div>

        </div>

      </div>

      <!-- 底栏 -->
      <footer class="px-6 py-3 border-t flex items-center justify-between shrink-0 text-xs ui-num" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-muted)">
        <span>{{ locale === 'en-US' ? 'Ctrl+, open preferences anytime' : 'Ctrl+, 随时呼出偏好设置' }}</span>
        <button @click="$emit('close')" class="ui-btn-primary px-4 py-1.5 rounded-xl font-semibold">
          {{ t('common.close') }}
        </button>
      </footer>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { openUrl } from '@tauri-apps/plugin-opener';
import { notifySuccess, notifyError, notifyInfo } from '../composables/useNotification';
import { APP_VERSION } from '../constants/appVersion';
import { useI18n } from '../i18n';
import AppIcon from './AppIcon.vue';

const props = defineProps<{
  isOpen: boolean;
  isLight: boolean;
  isDockExpanded: boolean;
}>();

defineEmits(['close', 'toggleTheme', 'toggleDock', 'openDiagnostic', 'clearData']);

const { t, locale, setLocale } = useI18n();

type TabId = 'environment' | 'updates' | 'appearance' | 'storage' | 'language';

interface PreferenceTab {
  id: TabId;
  label: string;
  icon: string;
}

const preferenceTabs = computed<PreferenceTab[]>(() => [
  { id: 'environment', label: t('preferences.tabs.environment'), icon: 'shield' },
  { id: 'updates', label: t('preferences.tabs.updates'), icon: 'refresh' },
  { id: 'appearance', label: t('preferences.tabs.appearance'), icon: 'sliders' },
  { id: 'storage', label: t('preferences.tabs.storage'), icon: 'database' },
  { id: 'language', label: t('preferences.tabs.language'), icon: 'globe' },
]);

const activeTab = ref<TabId>('environment');

import { useEnvironmentInspector } from '../composables/useEnvironmentInspector';

const {
  envScore,
  missingCount,
  notifyOnDegradedStartup,
  setStartupReminderEnabled,
} = useEnvironmentInspector();

function toggleStartupEnvReminder() {
  setStartupReminderEnabled(!notifyOnDegradedStartup.value);
}

// 2. 版本更新设置项
const autoCheckUpdate = ref(localStorage.getItem('omni_probe_auto_check_update') !== 'false');
function saveAutoCheckUpdate() {
  localStorage.setItem('omni_probe_auto_check_update', autoCheckUpdate.value ? 'true' : 'false');
  notifySuccess(locale.value === 'en-US' ? 'Update policy saved' : '更新策略已保存', autoCheckUpdate.value ? (locale.value === 'en-US' ? 'Enabled auto check on startup' : '已开启开机自动检查新版本') : (locale.value === 'en-US' ? 'Disabled auto check on startup' : '已关闭开机自动检查更新'));
}

const isCheckingUpdate = ref(false);
const updateResult = ref<any | null>(null);

async function checkForUpdates() {
  isCheckingUpdate.value = true;
  try {
    const res: any = await invoke('check_app_update_cmd');
    updateResult.value = res;
    if (res.has_update) {
      notifySuccess(locale.value === 'en-US' ? 'New release discovered' : '发现新版本发布', locale.value === 'en-US' ? `Release ${res.latest_version} is available for download` : `最新版本 ${res.latest_version} 已就绪，可一键下载更新`);
    } else {
      notifyInfo(locale.value === 'en-US' ? 'Version check complete' : '版本检查完成', locale.value === 'en-US' ? 'Omni-Probe is already running the latest stable release' : '当前探针系统已是最新稳定版本');
    }
  } catch (e: any) {
    notifyError(locale.value === 'en-US' ? 'Update check blocked' : '检查更新受阻', e || (locale.value === 'en-US' ? 'Cannot connect to GitHub Releases API, please check network' : '无法连接 GitHub Releases API，请检查网络'));
  } finally {
    isCheckingUpdate.value = false;
  }
}

async function openLink(url: string) {
  if (!url) return;
  try {
    await openUrl(url);
  } catch (e) {
    notifyError(locale.value === 'en-US' ? 'Failed to launch system browser' : '无法唤起系统浏览器打开链接', String(e));
  }
}

// 4. 存证与滚动 PCAP / Snaplen 策略状态
interface BackendRollingConfig {
  enabled: boolean;
  output_dir: string;
  max_file_size_bytes: number;
  max_file_duration_secs: number;
  max_disk_quota_bytes: number;
  snaplen_mode: 'Full' | { HeaderOnly: number } | string;
}

const snaplenMode = ref<'full' | 'header_only'>('full');
const rollingCfg = ref({
  enabled: false,
  output_dir: './captures',
  max_size_mb: 50,
  max_duration_secs: 3600,
  max_quota_gb: 2,
});

async function loadStorageEngineConfig() {
  try {
    const cfg = await invoke<BackendRollingConfig>('get_rolling_pcap_config_cmd');
    rollingCfg.value = {
      enabled: cfg.enabled,
      output_dir: cfg.output_dir || './captures',
      max_size_mb: Math.max(1, Math.round(cfg.max_file_size_bytes / (1024 * 1024))),
      max_duration_secs: cfg.max_file_duration_secs || 3600,
      max_quota_gb: Math.max(1, Math.round(cfg.max_disk_quota_bytes / (1024 * 1024 * 1024))),
    };
    snaplenMode.value = cfg.snaplen_mode === 'Full' ? 'full' : 'header_only';
  } catch (e) {
    console.warn('[PreferencesModal] 获取滚动落盘配置失败:', e);
  }
}

async function saveSnaplenMode(mode: 'full' | 'header_only') {
  try {
    snaplenMode.value = mode;
    const msg = await invoke<string>('set_snaplen_mode_cmd', { mode, limit: mode === 'header_only' ? 96 : null });
    notifySuccess(locale.value === 'en-US' ? 'Truncation policy updated' : '抓包截断策略已更新', msg);
  } catch (e) {
    notifyError(locale.value === 'en-US' ? 'Failed to set snaplen' : '设置 Snaplen 失败', String(e));
  }
}

async function saveRollingPcapConfig() {
  try {
    const msg = await invoke<string>('set_rolling_pcap_config_cmd', {
      enabled: rollingCfg.value.enabled,
      outputDir: rollingCfg.value.output_dir.trim() || './captures',
      maxSizeMb: Math.max(1, Number(rollingCfg.value.max_size_mb) || 50),
      maxDurationSecs: Math.max(60, Number(rollingCfg.value.max_duration_secs) || 3600),
      maxQuotaGb: Math.max(1, Number(rollingCfg.value.max_quota_gb) || 2),
    });
    notifySuccess(locale.value === 'en-US' ? 'Rolling PCAP configuration applied' : '滚动落盘配置已生效', msg);
  } catch (e) {
    notifyError(locale.value === 'en-US' ? 'Failed to update rolling config' : '更新滚动落盘配置失败', String(e));
  }
}

watch(
  () => props.isOpen,
  (open) => {
    if (open) {
      loadStorageEngineConfig();
    }
  }
);
</script>
