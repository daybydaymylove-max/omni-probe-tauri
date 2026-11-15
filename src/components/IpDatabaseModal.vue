<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 ui-modal-backdrop animate-in fade-in duration-150">
    <div class="w-full max-w-2xl ui-modal-surface rounded-3xl flex flex-col overflow-hidden max-h-[88vh]">
      
      <!-- 1. 顶栏 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-6 py-4 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-2.5">
          <span class="w-3 h-3 rounded-full bg-sky-500 shrink-0"></span>
          <div>
            <h3 class="text-sm font-bold flex items-center gap-2 flex-wrap" style="color: var(--text-primary)">
              <span>{{ t('ipDbModal.title') }}</span>
              <span v-if="dbStatus.loaded" class="text-[11px] ui-num px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 font-semibold">
                {{ t('ipDbModal.readyBadge') }}
              </span>
              <span v-else class="text-[11px] ui-num px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 font-semibold">
                {{ t('ipDbModal.notReadyBadge') }}
              </span>
            </h3>
            <p class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">
              {{ t('ipDbModal.subtitle') }}
            </p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer" :title="t('common.close')">
          <AppIcon name="close" :size="15" />
        </button>
      </header>

      <!-- 2. 内容区 -->
      <div class="p-6 overflow-auto custom-scrollbar space-y-4 text-xs select-text" style="background: var(--surface-content)">
        
        <div class="p-4 ui-sub-card grid grid-cols-2 md:grid-cols-4 gap-3 ui-num">
          <div>
            <div class="text-[11px] font-sans" style="color: var(--text-muted)">{{ t('ipDbModal.statusLabel') }}</div>
            <div class="font-bold mt-0.5 flex items-center gap-1" :class="dbStatus.loaded ? 'text-emerald-700 dark:text-emerald-400' : 'text-amber-700 dark:text-amber-400'">
              <AppIcon :name="dbStatus.loaded ? 'check' : 'alert'" :size="13" />
              <span>{{ dbStatus.loaded ? t('ipDbModal.statusLoaded') : t('ipDbModal.statusNotLoaded') }}</span>
            </div>
          </div>
          <div>
            <div class="text-[11px] font-sans" style="color: var(--text-muted)">{{ t('ipDbModal.fileSizeLabel') }}</div>
            <div class="font-bold mt-0.5" style="color: var(--text-primary)">
              {{ dbStatus.file_size > 0 ? (dbStatus.file_size / (1024 * 1024)).toFixed(2) + ' MB' : '0 MB' }}
            </div>
          </div>
          <div>
            <div class="text-[11px] font-sans" style="color: var(--text-muted)">{{ t('ipDbModal.timestampLabel') }}</div>
            <div class="font-bold mt-0.5" style="color: var(--text-primary)">
              {{ dbStatus.created_at > 0 ? formatDate(dbStatus.created_at) : 'N/A' }}
            </div>
          </div>
          <div>
            <div class="text-[11px] font-sans" style="color: var(--text-muted)">{{ t('ipDbModal.pathLabel') }}</div>
            <div class="font-bold truncate mt-0.5" style="color: var(--text-primary)" :title="dbStatus.file_path">
              {{ dbStatus.file_path || t('ipDbModal.notSpecified') }}
            </div>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="ui-content-card p-4 space-y-3 flex flex-col justify-between">
            <div>
              <div class="font-bold flex items-center gap-1.5 mb-1" style="color: var(--text-primary)">
                <AppIcon name="zap" :size="14" class="text-sky-600 dark:text-sky-400" />
                <span>{{ t('ipDbModal.modeATitle') }}</span>
              </div>
              <p class="text-[11px] leading-relaxed" style="color: var(--text-secondary)">
                {{ t('ipDbModal.modeADesc') }}
              </p>
            </div>

            <div>
              <label class="block text-[11px] mb-1 font-medium" style="color: var(--text-muted)">{{ t('ipDbModal.channelLabel') }}</label>
              <select v-model="downloadUrl" class="ui-input ui-num px-2.5 py-1.5 text-xs cursor-pointer">
                <option value="auto">{{ t('ipDbModal.channelAuto') }}</option>
                <option value="https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb">
                  {{ t('ipDbModal.channelJsdelivr') }}
                </option>
                <option value="https://ghfast.top/https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb">
                  {{ t('ipDbModal.channelGhfast') }}
                </option>
                <option value="https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb">
                  {{ t('ipDbModal.channelGithub') }}
                </option>
              </select>
            </div>

            <div v-if="isDownloading" class="space-y-1.5 bg-blue-500/10 p-2.5 rounded-xl border border-blue-500/25 ui-num">
              <div class="flex justify-between text-[11px] text-blue-700 dark:text-sky-300 font-bold">
                <span>{{ downloadStatusText }}</span>
                <span>{{ downloadProgress.percent }}% ({{ downloadProgress.speed_kbps }} KB/s)</span>
              </div>
              <div class="w-full rounded-full h-2 overflow-hidden" style="background: var(--surface-elevated)">
                <div class="bg-sky-500 h-2 transition-all duration-200" :style="{ width: `${downloadProgress.percent}%` }"></div>
              </div>
              <div class="text-[11px] flex justify-between" style="color: var(--text-muted)">
                <span>{{ t('ipDbModal.received') }}: {{ (downloadProgress.downloaded_bytes / (1024 * 1024)).toFixed(2) }} MB</span>
                <span>{{ t('ipDbModal.total') }}: {{ (downloadProgress.total_bytes / (1024 * 1024)).toFixed(2) }} MB</span>
              </div>
            </div>

            <button @click="startDownload" :disabled="isDownloading" class="w-full ui-btn-primary justify-center py-2 rounded-xl font-bold">
              <AppIcon :name="isDownloading ? 'refresh' : 'download'" :size="13" :class="isDownloading ? 'animate-spin' : ''" />
              <span>{{ isDownloading ? t('ipDbModal.btnDownloading') : t('ipDbModal.btnDownload') }}</span>
            </button>
          </div>

          <div class="ui-content-card p-4 space-y-3 flex flex-col justify-between">
            <div>
              <div class="font-bold flex items-center gap-1.5 mb-1" style="color: var(--text-primary)">
                <AppIcon name="shield" :size="14" class="text-emerald-600 dark:text-emerald-400" />
                <span>{{ t('ipDbModal.modeBTitle') }}</span>
              </div>
              <p class="text-[11px] leading-relaxed" style="color: var(--text-secondary)">
                {{ t('ipDbModal.modeBDesc') }}
              </p>
            </div>

            <div>
              <label class="block text-[11px] mb-1 font-medium" style="color: var(--text-muted)">{{ t('ipDbModal.pathInputLabel') }}</label>
              <input v-model="localFilePath" placeholder="如: E:\tools\data\ip2region.xdb" class="ui-input ui-num px-2.5 py-1.5 text-xs">
            </div>

            <div v-if="loadResultMsg" :class="['p-2 rounded-xl text-[11px] border', isLoadError ? 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/30' : 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30']">
              {{ loadResultMsg }}
            </div>

            <button @click="loadLocalFile" :disabled="!localFilePath.trim() || isLoadingLocal" class="w-full ui-btn-secondary justify-center py-2 rounded-xl font-bold">
              <AppIcon :name="isLoadingLocal ? 'refresh' : 'folder'" :size="13" :class="isLoadingLocal ? 'animate-spin' : ''" />
              <span>{{ isLoadingLocal ? t('ipDbModal.btnLoadingLocal') : t('ipDbModal.btnLoadLocal') }}</span>
            </button>
          </div>
        </div>

        <!-- 实时归属地测试工具 -->
        <div class="ui-sub-card p-4 space-y-3">
          <div class="font-bold flex items-center justify-between flex-wrap gap-2" style="color: var(--text-primary)">
            <span class="flex items-center gap-1.5">
              <AppIcon name="search" :size="14" />
              <span>{{ t('ipDbModal.testTitle') }}</span>
            </span>
            <span class="text-[11px] font-normal ui-num" style="color: var(--text-muted)">{{ t('ipDbModal.testLatency') }}</span>
          </div>

          <div class="flex gap-2">
            <input v-model="testIp" :placeholder="t('ipDbModal.testPlaceholder')" class="flex-1 ui-input ui-num px-3 py-1.5 text-xs">
            <button @click="runTestLookup" :disabled="!testIp.trim()" class="ui-btn-primary px-4 py-1.5 rounded-xl font-bold shrink-0">
              {{ t('ipDbModal.btnTest') }}
            </button>
          </div>

          <div v-if="testResult" class="ui-content-card p-3 space-y-1.5 ui-num">
            <div class="flex items-center justify-between border-b pb-1.5 flex-wrap gap-2" style="border-color: var(--border-subtle)">
              <div class="font-bold flex items-center gap-2" style="color: var(--text-primary)">
                <span>{{ testResult.ip }}</span>
                <span class="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-500/12 text-blue-700 dark:text-sky-300 border border-blue-500/25">
                  {{ testResult.zone_name }}
                </span>
                <span class="px-1.5 py-0.5 rounded text-[11px] font-bold ui-pill">
                  {{ testResult.security_level }}
                </span>
              </div>
              <span class="text-[11px] text-emerald-700 dark:text-emerald-300 font-bold bg-emerald-500/12 px-2 py-0.5 rounded border border-emerald-500/25">
                {{ t('ipDbModal.hitOffline') }}
              </span>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] pt-1" style="color: var(--text-secondary)">
              <div>{{ t('ipDbModal.country') }}: <strong style="color: var(--text-primary)">{{ testResult.country || 'N/A' }}</strong></div>
              <div>{{ t('ipDbModal.province') }}: <strong style="color: var(--text-primary)">{{ testResult.province || 'N/A' }}</strong></div>
              <div>{{ t('ipDbModal.city') }}: <strong style="color: var(--text-primary)">{{ testResult.city || 'N/A' }}</strong></div>
              <div>{{ t('ipDbModal.isp') }}: <strong class="text-indigo-700 dark:text-indigo-300 font-bold">{{ testResult.isp || 'N/A' }}</strong></div>
            </div>

            <div class="text-[11px] pt-1" style="color: var(--text-muted)">
              {{ t('ipDbModal.geoSummary') }}: <strong style="color: var(--text-primary)">{{ testResult.geo_summary }}</strong>
            </div>
          </div>
        </div>

      </div>

      <!-- 3. 底栏 -->
      <footer class="px-6 py-3 border-t flex items-center justify-between shrink-0" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
        <span class="text-[11px] ui-num" style="color: var(--text-muted)">{{ t('ipDbModal.footerSource') }}</span>
        <button @click="$emit('close')" class="ui-btn-secondary px-4 py-1.5 rounded-xl text-xs font-semibold">
          {{ t('ipDbModal.finishClose') }}
        </button>
      </footer>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted } from 'vue';
import AppIcon from './AppIcon.vue';
import { useI18n } from '../i18n';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

const props = defineProps<{
  isOpen: boolean;
}>();

const emit = defineEmits(['close', 'log']);

const { t, locale } = useI18n();
void t;
void locale;

interface DbStatus {
  loaded: boolean;
  file_path: string;
  file_size: number;
  created_at: number;
  version: number;
}

const dbStatus = ref<DbStatus>({
  loaded: false,
  file_path: '',
  file_size: 0,
  created_at: 0,
  version: 0,
});

const downloadUrl = ref('auto');
const isDownloading = ref(false);
const downloadStatusText = ref('ready');
const downloadProgress = ref({
  status: 'idle',
  downloaded_bytes: 0,
  total_bytes: 0,
  percent: 0,
  speed_kbps: 0,
});

const localFilePath = ref('data/ip2region.xdb');
const isLoadingLocal = ref(false);
const loadResultMsg = ref('');
const isLoadError = ref(false);

const testIp = ref('114.114.114.114');
const testResult = ref<any | null>(null);

let unlistenProgress: UnlistenFn | null = null;

async function refreshStatus() {
  try {
    dbStatus.value = await invoke<DbStatus>('get_ip_db_status_cmd');
  } catch (e) {
    console.error('获取 IP 库状态失败:', e);
  }
}

function formatDate(ts: number): string {
  if (!ts) return 'N/A';
  const d = new Date(ts * 1000);
  return d.toISOString().replace('T', ' ').slice(0, 19);
}

async function startDownload() {
  isDownloading.value = true;
  downloadStatusText.value = locale.value === 'en-US' ? 'Connecting to download channel...' : '正在连接下载通道并检测可用性...';
  downloadProgress.value = {
    status: 'connecting',
    downloaded_bytes: 0,
    total_bytes: 11 * 1024 * 1024,
    percent: 0,
    speed_kbps: 0,
  };

  try {
    const res = await invoke<string>('download_ip_db_cmd', { customUrl: downloadUrl.value === 'auto' ? null : downloadUrl.value });
    downloadStatusText.value = locale.value === 'en-US' ? 'Download completed and hot-loaded!' : '下载完成并已热加载!';
    emit('log', `[IP-DB] ${res}`);
    await refreshStatus();
  } catch (e: any) {
    downloadStatusText.value = `下载失败: ${e}`;
    emit('log', `[ERROR] IP 库下载失败: ${e}`);
  } finally {
    isDownloading.value = false;
  }
}

async function loadLocalFile() {
  if (!localFilePath.value.trim()) return;
  isLoadingLocal.value = true;
  loadResultMsg.value = '';
  isLoadError.value = false;

  try {
    const res = await invoke<string>('load_local_ip_db_cmd', { filePath: localFilePath.value.trim() });
    loadResultMsg.value = res;
    emit('log', `[IP-DB] ${res}`);
    await refreshStatus();
  } catch (e: any) {
    isLoadError.value = true;
    loadResultMsg.value = `加载失败: ${e}`;
    emit('log', `[ERROR] 加载本地 IP 库失败: ${e}`);
  } finally {
    isLoadingLocal.value = false;
  }
}

async function runTestLookup() {
  if (!testIp.value.trim()) return;
  try {
    testResult.value = await invoke('test_lookup_ip_cmd', { ip: testIp.value.trim() });
  } catch (e: any) {
    emit('log', `[ERROR] IP 探测测试失败: ${e}`);
  }
}

watch(() => props.isOpen, (open) => {
  if (open) {
    refreshStatus();
  }
});

onMounted(async () => {
  const isTauriEnv = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
  if (!isTauriEnv) return;
  await refreshStatus();
  try {
    unlistenProgress = await listen<any>('ip-db-download-progress', (event) => {
      downloadProgress.value = event.payload;
      const s = event.payload.status || '';
      if (s.startsWith('connecting')) {
        downloadStatusText.value = locale.value === 'en-US' ? `Connecting to source (${s})...` : `正在连接网络源 (${s})...`;
      } else if (s.startsWith('downloading')) {
        downloadStatusText.value = locale.value === 'en-US' ? `Downloading stream (${event.payload.speed_kbps} KB/s)...` : `正在高速下载数据流 (${event.payload.speed_kbps} KB/s)...`;
      } else if (s === 'fallback') {
        downloadStatusText.value = event.payload.error || (locale.value === 'en-US' ? 'Trying next fallback source...' : '正在自动尝试下一个备选源...');
      } else if (s === 'completed') {
        downloadStatusText.value = locale.value === 'en-US' ? 'Download completed, hot-reloaded into memory!' : '下载完成，已安全热重载进入全局内存！';
      } else if (s === 'error') {
        downloadStatusText.value = locale.value === 'en-US' ? `Download error: ${event.payload.error || 'Unknown error'}` : `下载出错: ${event.payload.error || '未知网络错误'}`;
      }
    });
  } catch (err) {
    console.warn('[IpDatabaseModal] 注册事件监听跳过:', err);
  }
});

onUnmounted(() => {
  if (unlistenProgress) {
    unlistenProgress();
    unlistenProgress = null;
  }
});
</script>
