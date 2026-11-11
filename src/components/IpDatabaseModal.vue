<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 ui-modal-backdrop animate-in fade-in duration-150">
    <div class="w-full max-w-2xl ui-modal-surface rounded-3xl flex flex-col overflow-hidden max-h-[88vh]">
      
      <!-- 1. 顶栏 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-6 py-4 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-2.5">
          <span class="w-3 h-3 rounded-full bg-sky-500 shrink-0"></span>
          <div>
            <h3 class="text-sm font-bold flex items-center gap-2 flex-wrap" style="color: var(--text-primary)">
              <span>离线 IP 归属地与地理情报库 (IP2Region xdb)</span>
              <span v-if="dbStatus.loaded" class="text-[11px] ui-num px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 font-semibold">
                已就绪 (微秒级)
              </span>
              <span v-else class="text-[11px] ui-num px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 font-semibold">
                未就绪 (基础字典)
              </span>
            </h3>
            <p class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">
              物理隔离内存索引，单次查询小于 5 微秒，解析全球国家、省份、城市与 ISP
            </p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer" title="关闭">
          <AppIcon name="close" :size="15" />
        </button>
      </header>

      <!-- 2. 内容区 -->
      <div class="p-6 overflow-auto custom-scrollbar space-y-4 text-xs select-text" style="background: var(--surface-content)">
        
        <div class="p-4 ui-sub-card grid grid-cols-2 md:grid-cols-4 gap-3 ui-num">
          <div>
            <div class="text-[11px] font-sans" style="color: var(--text-muted)">运行状态</div>
            <div class="font-bold mt-0.5 flex items-center gap-1" :class="dbStatus.loaded ? 'text-emerald-700 dark:text-emerald-400' : 'text-amber-700 dark:text-amber-400'">
              <AppIcon :name="dbStatus.loaded ? 'check' : 'alert'" :size="13" />
              <span>{{ dbStatus.loaded ? '内存已加载' : '未加载 (需下载/导入)' }}</span>
            </div>
          </div>
          <div>
            <div class="text-[11px] font-sans" style="color: var(--text-muted)">数据库体积</div>
            <div class="font-bold mt-0.5" style="color: var(--text-primary)">
              {{ dbStatus.file_size > 0 ? (dbStatus.file_size / (1024 * 1024)).toFixed(2) + ' MB' : '0 MB' }}
            </div>
          </div>
          <div>
            <div class="text-[11px] font-sans" style="color: var(--text-muted)">生成时间戳</div>
            <div class="font-bold mt-0.5" style="color: var(--text-primary)">
              {{ dbStatus.created_at > 0 ? formatDate(dbStatus.created_at) : 'N/A' }}
            </div>
          </div>
          <div>
            <div class="text-[11px] font-sans" style="color: var(--text-muted)">存储路径</div>
            <div class="font-bold truncate mt-0.5" style="color: var(--text-primary)" :title="dbStatus.file_path">
              {{ dbStatus.file_path || '未指定' }}
            </div>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="ui-content-card p-4 space-y-3 flex flex-col justify-between">
            <div>
              <div class="font-bold flex items-center gap-1.5 mb-1" style="color: var(--text-primary)">
                <AppIcon name="zap" :size="14" class="text-sky-600 dark:text-sky-400" />
                <span>模式 A: 在线一键下载 / 更新</span>
              </div>
              <p class="text-[11px] leading-relaxed" style="color: var(--text-secondary)">
                从官方源或镜像拉取最新编译的 ip2region.xdb 库 (约 11MB)，下载完成自动热加载。
              </p>
            </div>

            <div>
              <label class="block text-[11px] mb-1 font-medium" style="color: var(--text-muted)">下载通道:</label>
              <select v-model="downloadUrl" class="ui-input ui-num px-2.5 py-1.5 text-xs cursor-pointer">
                <option value="auto">智能多源自动容灾轮询 (CDN + 官方直连)</option>
                <option value="https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb">
                  JsDelivr 全球高速 CDN
                </option>
                <option value="https://ghfast.top/https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb">
                  GHFast 国内加速代理
                </option>
                <option value="https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb">
                  GitHub 官方原始仓库直链
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
                <span>已接收: {{ (downloadProgress.downloaded_bytes / (1024 * 1024)).toFixed(2) }} MB</span>
                <span>总大小: {{ (downloadProgress.total_bytes / (1024 * 1024)).toFixed(2) }} MB</span>
              </div>
            </div>

            <button @click="startDownload" :disabled="isDownloading" class="w-full ui-btn-primary justify-center py-2 rounded-xl font-bold">
              <AppIcon :name="isDownloading ? 'refresh' : 'download'" :size="13" :class="isDownloading ? 'animate-spin' : ''" />
              <span>{{ isDownloading ? '正在安全下载并校验...' : '一键下载最新 IP 归属地库' }}</span>
            </button>
          </div>

          <div class="ui-content-card p-4 space-y-3 flex flex-col justify-between">
            <div>
              <div class="font-bold flex items-center gap-1.5 mb-1" style="color: var(--text-primary)">
                <AppIcon name="shield" :size="14" class="text-emerald-600 dark:text-emerald-400" />
                <span>模式 B: 离线手动导入 / 加载</span>
              </div>
              <p class="text-[11px] leading-relaxed" style="color: var(--text-secondary)">
                适用于严禁联网的隔离内网，手动指定本地已准备的 ip2region.xdb 文件路径。
              </p>
            </div>

            <div>
              <label class="block text-[11px] mb-1 font-medium" style="color: var(--text-muted)">本地 xdb 文件路径:</label>
              <input v-model="localFilePath" placeholder="如: E:\tools\data\ip2region.xdb" class="ui-input ui-num px-2.5 py-1.5 text-xs">
            </div>

            <div v-if="loadResultMsg" :class="['p-2 rounded-xl text-[11px] border', isLoadError ? 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/30' : 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30']">
              {{ loadResultMsg }}
            </div>

            <button @click="loadLocalFile" :disabled="!localFilePath.trim() || isLoadingLocal" class="w-full ui-btn-secondary justify-center py-2 rounded-xl font-bold">
              <AppIcon :name="isLoadingLocal ? 'refresh' : 'folder'" :size="13" :class="isLoadingLocal ? 'animate-spin' : ''" />
              <span>{{ isLoadingLocal ? '正在验证并加载内存...' : '导入并热加载本地库' }}</span>
            </button>
          </div>
        </div>

        <!-- 实时归属地测试工具 -->
        <div class="ui-sub-card p-4 space-y-3">
          <div class="font-bold flex items-center justify-between flex-wrap gap-2" style="color: var(--text-primary)">
            <span class="flex items-center gap-1.5">
              <AppIcon name="search" :size="14" />
              <span>实时 IP 归属地与安全域探测测试</span>
            </span>
            <span class="text-[11px] font-normal ui-num" style="color: var(--text-muted)">单次耗时 &lt; 5 微秒</span>
          </div>

          <div class="flex gap-2">
            <input v-model="testIp" placeholder="输入任意 IPv4 地址 (如: 114.114.114.114)" class="flex-1 ui-input ui-num px-3 py-1.5 text-xs">
            <button @click="runTestLookup" :disabled="!testIp.trim()" class="ui-btn-primary px-4 py-1.5 rounded-xl font-bold shrink-0">
              测试解析
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
                离线命中
              </span>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] pt-1" style="color: var(--text-secondary)">
              <div>国家: <strong style="color: var(--text-primary)">{{ testResult.country || 'N/A' }}</strong></div>
              <div>省份: <strong style="color: var(--text-primary)">{{ testResult.province || 'N/A' }}</strong></div>
              <div>城市: <strong style="color: var(--text-primary)">{{ testResult.city || 'N/A' }}</strong></div>
              <div>运营商: <strong class="text-indigo-700 dark:text-indigo-300 font-bold">{{ testResult.isp || 'N/A' }}</strong></div>
            </div>

            <div class="text-[11px] pt-1" style="color: var(--text-muted)">
              归属摘要: <strong style="color: var(--text-primary)">{{ testResult.geo_summary }}</strong>
            </div>
          </div>
        </div>

      </div>

      <!-- 3. 底栏 -->
      <footer class="px-6 py-3 border-t flex items-center justify-between shrink-0" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
        <span class="text-[11px] ui-num" style="color: var(--text-muted)">数据来源: Lionsoul IP2Region (Apache 2.0)</span>
        <button @click="$emit('close')" class="ui-btn-secondary px-4 py-1.5 rounded-xl text-xs font-semibold">
          完成并关闭
        </button>
      </footer>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted } from 'vue';
import AppIcon from './AppIcon.vue';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

const props = defineProps<{
  isOpen: boolean;
}>();

const emit = defineEmits(['close', 'log']);

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
const downloadStatusText = ref('准备就绪');
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
  downloadStatusText.value = '正在连接下载通道并检测可用性...';
  downloadProgress.value = {
    status: 'connecting',
    downloaded_bytes: 0,
    total_bytes: 11 * 1024 * 1024,
    percent: 0,
    speed_kbps: 0,
  };

  try {
    const res = await invoke<string>('download_ip_db_cmd', { customUrl: downloadUrl.value === 'auto' ? null : downloadUrl.value });
    downloadStatusText.value = '下载完成并已热加载!';
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
        downloadStatusText.value = `正在连接网络源 (${s})...`;
      } else if (s.startsWith('downloading')) {
        downloadStatusText.value = `正在高速下载数据流 (${event.payload.speed_kbps} KB/s)...`;
      } else if (s === 'fallback') {
        downloadStatusText.value = event.payload.error || '正在自动尝试下一个备选源...';
      } else if (s === 'completed') {
        downloadStatusText.value = '下载完成，已安全热重载进入全局内存！';
      } else if (s === 'error') {
        downloadStatusText.value = `下载出错: ${event.payload.error || '未知网络错误'}`;
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
