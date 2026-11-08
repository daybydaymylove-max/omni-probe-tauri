<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md animate-in fade-in duration-150">
    <div class="w-full max-w-2xl bg-white/95 backdrop-blur-2xl rounded-3xl border border-white/60 shadow-2xl flex flex-col overflow-hidden max-h-[88vh]">
      
      <!-- 1. 顶栏 -->
      <div class="px-6 py-4 border-b border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <span class="w-3.5 h-3.5 rounded-full bg-blue-600 shadow-sm animate-pulse"></span>
          <div>
            <h3 class="text-sm font-bold text-slate-900 flex items-center gap-2">
              <span>离线 IP 归属地与地理情报库 (IP2Region xdb)</span>
              <span v-if="dbStatus.loaded" class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300">
                已就绪 (微秒级)
              </span>
              <span v-else class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-300">
                未就绪 (基础字典)
              </span>
            </h3>
            <p class="text-[11px] text-slate-500 font-mono mt-0.5">
              100% 物理隔离内存索引，单次查询小于 5 微秒，精准解析全球国家、省份、城市与 ISP
            </p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer">
          ✕
        </button>
      </div>

      <!-- 2. 内容区 -->
      <div class="p-6 overflow-auto custom-scrollbar space-y-4 text-xs font-mono">
        
        <!-- 2.1 状态概览卡片 -->
        <div class="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 grid grid-cols-2 md:grid-cols-4 gap-3">
          <div>
            <div class="text-[10px] text-slate-400">运行状态</div>
            <div class="font-bold mt-0.5" :class="dbStatus.loaded ? 'text-emerald-700' : 'text-amber-700'">
              {{ dbStatus.loaded ? '✅ 内存已加载' : '⚠️ 未加载 (需下载/导入)' }}
            </div>
          </div>
          <div>
            <div class="text-[10px] text-slate-400">数据库体积</div>
            <div class="font-bold text-slate-800 mt-0.5">
              {{ dbStatus.file_size > 0 ? (dbStatus.file_size / (1024 * 1024)).toFixed(2) + ' MB' : '0 MB' }}
            </div>
          </div>
          <div>
            <div class="text-[10px] text-slate-400">生成时间戳</div>
            <div class="font-bold text-slate-800 mt-0.5">
              {{ dbStatus.created_at > 0 ? formatDate(dbStatus.created_at) : 'N/A' }}
            </div>
          </div>
          <div>
            <div class="text-[10px] text-slate-400">存储路径</div>
            <div class="font-bold text-slate-800 truncate mt-0.5" :title="dbStatus.file_path">
              {{ dbStatus.file_path || '未指定' }}
            </div>
          </div>
        </div>

        <!-- 2.2 双模供给控制区 (在线一键下载 vs 离线手动导入) -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          
          <!-- 模式 A: 在线一键更新 (联网环境) -->
          <div class="p-4 rounded-2xl bg-white border border-slate-200/80 shadow-2xs space-y-3 flex flex-col justify-between">
            <div>
              <div class="font-bold text-slate-800 flex items-center gap-1.5 mb-1">
                <span>⚡ 模式 A: 在线一键下载 / 更新</span>
              </div>
              <p class="text-[11px] text-slate-500 font-normal leading-relaxed">
                从官方权威源或镜像拉取最新编译的 ip2region.xdb 库 (约 11MB)，下载完成自动热加载。
              </p>
            </div>

            <!-- 下载源选择 -->
            <div>
              <label class="block text-[10px] text-slate-500 mb-1">下载通道:</label>
              <select v-model="downloadUrl" class="w-full bg-slate-50 border border-slate-200 rounded-xl px-2.5 py-1.5 text-xs text-slate-800 focus:outline-none">
                <option value="auto">
                  ⚡ 智能多源自动容灾轮询 (推荐，国内多源 CDN + 官方直连)
                </option>
                <option value="https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb">
                  JsDelivr 全球高速 CDN (国内稳定推荐)
                </option>
                <option value="https://ghfast.top/https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb">
                  GHFast 国内加速代理
                </option>
                <option value="https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb">
                  GitHub 官方原始仓库直链 (需良好国际网络)
                </option>
              </select>
            </div>

            <!-- 进度条 -->
            <div v-if="isDownloading" class="space-y-1.5 bg-blue-50/80 p-2.5 rounded-xl border border-blue-200">
              <div class="flex justify-between text-[10px] text-blue-900 font-bold">
                <span>{{ downloadStatusText }}</span>
                <span>{{ downloadProgress.percent }}% ({{ downloadProgress.speed_kbps }} KB/s)</span>
              </div>
              <div class="w-full bg-blue-200/60 rounded-full h-2 overflow-hidden">
                <div class="bg-blue-600 h-2 transition-all duration-200" :style="{ width: `${downloadProgress.percent}%` }"></div>
              </div>
              <div class="text-[9px] text-slate-500 flex justify-between">
                <span>已接收: {{ (downloadProgress.downloaded_bytes / (1024 * 1024)).toFixed(2) }} MB</span>
                <span>总大小: {{ (downloadProgress.total_bytes / (1024 * 1024)).toFixed(2) }} MB</span>
              </div>
            </div>

            <button @click="startDownload" :disabled="isDownloading"
              class="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white py-2 rounded-xl font-bold transition-all shadow-sm cursor-pointer disabled:opacity-50 text-center">
              <span v-if="isDownloading">⏳ 正在安全下载并校验...</span>
              <span v-else>⬇ 一键下载最新 IP 归属地库</span>
            </button>
          </div>

          <!-- 模式 B: 离线导入 (严格物理隔离内网) -->
          <div class="p-4 rounded-2xl bg-white border border-slate-200/80 shadow-2xs space-y-3 flex flex-col justify-between">
            <div>
              <div class="font-bold text-slate-800 flex items-center gap-1.5 mb-1">
                <span>🛡 模式 B: 离线手动导入 / 加载</span>
              </div>
              <p class="text-[11px] text-slate-500 font-normal leading-relaxed">
                适用于严禁联网的涉密/工业控制网，手动指定本地已下载的 ip2region.xdb 文件路径。
              </p>
            </div>

            <div>
              <label class="block text-[10px] text-slate-500 mb-1">本地 xdb 文件路径:</label>
              <input v-model="localFilePath" placeholder="如: E:\tools\data\ip2region.xdb"
                class="w-full bg-slate-50 border border-slate-200 rounded-xl px-2.5 py-1.5 text-xs font-mono text-slate-800 focus:outline-none">
            </div>

            <div v-if="loadResultMsg" :class="['p-2 rounded-xl text-[11px] border', isLoadError ? 'bg-rose-50 text-rose-700 border-rose-200' : 'bg-emerald-50 text-emerald-800 border-emerald-200']">
              {{ loadResultMsg }}
            </div>

            <button @click="loadLocalFile" :disabled="!localFilePath.trim() || isLoadingLocal"
              class="w-full bg-slate-800 hover:bg-slate-900 text-white py-2 rounded-xl font-bold transition-all shadow-sm cursor-pointer disabled:opacity-50 text-center">
              <span v-if="isLoadingLocal">正在验证并加载内存...</span>
              <span v-else>📂 导入并热加载本地库</span>
            </button>
          </div>

        </div>

        <!-- 2.3 实时归属地测试小工具 (零网络延迟验证) -->
        <div class="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 space-y-3">
          <div class="font-bold text-slate-800 flex items-center justify-between">
            <span>🔬 实时 IP 归属地与安全域探测测试 (Microsecond Query)</span>
            <span class="text-[10px] text-slate-400 font-normal">单次耗时 &lt; 5 微秒</span>
          </div>

          <div class="flex gap-2">
            <input v-model="testIp" placeholder="输入任意 IPv4 地址 (如: 114.114.114.114 或 120.24.78.129)"
              class="flex-1 bg-white border border-slate-200 rounded-xl px-3 py-1.5 text-xs font-mono text-slate-800 focus:outline-none">
            <button @click="runTestLookup" :disabled="!testIp.trim()"
              class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded-xl font-bold transition-all shadow-2xs cursor-pointer disabled:opacity-40">
              测试解析
            </button>
          </div>

          <div v-if="testResult" class="p-3 bg-white border border-slate-200 rounded-xl space-y-1.5">
            <div class="flex items-center justify-between border-b border-slate-100 pb-1.5">
              <div class="font-bold text-slate-900 flex items-center gap-2">
                <span>{{ testResult.ip }}</span>
                <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-50 text-blue-800 border border-blue-200">
                  {{ testResult.zone_name }}
                </span>
                <span class="px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-100 text-slate-700">
                  {{ testResult.security_level }}
                </span>
              </div>
              <span class="text-[10px] text-emerald-700 font-bold bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                100% 离线命中
              </span>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-4 gap-2 text-slate-600 text-[11px] pt-1">
              <div>国家: <strong class="text-slate-800">{{ testResult.country || 'N/A' }}</strong></div>
              <div>省份: <strong class="text-slate-800">{{ testResult.province || 'N/A' }}</strong></div>
              <div>城市: <strong class="text-slate-800">{{ testResult.city || 'N/A' }}</strong></div>
              <div>运营商 (ISP): <strong class="text-indigo-700 font-bold">{{ testResult.isp || 'N/A' }}</strong></div>
            </div>

            <div class="text-[11px] text-slate-500 pt-1">
              归属摘要: <strong class="text-slate-900">{{ testResult.geo_summary }}</strong>
            </div>
          </div>
        </div>

      </div>

      <!-- 3. 底栏 -->
      <div class="px-6 py-3 border-t border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <span class="text-[11px] text-slate-400 font-mono">数据来源: Lionsoul IP2Region (Apache 2.0)</span>
        <button @click="$emit('close')" class="px-4 py-1.5 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer">
          完成并关闭
        </button>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted } from 'vue';
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
  await refreshStatus();
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
});

onUnmounted(() => {
  if (unlistenProgress) {
    unlistenProgress();
    unlistenProgress = null;
  }
});
</script>
