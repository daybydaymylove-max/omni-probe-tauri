<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md">
    <!-- 偏好设置主视窗 (Apple Mica Frost 工业级控制面板) -->
    <div class="w-full max-w-3xl max-h-[85vh] bg-white/95 dark:bg-slate-900/95 backdrop-blur-2xl rounded-3xl border border-white/60 dark:border-white/10 shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
      
      <!-- 顶栏：标题与关闭 -->
      <div class="px-6 py-4 border-b border-slate-200/60 dark:border-white/10 bg-white/40 dark:bg-black/20 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-2xl bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center text-white shadow-md shadow-cyan-500/25">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          </div>
          <div>
            <h3 class="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <span>系统偏好设置中心 (Preferences & Control)</span>
              <span class="text-[10px] font-mono px-2 py-0.2 rounded-full bg-cyan-500/10 text-cyan-600 dark:text-cyan-300 border border-cyan-500/20 font-bold">
                v0.2.4
              </span>
            </h3>
            <div class="text-[11px] font-mono text-slate-500 dark:text-slate-400 mt-0.5">
              集中控制：运行环境自检 · 自动版本更新 · 界面布局视觉 · 数据存储策略
            </div>
          </div>
        </div>

        <button @click="$emit('close')"
          class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-white/10 transition-colors cursor-pointer">
          ✕
        </button>
      </div>

      <!-- 分组导航与主体内容容器 -->
      <div class="flex-1 flex overflow-hidden">
        
        <!-- 左侧分组切换栏 -->
        <div class="w-48 border-r border-slate-200/60 dark:border-white/10 p-3 flex flex-col gap-1.5 bg-slate-50/50 dark:bg-black/20 shrink-0 font-sans text-xs">
          <button v-for="tab in preferenceTabs" :key="tab.id" @click="activeTab = tab.id"
            :class="[
              'w-full px-3 py-2.5 rounded-xl font-semibold flex items-center gap-2.5 transition-all text-left cursor-pointer',
              activeTab === tab.id
                ? 'bg-cyan-500/15 text-cyan-800 dark:text-cyan-300 font-bold border border-cyan-500/30 shadow-2xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-black/5 dark:hover:bg-white/5'
            ]">
            <span class="text-sm">{{ tab.icon }}</span>
            <span>{{ tab.label }}</span>
          </button>
        </div>

        <!-- 右侧设置项内容区 -->
        <div class="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-6">

          <!-- 1. 运行环境与多轨自愈设置 -->
          <div v-show="activeTab === 'environment'" class="space-y-4">
            <div class="border-b border-black/5 dark:border-white/10 pb-2">
              <h4 class="text-xs font-bold text-slate-900 dark:text-white">运行环境探活与多轨自愈控制</h4>
              <p class="text-[11px] text-slate-500 mt-0.5">管理底层驱动检查时机与离线免驱动自愈策略</p>
            </div>

            <!-- 开关项 1：开机自动弹窗检查 -->
            <div class="p-3.5 rounded-2xl bg-white/70 dark:bg-white/[0.02] border border-slate-200/80 dark:border-white/10 flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold text-slate-800 dark:text-slate-200">启动时显示全景环境自检面板</div>
                <div class="text-[11px] text-slate-500 mt-0.5">当检测到外部驱动未达 100% 时，在启动后友好弹出诊断引导（关闭后系统将静默执行后台多轨自愈）。</div>
              </div>
              <label class="relative inline-flex items-center cursor-pointer shrink-0">
                <input type="checkbox" :checked="!skipStartupEnvModal" @change="toggleStartupEnvModal" class="sr-only peer">
                <div class="w-11 h-6 bg-slate-300 peer-focus:outline-none rounded-full peer dark:bg-slate-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-600"></div>
              </label>
            </div>

            <!-- 状态卡片：当前就绪度总览 -->
            <div class="p-4 rounded-2xl bg-gradient-to-r from-cyan-50/60 to-blue-50/60 dark:from-cyan-950/20 dark:to-blue-950/20 border border-cyan-200/60 dark:border-cyan-500/20 flex items-center justify-between">
              <div>
                <div class="text-xs font-bold text-cyan-950 dark:text-cyan-200">当前多轨自愈系统状态</div>
                <div class="text-[11px] text-slate-600 dark:text-slate-400 mt-1 font-mono">
                  Npcap / USBPcap / TShark / ip2region 均已具备 100% 独立内置自愈保障。
                </div>
              </div>
              <button @click="$emit('openDiagnostic')"
                class="px-3.5 py-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-700 text-white font-bold text-xs shadow transition-all cursor-pointer shrink-0 flex items-center gap-1.5">
                <span>打开环境诊断中心</span>
                <span class="text-xs">🩺</span>
              </button>
            </div>
          </div>

          <!-- 2. 版本更新与发布渠道 -->
          <div v-show="activeTab === 'updates'" class="space-y-4">
            <div class="border-b border-black/5 dark:border-white/10 pb-2">
              <h4 class="text-xs font-bold text-slate-900 dark:text-white">在线版本与 GitHub Release 更新</h4>
              <p class="text-[11px] text-slate-500 mt-0.5">直接从官方 GitHub 仓库安全校验最新稳定版并提供自动安装包</p>
            </div>

            <!-- 当前版本与手动检查卡片 -->
            <div class="p-4 rounded-2xl bg-white/70 dark:bg-white/[0.02] border border-slate-200/80 dark:border-white/10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div>
                <div class="flex items-center gap-2">
                  <span class="text-xs font-bold text-slate-800 dark:text-slate-200">当前安装版本:</span>
                  <span class="text-xs font-mono font-bold text-cyan-600 dark:text-cyan-400">v0.2.4</span>
                  <span class="text-[10px] px-2 py-0.2 rounded-full bg-emerald-500/10 text-emerald-600 font-bold border border-emerald-500/20">全平台多架构</span>
                </div>
                <div class="text-[11px] text-slate-500 mt-1">官方仓库: github.com/daybydaymylove-max/omni-probe-tauri</div>
              </div>

              <button @click="checkForUpdates" :disabled="isCheckingUpdate"
                class="px-4 py-2 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-bold text-xs shadow-md transition-all cursor-pointer flex items-center gap-2 disabled:opacity-50 shrink-0">
                <span :class="isCheckingUpdate ? 'animate-spin' : ''">⟳</span>
                <span>{{ isCheckingUpdate ? '正在连接 GitHub 检查...' : '立即检查新版本' }}</span>
              </button>
            </div>

            <!-- 开关项 2：启动时自动检查更新 -->
            <div class="p-3.5 rounded-2xl bg-white/70 dark:bg-white/[0.02] border border-slate-200/80 dark:border-white/10 flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold text-slate-800 dark:text-slate-200">启动时后台自动检查新版本</div>
                <div class="text-[11px] text-slate-500 mt-0.5">在连接互联网时静默对比 GitHub Release 最新稳定版本，若有新版将在顶部通知栏温和提醒。</div>
              </div>
              <label class="relative inline-flex items-center cursor-pointer shrink-0">
                <input type="checkbox" v-model="autoCheckUpdate" @change="saveAutoCheckUpdate" class="sr-only peer">
                <div class="w-11 h-6 bg-slate-300 peer-focus:outline-none rounded-full peer dark:bg-slate-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-600"></div>
              </label>
            </div>

            <!-- 检查更新结果呈现区 -->
            <div v-if="updateResult" class="p-4 rounded-2xl border transition-all"
              :class="updateResult.has_update ? 'bg-emerald-50/70 dark:bg-emerald-950/20 border-emerald-300 dark:border-emerald-500/30' : 'bg-slate-50 dark:bg-black/20 border-slate-200 dark:border-white/10'">
              
              <div v-if="updateResult.has_update" class="space-y-3">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
                    <span class="text-xs font-bold text-emerald-900 dark:text-emerald-300">🎉 发现新版本发布: {{ updateResult.latest_version }}</span>
                    <span class="text-[10px] font-mono text-slate-400">({{ updateResult.published_at.substring(0, 10) }})</span>
                  </div>
                  <div class="flex items-center gap-2">
                    <button @click="openLink(updateResult.download_url)"
                      class="px-3 py-1.5 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs shadow transition-all cursor-pointer flex items-center gap-1">
                      <span>下载更新包</span>
                      <span class="text-xs">↓</span>
                    </button>
                    <button @click="openLink(updateResult.html_url)"
                      class="px-3 py-1.5 rounded-xl bg-white dark:bg-white/10 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-white/10 text-xs font-semibold transition-all cursor-pointer">
                      查看 Release
                    </button>
                  </div>
                </div>

                <div class="p-3 bg-white/80 dark:bg-slate-900/80 rounded-xl text-xs text-slate-700 dark:text-slate-300 font-mono space-y-1 border border-emerald-100 dark:border-white/5">
                  <div class="font-bold text-slate-900 dark:text-white">{{ updateResult.release_name }}</div>
                  <div class="text-[11px] text-slate-600 dark:text-slate-400 whitespace-pre-wrap max-h-36 overflow-y-auto custom-scrollbar">{{ updateResult.release_notes }}</div>
                </div>
              </div>

              <div v-else class="flex items-center justify-between text-xs text-slate-600 dark:text-slate-300">
                <div class="flex items-center gap-2">
                  <span class="text-emerald-500 font-bold">✓</span>
                  <span>当前已经是最新版本 ({{ updateResult.current_version }})，暂无更新。</span>
                </div>
                <span class="text-[10px] font-mono opacity-60">已与 GitHub Releases 同步</span>
              </div>
            </div>
          </div>

          <!-- 3. 视觉与桌面布局偏好 -->
          <div v-show="activeTab === 'appearance'" class="space-y-4">
            <div class="border-b border-black/5 dark:border-white/10 pb-2">
              <h4 class="text-xs font-bold text-slate-900 dark:text-white">视觉质感与工作区空间布局</h4>
              <p class="text-[11px] text-slate-500 mt-0.5">定制专属的苹果 2026 Liquid Mica 磨砂材质与分栏排版</p>
            </div>

            <!-- 主题双模态切换 -->
            <div class="p-3.5 rounded-2xl bg-white/70 dark:bg-white/[0.02] border border-slate-200/80 dark:border-white/10 flex items-center justify-between">
              <div>
                <div class="text-xs font-bold text-slate-800 dark:text-slate-200">系统外观模式</div>
                <div class="text-[11px] text-slate-500 mt-0.5">在 2026 苹果冰晶磨砂明亮与烟熏磨砂深色模式之间自由切换。</div>
              </div>
              <button @click="$emit('toggleTheme')"
                class="px-3.5 py-1.5 rounded-xl glass-pill text-xs font-semibold cursor-pointer shadow-sm">
                <span>{{ isLight ? '☀️ 当前: 冰晶明亮模式' : '🌙 当前: 烟熏深色模式' }}</span>
              </button>
            </div>

            <!-- 侧边栏默认形态 -->
            <div class="p-3.5 rounded-2xl bg-white/70 dark:bg-white/[0.02] border border-slate-200/80 dark:border-white/10 flex items-center justify-between">
              <div>
                <div class="text-xs font-bold text-slate-800 dark:text-slate-200">左侧灵动菜单栏形态</div>
                <div class="text-[11px] text-slate-500 mt-0.5">展开为 224px 的 6 汉字全名面板，或收缩为 64px 的 Mini 紧凑图标栏。</div>
              </div>
              <button @click="$emit('toggleDock')"
                class="px-3.5 py-1.5 rounded-xl border border-slate-200 dark:border-white/10 text-xs font-semibold hover:bg-black/5 dark:hover:bg-white/10 cursor-pointer">
                <span>{{ isDockExpanded ? '已展开 (点击收起)' : '已收起 (点击展开)' }}</span>
              </button>
            </div>
          </div>

          <!-- 4. 存储与数据引擎偏好 -->
          <div v-show="activeTab === 'storage'" class="space-y-4">
            <div class="border-b border-black/5 dark:border-white/10 pb-2">
              <h4 class="text-xs font-bold text-slate-900 dark:text-white">司法电子存证与本地数据策略</h4>
              <p class="text-[11px] text-slate-500 mt-0.5">管理 SHA-256 完整性封条周期与本地抓包缓存</p>
            </div>

            <!-- 周期封条说明 -->
            <div class="p-3.5 rounded-2xl bg-white/70 dark:bg-white/[0.02] border border-slate-200/80 dark:border-white/10 flex items-center justify-between">
              <div>
                <div class="text-xs font-bold text-slate-800 dark:text-slate-200">司法级哈希封条存证周期</div>
                <div class="text-[11px] text-slate-500 mt-0.5">每隔固定时间对抓取证据文件自动生成 SHA-256 签名，保障防篡改证据链。</div>
              </div>
              <span class="text-xs font-mono font-bold text-cyan-600 dark:text-cyan-400 bg-cyan-500/10 px-2.5 py-1 rounded-xl">
                60 秒 (默认基线)
              </span>
            </div>

            <!-- 一键重置缓存 -->
            <div class="p-3.5 rounded-2xl bg-rose-50/50 dark:bg-rose-950/20 border border-rose-200/60 dark:border-rose-500/20 flex items-center justify-between">
              <div>
                <div class="text-xs font-bold text-rose-900 dark:text-rose-200">清空捕获缓冲池与内核日志</div>
                <div class="text-[11px] text-slate-600 dark:text-slate-400 mt-0.5">释放内存中已解码报文与日志缓存，不影响磁盘持久化 PCAP。</div>
              </div>
              <button @click="$emit('clearData')"
                class="px-3.5 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-700 text-white font-bold text-xs shadow transition-all cursor-pointer">
                一键重置缓冲池
              </button>
            </div>
          </div>

        </div>

      </div>

      <!-- 底栏：关闭与提示 -->
      <div class="px-6 py-3 border-t border-slate-200/60 dark:border-white/10 bg-white/40 dark:bg-black/20 flex items-center justify-between shrink-0 text-xs text-slate-400 font-mono">
        <span>快捷键 Ctrl+, 随时呼出偏好设置</span>
        <button @click="$emit('close')" class="px-4 py-1.5 rounded-xl font-semibold bg-slate-900 dark:bg-white text-white dark:text-slate-900 hover:opacity-90 shadow-sm transition-all cursor-pointer font-sans">
          完成并关闭
        </button>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { openUrl } from '@tauri-apps/plugin-opener';
import { notifySuccess, notifyError, notifyInfo } from '../composables/useNotification';

defineProps<{
  isOpen: boolean;
  isLight: boolean;
  isDockExpanded: boolean;
}>();

defineEmits(['close', 'toggleTheme', 'toggleDock', 'openDiagnostic', 'clearData']);

type TabId = 'environment' | 'updates' | 'appearance' | 'storage';

interface PreferenceTab {
  id: TabId;
  label: string;
  icon: string;
}

const preferenceTabs: PreferenceTab[] = [
  { id: 'environment', label: '运行环境与自愈', icon: '🩺' },
  { id: 'updates', label: '版本检查与更新', icon: '🚀' },
  { id: 'appearance', label: '视觉质感与布局', icon: '🎨' },
  { id: 'storage', label: '存证与数据引擎', icon: '💾' },
];

const activeTab = ref<TabId>('environment');

// 1. 运行环境设置项
const skipStartupEnvModal = ref(localStorage.getItem('omni_probe_skip_startup_env_modal') === 'true');
function toggleStartupEnvModal() {
  skipStartupEnvModal.value = !skipStartupEnvModal.value;
  localStorage.setItem('omni_probe_skip_startup_env_modal', skipStartupEnvModal.value ? 'true' : 'false');
  notifySuccess('偏好设置已更新', skipStartupEnvModal.value ? '下次启动将跳过环境弹窗，保持后台多轨自愈' : '下次启动将展示全景环境自检面板');
}

// 2. 版本更新设置项
const autoCheckUpdate = ref(localStorage.getItem('omni_probe_auto_check_update') !== 'false');
function saveAutoCheckUpdate() {
  localStorage.setItem('omni_probe_auto_check_update', autoCheckUpdate.value ? 'true' : 'false');
  notifySuccess('更新策略已保存', autoCheckUpdate.value ? '已开启开机自动检查新版本' : '已关闭开机自动检查更新');
}

const isCheckingUpdate = ref(false);
const updateResult = ref<any | null>(null);

async function checkForUpdates() {
  isCheckingUpdate.value = true;
  try {
    const res: any = await invoke('check_app_update_cmd');
    updateResult.value = res;
    if (res.has_update) {
      notifySuccess('发现新版本发布', `最新版本 ${res.latest_version} 已就绪，可一键下载更新`);
    } else {
      notifyInfo('版本检查完成', '当前探针系统已是最新稳定版本');
    }
  } catch (e: any) {
    notifyError('检查更新受阻', e || '无法连接 GitHub Releases API，请检查网络');
  } finally {
    isCheckingUpdate.value = false;
  }
}

async function openLink(url: string) {
  if (!url) return;
  try {
    await openUrl(url);
  } catch (e) {
    window.open(url, '_blank');
  }
}
</script>
