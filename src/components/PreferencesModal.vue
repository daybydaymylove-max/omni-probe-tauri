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
              <span>系统偏好设置中心</span>
              <span class="text-[11px] ui-num px-2 py-0.5 rounded-full bg-sky-500/12 text-sky-700 dark:text-sky-300 border border-sky-500/25 font-bold">
                {{ APP_VERSION }}
              </span>
            </h3>
            <div class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">
              集中控制: 运行环境自检 · 自动版本更新 · 界面视觉主题 · 数据存储策略
            </div>
          </div>
        </div>

        <button @click="$emit('close')" class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer" title="关闭">
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
              <h4 class="text-xs font-bold" style="color: var(--text-primary)">运行环境探活与多轨自愈控制</h4>
              <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">管理底层驱动检查时机与离线免驱动自愈策略</p>
            </div>

            <div class="p-3.5 ui-sub-card flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">启动缺项时在角落轻提醒</div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">当检测到外置可选组件未安装时给出无阻塞气泡通知；关闭后仅在顶栏状态胶囊指示。</div>
              </div>
              <label class="relative inline-flex items-center cursor-pointer shrink-0">
                <input type="checkbox" :checked="notifyOnDegradedStartup" @change="toggleStartupEnvReminder" class="sr-only peer">
                <div class="w-11 h-6 bg-slate-300 dark:bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-sky-500"></div>
              </label>
            </div>

            <div class="p-4 ui-sub-card bg-sky-500/8 border-sky-500/25 flex items-center justify-between gap-3 flex-wrap">
              <div>
                <div class="text-xs font-bold text-sky-700 dark:text-sky-300">
                  当前底层环境状态 ({{ envScore ?? '--' }}%)
                </div>
                <div class="text-[11px] mt-1 ui-num" style="color: var(--text-secondary)">
                  {{ missingCount === 0 ? '全量扩展驱动与离线库均已完整就绪。' : `检测到 ${missingCount} 项外置驱动未装，内置多轨兜底运行正常。` }}
                </div>
              </div>
              <button @click.stop="$emit('openDiagnostic')" class="ui-btn-primary px-3.5 py-1.5 rounded-xl font-bold text-xs shrink-0">
                <AppIcon name="shield" :size="13" />
                <span>打开环境检查器</span>
              </button>
            </div>
          </div>

          <!-- 2. 版本更新 -->
          <div v-show="activeTab === 'updates'" class="space-y-4">
            <div class="border-b pb-2" style="border-color: var(--border-subtle)">
              <h4 class="text-xs font-bold" style="color: var(--text-primary)">在线版本与 GitHub Release 更新</h4>
              <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">校验官方 GitHub 仓库最新稳定版并提供安装包链接</p>
            </div>

            <div class="p-4 ui-sub-card flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div>
                <div class="flex items-center gap-2">
                  <span class="text-xs font-bold" style="color: var(--text-primary)">当前安装版本:</span>
                  <span class="text-xs ui-num font-bold" style="color: var(--accent-primary-text)">{{ APP_VERSION }}</span>
                  <span class="text-[11px] px-2 py-0.5 rounded-full bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 font-bold border border-emerald-500/25">原生桌面多平台架构</span>
                </div>
                <div class="text-[11px] mt-1" style="color: var(--text-muted)">官方仓库: github.com/daybydaymylove-max/omni-probe-tauri</div>
              </div>

              <button @click="checkForUpdates" :disabled="isCheckingUpdate" class="ui-btn-primary px-4 py-2 rounded-xl font-bold text-xs shrink-0">
                <AppIcon name="refresh" :size="13" :class="isCheckingUpdate ? 'animate-spin' : ''" />
                <span>{{ isCheckingUpdate ? '正在检查...' : '立即检查新版本' }}</span>
              </button>
            </div>

            <div class="p-3.5 ui-sub-card flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">启动时后台自动检查新版本</div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">连接互联网时自动对比 GitHub Release 最新版本并在通知栏提示。</div>
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
                    <span class="text-xs font-bold text-emerald-700 dark:text-emerald-300">发现新版本发布: {{ updateResult.latest_version }}</span>
                    <span class="text-[11px] ui-num" style="color: var(--text-muted)">({{ updateResult.published_at.substring(0, 10) }})</span>
                  </div>
                  <div class="flex items-center gap-2">
                    <button @click="openLink(updateResult.download_url)" class="ui-btn-primary px-3 py-1.5 rounded-xl font-bold text-xs">
                      <AppIcon name="download" :size="12" />
                      <span>下载更新包</span>
                    </button>
                    <button @click="openLink(updateResult.html_url)" class="ui-btn-secondary px-3 py-1.5 rounded-xl text-xs font-semibold">
                      查看 Release
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
                  <span>当前已是最新版本 ({{ updateResult.current_version }})。</span>
                </div>
                <span class="text-[11px] ui-num" style="color: var(--text-muted)">已同步 GitHub Releases</span>
              </div>
            </div>
          </div>

          <!-- 3. 视觉与桌面布局偏好 -->
          <div v-show="activeTab === 'appearance'" class="space-y-4">
            <div class="border-b pb-2" style="border-color: var(--border-subtle)">
              <h4 class="text-xs font-bold" style="color: var(--text-primary)">视觉质感与工作区空间布局</h4>
              <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">切换明暗语义外观与主菜单栏折叠形态</p>
            </div>

            <div class="p-3.5 ui-sub-card flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">系统外观模式</div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">在冰晶浅色模式与深空夜色模式之间自由切换。</div>
              </div>
              <button @click="$emit('toggleTheme')" class="ui-btn-secondary px-3.5 py-1.5 rounded-xl text-xs font-semibold shrink-0">
                <AppIcon :name="isLight ? 'sun' : 'moon'" :size="14" />
                <span>{{ isLight ? '当前: 冰晶浅色模式' : '当前: 深空夜色模式' }}</span>
              </button>
            </div>

            <div class="p-3.5 ui-sub-card flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">左侧导航栏形态</div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">展开为全名面板，或收缩为 64px 紧凑图标栏。</div>
              </div>
              <button @click="$emit('toggleDock')" class="ui-btn-secondary px-3.5 py-1.5 rounded-xl text-xs font-semibold shrink-0">
                <span>{{ isDockExpanded ? '已展开 (点击收起)' : '已收起 (点击展开)' }}</span>
              </button>
            </div>
          </div>

          <!-- 4. 存储与数据引擎 -->
          <div v-show="activeTab === 'storage'" class="space-y-4">
            <div class="border-b pb-2" style="border-color: var(--border-subtle)">
              <h4 class="text-xs font-bold" style="color: var(--text-primary)">司法电子存证与本地数据策略</h4>
              <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">管理 SHA-256 完整性封条周期与本地抓包缓存</p>
            </div>

            <div class="p-3.5 ui-sub-card flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">司法级哈希封条存证周期</div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">按周期对采集证据文件自动生成 SHA-256 签名，保障防篡改证据链。</div>
              </div>
              <span class="text-xs ui-num font-bold text-sky-700 dark:text-sky-300 bg-sky-500/12 px-2.5 py-1 rounded-xl border border-sky-500/25 shrink-0">
                60 秒 (默认基线)
              </span>
            </div>

            <!-- 抓包截断策略 (SnaplenMode) -->
            <div class="p-3.5 ui-sub-card space-y-2.5">
              <div class="flex items-center justify-between gap-3">
                <div>
                  <div class="text-xs font-bold" style="color: var(--text-primary)">链路抓包截断策略 (Snaplen)</div>
                  <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">控制持续落盘写入的单个报文最大截取长度，平衡取证完整性与磁盘 I/O</div>
                </div>
                <div class="flex items-center gap-1.5 text-xs">
                  <button
                    @click="saveSnaplenMode('full')"
                    :class="['px-2.5 py-1 rounded-lg font-semibold cursor-pointer', snaplenMode === 'full' ? 'bg-sky-600 text-white' : 'ui-btn-secondary']"
                  >
                    全帧保全 (Full)
                  </button>
                  <button
                    @click="saveSnaplenMode('header_only')"
                    :class="['px-2.5 py-1 rounded-lg font-semibold cursor-pointer', snaplenMode === 'header_only' ? 'bg-sky-600 text-white' : 'ui-btn-secondary']"
                  >
                    仅包头 (96B)
                  </button>
                </div>
              </div>
            </div>

            <!-- 持续滚动 PCAP 分卷落盘引擎设置 -->
            <div class="p-3.5 ui-sub-card space-y-3 text-xs">
              <div class="flex items-center justify-between gap-2">
                <div>
                  <div class="font-bold" style="color: var(--text-primary)">持续滚动 PCAP 分卷落盘引擎</div>
                  <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">自动按文件体积切割滚动 PCAP，并在超出配额时 FIFO 清理历史分片</div>
                </div>
                <label class="flex items-center gap-1.5 cursor-pointer font-semibold" style="color: var(--text-primary)">
                  <input type="checkbox" v-model="rollingCfg.enabled" class="accent-sky-600" />
                  <span>{{ rollingCfg.enabled ? '已启用' : '未启用' }}</span>
                </label>
              </div>
              <div class="grid grid-cols-1 sm:grid-cols-3 gap-2 ui-num">
                <div>
                  <div class="text-[10px] mb-1" style="color: var(--text-muted)">输出目录</div>
                  <input v-model="rollingCfg.output_dir" class="ui-input w-full px-2 py-1 text-xs" placeholder="./captures" />
                </div>
                <div>
                  <div class="text-[10px] mb-1" style="color: var(--text-muted)">单卷上限 (MB)</div>
                  <input v-model.number="rollingCfg.max_size_mb" type="number" min="1" max="4096" class="ui-input w-full px-2 py-1 text-xs" />
                </div>
                <div>
                  <div class="text-[10px] mb-1" style="color: var(--text-muted)">总磁盘配额 (GB)</div>
                  <input v-model.number="rollingCfg.max_quota_gb" type="number" min="1" max="1024" class="ui-input w-full px-2 py-1 text-xs" />
                </div>
              </div>
              <div class="flex justify-end">
                <button @click="saveRollingPcapConfig" class="ui-btn-primary px-3 py-1 rounded-xl text-xs font-semibold">
                  应用落盘策略
                </button>
              </div>
            </div>

            <div class="p-3.5 rounded-2xl bg-rose-500/8 border border-rose-500/25 flex items-center justify-between gap-4">
              <div>
                <div class="text-xs font-bold text-rose-700 dark:text-rose-300">清空捕获缓冲池与内核日志</div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-secondary)">释放内存中已解码报文与日志缓存，不影响磁盘持久化 PCAP。</div>
              </div>
              <button @click="$emit('clearData')" class="ui-btn-danger px-3.5 py-1.5 rounded-xl font-bold text-xs shrink-0">
                一键重置缓冲池
              </button>
            </div>
          </div>

        </div>

      </div>

      <!-- 底栏 -->
      <footer class="px-6 py-3 border-t flex items-center justify-between shrink-0 text-xs ui-num" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-muted)">
        <span>快捷键 Ctrl+, 随时呼出偏好设置</span>
        <button @click="$emit('close')" class="ui-btn-primary px-4 py-1.5 rounded-xl font-semibold">
          完成并关闭
        </button>
      </footer>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { openUrl } from '@tauri-apps/plugin-opener';
import { notifySuccess, notifyError, notifyInfo } from '../composables/useNotification';
import { APP_VERSION } from '../constants/appVersion';
import AppIcon from './AppIcon.vue';

const props = defineProps<{
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
  { id: 'environment', label: '运行环境与自愈', icon: 'shield' },
  { id: 'updates', label: '版本检查与更新', icon: 'refresh' },
  { id: 'appearance', label: '视觉质感与布局', icon: 'sliders' },
  { id: 'storage', label: '存证与数据引擎', icon: 'database' },
];

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
    notifyError('无法唤起系统浏览器打开链接', String(e));
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
    notifySuccess('抓包截断策略已更新', msg);
  } catch (e) {
    notifyError('设置 Snaplen 失败', String(e));
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
    notifySuccess('滚动落盘配置已生效', msg);
  } catch (e) {
    notifyError('更新滚动落盘配置失败', String(e));
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
