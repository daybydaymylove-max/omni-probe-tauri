<template>
  <Transition name="splash-fade">
    <section
      v-if="inspectorOpen"
      @click.stop
      role="dialog"
      :aria-label="t('envInspector.title')"
      class="absolute right-0 top-full mt-2.5 w-[min(94vw,480px)] max-h-[78vh] ui-modal-surface rounded-2xl flex flex-col overflow-hidden z-50 select-text"
    >
      <span class="lens-edge-lip" aria-hidden="true"></span>

      <!-- 1. 紧凑顶栏：健康度微环 + 分段控制器 + 动作按钮 -->
      <header class="ui-nav-glass border-b px-4 py-3 flex items-center justify-between gap-2 shrink-0">
        <div class="flex items-center gap-2.5 min-w-0">
          <div class="relative w-9 h-9 shrink-0 flex items-center justify-center">
            <svg class="w-9 h-9 -rotate-90" viewBox="0 0 36 36">
              <circle cx="18" cy="18" r="14" stroke="currentColor" stroke-width="3.2" style="color: var(--border-subtle)" fill="transparent" />
              <circle
                cx="18"
                cy="18"
                r="14"
                stroke="currentColor"
                stroke-width="3.2"
                :stroke-dasharray="87.96"
                :stroke-dashoffset="87.96 - (87.96 * (envScore ?? 0)) / 100"
                :class="scoreRingClass"
                fill="transparent"
                stroke-linecap="round"
                class="transition-all duration-500"
              />
            </svg>
            <span class="absolute text-[10px] font-bold ui-num" style="color: var(--text-primary)">
              {{ envScore ?? '--' }}
            </span>
          </div>

          <div class="min-w-0">
            <div class="flex items-center gap-1.5">
              <h3 class="text-xs font-bold truncate" style="color: var(--text-primary)">{{ t('envInspector.headerTitle') }}</h3>
              <span :class="['text-[10px] ui-num font-semibold px-1.5 py-0.5 rounded-full border', statusBadgeClass]">
                {{ statusBadgeText }}
              </span>
            </div>
            <div class="text-[10px] ui-num truncate mt-0.5" style="color: var(--text-muted)">
              {{ missingCount === 0 ? t('envInspector.readyStatus') : t('envInspector.missingStatus', { count: missingCount }) }}
            </div>
          </div>
        </div>

        <div class="flex items-center gap-1.5 shrink-0">
          <!-- 分段切换 -->
          <div class="p-0.5 rounded-xl ui-pill flex items-center text-[11px] font-semibold">
            <button
              type="button"
              @click="setInspectorTab('deps')"
              :class="[
                'px-2.5 py-1 rounded-lg transition-colors cursor-pointer',
                inspectorTab === 'deps' ? 'bg-[var(--accent-primary)] text-white shadow-2xs' : 'hover:bg-black/5 dark:hover:bg-white/5'
              ]"
              :style="inspectorTab !== 'deps' ? { color: 'var(--text-secondary)' } : undefined"
            >
              {{ t('envInspector.tabDeps') }}
            </button>
            <button
              type="button"
              @click="setInspectorTab('runtime')"
              :class="[
                'px-2.5 py-1 rounded-lg transition-colors cursor-pointer',
                inspectorTab === 'runtime' ? 'bg-[var(--accent-primary)] text-white shadow-2xs' : 'hover:bg-black/5 dark:hover:bg-white/5'
              ]"
              :style="inspectorTab !== 'runtime' ? { color: 'var(--text-secondary)' } : undefined"
            >
              {{ t('envInspector.tabRuntime') }}
            </button>
          </div>

          <button
            type="button"
            @click="onManualRefresh"
            :disabled="inspecting"
            class="w-7 h-7 rounded-full ui-pill flex items-center justify-center cursor-pointer disabled:opacity-50"
            :title="t('envInspector.refreshNow')"
          >
            <AppIcon name="refresh" :size="12" :class="inspecting ? 'animate-spin' : ''" />
          </button>

          <button
            type="button"
            @click="closeInspector"
            class="w-7 h-7 rounded-full ui-pill flex items-center justify-center cursor-pointer"
            :title="t('envInspector.closeEsc')"
          >
            <AppIcon name="close" :size="13" />
          </button>
        </div>
      </header>

      <!-- 2. 主体区 -->
      <div class="flex-1 overflow-y-auto custom-scrollbar p-3.5 space-y-2.5" style="background: var(--surface-content)">
        <!-- 标签 A: 轻量手风琴式依赖清单 -->
        <template v-if="inspectorTab === 'deps'">
          <div
            v-for="comp in (report?.components || [])"
            :key="comp.id"
            class="ui-sub-card p-2.5 transition-colors hover:border-sky-500/35"
          >
            <!-- 默认折叠态：单行高信息密度展示 -->
            <div class="flex items-center justify-between gap-2">
              <button
                type="button"
                @click="toggleExpand(comp.id)"
                class="flex items-center gap-2 min-w-0 flex-1 text-left cursor-pointer"
                :title="expandedId === comp.id ? (locale === 'en-US' ? 'Collapse details' : '收起详情') : (locale === 'en-US' ? 'Click to expand path, fallback mode and tips' : '点击展开路径、兜底原理与建议')"
              >
                <span :class="['w-2 h-2 rounded-full shrink-0', comp.is_ready ? 'bg-emerald-500' : 'bg-amber-500']"></span>
                <div class="min-w-0 flex-1">
                  <div class="flex items-center gap-1.5">
                    <span class="text-xs font-semibold truncate" style="color: var(--text-primary)">{{ comp.name }}</span>
                    <span
                      v-if="comp.version"
                      class="text-[10px] ui-num px-1.5 py-0.2 rounded bg-black/5 dark:bg-white/10 shrink-0"
                      style="color: var(--text-muted)"
                    >
                      {{ comp.version }}
                    </span>
                  </div>
                  <div class="text-[10.5px] ui-num truncate mt-0.5" style="color: var(--text-muted)">
                    <template v-if="comp.is_ready">{{ comp.path || comp.capability_enabled }}</template>
                    <template v-else>{{ comp.fallback_mode }}</template>
                  </div>
                </div>
              </button>

              <div class="flex items-center gap-1.5 shrink-0">
                <span
                  v-if="comp.is_ready"
                  class="text-[10px] ui-num font-semibold px-2 py-0.5 rounded-full bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 flex items-center gap-1"
                >
                  <AppIcon name="check" :size="10" />
                  <span>{{ locale === 'en-US' ? 'Ready' : '就绪' }}</span>
                </span>

                <button
                  v-else-if="comp.can_auto_install && !installingMap[comp.id] && confirmingComponent !== comp.id && !launchedMap[comp.id]"
                  type="button"
                  @click="confirmingComponent = comp.id"
                  class="ui-btn-primary text-[10.5px] px-2.5 py-1 rounded-lg"
                >
                  <AppIcon name="download" :size="11" />
                  <span>{{ comp.id === 'ip_db' ? (locale === 'en-US' ? 'Download DB' : '下载库') : (locale === 'en-US' ? 'Install' : '安装') }}</span>
                </button>

                <span
                  v-else-if="!comp.is_ready && !comp.can_auto_install"
                  class="text-[10px] ui-num font-semibold px-2 py-0.5 rounded-full flex items-center gap-1"
                  :class="comp.id === 'admin' ? 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border border-amber-500/25' : 'bg-sky-500/12 text-sky-700 dark:text-sky-300 border border-sky-500/25'"
                >
                  <AppIcon v-if="comp.id !== 'admin'" name="zap" :size="10" class="text-sky-500" />
                  <span>{{ comp.id === 'admin' ? (locale === 'en-US' ? 'Elevation Required' : '需提权') : (locale === 'en-US' ? 'Built-in Driver Active' : '内置驱动已接管') }}</span>
                </span>

                <button
                  type="button"
                  @click="toggleExpand(comp.id)"
                  class="w-6 h-6 rounded-lg hover:bg-black/5 dark:hover:bg-white/5 flex items-center justify-center cursor-pointer transition-transform"
                  :class="expandedId === comp.id ? 'rotate-180' : ''"
                  style="color: var(--text-muted)"
                  :aria-label="locale === 'en-US' ? 'Expand or collapse details' : '展开或收起详情'"
                >
                  <AppIcon name="chevron-down" :size="12" />
                </button>
              </div>
            </div>

            <!-- 行内安装二次确认 (无套娃弹窗) -->
            <div
              v-if="confirmingComponent === comp.id"
              class="mt-2 pt-2 border-t flex items-center justify-between gap-2 text-[11px]"
              style="border-color: var(--border-subtle)"
            >
              <span class="ui-num truncate" style="color: var(--text-secondary)">
                {{ locale === 'en-US' ? `Will download ${comp.installer_filename} (${comp.estimated_size_mb} MB) from official source` : `将从官网源下载 ${comp.installer_filename} (${comp.estimated_size_mb} MB)` }}
              </span>
              <div class="flex items-center gap-1.5 shrink-0">
                <button type="button" @click="startAutoInstall(comp.id)" class="ui-btn-primary text-[10.5px] px-2.5 py-1 rounded-lg">
                  {{ locale === 'en-US' ? 'Confirm Download' : '确认下载' }}
                </button>
                <button type="button" @click="confirmingComponent = null" class="ui-btn-secondary text-[10.5px] px-2 py-1 rounded-lg">
                  {{ locale === 'en-US' ? 'Cancel' : '取消' }}
                </button>
              </div>
            </div>

            <!-- 行内流式下载进度 -->
            <div
              v-if="installingMap[comp.id]"
              class="mt-2 pt-2 border-t space-y-1.5 text-[10.5px] ui-num"
              style="border-color: var(--border-subtle)"
            >
              <div class="flex items-center justify-between">
                <span class="text-sky-600 dark:text-sky-300 font-semibold flex items-center gap-1.5">
                  <AppIcon name="refresh" :size="11" class="animate-spin" />
                  <span>{{ installingMap[comp.id].status === 'launching' ? (locale === 'en-US' ? 'Launching wizard...' : '正在唤起向导...') : (locale === 'en-US' ? 'Downloading installer...' : '下载安装包中...') }}</span>
                </span>
                <span class="font-bold" style="color: var(--text-primary)">{{ installingMap[comp.id].percent.toFixed(1) }}%</span>
              </div>
              <div class="w-full h-1.5 rounded-full overflow-hidden" style="background: var(--surface-elevated)">
                <div
                  class="h-full bg-gradient-to-r from-sky-500 to-indigo-500 transition-all duration-200"
                  :style="{ width: `${installingMap[comp.id].percent}%` }"
                ></div>
              </div>
            </div>

            <!-- 行内安装完成校验条 -->
            <div
              v-if="launchedMap[comp.id]"
              class="mt-2 pt-2 border-t flex items-center justify-between gap-2 text-[11px]"
              style="border-color: var(--border-subtle)"
            >
              <span class="text-emerald-700 dark:text-emerald-300 font-medium">
                {{ comp.id === 'ip_db' ? (locale === 'en-US' ? 'Offline database written and active' : '离线库已写入并生效') : (locale === 'en-US' ? 'Installer wizard launched, refresh to verify once finished' : '安装向导已启动，完成后刷新核验') }}
              </span>
              <button
                type="button"
                @click="finishAndRecheck(comp.id)"
                class="px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-[10.5px] font-semibold cursor-pointer shrink-0"
              >
                {{ locale === 'en-US' ? 'Done & Refresh' : '完成并刷新' }}
              </button>
            </div>

            <!-- 展开后的详尽上下文 (渐进披露) -->
            <div
              v-if="expandedId === comp.id"
              class="mt-2 pt-2 border-t space-y-1.5 text-[11px]"
              style="border-color: var(--border-subtle); color: var(--text-secondary)"
            >
              <!-- 原生内置驱动自愈接管状态提示 -->
              <div v-if="!comp.is_ready && comp.id !== 'admin'" class="rounded-xl p-2.5 bg-sky-500/8 border border-sky-500/20 text-[11px] space-y-1">
                <div class="font-bold text-sky-700 dark:text-sky-300 flex items-center gap-1.5">
                  <AppIcon name="zap" :size="12" />
                  <span>{{ locale === 'en-US' ? 'Native Pipeline Active' : '原生内置驱动链路已自动接管' }}</span>
                </div>
                <div class="text-(--text-secondary) leading-relaxed">
                  {{ comp.fallback_mode }}
                </div>
              </div>

              <div class="leading-relaxed">
                <strong style="color: var(--text-primary)">{{ locale === 'en-US' ? 'Capability: ' : '扩展能力：' }}</strong>{{ comp.capability_enabled }}
              </div>
              <div class="leading-relaxed">
                <strong style="color: var(--text-primary)">{{ locale === 'en-US' ? 'Fallback Mode: ' : '兜底机制：' }}</strong>{{ comp.fallback_mode }}
              </div>
              <div v-if="!comp.is_ready" class="text-amber-700 dark:text-amber-300 leading-relaxed">
                <strong>{{ locale === 'en-US' ? 'Tips: ' : '处置建议：' }}</strong>{{ comp.install_tips }}
              </div>
              <div v-if="comp.official_url" class="flex justify-end pt-0.5">
                <button
                  type="button"
                  @click="openOfficialLink(comp.official_url)"
                  class="text-[10.5px] font-medium text-sky-600 dark:text-sky-400 hover:underline flex items-center gap-1 cursor-pointer"
                >
                  <span>{{ locale === 'en-US' ? 'Visit Official Release Page' : '访问官方发布页' }}</span>
                  <AppIcon name="arrow-right" :size="10" />
                </button>
              </div>
            </div>
          </div>
        </template>

        <!-- 标签 B: 按需激活的内核态零拷贝与 eBPF/XDP 监控 (不切入则不产生任何 2s 轮询) -->
        <template v-else>
          <div class="ui-sub-card p-3 space-y-2 text-xs">
            <div class="flex items-center justify-between gap-2">
              <span class="font-bold flex items-center gap-1.5" style="color: var(--text-primary)">
                <AppIcon name="cpu" :size="13" class="text-sky-600 dark:text-sky-400" />
                <span>{{ locale === 'en-US' ? 'Pinned-Memory Zero-Copy Pool' : '物理锁页零拷贝缓冲池' }}</span>
              </span>
              <span class="text-[10px] px-2 py-0.5 rounded-full ui-num bg-sky-500/12 text-sky-700 dark:text-sky-300 border border-sky-500/25">
                {{ zeroCopyTelemetry?.active_backend || (locale === 'en-US' ? 'Standby (No capture)' : '待机未抓包') }}
              </span>
            </div>

            <div class="grid grid-cols-3 gap-1.5 text-[10.5px] ui-num">
              <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                <div style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Pinned Physical RAM' : '锁页物理内存' }}</div>
                <div class="font-bold mt-0.5" style="color: var(--text-primary)">
                  {{ formatTelemetryBytes((zeroCopyTelemetry?.pinned_buffer_bytes || 0) + (zeroCopyTelemetry?.pool_total_memory_bytes || 0)) }}
                </div>
              </div>
              <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                <div style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Ring Ingested / Dropped' : 'Ring 入池 / 丢包' }}</div>
                <div class="font-bold mt-0.5" style="color: var(--text-primary)">
                  {{ (zeroCopyTelemetry?.ring_packets_total ?? 0).toLocaleString() }} /
                  <span :class="(zeroCopyTelemetry?.ring_drops_total || 0) > 0 ? 'text-rose-500' : 'text-emerald-500'">
                    {{ zeroCopyTelemetry?.ring_drops_total ?? 0 }}
                  </span>
                </div>
              </div>
              <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                <div style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Slot Utilization' : '槽位利用率' }}</div>
                <div class="font-bold mt-0.5" style="color: var(--text-primary)">
                  {{ (zeroCopyTelemetry?.pool_utilization_percent ?? 0).toFixed(1) }}%
                </div>
              </div>
            </div>
            <div class="text-[10.5px] ui-num" style="color: var(--text-muted)">
              {{ zeroCopyTelemetry?.status_detail || (locale === 'en-US' ? 'Sampling zero-copy & kernel queue metrics...' : '正在采集零拷贝与内核队列指标...') }}
            </div>
          </div>

          <div class="ui-sub-card p-3 space-y-2 text-xs">
            <div class="flex items-center justify-between gap-2">
              <span class="font-bold flex items-center gap-1.5" style="color: var(--text-primary)">
                <AppIcon name="shield" :size="13" class="text-indigo-600 dark:text-indigo-400" />
                <span>{{ locale === 'en-US' ? 'eBPF Verifier & XDP Shunting' : 'eBPF 验证器与 XDP 分流' }}</span>
              </span>
              <span class="text-[10px] ui-num px-2 py-0.5 rounded-full bg-indigo-500/12 text-indigo-700 dark:text-indigo-300">
                {{ xdpMetrics?.ebpf_instructions_count ?? 0 }} {{ locale === 'en-US' ? 'instructions' : '条指令' }}
              </span>
            </div>

            <div class="grid grid-cols-3 gap-1.5 text-[10.5px] ui-num">
              <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                <div style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Passed Packets' : '过审报文' }}</div>
                <div class="font-bold mt-0.5" style="color: var(--text-primary)">
                  {{ (xdpMetrics?.total_processed_packets ?? 0).toLocaleString() }}
                </div>
              </div>
              <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                <div style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Elephant Flow Bypass' : '大象流直通' }}</div>
                <div class="font-bold mt-0.5 text-emerald-600 dark:text-emerald-300">
                  {{ (xdpMetrics?.bypass_ratio_percentage ?? 0).toFixed(1) }}%
                </div>
              </div>
              <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                <div style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Frontend Filtered' : '前端拦截' }}</div>
                <div class="font-bold mt-0.5 text-rose-500">
                  {{ (xdpMetrics?.dropped_packets ?? 0).toLocaleString() }}
                </div>
              </div>
            </div>

            <div class="flex items-center gap-1.5 flex-wrap pt-1 border-t" style="border-color: var(--border-subtle)">
              <button
                v-for="preset in xdpPresetOptions"
                :key="preset.id"
                type="button"
                @click="applyXdpPreset(preset.id)"
                :disabled="switchingXdpPolicy"
                :title="preset.desc"
                :class="[
                  'px-2 py-1 rounded-lg text-[10.5px] font-medium transition-colors cursor-pointer border',
                  xdpMetrics?.active_policy_name === preset.id
                    ? 'bg-indigo-600 text-white border-indigo-500'
                    : 'ui-btn-secondary'
                ]"
              >
                {{ preset.label }}
              </button>
            </div>
          </div>
        </template>
      </div>

      <!-- 3. 轻量底部偏好条 -->
      <footer
        class="px-4 py-2 border-t flex items-center justify-between gap-2 shrink-0 text-[10.5px]"
        style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-muted)"
      >
        <label class="flex items-center gap-1.5 cursor-pointer select-none">
          <input
            type="checkbox"
            :checked="notifyOnDegradedStartup"
            @change="onToggleReminder(($event.target as HTMLInputElement).checked)"
            class="w-3.5 h-3.5 rounded accent-sky-500 cursor-pointer"
          />
          <span>{{ locale === 'en-US' ? 'Notify in corner when dependencies missing' : '启动缺项时角落提醒' }}</span>
        </label>
        <span class="ui-num shrink-0">{{ report?.checked_at || (locale === 'en-US' ? 'Probing' : '探活中') }}</span>
      </footer>
    </section>
  </Transition>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import AppIcon from './AppIcon.vue';
import { useEnvironmentInspector } from '../composables/useEnvironmentInspector';
import { useI18n } from '../i18n';

const { t, locale } = useI18n();

const {
  inspectorOpen,
  inspectorTab,
  report,
  inspecting,
  envScore,
  missingCount,
  confirmingComponent,
  installingMap,
  launchedMap,
  zeroCopyTelemetry,
  xdpMetrics,
  switchingXdpPolicy,
  notifyOnDegradedStartup,
  inspectEnvironment,
  refreshRuntimeTelemetry,
  closeInspector,
  setInspectorTab,
  setStartupReminderEnabled,
  startAutoInstall,
  finishAndRecheck,
  applyXdpPreset,
  openOfficialLink,
} = useEnvironmentInspector();

const expandedId = ref<string | null>(null);

function toggleExpand(id: string) {
  expandedId.value = expandedId.value === id ? null : id;
}

const xdpPresetOptions = [
  { id: 'default_inspection', label: locale.value === 'en-US' ? 'Full Deep Audit' : '全量深度审计', desc: locale.value === 'en-US' ? 'Parse all packets and bypass elephant flows' : '全部报文透传解析并开启大象流智能旁路' },
  { id: 'drop_icmp_probe', label: locale.value === 'en-US' ? 'Drop ICMP Probes' : '拦截 ICMP 探测', desc: locale.value === 'en-US' ? 'eBPF drops ICMPv4 probes at ingress' : 'eBPF 首包直接丢弃 ICMPv4 探活报文' },
  { id: 'redirect_tcp_xsk', label: locale.value === 'en-US' ? 'Fast TCP XSK Shunting' : 'TCP 高速直通分流', desc: locale.value === 'en-US' ? 'Direct TCP packets to AF_XDP / zero-copy ring' : 'TCP 报文优先定向 AF_XDP / 零拷贝直通环' },
];

const scoreRingClass = computed(() => {
  const s = envScore.value ?? 0;
  if (s >= 90) return 'text-emerald-500';
  if (s >= 50) return 'text-amber-500';
  return 'text-rose-500';
});

const statusBadgeClass = computed(() => {
  const s = envScore.value ?? 0;
  if (s >= 90) return 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/25';
  if (s >= 50) return 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/25';
  return 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/25';
});

const statusBadgeText = computed(() => {
  const level = report.value?.status_level;
  if (locale.value === 'en-US') {
    if (level === 'Optimal') return 'Optimal';
    if (level === 'Standard') return 'Standard';
    return 'Fallback';
  }
  if (level === 'Optimal') return '完整态';
  if (level === 'Standard') return '标准态';
  return '兜底态';
});

function formatTelemetryBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const exp = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const val = bytes / Math.pow(1024, exp);
  return `${val >= 10 ? val.toFixed(1) : val.toFixed(2)} ${units[exp]}`;
}

async function onManualRefresh() {
  if (inspectorTab.value === 'runtime') {
    await Promise.all([inspectEnvironment(true), refreshRuntimeTelemetry()]);
  } else {
    await inspectEnvironment(true);
  }
}

function onToggleReminder(checked: boolean) {
  setStartupReminderEnabled(checked);
}
</script>
