import { ref, computed } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { openUrl } from '@tauri-apps/plugin-opener';
import { notify, notifyError, notifySuccess } from './useNotification';

export interface ComponentStatus {
  id: string;
  name: string;
  category: string;
  is_ready: boolean;
  version?: string | null;
  path?: string | null;
  capability_enabled: string;
  fallback_mode: string;
  official_url: string;
  install_tips: string;
  can_auto_install: boolean;
  installer_filename?: string | null;
  estimated_size_mb?: number | null;
}

export interface EnvironmentReport {
  readiness_score: number;
  status_level: 'Optimal' | 'Standard' | 'Degraded' | string;
  summary: string;
  components: ComponentStatus[];
  checked_at: string;
}

export interface DownloadProgressPayload {
  component_id: string;
  status: 'downloading' | 'launching' | 'completed' | 'error' | string;
  percent: number;
  downloaded_bytes: number;
  total_bytes: number;
  error_msg?: string | null;
}

export interface KernelZeroCopyTelemetry {
  active_backend: string;
  rio_active: boolean;
  npcap_pool_active: boolean;
  is_physically_pinned: boolean;
  is_large_pages: boolean;
  pinned_buffer_bytes: number;
  ring_packets_total: number;
  ring_bytes_total: number;
  ring_drops_total: number;
  pool_total_slots: number;
  pool_allocations: number;
  pool_deallocations: number;
  pool_exhaustion_drops: number;
  pool_utilization_percent: number;
  pool_total_memory_bytes: number;
  status_detail: string;
}

export interface XdpBypassMetrics {
  total_processed_packets: number;
  passed_packets: number;
  dropped_packets: number;
  bypassed_packets: number;
  redirected_packets: number;
  total_bypassed_bytes: number;
  bypass_ratio_percentage: number;
  active_tcp_flows: number;
  direct_bypassed_flows: number;
  blocked_ips_count: number;
  ebpf_instructions_count: number;
  active_policy_name: string;
}

export type InspectorTab = 'deps' | 'runtime';

const STARTUP_SKIP_STORAGE_KEY = 'omni_probe_skip_startup_env_modal';

// ============================================================
// 全局单例响应式状态 (避免 App / 顶栏微囊 / 检查器 / 设置中心状态分裂与重复探活)
// ============================================================
const inspectorOpen = ref(false);
const inspectorTab = ref<InspectorTab>('deps');

const report = ref<EnvironmentReport | null>(null);
const inspecting = ref(false);
let inflightInspection: Promise<EnvironmentReport | null> | null = null;

const confirmingComponent = ref<string | null>(null);
const installingMap = ref<Record<string, DownloadProgressPayload>>({});
const launchedMap = ref<Record<string, boolean>>({});

const zeroCopyTelemetry = ref<KernelZeroCopyTelemetry | null>(null);
const xdpMetrics = ref<XdpBypassMetrics | null>(null);
const switchingXdpPolicy = ref(false);

const notifyOnDegradedStartup = ref<boolean>(
  localStorage.getItem(STARTUP_SKIP_STORAGE_KEY) !== 'true'
);

let progressUnlisten: UnlistenFn | null = null;
let progressListenerInit: Promise<void> | null = null;
let runtimePollTimer: ReturnType<typeof setInterval> | null = null;
let lastOpenedAtMs = 0;

const envScore = computed<number | null>(() => report.value?.readiness_score ?? null);
const isNpcapReady = computed(() => Boolean(report.value?.components.find(c => c.id === 'npcap')?.is_ready));
const isTsharkReady = computed(() => Boolean(report.value?.components.find(c => c.id === 'tshark')?.is_ready));
const isUsbpcapReady = computed(() => Boolean(report.value?.components.find(c => c.id === 'usbpcap')?.is_ready));
const isIpDbReady = computed(() => Boolean(report.value?.components.find(c => c.id === 'ip_db')?.is_ready));
const missingCount = computed(() => (report.value?.components || []).filter(c => !c.is_ready).length);
const hasActiveDownload = computed(() => Object.keys(installingMap.value).length > 0);

function setStartupReminderEnabled(enabled: boolean, silent: boolean = false): void {
  notifyOnDegradedStartup.value = enabled;
  localStorage.setItem(STARTUP_SKIP_STORAGE_KEY, enabled ? 'false' : 'true');
  if (!silent) {
    notifySuccess(
      '环境提醒偏好已保存',
      enabled
        ? '启动检测到可选驱动缺失时，将在角落给出非阻塞建议提醒'
        : '已开启静默启动模式，仅在顶栏状态胶囊实时展现环境指标'
    );
  }
}

async function ensureDownloadListener(): Promise<void> {
  if (progressUnlisten) return;
  if (progressListenerInit) return progressListenerInit;

  progressListenerInit = listen<DownloadProgressPayload>('installer-download-progress', (event) => {
    const p = event.payload;
    if (!p || !p.component_id) return;

    if (p.status === 'completed') {
      const next = { ...installingMap.value };
      delete next[p.component_id];
      installingMap.value = next;
      launchedMap.value = { ...launchedMap.value, [p.component_id]: true };
      notifySuccess('外部组件装配已完成', `组件 ${p.component_id} 已准备就绪，请点击完成验证生效`);
    } else if (p.status === 'error') {
      const next = { ...installingMap.value };
      delete next[p.component_id];
      installingMap.value = next;
      notifyError('官方安装包下载异常', p.error_msg || '网络请求或文件校验失败');
    } else {
      installingMap.value = { ...installingMap.value, [p.component_id]: p };
    }
  })
    .then((fn) => {
      progressUnlisten = fn;
    })
    .catch((e) => {
      console.warn('[ENV_INSPECTOR] 注册下载进度事件失败:', e);
    })
    .finally(() => {
      progressListenerInit = null;
    });

  return progressListenerInit;
}

/**
 * 执行一次全系统底层依赖探活；支持并发请求折叠与缓存复用
 * 时间复杂度: O(1) 状态检查与跨进程单次探活
 */
async function inspectEnvironment(forceRefresh: boolean = false): Promise<EnvironmentReport | null> {
  if (!forceRefresh && report.value) {
    return report.value;
  }
  if (inflightInspection) {
    return inflightInspection;
  }

  inspecting.value = true;
  inflightInspection = invoke<EnvironmentReport>('get_environment_inspection_cmd')
    .then((res) => {
      report.value = res;
      return res;
    })
    .catch((e) => {
      console.warn('[ENV_INSPECTOR] 环境探活失败:', e);
      return report.value;
    })
    .finally(() => {
      inspecting.value = false;
      inflightInspection = null;
    });

  return inflightInspection;
}

async function refreshRuntimeTelemetry(): Promise<void> {
  try {
    const [zc, xdp] = await Promise.all([
      invoke<KernelZeroCopyTelemetry>('get_kernel_zero_copy_telemetry_cmd'),
      invoke<XdpBypassMetrics>('get_xdp_bypass_metrics_cmd'),
    ]);
    zeroCopyTelemetry.value = zc;
    xdpMetrics.value = xdp;
  } catch (e) {
    console.warn('[ENV_INSPECTOR] 内核运行遥测调用异常:', e);
  }
}

function startRuntimePolling(): void {
  if (runtimePollTimer) return;
  refreshRuntimeTelemetry();
  runtimePollTimer = setInterval(() => {
    if (inspectorOpen.value && inspectorTab.value === 'runtime') {
      refreshRuntimeTelemetry();
    } else {
      stopRuntimePolling();
    }
  }, 2000);
}

function stopRuntimePolling(): void {
  if (runtimePollTimer) {
    clearInterval(runtimePollTimer);
    runtimePollTimer = null;
  }
}

function openInspector(tab?: InspectorTab): void {
  ensureDownloadListener();
  if (tab) {
    inspectorTab.value = tab;
  }
  lastOpenedAtMs = performance.now();
  inspectorOpen.value = true;
  if (!report.value) {
    inspectEnvironment(false);
  }
  if (inspectorTab.value === 'runtime') {
    startRuntimePolling();
  }
}

function closeInspector(): void {
  inspectorOpen.value = false;
  confirmingComponent.value = null;
  stopRuntimePolling();
}

function dismissInspectorOnOutsideClick(): void {
  if (performance.now() - lastOpenedAtMs < 80) {
    return;
  }
  closeInspector();
}

function toggleInspector(): void {
  if (inspectorOpen.value) {
    closeInspector();
  } else {
    openInspector();
  }
}

function setInspectorTab(tab: InspectorTab): void {
  inspectorTab.value = tab;
  if (tab === 'runtime' && inspectorOpen.value) {
    startRuntimePolling();
  } else {
    stopRuntimePolling();
  }
}

async function startAutoInstall(componentId: string): Promise<void> {
  await ensureDownloadListener();
  confirmingComponent.value = null;
  installingMap.value = {
    ...installingMap.value,
    [componentId]: {
      component_id: componentId,
      status: 'downloading',
      percent: 0,
      downloaded_bytes: 0,
      total_bytes: 1024 * 1024,
    },
  };

  try {
    const res = await invoke<string>('download_and_install_component_cmd', { componentId });
    const next = { ...installingMap.value };
    delete next[componentId];
    installingMap.value = next;
    launchedMap.value = { ...launchedMap.value, [componentId]: true };
    notifySuccess('装配引导已就绪', res || '已唤起安装流程，完成后可刷新校验状态');
  } catch (e: unknown) {
    const next = { ...installingMap.value };
    delete next[componentId];
    installingMap.value = next;
    notifyError('驱动安装引导受阻', e);
  }
}

async function finishAndRecheck(componentId: string): Promise<void> {
  const next = { ...launchedMap.value };
  delete next[componentId];
  launchedMap.value = next;
  await inspectEnvironment(true);
}

async function applyXdpPreset(preset: string): Promise<void> {
  switchingXdpPolicy.value = true;
  try {
    const msg = await invoke<string>('apply_xdp_policy_preset_cmd', { preset });
    await refreshRuntimeTelemetry();
    notifySuccess('eBPF 字节码策略已部署', msg);
  } catch (e) {
    notifyError('eBPF 策略部署受阻', String(e));
  } finally {
    switchingXdpPolicy.value = false;
  }
}

async function openOfficialLink(url: string): Promise<void> {
  if (!url) return;
  try {
    await openUrl(url);
  } catch (e) {
    notifyError('无法唤起系统关联浏览器打开链接', String(e));
  }
}

/**
 * 开机无阻塞温和提醒：当缺失非就绪依赖且用户未静音时，于角落展示非阻断 Toast 并附直达按钮
 */
function notifyDegradedIfNeeded(): void {
  if (!notifyOnDegradedStartup.value || !report.value) return;
  if (report.value.readiness_score >= 100) return;

  const missingNames = report.value.components
    .filter(c => !c.is_ready)
    .map(c => c.name.split(' ')[0])
    .slice(0, 3)
    .join(' / ');

  notify({
    type: 'info',
    title: `运行环境就绪度 ${report.value.readiness_score}%`,
    message: `可选外置组件未完全就绪（${missingNames}），系统已启用原生兜底链路。`,
    duration: 5500,
    action: {
      label: '打开检查器',
      onClick: () => openInspector('deps'),
    },
  });
}

export function useEnvironmentInspector() {
  return {
    inspectorOpen,
    inspectorTab,
    report,
    inspecting,
    envScore,
    isNpcapReady,
    isTsharkReady,
    isUsbpcapReady,
    isIpDbReady,
    missingCount,
    hasActiveDownload,
    confirmingComponent,
    installingMap,
    launchedMap,
    zeroCopyTelemetry,
    xdpMetrics,
    switchingXdpPolicy,
    notifyOnDegradedStartup,
    inspectEnvironment,
    refreshRuntimeTelemetry,
    openInspector,
    closeInspector,
    dismissInspectorOnOutsideClick,
    toggleInspector,
    setInspectorTab,
    setStartupReminderEnabled,
    startAutoInstall,
    finishAndRecheck,
    applyXdpPreset,
    openOfficialLink,
    notifyDegradedIfNeeded,
  };
}
