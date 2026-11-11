<template>
  <div v-if="isOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
    <div class="relative ui-modal-surface w-full max-w-4xl rounded-3xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      <span class="lens-edge-lip" aria-hidden="true"></span>

      <!-- 头部 -->
      <div class="ui-nav-glass px-6 py-4 border-b border-(--border-subtle) flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-indigo-500/12 border border-indigo-500/30 flex items-center justify-center text-indigo-600 dark:text-indigo-400">
            <AppIcon name="link" class="w-4 h-4" />
          </div>
          <div>
            <h3 class="text-sm font-bold text-(--text-primary)">跨平台串口透明拦截内核与全双工中继器</h3>
            <p class="text-xs text-(--text-muted) ui-num">内置 Win32 NamedPipe / POSIX PTY / RFC 2217 网桥 / WDM 内核过滤联动与双向硬件引脚透传</p>
          </div>
        </div>
        <button @click="$emit('close')" class="ui-btn-secondary w-8 h-8 rounded-full p-0 flex items-center justify-center cursor-pointer" aria-label="关闭弹窗">
          <AppIcon name="close" class="w-4 h-4" />
        </button>
      </div>

      <!-- 主体内容 -->
      <div class="p-6 space-y-5 overflow-auto max-h-[78vh] custom-scrollbar select-text">
        <!-- 1. 跨平台驱动与原生透明拦截能力探测条 -->
        <div class="ui-sub-card p-4 space-y-3 border-sky-500/30 rounded-2xl">
          <div class="flex items-center justify-between flex-wrap gap-2 border-b border-(--border-subtle) pb-2">
            <div class="flex items-center gap-2 text-xs font-bold text-(--text-primary)">
              <span class="w-2 h-2 rounded-full" :class="caps?.kernel_filter_driver.driver_loaded ? 'bg-emerald-500' : 'bg-sky-500'"></span>
              <span>跨平台透明虚拟串口与内核拦截矩阵 ({{ caps?.os_family?.toUpperCase() || '探测中' }})</span>
            </div>
            <div class="flex items-center gap-2">
              <button
                @click="runSmartIntercept"
                :disabled="isStartingIntercept"
                class="ui-btn-primary px-3 py-1 text-[11px] font-bold flex items-center gap-1 cursor-pointer disabled:opacity-45"
                title="自动探测系统 WDM 驱动 / COM占用情况 / OS 原生伪终端或 RFC2217 并启动最佳透明拦截链路"
              >
                <AppIcon name="zap" :size="12" />
                <span>{{ isStartingIntercept ? '智能检测中...' : '一键智能识别并启动透明拦截' }}</span>
              </button>
              <button @click="refreshAll" class="ui-btn-secondary px-2.5 py-1 text-[11px] flex items-center gap-1 cursor-pointer">
                <AppIcon name="refresh" :size="12" />
                <span>刷新能力探活</span>
              </button>
            </div>
          </div>

          <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] ui-num">
            <div class="ui-content-card p-2.5 rounded-xl">
              <div class="text-(--text-muted)">RFC 2217 TCP 串口网桥</div>
              <div class="font-bold mt-0.5 text-emerald-600 dark:text-emerald-400">全平台原生内置就绪</div>
            </div>
            <div class="ui-content-card p-2.5 rounded-xl">
              <div class="text-(--text-muted)">POSIX 内核 PTY 伪终端</div>
              <div class="font-bold mt-0.5" :class="caps?.posix_pty_supported ? 'text-emerald-600 dark:text-emerald-400' : 'text-(--text-secondary)'">
                {{ caps?.posix_pty_supported ? 'Linux/macOS 直出支持' : '仅类 Unix 内核可用' }}
              </div>
            </div>
            <div class="ui-content-card p-2.5 rounded-xl">
              <div class="text-(--text-muted)">Win32 NamedPipe 管道口</div>
              <div class="font-bold mt-0.5" :class="caps?.windows_named_pipe_supported ? 'text-emerald-600 dark:text-emerald-400' : 'text-(--text-secondary)'">
                {{ caps?.windows_named_pipe_supported ? 'CreateNamedPipeW 就绪' : '仅 Windows 平台' }}
              </div>
            </div>
            <div class="ui-content-card p-2.5 rounded-xl">
              <div class="text-(--text-muted)">WDM 上层过滤 (\\.\OmniSerialFilter)</div>
              <div class="font-bold mt-0.5" :class="caps?.kernel_filter_driver.driver_loaded ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'">
                {{ caps?.kernel_filter_driver.driver_loaded ? '驱动已加载 (IRP旁路)' : '未安装签名 .sys 驱动' }}
              </div>
            </div>
          </div>

          <div v-if="caps && !caps.kernel_filter_driver.driver_loaded" class="text-[11px] leading-relaxed text-(--text-secondary) px-1">
            {{ caps.kernel_filter_driver.detail_message }}
          </div>

          <div v-if="smartDiagnosisMsg" class="px-3 py-2 rounded-xl border border-amber-500/35 bg-amber-500/10 text-[11px] text-amber-800 dark:text-amber-200 leading-relaxed">
            <strong>智能拦截诊断 [{{ smartStrategyTag }}]：</strong>{{ smartDiagnosisMsg }}
          </div>

          <!-- 检测到的虚拟串口对一键对接建议 (com0com / Virtual Serial) -->
          <div v-if="caps?.detected_virtual_ports && caps.detected_virtual_ports.length > 0" class="flex items-center gap-2 flex-wrap px-1 text-[11px]">
            <span class="font-semibold text-(--text-muted)">已探测系统虚拟串口对:</span>
            <button
              v-for="pair in caps.detected_virtual_ports"
              :key="pair.pair_name"
              @click="applyVirtualPairToBridge(pair)"
              class="px-2.5 py-0.5 rounded-lg border border-emerald-500/35 bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 font-semibold cursor-pointer hover:bg-emerald-500/20"
              :title="`点击一键填入下方双工桥梁: ${pair.driver_source}`"
            >
              {{ pair.pair_name }} (一键带入桥梁)
            </button>
          </div>

          <!-- 启动零外挂透明虚拟拦截通道面板 -->
          <div class="ui-content-card p-3.5 rounded-xl space-y-3">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <span class="text-xs font-bold text-(--text-primary)">启动自研透明拦截代理会话 (兼容任何第三方上位机直连)</span>
              <div class="flex items-center gap-1.5 flex-wrap">
                <button
                  v-for="m in interceptModeTabs"
                  :key="m.id"
                  @click="selectedInterceptMode = m.id"
                  :class="[
                    'px-2.5 py-1 rounded-lg text-[11px] font-semibold border cursor-pointer transition-all',
                    selectedInterceptMode === m.id ? 'bg-sky-600 text-white border-sky-500' : 'ui-btn-secondary'
                  ]"
                >
                  {{ m.label }}
                </button>
              </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs items-end">
              <div>
                <label class="block text-[11px] font-semibold text-(--text-muted) mb-1">目标硬件串口 / 回环模式</label>
                <select v-model="interceptTargetPort" class="ui-input w-full px-2.5 py-1.5 text-xs ui-num">
                  <option value="LOOPBACK_ECHO">LOOPBACK_ECHO (无硬件自环压测模式)</option>
                  <option v-for="p in serialPorts" :key="p" :value="p">{{ p }}</option>
                </select>
              </div>

              <div v-if="selectedInterceptMode === 'rfc2217'">
                <label class="block text-[11px] font-semibold text-(--text-muted) mb-1">本地 TCP 监听端口 (0 为自动分配)</label>
                <input v-model.number="rfcListenPort" type="number" min="0" max="65535" class="ui-input w-full px-2.5 py-1.5 text-xs ui-num" />
              </div>

              <div v-else-if="selectedInterceptMode === 'winpipe'">
                <label class="block text-[11px] font-semibold text-(--text-muted) mb-1">管道名称标识 (生成 \\.\pipe\omni_com_*)</label>
                <input v-model="winPipeSuffix" type="text" placeholder="vcom1" class="ui-input w-full px-2.5 py-1.5 text-xs ui-num" />
              </div>

              <div v-else-if="selectedInterceptMode === 'unixpty'">
                <label class="block text-[11px] font-semibold text-(--text-muted) mb-1">POSIX 软链接路径别名 (可选)</label>
                <input v-model="unixSymlinkAlias" type="text" placeholder="/tmp/omni_vcom1" class="ui-input w-full px-2.5 py-1.5 text-xs ui-num" />
              </div>

              <div v-else>
                <label class="block text-[11px] font-semibold text-(--text-muted) mb-1">目标控制设备</label>
                <div class="px-2.5 py-1.5 rounded-xl border border-(--border-subtle) text-[11px] ui-num text-(--text-secondary)">
                  \\.\OmniSerialFilter (Ports UpperFilter)
                </div>
              </div>

              <button
                @click="launchInterceptSession"
                :disabled="isStartingIntercept || (selectedInterceptMode === 'wdm' && !caps?.kernel_filter_driver.driver_loaded)"
                class="ui-btn-primary py-1.5 px-3 text-xs font-bold cursor-pointer disabled:opacity-45"
              >
                {{ isStartingIntercept ? '启动中...' : '创建并监听透明拦截端点' }}
              </button>
            </div>

            <!-- 活跃拦截会话列表 -->
            <div v-if="activeInterceptSessions.length > 0" class="space-y-2 pt-2 border-t border-(--border-subtle)">
              <div
                v-for="s in activeInterceptSessions"
                :key="s.session_id"
                class="ui-sub-card p-2.5 rounded-xl flex items-center justify-between gap-2 flex-wrap text-[11px] ui-num"
              >
                <div class="min-w-0 flex-1 space-y-0.5">
                  <div class="font-bold text-(--text-primary) flex items-center gap-2 flex-wrap">
                    <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                    <span>{{ s.virtual_endpoint }}</span>
                    <span class="opacity-70">⇄ {{ s.target_port }}</span>
                    <span class="px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-700 dark:text-sky-300">@{{ s.baud_rate }} bps</span>
                  </div>
                  <div class="text-(--text-secondary)">
                    上行→设备: {{ formatBytes(s.bytes_upstream_to_target) }} · 设备→上行: {{ formatBytes(s.bytes_target_to_upstream) }} ·
                    捕获 {{ s.packets_captured }} 帧 · IOCTL {{ s.ioctl_control_events }} 次
                  </div>
                </div>
                <button @click="stopIntercept(s.session_id)" class="ui-btn-danger px-2.5 py-1 text-[11px] cursor-pointer shrink-0">
                  停止拦截
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- 2. 物理双串口全双工硬件桥梁配置面板 (已修复 B->A 全双工线程与引脚镜像) -->
        <div class="ui-sub-card border-indigo-500/30 rounded-2xl p-4 flex flex-col gap-3">
          <div class="flex items-center justify-between text-xs font-bold text-(--text-primary) border-b border-(--border-subtle) pb-2">
            <span>物理双串口全双工透明桥梁 (COM-A ⇄ COM-B + RTS/CTS 硬件流控引脚交叉同步)</span>
            <span class="text-[11px] text-indigo-600 dark:text-indigo-400 font-normal">独立双线程 A→B & B→A + 3.5T 分帧聚合</span>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <!-- 通道 A 配置 -->
            <div class="ui-content-card rounded-xl p-3 flex flex-col gap-2">
              <div class="font-bold text-(--text-primary) flex items-center justify-between">
                <span>端口 A (COM-A)</span>
                <span class="text-[11px] text-sky-600 dark:text-sky-400 ui-num">主控端 / 上位机</span>
              </div>
              <div>
                <label class="block text-[11px] font-bold text-(--text-muted) uppercase mb-1">选择串口</label>
                <select v-model="portA" class="ui-input w-full px-2.5 py-1.5 text-xs ui-num">
                  <option v-for="p in serialPorts" :key="p" :value="p" :disabled="p === portB">{{ p }}</option>
                </select>
              </div>
              <div class="grid grid-cols-2 gap-2">
                <div>
                  <label class="block text-[11px] font-bold text-(--text-muted) uppercase mb-1">波特率</label>
                  <select v-model.number="baudA" class="ui-input w-full px-2 py-1.5 text-xs ui-num">
                    <option :value="9600">9600</option>
                    <option :value="19200">19200</option>
                    <option :value="38400">38400</option>
                    <option :value="57600">57600</option>
                    <option :value="115200">115200</option>
                  </select>
                </div>
                <div>
                  <label class="block text-[11px] font-bold text-(--text-muted) uppercase mb-1">校验位</label>
                  <select v-model="parityA" class="ui-input w-full px-2 py-1.5 text-xs ui-num">
                    <option value="None">None 无校验</option>
                    <option value="Odd">Odd 奇校验</option>
                    <option value="Even">Even 偶校验</option>
                  </select>
                </div>
              </div>
            </div>

            <!-- 通道 B 配置 -->
            <div class="ui-content-card rounded-xl p-3 flex flex-col gap-2">
              <div class="font-bold text-(--text-primary) flex items-center justify-between">
                <span>端口 B (COM-B)</span>
                <span class="text-[11px] text-emerald-600 dark:text-emerald-400 ui-num">下位机 / 现场仪表</span>
              </div>
              <div>
                <label class="block text-[11px] font-bold text-(--text-muted) uppercase mb-1">选择串口</label>
                <select v-model="portB" class="ui-input w-full px-2.5 py-1.5 text-xs ui-num">
                  <option v-for="p in serialPorts" :key="p" :value="p" :disabled="p === portA">{{ p }}</option>
                </select>
              </div>
              <div class="grid grid-cols-2 gap-2">
                <div>
                  <label class="block text-[11px] font-bold text-(--text-muted) uppercase mb-1">波特率</label>
                  <select v-model.number="baudB" class="ui-input w-full px-2 py-1.5 text-xs ui-num">
                    <option :value="9600">9600</option>
                    <option :value="19200">19200</option>
                    <option :value="38400">38400</option>
                    <option :value="57600">57600</option>
                    <option :value="115200">115200</option>
                  </select>
                </div>
                <div>
                  <label class="block text-[11px] font-bold text-(--text-muted) uppercase mb-1">校验位</label>
                  <select v-model="parityB" class="ui-input w-full px-2 py-1.5 text-xs ui-num">
                    <option value="None">None 无校验</option>
                    <option value="Odd">Odd 奇校验</option>
                    <option value="Even">Even 偶校验</option>
                  </select>
                </div>
              </div>
            </div>
          </div>

          <button @click="startBridge" :disabled="isStarting || !portA || !portB || portA === portB"
            class="ui-btn-primary w-full text-xs py-2 font-bold inline-flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-40">
            <AppIcon v-if="isStarting" name="refresh" class="w-3.5 h-3.5 animate-spin" />
            <span>启动双串口全双工中继桥接 (COM-A ⇄ COM-B)</span>
          </button>
        </div>

        <!-- 3. 当前活跃物理中继器流水列表 -->
        <div class="space-y-3 border-t border-(--border-subtle) pt-4">
          <div class="flex items-center justify-between">
            <h4 class="text-xs font-bold text-(--text-primary) uppercase tracking-wider">
              当前活跃物理中继器清单 (<span class="ui-num">{{ activeBridges.length }}</span> 组)
            </h4>
            <button @click="fetchActiveBridges" class="ui-btn-secondary inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold cursor-pointer">
              <AppIcon name="refresh" class="w-3.5 h-3.5" />
              <span>刷新状态</span>
            </button>
          </div>

          <div class="space-y-2.5">
            <div v-for="b in activeBridges" :key="b.bridge_id"
              class="ui-content-card rounded-2xl p-3.5 flex flex-col gap-2">
              <div class="flex items-center justify-between gap-2">
                <div class="flex flex-wrap items-center gap-2 min-w-0">
                  <span class="w-2 h-2 rounded-full shrink-0" :class="b.is_running ? 'bg-emerald-500' : 'bg-slate-400'"></span>
                  <span class="font-bold text-xs text-(--text-primary) ui-num select-text">
                    {{ b.port_a }} (@{{ b.baud_a }}) ⇄ {{ b.port_b }} (@{{ b.baud_b }})
                  </span>
                  <span class="ui-pill text-[11px] px-2 py-0.5 ui-num select-text">
                    ID: {{ b.bridge_id }} · 运行 {{ b.uptime_secs }}s
                  </span>
                </div>
                <button @click="stopBridge(b.bridge_id)"
                  class="ui-btn-danger text-xs px-2.5 py-1 font-semibold cursor-pointer shrink-0">
                  停止中继
                </button>
              </div>

              <!-- 全双工双向转发度量 -->
              <div class="grid grid-cols-2 gap-2 text-xs ui-num bg-(--surface-content-alt) p-2.5 rounded-xl border border-(--border-subtle)">
                <div class="flex items-center justify-between">
                  <span class="text-(--text-muted)">A → B 转发量:</span>
                  <strong class="text-sky-600 dark:text-sky-400">{{ formatBytes(b.total_a_to_b_bytes) }}</strong>
                </div>
                <div class="flex items-center justify-between">
                  <span class="text-(--text-muted)">B → A 转发量:</span>
                  <strong class="text-emerald-600 dark:text-emerald-400">{{ formatBytes(b.total_b_to_a_bytes) }}</strong>
                </div>
              </div>
            </div>

            <EmptyState
              v-if="activeBridges.length === 0"
              icon="link"
              title="暂无运行中的双串口透明中继器"
              description="选择物理端口 A/B 启动全双工桥接，或在上方创建一个零外挂 RFC2217 / NamedPipe / POSIX PTY 虚拟拦截端点。"
            />
          </div>
        </div>
      </div>

      <!-- 底部关闭 -->
      <div class="px-6 py-3 border-t border-(--border-subtle) bg-(--surface-content-alt) flex items-center justify-end shrink-0">
        <button @click="$emit('close')" class="ui-btn-secondary px-4 py-1.5 text-xs font-semibold cursor-pointer">
          关闭
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { notifySuccess, notifyInfo, notifyError } from '../composables/useNotification';
import { ref, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';

export interface ActiveSerialBridgeInfo {
  bridge_id: string;
  port_a: string;
  baud_a: number;
  port_b: string;
  baud_b: number;
  start_time: string;
  uptime_secs: number;
  total_a_to_b_bytes: number;
  total_b_to_a_bytes: number;
  is_running: boolean;
}

interface VirtualPortPairHint {
  pair_name: string;
  port_a: string;
  port_b: string;
  driver_source: string;
}

interface SmartInterceptOutcome {
  started: boolean;
  recommended_strategy: string;
  diagnosis_reason: string;
  session?: InterceptSessionInfo | null;
}

interface SerialInterceptCapabilities {
  os_family: string;
  posix_pty_supported: boolean;
  windows_named_pipe_supported: boolean;
  rfc2217_gateway_supported: boolean;
  kernel_filter_driver: {
    driver_loaded: boolean;
    device_path: string;
    detail_message: string;
  };
  detected_virtual_ports?: VirtualPortPairHint[];
}

interface InterceptSessionInfo {
  session_id: string;
  mode: string;
  virtual_endpoint: string;
  target_port: string;
  baud_rate: number;
  uptime_secs: number;
  bytes_upstream_to_target: number;
  bytes_target_to_upstream: number;
  packets_captured: number;
  ioctl_control_events: number;
  is_running: boolean;
  status_detail: string;
}

const props = defineProps<{
  isOpen: boolean;
  serialPorts: string[];
}>();

const emit = defineEmits(['close', 'log']);

const portA = ref(props.serialPorts.length > 0 ? props.serialPorts[0] : '');
const baudA = ref(115200);
const parityA = ref('None');

const portB = ref(props.serialPorts.length > 1 ? props.serialPorts[1] : '');
const baudB = ref(9600);
const parityB = ref('None');

const isStarting = ref(false);
const activeBridges = ref<ActiveSerialBridgeInfo[]>([]);

const caps = ref<SerialInterceptCapabilities | null>(null);
const activeInterceptSessions = ref<InterceptSessionInfo[]>([]);
const selectedInterceptMode = ref<'rfc2217' | 'winpipe' | 'unixpty' | 'wdm'>('rfc2217');
const interceptTargetPort = ref('LOOPBACK_ECHO');
const rfcListenPort = ref(7001);
const winPipeSuffix = ref('vcom1');
const unixSymlinkAlias = ref('/tmp/omni_vcom1');
const isStartingIntercept = ref(false);
const smartDiagnosisMsg = ref('');
const smartStrategyTag = ref('');

const interceptModeTabs: Array<{ id: 'rfc2217' | 'winpipe' | 'unixpty' | 'wdm'; label: string }> = [
  { id: 'rfc2217', label: 'RFC 2217 TCP 网关' },
  { id: 'winpipe', label: 'Win32 NamedPipe' },
  { id: 'unixpty', label: 'POSIX PTY 节点' },
  { id: 'wdm', label: 'WDM 内核过滤' },
];

let pollTimer: ReturnType<typeof setInterval> | null = null;

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function defaultSerialConfig(baudRate: number, parity = 'None') {
  return {
    baud_rate: baudRate,
    data_bits: 8,
    parity,
    stop_bits: 1,
    flow_control: 'None',
    framing_mode: 'Auto3_5T',
    framing_timeout_ms: 30,
    framing_delimiter_hex: '0D0A',
    framing_fixed_length: 64,
  };
}

async function fetchCapabilities() {
  try {
    caps.value = await invoke<SerialInterceptCapabilities>('get_serial_intercept_capabilities_cmd');
  } catch (err) {
    console.warn('[SerialBridgeModal] 串口透明拦截能力探活返回异常:', err);
  }
}

async function fetchActiveBridges() {
  try {
    const [bridges, intercepts] = await Promise.all([
      invoke<ActiveSerialBridgeInfo[]>('list_active_serial_bridges'),
      invoke<InterceptSessionInfo[]>('list_active_intercept_sessions_cmd'),
    ]);
    activeBridges.value = bridges;
    activeInterceptSessions.value = intercepts;
  } catch (err) {
    console.debug('[SerialBridgeModal] poll inactive outside Tauri:', err);
  }
}

function refreshAll() {
  fetchCapabilities();
  fetchActiveBridges();
}

function applyVirtualPairToBridge(pair: VirtualPortPairHint) {
  portA.value = pair.port_a;
  portB.value = pair.port_b;
  notifySuccess('已载入虚拟串口对', `${pair.port_a} ⇄ ${pair.port_b} 已填入双全工桥梁参数区`);
}

async function runSmartIntercept() {
  isStartingIntercept.value = true;
  smartDiagnosisMsg.value = '';
  try {
    const prefer = selectedInterceptMode.value === 'winpipe' ? 'pipe' : selectedInterceptMode.value === 'rfc2217' ? 'rfc2217' : null;
    const outcome = await invoke<SmartInterceptOutcome>('smart_start_serial_intercept_cmd', {
      targetPort: interceptTargetPort.value,
      preferMode: prefer,
      config: defaultSerialConfig(115200),
    });
    smartStrategyTag.value = outcome.recommended_strategy;
    smartDiagnosisMsg.value = outcome.diagnosis_reason;
    await fetchActiveBridges();
    if (outcome.started && outcome.session) {
      notifySuccess('智能透明拦截已生效', `${outcome.recommended_strategy}: ${outcome.session.virtual_endpoint}`);
    } else {
      notifyInfo('智能串口拦截诊断完成', outcome.diagnosis_reason);
    }
  } catch (err) {
    notifyError('智能拦截探测异常', String(err));
  } finally {
    isStartingIntercept.value = false;
  }
}

async function launchInterceptSession() {
  isStartingIntercept.value = true;
  try {
    const cfg = defaultSerialConfig(115200);
    let info: InterceptSessionInfo;
    if (selectedInterceptMode.value === 'rfc2217') {
      info = await invoke<InterceptSessionInfo>('start_rfc2217_intercept_gateway_cmd', {
        listenPort: rfcListenPort.value,
        targetPort: interceptTargetPort.value,
        config: cfg,
      });
    } else if (selectedInterceptMode.value === 'winpipe') {
      info = await invoke<InterceptSessionInfo>('start_windows_named_pipe_intercept_cmd', {
        pipeSuffix: winPipeSuffix.value,
        targetPort: interceptTargetPort.value,
        config: cfg,
      });
    } else if (selectedInterceptMode.value === 'unixpty') {
      info = await invoke<InterceptSessionInfo>('start_unix_pty_intercept_cmd', {
        symlinkAlias: unixSymlinkAlias.value || null,
        targetPort: interceptTargetPort.value,
        config: cfg,
      });
    } else {
      info = await invoke<InterceptSessionInfo>('start_kernel_filter_tap_cmd');
    }
    await fetchActiveBridges();
    notifySuccess('透明拦截会话已建立', `${info.virtual_endpoint} ⇄ ${info.target_port}`);
  } catch (err) {
    notifyError('创建透明拦截会话受阻', String(err));
  } finally {
    isStartingIntercept.value = false;
  }
}

async function stopIntercept(sessionId: string) {
  try {
    const msg = await invoke<string>('stop_intercept_session_cmd', { sessionId });
    await fetchActiveBridges();
    notifyInfo('拦截会话已结束', msg);
  } catch (err) {
    notifyError('停止拦截会话失败', String(err));
  }
}

async function startBridge() {
  if (!portA.value || !portB.value || portA.value === portB.value || isStarting.value) return;
  isStarting.value = true;

  try {
    const res = await invoke<string>('start_serial_bridge_cmd', {
      portA: portA.value,
      configA: defaultSerialConfig(baudA.value, parityA.value),
      portB: portB.value,
      configB: defaultSerialConfig(baudB.value, parityB.value),
    });
    emit('log', res);
    await fetchActiveBridges();
    notifySuccess('全双工中继桥已建立', `${portA.value} ⇄ ${portB.value} 双向透传与引脚镜像就绪`);
  } catch (err) {
    notifyError('启动双串口中继受阻', String(err));
  } finally {
    isStarting.value = false;
  }
}

async function stopBridge(bridgeId: string) {
  try {
    const res = await invoke<string>('stop_serial_bridge_cmd', { bridgeId });
    emit('log', res);
    await fetchActiveBridges();
    notifyInfo('双串口中继已断开', '已安全终止双向数据透传与引脚监控');
  } catch (err) {
    notifyError('停止串口中继受阻', String(err));
  }
}

onMounted(() => {
  refreshAll();
  pollTimer = setInterval(fetchActiveBridges, 2000);
});

onUnmounted(() => {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
});
</script>
