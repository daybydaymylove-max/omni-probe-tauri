<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 ui-modal-backdrop">
    <div class="w-full max-w-2xl ui-modal-surface rounded-3xl flex flex-col overflow-hidden max-h-[92vh]">

      <!-- 顶栏 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-6 py-4 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <span class="w-3 h-3 rounded-full bg-amber-500 shrink-0"></span>
          <div>
            <h3 class="text-sm font-bold" style="color: var(--text-primary)">主动探测引擎 (Active Probing Engine)</h3>
            <p class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">ICMP 物理层探测 · TCP 端口探测 · 连续心跳探针 · 主动拉流引擎</p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer" title="关闭">
          <AppIcon name="close" :size="15" />
        </button>
      </header>

      <!-- 参数表单与动作区 -->
      <div class="p-6 space-y-4 overflow-auto custom-scrollbar" style="background: var(--surface-content)">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-bold mb-1" style="color: var(--text-secondary)">目标 IP 资产 (Target IP):</label>
            <input v-model="targetIp" placeholder="如: 192.168.1.50 或 10.0.0.1" class="w-full ui-input ui-num px-3 py-2 text-xs">
          </div>
          <div>
            <label class="block text-xs font-bold mb-1" style="color: var(--text-secondary)">目标端口 (Port / 逗号分隔):</label>
            <input v-model="targetPort" placeholder="如: 80 或 80,443,502,1883,8080" class="w-full ui-input ui-num px-3 py-2 text-xs">
          </div>
        </div>

        <div class="flex items-center gap-3 pt-1 flex-wrap">
          <button @click="doPing" :disabled="isProbing || !targetIp.trim()"
            class="flex-1 ui-btn-primary justify-center text-xs px-4 py-2.5 rounded-xl">
            <AppIcon name="radar" :size="13" />
            <span>物理层存活探测 (ICMP Ping)</span>
          </button>
          <button @click="doTcpProbe" :disabled="isProbing || !targetIp.trim()"
            class="flex-1 ui-btn-primary justify-center text-xs px-4 py-2.5 rounded-xl">
            <AppIcon name="link" :size="13" />
            <span>传输层端口探测 (TCP Connect)</span>
          </button>
          <button @click="logs = []" class="ui-btn-secondary px-3 py-2.5 rounded-xl text-xs font-semibold">
            清屏
          </button>
        </div>

        <div class="ui-sub-card p-3.5 space-y-2.5">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full shrink-0" :class="continuousRunning ? 'bg-emerald-500' : 'bg-slate-400'"></span>
              <span class="text-xs font-bold" style="color: var(--text-primary)">连续心跳探针</span>
              <span class="text-[11px] ui-num" style="color: var(--text-muted)">周期性 TCP 握手监测，断线自动记录</span>
            </div>
            <span v-if="continuousRunning" class="text-[11px] font-bold text-emerald-700 dark:text-emerald-300 bg-emerald-500/12 px-2 py-0.5 rounded-lg border border-emerald-500/25">运行中</span>
          </div>
          <div class="flex items-center gap-2 flex-wrap">
            <input v-model.number="continuousInterval" type="number" min="1" max="3600" title="探测周期（秒）"
              class="w-20 ui-input ui-num px-2.5 py-1.5 text-xs">
            <span class="text-[11px]" style="color: var(--text-muted)">秒/次，使用上方目标 IP 与首个端口</span>
            <div class="flex-1"></div>
            <button v-if="!continuousRunning" @click="startContinuous" :disabled="isProbing || !targetIp.trim()"
              class="ui-btn-primary text-xs px-3.5 py-1.5 rounded-xl">
              启动心跳
            </button>
            <button v-else @click="stopAllEngines" class="ui-btn-danger text-xs px-3.5 py-1.5 rounded-xl">
              停止
            </button>
          </div>
        </div>

        <div class="ui-sub-card p-3.5 space-y-2.5">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full shrink-0" :class="pullRunning ? 'bg-indigo-500' : 'bg-slate-400'"></span>
              <span class="text-xs font-bold" style="color: var(--text-primary)">主动拉流引擎</span>
              <span class="text-[11px] ui-num" style="color: var(--text-muted)">持续拉取目标端口数据流，断线自动重连</span>
            </div>
            <span v-if="pullRunning" class="text-[11px] font-bold text-indigo-700 dark:text-indigo-300 bg-indigo-500/12 px-2 py-0.5 rounded-lg border border-indigo-500/25">拉取中</span>
          </div>
          <div class="flex items-center gap-2 flex-wrap">
            <input v-model.number="pullReconnect" type="number" min="1" max="600" title="断线重连间隔（秒）"
              class="w-20 ui-input ui-num px-2.5 py-1.5 text-xs">
            <span class="text-[11px]" style="color: var(--text-muted)">秒后重连，使用上方目标 IP 与首个端口</span>
            <div class="flex-1"></div>
            <button v-if="!pullRunning" @click="startPull" :disabled="isProbing || !targetIp.trim()"
              class="ui-btn-primary text-xs px-3.5 py-1.5 rounded-xl">
              启动拉流
            </button>
            <button v-else @click="stopAllEngines" class="ui-btn-danger text-xs px-3.5 py-1.5 rounded-xl">
              停止
            </button>
          </div>
        </div>

        <!-- 实时控制台日志输出 -->
        <div class="flex flex-col gap-1.5 select-text">
          <div class="flex items-center justify-between text-[11px] ui-num" style="color: var(--text-muted)">
            <span>探针实时输出 (Console Logs)</span>
            <span>共 {{ logs.length }} 条记录</span>
          </div>
          <div ref="logBoxRef" class="ui-input font-mono-code p-3.5 text-xs h-56 overflow-auto space-y-1">
            <div v-for="(log, idx) in logs" :key="idx" :class="log.color || 'text-emerald-700 dark:text-emerald-400'" class="leading-relaxed">
              {{ log.text }}
            </div>
            <EmptyState
              v-if="logs.length === 0"
              class="py-8"
              icon="terminal"
              title="等待主动探测输出"
              description="请输入目标 IP 与端口，点击上方探测或心跳按钮启动执行。"
            />
          </div>
        </div>
      </div>

      <!-- 底栏 -->
      <footer class="px-6 py-3 border-t flex items-center justify-between shrink-0 text-xs ui-num" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-muted)">
        <span>ICMP / TCP / 心跳 / 拉流 实时物理耗时度量</span>
        <button @click="$emit('close')" class="ui-btn-secondary px-4 py-1.5 rounded-xl font-semibold">
          关闭
        </button>
      </footer>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, nextTick } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';

// ProbeResult 结构严格对齐 src-tauri/src/active_probe.rs L33-42
interface ProbeResult {
  id: number;
  timestamp: string;
  target: string;
  protocol: string;
  status: string;         // "ONLINE" | "OFFLINE" | "TIMEOUT"
  latency_ms: number;
  payload_hex: string;
  detected_protocol: string;
}

const props = defineProps<{
  isOpen: boolean;
  defaultIp?: string;
  defaultPort?: string | number;
}>();

defineEmits(['close']);

const targetIp = ref(props.defaultIp || '');
const targetPort = ref(String(props.defaultPort || '80'));
const isProbing = ref(false);
const logs = ref<Array<{ text: string; color?: string }>>([]);
const logBoxRef = ref<HTMLElement | null>(null);

const continuousRunning = ref(false);
const continuousInterval = ref(5);
const pullRunning = ref(false);
const pullReconnect = ref(5);

watch(() => props.isOpen, (open) => {
  if (open) {
    if (props.defaultIp) targetIp.value = props.defaultIp;
    if (props.defaultPort) targetPort.value = String(props.defaultPort);
  }
});

function appendLog(text: string, color = 'text-emerald-700 dark:text-emerald-400') {
  const ts = new Date().toLocaleTimeString('zh-CN', { hour12: false });
  logs.value.push({ text: `[${ts}] ${text}`, color });
  nextTick(() => {
    if (logBoxRef.value) {
      logBoxRef.value.scrollTop = logBoxRef.value.scrollHeight;
    }
  });
}

// 首个有效端口（供心跳探针与拉流引擎使用）
function firstPort(): number | null {
  const p = parseInt(targetPort.value.split(',')[0].trim(), 10);
  return !isNaN(p) && p > 0 && p <= 65535 ? p : null;
}

async function doPing() {
  const ip = targetIp.value.trim();
  if (!ip) return;
  isProbing.value = true;
  appendLog(`[*] 正在向 ${ip} 发射 ICMP 回显探针 (真实物理层 Ping)...`, 'text-sky-700 dark:text-sky-300');

  try {
    const res = await invoke<ProbeResult>('run_icmp_ping_cmd', { targetIp: ip, timeoutMs: 3000 });
    if (res.status === 'ONLINE') {
      appendLog(`[+] ICMP 应答成功: ${res.target} 存活 (RTT: ${res.latency_ms.toFixed(1)}ms)`, 'text-emerald-700 dark:text-emerald-300 font-bold');
      if (res.payload_hex) {
        appendLog(`    应答载荷: ${res.payload_hex}`, 'text-[var(--text-secondary)]');
      }
    } else if (res.status === 'TIMEOUT') {
      appendLog(`[!] ICMP 探针超时: ${ip} 无应答 (目标离线或防火墙丢弃回显)`, 'text-amber-700 dark:text-amber-300');
    } else {
      appendLog(`[-] ICMP 探测失败: ${ip} 状态=${res.status} (RTT: ${res.latency_ms.toFixed(1)}ms)`, 'text-rose-700 dark:text-rose-400');
    }
  } catch (e: any) {
    appendLog(`[-] ICMP 探测异常: ${e}`, 'text-rose-700 dark:text-rose-400');
  } finally {
    isProbing.value = false;
  }
}

async function doTcpProbe() {
  const ip = targetIp.value.trim();
  const portStr = targetPort.value.trim();
  if (!ip) return;

  const ports = portStr.split(',').map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p) && p > 0 && p <= 65535);
  if (ports.length === 0) {
    appendLog(`[!] 错误: 请输入有效的数字端口 (1-65535)`, 'text-rose-700 dark:text-rose-400');
    return;
  }

  isProbing.value = true;
  appendLog(`[*] 正在向 ${ip} 目标端口 [${ports.join(', ')}] 发起 TCP 三次握手探测...`, 'text-sky-700 dark:text-sky-300');

  const targets = ports.map(port => ({ ip, port }));
  try {
    await invoke('run_target_scan_cmd', { targets, timeoutMs: 2500 });
    appendLog(`[*] 靶向握手探测指令已下发，请留意系统日志流中的实时握手回执...`, 'text-[var(--text-secondary)]');
  } catch (e: any) {
    appendLog(`[-] 端口探测失败: ${e}`, 'text-rose-700 dark:text-rose-400');
  } finally {
    isProbing.value = false;
  }
}

async function startContinuous() {
  const ip = targetIp.value.trim();
  const port = firstPort();
  if (!ip) {
    appendLog(`[!] 错误: 请先输入目标 IP`, 'text-rose-700 dark:text-rose-400');
    return;
  }
  if (!port) {
    appendLog(`[!] 错误: 请在端口栏输入至少一个有效端口`, 'text-rose-700 dark:text-rose-400');
    return;
  }
  try {
    const res = await invoke<string>('start_continuous_probe_cmd', {
      host: ip,
      port,
      intervalSecs: continuousInterval.value
    });
    continuousRunning.value = true;
    appendLog(res, 'text-emerald-700 dark:text-emerald-300 font-bold');
  } catch (e: any) {
    appendLog(`[-] 心跳探针启动失败: ${e}`, 'text-rose-700 dark:text-rose-400');
  }
}

async function startPull() {
  const ip = targetIp.value.trim();
  const port = firstPort();
  if (!ip) {
    appendLog(`[!] 错误: 请先输入目标 IP`, 'text-rose-700 dark:text-rose-400');
    return;
  }
  if (!port) {
    appendLog(`[!] 错误: 请在端口栏输入至少一个有效端口`, 'text-rose-700 dark:text-rose-400');
    return;
  }
  try {
    const res = await invoke<string>('start_stream_pull_cmd', {
      host: ip,
      port,
      reconnectSecs: pullReconnect.value
    });
    pullRunning.value = true;
    appendLog(res, 'text-indigo-700 dark:text-indigo-300 font-bold');
  } catch (e: any) {
    appendLog(`[-] 拉流引擎启动失败: ${e}`, 'text-rose-700 dark:text-rose-400');
  }
}

async function stopAllEngines() {
  if (continuousRunning.value) {
    try {
      const res = await invoke<string>('stop_continuous_probe_cmd');
      appendLog(res, 'text-[var(--text-secondary)]');
    } catch (e: any) {
      appendLog(`[-] 停止心跳探针失败: ${e}`, 'text-rose-700 dark:text-rose-400');
    }
    continuousRunning.value = false;
  }
  if (pullRunning.value) {
    try {
      const res = await invoke<string>('stop_stream_pull_cmd');
      appendLog(res, 'text-[var(--text-secondary)]');
    } catch (e: any) {
      appendLog(`[-] 停止拉流失败: ${e}`, 'text-rose-700 dark:text-rose-400');
    }
    pullRunning.value = false;
  }
}
</script>
