<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md">
    <!-- 模态框主体 (Apple Glassmorphism 主动探测引擎控制台) -->
    <div class="w-full max-w-2xl bg-white/90 backdrop-blur-2xl rounded-3xl border border-white/60 shadow-2xl flex flex-col overflow-hidden max-h-[92vh]">

      <!-- 顶栏 -->
      <div class="px-6 py-4 border-b border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <span class="w-3 h-3 rounded-full bg-amber-500 shadow-sm"></span>
          <div>
            <h3 class="text-sm font-bold text-slate-900">主动探测引擎 (Active Probing Engine)</h3>
            <p class="text-[11px] text-slate-500 font-mono">ICMP 物理层探测 • TCP 端口探测 • 连续心跳探针 • 主动拉流引擎</p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer">
          ✕
        </button>
      </div>

      <!-- 参数表单与动作区 -->
      <div class="p-6 space-y-4 overflow-auto custom-scrollbar">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-bold text-slate-700 mb-1">目标 IP 资产 (Target IP):</label>
            <input v-model="targetIp" placeholder="如: 192.168.1.50 或 10.0.0.1"
              class="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-amber-500/30 shadow-2xs">
          </div>
          <div>
            <label class="block text-xs font-bold text-slate-700 mb-1">目标端口 (Port / 可逗号分隔):</label>
            <input v-model="targetPort" placeholder="如: 80 或 80,443,502,1883,8080"
              class="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-amber-500/30 shadow-2xs">
          </div>
        </div>

        <!-- 动作按钮行 1：单次探测 -->
        <div class="flex items-center gap-3 pt-1">
          <button @click="doPing" :disabled="isProbing || !targetIp.trim()"
            class="flex-1 bg-gradient-to-r from-sky-600 to-blue-600 hover:from-sky-700 hover:to-blue-700 text-white text-xs px-4 py-2.5 rounded-xl font-bold transition-all flex items-center justify-center gap-2 cursor-pointer shadow-sm active:scale-95 disabled:opacity-40">
            <span>🛰️ 物理层存活探测 (ICMP Ping)</span>
          </button>
          <button @click="doTcpProbe" :disabled="isProbing || !targetIp.trim()"
            class="flex-1 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white text-xs px-4 py-2.5 rounded-xl font-bold transition-all flex items-center justify-center gap-2 cursor-pointer shadow-sm active:scale-95 disabled:opacity-40">
            <span>🔓 传输层端口探测 (TCP Connect)</span>
          </button>
          <button @click="logs = []" class="px-3 py-2.5 rounded-xl text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-600 transition-colors cursor-pointer">
            清屏
          </button>
        </div>

        <!-- 动作区 2：连续心跳探测 (start_continuous_probe_cmd) -->
        <div class="rounded-2xl border border-slate-200 bg-slate-50/70 p-3.5 space-y-2.5">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full" :class="continuousRunning ? 'bg-emerald-500 animate-pulse' : 'bg-slate-300'"></span>
              <span class="text-xs font-bold text-slate-800">连续心跳探针 (Continuous Heartbeat Probe)</span>
              <span class="text-[10px] text-slate-400 font-mono">周期性 TCP 握手存活监测，目标断线自动记录</span>
            </div>
            <span v-if="continuousRunning" class="text-[10px] font-bold text-emerald-700 bg-emerald-500/10 px-2 py-0.5 rounded-lg border border-emerald-300/60">运行中</span>
          </div>
          <div class="flex items-center gap-2">
            <input v-model.number="continuousInterval" type="number" min="1" max="3600" title="探测周期（秒）"
              class="w-20 bg-white border border-slate-200 rounded-lg px-2 py-1.5 text-xs font-mono shadow-2xs">
            <span class="text-[11px] text-slate-500">秒/次，使用上方目标 IP 与首个端口</span>
            <div class="flex-1"></div>
            <button v-if="!continuousRunning" @click="startContinuous" :disabled="isProbing || !targetIp.trim()"
              class="bg-gradient-to-r from-emerald-600 to-green-600 hover:from-emerald-700 text-white text-xs px-3.5 py-1.5 rounded-xl font-bold cursor-pointer transition-all shadow-sm active:scale-95 disabled:opacity-40">
              启动心跳
            </button>
            <button v-else @click="stopAllEngines"
              class="bg-rose-500/10 hover:bg-rose-500/20 text-rose-700 border border-rose-300/60 text-xs px-3.5 py-1.5 rounded-xl font-bold cursor-pointer transition-all active:scale-95">
              停止
            </button>
          </div>
        </div>

        <!-- 动作区 3：主动拉流引擎 (start_stream_pull_cmd / stop_stream_pull_cmd) -->
        <div class="rounded-2xl border border-slate-200 bg-slate-50/70 p-3.5 space-y-2.5">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full" :class="pullRunning ? 'bg-indigo-500 animate-pulse' : 'bg-slate-300'"></span>
              <span class="text-xs font-bold text-slate-800">主动拉流引擎 (Active Stream Pull)</span>
              <span class="text-[10px] text-slate-400 font-mono">持续从目标端口拉取数据流，断线自动重连</span>
            </div>
            <span v-if="pullRunning" class="text-[10px] font-bold text-indigo-700 bg-indigo-500/10 px-2 py-0.5 rounded-lg border border-indigo-300/60">拉取中</span>
          </div>
          <div class="flex items-center gap-2">
            <input v-model.number="pullReconnect" type="number" min="1" max="600" title="断线重连间隔（秒）"
              class="w-20 bg-white border border-slate-200 rounded-lg px-2 py-1.5 text-xs font-mono shadow-2xs">
            <span class="text-[11px] text-slate-500">秒后重连，使用上方目标 IP 与首个端口</span>
            <div class="flex-1"></div>
            <button v-if="!pullRunning" @click="startPull" :disabled="isProbing || !targetIp.trim()"
              class="bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 text-white text-xs px-3.5 py-1.5 rounded-xl font-bold cursor-pointer transition-all shadow-sm active:scale-95 disabled:opacity-40">
              启动拉流
            </button>
            <button v-else @click="stopAllEngines"
              class="bg-rose-500/10 hover:bg-rose-500/20 text-rose-700 border border-rose-300/60 text-xs px-3.5 py-1.5 rounded-xl font-bold cursor-pointer transition-all active:scale-95">
              停止
            </button>
          </div>
        </div>

        <!-- 实时控制台日志输出 -->
        <div class="flex flex-col gap-1.5">
          <div class="flex items-center justify-between text-[11px] text-slate-500 font-mono">
            <span>探针实时输出 (Console Logs)</span>
            <span>共 {{ logs.length }} 条记录</span>
          </div>
          <div ref="logBoxRef" class="bg-slate-900/95 backdrop-blur-xl text-emerald-400 p-4 rounded-2xl font-mono text-xs h-56 overflow-auto border border-white/10 shadow-inner space-y-1">
            <div v-for="(log, idx) in logs" :key="idx" :class="log.color || 'text-emerald-400'" class="leading-relaxed">
              {{ log.text }}
            </div>
            <div v-if="logs.length === 0" class="text-slate-600 text-center py-16">
              请输入目标 IP 与端口，点击上方按钮发起主动刺探
            </div>
          </div>
        </div>
      </div>

      <!-- 底栏 -->
      <div class="px-6 py-3 border-t border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0 text-xs text-slate-400 font-mono">
        <span>ICMP/TCP/心跳/拉流 零假数据客观探活 • 真实物理耗时度量</span>
        <button @click="$emit('close')" class="px-4 py-1.5 rounded-xl font-semibold bg-slate-900 hover:bg-slate-800 text-white shadow-sm transition-all cursor-pointer">
          关闭
        </button>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, nextTick } from 'vue';
import { invoke } from '@tauri-apps/api/core';

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

function appendLog(text: string, color = 'text-emerald-400') {
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

// ============================================================
// A4 修复：真实 ICMP 物理层探测 (run_icmp_ping_cmd)
// 原实现以 probe_asset_ports_cmd 端口探活冒充 Ping，属前端造假，
// 现改为后端 active_probe 真实 ICMP 回显探测。
// ============================================================
async function doPing() {
  const ip = targetIp.value.trim();
  if (!ip) return;
  isProbing.value = true;
  appendLog(`[*] 🚀 正在向 ${ip} 发射 ICMP 回显探针 (真实物理层 Ping)...`, 'text-sky-300');

  try {
    const res = await invoke<ProbeResult>('run_icmp_ping_cmd', { targetIp: ip, timeoutMs: 3000 });
    if (res.status === 'ONLINE') {
      appendLog(`[+] 🎯 ICMP 应答成功: ${res.target} 存活 (RTT: ${res.latency_ms.toFixed(1)}ms)`, 'text-emerald-300 font-bold');
      if (res.payload_hex) {
        appendLog(`    应答载荷: ${res.payload_hex}`, 'text-slate-300');
      }
    } else if (res.status === 'TIMEOUT') {
      appendLog(`[!] ⏱ ICMP 探针超时: ${ip} 无应答 (目标离线或防火墙丢弃回显)`, 'text-amber-300');
    } else {
      appendLog(`[-] 🚫 ICMP 探测失败: ${ip} 状态=${res.status} (RTT: ${res.latency_ms.toFixed(1)}ms)`, 'text-rose-400');
    }
  } catch (e: any) {
    appendLog(`[-] 🚫 ICMP 探测异常: ${e}`, 'text-rose-400');
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
    appendLog(`[!] 错误: 请输入有效的数字端口 (1-65535)!`, 'text-rose-400');
    return;
  }

  isProbing.value = true;
  appendLog(`[*] 🔌 正在向 ${ip} 目标端口群 [${ports.join(', ')}] 发起 TCP 三次握手探测...`, 'text-sky-300');

  const targets = ports.map(port => ({ ip, port }));
  try {
    await invoke('run_target_scan_cmd', { targets, timeoutMs: 2500 });
    appendLog(`[*] 靶向握手探测指令已下发，请留意系统日志流中的实时握手回执...`, 'text-slate-300');
  } catch (e: any) {
    appendLog(`[-] 🚫 端口探测失败: ${e}`, 'text-rose-400');
  } finally {
    isProbing.value = false;
  }
}

// ============================================================
// B7: 连续心跳探针 (start_continuous_probe_cmd)
// 周期性对 host:port 发起 TCP 连接，探测结果经 packet-recovered
// 事件回传主表格与系统日志。
// ============================================================
async function startContinuous() {
  const ip = targetIp.value.trim();
  const port = firstPort();
  if (!ip) {
    appendLog(`[!] 错误: 请先输入目标 IP`, 'text-rose-400');
    return;
  }
  if (!port) {
    appendLog(`[!] 错误: 请在端口栏输入至少一个有效端口`, 'text-rose-400');
    return;
  }
  try {
    const res = await invoke<string>('start_continuous_probe_cmd', {
      host: ip,
      port,
      intervalSecs: continuousInterval.value
    });
    continuousRunning.value = true;
    appendLog(res, 'text-emerald-300 font-bold');
  } catch (e: any) {
    appendLog(`[-] 🚫 心跳探针启动失败: ${e}`, 'text-rose-400');
  }
}

// ============================================================
// B8: 主动拉流引擎 (start_stream_pull_cmd / stop_stream_pull_cmd)
// 持续连接目标端口拉取数据流，断线按间隔自动重连。
// ============================================================
async function startPull() {
  const ip = targetIp.value.trim();
  const port = firstPort();
  if (!ip) {
    appendLog(`[!] 错误: 请先输入目标 IP`, 'text-rose-400');
    return;
  }
  if (!port) {
    appendLog(`[!] 错误: 请在端口栏输入至少一个有效端口`, 'text-rose-400');
    return;
  }
  try {
    const res = await invoke<string>('start_stream_pull_cmd', {
      host: ip,
      port,
      reconnectSecs: pullReconnect.value
    });
    pullRunning.value = true;
    appendLog(res, 'text-indigo-300 font-bold');
  } catch (e: any) {
    appendLog(`[-] 🚫 拉流引擎启动失败: ${e}`, 'text-rose-400');
  }
}

async function stopAllEngines() {
  if (continuousRunning.value) {
    try {
      const res = await invoke<string>('stop_continuous_probe_cmd');
      appendLog(res, 'text-slate-300');
    } catch (e: any) {
      appendLog(`[-] 🚫 停止心跳探针失败: ${e}`, 'text-rose-400');
    }
    continuousRunning.value = false;
  }
  if (pullRunning.value) {
    try {
      const res = await invoke<string>('stop_stream_pull_cmd');
      appendLog(res, 'text-slate-300');
    } catch (e: any) {
      appendLog(`[-] 🚫 停止拉流失败: ${e}`, 'text-rose-400');
    }
    pullRunning.value = false;
  }
}
</script>
