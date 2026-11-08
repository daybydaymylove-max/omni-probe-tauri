<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md">
    <div class="w-full max-w-4xl bg-white/95 backdrop-blur-2xl rounded-3xl border border-white/60 shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      <!-- 头部 -->
      <div class="px-6 py-4 border-b border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-teal-50 border border-teal-200 flex items-center justify-center text-teal-700 text-sm font-bold shadow-2xs">
            ⚡
          </div>
          <div>
            <h3 class="text-sm font-bold text-slate-900">跨总线网关协议转换因果关联追踪看板</h3>
            <p class="text-[11px] text-slate-500 font-mono">纳秒级因果时序追踪：以太网 (Modbus-TCP) ⇄ 串口 (Modbus-RTU) 现场网关转换时延度量</p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer">
          ✕
        </button>
      </div>

      <!-- 主体内容 -->
      <div class="p-6 space-y-4 overflow-auto max-h-[75vh] custom-scrollbar">
        <!-- 统计看板 -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div class="bg-teal-50/70 border border-teal-100 p-3 rounded-2xl shadow-2xs">
            <div class="text-[10px] text-teal-600 font-bold uppercase">网关转换因果对数</div>
            <div class="text-base font-bold text-teal-950 font-mono mt-0.5">
              {{ correlations.length }} 组对
            </div>
          </div>
          <div class="bg-blue-50/70 border border-blue-100 p-3 rounded-2xl shadow-2xs">
            <div class="text-[10px] text-blue-600 font-bold uppercase">平均网关转发时延 (Avg Δt)</div>
            <div class="text-base font-bold text-blue-950 font-mono mt-0.5">
              {{ avgLatency.toFixed(2) }} ms
            </div>
          </div>
          <div class="bg-emerald-50/70 border border-emerald-100 p-3 rounded-2xl shadow-2xs">
            <div class="text-[10px] text-emerald-600 font-bold uppercase">最小时延 (Min Δt)</div>
            <div class="text-base font-bold text-emerald-950 font-mono mt-0.5">
              {{ minLatency.toFixed(2) }} ms
            </div>
          </div>
          <div class="bg-purple-50/70 border border-purple-100 p-3 rounded-2xl shadow-2xs">
            <div class="text-[10px] text-purple-600 font-bold uppercase">最大时延 (Max Δt)</div>
            <div class="text-base font-bold font-mono mt-0.5" :class="maxLatency > 100 ? 'text-rose-600' : 'text-purple-950'">
              {{ maxLatency.toFixed(2) }} ms
            </div>
          </div>
        </div>

        <!-- 列表工具栏 -->
        <div class="flex items-center justify-between text-xs pt-1">
          <div class="flex items-center gap-2">
            <span class="font-bold text-slate-700">因果关联事件明细流水 ({{ correlations.length }})</span>
            <span class="text-[10px] text-slate-400 font-mono">Δt = (t_serial - t_eth) / 10⁶ ms</span>
          </div>
          <div class="flex items-center gap-2">
            <button @click="fetchCorrelations" :disabled="isLoading"
              class="bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-2.5 py-1 rounded-xl text-xs font-semibold transition-all cursor-pointer shadow-2xs active:scale-95 disabled:opacity-40">
              <span v-if="isLoading">⏳</span>
              <span v-else>⟳</span>
              <span>即时刷新</span>
            </button>
          </div>
        </div>

        <!-- 因果事件对表格 -->
        <div class="border border-slate-200/80 rounded-2xl overflow-hidden bg-white shadow-2xs">
          <table class="w-full text-left text-xs font-mono border-collapse table-fixed">
            <thead class="bg-slate-100/90 text-slate-500 text-[10px] uppercase font-bold border-b border-slate-200">
              <tr>
                <th class="p-2.5 w-[20%]">关联 ID</th>
                <th class="p-2.5 w-[14%]">以太网帧 #ID</th>
                <th class="p-2.5 w-[14%]">串口帧 #ID</th>
                <th class="p-2.5 w-[16%]">规约/从机/功能码</th>
                <th class="p-2.5 w-[18%]">网关转换时延 (Δt)</th>
                <th class="p-2.5 w-[18%] text-center">状态评估</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100 text-[11px]">
              <tr v-for="item in correlations.slice().reverse()" :key="item.correlation_id" class="hover:bg-slate-50/80 transition-colors">
                <td class="p-2.5 font-bold text-slate-800 truncate" :title="item.correlation_id">
                  {{ item.correlation_id }}
                </td>
                <td class="p-2.5 text-blue-700 font-bold">
                  以太网 #{{ item.eth_packet_id }}
                </td>
                <td class="p-2.5 text-indigo-700 font-bold">
                  串口 #{{ item.serial_packet_id }}
                </td>
                <td class="p-2.5 text-slate-700">
                  <span class="font-semibold">{{ item.protocol }}</span>
                  <span class="text-slate-400 text-[10px] block">从机: {{ item.slave_addr }} | 功能: 0x{{ item.function_code.toString(16).padStart(2, '0').toUpperCase() }}</span>
                </td>
                <td class="p-2.5 font-bold" :class="getLatencyClass(item.latency_ms)">
                  {{ item.latency_ms.toFixed(3) }} ms
                </td>
                <td class="p-2.5 text-center">
                  <span :class="['px-2 py-0.5 rounded text-[9px] font-bold border shadow-2xs', getStatusBadge(item.latency_ms)]">
                    {{ item.latency_ms < 20 ? '✓ 优异' : item.latency_ms < 100 ? '⚡ 正常' : '⚠️ 高抖动' }}
                  </span>
                </td>
              </tr>
              <tr v-if="correlations.length === 0">
                <td colspan="6" class="p-8 text-center text-slate-400 text-xs">
                  暂未检测到以太网与串口间的协议因果对应对。当以太网接收 Modbus-TCP 且串口捕获到对应的 Modbus-RTU 转换帧时将自动关联。
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- 底部关闭 -->
      <div class="px-6 py-3 border-t border-slate-200/60 bg-white/40 flex items-center justify-end shrink-0">
        <button @click="$emit('close')" class="px-4 py-1.5 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer">
          关闭
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';

export interface CrossBusCorrelationRecord {
  correlation_id: string;
  eth_packet_id: number;
  serial_packet_id: number;
  protocol: string;
  slave_addr: number;
  function_code: number;
  latency_ms: number;
  eth_time_ns: number;
  serial_time_ns: number;
}

defineProps<{
  isOpen: boolean;
}>();

defineEmits(['close']);

const correlations = ref<CrossBusCorrelationRecord[]>([]);
const isLoading = ref(false);

let pollTimer: any = null;

const avgLatency = computed(() => {
  if (correlations.value.length === 0) return 0;
  const sum = correlations.value.reduce((acc, c) => acc + c.latency_ms, 0);
  return sum / correlations.value.length;
});

const minLatency = computed(() => {
  if (correlations.value.length === 0) return 0;
  return Math.min(...correlations.value.map(c => c.latency_ms));
});

const maxLatency = computed(() => {
  if (correlations.value.length === 0) return 0;
  return Math.max(...correlations.value.map(c => c.latency_ms));
});

function getLatencyClass(lat: number): string {
  if (lat < 20) return 'text-emerald-600';
  if (lat < 100) return 'text-amber-600';
  return 'text-rose-600';
}

function getStatusBadge(lat: number): string {
  if (lat < 20) return 'bg-emerald-50 text-emerald-800 border-emerald-200';
  if (lat < 100) return 'bg-amber-50 text-amber-800 border-amber-200';
  return 'bg-rose-50 text-rose-800 border-rose-200';
}

async function fetchCorrelations() {
  if (isLoading.value) return;
  isLoading.value = true;
  try {
    const list = await invoke<CrossBusCorrelationRecord[]>('get_cross_bus_correlations_cmd');
    correlations.value = list;
  } catch (err) {
    console.error('获取跨总线因果关联失败:', err);
  } finally {
    isLoading.value = false;
  }
}

onMounted(() => {
  fetchCorrelations();
  pollTimer = setInterval(fetchCorrelations, 2000);
});

onUnmounted(() => {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
});
</script>
