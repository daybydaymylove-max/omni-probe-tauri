<template>
  <div v-if="isOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
    <div class="ui-modal-surface w-full max-w-4xl rounded-3xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      <!-- 头部 -->
      <div class="ui-nav-glass px-6 py-4 border-b border-(--border-subtle) flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-teal-500/12 border border-teal-500/30 flex items-center justify-center text-teal-600 dark:text-teal-400">
            <AppIcon name="zap" class="w-4 h-4" />
          </div>
          <div>
            <h3 class="text-sm font-bold text-(--text-primary)">跨总线网关协议转换因果关联追踪看板</h3>
            <p class="text-xs text-(--text-muted) font-mono-code">纳秒级因果时序追踪：以太网 (Modbus-TCP) ⇄ 串口 (Modbus-RTU) 现场网关转换时延度量</p>
          </div>
        </div>
        <button @click="$emit('close')" class="ui-btn-secondary w-8 h-8 rounded-full p-0 flex items-center justify-center cursor-pointer" aria-label="关闭弹窗">
          <AppIcon name="close" class="w-4 h-4" />
        </button>
      </div>

      <!-- 主体内容 -->
      <div class="p-6 space-y-4 overflow-auto max-h-[75vh] custom-scrollbar">
        <!-- 统计看板 -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div class="ui-content-card p-3.5 rounded-2xl">
            <div class="text-[11px] text-teal-600 dark:text-teal-400 font-bold uppercase">网关转换因果对数</div>
            <div class="text-base font-bold text-(--text-primary) ui-num font-mono-code mt-0.5 select-text">
              {{ correlations.length }} 组对
            </div>
          </div>
          <div class="ui-content-card p-3.5 rounded-2xl">
            <div class="text-[11px] text-sky-600 dark:text-sky-400 font-bold uppercase">平均网关转发时延 (Avg Δt)</div>
            <div class="text-base font-bold text-(--text-primary) ui-num font-mono-code mt-0.5 select-text">
              {{ avgLatency.toFixed(2) }} ms
            </div>
          </div>
          <div class="ui-content-card p-3.5 rounded-2xl">
            <div class="text-[11px] text-emerald-600 dark:text-emerald-400 font-bold uppercase">最小时延 (Min Δt)</div>
            <div class="text-base font-bold text-(--text-primary) ui-num font-mono-code mt-0.5 select-text">
              {{ minLatency.toFixed(2) }} ms
            </div>
          </div>
          <div class="ui-content-card p-3.5 rounded-2xl">
            <div class="text-[11px] text-purple-600 dark:text-purple-400 font-bold uppercase">最大时延 (Max Δt)</div>
            <div class="text-base font-bold ui-num font-mono-code mt-0.5 select-text" :class="maxLatency > 100 ? 'text-rose-600 dark:text-rose-400' : 'text-(--text-primary)'">
              {{ maxLatency.toFixed(2) }} ms
            </div>
          </div>
        </div>

        <!-- 列表工具栏 -->
        <div class="flex items-center justify-between text-xs pt-1">
          <div class="flex items-center gap-2">
            <span class="font-bold text-(--text-primary)">因果关联事件明细流水 (<span class="ui-num">{{ correlations.length }}</span>)</span>
            <span class="text-[11px] text-(--text-muted) font-mono-code">Δt = (t_serial - t_eth) / 10⁶ ms</span>
          </div>
          <div class="flex items-center gap-2">
            <button @click="fetchCorrelations" :disabled="isLoading"
              class="ui-btn-secondary inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold cursor-pointer disabled:opacity-40">
              <AppIcon name="refresh" class="w-3.5 h-3.5" :class="{ 'animate-spin': isLoading }" />
              <span>即时刷新</span>
            </button>
          </div>
        </div>

        <!-- 因果事件对表格 -->
        <div class="ui-content-card rounded-2xl overflow-hidden">
          <table class="w-full text-left text-xs border-collapse table-fixed">
            <thead class="ui-table-head text-[11px] uppercase font-bold">
              <tr>
                <th class="p-2.5 w-[20%]">关联 ID</th>
                <th class="p-2.5 w-[14%]">以太网帧 #ID</th>
                <th class="p-2.5 w-[14%]">串口帧 #ID</th>
                <th class="p-2.5 w-[18%]">规约/从机/功能码</th>
                <th class="p-2.5 w-[18%]">网关转换时延 (Δt)</th>
                <th class="p-2.5 w-[16%] text-center">状态评估</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-(--border-subtle) text-xs">
              <tr v-for="item in correlations.slice().reverse()" :key="item.correlation_id" class="hover:bg-sky-500/5 transition-colors">
                <td class="p-2.5 font-semibold text-(--text-primary) ui-num font-mono-code truncate select-text" :title="item.correlation_id">
                  {{ item.correlation_id }}
                </td>
                <td class="p-2.5 text-sky-600 dark:text-sky-400 font-bold ui-num font-mono-code select-text">
                  以太网 #{{ item.eth_packet_id }}
                </td>
                <td class="p-2.5 text-indigo-600 dark:text-indigo-400 font-bold ui-num font-mono-code select-text">
                  串口 #{{ item.serial_packet_id }}
                </td>
                <td class="p-2.5 text-(--text-secondary) select-text">
                  <span class="font-semibold text-(--text-primary)">{{ item.protocol }}</span>
                  <span class="text-(--text-muted) text-[11px] font-mono-code ui-num block">从机: {{ item.slave_addr }} | 功能: 0x{{ item.function_code.toString(16).padStart(2, '0').toUpperCase() }}</span>
                </td>
                <td class="p-2.5 font-bold ui-num font-mono-code select-text" :class="getLatencyClass(item.latency_ms)">
                  {{ item.latency_ms.toFixed(3) }} ms
                </td>
                <td class="p-2.5 text-center">
                  <span :class="['px-2 py-0.5 rounded text-[11px] font-bold border', getStatusBadge(item.latency_ms)]">
                    {{ item.latency_ms < 20 ? '优异' : item.latency_ms < 100 ? '正常' : '高抖动' }}
                  </span>
                </td>
              </tr>
              <tr v-if="correlations.length === 0">
                <td colspan="6" class="p-4">
                  <EmptyState
                    icon="zap"
                    title="暂未检测到跨总线因果关联对"
                    description="当以太网接收 Modbus-TCP 且串口捕获到对应的 Modbus-RTU 转换帧时，将在此自动关联。"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 全总线纳秒级时钟对齐与级联故障根因诊断 (接入 cross_bus_diagnostic.rs) -->
        <div class="ui-sub-card border-indigo-500/30 rounded-2xl p-4 space-y-3">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="text-xs font-bold text-(--text-primary)">纳秒级全总线级联故障根因诊断 (Ethernet ⇄ Serial / USB)</div>
            <div class="flex flex-wrap items-center gap-3 text-[11px] font-mono-code ui-num text-(--text-secondary)">
              <span>追踪事务: <b class="text-indigo-600 dark:text-indigo-400">{{ cascadeMetrics.total_cascades_tracked }}</b></span>
              <span>网关瓶颈: <b class="text-amber-600 dark:text-amber-400">{{ cascadeMetrics.gateway_bottleneck_count }}</b></span>
              <span>从站超时: <b class="text-rose-600 dark:text-rose-400">{{ cascadeMetrics.slave_timeout_count }}</b></span>
              <span>物理CRC错: <b class="text-rose-600 dark:text-rose-400">{{ cascadeMetrics.crc_mismatch_error_count }}</b></span>
              <span>网关均耗时: <b class="text-(--text-primary)">{{ cascadeMetrics.avg_gateway_latency_ms.toFixed(2) }} ms</b></span>
            </div>
          </div>
          <div v-if="cascadeRecords.length === 0" class="text-xs text-(--text-muted) font-mono-code">
            当前跨总线级联故障诊断队列为空（正常通信转发时延或待采集级联样本）。
          </div>
          <div v-else class="space-y-1.5 max-h-40 overflow-y-auto custom-scrollbar text-xs font-mono-code">
            <div v-for="rec in cascadeRecords" :key="rec.transaction_id"
              class="ui-content-card p-2.5 rounded-xl flex items-center justify-between gap-2">
              <div class="truncate select-text">
                <span class="font-bold text-indigo-600 dark:text-indigo-400">[{{ rec.source_bus }} -> {{ rec.target_bus }}]</span>
                <span class="ml-1.5 text-(--text-primary) font-semibold">{{ rec.protocol }}</span>
                <span class="ml-2 text-(--text-secondary)">{{ rec.diagnosis_summary }}</span>
              </div>
              <span class="ui-pill px-2 py-0.5 text-(--text-primary) shrink-0 text-[11px] font-bold ui-num">
                {{ rec.fault_type }} ({{ rec.total_roundtrip_latency_ms?.toFixed(2) ?? '--' }} ms)
              </span>
            </div>
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
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';

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

export interface CascadeMetricsSnapshot {
  total_cascades_tracked: number;
  normal_forward_count: number;
  gateway_bottleneck_count: number;
  slave_timeout_count: number;
  crc_mismatch_error_count: number;
  avg_gateway_latency_ms: number;
}

export interface CascadeDiagnosticRecord {
  transaction_id: string;
  source_bus: string;
  target_bus: string;
  protocol: string;
  request_packet_id: number;
  response_packet_id?: number | null;
  gateway_forward_latency_ms?: number | null;
  total_roundtrip_latency_ms?: number | null;
  fault_type: string;
  diagnosis_summary: string;
  remedy_suggestion: string;
}

const correlations = ref<CrossBusCorrelationRecord[]>([]);
const cascadeMetrics = ref<CascadeMetricsSnapshot>({
  total_cascades_tracked: 0,
  normal_forward_count: 0,
  gateway_bottleneck_count: 0,
  slave_timeout_count: 0,
  crc_mismatch_error_count: 0,
  avg_gateway_latency_ms: 0,
});
const cascadeRecords = ref<CascadeDiagnosticRecord[]>([]);
const isLoading = ref(false);

let pollTimer: ReturnType<typeof setInterval> | null = null;

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
  if (lat < 20) return 'text-emerald-600 dark:text-emerald-400';
  if (lat < 100) return 'text-amber-600 dark:text-amber-400';
  return 'text-rose-600 dark:text-rose-400';
}

function getStatusBadge(lat: number): string {
  if (lat < 20) return 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30';
  if (lat < 100) return 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/30';
  return 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/30';
}

async function fetchCorrelations() {
  if (isLoading.value) return;
  isLoading.value = true;
  try {
    const [list, metrics, diagnostics] = await Promise.all([
      invoke<CrossBusCorrelationRecord[]>('get_cross_bus_correlations_cmd'),
      invoke<CascadeMetricsSnapshot>('get_cascade_metrics_cmd'),
      invoke<CascadeDiagnosticRecord[]>('get_recent_cascade_diagnostics_cmd', { limit: 30 }),
    ]);
    correlations.value = list;
    cascadeMetrics.value = metrics;
    cascadeRecords.value = diagnostics;
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
