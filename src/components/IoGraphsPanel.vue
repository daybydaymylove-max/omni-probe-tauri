<template>
  <div class="flex-1 flex flex-col gap-2.5 h-full overflow-hidden min-h-0">
    <!-- 顶部控制与统计指标卡 (实体工作区面板) -->
    <div class="ui-content-card p-3 flex flex-col gap-2.5 shrink-0">
      <div class="flex items-center justify-between flex-wrap gap-2">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="w-2.5 h-2.5 rounded-full bg-sky-500"></span>
          <h3 class="text-xs font-bold" style="color: var(--text-primary)">IO Graphs 高精时序曲线与吞吐聚合引擎</h3>
          <span class="text-[11px] ui-num" style="color: var(--text-muted)">(秒级高精聚合包率 PPS、带宽吞吐、TCP RTT 时延与重传)</span>
        </div>

        <div class="flex items-center gap-2 text-xs flex-wrap">
          <div class="flex ui-pill p-0.5 rounded-xl text-xs font-semibold">
            <button @click="activeMetric = 'pps'"
              :class="['px-2.5 py-1 rounded-lg transition-colors cursor-pointer',
                activeMetric === 'pps' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="activeMetric !== 'pps' ? { color: 'var(--text-secondary)' } : undefined">
              包率 (PPS)
            </button>
            <button @click="activeMetric = 'bandwidth'"
              :class="['px-2.5 py-1 rounded-lg transition-colors cursor-pointer',
                activeMetric === 'bandwidth' ? 'bg-emerald-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="activeMetric !== 'bandwidth' ? { color: 'var(--text-secondary)' } : undefined">
              带宽 (KB/s)
            </button>
            <button @click="activeMetric = 'rtt'"
              :class="['px-2.5 py-1 rounded-lg transition-colors cursor-pointer',
                activeMetric === 'rtt' ? 'bg-indigo-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="activeMetric !== 'rtt' ? { color: 'var(--text-secondary)' } : undefined">
              TCP RTT (ms)
            </button>
            <button @click="activeMetric = 'retrans'"
              :class="['px-2.5 py-1 rounded-lg transition-colors cursor-pointer',
                activeMetric === 'retrans' ? 'bg-rose-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="activeMetric !== 'retrans' ? { color: 'var(--text-secondary)' } : undefined">
              重传异常
            </button>
          </div>

          <select v-model.number="selectedWindow" @change="fetchData"
            class="ui-input ui-num w-auto px-2.5 py-1 text-xs cursor-pointer">
            <option :value="30">近 30 秒</option>
            <option :value="60">近 60 秒</option>
            <option :value="120">近 120 秒</option>
            <option :value="300">近 300 秒</option>
          </select>

          <button @click="toggleAutoRefresh"
            :class="['px-2.5 py-1 rounded-xl text-xs font-semibold border transition-colors cursor-pointer flex items-center gap-1.5',
              isAutoRefreshing ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/35' : 'ui-pill']">
            <span class="w-1.5 h-1.5 rounded-full" :class="isAutoRefreshing ? 'bg-sky-500' : 'bg-slate-400'"></span>
            <span>{{ isAutoRefreshing ? '自动刷新 (1s)' : '自动刷新: 关' }}</span>
          </button>

          <button @click="fetchData" :disabled="isLoading" class="ui-btn-secondary px-2.5 py-1 rounded-xl text-xs">
            <AppIcon name="refresh" :size="12" :class="isLoading ? 'animate-spin' : ''" />
            <span>刷新</span>
          </button>
        </div>
      </div>

      <div v-if="seriesData" class="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
        <div class="ui-sub-card bg-blue-500/8 border-blue-500/25 p-2.5">
          <div class="text-[11px] text-blue-700 dark:text-sky-300 font-bold uppercase">窗口吞吐 / 报文总数</div>
          <div class="text-sm font-bold ui-num mt-0.5" style="color: var(--text-primary)">
            {{ formatBytes(seriesData.total_bytes) }} / {{ seriesData.total_packets }} 帧
          </div>
        </div>
        <div class="ui-sub-card bg-emerald-500/8 border-emerald-500/25 p-2.5">
          <div class="text-[11px] text-emerald-700 dark:text-emerald-300 font-bold uppercase">包率 (PPS: 均值 / 峰值)</div>
          <div class="text-sm font-bold ui-num mt-0.5" style="color: var(--text-primary)">
            {{ seriesData.avg_pps.toFixed(1) }} / <span class="text-emerald-700 dark:text-emerald-400">{{ seriesData.max_pps }} pps</span>
          </div>
        </div>
        <div class="ui-sub-card bg-indigo-500/8 border-indigo-500/25 p-2.5">
          <div class="text-[11px] text-indigo-700 dark:text-indigo-300 font-bold uppercase">带宽 (均值 / 峰值)</div>
          <div class="text-sm font-bold ui-num mt-0.5" style="color: var(--text-primary)">
            {{ formatBytes(seriesData.avg_bps) }}/s / <span class="text-indigo-700 dark:text-indigo-400">{{ formatBytes(seriesData.max_bps) }}/s</span>
          </div>
        </div>
        <div class="ui-sub-card bg-purple-500/8 border-purple-500/25 p-2.5">
          <div class="text-[11px] text-purple-700 dark:text-purple-300 font-bold uppercase">TCP RTT 时延 (均值 / 峰值)</div>
          <div class="text-sm font-bold ui-num mt-0.5" style="color: var(--text-primary)">
            {{ seriesData.avg_rtt_ms.toFixed(2) }}ms / <span :class="seriesData.max_rtt_ms > 100 ? 'text-rose-700 dark:text-rose-400 font-bold' : 'text-purple-700 dark:text-purple-300'">{{ seriesData.max_rtt_ms.toFixed(2) }}ms</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 矢量时序曲线图表与点阵区域 (高对比实体工作区卡片) -->
    <div class="flex-1 ui-content-card p-3.5 flex flex-col min-h-0 relative">
      <div class="flex items-center justify-between text-xs ui-num mb-2 shrink-0 flex-wrap gap-2" style="color: var(--text-secondary)">
        <div class="flex items-center gap-2">
          <span class="text-sky-700 dark:text-sky-400 font-bold">当前曲线: {{ metricTitle }}</span>
          <span style="color: var(--border-strong)">|</span>
          <span>时间跨度: {{ selectedWindow }} 秒</span>
          <span style="color: var(--border-strong)">|</span>
          <span>采样点: {{ validBuckets.length }} 点</span>
        </div>
        <div v-if="hoveredPoint" class="text-emerald-700 dark:text-emerald-300 ui-sub-card px-2.5 py-0.5 text-[11px]">
          时间: {{ hoveredPoint.time_str }} | 数值: <strong>{{ formatHoverValue(hoveredPoint) }}</strong> | 重传: {{ hoveredPoint.retrans_count }}
        </div>
      </div>

      <!-- SVG 曲线图绘制容器 -->
      <div class="flex-1 relative overflow-hidden min-h-[160px]" ref="svgContainerRef">
        <svg v-if="validBuckets.length > 1" class="w-full h-full" :viewBox="`0 0 ${svgWidth} ${svgHeight}`" preserveAspectRatio="none">
          <defs>
            <linearGradient id="metricGrad" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" :stop-color="metricColor" stop-opacity="0.35" />
              <stop offset="100%" :stop-color="metricColor" stop-opacity="0.02" />
            </linearGradient>
          </defs>

          <g :stroke="isDarkTheme ? '#1e293b' : '#cbd5e1'" stroke-width="1" stroke-dasharray="3,3">
            <line v-for="i in 4" :key="i"
              :x1="paddingLeft" :y1="paddingTop + (graphHeight / 4) * (i - 1)"
              :x2="svgWidth - paddingRight" :y2="paddingTop + (graphHeight / 4) * (i - 1)" />
          </g>

          <g class="text-[11px] font-mono select-none" :fill="isDarkTheme ? '#94a3b8' : '#475569'" text-anchor="end">
            <text :x="paddingLeft - 6" :y="paddingTop + 10">{{ formatYAxisLabel(maxYVal) }}</text>
            <text :x="paddingLeft - 6" :y="paddingTop + (graphHeight / 2) + 4">{{ formatYAxisLabel(maxYVal / 2) }}</text>
            <text :x="paddingLeft - 6" :y="paddingTop + graphHeight">{{ formatYAxisLabel(0) }}</text>
          </g>

          <path :d="areaPathD" fill="url(#metricGrad)" />
          <path :d="linePathD" fill="none" :stroke="metricColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />

          <g v-for="(pt, idx) in pointCoords" :key="idx">
            <circle
              :cx="pt.x" :cy="pt.y" r="3"
              :fill="metricColor"
              class="transition-all hover:r-5 cursor-pointer"
              @mouseenter="hoveredPoint = validBuckets[idx]"
              @mouseleave="hoveredPoint = null"
            />
            <circle v-if="validBuckets[idx].retrans_count > 0"
              :cx="pt.x" :cy="pt.y - 6" r="4" fill="#f43f5e" stroke="#ffe4e6" stroke-width="1.5">
              <title>TCP 重传异常: {{ validBuckets[idx].retrans_count }} 次</title>
            </circle>
          </g>

          <g class="text-[11px] font-mono select-none" :fill="isDarkTheme ? '#94a3b8' : '#475569'" text-anchor="middle">
            <text v-if="pointCoords.length > 0" :x="pointCoords[0].x" :y="svgHeight - 4">
              {{ validBuckets[0]?.time_str }}
            </text>
            <text v-if="pointCoords.length > 2" :x="pointCoords[Math.floor(pointCoords.length / 2)].x" :y="svgHeight - 4">
              {{ validBuckets[Math.floor(validBuckets.length / 2)]?.time_str }}
            </text>
            <text v-if="pointCoords.length > 1" :x="pointCoords[pointCoords.length - 1].x" :y="svgHeight - 4">
              {{ validBuckets[validBuckets.length - 1]?.time_str }}
            </text>
          </g>
        </svg>

        <EmptyState
          v-else
          class="h-full py-6"
          icon="activity"
          title="正在捕获并聚合时序采样点"
          description="请等待数据包流入并生成 2 个以上连续时间桶，或点击上方【刷新】按钮。"
        />
      </div>

      <!-- 底部时序点阵数据明细折叠表 -->
      <div class="mt-2 border-t pt-2 shrink-0" style="border-color: var(--border-subtle)">
        <div class="flex items-center justify-between text-[11px] mb-1.5" style="color: var(--text-secondary)">
          <span class="font-bold">秒级时序点阵明细流水 (最近 {{ validBuckets.length }} 秒桶)</span>
          <button @click="showTable = !showTable" class="font-semibold hover:underline cursor-pointer flex items-center gap-1" style="color: var(--accent-primary-text)">
            <span>{{ showTable ? '收起明细' : '展开点阵明细' }}</span>
            <AppIcon :name="showTable ? 'chevron-up' : 'chevron-down'" :size="12" />
          </button>
        </div>

        <div v-if="showTable" class="max-h-36 overflow-auto custom-scrollbar ui-sub-card p-0 select-text">
          <table class="w-full text-left text-[11px] ui-num border-collapse table-fixed">
            <thead class="ui-table-head sticky top-0">
              <tr>
                <th class="p-1.5 w-[20%]">时间点</th>
                <th class="p-1.5 w-[20%] text-right">包数量 (PPS)</th>
                <th class="p-1.5 w-[20%] text-right">吞吐量 (BPS)</th>
                <th class="p-1.5 w-[20%] text-right">TCP RTT (ms)</th>
                <th class="p-1.5 w-[20%] text-right">重传计数</th>
              </tr>
            </thead>
            <tbody class="divide-y" style="border-color: var(--border-subtle); color: var(--text-secondary)">
              <tr v-for="b in validBuckets.slice().reverse()" :key="b.timestamp_sec" class="hover:bg-black/5 dark:hover:bg-white/5">
                <td class="p-1.5 truncate">{{ b.time_str }}</td>
                <td class="p-1.5 text-right font-bold text-blue-700 dark:text-sky-400">{{ b.packet_count }}</td>
                <td class="p-1.5 text-right text-emerald-700 dark:text-emerald-400">{{ formatBytes(b.byte_count) }}</td>
                <td class="p-1.5 text-right" :class="b.avg_rtt_ms > 50 ? 'text-amber-700 dark:text-amber-400 font-bold' : ''">
                  {{ b.avg_rtt_ms.toFixed(2) }}
                </td>
                <td class="p-1.5 text-right" :class="b.retrans_count > 0 ? 'text-rose-700 dark:text-rose-400 font-bold' : ''" :style="b.retrans_count === 0 ? { color: 'var(--text-muted)' } : undefined">
                  {{ b.retrans_count }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';

const isDarkTheme = ref(!document.documentElement.classList.contains('theme-apple-light'));
let themeObserver: MutationObserver | null = null;

export interface IoGraphPoint {
  timestamp_sec: number;
  time_str: string;
  packet_count: number;
  byte_count: number;
  avg_rtt_ms: number;
  retrans_count: number;
}

export interface IoGraphSeries {
  buckets: IoGraphPoint[];
  total_packets: number;
  total_bytes: number;
  avg_pps: number;
  max_pps: number;
  avg_bps: number;
  max_bps: number;
  avg_rtt_ms: number;
  max_rtt_ms: number;
}

const selectedWindow = ref(60);
const activeMetric = ref<'pps' | 'bandwidth' | 'rtt' | 'retrans'>('pps');
const isAutoRefreshing = ref(true);
const isLoading = ref(false);
const showTable = ref(false);
const seriesData = ref<IoGraphSeries | null>(null);
const hoveredPoint = ref<IoGraphPoint | null>(null);

let refreshTimer: any = null;

// SVG 布局尺寸
const svgWidth = 800;
const svgHeight = 220;
const paddingLeft = 55;
const paddingRight = 20;
const paddingTop = 15;
const paddingBottom = 25;

const graphWidth = computed(() => svgWidth - paddingLeft - paddingRight);
const graphHeight = computed(() => svgHeight - paddingTop - paddingBottom);

const validBuckets = computed(() => seriesData.value?.buckets || []);

const metricTitle = computed(() => {
  switch (activeMetric.value) {
    case 'pps': return '报文包率 (Packets / Second)';
    case 'bandwidth': return '吞吐带宽 (KB/s)';
    case 'rtt': return 'TCP 往返时延 RTT (ms)';
    case 'retrans': return 'TCP 重传异常计数 (Retransmissions)';
  }
});

const metricColor = computed(() => {
  switch (activeMetric.value) {
    case 'pps': return '#3b82f6'; // blue-500
    case 'bandwidth': return '#10b981'; // emerald-500
    case 'rtt': return '#6366f1'; // indigo-500
    case 'retrans': return '#f43f5e'; // rose-500
  }
});

// 计算当前指标在有效数据中的最大值 (用于 Y 轴归一化)
const maxYVal = computed(() => {
  if (validBuckets.value.length === 0) return 10;
  let max = 1;
  for (const b of validBuckets.value) {
    let val = 0;
    if (activeMetric.value === 'pps') val = b.packet_count;
    else if (activeMetric.value === 'bandwidth') val = b.byte_count / 1024.0;
    else if (activeMetric.value === 'rtt') val = b.avg_rtt_ms;
    else if (activeMetric.value === 'retrans') val = b.retrans_count;
    if (val > max) max = val;
  }
  return Math.ceil(max * 1.15); // 留出 15% 顶部余量
});

// 计算所有点的 SVG 像素坐标
const pointCoords = computed(() => {
  const buckets = validBuckets.value;
  if (buckets.length === 0) return [];
  const max = maxYVal.value;
  const count = buckets.length;
  const stepX = count > 1 ? graphWidth.value / (count - 1) : graphWidth.value / 2;

  return buckets.map((b, idx) => {
    let val = 0;
    if (activeMetric.value === 'pps') val = b.packet_count;
    else if (activeMetric.value === 'bandwidth') val = b.byte_count / 1024.0;
    else if (activeMetric.value === 'rtt') val = b.avg_rtt_ms;
    else if (activeMetric.value === 'retrans') val = b.retrans_count;

    const x = paddingLeft + idx * stepX;
    const norm = max > 0 ? Math.min(1.0, val / max) : 0;
    const y = paddingTop + graphHeight.value - (norm * graphHeight.value);
    return { x, y };
  });
});

// 生成 SVG 折线路径
const linePathD = computed(() => {
  const coords = pointCoords.value;
  if (coords.length < 2) return '';
  return coords.reduce((acc, pt, idx) => {
    return idx === 0 ? `M ${pt.x},${pt.y}` : `${acc} L ${pt.x},${pt.y}`;
  }, '');
});

// 生成 SVG 渐变填充闭合路径
const areaPathD = computed(() => {
  const coords = pointCoords.value;
  if (coords.length < 2) return '';
  const first = coords[0];
  const last = coords[coords.length - 1];
  const bottomY = paddingTop + graphHeight.value;
  return `${linePathD.value} L ${last.x},${bottomY} L ${first.x},${bottomY} Z`;
});

function formatHoverValue(pt: IoGraphPoint): string {
  switch (activeMetric.value) {
    case 'pps': return `${pt.packet_count} pps`;
    case 'bandwidth': return `${(pt.byte_count / 1024.0).toFixed(2)} KB/s`;
    case 'rtt': return `${pt.avg_rtt_ms.toFixed(2)} ms`;
    case 'retrans': return `${pt.retrans_count} 次`;
  }
}

function formatYAxisLabel(val: number): string {
  if (activeMetric.value === 'bandwidth') {
    return `${val.toFixed(1)}K`;
  } else if (activeMetric.value === 'rtt') {
    return `${val.toFixed(1)}ms`;
  }
  return `${Math.round(val)}`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

async function fetchData() {
  if (isLoading.value) return;
  isLoading.value = true;
  try {
    const res = await invoke<IoGraphSeries>('get_io_graph_series_cmd', {
      windowSeconds: selectedWindow.value,
    });
    seriesData.value = res;
  } catch (e) {
    console.error('获取 IO Graph 数据失败:', e);
  } finally {
    isLoading.value = false;
  }
}

function toggleAutoRefresh() {
  isAutoRefreshing.value = !isAutoRefreshing.value;
  if (isAutoRefreshing.value) {
    startAutoRefresh();
  } else {
    stopAutoRefresh();
  }
}

function startAutoRefresh() {
  stopAutoRefresh();
  refreshTimer = setInterval(() => {
    fetchData();
  }, 1000);
}

function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

onMounted(() => {
  themeObserver = new MutationObserver(() => {
    isDarkTheme.value = !document.documentElement.classList.contains('theme-apple-light');
  });
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

  fetchData();
  if (isAutoRefreshing.value) {
    startAutoRefresh();
  }
});

onUnmounted(() => {
  if (themeObserver) {
    themeObserver.disconnect();
    themeObserver = null;
  }
  stopAutoRefresh();
});
</script>
