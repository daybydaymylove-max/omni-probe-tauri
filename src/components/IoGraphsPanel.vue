<template>
  <div class="flex-1 flex flex-col gap-2.5 h-full overflow-hidden min-h-0">
    <!-- 顶部控制与统计指标卡 -->
    <div class="bg-white/80 backdrop-blur-md rounded-2xl border border-slate-200/80 p-3 shadow-sm flex flex-col gap-2.5 shrink-0">
      <div class="flex items-center justify-between flex-wrap gap-2">
        <div class="flex items-center gap-2.5">
          <span class="w-2.5 h-2.5 rounded-full bg-blue-600 animate-pulse"></span>
          <h3 class="text-xs font-bold text-slate-800">IO Graphs 高精纳秒时序曲线与吞吐聚合引擎</h3>
          <span class="text-[10px] text-slate-400 font-mono">（秒级高精聚合包率 PPS、带宽吞吐、TCP RTT 时延与重传异常）</span>
        </div>

        <!-- 操作区：观测维度、窗口大小、自动刷新 -->
        <div class="flex items-center gap-2 text-xs">
          <!-- 观测维度分段控件 -->
          <div class="flex bg-slate-100 p-0.5 rounded-xl text-xs font-semibold border border-slate-200">
            <button @click="activeMetric = 'pps'"
              :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer',
                activeMetric === 'pps' ? 'bg-white text-blue-700 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900']">
              包率 (PPS)
            </button>
            <button @click="activeMetric = 'bandwidth'"
              :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer',
                activeMetric === 'bandwidth' ? 'bg-white text-emerald-700 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900']">
              带宽 (KB/s)
            </button>
            <button @click="activeMetric = 'rtt'"
              :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer',
                activeMetric === 'rtt' ? 'bg-white text-indigo-700 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900']">
              TCP RTT (ms)
            </button>
            <button @click="activeMetric = 'retrans'"
              :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer',
                activeMetric === 'retrans' ? 'bg-white text-rose-700 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900']">
              重传异常
            </button>
          </div>

          <!-- 时间窗口选择 -->
          <select v-model.number="selectedWindow" @change="fetchData"
            class="bg-white border border-slate-200 rounded-xl px-2 py-1 text-xs font-mono text-slate-700 focus:outline-none shadow-2xs">
            <option :value="30">近 30 秒</option>
            <option :value="60">近 60 秒</option>
            <option :value="120">近 120 秒</option>
            <option :value="300">近 300 秒</option>
          </select>

          <!-- 自动刷新 Toggle -->
          <button @click="toggleAutoRefresh"
            :class="['px-2.5 py-1 rounded-xl text-xs font-semibold border transition-all cursor-pointer flex items-center gap-1 shadow-2xs active:scale-95',
              isAutoRefreshing ? 'bg-blue-50 text-blue-700 border-blue-200' : 'bg-white text-slate-600 border-slate-200']">
            <span class="w-1.5 h-1.5 rounded-full" :class="isAutoRefreshing ? 'bg-blue-600 animate-pulse' : 'bg-slate-300'"></span>
            <span>{{ isAutoRefreshing ? '自动刷新 (1s)' : '自动刷新: 关' }}</span>
          </button>

          <!-- 手动刷新 -->
          <button @click="fetchData" :disabled="isLoading"
            class="bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 px-2.5 py-1 rounded-xl text-xs font-semibold transition-all cursor-pointer shadow-2xs active:scale-95 disabled:opacity-40">
            <span v-if="isLoading">⏳</span>
            <span v-else>⟳</span>
            <span>刷新</span>
          </button>
        </div>
      </div>

      <!-- 聚合统计指标卡 -->
      <div v-if="seriesData" class="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
        <div class="bg-blue-50/70 border border-blue-100 p-2 rounded-xl">
          <div class="text-[10px] text-blue-600 font-bold uppercase">窗口吞吐 / 报文总数</div>
          <div class="text-sm font-bold text-blue-950 font-mono">
            {{ formatBytes(seriesData.total_bytes) }} / {{ seriesData.total_packets }} 帧
          </div>
        </div>
        <div class="bg-emerald-50/70 border border-emerald-100 p-2 rounded-xl">
          <div class="text-[10px] text-emerald-600 font-bold uppercase">包率 (PPS: 均值 / 峰值)</div>
          <div class="text-sm font-bold text-emerald-950 font-mono">
            {{ seriesData.avg_pps.toFixed(1) }} / <span class="text-emerald-700">{{ seriesData.max_pps }} pps</span>
          </div>
        </div>
        <div class="bg-indigo-50/70 border border-indigo-100 p-2 rounded-xl">
          <div class="text-[10px] text-indigo-600 font-bold uppercase">带宽 (均值 / 峰值)</div>
          <div class="text-sm font-bold text-indigo-950 font-mono">
            {{ formatBytes(seriesData.avg_bps) }}/s / <span class="text-indigo-700">{{ formatBytes(seriesData.max_bps) }}/s</span>
          </div>
        </div>
        <div class="bg-purple-50/70 border border-purple-100 p-2 rounded-xl">
          <div class="text-[10px] text-purple-600 font-bold uppercase">TCP RTT 时延 (均值 / 峰值)</div>
          <div class="text-sm font-bold text-purple-950 font-mono">
            {{ seriesData.avg_rtt_ms.toFixed(2) }}ms / <span :class="seriesData.max_rtt_ms > 100 ? 'text-rose-600 font-bold' : 'text-purple-700'">{{ seriesData.max_rtt_ms.toFixed(2) }}ms</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 矢量时序曲线图表与点阵区域 (Apple Pro Tools 深空终端) -->
    <div class="flex-1 bg-slate-900/90 backdrop-blur-xl rounded-2xl border border-white/10 p-3 shadow-inner flex flex-col min-h-0 relative">
      <!-- 曲线图表头部状态 -->
      <div class="flex items-center justify-between text-slate-400 text-xs font-mono mb-2 shrink-0">
        <div class="flex items-center gap-2">
          <span class="text-sky-400 font-bold">● 当前曲线: {{ metricTitle }}</span>
          <span class="text-slate-500">|</span>
          <span>时间跨度: {{ selectedWindow }} 秒</span>
          <span class="text-slate-500">|</span>
          <span>采样点: {{ validBuckets.length }} 点</span>
        </div>
        <div v-if="hoveredPoint" class="text-emerald-400 bg-slate-800/80 px-2 py-0.5 rounded-lg border border-slate-700 shadow-2xs">
          时间: {{ hoveredPoint.time_str }} | 数值: <strong>{{ formatHoverValue(hoveredPoint) }}</strong> | 重传: {{ hoveredPoint.retrans_count }}
        </div>
      </div>

      <!-- SVG 曲线图绘制容器 -->
      <div class="flex-1 relative overflow-hidden min-h-[160px]" ref="svgContainerRef">
        <svg v-if="validBuckets.length > 1" class="w-full h-full" :viewBox="`0 0 ${svgWidth} ${svgHeight}`" preserveAspectRatio="none">
          <defs>
            <!-- 渐变填充 -->
            <linearGradient id="metricGrad" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" :stop-color="metricColor" stop-opacity="0.45" />
              <stop offset="100%" :stop-color="metricColor" stop-opacity="0.02" />
            </linearGradient>
          </defs>

          <!-- 背景水平参考刻度线 (4 等分) -->
          <g class="stroke-slate-800" stroke-width="1" stroke-dasharray="3,3">
            <line v-for="i in 4" :key="i"
              :x1="paddingLeft" :y1="paddingTop + (graphHeight / 4) * (i - 1)"
              :x2="svgWidth - paddingRight" :y2="paddingTop + (graphHeight / 4) * (i - 1)" />
          </g>

          <!-- Y 轴刻度文字 -->
          <g class="text-[9px] fill-slate-500 font-mono select-none" text-anchor="end">
            <text :x="paddingLeft - 6" :y="paddingTop + 10">{{ formatYAxisLabel(maxYVal) }}</text>
            <text :x="paddingLeft - 6" :y="paddingTop + (graphHeight / 2) + 4">{{ formatYAxisLabel(maxYVal / 2) }}</text>
            <text :x="paddingLeft - 6" :y="paddingTop + graphHeight">{{ formatYAxisLabel(0) }}</text>
          </g>

          <!-- 填充区域 -->
          <path :d="areaPathD" fill="url(#metricGrad)" />

          <!-- 折线曲线 -->
          <path :d="linePathD" fill="none" :stroke="metricColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />

          <!-- 数据点与重传异常标定 -->
          <g v-for="(pt, idx) in pointCoords" :key="idx">
            <!-- 正常采样点 -->
            <circle
              :cx="pt.x" :cy="pt.y" r="3"
              :fill="metricColor"
              class="transition-all hover:r-5 cursor-pointer"
              @mouseenter="hoveredPoint = validBuckets[idx]"
              @mouseleave="hoveredPoint = null"
            />
            <!-- 重传异常标记点 (红色高亮脉冲) -->
            <circle v-if="validBuckets[idx].retrans_count > 0"
              :cx="pt.x" :cy="pt.y - 6" r="4" fill="#f43f5e" stroke="#ffe4e6" stroke-width="1.5">
              <title>TCP 重传异常: {{ validBuckets[idx].retrans_count }} 次</title>
            </circle>
          </g>

          <!-- X 轴时间刻度标签 (按首、中、尾) -->
          <g class="text-[9px] fill-slate-500 font-mono select-none" text-anchor="middle">
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

        <!-- 无数据或单点占位 -->
        <div v-else class="flex flex-col items-center justify-center h-full text-slate-500 text-xs">
          <span class="text-sm mb-1">⏳ 正在捕获并聚合时序采样点...</span>
          <span class="text-[10px]">请等待数据包流入并生成 2 个以上连续时间桶（或点击上方【刷新】）</span>
        </div>
      </div>

      <!-- 底部时序点阵数据明细折叠表 -->
      <div class="mt-2 border-t border-slate-800 pt-2 shrink-0">
        <div class="flex items-center justify-between text-[11px] text-slate-400 mb-1">
          <span class="font-bold">秒级时序点阵明细流水 (最近 {{ validBuckets.length }} 秒桶)</span>
          <button @click="showTable = !showTable" class="text-blue-400 hover:text-blue-300 transition-colors cursor-pointer">
            {{ showTable ? '收起明细 ▲' : '展开点阵明细 ▼' }}
          </button>
        </div>

        <div v-if="showTable" class="max-h-36 overflow-auto custom-scrollbar bg-slate-950/60 rounded-xl border border-slate-800">
          <table class="w-full text-left text-[10px] font-mono border-collapse table-fixed">
            <thead class="bg-slate-900 text-slate-400 sticky top-0 border-b border-slate-800">
              <tr>
                <th class="p-1.5 w-[20%]">时间点</th>
                <th class="p-1.5 w-[20%] text-right">包数量 (PPS)</th>
                <th class="p-1.5 w-[20%] text-right">吞吐量 (BPS)</th>
                <th class="p-1.5 w-[20%] text-right">TCP RTT (ms)</th>
                <th class="p-1.5 w-[20%] text-right">重传计数</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-850 text-slate-300">
              <tr v-for="b in validBuckets.slice().reverse()" :key="b.timestamp_sec" class="hover:bg-slate-800/50">
                <td class="p-1.5 truncate">{{ b.time_str }}</td>
                <td class="p-1.5 text-right font-bold text-blue-400">{{ b.packet_count }}</td>
                <td class="p-1.5 text-right text-emerald-400">{{ formatBytes(b.byte_count) }}</td>
                <td class="p-1.5 text-right" :class="b.avg_rtt_ms > 50 ? 'text-amber-400 font-bold' : 'text-slate-300'">
                  {{ b.avg_rtt_ms.toFixed(2) }}
                </td>
                <td class="p-1.5 text-right" :class="b.retrans_count > 0 ? 'text-rose-400 font-bold' : 'text-slate-500'">
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
  fetchData();
  if (isAutoRefreshing.value) {
    startAutoRefresh();
  }
});

onUnmounted(() => {
  stopAutoRefresh();
});
</script>
