<template>
  <div class="h-full flex flex-col overflow-hidden bg-slate-950 text-slate-100 select-none relative font-sans">
    
    <!-- 顶栏：地图控制中心与图层开关 -->
    <div class="px-6 py-3.5 border-b border-white/10 bg-slate-900/80 backdrop-blur-xl flex flex-wrap items-center justify-between gap-4 shrink-0 z-20">
      <div class="flex items-center gap-3">
        <div class="w-9 h-9 rounded-2xl bg-gradient-to-tr from-cyan-500 via-blue-600 to-indigo-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/25">
          <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <div>
          <div class="flex items-center gap-2">
            <h2 class="text-sm font-bold text-white tracking-wide">
              全球网络态势与地理情报地图 (Global Geo-Intelligence Map)
            </h2>
            <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
              100% 物理脱机
            </span>
          </div>
          <div class="text-[11px] font-mono text-slate-400 mt-0.5 flex items-center gap-3">
            <span>空间网格聚类: {{ mapData?.clusters?.length || 0 }} 城市节点</span>
            <span>·</span>
            <span>测地通信大圆: {{ mapData?.traffic_arcs?.length || 0 }} 骨干链路</span>
            <span>·</span>
            <span>太阳赤纬: {{ mapData?.terminator?.solar_declination_deg || 0 }}°</span>
          </div>
        </div>
      </div>

      <!-- 中间：投影模式与图层控制组 -->
      <div class="flex items-center gap-2 flex-wrap">
        <!-- 投影切换 -->
        <div class="p-1 rounded-2xl bg-slate-800/80 border border-white/10 flex items-center gap-1 text-xs font-semibold">
          <button
            @click="projectionMode = '3d'"
            :class="[
              'px-3 py-1.5 rounded-xl transition-all flex items-center gap-1.5 cursor-pointer',
              projectionMode === '3d'
                ? 'bg-indigo-600 text-white shadow-sm font-bold'
                : 'text-slate-400 hover:text-white'
            ]"
          >
            <span>🌍 3D 数字地球</span>
          </button>
          <button
            @click="projectionMode = '2d'"
            :class="[
              'px-3 py-1.5 rounded-xl transition-all flex items-center gap-1.5 cursor-pointer',
              projectionMode === '2d'
                ? 'bg-indigo-600 text-white shadow-sm font-bold'
                : 'text-slate-400 hover:text-white'
            ]"
          >
            <span>🗺️ 2D 全景平面</span>
          </button>
        </div>

        <!-- 图层显隐按钮组 -->
        <div class="flex items-center gap-1 text-xs font-mono">
          <button
            @click="layers.terminator = !layers.terminator"
            :class="layers.terminator ? 'bg-amber-950/60 text-amber-300 border-amber-800/80' : 'bg-slate-800/60 text-slate-500 border-white/5'"
            class="px-2.5 py-1.5 rounded-xl border transition-colors cursor-pointer flex items-center gap-1"
            title="切换真实太阳晨昏昼夜阴影"
          >
            <span>☀️ 晨昏线</span>
          </button>
          <button
            @click="layers.cables = !layers.cables"
            :class="layers.cables ? 'bg-cyan-950/60 text-cyan-300 border-cyan-800/80' : 'bg-slate-800/60 text-slate-500 border-white/5'"
            class="px-2.5 py-1.5 rounded-xl border transition-colors cursor-pointer flex items-center gap-1"
            title="切换洲际海底光缆骨干路由"
          >
            <span>⚓ 海底光缆</span>
          </button>
          <button
            @click="layers.arcs = !layers.arcs"
            :class="layers.arcs ? 'bg-indigo-950/60 text-indigo-300 border-indigo-800/80' : 'bg-slate-800/60 text-slate-500 border-white/5'"
            class="px-2.5 py-1.5 rounded-xl border transition-colors cursor-pointer flex items-center gap-1"
            title="切换通信流量测地飞线"
          >
            <span>⚡ 通信飞线</span>
          </button>
          <button
            @click="layers.graticules = !layers.graticules"
            :class="layers.graticules ? 'bg-slate-800 text-slate-200 border-slate-700' : 'bg-slate-800/60 text-slate-500 border-white/5'"
            class="px-2.5 py-1.5 rounded-xl border transition-colors cursor-pointer flex items-center gap-1"
            title="切换经纬度网格 (30° 步长)"
          >
            <span>🌐 经纬网</span>
          </button>
        </div>

        <!-- 刷新与重置视口 -->
        <div class="flex items-center gap-1.5 ml-1">
          <button
            @click="resetViewport"
            class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-white/10 transition-colors cursor-pointer"
            title="重置缩放与视角中心"
          >
            视口复位
          </button>
          <button
            @click="loadMapData"
            :disabled="loading"
            class="w-8 h-8 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-white/10 flex items-center justify-center transition-colors cursor-pointer disabled:opacity-50"
            title="刷新全球态势数据"
          >
            <span :class="loading ? 'animate-spin' : ''">⟳</span>
          </button>
        </div>
      </div>
    </div>

    <!-- 地图核心画板与右侧情报看板 -->
    <div class="flex-1 flex overflow-hidden relative">
      
      <!-- 主地图 Canvas 视口 -->
      <div
        ref="mapContainerRef"
        class="flex-1 h-full relative cursor-grab active:cursor-grabbing overflow-hidden bg-radial from-slate-900 via-slate-950 to-black"
        @mousedown="handleMouseDown"
        @mousemove="handleMouseMove"
        @mouseup="handleMouseUp"
        @mouseleave="handleMouseUp"
        @wheel.passive="handleWheel"
      >
        <canvas ref="mapCanvasRef" class="w-full h-full block"></canvas>

        <!-- 左下角：实时投影状态与操作提示 -->
        <div class="absolute bottom-4 left-4 p-3 rounded-2xl bg-slate-900/80 backdrop-blur-md border border-white/10 text-[11px] font-mono text-slate-400 space-y-1 pointer-events-none">
          <div class="text-white font-bold flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>视图模式: {{ projectionMode === '3d' ? '三维正射投影 (Orthographic)' : '等角圆柱全景投影 (Equirectangular)' }}</span>
          </div>
          <div>视口中心: 纬度 {{ centerLat.toFixed(1) }}°, 经度 {{ centerLon.toFixed(1) }}° | 缩放倍率: {{ scale.toFixed(2) }}x</div>
          <div class="text-slate-500">提示: 鼠标拖拽平移/旋转，滚轮放大缩小，点击城市节点穿透详情</div>
        </div>

        <!-- 悬浮的节点 Tooltip -->
        <div
          v-if="hoveredNode"
          class="absolute z-30 pointer-events-none p-3 rounded-xl bg-slate-900/95 backdrop-blur-xl border border-cyan-500/50 shadow-2xl text-xs font-mono space-y-1"
          :style="{ left: tooltipPos.x + 15 + 'px', top: tooltipPos.y - 15 + 'px' }"
        >
          <div class="font-bold text-white flex items-center gap-1.5">
            <span class="w-2 h-2 rounded-full" :class="hoveredNode.is_local_origin ? 'bg-emerald-400' : 'bg-cyan-400'"></span>
            <span>{{ hoveredNode.city_name }} ({{ hoveredNode.country_name }})</span>
          </div>
          <div class="text-slate-300">经纬度: {{ hoveredNode.center_coord.lat }}°, {{ hoveredNode.center_coord.lon }}°</div>
          <div class="text-slate-400">活跃主机 IP 数: {{ hoveredNode.active_ip_count }}</div>
          <div class="text-emerald-400">总吞吐: {{ formatBytes(hoveredNode.total_inbound_bytes + hoveredNode.total_outbound_bytes) }}</div>
          <div v-if="hoveredNode.threat_score > 0" class="text-rose-400 font-bold">
            ⚠️ 威胁评分: {{ hoveredNode.threat_score }}
          </div>
        </div>
      </div>

      <!-- 右侧：全球网络情报与态势看板 (可折叠) -->
      <div
        :class="[
          'w-84 border-l border-white/10 bg-slate-900/90 backdrop-blur-2xl flex flex-col transition-all duration-300 z-10 shrink-0 custom-scrollbar overflow-y-auto',
          isSidebarCollapsed ? 'w-0 border-l-0 p-0 overflow-hidden' : 'p-4 space-y-5'
        ]"
      >
        <!-- 侧边栏折叠按钮 -->
        <div class="flex items-center justify-between border-b border-white/10 pb-3">
          <h3 class="text-xs font-bold text-white flex items-center gap-2">
            <span>📊 全球通信情报看板</span>
          </h3>
          <button
            @click="isSidebarCollapsed = !isSidebarCollapsed"
            class="text-xs text-slate-400 hover:text-white cursor-pointer"
          >
            收起
          </button>
        </div>

        <!-- 全球宏观概览卡片 -->
        <div class="grid grid-cols-2 gap-2 text-xs font-mono">
          <div class="p-3 rounded-xl bg-slate-800/50 border border-white/5">
            <div class="text-[10px] text-slate-400">全球总通信流量</div>
            <div class="text-sm font-bold text-white mt-1">
              {{ formatBytes(mapData?.global_total_bytes || 0) }}
            </div>
          </div>
          <div class="p-3 rounded-xl bg-slate-800/50 border border-white/5">
            <div class="text-[10px] text-slate-400">捕获报文总数</div>
            <div class="text-sm font-bold text-cyan-400 mt-1">
              {{ (mapData?.global_packet_count || 0).toLocaleString() }}
            </div>
          </div>
        </div>

        <!-- 选中节点详情穿透 -->
        <div v-if="selectedNode" class="p-4 rounded-2xl bg-indigo-950/40 border border-indigo-500/40 space-y-3">
          <div class="flex items-center justify-between">
            <div class="font-bold text-white text-xs flex items-center gap-1.5">
              <span>📍 选中空间节点: {{ selectedNode.city_name }}</span>
            </div>
            <button
              @click="selectedNode = null"
              class="text-slate-400 hover:text-white text-xs cursor-pointer"
            >
              ✕
            </button>
          </div>

          <div class="text-xs font-mono space-y-1.5 text-slate-300">
            <div>所属区域: {{ selectedNode.country_name }} ({{ selectedNode.country_code }})</div>
            <div>地理坐标: {{ selectedNode.center_coord.lat }}°, {{ selectedNode.center_coord.lon }}°</div>
            <div>入站吞吐: {{ formatBytes(selectedNode.total_inbound_bytes) }}</div>
            <div>出站吞吐: {{ formatBytes(selectedNode.total_outbound_bytes) }}</div>
            <div>关联 IP (采样):</div>
            <div class="flex flex-wrap gap-1 mt-1">
              <span
                v-for="ip in selectedNode.sample_ips"
                :key="ip"
                @click="openDossierForIp(ip)"
                class="px-2 py-0.5 rounded-md bg-slate-800 hover:bg-indigo-600 text-[10px] text-indigo-300 hover:text-white transition-colors cursor-pointer border border-white/10"
                title="点击穿透查看该 IP 档案"
              >
                {{ ip }} ↗
              </span>
            </div>
          </div>
        </div>

        <!-- 全球洲际骨干海缆路由表 -->
        <div class="space-y-2">
          <div class="text-xs font-bold text-slate-300 flex items-center justify-between">
            <span>⚓ 洲际骨干海底光缆路由</span>
            <span class="text-[10px] text-cyan-400 font-mono">{{ mapData?.submarine_cables?.length || 0 }} 条骨干</span>
          </div>
          <div class="space-y-1.5">
            <div
              v-for="cable in mapData?.submarine_cables || []"
              :key="cable.cable_id"
              class="p-2.5 rounded-xl bg-slate-800/40 border border-white/5 hover:border-cyan-500/40 transition-colors text-xs font-mono"
            >
              <div class="font-bold text-cyan-300 truncate">{{ cable.name }}</div>
              <div class="text-[11px] text-slate-400 mt-1 flex justify-between">
                <span>总长度: {{ (cable.total_length_km / 1000).toFixed(1) }}k km</span>
                <span>设计容量: {{ cable.capacity_tbps }} Tbps</span>
              </div>
            </div>
          </div>
        </div>

        <!-- 国家/地区威胁与通信矩阵 -->
        <div class="space-y-2">
          <div class="text-xs font-bold text-slate-300 flex items-center justify-between">
            <span>🚨 跨境威胁分布矩阵 (ISO 3166)</span>
          </div>
          <div class="space-y-1 text-xs font-mono">
            <div
              v-for="(count, code) in mapData?.country_threat_matrix || {}"
              :key="code"
              class="flex items-center justify-between p-2 rounded-lg bg-red-950/20 border border-red-900/40"
            >
              <span class="font-bold text-red-300">{{ code }} 地区节点</span>
              <span class="text-red-400 font-bold">{{ count }} 起告警</span>
            </div>
            <div v-if="!mapData?.country_threat_matrix || Object.keys(mapData.country_threat_matrix).length === 0" class="text-slate-500 text-[11px]">
              未检测到跨境恶意渗透流量
            </div>
          </div>
        </div>

      </div>

    </div>

    <!-- 侧栏折叠时重新展开浮动按钮 -->
    <button
      v-if="isSidebarCollapsed"
      @click="isSidebarCollapsed = false"
      class="absolute top-20 right-4 z-20 px-3 py-1.5 rounded-xl bg-slate-900/90 border border-white/10 text-xs font-bold text-white shadow-xl hover:bg-slate-800 transition-colors cursor-pointer"
    >
      展开情报看板 ◀
    </button>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';

interface GeoCoord {
  lat: number;
  lon: number;
}

interface GeoMapClusterNode {
  cluster_id: string;
  center_coord: GeoCoord;
  city_name: string;
  country_code: string;
  country_name: string;
  total_inbound_bytes: number;
  total_outbound_bytes: number;
  packet_count: number;
  active_ip_count: number;
  sample_ips: string[];
  threat_score: number;
  is_local_origin: boolean;
}

interface GeoMapTrafficArc {
  flow_id: string;
  src_coord: GeoCoord;
  dst_coord: GeoCoord;
  src_city: string;
  dst_city: string;
  primary_protocol: string;
  total_bytes: number;
  packet_count: number;
  great_circle_distance_km: number;
  theoretical_fiber_rtt_ms: number;
  waypoints: GeoCoord[];
  is_threat_flow: boolean;
}

interface SolarTerminatorData {
  solar_declination_deg: number;
  subsolar_longitude_deg: number;
  terminator_points: GeoCoord[];
  utc_timestamp: string;
}

interface SubmarineCableRoute {
  cable_id: string;
  name: string;
  landing_points: GeoCoord[];
  total_length_km: number;
  capacity_tbps: number;
}

interface GlobalGeoMapDataset {
  clusters: GeoMapClusterNode[];
  traffic_arcs: GeoMapTrafficArc[];
  terminator: SolarTerminatorData;
  submarine_cables: SubmarineCableRoute[];
  country_threat_matrix: Record<string, number>;
  global_total_bytes: number;
  global_packet_count: number;
}

const mapContainerRef = ref<HTMLDivElement | null>(null);
const mapCanvasRef = ref<HTMLCanvasElement | null>(null);

const projectionMode = ref<'3d' | '2d'>('3d');
const loading = ref(false);
const isSidebarCollapsed = ref(false);

const layers = ref({
  terminator: true,
  cables: true,
  arcs: true,
  graticules: true,
});

const mapData = ref<GlobalGeoMapDataset | null>(null);
const selectedNode = ref<GeoMapClusterNode | null>(null);
const hoveredNode = ref<GeoMapClusterNode | null>(null);
const tooltipPos = ref({ x: 0, y: 0 });

// 视口状态
const centerLat = ref(35.0);
const centerLon = ref(105.0);
const scale = ref(1.0);

let isDragging = false;
let lastMousePos = { x: 0, y: 0 };
let animationFrameId: number | null = null;
let animPhase = 0;

// 世界大陆多边形离线骨干数据 (经纬度多边形闭合路径，100% 离线脱机)
const CONTINENT_POLYGONS: number[][][] = [
  // 欧亚非大陆主要轮廓
  [[-10, 36], [0, 42], [10, 45], [20, 40], [30, 38], [40, 42], [60, 40], [70, 30], [80, 20], [90, 22], [105, 20], [120, 25], [125, 40], [130, 50], [140, 55], [170, 65], [170, 72], [100, 78], [60, 75], [30, 70], [10, 60], [-5, 55], [-10, 40], [-10, 36]],
  // 非洲大陆
  [[-18, 15], [-15, 30], [-5, 36], [10, 37], [32, 31], [43, 12], [51, 11], [40, -10], [33, -28], [25, -34], [18, -34], [10, -5], [0, 5], [-18, 15]],
  // 北美洲
  [[-168, 65], [-140, 70], [-100, 75], [-60, 60], [-55, 50], [-70, 42], [-80, 25], [-97, 20], [-105, 22], [-115, 30], [-125, 48], [-140, 58], [-168, 65]],
  // 南美洲
  [[-80, 8], [-75, 11], [-60, 8], [-35, -5], [-38, -15], [-50, -30], [-65, -50], [-74, -53], [-75, -40], [-81, -5], [-80, 8]],
  // 澳大利亚
  [[114, -22], [125, -15], [135, -12], [148, -20], [152, -32], [140, -38], [118, -35], [114, -22]],
];

async function loadMapData() {
  loading.value = true;
  try {
    const res = await invoke<GlobalGeoMapDataset>('get_global_geo_map_data_cmd');
    if (res) {
      mapData.value = res;
    }
  } catch (err) {
    console.error('加载全球网络地理态势失败:', err);
  } finally {
    loading.value = false;
  }
}

function resetViewport() {
  centerLat.value = 35.0;
  centerLon.value = 105.0;
  scale.value = 1.0;
}

function handleMouseDown(e: MouseEvent) {
  isDragging = true;
  lastMousePos = { x: e.clientX, y: e.clientY };
}

function handleMouseMove(e: MouseEvent) {
  if (isDragging) {
    const dx = e.clientX - lastMousePos.x;
    const dy = e.clientY - lastMousePos.y;
    lastMousePos = { x: e.clientX, y: e.clientY };

    if (projectionMode.value === '3d') {
      const sensitivity = 0.3 / scale.value;
      centerLon.value -= dx * sensitivity;
      centerLat.value += dy * sensitivity;
      centerLat.value = Math.max(-85, Math.min(85, centerLat.value));
    } else {
      const sensitivity = 0.4 / scale.value;
      centerLon.value -= dx * sensitivity;
      centerLat.value += dy * sensitivity;
      centerLat.value = Math.max(-85, Math.min(85, centerLat.value));
    }
    while (centerLon.value > 180) centerLon.value -= 360;
    while (centerLon.value < -180) centerLon.value += 360;
  } else {
    // 检查 Hover 城市节点
    checkNodeHover(e);
  }
}

function handleMouseUp(_e: MouseEvent) {
  if (!isDragging) {
    // 点击选中
    if (hoveredNode.value) {
      selectedNode.value = hoveredNode.value;
    }
  }
  isDragging = false;
}

function handleWheel(e: WheelEvent) {
  const zoomFactor = e.deltaY < 0 ? 1.15 : 0.85;
  scale.value = Math.max(0.5, Math.min(6.0, scale.value * zoomFactor));
}

function checkNodeHover(e: MouseEvent) {
  const canvas = mapCanvasRef.value;
  if (!canvas || !mapData.value) return;

  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;

  let found: GeoMapClusterNode | null = null;
  for (const node of mapData.value.clusters) {
    const pt = project(node.center_coord.lat, node.center_coord.lon, canvas.width, canvas.height);
    if (pt.visible) {
      const dist = Math.hypot(pt.x - mx, pt.y - my);
      if (dist < 12) {
        found = node;
        tooltipPos.value = { x: e.clientX, y: e.clientY };
        break;
      }
    }
  }
  hoveredNode.value = found;
}

// 投影核心算法 (3D 正射投影 / 2D 等角全景)
function project(lat: number, lon: number, w: number, h: number): { x: number; y: number; visible: boolean } {
  if (projectionMode.value === '3d') {
    const phi = (lat * Math.PI) / 180;
    const lambda = (lon * Math.PI) / 180;
    const phi0 = (centerLat.value * Math.PI) / 180;
    const lambda0 = (centerLon.value * Math.PI) / 180;

    const cosC = Math.sin(phi0) * Math.sin(phi) + Math.cos(phi0) * Math.cos(phi) * Math.cos(lambda - lambda0);
    const visible = cosC > 0.05; // 正射投影背面遮挡剔除

    const r = Math.min(w, h) * 0.42 * scale.value;
    const x = w / 2 + r * Math.cos(phi) * Math.sin(lambda - lambda0);
    const y = h / 2 - r * (Math.cos(phi0) * Math.sin(phi) - Math.sin(phi0) * Math.cos(phi) * Math.cos(lambda - lambda0));

    return { x, y, visible };
  } else {
    // 2D 等角圆柱投影
    let dLon = lon - centerLon.value;
    while (dLon > 180) dLon -= 360;
    while (dLon < -180) dLon += 360;

    const rX = (w / 360) * scale.value;
    const rY = (h / 180) * scale.value;

    const x = w / 2 + dLon * rX;
    const y = h / 2 - (lat - centerLat.value) * rY;
    const visible = x >= -50 && x <= w + 50 && y >= -50 && y <= h + 50;

    return { x, y, visible };
  }
}

// 主渲染循环
function render() {
  const canvas = mapCanvasRef.value;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  animPhase = (animPhase + 0.015) % 1.0;

  // 1. 3D 渲染背景球与大气发光
  if (projectionMode.value === '3d') {
    const r = Math.min(w, h) * 0.42 * scale.value;
    const cx = w / 2;
    const cy = h / 2;

    // 大气发光光晕
    const glow = ctx.createRadialGradient(cx, cy, r * 0.9, cx, cy, r * 1.15);
    glow.addColorStop(0, 'rgba(56, 189, 248, 0.25)');
    glow.addColorStop(0.5, 'rgba(99, 102, 241, 0.12)');
    glow.addColorStop(1, 'rgba(0, 0, 0, 0)');
    ctx.fillStyle = glow;
    ctx.beginPath();
    ctx.arc(cx, cy, r * 1.2, 0, Math.PI * 2);
    ctx.fill();

    // 深邃地球球体底色
    const sphereGrad = ctx.createRadialGradient(cx - r * 0.3, cy - r * 0.3, r * 0.1, cx, cy, r);
    sphereGrad.addColorStop(0, '#0f172a');
    sphereGrad.addColorStop(1, '#020617');
    ctx.fillStyle = sphereGrad;
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.fill();
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.15)';
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }

  // 2. 经纬度网格线 (Graticules 30° 步长)
  if (layers.value.graticules) {
    ctx.strokeStyle = 'rgba(148, 163, 184, 0.1)';
    ctx.lineWidth = 1;
    for (let lat = -60; lat <= 60; lat += 30) {
      ctx.beginPath();
      let first = true;
      for (let lon = -180; lon <= 180; lon += 5) {
        const pt = project(lat, lon, w, h);
        if (pt.visible) {
          if (first) { ctx.moveTo(pt.x, pt.y); first = false; }
          else { ctx.lineTo(pt.x, pt.y); }
        } else {
          first = true;
        }
      }
      ctx.stroke();
    }
  }

  // 3. 绘制大陆板块矢量轮廓
  ctx.fillStyle = 'rgba(30, 41, 59, 0.65)';
  ctx.strokeStyle = 'rgba(56, 189, 248, 0.3)';
  ctx.lineWidth = 1.2;

  for (const poly of CONTINENT_POLYGONS) {
    ctx.beginPath();
    let first = true;
    for (const [lon, lat] of poly) {
      const pt = project(lat, lon, w, h);
      if (pt.visible) {
        if (first) { ctx.moveTo(pt.x, pt.y); first = false; }
        else { ctx.lineTo(pt.x, pt.y); }
      } else {
        first = true;
      }
    }
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
  }

  // 4. 昼夜晨昏线阴影 (Terminator Line)
  if (layers.value.terminator && mapData.value?.terminator) {
    ctx.fillStyle = 'rgba(2, 6, 23, 0.55)';
    ctx.strokeStyle = 'rgba(245, 158, 11, 0.6)';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    let first = true;
    for (const p of mapData.value.terminator.terminator_points) {
      const pt = project(p.lat, p.lon, w, h);
      if (pt.visible) {
        if (first) { ctx.moveTo(pt.x, pt.y); first = false; }
        else { ctx.lineTo(pt.x, pt.y); }
      } else {
        first = true;
      }
    }
    ctx.stroke();
  }

  // 5. 洲际海底光缆路由 (Submarine Cables)
  if (layers.value.cables && mapData.value?.submarine_cables) {
    ctx.strokeStyle = 'rgba(6, 182, 212, 0.45)';
    ctx.lineWidth = 1.5;
    ctx.setLineDash([4, 4]);

    for (const cable of mapData.value.submarine_cables) {
      ctx.beginPath();
      let first = true;
      for (const p of cable.landing_points) {
        const pt = project(p.lat, p.lon, w, h);
        if (pt.visible) {
          if (first) { ctx.moveTo(pt.x, pt.y); first = false; }
          else { ctx.lineTo(pt.x, pt.y); }
        } else {
          first = true;
        }
      }
      ctx.stroke();
    }
    ctx.setLineDash([]);
  }

  // 6. 测地通信飞线 (Geodesic Great-Circle Arcs)
  if (layers.value.arcs && mapData.value?.traffic_arcs) {
    for (const arc of mapData.value.traffic_arcs) {
      ctx.strokeStyle = arc.is_threat_flow ? 'rgba(244, 63, 94, 0.7)' : 'rgba(99, 102, 241, 0.55)';
      ctx.lineWidth = arc.is_threat_flow ? 2.5 : 1.5;

      ctx.beginPath();
      let first = true;
      for (const wp of arc.waypoints) {
        const pt = project(wp.lat, wp.lon, w, h);
        if (pt.visible) {
          if (first) { ctx.moveTo(pt.x, pt.y); first = false; }
          else { ctx.lineTo(pt.x, pt.y); }
        } else {
          first = true;
        }
      }
      ctx.stroke();

      // 沿飞线运动的动态能量粒子脉冲
      const pulseIdx = Math.floor(animPhase * (arc.waypoints.length - 1));
      const wpPulse = arc.waypoints[pulseIdx];
      if (wpPulse) {
        const pulsePt = project(wpPulse.lat, wpPulse.lon, w, h);
        if (pulsePt.visible) {
          ctx.fillStyle = arc.is_threat_flow ? '#fb7185' : '#38bdf8';
          ctx.beginPath();
          ctx.arc(pulsePt.x, pulsePt.y, 3.5, 0, Math.PI * 2);
          ctx.fill();
        }
      }
    }
  }

  // 7. 城市节点与聚类光圈 (Spatial Clusters)
  if (mapData.value?.clusters) {
    for (const node of mapData.value.clusters) {
      const pt = project(node.center_coord.lat, node.center_coord.lon, w, h);
      if (pt.visible) {
        const isHovered = hoveredNode.value?.cluster_id === node.cluster_id;
        const isSelected = selectedNode.value?.cluster_id === node.cluster_id;

        // 涟漪扩散光环
        ctx.fillStyle = node.is_local_origin
          ? 'rgba(16, 185, 129, 0.25)'
          : node.threat_score > 0
          ? 'rgba(244, 63, 94, 0.25)'
          : 'rgba(56, 189, 248, 0.2)';
        ctx.beginPath();
        const rippleR = 6 + (animPhase * 8);
        ctx.arc(pt.x, pt.y, rippleR, 0, Math.PI * 2);
        ctx.fill();

        // 实体核心圆点
        ctx.fillStyle = node.is_local_origin
          ? '#10b981'
          : node.threat_score > 0
          ? '#f43f5e'
          : '#38bdf8';
        ctx.beginPath();
        const baseR = isSelected || isHovered ? 6 : 4;
        ctx.arc(pt.x, pt.y, baseR, 0, Math.PI * 2);
        ctx.fill();

        if (isSelected) {
          ctx.strokeStyle = '#ffffff';
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        // 城市文字标签
        ctx.fillStyle = '#ffffff';
        ctx.font = '10px monospace';
        ctx.fillText(node.city_name, pt.x + 7, pt.y + 3);
      }
    }
  }

  animationFrameId = requestAnimationFrame(render);
}

function handleResize() {
  const container = mapContainerRef.value;
  const canvas = mapCanvasRef.value;
  if (!container || !canvas) return;

  const rect = container.getBoundingClientRect();
  canvas.width = rect.width;
  canvas.height = rect.height;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

function openDossierForIp(ip: string) {
  // 可联动主应用打开 IP Dossier 弹窗
  window.dispatchEvent(new CustomEvent('open-ip-dossier', { detail: { ip } }));
}

onMounted(() => {
  handleResize();
  window.addEventListener('resize', handleResize);
  loadMapData();
  render();
});

onUnmounted(() => {
  window.removeEventListener('resize', handleResize);
  if (animationFrameId !== null) {
    cancelAnimationFrame(animationFrameId);
  }
});

watch(projectionMode, () => {
  resetViewport();
});
</script>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 5px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: transparent;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(148, 163, 184, 0.2);
  border-radius: 9999px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(148, 163, 184, 0.4);
}
</style>
