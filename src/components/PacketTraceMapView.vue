<template>
  <div class="packet-trace-map-container flex flex-col gap-2.5 select-none w-full">
    <!-- 1. 顶栏：本地到目标网络 Trace 核心状态栏与快速操作 -->
    <div class="flex items-center justify-between flex-wrap gap-2 text-xs">
      <div class="flex items-center gap-2 flex-wrap">
        <div class="w-6 h-6 rounded-lg bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-600 dark:text-cyan-400 shrink-0 shadow-xs">
          <AppIcon :name="viewMode === '3d' ? 'globe' : 'compass'" :size="13" />
        </div>
        <div class="flex items-center gap-1.5 font-semibold" style="color: var(--text-primary)">
          <span>网络 Trace 链路 & 地理 MAP</span>
          <span class="text-[11px] px-1.5 py-0.2 rounded ui-pill font-mono">
            {{ isLanScenario ? 'RFC 1918 局域网' : 'WAN 广域骨干跨域' }}
          </span>
          <span v-if="targetAccuracyLevel" class="text-[10px] px-1.5 py-0.2 rounded bg-sky-500/10 text-sky-600 dark:text-cyan-300 border border-sky-500/20">
            {{ targetAccuracyLabel }}
          </span>
        </div>
      </div>

      <div class="flex items-center gap-1.5 shrink-0">
        <!-- 3D/2D 视口快速切换 -->
        <div class="ui-pill p-0.5 rounded-lg flex items-center gap-0.5 text-[10px] font-semibold border" :class="isDarkTheme ? 'border-white/10' : 'border-slate-300/60'">
          <button
            @click="viewMode = '3d'"
            :class="['px-2 py-0.5 rounded transition-colors cursor-pointer flex items-center gap-1',
              viewMode === '3d' ? 'bg-sky-500 text-white font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
            :style="viewMode !== '3d' ? { color: 'var(--text-secondary)' } : undefined"
            title="3D 数字地球视图"
          >
            <AppIcon name="globe" :size="11" />
            <span>3D 地球</span>
          </button>
          <button
            @click="viewMode = '2d'"
            :class="['px-2 py-0.5 rounded transition-colors cursor-pointer flex items-center gap-1',
              viewMode === '2d' ? 'bg-sky-500 text-white font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
            :style="viewMode !== '2d' ? { color: 'var(--text-secondary)' } : undefined"
            title="2D 全景平面投影视图"
          >
            <AppIcon name="compass" :size="11" />
            <span>2D 平面</span>
          </button>
        </div>

        <!-- 实时追踪触发按钮 -->
        <button
          v-if="targetIp"
          @click="startLiveTraceroute"
          :disabled="isTracing"
          class="px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-colors flex items-center gap-1 cursor-pointer"
          :class="isTracing ? 'bg-amber-500/20 text-amber-600 dark:text-amber-300 border border-amber-500/30 animate-pulse' : 'ui-btn-secondary hover:text-sky-600 dark:hover:text-cyan-300'"
          title="对当前目标 IP 启动真实逐跳路由追踪 (Traceroute)"
        >
          <AppIcon :name="isTracing ? 'refresh' : 'play'" :size="11" />
          <span>{{ isTracing ? `探测中 Hop ${currentHop}...` : '实时追踪 (Trace)' }}</span>
        </button>

        <!-- 全屏态势模态窗直通 -->
        <button
          v-if="targetIp"
          @click="$emit('openFullTraceroute', targetIp)"
          class="px-2.5 py-1 rounded-lg text-[11px] ui-btn-primary flex items-center gap-1 cursor-pointer font-bold shadow-xs"
          title="在全屏 3D 数字地球 / 2D 全景投影中完整展示"
        >
          <AppIcon name="compass" :size="11" />
          <span>全屏态势 ➔</span>
        </button>
      </div>
    </div>

    <!-- 2. 核心左右分栏：左侧逐跳节点流 + 右侧 3D 溯源数字地球 / 2D 全景地图 -->
    <div
      class="w-full rounded-2xl overflow-hidden border border-[var(--border-subtle)] flex flex-col md:flex-row"
      :class="compact ? 'h-[280px]' : 'h-[360px]'"
      style="background: var(--surface-content-alt)"
    >
      <!-- 左侧：逐跳节点序列流 (42% 宽度) -->
      <div class="w-full md:w-[42%] lg:w-[40%] border-r flex flex-col min-h-0 overflow-hidden" style="border-color: var(--border-subtle); background: var(--surface-content)">
        
        <!-- 左侧顶部指标摘要 -->
        <div class="p-2.5 border-b flex items-center justify-between text-[11px] ui-num shrink-0" style="border-color: var(--border-subtle); background: var(--surface-content-alt)">
          <div class="flex items-center gap-1.5 truncate">
            <span class="w-2 h-2 rounded-full bg-emerald-500 shrink-0"></span>
            <span style="color: var(--text-muted)">线距:</span>
            <strong class="text-emerald-700 dark:text-emerald-400 font-bold">
              {{ isLanScenario ? '< 50 m' : `${greatCircleDistanceKm.toFixed(0)} km` }}
            </strong>
          </div>
          <div class="flex items-center gap-1.5 truncate">
            <span style="color: var(--text-muted)">理论最低 RTT:</span>
            <strong class="text-sky-700 dark:text-cyan-400 font-bold">
              {{ isLanScenario ? '< 0.1 ms' : `~${theoreticalRttMs.toFixed(1)} ms` }}
            </strong>
          </div>
        </div>

        <!-- 左侧逐跳卡片滚动流 -->
        <div class="flex-1 overflow-y-auto p-2 space-y-1.5 custom-scrollbar select-text text-xs">
          <template v-for="(hop, idx) in displayHops" :key="'trace-hop-' + hop.hopNumber">
            <div
              :class="[
                'p-2 rounded-xl border transition-all cursor-pointer flex flex-col gap-1',
                hop.isSelf ? '!border-emerald-500/50 bg-emerald-500/8' :
                (hop.isDestination ? '!border-amber-500/60 bg-amber-500/10' : 'border-[var(--border-subtle)] bg-[var(--surface-content-alt)] hover:border-sky-500/50'),
                selectedHopIndex === idx ? 'ring-2 ring-sky-500' : ''
              ]"
              @click="focusOnHopNode(hop, idx)"
            >
              <!-- 顶部：跳数 + IP + RTT -->
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-1.5 font-mono">
                  <span
                    :class="[
                      'px-1.5 py-0.2 rounded text-[10px] font-bold',
                      hop.isSelf ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300' :
                      (hop.isDestination ? 'bg-amber-500/20 text-amber-700 dark:text-amber-300' : 'ui-pill text-slate-400')
                    ]"
                  >
                    #{{ hop.hopNumber }}
                  </span>
                  <span class="font-bold truncate max-w-[130px]" style="color: var(--text-primary)">
                    {{ hop.ip }}
                  </span>
                </div>

                <span class="text-[11px] font-mono font-bold" :class="getRttClass(hop.rttMs)">
                  {{ hop.rttMs < 0 ? '*' : (hop.isSelf ? '0.0ms' : `${hop.rttMs.toFixed(1)}ms`) }}
                </span>
              </div>

              <!-- 底部：地区与角色 -->
              <div class="flex items-center justify-between text-[11px]" style="color: var(--text-muted)">
                <span class="truncate text-sky-700 dark:text-cyan-300 font-medium">
                  {{ hop.location || hop.role }}
                </span>
                <span v-if="hop.lon && hop.lat" class="text-[10px] ui-num text-emerald-700 dark:text-emerald-400">
                  [{{ hop.lon.toFixed(1) }}°, {{ hop.lat.toFixed(1) }}°]
                </span>
              </div>
            </div>
          </template>
        </div>

        <!-- 左侧底部提示 -->
        <div class="px-2.5 py-1.5 border-t text-[10px] ui-num flex items-center justify-between shrink-0" style="border-color: var(--border-subtle); color: var(--text-muted)">
          <span>已捕获 {{ displayHops.length }} 跃点</span>
          <span>单击卡片对焦右侧地球</span>
        </div>
      </div>

      <!-- 右侧：3D 溯源数字地球 / 2D 平面投影 (58% 宽度) -->
      <div class="flex-1 relative flex flex-col min-h-0 overflow-hidden bg-slate-950/20">
        
        <!-- 模式 A: 3D 交互式数字地球 Canvas -->
        <canvas
          v-show="viewMode === '3d'"
          ref="globeMiniCanvasRef"
          class="w-full h-full cursor-grab active:cursor-grabbing select-none block"
          @mousedown="onGlobeMouseDown"
          @mousemove="onGlobeMouseMove"
          @mouseup="onGlobeMouseUp"
          @mouseleave="onGlobeMouseUp"
          @wheel.prevent="onGlobeWheel"
        ></canvas>

        <!-- 模式 B: 2D WGS-84 等角圆柱投影 SVG -->
        <svg
          v-show="viewMode === '2d'"
          viewBox="0 0 960 480"
          class="w-full h-full object-cover select-none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <filter id="ptm-glow-mini" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="2.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <linearGradient id="ptm-arc-gradient-mini" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stop-color="#10B981" />
              <stop offset="50%" stop-color="#38BDF8" />
              <stop offset="100%" stop-color="#F59E0B" />
            </linearGradient>
          </defs>

          <!-- 经纬网格 -->
          <g stroke="rgba(255,255,255,0.06)" stroke-width="0.7">
            <line x1="0" y1="240" x2="960" y2="240" stroke="rgba(56, 189, 248, 0.28)" stroke-width="1.2" />
            <line x1="480" y1="0" x2="480" y2="480" stroke="rgba(56, 189, 248, 0.28)" stroke-width="1.2" />
            <line x1="0" y1="177.5" x2="960" y2="177.5" stroke="rgba(245, 158, 11, 0.2)" stroke-dasharray="3 3" />
            <line x1="0" y1="302.5" x2="960" y2="302.5" stroke="rgba(245, 158, 11, 0.2)" stroke-dasharray="3 3" />
            <line v-for="x in [80, 160, 240, 320, 400, 560, 640, 720, 800, 880]" :key="'lon-m-' + x" :x1="x" y1="0" :x2="x" y2="480" stroke-dasharray="2 3" />
            <line v-for="y in [80, 160, 320, 400]" :key="'lat-m-' + y" x1="0" :y1="y" x2="960" :y2="y" stroke-dasharray="2 3" />
          </g>

          <!-- 大陆多边形 -->
          <g fill="rgba(30, 58, 110, 0.28)" stroke="rgba(56, 189, 248, 0.3)" stroke-width="0.8">
            <path v-for="(pathStr, pIdx) in worldLandPaths" :key="'poly-m-' + pIdx" :d="pathStr" />
          </g>

          <!-- 测地飞线 -->
          <g v-if="flightArcs.length > 0">
            <template v-for="(arc, aIdx) in flightArcs" :key="'arc-m-' + aIdx">
              <path :d="arc.pathData" fill="none" :stroke="arc.color" stroke-opacity="0.25" stroke-width="3.5" />
              <path
                :d="arc.pathData"
                fill="none"
                :stroke="arc.color"
                stroke-width="1.8"
                stroke-dasharray="6 4"
                class="animate-dash"
                filter="url(#ptm-glow-mini)"
              />
            </template>
          </g>

          <!-- 节点标记 -->
          <template v-for="wp in visibleWaypoints" :key="'wp-m-' + wp.hopNumber">
            <circle
              :cx="wp.x2d"
              :cy="wp.y2d"
              :r="wp.isSelf ? 8 : (wp.isDestination ? 9 : 6)"
              :fill="wp.isSelf ? 'rgba(16, 185, 129, 0.25)' : (wp.isDestination ? 'rgba(245, 158, 11, 0.25)' : 'rgba(56, 189, 248, 0.2)')"
            />
            <circle
              :cx="wp.x2d"
              :cy="wp.y2d"
              :r="wp.isDestination ? 4.5 : (wp.isSelf ? 4 : 3)"
              :fill="wp.isSelf ? '#10B981' : (wp.isDestination ? '#F59E0B' : '#38BDF8')"
              stroke="#ffffff"
              stroke-width="1.2"
            />
            <text
              :x="wp.x2d + 6"
              :y="wp.isDestination ? wp.y2d + 12 : wp.y2d - 4"
              :fill="wp.isSelf ? '#10B981' : (wp.isDestination ? '#F59E0B' : '#38BDF8')"
              font-size="9"
              font-weight="bold"
              font-family="monospace"
            >
              #{{ wp.hopNumber }}
            </text>
          </template>
        </svg>

        <!-- 3D 地球浮动操作提示 -->
        <div v-show="viewMode === '3d'" class="absolute bottom-2 left-2 text-[10px] ui-num liquid-panel px-2.5 py-1 rounded-xl select-none pointer-events-none shadow-xs" style="color: var(--text-secondary)">
          按住拖拽 360° 旋转 · 滚轮缩放
        </div>
        <div v-show="viewMode === '3d'" class="absolute top-2 right-2 text-[10px] ui-num liquid-panel px-2.5 py-1 rounded-xl select-none pointer-events-none shadow-xs text-sky-700 dark:text-cyan-400 font-bold">
          3D 空间测地数字地球
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, nextTick } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import AppIcon from './AppIcon.vue';
import {
  WORLD_LAND_POLYGONS,
  projectEquirectangular,
  calculateGreatCircleDistanceKm,
  calculateSpeedOfLightDelayMs,
  generateMultiHopFlightArcs,
  formatGeoLocation,
  interpolateGreatCirclePoint,
  type GeoWaypoint,
  type FlightArcSegment
} from '../utils/geoMap';

const isDarkTheme = ref(!document.documentElement.classList.contains('theme-apple-light'));
let themeObserver: MutationObserver | null = null;

// 视图模式: '3d' (数字地球) | '2d' (平面地图)
const viewMode = ref<'3d' | '2d'>('3d');

interface PacketRecord {
  id: number;
  src_ip: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  length?: number;
  [key: string]: any;
}

interface HopNode {
  hopNumber: number;
  ip: string;
  rttMs: number;
  role: string;
  location: string;
  isp?: string;
  lon?: number;
  lat?: number;
  isSelf?: boolean;
  isDestination?: boolean;
}

interface BackendTracerouteHop {
  hop: number;
  hop_number?: number;
  ip: string;
  rtt_ms?: number | null;
  is_timeout: boolean;
  geo?: {
    latitude: number;
    longitude: number;
    country: string;
    province: string;
    city: string;
    label: string;
  } | null;
  latitude?: number;
  longitude?: number;
  has_geo?: boolean;
  country: string;
  province: string;
  city: string;
  isp: string;
  zone_name: string;
  cumulative_distance_km: number;
  theoretical_fiber_rtt_ms: number;
  is_self: boolean;
  is_lan: boolean;
  lan_role?: string;
  subnet_cidr?: string;
  is_destination?: boolean;
}

const props = withDefaults(
  defineProps<{
    packet: PacketRecord | null;
    compact?: boolean;
  }>(),
  {
    compact: false
  }
);

const emit = defineEmits<{
  (e: 'openFullTraceroute', targetIp: string): void;
  (e: 'appendLog', msg: string): void;
}>();

const selectedHopIndex = ref<number | null>(null);

// 1. 本地与目标端点提取
const isLanScenario = computed(() => {
  if (!props.packet) return false;
  const ip = targetIp.value;
  return isPrivateIp(ip) || ip === '127.0.0.1' || ip.startsWith('10.') || ip.startsWith('192.168.');
});

function isPrivateIp(ip: string): boolean {
  if (!ip) return false;
  if (ip === '127.0.0.1' || ip === 'localhost') return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  if (ip.startsWith('172.')) {
    const parts = ip.split('.');
    const second = parseInt(parts[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

const targetIp = computed(() => {
  if (!props.packet) return '';
  if (isPrivateIp(props.packet.src_ip) && !isPrivateIp(props.packet.dst_ip)) {
    return props.packet.dst_ip;
  }
  return props.packet.dst_ip || props.packet.src_ip || '';
});

// 2. 节点地理情报
const localHopInfo = ref<{
  ip: string;
  lon: number;
  lat: number;
  location: string;
  isp?: string;
  city?: string;
}>({
  ip: '127.0.0.1',
  lon: 114.05,
  lat: 22.55,
  location: '本地基准锚点',
  city: '本机'
});

const targetHopInfo = ref<{
  ip: string;
  lon: number;
  lat: number;
  location: string;
  isp?: string;
  country?: string;
  province?: string;
  city?: string;
}>({
  ip: '',
  lon: -74.0,
  lat: 40.7,
  location: '目标主机',
  country: '公网目标',
  city: '目标'
});

const targetAccuracyLevel = ref<string>('');
const targetAccuracyLabel = computed(() => {
  if (targetAccuracyLevel.value === 'city') return '地级市级定位';
  if (targetAccuracyLevel.value === 'province') return '省级行政区定位';
  if (targetAccuracyLevel.value === 'country') return '国家定位';
  return '离线地理库定位';
});

// 3. 实时 Traceroute 状态与流式侦测
const isTracing = ref(false);
const currentHop = ref(1);
const liveHops = ref<HopNode[]>([]);
let unlistenHopEvent: UnlistenFn | null = null;

// 4. 组装展示跳数列表 (每一个节点都具备空间经纬度，若无则大圆 Slerp 空间插值)
const displayHops = computed<HopNode[]>(() => {
  if (liveHops.value.length > 0) {
    const list = [...liveHops.value];
    const total = list.length;
    const startLon = localHopInfo.value.lon;
    const startLat = localHopInfo.value.lat;
    const endLon = targetHopInfo.value.lon;
    const endLat = targetHopInfo.value.lat;

    for (let i = 0; i < total; i++) {
      if (list[i].lon === undefined || list[i].lat === undefined) {
        const t = i / Math.max(1, total - 1);
        const [lon, lat] = interpolateGreatCirclePoint(startLon, startLat, endLon, endLat, t);
        list[i].lon = lon;
        list[i].lat = lat;
      }
    }
    return list;
  }

  // 默认静态推导跳数骨架 (起点 ➔ 网关 ➔ 骨干 ➔ 终点)
  const total = isLanScenario.value ? 3 : 4;
  const startLon = localHopInfo.value.lon;
  const startLat = localHopInfo.value.lat;
  const endLon = targetHopInfo.value.lon;
  const endLat = targetHopInfo.value.lat;

  const hops: HopNode[] = [
    {
      hopNumber: 0,
      ip: localHopInfo.value.ip,
      rttMs: 0.1,
      role: '本机网卡',
      location: '本地主机终端',
      lon: startLon,
      lat: startLat,
      isSelf: true
    },
    {
      hopNumber: 1,
      ip: isLanScenario.value ? '192.168.1.1' : '局域网默认网关',
      rttMs: 0.6,
      role: '默认网关',
      location: '接入路由设备',
      lon: interpolateGreatCirclePoint(startLon, startLat, endLon, endLat, 1 / (total - 1))[0],
      lat: interpolateGreatCirclePoint(startLon, startLat, endLon, endLat, 1 / (total - 1))[1]
    }
  ];

  if (!isLanScenario.value) {
    hops.push({
      hopNumber: 2,
      ip: '骨干网络中继',
      rttMs: 14.0,
      role: '运营商核心路由',
      location: '广域网骨干节点',
      lon: interpolateGreatCirclePoint(startLon, startLat, endLon, endLat, 2 / (total - 1))[0],
      lat: interpolateGreatCirclePoint(startLon, startLat, endLon, endLat, 2 / (total - 1))[1]
    });
  }

  hops.push({
    hopNumber: isLanScenario.value ? 2 : 3,
    ip: targetHopInfo.value.ip || '目标端点',
    rttMs: isLanScenario.value ? 1.2 : Math.max(15, theoreticalRttMs.value * 2.2),
    role: '目标服务器',
    location: targetHopInfo.value.location,
    lon: endLon,
    lat: endLat,
    isDestination: true
  });

  return hops;
});

// 计算全量航路点
const visibleWaypoints = computed<GeoWaypoint[]>(() => {
  return displayHops.value.map(h => {
    const lon = h.lon ?? 114.05;
    const lat = h.lat ?? 22.55;
    const [x2d, y2d] = projectEquirectangular(lon, lat, 960, 480);
    return {
      hopNumber: h.hopNumber,
      ip: h.ip,
      lon,
      lat,
      x2d,
      y2d,
      rttMs: h.rttMs,
      role: h.role,
      location: h.location,
      isp: h.isp,
      isSelf: h.isSelf,
      isDestination: h.isDestination
    };
  });
});

// 飞线段
const flightArcs = computed<FlightArcSegment[]>(() => {
  return generateMultiHopFlightArcs(visibleWaypoints.value, 35);
});

const greatCircleDistanceKm = computed<number>(() => {
  return calculateGreatCircleDistanceKm(
    localHopInfo.value.lon,
    localHopInfo.value.lat,
    targetHopInfo.value.lon,
    targetHopInfo.value.lat
  );
});

const theoreticalRttMs = computed<number>(() => {
  return calculateSpeedOfLightDelayMs(greatCircleDistanceKm.value);
});

// 世界大陆 2D 轮廓
const worldLandPaths = computed(() => {
  return WORLD_LAND_POLYGONS.map(poly => {
    return (
      poly
        .map((pt, i) => {
          const [x, y] = projectEquirectangular(pt[0], pt[1], 960, 480);
          return `${i === 0 ? 'M' : 'L'} ${x} ${y}`;
        })
        .join(' ') + ' Z'
    );
  });
});

// ============================================================
// 3D 正射投影数字地球 (Mini 3D Globe Canvas)
// ============================================================
const globeMiniCanvasRef = ref<HTMLCanvasElement | null>(null);
const globeRotation = ref({
  centerLon: 114.05,
  centerLat: 22.55,
  targetLon: 114.05,
  targetLat: 22.55,
  isTransitioning: false,
  radius: 110,
  isDragging: false,
  lastMouseX: 0,
  lastMouseY: 0
});

let animationFrameId: number | null = null;
let pulseTime = 0;

function projectLonLatToMiniGlobe(lon: number, lat: number, centerLon: number, centerLat: number, radius: number) {
  const lambda = (lon * Math.PI) / 180.0;
  const phi = (lat * Math.PI) / 180.0;
  const lambda0 = (centerLon * Math.PI) / 180.0;
  const phi0 = (centerLat * Math.PI) / 180.0;

  const cosC = Math.sin(phi0) * Math.sin(phi) + Math.cos(phi0) * Math.cos(phi) * Math.cos(lambda - lambda0);
  const visible = cosC >= 0;

  const x = radius * Math.cos(phi) * Math.sin(lambda - lambda0);
  const y = radius * (Math.sin(phi0) * Math.cos(phi) * Math.cos(lambda - lambda0) - Math.cos(phi0) * Math.sin(phi));

  return { x, y: -y, visible };
}

function renderMiniGlobe() {
  const canvas = globeMiniCanvasRef.value;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const w = canvas.width;
  const h = canvas.height;
  const cx = w / 2;
  const cy = h / 2;
  const r = globeRotation.value.radius;
  const cLon = globeRotation.value.centerLon;
  const cLat = globeRotation.value.centerLat;

  ctx.clearRect(0, 0, w, h);
  const dark = isDarkTheme.value;

  // 大气光环
  const haloGrad = ctx.createRadialGradient(cx, cy, r * 0.9, cx, cy, r * 1.3);
  haloGrad.addColorStop(0, dark ? 'rgba(6, 182, 212, 0.3)' : 'rgba(14, 165, 233, 0.2)');
  haloGrad.addColorStop(1, 'rgba(15, 23, 42, 0)');
  ctx.fillStyle = haloGrad;
  ctx.beginPath();
  ctx.arc(cx, cy, r * 1.3, 0, Math.PI * 2);
  ctx.fill();

  // 球体背景
  const sphereGrad = ctx.createRadialGradient(cx - r * 0.35, cy - r * 0.35, r * 0.1, cx, cy, r);
  if (dark) {
    sphereGrad.addColorStop(0, '#0e2544');
    sphereGrad.addColorStop(0.65, '#06152a');
    sphereGrad.addColorStop(1, '#020617');
  } else {
    sphereGrad.addColorStop(0, '#e0f2fe');
    sphereGrad.addColorStop(0.65, '#bae6fd');
    sphereGrad.addColorStop(1, '#7dd3fc');
  }
  ctx.fillStyle = sphereGrad;
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.fill();

  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.clip();

  // 经纬网
  ctx.strokeStyle = dark ? 'rgba(56, 189, 248, 0.15)' : 'rgba(15, 23, 42, 0.12)';
  ctx.lineWidth = 0.8;
  for (let lat = -60; lat <= 60; lat += 30) {
    ctx.beginPath();
    let started = false;
    for (let lon = -180; lon <= 180; lon += 8) {
      const p = projectLonLatToMiniGlobe(lon, lat, cLon, cLat, r);
      if (p.visible) {
        if (!started) {
          ctx.moveTo(cx + p.x, cy + p.y);
          started = true;
        } else {
          ctx.lineTo(cx + p.x, cy + p.y);
        }
      } else {
        started = false;
      }
    }
    ctx.stroke();
  }

  // 大陆多边形
  ctx.fillStyle = dark ? 'rgba(30, 58, 95, 0.75)' : 'rgba(248, 250, 252, 0.92)';
  ctx.strokeStyle = dark ? 'rgba(34, 211, 238, 0.35)' : 'rgba(59, 130, 246, 0.35)';
  ctx.lineWidth = 1;

  for (const poly of WORLD_LAND_POLYGONS) {
    ctx.beginPath();
    let isDrawing = false;
    for (let i = 0; i < poly.length; i++) {
      const pt = poly[i];
      const p = projectLonLatToMiniGlobe(pt[0], pt[1], cLon, cLat, r);
      if (p.visible) {
        if (!isDrawing) {
          ctx.moveTo(cx + p.x, cy + p.y);
          isDrawing = true;
        } else {
          ctx.lineTo(cx + p.x, cy + p.y);
        }
      }
    }
    if (isDrawing) {
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    }
  }

  // 绘制大圆飞线与粒子
  const pts = visibleWaypoints.value;
  if (pts.length >= 2) {
    for (let i = 0; i < pts.length - 1; i++) {
      const p1 = pts[i];
      const p2 = pts[i + 1];

      const numSteps = 24;
      const arcPoints: { x: number; y: number; visible: boolean }[] = [];

      for (let s = 0; s <= numSteps; s++) {
        const t = s / numSteps;
        const [interpLon, interpLat] = interpolateGreatCirclePoint(p1.lon, p1.lat, p2.lon, p2.lat, t);
        const alt = Math.sin(t * Math.PI) * (r * 0.22);
        const pt = projectLonLatToMiniGlobe(interpLon, interpLat, cLon, cLat, r + alt);
        arcPoints.push(pt);
      }

      ctx.beginPath();
      let started = false;
      for (const ap of arcPoints) {
        if (ap.visible) {
          if (!started) {
            ctx.moveTo(cx + ap.x, cy + ap.y);
            started = true;
          } else {
            ctx.lineTo(cx + ap.x, cy + ap.y);
          }
        }
      }
      ctx.strokeStyle = p1.isSelf ? 'rgba(16, 185, 129, 0.85)' : (p2.isDestination ? 'rgba(245, 158, 11, 0.85)' : 'rgba(6, 182, 212, 0.8)');
      ctx.lineWidth = 2.2;
      ctx.stroke();

      // 光斑
      const flowT = (pulseTime * 0.9 + i * 0.35) % 1.0;
      const flowIdx = Math.floor(flowT * (arcPoints.length - 1));
      const flowPt = arcPoints[flowIdx];
      if (flowPt && flowPt.visible) {
        ctx.fillStyle = '#ffffff';
        ctx.shadowColor = '#38bdf8';
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(cx + flowPt.x, cy + flowPt.y, 3.2, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }
  }

  // 绘制信标
  for (let idx = 0; idx < pts.length; idx++) {
    const pt = pts[idx];
    const p = projectLonLatToMiniGlobe(pt.lon, pt.lat, cLon, cLat, r);
    if (p.visible) {
      const px = cx + p.x;
      const py = cy + p.y;
      const isSelected = selectedHopIndex.value === idx;

      ctx.beginPath();
      ctx.arc(px, py, isSelected ? 8 : 4.5, 0, Math.PI * 2);
      ctx.fillStyle = pt.isSelf ? '#10B981' : (pt.isDestination ? '#F59E0B' : '#38BDF8');
      ctx.shadowColor = ctx.fillStyle;
      ctx.shadowBlur = isSelected ? 10 : 5;
      ctx.fill();
      ctx.shadowBlur = 0;

      ctx.fillStyle = dark ? '#e2e8f0' : '#0f172a';
      ctx.font = 'bold 10px monospace';
      ctx.textAlign = 'center';
      ctx.fillText(`#${pt.hopNumber}`, px, py - 7);
    }
  }

  ctx.restore();

  ctx.strokeStyle = dark ? 'rgba(56, 189, 248, 0.4)' : 'rgba(14, 116, 144, 0.35)';
  ctx.lineWidth = 1.4;
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.stroke();
}

function animateMini() {
  pulseTime += 0.02;

  if (globeRotation.value.isTransitioning) {
    const targetLon = globeRotation.value.targetLon;
    const targetLat = globeRotation.value.targetLat;
    let diffLon = targetLon - globeRotation.value.centerLon;

    while (diffLon > 180) diffLon -= 360;
    while (diffLon < -180) diffLon += 360;

    const diffLat = targetLat - globeRotation.value.centerLat;

    if (Math.abs(diffLon) < 0.2 && Math.abs(diffLat) < 0.2) {
      globeRotation.value.centerLon = (targetLon + 360) % 360;
      globeRotation.value.centerLat = targetLat;
      globeRotation.value.isTransitioning = false;
    } else {
      globeRotation.value.centerLon = (globeRotation.value.centerLon + diffLon * 0.12 + 360) % 360;
      globeRotation.value.centerLat += diffLat * 0.12;
    }
  } else if (!globeRotation.value.isDragging && viewMode.value === '3d') {
    globeRotation.value.centerLon = (globeRotation.value.centerLon + 0.12) % 360;
  }

  if (viewMode.value === '3d') {
    renderMiniGlobe();
  }

  animationFrameId = requestAnimationFrame(animateMini);
}

function onGlobeMouseDown(e: MouseEvent) {
  globeRotation.value.isDragging = true;
  globeRotation.value.isTransitioning = false;
  globeRotation.value.lastMouseX = e.clientX;
  globeRotation.value.lastMouseY = e.clientY;
}

function onGlobeMouseMove(e: MouseEvent) {
  if (!globeRotation.value.isDragging) return;
  const dx = e.clientX - globeRotation.value.lastMouseX;
  const dy = e.clientY - globeRotation.value.lastMouseY;

  globeRotation.value.lastMouseX = e.clientX;
  globeRotation.value.lastMouseY = e.clientY;

  globeRotation.value.centerLon = (globeRotation.value.centerLon - dx * 0.4 + 360) % 360;
  globeRotation.value.centerLat = Math.max(-80, Math.min(80, globeRotation.value.centerLat + dy * 0.4));
}

function onGlobeMouseUp() {
  globeRotation.value.isDragging = false;
}

function onGlobeWheel(e: WheelEvent) {
  const delta = e.deltaY > 0 ? -8 : 8;
  globeRotation.value.radius = Math.max(70, Math.min(220, globeRotation.value.radius + delta));
}

function focusOnHopNode(hop: HopNode, idx: number) {
  selectedHopIndex.value = idx;
  if (hop.lon !== undefined && hop.lat !== undefined) {
    globeRotation.value.targetLon = hop.lon;
    globeRotation.value.targetLat = hop.lat;
    globeRotation.value.isTransitioning = true;
  }
}

function resizeMiniGlobe() {
  const canvas = globeMiniCanvasRef.value;
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  if (rect.width > 0 && rect.height > 0) {
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    globeRotation.value.radius = Math.min(rect.width, rect.height) * 0.42 * window.devicePixelRatio;
  }
}

// 5. 探测与事件驱动
async function setupEventListener() {
  if (unlistenHopEvent) return;
  try {
    unlistenHopEvent = await listen<BackendTracerouteHop>('traceroute-hop-event', event => {
      const p = event.payload;
      const hopNum = p.hop_number ?? p.hop ?? 0;
      currentHop.value = hopNum;

      let lon = p.longitude ?? p.geo?.longitude;
      let lat = p.latitude ?? p.geo?.latitude;

      if (p.is_self && p.geo) {
        localHopInfo.value = {
          ip: p.ip,
          lon: p.geo.longitude,
          lat: p.geo.latitude,
          location: p.geo.label || formatGeoLocation(p.country, p.province, p.city, p.is_lan),
          isp: p.isp,
          city: p.city || '本机'
        };
      }

      const existingIdx = liveHops.value.findIndex(h => h.hopNumber === hopNum);
      const hopItem: HopNode = {
        hopNumber: hopNum,
        ip: p.ip,
        rttMs: p.is_timeout || p.rtt_ms === null || p.rtt_ms === undefined ? -1 : p.rtt_ms,
        role: p.lan_role || (p.is_self ? '本地源' : (p.is_lan ? '局域网网关' : '骨干网络跃点')),
        location: formatGeoLocation(p.country, p.province, p.city, p.is_lan),
        isp: p.isp,
        lon,
        lat,
        isSelf: p.is_self,
        isDestination: p.ip === targetIp.value || p.is_destination
      };

      if (existingIdx >= 0) {
        liveHops.value[existingIdx] = hopItem;
      } else {
        liveHops.value.push(hopItem);
      }

      liveHops.value.sort((a, b) => a.hopNumber - b.hopNumber);

      if (p.ip === targetIp.value || p.is_destination) {
        isTracing.value = false;
      }
    });
  } catch {
    // 降级保护
  }
}

async function startLiveTraceroute() {
  const target = targetIp.value;
  if (!target || isTracing.value) return;

  isTracing.value = true;
  liveHops.value = [];
  currentHop.value = 1;
  selectedHopIndex.value = null;

  try {
    await setupEventListener();
    emit('appendLog', `[TRACE] 正在对目标 ${target} 启动逐跳路由追踪探测...`);
    if (typeof (window as any).__TAURI_INTERNALS__ !== 'undefined') {
      await invoke('start_traceroute_cmd', {
        target,
        maxHops: 16,
        timeoutMs: 800
      });
    } else {
      simulateWebTraceroute(target);
    }
  } catch (e: any) {
    emit('appendLog', `[TRACE-ERR] 路由追踪探测异常: ${e}`);
    simulateWebTraceroute(target);
  } finally {
    isTracing.value = false;
  }
}

function simulateWebTraceroute(target: string) {
  const isLan = isPrivateIp(target);
  const startLon = localHopInfo.value.lon;
  const startLat = localHopInfo.value.lat;
  const endLon = targetHopInfo.value.lon;
  const endLat = targetHopInfo.value.lat;

  const hopsMock: HopNode[] = [
    { hopNumber: 0, ip: localHopInfo.value.ip, rttMs: 0.1, role: '本机网络适配器', location: '本地主机', lon: startLon, lat: startLat, isSelf: true },
    { hopNumber: 1, ip: '192.168.1.1', rttMs: 0.8, role: '默认网关 (Gateway)', location: '企业主核心网关', lon: interpolateGreatCirclePoint(startLon, startLat, endLon, endLat, 0.25)[0], lat: interpolateGreatCirclePoint(startLon, startLat, endLon, endLat, 0.25)[1] },
    ...(isLan
      ? [{ hopNumber: 2, ip: target, rttMs: 1.5, role: '目标主机 (Target)', location: '企业子网内网节点', lon: endLon, lat: endLat, isDestination: true }]
      : [
          { hopNumber: 2, ip: '100.64.0.1', rttMs: 5.2, role: '城域网汇聚 (MAN)', location: '运营商汇聚节点', lon: interpolateGreatCirclePoint(startLon, startLat, endLon, endLat, 0.5)[0], lat: interpolateGreatCirclePoint(startLon, startLat, endLon, endLat, 0.5)[1] },
          { hopNumber: 3, ip: '202.97.12.33', rttMs: 18.6, role: '骨干网络出口 (ChinaNet)', location: '国家级骨干网', lon: interpolateGreatCirclePoint(startLon, startLat, endLon, endLat, 0.75)[0], lat: interpolateGreatCirclePoint(startLon, startLat, endLon, endLat, 0.75)[1] },
          { hopNumber: 4, ip: target, rttMs: 28.4, role: '目标主机 (Target)', location: targetHopInfo.value.location, lon: endLon, lat: endLat, isDestination: true }
        ])
  ];
  liveHops.value = hopsMock;
}

function getRttClass(rtt: number): string {
  if (rtt < 0) return 'text-slate-400';
  if (rtt < 2.0) return 'text-emerald-600 dark:text-emerald-400 font-bold';
  if (rtt < 30) return 'text-sky-600 dark:text-cyan-400 font-bold';
  if (rtt < 80) return 'text-blue-600 dark:text-sky-400 font-bold';
  if (rtt < 150) return 'text-amber-600 dark:text-amber-400 font-bold';
  return 'text-rose-600 dark:text-rose-400 font-bold';
}

// 目标 IP 解析监听
watch(
  () => targetIp.value,
  async (newIp) => {
    if (!newIp) return;
    targetHopInfo.value.ip = newIp;
    try {
      if (typeof (window as any).__TAURI_INTERNALS__ !== 'undefined') {
        const geo = await invoke<any>('lookup_ip_geo_coordinates_cmd', { ip: newIp });
        if (geo && geo.longitude && geo.latitude) {
          targetHopInfo.value.lon = geo.longitude;
          targetHopInfo.value.lat = geo.latitude;
          targetHopInfo.value.location = `${geo.country} · ${geo.province} · ${geo.city}`;
          targetHopInfo.value.city = geo.city;
          targetAccuracyLevel.value = geo.accuracy_level || 'city';
          // 自动旋转 3D 地球镜头聚焦中点
          const [midLon, midLat] = interpolateGreatCirclePoint(localHopInfo.value.lon, localHopInfo.value.lat, geo.longitude, geo.latitude, 0.5);
          globeRotation.value.targetLon = midLon;
          globeRotation.value.targetLat = midLat;
          globeRotation.value.isTransitioning = true;
        }
      }
    } catch {
      // 容错
    }
  },
  { immediate: true }
);

onMounted(() => {
  themeObserver = new MutationObserver(() => {
    isDarkTheme.value = !document.documentElement.classList.contains('theme-apple-light');
  });
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

  window.addEventListener('resize', resizeMiniGlobe);
  nextTick(() => {
    resizeMiniGlobe();
    animateMini();
  });
});

onUnmounted(() => {
  if (themeObserver) {
    themeObserver.disconnect();
    themeObserver = null;
  }
  window.removeEventListener('resize', resizeMiniGlobe);
  if (unlistenHopEvent) {
    unlistenHopEvent();
    unlistenHopEvent = null;
  }
  if (animationFrameId) {
    cancelAnimationFrame(animationFrameId);
  }
});
</script>

<style scoped>
@keyframes dash {
  to {
    stroke-dashoffset: -40;
  }
}

.animate-dash {
  animation: dash 2.2s linear infinite;
}

.custom-scrollbar::-webkit-scrollbar {
  width: 4px;
  height: 4px;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(148, 163, 184, 0.25);
  border-radius: 9999px;
}
</style>
