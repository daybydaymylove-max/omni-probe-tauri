<template>
  <div class="w-full h-full relative overflow-hidden flex flex-col" style="background: var(--surface-content);">
    <!-- 1. 顶部控制栏 (浮动导航玻璃层) -->
    <div class="absolute top-2.5 left-2.5 right-2.5 z-10 flex items-center justify-between pointer-events-none gap-2 flex-wrap select-none">
      <!-- 左侧：多层次拓扑布局模式切换分段控件 -->
      <div
        class="backdrop-blur-xl p-1 rounded-xl border shadow-md flex items-center gap-1 pointer-events-auto"
        style="background: var(--surface-glass-nav); border-color: var(--border-strong);"
      >
        <button
          @click="layoutMode = 'tiered'"
          :class="[
            'px-2.5 py-1 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 cursor-pointer',
            layoutMode === 'tiered'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)]'
          ]"
          title="多层次网状拓扑：核心网关 -> 工业控制与服务器 -> 现场终端 -> 外部公网"
        >
          <AppIcon name="layers" :size="13" />
          <span>网状层次</span>
        </button>

        <button
          @click="layoutMode = 'radar'"
          :class="[
            'px-2.5 py-1 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 cursor-pointer',
            layoutMode === 'radar'
              ? 'bg-indigo-600 text-white shadow-xs'
              : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)]'
          ]"
          title="同心圆雷达拓扑：以核心网关为圆心，多圈同心环结构分布"
        >
          <AppIcon name="radar" :size="13" />
          <span>同心雷达</span>
        </button>

        <button
          @click="layoutMode = 'force'"
          :class="[
            'px-2.5 py-1 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 cursor-pointer',
            layoutMode === 'force'
              ? 'bg-emerald-600 text-white shadow-xs'
              : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)]'
          ]"
          title="物理网状力导向拓扑：引力与排斥力动态物理演化"
        >
          <AppIcon name="zap" :size="13" />
          <span>动态力导</span>
        </button>
      </div>

      <!-- 右侧：拓扑指标胶囊与复位 -->
      <div class="flex items-center gap-1.5 pointer-events-auto">
        <div
          class="backdrop-blur-xl px-3 py-1 rounded-xl border shadow-md flex items-center gap-2.5 text-xs ui-num"
          style="background: var(--surface-glass-nav); border-color: var(--border-strong); color: var(--text-secondary);"
        >
          <div>节点: <strong class="font-semibold text-blue-500 dark:text-sky-400">{{ topologySummary.nodeCount }}</strong></div>
          <div class="w-[1px] h-3" style="background: var(--border-strong);"></div>
          <div>链路: <strong class="font-semibold text-emerald-600 dark:text-emerald-400">{{ topologySummary.linkCount }}</strong></div>
          <div class="w-[1px] h-3 hidden sm:block" style="background: var(--border-strong);"></div>
          <div class="hidden sm:block">纵深: <strong class="font-semibold text-amber-600 dark:text-amber-400">{{ topologySummary.tierCount }} 层</strong></div>
        </div>

        <button
          @click="resetZoom"
          class="backdrop-blur-xl px-2.5 py-1 rounded-xl border text-xs font-medium cursor-pointer shadow-md transition-all active:scale-95 flex items-center gap-1 hover:opacity-90"
          style="background: var(--surface-glass-nav); border-color: var(--border-strong); color: var(--text-primary);"
          title="重置视图缩放与居中"
        >
          <AppIcon name="refresh" :size="13" />
          <span>复位</span>
        </button>
      </div>
    </div>

    <!-- 2. 图表渲染主体 -->
    <div class="flex-1 w-full h-full relative">
      <v-chart
        v-if="topologySummary.nodeCount > 0"
        ref="chartRef"
        class="w-full h-full"
        :option="chartOption"
        autoresize
        @click="onChartClick"
      />

      <!-- 空状态待机面板 -->
      <div v-else class="w-full h-full flex items-center justify-center p-6">
        <EmptyState
          icon="radar"
          title="工业网络拓扑雷达待命中"
          description="点击顶部【全网深度扫描】发现局域网物理资产，或启动网卡嗅探捕获实时通信会话，系统将自动构建多层次网状拓扑。"
        />
      </div>
    </div>

    <!-- 3. 悬浮拓扑图例 (浮动玻璃层) -->
    <div
      v-if="topologySummary.nodeCount > 0"
      class="absolute bottom-2.5 left-2.5 backdrop-blur-xl px-3 py-1.5 rounded-xl border shadow-md flex items-center gap-3 text-[11px] font-medium select-none z-10 flex-wrap max-w-[calc(100%-20px)]"
      style="background: var(--surface-glass-nav); border-color: var(--border-strong); color: var(--text-secondary);"
    >
      <div class="flex items-center gap-1.5">
        <span class="w-2 h-2 rounded-full bg-[#6366f1] inline-block"></span>
        <span>Tier 1 核心网关</span>
      </div>
      <div class="flex items-center gap-1.5">
        <span class="w-2 h-2 rounded-full bg-[#0d9488] inline-block"></span>
        <span>Tier 2 控制中心/服务器</span>
      </div>
      <div class="flex items-center gap-1.5">
        <span class="w-2 h-2 rounded-full bg-[#0284c7] inline-block"></span>
        <span>Tier 3 现场终端</span>
      </div>
      <div class="flex items-center gap-1.5">
        <span class="w-2 h-2 rounded-full bg-[#10b981] inline-block"></span>
        <span>Tier 4 外部公网</span>
      </div>
      <div class="flex items-center gap-1.5">
        <span class="w-2 h-2 rounded-full bg-[#e11d48] inline-block"></span>
        <span>高熵/风险</span>
      </div>
    </div>

    <!-- 4. 节点全息情报与拓扑关系卡片 (交互抽屉 - 玻璃层) -->
    <transition name="slide-fade">
      <div
        v-if="selectedNode"
        class="absolute top-14 right-2.5 w-72 sm:w-80 max-w-[calc(100%-20px)] backdrop-blur-2xl rounded-2xl border shadow-2xl p-3.5 text-xs z-20 flex flex-col gap-2.5 max-h-[82%] overflow-auto custom-scrollbar select-text"
        style="background: var(--surface-glass-nav); border-color: var(--border-strong); color: var(--text-primary);"
      >
        <div class="flex items-center justify-between border-b pb-2" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2 min-w-0">
            <span class="w-2.5 h-2.5 rounded-full shrink-0" :style="{ backgroundColor: selectedNode.meta.color }"></span>
            <strong class="text-sm font-semibold text-blue-500 dark:text-sky-400 truncate ui-num" :title="selectedNode.name">
              {{ selectedNode.name }}
            </strong>
          </div>
          <button
            @click="selectedNode = null"
            class="p-1 rounded-lg transition-colors cursor-pointer text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)]"
            title="关闭详情面板"
          >
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="space-y-1.5 text-xs">
          <div class="flex justify-between gap-2">
            <span style="color: var(--text-muted);">拓扑层次:</span>
            <span class="font-medium text-indigo-600 dark:text-indigo-300 text-right">{{ selectedNode.meta.tierName }}</span>
          </div>
          <div class="flex justify-between gap-2">
            <span style="color: var(--text-muted);">设备角色:</span>
            <span class="font-medium text-right">{{ selectedNode.meta.role }}</span>
          </div>
          <div class="flex justify-between gap-2">
            <span style="color: var(--text-muted);">物理 MAC:</span>
            <span class="ui-num font-mono text-right">{{ selectedNode.mac || 'N/A' }}</span>
          </div>
          <div class="flex justify-between gap-2">
            <span style="color: var(--text-muted);">硬件厂商:</span>
            <span class="truncate max-w-[160px] text-right" :title="selectedNode.vendor">{{ selectedNode.vendor || '通用网络设备' }}</span>
          </div>
          <div v-if="selectedNode.zoneName" class="flex justify-between gap-2">
            <span style="color: var(--text-muted);">安全域:</span>
            <span class="text-indigo-600 dark:text-indigo-300 font-medium text-right">{{ selectedNode.zoneName }}</span>
          </div>
          <div v-if="selectedNode.osName" class="flex justify-between gap-2">
            <span style="color: var(--text-muted);">系统指纹:</span>
            <span class="text-emerald-600 dark:text-emerald-300 font-medium text-right">{{ selectedNode.osName }}</span>
          </div>
          <div v-if="selectedNode.hostname" class="flex justify-between gap-2">
            <span style="color: var(--text-muted);">主机名称:</span>
            <span class="text-amber-600 dark:text-amber-300 font-medium text-right">{{ selectedNode.hostname }}</span>
          </div>
          <div v-if="selectedNode.geoSummary" class="flex justify-between gap-2">
            <span style="color: var(--text-muted);">地理归属:</span>
            <span class="text-blue-600 dark:text-sky-300 text-right">{{ selectedNode.geoSummary }}</span>
          </div>
          <div class="flex justify-between gap-2">
            <span style="color: var(--text-muted);">累计吞吐:</span>
            <span class="text-emerald-600 dark:text-emerald-400 font-semibold ui-num text-right">{{ selectedNode.pktCount }} 帧报文</span>
          </div>
        </div>

        <!-- 开放端口 -->
        <div v-if="selectedNode.ports && selectedNode.ports.length > 0" class="border-t pt-2" style="border-color: var(--border-subtle);">
          <span class="text-[11px] font-semibold block mb-1.5" style="color: var(--text-muted);">开放网络服务与端口</span>
          <div class="flex items-center gap-1 flex-wrap">
            <span
              v-for="p in selectedNode.ports"
              :key="p"
              class="px-1.5 py-0.5 rounded bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold ui-num"
            >
              :{{ p }}
            </span>
          </div>
        </div>

        <!-- 关联邻居节点 -->
        <div class="border-t pt-2 flex-1" style="border-color: var(--border-subtle);">
          <span class="text-[11px] font-semibold block mb-1.5" style="color: var(--text-muted);">
            直连拓扑邻居 ({{ selectedNode.neighbors.length }} 个节点)
          </span>
          <div class="space-y-1 max-h-36 overflow-auto custom-scrollbar pr-1">
            <div
              v-for="nbr in selectedNode.neighbors"
              :key="nbr.peer"
              @click="openIpDossier(nbr.peer)"
              class="p-1.5 rounded-lg text-[11px] flex items-center justify-between border cursor-pointer transition-colors group hover:bg-[var(--surface-hover)]"
              style="background: var(--surface-content-alt); border-color: var(--border-subtle);"
              title="点击查阅该邻居 IP 全息档案与溯源"
            >
              <div class="flex items-center gap-1.5 truncate max-w-[175px]">
                <AppIcon
                  name="arrow-right"
                  :size="11"
                  :class="nbr.direction === 'out' ? 'text-emerald-500' : 'text-sky-500 rotate-180'"
                />
                <span class="font-semibold truncate ui-num group-hover:text-blue-500 dark:group-hover:text-sky-400" :title="nbr.peer">{{ nbr.peer }}</span>
              </div>
              <div class="flex items-center gap-1 shrink-0 ui-num" style="color: var(--text-muted);">
                <span class="text-amber-600 dark:text-amber-400 font-semibold">{{ nbr.protocol }}</span>
                <span>({{ nbr.count }})</span>
              </div>
            </div>
            <div v-if="selectedNode.neighbors.length === 0" class="text-[11px] py-2 text-center" style="color: var(--text-muted);">
              暂无通信邻居
            </div>
          </div>
        </div>

        <!-- 查阅全息档案与溯源按钮 -->
        <button
          v-if="selectedNode.id && selectedNode.id !== 'HOST_SYSTEM'"
          @click="openIpDossier(selectedNode.id)"
          class="ui-btn-primary w-full mt-1 py-1.5 px-3 text-xs font-medium justify-center shrink-0"
        >
          <AppIcon name="search" :size="13" />
          <span>查阅 IP 全息档案与溯源</span>
          <AppIcon name="arrow-right" :size="12" />
        </button>
      </div>
    </transition>

    <!-- IP 全息画像与行为溯源控制台 -->
    <IpDossierModal
      :isOpen="dossierVisible"
      :targetIp="selectedDossierIp"
      :packets="packets"
      :assets="assets"
      @close="dossierVisible = false"
      @filterTraffic="$emit('filterTraffic', $event)"
      @drillDown="selectedDossierIp = $event"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount } from 'vue';
import { use } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { GraphChart } from 'echarts/charts';
import { TooltipComponent } from 'echarts/components';
import VChart from 'vue-echarts';
import IpDossierModal from './IpDossierModal.vue';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';

use([CanvasRenderer, GraphChart, TooltipComponent]);

export interface DiscoveredAsset {
  ip: string;
  mac: string;
  role: string;
  scope: string;
  vendor: string;
  first_seen_ts: number;
  last_seen_ts: number;
  packet_count: number;
  protocols: string[];
  ports: number[];
  zone_name?: string;
  geo_summary?: string;
  hostname?: string;
}

const props = defineProps<{
  packets: any[];
  assets?: DiscoveredAsset[];
}>();

const emit = defineEmits(['filterTraffic']);

const chartRef = ref<any>(null);
const layoutMode = ref<'tiered' | 'radar' | 'force'>('tiered');
const selectedNode = ref<any | null>(null);
const dossierVisible = ref(false);
const selectedDossierIp = ref('');

const isDarkTheme = ref(
  typeof document !== 'undefined' ? !document.documentElement.classList.contains('theme-apple-light') : true
);

let themeObserver: MutationObserver | null = null;
onMounted(() => {
  if (typeof document === 'undefined') return;
  const syncTheme = () => {
    isDarkTheme.value = !document.documentElement.classList.contains('theme-apple-light');
  };
  syncTheme();
  themeObserver = new MutationObserver(syncTheme);
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
});

onBeforeUnmount(() => {
  themeObserver?.disconnect();
  themeObserver = null;
});

function openIpDossier(ip: string) {
  if (!ip) return;
  selectedDossierIp.value = ip;
  dossierVisible.value = true;
}

function resetZoom() {
  if (chartRef.value) {
    chartRef.value.dispatchAction({
      type: 'restore',
    });
  }
}

function onChartClick(params: any) {
  if (params.dataType === 'node' && params.data) {
    selectedNode.value = params.data.rawNode;
  } else {
    selectedNode.value = null;
  }
}

interface NodeMeta {
  tier: number;
  tierName: string;
  role: string;
  color: string;
  borderColor: string;
  shadowColor: string;
  baseSize: number;
}

/// 工业级多层拓扑层级分类算法 (Topological Hierarchy Deduction)
function deduceNodeHierarchy(ip: string, asset?: DiscoveredAsset): NodeMeta {
  // 1. 探针宿主主机
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'HOST_SYSTEM' || ip.toLowerCase() === 'localhost') {
    return {
      tier: 0,
      tierName: 'Tier 0 探针宿主',
      role: '探针采集中心 (Host)',
      color: '#f59e0b',
      borderColor: '#fde68a',
      shadowColor: '#d97706',
      baseSize: 44,
    };
  }

  // 2. 广播 / 组播特殊节点
  if (ip === '255.255.255.255' || ip.startsWith('224.') || ip.startsWith('239.') || ip.startsWith('ff0')) {
    return {
      tier: 3,
      tierName: '全网广播域',
      role: '广播/组播端点',
      color: '#fb923c',
      borderColor: '#fed7aa',
      shadowColor: '#ea580c',
      baseSize: 26,
    };
  }

  // 3. Tier 1: 核心网关与主路由器 (IP 结尾 .1 / .254 或角色含 GATEWAY / ROUTER)
  const isGateway = ip.endsWith('.1') || ip.endsWith('.254') ||
    asset?.role.includes('ROUTER') || asset?.role.includes('GATEWAY') || asset?.role.includes('网关') || asset?.role.includes('路由');
  if (isGateway) {
    return {
      tier: 1,
      tierName: 'Tier 1 核心网关/路由',
      role: asset?.role || '核心网关 / 三层交换',
      color: '#6366f1',
      borderColor: '#c7d2fe',
      shadowColor: '#4f46e5',
      baseSize: 46,
    };
  }

  // 4. Tier 2: 控制中心、工业 PLC、关键基础设施与服务器
  // 开放 Modbus 502, SL651 5003, MQTT 1883, HTTP/HTTPS, SSH, SMB 或厂商为工业/网络巨头
  const isServerOrPlc = (asset?.ports && asset.ports.some(p => [502, 5003, 1883, 80, 443, 8080, 22, 53, 3389, 445].includes(p))) ||
    asset?.role.includes('SERVER') || asset?.role.includes('PLC') || asset?.role.includes('RTU') ||
    asset?.role.includes('服务器') || asset?.role.includes('控制') ||
    ['Cisco', 'Huawei', 'H3C', 'Synology'].some(v => (asset?.vendor || '').includes(v));

  if (isServerOrPlc) {
    return {
      tier: 2,
      tierName: 'Tier 2 控制中心/PLC/服务器',
      role: asset?.role || '关键工业控制 / 业务服务器',
      color: '#0d9488',
      borderColor: '#99f6e4',
      shadowColor: '#0f766e',
      baseSize: 38,
    };
  }

  // 5. Tier 3: 局域网内部终端与业务工作站 (RFC 1918 私网)
  const isLanClient = ip.startsWith('192.168.') || ip.startsWith('10.') ||
    (ip.startsWith('172.') && !ip.startsWith('172.0.'));
  if (isLanClient) {
    return {
      tier: 3,
      tierName: 'Tier 3 局域网终端/工作站',
      role: asset?.role || '局域网活跃终端',
      color: '#0284c7',
      borderColor: '#bae6fd',
      shadowColor: '#0369a1',
      baseSize: 32,
    };
  }

  // 6. Tier 4: 外部公网服务与远程端点 (WAN)
  return {
    tier: 4,
    tierName: 'Tier 4 外部公网/云端',
    role: asset?.role || '外部公网业务节点',
    color: '#10b981',
    borderColor: '#a7f3d0',
    shadowColor: '#059669',
    baseSize: 30,
  };
}

/// 拓扑图核心计算引擎
const topologyData = computed(() => {
  const nodesMap = new Map<string, any>();
  const linksMap = new Map<string, any>();
  const assetMap = new Map<string, DiscoveredAsset>();

  // 1. 预先建立已知资产索引
  if (props.assets) {
    for (const a of props.assets) {
      assetMap.set(a.ip, a);
    }
  }

  // 2. 注入所有已知局域网资产节点（确保即使未抓包也有全网资产拓扑骨架）
  for (const [ip, a] of assetMap) {
    const meta = deduceNodeHierarchy(ip, a);
    nodesMap.set(ip, {
      name: ip,
      mac: a.mac,
      vendor: a.vendor,
      role: a.role,
      zoneName: a.zone_name,
      geoSummary: a.geo_summary,
      hostname: a.hostname,
      osName: '',
      ports: a.ports,
      pktCount: a.packet_count,
      meta,
      hasThreat: false,
      neighbors: [] as Array<{ peer: string; direction: 'in' | 'out'; protocol: string; count: number }>,
    });
  }

  // 3. 从数据包沉淀动态通信链路与未在资产库的公网/外部节点
  const recentPackets = props.packets.slice(-2000);
  for (const p of recentPackets) {
    if (!p.src_ip || !p.dst_ip) continue;

    // 源节点
    if (!nodesMap.has(p.src_ip)) {
      const a = assetMap.get(p.src_ip);
      const meta = deduceNodeHierarchy(p.src_ip, a);
      nodesMap.set(p.src_ip, {
        name: p.src_ip,
        mac: a?.mac || p.mac_src || 'N/A',
        vendor: a?.vendor || '外部网络端点',
        role: meta.role,
        zoneName: a?.zone_name,
        geoSummary: a?.geo_summary,
        hostname: a?.hostname,
        osName: '',
        ports: a?.ports || [],
        pktCount: 0,
        meta,
        hasThreat: p.entropy_level === 'critical' || p.entropy_level === 'suspicious',
        neighbors: [],
      });
    }

    // 宿节点
    if (!nodesMap.has(p.dst_ip)) {
      const a = assetMap.get(p.dst_ip);
      const meta = deduceNodeHierarchy(p.dst_ip, a);
      nodesMap.set(p.dst_ip, {
        name: p.dst_ip,
        mac: a?.mac || p.mac_dst || 'N/A',
        vendor: a?.vendor || '外部网络端点',
        role: meta.role,
        zoneName: a?.zone_name,
        geoSummary: a?.geo_summary,
        hostname: a?.hostname,
        osName: '',
        ports: a?.ports || [],
        pktCount: 0,
        meta,
        hasThreat: false,
        neighbors: [],
      });
    }

    // 动态提取并推导源节点 OS 指纹
    if (p.business_data && typeof p.business_data.ttl === 'number' && p.business_data.ttl > 0) {
      const node = nodesMap.get(p.src_ip);
      if (node && !node.osName) {
        const ttl = p.business_data.ttl;
        if (ttl <= 64) node.osName = 'Linux/RTOS';
        else if (ttl <= 128) node.osName = 'Windows';
        else node.osName = '网络设备/路由';
      }
    }

    const srcNode = nodesMap.get(p.src_ip);
    const dstNode = nodesMap.get(p.dst_ip);
    srcNode.pktCount++;
    dstNode.pktCount++;

    if (p.entropy_level === 'critical' || p.entropy_level === 'suspicious') {
      srcNode.hasThreat = true;
    }

    // 聚合通信链路
    const linkKey = `${p.src_ip}->${p.dst_ip}`;
    if (!linksMap.has(linkKey)) {
      linksMap.set(linkKey, {
        source: p.src_ip,
        target: p.dst_ip,
        count: 1,
        protocol: p.protocol || 'TCP',
        hasThreat: p.entropy_level === 'critical' || p.entropy_level === 'suspicious',
      });
    } else {
      const l = linksMap.get(linkKey);
      l.count++;
      if (p.entropy_level === 'critical' || p.entropy_level === 'suspicious') {
        l.hasThreat = true;
      }
    }
  }

  // 4. 为每个节点组装邻居列表
  for (const l of linksMap.values()) {
    const srcNode = nodesMap.get(l.source);
    const dstNode = nodesMap.get(l.target);
    if (srcNode) {
      srcNode.neighbors.push({ peer: l.target, direction: 'out', protocol: l.protocol, count: l.count });
    }
    if (dstNode) {
      dstNode.neighbors.push({ peer: l.source, direction: 'in', protocol: l.protocol, count: l.count });
    }
  }

  // 5. 若局域网终端尚无链路，自动建立到同网段核心网关的基础设施拓扑归属链路
  const gatewayNode = Array.from(nodesMap.values()).find(n => n.meta.tier === 1);
  if (gatewayNode) {
    for (const node of nodesMap.values()) {
      if (node.meta.tier === 3 && node.neighbors.length === 0) {
        const infLinkKey = `${node.name}->${gatewayNode.name}`;
        if (!linksMap.has(infLinkKey)) {
          linksMap.set(infLinkKey, {
            source: node.name,
            target: gatewayNode.name,
            count: 1,
            protocol: 'ARP_TOPO',
            isInfrastructure: true,
            hasThreat: false,
          });
        }
      }
    }
  }

  return {
    nodes: Array.from(nodesMap.values()),
    links: Array.from(linksMap.values()),
  };
});

const topologySummary = computed(() => {
  const nodes = topologyData.value.nodes;
  const tiers = new Set(nodes.map(n => n.meta.tier));
  return {
    nodeCount: nodes.length,
    linkCount: topologyData.value.links.length,
    tierCount: tiers.size,
  };
});

/// 坐标生成与图表配置构建 (大 O 复杂度: O(N + L))
const chartOption = computed(() => {
  const { nodes, links } = topologyData.value;
  const mode = layoutMode.value;
  const isDark = isDarkTheme.value;

  const labelColor = isDark ? '#f1f5f9' : '#0f172a';
  const labelBg = isDark ? 'rgba(12, 18, 30, 0.9)' : 'rgba(255, 255, 255, 0.94)';
  const labelBorder = isDark ? 'rgba(255, 255, 255, 0.16)' : 'rgba(15, 23, 42, 0.14)';
  const tooltipBg = isDark ? 'rgba(15, 23, 42, 0.95)' : 'rgba(255, 255, 255, 0.96)';
  const tooltipBorder = isDark ? '#334155' : '#cbd5e1';
  const tooltipTextColor = isDark ? '#f1f5f9' : '#0f172a';
  const tooltipTitleColor = isDark ? '#38bdf8' : '#0284c7';
  const tooltipMutedColor = isDark ? '#94a3b8' : '#64748b';
  const infraLineColor = isDark ? '#475569' : '#94a3b8';
  const activeLineColor = isDark ? '#38bdf8' : '#0284c7';

  // 虚拟画布基准尺寸
  const canvasW = 900;
  const canvasH = 650;

  // 按层次分组
  const tierGroups: Record<number, any[]> = { 0: [], 1: [], 2: [], 3: [], 4: [] };
  for (const n of nodes) {
    const t = n.meta.tier;
    if (!tierGroups[t]) tierGroups[t] = [];
    tierGroups[t].push(n);
  }

  // 节点呈现数据准备
  const graphNodes = nodes.map(n => {
    let x: number | undefined;
    let y: number | undefined;

    if (mode === 'tiered') {
      // 模式 1: 多层次网状坐标计算
      if (n.meta.tier === 0) {
        // 探针宿主：顶部偏左
        x = canvasW * 0.2;
        y = 70;
      } else if (n.meta.tier === 1) {
        // 核心网关：顶部居中
        const list = tierGroups[1];
        const idx = list.indexOf(n);
        x = canvasW * (0.4 + 0.2 * (idx / Math.max(list.length, 1)));
        y = 70;
      } else if (n.meta.tier === 2) {
        // 控制中心 / 服务器：次高层等间距
        const list = tierGroups[2];
        const idx = list.indexOf(n);
        const count = Math.max(list.length, 1);
        x = canvasW * 0.15 + (canvasW * 0.7) * ((idx + 0.5) / count);
        y = 220;
      } else if (n.meta.tier === 3) {
        // 局域网终端：下层展开 (支持多行)
        const list = tierGroups[3];
        const idx = list.indexOf(n);
        const row = Math.floor(idx / 6);
        const col = idx % 6;
        const rowCount = Math.min(list.length - row * 6, 6);
        x = canvasW * 0.1 + (canvasW * 0.8) * ((col + 0.5) / Math.max(rowCount, 1));
        y = 370 + row * 90;
      } else {
        // 外部公网：右侧或底部
        const list = tierGroups[4];
        const idx = list.indexOf(n);
        const count = Math.max(list.length, 1);
        x = canvasW * 0.15 + (canvasW * 0.7) * ((idx + 0.5) / count);
        y = 560;
      }
    } else if (mode === 'radar') {
      // 模式 2: 同心圆雷达极坐标计算
      const cx = canvasW / 2;
      const cy = canvasH / 2;

      if (n.meta.tier === 0 || n.meta.tier === 1) {
        // 圆心
        const list = [...(tierGroups[0] || []), ...(tierGroups[1] || [])];
        const idx = list.indexOf(n);
        const angle = (2 * Math.PI * idx) / Math.max(list.length, 1);
        x = cx + 35 * Math.cos(angle);
        y = cy + 35 * Math.sin(angle);
      } else if (n.meta.tier === 2) {
        // 第一环 (R = 130)
        const list = tierGroups[2];
        const idx = list.indexOf(n);
        const angle = (2 * Math.PI * idx) / Math.max(list.length, 1);
        x = cx + 135 * Math.cos(angle);
        y = cy + 135 * Math.sin(angle);
      } else if (n.meta.tier === 3) {
        // 第二环 (R = 240)
        const list = tierGroups[3];
        const idx = list.indexOf(n);
        const angle = (2 * Math.PI * idx) / Math.max(list.length, 1) + 0.2;
        x = cx + 245 * Math.cos(angle);
        y = cy + 245 * Math.sin(angle);
      } else {
        // 第三环 (R = 340)
        const list = tierGroups[4];
        const idx = list.indexOf(n);
        const angle = (2 * Math.PI * idx) / Math.max(list.length, 1) + 0.4;
        x = cx + 345 * Math.cos(angle);
        y = cy + 345 * Math.sin(angle);
      }
    }

    // 节点尺寸计算 (baseSize ~ +16px)
    const extraSize = Math.min(Math.log2(n.pktCount + 1) * 2.5, 16);
    const size = (n.hasThreat ? 44 : n.meta.baseSize) + extraSize;

    const color = n.hasThreat ? '#e11d48' : n.meta.color;
    const borderColor = n.hasThreat ? '#fecdd3' : n.meta.borderColor;
    const shadowColor = n.hasThreat ? '#be123c' : n.meta.shadowColor;

    return {
      name: n.name,
      value: n.pktCount,
      role: n.meta.role,
      tierName: n.meta.tierName,
      symbolSize: size,
      x,
      y,
      fixed: mode !== 'force',
      itemStyle: {
        color,
        borderColor,
        borderWidth: 2,
        shadowBlur: n.hasThreat ? 25 : 12,
        shadowColor,
      },
      label: {
        show: true,
        position: 'bottom',
        distance: 6,
        color: labelColor,
        fontSize: 11,
        fontWeight: 'bold',
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
        backgroundColor: labelBg,
        borderColor: labelBorder,
        borderWidth: 1,
        borderRadius: 4,
        padding: [2, 6],
      },
      rawNode: n,
    };
  });

  // 链路呈现转换
  const graphLinks = links.map(l => {
    const isThreat = l.hasThreat;
    const isInfra = l.isInfrastructure;
    const width = isInfra ? 1 : Math.min(1.5 + Math.log2(l.count + 1) * 0.8, 5);

    return {
      source: l.source,
      target: l.target,
      value: l.count,
      protocol: l.protocol,
      lineStyle: {
        color: isThreat ? '#f43f5e' : (isInfra ? infraLineColor : activeLineColor),
        type: isInfra ? 'dashed' : 'solid',
        opacity: isInfra ? 0.45 : 0.78,
        width,
        curveness: 0.15,
      },
    };
  });

  return {
    tooltip: {
      trigger: 'item',
      backgroundColor: tooltipBg,
      borderColor: tooltipBorder,
      borderWidth: 1,
      textStyle: { color: tooltipTextColor, fontSize: 12 },
      formatter: (params: any) => {
        if (params.dataType === 'node') {
          const raw = params.data.rawNode;
          const threatTag = raw.hasThreat ? '<span style="color: #e11d48; font-weight: bold;">[高熵风险]</span>' : '';
          return `
            <div style="font-family: ui-monospace, SFMono-Regular, monospace; padding: 2px;">
              <div style="font-weight: bold; color: ${tooltipTitleColor}; margin-bottom: 3px;">${raw.name} ${threatTag}</div>
              <div>层级: <span>${raw.meta.tierName}</span></div>
              <div>角色: <span>${raw.meta.role}</span></div>
              <div>MAC: <span style="color: ${tooltipMutedColor};">${raw.mac || 'N/A'}</span></div>
              <div>厂商: <span style="color: ${tooltipMutedColor};">${raw.vendor || '通用设备'}</span></div>
              <div>吞吐: <span style="color: #10b981; font-weight: bold;">${raw.pktCount} 帧报文</span></div>
              ${raw.ports && raw.ports.length > 0 ? `<div>端口: <span style="color: #f59e0b;">:${raw.ports.join(', :')}</span></div>` : ''}
            </div>
          `;
        } else if (params.dataType === 'edge') {
          const d = params.data;
          return `
            <div style="font-family: ui-monospace, SFMono-Regular, monospace; padding: 2px;">
              <div style="font-weight: bold; margin-bottom: 2px;">${d.lineStyle?.type === 'dashed' ? '基础设施拓扑关联' : '实时通信数据流'}</div>
              <div>${d.source} → ${d.target}</div>
              <div>通信频次: <span style="color: ${tooltipTitleColor}; font-weight: bold;">${d.value} 次</span></div>
              <div>应用规约: <span style="color: #f59e0b;">${d.protocol}</span></div>
            </div>
          `;
        }
        return '';
      },
    },
    series: [
      {
        type: 'graph',
        layout: mode === 'force' ? 'force' : 'none',
        force: mode === 'force' ? {
          repulsion: 360,
          edgeLength: [90, 200],
          gravity: 0.08,
          friction: 0.6,
        } : undefined,
        roam: true,
        draggable: true,
        edgeSymbol: ['none', 'arrow'],
        edgeSymbolSize: 6,
        data: graphNodes,
        links: graphLinks,
        emphasis: {
          focus: 'adjacency',
          lineStyle: { width: 5, color: activeLineColor },
        },
      },
    ],
  };
});
</script>

<style scoped>
.echarts {
  width: 100%;
  height: 100%;
}

.slide-fade-enter-active,
.slide-fade-leave-active {
  transition: all 0.25s ease-out;
}

.slide-fade-enter-from,
.slide-fade-leave-to {
  transform: translateX(20px);
  opacity: 0;
}
</style>
