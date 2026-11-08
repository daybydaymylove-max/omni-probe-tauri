<template>
  <div class="w-full h-full relative overflow-hidden flex flex-col select-none">
    <!-- 1. 顶部控制栏 (布局模式切换与拓扑情报胶囊) -->
    <div class="absolute top-2.5 left-2.5 right-2.5 z-10 flex items-center justify-between pointer-events-none gap-2 flex-wrap">
      <!-- 左侧：多层次拓扑布局模式切换分段控件 -->
      <div class="bg-slate-900/90 backdrop-blur-xl p-1 rounded-xl border border-white/20 shadow-xl flex items-center gap-1 pointer-events-auto">
        <button
          @click="layoutMode = 'tiered'"
          :class="[
            'px-2.5 py-1 rounded-lg text-xs font-semibold transition-all flex items-center gap-1 cursor-pointer',
            layoutMode === 'tiered'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-300 hover:text-white hover:bg-white/10'
          ]"
          title="多层次网状拓扑：核心网关 ➔ 工业控制与服务器 ➔ 现场终端 ➔ 外部公网"
        >
          <span>📐 网状层次</span>
        </button>

        <button
          @click="layoutMode = 'radar'"
          :class="[
            'px-2.5 py-1 rounded-lg text-xs font-semibold transition-all flex items-center gap-1 cursor-pointer',
            layoutMode === 'radar'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-300 hover:text-white hover:bg-white/10'
          ]"
          title="同心圆雷达拓扑：以核心网关为圆心，多圈同心环态势感知分布"
        >
          <span>🎯 同心雷达</span>
        </button>

        <button
          @click="layoutMode = 'force'"
          :class="[
            'px-2.5 py-1 rounded-lg text-xs font-semibold transition-all flex items-center gap-1 cursor-pointer',
            layoutMode === 'force'
              ? 'bg-emerald-600 text-white shadow-sm'
              : 'text-slate-300 hover:text-white hover:bg-white/10'
          ]"
          title="物理网状力导向拓扑：引力与排斥力动态物理演化"
        >
          <span>⚡ 动态力导</span>
        </button>
      </div>

      <!-- 右侧：拓扑指标胶囊与节点检索 -->
      <div class="flex items-center gap-1.5 pointer-events-auto">
        <div class="bg-slate-900/90 backdrop-blur-xl px-2.5 py-1 rounded-xl border border-white/20 shadow-xl flex items-center gap-2 text-xs font-mono text-slate-300">
          <div>节点: <strong class="text-sky-400 font-bold">{{ topologySummary.nodeCount }}</strong></div>
          <div class="w-[1px] h-3 bg-slate-700"></div>
          <div>链路: <strong class="text-emerald-400 font-bold">{{ topologySummary.linkCount }}</strong></div>
          <div class="w-[1px] h-3 bg-slate-700 hidden sm:block"></div>
          <div class="hidden sm:block">纵深: <strong class="text-amber-400 font-bold">{{ topologySummary.tierCount }}层</strong></div>
        </div>

        <button
          @click="resetZoom"
          class="bg-slate-900/90 hover:bg-slate-800 backdrop-blur-xl text-slate-300 hover:text-white px-2.5 py-1 rounded-xl border border-white/20 text-xs font-semibold cursor-pointer shadow transition-all active:scale-95"
          title="重置视图缩放与居中"
        >
          ⟲ 复位
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

      <!-- 空状态雷达待机动效看板 -->
      <div
        v-else
        class="w-full h-full flex flex-col items-center justify-center text-slate-400 p-6 select-none bg-slate-950"
      >
        <div class="relative w-28 h-28 mb-4 flex items-center justify-center">
          <div class="absolute inset-0 rounded-full border border-blue-500/30 animate-ping opacity-30"></div>
          <div class="absolute inset-3 rounded-full border border-dashed border-indigo-400/40 animate-spin opacity-50" style="animation-duration: 12s;"></div>
          <div class="absolute inset-6 rounded-full border border-blue-400/20"></div>
          <div class="w-12 h-12 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center text-xl shadow-inner">
            📡
          </div>
        </div>
        <p class="text-sm font-bold text-slate-200">工业网络拓扑雷达待命中</p>
        <p class="text-xs text-slate-500 mt-1 max-w-sm text-center leading-relaxed">
          点击左侧【全网深度扫描】发现局域网物理资产，或点击【启动网卡嗅探】捕获实时通信会话，系统将自动构建多层次网状拓扑
        </p>
      </div>
    </div>

    <!-- 3. 悬浮拓扑图例 (分层体系与规约标识) -->
    <div
      v-if="topologySummary.nodeCount > 0"
      class="absolute bottom-2.5 left-2.5 bg-slate-900/85 backdrop-blur-xl px-3 py-1.5 rounded-xl border border-white/20 shadow-xl flex items-center gap-2.5 text-[10px] font-medium text-slate-300 select-none z-10 flex-wrap max-w-[calc(100%-20px)]"
    >
      <div class="flex items-center gap-1">
        <span class="w-2 h-2 rounded-full bg-[#6366f1] ring-2 ring-indigo-300/40 inline-block shadow-xs"></span>
        <span>Tier 1 核心网关</span>
      </div>
      <div class="flex items-center gap-1">
        <span class="w-2 h-2 rounded-full bg-[#0d9488] ring-2 ring-teal-300/40 inline-block shadow-xs"></span>
        <span>Tier 2 控制中心/服务器</span>
      </div>
      <div class="flex items-center gap-1">
        <span class="w-2 h-2 rounded-full bg-[#0284c7] ring-2 ring-sky-300/40 inline-block shadow-xs"></span>
        <span>Tier 3 现场终端</span>
      </div>
      <div class="flex items-center gap-1">
        <span class="w-2 h-2 rounded-full bg-[#10b981] ring-2 ring-emerald-300/40 inline-block shadow-xs"></span>
        <span>Tier 4 外部公网</span>
      </div>
      <div class="flex items-center gap-1">
        <span class="w-2 h-2 rounded-full bg-[#e11d48] animate-pulse inline-block shadow-xs"></span>
        <span>高熵/风险</span>
      </div>
    </div>

    <!-- 4. 节点全息情报与拓扑关系卡片 (交互抽屉) -->
    <transition name="slide-fade">
      <div
        v-if="selectedNode"
        class="absolute top-14 right-2.5 w-72 sm:w-80 max-w-[calc(100%-20px)] bg-slate-900/95 backdrop-blur-2xl rounded-2xl border border-white/25 shadow-2xl p-3.5 text-xs font-mono text-slate-200 z-20 flex flex-col gap-2.5 max-h-[80%] overflow-auto custom-scrollbar"
      >
        <div class="flex items-center justify-between border-b border-slate-700/80 pb-2">
          <div class="flex items-center gap-2">
            <span class="w-3 h-3 rounded-full" :style="{ backgroundColor: selectedNode.meta.color }"></span>
            <strong class="text-sm font-bold text-sky-400 truncate max-w-[190px]" :title="selectedNode.name">
              {{ selectedNode.name }}
            </strong>
          </div>
          <button @click="selectedNode = null" class="text-slate-400 hover:text-white cursor-pointer text-sm">
            ✕
          </button>
        </div>

        <div class="space-y-1.5 text-[11px]">
          <div class="flex justify-between">
            <span class="text-slate-400">拓扑层次:</span>
            <span class="font-bold text-indigo-300">{{ selectedNode.meta.tierName }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">设备角色:</span>
            <span class="text-slate-100 font-semibold">{{ selectedNode.meta.role }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">物理 MAC:</span>
            <span class="text-slate-300">{{ selectedNode.mac || 'N/A' }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">硬件厂商:</span>
            <span class="text-slate-300 truncate max-w-[150px]" :title="selectedNode.vendor">{{ selectedNode.vendor || '通用网络设备' }}</span>
          </div>
          <div v-if="selectedNode.zoneName" class="flex justify-between">
            <span class="text-slate-400">安全域:</span>
            <span class="text-indigo-400 font-bold">{{ selectedNode.zoneName }}</span>
          </div>
          <div v-if="selectedNode.osName" class="flex justify-between">
            <span class="text-slate-400">系统指纹:</span>
            <span class="text-emerald-300 font-semibold">{{ selectedNode.osName }}</span>
          </div>
          <div v-if="selectedNode.hostname" class="flex justify-between">
            <span class="text-slate-400">主机名称:</span>
            <span class="text-amber-300 font-semibold">{{ selectedNode.hostname }}</span>
          </div>
          <div v-if="selectedNode.geoSummary" class="flex justify-between">
            <span class="text-slate-400">地理归属:</span>
            <span class="text-sky-300">{{ selectedNode.geoSummary }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">累计吞吐:</span>
            <span class="text-emerald-400 font-bold">{{ selectedNode.pktCount }} 帧报文</span>
          </div>
        </div>

        <!-- 开放端口 -->
        <div v-if="selectedNode.ports && selectedNode.ports.length > 0" class="border-t border-slate-800 pt-2">
          <span class="text-[10px] text-slate-400 uppercase font-bold block mb-1">开放网络服务与端口</span>
          <div class="flex items-center gap-1 flex-wrap">
            <span
              v-for="p in selectedNode.ports"
              :key="p"
              class="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[10px] font-bold"
            >
              :{{ p }}
            </span>
          </div>
        </div>

        <!-- 关联邻居节点 -->
        <div class="border-t border-slate-800 pt-2 flex-1">
          <span class="text-[10px] text-slate-400 uppercase font-bold block mb-1">
            直连拓扑邻居 ({{ selectedNode.neighbors.length }} 个节点)
          </span>
          <div class="space-y-1 max-h-36 overflow-auto custom-scrollbar pr-1">
            <div
              v-for="nbr in selectedNode.neighbors"
              :key="nbr.peer"
              @click="openIpDossier(nbr.peer)"
              class="bg-slate-800/80 hover:bg-slate-700/80 p-1.5 rounded-lg text-[10px] flex items-center justify-between border border-slate-700/60 cursor-pointer transition-colors group"
              title="点击查阅该邻居 IP 全息档案与溯源"
            >
              <div class="flex items-center gap-1 truncate max-w-[180px]">
                <span :class="nbr.direction === 'out' ? 'text-emerald-400' : 'text-sky-400'">
                  {{ nbr.direction === 'out' ? '➔' : '⬅' }}
                </span>
                <span class="font-bold truncate text-slate-200 group-hover:text-blue-300" :title="nbr.peer">{{ nbr.peer }}</span>
              </div>
              <div class="text-slate-400 flex items-center gap-1 shrink-0">
                <span class="text-amber-400 font-semibold">{{ nbr.protocol }}</span>
                <span>({{ nbr.count }}次)</span>
              </div>
            </div>
            <div v-if="selectedNode.neighbors.length === 0" class="text-slate-500 text-[10px] py-1 text-center">
              暂无通信邻居
            </div>
          </div>
        </div>

        <!-- 查阅全息档案与溯源按钮 -->
        <button
          v-if="selectedNode.id && selectedNode.id !== 'HOST_SYSTEM'"
          @click="openIpDossier(selectedNode.id)"
          class="w-full mt-2 py-1.5 px-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-xl text-xs font-semibold shadow-md flex items-center justify-center gap-1.5 cursor-pointer transition-all active:scale-95 shrink-0"
        >
          <span>🔍 查阅 IP 全息档案与溯源</span>
          <span class="text-[10px] opacity-75">↗</span>
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
import { ref, computed } from 'vue';
import { use } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { GraphChart } from 'echarts/charts';
import { TooltipComponent } from 'echarts/components';
import VChart from 'vue-echarts';
import IpDossierModal from './IpDossierModal.vue';

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
        color: '#f8fafc',
        fontSize: 10,
        fontWeight: 'bold',
        fontFamily: 'monospace',
        backgroundColor: 'rgba(15, 23, 42, 0.85)',
        borderColor: 'rgba(255, 255, 255, 0.2)',
        borderWidth: 1,
        borderRadius: 4,
        padding: [2, 5],
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
        color: isThreat ? '#f43f5e' : (isInfra ? '#475569' : '#38bdf8'),
        type: isInfra ? 'dashed' : 'solid',
        opacity: isInfra ? 0.4 : 0.75,
        width,
        curveness: 0.15,
      },
    };
  });

  return {
    tooltip: {
      trigger: 'item',
      backgroundColor: 'rgba(15, 23, 42, 0.94)',
      borderColor: '#334155',
      borderWidth: 1,
      textStyle: { color: '#f8fafc', fontSize: 11 },
      formatter: (params: any) => {
        if (params.dataType === 'node') {
          const raw = params.data.rawNode;
          const threatTag = raw.hasThreat ? '<span style="color: #f43f5e; font-weight: bold;">[高熵风险]</span>' : '';
          return `
            <div style="font-family: monospace; padding: 2px;">
              <div style="font-weight: bold; color: #38bdf8; margin-bottom: 2px;">${raw.name} ${threatTag}</div>
              <div>层级: <span style="color: #c7d2fe;">${raw.meta.tierName}</span></div>
              <div>角色: <span style="color: #cbd5e1;">${raw.meta.role}</span></div>
              <div>MAC: <span style="color: #94a3b8;">${raw.mac || 'N/A'}</span></div>
              <div>厂商: <span style="color: #94a3b8;">${raw.vendor || '通用设备'}</span></div>
              <div>吞吐: <span style="color: #4ade80; font-weight: bold;">${raw.pktCount} 帧报文</span></div>
              ${raw.ports && raw.ports.length > 0 ? `<div>端口: <span style="color: #facc15;">:${raw.ports.join(', :')}</span></div>` : ''}
            </div>
          `;
        } else if (params.dataType === 'edge') {
          const d = params.data;
          return `
            <div style="font-family: monospace; padding: 2px;">
              <div style="font-weight: bold; color: #e2e8f0;">${d.lineStyle?.type === 'dashed' ? '基础设施拓扑关联' : '实时通信数据流'}</div>
              <div>${d.source} ➔ ${d.target}</div>
              <div>通信频次: <span style="color: #38bdf8; font-weight: bold;">${d.value} 次</span></div>
              <div>应用规约: <span style="color: #facc15;">${d.protocol}</span></div>
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
          lineStyle: { width: 5, color: '#38bdf8' },
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
