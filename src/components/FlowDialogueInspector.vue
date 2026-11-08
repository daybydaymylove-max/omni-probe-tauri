<template>
  <div class="flex-1 flex flex-col gap-3 overflow-hidden">
    <!-- 顶部会话链路与通信节点配置面板 -->
    <div class="bg-white/90 rounded-2xl border border-white/80 shadow p-4 shrink-0 flex flex-col gap-3">
      <div class="flex items-center justify-between border-b border-slate-100 pb-2.5">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-blue-600 text-white flex items-center justify-center font-bold text-sm shadow-xs">
            🔄
          </div>
          <div>
            <h2 class="text-sm font-bold text-slate-800 flex items-center gap-1.5">
              <span>双向会话流与节点交互观测器 (Bidirectional Session Flow Inspector)</span>
            </h2>
            <p class="text-[10px] text-slate-400 mt-0.5">
              精准追踪发起端设备向目标端设备发送的业务报文，以及目标端反馈的应答与真实时序往返
            </p>
          </div>
        </div>

        <!-- 右侧指标与控制开关 -->
        <div class="flex items-center gap-2">
          <button @click="autoScroll = !autoScroll"
            :class="['text-xs px-2.5 py-1.5 rounded-lg border transition-all font-medium flex items-center gap-1',
              autoScroll ? 'bg-blue-50 text-blue-700 border-blue-200' : 'bg-slate-50 text-slate-500 border-slate-200']">
            <span>{{ autoScroll ? '⚡ 自动跟踪最新' : '⏸ 暂停自动滚屏' }}</span>
          </button>
        </div>
      </div>

      <!-- 通信节点配置与会话链路选择 -->
      <div class="grid grid-cols-[1fr_1fr_260px] gap-3 items-end">
        <!-- 发起端设备 (Client / Source) -->
        <div class="flex flex-col gap-1">
          <div class="flex items-center justify-between">
            <label class="text-[10px] font-bold text-blue-700 uppercase flex items-center gap-1">
              <span>🔵 发起端设备 (Client / Source)</span>
            </label>
            <span class="text-[9px] text-slate-400">支持多 IP 逗号分隔，留空匹配所有通信源</span>
          </div>
          <div class="relative">
            <input v-model="sourceInitiatorIp" placeholder="如: 192.168.1.10, 192.168.1.20 (逗号分隔)"
              class="w-full bg-blue-50/40 border border-blue-200 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-800 focus:outline-none focus:border-blue-400">
            <button v-if="sourceInitiatorIp" @click="sourceInitiatorIp = ''" class="absolute right-2 top-1.5 text-slate-400 hover:text-slate-600 text-xs">✕</button>
          </div>
        </div>

        <!-- 目标端设备 (Server / Target) -->
        <div class="flex flex-col gap-1">
          <div class="flex items-center justify-between">
            <label class="text-[10px] font-bold text-indigo-700 uppercase flex items-center gap-1">
              <span>🟣 目标端设备 (Server / Target)</span>
            </label>
            <span class="text-[9px] text-slate-400">支持 IP 或端口 (如: 192.168.1.100 或 8080)</span>
          </div>
          <div class="relative">
            <input v-model="targetCenterIp" placeholder="如: 192.168.1.100 或 8080 (IP 或端口)"
              class="w-full bg-indigo-50/40 border border-indigo-200 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-800 focus:outline-none focus:border-indigo-400">
            <button v-if="targetCenterIp" @click="targetCenterIp = ''" class="absolute right-2 top-1.5 text-slate-400 hover:text-slate-600 text-xs">✕</button>
          </div>
        </div>

        <!-- 自动提取的活跃会话链路对下拉列表 -->
        <div class="flex flex-col gap-1">
          <label class="text-[10px] font-bold text-slate-500 uppercase flex items-center gap-1">
            <span>⚡ 活跃会话链路对 (Active Session Pairs)</span>
          </label>
          <select @change="onSelectActiveFlow($event)" class="w-full bg-slate-50 border border-slate-200 rounded-lg px-2 py-1.5 text-xs font-mono text-slate-700 focus:outline-none">
            <option value="">-- 选择识别到的双向会话对 --</option>
            <option v-for="pair in activeFlowPairs" :key="pair.key" :value="pair.key">
              {{ pair.label }} ({{ pair.count }} 帧)
            </option>
          </select>
        </div>
      </div>

      <!-- 快速标签：一键添加已感知资产 -->
      <div v-if="assets && assets.length > 0" class="flex items-center gap-1.5 flex-wrap pt-1 border-t border-slate-100/60">
        <span class="text-[10px] text-slate-400 font-medium">快速加入发起端设备:</span>
        <button v-for="ast in assets.slice(0, 8)" :key="ast.ip"
          @click="addAssetToSource(ast.ip)"
          class="text-[10px] font-mono px-2 py-0.5 rounded-md bg-slate-100 hover:bg-blue-100 text-slate-600 hover:text-blue-700 border border-slate-200 transition-colors">
          + {{ ast.ip }}
        </button>
      </div>

      <!-- 统计指标条 -->
      <div class="grid grid-cols-4 gap-2 pt-1 border-t border-slate-100/60 text-xs font-mono">
        <div class="bg-blue-50/50 border border-blue-100 rounded-lg p-2 flex justify-between items-center">
          <span class="text-[10px] text-blue-600 font-bold uppercase">发起端 ➔ 目标端 发送</span>
          <span class="font-extrabold text-blue-900">{{ forwardCount }} 帧 ({{ formatBytes(forwardBytes) }})</span>
        </div>
        <div class="bg-indigo-50/50 border border-indigo-100 rounded-lg p-2 flex justify-between items-center">
          <span class="text-[10px] text-indigo-600 font-bold uppercase">目标端 ➔ 发起端 反馈</span>
          <span class="font-extrabold text-indigo-900">{{ reverseCount }} 帧 ({{ formatBytes(reverseBytes) }})</span>
        </div>
        <div class="bg-emerald-50/50 border border-emerald-100 rounded-lg p-2 flex justify-between items-center">
          <span class="text-[10px] text-emerald-600 font-bold uppercase">双向交互闭环率</span>
          <span class="font-extrabold text-emerald-800">{{ completionRate }}%</span>
        </div>
        <div class="bg-amber-50/50 border border-amber-100 rounded-lg p-2 flex justify-between items-center">
          <span class="text-[10px] text-amber-700 font-bold uppercase">平均响应时延</span>
          <span class="font-extrabold text-amber-900">{{ avgLatencyMs > 0 ? avgLatencyMs.toFixed(1) + ' ms' : '-' }}</span>
        </div>
      </div>
    </div>

    <!-- 主体：左侧双向时序对话流 + 右侧当前选中报文深度看板 -->
    <div class="flex-1 flex gap-3 overflow-hidden min-h-0">
      <!-- 左侧：双向对话流时序区 (Dialogue Stream) -->
      <div class="flex-1 bg-white/90 rounded-2xl border border-white/80 shadow flex flex-col overflow-hidden">
        <div class="px-4 py-2.5 border-b border-slate-100 bg-slate-50/80 flex items-center justify-between shrink-0">
          <div class="flex items-center gap-2">
            <span class="text-xs font-bold text-slate-700">双向通信往返时序流 (Bidirectional Stream)</span>
            <span class="text-[10px] font-mono px-2 py-0.2 rounded-full bg-blue-100 text-blue-800 font-bold">
              {{ flowDialogueList.length }} 笔记录
            </span>
          </div>
          <div class="flex items-center gap-2 text-[10px] text-slate-400">
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-blue-500 inline-block"></span> 左侧: 发起端 ➔ 目标端 (请求/上报)</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-indigo-500 inline-block"></span> 右侧: 目标端 ➔ 发起端 (反馈/应答)</span>
          </div>
        </div>

        <!-- 对话流滚动列表 -->
        <div class="flex-1 overflow-y-auto custom-scrollbar p-4 space-y-3" ref="dialogueContainerRef">
          <div v-for="item in flowDialogueList" :key="item.id"
            :class="[
              'flex flex-col max-w-[85%] transition-all cursor-pointer p-3 rounded-2xl border shadow-xs',
              item.isForward ? 'self-start bg-blue-50/70 border-blue-200/80 hover:border-blue-400' : 'self-end bg-indigo-50/70 border-indigo-200/80 hover:border-indigo-400',
              selectedPacket?.id === item.id ? 'ring-2 ring-blue-500 shadow-md' : ''
            ]"
            @click="selectPacket(item)">
            
            <!-- 气泡头部 -->
            <div class="flex items-center justify-between gap-3 text-[10px] font-mono mb-1.5 pb-1 border-b border-slate-200/60">
              <div class="flex items-center gap-1.5 font-bold">
                <span :class="['px-1.5 py-0.2 rounded text-[9px]', item.isForward ? 'bg-blue-600 text-white' : 'bg-indigo-600 text-white']">
                  {{ item.isForward ? '发起端 ➔ 目标端' : '目标端 ➔ 发起端' }}
                </span>
                <span class="text-slate-800">{{ item.src_ip }}:{{ item.src_port }} ➔ {{ item.dst_ip }}:{{ item.dst_port }}</span>
              </div>
              <div class="flex items-center gap-2 text-slate-400">
                <span v-if="!item.isForward && item.latencyMs !== undefined" class="text-emerald-700 font-bold bg-emerald-100/80 px-1.5 py-0.2 rounded">
                  Δt +{{ item.latencyMs }}ms
                </span>
                <span>{{ item.timestamp }}</span>
              </div>
            </div>

            <!-- 规约与功能码 -->
            <div class="flex items-center justify-between gap-2 mb-1.5">
              <div class="flex items-center gap-1.5">
                <span :class="['text-[10px] font-bold px-2 py-0.5 rounded', protocolBadgeColor(item.protocol)]">
                  {{ item.protocol }}
                </span>
                <span v-if="item.business_data?.function_name" class="text-xs font-bold text-blue-900 bg-white/80 px-2 py-0.5 rounded border border-blue-100">
                  {{ item.business_data.function_name }} ({{ item.business_data.function_code }})
                </span>
                <span v-if="item.business_data?.telemetry_station_bcd" class="text-[10px] font-mono text-teal-800 bg-teal-100/80 px-1.5 py-0.5 rounded">
                  终端/站号: {{ item.business_data.telemetry_station_bcd }}
                </span>
              </div>
              <span class="text-[10px] font-mono text-slate-400 font-semibold">{{ item.length }} Bytes</span>
            </div>

            <!-- 数据载荷预览 -->
            <div class="rounded-xl p-2 text-xs font-mono leading-relaxed break-all select-all border bg-amber-50/60 border-amber-200/80 text-amber-950 font-semibold">
              {{ item.raw_text || item.payload_hex?.slice(0, 100) || '[EMPTY PAYLOAD]' }}
            </div>

            <!-- 气泡底栏快捷按钮 -->
            <div class="flex items-center justify-between mt-2 pt-1 border-t border-slate-200/40 text-[10px]">
              <span class="text-slate-400 font-mono">
                Shannon: {{ item.entropy.toFixed(2) }}
              </span>
              <button @click.stop="$emit('openDeepDissector', item)" class="text-blue-600 hover:text-blue-800 font-bold flex items-center gap-0.5">
                <span>🔍 查看全景报文详情 ➔</span>
              </button>
            </div>
          </div>

          <div v-if="flowDialogueList.length === 0" class="flex flex-col items-center justify-center h-full text-slate-400 text-xs py-16">
            <span class="text-3xl mb-2">🔄</span>
            <span class="font-bold text-slate-600">等待匹配双向交互报文...</span>
            <span class="text-[11px] text-slate-400 mt-1">
              请检查上方发起端设备与目标端/中心端设备过滤条件，或在右上角选择已识别的活跃双向会话对
            </span>
          </div>
        </div>
      </div>

      <!-- 右侧：当前选中报文深度联动剖析看板 -->
      <div class="w-96 bg-white/90 rounded-2xl border border-white/80 shadow flex flex-col overflow-hidden shrink-0">
        <div class="px-4 py-3 border-b border-slate-100 bg-slate-50/80 flex items-center justify-between shrink-0">
          <div>
            <h3 class="text-xs font-bold text-slate-800">当前报文深度剖析</h3>
            <p class="text-[10px] text-slate-400 mt-0.5">双向流选中帧详查</p>
          </div>
          <button v-if="selectedPacket" @click="$emit('openDeepDissector', selectedPacket)"
            class="bg-blue-600 hover:bg-blue-700 text-white text-[10px] font-bold px-2.5 py-1 rounded-lg shadow-xs transition-all flex items-center gap-1 cursor-pointer">
            <span>🔍 全屏剖析</span>
          </button>
        </div>

        <div v-if="selectedPacket" class="flex-1 overflow-y-auto custom-scrollbar p-3.5 space-y-3">
          <!-- 基础元组 -->
          <div class="bg-slate-50 border border-slate-100 rounded-xl p-2.5 text-xs font-mono space-y-1">
            <div class="flex justify-between">
              <span class="text-slate-400 text-[10px]">帧序号 / 协议:</span>
              <span class="font-bold text-blue-700">#{{ selectedPacket.id }} - {{ selectedPacket.protocol }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-slate-400 text-[10px]">通信源:</span>
              <span class="font-semibold text-slate-800">{{ selectedPacket.src_ip }}:{{ selectedPacket.src_port }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-slate-400 text-[10px]">目标端:</span>
              <span class="font-semibold text-slate-800">{{ selectedPacket.dst_ip }}:{{ selectedPacket.dst_port }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-slate-400 text-[10px]">传输层 / 长度:</span>
              <span class="text-slate-700">{{ selectedPacket.transport }} | {{ selectedPacket.length }} 字节</span>
            </div>
          </div>

          <!-- 规约结构化解析卡片 -->
          <div v-if="selectedPacket.business_data && Object.keys(selectedPacket.business_data).length > 0" 
            class="bg-indigo-50/40 border border-indigo-100 rounded-xl p-2.5 space-y-1.5">
            <span class="text-[10px] font-bold text-indigo-900 uppercase block">📊 规约结构化字段</span>
            <div v-for="(val, k) in selectedPacket.business_data" :key="k" class="flex justify-between items-center text-xs font-mono py-0.5 border-b border-indigo-100/50 last:border-0">
              <span class="text-slate-400 text-[10px]">{{ k }}</span>
              <span class="font-bold text-indigo-950">{{ val }}</span>
            </div>
          </div>

          <!-- 明文展示 -->
          <div class="space-y-1">
            <div class="flex items-center justify-between">
              <span class="text-[10px] font-bold text-slate-400 uppercase">
                客观真实原始明文
              </span>
              <span class="text-[9px] font-bold px-1.5 py-0.2 rounded bg-amber-100 text-amber-900">
                原始真实
              </span>
            </div>
            <div class="rounded-xl p-2.5 text-[11px] font-mono leading-relaxed break-all select-all border max-h-36 overflow-y-auto custom-scrollbar bg-amber-50/40 border-amber-200 text-amber-950 font-semibold">
              {{ selectedPacket.raw_text || '[EMPTY]' }}
            </div>
          </div>

          <!-- 十六进制转储预览 -->
          <div class="space-y-1">
            <span class="text-[10px] font-bold text-slate-400 uppercase">十六进制与 ASCII 转储</span>
            <div class="bg-slate-900 rounded-xl p-2 text-[9px] font-mono text-emerald-400 select-all max-h-40 overflow-auto custom-scrollbar leading-snug whitespace-pre">
              <div v-for="(line, idx) in formatAlignedHexDump(selectedPacket.payload_hex).slice(0, 10)" :key="idx">{{ line }}</div>
              <div v-if="formatAlignedHexDump(selectedPacket.payload_hex).length > 10" class="text-slate-500 italic mt-1">
                ... 还有 {{ formatAlignedHexDump(selectedPacket.payload_hex).length - 10 }} 行，点击全屏剖析查看全部
              </div>
            </div>
          </div>

          <!-- 操作按钮 -->
          <div class="flex flex-col gap-1.5 pt-1 border-t border-slate-100">
            <button @click="$emit('replay', selectedPacket)" class="w-full bg-amber-50 hover:bg-amber-100 text-amber-700 border border-amber-200 text-xs py-1.5 rounded-lg font-medium">
              ▶ 物理重放报文
            </button>
            <button @click="$emit('saveBaseline', selectedPacket)" class="w-full bg-cyan-50 hover:bg-cyan-100 text-cyan-700 border border-cyan-200 text-xs py-1.5 rounded-lg font-medium">
              💾 固化为历史基线
            </button>
          </div>
        </div>

        <div v-else class="flex-1 flex flex-col items-center justify-center text-slate-400 p-6 text-center">
          <div class="text-2xl mb-2">👈</div>
          <p class="text-xs font-medium">点击左侧对话流中的气泡</p>
          <p class="text-[10px] mt-1 text-slate-400">即可在此查看其规约拆解与十六进制转储</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick } from 'vue';

interface PacketRecord {
  id: number;
  timestamp: string;
  direction: string;
  transport: string;
  protocol: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  length: number;
  payload_hex: string;
  entropy: number;
  entropy_level: string;
  mac_src: string;
  mac_dst: string;
  chain_hash: string;
  business_data?: Record<string, any>;
  raw_text?: string;
}

interface DiscoveredAsset {
  ip: string;
  mac: string;
  role: string;
  scope: string;
  vendor: string;
  ports: number[];
}

const props = defineProps<{
  packets: PacketRecord[];
  assets?: DiscoveredAsset[];
}>();

defineEmits(['openDeepDissector', 'replay', 'saveBaseline']);

// 通信节点过滤参数 (发起端与目标端/中心端)
const sourceInitiatorIp = ref('');
const targetCenterIp = ref('');
const autoScroll = ref(true);
const selectedPacket = ref<PacketRecord | null>(null);
const dialogueContainerRef = ref<HTMLElement | null>(null);

function addAssetToSource(ip: string) {
  if (!sourceInitiatorIp.value.trim()) {
    sourceInitiatorIp.value = ip;
  } else if (!sourceInitiatorIp.value.includes(ip)) {
    sourceInitiatorIp.value += `, ${ip}`;
  }
}

// 自动识别活跃会话链路对 (Source <-> Target)
const activeFlowPairs = computed(() => {
  const map = new Map<string, { key: string; label: string; count: number; ipA: string; ipB: string; portB: number }>();
  
  for (const p of props.packets) {
    if (!p.src_ip || !p.dst_ip) continue;
    // 排序生成标准对 key
    const ips = [p.src_ip, p.dst_ip].sort();
    const pairKey = `${ips[0]} <-> ${ips[1]}`;
    
    if (!map.has(pairKey)) {
      map.set(pairKey, {
        key: pairKey,
        label: `${p.src_ip} ⇋ ${p.dst_ip}`,
        count: 1,
        ipA: p.src_ip,
        ipB: p.dst_ip,
        portB: p.dst_port
      });
    } else {
      map.get(pairKey)!.count += 1;
    }
  }

  return Array.from(map.values()).sort((a, b) => b.count - a.count).slice(0, 15);
});

function onSelectActiveFlow(e: Event) {
  const sel = (e.target as HTMLSelectElement).value;
  if (!sel) return;
  const pair = activeFlowPairs.value.find(p => p.key === sel);
  if (pair) {
    sourceInitiatorIp.value = pair.ipA;
    targetCenterIp.value = pair.ipB;
  }
}

// 解析发起端设备 IP 列表
const sourceIpList = computed(() => {
  if (!sourceInitiatorIp.value.trim()) return [];
  return sourceInitiatorIp.value.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
});

// 解析目标端/中心端过滤条件
const targetTrim = computed(() => targetCenterIp.value.trim().toLowerCase());

// 真实时间戳解析算法 (支持纳秒/毫秒或 HH:mm:ss.SSS 格式)
// 时间复杂度: O(1)
// 空间复杂度: O(1)
function parseTimestampMs(tsStr: string, timestampNs?: number | string): number | null {
  if (timestampNs !== undefined && timestampNs !== null && timestampNs !== 0 && timestampNs !== '0') {
    try {
      const ns = typeof timestampNs === 'string' ? BigInt(timestampNs) : BigInt(Math.floor(timestampNs));
      return Number(ns / 1_000_000n);
    } catch {
      // 降级使用字符串解析
    }
  }
  if (!tsStr || typeof tsStr !== 'string') return null;
  const parts = tsStr.trim().split(/[\sT]+/);
  const timePart = parts[parts.length - 1];
  const match = timePart.match(/^(\d{1,2}):(\d{1,2}):(\d{1,2})(?:\.(\d{1,6}))?$/);
  if (!match) return null;
  const hours = parseInt(match[1], 10);
  const minutes = parseInt(match[2], 10);
  const seconds = parseInt(match[3], 10);
  const ms = match[4] ? parseInt(match[4].padEnd(3, '0').slice(0, 3), 10) : 0;
  return ((hours * 3600 + minutes * 60 + seconds) * 1000) + ms;
}

// 过滤出属于发起端与目标端/中心端的双向时序会话流
const flowDialogueList = computed(() => {
  const sList = sourceIpList.value;
  const tTarget = targetTrim.value;

  const result: Array<PacketRecord & { isForward: boolean; latencyMs?: number }> = [];
  let lastForwardTs: number | null = null;

  for (const p of props.packets) {
    const srcIp = p.src_ip.toLowerCase();
    const dstIp = p.dst_ip.toLowerCase();
    const srcPortStr = String(p.src_port);
    const dstPortStr = String(p.dst_port);

    // 判断是否满足 发起端 -> 目标端 (Forward 上行/请求)
    const matchSource_asSrc = sList.length === 0 || sList.some(ip => srcIp.includes(ip));
    const matchTarget_asDst = !tTarget || dstIp.includes(tTarget) || dstPortStr === tTarget;

    // 判断是否满足 目标端 -> 发起端 (Reverse 下行/反馈)
    const matchTarget_asSrc = !tTarget || srcIp.includes(tTarget) || srcPortStr === tTarget;
    const matchSource_asDst = sList.length === 0 || sList.some(ip => dstIp.includes(ip));

    if (matchSource_asSrc && matchTarget_asDst) {
      // 发起端 ➔ 目标端
      result.push({ ...p, isForward: true });
      lastForwardTs = parseTimestampMs(p.timestamp, (p as any).timestamp_ns);
    } else if (matchTarget_asSrc && matchSource_asDst) {
      // 目标端 ➔ 发起端：基于真实捕获时间差计算往返时延
      const currentTs = parseTimestampMs(p.timestamp, (p as any).timestamp_ns);
      let realLatency: number | undefined = undefined;
      if (currentTs !== null && lastForwardTs !== null) {
        let diff = currentTs - lastForwardTs;
        if (diff < 0 && diff > -86400000) {
          // 处理跨午夜 24 小时
          diff += 86400000;
        }
        if (diff >= 0 && diff < 3600000) {
          realLatency = Math.round(diff);
        }
      }
      result.push({ ...p, isForward: false, latencyMs: realLatency });
    }
  }

  return result;
});

// 统计
const forwardCount = computed(() => flowDialogueList.value.filter(p => p.isForward).length);
const reverseCount = computed(() => flowDialogueList.value.filter(p => !p.isForward).length);
const forwardBytes = computed(() => flowDialogueList.value.filter(p => p.isForward).reduce((acc, p) => acc + p.length, 0));
const reverseBytes = computed(() => flowDialogueList.value.filter(p => !p.isForward).reduce((acc, p) => acc + p.length, 0));

const completionRate = computed(() => {
  if (forwardCount.value === 0) return 100;
  return Math.min(100, Math.round((reverseCount.value / forwardCount.value) * 100));
});

// 纯真实计算：从有效往返时延样本动态统计平均值，无数据时返回 0（界面展示 -）
const avgLatencyMs = computed(() => {
  const validLatencies = flowDialogueList.value
    .filter(p => !p.isForward && typeof p.latencyMs === 'number' && p.latencyMs >= 0)
    .map(p => p.latencyMs as number);
  if (validLatencies.length === 0) return 0;
  const sum = validLatencies.reduce((acc, v) => acc + v, 0);
  return Number((sum / validLatencies.length).toFixed(1));
});

function selectPacket(p: PacketRecord) {
  selectedPacket.value = p;
}

function protocolBadgeColor(proto: string): string {
  if (!proto) return 'bg-slate-100 text-slate-600';
  if (proto.includes('SL651')) return 'bg-teal-100 text-teal-800';
  if (proto.includes('MODBUS')) return 'bg-amber-100 text-amber-800';
  if (proto.includes('MQTT')) return 'bg-purple-100 text-purple-800';
  if (proto.includes('HTTP')) return 'bg-blue-100 text-blue-800';
  if (proto.includes('HJ212')) return 'bg-emerald-100 text-emerald-800';
  return 'bg-slate-100 text-slate-700';
}

function formatAlignedHexDump(hexStr: string): string[] {
  if (!hexStr) return [];
  const clean = hexStr.replace(/\s+/g, '');
  const lines: string[] = [];
  
  for (let offset = 0; offset < clean.length; offset += 32) {
    const chunk = clean.slice(offset, offset + 32);
    const offsetHex = (offset / 2).toString(16).padStart(4, '0').toUpperCase();
    
    const hexBytes: string[] = [];
    const asciiChars: string[] = [];
    
    for (let i = 0; i < 32; i += 2) {
      if (i < chunk.length) {
        const byteHex = chunk.slice(i, i + 2).toUpperCase();
        hexBytes.push(byteHex);
        const byteVal = parseInt(byteHex, 16);
        if (byteVal >= 32 && byteVal <= 126) {
          asciiChars.push(String.fromCharCode(byteVal));
        } else {
          asciiChars.push('.');
        }
      } else {
        hexBytes.push('  ');
      }
    }
    
    const part1 = hexBytes.slice(0, 8).join(' ');
    const part2 = hexBytes.slice(8, 16).join(' ');
    const asciiPart = asciiChars.join('');
    
    lines.push(`${offsetHex} | ${part1}  ${part2} | ${asciiPart}`);
  }
  
  return lines;
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

watch(() => flowDialogueList.value.length, () => {
  if (autoScroll.value && dialogueContainerRef.value) {
    nextTick(() => {
      dialogueContainerRef.value!.scrollTop = dialogueContainerRef.value!.scrollHeight;
    });
  }
});
</script>
