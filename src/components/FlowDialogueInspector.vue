<template>
  <div class="flex-1 flex flex-col gap-3 overflow-hidden">
    <!-- 顶部会话链路与通信节点配置面板 (实体工作区面板) -->
    <div class="ui-content-card p-4 shrink-0 flex flex-col gap-3">
      <div class="flex items-center justify-between border-b pb-2.5 flex-wrap gap-2" style="border-color: var(--border-subtle)">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-sky-500/15 border border-sky-500/30 text-sky-700 dark:text-sky-300 flex items-center justify-center shrink-0">
            <AppIcon name="refresh" :size="16" />
          </div>
          <div>
            <h2 class="text-sm font-bold flex items-center gap-1.5" style="color: var(--text-primary)">
              <span>双向会话流与节点交互观测器</span>
            </h2>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">
              精准追踪发起端设备向目标端设备发送的业务报文，以及目标端反馈的应答与真实时序往返
            </p>
          </div>
        </div>

        <button @click="autoScroll = !autoScroll"
          :class="['text-xs px-3 py-1.5 rounded-xl border transition-colors font-semibold flex items-center gap-1.5 cursor-pointer',
            autoScroll ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/35' : 'ui-pill']">
          <AppIcon :name="autoScroll ? 'zap' : 'pause'" :size="12" />
          <span>{{ autoScroll ? '自动跟踪最新' : '暂停自动滚屏' }}</span>
        </button>
      </div>

      <!-- 通信节点配置与会话链路选择 -->
      <div class="grid grid-cols-1 lg:grid-cols-[1fr_1fr_260px] gap-3 items-end">
        <div class="flex flex-col gap-1">
          <div class="flex items-center justify-between">
            <label class="text-[11px] font-bold text-sky-700 dark:text-sky-300 uppercase flex items-center gap-1">
              <span class="w-2 h-2 rounded-full bg-sky-500"></span>
              <span>发起端设备 (Client / Source)</span>
            </label>
            <span class="text-[11px]" style="color: var(--text-muted)">支持多 IP 逗号分隔</span>
          </div>
          <div class="relative">
            <input v-model="sourceInitiatorIp" placeholder="如: 192.168.1.10, 192.168.1.20"
              class="ui-input ui-num px-3 py-1.5 text-xs pr-7">
            <button v-if="sourceInitiatorIp" @click="sourceInitiatorIp = ''" class="absolute right-2 top-1.5 cursor-pointer" style="color: var(--text-muted)">
              <AppIcon name="close" :size="12" />
            </button>
          </div>
        </div>

        <div class="flex flex-col gap-1">
          <div class="flex items-center justify-between">
            <label class="text-[11px] font-bold text-indigo-700 dark:text-indigo-300 uppercase flex items-center gap-1">
              <span class="w-2 h-2 rounded-full bg-indigo-500"></span>
              <span>目标端设备 (Server / Target)</span>
            </label>
            <span class="text-[11px]" style="color: var(--text-muted)">支持 IP 或端口</span>
          </div>
          <div class="relative">
            <input v-model="targetCenterIp" placeholder="如: 192.168.1.100 或 8080"
              class="ui-input ui-num px-3 py-1.5 text-xs pr-7">
            <button v-if="targetCenterIp" @click="targetCenterIp = ''" class="absolute right-2 top-1.5 cursor-pointer" style="color: var(--text-muted)">
              <AppIcon name="close" :size="12" />
            </button>
          </div>
        </div>

        <div class="flex flex-col gap-1">
          <label class="text-[11px] font-bold uppercase flex items-center gap-1" style="color: var(--text-muted)">
            <AppIcon name="link" :size="12" />
            <span>活跃会话链路对</span>
          </label>
          <select @change="onSelectActiveFlow($event)" class="ui-input ui-num px-2.5 py-1.5 text-xs cursor-pointer">
            <option value="">-- 选择识别到的双向会话对 --</option>
            <option v-for="pair in activeFlowPairs" :key="pair.key" :value="pair.key">
              {{ pair.label }} ({{ pair.count }} 帧)
            </option>
          </select>
        </div>
      </div>

      <!-- 快速标签 -->
      <div v-if="assets && assets.length > 0" class="flex items-center gap-1.5 flex-wrap pt-1.5 border-t" style="border-color: var(--border-subtle)">
        <span class="text-[11px] font-medium" style="color: var(--text-muted)">快速加入发起端设备:</span>
        <button v-for="ast in assets.slice(0, 8)" :key="ast.ip"
          @click="addAssetToSource(ast.ip)"
          class="text-[11px] ui-num px-2 py-0.5 rounded-md ui-pill cursor-pointer">
          + {{ ast.ip }}
        </button>
      </div>

      <!-- 统计指标条 -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-2 pt-1.5 border-t text-xs ui-num" style="border-color: var(--border-subtle)">
        <div class="ui-sub-card p-2 flex justify-between items-center bg-sky-500/8 border-sky-500/25">
          <span class="text-[11px] text-sky-700 dark:text-sky-300 font-bold">发起 → 目标</span>
          <span class="font-bold" style="color: var(--text-primary)">{{ forwardCount }} 帧 ({{ formatBytes(forwardBytes) }})</span>
        </div>
        <div class="ui-sub-card p-2 flex justify-between items-center bg-indigo-500/8 border-indigo-500/25">
          <span class="text-[11px] text-indigo-700 dark:text-indigo-300 font-bold">目标 → 发起</span>
          <span class="font-bold" style="color: var(--text-primary)">{{ reverseCount }} 帧 ({{ formatBytes(reverseBytes) }})</span>
        </div>
        <div class="ui-sub-card p-2 flex justify-between items-center bg-emerald-500/8 border-emerald-500/25">
          <span class="text-[11px] text-emerald-700 dark:text-emerald-300 font-bold">交互闭环率</span>
          <span class="font-bold text-emerald-700 dark:text-emerald-300">{{ completionRate }}%</span>
        </div>
        <div class="ui-sub-card p-2 flex justify-between items-center bg-amber-500/8 border-amber-500/25">
          <span class="text-[11px] text-amber-700 dark:text-amber-300 font-bold">平均响应时延</span>
          <span class="font-bold text-amber-700 dark:text-amber-300">{{ avgLatencyMs > 0 ? avgLatencyMs.toFixed(1) + ' ms' : '-' }}</span>
        </div>
      </div>
    </div>

    <!-- 主体：左侧双向时序对话流 + 右侧当前选中报文深度看板 -->
    <div class="flex-1 flex gap-3 overflow-hidden min-h-0">
      <div class="flex-1 ui-content-card flex flex-col overflow-hidden min-w-0">
        <div class="px-4 py-2.5 border-b flex items-center justify-between shrink-0 flex-wrap gap-2" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
          <div class="flex items-center gap-2">
            <span class="text-xs font-bold" style="color: var(--text-primary)">双向通信往返时序流</span>
            <span class="text-[11px] ui-num px-2 py-0.5 rounded-full bg-sky-500/12 text-sky-700 dark:text-sky-300 font-bold">
              {{ flowDialogueList.length }} 笔记录
            </span>
          </div>
          <div class="flex items-center gap-3 text-[11px]" style="color: var(--text-muted)">
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-sky-500 inline-block"></span> 发起 → 目标</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-indigo-500 inline-block"></span> 目标 → 发起</span>
          </div>
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar p-4 space-y-3 select-text" ref="dialogueContainerRef">
          <div v-for="item in flowDialogueList" :key="item.id"
            :class="[
              'flex flex-col max-w-[85%] transition-colors cursor-pointer p-3 rounded-2xl border shadow-2xs',
              item.isForward ? 'self-start bg-sky-500/10 border-sky-500/30 hover:border-sky-500/60' : 'self-end bg-indigo-500/10 border-indigo-500/30 hover:border-indigo-500/60',
              selectedPacket?.id === item.id ? 'ring-2 ring-sky-500' : ''
            ]"
            @click="selectPacket(item)">
            
            <div class="flex items-center justify-between gap-3 text-[11px] ui-num mb-1.5 pb-1 border-b" style="border-color: var(--border-subtle)">
              <div class="flex items-center gap-1.5 font-bold min-w-0">
                <span :class="['px-1.5 py-0.5 rounded text-[11px] shrink-0', item.isForward ? 'bg-sky-600 text-white' : 'bg-indigo-600 text-white']">
                  {{ item.isForward ? '发起 → 目标' : '目标 → 发起' }}
                </span>
                <span class="truncate" style="color: var(--text-primary)">{{ item.src_ip }}:{{ item.src_port }} → {{ item.dst_ip }}:{{ item.dst_port }}</span>
              </div>
              <div class="flex items-center gap-2 shrink-0" style="color: var(--text-muted)">
                <span v-if="!item.isForward && item.latencyMs !== undefined" class="text-emerald-700 dark:text-emerald-300 font-bold bg-emerald-500/15 px-1.5 py-0.5 rounded">
                  Δt +{{ item.latencyMs }}ms
                </span>
                <span>{{ item.timestamp }}</span>
              </div>
            </div>

            <div class="flex items-center justify-between gap-2 mb-1.5 flex-wrap">
              <div class="flex items-center gap-1.5 flex-wrap">
                <span :class="['text-[11px] font-bold px-2 py-0.5 rounded border', protocolBadgeColor(item.protocol)]">
                  {{ item.protocol }}
                </span>
                <span v-if="item.business_data?.function_name" class="text-xs font-bold text-blue-700 dark:text-sky-300 ui-pill px-2 py-0.5 rounded">
                  {{ item.business_data.function_name }} ({{ item.business_data.function_code }})
                </span>
                <span v-if="item.business_data?.telemetry_station_bcd" class="text-[11px] ui-num text-teal-700 dark:text-teal-300 bg-teal-500/15 px-1.5 py-0.5 rounded">
                  站号: {{ item.business_data.telemetry_station_bcd }}
                </span>
              </div>
              <span class="text-[11px] ui-num font-semibold" style="color: var(--text-muted)">{{ item.length }} Bytes</span>
            </div>

            <div class="rounded-xl p-2 text-xs font-mono-code leading-relaxed break-all select-text border bg-amber-500/10 border-amber-500/25 font-medium" style="color: var(--text-primary)">
              {{ item.raw_text || item.payload_hex?.slice(0, 100) || '[EMPTY PAYLOAD]' }}
            </div>

            <div class="flex items-center justify-between mt-2 pt-1 border-t text-[11px]" style="border-color: var(--border-subtle)">
              <span class="ui-num" style="color: var(--text-muted)">Shannon: {{ item.entropy.toFixed(2) }}</span>
              <button @click.stop="$emit('openDeepDissector', item)" class="font-semibold flex items-center gap-1 cursor-pointer hover:underline" style="color: var(--accent-primary-text)">
                <AppIcon name="search" :size="11" />
                <span>查看全景报文详情</span>
                <AppIcon name="arrow-right" :size="11" />
              </button>
            </div>
          </div>

          <EmptyState
            v-if="flowDialogueList.length === 0"
            class="py-12"
            icon="refresh"
            title="等待匹配双向交互报文"
            description="请检查上方发起端与目标端过滤条件，或在右上角下拉选择活跃双向会话对。"
          />
        </div>
      </div>

      <!-- 右侧：当前选中报文深度联动剖析看板 -->
      <aside class="w-80 xl:w-96 ui-content-card flex flex-col overflow-hidden shrink-0">
        <div class="px-4 py-3 border-b flex items-center justify-between shrink-0" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
          <div>
            <h3 class="text-xs font-bold" style="color: var(--text-primary)">当前报文深度剖析</h3>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">双向流选中帧详查</p>
          </div>
          <button v-if="selectedPacket" @click="$emit('openDeepDissector', selectedPacket)"
            class="ui-btn-primary text-[11px] px-2.5 py-1 rounded-lg">
            <AppIcon name="search" :size="12" />
            <span>全屏剖析</span>
          </button>
        </div>

        <div v-if="selectedPacket" class="flex-1 overflow-y-auto custom-scrollbar p-3.5 space-y-3 select-text">
          <div class="ui-sub-card p-2.5 text-xs ui-num space-y-1">
            <div class="flex justify-between">
              <span class="text-[11px]" style="color: var(--text-muted)">帧序号 / 协议:</span>
              <span class="font-bold" style="color: var(--accent-primary-text)">#{{ selectedPacket.id }} - {{ selectedPacket.protocol }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-[11px]" style="color: var(--text-muted)">通信源:</span>
              <span class="font-semibold" style="color: var(--text-primary)">{{ selectedPacket.src_ip }}:{{ selectedPacket.src_port }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-[11px]" style="color: var(--text-muted)">目标端:</span>
              <span class="font-semibold" style="color: var(--text-primary)">{{ selectedPacket.dst_ip }}:{{ selectedPacket.dst_port }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-[11px]" style="color: var(--text-muted)">传输层 / 长度:</span>
              <span style="color: var(--text-secondary)">{{ selectedPacket.transport }} | {{ selectedPacket.length }} 字节</span>
            </div>
          </div>

          <div v-if="selectedPacket.business_data && Object.keys(selectedPacket.business_data).length > 0"
            class="ui-sub-card bg-indigo-500/8 border-indigo-500/25 p-2.5 space-y-1.5">
            <span class="text-[11px] font-bold text-indigo-700 dark:text-indigo-300 uppercase flex items-center gap-1">
              <AppIcon name="layers" :size="12" />
              <span>规约结构化字段</span>
            </span>
            <div v-for="(val, k) in selectedPacket.business_data" :key="k" class="flex justify-between items-center text-xs ui-num py-0.5 border-b last:border-0" style="border-color: var(--border-subtle)">
              <span class="text-[11px]" style="color: var(--text-muted)">{{ k }}</span>
              <span class="font-bold" style="color: var(--text-primary)">{{ val }}</span>
            </div>
          </div>

          <div class="space-y-1">
            <div class="flex items-center justify-between">
              <span class="text-[11px] font-bold uppercase" style="color: var(--text-muted)">客观真实原始明文</span>
              <span class="text-[11px] font-bold px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-700 dark:text-amber-300">原始真实</span>
            </div>
            <div class="ui-input font-mono-code p-2.5 text-[11px] leading-relaxed break-all select-text max-h-36 overflow-y-auto custom-scrollbar">
              {{ selectedPacket.raw_text || '[EMPTY]' }}
            </div>
          </div>

          <div class="space-y-1">
            <span class="text-[11px] font-bold uppercase" style="color: var(--text-muted)">十六进制与 ASCII 转储</span>
            <div class="ui-input font-mono-code p-2.5 text-[11px] text-emerald-700 dark:text-emerald-400 select-text max-h-40 overflow-auto custom-scrollbar leading-snug whitespace-pre">
              <div v-for="(line, idx) in formatAlignedHexDump(selectedPacket.payload_hex).slice(0, 10)" :key="idx">{{ line }}</div>
              <div v-if="formatAlignedHexDump(selectedPacket.payload_hex).length > 10" class="italic mt-1" style="color: var(--text-muted)">
                ... 还有 {{ formatAlignedHexDump(selectedPacket.payload_hex).length - 10 }} 行，点击全屏剖析查看全部
              </div>
            </div>
          </div>

          <div class="flex flex-col gap-1.5 pt-1 border-t" style="border-color: var(--border-subtle)">
            <button @click="$emit('replay', selectedPacket)" class="w-full ui-btn-secondary justify-center text-xs py-1.5 rounded-lg">
              <AppIcon name="play" :size="12" />
              <span>物理重放报文</span>
            </button>
            <button @click="$emit('saveBaseline', selectedPacket)" class="w-full ui-btn-primary justify-center text-xs py-1.5 rounded-lg">
              <AppIcon name="archive" :size="12" />
              <span>固化为历史基线</span>
            </button>
          </div>
        </div>

        <EmptyState
          v-else
          class="flex-1 p-6"
          icon="info"
          title="选择对话流气泡"
          description="点击左侧任意双向报文气泡，即可在此查看其规约拆解与十六进制转储。"
        />
      </aside>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick } from 'vue';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';

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
    } catch (err) {
      console.warn('[FlowDialogueInspector] BigInt ns parse failed, falling back to string parsing:', timestampNs, err);
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
  if (!proto) return 'ui-pill';
  if (proto.includes('SL651')) return 'bg-teal-500/12 text-teal-700 dark:text-teal-300 border-teal-500/25';
  if (proto.includes('MODBUS')) return 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/25';
  if (proto.includes('MQTT')) return 'bg-purple-500/12 text-purple-700 dark:text-purple-300 border-purple-500/25';
  if (proto.includes('HTTP')) return 'bg-blue-500/12 text-blue-700 dark:text-sky-300 border-blue-500/25';
  if (proto.includes('HJ212')) return 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/25';
  return 'ui-pill';
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
