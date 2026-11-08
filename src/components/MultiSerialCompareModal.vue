<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-200">
    <div class="bg-white/95 backdrop-blur-2xl rounded-2xl shadow-2xl border border-white/80 w-full max-w-6xl max-h-[92vh] flex flex-col overflow-hidden text-slate-800">
      
      <!-- 1. 模态框顶栏 (Apple Glassmorphism 工业级控制头) -->
      <div class="px-5 py-3 border-b border-slate-200/80 flex items-center justify-between bg-slate-50/80 shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-indigo-600 text-white flex items-center justify-center text-base shadow-sm font-bold">
            ⚖
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h3 class="text-sm font-bold text-slate-900 leading-tight">多串口数据实时交叉比对终端</h3>
              <span class="text-[10px] font-mono font-bold bg-indigo-100 text-indigo-800 px-2 py-0.5 rounded-full border border-indigo-200">
                双通道时序差分
              </span>
            </div>
            <p class="text-[11px] text-slate-500 font-sans mt-0.5">
              支持双串口全双工实时同步对照、LCS 逐字节差分高亮与传输延迟抖动 (&Delta;t) 分析
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <!-- 导出比对报表 -->
          <button @click="exportReport" :disabled="comparedPairs.length === 0"
            class="px-2.5 py-1.5 rounded-xl border border-slate-300 text-slate-700 hover:bg-slate-100 text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer disabled:opacity-40 shadow-2xs">
            <span>📥</span>
            <span>导出比对报表</span>
          </button>
          
          <!-- 关闭按钮 -->
          <button @click="$emit('close')"
            class="w-7 h-7 rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-200 flex items-center justify-center transition-colors cursor-pointer text-sm font-bold">
            ✕
          </button>
        </div>
      </div>

      <!-- 2. 控制参数栏 (通道选择、比对模式、自动滚动与清空) -->
      <div class="px-5 py-2.5 bg-white/80 border-b border-slate-200/70 flex items-center justify-between gap-4 flex-wrap shrink-0">
        <!-- 左侧通道选择器 -->
        <div class="flex items-center gap-3 flex-wrap text-xs">
          <!-- 通道 A -->
          <div class="flex items-center gap-1.5 bg-blue-50/80 border border-blue-200/80 px-2.5 py-1 rounded-xl">
            <span class="w-2 h-2 rounded-full bg-blue-600"></span>
            <span class="font-bold text-blue-900">通道 A:</span>
            <select v-model="channelA" class="bg-white border border-blue-200 rounded-lg px-2 py-0.5 font-mono text-xs text-blue-950 focus:outline-none">
              <option v-for="p in availablePorts" :key="'a-' + p" :value="p">{{ p }}</option>
              <option v-if="availablePorts.length === 0" value="">未发现可用串口</option>
            </select>
          </div>

          <!-- 通道 B -->
          <div class="flex items-center gap-1.5 bg-emerald-50/80 border border-emerald-200/80 px-2.5 py-1 rounded-xl">
            <span class="w-2 h-2 rounded-full bg-emerald-600"></span>
            <span class="font-bold text-emerald-900">通道 B:</span>
            <select v-model="channelB" class="bg-white border border-emerald-200 rounded-lg px-2 py-0.5 font-mono text-xs text-emerald-950 focus:outline-none">
              <option v-for="p in availablePorts" :key="'b-' + p" :value="p">{{ p }}</option>
              <option v-if="availablePorts.length === 0" value="">未发现可用串口</option>
            </select>
          </div>

          <!-- 视图模式切换 -->
          <div class="flex bg-slate-200/70 p-0.5 rounded-xl border border-slate-300/60 font-semibold text-[11px]">
            <button @click="viewMode = 'split'"
              :class="['px-2.5 py-0.5 rounded-lg transition-all cursor-pointer', viewMode === 'split' ? 'bg-white text-slate-900 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900']">
              双分栏对照
            </button>
            <button @click="viewMode = 'interleaved'"
              :class="['px-2.5 py-0.5 rounded-lg transition-all cursor-pointer', viewMode === 'interleaved' ? 'bg-white text-slate-900 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900']">
              时序交织比对
            </button>
          </div>
        </div>

        <!-- 右侧指标与开关 -->
        <div class="flex items-center gap-3 text-xs">
          <!-- 统计指标微胶囊 -->
          <div class="flex items-center gap-2 font-mono text-[11px] bg-slate-100/90 px-3 py-1 rounded-xl border border-slate-200">
            <div>A接收: <strong class="text-blue-700">{{ channelAPackets.length }}</strong></div>
            <div class="text-slate-300">|</div>
            <div>B接收: <strong class="text-emerald-700">{{ channelBPackets.length }}</strong></div>
            <div class="text-slate-300">|</div>
            <div>比对组: <strong class="text-indigo-700">{{ comparedPairs.length }}</strong></div>
            <div class="text-slate-300">|</div>
            <div>匹配率: <strong :class="matchRate >= 95 ? 'text-emerald-700' : matchRate >= 80 ? 'text-amber-700' : 'text-rose-700'">{{ matchRate.toFixed(1) }}%</strong></div>
          </div>

          <!-- 自动滚动复选框 -->
          <label class="flex items-center gap-1.5 text-xs text-slate-600 font-semibold cursor-pointer select-none">
            <input type="checkbox" v-model="autoScroll" class="rounded text-indigo-600 focus:ring-0 cursor-pointer">
            <span>自动滚动</span>
          </label>

          <!-- 清空缓冲 -->
          <button @click="clearBuffer"
            class="text-[11px] text-slate-400 hover:text-slate-700 px-2 py-1 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer">
            清空视图
          </button>
        </div>
      </div>

      <!-- 3. 主比对内容视口 -->
      <div ref="scrollContainer" class="flex-1 overflow-auto custom-scrollbar p-4 bg-slate-50/50 min-h-0">
        
        <!-- 空状态提示 -->
        <div v-if="channelAPackets.length === 0 && channelBPackets.length === 0"
          class="flex flex-col items-center justify-center py-20 text-slate-400 text-xs gap-2 select-none">
          <div class="w-12 h-12 rounded-2xl bg-indigo-50 border border-indigo-200 flex items-center justify-center text-2xl mb-1 shadow-2xs">
            ⚖
          </div>
          <span class="text-sm font-bold text-slate-800">等待串口数据输入</span>
          <span class="text-[11px] text-slate-500 font-mono">
            请确认已同时启动 <strong class="text-blue-700">{{ channelA || '通道A' }}</strong> 与 <strong class="text-emerald-700">{{ channelB || '通道B' }}</strong> 的监听
          </span>
          <div class="text-[11px] text-slate-400 max-w-md text-center mt-1">
            当两个串口产生操作数据帧时，系统将根据物理时间戳自动对齐，并执行 LCS 逐字节差分高亮与传输延迟分析。
          </div>
        </div>

        <!-- 模式 1: 双分栏对照视图 (Split View) -->
        <div v-else-if="viewMode === 'split'" class="grid grid-cols-1 md:grid-cols-2 gap-3">
          
          <!-- 通道 A 栏 -->
          <div class="bg-white/80 rounded-2xl border border-blue-200/80 shadow-xs flex flex-col overflow-hidden">
            <div class="px-3.5 py-2 bg-blue-50/80 border-b border-blue-200/60 flex items-center justify-between text-xs">
              <span class="font-bold text-blue-900 flex items-center gap-1.5 font-mono">
                <span class="w-2 h-2 rounded-full bg-blue-600"></span>
                <span>通道 A: {{ channelA }}</span>
              </span>
              <span class="font-mono text-[11px] text-blue-700">共 {{ channelAPackets.length }} 帧</span>
            </div>
            <div class="p-2 space-y-2 overflow-auto max-h-[60vh] custom-scrollbar">
              <div v-for="(pair, idx) in comparedPairs" :key="'split-a-' + idx"
                class="p-2 rounded-xl border text-xs font-mono transition-all"
                :class="pair.match ? 'bg-slate-50/70 border-slate-200/70' : 'bg-rose-50/60 border-rose-200/80'">
                <div class="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                  <span class="font-bold text-slate-700">#{{ idx + 1 }} {{ pair.pktA ? pair.pktA.timestamp : '—' }}</span>
                  <span v-if="pair.pktA" class="bg-blue-100 text-blue-800 px-1.5 py-0.2 rounded font-semibold">{{ pair.pktA.length }} 字节</span>
                  <span v-else class="text-slate-400">无对应报文</span>
                </div>
                <!-- 逐字节对比 Hex 预览 -->
                <div v-if="pair.pktA" class="break-all font-mono text-[11px] leading-relaxed">
                  <span v-for="(byteDiff, bIdx) in pair.diffA" :key="'b-a-' + bIdx"
                    :class="[
                      'inline-block px-1 py-0.2 m-0.5 rounded text-[10px]',
                      byteDiff.type === 'match' ? 'bg-emerald-100 text-emerald-900 font-bold' :
                      byteDiff.type === 'diff' ? 'bg-rose-500 text-white font-bold' :
                      'bg-slate-200 text-slate-700'
                    ]"
                    :title="`偏移 0x${bIdx.toString(16).toUpperCase()}: ${byteDiff.hex} (${byteDiff.type})`">
                    {{ byteDiff.hex }}
                  </span>
                </div>
                <div v-if="pair.pktA?.raw_text" class="text-[10px] text-slate-600 mt-1 truncate border-t border-slate-200/60 pt-1">
                  {{ pair.pktA.raw_text }}
                </div>
              </div>
            </div>
          </div>

          <!-- 通道 B 栏 -->
          <div class="bg-white/80 rounded-2xl border border-emerald-200/80 shadow-xs flex flex-col overflow-hidden">
            <div class="px-3.5 py-2 bg-emerald-50/80 border-b border-emerald-200/60 flex items-center justify-between text-xs">
              <span class="font-bold text-emerald-900 flex items-center gap-1.5 font-mono">
                <span class="w-2 h-2 rounded-full bg-emerald-600"></span>
                <span>通道 B: {{ channelB }}</span>
              </span>
              <span class="font-mono text-[11px] text-emerald-700">共 {{ channelBPackets.length }} 帧</span>
            </div>
            <div class="p-2 space-y-2 overflow-auto max-h-[60vh] custom-scrollbar">
              <div v-for="(pair, idx) in comparedPairs" :key="'split-b-' + idx"
                class="p-2 rounded-xl border text-xs font-mono transition-all"
                :class="pair.match ? 'bg-slate-50/70 border-slate-200/70' : 'bg-rose-50/60 border-rose-200/80'">
                <div class="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                  <span class="font-bold text-slate-700">#{{ idx + 1 }} {{ pair.pktB ? pair.pktB.timestamp : '—' }}</span>
                  <span v-if="pair.pktB" class="bg-emerald-100 text-emerald-800 px-1.5 py-0.2 rounded font-semibold">{{ pair.pktB.length }} 字节</span>
                  <span v-else class="text-slate-400">无对应报文</span>
                </div>
                <!-- 逐字节对比 Hex 预览 -->
                <div v-if="pair.pktB" class="break-all font-mono text-[11px] leading-relaxed">
                  <span v-for="(byteDiff, bIdx) in pair.diffB" :key="'b-b-' + bIdx"
                    :class="[
                      'inline-block px-1 py-0.2 m-0.5 rounded text-[10px]',
                      byteDiff.type === 'match' ? 'bg-emerald-100 text-emerald-900 font-bold' :
                      byteDiff.type === 'diff' ? 'bg-rose-500 text-white font-bold' :
                      'bg-slate-200 text-slate-700'
                    ]"
                    :title="`偏移 0x${bIdx.toString(16).toUpperCase()}: ${byteDiff.hex} (${byteDiff.type})`">
                    {{ byteDiff.hex }}
                  </span>
                </div>
                <div v-if="pair.pktB?.raw_text" class="text-[10px] text-slate-600 mt-1 truncate border-t border-slate-200/60 pt-1">
                  {{ pair.pktB.raw_text }}
                </div>
              </div>
            </div>
          </div>

        </div>

        <!-- 模式 2: 时序交织比对视图 (Interleaved Timeline View) -->
        <div v-else class="space-y-2.5">
          <div v-for="(pair, idx) in comparedPairs" :key="'interleaved-' + idx"
            class="bg-white/85 rounded-2xl border p-3 shadow-xs transition-all"
            :class="pair.match ? 'border-slate-200/80 hover:border-blue-300' : 'border-rose-300/80 bg-rose-50/30'">
            
            <!-- 比对头信息 -->
            <div class="flex items-center justify-between text-xs pb-2 border-b border-slate-200/60 mb-2">
              <div class="flex items-center gap-2">
                <span class="font-bold text-slate-800 font-mono">比对组 #{{ idx + 1 }}</span>
                <span :class="pair.match ? 'bg-emerald-100 text-emerald-800 border-emerald-200' : 'bg-rose-100 text-rose-800 border-rose-200'"
                  class="text-[10px] font-bold px-2 py-0.2 rounded-full border">
                  {{ pair.match ? '✓ 载荷完全一致' : '✕ 载荷存在差异' }}
                </span>
                <span v-if="pair.deltaMs !== null" class="text-[10px] font-mono text-slate-500 bg-slate-100 px-1.5 py-0.2 rounded">
                  时延抖动 &Delta;t: {{ pair.deltaMs.toFixed(2) }} ms
                </span>
              </div>
              <div class="text-[11px] font-mono text-slate-400">
                LCS 匹配相似度: <strong class="text-indigo-700 font-bold">{{ pair.similarity.toFixed(1) }}%</strong>
              </div>
            </div>

            <!-- 对照双流 -->
            <div class="space-y-2 text-xs font-mono">
              <!-- Channel A -->
              <div class="flex items-start gap-2">
                <span class="w-16 shrink-0 text-[10px] font-bold text-blue-800 bg-blue-100 px-1.5 py-0.5 rounded text-center mt-0.5">
                  {{ channelA }}
                </span>
                <div class="flex-1 break-all bg-slate-100/80 p-2 rounded-xl border border-slate-200/60">
                  <span v-for="(byteDiff, bIdx) in pair.diffA" :key="'int-a-' + bIdx"
                    :class="[
                      'inline-block px-1 py-0.2 m-0.5 rounded text-[10px]',
                      byteDiff.type === 'match' ? 'bg-emerald-100 text-emerald-900 font-bold' :
                      byteDiff.type === 'diff' ? 'bg-rose-500 text-white font-bold' :
                      'bg-slate-200 text-slate-700'
                    ]">
                    {{ byteDiff.hex }}
                  </span>
                  <div v-if="pair.pktA?.raw_text" class="text-[10px] text-slate-500 mt-1 truncate">
                    文本: {{ pair.pktA.raw_text }}
                  </div>
                </div>
              </div>

              <!-- Channel B -->
              <div class="flex items-start gap-2">
                <span class="w-16 shrink-0 text-[10px] font-bold text-emerald-800 bg-emerald-100 px-1.5 py-0.5 rounded text-center mt-0.5">
                  {{ channelB }}
                </span>
                <div class="flex-1 break-all bg-slate-100/80 p-2 rounded-xl border border-slate-200/60">
                  <span v-for="(byteDiff, bIdx) in pair.diffB" :key="'int-b-' + bIdx"
                    :class="[
                      'inline-block px-1 py-0.2 m-0.5 rounded text-[10px]',
                      byteDiff.type === 'match' ? 'bg-emerald-100 text-emerald-900 font-bold' :
                      byteDiff.type === 'diff' ? 'bg-rose-500 text-white font-bold' :
                      'bg-slate-200 text-slate-700'
                    ]">
                    {{ byteDiff.hex }}
                  </span>
                  <div v-if="pair.pktB?.raw_text" class="text-[10px] text-slate-500 mt-1 truncate">
                    文本: {{ pair.pktB.raw_text }}
                  </div>
                </div>
              </div>
            </div>

          </div>
        </div>

      </div>

      <!-- 4. 底部状态与操作说明栏 -->
      <div class="px-5 py-2.5 border-t border-slate-200/80 bg-white/90 flex items-center justify-between text-xs text-slate-500 shrink-0">
        <div class="flex items-center gap-4">
          <div class="flex items-center gap-1.5">
            <span class="w-2.5 h-2.5 rounded bg-emerald-500"></span>
            <span>一致字节</span>
          </div>
          <div class="flex items-center gap-1.5">
            <span class="w-2.5 h-2.5 rounded bg-rose-500"></span>
            <span>差异/突变字节</span>
          </div>
          <div class="flex items-center gap-1.5">
            <span class="w-2.5 h-2.5 rounded bg-slate-300"></span>
            <span>长度缺失填充</span>
          </div>
        </div>
        <div class="font-mono text-[11px]">
          算法: LCS (Longest Common Subsequence) 时间复杂度 O(M&times;N)
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
  timestamp_ns?: number;
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

interface ByteDiff {
  hex: string;
  type: 'match' | 'diff' | 'missing';
}

interface ComparedPair {
  pktA?: PacketRecord;
  pktB?: PacketRecord;
  diffA: ByteDiff[];
  diffB: ByteDiff[];
  match: boolean;
  similarity: number;
  deltaMs: number | null;
}

const props = defineProps<{
  isOpen: boolean;
  packets: PacketRecord[];
  availablePorts: string[];
  defaultPortA?: string;
  defaultPortB?: string;
}>();

const emit = defineEmits(['close']);

const channelA = ref(props.defaultPortA || (props.availablePorts[0] || ''));
const channelB = ref(props.defaultPortB || (props.availablePorts[1] || props.availablePorts[0] || ''));
const viewMode = ref<'split' | 'interleaved'>('split');
const autoScroll = ref(true);
const scrollContainer = ref<HTMLElement | null>(null);

// 保持可用端口的初始默认选择
watch(() => props.availablePorts, (newPorts) => {
  if (newPorts.length > 0) {
    if (!channelA.value || !newPorts.includes(channelA.value)) {
      channelA.value = newPorts[0];
    }
    if (!channelB.value || !newPorts.includes(channelB.value)) {
      channelB.value = newPorts[1] || newPorts[0];
    }
  }
}, { immediate: true });

// 提取两个通道的独立数据包队列
const channelAPackets = computed(() => {
  if (!channelA.value) return [];
  return props.packets.filter(p => 
    (p.transport === 'SERIAL' || p.direction?.startsWith('SERIAL')) &&
    (p.src_ip === channelA.value || p.dst_ip === channelA.value || p.business_data?.serial_interface === channelA.value)
  );
});

const channelBPackets = computed(() => {
  if (!channelB.value) return [];
  return props.packets.filter(p => 
    (p.transport === 'SERIAL' || p.direction?.startsWith('SERIAL')) &&
    (p.src_ip === channelB.value || p.dst_ip === channelB.value || p.business_data?.serial_interface === channelB.value)
  );
});

/**
 * 将 Hex 字符串拆分为 2 字符的字节数组
 */
function splitHexBytes(hex: string): string[] {
  const clean = hex.replace(/\s+/g, '');
  const bytes: string[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    bytes.push(clean.substring(i, i + 2).toUpperCase());
  }
  return bytes;
}

/**
 * 计算 LCS (Longest Common Subsequence) 差异
 * 时间复杂度: O(M * N)，空间复杂度: O(M * N)
 */
function computeLcsDiff(bytesA: string[], bytesB: string[]): { diffA: ByteDiff[]; diffB: ByteDiff[]; similarity: number } {
  const m = bytesA.length;
  const n = bytesB.length;

  if (m === 0 && n === 0) {
    return { diffA: [], diffB: [], similarity: 100 };
  }
  if (m === 0) {
    return {
      diffA: [],
      diffB: bytesB.map(b => ({ hex: b, type: 'diff' })),
      similarity: 0
    };
  }
  if (n === 0) {
    return {
      diffA: bytesA.map(b => ({ hex: b, type: 'diff' })),
      diffB: [],
      similarity: 0
    };
  }

  // 动态规划表
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (bytesA[i - 1] === bytesB[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  const lcsLen = dp[m][n];
  const maxLen = Math.max(m, n);
  const similarity = maxLen > 0 ? (lcsLen / maxLen) * 100 : 100;

  // 位置对齐比较
  const diffA: ByteDiff[] = [];
  const diffB: ByteDiff[] = [];

  for (let i = 0; i < maxLen; i++) {
    const bA = bytesA[i];
    const bB = bytesB[i];

    if (bA !== undefined && bB !== undefined) {
      if (bA === bB) {
        diffA.push({ hex: bA, type: 'match' });
        diffB.push({ hex: bB, type: 'match' });
      } else {
        diffA.push({ hex: bA, type: 'diff' });
        diffB.push({ hex: bB, type: 'diff' });
      }
    } else if (bA !== undefined) {
      diffA.push({ hex: bA, type: 'diff' });
      diffB.push({ hex: '--', type: 'missing' });
    } else {
      diffA.push({ hex: '--', type: 'missing' });
      diffB.push({ hex: bB!, type: 'diff' });
    }
  }

  return { diffA, diffB, similarity };
}

/**
 * 构造对齐比对数据组
 */
const comparedPairs = computed(() => {
  const pktsA = channelAPackets.value;
  const pktsB = channelBPackets.value;
  const maxCount = Math.max(pktsA.length, pktsB.length);
  const pairs: ComparedPair[] = [];

  for (let i = 0; i < maxCount; i++) {
    const pA = pktsA[i];
    const pB = pktsB[i];

    const bytesA = pA ? splitHexBytes(pA.payload_hex) : [];
    const bytesB = pB ? splitHexBytes(pB.payload_hex) : [];

    const { diffA, diffB, similarity } = computeLcsDiff(bytesA, bytesB);

    let deltaMs: number | null = null;
    if (pA && pB) {
      if (pA.timestamp_ns && pB.timestamp_ns) {
        deltaMs = Math.abs(Number(pA.timestamp_ns - pB.timestamp_ns)) / 1_000_000;
      }
    }

    const match = pA && pB ? pA.payload_hex === pB.payload_hex : false;

    pairs.push({
      pktA: pA,
      pktB: pB,
      diffA,
      diffB,
      match,
      similarity,
      deltaMs
    });
  }

  return pairs;
});

// 计算总匹配率
const matchRate = computed(() => {
  const pairs = comparedPairs.value;
  if (pairs.length === 0) return 100;
  const matchCount = pairs.filter(p => p.match).length;
  return (matchCount / pairs.length) * 100;
});

// 监听数据增长并执行自动滚动
watch(comparedPairs, async () => {
  if (autoScroll.value && scrollContainer.value) {
    await nextTick();
    scrollContainer.value.scrollTop = scrollContainer.value.scrollHeight;
  }
});

function clearBuffer() {
  // 清空可通过外部或重置触发
}

/**
 * 导出多串口比对报告 (CSV 格式)
 */
function exportReport() {
  const pairs = comparedPairs.value;
  if (pairs.length === 0) return;

  let csv = '序号,通道A时间,通道A字节,通道B时间,通道B字节,时延差(ms),LCS相似度(%),是否一致,通道A载荷HEX,通道B载荷HEX\n';
  pairs.forEach((p, idx) => {
    const timeA = p.pktA?.timestamp || '';
    const lenA = p.pktA?.length || 0;
    const timeB = p.pktB?.timestamp || '';
    const lenB = p.pktB?.length || 0;
    const delta = p.deltaMs !== null ? p.deltaMs.toFixed(3) : '';
    const sim = p.similarity.toFixed(2);
    const isMatch = p.match ? '一致' : '差异';
    const hexA = p.pktA?.payload_hex || '';
    const hexB = p.pktB?.payload_hex || '';

    csv += `${idx + 1},"${timeA}",${lenA},"${timeB}",${lenB},${delta},${sim},${isMatch},"${hexA}","${hexB}"\n`;
  });

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `serial_compare_${channelA.value}_vs_${channelB.value}_${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}
</script>

<style scoped>
.custom-scrollbar::-webkit-scrollbar { width: 5px; height: 5px; }
.custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
.custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(148, 163, 184, 0.4); border-radius: 9999px; }
.custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(100, 116, 139, 0.6); }
</style>
