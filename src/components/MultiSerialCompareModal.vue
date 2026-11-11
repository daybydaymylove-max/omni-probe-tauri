<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 ui-modal-backdrop animate-in fade-in duration-200">
    <div class="ui-modal-surface rounded-2xl w-full max-w-6xl max-h-[92vh] flex flex-col overflow-hidden">
      <span class="lens-edge-lip" aria-hidden="true"></span>

      <!-- 1. 模态框顶栏 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-5 py-3 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-indigo-500/15 border border-indigo-500/30 text-indigo-700 dark:text-indigo-300 flex items-center justify-center shrink-0">
            <AppIcon name="scale" :size="16" />
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h3 class="text-sm font-bold leading-tight" style="color: var(--text-primary)">多串口数据实时交叉比对终端</h3>
              <span class="text-[11px] font-semibold bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 px-2 py-0.5 rounded-full border border-indigo-500/25">
                {{ channels.length }} 通道时序 LCS 对齐差分
              </span>
            </div>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">
              支持 2～4 路 COM 串口全双工同步对照、真实 LCS DP 回溯字节对齐与传输延迟抖动 (Δt) 分析
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <button
            v-if="comparedGroups.length > 0"
            @click="sendGroupToGlobalDiff(comparedGroups[comparedGroups.length - 1])"
            class="ui-btn-primary text-xs px-3 py-1.5 rounded-xl"
            title="将最新一轮多路串口帧送入全局多组中心对齐对比台"
          >
            <AppIcon name="layers" :size="13" />
            <span>送入全局多组精密矩阵</span>
          </button>
          <button @click="exportReport" :disabled="comparedGroups.length === 0" class="ui-btn-secondary text-xs px-3 py-1.5 rounded-xl">
            <AppIcon name="download" :size="13" />
            <span>导出比对报表</span>
          </button>
          <button @click="$emit('close')" class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer" title="关闭">
            <AppIcon name="close" :size="15" />
          </button>
        </div>
      </header>

      <!-- 2. 多路通道动态控制栏 -->
      <div class="px-5 py-2.5 border-b flex items-center justify-between gap-3 flex-wrap shrink-0 bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle)">
        <div class="flex items-center gap-2 flex-wrap text-xs">
          <div
            v-for="(_, cIdx) in channels"
            :key="cIdx"
            class="flex items-center gap-1.5 border px-2.5 py-1 rounded-xl"
            :class="getChannelChipClass(cIdx)"
          >
            <span class="w-2 h-2 rounded-full shrink-0" :style="{ background: getChannelColor(cIdx) }"></span>
            <span class="font-bold">{{ cIdx === 0 ? '基准 A' : `通道 ${String.fromCharCode(65 + cIdx)}` }}:</span>
            <select v-model="channels[cIdx]" class="ui-input ui-num w-auto py-0.5 px-2 text-xs cursor-pointer">
              <option v-for="p in availablePorts" :key="`ch-${cIdx}-${p}`" :value="p">{{ p }}</option>
              <option v-if="availablePorts.length === 0" value="">未发现可用串口</option>
            </select>
            <button
              v-if="channels.length > 2"
              @click="removeChannel(cIdx)"
              class="ml-0.5 opacity-65 hover:opacity-100 cursor-pointer"
              title="移除此对比通道"
            >
              <AppIcon name="close" :size="11" />
            </button>
          </div>

          <button
            v-if="channels.length < 4"
            @click="addChannel"
            class="ui-pill px-2.5 py-1 rounded-xl text-[11px] font-semibold cursor-pointer hover:text-[var(--text-primary)] flex items-center gap-1"
            title="新增第 3 或第 4 路串口同步比对"
          >
            <span>+ 增加串口通道</span>
          </button>

          <div class="flex ui-pill p-0.5 rounded-xl font-semibold text-[11px]">
            <button @click="viewMode = 'split'"
              :class="['px-2.5 py-1 rounded-lg transition-colors cursor-pointer', viewMode === 'split' ? 'bg-[var(--accent-primary)] text-white shadow-xs font-bold' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']">
              多栏同步对照
            </button>
            <button @click="viewMode = 'interleaved'"
              :class="['px-2.5 py-1 rounded-lg transition-colors cursor-pointer', viewMode === 'interleaved' ? 'bg-[var(--accent-primary)] text-white shadow-xs font-bold' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']">
              时序交织堆栈
            </button>
          </div>
        </div>

        <div class="flex items-center gap-2.5 text-xs">
          <div class="flex items-center gap-2 ui-num text-[11px] ui-pill px-3 py-1 rounded-xl">
            <div>比对轮次: <strong class="text-indigo-700 dark:text-indigo-300">{{ comparedGroups.length }}</strong></div>
            <span style="color: var(--border-strong)">|</span>
            <div>全匹配率: <strong :class="matchRate >= 95 ? 'text-emerald-700 dark:text-emerald-400' : matchRate >= 80 ? 'text-amber-700 dark:text-amber-400' : 'text-rose-700 dark:text-rose-400'">{{ matchRate.toFixed(1) }}%</strong></div>
          </div>

          <label class="flex items-center gap-1.5 text-xs font-semibold cursor-pointer select-none" style="color: var(--text-secondary)">
            <input type="checkbox" v-model="autoScroll" class="rounded accent-sky-500 cursor-pointer">
            <span>自动滚屏</span>
          </label>

          <button @click="clearBuffer" class="text-[11px] ui-pill px-2.5 py-1 rounded-lg cursor-pointer">
            清空当前轮次
          </button>
        </div>
      </div>

      <!-- 3. 主比对内容视口 -->
      <div ref="scrollContainer" class="flex-1 overflow-auto custom-scrollbar p-4 min-h-0 select-text bg-transparent">
        <EmptyState
          v-if="comparedGroups.length === 0"
          class="py-16"
          icon="scale"
          title="等待多路串口数据输入"
          :description="`请确认已启动 ${channels.filter(Boolean).join(' / ') || '目标串口'} 的监听，报文抵达后将按真实 LCS 回溯算法执行逐字节对齐高亮。`"
        />

        <!-- 模式 1: 多栏分屏同步对照视图 (动态支持 2~4 路并排) -->
        <div
          v-else-if="viewMode === 'split'"
          class="grid gap-3"
          :class="channels.length <= 2 ? 'grid-cols-1 md:grid-cols-2' : channels.length === 3 ? 'grid-cols-1 lg:grid-cols-3' : 'grid-cols-1 md:grid-cols-2 xl:grid-cols-4'"
        >
          <div
            v-for="(chName, cIdx) in channels"
            :key="`col-${cIdx}`"
            class="ui-content-card flex flex-col overflow-hidden"
          >
            <div class="px-3.5 py-2 border-b flex items-center justify-between text-xs bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle)">
              <span class="font-bold flex items-center gap-1.5 ui-num" style="color: var(--text-primary)">
                <span class="w-2 h-2 rounded-full" :style="{ background: getChannelColor(cIdx) }"></span>
                <span>{{ cIdx === 0 ? '基准 A' : `通道 ${String.fromCharCode(65 + cIdx)}` }}: {{ chName || '未选定' }}</span>
              </span>
              <span class="ui-num text-[11px]" style="color: var(--text-muted)">共 {{ channelPackets[cIdx]?.length || 0 }} 帧</span>
            </div>
            <div class="p-2.5 space-y-2 overflow-auto max-h-[60vh] custom-scrollbar">
              <div
                v-for="(grp, gIdx) in comparedGroups"
                :key="`split-${cIdx}-${gIdx}`"
                class="ui-sub-card p-2.5 text-xs ui-num transition-colors"
                :class="grp.allMatch ? '' : 'border-rose-500/40 bg-rose-500/8'"
              >
                <div class="flex items-center justify-between text-[11px] mb-1 gap-1 flex-wrap" style="color: var(--text-muted)">
                  <span class="font-bold" style="color: var(--text-primary)">
                    #{{ gIdx + 1 }} {{ grp.slots[cIdx]?.pkt ? grp.slots[cIdx].pkt!.timestamp : '—' }}
                  </span>
                  <div class="flex items-center gap-1.5">
                    <span v-if="cIdx > 0 && grp.slots[cIdx]?.deltaMs !== null" class="px-1.5 py-0.5 rounded ui-pill text-[11px]">
                      Δt {{ grp.slots[cIdx].deltaMs!.toFixed(1) }}ms
                    </span>
                    <span v-if="grp.slots[cIdx]?.pkt" class="bg-blue-500/12 text-blue-700 dark:text-sky-300 px-1.5 py-0.5 rounded font-semibold">
                      {{ grp.slots[cIdx].pkt!.length }}B
                    </span>
                    <span v-else>无对应帧</span>
                  </div>
                </div>

                <div v-if="grp.slots[cIdx]?.pkt" class="break-all font-mono-code text-[11px] leading-relaxed">
                  <span
                    v-for="(byteDiff, bIdx) in grp.slots[cIdx].alignedBytes"
                    :key="`b-${cIdx}-${bIdx}`"
                    :class="[
                      'inline-block px-1 py-0.5 m-0.5 rounded text-[11px]',
                      byteDiff.type === 'match' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 font-bold' :
                      byteDiff.type === 'insert' ? 'bg-blue-600 text-white font-bold' :
                      byteDiff.type === 'diff' ? 'bg-rose-600 text-white font-bold' :
                      'ui-pill opacity-50'
                    ]"
                    :title="`对齐位 ${bIdx}: ${byteDiff.hex} (${byteDiff.type})`"
                  >
                    {{ byteDiff.hex }}
                  </span>
                </div>
                <div v-if="grp.slots[cIdx]?.pkt?.raw_text" class="text-[11px] mt-1 truncate border-t pt-1" style="color: var(--text-secondary); border-color: var(--border-subtle)">
                  {{ grp.slots[cIdx].pkt!.raw_text }}
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 模式 2: 时序交织堆栈比对视图 -->
        <div v-else class="space-y-2.5">
          <div
            v-for="(grp, gIdx) in comparedGroups"
            :key="`interleaved-${gIdx}`"
            class="ui-content-card p-3 transition-colors"
            :class="grp.allMatch ? 'hover:border-sky-500/40' : 'border-rose-500/40 bg-rose-500/8'"
          >
            <div class="flex items-center justify-between text-xs pb-2 border-b mb-2 flex-wrap gap-2" style="border-color: var(--border-subtle)">
              <div class="flex items-center gap-2">
                <span class="font-bold ui-num" style="color: var(--text-primary)">比对轮次 #{{ gIdx + 1 }}</span>
                <span
                  :class="grp.allMatch ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' : 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30'"
                  class="text-[11px] font-bold px-2 py-0.5 rounded-full border flex items-center gap-1"
                >
                  <AppIcon :name="grp.allMatch ? 'check' : 'close'" :size="11" />
                  <span>{{ grp.allMatch ? '全通道载荷一致' : '存在长度或字节突变' }}</span>
                </span>
              </div>
              <div class="flex items-center gap-3 text-[11px] ui-num" style="color: var(--text-muted)">
                <span>最小 LCS 相似度: <strong class="text-indigo-700 dark:text-indigo-300 font-bold">{{ grp.minSimilarity.toFixed(1) }}%</strong></span>
                <button @click="sendGroupToGlobalDiff(grp)" class="ui-btn-secondary px-2 py-0.5 text-[11px]">
                  <AppIcon name="scale" :size="11" />
                  <span>深度差分</span>
                </button>
              </div>
            </div>

            <div class="space-y-2 text-xs font-mono-code">
              <div v-for="(slot, cIdx) in grp.slots" :key="`int-slot-${gIdx}-${cIdx}`" class="flex items-start gap-2">
                <span
                  class="w-20 shrink-0 text-[11px] font-bold px-1.5 py-0.5 rounded text-center mt-0.5 border"
                  :class="getChannelChipClass(cIdx)"
                >
                  {{ channels[cIdx] || `CH-${cIdx + 1}` }}
                </span>
                <div class="flex-1 break-all ui-sub-card p-2">
                  <template v-if="slot.pkt">
                    <span
                      v-for="(byteDiff, bIdx) in slot.alignedBytes"
                      :key="`int-b-${cIdx}-${bIdx}`"
                      :class="[
                        'inline-block px-1 py-0.5 m-0.5 rounded text-[11px]',
                        byteDiff.type === 'match' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 font-bold' :
                        byteDiff.type === 'insert' ? 'bg-blue-600 text-white font-bold' :
                        byteDiff.type === 'diff' ? 'bg-rose-600 text-white font-bold' :
                        'ui-pill opacity-50'
                      ]"
                    >
                      {{ byteDiff.hex }}
                    </span>
                    <div class="text-[11px] mt-1 flex justify-between gap-2" style="color: var(--text-muted)">
                      <span class="truncate">{{ slot.pkt.raw_text || 'BINARY STREAM' }}</span>
                      <span v-if="cIdx > 0 && slot.deltaMs !== null" class="shrink-0 ui-num">Δt: {{ slot.deltaMs.toFixed(2) }}ms · 相似 {{ slot.similarity.toFixed(1) }}%</span>
                    </div>
                  </template>
                  <span v-else class="text-[11px]" style="color: var(--text-muted)">该轮次本通道尚未抵达数据帧</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 4. 底部图例状态栏 -->
      <footer class="px-5 py-2.5 border-t flex items-center justify-between text-xs shrink-0 flex-wrap gap-2 bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle); color: var(--text-secondary)">
        <div class="flex items-center gap-4">
          <div class="flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded bg-emerald-500"></span><span>一致字节</span></div>
          <div class="flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded bg-rose-500"></span><span>替换/差异字节</span></div>
          <div class="flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded bg-blue-600"></span><span>前插/新增字节</span></div>
          <div class="flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded bg-slate-400"></span><span>对齐缺失 (-- 插槽)</span></div>
        </div>
        <div class="ui-num text-[11px]" style="color: var(--text-muted)">
          真实回溯 LCS DP 对齐算法 · 消除前插位移错乱
        </div>
      </footer>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick } from 'vue';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';
import { useUniversalDiff } from '../composables/useUniversalDiff';
import { saveTextViaNativeDesktop } from '../composables/useDesktopSave';

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
  type: 'match' | 'diff' | 'insert' | 'missing';
}

interface AlignedSlot {
  pkt?: PacketRecord;
  alignedBytes: ByteDiff[];
  similarity: number;
  deltaMs: number | null;
}

interface ComparedMultiGroup {
  slots: AlignedSlot[];
  allMatch: boolean;
  minSimilarity: number;
}

const props = defineProps<{
  isOpen: boolean;
  packets: PacketRecord[];
  availablePorts: string[];
  defaultPortA?: string;
  defaultPortB?: string;
}>();

defineEmits(['close']);

const diffBus = useUniversalDiff();
const channels = ref<string[]>([
  props.defaultPortA || (props.availablePorts[0] || ''),
  props.defaultPortB || (props.availablePorts[1] || props.availablePorts[0] || ''),
]);
const viewMode = ref<'split' | 'interleaved'>('split');
const autoScroll = ref(true);
const scrollContainer = ref<HTMLElement | null>(null);
const clearFloorIds = ref<Record<string, number>>({});

watch(
  () => props.availablePorts,
  (newPorts) => {
    if (newPorts.length > 0) {
      channels.value = channels.value.map((ch, idx) =>
        ch && newPorts.includes(ch) ? ch : newPorts[idx % newPorts.length]
      );
    }
  },
  { immediate: true }
);

function addChannel() {
  if (channels.value.length >= 4) return;
  const unused = props.availablePorts.find((p) => !channels.value.includes(p));
  channels.value.push(unused || props.availablePorts[0] || '');
}

function removeChannel(idx: number) {
  if (channels.value.length <= 2) return;
  channels.value.splice(idx, 1);
}

function getChannelColor(idx: number): string {
  return ['#38BDF8', '#10B981', '#A855F7', '#F59E0B'][idx % 4];
}

function getChannelChipClass(idx: number): string {
  const classes = [
    'bg-blue-500/10 border-blue-500/25 text-blue-700 dark:text-sky-300',
    'bg-emerald-500/10 border-emerald-500/25 text-emerald-700 dark:text-emerald-300',
    'bg-purple-500/10 border-purple-500/25 text-purple-700 dark:text-purple-300',
    'bg-amber-500/10 border-amber-500/25 text-amber-700 dark:text-amber-300',
  ];
  return classes[idx % 4];
}

const channelPackets = computed<PacketRecord[][]>(() =>
  channels.value.map((ch) => {
    if (!ch) return [];
    const floorId = clearFloorIds.value[ch] || 0;
    return props.packets.filter(
      (p) =>
        p.id > floorId &&
        (p.transport === 'SERIAL' || p.direction?.startsWith('SERIAL')) &&
        (p.src_ip === ch || p.dst_ip === ch || p.business_data?.serial_interface === ch)
    );
  })
);

function splitHexBytes(hex: string): string[] {
  const clean = (hex || '').replace(/\s+/g, '');
  const bytes: string[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    bytes.push(clean.substring(i, i + 2).toUpperCase());
  }
  return bytes;
}

/**
 * 真正通过 DP 回溯实现双序列 LCS 插入/删除/替换对齐（彻底消除同下标硬比导致的错位漂移）
 * 时间复杂度: O(M * N)，空间复杂度: O(M * N)
 */
function backtrackLcsDiff(bytesA: string[], bytesB: string[]): { alignedA: ByteDiff[]; alignedB: ByteDiff[]; similarity: number } {
  const m = bytesA.length;
  const n = bytesB.length;
  if (m === 0 && n === 0) return { alignedA: [], alignedB: [], similarity: 100 };
  if (m === 0) {
    return {
      alignedA: bytesB.map(() => ({ hex: '--', type: 'missing' })),
      alignedB: bytesB.map((b) => ({ hex: b, type: 'insert' })),
      similarity: 0,
    };
  }
  if (n === 0) {
    return {
      alignedA: bytesA.map((b) => ({ hex: b, type: 'diff' })),
      alignedB: bytesA.map(() => ({ hex: '--', type: 'missing' })),
      similarity: 0,
    };
  }

  // 安全阈值: 超大串口突发包 (> 400B) 降级直接对齐保护响应
  if (m * n > 160_000) {
    const maxLen = Math.max(m, n);
    let eq = 0;
    const alignedA: ByteDiff[] = [];
    const alignedB: ByteDiff[] = [];
    for (let i = 0; i < maxLen; i++) {
      const a = bytesA[i];
      const b = bytesB[i];
      if (a === b) eq++;
      alignedA.push(a ? { hex: a, type: a === b ? 'match' : 'diff' } : { hex: '--', type: 'missing' });
      alignedB.push(b ? { hex: b, type: a === b ? 'match' : 'diff' } : { hex: '--', type: 'missing' });
    }
    return { alignedA, alignedB, similarity: (eq / maxLen) * 100 };
  }

  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] =
        bytesA[i - 1] === bytesB[j - 1]
          ? dp[i - 1][j - 1] + 1
          : Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }

  const alignedA: ByteDiff[] = [];
  const alignedB: ByteDiff[] = [];
  let i = m;
  let j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && bytesA[i - 1] === bytesB[j - 1]) {
      alignedA.push({ hex: bytesA[i - 1], type: 'match' });
      alignedB.push({ hex: bytesB[j - 1], type: 'match' });
      i--;
      j--;
    } else if (i > 0 && j > 0 && dp[i - 1][j] === dp[i][j - 1]) {
      // 同等代价值时按原地替换压缩展示长度
      alignedA.push({ hex: bytesA[i - 1], type: 'diff' });
      alignedB.push({ hex: bytesB[j - 1], type: 'diff' });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      alignedA.push({ hex: '--', type: 'missing' });
      alignedB.push({ hex: bytesB[j - 1], type: 'insert' });
      j--;
    } else {
      alignedA.push({ hex: bytesA[i - 1], type: 'diff' });
      alignedB.push({ hex: '--', type: 'missing' });
      i--;
    }
  }

  alignedA.reverse();
  alignedB.reverse();
  const lcsLen = dp[m][n];
  const similarity = (lcsLen / Math.max(m, n)) * 100;
  return { alignedA, alignedB, similarity };
}

const comparedGroups = computed<ComparedMultiGroup[]>(() => {
  const lists = channelPackets.value;
  const maxCount = Math.max(...lists.map((l) => l.length), 0);
  const groups: ComparedMultiGroup[] = [];

  for (let roundIdx = 0; roundIdx < maxCount; roundIdx++) {
    const pkts = lists.map((l) => l[roundIdx]);
    const anchorPkt = pkts[0];
    const bytesAnchor = anchorPkt ? splitHexBytes(anchorPkt.payload_hex) : [];

    const slots: AlignedSlot[] = pkts.map((pkt, cIdx) => {
      if (cIdx === 0) {
        const selfDiff = bytesAnchor.map<ByteDiff>((h) => ({ hex: h, type: 'match' }));
        return { pkt, alignedBytes: selfDiff, similarity: 100, deltaMs: 0 };
      }
      const bytesCur = pkt ? splitHexBytes(pkt.payload_hex) : [];
      const { alignedB, similarity } = backtrackLcsDiff(bytesAnchor, bytesCur);
      let deltaMs: number | null = null;
      if (anchorPkt?.timestamp_ns && pkt?.timestamp_ns) {
        deltaMs = Math.abs(Number(pkt.timestamp_ns - anchorPkt.timestamp_ns)) / 1_000_000;
      }
      return { pkt, alignedBytes: alignedB, similarity, deltaMs };
    });

    // 若只有 2 路通道，顺便把 Anchor 对 B 的缺失槽同步展示出来以直观看到对比对齐
    if (pkts.length === 2 && anchorPkt && pkts[1]) {
      const { alignedA, alignedB } = backtrackLcsDiff(bytesAnchor, splitHexBytes(pkts[1].payload_hex));
      slots[0].alignedBytes = alignedA;
      slots[1].alignedBytes = alignedB;
    }

    const validPkts = pkts.filter((p): p is PacketRecord => Boolean(p));
    const allMatch =
      validPkts.length === channels.value.length &&
      validPkts.every((p) => p.payload_hex === validPkts[0].payload_hex);
    const minSimilarity = Math.min(...slots.map((s) => s.similarity));
    groups.push({ slots, allMatch, minSimilarity });
  }

  return groups;
});

const matchRate = computed(() => {
  const gs = comparedGroups.value;
  if (gs.length === 0) return 100;
  return (gs.filter((g) => g.allMatch).length / gs.length) * 100;
});

watch(comparedGroups, async () => {
  if (autoScroll.value && scrollContainer.value) {
    await nextTick();
    scrollContainer.value.scrollTop = scrollContainer.value.scrollHeight;
  }
});

function clearBuffer() {
  const nextFloors = { ...clearFloorIds.value };
  channels.value.forEach((ch) => {
    if (!ch) return;
    const latest = props.packets.reduce((max, p) => (p.id > max ? p.id : max), 0);
    nextFloors[ch] = latest;
  });
  clearFloorIds.value = nextFloors;
}

function sendGroupToGlobalDiff(grp: ComparedMultiGroup) {
  const validItems = grp.slots
    .map((slot, idx) => ({ slot, ch: channels.value[idx] || `串口 ${idx + 1}` }))
    .filter((x) => Boolean(x.slot.pkt))
    .map(({ slot, ch }) => ({
      ...slot.pkt,
      label: `[串口 ${ch}] #${slot.pkt!.id}`,
      endpoint_src: ch,
      endpoint_dst: slot.pkt!.dst_ip || 'HOST',
    }));

  if (validItems.length >= 2) {
    diffBus.openMultiDiff(validItems, 0, validItems.length > 2 ? 'multi' : 'hex');
  }
}

async function exportReport() {
  const groups = comparedGroups.value;
  if (groups.length === 0) return;

  const chHeaders = channels.value.map((ch, idx) => `通道${idx + 1}(${ch})时间,通道${idx + 1}字节,通道${idx + 1}HEX`).join(',');
  let csv = `轮次,${chHeaders},全匹配,最小相似度(%)\n`;
  groups.forEach((grp, idx) => {
    const cols = grp.slots
      .map((s) => `"${s.pkt?.timestamp || ''}",${s.pkt?.length || 0},"${s.pkt?.payload_hex || ''}"`)
      .join(',');
    csv += `${idx + 1},${cols},${grp.allMatch ? '一致' : '差异'},${grp.minSimilarity.toFixed(2)}\n`;
  });

  await saveTextViaNativeDesktop(
    `serial_multi_compare_${channels.value.filter(Boolean).join('_vs_')}_${Date.now()}.csv`,
    csv,
    'CSV 表格 (*.csv)',
    '*.csv',
    '导出多通道串口比对表'
  );
}
</script>
