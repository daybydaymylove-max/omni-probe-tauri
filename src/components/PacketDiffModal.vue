<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-md p-4 animate-in fade-in duration-200">
    <!-- 主模态视窗 (Beyond Compare + Wireshark 工业级双栏工作台) -->
    <div class="w-full max-w-7xl h-[90vh] bg-slate-900/95 backdrop-blur-2xl rounded-2xl border border-slate-700/80 shadow-2xl flex flex-col overflow-hidden text-slate-100 font-sans">
      
      <!-- 1. 顶部控制栏与对比摘要胶囊 -->
      <div class="px-5 py-3 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center shadow-md">
            <span class="text-sm">⚖️</span>
          </div>
          <div>
            <h2 class="text-sm font-bold text-white flex items-center gap-2">
              <span>专业报文协议与 Hex 双栏差分工作台</span>
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                Wireshark + Beyond Compare 对齐
              </span>
            </h2>
            <div class="text-[11px] text-slate-400">
              {{ diffResult?.summary || '逐字节 LCS 严格对齐与多层协议树逐字段比对' }}
            </div>
          </div>
        </div>

        <!-- 模式切换分段控件 -->
        <div class="flex bg-slate-800/90 p-1 rounded-xl border border-slate-700/80 text-xs font-semibold">
          <button @click="activeMode = 'hex'"
            :class="['px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
              activeMode === 'hex' ? 'bg-indigo-600 text-white shadow-sm font-bold' : 'text-slate-400 hover:text-white']">
            <span>🔠 逐字节 Hex 同步比对</span>
          </button>
          <button @click="activeMode = 'fields'"
            :class="['px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
              activeMode === 'fields' ? 'bg-indigo-600 text-white shadow-sm font-bold' : 'text-slate-400 hover:text-white']">
            <span>🌲 协议树字段差异</span>
            <span v-if="differentFieldsCount > 0" class="px-1.5 py-0.2 rounded-full text-[9px] bg-rose-500 text-white font-mono font-bold">
              {{ differentFieldsCount }}
            </span>
          </button>
          <button @click="activeMode = 'samples'"
            :class="['px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
              activeMode === 'samples' ? 'bg-indigo-600 text-white shadow-sm font-bold' : 'text-slate-400 hover:text-white']">
            <span>📦 报文样本库</span>
            <span v-if="storedSamples.length > 0" class="px-1.5 py-0.2 rounded-full text-[9px] bg-slate-700 text-slate-300 font-mono">
              {{ storedSamples.length }}
            </span>
          </button>
        </div>

        <!-- 差异突变率指示卡 -->
        <div v-if="diffResult" class="flex items-center gap-3 bg-slate-800/80 px-3 py-1.5 rounded-xl border border-slate-700 text-xs font-mono">
          <div class="text-[11px] text-slate-400">
            突变字节: <strong class="text-rose-400">{{ diffResult.mutated_bytes_count }}</strong> / {{ Math.max(diffResult.total_bytes_a, diffResult.total_bytes_b) }}
          </div>
          <div class="w-24 bg-slate-700 h-2 rounded-full overflow-hidden">
            <div class="h-full transition-all duration-300"
              :class="diffResult.mutation_rate_percent > 30 ? 'bg-rose-500' : 'bg-amber-400'"
              :style="{ width: `${Math.min(100, diffResult.mutation_rate_percent)}%` }"></div>
          </div>
          <span :class="['text-[11px] font-bold', diffResult.mutation_rate_percent > 30 ? 'text-rose-400' : 'text-amber-300']">
            {{ diffResult.mutation_rate_percent.toFixed(1) }}%
          </span>
        </div>

        <!-- 导出与关闭按钮组 -->
        <div class="flex items-center gap-2">
          <button v-if="diffResult" @click="exportDiffReport"
            class="px-3 py-1.5 rounded-xl bg-indigo-600/30 hover:bg-indigo-600 text-indigo-200 hover:text-white border border-indigo-500/40 text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
            title="导出双报文差异分析报告 (Markdown)">
            <span>📥</span>
            <span>导出差分报告</span>
          </button>
          <button @click="$emit('close')"
            class="w-8 h-8 rounded-xl bg-slate-800 hover:bg-rose-600 hover:text-white text-slate-400 flex items-center justify-center transition-colors cursor-pointer border border-slate-700"
            title="关闭视窗">
            ✕
          </button>
        </div>
      </div>

      <!-- 2. 双报文元信息对比条 (Header Compare Bar) -->
      <div class="px-5 py-2.5 bg-slate-950/60 border-b border-slate-800 text-xs font-mono shrink-0 flex items-center gap-3">
        <!-- 左侧：基准报文 A -->
        <div class="flex-1 flex items-center justify-between bg-slate-900/80 border border-slate-700/80 px-3 py-1.5 rounded-xl">
          <div class="flex items-center gap-2 truncate">
            <span class="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 text-[10px] font-bold">
              基准报文 A
            </span>
            <span class="font-bold text-white truncate">{{ packetA ? `#${packetA.id} ${packetA.protocol}` : '未指定' }}</span>
            <span class="text-slate-400 truncate text-[11px]" v-if="packetA">
              {{ packetA.src_ip }}:{{ packetA.src_port }} ➔ {{ packetA.dst_ip }}:{{ packetA.dst_port }}
            </span>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <span class="text-[10px] text-slate-400 font-normal">{{ packetA ? `${packetA.length} 字节` : '' }}</span>
            <button v-if="packetA" @click="doSaveSample(packetA, 'A')"
              class="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-0.5 rounded-lg border border-slate-700 transition-colors cursor-pointer"
              title="将报文 A 保存到样本库">
              💾 存为样本
            </button>
          </div>
        </div>

        <!-- 中间：互换 A ⇄ B 按钮 -->
        <button @click="swapPackets" :disabled="!packetA || !packetB"
          class="shrink-0 w-8 h-8 rounded-xl bg-slate-800/80 hover:bg-indigo-600/40 text-slate-300 hover:text-white border border-slate-700 flex items-center justify-center transition-all cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed shadow-xs"
          title="互换基准报文 A 与比对报文 B 的比对方向">
          🔄
        </button>

        <!-- 右侧：比对报文 B -->
        <div class="flex-1 flex items-center justify-between bg-slate-900/80 border border-slate-700/80 px-3 py-1.5 rounded-xl">
          <div class="flex items-center gap-2 truncate">
            <span class="px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-[10px] font-bold">
              比对报文 B
            </span>
            <span class="font-bold text-white truncate">{{ packetB ? `#${packetB.id} ${packetB.protocol}` : '未指定' }}</span>
            <span class="text-slate-400 truncate text-[11px]" v-if="packetB">
              {{ packetB.src_ip }}:{{ packetB.src_port }} ➔ {{ packetB.dst_ip }}:{{ packetB.dst_port }}
            </span>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <span class="text-[10px] text-slate-400 font-normal">{{ packetB ? `${packetB.length} 字节` : '' }}</span>
            <button v-if="packetB" @click="doSaveSample(packetB, 'B')"
              class="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-0.5 rounded-lg border border-slate-700 transition-colors cursor-pointer"
              title="将报文 B 保存到样本库">
              💾 存为样本
            </button>
          </div>
        </div>
      </div>

      <!-- 3. 主体视窗：根据 activeMode 呈现 -->
      <div class="flex-1 overflow-hidden min-h-0 relative">
        
        <!-- 模式一：逐字节 Hex 同步滚动对齐对比 (Beyond Compare 核心) -->
        <div v-show="activeMode === 'hex'" class="h-full grid grid-cols-2 gap-px bg-slate-800">
          
          <!-- 左栏：报文 A Hex 视窗 -->
          <div ref="hexScrollA" @scroll="onScrollA"
            class="h-full overflow-y-auto overflow-x-hidden bg-slate-950 p-4 font-mono text-xs select-text custom-scrollbar">
            <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2 border-b border-slate-800 pb-1 flex justify-between">
              <span>偏移量 | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
              <span>ASCII 预览</span>
            </div>

            <div v-if="diffResult?.hex_diff_a?.hex_rows" class="space-y-1">
              <div v-for="row in diffResult.hex_diff_a.hex_rows" :key="row.offset"
                class="flex items-center justify-between hover:bg-slate-900/80 px-1 py-0.5 rounded transition-colors">
                <!-- 偏移量 -->
                <span class="text-slate-500 select-none w-12 shrink-0">{{ row.offset }}</span>

                <!-- 16 字节十六进制区 -->
                <div class="flex items-center gap-1.5 flex-1 mx-2">
                  <div class="flex items-center gap-1">
                    <span v-for="(cell, ci) in row.cells.slice(0, 8)" :key="ci"
                      :class="['px-1 py-0.2 rounded-xs text-center min-w-[20px] transition-all', getCellClass(cell.diff_type)]"
                      :title="cell.diff_type !== 'equal' ? `突变类型: ${cell.diff_type}` : ''">
                      {{ cell.hex }}
                    </span>
                  </div>
                  <span class="text-slate-700 select-none">|</span>
                  <div class="flex items-center gap-1">
                    <span v-for="(cell, ci) in row.cells.slice(8, 16)" :key="ci"
                      :class="['px-1 py-0.2 rounded-xs text-center min-w-[20px] transition-all', getCellClass(cell.diff_type)]"
                      :title="cell.diff_type !== 'equal' ? `突变类型: ${cell.diff_type}` : ''">
                      {{ cell.hex }}
                    </span>
                  </div>
                </div>

                <!-- ASCII 字符区 -->
                <div class="text-slate-400 select-none w-28 shrink-0 tracking-widest pl-2 border-l border-slate-800 text-[11px]">
                  {{ row.ascii_repr }}
                </div>
              </div>
            </div>
            <div v-else class="text-center text-slate-500 py-16">
              请选择两个有效报文执行比对
            </div>
          </div>

          <!-- 右栏：报文 B Hex 视窗 -->
          <div ref="hexScrollB" @scroll="onScrollB"
            class="h-full overflow-y-auto overflow-x-hidden bg-slate-950 p-4 font-mono text-xs select-text custom-scrollbar">
            <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2 border-b border-slate-800 pb-1 flex justify-between">
              <span>偏移量 | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
              <span>ASCII 预览</span>
            </div>

            <div v-if="diffResult?.hex_diff_b?.hex_rows" class="space-y-1">
              <div v-for="row in diffResult.hex_diff_b.hex_rows" :key="row.offset"
                class="flex items-center justify-between hover:bg-slate-900/80 px-1 py-0.5 rounded transition-colors">
                <!-- 偏移量 -->
                <span class="text-slate-500 select-none w-12 shrink-0">{{ row.offset }}</span>

                <!-- 16 字节十六进制区 -->
                <div class="flex items-center gap-1.5 flex-1 mx-2">
                  <div class="flex items-center gap-1">
                    <span v-for="(cell, ci) in row.cells.slice(0, 8)" :key="ci"
                      :class="['px-1 py-0.2 rounded-xs text-center min-w-[20px] transition-all', getCellClass(cell.diff_type)]"
                      :title="cell.diff_type !== 'equal' ? `突变类型: ${cell.diff_type}` : ''">
                      {{ cell.hex }}
                    </span>
                  </div>
                  <span class="text-slate-700 select-none">|</span>
                  <div class="flex items-center gap-1">
                    <span v-for="(cell, ci) in row.cells.slice(8, 16)" :key="ci"
                      :class="['px-1 py-0.2 rounded-xs text-center min-w-[20px] transition-all', getCellClass(cell.diff_type)]"
                      :title="cell.diff_type !== 'equal' ? `突变类型: ${cell.diff_type}` : ''">
                      {{ cell.hex }}
                    </span>
                  </div>
                </div>

                <!-- ASCII 字符区 -->
                <div class="text-slate-400 select-none w-28 shrink-0 tracking-widest pl-2 border-l border-slate-800 text-[11px]">
                  {{ row.ascii_repr }}
                </div>
              </div>
            </div>
            <div v-else class="text-center text-slate-500 py-16">
              请选择两个有效报文执行比对
            </div>
          </div>
        </div>

        <!-- 模式二：协议树逐字段差异比对 (Wireshark 协议解析比对) -->
        <div v-show="activeMode === 'fields'" class="h-full overflow-auto bg-slate-950 p-4 custom-scrollbar">
          <table class="w-full text-left text-xs font-mono border-collapse table-fixed">
            <thead class="bg-slate-900 border-b border-slate-800 text-[10px] font-bold text-slate-400 uppercase sticky top-0 z-10">
              <tr>
                <th class="p-2.5 w-[16%]">规约分层</th>
                <th class="p-2.5 w-[24%]">协议字段名称</th>
                <th class="p-2.5 w-[24%]">报文 A 取值 (基准)</th>
                <th class="p-2.5 w-[24%]">报文 B 取值 (比对)</th>
                <th class="p-2.5 w-[12%] text-center">比对状态</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/80 text-[11px]">
              <tr v-for="(f, idx) in diffResult?.field_diffs || []" :key="idx"
                :class="['hover:bg-slate-900/60 transition-colors',
                  f.is_different ? 'bg-amber-950/20' : '']">
                <td class="p-2.5 font-bold text-slate-400 truncate">{{ f.layer }}</td>
                <td class="p-2.5 text-white font-semibold truncate">{{ f.field_name }}</td>
                <td class="p-2.5 text-slate-300 truncate" :title="f.val_a">
                  <span :class="f.is_different ? 'text-amber-300 font-bold' : ''">{{ f.val_a || '—' }}</span>
                </td>
                <td class="p-2.5 text-slate-300 truncate" :title="f.val_b">
                  <span :class="f.is_different ? 'text-rose-400 font-bold' : ''">{{ f.val_b || '—' }}</span>
                </td>
                <td class="p-2.5 text-center truncate">
                  <span :class="['px-2 py-0.5 rounded text-[9px] font-bold',
                    f.diff_type === 'EQUAL' ? 'bg-slate-800 text-slate-400 border border-slate-700' :
                    f.diff_type === 'CHANGED' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                    f.diff_type === 'ADDED_IN_B' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' :
                    'bg-rose-500/20 text-rose-300 border border-rose-500/40']">
                    {{ f.diff_type === 'EQUAL' ? '一致' : f.diff_type === 'CHANGED' ? '差异' : f.diff_type === 'ADDED_IN_B' ? 'B 新增' : 'B 缺失' }}
                  </span>
                </td>
              </tr>
              <tr v-if="!diffResult?.field_diffs || diffResult.field_diffs.length === 0">
                <td colspan="5" class="p-12 text-center text-slate-500">
                  暂无协议字段比对数据
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 模式三：报文特征样本库管理 (Packet Sample Archival) -->
        <div v-show="activeMode === 'samples'" class="h-full overflow-auto bg-slate-950 p-5 space-y-3 custom-scrollbar">
          <div class="flex items-center justify-between border-b border-slate-800 pb-2">
            <div class="text-xs text-slate-300">
              已固化报文样本库 (共 <strong>{{ storedSamples.length }}</strong> 笔历史样本)
            </div>
            <button @click="loadStoredSamples"
              class="bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs px-3 py-1 rounded-xl border border-slate-700 transition-colors cursor-pointer">
              ⟳ 刷新样本库
            </button>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div v-for="s in storedSamples" :key="s.id"
              class="bg-slate-900 border border-slate-800 p-3 rounded-xl flex flex-col gap-2 hover:border-slate-700 transition-all">
              <div class="flex items-center justify-between">
                <span class="font-bold text-white text-xs truncate max-w-[280px]" :title="s.name">{{ s.name }}</span>
                <span class="text-[10px] font-mono text-slate-500">{{ s.created_at }}</span>
              </div>
              <div class="text-[11px] font-mono text-slate-400 bg-slate-950/80 p-2 rounded-lg border border-slate-800/80">
                <div>报文: #{{ s.packet.id }} | 规约: <strong class="text-indigo-400">{{ s.packet.protocol }}</strong> | 长度: {{ s.packet.length }} 字节</div>
                <div>端点: {{ s.packet.src_ip }}:{{ s.packet.src_port }} ➔ {{ s.packet.dst_ip }}:{{ s.packet.dst_port }}</div>
              </div>
              <div class="flex items-center gap-2 text-xs">
                <button @click="$emit('selectAsA', s.packet)"
                  class="flex-1 bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 py-1 rounded-lg transition-colors cursor-pointer font-semibold">
                  设为基准报文 A
                </button>
                <button @click="$emit('selectAsB', s.packet)"
                  class="flex-1 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 py-1 rounded-lg transition-colors cursor-pointer font-semibold">
                  设为比对报文 B
                </button>
                <button @click="doDeleteSample(s.id)"
                  class="bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 px-2 py-1 rounded-lg transition-colors cursor-pointer">
                  🗑️
                </button>
              </div>
            </div>

            <div v-if="storedSamples.length === 0" class="col-span-2 p-12 text-center text-slate-500 text-xs">
              样本库为空。您可以在上方点击【存为样本】将抓获的特征报文持久化归档。
            </div>
          </div>
        </div>

      </div>

      <!-- 4. 底部状态与操作栏 -->
      <div class="px-5 py-2.5 bg-slate-900 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 shrink-0 font-mono">
        <div class="flex items-center gap-3">
          <span class="flex items-center gap-1.5">
            <span class="w-2 h-2 rounded-full bg-rose-500"></span>
            <span>红色高亮: 突变/替换/删除</span>
          </span>
          <span class="flex items-center gap-1.5">
            <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span>绿色高亮: 突变插入</span>
          </span>
          <span class="flex items-center gap-1.5">
            <span class="w-2 h-2 rounded-full bg-slate-600"></span>
            <span>灰色: 相同字节</span>
          </span>
        </div>

        <div class="flex items-center gap-2">
          <button @click="$emit('close')"
            class="bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-1.5 rounded-xl border border-slate-700 transition-colors cursor-pointer font-semibold">
            关闭视窗
          </button>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { notifySuccess, notifyInfo, notifyError } from '../composables/useNotification';
import { invoke } from '@tauri-apps/api/core';

export interface ByteCell {
  hex: string;
  ascii: string;
  diff_type: string; // "equal"|"replace"|"insert"|"delete"
}

export interface HexRow {
  offset: string;
  cells: ByteCell[];
  ascii_repr: string;
}

export interface ParsedPayload {
  label: string;
  byte_length: number;
  hex_rows: HexRow[];
}

export interface FieldDiffItem {
  layer: string;
  field_name: string;
  val_a: string;
  val_b: string;
  is_different: boolean;
  diff_type: string;
}

export interface DualPacketDiffResult {
  packet_a_id: number;
  packet_b_id: number;
  packet_a_desc: string;
  packet_b_desc: string;
  total_bytes_a: number;
  total_bytes_b: number;
  mutated_bytes_count: number;
  mutation_rate_percent: number;
  hex_diff_a: ParsedPayload;
  hex_diff_b: ParsedPayload;
  field_diffs: FieldDiffItem[];
  summary: string;
}

export interface StoredPacketSample {
  id: string;
  name: string;
  created_at: string;
  packet: any;
}

const props = defineProps<{
  isOpen: boolean;
  packetA: any | null;
  packetB: any | null;
}>();

const emit = defineEmits(['close', 'selectAsA', 'selectAsB', 'appendLog']);

const activeMode = ref<'hex' | 'fields' | 'samples'>('hex');
const diffResult = ref<DualPacketDiffResult | null>(null);
const storedSamples = ref<StoredPacketSample[]>([]);

// 同步滚动相关引用与标记
const hexScrollA = ref<HTMLElement | null>(null);
const hexScrollB = ref<HTMLElement | null>(null);
let isSyncingA = false;
let isSyncingB = false;

function onScrollA() {
  if (isSyncingA || !hexScrollA.value || !hexScrollB.value) return;
  isSyncingB = true;
  hexScrollB.value.scrollTop = hexScrollA.value.scrollTop;
  requestAnimationFrame(() => { isSyncingB = false; });
}

function onScrollB() {
  if (isSyncingB || !hexScrollA.value || !hexScrollB.value) return;
  isSyncingA = true;
  hexScrollA.value.scrollTop = hexScrollB.value.scrollTop;
  requestAnimationFrame(() => { isSyncingA = false; });
}

function getCellClass(diffType: string): string {
  if (diffType === 'replace' || diffType === 'delete') {
    return 'bg-rose-600 text-white font-bold shadow-xs';
  }
  if (diffType === 'insert') {
    return 'bg-emerald-600 text-white font-bold shadow-xs';
  }
  return 'text-slate-400 hover:text-white';
}

const differentFieldsCount = computed(() => {
  if (!diffResult.value?.field_diffs) return 0;
  return diffResult.value.field_diffs.filter(f => f.is_different).length;
});

async function runCompare() {
  if (!props.packetA || !props.packetB) return;
  try {
    const res = await invoke<DualPacketDiffResult>('compare_two_packets_cmd', {
      packetA: props.packetA,
      packetB: props.packetB
    });
    diffResult.value = res;
  } catch (e: any) {
    console.error('双报文深度差分失败:', e);
  }
}

async function loadStoredSamples() {
  try {
    const res = await invoke<StoredPacketSample[]>('list_packet_samples_cmd');
    storedSamples.value = res || [];
  } catch (e: any) {
    console.error('加载报文样本库失败:', e);
  }
}

async function doSaveSample(packet: any, slot: 'A' | 'B') {
  const defaultName = `样本_#${packet.id}_${packet.protocol}_${slot}`;
  const name = prompt('请输入该报文样本归档名称:', defaultName);
  if (!name) return;
  try {
    await invoke('save_packet_sample_cmd', {
      name: name.trim(),
      packet
    });
    await loadStoredSamples();
    emit('appendLog', `[DIFF] ✓ 报文 #${packet.id} 已固化为特征样本: ${name}`);
    notifySuccess('特征样本固化成功', `报文 #${packet.id} 已成功归档为样本: ${name}`);
  } catch (e: any) {
    notifyError('保存特征样本受阻', e);
  }
}

async function doDeleteSample(id: string) {
  if (!confirm('确定要删除此份历史报文样本吗？')) return;
  try {
    await invoke('delete_packet_sample_cmd', { id });
    await loadStoredSamples();
    notifyInfo('特征样本已移除', '该样本已从本地样本库中安全删除');
  } catch (e: any) {
    notifyError('删除特征样本受阻', e);
  }
}

function swapPackets() {
  if (!props.packetA || !props.packetB) return;
  const tempA = props.packetA;
  emit('selectAsA', props.packetB);
  emit('selectAsB', tempA);
}

function exportDiffReport() {
  if (!diffResult.value) return;
  const res = diffResult.value;
  const timeStr = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '');

  let md = `# Omni-Probe 双报文协议与 Hex 差分分析报告\n\n`;
  md += `- **分析生成时间**: ${timeStr}\n`;
  md += `- **基准报文 A**: #${res.packet_a_id} (${props.packetA?.protocol || 'N/A'}) - ${props.packetA?.src_ip}:${props.packetA?.src_port} ➔ ${props.packetA?.dst_ip}:${props.packetA?.dst_port} (${res.total_bytes_a} 字节)\n`;
  md += `- **比对报文 B**: #${res.packet_b_id} (${props.packetB?.protocol || 'N/A'}) - ${props.packetB?.src_ip}:${props.packetB?.src_port} ➔ ${props.packetB?.dst_ip}:${props.packetB?.dst_port} (${res.total_bytes_b} 字节)\n`;
  md += `- **比对结论**: ${res.summary}\n`;
  md += `- **突变字节数**: ${res.mutated_bytes_count} / ${Math.max(res.total_bytes_a, res.total_bytes_b)} (突变率: ${res.mutation_rate_percent.toFixed(2)}%)\n\n`;

  md += `## 1. 协议树逐字段比对清单\n\n`;
  md += `| 规约分层 | 协议字段 | 报文 A 取值 | 报文 B 取值 | 比对状态 |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- |\n`;
  if (res.field_diffs && res.field_diffs.length > 0) {
    res.field_diffs.forEach(f => {
      const status = f.diff_type === 'EQUAL' ? '一致' : f.diff_type === 'CHANGED' ? '**差异**' : f.diff_type === 'ADDED_IN_B' ? 'B新增' : 'B缺失';
      md += `| ${f.layer} | ${f.field_name} | \`${f.val_a || '-'}\` | \`${f.val_b || '-'}\` | ${status} |\n`;
    });
  } else {
    md += `| 规约层 | 无字段差异记录 | - | - | 一致 |\n`;
  }

  md += `\n## 2. 载荷十六进制 Myers 差分对齐\n\n`;
  md += `### 报文 A (基准):\n\`\`\`\n`;
  if (res.hex_diff_a?.hex_rows) {
    res.hex_diff_a.hex_rows.forEach(r => {
      const hexStr = r.cells.map(c => c.hex).join(' ');
      md += `${r.offset}  ${hexStr.padEnd(48, ' ')}  |${r.ascii_repr}|\n`;
    });
  }
  md += `\`\`\`\n\n`;

  md += `### 报文 B (比对):\n\`\`\`\n`;
  if (res.hex_diff_b?.hex_rows) {
    res.hex_diff_b.hex_rows.forEach(r => {
      const hexStr = r.cells.map(c => c.hex).join(' ');
      md += `${r.offset}  ${hexStr.padEnd(48, ' ')}  |${r.ascii_repr}|\n`;
    });
  }
  md += `\`\`\`\n\n`;

  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `packet_diff_#${res.packet_a_id}_vs_#${res.packet_b_id}_${Date.now()}.md`;
  a.click();
  URL.revokeObjectURL(url);
  notifySuccess('差分分析报告已导出', `已成功生成报文 #${res.packet_a_id} 与 #${res.packet_b_id} 的 Markdown 报告`);
}

watch(() => [props.packetA, props.packetB, props.isOpen], () => {
  if (props.isOpen && props.packetA && props.packetB) {
    runCompare();
  }
}, { immediate: true });

onMounted(() => {
  loadStoredSamples();
});
</script>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: rgba(15, 23, 42, 0.6);
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(51, 65, 85, 0.8);
  border-radius: 9999px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(71, 85, 105, 1);
}
</style>
