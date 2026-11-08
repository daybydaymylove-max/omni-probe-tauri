<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md animate-in fade-in duration-150">
    <div class="w-full max-w-lg bg-white/95 backdrop-blur-2xl rounded-3xl border border-white/60 shadow-2xl flex flex-col overflow-hidden">
      
      <!-- 1. 顶栏 -->
      <div class="px-6 py-4 border-b border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <span class="w-3 h-3 rounded-full bg-teal-500 shadow-sm"></span>
          <div>
            <h3 class="text-sm font-bold text-slate-900">工业级流量与数据帧导出 (Export Pipeline)</h3>
            <p class="text-[11px] text-slate-500 font-mono">支持导出为 PCAPng 司法存证、PCAP (Wireshark)、CSV、JSON 审计或 HAR 归档</p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer">
          ✕
        </button>
      </div>

      <!-- 2. 表单配置区 -->
      <div class="p-6 space-y-4 text-xs font-mono">
        <!-- 导出范围 -->
        <div>
          <label class="block font-bold text-slate-700 mb-1.5">1. 选择导出报文范围 (Scope):</label>
          <div class="grid grid-cols-3 gap-2">
            <button @click="exportScope = 'all'"
              :class="['p-2.5 rounded-xl border text-center transition-all cursor-pointer', exportScope === 'all' ? 'border-teal-500 bg-teal-50 text-teal-800 font-bold shadow-2xs' : 'border-slate-200 hover:bg-slate-50 text-slate-600']">
              <div>全部报文</div>
              <div class="text-[10px] text-slate-400 mt-0.5">{{ allPackets.length }} 帧</div>
            </button>
            <button @click="exportScope = 'filtered'"
              :class="['p-2.5 rounded-xl border text-center transition-all cursor-pointer', exportScope === 'filtered' ? 'border-teal-500 bg-teal-50 text-teal-800 font-bold shadow-2xs' : 'border-slate-200 hover:bg-slate-50 text-slate-600']">
              <div>当前过滤匹配</div>
              <div class="text-[10px] text-slate-400 mt-0.5">{{ filteredPackets.length }} 帧</div>
            </button>
            <button @click="exportScope = 'critical'"
              :class="['p-2.5 rounded-xl border text-center transition-all cursor-pointer', exportScope === 'critical' ? 'border-teal-500 bg-teal-50 text-teal-800 font-bold shadow-2xs' : 'border-slate-200 hover:bg-slate-50 text-slate-600']">
              <div>高熵/异常子集</div>
              <div class="text-[10px] text-slate-400 mt-0.5">{{ criticalPackets.length }} 帧</div>
            </button>
          </div>
        </div>

        <!-- 导出格式 -->
        <div>
          <label class="block font-bold text-slate-700 mb-1.5">2. 选择导出文件格式 (Format):</label>
          <div class="grid grid-cols-2 gap-2">
            <button @click="exportFormat = 'pcapng'"
              :class="['p-2.5 rounded-xl border text-left transition-all cursor-pointer flex items-center gap-2', exportFormat === 'pcapng' ? 'border-teal-600 bg-teal-50/90 text-teal-950 font-bold shadow-2xs ring-2 ring-teal-500/20' : 'border-slate-200 hover:bg-slate-50 text-slate-700']">
              <span class="text-base">🛡️</span>
              <div>
                <div class="text-xs flex items-center gap-1.5">
                  <span>PCAPng 司法存证</span>
                  <span class="text-[9px] bg-teal-600 text-white px-1 py-0.2 rounded font-sans">推荐</span>
                </div>
                <div class="text-[10px] text-slate-400 font-normal">含 SHB/IDB/EPB 结构与哈希存证</div>
              </div>
            </button>

            <button @click="exportFormat = 'pcap'"
              :class="['p-2.5 rounded-xl border text-left transition-all cursor-pointer flex items-center gap-2', exportFormat === 'pcap' ? 'border-blue-500 bg-blue-50/80 text-blue-900 font-bold shadow-2xs' : 'border-slate-200 hover:bg-slate-50 text-slate-700']">
              <span class="text-base">🦈</span>
              <div>
                <div class="text-xs">标准 PCAP 二进制</div>
                <div class="text-[10px] text-slate-400 font-normal">Wireshark 经典 libpcap 帧格式</div>
              </div>
            </button>

            <button @click="exportFormat = 'csv'"
              :class="['p-2.5 rounded-xl border text-left transition-all cursor-pointer flex items-center gap-2', exportFormat === 'csv' ? 'border-emerald-500 bg-emerald-50/80 text-emerald-900 font-bold shadow-2xs' : 'border-slate-200 hover:bg-slate-50 text-slate-700']">
              <span class="text-base">📊</span>
              <div>
                <div class="text-xs">结构化 CSV 流水</div>
                <div class="text-[10px] text-slate-400 font-normal">Excel / Pandas 科学数据统计</div>
              </div>
            </button>

            <button @click="exportFormat = 'json'"
              :class="['p-2.5 rounded-xl border text-left transition-all cursor-pointer flex items-center gap-2', exportFormat === 'json' ? 'border-amber-500 bg-amber-50/80 text-amber-900 font-bold shadow-2xs' : 'border-slate-200 hover:bg-slate-50 text-slate-700']">
              <span class="text-base">📜</span>
              <div>
                <div class="text-xs">JSON 审计明细</div>
                <div class="text-[10px] text-slate-400 font-normal">SIEM / SOC 日志审计直接入库</div>
              </div>
            </button>

            <button @click="exportFormat = 'har'"
              :class="['p-2.5 rounded-xl border text-left transition-all cursor-pointer flex items-center gap-2 col-span-2', exportFormat === 'har' ? 'border-purple-500 bg-purple-50/80 text-purple-900 font-bold shadow-2xs' : 'border-slate-200 hover:bg-slate-50 text-slate-700']">
              <span class="text-base">🌐</span>
              <div>
                <div class="text-xs">HAR 1.2 归档格式</div>
                <div class="text-[10px] text-slate-400 font-normal">HTTP 请求/响应浏览器标准会话归档</div>
              </div>
            </button>
          </div>
        </div>

        <!-- 司法级存证附加注释 (PCAPng 专属) -->
        <div v-if="exportFormat === 'pcapng'" class="p-3 bg-teal-50/60 rounded-xl border border-teal-200/60 space-y-1.5 animate-in fade-in duration-150">
          <div class="flex items-center justify-between text-teal-900 font-bold text-[11px]">
            <span>司法链存证注释 (Section Header Comment):</span>
            <span class="text-[10px] text-teal-600 font-normal">Option Code 0x0001</span>
          </div>
          <input v-model="forensicComment"
            placeholder="例: Omni-Probe Judicial Certified Forensics Chain Hash Verified"
            class="w-full bg-white border border-teal-200 rounded-lg px-2.5 py-1.5 text-[11px] font-mono text-slate-800 focus:outline-none focus:ring-1 focus:ring-teal-500">
        </div>

        <!-- 导出路径与文件名 -->
        <div>
          <label class="block font-bold text-slate-700 mb-1">3. 保存文件绝对路径 (File Path):</label>
          <input v-model="targetFilePath"
            class="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-teal-500/30 shadow-2xs">
          <p class="text-[10px] text-slate-400 mt-1">支持自定义绝对路径，默认保存至当前系统目录</p>
        </div>

        <!-- 状态反馈 -->
        <div v-if="exportStatus" :class="['p-3 rounded-xl text-xs font-mono border', isError ? 'bg-rose-50 text-rose-700 border-rose-200' : 'bg-teal-50 text-teal-800 border-teal-200']">
          {{ exportStatus }}
        </div>
      </div>

      <!-- 3. 底栏操作 -->
      <div class="px-6 py-3 border-t border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <span class="text-[11px] text-slate-400 font-mono">待导出: {{ selectedTargetPackets.length }} 帧</span>
        <div class="flex items-center gap-2">
          <button @click="$emit('close')" class="px-4 py-1.5 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer">
            取消
          </button>
          <button @click="doExport" :disabled="isExporting || selectedTargetPackets.length === 0"
            class="bg-gradient-to-r from-teal-600 to-teal-700 hover:from-teal-700 hover:to-teal-800 text-white text-xs px-5 py-1.5 rounded-xl font-bold cursor-pointer transition-all shadow-sm active:scale-95 disabled:opacity-40">
            <span v-if="isExporting">导出中...</span>
            <span v-else>执行导出</span>
          </button>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';

const props = defineProps<{
  isOpen: boolean;
  allPackets: any[];
  filteredPackets: any[];
}>();

const emit = defineEmits(['close', 'log']);

const exportScope = ref<'all' | 'filtered' | 'critical'>('filtered');
const exportFormat = ref<'pcapng' | 'pcap' | 'csv' | 'json' | 'har'>('pcapng');
const targetFilePath = ref('');
const forensicComment = ref('Omni-Probe Judicial Certified Forensics Chain Hash Verified (GB/T 22239 Level 3)');
const isExporting = ref(false);
const exportStatus = ref('');
const isError = ref(false);

const criticalPackets = computed(() =>
  props.allPackets.filter(p => p.entropy_level === 'critical')
);

const selectedTargetPackets = computed(() => {
  if (exportScope.value === 'all') return props.allPackets;
  if (exportScope.value === 'critical') return criticalPackets.value;
  return props.filteredPackets;
});

// 动态生成默认文件名
watch(
  [() => props.isOpen, exportFormat],
  ([open, fmt]) => {
    if (open) {
      const dt = new Date().toISOString().replace(/[-:T.]/g, '_').slice(0, 15);
      const ext = fmt;
      targetFilePath.value = `export_packets_${dt}.${ext}`;
      exportStatus.value = '';
      isError.value = false;
    }
  },
  { immediate: true }
);

async function doExport() {
  if (selectedTargetPackets.value.length === 0) {
    exportStatus.value = '错误: 待导出的报文数量为 0';
    isError.value = true;
    return;
  }

  isExporting.value = true;
  exportStatus.value = '正在编码并写入文件...';
  isError.value = false;

  const packetsToExport = selectedTargetPackets.value.map(p => ({
    id: p.id,
    timestamp: p.timestamp,
    direction: p.direction,
    transport: p.transport,
    protocol: p.protocol,
    src_ip: p.src_ip,
    dst_ip: p.dst_ip,
    src_port: p.src_port,
    dst_port: p.dst_port,
    length: p.length,
    payload_hex: p.payload_hex,
    entropy: p.entropy,
    entropy_level: p.entropy_level,
    mac_src: p.mac_src,
    mac_dst: p.mac_dst,
    chain_hash: p.chain_hash,
    raw_text: p.raw_text,
  }));

  try {
    let count = 0;
    if (exportFormat.value === 'pcapng') {
      count = await invoke<number>('export_packets_pcapng_cmd', {
        packets: packetsToExport,
        filePath: targetFilePath.value,
        ifaceName: 'any',
        forensicComment: forensicComment.value || null,
      });
    } else if (exportFormat.value === 'pcap') {
      count = await invoke<number>('export_packets_pcap_cmd', {
        packets: packetsToExport,
        filePath: targetFilePath.value,
      });
    } else if (exportFormat.value === 'csv') {
      count = await invoke<number>('export_packets_csv_cmd', {
        packets: packetsToExport,
        filePath: targetFilePath.value,
      });
    } else if (exportFormat.value === 'json') {
      count = await invoke<number>('export_packets_json_cmd', {
        packets: packetsToExport,
        filePath: targetFilePath.value,
      });
    } else if (exportFormat.value === 'har') {
      count = await invoke<number>('export_packets_har_cmd', {
        packets: packetsToExport,
        filePath: targetFilePath.value,
      });
    }

    exportStatus.value = `导出成功! 共写入 ${count} 帧至 ${targetFilePath.value}`;
    emit('log', `[EXPORT] 成功导出 ${count} 帧至 ${targetFilePath.value}`);
  } catch (e: any) {
    isError.value = true;
    exportStatus.value = `导出失败: ${e}`;
    emit('log', `[ERROR] 导出失败: ${e}`);
  } finally {
    isExporting.value = false;
  }
}
</script>
