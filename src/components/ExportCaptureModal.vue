<template>
  <div v-if="isOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4 animate-in fade-in duration-150">
    <div class="ui-modal-surface w-full max-w-lg rounded-3xl flex flex-col overflow-hidden">
      
      <!-- 1. 顶栏 -->
      <div class="ui-nav-glass px-6 py-4 border-b border-(--border-subtle) flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-teal-500/12 border border-teal-500/30 flex items-center justify-center text-teal-600 dark:text-teal-400">
            <AppIcon name="download" class="w-4 h-4" />
          </div>
          <div>
            <h3 class="text-sm font-bold text-(--text-primary)">工业级流量与数据帧导出 (Export Pipeline)</h3>
            <p class="text-xs text-(--text-muted) font-mono-code">支持 PCAPng 司法存证、PCAP、CSV、JSON 或 HAR 归档</p>
          </div>
        </div>
        <button @click="$emit('close')" class="ui-btn-secondary w-8 h-8 rounded-full p-0 flex items-center justify-center cursor-pointer" aria-label="关闭弹窗">
          <AppIcon name="close" class="w-4 h-4" />
        </button>
      </div>

      <!-- 2. 表单配置区 -->
      <div class="p-6 space-y-4 text-xs">
        <!-- 导出范围 -->
        <div>
          <label class="block font-bold text-(--text-primary) mb-1.5">1. 选择导出报文范围 (Scope):</label>
          <div class="grid grid-cols-3 gap-2">
            <button @click="exportScope = 'all'"
              :class="['p-2.5 rounded-xl border text-center transition-all cursor-pointer', exportScope === 'all' ? 'border-teal-500 bg-teal-500/12 text-teal-700 dark:text-teal-300 font-bold' : 'ui-sub-card text-(--text-secondary) hover:border-(--border-strong)']">
              <div>全部报文</div>
              <div class="text-[11px] text-(--text-muted) ui-num font-mono-code mt-0.5">{{ allPackets.length }} 帧</div>
            </button>
            <button @click="exportScope = 'filtered'"
              :class="['p-2.5 rounded-xl border text-center transition-all cursor-pointer', exportScope === 'filtered' ? 'border-teal-500 bg-teal-500/12 text-teal-700 dark:text-teal-300 font-bold' : 'ui-sub-card text-(--text-secondary) hover:border-(--border-strong)']">
              <div>当前过滤匹配</div>
              <div class="text-[11px] text-(--text-muted) ui-num font-mono-code mt-0.5">{{ filteredPackets.length }} 帧</div>
            </button>
            <button @click="exportScope = 'critical'"
              :class="['p-2.5 rounded-xl border text-center transition-all cursor-pointer', exportScope === 'critical' ? 'border-teal-500 bg-teal-500/12 text-teal-700 dark:text-teal-300 font-bold' : 'ui-sub-card text-(--text-secondary) hover:border-(--border-strong)']">
              <div>高熵/异常子集</div>
              <div class="text-[11px] text-(--text-muted) ui-num font-mono-code mt-0.5">{{ criticalPackets.length }} 帧</div>
            </button>
          </div>
        </div>

        <!-- 导出格式 -->
        <div>
          <label class="block font-bold text-(--text-primary) mb-1.5">2. 选择导出文件格式 (Format):</label>
          <div class="grid grid-cols-2 gap-2">
            <button @click="exportFormat = 'pcapng'"
              :class="['p-2.5 rounded-xl border text-left transition-all cursor-pointer flex items-center gap-2.5', exportFormat === 'pcapng' ? 'border-teal-500 bg-teal-500/12 text-teal-700 dark:text-teal-300 font-bold ring-1 ring-teal-500/25' : 'ui-sub-card text-(--text-secondary) hover:border-(--border-strong)']">
              <AppIcon name="shield" class="w-4 h-4 shrink-0" />
              <div class="min-w-0">
                <div class="text-xs flex items-center gap-1.5">
                  <span class="truncate">PCAPng 司法存证</span>
                  <span class="text-[11px] bg-teal-600 text-white px-1.5 py-0.2 rounded font-medium shrink-0">推荐</span>
                </div>
                <div class="text-[11px] text-(--text-muted) font-normal truncate">含 SHB/IDB/EPB 与哈希存证</div>
              </div>
            </button>

            <button @click="exportFormat = 'pcap'"
              :class="['p-2.5 rounded-xl border text-left transition-all cursor-pointer flex items-center gap-2.5', exportFormat === 'pcap' ? 'border-sky-500 bg-sky-500/12 text-sky-700 dark:text-sky-300 font-bold' : 'ui-sub-card text-(--text-secondary) hover:border-(--border-strong)']">
              <AppIcon name="activity" class="w-4 h-4 shrink-0" />
              <div class="min-w-0">
                <div class="text-xs truncate">标准 PCAP 二进制</div>
                <div class="text-[11px] text-(--text-muted) font-normal truncate">Wireshark 经典 libpcap 格式</div>
              </div>
            </button>

            <button @click="exportFormat = 'csv'"
              :class="['p-2.5 rounded-xl border text-left transition-all cursor-pointer flex items-center gap-2.5', exportFormat === 'csv' ? 'border-emerald-500 bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 font-bold' : 'ui-sub-card text-(--text-secondary) hover:border-(--border-strong)']">
              <AppIcon name="layers" class="w-4 h-4 shrink-0" />
              <div class="min-w-0">
                <div class="text-xs truncate">结构化 CSV 流水</div>
                <div class="text-[11px] text-(--text-muted) font-normal truncate">表格分析与科学数据统计</div>
              </div>
            </button>

            <button @click="exportFormat = 'json'"
              :class="['p-2.5 rounded-xl border text-left transition-all cursor-pointer flex items-center gap-2.5', exportFormat === 'json' ? 'border-amber-500 bg-amber-500/12 text-amber-700 dark:text-amber-300 font-bold' : 'ui-sub-card text-(--text-secondary) hover:border-(--border-strong)']">
              <AppIcon name="code" class="w-4 h-4 shrink-0" />
              <div class="min-w-0">
                <div class="text-xs truncate">JSON 审计明细</div>
                <div class="text-[11px] text-(--text-muted) font-normal truncate">SIEM / SOC 日志审计入库</div>
              </div>
            </button>

            <button @click="exportFormat = 'har'"
              :class="['p-2.5 rounded-xl border text-left transition-all cursor-pointer flex items-center gap-2.5 col-span-2', exportFormat === 'har' ? 'border-purple-500 bg-purple-500/12 text-purple-700 dark:text-purple-300 font-bold' : 'ui-sub-card text-(--text-secondary) hover:border-(--border-strong)']">
              <AppIcon name="globe" class="w-4 h-4 shrink-0" />
              <div class="min-w-0">
                <div class="text-xs">HAR 1.2 归档格式</div>
                <div class="text-[11px] text-(--text-muted) font-normal">HTTP 请求/响应浏览器标准会话归档</div>
              </div>
            </button>
          </div>
        </div>

        <!-- 司法级存证附加注释 (PCAPng 专属) -->
        <div v-if="exportFormat === 'pcapng'" class="ui-sub-card border-teal-500/30 p-3 rounded-xl space-y-1.5 animate-in fade-in duration-150">
          <div class="flex items-center justify-between text-teal-700 dark:text-teal-300 font-bold text-xs">
            <span>司法链存证注释 (Section Header Comment):</span>
            <span class="text-[11px] text-(--text-muted) font-mono-code font-normal">Option Code 0x0001</span>
          </div>
          <input v-model="forensicComment"
            placeholder="例: Omni-Probe Judicial Certified Forensics Chain Hash Verified"
            class="ui-input w-full px-2.5 py-1.5 text-xs font-mono-code">
        </div>

        <!-- 导出路径与文件名 -->
        <div>
          <label class="block font-bold text-(--text-primary) mb-1">3. 保存文件绝对路径 (File Path):</label>
          <input v-model="targetFilePath"
            class="ui-input w-full px-3 py-2 text-xs font-mono-code select-text">
          <p class="text-[11px] text-(--text-muted) mt-1">支持自定义绝对路径，默认保存至当前系统目录</p>
        </div>

        <!-- 状态反馈 -->
        <div v-if="exportStatus" :class="['p-3 rounded-xl text-xs font-mono-code border select-text', isError ? 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/30' : 'bg-teal-500/12 text-teal-700 dark:text-teal-300 border-teal-500/30']">
          {{ exportStatus }}
        </div>
      </div>

      <!-- 3. 底栏操作 -->
      <div class="px-6 py-3 border-t border-(--border-subtle) bg-(--surface-content-alt) flex items-center justify-between shrink-0">
        <span class="text-xs text-(--text-muted) font-mono-code ui-num">待导出: {{ selectedTargetPackets.length }} 帧</span>
        <div class="flex items-center gap-2">
          <button @click="$emit('close')" class="ui-btn-secondary px-4 py-1.5 text-xs font-semibold cursor-pointer">
            取消
          </button>
          <button @click="doExport" :disabled="isExporting || selectedTargetPackets.length === 0"
            class="ui-btn-primary text-xs px-5 py-1.5 font-bold cursor-pointer disabled:opacity-40">
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
import AppIcon from './AppIcon.vue';

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
