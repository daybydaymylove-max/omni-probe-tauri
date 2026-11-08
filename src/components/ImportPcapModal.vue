<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md animate-in fade-in duration-150">
    <div class="w-full max-w-lg bg-white/95 backdrop-blur-2xl rounded-3xl border border-white/60 shadow-2xl flex flex-col overflow-hidden">
      
      <!-- 1. 顶栏 -->
      <div class="px-6 py-4 border-b border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <span class="w-3 h-3 rounded-full bg-blue-500 shadow-sm"></span>
          <div>
            <h3 class="text-sm font-bold text-slate-900">离线 PCAP 流量导入与回放 (Offline Ingestion)</h3>
            <p class="text-[11px] text-slate-500 font-mono">载入本地 .pcap 文件，执行协议解码、信息熵计算与二次离线解剖</p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer">
          ✕
        </button>
      </div>

      <!-- 2. 内容区 -->
      <div class="p-6 space-y-4 text-xs font-mono">
        <div>
          <label class="block font-bold text-slate-700 mb-1">PCAP 文件绝对路径 (File Path):</label>
          <input v-model="filePath" placeholder="请输入 .pcap 文件的绝对路径 (如 E:\captures\sample.pcap 或 /home/user/captures/sample.pcap)"
            class="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500/30 shadow-2xs">
          <p class="text-[10px] text-slate-400 mt-1">支持由 Wireshark、tcpdump 等工业工具生成的标准以太网 PCAP 格式</p>
        </div>

        <!-- 结果反馈 -->
        <div v-if="statusMsg" :class="['p-3 rounded-xl text-xs font-mono border', isError ? 'bg-rose-50 text-rose-700 border-rose-200' : 'bg-blue-50 text-blue-800 border-blue-200']">
          {{ statusMsg }}
        </div>
      </div>

      <!-- 3. 底栏操作 -->
      <div class="px-6 py-3 border-t border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <span class="text-[11px] text-slate-400 font-mono">解析后将无缝载入主表格</span>
        <div class="flex items-center gap-2">
          <button @click="$emit('close')" class="px-4 py-1.5 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer">
            取消
          </button>
          <button @click="doImport" :disabled="isImporting || !filePath.trim()"
            class="bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white text-xs px-5 py-1.5 rounded-xl font-bold cursor-pointer transition-all shadow-sm active:scale-95 disabled:opacity-40">
            <span v-if="isImporting">解析中...</span>
            <span v-else>载入回放</span>
          </button>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { invoke } from '@tauri-apps/api/core';

defineProps<{
  isOpen: boolean;
}>();

const emit = defineEmits(['close', 'imported', 'log']);

const filePath = ref('');
const isImporting = ref(false);
const statusMsg = ref('');
const isError = ref(false);

async function doImport() {
  if (!filePath.value.trim()) return;
  isImporting.value = true;
  statusMsg.value = '正在解析 PCAP 文件...';
  isError.value = false;

  try {
    const list = await invoke<any[]>('import_pcap_file_cmd', { filePath: filePath.value.trim() });
    statusMsg.value = `解析成功! 共提取 ${list.length} 个数据帧`;
    emit('log', `[PCAP-IMPORT] 成功从 ${filePath.value} 导入 ${list.length} 个离线报文`);
    emit('imported', list);
    setTimeout(() => {
      emit('close');
    }, 1000);
  } catch (e: any) {
    isError.value = true;
    statusMsg.value = `导入失败: ${e}`;
    emit('log', `[ERROR] PCAP 导入失败: ${e}`);
  } finally {
    isImporting.value = false;
  }
}
</script>
