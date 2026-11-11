<template>
  <div v-if="isOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4 animate-in fade-in duration-150">
    <div class="ui-modal-surface w-full max-w-lg rounded-3xl flex flex-col overflow-hidden">
      
      <!-- 1. 顶栏 -->
      <div class="ui-nav-glass px-6 py-4 border-b border-(--border-subtle) flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-sky-500/12 border border-sky-500/30 flex items-center justify-center text-sky-600 dark:text-sky-400">
            <AppIcon name="upload" class="w-4 h-4" />
          </div>
          <div>
            <h3 class="text-sm font-bold text-(--text-primary)">离线 PCAP 流量导入与回放 (Offline Ingestion)</h3>
            <p class="text-xs text-(--text-muted) font-mono-code">载入本地 .pcap 文件，执行协议解码与二次离线解剖</p>
          </div>
        </div>
        <button @click="$emit('close')" class="ui-btn-secondary w-8 h-8 rounded-full p-0 flex items-center justify-center cursor-pointer" aria-label="关闭弹窗">
          <AppIcon name="close" class="w-4 h-4" />
        </button>
      </div>

      <!-- 2. 内容区 -->
      <div class="p-6 space-y-4 text-xs">
        <div>
          <label class="block font-bold text-(--text-primary) mb-1.5">PCAP 文件绝对路径 (File Path):</label>
          <input v-model="filePath" placeholder="请输入 .pcap 文件的绝对路径 (如 E:\captures\sample.pcap)"
            class="ui-input w-full px-3 py-2 text-xs font-mono-code select-text">
          <p class="text-[11px] text-(--text-muted) mt-1.5">支持由 Wireshark、tcpdump 等工业工具生成的标准以太网 PCAP 格式</p>
        </div>

        <!-- 结果反馈 -->
        <div v-if="statusMsg" :class="['p-3 rounded-xl text-xs font-mono-code border select-text', isError ? 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/30' : 'bg-sky-500/12 text-sky-700 dark:text-sky-300 border-sky-500/30']">
          {{ statusMsg }}
        </div>
      </div>

      <!-- 3. 底栏操作 -->
      <div class="px-6 py-3 border-t border-(--border-subtle) bg-(--surface-content-alt) flex items-center justify-between shrink-0">
        <span class="text-xs text-(--text-muted) font-mono-code">解析后将无缝载入主表格</span>
        <div class="flex items-center gap-2">
          <button @click="$emit('close')" class="ui-btn-secondary px-4 py-1.5 text-xs font-semibold cursor-pointer">
            取消
          </button>
          <button @click="doImport" :disabled="isImporting || !filePath.trim()"
            class="ui-btn-primary text-xs px-5 py-1.5 font-bold cursor-pointer disabled:opacity-40">
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
import AppIcon from './AppIcon.vue';

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
