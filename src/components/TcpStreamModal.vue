<template>
  <div v-if="isOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4 animate-in fade-in duration-150">
    <div class="ui-modal-surface w-full max-w-4xl rounded-3xl flex flex-col overflow-hidden max-h-[88vh]">
      
      <!-- 1. 顶层标题栏 (对齐 Wireshark Follow TCP Stream) -->
      <div class="ui-nav-glass px-6 py-4 border-b border-(--border-subtle) flex items-center justify-between shrink-0 gap-3">
        <div class="flex items-center gap-3 min-w-0">
          <div class="w-8 h-8 rounded-xl bg-sky-500/12 border border-sky-500/30 flex items-center justify-center text-sky-600 dark:text-sky-400 shrink-0">
            <AppIcon name="traffic" class="w-4 h-4" />
          </div>
          <div class="min-w-0">
            <h3 class="text-sm font-bold text-(--text-primary) flex flex-wrap items-center gap-2">
              <span>双向会话流重组与追踪 (Follow TCP Stream)</span>
              <span class="text-xs ui-num font-mono-code px-2 py-0.5 rounded-lg bg-sky-500/12 text-sky-700 dark:text-sky-300 border border-sky-500/30 select-text">
                {{ srcIp }}:{{ srcPort }} ⇄ {{ dstIp }}:{{ dstPort }}
              </span>
            </h3>
            <p class="text-xs text-(--text-muted) font-mono-code mt-0.5">
              基于 TCP 序列号顺序重组，双色区分客户端请求 (C -> S) 与服务端响应 (S -> C)
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2 shrink-0">
          <!-- 格式切换 -->
          <div class="ui-sub-card flex p-0.5 rounded-xl text-xs font-semibold">
            <button @click="displayMode = 'ascii'"
              :class="['px-3 py-1 rounded-lg transition-all cursor-pointer', displayMode === 'ascii' ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300 font-bold border border-sky-500/30' : 'text-(--text-secondary) hover:text-(--text-primary) border border-transparent']">
              ASCII 文本
            </button>
            <button @click="displayMode = 'hex'"
              :class="['px-3 py-1 rounded-lg transition-all cursor-pointer', displayMode === 'hex' ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300 font-bold border border-sky-500/30' : 'text-(--text-secondary) hover:text-(--text-primary) border border-transparent']">
              十六进制 (Hex)
            </button>
          </div>

          <button @click="$emit('close')"
            class="ui-btn-secondary w-8 h-8 rounded-full p-0 flex items-center justify-center cursor-pointer ml-1"
            aria-label="关闭弹窗">
            <AppIcon name="close" class="w-4 h-4" />
          </button>
        </div>
      </div>

      <!-- 2. 会话重组统计与过滤栏 -->
      <div class="px-6 py-2.5 bg-(--surface-content-alt) border-b border-(--border-subtle) flex flex-wrap items-center justify-between gap-2 text-xs font-mono-code shrink-0">
        <div class="flex flex-wrap items-center gap-4 text-(--text-secondary) ui-num">
          <div>重组分段: <strong class="text-(--text-primary)">{{ chunks.length }}</strong> 块</div>
          <div>客户端发往: <strong class="text-sky-600 dark:text-sky-400">{{ clientBytes }}</strong> 字节</div>
          <div>服务端回包: <strong class="text-rose-600 dark:text-rose-400">{{ serverBytes }}</strong> 字节</div>
          <div>总流经: <strong class="text-(--text-primary)">{{ clientBytes + serverBytes }}</strong> 字节</div>
        </div>

        <div class="flex items-center gap-2">
          <button @click="copyFullStream" class="ui-btn-secondary inline-flex items-center gap-1.5 px-3 py-1 text-xs cursor-pointer font-semibold">
            <AppIcon name="code" class="w-3.5 h-3.5" />
            <span>复制全部会话</span>
          </button>
          <button @click="saveStreamAsFile" class="ui-btn-primary inline-flex items-center gap-1.5 px-3 py-1 text-xs cursor-pointer font-bold">
            <AppIcon name="download" class="w-3.5 h-3.5" />
            <span>导出会话文本</span>
          </button>
        </div>
      </div>

      <!-- 3. 重组会话数据流展现区 (实体稳态双模态终端衬底) -->
      <div class="flex-1 overflow-auto custom-scrollbar p-4 bg-(--surface-window) font-mono-code text-xs leading-relaxed select-text space-y-3">
        <div v-if="loading" class="flex items-center justify-center h-48 text-(--text-secondary) gap-2">
          <AppIcon name="refresh" class="w-4 h-4 animate-spin text-sky-600 dark:text-sky-400" />
          <span>正在对 TCP 序列号进行多重乱序重组与流追踪...</span>
        </div>

        <EmptyState
          v-else-if="chunks.length === 0"
          icon="traffic"
          title="未提取到有效的会话载荷数据"
          description="该连接可能仅包含 TCP 握手/挥手控制标志或载荷数据为空。"
        />

        <div v-else v-for="(chunk, idx) in chunks" :key="idx"
          :class="[
            'p-3.5 rounded-xl border transition-all',
            chunk.direction === 'client'
              ? 'bg-sky-500/10 border-sky-500/30 text-(--text-primary)'
              : 'bg-rose-500/10 border-rose-500/30 text-(--text-primary)'
          ]">
          <div class="flex items-center justify-between pb-1.5 mb-2 border-b border-(--border-subtle) text-[11px] select-none">
            <span class="font-bold flex items-center gap-1.5">
              <span class="w-2 h-2 rounded-full" :class="chunk.direction === 'client' ? 'bg-sky-500' : 'bg-rose-500'"></span>
              <span :class="chunk.direction === 'client' ? 'text-sky-700 dark:text-sky-300' : 'text-rose-700 dark:text-rose-300'">
                {{ chunk.direction === 'client' ? `客户端 [${srcIp}:${srcPort}] -> 服务端` : `服务端 [${dstIp}:${dstPort}] -> 客户端` }}
              </span>
            </span>
            <span class="text-(--text-muted) ui-num">{{ chunk.timestamp }} • {{ chunk.length }} 字节</span>
          </div>

          <div class="whitespace-pre-wrap break-all font-mono-code">
            {{ displayMode === 'ascii' ? chunk.payload_text : formatHex(chunk.payload_hex) }}
          </div>
        </div>
      </div>

      <!-- 4. 底栏操作提示 -->
      <div class="px-6 py-3 border-t border-(--border-subtle) bg-(--surface-content-alt) flex items-center justify-between shrink-0 text-xs text-(--text-muted) font-mono-code">
        <span>提示: 玫瑰红卡片代表服务端响应，海天蓝卡片代表客户端请求</span>
        <button @click="$emit('close')" class="ui-btn-secondary px-4 py-1.5 font-semibold cursor-pointer">
          关闭
        </button>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';
import { saveTextViaNativeDesktop } from '../composables/useDesktopSave';

interface StreamChunk {
  direction: string;
  timestamp: string;
  payload_hex: string;
  payload_text: string;
  length: number;
}

const props = defineProps<{
  isOpen: boolean;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  transport: string;
}>();

defineEmits(['close']);

const displayMode = ref<'ascii' | 'hex'>('ascii');
const loading = ref(false);
const chunks = ref<StreamChunk[]>([]);

const clientBytes = computed(() =>
  chunks.value.filter(c => c.direction === 'client').reduce((acc, c) => acc + c.length, 0)
);
const serverBytes = computed(() =>
  chunks.value.filter(c => c.direction === 'server').reduce((acc, c) => acc + c.length, 0)
);

watch(
  () => props.isOpen,
  async (open) => {
    if (open && props.srcIp && props.dstIp) {
      await loadStream();
    } else {
      chunks.value = [];
    }
  }
);

async function loadStream() {
  loading.value = true;
  chunks.value = [];
  try {
    const res = await invoke<StreamChunk[]>('follow_tcp_stream_cmd', {
      srcIp: props.srcIp,
      dstIp: props.dstIp,
      srcPort: props.srcPort,
      dstPort: props.dstPort,
      transport: props.transport || 'TCP',
    });
    chunks.value = res;
  } catch (e) {
    console.warn('追踪 TCP 流失败:', e);
    chunks.value = [];
  } finally {
    loading.value = false;
  }
}

function formatHex(hexStr: string): string {
  if (!hexStr) return '';
  const pairs: string[] = [];
  for (let i = 0; i < hexStr.length; i += 2) {
    pairs.push(hexStr.slice(i, i + 2));
  }
  return pairs.join(' ');
}

function copyFullStream() {
  if (chunks.value.length === 0) return;
  const fullText = chunks.value
    .map(c => `[${c.direction === 'client' ? 'CLIENT' : 'SERVER'} - ${c.timestamp} - ${c.length}B]\n${displayMode.value === 'ascii' ? c.payload_text : formatHex(c.payload_hex)}`)
    .join('\n\n');
  navigator.clipboard.writeText(fullText);
}

async function saveStreamAsFile() {
  if (chunks.value.length === 0) return;
  const fullText = chunks.value
    .map(c => `[${c.direction === 'client' ? 'CLIENT' : 'SERVER'} - ${c.timestamp} - ${c.length}B]\n${c.payload_text}`)
    .join('\n\n');

  await saveTextViaNativeDesktop(
    `stream_${props.srcIp}_${props.srcPort}_${props.dstIp}_${props.dstPort}.txt`,
    fullText,
    'TCP 会话重组文本 (*.txt)',
    '*.txt;*.log',
    '导出 TCP 流重组文本'
  );
}
</script>
