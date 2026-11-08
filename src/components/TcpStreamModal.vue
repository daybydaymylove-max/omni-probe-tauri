<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md animate-in fade-in duration-150">
    <div class="w-full max-w-4xl bg-white/95 backdrop-blur-2xl rounded-3xl border border-white/60 shadow-2xl flex flex-col overflow-hidden max-h-[88vh]">
      
      <!-- 1. 顶层标题栏 (对齐 Wireshark Follow TCP Stream 专业体验) -->
      <div class="px-6 py-4 border-b border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-3">
          <span class="w-3.5 h-3.5 rounded-full bg-blue-600 shadow-sm animate-pulse"></span>
          <div>
            <h3 class="text-sm font-bold text-slate-900 flex items-center gap-2">
              <span>双向会话流重组与追踪 (Follow TCP Stream)</span>
              <span class="text-xs font-mono px-2 py-0.5 rounded-lg bg-blue-50 text-blue-700 border border-blue-200">
                {{ srcIp }}:{{ srcPort }} ⇄ {{ dstIp }}:{{ dstPort }}
              </span>
            </h3>
            <p class="text-[11px] text-slate-500 font-mono mt-0.5">
              基于 TCP 序列号顺序重组，红蓝双色区分客户端请求 (C➔S) 与服务端响应 (S➔C)
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <!-- 格式切换 -->
          <div class="flex bg-slate-100 p-0.5 rounded-xl text-xs font-semibold border border-slate-200/80">
            <button @click="displayMode = 'ascii'"
              :class="['px-3 py-1 rounded-lg transition-all cursor-pointer', displayMode === 'ascii' ? 'bg-white text-blue-700 shadow-xs font-bold' : 'text-slate-600 hover:text-slate-900']">
              ASCII 文本
            </button>
            <button @click="displayMode = 'hex'"
              :class="['px-3 py-1 rounded-lg transition-all cursor-pointer', displayMode === 'hex' ? 'bg-white text-blue-700 shadow-xs font-bold' : 'text-slate-600 hover:text-slate-900']">
              十六进制 (Hex)
            </button>
          </div>

          <button @click="$emit('close')"
            class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer ml-2">
            ✕
          </button>
        </div>
      </div>

      <!-- 2. 会话重组统计与过滤栏 -->
      <div class="px-6 py-2.5 bg-slate-50/80 border-b border-slate-200/50 flex items-center justify-between text-xs font-mono shrink-0">
        <div class="flex items-center gap-4 text-slate-600">
          <div>重组分段: <strong class="text-slate-900">{{ chunks.length }}</strong> 块</div>
          <div>客户端发往: <strong class="text-blue-700">{{ clientBytes }}</strong> 字节</div>
          <div>服务端回包: <strong class="text-rose-700">{{ serverBytes }}</strong> 字节</div>
          <div>总流经: <strong class="text-slate-900">{{ clientBytes + serverBytes }}</strong> 字节</div>
        </div>

        <div class="flex items-center gap-2">
          <button @click="copyFullStream" class="bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 px-3 py-1 rounded-lg text-xs cursor-pointer font-semibold shadow-2xs">
            📋 复制全部会话内容
          </button>
          <button @click="saveStreamAsFile" class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded-lg text-xs cursor-pointer font-bold shadow-xs">
            💾 导出会话文本
          </button>
        </div>
      </div>

      <!-- 3. 重组会话数据流展现区 (深色终端磨砂模式) -->
      <div class="flex-1 overflow-auto custom-scrollbar p-4 bg-slate-900 font-mono text-xs leading-relaxed select-text space-y-3">
        <div v-if="loading" class="flex items-center justify-center h-48 text-slate-400 gap-2">
          <span class="animate-spin text-blue-400">⏳</span>
          <span>正在对 TCP 序列号进行多重乱序重组与流追踪...</span>
        </div>

        <div v-else-if="chunks.length === 0" class="flex flex-col items-center justify-center h-48 text-slate-500 gap-2">
          <span>未提取到有效的会话载荷数据</span>
          <span class="text-[10px]">该连接可能仅包含 TCP 握手/挥手控制标志或载荷已被丢弃</span>
        </div>

        <div v-else v-for="(chunk, idx) in chunks" :key="idx"
          :class="[
            'p-3 rounded-xl border transition-all',
            chunk.direction === 'client'
              ? 'bg-blue-950/40 border-blue-800/40 text-sky-200'
              : 'bg-rose-950/40 border-rose-800/40 text-rose-200'
          ]">
          <div class="flex items-center justify-between pb-1.5 mb-2 border-b border-white/10 text-[10px] opacity-75 select-none">
            <span class="font-bold flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full" :class="chunk.direction === 'client' ? 'bg-sky-400' : 'bg-rose-400'"></span>
              <span>{{ chunk.direction === 'client' ? `客户端 [${srcIp}:${srcPort}] ➔ 服务端` : `服务端 [${dstIp}:${dstPort}] ➔ 客户端` }}</span>
            </span>
            <span>{{ chunk.timestamp }} • {{ chunk.length }} 字节</span>
          </div>

          <div class="whitespace-pre-wrap break-all font-mono">
            {{ displayMode === 'ascii' ? chunk.payload_text : formatHex(chunk.payload_hex) }}
          </div>
        </div>
      </div>

      <!-- 4. 底栏操作提示 -->
      <div class="px-6 py-3 border-t border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0 text-[11px] text-slate-500 font-mono">
        <span>提示: 红色表示服务端响应数据，蓝色表示客户端请求数据</span>
        <button @click="$emit('close')" class="px-4 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold cursor-pointer">
          关闭
        </button>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { invoke } from '@tauri-apps/api/core';

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

function saveStreamAsFile() {
  if (chunks.value.length === 0) return;
  const fullText = chunks.value
    .map(c => `[${c.direction === 'client' ? 'CLIENT' : 'SERVER'} - ${c.timestamp} - ${c.length}B]\n${c.payload_text}`)
    .join('\n\n');

  const blob = new Blob([fullText], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `stream_${props.srcIp}_${props.srcPort}_${props.dstIp}_${props.dstPort}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}
</script>
