<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md">
    <div class="w-full max-w-2xl bg-white/95 backdrop-blur-2xl rounded-3xl border border-white/60 shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      <!-- 模态框头部 -->
      <div class="px-6 py-4 border-b border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-indigo-50 border border-indigo-200 flex items-center justify-center text-indigo-700 text-sm font-bold shadow-2xs">
            📟
          </div>
          <div>
            <h3 class="text-sm font-bold text-slate-900">串口工业通信参数与动态分帧配置</h3>
            <p class="text-[11px] text-slate-500 font-mono">符合 Modbus RTU / DL/T 645 / NMEA 0183 规约硬件参数与 3.5T 动态超时推导</p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer">
          ✕
        </button>
      </div>

      <!-- 模态框主体内容 -->
      <div class="p-6 space-y-5 overflow-auto max-h-[75vh] custom-scrollbar">
        <!-- 行业预设模板快捷载入 -->
        <div class="bg-indigo-50/70 border border-indigo-100 rounded-2xl p-3 flex flex-col gap-2">
          <div class="flex items-center justify-between text-xs font-bold text-indigo-950">
            <span>⚡ 行业标准规约预设模板:</span>
            <span class="text-[10px] text-indigo-600 font-normal">一键载入工控标准物理层与分帧策略</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
            <button @click="applyPreset('modbus_rtu')"
              class="bg-white hover:bg-indigo-100/70 text-indigo-900 border border-indigo-200 p-2 rounded-xl text-left transition-all cursor-pointer shadow-2xs">
              <div class="font-bold text-[11px]">Modbus RTU</div>
              <div class="text-[10px] text-slate-500 font-mono">9600, 8-N-1, 3.5T</div>
            </button>
            <button @click="applyPreset('dlt645')"
              class="bg-white hover:bg-indigo-100/70 text-indigo-900 border border-indigo-200 p-2 rounded-xl text-left transition-all cursor-pointer shadow-2xs">
              <div class="font-bold text-[11px]">DL/T 645 电表</div>
              <div class="text-[10px] text-slate-500 font-mono">2400, 8-E-1, 3.5T</div>
            </button>
            <button @click="applyPreset('nmea0183')"
              class="bg-white hover:bg-indigo-100/70 text-indigo-900 border border-indigo-200 p-2 rounded-xl text-left transition-all cursor-pointer shadow-2xs">
              <div class="font-bold text-[11px]">NMEA 0183 导航</div>
              <div class="text-[10px] text-slate-500 font-mono">4800, 8-N-1, CRLF</div>
            </button>
            <button @click="applyPreset('high_speed')"
              class="bg-white hover:bg-indigo-100/70 text-indigo-900 border border-indigo-200 p-2 rounded-xl text-left transition-all cursor-pointer shadow-2xs">
              <div class="font-bold text-[11px]">高速工控串口</div>
              <div class="text-[10px] text-slate-500 font-mono">115200, 8-N-1, 3.5T</div>
            </button>
          </div>
        </div>

        <!-- 硬件参数配置网格 -->
        <div class="space-y-3">
          <h4 class="text-xs font-bold text-slate-700 uppercase tracking-wider">1. 物理层四大参数与流控</h4>
          <div class="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
            <div>
              <label class="block text-[11px] font-bold text-slate-600 mb-1">目标串口 (COM Port)</label>
              <select v-model="selectedPort"
                class="w-full bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
                <option v-for="p in serialPorts" :key="p" :value="p">{{ p }}</option>
                <option v-if="serialPorts.length === 0" value="">未发现可用串口</option>
              </select>
            </div>

            <div>
              <label class="block text-[11px] font-bold text-slate-600 mb-1">波特率 (Baud Rate)</label>
              <select v-model.number="config.baud_rate"
                class="w-full bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
                <option :value="1200">1200 bps</option>
                <option :value="2400">2400 bps</option>
                <option :value="4800">4800 bps</option>
                <option :value="9600">9600 bps</option>
                <option :value="19200">19200 bps</option>
                <option :value="38400">38400 bps</option>
                <option :value="57600">57600 bps</option>
                <option :value="115200">115200 bps</option>
                <option :value="230400">230400 bps</option>
                <option :value="460800">460800 bps</option>
                <option :value="921600">921600 bps</option>
              </select>
            </div>

            <div>
              <label class="block text-[11px] font-bold text-slate-600 mb-1">数据位 (Data Bits)</label>
              <select v-model.number="config.data_bits"
                class="w-full bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
                <option :value="5">5 Bits</option>
                <option :value="6">6 Bits</option>
                <option :value="7">7 Bits</option>
                <option :value="8">8 Bits (常用)</option>
              </select>
            </div>

            <div>
              <label class="block text-[11px] font-bold text-slate-600 mb-1">奇偶校验位 (Parity)</label>
              <select v-model="config.parity"
                class="w-full bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
                <option value="None">None 无校验 (8-N-1)</option>
                <option value="Odd">Odd 奇校验</option>
                <option value="Even">Even 偶校验 (DL/T 645)</option>
              </select>
            </div>

            <div>
              <label class="block text-[11px] font-bold text-slate-600 mb-1">停止位 (Stop Bits)</label>
              <select v-model.number="config.stop_bits"
                class="w-full bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
                <option :value="1">1 停止位</option>
                <option :value="2">2 停止位</option>
              </select>
            </div>

            <div>
              <label class="block text-[11px] font-bold text-slate-600 mb-1">硬件/软件流控 (Flow Control)</label>
              <select v-model="config.flow_control"
                class="w-full bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
                <option value="None">None 无流控</option>
                <option value="Software">Software 软件流控 (XON/XOFF)</option>
                <option value="Hardware">Hardware 硬件流控 (RTS/CTS)</option>
              </select>
            </div>
          </div>
        </div>

        <!-- 动态分帧策略配置 -->
        <div class="space-y-3 border-t border-slate-200/60 pt-4">
          <div class="flex items-center justify-between">
            <h4 class="text-xs font-bold text-slate-700 uppercase tracking-wider">2. 工业级数据流分帧引擎 (Framing Engine)</h4>
            <span class="text-[10px] text-indigo-600 font-mono font-bold bg-indigo-50 px-2 py-0.5 rounded-lg border border-indigo-200">
              理论 3.5T 动态超时: {{ calculated3_5tMs.toFixed(2) }} ms
            </span>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div>
              <label class="block text-[11px] font-bold text-slate-600 mb-1">分帧模式 (Frame Mode)</label>
              <select v-model="config.frame_mode"
                class="w-full bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 font-bold text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
                <option value="Auto3_5T">Auto3_5T: 智能 3.5 字符动态时间超时分帧 (推荐)</option>
                <option value="TimeoutMs">TimeoutMs: 显式固定静默超时分帧 (ms)</option>
                <option value="Delimiter">Delimiter: 特殊定界符分帧 (如 0D0A 回车换行)</option>
                <option value="FixedLength">FixedLength: 固定字节长度分帧</option>
              </select>
            </div>

            <!-- 根据模式显示对应参数输入 -->
            <div v-if="config.frame_mode === 'TimeoutMs'">
              <label class="block text-[11px] font-bold text-slate-600 mb-1">静默超时毫秒数 (Timeout ms)</label>
              <input v-model.number="config.frame_timeout_ms" type="number" min="1" max="10000"
                class="w-full bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
            </div>

            <div v-else-if="config.frame_mode === 'Delimiter'">
              <label class="block text-[11px] font-bold text-slate-600 mb-1">定界符十六进制 (Delimiter Hex)</label>
              <input v-model="config.frame_delimiter_hex" placeholder="如 0D0A 或 0A"
                class="w-full bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
            </div>

            <div v-else-if="config.frame_mode === 'FixedLength'">
              <label class="block text-[11px] font-bold text-slate-600 mb-1">每帧固定字节长度 (Fixed Length)</label>
              <input v-model.number="config.frame_fixed_length" type="number" min="1" max="65535"
                class="w-full bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
            </div>

            <div v-else class="flex items-center text-[11px] text-slate-500 bg-slate-50 p-2 rounded-xl border border-slate-200">
              <span>根据波特率与字符结构，底层引擎自动计算 3.5 字符无数据静默判定为一帧。</span>
            </div>
          </div>
        </div>

        <!-- 启动状态反馈 -->
        <div v-if="statusMsg" :class="['p-3 rounded-xl text-xs font-mono border',
          statusMsg.startsWith('✓') ? 'bg-emerald-50 text-emerald-800 border-emerald-200' : 'bg-rose-50 text-rose-800 border-rose-200']">
          {{ statusMsg }}
        </div>
      </div>

      <!-- 模态框底部操作栏 -->
      <div class="px-6 py-3 border-t border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <span class="text-[11px] text-slate-500 font-mono">
          当前配置: {{ selectedPort || '未选串口' }} @ {{ config.baud_rate }}bps ({{ config.data_bits }}-{{ config.parity[0] }}-{{ config.stop_bits }})
        </span>
        <div class="flex items-center gap-2">
          <button @click="$emit('close')" class="px-3.5 py-1.5 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer">
            取消
          </button>
          <button @click="startCaptureWithConfig" :disabled="isStarting || !selectedPort"
            class="bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white text-xs px-4 py-1.5 rounded-xl font-bold cursor-pointer transition-all shadow-sm active:scale-95 disabled:opacity-40">
            <span v-if="isStarting" class="animate-spin">⏳ </span>
            <span>以专业参数挂钩监听</span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { invoke } from '@tauri-apps/api/core';

const props = defineProps<{
  isOpen: boolean;
  serialPorts: string[];
  defaultPort?: string;
}>();

const emit = defineEmits(['close', 'started', 'log']);

const selectedPort = ref(props.defaultPort || (props.serialPorts.length > 0 ? props.serialPorts[0] : ''));
const isStarting = ref(false);
const statusMsg = ref<string | null>(null);

const config = ref({
  baud_rate: 9600,
  data_bits: 8,
  parity: 'None',
  stop_bits: 1,
  flow_control: 'None',
  frame_mode: 'Auto3_5T',
  frame_timeout_ms: 50,
  frame_delimiter_hex: '0D0A',
  frame_fixed_length: 64,
});

// 计算 3.5 字符时间 (ms)
const calculated3_5tMs = computed(() => {
  const baud = config.value.baud_rate || 9600;
  if (baud > 19200) {
    return 1.75; // Modbus 规范：高于 19200 时固定为 1.75ms
  }
  const bitsPerChar = 1 + config.value.data_bits + (config.value.parity === 'None' ? 0 : 1) + config.value.stop_bits;
  const bitTimeMs = 1000.0 / baud;
  return 3.5 * bitsPerChar * bitTimeMs;
});

function applyPreset(preset: 'modbus_rtu' | 'dlt645' | 'nmea0183' | 'high_speed') {
  if (preset === 'modbus_rtu') {
    config.value.baud_rate = 9600;
    config.value.data_bits = 8;
    config.value.parity = 'None';
    config.value.stop_bits = 1;
    config.value.flow_control = 'None';
    config.value.frame_mode = 'Auto3_5T';
  } else if (preset === 'dlt645') {
    config.value.baud_rate = 2400;
    config.value.data_bits = 8;
    config.value.parity = 'Even';
    config.value.stop_bits = 1;
    config.value.flow_control = 'None';
    config.value.frame_mode = 'Auto3_5T';
  } else if (preset === 'nmea0183') {
    config.value.baud_rate = 4800;
    config.value.data_bits = 8;
    config.value.parity = 'None';
    config.value.stop_bits = 1;
    config.value.flow_control = 'None';
    config.value.frame_mode = 'Delimiter';
    config.value.frame_delimiter_hex = '0D0A';
  } else if (preset === 'high_speed') {
    config.value.baud_rate = 115200;
    config.value.data_bits = 8;
    config.value.parity = 'None';
    config.value.stop_bits = 1;
    config.value.flow_control = 'None';
    config.value.frame_mode = 'Auto3_5T';
  }
}

async function startCaptureWithConfig() {
  if (!selectedPort.value || isStarting.value) return;
  isStarting.value = true;
  statusMsg.value = null;

  try {
    const res = await invoke<string>('start_serial_capture_with_config', {
      port: selectedPort.value,
      config: config.value,
    });
    statusMsg.value = `✓ ${res}`;
    emit('log', res);
    emit('started', { port: selectedPort.value, baudRate: config.value.baud_rate });
    setTimeout(() => {
      emit('close');
      statusMsg.value = null;
    }, 1200);
  } catch (err: any) {
    statusMsg.value = `❌ 启动失败: ${err?.message || String(err)}`;
  } finally {
    isStarting.value = false;
  }
}
</script>
