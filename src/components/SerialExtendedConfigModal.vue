<template>
  <div v-if="isOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
    <div class="ui-modal-surface w-full max-w-2xl rounded-3xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      <!-- 模态框头部 -->
      <div class="ui-nav-glass px-6 py-4 border-b border-(--border-subtle) flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-indigo-500/12 border border-indigo-500/30 flex items-center justify-center text-indigo-600 dark:text-indigo-400">
            <AppIcon name="serial" class="w-4 h-4" />
          </div>
          <div>
            <h3 class="text-sm font-bold text-(--text-primary)">串口工业通信参数与动态分帧配置</h3>
            <p class="text-xs text-(--text-muted) font-mono-code">符合 Modbus RTU / DL/T 645 / NMEA 0183 规约与 3.5T 超时推导</p>
          </div>
        </div>
        <button @click="$emit('close')" class="ui-btn-secondary w-8 h-8 rounded-full p-0 flex items-center justify-center cursor-pointer" aria-label="关闭弹窗">
          <AppIcon name="close" class="w-4 h-4" />
        </button>
      </div>

      <!-- 模态框主体内容 -->
      <div class="p-6 space-y-5 overflow-auto max-h-[75vh] custom-scrollbar">
        <!-- 行业预设模板快捷载入 -->
        <div class="ui-sub-card border-indigo-500/30 rounded-2xl p-3.5 flex flex-col gap-2.5">
          <div class="flex items-center justify-between text-xs font-bold text-(--text-primary)">
            <span class="inline-flex items-center gap-1.5">
              <AppIcon name="zap" class="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
              <span>行业标准规约预设模板:</span>
            </span>
            <span class="text-[11px] text-indigo-600 dark:text-indigo-400 font-normal">一键载入工控标准物理层与分帧策略</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
            <button @click="applyPreset('modbus_rtu')"
              class="ui-content-card hover:border-indigo-500/50 text-(--text-primary) p-2.5 rounded-xl text-left transition-all cursor-pointer">
              <div class="font-bold text-xs">Modbus RTU</div>
              <div class="text-[11px] text-(--text-muted) font-mono-code ui-num">9600, 8-N-1, 3.5T</div>
            </button>
            <button @click="applyPreset('dlt645')"
              class="ui-content-card hover:border-indigo-500/50 text-(--text-primary) p-2.5 rounded-xl text-left transition-all cursor-pointer">
              <div class="font-bold text-xs">DL/T 645 电表</div>
              <div class="text-[11px] text-(--text-muted) font-mono-code ui-num">2400, 8-E-1, 3.5T</div>
            </button>
            <button @click="applyPreset('nmea0183')"
              class="ui-content-card hover:border-indigo-500/50 text-(--text-primary) p-2.5 rounded-xl text-left transition-all cursor-pointer">
              <div class="font-bold text-xs">NMEA 0183 导航</div>
              <div class="text-[11px] text-(--text-muted) font-mono-code ui-num">4800, 8-N-1, CRLF</div>
            </button>
            <button @click="applyPreset('high_speed')"
              class="ui-content-card hover:border-indigo-500/50 text-(--text-primary) p-2.5 rounded-xl text-left transition-all cursor-pointer">
              <div class="font-bold text-xs">高速工控串口</div>
              <div class="text-[11px] text-(--text-muted) font-mono-code ui-num">115200, 8-N-1, 3.5T</div>
            </button>
          </div>
        </div>

        <!-- 硬件参数配置网格 -->
        <div class="space-y-3">
          <h4 class="text-xs font-bold text-(--text-primary) uppercase tracking-wider">1. 物理层四大参数与流控</h4>
          <div class="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
            <div>
              <label class="block text-[11px] font-bold text-(--text-secondary) mb-1">目标串口 (COM Port)</label>
              <select v-model="selectedPort"
                class="ui-input w-full px-2.5 py-1.5 font-mono-code text-xs">
                <option v-for="p in serialPorts" :key="p" :value="p">{{ p }}</option>
                <option v-if="serialPorts.length === 0" value="">未发现可用串口</option>
              </select>
            </div>

            <div>
              <label class="block text-[11px] font-bold text-(--text-secondary) mb-1">波特率 (Baud Rate)</label>
              <select v-model.number="config.baud_rate"
                class="ui-input w-full px-2.5 py-1.5 font-mono-code ui-num text-xs">
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
              <label class="block text-[11px] font-bold text-(--text-secondary) mb-1">数据位 (Data Bits)</label>
              <select v-model.number="config.data_bits"
                class="ui-input w-full px-2.5 py-1.5 font-mono-code ui-num text-xs">
                <option :value="5">5 Bits</option>
                <option :value="6">6 Bits</option>
                <option :value="7">7 Bits</option>
                <option :value="8">8 Bits (常用)</option>
              </select>
            </div>

            <div>
              <label class="block text-[11px] font-bold text-(--text-secondary) mb-1">奇偶校验位 (Parity)</label>
              <select v-model="config.parity"
                class="ui-input w-full px-2.5 py-1.5 font-mono-code text-xs">
                <option value="None">None 无校验 (8-N-1)</option>
                <option value="Odd">Odd 奇校验</option>
                <option value="Even">Even 偶校验 (DL/T 645)</option>
              </select>
            </div>

            <div>
              <label class="block text-[11px] font-bold text-(--text-secondary) mb-1">停止位 (Stop Bits)</label>
              <select v-model.number="config.stop_bits"
                class="ui-input w-full px-2.5 py-1.5 font-mono-code ui-num text-xs">
                <option :value="1">1 停止位</option>
                <option :value="2">2 停止位</option>
              </select>
            </div>

            <div>
              <label class="block text-[11px] font-bold text-(--text-secondary) mb-1">硬件/软件流控 (Flow Control)</label>
              <select v-model="config.flow_control"
                class="ui-input w-full px-2.5 py-1.5 font-mono-code text-xs">
                <option value="None">None 无流控</option>
                <option value="Software">Software 软件流控 (XON/XOFF)</option>
                <option value="Hardware">Hardware 硬件流控 (RTS/CTS)</option>
              </select>
            </div>
          </div>
        </div>

        <!-- 动态分帧策略配置 -->
        <div class="space-y-3 border-t border-(--border-subtle) pt-4">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <h4 class="text-xs font-bold text-(--text-primary) uppercase tracking-wider">2. 工业级数据流分帧引擎 (Framing Engine)</h4>
            <span class="text-[11px] text-indigo-700 dark:text-indigo-300 font-mono-code ui-num font-bold bg-indigo-500/12 px-2.5 py-0.5 rounded-lg border border-indigo-500/30">
              理论 3.5T 动态超时: {{ calculated3_5tMs.toFixed(2) }} ms
            </span>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div>
              <label class="block text-[11px] font-bold text-(--text-secondary) mb-1">分帧模式 (Frame Mode)</label>
              <select v-model="config.frame_mode"
                class="ui-input w-full px-2.5 py-1.5 font-bold text-xs">
                <option value="Auto3_5T">Auto3_5T: 智能 3.5 字符动态时间超时分帧 (推荐)</option>
                <option value="TimeoutMs">TimeoutMs: 显式固定静默超时分帧 (ms)</option>
                <option value="Delimiter">Delimiter: 特殊定界符分帧 (如 0D0A 回车换行)</option>
                <option value="FixedLength">FixedLength: 固定字节长度分帧</option>
              </select>
            </div>

            <!-- 根据模式显示对应参数输入 -->
            <div v-if="config.frame_mode === 'TimeoutMs'">
              <label class="block text-[11px] font-bold text-(--text-secondary) mb-1">静默超时毫秒数 (Timeout ms)</label>
              <input v-model.number="config.frame_timeout_ms" type="number" min="1" max="10000"
                class="ui-input w-full px-2.5 py-1.5 font-mono-code ui-num text-xs">
            </div>

            <div v-else-if="config.frame_mode === 'Delimiter'">
              <label class="block text-[11px] font-bold text-(--text-secondary) mb-1">定界符十六进制 (Delimiter Hex)</label>
              <input v-model="config.frame_delimiter_hex" placeholder="如 0D0A 或 0A"
                class="ui-input w-full px-2.5 py-1.5 font-mono-code text-xs">
            </div>

            <div v-else-if="config.frame_mode === 'FixedLength'">
              <label class="block text-[11px] font-bold text-(--text-secondary) mb-1">每帧固定字节长度 (Fixed Length)</label>
              <input v-model.number="config.frame_fixed_length" type="number" min="1" max="65535"
                class="ui-input w-full px-2.5 py-1.5 font-mono-code ui-num text-xs">
            </div>

            <div v-else class="ui-sub-card flex items-center text-xs text-(--text-secondary) p-2.5 rounded-xl">
              <span>根据波特率与字符结构，底层引擎自动计算 3.5 字符无数据静默判定为一帧。</span>
            </div>
          </div>
        </div>

        <!-- 启动状态反馈 -->
        <div v-if="statusMsg" :class="['p-3 rounded-xl text-xs font-mono-code border select-text',
          !isStatusError ? 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' : 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/30']">
          {{ statusMsg }}
        </div>
      </div>

      <!-- 模态框底部操作栏 -->
      <div class="px-6 py-3 border-t border-(--border-subtle) bg-(--surface-content-alt) flex items-center justify-between shrink-0">
        <span class="text-xs text-(--text-muted) font-mono-code ui-num">
          当前配置: {{ selectedPort || '未选串口' }} @ {{ config.baud_rate }}bps ({{ config.data_bits }}-{{ config.parity[0] }}-{{ config.stop_bits }})
        </span>
        <div class="flex items-center gap-2">
          <button @click="$emit('close')" class="ui-btn-secondary px-3.5 py-1.5 text-xs font-semibold cursor-pointer">
            取消
          </button>
          <button @click="startCaptureWithConfig" :disabled="isStarting || !selectedPort"
            class="ui-btn-primary text-xs px-4 py-1.5 font-bold inline-flex items-center gap-1.5 cursor-pointer disabled:opacity-40">
            <AppIcon v-if="isStarting" name="refresh" class="w-3.5 h-3.5 animate-spin" />
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
import AppIcon from './AppIcon.vue';

const props = defineProps<{
  isOpen: boolean;
  serialPorts: string[];
  defaultPort?: string;
}>();

const emit = defineEmits(['close', 'started', 'log']);

const selectedPort = ref(props.defaultPort || (props.serialPorts.length > 0 ? props.serialPorts[0] : ''));
const isStarting = ref(false);
const statusMsg = ref<string | null>(null);
const isStatusError = ref(false);

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
  isStatusError.value = false;

  try {
    const res = await invoke<string>('start_serial_capture_with_config', {
      port: selectedPort.value,
      config: config.value,
    });
    isStatusError.value = false;
    statusMsg.value = res;
    emit('log', res);
    emit('started', { port: selectedPort.value, baudRate: config.value.baud_rate });
    setTimeout(() => {
      emit('close');
      statusMsg.value = null;
    }, 1200);
  } catch (err: any) {
    isStatusError.value = true;
    statusMsg.value = `启动失败: ${err?.message || String(err)}`;
  } finally {
    isStarting.value = false;
  }
}
</script>
