<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md">
    <div class="w-full max-w-3xl bg-white/95 backdrop-blur-2xl rounded-3xl border border-white/60 shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      <!-- 头部 -->
      <div class="px-6 py-4 border-b border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-indigo-50 border border-indigo-200 flex items-center justify-center text-indigo-700 text-sm font-bold shadow-2xs">
            🔀
          </div>
          <div>
            <h3 class="text-sm font-bold text-slate-900">双串口工业级透明中继器 (SerialBridge)</h3>
            <p class="text-[11px] text-slate-500 font-mono">实现 A/B 双串口纳秒级零损耗双向全双工透传与镜像嗅探</p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer">
          ✕
        </button>
      </div>

      <!-- 主体内容 -->
      <div class="p-6 space-y-5 overflow-auto max-h-[75vh] custom-scrollbar">
        <!-- 启动新中继配置面板 -->
        <div class="bg-indigo-50/70 border border-indigo-100 rounded-2xl p-4 flex flex-col gap-3">
          <div class="flex items-center justify-between text-xs font-bold text-indigo-950 border-b border-indigo-200/60 pb-2">
            <span>建立双串口双向透明中继通道</span>
            <span class="text-[10px] text-indigo-600 font-normal">A ➔ B 与 B ➔ A 实时双向转发并截获留存</span>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <!-- 通道 A 配置 -->
            <div class="bg-white border border-indigo-200/80 rounded-xl p-3 flex flex-col gap-2 shadow-2xs">
              <div class="font-bold text-slate-800 flex items-center justify-between">
                <span>端口 A (COM-A)</span>
                <span class="text-[10px] text-blue-600 font-mono">主控端 / 上位机</span>
              </div>
              <div>
                <label class="block text-[10px] font-bold text-slate-500 uppercase mb-1">选择串口</label>
                <select v-model="portA" class="w-full bg-white border border-slate-200 rounded-lg px-2.5 py-1 text-xs font-mono">
                  <option v-for="p in serialPorts" :key="p" :value="p" :disabled="p === portB">{{ p }}</option>
                </select>
              </div>
              <div class="grid grid-cols-2 gap-2">
                <div>
                  <label class="block text-[10px] font-bold text-slate-500 uppercase mb-1">波特率</label>
                  <select v-model.number="baudA" class="w-full bg-white border border-slate-200 rounded-lg px-2 py-1 text-xs font-mono">
                    <option :value="9600">9600</option>
                    <option :value="19200">19200</option>
                    <option :value="38400">38400</option>
                    <option :value="57600">57600</option>
                    <option :value="115200">115200</option>
                  </select>
                </div>
                <div>
                  <label class="block text-[10px] font-bold text-slate-500 uppercase mb-1">校验位</label>
                  <select v-model="parityA" class="w-full bg-white border border-slate-200 rounded-lg px-2 py-1 text-xs font-mono">
                    <option value="None">None 无校验</option>
                    <option value="Odd">Odd 奇校验</option>
                    <option value="Even">Even 偶校验</option>
                  </select>
                </div>
              </div>
            </div>

            <!-- 通道 B 配置 -->
            <div class="bg-white border border-indigo-200/80 rounded-xl p-3 flex flex-col gap-2 shadow-2xs">
              <div class="font-bold text-slate-800 flex items-center justify-between">
                <span>端口 B (COM-B)</span>
                <span class="text-[10px] text-emerald-600 font-mono">下位机 / 现场仪表</span>
              </div>
              <div>
                <label class="block text-[10px] font-bold text-slate-500 uppercase mb-1">选择串口</label>
                <select v-model="portB" class="w-full bg-white border border-slate-200 rounded-lg px-2.5 py-1 text-xs font-mono">
                  <option v-for="p in serialPorts" :key="p" :value="p" :disabled="p === portA">{{ p }}</option>
                </select>
              </div>
              <div class="grid grid-cols-2 gap-2">
                <div>
                  <label class="block text-[10px] font-bold text-slate-500 uppercase mb-1">波特率</label>
                  <select v-model.number="baudB" class="w-full bg-white border border-slate-200 rounded-lg px-2 py-1 text-xs font-mono">
                    <option :value="9600">9600</option>
                    <option :value="19200">19200</option>
                    <option :value="38400">38400</option>
                    <option :value="57600">57600</option>
                    <option :value="115200">115200</option>
                  </select>
                </div>
                <div>
                  <label class="block text-[10px] font-bold text-slate-500 uppercase mb-1">校验位</label>
                  <select v-model="parityB" class="w-full bg-white border border-slate-200 rounded-lg px-2 py-1 text-xs font-mono">
                    <option value="None">None 无校验</option>
                    <option value="Odd">Odd 奇校验</option>
                    <option value="Even">Even 偶校验</option>
                  </select>
                </div>
              </div>
            </div>
          </div>

          <button @click="startBridge" :disabled="isStarting || !portA || !portB || portA === portB"
            class="w-full bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 text-white text-xs py-2 rounded-xl font-bold transition-all shadow-sm active:scale-95 disabled:opacity-40 cursor-pointer">
            <span v-if="isStarting" class="animate-spin">⏳ </span>
            <span>启动双串口中继透明桥接 (COM-A ⇄ COM-B)</span>
          </button>
        </div>

        <!-- 当前活跃中继器流水列表 -->
        <div class="space-y-3 border-t border-slate-200/60 pt-4">
          <div class="flex items-center justify-between">
            <h4 class="text-xs font-bold text-slate-700 uppercase tracking-wider">
              当前活跃中继器清单 ({{ activeBridges.length }} 组)
            </h4>
            <button @click="fetchActiveBridges" class="text-[11px] text-indigo-600 hover:text-indigo-800 font-semibold cursor-pointer">
              ⟳ 刷新状态
            </button>
          </div>

          <div class="space-y-2.5">
            <div v-for="b in activeBridges" :key="b.bridge_id"
              class="bg-white border border-slate-200/80 rounded-2xl p-3.5 shadow-2xs flex flex-col gap-2">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-2">
                  <span class="w-2 h-2 rounded-full" :class="b.is_running ? 'bg-emerald-500 animate-pulse' : 'bg-slate-300'"></span>
                  <span class="font-bold text-xs text-slate-900 font-mono">
                    {{ b.port_a }} (@{{ b.baud_a }}) ⇄ {{ b.port_b }} (@{{ b.baud_b }})
                  </span>
                  <span class="text-[10px] bg-slate-100 text-slate-600 px-2 py-0.5 rounded font-mono">
                    ID: {{ b.bridge_id }}
                  </span>
                </div>
                <button @click="stopBridge(b.bridge_id)"
                  class="bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-xs px-2.5 py-1 rounded-xl font-semibold transition-all cursor-pointer shadow-2xs active:scale-95">
                  停止中继
                </button>
              </div>

              <!-- 流量双向转发度量 -->
              <div class="grid grid-cols-2 gap-2 text-xs font-mono bg-slate-50 p-2.5 rounded-xl border border-slate-100">
                <div class="flex items-center justify-between">
                  <span class="text-slate-500">A ➔ B 转发量:</span>
                  <strong class="text-blue-700">{{ formatBytes(b.bytes_a_to_b) }}</strong>
                </div>
                <div class="flex items-center justify-between">
                  <span class="text-slate-500">B ➔ A 转发量:</span>
                  <strong class="text-emerald-700">{{ formatBytes(b.bytes_b_to_a) }}</strong>
                </div>
              </div>
            </div>

            <div v-if="activeBridges.length === 0" class="p-8 text-center text-slate-400 text-xs bg-slate-50/50 rounded-2xl border border-dashed border-slate-200">
              暂无运行中的双串口透明中继器
            </div>
          </div>
        </div>
      </div>

      <!-- 底部关闭 -->
      <div class="px-6 py-3 border-t border-slate-200/60 bg-white/40 flex items-center justify-end shrink-0">
        <button @click="$emit('close')" class="px-4 py-1.5 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer">
          关闭
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { notifySuccess, notifyInfo, notifyError } from '../composables/useNotification';
import { ref, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';

export interface ActiveSerialBridgeInfo {
  bridge_id: string;
  port_a: string;
  baud_a: number;
  port_b: string;
  baud_b: number;
  start_time: string;
  bytes_a_to_b: number;
  bytes_b_to_a: number;
  is_running: boolean;
}

const props = defineProps<{
  isOpen: boolean;
  serialPorts: string[];
}>();

const emit = defineEmits(['close', 'log']);

const portA = ref(props.serialPorts.length > 0 ? props.serialPorts[0] : '');
const baudA = ref(115200);
const parityA = ref('None');

const portB = ref(props.serialPorts.length > 1 ? props.serialPorts[1] : '');
const baudB = ref(9600);
const parityB = ref('None');

const isStarting = ref(false);
const activeBridges = ref<ActiveSerialBridgeInfo[]>([]);

let pollTimer: any = null;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

async function fetchActiveBridges() {
  try {
    const list = await invoke<ActiveSerialBridgeInfo[]>('list_active_serial_bridges');
    activeBridges.value = list;
  } catch (err) {
    console.error('获取活跃串口中继器失败:', err);
  }
}

async function startBridge() {
  if (!portA.value || !portB.value || portA.value === portB.value || isStarting.value) return;
  isStarting.value = true;

  try {
    const configA = {
      baud_rate: baudA.value,
      data_bits: 8,
      parity: parityA.value,
      stop_bits: 1,
      flow_control: 'None',
      frame_mode: 'Auto3_5T',
      frame_timeout_ms: 50,
      frame_delimiter_hex: '0D0A',
      frame_fixed_length: 64,
    };
    const configB = {
      baud_rate: baudB.value,
      data_bits: 8,
      parity: parityB.value,
      stop_bits: 1,
      flow_control: 'None',
      frame_mode: 'Auto3_5T',
      frame_timeout_ms: 50,
      frame_delimiter_hex: '0D0A',
      frame_fixed_length: 64,
    };

    const res = await invoke<string>('start_serial_bridge_cmd', {
      portA: portA.value,
      configA,
      portB: portB.value,
      configB,
    });
    emit('log', res);
    await fetchActiveBridges();
    notifySuccess('双串口中继已建立', `${portA.value} ⇄ ${portB.value} 双向中继链路已接通`);
  } catch (err: any) {
    notifyError('启动双串口中继受阻', err);
  } finally {
    isStarting.value = false;
  }
}

async function stopBridge(bridgeId: string) {
  try {
    const res = await invoke<string>('stop_serial_bridge_cmd', {
      bridgeId,
    });
    emit('log', res);
    await fetchActiveBridges();
    notifyInfo('双串口中继已断开', '已安全终止数据双向转发桥接');
  } catch (err: any) {
    notifyError('停止串口中继受阻', err);
  }
}

onMounted(() => {
  fetchActiveBridges();
  pollTimer = setInterval(fetchActiveBridges, 2000);
});

onUnmounted(() => {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
});
</script>
