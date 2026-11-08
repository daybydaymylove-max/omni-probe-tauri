<template>
  <div class="bg-white/80 backdrop-blur-xl rounded-2xl border border-indigo-100 shadow-sm p-3.5 flex flex-col gap-3">
    <!-- 面板头部 -->
    <div class="flex items-center justify-between border-b border-slate-200/60 pb-2.5 flex-wrap gap-2">
      <div class="flex items-center gap-2">
        <span class="w-2 h-2 rounded-full bg-indigo-600 animate-pulse"></span>
        <span class="text-xs font-bold text-indigo-950">RS-232 / Modem 硬件握手引脚状态与电平控制</span>
        <span class="text-[10px] text-slate-500 font-mono">（实时采集 CTS/DSR/RI/CD 与主动反控 RTS/DTR）</span>
      </div>

      <!-- 操作与选择串口 -->
      <div class="flex items-center gap-2 text-xs">
        <select v-model="selectedPort" @change="fetchStatus"
          class="bg-white border border-slate-200 rounded-xl px-2 py-1 text-xs font-mono text-slate-700 focus:outline-none shadow-2xs">
          <option v-for="p in serialPorts" :key="p" :value="p">{{ p }}</option>
          <option v-if="serialPorts.length === 0" value="">未发现串口</option>
        </select>

        <!-- 自动轮询 Toggle -->
        <button @click="togglePolling"
          :class="['px-2.5 py-1 rounded-xl text-xs font-semibold border transition-all cursor-pointer flex items-center gap-1 shadow-2xs active:scale-95',
            isPolling ? 'bg-indigo-50 text-indigo-700 border-indigo-300' : 'bg-white text-slate-600 border-slate-200']">
          <span class="w-1.5 h-1.5 rounded-full" :class="isPolling ? 'bg-indigo-600 animate-pulse' : 'bg-slate-300'"></span>
          <span>{{ isPolling ? '轮询中 (1s)' : '自动轮询: 关' }}</span>
        </button>

        <!-- 手动刷新 -->
        <button @click="fetchStatus" :disabled="isLoading || !selectedPort"
          class="bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-2.5 py-1 rounded-xl text-xs font-semibold transition-all cursor-pointer shadow-2xs active:scale-95 disabled:opacity-40">
          <span v-if="isLoading">⏳</span>
          <span v-else>⟳</span>
          <span>刷新电平</span>
        </button>
      </div>
    </div>

    <!-- 引脚状态指示灯与控制开关网格 -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
      <!-- 1. 输入引脚状态 (Input Pins / Status from Device) -->
      <div class="bg-slate-50/70 border border-slate-200/80 rounded-xl p-2.5 flex flex-col gap-2">
        <div class="text-[11px] font-bold text-slate-700 uppercase flex items-center justify-between">
          <span>设备输入引脚状态 (Inputs from Remote)</span>
          <span class="text-[9px] text-slate-400 font-normal">绿色: 有效/高电平 | 灰色: 无效/低电平</span>
        </div>

        <div class="grid grid-cols-2 gap-2 text-xs font-mono">
          <!-- CTS -->
          <div class="bg-white border border-slate-200/80 p-2 rounded-lg flex items-center justify-between shadow-2xs">
            <div>
              <div class="font-bold text-slate-800">CTS (Clear To Send)</div>
              <div class="text-[9px] text-slate-400">允许发送信号</div>
            </div>
            <div class="flex items-center gap-1.5">
              <span class="w-3 h-3 rounded-full transition-colors shadow-2xs"
                :class="modemStatus?.cts ? 'bg-emerald-500 shadow-emerald-200 ring-2 ring-emerald-300 animate-pulse' : 'bg-slate-300'"></span>
              <span class="text-[10px] font-bold" :class="modemStatus?.cts ? 'text-emerald-700' : 'text-slate-400'">
                {{ modemStatus?.cts ? 'ON' : 'OFF' }}
              </span>
            </div>
          </div>

          <!-- DSR -->
          <div class="bg-white border border-slate-200/80 p-2 rounded-lg flex items-center justify-between shadow-2xs">
            <div>
              <div class="font-bold text-slate-800">DSR (Data Set Ready)</div>
              <div class="text-[9px] text-slate-400">数据设备就绪</div>
            </div>
            <div class="flex items-center gap-1.5">
              <span class="w-3 h-3 rounded-full transition-colors shadow-2xs"
                :class="modemStatus?.dsr ? 'bg-emerald-500 shadow-emerald-200 ring-2 ring-emerald-300 animate-pulse' : 'bg-slate-300'"></span>
              <span class="text-[10px] font-bold" :class="modemStatus?.dsr ? 'text-emerald-700' : 'text-slate-400'">
                {{ modemStatus?.dsr ? 'ON' : 'OFF' }}
              </span>
            </div>
          </div>

          <!-- RI -->
          <div class="bg-white border border-slate-200/80 p-2 rounded-lg flex items-center justify-between shadow-2xs">
            <div>
              <div class="font-bold text-slate-800">RI (Ring Indicator)</div>
              <div class="text-[9px] text-slate-400">振铃指示信号</div>
            </div>
            <div class="flex items-center gap-1.5">
              <span class="w-3 h-3 rounded-full transition-colors shadow-2xs"
                :class="modemStatus?.ri ? 'bg-amber-500 shadow-amber-200 ring-2 ring-amber-300 animate-pulse' : 'bg-slate-300'"></span>
              <span class="text-[10px] font-bold" :class="modemStatus?.ri ? 'text-amber-700' : 'text-slate-400'">
                {{ modemStatus?.ri ? 'ON' : 'OFF' }}
              </span>
            </div>
          </div>

          <!-- CD -->
          <div class="bg-white border border-slate-200/80 p-2 rounded-lg flex items-center justify-between shadow-2xs">
            <div>
              <div class="font-bold text-slate-800">CD (Carrier Detect)</div>
              <div class="text-[9px] text-slate-400">载波检测信号</div>
            </div>
            <div class="flex items-center gap-1.5">
              <span class="w-3 h-3 rounded-full transition-colors shadow-2xs"
                :class="modemStatus?.cd ? 'bg-emerald-500 shadow-emerald-200 ring-2 ring-emerald-300 animate-pulse' : 'bg-slate-300'"></span>
              <span class="text-[10px] font-bold" :class="modemStatus?.cd ? 'text-emerald-700' : 'text-slate-400'">
                {{ modemStatus?.cd ? 'ON' : 'OFF' }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- 2. 输出引脚电平反控 (Outputs to Device / Local Control) -->
      <div class="bg-slate-50/70 border border-slate-200/80 rounded-xl p-2.5 flex flex-col gap-2">
        <div class="text-[11px] font-bold text-slate-700 uppercase flex items-center justify-between">
          <span>本地输出引脚电平控制 (Outputs Control)</span>
          <span class="text-[9px] text-indigo-600 font-normal">点击开关实时翻转物理引脚电平</span>
        </div>

        <div class="grid grid-cols-2 gap-2 text-xs font-mono">
          <!-- RTS 控制 -->
          <div class="bg-white border border-slate-200/80 p-2.5 rounded-lg flex flex-col justify-between shadow-2xs gap-2">
            <div>
              <div class="font-bold text-slate-800">RTS (Request To Send)</div>
              <div class="text-[9px] text-slate-400">请求发送控制电平</div>
            </div>
            <div class="flex items-center justify-between">
              <span class="text-[10px] font-bold" :class="rtsState ? 'text-indigo-700' : 'text-slate-400'">
                状态: {{ rtsState ? 'HIGH (高)' : 'LOW (低)' }}
              </span>
              <button @click="toggleRts" :disabled="!selectedPort"
                :class="['px-3 py-1 rounded-lg font-bold text-[10px] transition-all cursor-pointer active:scale-95 shadow-2xs',
                  rtsState ? 'bg-indigo-600 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200']">
                {{ rtsState ? '置为 LOW' : '置为 HIGH' }}
              </button>
            </div>
          </div>

          <!-- DTR 控制 -->
          <div class="bg-white border border-slate-200/80 p-2.5 rounded-lg flex flex-col justify-between shadow-2xs gap-2">
            <div>
              <div class="font-bold text-slate-800">DTR (Data Terminal Ready)</div>
              <div class="text-[9px] text-slate-400">数据终端就绪电平</div>
            </div>
            <div class="flex items-center justify-between">
              <span class="text-[10px] font-bold" :class="dtrState ? 'text-indigo-700' : 'text-slate-400'">
                状态: {{ dtrState ? 'HIGH (高)' : 'LOW (低)' }}
              </span>
              <button @click="toggleDtr" :disabled="!selectedPort"
                :class="['px-3 py-1 rounded-lg font-bold text-[10px] transition-all cursor-pointer active:scale-95 shadow-2xs',
                  dtrState ? 'bg-indigo-600 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200']">
                {{ dtrState ? '置为 LOW' : '置为 HIGH' }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 错误或反馈提示 -->
    <div v-if="errorMsg" class="p-2 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-[11px] font-mono">
      {{ errorMsg }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';

export interface SerialModemStatus {
  port_name: string;
  cts: boolean;
  dsr: boolean;
  ri: boolean;
  cd: boolean;
  rts: boolean;
  dtr: boolean;
}

const props = defineProps<{
  serialPorts: string[];
  defaultPort?: string;
}>();

const selectedPort = ref(props.defaultPort || (props.serialPorts.length > 0 ? props.serialPorts[0] : ''));
const modemStatus = ref<SerialModemStatus | null>(null);
const isLoading = ref(false);
const isPolling = ref(false);
const errorMsg = ref<string | null>(null);

const rtsState = ref(false);
const dtrState = ref(false);

let pollTimer: any = null;

watch(() => props.defaultPort, (val) => {
  if (val) {
    selectedPort.value = val;
    fetchStatus();
  }
});

async function fetchStatus() {
  if (!selectedPort.value) return;
  isLoading.value = true;
  errorMsg.value = null;

  try {
    const res = await invoke<SerialModemStatus>('get_serial_modem_status', {
      port: selectedPort.value,
    });
    modemStatus.value = res;
    rtsState.value = res.rts;
    dtrState.value = res.dtr;
  } catch (err: any) {
    errorMsg.value = `获取引脚电平失败: ${err?.message || String(err)}`;
  } finally {
    isLoading.value = false;
  }
}

async function toggleRts() {
  if (!selectedPort.value) return;
  const next = !rtsState.value;
  try {
    await invoke('set_serial_pin_state', {
      port: selectedPort.value,
      rts: next,
      dtr: null,
    });
    rtsState.value = next;
    if (modemStatus.value) modemStatus.value.rts = next;
  } catch (err: any) {
    errorMsg.value = `设置 RTS 电平失败: ${err?.message || String(err)}`;
  }
}

async function toggleDtr() {
  if (!selectedPort.value) return;
  const next = !dtrState.value;
  try {
    await invoke('set_serial_pin_state', {
      port: selectedPort.value,
      rts: null,
      dtr: next,
    });
    dtrState.value = next;
    if (modemStatus.value) modemStatus.value.dtr = next;
  } catch (err: any) {
    errorMsg.value = `设置 DTR 电平失败: ${err?.message || String(err)}`;
  }
}

function togglePolling() {
  isPolling.value = !isPolling.value;
  if (isPolling.value) {
    fetchStatus();
    pollTimer = setInterval(fetchStatus, 1000);
  } else {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }
}

onMounted(() => {
  if (selectedPort.value) {
    fetchStatus();
  }
});

onUnmounted(() => {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
});
</script>
