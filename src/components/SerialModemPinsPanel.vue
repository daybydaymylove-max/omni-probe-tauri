<template>
  <div class="ui-content-card rounded-2xl p-4 flex flex-col gap-3">
    <!-- 面板头部 -->
    <div class="flex items-center justify-between border-b border-(--border-subtle) pb-2.5 flex-wrap gap-2">
      <div class="flex items-center gap-2">
        <span class="w-2 h-2 rounded-full bg-indigo-500"></span>
        <span class="text-xs font-bold text-(--text-primary)">RS-232 / Modem 硬件握手引脚状态与电平控制</span>
        <span class="text-[11px] text-(--text-muted) font-mono-code">实时采集 CTS/DSR/RI/CD 与主动反控 RTS/DTR</span>
      </div>

      <!-- 操作与选择串口 -->
      <div class="flex items-center gap-2 text-xs">
        <select v-model="selectedPort" @change="fetchStatus"
          class="ui-input px-2.5 py-1 text-xs font-mono-code">
          <option v-for="p in serialPorts" :key="p" :value="p">{{ p }}</option>
          <option v-if="serialPorts.length === 0" value="">未发现串口</option>
        </select>

        <!-- 自动轮询 Toggle -->
        <button @click="togglePolling"
          :class="['px-2.5 py-1 rounded-xl text-xs font-semibold border transition-all cursor-pointer inline-flex items-center gap-1.5',
            isPolling ? 'bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border-indigo-500/35' : 'ui-btn-secondary']">
          <span class="w-1.5 h-1.5 rounded-full" :class="isPolling ? 'bg-indigo-500' : 'bg-slate-400'"></span>
          <span>{{ isPolling ? '轮询中 (1s)' : '自动轮询: 关' }}</span>
        </button>

        <!-- 手动刷新 -->
        <button @click="fetchStatus" :disabled="isLoading || !selectedPort"
          class="ui-btn-secondary inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold cursor-pointer disabled:opacity-40">
          <AppIcon name="refresh" class="w-3.5 h-3.5" :class="{ 'animate-spin': isLoading }" />
          <span>刷新电平</span>
        </button>
      </div>
    </div>

    <!-- 引脚状态指示灯与控制开关网格 -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
      <!-- 1. 输入引脚状态 (Input Pins / Status from Device) -->
      <div class="ui-sub-card rounded-xl p-3 flex flex-col gap-2">
        <div class="text-xs font-bold text-(--text-primary) uppercase flex items-center justify-between gap-2">
          <span>设备输入引脚状态 (Inputs)</span>
          <span class="text-[11px] text-(--text-muted) font-normal">绿: 有效高电平 | 灰: 低电平</span>
        </div>

        <div class="grid grid-cols-2 gap-2 text-xs font-mono-code">
          <!-- CTS -->
          <div class="ui-content-card p-2.5 rounded-lg flex items-center justify-between">
            <div>
              <div class="font-bold text-(--text-primary)">CTS (Clear To Send)</div>
              <div class="text-[11px] text-(--text-muted) font-sans">允许发送信号</div>
            </div>
            <div class="flex items-center gap-1.5">
              <span class="w-2.5 h-2.5 rounded-full transition-colors"
                :class="modemStatus?.cts ? 'bg-emerald-500' : 'bg-slate-400'"></span>
              <span class="text-[11px] font-bold ui-num" :class="modemStatus?.cts ? 'text-emerald-600 dark:text-emerald-400' : 'text-(--text-muted)'">
                {{ modemStatus?.cts ? 'ON' : 'OFF' }}
              </span>
            </div>
          </div>

          <!-- DSR -->
          <div class="ui-content-card p-2.5 rounded-lg flex items-center justify-between">
            <div>
              <div class="font-bold text-(--text-primary)">DSR (Data Set Ready)</div>
              <div class="text-[11px] text-(--text-muted) font-sans">数据设备就绪</div>
            </div>
            <div class="flex items-center gap-1.5">
              <span class="w-2.5 h-2.5 rounded-full transition-colors"
                :class="modemStatus?.dsr ? 'bg-emerald-500' : 'bg-slate-400'"></span>
              <span class="text-[11px] font-bold ui-num" :class="modemStatus?.dsr ? 'text-emerald-600 dark:text-emerald-400' : 'text-(--text-muted)'">
                {{ modemStatus?.dsr ? 'ON' : 'OFF' }}
              </span>
            </div>
          </div>

          <!-- RI -->
          <div class="ui-content-card p-2.5 rounded-lg flex items-center justify-between">
            <div>
              <div class="font-bold text-(--text-primary)">RI (Ring Indicator)</div>
              <div class="text-[11px] text-(--text-muted) font-sans">振铃指示信号</div>
            </div>
            <div class="flex items-center gap-1.5">
              <span class="w-2.5 h-2.5 rounded-full transition-colors"
                :class="modemStatus?.ri ? 'bg-amber-500' : 'bg-slate-400'"></span>
              <span class="text-[11px] font-bold ui-num" :class="modemStatus?.ri ? 'text-amber-600 dark:text-amber-400' : 'text-(--text-muted)'">
                {{ modemStatus?.ri ? 'ON' : 'OFF' }}
              </span>
            </div>
          </div>

          <!-- CD -->
          <div class="ui-content-card p-2.5 rounded-lg flex items-center justify-between">
            <div>
              <div class="font-bold text-(--text-primary)">CD (Carrier Detect)</div>
              <div class="text-[11px] text-(--text-muted) font-sans">载波检测信号</div>
            </div>
            <div class="flex items-center gap-1.5">
              <span class="w-2.5 h-2.5 rounded-full transition-colors"
                :class="modemStatus?.cd ? 'bg-emerald-500' : 'bg-slate-400'"></span>
              <span class="text-[11px] font-bold ui-num" :class="modemStatus?.cd ? 'text-emerald-600 dark:text-emerald-400' : 'text-(--text-muted)'">
                {{ modemStatus?.cd ? 'ON' : 'OFF' }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- 2. 输出引脚电平反控 (Outputs to Device / Local Control) -->
      <div class="ui-sub-card rounded-xl p-3 flex flex-col gap-2">
        <div class="text-xs font-bold text-(--text-primary) uppercase flex items-center justify-between gap-2">
          <span>本地输出引脚电平控制 (Outputs)</span>
          <span class="text-[11px] text-indigo-600 dark:text-indigo-400 font-normal">点击切换物理引脚电平</span>
        </div>

        <div class="grid grid-cols-2 gap-2 text-xs font-mono-code">
          <!-- RTS 控制 -->
          <div class="ui-content-card p-2.5 rounded-lg flex flex-col justify-between gap-2">
            <div>
              <div class="font-bold text-(--text-primary)">RTS (Request To Send)</div>
              <div class="text-[11px] text-(--text-muted) font-sans">请求发送控制电平</div>
            </div>
            <div class="flex items-center justify-between gap-2">
              <span class="text-[11px] font-bold ui-num" :class="rtsState ? 'text-indigo-600 dark:text-indigo-400' : 'text-(--text-muted)'">
                {{ rtsState ? 'HIGH (高)' : 'LOW (低)' }}
              </span>
              <button @click="toggleRts" :disabled="!selectedPort"
                :class="['px-2.5 py-1 rounded-lg font-bold text-[11px] transition-all cursor-pointer disabled:opacity-40',
                  rtsState ? 'ui-btn-primary' : 'ui-btn-secondary']">
                {{ rtsState ? '置为 LOW' : '置为 HIGH' }}
              </button>
            </div>
          </div>

          <!-- DTR 控制 -->
          <div class="ui-content-card p-2.5 rounded-lg flex flex-col justify-between gap-2">
            <div>
              <div class="font-bold text-(--text-primary)">DTR (Data Terminal Ready)</div>
              <div class="text-[11px] text-(--text-muted) font-sans">数据终端就绪电平</div>
            </div>
            <div class="flex items-center justify-between gap-2">
              <span class="text-[11px] font-bold ui-num" :class="dtrState ? 'text-indigo-600 dark:text-indigo-400' : 'text-(--text-muted)'">
                {{ dtrState ? 'HIGH (高)' : 'LOW (低)' }}
              </span>
              <button @click="toggleDtr" :disabled="!selectedPort"
                :class="['px-2.5 py-1 rounded-lg font-bold text-[11px] transition-all cursor-pointer disabled:opacity-40',
                  dtrState ? 'ui-btn-primary' : 'ui-btn-secondary']">
                {{ dtrState ? '置为 LOW' : '置为 HIGH' }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 错误或反馈提示 -->
    <div v-if="errorMsg" class="p-2.5 rounded-xl bg-rose-500/12 border border-rose-500/30 text-rose-700 dark:text-rose-300 text-xs font-mono-code select-text">
      {{ errorMsg }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import AppIcon from './AppIcon.vue';

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

let unlistenModemChanged: UnlistenFn | null = null;

onMounted(async () => {
  if (selectedPort.value) {
    fetchStatus();
  }
  try {
    unlistenModemChanged = await listen<Partial<SerialModemStatus> & { port?: string }>(
      'serial-modem-status-changed',
      ({ payload }) => {
        const targetPort = payload.port || payload.port_name;
        if (!targetPort || targetPort === selectedPort.value) {
          if (modemStatus.value) {
            modemStatus.value = {
              ...modemStatus.value,
              cts: payload.cts ?? modemStatus.value.cts,
              dsr: payload.dsr ?? modemStatus.value.dsr,
              ri: payload.ri ?? modemStatus.value.ri,
              cd: payload.cd ?? modemStatus.value.cd,
              rts: payload.rts ?? modemStatus.value.rts,
              dtr: payload.dtr ?? modemStatus.value.dtr,
            };
          } else {
            fetchStatus();
          }
        }
      }
    );
  } catch (e) {
    console.warn('[SerialModemPinsPanel] 挂载引脚事件监听失败:', e);
  }
});

onUnmounted(() => {
  if (unlistenModemChanged) {
    unlistenModemChanged();
    unlistenModemChanged = null;
  }
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
});
</script>
