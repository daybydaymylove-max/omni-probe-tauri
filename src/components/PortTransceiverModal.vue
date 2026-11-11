<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 ui-modal-backdrop flex items-center justify-center p-4">
    <div class="ui-modal-surface rounded-2xl w-full max-w-3xl max-h-[85vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      <!-- 模态框顶栏 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-5 py-3.5 flex items-center justify-between shrink-0 flex-wrap gap-2">
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-xl bg-sky-500/15 border border-sky-500/30 text-sky-700 dark:text-sky-300 flex items-center justify-center font-mono font-bold text-xs shrink-0">
            TX
          </div>
          <div>
            <h3 class="text-xs font-bold leading-none" style="color: var(--text-primary)">
              端口与物理总线数据双向出入执行器
            </h3>
            <p class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">
              支持网络传输层 (TCP/UDP) 与物理串口 (COM) 真实写出与回包捕获 (TX → RX)
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2.5">
          <div class="flex ui-pill p-1 rounded-xl text-xs font-semibold">
            <button @click="channel = 'network'"
              :class="['px-3 py-1 rounded-lg transition-colors cursor-pointer',
                channel === 'network' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="channel !== 'network' ? { color: 'var(--text-secondary)' } : undefined">
              网络端口 (TCP/UDP)
            </button>
            <button @click="channel = 'serial'"
              :class="['px-3 py-1 rounded-lg transition-colors cursor-pointer',
                channel === 'serial' ? 'bg-indigo-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="channel !== 'serial' ? { color: 'var(--text-secondary)' } : undefined">
              物理串口 (COM)
            </button>
          </div>

          <button @click="$emit('close')" class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer" title="关闭">
            <AppIcon name="close" :size="15" />
          </button>
        </div>
      </header>

      <!-- 模态框主体 -->
      <div class="flex-1 flex flex-col overflow-hidden min-h-0" style="background: var(--surface-content)">
        <div class="p-4 border-b space-y-3 shrink-0" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
          <template v-if="channel === 'network'">
            <div class="grid grid-cols-1 sm:grid-cols-[1fr_85px_80px_90px] gap-2.5 items-center">
              <div>
                <label class="text-[11px] font-bold uppercase block mb-0.5" style="color: var(--text-muted)">目标 IP</label>
                <input v-model="netIp" placeholder="192.168.1.100" class="ui-input ui-num px-2.5 py-1.5 text-xs">
              </div>
              <div>
                <label class="text-[11px] font-bold uppercase block mb-0.5" style="color: var(--text-muted)">端口</label>
                <input v-model.number="netPort" type="number" min="1" max="65535" class="ui-input ui-num px-2.5 py-1.5 text-xs">
              </div>
              <div>
                <label class="text-[11px] font-bold uppercase block mb-0.5" style="color: var(--text-muted)">协议</label>
                <select v-model="netTransport" class="ui-input ui-num px-2 py-1.5 text-xs font-bold cursor-pointer">
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                </select>
              </div>
              <div>
                <label class="text-[11px] font-bold uppercase block mb-0.5" style="color: var(--text-muted)">超时 (ms)</label>
                <input v-model.number="netTimeout" type="number" min="200" max="10000" class="ui-input ui-num px-2.5 py-1.5 text-xs">
              </div>
            </div>

            <div class="space-y-1.5">
              <div class="flex items-center justify-between text-[11px]">
                <span class="font-bold uppercase" style="color: var(--text-muted)">出向载荷 (Hex)</span>
                <select @change="applyNetPreset(($event.target as HTMLSelectElement).value)"
                  class="ui-input w-auto px-2 py-0.5 text-[11px] cursor-pointer">
                  <option value="">-- 选择标准规约载荷模板 --</option>
                  <option value="modbus_read">Modbus-TCP: 读保持寄存器 0-1 (Func 03)</option>
                  <option value="http_get">HTTP/1.1: 基础探测请求 (GET /)</option>
                  <option value="mqtt_ping">MQTT: 探活心跳 (PINGREQ)</option>
                  <option value="iec104_test">IEC 60870-5-104: U 格式测试激活帧</option>
                </select>
              </div>
              <textarea v-model="netPayload" rows="2" placeholder="输入待发送的 Hex 字节流，如: 00 01 00 00 00 06 01 03 00 00 00 02"
                class="w-full ui-input font-mono-code p-2 text-xs"></textarea>
            </div>

            <button @click="executeTransceive" :disabled="isExecuting || !netPayload.trim()"
              class="w-full ui-btn-primary justify-center py-2 rounded-xl text-xs font-bold">
              <AppIcon :name="isExecuting ? 'refresh' : 'play'" :size="13" :class="isExecuting ? 'animate-spin' : ''" />
              <span>{{ isExecuting ? '正在执行通信并捕获对端回包...' : '执行物理写出与回包捕获 (TX → RX)' }}</span>
            </button>
          </template>

          <template v-else-if="channel === 'serial'">
            <div class="grid grid-cols-1 sm:grid-cols-[1fr_115px_100px] gap-2.5 items-center">
              <div>
                <label class="text-[11px] font-bold uppercase block mb-0.5" style="color: var(--text-muted)">目标 COM 串口</label>
                <select v-model="selectedSerialPort" class="ui-input ui-num px-2.5 py-1.5 text-xs cursor-pointer">
                  <option v-for="p in serialPorts" :key="p" :value="p">{{ p }}</option>
                  <option v-if="serialPorts.length === 0" value="">未发现可用物理串口</option>
                </select>
              </div>
              <div>
                <label class="text-[11px] font-bold uppercase block mb-0.5" style="color: var(--text-muted)">波特率</label>
                <select v-model.number="serialBaud" class="ui-input ui-num px-2.5 py-1.5 text-xs cursor-pointer">
                  <option :value="9600">9600 bps</option>
                  <option :value="19200">19200 bps</option>
                  <option :value="38400">38400 bps</option>
                  <option :value="57600">57600 bps</option>
                  <option :value="115200">115200 bps</option>
                </select>
              </div>
              <div>
                <label class="text-[11px] font-bold uppercase block mb-0.5" style="color: var(--text-muted)">发送格式</label>
                <label class="flex items-center gap-1.5 cursor-pointer text-xs font-bold text-indigo-700 dark:text-indigo-300 h-[32px]">
                  <input type="checkbox" v-model="serialIsHex" class="accent-indigo-600">
                  <span class="ui-num text-[11px]">HEX 模式</span>
                </label>
              </div>
            </div>

            <div class="space-y-1.5">
              <div class="flex items-center justify-between text-[11px]">
                <span class="font-bold uppercase" style="color: var(--text-muted)">串口写出指令</span>
                <select @change="applySerialPreset(($event.target as HTMLSelectElement).value)"
                  class="ui-input w-auto px-2 py-0.5 text-[11px] cursor-pointer">
                  <option value="">-- 选择串口指令模板 --</option>
                  <option value="modbus_rtu_read">Modbus-RTU: 读从站 01 寄存器 (01 03 00 00 00 02 C4 0B)</option>
                  <option value="at_cmd">AT 握手测试 (AT\r\n)</option>
                </select>
              </div>
              <textarea v-model="serialPayload" rows="2" placeholder="输入待写出到串口的数据 (HEX 如: 01 03 00 00 00 02 C4 0B)"
                class="w-full ui-input font-mono-code p-2 text-xs"></textarea>
            </div>

            <button @click="executeTransceive" :disabled="isExecuting || !serialPayload.trim() || !selectedSerialPort"
              class="w-full ui-btn-primary justify-center py-2 rounded-xl text-xs font-bold">
              <AppIcon :name="isExecuting ? 'refresh' : 'play'" :size="13" :class="isExecuting ? 'animate-spin' : ''" />
              <span>{{ isExecuting ? '正在向串口写出指令...' : '执行串口写出与双向侦测' }}</span>
            </button>
          </template>
        </div>

        <!-- 下部：双向出入留痕历史流水 -->
        <div class="flex-1 flex flex-col overflow-hidden min-h-0">
          <div class="px-4 py-2 border-b flex items-center justify-between text-xs font-bold shrink-0" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-primary)">
            <span>双向操作留痕流水 ({{ history.length }} 笔)</span>
            <button v-if="history.length > 0" @click="history = []" class="text-[11px] ui-pill px-2 py-0.5 rounded font-normal cursor-pointer">
              清空
            </button>
          </div>

          <div class="flex-1 overflow-auto custom-scrollbar p-3 space-y-2 select-text">
            <div v-for="item in history" :key="item.id" class="ui-sub-card p-2.5 text-xs ui-num space-y-1.5">
              <div class="flex items-center justify-between text-[11px] border-b pb-1" style="border-color: var(--border-subtle); color: var(--text-muted)">
                <div class="flex items-center gap-1.5">
                  <span :class="['px-2 py-0.5 rounded-md text-[11px] font-bold border',
                    item.status === 'SUCCESS' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' : 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30']">
                    {{ item.status }}
                  </span>
                  <span class="font-bold" style="color: var(--text-primary)">{{ item.channel }} → {{ item.target }}</span>
                </div>
                <span>{{ item.time }} ({{ item.latencyMs.toFixed(1) }} ms)</span>
              </div>

              <div class="text-[11px] text-blue-700 dark:text-sky-300 break-all bg-blue-500/10 p-2 rounded-lg border border-blue-500/25">
                <strong class="font-bold mr-1.5">[TX 发送 {{ item.bytesSent }}B]:</strong>
                <span>{{ item.txPayload }}</span>
              </div>

              <div v-if="item.bytesReceived > 0" class="text-[11px] text-emerald-700 dark:text-emerald-300 break-all bg-emerald-500/10 p-2 rounded-lg border border-emerald-500/25">
                <div class="font-bold mb-0.5">[RX 接收 {{ item.bytesReceived }}B] 协议: {{ item.detectedProto }}</div>
                <div><strong>HEX:</strong> {{ item.rxPayload }}</div>
                <div v-if="item.rxText" class="mt-0.5" style="color: var(--text-primary)"><strong>明文:</strong> {{ item.rxText }}</div>
              </div>

              <div v-else-if="item.error" class="bg-rose-500/10 border border-rose-500/25 rounded-lg p-2 text-[11px] text-rose-700 dark:text-rose-300">
                <strong class="font-bold">错误/超时:</strong> {{ item.error }}
              </div>
            </div>

            <EmptyState
              v-if="history.length === 0"
              class="py-8"
              icon="serial"
              title="暂无双向出入操作记录"
              description="配置目标与载荷后点击【执行物理写出与回包捕获】进行实时侦测。"
            />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';
import { invoke } from '@tauri-apps/api/core';

defineProps<{
  isOpen: boolean;
  serialPorts: string[];
}>();

defineEmits(['close']);

interface TransceiveHistoryItem {
  id: number;
  time: string;
  channel: string;
  target: string;
  transport: string;
  status: 'SUCCESS' | 'ERROR';
  bytesSent: number;
  bytesReceived: number;
  latencyMs: number;
  txPayload: string;
  rxPayload: string;
  rxText: string;
  detectedProto: string;
  error?: string;
}

const channel = ref<'network' | 'serial'>('network');

const netIp = ref('');
const netPort = ref(502);
const netTransport = ref<'TCP' | 'UDP'>('TCP');
const netTimeout = ref(2000);
const netPayload = ref('00 01 00 00 00 06 01 03 00 00 00 02');

const selectedSerialPort = ref('');
const serialBaud = ref(9600);
const serialIsHex = ref(true);
const serialPayload = ref('01 03 00 00 00 02 C4 0B');

const isExecuting = ref(false);
const history = ref<TransceiveHistoryItem[]>([]);

function applyNetPreset(val: string) {
  if (val === 'modbus_read') {
    netPort.value = 502;
    netTransport.value = 'TCP';
    netPayload.value = '00 01 00 00 00 06 01 03 00 00 00 02';
  } else if (val === 'http_get') {
    netPort.value = 80;
    netTransport.value = 'TCP';
    netPayload.value = '47 45 54 20 2F 20 48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20 6C 6F 63 61 6C 68 6F 73 74 0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 63 6C 6F 73 65 0D 0A 0D 0A';
  } else if (val === 'mqtt_ping') {
    netPort.value = 1883;
    netTransport.value = 'TCP';
    netPayload.value = 'C0 00';
  } else if (val === 'iec104_test') {
    netPort.value = 2404;
    netTransport.value = 'TCP';
    netPayload.value = '68 04 43 00 00 00';
  }
}

function applySerialPreset(val: string) {
  if (val === 'modbus_rtu_read') {
    serialIsHex.value = true;
    serialPayload.value = '01 03 00 00 00 02 C4 0B';
  } else if (val === 'at_cmd') {
    serialIsHex.value = false;
    serialPayload.value = 'AT\r\n';
  }
}

async function executeTransceive() {
  if (isExecuting.value) return;
  isExecuting.value = true;
  const ts = new Date().toLocaleTimeString('zh-CN', { hour12: false });

  try {
    if (channel.value === 'network') {
      const res = await invoke<any>('send_port_transceive_cmd', {
        targetIp: netIp.value.trim(),
        targetPort: netPort.value,
        transport: netTransport.value,
        payloadHex: netPayload.value.trim(),
        timeoutMs: netTimeout.value
      });

      history.value.unshift({
        id: Date.now(),
        time: ts,
        channel: `网络 ${netTransport.value}`,
        target: `${netIp.value}:${netPort.value}`,
        transport: netTransport.value,
        status: res.success ? 'SUCCESS' : 'ERROR',
        bytesSent: res.bytes_sent,
        bytesReceived: res.bytes_received,
        latencyMs: res.latency_ms,
        txPayload: netPayload.value.trim(),
        rxPayload: res.response_hex || '',
        rxText: res.response_text || '',
        detectedProto: res.detected_protocol || 'UNKNOWN',
        error: res.error_msg
      });
    } else if (channel.value === 'serial') {
      const start = performance.now();
      const bytesSent = await invoke<number>('send_serial_data_cmd', {
        port: selectedSerialPort.value,
        baudRate: serialBaud.value,
        payload: serialPayload.value.trim(),
        isHex: serialIsHex.value
      });
      const latencyMs = performance.now() - start;

      history.value.unshift({
        id: Date.now(),
        time: ts,
        channel: '物理串口',
        target: `${selectedSerialPort.value} @ ${serialBaud.value} bps`,
        transport: 'SERIAL',
        status: 'SUCCESS',
        bytesSent,
        bytesReceived: 0,
        latencyMs,
        txPayload: serialPayload.value.trim(),
        rxPayload: '',
        rxText: '',
        detectedProto: 'SERIAL_TX',
        error: undefined
      });
    }
  } catch (err: any) {
    history.value.unshift({
      id: Date.now(),
      time: ts,
      channel: channel.value === 'network' ? '网络端口' : '物理串口',
      target: channel.value === 'network' ? `${netIp.value}:${netPort.value}` : selectedSerialPort.value,
      transport: 'N/A',
      status: 'ERROR',
      bytesSent: 0,
      bytesReceived: 0,
      latencyMs: 0,
      txPayload: channel.value === 'network' ? netPayload.value : serialPayload.value,
      rxPayload: '',
      rxText: '',
      detectedProto: '',
      error: String(err)
    });
  } finally {
    isExecuting.value = false;
  }
}
</script>
