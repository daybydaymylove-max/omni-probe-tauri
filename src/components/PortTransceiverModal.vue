<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-md flex items-center justify-center p-4">
    <div class="bg-white/85 backdrop-blur-2xl rounded-2xl border border-white/60 shadow-2xl w-full max-w-3xl max-h-[85vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      <!-- 模态框顶栏 (毛玻璃微光) -->
      <div class="px-5 py-3.5 border-b border-slate-200/50 flex items-center justify-between bg-white/40 backdrop-blur-md shrink-0">
        <div class="flex items-center gap-3">
          <div class="w-7 h-7 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-600 text-white flex items-center justify-center font-mono font-bold text-xs shadow-sm">
            TX
          </div>
          <div>
            <h3 class="text-xs font-bold text-slate-900 leading-none">
              端口与物理总线数据双向出入执行器 (Port & Bus Transceiver)
            </h3>
            <p class="text-[10px] text-slate-500 font-mono mt-0.5">
              支持网络传输层 (TCP/UDP) 与 物理串口 (COM) 真实写出与回包捕获 (TX ➔ RX)
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2.5">
          <!-- 渠道切换分段控件 (苹果毛玻璃微胶囊) -->
          <div class="flex bg-slate-200/60 backdrop-blur-md p-1 rounded-xl text-xs font-semibold border border-white/40 shadow-inner">
            <button @click="channel = 'network'"
              :class="['px-3 py-1 rounded-lg transition-all cursor-pointer',
                channel === 'network' ? 'bg-white text-blue-700 shadow-sm font-bold' : 'text-slate-600 hover:text-slate-900']">
              网络端口 (TCP/UDP)
            </button>
            <button @click="channel = 'serial'"
              :class="['px-3 py-1 rounded-lg transition-all cursor-pointer',
                channel === 'serial' ? 'bg-white text-indigo-700 shadow-sm font-bold' : 'text-slate-600 hover:text-slate-900']">
              物理串口 (COM)
            </button>
          </div>

          <button @click="$emit('close')" class="text-slate-400 hover:text-slate-700 p-1.5 rounded-xl hover:bg-white/60 transition-colors cursor-pointer">
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      </div>

      <!-- 模态框主体：上部参数配置与写出 + 下部双向留痕流水 -->
      <div class="flex-1 flex flex-col overflow-hidden min-h-0">
        <!-- 参数配置面板 -->
        <div class="p-4 border-b border-slate-200/50 bg-white/40 backdrop-blur-md space-y-3 shrink-0">
          <!-- 网络端口分支 -->
          <template v-if="channel === 'network'">
            <div class="grid grid-cols-[1fr_85px_75px_85px] gap-2.5 items-center">
              <div>
                <label class="text-[10px] font-bold text-slate-500 uppercase block mb-0.5">目标 IP</label>
                <input v-model="netIp" placeholder="192.168.1.100"
                  class="w-full bg-white/80 border border-slate-200/80 rounded-xl px-2.5 py-1 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500/30 shadow-2xs">
              </div>
              <div>
                <label class="text-[10px] font-bold text-slate-500 uppercase block mb-0.5">端口</label>
                <input v-model.number="netPort" type="number" min="1" max="65535"
                  class="w-full bg-white/80 border border-slate-200/80 rounded-xl px-2.5 py-1 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500/30 shadow-2xs">
              </div>
              <div>
                <label class="text-[10px] font-bold text-slate-500 uppercase block mb-0.5">协议</label>
                <select v-model="netTransport"
                  class="w-full bg-white/80 border border-slate-200/80 rounded-xl px-2 py-1 text-xs font-bold text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500/30 shadow-2xs">
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                </select>
              </div>
              <div>
                <label class="text-[10px] font-bold text-slate-500 uppercase block mb-0.5">超时 (ms)</label>
                <input v-model.number="netTimeout" type="number" min="200" max="10000"
                  class="w-full bg-white/80 border border-slate-200/80 rounded-xl px-2.5 py-1 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500/30 shadow-2xs">
              </div>
            </div>

            <div class="space-y-1">
              <div class="flex items-center justify-between text-[11px]">
                <span class="font-bold text-slate-500 uppercase">出向载荷 (Hex)</span>
                <select @change="applyNetPreset(($event.target as HTMLSelectElement).value)"
                  class="bg-white/80 border border-slate-200/80 rounded-lg px-2 py-0.5 text-[11px] text-slate-700 focus:outline-none shadow-2xs">
                  <option value="">-- 选择标准规约载荷模板 --</option>
                  <option value="modbus_read">Modbus-TCP: 读保持寄存器 0-1 (Func 03)</option>
                  <option value="http_get">HTTP/1.1: 基础探测请求 (GET /)</option>
                  <option value="mqtt_ping">MQTT: 探活心跳 (PINGREQ)</option>
                  <option value="iec104_test">IEC 60870-5-104: U 格式测试激活帧</option>
                </select>
              </div>
              <textarea v-model="netPayload" rows="2" placeholder="输入待发送的 Hex 字节流，如: 00 01 00 00 00 06 01 03 00 00 00 02"
                class="w-full bg-white/80 border border-slate-200/80 rounded-xl p-2 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500/30 shadow-2xs"></textarea>
            </div>

            <button @click="executeTransceive" :disabled="isExecuting || !netPayload.trim()"
              class="w-full py-2 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 shadow-sm transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-40 active:scale-95">
              <span v-if="isExecuting" class="animate-spin">⏳</span>
              <span>{{ isExecuting ? '正在执行通信并捕获对端回包...' : '执行物理写出与回包捕获 (TX ➔ RX)' }}</span>
            </button>
          </template>

          <!-- 物理串口分支 -->
          <template v-else-if="channel === 'serial'">
            <div class="grid grid-cols-[1fr_110px_90px] gap-2.5 items-center">
              <div>
                <label class="text-[10px] font-bold text-slate-500 uppercase block mb-0.5">目标 COM 串口</label>
                <select v-model="selectedSerialPort"
                  class="w-full bg-white/80 border border-slate-200/80 rounded-xl px-2.5 py-1 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
                  <option v-for="p in serialPorts" :key="p" :value="p">{{ p }}</option>
                  <option v-if="serialPorts.length === 0" value="">未发现可用物理串口</option>
                </select>
              </div>
              <div>
                <label class="text-[10px] font-bold text-slate-500 uppercase block mb-0.5">波特率</label>
                <select v-model.number="serialBaud"
                  class="w-full bg-white/80 border border-slate-200/80 rounded-xl px-2.5 py-1 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
                  <option :value="9600">9600 bps</option>
                  <option :value="19200">19200 bps</option>
                  <option :value="38400">38400 bps</option>
                  <option :value="57600">57600 bps</option>
                  <option :value="115200">115200 bps</option>
                </select>
              </div>
              <div>
                <label class="text-[10px] font-bold text-slate-500 uppercase block mb-0.5">发送格式</label>
                <label class="flex items-center gap-1.5 cursor-pointer text-xs font-bold text-indigo-700 h-[32px]">
                  <input type="checkbox" v-model="serialIsHex" class="accent-indigo-600">
                  <span class="font-mono text-[11px]">HEX 模式</span>
                </label>
              </div>
            </div>

            <div class="space-y-1">
              <div class="flex items-center justify-between text-[11px]">
                <span class="font-bold text-slate-500 uppercase">串口写出指令</span>
                <select @change="applySerialPreset(($event.target as HTMLSelectElement).value)"
                  class="bg-white/80 border border-slate-200/80 rounded-lg px-2 py-0.5 text-[11px] text-slate-700 focus:outline-none shadow-2xs">
                  <option value="">-- 选择串口指令模板 --</option>
                  <option value="modbus_rtu_read">Modbus-RTU: 读从站 01 寄存器 (01 03 00 00 00 02 C4 0B)</option>
                  <option value="at_cmd">AT 握手测试 (AT\r\n)</option>
                </select>
              </div>
              <textarea v-model="serialPayload" rows="2" placeholder="输入待写出到串口的数据 (HEX 如: 01 03 00 00 00 02 C4 0B)"
                class="w-full bg-white/80 border border-slate-200/80 rounded-xl p-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs"></textarea>
            </div>

            <button @click="executeTransceive" :disabled="isExecuting || !serialPayload.trim() || !selectedSerialPort"
              class="w-full py-2 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 shadow-sm transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-40 active:scale-95">
              <span v-if="isExecuting" class="animate-spin">⏳</span>
              <span>{{ isExecuting ? '正在向串口写出指令...' : '执行串口写出与双向侦测' }}</span>
            </button>
          </template>
        </div>

        <!-- 下部：双向出入留痕历史流水 (苹果毛玻璃卡片流水) -->
        <div class="flex-1 flex flex-col overflow-hidden min-h-0 bg-slate-50/20">
          <div class="px-4 py-2 border-b border-slate-200/50 flex items-center justify-between bg-white/40 backdrop-blur-md text-xs font-bold text-slate-700 shrink-0">
            <span>双向操作留痕流水 ({{ history.length }} 笔)</span>
            <button v-if="history.length > 0" @click="history = []" class="text-[11px] text-slate-400 hover:text-slate-600 font-normal cursor-pointer">
              清空
            </button>
          </div>

          <div class="flex-1 overflow-auto custom-scrollbar p-3 space-y-2">
            <div v-for="item in history" :key="item.id"
              class="bg-white/80 backdrop-blur-md border border-white/80 rounded-xl p-2.5 text-xs font-mono shadow-2xs space-y-1.5 hover:shadow-sm transition-all">
              <div class="flex items-center justify-between text-[10px] text-slate-500 border-b border-slate-100/80 pb-1">
                <div class="flex items-center gap-1.5">
                  <span :class="['px-2 py-0.5 rounded-md text-[9px] font-bold border shadow-2xs',
                    item.status === 'SUCCESS' ? 'bg-emerald-100 text-emerald-800 border-emerald-300' : 'bg-rose-100 text-rose-800 border-rose-300']">
                    {{ item.status }}
                  </span>
                  <span class="font-bold text-slate-800">{{ item.channel }} ➔ {{ item.target }}</span>
                </div>
                <span>{{ item.time }} ({{ item.latencyMs.toFixed(1) }} ms)</span>
              </div>

              <!-- TX 出向数据：科技蓝 -->
              <div class="text-[11px] text-blue-900 break-all bg-blue-500/10 p-2 rounded-lg border border-blue-200/80 shadow-2xs">
                <strong class="text-blue-700 font-bold mr-1.5">[TX 发送 {{ item.bytesSent }}B]:</strong>
                <span>{{ item.txPayload }}</span>
              </div>

              <!-- RX 入向回包：翠绿 -->
              <div v-if="item.bytesReceived > 0" class="text-[11px] text-emerald-900 break-all bg-emerald-500/10 p-2 rounded-lg border border-emerald-200/80 shadow-2xs">
                <div class="text-emerald-800 font-bold mb-0.5">[RX 接收 {{ item.bytesReceived }}B] 协议: {{ item.detectedProto }}</div>
                <div><strong>HEX:</strong> {{ item.rxPayload }}</div>
                <div v-if="item.rxText" class="text-slate-700 mt-0.5"><strong>明文:</strong> {{ item.rxText }}</div>
              </div>

              <!-- 错误提示：玫瑰红 -->
              <div v-else-if="item.error" class="bg-rose-500/10 border border-rose-200/80 rounded-lg p-2 text-[11px] text-rose-800 shadow-2xs">
                <strong class="font-bold text-rose-800">错误/超时:</strong> {{ item.error }}
              </div>
            </div>

            <div v-if="history.length === 0" class="flex flex-col items-center justify-center h-full text-slate-400 text-xs py-10 gap-1">
              <span>暂无双向出入操作记录</span>
              <span class="text-[10px] text-slate-400">配置目标与载荷后点击“执行物理写出与回包捕获”进行客观侦测</span>
            </div>
          </div>
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
