<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md">
    <div class="w-full max-w-5xl bg-white/95 backdrop-blur-2xl rounded-3xl border border-white/60 shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150 max-h-[90vh]">
      <!-- 模态框头部 -->
      <div class="px-6 py-4 border-b border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-9 h-9 rounded-2xl bg-amber-50 border border-amber-200 flex items-center justify-center text-amber-700 text-lg font-bold shadow-2xs">
            🍯
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h3 class="text-sm font-bold text-slate-900">主动诱饵蜜罐侦测与威胁溯源工作台</h3>
              <span :class="['px-2 py-0.5 rounded-full text-[10px] font-mono font-bold flex items-center gap-1 border',
                isRunning ? 'bg-emerald-50 text-emerald-800 border-emerald-200' : 'bg-slate-100 text-slate-500 border-slate-200']">
                <span class="w-1.5 h-1.5 rounded-full" :class="isRunning ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'"></span>
                <span>{{ isRunning ? '诱捕引擎运行中' : '诱捕引擎已停止' }}</span>
              </span>
            </div>
            <p class="text-[11px] text-slate-500 font-mono">基于真实非阻塞底层网络套接字绑定，实现工控与 IT 多端口诱饵欺骗、令牌桶防击穿与全息证据链留存</p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer">
          ✕
        </button>
      </div>

      <!-- 模态框主体 -->
      <div class="p-6 space-y-4 overflow-auto flex-1 custom-scrollbar">
        <!-- 统计态势看板 -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div class="bg-amber-50/70 border border-amber-200/80 p-3 rounded-2xl shadow-2xs">
            <div class="text-[10px] text-amber-600 font-bold uppercase">累计诱捕命中记录</div>
            <div class="text-xl font-bold text-amber-950 font-mono mt-0.5">
              {{ packets.length }} <span class="text-xs font-normal text-amber-700">笔</span>
            </div>
          </div>
          <div class="bg-rose-50/70 border border-rose-200/80 p-3 rounded-2xl shadow-2xs">
            <div class="text-[10px] text-rose-600 font-bold uppercase">独立攻击源 IP 数</div>
            <div class="text-xl font-bold text-rose-950 font-mono mt-0.5">
              {{ uniqueSourceIps.length }} <span class="text-xs font-normal text-rose-700">个</span>
            </div>
          </div>
          <div class="bg-indigo-50/70 border border-indigo-200/80 p-3 rounded-2xl shadow-2xs">
            <div class="text-[10px] text-indigo-600 font-bold uppercase">活动诱饵端口矩阵</div>
            <div class="text-xl font-bold text-indigo-950 font-mono mt-0.5">
              {{ honeypotPorts.length }} <span class="text-xs font-normal text-indigo-700">个端口</span>
            </div>
          </div>
          <div class="bg-purple-50/70 border border-purple-200/80 p-3 rounded-2xl shadow-2xs">
            <div class="text-[10px] text-purple-600 font-bold uppercase">高熵可疑载荷 (Entropy ≥ 7.0)</div>
            <div class="text-xl font-bold text-purple-950 font-mono mt-0.5">
              {{ highEntropyCount }} <span class="text-xs font-normal text-purple-700">笔</span>
            </div>
          </div>
        </div>

        <!-- 诱饵端口矩阵配置面板 -->
        <div class="bg-slate-50/80 border border-slate-200 rounded-2xl p-4 flex flex-col gap-3">
          <div class="flex items-center justify-between border-b border-slate-200/70 pb-2.5 flex-wrap gap-2">
            <div class="flex items-center gap-2">
              <span class="text-xs font-bold text-slate-800">诱饵端口矩阵配置 (Honeypot Decoy Ports)</span>
              <span class="text-[10px] text-slate-500">（底层由 Tokio 异步协程真实绑定侦听）</span>
            </div>

            <!-- 启停操作按钮 -->
            <div class="flex items-center gap-2">
              <button v-if="!isRunning" @click="startHoneypotEngine" :disabled="isOperating || honeypotPorts.length === 0"
                class="bg-gradient-to-r from-amber-600 to-amber-700 hover:from-amber-700 hover:to-amber-800 text-white text-xs px-4 py-1.5 rounded-xl font-bold transition-all shadow-sm active:scale-95 disabled:opacity-40 cursor-pointer flex items-center gap-1.5">
                <span v-if="isOperating" class="animate-spin">⏳</span>
                <span v-else>▶</span>
                <span>启动蜜罐诱捕</span>
              </button>
              <button v-else @click="stopHoneypotEngine" :disabled="isOperating"
                class="bg-rose-500/15 hover:bg-rose-500/25 text-rose-800 border border-rose-300 text-xs px-4 py-1.5 rounded-xl font-bold transition-all shadow-2xs active:scale-95 cursor-pointer flex items-center gap-1.5">
                <span v-if="isOperating" class="animate-spin">⏳</span>
                <span v-else class="w-2 h-2 rounded-full bg-rose-600 animate-pulse"></span>
                <span>停止蜜罐诱捕</span>
              </button>
            </div>
          </div>

          <!-- 快速载入预设模板 -->
          <div class="flex items-center gap-2 text-xs flex-wrap">
            <span class="text-[11px] font-bold text-slate-500">⚡ 快速载入诱饵模板:</span>
            <button @click="loadPreset('industrial')" :disabled="isRunning"
              class="bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all cursor-pointer shadow-2xs disabled:opacity-40">
              工控与电力协议 (502 Modbus, 102 S7, 2404 104, 1883 MQTT)
            </button>
            <button @click="loadPreset('it_services')" :disabled="isRunning"
              class="bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all cursor-pointer shadow-2xs disabled:opacity-40">
              IT 常见攻击服务 (21 FTP, 22 SSH, 23 Telnet, 80 HTTP, 3389 RDP)
            </button>
            <button @click="loadPreset('database')" :disabled="isRunning"
              class="bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all cursor-pointer shadow-2xs disabled:opacity-40">
              数据库服务 (3306 MySQL, 5432 PG, 6379 Redis)
            </button>
          </div>

          <!-- 自定义端口添加与当前诱饵胶囊列表 -->
          <div class="flex items-center gap-2 flex-wrap">
            <div class="flex items-center gap-1 text-xs">
              <input v-model.number="customPort" type="number" min="1" max="65535" placeholder="端口号 (1-65535)" :disabled="isRunning"
                class="w-32 bg-white border border-slate-200 rounded-xl px-2.5 py-1 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-amber-500/30 shadow-2xs">
              <select v-model="customProto" :disabled="isRunning"
                class="bg-white border border-slate-200 rounded-xl px-2 py-1 text-xs font-bold text-slate-800 focus:outline-none shadow-2xs">
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </select>
              <button @click="addCustomPort" :disabled="isRunning || !customPort"
                class="bg-slate-200 hover:bg-slate-300 text-slate-800 px-3 py-1 rounded-xl text-xs font-bold transition-all cursor-pointer disabled:opacity-40">
                + 添加诱饵
              </button>
            </div>

            <!-- 当前端口矩阵胶囊 -->
            <div class="flex items-center gap-1.5 flex-wrap ml-2">
              <span v-for="(hp, idx) in honeypotPorts" :key="`${hp.port}-${hp.proto}`"
                class="bg-white border border-amber-200/90 text-amber-950 px-2.5 py-1 rounded-xl text-xs font-mono font-bold flex items-center gap-1.5 shadow-2xs">
                <span class="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
                <span>:{{ hp.port }}/{{ hp.proto.toUpperCase() }}</span>
                <button v-if="!isRunning" @click="removePort(idx)" class="text-slate-400 hover:text-rose-600 transition-colors ml-0.5 cursor-pointer">
                  ✕
                </button>
              </span>
              <span v-if="honeypotPorts.length === 0" class="text-xs text-slate-400">
                尚未配置诱饵端口
              </span>
            </div>
          </div>
        </div>

        <!-- 诱捕流水记录明细表格 -->
        <div class="space-y-2">
          <div class="flex items-center justify-between text-xs">
            <div class="flex items-center gap-2">
              <span class="font-bold text-slate-800">实时诱捕命中日志流水 ({{ filteredPackets.length }} / {{ packets.length }})</span>
              <span class="text-[10px] text-slate-400 font-mono">（自动关联 DPI 协议识别与司法链式哈希封存）</span>
            </div>
            <div class="flex items-center gap-2">
              <input v-model="filterText" placeholder="过滤源 IP / 端口 / 协议"
                class="w-48 bg-white border border-slate-200 rounded-xl px-2.5 py-1 text-[11px] font-mono focus:outline-none shadow-2xs">
              <button @click="$emit('clearHoneypotData')" class="text-slate-400 hover:text-rose-600 text-xs px-2 py-1 rounded cursor-pointer">
                清空记录
              </button>
            </div>
          </div>

          <div class="border border-slate-200/80 rounded-2xl overflow-hidden bg-white shadow-2xs max-h-72 overflow-y-auto custom-scrollbar">
            <table class="w-full text-left text-xs font-mono border-collapse table-fixed">
              <thead class="bg-slate-100/90 text-slate-500 text-[10px] uppercase font-bold border-b border-slate-200 sticky top-0 z-10">
                <tr>
                  <th class="p-2 w-[12%]">时间戳</th>
                  <th class="p-2 w-[22%]">攻击源地址 (Src IP:Port)</th>
                  <th class="p-2 w-[16%]">命中诱饵端口 (Decoy)</th>
                  <th class="p-2 w-[14%]">DPI 规约协议</th>
                  <th class="p-2 w-[12%] text-center">信息熵</th>
                  <th class="p-2 w-[24%]">载荷数据预览 (Payload Hex)</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-100 text-[11px]">
                <tr v-for="p in filteredPackets" :key="p.id" class="hover:bg-amber-50/40 transition-colors">
                  <td class="p-2 text-slate-500 truncate">{{ p.timestamp }}</td>
                  <td class="p-2 font-bold text-rose-700 truncate" :title="`${p.src_ip}:${p.src_port}`">
                    <div class="flex items-center gap-1.5">
                      <span>{{ p.src_ip }}:{{ p.src_port }}</span>
                      <button @click.stop="$emit('filterTraffic', p.src_ip)" title="一键穿透至流量分析大屏过滤该 IP 报文"
                        class="px-1 py-0.2 bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 rounded text-[9px] font-sans transition-colors cursor-pointer">
                        🔍 穿透
                      </button>
                      <button @click.stop="$emit('openDossier', p.src_ip)" title="打开该攻击源 IP 全息画像档案"
                        class="px-1 py-0.2 bg-purple-50 hover:bg-purple-100 text-purple-700 border border-purple-200 rounded text-[9px] font-sans transition-colors cursor-pointer">
                        📁 档案
                      </button>
                    </div>
                  </td>
                  <td class="p-2 font-bold text-amber-800 truncate">
                    :{{ p.dst_port }} ({{ p.transport }})
                  </td>
                  <td class="p-2 truncate">
                    <span class="px-1.5 py-0.5 rounded text-[9px] font-bold bg-indigo-50 text-indigo-800 border border-indigo-200">
                      {{ p.protocol }}
                    </span>
                  </td>
                  <td class="p-2 text-center font-bold" :class="p.entropy >= 7.0 ? 'text-purple-700' : 'text-slate-600'">
                    {{ p.entropy ? p.entropy.toFixed(2) : '0.00' }}
                  </td>
                  <td class="p-2 truncate font-mono text-[10px] text-slate-700" :title="p.payload_hex">
                    {{ p.payload_hex || '(TCP 连接建立建立握手)' }}
                  </td>
                </tr>
                <tr v-if="filteredPackets.length === 0">
                  <td colspan="6" class="p-8 text-center text-slate-400 text-xs">
                    {{ packets.length === 0 ? '暂无蜜罐诱捕命中记录。启动诱捕后，外部对诱饵端口的扫描或连接将在此实时告警。' : '无符合过滤条件的诱捕记录' }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- 底部关闭 -->
      <div class="px-6 py-3 border-t border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <span class="text-[11px] text-slate-400 font-mono">
          蜜罐流量已落盘至 received_data.jsonl 并同步接入司法链式哈希
        </span>
        <button @click="$emit('close')" class="px-4 py-1.5 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer">
          关闭
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';

export interface HoneypotPacketRecord {
  id: number;
  timestamp: string;
  timestamp_ns: number;
  direction: string;
  transport: string;
  protocol: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  length: number;
  payload_hex: string;
  entropy: number;
  chain_hash: string;
}

const props = defineProps<{
  isOpen: boolean;
  packets: HoneypotPacketRecord[];
  isRunning?: boolean;
}>();

const emit = defineEmits(['close', 'clearHoneypotData', 'statusChanged', 'log', 'filterTraffic', 'openDossier']);

const isRunning = ref(props.isRunning || false);
const isOperating = ref(false);
const filterText = ref('');

const customPort = ref<number | null>(null);
const customProto = ref<'tcp' | 'udp'>('tcp');

const honeypotPorts = ref<Array<{ port: number; proto: string }>>([
  { port: 21, proto: 'tcp' },
  { port: 22, proto: 'tcp' },
  { port: 80, proto: 'tcp' },
  { port: 502, proto: 'tcp' },
  { port: 1883, proto: 'tcp' },
  { port: 3389, proto: 'tcp' },
]);

const uniqueSourceIps = computed(() => {
  const set = new Set<string>();
  props.packets.forEach(p => {
    if (p.src_ip) set.add(p.src_ip);
  });
  return Array.from(set);
});

const highEntropyCount = computed(() => {
  return props.packets.filter(p => p.entropy >= 7.0).length;
});

const filteredPackets = computed(() => {
  if (!filterText.value.trim()) return props.packets;
  const q = filterText.value.trim().toLowerCase();
  return props.packets.filter(p =>
    p.src_ip.toLowerCase().includes(q) ||
    String(p.src_port).includes(q) ||
    String(p.dst_port).includes(q) ||
    p.protocol.toLowerCase().includes(q) ||
    p.transport.toLowerCase().includes(q)
  );
});

function loadPreset(preset: 'industrial' | 'it_services' | 'database') {
  if (preset === 'industrial') {
    honeypotPorts.value = [
      { port: 502, proto: 'tcp' },  // Modbus TCP
      { port: 102, proto: 'tcp' },  // S7comm
      { port: 2404, proto: 'tcp' }, // IEC 60870-5-104
      { port: 1883, proto: 'tcp' }, // MQTT
      { port: 44818, proto: 'tcp' },// EtherNet/IP
    ];
  } else if (preset === 'it_services') {
    honeypotPorts.value = [
      { port: 21, proto: 'tcp' },
      { port: 22, proto: 'tcp' },
      { port: 23, proto: 'tcp' },
      { port: 80, proto: 'tcp' },
      { port: 3389, proto: 'tcp' },
    ];
  } else if (preset === 'database') {
    honeypotPorts.value = [
      { port: 3306, proto: 'tcp' },
      { port: 5432, proto: 'tcp' },
      { port: 6379, proto: 'tcp' },
      { port: 27017, proto: 'tcp' },
    ];
  }
}

function addCustomPort() {
  if (!customPort.value || customPort.value < 1 || customPort.value > 65535) return;
  if (honeypotPorts.value.some(p => p.port === customPort.value && p.proto === customProto.value)) {
    return;
  }
  honeypotPorts.value.push({
    port: customPort.value,
    proto: customProto.value,
  });
  customPort.value = null;
}

function removePort(idx: number) {
  honeypotPorts.value.splice(idx, 1);
}

async function startHoneypotEngine() {
  if (honeypotPorts.value.length === 0 || isOperating.value) return;
  isOperating.value = true;
  try {
    const res = await invoke<string>('start_honeypot_cmd', {
      ports: honeypotPorts.value.map(hp => ({ port: hp.port, proto: hp.proto })),
    });
    isRunning.value = true;
    emit('statusChanged', true);
    emit('log', res);
  } catch (err: any) {
    alert(`启动蜜罐诱捕失败: ${err?.message || String(err)}`);
  } finally {
    isOperating.value = false;
  }
}

async function stopHoneypotEngine() {
  if (isOperating.value) return;
  isOperating.value = true;
  try {
    const res = await invoke<string>('stop_honeypot_cmd');
    isRunning.value = false;
    emit('statusChanged', false);
    emit('log', res);
  } catch (err: any) {
    alert(`停止蜜罐诱捕失败: ${err?.message || String(err)}`);
  } finally {
    isOperating.value = false;
  }
}

async function checkStatus() {
  try {
    const res = await invoke<boolean>('is_honeypot_running_cmd');
    isRunning.value = res;
    emit('statusChanged', res);
  } catch (e) {
    console.error('获取蜜罐运行状态失败:', e);
  }
}

onMounted(() => {
  checkStatus();
});
</script>
