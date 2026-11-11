<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 ui-modal-backdrop">
    <div class="w-full max-w-5xl ui-modal-surface rounded-3xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150 max-h-[90vh]">
      <!-- 模态框头部 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-6 py-4 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-700 dark:text-amber-300 shrink-0">
            <AppIcon name="shield" :size="18" />
          </div>
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <h3 class="text-sm font-bold" style="color: var(--text-primary)">主动诱饵蜜罐侦测与威胁溯源工作台</h3>
              <span :class="['px-2 py-0.5 rounded-full text-[11px] ui-num font-bold flex items-center gap-1.5 border',
                isRunning ? 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' : 'ui-pill']">
                <span class="w-1.5 h-1.5 rounded-full" :class="isRunning ? 'bg-emerald-500' : 'bg-slate-400'"></span>
                <span>{{ isRunning ? '诱捕引擎运行中' : '诱捕引擎已停止' }}</span>
              </span>
            </div>
            <p class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">基于非阻塞底层套接字绑定，实现工控与 IT 多端口诱饵欺骗与证据链留存</p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer" title="关闭">
          <AppIcon name="close" :size="15" />
        </button>
      </header>

      <!-- 模态框主体 -->
      <div class="p-6 space-y-4 overflow-auto flex-1 custom-scrollbar select-text" style="background: var(--surface-content)">
        <!-- 统计指标看板 -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div class="ui-sub-card bg-amber-500/8 border-amber-500/25 p-3">
            <div class="text-[11px] text-amber-700 dark:text-amber-300 font-bold uppercase">累计诱捕命中记录</div>
            <div class="text-xl font-bold ui-num mt-0.5" style="color: var(--text-primary)">
              {{ packets.length }} <span class="text-xs font-normal" style="color: var(--text-muted)">笔</span>
            </div>
          </div>
          <div class="ui-sub-card bg-rose-500/8 border-rose-500/25 p-3">
            <div class="text-[11px] text-rose-700 dark:text-rose-300 font-bold uppercase">独立攻击源 IP 数</div>
            <div class="text-xl font-bold ui-num mt-0.5" style="color: var(--text-primary)">
              {{ uniqueSourceIps.length }} <span class="text-xs font-normal" style="color: var(--text-muted)">个</span>
            </div>
          </div>
          <div class="ui-sub-card bg-indigo-500/8 border-indigo-500/25 p-3">
            <div class="text-[11px] text-indigo-700 dark:text-indigo-300 font-bold uppercase">活动诱饵端口矩阵</div>
            <div class="text-xl font-bold ui-num mt-0.5" style="color: var(--text-primary)">
              {{ honeypotPorts.length }} <span class="text-xs font-normal" style="color: var(--text-muted)">个端口</span>
            </div>
          </div>
          <div class="ui-sub-card bg-purple-500/8 border-purple-500/25 p-3">
            <div class="text-[11px] text-purple-700 dark:text-purple-300 font-bold uppercase">高熵可疑载荷 (Entropy ≥ 7.0)</div>
            <div class="text-xl font-bold ui-num mt-0.5" style="color: var(--text-primary)">
              {{ highEntropyCount }} <span class="text-xs font-normal" style="color: var(--text-muted)">笔</span>
            </div>
          </div>
        </div>

        <!-- 诱饵端口矩阵配置面板 -->
        <div class="ui-content-card p-4 flex flex-col gap-3">
          <div class="flex items-center justify-between border-b pb-2.5 flex-wrap gap-2" style="border-color: var(--border-subtle)">
            <div class="flex items-center gap-2">
              <span class="text-xs font-bold" style="color: var(--text-primary)">诱饵端口矩阵配置</span>
              <span class="text-[11px]" style="color: var(--text-muted)">(底层由 Tokio 异步协程绑定侦听)</span>
            </div>

            <div class="flex items-center gap-2">
              <button v-if="!isRunning" @click="startHoneypotEngine" :disabled="isOperating || honeypotPorts.length === 0"
                class="ui-btn-primary text-xs px-4 py-1.5 rounded-xl">
                <AppIcon :name="isOperating ? 'refresh' : 'play'" :size="12" :class="isOperating ? 'animate-spin' : ''" />
                <span>启动蜜罐诱捕</span>
              </button>
              <button v-else @click="stopHoneypotEngine" :disabled="isOperating"
                class="ui-btn-danger text-xs px-4 py-1.5 rounded-xl">
                <AppIcon v-if="isOperating" name="refresh" :size="12" class="animate-spin" />
                <span v-else class="w-2 h-2 rounded-full bg-rose-500"></span>
                <span>停止蜜罐诱捕</span>
              </button>
            </div>
          </div>

          <div class="flex items-center gap-2 text-xs flex-wrap">
            <span class="text-[11px] font-bold flex items-center gap-1" style="color: var(--text-muted)">
              <AppIcon name="zap" :size="12" />
              <span>快速载入诱饵模板:</span>
            </span>
            <button @click="loadPreset('industrial')" :disabled="isRunning"
              class="ui-pill px-2.5 py-1 rounded-lg text-[11px] font-semibold cursor-pointer disabled:opacity-40">
              工控与电力协议 (502 Modbus, 102 S7, 2404 104, 1883 MQTT)
            </button>
            <button @click="loadPreset('it_services')" :disabled="isRunning"
              class="ui-pill px-2.5 py-1 rounded-lg text-[11px] font-semibold cursor-pointer disabled:opacity-40">
              IT 常见攻击服务 (21 FTP, 22 SSH, 23 Telnet, 80 HTTP, 3389 RDP)
            </button>
            <button @click="loadPreset('database')" :disabled="isRunning"
              class="ui-pill px-2.5 py-1 rounded-lg text-[11px] font-semibold cursor-pointer disabled:opacity-40">
              数据库服务 (3306 MySQL, 5432 PG, 6379 Redis)
            </button>
          </div>

          <div class="flex items-center gap-2 flex-wrap">
            <div class="flex items-center gap-1.5 text-xs">
              <input v-model.number="customPort" type="number" min="1" max="65535" placeholder="端口号 (1-65535)" :disabled="isRunning"
                class="w-36 ui-input ui-num px-2.5 py-1 text-xs">
              <select v-model="customProto" :disabled="isRunning" class="ui-input ui-num w-auto px-2 py-1 text-xs font-bold cursor-pointer">
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </select>
              <button @click="addCustomPort" :disabled="isRunning || !customPort" class="ui-btn-secondary px-3 py-1 rounded-xl text-xs">
                + 添加诱饵
              </button>
            </div>

            <div class="flex items-center gap-1.5 flex-wrap ml-1">
              <span v-for="(hp, idx) in honeypotPorts" :key="`${hp.port}-${hp.proto}`"
                class="ui-sub-card border-amber-500/35 px-2.5 py-1 text-xs ui-num font-bold flex items-center gap-1.5" style="color: var(--text-primary)">
                <span class="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
                <span>:{{ hp.port }}/{{ hp.proto.toUpperCase() }}</span>
                <button v-if="!isRunning" @click="removePort(idx)" class="hover:text-rose-500 transition-colors ml-0.5 cursor-pointer" style="color: var(--text-muted)">
                  <AppIcon name="close" :size="11" />
                </button>
              </span>
              <span v-if="honeypotPorts.length === 0" class="text-xs" style="color: var(--text-muted)">
                尚未配置诱饵端口
              </span>
            </div>
          </div>
        </div>

        <!-- 诱捕流水记录明细表格 -->
        <div class="space-y-2.5">
          <div class="flex flex-wrap items-center justify-between gap-2 text-xs">
            <div class="flex items-center gap-2">
              <span class="font-bold text-(--text-primary)">实时诱捕命中日志流水 (<span class="ui-num">{{ filteredPackets.length }}</span> / <span class="ui-num">{{ packets.length }}</span>)</span>
              <span class="text-xs text-(--text-muted)">自动关联 DPI 协议识别与司法链式哈希封存</span>
            </div>
            <div class="flex items-center gap-2">
              <input v-model="filterText" placeholder="过滤源 IP / 端口 / 协议"
                class="ui-input w-52 px-2.5 py-1 text-xs font-mono-code">
              <button @click="$emit('clearHoneypotData')" class="ui-btn-secondary px-2.5 py-1 text-xs hover:text-rose-600 dark:hover:text-rose-400 cursor-pointer">
                清空记录
              </button>
            </div>
          </div>

          <div class="ui-content-card rounded-2xl overflow-hidden max-h-72 overflow-y-auto custom-scrollbar">
            <table class="w-full text-left text-xs border-collapse table-fixed">
              <thead class="ui-table-head text-[11px] uppercase font-bold sticky top-0 z-10">
                <tr>
                  <th class="p-2.5 w-[13%]">时间戳</th>
                  <th class="p-2.5 w-[24%]">攻击源地址 (Src IP:Port)</th>
                  <th class="p-2.5 w-[14%]">命中诱饵端口</th>
                  <th class="p-2.5 w-[13%]">DPI 规约协议</th>
                  <th class="p-2.5 w-[10%] text-center">信息熵</th>
                  <th class="p-2.5 w-[26%]">载荷数据预览 (Payload Hex)</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-(--border-subtle) text-xs">
                <tr v-for="p in filteredPackets" :key="p.id" class="hover:bg-amber-500/8 transition-colors">
                  <td class="p-2.5 text-(--text-muted) ui-num font-mono-code truncate select-text">{{ p.timestamp }}</td>
                  <td class="p-2.5 font-semibold text-rose-600 dark:text-rose-400 truncate select-text" :title="`${p.src_ip}:${p.src_port}`">
                    <div class="flex items-center gap-1.5">
                      <span class="ui-num font-mono-code truncate">{{ p.src_ip }}:{{ p.src_port }}</span>
                      <button @click.stop="$emit('filterTraffic', p.src_ip)" title="一键穿透至流量分析监控看板过滤该 IP 报文"
                        class="inline-flex items-center gap-1 px-1.5 py-0.5 bg-sky-500/12 hover:bg-sky-500/20 text-sky-700 dark:text-sky-300 border border-sky-500/30 rounded text-[11px] font-medium transition-colors cursor-pointer shrink-0">
                        <AppIcon name="search" class="w-3 h-3" />
                        <span>穿透</span>
                      </button>
                      <button @click.stop="$emit('openDossier', p.src_ip)" title="打开该攻击源 IP 全息画像档案"
                        class="inline-flex items-center gap-1 px-1.5 py-0.5 bg-purple-500/12 hover:bg-purple-500/20 text-purple-700 dark:text-purple-300 border border-purple-500/30 rounded text-[11px] font-medium transition-colors cursor-pointer shrink-0">
                        <AppIcon name="folder" class="w-3 h-3" />
                        <span>档案</span>
                      </button>
                    </div>
                  </td>
                  <td class="p-2.5 font-bold text-amber-700 dark:text-amber-300 ui-num font-mono-code truncate select-text">
                    :{{ p.dst_port }} ({{ p.transport }})
                  </td>
                  <td class="p-2.5 truncate">
                    <span class="px-1.5 py-0.5 rounded text-[11px] font-bold bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30">
                      {{ p.protocol }}
                    </span>
                  </td>
                  <td class="p-2.5 text-center font-bold ui-num font-mono-code" :class="p.entropy >= 7.0 ? 'text-purple-600 dark:text-purple-400' : 'text-(--text-secondary)'">
                    {{ p.entropy ? p.entropy.toFixed(2) : '0.00' }}
                  </td>
                  <td class="p-2.5 truncate font-mono-code text-[11px] text-(--text-secondary) select-text" :title="p.payload_hex">
                    {{ p.payload_hex || '(TCP 建立握手)' }}
                  </td>
                </tr>
                <tr v-if="filteredPackets.length === 0">
                  <td colspan="6" class="p-4">
                    <EmptyState
                      icon="shield"
                      :title="packets.length === 0 ? '暂无蜜罐诱捕命中记录' : '无符合过滤条件的诱捕记录'"
                      :description="packets.length === 0 ? '启动诱捕后，外部对诱饵端口的扫描或连接将在此实时告警。' : '请调整右上角 IP、端口或协议过滤关键词后重试。'"
                    />
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- 底部关闭 -->
      <div class="px-6 py-3 border-t border-(--border-subtle) bg-(--surface-content-alt) flex items-center justify-between shrink-0">
        <span class="text-xs text-(--text-muted) font-mono-code">
          蜜罐流量已落盘至 received_data.jsonl 并同步接入司法链式哈希
        </span>
        <button @click="$emit('close')" class="ui-btn-secondary px-4 py-1.5 text-xs font-semibold cursor-pointer">
          关闭
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { notifySuccess, notifyInfo, notifyError } from '../composables/useNotification';
import { ref, computed, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';

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
    notifySuccess('蜜罐诱捕引擎已启动', '已监听仿真工控与网络高危服务端口，实时捕获未授权扫描');
  } catch (err: any) {
    notifyError('启动蜜罐诱捕受阻', err);
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
    notifyInfo('蜜罐诱捕已停止', '所有虚拟诱捕端口已安全关闭并释放');
  } catch (err: any) {
    notifyError('停止蜜罐诱捕受阻', err);
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
