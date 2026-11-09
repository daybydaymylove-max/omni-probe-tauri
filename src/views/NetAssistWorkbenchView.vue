<template>
  <div class="h-full w-full flex flex-col overflow-hidden bg-slate-100/50 dark:bg-slate-900/50 backdrop-blur-2xl p-4 gap-3 select-none">
    
    <!-- 顶栏：工作台标识与状态概览 -->
    <header class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-xl border border-slate-200/60 dark:border-slate-700/60 rounded-2xl px-5 py-3 flex items-center justify-between shrink-0 shadow-sm">
      <div class="flex items-center gap-3.5">
        <div class="w-9 h-9 rounded-xl bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center text-white shadow-md shadow-sky-500/20 font-mono font-bold text-xs">
          NET
        </div>
        <div>
          <h2 class="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <span>工业级网络调试助手工作台 (NetAssist Pro)</span>
            <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold tracking-tight"
              :class="isRunning ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30' : 'bg-slate-500/15 text-slate-500 border border-slate-500/30'">
              {{ isRunning ? `● ${sessionStatus}` : '○ 会话待命 (IDLE)' }}
            </span>
          </h2>
          <p class="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 font-mono">
            全双工异步非阻塞通信 · TCP 客户端/服务端 · UDP 单播/广播/组播 · 帧超时断包 · 工控规约双向联动
          </p>
        </div>
      </div>

      <!-- 右侧快速统计概览 -->
      <div class="flex items-center gap-4 text-xs font-mono">
        <div class="flex items-center gap-2 bg-slate-100/80 dark:bg-slate-900/80 px-3 py-1.5 rounded-xl border border-slate-200/50 dark:border-slate-700/50">
          <span class="text-slate-400">RX:</span>
          <span class="font-bold text-emerald-600 dark:text-emerald-400">{{ formatBytes(stats.rxBytes) }} ({{ stats.rxPackets }} 帧)</span>
          <span class="text-slate-300 dark:text-slate-600">|</span>
          <span class="text-slate-400">TX:</span>
          <span class="font-bold text-sky-600 dark:text-sky-400">{{ formatBytes(stats.txBytes) }} ({{ stats.txPackets }} 帧)</span>
        </div>
        <button @click="resetStats" class="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg hover:bg-slate-200/50 dark:hover:bg-slate-700/50 cursor-pointer" title="清空统计数据">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>
      </div>
    </header>

    <!-- 主工作区：三栏布局 (左控制 / 中收发终端 / 右预设与模板) -->
    <div class="flex-1 grid grid-cols-12 gap-3 min-h-0">
      
      <!-- 1. 左栏：协议模式与套接字控制面板 (4 列) -->
      <aside class="col-span-3 bg-white/80 dark:bg-slate-800/80 backdrop-blur-xl border border-slate-200/60 dark:border-slate-700/60 rounded-2xl p-4 flex flex-col gap-3.5 overflow-y-auto custom-scrollbar shadow-sm">
        
        <!-- 协议模式切换胶囊 -->
        <div>
          <label class="text-[10px] font-bold text-slate-500 uppercase block mb-1.5">通信规约模式</label>
          <div class="grid grid-cols-3 gap-1 bg-slate-100 dark:bg-slate-900/80 p-1 rounded-xl border border-slate-200/60 dark:border-slate-700/60">
            <button
              v-for="m in protocolModes"
              :key="m.id"
              @click="!isRunning && (selectedMode = m.id)"
              :disabled="isRunning"
              :class="['py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer text-center',
                selectedMode === m.id ? 'bg-white dark:bg-slate-800 text-sky-600 dark:text-sky-400 shadow-sm' : 'text-slate-600 dark:text-slate-400 hover:text-slate-900',
                isRunning ? 'opacity-50 cursor-not-allowed' : '']"
            >
              {{ m.label }}
            </button>
          </div>
        </div>

        <!-- 参数配置表单 -->
        <div class="space-y-3 font-mono text-xs">
          <!-- TCP Client 参数 -->
          <template v-if="selectedMode === 'TCP_CLIENT'">
            <div>
              <label class="text-[10px] font-bold text-slate-500 block mb-1">目标远端 IP</label>
              <input v-model="targetIp" :disabled="isRunning" placeholder="127.0.0.1" class="form-input-box" />
            </div>
            <div>
              <label class="text-[10px] font-bold text-slate-500 block mb-1">目标远端端口</label>
              <input v-model.number="targetPort" :disabled="isRunning" type="number" placeholder="8080" class="form-input-box" />
            </div>
          </template>

          <!-- TCP Server 参数 -->
          <template v-else-if="selectedMode === 'TCP_SERVER'">
            <div>
              <label class="text-[10px] font-bold text-slate-500 block mb-1">本地监听 IP</label>
              <input v-model="localBindIp" :disabled="isRunning" placeholder="0.0.0.0" class="form-input-box" />
            </div>
            <div>
              <label class="text-[10px] font-bold text-slate-500 block mb-1">本地监听端口</label>
              <input v-model.number="localBindPort" :disabled="isRunning" type="number" placeholder="8080" class="form-input-box" />
            </div>
            <!-- TCP Server 连接池 -->
            <div>
              <div class="flex items-center justify-between mb-1">
                <label class="text-[10px] font-bold text-slate-500">活动客户端连接池</label>
                <span class="text-[10px] text-sky-600 dark:text-sky-400 font-bold">({{ activeClients.length }} 在线)</span>
              </div>
              <select v-model="selectedClientTarget" class="form-input-box font-mono">
                <option value="">-- 群发广播给所有客户端 --</option>
                <option v-for="c in activeClients" :key="c" :value="c">指定端点: {{ c }}</option>
              </select>
            </div>
          </template>

          <!-- UDP 模式参数 -->
          <template v-else-if="selectedMode === 'UDP'">
            <div class="grid grid-cols-2 gap-2">
              <div>
                <label class="text-[10px] font-bold text-slate-500 block mb-1">本地绑定端口</label>
                <input v-model.number="localBindPort" :disabled="isRunning" type="number" placeholder="0 (随机)" class="form-input-box" />
              </div>
              <div>
                <label class="text-[10px] font-bold text-slate-500 block mb-1">目标远端端口</label>
                <input v-model.number="targetPort" placeholder="8080" class="form-input-box" />
              </div>
            </div>
            <div>
              <label class="text-[10px] font-bold text-slate-500 block mb-1">目标主机 IP (支持 255.255.255.255)</label>
              <input v-model="targetIp" placeholder="127.0.0.1 / 255.255.255.255" class="form-input-box" />
            </div>
          </template>

          <!-- 帧断包超时阈值 -->
          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="text-[10px] font-bold text-slate-500">帧间隔断包判定阈值</label>
              <span class="text-[10px] text-slate-500">{{ frameTimeoutMs }} ms</span>
            </div>
            <input v-model.number="frameTimeoutMs" :disabled="isRunning" type="range" min="5" max="200" step="5" class="w-full accent-sky-500 cursor-pointer" />
            <p class="text-[9px] text-slate-400 mt-0.5">当两批碎片数据间隔超过该时长，判定为独立完整业务帧并上屏</p>
          </div>
        </div>

        <!-- 会话启停按钮 -->
        <div class="mt-auto pt-2">
          <button
            @click="toggleSession"
            :class="['w-full py-2.5 rounded-xl font-bold text-xs transition-all shadow-sm active:scale-95 cursor-pointer flex items-center justify-center gap-2',
              isRunning ? 'bg-rose-600 hover:bg-rose-700 text-white shadow-rose-500/20' : 'bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-600 hover:to-indigo-700 text-white shadow-sky-500/20']"
          >
            <span>{{ isRunning ? '■ 停止会话并释放端口' : '▶ 启动并建立通信连接' }}</span>
          </button>
        </div>
      </aside>

      <!-- 2. 中栏：全双工数据交互终端 (6 列) -->
      <main class="col-span-6 flex flex-col gap-3 min-h-0">
        
        <!-- 上部：数据接收区 (RX Terminal) -->
        <div class="flex-1 bg-white/80 dark:bg-slate-800/80 backdrop-blur-xl border border-slate-200/60 dark:border-slate-700/60 rounded-2xl flex flex-col overflow-hidden shadow-sm min-h-0">
          
          <!-- 接收区顶栏控制器 -->
          <div class="px-4 py-2 border-b border-slate-200/50 dark:border-slate-700/50 flex items-center justify-between bg-slate-50/50 dark:bg-slate-900/30 text-xs shrink-0">
            <div class="flex items-center gap-3">
              <span class="font-bold text-slate-700 dark:text-slate-200 text-xs flex items-center gap-1.5">
                <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                <span>数据接收终端 (RX) [{{ packetLog.length }} 帧]</span>
              </span>
              <!-- HEX / ASCII 切换 -->
              <div class="flex items-center bg-slate-200/60 dark:bg-slate-700/60 p-0.5 rounded-lg text-[11px] font-mono">
                <button @click="rxFormat = 'HEX'" :class="['px-2 py-0.5 rounded-md transition-all', rxFormat === 'HEX' ? 'bg-white dark:bg-slate-800 text-sky-600 font-bold shadow-xs' : 'text-slate-600 dark:text-slate-400']">HEX</button>
                <button @click="rxFormat = 'ASCII'" :class="['px-2 py-0.5 rounded-md transition-all', rxFormat === 'ASCII' ? 'bg-white dark:bg-slate-800 text-sky-600 font-bold shadow-xs' : 'text-slate-600 dark:text-slate-400']">ASCII</button>
              </div>
            </div>

            <!-- 控制开关 -->
            <div class="flex items-center gap-2 text-[11px] text-slate-500">
              <label class="flex items-center gap-1 cursor-pointer">
                <input type="checkbox" v-model="showTimestamp" class="accent-sky-500 rounded" />
                <span>时标</span>
              </label>
              <label class="flex items-center gap-1 cursor-pointer">
                <input type="checkbox" v-model="autoScroll" class="accent-sky-500 rounded" />
                <span>滚屏</span>
              </label>
              <button @click="packetLog = []" class="px-2 py-0.5 hover:bg-slate-200/50 dark:hover:bg-slate-700/50 rounded text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer">清屏</button>
              <button @click="exportLog" class="px-2 py-0.5 hover:bg-slate-200/50 dark:hover:bg-slate-700/50 rounded text-sky-600 dark:text-sky-400 font-bold cursor-pointer">保存日志</button>
            </div>
          </div>

          <!-- 消息流滚动画布 -->
          <div ref="rxScrollContainer" class="flex-1 overflow-y-auto custom-scrollbar p-3 space-y-2 font-mono text-xs select-text">
            <div
              v-for="item in packetLog"
              :key="item.id"
              class="p-2 rounded-xl border transition-all text-xs"
              :class="item.direction === 'RX'
                ? 'bg-emerald-500/5 border-emerald-500/20 text-slate-800 dark:text-slate-100'
                : 'bg-sky-500/5 border-sky-500/20 text-slate-800 dark:text-slate-100'"
            >
              <div class="flex items-center justify-between text-[10px] text-slate-400 mb-1 border-b border-slate-200/40 dark:border-slate-700/40 pb-0.5">
                <div class="flex items-center gap-2">
                  <span
                    class="px-1.5 py-0.2 rounded font-bold uppercase text-[9px]"
                    :class="item.direction === 'RX' ? 'bg-emerald-500 text-white' : 'bg-sky-500 text-white'"
                  >
                    {{ item.direction }}
                  </span>
                  <span class="font-bold text-slate-700 dark:text-slate-300">{{ item.remote_addr }}</span>
                  <span>({{ item.length }} Bytes)</span>
                </div>
                <span v-if="showTimestamp">{{ formatTime(item.timestamp_ms) }}</span>
              </div>

              <!-- HEX 显示 -->
              <div v-if="rxFormat === 'HEX'" class="break-all tracking-wider font-semibold text-slate-700 dark:text-slate-200">
                {{ formatHexSpaced(item.payload_hex) }}
              </div>
              <!-- ASCII 纯文本 -->
              <div v-else class="break-all whitespace-pre-wrap font-sans text-slate-700 dark:text-slate-200">
                {{ item.payload_text }}
              </div>
            </div>

            <!-- 空态提示 -->
            <div v-if="packetLog.length === 0" class="h-full flex flex-col items-center justify-center text-slate-400 text-xs py-10 gap-1.5">
              <svg class="w-8 h-8 text-slate-300 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
              </svg>
              <span>暂无通信数据流水</span>
              <span class="text-[10px] text-slate-400">建立通信后收发报文将在此毫秒级实时显现</span>
            </div>
          </div>
        </div>

        <!-- 下部：数据发送控制区 (TX Terminal) -->
        <div class="h-44 bg-white/80 dark:bg-slate-800/80 backdrop-blur-xl border border-slate-200/60 dark:border-slate-700/60 rounded-2xl flex flex-col overflow-hidden shadow-sm shrink-0">
          
          <!-- 发送控制工具栏 -->
          <div class="px-4 py-1.5 border-b border-slate-200/50 dark:border-slate-700/50 flex items-center justify-between bg-slate-50/50 dark:bg-slate-900/30 text-xs shrink-0">
            <div class="flex items-center gap-3">
              <span class="font-bold text-slate-700 dark:text-slate-200 text-xs flex items-center gap-1.5">
                <span class="w-2 h-2 rounded-full bg-sky-500"></span>
                <span>数据发送终端 (TX)</span>
              </span>
              <!-- 发送格式 HEX / ASCII -->
              <div class="flex items-center bg-slate-200/60 dark:bg-slate-700/60 p-0.5 rounded-lg text-[11px] font-mono">
                <button @click="txFormat = 'HEX'" :class="['px-2 py-0.5 rounded-md transition-all', txFormat === 'HEX' ? 'bg-white dark:bg-slate-800 text-sky-600 font-bold shadow-xs' : 'text-slate-600 dark:text-slate-400']">HEX</button>
                <button @click="txFormat = 'ASCII'" :class="['px-2 py-0.5 rounded-md transition-all', txFormat === 'ASCII' ? 'bg-white dark:bg-slate-800 text-sky-600 font-bold shadow-xs' : 'text-slate-600 dark:text-slate-400']">ASCII</button>
              </div>
            </div>

            <!-- 校验和追加与换行 -->
            <div class="flex items-center gap-2 text-[11px]">
              <select v-model="appendChecksum" class="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-2 py-0.5 text-slate-700 dark:text-slate-200 text-[10px] font-bold">
                <option value="NONE">无校验和</option>
                <option value="MODBUS_CRC16">Modbus CRC-16 (低字节在前)</option>
                <option value="CRC32">CRC-32 (IEEE 802.3)</option>
                <option value="SUM8">8位累加和 (SumCheck)</option>
                <option value="BCC">异或校验 (BCC/XOR)</option>
              </select>

              <label class="flex items-center gap-1 text-slate-500 cursor-pointer">
                <input type="checkbox" v-model="appendNewline" class="accent-sky-500 rounded" />
                <span>\\r\\n 换行</span>
              </label>

              <!-- 定时自动循环发送 -->
              <div class="flex items-center gap-1 pl-2 border-l border-slate-200 dark:border-slate-700">
                <label class="flex items-center gap-1 text-slate-500 cursor-pointer">
                  <input type="checkbox" v-model="autoRepeat" @change="toggleAutoRepeat" class="accent-sky-500 rounded" />
                  <span>自动轮发</span>
                </label>
                <input v-model.number="repeatIntervalMs" type="number" min="50" max="60000" class="w-14 px-1 py-0.5 text-[10px] font-mono border rounded bg-white dark:bg-slate-800" />
                <span class="text-[10px] text-slate-400">ms</span>
              </div>
            </div>
          </div>

          <!-- 发送文本域与发送按钮 -->
          <div class="flex-1 flex p-2 gap-2 min-h-0">
            <textarea
              v-model="txPayload"
              :placeholder="txFormat === 'HEX' ? '输入待发送的十六进制字节流，如: 01 03 00 00 00 02' : '输入待发送的 ASCII 文本字符内容 (支持 \\r\\n)'"
              class="flex-1 h-full bg-slate-50/50 dark:bg-slate-900/50 border border-slate-200/80 dark:border-slate-700/80 rounded-xl p-2.5 text-xs font-mono text-slate-800 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500/30 resize-none"
              @keydown.ctrl.enter="sendPayload"
            />
            <div class="flex flex-col gap-1.5 w-24 shrink-0">
              <button
                @click="sendPayload"
                :disabled="!isRunning || !txPayload.trim()"
                class="flex-1 rounded-xl bg-gradient-to-tr from-sky-500 to-indigo-600 hover:from-sky-600 hover:to-indigo-700 text-white font-bold text-xs shadow-sm transition-all flex flex-col items-center justify-center gap-0.5 cursor-pointer disabled:opacity-40 active:scale-95"
              >
                <span>立即发送</span>
                <span class="text-[9px] font-normal opacity-80">(Ctrl+Enter)</span>
              </button>
              <button @click="txPayload = ''" class="py-1 text-[10px] text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 bg-slate-100 dark:bg-slate-700/50 rounded-lg cursor-pointer">清空输入</button>
            </div>
          </div>
        </div>
      </main>

      <!-- 3. 右栏：工控规约模板与快捷预设指令列表 (3 列) -->
      <aside class="col-span-3 bg-white/80 dark:bg-slate-800/80 backdrop-blur-xl border border-slate-200/60 dark:border-slate-700/60 rounded-2xl p-4 flex flex-col gap-3.5 overflow-y-auto custom-scrollbar shadow-sm">
        
        <!-- 标准工控协议模板一键加载 -->
        <div>
          <label class="text-[10px] font-bold text-slate-500 uppercase block mb-1.5">标准工控规约载荷模板</label>
          <select @change="applyProtocolPreset(($event.target as HTMLSelectElement).value)" class="form-input-box">
            <option value="">-- 选择工控标准报文 --</option>
            <option value="modbus_read">Modbus-TCP: 读保持寄存器 0-1 (Func 03)</option>
            <option value="modbus_write">Modbus-TCP: 写单个保持寄存器 (Func 06)</option>
            <option value="modbus_rtu">Modbus-RTU: 读寄存器 (含CRC16: 01 03 00 00 00 02 C4 0B)</option>
            <option value="s7comm_setup">西门子 S7Comm: COTP 与通信握手请求</option>
            <option value="iec104_testfr">电力 IEC 104: U 格式测试激活帧 (TESTFR_ACT)</option>
            <option value="mqtt_ping">物联网 MQTT: 心跳保活帧 (PINGREQ)</option>
            <option value="http_probe">HTTP/1.1: 基础探活请求 (GET / HTTP/1.1)</option>
            <option value="sl651_telemetry">水利 SL651: 遥测数据上报帧</option>
          </select>
        </div>

        <!-- 预设快捷指令轮询列表 (Command Presets) -->
        <div class="flex-1 flex flex-col min-h-0 border-t border-slate-200/60 dark:border-slate-700/60 pt-3">
          <div class="flex items-center justify-between mb-2">
            <span class="text-[10px] font-bold text-slate-500 uppercase">多指令快捷调度列表</span>
            <button @click="addNewPreset" class="text-[10px] text-sky-600 dark:text-sky-400 font-bold hover:underline cursor-pointer">+ 添加指令</button>
          </div>

          <div class="flex-1 overflow-y-auto custom-scrollbar space-y-2 pr-0.5">
            <div
              v-for="(cmd, idx) in presetCommands"
              :key="idx"
              class="bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/60 dark:border-slate-700/60 rounded-xl p-2 text-xs font-mono space-y-1.5"
            >
              <div class="flex items-center justify-between text-[10px]">
                <input v-model="cmd.name" class="font-bold text-slate-700 dark:text-slate-200 bg-transparent border-b border-transparent focus:border-sky-400 outline-none w-28" />
                <div class="flex items-center gap-1.5">
                  <button @click="sendSpecificPreset(cmd)" :disabled="!isRunning" class="px-2 py-0.5 bg-sky-500 hover:bg-sky-600 text-white rounded text-[9px] font-bold cursor-pointer disabled:opacity-40">发送</button>
                  <button @click="presetCommands.splice(idx, 1)" class="text-slate-400 hover:text-rose-500 text-[10px] cursor-pointer">✕</button>
                </div>
              </div>
              <input v-model="cmd.payload" placeholder="HEX 数据载荷" class="w-full bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded px-1.5 py-0.5 text-[10px] text-slate-600 dark:text-slate-300" />
            </div>
          </div>
        </div>

      </aside>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import {
  notifySuccess,
  notifyInfo,
  notifyWarning,
  notifyError,
} from '../composables/useNotification';

interface ProtocolModeOption {
  id: 'TCP_CLIENT' | 'TCP_SERVER' | 'UDP';
  label: string;
}

const protocolModes: ProtocolModeOption[] = [
  { id: 'TCP_CLIENT', label: 'TCP 客户端' },
  { id: 'TCP_SERVER', label: 'TCP 服务端' },
  { id: 'UDP', label: 'UDP 模式' },
];

const selectedMode = ref<'TCP_CLIENT' | 'TCP_SERVER' | 'UDP'>('TCP_CLIENT');
const isRunning = ref(false);
const sessionStatus = ref('就绪');

// 配置参数
const targetIp = ref('127.0.0.1');
const targetPort = ref(8080);
const localBindIp = ref('0.0.0.0');
const localBindPort = ref(8080);
const frameTimeoutMs = ref(25);
const activeClients = ref<string[]>([]);
const selectedClientTarget = ref('');

// 收发控制与日志
const rxFormat = ref<'HEX' | 'ASCII'>('HEX');
const txFormat = ref<'HEX' | 'ASCII'>('HEX');
const showTimestamp = ref(true);
const autoScroll = ref(true);
const appendChecksum = ref('NONE');
const appendNewline = ref(false);
const autoRepeat = ref(false);
const repeatIntervalMs = ref(1000);
const txPayload = ref('01 03 00 00 00 02');

interface PacketLogItem {
  id: string;
  direction: 'TX' | 'RX';
  mode: string;
  local_addr: string;
  remote_addr: string;
  length: usize;
  payload_hex: string;
  payload_text: string;
  timestamp_ms: number;
}

type usize = number;

const packetLog = ref<PacketLogItem[]>([]);
const rxScrollContainer = ref<HTMLDivElement | null>(null);

// 统计信息
const stats = ref({
  rxBytes: 0,
  rxPackets: 0,
  txBytes: 0,
  txPackets: 0,
});

let repeatTimer: any = null;
let unlistenPacket: UnlistenFn | null = null;
let unlistenStatus: UnlistenFn | null = null;
let unlistenClients: UnlistenFn | null = null;

// 预设指令表
interface PresetCommand {
  name: string;
  payload: string;
}

const presetCommands = ref<PresetCommand[]>([
  { name: 'Modbus 读保持寄存器', payload: '01 03 00 00 00 02' },
  { name: 'Modbus 读输入寄存器', payload: '01 04 00 00 00 02' },
  { name: 'S7Comm 握手请求', payload: '03 00 00 16 11 E0 00 00 00 01 00 C1 02 01 00 C2 02 01 02 C0 01 09' },
  { name: 'IEC 104 测试激活帧', payload: '68 04 43 00 00 00' },
  { name: 'MQTT PINGREQ 心跳', payload: 'C0 00' },
]);

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString('zh-CN', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

function formatHexSpaced(hexStr: string): string {
  const clean = hexStr.replace(/\s+/g, '');
  return clean.match(/.{1,2}/g)?.join(' ') || hexStr;
}

function resetStats() {
  stats.value = { rxBytes: 0, rxPackets: 0, txBytes: 0, txPackets: 0 };
  notifyInfo('通信统计已复位', 'RX/TX 吞吐与帧计数器已归零');
}

async function toggleSession() {
  if (isRunning.value) {
    try {
      await invoke('stop_net_assist_session_cmd');
      isRunning.value = false;
      sessionStatus.value = '已停止';
      if (repeatTimer) {
        clearInterval(repeatTimer);
        repeatTimer = null;
        autoRepeat.value = false;
      }
      notifyInfo('网络调试会话已终止', '物理套接字句柄已安全释放');
    } catch (e) {
      notifyError('停止会话失败', e);
    }
  } else {
    try {
      const config = {
        mode: selectedMode.value,
        local_ip: selectedMode.value === 'TCP_CLIENT' ? null : localBindIp.value,
        local_port: selectedMode.value === 'TCP_CLIENT' ? null : localBindPort.value,
        remote_ip: selectedMode.value === 'TCP_SERVER' ? null : targetIp.value,
        remote_port: selectedMode.value === 'TCP_SERVER' ? null : targetPort.value,
        frame_timeout_ms: frameTimeoutMs.value,
      };

      await invoke('start_net_assist_session_cmd', { config });
      isRunning.value = true;
      sessionStatus.value = '运行中';
      notifySuccess('网络调试会话已建立', `模式: ${selectedMode.value}，端口已成功绑定接通`);
    } catch (e) {
      notifyError('启动调试会话受阻', e);
    }
  }
}

async function sendPayload() {
  if (!isRunning.value) {
    notifyWarning('操作受阻', '请先启动调试会话并建立套接字连接');
    return;
  }

  let raw = txPayload.value.trim();
  if (!raw) return;

  // 1. 如果是 ASCII 模式，先转为 HEX
  let hexToSend = '';
  if (txFormat.value === 'ASCII') {
    if (appendNewline.value) {
      raw += '\r\n';
    }
    const encoder = new TextEncoder();
    const bytes = encoder.encode(raw);
    hexToSend = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  } else {
    hexToSend = raw.replace(/\s+/g, '');
    if (appendNewline.value) {
      hexToSend += '0D0A';
    }
  }

  // 2. 计算并追加校验和
  if (appendChecksum.value !== 'NONE') {
    try {
      const checksumStr = await invoke<string>('calculate_checksum_cmd', {
        payloadHex: hexToSend,
        algo: appendChecksum.value,
      });
      hexToSend += checksumStr.replace(/\s+/g, '');
    } catch (e) {
      notifyError('校验和计算失败', e);
      return;
    }
  }

  try {
    const target = selectedMode.value === 'TCP_SERVER' && selectedClientTarget.value ? selectedClientTarget.value : null;
    const sentBytes = await invoke<number>('send_net_assist_data_cmd', {
      payloadHex: hexToSend,
      targetClient: target,
    });
    stats.value.txBytes += sentBytes;
    stats.value.txPackets += 1;
  } catch (e) {
    notifyError('发送数据受阻', e);
  }
}

function sendSpecificPreset(preset: PresetCommand) {
  txPayload.value = preset.payload;
  sendPayload();
}

function addNewPreset() {
  presetCommands.value.push({
    name: `自定义指令 ${presetCommands.value.length + 1}`,
    payload: '01 03 00 00 00 01',
  });
}

function toggleAutoRepeat() {
  if (autoRepeat.value) {
    if (!isRunning.value) {
      notifyWarning('请先启动会话', '调试会话处于就绪状态下方可执行循环自动发送');
      autoRepeat.value = false;
      return;
    }
    repeatTimer = setInterval(() => {
      sendPayload();
    }, Math.max(50, repeatIntervalMs.value));
    notifyInfo('自动循环发送已启动', `发送步长间隔: ${repeatIntervalMs.value} ms`);
  } else {
    if (repeatTimer) {
      clearInterval(repeatTimer);
      repeatTimer = null;
    }
    notifyInfo('自动循环发送已停止', '已恢复手动发报模式');
  }
}

function applyProtocolPreset(type: string) {
  if (!type) return;
  txFormat.value = 'HEX';
  switch (type) {
    case 'modbus_read':
      txPayload.value = '00 01 00 00 00 06 01 03 00 00 00 02';
      appendChecksum.value = 'NONE';
      break;
    case 'modbus_write':
      txPayload.value = '00 02 00 00 00 06 01 06 00 01 00 64';
      appendChecksum.value = 'NONE';
      break;
    case 'modbus_rtu':
      txPayload.value = '01 03 00 00 00 02 C4 0B';
      appendChecksum.value = 'NONE';
      break;
    case 's7comm_setup':
      txPayload.value = '03 00 00 16 11 E0 00 00 00 01 00 C1 02 01 00 C2 02 01 02 C0 01 09';
      break;
    case 'iec104_testfr':
      txPayload.value = '68 04 43 00 00 00';
      break;
    case 'mqtt_ping':
      txPayload.value = 'C0 00';
      break;
    case 'http_probe':
      txFormat.value = 'ASCII';
      txPayload.value = 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: OmniProbe-NetAssist/0.2.2\r\nConnection: close\r\n\r\n';
      break;
    case 'sl651_telemetry':
      txPayload.value = '7E 7E 01 00 00 00 00 01 00 02 32 00 00 03 14 00 00 00';
      break;
  }
  notifyInfo('规约模板已载入', `已将 ${type} 报文填入出向发送区`);
}

function exportLog() {
  if (packetLog.value.length === 0) {
    notifyWarning('导出提示', '当前无数据记录可供导出');
    return;
  }
  const lines = packetLog.value.map(p => {
    return `[${formatTime(p.timestamp_ms)}] [${p.direction}] ${p.remote_addr} (${p.length}B)\nHEX: ${p.payload_hex}\nTXT: ${p.payload_text}\n`;
  });
  const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `OmniProbe_NetAssist_Log_${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
  notifySuccess('通信日志导出成功', '已生成纯文本日志文件并启动保存');
}

onMounted(async () => {
  // 监听数据包事件
  unlistenPacket = await listen<PacketLogItem>('net-assist-packet', (event) => {
    const p = event.payload;
    packetLog.value.push(p);
    if (packetLog.value.length > 5000) {
      packetLog.value.shift();
    }
    if (p.direction === 'RX') {
      stats.value.rxBytes += p.length;
      stats.value.rxPackets += 1;
    }
    if (autoScroll.value) {
      nextTick(() => {
        if (rxScrollContainer.value) {
          rxScrollContainer.value.scrollTop = rxScrollContainer.value.scrollHeight;
        }
      });
    }
  });

  // 监听状态变迁
  unlistenStatus = await listen<string>('net-assist-status', (event) => {
    sessionStatus.value = event.payload;
    if (event.payload === 'STOPPED' || event.payload === 'DISCONNECTED_BY_PEER') {
      isRunning.value = false;
      if (repeatTimer) {
        clearInterval(repeatTimer);
        repeatTimer = null;
        autoRepeat.value = false;
      }
    }
  });

  // 监听客户端连接池更新
  unlistenClients = await listen<any>('net-assist-clients', (event) => {
    activeClients.value = event.payload.active_clients || [];
    if (event.payload.event_type === 'CONNECTED') {
      notifyInfo('新客户端接入', `端点: ${event.payload.client_addr} 已连接`);
    } else {
      notifyWarning('客户端断开', `端点: ${event.payload.client_addr} 已退出`);
    }
  });
});

onUnmounted(() => {
  if (unlistenPacket) unlistenPacket();
  if (unlistenStatus) unlistenStatus();
  if (unlistenClients) unlistenClients();
  if (repeatTimer) clearInterval(repeatTimer);
});
</script>

<style scoped>
.form-input-box {
  width: 100%;
  background-color: rgba(255, 255, 255, 0.8);
  border: 1px solid rgba(226, 232, 240, 0.8);
  border-radius: 0.75rem;
  padding: 0.35rem 0.65rem;
  font-size: 0.75rem;
  outline: none;
  transition: all 0.15s ease-in-out;
}

:global(.theme-apple-dark) .form-input-box {
  background-color: rgba(30, 41, 59, 0.8);
  border-color: rgba(51, 65, 85, 0.8);
  color: #f1f5f9;
}

.form-input-box:focus {
  border-color: rgba(14, 165, 233, 0.6);
  box-shadow: 0 0 0 2px rgba(14, 165, 233, 0.15);
}
</style>
