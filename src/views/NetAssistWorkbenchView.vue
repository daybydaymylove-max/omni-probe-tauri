<template>
  <div class="h-full w-full flex flex-col overflow-hidden bg-slate-100/40 dark:bg-slate-900/40 backdrop-blur-2xl p-3 gap-2.5 select-none font-sans">
    
    <!-- 顶栏：工作台标识、运行态指示与统计概览 (Apple 2026 Liquid Glass) -->
    <header class="glass-surface rounded-2xl px-4 py-2.5 flex items-center justify-between shrink-0 shadow-sm border border-slate-200/80 dark:border-white/10">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 rounded-xl bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center text-white shadow-md shadow-sky-500/25 font-mono font-bold text-xs">
          NET
        </div>
        <div>
          <div class="flex items-center gap-2">
            <h2 class="text-xs font-bold text-slate-800 dark:text-slate-100 tracking-tight">
              工业级全双工网络调试助手 (NetAssist Pro)
            </h2>
            <span class="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold flex items-center gap-1 border shadow-2xs"
              :class="isRunning
                ? 'bg-emerald-50 text-emerald-800 border-emerald-300 dark:bg-emerald-950/70 dark:text-emerald-300 dark:border-emerald-700'
                : 'bg-slate-100 text-slate-600 border-slate-300 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700'">
              <span class="w-1.5 h-1.5 rounded-full shrink-0"
                :class="isRunning ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'"></span>
              <span>{{ isRunning ? `会话运行中: ${sessionStatus}` : '○ 会话待命 (IDLE)' }}</span>
            </span>
          </div>
          <p class="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5 font-mono">
            全双工异步通信 · TCP 客户端/服务端 · UDP 单播/广播/组播 · 帧超时断包 · 工业规约双向校验
          </p>
        </div>
      </div>

      <!-- 右侧快速统计概览与联动按钮 -->
      <div class="flex items-center gap-3 text-xs font-mono">
        <!-- 统计胶囊 -->
        <div class="flex items-center gap-2.5 glass-pill px-3 py-1 rounded-xl border border-slate-200/60 dark:border-white/10 text-[11px]">
          <span class="text-slate-500 dark:text-slate-400">RX:</span>
          <span class="font-bold text-emerald-700 dark:text-emerald-400">{{ formatBytes(stats.rxBytes) }} ({{ stats.rxPackets }} 帧)</span>
          <span class="text-slate-300 dark:text-slate-600">|</span>
          <span class="text-slate-500 dark:text-slate-400">TX:</span>
          <span class="font-bold text-sky-700 dark:text-sky-400">{{ formatBytes(stats.txBytes) }} ({{ stats.txPackets }} 帧)</span>
        </div>

        <button @click="resetStats" class="glass-pill p-1.5 text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-100 rounded-xl cursor-pointer transition-colors" title="复位收发统计">
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>

        <button @click="$emit('switchWorkbench', 'traffic')" class="glass-pill px-2.5 py-1 rounded-xl text-[10px] font-bold text-sky-700 dark:text-sky-300 hover:text-sky-900 flex items-center gap-1 cursor-pointer transition-colors" title="前往全息流量分析大盘">
          <span>↗ 全息流量大盘</span>
        </button>
      </div>
    </header>

    <!-- 主工作区：三栏布局 (左控制 / 中收发终端 / 右工控模板与多指令矩阵) -->
    <div class="flex-1 grid grid-cols-12 gap-2.5 min-h-0">
      
      <!-- 1. 左栏：协议模式与套接字控制面板 (3 列) -->
      <aside class="col-span-3 glass-surface rounded-2xl p-3.5 flex flex-col gap-3 overflow-y-auto custom-scrollbar border border-slate-200/80 dark:border-white/10 shadow-sm">
        
        <!-- 协议模式切换胶囊 -->
        <div>
          <label class="text-[10px] font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider block mb-1.5 font-mono">通信规约模式</label>
          <div class="grid grid-cols-3 gap-1 glass-pill p-0.5 rounded-xl border border-slate-200/60 dark:border-white/10">
            <button
              v-for="m in protocolModes"
              :key="m.id"
              @click="!isRunning && (selectedMode = m.id)"
              :disabled="isRunning"
              :class="['py-1 rounded-lg text-xs font-bold transition-all cursor-pointer text-center',
                selectedMode === m.id
                  ? 'bg-sky-500/20 text-sky-800 dark:text-sky-300 shadow-2xs border border-sky-400/40'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white',
                isRunning ? 'opacity-50 cursor-not-allowed' : '']"
            >
              {{ m.label }}
            </button>
          </div>
        </div>

        <!-- 参数配置表单 -->
        <div class="space-y-2.5 font-mono text-xs">
          <!-- TCP Client 参数 -->
          <template v-if="selectedMode === 'TCP_CLIENT'">
            <div>
              <div class="flex items-center justify-between mb-1">
                <label class="text-[10px] font-bold text-slate-700 dark:text-slate-300">目标远端 IP (Host)</label>
                <div class="flex items-center gap-1 text-[9px] text-sky-700 dark:text-sky-400 cursor-pointer">
                  <span @click="targetIp = '127.0.0.1'" class="hover:underline">127.0.0.1</span>
                  <span>·</span>
                  <span @click="targetIp = '192.168.1.100'" class="hover:underline">192.168.1.100</span>
                </div>
              </div>
              <input v-model="targetIp" :disabled="isRunning" placeholder="127.0.0.1" class="form-input-box" />
            </div>

            <div>
              <div class="flex items-center justify-between mb-1">
                <label class="text-[10px] font-bold text-slate-700 dark:text-slate-300">目标服务端口 (Port)</label>
                <span class="text-[9px] text-slate-500 font-normal">标准工控/Web</span>
              </div>
              <input v-model.number="targetPort" :disabled="isRunning" type="number" placeholder="8080" class="form-input-box mb-1.5" />
              <!-- 快捷端口一键填入微胶囊 -->
              <div class="flex flex-wrap gap-1">
                <button
                  v-for="p in quickPorts"
                  :key="p.port"
                  @click="!isRunning && (targetPort = p.port)"
                  :disabled="isRunning"
                  class="px-1.5 py-0.5 rounded text-[9px] font-bold glass-pill border border-slate-200 dark:border-white/10 hover:border-sky-400 text-slate-700 dark:text-slate-300 hover:text-sky-700 cursor-pointer transition-colors"
                  :title="p.desc"
                >
                  {{ p.port }} {{ p.label }}
                </button>
              </div>
            </div>
          </template>

          <!-- TCP Server 参数 -->
          <template v-else-if="selectedMode === 'TCP_SERVER'">
            <div>
              <div class="flex items-center justify-between mb-1">
                <label class="text-[10px] font-bold text-slate-700 dark:text-slate-300">本地监听网卡与 IP</label>
                <button @click="loadLocalIpAddresses" class="text-[9px] text-sky-700 dark:text-sky-400 hover:underline cursor-pointer" title="刷新本机网卡列表">
                  ↻ 刷新网卡
                </button>
              </div>
              <!-- 本机网卡智能选择下拉框 -->
              <select v-model="localBindIp" :disabled="isRunning" class="form-input-box font-mono mb-1 text-[11px]">
                <option v-for="ipInfo in localIpList" :key="ipInfo.ip" :value="ipInfo.ip">
                  {{ ipInfo.name }}
                </option>
              </select>
              <input v-model="localBindIp" :disabled="isRunning" placeholder="0.0.0.0" class="form-input-box text-[11px]" title="或自由手动编辑 IP" />
            </div>

            <div>
              <label class="text-[10px] font-bold text-slate-700 dark:text-slate-300 block mb-1">本地监听端口</label>
              <input v-model.number="localBindPort" :disabled="isRunning" type="number" placeholder="8080" class="form-input-box mb-1" />
              <div class="flex flex-wrap gap-1">
                <button
                  v-for="p in quickPorts"
                  :key="p.port"
                  @click="!isRunning && (localBindPort = p.port)"
                  :disabled="isRunning"
                  class="px-1.5 py-0.5 rounded text-[9px] font-bold glass-pill border border-slate-200 dark:border-white/10 hover:border-sky-400 text-slate-700 dark:text-slate-300 hover:text-sky-700 cursor-pointer transition-colors"
                  :title="p.desc"
                >
                  {{ p.port }} {{ p.label }}
                </button>
              </div>
            </div>

            <!-- TCP Server 连接池管理 -->
            <div class="pt-1 border-t border-slate-200/60 dark:border-white/10">
              <div class="flex items-center justify-between mb-1">
                <label class="text-[10px] font-bold text-slate-700 dark:text-slate-300">活动客户端连接池</label>
                <span class="text-[9px] font-bold px-1.5 py-0.2 rounded-full"
                  :class="activeClients.length > 0 ? 'bg-emerald-100 text-emerald-800 border border-emerald-300' : 'bg-slate-100 text-slate-500'">
                  {{ activeClients.length }} 在线
                </span>
              </div>
              <select v-model="selectedClientTarget" class="form-input-box font-mono text-[11px]">
                <option value="">-- [广播群发] 全部在线客户端 --</option>
                <option v-for="c in activeClients" :key="c" :value="c">指定端点: {{ c }}</option>
              </select>
            </div>
          </template>

          <!-- UDP 模式参数 -->
          <template v-else-if="selectedMode === 'UDP'">
            <div class="grid grid-cols-2 gap-1.5">
              <div>
                <label class="text-[10px] font-bold text-slate-700 dark:text-slate-300 block mb-1">本地绑定端口</label>
                <input v-model.number="localBindPort" :disabled="isRunning" type="number" placeholder="0 (随机)" class="form-input-box" />
              </div>
              <div>
                <label class="text-[10px] font-bold text-slate-700 dark:text-slate-300 block mb-1">目标远端端口</label>
                <input v-model.number="targetPort" placeholder="8080" class="form-input-box" />
              </div>
            </div>
            <div>
              <div class="flex items-center justify-between mb-1">
                <label class="text-[10px] font-bold text-slate-700 dark:text-slate-300">目标主机 IP</label>
                <span class="text-[9px] text-sky-700 dark:text-sky-400 cursor-pointer hover:underline" @click="targetIp = '255.255.255.255'">广播 255.255.255.255</span>
              </div>
              <input v-model="targetIp" placeholder="127.0.0.1 或 255.255.255.255" class="form-input-box" />
            </div>
          </template>

          <!-- 帧断包超时阈值 -->
          <div class="pt-1 border-t border-slate-200/60 dark:border-white/10">
            <div class="flex items-center justify-between mb-1">
              <label class="text-[10px] font-bold text-slate-700 dark:text-slate-300">帧间隔断包切分阈值</label>
              <span class="text-[10px] font-bold text-sky-700 dark:text-sky-400">{{ frameTimeoutMs }} ms</span>
            </div>
            <input v-model.number="frameTimeoutMs" :disabled="isRunning" type="range" min="5" max="200" step="5" class="w-full accent-sky-500 cursor-pointer" />
            <p class="text-[9px] text-slate-500 dark:text-slate-400 mt-0.5 leading-tight">碎片数据接收间隔超过该时长，自动定界为完整规约帧上屏</p>
          </div>
        </div>

        <!-- 会话启停大按钮 -->
        <div class="mt-auto pt-2">
          <button
            @click="toggleSession"
            :class="['w-full py-2.5 rounded-xl font-bold text-xs transition-all shadow-sm active:scale-95 cursor-pointer flex items-center justify-center gap-1.5',
              isRunning
                ? 'bg-rose-600 hover:bg-rose-700 text-white shadow-rose-500/25'
                : 'bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-600 hover:to-indigo-700 text-white shadow-sky-500/25']"
          >
            <span class="w-2 h-2 rounded-full" :class="isRunning ? 'bg-white animate-ping' : 'bg-white/80'"></span>
            <span>{{ isRunning ? '■ 停止会话并释放套接字' : '▶ 启动并建立通信套接字' }}</span>
          </button>
        </div>
      </aside>

      <!-- 2. 中栏：全双工终端核心区 (6 列) -->
      <main class="col-span-6 flex flex-col gap-2.5 min-h-0">
        
        <!-- 上部：数据接收终端 (RX Terminal) -->
        <div class="flex-1 glass-surface rounded-2xl flex flex-col overflow-hidden shadow-sm min-h-0 border border-slate-200/80 dark:border-white/10">
          
          <!-- 接收区顶栏控制条 -->
          <div class="px-3.5 py-1.5 border-b border-slate-200/60 dark:border-white/10 flex items-center justify-between bg-white/40 dark:bg-black/20 text-xs shrink-0 backdrop-blur-md">
            <div class="flex items-center gap-2.5">
              <span class="font-bold text-slate-800 dark:text-slate-200 text-xs flex items-center gap-1.5">
                <span class="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_6px_#10B981]"></span>
                <span>数据接收终端 (RX)</span>
                <span class="text-[10px] font-mono text-slate-500">[{{ filteredPacketLog.length }} / {{ packetLog.length }} 帧]</span>
              </span>
              <!-- HEX / ASCII 切换 -->
              <div class="flex items-center glass-pill p-0.5 rounded-lg text-[10px] font-mono">
                <button @click="rxFormat = 'HEX'" :class="['px-2 py-0.5 rounded-md transition-all font-bold cursor-pointer', rxFormat === 'HEX' ? 'bg-cyan-500/20 text-cyan-800 dark:text-cyan-300 shadow-2xs' : 'text-slate-600 dark:text-slate-400']">HEX</button>
                <button @click="rxFormat = 'ASCII'" :class="['px-2 py-0.5 rounded-md transition-all font-bold cursor-pointer', rxFormat === 'ASCII' ? 'bg-cyan-500/20 text-cyan-800 dark:text-cyan-300 shadow-2xs' : 'text-slate-600 dark:text-slate-400']">ASCII</button>
              </div>
            </div>

            <!-- 控制开关群与搜索 -->
            <div class="flex items-center gap-2 text-[11px] text-slate-600 dark:text-slate-300">
              <!-- 关键字过滤输入框 -->
              <div class="flex items-center gap-1 px-2 py-0.5 rounded-lg bg-white/60 dark:bg-black/30 border border-slate-300/60 dark:border-white/10 text-[10px]">
                <span>🔍</span>
                <input v-model="rxSearchQuery" placeholder="过滤关键字 / HEX..." class="bg-transparent outline-none w-24 text-[10px] font-mono text-slate-800 dark:text-slate-200" />
                <button v-if="rxSearchQuery" @click="rxSearchQuery = ''" class="text-slate-400 hover:text-slate-700 cursor-pointer">✕</button>
              </div>

              <label class="flex items-center gap-1 cursor-pointer select-none">
                <input type="checkbox" v-model="showTimestamp" class="accent-sky-500 rounded" />
                <span class="text-[10px]">时标</span>
              </label>

              <label class="flex items-center gap-1 cursor-pointer select-none">
                <input type="checkbox" v-model="autoScroll" class="accent-sky-500 rounded" />
                <span class="text-[10px]">滚屏</span>
              </label>

              <!-- 暂停接收开关 -->
              <button
                @click="isRxPaused = !isRxPaused"
                :class="['px-1.5 py-0.5 rounded text-[10px] font-bold border cursor-pointer transition-colors',
                  isRxPaused ? 'bg-amber-100 text-amber-900 border-amber-300' : 'glass-pill text-slate-600 dark:text-slate-300']"
                :title="isRxPaused ? '已暂停刷新视窗，点击恢复' : '点击暂停滚屏刷新以供排查'"
              >
                {{ isRxPaused ? '⏸ 已暂停' : '▶ 接收中' }}
              </button>

              <button @click="packetLog = []" class="px-1.5 py-0.5 glass-pill rounded text-[10px] text-slate-500 hover:text-slate-800 cursor-pointer">清屏</button>
              <button @click="exportLog" class="px-2 py-0.5 glass-pill rounded text-[10px] text-sky-700 dark:text-sky-300 font-bold hover:text-sky-900 cursor-pointer">导出</button>
            </div>
          </div>

          <!-- 消息流滚动画布 -->
          <div ref="rxScrollContainer" class="flex-1 overflow-y-auto custom-scrollbar p-2.5 space-y-1.5 font-mono text-xs select-text">
            <div
              v-for="item in filteredPacketLog"
              :key="item.id"
              class="group relative p-2 rounded-xl border transition-all text-xs"
              :class="item.direction === 'RX'
                ? 'bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-200/70 dark:border-emerald-800/40'
                : 'bg-sky-50/50 dark:bg-sky-950/20 border-sky-200/70 dark:border-sky-800/40'"
            >
              <!-- 消息头元数据 -->
              <div class="flex items-center justify-between text-[10px] text-slate-500 dark:text-slate-400 mb-1 border-b border-slate-200/50 dark:border-white/5 pb-0.5">
                <div class="flex items-center gap-1.5">
                  <span
                    class="px-1.5 py-0.2 rounded font-bold uppercase text-[9px] shadow-2xs"
                    :class="item.direction === 'RX' ? 'bg-emerald-600 text-white' : 'bg-sky-600 text-white'"
                  >
                    {{ item.direction }}
                  </span>
                  <span class="font-bold text-slate-800 dark:text-slate-200">{{ item.remote_addr }}</span>
                  <span class="font-medium text-slate-600 dark:text-slate-400">({{ item.length }} B)</span>
                </div>
                <div class="flex items-center gap-2">
                  <span v-if="showTimestamp" class="text-slate-500 dark:text-slate-400">{{ formatTime(item.timestamp_ms) }}</span>
                  
                  <!-- 悬停快捷操作按钮组 -->
                  <div class="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1">
                    <button @click="copyText(item.payload_hex)" class="px-1 py-0.2 rounded bg-white dark:bg-slate-800 border text-[9px] text-slate-700 dark:text-slate-200 hover:text-sky-600 cursor-pointer" title="复制 HEX">
                      HEX
                    </button>
                    <button @click="copyText(item.payload_text)" class="px-1 py-0.2 rounded bg-white dark:bg-slate-800 border text-[9px] text-slate-700 dark:text-slate-200 hover:text-sky-600 cursor-pointer" title="复制 ASCII">
                      TXT
                    </button>
                    <button @click="fillTxInput(item.payload_hex)" class="px-1 py-0.2 rounded bg-sky-50 text-sky-800 border border-sky-200 text-[9px] font-bold hover:bg-sky-100 cursor-pointer" title="转入发送区重发">
                      ↩ 载入
                    </button>
                    <button @click="inspectPacketInModal(item)" class="px-1 py-0.2 rounded bg-indigo-50 text-indigo-800 border border-indigo-200 text-[9px] font-bold hover:bg-indigo-100 cursor-pointer" title="在 Omni-Probe 报文分析器中全景解构此帧">
                      🔬 解构
                    </button>
                  </div>
                </div>
              </div>

              <!-- HEX 显示 (双字符空格分块，高对比度工业等宽字阶) -->
              <div v-if="rxFormat === 'HEX'" class="break-all tracking-wider font-mono font-semibold text-slate-800 dark:text-slate-100 leading-relaxed text-[11px]">
                {{ formatHexSpaced(item.payload_hex) }}
              </div>
              <!-- ASCII 纯文本 -->
              <div v-else class="break-all whitespace-pre-wrap font-mono text-slate-800 dark:text-slate-100 leading-relaxed text-[11px]">
                {{ item.payload_text }}
              </div>
            </div>

            <!-- 空态提示 -->
            <div v-if="filteredPacketLog.length === 0" class="h-full flex flex-col items-center justify-center text-slate-400 text-xs py-10 gap-1.5 select-none">
              <div class="w-10 h-10 rounded-xl glass-pill flex items-center justify-center text-slate-400 text-lg mb-1">
                📡
              </div>
              <span class="font-bold text-slate-700 dark:text-slate-300">暂无通信数据流水</span>
              <span class="text-[10px] text-slate-500 font-mono">启动会话后收发报文将在此毫秒级实时显现，支持十六进制与 ASCII 实时双模解析</span>
            </div>
          </div>
        </div>

        <!-- 下部：数据发送控制终端 (TX Terminal) -->
        <div class="h-48 glass-surface rounded-2xl flex flex-col overflow-hidden shadow-sm shrink-0 border border-slate-200/80 dark:border-white/10">
          
          <!-- 发送控制工具栏 -->
          <div class="px-3.5 py-1.5 border-b border-slate-200/60 dark:border-white/10 flex items-center justify-between bg-white/40 dark:bg-black/20 text-xs shrink-0 backdrop-blur-md">
            <div class="flex items-center gap-2.5">
              <span class="font-bold text-slate-800 dark:text-slate-200 text-xs flex items-center gap-1.5">
                <span class="w-2 h-2 rounded-full bg-sky-500 shadow-[0_0_6px_#0EA5E9]"></span>
                <span>数据发送终端 (TX)</span>
              </span>
              <!-- 发送格式 HEX / ASCII -->
              <div class="flex items-center glass-pill p-0.5 rounded-lg text-[10px] font-mono">
                <button @click="txFormat = 'HEX'" :class="['px-2 py-0.5 rounded-md transition-all font-bold cursor-pointer', txFormat === 'HEX' ? 'bg-cyan-500/20 text-cyan-800 dark:text-cyan-300 shadow-2xs' : 'text-slate-600 dark:text-slate-400']">HEX</button>
                <button @click="txFormat = 'ASCII'" :class="['px-2 py-0.5 rounded-md transition-all font-bold cursor-pointer', txFormat === 'ASCII' ? 'bg-cyan-500/20 text-cyan-800 dark:text-cyan-300 shadow-2xs' : 'text-slate-600 dark:text-slate-400']">ASCII</button>
              </div>
            </div>

            <!-- 校验和、换行与轮发 -->
            <div class="flex items-center gap-2 text-[11px]">
              <!-- 工业级校验和选择器 -->
              <select v-model="appendChecksum" class="form-input-box py-0.5 text-[10px] font-bold text-slate-700 dark:text-slate-200 w-auto">
                <option value="NONE">无校验和</option>
                <option value="MODBUS_CRC16">Modbus CRC-16 (低字节在前)</option>
                <option value="CRC32">CRC-32 (IEEE 802.3)</option>
                <option value="SUM8">8位累加和 (SumCheck)</option>
                <option value="BCC">异或校验 (BCC/XOR)</option>
              </select>

              <!-- 发送换行符 -->
              <select v-model="newlineType" class="form-input-box py-0.5 text-[10px] font-bold text-slate-700 dark:text-slate-200 w-auto">
                <option value="NONE">无换行</option>
                <option value="CRLF">\r\n (CRLF)</option>
                <option value="LF">\n (LF)</option>
                <option value="CR">\r (CR)</option>
              </select>

              <!-- 定时自动循环发送 -->
              <div class="flex items-center gap-1 pl-2 border-l border-slate-200/80 dark:border-white/10">
                <label class="flex items-center gap-1 text-slate-600 dark:text-slate-300 cursor-pointer select-none">
                  <input type="checkbox" v-model="autoRepeat" @change="toggleAutoRepeat" class="accent-sky-500 rounded" />
                  <span class="text-[10px] font-bold">自动轮发</span>
                </label>
                <input v-model.number="repeatIntervalMs" type="number" min="50" max="60000" class="w-14 px-1 py-0.5 text-[10px] font-mono border rounded bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-100 text-center" />
                <span class="text-[10px] text-slate-400">ms</span>
              </div>
            </div>
          </div>

          <!-- 发送文本域与操作区 -->
          <div class="flex-1 flex p-2 gap-2 min-h-0">
            <div class="flex-1 flex flex-col relative min-h-0">
              <textarea
                v-model="txPayload"
                :placeholder="txFormat === 'HEX' ? '输入待发送的十六进制字节流，如: 01 03 00 00 00 02 (支持自动格式整理)' : '输入待发送的 ASCII 文本字符内容...'"
                class="flex-1 w-full bg-white/70 dark:bg-black/30 border rounded-xl p-2 font-mono text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500/30 resize-none transition-colors"
                :class="hexValidation.valid ? 'border-slate-300/80 dark:border-white/10' : 'border-rose-400 ring-1 ring-rose-400/30'"
                @keydown.ctrl.enter="sendPayload"
              />
              
              <!-- 底部状态指示条 (HEX 有效性、字节数与动态校验和预知) -->
              <div class="flex items-center justify-between px-2 py-1 text-[10px] font-mono text-slate-500 dark:text-slate-400 bg-slate-50/80 dark:bg-slate-900/40 rounded-b-xl border-t border-slate-200/50 dark:border-white/5">
                <div class="flex items-center gap-2">
                  <span v-if="txFormat === 'HEX'" :class="hexValidation.valid ? 'text-emerald-700 dark:text-emerald-400' : 'text-rose-600 font-bold'">
                    {{ hexValidation.message }}
                  </span>
                  <span v-else class="text-slate-600 dark:text-slate-300">
                    字符长度: {{ txPayload.length }} 字符
                  </span>
                  
                  <!-- 动态校验和预知微胶囊 -->
                  <span v-if="previewChecksum && appendChecksum !== 'NONE'" class="px-1.5 py-0.2 rounded bg-amber-100 text-amber-900 border border-amber-300 font-bold text-[9px]">
                    + {{ appendChecksum }}: [{{ previewChecksum }}]
                  </span>
                </div>

                <!-- 历史快速选用下拉 -->
                <div v-if="txHistoryList.length > 0" class="flex items-center gap-1">
                  <span>历史:</span>
                  <select @change="txPayload = ($event.target as HTMLSelectElement).value" class="bg-transparent text-slate-700 dark:text-slate-300 text-[10px] outline-none max-w-[120px] truncate cursor-pointer">
                    <option value="">-- 最近发送 --</option>
                    <option v-for="(h, idx) in txHistoryList" :key="idx" :value="h">{{ h }}</option>
                  </select>
                </div>
              </div>
            </div>

            <!-- 右侧动作按钮列 -->
            <div class="flex flex-col gap-1.5 w-24 shrink-0">
              <button
                @click="sendPayload"
                :disabled="!isRunning || !txPayload.trim() || (txFormat === 'HEX' && !hexValidation.valid)"
                class="flex-1 rounded-xl bg-gradient-to-tr from-sky-500 to-indigo-600 hover:from-sky-600 hover:to-indigo-700 text-white font-bold text-xs shadow-sm transition-all flex flex-col items-center justify-center gap-0.5 cursor-pointer disabled:opacity-40 active:scale-95"
              >
                <span>立即发送</span>
                <span class="text-[9px] font-normal opacity-80">(Ctrl+Enter)</span>
              </button>
              
              <button
                v-if="txFormat === 'HEX'"
                @click="formatTxHex"
                class="py-1 text-[10px] text-slate-600 dark:text-slate-300 hover:text-sky-600 glass-pill rounded-lg cursor-pointer font-mono"
                title="自动将十六进制字节按空格规范对齐"
              >
                整理格式
              </button>

              <button @click="txPayload = ''" class="py-1 text-[10px] text-slate-400 hover:text-rose-500 glass-pill rounded-lg cursor-pointer">
                清空输入
              </button>
            </div>
          </div>
        </div>
      </main>

      <!-- 3. 右栏：工控规约载荷模板与快捷多指令调度矩阵 (3 列) -->
      <aside class="col-span-3 glass-surface rounded-2xl p-3.5 flex flex-col gap-3 overflow-y-auto custom-scrollbar border border-slate-200/80 dark:border-white/10 shadow-sm">
        
        <!-- 标准工控协议模板一键加载 -->
        <div>
          <label class="text-[10px] font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider block mb-1.5 font-mono">标准工控规约载荷模板</label>
          <select @change="applyProtocolPreset(($event.target as HTMLSelectElement).value); ($event.target as HTMLSelectElement).value = ''" class="form-input-box text-[11px] font-mono">
            <option value="">-- 一键填入工业标准载荷 --</option>
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

        <!-- 预设多指令快捷调度列表 (Preset Command Matrix) -->
        <div class="flex-1 flex flex-col min-h-0 border-t border-slate-200/60 dark:border-white/10 pt-2.5">
          <div class="flex items-center justify-between mb-1.5">
            <div class="flex items-center gap-1.5">
              <span class="text-[10px] font-bold text-slate-700 dark:text-slate-300 uppercase font-mono">多指令快捷调度矩阵</span>
              <span class="text-[9px] text-slate-400">({{ presetCommands.length }})</span>
            </div>
            <button @click="addNewPreset" class="text-[10px] text-sky-700 dark:text-sky-400 font-bold hover:underline cursor-pointer">
              + 添加指令
            </button>
          </div>

          <!-- 全量指令循环轮发控制器 (Sequence Poller) -->
          <div class="glass-pill p-2 rounded-xl mb-2 border border-slate-200/80 dark:border-white/10 flex items-center justify-between">
            <div class="flex items-center gap-1.5">
              <button
                @click="toggleSequencePoller"
                :class="['px-2 py-1 rounded-lg text-[10px] font-bold cursor-pointer transition-colors flex items-center gap-1',
                  isSequencePolling
                    ? 'bg-rose-600 text-white'
                    : 'bg-gradient-to-r from-sky-500 to-indigo-600 text-white']"
                :disabled="!isRunning || presetCommands.length === 0"
              >
                <span>{{ isSequencePolling ? '■ 停止轮发' : '⚡ 序列轮发' }}</span>
              </button>
              <span class="text-[10px] text-slate-500 font-mono">步长:</span>
              <input v-model.number="sequenceIntervalMs" type="number" min="100" max="10000" class="w-12 px-1 text-[10px] font-mono border rounded bg-white dark:bg-slate-800 text-center" />
              <span class="text-[10px] text-slate-400 font-mono">ms</span>
            </div>
            <span v-if="isSequencePolling" class="text-[9px] font-bold text-emerald-600 animate-pulse font-mono">
              发送中 #{{ activeSequenceIdx + 1 }}
            </span>
          </div>

          <!-- 指令卡片列表 -->
          <div class="flex-1 overflow-y-auto custom-scrollbar space-y-1.5 pr-0.5">
            <div
              v-for="(cmd, idx) in presetCommands"
              :key="idx"
              class="glass-pill rounded-xl p-2 text-xs font-mono space-y-1 border transition-all"
              :class="isSequencePolling && activeSequenceIdx === idx
                ? 'border-sky-500 ring-2 ring-sky-500/20 bg-sky-50/50'
                : 'border-slate-200/60 dark:border-white/10'"
            >
              <div class="flex items-center justify-between text-[10px]">
                <input v-model="cmd.name" @change="savePresetsToStorage" class="font-bold text-slate-800 dark:text-slate-100 bg-transparent border-b border-transparent focus:border-sky-400 outline-none w-32" />
                <div class="flex items-center gap-1">
                  <button @click="sendSpecificPreset(cmd)" :disabled="!isRunning" class="px-2 py-0.5 bg-sky-600 hover:bg-sky-700 text-white rounded text-[9px] font-bold cursor-pointer disabled:opacity-40">
                    发送
                  </button>
                  <button @click="deletePreset(idx)" class="text-slate-400 hover:text-rose-500 text-[10px] px-1 cursor-pointer" title="删除该指令">
                    ✕
                  </button>
                </div>
              </div>
              <input v-model="cmd.payload" @change="savePresetsToStorage" placeholder="HEX 字节流" class="w-full bg-white/90 dark:bg-black/40 border border-slate-200/80 dark:border-white/10 rounded px-1.5 py-0.5 text-[10px] text-slate-800 dark:text-slate-200 font-mono" />
            </div>
          </div>
        </div>

      </aside>

    </div>

    <!-- 全景报文深度解构模态框 (与 Omni-Probe 探针核心完全打通) -->
    <PacketDetailModal
      :is-open="isDetailModalOpen"
      :packet="modalPacket"
      @close="isDetailModalOpen = false"
    />

  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, nextTick } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import {
  notifySuccess,
  notifyInfo,
  notifyWarning,
  notifyError,
} from '../composables/useNotification';
import PacketDetailModal from '../components/PacketDetailModal.vue';
interface PacketRecord {
  id: number;
  timestamp: string;
  timestamp_ns?: number;
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
  entropy_level: string;
  mac_src: string;
  mac_dst: string;
  chain_hash: string;
  business_data?: Record<string, any>;
  raw_text?: string;
}

defineEmits(['switchWorkbench']);

interface ProtocolModeOption {
  id: 'TCP_CLIENT' | 'TCP_SERVER' | 'UDP';
  label: string;
}

const protocolModes: ProtocolModeOption[] = [
  { id: 'TCP_CLIENT', label: 'TCP 客户端' },
  { id: 'TCP_SERVER', label: 'TCP 服务端' },
  { id: 'UDP', label: 'UDP 模式' },
];

const quickPorts = [
  { port: 502, label: 'Modbus', desc: '工业 Modbus-TCP 标准通信端口' },
  { port: 102, label: 'S7', desc: '西门子 S7Comm PLC 通信端口' },
  { port: 2404, label: '104', desc: '电力调度 IEC 60870-5-104 端口' },
  { port: 1883, label: 'MQTT', desc: '物联网 MQTT 消息代理端口' },
  { port: 80, label: 'HTTP', desc: '标准超文本通信端口' },
  { port: 8080, label: 'Web', desc: '常用开发与嵌入式 Web 端口' },
  { port: 44818, label: 'ENIP', desc: '罗克韦尔 EtherNet/IP 工业端口' },
];

interface LocalIpInfo {
  ip: string;
  name: string;
  is_loopback: boolean;
}

const selectedMode = ref<'TCP_CLIENT' | 'TCP_SERVER' | 'UDP'>('TCP_CLIENT');
const isRunning = ref(false);
const sessionStatus = ref('就绪');

// 配置参数
const targetIp = ref('127.0.0.1');
const targetPort = ref(8080);
const localBindIp = ref('0.0.0.0');
const localBindPort = ref(8080);
const localIpList = ref<LocalIpInfo[]>([
  { ip: '0.0.0.0', name: '0.0.0.0 (全部本地网卡 / Any)', is_loopback: false },
  { ip: '127.0.0.1', name: '127.0.0.1 (本地回环 / Loopback)', is_loopback: true },
]);
const frameTimeoutMs = ref(25);
const activeClients = ref<string[]>([]);
const selectedClientTarget = ref('');

// 收发控制与日志
const rxFormat = ref<'HEX' | 'ASCII'>('HEX');
const txFormat = ref<'HEX' | 'ASCII'>('HEX');
const showTimestamp = ref(true);
const autoScroll = ref(true);
const isRxPaused = ref(false);
const rxSearchQuery = ref('');
const appendChecksum = ref('NONE');
const newlineType = ref<'NONE' | 'CRLF' | 'LF' | 'CR'>('NONE');
const autoRepeat = ref(false);
const repeatIntervalMs = ref(1000);
const txPayload = ref('01 03 00 00 00 02');
const previewChecksum = ref('');
const txHistoryList = ref<string[]>([]);

// 序列轮发
const isSequencePolling = ref(false);
const sequenceIntervalMs = ref(500);
const activeSequenceIdx = ref(0);
let sequenceTimer: any = null;

interface PacketLogItem {
  id: string;
  direction: 'TX' | 'RX';
  mode: string;
  local_addr: string;
  remote_addr: string;
  length: number;
  payload_hex: string;
  payload_text: string;
  timestamp_ms: number;
}

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

// 报文解构弹窗状态
const isDetailModalOpen = ref(false);
const modalPacket = ref<PacketRecord | null>(null);

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

// 过滤接收日志
const filteredPacketLog = computed(() => {
  const query = rxSearchQuery.value.trim().toLowerCase();
  if (!query) return packetLog.value;
  return packetLog.value.filter(p =>
    p.payload_hex.toLowerCase().includes(query) ||
    p.payload_text.toLowerCase().includes(query) ||
    p.remote_addr.toLowerCase().includes(query)
  );
});

// HEX 输入实时校验计算
const hexValidation = computed(() => {
  if (txFormat.value !== 'HEX') {
    return { valid: true, message: 'ASCII 文本模式' };
  }
  const clean = txPayload.value.replace(/\s+/g, '');
  if (!clean) {
    return { valid: true, message: '待输入数据' };
  }
  if (!/^[0-9a-fA-F]*$/.test(clean)) {
    return { valid: false, message: '存在非十六进制字符 (合法范围: 0-9, A-F)' };
  }
  if (clean.length % 2 !== 0) {
    return { valid: false, message: '半字节缺失 (当前为奇数个字符)' };
  }
  const bytesCount = clean.length / 2;
  return { valid: true, message: `有效载荷: ${bytesCount} 字节` };
});

// 监听并动态预计算即将追加的校验和
watch([txPayload, appendChecksum, txFormat], async () => {
  if (appendChecksum.value === 'NONE' || txFormat.value !== 'HEX') {
    previewChecksum.value = '';
    return;
  }
  const clean = txPayload.value.replace(/\s+/g, '');
  if (!clean || !/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) {
    previewChecksum.value = '';
    return;
  }
  try {
    const res = await invoke<string>('calculate_checksum_cmd', {
      payloadHex: clean,
      algo: appendChecksum.value,
    });
    previewChecksum.value = res;
  } catch {
    previewChecksum.value = '';
  }
}, { immediate: true });

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

function formatTxHex() {
  const clean = txPayload.value.replace(/\s+/g, '');
  if (/^[0-9a-fA-F]*$/.test(clean)) {
    txPayload.value = formatHexSpaced(clean).toUpperCase();
  }
}

function copyText(str: string) {
  if (!str) return;
  navigator.clipboard.writeText(str).then(() => {
    notifySuccess('已复制至剪贴板', str.length > 30 ? `${str.slice(0, 30)}...` : str);
  });
}

function fillTxInput(hexStr: string) {
  txPayload.value = formatHexSpaced(hexStr);
  txFormat.value = 'HEX';
  notifyInfo('已载入发送输入区', '可直接修改后执行回显或反向发送');
}

function resetStats() {
  stats.value = { rxBytes: 0, rxPackets: 0, txBytes: 0, txPackets: 0 };
  notifyInfo('通信统计已复位', 'RX/TX 吞吐与帧计数器已归零');
}

async function loadLocalIpAddresses() {
  try {
    const ips = await invoke<LocalIpInfo[]>('get_local_ip_addresses_cmd');
    if (ips && ips.length > 0) {
      localIpList.value = ips;
      if (ips.some(i => i.ip !== '0.0.0.0' && i.ip !== '127.0.0.1')) {
        const primary = ips.find(i => i.name.includes('默认主通信') || (!i.is_loopback && i.ip !== '0.0.0.0'));
        if (primary && localBindIp.value === '0.0.0.0') {
          localBindIp.value = primary.ip;
        }
      }
    }
  } catch (e) {
    console.error('获取本机网卡失败:', e);
  }
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
      if (sequenceTimer) {
        clearInterval(sequenceTimer);
        sequenceTimer = null;
        isSequencePolling.value = false;
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

  // 1. 如果是 ASCII 模式，根据换行规则转为 HEX
  let hexToSend = '';
  if (txFormat.value === 'ASCII') {
    if (newlineType.value === 'CRLF') raw += '\r\n';
    else if (newlineType.value === 'LF') raw += '\n';
    else if (newlineType.value === 'CR') raw += '\r';

    const encoder = new TextEncoder();
    const bytes = encoder.encode(raw);
    hexToSend = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  } else {
    hexToSend = raw.replace(/\s+/g, '');
    if (newlineType.value === 'CRLF') hexToSend += '0D0A';
    else if (newlineType.value === 'LF') hexToSend += '0A';
    else if (newlineType.value === 'CR') hexToSend += '0D';
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

    // 记录历史
    const cleanPayload = txPayload.value.trim();
    if (!txHistoryList.value.includes(cleanPayload)) {
      txHistoryList.value.unshift(cleanPayload);
      if (txHistoryList.value.length > 10) txHistoryList.value.pop();
      try {
        localStorage.setItem('omni_probe_net_assist_tx_history_v1', JSON.stringify(txHistoryList.value));
      } catch {}
    }
  } catch (e) {
    notifyError('发送数据受阻', e);
  }
}

function sendSpecificPreset(preset: PresetCommand) {
  txPayload.value = preset.payload;
  txFormat.value = 'HEX';
  sendPayload();
}

function addNewPreset() {
  presetCommands.value.push({
    name: `自定义指令 ${presetCommands.value.length + 1}`,
    payload: '01 03 00 00 00 01',
  });
  savePresetsToStorage();
}

function deletePreset(idx: number) {
  presetCommands.value.splice(idx, 1);
  savePresetsToStorage();
}

function savePresetsToStorage() {
  try {
    localStorage.setItem('omni_probe_net_assist_presets_v1', JSON.stringify(presetCommands.value));
  } catch {}
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

function toggleSequencePoller() {
  if (isSequencePolling.value) {
    if (sequenceTimer) {
      clearInterval(sequenceTimer);
      sequenceTimer = null;
    }
    isSequencePolling.value = false;
    notifyInfo('指令序列轮发已终止', '已暂停周期多从站轮询');
  } else {
    if (!isRunning.value) {
      notifyWarning('会话未建立', '请先启动网络调试会话后再执行序列轮发');
      return;
    }
    if (presetCommands.value.length === 0) {
      notifyWarning('无预置指令', '请先在右侧添加至少一条待发送指令');
      return;
    }
    isSequencePolling.value = true;
    activeSequenceIdx.value = 0;
    
    // 执行首发
    sendSpecificPreset(presetCommands.value[0]);

    sequenceTimer = setInterval(() => {
      activeSequenceIdx.value = (activeSequenceIdx.value + 1) % presetCommands.value.length;
      const cmd = presetCommands.value[activeSequenceIdx.value];
      if (cmd) {
        sendSpecificPreset(cmd);
      }
    }, Math.max(100, sequenceIntervalMs.value));

    notifySuccess('多指令序列轮发已启动', `步长间隔: ${sequenceIntervalMs.value} ms`);
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
  notifyInfo('工控规约模板已载入', `已将 ${type} 报文载入发送终端`);
}

function exportLog() {
  if (packetLog.value.length === 0) {
    notifyWarning('导出提示', '当前无数据记录可供导出');
    return;
  }
  const lines = packetLog.value.map(p => {
    return `[${formatTime(p.timestamp_ms)}] [${p.direction}] ${p.remote_addr} (${p.length} Bytes)\nHEX: ${p.payload_hex}\nTXT: ${p.payload_text}\n`;
  });
  const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `OmniProbe_NetAssist_Log_${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
  notifySuccess('通信日志导出成功', '已生成纯文本日志文件并已启动下载');
}

// 在全景报文分析模态框中解构此报文
function inspectPacketInModal(item: PacketLogItem) {
  const [remIp, remPortStr] = item.remote_addr.split(':');
  const [locIp, locPortStr] = item.local_addr.split(':');
  const remPort = parseInt(remPortStr || '0', 10);
  const locPort = parseInt(locPortStr || '0', 10);

  modalPacket.value = {
    id: parseInt(item.id.replace(/\D/g, '') || '1', 10),
    timestamp: formatTime(item.timestamp_ms),
    src_ip: item.direction === 'TX' ? (locIp || '127.0.0.1') : (remIp || '127.0.0.1'),
    src_port: item.direction === 'TX' ? locPort : remPort,
    dst_ip: item.direction === 'TX' ? (remIp || '127.0.0.1') : (locIp || '127.0.0.1'),
    dst_port: item.direction === 'TX' ? remPort : locPort,
    protocol: item.mode.includes('TCP') ? 'TCP' : 'UDP',
    length: item.length,
    direction: item.direction === 'RX' ? 'PASSIVE_RECV' : 'ACTIVE_PULL',
    transport: item.mode.includes('TCP') ? 'TCP' : 'UDP',
    payload_hex: item.payload_hex,
    raw_text: item.payload_text,
    entropy: 4.5,
    entropy_level: 'normal',
    mac_src: '00:1B:21:A4:B0:12',
    mac_dst: '00:50:56:C0:00:08',
    chain_hash: 'NET_ASSIST_GENESIS_CHAIN',
    business_data: undefined,
  };
  isDetailModalOpen.value = true;
}

onMounted(async () => {
  // 加载本机网卡列表
  await loadLocalIpAddresses();

  // 读取持久化预设与历史
  try {
    const savedPresets = localStorage.getItem('omni_probe_net_assist_presets_v1');
    if (savedPresets) {
      const parsed = JSON.parse(savedPresets);
      if (Array.isArray(parsed) && parsed.length > 0) {
        presetCommands.value = parsed;
      }
    }
    const savedHistory = localStorage.getItem('omni_probe_net_assist_tx_history_v1');
    if (savedHistory) {
      const parsedHistory = JSON.parse(savedHistory);
      if (Array.isArray(parsedHistory)) {
        txHistoryList.value = parsedHistory;
      }
    }

    // 检查是否有来自流量大盘右键推送的载荷
    const incoming = localStorage.getItem('omni_probe_net_assist_incoming_payload');
    if (incoming) {
      txPayload.value = formatHexSpaced(incoming);
      txFormat.value = 'HEX';
      localStorage.removeItem('omni_probe_net_assist_incoming_payload');
      notifyInfo('已载入待测报文载荷', '来自全息流量分析大盘的快捷推送');
    }
  } catch {}

  // 监听数据包事件
  unlistenPacket = await listen<PacketLogItem>('net-assist-packet', (event) => {
    const p = event.payload;
    if (p.direction === 'RX') {
      stats.value.rxBytes += p.length;
      stats.value.rxPackets += 1;
    }
    
    // 如果未暂停，追加上屏
    if (!isRxPaused.value) {
      packetLog.value.push(p);
      if (packetLog.value.length > 5000) {
        packetLog.value.shift();
      }
      if (autoScroll.value) {
        nextTick(() => {
          if (rxScrollContainer.value) {
            rxScrollContainer.value.scrollTop = rxScrollContainer.value.scrollHeight;
          }
        });
      }
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
      if (sequenceTimer) {
        clearInterval(sequenceTimer);
        sequenceTimer = null;
        isSequencePolling.value = false;
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
  if (sequenceTimer) clearInterval(sequenceTimer);
});
</script>

<style scoped>
.form-input-box {
  width: 100%;
  background: rgba(255, 255, 255, 0.85);
  border: 1px solid rgba(203, 213, 225, 0.8);
  border-radius: 0.75rem;
  padding: 0.35rem 0.65rem;
  font-size: 0.75rem;
  color: #0f172a;
  outline: none;
  transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
}

:global(.theme-apple-dark) .form-input-box {
  background: rgba(15, 23, 42, 0.8);
  border-color: rgba(255, 255, 255, 0.15);
  color: #f8fafc;
}

.form-input-box:focus {
  border-color: rgba(14, 165, 233, 0.7);
  box-shadow: 0 0 0 2px rgba(14, 165, 233, 0.15);
}
</style>
