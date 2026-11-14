<template>
  <div class="h-full w-full flex flex-col overflow-hidden gap-2.5 select-none font-sans">
    
    <!-- 顶栏：工作台标识、运行态指示与统计概览 (Liquid Glass 浮动导航层) -->
    <header class="ui-nav-glass rounded-2xl px-4 py-2.5 flex items-center justify-between shrink-0 flex-wrap gap-2">
      <span class="lens-edge-lip" aria-hidden="true"></span>
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 rounded-xl bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)] border border-[var(--accent-primary)]/20 flex items-center justify-center shrink-0">
          <AppIcon name="terminal" :size="16" />
        </div>
        <div>
          <div class="flex items-center gap-2">
            <h2 class="text-[13px] font-bold tracking-tight" style="color: var(--text-primary)">
              工业级全双工网络调试助手
            </h2>
            <span class="px-2 py-0.5 rounded-full text-[11px] font-semibold flex items-center gap-1.5 border ui-num"
              :class="isRunning
                ? 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                : 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/20'">
              <span class="w-1.5 h-1.5 rounded-full shrink-0"
                :class="isRunning ? 'bg-emerald-500' : 'bg-slate-400'"></span>
              <span>{{ isRunning ? `会话运行中: ${sessionStatus}` : '会话待命 (IDLE)' }}</span>
            </span>
          </div>
          <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">
            全双工异步通信 · TCP 客户端/服务端 · UDP 单播/广播/组播 · 帧超时断包 · 工业规约双向校验
          </p>
        </div>
      </div>

      <!-- 右侧快速统计概览与联动按钮 -->
      <div class="flex items-center gap-2.5 text-xs ui-num">
        <!-- 统计胶囊 -->
        <div class="flex items-center gap-2.5 ui-pill px-3 py-1 rounded-xl text-[11px]">
          <span style="color: var(--text-muted)">RX:</span>
          <span class="font-bold text-emerald-700 dark:text-emerald-400">{{ formatBytes(stats.rxBytes) }} ({{ stats.rxPackets }} 帧)</span>
          <span style="color: var(--border-strong)">|</span>
          <span style="color: var(--text-muted)">TX:</span>
          <span class="font-bold text-sky-700 dark:text-sky-400">{{ formatBytes(stats.txBytes) }} ({{ stats.txPackets }} 帧)</span>
        </div>

        <button @click="resetStats" class="ui-pill p-1.5 rounded-xl cursor-pointer" title="复位收发统计">
          <AppIcon name="refresh" :size="14" />
        </button>

        <button @click="$emit('switchWorkbench', 'traffic')" class="ui-pill px-2.5 py-1 rounded-xl text-[11px] font-semibold flex items-center gap-1.5 cursor-pointer" style="color: var(--accent-primary-text)" title="前往流量分析看板">
          <AppIcon name="traffic" :size="13" />
          <span>流量分析看板</span>
          <AppIcon name="arrow-right" :size="11" />
        </button>
      </div>
    </header>

    <!-- 主工作区：三栏布局 (左控制 / 中收发终端 / 右工控模板与多指令矩阵) -->
    <div class="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-2.5 min-h-0">
      
      <!-- 1. 左栏：协议模式与套接字控制面板 (3 列) -->
      <aside class="lg:col-span-3 ui-content-card p-3.5 flex flex-col gap-3 overflow-y-auto custom-scrollbar">
        
        <!-- 协议模式切换胶囊 -->
        <div>
          <label class="text-[11px] font-bold uppercase tracking-wider block mb-1.5" style="color: var(--text-secondary)">通信规约模式</label>
          <div class="grid grid-cols-3 gap-1 ui-pill p-0.5 rounded-xl">
            <button
              v-for="m in protocolModes"
              :key="m.id"
              @click="!isRunning && (selectedMode = m.id)"
              :disabled="isRunning"
              :class="['py-1 rounded-lg text-xs font-semibold transition-colors cursor-pointer text-center',
                selectedMode === m.id
                  ? 'bg-sky-500/18 text-sky-700 dark:text-sky-300 border border-sky-500/35'
                  : 'hover:bg-black/5 dark:hover:bg-white/5',
                isRunning ? 'opacity-50 cursor-not-allowed' : '']"
              :style="selectedMode !== m.id ? { color: 'var(--text-secondary)' } : undefined"
            >
              {{ m.label }}
            </button>
          </div>
        </div>

        <!-- 参数配置表单 -->
        <div class="space-y-2.5 text-xs">
          <!-- TCP Client 参数 -->
          <template v-if="selectedMode === 'TCP_CLIENT'">
            <div>
              <div class="flex items-center justify-between mb-1">
                <label class="text-[11px] font-semibold" style="color: var(--text-secondary)">目标远端 IP (Host)</label>
                <div class="flex items-center gap-1.5 text-[11px] ui-num cursor-pointer" style="color: var(--accent-primary-text)">
                  <span @click="targetIp = '127.0.0.1'" class="hover:underline">127.0.0.1</span>
                  <span style="color: var(--text-muted)">·</span>
                  <span @click="targetIp = '192.168.1.100'" class="hover:underline">192.168.1.100</span>
                </div>
              </div>
              <input v-model="targetIp" :disabled="isRunning" placeholder="127.0.0.1" class="ui-input ui-num" />
            </div>

            <div>
              <div class="flex items-center justify-between mb-1">
                <label class="text-[11px] font-semibold" style="color: var(--text-secondary)">目标服务端口 (Port)</label>
                <span class="text-[11px]" style="color: var(--text-muted)">标准工控/Web</span>
              </div>
              <input v-model.number="targetPort" :disabled="isRunning" type="number" placeholder="8080" class="ui-input ui-num mb-1.5" />
              <!-- 快捷端口一键填入微胶囊 -->
              <div class="flex flex-wrap gap-1">
                <button
                  v-for="p in quickPorts"
                  :key="p.port"
                  @click="!isRunning && (targetPort = p.port)"
                  :disabled="isRunning"
                  class="px-2 py-0.5 rounded text-[11px] font-medium glass-pill hover:border-blue-500 text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer transition-colors"
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
                <label class="text-[11px] font-semibold" style="color: var(--text-secondary);">本地监听网卡与 IP</label>
                <button @click="loadLocalIpAddresses" class="text-[11px] text-blue-600 dark:text-sky-400 hover:underline cursor-pointer flex items-center gap-1" title="刷新本机网卡列表">
                  <AppIcon name="refresh" :size="11" />
                  <span>刷新网卡</span>
                </button>
              </div>
              <select v-model="localBindIp" :disabled="isRunning" class="ui-input w-full px-2.5 py-1.5 font-mono mb-1.5 text-xs">
                <option v-for="ipInfo in localIpList" :key="ipInfo.ip" :value="ipInfo.ip">{{ ipInfo.name }}</option>
              </select>
              <input v-model="localBindIp" :disabled="isRunning" placeholder="0.0.0.0" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono" title="或自由手动编辑 IP" />
            </div>

            <div>
              <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-secondary);">本地监听端口</label>
              <input v-model.number="localBindPort" :disabled="isRunning" type="number" placeholder="8080" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono ui-num mb-1.5" />
              <div class="flex flex-wrap gap-1">
                <button
                  v-for="p in quickPorts"
                  :key="p.port"
                  @click="!isRunning && (localBindPort = p.port)"
                  :disabled="isRunning"
                  class="px-2 py-0.5 rounded text-[11px] font-medium glass-pill hover:border-blue-500 text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer transition-colors"
                  :title="p.desc"
                >
                  {{ p.port }} {{ p.label }}
                </button>
              </div>
            </div>

            <div class="pt-1.5 border-t" style="border-color: var(--border-subtle);">
              <div class="flex items-center justify-between mb-1">
                <label class="text-[11px] font-semibold" style="color: var(--text-secondary);">活动客户端连接池</label>
                <span
                  class="text-[11px] font-semibold px-2 py-0.5 rounded-full ui-num"
                  :class="activeClients.length > 0 ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'ui-pill'"
                >
                  {{ activeClients.length }} 在线
                </span>
              </div>
              <select v-model="selectedClientTarget" class="ui-input w-full px-2.5 py-1.5 font-mono text-xs">
                <option value="">-- [广播群发] 全部在线客户端 --</option>
                <option v-for="c in activeClients" :key="c" :value="c">指定端点: {{ c }}</option>
              </select>
            </div>
          </template>

          <!-- UDP 模式参数 -->
          <template v-else-if="selectedMode === 'UDP'">
            <div class="grid grid-cols-2 gap-1.5">
              <div>
                <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-secondary);">本地绑定端口</label>
                <input v-model.number="localBindPort" :disabled="isRunning" type="number" placeholder="0 (随机)" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono ui-num" />
              </div>
              <div>
                <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-secondary);">目标远端端口</label>
                <input v-model.number="targetPort" placeholder="8080" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono ui-num" />
              </div>
            </div>
            <div>
              <div class="flex items-center justify-between mb-1">
                <label class="text-[11px] font-semibold" style="color: var(--text-secondary);">目标主机 IP</label>
                <span class="text-[11px] text-blue-600 dark:text-sky-400 cursor-pointer hover:underline" @click="targetIp = '255.255.255.255'">广播 255.255.255.255</span>
              </div>
              <input v-model="targetIp" placeholder="127.0.0.1 或 255.255.255.255" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono" />
            </div>
          </template>

          <!-- 帧断包超时阈值 -->
          <div class="pt-1.5 border-t" style="border-color: var(--border-subtle);">
            <div class="flex items-center justify-between mb-1">
              <label class="text-[11px] font-semibold" style="color: var(--text-secondary);">帧间隔断包切分阈值</label>
              <span class="text-[11px] font-semibold text-blue-600 dark:text-sky-400 ui-num">{{ frameTimeoutMs }} ms</span>
            </div>
            <input v-model.number="frameTimeoutMs" :disabled="isRunning" type="range" min="5" max="200" step="5" class="w-full accent-blue-600 cursor-pointer" />
            <p class="text-[11px] mt-0.5 leading-tight" style="color: var(--text-muted);">碎片数据接收间隔超过该时长，自动定界为完整规约帧上屏</p>
          </div>
        </div>

        <!-- 会话启停按钮 -->
        <div class="mt-auto pt-2">
          <button
            @click="toggleSession"
            :class="['w-full py-2.5 rounded-xl font-semibold text-xs transition-all active:scale-95 cursor-pointer flex items-center justify-center gap-2',
              isRunning ? 'bg-rose-600 hover:bg-rose-500 text-white' : 'ui-btn-primary justify-center']"
          >
            <AppIcon :name="isRunning ? 'stop' : 'play'" :size="13" />
            <span>{{ isRunning ? '停止会话并释放套接字' : '启动并建立通信套接字' }}</span>
          </button>
        </div>
      </aside>

      <!-- 2. 中栏：全双工终端核心区 (6 列) -->
      <main class="lg:col-span-6 flex flex-col gap-2.5 min-h-0">
        <!-- 上部：数据接收终端 (RX Terminal - 实体衬底) -->
        <div class="flex-1 ui-content-card flex flex-col overflow-hidden min-h-0">
          <div class="px-3.5 py-2 border-b flex items-center justify-between text-xs shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle);">
            <div class="flex items-center gap-2.5">
              <span class="font-semibold flex items-center gap-1.5" style="color: var(--text-primary);">
                <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                <span>数据接收终端 (RX)</span>
                <span class="text-[11px] ui-num" style="color: var(--text-muted);">[{{ filteredPacketLog.length }} / {{ packetLog.length }} 帧]</span>
              </span>
              <div class="flex items-center glass-pill p-0.5 rounded-lg text-[11px] font-mono">
                <button @click="rxFormat = 'HEX'" :class="['px-2 py-0.5 rounded-md transition-all font-semibold cursor-pointer', rxFormat === 'HEX' ? 'bg-blue-600 text-white' : 'text-[var(--text-secondary)]']">HEX</button>
                <button @click="rxFormat = 'ASCII'" :class="['px-2 py-0.5 rounded-md transition-all font-semibold cursor-pointer', rxFormat === 'ASCII' ? 'bg-blue-600 text-white' : 'text-[var(--text-secondary)]']">ASCII</button>
              </div>
            </div>

            <div class="flex items-center gap-2 text-[11px] flex-wrap" style="color: var(--text-secondary);">
              <div class="flex items-center gap-1 px-2 py-0.5 rounded-lg border text-[11px]" style="background: var(--surface-input); border-color: var(--border-subtle);">
                <AppIcon name="search" :size="11" style="color: var(--text-muted);" />
                <input v-model="rxSearchQuery" placeholder="过滤关键字 / HEX..." class="bg-transparent outline-none w-24 text-[11px] font-mono" style="color: var(--text-primary);" />
                <button v-if="rxSearchQuery" @click="rxSearchQuery = ''" class="cursor-pointer" style="color: var(--text-muted);">
                  <AppIcon name="close" :size="11" />
                </button>
              </div>

              <label class="flex items-center gap-1 cursor-pointer select-none">
                <input type="checkbox" v-model="showTimestamp" class="accent-blue-600 rounded" />
                <span>时标</span>
              </label>

              <label class="flex items-center gap-1 cursor-pointer select-none">
                <input type="checkbox" v-model="autoScroll" class="accent-blue-600 rounded" />
                <span>滚屏</span>
              </label>

              <button
                @click="isRxPaused = !isRxPaused"
                :class="['px-2 py-0.5 rounded-lg text-[11px] font-semibold border cursor-pointer transition-colors flex items-center gap-1',
                  isRxPaused ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30' : 'ui-pill']"
              >
                <AppIcon :name="isRxPaused ? 'pause' : 'play'" :size="10" />
                <span>{{ isRxPaused ? '已暂停' : '接收中' }}</span>
              </button>

              <button @click="packetLog = []" class="ui-btn-secondary px-2 py-0.5 text-[11px]">清屏</button>
              <button @click="diffBus.openScratchpad()" class="ui-btn-secondary px-2 py-0.5 text-[11px] text-indigo-600 dark:text-indigo-300" title="打开自由数据差分工作台">
                <AppIcon name="scale" :size="11" />
                <span>比对</span>
              </button>
              <button @click="exportLog" class="ui-btn-secondary px-2 py-0.5 text-[11px]">导出</button>
            </div>
          </div>

          <div ref="rxScrollContainer" class="flex-1 overflow-y-auto custom-scrollbar p-2.5 space-y-1.5 font-mono text-xs select-text" style="background: var(--surface-content-alt);">
            <div
              v-for="item in filteredPacketLog"
              :key="item.id"
              class="group relative p-2.5 rounded-xl border transition-all text-xs"
              :class="item.direction === 'RX'
                ? 'bg-emerald-500/8 border-emerald-500/25'
                : 'bg-blue-500/8 border-blue-500/25'"
            >
              <div class="flex items-center justify-between text-[11px] mb-1 border-b pb-1 flex-wrap gap-1" style="border-color: var(--border-subtle); color: var(--text-muted);">
                <div class="flex items-center gap-1.5">
                  <span
                    class="px-1.5 py-0.5 rounded font-semibold uppercase text-[11px]"
                    :class="item.direction === 'RX' ? 'bg-emerald-600 text-white' : 'bg-blue-600 text-white'"
                  >
                    {{ item.direction }}
                  </span>
                  <span class="font-semibold ui-num" style="color: var(--text-primary);">{{ item.remote_addr }}</span>
                  <span class="ui-num">({{ item.length }} B)</span>
                </div>
                <div class="flex items-center gap-1.5">
                  <span v-if="showTimestamp" class="ui-num">{{ formatTime(item.timestamp_ms) }}</span>

                  <div class="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1">
                    <button @click="copyText(item.payload_hex)" class="ui-pill px-1.5 py-0.5 text-[11px] cursor-pointer" title="复制 HEX">HEX</button>
                    <button @click="copyText(item.payload_text)" class="ui-pill px-1.5 py-0.5 text-[11px] cursor-pointer" title="复制 ASCII">TXT</button>
                    <button @click="fillTxInput(item.payload_hex)" class="px-1.5 py-0.5 rounded bg-blue-500/12 text-blue-700 dark:text-sky-300 border border-blue-500/25 text-[11px] font-semibold cursor-pointer" title="转入发送区重发">载入</button>
                    <button @click="inspectPacketInModal(item)" class="px-1.5 py-0.5 rounded bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25 text-[11px] font-semibold cursor-pointer" title="全景解构此帧">解构</button>
                    <button @click="setDiffSlotA(item)" class="px-1.5 py-0.5 rounded bg-blue-500/12 text-blue-700 dark:text-sky-300 border border-blue-500/25 text-[11px] font-semibold cursor-pointer">设为 A</button>
                    <button @click="setDiffSlotB(item)" class="px-1.5 py-0.5 rounded bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25 text-[11px] font-semibold cursor-pointer">设为 B</button>
                    <button @click="addLogToDiffQueue(item)" class="px-1.5 py-0.5 rounded bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer" title="加入全局多组比对队列">+ 入队</button>
                  </div>
                </div>
              </div>

              <div v-if="rxFormat === 'HEX'" class="break-all tracking-wider font-mono font-semibold leading-relaxed text-[11px]" style="color: var(--text-primary);">
                {{ formatHexSpaced(item.payload_hex) }}
              </div>
              <div v-else class="break-all whitespace-pre-wrap font-mono leading-relaxed text-[11px]" style="color: var(--text-primary);">
                {{ item.payload_text }}
              </div>
            </div>

            <EmptyState
              v-if="filteredPacketLog.length === 0"
              icon="radar"
              title="暂无通信数据流水"
              description="启动会话后收发报文将在此毫秒级实时显现，支持十六进制与 ASCII 双模解析。"
            />
          </div>
        </div>

        <!-- 下部：数据发送控制终端 (TX Terminal) -->
        <div class="h-56 ui-content-card flex flex-col overflow-hidden shrink-0">
          <div class="px-3.5 py-1.5 border-b flex items-center justify-between text-xs shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle);">
            <div class="flex items-center gap-2.5 shrink-0">
              <span class="font-semibold text-xs flex items-center gap-1.5 whitespace-nowrap" style="color: var(--text-primary);">
                <span class="w-2 h-2 rounded-full bg-blue-500"></span>
                <span>数据发送终端 (TX)</span>
              </span>
              <div class="flex items-center glass-pill p-0.5 rounded-lg text-[11px] font-mono shrink-0">
                <button @click="txFormat = 'HEX'" :class="['px-2 py-0.5 rounded-md transition-all font-semibold cursor-pointer', txFormat === 'HEX' ? 'bg-blue-600 text-white' : 'text-[var(--text-secondary)]']">HEX</button>
                <button @click="txFormat = 'ASCII'" :class="['px-2 py-0.5 rounded-md transition-all font-semibold cursor-pointer', txFormat === 'ASCII' ? 'bg-blue-600 text-white' : 'text-[var(--text-secondary)]']">ASCII</button>
              </div>
            </div>

            <div class="flex items-center gap-2 text-[11px] flex-wrap">
              <select v-model="appendChecksum" style="width: auto" class="ui-input px-2 py-1 text-[11px] font-semibold shrink-0">
                <option value="NONE">无校验和</option>
                <option value="MODBUS_CRC16">Modbus CRC-16 (低字节在前)</option>
                <option value="CRC32">CRC-32 (IEEE 802.3)</option>
                <option value="SUM8">8位累加和 (SumCheck)</option>
                <option value="BCC">异或校验 (BCC/XOR)</option>
              </select>

              <select v-model="newlineType" style="width: auto" class="ui-input px-2 py-1 text-[11px] font-semibold shrink-0">
                <option value="NONE">无换行</option>
                <option value="CRLF">\r\n (CRLF)</option>
                <option value="LF">\n (LF)</option>
                <option value="CR">\r (CR)</option>
              </select>

              <div class="flex items-center gap-1 pl-2 border-l shrink-0 whitespace-nowrap" style="border-color: var(--border-subtle);">
                <label class="flex items-center gap-1 cursor-pointer select-none whitespace-nowrap" style="color: var(--text-secondary);">
                  <input type="checkbox" v-model="autoRepeat" @change="toggleAutoRepeat" class="accent-blue-600 rounded" />
                  <span class="text-[11px] font-semibold">自动轮发</span>
                </label>
                <input v-model.number="repeatIntervalMs" type="number" min="50" max="60000" style="width: 72px" class="ui-input px-1.5 py-0.5 text-[11px] ui-num text-center shrink-0" />
                <span class="text-[11px]" style="color: var(--text-muted);">ms</span>
              </div>
            </div>
          </div>

          <div class="flex-1 flex p-2 gap-2 min-h-0">
            <div class="flex-1 flex flex-col relative min-h-0">
              <textarea
                v-model="txPayload"
                :placeholder="txFormat === 'HEX' ? '输入待发送的十六进制字节流，如: 01 03 00 00 00 02' : '输入待发送的 ASCII 文本字符内容...'"
                class="ui-input flex-1 w-full p-2 font-mono text-xs resize-none"
                :class="hexValidation.valid ? '' : 'border-rose-500'"
                @keydown.ctrl.enter="sendPayload"
              />

              <div class="flex items-center justify-between px-2 py-1 text-[11px] font-mono rounded-b-xl border-t" style="border-color: var(--border-subtle); color: var(--text-muted);">
                <div class="flex items-center gap-2">
                  <span v-if="txFormat === 'HEX'" :class="hexValidation.valid ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400 font-semibold'">
                    {{ hexValidation.message }}
                  </span>
                  <span v-else>字符长度: {{ txPayload.length }} 字符</span>

                  <span v-if="previewChecksum && appendChecksum !== 'NONE'" class="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/25 font-semibold text-[11px]">
                    + {{ appendChecksum }}: [{{ previewChecksum }}]
                  </span>
                </div>

                <div v-if="txHistoryList.length > 0" class="flex items-center gap-1">
                  <span>历史:</span>
                  <select @change="txPayload = ($event.target as HTMLSelectElement).value" class="bg-transparent text-[11px] outline-none max-w-[120px] truncate cursor-pointer" style="color: var(--text-primary);">
                    <option value="">-- 最近发送 --</option>
                    <option v-for="(h, idx) in txHistoryList" :key="idx" :value="h">{{ h }}</option>
                  </select>
                </div>
              </div>
            </div>

            <div class="flex flex-col gap-1.5 w-28 shrink-0">
              <button
                @click="compareTxWithLastRx"
                :disabled="!txPayload.trim() || !lastRxItem"
                class="ui-btn-secondary py-1 px-2 text-[11px] justify-center"
                title="对比请求报文与最新响应帧"
              >
                <AppIcon name="scale" :size="11" />
                <span>请求 vs 响应</span>
              </button>
              <button
                @click="sendPayload"
                :disabled="!isRunning || !txPayload.trim() || (txFormat === 'HEX' && !hexValidation.valid)"
                class="ui-btn-primary flex-1 flex-col justify-center gap-0.5 text-xs"
              >
                <span>立即发送</span>
                <span class="text-[11px] font-normal opacity-80">(Ctrl+Enter)</span>
              </button>

              <div class="grid grid-cols-2 gap-1">
                <button v-if="txFormat === 'HEX'" @click="formatTxHex" class="ui-btn-secondary py-1 px-1 text-[11px] justify-center">整理</button>
                <button @click="txPayload = ''" :class="txFormat === 'HEX' ? '' : 'col-span-2'" class="ui-btn-secondary py-1 px-1 text-[11px] justify-center">清空</button>
              </div>
            </div>
          </div>
        </div>
      </main>

      <!-- 3. 右栏：工控规约载荷模板与快捷多指令调度矩阵 -->
      <aside class="lg:col-span-3 ui-content-card p-3.5 flex flex-col gap-3 overflow-y-auto custom-scrollbar">
        <div>
          <label class="text-[11px] font-semibold block mb-1.5" style="color: var(--text-secondary);">标准工控规约载荷模板</label>
          <select @change="applyProtocolPreset(($event.target as HTMLSelectElement).value); ($event.target as HTMLSelectElement).value = ''" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono">
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

        <div class="flex-1 flex flex-col min-h-0 border-t pt-2.5" style="border-color: var(--border-subtle);">
          <div class="flex items-center justify-between mb-1.5">
            <div class="flex items-center gap-1.5">
              <span class="text-[11px] font-semibold" style="color: var(--text-secondary);">多指令快捷调度矩阵</span>
              <span class="text-[11px] ui-num" style="color: var(--text-muted);">({{ presetCommands.length }})</span>
            </div>
            <button @click="addNewPreset" class="text-[11px] text-blue-600 dark:text-sky-400 font-semibold hover:underline cursor-pointer">
              + 添加指令
            </button>
          </div>

          <div class="ui-sub-card p-2 mb-2 flex items-center justify-between flex-wrap gap-1.5">
            <div class="flex items-center gap-1.5 flex-wrap">
              <button
                @click="toggleSequencePoller"
                :class="['px-2.5 py-1 rounded-lg text-[11px] font-semibold cursor-pointer transition-colors inline-flex items-center gap-1 whitespace-nowrap shrink-0',
                  isSequencePolling ? 'bg-rose-600 text-white' : 'bg-blue-600 text-white']"
                :disabled="!isRunning || presetCommands.length === 0"
              >
                <AppIcon :name="isSequencePolling ? 'stop' : 'zap'" :size="11" />
                <span>{{ isSequencePolling ? '停止轮发' : '序列轮发' }}</span>
              </button>
              <span class="text-[11px] whitespace-nowrap" style="color: var(--text-muted);">步长:</span>
              <input v-model.number="sequenceIntervalMs" type="number" min="100" max="10000" style="width: 72px" class="ui-input px-1.5 py-0.5 text-[11px] ui-num text-center shrink-0" />
              <span class="text-[11px] whitespace-nowrap" style="color: var(--text-muted);">ms</span>
            </div>
            <span v-if="isSequencePolling" class="text-[11px] font-semibold text-emerald-600 dark:text-emerald-400 ui-num">
              发送中 #{{ activeSequenceIdx + 1 }}
            </span>
          </div>

          <div class="flex-1 overflow-y-auto custom-scrollbar space-y-1.5 pr-0.5">
            <div
              v-for="(cmd, idx) in presetCommands"
              :key="idx"
              class="ui-sub-card p-2 text-xs font-mono space-y-1 transition-all"
              :class="isSequencePolling && activeSequenceIdx === idx ? 'border-blue-500 ring-1 ring-blue-500/30' : ''"
            >
              <div class="flex items-center justify-between text-[11px]">
                <input v-model="cmd.name" @change="savePresetsToStorage" class="font-semibold bg-transparent border-b border-transparent focus:border-blue-500 outline-none w-32" style="color: var(--text-primary);" />
                <div class="flex items-center gap-1">
                  <button @click="sendSpecificPreset(cmd)" :disabled="!isRunning" class="ui-btn-primary px-2 py-0.5 text-[11px]">发送</button>
                  <button @click="deletePreset(idx)" class="p-1 cursor-pointer hover:text-rose-500" style="color: var(--text-muted);" title="删除该指令">
                    <AppIcon name="close" :size="11" />
                  </button>
                </div>
              </div>
              <input v-model="cmd.payload" @change="savePresetsToStorage" placeholder="HEX 字节流" class="ui-input w-full px-2 py-1 text-[11px] font-mono" />
            </div>
          </div>
        </div>
      </aside>
    </div>

    <PacketDetailModal :is-open="isDetailModalOpen" :packet="modalPacket" @close="isDetailModalOpen = false" />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, nextTick } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import AppIcon from '../components/AppIcon.vue';
import EmptyState from '../components/EmptyState.vue';
import { saveTextViaNativeDesktop } from '../composables/useDesktopSave';
import {
  notifySuccess,
  notifyInfo,
  notifyWarning,
  notifyError,
} from '../composables/useNotification';
import { useUniversalDiff } from '../composables/useUniversalDiff';
import PacketDetailModal from '../components/PacketDetailModal.vue';
import { APP_VERSION_RAW } from '../constants/appVersion';
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

// 全局通用数据比对总线联动
const diffBus = useUniversalDiff();

const lastRxItem = computed(() => {
  for (let i = packetLog.value.length - 1; i >= 0; i--) {
    if (packetLog.value[i].direction === 'RX') return packetLog.value[i];
  }
  return null;
});

function buildLogDiffPayload(item: PacketLogItem) {
  return {
    id: item.id,
    label: `[${item.direction}] ${item.remote_addr}`,
    timestamp: formatTime(item.timestamp_ms),
    direction: item.direction,
    protocol: selectedMode.value,
    src: item.direction === 'TX' ? item.local_addr : item.remote_addr,
    dst: item.direction === 'TX' ? item.remote_addr : item.local_addr,
    payloadHex: item.payload_hex,
    rawText: item.payload_text,
    length: item.length,
    extraFields: {
      direction: item.direction,
      transport_mode: selectedMode.value,
      local_endpoint: item.local_addr || '-',
      remote_endpoint: item.remote_addr || '-'
    }
  };
}

function setDiffSlotA(item: PacketLogItem) {
  diffBus.setSlotA(buildLogDiffPayload(item), `套接字调试 ${item.direction} #${item.id}`);
}

function setDiffSlotB(item: PacketLogItem) {
  diffBus.setSlotB(buildLogDiffPayload(item), `套接字调试 ${item.direction} #${item.id}`);
  if (diffBus.slotA.value) {
    diffBus.compareSlots();
  }
}

function addLogToDiffQueue(item: PacketLogItem) {
  diffBus.addToQueue(buildLogDiffPayload(item), `套接字 ${item.direction} #${item.id}`, false);
}

function compareTxWithLastRx() {
  if (!lastRxItem.value) {
    notifyWarning('提示', '尚未捕获到任何对端响应帧，请先发送并接收数据');
    return;
  }
  const isAsciiMode = txFormat.value === 'ASCII';
  const cleanHex = !isAsciiMode ? txPayload.value.replace(/[\s\r\n\t]/g, '') : '';
  const txItem = {
    id: 'TX_DRAFT',
    label: `[TX 请求帧] ${targetIp.value || '127.0.0.1'}:${targetPort.value || 0}`,
    timestamp: new Date().toLocaleTimeString(),
    direction: 'TX',
    protocol: selectedMode.value,
    src: localBindIp.value || '0.0.0.0',
    dst: `${targetIp.value || '127.0.0.1'}:${targetPort.value || 0}`,
    format: isAsciiMode ? 'ASCII' : 'HEX',
    isRawText: isAsciiMode,
    payloadHex: cleanHex,
    rawText: isAsciiMode ? txPayload.value : '',
    length: cleanHex ? cleanHex.length / 2 : txPayload.value.length
  };
  const rxItem = {
    id: lastRxItem.value.id,
    label: `[RX 最新回复] ${lastRxItem.value.remote_addr}`,
    timestamp: formatTime(lastRxItem.value.timestamp_ms),
    direction: 'RX',
    protocol: selectedMode.value,
    src: lastRxItem.value.remote_addr,
    dst: lastRxItem.value.local_addr || '0.0.0.0',
    payloadHex: lastRxItem.value.payload_hex,
    rawText: lastRxItem.value.payload_text,
    length: lastRxItem.value.length
  };
  diffBus.openUniversalDiff(txItem, rxItem, 'hex');
}

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
      } catch (err) {
        console.warn('[NetAssist] persist tx history to localStorage failed:', err);
      }
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
  } catch (err) {
    console.warn('[NetAssist] persist preset commands to localStorage failed:', err);
  }
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
      txPayload.value = `GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: OmniProbe-SocketDebugger/${APP_VERSION_RAW}\r\nConnection: close\r\n\r\n`;
      break;
    case 'sl651_telemetry':
      txPayload.value = '7E 7E 01 00 00 00 00 01 00 02 32 00 00 03 14 00 00 00';
      break;
  }
  notifyInfo('工控规约模板已载入', `已将 ${type} 报文载入发送终端`);
}

async function exportLog() {
  if (packetLog.value.length === 0) {
    notifyWarning('导出提示', '当前无数据记录可供导出');
    return;
  }
  const lines = packetLog.value.map(p => {
    return `[${formatTime(p.timestamp_ms)}] [${p.direction}] ${p.remote_addr} (${p.length} Bytes)\nHEX: ${p.payload_hex}\nTXT: ${p.payload_text}\n`;
  });
  await saveTextViaNativeDesktop(
    `OmniProbe_SocketLog_${Date.now()}.txt`,
    lines.join('\n'),
    '通信日志文本 (*.txt)',
    '*.txt;*.log',
    '导出网络调试通信日志'
  );
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
    entropy: 0,
    entropy_level: 'normal',
    mac_src: '-- (Socket 通道)',
    mac_dst: '-- (Socket 通道)',
    chain_hash: `NET_ASSIST_${item.id}`,
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

    // 检查是否有来自全息流量分析台右键推送的载荷
    const incoming = localStorage.getItem('omni_probe_net_assist_incoming_payload');
    if (incoming) {
      txPayload.value = formatHexSpaced(incoming);
      txFormat.value = 'HEX';
      localStorage.removeItem('omni_probe_net_assist_incoming_payload');
      notifyInfo('已载入待测报文载荷', '来自全息流量分析台的快捷推送');
    }
  } catch (err) {
    console.warn('[NetAssist] restore persisted storage or incoming payload failed:', err);
  }

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

  // 监听客户端连接池更新并主动同步一次现有在连客户端
  try {
    const curClients = await invoke<string[]>('get_net_assist_clients_cmd');
    if (Array.isArray(curClients)) {
      activeClients.value = curClients;
    }
  } catch (e) {
    console.error('同步在连客户端清单失败:', e);
  }
  unlistenClients = await listen<{ active_clients?: string[]; event_type?: string; client_addr?: string }>('net-assist-clients', (event) => {
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
