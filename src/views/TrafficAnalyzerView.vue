<template>
  <div class="flex-1 flex flex-col gap-2 overflow-hidden min-w-0 h-full">

    <!-- 1. UPPER SECTION: TOPOLOGY HORIZON -->
    <div v-show="isHorizonExpanded" class="h-[32%] flex flex-col lg:flex-row gap-2.5 shrink-0 min-h-[210px] transition-all duration-300">

      <!-- 1.1 左侧：工业控制通信拓扑画布 -->
      <div class="flex-1 ui-content-card p-3 flex flex-col relative overflow-hidden">
        <!-- 标题行与节点状态指示 -->
        <div class="flex items-center justify-between mb-1.5 z-10 flex-wrap gap-2">
          <div class="flex items-center gap-2">
            <span class="text-xs font-semibold tracking-tight" style="color: var(--text-primary);">多总线物理通信拓扑</span>
            <span class="text-[11px] ui-num px-2 py-0.5 rounded-full bg-blue-500/12 text-blue-700 dark:text-sky-300 border border-blue-500/25 font-medium">
              {{ topoNodes.length }} 个活跃通信节点
            </span>
          </div>
          <div class="flex items-center gap-2.5 flex-wrap">
            <!-- 物理外设总线切换 -->
            <div class="flex glass-pill p-0.5 rounded-xl text-[11px] font-mono">
              <button @click="activeBus = 'nic'" :class="['px-2.5 py-0.5 rounded-lg transition-all cursor-pointer', activeBus === 'nic' ? 'bg-[var(--accent-primary)] text-white font-semibold shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']">NIC</button>
              <button @click="activeBus = 'serial'" :class="['px-2.5 py-0.5 rounded-lg transition-all cursor-pointer', activeBus === 'serial' ? 'bg-[var(--accent-primary)] text-white font-semibold shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']">COM</button>
              <button @click="activeBus = 'usb'" :class="['px-2.5 py-0.5 rounded-lg transition-all cursor-pointer', activeBus === 'usb' ? 'bg-[var(--accent-primary)] text-white font-semibold shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']">USB</button>
            </div>

            <!-- 串口控制微组件 -->
            <div v-if="activeBus === 'serial'" class="flex items-center gap-1.5 text-xs font-mono glass-pill px-2 py-0.5 rounded-xl">
              <select
                :value="selectedSerial"
                @change="$emit('updateSerial', ($event.target as HTMLSelectElement).value)"
                class="bg-transparent text-xs focus:outline-none max-w-[120px] truncate"
                style="color: var(--text-primary);"
                :title="getSerialDetailTitle(selectedSerial)"
              >
                <option v-for="p in serialPorts" :key="p" :value="p">
                  {{ getSerialOptionLabel(p) }}
                </option>
              </select>
              <select
                :value="serialBaudRate"
                @change="onBaudRateChange(Number(($event.target as HTMLSelectElement).value))"
                class="bg-transparent text-xs focus:outline-none"
                style="color: var(--text-primary);"
              >
                <option :value="9600">9600</option>
                <option :value="19200">19200</option>
                <option :value="115200">115200</option>
              </select>
              <button
                @click="triggerStartSerial(selectedSerial, serialBaudRate)"
                class="text-indigo-600 dark:text-indigo-300 hover:underline text-[11px] px-1.5 py-0.5 rounded border border-indigo-500/30 cursor-pointer"
              >
                {{ isSerialRunning ? '重置' : '监听' }}
              </button>
              <button
                @click="triggerSendProbeFrame"
                :disabled="!selectedSerial || isSendingProbe"
                class="text-amber-600 dark:text-amber-300 hover:underline text-[11px] px-1.5 py-0.5 rounded border border-amber-500/30 cursor-pointer"
              >
                探活
              </button>
            </div>

            <!-- USB 控制微组件 -->
            <div v-else-if="activeBus === 'usb'" class="flex items-center gap-1.5 text-xs font-mono glass-pill px-2 py-0.5 rounded-xl">
              <span class="text-purple-600 dark:text-purple-300 text-[11px]">USB: {{ usbDevices.length }}</span>
              <button
                @click="triggerStartUsb"
                class="text-purple-600 dark:text-purple-300 hover:underline text-[11px] px-1.5 py-0.5 rounded border border-purple-500/30 cursor-pointer"
              >
                {{ isUsbRunning ? '重启' : '挂钩' }}
              </button>
            </div>

            <div class="hidden xl:flex items-center gap-2.5 text-[11px]" style="color: var(--text-muted);">
              <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-rose-500"></span>安全告警</span>
              <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-emerald-500"></span>Modbus 节点</span>
              <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-amber-500"></span>S7 PLC 节点</span>
              <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-cyan-400"></span>源端节点</span>
              <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-blue-400"></span>目的节点</span>
            </div>

            <button
              @click="isHorizonExpanded = false"
              title="收起拓扑面板，最大化报文流水线"
              class="w-6 h-6 rounded-lg glass-pill hover:bg-[var(--surface-hover)] flex items-center justify-center transition-all cursor-pointer"
              style="color: var(--text-secondary);"
            >
              <AppIcon name="chevron-up" :size="12" />
            </button>
          </div>
        </div>

        <!-- Canvas 动态渲染容器 (双模态自适应半透液态玻璃视口) -->
        <div class="relative flex-1 rounded-xl border overflow-hidden flex items-center justify-center" style="background: var(--surface-content-alt); border-color: var(--border-subtle);">
          <canvas ref="topologyCanvasRef" class="w-full h-full absolute inset-0"></canvas>

          <!-- 画布内嵌遥测条 (跟随双模态语义液态玻璃胶囊) -->
          <div class="ui-nav-glass absolute bottom-2.5 left-3 flex items-center gap-4 pointer-events-none z-10 px-3.5 py-1.5 rounded-xl font-mono">
            <div>
              <div class="text-[11px] font-sans" style="color: var(--text-muted);">实时吞吐率</div>
              <div class="text-sm font-bold flex items-center gap-1 ui-num" style="color: var(--text-primary);">
                <span>{{ telemetryThroughputMbps }}</span>
                <span class="text-xs text-[var(--accent-primary-text)] font-normal">Mbps</span>
              </div>
            </div>
            <div class="h-5 w-px" style="background: var(--border-subtle);"></div>
            <div>
              <div class="text-[11px] font-sans" style="color: var(--text-muted);">瞬时包率</div>
              <div class="text-sm font-bold flex items-center gap-1 ui-num" style="color: var(--text-primary);">
                <span>{{ telemetryPps.toLocaleString() }}</span>
                <span class="text-xs text-emerald-600 dark:text-emerald-400 font-normal">pps</span>
              </div>
            </div>
            <div class="h-5 w-px" style="background: var(--border-subtle);"></div>
            <div>
              <div class="text-[11px] font-sans" style="color: var(--text-muted);">平均抖动</div>
              <div class="text-sm font-bold flex items-center gap-1 ui-num" style="color: var(--text-primary);">
                <span>{{ telemetryJitterMs }}</span>
                <span class="text-xs font-normal" style="color: var(--text-secondary);">ms</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 1.2 右侧：核心运行指标统计面板 -->
      <div class="w-full lg:w-80 xl:w-96 ui-content-card p-3.5 flex flex-col justify-between shrink-0">
        <!-- Header -->
        <div class="flex items-center justify-between gap-2">
          <span class="text-xs font-bold uppercase tracking-wider text-(--text-secondary)">工业合规与系统健康矩阵</span>
          <span
            class="text-[11px] font-mono-code font-bold px-2 py-0.5 rounded-full border shrink-0 ui-num"
            :class="complianceHealthSummary.badgeClass"
          >
            {{ complianceHealthSummary.headerBadge }}
          </span>
        </div>

        <!-- Big Metric 1: 累计解包帧数 (Total Frames Audited) -->
        <div class="flex flex-col py-1 border-b border-(--border-subtle)">
          <span class="text-[11px] text-(--text-muted) font-medium">累计解包帧数 (Total Frames Audited)</span>
          <div class="flex items-baseline gap-2 mt-0.5">
            <span class="metric-display ui-num">{{ packets.length.toLocaleString() }}</span>
            <span class="text-xs font-mono-code ui-num text-emerald-600 dark:text-emerald-400 font-semibold">{{ telemetryRateText }}</span>
          </div>
        </div>

        <!-- Big Metric 2: 工业 OT 协议载荷占比连续分段条 -->
        <div class="flex flex-col gap-1.5 py-1">
          <div class="flex justify-between items-center text-[11px]">
            <span class="text-slate-400">工业 OT 协议载荷占比</span>
            <span class="font-mono text-cyan-950 dark:text-cyan-300 font-bold">{{ industrialRatioText }}</span>
          </div>
          <!-- 分段彩色胶囊条 -->
          <div class="w-full h-2.5 rounded-full overflow-hidden flex p-0.5 gap-0.5 border" style="background: var(--surface-input); border-color: var(--border-subtle);">
            <div class="h-full rounded-sm bg-cyan-500 transition-all duration-300" :style="{ width: `${protocolStats.modbus}%` }" title="Modbus TCP"></div>
            <div class="h-full rounded-sm bg-amber-500 transition-all duration-300" :style="{ width: `${protocolStats.s7}%` }" title="Siemens S7Comm"></div>
            <div class="h-full rounded-sm bg-violet-500 transition-all duration-300" :style="{ width: `${protocolStats.ethercat}%` }" title="EtherCAT"></div>
            <div class="h-full rounded-sm bg-emerald-500 transition-all duration-300" :style="{ width: `${protocolStats.iec104}%` }" title="IEC 60870-5-104 / DNP3"></div>
          </div>
          <div class="grid grid-cols-4 gap-1 text-[11px] ui-num pt-0.5" style="color: var(--text-muted);">
            <span class="flex items-center gap-1 truncate"><span class="w-1.5 h-1.5 rounded-full bg-cyan-500 shrink-0"></span>Modbus {{ protocolStats.modbus }}%</span>
            <span class="flex items-center gap-1 truncate"><span class="w-1.5 h-1.5 rounded-full bg-amber-500 shrink-0"></span>S7 {{ protocolStats.s7 }}%</span>
            <span class="flex items-center gap-1 truncate"><span class="w-1.5 h-1.5 rounded-full bg-violet-500 shrink-0"></span>EtherCAT {{ protocolStats.ethercat }}%</span>
            <span class="flex items-center gap-1 truncate"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0"></span>其他 {{ protocolStats.iec104 }}%</span>
          </div>
        </div>

        <!-- Big Metric 3: 指令白名单合规卡片（动态关联实时捕获与违规拦截记录） -->
        <div class="ui-sub-card p-2.5 flex items-center justify-between gap-2">
          <div class="flex items-center gap-2.5 min-w-0">
            <div
              class="w-7 h-7 rounded-lg border flex items-center justify-center shrink-0"
              :class="complianceHealthSummary.iconBoxClass"
            >
              <AppIcon :name="complianceHealthSummary.iconName" :size="15" />
            </div>
            <div class="min-w-0">
              <div class="text-xs font-semibold truncate" style="color: var(--text-primary);">{{ complianceHealthSummary.title }}</div>
              <div class="text-[11px] truncate" style="color: var(--text-muted);" :title="complianceHealthSummary.subtitle">
                {{ complianceHealthSummary.subtitle }}
              </div>
            </div>
          </div>
          <span class="text-xs ui-num font-semibold shrink-0" :class="complianceHealthSummary.countClass">
            {{ complianceHealthSummary.countLabel }}
          </span>
        </div>
      </div>
    </div>

    <!-- 2. LOWER SECTION: 实体稳态主舞台 + 随行解构抽屉 -->
    <div class="flex-1 ui-content-card flex overflow-hidden min-h-0 relative">

      <!-- 2.1 中央主舞台：实时报文全景流 -->
      <div class="flex-1 flex flex-col overflow-hidden min-w-0 relative">
        <!-- 悬空穿透液态玻璃控制栏 (Floating Liquid Toolbar Over Scrollable Grid) -->
        <div class="stage-header-bar absolute top-2.5 left-3 right-3 z-40 rounded-2xl flex items-center justify-between gap-1.5 flex-wrap gap-y-1">
          <span class="lens-edge-lip" aria-hidden="true"></span>
          <!-- 左翼：指示灯、精简标题、高频协议胶囊与拓扑切换 -->
          <div class="flex items-center gap-1.5 shrink-0">
            <span class="live-pulse-dot shrink-0"></span>
            <span class="text-xs font-semibold tracking-tight shrink-0 whitespace-nowrap" style="color: var(--text-primary);">
              <span class="hidden 2xl:inline">实时报文全景流</span>
              <span class="2xl:hidden">报文流</span>
            </span>
            <span
              v-if="isRunning && captureCapability && captureCapability.external_ready && captureCapability.targets.length > 0"
              class="hidden xl:inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 ui-num shrink-0"
              :title="`外网并发挂载接口: ${captureCapability.targets.join(', ')}`"
            >
              全网 {{ captureCapability.targets.length }} 口
            </span>

            <!-- 协议快速微胶囊群 -->
            <div class="flex items-center gap-0.5 glass-pill p-0.5 rounded-xl text-[11px] shrink-0">
              <button
                v-for="tag in quickProtocolTags.slice(0, 3)"
                :key="tag.value"
                @click="filterProtocol = tag.value"
                :title="tag.title || tag.label"
                :class="[
                  'px-2 py-0.5 rounded-lg font-medium transition-all cursor-pointer whitespace-nowrap text-[11px]',
                  filterProtocol === tag.value
                    ? 'bg-[var(--accent-primary)] text-white font-semibold shadow-xs'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                ]"
              >
                {{ tag.label }}
              </button>
              <select v-model="filterProtocol" class="bg-transparent text-[11px] rounded-lg px-1 py-0.5 focus:outline-none border-l cursor-pointer max-w-[78px]" style="color: var(--text-primary); border-color: var(--border-subtle);">
                <option value="">更多</option>
                <option v-for="p in protocolList" :key="p" :value="p">{{ p }}</option>
              </select>
            </div>

            <!-- 多总线拓扑面板展开/折叠胶囊 (包含 NIC / COM 串口 / USB 快速切换) -->
            <button
              @click="isHorizonExpanded = !isHorizonExpanded"
              title="展开/收起多总线控制与实时通信拓扑 (NIC / COM 串口 / USB)"
              :class="['text-[11px] font-medium px-2 py-0.5 rounded-xl transition-all cursor-pointer flex items-center gap-1 glass-pill whitespace-nowrap shrink-0',
                isHorizonExpanded ? 'text-blue-600 dark:text-sky-400 border-blue-500/40 bg-blue-500/12' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
            >
              <AppIcon :name="isHorizonExpanded ? 'chevron-up' : 'chevron-down'" :size="12" />
              <span>{{ isHorizonExpanded ? '收起总线' : '总线拓扑' }}</span>
            </button>
          </div>

          <!-- 中腹：Display Filter 胶囊 -->
          <div class="flex-1 min-w-[68px] max-w-[160px] flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[11px] focus-within:border-blue-500 transition-all" style="background: var(--surface-input); border-color: var(--border-subtle);">
            <AppIcon name="search" :size="12" style="color: var(--text-muted);" class="shrink-0" />
            <input
              v-model="filterInput"
              @keydown.enter="applyDisplayFilter"
              @input="onFilterInputDebounced"
              placeholder="过滤 (s7comm)..."
              class="bg-transparent text-[11px] outline-none w-full min-w-0 font-mono"
              style="color: var(--text-primary);"
            />
            <button v-if="filterInput" @click="clearDisplayFilter" class="cursor-pointer p-0.5 shrink-0" style="color: var(--text-muted);" title="清空过滤">
              <AppIcon name="close" :size="11" />
            </button>
            <button v-if="filterInput" @click="applyDisplayFilter" class="text-[11px] font-semibold text-blue-600 dark:text-sky-400 px-1.5 py-0.5 rounded bg-blue-500/12 cursor-pointer shrink-0">
              过滤
            </button>
          </div>

          <!-- 右翼：三大点击式工具菜单 + 遥测数据 + 随行解构抽屉开关 -->
          <div class="flex items-center gap-1 text-xs shrink-0 whitespace-nowrap">
            <!-- 1. 深度分析工具下拉菜单 (Click Popover) -->
            <div class="relative">
              <button
                @click.stop="toggleDropdown('analyze')"
                :class="['glass-pill px-2 py-1 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-1 text-[11px]',
                  activeDropdown === 'analyze' ? 'border-blue-500/50 text-blue-600 dark:text-sky-300' : 'text-[var(--text-primary)]']"
              >
                <AppIcon name="activity" :size="12" class="text-blue-500" />
                <span>分析</span>
                <AppIcon name="chevron-down" :size="11" />
              </button>
              <div
                v-if="activeDropdown === 'analyze'"
                @click.stop
                class="ui-modal-surface absolute right-0 top-full mt-1.5 w-48 rounded-2xl p-1.5 z-50 space-y-0.5 font-medium"
              >
                <button @click="openWaveTab(); closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="activity" :size="13" class="text-blue-500" />
                  <span>示波波形追踪</span>
                </button>
                <button @click="openIoGraphsTab(); closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="traffic" :size="13" class="text-indigo-500" />
                  <span>IO Graphs 点阵</span>
                </button>
                <button @click="diffBus.compareSlots(); closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="scale" :size="13" class="text-emerald-500" />
                  <span>双组/多组精密差分</span>
                </button>
                <button @click="openGlobalMultiDiffWithSelected(); closeAllDropdowns()" :disabled="selectedPackets.size < 2" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer disabled:opacity-40" style="color: var(--text-primary);">
                  <AppIcon name="git-branch" :size="13" class="text-indigo-500" />
                  <span>送入 Center-Star 多组对齐</span>
                </button>
                <button @click="isMultiCompareOpen = true; closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="usb" :size="13" class="text-cyan-500" />
                  <span>多串口实时交叉对比 (2-4路)</span>
                </button>
                <button @click="openMatrixTab(); closeAllDropdowns()" :disabled="selectedPackets.size < 2" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer disabled:opacity-40" style="color: var(--text-primary);">
                  <AppIcon name="layers" :size="13" class="text-purple-500" />
                  <span>多报文矩阵</span>
                </button>
                <button @click="openTraceroute(''); closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="globe" :size="13" class="text-sky-500" />
                  <span>可视路由追踪</span>
                </button>
                <button @click="toggleIndustrialTxPanel(); closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="cpu" :size="13" class="text-amber-500" />
                  <span>工控主从事务时延</span>
                </button>
                <button @click="toggleTimeseriesHeatmapPanel(); closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="radar" :size="13" class="text-indigo-500" />
                  <span>时序聚合与热力矩阵</span>
                </button>
                <button @click="isVpnDetectorOpen = true; closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs font-semibold cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="shield" :size="13" class="text-rose-500" />
                  <span>VPN / 加密代理四维侦测</span>
                </button>
              </div>
            </div>

            <!-- 2. 链路执行工具下拉菜单 -->
            <div class="relative">
              <button
                @click.stop="toggleDropdown('control')"
                :class="['glass-pill px-2 py-1 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-1 text-[11px]',
                  activeDropdown === 'control' ? 'border-amber-500/50 text-amber-600 dark:text-amber-300' : 'text-[var(--text-primary)]']"
              >
                <AppIcon name="zap" :size="12" class="text-amber-500" />
                <span>控制</span>
                <AppIcon name="chevron-down" :size="11" />
              </button>
              <div
                v-if="activeDropdown === 'control'"
                @click.stop
                class="ui-modal-surface absolute right-0 top-full mt-1.5 w-52 rounded-2xl p-1.5 z-50 space-y-0.5 font-medium"
              >
                <button @click="$emit('switchWorkbench', 'net_assist'); closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs font-semibold cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="terminal" :size="13" class="text-sky-500" />
                  <span>网络通信调试</span>
                </button>
                <button @click="isTargetProbeOpen = true; closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="radar" :size="13" class="text-amber-500" />
                  <span>靶向主动反探</span>
                </button>
                <button @click="openInjectModal(selectedPacket?.payload_hex); closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="zap" :size="13" class="text-rose-500" />
                  <span>链路层帧注入</span>
                </button>
                <button @click="toggleReplayConsole(); closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="play" :size="13" class="text-emerald-500" />
                  <span>PCAP 线速重放控制台</span>
                </button>
                <button @click="isColumnSettingsOpen = true; closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="sliders" :size="13" class="text-slate-500" />
                  <span>调整字段列宽</span>
                </button>
                <button @click="resetAllColWidths(); closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-muted);">
                  <AppIcon name="refresh" :size="13" />
                  <span>重置默认列宽</span>
                </button>
              </div>
            </div>

            <!-- 3. 数据归档与基线下拉菜单 -->
            <div class="relative">
              <button
                @click.stop="toggleDropdown('archive')"
                :class="['glass-pill px-2 py-1 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-1 text-[11px]',
                  activeDropdown === 'archive' ? 'border-emerald-500/50 text-emerald-600 dark:text-emerald-300' : 'text-[var(--text-primary)]']"
              >
                <AppIcon name="archive" :size="12" class="text-emerald-500" />
                <span>归档</span>
                <AppIcon name="chevron-down" :size="11" />
              </button>
              <div
                v-if="activeDropdown === 'archive'"
                @click.stop
                class="ui-modal-surface absolute right-0 top-full mt-1.5 w-48 rounded-2xl p-1.5 z-50 space-y-0.5 font-medium"
              >
                <button @click="saveSelectedAsBaseline(); closeAllDropdowns()" :disabled="!selectedPacket" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer disabled:opacity-40" style="color: var(--text-primary);">
                  <AppIcon name="archive" :size="13" class="text-emerald-500" />
                  <span>存为历史基线</span>
                </button>
                <button @click="runJointBaselineCompare(); closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="scale" :size="13" class="text-indigo-500" />
                  <span>联合基线比对</span>
                </button>
                <button @click="loadHistoricalBaseline(); closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="folder" :size="13" class="text-amber-500" />
                  <span>载入历史基线库</span>
                </button>
                <button @click="isExportOpen = true; closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="download" :size="13" class="text-blue-500" />
                  <span>导出 PCAP/CSV</span>
                </button>
                <button @click="isImportOpen = true; closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-[var(--surface-hover)] flex items-center gap-2 transition-colors text-xs cursor-pointer" style="color: var(--text-primary);">
                  <AppIcon name="upload" :size="13" class="text-sky-500" />
                  <span>导入离线 PCAP</span>
                </button>
                <button @click="$emit('clearData'); closeAllDropdowns()" class="w-full text-left px-2.5 py-1.5 rounded-xl hover:bg-rose-500/12 text-rose-600 dark:text-rose-400 flex items-center gap-2 transition-colors text-xs cursor-pointer">
                  <AppIcon name="trash" :size="13" />
                  <span>清空捕获缓冲池</span>
                </button>
              </div>
            </div>

            <!-- 吞吐与包率微指标 -->
            <div class="hidden 2xl:flex items-center gap-1.5 ui-num text-[11px] glass-pill px-2.5 py-1 rounded-xl" style="color: var(--text-muted);">
              <span>吞吐: <b style="color: var(--text-primary);">{{ formatBytes(totalBytes) }}</b></span>
              <span v-if="criticalCount > 0" class="text-rose-600 dark:text-rose-400 font-semibold bg-rose-500/15 px-1.5 rounded text-[11px]">高熵: {{ criticalCount }}</span>
            </div>

            <!-- 随行解构抽屉开关 -->
            <button
              @click="isInspectorOpen = !isInspectorOpen"
              :class="['px-2 py-1 rounded-xl glass-pill transition-colors flex items-center gap-1 text-[11px] font-semibold cursor-pointer shrink-0 whitespace-nowrap',
                isInspectorOpen ? 'bg-[var(--accent-primary)] text-white border-transparent shadow-xs' : 'text-[var(--text-primary)] hover:bg-[var(--surface-hover)]']"
            >
              <AppIcon name="code" :size="12" />
              <span>{{ isInspectorOpen ? '收起解构' : '随行解构' }}</span>
              <span class="kbd-badge hidden 2xl:inline-block">R</span>
            </button>
          </div>
        </div>

        <!-- 上部扩展控制台容器 (当任意分析控制台开启时自动预留悬浮条避让空间) -->
        <div v-if="isReplayPanelOpen || isIndustrialTxOpen || isTimeseriesHeatmapOpen" class="pt-[62px] shrink-0 flex flex-col">
        <!-- PCAP 线速重放控制台 -->
        <div v-if="isReplayPanelOpen" class="px-3 py-2 border-b flex flex-wrap items-center justify-between gap-2 text-xs shrink-0" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-primary);">
          <div class="flex items-center gap-1.5 flex-1 min-w-[260px]">
            <span class="text-blue-600 dark:text-sky-400 font-semibold shrink-0 flex items-center gap-1">
              <AppIcon name="play" :size="12" />
              <span>线速重放</span>
            </span>
            <input
              v-model="replayFilePath"
              placeholder="输入本地 .pcap / .pcapng 文件绝对路径..."
              class="ui-input flex-1 min-w-[160px] px-2.5 py-1 text-[11px] font-mono"
            />
            <button @click="loadReplayFile" :disabled="replayLoading || !replayFilePath.trim()" class="ui-btn-primary px-2.5 py-1 text-[11px] shrink-0">
              <AppIcon name="folder" :size="12" />
              <span>载入文件</span>
            </button>
          </div>

          <div class="flex items-center gap-1.5 shrink-0">
            <select v-model="replayMode" class="ui-input px-2 py-1 text-[11px]">
              <option value="paced">原速/倍速 (Paced)</option>
              <option value="top_speed">全速突发 (TopSpeed)</option>
              <option value="step">单步精确 (Step)</option>
            </select>
            <input
              v-if="replayMode === 'paced'"
              v-model.number="replaySpeed"
              type="number"
              step="0.5"
              min="0.1"
              max="100"
              title="重放倍速 (如 1.0 表示原时间戳)"
              class="ui-input w-14 px-1.5 py-1 text-[11px] text-center ui-num"
            />
            <input
              v-model.number="replayLoops"
              type="number"
              min="1"
              max="9999"
              title="循环次数"
              class="ui-input w-12 px-1.5 py-1 text-[11px] text-center ui-num"
            />

            <button @click="startReplay" :disabled="!replayFileInfo && replayTelemetry.total_packets === 0" class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 px-2.5 py-1 text-[11px]">开始</button>
            <button v-if="replayTelemetry.state === 'Playing'" @click="pauseReplay" class="ui-btn-primary bg-amber-600 hover:bg-amber-500 px-2.5 py-1 text-[11px]">暂停</button>
            <button v-if="replayTelemetry.state === 'Paused'" @click="resumeReplay" class="ui-btn-primary px-2.5 py-1 text-[11px]">恢复</button>
            <button v-if="replayMode === 'step' || replayTelemetry.state === 'Paused'" @click="stepReplay" class="ui-btn-primary bg-indigo-600 hover:bg-indigo-500 px-2.5 py-1 text-[11px]">单步</button>
            <button @click="stopReplay" class="ui-btn-danger px-2.5 py-1 text-[11px]">停止</button>
          </div>

          <div class="flex items-center gap-2 text-[11px] ui-num shrink-0" style="color: var(--text-secondary);">
            <span class="px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-600 dark:text-sky-300 font-semibold">{{ replayTelemetry.state }}</span>
            <span>{{ replayTelemetry.current_index }}/{{ replayTelemetry.total_packets }} ({{ replayTelemetry.progress_percent.toFixed(1) }}%)</span>
            <span class="text-emerald-600 dark:text-emerald-400">{{ replayTelemetry.current_pps.toFixed(0) }} pps · {{ replayTelemetry.current_mbps.toFixed(2) }} Mbps</span>
            <button @click="isReplayPanelOpen = false" class="p-1 cursor-pointer hover:opacity-75" style="color: var(--text-muted);" title="折叠重放面板">
              <AppIcon name="close" :size="12" />
            </button>
          </div>
        </div>

        <!-- 工控主从事务配对与微秒时延分析抽屉 -->
        <div v-if="isIndustrialTxOpen" class="px-3 py-2.5 border-b flex flex-col gap-2 text-xs shrink-0 max-h-56 overflow-hidden" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-primary);">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="flex items-center gap-3 flex-wrap ui-num">
              <span class="text-amber-600 dark:text-amber-300 font-semibold flex items-center gap-1">
                <AppIcon name="cpu" :size="13" />
                <span>工控主从事务与往返时延追踪</span>
              </span>
              <span>总事务: <b>{{ txStats?.total_transactions_recorded ?? 0 }}</b></span>
              <span>成功: <b class="text-emerald-600 dark:text-emerald-400">{{ txStats?.successful_transactions ?? 0 }}</b></span>
              <span>异常/超时: <b class="text-rose-600 dark:text-rose-400">{{ txStats?.exception_transactions ?? 0 }} / {{ txStats?.timeout_transactions ?? 0 }}</b></span>
              <span>平均/最大时延: <b class="text-blue-600 dark:text-sky-300">{{ (txStats?.avg_plc_latency_ms ?? 0).toFixed(2) }} / {{ (txStats?.max_plc_latency_ms ?? 0).toFixed(2) }} ms</b></span>
            </div>
            <div class="flex items-center gap-1.5">
              <button @click="fetchIndustrialTxData" class="ui-btn-secondary px-2 py-0.5 text-[11px]">
                <AppIcon name="refresh" :size="11" />
                <span>刷新</span>
              </button>
              <button @click="isIndustrialTxOpen = false" class="p-1 cursor-pointer" style="color: var(--text-muted);">
                <AppIcon name="close" :size="12" />
              </button>
            </div>
          </div>
          <div class="overflow-y-auto custom-scrollbar max-h-36 border rounded-lg p-1.5 space-y-1" style="background: var(--surface-content); border-color: var(--border-subtle);">
            <div v-if="recentIndustrialTxs.length === 0" class="text-center py-3 text-[11px]" style="color: var(--text-muted);">
              暂无完整配对工控事务记录（捕获 Modbus / S7 等主从请求与响应包后将自动计算微秒级往返时延）。
            </div>
            <div v-for="tx in recentIndustrialTxs" :key="tx.id" class="flex items-center justify-between px-2 py-1 rounded bg-[var(--surface-sub)] text-[11px] ui-num">
              <span class="text-blue-600 dark:text-sky-300">{{ tx.req_time }} | {{ tx.client_ip }} → {{ tx.server_ip }} [{{ tx.protocol }} FC:0x{{ tx.function_code.toString(16) }}]</span>
              <span class="truncate max-w-xs mx-2" style="color: var(--text-secondary);">{{ tx.summary }}</span>
              <span :class="tx.status === 'SUCCESS' ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'" class="font-semibold shrink-0">
                {{ tx.status }} ({{ tx.plc_latency_ms.toFixed(2) }}ms)
              </span>
            </div>
          </div>
        </div>

        <!-- 多分辨率时序桶与高频交互通信对热力矩阵抽屉 -->
        <div v-if="isTimeseriesHeatmapOpen" class="px-3 py-2.5 border-b flex flex-col gap-2 text-xs shrink-0 max-h-56 overflow-hidden" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-primary);">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="flex items-center gap-3 flex-wrap ui-num">
              <span class="text-indigo-600 dark:text-indigo-300 font-semibold flex items-center gap-1">
                <AppIcon name="radar" :size="13" />
                <span>多分辨率时序与交互通信矩阵热力榜</span>
              </span>
              <select v-model="tsResolution" @change="fetchTimeseriesHeatmapData" class="ui-input px-2 py-0.5 text-[11px]">
                <option value="1s">1 秒粒度桶</option>
                <option value="10s">10 秒粒度桶</option>
                <option value="60s">60 秒粒度桶</option>
                <option value="1h">1 小时粒度桶</option>
              </select>
              <span style="color: var(--text-muted);">活跃时间桶: <b style="color: var(--text-primary);">{{ tsBuckets.length }}</b> 个</span>
              <span style="color: var(--text-muted);">热点通信对: <b class="text-blue-600 dark:text-sky-300">{{ heatmapCells.length }}</b> 组</span>
            </div>
            <div class="flex items-center gap-1.5">
              <button @click="fetchTimeseriesHeatmapData" class="ui-btn-secondary px-2 py-0.5 text-[11px]">
                <AppIcon name="refresh" :size="11" />
                <span>刷新</span>
              </button>
              <button @click="isTimeseriesHeatmapOpen = false" class="p-1 cursor-pointer" style="color: var(--text-muted);">
                <AppIcon name="close" :size="12" />
              </button>
            </div>
          </div>
          <div class="grid grid-cols-12 gap-2 overflow-hidden">
            <div class="col-span-7 overflow-y-auto custom-scrollbar max-h-36 border rounded-lg p-1.5 space-y-1" style="background: var(--surface-content); border-color: var(--border-subtle);">
              <div v-if="heatmapCells.length === 0" class="text-center py-3 text-[11px]" style="color: var(--text-muted);">暂无统计窗口通信矩阵数据</div>
              <div v-for="(c, idx) in heatmapCells" :key="idx" class="flex items-center justify-between px-2 py-1 rounded text-[11px] ui-num">
                <span style="color: var(--text-primary);">{{ c.source_ip }} → {{ c.dest_ip }}</span>
                <span style="color: var(--text-muted);">交互 {{ c.interaction_count }} 次 | {{ (c.total_bytes / 1024).toFixed(1) }} KB</span>
                <span :class="c.error_count > 0 ? 'text-rose-600 dark:text-rose-400' : (c.is_industrial ? 'text-amber-600 dark:text-amber-300' : 'text-emerald-600 dark:text-emerald-400')">
                  {{ c.is_industrial ? '工控流' : '通用流' }} (写:{{ c.write_operation_count }}/错:{{ c.error_count }})
                </span>
              </div>
            </div>
            <div class="col-span-5 flex flex-col gap-1 max-h-36 border rounded-lg p-1.5" style="background: var(--surface-content); border-color: var(--border-subtle);">
              <div v-if="tsBuckets.length === 0" class="text-center py-6 text-[11px]" style="color: var(--text-muted);">暂无时序聚合桶记录</div>
              <template v-else>
                <div class="h-14 rounded bg-slate-950/85 border border-white/10 px-1 py-0.5 shrink-0 flex items-center">
                  <svg v-if="tsBuckets.length >= 2" viewBox="0 0 320 48" class="w-full h-full">
                    <polyline :points="tsPktPolyline" fill="none" stroke="#38bdf8" stroke-width="1.6" stroke-linejoin="round" />
                    <polyline :points="tsIndPolyline" fill="none" stroke="#f59e0b" stroke-width="1.4" stroke-dasharray="3 2" stroke-linejoin="round" />
                  </svg>
                  <div v-else class="w-full text-center text-[10px] text-slate-400">单时间桶等待延续...</div>
                </div>
                <div class="overflow-y-auto custom-scrollbar space-y-0.5 flex-1">
                  <div v-for="(b, idx) in tsBuckets.slice(-8).reverse()" :key="idx" class="flex items-center justify-between px-2 py-0.5 rounded text-[10px] ui-num">
                    <span style="color: var(--text-muted);">@{{ new Date(b.slot_timestamp_s * 1000).toLocaleTimeString() }}</span>
                    <span class="text-blue-600 dark:text-sky-300">{{ b.packet_count }} 帧 / {{ b.byte_count }} B</span>
                    <span class="text-amber-600 dark:text-amber-300">工控 {{ b.industrial_packet_count }}</span>
                  </div>
                </div>
              </template>
            </div>
          </div>
        </div>
        </div>

        <!-- 全贯穿虚拟滚动表格容器 (透明透景底衬 + 顶底渐变羽化 + 滚动穿越悬浮栏) -->
        <div ref="tableContainer" @scroll="onScroll" class="flex-1 overflow-auto custom-scrollbar relative min-h-0 select-text bg-transparent liquid-scroll-fade">
          <!-- 非特权/缺驱动外网降级明确阻断警示横幅 -->
          <div
            v-if="isRunning && captureCapability && !captureCapability.external_ready"
            class="mx-3 mt-[62px] mb-1 rounded-2xl border border-amber-500/45 bg-amber-500/12 px-3.5 py-2.5 flex items-center justify-between gap-3 text-xs z-30 relative shadow-xs"
          >
            <div class="flex items-start gap-2 min-w-0">
              <AppIcon name="alert" :size="15" class="text-amber-600 dark:text-amber-300 shrink-0 mt-0.5" />
              <div class="min-w-0 space-y-0.5">
                <div class="font-bold text-amber-800 dark:text-amber-200">
                  外网捕获通道受限（当前仅局域网多播/ARP 雷达运行中）
                </div>
                <div class="text-[11px] leading-snug text-amber-900/85 dark:text-amber-100/85">
                  {{ captureCapability.reason }}
                </div>
              </div>
            </div>
            <button
              @click="$emit('openEnvInspector')"
              class="ui-btn-primary px-3 py-1.5 rounded-xl text-[11px] font-semibold shrink-0 whitespace-nowrap"
            >
              环境自检 / 安装 Npcap
            </button>
          </div>

          <div :style="{ minWidth: totalTableMinWidth }">
            <!-- 顶部穿透让位垫片：未开上部工具抽屉与降级横幅时确保初始表头对齐悬浮控制栏下方 -->
            <div v-if="!(isReplayPanelOpen || isIndustrialTxOpen || isTimeseriesHeatmapOpen || (isRunning && captureCapability && !captureCapability.external_ready))" class="h-[60px] shrink-0 pointer-events-none"></div>
            <!-- 表头 (悬浮停靠在控制栏下方，允许下方滚动数据行穿透上方玻璃条) -->
            <div
              :class="['ui-table-head sticky z-20 px-3.5 py-2.5 items-center tracking-wider select-none', (isReplayPanelOpen || isIndustrialTxOpen || isTimeseriesHeatmapOpen || (isRunning && captureCapability && !captureCapability.external_ready)) ? 'top-0' : 'top-[60px]']"
              :style="gridTemplateStyle"
            >
              <div v-for="(col, idx) in visibleColumns" :key="col.key" class="relative group flex items-center justify-between pr-2.5 h-full min-w-0">
                <div
                  @click="col.sortable ? toggleSort(col.key) : null"
                  :class="['truncate flex items-center gap-0.5 min-w-0 flex-1', col.sortable ? 'cursor-pointer hover:text-blue-500' : '']"
                  :title="`${getColumnLabel(col)} (点击排序)`"
                >
                  <span class="truncate">{{ getColumnLabel(col) }}</span>
                  <span v-if="col.sortable && sortKey === col.key" class="text-blue-500 font-bold ml-0.5 shrink-0">
                    {{ sortAsc ? '▲' : '▼' }}
                  </span>
                </div>
                <div
                  class="absolute -right-1 top-0 bottom-0 w-3 cursor-col-resize flex items-center justify-center hover:bg-blue-500/20 active:bg-blue-500 transition-colors z-30 select-none"
                  :class="resizingColumnKey === col.key ? 'bg-blue-500/30' : ''"
                  @mousedown.stop.prevent="startColResize($event, idx)"
                  @dblclick.stop.prevent="resetColWidth(idx)"
                >
                  <div class="w-[1px] h-3 group-hover:bg-blue-500 transition-colors" style="background: var(--border-strong);"></div>
                </div>
              </div>
            </div>

            <!-- 虚拟滚动行 -->
            <div :style="{ height: totalHeight + 'px', position: 'relative' }">
              <div :style="{ transform: `translateY(${offsetY}px)`, position: 'absolute', top: 0, left: 0, right: 0 }">
                <div
                  v-for="(pkt, vIdx) in visiblePackets"
                  :key="pkt.id"
                  @click="handleRowClick($event, pkt, startIdx + vIdx)"
                  @dblclick="openDetailModal(pkt)"
                  @contextmenu.prevent="openContextMenu($event, pkt)"
                  :style="{ ...gridTemplateStyle, borderColor: 'var(--border-subtle)' }"
                  :class="[
                    'h-[34px] px-3.5 text-xs border-b cursor-pointer items-center transition-colors overflow-hidden',
                    selectedPacket?.id === pkt.id ? 'bg-blue-500/12 border-l-[3px] border-blue-500 font-semibold' :
                    selectedPackets.has(pkt.id) ? 'bg-indigo-500/12' :
                    pkt.entropy_level === 'critical' ? 'bg-rose-500/8 hover:bg-rose-500/15' :
                    'hover:bg-[var(--surface-hover)]'
                  ]"
                >
                  <!-- 1. 序号 -->
                  <div v-if="isColVisible('id')" class="font-semibold text-blue-600 dark:text-sky-400 ui-num min-w-0 truncate flex items-center gap-1.5" :title="`报文帧序号 #${pkt.id}`">
                    <input
                      type="checkbox"
                      :checked="selectedPackets.has(pkt.id)"
                      @click.stop="togglePacketCheck(pkt)"
                      class="rounded focus:ring-0 cursor-pointer w-3.5 h-3.5 shrink-0 accent-blue-600"
                    />
                    <span class="truncate">#{{ pkt.id }}</span>
                  </div>

                  <!-- 2. 精准时间 -->
                  <div v-if="isColVisible('timestamp')" class="text-[11px] ui-num truncate min-w-0" style="color: var(--text-muted);" :title="pkt.timestamp">
                    {{ pkt.timestamp }}
                  </div>

                  <!-- 3. 源端点 -->
                  <div v-if="isColVisible('src_endpoint')" class="text-[11px] truncate ui-num flex items-center gap-1 min-w-0" :title="formatEndpointTitle(pkt.src_ip, pkt.src_port, pkt)">
                    <template v-if="pkt.transport === 'SERIAL' || pkt.direction?.startsWith('SERIAL')">
                      <span :class="['font-semibold shrink-0 flex items-center gap-1 px-1.5 py-0.5 rounded border text-[11px]', getSerialBadgeStyle(pkt.src_ip || 'COM')]">
                        <AppIcon name="serial" :size="11" />
                        <span>{{ pkt.src_ip || 'COM' }}</span>
                      </span>
                    </template>
                    <template v-else-if="pkt.transport === 'USB' || pkt.direction?.startsWith('USB')">
                      <span class="font-semibold text-purple-600 dark:text-purple-300 shrink-0 flex items-center gap-1">
                        <AppIcon name="usb" :size="11" />
                        <span>{{ pkt.src_ip || 'USB' }}</span>
                      </span>
                    </template>
                    <template v-else>
                      <span
                        class="font-semibold truncate hover:text-blue-500 hover:underline cursor-pointer transition-colors"
                        style="color: var(--text-primary);"
                        @click.stop="openIpDossier(pkt.src_ip)"
                        title="点击查阅该 IP 全息档案"
                      >
                        {{ formatEndpoint(pkt.src_ip, pkt.src_port) }}
                      </span>
                      <span
                        v-if="getRemoteIpTag(pkt)"
                        class="text-[11px] text-blue-700 dark:text-sky-300 px-1.5 py-0.5 rounded bg-blue-500/12 border border-blue-500/25 shrink-0 font-medium"
                        :title="getRemoteIpLocation(pkt)"
                      >
                        {{ getRemoteIpTag(pkt) }}
                      </span>
                    </template>
                  </div>

                  <!-- 4. 目标端点 -->
                  <div v-if="isColVisible('dst_endpoint')" class="text-[11px] ui-num truncate min-w-0" :title="formatEndpointTitle(pkt.dst_ip, pkt.dst_port, pkt, true)">
                    <span
                      class="truncate hover:text-blue-500 hover:underline cursor-pointer transition-colors font-medium"
                      style="color: var(--text-primary);"
                      @click.stop="openIpDossier(pkt.dst_ip)"
                    >
                      {{ formatEndpoint(pkt.dst_ip, pkt.dst_port) }}
                    </span>
                    <span
                      v-if="getEndpointTag(pkt, true)"
                      class="text-[11px] text-blue-700 dark:text-sky-300 px-1.5 py-0.5 rounded bg-blue-500/12 border border-blue-500/25 shrink-0 font-medium ml-1"
                      :title="getEndpointLocation(pkt, true)"
                    >
                      {{ getEndpointTag(pkt, true) }}
                    </span>
                  </div>

                  <!-- 5. 规约协议 -->
                  <div v-if="isColVisible('protocol')" class="min-w-0 truncate">
                    <span :class="['px-2 py-0.5 rounded text-[11px] font-semibold truncate block max-w-full', protocolColor(pkt.protocol)]">
                      {{ pkt.protocol }}
                    </span>
                  </div>

                  <!-- 6. 载荷大小 -->
                  <div v-if="isColVisible('length')" class="text-[11px] ui-num truncate min-w-0 text-right pr-2 font-medium" style="color: var(--text-secondary);">
                    {{ pkt.length }} B
                  </div>

                  <!-- 7. 应用层解析关键信息 -->
                  <div v-if="isColVisible('l7_summary')" class="text-[11px] font-mono truncate min-w-0 flex items-center gap-1.5" :title="getPacketL7Summary(pkt)">
                    <span v-if="pkt.entropy_level === 'critical'" class="w-1.5 h-1.5 rounded-full bg-rose-500 shrink-0"></span>

                    <template v-if="parseL7StructuredSummary(pkt).kind === 'sys_ctrl'">
                      <span :class="['px-1.5 py-0.5 rounded text-[11px] border font-mono shrink-0', parseL7StructuredSummary(pkt).badgeClass]">
                        {{ parseL7StructuredSummary(pkt).badge }}
                      </span>
                      <span :class="['px-1.5 py-0.5 rounded text-[11px] font-semibold font-mono shrink-0', parseL7StructuredSummary(pkt).actionClass]">
                        {{ parseL7StructuredSummary(pkt).action }}
                      </span>
                      <span class="truncate font-mono font-medium" style="color: var(--text-primary);">
                        {{ parseL7StructuredSummary(pkt).detail }}
                      </span>
                    </template>

                    <template v-else-if="parseL7StructuredSummary(pkt).kind === 'ascii_hex'">
                      <span class="px-1.5 py-0.5 rounded text-[11px] font-semibold font-mono bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-500/25 shrink-0">
                        ASCII
                      </span>
                      <span class="truncate max-w-[220px] font-mono font-medium" style="color: var(--text-primary);">
                        {{ parseL7StructuredSummary(pkt).asciiText }}
                      </span>
                      <span style="color: var(--text-muted);">|</span>
                      <span class="px-1.5 py-0.5 rounded text-[11px] font-semibold font-mono bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/25 shrink-0">
                        HEX
                      </span>
                      <span class="truncate font-mono text-[11px]" style="color: var(--text-secondary);">
                        {{ parseL7StructuredSummary(pkt).hexText }}
                      </span>
                    </template>

                    <template v-else-if="parseL7StructuredSummary(pkt).kind === 'key_val'">
                      <span class="font-semibold text-blue-700 dark:text-sky-300 shrink-0">
                        {{ parseL7StructuredSummary(pkt).prefix }}
                      </span>
                      <span style="color: var(--text-muted);">|</span>
                      <span class="truncate font-mono font-medium" style="color: var(--text-primary);">
                        {{ parseL7StructuredSummary(pkt).body }}
                      </span>
                    </template>

                    <template v-else>
                      <span :class="['truncate font-mono font-medium', pkt.entropy_level === 'critical' ? 'text-rose-600 dark:text-rose-300 font-semibold' : '']" :style="pkt.entropy_level === 'critical' ? {} : { color: 'var(--text-primary)' }">
                        {{ parseL7StructuredSummary(pkt).plainText }}
                      </span>
                    </template>
                  </div>

                  <!-- 高级扩展列 -->
                  <div v-if="isColVisible('direction')" class="min-w-0 truncate">
                    <span :class="['px-1.5 py-0.5 rounded text-[11px] font-semibold border inline-block truncate max-w-full', directionBadgeClass(pkt.direction)]">
                      {{ pkt.direction === 'HONEYPOT_RECV' ? '诱捕' : pkt.direction }}
                    </span>
                  </div>

                  <div
                    v-if="isColVisible('transport')"
                    class="text-[11px] font-semibold truncate min-w-0"
                    :class="pkt.transport === 'SERIAL' ? 'text-indigo-600 dark:text-indigo-300' : pkt.transport === 'USB' ? 'text-purple-600 dark:text-purple-300' : ''"
                    :style="pkt.transport === 'SERIAL' || pkt.transport === 'USB' ? {} : { color: 'var(--text-secondary)' }"
                  >
                    {{ pkt.transport }}
                  </div>

                  <div v-if="isColVisible('entropy')" class="text-[11px] ui-num truncate min-w-0">
                    <span
                      :class="[
                        pkt.entropy >= 7.5 ? 'text-rose-700 dark:text-rose-300 font-semibold bg-rose-500/15 px-1.5 py-0.5 rounded border border-rose-500/25' :
                        pkt.entropy >= 6.0 ? 'text-amber-700 dark:text-amber-300 font-semibold bg-amber-500/15 px-1.5 py-0.5 rounded border border-amber-500/25' :
                        'text-[var(--text-muted)]'
                      ]"
                    >
                      {{ pkt.entropy ? pkt.entropy.toFixed(2) : '0.00' }}
                    </span>
                  </div>

                  <div v-if="isColVisible('mac_src')" class="text-[11px] font-mono truncate min-w-0" style="color: var(--text-muted);" :title="pkt.mac_src">
                    {{ pkt.mac_src || 'N/A' }}
                  </div>

                  <div v-if="isColVisible('payload')" class="text-[11px] truncate font-mono min-w-0" style="color: var(--text-secondary);" :title="pkt.raw_text || pkt.payload_hex">
                    {{ pkt.raw_text || pkt.payload_hex }}
                  </div>
                </div>
              </div>
            </div>
            <!-- 底部穿透垫片：仅在存在报文列表时撑开末尾，确保最底行可滚动越过 Dock 完整查阅 -->
            <div v-if="filteredPackets.length > 0" class="h-[68px] shrink-0 pointer-events-none"></div>
          </div>
        </div>

        <!-- 空状态引导工作台 (严格零造假，避让上下悬浮玻璃栏居中，直显四大物理/无线总线入口) -->
        <div
          v-if="filteredPackets.length === 0"
          class="absolute inset-x-0 top-20 bottom-20 flex items-center justify-center z-10 px-6"
        >
          <div v-if="packets.length === 0" class="max-w-3xl w-full flex flex-col items-center text-center gap-4">
            <div class="w-12 h-12 rounded-2xl ui-nav-glass flex items-center justify-center text-[var(--accent-primary-text)] shadow-sm">
              <AppIcon name="radar" :size="24" />
            </div>
            <div class="space-y-1">
              <h3 class="text-[15px] font-semibold tracking-tight" style="color: var(--text-primary);">
                全总线工业网络分析引擎已就绪
              </h3>
              <p class="text-xs max-w-xl mx-auto leading-relaxed" style="color: var(--text-muted);">
                同时支持物理网卡、COM 串口、USB 描述符/URB 及无线 Wi-Fi / 蓝牙四大物理通信通道，请选择下方任一总线入口直接启动：
              </p>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 w-full text-left">
              <!-- 1. NIC 网卡捕获 -->
              <button @click="$emit('startCapture')"
                class="ui-sub-card p-3.5 rounded-2xl hover:border-[var(--accent-primary)]/45 hover:bg-[var(--surface-hover)] transition-all cursor-pointer group flex flex-col gap-2">
                <div class="flex items-center justify-between">
                  <div class="w-8 h-8 rounded-xl bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)] flex items-center justify-center">
                    <AppIcon name="play" :size="15" />
                  </div>
                  <span class="ui-pill text-[11px] ui-num px-2 py-0.5 rounded-full">
                    {{ interfaces.length }} 网卡
                  </span>
                </div>
                <div>
                  <div class="text-xs font-semibold flex items-center justify-between" style="color: var(--text-primary);">
                    <span>网卡捕获 (NIC)</span>
                    <AppIcon name="arrow-right" :size="12" class="opacity-50 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                  <p class="text-[11px] mt-1 leading-snug" style="color: var(--text-muted);">启用 Npcap / Raw Socket 实时抓取 L2–L7 流量</p>
                </div>
              </button>

              <!-- 2. COM 物理串口 -->
              <button @click="$emit('switchWorkbench', 'hardware')"
                class="ui-sub-card p-3.5 rounded-2xl hover:border-indigo-500/45 hover:bg-[var(--surface-hover)] transition-all cursor-pointer group flex flex-col gap-2">
                <div class="flex items-center justify-between">
                  <div class="w-8 h-8 rounded-xl bg-indigo-500/14 text-indigo-600 dark:text-indigo-300 border border-indigo-500/20 flex items-center justify-center">
                    <AppIcon name="serial" :size="15" />
                  </div>
                  <span class="ui-pill text-[11px] ui-num px-2 py-0.5 rounded-full">
                    {{ serialPorts.length }} 串口
                  </span>
                </div>
                <div>
                  <div class="text-xs font-semibold flex items-center justify-between" style="color: var(--text-primary);">
                    <span>COM 串口总线</span>
                    <AppIcon name="arrow-right" :size="12" class="opacity-50 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                  <p class="text-[11px] mt-1 leading-snug" style="color: var(--text-muted);">
                    {{ serialPorts.length > 0 ? `已就绪 ${selectedSerial || serialPorts[0]}，支持 RS-232/485 监听与收发` : '查看物理串口清单、波特率配置与双向交互' }}
                  </p>
                </div>
              </button>

              <!-- 3. USB 总线与 URB -->
              <button @click="$emit('switchWorkbench', 'hardware')"
                class="ui-sub-card p-3.5 rounded-2xl hover:border-purple-500/45 hover:bg-[var(--surface-hover)] transition-all cursor-pointer group flex flex-col gap-2">
                <div class="flex items-center justify-between">
                  <div class="w-8 h-8 rounded-xl bg-purple-500/14 text-purple-600 dark:text-purple-300 border border-purple-500/20 flex items-center justify-center">
                    <AppIcon name="usb" :size="15" />
                  </div>
                  <span class="ui-pill text-[11px] ui-num px-2 py-0.5 rounded-full">
                    {{ usbDevices.length }} 设备
                  </span>
                </div>
                <div>
                  <div class="text-xs font-semibold flex items-center justify-between" style="color: var(--text-primary);">
                    <span>USB 外设总线</span>
                    <AppIcon name="arrow-right" :size="12" class="opacity-50 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                  <p class="text-[11px] mt-1 leading-snug" style="color: var(--text-muted);">物理 USB 设备画像、PnP 热插拔审计与 URB 解析</p>
                </div>
              </button>

              <!-- 4. Wi-Fi 与蓝牙无线 -->
              <button @click="$emit('openWireless')"
                class="ui-sub-card p-3.5 rounded-2xl hover:border-sky-500/45 hover:bg-[var(--surface-hover)] transition-all cursor-pointer group flex flex-col gap-2">
                <div class="flex items-center justify-between">
                  <div class="w-8 h-8 rounded-xl bg-sky-500/14 text-sky-600 dark:text-sky-300 border border-sky-500/20 flex items-center justify-center">
                    <AppIcon name="wifi" :size="15" />
                  </div>
                  <span class="ui-pill text-[11px] ui-num px-2 py-0.5 rounded-full">
                    Wi-Fi · BLE
                  </span>
                </div>
                <div>
                  <div class="text-xs font-semibold flex items-center justify-between" style="color: var(--text-primary);">
                    <span>无线 Wi-Fi / 蓝牙</span>
                    <AppIcon name="arrow-right" :size="12" class="opacity-50 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                  <p class="text-[11px] mt-1 leading-snug" style="color: var(--text-muted);">802.11 频谱热力、BLE HCI 距离雷达与单帧解码</p>
                </div>
              </button>
            </div>

            <button @click="isImportOpen = true"
              class="ui-pill px-4 py-1.5 rounded-full text-xs font-medium flex items-center gap-2 cursor-pointer hover:bg-[var(--surface-glass-pill-hover)]">
              <AppIcon name="upload" :size="13" />
              <span>或导入本地 .pcap / .pcapng 离线数据包执行还原分析</span>
            </button>
          </div>

          <EmptyState
            v-else
            icon="search"
            title="未找到匹配当前条件的报文"
            description="已捕获的报文均不符合当前过滤条件，请调整关键词或切换协议范围。"
          >
            <template #actions>
              <button @click="clearDisplayFilter(); filterProtocol = ''" class="ui-btn-secondary px-3 py-1 text-xs">
                重置所有筛选条件
              </button>
            </template>
          </EmptyState>
        </div>

        <!-- 多选快捷操作悬浮舱 -->
        <div
          v-if="selectedPackets.size >= 2"
          class="ui-modal-surface absolute bottom-14 left-1/2 -translate-x-1/2 z-30 px-4 py-2 rounded-2xl flex items-center gap-3 select-none"
        >
          <span class="lens-edge-lip" aria-hidden="true"></span>
          <div class="flex items-center gap-2 text-xs font-semibold text-indigo-600 dark:text-indigo-300 ui-num">
            <span class="w-2 h-2 rounded-full bg-indigo-500"></span>
            <span>已选定 <strong style="color: var(--text-primary);">{{ selectedPackets.size }}</strong> 帧报文</span>
          </div>

          <div class="h-4 w-px" style="background: var(--border-strong);"></div>

          <div class="flex items-center gap-2 text-xs">
            <button v-if="selectedPackets.size === 2" @click="openDiffWithSelected2" class="ui-btn-primary px-3 py-1 text-xs">
              <AppIcon name="scale" :size="13" />
              <span>双报文差分 (A vs B)</span>
            </button>
            <button @click="openGlobalMultiDiffWithSelected" class="ui-btn-primary px-3 py-1 text-xs">
              <AppIcon name="git-branch" :size="13" />
              <span>送入全局多组精密比对 ({{ selectedPackets.size }})</span>
            </button>
            <button @click="openMatrixTab" class="ui-btn-secondary px-2.5 py-1 text-xs">
              <AppIcon name="layers" :size="13" />
              <span>侧栏矩阵</span>
            </button>
            <button @click="saveSelectedPacketsAsBaseline" class="ui-btn-secondary px-2.5 py-1 text-xs">
              <AppIcon name="archive" :size="13" />
              <span>存为特征基线</span>
            </button>
            <button @click="clearSelectedPackets" class="ui-btn-secondary px-2 py-1 text-xs">
              <AppIcon name="close" :size="12" />
              <span>取消</span>
            </button>
          </div>
        </div>

        <!-- 底部悬浮贯穿控制岛 (Floating Liquid Glass Dock Over Stream) -->
        <div class="pointer-events-none absolute bottom-3 inset-x-3 flex justify-center z-40 overflow-x-auto custom-scrollbar-none">
          <div class="bottom-liquid-dock pointer-events-auto relative">
            <span class="lens-edge-lip" aria-hidden="true"></span>
            <div class="scope-group">
              <button class="scope-btn" :class="{ active: currentScopeFilter === 'all' }" @click="setScope('all')" title="全量流量 (快捷键 0)">
                <span>全量流</span>
                <span class="kbd-badge">0</span>
              </button>
              <button class="scope-btn" :class="{ active: currentScopeFilter === 'alert' }" @click="setScope('alert')" title="告警与高熵快筛 (快捷键 A)">
                <AppIcon name="alert" :size="12" class="text-rose-500" />
                <span>告警</span>
                <span class="kbd-badge">A</span>
              </button>
              <button class="scope-btn" :class="{ active: currentScopeFilter === 'industrial' }" @click="setScope('industrial')" title="仅显示工控 OT 规约 (快捷键 I)">
                <AppIcon name="zap" :size="12" class="text-amber-500" />
                <span>工控</span>
                <span class="kbd-badge">I</span>
              </button>
              <button class="scope-btn" :class="{ active: currentScopeFilter === 'serial_usb' }" @click="setScope('serial_usb')" title="仅显示物理总线 (快捷键 B)">
                <AppIcon name="usb" :size="12" class="text-indigo-500" />
                <span>总线</span>
                <span class="kbd-badge">B</span>
              </button>
            </div>

            <div class="telemetry-capsule shrink-0">
              <div class="flex items-center gap-1">
                <span class="opacity-65 text-[11px] hidden xl:inline">速率:</span>
                <b class="ui-num" style="color: var(--text-primary);">{{ telemetryThroughputMbps }}M</b>
              </div>
              <span class="opacity-20">|</span>
              <div class="flex items-center gap-1">
                <span class="opacity-65 text-[11px] hidden xl:inline">包率:</span>
                <b class="ui-num" style="color: var(--text-primary);">{{ telemetryPps.toLocaleString() }}pps</b>
              </div>
              <span class="opacity-20">|</span>
              <div class="flex items-center gap-1">
                <span class="opacity-65 text-[11px] hidden xl:inline">总帧:</span>
                <b class="text-blue-600 dark:text-sky-400 ui-num">{{ packets.length.toLocaleString() }}</b>
              </div>
            </div>

            <div class="flex items-center gap-1 shrink-0">
              <button class="action-deck-btn" :class="{ active: isAutoScroll }" @click="isAutoScroll = !isAutoScroll" title="开启/关闭随流滚屏 (快捷键 S)">
                <span>随流滚屏</span>
                <span class="kbd-badge">S</span>
              </button>
              <button class="action-deck-btn" :class="{ active: isPaused }" @click="isPaused ? $emit('resumeCapture') : $emit('pauseCapture')" title="暂停/恢复嗅探 (快捷键 Space)">
                <AppIcon :name="isPaused ? 'play' : 'pause'" :size="12" />
                <span>{{ isPaused ? '恢复' : '暂停' }}</span>
                <span class="kbd-badge">Space</span>
              </button>
              <button class="action-deck-btn" @click="$emit('clearData')" title="清空缓冲区 (快捷键 ⌥K)">
                <span>清空</span>
                <span class="kbd-badge">⌥K</span>
              </button>
              <button class="action-deck-btn" @click="isExportOpen = true" title="导出当前 PCAPng 原始包 (快捷键 ⌘E)">
                <span>导出</span>
                <span class="kbd-badge">⌘E</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- 3.2 随行协议解构抽屉 (Adaptive Inspector Drawer) -->
      <aside
        :class="[
          'flex flex-col border-l shrink-0 overflow-hidden transition-all duration-300 ease-[cubic-bezier(0.25,1,0.5,1)] z-30 select-text',
          isInspectorOpen ? 'w-[300px] xl:w-[350px] 2xl:w-[400px] max-w-[38%] opacity-100' : 'w-0 opacity-0 pointer-events-none'
        ]"
        style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-primary);"
      >
        <div class="px-4 py-2.5 border-b flex items-center justify-between shrink-0" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2.5 min-w-0">
            <div class="drawer-icon-capsule text-blue-500">
              <AppIcon name="code" :size="14" />
            </div>
            <div class="min-w-0">
              <div class="text-xs font-semibold tracking-tight truncate" style="color: var(--text-primary);">随行协议解构 (Inspector)</div>
              <div class="text-[11px] ui-num truncate max-w-[180px]" style="color: var(--text-muted);" v-if="selectedPacket">
                帧 #{{ selectedPacket.id }} · {{ selectedPacket.protocol }} · {{ selectedPacket.length }}B
              </div>
            </div>
          </div>

          <div class="flex items-center gap-1.5 shrink-0">
            <button v-if="selectedPacket" @click="queuePacketForDiff(selectedPacket)"
              class="px-2 py-1 rounded-lg bg-emerald-500/12 hover:bg-emerald-500 text-emerald-700 dark:text-emerald-300 hover:text-white border border-emerald-500/30 text-[11px] font-semibold cursor-pointer transition-colors"
              title="加入全局多组比对队列">
              + 入队比对
            </button>
            <div class="flex glass-pill p-0.5 rounded-xl text-[11px]">
              <button @click="activeBottomTab = 'hexdump'" :class="['px-2 py-0.5 rounded-lg transition-all cursor-pointer font-medium', activeBottomTab === 'hexdump' ? 'bg-[var(--accent-primary)] text-white font-semibold shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']">L7</button>
              <button @click="activeBottomTab = 'tracemap'" :class="['px-2 py-0.5 rounded-lg transition-all cursor-pointer font-medium flex items-center gap-1', activeBottomTab === 'tracemap' ? 'bg-[var(--accent-primary)] text-white font-semibold shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']" title="查看本地 IP 到目标 IP 的网络 Trace 与 MAP 态势图">
                <AppIcon name="globe" :size="11" />
                <span>Trace/MAP</span>
              </button>
              <button @click="activeBottomTab = 'dialogue'" :class="['px-2 py-0.5 rounded-lg transition-all cursor-pointer font-medium', activeBottomTab === 'dialogue' ? 'bg-[var(--accent-primary)] text-white font-semibold shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']">会话</button>
              <button @click="activeBottomTab = 'iographs'" :class="['px-2 py-0.5 rounded-lg transition-all cursor-pointer font-medium', activeBottomTab === 'iographs' ? 'bg-[var(--accent-primary)] text-white font-semibold shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']">IO图</button>
              <button @click="activeBottomTab = 'wave'" :class="['px-2 py-0.5 rounded-lg transition-all cursor-pointer font-medium', activeBottomTab === 'wave' ? 'bg-[var(--accent-primary)] text-white font-semibold shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']">示波</button>
            </div>
            <button @click="isInspectorOpen = false" class="drawer-close-btn" title="收起随行解构抽屉 (ESC 或 R)">
              <AppIcon name="close" :size="13" />
            </button>
          </div>
        </div>

        <!-- 子视图 1: 默认 L7 深度解构与 HexDump -->
        <div v-if="activeBottomTab === 'hexdump'" class="flex-1 overflow-y-auto p-3.5 space-y-3 text-xs custom-scrollbar">
          <template v-if="selectedPacket">
            <div class="apple-group-card space-y-1.5">
              <div class="group-card-title">
                <span>传输与网络层拓扑 (L2 - L4)</span>
                <span class="badge-subtle">{{ selectedPacket.transport || 'TCP' }}</span>
              </div>
              <div class="text-[11px] leading-relaxed ui-num space-y-0.5" style="color: var(--text-secondary);">
                <div>Ethernet II · <span class="font-mono">{{ selectedPacket.mac_src || '--' }}</span> → <span class="font-mono">{{ selectedPacket.mac_dst || '--' }}</span></div>
                <div>IP · <span class="font-semibold" style="color: var(--text-primary);">{{ selectedPacket.src_ip || '--' }}</span> → <span class="font-semibold" style="color: var(--text-primary);">{{ selectedPacket.dst_ip || '--' }}</span></div>
                <div class="text-blue-600 dark:text-sky-300 font-medium">端口: <span>{{ selectedPacket.src_port || '-' }}</span> → <span>{{ selectedPacket.dst_port || '-' }}</span></div>
              </div>
            </div>

            <!-- 本地 IP 到目标 IP 的网络 Trace 跃点拓扑与地理 MAP 态势速览 (用户报文流点击核心诉求) -->
            <div class="apple-group-card p-2.5">
              <PacketTraceMapView
                :packet="selectedPacket"
                :compact="true"
                @openFullTraceroute="openTraceroute"
                @appendLog="msg => emit('appendLog', msg)"
              />
            </div>

            <div class="apple-group-card space-y-2">
              <div class="group-card-title">
                <span style="color: var(--text-primary);">{{ l7DecodedTree.protocolTitle }}</span>
                <span class="badge-subtle text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/10">{{ l7DecodedTree.statusBadge }}</span>
              </div>
              <div class="space-y-1 text-[11px] font-mono">
                <div
                  v-for="(item, idx) in l7DecodedTree.nodes"
                  :key="idx"
                  :class="[
                    'transition-colors group relative flex items-center justify-between py-1 rounded-lg px-2 hover:bg-[var(--surface-hover)]',
                    item.level === 1 ? 'border-l-2 border-amber-500 font-semibold' :
                    item.level === 2 ? 'pl-4 border-l border-blue-500 text-blue-700 dark:text-sky-300' :
                    'pl-6 border-l border-emerald-500 text-emerald-700 dark:text-emerald-300'
                  ]"
                  :style="item.level === 1 ? { color: 'var(--text-primary)' } : {}"
                >
                  <span class="truncate mr-2">{{ item.text }}</span>
                  <div v-if="item.fieldKey" class="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1 shrink-0">
                    <button
                      @click.stop="quickApplyFieldFilter(item.fieldKey, item.fieldValue, '==')"
                      class="text-[11px] px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-700 dark:text-sky-300 border border-blue-500/25 cursor-pointer"
                      title="作为过滤条件应用 (==)"
                    >
                      过滤
                    </button>
                    <button
                      @click.stop="quickApplyFieldFilter(item.fieldKey, item.fieldValue, '!=')"
                      class="text-[11px] px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/25 cursor-pointer"
                      title="排除此字段 (!=)"
                    >
                      排除
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div class="apple-group-card space-y-1.5">
              <div class="group-card-title">
                <span>Raw Hex Payload ({{ selectedPacket.length }} Bytes)</span>
                <button @click="copyHex(selectedPacket.payload_hex)" class="text-blue-600 dark:text-sky-400 hover:underline cursor-pointer text-[11px] flex items-center gap-1">
                  <AppIcon name="document" :size="12" />
                  <span>复制 Hex</span>
                </button>
              </div>
              <div class="hex-container max-h-52 overflow-y-auto custom-scrollbar select-text text-[11px]">
                <div v-for="(line, idx) in formatAlignedHexDump(selectedPacket.payload_hex)" :key="idx" class="leading-relaxed whitespace-pre font-mono">
                  <span style="color: var(--text-muted);">{{ line.slice(0, 6) }}</span>
                  <span style="color: var(--text-primary);">{{ line.slice(6, 54) }}</span>
                  <span class="text-blue-600 dark:text-sky-300 font-semibold">{{ line.slice(54) }}</span>
                </div>
                <div v-if="!selectedPacket.payload_hex" class="text-[11px] py-1" style="color: var(--text-muted);">
                  (无应用层载荷)
                </div>
              </div>
            </div>
          </template>

          <EmptyState
            v-else
            icon="code"
            title="报文深度语义解构视窗"
            description="在左侧列表中点击任意报文，即可实时展开 L2-L7 深度解构与 Hex 对齐视窗。"
          />
        </div>

        <!-- 子视图 1.5: 本地 IP 到目标 IP 专属网络 Trace 与 MAP 全息态势 -->
        <div v-else-if="activeBottomTab === 'tracemap'" class="flex-1 overflow-y-auto p-3.5 space-y-3 text-xs custom-scrollbar">
          <template v-if="selectedPacket">
            <div class="apple-group-card p-3">
              <PacketTraceMapView
                :packet="selectedPacket"
                :compact="false"
                @openFullTraceroute="openTraceroute"
                @appendLog="msg => emit('appendLog', msg)"
              />
            </div>
          </template>
          <EmptyState
            v-else
            icon="globe"
            title="本地 ➔ 目标网络 Trace & 地理 MAP 视窗"
            description="请在左侧报文列表中点击选择任意数据帧，即可实时测算并呈现从本地主机到目标主机的端到端跳数追踪 (Trace) 与地理链路 (MAP) 态势。"
          />
        </div>

        <!-- 子视图 2: 双向会话交互流 -->
        <div v-else-if="activeBottomTab === 'dialogue'" class="flex-1 flex flex-col min-h-0 overflow-hidden p-2">
          <FlowDialogueInspector
            :packets="packets"
            :assets="assets"
            @openDeepDissector="openDetailModal"
            @replayPacket="$emit('replayPacket', $event)"
            @saveBaseline="saveAsBaseline"
          />
        </div>

        <!-- 子视图 3: IO Graphs -->
        <div v-else-if="activeBottomTab === 'iographs'" class="flex-1 flex flex-col min-h-0 overflow-hidden p-2">
          <IoGraphsPanel :packets="packets" />
        </div>

        <!-- 子视图 4: 实时示波波形追踪 -->
        <div v-else-if="activeBottomTab === 'wave'" class="flex-1 overflow-y-auto p-3 space-y-3 text-xs custom-scrollbar">
          <div class="flex items-center justify-between">
            <span class="font-semibold" style="color: var(--text-primary);">载荷示波波形追踪</span>
            <div class="flex items-center gap-1.5">
              <button @click="startWave" :disabled="waveActive" class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 px-2.5 py-1 text-[11px]">
                <AppIcon name="play" :size="11" />
                <span>开始采样</span>
              </button>
              <button @click="stopWave" :disabled="!waveActive" class="ui-btn-danger px-2.5 py-1 text-[11px]">
                <AppIcon name="stop" :size="11" />
                <span>停止</span>
              </button>
            </div>
          </div>
          <div class="h-44 rounded-xl border relative overflow-hidden flex items-center justify-center" style="background: var(--surface-input); border-color: var(--border-subtle);">
            <canvas ref="waveCanvasRef" class="w-full h-full"></canvas>
            <div v-if="wavePoints.length === 0" class="absolute text-[11px]" style="color: var(--text-muted);">
              等待采样数据点流入...
            </div>
          </div>
          <div class="text-[11px] ui-num flex justify-between" style="color: var(--text-muted);">
            <span>峰值: {{ waveMax }}</span>
            <span>谷值: {{ waveMin }}</span>
            <span>点数: {{ wavePoints.length }}</span>
          </div>
        </div>

        <!-- 子视图 5: 多报文矩阵特征比对 -->
        <div v-else-if="activeBottomTab === 'matrix'" class="flex-1 overflow-y-auto p-3 space-y-3 text-xs custom-scrollbar">
          <div class="flex items-center justify-between pb-2 border-b flex-wrap gap-2" style="border-color: var(--border-subtle);">
            <div class="flex items-center gap-2">
              <span class="font-semibold" style="color: var(--text-primary);">多报文矩阵特征比对</span>
              <span class="text-[11px] ui-num px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 font-semibold">
                已载入 {{ matrixPayloads.length }} 组
              </span>
            </div>
            <div class="flex items-center gap-1.5">
              <button @click="openGlobalMultiDiffWithSelected" :disabled="selectedPackets.size < 2" class="ui-btn-primary px-2 py-1 text-[11px]" title="将选中报文组送入全局 Center-Star 居中精密对齐工作台">
                <AppIcon name="git-branch" :size="11" />
                <span>全局 Center-Star</span>
              </button>
              <button @click="runMatrixCompare" :disabled="selectedPackets.size < 2" class="ui-btn-secondary px-2 py-1 text-[11px]">
                <AppIcon name="refresh" :size="11" />
                <span>重算</span>
              </button>
              <button @click="runJointBaselineCompare" class="ui-btn-secondary px-2 py-1 text-[11px]" title="与已固化的历史基线联合比对">
                <span>联合基线</span>
              </button>
              <button @click="exportMatrixReport" :disabled="!matrixResult" class="ui-btn-secondary px-2 py-1 text-[11px]" title="导出矩阵特征分析报告">
                <AppIcon name="download" :size="11" />
                <span>导出</span>
              </button>
            </div>
          </div>

          <template v-if="matrixResult && matrixResult.payloads && matrixResult.payloads.length > 0">
            <div class="rounded-xl p-2.5 border bg-indigo-500/10 border-indigo-500/25 space-y-1">
              <div class="flex items-center justify-between text-[11px] text-indigo-700 dark:text-indigo-300">
                <span class="font-semibold">比对分析概要</span>
                <span>模式: {{ matrixResult.mode || 'LCS 特征对齐' }}</span>
              </div>
              <div class="text-xs" style="color: var(--text-primary);">{{ matrixResult.summary }}</div>
            </div>

            <div v-if="matrixResult?.mutation_spectrum && matrixResult.mutation_spectrum.length > 0" class="ui-sub-card p-3 space-y-2">
              <div class="flex items-center justify-between text-[11px]">
                <div class="flex items-center gap-2">
                  <span class="font-semibold" style="color: var(--text-primary);">多样本变异波率谱与局部信息熵</span>
                  <span class="ui-num" style="color: var(--text-muted);">跨度 {{ matrixResult.mutation_spectrum.length }} 字节</span>
                </div>
                <div v-if="hoverSpectrumBin" class="ui-num text-blue-600 dark:text-sky-300 font-semibold">
                  0x{{ hoverSpectrumBin.offset.toString(16).toUpperCase() }} | 波率 {{ hoverSpectrumBin.mutation_rate.toFixed(1) }}% | 熵 {{ hoverSpectrumBin.entropy.toFixed(2) }}
                </div>
                <span v-else class="text-[11px]" style="color: var(--text-muted);">悬停查看偏移统计</span>
              </div>
              <div class="h-28 relative overflow-hidden flex items-center justify-center">
                <canvas ref="matrixSpectrumCanvas" @mousemove="onMatrixSpectrumHover" @mouseleave="hoverSpectrumBin = null" class="w-full h-full cursor-crosshair"></canvas>
              </div>
            </div>

            <div class="flex items-center gap-3 text-[11px] px-1 flex-wrap" style="color: var(--text-muted);">
              <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-emerald-500"></span>0% 变异</span>
              <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-amber-500"></span>1~50% 抖动</span>
              <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-rose-500"></span>&gt;50% 突变</span>
              <span class="flex items-center gap-1"><span class="w-3 h-0.5 bg-purple-500 inline-block"></span>熵折线</span>
            </div>

            <div class="space-y-3">
              <div v-for="(p, pIdx) in matrixResult.payloads" :key="pIdx" class="ui-sub-card p-2.5 space-y-1.5">
                <div class="flex items-center justify-between text-[11px] border-b pb-1" style="border-color: var(--border-subtle);">
                  <span class="font-semibold text-blue-600 dark:text-sky-300 font-mono truncate mr-2">{{ p.label }}</span>
                  <span class="ui-num shrink-0" style="color: var(--text-muted);">{{ p.byte_length }} 字节</span>
                </div>

                <div class="space-y-1 font-mono text-[11px]">
                  <div v-for="row in p.hex_rows" :key="row.offset" class="flex items-center justify-between hover:bg-[var(--surface-hover)] px-1 py-0.5 rounded">
                    <span class="w-11 shrink-0 select-none" style="color: var(--text-muted);">{{ row.offset }}</span>
                    <div class="flex items-center gap-1 flex-1 mx-1.5 overflow-x-auto">
                      <span
                        v-for="(c, cIdx) in row.cells"
                        :key="cIdx"
                        :class="[
                          'px-0.5 rounded-xs text-center min-w-[18px]',
                          c.diff_type === 'mutation' || c.diff_type === 'replace' ? 'bg-rose-500 text-white font-semibold' :
                          c.diff_type === 'insert' ? 'bg-emerald-500 text-white font-semibold' :
                          ''
                        ]"
                        :style="c.diff_type === 'equal' || c.diff_type === 'missing' ? { color: c.diff_type === 'missing' ? 'var(--text-muted)' : 'var(--text-secondary)' } : {}"
                        :title="c.diff_type !== 'equal' ? `突变类型: ${c.diff_type} (${c.hex})` : c.hex"
                      >
                        {{ c.hex }}
                      </span>
                    </div>
                    <span class="w-24 shrink-0 truncate pl-1.5 border-l select-none text-[11px]" style="border-color: var(--border-subtle); color: var(--text-muted);">
                      {{ row.ascii_repr }}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </template>

          <EmptyState v-else icon="layers" title="请选择至少 2 帧报文" description="按住 Ctrl 或 Shift 点选多帧报文即可开启特征矩阵比对。">
            <template #actions>
              <button v-if="filteredPackets.length >= 2" @click="quickSelectFirstTwoAndCompare" class="ui-btn-primary px-3 py-1 text-xs mt-2">
                快速对比前两帧
              </button>
            </template>
          </EmptyState>
        </div>
      </aside>
    </div>
<!-- 4. 全景深度解剖模态框 -->
    <PacketDetailModal
      :isOpen="isDetailModalOpen"
      :packet="detailPacket"
      @close="isDetailModalOpen = false"
      @replayPacket="$emit('replayPacket', $event)"
      @saveBaseline="saveAsBaseline"
    />

    <!-- 5. 靶向主动反探独立控制台模态框 -->
    <TargetProbeModal
      :isOpen="isTargetProbeOpen"
      :defaultIp="selectedPacket?.src_ip || ''"
      :defaultPort="selectedPacket?.src_port || 80"
      @close="isTargetProbeOpen = false"
    />

    <!-- 5b. 全环境 VPN / 加密代理隧道四维交叉侦测引擎 -->
    <VpnTunnelDetectorModal
      :isOpen="isVpnDetectorOpen"
      @close="isVpnDetectorOpen = false"
    />

    <!-- 6. 端口双向出入执行器模态框 -->
    <PortTransceiverModal
      :isOpen="isTransceiverModalOpen"
      :serialPorts="serialPorts"
      @close="isTransceiverModalOpen = false"
    />

    <!-- 7. 原始帧物理注入模态框 -->
    <div v-if="isInjectModalOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface w-full max-w-xl rounded-3xl flex flex-col overflow-hidden">
        <div class="px-6 py-4 border-b flex items-center justify-between shrink-0" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2.5">
            <span class="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
            <div>
              <h3 class="text-sm font-semibold" style="color: var(--text-primary);">链路层原始帧物理注入 (Raw Packet Injection)</h3>
              <p class="text-[11px] font-mono" style="color: var(--text-muted);">底层非阻塞原始套接字直接构造并下发报文帧</p>
            </div>
          </div>
          <button @click="isInjectModalOpen = false" class="w-8 h-8 rounded-full flex items-center justify-center hover:bg-[var(--surface-hover)] transition-colors cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="p-6 space-y-4 overflow-auto">
          <div>
            <label class="block text-xs font-semibold mb-1.5" style="color: var(--text-secondary);">选择目标网络接口 (Interface):</label>
            <select v-model="injectIface" class="ui-input w-full px-3 py-2 text-xs font-mono">
              <option v-for="iface in interfaces" :key="iface" :value="iface">{{ iface }}</option>
              <option v-if="interfaces.length === 0" value="">未发现物理网卡接口</option>
            </select>
          </div>

          <div>
            <div class="flex items-center justify-between mb-1.5">
              <label class="text-xs font-semibold" style="color: var(--text-secondary);">原始帧十六进制载荷 (Raw Hex Payload):</label>
              <div class="flex items-center gap-2">
                <button @click="formatInjectHex" class="text-[11px] text-blue-600 dark:text-sky-400 hover:underline font-semibold cursor-pointer">
                  清洗并格式化
                </button>
                <span class="text-[11px] ui-num" style="color: var(--text-muted);">
                  {{ injectByteLength }} 字节 ({{ injectHexClean.length }} 字符)
                </span>
              </div>
            </div>
            <textarea
              v-model="injectHex"
              rows="5"
              placeholder="例如: 00 11 22 33 44 55 66 77 88 99 AA BB 08 00 45 00 ..."
              class="ui-input w-full p-3 text-xs font-mono text-emerald-700 dark:text-emerald-400 custom-scrollbar"
            ></textarea>
            <p v-if="injectError" class="text-[11px] text-rose-600 dark:text-rose-400 font-semibold mt-1">{{ injectError }}</p>
          </div>

          <div v-if="injectResult" class="ui-sub-card p-3 text-xs font-mono" style="color: var(--text-primary);">
            {{ injectResult }}
          </div>
        </div>

        <div class="px-6 py-3 border-t flex items-center justify-between shrink-0" style="border-color: var(--border-subtle);">
          <span class="text-[11px]" style="color: var(--text-muted);">请确保十六进制帧格式包含完整二/三层报头</span>
          <div class="flex items-center gap-2">
            <button @click="isInjectModalOpen = false" class="ui-btn-secondary px-3.5 py-1.5 text-xs">取消</button>
            <button @click="doInjectRawPacket" :disabled="isInjecting || !isInjectValid" class="ui-btn-danger bg-rose-600 text-white border-rose-600 hover:bg-rose-500 px-4 py-1.5 text-xs">
              <AppIcon v-if="isInjecting" name="refresh" :size="13" class="animate-spin" />
              <span>执行物理注入</span>
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- 8. 追踪 TCP 会话流模态框 -->
    <TcpStreamModal
      :isOpen="isTcpStreamOpen"
      :srcIp="tcpStreamPacket?.src_ip || ''"
      :dstIp="tcpStreamPacket?.dst_ip || ''"
      :srcPort="tcpStreamPacket?.src_port || 0"
      :dstPort="tcpStreamPacket?.dst_port || 0"
      :transport="tcpStreamPacket?.transport || 'TCP'"
      @close="isTcpStreamOpen = false"
    />

    <!-- 9. 导出流量模态框 (PCAP/CSV/JSON/HAR) -->
    <ExportCaptureModal
      :isOpen="isExportOpen"
      :allPackets="packets"
      :filteredPackets="filteredPackets"
      @close="isExportOpen = false"
      @log="$emit('appendLog', $event)"
    />

    <!-- 10. 导入 PCAP 离线模态框 -->
    <ImportPcapModal
      :isOpen="isImportOpen"
      @close="isImportOpen = false"
      @imported="handleImportedPackets"
      @log="$emit('appendLog', $event)"
    />

    <!-- 11. 内网 CIDR 资产定义与安全域模态框 -->
    <CidrAssetModal
      :isOpen="isCidrAssetOpen"
      @close="isCidrAssetOpen = false"
      @log="$emit('appendLog', $event)"
    />

    <!-- 12. 离线 IP 归属地库 (IP2Region xdb) 控制模态框 -->
    <IpDatabaseModal
      :isOpen="isIpDbOpen"
      @close="isIpDbOpen = false"
      @log="$emit('appendLog', $event)"
    />

    <!-- 13. 侦听列表字段显示长度与列宽调节模态框 -->
    <ColumnSettingsModal
      :isOpen="isColumnSettingsOpen"
      :columns="columns"
      @close="isColumnSettingsOpen = false"
      @save="onSaveColumnSettings"
    />

    <!-- 13. 表格行右键上下文菜单浮层 -->
    <div
      v-if="contextMenu.visible"
      :style="{ top: `${contextMenu.y}px`, left: `${contextMenu.x}px` }"
      class="ui-modal-surface fixed z-50 rounded-2xl py-1.5 w-52 text-xs font-medium select-none"
    >
      <div class="px-3 py-1.5 text-[11px] font-semibold border-b mb-1 ui-num" style="color: var(--text-muted); border-color: var(--border-subtle);">
        报文 #{{ contextMenu.packet?.id }}
      </div>
      <template v-if="selectedPackets.size === 2">
        <button @click="openDiffWithSelected2(); closeContextMenu()" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors font-semibold text-indigo-600 dark:text-indigo-300 border-b" style="border-color: var(--border-subtle);">
          <AppIcon name="scale" :size="13" />
          <span>比对选中的 2 帧报文</span>
        </button>
      </template>
      <template v-if="selectedPackets.size >= 2">
        <button @click="openGlobalMultiDiffWithSelected(); closeContextMenu()" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors font-semibold text-emerald-600 dark:text-emerald-300 border-b" style="border-color: var(--border-subtle);">
          <AppIcon name="git-branch" :size="13" />
          <span>全局 Center-Star {{ selectedPackets.size }} 组对齐</span>
        </button>
        <button @click="openMatrixTab(); closeContextMenu()" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors font-semibold text-purple-600 dark:text-purple-300 border-b" style="border-color: var(--border-subtle);">
          <AppIcon name="layers" :size="13" />
          <span>侧栏 {{ selectedPackets.size }} 帧矩阵</span>
        </button>
      </template>
      <button v-if="contextMenu.packet?.src_ip" @click="quickApplyFieldFilter('ip.src', contextMenu.packet?.src_ip, '=='); closeContextMenu()" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors" style="color: var(--text-primary);">
        <AppIcon name="filter" :size="13" class="text-blue-500" />
        <span class="truncate">按源 IP 过滤 ({{ contextMenu.packet?.src_ip }})</span>
      </button>
      <button v-if="contextMenu.packet?.dst_ip" @click="quickApplyFieldFilter('ip.dst', contextMenu.packet?.dst_ip, '=='); closeContextMenu()" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors" style="color: var(--text-primary);">
        <AppIcon name="filter" :size="13" class="text-blue-500" />
        <span class="truncate">按目的 IP 过滤 ({{ contextMenu.packet?.dst_ip }})</span>
      </button>
      <button v-if="contextMenu.packet?.protocol" @click="quickApplyFieldFilter('ip.proto', contextMenu.packet?.protocol, '=='); closeContextMenu()" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors" style="color: var(--text-primary);">
        <AppIcon name="filter" :size="13" class="text-blue-500" />
        <span class="truncate">按规约过滤 ({{ contextMenu.packet?.protocol }})</span>
      </button>
      <div class="h-px my-1" style="background: var(--border-subtle);"></div>
      <button v-if="contextMenu.packet?.transport === 'TCP'" @click="menuAction('tcp_stream')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors text-blue-600 dark:text-sky-300 font-semibold">
        <AppIcon name="link" :size="13" />
        <span>追踪 TCP 会话流</span>
      </button>
      <button @click="menuAction('add_diff_queue')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors text-emerald-600 dark:text-emerald-300 font-semibold">
        <AppIcon name="plus" :size="13" />
        <span>加入全局多组比对队列</span>
      </button>
      <button @click="menuAction('set_diff_a')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors text-indigo-600 dark:text-indigo-300 font-semibold">
        <AppIcon name="scale" :size="13" />
        <span>设为对比基准报文 A</span>
      </button>
      <button v-if="diffBus.currentItemA.value" @click="menuAction('diff_with_a')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors font-semibold text-purple-600 dark:text-purple-300">
        <AppIcon name="search" :size="13" />
        <span>与基准 ({{ diffBus.currentItemA.value.label }}) 差分比对</span>
      </button>
      <button @click="menuAction('save_sample')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors" style="color: var(--text-primary);">
        <AppIcon name="archive" :size="13" class="text-emerald-500" />
        <span>存入报文特征样本库</span>
      </button>
      <button @click="menuAction('inject')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors" style="color: var(--text-primary);">
        <AppIcon name="zap" :size="13" class="text-rose-500" />
        <span>注入此帧载荷</span>
      </button>
      <button @click="sendPayloadToNetAssist(contextMenu.packet); closeContextMenu()" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors font-semibold text-sky-600 dark:text-sky-300">
        <AppIcon name="terminal" :size="13" />
        <span>推送至网络通信调试</span>
      </button>
      <button @click="menuAction('detail')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors" style="color: var(--text-primary);">
        <AppIcon name="code" :size="13" />
        <span>全景深度解剖</span>
      </button>
      <button @click="menuAction('baseline')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors" style="color: var(--text-primary);">
        <AppIcon name="shield" :size="13" />
        <span>固化为历史基线</span>
      </button>
      <button @click="menuAction('replay')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors" style="color: var(--text-primary);">
        <AppIcon name="refresh" :size="13" />
        <span>重放传输层报文</span>
      </button>
      <button v-if="contextMenu.packet?.src_ip" @click="menuAction('dossier_src')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors text-blue-600 dark:text-sky-300">
        <AppIcon name="search" :size="13" />
        <span>源 IP 全息档案溯源</span>
      </button>
      <button v-if="contextMenu.packet?.dst_ip" @click="menuAction('dossier_dst')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors text-blue-600 dark:text-sky-300">
        <AppIcon name="search" :size="13" />
        <span>目的 IP 全息档案溯源</span>
      </button>
      <button v-if="contextMenu.packet?.src_ip" @click="menuAction('traceroute_src')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors text-emerald-600 dark:text-emerald-300">
        <AppIcon name="globe" :size="13" />
        <span>源 IP 测地路由追踪</span>
      </button>
      <button v-if="contextMenu.packet?.dst_ip" @click="menuAction('traceroute_dst')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors text-emerald-600 dark:text-emerald-300 font-medium">
        <AppIcon name="globe" :size="13" />
        <span>追踪本地至目标网络路由 (Trace & MAP)</span>
      </button>
      <button @click="menuAction('copy')" class="w-full text-left px-3 py-1.5 hover:bg-[var(--surface-hover)] flex items-center gap-2 cursor-pointer transition-colors" style="color: var(--text-primary);">
        <AppIcon name="document" :size="13" />
        <span>复制十六进制载荷</span>
      </button>
    </div>

    <!-- 14. 多串口数据实时交叉比对终端模态框 -->
    <MultiSerialCompareModal
      :isOpen="isMultiCompareOpen"
      :packets="packets"
      :availablePorts="serialPorts"
      :defaultPortA="activeSerialPorts && activeSerialPorts[0] ? activeSerialPorts[0] : (serialPorts[0] || '')"
      :defaultPortB="activeSerialPorts && activeSerialPorts[1] ? activeSerialPorts[1] : (serialPorts[1] || serialPorts[0] || '')"
      @close="isMultiCompareOpen = false"
    />

    <!-- 15. IP 全息画像与行为溯源控制台模态框 (点击任意 IP 穿透下钻) -->
    <IpDossierModal
      :isOpen="isIpDossierOpen"
      :targetIp="dossierIp"
      :packets="packets"
      :assets="assets"
      @close="isIpDossierOpen = false"
      @filterTraffic="onFilterTrafficByIp"
      @drillDown="dossierIp = $event"
    />

    <!-- 16. 统一由 App.vue 挂载唯一全局 <PacketDiffModal /> 响应 diffBus，消除双实例死锁 -->

    <!-- 17. 测地线可视路由追踪与地球地理情报工作台模态框 (TASK-43) -->
    <GeodesicTracerouteModal
      :isOpen="isTracerouteOpen"
      :initialTarget="tracerouteTarget"
      @close="isTracerouteOpen = false"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, defineAsyncComponent, nextTick, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { notifyError, notifyInfo, notifySuccess } from '../composables/useNotification';
import { useUniversalDiff } from '../composables/useUniversalDiff';
import { saveTextViaNativeDesktop } from '../composables/useDesktopSave';
import { uiPrompt } from '../composables/useConfirmDialog';
import PacketDetailModal from '../components/PacketDetailModal.vue';
import PacketTraceMapView from '../components/PacketTraceMapView.vue';
import AppIcon from '../components/AppIcon.vue';
import EmptyState from '../components/EmptyState.vue';

export interface SerialPortDetail {
  port_name: string;
  description: string;
  hardware_id: string;
  manufacturer?: string;
  product?: string;
  port_type: string;
  is_usb: boolean;
  is_available: boolean;
  is_in_use_by_us: boolean;
}

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

export interface MutationWaveBin {
  offset: number;
  mutation_rate: number;
  unique_values_count: number;
  entropy: number;
  dominant_hex: string;
}

interface MatrixResult {
  mode?: string;
  summary: string;
  mutation_spectrum?: MutationWaveBin[];
  payloads: Array<{
    label: string;
    byte_length: number;
    hex_rows: Array<{
      offset: string;
      cells: Array<{ hex: string; ascii: string; diff_type: string }>;
      ascii_repr: string;
    }>;
  }>;
}

const props = defineProps<{
  packets: PacketRecord[];
  assets?: any[];
  isRunning: boolean;
  isPaused?: boolean;
  isSerialRunning?: boolean;
  isUsbRunning?: boolean;
  selectedIface: string;
  bpfFilter: string;
  interfaces: string[];
  serialPorts: string[];
  serialPortsDetail?: SerialPortDetail[];
  activeSerialPorts?: string[];
  serialPortBaudRates?: Record<string, number>;
  selectedSerial: string;
  serialBaudRate: number;
  usbDevices: any[];
  captureCapability?: {
    external_ready: boolean;
    scope: string;
    reason: string;
    targets: string[];
  };
}>();

const emit = defineEmits([
  'startCapture', 'pauseCapture', 'resumeCapture', 'stopCapture',
  'startSerialCapture', 'stopSerialCapture',
  'startUsbCapture', 'stopUsbCapture', 'refreshUsb', 'refreshSerial',
  'updateSerial', 'updateBaudRate', 'updatePortBaudRate',
  'clearData',
  'updateBpf', 'updateIface', 'replayPacket', 'saveBaseline',
  'appendLog', 'importPackets', 'openHoneypot', 'openWireless', 'switchWorkbench', 'openEnvInspector'
]);

const TargetProbeModal = defineAsyncComponent(() => import('../components/TargetProbeModal.vue'));
const PortTransceiverModal = defineAsyncComponent(() => import('../components/PortTransceiverModal.vue'));
const FlowDialogueInspector = defineAsyncComponent(() => import('../components/FlowDialogueInspector.vue'));
const TcpStreamModal = defineAsyncComponent(() => import('../components/TcpStreamModal.vue'));
const ExportCaptureModal = defineAsyncComponent(() => import('../components/ExportCaptureModal.vue'));
const ImportPcapModal = defineAsyncComponent(() => import('../components/ImportPcapModal.vue'));
const CidrAssetModal = defineAsyncComponent(() => import('../components/CidrAssetModal.vue'));
const IpDatabaseModal = defineAsyncComponent(() => import('../components/IpDatabaseModal.vue'));
const ColumnSettingsModal = defineAsyncComponent(() => import('../components/ColumnSettingsModal.vue'));
const MultiSerialCompareModal = defineAsyncComponent(() => import('../components/MultiSerialCompareModal.vue'));
const IpDossierModal = defineAsyncComponent(() => import('../components/IpDossierModal.vue'));
const IoGraphsPanel = defineAsyncComponent(() => import('../components/IoGraphsPanel.vue'));
const GeodesicTracerouteModal = defineAsyncComponent(() => import('../components/GeodesicTracerouteModal.vue'));
const VpnTunnelDetectorModal = defineAsyncComponent(() => import('../components/VpnTunnelDetectorModal.vue'));

const diffBus = useUniversalDiff();

// 测地线可视路由追踪与地球地理情报 (TASK-43)
const isTracerouteOpen = ref(false);
const tracerouteTarget = ref('');
function openTraceroute(target?: string) {
  tracerouteTarget.value = target || '';
  isTracerouteOpen.value = true;
}

// 工业网络运行监控看板与网络拓扑动画引擎
// 默认收起监控看板，释放 85% 以上空间给中央主舞台报文流 (对标 apple_liquid_drawer_showcase)
const isHorizonExpanded = ref(false);
const isInspectorOpen = ref(false); // 默认收起空白右抽屉，单击帧或按 R / 点击随行解构随时展开
const topologyCanvasRef = ref<HTMLCanvasElement | null>(null);

const quickProtocolTags = [
  { label: '全部协议', value: '', title: '全部规约协议 (All)' },
  { label: 'Modbus', value: 'MODBUS', title: 'Modbus TCP/RTU (502)' },
  { label: 'S7comm', value: 'S7COMM', title: '西门子 S7Comm/S7Plus (102)' },
  { label: 'EtherCAT', value: 'ETHERCAT', title: 'EtherCAT 工业以太网' },
  { label: 'IEC 104', value: 'IEC104', title: '电力远动规约 IEC 60870-5-104' },
  { label: 'SL651', value: 'SL651', title: '水利水文监测规约 SL651-2014' },
  { label: 'MQTT', value: 'MQTT', title: '工业物联网传输 MQTT' },
];

// 动态协议载荷占比统计 (100% 源自真实捕获帧统计，绝不伪造占比)
const protocolStats = computed(() => {
  const pkts = props.packets;
  if (!pkts || pkts.length === 0) {
    return { modbus: 0, s7: 0, ethercat: 0, iec104: 0 };
  }
  let modbusCount = 0;
  let s7Count = 0;
  let ecatCount = 0;
  let iec104Count = 0;
  const recent = pkts.slice(-500);
  for (const p of recent) {
    const proto = (p.protocol || '').toUpperCase();
    if (proto.includes('MODBUS')) modbusCount++;
    else if (proto.includes('S7')) s7Count++;
    else if (proto.includes('ETHERCAT') || proto.includes('ECAT')) ecatCount++;
    else if (proto.includes('IEC') || proto.includes('104')) iec104Count++;
  }
  const total = recent.length || 1;
  const modbus = Math.round((modbusCount / total) * 100);
  const s7 = Math.round((s7Count / total) * 100);
  const ethercat = Math.round((ecatCount / total) * 100);
  const iec104 = Math.round((iec104Count / total) * 100);
  return { modbus, s7, ethercat, iec104 };
});

const industrialRatioText = computed(() => {
  const total = protocolStats.value.modbus + protocolStats.value.s7 + protocolStats.value.ethercat + protocolStats.value.iec104;
  return total > 0 ? `${total}% (工控高优先级)` : '0% (暂无工控报文)';
});

// 实时指令与威胁合规汇总（100% 由真实捕获报文驱动，禁止无抓包或已违规状态静态报绿）
const complianceHealthSummary = computed(() => {
  const pkts = props.packets || [];
  if (pkts.length === 0) {
    return {
      headerBadge: '待捕获评估',
      badgeClass: 'text-slate-600 dark:text-slate-300 bg-slate-500/10 border-slate-500/25',
      iconBoxClass: 'bg-slate-500/10 border-slate-500/25 text-[var(--text-muted)]',
      iconName: 'shield',
      title: '指令审计引擎待命',
      subtitle: '尚未捕获报文，启动采集后按实审计违规指令',
      countLabel: '—',
      countClass: 'text-[var(--text-muted)]',
    };
  }

  let violationCount = 0;
  let writeOpsCount = 0;
  let latestAlertDesc = '';

  for (const p of pkts) {
    const bd = p?.business_data;
    const protoUpper = String(p?.protocol || '').toUpperCase();
    const hasViolation = Boolean(
      bd?.ics_acl_violation ||
      bd?.threat_hit ||
      bd?.vlan_threat_alert ||
      protoUpper.includes('ALERT') ||
      p?.entropy_level === 'critical'
    );
    if (hasViolation) {
      violationCount++;
      const reason = bd?.ics_acl_violation?.violation_reason || bd?.vlan_threat_alert || p?.protocol;
      latestAlertDesc = `${p?.src_ip || ''}→${p?.dst_ip || ''} (${reason})`;
    }
    if (bd?.is_write || bd?.modbus_tcp?.is_write) {
      writeOpsCount++;
    }
  }

  if (violationCount > 0) {
    return {
      headerBadge: `检出 ${violationCount} 项异常`,
      badgeClass: 'text-rose-700 dark:text-rose-300 bg-rose-500/15 border-rose-500/35',
      iconBoxClass: 'bg-rose-500/15 border-rose-500/35 text-rose-600 dark:text-rose-400',
      iconName: 'alert',
      title: '检出越权/高危特征报文',
      subtitle: latestAlertDesc || `写操作 ${writeOpsCount} 帧 · 请核查告警详情与等保控制台`,
      countLabel: `${violationCount} 异常`,
      countClass: 'text-rose-600 dark:text-rose-400',
    };
  }

  return {
    headerBadge: '实时监视正常',
    badgeClass: 'text-emerald-700 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/25',
    iconBoxClass: 'bg-emerald-500/15 border-emerald-500/30 text-emerald-600 dark:text-emerald-400',
    iconName: 'check',
    title: '指令白名单实时监看中',
    subtitle: `已实时审计 ${pkts.length.toLocaleString()} 帧（工控写指令 ${writeOpsCount} 帧）`,
    countLabel: '0 违规',
    countClass: 'text-emerald-600 dark:text-emerald-400',
  };
});

// 真实遥测吞吐率、PPS与基于真实到达时间差的抖动 Jitter
const telemetryPps = ref(0);
const telemetryThroughputMbps = ref('0.00');
const telemetryJitterMs = ref('0.00');

let ppsCounter = 0;
let bytesCounter = 0;
let lastTelemetryCalc = performance.now();
let lastPacketArrivalTime = 0;
let lastInterArrivalMs = 0;
let smoothedJitterMs = 0;

watch(() => props.packets.length, (newLen, oldLen) => {
  if (newLen === 0) {
    topoNodes = [];
    topoLinks = [];
    topoNodeIndexMap.clear();
    ppsCounter = 0;
    bytesCounter = 0;
    telemetryPps.value = 0;
    telemetryThroughputMbps.value = '0.00';
    telemetryJitterMs.value = '0.00';
    return;
  }
  const delta = newLen - (oldLen || 0);
  if (delta > 0 && props.packets.length > 0) {
    const now = performance.now();
    if (lastPacketArrivalTime > 0) {
      const iat = now - lastPacketArrivalTime;
      const diff = Math.abs(iat - lastInterArrivalMs);
      smoothedJitterMs = smoothedJitterMs * 0.75 + diff * 0.25;
      lastInterArrivalMs = iat;
    }
    lastPacketArrivalTime = now;

    const startIdx = Math.max(0, newLen - delta);
    for (let i = startIdx; i < newLen; i++) {
      const p = props.packets[i];
      if (!p) continue;
      ppsCounter += 1;
      bytesCounter += (p.length || 64);
      emitRealTopologyFlowParticle(p.src_ip, p.dst_ip, p.protocol);
    }
  }
});

let telemetryTimer: any = null;
function updateTelemetryMetrics() {
  const now = performance.now();
  const elapsed = (now - lastTelemetryCalc) / 1000;
  if (elapsed >= 0.8) {
    const calculatedPps = Math.round(ppsCounter / elapsed);
    const mbpsVal = (bytesCounter * 8) / (elapsed * 1000 * 1000);
    telemetryPps.value = calculatedPps;
    telemetryThroughputMbps.value = mbpsVal.toFixed(2);
    telemetryJitterMs.value = ppsCounter > 0 ? Math.min(999.9, smoothedJitterMs).toFixed(2) : '0.00';
    ppsCounter = 0;
    bytesCounter = 0;
    lastTelemetryCalc = now;
  }
}

// 动态真实网络会话拓扑 Canvas 引擎 (绝不静态硬编码任何假节点与假粒子)
interface TopoNode {
  id: string;
  x: number;
  y: number;
  label: string;
  color: string;
  pulse: number;
}
interface TopoLink {
  from: number;
  to: number;
  packets: Array<{ progress: number; speed: number }>;
}

let topoNodes: TopoNode[] = [];
let topoLinks: TopoLink[] = [];
const topoNodeIndexMap = new Map<string, number>();

function ensureDynamicTopoEndpoints(ip: string, isSource: boolean, proto?: string): number {
  const clean = (ip || '').trim();
  if (!clean) return -1;
  const existing = topoNodeIndexMap.get(clean);
  if (existing !== undefined) return existing;

  // 环形最多展示 Top-8 实时高频实体节点，防界面拥挤
  if (topoNodes.length >= 8) {
    return -1;
  }
  const idx = topoNodes.length;
  const angle = (idx / 8) * Math.PI * 2 - Math.PI / 2;
  const rx = 0.34;
  const ry = 0.32;
  const pUpper = (proto || '').toUpperCase();
  const color = pUpper.includes('ALERT')
    ? '#F43F5E'
    : pUpper.includes('MODBUS')
    ? '#10B981'
    : pUpper.includes('S7')
    ? '#F59E0B'
    : isSource
    ? '#00F2FE'
    : '#4FACFE';

  topoNodes.push({
    id: clean,
    x: 0.5 + rx * Math.cos(angle),
    y: 0.5 + ry * Math.sin(angle),
    label: clean,
    color,
    pulse: 1.0,
  });
  topoNodeIndexMap.set(clean, idx);
  return idx;
}

function emitRealTopologyFlowParticle(srcIp?: string, dstIp?: string, protocol?: string) {
  if (!srcIp || !dstIp) return;
  const iSrc = ensureDynamicTopoEndpoints(srcIp, true, protocol);
  const iDst = ensureDynamicTopoEndpoints(dstIp, false, protocol);
  if (iSrc < 0 || iDst < 0 || iSrc === iDst) return;

  topoNodes[iSrc].pulse = 1.0;
  let link = topoLinks.find(l => (l.from === iSrc && l.to === iDst) || (l.from === iDst && l.to === iSrc));
  if (!link) {
    link = { from: iSrc, to: iDst, packets: [] };
    topoLinks.push(link);
  }
  if (link.packets.length < 6) {
    link.packets.push({ progress: 0, speed: 0.025 });
  }
}

let topoAnimId: number | null = null;
function startTopologyAnimation() {
  const canvas = topologyCanvasRef.value;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  function resize() {
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx?.scale(dpr, dpr);
  }

  resize();
  window.addEventListener('resize', resize);

  function render() {
    if (!canvas || !ctx) return;
    const rect = canvas.getBoundingClientRect();
    const w = rect.width;
    const h = rect.height;
    if (w <= 0 || h <= 0) {
      topoAnimId = requestAnimationFrame(render);
      return;
    }

    const dpr = window.devicePixelRatio || 1;
    const targetW = Math.round(w * dpr);
    const targetH = Math.round(h * dpr);
    if (canvas.width !== targetW || canvas.height !== targetH) {
      canvas.width = targetW;
      canvas.height = targetH;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    ctx.clearRect(0, 0, w, h);

    const isLightMode = document.querySelector('.theme-apple-light') !== null;

    // 绘制微米级暗调网格 (自适应浅色与深色)
    ctx.strokeStyle = isLightMode ? 'rgba(0, 0, 0, 0.04)' : 'rgba(255, 255, 255, 0.025)';
    ctx.lineWidth = 1;
    const step = 36;
    for (let x = 0; x < w; x += step) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }
    for (let y = 0; y < h; y += step) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    // 若尚无真实捕获拓扑节点，显示客观待机网格提示，严禁虚构连线与粒子
    if (topoNodes.length === 0) {
      ctx.fillStyle = isLightMode ? 'rgba(15, 23, 42, 0.55)' : 'rgba(148, 163, 184, 0.65)';
      ctx.font = 'bold 12px monospace';
      ctx.textAlign = 'center';
      ctx.fillText('待机中: 启动网卡嗅探或导入 PCAP 后自动绘制真实活跃流拓扑', w / 2, h / 2);
    }

    // 绘制真实连线与实时流光粒子
    topoLinks.forEach(l => {
      const n1 = topoNodes[l.from];
      const n2 = topoNodes[l.to];
      const x1 = n1.x * w;
      const y1 = n1.y * h;
      const x2 = n2.x * w;
      const y2 = n2.y * h;

      ctx.strokeStyle = isLightMode ? 'rgba(0, 0, 0, 0.12)' : 'rgba(255, 255, 255, 0.08)';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.lineTo(x2, y2);
      ctx.stroke();

      for (let i = l.packets.length - 1; i >= 0; i--) {
        const p = l.packets[i];
        p.progress += p.speed;
        if (p.progress >= 1) {
          l.packets.splice(i, 1);
          n2.pulse = 1.0;
          continue;
        }

        const px = x1 + (x2 - x1) * p.progress;
        const py = y1 + (y2 - y1) * p.progress;

        ctx.fillStyle = '#00F2FE';
        ctx.shadowColor = '#00F2FE';
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(px, py, 2.2, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    });

    // 绘制节点
    topoNodes.forEach(n => {
      const nx = n.x * w;
      const ny = n.y * h;

      if (n.pulse > 0) {
        ctx.strokeStyle = n.color;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(nx, ny, 14 + (1 - n.pulse) * 18, 0, Math.PI * 2);
        ctx.stroke();
        n.pulse -= 0.03;
      }

      const radGlow = ctx.createRadialGradient(nx, ny, 2, nx, ny, 22);
      radGlow.addColorStop(0, n.color + '44');
      radGlow.addColorStop(1, 'transparent');
      ctx.fillStyle = radGlow;
      ctx.beginPath();
      ctx.arc(nx, ny, 22, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = '#0A0D14';
      ctx.strokeStyle = n.color;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(nx, ny, 7.5, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = n.color;
      ctx.beginPath();
      ctx.arc(nx, ny, 3.2, 0, Math.PI * 2);
      ctx.fill();

      ctx.font = '10px "Plus Jakarta Sans", sans-serif';
      ctx.textAlign = 'center';
      const textMetrics = ctx.measureText(n.label);
      const textW = textMetrics.width;
      // 智能避让：底部节点标签绘制于节点上方，顶部节点标签绘制于节点下方
      const labelY = ny > h * 0.52 ? ny - 16 : ny + 21;
      const rectY = ny > h * 0.52 ? ny - 24 : ny + 10;
      ctx.fillStyle = isLightMode ? 'rgba(255, 255, 255, 0.92)' : 'rgba(10, 13, 20, 0.85)';
      ctx.beginPath();
      ctx.roundRect(nx - textW / 2 - 5, rectY, textW + 10, 15, 4);
      ctx.fill();
      ctx.strokeStyle = isLightMode ? 'rgba(0, 0, 0, 0.1)' : 'rgba(255, 255, 255, 0.12)';
      ctx.stroke();

      ctx.fillStyle = isLightMode ? '#0F172A' : '#E2E8F0';
      ctx.fillText(n.label, nx, labelY);
    });

    topoAnimId = requestAnimationFrame(render);
  }

  topoAnimId = requestAnimationFrame(render);
}

// 双报文/多报文比对状态由全局 diffBus 统一管理



function copyHex(hex?: string) {
  if (hex && navigator.clipboard) {
    navigator.clipboard.writeText(hex);
  }
}

const telemetryRateText = computed(() => {
  if (props.packets.length === 0 || !props.isRunning || props.isPaused) {
    return '待命热备';
  }
  return telemetryPps.value > 0 ? `+${(telemetryPps.value / 1000).toFixed(1)}k/s` : '实时监听';
});

const activeBus = ref<'nic' | 'serial' | 'usb'>('nic');
const isTransceiverModalOpen = ref(false);
const isTargetProbeOpen = ref(false);
const isVpnDetectorOpen = ref(false);
const isDetailModalOpen = ref(false);
const isMultiCompareOpen = ref(false);
const detailPacket = ref<PacketRecord | null>(null);

const isIpDossierOpen = ref(false);
const dossierIp = ref('');

function openIpDossier(ip: string) {
  if (!ip) return;
  dossierIp.value = ip;
  isIpDossierOpen.value = true;
}

function onFilterTrafficByIp(ip: string) {
  filterText.value = ip;
}

const isSendingProbe = ref(false);
const probeResultMsg = ref<string | null>(null);

async function triggerSendProbeFrame() {
  if (!props.selectedSerial || isSendingProbe.value) return;
  isSendingProbe.value = true;
  probeResultMsg.value = null;
  try {
    const res = await invoke<string>('send_serial_probe_frame_cmd', {
      port: props.selectedSerial,
      baudRate: props.serialBaudRate,
    });
    probeResultMsg.value = `探活成功: ${props.selectedSerial}`;
    emit('appendLog', res);
    setTimeout(() => { probeResultMsg.value = null; }, 4000);
  } catch (err: any) {
    const errMsg = err?.message || String(err);
    probeResultMsg.value = `探活失败: ${errMsg}`;
    emit('appendLog', `[SERIAL] 探活帧发送失败: ${errMsg}`);
    setTimeout(() => { probeResultMsg.value = null; }, 5000);
  } finally {
    isSendingProbe.value = false;
  }
}

function triggerStartUsb() {
  activeBus.value = 'usb';
  emit('startUsbCapture');
}

function triggerStartSerial(port: string, baudRate: number) {
  activeBus.value = 'serial';
  emit('startSerialCapture', port, baudRate);
}

function onBaudRateChange(rate: number) {
  emit('updateBaudRate', rate);
  if (props.selectedSerial) {
    emit('updatePortBaudRate', { port: props.selectedSerial, baudRate: rate });
  }
}

function getSerialOptionLabel(portName: string): string {
  const detail = props.serialPortsDetail?.find(d => d.port_name === portName);
  if (detail) {
    const statusIcon = detail.is_available ? '[可用]' : '[占用]';
    const typeTag = detail.is_usb ? '[USB]' : '[板载/PCI]';
    const desc = detail.product || detail.manufacturer || detail.description;
    return `${statusIcon} ${portName} ${typeTag} - ${desc}`;
  }
  return portName;
}

function getSerialDetailTitle(portName: string): string {
  const detail = props.serialPortsDetail?.find(d => d.port_name === portName);
  if (detail) {
    const availText = detail.is_available ? '状态: 空闲可用' : '状态: 被占用或无访问权限';
    const inUseText = detail.is_in_use_by_us ? ' (正在被本探针监听)' : '';
    return `${availText}${inUseText}\n描述: ${detail.description}\n硬件ID: ${detail.hardware_id}\n类型: ${detail.port_type}`;
  }
  return portName;
}

function getSerialBadgeStyle(portName: string): string {
  const palette = [
    'bg-blue-500/12 text-blue-700 dark:text-sky-300 border-blue-500/25',
    'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/25',
    'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/25',
    'bg-purple-500/12 text-purple-700 dark:text-purple-300 border-purple-500/25',
    'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/25',
    'bg-teal-500/12 text-teal-700 dark:text-teal-300 border-teal-500/25',
    'bg-cyan-500/12 text-cyan-700 dark:text-cyan-300 border-cyan-500/25',
  ];
  let hash = 0;
  for (let i = 0; i < (portName || '').length; i++) {
    hash = (hash << 5) - hash + portName.charCodeAt(i);
    hash |= 0;
  }
  const idx = Math.abs(hash) % palette.length;
  return palette[idx];
}

// 顶部菜单点击展开状态 (替换 hover 下拉)
const activeDropdown = ref<'analyze' | 'control' | 'archive' | null>(null);
function toggleDropdown(menu: 'analyze' | 'control' | 'archive') {
  activeDropdown.value = activeDropdown.value === menu ? null : menu;
}
function closeAllDropdowns() {
  activeDropdown.value = null;
}

// 工业级专业模块模态框状态
const isTcpStreamOpen = ref(false);
const isExportOpen = ref(false);
const isImportOpen = ref(false);
const isCidrAssetOpen = ref(false);
const isIpDbOpen = ref(false);
const tcpStreamPacket = ref<PacketRecord | null>(null);

// PCAP 线速重放控制台状态
interface ReplayCaptureInfo {
  format: string;
  byte_order: string;
  total_packets: number;
  total_bytes: number;
  duration_seconds: number;
  average_pps: number;
  average_mbps: number;
}
interface ReplayTelemetry {
  state: string;
  current_index: number;
  total_packets: number;
  current_loop: number;
  max_loops: number;
  sent_packets: number;
  sent_bytes: number;
  elapsed_micros: number;
  current_pps: number;
  current_mbps: number;
  progress_percent: number;
  estimated_remaining_secs: number;
}

const isReplayPanelOpen = ref(false);
const replayFilePath = ref('');
const replayMode = ref<'paced' | 'top_speed' | 'step'>('paced');
const replaySpeed = ref<number>(1.0);
const replayLoops = ref<number>(1);
const replayLoading = ref(false);
const replayFileInfo = ref<ReplayCaptureInfo | null>(null);
const replayTelemetry = ref<ReplayTelemetry>({
  state: 'Idle',
  current_index: 0,
  total_packets: 0,
  current_loop: 0,
  max_loops: 1,
  sent_packets: 0,
  sent_bytes: 0,
  elapsed_micros: 0,
  current_pps: 0,
  current_mbps: 0,
  progress_percent: 0,
  estimated_remaining_secs: 0,
});
let replayPollTimer: ReturnType<typeof setInterval> | null = null;

async function fetchReplayTelemetry() {
  try {
    replayTelemetry.value = await invoke<ReplayTelemetry>('get_pcap_replay_telemetry_cmd');
    if (['Idle', 'Completed', 'Stopped'].includes(replayTelemetry.value.state) && replayPollTimer) {
      clearInterval(replayPollTimer);
      replayPollTimer = null;
    }
  } catch (e) {
    console.error('获取 PCAP 重放遥测失败:', e);
  }
}

function ensureReplayPolling() {
  if (!replayPollTimer) {
    replayPollTimer = setInterval(fetchReplayTelemetry, 500);
  }
}

async function toggleReplayConsole() {
  isReplayPanelOpen.value = !isReplayPanelOpen.value;
  if (isReplayPanelOpen.value) {
    await fetchReplayTelemetry();
  }
}

async function loadReplayFile() {
  if (!replayFilePath.value.trim()) return;
  replayLoading.value = true;
  try {
    replayFileInfo.value = await invoke<ReplayCaptureInfo>('load_pcap_replay_file_cmd', {
      filePath: replayFilePath.value.trim(),
    });
    await fetchReplayTelemetry();
    notifySuccess(
      '重放文件加载完成',
      `${replayFileInfo.value.format} | 共 ${replayFileInfo.value.total_packets} 帧 · 平均 ${replayFileInfo.value.average_pps.toFixed(0)} pps`
    );
  } catch (e) {
    notifyError('重放文件加载失败', e);
  } finally {
    replayLoading.value = false;
  }
}

async function startReplay() {
  try {
    await invoke<string>('start_pcap_replay_cmd', {
      mode: replayMode.value,
      speedMultiplier: replaySpeed.value,
      loopCount: replayLoops.value,
    });
    ensureReplayPolling();
    await fetchReplayTelemetry();
  } catch (e) {
    notifyError('启动线速重放失败', e);
  }
}

async function pauseReplay() {
  try {
    await invoke<string>('pause_pcap_replay_cmd');
    await fetchReplayTelemetry();
  } catch (e) {
    notifyError('暂停重放失败', e);
  }
}

async function resumeReplay() {
  try {
    await invoke<string>('resume_pcap_replay_cmd');
    ensureReplayPolling();
    await fetchReplayTelemetry();
  } catch (e) {
    notifyError('恢复重放失败', e);
  }
}

async function stepReplay() {
  try {
    await invoke<string>('step_pcap_replay_cmd');
    await fetchReplayTelemetry();
  } catch (e) {
    notifyError('单步触发失败', e);
  }
}

async function stopReplay() {
  try {
    await invoke<string>('stop_pcap_replay_cmd');
    await fetchReplayTelemetry();
  } catch (e) {
    notifyError('停止重放失败', e);
  }
}

// 工控事务追踪与多分辨率时序/矩阵状态
interface TransactionMetricsSnapshot {
  total_transactions_recorded: number;
  successful_transactions: number;
  exception_transactions: number;
  timeout_transactions: number;
  avg_plc_latency_ms: number;
  max_plc_latency_ms: number;
  min_plc_latency_ms: number;
  active_pending_count: number;
}
interface CompletedIndustrialTransaction {
  id: number;
  flow_key: string;
  client_ip: string;
  server_ip: string;
  protocol: string;
  transaction_id: number;
  function_code: number;
  req_time: string;
  plc_latency_ms: number;
  status: string;
  summary: string;
}
interface TimeSeriesBucket {
  slot_timestamp_s: number;
  packet_count: number;
  byte_count: number;
  industrial_packet_count: number;
  write_operation_count: number;
  error_or_threat_count: number;
}
interface TopologyHeatmapCell {
  source_ip: string;
  dest_ip: string;
  interaction_count: number;
  total_bytes: number;
  write_operation_count: number;
  error_count: number;
  is_industrial: boolean;
}

const isIndustrialTxOpen = ref(false);
const txStats = ref<TransactionMetricsSnapshot | null>(null);
const recentIndustrialTxs = ref<CompletedIndustrialTransaction[]>([]);

const isTimeseriesHeatmapOpen = ref(false);
const tsResolution = ref<'1s' | '10s' | '60s' | '1h'>('1s');
const tsBuckets = ref<TimeSeriesBucket[]>([]);
const heatmapCells = ref<TopologyHeatmapCell[]>([]);

function buildTsPolyline(field: 'packet_count' | 'industrial_packet_count'): string {
  const recent = tsBuckets.value.slice(-48);
  if (recent.length < 2) return '';
  const maxVal = Math.max(1, ...recent.map(b => b.packet_count || 0));
  const stepX = 320 / Math.max(1, recent.length - 1);
  return recent
    .map((b, idx) => {
      const val = b[field] || 0;
      const y = 44 - (val / maxVal) * 40;
      return `${(idx * stepX).toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
}

const tsPktPolyline = computed(() => buildTsPolyline('packet_count'));
const tsIndPolyline = computed(() => buildTsPolyline('industrial_packet_count'));

async function fetchIndustrialTxData() {
  try {
    const [stats, list] = await Promise.all([
      invoke<TransactionMetricsSnapshot>('get_industrial_transaction_stats_cmd'),
      invoke<CompletedIndustrialTransaction[]>('get_recent_industrial_transactions_cmd', { limit: 40 }),
    ]);
    txStats.value = stats;
    recentIndustrialTxs.value = list;
  } catch (e) {
    console.error('获取工控事务数据失败:', e);
  }
}

async function toggleIndustrialTxPanel() {
  isIndustrialTxOpen.value = !isIndustrialTxOpen.value;
  if (isIndustrialTxOpen.value) {
    await fetchIndustrialTxData();
  }
}

async function fetchTimeseriesHeatmapData() {
  try {
    const [series, heatmap] = await Promise.all([
      invoke<TimeSeriesBucket[]>('get_timeseries_metrics_cmd', { resolution: tsResolution.value }),
      invoke<TopologyHeatmapCell[]>('get_industrial_heatmap_matrix_cmd', { limit: 30 }),
    ]);
    tsBuckets.value = series;
    heatmapCells.value = heatmap;
  } catch (e) {
    console.error('获取时序热力矩阵失败:', e);
  }
}

async function toggleTimeseriesHeatmapPanel() {
  isTimeseriesHeatmapOpen.value = !isTimeseriesHeatmapOpen.value;
  if (isTimeseriesHeatmapOpen.value) {
    await fetchTimeseriesHeatmapData();
  }
}

// bottomTabs inline migrated
const activeBottomTab = ref('hexdump');

function openIoGraphsTab() {
  activeBottomTab.value = 'iographs';
  isInspectorOpen.value = true;
}

const selectedPacket = ref<PacketRecord | null>(null);
const selectedPackets = ref<Set<number>>(new Set());

// 默认联动：自动选中首个规约报文，避免右侧抽屉处于空选状态
watch(() => props.packets, (newPackets) => {
  if (!selectedPacket.value && newPackets && newPackets.length > 0) {
    const defaultPkt = newPackets[0];
    selectedPacket.value = defaultPkt;
    selectedPackets.value = new Set([defaultPkt.id]);
  }
}, { immediate: true });

const filterText = ref('');
const filterInput = ref('');
const filterProtocol = ref('');
const filterValidation = ref<{ valid: boolean; error: string | null; ast_summary: string | null }>({
  valid: false,
  error: null,
  ast_summary: null
});
const astMatchedIds = ref<Set<number> | null>(null);
const streamBufferStats = ref<{
  total_captured: number;
  current_buffered: number;
  max_capacity: number;
  flushed_segments_count: number;
  last_flush_time: string;
  last_packet_time: string;
} | null>(null);
let filterDebounceTimer: any = null;
let streamBufferTimer: any = null;

function onFilterInputDebounced() {
  if (filterDebounceTimer) clearTimeout(filterDebounceTimer);
  filterDebounceTimer = setTimeout(async () => {
    const expr = filterInput.value.trim();
    if (!expr) {
      filterValidation.value = { valid: false, error: null, ast_summary: null };
      astMatchedIds.value = null;
      filterText.value = '';
      return;
    }

    const hasAstSyntax = /[=!><]|&&|\|\||contains/i.test(expr);
    if (!hasAstSyntax) {
      filterValidation.value = { valid: false, error: null, ast_summary: null };
      return;
    }

    try {
      const res = await invoke<{ valid: boolean; error?: string; ast_summary?: string }>('validate_display_filter_cmd', {
        expression: expr
      });
      if (res.valid) {
        filterValidation.value = { valid: true, error: null, ast_summary: res.ast_summary || null };
      } else {
        filterValidation.value = { valid: false, error: res.error || '语法不合规', ast_summary: null };
      }
    } catch (e: any) {
      filterValidation.value = { valid: false, error: String(e), ast_summary: null };
    }
  }, 200);
}

async function applyDisplayFilter() {
  const expr = filterInput.value.trim();
  if (!expr) {
    filterText.value = '';
    astMatchedIds.value = null;
    return;
  }

  if (filterValidation.value.valid) {
    try {
      const ids = await invoke<number[]>('filter_packets_by_ast_cmd', {
        expression: expr,
        packets: busTotalPackets.value
      });
      astMatchedIds.value = new Set(ids);
      filterText.value = expr;
    } catch (e: any) {
      filterValidation.value = { valid: false, error: `执行失败: ${e}`, ast_summary: null };
      astMatchedIds.value = null;
    }
  } else {
    astMatchedIds.value = null;
    filterText.value = expr;
  }
}

function quickApplyAstFilter(expr: string) {
  filterInput.value = expr;
  onFilterInputDebounced();
  setTimeout(() => {
    applyDisplayFilter();
  }, 250);
}

function quickApplyFieldFilter(fieldKey: string, fieldValue: string | undefined, op: '==' | '!=' = '==') {
  if (!fieldKey) return;
  const isNumeric = fieldValue && /^\d+$/.test(fieldValue);
  const valStr = isNumeric ? fieldValue : `"${fieldValue || ''}"`;
  quickApplyAstFilter(`${fieldKey} ${op} ${valStr}`);
}

function clearDisplayFilter() {
  filterInput.value = '';
  filterText.value = '';
  filterValidation.value = { valid: false, error: null, ast_summary: null };
  astMatchedIds.value = null;
}
const sortKey = ref<string>('id');
const sortAsc = ref<boolean>(false);

const protocolList = [
  'HTTP','HTTP_REQ','HTTP_RES','TLS_HANDSHAKE','TLS_APP_DATA','DNS_QUERY','DNS_RESP','SSH',
  'MODBUS_TCP','MODBUS_RTU','S7_COMM','ENIP','BACNET','DNP3','IEC104','OPC-UA',
  'MQTT','MQTT-TLS','AMQP','COAP','HJ212','SL651_WATER',
  'REDIS','MYSQL','POSTGRESQL','MONGODB','SMTP_CMD','FTP_CMD','NTP','DHCP','SMB2',
  'SERIAL_TX','SERIAL_RX','USB_PnP','USB_STORAGE','USBPcap'
];

interface ColumnDef {
  key: string;
  label: string;
  defaultWidth: number;
  minWidth: number;
  width: number;
  sortable?: boolean;
  visible?: boolean;
}

const DEFAULT_COLUMNS: ColumnDef[] = [
  { key: 'id', label: '序号', defaultWidth: 56, minWidth: 46, width: 56, sortable: true, visible: true },
  { key: 'timestamp', label: '精准时间', defaultWidth: 80, minWidth: 68, width: 80, sortable: true, visible: true },
  { key: 'src_endpoint', label: '源端点 (Source)', defaultWidth: 134, minWidth: 100, width: 134, sortable: true, visible: true },
  { key: 'dst_endpoint', label: '目标端点 (Target)', defaultWidth: 134, minWidth: 100, width: 134, sortable: true, visible: true },
  { key: 'protocol', label: '规约协议', defaultWidth: 74, minWidth: 58, width: 74, sortable: true, visible: true },
  { key: 'length', label: '载荷大小', defaultWidth: 58, minWidth: 44, width: 58, sortable: true, visible: true },
  { key: 'l7_summary', label: '应用层解析摘要 (L7)', defaultWidth: 170, minWidth: 120, width: 170, sortable: false, visible: true },
  // 扩展列（默认隐藏，供高级审计自由开启）
  { key: 'direction', label: '流向模式', defaultWidth: 70, minWidth: 50, width: 70, sortable: true, visible: false },
  { key: 'transport', label: '传输总线', defaultWidth: 65, minWidth: 50, width: 65, sortable: true, visible: false },
  { key: 'entropy', label: '信息熵', defaultWidth: 55, minWidth: 40, width: 55, sortable: true, visible: false },
  { key: 'mac_src', label: '物理 MAC', defaultWidth: 110, minWidth: 70, width: 110, sortable: false, visible: false },
  { key: 'payload', label: '十六进制载荷', defaultWidth: 200, minWidth: 100, width: 200, sortable: false, visible: false },
];

const COLUMN_STORAGE_KEY = 'omni_probe_table_column_widths_v7_apple_hig';

interface StoredColumnConfig {
  width: number;
  visible?: boolean;
}

function loadStoredColumnConfigs(): Record<string, StoredColumnConfig> {
  try {
    const raw = localStorage.getItem(COLUMN_STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch (err) {
    console.warn('[TrafficAnalyzer] loadStoredColumnConfigs JSON parse failed, using defaults:', err);
    return {};
  }
}

function saveColumnConfigs(cols: ColumnDef[]) {
  try {
    const map: Record<string, StoredColumnConfig> = {};
    cols.forEach(c => {
      map[c.key] = {
        width: c.width,
        visible: c.visible !== false,
      };
    });
    localStorage.setItem(COLUMN_STORAGE_KEY, JSON.stringify(map));
  } catch (err) {
    console.warn('[TrafficAnalyzer] saveColumnConfigs to localStorage failed:', err);
  }
}

const storedConfigs = loadStoredColumnConfigs();
const columns = ref<ColumnDef[]>(
  DEFAULT_COLUMNS.map(c => {
    const stored = storedConfigs[c.key];
    return {
      ...c,
      width: stored?.width ? Math.max(c.minWidth, stored.width) : c.defaultWidth,
      visible: stored?.visible !== undefined ? stored.visible : (c.visible !== false),
    };
  })
);

const isColumnSettingsOpen = ref(false);

const visibleColumns = computed(() => columns.value.filter(c => c.visible !== false));

function isColVisible(key: string): boolean {
  const col = columns.value.find(c => c.key === key);
  return col ? col.visible !== false : false;
}

const gridTemplateStyle = computed(() => {
  const visible = visibleColumns.value;
  const parts = visible.map((c, idx) => {
    if (idx === visible.length - 1) {
      return `minmax(${c.width}px, 1fr)`;
    }
    return `${c.width}px`;
  });
  return {
    display: 'grid',
    gridTemplateColumns: parts.join(' '),
    gap: '0.5rem',
  };
});

const totalTableMinWidth = computed(() => {
  const visible = visibleColumns.value;
  const sum = visible.reduce((acc, c) => acc + c.width, 0);
  const gaps = Math.max(0, visible.length - 1) * 8 + 32;
  return `${sum + gaps}px`;
});

const resizingColumnKey = ref<string | null>(null);
const resizeGuideX = ref(0);
const resizingColumnLabel = ref('');
const resizingCurrentWidth = ref(0);
let startX = 0;
let startWidth = 0;
let currentVisibleColIndex = -1;

function startColResize(e: MouseEvent, visibleIndex: number) {
  e.preventDefault();
  e.stopPropagation();
  currentVisibleColIndex = visibleIndex;
  const col = visibleColumns.value[visibleIndex];
  if (!col) return;
  resizingColumnKey.value = col.key;
  resizingColumnLabel.value = col.label;
  resizingCurrentWidth.value = col.width;
  startX = e.clientX;
  startWidth = col.width;
  resizeGuideX.value = e.clientX;

  document.body.style.cursor = 'col-resize';
  document.body.style.userSelect = 'none';

  window.addEventListener('mousemove', onColResizeMove);
  window.addEventListener('mouseup', onColResizeEnd);
}

function onColResizeMove(e: MouseEvent) {
  if (currentVisibleColIndex < 0) return;
  const col = visibleColumns.value[currentVisibleColIndex];
  if (!col) return;
  const deltaX = e.clientX - startX;
  const newWidth = Math.max(col.minWidth, startWidth + deltaX);
  col.width = Math.round(newWidth);
  resizingCurrentWidth.value = col.width;
  resizeGuideX.value = e.clientX;
}

function onColResizeEnd() {
  currentVisibleColIndex = -1;
  resizingColumnKey.value = null;
  document.body.style.cursor = '';
  document.body.style.userSelect = '';
  window.removeEventListener('mousemove', onColResizeMove);
  window.removeEventListener('mouseup', onColResizeEnd);
  saveColumnConfigs(columns.value);
}

function resetColWidth(visibleIndex: number) {
  const col = visibleColumns.value[visibleIndex];
  if (!col) return;
  col.width = col.defaultWidth;
  saveColumnConfigs(columns.value);
}

function resetAllColWidths() {
  columns.value.forEach(c => {
    const def = DEFAULT_COLUMNS.find(d => d.key === c.key);
    c.width = c.defaultWidth;
    c.visible = def ? (def.visible !== false) : true;
  });
  saveColumnConfigs(columns.value);
}

function onSaveColumnSettings(updatedCols: ColumnDef[]) {
  columns.value = updatedCols;
  saveColumnConfigs(columns.value);
}

function toggleSort(key: string) {
  if (sortKey.value === key) {
    sortAsc.value = !sortAsc.value;
  } else {
    sortKey.value = key;
    sortAsc.value = true;
  }
}

/**
 * 格式化获取 IP 地理或资产归属位置字符串
 * 输出格式: 国家/地区/地址 (例如: "中国/江苏/南京/电信", "中国/广东/深圳/阿里云", "内网/大型企业主干网")
 */
function formatEndpoint(ip?: string, port?: number): string {
  const safeIp = ip || '0.0.0.0';
  if (port && port > 0) {
    return `${safeIp}:${port}`;
  }
  return safeIp;
}

function formatEndpointTitle(ip?: string, port?: number, pkt?: PacketRecord, isDst = false): string {
  const ep = formatEndpoint(ip, port);
  const loc = pkt ? getEndpointLocation(pkt, isDst) : '';
  return loc ? `${ep} (${loc})` : ep;
}

function getEndpointLocation(pkt: PacketRecord | null | undefined, isDst = false): string {
  if (!pkt) return '';
  const bdata = pkt.business_data;
  if (!bdata) return '';

  const prefix = isDst ? 'dst_' : 'src_';
  const country = bdata[`${prefix}country`] && bdata[`${prefix}country`] !== '0' ? String(bdata[`${prefix}country`]).trim() : '';
  const province = bdata[`${prefix}province`] && bdata[`${prefix}province`] !== '0' && bdata[`${prefix}province`] !== country ? String(bdata[`${prefix}province`]).trim() : '';
  const city = bdata[`${prefix}city`] && bdata[`${prefix}city`] !== '0' && bdata[`${prefix}city`] !== province ? String(bdata[`${prefix}city`]).trim() : '';
  const isp = bdata[`${prefix}isp`] && bdata[`${prefix}isp`] !== '0' ? String(bdata[`${prefix}isp`]).trim() : '';

  const segments: string[] = [];
  if (country) segments.push(country);
  if (province) segments.push(province);
  if (city) segments.push(city);
  if (isp) segments.push(isp);

  if (segments.length > 0) {
    return segments.join('/');
  }

  const zone = bdata[`${prefix}zone`];
  if (zone) {
    return String(zone).trim();
  }

  const geo = bdata[`${prefix}geo`];
  if (geo) {
    return String(geo).trim();
  }

  return '';
}

function getEndpointTag(pkt: PacketRecord | null | undefined, isDst = false): string {
  if (!pkt) return '';
  const loc = getEndpointLocation(pkt, isDst);
  if (!loc) return '';
  if (loc.includes('内网') || loc.includes('私网') || loc.includes('RFC 1918') || loc.includes('保留')) {
    return '内网';
  }
  if (loc.includes('回环') || loc.includes('127.0.0.1')) {
    return '回环';
  }
  if (loc.includes('专线')) {
    return '专线';
  }
  const parts = loc.split('/').filter(Boolean);
  if (parts.length === 0) return '';
  
  // 智能优先级提取：有城市优先显示城市(如 杭州/南京/Monroe)，无城市有省份显示省份，再次国家/运营商
  const bdata = pkt.business_data;
  const prefix = isDst ? 'dst_' : 'src_';
  if (bdata) {
    const city = bdata[`${prefix}city`];
    if (city && city !== '0') {
      const cleanCity = String(city).replace(/[()（）省市区县]/g, '').trim();
      if (cleanCity) return cleanCity.slice(0, 4);
    }
    const prov = bdata[`${prefix}province`];
    if (prov && prov !== '0') {
      const cleanProv = String(prov).replace(/[()（）省市]/g, '').trim();
      if (cleanProv) return cleanProv.slice(0, 4);
    }
  }

  const last = parts[parts.length - 1] || '';
  const clean = last.replace(/[()（）]/g, '').trim();
  return clean.length > 4 ? clean.slice(0, 4) : clean;
}

function getRemoteIpTag(pkt: PacketRecord | null | undefined): string {
  return getEndpointTag(pkt, false);
}

function getRemoteIpLocation(pkt: PacketRecord | null | undefined): string {
  return getEndpointLocation(pkt, false);
}

function formatRemoteIp(pkt: PacketRecord | null | undefined): string {
  if (!pkt) return '';
  const ip = pkt.src_ip || 'LOCAL_HOST';
  const loc = getRemoteIpLocation(pkt);
  return loc ? `${ip} (${loc})` : ip;
}

function hexToBytes(hexStr?: string): number[] {
  if (!hexStr) return [];
  const cleaned = hexStr.replace(/\s+/g, '');
  if (cleaned.length < 2) return [];
  const out: number[] = [];
  for (let i = 0; i + 1 < cleaned.length; i += 2) {
    const val = parseInt(cleaned.slice(i, i + 2), 16);
    if (!Number.isNaN(val)) out.push(val);
  }
  return out;
}

function getPacketL7Summary(pkt: PacketRecord): string {
  if (!pkt) return '';
  const bdata = pkt.business_data;
  if (bdata?.ics_acl_violation) {
    const v = bdata.ics_acl_violation as { reason?: string; rule_name?: string };
    return `[ACL阻断] ${v.rule_name || '越权控制'} ${v.reason || ''}`.trim();
  }
  if (Array.isArray(bdata?.threat_hits) && bdata.threat_hits.length > 0) {
    const firstHit = bdata.threat_hits[0] as { name?: string };
    return `[威胁命中:${bdata.threat_hits.length}] ${firstHit?.name || '特征告警'}`;
  }
  if (bdata?.tls_ja3_hash) {
    return `TLS JA3:${String(bdata.tls_ja3_hash).slice(0, 12)}... | JA4:${bdata.tls_ja4 || '--'}`;
  }
  if (bdata?.quic_decrypted) {
    return `QUIC/HTTP3 ${bdata.quic_packet_type || 'Initial'} | PN:${bdata.quic_packet_number ?? '--'} (${bdata.quic_frames_count ?? 0} 帧)`;
  }
  if (bdata?.plugin_summary) {
    return String(bdata.plugin_summary);
  }
  if (pkt.raw_text && pkt.raw_text.trim() && !pkt.raw_text.startsWith('0x') && pkt.raw_text.length < 140) {
    return pkt.raw_text.trim();
  }

  // 严格从真实 payload_hex 解码帧首部关键字段，禁止按协议名拼凑虚假默认值
  const bytes = hexToBytes(pkt.payload_hex);
  const proto = (pkt.protocol || '').toUpperCase();
  if (proto.includes('MODBUS') && bytes.length >= 8 && bytes[2] === 0 && bytes[3] === 0) {
    const transId = (bytes[0] << 8) | bytes[1];
    const unitId = bytes[6];
    const fc = bytes[7];
    const regAddr = bytes.length >= 10 ? ((bytes[8] << 8) | bytes[9]) : null;
    return regAddr !== null
      ? `MBAP TransID:0x${transId.toString(16).padStart(4, '0')} | Unit:${unitId} | FC:0x${fc.toString(16).padStart(2, '0')} | Addr:0x${regAddr.toString(16).padStart(4, '0')}`
      : `MBAP TransID:0x${transId.toString(16).padStart(4, '0')} | Unit:${unitId} | FC:0x${fc.toString(16).padStart(2, '0')}`;
  }
  if (proto.includes('S7') && bytes.length >= 12) {
    const s7Idx = bytes.findIndex((b, idx) => b === 0x32 && idx + 4 < bytes.length);
    if (s7Idx >= 0) {
      const rosctr = bytes[s7Idx + 1];
      const pduRef = (bytes[s7Idx + 4] << 8) | bytes[s7Idx + 5];
      return `S7Comm ROSCTR:0x${rosctr.toString(16).padStart(2, '0')} | PDU-Ref:0x${pduRef.toString(16).padStart(4, '0')} (${bytes.length}B)`;
    }
  }
  if (proto.includes('ARP')) {
    return `ARP 解析: ${pkt.src_ip || '--'} -> ${pkt.dst_ip || '--'} (${pkt.length}B)`;
  }
  if (bytes.length > 0) {
    const asciiPreview = bytes
      .slice(0, 48)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    return `Hex[${bytes.length}B]: ${pkt.payload_hex.slice(0, 24)} (${asciiPreview.slice(0, 24)})`;
  }
  return `${pkt.protocol || pkt.transport || 'Frame'} (${pkt.length} 字节，无应用层载荷)`;
}

interface L7StructuredSummary {
  kind: 'sys_ctrl' | 'ascii_hex' | 'key_val' | 'plain';
  badge?: string;
  badgeClass?: string;
  action?: string;
  actionClass?: string;
  detail?: string;
  asciiText?: string;
  hexText?: string;
  prefix?: string;
  body?: string;
  plainText?: string;
}

function parseL7StructuredSummary(pkt: PacketRecord): L7StructuredSummary {
  const raw = getPacketL7Summary(pkt);
  if (!raw) return { kind: 'plain', plainText: '' };

  // 1. 系统控制事件: [SYS_CTRL] ACTION DETAIL
  if (raw.startsWith('[SYS_CTRL]')) {
    const after = raw.slice(10).trim();
    const spaceIdx = after.indexOf(' ');
    let action = '';
    let detail = '';
    if (spaceIdx > 0) {
      action = after.slice(0, spaceIdx).trim();
      detail = after.slice(spaceIdx + 1).trim();
    } else {
      action = after;
      detail = '';
    }

    let actionClass = 'text-sky-700 dark:text-sky-200 bg-sky-500/12 border border-sky-500/25 font-semibold';
    if (/DISCONNECT|CLOSE|RESET|FAIL|ERROR|DROP|TIMEOUT/i.test(action)) {
      actionClass = 'text-rose-700 dark:text-rose-200 bg-rose-500/15 border border-rose-500/25 font-semibold';
    } else if (/CONNECT|OPEN|ACCEPT|ESTABLISHED|OK|ACK/i.test(action)) {
      actionClass = 'text-emerald-700 dark:text-emerald-200 bg-emerald-500/15 border border-emerald-500/25 font-semibold';
    }

    return {
      kind: 'sys_ctrl',
      badge: 'SYS_CTRL',
      badgeClass: 'bg-slate-500/15 text-slate-700 dark:text-slate-200 border-slate-500/25 font-semibold',
      action,
      actionClass,
      detail
    };
  }

  // 2. 双模载荷预览: [ASCII] ... | [HEX] ...
  const asciiHexMatch = raw.match(/^\[ASCII\]\s*(.*?)\s*\|\s*\[HEX\]\s*(.*)$/);
  if (asciiHexMatch) {
    return {
      kind: 'ascii_hex',
      asciiText: asciiHexMatch[1],
      hexText: asciiHexMatch[2]
    };
  }

  // 3. 键值或指令分隔: 包含 | 或者 : 的规约解析
  if (raw.includes(' | ')) {
    const pipeIdx = raw.indexOf(' | ');
    return {
      kind: 'key_val',
      prefix: raw.slice(0, pipeIdx).trim(),
      body: raw.slice(pipeIdx + 3).trim()
    };
  }

  // 4. 普通纯文本
  return {
    kind: 'plain',
    plainText: raw
  };
}

interface L7TreeNode {
  text: string;
  level: number;
  fieldKey?: string;
  fieldValue?: string;
}

interface L7TreeResult {
  protocolTitle: string;
  statusBadge: string;
  nodes: L7TreeNode[];
}

const l7DecodedTree = computed<L7TreeResult>(() => {
  const pkt = selectedPacket.value;
  if (!pkt) {
    return {
      protocolTitle: '未选定报文',
      statusBadge: '待命',
      nodes: []
    };
  }

  const bytes = hexToBytes(pkt.payload_hex);
  const proto = (pkt.protocol || 'UNKNOWN').toUpperCase();
  const bdata = pkt.business_data || {};
  const nodes: L7TreeNode[] = [];

  // 1. 从真实十六进制应用层载荷解码底层协议字段 (无静态假数值)
  if (proto.includes('MODBUS') && bytes.length >= 8 && bytes[2] === 0 && bytes[3] === 0) {
    const transId = (bytes[0] << 8) | bytes[1];
    const pduLen = (bytes[4] << 8) | bytes[5];
    const unitId = bytes[6];
    const funcCode = bytes[7];
    nodes.push(
      { text: `▸ MBAP Header: TransID=0x${transId.toString(16).padStart(4, '0')}, Proto=0x0000, Len=${pduLen}, Unit=${unitId}`, level: 1, fieldKey: 'modbus.trans_id', fieldValue: String(transId) },
      { text: `▸ Modbus PDU: Function Code 0x${funcCode.toString(16).padStart(2, '0')} (${funcCode})`, level: 1, fieldKey: 'modbus.func_code', fieldValue: String(funcCode) },
    );
    if (bytes.length >= 10) {
      const refAddr = (bytes[8] << 8) | bytes[9];
      nodes.push({ text: `• 起始寄存器/线圈地址: 0x${refAddr.toString(16).padStart(4, '0')} (${refAddr})`, level: 2, fieldKey: 'modbus.reference_num', fieldValue: String(refAddr) });
    }
    if (bytes.length > 10) {
      nodes.push({ text: `• 真实数据载荷 (${bytes.length - 8}B): ${pkt.payload_hex.slice(16, 80)}`, level: 3 });
    }
  } else if (proto.includes('S7') && bytes.length >= 8) {
    const s7Idx = bytes.findIndex((b, idx) => b === 0x32 && idx + 8 <= bytes.length);
    if (s7Idx >= 0) {
      const rosctr = bytes[s7Idx + 1];
      const pduRef = (bytes[s7Idx + 4] << 8) | bytes[s7Idx + 5];
      const paramLen = (bytes[s7Idx + 6] << 8) | bytes[s7Idx + 7];
      const dataLen = bytes.length >= s7Idx + 10 ? ((bytes[s7Idx + 8] << 8) | bytes[s7Idx + 9]) : 0;
      nodes.push(
        { text: `▸ S7 Header (offset +${s7Idx}): ProtoId=0x32, ROSCTR=0x${rosctr.toString(16).padStart(2, '0')}, PDU-Ref=0x${pduRef.toString(16).padStart(4, '0')}`, level: 1, fieldKey: 's7comm.rosctr', fieldValue: String(rosctr) },
        { text: `• ParamLen=${paramLen}B | DataLen=${dataLen}B`, level: 2 },
      );
    }
  } else if ((proto.includes('SL651') || proto.includes('WATER')) && bytes.length >= 10 && bytes[0] === 0x7e && bytes[1] === 0x7e) {
    const centerAddr = bytes[2];
    const stationHex = bytes.slice(3, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
    const funcCode = bytes[10];
    nodes.push(
      { text: `▸ SL651-2014 帧定界符: 0x7E 0x7E | 报文长度: ${bytes.length}B`, level: 1 },
      { text: `• 实测中心站地址: 0x${centerAddr.toString(16).padStart(2, '0')} | 遥测站码(BCD): ${stationHex} | 功能码: 0x${funcCode.toString(16).padStart(2, '0')}`, level: 2 },
    );
  } else if ((proto.includes('104') || proto.includes('IEC')) && bytes.length >= 6 && bytes[0] === 0x68) {
    const apduLen = bytes[1];
    nodes.push(
      { text: `▸ IEC-104 APCI: Start=0x68, APDU Length=${apduLen}B`, level: 1 },
      { text: `• Control Octets: ${bytes.slice(2, 6).map((b) => '0x' + b.toString(16).padStart(2, '0')).join(' ')}`, level: 2 },
    );
    if (bytes.length >= 8) {
      nodes.push({ text: `• ASDU TypeID=${bytes[6]} | VSQ=0x${bytes[7].toString(16).padStart(2, '0')}`, level: 3 });
    }
  }

  // 2. 注入全部来自后端引擎的真实解析与审计字段 (DPI / GeoIP / TLS指纹 / QUIC / ACL / 威胁命中)
  const bdataEntries = Object.entries(bdata);
  if (bdataEntries.length > 0) {
    nodes.push({ text: `▸ 后端引擎实时解构字段 (共 ${bdataEntries.length} 项)`, level: 1 });
    for (const [k, v] of bdataEntries) {
      const formattedVal = typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v);
      nodes.push({
        text: `• ${k}: ${formattedVal.length > 140 ? formattedVal.slice(0, 140) + '...' : formattedVal}`,
        level: 2,
      });
    }
  }

  // 3. 若无高层结构则呈现真实字节长度、信息熵与原始 ASCII 摘要
  if (nodes.length === 0) {
    const rawPreview = bytes.length > 0
      ? bytes.slice(0, 48).map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('')
      : '无应用层载荷';
    nodes.push(
      { text: `▸ 帧长度: ${pkt.length} 字节 | 实测载荷: ${bytes.length} 字节 | 信息熵: ${pkt.entropy ? pkt.entropy.toFixed(2) : '0.00'}`, level: 1 },
      { text: `• 物理 MAC: ${pkt.mac_src || '--'} ➔ ${pkt.mac_dst || '--'}`, level: 2 },
      { text: `• 原始 ASCII 预览: ${pkt.raw_text || rawPreview}`, level: 3 },
    );
  }

  const hasThreat = Boolean(bdata.ics_acl_violation) || (Array.isArray(bdata.threat_hits) && bdata.threat_hits.length > 0);
  const statusBadge = hasThreat
    ? '安全威胁 / 策略命中'
    : (bdataEntries.length > 0 ? `引擎解析 ${bdataEntries.length} 字段` : '原始载荷实测');

  return {
    protocolTitle: `${pkt.protocol || 'Ethernet II'} (${pkt.transport || 'L2'}) 实测解析`,
    statusBadge,
    nodes,
  };
});

// 严格对齐 Python 原版过滤算法：支持逗号 (OR) 与空格 (AND)，并支持地理与运营商搜索
function checkFilter(p: PacketRecord, filter: string): boolean {
  if (!filter) return true;
  const orGroups = filter.split(',').map(g => g.trim().toLowerCase()).filter(Boolean);
  if (orGroups.length === 0) return true;

  for (const group of orGroups) {
    const andTerms = group.split(/\s+/).filter(Boolean);
    let groupMatch = true;
    for (const term of andTerms) {
      const bdata = p.business_data;
      const termMatch =
        String(p.src_port).includes(term) ||
        String(p.dst_port).includes(term) ||
        p.src_ip.toLowerCase().includes(term) ||
        p.dst_ip.toLowerCase().includes(term) ||
        formatRemoteIp(p).toLowerCase().includes(term) ||
        p.protocol.toLowerCase().includes(term) ||
        p.transport.toLowerCase().includes(term) ||
        p.direction.toLowerCase().includes(term) ||
        (p.mac_src && p.mac_src.toLowerCase().includes(term)) ||
        (p.mac_dst && p.mac_dst.toLowerCase().includes(term)) ||
        (p.payload_hex && p.payload_hex.toLowerCase().includes(term)) ||
        (p.raw_text && p.raw_text.toLowerCase().includes(term)) ||
        (bdata?.src_country && String(bdata.src_country).toLowerCase().includes(term)) ||
        (bdata?.src_province && String(bdata.src_province).toLowerCase().includes(term)) ||
        (bdata?.src_city && String(bdata.src_city).toLowerCase().includes(term)) ||
        (bdata?.src_isp && String(bdata.src_isp).toLowerCase().includes(term)) ||
        (bdata?.src_geo && String(bdata.src_geo).toLowerCase().includes(term)) ||
        (bdata?.src_zone && String(bdata.src_zone).toLowerCase().includes(term));
      
      if (!termMatch) {
        groupMatch = false;
        break;
      }
    }
    if (groupMatch) return true;
  }
  return false;
}

/**
 * 根据当前总线类型自适应表头标签
 */
function getColumnLabel(col: ColumnDef): string {
  if (activeBus.value === 'serial') {
    if (col.key === 'src_ip') return '物理串口 (COM)';
    if (col.key === 'mac_src') return '通信端点';
    if (col.key === 'src_port') return '串口状态';
    if (col.key === 'dst_port') return '波特率';
    if (col.key === 'transport') return '总线类型';
    if (col.key === 'direction') return '串口流向';
  } else if (activeBus.value === 'usb') {
    if (col.key === 'src_ip') return 'USB 设备标识';
    if (col.key === 'mac_src') return '传输类型';
    if (col.key === 'src_port') return '端点号';
    if (col.key === 'dst_port') return '通信状态';
  }
  return col.label;
}

/**
 * 当前选定物理总线下的全部报文池 (总线物理隔离)
 */
const busTotalPackets = computed(() => {
  const all = props.packets;
  if (activeBus.value === 'serial') {
    return all.filter(p => p.transport === 'SERIAL' || p.direction?.startsWith('SERIAL'));
  } else if (activeBus.value === 'usb') {
    return all.filter(p => p.transport === 'USB' || p.direction?.startsWith('USB'));
  } else {
    // 网卡模式：严格排除串口与 USB 报文
    return all.filter(p => p.transport !== 'SERIAL' && p.transport !== 'USB' && !p.direction?.startsWith('SERIAL') && !p.direction?.startsWith('USB'));
  }
});

// 苹果数据流控制底盘：当前作用域过滤 (all | alert | industrial | serial_usb)
const currentScopeFilter = ref<'all' | 'alert' | 'industrial' | 'serial_usb'>('all');
const isAutoScroll = ref(true);

function setScope(scope: 'all' | 'alert' | 'industrial' | 'serial_usb') {
  currentScopeFilter.value = scope;
}

const filteredPackets = computed(() => {
  let list = busTotalPackets.value;
  if (currentScopeFilter.value === 'alert') {
    list = list.filter(p => p.entropy_level === 'critical' || (p as any).is_alert || (p as any).severity === 'high');
  } else if (currentScopeFilter.value === 'industrial') {
    list = list.filter(p => /^MODBUS|S7_|ENIP|DNP3|IEC104|BACNET|OPC|ETHERCAT|GOOSE|MMS/i.test(p.protocol));
  } else if (currentScopeFilter.value === 'serial_usb') {
    list = list.filter(p => p.transport === 'SERIAL' || p.transport === 'USB' || p.direction?.startsWith('SERIAL') || p.direction?.startsWith('USB'));
  }
  if (astMatchedIds.value !== null) {
    list = list.filter(p => astMatchedIds.value!.has(p.id));
  } else if (filterText.value.trim()) {
    list = list.filter(p => checkFilter(p, filterText.value.trim()));
  }
  if (filterProtocol.value) {
    list = list.filter(p => p.protocol.startsWith(filterProtocol.value));
  }
  if (sortKey.value) {
    const k = sortKey.value;
    list = [...list].sort((a, b) => {
      let va: any = (a as any)[k];
      let vb: any = (b as any)[k];
      if (k === 'src_endpoint') {
        va = formatEndpoint(a.src_ip, a.src_port);
        vb = formatEndpoint(b.src_ip, b.src_port);
      } else if (k === 'dst_endpoint') {
        va = formatEndpoint(a.dst_ip, a.dst_port);
        vb = formatEndpoint(b.dst_ip, b.dst_port);
      } else if (k === 'l7_summary') {
        va = getPacketL7Summary(a);
        vb = getPacketL7Summary(b);
      }
      let res = 0;
      if (typeof va === 'number' && typeof vb === 'number') {
        res = va - vb;
      } else {
        res = String(va || '').localeCompare(String(vb || ''));
      }
      return sortAsc.value ? res : -res;
    });
  }
  return list;
});

// 虚拟滚动
const tableContainer = ref<HTMLElement | null>(null);
const ROW_HEIGHT = 34;
const BUFFER = 10;
const scrollTop = ref(0);
const containerHeight = ref(500);

function onScroll(e: Event) {
  const el = e.target as HTMLElement;
  scrollTop.value = el.scrollTop;
  containerHeight.value = el.clientHeight;
}

const totalHeight = computed(() => filteredPackets.value.length * ROW_HEIGHT);
const startIdx = computed(() => Math.max(0, Math.floor(scrollTop.value / ROW_HEIGHT) - BUFFER));
const endIdx = computed(() => Math.min(filteredPackets.value.length, startIdx.value + Math.ceil(containerHeight.value / ROW_HEIGHT) + BUFFER * 2));
const visiblePackets = computed(() => filteredPackets.value.slice(startIdx.value, endIdx.value));
const offsetY = computed(() => startIdx.value * ROW_HEIGHT);

const lastClickedIndex = ref<number>(-1);

function handleRowClick(e: MouseEvent, pkt: PacketRecord, index?: number) {
  isInspectorOpen.value = true; // 单击报文行即时滑出随行抽屉
  if (e.shiftKey && lastClickedIndex.value >= 0 && index !== undefined) {
    const start = Math.min(lastClickedIndex.value, index);
    const end = Math.max(lastClickedIndex.value, index);
    const newSet = new Set(selectedPackets.value);
    for (let i = start; i <= end; i++) {
      const p = filteredPackets.value[i];
      if (p) newSet.add(p.id);
    }
    selectedPackets.value = newSet;
    selectedPacket.value = pkt;
  } else if (e.ctrlKey || e.metaKey) {
    const s = new Set(selectedPackets.value);
    if (s.has(pkt.id)) s.delete(pkt.id); else s.add(pkt.id);
    selectedPackets.value = s;
    selectedPacket.value = pkt;
    if (index !== undefined) lastClickedIndex.value = index;
  } else {
    selectedPacket.value = pkt;
    selectedPackets.value = new Set([pkt.id]);
    if (index !== undefined) lastClickedIndex.value = index;
  }
}

function togglePacketCheck(pkt: PacketRecord) {
  const s = new Set(selectedPackets.value);
  if (s.has(pkt.id)) s.delete(pkt.id); else s.add(pkt.id);
  selectedPackets.value = s;
  selectedPacket.value = pkt;
}

function clearSelectedPackets() {
  selectedPackets.value = new Set();
}

function openDiffWithSelected2() {
  const selArr = Array.from(selectedPackets.value)
    .map(id => props.packets.find(p => p.id === id))
    .filter(Boolean) as PacketRecord[];
  if (selArr.length >= 2) {
    diffBus.openUniversalDiff(selArr[0], selArr[1], 'hex');
    emit('appendLog', `[DIFF] ✓ 已将选中的报文 #${selArr[0].id} 与 #${selArr[1].id} 送入双组精密比对工作台`);
  }
}

function openGlobalMultiDiffWithSelected() {
  const selArr = Array.from(selectedPackets.value)
    .map(id => props.packets.find(p => p.id === id))
    .filter(Boolean) as PacketRecord[];
  if (selArr.length >= 2) {
    const items = selArr.map((p) => ({
      ...p,
      label: `帧 #${p.id} (${p.protocol || 'RAW'})`
    }));
    diffBus.openMultiDiff(items, 0, 'multi');
    emit('appendLog', `[DIFF] ✓ 已将选中的 ${items.length} 帧报文送入全局 Center-Star 多组精准对齐工作台`);
  }
}

function queuePacketForDiff(pkt: PacketRecord) {
  diffBus.addToQueue(pkt, `帧 #${pkt.id} (${pkt.protocol || 'RAW'})`, false);
}

async function quickSelectFirstTwoAndCompare() {
  if (filteredPackets.value.length >= 2) {
    const p1 = filteredPackets.value[0];
    const p2 = filteredPackets.value[1];
    selectedPackets.value = new Set([p1.id, p2.id]);
    selectedPacket.value = p1;
    await runMatrixCompare();
  }
}

async function saveSelectedPacketsAsBaseline() {
  const selArr = Array.from(selectedPackets.value)
    .map(id => props.packets.find(p => p.id === id))
    .filter(Boolean) as PacketRecord[];
  if (selArr.length === 0) return;
  const payloads = selArr.map(p => p.payload_hex).filter(Boolean);
  if (payloads.length === 0) return;
  try {
    const count = await invoke<number>('save_baseline_payloads_cmd', { payloads });
    emit('appendLog', `[BASELINE] ✓ 已批量保存 ${count} 条报文特征载荷至基线库`);
    notifySuccess('基线固化成功', `已批量保存 ${count} 条特征报文至本地基线库`);
  } catch (e: any) {
    emit('appendLog', `[ERROR] 批量保存基线失败: ${e}`);
    notifyError('保存基线受阻', e);
  }
}

function openDetailModal(pkt: PacketRecord) {
  detailPacket.value = pkt;
  isDetailModalOpen.value = true;
}

function saveSelectedAsBaseline() {
  if (selectedPacket.value) {
    emit('saveBaseline', selectedPacket.value);
  }
}

function saveAsBaseline(pkt: PacketRecord) {
  emit('saveBaseline', pkt);
}

function openMatrixTab() {
  runMatrixCompare();
  activeBottomTab.value = 'matrix';
  isInspectorOpen.value = true;
}

function openWaveTab() {
  if (selectedPacket.value) {
    setupWaveFromSelected();
  }
  activeBottomTab.value = 'wave';
  isInspectorOpen.value = true;
}

// 示波器波形追踪逻辑 (实时对接后端 wave-data IPC 事件)
const waveCanvasRef = ref<HTMLCanvasElement | null>(null);
const wavePoints = ref<Array<{ value: number; ts_ms: number }>>([]);
const waveConfig = ref({ ip: '*', offset: 0, length: 2, signed: false, little_endian: false });
const waveActive = ref(false);
const waveMax = computed(() => wavePoints.value.length ? Math.max(...wavePoints.value.map(p => p.value)) : 0);
const waveMin = computed(() => wavePoints.value.length ? Math.min(...wavePoints.value.map(p => p.value)) : 0);

function setupWaveFromSelected() {
  if (!selectedPacket.value) return;
  waveConfig.value.ip = selectedPacket.value.src_ip;
}

async function startWave() {
  const targetIp = waveConfig.value.ip.trim() || '*';
  waveConfig.value.ip = targetIp;
  wavePoints.value = [];
  try {
    await invoke('set_wave_tracker', {
      ip: targetIp,
      offset: waveConfig.value.offset,
      length: waveConfig.value.length,
      signed: waveConfig.value.signed,
      littleEndian: waveConfig.value.little_endian
    });
    waveActive.value = true;
    emit('appendLog', `[WAVE] 物理示波波形采样已启动 (Target=${targetIp}, Offset=${waveConfig.value.offset}B, Len=${waveConfig.value.length}B)`);
  } catch (e) {
    emit('appendLog', `[ERROR] 示波器波形追踪启动失败: ${e}`);
  }
}

async function stopWave() {
  try {
    await invoke('set_wave_tracker', { ip: '', offset: 0, length: 0, signed: false, littleEndian: false });
  } catch (e) {
    emit('appendLog', `[ERROR] 停止示波器波形追踪失败: ${e}`);
  }
  waveActive.value = false;
}

function drawWaveform() {
  const canvas = waveCanvasRef.value;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) return;
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);
  const W = rect.width, H = rect.height;

  // 苹果深空蓝灰通透背景
  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, '#0f172a');
  grad.addColorStop(1, '#020617');
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, W, H);
  const pts = wavePoints.value;
  if (pts.length < 2) return;

  const min = waveMin.value, max = waveMax.value, range = max - min || 1;
  const toY = (v: number) => H - 20 - ((v - min) / range) * (H - 40);

  ctx.strokeStyle = 'rgba(51, 65, 85, 0.4)';
  ctx.lineWidth = 1;
  for (let g = 0; g <= 4; g++) {
    const y = 15 + (g / 4) * (H - 30);
    ctx.beginPath(); ctx.moveTo(40, y); ctx.lineTo(W - 10, y); ctx.stroke();
    ctx.fillStyle = '#94a3b8'; ctx.font = '10px monospace';
    ctx.fillText((max - (g / 4) * range).toFixed(0), 4, y + 3);
  }

  // 霓虹微光科技蓝线条
  ctx.shadowColor = 'rgba(56, 189, 248, 0.8)';
  ctx.shadowBlur = 8;
  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 2;
  ctx.beginPath();
  const step = (W - 50) / Math.max(pts.length - 1, 1);
  pts.forEach((p, i) => {
    const x = 45 + i * step;
    const y = toY(p.value);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.shadowBlur = 0;
}

watch(wavePoints, () => nextTick(drawWaveform), { deep: false });
watch(activeBottomTab, v => {
  if (v === 'wave') nextTick(drawWaveform);
});

// LCS 矩阵比对逻辑
const matrixPayloads = ref<string[]>([]);
const matrixResult = ref<MatrixResult | null>(null);
const matrixSpectrumCanvas = ref<HTMLCanvasElement | null>(null);
const hoverSpectrumBin = ref<MutationWaveBin | null>(null);

function drawMatrixSpectrum() {
  const canvas = matrixSpectrumCanvas.value;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) return;

  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);

  const W = rect.width;
  const H = rect.height;

  // 底色
  ctx.fillStyle = '#020617';
  ctx.fillRect(0, 0, W, H);

  const padL = 30;
  const padR = 14;
  const padT = 10;
  const padB = 18;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  // 标尺参考线
  ctx.strokeStyle = 'rgba(51, 65, 85, 0.4)';
  ctx.lineWidth = 1;
  ctx.fillStyle = '#64748b';
  ctx.font = '9px monospace';

  const rates = [0, 50, 100];
  for (const r of rates) {
    const y = padT + plotH - (r / 100) * plotH;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(W - padR, y);
    ctx.stroke();
    ctx.fillText(`${r}%`, 4, y + 3);
  }

  const spec = matrixResult.value?.mutation_spectrum || [];
  if (spec.length === 0) return;

  const colW = Math.max(1, (plotW / spec.length) - 1);
  const stepX = plotW / spec.length;

  // 1. 绘制变异波率彩色直方柱
  spec.forEach((b, idx) => {
    const barH = (b.mutation_rate / 100) * plotH;
    const x = padL + idx * stepX;
    const y = padT + plotH - barH;

    if (b.mutation_rate === 0) {
      ctx.fillStyle = '#10b981'; // 0% 翡翠绿
      ctx.fillRect(x, padT + plotH - 2, Math.max(1, colW), 2);
    } else if (b.mutation_rate <= 50) {
      ctx.fillStyle = '#f59e0b'; // 1~50% 琥珀黄
      ctx.fillRect(x, y, Math.max(1, colW), Math.max(2, barH));
    } else {
      ctx.fillStyle = '#f43f5e'; // >50% 玫瑰红
      ctx.fillRect(x, y, Math.max(1, colW), Math.max(2, barH));
    }
  });

  // 2. 叠加局部信息熵折线 (紫色)
  ctx.strokeStyle = '#c084fc';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  spec.forEach((b, idx) => {
    const x = padL + (idx + 0.5) * stepX;
    const y = padT + plotH - (Math.min(8.0, b.entropy) / 8.0) * plotH;
    if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // 3. 悬浮高亮指示
  if (hoverSpectrumBin.value) {
    const idx = hoverSpectrumBin.value.offset;
    const x = padL + idx * stepX;
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 1.5;
    ctx.strokeRect(x - 1, padT, Math.max(2, colW + 2), plotH);
  }
}

function onMatrixSpectrumHover(e: MouseEvent) {
  const canvas = matrixSpectrumCanvas.value;
  if (!canvas || !matrixResult.value?.mutation_spectrum) return;
  const rect = canvas.getBoundingClientRect();
  const mouseX = e.clientX - rect.left;
  const padL = 30;
  const padR = 14;
  const plotW = rect.width - padL - padR;
  const spec = matrixResult.value.mutation_spectrum;
  if (spec.length === 0) return;

  const relX = Math.max(0, Math.min(plotW, mouseX - padL));
  const idx = Math.min(spec.length - 1, Math.floor((relX / plotW) * spec.length));
  hoverSpectrumBin.value = spec[idx] || null;
  drawMatrixSpectrum();
}

watch([matrixResult, activeBottomTab], () => {
  if (activeBottomTab.value === 'matrix') {
    nextTick(drawMatrixSpectrum);
  }
});

async function runMatrixCompare() {
  const fromSel = Array.from(selectedPackets.value)
    .map(id => props.packets.find(p => p.id === id))
    .filter(Boolean) as PacketRecord[];
  if (fromSel.length < 2) return;
  const payloads = fromSel.map(p => p.payload_hex);
  const labels = fromSel.map(p => `#${p.id} [${p.protocol}] ${p.src_ip}:${p.src_port}➔${p.dst_ip}:${p.dst_port}`);
  matrixPayloads.value = payloads;
  activeBottomTab.value = 'matrix';
  try {
    matrixResult.value = await invoke<MatrixResult>('run_matrix_compare_labeled_cmd', { payloads, labels });
    emit('appendLog', `[MATRIX] ✓ 成功完成 ${fromSel.length} 组特征报文矩阵对齐比对`);
    nextTick(drawMatrixSpectrum);
  } catch (e) {
    emit('appendLog', `[ERROR] LCS 矩阵比对失败: ${e}`);
  }
}

async function exportMatrixReport() {
  if (!matrixResult.value) return;
  const res = matrixResult.value;
  const timeStr = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '');
  let md = `# Omni-Probe 多报文矩阵特征比对分析报告\n\n`;
  md += `- **生成时间**: ${timeStr}\n`;
  md += `- **比对样本总数**: ${res.payloads.length} 组\n`;
  md += `- **分析结论**: ${res.summary}\n\n`;

  if (res.mutation_spectrum && res.mutation_spectrum.length > 0) {
    md += `## 1. 各字节偏移变异波率与局部熵分布\n\n`;
    md += `| 字节偏移 | 主导特征十六进制 | 变异波率 (%) | 局部信息熵 (bit) | 变异等级 |\n`;
    md += `| :--- | :--- | :--- | :--- | :--- |\n`;
    res.mutation_spectrum.forEach(b => {
      const level = b.mutation_rate === 0 ? '基准特征码' : b.mutation_rate <= 50 ? '低频抖动' : '**高频突变**';
      md += `| 0x${b.offset.toString(16).toUpperCase()} (#${b.offset}) | \`0x${b.dominant_hex}\` | ${b.mutation_rate.toFixed(1)}% | ${b.entropy.toFixed(3)} | ${level} |\n`;
    });
    md += `\n`;
  }

  md += `## 2. 各样本特征对齐 Hex 矩阵\n\n`;
  res.payloads.forEach((p, idx) => {
    md += `### 样本 ${idx + 1}: ${p.label} (${p.byte_length} 字节)\n\`\`\`\n`;
    p.hex_rows.forEach(r => {
      const hexStr = r.cells.map(c => c.hex).join(' ');
      md += `${r.offset}  ${hexStr.padEnd(48, ' ')}  |${r.ascii_repr}|\n`;
    });
    md += `\`\`\`\n\n`;
  });
  await saveTextViaNativeDesktop(
    `matrix_diff_report_${Date.now()}.md`,
    md,
    'Markdown 分析报告 (*.md)',
    '*.md',
    '导出多报文特征矩阵报告'
  );
}

async function loadHistoricalBaseline() {
  try {
    const list = await invoke<string[]>('load_baseline_payloads_cmd');
    if (list.length > 0) matrixPayloads.value = list;
  } catch (e) {
    emit('appendLog', `[ERROR] 加载历史基线失败: ${e}`);
  }
}

async function runJointBaselineCompare() {
  try {
    matrixResult.value = await invoke<MatrixResult>('compare_with_historical_baseline_cmd', {
      currentPayloads: matrixPayloads.value
    });
  } catch (e) {
    emit('appendLog', `[ERROR] 联合基线比对失败: ${e}`);
  }
}

const totalBytes = computed(() => props.packets.reduce((acc, p) => acc + (p.length || 0), 0));
const criticalCount = computed(() => props.packets.filter(p => p.entropy_level === 'critical').length);

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function directionBadgeClass(direction: string): string {
  if (direction === 'HONEYPOT_RECV') {
    return 'bg-amber-500 text-slate-950 font-semibold border-amber-600';
  }
  if (direction === 'SYS_CTRL') {
    return 'bg-slate-500/15 text-slate-700 dark:text-slate-200 border-slate-500/25 font-semibold';
  }
  if (direction === 'SYS_ALERT') {
    return 'bg-rose-500/15 text-rose-700 dark:text-rose-200 border-rose-500/30 font-semibold';
  }
  if (direction === 'PASSIVE_RECV' || direction === 'IN' || direction === 'PORT_INBOUND' || direction === 'INBOUND') {
    return 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30 font-semibold';
  }
  if (direction === 'ACTIVE_PULL' || direction === 'OUT' || direction === 'PORT_OUTBOUND' || direction === 'OUTBOUND') {
    return 'bg-blue-500/15 text-blue-700 dark:text-sky-300 border-blue-500/30 font-semibold';
  }
  if (direction === 'SERIAL_TX') return 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border-indigo-500/30 font-semibold';
  if (direction === 'SERIAL_RX') return 'bg-purple-500/15 text-purple-700 dark:text-purple-300 border-purple-500/30 font-semibold';
  if (direction === 'USB_ATTACH' || direction === 'USB_DETACH') return 'bg-teal-500/15 text-teal-700 dark:text-teal-300 border-teal-500/30 font-semibold';
  return 'bg-slate-500/12 text-slate-700 dark:text-slate-300 border-slate-500/25 font-medium';
}

function protocolColor(proto: string): string {
  if (/^MODBUS/.test(proto)) return 'proto-badge proto-modbus';
  if (/^S7_|^S7COMM/.test(proto)) return 'proto-badge proto-s7comm';
  if (/^IEC104/.test(proto)) return 'proto-badge proto-iec104';
  if (/^GOOSE/.test(proto)) return 'proto-badge proto-goose';
  if (/^ENIP/.test(proto)) return 'proto-badge proto-enip';
  if (/^OPC/.test(proto)) return 'proto-badge proto-opcua';
  if (/^ALERT|^DLP/.test(proto)) return 'proto-badge proto-alert';
  if (/^MQTT|AMQP|COAP/.test(proto)) return 'proto-badge bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30';
  if (/^TLS|SSH/.test(proto)) return 'proto-badge bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30';
  if (/^HTTP/.test(proto)) return 'proto-badge bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-500/30';
  if (/^DNS|NTP|DHCP/.test(proto)) return 'proto-badge bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30';
  if (/^SERIAL/.test(proto)) return 'proto-badge bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30';
  if (/^USB/.test(proto)) return 'proto-badge bg-fuchsia-500/15 text-fuchsia-700 dark:text-fuchsia-300 border border-fuchsia-500/30';
  return 'proto-badge bg-slate-500/15 text-slate-700 dark:text-slate-300 border border-slate-500/25';
}

function formatAlignedHexDump(hexStr: string): string[] {
  if (!hexStr) return [];
  const clean = hexStr.replace(/\s+/g, '');
  const lines: string[] = [];
  for (let offset = 0; offset < clean.length; offset += 32) {
    const chunk = clean.slice(offset, offset + 32);
    const offsetHex = (offset / 2).toString(16).padStart(4, '0').toUpperCase();
    const hexBytes: string[] = [];
    const asciiChars: string[] = [];
    for (let i = 0; i < 32; i += 2) {
      if (i < chunk.length) {
        const byteHex = chunk.slice(i, i + 2).toUpperCase();
        hexBytes.push(byteHex);
        const byteVal = parseInt(byteHex, 16);
        asciiChars.push(byteVal >= 32 && byteVal <= 126 ? String.fromCharCode(byteVal) : '.');
      } else {
        hexBytes.push('  ');
      }
    }
    const part1 = hexBytes.slice(0, 8).join(' ');
    const part2 = hexBytes.slice(8, 16).join(' ');
    lines.push(`${offsetHex} | ${part1}  ${part2} | ${asciiChars.join('')}`);
  }
  return lines;
}

// ============================================================
// B10: 原始帧物理注入逻辑 (inject_raw_packet)
// ============================================================
const isInjectModalOpen = ref(false);
const injectIface = ref(props.selectedIface || (props.interfaces.length > 0 ? props.interfaces[0] : ''));
const injectHex = ref('');
const isInjecting = ref(false);
const injectResult = ref('');
const injectError = ref('');

watch(() => props.selectedIface, val => {
  if (val && !injectIface.value) injectIface.value = val;
});
watch(() => props.interfaces, list => {
  if (list.length > 0 && !injectIface.value) injectIface.value = list[0];
});

const injectHexClean = computed(() => injectHex.value.replace(/[^0-9a-fA-F]/g, ''));
const injectByteLength = computed(() => Math.floor(injectHexClean.value.length / 2));
const isInjectValid = computed(() => {
  return injectHexClean.value.length >= 28 &&
    injectHexClean.value.length % 2 === 0 &&
    !!injectIface.value;
});

function formatInjectHex() {
  const clean = injectHexClean.value.toUpperCase();
  if (!clean) return;
  const pairs: string[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    pairs.push(clean.slice(i, i + 2));
  }
  injectHex.value = pairs.join(' ');
}

function openInjectModal(prefillHex?: string) {
  if (prefillHex) {
    injectHex.value = prefillHex;
    formatInjectHex();
  }
  if (!injectIface.value && props.interfaces.length > 0) {
    injectIface.value = props.selectedIface || props.interfaces[0];
  }
  injectResult.value = '';
  injectError.value = '';
  isInjectModalOpen.value = true;
}

async function doInjectRawPacket() {
  if (!isInjectValid.value) {
    injectError.value = '请输入有效且偶数长度的十六进制载荷 (至少 14 字节 L2 以太网帧头)';
    return;
  }
  isInjecting.value = true;
  injectError.value = '';
  injectResult.value = '';

  try {
    const res = await invoke<string>('inject_raw_packet', {
      rawHex: injectHexClean.value,
      iface: injectIface.value
    });
    injectResult.value = res;
    emit('appendLog', res);
  } catch (e: any) {
    injectError.value = `注入失败: ${e}`;
    emit('appendLog', `[ERROR] 原始帧注入失败: ${e}`);
  } finally {
    isInjecting.value = false;
  }
}

// ============================================================
// 表格行右键上下文菜单逻辑 (Context Menu)
// ============================================================
const contextMenu = ref({
  visible: false,
  x: 0,
  y: 0,
  packet: null as PacketRecord | null
});

function openContextMenu(e: MouseEvent, pkt: PacketRecord) {
  const menuWidth = 200;
  const menuHeight = 220;
  const x = Math.min(e.clientX, window.innerWidth - menuWidth - 10);
  const y = Math.min(e.clientY, window.innerHeight - menuHeight - 10);

  contextMenu.value = {
    visible: true,
    x,
    y,
    packet: pkt
  };
  selectedPacket.value = pkt;
}

function closeContextMenu() {
  if (contextMenu.value.visible) {
    contextMenu.value.visible = false;
  }
}

function sendPayloadToNetAssist(pkt: PacketRecord | null) {
  if (!pkt) return;
  const hex = pkt.payload_hex || '';
  if (hex) {
    try {
      localStorage.setItem('omni_probe_net_assist_incoming_payload', hex);
    } catch (err) {
      console.warn('[TrafficAnalyzer] store incoming payload for NetAssist failed:', err);
    }
  }
  emit('switchWorkbench', 'net_assist');
  notifySuccess('已推送至网络调试助手', `报文 #${pkt.id} (${pkt.protocol}) 载荷已准备就绪`);
}

function menuAction(action: 'inject' | 'detail' | 'baseline' | 'replay' | 'copy' | 'tcp_stream' | 'dossier_src' | 'dossier_dst' | 'traceroute_src' | 'traceroute_dst' | 'set_diff_a' | 'diff_with_a' | 'add_diff_queue' | 'save_sample') {
  const pkt = contextMenu.value.packet;
  closeContextMenu();
  if (!pkt) return;

  if (action === 'add_diff_queue') {
    queuePacketForDiff(pkt);
  } else if (action === 'set_diff_a') {
    diffBus.setSlotA(pkt, `帧 #${pkt.id} (${pkt.protocol})`);
    emit('appendLog', `[DIFF] ✓ 已将报文 #${pkt.id} (${pkt.protocol}) 设为全局对比基准项 A`);
    notifyInfo('已设定基准项 A', `报文 #${pkt.id} (${pkt.protocol}) 已作为参照基准`);
  } else if (action === 'diff_with_a') {
    diffBus.setSlotB(pkt, `帧 #${pkt.id} (${pkt.protocol})`);
    diffBus.compareSlots();
  } else if (action === 'save_sample') {
    const defaultName = `样本_#${pkt.id}_${pkt.protocol}`;
    uiPrompt('请输入该报文特征样本归档名称:', defaultName, {
      title: '存入报文特征样本库',
      placeholder: '请输入归档样本名称',
      confirmText: '保存样本',
    }).then((name) => {
      if (name && name.trim()) {
        invoke('save_packet_sample_cmd', { name: name.trim(), packet: pkt })
          .then(() => {
            emit('appendLog', `[DIFF] 已将报文 #${pkt.id} 成功存入样本库: ${name.trim()}`);
            notifySuccess('样本保存成功', `已将 #${pkt.id} 归档为: ${name.trim()}`);
          })
          .catch((err) => {
            notifyError('保存流量分析样本受阻', err);
          });
      }
    });
  } else if (action === 'tcp_stream') {
    tcpStreamPacket.value = pkt;
    isTcpStreamOpen.value = true;
  } else if (action === 'inject') {
    openInjectModal(pkt.payload_hex);
  } else if (action === 'detail') {
    openDetailModal(pkt);
  } else if (action === 'baseline') {
    saveAsBaseline(pkt);
  } else if (action === 'replay') {
    emit('replayPacket', pkt);
  } else if (action === 'dossier_src' && pkt.src_ip) {
    openIpDossier(pkt.src_ip);
  } else if (action === 'dossier_dst' && pkt.dst_ip) {
    openIpDossier(pkt.dst_ip);
  } else if (action === 'traceroute_src' && pkt.src_ip) {
    openTraceroute(pkt.src_ip);
  } else if (action === 'traceroute_dst' && pkt.dst_ip) {
    activeBottomTab.value = 'tracemap';
    isInspectorOpen.value = true;
    openTraceroute(pkt.dst_ip);
  } else if (action === 'copy') {
    if (pkt.payload_hex && navigator.clipboard) {
      navigator.clipboard.writeText(pkt.payload_hex);
      emit('appendLog', `[CLIPBOARD] 已复制报文 #${pkt.id} 载荷至剪贴板`);
    }
  }
}

function handleImportedPackets(importedList: PacketRecord[]) {
  if (importedList && importedList.length > 0) {
    emit('importPackets', importedList);
    emit('appendLog', `[TRAFFIC] 成功载入 ${importedList.length} 个离线数据包至主分析视图`);
  }
}

let tableResizeObserver: ResizeObserver | null = null;

function autoSelectFirstCorePacket() {
  if (selectedPacket.value && filteredPackets.value.some(p => p.id === selectedPacket.value?.id)) {
    return;
  }
  const list = filteredPackets.value;
  if (!list || list.length === 0) return;
  const corePacket = list.find(p => {
    const proto = (p.protocol || '').toUpperCase();
    return proto.includes('S7') || proto.includes('MODBUS') || proto.includes('ETHERCAT') || proto.includes('104') || proto.includes('SL651');
  });
  selectedPacket.value = corePacket || list[0];
}

watch(filteredPackets, () => {
  autoSelectFirstCorePacket();
}, { immediate: true });

async function updateStreamBufferStats() {
  try {
    streamBufferStats.value = await invoke('get_stream_buffer_stats_cmd');
  } catch (err) {
    console.warn('[TrafficAnalyzer] get_stream_buffer_stats_cmd polling failed:', err);
  }
}

function handleScopeKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape') {
    closeAllDropdowns();
  }
  if (['INPUT', 'TEXTAREA'].includes((e.target as HTMLElement)?.tagName)) return;
  if (e.key === 'Escape') {
    isInspectorOpen.value = false; // ESC 一键收起抽屉
    return;
  }
  if (e.key === 'r' || e.key === 'R') {
    isInspectorOpen.value = !isInspectorOpen.value; // R 键随行解构开关
    return;
  }
  if (e.key === '0') {
    setScope('all');
  } else if (e.key === 'a' || e.key === 'A') {
    setScope('alert');
  } else if (e.key === 'i' || e.key === 'I') {
    setScope('industrial');
  } else if (e.key === 'b' || e.key === 'B') {
    setScope('serial_usb');
  } else if (e.key === 's' || e.key === 'S') {
    isAutoScroll.value = !isAutoScroll.value;
  } else if (e.key === ' ') {
    e.preventDefault();
    if (props.isPaused) emit('resumeCapture');
    else emit('pauseCapture');
  }
}

let unlistenWaveData: UnlistenFn | null = null;
let unlistenIndustrialTx: UnlistenFn | null = null;
let unlistenIndustrialTimeout: UnlistenFn | null = null;

onMounted(async () => {
  window.addEventListener('keydown', handleScopeKeydown);
  startTopologyAnimation();
  telemetryTimer = setInterval(updateTelemetryMetrics, 1000);
  updateStreamBufferStats();
  streamBufferTimer = setInterval(updateStreamBufferStats, 2000);

  try {
    unlistenWaveData = await listen<{ ip: string; value: number; ts_ms: number }>('wave-data', (event) => {
      if (!waveActive.value || !event.payload) return;
      const next = [...wavePoints.value, { value: Number(event.payload.value) || 0, ts_ms: Number(event.payload.ts_ms) || Date.now() }];
      wavePoints.value = next.length > 240 ? next.slice(-240) : next;
    });
    unlistenIndustrialTx = await listen<CompletedIndustrialTransaction>('industrial-transaction-event', () => {
      if (isIndustrialTxOpen.value) {
        fetchIndustrialTxData();
      }
    });
    unlistenIndustrialTimeout = await listen<{ src_ip?: string; dst_ip?: string }>('industrial-transaction-timeout', ({ payload }) => {
      emit('appendLog', `[INDUSTRIAL-TX-TIMEOUT] 工控主从请求响应超时: ${payload?.src_ip || ''} -> ${payload?.dst_ip || ''}`);
      if (isIndustrialTxOpen.value) {
        fetchIndustrialTxData();
      }
    });
  } catch (e) {
    console.warn('注册实时事件监听失败:', e);
  }

  window.addEventListener('click', closeContextMenu);
  window.addEventListener('click', closeAllDropdowns);
  nextTick(() => {
    if (tableContainer.value) {
      containerHeight.value = tableContainer.value.clientHeight || 500;
      tableResizeObserver = new ResizeObserver((entries) => {
        for (const entry of entries) {
          if (entry.contentRect.height > 0) {
            containerHeight.value = entry.contentRect.height;
          }
        }
      });
      tableResizeObserver.observe(tableContainer.value);
    }
  });
});

onUnmounted(() => {
  window.removeEventListener('keydown', handleScopeKeydown);
  if (unlistenWaveData) {
    unlistenWaveData();
    unlistenWaveData = null;
  }
  if (unlistenIndustrialTx) {
    unlistenIndustrialTx();
    unlistenIndustrialTx = null;
  }
  if (unlistenIndustrialTimeout) {
    unlistenIndustrialTimeout();
    unlistenIndustrialTimeout = null;
  }
  if (topoAnimId) cancelAnimationFrame(topoAnimId);
  if (telemetryTimer) clearInterval(telemetryTimer);
  if (streamBufferTimer) clearInterval(streamBufferTimer);
  if (replayPollTimer) {
    clearInterval(replayPollTimer);
    replayPollTimer = null;
  }

  window.removeEventListener('click', closeContextMenu);
  window.removeEventListener('click', closeAllDropdowns);
  window.removeEventListener('mousemove', onColResizeMove);
  window.removeEventListener('mouseup', onColResizeEnd);
  if (tableResizeObserver) {
    tableResizeObserver.disconnect();
    tableResizeObserver = null;
  }
});
</script>
