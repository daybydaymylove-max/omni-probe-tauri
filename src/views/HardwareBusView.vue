<template>
  <div class="flex-1 flex flex-col gap-2.5 overflow-hidden min-w-0 font-sans" style="color: var(--text-primary);">

    <!-- 1. 顶部状态栏与物理总线控制栏 (真 Liquid Glass 控制层) -->
    <header class="ui-nav-glass rounded-2xl px-3.5 py-2 flex items-center justify-between shrink-0 gap-3 select-none flex-wrap">
      <span class="lens-edge-lip" aria-hidden="true"></span>

      <!-- 1.1 左侧：核心标题与总线启停控制 -->
      <div class="flex items-center gap-3 shrink-0 flex-wrap">
        <div class="flex items-center gap-2">
          <div class="w-7 h-7 rounded-lg bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)] border border-[var(--accent-primary)]/20 flex items-center justify-center shrink-0">
            <AppIcon name="cpu" :size="15" />
          </div>
          <h2 class="text-[13px] font-semibold tracking-tight whitespace-nowrap" style="color: var(--text-primary);">
            物理外设与端口出入中心
          </h2>
        </div>

        <div class="h-4 w-px shrink-0" style="background: var(--border-strong);"></div>

        <!-- USB 总线嗅探启停控制 -->
        <div class="flex items-center gap-1.5 text-xs whitespace-nowrap shrink-0">
          <span class="text-[11px] font-medium" style="color: var(--text-muted);">USB:</span>
          <button v-if="!isUsbRunning" @click="$emit('startUsbCapture')" class="ui-btn-primary px-2.5 py-1 text-[11px]">
            <AppIcon name="play" :size="11" />
            <span>挂钩 USB</span>
          </button>
          <button v-else @click="$emit('stopUsbCapture')" class="ui-btn-danger px-2.5 py-1 text-[11px]">
            <span class="w-1.5 h-1.5 rounded-full bg-current"></span>
            <span>停止 USB</span>
          </button>
        </div>

        <div class="h-4 w-px shrink-0" style="background: var(--border-strong);"></div>

        <!-- 物理 COM 串口直选与嗅探启停控制 -->
        <div class="flex items-center gap-1.5 text-xs whitespace-nowrap shrink-0">
          <span class="text-[11px] font-medium" style="color: var(--text-muted);">COM 串口:</span>
          <select
            :value="localSerial"
            @change="onSelectSerial(($event.target as HTMLSelectElement).value)"
            class="ui-input w-auto max-w-[140px] px-2 py-0.5 text-[11px] font-mono cursor-pointer"
            title="选择目标 COM 物理或虚拟串口"
          >
            <option v-if="serialPorts.length === 0" value="">未检出 COM</option>
            <option v-for="p in serialPorts" :key="p" :value="p">{{ p }}</option>
          </select>
          <select
            :value="localBaudRate"
            @change="onSelectBaudRate(Number(($event.target as HTMLSelectElement).value))"
            class="ui-input w-auto px-1.5 py-0.5 text-[11px] ui-num cursor-pointer"
            title="选择串口通信波特率"
          >
            <option :value="9600">9600</option>
            <option :value="19200">19200</option>
            <option :value="38400">38400</option>
            <option :value="57600">57600</option>
            <option :value="115200">115200</option>
          </select>
          <button
            v-if="!isPortActive(localSerial)"
            @click="startPortMonitor(localSerial)"
            :disabled="!localSerial"
            class="ui-btn-secondary px-2.5 py-1 text-[11px]"
          >
            <AppIcon name="play" :size="11" />
            <span>监听串口</span>
          </button>
          <button
            v-else
            @click="$emit('stopSerialCapture', localSerial)"
            class="ui-btn-danger px-2.5 py-1 text-[11px]"
          >
            <span class="w-1.5 h-1.5 rounded-full bg-current"></span>
            <span>停止 {{ localSerial }}</span>
          </button>
        </div>
      </div>

      <!-- 1.2 中间与右侧：四总线计数微囊与专业工具组 -->
      <div class="flex items-center gap-1.5 text-xs overflow-x-auto custom-scrollbar-x py-0.5 shrink min-w-0">
        <div class="ui-pill px-2.5 py-0.5 rounded-full whitespace-nowrap shrink-0 font-semibold flex items-center gap-1.5 ui-num" title="已识别物理 USB 设备数">
          <span class="text-[11px]" style="color: var(--text-muted);">USB</span>
          <span class="text-xs" style="color: var(--text-primary);">{{ usbDevices.length }}</span>
        </div>
        <div class="ui-pill px-2.5 py-0.5 rounded-full whitespace-nowrap shrink-0 font-semibold flex items-center gap-1.5 ui-num" title="系统已检出 COM 物理/虚拟/蓝牙串口总数">
          <span class="text-[11px]" style="color: var(--text-muted);">COM</span>
          <span class="text-xs" style="color: var(--text-primary);">{{ serialPorts.length }}</span>
        </div>
        <div class="ui-pill px-2.5 py-0.5 rounded-full whitespace-nowrap shrink-0 font-semibold flex items-center gap-1.5 ui-num">
          <span class="text-[11px]" style="color: var(--text-muted);">留痕</span>
          <span class="text-xs" style="color: var(--text-primary);">{{ transceiveHistory.length }}</span>
        </div>

        <div class="h-3.5 w-px shrink-0 mx-0.5" style="background: var(--border-strong);"></div>

        <button @click="$emit('openWireless')" class="ui-btn-secondary px-2.5 py-1 text-[11px] whitespace-nowrap shrink-0" title="打开无线 Wi-Fi / VLAN / 蓝牙近场监控控制台">
          <AppIcon name="wifi" :size="12" />
          <span>Wi-Fi/蓝牙</span>
        </button>

        <button @click="isSerialConfigOpen = true" class="ui-btn-secondary px-2.5 py-1 text-[11px] whitespace-nowrap shrink-0">
          <AppIcon name="sliders" :size="12" />
          <span>串口参数</span>
        </button>

        <button
          @click="showModemPins = !showModemPins"
          :class="['text-[11px] px-2.5 py-1 rounded-lg font-medium transition-all flex items-center gap-1 cursor-pointer border whitespace-nowrap shrink-0',
            showModemPins ? 'bg-[var(--accent-primary)] text-white border-transparent shadow-xs' : 'ui-btn-secondary']"
        >
          <AppIcon name="activity" :size="12" />
          <span>引脚电平</span>
        </button>

        <button @click="isSerialBridgeOpen = true" class="ui-btn-secondary px-2.5 py-1 text-[11px] whitespace-nowrap shrink-0">
          <AppIcon name="link" :size="12" />
          <span>串口中继</span>
        </button>

        <button @click="isUsbDescriptorTreeOpen = true" class="ui-btn-secondary px-2.5 py-1 text-[11px] whitespace-nowrap shrink-0">
          <AppIcon name="layers" :size="12" />
          <span>描述符树</span>
        </button>

        <button @click="isCrossBusCausalityOpen = true" class="ui-btn-secondary px-2.5 py-1 text-[11px] whitespace-nowrap shrink-0">
          <AppIcon name="zap" :size="12" />
          <span>跨总线因果</span>
        </button>

        <button
          @click="toggleCanDrawer"
          :class="['text-[11px] px-2.5 py-1 rounded-lg font-medium transition-all flex items-center gap-1 cursor-pointer border whitespace-nowrap shrink-0',
            showCanDiagnosticDrawer ? 'bg-[var(--accent-primary)] text-white border-transparent shadow-xs' : 'ui-btn-secondary']"
        >
          <AppIcon name="cpu" :size="12" />
          <span>CAN 诊断</span>
        </button>

        <button
          @click="showUartLogicDrawer = !showUartLogicDrawer"
          :class="['text-[11px] px-2.5 py-1 rounded-lg font-medium transition-all flex items-center gap-1 cursor-pointer border whitespace-nowrap shrink-0',
            showUartLogicDrawer ? 'bg-[var(--accent-primary)] text-white border-transparent shadow-xs' : 'ui-btn-secondary']"
        >
          <AppIcon name="activity" :size="12" />
          <span>UART 解调</span>
        </button>

        <button
          @click="showComplianceWorkbench = !showComplianceWorkbench"
          :class="['text-[11px] px-2.5 py-1 rounded-lg font-semibold transition-all flex items-center gap-1.5 cursor-pointer border whitespace-nowrap shrink-0',
            showComplianceWorkbench ? 'bg-[var(--accent-primary)] text-white border-transparent shadow-xs' : 'ui-btn-secondary']"
        >
          <AppIcon name="shield" :size="12" />
          <span>白名单审计</span>
          <span
            v-if="complianceReport"
            :class="['px-1.5 py-0.5 rounded-full text-[11px] ui-num font-semibold',
              complianceReport.unauthorized_count > 0
                ? (showComplianceWorkbench ? 'bg-rose-500/80 text-white' : 'bg-rose-500/15 text-rose-600 dark:text-rose-400')
                : (showComplianceWorkbench ? 'bg-white/20 text-white' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300')]"
          >
            {{ complianceReport.unauthorized_count > 0 ? `未授权:${complianceReport.unauthorized_count}` : `${complianceReport.compliance_rate.toFixed(0)}%` }}
          </span>
        </button>

        <button @click="refreshAllHardwareBuses" title="重新扫描系统物理 USB 外设与 COM 串口" class="ui-btn-secondary px-2.5 py-1 text-[11px] whitespace-nowrap shrink-0">
          <AppIcon name="refresh" :size="12" />
          <span>刷新外设</span>
        </button>
      </div>
    </header>

    <!-- 1.5 CAN / CAN-FD 总线健康监控抽屉 -->
    <section v-if="showCanDiagnosticDrawer" class="ui-content-card border-amber-500/35 p-3 flex flex-col gap-2.5 shrink-0 text-xs select-text">
      <div class="flex items-center justify-between border-b pb-2 gap-2 flex-wrap" style="border-color: var(--border-subtle);">
        <div class="flex items-center gap-2">
          <span class="w-2 h-2 rounded-full bg-amber-500"></span>
          <span class="font-semibold text-amber-700 dark:text-amber-300">CAN 2.0 / CAN-FD 现场总线深度诊断与健康评估</span>
        </div>
        <div class="flex items-center gap-2">
          <button @click="fetchCanDiagnostics" class="ui-btn-secondary px-2.5 py-1 text-[11px]">
            <AppIcon name="refresh" :size="11" />
            <span>刷新快照</span>
          </button>
          <button @click="showCanDiagnosticDrawer = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-muted);">
            <AppIcon name="close" :size="13" />
          </button>
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-12 gap-3">
        <div class="lg:col-span-5 space-y-2">
          <div class="grid grid-cols-3 gap-1.5 text-[11px]">
            <div class="ui-sub-card p-2">
              <div style="color: var(--text-muted);">总线负载率</div>
              <div class="text-amber-600 dark:text-amber-300 font-semibold text-sm ui-num mt-0.5">{{ (canHealth?.bus_load_percentage ?? 0).toFixed(2) }}%</div>
            </div>
            <div class="ui-sub-card p-2">
              <div style="color: var(--text-muted);">帧速率 / 错误帧</div>
              <div class="font-semibold text-xs ui-num mt-0.5" style="color: var(--text-primary);">{{ (canHealth?.frames_per_second ?? 0).toFixed(1) }} fps / <span class="text-rose-600 dark:text-rose-400">{{ canHealth?.total_error_frames ?? 0 }}</span></div>
            </div>
            <div class="ui-sub-card p-2">
              <div style="color: var(--text-muted);">总线健康等级</div>
              <div class="text-emerald-600 dark:text-emerald-400 font-semibold text-xs mt-0.5">{{ canHealth?.health_status ?? 'Idle (无总线帧)' }}</div>
            </div>
          </div>
          <div class="max-h-24 overflow-y-auto rounded-xl border p-2 text-[11px]" style="border-color: var(--border-subtle); background: var(--surface-content-alt); color: var(--text-muted);">
            <div v-if="canCausalRecords.length === 0">暂无以太网-CAN 网关因果事务记录 ({{ canHealth?.total_frames_dissected ?? 0 }} 帧已解析)</div>
            <div v-for="rec in canCausalRecords" :key="rec.transaction_id" class="py-0.5 border-b flex justify-between ui-num" style="border-color: var(--border-subtle);">
              <span style="color: var(--text-primary);">{{ rec.eth_protocol }} → CAN ID: {{ rec.can_frame_id ?? '--' }}</span>
              <span class="text-blue-600 dark:text-sky-300">{{ rec.verdict }} ({{ rec.gateway_latency_us?.toFixed(1) ?? '--' }}us)</span>
            </div>
          </div>
        </div>

        <div class="lg:col-span-7 flex flex-col gap-2">
          <div class="flex items-center gap-1.5 flex-wrap">
            <input v-model="canRawHex" placeholder="输入 CAN SocketCAN/PCAN 帧 Hex (如 0000012304000000deadbeef)" class="ui-input flex-1 min-w-[210px] px-2.5 py-1 text-xs font-mono" />
            <input v-model.number="canNominalBps" type="number" title="标称波特率 (bps)" class="ui-input w-24 px-2 py-1 text-xs ui-num" />
            <input v-model.number="canDataBps" type="number" title="CAN-FD 数据段波特率 (bps)" class="ui-input w-24 px-2 py-1 text-xs ui-num" />
            <button @click="runCanDissection" :disabled="!canRawHex.trim()" class="ui-btn-primary bg-amber-600 hover:bg-amber-500 px-3 py-1 text-xs">解剖 CAN 帧</button>
          </div>
          <div v-if="dissectedCan" class="ui-sub-card p-2.5 text-[11px] flex flex-wrap gap-x-4 gap-y-1 ui-num" style="color: var(--text-primary);">
            <span>CAN ID: <b class="text-amber-600 dark:text-amber-300">0x{{ dissectedCan.can_id.toString(16).toUpperCase() }}</b> ({{ dissectedCan.is_extended_id ? '29-bit EXT' : '11-bit STD' }})</span>
            <span>协议: <b class="text-blue-600 dark:text-sky-300">{{ dissectedCan.protocol_type }}</b> ({{ dissectedCan.frame_class }})</span>
            <span>DLC: <b>{{ dissectedCan.dlc }}</b> · 载荷: <b>{{ dissectedCan.payload_len }}B</b></span>
            <span>线占时: <b>{{ dissectedCan.wire_duration_us.toFixed(2) }} μs</b></span>
            <span v-if="dissectedCan.error_detail" class="text-rose-600 dark:text-rose-400 font-semibold">故障: {{ dissectedCan.error_detail }}</span>
            <span class="w-full text-emerald-600 dark:text-emerald-400 font-mono">Payload Hex: {{ dissectedCan.payload.map((b) => b.toString(16).padStart(2, '0')).join(' ') || 'EMPTY' }}</span>
          </div>
        </div>
      </div>
    </section>

    <!-- 1.6 物理逻辑分析仪：UART 电平解调与信号完整性评估抽屉 -->
    <section v-if="showUartLogicDrawer" class="ui-content-card border-emerald-500/35 p-3 flex flex-col gap-2.5 shrink-0 text-xs select-text">
      <div class="flex items-center justify-between border-b pb-2 gap-2 flex-wrap" style="border-color: var(--border-subtle);">
        <div class="flex items-center gap-2">
          <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
          <span class="font-semibold text-emerald-700 dark:text-emerald-300">物理逻辑分析仪 · 亚微秒级毛刺滤波 / UART 电平解调 / 抖动评估</span>
        </div>
        <button @click="showUartLogicDrawer = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-muted);">
          <AppIcon name="close" :size="13" />
        </button>
      </div>

      <div class="flex items-center gap-2 flex-wrap">
        <input v-model="uartSamplesHex" placeholder="输入数字采样比特流 Hex (MSB 先行, 每字节表示8个采样点电平)" class="ui-input flex-1 min-w-[240px] px-2.5 py-1 text-xs font-mono" />
        <label class="text-[11px]" style="color: var(--text-muted);">采样间隔(ns):</label>
        <input v-model.number="uartIntervalNs" type="number" min="1" class="ui-input w-20 px-2 py-1 text-xs ui-num" />
        <label class="text-[11px]" style="color: var(--text-muted);">波特率:</label>
        <input v-model.number="uartBaudRate" type="number" min="300" class="ui-input w-24 px-2 py-1 text-xs ui-num" />
        <label class="text-[11px]" style="color: var(--text-muted);">滤波门限(ns):</label>
        <input v-model.number="uartMinGlitchNs" type="number" min="0" class="ui-input w-20 px-2 py-1 text-xs ui-num" />
        <button @click="runUartDemodulate" :disabled="!uartSamplesHex.trim()" class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 px-3 py-1 text-xs">UART 电平解码</button>
        <button @click="runSignalIntegrity" :disabled="!uartSamplesHex.trim()" class="ui-btn-primary px-3 py-1 text-xs">信号完整性评估</button>
      </div>

      <div v-if="uartBytes.length > 0 || signalSnapshot" class="grid grid-cols-1 lg:grid-cols-12 gap-2.5 text-[11px]">
        <div v-if="uartBytes.length > 0" class="lg:col-span-6 ui-sub-card p-2.5 max-h-28 overflow-y-auto">
          <div class="text-emerald-600 dark:text-emerald-300 font-semibold mb-1 ui-num">解码出 {{ uartBytes.length }} 字节 UART 数据:</div>
          <div class="flex flex-wrap gap-1.5 font-mono">
            <span
              v-for="(u, i) in uartBytes"
              :key="i"
              :class="u.framing_error || u.parity_error ? 'border-rose-500/40 text-rose-700 dark:text-rose-300 bg-rose-500/15' : 'border-emerald-500/30 bg-emerald-500/10'"
              :style="u.framing_error || u.parity_error ? {} : { color: 'var(--text-primary)' }"
              class="px-1.5 py-0.5 rounded border"
            >
              0x{{ u.byte_value.toString(16).padStart(2, '0').toUpperCase() }}<template v-if="u.char_representation"> ('{{ u.char_representation }}')</template>
            </span>
          </div>
        </div>
        <div v-if="signalSnapshot" :class="uartBytes.length > 0 ? 'lg:col-span-6' : 'lg:col-span-12'" class="ui-sub-card p-2.5 flex flex-wrap gap-x-4 gap-y-1 ui-num" style="color: var(--text-primary);">
          <span>信号质量定性: <b class="text-blue-600 dark:text-sky-300">{{ signalSnapshot.integrity_grade }}</b></span>
          <span>占空比: <b>{{ signalSnapshot.duty_cycle_percentage.toFixed(1) }}%</b></span>
          <span>抖动标准差: <b>{{ signalSnapshot.jitter_stddev_ns.toFixed(1) }} ns</b></span>
          <span>滤除毛刺数: <b class="text-amber-600 dark:text-amber-300">{{ signalSnapshot.glitches_detected }}</b></span>
          <span>正/负均宽: <b>{{ signalSnapshot.mean_high_pulse_width_ns.toFixed(1) }} / {{ signalSnapshot.mean_low_pulse_width_ns.toFixed(1) }} ns</b></span>
        </div>
      </div>
    </section>

    <!-- 2. 物理外设基线白名单工作台 -->
    <section v-if="showComplianceWorkbench" class="ui-content-card border-purple-500/35 p-3 flex flex-col gap-2.5 shrink-0 select-text">
      <div class="flex items-center justify-between border-b pb-2 flex-wrap gap-2" style="border-color: var(--border-subtle);">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="w-2 h-2 rounded-full bg-purple-500"></span>
          <span class="text-xs font-semibold text-purple-700 dark:text-purple-300">物理外设基线白名单固化与即插即用合规差分审计</span>
          <span class="text-[11px]" style="color: var(--text-muted);">
            对标 GB/T 22239 等保三级物理与环境安全接入控制
          </span>
        </div>

        <div class="flex items-center gap-2 text-xs flex-wrap">
          <button @click="doSaveCurrentAsWhitelist" :disabled="isSavingWhitelist" class="ui-btn-primary bg-purple-600 hover:bg-purple-500 px-3 py-1 text-xs">
            <AppIcon v-if="isSavingWhitelist" name="refresh" :size="12" class="animate-spin" />
            <AppIcon v-else name="lock" :size="12" />
            <span>固化当前在线外设为基线</span>
          </button>
          <button @click="doVerifyCompliance" :disabled="isAuditingCompliance" class="ui-btn-primary px-3 py-1 text-xs">
            <AppIcon v-if="isAuditingCompliance" name="refresh" :size="12" class="animate-spin" />
            <AppIcon v-else name="search" :size="12" />
            <span>执行合规差分比对</span>
          </button>
          <button @click="doClearWhitelist" title="清空现有白名单" class="ui-btn-danger px-2.5 py-1 text-xs">
            清空白名单
          </button>
        </div>
      </div>

      <div v-if="complianceReport" class="flex flex-col gap-2">
        <div class="grid grid-cols-2 md:grid-cols-5 gap-2 text-xs">
          <div class="bg-purple-500/10 border border-purple-500/25 p-2 rounded-xl">
            <div class="text-[11px] text-purple-600 dark:text-purple-300 font-semibold">受信任基线 / 当前在线</div>
            <div class="text-sm font-semibold ui-num mt-0.5" style="color: var(--text-primary);">{{ complianceReport.total_whitelist }} 基准 / {{ complianceReport.total_online }} 在线</div>
          </div>
          <div class="bg-emerald-500/10 border border-emerald-500/25 p-2 rounded-xl">
            <div class="text-[11px] text-emerald-600 dark:text-emerald-300 font-semibold">合规受控外设</div>
            <div class="text-sm font-semibold text-emerald-600 dark:text-emerald-400 ui-num mt-0.5">{{ complianceReport.compliant_count }} 个</div>
          </div>
          <div class="bg-rose-500/10 border border-rose-500/25 p-2 rounded-xl">
            <div class="text-[11px] text-rose-600 dark:text-rose-300 font-semibold">未授权非法外设</div>
            <div class="text-sm font-semibold text-rose-600 dark:text-rose-400 ui-num mt-0.5 flex items-center gap-1">
              <AppIcon name="alert" :size="13" />
              <span>{{ complianceReport.unauthorized_count }} 个</span>
            </div>
          </div>
          <div class="bg-amber-500/10 border border-amber-500/25 p-2 rounded-xl">
            <div class="text-[11px] text-amber-600 dark:text-amber-300 font-semibold">基线设备离线缺失</div>
            <div class="text-sm font-semibold text-amber-600 dark:text-amber-400 ui-num mt-0.5">{{ complianceReport.missing_count }} 个</div>
          </div>
          <div class="ui-sub-card p-2 rounded-xl">
            <div class="text-[11px] font-semibold" style="color: var(--text-muted);">物理安全合规率</div>
            <div :class="['text-sm font-semibold ui-num mt-0.5', complianceReport.compliance_rate >= 100 ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400']">
              {{ complianceReport.compliance_rate.toFixed(1) }}%
            </div>
          </div>
        </div>

        <div class="flex items-center justify-between text-xs pt-1 flex-wrap gap-2">
          <span class="font-semibold ui-num" style="color: var(--text-secondary);">硬件合规审计明细 ({{ filteredComplianceItems.length }} / {{ complianceReport.items.length }})</span>
          <div class="flex gap-1 text-[11px] font-semibold">
            <button @click="whitelistFilter = 'ALL'" :class="['px-2.5 py-0.5 rounded-lg border transition-all cursor-pointer', whitelistFilter === 'ALL' ? 'bg-purple-600 text-white border-purple-600' : 'ui-pill']">
              全部 ({{ complianceReport.items.length }})
            </button>
            <button @click="whitelistFilter = 'UNAUTHORIZED'" :class="['px-2.5 py-0.5 rounded-lg border transition-all cursor-pointer', whitelistFilter === 'UNAUTHORIZED' ? 'bg-rose-600 text-white border-rose-600' : 'border-rose-500/25 text-rose-600 dark:text-rose-300 bg-rose-500/10']">
              未授权 ({{ complianceReport.unauthorized_count }})
            </button>
            <button @click="whitelistFilter = 'MISSING'" :class="['px-2.5 py-0.5 rounded-lg border transition-all cursor-pointer', whitelistFilter === 'MISSING' ? 'bg-amber-600 text-white border-amber-600' : 'border-amber-500/25 text-amber-600 dark:text-amber-300 bg-amber-500/10']">
              离线缺失 ({{ complianceReport.missing_count }})
            </button>
            <button @click="whitelistFilter = 'COMPLIANT'" :class="['px-2.5 py-0.5 rounded-lg border transition-all cursor-pointer', whitelistFilter === 'COMPLIANT' ? 'bg-emerald-600 text-white border-emerald-600' : 'border-emerald-500/25 text-emerald-600 dark:text-emerald-300 bg-emerald-500/10']">
              合规受控 ({{ complianceReport.compliant_count }})
            </button>
          </div>
        </div>

        <div class="max-h-48 overflow-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <table class="w-full text-left text-xs border-collapse table-fixed">
            <thead class="ui-table-head sticky top-0 z-10 select-none">
              <tr>
                <th class="p-2 w-[12%]">总线类型</th>
                <th class="p-2 w-[24%]">硬件唯一标识 (VID/PID/COM)</th>
                <th class="p-2 w-[22%]">物理设备名称</th>
                <th class="p-2 w-[14%] text-center">合规状态</th>
                <th class="p-2 w-[28%]">合规审计结论与用途备注</th>
              </tr>
            </thead>
            <tbody class="divide-y text-xs" style="border-color: var(--border-subtle);">
              <tr
                v-for="item in filteredComplianceItems"
                :key="item.identifier"
                :class="['hover:bg-[var(--surface-hover)] transition-colors', item.status === 'UNAUTHORIZED' ? 'bg-rose-500/8' : '']"
              >
                <td class="p-2 truncate font-semibold">
                  <span :class="['px-1.5 py-0.5 rounded text-[11px]', item.category === 'USB' ? 'bg-purple-500/15 text-purple-700 dark:text-purple-300' : 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300']">
                    {{ item.category }}
                  </span>
                </td>
                <td class="p-2 font-semibold font-mono truncate" style="color: var(--text-primary);" :title="item.identifier">{{ item.identifier }}</td>
                <td class="p-2 truncate" style="color: var(--text-secondary);" :title="item.name">{{ item.name }}</td>
                <td class="p-2 text-center truncate">
                  <span
                    :class="['px-2 py-0.5 rounded text-[11px] font-semibold',
                      item.status === 'COMPLIANT' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' :
                      item.status === 'UNAUTHORIZED' ? 'bg-rose-600 text-white' :
                      'bg-amber-500/15 text-amber-700 dark:text-amber-300']"
                  >
                    {{ item.status === 'COMPLIANT' ? '合规受控' : item.status === 'UNAUTHORIZED' ? '未授权外设' : '离线缺失' }}
                  </span>
                </td>
                <td class="p-2 truncate">
                  <div class="flex items-center gap-1.5 truncate" :title="item.alert_desc">
                    <span class="truncate text-[11px]" :class="item.status === 'UNAUTHORIZED' ? 'text-rose-600 dark:text-rose-400 font-semibold' : ''" :style="item.status === 'UNAUTHORIZED' ? {} : { color: 'var(--text-secondary)' }">
                      {{ item.alert_desc }}
                    </span>
                    <span v-if="item.description" class="text-[11px] shrink-0" style="color: var(--text-muted);">({{ item.description }})</span>
                  </div>
                </td>
              </tr>
              <tr v-if="filteredComplianceItems.length === 0">
                <td colspan="5" class="p-6 text-center text-xs" style="color: var(--text-muted);">
                  暂无匹配的硬件审计项
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      <div v-else class="ui-sub-card p-3 text-center text-xs border-dashed" style="color: var(--text-muted);">
        尚未执行硬件合规比对。请点击【固化当前在线外设为基线】建立受信任基准，或点击【执行合规差分比对】。
      </div>
    </section>

    <SerialModemPinsPanel v-if="showModemPins" :serialPorts="serialPorts" :defaultPort="localSerial" />

    <!-- 3. 主体工作区 (实体稳态衬底，开放选区) -->
    <main class="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-2.5 overflow-hidden min-h-0 select-text">

      <!-- 3.1 左栏：物理 COM 串口资产 + USB 外设画像 + 总线实时审计流 -->
      <div class="flex flex-col gap-2.5 overflow-hidden min-w-0 min-h-0">

        <!-- 3.1.1 物理 / 虚拟 COM 串口资产清单 -->
        <div class="flex-[2] ui-content-card flex flex-col overflow-hidden min-h-0">
          <div class="px-3.5 py-2 border-b flex items-center justify-between text-xs font-semibold shrink-0 gap-2" style="border-color: var(--border-subtle); color: var(--text-primary);">
            <div class="flex items-center gap-2 min-w-0">
              <span class="w-1.5 h-1.5 rounded-full bg-indigo-500 shrink-0"></span>
              <span class="truncate">物理 / 虚拟 COM 串口清单</span>
              <span class="text-[11px] ui-num text-indigo-700 dark:text-indigo-300 bg-indigo-500/12 px-2 py-0.5 rounded border border-indigo-500/25 shrink-0">
                {{ filteredSerialList.length }} 通信端口
              </span>
              <span v-if="activeSerialCount > 0" class="text-[11px] ui-num text-emerald-700 dark:text-emerald-300 bg-emerald-500/12 px-2 py-0.5 rounded border border-emerald-500/25 shrink-0">
                {{ activeSerialCount }} 监听中
              </span>
            </div>
            <div class="flex items-center gap-1.5 shrink-0">
              <button @click="isMultiSerialCompareOpen = true"
                title="开启 2~4 路 COM 串口 LCS 实时交叉比对终端"
                class="px-2 py-1 rounded-lg bg-indigo-500/12 hover:bg-indigo-500/20 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25 text-[11px] font-semibold cursor-pointer flex items-center gap-1 whitespace-nowrap">
                <AppIcon name="scale" :size="11" />
                <span>多路交叉比对</span>
              </button>
              <input v-model="serialFilter" placeholder="过滤 COM / 芯片 / 蓝牙" class="ui-input w-36 px-2.5 py-1 text-xs" />
              <button @click="$emit('refreshSerial')" title="重新扫描系统 COM 物理与蓝牙虚拟串口" class="ui-pill p-1.5 rounded-lg cursor-pointer">
                <AppIcon name="refresh" :size="12" />
              </button>
            </div>
          </div>

          <div class="flex-1 overflow-auto custom-scrollbar p-2.5 space-y-2">
            <div v-for="sp in filteredSerialList" :key="sp.port_name" class="ui-sub-card hover:border-indigo-500/40 p-2.5 flex flex-col gap-1.5 text-xs transition-all">
              <div class="flex items-center justify-between gap-2 flex-wrap">
                <div class="flex items-center gap-2 min-w-0">
                  <span class="px-2 py-0.5 rounded-md font-mono font-bold text-xs bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30 shrink-0">
                    {{ sp.port_name }}
                  </span>
                  <span class="font-semibold truncate" style="color: var(--text-primary);" :title="sp.description">
                    {{ sp.product || sp.description }}
                  </span>
                </div>
                <div class="flex items-center gap-1.5 shrink-0">
                  <span :class="['text-[11px] font-semibold px-2 py-0.5 rounded-lg border', getSerialTypeBadge(sp)]">
                    {{ sp.port_type }}
                  </span>
                  <button
                    @click="togglePortCapture(sp.port_name)"
                    :class="isPortActive(sp.port_name) ? 'ui-btn-danger px-2 py-0.5 text-[11px]' : 'ui-btn-secondary px-2 py-0.5 text-[11px]'"
                  >
                    <span>{{ isPortActive(sp.port_name) ? '停止' : '监听' }}</span>
                  </button>
                  <button
                    @click="focusSerialTransceive(sp.port_name)"
                    title="切换到串口双向发包调试"
                    class="ui-btn-primary px-2 py-0.5 text-[11px]"
                  >
                    <span>调试</span>
                  </button>
                  <button
                    @click="addSerialPortToDiffQueue(sp)"
                    title="将此串口硬件属性与驱动配置加入比对队列"
                    class="px-2 py-0.5 rounded-lg bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 font-semibold text-[11px] cursor-pointer"
                  >
                    + 入队
                  </button>
                </div>
              </div>

              <div class="grid grid-cols-2 gap-1.5 text-[11px] font-mono px-2 py-1.5 rounded-lg border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle); color: var(--text-muted);">
                <div class="truncate" :title="sp.hardware_id">
                  <span>硬件标识: </span>
                  <strong class="text-indigo-600 dark:text-indigo-300">{{ sp.hardware_id || 'STANDARD_COM' }}</strong>
                </div>
                <div class="truncate" :title="sp.manufacturer || '通用串口控制器'">
                  <span>驱动厂商: </span>
                  <span class="font-medium" style="color: var(--text-primary);">{{ sp.manufacturer || '系统标准驱动' }}</span>
                </div>
              </div>
            </div>

            <EmptyState
              v-if="filteredSerialList.length === 0"
              icon="serial"
              title="未检测到在线物理或虚拟 COM 串口"
              description="连接 USB 转串口适配器 (CH340/CP210x/FT232)、RS-485 板卡或已配对蓝牙 SPP 串口后，点击右上角刷新即可自动纳管。"
            />
          </div>
        </div>

        <!-- 3.1.2 物理 USB 设备画像清单 -->
        <div class="flex-[2] ui-content-card flex flex-col overflow-hidden min-h-0">
          <div class="px-3.5 py-2 border-b flex items-center justify-between text-xs font-semibold shrink-0 gap-2" style="border-color: var(--border-subtle); color: var(--text-primary);">
            <div class="flex items-center gap-2">
              <span class="w-1.5 h-1.5 rounded-full bg-purple-500"></span>
              <span>物理 USB 设备画像清单</span>
              <span class="text-[11px] ui-num text-purple-600 dark:text-purple-300 bg-purple-500/12 px-2 py-0.5 rounded border border-purple-500/25">
                {{ filteredUsbDevices.length }} 活跃端点
              </span>
            </div>
            <input v-model="usbFilter" placeholder="过滤设备名 / VID / PID / 类别" class="ui-input w-44 px-2.5 py-1 text-xs" />
          </div>

          <div class="flex-1 overflow-auto custom-scrollbar p-2.5 space-y-2">
            <div v-for="dev in filteredUsbDevices" :key="dev.instance_id" class="ui-sub-card hover:border-purple-500/40 p-2.5 flex flex-col gap-1.5 text-xs transition-all group">
              <div class="flex items-center justify-between gap-2">
                <span class="font-semibold truncate flex-1 group-hover:text-purple-600 dark:group-hover:text-purple-300 transition-colors" style="color: var(--text-primary);" :title="dev.device_name">
                  {{ dev.device_name }}
                </span>
                <div class="flex items-center gap-1.5 shrink-0">
                  <button
                    @click="openUsbDescriptorTree(dev)"
                    title="解析并展开此设备的四级标准描述符树"
                    class="text-[11px] font-medium text-purple-700 dark:text-purple-300 bg-purple-500/12 hover:bg-purple-500/20 border border-purple-500/25 px-2 py-0.5 rounded-md cursor-pointer transition-colors flex items-center gap-1"
                  >
                    <AppIcon name="layers" :size="11" />
                    <span>描述符</span>
                  </button>
                  <button
                    @click="addUsbDeviceToDiffQueue(dev)"
                    title="将此 USB 外设参数指纹加入全局比对队列"
                    class="text-[11px] font-semibold text-emerald-700 dark:text-emerald-300 bg-emerald-500/12 hover:bg-emerald-500/20 border border-emerald-500/25 px-2 py-0.5 rounded-md cursor-pointer transition-colors"
                  >
                    + 入队
                  </button>
                  <span :class="['text-[11px] font-semibold px-2 py-0.5 rounded-lg border', getUsbClassBadge(dev.class_desc)]">
                    {{ dev.class_desc }}
                  </span>
                </div>
              </div>

              <div class="grid grid-cols-2 gap-1.5 text-[11px] font-mono p-2 rounded-lg border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle); color: var(--text-muted);">
                <div class="truncate">
                  <span>硬件 ID: </span>
                  <strong class="text-purple-600 dark:text-purple-300">VID_{{ dev.vid }} &amp; PID_{{ dev.pid }}</strong>
                </div>
                <div class="truncate">
                  <span>驱动服务: </span>
                  <span class="font-medium" style="color: var(--text-primary);">{{ dev.service || 'N/A' }}</span>
                </div>
                <div class="truncate" :title="dev.manufacturer">
                  <span>制造商: </span>
                  <span class="font-medium" style="color: var(--text-primary);">{{ dev.manufacturer || '未知' }}</span>
                </div>
                <div class="truncate" :title="dev.location_info">
                  <span>物理位置: </span>
                  <span class="font-medium" style="color: var(--text-primary);">{{ dev.location_info || 'Root' }}</span>
                </div>
              </div>
            </div>

            <EmptyState v-if="filteredUsbDevices.length === 0" icon="usb" title="未检索到匹配的物理 USB 外设" description="挂钩 USB 引擎或刷新外设后，将自动扫描物理主机控制器下的外设端点。" />
          </div>
        </div>

        <!-- 3.1.3 USB 与串口总线实时事件及 PnP 审计流水线 -->
        <div class="flex-[2] ui-content-card flex flex-col overflow-hidden min-h-0">
          <div class="px-3.5 py-2 border-b flex items-center justify-between text-xs font-semibold shrink-0" style="border-color: var(--border-subtle); color: var(--text-primary);">
            <div class="flex items-center gap-2">
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              <span>USB / COM 总线帧与 PnP 热插拔审计流</span>
            </div>
            <span class="text-[11px] ui-num" style="color: var(--text-muted);">{{ usbAuditEvents.length }} 条实时记录</span>
          </div>

          <div class="flex-1 overflow-auto custom-scrollbar p-2.5 space-y-1.5">
            <div
              v-for="ev in usbAuditEvents"
              :key="ev.id"
              :class="['flex items-center gap-2.5 px-3 py-1.5 rounded-xl text-xs font-mono border transition-colors',
                ev.direction === 'USB_ATTACH' ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-200 border-emerald-500/25' :
                ev.direction === 'USB_DETACH' ? 'bg-amber-500/10 text-amber-700 dark:text-amber-200 border-amber-500/25' :
                ev.transport === 'SERIAL' ? 'bg-indigo-500/10 text-indigo-700 dark:text-indigo-200 border-indigo-500/25' :
                'ui-sub-card']"
            >
              <span class="text-[11px] ui-num w-16 shrink-0" style="color: var(--text-muted);">{{ ev.timestamp }}</span>
              <span
                :class="['px-2 py-0.5 rounded-md text-[11px] font-semibold shrink-0',
                  ev.direction === 'USB_ATTACH' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' :
                  ev.direction === 'USB_DETACH' ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300' :
                  ev.transport === 'SERIAL' ? 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300' :
                  'bg-purple-500/15 text-purple-700 dark:text-purple-300']"
              >
                {{ ev.direction === 'USB_ATTACH' ? 'USB 接入' : ev.direction === 'USB_DETACH' ? 'USB 拔出' : ev.transport === 'SERIAL' ? `COM ${ev.protocol || '帧'}` : (ev.protocol || 'USB URB') }}
              </span>
              <span class="truncate flex-1 text-[11px]" style="color: var(--text-primary);">{{ ev.raw_text || ev.payload_hex }}</span>
              <div class="flex items-center gap-1 shrink-0">
                <button @click="setBusEventDiffSlot('A', ev)" class="px-1.5 py-0.5 rounded bg-blue-500/12 hover:bg-blue-500/20 text-blue-700 dark:text-sky-300 border border-blue-500/25 text-[11px] font-semibold cursor-pointer" title="设为比对基准 A">A</button>
                <button @click="setBusEventDiffSlot('B', ev)" class="px-1.5 py-0.5 rounded bg-purple-500/12 hover:bg-purple-500/20 text-purple-700 dark:text-purple-300 border border-purple-500/25 text-[11px] font-semibold cursor-pointer" title="设为比对项 B 并对比">B</button>
                <button @click="addBusEventToDiffQueue(ev)" class="px-1.5 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer" title="加入全局多组比对队列">+入队</button>
              </div>
            </div>

            <EmptyState
              v-if="usbAuditEvents.length === 0"
              icon="usb"
              title="USB / COM 物理总线审计待命中"
              description="开启【挂钩 USB】或【监听串口】后，热插拔与串口/URB 报文将实时呈现于此。"
            />
          </div>
        </div>
      </div>

      <!-- 3.2 右栏：端口全双工双向出入执行器 -->
      <div class="ui-content-card flex flex-col overflow-hidden min-h-0 min-w-0">
        <div class="px-3.5 py-2 border-b flex items-center justify-between shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2">
            <span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
            <span class="text-xs font-semibold tracking-tight" style="color: var(--text-primary);">端口数据双向出入执行器 (TX → RX)</span>
          </div>

          <div class="glass-pill flex p-0.5 rounded-xl text-xs font-medium">
            <button @click="portOpChannel = 'network'" :class="['px-3 py-1 rounded-lg transition-all cursor-pointer text-[11px]', portOpChannel === 'network' ? 'bg-blue-600 text-white font-semibold' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']">
              网络端口 (TCP/UDP)
            </button>
            <button @click="portOpChannel = 'serial'" :class="['px-3 py-1 rounded-lg transition-all cursor-pointer text-[11px]', portOpChannel === 'serial' ? 'bg-indigo-600 text-white font-semibold' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']">
              物理串口 (COM)
            </button>
          </div>
        </div>

        <div class="p-3.5 border-b space-y-2.5 text-xs shrink-0 bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
          <template v-if="portOpChannel === 'network'">
            <div class="grid grid-cols-1 sm:grid-cols-[1fr_80px_75px_85px] gap-2 items-center">
              <div>
                <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">目标 IP 地址</label>
                <input v-model="portOpIp" placeholder="例如: 192.168.1.100" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono" />
              </div>
              <div>
                <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">端口</label>
                <input v-model.number="portOpPort" type="number" min="1" max="65535" class="ui-input w-full px-2.5 py-1.5 text-xs ui-num" />
              </div>
              <div>
                <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">规约总线</label>
                <select v-model="portOpTransport" class="ui-input w-full px-2 py-1.5 text-xs font-semibold text-blue-600 dark:text-sky-300">
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                </select>
              </div>
              <div>
                <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">超时(ms)</label>
                <input v-model.number="portOpTimeout" type="number" min="200" max="10000" class="ui-input w-full px-2.5 py-1.5 text-xs ui-num" />
              </div>
            </div>

            <div class="space-y-1">
              <div class="flex items-center justify-between text-[11px]">
                <span class="font-semibold" style="color: var(--text-muted);">出向操作载荷 (Payload Hex)</span>
                <select @change="onPresetSelect($event)" class="ui-input px-2 py-0.5 text-[11px] text-blue-600 dark:text-sky-300 cursor-pointer">
                  <option value="">-- 选择标准工业规约探测模板 --</option>
                  <option value="modbus_read_holding">Modbus-TCP: 读保持寄存器 0-1 (Func 03)</option>
                  <option value="http_get">HTTP/1.1: 基础心跳 GET 探测请求</option>
                  <option value="mqtt_ping">MQTT 物联: PINGREQ 保持心跳包</option>
                  <option value="iec104_test">IEC 60870-5-104: U 格式测试激活帧</option>
                </select>
              </div>
              <textarea v-model="portOpPayload" rows="2" placeholder="输入十六进制报文 (如: 00 01 00 00 00 06 01 03 00 00 00 02) 或明文字符串" class="ui-input w-full p-2 text-xs font-mono resize-none custom-scrollbar"></textarea>
            </div>

            <button @click="executePortTransceive" :disabled="portOpExecuting || !portOpPayload.trim()" class="ui-btn-primary w-full py-2 text-xs justify-center">
              <AppIcon v-if="portOpExecuting" name="refresh" :size="13" class="animate-spin" />
              <AppIcon v-else name="zap" :size="13" />
              <span>执行写出与回包捕获 (TX → RX)</span>
            </button>
          </template>

          <template v-else-if="portOpChannel === 'serial'">
            <div class="grid grid-cols-2 gap-2">
              <div>
                <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">目标物理串口</label>
                <select
                  :value="localSerial"
                  @change="onSelectSerial(($event.target as HTMLSelectElement).value)"
                  class="ui-input w-full px-2.5 py-1.5 text-xs font-mono"
                >
                  <option v-for="p in serialPorts" :key="p" :value="p">{{ p }}</option>
                  <option v-if="serialPorts.length === 0" value="">未发现串口</option>
                </select>
              </div>
              <div>
                <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">通信波特率</label>
                <select
                  :value="localBaudRate"
                  @change="onSelectBaudRate(Number(($event.target as HTMLSelectElement).value))"
                  class="ui-input w-full px-2.5 py-1.5 text-xs ui-num"
                >
                  <option :value="9600">9600 bps</option>
                  <option :value="19200">19200 bps</option>
                  <option :value="38400">38400 bps</option>
                  <option :value="57600">57600 bps</option>
                  <option :value="115200">115200 bps</option>
                </select>
              </div>
            </div>

            <div class="space-y-1">
              <div class="flex items-center justify-between text-[11px]">
                <span class="font-semibold" style="color: var(--text-muted);">串口写出指令</span>
                <label class="flex items-center gap-1.5 cursor-pointer">
                  <input type="checkbox" v-model="portOpSerialIsHex" class="accent-indigo-600" />
                  <span class="text-[11px] font-semibold text-indigo-600 dark:text-indigo-300">按 HEX 模式发送</span>
                </label>
              </div>
              <textarea v-model="portOpSerialPayload" rows="2" placeholder="输入待写出到串口的指令 (如: 01 03 00 00 00 02 C4 0B)" class="ui-input w-full p-2 text-xs font-mono resize-none custom-scrollbar"></textarea>
            </div>

            <button @click="executePortTransceive" :disabled="portOpExecuting || !portOpSerialPayload.trim() || !localSerial" class="ui-btn-primary w-full py-2 text-xs justify-center">
              <AppIcon v-if="portOpExecuting" name="refresh" :size="13" class="animate-spin" />
              <AppIcon v-else name="serial" :size="13" />
              <span>执行串口写出与双向侦测</span>
            </button>
          </template>
        </div>

        <!-- 双向操作流水历史终端 -->
        <div class="flex-1 overflow-auto custom-scrollbar p-3 space-y-2 min-h-0 bg-transparent">
          <div v-for="item in transceiveHistory" :key="item.id" class="ui-sub-card p-2.5 text-xs space-y-1.5">
            <div class="flex items-center justify-between text-[11px] border-b pb-1.5 flex-wrap gap-1.5" style="border-color: var(--border-subtle); color: var(--text-muted);">
              <span class="font-semibold" style="color: var(--text-primary);">{{ item.channel }} | {{ item.target }}</span>
              <div class="flex items-center gap-1.5 flex-wrap ui-num">
                <span>{{ item.time }} (RTT: {{ item.latencyMs.toFixed(1) }}ms)</span>
                <button
                  v-if="item.bytesReceived > 0"
                  @click="compareSerialTxRx(item)"
                  class="px-2 py-0.5 rounded bg-indigo-500/12 hover:bg-indigo-500/20 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25 font-semibold text-[11px] cursor-pointer flex items-center gap-1"
                  title="比对发送帧与回复帧的差分与波形"
                >
                  <AppIcon name="scale" :size="11" />
                  <span>TX vs RX</span>
                </button>
                <button @click="setDiffSlotA(item)" class="px-1.5 py-0.5 rounded bg-blue-500/12 hover:bg-blue-500/20 text-blue-700 dark:text-sky-300 border border-blue-500/25 text-[11px] font-semibold cursor-pointer">
                  设为 A
                </button>
                <button @click="setDiffSlotB(item)" class="px-1.5 py-0.5 rounded bg-purple-500/12 hover:bg-purple-500/20 text-purple-700 dark:text-purple-300 border border-purple-500/25 text-[11px] font-semibold cursor-pointer">
                  设为 B
                </button>
                <button @click="addTransceiveToDiffQueue(item)" class="px-1.5 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer" title="加入全局多组比对队列">
                  + 入队
                </button>
              </div>
            </div>

            <div class="text-[11px] font-mono break-all bg-blue-500/10 p-2 rounded-lg border border-blue-500/20 text-blue-800 dark:text-blue-200">
              <strong class="font-semibold mr-1.5">[TX 发送 {{ item.bytesSent }}B]:</strong>
              <span>{{ item.txPayload }}</span>
            </div>

            <div v-if="item.bytesReceived > 0" class="text-[11px] font-mono break-all bg-emerald-500/10 p-2 rounded-lg border border-emerald-500/20 text-emerald-800 dark:text-emerald-200">
              <div class="font-semibold mb-0.5">[RX 接收 {{ item.bytesReceived }}B] 协议: {{ item.detectedProto || 'RAW' }}</div>
              <div><strong>HEX:</strong> {{ item.rxPayload }}</div>
              <div v-if="item.rxText" class="mt-0.5" style="color: var(--text-primary);"><strong>ASCII:</strong> {{ item.rxText }}</div>
            </div>

            <div v-else-if="item.error" class="bg-rose-500/12 text-[11px] text-rose-700 dark:text-rose-300 p-2 rounded-lg border border-rose-500/25">
              <strong>ERR:</strong> {{ item.error }}
            </div>
          </div>

          <EmptyState
            v-if="transceiveHistory.length === 0"
            icon="zap"
            title="暂无双向端口交互出入流水"
            description="配置目标 IP/端口或物理串口，点击上方【执行写出与回包捕获】即可开始双向交互。"
          />
        </div>
      </div>
    </main>

    <SerialExtendedConfigModal :isOpen="isSerialConfigOpen" :serialPorts="serialPorts" :defaultPort="localSerial" @close="isSerialConfigOpen = false" @started="onSerialConfigStarted" @log="$emit('appendLog', $event)" />
    <SerialBridgeModal :isOpen="isSerialBridgeOpen" :serialPorts="serialPorts" @close="isSerialBridgeOpen = false" @log="$emit('appendLog', $event)" />
    <UsbDescriptorTreeModal :isOpen="isUsbDescriptorTreeOpen" :initialHex="usbDescriptorHex" @close="isUsbDescriptorTreeOpen = false" />
    <CrossBusCausalityModal :isOpen="isCrossBusCausalityOpen" @close="isCrossBusCausalityOpen = false" />
    <MultiSerialCompareModal
      :isOpen="isMultiSerialCompareOpen"
      :packets="packets"
      :availablePorts="serialPorts"
      :defaultPortA="activeSerialPorts && activeSerialPorts[0] ? activeSerialPorts[0] : (serialPorts[0] || '')"
      :defaultPortB="activeSerialPorts && activeSerialPorts[1] ? activeSerialPorts[1] : (serialPorts[1] || serialPorts[0] || '')"
      @close="isMultiSerialCompareOpen = false"
    />
  </div>
</template>

<script setup lang="ts">
import { notifySuccess, notifyWarning, notifyError } from '../composables/useNotification';
import { uiConfirm } from '../composables/useConfirmDialog';
import { useUniversalDiff } from '../composables/useUniversalDiff';
import { ref, computed, onMounted, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from '../components/AppIcon.vue';
import EmptyState from '../components/EmptyState.vue';
import SerialModemPinsPanel from '../components/SerialModemPinsPanel.vue';
import SerialExtendedConfigModal from '../components/SerialExtendedConfigModal.vue';
import SerialBridgeModal from '../components/SerialBridgeModal.vue';
import UsbDescriptorTreeModal from '../components/UsbDescriptorTreeModal.vue';
import CrossBusCausalityModal from '../components/CrossBusCausalityModal.vue';
import MultiSerialCompareModal from '../components/MultiSerialCompareModal.vue';

const isMultiSerialCompareOpen = ref(false);

export interface HardwareWhitelistItem {
  category: string;
  identifier: string;
  name: string;
  manufacturer: string;
  serial_number: string;
  added_at: string;
  description: string;
}

export interface HardwareWhitelistConfig {
  version: number;
  updated_at: string;
  items: HardwareWhitelistItem[];
}

export interface HardwareComplianceItem {
  category: string;
  identifier: string;
  name: string;
  status: string; // "COMPLIANT" | "UNAUTHORIZED" | "MISSING"
  alert_desc: string;
  description: string;
}

export interface HardwareComplianceReport {
  audit_time: string;
  total_whitelist: number;
  total_online: number;
  compliant_count: number;
  unauthorized_count: number;
  missing_count: number;
  compliance_rate: number;
  items: HardwareComplianceItem[];
}

interface UsbDeviceInfo {
  instance_id: string;
  vid: string;
  pid: string;
  device_name: string;
  friendly_name: string;
  manufacturer: string;
  service: string;
  class_desc: string;
  location_info: string;
  is_connected: boolean;
}

interface TransceiveHistoryItem {
  id: number;
  time: string;
  channel: string;
  target: string;
  transport: string;
  status: 'SUCCESS' | 'TIMEOUT' | 'ERROR';
  bytesSent: number;
  bytesReceived: number;
  latencyMs: number;
  txPayload: string;
  rxPayload: string;
  rxText: string;
  detectedProto: string;
  error?: string;
}

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

const props = defineProps<{
  usbDevices: UsbDeviceInfo[];
  packets: any[];
  serialPorts: string[];
  serialPortsDetail?: SerialPortDetail[];
  activeSerialPorts?: string[];
  selectedSerial?: string;
  serialBaudRate?: number;
  isUsbRunning?: boolean;
  isSerialRunning?: boolean;
}>();

const emit = defineEmits([
  'refreshUsb',
  'refreshSerial',
  'updateSerial',
  'updateBaudRate',
  'startUsbCapture',
  'stopUsbCapture',
  'startSerialCapture',
  'stopSerialCapture',
  'appendLog',
  'openWireless',
]);

// 硬件基线白名单与合规审计状态
const showComplianceWorkbench = ref(false);
const complianceReport = ref<HardwareComplianceReport | null>(null);

// CAN 总线与逻辑分析仪抽屉状态 (全量强类型声明)
interface DissectedCanFrame {
  timestamp_ns: number;
  raw_id: number;
  can_id: number;
  protocol_type: string;
  frame_class: string;
  is_extended_id: boolean;
  is_remote_frame: boolean;
  is_fd: boolean;
  bit_rate_switch: boolean;
  error_state_indicator: boolean;
  dlc: number;
  payload_len: number;
  payload: number[];
  error_detail?: string | null;
  wire_duration_us: number;
}
interface CanBusHealthSnapshot {
  bus_load_percentage: number;
  frames_per_second: number;
  error_frames_per_second: number;
  total_frames_dissected: number;
  total_error_frames: number;
  health_status: string;
}
interface EthernetCanTransaction {
  transaction_id: string;
  eth_packet_id: number;
  eth_timestamp_ns: number;
  eth_protocol: string;
  can_frame_id?: number | null;
  can_timestamp_ns?: number | null;
  gateway_latency_us?: number | null;
  verdict: string;
  root_cause_diagnosis: string;
  remedy_suggestion: string;
}
interface DemodulatedUartByte {
  byte_value: number;
  char_representation?: string | null;
  start_sample_index: number;
  timestamp_ns: number;
  parity_error: boolean;
  framing_error: boolean;
}
interface SignalIntegritySnapshot {
  duty_cycle_percentage: number;
  mean_high_pulse_width_ns: number;
  mean_low_pulse_width_ns: number;
  jitter_stddev_ns: number;
  glitches_detected: number;
  integrity_grade: string;
}

const showCanDiagnosticDrawer = ref(false);
const canHealth = ref<CanBusHealthSnapshot | null>(null);
const canCausalRecords = ref<EthernetCanTransaction[]>([]);
const canRawHex = ref('');
const canNominalBps = ref(500000);
const canDataBps = ref(2000000);
const dissectedCan = ref<DissectedCanFrame | null>(null);

const showUartLogicDrawer = ref(false);
const uartSamplesHex = ref('');
const uartIntervalNs = ref(100);
const uartBaudRate = ref(115200);
const uartMinGlitchNs = ref(500);
const uartBytes = ref<DemodulatedUartByte[]>([]);
const signalSnapshot = ref<SignalIntegritySnapshot | null>(null);

async function fetchCanDiagnostics() {
  try {
    const [health, records] = await Promise.all([
      invoke<CanBusHealthSnapshot>('get_can_bus_health_cmd'),
      invoke<EthernetCanTransaction[]>('get_can_causal_records_cmd'),
    ]);
    canHealth.value = health;
    canCausalRecords.value = records;
  } catch (e) {
    console.error('获取 CAN 总线快照失败:', e);
  }
}

async function toggleCanDrawer() {
  showCanDiagnosticDrawer.value = !showCanDiagnosticDrawer.value;
  if (showCanDiagnosticDrawer.value) {
    await fetchCanDiagnostics();
  }
}

async function runCanDissection() {
  const cleaned = canRawHex.value.trim().replace(/\s+/g, '');
  if (!cleaned) return;
  try {
    dissectedCan.value = await invoke<DissectedCanFrame>('dissect_can_packet_cmd', {
      rawHex: cleaned,
      timestampNs: Date.now() * 1_000_000,
      nominalBps: canNominalBps.value,
      dataBps: canDataBps.value,
    });
    await fetchCanDiagnostics();
  } catch (e) {
    notifyError('CAN 二进制帧解码失败', e);
  }
}

async function runUartDemodulate() {
  const cleaned = uartSamplesHex.value.trim().replace(/\s+/g, '');
  if (!cleaned) return;
  try {
    uartBytes.value = await invoke<DemodulatedUartByte[]>('demodulate_physical_uart_cmd', {
      samplesBinaryHex: cleaned,
      sampleIntervalNs: uartIntervalNs.value,
      baudRate: uartBaudRate.value,
      minGlitchNs: uartMinGlitchNs.value,
    });
    if (uartBytes.value.length === 0) {
      notifyWarning('UART 解调无起止字符', '未检测到符合选定波特率的有效 Start/Stop 帧序列');
    }
  } catch (e) {
    notifyError('UART 电平解调失败', e);
  }
}

async function runSignalIntegrity() {
  const cleaned = uartSamplesHex.value.trim().replace(/\s+/g, '');
  if (!cleaned) return;
  try {
    signalSnapshot.value = await invoke<SignalIntegritySnapshot>('evaluate_signal_integrity_cmd', {
      samplesBinaryHex: cleaned,
      sampleIntervalNs: uartIntervalNs.value,
      expectedBaud: uartBaudRate.value,
    });
  } catch (e) {
    notifyError('信号完整性评估失败', e);
  }
}
const whitelistConfig = ref<HardwareWhitelistConfig | null>(null);
const isSavingWhitelist = ref(false);
const isAuditingCompliance = ref(false);
const whitelistFilter = ref<'ALL' | 'UNAUTHORIZED' | 'MISSING' | 'COMPLIANT'>('ALL');

async function loadWhitelist() {
  try {
    const res = await invoke<HardwareWhitelistConfig>('get_hardware_whitelist_cmd');
    whitelistConfig.value = res;
  } catch (e: any) {
    console.error('加载硬件白名单失败:', e);
  }
}

async function doSaveCurrentAsWhitelist() {
  isSavingWhitelist.value = true;
  try {
    const items: HardwareWhitelistItem[] = [];
    const nowStr = new Date().toLocaleString();

    // 1. 固化当前在线的所有 USB 设备
    for (const dev of props.usbDevices) {
      const vidPid = `VID_${dev.vid}_PID_${dev.pid}`.toUpperCase();
      items.push({
        category: 'USB',
        identifier: vidPid,
        name: dev.device_name || dev.friendly_name || 'USB 外设',
        manufacturer: dev.manufacturer || '未知厂商',
        serial_number: dev.instance_id,
        added_at: nowStr,
        description: `基线外设 (${dev.class_desc})`
      });
    }

    // 2. 固化当前在线的所有物理/虚拟串口
    for (const port of props.serialPorts) {
      items.push({
        category: 'SERIAL',
        identifier: port,
        name: `串口 ${port}`,
        manufacturer: '物理总线',
        serial_number: port,
        added_at: nowStr,
        description: '受信任工业通信串口'
      });
    }

    const count = await invoke<number>('save_hardware_whitelist_cmd', { items });
    emit('appendLog', `[HARDWARE] ✓ 成功固化 ${count} 个硬件为受信任基线白名单`);
    notifySuccess('硬件基线白名单固化成功', `已将当前 ${count} 个在线物理设备固化至受信任白名单库`);
    await loadWhitelist();
    await doVerifyCompliance();
  } catch (e: any) {
    notifyError('固化硬件白名单受阻', e);
  } finally {
    isSavingWhitelist.value = false;
  }
}

async function doVerifyCompliance() {
  isAuditingCompliance.value = true;
  try {
    const res = await invoke<HardwareComplianceReport>('verify_hardware_compliance_cmd');
    complianceReport.value = res;
    emit('appendLog', `[HARDWARE] 物理硬件合规差分比对完成: 合规率 ${res.compliance_rate.toFixed(1)}% | 未授权外设: ${res.unauthorized_count} | 离线缺失: ${res.missing_count}`);
  } catch (e: any) {
    console.error('硬件合规比对失败:', e);
  } finally {
    isAuditingCompliance.value = false;
  }
}

async function doClearWhitelist() {
  const confirmed = await uiConfirm(
    '确定要清空现有硬件白名单基线吗？清空后所有在线外设都将被标记为未授权外设！',
    { title: '确认清空硬件白名单', confirmText: '确认清空', danger: true }
  );
  if (!confirmed) return;
  try {
    await invoke('clear_hardware_whitelist_cmd');
    await loadWhitelist();
    await doVerifyCompliance();
    emit('appendLog', '[HARDWARE] 已清空硬件基线白名单');
    notifyWarning('硬件白名单已清空', '基线已重置，当前所有外设已被判定为未授权');
  } catch (e: any) {
    notifyError('清空白名单受阻', e);
  }
}

const filteredComplianceItems = computed(() => {
  if (!complianceReport.value) return [];
  let list = complianceReport.value.items;
  if (whitelistFilter.value === 'UNAUTHORIZED') {
    list = list.filter(i => i.status === 'UNAUTHORIZED');
  } else if (whitelistFilter.value === 'MISSING') {
    list = list.filter(i => i.status === 'MISSING');
  } else if (whitelistFilter.value === 'COMPLIANT') {
    list = list.filter(i => i.status === 'COMPLIANT');
  }
  return list;
});

onMounted(() => {
  loadWhitelist();
  doVerifyCompliance();
});

// 工业级专业模块状态
const isSerialConfigOpen = ref(false);
const showModemPins = ref(false);
const isSerialBridgeOpen = ref(false);
const isUsbDescriptorTreeOpen = ref(false);
const isCrossBusCausalityOpen = ref(false);
const usbDescriptorHex = ref('');

function openUsbDescriptorTree(dev?: UsbDeviceInfo) {
  if (dev) {
    if (dev.class_desc.includes('HID') || dev.class_desc.includes('人机交互') || dev.class_desc.includes('鼠标') || dev.class_desc.includes('键盘')) {
      usbDescriptorHex.value = '12 01 00 02 00 00 00 40 86 80 20 08 00 01 01 02 00 01 09 02 22 00 01 01 00 A0 32 09 04 00 00 01 03 01 02 00 07 05 81 03 08 00 0A';
    } else if (dev.class_desc.includes('存储') || dev.class_desc.includes('U盘')) {
      usbDescriptorHex.value = '12 01 10 02 00 00 00 40 51 09 63 16 00 01 01 02 03 01 09 02 20 00 01 01 00 C0 32 09 04 00 00 02 08 06 50 00 07 05 81 02 40 00 00 07 05 02 02 40 00 00';
    } else if (dev.class_desc.includes('串口') || dev.class_desc.includes('CDC')) {
      usbDescriptorHex.value = '12 01 00 02 02 00 00 40 86 1A 23 75 00 02 01 02 03 01 09 02 43 00 02 01 00 80 32 09 04 00 00 01 02 02 01 00 07 05 82 03 0A 00 01 09 04 01 00 02 0A 00 00 00 07 05 02 02 40 00 00 07 05 82 02 40 00 00';
    } else {
      usbDescriptorHex.value = '12 01 00 02 00 00 00 40 86 80 20 08 00 01 01 02 00 01 09 02 22 00 01 01 00 A0 32 09 04 00 00 01 03 01 02 00 07 05 81 03 08 00 0A';
    }
  }
  isUsbDescriptorTreeOpen.value = true;
}

function onSerialConfigStarted(payload: { port: string; baudRate: number }) {
  onSelectSerial(payload.port);
  onSelectBaudRate(payload.baudRate);
}

const usbFilter = ref('');
const serialFilter = ref('');
const portOpChannel = ref<'network' | 'serial'>('network');
const portOpIp = ref('');
const portOpPort = ref(502);
const portOpTransport = ref<'TCP' | 'UDP'>('TCP');
const portOpTimeout = ref(2000);
const portOpPayload = ref('00 01 00 00 00 06 01 03 00 00 00 02');
const localSerial = ref(props.selectedSerial || (props.serialPorts.length > 0 ? props.serialPorts[0] : ''));
const localBaudRate = ref(props.serialBaudRate || 9600);
const portOpSerialPayload = ref('01 03 00 00 00 02 C4 0B');
const portOpSerialIsHex = ref(true);
const portOpExecuting = ref(false);
const transceiveHistory = ref<TransceiveHistoryItem[]>([]);

watch(
  () => props.selectedSerial,
  (val) => {
    if (val && val !== localSerial.value) {
      localSerial.value = val;
    }
  }
);

watch(
  () => props.serialPorts,
  (ports) => {
    if ((!localSerial.value || !ports.includes(localSerial.value)) && ports.length > 0) {
      localSerial.value = ports[0];
      emit('updateSerial', ports[0]);
    }
  },
  { immediate: true }
);

watch(
  () => props.serialBaudRate,
  (rate) => {
    if (rate && rate !== localBaudRate.value) {
      localBaudRate.value = rate;
    }
  }
);

function onSelectSerial(port: string) {
  localSerial.value = port;
  emit('updateSerial', port);
}

function onSelectBaudRate(rate: number) {
  localBaudRate.value = rate;
  emit('updateBaudRate', rate);
}

function refreshAllHardwareBuses() {
  emit('refreshUsb');
  emit('refreshSerial');
}

const normalizedSerialList = computed<SerialPortDetail[]>(() => {
  if (props.serialPortsDetail && props.serialPortsDetail.length > 0) {
    return props.serialPortsDetail;
  }
  return props.serialPorts.map((portName) => ({
    port_name: portName,
    description: `${portName} (系统通信端口)`,
    hardware_id: 'STANDARD_COM',
    port_type: '标准硬件串口',
    is_usb: false,
    is_available: true,
    is_in_use_by_us: (props.activeSerialPorts || []).includes(portName),
  }));
});

const filteredSerialList = computed(() => {
  const q = serialFilter.value.trim().toLowerCase();
  if (!q) return normalizedSerialList.value;
  return normalizedSerialList.value.filter((sp) =>
    sp.port_name.toLowerCase().includes(q) ||
    sp.description.toLowerCase().includes(q) ||
    sp.port_type.toLowerCase().includes(q) ||
    (sp.manufacturer || '').toLowerCase().includes(q) ||
    (sp.product || '').toLowerCase().includes(q) ||
    sp.hardware_id.toLowerCase().includes(q)
  );
});

const activeSerialCount = computed(() => {
  if (props.activeSerialPorts && props.activeSerialPorts.length > 0) {
    return props.activeSerialPorts.length;
  }
  return props.isSerialRunning ? 1 : 0;
});

function isPortActive(portName: string): boolean {
  if (!portName) return false;
  if (props.activeSerialPorts && props.activeSerialPorts.length > 0) {
    return props.activeSerialPorts.includes(portName);
  }
  return !!props.isSerialRunning && localSerial.value === portName;
}

function startPortMonitor(portName: string) {
  if (!portName) return;
  onSelectSerial(portName);
  emit('startSerialCapture', portName, localBaudRate.value);
}

function togglePortCapture(portName: string) {
  if (isPortActive(portName)) {
    emit('stopSerialCapture', portName);
  } else {
    startPortMonitor(portName);
  }
}

function focusSerialTransceive(portName: string) {
  onSelectSerial(portName);
  portOpChannel.value = 'serial';
}

function getSerialTypeBadge(sp: SerialPortDetail): string {
  if (sp.port_type.includes('蓝牙') || sp.hardware_id.includes('BTH')) {
    return 'bg-sky-500/12 text-sky-700 dark:text-sky-300 border-sky-500/25';
  }
  if (sp.is_usb || sp.port_type.includes('USB')) {
    return 'bg-purple-500/12 text-purple-700 dark:text-purple-300 border-purple-500/25';
  }
  return 'bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border-indigo-500/25';
}

// 全局通用数据比对总线
const diffBus = useUniversalDiff();

function buildTransceiveItem(item: TransceiveHistoryItem) {
  return {
    id: `SER_${item.id}`,
    label: `[总线] ${item.channel} ${item.target}`,
    timestamp: item.time,
    protocol: item.detectedProto || 'BUS_IO',
    src: item.channel,
    dst: item.target,
    payloadHex: (item.rxPayload || item.txPayload).replace(/\s+/g, ''),
    rawText: item.rxText,
    length: item.bytesReceived || item.bytesSent,
    extraFields: {
      channel: item.channel,
      transport: item.transport,
      latency_ms: String(item.latencyMs),
      status: item.status
    }
  };
}

function compareSerialTxRx(item: TransceiveHistoryItem) {
  const txItem = {
    id: `SER_TX_${item.id}`,
    label: `[硬件发送] ${item.channel} ➔ ${item.target}`,
    timestamp: item.time,
    protocol: item.detectedProto || 'BUS_TX',
    src: '本地总线主机',
    dst: item.target,
    payloadHex: item.txPayload.replace(/\s+/g, ''),
    length: item.bytesSent
  };
  const rxItem = {
    id: `SER_RX_${item.id}`,
    label: `[硬件回包] ${item.channel} ➔ ${item.target}`,
    timestamp: item.time,
    protocol: item.detectedProto || 'BUS_RX',
    src: item.target,
    dst: '本地总线主机',
    payloadHex: item.rxPayload.replace(/\s+/g, ''),
    rawText: item.rxText,
    length: item.bytesReceived
  };
  diffBus.openUniversalDiff(txItem, rxItem, 'hex');
}

function setDiffSlotA(item: TransceiveHistoryItem) {
  diffBus.setSlotA(buildTransceiveItem(item), `总线 ${item.channel}`);
}

function setDiffSlotB(item: TransceiveHistoryItem) {
  diffBus.setSlotB(buildTransceiveItem(item), `总线 ${item.channel}`);
  if (diffBus.slotA.value) {
    diffBus.compareSlots();
  }
}

function addTransceiveToDiffQueue(item: TransceiveHistoryItem) {
  diffBus.addToQueue(buildTransceiveItem(item), `总线 #${item.id} ${item.channel}`, false);
}

function addSerialPortToDiffQueue(sp: SerialPortDetail) {
  const summary = `PORT=${sp.port_name};TYPE=${sp.port_type};HWID=${sp.hardware_id || 'N/A'};MFG=${sp.manufacturer || 'STD'}`;
  diffBus.addToQueue({
    id: `COM_${sp.port_name}`,
    label: `[COM 串口] ${sp.port_name} (${sp.port_type})`,
    protocol: 'SERIAL-COM',
    src: sp.port_name,
    dst: sp.manufacturer || '标准串口控制器',
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: summary,
    length: summary.length,
    extraFields: {
      port_name: sp.port_name,
      port_type: sp.port_type,
      hardware_id: sp.hardware_id || '-',
      product: sp.product || sp.description || '-',
      manufacturer: sp.manufacturer || '-',
      is_usb: String(sp.is_usb)
    }
  }, `COM ${sp.port_name}`, false);
}

function addUsbDeviceToDiffQueue(dev: UsbDeviceInfo) {
  const summary = `VID=${dev.vid};PID=${dev.pid};CLASS=${dev.class_desc};SVC=${dev.service || 'N/A'};LOC=${dev.location_info || 'Root'}`;
  diffBus.addToQueue({
    id: `USB_${dev.vid}_${dev.pid}`,
    label: `[USB] ${dev.device_name}`,
    protocol: `USB-${dev.class_desc || 'DEV'}`,
    src: `VID_${dev.vid}:PID_${dev.pid}`,
    dst: dev.location_info || 'USB Root Hub',
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: summary,
    length: summary.length,
    extraFields: {
      vid: dev.vid,
      pid: dev.pid,
      manufacturer: dev.manufacturer || '-',
      service: dev.service || '-',
      class_desc: dev.class_desc || '-',
      instance_id: dev.instance_id
    }
  }, `USB ${dev.vid}:${dev.pid}`, false);
}

function buildBusEventItem(ev: any) {
  const cleanHex = typeof ev.payload_hex === 'string' ? ev.payload_hex.replace(/\s+/g, '') : '';
  return {
    id: `BUS_EV_${ev.id}`,
    label: `[${ev.transport || 'BUS'}] ${ev.protocol || ev.direction || 'EVENT'} #${ev.id}`,
    timestamp: ev.timestamp,
    protocol: ev.protocol || ev.transport || 'BUS',
    src: ev.src_ip || ev.direction || 'LOCAL_BUS',
    dst: ev.dst_ip || 'HOST',
    payloadHex: cleanHex,
    rawText: ev.raw_text || '',
    length: ev.length || (cleanHex ? cleanHex.length / 2 : (ev.raw_text?.length || 0)),
    extraFields: {
      transport: ev.transport || '-',
      direction: ev.direction || '-',
      info: ev.info || '-'
    }
  };
}

function setBusEventDiffSlot(slot: 'A' | 'B', ev: any) {
  const item = buildBusEventItem(ev);
  if (slot === 'A') {
    diffBus.setSlotA(item, item.label);
  } else {
    diffBus.setSlotB(item, item.label);
    if (diffBus.slotA.value) diffBus.compareSlots();
  }
}

function addBusEventToDiffQueue(ev: any) {
  const item = buildBusEventItem(ev);
  diffBus.addToQueue(item, item.label, false);
}

const filteredUsbDevices = computed(() => {
  if (!usbFilter.value.trim()) return props.usbDevices;
  const q = usbFilter.value.trim().toLowerCase();
  return props.usbDevices.filter(d =>
    d.device_name.toLowerCase().includes(q) ||
    d.vid.toLowerCase().includes(q) ||
    d.pid.toLowerCase().includes(q) ||
    d.class_desc.toLowerCase().includes(q) ||
    d.manufacturer.toLowerCase().includes(q)
  );
});

const usbAuditEvents = computed(() => props.packets.filter(p => p.direction === 'USB_ATTACH' || p.direction === 'USB_DETACH' || p.transport === 'USB' || p.transport === 'SERIAL').slice(-80).reverse());

function getUsbClassBadge(classDesc: string): string {
  if (classDesc.includes('串口') || classDesc.includes('CDC') || classDesc.includes('RS485')) {
    return 'bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border-indigo-500/25';
  } else if (classDesc.includes('存储') || classDesc.includes('U盘')) {
    return 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/25';
  } else if (classDesc.includes('HID') || classDesc.includes('人机交互')) {
    return 'bg-cyan-500/12 text-cyan-700 dark:text-cyan-300 border-cyan-500/25';
  } else if (classDesc.includes('视觉') || classDesc.includes('相机')) {
    return 'bg-blue-500/12 text-blue-700 dark:text-sky-300 border-blue-500/25';
  }
  return 'bg-purple-500/12 text-purple-700 dark:text-purple-300 border-purple-500/25';
}

function onPresetSelect(e: Event) {
  const sel = (e.target as HTMLSelectElement).value;
  if (!sel) return;
  if (sel === 'modbus_read_holding') {
    portOpPort.value = 502;
    portOpTransport.value = 'TCP';
    portOpPayload.value = '00 01 00 00 00 06 01 03 00 00 00 02';
  } else if (sel === 'http_get') {
    portOpPort.value = 80;
    portOpTransport.value = 'TCP';
    portOpPayload.value = `GET / HTTP/1.1\r\nHost: ${portOpIp.value || '127.0.0.1'}\r\nUser-Agent: OmniProbe/0.1.0\r\nConnection: close\r\n\r\n`;
  } else if (sel === 'mqtt_ping') {
    portOpPort.value = 1883;
    portOpTransport.value = 'TCP';
    portOpPayload.value = 'C0 00';
  } else if (sel === 'iec104_test') {
    portOpPort.value = 2404;
    portOpTransport.value = 'TCP';
    portOpPayload.value = '68 04 43 00 00 00';
  }
}

async function executePortTransceive() {
  if (portOpExecuting.value) return;
  portOpExecuting.value = true;
  const ts = new Date().toLocaleTimeString('zh-CN', { hour12: false });

  try {
    if (portOpChannel.value === 'network') {
      const res = await invoke<any>('send_port_transceive_cmd', {
        targetIp: portOpIp.value.trim(),
        targetPort: portOpPort.value,
        transport: portOpTransport.value,
        payloadHex: portOpPayload.value.trim(),
        timeoutMs: portOpTimeout.value
      });

      transceiveHistory.value.unshift({
        id: Date.now(),
        time: ts,
        channel: `网络 ${portOpTransport.value}`,
        target: `${portOpIp.value}:${portOpPort.value}`,
        transport: portOpTransport.value,
        status: res.success ? 'SUCCESS' : 'ERROR',
        bytesSent: res.bytes_sent,
        bytesReceived: res.bytes_received,
        latencyMs: res.latency_ms,
        txPayload: portOpPayload.value.trim(),
        rxPayload: res.response_hex || '',
        rxText: res.response_text || '',
        detectedProto: res.detected_protocol || '',
        error: res.error_msg
      });
    } else if (portOpChannel.value === 'serial') {
      const start = performance.now();
      const bytesSent = await invoke<number>('send_serial_data_cmd', {
        port: localSerial.value,
        baudRate: localBaudRate.value,
        payload: portOpSerialPayload.value.trim(),
        isHex: portOpSerialIsHex.value
      });
      const latencyMs = performance.now() - start;

      transceiveHistory.value.unshift({
        id: Date.now(),
        time: ts,
        channel: '物理串口',
        target: `${localSerial.value} @ ${localBaudRate.value} bps`,
        transport: 'SERIAL',
        status: 'SUCCESS',
        bytesSent,
        bytesReceived: 0,
        latencyMs,
        txPayload: portOpSerialPayload.value.trim(),
        rxPayload: '',
        rxText: '',
        detectedProto: 'SERIAL_TX',
        error: undefined
      });
    }
  } catch (err: any) {
    transceiveHistory.value.unshift({
      id: Date.now(),
      time: ts,
      channel: portOpChannel.value === 'network' ? '网络端口' : '物理串口',
      target: portOpChannel.value === 'network' ? `${portOpIp.value}:${portOpPort.value}` : localSerial.value,
      transport: 'N/A',
      status: 'ERROR',
      bytesSent: 0,
      bytesReceived: 0,
      latencyMs: 0,
      txPayload: portOpChannel.value === 'network' ? portOpPayload.value : portOpSerialPayload.value,
      rxPayload: '',
      rxText: '',
      detectedProto: '',
      error: String(err)
    });
  } finally {
    portOpExecuting.value = false;
  }
}
</script>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 5px;
  height: 5px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: transparent;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.15);
  border-radius: 4px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.25);
}

.custom-scrollbar-x::-webkit-scrollbar {
  height: 3px;
}
.custom-scrollbar-x::-webkit-scrollbar-track {
  background: transparent;
}
.custom-scrollbar-x::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.15);
  border-radius: 3px;
}
</style>
