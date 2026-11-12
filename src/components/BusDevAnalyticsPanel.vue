<template>
  <section class="ui-content-card border-sky-500/35 p-3.5 flex flex-col gap-3 shrink-0 select-text">
    <!-- 顶部栏：3 大工程模式页签 + 刷新状态 -->
    <div class="flex items-center justify-between gap-2 flex-wrap border-b pb-2.5" style="border-color: var(--border-subtle);">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="w-2 h-2 rounded-full bg-sky-500"></span>
        <h3 class="text-xs font-bold" style="color: var(--text-primary);">
          COM &amp; USB 深度协议开发辅助、ECharts 科研统计与巡检报告工作台
        </h3>
        <div class="p-0.5 rounded-xl ui-pill flex items-center gap-0.5 text-[11px] font-semibold">
          <button
            v-for="tab in panelTabs"
            :key="tab.id"
            @click="activeTab = tab.id"
            :class="[
              'px-2.5 py-0.5 rounded-lg transition-colors cursor-pointer flex items-center gap-1',
              activeTab === tab.id ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5'
            ]"
            :style="activeTab !== tab.id ? { color: 'var(--text-secondary)' } : undefined"
          >
            <AppIcon :name="tab.icon" :size="11" />
            <span>{{ tab.label }}</span>
          </button>
        </div>
      </div>

      <div class="flex items-center gap-2 text-[11px]">
        <span v-if="statusNotice" class="ui-num text-sky-700 dark:text-sky-300 font-medium truncate max-w-sm" :title="statusNotice">
          {{ statusNotice }}
        </span>
        <button @click="refreshSnapshot" class="ui-btn-secondary px-2.5 py-1 text-[11px]">
          <AppIcon name="refresh" :size="11" />
          <span>刷新指标</span>
        </button>
        <button @click="$emit('close')" class="ui-pill px-2.5 py-1 text-[11px] rounded-lg cursor-pointer" style="color: var(--text-muted);">
          收起工作台
        </button>
      </div>
    </div>

    <!-- ================================================================== -->
    <!-- 页签 1: COM 串口工控辅助开发、校验码计算、自动应答仿真 & Modbus 矩阵 -->
    <!-- ================================================================== -->
    <div v-if="activeTab === 'com-dev'" class="space-y-3">
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-3">
        <!-- 左: 工业校验构造器 + 周期定时发送控制 -->
        <div class="lg:col-span-6 ui-sub-card p-3 space-y-2.5 text-xs">
          <div class="flex items-center justify-between">
            <span class="font-bold flex items-center gap-1.5" style="color: var(--text-primary);">
              <AppIcon name="zap" :size="13" />
              <span>协议校验码生成器 &amp; 周期定时测试发射器</span>
            </span>
            <span
              v-if="snapshot?.periodic_tx.running"
              class="px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 text-[10px] font-bold ui-num"
            >
              循环发射中: {{ snapshot.periodic_tx.sent_count }} 帧 ({{ snapshot.periodic_tx.port_name }})
            </span>
          </div>

          <div class="grid grid-cols-3 gap-2 text-[11px]">
            <div>
              <label class="text-[10px] block mb-0.5" style="color: var(--text-muted);">校验算法</label>
              <select v-model="chkAlgo" class="ui-input w-full px-2 py-1 text-[11px]">
                <option value="MODBUS_CRC16">Modbus CRC-16 (LE)</option>
                <option value="CCITT_CRC16">CCITT CRC-16 (BE)</option>
                <option value="MODBUS_LRC">Modbus ASCII LRC</option>
                <option value="SUM8">累加和 SUM-8</option>
                <option value="XOR8">异或校验 XOR-8 (NMEA)</option>
              </select>
            </div>
            <div>
              <label class="text-[10px] block mb-0.5" style="color: var(--text-muted);">周期发送间隔 (ms)</label>
              <input type="number" v-model.number="periodicIntervalMs" min="25" max="60000" class="ui-input w-full px-2 py-1 text-[11px] ui-num" />
            </div>
            <div>
              <label class="text-[10px] block mb-0.5" style="color: var(--text-muted);">发包上限 (0=无限)</label>
              <input type="number" v-model.number="periodicMaxIter" min="0" max="100000" class="ui-input w-full px-2 py-1 text-[11px] ui-num" />
            </div>
          </div>

          <div class="space-y-1">
            <div class="flex items-center justify-between text-[11px]">
              <span style="color: var(--text-muted);">原始请求正文 (无需手算结尾校验位)</span>
              <div class="flex items-center gap-3">
                <label class="flex items-center gap-1 cursor-pointer">
                  <input type="checkbox" v-model="chkIsHex" class="accent-sky-500" />
                  <span>HEX 输入</span>
                </label>
                <label class="flex items-center gap-1 cursor-pointer">
                  <input type="checkbox" v-model="periodicAppendCrc" class="accent-indigo-500" />
                  <span>定时自动追加 Modbus CRC16</span>
                </label>
              </div>
            </div>
            <input
              v-model="chkPayload"
              placeholder="例如: 01 03 00 00 00 02"
              class="ui-input w-full px-2.5 py-1.5 text-xs font-mono"
            />
          </div>

          <div class="flex items-center gap-2 flex-wrap text-[11px]">
            <button @click="runComputeChecksum" class="ui-btn-secondary px-2.5 py-1">计算校验码</button>
            <button
              v-if="chkResult"
              @click="$emit('fillSerialPayload', chkResult.combined_frame_hex, true)"
              class="px-2.5 py-1 rounded-lg bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-500/30 font-semibold cursor-pointer"
            >
              一键填回右栏串口发包框
            </button>
            <button
              v-if="!snapshot?.periodic_tx.running"
              @click="startPeriodicTx"
              :disabled="!selectedSerialPort || !chkPayload.trim()"
              class="ui-btn-primary px-2.5 py-1 disabled:opacity-45"
            >
              启动定时发射 ({{ selectedSerialPort || '未选串口' }})
            </button>
            <button v-else @click="stopPeriodicTx" class="ui-btn-danger px-2.5 py-1">
              停止定时发射
            </button>
          </div>

          <div v-if="chkResult" class="p-2 rounded-lg border bg-[var(--surface-glass-pill)] text-[11px] font-mono space-y-0.5" style="border-color: var(--border-subtle);">
            <div>校验码 ({{ chkResult.algorithm }}): <strong class="text-emerald-600 dark:text-emerald-300">{{ chkResult.checksum_hex }}</strong></div>
            <div class="break-all" style="color: var(--text-primary);">完整待发帧 ({{ chkResult.byte_length }} B): {{ chkResult.combined_frame_hex }}</div>
          </div>
        </div>

        <!-- 右: ECharts COM 帧间到达间隔 Δt 分布直方图 -->
        <div class="lg:col-span-6 ui-sub-card p-3 space-y-2">
          <div class="flex items-center justify-between text-xs">
            <span class="font-bold flex items-center gap-1.5" style="color: var(--text-primary);">
              <AppIcon name="activity" :size="13" />
              <span>串口帧间静默时隙 (Δt) 分布直方图 &amp; CRC 误码健康度</span>
            </span>
            <span class="text-[10px] ui-num" style="color: var(--text-muted);">
              {{ snapshot?.serial_gap_metrics.length || 0 }} 个活跃端口 · 总 CRC 错误 {{ totalSerialCrcErrors }}
            </span>
          </div>
          <div class="h-44 w-full relative">
            <VChart v-if="snapshot && snapshot.serial_gap_metrics.length > 0" :option="serialGapEchartOption" autoresize class="w-full h-full" />
            <div v-else class="w-full h-full flex items-center justify-center text-[11px]" style="color: var(--text-muted);">
              开启监听物理串口接收数据帧后，将自动统计微/毫秒级帧间 Δt 粘连风险分布
            </div>
          </div>
          <div v-if="snapshot && snapshot.serial_gap_metrics.length > 0" class="flex flex-wrap gap-2 text-[10px] ui-num" style="color: var(--text-secondary);">
            <span v-for="m in snapshot.serial_gap_metrics" :key="m.port_name" class="px-2 py-0.5 rounded border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
              <strong>{{ m.port_name }}</strong>: {{ m.total_rx_frames }} 帧 ({{ m.total_rx_bytes }}B) · 均值 Δt={{ m.avg_gap_ms }}ms · CRC 错 {{ m.modbus_crc_errors }}
            </span>
          </div>
        </div>
      </div>

      <!-- Modbus RTU 实时寄存器画像矩阵 + 从站自动应答仿真规则 -->
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-3">
        <!-- Modbus 实时寄存器矩阵 -->
        <div class="lg:col-span-6 ui-sub-card p-3 space-y-2 text-xs">
          <div class="flex items-center justify-between">
            <span class="font-bold" style="color: var(--text-primary);">Modbus RTU 实时寄存器快照矩阵</span>
            <span class="text-[10px] ui-num" style="color: var(--text-muted);">共 {{ snapshot?.modbus_registers.length || 0 }} 个在映点位</span>
          </div>
          <div class="max-h-48 overflow-y-auto overflow-x-auto border rounded-lg" style="border-color: var(--border-subtle);">
            <table class="w-full text-left border-collapse text-[11px] ui-num">
              <thead class="ui-table-head text-[10px] uppercase sticky top-0">
                <tr>
                  <th class="py-1.5 px-2">端口 / 从站</th>
                  <th class="py-1.5 px-2">功能码</th>
                  <th class="py-1.5 px-2">寄存器址</th>
                  <th class="py-1.5 px-2">Dec (U16 / I16)</th>
                  <th class="py-1.5 px-2">HEX</th>
                  <th class="py-1.5 px-2">趋势 / 次数</th>
                </tr>
              </thead>
              <tbody class="divide-y" style="border-color: var(--border-subtle); color: var(--text-secondary);">
                <tr v-for="reg in (snapshot?.modbus_registers || [])" :key="reg.key">
                  <td class="py-1 px-2 font-semibold" style="color: var(--text-primary);">{{ reg.port_name }} · S{{ reg.slave_id }}</td>
                  <td class="py-1 px-2 font-mono">0x{{ reg.function_code.toString(16).padStart(2, '0').toUpperCase() }}</td>
                  <td class="py-1 px-2 font-mono">0x{{ reg.register_addr.toString(16).padStart(4, '0').toUpperCase() }}</td>
                  <td class="py-1 px-2">{{ reg.raw_u16 }} / {{ reg.signed_i16 }}</td>
                  <td class="py-1 px-2 font-mono">{{ reg.hex_value }}</td>
                  <td class="py-1 px-2">
                    <span
                      :class="['px-1 py-0.2 rounded text-[10px] font-bold mr-1',
                        reg.trend === 'UP' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' :
                        reg.trend === 'DOWN' ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300' :
                        'ui-pill']"
                    >
                      {{ reg.trend }}
                    </span>
                    <span class="opacity-75">×{{ reg.update_count }}</span>
                  </td>
                </tr>
                <tr v-if="!snapshot || snapshot.modbus_registers.length === 0">
                  <td colspan="6" class="py-5 text-center text-[11px]" style="color: var(--text-muted);">
                    暂无 Modbus RTU 寄存器数据（解析到合法 Function 03/04/06 帧后将自动关联请求基址沉淀快照）
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- 从站规则自动应答仿真器 -->
        <div class="lg:col-span-6 ui-sub-card p-3 space-y-2 text-xs">
          <div class="flex items-center justify-between">
            <span class="font-bold" style="color: var(--text-primary);">交互式串口从站仿真器 (规则匹配自动应答)</span>
            <span class="text-[10px] ui-num" style="color: var(--text-muted);">已配置 {{ snapshot?.auto_rules.length || 0 }} 条规则</span>
          </div>
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-1.5 text-[11px]">
            <input v-model="newRule.name" placeholder="规则名" class="ui-input px-2 py-1" />
            <select v-model="newRule.port_filter" class="ui-input px-1.5 py-1">
              <option value="ALL">全部串口</option>
              <option v-for="p in serialPorts" :key="p" :value="p">{{ p }}</option>
            </select>
            <select v-model="newRule.match_mode" class="ui-input px-1.5 py-1">
              <option value="HEX_PREFIX">HEX 前缀匹配</option>
              <option value="HEX_EXACT">HEX 全帧精确</option>
              <option value="MODBUS_FUNC">Modbus 功能码</option>
              <option value="ASCII_CONTAINS">ASCII 文本包含</option>
            </select>
            <input v-model="newRule.match_pattern" placeholder="匹配值 (如 01 03)" class="ui-input px-2 py-1 font-mono" />
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-[1fr_72px_auto] gap-1.5 items-center text-[11px]">
            <input v-model="newRule.response_payload" placeholder="应答报文 (如 01 03 02 00 64)" class="ui-input px-2 py-1 font-mono" />
            <input type="number" v-model.number="newRule.delay_ms" min="0" max="5000" title="延时(ms)" class="ui-input px-2 py-1 ui-num" />
            <div class="flex items-center gap-2">
              <label class="flex items-center gap-1 cursor-pointer">
                <input type="checkbox" v-model="newRule.append_modbus_crc16" class="accent-indigo-500" />
                <span>+CRC16</span>
              </label>
              <button @click="addAutoResponderRule" class="ui-btn-primary px-2.5 py-1 text-[11px]">+ 添加规则</button>
            </div>
          </div>

          <div class="max-h-28 overflow-y-auto space-y-1">
            <div
              v-for="r in (snapshot?.auto_rules || [])"
              :key="r.id"
              class="px-2 py-1.5 rounded-lg border flex items-center justify-between gap-2 text-[11px] ui-num bg-[var(--surface-glass-pill)]"
              style="border-color: var(--border-subtle);"
            >
              <div class="truncate">
                <span class="font-bold" style="color: var(--text-primary);">{{ r.name || '规则' }}</span>
                <span class="ml-1.5 text-sky-600 dark:text-sky-300">[{{ r.port_filter }} · {{ r.match_mode }}: {{ r.match_pattern }}]</span>
                <span class="ml-1.5">→ {{ r.response_payload }} {{ r.append_modbus_crc16 ? '+CRC' : '' }} ({{ r.delay_ms }}ms)</span>
                <span class="ml-1.5 text-emerald-600 dark:text-emerald-300">触发 {{ r.trigger_count }} 次</span>
              </div>
              <div class="flex items-center gap-1.5 shrink-0">
                <button @click="toggleAutoRule(r)" class="px-1.5 py-0.5 rounded border text-[10px] cursor-pointer" :class="r.enabled ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' : 'ui-pill'">
                  {{ r.enabled ? '已启用' : '已暂停' }}
                </button>
                <button @click="removeAutoRule(r.id)" class="text-rose-500 hover:underline text-[10px] cursor-pointer">删除</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ================================================================== -->
    <!-- 页签 2: USB 深度逆向、Endpoint 带宽与 USBPcap (.pcap) 互操作 -->
    <!-- ================================================================== -->
    <div v-else-if="activeTab === 'usb-dev'" class="space-y-3">
      <div class="flex items-center justify-between flex-wrap gap-2 text-xs">
        <div class="flex items-center gap-2 flex-wrap ui-num">
          <span class="px-2 py-0.5 rounded-full ui-pill">总 URB: <strong>{{ snapshot?.usb_total_urbs || 0 }}</strong></span>
          <span class="px-2 py-0.5 rounded-full bg-sky-500/12 text-sky-700 dark:text-sky-300">Control: {{ snapshot?.usb_control_urbs || 0 }}</span>
          <span class="px-2 py-0.5 rounded-full bg-indigo-500/12 text-indigo-700 dark:text-indigo-300">Bulk: {{ snapshot?.usb_bulk_urbs || 0 }}</span>
          <span class="px-2 py-0.5 rounded-full bg-emerald-500/12 text-emerald-700 dark:text-emerald-300">Interrupt: {{ snapshot?.usb_interrupt_urbs || 0 }}</span>
          <span class="px-2 py-0.5 rounded-full bg-amber-500/12 text-amber-700 dark:text-amber-300">Isoch: {{ snapshot?.usb_isochronous_urbs || 0 }}</span>
          <span class="px-2 py-0.5 rounded-full" :class="(snapshot?.usb_error_urbs || 0) > 0 ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 font-bold' : 'ui-pill'">
            USBD 异常: {{ snapshot?.usb_error_urbs || 0 }}
          </span>
        </div>

        <div class="flex items-center gap-2">
          <button
            @click="exportUsbPcap"
            :disabled="!snapshot || snapshot.usb_recent_urbs.length === 0"
            class="ui-btn-secondary px-2.5 py-1 text-[11px] flex items-center gap-1 disabled:opacity-45"
          >
            <AppIcon name="download" :size="12" />
            <span>导出 USBPcap (.pcap)</span>
          </button>
          <button @click="importUsbPcap" class="ui-btn-primary px-2.5 py-1 text-[11px] flex items-center gap-1">
            <AppIcon name="upload" :size="12" />
            <span>导入 .pcap 重放</span>
          </button>
        </div>
      </div>

      <!-- 双 ECharts USB 科研图形 -->
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-3">
        <div class="lg:col-span-5 ui-sub-card p-3 space-y-1.5">
          <div class="text-xs font-bold" style="color: var(--text-primary);">1. USB 传输类型分布占比 (Control / Bulk / Interrupt / Isoch)</div>
          <div class="h-44 w-full relative">
            <VChart v-if="snapshot && snapshot.usb_total_urbs > 0" :option="usbTransferPieOption" autoresize class="w-full h-full" />
            <div v-else class="w-full h-full flex items-center justify-center text-[11px]" style="color: var(--text-muted);">
              开启 USBPcap 捕获或导入 .pcap 抓包后自动绘出传输分布
            </div>
          </div>
        </div>

        <div class="lg:col-span-7 ui-sub-card p-3 space-y-1.5">
          <div class="text-xs font-bold" style="color: var(--text-primary);">2. 物理总线 Endpoint 端点 IN / OUT 吞吐分布 (Bytes)</div>
          <div class="h-44 w-full relative">
            <VChart v-if="snapshot && snapshot.usb_endpoints.length > 0" :option="usbEndpointBarOption" autoresize class="w-full h-full" />
            <div v-else class="w-full h-full flex items-center justify-center text-[11px]" style="color: var(--text-muted);">
              等待捕获端点读写流量
            </div>
          </div>
        </div>
      </div>

      <!-- 端点吞吐表 + Control Setup / CDC / HID / SCSI 解剖时间线 -->
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-3">
        <div class="lg:col-span-5 ui-sub-card p-3 space-y-2 text-xs">
          <div class="font-bold" style="color: var(--text-primary);">活跃 USB Endpoint 端点健康清单</div>
          <div class="max-h-48 overflow-y-auto border rounded-lg" style="border-color: var(--border-subtle);">
            <table class="w-full text-left border-collapse text-[11px] ui-num">
              <thead class="ui-table-head text-[10px] uppercase sticky top-0">
                <tr>
                  <th class="py-1.5 px-2">端点标识</th>
                  <th class="py-1.5 px-2">类型</th>
                  <th class="py-1.5 px-2">IN / OUT</th>
                  <th class="py-1.5 px-2">URB / 错</th>
                </tr>
              </thead>
              <tbody class="divide-y" style="border-color: var(--border-subtle); color: var(--text-secondary);">
                <tr v-for="ep in (snapshot?.usb_endpoints || [])" :key="ep.endpoint_key">
                  <td class="py-1 px-2 font-mono font-semibold" style="color: var(--text-primary);">{{ ep.endpoint_key }}</td>
                  <td class="py-1 px-2">{{ ep.transfer_type }}</td>
                  <td class="py-1 px-2">{{ ep.in_bytes }}B / {{ ep.out_bytes }}B</td>
                  <td class="py-1 px-2">
                    {{ ep.urb_count }} /
                    <span :class="ep.error_urb_count > 0 ? 'text-rose-500 font-bold' : ''">{{ ep.error_urb_count }}</span>
                  </td>
                </tr>
                <tr v-if="!snapshot || snapshot.usb_endpoints.length === 0">
                  <td colspan="4" class="py-5 text-center text-[11px]" style="color: var(--text-muted);">暂无活跃端点统计</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div class="lg:col-span-7 ui-sub-card p-3 space-y-2 text-xs">
          <div class="font-bold" style="color: var(--text-primary);">USB Control Setup / CDC-ACM / SCSI / HID 协议逆向流水</div>
          <div class="max-h-48 overflow-y-auto border rounded-lg" style="border-color: var(--border-subtle);">
            <table class="w-full text-left border-collapse text-[11px] ui-num">
              <thead class="ui-table-head text-[10px] uppercase sticky top-0">
                <tr>
                  <th class="py-1.5 px-2">时间</th>
                  <th class="py-1.5 px-2">端点 · 方向</th>
                  <th class="py-1.5 px-2">规约层</th>
                  <th class="py-1.5 px-2">深度解码语义</th>
                </tr>
              </thead>
              <tbody class="divide-y" style="border-color: var(--border-subtle); color: var(--text-secondary);">
                <tr v-for="u in (snapshot?.usb_recent_urbs || []).slice(0, 60)" :key="u.id" :class="u.is_error ? 'bg-rose-500/8' : ''">
                  <td class="py-1 px-2 whitespace-nowrap">{{ u.timestamp }}</td>
                  <td class="py-1 px-2 font-mono whitespace-nowrap">{{ u.endpoint_key }} {{ u.direction }}</td>
                  <td class="py-1 px-2 font-semibold" style="color: var(--text-primary);">{{ u.protocol }}</td>
                  <td class="py-1 px-2 truncate max-w-md" :title="u.summary">{{ u.summary }}</td>
                </tr>
                <tr v-if="!snapshot || snapshot.usb_recent_urbs.length === 0">
                  <td colspan="4" class="py-5 text-center text-[11px]" style="color: var(--text-muted);">暂无 URB 报文流</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- ================================================================== -->
    <!-- 页签 3: COM & USB 综合分析评估报告生成与原子导出 -->
    <!-- ================================================================== -->
    <div v-else-if="activeTab === 'report'" class="space-y-3 text-xs">
      <div class="flex items-center justify-between flex-wrap gap-2">
        <div style="color: var(--text-secondary);">
          自动汇集：在线 COM 串口、USB 拓扑外设、帧间时隙统计、Modbus RTU 寄存器矩阵、USB 端点吞吐及示波黄金波形智能对比评估。
        </div>
        <div class="flex items-center gap-2 flex-wrap">
          <button @click="generateInspectionReport" :disabled="reportBusy" class="ui-btn-primary px-3 py-1 text-[11px]">
            <AppIcon name="refresh" :size="12" :class="reportBusy ? 'animate-spin' : ''" />
            <span>{{ reportBusy ? '生成中...' : '生成综合分析报告' }}</span>
          </button>
          <button
            v-if="reportBundle"
            @click="exportInspectionReport('md')"
            class="ui-btn-secondary px-2.5 py-1 text-[11px] flex items-center gap-1"
          >
            <AppIcon name="download" :size="12" />
            <span>导出 Markdown (.md)</span>
          </button>
          <button
            v-if="reportBundle"
            @click="exportInspectionReport('html')"
            class="px-2.5 py-1 rounded-lg bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 text-[11px] font-semibold cursor-pointer flex items-center gap-1"
          >
            <AppIcon name="download" :size="12" />
            <span>导出 HTML 报告</span>
          </button>
        </div>
      </div>

      <div v-if="reportBundle" class="ui-sub-card p-3 space-y-2">
        <div class="flex items-center justify-between text-[11px] ui-num" style="color: var(--text-muted);">
          <span>报告生成时间戳: <strong style="color: var(--text-primary);">{{ reportBundle.generated_at }}</strong></span>
          <span>关联黄金波形对比: <strong>{{ latestWaveComparison ? latestWaveComparison.baseline_name : '尚未执行波形对比' }}</strong></span>
        </div>
        <pre class="p-3 rounded-lg ui-input font-mono text-[11px] max-h-64 overflow-auto custom-scrollbar whitespace-pre-wrap">{{ reportBundle.markdown }}</pre>
      </div>
      <div v-else class="ui-sub-card p-6 text-center text-[11px]" style="color: var(--text-muted);">
        点击右上方「生成综合分析报告」即可实时编译格式化的硬件总线监测与诊断报告，支持一键导出 `.md` 与自包含 `.html`。
      </div>
    </div>

    <!-- ================================================================== -->
    <!-- 页签 4: 单片机开发伴侣 (RTOS 行终端 / 固件分片下发 / MCU 外设速算) -->
    <!-- ================================================================== -->
    <div v-else-if="activeTab === 'mcu-studio'" class="space-y-3 text-xs">
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-3">
        <!-- 左: 嵌入式 RTOS ANSI 日志净化终端 & Crash/Panic 捕捉与导出 -->
        <div class="lg:col-span-6 ui-sub-card p-3 space-y-2">
          <div class="flex items-center justify-between flex-wrap gap-1.5">
            <span class="font-bold flex items-center gap-1.5" style="color: var(--text-primary);">
              <AppIcon name="activity" :size="13" />
              <span>RTOS 行式终端与 Panic/HardFault 捕获 (ANSI 净化)</span>
            </span>
            <div class="flex items-center gap-1.5 text-[10px] ui-num">
              <span class="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-700 dark:text-rose-300 font-bold">Panic: {{ mcuConsole?.panic_or_reboot_count || 0 }}</span>
              <span class="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 font-bold">Err: {{ mcuConsole?.error_count || 0 }}</span>
              <span class="px-1.5 py-0.5 rounded ui-pill">Warn: {{ mcuConsole?.warning_count || 0 }}</span>
            </div>
          </div>

          <div class="flex items-center gap-2 flex-wrap text-[11px]">
            <button @click="refreshMcuConsole" class="ui-btn-secondary px-2.5 py-1 text-[11px]">刷新串口控制台</button>
            <button @click="exportMcuSerialLog('txt')" :disabled="!mcuConsole || !mcuConsole.clean_text" class="ui-btn-secondary px-2.5 py-1 text-[11px] disabled:opacity-45">导出日志 (.txt)</button>
            <button @click="exportMcuSerialLog('hex')" :disabled="serialPackets.length === 0" class="ui-btn-secondary px-2.5 py-1 text-[11px] disabled:opacity-45">导出原始流 (.hex)</button>
          </div>

          <div class="max-h-40 overflow-y-auto rounded-lg border p-2 font-mono text-[11px] space-y-0.5 bg-slate-950 text-slate-200" style="border-color: var(--border-subtle);">
            <div
              v-for="(line, lIdx) in (mcuConsole?.clean_lines || []).slice(-120)"
              :key="lIdx"
              :class="line.toUpperCase().includes('HARDFAULT') || line.toUpperCase().includes('PANIC') || line.toUpperCase().includes('GURU') ? 'text-rose-400 font-bold' : line.toUpperCase().includes('ERROR') ? 'text-amber-300' : ''"
            >
              {{ line }}
            </div>
            <div v-if="!mcuConsole || mcuConsole.clean_lines.length === 0" class="text-slate-400 py-4 text-center">
              暂无串口文本流（接收串口打印后自动剥离 ESC[..m 转义码并按行高亮显示异常日志）
            </div>
          </div>

          <!-- 固件 / 测试二进制 .bin 分片传输助手 -->
          <div class="pt-2 border-t space-y-1.5" style="border-color: var(--border-subtle);">
            <div class="flex items-center justify-between">
              <span class="font-bold" style="color: var(--text-primary);">二进制 .bin 固件分片传输助手 (Bootloader/Flash)</span>
              <span class="text-[10px] ui-num" style="color: var(--text-muted);">{{ selectedSerialPort || '未选串口' }} @ {{ selectedBaudRate }}</span>
            </div>
            <div class="flex items-center gap-2 flex-wrap text-[11px]">
              <label class="flex items-center gap-1">
                <span>分片(B):</span>
                <input type="number" v-model.number="binChunkSize" min="16" max="4096" class="ui-input w-16 px-1.5 py-0.5 ui-num" />
              </label>
              <label class="flex items-center gap-1">
                <span>间隔(ms):</span>
                <input type="number" v-model.number="binChunkDelayMs" min="0" max="2000" class="ui-input w-14 px-1.5 py-0.5 ui-num" />
              </label>
              <button
                @click="runSendBinFile"
                :disabled="binTxBusy || !selectedSerialPort"
                class="ui-btn-primary px-2.5 py-1 text-[11px] disabled:opacity-45"
              >
                {{ binTxBusy ? '分片传输中...' : '选 .bin 文件并分片下发' }}
              </button>
            </div>
            <div v-if="binTxRes" class="text-[10px] ui-num text-emerald-700 dark:text-emerald-300 font-mono">
              {{ binTxRes.message }}
            </div>
          </div>
        </div>

        <!-- 右: MCU 工程师硬件算表工具箱 (Timer PSC/ARR + UART误差 + 4端序浮点 + 8-bit Bitmask) -->
        <div class="lg:col-span-6 ui-sub-card p-3 space-y-2.5">
          <div class="font-bold flex items-center gap-1.5" style="color: var(--text-primary);">
            <AppIcon name="cpu" :size="13" />
            <span>MCU 硬件配置与字节序速算工具箱</span>
          </div>

          <!-- 1. Timer / PWM 最优 (PSC, ARR) 求解 -->
          <div class="p-2 rounded-lg border space-y-1.5 bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
            <div class="flex items-center justify-between gap-2 text-[11px] flex-wrap">
              <span class="font-bold">1. Timer/PWM 最优分频 (PSC, ARR)</span>
              <div class="flex items-center gap-1.5">
                <input type="number" v-model.number="timerClkMhz" step="1" title="主频 MHz" class="ui-input w-16 px-1.5 py-0.5 ui-num" />
                <span>MHz →</span>
                <input type="number" v-model.number="timerTargetHz" step="100" title="目标 Hz" class="ui-input w-20 px-1.5 py-0.5 ui-num" />
                <span>Hz</span>
                <label class="flex items-center gap-1 cursor-pointer"><input type="checkbox" v-model="timerIs32Bit" class="accent-sky-500" />32b</label>
                <button @click="solveTimerParams" class="ui-btn-secondary px-2 py-0.5">求解</button>
              </div>
            </div>
            <div v-if="timerSolutions.length > 0" class="grid grid-cols-1 sm:grid-cols-2 gap-1 text-[10px] ui-num font-mono">
              <div v-for="(s, idx) in timerSolutions.slice(0, 4)" :key="idx" class="px-2 py-0.5 rounded border" style="border-color: var(--border-subtle);">
                PSC={{ s.psc }} · ARR={{ s.arr }} → {{ s.actual_freq_hz }}Hz (误差 {{ s.error_ppm }}ppm · {{ s.duty_resolution_bits }}b PWM)
              </div>
            </div>
          </div>

          <!-- 2. UART 波特率时钟误差验证 -->
          <div class="p-2 rounded-lg border space-y-1 bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
            <div class="flex items-center justify-between gap-2 text-[11px] flex-wrap">
              <span class="font-bold">2. UART 时钟误差 (±2% 容限)</span>
              <div class="flex items-center gap-1.5">
                <input type="number" v-model.number="uartApbMhz" step="1" class="ui-input w-14 px-1.5 py-0.5 ui-num" />MHz ·
                <input type="number" v-model.number="uartTestBaud" class="ui-input w-20 px-1.5 py-0.5 ui-num" />bps
                <button @click="verifyUartBaud" class="ui-btn-secondary px-2 py-0.5">核验</button>
              </div>
            </div>
            <div v-if="uartBaudRes" class="text-[10px] ui-num font-mono" :class="uartBaudRes.within_spec ? 'text-emerald-600 dark:text-emerald-300' : 'text-rose-500 font-bold'">
              {{ uartBaudRes.diagnostic }}
            </div>
          </div>

          <!-- 3. 32-bit 4 字节端序互译 & 8-bit 寄存器位域 Bitmask 解析 -->
          <div class="p-2 rounded-lg border space-y-1.5 bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
            <div class="flex items-center justify-between gap-2 text-[11px] flex-wrap">
              <span class="font-bold">3. 四端序 32-bit 解析 &amp; Bit7..0 位灯</span>
              <div class="flex items-center gap-1.5">
                <input v-model="wordHexInput" placeholder="42 28 00 00" class="ui-input w-28 px-1.5 py-0.5 font-mono" />
                <button @click="decodeWordEndian" class="ui-btn-secondary px-2 py-0.5">解析</button>
                <input v-model="byteMaskHex" placeholder="A5" title="单字节 Bitmask" class="ui-input w-12 px-1.5 py-0.5 font-mono text-center" />
              </div>
            </div>
            <div v-if="wordEndians.length > 0" class="grid grid-cols-2 gap-1 text-[10px] ui-num font-mono">
              <div v-for="w in wordEndians" :key="w.order_name" class="px-1.5 py-0.5 rounded border truncate" style="border-color: var(--border-subtle);" :title="`Int32=${w.int32}, Uint32=${w.uint32}`">
                <strong>{{ w.order_name.slice(0, 4) }}</strong>: Float={{ w.float32 }} | I32={{ w.int32 }}
              </div>
            </div>
            <div class="flex items-center gap-1 text-[10px] font-mono">
              <span style="color: var(--text-muted);">Bit(0x{{ parsedMaskByte.toString(16).padStart(2, '0').toUpperCase() }}):</span>
              <span
                v-for="bitIdx in [7, 6, 5, 4, 3, 2, 1, 0]"
                :key="bitIdx"
                :class="['px-1.5 py-0.2 rounded border', ((parsedMaskByte >> bitIdx) & 1) === 1 ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-500/40 font-bold' : 'opacity-45']"
              >
                b{{ bitIdx }}={{ (parsedMaskByte >> bitIdx) & 1 }}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { use } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { BarChart, PieChart } from 'echarts/charts';
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components';
import VChart from 'vue-echarts';
import AppIcon from './AppIcon.vue';
import type { SmartWaveformComparisonResult, OscilloscopePacketItem } from './PhysicalBusOscilloscope.vue';

use([CanvasRenderer, BarChart, PieChart, GridComponent, TooltipComponent, LegendComponent]);

const props = defineProps<{
  serialPorts: string[];
  selectedSerialPort: string;
  selectedBaudRate: number;
  packets: OscilloscopePacketItem[];
  latestWaveComparison: SmartWaveformComparisonResult | null;
}>();

defineEmits<{
  (e: 'fillSerialPayload', payloadHex: string, isHex: boolean): void;
  (e: 'close'): void;
}>();

const panelTabs = [
  { id: 'com-dev', label: 'COM 辅助开发 / Modbus 矩阵', icon: 'cpu' },
  { id: 'mcu-studio', label: '单片机开发伴侣 (终端/烧录/速算)', icon: 'zap' },
  { id: 'usb-dev', label: 'USB 逆向与端点画像', icon: 'layers' },
  { id: 'report', label: '巡检报告工坊', icon: 'database' },
] as const;

const activeTab = ref<'com-dev' | 'mcu-studio' | 'usb-dev' | 'report'>('com-dev');
const statusNotice = ref('');

interface SerialPortGapMetrics {
  port_name: string;
  total_rx_frames: number;
  total_rx_bytes: number;
  modbus_crc_errors: number;
  last_gap_ms: number;
  avg_gap_ms: number;
  min_gap_ms: number;
  max_gap_ms: number;
  gap_histogram: number[];
}

interface ModbusRegisterCell {
  key: string;
  port_name: string;
  slave_id: number;
  function_code: number;
  register_addr: number;
  raw_u16: number;
  signed_i16: number;
  hex_value: string;
  prev_u16: number | null;
  trend: string;
  update_count: number;
  last_updated_at: string;
}

interface SerialAutoResponderRule {
  id: string;
  name: string;
  enabled: boolean;
  port_filter: string;
  match_mode: string;
  match_pattern: string;
  response_payload: string;
  response_is_hex: boolean;
  append_modbus_crc16: boolean;
  delay_ms: number;
  trigger_count: number;
  last_triggered_at?: string | null;
}

interface SerialPeriodicTxStatus {
  running: boolean;
  port_name: string;
  baud_rate: number;
  interval_ms: number;
  sent_count: number;
  max_iterations: number;
}

interface UsbEndpointStats {
  endpoint_key: string;
  bus: number;
  device_addr: number;
  endpoint: number;
  transfer_type: string;
  in_bytes: number;
  out_bytes: number;
  urb_count: number;
  error_urb_count: number;
  last_usbd_status: string;
  last_protocol: string;
  last_seen: string;
}

interface UsbUrbEventItem {
  id: number;
  timestamp: string;
  controller: string;
  endpoint_key: string;
  transfer_type: string;
  direction: string;
  protocol: string;
  payload_len: number;
  usbd_status: string;
  is_error: boolean;
  summary: string;
}

interface BusIntelligenceSnapshot {
  serial_gap_metrics: SerialPortGapMetrics[];
  modbus_registers: ModbusRegisterCell[];
  auto_rules: SerialAutoResponderRule[];
  periodic_tx: SerialPeriodicTxStatus;
  usb_total_urbs: number;
  usb_total_bytes: number;
  usb_control_urbs: number;
  usb_bulk_urbs: number;
  usb_interrupt_urbs: number;
  usb_isochronous_urbs: number;
  usb_error_urbs: number;
  usb_pnp_attach_count: number;
  usb_pnp_detach_count: number;
  usb_endpoints: UsbEndpointStats[];
  usb_recent_urbs: UsbUrbEventItem[];
}

interface SerialChecksumOutcome {
  algorithm: string;
  checksum_hex: string;
  combined_frame_hex: string;
  byte_length: number;
}

interface UsbPcapImportResult {
  cancelled: boolean;
  imported_urbs: number;
  diagnostic_message: string;
}

interface BusInspectionReportBundle {
  generated_at: string;
  markdown: string;
  html: string;
}

interface NativeSaveOutcome {
  saved: boolean;
  cancelled: boolean;
  path: string | null;
  bytes_written: number;
  message: string;
}

const snapshot = ref<BusIntelligenceSnapshot | null>(null);
const isDarkTheme = ref(
  typeof document !== 'undefined' ? !document.documentElement.classList.contains('theme-apple-light') : true
);

// 校验计算器 + 周期发射台
const chkAlgo = ref('MODBUS_CRC16');
const chkPayload = ref('01 03 00 00 00 02');
const chkIsHex = ref(true);
const chkResult = ref<SerialChecksumOutcome | null>(null);
const periodicIntervalMs = ref(500);
const periodicMaxIter = ref(0);
const periodicAppendCrc = ref(true);

// 自动应答规则输入
const newRule = ref({
  name: '从站仿真应答',
  port_filter: 'ALL',
  match_mode: 'HEX_PREFIX',
  match_pattern: '01 03',
  response_payload: '01 03 02 00 64',
  response_is_hex: true,
  append_modbus_crc16: true,
  delay_ms: 10,
});

// 巡检报告
const reportBundle = ref<BusInspectionReportBundle | null>(null);
const reportBusy = ref(false);

const totalSerialCrcErrors = computed(() =>
  (snapshot.value?.serial_gap_metrics || []).reduce((acc, m) => acc + m.modbus_crc_errors, 0)
);

const chartTokens = computed(() => ({
  textPrimary: isDarkTheme.value ? '#e2e8f0' : '#0f172a',
  textMuted: isDarkTheme.value ? '#94a3b8' : '#64748b',
  splitLine: isDarkTheme.value ? 'rgba(148,163,184,0.14)' : 'rgba(15,23,42,0.10)',
  tooltipBg: isDarkTheme.value ? 'rgba(15,23,42,0.94)' : 'rgba(255,255,255,0.96)',
}));

const serialGapEchartOption = computed(() => {
  const t = chartTokens.value;
  const agg = [0, 0, 0, 0, 0];
  for (const m of snapshot.value?.serial_gap_metrics || []) {
    for (let i = 0; i < 5; i++) {
      agg[i] += m.gap_histogram[i] || 0;
    }
  }
  const colors = ['#f43f5e', '#38bdf8', '#10b981', '#6366f1', '#94a3b8'];
  return {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis', backgroundColor: t.tooltipBg, textStyle: { color: t.textPrimary, fontSize: 11 } },
    grid: { left: 36, right: 12, top: 18, bottom: 26 },
    xAxis: {
      type: 'category',
      data: ['<5ms 粘连风险', '5~20ms', '20~100ms', '100~500ms', '>500ms'],
      axisLabel: { color: t.textMuted, fontSize: 9, interval: 0 },
      axisLine: { lineStyle: { color: t.splitLine } },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: t.textMuted, fontSize: 9 },
      splitLine: { lineStyle: { color: t.splitLine, type: 'dashed' } },
    },
    series: [
      {
        name: '到达帧数',
        type: 'bar',
        barWidth: '46%',
        data: agg.map((v, idx) => ({
          value: v,
          itemStyle: { color: colors[idx], borderRadius: [4, 4, 0, 0] },
        })),
      },
    ],
  };
});

const usbTransferPieOption = computed(() => {
  const t = chartTokens.value;
  const s = snapshot.value;
  const data = [
    { name: 'Control', value: s?.usb_control_urbs || 0 },
    { name: 'Bulk', value: s?.usb_bulk_urbs || 0 },
    { name: 'Interrupt', value: s?.usb_interrupt_urbs || 0 },
    { name: 'Isochronous', value: s?.usb_isochronous_urbs || 0 },
  ].filter(d => d.value > 0);
  return {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item', backgroundColor: t.tooltipBg, textStyle: { color: t.textPrimary, fontSize: 11 }, formatter: '{b}: {c} ({d}%)' },
    legend: { orient: 'vertical', right: 4, top: 'middle', textStyle: { color: t.textMuted, fontSize: 10 } },
    series: [
      {
        type: 'pie',
        radius: ['42%', '72%'],
        center: ['36%', '50%'],
        label: { show: false },
        data,
      },
    ],
  };
});

const usbEndpointBarOption = computed(() => {
  const t = chartTokens.value;
  const eps = (snapshot.value?.usb_endpoints || []).slice(0, 8);
  return {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis', backgroundColor: t.tooltipBg, textStyle: { color: t.textPrimary, fontSize: 11 } },
    legend: { top: 0, textStyle: { color: t.textMuted, fontSize: 10 } },
    grid: { left: 48, right: 12, top: 26, bottom: 26 },
    xAxis: {
      type: 'category',
      data: eps.map(e => e.endpoint_key.replace(/^Bus\d+:/, '')),
      axisLabel: { color: t.textMuted, fontSize: 9 },
      axisLine: { lineStyle: { color: t.splitLine } },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: t.textMuted, fontSize: 9 },
      splitLine: { lineStyle: { color: t.splitLine, type: 'dashed' } },
    },
    series: [
      { name: 'IN (Bytes)', type: 'bar', data: eps.map(e => e.in_bytes), itemStyle: { color: '#38bdf8', borderRadius: [3, 3, 0, 0] } },
      { name: 'OUT (Bytes)', type: 'bar', data: eps.map(e => e.out_bytes), itemStyle: { color: '#a78bfa', borderRadius: [3, 3, 0, 0] } },
    ],
  };
});

async function refreshSnapshot() {
  try {
    snapshot.value = await invoke<BusIntelligenceSnapshot>('get_bus_intelligence_snapshot_cmd');
  } catch (e) {
    console.error('获取总线智能统计快照失败:', e);
  }
}

async function runComputeChecksum() {
  try {
    chkResult.value = await invoke<SerialChecksumOutcome>('compute_serial_checksum_cmd', {
      algorithm: chkAlgo.value,
      payload: chkPayload.value,
      isHex: chkIsHex.value,
    });
    statusNotice.value = `校验构造成功 (${chkResult.value.algorithm}): ${chkResult.value.checksum_hex}`;
  } catch (e) {
    statusNotice.value = `校验计算受阻: ${String(e)}`;
  }
}

async function startPeriodicTx() {
  if (!props.selectedSerialPort) return;
  try {
    const res = await invoke<SerialPeriodicTxStatus>('start_serial_periodic_tx_cmd', {
      portName: props.selectedSerialPort,
      baudRate: props.selectedBaudRate || 115200,
      payloadStr: chkPayload.value,
      isHex: chkIsHex.value,
      appendModbusCrc16: periodicAppendCrc.value,
      intervalMs: periodicIntervalMs.value,
      maxIterations: periodicMaxIter.value,
    });
    statusNotice.value = `已启动定时发送: ${res.port_name} @ ${res.interval_ms}ms`;
    await refreshSnapshot();
  } catch (e) {
    statusNotice.value = `启动定时发射失败: ${String(e)}`;
  }
}

async function stopPeriodicTx() {
  try {
    const res = await invoke<SerialPeriodicTxStatus>('stop_serial_periodic_tx_cmd');
    statusNotice.value = `已停止定时发射 (累计发送 ${res.sent_count} 帧)`;
    await refreshSnapshot();
  } catch (e) {
    statusNotice.value = `停止定时发射异常: ${String(e)}`;
  }
}

async function addAutoResponderRule() {
  try {
    await invoke<SerialAutoResponderRule[]>('upsert_serial_auto_rule_cmd', {
      rule: {
        id: '',
        name: newRule.value.name,
        enabled: true,
        port_filter: newRule.value.port_filter,
        match_mode: newRule.value.match_mode,
        match_pattern: newRule.value.match_pattern,
        response_payload: newRule.value.response_payload,
        response_is_hex: newRule.value.response_is_hex,
        append_modbus_crc16: newRule.value.append_modbus_crc16,
        delay_ms: newRule.value.delay_ms,
        trigger_count: 0,
      },
    });
    statusNotice.value = `已生效自动应答规则: ${newRule.value.name}`;
    await refreshSnapshot();
  } catch (e) {
    statusNotice.value = `添加自动规则失败: ${String(e)}`;
  }
}

async function toggleAutoRule(r: SerialAutoResponderRule) {
  try {
    await invoke('upsert_serial_auto_rule_cmd', {
      rule: { ...r, enabled: !r.enabled },
    });
    await refreshSnapshot();
  } catch (e) {
    statusNotice.value = `更新规则状态失败: ${String(e)}`;
  }
}

async function removeAutoRule(ruleId: string) {
  try {
    await invoke('delete_serial_auto_rule_cmd', { ruleId });
    await refreshSnapshot();
  } catch (e) {
    statusNotice.value = `删除规则失败: ${String(e)}`;
  }
}

async function exportUsbPcap() {
  try {
    const res = await invoke<NativeSaveOutcome>('export_usb_usbpcap_pcap_cmd');
    statusNotice.value = res.message;
  } catch (e) {
    statusNotice.value = `导出 .pcap 失败: ${String(e)}`;
  }
}

async function importUsbPcap() {
  try {
    const res = await invoke<UsbPcapImportResult>('pick_and_import_usb_pcap_cmd');
    statusNotice.value = res.diagnostic_message;
    if (!res.cancelled) {
      await refreshSnapshot();
    }
  } catch (e) {
    statusNotice.value = `导入 .pcap 失败: ${String(e)}`;
  }
}

async function generateInspectionReport() {
  reportBusy.value = true;
  try {
    reportBundle.value = await invoke<BusInspectionReportBundle>('generate_bus_inspection_report_cmd', {
      waveCompare: props.latestWaveComparison,
    });
    statusNotice.value = `巡检综合报告已生成 (${reportBundle.value.generated_at})`;
  } catch (e) {
    statusNotice.value = `生成报告异常: ${String(e)}`;
  } finally {
    reportBusy.value = false;
  }
}

async function exportInspectionReport(format: 'md' | 'html') {
  if (!reportBundle.value) return;
  try {
    const content = format === 'html' ? reportBundle.value.html : reportBundle.value.markdown;
    const outcome = await invoke<NativeSaveOutcome>('export_bus_inspection_report_cmd', {
      format,
      content,
    });
    statusNotice.value = outcome.message;
  } catch (e) {
    statusNotice.value = `导出报告失败: ${String(e)}`;
  }
}

// --- MCU 单片机开发伴侣状态与交互 ---
interface McuConsoleLogAnalysis {
  clean_lines: string[];
  clean_text: string;
  error_count: number;
  warning_count: number;
  panic_or_reboot_count: number;
  critical_alerts: string[];
}

interface SerialBinFileTransferResult {
  cancelled: boolean;
  bytes_sent: number;
  chunks_sent: number;
  crc32_hex: string;
  message: string;
}

interface McuTimerSolution {
  psc: number;
  arr: number;
  actual_freq_hz: number;
  error_ppm: number;
  duty_resolution_bits: number;
}

interface UartBaudCalcResult {
  within_spec: boolean;
  diagnostic: string;
}

interface ModbusWordEndianView {
  order_name: string;
  raw_hex: string;
  float32: string;
  int32: number;
  uint32: number;
}

const mcuConsole = ref<McuConsoleLogAnalysis | null>(null);
const binChunkSize = ref(256);
const binChunkDelayMs = ref(15);
const binTxBusy = ref(false);
const binTxRes = ref<SerialBinFileTransferResult | null>(null);
const timerClkMhz = ref(72);
const timerTargetHz = ref(20000);
const timerIs32Bit = ref(false);
const timerSolutions = ref<McuTimerSolution[]>([]);
const uartApbMhz = ref(72);
const uartTestBaud = ref(115200);
const uartBaudRes = ref<UartBaudCalcResult | null>(null);
const wordHexInput = ref('42 28 00 00');
const wordEndians = ref<ModbusWordEndianView[]>([]);
const byteMaskHex = ref('A5');

const serialPackets = computed(() =>
  (props.packets || []).filter(p => (p.transport || '').toUpperCase() === 'SERIAL' || (p.direction || '').toUpperCase().startsWith('SERIAL'))
);

const parsedMaskByte = computed(() => {
  const clean = byteMaskHex.value.replace(/[^0-9a-fA-F]/g, '').slice(0, 2);
  const v = Number.parseInt(clean || '0', 16);
  return Number.isNaN(v) ? 0 : (v & 0xFF);
});

async function refreshMcuConsole() {
  const chunks = serialPackets.value.slice(-150).map(p => p.raw_text || p.payload_hex || '').filter(Boolean);
  if (chunks.length === 0) return;
  try {
    mcuConsole.value = await invoke<McuConsoleLogAnalysis>('analyze_mcu_console_lines_cmd', { rawChunks: chunks });
  } catch (e) {
    console.error('MCU 日志解析异常:', e);
  }
}

async function exportMcuSerialLog(format: 'txt' | 'hex') {
  const content = format === 'hex'
    ? serialPackets.value.map(p => `[${p.timestamp}] ${p.direction || 'RX'}: ${p.payload_hex}`).join('\n')
    : (mcuConsole.value?.clean_text || '');
  if (!content) return;
  try {
    const res = await invoke<NativeSaveOutcome>('export_serial_stream_log_cmd', { format, content });
    statusNotice.value = res.message;
  } catch (e) {
    statusNotice.value = `导出串口记录失败: ${String(e)}`;
  }
}

async function runSendBinFile() {
  if (!props.selectedSerialPort) return;
  binTxBusy.value = true;
  try {
    binTxRes.value = await invoke<SerialBinFileTransferResult>('pick_and_send_serial_bin_file_cmd', {
      portName: props.selectedSerialPort,
      baudRate: props.selectedBaudRate || 115200,
      chunkSize: binChunkSize.value || 256,
      interChunkMs: binChunkDelayMs.value ?? 15,
    });
    statusNotice.value = binTxRes.value.message;
  } catch (e) {
    statusNotice.value = `固件下发受阻: ${String(e)}`;
  } finally {
    binTxBusy.value = false;
  }
}

async function solveTimerParams() {
  try {
    timerSolutions.value = await invoke<McuTimerSolution[]>('solve_mcu_timer_psc_arr_cmd', {
      timerClkHz: Math.round((timerClkMhz.value || 72) * 1_000_000),
      targetFreqHz: timerTargetHz.value || 1000,
      is32bit: timerIs32Bit.value,
    });
  } catch (e) {
    statusNotice.value = `定时器求解失败: ${String(e)}`;
  }
}

async function verifyUartBaud() {
  try {
    uartBaudRes.value = await invoke<UartBaudCalcResult>('calc_uart_baud_error_cmd', {
      apbClkHz: Math.round((uartApbMhz.value || 72) * 1_000_000),
      targetBaud: uartTestBaud.value || 115200,
      oversampling: 16,
    });
  } catch (e) {
    statusNotice.value = `波特率核验受阻: ${String(e)}`;
  }
}

async function decodeWordEndian() {
  try {
    wordEndians.value = await invoke<ModbusWordEndianView[]>('decode_modbus_32bit_word_cmd', { rawHex: wordHexInput.value });
  } catch (e) {
    statusNotice.value = `端序解析失败: ${String(e)}`;
  }
}

let pollTimer: number | null = null;
let themeObserver: MutationObserver | null = null;

onMounted(() => {
  if (typeof document !== 'undefined') {
    const syncTheme = () => {
      isDarkTheme.value = !document.documentElement.classList.contains('theme-apple-light');
    };
    syncTheme();
    themeObserver = new MutationObserver(syncTheme);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
  }
  refreshSnapshot();
  refreshMcuConsole();
  solveTimerParams();
  verifyUartBaud();
  decodeWordEndian();
  pollTimer = window.setInterval(() => {
    refreshSnapshot();
    if (activeTab.value === 'mcu-studio') refreshMcuConsole();
  }, 1800);
});

onUnmounted(() => {
  if (themeObserver) {
    themeObserver.disconnect();
    themeObserver = null;
  }
  if (pollTimer) clearInterval(pollTimer);
});
</script>
