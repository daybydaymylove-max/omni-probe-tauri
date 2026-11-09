<template>
  <div class="flex-1 flex flex-col gap-2.5 overflow-hidden min-w-0 font-sans text-slate-200">
    
    <!-- 1. 顶部状态栏与物理总线控制中枢 (深色全息玻璃控制台) -->
    <header class="glass-surface backdrop-blur-2xl rounded-2xl border border-white/10 shadow-xl px-3.5 py-2 flex items-center justify-between shrink-0 gap-3 select-none">
      
      <!-- 1.1 左侧：核心标题与总线启停控制 -->
      <div class="flex items-center gap-3 shrink-0">
        <div class="flex items-center gap-2">
          <div class="w-6 h-6 rounded-lg bg-gradient-to-tr from-purple-500 to-indigo-600 flex items-center justify-center shadow-md shadow-purple-500/20 shrink-0">
            <svg class="w-3.5 h-3.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/>
            </svg>
          </div>
          <h2 class="text-xs font-bold text-white tracking-tight whitespace-nowrap">
            物理外设画像与端口出入中心
          </h2>
        </div>

        <div class="h-4 w-px bg-white/10 shrink-0"></div>

        <!-- USB 总线嗅探启停控制 -->
        <div class="flex items-center gap-1.5 text-xs whitespace-nowrap shrink-0">
          <span class="text-[11px] text-slate-400 font-medium">USB总线:</span>
          <button v-if="!isUsbRunning" @click="$emit('startUsbCapture')"
            class="bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-[11px] px-2.5 py-1 rounded-xl font-bold transition-all flex items-center gap-1 cursor-pointer shadow-md shadow-purple-600/20 active:scale-95 whitespace-nowrap shrink-0">
            <svg class="w-3 h-3 fill-current text-purple-200 shrink-0" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
            <span>挂钩 USB 总线</span>
          </button>
          <button v-else @click="$emit('stopUsbCapture')"
            class="bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/40 text-[11px] px-2.5 py-1 rounded-xl font-bold transition-all flex items-center gap-1.5 cursor-pointer active:scale-95 whitespace-nowrap shrink-0">
            <span class="w-2 h-2 rounded-full bg-purple-400 animate-pulse"></span>
            <span>停止 USB 嗅探</span>
          </button>
        </div>

        <div class="h-4 w-px bg-white/10 shrink-0"></div>

        <!-- 物理串口嗅探启停控制 -->
        <div class="flex items-center gap-1.5 text-xs whitespace-nowrap shrink-0">
          <span class="text-[11px] text-slate-400 font-medium">串口总线:</span>
          <button v-if="!isSerialRunning" @click="$emit('startSerialCapture', selectedSerial, serialBaudRate)" :disabled="!selectedSerial"
            class="bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white text-[11px] px-2.5 py-1 rounded-xl font-bold transition-all flex items-center gap-1 cursor-pointer disabled:opacity-40 shadow-md shadow-indigo-600/20 active:scale-95 whitespace-nowrap shrink-0">
            <svg class="w-3 h-3 fill-current text-indigo-200 shrink-0" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
            <span>监听串口</span>
          </button>
          <button v-else @click="$emit('stopSerialCapture')"
            class="bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/40 text-[11px] px-2.5 py-1 rounded-xl font-bold transition-all flex items-center gap-1.5 cursor-pointer active:scale-95 whitespace-nowrap shrink-0">
            <span class="w-2 h-2 rounded-full bg-indigo-400 animate-pulse"></span>
            <span>停止串口监听</span>
          </button>
        </div>
      </div>

      <!-- 1.2 中间与右侧：状态指示胶囊与高级工具组 (横向自适应、强制绝不折行) -->
      <div class="flex items-center gap-1.5 text-xs font-mono overflow-x-auto custom-scrollbar-x py-0.5 shrink min-w-0">
        
        <!-- 核心计数指标胶囊 -->
        <div class="bg-purple-500/10 text-purple-300 border border-purple-500/25 px-2 py-0.5 rounded-lg whitespace-nowrap shrink-0 font-bold flex items-center gap-1">
          <span class="text-[10px] text-purple-400/80 font-sans">USB设备</span>
          <span class="text-xs text-white">{{ usbDevices.length }}</span>
        </div>
        <div class="bg-indigo-500/10 text-indigo-300 border border-indigo-500/25 px-2 py-0.5 rounded-lg whitespace-nowrap shrink-0 font-bold flex items-center gap-1">
          <span class="text-[10px] text-indigo-400/80 font-sans">串口/CDC</span>
          <span class="text-xs text-white">{{ usbSerialCount }}</span>
        </div>
        <div class="bg-emerald-500/10 text-emerald-300 border border-emerald-500/25 px-2 py-0.5 rounded-lg whitespace-nowrap shrink-0 font-bold flex items-center gap-1">
          <span class="text-[10px] text-emerald-400/80 font-sans">出入留痕</span>
          <span class="text-xs text-white">{{ transceiveHistory.length }}</span>
        </div>

        <div class="h-3.5 w-px bg-white/10 shrink-0 mx-0.5"></div>

        <!-- 串口高级参数入口 -->
        <button @click="isSerialConfigOpen = true"
          class="bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white border border-white/10 text-[11px] px-2 py-0.5 rounded-lg font-medium shadow-2xs transition-all flex items-center gap-1 cursor-pointer active:scale-95 whitespace-nowrap shrink-0">
          <span>📟 串口高级参数</span>
        </button>

        <!-- Modem 引脚电平控制 -->
        <button @click="showModemPins = !showModemPins"
          :class="['text-[11px] px-2 py-0.5 rounded-lg font-medium shadow-2xs transition-all flex items-center gap-1 cursor-pointer active:scale-95 border whitespace-nowrap shrink-0',
            showModemPins ? 'bg-indigo-600 text-white border-indigo-500' : 'bg-white/5 hover:bg-white/10 text-indigo-300 border-indigo-500/30']">
          <span>💡 引脚电平</span>
        </button>

        <!-- 双串口中继 -->
        <button @click="isSerialBridgeOpen = true"
          class="bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white border border-white/10 text-[11px] px-2 py-0.5 rounded-lg font-medium shadow-2xs transition-all flex items-center gap-1 cursor-pointer active:scale-95 whitespace-nowrap shrink-0">
          <span>🔀 双串口中继</span>
        </button>

        <!-- USB 描述符树查看器 -->
        <button @click="isUsbDescriptorTreeOpen = true"
          class="bg-white/5 hover:bg-white/10 text-purple-300 hover:text-purple-200 border border-purple-500/30 text-[11px] px-2 py-0.5 rounded-lg font-medium shadow-2xs transition-all flex items-center gap-1 cursor-pointer active:scale-95 whitespace-nowrap shrink-0">
          <span>🌲 描述符树</span>
        </button>

        <!-- 跨总线因果看板 -->
        <button @click="isCrossBusCausalityOpen = true"
          class="bg-white/5 hover:bg-white/10 text-cyan-300 hover:text-cyan-200 border border-cyan-500/30 text-[11px] px-2 py-0.5 rounded-lg font-medium shadow-2xs transition-all flex items-center gap-1 cursor-pointer active:scale-95 whitespace-nowrap shrink-0">
          <span>⚡ 跨总线因果</span>
        </button>

        <!-- 硬件基线白名单与合规审计 -->
        <button @click="showComplianceWorkbench = !showComplianceWorkbench"
          :class="['text-[11px] px-2.5 py-0.5 rounded-lg font-bold shadow-sm transition-all flex items-center gap-1.5 cursor-pointer active:scale-95 border whitespace-nowrap shrink-0',
            showComplianceWorkbench ? 'bg-purple-600 text-white border-purple-500 shadow-purple-900/40' : 'bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border-purple-500/30']">
          <span>🛡️ 白名单审计</span>
          <span v-if="complianceReport" :class="['px-1.5 py-0.2 rounded text-[9px] font-mono font-bold',
            complianceReport.unauthorized_count > 0 ? 'bg-rose-500 text-white' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40']">
            {{ complianceReport.unauthorized_count > 0 ? `未授权:${complianceReport.unauthorized_count}` : `${complianceReport.compliance_rate.toFixed(0)}%` }}
          </span>
        </button>

        <!-- 刷新外设按钮 -->
        <button @click="$emit('refreshUsb')" title="重新扫描系统物理 USB 与 COM 串口"
          class="bg-white/5 hover:bg-white/15 text-slate-300 hover:text-white border border-white/10 px-2 py-0.5 rounded-lg font-sans font-semibold transition-all cursor-pointer shadow-2xs active:scale-95 whitespace-nowrap shrink-0">
          刷新外设
        </button>
      </div>
    </header>

    <!-- 2. 物理外设基线白名单与即插即用合规差分工作台 (展开抽屉) -->
    <section v-if="showComplianceWorkbench" class="glass-surface backdrop-blur-2xl rounded-2xl border border-purple-500/30 shadow-2xl p-3 flex flex-col gap-2.5 shrink-0">
      <div class="flex items-center justify-between border-b border-white/10 pb-2 flex-wrap gap-2">
        <div class="flex items-center gap-2">
          <span class="w-2 h-2 rounded-full bg-purple-400 animate-pulse"></span>
          <span class="text-xs font-bold text-purple-200">物理外设基线白名单固化与即插即用合规差分审计</span>
          <span class="text-[10px] text-slate-400 font-mono">
            对标 GB/T 22239 等保三级物理与环境安全接入控制
          </span>
        </div>

        <div class="flex items-center gap-2 text-xs">
          <button @click="doSaveCurrentAsWhitelist" :disabled="isSavingWhitelist"
            class="bg-purple-600 hover:bg-purple-500 text-white text-[11px] px-2.5 py-1 rounded-xl font-bold shadow-md transition-all flex items-center gap-1 cursor-pointer disabled:opacity-40 active:scale-95 whitespace-nowrap">
            <span v-if="isSavingWhitelist" class="animate-spin">⏳</span>
            <span v-else>🔒</span>
            <span>固化当前在线外设为基线白名单</span>
          </button>
          <button @click="doVerifyCompliance" :disabled="isAuditingCompliance"
            class="bg-indigo-600 hover:bg-indigo-500 text-white text-[11px] px-2.5 py-1 rounded-xl font-bold shadow-md transition-all flex items-center gap-1 cursor-pointer disabled:opacity-40 active:scale-95 whitespace-nowrap">
            <span v-if="isAuditingCompliance" class="animate-spin">⏳</span>
            <span v-else>🔍</span>
            <span>执行合规差分比对</span>
          </button>
          <button @click="doClearWhitelist" title="清空现有白名单"
            class="bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 px-2 py-1 rounded-xl font-bold transition-all cursor-pointer text-[11px] active:scale-95 whitespace-nowrap">
            清空白名单
          </button>
        </div>
      </div>

      <!-- 合规状态仪表看板 -->
      <div v-if="complianceReport" class="flex flex-col gap-2">
        <div class="grid grid-cols-2 md:grid-cols-5 gap-2 text-xs">
          <div class="bg-purple-500/10 border border-purple-500/20 p-2 rounded-xl">
            <div class="text-[9px] text-purple-400 font-bold uppercase">受信任基线 / 当前在线</div>
            <div class="text-sm font-bold text-purple-200 font-mono mt-0.5">{{ complianceReport.total_whitelist }} 基准 / {{ complianceReport.total_online }} 在线</div>
          </div>
          <div class="bg-emerald-500/10 border border-emerald-500/20 p-2 rounded-xl">
            <div class="text-[9px] text-emerald-400 font-bold uppercase">合规受控外设</div>
            <div class="text-sm font-bold text-emerald-300 font-mono mt-0.5">✓ {{ complianceReport.compliant_count }} 个</div>
          </div>
          <div class="bg-rose-500/10 border border-rose-500/20 p-2 rounded-xl">
            <div class="text-[9px] text-rose-400 font-bold uppercase">未授权非法外设</div>
            <div class="text-sm font-bold text-rose-300 font-mono mt-0.5">🚨 {{ complianceReport.unauthorized_count }} 个</div>
          </div>
          <div class="bg-amber-500/10 border border-amber-500/20 p-2 rounded-xl">
            <div class="text-[9px] text-amber-400 font-bold uppercase">基线设备离线缺失</div>
            <div class="text-sm font-bold text-amber-300 font-mono mt-0.5">⚠️ {{ complianceReport.missing_count }} 个</div>
          </div>
          <div class="bg-slate-800/60 border border-white/10 p-2 rounded-xl">
            <div class="text-[9px] text-slate-400 font-bold uppercase">物理安全合规率</div>
            <div :class="['text-sm font-bold font-mono mt-0.5', complianceReport.compliance_rate >= 100 ? 'text-emerald-400' : 'text-rose-400']">
              {{ complianceReport.compliance_rate.toFixed(1) }}%
            </div>
          </div>
        </div>

        <!-- 差异过滤与明细列表 -->
        <div class="flex items-center justify-between text-xs pt-1">
          <span class="font-bold text-slate-300 text-[11px]">硬件合规审计明细 ({{ filteredComplianceItems.length }} / {{ complianceReport.items.length }})</span>
          <div class="flex gap-1 text-[10px] font-bold">
            <button @click="whitelistFilter = 'ALL'"
              :class="['px-2 py-0.5 rounded-lg border transition-all cursor-pointer',
                whitelistFilter === 'ALL' ? 'bg-purple-600 text-white border-purple-500' : 'bg-white/5 text-slate-300 border-white/10']">
              全部 ({{ complianceReport.items.length }})
            </button>
            <button @click="whitelistFilter = 'UNAUTHORIZED'"
              :class="['px-2 py-0.5 rounded-lg border transition-all cursor-pointer',
                whitelistFilter === 'UNAUTHORIZED' ? 'bg-rose-600 text-white border-rose-500' : 'bg-white/5 text-rose-300 border-white/10']">
              未授权 ({{ complianceReport.unauthorized_count }})
            </button>
            <button @click="whitelistFilter = 'MISSING'"
              :class="['px-2 py-0.5 rounded-lg border transition-all cursor-pointer',
                whitelistFilter === 'MISSING' ? 'bg-amber-600 text-white border-amber-500' : 'bg-white/5 text-amber-300 border-white/10']">
              离线缺失 ({{ complianceReport.missing_count }})
            </button>
            <button @click="whitelistFilter = 'COMPLIANT'"
              :class="['px-2 py-0.5 rounded-lg border transition-all cursor-pointer',
                whitelistFilter === 'COMPLIANT' ? 'bg-emerald-600 text-white border-emerald-500' : 'bg-white/5 text-emerald-300 border-white/10']">
              合规受控 ({{ complianceReport.compliant_count }})
            </button>
          </div>
        </div>

        <!-- 明细表格 -->
        <div class="max-h-48 overflow-auto custom-scrollbar border border-white/10 rounded-xl bg-black/40">
          <table class="w-full text-left text-xs font-mono border-collapse table-fixed">
            <thead class="bg-white/5 border-b border-white/10 text-[10px] font-bold text-slate-400 uppercase sticky top-0 z-10 backdrop-blur-md">
              <tr>
                <th class="p-2 w-[12%]">总线类型</th>
                <th class="p-2 w-[24%]">硬件唯一标识 (VID/PID/COM)</th>
                <th class="p-2 w-[22%]">物理设备名称</th>
                <th class="p-2 w-[14%] text-center">合规状态</th>
                <th class="p-2 w-[28%]">合规审计结论与用途备注</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5 text-[11px]">
              <tr v-for="item in filteredComplianceItems" :key="item.identifier"
                :class="['hover:bg-white/[0.03] transition-colors',
                  item.status === 'UNAUTHORIZED' ? 'bg-rose-500/10' : '']">
                <td class="p-2 truncate font-bold">
                  <span :class="['px-1.5 py-0.2 rounded text-[9px]',
                    item.category === 'USB' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' : 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30']">
                    {{ item.category }}
                  </span>
                </td>
                <td class="p-2 font-bold text-slate-200 truncate" :title="item.identifier">{{ item.identifier }}</td>
                <td class="p-2 text-slate-300 truncate" :title="item.name">{{ item.name }}</td>
                <td class="p-2 text-center truncate">
                  <span :class="['px-2 py-0.5 rounded text-[9px] font-bold',
                    item.status === 'COMPLIANT' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' :
                    item.status === 'UNAUTHORIZED' ? 'bg-rose-600 text-white shadow-2xs' :
                    'bg-amber-500/20 text-amber-300 border border-amber-500/30']">
                    {{ item.status === 'COMPLIANT' ? '合规受控' : item.status === 'UNAUTHORIZED' ? '🚨 未授权外设' : '⚠️ 离线缺失' }}
                  </span>
                </td>
                <td class="p-2 truncate">
                  <div class="flex items-center gap-1.5 truncate" :title="item.alert_desc">
                    <span class="truncate text-[10px]" :class="item.status === 'UNAUTHORIZED' ? 'text-rose-400 font-semibold' : 'text-slate-400'">
                      {{ item.alert_desc }}
                    </span>
                    <span v-if="item.description" class="text-slate-500 text-[10px] shrink-0">({{ item.description }})</span>
                  </div>
                </td>
              </tr>
              <tr v-if="filteredComplianceItems.length === 0">
                <td colspan="5" class="p-6 text-center text-slate-500 text-xs">
                  暂无匹配的硬件审计项
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      <div v-else class="p-3 text-center text-slate-400 text-xs bg-black/30 rounded-xl border border-dashed border-white/10">
        尚未执行硬件合规比对。请点击【固化当前在线外设为基线白名单】建立受信任基准，或点击【执行合规差分比对】。
      </div>
    </section>

    <!-- Modem 硬件引脚状态与电平控制面板 (SerialModemPinsPanel) -->
    <SerialModemPinsPanel
      v-if="showModemPins"
      :serialPorts="serialPorts"
      :defaultPort="selectedSerial"
    />

    <!-- 3. 主体工作区：左栏 USB 设备与 PnP 实时流水 + 右栏 端口全双工双向出入执行器 -->
    <main class="flex-1 flex gap-2.5 overflow-hidden min-h-0">
      
      <!-- 3.1 左栏：物理 USB 画像与 PnP 实时审计流水线 (占比 50%) -->
      <div class="flex-1 flex flex-col gap-2.5 overflow-hidden min-w-0">
        
        <!-- 物理 USB 设备画像清单 -->
        <div class="flex-[3] glass-surface backdrop-blur-2xl rounded-2xl border border-white/10 shadow-xl flex flex-col overflow-hidden min-h-0">
          <div class="px-3.5 py-2 border-b border-white/10 bg-white/[0.02] flex items-center justify-between text-xs font-bold text-slate-200 shrink-0">
            <div class="flex items-center gap-2">
              <span class="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
              <span>物理 USB 设备画像清单</span>
              <span class="text-[10px] font-mono text-purple-400/80 bg-purple-500/10 px-1.5 py-0.2 rounded border border-purple-500/20">
                {{ filteredUsbDevices.length }} 活跃端点
              </span>
            </div>
            <div class="relative">
              <input v-model="usbFilter" placeholder="过滤设备名 / VID / PID / 类别"
                class="w-48 bg-black/50 border border-white/10 rounded-xl px-2.5 py-1 text-[11px] font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-purple-500/60 focus:ring-1 focus:ring-purple-500/30 transition-all">
            </div>
          </div>

          <div class="flex-1 overflow-auto custom-scrollbar p-2.5 space-y-2">
            <div v-for="dev in filteredUsbDevices" :key="dev.instance_id"
              class="bg-[#121824]/90 border border-white/5 hover:border-purple-500/40 p-2.5 rounded-xl flex flex-col gap-1.5 text-xs transition-all shadow-sm group">
              <div class="flex items-center justify-between gap-2">
                <span class="font-bold text-slate-100 truncate flex-1 group-hover:text-purple-300 transition-colors" :title="dev.device_name">
                  {{ dev.device_name }}
                </span>
                <div class="flex items-center gap-1.5 shrink-0">
                  <button @click="openUsbDescriptorTree(dev)" title="解析并展开此设备的四级标准描述符树"
                    class="text-[9px] font-bold text-purple-300 bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/30 px-1.5 py-0.5 rounded-md cursor-pointer transition-colors shadow-2xs">
                    🌲 描述符
                  </button>
                  <!-- 设备类别彩色徽章 -->
                  <span :class="['text-[9px] font-bold px-2 py-0.5 rounded-lg border shadow-2xs backdrop-blur-sm', getUsbClassBadge(dev.class_desc)]">
                    {{ dev.class_desc }}
                  </span>
                </div>
              </div>

              <!-- 硬件元数据网格 -->
              <div class="grid grid-cols-2 gap-1.5 text-[10px] font-mono bg-black/40 p-2 rounded-lg border border-white/5 text-slate-400">
                <div class="truncate">
                  <span>硬件 ID: </span>
                  <strong class="text-purple-400 font-bold">VID_{{ dev.vid }} & PID_{{ dev.pid }}</strong>
                </div>
                <div class="truncate">
                  <span>驱动服务: </span>
                  <span class="text-slate-200 font-medium">{{ dev.service || 'N/A' }}</span>
                </div>
                <div class="truncate" :title="dev.manufacturer">
                  <span>制造商: </span>
                  <span class="text-slate-200 font-medium">{{ dev.manufacturer || '未知' }}</span>
                </div>
                <div class="truncate" :title="dev.location_info">
                  <span>物理位置: </span>
                  <span class="text-slate-200 font-medium">{{ dev.location_info || 'Root' }}</span>
                </div>
              </div>
            </div>

            <!-- 空状态 -->
            <div v-if="filteredUsbDevices.length === 0" class="flex flex-col items-center justify-center py-16 text-slate-500 text-xs gap-2">
              <svg class="w-8 h-8 text-slate-600 stroke-current fill-none" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/>
              </svg>
              <span>未检索到匹配的物理 USB 外设</span>
            </div>
          </div>
        </div>

        <!-- 物理 USB PnP 实时事件审计流水线 -->
        <div class="flex-[2] glass-surface backdrop-blur-2xl rounded-2xl border border-white/10 shadow-xl flex flex-col overflow-hidden min-h-0">
          <div class="px-3.5 py-2 border-b border-white/10 bg-white/[0.02] flex items-center justify-between text-xs font-bold text-slate-200 shrink-0">
            <div class="flex items-center gap-2">
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              <span>物理 USB 即插即用 (PnP) 实时审计流水线</span>
            </div>
            <span class="text-[10px] text-slate-400 font-mono">{{ usbAuditEvents.length }} 条审计事件</span>
          </div>

          <div class="flex-1 overflow-auto custom-scrollbar p-2.5 space-y-1.5">
            <div v-for="ev in usbAuditEvents" :key="ev.id"
              :class="['flex items-center gap-2.5 px-3 py-1.5 rounded-xl text-xs font-mono border backdrop-blur-md shadow-2xs transition-colors',
                ev.direction === 'USB_ATTACH' ? 'bg-emerald-500/10 text-emerald-200 border-emerald-500/30' :
                ev.direction === 'USB_DETACH' ? 'bg-amber-500/10 text-amber-200 border-amber-500/30' :
                'bg-slate-900/60 text-slate-300 border-white/5']">
              <span class="text-[10px] text-slate-500 w-16 shrink-0">{{ ev.timestamp }}</span>
              <span :class="['px-2 py-0.5 rounded-md text-[9px] font-bold shrink-0 shadow-2xs',
                ev.direction === 'USB_ATTACH' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-amber-500/20 text-amber-300 border border-amber-500/40']">
                {{ ev.direction === 'USB_ATTACH' ? '接入 ATTACH' : '拔出 DETACH' }}
              </span>
              <span class="truncate flex-1 text-[11px] text-slate-300 font-mono">{{ ev.raw_text || ev.payload_hex }}</span>
            </div>

            <!-- 空状态 -->
            <div v-if="usbAuditEvents.length === 0" class="flex flex-col items-center justify-center h-full py-8 text-slate-500 text-xs gap-1.5">
              <span class="text-sm">🔌</span>
              <span>USB 物理插拔守护进程待命中，暂无动态即插即用事件</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 3.2 右栏：端口全双工双向出入执行器 (TX ➔ RX) (占比 50%) -->
      <div class="flex-1 glass-surface backdrop-blur-2xl rounded-2xl border border-white/10 shadow-xl flex flex-col overflow-hidden min-h-0 min-w-0">
        
        <!-- 执行器头部：信道模式切换 (TCP/UDP 网络端口 vs 物理串口 COM) -->
        <div class="px-3.5 py-2 border-b border-white/10 bg-white/[0.02] flex items-center justify-between shrink-0">
          <div class="flex items-center gap-2">
            <span class="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
            <span class="text-xs font-bold text-white tracking-tight">端口数据双向出入执行器 (TX ➔ RX)</span>
          </div>

          <div class="flex bg-black/60 p-0.5 rounded-xl text-xs font-semibold border border-white/10 shadow-inner">
            <button @click="portOpChannel = 'network'"
              :class="['px-3 py-1 rounded-lg transition-all cursor-pointer font-bold text-[11px]',
                portOpChannel === 'network' ? 'bg-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200']">
              网络端口 (TCP/UDP)
            </button>
            <button @click="portOpChannel = 'serial'"
              :class="['px-3 py-1 rounded-lg transition-all cursor-pointer font-bold text-[11px]',
                portOpChannel === 'serial' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200']">
              物理串口 (COM)
            </button>
          </div>
        </div>

        <!-- 执行配置控制台表单 -->
        <div class="p-3.5 border-b border-white/10 space-y-2.5 text-xs shrink-0 bg-black/30">
          
          <!-- 渠道 A: 网络端口参数 -->
          <template v-if="portOpChannel === 'network'">
            <div class="grid grid-cols-[1fr_80px_75px_80px] gap-2 items-center">
              <div>
                <label class="text-[10px] font-bold text-slate-400 uppercase block mb-1">目标 IP 地址</label>
                <input v-model="portOpIp" placeholder="例如: 192.168.1.100"
                  class="w-full bg-[#131B26] border border-white/15 rounded-xl px-2.5 py-1.5 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-all">
              </div>
              <div>
                <label class="text-[10px] font-bold text-slate-400 uppercase block mb-1">端口</label>
                <input v-model.number="portOpPort" type="number" min="1" max="65535"
                  class="w-full bg-[#131B26] border border-white/15 rounded-xl px-2.5 py-1.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-all">
              </div>
              <div>
                <label class="text-[10px] font-bold text-slate-400 uppercase block mb-1">规约总线</label>
                <select v-model="portOpTransport"
                  class="w-full bg-[#131B26] border border-white/15 rounded-xl px-2 py-1.5 text-xs font-bold text-cyan-300 focus:outline-none focus:border-cyan-500 transition-all">
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                </select>
              </div>
              <div>
                <label class="text-[10px] font-bold text-slate-400 uppercase block mb-1">超时(ms)</label>
                <input v-model.number="portOpTimeout" type="number" min="200" max="10000"
                  class="w-full bg-[#131B26] border border-white/15 rounded-xl px-2.5 py-1.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500 transition-all">
              </div>
            </div>

            <!-- 载荷与预设模板 -->
            <div class="space-y-1">
              <div class="flex items-center justify-between text-[11px]">
                <span class="font-bold text-slate-400 uppercase">出向操作载荷 (Payload Hex)</span>
                <select @change="onPresetSelect($event)"
                  class="bg-[#131B26] border border-white/15 rounded-lg px-2 py-0.5 text-[10px] text-cyan-300 focus:outline-none cursor-pointer">
                  <option value="">-- 选择标准工业规约探测模板 --</option>
                  <option value="modbus_read_holding">Modbus-TCP: 读保持寄存器 0-1 (Func 03)</option>
                  <option value="http_get">HTTP/1.1: 基础心跳 GET 探测请求</option>
                  <option value="mqtt_ping">MQTT 物联: PINGREQ 保持心跳包</option>
                  <option value="iec104_test">IEC 60870-5-104: U 格式测试激活帧</option>
                </select>
              </div>
              <textarea v-model="portOpPayload" rows="2" placeholder="输入十六进制报文 (如: 00 01 00 00 00 06 01 03 00 00 00 02) 或明文字符串"
                class="w-full bg-[#131B26] border border-white/15 rounded-xl p-2 text-xs font-mono text-cyan-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-all resize-none custom-scrollbar"></textarea>
            </div>

            <!-- 写出并回捕按钮 -->
            <button @click="executePortTransceive" :disabled="portOpExecuting || !portOpPayload.trim()"
              class="w-full bg-gradient-to-r from-blue-600 via-cyan-600 to-teal-600 hover:from-blue-500 hover:via-cyan-500 hover:to-teal-500 text-white text-xs py-2 rounded-xl font-bold shadow-lg shadow-cyan-600/20 transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-40 active:scale-98">
              <span v-if="portOpExecuting" class="animate-spin">⏳</span>
              <span v-else>⚡</span>
              <span>执行写出与回包捕获 (TX ➔ RX)</span>
            </button>
          </template>

          <!-- 渠道 B: 物理串口参数 -->
          <template v-else-if="portOpChannel === 'serial'">
            <div class="grid grid-cols-2 gap-2">
              <div>
                <label class="text-[10px] font-bold text-slate-400 uppercase block mb-1">目标物理串口</label>
                <select v-model="selectedSerial"
                  class="w-full bg-[#131B26] border border-white/15 rounded-xl px-2.5 py-1.5 text-xs font-mono text-indigo-300 focus:outline-none focus:border-indigo-500 transition-all">
                  <option v-for="p in serialPorts" :key="p" :value="p">{{ p }}</option>
                  <option v-if="serialPorts.length === 0" value="">未发现串口</option>
                </select>
              </div>
              <div>
                <label class="text-[10px] font-bold text-slate-400 uppercase block mb-1">通信波特率</label>
                <select v-model.number="serialBaudRate"
                  class="w-full bg-[#131B26] border border-white/15 rounded-xl px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500 transition-all">
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
                <span class="font-bold text-slate-400 uppercase">串口写出指令</span>
                <label class="flex items-center gap-1.5 cursor-pointer">
                  <input type="checkbox" v-model="portOpSerialIsHex" class="accent-indigo-500">
                  <span class="font-mono text-[10px] font-bold text-indigo-400">按 HEX 模式发送</span>
                </label>
              </div>
              <textarea v-model="portOpSerialPayload" rows="2" placeholder="输入待写出到串口的指令 (如: 01 03 00 00 00 02 C4 0B)"
                class="w-full bg-[#131B26] border border-white/15 rounded-xl p-2 text-xs font-mono text-indigo-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition-all resize-none custom-scrollbar"></textarea>
            </div>

            <button @click="executePortTransceive" :disabled="portOpExecuting || !portOpSerialPayload.trim() || !selectedSerial"
              class="w-full bg-gradient-to-r from-indigo-600 via-purple-600 to-pink-600 hover:from-indigo-500 hover:to-pink-500 text-white text-xs py-2 rounded-xl font-bold shadow-lg shadow-indigo-600/20 transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-40 active:scale-98">
              <span v-if="portOpExecuting" class="animate-spin">⏳</span>
              <span v-else>📡</span>
              <span>执行串口写出与双向侦测</span>
            </button>
          </template>
        </div>

        <!-- 双向操作流水历史终端 (Terminal Output) -->
        <div class="flex-1 overflow-auto custom-scrollbar p-3 space-y-2 bg-black/40 min-h-0">
          <div v-for="item in transceiveHistory" :key="item.id"
            class="bg-[#121824]/90 border border-white/10 rounded-xl p-2.5 text-xs font-mono space-y-1.5 shadow-md">
            <div class="flex items-center justify-between text-[10px] text-slate-400 border-b border-white/5 pb-1">
              <span class="font-bold text-slate-200">{{ item.channel }} | {{ item.target }}</span>
              <span class="font-mono">{{ item.time }} (RTT: {{ item.latencyMs.toFixed(1) }}ms)</span>
            </div>
            
            <!-- TX 出向 -->
            <div class="text-[11px] text-blue-200 break-all bg-blue-500/10 p-2 rounded-lg border border-blue-500/20">
              <strong class="text-blue-400 font-bold mr-1.5">[TX 发送 {{ item.bytesSent }}B]:</strong>
              <span class="font-mono">{{ item.txPayload }}</span>
            </div>
            
            <!-- RX 入向 -->
            <div v-if="item.bytesReceived > 0" class="text-[11px] text-emerald-200 break-all bg-emerald-500/10 p-2 rounded-lg border border-emerald-500/20">
              <div class="text-emerald-400 font-bold mb-0.5">[RX 接收 {{ item.bytesReceived }}B] 协议: {{ item.detectedProto || 'RAW' }}</div>
              <div><strong class="text-emerald-400">HEX:</strong> {{ item.rxPayload }}</div>
              <div v-if="item.rxText" class="text-slate-300 mt-0.5"><strong class="text-emerald-400">ASCII:</strong> {{ item.rxText }}</div>
            </div>
            
            <!-- ERR 错误 -->
            <div v-else-if="item.error" class="bg-rose-500/15 text-[11px] text-rose-300 p-2 rounded-lg border border-rose-500/30">
              <strong class="font-bold text-rose-400">ERR:</strong> {{ item.error }}
            </div>
          </div>

          <!-- 空状态与引导操作 -->
          <div v-if="transceiveHistory.length === 0" class="flex flex-col items-center justify-center h-full py-12 text-slate-500 text-xs gap-2">
            <div class="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-lg text-cyan-400">
              ⚡
            </div>
            <span class="font-medium text-slate-400">暂无双向端口交互出入流水</span>
            <span class="text-[10px] text-slate-600 max-w-xs text-center font-mono">
              配置目标 IP/端口或物理串口，点击上方【执行写出与回包捕获】即可开始双向交互探针作业
            </span>
          </div>
        </div>
      </div>
    </main>

    <!-- 4. 工业级外设与总线扩展模态框集 -->
    
    <!-- 串口工业通信参数与动态分帧配置模态框 -->
    <SerialExtendedConfigModal
      :isOpen="isSerialConfigOpen"
      :serialPorts="serialPorts"
      :defaultPort="selectedSerial"
      @close="isSerialConfigOpen = false"
      @started="onSerialConfigStarted"
      @log="$emit('appendLog', $event)"
    />

    <!-- 双串口工业级透明中继器模态框 -->
    <SerialBridgeModal
      :isOpen="isSerialBridgeOpen"
      :serialPorts="serialPorts"
      @close="isSerialBridgeOpen = false"
      @log="$emit('appendLog', $event)"
    />

    <!-- USB 标准描述符树深度展开分析器模态框 -->
    <UsbDescriptorTreeModal
      :isOpen="isUsbDescriptorTreeOpen"
      :initialHex="usbDescriptorHex"
      @close="isUsbDescriptorTreeOpen = false"
    />

    <!-- 跨总线网关协议转换因果关联追踪看板模态框 -->
    <CrossBusCausalityModal
      :isOpen="isCrossBusCausalityOpen"
      @close="isCrossBusCausalityOpen = false"
    />

  </div>
</template>

<script setup lang="ts">
import { notifySuccess, notifyWarning, notifyError } from '../composables/useNotification';
import { ref, computed, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import SerialModemPinsPanel from '../components/SerialModemPinsPanel.vue';
import SerialExtendedConfigModal from '../components/SerialExtendedConfigModal.vue';
import SerialBridgeModal from '../components/SerialBridgeModal.vue';
import UsbDescriptorTreeModal from '../components/UsbDescriptorTreeModal.vue';
import CrossBusCausalityModal from '../components/CrossBusCausalityModal.vue';

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

const props = defineProps<{
  usbDevices: UsbDeviceInfo[];
  packets: any[];
  serialPorts: string[];
  isUsbRunning?: boolean;
  isSerialRunning?: boolean;
}>();

const emit = defineEmits(['refreshUsb', 'startUsbCapture', 'stopUsbCapture', 'startSerialCapture', 'stopSerialCapture', 'appendLog']);

// 硬件基线白名单与合规审计状态
const showComplianceWorkbench = ref(false);
const complianceReport = ref<HardwareComplianceReport | null>(null);
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
  if (!confirm('确定要清空现有硬件白名单基线吗？清空后所有在线外设都将被标记为未授权外设！')) return;
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
  selectedSerial.value = payload.port;
  serialBaudRate.value = payload.baudRate;
}

const usbFilter = ref('');
const portOpChannel = ref<'network' | 'serial'>('network');
const portOpIp = ref('');
const portOpPort = ref(502);
const portOpTransport = ref<'TCP' | 'UDP'>('TCP');
const portOpTimeout = ref(2000);
const portOpPayload = ref('00 01 00 00 00 06 01 03 00 00 00 02');
const selectedSerial = ref(props.serialPorts.length > 0 ? props.serialPorts[0] : '');
const serialBaudRate = ref(9600);
const portOpSerialPayload = ref('01 03 00 00 00 02 C4 0B');
const portOpSerialIsHex = ref(true);
const portOpExecuting = ref(false);
const transceiveHistory = ref<TransceiveHistoryItem[]>([]);

const usbSerialCount = computed(() => props.usbDevices.filter(d => d.class_desc.includes('串口') || d.class_desc.includes('CDC')).length);

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

const usbAuditEvents = computed(() => props.packets.filter(p => p.direction === 'USB_ATTACH' || p.direction === 'USB_DETACH' || p.transport === 'USB').slice(-80).reverse());

function getUsbClassBadge(classDesc: string): string {
  if (classDesc.includes('串口') || classDesc.includes('CDC') || classDesc.includes('RS485')) {
    return 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30';
  } else if (classDesc.includes('存储') || classDesc.includes('U盘')) {
    return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
  } else if (classDesc.includes('HID') || classDesc.includes('人机交互')) {
    return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
  } else if (classDesc.includes('视觉') || classDesc.includes('相机')) {
    return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
  }
  return 'bg-purple-500/20 text-purple-300 border-purple-500/30';
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
        port: selectedSerial.value,
        baudRate: serialBaudRate.value,
        payload: portOpSerialPayload.value.trim(),
        isHex: portOpSerialIsHex.value
      });
      const latencyMs = performance.now() - start;

      transceiveHistory.value.unshift({
        id: Date.now(),
        time: ts,
        channel: '物理串口',
        target: `${selectedSerial.value} @ ${serialBaudRate.value} bps`,
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
      target: portOpChannel.value === 'network' ? `${portOpIp.value}:${portOpPort.value}` : selectedSerial.value,
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
