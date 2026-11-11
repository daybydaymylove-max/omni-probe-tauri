<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 ui-modal-backdrop">
    <div class="w-full max-w-4xl max-h-[92vh] ui-modal-surface rounded-3xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
      <span class="lens-edge-lip" aria-hidden="true"></span>
      
      <!-- 顶栏：标题与操作 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-6 py-4 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-700 dark:text-sky-300 shrink-0">
            <AppIcon name="shield" :size="18" />
          </div>
          <div>
            <h3 class="text-sm font-bold flex items-center gap-2" style="color: var(--text-primary)">
              <span>底层抓包驱动与解剖环境诊断中心</span>
            </h3>
            <div class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">
              探活诊断覆盖: Npcap 驱动 · TShark 引擎 · USBPcap 总线 · ip2region 库 · 进程特权
            </div>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <button @click="refreshInspection" :disabled="loading" class="ui-btn-secondary text-xs px-3.5 py-1.5 rounded-xl">
            <AppIcon name="refresh" :size="13" :class="loading ? 'animate-spin' : ''" />
            <span>{{ loading ? '深度探活中...' : '重新检测' }}</span>
          </button>
          <button @click="$emit('close')" class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer ml-1" title="关闭">
            <AppIcon name="close" :size="15" />
          </button>
        </div>
      </header>

      <!-- 主体内容 -->
      <div class="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-4 select-text" style="background: var(--surface-content)">
        
        <!-- 综合健康度大卡片 -->
        <div class="p-4 ui-sub-card flex flex-col md:flex-row items-center justify-between gap-4">
          <div class="flex items-center gap-4">
            <div class="relative w-16 h-16 shrink-0 flex items-center justify-center">
              <svg class="w-16 h-16 transform -rotate-90">
                <circle cx="32" cy="32" r="26" stroke="currentColor" stroke-width="5" style="color: var(--border-subtle)" fill="transparent" />
                <circle cx="32" cy="32" r="26" stroke="currentColor" stroke-width="5"
                  :stroke-dasharray="163.3"
                  :stroke-dashoffset="163.3 - (163.3 * (report?.readiness_score || 0)) / 100"
                  :class="scoreColorClass"
                  fill="transparent"
                  stroke-linecap="round"
                  class="transition-all duration-700" />
              </svg>
              <span class="absolute text-sm font-bold ui-num" style="color: var(--text-primary)">
                {{ report?.readiness_score || 0 }}%
              </span>
            </div>

            <div>
              <div class="flex items-center gap-2 flex-wrap">
                <span class="text-xs font-bold" style="color: var(--text-primary)">运行环境就绪度:</span>
                <span :class="['text-xs ui-num font-bold px-2 py-0.5 rounded-full border', badgeColorClass]">
                  {{ statusText }}
                </span>
                <span class="text-[11px] ui-num" style="color: var(--text-muted)">诊断时间: {{ report?.checked_at }}</span>
              </div>
              <p class="text-xs leading-relaxed mt-1 max-w-xl" style="color: var(--text-secondary)">
                {{ report?.summary }}
              </p>
            </div>
          </div>

          <div class="text-[11px] ui-num p-3 rounded-xl border shrink-0 space-y-1" style="background: var(--surface-content); border-color: var(--border-subtle); color: var(--text-secondary)">
            <div class="font-bold border-b pb-1 mb-1" style="color: var(--text-primary); border-color: var(--border-subtle)">多轨并行自愈就绪矩阵</div>
            <div>· 工业规约解剖: <strong class="text-emerald-700 dark:text-emerald-400">42+ 原生自愈轨已就绪</strong></div>
            <div>· 全协议官方解剖: <strong :class="isTsharkReady ? 'text-emerald-700 dark:text-emerald-400' : 'text-indigo-700 dark:text-indigo-400'">{{ isTsharkReady ? 'Wireshark 官方轨' : '原生 Rust 42+ 自愈轨' }}</strong></div>
            <div>· 网络数据嗅探: <strong :class="isNpcapReady ? 'text-emerald-700 dark:text-emerald-400' : 'text-indigo-700 dark:text-indigo-400'">{{ isNpcapReady ? 'Npcap L2 混杂轨' : 'Raw Socket 双轨自愈' }}</strong></div>
            <div>· 物理 USB 总线: <strong :class="isUsbpcapReady ? 'text-emerald-700 dark:text-emerald-400' : 'text-amber-700 dark:text-amber-400'">{{ isUsbpcapReady ? 'URB 物理硬件轨' : 'PnP 设备拓扑自愈' }}</strong></div>
            <div>· 离线地理情报: <strong :class="isIpDbReady ? 'text-emerald-700 dark:text-emerald-400' : 'text-indigo-700 dark:text-indigo-400'">{{ isIpDbReady ? '千万级 XDB 离线库' : '内置 LPM CIDR 自愈轨' }}</strong></div>
          </div>
        </div>

        <!-- 缺少 USBPcap 驱动时的提醒 -->
        <div v-if="!isUsbpcapReady" class="p-3.5 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-xs space-y-1.5">
          <div class="font-bold flex items-center justify-between flex-wrap gap-2">
            <div class="flex items-center gap-2 text-amber-700 dark:text-amber-300">
              <AppIcon name="alert" :size="15" />
              <span>物理 USB 总线捕获驱动 (USBPcap) 缺失提醒与多轨自愈说明</span>
            </div>
            <button v-if="!launchedMap['usbpcap'] && !installingMap['usbpcap']"
              @click="confirmingComponent = 'usbpcap'"
              class="px-2.5 py-1 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-bold text-[11px] transition-colors cursor-pointer flex items-center gap-1">
              <span>立即安装 USBPcap</span>
              <AppIcon name="download" :size="11" />
            </button>
          </div>
          <div class="text-[11px] leading-relaxed space-y-1 pl-6 ui-num" style="color: var(--text-secondary)">
            <div>· <strong>当前自愈状态</strong>：系统已自动调用 Windows 原生 PnP 设备管理器拓扑总线，USB 外设热插拔感知与串口 COM 调试完全正常；</div>
            <div>· <strong>受限功能</strong>：无法捕获微秒级物理 URB 请求块与 BadUSB 击键时序（IAT &lt; 25ms 硬件特征）。如需深度 URB 分析，建议一键安装驱动。</div>
          </div>
        </div>

        <!-- 五大核心组件细化卡片列表 -->
        <div class="space-y-3 text-xs">
          <div v-for="comp in report?.components" :key="comp.id" class="ui-content-card p-4 hover:border-sky-500/40 transition-colors">
            <div class="flex items-start justify-between gap-3 flex-wrap">
              <div class="flex items-center gap-2.5">
                <span :class="['w-2.5 h-2.5 rounded-full shrink-0', comp.is_ready ? 'bg-emerald-500' : 'bg-amber-500']"></span>
                <div>
                  <div class="font-bold text-xs flex items-center gap-2 flex-wrap" style="color: var(--text-primary)">
                    <span>{{ comp.name }}</span>
                    <span :class="['text-[11px] px-2 py-0.5 rounded-full ui-num font-bold border flex items-center gap-1', comp.is_ready ? 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' : 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/30']">
                      <AppIcon :name="comp.is_ready ? 'check' : 'alert'" :size="11" />
                      <span>{{ comp.is_ready ? '外部资源就绪' : '外部驱动缺失 (多轨自愈中)' }}</span>
                    </span>
                    <span class="text-[11px] px-2 py-0.5 rounded-full ui-num font-bold bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25 flex items-center gap-1">
                      <AppIcon name="zap" :size="11" />
                      <span>内置自愈轨已就绪</span>
                    </span>
                  </div>
                  <div class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">
                    <span v-if="comp.path">路径: {{ comp.path }}</span>
                    <span v-else-if="comp.version">版本: {{ comp.version }}</span>
                    <span v-else class="text-indigo-700 dark:text-indigo-300">已自动切换至系统原生多轨自愈实现</span>
                  </div>
                </div>
              </div>

              <div class="flex items-center gap-2 shrink-0">
                <button v-if="!comp.is_ready && comp.can_auto_install && !installingMap[comp.id] && confirmingComponent !== comp.id && !launchedMap[comp.id]"
                  @click="confirmingComponent = comp.id"
                  class="ui-btn-primary text-xs px-3 py-1.5 rounded-xl">
                  <AppIcon name="download" :size="13" />
                  <span>{{ comp.id === 'ip_db' ? '自动下载离线库' : '自动从官网安装' }}</span>
                </button>

                <button @click="openLink(comp.official_url)" class="ui-btn-secondary text-xs px-3 py-1.5 rounded-xl shrink-0">
                  <span>官方主页</span>
                  <AppIcon name="arrow-right" :size="12" />
                </button>
              </div>
            </div>

            <!-- 确认从官网下载安装 -->
            <div v-if="confirmingComponent === comp.id"
              class="mt-3 p-3.5 bg-blue-500/10 rounded-xl border border-blue-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
              <div>
                <div class="text-xs font-bold text-blue-700 dark:text-blue-200 flex items-center gap-1.5">
                  <AppIcon name="download" :size="13" />
                  <span>是否确认从官方镜像安全下载并装配 {{ comp.name }}？</span>
                </div>
                <div class="text-[11px] mt-1 ui-num" style="color: var(--text-secondary)">
                  将下载: <strong>{{ comp.installer_filename }}</strong> (约 {{ comp.estimated_size_mb }} MB) · 下载后自动完成装配或唤起向导。
                </div>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <button @click="startAutoInstall(comp.id)" class="ui-btn-primary text-xs px-3 py-1.5 rounded-lg">
                  确认并开始下载
                </button>
                <button @click="confirmingComponent = null" class="ui-btn-secondary text-xs px-3 py-1.5 rounded-lg">
                  取消
                </button>
              </div>
            </div>

            <!-- 下载进度条卡片 -->
            <div v-if="installingMap[comp.id]" class="mt-3 p-3 ui-sub-card space-y-2">
              <div class="flex items-center justify-between text-xs ui-num">
                <span class="text-blue-700 dark:text-blue-300 font-bold flex items-center gap-2">
                  <AppIcon name="refresh" :size="13" class="animate-spin" />
                  <span>{{ installingMap[comp.id].status === 'launching' ? '已完成下载，正在唤起向导或装配数据...' : '正在从官方源流式下载中...' }}</span>
                </span>
                <span class="font-bold" style="color: var(--text-primary)">{{ installingMap[comp.id].percent.toFixed(1) }}%</span>
              </div>
              <div class="w-full h-2 rounded-full overflow-hidden" style="background: var(--surface-elevated)">
                <div class="h-full bg-gradient-to-r from-sky-500 to-indigo-600 transition-all duration-200"
                  :style="{ width: `${installingMap[comp.id].percent}%` }"></div>
              </div>
              <div class="text-[11px] flex items-center justify-between ui-num" style="color: var(--text-muted)">
                <span>已接收: {{ (installingMap[comp.id].downloaded_bytes / 1024 / 1024).toFixed(2) }} MB</span>
                <span>总预计: {{ (installingMap[comp.id].total_bytes / 1024 / 1024).toFixed(2) }} MB</span>
              </div>
            </div>

            <!-- 安装启动提示 -->
            <div v-if="launchedMap[comp.id]"
              class="mt-3 p-3 bg-emerald-500/12 rounded-xl border border-emerald-500/30 flex items-center justify-between gap-3 text-xs">
              <div class="text-emerald-700 dark:text-emerald-300 font-semibold flex items-center gap-1.5">
                <AppIcon name="check" :size="14" />
                <span>{{ comp.id === 'ip_db' ? '已成功装载官方离线数据库，即刻生效！' : '官方安装程序向导已启动，请在弹出窗口完成安装。' }}</span>
              </div>
              <button @click="finishAndRecheck(comp.id)"
                class="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs transition-colors cursor-pointer shrink-0 flex items-center gap-1.5">
                <AppIcon name="refresh" :size="12" />
                <span>完成并重新检测</span>
              </button>
            </div>

            <!-- 能力与多轨自愈对比 -->
            <div class="mt-3 pt-3 border-t grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]" style="border-color: var(--border-subtle)">
              <div class="p-2.5 rounded-xl bg-emerald-500/8 border border-emerald-500/20">
                <div class="font-bold text-emerald-700 dark:text-emerald-300 mb-0.5 flex items-center gap-1">
                  <AppIcon name="zap" :size="12" />
                  <span>外部扩展轨能力:</span>
                </div>
                <div class="leading-relaxed" style="color: var(--text-secondary)">{{ comp.capability_enabled }}</div>
              </div>

              <div class="p-2.5 rounded-xl bg-indigo-500/8 border border-indigo-500/20">
                <div class="font-bold text-indigo-700 dark:text-indigo-300 mb-0.5 flex items-center gap-1">
                  <AppIcon name="shield" :size="12" />
                  <span>内置多轨自愈机制:</span>
                </div>
                <div class="leading-relaxed" style="color: var(--text-secondary)">{{ comp.fallback_mode }}</div>
              </div>
            </div>

            <div v-if="!comp.is_ready" class="mt-2.5 px-3 py-1.5 rounded-xl bg-amber-500/10 border border-amber-500/25 text-[11px] text-amber-700 dark:text-amber-300 flex items-start gap-1.5">
              <AppIcon name="info" :size="13" class="shrink-0 mt-0.5" />
              <span><strong>优化建议:</strong> {{ comp.install_tips }}</span>
            </div>
          </div>
        </div>

        <!-- 国密与国产信创合规架构说明 -->
        <div class="mt-4 p-5 ui-content-card border-rose-500/25 space-y-4">
          <div class="flex items-center justify-between border-b pb-3 flex-wrap gap-2" style="border-color: var(--border-subtle)">
            <div class="flex items-center gap-2.5">
              <span class="w-2.5 h-2.5 rounded-full bg-rose-500 shrink-0"></span>
              <h4 class="text-xs font-bold flex items-center gap-2 flex-wrap" style="color: var(--text-primary)">
                <span>自主可控内核与信创标准规范兼容声明</span>
                <span class="text-[11px] px-2 py-0.5 rounded-full ui-num font-bold bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30">
                  内生核心 · 可选外挂扩展
                </span>
              </h4>
            </div>
            <div class="text-[11px] ui-num text-rose-700 dark:text-rose-300">
              Rust 原生主流水线 · 驱动/外置轨按实探测
            </div>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div class="ui-sub-card p-3.5 space-y-1">
              <div class="font-bold flex items-center gap-1.5 text-xs" style="color: var(--text-primary)">
                <AppIcon name="shield" :size="14" class="text-rose-600 dark:text-rose-400" />
                <span>自主内生代码控制权 (In-Tree Rust Pipeline)</span>
              </div>
              <div class="text-[11px] leading-relaxed ui-num" style="color: var(--text-secondary)">
                从数据链路层抓包到应用层状态机重组均由工程内置实现，具备完备的多轨自愈与降级接管能力。
              </div>
            </div>

            <div class="ui-sub-card p-3.5 space-y-1">
              <div class="font-bold flex items-center gap-1.5 text-xs" style="color: var(--text-primary)">
                <AppIcon name="lock" :size="14" class="text-amber-600 dark:text-amber-400" />
                <span>商用密码国密体系内置 (GM/T Cryptography)</span>
              </div>
              <div class="text-[11px] leading-relaxed ui-num" style="color: var(--text-secondary)">
                内置 GM/T 0004-2012 (SM3 杂凑，用于 Merkle 防伪存证链) 与 GM/T 0002-2012 (SM4 对称加密，用于涉密载荷加密与脱敏)。
              </div>
            </div>

            <div class="ui-sub-card p-3.5 space-y-1">
              <div class="font-bold flex items-center gap-1.5 text-xs" style="color: var(--text-primary)">
                <AppIcon name="document" :size="14" class="text-blue-600 dark:text-sky-400" />
                <span>关键行业国家标准规约原生解析</span>
              </div>
              <div class="text-[11px] leading-relaxed ui-num" style="color: var(--text-secondary)">
                原生解析水利部 SL651-2014、生态环保 HJ 212-2017、电网 DL/T 645-2007、远动 DL/T 634.5104、公文格式 GB/T 9704-2012。
              </div>
            </div>

            <div class="ui-sub-card p-3.5 space-y-1">
              <div class="font-bold flex items-center gap-1.5 text-xs" style="color: var(--text-primary)">
                <AppIcon name="cpu" :size="14" class="text-emerald-600 dark:text-emerald-400" />
                <span>多操作系统与国产架构兼容</span>
              </div>
              <div class="text-[11px] leading-relaxed ui-num" style="color: var(--text-secondary)">
                支持统信 UOS、银河麒麟 KylinOS、OpenEuler 等平台及 LoongArch64、ARM64、x86-64 处理器架构。
              </div>
            </div>
          </div>
        </div>

        <!-- 零拷贝内存池 (Win32 RIO / 物理锁页) & eBPF/XDP 线速分流引擎实况 -->
        <div class="mt-4 p-5 ui-content-card border-sky-500/25 space-y-4">
          <div class="flex items-center justify-between border-b pb-3 flex-wrap gap-2" style="border-color: var(--border-subtle)">
            <div class="flex items-center gap-2.5">
              <span
                class="w-2.5 h-2.5 rounded-full shrink-0"
                :class="zeroCopyTelemetry?.rio_active || zeroCopyTelemetry?.npcap_pool_active ? 'bg-emerald-500 animate-pulse' : 'bg-sky-500'"
              ></span>
              <h4 class="text-xs font-bold flex items-center gap-2 flex-wrap" style="color: var(--text-primary)">
                <span>零拷贝收包缓冲池与 eBPF/XDP 流分流引擎实况</span>
                <span class="text-[11px] px-2 py-0.5 rounded-full ui-num font-bold bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-500/30">
                  {{ zeroCopyTelemetry?.active_backend || '待机未开启抓包' }}
                </span>
              </h4>
            </div>
            <div class="flex items-center gap-2">
              <span class="text-[11px] ui-num" style="color: var(--text-muted)">
                每 2 秒自动采集底层运行时遥测
              </span>
              <button
                @click="refreshRuntimeTelemetry"
                class="ui-btn-secondary px-2.5 py-1 text-[11px] flex items-center gap-1"
                title="立即拉取内核零拷贝与 XDP 实时统计"
              >
                <AppIcon name="refresh" :size="12" />
                <span>刷新遥测</span>
              </button>
            </div>
          </div>

          <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
            <!-- 左栏：Win32 RIO / Double-Buffered Zero-Copy Pool -->
            <div class="ui-sub-card p-4 space-y-3">
              <div class="flex items-center justify-between gap-2">
                <div class="font-bold flex items-center gap-1.5 text-xs" style="color: var(--text-primary)">
                  <AppIcon name="cpu" :size="14" class="text-sky-600 dark:text-sky-400" />
                  <span>物理锁页零拷贝缓冲池 (Win32 RIO / Double-Page)</span>
                </div>
                <span
                  class="text-[11px] px-2 py-0.5 rounded font-semibold ui-num shrink-0"
                  :class="zeroCopyTelemetry?.is_large_pages
                    ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                    : zeroCopyTelemetry?.is_physically_pinned
                      ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300'
                      : 'bg-slate-500/15 text-slate-600 dark:text-slate-300'"
                >
                  {{ zeroCopyTelemetry?.is_large_pages ? '2MB 物理大页' : (zeroCopyTelemetry?.is_physically_pinned ? 'VirtualLock 物理锁页' : '标准页池') }}
                </span>
              </div>

              <div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                  <div class="text-[11px]" style="color: var(--text-muted)">已锁定物理内存</div>
                  <div class="text-xs font-bold ui-num mt-0.5" style="color: var(--text-primary)">
                    {{ formatTelemetryBytes((zeroCopyTelemetry?.pinned_buffer_bytes || 0) + (zeroCopyTelemetry?.pool_total_memory_bytes || 0)) }}
                  </div>
                </div>
                <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                  <div class="text-[11px]" style="color: var(--text-muted)">Ring 累计入池</div>
                  <div class="text-xs font-bold ui-num mt-0.5 text-sky-700 dark:text-sky-300">
                    {{ (zeroCopyTelemetry?.ring_packets_total ?? 0).toLocaleString() }} 帧
                  </div>
                </div>
                <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                  <div class="text-[11px]" style="color: var(--text-muted)">双页槽利用率</div>
                  <div class="text-xs font-bold ui-num mt-0.5" style="color: var(--text-primary)">
                    {{ (zeroCopyTelemetry?.pool_utilization_percent ?? 0).toFixed(1) }}%
                  </div>
                </div>
                <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                  <div class="text-[11px]" style="color: var(--text-muted)">耗尽/Ring 丢弃</div>
                  <div
                    class="text-xs font-bold ui-num mt-0.5"
                    :class="(zeroCopyTelemetry?.ring_drops_total || 0) + (zeroCopyTelemetry?.pool_exhaustion_drops || 0) > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'"
                  >
                    {{ ((zeroCopyTelemetry?.ring_drops_total ?? 0) + (zeroCopyTelemetry?.pool_exhaustion_drops ?? 0)).toLocaleString() }}
                  </div>
                </div>
              </div>

              <div class="text-[11px] leading-relaxed ui-num flex flex-wrap items-center justify-between gap-2 pt-1 border-t" style="border-color: var(--border-subtle); color: var(--text-secondary)">
                <span>{{ zeroCopyTelemetry?.status_detail || '正在读取物理锁页缓冲池与内核队列状态...' }}</span>
                <span class="shrink-0">槽位: {{ zeroCopyTelemetry?.pool_allocations ?? 0 }} 分配 / {{ zeroCopyTelemetry?.pool_deallocations ?? 0 }} 翻页回收 ({{ zeroCopyTelemetry?.pool_total_slots ?? 0 }} 槽上限)</span>
              </div>
            </div>

            <!-- 右栏：eBPF Verifier + XDP Flow Steering -->
            <div class="ui-sub-card p-4 space-y-3">
              <div class="flex items-center justify-between gap-2 flex-wrap">
                <div class="font-bold flex items-center gap-1.5 text-xs" style="color: var(--text-primary)">
                  <AppIcon name="shield" :size="14" class="text-indigo-600 dark:text-indigo-400" />
                  <span>eBPF 字节码验证器与 TCP 五元组流直通 (XDP)</span>
                </div>
                <span class="text-[11px] px-2 py-0.5 rounded font-semibold ui-num bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 shrink-0">
                  策略: {{ xdpMetrics?.active_policy_name || 'default_inspection' }} ({{ xdpMetrics?.ebpf_instructions_count ?? 0 }} 条指令)
                </span>
              </div>

              <div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                  <div class="text-[11px]" style="color: var(--text-muted)">总过审报文</div>
                  <div class="text-xs font-bold ui-num mt-0.5" style="color: var(--text-primary)">
                    {{ (xdpMetrics?.total_processed_packets ?? 0).toLocaleString() }}
                  </div>
                </div>
                <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                  <div class="text-[11px]" style="color: var(--text-muted)">大象流旁路直通</div>
                  <div class="text-xs font-bold ui-num mt-0.5 text-emerald-700 dark:text-emerald-300">
                    {{ (xdpMetrics?.bypassed_packets ?? 0).toLocaleString() }} ({{ (xdpMetrics?.bypass_ratio_percentage ?? 0).toFixed(1) }}%)
                  </div>
                </div>
                <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                  <div class="text-[11px]" style="color: var(--text-muted)">XDP 前端丢弃</div>
                  <div class="text-xs font-bold ui-num mt-0.5 text-rose-600 dark:text-rose-400">
                    {{ (xdpMetrics?.dropped_packets ?? 0).toLocaleString() }} ({{ xdpMetrics?.blocked_ips_count ?? 0 }} IP 黑名单)
                  </div>
                </div>
                <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                  <div class="text-[11px]" style="color: var(--text-muted)">活跃流 / 重定向</div>
                  <div class="text-xs font-bold ui-num mt-0.5" style="color: var(--text-primary)">
                    {{ xdpMetrics?.active_tcp_flows ?? 0 }} 流 / {{ (xdpMetrics?.redirected_packets ?? 0).toLocaleString() }}
                  </div>
                </div>
              </div>

              <!-- 实时热切换策略组 (经过后端 EbpfVerifier 安全校验) -->
              <div class="flex items-center justify-between gap-2 flex-wrap pt-1 border-t" style="border-color: var(--border-subtle)">
                <span class="text-[11px] font-medium" style="color: var(--text-muted)">eBPF 运行策略热部署:</span>
                <div class="flex items-center gap-1.5 flex-wrap">
                  <button
                    v-for="preset in xdpPresetOptions"
                    :key="preset.id"
                    @click="applyXdpPreset(preset.id)"
                    :disabled="switchingXdpPolicy"
                    :class="[
                      'px-2.5 py-1 rounded-lg text-[11px] font-medium transition-all cursor-pointer border',
                      xdpMetrics?.active_policy_name === preset.id
                        ? 'bg-indigo-600 text-white border-indigo-500 shadow-2xs'
                        : 'ui-btn-secondary'
                    ]"
                    :title="preset.desc"
                  >
                    {{ preset.label }}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

      </div>

      <!-- 底栏 -->
      <footer class="px-6 py-3 border-t flex flex-col sm:flex-row items-center justify-between gap-3 shrink-0 text-xs" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-secondary)">
        <label class="flex items-center gap-2 cursor-pointer select-none">
          <input type="checkbox" v-model="skipStartupModal" @change="onToggleSkipStartup"
            class="w-4 h-4 rounded accent-sky-500 cursor-pointer" />
          <span class="text-xs font-medium">下次启动时不主动弹出此自检窗口 (保持后台静默多轨自愈)</span>
        </label>

        <div class="flex items-center gap-3 shrink-0">
          <span class="text-[11px] hidden md:inline" style="color: var(--text-muted)">可随时点击顶栏【环境诊断】重新呼出</span>
          <button @click="$emit('close')" class="ui-btn-primary px-4 py-1.5 rounded-xl font-semibold">
            关闭诊断
          </button>
        </div>
      </footer>

    </div>
  </div>
</template>

<script setup lang="ts">
import { notifySuccess, notifyError } from '../composables/useNotification';
import { ref, computed, onMounted, onUnmounted, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { openUrl } from '@tauri-apps/plugin-opener';
import AppIcon from './AppIcon.vue';

interface ComponentStatus {
  id: string;
  name: string;
  category: string;
  is_ready: boolean;
  version?: string;
  path?: string;
  capability_enabled: string;
  fallback_mode: string;
  official_url: string;
  install_tips: string;
  can_auto_install: boolean;
  installer_filename?: string;
  estimated_size_mb?: number;
}

interface EnvironmentReport {
  readiness_score: number;
  status_level: string;
  summary: string;
  components: ComponentStatus[];
  checked_at: string;
}

interface DownloadProgressPayload {
  component_id: string;
  status: string;
  percent: number;
  downloaded_bytes: number;
  total_bytes: number;
  error_msg?: string;
}

interface KernelZeroCopyTelemetry {
  active_backend: string;
  rio_active: boolean;
  npcap_pool_active: boolean;
  is_physically_pinned: boolean;
  is_large_pages: boolean;
  pinned_buffer_bytes: number;
  ring_packets_total: number;
  ring_bytes_total: number;
  ring_drops_total: number;
  pool_total_slots: number;
  pool_allocations: number;
  pool_deallocations: number;
  pool_exhaustion_drops: number;
  pool_utilization_percent: number;
  pool_total_memory_bytes: number;
  status_detail: string;
}

interface XdpBypassMetrics {
  total_processed_packets: number;
  passed_packets: number;
  dropped_packets: number;
  bypassed_packets: number;
  redirected_packets: number;
  total_bypassed_bytes: number;
  bypass_ratio_percentage: number;
  active_tcp_flows: number;
  direct_bypassed_flows: number;
  blocked_ips_count: number;
  ebpf_instructions_count: number;
  active_policy_name: string;
}

const props = defineProps<{
  isOpen: boolean;
}>();

defineEmits(['close']);

const report = ref<EnvironmentReport | null>(null);
const loading = ref(false);
const zeroCopyTelemetry = ref<KernelZeroCopyTelemetry | null>(null);
const xdpMetrics = ref<XdpBypassMetrics | null>(null);
const switchingXdpPolicy = ref(false);
let telemetryTimer: ReturnType<typeof setInterval> | null = null;

const xdpPresetOptions = [
  { id: 'default_inspection', label: '全量深度审计', desc: '全部报文透传解析并开启大象流智能旁路' },
  { id: 'drop_icmp_probe', label: '拦截 ICMP 探测', desc: 'eBPF 首包直接丢弃 ICMPv4 探活报文' },
  { id: 'redirect_tcp_xsk', label: 'TCP 高速直通分流', desc: 'TCP 报文优先定向 AF_XDP / 零拷贝直通环' },
];

function formatTelemetryBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const exp = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const val = bytes / Math.pow(1024, exp);
  return `${val >= 10 ? val.toFixed(1) : val.toFixed(2)} ${units[exp]}`;
}

async function refreshRuntimeTelemetry() {
  try {
    const [zc, xdp] = await Promise.all([
      invoke<KernelZeroCopyTelemetry>('get_kernel_zero_copy_telemetry_cmd'),
      invoke<XdpBypassMetrics>('get_xdp_bypass_metrics_cmd'),
    ]);
    zeroCopyTelemetry.value = zc;
    xdpMetrics.value = xdp;
  } catch (e) {
    console.warn('[RUNTIME_TELEMETRY] 内核遥测调用返回异常:', e);
  }
}

async function applyXdpPreset(preset: string) {
  switchingXdpPolicy.value = true;
  try {
    const msg = await invoke<string>('apply_xdp_policy_preset_cmd', { preset });
    await refreshRuntimeTelemetry();
    notifySuccess('eBPF 字节码策略已部署', msg);
  } catch (e) {
    notifyError('eBPF 策略部署受阻', String(e));
  } finally {
    switchingXdpPolicy.value = false;
  }
}

function startTelemetryPolling() {
  if (telemetryTimer) return;
  telemetryTimer = setInterval(() => {
    if (props.isOpen) {
      refreshRuntimeTelemetry();
    }
  }, 2000);
}

function stopTelemetryPolling() {
  if (telemetryTimer) {
    clearInterval(telemetryTimer);
    telemetryTimer = null;
  }
}

// 启动跳过选项管理 (本地存储持久化，满足用户灵活切换要求)
const skipStartupModal = ref(localStorage.getItem('omni_probe_skip_startup_env_modal') === 'true');
function onToggleSkipStartup() {
  localStorage.setItem('omni_probe_skip_startup_env_modal', skipStartupModal.value ? 'true' : 'false');
  if (skipStartupModal.value) {
    notifySuccess('偏好设置已更新', '下次启动时将跳过主动弹窗，保持后台多轨自愈运行；您可随时点击顶栏环境诊断重新呼出');
  } else {
    notifySuccess('偏好设置已更新', '下次启动若存在缺失外部依赖，将主动弹出全景环境诊断中心');
  }
}

// 安装交互状态管理
const confirmingComponent = ref<string | null>(null);
const installingMap = ref<Record<string, DownloadProgressPayload>>({});
const launchedMap = ref<Record<string, boolean>>({});

let unlistenProgress: (() => void) | null = null;

const isNpcapReady = computed(() => {
  return report.value?.components.find(c => c.id === 'npcap')?.is_ready || false;
});

const isTsharkReady = computed(() => {
  return report.value?.components.find(c => c.id === 'tshark')?.is_ready || false;
});

const isUsbpcapReady = computed(() => {
  return report.value?.components.find(c => c.id === 'usbpcap')?.is_ready || false;
});

const isIpDbReady = computed(() => {
  return report.value?.components.find(c => c.id === 'ip_db')?.is_ready || false;
});

const scoreColorClass = computed(() => {
  const s = report.value?.readiness_score || 0;
  if (s >= 90) return 'text-emerald-500';
  if (s >= 50) return 'text-amber-500';
  return 'text-rose-500';
});

const badgeColorClass = computed(() => {
  const s = report.value?.readiness_score || 0;
  if (s >= 90) return 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/30';
  if (s >= 50) return 'bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30';
  return 'bg-rose-500/15 text-rose-700 dark:text-rose-400 border-rose-500/30';
});

const statusText = computed(() => {
  const level = report.value?.status_level;
  if (level === 'Optimal') return '工业最佳全能态';
  if (level === 'Standard') return '工业标准运行态';
  return '多轨自愈兜底态';
});

async function refreshInspection() {
  loading.value = true;
  try {
    const [res] = await Promise.all([
      invoke<EnvironmentReport>('get_environment_inspection_cmd'),
      refreshRuntimeTelemetry(),
    ]);
    report.value = res;
  } catch (e) {
    console.error('[ENV_INSPECTOR] 诊断失败:', e);
  } finally {
    loading.value = false;
  }
}

async function startAutoInstall(componentId: string) {
  confirmingComponent.value = null;
  installingMap.value[componentId] = {
    component_id: componentId,
    status: 'downloading',
    percent: 0,
    downloaded_bytes: 0,
    total_bytes: 1024 * 1024,
  };

  try {
    const res: string = await invoke('download_and_install_component_cmd', {
      componentId,
    });
    delete installingMap.value[componentId];
    launchedMap.value[componentId] = true;
    notifySuccess('装配引导已启动', res || '已成功唤起官方安装程序向导，请完成安装后点击刷新检测');
  } catch (e: any) {
    delete installingMap.value[componentId];
    notifyError('驱动安装引导受阻', e);
  }
}

function finishAndRecheck(componentId: string) {
  delete launchedMap.value[componentId];
  refreshInspection();
}

async function openLink(url: string) {
  if (!url) return;
  try {
    await openUrl(url);
  } catch (e) {
    notifyError('无法唤起系统关联程序打开链接', String(e));
  }
}

watch(() => props.isOpen, (open) => {
  if (open) {
    refreshInspection();
    startTelemetryPolling();
  } else {
    stopTelemetryPolling();
  }
});

onMounted(async () => {
  refreshInspection();
  if (props.isOpen) {
    startTelemetryPolling();
  }
  try {
    unlistenProgress = await listen<DownloadProgressPayload>('installer-download-progress', (event) => {
      const p = event.payload;
      if (p.status === 'completed') {
        delete installingMap.value[p.component_id];
        launchedMap.value[p.component_id] = true;
      } else if (p.status === 'error') {
        delete installingMap.value[p.component_id];
        notifyError('官方安装包下载异常', p.error_msg);
      } else {
        installingMap.value[p.component_id] = p;
      }
    });
  } catch (e) {
    console.warn('[PROGRESS_LISTENER] 无法监听下载事件:', e);
  }
});

onUnmounted(() => {
  stopTelemetryPolling();
  if (unlistenProgress) {
    unlistenProgress();
  }
});
</script>
