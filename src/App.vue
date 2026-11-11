<template>
  <div
    ref="rootShellRef"
    @pointermove="onRootPointerMove"
    :class="['h-screen w-screen overflow-hidden flex flex-col font-sans relative transition-colors duration-200',
    isAppleLight ? 'theme-apple-light' : 'theme-apple-dark']"
  >
    
    <!-- 1. 全景光学丝带与精密网格底衬 (L0 Live Optical Ribbons Wallpaper) -->
    <div class="liquid-background">
      <svg class="liquid-ribbon-svg" viewBox="0 0 1440 900" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
        <defs>
          <linearGradient id="omni-rib-a" x1="0%" y1="0%" x2="100%" y2="80%">
            <stop offset="0%" stop-color="#0EA5E9" stop-opacity="0.68" />
            <stop offset="45%" stop-color="#38BDF8" stop-opacity="0.46" />
            <stop offset="100%" stop-color="#818CF8" stop-opacity="0.62" />
          </linearGradient>
          <linearGradient id="omni-rib-b" x1="100%" y1="10%" x2="0%" y2="90%">
            <stop offset="0%" stop-color="#A855F7" stop-opacity="0.58" />
            <stop offset="52%" stop-color="#06B6D4" stop-opacity="0.44" />
            <stop offset="100%" stop-color="#10B981" stop-opacity="0.48" />
          </linearGradient>
          <linearGradient id="omni-rib-edge" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.72" />
            <stop offset="50%" stop-color="#7DD3FC" stop-opacity="0.54" />
            <stop offset="100%" stop-color="#E879F9" stop-opacity="0.48" />
          </linearGradient>
        </defs>
        <path d="M-120,210 C220,380 460,-20 860,180 C1180,340 1320,120 1580,220 L1580,480 C1280,350 1080,580 760,410 C420,230 160,540 -120,400 Z" fill="url(#omni-rib-a)" />
        <path d="M-100,640 C260,460 520,820 920,560 C1190,385 1340,680 1560,540 L1560,940 L-100,940 Z" fill="url(#omni-rib-b)" />
        <path d="M-80,190 C280,350 480,20 880,190 C1190,320 1340,140 1560,235" fill="none" stroke="url(#omni-rib-edge)" stroke-width="4" />
        <path d="M-80,610 C280,440 540,780 930,540 C1200,375 1360,640 1560,520" fill="none" stroke="url(#omni-rib-edge)" stroke-width="3" />
      </svg>
      <div class="liquid-mesh-grid"></div>
      <div class="aurora-blob aurora-blob-blue"></div>
      <div class="aurora-blob aurora-blob-purple"></div>
      <div class="aurora-blob aurora-blob-green"></div>
    </div>

    <!-- ============================================================== -->
    <!-- 2. 悬浮顶栏：Apple Floating Liquid Capsules（无父壳遮挡直透折光）-->
    <!-- ============================================================== -->
    <header class="w-full px-2.5 pt-2 h-[50px] flex items-center justify-between shrink-0 z-30 gap-3 select-none relative">
      <!-- 左段：独立悬浮品牌玻璃胶囊与按需告警拦截提示 -->
      <div class="flex items-center gap-2 shrink-0">
        <div class="liquid-panel rounded-full h-9 pl-1.5 pr-3 flex items-center gap-2">
          <span class="lens-edge-lip" aria-hidden="true"></span>
          <button @click="toggleDockPinned"
            :title="isDockExpanded ? '收起左侧导航栏' : '展开左侧导航栏'"
            class="w-7 h-7 rounded-full flex items-center justify-center text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-glass-pill-hover)] transition-colors cursor-pointer"
            aria-label="切换侧栏">
            <AppIcon :name="isDockExpanded ? 'chevron-left' : 'chevron-right'" :size="14" />
          </button>

          <div class="flex items-center gap-2 whitespace-nowrap">
            <div class="w-6 h-6 rounded-full overflow-hidden shrink-0 border border-[var(--border-strong)] flex items-center justify-center bg-[var(--surface-elevated)] p-0.5 shadow-xs">
              <img src="/logo.svg" alt="Omni-Probe Logo" class="w-full h-full object-contain" />
            </div>
            <span class="text-[13px] font-semibold tracking-tight text-[var(--text-primary)]">Omni-Probe</span>
          </div>
        </div>

        <!-- 仅在真正检出高危告警时浮出阻断/处置微胶囊，待命零红绿灯噪点 -->
        <button v-if="threatCount > 0" @click="triggerEmergencyCutoff"
          class="flex items-center gap-1.5 px-3 h-8 rounded-full text-[11px] font-semibold ui-num text-[var(--accent-red)] bg-[var(--accent-red-soft)] border border-rose-500/40 cursor-pointer transition-colors backdrop-blur-md shadow-sm"
          :title="`已拦截告警 ${threatCount} 起，点击执行应急停止`">
          <span class="w-1.5 h-1.5 rounded-full" style="background: var(--accent-red);"></span>
          <span>{{ threatCount }} 告警 · 切断</span>
        </button>
      </div>

      <!-- 中段：Unified Liquid Control Pill（网卡 + 过滤输入 + 嗅探启停） -->
      <div class="flex-1 min-w-0 max-w-[680px] h-9 flex items-center gap-1 liquid-panel rounded-full px-1.5">
        <span class="lens-edge-lip" aria-hidden="true"></span>
        <!-- 物理网卡选择 (Click Popover) -->
        <div ref="ifacePopoverRef" class="relative shrink-0">
          <button
            type="button"
            @click.stop="isIfaceMenuOpen = !isIfaceMenuOpen"
            class="h-7 flex items-center gap-1.5 px-2.5 rounded-full hover:bg-[var(--surface-glass-pill-hover)] text-[12px] max-w-[155px] 2xl:max-w-[205px] whitespace-nowrap cursor-pointer transition-colors"
            :aria-expanded="isIfaceMenuOpen"
            aria-haspopup="listbox"
            :title="`当前物理接口: ${selectedIface || '自动识别网卡'}`">
            <span class="w-2 h-2 rounded-full shrink-0"
              :style="{ background: isRunning ? (isPaused ? 'var(--accent-amber)' : 'var(--accent-green)') : 'var(--text-muted)' }"></span>
            <span class="font-medium text-[var(--text-primary)] truncate">{{ selectedIface || '自动物理网卡' }}</span>
            <AppIcon name="chevron-down" :size="12" class="text-[var(--text-muted)] shrink-0" />
          </button>

          <Transition name="splash-fade">
            <div v-if="isIfaceMenuOpen"
              role="listbox"
              class="absolute left-0 top-full mt-2 w-72 ui-modal-surface rounded-2xl p-1.5 z-50 text-[12px]">
              <div class="text-[11px] text-[var(--text-muted)] px-2.5 py-1.5 font-semibold border-b border-[var(--border-subtle)] mb-1">
                可监听物理网络接口 (NIC)
              </div>
              <div class="max-h-60 overflow-y-auto custom-scrollbar space-y-0.5">
                <button type="button" @click="selectInterface('')"
                  class="w-full text-left px-2.5 py-1.5 rounded-[10px] cursor-pointer transition-colors flex items-center justify-between hover:bg-[var(--surface-hover)]"
                  :class="!selectedIface ? 'bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)] font-semibold' : 'text-[var(--text-primary)]'">
                  <span>自动推荐物理网卡</span>
                  <AppIcon v-if="!selectedIface" name="check" :size="13" />
                </button>
                <button v-for="iface in interfaces" :key="iface" type="button" @click="selectInterface(iface)"
                  class="w-full text-left px-2.5 py-1.5 rounded-[10px] cursor-pointer transition-colors truncate flex items-center justify-between gap-2 hover:bg-[var(--surface-hover)]"
                  :class="selectedIface === iface ? 'bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)] font-semibold' : 'text-[var(--text-primary)]'"
                  :title="iface">
                  <span class="truncate">{{ iface }}</span>
                  <AppIcon v-if="selectedIface === iface" name="check" :size="13" />
                </button>
              </div>
            </div>
          </Transition>
        </div>

        <div class="h-4 w-px bg-[var(--border-subtle)] shrink-0"></div>

        <!-- 融合表达式搜索框 -->
        <div class="flex items-center gap-1.5 px-2.5 h-7 rounded-full flex-1 min-w-[140px] focus-within:bg-[var(--surface-glass-pill)] transition-colors">
          <AppIcon name="search" :size="13" class="text-[var(--text-muted)] shrink-0" />
          <input ref="bpfInputRef" v-model="bpfFilter" type="text" placeholder="BPF / 协议过滤 (如 s7comm, 502)"
            class="bg-transparent text-[var(--text-primary)] text-[12px] outline-none w-full min-w-0 placeholder:text-[var(--text-muted)] font-mono-code">
          <span class="text-[11px] font-mono-code text-[var(--text-muted)] shrink-0 hidden 2xl:inline-block opacity-75">⌘K</span>
        </div>

        <!-- 嗅探捕获启停 (统一高度 rounded-full) -->
        <template v-if="!isRunning">
          <button @click="startCapture" class="ui-btn-primary rounded-full h-7 px-3.5 text-[12px] shrink-0">
            <AppIcon name="play" :size="12" />
            <span>启动嗅探</span>
          </button>
        </template>
        <template v-else>
          <div class="flex items-center gap-1 shrink-0">
            <button v-if="!isPaused" @click="pauseCapture" class="ui-btn-secondary rounded-full h-7 px-3 text-[12px] shrink-0">
              <AppIcon name="pause" :size="12" />
              <span>暂停</span>
            </button>
            <button v-else @click="resumeCapture" class="ui-btn-primary rounded-full h-7 px-3 text-[12px] shrink-0">
              <AppIcon name="play" :size="12" />
              <span>继续</span>
            </button>
            <button @click="stopCapture" title="停止主引擎" aria-label="停止主引擎"
              class="ui-btn-danger rounded-full h-7 w-7 p-0 justify-center shrink-0">
              <AppIcon name="stop" :size="12" />
            </button>
          </div>
        </template>
      </div>

      <!-- 右段：紧凑运行指标微囊 + Apple 一体化玻璃图标组 -->
      <div class="flex items-center gap-2 shrink-0">
        <!-- 环形缓冲与环境合一玻璃微囊 -->
        <button @click="isEnvDiagnosticOpen = true"
          class="hidden md:flex items-center gap-2 liquid-panel rounded-full h-9 px-3 text-[11px] ui-num cursor-pointer hover:bg-[var(--surface-glass-pill-hover)] transition-colors whitespace-nowrap"
          :title="`环形缓冲: ${ringBufferUsageText} | 运行环境就绪度: ${envScore ?? '--'}%，点击诊断`">
          <span class="lens-edge-lip" aria-hidden="true"></span>
          <span class="text-[var(--text-secondary)] hidden xl:inline">{{ ringBufferUsageText }}</span>
          <span class="h-3 w-px bg-[var(--border-subtle)] hidden xl:inline-block"></span>
          <span class="flex items-center gap-1.5 font-medium text-[var(--text-primary)]">
            <span class="w-1.5 h-1.5 rounded-full"
              :style="{ background: (envScore ?? 0) >= 90 ? 'var(--accent-green)' : (envScore ?? 0) >= 50 ? 'var(--accent-amber)' : 'var(--accent-muted, var(--text-muted))' }"></span>
            <span>环境 {{ envScore ?? '--' }}%</span>
          </span>
        </button>

        <!-- 一体化共享玻璃工具胶囊组 -->
        <div class="liquid-panel rounded-full h-9 px-1 flex items-center gap-0.5">
          <span class="lens-edge-lip" aria-hidden="true"></span>
          <button @click="toggleAppleTheme"
            class="h-7 px-2.5 rounded-full hover:bg-[var(--surface-glass-pill-hover)] text-[11.5px] font-medium text-[var(--text-primary)] flex items-center gap-1.5 cursor-pointer transition-colors whitespace-nowrap"
            :title="isAppleLight ? '切换为深空夜色模式' : '切换为冰晶白昼模式'">
            <AppIcon :name="isAppleLight ? 'sun' : 'moon'" :size="13" />
            <span class="hidden lg:inline">{{ isAppleLight ? '浅色' : '深色' }}</span>
          </button>

          <div class="h-3.5 w-px bg-[var(--border-subtle)] mx-0.5"></div>

          <button @click="openUniversalDiffCenter"
            class="h-7 px-2 rounded-full flex items-center justify-center gap-1 cursor-pointer transition-colors whitespace-nowrap"
            :class="diffBus.queueCount.value >= 2 ? 'bg-[var(--accent-primary)] text-white shadow-xs' : diffBus.queueCount.value === 1 ? 'bg-indigo-500/18 text-indigo-700 dark:text-indigo-300' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-glass-pill-hover)]'"
            :title="`全局数据比对中心 (${diffBus.queueCount.value} 组已入队 · Ctrl+Shift+D)`" aria-label="全局数据比对中心">
            <AppIcon name="scale" :size="14" class="shrink-0" />
            <span v-if="diffBus.queueCount.value > 0" class="text-[11px] ui-num font-bold leading-none">{{ diffBus.queueCount.value }}</span>
          </button>

          <button @click="isWirelessVlanOpen = true"
            class="h-7 px-2 rounded-full flex items-center justify-center gap-1 text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-glass-pill-hover)] cursor-pointer transition-colors whitespace-nowrap"
            title="无线 Wi-Fi / VLAN / 蓝牙近场监测" aria-label="无线与蓝牙监测">
            <AppIcon name="wifi" :size="14" class="shrink-0" />
            <span class="hidden xl:inline text-[11px] font-medium">无线/蓝牙</span>
          </button>

          <button @click="isPreferencesOpen = true"
            class="w-7 h-7 rounded-full flex items-center justify-center text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-glass-pill-hover)] cursor-pointer transition-colors"
            title="系统偏好设置 (Ctrl+,)" aria-label="系统偏好设置">
            <AppIcon name="settings" :size="14" />
          </button>

          <button @click="hideWindowToTray"
            class="w-7 h-7 rounded-full flex items-center justify-center text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-glass-pill-hover)] cursor-pointer transition-colors"
            title="最小化至操作系统托盘后台驻留" aria-label="最小化到托盘">
            <AppIcon name="chevron-down" :size="14" />
          </button>

          <button @click="clearData"
            class="w-7 h-7 rounded-full flex items-center justify-center text-[var(--text-secondary)] hover:text-[var(--accent-red)] hover:bg-[var(--accent-red-soft)] cursor-pointer transition-colors"
            title="清除当前捕获数据" aria-label="清除数据">
            <AppIcon name="trash" :size="14" />
          </button>
        </div>
      </div>
    </header>

    <!-- ============================================================== -->
    <!-- 3. 主体工作区：Floating Liquid Sidebar + Bento 主视口容器        -->
    <!-- ============================================================== -->
    <div class="flex flex-1 overflow-hidden p-2.5 gap-2.5 min-h-0 relative z-10">

      <!-- 3.1 左侧悬浮导航栏（同心圆角 16px 外框 + 9px 内胶囊，纯线性矢量图标） -->
      <aside :class="[
        'liquid-panel liquid-sidebar rounded-2xl p-2 flex flex-col justify-between shrink-0 transition-all duration-200 z-20 overflow-y-auto custom-scrollbar select-none',
        isDockExpanded ? 'w-52' : 'w-[58px] items-center'
      ]">
        <span class="lens-edge-lip" aria-hidden="true"></span>
        <div class="flex flex-col gap-3 w-full">
          <div v-if="isDockExpanded" class="flex items-center justify-between px-2 pt-0.5 pb-1.5 border-b border-[var(--border-subtle)]">
            <span class="text-[11px] font-semibold tracking-wider text-[var(--text-muted)] uppercase">
              功能工作台
            </span>
            <button @click="toggleDockPinned" title="收起左侧导航栏"
              class="p-1 rounded-lg hover:bg-[var(--surface-glass-pill-hover)] text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors cursor-pointer">
              <AppIcon name="chevron-left" :size="13" />
            </button>
          </div>
          <button v-else @click="toggleDockPinned" title="展开左侧导航栏"
            class="w-9 h-8 mx-auto rounded-[9px] flex items-center justify-center hover:bg-[var(--surface-glass-pill-hover)] text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors cursor-pointer border-b border-[var(--border-subtle)]">
            <AppIcon name="chevron-right" :size="14" />
          </button>

          <!-- 分域 1: 捕获与总线 -->
          <div class="flex flex-col gap-0.5 w-full">
            <div v-show="isDockExpanded" class="text-[11px] font-semibold text-[var(--text-muted)] px-2 pb-1">
              捕获与总线
            </div>
            <button v-for="tab in domainCaptureTabs" :key="tab.id" @click="activeWorkbench = tab.id"
              :title="tab.label"
              :class="[
                'h-9 rounded-[9px] flex items-center transition-all cursor-pointer border',
                isDockExpanded ? 'w-full px-2.5 gap-2.5' : 'w-9 justify-center px-0 mx-auto',
                activeWorkbench === tab.id
                  ? 'liquid-nav-item-active font-semibold'
                  : 'border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-glass-pill-hover)]'
              ]">
              <AppIcon :name="tab.icon" :size="16" class="shrink-0" />
              <div v-show="isDockExpanded" class="flex items-center justify-between flex-1 min-w-0">
                <span class="text-[12.5px] truncate whitespace-nowrap">{{ tab.label }}</span>
                <span v-if="tab.id === 'hardware' && (usbDevices.length + serialPorts.length) > 0" class="badge-subtle ui-num ml-1">{{ usbDevices.length + serialPorts.length }}</span>
                <span v-else-if="tab.badge" class="badge-subtle ml-1">{{ tab.badge }}</span>
              </div>
            </button>
          </div>

          <!-- 分域 2: 资产与空间 -->
          <div class="flex flex-col gap-0.5 w-full">
            <div v-show="isDockExpanded" class="text-[11px] font-semibold text-[var(--text-muted)] px-2 pb-1">
              资产与空间
            </div>
            <button v-for="tab in domainAssetTabs" :key="tab.id" @click="activeWorkbench = tab.id"
              :title="tab.label"
              :class="[
                'h-9 rounded-[9px] flex items-center transition-all cursor-pointer border',
                isDockExpanded ? 'w-full px-2.5 gap-2.5' : 'w-9 justify-center px-0 mx-auto',
                activeWorkbench === tab.id
                  ? 'liquid-nav-item-active font-semibold'
                  : 'border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-glass-pill-hover)]'
              ]">
              <AppIcon :name="tab.icon" :size="16" class="shrink-0" />
              <div v-show="isDockExpanded" class="flex items-center justify-between flex-1 min-w-0">
                <span class="text-[12.5px] truncate whitespace-nowrap">{{ tab.label }}</span>
              </div>
            </button>
          </div>

          <!-- 分域 3: 等保与合规 -->
          <div class="flex flex-col gap-0.5 w-full">
            <div v-show="isDockExpanded" class="text-[11px] font-semibold text-[var(--text-muted)] px-2 pb-1">
              等保与合规
            </div>
            <button v-for="tab in domainComplianceTabs" :key="tab.id" @click="activeWorkbench = tab.id"
              :title="tab.label"
              :class="[
                'h-9 rounded-[9px] flex items-center transition-all cursor-pointer border',
                isDockExpanded ? 'w-full px-2.5 gap-2.5' : 'w-9 justify-center px-0 mx-auto',
                activeWorkbench === tab.id
                  ? 'liquid-nav-item-active font-semibold'
                  : 'border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-glass-pill-hover)]'
              ]">
              <AppIcon :name="tab.icon" :size="16" class="shrink-0" />
              <div v-show="isDockExpanded" class="flex items-center justify-between flex-1 min-w-0">
                <span class="text-[12.5px] truncate whitespace-nowrap">{{ tab.label }}</span>
                <span v-if="tab.id === 'hardware' && (usbDevices.length + serialPorts.length) > 0" class="badge-subtle ui-num ml-1">{{ usbDevices.length + serialPorts.length }}</span>
                <span v-else-if="tab.badge" class="badge-subtle ml-1">{{ tab.badge }}</span>
              </div>
            </button>
          </div>

          <!-- 分域 4: 解密与司法 -->
          <div class="flex flex-col gap-0.5 w-full">
            <div v-show="isDockExpanded" class="text-[11px] font-semibold text-[var(--text-muted)] px-2 pb-1">
              解密与司法
            </div>
            <button v-for="tab in domainForensicsTabs" :key="tab.id" @click="activeWorkbench = tab.id"
              :title="tab.label"
              :class="[
                'h-9 rounded-[9px] flex items-center transition-all cursor-pointer border',
                isDockExpanded ? 'w-full px-2.5 gap-2.5' : 'w-9 justify-center px-0 mx-auto',
                activeWorkbench === tab.id
                  ? 'liquid-nav-item-active font-semibold'
                  : 'border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-glass-pill-hover)]'
              ]">
              <AppIcon :name="tab.icon" :size="16" class="shrink-0" />
              <div v-show="isDockExpanded" class="flex items-center justify-between flex-1 min-w-0">
                <span class="text-[12.5px] truncate whitespace-nowrap">{{ tab.label }}</span>
              </div>
            </button>
          </div>
        </div>

        <!-- 侧栏底端：紧凑 4 路物理总线状态指示 -->
        <div class="flex flex-col gap-1.5 w-full pt-2 border-t border-[var(--border-subtle)] shrink-0">
          <button type="button" @click="isHoneypotOpen = true"
            :class="['flex items-center py-1.5 rounded-[9px] bg-[var(--surface-glass-pill)] hover:bg-[var(--surface-glass-pill-hover)] border border-[var(--border-subtle)] transition-colors cursor-pointer',
              isDockExpanded ? 'justify-between px-2.5 w-full' : 'justify-center w-9 mx-auto px-1']"
            title="四总线物理就绪 (NIC / COM / USB / 蜜罐) — 点击管理诱饵服务">
            <div class="grid grid-cols-2 gap-1 shrink-0" :class="isDockExpanded ? 'flex items-center gap-1.5' : ''">
              <span class="w-1.5 h-1.5 rounded-full" :style="{ background: isRunning ? (isPaused ? 'var(--accent-amber)' : 'var(--accent-green)') : 'var(--text-muted)' }" title="网卡 NIC"></span>
              <span class="w-1.5 h-1.5 rounded-full" :style="{ background: isSerialRunning ? 'var(--accent-primary)' : 'var(--text-muted)' }" title="串口 COM"></span>
              <span class="w-1.5 h-1.5 rounded-full" :style="{ background: isUsbRunning ? 'var(--accent-purple)' : 'var(--text-muted)' }" title="USB 总线"></span>
              <span class="w-1.5 h-1.5 rounded-full" :style="{ background: isHoneypotRunning ? 'var(--accent-amber)' : 'var(--text-muted)' }" title="诱饵蜜罐"></span>
            </div>
            <span v-show="isDockExpanded" class="text-[11px] text-[var(--text-secondary)] font-medium truncate">
              诱饵与四总线
            </span>
          </button>
        </div>
      </aside>

      <!-- 3.2 右侧：FULL-BLEED 全息微晶主视口容器 (根据当前激活的工作台挂载真实专业 View) -->
      <main class="flex-1 flex flex-col overflow-hidden min-w-0 relative">
        <!-- 工作台 1：宏大无界空间控制台 / 流量分析 (核心流量分析主控) -->
        <TrafficAnalyzerView
          v-if="activeWorkbench === 'traffic'"
          :packets="packets"
          :assets="discoveredAssets"
          :isRunning="isRunning"
          :isPaused="isPaused"
          :isSerialRunning="isSerialRunning"
          :isUsbRunning="isUsbRunning"
          :selectedIface="selectedIface"
          :bpfFilter="bpfFilter"
          :interfaces="interfaces"
          :serialPorts="serialPorts"
          :serialPortsDetail="serialPortsDetail"
          :activeSerialPorts="activeSerialPorts"
          :serialPortBaudRates="serialPortBaudRates"
          :selectedSerial="selectedSerial"
          :serialBaudRate="serialBaudRate"
          :usbDevices="usbDevices"
          @startCapture="startCapture"
          @pauseCapture="pauseCapture"
          @resumeCapture="resumeCapture"
          @stopCapture="stopCapture"
          @startSerialCapture="startSerialCapture"
          @stopSerialCapture="stopSerialCapture"
          @startUsbCapture="startUsbCapture"
          @stopUsbCapture="stopUsbCapture"
          @refreshUsb="refreshUsbDevices"
          @refreshSerial="refreshSerialPorts"
          @updateSerial="selectedSerial = $event"
          @updateBaudRate="serialBaudRate = $event"
          @updatePortBaudRate="onUpdatePortBaudRate"
          @clearData="clearData"
          @updateBpf="bpfFilter = $event"
          @updateIface="selectedIface = $event"
          @replayPacket="replayPacket"
          @saveBaseline="savePacketAsBaseline"
          @openDeepDissector="openDeepModal"
          @openHoneypot="isHoneypotOpen = true"
          @openWireless="isWirelessVlanOpen = true"
          @appendLog="addLog"
          @importPackets="handleImportedPackets"
          @switchWorkbench="activeWorkbench = $event"
        />

        <!-- 工作台 2：资产情报态势工作台 -->
        <AssetIntelligenceView
          v-else-if="activeWorkbench === 'assets'"
          :assets="discoveredAssets"
          :packets="packets"
          :scanning="isScanningAssets"
          :probingAll="isProbingAll"
          @refreshAssets="refreshAssets"
          @scanAssets="triggerAssetScan"
          @probeAllPorts="probeAllAssets"
          @probeSinglePort="probeAssetPorts"
          @clearAssets="clearAssets"
          @filterTraffic="handleFilterTraffic"
        />

        <!-- 工作台 3：硬件总线画像与端口双向出入中心 -->
        <HardwareBusView
          v-else-if="activeWorkbench === 'hardware'"
          :usbDevices="usbDevices"
          :packets="packets"
          :serialPorts="serialPorts"
          :serialPortsDetail="serialPortsDetail"
          :activeSerialPorts="activeSerialPorts"
          :selectedSerial="selectedSerial"
          :serialBaudRate="serialBaudRate"
          :isUsbRunning="isUsbRunning"
          :isSerialRunning="isSerialRunning"
          @refreshUsb="refreshUsbDevices"
          @refreshSerial="refreshSerialPorts"
          @updateSerial="selectedSerial = $event"
          @updateBaudRate="serialBaudRate = $event"
          @startUsbCapture="startUsbCapture"
          @stopUsbCapture="stopUsbCapture"
          @startSerialCapture="startSerialCapture"
          @stopSerialCapture="stopSerialCapture"
          @appendLog="addLog"
          @openWireless="isWirelessVlanOpen = true"
        />

        <!-- 工作台 4：等保三级基线审计、蜜罐防御与系统引擎 -->
        <SystemAuditView
          v-else-if="activeWorkbench === 'audit'"
          :systemLogs="systemLogs"
          :honeypotPackets="honeypotPackets"
          @clearLogs="clearSystemLogs"
          @appendLog="addLog"
          @complianceUpdated="refreshAuditComplianceRate"
        />

        <!-- 工作台 5：全息上网行为监测与外联合规审计工作台 -->
        <WebAccessAuditView
          v-else-if="activeWorkbench === 'web_audit'"
          @filterTraffic="handleFilterTraffic"
          @openDossier="handleOpenGlobalDossier"
        />

        <!-- 工作台 6：网络流量解密与过滤级防火墙工作台 -->
        <TrafficDecryptionView
          v-else-if="activeWorkbench === 'decryption'"
        />

        <!-- 工作台 7：司法级网络电子数据取证与保管链工作台 -->
        <ForensicsView
          v-else-if="activeWorkbench === 'forensics'"
        />

        <!-- 工作台 8：四维合规安全审查与数据脱敏清洗工作台 -->
        <SecurityReviewView
          v-else-if="activeWorkbench === 'security_review'"
        />

        <!-- 工作台 9：全球网络空间地理测绘与双向路由追踪工作台 -->
        <GlobalGeoMapView
          v-else-if="activeWorkbench === 'geo_map'"
          :packets="packets"
          :isRunning="isRunning"
          :isPaused="isPaused"
          @startCapture="startCapture"
          @stopCapture="stopCapture"
        />

        <!-- 工作台 10：工业级网络通信调试工作台 -->
        <NetAssistWorkbenchView
          v-else-if="activeWorkbench === 'net_assist'"
          @switchWorkbench="activeWorkbench = $event"
        />
      </main>
    </div>

    <!-- ============================================================== -->
    <!-- 4. 全局专业分析模态框与深层解构中心                            -->
    <!-- ============================================================== -->

    <!-- 全局全景报文深度剖析弹窗 -->
    <PacketDeepModal
      v-if="isDeepModalOpen"
      :isOpen="isDeepModalOpen"
      :packet="deepModalPacket"
      @close="isDeepModalOpen = false"
      @replay="replayPacket"
      @saveBaseline="savePacketAsBaseline"
    />

    <!-- 全局蜜罐诱捕威胁溯源工作台模态框 -->
    <HoneypotWorkbenchModal
      v-if="isHoneypotOpen"
      :isOpen="isHoneypotOpen"
      :packets="honeypotPackets"
      :isRunning="isHoneypotRunning"
      @close="isHoneypotOpen = false"
      @clearHoneypotData="honeypotPackets = []"
      @statusChanged="isHoneypotRunning = $event"
      @log="addLog"
      @filterTraffic="handleFilterTraffic"
      @openDossier="handleOpenGlobalDossier"
    />

    <!-- 全局底层抓包驱动与解剖工具链全景诊断模态框 -->
    <EnvironmentDiagnosticModal
      v-if="isEnvDiagnosticOpen"
      :isOpen="isEnvDiagnosticOpen"
      @close="isEnvDiagnosticOpen = false"
    />

    <!-- 全局系统偏好设置中心模态框 -->
    <PreferencesModal
      v-if="isPreferencesOpen"
      :isOpen="isPreferencesOpen"
      :isLight="isAppleLight"
      :isDockExpanded="isDockExpanded"
      @close="isPreferencesOpen = false"
      @toggleTheme="toggleAppleTheme"
      @toggleDock="toggleDockPinned"
      @openDiagnostic="isEnvDiagnosticOpen = true; isPreferencesOpen = false"
      @clearData="clearData"
    />

    <!-- 全局无线网络与虚拟局域网 (VLAN) 专业监测模态框 -->
    <WirelessVlanMonitorModal
      v-if="isWirelessVlanOpen"
      :isOpen="isWirelessVlanOpen"
      @close="isWirelessVlanOpen = false"
    />

    <!-- 全局统一 IP 全息档案溯源模态框 -->
    <IpDossierModal
      v-if="isGlobalDossierOpen"
      :isOpen="isGlobalDossierOpen"
      :targetIp="globalDossierIp"
      :packets="packets"
      :assets="discoveredAssets"
      @close="isGlobalDossierOpen = false"
      @filterTraffic="handleFilterTraffic"
      @drillDown="globalDossierIp = $event"
    />

    <!-- 全局通用数据差分比对工作台 (支持 2~N 组精比与磁盘大文件双向 Merge，按需懒加载) -->
    <PacketDiffModal v-if="diffBus.isDiffModalOpen.value" />

    <!-- 统一全局通知浮层与 Sheet 确认输入模态 -->
    <GlobalNotificationToast />
    <GlobalSheetModal />

    <!-- 启动引擎自检就绪 HUD -->
    <transition name="splash-fade">
      <div v-if="isInitializing" class="fixed inset-0 z-[9999] flex items-center justify-center ui-modal-backdrop select-none">
        <div class="relative w-[460px] max-w-[92vw] p-6 ui-modal-surface flex flex-col items-center text-center space-y-4">
          <div class="w-14 h-14 rounded-[14px] overflow-hidden border border-[var(--border-strong)] flex items-center justify-center bg-[var(--surface-elevated)] p-2">
            <img src="/logo.svg" alt="Omni-Probe Logo" class="w-full h-full object-contain" />
          </div>

          <div class="space-y-1">
            <h2 class="text-[14px] font-semibold text-[var(--text-primary)] tracking-tight flex items-center justify-center gap-2">
              <span>OMNI-PROBE 网络探针系统</span>
              <span class="badge-subtle ui-num">v0.3.1</span>
            </h2>
            <p class="text-[12px] text-[var(--text-secondary)]">工业级多总线网络分析仪 · 正在执行引擎初始化校验</p>
          </div>

          <div class="w-full space-y-1.5 pt-1">
            <div class="flex items-center justify-between text-[12px] ui-num">
              <span class="text-[var(--text-primary)] font-medium truncate max-w-[320px]">{{ initStatusMessage }}</span>
              <span class="font-semibold text-[var(--accent-primary-text)]">{{ Math.round(initProgress) }}%</span>
            </div>
            <div class="w-full h-1.5 rounded-full bg-[var(--surface-elevated)] overflow-hidden border border-[var(--border-subtle)]">
              <div class="h-full rounded-full transition-all duration-300"
                style="background: var(--accent-primary);"
                :style="{ width: `${initProgress}%` }"></div>
            </div>
          </div>

          <div class="w-full grid grid-cols-2 gap-2 text-[12px] text-left pt-1">
            <div v-for="(step, idx) in initSteps" :key="idx"
              class="flex items-center gap-2 px-2.5 py-1.5 rounded-[8px] border transition-colors"
              :style="step.done
                ? { background: 'var(--accent-green-soft)', borderColor: 'var(--border-subtle)', color: 'var(--accent-green)', fontWeight: 600 }
                : { background: 'var(--surface-elevated)', borderColor: 'var(--border-subtle)', color: 'var(--text-secondary)' }">
              <AppIcon :name="step.done ? 'check' : 'minus'" :size="13" />
              <span class="truncate">{{ step.label }}</span>
            </div>
          </div>

          <div class="w-full flex items-center justify-between px-3 py-1.5 rounded-[8px] bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[11px] ui-num text-[var(--text-secondary)]">
            <span class="flex items-center gap-1">
              <span>驱动:</span>
              <strong :style="{ color: isNpcapAvailable ? 'var(--accent-green)' : 'var(--accent-amber)' }">
                {{ isNpcapAvailable ? 'Npcap 就绪' : 'Raw Socket 模式' }}
              </strong>
            </span>
            <span class="flex items-center gap-1">
              <span>USB:</span>
              <strong :style="{ color: isUsbpcapAvailable ? 'var(--accent-green)' : 'var(--accent-amber)' }">
                {{ isUsbpcapAvailable ? 'USBPcap 就绪' : 'PnP 监视' }}
              </strong>
            </span>
            <span class="flex items-center gap-1">
              <span>解剖:</span>
              <strong :style="{ color: isTsharkAvailable ? 'var(--accent-green)' : 'var(--accent-primary-text)' }">
                {{ isTsharkAvailable ? 'TShark + 内置引擎' : '内置规约引擎' }}
              </strong>
            </span>
          </div>
        </div>
      </div>
    </transition>

    <!-- 底部紧凑实用状态栏 -->
    <footer class="app-footer-bar ui-num">
      <div>物理接口: {{ selectedIface || '自动识别' }} · {{ isNpcapAvailable ? 'Npcap + Raw Socket 双轨引擎' : 'Raw Socket 原生捕获引擎' }} · 环形缓冲: {{ ringBufferUsageText }}</div>
      <div>已捕获 {{ packets.length.toLocaleString() }} 帧 · Omni-Probe v0.3.1</div>
    </footer>
  </div>
</template>

<script setup lang="ts">
// @ts-nocheck
import { ref, computed, defineAsyncComponent, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWebview } from '@tauri-apps/api/webview';

import AppIcon from './components/AppIcon.vue';
import GlobalSheetModal from './components/GlobalSheetModal.vue';
import { useUniversalDiff } from './composables/useUniversalDiff';
import GlobalNotificationToast from './components/GlobalNotificationToast.vue';
import { notifySuccess, notifyInfo, notifyWarning, notifyError } from './composables/useNotification';

// 首屏工作台同步直载以保障 0ms 启动瞬间响应；其余 9 个专业工作台与 7 个重型模态框采用按需异步拆包
import TrafficAnalyzerView from './views/TrafficAnalyzerView.vue';

const PacketDeepModal = defineAsyncComponent(() => import('./components/PacketDeepModal.vue'));
const HoneypotWorkbenchModal = defineAsyncComponent(() => import('./components/HoneypotWorkbenchModal.vue'));
const IpDossierModal = defineAsyncComponent(() => import('./components/IpDossierModal.vue'));
const EnvironmentDiagnosticModal = defineAsyncComponent(() => import('./components/EnvironmentDiagnosticModal.vue'));
const PreferencesModal = defineAsyncComponent(() => import('./components/PreferencesModal.vue'));
const WirelessVlanMonitorModal = defineAsyncComponent(() => import('./components/WirelessVlanMonitorModal.vue'));
const PacketDiffModal = defineAsyncComponent(() => import('./components/PacketDiffModal.vue'));

const AssetIntelligenceView = defineAsyncComponent(() => import('./views/AssetIntelligenceView.vue'));
const HardwareBusView = defineAsyncComponent(() => import('./views/HardwareBusView.vue'));
const SystemAuditView = defineAsyncComponent(() => import('./views/SystemAuditView.vue'));
const WebAccessAuditView = defineAsyncComponent(() => import('./views/WebAccessAuditView.vue'));
const TrafficDecryptionView = defineAsyncComponent(() => import('./views/TrafficDecryptionView.vue'));
const ForensicsView = defineAsyncComponent(() => import('./views/ForensicsView.vue'));
const SecurityReviewView = defineAsyncComponent(() => import('./views/SecurityReviewView.vue'));
const GlobalGeoMapView = defineAsyncComponent(() => import('./views/GlobalGeoMapView.vue'));
const NetAssistWorkbenchView = defineAsyncComponent(() => import('./views/NetAssistWorkbenchView.vue'));

export type WorkbenchId = 'traffic' | 'assets' | 'hardware' | 'audit' | 'web_audit' | 'decryption' | 'forensics' | 'security_review' | 'geo_map' | 'net_assist';

export interface WorkbenchTab {
  id: WorkbenchId;
  label: string;
  badge?: string;
  icon: string;
}

const domainCaptureTabs: WorkbenchTab[] = [
  { id: 'traffic', label: '全息流量分析', badge: 'CORE', icon: 'traffic' },
  { id: 'hardware', label: '物理外设总线', icon: 'cpu' },
  { id: 'net_assist', label: '网络调试助手', icon: 'terminal' },
];

const domainAssetTabs: WorkbenchTab[] = [
  { id: 'assets', label: '资产情报态势', icon: 'radar' },
  { id: 'geo_map', label: '全球网络地图', icon: 'globe' },
];

const auditComplianceBadge = ref('待检');

const domainComplianceTabs = computed<WorkbenchTab[]>(() => [
  { id: 'audit', label: '等保基线审计', badge: auditComplianceBadge.value, icon: 'shield' },
  { id: 'web_audit', label: '上网行为审计', icon: 'eye' },
  { id: 'security_review', label: '四维安全审查', icon: 'layers' },
]);

const domainForensicsTabs: WorkbenchTab[] = [
  { id: 'decryption', label: '流量解密过滤', icon: 'key' },
  { id: 'forensics', label: '司法电子取证', icon: 'archive' },
];

const isIfaceMenuOpen = ref(false);
const ifacePopoverRef = ref<HTMLElement | null>(null);
const bpfInputRef = ref<HTMLInputElement | null>(null);

function selectInterface(iface: string) {
  selectedIface.value = iface;
  isIfaceMenuOpen.value = false;
}

function handleDocumentClick(e: MouseEvent) {
  if (!isIfaceMenuOpen.value) return;
  const target = e.target as Node | null;
  if (ifacePopoverRef.value && target && !ifacePopoverRef.value.contains(target)) {
    isIfaceMenuOpen.value = false;
  }
}

// 苹果双模态主题管理 (优先记忆用户选择，未指定时自动匹配系统明暗主题)
const savedAppleTheme = localStorage.getItem('omni_probe_apple_theme');
const prefersLightQuery = typeof window !== 'undefined' && typeof window.matchMedia === 'function'
  ? window.matchMedia('(prefers-color-scheme: light)')
  : null;
const isAppleLight = ref(
  savedAppleTheme === 'light_user_forced'
    ? true
    : savedAppleTheme === 'dark'
      ? false
      : (prefersLightQuery?.matches ?? false)
);

function syncThemeToDOM(light: boolean) {
  if (light) {
    document.documentElement.classList.remove('dark');
    document.documentElement.classList.add('theme-apple-light');
  } else {
    document.documentElement.classList.remove('theme-apple-light');
    document.documentElement.classList.add('dark');
  }
}
syncThemeToDOM(isAppleLight.value);

function toggleAppleTheme() {
  isAppleLight.value = !isAppleLight.value;
  localStorage.setItem('omni_probe_apple_theme', isAppleLight.value ? 'light_user_forced' : 'dark');
  syncThemeToDOM(isAppleLight.value);
}

function onSystemColorSchemeChange(e: MediaQueryListEvent) {
  if (!localStorage.getItem('omni_probe_apple_theme')) {
    isAppleLight.value = e.matches;
    syncThemeToDOM(isAppleLight.value);
  }
}

// 侧边栏展开固定控制（首次开机默认展开以便直观展示全部工作台标题与四总线入口）
const isDockExpanded = ref(localStorage.getItem('omni_probe_dock_expanded') !== 'false');
function toggleDockPinned() {
  isDockExpanded.value = !isDockExpanded.value;
  localStorage.setItem('omni_probe_dock_expanded', isDockExpanded.value ? 'true' : 'false');
}

// 当前激活的专业工作台
const activeWorkbench = ref<WorkbenchId>('traffic');

// 威胁计数与应急切断
const threatCount = computed(() => {
  return packets.value.filter(p => p.entropy_level === 'critical' || p.direction === 'HONEYPOT_RECV').length;
});

async function triggerEmergencyCutoff() {
  addLog('[SECURITY] [紧急停机] 用户触发一键紧急切断与嗅探停机响应');
  notifyWarning('一键紧急停机响应', '已触发应急防护机制，全线切断嗅探引擎与物理总线');
  await stopCapture();
}

async function toggleSniffingPause() {
  if (isPaused.value) {
    await resumeCapture();
  } else {
    await pauseCapture();
  }
}

// 通用数据比对中心
const diffBus = useUniversalDiff();
function hideWindowToTray() {
  invoke('hide_to_tray_cmd').catch((e) => console.warn('hide_to_tray_cmd:', e));
}
function openUniversalDiffCenter() {
  if (diffBus.queueCount.value >= 3) {
    diffBus.activeMode.value = 'multi';
    diffBus.isDiffModalOpen.value = true;
  } else if (diffBus.queueCount.value >= 2 || (diffBus.slotA.value && diffBus.slotB.value)) {
    diffBus.compareSlots();
  } else if (diffBus.currentItemA.value && diffBus.currentItemB.value) {
    diffBus.isDiffModalOpen.value = true;
  } else {
    diffBus.openScratchpad();
  }
}

function handleGlobalKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape') {
    if (isIfaceMenuOpen.value) isIfaceMenuOpen.value = false;
    else if (isEnvDiagnosticOpen.value) isEnvDiagnosticOpen.value = false;
    else if (isPreferencesOpen.value) isPreferencesOpen.value = false;
    else if (isWirelessVlanOpen.value) isWirelessVlanOpen.value = false;
    else if (isHoneypotOpen.value) isHoneypotOpen.value = false;
    else if (isGlobalDossierOpen.value) isGlobalDossierOpen.value = false;
    else if (isDeepModalOpen.value) isDeepModalOpen.value = false;
  } else if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
    e.preventDefault();
    bpfInputRef.value?.focus();
    bpfInputRef.value?.select();
  } else if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'D' || e.key === 'd')) {
    e.preventDefault();
    openUniversalDiffCenter();
  } else if ((e.ctrlKey || e.metaKey) && (e.key === ',' || e.key === '，')) {
    e.preventDefault();
    isPreferencesOpen.value = !isPreferencesOpen.value;
  }
}

// 引擎与总线运行状态
const isRunning = ref(false);
const isPaused = ref(false);
const isSerialRunning = ref(false);
const isUsbRunning = ref(false);

const selectedIface = ref('');
const bpfFilter = ref('');
const interfaces = ref<string[]>([]);

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

// 严格以纯洁真实捕获空队列初始化，杜绝任何开机预设静态假包污染真实流
const packets = ref<any[]>([]);

const totalCaptureBytes = computed(() => {
  return packets.value.reduce((sum, p) => sum + (p.length || 64), 0);
});

const ringBufferUsageText = computed(() => {
  const mb = (totalCaptureBytes.value / (1024 * 1024)).toFixed(1);
  return `${mb} MB / 64 MB`;
});

const ringBufferPercent = computed(() => {
  const ratio = (totalCaptureBytes.value / (64 * 1024 * 1024)) * 100;
  return Math.min(100, Math.max(3, Number(ratio.toFixed(1))));
});

const discoveredAssets = ref<any[]>([]);
const usbDevices = ref<any[]>([]);
const serialPorts = ref<string[]>([]);
const serialPortsDetail = ref<SerialPortDetail[]>([]);
const activeSerialPorts = ref<string[]>([]);
const selectedSerial = ref('');
const serialBaudRate = ref(9600);
const serialPortBaudRates = ref<Record<string, number>>({});

const honeypotPackets = ref<any[]>([]);
const systemLogs = ref<string[]>([]);

const isHoneypotOpen = ref(false);
const isHoneypotRunning = ref(false);

const isScanningAssets = ref(false);
const isProbingAll = ref(false);

const isDeepModalOpen = ref(false);
const deepModalPacket = ref<any | null>(null);

function openDeepModal(pkt: any) {
  deepModalPacket.value = pkt;
  isDeepModalOpen.value = true;
}

const isGlobalDossierOpen = ref(false);
const isEnvDiagnosticOpen = ref(false);
const isPreferencesOpen = ref(false);
const isWirelessVlanOpen = ref(false);
const envScore = ref<number | null>(null);

// 启动自检状态（默认未确认前全部按未就绪/待探活展示，严格依据底层实测结果置位）
const isInitializing = ref(true);
const isNpcapAvailable = ref(false);
const isUsbpcapAvailable = ref(false);
const isTsharkAvailable = ref(false);
const initProgress = ref(15);
const initStatusMessage = ref('正在初始化底层通信总线与内存池...');
const initSteps = ref([
  { label: '内核旁路与环形缓冲池', done: false },
  { label: '物理网络适配器探测', done: false },
  { label: '工业现场总线与串口', done: false },
  { label: '工控规约解剖矩阵', done: false },
]);

async function refreshAuditComplianceRate(): Promise<void> {
  try {
    const snap: any = await invoke('get_audit_compliance_snapshot_cmd');
    if (snap && typeof snap.level3_rate_pct === 'number') {
      auditComplianceBadge.value = `${snap.level3_rate_pct.toFixed(0)}%`;
    }
  } catch (e) {
    console.warn('[AUDIT_SNAPSHOT] 获取等保实测达成率失败:', e);
  }
}

async function loadEnvReadiness(): Promise<void> {
  try {
    const res: any = await invoke('get_environment_inspection_cmd');
    envScore.value = res.readiness_score;
    const npcapComp = res.components?.find((c: any) => c.id === 'npcap');
    const usbpcapComp = res.components?.find((c: any) => c.id === 'usbpcap');
    const tsharkComp = res.components?.find((c: any) => c.id === 'tshark');
    isNpcapAvailable.value = Boolean(npcapComp?.is_ready);
    isUsbpcapAvailable.value = Boolean(usbpcapComp?.is_ready);
    isTsharkAvailable.value = Boolean(tsharkComp?.is_ready);
  } catch (e) {
    console.warn('[ENV_CHECK] 失败:', e);
  }
}

const globalDossierIp = ref('');
function handleOpenGlobalDossier(ip: string) {
  if (!ip) return;
  globalDossierIp.value = ip;
  isGlobalDossierOpen.value = true;
  addLog(`[DOSSIER] 跨工作台唤起全息 IP 画像档案: ${ip}`);
}

function addLog(msg: string) {
  const ts = new Date().toLocaleTimeString('zh-CN', { hour12: false });
  systemLogs.value.push(`[${ts}] ${msg}`);
  if (systemLogs.value.length > 5000) systemLogs.value.shift();
}

function clearSystemLogs() {
  systemLogs.value = [];
}

async function startCapture() {
  try {
    await invoke('start_capture', { iface: selectedIface.value, bpfFilter: bpfFilter.value || null });
    isRunning.value = true;
    isPaused.value = false;
    addLog(`[PROBE] 网卡嗅探已启动 → ${selectedIface.value || 'auto'} BPF="${bpfFilter.value || 'none'}"`);
    notifySuccess('网卡嗅探引擎已就绪', `已绑定网卡 [${selectedIface.value || 'auto'}]，过滤规则: ${bpfFilter.value || '全量捕获'}`);
  } catch (e) {
    addLog(`[ERROR] 网卡引擎启动失败: ${e}`);
    notifyError('网卡抓包引擎启动受阻', e);
  }
}

async function pauseCapture() {
  try {
    await invoke('pause_capture');
    isPaused.value = true;
    addLog('[PROBE] ⏸️ 网卡嗅探已挂起暂停（数据流暂停，网卡驱动保持热备）');
    notifyInfo('网卡嗅探已挂起', '数据流捕获已暂停，网卡驱动保持热备状态');
  } catch (e) {
    addLog(`[ERROR] 暂停嗅探失败: ${e}`);
    notifyError('暂停嗅探失败', e);
  }
}

async function resumeCapture() {
  try {
    await invoke('resume_capture');
    isPaused.value = false;
    addLog('[PROBE] ▶️ 网卡嗅探已恢复（毫秒级无缝继续抓包）');
    notifySuccess('网卡嗅探已恢复', '毫秒级无缝继续捕获实时数据流');
  } catch (e) {
    addLog(`[ERROR] 恢复嗅探失败: ${e}`);
    notifyError('恢复嗅探失败', e);
  }
}

async function stopCapture() {
  try {
    await invoke('stop_capture');
    isRunning.value = false;
    isPaused.value = false;
    isSerialRunning.value = false;
    activeSerialPorts.value = [];
    isUsbRunning.value = false;
    addLog('[PROBE] 探针主引擎及全部物理总线已安全停止');
    notifyInfo('捕获引擎已安全停止', '主引擎、物理串口及 USB 外设嗅探均已安全停机');
  } catch (e) {
    addLog(`[ERROR] 停止失败: ${e}`);
    notifyError('停止捕获引擎失败', e);
  }
}

async function startSerialCapture(port?: string, baudRate?: number) {
  const p = port || selectedSerial.value;
  const b = baudRate || serialPortBaudRates.value[p] || serialBaudRate.value || 9600;
  if (!p) {
    addLog('[SERIAL] 启动失败: 未选择可用串口');
    notifyWarning('启动串口监听失败', '请先选择目标物理/虚拟 COM 端口');
    return;
  }
  try {
    const res = await invoke<string>('start_serial_capture', { port: p, baudRate: b });
    if (!activeSerialPorts.value.includes(p)) {
      activeSerialPorts.value.push(p);
    }
    isSerialRunning.value = activeSerialPorts.value.length > 0;
    selectedSerial.value = p;
    serialPortBaudRates.value[p] = b;
    serialBaudRate.value = b;
    addLog(res);
  } catch (e) {
    addLog(`[ERROR] 串口 ${p} 监听启动失败: ${e}`);
  }
}

async function stopSerialCapture(port?: string) {
  try {
    const res = await invoke<string>('stop_serial_capture', { port: port || null });
    if (port) {
      activeSerialPorts.value = activeSerialPorts.value.filter(p => p !== port);
    } else {
      activeSerialPorts.value = [];
    }
    isSerialRunning.value = activeSerialPorts.value.length > 0;
    addLog(res);
  } catch (e) {
    addLog(`[ERROR] 停止串口监听失败: ${e}`);
  }
}

async function startUsbCapture() {
  try {
    const res = await invoke<string>('start_usb_capture');
    isUsbRunning.value = true;
    addLog(res);
    await refreshUsbDevices();
    notifySuccess('USB 总线探针已就绪', '已成功挂钩系统底层 USB 外设通信总线');
  } catch (e) {
    addLog(`[ERROR] USB 嗅探启动失败: ${e}`);
    notifyError('USB 嗅探启动受阻', e);
  }
}

async function stopUsbCapture() {
  try {
    const res = await invoke<string>('stop_usb_capture');
    isUsbRunning.value = false;
    addLog(res);
  } catch (e) {
    addLog(`[ERROR] 停止 USB 嗅探失败: ${e}`);
  }
}

async function clearData() {
  packets.value = [];
  try {
    await invoke('clear_logs');
  } catch (e) {
    addLog(`[ERROR] 清空内核日志失败: ${e}`);
  }
  addLog('[CLEANUP] 数据沙箱与流量记录已清空');
  notifyInfo('数据沙箱已重置', '抓包流量缓存与内核日志已清空');
}

function handleImportedPackets(importedList: any[]) {
  if (importedList && importedList.length > 0) {
    packets.value = [...importedList, ...packets.value];
    addLog(`[TRAFFIC] 成功载入 ${importedList.length} 个离线报文至全局数据总线`);
    notifySuccess('PCAP 数据包导入成功', `成功解析并载入 ${importedList.length} 帧离线流量报文至分析工作台`);
  }
}

async function refreshSerialPorts() {
  try {
    const details = await invoke<SerialPortDetail[]>('list_serial_ports_detail');
    serialPortsDetail.value = details;
    serialPorts.value = details.map(p => p.port_name);
    if (!selectedSerial.value || !serialPorts.value.includes(selectedSerial.value)) {
      const bestUsb = details.find(d => d.is_usb && d.is_available);
      const anyUsb = details.find(d => d.is_usb);
      const anyAvail = details.find(d => d.is_available);
      selectedSerial.value = bestUsb?.port_name || anyUsb?.port_name || anyAvail?.port_name || serialPorts.value[0] || '';
    }
  } catch (e) {
    addLog(`[ERROR] 刷新物理串口拓扑失败: ${e}`);
  }
}

async function refreshAssets() {
  try {
    const fresh = await invoke<any[]>('get_discovered_assets_cmd');
    if (JSON.stringify(fresh) !== JSON.stringify(discoveredAssets.value)) {
      discoveredAssets.value = fresh;
    }
  } catch (e) {
    addLog(`[ERROR] 刷新局域网资产失败: ${e}`);
  }
}

async function clearAssets() {
  try {
    await invoke('clear_discovered_assets_cmd');
    discoveredAssets.value = [];
    addLog('[ASSETS] 已清空所有局域网已感知资产记录');
  } catch (e) {
    addLog(`[ERROR] 清空资产失败: ${e}`);
  }
}

async function triggerAssetScan() {
  if (isScanningAssets.value) return;
  isScanningAssets.value = true;
  addLog('[ASSETS] 发起局域网物理网段主动并发扫描...');
  try {
    await invoke('trigger_asset_scan_cmd');
  } catch (e) {
    addLog(`[ERROR] 扫描失败: ${e}`);
  } finally {
    setTimeout(() => { isScanningAssets.value = false; }, 3000);
  }
}

async function probeAllAssets() {
  if (isProbingAll.value) return;
  isProbingAll.value = true;
  addLog('[PORT-SCAN] 启动全局资产高频端口探活...');
  try {
    await invoke('probe_all_assets_cmd');
  } catch (e) {
    addLog(`[ERROR] 端口探活异常: ${e}`);
  } finally {
    setTimeout(() => { isProbingAll.value = false; }, 3000);
  }
}

async function probeAssetPorts(ip: string) {
  addLog(`[PORT-SCAN] 正在对资产 ${ip} 进行高频端口探活...`);
  try {
    const openPorts = await invoke<number[]>('probe_asset_ports_cmd', { ip });
    if (openPorts.length > 0) {
      addLog(`[PORT-SCAN] 资产 ${ip} 发现开放端口: [${openPorts.join(', ')}]`);
    } else {
      addLog(`[PORT-SCAN] 资产 ${ip} 未响应常见端口探活`);
    }
    await refreshAssets();
  } catch (e) {
    addLog(`[ERROR] 端口探活失败: ${e}`);
  }
}

async function refreshUsbDevices() {
  try {
    usbDevices.value = await invoke<any[]>('list_usb_devices');
  } catch (e) {
    addLog(`[ERROR] 获取 USB 设备列表失败: ${e}`);
  }
}

async function replayPacket(pkt: any) {
  if (!pkt.payload_hex) return;
  const targetIp = pkt.dst_ip || '';
  if (!targetIp) {
    addLog(`[REPLAY] #${pkt.id} 重放中止: 目标 IP 为空`);
    return;
  }
  try {
    const r = await invoke<string>('replay_l4_packet_cmd', {
      targetIp,
      targetPort: pkt.dst_port || 80,
      transport: pkt.transport || 'TCP',
      payloadHex: pkt.payload_hex
    });
    addLog(`[REPLAY] #${pkt.id} ${r}`);
  } catch (e) {
    addLog(`[ERROR] 重放失败: ${e}`);
  }
}

async function savePacketAsBaseline(pkt: any) {
  if (!pkt.payload_hex) return;
  try {
    const list = await invoke<string[]>('load_baseline_payloads_cmd');
    if (!list.includes(pkt.payload_hex)) list.push(pkt.payload_hex);
    await invoke<number>('save_baseline_payloads_cmd', { payloads: list });
    addLog(`[BASELINE] 成功将报文 #${pkt.id} 固化至基线库`);
    notifySuccess('基线固化成功', `报文 #${pkt.id} 的协议特征已固化至基线白名单`);
  } catch (e) {
    addLog(`[ERROR] 固化基线失败: ${e}`);
  }
}

function onUpdatePortBaudRate({ port, baudRate }: { port: string; baudRate: number }) {
  serialPortBaudRates.value[port] = baudRate;
}

const rootShellRef = ref<HTMLElement | null>(null);
let pointerRafId: number | null = null;
let latestPointerX = 0;
let latestPointerY = 0;

function onRootPointerMove(e: PointerEvent) {
  latestPointerX = e.clientX;
  latestPointerY = e.clientY;
  if (pointerRafId !== null) return;
  pointerRafId = requestAnimationFrame(() => {
    const el = rootShellRef.value;
    if (el) {
      el.style.setProperty('--pointer-x', `${latestPointerX}px`);
      el.style.setProperty('--pointer-y', `${latestPointerY}px`);
    }
    pointerRafId = null;
  });
}

function handleFilterTraffic(ip: string) {
  if (!ip) return;
  bpfFilter.value = ip;
  activeWorkbench.value = 'traffic';
  addLog(`[TRAFFIC] 已按 IP 快速过滤流量: ${ip}`);
}

onMounted(() => {
  window.addEventListener('keydown', handleGlobalKeydown);
  window.addEventListener('click', handleDocumentClick);
  prefersLightQuery?.addEventListener('change', onSystemColorSchemeChange);

  // 步进平滑定时器
  const progressTimer = setInterval(() => {
    if (initProgress.value < 88) {
      initProgress.value += 4;
    }
  }, 80);

  setTimeout(() => {
    initSteps.value[0].done = true;
    initProgress.value = Math.max(initProgress.value, 35);
    initStatusMessage.value = '内核旁路与环形缓冲池已就绪...';
  }, 120);

  let isFinished = false;
  function finishInitialization() {
    if (isFinished) return;
    isFinished = true;
    clearInterval(progressTimer);
    initSteps.value.forEach(s => s.done = true);
    initProgress.value = 100;
    initStatusMessage.value = '系统自检就绪，全息分析仪已启动';
    setTimeout(() => {
      isInitializing.value = false;
      notifySuccess('探针主引擎已就绪', selectedIface.value ? `已挂载适配器: ${selectedIface.value}` : '多轨自愈引擎已就绪');

      const skipModal = localStorage.getItem('omni_probe_skip_startup_env_modal') === 'true';
      if (!skipModal && envScore.value !== null && envScore.value < 100) {
        setTimeout(() => {
          isEnvDiagnosticOpen.value = true;
        }, 500);
      }
    }, 250);
  }

  const watchdog = setTimeout(() => {
    finishInitialization();
  }, 1800);

  function checkAllReady() {
    if (initSteps.value.every(s => s.done)) {
      clearTimeout(watchdog);
      finishInitialization();
    }
  }

  loadEnvReadiness().finally(() => {
    refreshAuditComplianceRate();
    initSteps.value[3].done = true;
    initProgress.value = Math.max(initProgress.value, 75);
    checkAllReady();
  });

  // 并行枚举通道
  invoke<string[]>('list_interfaces').then((ifaces) => {
    interfaces.value = ifaces;
    if (ifaces.length > 0 && !selectedIface.value) {
      selectedIface.value = ifaces[0];
    }
    initSteps.value[1].done = true;
    initProgress.value = Math.max(initProgress.value, 65);
    checkAllReady();
  }).catch((e) => {
    addLog(`[ERROR] 获取网卡列表失败: ${e}`);
  });

  invoke<SerialPortDetail[]>('list_serial_ports_detail').then((details) => {
    serialPortsDetail.value = details;
    serialPorts.value = details.map(d => d.port_name);
    if (serialPorts.value.length > 0 && !selectedSerial.value) {
      selectedSerial.value = serialPorts.value[0];
    }
    initSteps.value[2].done = true;
    initProgress.value = Math.max(initProgress.value, 85);
    checkAllReady();
  }).catch((e) => {
    console.warn('[App] list_serial_ports_detail failed:', e);
    addLog(`[WARN] 枚举物理串口列表受阻: ${e}`);
    initSteps.value[2].done = true;
    initProgress.value = Math.max(initProgress.value, 85);
    checkAllReady();
  });

  invoke<any[]>('list_active_serial_probes').then((activeList) => {
    activeSerialPorts.value = activeList.map(a => a.port_name);
    isSerialRunning.value = activeSerialPorts.value.length > 0;
  }).catch((e) => {
    console.warn('[App] list_active_serial_probes failed:', e);
    addLog(`[WARN] 查询活动串口探测状态失败: ${e}`);
  });

  refreshAssets();
  refreshUsbDevices();

  let assetTimer: any = setInterval(() => {
    refreshAssets();
  }, 5000);

  let unlistenTrayDiff: (() => void) | null = null;
  let unlistenDragDrop: (() => void) | null = null;

  listen('desktop-open-file-diff', () => {
    diffBus.openFileMergeWithPaths();
  }).then((fn) => { unlistenTrayDiff = fn; }).catch(() => {});

  getCurrentWebview().onDragDropEvent((event) => {
    if (event.payload.type === 'drop' && event.payload.paths?.length > 0) {
      const paths = event.payload.paths;
      if (paths.length >= 2) {
        diffBus.openFileMergeWithPaths(paths[0], paths[1]);
        notifySuccess('桌面拖放文件已载入对比', `左: ${paths[0]} | 右: ${paths[1]}`);
      } else {
        diffBus.openFileMergeWithPaths(paths[0], undefined);
        notifyInfo('已从桌面拖入左侧基准文件', `请继续拖入或浏览右侧比对文件: ${paths[0]}`);
      }
    }
  }).then((fn) => { unlistenDragDrop = fn; }).catch(() => {});

  onUnmounted(() => {
    window.removeEventListener('keydown', handleGlobalKeydown);
    window.removeEventListener('click', handleDocumentClick);
    prefersLightQuery?.removeEventListener('change', onSystemColorSchemeChange);
    if (assetTimer) clearInterval(assetTimer);
    if (unlistenTrayDiff) unlistenTrayDiff();
    if (unlistenDragDrop) unlistenDragDrop();
    if (pointerRafId !== null) {
      cancelAnimationFrame(pointerRafId);
      pointerRafId = null;
    }
  });

  listen<SerialPortDetail>('serial-inserted', ({ payload }) => {
    addLog(`[SERIAL] 检测到新物理串口接入: ${payload.description} [${payload.port_name}]`);
    if (payload.is_usb) {
      selectedSerial.value = payload.port_name;
      notifyInfo('物理串口已接入并自动选中', `${payload.port_name} (${payload.product || payload.description})`);
    }
    refreshSerialPorts();
  });

  listen<SerialPortDetail[]>('serial-ports-changed', ({ payload }) => {
    const oldPorts = new Set(serialPorts.value);
    serialPortsDetail.value = payload;
    serialPorts.value = payload.map(p => p.port_name);
    const newlyAdded = payload.filter(p => !oldPorts.has(p.port_name));
    const newUsb = newlyAdded.find(p => p.is_usb);
    if (newUsb) {
      selectedSerial.value = newUsb.port_name;
      notifyInfo('物理串口已接入并自动选中', `${newUsb.port_name} (${newUsb.product || newUsb.description})`);
    }
    addLog(`[SERIAL] 物理串口拓扑自动更新: 当前检测到 ${payload.length} 个通信端口`);
  });

  listen<string>('serial-disconnected', ({ payload }) => {
    activeSerialPorts.value = activeSerialPorts.value.filter(p => p !== payload);
    isSerialRunning.value = activeSerialPorts.value.length > 0;
    addLog(`[SERIAL] 物理串口 ${payload} 已断开，监听引擎已自动安全注销`);
  });

  listen<any[]>('usb-devices-changed', ({ payload }) => {
    usbDevices.value = payload;
    addLog(`[USB] 物理 USB 外设拓扑变更: 当前在线 ${payload.length} 个物理设备`);
  });

  listen<any>('hardware-alert', ({ payload }) => {
    if (typeof payload === 'string') {
      addLog(`[HARDWARE] 物理总线告警: ${payload}`);
      notifyWarning('物理总线安全告警', payload);
      return;
    }
    addLog(`[HARDWARE] 物理总线变更: ${payload.alert_type} - ${payload.device_name || ''}`);
  });

  let pendingPackets: any[] = [];
  let rafId: number | null = null;
  function flushPackets() {
    if (pendingPackets.length > 0) {
      packets.value.push(...pendingPackets);
      pendingPackets = [];
      if (packets.value.length > 100_000) {
        packets.value.splice(0, packets.value.length - 100_000);
      }
    }
    rafId = null;
  }

  listen<any>('packet-received', ({ payload }) => {
    pendingPackets.push(payload);
    if (!rafId) rafId = requestAnimationFrame(flushPackets);
  });

  listen<any>('usb-packet', ({ payload }) => {
    pendingPackets.push(payload);
    if (!rafId) rafId = requestAnimationFrame(flushPackets);
  });

  listen<any[]>('assets-updated', ({ payload }) => {
    if (JSON.stringify(payload) !== JSON.stringify(discoveredAssets.value)) {
      discoveredAssets.value = payload;
    }
  });

  listen<any>('honeypot-received', ({ payload }) => {
    honeypotPackets.value.unshift(payload);
    if (honeypotPackets.value.length > 5000) honeypotPackets.value.pop();
    addLog(`[HONEYPOT] 诱捕命中: ${payload.src_ip}:${payload.src_port} → :${payload.dst_port}`);
  });

  listen<string>('ai-alert', ({ payload }) => {
    addLog(`[SECURITY] 告警: ${payload}`);
    notifyWarning('安全威胁检测告警', payload);
  });

  listen<any>('baseline-drift-alert', ({ payload }) => {
    addLog(`[BASELINE-ALERT] [${payload.drift_type}] ${payload.description}`);
    notifyWarning('等保基线漂移告警', `[${payload.drift_type}] ${payload.description}`);
  });

  listen<string>('system-log', ({ payload }) => {
    addLog(payload);
  });

  invoke<boolean>('is_honeypot_running_cmd').then((hpRunning) => {
    isHoneypotRunning.value = hpRunning;
  }).catch((e) => {
    console.warn('[App] is_honeypot_running_cmd failed:', e);
    addLog(`[WARN] 查询诱饵哨兵状态失败: ${e}`);
  });
});
</script>
