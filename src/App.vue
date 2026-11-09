<template>
  <div :class="['h-screen w-screen overflow-hidden flex flex-col select-none font-sans relative transition-colors duration-300',
    isAppleLight ? 'theme-apple-light text-slate-800' : 'theme-apple-dark text-slate-100']">
    
    <!-- 2026 苹果 Liquid 磨砂与 Win11 通透极光流光 (Liquid Aurora Background) -->
    <div class="liquid-aurora-container">
      <div class="aurora-blob-1"></div>
      <div class="aurora-blob-2"></div>
      <div class="aurora-blob-3"></div>
    </div>
    <!-- 实体物理微米级噪点滤镜层 (Physical Materiality Noise Layer) -->
    <div class="noise-layer"></div>

    <!-- 顶栏：一体化通栏导航与居中浮动 HUD 动态岛 (Top Window Bar & Floating HUD Island) -->
    <header class="header-glass w-full flex items-center justify-between px-4 py-2 shrink-0 z-30 select-none gap-3">
      <!-- 左侧：真实客观的系统三维安全健康控制中枢与应用标识 -->
      <div class="flex items-center gap-3 shrink-0">
        <!-- 系统三维安全健康客观状态与控制中枢 (客观严谨物理指标与一键控制) -->
        <div class="flex items-center gap-1.5 p-1 rounded-2xl glass-surface border border-white/20 select-none shadow-sm" title="系统三维安全运行与控制中枢">
          <!-- 🔴 红色指示器：网络威胁拦截与紧急切断 -->
          <button @click="triggerEmergencyCutoff"
            :class="['flex items-center gap-1.5 px-2.5 py-1 rounded-xl text-xs font-mono font-bold transition-all cursor-pointer shadow-sm',
              threatCount > 0 ? 'bg-rose-500/25 text-rose-500 border border-rose-500/50 animate-pulse' : 'bg-rose-500/10 text-rose-600 hover:bg-rose-500/20 border border-rose-500/20']"
            :title="`[安全威胁与涉密阻断: ${threatCount} 起] 点击一键执行紧急切断与主引擎停机`">
            <span class="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_6px_#F43F5E]"></span>
            <span class="text-[11px] whitespace-nowrap">{{ threatCount > 0 ? `威胁阻断 ${threatCount}` : '应急切断' }}</span>
          </button>

          <!-- 🟡 黄色指示器：嗅探状态与高熵预警 -->
          <button @click="toggleSniffingPause"
            :class="['flex items-center gap-1.5 px-2.5 py-1 rounded-xl text-xs font-mono font-bold transition-all cursor-pointer shadow-sm',
              isPaused ? 'bg-amber-500/25 text-amber-600 border border-amber-500/50' : (isRunning ? 'bg-emerald-500/15 text-emerald-600 border border-emerald-500/30' : 'bg-slate-500/10 text-slate-500 border border-slate-500/20')]"
            :title="`[引擎工作状态: ${isPaused ? '已挂起' : (isRunning ? '运行中' : '待命')}] 点击暂停/恢复数据捕获`">
            <span class="w-2.5 h-2.5 rounded-full" :class="isPaused ? 'bg-amber-500 animate-pulse' : (isRunning ? 'bg-emerald-500' : 'bg-slate-400')"></span>
            <span class="text-[11px] whitespace-nowrap">{{ isPaused ? '引擎已挂起' : (isRunning ? '嗅探运行中' : '引擎待命') }}</span>
          </button>

          <!-- 🟢 绿色指示器：等保三级合规健康态 -->
          <button @click="activeWorkbench = 'audit'"
            class="flex items-center gap-1.5 px-2.5 py-1 rounded-xl text-xs font-mono font-bold bg-emerald-500/10 text-emerald-600 border border-emerald-500/20 hover:bg-emerald-500/20 transition-all cursor-pointer shadow-sm"
            title="[等保三级合规达标: 100%] 当前系统处于白名单合规保护态，点击查看等保审计工作台">
            <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 status-pulse shadow-[0_0_6px_#10B981]"></span>
            <span class="text-[11px] whitespace-nowrap">等保三级达标</span>
          </button>
        </div>

        <div class="h-4 w-px bg-white/10 shrink-0"></div>

        <!-- 应用 Identity 与侧边栏快捷收缩/展开按钮 -->
        <div class="flex items-center gap-1.5">
          <button @click="toggleDockPinned"
            :title="isDockExpanded ? '收起左侧菜单栏' : '展开左侧菜单栏'"
            class="p-1.5 rounded-xl hover:bg-black/5 dark:hover:bg-white/10 text-slate-500 hover:text-cyan-600 dark:hover:text-cyan-300 transition-all cursor-pointer mr-0.5"
            aria-label="切换侧栏">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h8m-8 6h16" />
            </svg>
          </button>
          <div class="w-7 h-7 rounded-xl overflow-hidden shadow-lg shadow-cyan-500/25 shrink-0 border border-white/20 flex items-center justify-center bg-slate-900/90 p-0.5">
            <img src="/logo.svg" alt="Omni-Probe Logo" class="w-full h-full object-contain" />
          </div>
          <div class="flex flex-col whitespace-nowrap">
            <div class="flex items-center gap-1.5">
              <span class="text-xs font-bold tracking-tight text-slate-800 dark:text-white/95">OMNI-PROBE</span>
              <span class="text-[9px] font-mono font-semibold px-1.5 py-0.2 rounded-full glass-pill text-cyan-950 dark:text-cyan-300">
                2026 MICA FROST
              </span>
            </div>
            <span class="text-[9px] opacity-60 font-medium leading-none mt-0.5">全息工业网络分析控制台</span>
          </div>
        </div>
      </div>
<!-- 中间：FLOATING HUD DYNAMIC ISLAND (流体动态岛控制中枢) -->
      <div class="flex items-center gap-2 glass-surface rounded-full px-3.5 py-1 shadow-2xl border border-white/10 shrink-0">
        <!-- 实时嗅探呼吸指示灯 -->
        <div class="flex items-center gap-1.5 pl-1 pr-1.5 whitespace-nowrap shrink-0">
          <span class="w-2 h-2 rounded-full status-pulse shrink-0"
            :class="isRunning ? (isPaused ? 'bg-amber-400 shadow-[0_0_8px_#F59E0B]' : 'bg-emerald-400 shadow-[0_0_8px_#10B981]') : 'bg-slate-500'"></span>
          <span class="text-[11px] font-bold uppercase tracking-wider font-mono shrink-0"
            :class="isRunning ? (isPaused ? 'text-amber-300' : 'text-emerald-300') : 'text-slate-400'">
            {{ isRunning ? (isPaused ? 'PAUSED' : 'LIVE SNIFFING') : 'STANDBY' }}
          </span>
        </div>

        <div class="h-4 w-px bg-white/10 shrink-0"></div>

        <!-- 物理网卡切换胶囊 -->
        <div class="relative group shrink-0">
          <div class="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-white/5 hover:bg-white/10 transition-colors cursor-pointer text-[11px] max-w-[150px] md:max-w-[200px] whitespace-nowrap"
            :title="`当前物理接口: ${selectedIface || '自动物理网卡'}`">
            <svg class="w-3.5 h-3.5 text-cyan-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/>
            </svg>
            <span class="font-mono font-medium text-slate-200 truncate">{{ selectedIface || '自动识别网卡' }}</span>
            <svg class="w-3 h-3 text-slate-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
            </svg>
          </div>
          <!-- 悬浮网卡切换菜单 -->
          <div class="absolute left-0 top-full mt-1.5 w-64 glass-surface rounded-2xl p-2 hidden group-hover:block z-50 border border-white/15 shadow-2xl font-mono text-xs">
            <div class="text-[10px] text-slate-400 px-2 py-1 font-bold uppercase tracking-wider border-b border-white/10 mb-1">
              可监听物理以太网卡
            </div>
            <div @click="selectedIface = ''"
              class="px-2.5 py-1.5 rounded-xl cursor-pointer hover:bg-cyan-500/20 text-slate-200 hover:text-cyan-300 transition-colors flex items-center justify-between"
              :class="!selectedIface ? 'bg-cyan-500/15 text-cyan-300 font-bold' : ''">
              <span>自动推荐物理网卡</span>
              <span v-if="!selectedIface" class="text-cyan-400 text-[10px]">✓ 推荐</span>
            </div>
            <div v-for="iface in interfaces" :key="iface" @click="selectedIface = iface"
              class="px-2.5 py-1.5 rounded-xl cursor-pointer hover:bg-cyan-500/20 text-slate-200 hover:text-cyan-300 transition-colors truncate"
              :class="selectedIface === iface ? 'bg-cyan-500/15 text-cyan-300 font-bold' : ''"
              :title="iface">
              {{ iface }}
            </div>
          </div>
        </div>

        <div class="h-4 w-px bg-white/10 shrink-0"></div>

        <!-- 多维表达式过滤胶囊输入框 -->
        <div class="flex items-center gap-2 px-3 py-1 rounded-full bg-white/80 dark:bg-black/50 border border-slate-300/50 dark:border-white/10 text-[11px] w-64 md:w-72 focus-within:border-cyan-500/60 focus-within:ring-1 focus-within:ring-cyan-500/30 transition-all shrink-0">
          <svg class="w-3.5 h-3.5 text-slate-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          <input v-model="bpfFilter" type="text" placeholder="多维过滤 (例如: s7comm, 502)"
            class="bg-transparent text-slate-200 text-[11px] outline-none w-full placeholder:text-slate-500 font-mono">
          <span class="text-[9px] font-mono text-slate-400 bg-white/5 border border-white/10 px-1.5 py-0.2 rounded shrink-0">Ctrl+K</span>
        </div>

        <!-- 嗅探捕获控制按钮：加 whitespace-nowrap shrink-0 绝不折行 -->
        <template v-if="!isRunning">
          <button @click="startCapture"
            class="flex items-center gap-1.5 px-3 py-1 rounded-full bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-600 hover:to-teal-700 text-white font-semibold text-[11px] shadow-lg shadow-emerald-500/25 transition-all active:scale-95 cursor-pointer whitespace-nowrap shrink-0">
            <svg class="w-3.5 h-3.5 fill-current shrink-0" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
            <span class="whitespace-nowrap">启动网卡嗅探</span>
          </button>
        </template>
        <template v-else>
          <button v-if="!isPaused" @click="pauseCapture"
            class="flex items-center gap-1.5 px-3 py-1 rounded-full bg-gradient-to-r from-rose-500 to-rose-600 hover:from-rose-600 hover:to-rose-700 text-white font-semibold text-[11px] shadow-lg shadow-rose-500/25 transition-all active:scale-95 cursor-pointer whitespace-nowrap shrink-0">
            <svg class="w-3.5 h-3.5 shrink-0" fill="currentColor" viewBox="0 0 24 24">
              <rect x="6" y="6" width="12" height="12" rx="2"/>
            </svg>
            <span class="whitespace-nowrap">暂停捕获</span>
          </button>
          <button v-else @click="resumeCapture"
            class="flex items-center gap-1.5 px-3 py-1 rounded-full bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-600 hover:to-blue-700 text-white font-semibold text-[11px] shadow-lg shadow-blue-500/25 transition-all active:scale-95 cursor-pointer whitespace-nowrap shrink-0">
            <svg class="w-3.5 h-3.5 fill-current shrink-0" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
            <span class="whitespace-nowrap">继续嗅探</span>
          </button>

          <!-- 停止按钮 -->
          <button @click="stopCapture" title="停止主引擎"
            class="p-1 rounded-full hover:bg-rose-500/20 text-rose-400 hover:text-rose-300 transition-colors cursor-pointer border border-rose-500/30 shrink-0">
            <svg class="w-3.5 h-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </template>
      </div>

      <!-- 右侧：环形缓冲池、苹果主题切换与全局快捷操作 -->
      <div class="flex items-center gap-2.5 shrink-0">
        <!-- 环形缓冲池指标胶囊：严格单行展示 -->
        <div class="flex items-center gap-2 glass-pill px-3 py-1 rounded-full text-[11px] whitespace-nowrap shrink-0 font-mono">
          <span class="opacity-70 font-sans">环形缓冲池:</span>
          <span class="font-bold text-cyan-950 dark:text-cyan-300">{{ ringBufferUsageText }}</span>
          <div class="w-12 h-1.5 bg-white/10 rounded-full overflow-hidden shrink-0">
            <div class="h-full bg-gradient-to-r from-cyan-400 to-blue-500 transition-all duration-300"
              :style="{ width: `${ringBufferPercent}%` }"></div>
          </div>
        </div>

        <!-- 苹果 2026 双模态一键切换按钮 (☀️ 冰晶明亮 / 🌙 磨砂深色) -->
        <button @click="toggleAppleTheme"
          class="glass-pill px-3 py-1 rounded-full text-xs font-semibold flex items-center gap-1.5 cursor-pointer shadow-md transition-all active:scale-95"
          :title="isAppleLight ? '切换为 2026 苹果烟熏磨砂深色模式' : '切换为 2026 苹果冰晶磨砂明亮模式'">
          <span>{{ isAppleLight ? '☀️ 冰晶明亮' : '🌙 磨砂深色' }}</span>
        </button>

        <!-- 常用动作按钮组 -->
        <div class="flex items-center gap-1 shrink-0">
          <!-- 全球网络地理态势地图一键直达 -->
          <!-- 全局通用数据比对中心 (跨模块通用基础设施) -->
          <button @click="openUniversalDiffCenter"
            class="flex items-center gap-1.5 px-2.5 py-1 rounded-full glass-pill hover:bg-white/10 transition-colors cursor-pointer text-xs font-mono shrink-0 shadow-xs"
            :class="diffBus.hasBothSlots.value ? 'bg-indigo-600/70 border-indigo-400 text-white font-bold' : ''"
            :title="`[全局数据比对中心 (Ctrl+Shift+D)] 槽位 A: ${diffBus.slotA.value ? '已装载' : '空'} | 槽位 B: ${diffBus.slotB.value ? '已装载' : '空'}`">
            <span class="text-xs">⚖️</span>
            <span class="text-[11px] font-semibold text-indigo-900 dark:text-indigo-200">数据比对</span>
            <span v-if="diffBus.slotA.value || diffBus.slotB.value" class="w-1.5 h-1.5 rounded-full bg-indigo-400 shadow-[0_0_6px_#818CF8]"></span>
          </button>
          <button @click="activeWorkbench = 'geo_map'"
            class="flex items-center gap-1.5 px-2.5 py-1 rounded-full glass-pill hover:bg-white/10 transition-colors cursor-pointer text-xs font-mono shrink-0 shadow-xs"
            :class="activeWorkbench === 'geo_map' ? 'bg-indigo-600/60 border-indigo-400 text-white font-bold' : ''"
            title="一键切入全球网络地理态势与地图工作台">
            <span class="text-xs">🌍</span>
            <span class="text-[11px] font-semibold text-cyan-900 dark:text-cyan-200">全球地图</span>
          </button>
          <!-- 无线与虚拟局域网专业监测控制台 -->
          <button @click="isWirelessVlanOpen = true"
            class="flex items-center gap-1.5 px-2.5 py-1 rounded-full glass-pill hover:bg-white/10 transition-colors cursor-pointer text-xs font-mono shrink-0 shadow-xs"
            title="点击打开 Wi-Fi 频谱 / VLAN 拓扑 / 蓝牙近场空间感知专业控制台">
            <span class="text-xs">📶</span>
            <span class="text-[11px] font-semibold text-sky-200">无线/VLAN</span>
          </button>
          <button @click="isEnvDiagnosticOpen = true"
            class="flex items-center gap-1.5 px-2.5 py-1 rounded-full glass-pill hover:bg-white/10 transition-colors cursor-pointer text-xs font-mono shrink-0"
            :title="`[底层运行环境就绪度: ${envScore ?? '--'}%] 点击查看 Npcap / Wireshark / USBPcap 驱动诊断`">
            <span class="w-2 h-2 rounded-full"
              :class="(envScore ?? 0) >= 90 ? 'bg-emerald-400 shadow-[0_0_6px_#10B981]' : (envScore ?? 0) >= 50 ? 'bg-amber-400 shadow-[0_0_6px_#F59E0B]' : 'bg-rose-400 shadow-[0_0_6px_#F43F5E]'"></span>
            <span class="text-[11px] font-semibold text-slate-200">环境: {{ envScore ?? '--' }}%</span>
          </button>
          <button @click="clearData" class="p-1.5 rounded-full hover:bg-white/10 opacity-70 hover:opacity-100 hover:text-rose-400 transition-colors cursor-pointer shrink-0" title="清除缓冲区数据">
            <svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
            </svg>
          </button>
          <button @click="isHoneypotOpen = true" class="p-1.5 rounded-full hover:bg-white/10 opacity-70 hover:opacity-100 hover:text-amber-400 transition-colors cursor-pointer shrink-0" title="蜜罐主动诱捕威胁溯源">
            <span class="text-xs">🍯</span>
          </button>
        </div>
      </div>
    </header>

    <!-- 主体工作区容器 (苹果 2026 灵动磨砂侧栏 + Bento 便当盒空间) -->
    <div class="flex flex-1 overflow-hidden p-3 pt-1 gap-3 min-h-0 relative z-10">

      <!-- 左侧：苹果 2026 灵动悬浮磨砂侧栏 (支持平滑收缩为 Mini 图标栏与展开为 6 汉字面板) -->
      <aside :class="[
        'dock-glass rounded-3xl p-2 flex flex-col justify-between shrink-0 transition-all duration-300 ease-out shadow-xl z-20 overflow-hidden select-none',
        isDockExpanded ? 'w-56' : 'w-16 items-center'
      ]">
        <!-- 8 大专业工作台导航 -->
        <div class="flex flex-col gap-1.5 w-full">
          <!-- 侧边栏顶部小工具栏：中文功能区标题与收缩/展开切换按钮 -->
          <div :class="['flex items-center py-1 mb-1 border-b border-black/5 dark:border-white/10',
            isDockExpanded ? 'justify-between px-2 w-full' : 'justify-center w-full']">
            <span v-show="isDockExpanded" class="text-[11px] font-bold tracking-wider text-slate-700 dark:text-slate-200 whitespace-nowrap font-sans">
              功能工作台
            </span>
            <button @click="toggleDockPinned"
              :title="isDockExpanded ? '收起左侧菜单栏' : '展开左侧菜单栏'"
              class="flex items-center gap-1 p-1.5 rounded-xl hover:bg-black/5 dark:hover:bg-white/10 text-slate-500 hover:text-cyan-600 dark:hover:text-cyan-300 transition-colors cursor-pointer text-xs">
              <span v-if="isDockExpanded" class="text-[10px] font-medium">收缩</span>
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path v-if="isDockExpanded" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2" d="M15 19l-7-7 7-7" />
                <path v-else stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2" d="M9 5l7 7-7 7" />
              </svg>
            </button>
          </div>

          <!-- 8 大工作台按钮列表：严格统一 6 个汉字名称与专业图标 (收缩态下居中显示图标与精准提示) -->
          <button v-for="tab in workbenchTabs" :key="tab.id" @click="activeWorkbench = tab.id"
            :title="tab.label"
            :class="[
              'relative h-10 rounded-2xl flex items-center transition-all cursor-pointer select-none',
              isDockExpanded ? 'w-full px-2.5 gap-3' : 'w-10 justify-center px-0 mx-auto',
              activeWorkbench === tab.id
                ? 'bg-cyan-500/20 text-cyan-600 dark:text-cyan-300 shadow-sm border border-cyan-400/40 font-bold'
                : 'opacity-80 hover:opacity-100 hover:bg-slate-200/50 dark:hover:bg-white/5 text-slate-700 dark:text-slate-200 border border-transparent'
            ]">
            <div class="w-5 h-5 flex items-center justify-center shrink-0">
              <svg class="w-5 h-5 stroke-current fill-none stroke-2 shrink-0" viewBox="0 0 24 24">
                <path :d="tab.svgPath" />
              </svg>
            </div>
            <!-- 中文 6 汉字全称标签：展开态整齐显现，收缩态优雅隐藏 -->
            <div v-show="isDockExpanded" class="flex items-center justify-between flex-1 min-w-0">
              <span class="text-xs tracking-tight truncate whitespace-nowrap font-medium">{{ tab.label }}</span>
            </div>
            <!-- 激活态极光指示条 -->
            <div v-if="activeWorkbench === tab.id"
              :class="isDockExpanded ? 'absolute -left-1 w-1.5 h-6 bg-cyan-500 rounded-r-full shadow-[0_0_8px_#00F2FE]' : 'absolute -left-1 w-1 h-5 bg-cyan-500 rounded-r-full shadow-[0_0_8px_#00F2FE]'"></div>
          </button>
        </div>

        <!-- 底栏：4 大物理总线微型指示灯与系统健康 -->
        <div class="flex flex-col gap-2 w-full px-1 pt-2 border-t border-black/5 dark:border-white/10">
          <!-- 4 物理总线微态指示器 -->
          <div :class="['flex items-center py-1 rounded-xl glass-pill',
            isDockExpanded ? 'justify-between px-2 w-full' : 'justify-center w-10 mx-auto px-1']"
            title="物理总线: NIC / COM / USB / 蜜罐">
            <div class="flex items-center gap-1.5">
              <span class="w-2 h-2 rounded-full" :class="isRunning ? (isPaused ? 'bg-amber-400 shadow-[0_0_6px_#F59E0B]' : 'bg-emerald-400 shadow-[0_0_6px_#10B981] status-pulse') : 'bg-slate-400'" title="网卡 (NIC)"></span>
              <span class="w-2 h-2 rounded-full" :class="isSerialRunning ? 'bg-indigo-400 shadow-[0_0_6px_#818CF8] status-pulse' : 'bg-slate-400'" title="串口 (COM)"></span>
              <span class="w-2 h-2 rounded-full" :class="isUsbRunning ? 'bg-purple-400 shadow-[0_0_6px_#C084FC] status-pulse' : 'bg-slate-400'" title="USB 总线"></span>
              <span class="w-2 h-2 rounded-full cursor-pointer" :class="isHoneypotRunning ? 'bg-amber-400 shadow-[0_0_6px_#F59E0B] status-pulse' : 'bg-slate-400'" @click="isHoneypotOpen = true" title="诱饵蜜罐"></span>
            </div>
            <span v-show="isDockExpanded" class="text-[9px] font-mono opacity-60 truncate">
              四总线热备
            </span>
          </div>

          <div :class="['flex items-center text-xs opacity-75',
            isDockExpanded ? 'gap-2 px-1' : 'justify-center w-full']">
            <div class="w-6 h-6 rounded-full bg-gradient-to-tr from-slate-700 to-slate-600 flex items-center justify-center border border-white/20 text-[9px] font-bold text-white shadow-md shrink-0">
              OP
            </div>
            <div v-show="isDockExpanded" class="flex flex-col min-w-0 leading-tight">
              <span class="text-[10px] font-bold text-slate-800 dark:text-white truncate">Omni-Probe v0.1.0</span>
              <span class="text-[8px] font-mono opacity-60">等保三级合规认证</span>
            </div>
          </div>
        </div>
      </aside>

      <!-- 右侧：FULL-BLEED 主视口容器 -->
      <main class="flex-1 flex flex-col overflow-hidden min-w-0">
        <!-- 工作台 1：宏大无界空间控制台 / 流量分析 -->
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
          @appendLog="addLog"
          @importPackets="handleImportedPackets"
          @switchWorkbench="activeWorkbench = $event"
        />

        <!-- 工作台 2：资产拓扑态势工作台 -->
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
          :isUsbRunning="isUsbRunning"
          :isSerialRunning="isSerialRunning"
          @refreshUsb="refreshUsbDevices"
          @startUsbCapture="startUsbCapture"
          @stopUsbCapture="stopUsbCapture"
          @startSerialCapture="startSerialCapture"
          @stopSerialCapture="stopSerialCapture"
        />

        <!-- 工作台 4：安全审计、蜜罐防御与系统引擎 -->
        <SystemAuditView
          v-else-if="activeWorkbench === 'audit'"
          :systemLogs="systemLogs"
          :honeypotPackets="honeypotPackets"
          @clearLogs="clearSystemLogs"
          @appendLog="addLog"
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

        <!-- 工作台 9：全球网络地理态势与地图工作台 -->
        <GlobalGeoMapView
          v-else-if="activeWorkbench === 'geo_map'"
        />

        <!-- 工作台 10：工业级网络通信调试工作台 -->
        <NetAssistWorkbenchView
          v-else-if="activeWorkbench === 'net_assist'"
          @switchWorkbench="activeWorkbench = $event"
        />
      </main>
    </div>

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

    <!-- 全局统一 IP 全息档案溯源模态框 -->
    <!-- 全局底层抓包驱动与解剖工具链全景诊断模态框 -->
    <EnvironmentDiagnosticModal
      v-if="isEnvDiagnosticOpen"
      :isOpen="isEnvDiagnosticOpen"
      @close="isEnvDiagnosticOpen = false"
    />

    <!-- 全局无线网络 (Wi-Fi/蓝牙) 与虚拟局域网 (VLAN) 专业监测模态框 -->
    <WirelessVlanMonitorModal
      v-if="isWirelessVlanOpen"
      :isOpen="isWirelessVlanOpen"
      @close="isWirelessVlanOpen = false"
    />

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

    <!-- 统一全局通知/友好提示浮层 (四级告警与防抖抑制) -->
    <!-- 全局通用数据比对工作台 (双栏 Hex 同步 + 规约树差分 + 载荷波线波率 + 自由草稿) -->
    <PacketDiffModal />

    <GlobalNotificationToast />

    <!-- 启动中枢自检就绪友好提示 HUD (Launch & Readiness Splash Transition) -->
    <transition name="splash-fade">
      <div v-if="isInitializing" class="fixed inset-0 z-[9999] flex items-center justify-center bg-slate-900/50 dark:bg-black/75 backdrop-blur-2xl select-none">
        <div class="relative w-[480px] p-7 rounded-3xl glass-surface border border-slate-200/80 dark:border-white/20 shadow-2xl flex flex-col items-center text-center space-y-4">
          <!-- 呼吸脉冲徽标 -->
          <div class="relative flex items-center justify-center my-1">
            <div class="absolute w-20 h-20 rounded-full bg-cyan-500/20 animate-ping"></div>
            <div class="w-16 h-16 rounded-2xl overflow-hidden shadow-xl shadow-cyan-500/30 border border-white/30 flex items-center justify-center bg-slate-900/95 p-1 relative z-10">
              <img src="/logo.svg" alt="Omni-Probe Logo" class="w-full h-full object-contain filter drop-shadow(0 0 8px rgba(6,182,212,0.6))" />
            </div>
          </div>

          <!-- 系统标题与版本 -->
          <div class="space-y-0.5">
            <h2 class="text-sm font-bold text-slate-900 dark:text-white tracking-tight flex items-center justify-center gap-2">
              <span>OMNI-PROBE 网络探针系统</span>
              <span class="text-[10px] px-2 py-0.5 rounded-full bg-cyan-100 text-cyan-900 dark:bg-cyan-500/20 dark:text-cyan-300 font-mono font-bold">v0.2.4</span>
            </h2>
            <p class="text-[11px] text-slate-600 dark:text-slate-400 font-mono">工业级全栈多总线网络深度分析仪 · 正在启动自检</p>
          </div>

          <!-- 动态进度条 -->
          <div class="w-full space-y-1.5 pt-1">
            <div class="flex items-center justify-between text-xs font-mono">
              <span class="text-slate-800 dark:text-slate-200 font-medium truncate max-w-[340px]">{{ initStatusMessage }}</span>
              <span class="font-bold text-cyan-800 dark:text-cyan-300">{{ Math.round(initProgress) }}%</span>
            </div>
            <div class="w-full h-2 rounded-full bg-slate-200 dark:bg-white/10 overflow-hidden p-0.5 border border-slate-300 dark:border-white/15">
              <div class="h-full rounded-full bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-600 transition-all duration-300 shadow-sm"
                :style="{ width: `${initProgress}%` }"></div>
            </div>
          </div>

          <!-- 阶段式就绪清单 -->
          <div class="w-full grid grid-cols-2 gap-2 text-[11px] font-mono text-left pt-2">
            <div v-for="(step, idx) in initSteps" :key="idx"
              class="flex items-center gap-2 px-2.5 py-1.5 rounded-xl border transition-all"
              :class="step.done 
                ? 'bg-emerald-50 text-emerald-900 border-emerald-300 dark:bg-emerald-950/40 dark:border-emerald-800 dark:text-emerald-300 font-semibold' 
                : 'bg-slate-100/60 text-slate-500 border-slate-200 dark:bg-white/5 dark:border-white/10 dark:text-slate-400'">
              <span class="text-xs">{{ step.done ? '✓' : '○' }}</span>
              <span class="truncate">{{ step.label }}</span>
            </div>
          </div>

          <!-- 环境核心驱动微胶囊状态 (Npcap / USBPcap / Wireshark) -->
          <div class="w-full flex items-center justify-between px-3 py-1.5 rounded-xl bg-slate-100/70 dark:bg-black/30 border border-slate-200/80 dark:border-white/10 text-[10px] font-mono text-slate-600 dark:text-slate-400">
            <span class="flex items-center gap-1">
              <span>驱动探活:</span>
              <span class="text-emerald-700 dark:text-emerald-400 font-bold">Npcap ✓</span>
            </span>
            <span class="flex items-center gap-1">
              <span>物理 USB:</span>
              <span :class="isUsbpcapAvailable ? 'text-emerald-700 dark:text-emerald-400 font-bold' : 'text-amber-600 dark:text-amber-400 font-bold'">
                {{ isUsbpcapAvailable ? 'USBPcap 就绪' : 'USBPcap 缺失(降级)' }}
              </span>
            </span>
            <span class="flex items-center gap-1">
              <span>Wireshark:</span>
              <span class="text-emerald-700 dark:text-emerald-400 font-bold">3200+ 规约</span>
            </span>
          </div>
        </div>
      </div>
    </transition>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

import PacketDeepModal from './components/PacketDeepModal.vue';
import HoneypotWorkbenchModal from './components/HoneypotWorkbenchModal.vue';
import IpDossierModal from './components/IpDossierModal.vue';
import EnvironmentDiagnosticModal from './components/EnvironmentDiagnosticModal.vue';
import WirelessVlanMonitorModal from './components/WirelessVlanMonitorModal.vue';
import PacketDiffModal from './components/PacketDiffModal.vue';
import { useUniversalDiff } from './composables/useUniversalDiff';
import GlobalNotificationToast from './components/GlobalNotificationToast.vue';
import { notifySuccess, notifyInfo, notifyWarning, notifyError } from './composables/useNotification';
import TrafficAnalyzerView from './views/TrafficAnalyzerView.vue';
import AssetIntelligenceView from './views/AssetIntelligenceView.vue';
import HardwareBusView from './views/HardwareBusView.vue';
import SystemAuditView from './views/SystemAuditView.vue';
import WebAccessAuditView from './views/WebAccessAuditView.vue';
import TrafficDecryptionView from './views/TrafficDecryptionView.vue';
import ForensicsView from './views/ForensicsView.vue';
import SecurityReviewView from './views/SecurityReviewView.vue';
import GlobalGeoMapView from './views/GlobalGeoMapView.vue';
import NetAssistWorkbenchView from './views/NetAssistWorkbenchView.vue';

type WorkbenchId = 'traffic' | 'assets' | 'hardware' | 'audit' | 'web_audit' | 'decryption' | 'forensics' | 'security_review' | 'geo_map' | 'net_assist';

interface WorkbenchTab {
  id: WorkbenchId;
  label: string;
  svgPath: string;
}

const workbenchTabs: WorkbenchTab[] = [
  {
    id: 'traffic',
    label: '全息流量分析',
    svgPath: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z'
  },
  {
    id: 'assets',
    label: '资产情报态势',
    svgPath: 'M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-.778.099-1.533.284-2.253'
  },
  {
    id: 'hardware',
    label: '物理外设总线',
    svgPath: 'M8.25 3v1.5M4.5 8.25H3m18 0h-1.5M4.5 12H3m18 0h-1.5m-15 3.75H3m18 0h-1.5M8.25 19.5V21M12 3v1.5m0 15V21m3.75-18v1.5m0 15V21m-9-1.5h10.5a2.25 2.25 0 002.25-2.25V6.75a2.25 2.25 0 00-2.25-2.25H6.75A2.25 2.25 0 004.5 6.75v10.5a2.25 2.25 0 002.25 2.25zm.75-12h9v9h-9v-9z'
  },
  {
    id: 'audit',
    label: '等保基线审计',
    svgPath: 'M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z'
  },
  {
    id: 'web_audit',
    label: '上网行为审计',
    svgPath: 'M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253'
  },
  {
    id: 'decryption',
    label: '流量解密过滤',
    svgPath: 'M13.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H3.75A2.25 2.25 0 001.5 12v6.75a2.25 2.25 0 002.25 2.25z'
  },
  {
    id: 'forensics',
    label: '司法电子取证',
    svgPath: 'M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H3.75A2.25 2.25 0 001.5 12v6.75a2.25 2.25 0 002.25 2.25zM12 15a1.5 1.5 0 100-3 1.5 1.5 0 000 3z'
  },
  {
    id: 'security_review',
    label: '四维安全审查',
    svgPath: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z'
  },
  {
    id: 'geo_map',
    label: '全球网络地图',
    svgPath: 'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z'
  },
  {
    id: 'net_assist',
    label: '网络调试助手',
    svgPath: 'M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z'
  }
];

// 苹果 2026 双模态磨砂主题控制 (Apple Frosted Light / Dark Mica)
// 默认强制采用 2026 苹果冰晶磨砂明亮模式 (Apple Frosted Light)，除非用户主动存为 dark
// 绝对强制默认：苹果 2026 冰晶明亮磨砂模式 (Apple Frosted Light)
const isAppleLight = ref(true);
function toggleAppleTheme() {
  isAppleLight.value = !isAppleLight.value;
  localStorage.setItem('omni_probe_apple_theme', isAppleLight.value ? 'light' : 'dark');
  if (isAppleLight.value) {
    document.documentElement.classList.remove('theme-apple-dark');
    document.documentElement.classList.add('theme-apple-light');
    document.body.classList.remove('theme-apple-dark');
    document.body.classList.add('theme-apple-light');
  } else {
    document.documentElement.classList.remove('theme-apple-light');
    document.documentElement.classList.add('theme-apple-dark');
    document.body.classList.remove('theme-apple-light');
    document.body.classList.add('theme-apple-dark');
  }
}

// 侧边栏展开固定控制
// 默认固定展开侧栏，让 8 大工作台与 6 汉字标签一目了然
const isDockExpanded = ref(localStorage.getItem('omni_probe_dock_expanded') !== 'false');
function toggleDockPinned() {
  isDockExpanded.value = !isDockExpanded.value;
  localStorage.setItem('omni_probe_dock_expanded', isDockExpanded.value ? 'true' : 'false');
}

// 系统三维安全健康客观状态与控制中枢
const threatCount = computed(() => {
  return packets.value.filter(p => p.entropy_level === 'critical' || p.direction === 'HONEYPOT_RECV').length;
});

async function triggerEmergencyCutoff() {
  addLog('[SECURITY] ⚠️ 用户触发一键紧急切断与嗅探停机响应');
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

const activeWorkbench = ref<WorkbenchId>('traffic');

const diffBus = useUniversalDiff();

function openUniversalDiffCenter() {
  if (diffBus.slotA.value && diffBus.slotB.value) {
    diffBus.compareSlots();
  } else if (diffBus.currentItemA.value && diffBus.currentItemB.value) {
    diffBus.isDiffModalOpen.value = true;
  } else {
    diffBus.openScratchpad();
  }
}

function handleGlobalKeydown(e: KeyboardEvent) {
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'D' || e.key === 'd')) {
    e.preventDefault();
    openUniversalDiffCenter();
  }
}
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
const isWirelessVlanOpen = ref(false);
const envScore = ref<number | null>(null);

// 启动自检就绪状态与友好提示控制器
const isInitializing = ref(true);
const isUsbpcapAvailable = ref(true);
const initProgress = ref(15);
const initStatusMessage = ref('正在初始化底层通信总线与内存池...');
const initSteps = ref([
  { label: '内核旁路与环形缓冲池', done: false },
  { label: '物理网络适配器探测', done: false },
  { label: '工业现场总线与串口', done: false },
  { label: '工控规约解剖矩阵', done: false },
]);

async function loadEnvReadiness(): Promise<void> {
  try {
    const res: any = await invoke('get_environment_inspection_cmd');
    envScore.value = res.readiness_score;
    const usbpcapComp = res.components?.find((c: any) => c.id === 'usbpcap');
    if (usbpcapComp) {
      isUsbpcapAvailable.value = !!usbpcapComp.is_ready;
    }
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

function handleFilterTraffic(ip: string) {
  if (!ip) return;
  bpfFilter.value = ip;
  activeWorkbench.value = 'traffic';
  addLog(`[TRAFFIC] 已按 IP 快速过滤流量: ${ip}`);
}

onMounted(() => {
  window.addEventListener('keydown', handleGlobalKeydown);
  // 步进平滑定时器
  const progressTimer = setInterval(() => {
    if (initProgress.value < 88) {
      initProgress.value += 4;
    }
  }, 80);

  // 阶段 1: 内存池与内核旁路
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
      notifySuccess('探针中枢已就绪', selectedIface.value ? `已自动绑定网络适配器: ${selectedIface.value}` : '系统已就绪，等待选择目标网络适配器');
      if (!isUsbpcapAvailable.value) {
        setTimeout(() => {
          notifyWarning(
            '物理 USB 捕获驱动未就绪',
            '系统未检测到 USBPcap 驱动，USB 抓包已降级为只读 PnP 事件监听，无法捕获原始 URB 数据包。如需完整物理总线捕获，可点击顶栏环境诊断进行安装。'
          );
        }, 1200);
      }
    }, 250);
  }

  // 1.8 秒防卡顿兜底看门狗 (Watchdog)
  const watchdog = setTimeout(() => {
    finishInitialization();
  }, 1800);

  function checkAllReady() {
    if (initSteps.value.every(s => s.done)) {
      clearTimeout(watchdog);
      finishInitialization();
    }
  }

  // 任务 1: 环境检查
  loadEnvReadiness().finally(() => {
    initSteps.value[3].done = true;
    initProgress.value = Math.max(initProgress.value, 75);
    checkAllReady();
  });
  // 确保 DOM 根节点立即挂载苹果 2026 冰晶磨砂明亮类名
  document.documentElement.classList.remove('theme-apple-dark');
  document.documentElement.classList.add('theme-apple-light');
  document.body.classList.remove('theme-apple-dark');
  document.body.classList.add('theme-apple-light');
  localStorage.setItem('omni_probe_apple_theme', 'light');

  // 并行通道 A: 网卡枚举与后台自启嗅探 (不阻塞首屏交互)
  invoke<string[]>('list_interfaces').then((ifaces) => {
    interfaces.value = ifaces;
    if (ifaces.length > 0 && !selectedIface.value) {
      selectedIface.value = ifaces[0];
    }
    initSteps.value[1].done = true;
    initProgress.value = Math.max(initProgress.value, 65);
    initStatusMessage.value = `已检测到 ${ifaces.length} 个网络接口，已挂载物理网卡...`;
    startCapture();
    checkAllReady();
  }).catch((e) => {
    addLog(`[ERROR] 获取网卡列表失败: ${e}`);
  });

  // 并行通道 B: 物理与虚拟串口极速枚举 (不阻塞首屏交互)
  invoke<SerialPortDetail[]>('list_serial_ports_detail').then((details) => {
    serialPortsDetail.value = details;
    serialPorts.value = details.map(d => d.port_name);
    if (serialPorts.value.length > 0 && !selectedSerial.value) {
      selectedSerial.value = serialPorts.value[0];
    }
    initSteps.value[2].done = true;
    initProgress.value = Math.max(initProgress.value, 85);
    checkAllReady();
  }).catch(() => {
    invoke<string[]>('list_serial_ports').then((ports) => {
      serialPorts.value = ports;
      if (ports.length > 0 && !selectedSerial.value) {
        selectedSerial.value = ports[0];
      }
    }).catch((err) => {
      addLog(`[ERROR] 获取物理串口列表失败: ${err}`);
    });
  });

  // 并行通道 C: 活跃串口探活
  invoke<any[]>('list_active_serial_probes').then((activeList) => {
    activeSerialPorts.value = activeList.map(a => a.port_name);
    isSerialRunning.value = activeSerialPorts.value.length > 0;
  }).catch(() => {});

  // 并行通道 D: 局域网资产感知与 USB 设备扫描
  refreshAssets();
  refreshUsbDevices();

  let assetTimer: any = null;
  assetTimer = setInterval(() => {
    refreshAssets();
  }, 5000);

  onUnmounted(() => {
  window.removeEventListener('keydown', handleGlobalKeydown);
    if (assetTimer) {
      clearInterval(assetTimer);
      assetTimer = null;
    }
  });

  listen<SerialPortDetail>('serial-inserted', ({ payload }) => {
    addLog(`[SERIAL] 🔌 检测到新物理串口接入: ${payload.description} [${payload.port_name}]`);
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
    } else if (!selectedSerial.value || !serialPorts.value.includes(selectedSerial.value)) {
      const bestUsb = payload.find(d => d.is_usb && d.is_available);
      const anyUsb = payload.find(d => d.is_usb);
      const anyAvail = payload.find(d => d.is_available);
      selectedSerial.value = bestUsb?.port_name || anyUsb?.port_name || anyAvail?.port_name || serialPorts.value[0] || '';
    }
    addLog(`[SERIAL] 🔌 物理串口拓扑自动更新: 当前检测到 ${payload.length} 个通信端口`);
  });

  listen<string>('serial-disconnected', ({ payload }) => {
    activeSerialPorts.value = activeSerialPorts.value.filter(p => p !== payload);
    isSerialRunning.value = activeSerialPorts.value.length > 0;
    addLog(`[SERIAL] 🚨 物理串口 ${payload} 已断开，监听引擎已自动安全注销`);
  });

  listen<any[]>('usb-devices-changed', ({ payload }) => {
    usbDevices.value = payload;
    addLog(`[USB] 🔌 物理 USB 外设拓扑变更: 当前在线 ${payload.length} 个物理设备`);
  });

  listen<any>('hardware-alert', ({ payload }) => {
    if (typeof payload === 'string') {
      addLog(`[HARDWARE] 物理总线告警: ${payload}`);
      notifyWarning('物理总线安全告警', payload);
      return;
    }
    const alertType = payload.alert_type;
    const devName = payload.device_name || '';
    addLog(`[HARDWARE] 物理总线变更: ${alertType} - ${devName}`);

    if (alertType === 'USB_ATTACH') {
      notifyInfo('物理 USB 外设接入', devName);
      refreshUsbDevices();
    } else if (alertType === 'USB_DETACH') {
      notifyWarning('物理 USB 外设拔出', devName);
      refreshUsbDevices();
    } else if (alertType === 'SERIAL_ATTACH') {
      notifyInfo('物理串口设备接入', devName);
      refreshSerialPorts();
    } else if (alertType === 'SERIAL_DETACH') {
      notifyWarning('物理串口设备拔出', devName);
      refreshSerialPorts();
    }
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
    if (!rafId) {
      rafId = requestAnimationFrame(flushPackets);
    }
  });

  listen<any>('usb-packet', ({ payload }) => {
    pendingPackets.push(payload);
    if (!rafId) {
      rafId = requestAnimationFrame(flushPackets);
    }
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
  }).catch(() => {});
});
</script>

<style>
.custom-scrollbar::-webkit-scrollbar { width: 4px; height: 4px; }
.custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
.custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(148, 163, 184, 0.4); border-radius: 9999px; }
.custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(100, 116, 139, 0.6); }
.slide-up-enter-active, .slide-up-leave-active { transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1); }
.slide-up-enter-from, .slide-up-leave-to { opacity: 0; transform: translateY(12px); }
.splash-fade-enter-active, .splash-fade-leave-active { transition: opacity 0.35s ease, transform 0.35s ease; }
.splash-fade-enter-from { opacity: 0; transform: scale(0.97); }
.splash-fade-leave-to { opacity: 0; transform: scale(1.02); }
</style>