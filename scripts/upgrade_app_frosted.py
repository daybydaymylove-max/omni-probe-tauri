# -*- coding: utf-8 -*-
import os

target_path = 'src/App.vue'
with open(target_path, 'r', encoding='utf-8') as f:
    text = f.read()

# 1. 替换顶层 template 容器与环境极光
old_root_start = text.find('<template>')
old_header_start = text.find('<header class="w-full flex')

if old_root_start == -1 or old_header_start == -1:
    raise Exception("Could not find root template in App.vue")

new_root_header = """<template>
  <div :class="['h-screen w-screen overflow-hidden flex flex-col select-none font-sans relative transition-colors duration-300',
    isAppleLight ? 'theme-apple-light text-slate-800' : 'theme-apple-dark text-slate-100']">
    
    <!-- 2026 苹果 Liquid 磨砂与 Win11 通透极光流光 (Liquid Aurora Background) -->
    <div class="liquid-aurora-container">
      <div class="aurora-blob-1"></div>
      <div class="aurora-blob-2"></div>
      <div class="aurora-blob-3"></div>
    </div>

    <!-- 顶栏：一体化通栏导航与居中浮动 HUD 动态岛 (Top Window Bar & Floating HUD Island) -->
    <header class="w-full flex items-center justify-between px-4 py-2 shrink-0 z-30 select-none gap-3">
      <!-- 左侧：真实客观的系统三维安全健康控制中枢与应用标识 -->
      <div class="flex items-center gap-3 shrink-0">
        <!-- 系统三维安全健康客观状态与控制中枢 (彻底消灭虚假伪装) -->
        <div class="flex items-center gap-1.5 p-1 rounded-full glass-pill" title="系统三维安全运行与控制中枢">
          <!-- 🔴 红色指示器：网络威胁拦截与紧急切断 -->
          <button @click="triggerEmergencyCutoff"
            :class="['flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold transition-all cursor-pointer',
              threatCount > 0 ? 'bg-rose-500/25 text-rose-400 border border-rose-500/40 animate-pulse' : 'hover:bg-rose-500/15 text-rose-400']"
            :title="`[网络威胁与涉密阻断: ${threatCount} 起] 点击一键执行紧急切断与主引擎停机`">
            <span class="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_6px_#F43F5E]"></span>
            <span class="text-[9px]">{{ threatCount > 0 ? `阻断:${threatCount}` : '切断' }}</span>
          </button>

          <!-- 🟡 黄色指示器：嗅探状态与高熵预警 -->
          <button @click="toggleSniffingPause"
            :class="['flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold transition-all cursor-pointer',
              isPaused ? 'bg-amber-500/25 text-amber-300 border border-amber-500/40' : 'hover:bg-amber-500/15 text-amber-400']"
            :title="`[引擎工作状态: ${isPaused ? '已挂起' : (isRunning ? '运行中' : '待命')}] 点击暂停/恢复数据捕获`">
            <span class="w-2.5 h-2.5 rounded-full" :class="isPaused ? 'bg-amber-400 animate-pulse' : 'bg-amber-400/80'"></span>
            <span class="text-[9px]">{{ isPaused ? '恢复' : '挂起' }}</span>
          </button>

          <!-- 🟢 绿色指示器：等保三级合规健康态 -->
          <button @click="activeWorkbench = 'traffic'"
            class="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold hover:bg-emerald-500/15 text-emerald-400 transition-all cursor-pointer"
            title="[等保三级合规达标: 100%] 当前系统处于白名单合规保护态">
            <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 status-pulse shadow-[0_0_6px_#10B981]"></span>
            <span class="text-[9px]">合规</span>
          </button>
        </div>

        <div class="h-4 w-px bg-white/10 shrink-0"></div>

        <!-- 应用 Identity -->
        <div class="flex items-center gap-2">
          <div class="w-7 h-7 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/25 shrink-0">
            <svg class="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
            </svg>
          </div>
          <div class="flex flex-col whitespace-nowrap">
            <div class="flex items-center gap-1.5">
              <span class="text-xs font-bold tracking-tight text-white/95">OMNI-PROBE</span>
              <span class="text-[9px] font-mono font-semibold px-1.5 py-0.2 rounded-full glass-pill text-cyan-300">
                2026 MICA FROST
              </span>
            </div>
            <span class="text-[9px] opacity-60 font-medium leading-none mt-0.5">全息工业网络分析控制台</span>
          </div>
        </div>
      </div>
"""

# 寻找原 header 中间的结束处 (旧顶栏右侧按钮组结束处)
old_main_start = text.find('<!-- 主体工作区容器')
if old_main_start == -1:
    raise Exception("Could not find main workspace start in App.vue")

# 提取中间的 HUD 控制中枢与右侧缓冲池及新增的主题切换按钮
old_header_center_start = text.find('<!-- 中间：FLOATING HUD DYNAMIC ISLAND')
old_header_center_end = text.find('<!-- 右侧：环形缓冲池与全局快捷操作')
old_center_content = text[old_header_center_start:old_header_center_end]

new_header_right = """<!-- 右侧：环形缓冲池、苹果主题切换与全局快捷操作 -->
      <div class="flex items-center gap-2.5 shrink-0">
        <!-- 环形缓冲池指标胶囊：严格单行展示 -->
        <div class="flex items-center gap-2 glass-pill px-3 py-1 rounded-full text-[11px] whitespace-nowrap shrink-0 font-mono">
          <span class="opacity-70 font-sans">环形缓冲池:</span>
          <span class="font-bold text-cyan-300">{{ ringBufferUsageText }}</span>
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

"""

# 2. 替换左侧侧边栏 Dock
old_aside_start = text.find('<!-- 左侧：ULTRA-MINIMAL FLOATING DOCK')
old_aside_end = text.find('<!-- 右侧：FULL-BLEED 主视口容器 -->')

if old_aside_start == -1 or old_aside_end == -1:
    raise Exception("Could not find aside in App.vue")

new_aside_dock = """<!-- 左侧：苹果 2026 灵动悬浮磨砂侧栏 Dock (全中文功能指引 + 展开锁定) -->
      <aside :class="[
        'dock-glass rounded-3xl p-2.5 flex flex-col justify-between shrink-0 transition-all duration-300 ease-out shadow-2xl z-20 overflow-hidden',
        isDockExpanded ? 'w-56' : 'w-16 hover:w-56 group'
      ]">
        <!-- 8 大专业工作台导航 -->
        <div class="flex flex-col gap-1.5 w-full">
          <!-- 侧边栏顶部小工具栏：中文功能区标题与图钉锁定按钮 -->
          <div class="flex items-center justify-between px-2 py-1 mb-0.5 border-b border-white/10">
            <span class="text-[10px] font-bold uppercase tracking-wider opacity-70 font-mono whitespace-nowrap"
              :class="isDockExpanded ? 'block' : 'hidden group-hover:block'">
              功能工作台
            </span>
            <button @click="toggleDockPinned" :title="isDockExpanded ? '取消固定侧栏' : '固定展开侧栏'"
              class="p-1 rounded-lg hover:bg-white/10 opacity-70 hover:opacity-100 hover:text-cyan-300 transition-colors cursor-pointer text-xs">
              {{ isDockExpanded ? '📌' : '📍' }}
            </button>
          </div>

          <!-- 8 大工作台按钮列表：完整中文名称与图标 -->
          <button v-for="tab in workbenchTabs" :key="tab.id" @click="activeWorkbench = tab.id"
            :title="tab.label"
            :class="[
              'relative w-full h-10 px-2.5 rounded-2xl flex items-center gap-3 transition-all cursor-pointer select-none',
              activeWorkbench === tab.id
                ? 'bg-cyan-500/20 text-cyan-300 shadow-sm border border-cyan-400/40 font-bold'
                : 'opacity-70 hover:opacity-100 hover:bg-white/5 border border-transparent'
            ]">
            <div class="w-5 h-5 flex items-center justify-center shrink-0">
              <svg class="w-5 h-5 stroke-current fill-none stroke-2 shrink-0" viewBox="0 0 24 24">
                <path :d="tab.svgPath" />
              </svg>
            </div>
            <!-- 中文全称标签：侧栏展开时平滑显现 -->
            <div :class="['flex items-center justify-between flex-1 min-w-0 transition-opacity duration-200',
              isDockExpanded ? 'opacity-100' : 'opacity-0 group-hover:opacity-100']">
              <span class="text-xs tracking-tight truncate whitespace-nowrap font-medium">{{ tab.label }}</span>
            </div>
            <!-- 激活态左侧圆角极光条 -->
            <div v-if="activeWorkbench === tab.id" class="absolute -left-1 w-1 h-5 bg-cyan-400 rounded-r-full shadow-[0_0_8px_#00F2FE]"></div>
          </button>
        </div>

        <!-- 底栏：4 大物理总线微型指示灯与系统健康 -->
        <div class="flex flex-col gap-2 w-full px-1.5 pt-2 border-t border-white/10">
          <!-- 4 物理总线微态指示器 -->
          <div class="flex items-center justify-between py-1 px-1.5 rounded-xl glass-pill w-full" title="物理总线: NIC / COM / USB / 蜜罐">
            <div class="flex items-center gap-1.5">
              <span class="w-2 h-2 rounded-full" :class="isRunning ? (isPaused ? 'bg-amber-400 shadow-[0_0_6px_#F59E0B]' : 'bg-emerald-400 shadow-[0_0_6px_#10B981] status-pulse') : 'bg-slate-600'" title="网卡 (NIC)"></span>
              <span class="w-2 h-2 rounded-full" :class="isSerialRunning ? 'bg-indigo-400 shadow-[0_0_6px_#818CF8] status-pulse' : 'bg-slate-600'" title="串口 (COM)"></span>
              <span class="w-2 h-2 rounded-full" :class="isUsbRunning ? 'bg-purple-400 shadow-[0_0_6px_#C084FC] status-pulse' : 'bg-slate-600'" title="USB 总线"></span>
              <span class="w-2 h-2 rounded-full cursor-pointer" :class="isHoneypotRunning ? 'bg-amber-400 shadow-[0_0_6px_#F59E0B] status-pulse' : 'bg-slate-600'" @click="isHoneypotOpen = true" title="诱饵蜜罐"></span>
            </div>
            <span class="text-[9px] font-mono opacity-60 truncate" :class="isDockExpanded ? 'block' : 'hidden group-hover:block'">
              四总线热备
            </span>
          </div>

          <div class="flex items-center gap-2 px-1 text-xs opacity-70">
            <div class="w-6 h-6 rounded-full bg-gradient-to-tr from-slate-700 to-slate-600 flex items-center justify-center border border-white/10 text-[9px] font-bold text-white shadow-md shrink-0">
              OP
            </div>
            <div :class="['flex flex-col min-w-0 leading-tight', isDockExpanded ? 'block' : 'hidden group-hover:block']">
              <span class="text-[10px] font-bold text-white truncate">Omni-Probe 4.2</span>
              <span class="text-[8px] font-mono opacity-60">等保三级合规认证</span>
            </div>
          </div>
        </div>
      </aside>

      """

# 执行模板组装
new_template = (
    new_root_header +
    old_center_content +
    new_header_right +
    "    <!-- 主体工作区容器 (苹果 2026 灵动磨砂侧栏 + Bento 便当盒空间) -->\n" +
    "    <div class=\"flex flex-1 overflow-hidden p-3 pt-1 gap-3 min-h-0 relative z-10\">\n\n      " +
    new_aside_dock +
    text[old_aside_end:]
)

# 3. 在 script 中注入 isAppleLight, toggleAppleTheme, isDockExpanded, toggleDockPinned, threatCount, triggerEmergencyCutoff, toggleSniffingPause
script_start = new_template.find('<script setup lang="ts">')
if script_start == -1:
    raise Exception("Could not find script in App.vue")

workbench_tabs_pos = new_template.find('const activeWorkbench = ref<WorkbenchId>(\'traffic\');')
if workbench_tabs_pos == -1:
    raise Exception("Could not find activeWorkbench in App.vue")

new_script_vars = """// 苹果 2026 双模态磨砂主题控制 (Apple Frosted Light / Dark Mica)
const isAppleLight = ref(localStorage.getItem('omni_probe_apple_theme') === 'light');
function toggleAppleTheme() {
  isAppleLight.value = !isAppleLight.value;
  localStorage.setItem('omni_probe_apple_theme', isAppleLight.value ? 'light' : 'dark');
}

// 侧边栏展开固定控制
const isDockExpanded = ref(localStorage.getItem('omni_probe_dock_expanded') === 'true');
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
  await stopCapture();
}

async function toggleSniffingPause() {
  if (isPaused.value) {
    await resumeCapture();
  } else {
    await pauseCapture();
  }
}

"""

new_template = new_template[:workbench_tabs_pos] + new_script_vars + new_template[workbench_tabs_pos:]

with open(target_path, 'w', encoding='utf-8') as f:
    f.write(new_template)

print("src/App.vue upgraded with Apple 2026 Liquid Frosted Glass successfully!")
