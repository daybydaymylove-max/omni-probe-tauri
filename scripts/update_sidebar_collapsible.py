# -*- coding: utf-8 -*-

app_vue_path = "src/App.vue"

with open(app_vue_path, "r", encoding="utf-8") as f:
    code = f.read()

# 1. Add sidebar toggle button next to app identity in topbar
old_identity = """        <!-- 应用 Identity -->
        <div class="flex items-center gap-2">"""

new_identity = """        <!-- 应用 Identity 与侧边栏快捷收缩/展开按钮 -->
        <div class="flex items-center gap-1.5">
          <button @click="toggleDockPinned"
            :title="isDockExpanded ? '收起左侧菜单栏' : '展开左侧菜单栏'"
            class="p-1.5 rounded-xl hover:bg-black/5 dark:hover:bg-white/10 text-slate-500 hover:text-cyan-600 dark:hover:text-cyan-300 transition-all cursor-pointer mr-0.5"
            aria-label="切换侧栏">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h8m-8 6h16" />
            </svg>
          </button>"""

if old_identity in code:
    code = code.replace(old_identity, new_identity, 1)
    print("Top bar sidebar toggle button added.")

# 2. Replace entire <aside> sidebar block
aside_start = code.find("<!-- 左侧：苹果 2026 灵动悬浮磨砂侧栏 Dock")
aside_end = code.find("</aside>") + len("</aside>")

if aside_start != -1 and aside_end != -1:
    new_aside = """<!-- 左侧：苹果 2026 灵动悬浮磨砂侧栏 (支持平滑收缩为 Mini 图标栏与展开为 6 汉字面板) -->
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
              <span class="text-[10px] font-bold text-slate-800 dark:text-white truncate">Omni-Probe 4.2</span>
              <span class="text-[8px] font-mono opacity-60">等保三级合规认证</span>
            </div>
          </div>
        </div>
      </aside>"""
    code = code[:aside_start] + new_aside + code[aside_end:]
    print("Sidebar rewritten with full collapsible mechanics.")
else:
    print("Sidebar block not matched directly.")

with open(app_vue_path, "w", encoding="utf-8") as f:
    f.write(code)

print("update_sidebar_collapsible.py executed.")
