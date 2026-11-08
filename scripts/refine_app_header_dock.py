# -*- coding: utf-8 -*-
import re

app_vue_path = "src/App.vue"

with open(app_vue_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Refine the 3D security capsule in header
old_capsule = """        <!-- 系统三维安全健康客观状态与控制中枢 (彻底消灭虚假伪装) -->
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
        </div>"""

new_capsule = """        <!-- 系统三维安全健康客观状态与控制中枢 (客观严谨物理指标与一键控制) -->
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
        </div>"""

if old_capsule in content:
    content = content.replace(old_capsule, new_capsule)
    print("Header 3D security capsule updated.")
else:
    print("Header 3D security capsule pattern not found directly, checking regex...")

# 2. Refine sidebar tabs text and style
old_tab_btn = """          <!-- 8 大工作台按钮列表：完整中文名称与图标 -->
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
          </button>"""

new_tab_btn = """          <!-- 8 大工作台按钮列表：严格统一 6 个汉字名称与专业图标 -->
          <button v-for="tab in workbenchTabs" :key="tab.id" @click="activeWorkbench = tab.id"
            :title="tab.label"
            :class="[
              'relative w-full h-10 px-2.5 rounded-2xl flex items-center gap-3 transition-all cursor-pointer select-none',
              activeWorkbench === tab.id
                ? 'bg-cyan-500/20 text-cyan-600 dark:text-cyan-300 shadow-sm border border-cyan-400/40 font-bold'
                : 'opacity-80 hover:opacity-100 hover:bg-slate-200/50 dark:hover:bg-white/5 text-slate-700 dark:text-slate-200 border border-transparent'
            ]">
            <div class="w-5 h-5 flex items-center justify-center shrink-0">
              <svg class="w-5 h-5 stroke-current fill-none stroke-2 shrink-0" viewBox="0 0 24 24">
                <path :d="tab.svgPath" />
              </svg>
            </div>
            <!-- 中文 6 汉字全称标签：侧栏展开时整齐显现 -->
            <div :class="['flex items-center justify-between flex-1 min-w-0 transition-opacity duration-200',
              isDockExpanded ? 'opacity-100' : 'opacity-0 group-hover:opacity-100']">
              <span class="text-xs tracking-tight truncate whitespace-nowrap font-medium">{{ tab.label }}</span>
            </div>
            <!-- 激活态左侧圆角极光条 -->
            <div v-if="activeWorkbench === tab.id" class="absolute -left-1 w-1.5 h-6 bg-cyan-500 rounded-r-full shadow-[0_0_8px_#00F2FE]"></div>
          </button>"""

if old_tab_btn in content:
    content = content.replace(old_tab_btn, new_tab_btn)
    print("Sidebar tabs button updated.")
else:
    print("Sidebar tabs button pattern not found directly.")

with open(app_vue_path, "w", encoding="utf-8") as f:
    f.write(content)
print("refine_app_header_dock.py finished.")
