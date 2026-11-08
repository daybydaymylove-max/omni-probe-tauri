# -*- coding: utf-8 -*-

style_css = """@import "tailwindcss";

/* ------------------------------------------------------------- */
/* 2026 苹果磨砂 (Apple Liquid Frosted Glass) 与 Win11 Mica 材质变量 */
/* 默认：纯正苹果冰晶磨砂明亮质感 (Apple Liquid Frost Light) */
/* ------------------------------------------------------------- */
:root {
  --font-ui: "Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI Variable", "Segoe UI", Roboto, sans-serif;
  --font-mono: "JetBrains Mono", Consolas, "Courier New", monospace;

  /* 默认：苹果 2026 冰晶磨砂与 Win11 亚克力白昼明亮 */
  --bg-base: #F4F6FB;
  --bg-surface: rgba(255, 255, 255, 0.82);
  --bg-surface-elevated: rgba(255, 255, 255, 0.94);
  --border-subtle: rgba(0, 0, 0, 0.08);
  --border-highlight: rgba(255, 255, 255, 0.95);
  --text-primary: #0F172A;
  --text-secondary: #475569;
  --text-muted: #64748B;
  --glow-cyan: rgba(0, 242, 254, 0.20);
  --glow-blue: rgba(79, 172, 254, 0.20);
  --dock-bg: rgba(255, 255, 255, 0.88);
}

/* 仅当显式切换至暗黑模式时激活深色变量 */
.theme-apple-dark {
  --bg-base: #0B0E14;
  --bg-surface: rgba(20, 24, 35, 0.65);
  --bg-surface-elevated: rgba(30, 36, 52, 0.78);
  --border-subtle: rgba(255, 255, 255, 0.10);
  --border-highlight: rgba(255, 255, 255, 0.20);
  --text-primary: #F1F5F9;
  --text-secondary: #94A3B8;
  --text-muted: #64748B;
  --glow-cyan: rgba(0, 242, 254, 0.25);
  --glow-blue: rgba(79, 172, 254, 0.25);
  --dock-bg: rgba(18, 22, 32, 0.72);
}

* {
  box-sizing: border-box;
  -webkit-font-smoothing: antialiased;
}

body {
  margin: 0;
  padding: 0;
  font-family: var(--font-ui);
  background-color: var(--bg-base);
  color: var(--text-primary);
  overflow: hidden;
  user-select: none;
  transition: background-color 0.3s ease, color 0.3s ease;
}

/* ------------------------------------------------------------- */
/* 通透环境极光流光 (Liquid Aurora Background) */
/* 苹果磨砂与 Win11 亚克力核心：必须有底层流光渗透方显通透高雅 */
/* ------------------------------------------------------------- */
.liquid-aurora-container {
  position: absolute;
  inset: 0;
  pointer-events: none;
  z-index: 0;
  overflow: hidden;
}

.aurora-blob-1 {
  position: absolute;
  top: -80px;
  left: 15%;
  width: 580px;
  height: 580px;
  border-radius: 9999px;
  filter: blur(100px);
  pointer-events: none;
  background: radial-gradient(circle, rgba(56, 189, 248, 0.25) 0%, rgba(96, 165, 250, 0.15) 50%, transparent 70%);
  transition: all 0.5s ease;
}

.aurora-blob-2 {
  position: absolute;
  bottom: -80px;
  right: 20%;
  width: 550px;
  height: 550px;
  border-radius: 9999px;
  filter: blur(100px);
  pointer-events: none;
  background: radial-gradient(circle, rgba(192, 132, 252, 0.22) 0%, rgba(129, 140, 248, 0.12) 50%, transparent 70%);
  transition: all 0.5s ease;
}

.aurora-blob-3 {
  position: absolute;
  top: 35%;
  right: 5%;
  width: 320px;
  height: 320px;
  border-radius: 9999px;
  filter: blur(90px);
  pointer-events: none;
  background: radial-gradient(circle, rgba(52, 211, 153, 0.20) 0%, transparent 70%);
  transition: all 0.5s ease;
}

/* 深色模式流光配色 */
.theme-apple-dark .aurora-blob-1 {
  background: radial-gradient(circle, rgba(6, 182, 212, 0.16) 0%, rgba(59, 130, 246, 0.08) 50%, transparent 70%);
}
.theme-apple-dark .aurora-blob-2 {
  background: radial-gradient(circle, rgba(147, 51, 234, 0.15) 0%, rgba(99, 102, 241, 0.08) 50%, transparent 70%);
}
.theme-apple-dark .aurora-blob-3 {
  background: radial-gradient(circle, rgba(16, 185, 129, 0.12) 0%, transparent 70%);
}

/* ------------------------------------------------------------- */
/* 苹果磨砂核心材质类 (Apple Liquid Frosted Glass) */
/* ------------------------------------------------------------- */
.glass-surface,
.glass-apple {
  background: var(--bg-surface) !important;
  backdrop-filter: blur(42px) saturate(190%) !important;
  -webkit-backdrop-filter: blur(42px) saturate(190%) !important;
  border: 1px solid var(--border-subtle) !important;
  box-shadow: 
    inset 0 1px 1px 0 var(--border-highlight),
    0 16px 36px -12px rgba(100, 116, 139, 0.12) !important;
  transition: background-color 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease;
}

.theme-apple-dark .glass-surface,
.theme-apple-dark .glass-apple {
  box-shadow: 
    inset 0 1px 1px 0 rgba(255, 255, 255, 0.14),
    0 20px 42px -12px rgba(0, 0, 0, 0.55) !important;
}

/* 悬浮磨砂胶囊 (Glass Pill) */
.glass-pill {
  background: rgba(255, 255, 255, 0.75) !important;
  backdrop-filter: blur(24px) saturate(180%) !important;
  -webkit-backdrop-filter: blur(24px) saturate(180%) !important;
  border: 1px solid var(--border-subtle) !important;
  box-shadow: inset 0 1px 0 0 rgba(255, 255, 255, 1), 0 2px 6px rgba(0, 0, 0, 0.04) !important;
  color: #1E293B !important;
  transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1) !important;
}

.glass-pill:hover {
  background: rgba(255, 255, 255, 0.95) !important;
  border-color: rgba(0, 0, 0, 0.15) !important;
  transform: translateY(-0.5px);
}

.theme-apple-dark .glass-pill {
  background: rgba(255, 255, 255, 0.05) !important;
  border-color: var(--border-subtle) !important;
  box-shadow: inset 0 1px 0 0 var(--border-highlight) !important;
  color: #F1F5F9 !important;
}
.theme-apple-dark .glass-pill:hover {
  background: rgba(255, 255, 255, 0.09) !important;
  border-color: var(--border-highlight) !important;
}

/* 苹果 Dock 侧边栏专属磨砂 */
.dock-glass {
  background: var(--dock-bg) !important;
  backdrop-filter: blur(48px) saturate(200%) !important;
  -webkit-backdrop-filter: blur(48px) saturate(200%) !important;
  border: 1px solid var(--border-subtle) !important;
}

/* 大排印 Display 大字号雕塑感 */
.metric-display {
  font-size: 2.75rem;
  line-height: 1;
  font-weight: 800;
  letter-spacing: -0.04em;
  background: linear-gradient(180deg, #0F172A 0%, #475569 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.theme-apple-dark .metric-display {
  background: linear-gradient(180deg, #FFFFFF 0%, #94A3B8 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

/* 状态呼吸灯微发光脉冲 */
@keyframes subtle-pulse {
  0%, 100% { opacity: 0.95; transform: scale(1); }
  50% { opacity: 0.55; transform: scale(1.08); }
}
.status-pulse {
  animation: subtle-pulse 2.8s infinite ease-in-out;
}

/* 极细微米级滚动条 */
::-webkit-scrollbar {
  width: 5px;
  height: 5px;
}
::-webkit-scrollbar-track {
  background: transparent;
}
::-webkit-scrollbar-thumb {
  background: rgba(148, 163, 184, 0.25);
  border-radius: 9999px;
}
::-webkit-scrollbar-thumb:hover {
  background: rgba(148, 163, 184, 0.45);
}

/* 动画过渡类 */
.slide-up-enter-active,
.slide-up-leave-active {
  transition: all 0.25s ease-out;
}
.slide-up-enter-from,
.slide-up-leave-to {
  opacity: 0;
  transform: translateY(12px);
}

/* ------------------------------------------------------------- */
/* 彻底消灭全局深色硬编码样式：全部映射为明亮苹果磨砂 */
/* ------------------------------------------------------------- */
:not(.theme-apple-dark) [class*="bg-black"],
:not(.theme-apple-dark) [class*="bg-slate-900"],
:not(.theme-apple-dark) [class*="bg-slate-950"],
:not(.theme-apple-dark) [class*="bg-gray-900"],
:not(.theme-apple-dark) [class*="bg-gray-950"],
:not(.theme-apple-dark) [class*="bg-[#0"],
:not(.theme-apple-dark) [class*="bg-[#1"] {
  background-color: rgba(255, 255, 255, 0.85) !important;
  color: #0F172A !important;
  border-color: rgba(0, 0, 0, 0.08) !important;
  box-shadow: 0 4px 20px -2px rgba(100, 116, 139, 0.08) !important;
}

:not(.theme-apple-dark) [class*="border-white"] {
  border-color: rgba(0, 0, 0, 0.08) !important;
}

:not(.theme-apple-dark) .text-white {
  color: #0F172A !important;
}

:not(.theme-apple-dark) .text-slate-100,
:not(.theme-apple-dark) .text-slate-200,
:not(.theme-apple-dark) .text-slate-300 {
  color: #1E293B !important;
}

:not(.theme-apple-dark) .text-slate-400 {
  color: #475569 !important;
}

:not(.theme-apple-dark) .text-slate-500 {
  color: #64748B !important;
}

input {
  color: #0F172A;
}
input::placeholder {
  color: #94A3B8;
}
"""

with open("src/style.css", "w", encoding="utf-8") as f:
    f.write(style_css)

print("src/style.css written with pure Apple Light Frost as DEFAULT :root.")
