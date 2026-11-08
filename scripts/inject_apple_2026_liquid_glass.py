# -*- coding: utf-8 -*-

style_path = "src/style.css"
html_path = "index.html"
app_vue_path = "src/App.vue"

# 1. Update index.html to include noise texture & ambient canvas container
with open(html_path, "r", encoding="utf-8") as f:
    html_code = f.read()

# Make sure html has noise overlay and liquid styling
if "noise-layer" not in html_code:
    html_code = html_code.replace(
        '<body class="overflow-hidden bg-[#F4F6FB] text-slate-800 select-none theme-apple-light">',
        '<body class="overflow-hidden bg-[#F4F6FB] text-slate-800 select-none theme-apple-light relative">'
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_code)
    print("index.html updated.")

# 2. Complete rewrite of style.css with authentic 2026 Apple Liquid Glass Physics
style_css = """@import "tailwindcss";

/* ============================================================= */
/* 2026 苹果液态玻璃 (Apple Liquid Frosted Glass) 核心物理材质引擎 */
/* ============================================================= */
:root {
  --font-ui: "Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI Variable", "Segoe UI", Roboto, sans-serif;
  --font-mono: "JetBrains Mono", Consolas, "Courier New", monospace;

  /* 默认：苹果 2026 白昼冰晶液态玻璃 (Apple Liquid Frost Light) */
  --bg-base: #F4F6FB;
  --text-primary: #0F172A;
  --text-secondary: #334155;
  --text-muted: #64748B;
  --border-subtle: rgba(255, 255, 255, 0.85);
  --border-highlight: rgba(255, 255, 255, 0.98);
}

.theme-apple-dark {
  --bg-base: #07090E;
  --text-primary: #F8FAFC;
  --text-secondary: #CBD5E1;
  --text-muted: #94A3B8;
  --border-subtle: rgba(255, 255, 255, 0.12);
  --border-highlight: rgba(255, 255, 255, 0.22);
}

* {
  box-sizing: border-box;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

body {
  margin: 0;
  padding: 0;
  font-family: var(--font-ui);
  background-color: var(--bg-base);
  color: var(--text-primary);
  overflow: hidden;
  user-select: none;
  transition: background-color 0.35s cubic-bezier(0.16, 1, 0.3, 1), color 0.35s ease;
}

/* ------------------------------------------------------------- */
/* 动态液态环境极光 (Liquid Ambient Aurora Drift) */
/* 苹果 2026 液态玻璃精髓：底层流体光斑缓慢呼吸流动，折射出波光粼粼的微光 */
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
  top: -120px;
  left: 12%;
  width: 680px;
  height: 680px;
  border-radius: 9999px;
  filter: blur(110px);
  pointer-events: none;
  background: radial-gradient(circle, rgba(0, 242, 254, 0.32) 0%, rgba(79, 172, 254, 0.18) 45%, transparent 70%);
  animation: aurora-drift-1 22s infinite ease-in-out;
}

.aurora-blob-2 {
  position: absolute;
  bottom: -100px;
  right: 18%;
  width: 640px;
  height: 640px;
  border-radius: 9999px;
  filter: blur(110px);
  pointer-events: none;
  background: radial-gradient(circle, rgba(192, 132, 252, 0.28) 0%, rgba(129, 140, 248, 0.15) 50%, transparent 70%);
  animation: aurora-drift-2 26s infinite ease-in-out;
}

.aurora-blob-3 {
  position: absolute;
  top: 30%;
  right: 4%;
  width: 420px;
  height: 420px;
  border-radius: 9999px;
  filter: blur(95px);
  pointer-events: none;
  background: radial-gradient(circle, rgba(52, 211, 153, 0.24) 0%, rgba(16, 185, 129, 0.10) 50%, transparent 70%);
  animation: aurora-drift-3 18s infinite ease-in-out;
}

@keyframes aurora-drift-1 {
  0%, 100% { transform: translate(0, 0) scale(1); }
  50% { transform: translate(70px, 40px) scale(1.10); }
}

@keyframes aurora-drift-2 {
  0%, 100% { transform: translate(0, 0) scale(1); }
  50% { transform: translate(-60px, -35px) scale(1.08); }
}

@keyframes aurora-drift-3 {
  0%, 100% { transform: translate(0, 0) scale(1); }
  50% { transform: translate(45px, -50px) scale(1.14); }
}

/* 深色模式流光配色 */
.theme-apple-dark .aurora-blob-1 {
  background: radial-gradient(circle, rgba(0, 242, 254, 0.20) 0%, rgba(59, 130, 246, 0.10) 45%, transparent 70%);
}
.theme-apple-dark .aurora-blob-2 {
  background: radial-gradient(circle, rgba(168, 85, 247, 0.18) 0%, rgba(99, 102, 241, 0.08) 50%, transparent 70%);
}
.theme-apple-dark .aurora-blob-3 {
  background: radial-gradient(circle, rgba(16, 185, 129, 0.14) 0%, transparent 70%);
}

/* 微米级物理噪点层：消除色阶断层，赋予实体玻璃厚度质感 */
.noise-layer {
  position: absolute;
  inset: 0;
  opacity: 0.022;
  pointer-events: none;
  z-index: 1;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E");
}

/* ------------------------------------------------------------- */
/* 2026 苹果液态玻璃核心表面 (Apple Liquid Glass Surfaces) */
/* ------------------------------------------------------------- */
.glass-surface,
.glass-apple {
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.72) 0%, rgba(255, 255, 255, 0.48) 100%) !important;
  backdrop-filter: blur(40px) saturate(200%) !important;
  -webkit-backdrop-filter: blur(40px) saturate(200%) !important;
  border: 1px solid rgba(255, 255, 255, 0.85) !important;
  box-shadow: 
    0 20px 45px -15px rgba(100, 116, 139, 0.14),
    inset 0 1.5px 1px 0 rgba(255, 255, 255, 0.98),
    inset 0 -1px 1px 0 rgba(0, 0, 0, 0.03) !important;
  transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}

.theme-apple-dark .glass-surface,
.theme-apple-dark .glass-apple {
  background: linear-gradient(135deg, rgba(18, 22, 32, 0.75) 0%, rgba(10, 14, 22, 0.60) 100%) !important;
  border: 1px solid rgba(255, 255, 255, 0.12) !important;
  box-shadow: 
    0 24px 48px -15px rgba(0, 0, 0, 0.65),
    inset 0 1.5px 1px 0 rgba(255, 255, 255, 0.18),
    inset 0 -1px 1px 0 rgba(0, 0, 0, 0.5) !important;
}

/* 苹果 Dock 侧边栏专属液态悬浮材质 */
.dock-glass {
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.78) 0%, rgba(255, 255, 255, 0.58) 100%) !important;
  backdrop-filter: blur(48px) saturate(210%) !important;
  -webkit-backdrop-filter: blur(48px) saturate(210%) !important;
  border: 1px solid rgba(255, 255, 255, 0.90) !important;
  box-shadow: 
    0 24px 50px -12px rgba(100, 116, 139, 0.16),
    inset 0 1.5px 1.5px 0 rgba(255, 255, 255, 1) !important;
}

.theme-apple-dark .dock-glass {
  background: linear-gradient(180deg, rgba(18, 22, 34, 0.82) 0%, rgba(12, 15, 24, 0.70) 100%) !important;
  border: 1px solid rgba(255, 255, 255, 0.14) !important;
  box-shadow: 
    0 24px 50px -12px rgba(0, 0, 0, 0.75),
    inset 0 1.5px 1.5px 0 rgba(255, 255, 255, 0.18) !important;
}

/* 悬浮磨砂胶囊 (Glass Pill / Liquid Dynamic Island) */
.glass-pill {
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.82) 0%, rgba(255, 255, 255, 0.60) 100%) !important;
  backdrop-filter: blur(28px) saturate(190%) !important;
  -webkit-backdrop-filter: blur(28px) saturate(190%) !important;
  border: 1px solid rgba(255, 255, 255, 0.90) !important;
  box-shadow: 
    0 4px 16px -2px rgba(100, 116, 139, 0.10),
    inset 0 1px 0 0 rgba(255, 255, 255, 1) !important;
  color: #1E293B !important;
  transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1) !important;
}

.glass-pill:hover {
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.96) 0%, rgba(255, 255, 255, 0.78) 100%) !important;
  border-color: rgba(0, 242, 254, 0.40) !important;
  box-shadow: 
    0 8px 24px -4px rgba(0, 242, 254, 0.25),
    inset 0 1px 0 0 rgba(255, 255, 255, 1) !important;
  transform: translateY(-0.5px);
}

.theme-apple-dark .glass-pill {
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.08) 0%, rgba(255, 255, 255, 0.03) 100%) !important;
  border-color: rgba(255, 255, 255, 0.12) !important;
  box-shadow: inset 0 1px 0 0 rgba(255, 255, 255, 0.16) !important;
  color: #F1F5F9 !important;
}

.theme-apple-dark .glass-pill:hover {
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.14) 0%, rgba(255, 255, 255, 0.06) 100%) !important;
  border-color: rgba(0, 242, 254, 0.35) !important;
  box-shadow: 0 8px 24px -4px rgba(0, 242, 254, 0.20) !important;
}

/* Display 大字号雕塑感 */
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
  background: rgba(148, 163, 184, 0.30);
  border-radius: 9999px;
}
::-webkit-scrollbar-thumb:hover {
  background: rgba(148, 163, 184, 0.50);
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
/* 全局自适应浅色苹果液态玻璃映射 */
/* ------------------------------------------------------------- */
:not(.theme-apple-dark) [class*="bg-black"],
:not(.theme-apple-dark) [class*="bg-slate-900"],
:not(.theme-apple-dark) [class*="bg-slate-950"],
:not(.theme-apple-dark) [class*="bg-gray-900"],
:not(.theme-apple-dark) [class*="bg-gray-950"],
:not(.theme-apple-dark) [class*="bg-[#0"],
:not(.theme-apple-dark) [class*="bg-[#1"] {
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.75) 0%, rgba(255, 255, 255, 0.52) 100%) !important;
  color: #0F172A !important;
  border-color: rgba(255, 255, 255, 0.85) !important;
  box-shadow: 
    0 16px 36px -12px rgba(100, 116, 139, 0.12),
    inset 0 1px 1px 0 rgba(255, 255, 255, 0.95) !important;
}

:not(.theme-apple-dark) [class*="border-white"] {
  border-color: rgba(255, 255, 255, 0.85) !important;
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

with open(style_path, "w", encoding="utf-8") as f:
    f.write(style_css)

print("src/style.css written with true 2026 Apple Liquid Glass Physics.")
