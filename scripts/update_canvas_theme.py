# -*- coding: utf-8 -*-

view_path = "src/views/TrafficAnalyzerView.vue"

with open(view_path, "r", encoding="utf-8") as f:
    code = f.read()

# 1. Update canvas container style
code = code.replace(
    '<div class="relative flex-1 rounded-xl bg-black/40 border border-white/5 overflow-hidden flex items-center justify-center">',
    '<div class="relative flex-1 rounded-xl bg-slate-900/10 dark:bg-black/40 border border-slate-300/30 dark:border-white/5 overflow-hidden flex items-center justify-center">'
)

# 2. Update telemetry bar in canvas
code = code.replace(
    '<div class="absolute bottom-2.5 left-3 flex items-center gap-5 pointer-events-none z-10 bg-black/60 backdrop-blur-md px-3.5 py-1.5 rounded-xl border border-white/10 shadow-lg font-mono">',
    '<div class="absolute bottom-2.5 left-3 flex items-center gap-5 pointer-events-none z-10 glass-pill px-3.5 py-1.5 rounded-xl shadow-lg font-mono">'
)

# 3. Update canvas render theme sensitivity
old_render_start = """    ctx.clearRect(0, 0, w, h);

    // 绘制微米级暗调网格
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.025)';"""

new_render_start = """    ctx.clearRect(0, 0, w, h);

    const isLightMode = document.querySelector('.theme-apple-light') !== null;

    // 绘制微米级暗调网格 (自适应浅色与深色)
    ctx.strokeStyle = isLightMode ? 'rgba(0, 0, 0, 0.04)' : 'rgba(255, 255, 255, 0.025)';"""

if old_render_start in code:
    code = code.replace(old_render_start, new_render_start)
    print("Canvas grid theme updated.")

old_link_stroke = """      ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
      ctx.lineWidth = 1.5;"""

new_link_stroke = """      ctx.strokeStyle = isLightMode ? 'rgba(0, 0, 0, 0.12)' : 'rgba(255, 255, 255, 0.08)';
      ctx.lineWidth = 1.5;"""

if old_link_stroke in code:
    code = code.replace(old_link_stroke, new_link_stroke)
    print("Canvas link stroke updated.")

old_node_label = """      ctx.fillStyle = 'rgba(10, 13, 20, 0.85)';
      ctx.beginPath();
      ctx.roundRect(nx - textW / 2 - 5, rectY, textW + 10, 15, 4);
      ctx.fill();
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.12)';
      ctx.stroke();

      ctx.fillStyle = '#E2E8F0';
      ctx.fillText(n.label, nx, labelY);"""

new_node_label = """      ctx.fillStyle = isLightMode ? 'rgba(255, 255, 255, 0.92)' : 'rgba(10, 13, 20, 0.85)';
      ctx.beginPath();
      ctx.roundRect(nx - textW / 2 - 5, rectY, textW + 10, 15, 4);
      ctx.fill();
      ctx.strokeStyle = isLightMode ? 'rgba(0, 0, 0, 0.1)' : 'rgba(255, 255, 255, 0.12)';
      ctx.stroke();

      ctx.fillStyle = isLightMode ? '#0F172A' : '#E2E8F0';
      ctx.fillText(n.label, nx, labelY);"""

if old_node_label in code:
    code = code.replace(old_node_label, new_node_label)
    print("Canvas node label updated.")

with open(view_path, "w", encoding="utf-8") as f:
    f.write(code)

print("TrafficAnalyzerView.vue canvas styling updated successfully.")
