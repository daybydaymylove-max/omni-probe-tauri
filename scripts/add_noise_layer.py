# -*- coding: utf-8 -*-

app_vue_path = "src/App.vue"

with open(app_vue_path, "r", encoding="utf-8") as f:
    code = f.read()

target = """    <!-- 2026 苹果 Liquid 磨砂与 Win11 通透极光流光 (Liquid Aurora Background) -->
    <div class="liquid-aurora-container">
      <div class="aurora-blob-1"></div>
      <div class="aurora-blob-2"></div>
      <div class="aurora-blob-3"></div>
    </div>"""

replacement = """    <!-- 2026 苹果 Liquid 磨砂与 Win11 通透极光流光 (Liquid Aurora Background) -->
    <div class="liquid-aurora-container">
      <div class="aurora-blob-1"></div>
      <div class="aurora-blob-2"></div>
      <div class="aurora-blob-3"></div>
    </div>
    <!-- 实体物理微米级噪点滤镜层 (Physical Materiality Noise Layer) -->
    <div class="noise-layer"></div>"""

if target in code:
    code = code.replace(target, replacement, 1)
    with open(app_vue_path, "w", encoding="utf-8") as f:
        f.write(code)
    print("noise-layer added to App.vue.")
else:
    print("Target not found directly.")
