# -*- coding: utf-8 -*-
import os

app_vue_path = "src/App.vue"
style_css_path = "src/style.css"

# 1. Update style.css
with open(style_css_path, "r", encoding="utf-8") as f:
    css_content = f.read()

# Replace or append light theme rules
light_theme_idx = css_content.find("/* 苹果冰晶磨砂浅色模式全局高对比度自动适配 */")
if light_theme_idx != -1:
    css_base = css_content[:light_theme_idx]
else:
    css_base = css_content

new_light_rules = """/* 苹果冰晶磨砂浅色模式全局高对比度自动适配 (Apple Liquid Frost Light) */
.theme-apple-light {
  color: #0F172A !important;
  background-color: #F4F6FB !important;
}

.theme-apple-light .text-white {
  color: #0F172A !important;
}

.theme-apple-light .text-slate-100,
.theme-apple-light .text-slate-200,
.theme-apple-light .text-slate-300 {
  color: #1E293B !important;
}

.theme-apple-light .text-slate-400 {
  color: #475569 !important;
}

.theme-apple-light .text-slate-500 {
  color: #64748B !important;
}

/* 覆盖所有深色背景：转化为纯净透亮的苹果白昼磨砂材质 */
.theme-apple-light [class*="bg-black"],
.theme-apple-light [class*="bg-slate-900"],
.theme-apple-light [class*="bg-slate-950"],
.theme-apple-light [class*="bg-gray-900"],
.theme-apple-light [class*="bg-gray-950"],
.theme-apple-light [class*="bg-[#0"],
.theme-apple-light [class*="bg-[#1"] {
  background-color: rgba(255, 255, 255, 0.85) !important;
  color: #0F172A !important;
  border-color: rgba(0, 0, 0, 0.08) !important;
  box-shadow: 0 4px 20px -2px rgba(100, 116, 139, 0.08) !important;
}

.theme-apple-light [class*="border-white"] {
  border-color: rgba(0, 0, 0, 0.08) !important;
}

.theme-apple-light input {
  color: #0F172A !important;
}
.theme-apple-light input::placeholder {
  color: #94A3B8 !important;
}
"""

with open(style_css_path, "w", encoding="utf-8") as f:
    f.write(css_base + new_light_rules)
print("style.css updated successfully.")

# 2. Update App.vue
with open(app_vue_path, "r", encoding="utf-8") as f:
    vue_content = f.read()

# Update isAppleLight default to true (unless dark)
vue_content = vue_content.replace(
    "const isAppleLight = ref(localStorage.getItem('omni_probe_apple_theme') === 'light');",
    "// 默认强制采用 2026 苹果冰晶磨砂明亮模式 (Apple Frosted Light)，除非用户主动存为 dark\nconst isAppleLight = ref(localStorage.getItem('omni_probe_apple_theme') !== 'dark');"
)

# Update isDockExpanded default to true (unless false)
vue_content = vue_content.replace(
    "const isDockExpanded = ref(localStorage.getItem('omni_probe_dock_expanded') === 'true');",
    "// 默认固定展开侧栏，让 8 大工作台与 6 汉字标签一目了然\nconst isDockExpanded = ref(localStorage.getItem('omni_probe_dock_expanded') !== 'false');"
)

with open(app_vue_path, "w", encoding="utf-8") as f:
    f.write(vue_content)
print("App.vue defaults updated successfully.")
