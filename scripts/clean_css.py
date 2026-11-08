# -*- coding: utf-8 -*-
with open('src/style.css', 'r', encoding='utf-8') as f:
    text = f.read()

pos = text.find('/* 苹果冰晶磨砂浅色模式全局高对比度自动适配 */')
header = text[:pos] if pos != -1 else text

clean_section = """/* 苹果冰晶磨砂浅色模式全局高对比度自动适配 */
.theme-apple-light {
  color: #0F172A !important;
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
  color: #64748B !important;
}

.theme-apple-light [class*="bg-black"] {
  background-color: rgba(241, 245, 249, 0.75) !important;
  border-color: rgba(0, 0, 0, 0.08) !important;
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

with open('src/style.css', 'w', encoding='utf-8') as f:
    f.write(header + clean_section)
print('style.css cleaned perfectly!')
