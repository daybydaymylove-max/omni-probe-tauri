# -*- coding: utf-8 -*-

app_vue_path = "src/App.vue"

with open(app_vue_path, "r", encoding="utf-8") as f:
    code = f.read()

# 1. Force isAppleLight = ref(true)
code = code.replace(
    "const isAppleLight = ref(localStorage.getItem('omni_probe_apple_theme') !== 'dark');",
    "// 绝对强制默认：苹果 2026 冰晶明亮磨砂模式 (Apple Frosted Light)\nconst isAppleLight = ref(true);"
)

# 2. In toggleAppleTheme, toggle class on documentElement as well
old_toggle = """function toggleAppleTheme() {
  isAppleLight.value = !isAppleLight.value;
  localStorage.setItem('omni_probe_apple_theme', isAppleLight.value ? 'light' : 'dark');
}"""

new_toggle = """function toggleAppleTheme() {
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
}"""

if old_toggle in code:
    code = code.replace(old_toggle, new_toggle)
    print("toggleAppleTheme function enhanced.")

# 3. In onMounted, ensure documentElement and body have theme-apple-light
onmounted_pattern = "onMounted(async () => {"
onmounted_replacement = """onMounted(async () => {
  // 确保 DOM 根节点立即挂载苹果 2026 冰晶磨砂明亮类名
  document.documentElement.classList.remove('theme-apple-dark');
  document.documentElement.classList.add('theme-apple-light');
  document.body.classList.remove('theme-apple-dark');
  document.body.classList.add('theme-apple-light');
  localStorage.setItem('omni_probe_apple_theme', 'light');"""

if onmounted_pattern in code:
    code = code.replace(onmounted_pattern, onmounted_replacement, 1)
    print("onMounted forced light added.")

# 4. Search input container in topbar: replace bg-black/50
code = code.replace(
    '<div class="flex items-center gap-2 px-3 py-1 rounded-full bg-black/50 border border-white/10 text-[11px] w-64 md:w-72',
    '<div class="flex items-center gap-2 px-3 py-1 rounded-full bg-white/80 dark:bg-black/50 border border-slate-300/50 dark:border-white/10 text-[11px] w-64 md:w-72'
)

# 5. OMNI-PROBE text in header
code = code.replace(
    '<span class="text-xs font-bold tracking-tight text-white/95">OMNI-PROBE</span>',
    '<span class="text-xs font-bold tracking-tight text-slate-800 dark:text-white/95">OMNI-PROBE</span>'
)

with open(app_vue_path, "w", encoding="utf-8") as f:
    f.write(code)

print("src/App.vue updated with forced pure Apple Light mode.")
