with open('src/App.vue', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. 顶栏液态玻璃化
t1 = '<header class="w-full flex items-center justify-between px-4 py-2 shrink-0 z-30 select-none gap-3">'
r1 = '<header class="header-glass w-full flex items-center justify-between px-4 py-2 shrink-0 z-30 select-none gap-3">'
if t1 in text:
    text = text.replace(t1, r1, 1)

# 2. 右下角告警弹框液态玻璃化
old_alert_prefix = 'fixed bottom-4 right-4 bg-slate-900/95'
new_alert_prefix = 'fixed bottom-4 right-4 glass-surface backdrop-blur-2xl text-slate-800'
if old_alert_prefix in text:
    text = text.replace(old_alert_prefix, new_alert_prefix, 1)

old_rose = 'text-rose-200'
new_rose = 'text-rose-600 font-bold'
if old_rose in text:
    text = text.replace(old_rose, new_rose, 1)

with open('src/App.vue', 'w', encoding='utf-8') as f:
    f.write(text)

print("APP_VUE_SUCCESS")
