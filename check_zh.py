import os
import re
with open('src/App.vue', 'r', encoding='utf-8') as f:
    code = f.read()
    
# Let's check the buttons and header text
matches = re.findall(r'<button[^>]*>(.*?)</button>', code)
print("Buttons:", matches)

print("Title:", re.findall(r'<h1[^>]*>(.*?)</h1>', code))
print("Headers:", re.findall(r'<th[^>]*>(.*?)</th>', code))
