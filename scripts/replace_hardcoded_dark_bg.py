# -*- coding: utf-8 -*-
import glob
import re

files_to_check = glob.glob("src/views/*.vue") + glob.glob("src/components/*.vue")

replaced_count = 0

for file_path in files_to_check:
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    orig_content = content
    # Replace bg-[#0B0F17] / bg-[#0F1520] / bg-[#0e1017] with glass-surface or adaptive classes
    content = re.sub(r'bg-\[#0B0F17\](?:/85|/90)?', 'glass-surface', content)
    content = re.sub(r'bg-\[#0F1520\](?:/80|/90)?', 'glass-surface', content)
    content = re.sub(r'bg-\[#0e1017\](?:/95)?', 'glass-surface', content)

    if content != orig_content:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Updated {file_path}")
        replaced_count += 1

print(f"Total files updated: {replaced_count}")
