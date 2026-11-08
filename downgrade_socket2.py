import os
import re

file_path = 'src-tauri/Cargo.toml'
with open(file_path, 'r', encoding='utf-8') as f:
    toml = f.read()

toml = toml.replace('socket2 = "0.5"', 'socket2 = "0.4.3"')

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(toml)

file_path2 = 'src-tauri/src/sniffer.rs'
with open(file_path2, 'r', encoding='utf-8') as f:
    code = f.read()

code = code.replace('Type::raw()', 'Type::RAW')

with open(file_path2, 'w', encoding='utf-8') as f:
    f.write(code)

print("Downgraded socket2 and reverted to Type::RAW")
