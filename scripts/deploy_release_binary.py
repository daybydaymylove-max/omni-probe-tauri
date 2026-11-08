# -*- coding: utf-8 -*-
import os
import shutil
import time

src = os.path.abspath("src-tauri/target/release/omni-probe-tauri.exe")
dst = os.path.abspath("./omni-probe-tauri.exe")

if not os.path.exists(src):
    print(f"Error: Source file does not exist: {src}")
    exit(1)

# Check if dst is locked, retry up to 5 times
for attempt in range(5):
    try:
        shutil.copy2(src, dst)
        size = os.path.getsize(dst)
        mtime = time.ctime(os.path.getmtime(dst))
        print(f"Success: Deployed {dst}")
        print(f"File Size: {size} bytes")
        print(f"Last Modified: {mtime}")
        break
    except PermissionError as e:
        print(f"Attempt {attempt + 1}: Destination is locked by running process, retrying in 2 seconds...")
        time.sleep(2)
else:
    print("Failed to overwrite omni-probe-tauri.exe because it is currently locked by a running process.")
    exit(1)
