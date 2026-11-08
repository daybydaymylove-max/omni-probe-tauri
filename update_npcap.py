import urllib.request
import os
import json

url = 'https://npcap.com/dist/npcap-1.88.exe'
installer_path = 'npcap-1.88.exe'
old_installer = 'npcap-1.79.exe'

print('Downloading Npcap 1.88...')
try:
    urllib.request.urlretrieve(url, installer_path)
    print('Downloaded Npcap 1.88 successfully.')
    
    if os.path.exists(old_installer):
        os.remove(old_installer)
        print('Removed old 1.79 installer.')
        
    file_path = 'src-tauri/tauri.conf.json'
    with open(file_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
        
    if 'bundle' in config and 'resources' in config['bundle']:
        resources = config['bundle']['resources']
        if '../npcap-1.79.exe' in resources:
            resources.remove('../npcap-1.79.exe')
        if '../npcap-1.88.exe' not in resources:
            resources.append('../npcap-1.88.exe')
            
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print("Tauri config updated for 1.88.")

except Exception as e:
    print('Error:', e)
