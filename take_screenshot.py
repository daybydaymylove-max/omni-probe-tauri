import platform
import os
try:
    from PIL import ImageGrab
    img = ImageGrab.grab()
    img.save('screenshot.png')
    print('Screenshot saved using PIL.')
except Exception as e:
    print('PIL failed:', e)
