@echo off
chcp 65001 >nul
title 启动 Omni-Probe 开发热重载模式 (Dev Mode)

echo ======================================================================
echo  Omni-Probe 开发热重载模式
echo  提示: 将自动启动 Vite 开发服务器 (127.0.0.1:1420) 并挂起 Tauri 调试窗口
echo ======================================================================
echo.

cd /d "%~dp0"
call npm run tauri dev
pause
