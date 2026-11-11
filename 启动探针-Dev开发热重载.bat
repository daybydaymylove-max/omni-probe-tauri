@echo off
chcp 65001 >nul
title 启动 Omni-Probe 纯正原生桌面版 (Tauri Native Desktop GUI · 无 HTTP 服务模式)

echo ======================================================================
echo  Omni-Probe 原生桌面窗口直接拉起 (非 HTTP 浏览器模式)
echo  说明: 静态前端已编译嵌入本地二进制并通过 Tauri 内嵌协议直载，
echo        不开启外部 1420 HTTP 开发端口，支持系统托盘与原生文件对话框。
echo ======================================================================
echo.

cd /d "%~dp0"
call npm run desktop
pause
