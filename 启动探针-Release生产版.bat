@echo off
chcp 65001 >nul
title 启动 Omni-Probe 探针系统 (Release 生产发布版)

echo ======================================================================
echo  Omni-Probe 企业级多总线全能探针监控面板
echo  模式: Release 独立发布版 (UI 资源已 100%% 静态内嵌，无需本地开发端口)
echo ======================================================================
echo.

set EXE_PATH=%~dp0src-tauri\target\release\omni-probe-tauri.exe

if not exist "%EXE_PATH%" (
    echo [错误] 未检测到 Release 可执行程序: %EXE_PATH%
    echo 请先执行构建或检查编译产物。
    pause
    exit /b 1
)

echo [信息] 正在启动原生客户端窗口...
start "" "%EXE_PATH%"
exit
