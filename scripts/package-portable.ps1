# ==============================================================================
# Omni-Probe 工业级 Windows 纯绿色免安装脱机便携打包工具
# 文件路径: scripts/package-portable.ps1
#
# 核心职责:
# 1. 彻底解决离线隔离网络与精简版 Windows 11 (Tiny11/LTSC) 缺失 WebView2 运行时痛点;
# 2. 自动拉取 Release 产物 (omni-probe-tauri.exe) 与 WebView2Runtime 绿色便携目录合并;
# 3. 配合主程序启动时的 WEBVIEW2_BROWSER_EXECUTABLE_FOLDER 自动探测注入逻辑，实现脱机双击即跑;
# 4. 自动生成 SHA-256 完整性哈希校验清单与便携运行指引.
# ==============================================================================

[CmdletBinding()]
param(
    [string]$Version = "0.3.4",
    [string]$SourceExe = "src-tauri/target/release/omni-probe-tauri.exe",
    [string]$OutputDir = "dist",
    [string]$WebView2FixedRuntimeDir = "" # 可选：本地已下载的 WebView2 Fixed Version 文件夹路径
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Omni-Probe v$Version 绿色便携离线包自动化构建流程启动" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. 验证目标执行文件
if (-not (Test-Path $SourceExe)) {
    Write-Host "[!] 未找到 Release 执行文件: $SourceExe" -ForegroundColor Yellow
    Write-Host "[*] 正在执行生产级构建: cargo build --release ..." -ForegroundColor Gray
    Push-Location "src-tauri"
    cargo build --release
    Pop-Location
}

if (-not (Test-Path $SourceExe)) {
    throw "构建失败，未能生成目标文件: $SourceExe"
}

$ExeSize = (Get-Item $SourceExe).Length
Write-Host "[+] 找到 Release 可执行文件: $SourceExe ($([math]::Round($ExeSize / 1MB, 2)) MB)" -ForegroundColor Green

# 2. 建立便携发行目录
$PortableDirName = "OmniProbe-Portable-v$Version"
$TargetDir = Join-Path $OutputDir $PortableDirName
if (Test-Path $TargetDir) {
    Remove-Item -Recurse -Force $TargetDir
}
New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null

# 3. 复制核心程序
$DestExe = Join-Path $TargetDir "omni-probe-tauri.exe"
Copy-Item -Path $SourceExe -Destination $DestExe -Force
Write-Host "[+] 核心程序复制完成: $DestExe" -ForegroundColor Green

# 4. 组装绿色 WebView2Runtime 目录
$DestWv2Dir = Join-Path $TargetDir "WebView2Runtime"
if ($WebView2FixedRuntimeDir -and (Test-Path $WebView2FixedRuntimeDir)) {
    Write-Host "[*] 正在复制外部指定的 WebView2 Fixed Version 运行时..." -ForegroundColor Cyan
    Copy-Item -Recurse -Path $WebView2FixedRuntimeDir -Destination $DestWv2Dir -Force
    Write-Host "[+] 离线独立 WebView2 运行时已内嵌完成: $DestWv2Dir" -ForegroundColor Green
} else {
    New-Item -ItemType Directory -Path $DestWv2Dir -Force | Out-Null
    $PlaceholderReadme = Join-Path $DestWv2Dir "README-离线运行时说明.txt"
    $ReadmeContent = @"
【Omni-Probe 离线绿色独立运行时目录说明】

若您所运行的 Windows 电脑为纯离线机房环境、或被深度精简的 Windows 11/10 (提示 Could not find the WebView2 Runtime):
1. 请从微软官方下载 Microsoft Edge WebView2 Fixed Version (固定版本独立分发包):
   https://developer.microsoft.com/en-us/microsoft-edge/webview2/
2. 将下载的 CAB/Zip 包解压后的所有 dll 与 exe 文件直接放入本目录 (WebView2Runtime\) 即可。
3. Omni-Probe 启动时会自动识别本目录并无感知接管，无需在操作系统安装任何软件，实现 100% 绿色便携！
"@
    Set-Content -Path $PlaceholderReadme -Value $ReadmeContent -Encoding UTF8
    Write-Host "[i] 预置绿色便携自愈引导: $PlaceholderReadme" -ForegroundColor Gray
}

# 5. 生成一键启动与环境修复引导批处理
$LauncherBat = Join-Path $TargetDir "启动 Omni-Probe (一键环境修复).bat"
$BatContent = @"
@echo off
chcp 65001 >nul
title Omni-Probe 绿色便携启动与自检工具
echo ========================================================
echo   Omni-Probe 工业全能网络探针系统 - 环境快速自检
echo ========================================================

:: 1. 自动剥离 Windows 11 智能应用控制 (SAC) 与网络下载 Mark-of-the-Web (MOTW) 阻断标记
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path '%~dp0' -File | ForEach-Object { Unblock-File -Path `$_.FullName -ErrorAction SilentlyContinue }" >nul 2>&1

:: 2. 检查主程序完整性
if not exist "%~dp0omni-probe-tauri.exe" (
    echo [错误] 未在当前目录下找到 omni-probe-tauri.exe！
    echo 请确认是否已被杀毒软件误隔离或未完整解压。
    pause
    exit /b 1
)

:: 3. 启动主程序
start "" "%~dp0omni-probe-tauri.exe"
exit
"@
Set-Content -Path $LauncherBat -Value $BatContent -Encoding Default
Write-Host "[+] 一键启动与环境自愈批处理生成完成: $LauncherBat" -ForegroundColor Green

# 6. 生成便携运行指引
$GuidePath = Join-Path $TargetDir "使用说明.txt"
$GuideContent = @"
================================================================================
Omni-Probe 工业全能网络探针与网工工具箱 (v$Version 绿色便携版)
================================================================================

【特性与运行环境】
1. 本程序为单文件绿色免安装架构，解压后双击 omni-probe-tauri.exe 即可运行。
2. 原生内置 RFC 1035 DNS 探针、RFC 1350 TFTP 固件分发服务器、RFC 854 网工管理终端 (Telnet/SSH)。
3. 支持 Npcap 驱动抓包与 Windows 原生免驱 NDIS-ETW 链路层抓包双轨自愈。
4. 快捷键:
   - Ctrl + T : 秒开网工高频原子工具箱 (子网计算/VLSM/TCPing/TFTP/管理终端/离线字典)
   - Ctrl + N : 启动/停止网络报文捕获流水线

【常见运行提示处理】
- 若遇到 Windows 11 智能应用控制 (SAC) 拦截:
  由于本地构建的开源程序未在微软公网安全图谱累积商业信誉，请右键属性勾选【解除锁定】，
  或使用配套 scripts/sign-authenticode.ps1 脚本为二进制注入合规签名。
- 若提示缺少 WebView2:
  将微软官方 WebView2 Fixed Version 解压放置于本程序同级的 WebView2Runtime\ 目录即可脱机自愈。
================================================================================
"@
Set-Content -Path $GuidePath -Value $GuideContent -Encoding UTF8

# 6. 计算 SHA-256 校验和
$ExeHash = (Get-FileHash -Path $DestExe -Algorithm SHA256).Hash
$ChecksumPath = Join-Path $TargetDir "SHA256SUMS.txt"
Set-Content -Path $ChecksumPath -Value "$ExeHash  omni-probe-tauri.exe" -Encoding ASCII
Write-Host "[+] SHA-256: $ExeHash" -ForegroundColor Yellow

# 7. 压缩生成便携发布包
$ZipPath = Join-Path $OutputDir "$PortableDirName.zip"
if (Test-Path $ZipPath) {
    Remove-Item -Force $ZipPath
}
Write-Host "[*] 正在打包便携 ZIP 压缩包..." -ForegroundColor Cyan
Compress-Archive -Path "$TargetDir\*" -DestinationPath $ZipPath -CompressionLevel Optimal
$ZipSize = (Get-Item $ZipPath).Length
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  打包成功！" -ForegroundColor Green
Write-Host "  便携包路径: $ZipPath ($([math]::Round($ZipSize / 1MB, 2)) MB)" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
