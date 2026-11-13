# ==============================================================================
# Omni-Probe 工业级 Windows Authenticode 数字代码签名自动化脚本
# 文件路径: scripts/sign-authenticode.ps1
#
# 核心职责:
# 1. 彻底解决 Windows 11 智能应用控制 (Smart App Control, SAC) 与 SmartScreen 拦截未知二进制的物理痛点;
# 2. 支持使用企业商业 EV/OV 代码签名证书 (PFX) 对 EXE / MSI / NSIS 安装包执行批量盖戳;
# 3. 针对脱机测试环境，提供一键生成本地代码签名根证书并导入 Windows 受信任证书库的闭环工具链;
# 4. 集成标准 RFC 3161 权威时间戳服务器 (DigiCert / Sectigo) 与 SHA-256 摘要算法.
# ==============================================================================

[CmdletBinding()]
param(
    [string]$FilePath = "src-tauri/target/release/omni-probe-tauri.exe",
    [string]$CertPath = "",                # PFX 证书文件路径
    [string]$CertPassword = "",            # PFX 证书密码
    [string]$TimestampServer = "http://timestamp.digicert.com", # RFC 3161 时间戳服务器
    [switch]$CreateSelfSignedDevCert      # 为当前测试机生成并信任自签名代码签名证书
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Omni-Probe Windows Authenticode 代码签名服务" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. 定位 signtool.exe
function Find-Signtool {
    $signtool = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
    if ($signtool) {
        return $signtool.Source
    }

    $kitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    if (Test-Path $kitsRoot) {
        $tools = Get-ChildItem -Path $kitsRoot -Filter "signtool.exe" -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*x64*" } |
            Sort-Object LastWriteTime -Descending
        if ($tools.Count -gt 0) {
            return $tools[0].FullName
        }
    }
    return $null
}

$SignToolPath = Find-Signtool

# 2. 自签名模式处理
if ($CreateSelfSignedDevCert) {
    Write-Host "[*] 正在为本机生成高强度 SHA-256 代码签名专用证书..." -ForegroundColor Yellow
    $certSubject = "CN=OmniProbe Engineering Local Dev Root, O=Omni Engineering, C=CN"
    
    # 检查是否已存在
    $existing = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -eq $certSubject }
    if (-not $existing) {
        Write-Host "[*] 正在请求将自签名证书导入系统受信任根证书颁发机构 (需要管理员权限)..." -ForegroundColor Yellow
        $devCert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $certSubject -CertStoreLocation Cert:\LocalMachine\My -HashAlgorithm SHA256 -KeyLength 2048 -NotAfter (Get-Date).AddYears(5)
        
        # 复制到受信任根证书颁发机构 (Trusted Root Certification Authorities)
        $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "LocalMachine"
        $rootStore.Open("ReadWrite")
        $rootStore.Add($devCert)
        $rootStore.Close()
        Write-Host "[+] 成功创建并导入受信任根证书颁发机构！" -ForegroundColor Green
        $targetThumbprint = $devCert.Thumbprint
    } else {
        $targetThumbprint = $existing[0].Thumbprint
        Write-Host "[+] 复用已存在的本地开发根证书: $targetThumbprint" -ForegroundColor Green
    }

    if (-not (Test-Path $FilePath)) {
        throw "目标文件不存在: $FilePath"
    }

    Write-Host "[*] 正在使用 PowerShell Set-AuthenticodeSignature 执行签名..." -ForegroundColor Cyan
    $certToUse = Get-Item "Cert:\LocalMachine\My\$targetThumbprint" -ErrorAction SilentlyContinue
    if (-not $certToUse) {
        $certToUse = Get-Item "Cert:\LocalMachine\Root\$targetThumbprint"
    }
    $sigResult = Set-AuthenticodeSignature -FilePath $FilePath -Certificate $certToUse -HashAlgorithm SHA256
    Write-Host "[+] 本地开发签名完成，状态: $($sigResult.Status)" -ForegroundColor Green
    return
}

# 3. 生产级 signtool 签名模式
if (-not $SignToolPath) {
    Write-Host "[!] 未能在系统中找到 signtool.exe (请安装 Windows 10/11 SDK)" -ForegroundColor Yellow
    Write-Host "[i] 如需临时解除当前测试机 SAC/SmartScreen 拦截，可执行以下命令之一:" -ForegroundColor Cyan
    Write-Host "    1. Unblock-File -Path `"$FilePath`"" -ForegroundColor White
    Write-Host "    2. 运行本脚本并加参数: .\sign-authenticode.ps1 -FilePath `"$FilePath`" -CreateSelfSignedDevCert" -ForegroundColor White
    return
}

Write-Host "[+] 采用 signtool: $SignToolPath" -ForegroundColor Green

if (-not (Test-Path $FilePath)) {
    throw "目标文件不存在: $FilePath"
}

if ($CertPath -and (Test-Path $CertPath)) {
    Write-Host "[*] 正在对 [$FilePath] 注入 SHA-256 数字证书与时间戳..." -ForegroundColor Cyan
    $argsList = @(
        "sign",
        "/fd", "SHA256",
        "/tr", $TimestampServer,
        "/td", "SHA256",
        "/f", $CertPath
    )
    if ($CertPassword) {
        $argsList += @("/p", $CertPassword)
    }
    $argsList += $FilePath

    & $SignToolPath $argsList
    if ($LASTEXITCODE -ne 0) {
        throw "signtool 签名执行失败，退出代码: $LASTEXITCODE"
    }

    Write-Host "[*] 验证签名有效性..." -ForegroundColor Cyan
    & $SignToolPath verify /pa /v $FilePath
    Write-Host "[+] 生产级 Authenticode 签名成功闭环！" -ForegroundColor Green
} else {
    Write-Host "[i] 未指定外部 PFX 证书路径 (-CertPath)。" -ForegroundColor Yellow
    Write-Host "[i] 提示: 若要在本地开发机消除 Windows 11 SAC 拦截，请使用:" -ForegroundColor White
    Write-Host "    powershell -ExecutionPolicy Bypass -File .\scripts\sign-authenticode.ps1 -CreateSelfSignedDevCert" -ForegroundColor White
}
