# ==============================================================================
# Omni-Probe 工业全能探针系统 - Windows 本地开发证书自签名工具
# 用于消除杀毒软件未知二进制误报与 SmartScreen 拦截
# ==============================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Omni-Probe 本地 Authenticode 代码签名工具" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$ExePath = Join-Path $PSScriptRoot "src-tauri\target\release\omni-probe-tauri.exe"
$CertSubject = "CN=OmniProbe Industrial Probe Enterprise, O=ChinaCPU, C=CN"

if (-not (Test-Path $ExePath)) {
    Write-Host "[错误] 未找到目标可执行文件: $ExePath" -ForegroundColor Red
    Write-Host "请先运行构建生成 release 可执行文件。" -ForegroundColor Yellow
    exit 1
}

Write-Host "[1/3] 检查/创建本地受信任代码签名证书..." -ForegroundColor Yellow
$ExistingCert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -like "*OmniProbe*" } | Select-Object -First 1

if (-not $ExistingCert) {
    Write-Host "正在生成自签名代码证书: $CertSubject ..." -ForegroundColor Gray
    $Cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $CertSubject -CertStoreLocation Cert:\CurrentUser\My -HashAlgorithm SHA256
    
    # 导出并导入到当前用户的受信任根证书颁发机构
    $CertBytes = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $TempCertPath = [System.IO.Path]::GetTempFileName()
    [System.IO.File]::WriteAllBytes($TempCertPath, $CertBytes)
    Import-Certificate -FilePath $TempCertPath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
    Remove-Item $TempCertPath -Force
    Write-Host "✅ 证书已成功创建并信任！" -ForegroundColor Green
} else {
    $Cert = $ExistingCert
    Write-Host "✅ 发现已存在本地证书: $($Cert.Thumbprint)" -ForegroundColor Green
}

Write-Host "[2/3] 对可执行程序执行 Authenticode 代码签名..." -ForegroundColor Yellow
$SignResult = Set-AuthenticodeSignature -FilePath $ExePath -Certificate $Cert -HashAlgorithm SHA256

if ($SignResult.Status -eq "Valid") {
    Write-Host "✅ 代码签名成功！文件状态: Valid" -ForegroundColor Green
} else {
    Write-Host "⚠️ 签名完成，状态: $($SignResult.Status) ($($SignResult.StatusMessage))" -ForegroundColor Yellow
}

Write-Host "[3/3] 同步复制已签名的可执行文件至项目根目录..." -ForegroundColor Yellow
$RootExe = Join-Path $PSScriptRoot "omni-probe-tauri.exe"
Copy-Item -Path $ExePath -Destination $RootExe -Force
Write-Host "✅ 已就绪: $RootExe" -ForegroundColor Green
Write-Host "现在可以双击运行 omni-probe-tauri.exe，不再被误报为无签名威胁！" -ForegroundColor Cyan
