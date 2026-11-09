$version = "v0.2.1"
$binName = "omni-probe-tauri.exe"
$releaseBin = "src-tauri/target/release/$binName"

Write-Host "Checking binary: $releaseBin"
if (-Not (Test-Path $releaseBin)) {
    Write-Error "Release binary $releaseBin not found!"
    exit 1
}

$winZip = "omni-probe-tauri-$version-windows-x64.zip"
$sourceZip = "omni-probe-tauri-$version-source.zip"

# Remove existing zip files if any
if (Test-Path $winZip) { Remove-Item $winZip -Force }
if (Test-Path $sourceZip) { Remove-Item $sourceZip -Force }

# 1. Package Windows Release Binary
Write-Host "Packaging Windows Release to $winZip ..."
$tempDir = "temp_release_win"
if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
New-Item -ItemType Directory -Path $tempDir | Out-Null

Copy-Item $releaseBin -Destination "$tempDir/$binName"
Copy-Item "README.md" -Destination "$tempDir/README.md"
if (Test-Path "LICENSE") { Copy-Item "LICENSE" -Destination "$tempDir/LICENSE" }

Compress-Archive -Path "$tempDir/*" -DestinationPath $winZip -CompressionLevel Optimal
Remove-Item -Recurse -Force $tempDir
Write-Host "Created $winZip successfully."

# 2. Package Clean Source Code (using git archive)
Write-Host "Packaging clean source code using git archive to $sourceZip ..."
git archive --format=zip -o $sourceZip HEAD
Write-Host "Created $sourceZip successfully."

# Check file sizes
Get-Item $winZip, $sourceZip | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
