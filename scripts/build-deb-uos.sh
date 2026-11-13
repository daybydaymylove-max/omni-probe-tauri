#!/bin/bash
# ==============================================================================
# Omni-Probe 工业全能网络探针 - 统信 UOS / Deepin / Debian 原生 .deb 打包脚本
# 文件路径: scripts/build-deb-uos.sh
#
# 核心职责:
# 1. 面向统信 UOS (V20/V23)、深度 Deepin 及 Debian/Ubuntu 信创生态环境构建合规安装包;
# 2. 自动注入 Linux 原生 Linux Capabilities (CAP_NET_RAW, CAP_NET_ADMIN);
# 3. 彻底根除信创用户必须 sudo root 启动才能捕获网络数据包的体验断点;
# 4. 自动集成 XDG 桌面菜单、多分辨率图标与全局命令行软链接.
# ==============================================================================

set -euo pipefail

VERSION="0.3.4"
ARCH="${1:-amd64}" # 支持 amd64, arm64, loongarch64
SOURCE_BIN="src-tauri/target/release/omni-probe-tauri"
BUILD_ROOT="dist/deb_build/omni-probe_${VERSION}_${ARCH}"

echo "=========================================================="
echo "  Omni-Probe v${VERSION} 信创 UOS/Debian .deb 构建服务"
echo "  目标架构: ${ARCH}"
echo "=========================================================="

# 1. 检查二进制产物
if [ ! -f "${SOURCE_BIN}" ]; then
    echo "[*] 未找到 Release 二进制，正在执行跨平台编译..."
    cargo build --release --manifest-path src-tauri/Cargo.toml
fi

if [ ! -f "${SOURCE_BIN}" ]; then
    echo "[!] 编译失败，未找到目标文件: ${SOURCE_BIN}"
    exit 1
fi

# 2. 建立目录树
rm -rf "${BUILD_ROOT}"
mkdir -p "${BUILD_ROOT}/DEBIAN"
mkdir -p "${BUILD_ROOT}/opt/omni-probe"
mkdir -p "${BUILD_ROOT}/usr/bin"
mkdir -p "${BUILD_ROOT}/usr/share/applications"
mkdir -p "${BUILD_ROOT}/usr/share/icons/hicolor/512x512/apps"

# 3. 复制可执行文件与资源
cp -p "${SOURCE_BIN}" "${BUILD_ROOT}/opt/omni-probe/omni-probe-tauri"
chmod 755 "${BUILD_ROOT}/opt/omni-probe/omni-probe-tauri"

cp -p scripts/omni-probe.desktop "${BUILD_ROOT}/usr/share/applications/omni-probe.desktop"
chmod 644 "${BUILD_ROOT}/usr/share/applications/omni-probe.desktop"

# 图标处理 (若存在 app-icon 则复制，否则生成软链接)
if [ -f "src-tauri/icons/icon.png" ]; then
    cp -p "src-tauri/icons/icon.png" "${BUILD_ROOT}/usr/share/icons/hicolor/512x512/apps/omni-probe.png"
elif [ -f "src-tauri/icons/128x128.png" ]; then
    cp -p "src-tauri/icons/128x128.png" "${BUILD_ROOT}/usr/share/icons/hicolor/512x512/apps/omni-probe.png"
fi

# 创建全局命令行快捷执行
ln -sf "/opt/omni-probe/omni-probe-tauri" "${BUILD_ROOT}/usr/bin/omni-probe"

# 4. 编写 DEBIAN/control 控制文件
cat <<EOF > "${BUILD_ROOT}/DEBIAN/control"
Package: omni-probe
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Omni Engineering Team <daybydaymylove2009@gmail.com>
Depends: libwebkit2gtk-4.1-0 | libwebkit2gtk-4.0-37, libpcap0.8, libglib2.0-0, libssl3 | libssl1.1, libc6
Description: Omni-Probe 工业全能网络探针与网工工具箱
 Omni-Probe 是一款工业级多总线协议审计、跨介质流式差分比对与网络工程师现场应急工具集。
 原生内置 RFC 1035 DNS 探针、RFC 1350 TFTP 服务器、RFC 854 管理终端 (Telnet/SSH)、
 IEEE 802.1AB LLDP/CDP 拓扑发现、SNMPv3 USM 加密采集、Modbus/S7/104 工控协议解码与 WFP/nftables 防护。
EOF

# 5. 编写 DEBIAN/postinst 自动提权脚本 (免 root 抓包核心)
cat <<'EOF' > "${BUILD_ROOT}/DEBIAN/postinst"
#!/bin/sh
set -e

# 为可执行文件赋予 Linux 原生网络底层抓包与网卡配置权能，免去以 root 权限运行的安全隐患
if command -v setcap >/dev/null 2>&1; then
    echo "正在配置 Omni-Probe 原生底层网络抓包权限 (CAP_NET_RAW, CAP_NET_ADMIN)..."
    setcap cap_net_raw,cap_net_admin=eip /opt/omni-probe/omni-probe-tauri || true
fi

# 更新图标与桌面缓存
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q /usr/share/icons/hicolor || true
fi

exit 0
EOF
chmod 755 "${BUILD_ROOT}/DEBIAN/postinst"

# 6. 编写 DEBIAN/prerm 卸载前清理脚本
cat <<'EOF' > "${BUILD_ROOT}/DEBIAN/prerm"
#!/bin/sh
set -e
rm -f /usr/bin/omni-probe
exit 0
EOF
chmod 755 "${BUILD_ROOT}/DEBIAN/prerm"

# 7. 执行 dpkg-deb 打包
OUTPUT_DEB="dist/omni-probe_${VERSION}_${ARCH}.deb"
mkdir -p dist
if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --build "${BUILD_ROOT}" "${OUTPUT_DEB}"
    echo "=========================================================="
    echo "  [+] UOS/Debian 原生软件包打包成功！"
    echo "  产物路径: ${OUTPUT_DEB}"
    echo "=========================================================="
else
    echo "[i] 当前系统未安装 dpkg-deb，构建目录已就绪: ${BUILD_ROOT}"
    echo "    可在 UOS / Debian 终端直接运行: dpkg-deb --build ${BUILD_ROOT} ${OUTPUT_DEB}"
fi
