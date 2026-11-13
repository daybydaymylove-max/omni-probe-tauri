#!/bin/bash
# ==============================================================================
# Omni-Probe 工业全能网络探针 - 银河麒麟 Kylin V10 / openEuler 原生 .rpm 打包脚本
# 文件路径: scripts/build-rpm-kylin.sh
#
# 核心职责:
# 1. 面向银河麒麟 (Kylin V10 SP1/SP2/SP3)、华为 openEuler 及 RedHat/CentOS 信创生态;
# 2. 自动生成标准 RPM 构建 Spec 描述文件;
# 3. 在 %post 阶段自动执行 setcap 提权与桌面数据库更新;
# 4. 彻底打通信创 RPM 生态分发闭环.
# ==============================================================================

set -euo pipefail

VERSION="0.3.4"
RELEASE="1"
ARCH="${1:-x86_64}" # 支持 x86_64, aarch64, loongarch64
RPM_TOPDIR="${HOME}/rpmbuild"
SPEC_FILE="dist/omni-probe.spec"

echo "=========================================================="
echo "  Omni-Probe v${VERSION} 信创 银河麒麟/openEuler .rpm 构建"
echo "  目标架构: ${ARCH}"
echo "=========================================================="

mkdir -p dist
mkdir -p "${RPM_TOPDIR}/SOURCES" "${RPM_TOPDIR}/SPECS" "${RPM_TOPDIR}/BUILD" "${RPM_TOPDIR}/RPMS" "${RPM_TOPDIR}/SRPMS"

# 1. 编写 RPM Spec 文件
cat <<EOF > "${SPEC_FILE}"
Name:           omni-probe
Version:        ${VERSION}
Release:        ${RELEASE}%{?dist}
Summary:        工业全能网络探针与网工工具箱 (Industrial-grade Network Probe & Toolkit)
License:        Apache-2.0
URL:            https://github.com/daybydaymylove-max/omni-probe-tauri
Group:          Applications/Engineering

Requires:       webkit2gtk4.1, libpcap, glib2, openssl-libs
AutoReqProv:    yes

%description
Omni-Probe 是一款工业级多总线协议审计、跨介质流式差分比对与网络工程师现场应急工具集。
原生内置 RFC 1035 DNS 探针、RFC 1350 TFTP 服务器、RFC 854 管理终端 (Telnet/SSH)、
IEEE 802.1AB LLDP/CDP 拓扑发现、SNMPv3 USM 加密采集、Modbus/S7/104 工控协议解码与 WFP/nftables 防护。

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/opt/omni-probe
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/share/applications
mkdir -p %{buildroot}/usr/share/icons/hicolor/512x512/apps

# 复制二进制与桌面入口
cp -p ../src-tauri/target/release/omni-probe-tauri %{buildroot}/opt/omni-probe/omni-probe-tauri
cp -p ../scripts/omni-probe.desktop %{buildroot}/usr/share/applications/omni-probe.desktop
ln -sf /opt/omni-probe/omni-probe-tauri %{buildroot}/usr/bin/omni-probe

if [ -f "../src-tauri/icons/icon.png" ]; then
    cp -p ../src-tauri/icons/icon.png %{buildroot}/usr/share/icons/hicolor/512x512/apps/omni-probe.png
fi

%files
/opt/omni-probe/omni-probe-tauri
/usr/bin/omni-probe
/usr/share/applications/omni-probe.desktop
/usr/share/icons/hicolor/512x512/apps/omni-probe.png

%post
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin=eip /opt/omni-probe/omni-probe-tauri || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi

%preun
if [ \$1 -eq 0 ]; then
    rm -f /usr/bin/omni-probe
fi

%changelog
* Wed Nov 13 2026 Omni Engineering Team <daybydaymylove2009@gmail.com> - ${VERSION}-${RELEASE}
- 初始工业级银河麒麟/openEuler RPM 发布，支持原生 RFC 854 网工管理终端与信创特权自愈
EOF

echo "[+] Spec 文件已生成: ${SPEC_FILE}"

# 2. 如果存在 rpmbuild 则执行构建
if command -v rpmbuild >/dev/null 2>&1; then
    rpmbuild -bb --target "${ARCH}" "${SPEC_FILE}"
    echo "[+] RPM 构建成功，查看 ${RPM_TOPDIR}/RPMS/${ARCH}/"
else
    echo "[i] 当前系统未安装 rpmbuild 工具链。"
    echo "    可在银河麒麟 / openEuler / CentOS 终端执行: rpmbuild -bb --target ${ARCH} ${SPEC_FILE}"
fi
