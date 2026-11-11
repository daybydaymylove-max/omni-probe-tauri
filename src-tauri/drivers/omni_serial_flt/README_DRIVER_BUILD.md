# Omni-Probe Windows 内核串口上层过滤驱动 (`omni_serial_flt.sys`) 编译与签名说明

## 1. 架构说明
`omni_serial_flt.c` 为纯标准 Windows Driver Model (WDM) 上层过滤驱动，挂载于系统 `Ports` 类 (`{4d36e978-e325-11ce-bfc1-08002be10318}`) 设备栈上层，拦截 `IRP_MJ_READ`、`IRP_MJ_WRITE` 与 `IOCTL_SERIAL_*`（波特率、数据位、校验位、DTR/RTS 控制线），并通过安全 ACL 控制的 `\Device\OmniSerialFilterControl` (`\\.\OmniSerialFilter`) 控制设备向管理员权限运行的 `Omni-Probe` 主程序实时导出内核环形事件队列 (`IOCTL_OMNI_SERIAL_POLL_EVENTS`)。

## 2. 编译前提
本工程主机当前安装有 Windows SDK `10.0.26100.0`，未安装 **Windows Driver Kit (WDK)** 及内核代码签名证书（EV/WHQL）；因 Windows 64 位生产系统强制内核驱动签名校验（Driver Signature Enforcement），`omni_serial_flt.sys` 需在已装 WDK 的环境执行编译与签名后部署：
1. 安装与当前 SDK 匹配的 WDK (Windows 11 / Server 2022 WDK)；
2. 使用 WDK EWDK / Visual Studio Developer Command Prompt 编译生成 `omni_serial_flt.sys`；
3. 开发测试环境可执行测试签名（`signtool sign`），生产交付需通过微软 Hardware Dev Center Attestation 签名，再以管理员权限右键安装 `omni_serial_flt.inf`。

## 3. 跨平台及无签名驱动场景运行时自研保障
即使尚未部署签名后的 `omni_serial_flt.sys`，`Omni-Probe` 用户态亦已内建完整等价穿透通道：
- **Linux / macOS / 国产 OS (UOS/Kylin/OpenEuler)**：零外部驱动直连内核 POSIX PTY 伪终端与 `TIOCMGET`/`TIOCMSET` 硬件引脚透传；
- **Windows**：内建全双工双向双线程透传桥梁 (`start_serial_bridge`)、Win32 `NamedPipe` (`\\.\pipe\omni_com_*`) 虚拟串口服务器与完整 `RFC 2217` Telnet Com-Port 控制网关；一旦系统中检测到 `\\.\OmniSerialFilter` 已加载，主引擎将自动切入真内核 IRP 旁路监听。
