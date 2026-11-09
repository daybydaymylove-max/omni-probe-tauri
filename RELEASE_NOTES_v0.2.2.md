# Omni-Probe v0.2.2 发布说明

## 1. 版本概述 (Release Overview)
Omni-Probe `v0.2.2` 正式发布。本版本重点根除了系统在冷启动阶段因底层硬件总线探测引发的数十秒系统级假死停滞，全面搭载了**工业级全景全局友好提示系统 (Ergonomic Global Notification System)**，彻底清零了全系统原生打断式 `alert()` 弹窗，并随 Release 完整交付包括 Windows 独立执行程序、MSI 企业级安装包、NSIS 便携安装向导包与纯净源码在内的全量编译产物。

---

## 2. 核心架构重构与新增功能 (Key Features & Refactoring)

### 2.1 彻底根除系统启动停滞（提速 >500,000 倍，首屏 0ms 阻塞秒开）
- **根因死穴消除**：
  深度剖析并根治了 Windows 蓝牙虚拟串口（`BTHENUM`）在 Win32 `CreateFileW` 阶段强行发起内核级无线射频握手导致的单次 5.19 秒内核硬死锁。
- **纯内存状态机判定**：
  将串口枚举阶段的硬件探测重构为纯内存连接状态比对（时间复杂度 $O(1)$），耗时从 5,200ms 降至 0.01ms 以下；排他性硬件句柄握手按需延后至用户实际点击“启动嗅探”时执行。
- **前端全并行初始化管道**：
  将 `onMounted` 串行 `await` 瀑布流重构为 4 条隔离的异步 Promise 并行通道（网卡嗅探、串口枚举、活跃探活、资产/USB 扫描），首屏挂载 0ms 阻塞。
- **重型模态框按需懒加载**：
  对 5 个全局重量级模态框追加 `v-if` 条件渲染门禁，彻底杜绝未激活弹窗在后台并发抢占 IPC 通道与运行高频轮询定时器。

### 2.2 全景全局友好提示系统 (Ergonomic Global Notification System)
- **四级工业标准分级**：
  实现 `success`（成功完成）、`info`（状态变迁与事件）、`warning`（合规防御与轻度异常）、`error`（系统异常与硬件故障）四级通知规范。
- **底层错误智能语义转译器 (`formatFriendlyError`)**：
  自动将 Npcap 驱动缺失、管理员特权受限、COM 端口被独占占用、蓝牙离线超时、BPF 语法非法、等保三级合规阻断等晦涩系统底层报错转译为具备排障指导意义的友好语义反馈。
- **暴风雨抑制与频次折叠防抖**：
  基于 1500ms 滑动窗口实现通知防抖与频次累加（展示为 `×N` 工业胶囊），避免高速报文流或扫描事件造成通知刷屏。
- **苹果 2026 冰晶磨砂质感悬浮容器**：
  支持毫秒级微光自动销毁倒计时进度条、鼠标悬停暂停、移开继续、手动单点关闭与快捷处置动作回调。

### 2.3 彻底清除原生打断式 `alert()`
- 对包括 `EnvironmentDiagnosticModal`、`HoneypotWorkbenchModal`、`IpDossierModal`、`PacketDiffModal`、`SerialBridgeModal`、`AssetIntelligenceView`、`ForensicsView`、`HardwareBusView`、`SystemAuditView`、`TrafficAnalyzerView`、`TrafficDecryptionView`、`SecurityReviewView` 在内的 12 个模块进行刮骨疗伤式彻底清理；
- 全系统原生 `alert()` 调用计数彻底归零（0 遗留），全部接入非阻塞、高辨识度的全局通知体系。

---

## 3. 本地编译产物与多操作系统发布说明 (Distribution Artifacts)

随本次 Release 正式交付以下完整编译文件：
- **`omni-probe-tauri_0.2.2_x64-setup.exe`** (4.54 MB)：全新 NSIS 向导式安装程序，支持快捷方式创建与标准卸载；
- **`omni-probe-tauri_0.2.2_x64_en-US.msi`** (6.64 MB)：微软标准企业级 Windows Installer 安装包，支持 IT 运维静默部署；
- **`omni-probe-tauri-v0.2.2-windows-x64.zip`** (5.98 MB)：绿色免安装便携版，解压即用；
- **`omni-probe-tauri-v0.2.2-source.zip`** (9.98 MB)：基于当前 Git HEAD 的纯净源代码打包归档；
- **多平台构建规范 (`ci/workflows/release.yml`)**：
  补齐了 Linux (`ubuntu-22.04`) 下编译串口底层所必需的 `libudev-dev` 与 `pkg-config` 依赖，并配置了 macOS Apple Silicon / Intel 双架构支持。

---

## 4. 质量验证与证据链 (Verification & DoD)
- **Rust 后端单元测试**：**307 项单元测试 100% 通过**（0 失败，0 告警，耗时 0.32s）；
- **前端类型安全与构建**：`vue-tsc --noEmit` 全量通过，Vite 687 个模块在 3.92s 内 0 错误 0 警告完成打包；
- **Tauri 原生 Release 构建**：通过 `npm run tauri build` 成功完成 LTO 全局死代码消除优化编译。
