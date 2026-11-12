# Omni-Probe 工业级全能网络探针系统 v0.3.2 发行注记

**发布时间**：2026-11-12  
**代码基线**：GitHub Release `v0.3.2`  
**核心定位**：全链路网络主动扫描与无截断流式统计对比、COM/USB 单片机开发辅助、BLE/HCI 空口连续监测与实机图文操作手册全同步

---

## 🛠 本次版本工程迭代 (Changelog)

### 1. 网络主动扫描、多维统计画像与基线 / `.pcap` 智能对照 (`net_intelligence.rs`)
- **CIDR/区间高并发主动端口与 Banner 引擎**：支持 `/23`..`/32` 网段（上限 512 主机 / 2048 探测并发限流、`Semaphore(64)`）、HTTP `HEAD` / Redis `PING (+PONG)` / SSH / FTP 只读 Banner 提取，并扩展 `discovery.rs` 资产探测端口矩阵至 39 个主流 IT/OT/数据库端口；支持可选标准载荷触发式 UDP 协议探测 (`53 DNS` / `123 NTP` / `161 SNMP` / `47808 BACnet/IP`)；
- **全量流式多维统计累加器 & ECharts 面板**：在全局抓包统一收口引入 $O(1)$ 无截断 `LiveNetAccumulator`，在 `IoGraphsPanel` 中以 ECharts 呈现 **协议层次占比、Top Talkers 双向读写吞吐、RFC 2544 标准七档报文长度分布、MAD 包间隔抖动** 及 **黄金基线参考线叠加**；
- **双样本对比 & 安全导出**：支持本地黄金基线 (`network_traffic_baseline.json`) 与离线 `.pcap` 文件直对比，支持导出 Markdown 与全字符严格防 XSS 转义的自包含 HTML 网络审计报告。

### 2. 物理外设总线：单片机开发伴侣与数字信号黄金波形比对 (`bus_intelligence.rs`)
- **数字波形算法引擎**：Cooley-Tukey Radix-2 FFT + Hann 汉宁窗功率谱分析、Pearson 相关系数与 Sakoe-Chiba 带约束 DTW 黄金波形对齐比对；
- **嵌入式辅助开发套件 (`BusDevAnalyticsPanel`)**：VOFA+ `JustFloat` / 自定义 `Struct` 多通道波形解调、PID 阶跃超调量/上升时间/调节时间求解、STM32/MCU Timer `(PSC, ARR)` 与 UART ±2% 容限速算、RTOS 行式终端与 `.bin` 固件分片传输、Modbus RTU 寄存器快照矩阵、USBPcap (DLT=249) 双向导出及巡检报告导出；
- **IEEE 1364 `.vcd` 数字方波高精度解调**：支持纳秒级精度 (`s`–`fs`) 方波多总线 (`UART / I2C / SPI / CAN`) 解码与 SUMP/OLS 硬件探头对接。

### 3. 蓝牙 BR/EDR / BLE / HCI 专业监测升级 (`bluetooth_monitor.rs`)
- 支持 WinRT BLE 持续空口监听、Windows `BTHPORT` ETW 驱动级 HCI/L2CAP 抓取、RFC 1761 `.btsnoop` 双向导入导出、BLE GATT 服务审计、以及四联 ECharts 近场极坐标与 RSSI 实时/历史对照图。

### 4. Windows 原生免驱以太网兜底 & 完整图文操作手册同步
- 新增 Windows 原生 `win_ndis_capture.rs` 免 `Npcap` L2 捕获兼容路径；
- 随仓同步交付完整图文手册 [docs/USER_MANUAL.md](docs/USER_MANUAL.md) 与 `docs/manual-images/` 实机高清截图，由集成测试 `tests/manual_sync_check.rs` 自动防护版本与页面条目一致性。

---

## 🧪 全仓验证结果
- `cargo test --manifest-path src-tauri/Cargo.toml --no-fail-fast`：**396 项测试全部通过**（单元测试 386 项 + `live_system_verification` 1 项 + `manual_sync_check` 1 项 + `universal_diff_exhaustive_verification` 8 项）；
- `npm run build` (`vue-tsc --noEmit && vite build`)：**709 modules transformed，0 TypeScript errors**；
- Windows 桌面安装包产物：`omni-probe-tauri.exe`、`omni-probe-tauri_0.3.2_x64_en-US.msi`、`omni-probe-tauri_0.3.2_x64-setup.exe`。
