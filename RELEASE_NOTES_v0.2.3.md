# Omni-Probe 工业级全能网络探针系统 v0.2.3 发行说明 (Release Notes)

**发布日期**: 2026-11-09  
**版本代号**: Grand Horizon (Universal Diff & Multi-Platform CI)  
**支持平台**: Windows 10/11 (x64), Linux (Ubuntu 20.04+/Debian/Arch), macOS 12+ (Apple Silicon M系列 & Intel x86_64)

---

### 一、 核心架构重构：全局全源数据比对总线 (Universal Diff Bus)

为彻底解决传统网络分析软件中“抓包、串口、调试助手各模块相互孤立”的痛点，v0.2.3 构建了贯通全系统的通用比对基础设施：

1. **系统级单例状态机与统一调度 (`src/composables/useUniversalDiff.ts`)**：
   - 跨模块槽位管理（Slot A & Slot B），支持在任何列表、终端与日志流中点选数据存入对比；
   - 包含高健壮性数据归一化适配器（`normalizeToDiffableItem`），无缝兼容网络数据包、调试助手日志、工业串口帧、TLS 解密流及用户剪贴板数据；
   - 支持全局快捷键 `Ctrl + Shift + D`（Mac 为 `Cmd + Shift + D`）随时呼出比对中心。

2. **全源业务模块深度接入**：
   - **网络流量嗅探 (`TrafficAnalyzerView`)**：报文右键菜单支持【设为全局比对 A/B】与深度比对；
   - **NetAssist 调试助手 (`NetAssistWorkbenchView`)**：
     - 收发历史流每条记录悬停支持【⚖️ 设为 A】与【⚖️ 设为 B】；
     - 发送控制区支持【⚖️ 请求 vs 响应】一键差分（当前待发请求与最新收到回包即时对比）；
     - 终端顶部提供【⚖️ 自由比对草稿】直达入口；
   - **硬件串口与工业总线 (`HardwareBusView`)**：双向交互终端支持【⚖️ 对比 TX vs RX】与槽位存入；
   - **TLS/HTTPS 全息代理解密 (`TrafficDecryptionView`)**：选中解密会话支持【⚖️ 请求 vs 响应】明文差分；
   - **自由数据草稿箱 (`Scratchpad`)**：双栏十六进制与文本编辑器，支持去除杂乱字符格式化 Hex，并内置 Modbus、TCP 握手、HTTP、DLT645 预设规约。

---

### 二、 科学分析与统计引擎升级

1. **载荷波形与五维科学指标**：
   - **余弦几何相似度 (Cosine Similarity)**：精确量化报文载荷向量的夹角几何同构度（防除零安全夹紧）；
   - **皮尔逊线性相关系数 (Pearson Correlation)**：计算两序列波动的协同趋势（$[-1.0, +1.0]$）；
   - **逐字节变异波率 (Mutation Wave Rate)**：精确计算突变跳变字节占最大载荷的真实百分比；
   - **平均绝对振幅偏差 (MAD)**：量化全字节平均偏差震级（$0 \sim 255$）；
   - **最大跳变峰位 (Max Delta)**：精确锁定出现最大跳变的字节偏移地址与振幅；
   - **Canvas 矢量双波线与十字探针**：青蓝折线与霓虹紫折线叠加呈现，支持高分屏物理像素级 Crosshair 探针与点击柱位回切 Hex 视窗联动。

2. **多报文特征矩阵与局部信息熵**：
   - 多报文 LCS 变异波率柱状谱；
   - 叠加逐偏移局部香农信息熵折线（$0.0 \sim 8.0\text{ bit}$）。

---

### 三、 人机工程学高反差视觉治理

1. **全面遵循 WCAG 2.1 AA/AAA 色彩对比度规范**：
   - 彻底废除白底低对比度发飘浅字（`text-cyan-200` 等），正文严格规范为冷峻深色阶 `text-slate-800` / `text-slate-900`（对比度 $> 10:1$）；
   - 深色暗黑模式统一使用高对比度冷灰白 `text-slate-100` / `text-slate-200`（对比度 $> 12:1$）。
2. **5 色阶无歧义语义标注体系**：
   - 冷灰阶（一致基线）
   - 玫瑰酒红（数值突变 / 替换）
   - 翡翠绿（突变插入 / 新增）
   - 琥珀金（缺失 / 截断）
   - 霓虹紫（大跨度跃变 $\Delta \ge 128$）

---

### 四、 官方 GitHub Actions 多平台矩阵构建支持

1. **发布工作流标准化 (`.github/workflows/release.yml`)**：
   - 规范迁移至 `.github/workflows/` 标准路径，打通 GitHub 官方 CI/CD 自动侦测；
   - 配置 `windows-latest`、`ubuntu-22.04`、`macos-latest` 三大操作系统并行矩阵编译；
   - 只要推送 `v*` 标签或手动触发 `workflow_dispatch`，GitHub 即自动并行编译并产出 Linux (DEB/AppImage)、macOS (DMG/APP) 与 Windows (MSI/EXE) 原生包。

---

### 五、 工业级验证与测试度量 (DoD)

- **后端测试套件**：320 项 Lib 单元测试 + 6 项全源集成测试（覆盖 5 大数据源与 3 类极端边界用例）**100% 通过**；
- **前端生产构建**：TypeScript 0 错误，690 个模块全量成功打包；
- **代码规范**：零占位符，无 `TODO`，无硬编码。
