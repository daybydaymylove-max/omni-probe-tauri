# Omni-Probe 贡献指南 (Contributing Guide)

感谢您对 **Omni-Probe 工业全能网络探针系统** 的关注与支持！

本项目遵循工业级严谨工程标准与科学学术诚信原则。为了保障核心算法的健壮性与代码资产的长期可维护性，请所有贡献者在提交 Issue 或 Pull Request (PR) 前仔细阅读本指南。

---

## 一、 行为与代码准则

1. **绝对禁止占位符 (Zero Placeholders)**：
   提交的代码严禁包含任何未实现的 `TODO`、`pass` 或 `...` 省略语法，所有提交必须是完整、连贯、能够直接通过编译并运行的工业生产级代码。
2. **大 O 复杂度显式标注**：
   涉及数据结构遍历、密码学运算、协议状态机解析的核心函数，必须在文档注释中显式标注时间复杂度（Time Complexity）与空间复杂度（Space Complexity）。
3. **强制边界与极限防御**：
   新增模块必须覆盖至少三类极限边界用例（零数据输入、溢出/千万级吞吐、畸形截断数据），遵循 Fail-Fast 原则。
4. **拒绝自嗨与浮夸用词**：
   注释、文档及 PR 描述中严禁使用虚夸、营销煽动或军事化用语，坚持客观冷峻的工程事实描述。

---

## 二、 本地开发与环境配置

### 前置要求
- **Rust 工具链**：1.75.0 或更高版本 (`cargo`, `rustc`)；
- **Node.js**：18.0.0 或更高版本 (`npm`)；
- **抓包驱动**：
  - Windows: 安装 [Npcap 1.70+](https://npcap.com/)（勾选 "Install Npcap in WinPcap API-compatible Mode"）；
  - Linux: 需 `libpcap-dev` (`sudo apt install libpcap-dev`)。

### 编译与验证命令
在提交 PR 之前，必须在本地完整执行以下验证流水线并确保 100% 通过：

```bash
# 1. 运行所有 Rust 库单元测试 (当前基准: 274 项全部绿灯)
cargo test --manifest-path src-tauri/Cargo.toml --lib

# 2. 运行端到端集成穿透测试 (当前基准: 18 项全部绿灯)
cargo test --manifest-path src-tauri/Cargo.toml --test '*'

# 3. 静态代码分析与编译器零警告检查
cargo check --manifest-path src-tauri/Cargo.toml

# 4. 前端类型检查与 Vite 生产构建 (零错误)
npm run build
```

---

## 三、 Pull Request 规范

1. **分支策略**：从 `main` 分支拉出特性分支（如 `feat/can-fd-extended` 或 `fix/quic-varint-overflow`）；
2. **Commit 规范**：遵循 Conventional Commits 标准：
   - `feat:` 新增功能
   - `fix:` 缺陷修复
   - `perf:` 性能与时空优化
   - `test:` 测试用例补充
   - `docs:` 文档与对标报告演进
3. **随附测试用例**：每个 PR 必须附带可独立运行的单元测试或集成测试，并随 PR 贴出测试通过的终端日志截图或控制台输出。

再次感谢您对工业级开源网络安全生态的贡献！
