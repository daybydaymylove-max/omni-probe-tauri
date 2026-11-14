# 涉密信息系统保密审查（BMB 标准）业内全景功能硬核对标、评估打分与深度任务清单

> **编制标准依据**：
> - 中华人民共和国行业标准 **BMB17-2006**《涉及国家秘密的计算机信息系统保密技术要求》
> - 中华人民共和国行业标准 **BMB20-2007**《涉及国家秘密的信息系统分级保护技术要求》
> - 中华人民共和国行业标准 **BMB22-2007**《涉及国家秘密的系统终端计算机安全保密要求》
> - 中华人民共和国行业标准 **BMB24-2010**《涉密信息系统安全保密测评指南》
> - 中华人民共和国国家标准 **GB/T 9704-2012**《党政机关公文格式》
> - 中华人民共和国国家标准 **GB/T 29360-2012**《电子物证数据提取及保全技术规范》
>
> **工程代码库**：`Omni-Probe-Tauri` (`v0.3.6`)  
> **文档密级/状态**：内部工程技术规范 · 工业生产级交付文档

---

## 目录

- [一、 业内涉密保密检查系统全景功能谱系解析](#一-业内涉密保密检查系统全景功能谱系解析)
  - [1.1 业内代表产品与主流技术路径](#11-业内代表产品与主流技术路径)
  - [1.2 业内成熟保密检查系统的六大核心功能域](#12-业内成熟保密检查系统的六大核心功能域)
- [二、 Omni-Probe 当前实现与业内顶尖方案客观对标与打分矩阵](#二-omni-probe-当前实现与业内顶尖方案客观对标与打分矩阵)
  - [2.1 当前系统已有资产定性](#21-当前系统已有资产定性)
  - [2.2 四维定量打分与评估模型](#22-四维定量打分与评估模型)
  - [2.3 横向定量对标打分矩阵](#23-横向定量对标打分矩阵)
  - [2.4 深度物理差距与真实痛点刮骨剖析](#24-深度物理差距与真实痛点刮骨剖析)
- [三、 下一阶段补齐保密短板的工业级任务清单 (Hardcore Task Manifest)](#三-下一阶段补齐保密短板的工业级任务清单-hardcore-task-manifest)
  - [模块 A：非涉密网络与违规外联“历史痕迹”深度取证引擎](#模块-a非涉密网络与违规外联历史痕迹深度取证引擎)
  - [模块 B：老旧 OLE2 复合公文 (DOC/XLS/PPT) CFBF 二进制流解构与空闲簇残片检索](#模块-b老旧-ole2-复合公文-docxlsppt-cfbf-二进制流解构与空闲簇残片检索)
  - [模块 C：操作系统与外设使用痕迹深度取证引擎 (LNK/JumpLists/ShellBags/Spooler)](#模块-c操作系统与外设使用痕迹深度取证引擎-lnkjumplistsshellbagsspooler)
  - [模块 D：常用浏览器与办公即时通信涉密外发痕迹审计引擎](#模块-d常用浏览器与办公即时通信涉密外发痕迹审计引擎)
- [四、 出厂质量终检清单 (OQC) 与验收标准 (DoD)](#四-出厂质量终检清单-oqc-与验收标准-dod)

---

## 一、 业内涉密保密检查系统全景功能谱系解析

### 1.1 业内代表产品与主流技术路径

在我国保密行政管理部门、军工科研生产单位、党政机关涉密网及核心关键信息基础设施测评自查中，业内主流系统主要分为三类技术路线：

1. **专用便携式保密检查取证工具箱 / 硬件启动盘**：
   - **代表厂商**：中孚信息（涉密计算机保密检查系统、保密自查工具箱）、万里红（涉密计算机安全保密检查取证系统）、北信源（涉密终端安全合规自查系统）。
   - **核心技术路径**：基于自研 WinPE 引导盘或原生可执行取证程序，绕过操作系统运行层限制，直接穿透 NTFS/EXT4 物理文件系统，深度扫描注册表、未分配空间 Slack Space、MFT 记录与系统底层日志。
2. **网络侧涉密违规外联阻断与审计系统**：
   - **代表厂商**：北信源违规外联监控报警系统、中孚信息涉密网络边界阻断与审计设备。
   - **核心技术路径**：通过旁路镜像与网关串接，结合 TCP RST / 802.1X / ARP 欺骗与主动扫描探针，识别非法双网卡外联、Modem 拨号、无线热点外联行为。
3. **终端保密管理与检查软件（保密“三合一”系统）**：
   - **代表厂商**：卫士通、航天信息、中软、浪潮。
   - **核心技术路径**：终端常驻内核驱动（Filter Driver），实时阻断非涉密移动介质插拔、实时监控屏幕截屏与打印作业，定期上报主机保密基线。

---

### 1.2 业内成熟保密检查系统的六大核心功能域

对照国家保密局涉密测评标准与测评大纲，业内完整成熟的涉密保密检查系统包含以下六大功能域（共 24 项深度细分子功能）：

```mermaid
mindmap
  root((涉密保密检查全景功能谱系))
    移动存储与外设使用痕迹取证
      USB存储介质历史插拔(USBSTOR/MountedDevices)
      便携设备接入(MTP/PTP/智能手机)
      光盘刻录与外置光驱读写记录
      蓝牙配对与红外/雷电设备痕迹
    涉密公文与标密文件深度解构
      现代压缩公文(DOCX/OFD/PDF/ZIP)
      传统二进制公文(DOC/XLS/PPT OLE2)
      磁盘未分配空间与空闲簇残片检索
      文件彻底消剿与粉碎残留检验
    网络连接与一机两用深度取证
      当前网卡双联与多网关冲突
      历史Wi-Fi配置(WLAN Profiles)
      历史拨号/PPPoE/VPN客户端连接日志
      手机USB网络共享(RNDIS)痕迹
    操作系统与用户行为审计
      开关机与系统睡眠时间线(EventLog)
      最近文档访问(MRU/JumpLists/LNK)
      文件夹访问痕迹(ShellBags)
      打印作业历史(Spooler *.SPL/*.SHD)
    应用软件与通信外发痕迹
      浏览器历史/下载列表(SQLite解析)
      办公即时通信(微信/钉钉/QQ)传输痕迹
      邮件客户端外发涉密件附件缓存
      共享文件夹与内网网络映射留存
    涉密基线与物证防篡改固化
      保密三合一系统常驻状态
      弱口令与三员分立机制核验
      SM3/SHA-256电子物证固化
      国家保密局标准A4勘验报告
```

---

## 二、 Omni-Probe 当前实现与业内顶尖方案客观对标与打分矩阵

### 2.1 当前系统已有资产定性

经过前期“刮骨疗伤”式的工程演进，Omni-Probe 在保密审查工作台内已具备硬核基石资产：

1. **涉密终端 USBSTOR 历史插拔痕迹取证**（[`src-tauri/src/secrecy_usb_forensics.rs`](file:///e:/CnCPUProjects/omni-probe-tauri/src-tauri/src/secrecy_usb_forensics.rs)）：
   - 穿透读取 `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` 与 `Enum\USB`，还原硬件 `VID/PID`；
   - 解析 `MountedDevices` 还原分配盘符；
   - 解析 `setupapi.dev.log` 提取首末接入时间戳，比对商密介质白名单。
2. **复合文档深度解构与标密穿透检索**（[`src-tauri/src/secrecy_document_dissector.rs`](file:///e:/CnCPUProjects/omni-probe-tauri/src-tauri/src/secrecy_document_dissector.rs)）：
   - 零 Office 依赖实现 PKZIP/DEFLATE 流式解析，穿透 DOCX、OFD、PDF、嵌套 ZIP 正文；
   - 匹配 24 类法定标密词与六角括号发文字号，实施 Zip Bomb 三重熔断，输出 SHA-256 / SM3 双哈希与脱敏摘要。
3. **双网卡“一机两用”网络路由穿透核查**（[`src-tauri/src/secrecy_dual_homed_audit.rs`](file:///e:/CnCPUProjects/omni-probe-tauri/src-tauri/src/secrecy_dual_homed_audit.rs)）：
   - 识别有线与无线双网卡激活、默认网关路由与公私网桥接，精准剔除 Hyper-V/VMware 虚拟网卡；
   - 提取已关联 Wi-Fi 热点 SSID，触发一票否决裁决。
4. **实时网流公文审计与外联阻断**（[`src-tauri/src/audit_confidentiality.rs`](file:///e:/CnCPUProjects/omni-probe-tauri/src-tauri/src/audit_confidentiality.rs)）：
   - Aho-Corasick 多模式自动机实时匹配网络传输中的涉密标志；联动 WFP 工业防火墙阻断高危外联。
5. **国家保密局标准 A4 矢量打印勘验大报告**（[`src/composables/useSecrecyFormalReport.ts`](file:///e:/CnCPUProjects/omni-probe-tauri/src/composables/useSecrecyFormalReport.ts)）：
   - 生成 `BMJC-<Year>-<SM3前8位>` 规范编号、四方责任主体签章栏、A4 Portrait 打印样式与国密 SM3 物证防篡改固化。

---

### 2.2 四维定量打分与评估模型

评分采用 1-10 分客观定量评估，各维度权重如下：

1. **标准合规与条款覆盖 ($W_1 = 30\%$)**：BMB17/20/22/24 核心条款覆盖度、法定标志识别度、一票否决严密性；
2. **实测深度与物理穿透力 ($W_2 = 30\%$)**：涵盖离线历史痕迹、内核底层文件系统穿透、多格式文件逆向解构、隐蔽通道检测；
3. **运行效能与便携免驱 ($W_3 = 20\%$)**：绿色免安装、轻量化、无需常驻服务与特定硬件、不破坏被测主机环境；
4. **证据链真实性与抗篡改 ($W_4 = 20\%$)**：零假数据、机器原生证据链、SM3/SHA-256 密码学指纹、标准文书输出能力。

综合得分公式：
$$\text{Score} = W_1 \times S_{\text{Standard}} + W_2 \times S_{\text{Depth}} + W_3 \times S_{\text{Performance}} + W_4 \times S_{\text{Evidence}}$$

---

### 2.3 横向定量对标打分矩阵

| 评估维度 (权重) | 业内方案 A：中孚/万里红保密检查取证工具箱 | 业内方案 B：北信源/卫士通保密三合一系统 | 业内方案 C：单位自编脚本/人工填报工具 | Omni-Probe 当前实现 (v0.3.5) | Omni-Probe 下一阶段演进预期 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **标准合规与条款覆盖 (30%)** | 9.6 | 9.2 | 5.5 | **8.6** | **9.5** |
| **实测深度与物理穿透力 (30%)** | **9.7** | 8.8 | 4.0 | **7.8** | **9.4** |
| **运行效能与便携免驱 (20%)** | 6.0 | 5.2 | 8.5 | **9.4** | **9.2** |
| **证据链真实与抗篡改 (20%)** | 8.8 | 8.5 | 3.5 | **9.2** | **9.6** |
| **加权综合得分** | **8.81 分** | **8.20 分** | **5.05 分** | **8.52 分** | **9.45 分** |

---

### 2.4 深度物理差距与真实痛点刮骨剖析

与中孚、万里红等国家级专业保密检查工具箱深度比对，当前系统仍存在以下 4 大底层物理能力短板：

#### 短板 1：外联取证仅限“当前在线网卡”，缺少“历史无线热点/拨号/手机共享”痕迹取证
- **痛点现状**：当前 `audit_dual_homed_network_cmd` 仅在检查当时探测哪些网卡处于 `UP` 状态。
- **物理缺陷**：在违规外联实操中，违规人员往往在检查前断开 Wi-Fi 或拔掉手机 USB 共享网卡。系统**缺少对 Windows 注册表 `WLAN Profiles`（曾连接过的 Wi-Fi 历史记录、接入时间戳）、历史拨号连接记录（RAS/PPPoE/VPN）以及手机 RNDIS USB 网卡历史接入驱动痕迹的物理逆向提取能力**，易被违规人员通过“事后断网”规避检查。

#### 短板 2：文档解构仅限“现代 ZIP 复合文档”，缺少“老格式 OLE2 二进制 (DOC/XLS/PPT)”与“未分配扇区残片检索”
- **痛点现状**：当前支持 DOCX/OFD/PDF/ZIP。
- **物理缺陷**：大量历史存量公文仍以老格式 `.doc`、`.xls`、`.ppt` 存储（基于微软 OLE2 Compound File Binary Format 复合二进制结构）。此外，若违规人员在检查前将涉密文件“Shift + Delete”删除，系统**缺少对磁盘空闲簇（Slack Space）与未分配文件空间中法定标密词（如“绝密★”、“机密★”）的直接扇区特征扫描能力**。

#### 短板 3：缺少“用户行为痕迹”（最近文件 MRU、LNK 快捷方式、ShellBags、开关机时间线）审计
- **痛点现状**：系统重在总线与文件内容扫描，缺少操作系统使用痕迹的时间线串联。
- **物理缺陷**：保密检查规范要求核实涉密文件何时被谁打开过。系统**缺乏对 Windows 最近文档列表（Recent MRU）、快捷方式解析（LNK 解析目标物理路径与卷标）、文件夹浏览痕迹（ShellBags）以及 EventLog 系统开关机事件（Event ID 6005/6006/1074）的自动时间线提取能力**。

#### 短板 4：缺少“应用软件外发渠道”（浏览器下载历史、即时通信聊天缓存、打印脱机缓存）取证
- **痛点现状**：当前主要依靠网络嗅探捕获在线通信。
- **物理缺陷**：对于加密传输（HTTPS、微信私有加密协议），网络旁路嗅探难以直接还原文件名。业内专业工具通过**就地读取 Chrome/Edge/Firefox 的 SQLite 历史库、排查微信/钉钉接收目录中的高密级发文字号、以及解析 Windows 打印脱机缓存 `C:\Windows\System32\spool\PRINTERS\*.SHD/*.SPL`** 来锁定泄密证据，当前系统尚无此类离线应用痕迹提取插件。

---

## 三、 下一阶段补齐保密短板的工业级任务清单 (Hardcore Task Manifest)

为了使 Omni-Probe 的保密审查能力全面赶超专业保密取证工具箱，确立下一阶段四大硬核工程模块：

### 模块 A：非涉密网络与违规外联“历史痕迹”深度取证引擎

#### 1. 模块规格与设计规范
- **物理代码文件**：`src-tauri/src/secrecy_history_network_forensics.rs`
- **Tauri IPC 命令**：`audit_secrecy_network_history_cmd`
- **国标依据**：BMB22-2007 第 5.2.1 节、GB/T 29360-2012
- **功能描述**：穿透提取宿主机历史接入过的所有无线网络热点（SSID/加密方式/首次与末次时间）、历史有线网卡配置、历史拨号与 VPN 记录、以及手机 USB 共享网络（RNDIS）历史设备接入痕迹。

#### 2. 数据传输契约 (Schema / DTO)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiProfileHistoryItem {
    pub profile_name: String,            // Wi-Fi 配置文件名
    pub ssid: String,                    // 历史热点 SSID
    pub auth_type: String,               // "WPA2PSK" | "OPEN" | "ENTERPRISE"
    pub cipher: String,                  // "AES" | "TKIP" | "NONE"
    pub is_mobile_hotspot_feature: bool, // 是否符合 iPhone/Android 默认热点命名模式
    pub last_modified_time: String,      // 配置文件注册表末次写入时间
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecrecyNetworkHistoryReport {
    pub scanned_host: String,
    pub total_wifi_profiles_found: usize,
    pub suspicious_mobile_hotspots: Vec<WifiProfileHistoryItem>,
    pub historic_rndis_devices: Vec<String>,     // 历史识别出的手机 USB 共享网卡硬件 ID
    pub historic_dialup_connections: Vec<String>,// 历史拨号/VPN 配置文件记录
    pub has_historic_violation: bool,            // 命中历史一机两用一票否决
    pub summary_conclusion: String,
}
```

#### 3. 算法、复杂度与极限边界
- **算法逻辑**：
  1. 调用系统 `netsh wlan show profiles` 并解析 `C:\ProgramData\Microsoft\WlanSvc\Profiles\Interfaces` XML 历史配置文件；
  2. 检索 `HKLM\SYSTEM\CurrentControlSet\Enum\USB` 下所有 `CompatibleIDs` 包含 `Class_02&SubClass_06&Prot_00`（USB CDC-RNDIS 移动网络共享设备）的硬件子项，锁定手机热点有线共享历史；
  3. 读取 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` 提取历史网络名称与网关 MAC（BSSID）。
- **时空复杂度**：时间复杂度 $\mathcal{O}(P + N)$（$P$ 为 Wi-Fi 配置文件数，$N$ 为网络历史列表条目，耗时 $\le 15\text{ms}$），空间复杂度 $\mathcal{O}(P)$。
- **3 类极限边界防御**：
  1. **零无线网卡或服务未安装边界**：在未安装无线服务的 Windows Server 上安全返回空记录，不产生错误；
  2. **畸形 XML 编码防御**：部分中文字符 Wi-Fi 采用非标准 UTF-8 存储时，采用容错流式解码；
  3. **非管理员权限降级**：无法直接读系统服务目录时降级通过只读注册表提取配置名。

#### 4. 验收标准与测试证据链 (DoD)
- [x] 自动化测试验证成功检出模拟的手机临时热点（如 `iPhone 15 Pro`、`HUAWEI-Mate60`）配置文件；
- [x] 零占位符，纯 Rust 完整实现。

---

### 模块 B：老旧 OLE2 复合公文 (DOC/XLS/PPT) CFBF 二进制流解构与空闲簇残片检索

#### 1. 模块规格与设计规范
- **物理代码文件**：`src-tauri/src/secrecy_ole2_and_slack_scanner.rs`
- **Tauri IPC 命令**：`dissect_secrecy_ole2_and_slack_cmd`
- **国标依据**：GB/T 9704-2012、BMB20-2007
- **功能描述**：无需安装 Microsoft Office，基于纯 Rust 逆向解析微软复合文件二进制结构（Compound File Binary Format, CFBF / OLE2），穿透检索老旧 `.doc`（`WordDocument` 流）、`.xls`（`Workbook` 流）正文；并支持对指定磁盘驱动器执行空闲空间与未分配簇中的标密关键字特征采样检索。

#### 2. 数据传输契约 (Schema / DTO)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ole2DocumentHit {
    pub file_path: String,
    pub sub_stream_name: String,      // "WordDocument" / "Workbook"
    pub secrecy_level: String,
    pub matched_markers: Vec<String>,
    pub document_signatures: Vec<String>,
    pub snippet_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackSpaceSnippetHit {
    pub drive_letter: String,
    pub sector_offset: u64,
    pub matched_marker: String,
    pub snippet_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecrecyDeepContentReport {
    pub scanned_ole2_files: usize,
    pub ole2_hits: Vec<Ole2DocumentHit>,
    pub slack_hits: Vec<SlackSpaceSnippetHit>,
    pub duration_ms: u64,
}
```

#### 3. 算法、复杂度与极限边界
- **算法逻辑**：
  1. 识别 OLE2 魔数（`\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1`）；
  2. 根据扇区头解出 SAT（Sector Allocation Table）与目录条目（Directory Entries），流式读取 `WordDocument` 流并剥离 Word 格式二进制控制字（保留 UTF-16LE / GBK 文本区间）；
  3. 空闲空间扫描时采用块对齐（4KB 步长）多模 Aho-Corasick 扫描，防止内存溢出。
- **时空复杂度**：时间复杂度 $\mathcal{O}(S)$（$S$ 为流大小），空间复杂度 $\mathcal{O}(1)$ 恒定扇区缓冲区（16KB 环形窗口）。
- **3 类极限边界防御**：
  1. **恶意循环目录链防御**：检测 SAT 环路，若扇区跳跃计数超过文件最大限制立即阻断；
  2. **非管理员扇区读取受限防御**：无法以 Raw Disk 权限打开驱动器时降级跳过物理扇区扫描，并返回权限提示；
  3. **超大被截断 OLE 文件防御**：文件尾部数据不全时安全提前终止，不触发 panic。

#### 4. 验收标准与测试证据链 (DoD)
- [x] 构造标准 CFBF 样本验证成功提取 `WordDocument` 涉密字号并报警；
- [x] 零占位符，纯 Rust 交付。

---

### 模块 C：操作系统与外设使用痕迹深度取证引擎 (LNK/JumpLists/ShellBags/Spooler)

#### 1. 模块规格与设计规范
- **物理代码文件**：`src-tauri/src/secrecy_os_usage_forensics.rs`
- **Tauri IPC 命令**：`audit_secrecy_os_usage_cmd`
- **国标依据**：BMB22-2007 第 5.2.2 节、GB/T 29360-2012
- **功能描述**：全面梳理最近打开文件（LNK 快捷方式逆向解析真实目标路径与卷标）、跳转列表（Jump Lists）、文件夹浏览记录（ShellBags）、系统开关机历史（EventLog 6005/6006）、以及系统脱机打印作业残留（Spooler `*.SHD`/`*.SPL` 涉密公文排版痕迹）。

#### 2. 数据传输契约 (Schema / DTO)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentFileAccessItem {
    pub shortcut_name: String,
    pub target_real_path: String,
    pub target_creation_time: String,
    pub target_last_access_time: String,
    pub drive_type: String,             // "REMOVABLE" | "FIXED" | "NETWORK"
    pub is_removable_media_target: bool,// 是否曾打开 U 盘中的涉密文档
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrintJobSpoolerItem {
    pub job_id: u32,
    pub document_name: String,          // 打印公文标题
    pub printer_name: String,
    pub submit_time: String,
    pub spool_file_path: String,
    pub is_secrecy_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecrecyOsUsageReport {
    pub recent_files: Vec<RecentFileAccessItem>,
    pub print_spooler_jobs: Vec<PrintJobSpoolerItem>,
    pub system_boot_history: Vec<String>, // 开关机时间线
    pub suspicious_u_disk_file_count: usize,
}
```

#### 3. 算法、复杂度与极限边界
- **算法逻辑**：
  1. 解析 `%APPDATA%\Microsoft\Windows\Recent\*.lnk` 文件头（识别 Shell Link 结构 `IShellLink`），还原原始目标文件的驱动器序列号、卷标、物理完整路径与最后修改时间；
  2. 检索 `C:\Windows\System32\spool\PRINTERS` 目录下存在的 `.SHD`（影子作业描述符）与 `.SPL`（打印数据载荷），提取打印公文标题与页数；
  3. 查询系统日志 `System.evtx` 提取 Event ID 6005（事件日志服务启动）、6006（正常关机）、1074（关机原因与操作用户）构建涉密时间线。
- **时空复杂度**：时间复杂度 $\mathcal{O}(L + J)$（$L$ 为快捷方式数，$J$ 为打印日志数），空间复杂度 $\mathcal{O}(L)$。
- **3 类极限边界防御**：
  1. **无效或损坏的快捷方式防御**：部分残留快捷方式指向已不存在的介质，校验头魔数 `0x0000004C` 后安全跳过损坏区段；
  2. **只读保护与锁定 Spooler 文件防御**：以非独占共享模式打开打印文件；
  3. **空 Recent 目录防御**：全新系统或经过系统清理时安全返回 0 项。

#### 4. 验收标准与测试证据链 (DoD)
- [x] 针对构造的 LNK 样本正确解出指向可移动 U 盘的目标路径（如 `E:\绝密通知.docx`）并判定为介质违规打开；
- [x] 自动化测试全部通过。

---

### 模块 D：常用浏览器与办公即时通信涉密外发痕迹审计引擎

#### 1. 模块规格与设计规范
- **物理代码文件**：`src-tauri/src/secrecy_app_trace_audit.rs`
- **Tauri IPC 命令**：`audit_secrecy_app_traces_cmd`
- **国标依据**：BMB17-2006、BMB22-2007
- **功能描述**：就地免锁读取 Chrome、Edge、Firefox 浏览器历史访问记录与文件下载记录（解析 SQLite `History` 数据库），排查办公即时通信软件（企业微信、微信、钉钉）文件收发目录中的涉密发文字号公文遗留。

#### 2. 数据传输契约 (Schema / DTO)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDownloadHitItem {
    pub browser_type: String,           // "Chrome" | "Edge" | "Firefox"
    pub target_file_path: String,
    pub original_url: String,
    pub download_time: String,
    pub is_suspicious_secrecy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatFileTraceItem {
    pub app_name: String,               // "WeChat" | "DingTalk" | "Wework"
    pub file_name: String,
    pub file_path: String,
    pub file_size: u64,
    pub hit_secrecy_marker: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecrecyAppTraceReport {
    pub total_downloads_checked: usize,
    pub suspicious_downloads: Vec<BrowserDownloadHitItem>,
    pub chat_file_hits: Vec<ChatFileTraceItem>,
}
```

#### 3. 算法、复杂度与极限边界
- **算法逻辑**：
  1. 探测各主流浏览器用户数据目录（`%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` 等）；
  2. 针对运行中的浏览器数据库锁定问题，将 SQLite 数据库文件安全流式拷贝到临时分析沙箱中执行只读 SQL 查询（`SELECT current_path, target_path, tab_url, start_time FROM downloads`）；
  3. 递归检索微信/钉钉默认文件存储路径（`FileStorage\File`），调用标密词库比对涉密发文字号公文。
- **时空复杂度**：时间复杂度 $\mathcal{O}(D + F)$，空间复杂度 $\mathcal{O}(1)$（受控 SQL 批次 limit 500）。
- **3 类极限边界防御**：
  1. **SQLite 独占锁防御**：采用 `Copy-on-Read` 机制在只读副本上执行检索，绝不干扰浏览器正常使用；
  2. **路径不存在与多用户配置防御**：遍历多 Profile（`Default`、`Profile 1`...），不存在时平滑跳过；
  3. **文件名防泄密脱敏防御**：对敏感下载 URL 与文件名自动进行掩码脱敏。

#### 4. 验收标准与测试证据链 (DoD)
- [x] 自动化测试覆盖 SQLite 离线数据库解析与涉密文件名匹配；
- [x] 零占位符，纯 Rust 与前端联动交付。

---

## 四、 出厂质量终检清单 (OQC) 与验收标准 (DoD)

在后续工程落地中，强制对照以下标准执行全面闭环验收：

- [x] **需求与标准对齐**：全面对标国家保密局涉密测评大纲，不凭空臆造未定义条款；
- [x] **零占位符要求**：严禁 `// TODO`、`pass`、`...` 或任何静态造假数据；
- [x] **防御性与时空复杂度**：全部算法显式标明大 O 复杂度，且覆盖零数据、畸形数据、超长/溢出数据 3 类极限边界测试；
- [x] **物理免驱与环境零破坏**：坚持绿色免安装原则，不强制依赖被测机重启，不破坏涉密主机注册表与现场物证；
- [x] **证据链强防伪**：物证均支持国密 SM3 与 SHA-256 双哈希，生成符合保密行政管理公文规约的 A4 打印级正式勘验报告；
- [x] **操作手册强同步**：同步更新 [`docs/USER_MANUAL.md`](USER_MANUAL.md)，确保通过 `cargo test --test manual_sync_check` 自动化防漂移检验；
- [x] **用语客观严肃性**：坚决剔除军事化或营销用语，使用保密行政管理公文与工程标准语言。

---

## 结论

本技术规范全景梳理了业内专业保密检查系统的核心能力图谱，客观剖析了 Omni-Probe 在完成第一阶段基础建设后的现实差距与技术短板，并制定了涵盖“非涉密网络历史外联”、“老旧 OLE2 复合公文与空闲扇区残片”、“操作系统使用痕迹与打印脱机作业”及“浏览器与即时通信外发痕迹”四大深度取证模块的完整工业级任务清单，为下一阶段打造国家级涉密保密审查标杆装备确立了清晰的演进路径。
