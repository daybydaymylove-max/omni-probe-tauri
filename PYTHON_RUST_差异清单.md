# Omni-Probe Python 版与 Rust 版实现差异审计清单

> 审计基线：Python 版 `E:\CnCPUProjects\YCSLJ-2026\tools\`（omni_probe_gui.py 863 行 + port_listener.py 836 行 + config.json），
> Rust 版 `E:\CnCPUProjects\YCSLJ-2026\omni-probe-tauri\src-tauri\src\`（18 个 .rs 模块 + protocol_signatures.json）。
> 审计方式：逐文件精读 + 交叉 Grep 验证调用关系，非抽样。
> 文档用途：作为后续"更新、改进、修复"的工程依据。每项缺陷均标注文件、位置、影响与修复建议。

---

## 一、总览与版本定位

| 维度 | Python 版 | Rust 版 |
|---|---|---|
| 架构 | 双进程：tkinter GUI（omni_probe_gui.py）+ 引擎子进程（port_listener.py，`subprocess -u` 启动，stdout 日志管道） | 单进程：Tauri 2 应用，前端 Vue 3 + TypeScript，后端多线程 + Tokio runtime，事件总线（emit/listen）通信 |
| 异步模型 | asyncio 单事件循环（ProactorLoop） | std::thread + tokio（metrics 用 current_thread，honeypot 用 multi_thread 4 worker） |
| 嗅探 | Scapy sniff + TCPSession 流重组（用户态） | pcap crate（Npcap L2）+ pnet 解析；Raw Socket SIO_RCVALL 兜底；LAN 组播 join；SendARP 雷达 |
| 落盘体系 | received_data.jsonl（TimedRotatingFileHandler 30 天轮转）+ capture.pcap（TruePcapWriter 应用层重组）+ forensic_capture.pcap（L2 append）+ listener.log | 仅 forensic_capture.pcap（truncate 模式，重启清空）；**received_data.jsonl / listener.log / capture.pcap 三个文件在 Rust 侧无任何写入代码** |
| 配置体系 | config.json 驱动一切（端口表、探测目标、阈值、正则、云端、舰队） | 无配置文件；端口表、目标、阈值硬编码于源码或由 UI 每次传参 |
| 记录总线 | 文件轮询（GUI 0.1s 增量读 jsonl） | Tauri 事件 emit（packet-received / ai-alert / wave-data / hardware-alert / honeypot-received / assets-updated / system-log）+ cloud 推送 |
| GUI 数据完整性 | UI 裁剪 1000 行，内存环形 10000 条 | 前端自管理（本清单不审计前端 Vue 代码，仅审计后端事件源） |

---

## 二、模块映射总表

| 功能域 | Python 实现 | Rust 实现 | 对齐结论 |
|---|---|---|---|
| DPI 协议识别 | port_listener.py `ProtocolDetector.detect`（~15 协议单阶段顺序匹配） | dpi.rs 四阶段（字典热加载 > 端口 > 魔数 > 正则），35+ 协议 | **Rust 增强** |
| 应用层字段拆解 | `DictionaryDissector`（仅 uint 大端） | dpi.rs `dissect_payload`（uint/uint_le/hex/string/float/float_le/double/double_le + SL651/MODBUS/S7/DNS 内置语义拆解） | **Rust 增强** |
| L2 嗅探引擎 | `PassiveDiscoveryEngine`（Scapy sniff TCPSession + BPF + ARP 处理） | sniffer.rs `run_sniffer_pipeline`（Npcap 打开 → 主循环 → parse_ethernet_frame → tcp_reassembly 50ms） | 机制对齐，细节见 §3.2 |
| 应用层监听（TCP/UDP 服务） | `TCPServerHandler`（asyncio Protocol，50ms 组帧）+ `UDPServerProtocol`，config.json 端口表 | sniffer.rs `start_dual_track_services`（硬编码 [8080,5003,502,1883]，单次 read 4096B，200ms 超时，无组帧） | **Rust 退化** |
| 主动 TCP 拉取 | `active_tcp_probe`（持续连接读流 + 50ms 组帧 + ACTIVE_PULL 记录） | active_probe.rs `start_continuous_probe`（周期心跳探活，不产生数据记录） | **Rust 退化** |
| 串口采集 | `active_serial_probe`（pyserial，50ms 组帧） | serial.rs `start_serial_probe`（SERIAL_RX 50ms 组帧）+ `send_serial_data`（SERIAL_TX） | 对齐 + Rust 增强 TX |
| USB 嗅探 | `USBSnifferEngine`（USBPcapCMD 子进程管道，chunk[:256]） | usb.rs（USBPcapCMD + 注册表/sysfs 枚举 + PnP 回退） | 对齐 + Rust 增强枚举 |
| 硬件监控 | GUI 内 WMI Win32_PnPEntity 全 USB PnP 设备（2 秒） | hardware.rs serialport::available_ports（3 秒，仅串口类设备） | **Rust 覆盖面退化** |
| 蜜罐 | 无 | honeypot.rs（TCP/UDP 蜜罐 + 令牌桶 + TCP_CONNECT 事件） | **Rust 新增** |
| 限流 | `TokenBucketIPFilter` + 超限 `transport.abort()` 物理断连 | throttle.rs GLOBAL_THROTTLE（丢记录，不断连） | 机制差异（见 §3.7） |
| 脱敏 | `DataSanitizer`（config.json 2 条正则，初始化固定） | sanitizer.rs（内置 4 组规则 + 动态下发 + 运行时开关） | **Rust 增强** |
| 云端推送 | `CloudStreamingAdapter`（aiohttp，Queue 10000 / 批 100 / 3s 超时） | cloud.rs（reqwest，mpsc 10000 / 批 100 / 500ms / 5s 超时） | 对齐（批次节奏差异） |
| 指标导出 | `handle_fleet_api`（9091，4 指标含 probe_active_connections） | metrics.rs（9091，4 指标含 probe_honeypot_running） | **指标名不一致** |
| 取证封条 | `ForensicIntegritySealer`（60s，封 received_data.jsonl + capture.pcap） | forensics.rs（60s，封 forensic_capture.pcap + listener.log） | **封印对象错位**（两个都是幽灵文件问题，见 §4.2） |
| 结构化落盘 | `DataHandler.handle` → received_data.jsonl | **完全缺失** | **Rust 退化（最严重项之一）** |
| 应用层 PCAP | `TruePcapWriter`（重组 Ether/IP/TCP/UDP/Raw，append）→ capture.pcap | **缺失**（pcap.rs 为死代码，见 §4.4） | **Rust 退化** |
| 异常检测 | `AnomalyDetectionEngine`（10s 窗口 >100 帧固定阈值 + 新端口 >2） | analyzer.rs `FlowBaseline`（30s 窗口 + EMA α=0.05 3σ + rate>5 下限 + 10s 端口切片 new_ports>=3） | **Rust 增强** |
| 波形示波器 | GUI tk Canvas（offset/length/signed，deque 100） | analyzer.rs WaveConfig（+ little_endian）+ emit wave-data | 对齐 + Rust 增强小端 |
| 矩阵比对 | GUI difflib.SequenceMatcher（双包 replace/delete/insert；多包垂直 mutating_indices；标签区分 [历史基线]/[实时截获]） | analyzer.rs `smart_diff_payloads`（手写 LCS DP + delete/insert 合并 replace；标签统一"样本 01"） | 算法等价，标签语义退化 |
| 基线管理 | GUI（baseline_payloads.json） | analyzer.rs save/load_baseline_payloads（同名文件） | 对齐 |
| L2 重放 | GUI 右键 sendp(Ether(bytes.fromhex(hex))) | sniffer.rs `inject_packet`（cap.sendpacket）+ active_probe.rs `replay_l4_packet`（L4 重放） | 对齐 + Rust 增强 L4 |
| L4 反探 | GUI subprocess ping + socket connect_ex | active_probe.rs run_icmp_ping（系统 ping）+ probe_tcp_connect + run_target_scan 并发 | 对齐 |
| ARP 雷达 | 无 | sniffer.rs `trigger_lan_radar_discovery`（SendARP FFI，4 线程×64，6ms 间隔，8s 一轮） | **Rust 新增（含合成帧标注问题）** |
| 资产发现 | 无（仅 ARP 被动学习） | discovery.rs（arp -a 邻居表 + OUI 厂商 + 300 并发端口扫描 + 守护线程 4s/20s） | **Rust 新增** |
| Raw Socket 兜底 | 无 | sniffer.rs win_raw 模块（ws2_32 FFI SIO_RCVALL） | **Rust 新增** |
| 链式哈希 | `DataHandler` 单一 last_hash 全局链 | 分裂多链（见 §4.6） | **Rust 退化（司法完整性）** |
| 清空操作 | GUI 物理删除 6 个文件 | lib.rs `clear_logs` 截断 3 个文件 | 行为差异（见 §3.14） |

---

## 三、逐模块深度差异

### 3.1 DPI 协议识别（dpi.rs ↔ ProtocolDetector/DictionaryDissector）

| 项 | Python | Rust | 差异判定 |
|---|---|---|---|
| 识别策略 | 单阶段：按魔数/正则顺序匹配（~15 协议），无端口参与 | 四阶段：动态 JSON 字典（RwLock 热加载，notify 200ms 防抖）→ 端口精确（40 条规则）→ 魔数（8 条，含长度校验）→ 正则（7 条） | Rust 增强 |
| 协议覆盖 | MODBUS/HTTP/DNS/MQTT/SL651/HJ212 等约 15 种 | 35+ 种（新增 S7/ENIP/BACNET/DNP3/OPC-UA/OMRON-FINS/MITSUBISHI-MC/IEC104/AMQP/COAP/MYSQL/POSTGRESQL/MONGODB/VNC/RDP/SNMP/SMB/LLDP 等） | Rust 增强 |
| 魔数校验深度 | 前缀匹配 | TLS/MODBUS_TCP 帧长一致性校验、MQTT 严格 OASIS 报文类型校验、DHCP magic cookie 校验 | Rust 增强 |
| 字典拆解 data_type | 仅 uint（大端） | uint/uint_le/hex/string/float/float_le/double/double_le | Rust 增强 |
| SL651 拆解 | 基础 | 中心站地址/遥测站 BCD/密码 hex/功能码语义表 0x2F~0x41/CRC16 | Rust 增强 |
| 未识别协议命名 | `UNKNOWN:{port}`（含端口信息） | `UNKNOWN_PAYLOAD`（无端口信息） | Python 信息量更优 |
| HTTP 命名 | `HTTP_REQ` | `HTTP` | 命名不一致 |
| 测试 | 无 | dpi.rs 内 6 个单元测试 | Rust 增强 |

### 3.2 L2 嗅探引擎（sniffer.rs run_sniffer_pipeline ↔ PassiveDiscoveryEngine）

| 项 | Python | Rust |
|---|---|---|
| 打开方式 | Scapy sniff(iface, filter=BPF, session=TCPSession) | pcap::Capture（1000ms 超时、promisc、snaplen 65535、buffer 32MB、timeout 50ms、BPF 注入） |
| 流重组 | TCPSession（内核级 ACK 确认重组，带 seq 重排） | 自研 tcp_reassembly HashMap + 50ms 静默刷新，**无 seq 重排、无去重、无 gap 检测** |
| ARP 处理 | Scapy 自动 + 主动学习 | parse_ethernet_frame 手写（ARP/RARP，含 42 字节帧解析） |
| EtherType 覆盖 | Scapy 内置全量 | 手写：IPv4/IPv6/ARP/VLAN/LLDP/MPLS/PPPoE/EAPOL/PTP/MACsec/FCoE，畸形帧 L2_MALFORMED 安全承接 |
| 方向分类 | Scapy 判断 | classify_network_direction：PORT_INBOUND/OUTBOUND/LOOPBACK/LAN_FORWARD/BROADCAST |
| 设备枚举 | Scapy get_if_list | safe_list_devices（300ms 超时熔断）+ netsh 降级 + **硬编码 Realtek GUID 兜底**（\Device\NPF_{3A9D9EF7-...}，见 §7） |
| 兜底路径 | 无 | raw socket SIO_RCVALL（win_raw 模块，独立链 RAW_SOCKET_GENESIS_2026） |
| 取证落盘 | forensic_capture.pcap append | forensic.write_packet（**仅此一条路径落 PCAP**，应用层数据不落） |
| 自检 | 无 | trigger_self_check_probe（连 127.0.0.1:8080 HTTP GET） |

**Rust 侧 TCP 重组缺陷明细**：tcp_reassembly 仅按 (src,dst,port) 聚合 payload，缺失：
1. seq 序号重排（乱序报文将字节序错乱拼接）；
2. 重传去重（重传报文重复入库）；
3. gap/洞检测（丢包后前后段直接拼接，产生损坏数据）。
Python TCPSession 三项均有。**修复建议**：实现 seq 窗口缓冲 + 排序 flush + 按 ack 去重。

### 3.3 双轨服务（start_dual_track_services ↔ TCPServerHandler/UDPServerProtocol）

| 项 | Python | Rust | 判定 |
|---|---|---|---|
| 端口来源 | config.json servers 表（8080/502/1883 tcp） | 硬编码 [8080,5003,502,1883] | Rust 退化 |
| 读模式 | asyncio Protocol data_received 累积 + 50ms 定时器组帧 | 单次 read 4096B + 200ms 超时（read_exact 语义），**无组帧** | Rust 退化 |
| 大载荷 | 分片正确组帧 | >4096B 载荷分多条记录或丢失 | Rust 退化 |
| 连接事件 | TCP_CONNECT/TCP_DISCONNECT SYS_CTRL 带外事件 | 无（仅 honeypot.rs 有 TCP_CONNECT） | Rust 退化 |
| MAC 字段 | 真实本机 MAC | 硬编码 "00:11:22:33:44:55" | Rust 造假字段 |
| dst_ip | 真实本机 IP | 字面量 "LOCAL_HONEYPOT" | Rust 语义降级 |
| UDP 5003 协议 | 走 DPI 动态识别 | 硬编码 "SL651_WATER" | Rust 退化（绕过 DPI） |
| PCAP 落盘 | TruePcapWriter 重组落 capture.pcap | 不落 | Rust 退化 |

### 3.4 主动探测（active_probe.rs ↔ active_tcp_probe/active_serial_probe）

| 项 | Python | Rust | 判定 |
|---|---|---|---|
| TCP 主动 | 持续连接、持续读流、50ms 组帧、产生 ACTIVE_PULL 记录入链 | start_continuous_probe 周期心跳，仅 ProbeResult 探活，无数据记录 | **Rust 退化** |
| 探测目标来源 | config.json active_probes | UI 每次传参（无持久化） | Rust 退化 |
| ICMP | subprocess 系统 ping | 同（系统 ping） | 对齐 |
| TCP banner | socket connect_ex + 读 | TcpStream connect_timeout + banner 读（latency_ms） | 对齐 |
| L4 重放 | 无 | replay_l4_packet（UDP send_to / TCP 写读）+ PortTransceiveResult | Rust 新增 |
| 串口重试 | 递归 retry（**栈溢出风险**，见 §6） | 循环 | Rust 优 |

### 3.5 串口（serial.rs ↔ active_serial_probe）

| 项 | Python | Rust |
|---|---|---|
| RX 组帧 | 50ms | 50ms（对齐） |
| TX 发送 | 无 | send_serial_data（SERIAL_TX 记录，chain_hash="SERIAL_TX_{id}" 不入全局链） |
| 记录 | PASSIVE_RECV 同一管线 | SERIAL_RX，src_ip="HOST_SYSTEM"，入令牌桶豁免名单 |

### 3.6 取证体系（forensics.rs ↔ ForensicIntegritySealer/TruePcapWriter）

| 项 | Python | Rust | 判定 |
|---|---|---|---|
| L2 pcap | forensic_capture.pcap **append** | **truncate(true)**——每次进程启动清空历史证据 | **P0 级司法退化** |
| 应用层 pcap | capture.pcap（TruePcapWriter 重组 Ether/IP/TCP/UDP/Raw） | **无**（pcap.rs 死代码，见 §4.4） | Rust 退化 |
| 结构化 jsonl | received_data.jsonl + 30 天轮转 | **无任何写入代码** | Rust 退化 |
| 文本日志 | listener.log（引擎 stdout 重定向） | **无任何写入代码** | Rust 退化 |
| 封条对象 | received_data.jsonl + capture.pcap（真实存在） | forensic_capture.pcap + **listener.log（幽灵文件）** | Rust 错位 |
| 封条周期/原因 | 60s / SCHEDULED_AUDIT / SHUTDOWN_FINAL_SEAL / MANUAL | 60s / SCHEDULED_AUDIT / SHUTDOWN_FINAL_SEAL（**无 MANUAL 手动封条命令**） | Rust 缺 MANUAL |
| 熵算法 | O(256·n) count 循环 + round(2) | freq[256] 单遍 O(n) + clamp(0,8)（无 round） | Rust 优（精度差异见 §3.12） |
| 写锁行为 | — | try_lock 锁忙**静默丢包**（不重试不入队） | Rust 缺陷 |
| 哈希 | — | hash_file_sha256 1MB 块流式（优） | — |

### 3.7 限流（throttle.rs ↔ TokenBucketIPFilter/ThreatIntelligenceEngine）

| 项 | Python | Rust | 判定 |
|---|---|---|---|
| 算法 | 令牌桶 per-IP | 同（lazy refill，O(1)） | 对齐 |
| 超限处置 | transport.abort() **物理断连** | 仅丢记录（连接继续） | 行为差异：Python 防御性强，Rust 观测性好（丢记录但连接存续）；**建议 Rust 增加 auto_drop 可选断连** |
| 豁免 | — | LOCAL_SERIAL/USB_CONTROLLER 豁免 | Rust 增强 |
| gc | — | gc() 300s 存在但 **无调用方** → HashMap 无限膨胀 | **Rust 缺陷（内存泄漏级）** |
| 默认值 | config max_pps 50 | 50/50 硬编码 | 配置体系差异 |
| 动态更新 | 无 | update_throttle_config（清空旧桶） | Rust 增强 |

### 3.8 蜜罐（honeypot.rs，Rust 独有）

- HoneypotRecord direction="HONEYPOT_RECV"，**无 chain_hash 字段**（司法链断裂点）。
- TCP 蜜罐：令牌桶检测 + TCP_CONNECT 事件 + 200ms 读超时 + 关闭 flush。
- UDP 蜜罐 + emit_honeypot_record（cloud + honeypot-received）。
- metrics 第 4 指标 probe_honeypot_running 与 Python probe_active_connections 不一致（见 §3.10）。

### 3.9 脱敏（sanitizer.rs ↔ DataSanitizer）

| 项 | Python | Rust | 判定 |
|---|---|---|---|
| 规则来源 | config.json 初始化 2 条（password/token） | 内置 4 组（手机号/身份证/键值敏感词/Authorization Bearer）+ 动态下发 | Rust 增强 |
| 运行时开关 | 无 | GLOBAL_SANITIZATION_ENABLED | Rust 增强 |
| 测试 | 无 | 6 个单元测试 | Rust 增强 |

### 3.10 指标（metrics.rs ↔ handle_fleet_api）

| 指标 | Python | Rust |
|---|---|---|
| probe_packets_total | 有 | 有 |
| probe_bytes_total | 有 | 有 |
| probe_threats_blocked_total | 有 | 有 |
| 第 4 指标 | **probe_active_connections** | **probe_honeypot_running** |

**判定**：指标集不对齐。Python 的 active_connections 是流量态势核心指标；Rust 用 honeypot gauge 替换导致 Prometheus 看板迁移后语义断裂。**修复建议**：Rust 补 probe_active_connections（可由 tcp_reassembly/双轨连接计数推导），honeypot_running 作为第 5 指标保留。

### 3.11 云端推送（cloud.rs ↔ CloudStreamingAdapter）

| 项 | Python | Rust |
|---|---|---|
| 队列容量 | 10000 | 10000 |
| 批次 | 100 条 | 100 条 / 500ms |
| 超时 | 3s | 5s |
| 客户端 | aiohttp | reqwest（连接池复用） |
| 关闭 | — | stop 优雅关闭（flush） |

对齐。Rust 批次节奏更密（500ms vs Python 3s 超时兜底），可接受。

### 3.12 分析器（analyzer.rs ↔ AnomalyDetectionEngine/GUI 波形/矩阵）

| 项 | Python | Rust | 判定 |
|---|---|---|---|
| 异常阈值 | 固定 100 帧/10s + 新端口>2 | EMA α=0.05 3σ 自适应 + rate>5 下限 + 10s 端口切片 new_ports>=3 | **Rust 增强（学术级）** |
| 熵精度 | round(2)（两位小数） | 全精度 clamp(0,8) | Rust 优；**但两版 UI 阈值展示一致性需前端适配** |
| 波形 | offset/length/signed | + little_endian | Rust 增强 |
| 双包差分 | difflib.SequenceMatcher | 手写 LCS DP + delete/insert 合并 replace | 算法等价（LCS O(mn) 与 SM 同阶） |
| 差分标签 | 区分 [历史基线]/[实时截获] | 统一"样本 01" | **Rust 语义退化**（无法溯源样本性质） |
| 多包差分 | mutating_indices | mutating HashSet | 对齐 |

### 3.13 USB 与硬件（usb.rs/hardware.rs ↔ USBSnifferEngine/WMI）

| 项 | Python | Rust | 判定 |
|---|---|---|---|
| USB 捕获 | USBPcapCMD -d \\.\USBPcap1 -o -，chunk[:256] | 同命令 + `-A` 参数 + PnP 回退 | 对齐 |
| 设备枚举 | WMI Win32_PnPEntity（**全 USB PnP 设备**） | 注册表 Enum\USB + sysfs + serialport（**实际生效面仅串口类**，hardware.rs 3s 轮询） | **Rust 覆盖面退化**（U 盘/摄像头/网卡类 USB 设备不产生 hardware-alert） |
| 监控周期 | 2s | 3s | 等价 |

### 3.14 清空与生命周期

| 项 | Python | Rust | 判定 |
|---|---|---|---|
| 清空 | 物理删除 6 个文件（jsonl/pcap/封条/基线等） | clear_logs 截断 3 个文件（**不删 sha256 封条、不删基线**） | 行为不一致；Rust 残留旧封条与基线，**清空后封条仍指向已截断文件 → 证据链自相矛盾** |
| 停止序列 | — | stop_capture：serial/usb/honeypot/cloud 停止 + SHUTDOWN_FINAL_SEAL | Rust 结构更清晰 |

### 3.15 资产发现与 ARP 雷达（discovery.rs/sniffer.rs，Rust 独有）

- discovery.rs：infer_vendor_by_mac（OUI）、classify_ip、sync_kernel_neighbors（arp -a / /proc/net/arp）、scan_lan_subnet_active（SendARP 并发）、probe_asset_ports（300 并发）、守护线程（4s 邻居表 + 20s ARP 探活）。
- sniffer.rs trigger_lan_radar_discovery：SendARP 全网段 1-254、4 线程×64、6ms 间隔、8s 一轮，构造 42 字节**合成 ARP Reply** 记录（direction="PORT_LAN_FORWARD"、chain_hash="ARP_RADAR_{id}" 不入链、目的 MAC 硬编码 34:5A:60:6E:2A:4B）。
- **合规性标注（反造假条款）**：该记录是本地合成的雷达回波（SendARP 应答的表示），并非线缆上真实捕获的帧。记录本身有工程价值，但必须：
  1. 在记录字段（如 business_data.radar_synthetic=true）中显式标注合成属性；
  2. 不得写入 forensic_capture.pcap（当前未写入，正确）；
  3. 前端不得与真实捕获帧无差别混排（当前混排，需加标识）。

### 3.16 LAN 组播嗅探（Rust 独有）

start_native_lan_sniffer：join SSDP 1900 / mDNS 5353 / NetBIOS 137/138 / WS-DISC 3702。Python 无此能力。

---

## 四、Rust 相对 Python 的退化缺口清单（修复依据）

### P0 —— 司法取证完整性（证据销毁级）

| # | 缺陷 | 位置 | 影响 | 修复建议 |
|---|---|---|---|---|
| 4.1 | forensic_capture.pcap 以 truncate(true) 打开，**每次启动销毁全部历史证据** | forensics.rs:8-13 GLOBAL_PCAP_WRITER Lazy | 违反证据保全基本原则；Python 为 append | 改 `append(true)` + 文件为空时写 pcap 全局头（pcap_file crate 的 PcapWriter::append 语义）；或自管文件头判断 |
| 4.2 | 封条引擎监控 listener.log、clear_logs 截断 listener.log / received_data.jsonl，但**两文件无任何代码写入**（幽灵文件） | lib.rs start_capture 封条列表 / clear_logs | 封条对空文件/不存在文件打封（"NOT FOUND OR UNREADABLE"），证据链自欺 | 与 4.3 一并修复：实现两文件真实写入后再纳入封条；或从封条/清理列表移除 |
| 4.3 | received_data.jsonl 结构化落盘完全缺失（Python 有 30 天轮转） | 全局 | 数据只存在于前端内存与云端，进程崩溃即失；离线场景无审计底账 | 在 process_incoming_record/emit_honeypot_record 等记录产生点统一接入 jsonl writer（Mutex<File> append + 按天轮转） |
| 4.4 | capture.pcap 应用层重组落盘缺失；pcap.rs 为**死代码**（PCAP 静态量零调用方）且路径 "../capture.pcap" 指向上级目录、手工伪 Ethernet 头 | pcap.rs 全文 | 死代码误导维护者；应用层报文（双轨/蜜罐/串口/USB）无 PCAP 保全 | 二选一：(a) 删除 pcap.rs，在 forensics.rs 增加应用层重组 writer（参照 Python TruePcapWriter：构造 Ether/IP/TCP 或 UDP + payload 再 write_packet）；(b) 激活 pcap.rs 并修正路径与调用方。不可保留现状 |
| 4.5 | 链式哈希分裂：GLOBAL_CHAIN_HASH（双轨）、Npcap 局部 last_hash、raw socket 独立链（RAW_SOCKET_GENESIS_2026）、ARP_RADAR_{id}、SERIAL_TX_{id} 不入链、HoneypotRecord **无 chain_hash 字段** | sniffer.rs / serial.rs / honeypot.rs | 无法构建单一全局司法证据链；跨引擎记录无法互相校验 | 统一为单一 GLOBAL_CHAIN_HASH 原子更新点（fetch_add + 串行化）；合成记录（雷达/TX）以带前缀哈希入链并标注 synthetic |

### P1 —— 数据完整性与协议正确性

| # | 缺陷 | 位置 | 修复建议 |
|---|---|---|---|
| 4.6 | 双轨 TCP 无组帧：单次 read 4096B、200ms 超时 | sniffer.rs start_dual_track_services | 循环 read + 50ms 静默组帧（对齐 Python tcp_framing_timeout=0.05） |
| 4.7 | tcp_reassembly 无 seq 重排/去重/gap 检测 | sniffer.rs 主循环 | 引入 per-flow seq 缓冲与有序 flush |
| 4.8 | TCP_CONNECT/TCP_DISCONNECT SYS_CTRL 带外事件缺失 | 双轨路径 | 在 accept/close 处发 SYS_CTRL 记录（honeypot.rs 已有 connect 事件可复用模式） |
| 4.9 | ACTIVE_PULL 主动拉流模式缺失（退化为心跳） | active_probe.rs start_continuous_probe | 增加 stream 模式：连接保持 + 持续读 + 组帧 + ACTIVE_PULL 记录 |
| 4.10 | 双轨 MAC 硬编码 "00:11:22:33:44:55"、dst_ip="LOCAL_HONEYPOT" | sniffer.rs | 运行时取真实 MAC/IP（ipconfig 或局部缓存一次） |
| 4.11 | UDP 5003 协议硬编码 SL651_WATER 绕过 DPI | sniffer.rs | 改走 dpi::identify_protocol |
| 4.12 | 配置文件体系缺失（端口/目标/阈值硬编码） | sniffer.rs/lib.rs | 引入 config.json（对齐 Python schema），启动加载 + UI 可改 |
| 4.13 | probe_active_connections 指标缺失（被 honeypot_running 替换） | metrics.rs | 补第 5 指标（连接计数器），保留 honeypot gauge |
| 4.14 | BPF 仅 Npcap 路径生效（raw socket/组播路径不过滤） | sniffer.rs | 文档化限制或全路径统一前置过滤 |
| 4.15 | throttle gc() 无调用方 → HashMap 无限膨胀 | throttle.rs | 在 check_and_throttle 内按周期触发 gc（如每 60s 一次） |
| 4.16 | forensic.write_packet try_lock 锁忙静默丢包 | forensics.rs:27 | 改 blocking lock 或失败入队重试 |
| 4.17 | 硬编码设备 GUID 兜底（\Device\NPF_{3A9D9EF7-0558-4456-ABF9-9F25FF131739}） | sniffer.rs list_network_interfaces / inject_packet | 移除硬编码；枚举失败应显式报错给 UI |
| 4.18 | clear_logs 不删封条/基线 → 清空后封条与文件内容矛盾 | lib.rs clear_logs | 对齐 Python：删除或提示用户封条文件一并处理 |
| 4.19 | MANUAL 手动封条命令缺失 | forensics.rs / lib.rs | 增加 Tauri command do_manual_seal |
| 4.20 | 矩阵比对标签无 [历史基线]/[实时截获] 区分 | analyzer.rs smart_diff_payloads | diff 入参携带 origin 标签透传前端 |

---

## 五、Rust 相对 Python 的增强项清单（保持并巩固）

| # | 增强项 | 位置 | 说明 |
|---|---|---|---|
| 5.1 | DPI 四阶段 + 35+ 协议 + JSON 字典热加载（notify 200ms 防抖） | dpi.rs | 结构化规则外置，生产可运维 |
| 5.2 | SL651-2014 水文规约专业拆解（BCD 地址/功能码语义 0x2F~0x41/CRC16） | dpi.rs dissect_payload | 行业规约级 |
| 5.3 | data_type 扩展 float/double/小端 | dpi.rs | Python 仅 uint 大端 |
| 5.4 | EMA 3σ 自适应异常检测（α=0.05，rate>5 下限，端口切片） | analyzer.rs FlowBaseline | 替代固定 100 帧阈值 |
| 5.5 | 蜜罐引擎（TCP/UDP + 令牌桶 + TCP_CONNECT 事件） | honeypot.rs | Python 无 |
| 5.6 | 资产发现系统（邻居表同步 + OUI + 300 并发端口扫描 + 守护线程） | discovery.rs | Python 无 |
| 5.7 | ARP 雷达（SendARP FFI，4 线程×64，6ms 间隔） | sniffer.rs | 需按 §3.15 标注合成属性 |
| 5.8 | Raw Socket SIO_RCVALL 兜底嗅探（ws2_32 FFI 手写） | sniffer.rs win_raw | Npcap 不可用时降级可用 |
| 5.9 | LAN 组播嗅探（SSDP/mDNS/NetBIOS/WS-DISC join） | sniffer.rs start_native_lan_sniffer | Python 无 |
| 5.10 | 串口 TX 发送（SERIAL_TX 记录） | serial.rs send_serial_data | Python 无 |
| 5.11 | L4 报文重放与收发（replay_l4_packet / PortTransceiveResult） | active_probe.rs | Python 仅 L2 sendp |
| 5.12 | 脱敏内置 4 组规则 + 动态下发 + 运行时开关 | sanitizer.rs | Python 仅 config 2 条且不可变 |
| 5.13 | 限速动态更新（update_throttle_config） | throttle.rs | Python 需改 config 重启 |
| 5.14 | 熵值 O(n) 单遍 + 1MB 块流式文件哈希 | forensics.rs | Python O(256·n) |
| 5.15 | 波形 little_endian 解码 | analyzer.rs decode_wave_bytes | Python 仅大端 |
| 5.16 | 设备枚举熔断（safe_list_devices 300ms） | sniffer.rs | 防 UI 卡死 |
| 5.17 | 单元测试（dpi 6 个 + sanitizer 6 个 + forensics 3 个） | 各模块 | Python 零测试 |
| 5.18 | pcap 32MB 内核缓冲 + snaplen 65535 显式调优 | sniffer.rs Capture 打开参数 | 工程化调参 |

---

## 六、Python 侧固有缺陷（反向借鉴，Rust 已规避或需规避）

| # | 缺陷 | 位置 | Rust 现状 |
|---|---|---|---|
| 6.1 | active_serial_probe 递归重试 → **栈溢出风险**（长时运行串口反复失败时递归深度无界） | port_listener.py | Rust 循环实现（已规避） |
| 6.2 | GUI 轮询文件（0.1s stat + 增量读）延迟与 IO 开销 | omni_probe_gui.py | 事件总线（已规避） |
| 6.3 | 固定阈值 100 帧/10s，无法适配流量基线 | AnomalyDetectionEngine | EMA 3σ（已规避） |
| 6.4 | DPI ~15 协议且规则硬编码源码 | ProtocolDetector | 字典外置热加载（已规避） |
| 6.5 | 熵 O(256·n) 重复扫描 | 同上 | O(n)（已规避） |
| 6.6 | WMI 依赖（Linux/macOS 不可用） | GUI 硬件监控 | serialport 跨平台（但覆盖面缩窄，见 §3.13） |

---

## 七、硬编码路径 / 端口 / GUID / 常量清单（去硬编码改造依据）

| 类别 | 值 | 位置 | 处置建议 |
|---|---|---|---|
| 设备 GUID | `\Device\NPF_{3A9D9EF7-0558-4456-ABF9-9F25FF131739}`（Realtek） | sniffer.rs（枚举兜底 + inject_packet auto 分支） | 删除，失败显式上报 |
| MAC | `00:11:22:33:44:55`（双轨记录） | sniffer.rs | 运行时取真实 MAC |
| MAC | `34:5A:60:6E:2A:4B`（ARP 雷达目的 MAC） | sniffer.rs | 标注合成或取本机 MAC |
| 端口表 | TCP [8080,5003,502,1883]；UDP 5003/8080 | sniffer.rs start_dual_track_services | config.json |
| 自检目标 | 127.0.0.1:8080 | sniffer.rs trigger_self_check_probe | config.json |
| 雷达参数 | 1-254 / 4 线程×64 / 6ms / 8s | sniffer.rs trigger_lan_radar_discovery | config.json |
| 限流默认 | 50 / 50 | throttle.rs GLOBAL_THROTTLE | config.json |
| 指标端口 | 9091 | metrics.rs（Python config fleet） | config.json |
| 封条周期 | 60s | lib.rs 启动参数 | config.json |
| 文件名 | forensic_capture.pcap / listener.log / received_data.jsonl / baseline_payloads.json | forensics.rs/lib.rs/analyzer.rs | config.json data_storage 段 |
| pcap 死代码路径 | `../capture.pcap`（上级目录） | pcap.rs:11 | 随 §4.4 一并处置 |
| 链创世 | RAW_SOCKET_GENESIS_2026 | sniffer.rs win_raw | 随 §4.5 统一链改造 |
| 工作目录 | 相对路径（依赖进程 CWD） | 所有文件 IO | 启动时锚定 exe 目录或数据目录 |

---

## 八、修复优先级路线图

**P0（证据完整性，立即）**：§4.1 truncate→append → §4.3 jsonl 落盘 → §4.4 pcap.rs 处置与应用层 PCAP → §4.5 链统一 → §4.2 幽灵文件对齐。
**P1（数据正确性）**：§4.6 组帧 → §4.7 seq 重排 → §4.8 连接事件 → §4.9 ACTIVE_PULL → §4.10/4.11 真实 MAC/IP 与 DPI 直通。
**P2（可配置与一致性）**：§4.12 config.json → §4.13 指标补齐 → §4.17/4.18 去硬编码与清空对齐 → §4.19/4.20 封条命令与比对标签。
**P3（健壮性）**：§4.14 BPF 全路径 → §4.15 gc 接线 → §4.16 锁行为 → §3.13 硬件监控覆盖面（评估引入 Windows SetupAPI/注册表全量 USB 枚举）。

---

## 九、审计方法与局限性声明

- 本清单基于对 Python 两文件（1699 行）与 Rust 18 模块（约 6800 行）的全文精读，辅以 Grep 调用关系验证（PCAP 死代码、write_packet 唯一调用点、gc 无调用方等结论均经全局检索确认）。
- 前端 Vue/TS 代码不在本次审计范围；§3.15 合规性标注涉及前端展示行为，实施时需联动前端。
- 行号以当前工作区快照为准，后续改动会偏移，以函数/结构名定位为准。
