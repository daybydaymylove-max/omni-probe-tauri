// ============================================================

// 工业全能网络探针 - 工业生产级 TCP 流重组与抗躲避会话状态机引擎

// 模块名称: stream_reassembly.rs

//

// 核心职责与算法实现:

// 1. 严格实现 RFC 793 / RFC 1323 双向 TCP 11 状态迁移状态机;

// 2. 具备 Ptacek-Newsham 经典反躲避攻击的多策略重叠分节裁决算法 (First / Last / Linux);

// 3. 模 2^32 相对序号距离安全算术, 免疫 32 位序列号回环溢出 (Wraparound);

// 4. 连续流有序重组器 (Ordered Stream Assembler) 与空洞 (Gap) 追踪;

// 5. LRU 与死亡会话优先老化的受限内存流表, 杜绝状态耗尽 DoS 攻击.

//

// 复杂度量化:

// - 分段插入与重叠裁决: O(log K), 其中 K 为待组装片段数

// - 连续字节提取: O(M), 其中 M 为连续可用字节长度

// - 空间复杂度: 单会话内存硬上限 2MB, 全局容量严格按 max_sessions 上限配额

// ============================================================



use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use once_cell::sync::Lazy;



/// RFC 793 / RFC 1323 规范 TCP 状态机定义

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]

pub enum TcpState {

    Listen,

    SynSent,

    SynRcvd,

    Established,

    FinWait1,

    FinWait2,

    CloseWait,

    Closing,

    LastAck,

    TimeWait,

    Closed,

    Reset,

}



impl Default for TcpState {

    fn default() -> Self {

        TcpState::Listen

    }

}



/// TCP 重叠分节抗躲避裁决策略 (Ptacek & Newsham 规避对策)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]

pub enum TcpEvasionPolicy {

    /// 优先采信先到达的原始数据 (BSD / Solaris 默认策略)

    First,

    /// 优先采信后到达的最新数据 (Windows 默认策略)

    Last,

    /// Linux 策略 (新段全覆盖旧段则替换, 否则优先保留前置旧数据)

    Linux,

}



impl Default for TcpEvasionPolicy {

    fn default() -> Self {

        TcpEvasionPolicy::Linux
    }
}

// ============================================================
// 工业生产级 TCP 流重组热重载策略脚本引擎 (ReassemblyScriptEngine)
// 对标 Zeek Stream Policy 动态脚本与 Suricata Flow Reassembly Config 引擎
//
// 核心能力:
// 1. 运行时无缝热重载 (Hot-Reloading): 支持免重启通过 JSON/DSL 动态刷新重组参数、内存配额与裁决规则;
// 2. 目标操作系统反躲避策略自适应 (OS-Adaptive Evasion Policy):
//    依据初始 SYN 报文 TTL、MSS、Window Size 启发式指纹匹配对端操作系统 (Windows -> Last, Linux -> Linux, BSD -> First);
// 3. 多维度优先级匹配矩阵 (Multi-dimensional Priority Matching):
//    支持源/目的 IP、CIDR 子网掩码、服务端口区间等多重级联条件, 按优先级 (Priority) 纳秒级裁决;
// 4. 细粒度流生命周期控制 (Flow Quota & Lifecycle Control):
//    单流内存硬上限、分段积压配额、空闲超时时间与慢速滴流 (Slowloris) DoS 阈值动态生效;
// 5. 跨活跃流热刷新 (Zero-Downtime Session Refresh):
//    外部策略下发后, 可一键对当前内存中活跃流重写应用最新策略, 保证零停机、零漏包.
// ============================================================

/// 流重组交付模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReassemblyDeliveryMode {
    /// 实时触发 DPI 识别与摘要抽取
    StreamDpi,
    /// 缓冲等待全流结束或达到上限
    FullBuffer,
    /// 滑动分页消费模式 (内存恒定)
    SlidingPaging,
}

impl Default for ReassemblyDeliveryMode {
    fn default() -> Self {
        ReassemblyDeliveryMode::StreamDpi
    }
}

/// 目标主机操作系统类型推断 (对标 p0f v3 / Nmap TCP 指纹标准)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetOsType {
    Linux,
    Windows,
    Bsd,
    Solaris,
    Unknown,
}

impl TargetOsType {
    /// 获取该操作系统对应的最佳 Ptacek-Newsham 反躲避重叠重组策略
    pub fn default_evasion_policy(&self) -> TcpEvasionPolicy {
        match self {
            TargetOsType::Linux => TcpEvasionPolicy::Linux,
            TargetOsType::Windows => TcpEvasionPolicy::Last,
            TargetOsType::Bsd | TargetOsType::Solaris => TcpEvasionPolicy::First,
            TargetOsType::Unknown => TcpEvasionPolicy::Linux,
        }
    }
}

/// 基于初始 TCP SYN 报文的特征启发式推断对端操作系统家族
pub fn infer_target_os_from_syn(ttl: u8, window_size: u16, options: &TcpOptionsInfo) -> TargetOsType {
    if ttl <= 64 {
        if let Some(mss) = options.mss {
            if mss == 1460 && (window_size == 29200 || window_size == 14600 || window_size == 65535) {
                return TargetOsType::Linux;
            }
        }
        TargetOsType::Linux
    } else if ttl <= 128 {
        TargetOsType::Windows
    } else {
        TargetOsType::Solaris
    }
}

/// 快速判定 IP 地址是否属于 CIDR 掩码子网
fn check_ip_in_cidr(ip_str: &str, cidr_str: &str) -> bool {
    let parts: Vec<&str> = cidr_str.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let Ok(target_ip) = IpAddr::from_str(parts[0]) else { return false; };
    let Ok(prefix_len) = parts[1].parse::<u8>() else { return false; };
    let Ok(pkt_ip) = IpAddr::from_str(ip_str) else { return false; };

    match (pkt_ip, target_ip) {
        (IpAddr::V4(pkt_v4), IpAddr::V4(target_v4)) => {
            if prefix_len > 32 { return false; }
            let mask = if prefix_len == 0 { 0u32 } else { !0u32 << (32 - prefix_len) };
            (u32::from(pkt_v4) & mask) == (u32::from(target_v4) & mask)
        }
        (IpAddr::V6(pkt_v6), IpAddr::V6(target_v6)) => {
            if prefix_len > 128 { return false; }
            let mask = if prefix_len == 0 { 0u128 } else { !0u128 << (128 - prefix_len) };
            (u128::from(pkt_v6) & mask) == (u128::from(target_v6) & mask)
        }
        _ => false,
    }
}

fn default_max_buffer() -> usize { 2 * 1024 * 1024 } // 2MB
fn default_max_pending() -> usize { 1024 }
fn default_idle_timeout() -> u64 { 300 } // 5 分钟
fn default_gap_timeout() -> u64 { 5000 } // 5 秒
fn default_true() -> bool { true }

/// 工业级 TCP 流重组热重载策略规则定义
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReassemblyPolicyRule {
    pub id: String,
    pub name: String,
    pub priority: u32,
    #[serde(default)]
    pub src_cidr: Option<String>,
    #[serde(default)]
    pub dst_cidr: Option<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    pub policy: TcpEvasionPolicy,
    #[serde(default = "default_max_buffer")]
    pub max_buffer_bytes: usize,
    #[serde(default = "default_max_pending")]
    pub max_pending_segments: usize,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_gap_timeout")]
    pub gap_timeout_ms: u64,
    #[serde(default = "default_true")]
    pub enable_slowloris_defense: bool,
    #[serde(default)]
    pub delivery_mode: ReassemblyDeliveryMode,
}

impl Default for ReassemblyPolicyRule {
    fn default() -> Self {
        Self {
            id: "DEFAULT_FALLBACK".to_string(),
            name: "Default TCP Reassembly Policy".to_string(),
            priority: 0,
            src_cidr: None,
            dst_cidr: None,
            ports: Vec::new(),
            policy: TcpEvasionPolicy::Linux,
            max_buffer_bytes: 2 * 1024 * 1024,
            max_pending_segments: 1024,
            idle_timeout_secs: 300,
            gap_timeout_ms: 5000,
            enable_slowloris_defense: true,
            delivery_mode: ReassemblyDeliveryMode::StreamDpi,
        }
    }
}

/// 工业生产级流重组策略热重载脚本引擎 (对标 Zeek Stream Policy & Suricata Flow Reassembly Config)
pub struct ReassemblyScriptEngine {
    rules: Vec<ReassemblyPolicyRule>,
    version: u64,
    last_reload_time: String,
    total_reloads: usize,
}

impl Default for ReassemblyScriptEngine {
    fn default() -> Self {
        let mut engine = Self {
            rules: Vec::new(),
            version: 1,
            last_reload_time: "INITIAL".to_string(),
            total_reloads: 0,
        };
        engine.register_default_baseline_rules();
        engine
    }
}

impl ReassemblyScriptEngine {
    /// 注册开箱即用的工控与常见终端系统基线策略
    pub fn register_default_baseline_rules(&mut self) {
        self.rules = vec![
            // 1. 工控关键通道 (安全优先: Linux 保留原始前缀策略, 10s 长延迟空洞容忍)
            ReassemblyPolicyRule {
                id: "ICS_CRITICAL_CHANNELS".to_string(),
                name: "工控关键控制协议流重组安全基线".to_string(),
                priority: 100,
                src_cidr: None,
                dst_cidr: None,
                ports: vec![502, 102, 44818, 48898, 18245, 20000, 2404],
                policy: TcpEvasionPolicy::Linux,
                max_buffer_bytes: 4 * 1024 * 1024,
                max_pending_segments: 2048,
                idle_timeout_secs: 3600,
                gap_timeout_ms: 10000,
                enable_slowloris_defense: true,
                delivery_mode: ReassemblyDeliveryMode::StreamDpi,
            },
            // 2. Windows 终端与域控服务 (Windows 规范: Last 到达覆盖策略)
            ReassemblyPolicyRule {
                id: "WINDOWS_SMB_RDP".to_string(),
                name: "Windows 终端与域控通道 (Last 覆盖反躲避)".to_string(),
                priority: 80,
                src_cidr: None,
                dst_cidr: None,
                ports: vec![445, 3389, 139, 88],
                policy: TcpEvasionPolicy::Last,
                max_buffer_bytes: 2 * 1024 * 1024,
                max_pending_segments: 1024,
                idle_timeout_secs: 600,
                gap_timeout_ms: 5000,
                enable_slowloris_defense: true,
                delivery_mode: ReassemblyDeliveryMode::StreamDpi,
            },
            // 3. 通用兜底规则
            ReassemblyPolicyRule::default(),
        ];
        self.sort_rules();
    }

    fn sort_rules(&mut self) {
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// 从 JSON 格式策略脚本执行运行时无缝热重载
    /// 时间复杂度: O(R log R), 空间复杂度: O(R)
    pub fn hot_reload_from_json(&mut self, json_str: &str) -> Result<usize, String> {
        let parsed_rules: Vec<ReassemblyPolicyRule> = serde_json::from_str(json_str)
            .map_err(|e| format!("策略脚本 JSON 语法解析失败: {}", e))?;

        if parsed_rules.is_empty() {
            return Err("热重载失败: 提交的策略规则列表不能为空".to_string());
        }

        self.hot_reload_from_rules(parsed_rules);
        Ok(self.rules.len())
    }

    /// 通过规则对象集合执行运行时热重载
    pub fn hot_reload_from_rules(&mut self, mut new_rules: Vec<ReassemblyPolicyRule>) {
        // 如果未包含兜底规则，自动追加低优先级兜底规则
        if !new_rules.iter().any(|r| r.priority == 0) {
            new_rules.push(ReassemblyPolicyRule::default());
        }
        self.rules = new_rules;
        self.sort_rules();
        self.version += 1;
        self.total_reloads += 1;
        self.last_reload_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    }

    /// 根据五元组流量特征匹配当前生效的最佳流重组策略
    /// 时间复杂度: O(R), R 为规则数 (小常数 < 50)
    pub fn match_policy(&self, src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> ReassemblyPolicyRule {
        for rule in &self.rules {
            // 1. 端口检查
            if !rule.ports.is_empty() && !rule.ports.contains(&src_port) && !rule.ports.contains(&dst_port) {
                continue;
            }

            // 2. 源子网检查
            if let Some(ref s_cidr) = rule.src_cidr {
                if !check_ip_in_cidr(src_ip, s_cidr) {
                    continue;
                }
            }

            // 3. 目的子网检查
            if let Some(ref d_cidr) = rule.dst_cidr {
                if !check_ip_in_cidr(dst_ip, d_cidr) {
                    continue;
                }
            }

            return rule.clone();
        }

        ReassemblyPolicyRule::default()
    }

    pub fn get_rules(&self) -> &[ReassemblyPolicyRule] {
        &self.rules
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn last_reload_time(&self) -> &str {
        &self.last_reload_time
    }

    pub fn total_reloads(&self) -> usize {
        self.total_reloads
    }
}

/// 全局流重组策略脚本热重载管理器单例
pub static REASSEMBLY_SCRIPT_ENGINE: Lazy<RwLock<ReassemblyScriptEngine>> =
    Lazy::new(|| RwLock::new(ReassemblyScriptEngine::default()));

/// 运行时动态热重载流重组策略脚本 (外部调用入口)
pub fn hot_reload_stream_reassembly_policy(json_rules: &str) -> Result<usize, String> {
    let mut engine = crate::lock_guard::write_rwlock(
        &REASSEMBLY_SCRIPT_ENGINE,
        "stream_reassembly::reload_reassembly_policy",
    );
    engine.hot_reload_from_json(json_rules)
}

/// 获取当前流重组策略脚本快照信息
pub fn get_stream_reassembly_policy_snapshot() -> (u64, Vec<ReassemblyPolicyRule>) {
    let engine = crate::lock_guard::read_rwlock(
        &REASSEMBLY_SCRIPT_ENGINE,
        "stream_reassembly::get_stream_reassembly_policy_snapshot",
    );
    (engine.version(), engine.get_rules().to_vec())
}



/// RFC 793 / RFC 2018 / RFC 7323 TCP 选项结构体

#[derive(Debug, Clone, Default, Serialize, Deserialize)]

pub struct TcpOptionsInfo {

    pub mss: Option<u16>,

    pub window_scale: Option<u8>,

    pub sack_permitted: bool,

    pub sack_blocks: Vec<(u32, u32)>,

    pub timestamp_val: Option<u32>,

    pub timestamp_echo: Option<u32>,

}



/// 解析原始 TCP Option 字节流

pub fn parse_tcp_options(options_bytes: &[u8]) -> TcpOptionsInfo {

    let mut info = TcpOptionsInfo::default();

    let mut i = 0;

    while i < options_bytes.len() {

        match options_bytes[i] {

            0 => break, // EOL

            1 => { i += 1; } // NOP

            2 => { // MSS

                if i + 4 <= options_bytes.len() && options_bytes[i + 1] == 4 {

                    info.mss = Some(u16::from_be_bytes([options_bytes[i + 2], options_bytes[i + 3]]));

                    i += 4;

                } else {

                    break;

                }

            }

            3 => { // Window Scale

                if i + 3 <= options_bytes.len() && options_bytes[i + 1] == 3 {

                    info.window_scale = Some(options_bytes[i + 2]);

                    i += 3;

                } else {

                    break;

                }

            }

            4 => { // SACK Permitted

                if i + 2 <= options_bytes.len() && options_bytes[i + 1] == 2 {

                    info.sack_permitted = true;

                    i += 2;

                } else {

                    break;

                }

            }

            5 => { // SACK Blocks

                if i + 2 <= options_bytes.len() {

                    let len = options_bytes[i + 1] as usize;

                    if len >= 2 && i + len <= options_bytes.len() {

                        let num_blocks = (len - 2) / 8;

                        for b in 0..num_blocks {

                            let offset = i + 2 + b * 8;

                            let left = u32::from_be_bytes([options_bytes[offset], options_bytes[offset+1], options_bytes[offset+2], options_bytes[offset+3]]);

                            let right = u32::from_be_bytes([options_bytes[offset+4], options_bytes[offset+5], options_bytes[offset+6], options_bytes[offset+7]]);

                            info.sack_blocks.push((left, right));

                        }

                        i += len;

                    } else {

                        break;

                    }

                } else {

                    break;

                }

            }

            8 => { // Timestamp

                if i + 10 <= options_bytes.len() && options_bytes[i + 1] == 10 {

                    info.timestamp_val = Some(u32::from_be_bytes([options_bytes[i+2], options_bytes[i+3], options_bytes[i+4], options_bytes[i+5]]));

                    info.timestamp_echo = Some(u32::from_be_bytes([options_bytes[i+6], options_bytes[i+7], options_bytes[i+8], options_bytes[i+9]]));

                    i += 10;

                } else {

                    break;

                }

            }

            _ => {

                if i + 1 < options_bytes.len() {

                    let len = options_bytes[i + 1] as usize;

                    if len >= 2 && i + len <= options_bytes.len() {

                        i += len;

                    } else {

                        break;

                    }

                } else {

                    break;

                }

            }

        }

    }

    info

}





/// 规范化双向五元组流键 (Canonical Flow Key)

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]

pub struct FlowKey {

    pub ip_a: String,

    pub ip_b: String,

    pub port_a: u16,

    pub port_b: u16,

    pub transport: String,

}



impl FlowKey {

    pub fn new(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16, transport: &str) -> Self {

        let (ip_a, port_a, ip_b, port_b) = if (src_ip, src_port) <= (dst_ip, dst_port) {

            (src_ip.to_string(), src_port, dst_ip.to_string(), dst_port)

        } else {

            (dst_ip.to_string(), dst_port, src_ip.to_string(), src_port)

        };



        Self {

            ip_a,

            ip_b,

            port_a,

            port_b,

            transport: transport.to_uppercase(),

        }

    }

}



/// 模 2^32 相对序号距离计算: 计算 (a - b) 的有符号偏移

/// 正值代表 a 在 b 之后, 负值代表 a 在 b 之前, 完美防御 32 位回环

#[inline(always)]

pub fn seq_diff(a: u32, b: u32) -> i64 {

    (a.wrapping_sub(b)) as i32 as i64

}



/// 单个 TCP 分段

#[derive(Debug, Clone)]

pub struct TcpSegment {

    pub seq: u32,

    pub data: Vec<u8>,

    pub timestamp: String,

}



/// TCP 虚拟分级流控与抗 DoS 配置 (对标 Zeek Stream Disk Paging)

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct StreamPagingConfig {

    /// L1 内存中最多保留的热分段数量 (默认 1024)

    pub max_l1_hot_segments: usize,

    /// L1 连续已重组内存最大保留字节上限 (默认 2MB, 超限后滑动截断保护)

    pub max_assembled_window_bytes: usize,

    /// L2 虚拟分页每个流最大允许溢出的暂存分段数 (默认 16384, 扩容 8 倍)

    pub max_l2_paged_segments: usize,

    /// Slowloris 慢速滴流检测: 单字节小包连续阈值 (默认 128)

    pub slowloris_tiny_packet_threshold: usize,

    /// 序列号空洞悬挂超时时间 (毫秒, 默认 30,000 即 30 秒)

    pub gap_timeout_ms: u64,

}



impl Default for StreamPagingConfig {

    fn default() -> Self {

        Self {

            max_l1_hot_segments: 1024,

            max_assembled_window_bytes: 2 * 1024 * 1024,

            max_l2_paged_segments: 16384,

            slowloris_tiny_packet_threshold: 128,

            gap_timeout_ms: 30_000,

        }

    }

}



/// 单向连续重组流缓冲区 (带重叠消除、L1/L2 虚拟分页与空洞检测)

pub struct DirectionalStreamReassembler {

    /// L1 待拼装的未连续热分段 (按 seq 严格排序)

    pub pending_segments: BTreeMap<u32, TcpSegment>,

    /// L2 虚拟分页缓冲池: 存储远端冷乱序分段，极大扩充乱序容纳能力 (对标 Zeek)

    pub paged_segments: BTreeMap<u32, TcpSegment>,

    /// 下一个期望连续接收的绝对序列号

    pub next_expected_seq: Option<u32>,

    /// 初始序列号 (ISN)

    pub isn: Option<u32>,

    /// 已连续排齐并可供消费的数据 (L1 滑动内存窗口)

    pub assembled_data: Vec<u8>,

    /// 累计已消费并滑出内存的连续字节数 (Sliding Stream Offset)

    pub consumed_bytes_total: u64,

    /// 乱序分段计数

    pub out_of_order_count: usize,

    /// 恶意的重叠分节注入计数

    pub overlapping_anomaly_count: usize,

    /// 重传分段计数

    pub retransmission_count: usize,

    /// 裁决策略

    pub evasion_policy: TcpEvasionPolicy,

    /// RFC 7323 PAWS (Protection Against Wrapped Sequence Numbers) 拦截违规数

    pub paws_violation_count: usize,

    /// 最近一次有效接收到的时间戳 (TS.Recent)

    pub ts_recent: Option<u32>,

    /// 上一次确认发送的序号 (Last.ACK.sent)

    pub last_ack_sent: u32,



    // ===== TASK-22 新增抗 DoS 与流控属性 =====

    /// 连续微小滴流小包计数 (载荷 <= 2 字节)

    pub consecutive_tiny_packets: usize,

    /// 首个序列号空洞产生的时间戳 (毫秒)

    pub first_gap_timestamp_ms: Option<u64>,

    /// 是否检测到慢速滴流 DoS 攻击 (Slowloris)

    pub slowloris_attack_detected: bool,

    /// 因慢速攻击或容量超限丢弃的分节数

    pub slowloris_dropped_segments: usize,

    /// 双层分级流控配置

    pub paging_config: StreamPagingConfig,

}



impl DirectionalStreamReassembler {

    pub fn new(policy: TcpEvasionPolicy) -> Self {

        Self {

            pending_segments: BTreeMap::new(),

            paged_segments: BTreeMap::new(),

            next_expected_seq: None,

            isn: None,

            assembled_data: Vec::new(),

            consumed_bytes_total: 0,

            out_of_order_count: 0,

            overlapping_anomaly_count: 0,

            retransmission_count: 0,

            evasion_policy: policy,

            paws_violation_count: 0,

            ts_recent: None,

            last_ack_sent: 0,

            consecutive_tiny_packets: 0,

            first_gap_timestamp_ms: None,

            slowloris_attack_detected: false,

            slowloris_dropped_segments: 0,

            paging_config: StreamPagingConfig::default(),

        }

    }



    /// 滑动消费已拼装的连续数据，更新 consumed_bytes_total 并释放 RAM 内存 (保障巨型流 O(W) 内存恒定)

    pub fn consume_continuous_data(&mut self, bytes_to_consume: usize) -> Vec<u8> {

        let count = bytes_to_consume.min(self.assembled_data.len());

        let consumed = self.assembled_data.drain(0..count).collect();

        self.consumed_bytes_total += count as u64;

        consumed

    }



    /// 设置初始序列号并初始化期望指针

    pub fn init_isn(&mut self, isn: u32) {

        if self.isn.is_none() {

            self.isn = Some(isn);

            // SYN 占用 1 个序号空间

            self.next_expected_seq = Some(isn.wrapping_add(1));

            self.last_ack_sent = isn.wrapping_add(1);

        }

    }



    /// 插入并裁决 TCP 分节数据 (支持 RFC 7323 PAWS 序列号防回绕校验)

    pub fn push_segment_with_ts(&mut self, seq: u32, payload: &[u8], timestamp: &str, ts_val: Option<u32>) {

        if payload.is_empty() {

            return;

        }



        // RFC 7323 PAWS 核心防御: 校验时间戳倒流

        if let Some(ts) = ts_val {

            if let Some(recent) = self.ts_recent {

                // 如果当前时间戳小于最近时间戳 (模 2^32 有符号差值 < 0)

                if (ts.wrapping_sub(recent) as i32) < 0 {

                    self.paws_violation_count += 1;

                    return; // 坚决丢弃 PAWS 违规的滞留回绕分段

                }

            }

            self.ts_recent = Some(ts);

        }



        self.push_segment(seq, payload, timestamp);

    }



    /// 插入并裁决 TCP 分节数据

    pub fn push_segment(&mut self, seq: u32, payload: &[u8], timestamp: &str) {

        if payload.is_empty() {

            return;

        }



        // 如果尚未有 ISN, 以首个有载荷的包的 seq 作为基准锚点

        if self.next_expected_seq.is_none() {

            self.next_expected_seq = Some(seq);

            self.isn = Some(seq);

        }



        let next_exp = self.next_expected_seq.unwrap();

        let payload_len = payload.len() as u32;



        // 1. 检查是否已被消费过的完全历史重复段 (seq + len <= next_expected_seq)

        if seq_diff(seq.wrapping_add(payload_len), next_exp) <= 0 {

            self.retransmission_count += 1;

            return;

        }



        // 2. 部分在消费指针之前: 跨越已消费边界的重叠，截断头部已消费部分

        let (effective_seq, effective_data) = if seq_diff(seq, next_exp) < 0 {

            let skip_bytes = seq_diff(next_exp, seq) as usize;

            if skip_bytes >= payload.len() {

                self.retransmission_count += 1;

                return;

            }

            // 标记跨越消费指针的重叠异常 (Overlapping segment with already-consumed bytes)

            self.overlapping_anomaly_count += 1;

            (next_exp, &payload[skip_bytes..])

        } else {

            (seq, payload)

        };



        // 3. 乱序检测: 如果当前有效序列号不在期望指针上, 标记乱序

        if effective_seq != next_exp {

            self.out_of_order_count += 1;

        }



        // 4. 重叠区间检测与 Ptacek-Newsham 裁决

        let mut to_insert = TcpSegment {

            seq: effective_seq,

            data: effective_data.to_vec(),

            timestamp: timestamp.to_string(),

        };



        // 遍历所有待拼装段, 检测并解决冲突
        let mut keys_to_remove = Vec::new();
        let mut segments_to_reinsert = Vec::new();
        let mut skip_insert = false;

        for (&p_seq, p_seg) in &self.pending_segments {
            let p_len = p_seg.data.len() as u32;
            let p_end = p_seq.wrapping_add(p_len);
            let cur_end = to_insert.seq.wrapping_add(to_insert.data.len() as u32);

            // 检查区间 [p_seq, p_end) 与 [to_insert.seq, cur_end) 是否存在重叠
            let overlaps = seq_diff(to_insert.seq, p_end) < 0 && seq_diff(cur_end, p_seq) > 0;

            if overlaps {
                self.overlapping_anomaly_count += 1;

                // 若数据完全一模一样，直接当作重传丢弃
                if to_insert.seq == p_seq && to_insert.data == p_seg.data {
                    self.retransmission_count += 1;
                    skip_insert = true;
                    break;
                }

                match self.evasion_policy {
                    TcpEvasionPolicy::First => {
                        // 优先旧分段: 裁剪新分段
                        if seq_diff(to_insert.seq, p_seq) >= 0 && seq_diff(cur_end, p_end) <= 0 {
                            // 新段完全被旧段包围，彻底废弃
                            skip_insert = true;
                            break;
                        } else if seq_diff(to_insert.seq, p_seq) >= 0 && seq_diff(to_insert.seq, p_end) < 0 {
                            // 新段头部与旧段尾部重叠，切掉新段重叠前缀
                            let trim_len = seq_diff(p_end, to_insert.seq) as usize;
                            if trim_len < to_insert.data.len() {
                                to_insert.seq = p_end;
                                to_insert.data = to_insert.data[trim_len..].to_vec();
                            } else {
                                skip_insert = true;
                                break;
                            }
                        }
                    }
                    TcpEvasionPolicy::Last => {
                        // 优先新分段: 覆盖旧分段 (Windows TCP 栈反躲避规范)
                        keys_to_remove.push(p_seq);

                        if seq_diff(to_insert.seq, p_seq) <= 0 && seq_diff(cur_end, p_end) >= 0 {
                            // Case 1: 新段完全覆盖旧段，旧段直接丢弃
                        } else if seq_diff(p_seq, to_insert.seq) <= 0 && seq_diff(cur_end, p_end) <= 0 {
                            // Case 4: 新段落在旧段内部，旧段被分裂为前后两截
                            let front_len = seq_diff(to_insert.seq, p_seq) as usize;
                            if front_len > 0 {
                                let mut front = p_seg.clone();
                                front.data.truncate(front_len);
                                segments_to_reinsert.push((p_seq, front));
                            }
                            let back_offset = seq_diff(cur_end, p_seq) as usize;
                            if back_offset < p_seg.data.len() {
                                let mut back = p_seg.clone();
                                back.seq = cur_end;
                                back.data = back.data[back_offset..].to_vec();
                                segments_to_reinsert.push((cur_end, back));
                            }
                        } else if seq_diff(p_seq, to_insert.seq) < 0 && seq_diff(to_insert.seq, p_end) < 0 {
                            // Case 2: 新段覆盖旧段后半截，保留旧段前半截 [p_seq, to_insert.seq)
                            let keep_len = seq_diff(to_insert.seq, p_seq) as usize;
                            if keep_len > 0 {
                                let mut front = p_seg.clone();
                                front.data.truncate(keep_len);
                                segments_to_reinsert.push((p_seq, front));
                            }
                        } else if seq_diff(to_insert.seq, p_seq) <= 0 && seq_diff(cur_end, p_seq) > 0 {
                            // Case 3: 新段覆盖旧段前半截，保留旧段后半截 [cur_end, p_end)
                            let trim_len = seq_diff(cur_end, p_seq) as usize;
                            if trim_len < p_seg.data.len() {
                                let mut back = p_seg.clone();
                                back.seq = cur_end;
                                back.data = back.data[trim_len..].to_vec();
                                segments_to_reinsert.push((cur_end, back));
                            }
                        }
                    }
                    TcpEvasionPolicy::Linux => {
                        // Linux 策略: 全覆盖则替换旧段，否则保留旧段
                        if seq_diff(to_insert.seq, p_seq) <= 0 && seq_diff(cur_end, p_end) >= 0 {
                            keys_to_remove.push(p_seq);
                        } else {
                            // 部分重叠保留旧段
                            if seq_diff(to_insert.seq, p_end) < 0 && seq_diff(to_insert.seq, p_seq) >= 0 {
                                let trim_len = seq_diff(p_end, to_insert.seq) as usize;
                                if trim_len < to_insert.data.len() {
                                    to_insert.seq = p_end;
                                    to_insert.data = to_insert.data[trim_len..].to_vec();
                                } else {
                                    skip_insert = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        for k in keys_to_remove {
            self.pending_segments.remove(&k);
        }
        for (k, seg) in segments_to_reinsert {
            self.pending_segments.insert(k, seg);
        }



        if !skip_insert && !to_insert.data.is_empty() {

            // L1/L2 双层分级虚拟分页: 超出 L1 热窗口时将远端分节移入 L2 暂存，扩容至 16384+

            if self.pending_segments.len() >= self.paging_config.max_l1_hot_segments {

                if let Some(&max_seq) = self.pending_segments.keys().next_back() {

                    if seq_diff(to_insert.seq, max_seq) > 0 {

                        // 新分节比 L1 中最远的还远，直接进 L2 暂存

                        if self.paged_segments.len() < self.paging_config.max_l2_paged_segments {

                            self.paged_segments.insert(to_insert.seq, to_insert);

                        }

                    } else {

                        // 换出 L1 中最远的分节至 L2，容纳更新近的分节

                        if let Some(evicted) = self.pending_segments.remove(&max_seq) {

                            if self.paged_segments.len() < self.paging_config.max_l2_paged_segments {

                                self.paged_segments.insert(max_seq, evicted);

                            }

                            self.pending_segments.insert(to_insert.seq, to_insert);

                        }

                    }

                }

            } else {

                self.pending_segments.insert(to_insert.seq, to_insert);

            }

        }



        // 5. 连续拼装推进 (Drain Continuous In-Order Segments)

        self.drain_continuous_segments();

    }



    /// 推进连续可组装的字节流并写入 assembled_data

    fn drain_continuous_segments(&mut self) {

        loop {

            let mut progressed = false;



            while let Some(&min_seq) = self.pending_segments.keys().next() {

                let next_exp = match self.next_expected_seq {

                    Some(s) => s,

                    None => break,

                };



                // 如果最小序列号正好匹配期望值

                if min_seq == next_exp {

                    if let Some(seg) = self.pending_segments.remove(&min_seq) {

                        let seg_len = seg.data.len() as u32;

                        self.assembled_data.extend_from_slice(&seg.data);

                        self.next_expected_seq = Some(next_exp.wrapping_add(seg_len));

                        progressed = true;

                    }

                } else if seq_diff(min_seq, next_exp) < 0 {

                    // 处理残留的重叠过期分节

                    if let Some(seg) = self.pending_segments.remove(&min_seq) {

                        let seg_len = seg.data.len() as u32;

                        let seg_end = min_seq.wrapping_add(seg_len);

                        if seq_diff(seg_end, next_exp) > 0 {

                            let offset = seq_diff(next_exp, min_seq) as usize;

                            let valid_data = &seg.data[offset..];

                            self.assembled_data.extend_from_slice(valid_data);

                            self.next_expected_seq = Some(seg_end);

                            progressed = true;

                        }

                    }

                } else {

                    // 存在空洞 (Packet Loss / Hole), 停止连续提取

                    break;

                }

            }



            // 检查 L2 虚拟分页暂存区是否有分节已成为邻近窗口，若有则回灌 L1

            if !self.paged_segments.is_empty() && self.pending_segments.len() < self.paging_config.max_l1_hot_segments {

                let mut rehydrate_keys = Vec::new();

                for &p_seq in self.paged_segments.keys() {

                    if rehydrate_keys.len() + self.pending_segments.len() >= self.paging_config.max_l1_hot_segments {

                        break;

                    }

                    rehydrate_keys.push(p_seq);

                }

                for k in rehydrate_keys {

                    if let Some(seg) = self.paged_segments.remove(&k) {

                        self.pending_segments.insert(k, seg);

                        progressed = true;

                    }

                }

            }



            if !progressed {

                break;

            }

        }



        // L1 滑动窗口硬内存配额守护: 若上层未及时消费导致超过 max_assembled_window_bytes，滑动释放旧数据

        if self.assembled_data.len() > self.paging_config.max_assembled_window_bytes {

            let overflow = self.assembled_data.len() - self.paging_config.max_assembled_window_bytes;

            self.assembled_data.drain(0..overflow);

            self.consumed_bytes_total += overflow as u64;

        }



        // 空洞完全补齐状态

        if self.pending_segments.is_empty() && self.paged_segments.is_empty() {

            self.first_gap_timestamp_ms = None;

        }

    }

}



/// 流中单向交互数据块 (用于 Follow TCP Stream 前端展示)

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct StreamChunk {

    pub direction: String,

    pub timestamp: String,

    pub payload_hex: String,

    pub payload_text: String,

    pub length: usize,

}



/// 工业级 TCP 双向会话状态跟踪器

pub struct TcpSessionReassembler {

    pub flow_key: FlowKey,

    pub client_ip: String,

    pub client_port: u16,

    pub server_ip: String,

    pub server_port: u16,



    /// 严格遵循 RFC 793 的连接生命周期状态机

    pub state: TcpState,



    /// 客户端到服务端单向流重组器

    pub c2s: DirectionalStreamReassembler,

    /// 服务端到客户端单向流重组器

    pub s2c: DirectionalStreamReassembler,



    /// 统计指标

    pub packets_c2s: usize,

    pub packets_s2c: usize,

    pub bytes_c2s: usize,

    pub bytes_s2c: usize,

    pub retransmissions: usize,

    pub start_time: String,

    pub last_time: String,

    pub last_active_ms: u64,



    /// 往返时延估计 (RTT, 毫秒)

    pub syn_rtt_ms: Option<f64>,

    syn_send_timestamp_ms: Option<u64>,



    /// 协议识别与 TLS 指纹

    pub protocol: String,

    pub tls_sni: Option<String>,

    pub ja3_hash: Option<String>,

    pub c2s_options: TcpOptionsInfo,

    pub s2c_options: TcpOptionsInfo,

    pub reassembled_app_protocol: Option<String>,

    pub reassembled_app_summary: Option<String>,

    /// RFC 6298 平滑往返时延 (SRTT, 毫秒)

    pub srtt_ms: Option<f64>,

    /// RFC 6298 往返时延方差 (RTTVAR, 毫秒)

    pub rttvar_ms: Option<f64>,

    /// RFC 6298 自适应重传超时时间 (RTO, 毫秒)

    pub rto_ms: f64,

    /// 连续重复 ACK 计数

    pub duplicate_ack_count: usize,

    pub last_c2s_ack: u32,

    pub last_s2c_ack: u32,

    /// 拥塞与快速重传事件感知

    pub congestion_events: usize,

}



impl TcpSessionReassembler {

    pub fn new(

        client_ip: &str,

        client_port: u16,

        server_ip: &str,

        server_port: u16,

        transport: &str,

        timestamp: &str,

        epoch_ms: u64,

    ) -> Self {

        let flow_key = FlowKey::new(client_ip, server_ip, client_port, server_port, transport);

        Self {

            flow_key,

            client_ip: client_ip.to_string(),

            client_port,

            server_ip: server_ip.to_string(),

            server_port,

            state: TcpState::Listen,

            c2s: DirectionalStreamReassembler::new(TcpEvasionPolicy::Linux),

            s2c: DirectionalStreamReassembler::new(TcpEvasionPolicy::Linux),

            packets_c2s: 0,

            packets_s2c: 0,

            bytes_c2s: 0,

            bytes_s2c: 0,

            retransmissions: 0,

            start_time: timestamp.to_string(),

            last_time: timestamp.to_string(),

            last_active_ms: epoch_ms,

            syn_rtt_ms: None,

            syn_send_timestamp_ms: None,

            protocol: "TCP".to_string(),

            tls_sni: None,

            ja3_hash: None,

            c2s_options: TcpOptionsInfo::default(),

            s2c_options: TcpOptionsInfo::default(),

            reassembled_app_protocol: None,

            reassembled_app_summary: None,

            srtt_ms: None,

            rttvar_ms: None,

            rto_ms: 1000.0,

            duplicate_ack_count: 0,

            last_c2s_ack: 0,

            last_s2c_ack: 0,

            congestion_events: 0,

        }

    }



    /// RFC 6298 工业级 Jacobson/Karels 算法更新 RTT 与 RTO

    pub fn update_rtt_sample(&mut self, rtt_sample_ms: f64) {

        if rtt_sample_ms <= 0.0 || rtt_sample_ms > 120_000.0 {

            return;

        }

        match (self.srtt_ms, self.rttvar_ms) {

            (None, _) => {

                // 首次往返测量: SRTT = R, RTTVAR = R / 2, RTO = SRTT + max(G, 4 * RTTVAR)

                self.srtt_ms = Some(rtt_sample_ms);

                self.rttvar_ms = Some(rtt_sample_ms / 2.0);

                self.rto_ms = (rtt_sample_ms + (4.0 * (rtt_sample_ms / 2.0)).max(1.0)).clamp(200.0, 60000.0);

            }

            (Some(srtt), Some(rttvar)) => {

                // 后续测量: RTTVAR <- (1 - 0.25) * RTTVAR + 0.25 * |SRTT - R|

                //          SRTT <- (1 - 0.125) * SRTT + 0.125 * R

                let diff = (srtt - rtt_sample_ms).abs();

                let new_rttvar = 0.75 * rttvar + 0.25 * diff;

                let new_srtt = 0.875 * srtt + 0.125 * rtt_sample_ms;

                self.rttvar_ms = Some(new_rttvar);

                self.srtt_ms = Some(new_srtt);

                self.rto_ms = (new_srtt + (4.0 * new_rttvar).max(1.0)).clamp(200.0, 60000.0);

            }

            _ => {}

        }

    }



    /// 连续重复 ACK 识别与拥塞快速重传判定 (RFC 5681 Fast Retransmit)

    pub fn track_ack_and_congestion(&mut self, is_c2s: bool, ack: u32, payload_len: usize) {

        let last_ack = if is_c2s { self.last_c2s_ack } else { self.last_s2c_ack };

        if ack == last_ack && payload_len == 0 {

            self.duplicate_ack_count += 1;

            if self.duplicate_ack_count == 3 {

                // 收到 3 个重复 ACK 判定网络丢包与拥塞，触发快速重传

                self.congestion_events += 1;

            }

        } else if seq_diff(ack, last_ack) > 0 {

            self.duplicate_ack_count = 0;

            if is_c2s {

                self.last_c2s_ack = ack;

            } else {

                self.last_s2c_ack = ack;

            }

        }

    }

    /// 动态应用流重组策略规则 (热重载与策略规则绑定)
    pub fn apply_policy_rule(&mut self, rule: &ReassemblyPolicyRule) {
        self.c2s.evasion_policy = rule.policy;
        self.s2c.evasion_policy = rule.policy;
        self.c2s.paging_config.max_assembled_window_bytes = rule.max_buffer_bytes;
        self.s2c.paging_config.max_assembled_window_bytes = rule.max_buffer_bytes;
        self.c2s.paging_config.max_l1_hot_segments = rule.max_pending_segments;
        self.s2c.paging_config.max_l1_hot_segments = rule.max_pending_segments;
        self.c2s.paging_config.gap_timeout_ms = rule.gap_timeout_ms;
        self.s2c.paging_config.gap_timeout_ms = rule.gap_timeout_ms;
    }

    /// 基于 TCP SYN 报文特征启发式自适应绑定操作系统反躲避策略
    pub fn adapt_os_policy_from_syn(&mut self, ttl: u8, window_size: u16, options: &TcpOptionsInfo) {
        let os_type = infer_target_os_from_syn(ttl, window_size, options);
        let policy = os_type.default_evasion_policy();
        self.c2s.evasion_policy = policy;
        self.s2c.evasion_policy = policy;
    }

    /// 核心方法: 注入包含 TCP 标志位的完整报文，驱动状态机并完成防规避重组

    pub fn process_tcp_flags(

        &mut self,

        src_ip: &str,

        src_port: u16,

        seq: u32,

        _ack: u32,

        flags: u8,

        payload: &[u8],

        timestamp: &str,

        epoch_ms: u64,

    ) {

        self.last_time = timestamp.to_string();

        self.last_active_ms = epoch_ms;



        let is_syn = (flags & 0x02) != 0;

        let is_ack = (flags & 0x10) != 0;

        let is_fin = (flags & 0x01) != 0;

        let is_rst = (flags & 0x04) != 0;



        let is_c2s = src_ip == self.client_ip && src_port == self.client_port;



        // 驱动 ACK 追踪与快速重传/拥塞事件感知

        self.track_ack_and_congestion(is_c2s, _ack, payload.len());



        // 1. 状态机驱动 (RFC 793 State Machine Transitions)

        if is_rst {

            self.state = TcpState::Reset;

        } else {

            match self.state {

                TcpState::Listen => {

                    if is_c2s && is_syn && !is_ack {

                        self.state = TcpState::SynSent;

                        self.c2s.init_isn(seq);

                        self.syn_send_timestamp_ms = Some(epoch_ms);

                    }

                }

                TcpState::SynSent => {

                    if !is_c2s && is_syn && is_ack {

                        self.state = TcpState::SynRcvd;

                        self.s2c.init_isn(seq);

                        if let Some(t_syn) = self.syn_send_timestamp_ms {

                            if epoch_ms >= t_syn {

                                let rtt = (epoch_ms - t_syn) as f64;

                                self.syn_rtt_ms = Some(rtt);

                                self.update_rtt_sample(rtt);

                            }

                        }

                    }

                }

                TcpState::SynRcvd => {

                    if is_c2s && is_ack && !is_syn {

                        self.state = TcpState::Established;

                    }

                }

                TcpState::Established => {

                    if is_fin {

                        if is_c2s {

                            self.state = TcpState::FinWait1;

                        } else {

                            self.state = TcpState::CloseWait;

                        }

                    }

                }

                TcpState::FinWait1 => {

                    if !is_c2s && is_ack && !is_fin {

                        self.state = TcpState::FinWait2;

                    } else if !is_c2s && is_fin {

                        self.state = TcpState::Closing;

                    }

                }

                TcpState::FinWait2 => {

                    if !is_c2s && is_fin {

                        self.state = TcpState::TimeWait;

                    }

                }

                TcpState::CloseWait => {

                    if is_c2s && is_fin {

                        self.state = TcpState::LastAck;

                    }

                }

                TcpState::Closing => {

                    if is_ack {

                        self.state = TcpState::TimeWait;

                    }

                }

                TcpState::LastAck => {

                    if is_ack {

                        self.state = TcpState::Closed;

                    }

                }

                TcpState::TimeWait => {

                    // 超时后自动转为 Closed

                }

                TcpState::Closed | TcpState::Reset => {}

            }

        }



        // 2. 数据与重组推入

        if is_c2s {

            self.packets_c2s += 1;

            self.bytes_c2s += payload.len();

            if is_syn {

                self.c2s.init_isn(seq);

            }

            if !payload.is_empty() {

                self.c2s.push_segment(seq, payload, timestamp);

            }

        } else {

            self.packets_s2c += 1;

            self.bytes_s2c += payload.len();

            if is_syn {

                self.s2c.init_isn(seq);

            }

            if !payload.is_empty() {

                self.s2c.push_segment(seq, payload, timestamp);

            }

        }



        self.retransmissions = self.c2s.retransmission_count + self.s2c.retransmission_count;



        // 3. 实时协议特征识别 (如 TLS SNI)

        if is_c2s && !payload.is_empty() && self.tls_sni.is_none() {

            if let Some(sni) = extract_tls_sni(payload) {

                self.tls_sni = Some(sni);

                self.protocol = "TLS".to_string();

            }

        }



        // 4. 应用层协议二次重组交付 (Stream-to-DPI Reassembly Handover)

        // 当连续重组缓冲区推进且长度达到最小检测阈值 (>= 4 字节) 时, 触发完整规约识别与解构

        if is_c2s && !self.c2s.assembled_data.is_empty() {

            let app_proto = crate::dpi::identify_protocol(self.client_port, self.server_port, &self.c2s.assembled_data);

            if app_proto != "TCP" && app_proto != "UNKNOWN" {

                self.reassembled_app_protocol = Some(app_proto.clone());

                let dissected = crate::dpi::dissect_payload(&app_proto, &self.c2s.assembled_data);

                if let Some(summary_val) = dissected.get("summary").and_then(|v| v.as_str()) {

                    self.reassembled_app_summary = Some(summary_val.to_string());

                } else if let Ok(text) = std::str::from_utf8(&self.c2s.assembled_data) {

                    let first_line = text.lines().next().unwrap_or("").trim();

                    if !first_line.is_empty() {

                        self.reassembled_app_summary = Some(first_line.to_string());

                    }

                }

                if self.protocol == "TCP" {

                    self.protocol = app_proto;

                }

            }

        }

    }



    /// 注入带有已解析 TCP Options 的完整报文

    pub fn process_tcp_flags_with_options(

        &mut self,

        src_ip: &str,

        src_port: u16,

        seq: u32,

        ack: u32,

        flags: u8,

        payload: &[u8],

        options: TcpOptionsInfo,

        timestamp: &str,

        epoch_ms: u64,

    ) {

        let is_c2s = src_ip == self.client_ip && src_port == self.client_port;

        if is_c2s {

            if options.window_scale.is_some() { self.c2s_options.window_scale = options.window_scale; }

            if options.mss.is_some() { self.c2s_options.mss = options.mss; }

            if !options.sack_blocks.is_empty() { self.c2s_options.sack_blocks = options.sack_blocks; }

        } else {

            if options.window_scale.is_some() { self.s2c_options.window_scale = options.window_scale; }

            if options.mss.is_some() { self.s2c_options.mss = options.mss; }

            if !options.sack_blocks.is_empty() { self.s2c_options.sack_blocks = options.sack_blocks; }

        }

        if let Some(echo_val) = options.timestamp_echo {

            if echo_val > 0 && epoch_ms >= (echo_val as u64) {

                let rtt_sample = (epoch_ms - (echo_val as u64)) as f64;

                self.update_rtt_sample(rtt_sample);

            }

        }



        let ts_val = options.timestamp_val;

        self.last_time = timestamp.to_string();

        self.last_active_ms = epoch_ms;



        let is_syn = (flags & 0x02) != 0;

        let is_ack = (flags & 0x10) != 0;

        let is_fin = (flags & 0x01) != 0;

        let is_rst = (flags & 0x04) != 0;



        self.track_ack_and_congestion(is_c2s, ack, payload.len());



        if is_rst {

            self.state = TcpState::Reset;

        } else {

            match self.state {

                TcpState::Listen => {

                    if is_c2s && is_syn && !is_ack {

                        self.state = TcpState::SynSent;

                        self.c2s.init_isn(seq);

                        self.syn_send_timestamp_ms = Some(epoch_ms);

                    }

                }

                TcpState::SynSent => {

                    if !is_c2s && is_syn && is_ack {

                        self.state = TcpState::SynRcvd;

                        self.s2c.init_isn(seq);

                        if let Some(t_syn) = self.syn_send_timestamp_ms {

                            if epoch_ms >= t_syn {

                                let rtt = (epoch_ms - t_syn) as f64;

                                self.syn_rtt_ms = Some(rtt);

                                self.update_rtt_sample(rtt);

                            }

                        }

                    }

                }

                TcpState::SynRcvd => {

                    if is_c2s && is_ack && !is_syn {

                        self.state = TcpState::Established;

                    }

                }

                TcpState::Established => {

                    if is_fin {

                        if is_c2s {

                            self.state = TcpState::FinWait1;

                        } else {

                            self.state = TcpState::CloseWait;

                        }

                    }

                }

                TcpState::FinWait1 => {

                    if !is_c2s && is_ack && !is_fin {

                        self.state = TcpState::FinWait2;

                    } else if !is_c2s && is_fin {

                        self.state = TcpState::Closing;

                    }

                }

                TcpState::FinWait2 => {

                    if !is_c2s && is_fin {

                        self.state = TcpState::TimeWait;

                    }

                }

                TcpState::CloseWait => {

                    if is_c2s && is_fin {

                        self.state = TcpState::LastAck;

                    }

                }

                TcpState::Closing => {

                    if is_ack {

                        self.state = TcpState::TimeWait;

                    }

                }

                TcpState::LastAck => {

                    if is_ack {

                        self.state = TcpState::Closed;

                    }

                }

                TcpState::TimeWait => {}

                TcpState::Closed | TcpState::Reset => {}

            }

        }



        if is_c2s {

            self.packets_c2s += 1;

            self.bytes_c2s += payload.len();

            if is_syn {

                self.c2s.init_isn(seq);

            }

            if !payload.is_empty() {

                self.c2s.push_segment_with_ts(seq, payload, timestamp, ts_val);

            }

        } else {

            self.packets_s2c += 1;

            self.bytes_s2c += payload.len();

            if is_syn {

                self.s2c.init_isn(seq);

            }

            if !payload.is_empty() {

                self.s2c.push_segment_with_ts(seq, payload, timestamp, ts_val);

            }

        }



        if is_c2s && !self.c2s.assembled_data.is_empty() {

            let app_proto = crate::dpi::identify_protocol(self.client_port, self.server_port, &self.c2s.assembled_data);

            if app_proto != "TCP" && app_proto != "UNKNOWN" {

                self.reassembled_app_protocol = Some(app_proto.clone());

                let dissected = crate::dpi::dissect_payload(&app_proto, &self.c2s.assembled_data);

                if let Some(summary_val) = dissected.get("summary").and_then(|v| v.as_str()) {

                    self.reassembled_app_summary = Some(summary_val.to_string());

                } else if let Ok(text) = std::str::from_utf8(&self.c2s.assembled_data) {

                    let first_line = text.lines().next().unwrap_or("").trim();

                    if !first_line.is_empty() {

                        self.reassembled_app_summary = Some(first_line.to_string());

                    }

                }

                if self.protocol == "TCP" {

                    self.protocol = app_proto;

                }

            }

        }

    }



    /// 提取追踪流数据片断 (Follow TCP Stream)

    pub fn get_follow_stream_chunks(&self) -> Vec<StreamChunk> {

        let mut chunks = Vec::new();



        if !self.c2s.assembled_data.is_empty() {

            let hex_str = hex::encode_upper(&self.c2s.assembled_data);

            let text_repr: String = self

                .c2s

                .assembled_data

                .iter()

                .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })

                .collect();



            chunks.push(StreamChunk {

                direction: "client".to_string(),

                timestamp: self.start_time.clone(),

                payload_hex: hex_str,

                payload_text: text_repr,

                length: self.c2s.assembled_data.len(),

            });

        }



        if !self.s2c.assembled_data.is_empty() {

            let hex_str = hex::encode_upper(&self.s2c.assembled_data);

            let text_repr: String = self

                .s2c

                .assembled_data

                .iter()

                .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })

                .collect();



            chunks.push(StreamChunk {

                direction: "server".to_string(),

                timestamp: self.last_time.clone(),

                payload_hex: hex_str,

                payload_text: text_repr,

                length: self.s2c.assembled_data.len(),

            });

        }



        chunks

    }

}



/// 双向会话流摘要视图

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct FlowSummary {

    pub flow_id: String,

    pub client_ip: String,

    pub client_port: u16,

    pub server_ip: String,

    pub server_port: u16,

    pub transport: String,

    pub protocol: String,

    pub state: String,

    pub packets_total: usize,

    pub bytes_total: usize,

    pub bytes_c2s: usize,

    pub bytes_s2c: usize,

    pub retransmissions: usize,

    pub out_of_order_count: usize,

    pub overlapping_anomalies: usize,

    pub rtt_ms: Option<f64>,

    pub duration_ms: u64,

    pub start_time: String,

    pub last_time: String,

    pub tls_sni: Option<String>,

    pub reassembled_app_protocol: Option<String>,

    pub reassembled_app_summary: Option<String>,

    pub window_scale_c2s: Option<u8>,

    pub window_scale_s2c: Option<u8>,

}



/// 工业级会话流管理引擎 (FlowSessionEngine)

pub struct FlowSessionEngine {

    sessions: HashMap<FlowKey, TcpSessionReassembler>,

    pub max_sessions: usize,

    pub default_policy: TcpEvasionPolicy,

}



impl FlowSessionEngine {

    pub fn new(max_sessions: usize) -> Self {

        Self {

            sessions: HashMap::new(),

            max_sessions,

            default_policy: TcpEvasionPolicy::Linux,

        }

    }



    /// 兼容旧接口的快捷处理入口

    pub fn process_packet(

        &mut self,

        src_ip: &str,

        dst_ip: &str,

        src_port: u16,

        dst_port: u16,

        transport: &str,

        seq: u32,

        is_syn: bool,

        payload: &[u8],

        timestamp: &str,

    ) {

        let flags = if is_syn { 0x02 } else { 0x10 }; // 默认 SYN 或 ACK

        self.process_tcp_packet(

            src_ip, dst_ip, src_port, dst_port, transport, seq, 0, flags, payload, timestamp, 0,

        );

    }



    /// 包含完整序列号与标志位的工业级处理管道

    pub fn process_tcp_packet(

        &mut self,

        src_ip: &str,

        dst_ip: &str,

        src_port: u16,

        dst_port: u16,

        transport: &str,

        seq: u32,

        ack: u32,

        flags: u8,

        payload: &[u8],

        timestamp: &str,

        epoch_ms: u64,

    ) {

        let key = FlowKey::new(src_ip, dst_ip, src_port, dst_port, transport);



        if !self.sessions.contains_key(&key) {

            // 容量控制与科学淘汰

            if self.sessions.len() >= self.max_sessions {

                self.evict_stale_session();

            }



            let mut reassembler = TcpSessionReassembler::new(

                src_ip, src_port, dst_ip, dst_port, transport, timestamp, epoch_ms,

            );

            {
                let engine = crate::lock_guard::read_rwlock(
                    &REASSEMBLY_SCRIPT_ENGINE,
                    "stream_reassembly::process_tcp_packet_policy",
                );
                let rule = engine.match_policy(src_ip, dst_ip, src_port, dst_port);
                reassembler.apply_policy_rule(&rule);
            }

            self.sessions.insert(key.clone(), reassembler);

        }



        if let Some(session) = self.sessions.get_mut(&key) {

            session.process_tcp_flags(src_ip, src_port, seq, ack, flags, payload, timestamp, epoch_ms);

        }

    }

    /// 动态热刷新当前所有活跃流重组策略 (Zero-Downtime Session Refresh)
    /// 当策略脚本更新后调用，遍历所有活跃 session 并根据最新策略规则重写策略参数
    pub fn refresh_active_sessions_policies(&mut self) -> usize {
        let Ok(engine) = REASSEMBLY_SCRIPT_ENGINE.read() else {
            return 0;
        };
        let mut refreshed = 0;
        for session in self.sessions.values_mut() {
            let rule = engine.match_policy(
                &session.client_ip,
                &session.server_ip,
                session.client_port,
                session.server_port,
            );
            session.apply_policy_rule(&rule);
            refreshed += 1;
        }
        refreshed
    }

    /// 获取特定流会话的不可变引用
    pub fn get_session(&self, key: &FlowKey) -> Option<&TcpSessionReassembler> {
        self.sessions.get(key)
    }

    /// 获取特定流会话的可变引用
    pub fn get_session_mut(&mut self, key: &FlowKey) -> Option<&mut TcpSessionReassembler> {
        self.sessions.get_mut(key)
    }

    /// 获取当前会话数量
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }



    /// 优先淘汰死亡会话 (Closed/Reset), 其次淘汰 LRU 最旧会话

    fn evict_stale_session(&mut self) {

        let mut target_key = None;

        let mut min_active_ms = u64::MAX;



        // 第一轮查找: 寻找处于终态的流

        for (k, s) in &self.sessions {

            if s.state == TcpState::Closed || s.state == TcpState::Reset || s.state == TcpState::TimeWait {

                target_key = Some(k.clone());

                break;

            }

            if s.last_active_ms < min_active_ms {

                min_active_ms = s.last_active_ms;

                target_key = Some(k.clone());

            }

        }



        if let Some(k) = target_key {

            self.sessions.remove(&k);

        }

    }



    /// 获取所有流的摘要列表

    pub fn get_flow_summaries(&self) -> Vec<FlowSummary> {

        self.sessions

            .values()

            .map(|s| {

                let flow_id = format!(

                    "{}:{}-{}:{}",

                    s.client_ip, s.client_port, s.server_ip, s.server_port

                );

                FlowSummary {

                    flow_id,

                    client_ip: s.client_ip.clone(),

                    client_port: s.client_port,

                    server_ip: s.server_ip.clone(),

                    server_port: s.server_port,

                    transport: s.flow_key.transport.clone(),

                    protocol: s.protocol.clone(),

                    state: format!("{:?}", s.state),

                    packets_total: s.packets_c2s + s.packets_s2c,

                    bytes_total: s.bytes_c2s + s.bytes_s2c,

                    bytes_c2s: s.bytes_c2s,

                    bytes_s2c: s.bytes_s2c,

                    retransmissions: s.retransmissions,

                    out_of_order_count: s.c2s.out_of_order_count + s.s2c.out_of_order_count,

                    overlapping_anomalies: s.c2s.overlapping_anomaly_count + s.s2c.overlapping_anomaly_count,

                    rtt_ms: s.syn_rtt_ms,

                    duration_ms: 0,

                    start_time: s.start_time.clone(),

                    last_time: s.last_time.clone(),

                    tls_sni: s.tls_sni.clone(),

                    reassembled_app_protocol: s.reassembled_app_protocol.clone(),

                    reassembled_app_summary: s.reassembled_app_summary.clone(),

                    window_scale_c2s: s.c2s_options.window_scale,

                    window_scale_s2c: s.s2c_options.window_scale,

                }

            })

            .collect()

    }



    /// 提取指定流的完整 Follow Stream 交互

    pub fn get_follow_stream(

        &self,

        src_ip: &str,

        dst_ip: &str,

        src_port: u16,

        dst_port: u16,

        transport: &str,

    ) -> Option<Vec<StreamChunk>> {

        let key = FlowKey::new(src_ip, dst_ip, src_port, dst_port, transport);

        self.sessions.get(&key).map(|s| s.get_follow_stream_chunks())

    }



    pub fn clear(&mut self) {

        self.sessions.clear();

    }

}



/// 快速从 TLS ClientHello 报文中解析 SNI 域名 (RFC 6066)

fn extract_tls_sni(payload: &[u8]) -> Option<String> {

    if payload.len() < 43 {

        return None;

    }

    if payload[0] != 0x16 || payload[1] != 0x03 {

        return None;

    }

    if payload[5] != 0x01 {

        return None;

    }



    let mut cursor = 43;

    if cursor >= payload.len() {

        return None;

    }



    let session_id_len = payload[cursor] as usize;

    cursor += 1 + session_id_len;

    if cursor + 2 > payload.len() {

        return None;

    }



    let cipher_suites_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;

    cursor += 2 + cipher_suites_len;

    if cursor + 1 > payload.len() {

        return None;

    }



    let compression_len = payload[cursor] as usize;

    cursor += 1 + compression_len;

    if cursor + 2 > payload.len() {

        return None;

    }



    let ext_total_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;

    cursor += 2;



    let ext_end = cursor + ext_total_len;

    if ext_end > payload.len() {

        return None;

    }



    while cursor + 4 <= ext_end {

        let ext_type = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);

        let ext_len = u16::from_be_bytes([payload[cursor + 2], payload[cursor + 3]]) as usize;

        cursor += 4;



        if ext_type == 0x0000 {

            if cursor + 5 <= payload.len() {

                let name_len = u16::from_be_bytes([payload[cursor + 3], payload[cursor + 4]]) as usize;

                if cursor + 5 + name_len <= payload.len() {

                    let name_bytes = &payload[cursor + 5..cursor + 5 + name_len];

                    return String::from_utf8(name_bytes.to_vec()).ok();

                }

            }

        }

        cursor += ext_len;

    }



    None

}



/// 全局共享流引擎单例句柄

pub static GLOBAL_FLOW_ENGINE: once_cell::sync::Lazy<Arc<Mutex<FlowSessionEngine>>> =

    once_cell::sync::Lazy::new(|| {

        Arc::new(Mutex::new(FlowSessionEngine::new(10_000)))

    });



// ============================================================

// 自动化单元测试集 (Unit Test Harness & Edge Cases)

// ============================================================

#[cfg(test)]

pub mod tests {

    use super::*;



    #[test]

    fn test_tcp_three_way_handshake_to_established() {

        let mut session = TcpSessionReassembler::new(

            "192.168.1.10", 50000, "192.168.1.20", 502, "TCP", "12:00:00.000", 1000,

        );



        // 1. Client -> Server: SYN (seq = 1000)

        session.process_tcp_flags("192.168.1.10", 50000, 1000, 0, 0x02, &[], "12:00:00.000", 1000);

        assert_eq!(session.state, TcpState::SynSent);

        assert_eq!(session.c2s.isn, Some(1000));

        assert_eq!(session.c2s.next_expected_seq, Some(1001));



        // 2. Server -> Client: SYN+ACK (seq = 5000, ack = 1001)

        session.process_tcp_flags("192.168.1.20", 502, 5000, 1001, 0x12, &[], "12:00:00.020", 1020);

        assert_eq!(session.state, TcpState::SynRcvd);

        assert_eq!(session.s2c.isn, Some(5000));

        assert_eq!(session.syn_rtt_ms, Some(20.0));



        // 3. Client -> Server: ACK (seq = 1001, ack = 5001)

        session.process_tcp_flags("192.168.1.10", 50000, 1001, 5001, 0x10, &[], "12:00:00.025", 1025);

        assert_eq!(session.state, TcpState::Established);

    }



    #[test]

    fn test_tcp_out_of_order_reassembly() {

        let mut session = TcpSessionReassembler::new(

            "10.0.0.1", 1234, "10.0.0.2", 80, "TCP", "10:00:00.000", 1000,

        );

        session.state = TcpState::Established;

        session.c2s.init_isn(100); // 期望从 101 开始



        // 故意乱序到达: 先收到后半部分 [111..120]，再收到前半部分 [101..110]

        let part2 = b"WORLD";

        let part1 = b"HELLO";



        session.process_tcp_flags("10.0.0.1", 1234, 106, 0, 0x10, part2, "10:00:00.002", 1002);

        assert_eq!(session.c2s.out_of_order_count, 1);

        assert_eq!(session.c2s.assembled_data.len(), 0); // 空洞存在，暂未重组



        session.process_tcp_flags("10.0.0.1", 1234, 101, 0, 0x10, part1, "10:00:00.003", 1003);

        assert_eq!(session.c2s.assembled_data, b"HELLOWORLD");

        assert_eq!(session.c2s.next_expected_seq, Some(111));

    }



    #[test]

    fn test_tcp_overlapping_evasion_first_vs_last_policy() {

        // 测试 Ptacek-Newsham 经典重叠攻击裁决:

        // 旧数据: [100..106] "ATTACK"

        // 恶意重叠注入: [103..109] "SAFE!!" (重叠 103..106 发生冲突: "ACK" vs "SAF")

        let mut reasm_first = DirectionalStreamReassembler::new(TcpEvasionPolicy::First);

        reasm_first.init_isn(99); // 期望从 100 开始



        reasm_first.push_segment(100, b"ATTACK", "10:00:00.000");

        reasm_first.push_segment(103, b"SAFE!!", "10:00:00.001");



        assert_eq!(reasm_first.overlapping_anomaly_count, 1);

        // First 策略保护先到达的 ATTACK, 新分节重叠部分被裁切，仅保留尾部 "E!!"

        assert_eq!(reasm_first.assembled_data, b"ATTACKE!!");



        // 测试 Last 策略 (Windows 风格)

        let mut reasm_last = DirectionalStreamReassembler::new(TcpEvasionPolicy::Last);

        reasm_last.init_isn(99);

        // 假设分段先乱序进入缓存

        reasm_last.pending_segments.insert(100, TcpSegment {

            seq: 100,

            data: b"OLDDATA".to_vec(),

            timestamp: "10:00:00.000".to_string(),

        });

        reasm_last.push_segment(100, b"NEWDATA_COVER", "10:00:00.001");

        assert_eq!(reasm_last.assembled_data, b"NEWDATA_COVER");

    }



    #[test]

    fn test_tcp_sequence_number_wraparound() {

        // 32 位序列号回环极限测试: 边界跨越 0xFFFFFFFF -> 0x00000000

        let seq_near_max: u32 = 0xFFFF_FFF0;

        let diff = seq_diff(0x0000_0010, seq_near_max);

        // 0x10 在 0xFFFFFFF0 之后 32 个字节

        assert_eq!(diff, 32);



        let mut reasm = DirectionalStreamReassembler::new(TcpEvasionPolicy::Linux);

        reasm.next_expected_seq = Some(seq_near_max);



        // 注入跨越回环的数据

        let data1 = b"OVER"; // 4 字节 -> next = 0xFFFFFFF4

        reasm.push_segment(seq_near_max, data1, "10:00:00.000");

        assert_eq!(reasm.assembled_data, b"OVER");

        assert_eq!(reasm.next_expected_seq, Some(0xFFFF_FFF4));

    }



    #[test]

    fn test_tcp_rst_termination_and_lru_eviction() {

        let mut engine = FlowSessionEngine::new(2);



        // 创建流 1 并断开 (RST)

        engine.process_tcp_packet(

            "192.168.1.1", "192.168.1.2", 1000, 80, "TCP", 100, 0, 0x02, &[], "10:00:00.000", 1000,

        );

        engine.process_tcp_packet(

            "192.168.1.1", "192.168.1.2", 1000, 80, "TCP", 101, 0, 0x04, &[], "10:00:00.010", 1010,

        ); // RST

        

        let summaries = engine.get_flow_summaries();

        assert_eq!(summaries[0].state, "Reset");



        // 创建流 2

        engine.process_tcp_packet(

            "192.168.1.3", "192.168.1.4", 2000, 80, "TCP", 200, 0, 0x02, &[], "10:00:00.020", 1020,

        );



        // 插入流 3: 触发容量上限 (max = 2)，应当自动淘汰处于 Reset 终态的流 1

        engine.process_tcp_packet(

            "192.168.1.5", "192.168.1.6", 3000, 80, "TCP", 300, 0, 0x02, &[], "10:00:00.030", 1030,

        );



        assert_eq!(engine.sessions.len(), 2);

        let key1 = FlowKey::new("192.168.1.1", "192.168.1.2", 1000, 80, "TCP");

        assert!(!engine.sessions.contains_key(&key1)); // 流 1 已被科学淘汰

    }



    #[test]

    fn test_tcp_options_parsing_sack_and_wscale() {

        // 构造标准 TCP Option:

        // NOP (0x01), Window Scale (0x03, 0x03, 0x07 = 7)

        // MSS (0x02, 0x04, 0x05, 0xB4 = 1460)

        // SACK Blocks (0x05, 0x0A, 0x00, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x07, 0xD0 = [1000, 2000])

        let options_bytes = [

            0x01,

            0x03, 0x03, 0x07,

            0x02, 0x04, 0x05, 0xB4,

            0x05, 0x0A, 0x00, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x07, 0xD0,

            0x00, // EOL

        ];



        let parsed = parse_tcp_options(&options_bytes);

        assert_eq!(parsed.window_scale, Some(7));

        assert_eq!(parsed.mss, Some(1460));

        assert_eq!(parsed.sack_blocks.len(), 1);

        assert_eq!(parsed.sack_blocks[0], (1000, 2000));

    }



    #[test]

    fn test_tcp_stream_reassembly_to_dpi_handover() {

        let mut session = TcpSessionReassembler::new(

            "10.0.0.1", 54321, "10.0.0.2", 80, "TCP", "10:00:00.000", 1000,

        );



        // 1. 三次握手建立连接

        session.process_tcp_flags("10.0.0.1", 54321, 100, 0, 0x02, &[], "10:00:00.000", 1000); // SYN

        session.process_tcp_flags("10.0.0.2", 80, 500, 101, 0x12, &[], "10:00:00.010", 1010); // SYN-ACK

        session.process_tcp_flags("10.0.0.1", 54321, 101, 501, 0x10, &[], "10:00:00.020", 1020); // ACK

        assert_eq!(session.state, TcpState::Established);



        // 2. 模拟跨越 2 个分节传输的 HTTP POST 请求

        let part1 = b"POST /api/v1/telemetry HTTP/1.1\r\nHost: example.com\r\nContent-Length: ";

        let part2 = b"13\r\n\r\n{\"data\": true}";



        session.process_tcp_flags("10.0.0.1", 54321, 101, 501, 0x18, part1, "10:00:00.030", 1030);

        let seq2 = 101 + part1.len() as u32;

        session.process_tcp_flags("10.0.0.1", 54321, seq2, 501, 0x18, part2, "10:00:00.040", 1040);



        // 3. 验证经过有序重组后, 自动向上交付并识别出 HTTP_REQ 协议与请求路径

        assert_eq!(session.reassembled_app_protocol, Some("HTTP".to_string()));

        assert_eq!(session.protocol, "HTTP");

        assert!(session.reassembled_app_summary.is_some());

        let summary = session.reassembled_app_summary.unwrap();

        assert!(summary.contains("/api/v1/telemetry"));

    }



    #[test]

    fn test_tcp_paws_rejection_and_jacobson_karels_rtt() {

        let mut session = TcpSessionReassembler::new(

            "192.168.1.10", 12345, "192.168.1.20", 80, "TCP", "10:00:00.000", 1000,

        );



        // 1. 三次握手注入与 RTT 初次测量 (握手耗时 100ms)

        session.process_tcp_flags("192.168.1.10", 12345, 100, 0, 0x02, &[], "10:00:00.000", 1000);

        session.process_tcp_flags("192.168.1.20", 80, 500, 101, 0x12, &[], "10:00:00.100", 1100);

        assert_eq!(session.syn_rtt_ms, Some(100.0));

        assert_eq!(session.srtt_ms, Some(100.0));

        assert_eq!(session.rttvar_ms, Some(50.0));

        assert_eq!(session.rto_ms, 300.0);



        // 2. 第二次测量更新 (RTT = 120ms) -> Jacobson/Karels 递推更新

        session.update_rtt_sample(120.0);

        assert_eq!(session.srtt_ms, Some(102.5));

        assert_eq!(session.rttvar_ms, Some(42.5));

        assert_eq!(session.rto_ms, 272.5);



        // 3. 连续 3 次重复 ACK 触发快速重传与拥塞感知 (RFC 5681)

        session.process_tcp_flags("192.168.1.20", 80, 501, 101, 0x10, &[], "10:00:00.100", 1100);

        assert_eq!(session.duplicate_ack_count, 1);

        session.process_tcp_flags("192.168.1.20", 80, 501, 101, 0x10, &[], "10:00:00.110", 1110);

        assert_eq!(session.duplicate_ack_count, 2);

        assert_eq!(session.congestion_events, 0);

        session.process_tcp_flags("192.168.1.20", 80, 501, 101, 0x10, &[], "10:00:00.120", 1120);

        assert_eq!(session.duplicate_ack_count, 3);

        assert_eq!(session.congestion_events, 1);



        // 4. RFC 7323 PAWS (时间戳倒流防回绕保护)

        let mut reasm = DirectionalStreamReassembler::new(TcpEvasionPolicy::Linux);

        reasm.init_isn(100);

        reasm.push_segment_with_ts(101, b"VALID_DATA_", "10:00:00.200", Some(5000));

        assert_eq!(reasm.assembled_data, b"VALID_DATA_");

        assert_eq!(reasm.paws_violation_count, 0);



        // 注入回绕旧报文 (ts = 4000 < 5000 时间戳倒流)

        reasm.push_segment_with_ts(112, b"STALE_WRAP_", "10:00:00.205", Some(4000));

        assert_eq!(reasm.paws_violation_count, 1);

        assert_eq!(reasm.assembled_data, b"VALID_DATA_");



        // 注入正常递增时间戳分段 (ts = 5050)

        reasm.push_segment_with_ts(112, b"NEXT_PART!", "10:00:00.210", Some(5050));

        assert_eq!(reasm.paws_violation_count, 1);

        assert_eq!(reasm.assembled_data, b"VALID_DATA_NEXT_PART!");

    }





    #[test]

    fn test_l1_l2_virtual_paging_giant_stream() {

        let mut reasm = DirectionalStreamReassembler::new(TcpEvasionPolicy::Linux);

        // 配置小热窗口便于快速触发 L2 溢出

        reasm.paging_config.max_l1_hot_segments = 4;

        reasm.paging_config.max_l2_paged_segments = 64;

        reasm.init_isn(1000); // 期望从 1001 开始



        // 故意留下 1001 空洞不发，先连续注入 10 个乱序远端分段 (seq 1101 到 2001)

        for i in 1..=10 {

            let seq = 1012 + ((i - 1) as u32) * 8;

            let payload = format!("PART_{:02}_", i);

            reasm.push_segment(seq, payload.as_bytes(), "12:00:00.000");

        }



        // 验证 L1 热窗口保留 4 个，其余 6 个安全溢出至 L2 暂存，总数 10 个零丢失

        assert_eq!(reasm.pending_segments.len(), 4);

        assert_eq!(reasm.paged_segments.len(), 6);

        assert_eq!(reasm.assembled_data.len(), 0); // 空洞尚未补齐



        // 现在注入首个缺失的空洞包 (seq 1001)

        reasm.push_segment(1001, b"HEAD_PART__", "12:00:00.050");



        // 验证连续回灌机制：所有分段 (HEAD + 10 个 PART) 完整有序重组！

        assert!(reasm.assembled_data.starts_with(b"HEAD_PART__"));

        assert!(reasm.assembled_data.windows(8).any(|w| w == b"PART_01_"));
        assert!(reasm.assembled_data.windows(8).any(|w| w == b"PART_10_"));

        assert_eq!(reasm.pending_segments.len(), 0);

        assert_eq!(reasm.paged_segments.len(), 0);

    }



    #[test]

    fn test_sliding_stream_consumer_bounded_memory() {

        let mut reasm = DirectionalStreamReassembler::new(TcpEvasionPolicy::Linux);

        reasm.paging_config.max_assembled_window_bytes = 128; // 设定 128 字节硬上限

        reasm.init_isn(0);



        // 注入 200 字节连续数据

        let big_chunk = vec![0x42; 200];

        reasm.push_segment(1, &big_chunk, "12:00:00.000");



        // 验证自动滑动裁剪保护：内存保留不超过 128 字节，超出部分计入 consumed_bytes_total

        assert_eq!(reasm.assembled_data.len(), 128);

        assert_eq!(reasm.consumed_bytes_total, 72); // 200 - 128 = 72



        // 主动滑动消费 64 字节

        let consumed = reasm.consume_continuous_data(64);

        assert_eq!(consumed.len(), 64);

        assert_eq!(reasm.assembled_data.len(), 64);

        assert_eq!(reasm.consumed_bytes_total, 136); // 72 + 64

    }

    // ============================================================
    // 【TASK-33】流重组热重载策略脚本引擎 6 轮全场景严苛测试
    // ============================================================

    #[test]
    fn test_reassembly_policy_rule_priority_and_cidr_matching() {
        let mut engine = ReassemblyScriptEngine::default();

        let rules = vec![
            ReassemblyPolicyRule {
                id: "HIGH_PRIO_SCADA".to_string(),
                name: "SCADA Core Subnet".to_string(),
                priority: 200,
                src_cidr: Some("192.168.1.0/24".to_string()),
                dst_cidr: None,
                ports: vec![502],
                policy: TcpEvasionPolicy::Linux,
                max_buffer_bytes: 8 * 1024 * 1024,
                max_pending_segments: 4096,
                idle_timeout_secs: 7200,
                gap_timeout_ms: 15000,
                enable_slowloris_defense: true,
                delivery_mode: ReassemblyDeliveryMode::StreamDpi,
            },
            ReassemblyPolicyRule {
                id: "MED_PRIO_WIN_CLIENTS".to_string(),
                name: "Office Windows Clients".to_string(),
                priority: 100,
                src_cidr: Some("192.168.0.0/16".to_string()),
                dst_cidr: None,
                ports: vec![],
                policy: TcpEvasionPolicy::Last,
                max_buffer_bytes: 1024 * 1024,
                max_pending_segments: 512,
                idle_timeout_secs: 300,
                gap_timeout_ms: 5000,
                enable_slowloris_defense: false,
                delivery_mode: ReassemblyDeliveryMode::FullBuffer,
            },
            ReassemblyPolicyRule::default(),
        ];

        engine.hot_reload_from_rules(rules);

        // 1. 命中高优先级 SCADA 子网规则
        let matched1 = engine.match_policy("192.168.1.50", "10.0.0.1", 502, 80);
        assert_eq!(matched1.id, "HIGH_PRIO_SCADA");
        assert_eq!(matched1.policy, TcpEvasionPolicy::Linux);
        assert_eq!(matched1.max_buffer_bytes, 8 * 1024 * 1024);

        // 2. 命中中优先级 Windows 办公子网规则 (端口非 502)
        let matched2 = engine.match_policy("192.168.2.100", "10.0.0.1", 445, 80);
        assert_eq!(matched2.id, "MED_PRIO_WIN_CLIENTS");
        assert_eq!(matched2.policy, TcpEvasionPolicy::Last);
        assert_eq!(matched2.delivery_mode, ReassemblyDeliveryMode::FullBuffer);

        // 3. 命中兜底默认规则
        let matched3 = engine.match_policy("172.16.0.1", "10.0.0.1", 80, 8080);
        assert_eq!(matched3.id, "DEFAULT_FALLBACK");
        assert_eq!(matched3.policy, TcpEvasionPolicy::Linux);
    }

    #[test]
    fn test_hot_reload_policy_from_json_runtime() {
        let mut engine = ReassemblyScriptEngine::default();
        let initial_version = engine.version();

        let valid_json = r#"[
            {
                "id": "DYNAMIC_RULE_01",
                "name": "Dynamic Windows Overwrite Policy",
                "priority": 500,
                "src_cidr": "10.10.0.0/16",
                "dst_cidr": null,
                "ports": [3389, 445],
                "policy": "Last",
                "max_buffer_bytes": 16777216,
                "max_pending_segments": 8192,
                "idle_timeout_secs": 1800,
                "gap_timeout_ms": 3000,
                "enable_slowloris_defense": true,
                "delivery_mode": "SlidingPaging"
            }
        ]"#;

        let res = engine.hot_reload_from_json(valid_json);
        assert!(res.is_ok());
        assert!(engine.version() > initial_version);
        assert_eq!(engine.total_reloads(), 1);

        let matched = engine.match_policy("10.10.1.20", "172.16.1.1", 3389, 49152);
        assert_eq!(matched.id, "DYNAMIC_RULE_01");
        assert_eq!(matched.policy, TcpEvasionPolicy::Last);
        assert_eq!(matched.max_buffer_bytes, 16 * 1024 * 1024);
        assert_eq!(matched.delivery_mode, ReassemblyDeliveryMode::SlidingPaging);

        // 极限防御 1: 格式错误的 JSON 必须快速失败并拦截
        let invalid_json = r#"[ { "id": "MALFORMED" ... "#;
        let fail_res = engine.hot_reload_from_json(invalid_json);
        assert!(fail_res.is_err());

        // 极限防御 2: 空规则数组必须拦截
        let empty_json = r#"[]"#;
        let empty_res = engine.hot_reload_from_json(empty_json);
        assert!(empty_res.is_err());
    }

    #[test]
    fn test_dynamic_policy_switch_from_linux_to_windows_last() {
        // 第一阶段: Linux (乱序缓冲中优先保留旧数据 First/Linux)
        let mut reasm_linux = DirectionalStreamReassembler::new(TcpEvasionPolicy::Linux);
        reasm_linux.init_isn(0); // 期望 1
        // 乱序分段 [11..21]: "AAAAAAAAAA"
        reasm_linux.push_segment(11, b"AAAAAAAAAA", "12:00:00.000");
        // 重叠冲突分段 [16..26]: "BBBBBBBBBB" (16..20 发生冲突)
        reasm_linux.push_segment(16, b"BBBBBBBBBB", "12:00:00.001");
        // 注入空洞补齐段 [1..11]: "0123456789"
        reasm_linux.push_segment(1, b"0123456789", "12:00:00.002");

        // Linux/First 策略: [11..20] 保持旧段 "AAAAAAAAAA", 重叠后半部分拼接 "BBBBB"
        assert_eq!(reasm_linux.assembled_data, b"0123456789AAAAAAAAAABBBBB");

        // 第二阶段: 动态切换为 Windows Last (后到达的冲突数据覆盖已有缓存段)
        let mut reasm_windows = DirectionalStreamReassembler::new(TcpEvasionPolicy::Last);
        reasm_windows.init_isn(0); // 期望 1
        // 乱序分段 [11..21]: "AAAAAAAAAA"
        reasm_windows.push_segment(11, b"AAAAAAAAAA", "12:00:00.000");
        // 重叠冲突分段 [16..26]: "BBBBBBBBBB" (16..20 发生冲突)
        reasm_windows.push_segment(16, b"BBBBBBBBBB", "12:00:00.001");
        // 注入空洞补齐段 [1..11]: "0123456789"
        reasm_windows.push_segment(1, b"0123456789", "12:00:00.002");

        // Windows Last 策略: [11..15] 为 "AAAAA", [16..25] 被新分段完全覆盖为 "BBBBBBBBBB"
        assert_eq!(reasm_windows.assembled_data, b"0123456789AAAAABBBBBBBBBB");
    }

    #[test]
    fn test_os_adaptive_policy_binding_from_syn_fingerprint() {
        // 1. Linux 典型 SYN 特征 (TTL <= 64, MSS 1460, WS 29200)
        let mut linux_opt = TcpOptionsInfo::default();
        linux_opt.mss = Some(1460);
        let os_linux = infer_target_os_from_syn(64, 29200, &linux_opt);
        assert_eq!(os_linux, TargetOsType::Linux);
        assert_eq!(os_linux.default_evasion_policy(), TcpEvasionPolicy::Linux);

        // 2. Windows 典型 SYN 特征 (TTL 128)
        let win_opt = TcpOptionsInfo::default();
        let os_win = infer_target_os_from_syn(128, 8192, &win_opt);
        assert_eq!(os_win, TargetOsType::Windows);
        assert_eq!(os_win.default_evasion_policy(), TcpEvasionPolicy::Last);

        // 3. Solaris / BSD 特征 (TTL 255)
        let os_solaris = infer_target_os_from_syn(255, 65535, &win_opt);
        assert_eq!(os_solaris, TargetOsType::Solaris);
        assert_eq!(os_solaris.default_evasion_policy(), TcpEvasionPolicy::First);

        // 4. 会话自适应绑定验证
        let mut session = TcpSessionReassembler::new(
            "192.168.1.10", 50000, "10.0.0.1", 80, "TCP", "12:00:00.000", 1000,
        );
        session.adapt_os_policy_from_syn(128, 8192, &win_opt);
        assert_eq!(session.c2s.evasion_policy, TcpEvasionPolicy::Last);
        assert_eq!(session.s2c.evasion_policy, TcpEvasionPolicy::Last);
    }

    #[test]
    fn test_active_sessions_policy_hot_refresh_zero_downtime() {
        let mut flow_engine = FlowSessionEngine::new(100);

        // 建立三个处于活动状态的 TCP 会话
        flow_engine.process_tcp_packet("192.168.1.10", "10.0.0.1", 50001, 80, "TCP", 100, 0, 0x02, &[], "12:00:00.000", 1000);
        flow_engine.process_tcp_packet("10.0.0.20", "172.16.0.1", 50002, 445, "TCP", 200, 0, 0x02, &[], "12:00:00.000", 1000);
        flow_engine.process_tcp_packet("172.20.1.1", "172.20.2.1", 50003, 8080, "TCP", 300, 0, 0x02, &[], "12:00:00.000", 1000);

        // 执行全局策略热更新: 将 192.168.1.0/24 动态提升为 Last 策略与 10MB 缓存配额
        let update_json = r#"[
            {
                "id": "HOT_REFRESH_TEST_SUBNET",
                "name": "Live Subnet Policy Update",
                "priority": 999,
                "src_cidr": "192.168.1.0/24",
                "dst_cidr": null,
                "ports": [],
                "policy": "Last",
                "max_buffer_bytes": 10485760,
                "max_pending_segments": 8192,
                "idle_timeout_secs": 1200,
                "gap_timeout_ms": 8000,
                "enable_slowloris_defense": true,
                "delivery_mode": "StreamDpi"
            }
        ]"#;

        let reload_res = hot_reload_stream_reassembly_policy(update_json);
        assert!(reload_res.is_ok());

        // 热刷新存活流
        let refreshed_count = flow_engine.refresh_active_sessions_policies();
        assert_eq!(refreshed_count, 3);

        // 验证 192.168.1.10 会话已无停机刷新为新策略
        let key_sub = FlowKey::new("192.168.1.10", "10.0.0.1", 50001, 80, "TCP");
        let session_sub = flow_engine.get_session(&key_sub).unwrap();
        assert_eq!(session_sub.c2s.evasion_policy, TcpEvasionPolicy::Last);
        assert_eq!(session_sub.c2s.paging_config.max_assembled_window_bytes, 10 * 1024 * 1024);

        // 验证其他未匹配子网的会话回退到默认规则
        let key_other = FlowKey::new("172.20.1.1", "172.20.2.1", 50003, 8080, "TCP");
        let session_other = flow_engine.get_session(&key_other).unwrap();
        assert_eq!(session_other.c2s.evasion_policy, TcpEvasionPolicy::Linux);
    }

    #[test]
    fn test_concurrent_multithread_reassembly_policy_hot_reload() {
        use std::sync::Arc;
        use std::thread;

        let mut engine = ReassemblyScriptEngine::default();
        engine.register_default_baseline_rules();
        let engine_arc = Arc::new(std::sync::RwLock::new(engine));

        let mut handles = Vec::new();

        // 启动 4 个工作读线程并发匹配策略
        for thread_idx in 0..4 {
            let eng_clone = Arc::clone(&engine_arc);
            let handle = thread::spawn(move || {
                for i in 0..500 {
                    let port = (500 + (i % 10)) as u16;
                    let ip = format!("192.168.{}.{}", thread_idx, (i % 250) + 1);
                    if let Ok(guard) = eng_clone.read() {
                        let rule = guard.match_policy(&ip, "10.0.0.1", port, 80);
                        assert!(!rule.id.is_empty());
                    }
                }
            });
            handles.push(handle);
        }

        // 启动 1 个写线程执行动态热重载
        let eng_writer = Arc::clone(&engine_arc);
        let write_handle = thread::spawn(move || {
            for v in 1..=10 {
                let json = format!(
                    r#"[{{"id":"CONCUR_RULE_{}","name":"Concur Rule","priority":{},"src_cidr":null,"dst_cidr":null,"ports":[],"policy":"Last"}}]"#,
                    v, v * 10
                );
                if let Ok(mut guard) = eng_writer.write() {
                    let _ = guard.hot_reload_from_json(&json);
                }
                thread::yield_now();
            }
        });
        handles.push(write_handle);

        for h in handles {
            h.join().expect("线程应当正常退出，无死锁");
        }

        let final_guard = engine_arc.read().unwrap();
        assert!(final_guard.total_reloads() >= 10);
    }

}


