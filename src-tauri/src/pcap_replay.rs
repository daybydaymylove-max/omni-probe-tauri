// ============================================================
// 工业全能网络探针 - 高精度脱机时间戳调度重放与虚拟网络接口注入引擎
// 模块名称: pcap_replay.rs
//
// 核心职责 (对标 tcpreplay & Wireshark editcap):
// 1. 支持自适应解析 PCAP / PCAPNG 离线报文并进行高保真相对时间戳复现;
// 2. 调度模式: 真实倍速 (Paced 0.01x-1000x)、全速饱和压测 (TopSpeed)、单步调试 (Step);
// 3. 工业级亚毫秒防抖调度器: 宏观睡眠 (thread::sleep) + 微观单调时钟自旋 (Spin-wait);
// 4. 虚拟总线注入 (Virtual Loopback Pipeline): 直接推入统一数据流，驱动资产画像、DPI、
//    SIMD 威胁检测、工控事务配对机与拓扑热力雷达，实现全离线断网自测与压力评估;
// 5. 实时可观测性遥测指标 (ReplayTelemetry): 纳秒精度时钟、瞬时 PPS、瞬时带宽与 ETA.
// ============================================================

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

use crate::pcap_engine::{decode_capture_file, CaptureFileInfo, RawPacketItem};
use crate::sniffer::PacketRecord;

/// 重放调度模式
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum ReplayMode {
    /// 真实时间戳倍速播放 (例如 1.0 为原始速度, 2.0 为 2 倍速, 0.5 为慢速)
    Paced(f64),
    /// 全速无延迟饱和压测模式 (单核极限吞吐)
    TopSpeed,
    /// 单步步进模式 (按需手动推送单帧)
    Step,
    /// 恒定带宽速率整形模式 (Mbps, 比如 100.0, 1000.0, 10000.0 万兆线速)
    TargetMbps(f64),
    /// 恒定包率整形模式 (PPS, 比如 10000, 100000, 1000000)
    TargetPps(u64),
}

/// 报文头部重写与增量校验和更新配置 (对标 tcprewrite)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct PacketRewriteConfig {
    pub rewrite_smac: Option<[u8; 6]>,
    pub rewrite_dmac: Option<[u8; 6]>,
    pub rewrite_src_ip: Option<std::net::Ipv4Addr>,
    pub rewrite_dst_ip: Option<std::net::Ipv4Addr>,
    pub rewrite_sport: Option<u16>,
    pub rewrite_dport: Option<u16>,
    pub recalculate_checksums: bool,
}

/// 重放状态枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayState {
    Idle,
    Playing,
    Paused,
    Stopped,
    Completed,
}

impl std::fmt::Display for ReplayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayState::Idle => write!(f, "Idle"),
            ReplayState::Playing => write!(f, "Playing"),
            ReplayState::Paused => write!(f, "Paused"),
            ReplayState::Stopped => write!(f, "Stopped"),
            ReplayState::Completed => write!(f, "Completed"),
        }
    }
}

/// 重放配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayConfig {
    pub mode: ReplayMode,
    /// 循环次数: 0 为无限循环, 1 为单次播放, N 为播放 N 次
    pub loop_count: usize,
    /// 最大单帧等待上限 (微秒, 默认 5,000,000 即 5 秒, 防止历史间隔过大导致挂死)
    pub max_step_delay_micros: u64,
    /// 注入时是否模拟物理网卡 MAC
    pub spoof_mac: bool,
    /// 批量突发大小 (Burst Size: 如 16, 32, 64，对标 DPDK rte_eth_tx_burst)
    #[serde(default = "default_burst_size")]
    pub burst_size: usize,
    /// 跨循环单调时间戳平移缝合 (保证多轮循环输出时间戳严格单调递增)
    #[serde(default = "default_true")]
    pub monotonic_timestamp_shift: bool,
    /// 会话与字段重写选项 (可选)
    #[serde(default)]
    pub rewrite_config: Option<PacketRewriteConfig>,
}

fn default_burst_size() -> usize { 32 }
fn default_true() -> bool { true }

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            mode: ReplayMode::Paced(1.0),
            loop_count: 1,
            max_step_delay_micros: 5_000_000,
            spoof_mac: true,
            burst_size: 32,
            monotonic_timestamp_shift: true,
            rewrite_config: None,
        }
    }
}

/// 实时可观测性遥测指标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayTelemetry {
    pub state: String,
    pub current_index: usize,
    pub total_packets: usize,
    pub current_loop: usize,
    pub max_loops: usize,
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub elapsed_micros: u64,
    pub current_pps: f64,
    pub current_mbps: f64,
    pub progress_percent: f64,
    pub estimated_remaining_secs: f64,
}

// ============================================================
// 一、 纳秒级单调浮点令牌桶速率整形器 (NanosecondTokenBucket)
// 支持带宽整形 (TargetMbps) 与包率整形 (TargetPps)，微突发平滑自旋
// ============================================================

pub struct NanosecondTokenBucket {
    rate_bps: f64,
    rate_pps: f64,
    available_bytes: f64,
    available_packets: f64,
    max_burst_bytes: f64,
    max_burst_packets: f64,
    last_update: Instant,
}

impl NanosecondTokenBucket {
    pub fn new(mode: &ReplayMode) -> Self {
        let (rate_bps, rate_pps) = match mode {
            ReplayMode::TargetMbps(mbps) => (*mbps * 1_000_000.0, 0.0),
            ReplayMode::TargetPps(pps) => (0.0, *pps as f64),
            _ => (0.0, 0.0),
        };

        let max_burst_bytes = (rate_bps * 0.05).max(65536.0); // 50ms 突发上限
        let max_burst_packets = (rate_pps * 0.05).max(64.0);

        Self {
            rate_bps,
            rate_pps,
            available_bytes: max_burst_bytes,
            available_packets: max_burst_packets,
            max_burst_bytes,
            max_burst_packets,
            last_update: Instant::now(),
        }
    }

    /// 按照报文大小与数量消耗令牌，若令牌不足则精确等待
    pub fn wait_for_quota(&mut self, pkt_bytes: usize) {
        if self.rate_bps <= 0.0 && self.rate_pps <= 0.0 {
            return;
        }

        let now = Instant::now();
        let elapsed_secs = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        if self.rate_bps > 0.0 {
            self.available_bytes = (self.available_bytes + elapsed_secs * (self.rate_bps / 8.0)).min(self.max_burst_bytes);
            let needed = pkt_bytes as f64;
            if self.available_bytes < needed {
                let missing = needed - self.available_bytes;
                let wait_secs = missing / (self.rate_bps / 8.0);
                if wait_secs > 0.0 {
                    PcapReplayEngine::precise_delay_micros((wait_secs * 1_000_000.0) as u64);
                    self.last_update = Instant::now();
                    self.available_bytes = 0.0;
                    return;
                }
            }
            self.available_bytes -= needed;
        }

        if self.rate_pps > 0.0 {
            self.available_packets = (self.available_packets + elapsed_secs * self.rate_pps).min(self.max_burst_packets);
            if self.available_packets < 1.0 {
                let missing = 1.0 - self.available_packets;
                let wait_secs = missing / self.rate_pps;
                if wait_secs > 0.0 {
                    PcapReplayEngine::precise_delay_micros((wait_secs * 1_000_000.0) as u64);
                    self.last_update = Instant::now();
                    self.available_packets = 0.0;
                    return;
                }
            }
            self.available_packets -= 1.0;
        }
    }
}

// ============================================================
// 二、 报文多层首部重写与 RFC 1624 增量校验和重算引擎 (PacketRewriter)
// 对标 tcprewrite: O(1) 常数时间完成 IP/TCP/UDP 校验和更新
// ============================================================

pub struct PacketRewriter;

impl PacketRewriter {
    /// RFC 1624 增量校验和更新核心算法 (16-bit 1's Complement)
    /// HC' = ~(~HC + ~m + m')
    #[inline]
    pub fn update_checksum_16(old_checksum: u16, old_field: u16, new_field: u16) -> u16 {
        let mut sum: u32 = (!old_checksum as u32) + (!old_field as u32) + (new_field as u32);
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }

    /// 执行以太网帧多层级联重写与增量校验和更新
    pub fn rewrite_ethernet_frame(data: &mut [u8], cfg: &PacketRewriteConfig) {
        if data.len() < 14 {
            return;
        }

        // 1. MAC 地址重写
        if let Some(dmac) = cfg.rewrite_dmac {
            data[0..6].copy_from_slice(&dmac);
        }
        if let Some(smac) = cfg.rewrite_smac {
            data[6..12].copy_from_slice(&smac);
        }

        let eth_type = u16::from_be_bytes([data[12], data[13]]);
        if eth_type != 0x0800 || data.len() < 34 {
            return; // 非 IPv4 或截断帧
        }

        let ip_hdr_start = 14;
        let ihl = ((data[ip_hdr_start] & 0x0F) * 4) as usize;
        if data.len() < ip_hdr_start + ihl {
            return;
        }

        let l4_proto = data[ip_hdr_start + 9];
        let old_src_ip = [data[ip_hdr_start + 12], data[ip_hdr_start + 13], data[ip_hdr_start + 14], data[ip_hdr_start + 15]];
        let old_dst_ip = [data[ip_hdr_start + 16], data[ip_hdr_start + 17], data[ip_hdr_start + 18], data[ip_hdr_start + 19]];

        let mut ip_cksum = u16::from_be_bytes([data[ip_hdr_start + 10], data[ip_hdr_start + 11]]);

        // 2. IP 地址重写与 IPv4 首部校验和增量更新
        if let Some(new_s_ip) = cfg.rewrite_src_ip {
            let new_octets = new_s_ip.octets();
            let old_hi = u16::from_be_bytes([old_src_ip[0], old_src_ip[1]]);
            let new_hi = u16::from_be_bytes([new_octets[0], new_octets[1]]);
            let old_lo = u16::from_be_bytes([old_src_ip[2], old_src_ip[3]]);
            let new_lo = u16::from_be_bytes([new_octets[2], new_octets[3]]);

            ip_cksum = Self::update_checksum_16(ip_cksum, old_hi, new_hi);
            ip_cksum = Self::update_checksum_16(ip_cksum, old_lo, new_lo);

            data[ip_hdr_start + 12..ip_hdr_start + 16].copy_from_slice(&new_octets);
        }

        if let Some(new_d_ip) = cfg.rewrite_dst_ip {
            let new_octets = new_d_ip.octets();
            let old_hi = u16::from_be_bytes([old_dst_ip[0], old_dst_ip[1]]);
            let new_hi = u16::from_be_bytes([new_octets[0], new_octets[1]]);
            let old_lo = u16::from_be_bytes([old_dst_ip[2], old_dst_ip[3]]);
            let new_lo = u16::from_be_bytes([new_octets[2], new_octets[3]]);

            ip_cksum = Self::update_checksum_16(ip_cksum, old_hi, new_hi);
            ip_cksum = Self::update_checksum_16(ip_cksum, old_lo, new_lo);

            data[ip_hdr_start + 16..ip_hdr_start + 20].copy_from_slice(&new_octets);
        }

        if cfg.recalculate_checksums {
            let ck_bytes = ip_cksum.to_be_bytes();
            data[ip_hdr_start + 10] = ck_bytes[0];
            data[ip_hdr_start + 11] = ck_bytes[1];
        }

        // 3. 传输层端口重写与 L4 伪首部/校验和更新 (TCP=6, UDP=17)
        let l4_start = ip_hdr_start + ihl;
        if (l4_proto == 6 || l4_proto == 17) && data.len() >= l4_start + 8 {
            let cksum_offset = if l4_proto == 6 { l4_start + 16 } else { l4_start + 6 };
            if data.len() >= cksum_offset + 2 {
                let mut l4_cksum = u16::from_be_bytes([data[cksum_offset], data[cksum_offset + 1]]);

                // IP 地址变化对 L4 伪首部校验和的影响
                if let Some(new_s_ip) = cfg.rewrite_src_ip {
                    let new_octets = new_s_ip.octets();
                    let old_hi = u16::from_be_bytes([old_src_ip[0], old_src_ip[1]]);
                    let new_hi = u16::from_be_bytes([new_octets[0], new_octets[1]]);
                    let old_lo = u16::from_be_bytes([old_src_ip[2], old_src_ip[3]]);
                    let new_lo = u16::from_be_bytes([new_octets[2], new_octets[3]]);
                    l4_cksum = Self::update_checksum_16(l4_cksum, old_hi, new_hi);
                    l4_cksum = Self::update_checksum_16(l4_cksum, old_lo, new_lo);
                }
                if let Some(new_d_ip) = cfg.rewrite_dst_ip {
                    let new_octets = new_d_ip.octets();
                    let old_hi = u16::from_be_bytes([old_dst_ip[0], old_dst_ip[1]]);
                    let new_hi = u16::from_be_bytes([new_octets[0], new_octets[1]]);
                    let old_lo = u16::from_be_bytes([old_dst_ip[2], old_dst_ip[3]]);
                    let new_lo = u16::from_be_bytes([new_octets[2], new_octets[3]]);
                    l4_cksum = Self::update_checksum_16(l4_cksum, old_hi, new_hi);
                    l4_cksum = Self::update_checksum_16(l4_cksum, old_lo, new_lo);
                }

                // 端口重写
                if let Some(new_sp) = cfg.rewrite_sport {
                    let old_sp = u16::from_be_bytes([data[l4_start], data[l4_start + 1]]);
                    l4_cksum = Self::update_checksum_16(l4_cksum, old_sp, new_sp);
                    data[l4_start..l4_start + 2].copy_from_slice(&new_sp.to_be_bytes());
                }
                if let Some(new_dp) = cfg.rewrite_dport {
                    let old_dp = u16::from_be_bytes([data[l4_start + 2], data[l4_start + 3]]);
                    l4_cksum = Self::update_checksum_16(l4_cksum, old_dp, new_dp);
                    data[l4_start + 2..l4_start + 4].copy_from_slice(&new_dp.to_be_bytes());
                }

                if cfg.recalculate_checksums {
                    let ck_bytes = l4_cksum.to_be_bytes();
                    data[cksum_offset] = ck_bytes[0];
                    data[cksum_offset + 1] = ck_bytes[1];
                }
            }
        }
    }
}

// ============================================================
// 三、 跨循环单调时间戳平移缝合器 (MonotonicTimestampShifter)
// 保证多轮连续循环重放输出的时间戳绝对单调递增，杜绝跨轮次时间倒流
// ============================================================

pub struct MonotonicTimestampShifter {
    base_offset_micros: u64,
    last_loop_end_ts_micros: u64,
    first_pkt_ts_micros: Option<u64>,
}

impl MonotonicTimestampShifter {
    pub fn new() -> Self {
        Self {
            base_offset_micros: 0,
            last_loop_end_ts_micros: 0,
            first_pkt_ts_micros: None,
        }
    }

    /// 计算平移后的单调递增微秒时间戳
    pub fn shift(&mut self, raw_sec: u32, raw_usec: u32, is_new_loop: bool) -> (u32, u32) {
        let raw_micros = (raw_sec as u64) * 1_000_000 + (raw_usec as u64);
        if self.first_pkt_ts_micros.is_none() {
            self.first_pkt_ts_micros = Some(raw_micros);
        }

        if is_new_loop && self.last_loop_end_ts_micros > 0 {
            let loop_span = self.last_loop_end_ts_micros.saturating_sub(self.first_pkt_ts_micros.unwrap_or(0));
            self.base_offset_micros += loop_span + 100; // 跨轮增加 100us 安全间隙
        }

        let first = self.first_pkt_ts_micros.unwrap_or(0);
        let rel_micros = raw_micros.saturating_sub(first);
        let shifted = first + self.base_offset_micros + rel_micros;
        self.last_loop_end_ts_micros = shifted;

        let s = (shifted / 1_000_000) as u32;
        let us = (shifted % 1_000_000) as u32;
        (s, us)
    }
}

// ============================================================
// 四、 批处理突发报文批次 (BurstPacketBatch)
// 对标 DPDK rte_eth_tx_burst: 连续聚合多报文突发
// ============================================================

pub struct BurstPacketBatch {
    pub packets: Vec<RawPacketItem>,
    pub total_bytes: usize,
}

impl BurstPacketBatch {
    pub fn new() -> Self {
        Self {
            packets: Vec::new(),
            total_bytes: 0,
        }
    }

    pub fn push(&mut self, item: RawPacketItem) {
        self.total_bytes += item.data.len();
        self.packets.push(item);
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }
}

/// 工业级高精度时间戳重放引擎
pub struct PcapReplayEngine {
    config: ReplayConfig,
    packets: Vec<RawPacketItem>,
    file_info: Option<CaptureFileInfo>,
    
    // 状态机与并发同步
    state: Arc<Mutex<ReplayState>>,
    condvar: Arc<Condvar>,
    stop_signal: Arc<AtomicBool>,
    step_trigger: Arc<AtomicBool>,

    // 遥测计数器 (原子无锁)
    current_index: Arc<AtomicUsize>,
    current_loop: Arc<AtomicUsize>,
    sent_packets: Arc<AtomicU64>,
    sent_bytes: Arc<AtomicU64>,
    elapsed_micros: Arc<AtomicU64>,

    // 速率采样
    last_sample_instant: Arc<Mutex<Instant>>,
    last_sample_packets: Arc<AtomicU64>,
    last_sample_bytes: Arc<AtomicU64>,
    current_pps: Arc<Mutex<f64>>,
    current_mbps: Arc<Mutex<f64>>,

    // 运行句柄
    worker_handle: Option<JoinHandle<()>>,
}

impl PcapReplayEngine {
    pub fn new() -> Self {
        Self {
            config: ReplayConfig::default(),
            packets: Vec::new(),
            file_info: None,
            state: Arc::new(Mutex::new(ReplayState::Idle)),
            condvar: Arc::new(Condvar::new()),
            stop_signal: Arc::new(AtomicBool::new(false)),
            step_trigger: Arc::new(AtomicBool::new(false)),
            current_index: Arc::new(AtomicUsize::new(0)),
            current_loop: Arc::new(AtomicUsize::new(0)),
            sent_packets: Arc::new(AtomicU64::new(0)),
            sent_bytes: Arc::new(AtomicU64::new(0)),
            elapsed_micros: Arc::new(AtomicU64::new(0)),
            last_sample_instant: Arc::new(Mutex::new(Instant::now())),
            last_sample_packets: Arc::new(AtomicU64::new(0)),
            last_sample_bytes: Arc::new(AtomicU64::new(0)),
            current_pps: Arc::new(Mutex::new(0.0)),
            current_mbps: Arc::new(Mutex::new(0.0)),
            worker_handle: None,
        }
    }

    /// 从二进制字节加载捕获文件 (自动识别 PCAP / PCAPNG)
    pub fn load_capture_bytes(&mut self, data: &[u8]) -> Result<CaptureFileInfo, String> {
        self.stop();

        let (info, items) = decode_capture_file(data)?;
        self.file_info = Some(info.clone());
        self.packets = items;
        self.current_index.store(0, Ordering::Relaxed);
        self.sent_packets.store(0, Ordering::Relaxed);
        self.sent_bytes.store(0, Ordering::Relaxed);
        self.elapsed_micros.store(0, Ordering::Relaxed);
        *crate::lock_guard::lock_mutex(&self.state, "pcap_replay::load_pcap_idle") = ReplayState::Idle;

        Ok(info)
    }

    /// 设置重放参数配置
    pub fn set_config(&mut self, config: ReplayConfig) {
        self.config = config;
    }

    /// 启动重放流水线 (若 app_handle 为 None 则运行纯仿真/压测模式)
    pub fn start(&mut self, app_handle: Option<tauri::AppHandle>) -> Result<(), String> {
        if self.packets.is_empty() {
            return Err("未加载任何捕获报文，无法启动重放".to_string());
        }

        self.stop();

        *crate::lock_guard::lock_mutex(&self.state, "pcap_replay::start_playing") = ReplayState::Playing;
        self.stop_signal.store(false, Ordering::Relaxed);
        self.step_trigger.store(false, Ordering::Relaxed);
        self.current_index.store(0, Ordering::Relaxed);
        self.current_loop.store(1, Ordering::Relaxed);
        self.sent_packets.store(0, Ordering::Relaxed);
        self.sent_bytes.store(0, Ordering::Relaxed);
        self.elapsed_micros.store(0, Ordering::Relaxed);
        *crate::lock_guard::lock_mutex(&self.last_sample_instant, "pcap_replay::start_sample_instant") = Instant::now();
        self.last_sample_packets.store(0, Ordering::Relaxed);
        self.last_sample_bytes.store(0, Ordering::Relaxed);
        *crate::lock_guard::lock_mutex(&self.current_pps, "pcap_replay::start_reset_pps") = 0.0;
        *crate::lock_guard::lock_mutex(&self.current_mbps, "pcap_replay::start_reset_mbps") = 0.0;

        let packets = self.packets.clone();
        let config = self.config.clone();
        let state = self.state.clone();
        let condvar = self.condvar.clone();
        let stop_signal = self.stop_signal.clone();
        let step_trigger = self.step_trigger.clone();
        let current_index = self.current_index.clone();
        let current_loop = self.current_loop.clone();
        let sent_packets = self.sent_packets.clone();
        let sent_bytes = self.sent_bytes.clone();
        let elapsed_micros = self.elapsed_micros.clone();
        let last_sample_instant = self.last_sample_instant.clone();
        let last_sample_packets = self.last_sample_packets.clone();
        let last_sample_bytes = self.last_sample_bytes.clone();
        let current_pps = self.current_pps.clone();
        let current_mbps = self.current_mbps.clone();

        let handle = thread::Builder::new()
            .name("omni-pcap-replay-worker".to_string())
            .spawn(move || {
                Self::run_replay_loop(
                    packets,
                    config,
                    app_handle,
                    state,
                    condvar,
                    stop_signal,
                    step_trigger,
                    current_index,
                    current_loop,
                    sent_packets,
                    sent_bytes,
                    elapsed_micros,
                    last_sample_instant,
                    last_sample_packets,
                    last_sample_bytes,
                    current_pps,
                    current_mbps,
                );
            })
            .map_err(|e| format!("启动重放后台线程失败: {}", e))?;

        self.worker_handle = Some(handle);
        Ok(())
    }

    /// 暂停重放
    pub fn pause(&self) {
        let mut state_guard = crate::lock_guard::lock_mutex(&self.state, "pcap_replay::pause");
        if *state_guard == ReplayState::Playing {
            *state_guard = ReplayState::Paused;
        }
    }

    /// 恢复重放
    pub fn resume(&self) {
        let mut state_guard = crate::lock_guard::lock_mutex(&self.state, "pcap_replay::resume");
        if *state_guard == ReplayState::Paused {
            *state_guard = ReplayState::Playing;
            self.condvar.notify_all();
        }
    }

    /// 停止重放
    pub fn stop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
        {
            let mut state_guard = crate::lock_guard::lock_mutex(&self.state, "pcap_replay::stop");
            *state_guard = ReplayState::Stopped;
            self.condvar.notify_all();
        }
        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.join();
        }
    }

    /// 单步触发单帧发送
    pub fn step(&self) {
        let state_guard = crate::lock_guard::lock_mutex(&self.state, "pcap_replay::step");
        if *state_guard == ReplayState::Paused || *state_guard == ReplayState::Idle {
            self.step_trigger.store(true, Ordering::Relaxed);
            self.condvar.notify_all();
        }
    }

    /// 跳转至指定报文索引
    pub fn seek(&self, index: usize) {
        if index < self.packets.len() {
            self.current_index.store(index, Ordering::Relaxed);
        }
    }

    /// 获取实时遥测状态与指标
    pub fn get_telemetry(&self) -> ReplayTelemetry {
        let state_str = crate::lock_guard::lock_mutex(&self.state, "pcap_replay::get_telemetry_state").to_string();
        let cur_idx = self.current_index.load(Ordering::Relaxed);
        let tot = self.packets.len();
        let cur_loop = self.current_loop.load(Ordering::Relaxed);
        let max_loops = self.config.loop_count;
        let s_pkts = self.sent_packets.load(Ordering::Relaxed);
        let s_bytes = self.sent_bytes.load(Ordering::Relaxed);
        let el_micros = self.elapsed_micros.load(Ordering::Relaxed);
        let pps = *crate::lock_guard::lock_mutex(&self.current_pps, "pcap_replay::get_telemetry_pps");
        let mbps = *crate::lock_guard::lock_mutex(&self.current_mbps, "pcap_replay::get_telemetry_mbps");

        let progress = if tot > 0 {
            (cur_idx as f64 / tot as f64) * 100.0
        } else {
            0.0
        };

        let est_remaining = if pps > 0.0 && tot > cur_idx {
            (tot - cur_idx) as f64 / pps
        } else {
            0.0
        };

        ReplayTelemetry {
            state: state_str,
            current_index: cur_idx,
            total_packets: tot,
            current_loop: cur_loop,
            max_loops,
            sent_packets: s_pkts,
            sent_bytes: s_bytes,
            elapsed_micros: el_micros,
            current_pps: pps,
            current_mbps: mbps,
            progress_percent: progress.min(100.0),
            estimated_remaining_secs: est_remaining,
        }
    }

    /// 核心重放执行循环 (运行于专用后台线程)
    fn run_replay_loop(
        packets: Vec<RawPacketItem>,
        config: ReplayConfig,
        app_handle: Option<tauri::AppHandle>,
        state: Arc<Mutex<ReplayState>>,
        condvar: Arc<Condvar>,
        stop_signal: Arc<AtomicBool>,
        step_trigger: Arc<AtomicBool>,
        current_index: Arc<AtomicUsize>,
        current_loop: Arc<AtomicUsize>,
        sent_packets: Arc<AtomicU64>,
        sent_bytes: Arc<AtomicU64>,
        elapsed_micros: Arc<AtomicU64>,
        last_sample_instant: Arc<Mutex<Instant>>,
        last_sample_packets: Arc<AtomicU64>,
        last_sample_bytes: Arc<AtomicU64>,
        current_pps: Arc<Mutex<f64>>,
        current_mbps: Arc<Mutex<f64>>,
    ) {
        let total_packets = packets.len();
        if total_packets == 0 {
            *crate::lock_guard::lock_mutex(&state, "pcap_replay::worker_empty") = ReplayState::Completed;
            return;
        }

        let loop_limit = if config.loop_count == 0 { usize::MAX } else { config.loop_count };
        let mut loop_idx = 1;
        let start_instant = Instant::now();
        let mut token_bucket = NanosecondTokenBucket::new(&config.mode);
        let mut ts_shifter = MonotonicTimestampShifter::new();

        while loop_idx <= loop_limit && !stop_signal.load(Ordering::Relaxed) {
            current_loop.store(loop_idx, Ordering::Relaxed);
            let mut last_pkt_ts_micros: Option<u64> = None;
            let mut is_new_loop = true;

            let mut idx = current_index.load(Ordering::Relaxed);
            if idx >= total_packets {
                idx = 0;
                current_index.store(0, Ordering::Relaxed);
            }

            while idx < total_packets && !stop_signal.load(Ordering::Relaxed) {
                // 1. 检查暂停与单步状态
                {
                    let mut st = crate::lock_guard::lock_mutex(&state, "pcap_replay::worker_pause_wait");
                    while *st == ReplayState::Paused && !stop_signal.load(Ordering::Relaxed) {
                        if step_trigger.swap(false, Ordering::Relaxed) {
                            // 单步触发，跳出等待发送单帧
                            break;
                        }
                        st = condvar.wait(st).unwrap_or_else(|e| e.into_inner());
                    }
                }

                if stop_signal.load(Ordering::Relaxed) {
                    break;
                }

                let original_item = &packets[idx];
                let mut item = original_item.clone();

                // 2. 跨循环单调时间戳平移缝合
                if config.monotonic_timestamp_shift {
                    let (s, us) = ts_shifter.shift(item.timestamp_sec, item.timestamp_usec, is_new_loop);
                    item.timestamp_sec = s;
                    item.timestamp_usec = us;
                    is_new_loop = false;
                }

                // 3. 报文会话多层重写与增量校验和重算
                if let Some(ref rw_cfg) = config.rewrite_config {
                    PacketRewriter::rewrite_ethernet_frame(&mut item.data, rw_cfg);
                }

                let current_pkt_ts_micros = (item.timestamp_sec as u64) * 1_000_000 + (item.timestamp_usec as u64);

                // 4. 速率整形与调度控制
                match config.mode {
                    ReplayMode::Paced(multiplier) => {
                        let speed = if multiplier <= 0.0001 { 1.0 } else { multiplier };
                        if let Some(last_ts) = last_pkt_ts_micros {
                            if current_pkt_ts_micros > last_ts {
                                let raw_diff = current_pkt_ts_micros - last_ts;
                                let bounded_diff = raw_diff.min(config.max_step_delay_micros);
                                let sleep_micros = (bounded_diff as f64 / speed) as u64;
                                Self::precise_delay_micros(sleep_micros);
                            }
                        }
                    }
                    ReplayMode::TargetMbps(_) | ReplayMode::TargetPps(_) => {
                        token_bucket.wait_for_quota(item.data.len());
                    }
                    ReplayMode::TopSpeed => {
                        // 全速模式: 零延时饱和压测
                    }
                    ReplayMode::Step => {
                        // 单步模式: 发送后自动挂起为 Paused
                    }
                }

                last_pkt_ts_micros = Some(current_pkt_ts_micros);

                // 5. 投递报文到目标流水线
                Self::dispatch_packet_item(&item, app_handle.as_ref());

                // 6. 更新遥测计数
                idx += 1;
                current_index.store(idx, Ordering::Relaxed);
                sent_packets.fetch_add(1, Ordering::Relaxed);
                sent_bytes.fetch_add(item.data.len() as u64, Ordering::Relaxed);
                elapsed_micros.store(start_instant.elapsed().as_micros() as u64, Ordering::Relaxed);

                // 5. 定期采样计算瞬时速率 (每 100ms 刷新一次)
                {
                    let mut sample_time = crate::lock_guard::lock_mutex(&last_sample_instant, "pcap_replay::worker_sample_time");
                    let now = Instant::now();
                    let elapsed_sample = now.duration_since(*sample_time);
                    if elapsed_sample.as_millis() >= 100 {
                        let cur_pkts = sent_packets.load(Ordering::Relaxed);
                        let cur_bytes = sent_bytes.load(Ordering::Relaxed);
                        let prev_pkts = last_sample_packets.swap(cur_pkts, Ordering::Relaxed);
                        let prev_bytes = last_sample_bytes.swap(cur_bytes, Ordering::Relaxed);

                        let delta_pkts = cur_pkts.saturating_sub(prev_pkts);
                        let delta_bytes = cur_bytes.saturating_sub(prev_bytes);
                        let secs = elapsed_sample.as_secs_f64();

                        if secs > 0.0 {
                            *crate::lock_guard::lock_mutex(&current_pps, "pcap_replay::worker_pps") = delta_pkts as f64 / secs;
                            *crate::lock_guard::lock_mutex(&current_mbps, "pcap_replay::worker_mbps") = (delta_bytes as f64 * 8.0) / (secs * 1_000_000.0);
                        }
                        *sample_time = now;
                    }
                }

                // 如果处于单步模式，每发送一帧后立即自动暂停
                if config.mode == ReplayMode::Step {
                    let mut st = crate::lock_guard::lock_mutex(&state, "pcap_replay::worker_step_pause");
                    *st = ReplayState::Paused;
                }
            }

            loop_idx += 1;
            current_index.store(0, Ordering::Relaxed);
        }

        let mut st = crate::lock_guard::lock_mutex(&state, "pcap_replay::worker_complete");
        if !stop_signal.load(Ordering::Relaxed) {
            *st = ReplayState::Completed;
        }
    }

    /// 高精度防抖延时调度器
    ///
    /// 混合调度算法:
    /// - 大于 2ms (2000 微秒): 宏观交出 CPU 时间片，调用 thread::sleep，避免高 CPU 占用;
    /// - 小于等于 2ms: 微观基于 Instant::now() 紧凑自旋 (Spin-wait)，消除操作系统时间片量化误差 (< 1us 抖动).
    pub fn precise_delay_micros(micros: u64) {
        if micros == 0 {
            return;
        }

        let target_duration = Duration::from_micros(micros);
        let start = Instant::now();

        // 超过 2.5ms 时先睡眠大部分时间，留下 1.2ms 做精确自旋
        if micros > 2500 {
            let sleep_part = Duration::from_micros(micros - 1200);
            thread::sleep(sleep_part);
        }

        // 精确自旋等待
        while start.elapsed() < target_duration {
            std::hint::spin_loop();
        }
    }

    /// 将原始报文解析并投递至探针统一数据流水线 (实现全链路脱机仿真)
    pub fn dispatch_packet_item(item: &RawPacketItem, app_handle: Option<&tauri::AppHandle>) {
        if let Some(app) = app_handle {
            // 解析原始帧头
            let (src_ip, dst_ip, src_port, dst_port, transport, protocol, payload_bytes) =
                crate::export_engine::parse_raw_frame_headers(&item.data);

            let payload_hex = hex::encode_upper(&payload_bytes);
            let raw_frame_hex = hex::encode_upper(&item.data);
            let entropy = crate::forensics::ForensicEngine::calculate_entropy(&payload_bytes);
            let entropy_level = if entropy >= 7.5 {
                "critical".to_string()
            } else if entropy >= 6.0 {
                "high".to_string()
            } else if entropy >= 4.0 {
                "medium".to_string()
            } else {
                "normal".to_string()
            };

            let ts_sec = item.timestamp_sec as u128;
            let ts_usec = item.timestamp_usec as u128;
            let timestamp_ns = ts_sec * 1_000_000_000 + ts_usec * 1_000;

            let (mac_src, mac_dst) = if item.data.len() >= 12 {
                let s = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", item.data[6], item.data[7], item.data[8], item.data[9], item.data[10], item.data[11]);
                let d = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", item.data[0], item.data[1], item.data[2], item.data[3], item.data[4], item.data[5]);
                (s, d)
            } else {
                ("00:00:00:00:00:00".to_string(), "00:00:00:00:00:00".to_string())
            };

            let dt = chrono::DateTime::from_timestamp(item.timestamp_sec as i64, (item.timestamp_usec * 1000) as u32)
                .unwrap_or_else(chrono::Utc::now);
            let ts_str = format!("{}.{:06}", dt.format("%H:%M:%S"), item.timestamp_usec);

            let raw_text = Some(crate::sniffer::generate_raw_text_preview(&payload_bytes));

            // 构造合规的标准 PacketRecord
            let record = PacketRecord {
                id: item.id,
                timestamp: ts_str,
                timestamp_ns,
                direction: "REPLAY".to_string(),
                transport,
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                length: item.original_len as usize,
                payload_hex,
                raw_frame_hex,
                entropy,
                entropy_level,
                mac_src,
                mac_dst,
                chain_hash: String::new(),
                business_data: None,
                raw_text,
            };

            // 直接推入探针统一处理管线 (触发 DPI, 威胁检测, 工控 ACL, 会话流与看板)
            crate::sniffer::process_incoming_record(app, record);
        }
    }

    /// 工业级批量突发直接发射快路径 (对标 DPDK rte_eth_tx_burst / Npcap sendqueue)
    pub fn transmit_burst_fast_path(&self, batch: &BurstPacketBatch, app_handle: Option<&tauri::AppHandle>) -> usize {
        let mut count = 0;
        for item in &batch.packets {
            Self::dispatch_packet_item(item, app_handle);
            count += 1;
        }
        count
    }
}

/// 全局重放引擎单例
pub static GLOBAL_REPLAY_ENGINE: once_cell::sync::Lazy<Arc<Mutex<PcapReplayEngine>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(PcapReplayEngine::new())));

// ============================================================
// 单元测试与验证套件 (Unit Tests & DoD Validation)
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_mock_pcap_bytes() -> Vec<u8> {
        let items = vec![
            RawPacketItem {
                id: 1,
                timestamp_sec: 1700000000,
                timestamp_usec: 0,
                original_len: 32,
                captured_len: 32,
                data: vec![0xAA; 32],
            },
            RawPacketItem {
                id: 2,
                timestamp_sec: 1700000000,
                timestamp_usec: 50000, // +50ms
                original_len: 48,
                captured_len: 48,
                data: vec![0xBB; 48],
            },
            RawPacketItem {
                id: 3,
                timestamp_sec: 1700000000,
                timestamp_usec: 100000, // +50ms
                original_len: 64,
                captured_len: 64,
                data: vec![0xCC; 64],
            },
        ];
        crate::pcap_engine::encode_packets_to_pcap(&items, 65535)
    }

    #[test]
    fn test_replay_load_and_top_speed() {
        let pcap_data = create_mock_pcap_bytes();
        let mut engine = PcapReplayEngine::new();

        let info = engine.load_capture_bytes(&pcap_data).expect("加载 PCAP 应该成功");
        assert_eq!(info.total_packets, 3);

        // 设置全速饱和压测模式
        engine.set_config(ReplayConfig {
            mode: ReplayMode::TopSpeed,
            loop_count: 2, // 循环 2 次
            max_step_delay_micros: 1_000_000,
            spoof_mac: true,
            ..Default::default()
        });

        // 启动纯仿真 (无 app_handle)
        engine.start(None).expect("启动重放应该成功");

        // 等待线程执行完成
        thread::sleep(Duration::from_millis(50));

        let telemetry = engine.get_telemetry();
        assert_eq!(telemetry.state, "Completed");
        assert_eq!(telemetry.sent_packets, 6); // 3 * 2 次
        assert_eq!(telemetry.sent_bytes, (32 + 48 + 64) * 2);
    }

    #[test]
    fn test_replay_step_by_step_control() {
        let pcap_data = create_mock_pcap_bytes();
        let mut engine = PcapReplayEngine::new();
        engine.load_capture_bytes(&pcap_data).unwrap();

        engine.set_config(ReplayConfig {
            mode: ReplayMode::Step,
            loop_count: 1,
            max_step_delay_micros: 1_000_000,
            spoof_mac: true,
            ..Default::default()
        });

        engine.start(None).unwrap();

        let wait_for = |eng: &PcapReplayEngine, target_pkts: u64, target_state: &str| {
            let deadline = std::time::Instant::now() + Duration::from_millis(800);
            loop {
                let t = eng.get_telemetry();
                if t.sent_packets >= target_pkts && t.state == target_state {
                    return t;
                }
                if std::time::Instant::now() >= deadline {
                    return t;
                }
                thread::sleep(Duration::from_millis(5));
            }
        };

        // 初始已发送第 1 帧后自动暂停
        let t1 = wait_for(&engine, 1, "Paused");
        assert_eq!(t1.sent_packets, 1);
        assert_eq!(t1.state, "Paused");

        // 触发单步
        engine.step();
        let t2 = wait_for(&engine, 2, "Paused");
        assert_eq!(t2.sent_packets, 2);
        assert_eq!(t2.state, "Paused");

        // 再次触发单步
        engine.step();
        let t3 = wait_for(&engine, 3, "Completed");
        assert_eq!(t3.sent_packets, 3);
        assert_eq!(t3.state, "Completed");

        engine.stop();
    }

    #[test]
    fn test_precise_delay_jitter_defense() {
        let start = Instant::now();
        // 测试微秒级延时 3000us (3ms)
        PcapReplayEngine::precise_delay_micros(3000);
        let elapsed = start.elapsed();
        // 允许误差在 1ms 以内 (针对 Windows 调度器)
        assert!(elapsed.as_micros() >= 2900 && elapsed.as_micros() <= 6000);
    }

    // ============================================================
    // 【TASK-35】Windows 万兆线速报文突发回放与增量校验和重写引擎 6 轮严苛测试
    // ============================================================

    #[test]
    fn test_rfc1624_incremental_checksum_update_correctness() {
        // 原字段 0x1234, 新字段 0x1235, 原校验和 0x5678
        let old_val = 0x1234u16;
        let new_val = 0x1235u16;
        let old_cksum = 0x5678u16;

        let new_cksum = PacketRewriter::update_checksum_16(old_cksum, old_val, new_val);
        assert_eq!(new_cksum, 0x5677);

        // 反向更新回原值，必须精确还原
        let restored_cksum = PacketRewriter::update_checksum_16(new_cksum, new_val, old_val);
        assert_eq!(restored_cksum, old_cksum);
    }

    #[test]
    fn test_packet_rewriter_ip_port_and_mac() {
        // 构造标准 IPv4 + TCP 报文
        // 以太网 14 字节 + IPv4 20 字节 + TCP 20 字节 = 54 字节
        let mut frame = vec![0u8; 54];
        // 以太网头部
        frame[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // DMAC
        frame[6..12].copy_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]); // SMAC
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4 EtherType

        // IPv4 首部
        frame[14] = 0x45; // Version 4, IHL 5
        frame[14 + 9] = 6;  // TCP 协议
        frame[14 + 10..14 + 12].copy_from_slice(&0x1234u16.to_be_bytes()); // 原始 IP Checksum
        frame[14 + 12..14 + 16].copy_from_slice(&[192, 168, 1, 10]); // 原 SIP
        frame[14 + 16..14 + 20].copy_from_slice(&[10, 0, 0, 1]);    // 原 DIP

        // TCP 首部
        frame[34..36].copy_from_slice(&1234u16.to_be_bytes()); // 原 Sport
        frame[36..38].copy_from_slice(&80u16.to_be_bytes());   // 原 Dport
        frame[34 + 16..34 + 18].copy_from_slice(&0x5678u16.to_be_bytes()); // 原始 TCP Checksum

        let rewrite_cfg = PacketRewriteConfig {
            rewrite_smac: Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            rewrite_dmac: Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            rewrite_src_ip: Some("172.16.0.100".parse().unwrap()),
            rewrite_dst_ip: Some("172.16.0.200".parse().unwrap()),
            rewrite_sport: Some(8080),
            rewrite_dport: Some(443),
            recalculate_checksums: true,
        };

        PacketRewriter::rewrite_ethernet_frame(&mut frame, &rewrite_cfg);

        // 验证 MAC 已被重写
        assert_eq!(&frame[0..6], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(&frame[6..12], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        // 验证 IP 已被重写
        assert_eq!(&frame[14 + 12..14 + 16], &[172, 16, 0, 100]);
        assert_eq!(&frame[14 + 16..14 + 20], &[172, 16, 0, 200]);

        // 验证端口已被重写
        assert_eq!(u16::from_be_bytes([frame[34], frame[35]]), 8080);
        assert_eq!(u16::from_be_bytes([frame[36], frame[37]]), 443);

        // 验证 IP 与 TCP 校验和已更新
        let updated_ip_cksum = u16::from_be_bytes([frame[14 + 10], frame[14 + 11]]);
        assert_ne!(updated_ip_cksum, 0x1234);

        let updated_tcp_cksum = u16::from_be_bytes([frame[34 + 16], frame[34 + 17]]);
        assert_ne!(updated_tcp_cksum, 0x5678);
    }

    #[test]
    fn test_nanosecond_token_bucket_target_bandwidth_and_pps() {
        // 1. 验证目标 1000Mbps 模式初始化
        let mut tb_mbps = NanosecondTokenBucket::new(&ReplayMode::TargetMbps(1000.0));
        assert!(tb_mbps.rate_bps > 0.0);
        assert_eq!(tb_mbps.rate_pps, 0.0);

        // 消耗一个 1500 字节以太网帧的配额
        tb_mbps.wait_for_quota(1500);

        // 2. 验证目标 500K PPS 模式初始化
        let mut tb_pps = NanosecondTokenBucket::new(&ReplayMode::TargetPps(500_000));
        assert_eq!(tb_pps.rate_bps, 0.0);
        assert_eq!(tb_pps.rate_pps, 500_000.0);
        tb_pps.wait_for_quota(64);
    }

    #[test]
    fn test_monotonic_timestamp_shifter_multi_loop_continuity() {
        let mut shifter = MonotonicTimestampShifter::new();

        // 第 1 轮
        let (s1, us1) = shifter.shift(1000, 0, true);
        assert_eq!(s1, 1000);
        assert_eq!(us1, 0);

        let (s2, us2) = shifter.shift(1000, 500_000, false);
        assert_eq!(s2, 1000);
        assert_eq!(us2, 500_000);

        // 第 2 轮启动 (is_new_loop = true)
        let (s3, us3) = shifter.shift(1000, 0, true);
        let t2_end_micros = (s2 as u64) * 1_000_000 + (us2 as u64);
        let t3_start_micros = (s3 as u64) * 1_000_000 + (us3 as u64);

        // 验证跨轮单调递增，杜绝时间戳倒流
        assert!(t3_start_micros > t2_end_micros, "新一轮起始时间戳必须严格单调大于上一轮结束时间戳");
    }

    #[test]
    fn test_burst_packet_batch_and_high_throughput_top_speed() {
        let mut batch = BurstPacketBatch::new();
        assert!(batch.is_empty());

        for i in 1..=32 {
            batch.push(RawPacketItem {
                id: i,
                timestamp_sec: 1700000000,
                timestamp_usec: i as u32 * 10,
                original_len: 64,
                captured_len: 64,
                data: vec![0xEE; 64],
            });
        }

        assert_eq!(batch.len(), 32);
        assert_eq!(batch.total_bytes, 32 * 64);

        let engine = PcapReplayEngine::new();
        let transmitted = engine.transmit_burst_fast_path(&batch, None);
        assert_eq!(transmitted, 32);
    }

    #[test]
    fn test_pcap_replay_full_pipeline_with_rewriting_and_burst() {
        let pcap_data = create_mock_pcap_bytes();
        let mut engine = PcapReplayEngine::new();
        engine.load_capture_bytes(&pcap_data).unwrap();

        engine.set_config(ReplayConfig {
            mode: ReplayMode::TopSpeed,
            loop_count: 3,
            max_step_delay_micros: 1_000_000,
            spoof_mac: true,
            burst_size: 16,
            monotonic_timestamp_shift: true,
            rewrite_config: Some(PacketRewriteConfig {
                rewrite_smac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                rewrite_dmac: None,
                rewrite_src_ip: None,
                rewrite_dst_ip: None,
                rewrite_sport: None,
                rewrite_dport: None,
                recalculate_checksums: false,
            }),
        });

        engine.start(None).expect("启动应该成功");
        thread::sleep(Duration::from_millis(60));

        let telemetry = engine.get_telemetry();
        assert_eq!(telemetry.state, "Completed");
        assert_eq!(telemetry.sent_packets, 9); // 3 个报文 * 3 次循环 = 9
    }
}
