//! 网络深度主动扫描、多维统计分析、基线/.pcap比对与行业审计报告引擎
//!
//! # 核心工业级能力
//! 1. **可控高并发 CIDR/IP段主动端口与安全只读 Banner 提取引擎**:
//!    - 原生解析 CIDR (`/23`..`/32`, 上限 512 主机)、连字符 IP 段 (`192.168.1.1-50`) 及端口表达式 (`21-23,80,443,502,6379,8000-8020`)
//!    - 采用 `tokio::sync::Semaphore(64)` 严格并发限流，单次探测任务上限 `2048` 防系统句柄枯竭
//!    - 使用全平台稳定 TCP Connect 握手 + 安全只读探针（HTTP `HEAD /`, Redis `PING`, SSH/FTP/Telnet Welcome Banner 主动接收）
//!    - **诚实系统边界声明**: 不伪造底层原始套接字 `TCP SYN` 半开包，也不做无根据的 UDP 盲判
//! 2. **Wireshark 级多维流量统计引擎**:
//!    - 时间复杂度 $O(N + K \log K)$，空间复杂度 $O(K)$ ($N$ 为包样本数, $K$ 为唯一 IP/会话数)
//!    - 计算协议层次分布、Top Talkers 双向流量排行、无向五元组活跃会话、RFC 2544 七档帧长分布、基于 MAD 的包间隔抖动 (`jitter_ms`)
//! 3. **黄金网络基线 & 离线 `.pcap` 双样本智能比对引擎**:
//!    - 持久化 `network_traffic_baseline.json`，对比吞吐/PPS 变化率、信息熵漂移、协议占比偏移、RFC 2544 包长偏移及新增活跃 IP
//!    - 直接复用 `export_engine::import_pcap_file` 实现“当前实时捕获 vs 本地历史 `.pcap` 文件”双样本精准对照
//! 4. **网络安全巡检与统计审计报告导出 (Markdown & 全转义防 XSS 自包含 HTML)**

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;

const MAX_SCAN_HOSTS: usize = 512;
const MAX_SCAN_PROBES: usize = 2048;
const SCAN_CONCURRENCY: usize = 64;
const MAX_LIVE_JITTER_WINDOW: usize = 16_384;
const BASELINE_FILE_NAME: &str = "network_traffic_baseline.json";

static LAST_SCAN_SUMMARY: Lazy<RwLock<Option<NetworkPortScanSummary>>> =
    Lazy::new(|| RwLock::new(None));

fn net_data_dir() -> Option<PathBuf> {
    crate::forensics::data_path(BASELINE_FILE_NAME)
        .parent()
        .map(|p| p.to_path_buf())
}

fn current_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn html_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn sanitize_banner(bytes: &[u8]) -> String {
    let mut cleaned = String::with_capacity(bytes.len().min(160));
    for &b in bytes.iter().take(256) {
        if cleaned.len() >= 160 {
            break;
        }
        match b {
            b'\r' | b'\n' | b'\t' => {
                if !cleaned.ends_with(' ') && !cleaned.is_empty() {
                    cleaned.push(' ');
                }
            }
            0x20..=0x7E => cleaned.push(b as char),
            _ => {}
        }
    }
    cleaned.trim().to_string()
}

// ============================================================================
// 1. 目标网段与端口表达式解析 + 并发 Banner 主动扫描引擎
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPortScanItem {
    pub ip: String,
    pub port: u16,
    pub status: String,
    pub protocol: String,
    pub rtt_ms: f64,
    pub banner: String,
    pub is_high_risk: bool,
    pub risk_flag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RttHistogramBucket {
    pub label: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPortScanSummary {
    pub target_spec: String,
    pub port_spec: String,
    pub host_count: usize,
    pub port_count: usize,
    pub total_probes: usize,
    pub open_count: usize,
    pub closed_count: usize,
    pub high_risk_count: usize,
    pub avg_open_rtt_ms: f64,
    pub max_open_rtt_ms: f64,
    pub duration_ms: u64,
    pub scanned_at_ms: u64,
    pub probe_method_note: String,
    pub open_items: Vec<NetworkPortScanItem>,
    pub all_items: Vec<NetworkPortScanItem>,
    pub rtt_histogram: Vec<RttHistogramBucket>,
}

/// 解析目标主机表达式（支持单 IP、CIDR `/23`..`/32`、末段或起止 IP 范围）
///
/// 时间复杂度: O(H), 空间复杂度: O(H), H <= MAX_SCAN_HOSTS (512)
pub fn parse_target_spec(spec: &str) -> Result<Vec<Ipv4Addr>, String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err("目标地址不能为空".to_string());
    }

    if let Some((ip_part, prefix_part)) = trimmed.split_once('/') {
        let base_ip: Ipv4Addr = ip_part
            .trim()
            .parse()
            .map_err(|_| format!("非法 IPv4 网段地址: {}", ip_part.trim()))?;
        let prefix: u32 = prefix_part
            .trim()
            .parse()
            .map_err(|_| format!("非法 CIDR 前缀长度: {}", prefix_part.trim()))?;
        if prefix > 32 {
            return Err("CIDR 前缀长度必须在 0..=32 之间".to_string());
        }
        if prefix < 23 {
            return Err(format!(
                "CIDR /{} 范围过大 (最多允许 /23 即 512 台主机，防止扫描风暴)",
                prefix
            ));
        }

        let base_u32 = u32::from(base_ip);
        let mask = if prefix == 0 { 0u32 } else { (!0u32) << (32 - prefix) };
        let network = base_u32 & mask;
        let broadcast = network | (!mask);

        let mut hosts = Vec::new();
        if prefix == 32 {
            hosts.push(Ipv4Addr::from(network));
        } else if prefix == 31 {
            hosts.push(Ipv4Addr::from(network));
            hosts.push(Ipv4Addr::from(broadcast));
        } else {
            for addr in (network + 1)..broadcast {
                if hosts.len() >= MAX_SCAN_HOSTS {
                    break;
                }
                hosts.push(Ipv4Addr::from(addr));
            }
        }
        return Ok(hosts);
    }

    if let Some((start_str, end_str)) = trimmed.split_once('-') {
        let start_ip: Ipv4Addr = start_str
            .trim()
            .parse()
            .map_err(|_| format!("非法起始 IPv4 地址: {}", start_str.trim()))?;
        let end_trimmed = end_str.trim();
        let end_ip: Ipv4Addr = if let Ok(full) = end_trimmed.parse::<Ipv4Addr>() {
            full
        } else if let Ok(last_octet) = end_trimmed.parse::<u8>() {
            let octets = start_ip.octets();
            Ipv4Addr::new(octets[0], octets[1], octets[2], last_octet)
        } else {
            return Err(format!("非法结束 IP/末段表达式: {}", end_trimmed));
        };

        let start_u32 = u32::from(start_ip);
        let end_u32 = u32::from(end_ip);
        if end_u32 < start_u32 {
            return Err("结束 IP 不能小于起始 IP".to_string());
        }
        let span = (end_u32 - start_u32) as usize + 1;
        if span > MAX_SCAN_HOSTS {
            return Err(format!(
                "IP 范围包含 {} 个主机，超出单次扫描上限 ({})",
                span, MAX_SCAN_HOSTS
            ));
        }
        let mut hosts = Vec::with_capacity(span);
        for addr in start_u32..=end_u32 {
            hosts.push(Ipv4Addr::from(addr));
        }
        return Ok(hosts);
    }

    let mut unique = BTreeSet::new();
    for token in trimmed.split([',', ';', ' ']) {
        let tok = token.trim();
        if tok.is_empty() {
            continue;
        }
        let ip: Ipv4Addr = tok
            .parse()
            .map_err(|_| format!("非法 IPv4 地址: {}", tok))?;
        unique.insert(ip);
        if unique.len() > MAX_SCAN_HOSTS {
            return Err(format!("目标主机数超过上限 {}", MAX_SCAN_HOSTS));
        }
    }
    if unique.is_empty() {
        return Err("未解析到任何有效 IPv4 目标".to_string());
    }
    Ok(unique.into_iter().collect())
}

/// 解析端口表达（支持预设别名 `top25` / `ics` / `db_admin` 及端口/区间混合 `21-23,80,443,502`）
///
/// 时间复杂度: O(P log P), 空间复杂度: O(P)
pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>, String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err("端口表达式不能为空".to_string());
    }

    let expanded = match trimmed.to_ascii_lowercase().as_str() {
        "top25" => "21,22,23,25,53,80,110,135,139,143,443,445,502,993,995,1433,1521,1883,3306,3389,5432,5900,6379,8080,8443",
        "ics" => "102,502,1089,1911,2222,2404,4840,5003,5094,1883,8883,20000,44818,47808",
        "db_admin" => "21,22,23,135,139,445,1433,1521,2375,3306,3389,5432,5900,6379,9200,11211,27017",
        _ => trimmed,
    };

    let mut ports = BTreeSet::new();
    for raw_part in expanded.split(',') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start_s, end_s)) = part.split_once('-') {
            let start: u16 = start_s
                .trim()
                .parse()
                .map_err(|_| format!("非法起始端口: {}", start_s.trim()))?;
            let end: u16 = end_s
                .trim()
                .parse()
                .map_err(|_| format!("非法结束端口: {}", end_s.trim()))?;
            if start == 0 || end == 0 {
                return Err("端口号不能为 0 (合法范围 1..=65535)".to_string());
            }
            if end < start {
                return Err(format!("端口区间倒置: {}-{}", start, end));
            }
            if (end - start) as usize + 1 > MAX_SCAN_PROBES {
                return Err(format!("单个端口区间过大 (>{})", MAX_SCAN_PROBES));
            }
            for p in start..=end {
                ports.insert(p);
                if ports.len() > MAX_SCAN_PROBES {
                    return Err(format!("总端口数量超过上限 {}", MAX_SCAN_PROBES));
                }
            }
        } else {
            let p: u16 = part
                .parse()
                .map_err(|_| format!("非法端口号: {}", part))?;
            if p == 0 {
                return Err("端口号不能为 0".to_string());
            }
            ports.insert(p);
            if ports.len() > MAX_SCAN_PROBES {
                return Err(format!("总端口数量超过上限 {}", MAX_SCAN_PROBES));
            }
        }
    }

    if ports.is_empty() {
        return Err("未解析出任何有效端口".to_string());
    }
    Ok(ports.into_iter().collect())
}

fn is_http_probe_port(port: u16) -> bool {
    matches!(port, 80 | 81 | 3000 | 5000 | 8000 | 8008 | 8080 | 8081 | 8888 | 9000 | 9090)
}

#[derive(Clone, Copy, Debug)]
enum TcpProbeMode {
    Auto,
    Redis,
    Http,
    WelcomeBanner,
}

async fn probe_single_tcp_banner_with_mode(
    ip: Ipv4Addr,
    port: u16,
    timeout: Duration,
    mode: TcpProbeMode,
) -> NetworkPortScanItem {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let started = Instant::now();
    let proto = crate::discovery::infer_protocol_by_port(port).to_string();
    let base_high_risk = crate::discovery::is_high_risk_port(port);

    let connect_res = tokio::time::timeout(timeout, TcpStream::connect(addr)).await;
    let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;

    let mut stream = match connect_res {
        Ok(Ok(s)) => s,
        _ => {
            return NetworkPortScanItem {
                ip: ip.to_string(),
                port,
                status: "CLOSED".to_string(),
                protocol: proto,
                rtt_ms: (rtt_ms * 100.0).round() / 100.0,
                banner: String::new(),
                is_high_risk: false,
                risk_flag: None,
            };
        }
    };

    let effective_mode = match mode {
        TcpProbeMode::Auto => {
            if port == 6379 {
                TcpProbeMode::Redis
            } else if is_http_probe_port(port) {
                TcpProbeMode::Http
            } else {
                TcpProbeMode::WelcomeBanner
            }
        }
        other => other,
    };

    let banner_timeout = timeout.min(Duration::from_millis(500));
    let mut buf = [0u8; 512];
    let mut banner = String::new();
    let mut risk_flag: Option<String> = None;

    match effective_mode {
        TcpProbeMode::Redis => {
            if tokio::time::timeout(banner_timeout, stream.write_all(b"*1\r\n$4\r\nPING\r\n"))
                .await
                .is_ok()
            {
                if let Ok(Ok(n)) = tokio::time::timeout(banner_timeout, stream.read(&mut buf)).await {
                    if n > 0 {
                        banner = sanitize_banner(&buf[..n]);
                        if banner.starts_with("+PONG") {
                            risk_flag = Some("UNAUTH_REDIS".to_string());
                        }
                    }
                }
            }
        }
        TcpProbeMode::Http => {
            let req = format!(
                "HEAD / HTTP/1.0\r\nHost: {}\r\nUser-Agent: OmniProbe/{}\r\nConnection: close\r\n\r\n",
                ip,
                env!("CARGO_PKG_VERSION")
            );
            if tokio::time::timeout(banner_timeout, stream.write_all(req.as_bytes()))
                .await
                .is_ok()
            {
                if let Ok(Ok(n)) = tokio::time::timeout(banner_timeout, stream.read(&mut buf)).await {
                    if n > 0 {
                        let raw_text = String::from_utf8_lossy(&buf[..n]);
                        let first_line = raw_text.lines().next().unwrap_or("").trim();
                        let server_hdr = raw_text
                            .lines()
                            .find(|l| l.to_ascii_lowercase().starts_with("server:"))
                            .map(|l| l.trim())
                            .unwrap_or("");
                        banner = if !server_hdr.is_empty() {
                            sanitize_banner(format!("{} | {}", first_line, server_hdr).as_bytes())
                        } else {
                            sanitize_banner(first_line.as_bytes())
                        };
                    }
                }
            }
        }
        TcpProbeMode::WelcomeBanner | TcpProbeMode::Auto => {
            if let Ok(Ok(n)) = tokio::time::timeout(banner_timeout, stream.read(&mut buf)).await {
                if n > 0 {
                    banner = sanitize_banner(&buf[..n]);
                }
            }
        }
    }

    if risk_flag.is_none() {
        if matches!(port, 21 | 23) {
            risk_flag = Some("CLEARTEXT_MGMT".to_string());
        } else if base_high_risk {
            risk_flag = Some("HIGH_RISK_PORT".to_string());
        }
    }

    let is_high_risk = base_high_risk || risk_flag.is_some();

    NetworkPortScanItem {
        ip: ip.to_string(),
        port,
        status: "OPEN".to_string(),
        protocol: proto,
        rtt_ms: (rtt_ms * 100.0).round() / 100.0,
        banner,
        is_high_risk,
        risk_flag,
    }
}

#[derive(Clone, Copy, Debug)]
enum UdpProbeKind {
    Dns,
    Ntp,
    SnmpPublic,
    Bacnet,
}

fn udp_probe_kind_for_port(port: u16) -> Option<UdpProbeKind> {
    match port {
        53 => Some(UdpProbeKind::Dns),
        123 => Some(UdpProbeKind::Ntp),
        161 => Some(UdpProbeKind::SnmpPublic),
        47808 => Some(UdpProbeKind::Bacnet),
        _ => None,
    }
}

/// 行业合规只读载荷触发式 UDP 扫描：仅向支持标准协议查询载荷的端口发包，且仅在收到合规应答报文时标记 OPEN（严禁无根据盲判 OPEN|FILTERED）
async fn probe_single_udp_kind(
    ip: Ipv4Addr,
    port: u16,
    timeout: Duration,
    kind: UdpProbeKind,
) -> Option<NetworkPortScanItem> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let target = SocketAddr::new(IpAddr::V4(ip), port);
    let started = Instant::now();

    let payload: Vec<u8> = match kind {
        UdpProbeKind::Dns => vec![
            0x4F, 0x50, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x09, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ],
        UdpProbeKind::Ntp => {
            let mut pkt = vec![0u8; 48];
            pkt[0] = 0x23; // LI=0, VN=4, Mode=3 (Client)
            pkt
        }
        UdpProbeKind::SnmpPublic => vec![
            0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c',
            0xA0, 0x1C, 0x02, 0x04, 0x1A, 0x2B, 0x3C, 0x4D, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
        ],
        UdpProbeKind::Bacnet => vec![0x81, 0x0B, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08],
    };

    if sock.send_to(&payload, target).await.is_err() {
        return None;
    }

    let mut resp = [0u8; 512];
    let n = match tokio::time::timeout(timeout, sock.recv_from(&mut resp)).await {
        Ok(Ok((len, _))) if len > 0 => len,
        _ => return None,
    };
    let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;

    let (valid, proto, banner, risk_flag) = match kind {
        UdpProbeKind::Dns => {
            let ok = n >= 12 && resp[0] == 0x4F && resp[1] == 0x50 && (resp[2] & 0x80) != 0;
            (ok, "DNS_UDP", format!("DNS Standard Query Response ({}B)", n), None)
        }
        UdpProbeKind::Ntp => {
            let ok = n >= 48 && (resp[0] & 0x07) == 4;
            (ok, "NTP_UDP", format!("NTPv4 Server Stratum={}", resp[1]), None)
        }
        UdpProbeKind::SnmpPublic => {
            let ok = n >= 10 && resp[0] == 0x30 && resp[..n].windows(1).any(|w| w[0] == 0xA2);
            (
                ok,
                "SNMP_UDP",
                "SNMPv2c GetResponse (public community)".to_string(),
                Some("SNMP_DEFAULT_PUBLIC".to_string()),
            )
        }
        UdpProbeKind::Bacnet => {
            let ok = n >= 4 && resp[0] == 0x81;
            (ok, "BACNET_UDP", format!("BACnet/IP BVLC Response ({}B)", n), Some("HIGH_RISK_PORT".to_string()))
        }
    };

    if !valid {
        return None;
    }

    let is_high_risk = risk_flag.is_some();
    Some(NetworkPortScanItem {
        ip: ip.to_string(),
        port,
        status: "OPEN".to_string(),
        protocol: proto.to_string(),
        rtt_ms: (rtt_ms * 100.0).round() / 100.0,
        banner,
        is_high_risk,
        risk_flag,
    })
}

async fn probe_single_tcp_banner(
    ip: Ipv4Addr,
    port: u16,
    timeout: Duration,
) -> NetworkPortScanItem {
    probe_single_tcp_banner_with_mode(ip, port, timeout, TcpProbeMode::Auto).await
}

fn build_rtt_histogram(open_items: &[NetworkPortScanItem]) -> Vec<RttHistogramBucket> {
    let mut b_lt2 = 0usize;
    let mut b_2_10 = 0usize;
    let mut b_10_50 = 0usize;
    let mut b_50_200 = 0usize;
    let mut b_gt200 = 0usize;
    for item in open_items {
        let rtt = item.rtt_ms;
        if rtt < 2.0 {
            b_lt2 += 1;
        } else if rtt < 10.0 {
            b_2_10 += 1;
        } else if rtt < 50.0 {
            b_10_50 += 1;
        } else if rtt < 200.0 {
            b_50_200 += 1;
        } else {
            b_gt200 += 1;
        }
    }
    vec![
        RttHistogramBucket { label: "<2ms".to_string(), count: b_lt2 },
        RttHistogramBucket { label: "2-10ms".to_string(), count: b_2_10 },
        RttHistogramBucket { label: "10-50ms".to_string(), count: b_10_50 },
        RttHistogramBucket { label: "50-200ms".to_string(), count: b_50_200 },
        RttHistogramBucket { label: ">200ms".to_string(), count: b_gt200 },
    ]
}

/// 执行批量高并发 TCP Connect + Banner（可选触发式标准协议 UDP）主动扫描核心逻辑
///
/// 时间复杂度: O(H * P / C), C=64 信号量并发控制; 空间复杂度: O(H * P)
pub async fn run_network_port_scan_core(
    target_spec: &str,
    port_spec: &str,
    timeout_ms: Option<u64>,
    include_closed: bool,
    sync_assets: bool,
) -> Result<NetworkPortScanSummary, String> {
    run_network_port_scan_with_options_core(
        target_spec,
        port_spec,
        timeout_ms,
        include_closed,
        sync_assets,
        false,
    )
    .await
}

pub async fn run_network_port_scan_with_options_core(
    target_spec: &str,
    port_spec: &str,
    timeout_ms: Option<u64>,
    include_closed: bool,
    sync_assets: bool,
    include_udp: bool,
) -> Result<NetworkPortScanSummary, String> {
    let hosts = parse_target_spec(target_spec)?;
    let ports = parse_port_spec(port_spec)?;
    let udp_ports_per_host = if include_udp {
        ports
            .iter()
            .filter(|&&p| udp_probe_kind_for_port(p).is_some())
            .count()
    } else {
        0
    };
    let total_probes = hosts
        .len()
        .checked_mul(ports.len() + udp_ports_per_host)
        .ok_or_else(|| "扫描组合总数溢出".to_string())?;
    if total_probes > MAX_SCAN_PROBES {
        return Err(format!(
            "探测总任务数 {} 超过安全限流上限 {}（请缩小网段或端口区间）",
            total_probes, MAX_SCAN_PROBES
        ));
    }

    let clamped_timeout = Duration::from_millis(timeout_ms.unwrap_or(600).clamp(150, 5000));
    let sem = Arc::new(Semaphore::new(SCAN_CONCURRENCY));
    let started = Instant::now();

    let mut tcp_handles = Vec::with_capacity(hosts.len() * ports.len());
    let mut udp_handles = Vec::with_capacity(hosts.len() * udp_ports_per_host);
    for ip in &hosts {
        for &port in &ports {
            let ip_val = *ip;
            let sem_clone = Arc::clone(&sem);
            tcp_handles.push(tokio::spawn(async move {
                let _permit = sem_clone.acquire().await;
                probe_single_tcp_banner(ip_val, port, clamped_timeout).await
            }));

            if include_udp {
                if let Some(udp_kind) = udp_probe_kind_for_port(port) {
                    let sem_udp = Arc::clone(&sem);
                    udp_handles.push(tokio::spawn(async move {
                        let _permit = sem_udp.acquire().await;
                        probe_single_udp_kind(ip_val, port, clamped_timeout, udp_kind).await
                    }));
                }
            }
        }
    }

    let mut open_items = Vec::new();
    let mut closed_count = 0usize;
    let mut kept_all = Vec::new();

    for h in tcp_handles {
        if let Ok(item) = h.await {
            if item.status == "OPEN" {
                if sync_assets {
                    crate::discovery::record_asset(
                        &item.ip,
                        "00:00:00:00:00:00",
                        &item.protocol,
                        item.port,
                    );
                }
                open_items.push(item.clone());
                kept_all.push(item);
            } else {
                closed_count += 1;
                if include_closed && kept_all.len() < 256 {
                    kept_all.push(item);
                }
            }
        }
    }

    for uh in udp_handles {
        if let Ok(Some(item)) = uh.await {
            if sync_assets {
                crate::discovery::record_asset(
                    &item.ip,
                    "00:00:00:00:00:00",
                    &item.protocol,
                    item.port,
                );
            }
            open_items.push(item.clone());
            kept_all.push(item);
        } else {
            closed_count += 1;
        }
    }

    open_items.sort_by(|a, b| a.ip.cmp(&b.ip).then_with(|| a.port.cmp(&b.port)));

    let open_count = open_items.len();
    let high_risk_count = open_items.iter().filter(|i| i.is_high_risk).count();
    let (avg_open_rtt_ms, max_open_rtt_ms) = if open_count > 0 {
        let sum: f64 = open_items.iter().map(|i| i.rtt_ms).sum();
        let max_v = open_items
            .iter()
            .map(|i| i.rtt_ms)
            .fold(0.0_f64, f64::max);
        (
            ((sum / open_count as f64) * 100.0).round() / 100.0,
            (max_v * 100.0).round() / 100.0,
        )
    } else {
        (0.0, 0.0)
    };

    let rtt_histogram = build_rtt_histogram(&open_items);
    let note = if include_udp {
        "基于跨平台 TCP Connect + 只读 Banner + 标准载荷触发式 UDP(DNS/NTP/SNMP/BACnet) 探测（仅对收到协议合法应答端口标记 OPEN，不含无权 TCP SYN 半开伪造与盲猜）"
    } else {
        "基于跨平台标准全连接 TCP Connect + 应用层只读 Banner 探针（不含底层原始 TCP SYN 半开包及无状态 UDP 盲判）"
    };
    let summary = NetworkPortScanSummary {
        target_spec: target_spec.trim().to_string(),
        port_spec: port_spec.trim().to_string(),
        host_count: hosts.len(),
        port_count: ports.len(),
        total_probes,
        open_count,
        closed_count,
        high_risk_count,
        avg_open_rtt_ms,
        max_open_rtt_ms,
        duration_ms: started.elapsed().as_millis() as u64,
        scanned_at_ms: current_epoch_ms(),
        probe_method_note: note.to_string(),
        open_items,
        all_items: kept_all,
        rtt_histogram,
    };

    if let Ok(mut guard) = LAST_SCAN_SUMMARY.write() {
        *guard = Some(summary.clone());
    }

    Ok(summary)
}

#[tauri::command]
pub async fn run_network_port_scan_cmd(
    target_spec: String,
    port_spec: String,
    timeout_ms: Option<u64>,
    include_closed: Option<bool>,
    include_udp: Option<bool>,
) -> Result<NetworkPortScanSummary, String> {
    run_network_port_scan_with_options_core(
        &target_spec,
        &port_spec,
        timeout_ms,
        include_closed.unwrap_or(false),
        true,
        include_udp.unwrap_or(false),
    )
    .await
}

// ============================================================================
// 2. Wireshark 级多维网络流量统计引擎
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetTrafficSample {
    pub protocol: String,
    pub transport: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub length: usize,
    pub timestamp_ns: u128,
    pub entropy: f64,
}

impl From<&crate::sniffer::PacketRecord> for NetTrafficSample {
    fn from(p: &crate::sniffer::PacketRecord) -> Self {
        Self {
            protocol: p.protocol.clone(),
            transport: p.transport.clone(),
            src_ip: p.src_ip.clone(),
            dst_ip: p.dst_ip.clone(),
            src_port: p.src_port,
            dst_port: p.dst_port,
            length: p.length,
            timestamp_ns: p.timestamp_ns,
            entropy: p.entropy,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolStatItem {
    pub protocol: String,
    pub packet_count: usize,
    pub byte_count: u64,
    pub packet_ratio_pct: f64,
    pub byte_ratio_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpTalkerItem {
    pub ip: String,
    pub tx_packets: usize,
    pub rx_packets: usize,
    pub total_packets: usize,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub total_bytes: u64,
    pub peer_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationStatItem {
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub protocol: String,
    pub packet_count: usize,
    pub byte_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketLengthBucket {
    pub label: String,
    pub packet_count: usize,
    pub ratio_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTrafficStats {
    pub total_packets: usize,
    pub total_bytes: u64,
    pub unique_ips: usize,
    pub avg_packet_len: f64,
    pub avg_entropy: f64,
    pub duration_sec: f64,
    pub mean_iat_ms: f64,
    pub jitter_ms: f64,
    pub protocol_breakdown: Vec<ProtocolStatItem>,
    pub top_talkers: Vec<IpTalkerItem>,
    pub top_conversations: Vec<ConversationStatItem>,
    pub length_distribution: Vec<PacketLengthBucket>,
    pub active_ips: Vec<String>,
}

fn rfc2544_bucket_index(len: usize) -> usize {
    if len <= 63 {
        0
    } else if len <= 127 {
        1
    } else if len <= 255 {
        2
    } else if len <= 511 {
        3
    } else if len <= 1023 {
        4
    } else if len <= 1518 {
        5
    } else {
        6
    }
}

const RFC2544_LABELS: [&str; 7] = [
    "0-63B",
    "64-127B",
    "128-255B",
    "256-511B",
    "512-1023B",
    "1024-1518B",
    ">1518B",
];

fn normalize_protocol_label(proto: &str, transport: &str) -> String {
    let p = proto.trim();
    if !p.is_empty() && p != "UNKNOWN" {
        return p.to_ascii_uppercase();
    }
    let t = transport.trim();
    if !t.is_empty() {
        return t.to_ascii_uppercase();
    }
    "OTHER".to_string()
}

fn valid_ip_endpoint(ip: &str) -> Option<&str> {
    let trimmed = ip.trim();
    if trimmed.is_empty() || trimmed == "0.0.0.0" || trimmed == "N/A" || trimmed == "-" {
        None
    } else {
        Some(trimmed)
    }
}

#[derive(Default)]
struct TalkerAcc {
    tx_packets: usize,
    rx_packets: usize,
    tx_bytes: u64,
    rx_bytes: u64,
    peers: BTreeSet<String>,
}

/// 后端流式全量统计累加器：O(1) 入包，消除前端视窗 <= 2500 条截断限制，有界时间窗口计算 MAD 抖动
#[derive(Default)]
pub struct LiveNetAccumulator {
    total_packets: usize,
    total_bytes: u64,
    sum_entropy: f64,
    first_ts_ns: u128,
    last_ts_ns: u128,
    proto_map: HashMap<String, (usize, u64)>,
    talker_map: HashMap<String, TalkerAcc>,
    conv_map: HashMap<(String, String, String), (usize, u64)>,
    len_counts: [usize; 7],
    recent_timestamps: VecDeque<u128>,
}

impl LiveNetAccumulator {
    pub fn reset(&mut self) {
        self.total_packets = 0;
        self.total_bytes = 0;
        self.sum_entropy = 0.0;
        self.first_ts_ns = 0;
        self.last_ts_ns = 0;
        self.proto_map.clear();
        self.talker_map.clear();
        self.conv_map.clear();
        self.len_counts = [0usize; 7];
        self.recent_timestamps.clear();
    }

    pub fn ingest_sample(&mut self, s: &NetTrafficSample) {
        let len_u64 = s.length as u64;
        self.total_packets = self.total_packets.saturating_add(1);
        self.total_bytes = self.total_bytes.saturating_add(len_u64);
        if s.entropy.is_finite() && s.entropy >= 0.0 {
            self.sum_entropy += s.entropy;
        }
        self.len_counts[rfc2544_bucket_index(s.length)] += 1;

        let proto = normalize_protocol_label(&s.protocol, &s.transport);
        let p_entry = self.proto_map.entry(proto.clone()).or_insert((0, 0));
        p_entry.0 += 1;
        p_entry.1 = p_entry.1.saturating_add(len_u64);

        let src_valid = valid_ip_endpoint(&s.src_ip);
        let dst_valid = valid_ip_endpoint(&s.dst_ip);
        if let Some(src) = src_valid {
            // 有界键保护：超过 20,000 个独立 IP 时停止插入新节点防内存无限膨胀，已有节点继续计数
            if self.talker_map.contains_key(src) || self.talker_map.len() < 20_000 {
                let acc = self.talker_map.entry(src.to_string()).or_default();
                acc.tx_packets += 1;
                acc.tx_bytes = acc.tx_bytes.saturating_add(len_u64);
                if let Some(dst) = dst_valid {
                    if acc.peers.len() < 512 {
                        acc.peers.insert(dst.to_string());
                    }
                }
            }
        }
        if let Some(dst) = dst_valid {
            if self.talker_map.contains_key(dst) || self.talker_map.len() < 20_000 {
                let acc = self.talker_map.entry(dst.to_string()).or_default();
                acc.rx_packets += 1;
                acc.rx_bytes = acc.rx_bytes.saturating_add(len_u64);
                if let Some(src) = src_valid {
                    if acc.peers.len() < 512 {
                        acc.peers.insert(src.to_string());
                    }
                }
            }
        }

        if let (Some(src), Some(dst)) = (src_valid, dst_valid) {
            if self.conv_map.len() < 30_000 {
                let ep_src = if s.src_port > 0 {
                    format!("{}:{}", src, s.src_port)
                } else {
                    src.to_string()
                };
                let ep_dst = if s.dst_port > 0 {
                    format!("{}:{}", dst, s.dst_port)
                } else {
                    dst.to_string()
                };
                let (a, b) = if ep_src <= ep_dst {
                    (ep_src, ep_dst)
                } else {
                    (ep_dst, ep_src)
                };
                let c_entry = self.conv_map.entry((a, b, proto)).or_insert((0, 0));
                c_entry.0 += 1;
                c_entry.1 = c_entry.1.saturating_add(len_u64);
            }
        }

        if s.timestamp_ns > 0 {
            if self.first_ts_ns == 0 || s.timestamp_ns < self.first_ts_ns {
                self.first_ts_ns = s.timestamp_ns;
            }
            if s.timestamp_ns > self.last_ts_ns {
                self.last_ts_ns = s.timestamp_ns;
            }
            if self.recent_timestamps.len() >= MAX_LIVE_JITTER_WINDOW {
                self.recent_timestamps.pop_front();
            }
            self.recent_timestamps.push_back(s.timestamp_ns);
        }
    }

    pub fn snapshot_stats(&self) -> NetworkTrafficStats {
        let mut ts_vec: Vec<u128> = self.recent_timestamps.iter().copied().collect();
        let total_span_sec = if self.last_ts_ns > self.first_ts_ns && self.first_ts_ns > 0 {
            Some(self.last_ts_ns.saturating_sub(self.first_ts_ns) as f64 / 1_000_000_000.0)
        } else {
            None
        };
        finalize_stats_view(
            self.total_packets,
            self.total_bytes,
            self.sum_entropy,
            &self.proto_map,
            &self.talker_map,
            &self.conv_map,
            &self.len_counts,
            &mut ts_vec,
            total_span_sec,
        )
    }
}

static LIVE_NET_ACC: Lazy<Mutex<LiveNetAccumulator>> =
    Lazy::new(|| Mutex::new(LiveNetAccumulator::default()));

/// 从全局抓包统一收口流 O(1) 实时喂入累加器（消除前端 2500 条抽样盲区）
pub fn ingest_live_packet(record: &crate::sniffer::PacketRecord) {
    let sample = NetTrafficSample::from(record);
    if let Ok(mut guard) = LIVE_NET_ACC.lock() {
        guard.ingest_sample(&sample);
    }
}

pub fn reset_live_net_stats() {
    if let Ok(mut guard) = LIVE_NET_ACC.lock() {
        guard.reset();
    }
}

pub fn get_live_net_stats_snapshot() -> NetworkTrafficStats {
    if let Ok(guard) = LIVE_NET_ACC.lock() {
        guard.snapshot_stats()
    } else {
        analyze_network_traffic_stats_core(&[])
    }
}

#[allow(clippy::too_many_arguments)]
fn finalize_stats_view(
    total_packets: usize,
    total_bytes: u64,
    sum_entropy: f64,
    proto_map: &HashMap<String, (usize, u64)>,
    talker_map: &HashMap<String, TalkerAcc>,
    conv_map: &HashMap<(String, String, String), (usize, u64)>,
    len_counts: &[usize; 7],
    timestamps: &mut [u128],
    override_duration_sec: Option<f64>,
) -> NetworkTrafficStats {
    if total_packets == 0 {
        return NetworkTrafficStats {
            total_packets: 0,
            total_bytes: 0,
            unique_ips: 0,
            avg_packet_len: 0.0,
            avg_entropy: 0.0,
            duration_sec: 0.0,
            mean_iat_ms: 0.0,
            jitter_ms: 0.0,
            protocol_breakdown: Vec::new(),
            top_talkers: Vec::new(),
            top_conversations: Vec::new(),
            length_distribution: RFC2544_LABELS
                .iter()
                .map(|l| PacketLengthBucket {
                    label: (*l).to_string(),
                    packet_count: 0,
                    ratio_pct: 0.0,
                })
                .collect(),
            active_ips: Vec::new(),
        };
    }

    let mut proto_items: Vec<ProtocolStatItem> = proto_map
        .iter()
        .map(|(protocol, &(pkt_c, byte_c))| ProtocolStatItem {
            protocol: protocol.clone(),
            packet_count: pkt_c,
            byte_count: byte_c,
            packet_ratio_pct: (pkt_c as f64 / total_packets as f64) * 100.0,
            byte_ratio_pct: if total_bytes > 0 {
                (byte_c as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            },
        })
        .collect();
    proto_items.sort_by(|a, b| {
        b.byte_count
            .cmp(&a.byte_count)
            .then_with(|| b.packet_count.cmp(&a.packet_count))
    });
    if proto_items.len() > 10 {
        let tail = proto_items.split_off(9);
        let tail_pkts: usize = tail.iter().map(|x| x.packet_count).sum();
        let tail_bytes: u64 = tail.iter().map(|x| x.byte_count).sum();
        proto_items.push(ProtocolStatItem {
            protocol: "OTHER".to_string(),
            packet_count: tail_pkts,
            byte_count: tail_bytes,
            packet_ratio_pct: (tail_pkts as f64 / total_packets as f64) * 100.0,
            byte_ratio_pct: if total_bytes > 0 {
                (tail_bytes as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            },
        });
    }

    let unique_ips = talker_map.len();
    let mut active_ips: Vec<String> = talker_map.keys().cloned().collect();
    active_ips.sort();

    let mut talkers: Vec<IpTalkerItem> = talker_map
        .iter()
        .map(|(ip, acc)| IpTalkerItem {
            ip: ip.clone(),
            tx_packets: acc.tx_packets,
            rx_packets: acc.rx_packets,
            total_packets: acc.tx_packets + acc.rx_packets,
            tx_bytes: acc.tx_bytes,
            rx_bytes: acc.rx_bytes,
            total_bytes: acc.tx_bytes + acc.rx_bytes,
            peer_count: acc.peers.len(),
        })
        .collect();
    talkers.sort_by(|a, b| {
        b.total_bytes
            .cmp(&a.total_bytes)
            .then_with(|| b.total_packets.cmp(&a.total_packets))
    });
    talkers.truncate(10);

    let mut conversations: Vec<ConversationStatItem> = conv_map
        .iter()
        .map(|((a, b, proto), &(pkt_c, byte_c))| ConversationStatItem {
            endpoint_a: a.clone(),
            endpoint_b: b.clone(),
            protocol: proto.clone(),
            packet_count: pkt_c,
            byte_count: byte_c,
        })
        .collect();
    conversations.sort_by(|a, b| {
        b.byte_count
            .cmp(&a.byte_count)
            .then_with(|| b.packet_count.cmp(&a.packet_count))
    });
    conversations.truncate(10);

    let length_distribution: Vec<PacketLengthBucket> = RFC2544_LABELS
        .iter()
        .enumerate()
        .map(|(idx, label)| PacketLengthBucket {
            label: (*label).to_string(),
            packet_count: len_counts[idx],
            ratio_pct: (len_counts[idx] as f64 / total_packets as f64) * 100.0,
        })
        .collect();

    timestamps.sort_unstable();
    let (duration_sec, mean_iat_ms, jitter_ms) = if timestamps.len() >= 2 {
        let span_ns = timestamps[timestamps.len() - 1].saturating_sub(timestamps[0]);
        let dur_s = override_duration_sec.unwrap_or(span_ns as f64 / 1_000_000_000.0);
        let mut iats_ms: Vec<f64> = Vec::with_capacity(timestamps.len() - 1);
        for w in timestamps.windows(2) {
            iats_ms.push((w[1].saturating_sub(w[0])) as f64 / 1_000_000.0);
        }
        let mean = iats_ms.iter().sum::<f64>() / iats_ms.len() as f64;
        iats_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = iats_ms[iats_ms.len() / 2];
        let mut devs: Vec<f64> = iats_ms.iter().map(|v| (v - median).abs()).collect();
        devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mad = devs[devs.len() / 2];
        (dur_s, mean, mad)
    } else {
        (override_duration_sec.unwrap_or(0.0), 0.0, 0.0)
    };

    NetworkTrafficStats {
        total_packets,
        total_bytes,
        unique_ips,
        avg_packet_len: total_bytes as f64 / total_packets as f64,
        avg_entropy: sum_entropy / total_packets as f64,
        duration_sec,
        mean_iat_ms: (mean_iat_ms * 1000.0).round() / 1000.0,
        jitter_ms: (jitter_ms * 1000.0).round() / 1000.0,
        protocol_breakdown: proto_items,
        top_talkers: talkers,
        top_conversations: conversations,
        length_distribution,
        active_ips,
    }
}

/// 单遍 O(N) 构建多维网络流量统计（复用共享累加器）
pub fn analyze_network_traffic_stats_core(samples: &[NetTrafficSample]) -> NetworkTrafficStats {
    if samples.is_empty() {
        return finalize_stats_view(
            0,
            0,
            0.0,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &[0usize; 7],
            &mut [],
            None,
        );
    }
    let mut acc = LiveNetAccumulator::default();
    for s in samples {
        acc.ingest_sample(s);
    }
    acc.snapshot_stats()
}

fn resolve_stats_backend_or_samples(
    samples: Option<Vec<NetTrafficSample>>,
    use_backend_full: Option<bool>,
) -> NetworkTrafficStats {
    if use_backend_full.unwrap_or(true) {
        let backend_stats = get_live_net_stats_snapshot();
        if backend_stats.total_packets > 0 {
            return backend_stats;
        }
    }
    analyze_network_traffic_stats_core(&samples.unwrap_or_default())
}

#[tauri::command]
pub fn analyze_network_traffic_stats_cmd(
    samples: Option<Vec<NetTrafficSample>>,
    use_backend_full: Option<bool>,
) -> NetworkTrafficStats {
    resolve_stats_backend_or_samples(samples, use_backend_full)
}

#[tauri::command]
pub fn reset_live_net_stats_cmd() {
    reset_live_net_stats();
}

// ============================================================================
// 3. 黄金网络基线持久化 + 实时 vs 历史/PCAP 智能对比引擎
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoBucketSummaryInput {
    pub packet_count: usize,
    pub byte_count: usize,
    pub avg_rtt_ms: f64,
    pub retrans_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTrafficBaseline {
    pub name: String,
    pub saved_at_ms: u64,
    pub avg_pps: f64,
    pub avg_bps: f64,
    pub avg_rtt_ms: f64,
    pub retrans_rate_pct: f64,
    pub stats: NetworkTrafficStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDeltaItem {
    pub protocol: String,
    pub baseline_pct: f64,
    pub current_pct: f64,
    pub delta_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LengthBucketDeltaItem {
    pub label: String,
    pub baseline_pct: f64,
    pub current_pct: f64,
    pub delta_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkComparisonReport {
    pub baseline_name: String,
    pub baseline_saved_at_ms: u64,
    pub baseline_total_packets: usize,
    pub current_total_packets: usize,
    pub baseline_avg_pps: f64,
    pub current_avg_pps: f64,
    pub pps_change_pct: f64,
    pub baseline_avg_bps: f64,
    pub current_avg_bps: f64,
    pub bps_change_pct: f64,
    pub entropy_delta: f64,
    pub jitter_delta_ms: f64,
    pub avg_len_delta: f64,
    pub protocol_deltas: Vec<ProtocolDeltaItem>,
    pub length_deltas: Vec<LengthBucketDeltaItem>,
    pub new_external_ips: Vec<String>,
    pub disappeared_ips: Vec<String>,
    pub anomaly_verdict: String,
    pub anomaly_reasons: Vec<String>,
}

fn summarize_io_buckets_rates(buckets: &[IoBucketSummaryInput]) -> (f64, f64, f64, f64) {
    if buckets.is_empty() {
        return (0.0, 0.0, 0.0, 0.0);
    }
    let count = buckets.len() as f64;
    let total_pkts: usize = buckets.iter().map(|b| b.packet_count).sum();
    let total_bytes: usize = buckets.iter().map(|b| b.byte_count).sum();
    let total_retrans: usize = buckets.iter().map(|b| b.retrans_count).sum();
    let mut rtt_sum = 0.0_f64;
    let mut rtt_cnt = 0usize;
    for b in buckets {
        if b.avg_rtt_ms > 0.0 {
            rtt_sum += b.avg_rtt_ms;
            rtt_cnt += 1;
        }
    }
    let avg_pps = total_pkts as f64 / count;
    let avg_bps = total_bytes as f64 / count;
    let avg_rtt = if rtt_cnt > 0 { rtt_sum / rtt_cnt as f64 } else { 0.0 };
    let retrans_pct = if total_pkts > 0 {
        (total_retrans as f64 / total_pkts as f64) * 100.0
    } else {
        0.0
    };
    (avg_pps, avg_bps, avg_rtt, retrans_pct)
}

/// 将已计算好的 `NetworkTrafficStats` 固化为黄金基线（支持全量无截断流式统计直存）
pub fn save_network_baseline_stats_in_dir(
    dir: &Path,
    name: &str,
    stats: NetworkTrafficStats,
    buckets: &[IoBucketSummaryInput],
) -> Result<NetworkTrafficBaseline, String> {
    let (avg_pps, avg_bps, avg_rtt_ms, retrans_rate_pct) = summarize_io_buckets_rates(buckets);
    if stats.total_packets == 0 && buckets.iter().all(|b| b.packet_count == 0) {
        return Err("当前无有效实时流量数据包，无法固化空黄金基线".to_string());
    }

    fs::create_dir_all(dir).map_err(|e| format!("创建基线目录失败: {}", e))?;
    let baseline_name = if name.trim().is_empty() {
        "默认网络黄金基线".to_string()
    } else {
        name.trim().to_string()
    };
    let baseline = NetworkTrafficBaseline {
        name: baseline_name,
        saved_at_ms: current_epoch_ms(),
        avg_pps,
        avg_bps,
        avg_rtt_ms,
        retrans_rate_pct,
        stats,
    };

    let json = serde_json::to_string_pretty(&baseline)
        .map_err(|e| format!("序列化网络基线失败: {}", e))?;
    fs::write(dir.join(BASELINE_FILE_NAME), json)
        .map_err(|e| format!("写入网络基线文件失败: {}", e))?;
    Ok(baseline)
}

/// 固化网络流量黄金基线到指定目录 (`network_traffic_baseline.json`)
pub fn save_network_baseline_in_dir(
    dir: &Path,
    name: &str,
    samples: &[NetTrafficSample],
    buckets: &[IoBucketSummaryInput],
) -> Result<NetworkTrafficBaseline, String> {
    let stats = analyze_network_traffic_stats_core(samples);
    save_network_baseline_stats_in_dir(dir, name, stats, buckets)
}

pub fn load_network_baseline_in_dir(dir: &Path) -> Result<Option<NetworkTrafficBaseline>, String> {
    let path = dir.join(BASELINE_FILE_NAME);
    if !path.exists() {
        return Ok(None);
    }
    let content =
        fs::read_to_string(&path).map_err(|e| format!("读取网络基线失败: {}", e))?;
    let parsed: NetworkTrafficBaseline =
        serde_json::from_str(&content).map_err(|e| format!("解析网络基线损坏: {}", e))?;
    Ok(Some(parsed))
}

fn pct_change(base: f64, cur: f64) -> f64 {
    if base.abs() < 1e-9 {
        if cur.abs() < 1e-9 { 0.0 } else { 100.0 }
    } else {
        ((cur - base) / base) * 100.0
    }
}

/// 执行双样本对比核心算法（直接接收 `NetworkTrafficStats`，支持后端全量实时累加器无缝对账）
pub fn compare_network_stats_core(
    baseline_name: &str,
    baseline_saved_at_ms: u64,
    baseline_stats: &NetworkTrafficStats,
    baseline_avg_pps: f64,
    baseline_avg_bps: f64,
    cur_stats: &NetworkTrafficStats,
    current_buckets: &[IoBucketSummaryInput],
) -> Result<NetworkComparisonReport, String> {
    if cur_stats.total_packets == 0 && baseline_stats.total_packets == 0 {
        return Err("对比样本为空，请先捕获或导入数据包".to_string());
    }
    let (cur_avg_pps, cur_avg_bps, _, _) = summarize_io_buckets_rates(current_buckets);

    let mut base_proto_map: BTreeMap<String, f64> = BTreeMap::new();
    for p in &baseline_stats.protocol_breakdown {
        base_proto_map.insert(p.protocol.clone(), p.packet_ratio_pct);
    }
    let mut cur_proto_map: BTreeMap<String, f64> = BTreeMap::new();
    for p in &cur_stats.protocol_breakdown {
        cur_proto_map.insert(p.protocol.clone(), p.packet_ratio_pct);
    }

    let mut all_protos: BTreeSet<String> = BTreeSet::new();
    all_protos.extend(base_proto_map.keys().cloned());
    all_protos.extend(cur_proto_map.keys().cloned());

    let mut protocol_deltas: Vec<ProtocolDeltaItem> = all_protos
        .into_iter()
        .map(|proto| {
            let bp = *base_proto_map.get(&proto).unwrap_or(&0.0);
            let cp = *cur_proto_map.get(&proto).unwrap_or(&0.0);
            ProtocolDeltaItem {
                protocol: proto,
                baseline_pct: (bp * 100.0).round() / 100.0,
                current_pct: (cp * 100.0).round() / 100.0,
                delta_pct: ((cp - bp) * 100.0).round() / 100.0,
            }
        })
        .collect();
    protocol_deltas.sort_by(|a, b| {
        b.delta_pct
            .abs()
            .partial_cmp(&a.delta_pct.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let length_deltas: Vec<LengthBucketDeltaItem> = RFC2544_LABELS
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let bp = baseline_stats
                .length_distribution
                .get(i)
                .map(|x| x.ratio_pct)
                .unwrap_or(0.0);
            let cp = cur_stats
                .length_distribution
                .get(i)
                .map(|x| x.ratio_pct)
                .unwrap_or(0.0);
            LengthBucketDeltaItem {
                label: (*label).to_string(),
                baseline_pct: (bp * 100.0).round() / 100.0,
                current_pct: (cp * 100.0).round() / 100.0,
                delta_pct: ((cp - bp) * 100.0).round() / 100.0,
            }
        })
        .collect();

    let base_ip_set: BTreeSet<&str> = baseline_stats.active_ips.iter().map(|s| s.as_str()).collect();
    let cur_ip_set: BTreeSet<&str> = cur_stats.active_ips.iter().map(|s| s.as_str()).collect();

    let new_external_ips: Vec<String> = cur_ip_set
        .difference(&base_ip_set)
        .map(|s| (*s).to_string())
        .take(50)
        .collect();
    let disappeared_ips: Vec<String> = base_ip_set
        .difference(&cur_ip_set)
        .map(|s| (*s).to_string())
        .take(50)
        .collect();

    let pps_change_pct = pct_change(baseline_avg_pps, cur_avg_pps);
    let bps_change_pct = pct_change(baseline_avg_bps, cur_avg_bps);
    let entropy_delta = cur_stats.avg_entropy - baseline_stats.avg_entropy;
    let jitter_delta_ms = cur_stats.jitter_ms - baseline_stats.jitter_ms;
    let avg_len_delta = cur_stats.avg_packet_len - baseline_stats.avg_packet_len;

    let mut anomaly_reasons = Vec::new();
    let mut score = 0u32;

    if entropy_delta.abs() >= 1.2 {
        score += 2;
        anomaly_reasons.push(format!(
            "负载平均信息熵偏移 {:+.2} bits/byte（可能出现加密通道、隧道封装或协议结构变化）",
            entropy_delta
        ));
    }
    if let Some(top_shift) = protocol_deltas.first() {
        if top_shift.delta_pct.abs() >= 20.0 {
            score += 2;
            anomaly_reasons.push(format!(
                "协议 {} 占比大幅偏移 {:+.1}%（基线 {:.1}% -> 当前 {:.1}%）",
                top_shift.protocol, top_shift.delta_pct, top_shift.baseline_pct, top_shift.current_pct
            ));
        }
    }
    if !new_external_ips.is_empty() && baseline_stats.total_packets > 0 {
        score += if new_external_ips.len() >= 5 { 2 } else { 1 };
        anomaly_reasons.push(format!(
            "发现 {} 个基线未收录的活跃 IP（示例: {}）",
            new_external_ips.len(),
            new_external_ips.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    if baseline_avg_bps > 0.0 && bps_change_pct.abs() >= 100.0 {
        score += 1;
        anomaly_reasons.push(format!("平均吞吐速率变化 {:+.1}%", bps_change_pct));
    }
    if jitter_delta_ms > 20.0 {
        score += 1;
        anomaly_reasons.push(format!("包间隔抖动 MAD 上升 +{:.2} ms", jitter_delta_ms));
    }

    let anomaly_verdict = if score >= 3 {
        "SIGNIFICANT_ANOMALY".to_string()
    } else if score >= 1 {
        "DRIFT_WARNING".to_string()
    } else {
        "NORMAL".to_string()
    };

    if anomaly_reasons.is_empty() {
        anomaly_reasons.push("实时流量协议结构、帧长分布与基线一致，未见显著漂移".to_string());
    }

    Ok(NetworkComparisonReport {
        baseline_name: baseline_name.to_string(),
        baseline_saved_at_ms,
        baseline_total_packets: baseline_stats.total_packets,
        current_total_packets: cur_stats.total_packets,
        baseline_avg_pps,
        current_avg_pps: cur_avg_pps,
        pps_change_pct: (pps_change_pct * 10.0).round() / 10.0,
        baseline_avg_bps,
        current_avg_bps: cur_avg_bps,
        bps_change_pct: (bps_change_pct * 10.0).round() / 10.0,
        entropy_delta: (entropy_delta * 1000.0).round() / 1000.0,
        jitter_delta_ms: (jitter_delta_ms * 1000.0).round() / 1000.0,
        avg_len_delta: (avg_len_delta * 10.0).round() / 10.0,
        protocol_deltas,
        length_deltas,
        new_external_ips,
        disappeared_ips,
        anomaly_verdict,
        anomaly_reasons,
    })
}

/// 执行双样本（基线或外部 PCAP vs 当前实时样本切片）多维智能对比
pub fn compare_network_samples_core(
    baseline_name: &str,
    baseline_saved_at_ms: u64,
    baseline_stats: &NetworkTrafficStats,
    baseline_avg_pps: f64,
    baseline_avg_bps: f64,
    current_samples: &[NetTrafficSample],
    current_buckets: &[IoBucketSummaryInput],
) -> Result<NetworkComparisonReport, String> {
    let cur_stats = analyze_network_traffic_stats_core(current_samples);
    compare_network_stats_core(
        baseline_name,
        baseline_saved_at_ms,
        baseline_stats,
        baseline_avg_pps,
        baseline_avg_bps,
        &cur_stats,
        current_buckets,
    )
}

pub fn compare_network_with_baseline_in_dir(
    dir: &Path,
    current_samples: &[NetTrafficSample],
    current_buckets: &[IoBucketSummaryInput],
) -> Result<NetworkComparisonReport, String> {
    let baseline = load_network_baseline_in_dir(dir)?
        .ok_or_else(|| "尚未固化任何网络黄金基线，请先点击「固化网络基线」".to_string())?;
    compare_network_samples_core(
        &baseline.name,
        baseline.saved_at_ms,
        &baseline.stats,
        baseline.avg_pps,
        baseline.avg_bps,
        current_samples,
        current_buckets,
    )
}

#[tauri::command]
pub fn save_network_baseline_cmd(
    name: Option<String>,
    samples: Option<Vec<NetTrafficSample>>,
    buckets: Vec<IoBucketSummaryInput>,
    use_backend_full: Option<bool>,
) -> Result<NetworkTrafficBaseline, String> {
    let dir = net_data_dir().ok_or_else(|| "无法定位应用数据目录".to_string())?;
    let stats = resolve_stats_backend_or_samples(samples, use_backend_full);
    save_network_baseline_stats_in_dir(&dir, name.as_deref().unwrap_or("默认网络黄金基线"), stats, &buckets)
}

#[tauri::command]
pub fn get_network_baseline_cmd() -> Result<Option<NetworkTrafficBaseline>, String> {
    let dir = net_data_dir().ok_or_else(|| "无法定位应用数据目录".to_string())?;
    load_network_baseline_in_dir(&dir)
}

#[tauri::command]
pub fn compare_network_with_baseline_cmd(
    samples: Option<Vec<NetTrafficSample>>,
    buckets: Vec<IoBucketSummaryInput>,
    use_backend_full: Option<bool>,
) -> Result<NetworkComparisonReport, String> {
    let dir = net_data_dir().ok_or_else(|| "无法定位应用数据目录".to_string())?;
    let baseline = load_network_baseline_in_dir(&dir)?
        .ok_or_else(|| "尚未固化任何网络黄金基线，请先点击「固化网络基线」".to_string())?;
    let cur_stats = resolve_stats_backend_or_samples(samples, use_backend_full);
    compare_network_stats_core(
        &baseline.name,
        baseline.saved_at_ms,
        &baseline.stats,
        baseline.avg_pps,
        baseline.avg_bps,
        &cur_stats,
        &buckets,
    )
}

#[tauri::command]
pub fn pick_and_compare_network_pcap_cmd(
    current_samples: Option<Vec<NetTrafficSample>>,
    current_buckets: Vec<IoBucketSummaryInput>,
    use_backend_full: Option<bool>,
) -> Result<Option<NetworkComparisonReport>, String> {
    let picked = crate::desktop_native::pick_native_file_dialog(
        "选择历史网络 .pcap 基准文件与实时流量进行多维对照",
        "PCAP Capture Files",
        "*.pcap",
    )?;
    let path = match picked {
        Some(p) => p,
        None => return Ok(None),
    };

    let records = crate::export_engine::import_pcap_file(&path)?;
    if records.is_empty() {
        return Err("所选 .pcap 文件不包含任何有效数据包".to_string());
    }
    let pcap_samples: Vec<NetTrafficSample> = records.iter().map(NetTrafficSample::from).collect();
    let pcap_stats = analyze_network_traffic_stats_core(&pcap_samples);
    let dur = if pcap_stats.duration_sec > 0.001 {
        pcap_stats.duration_sec
    } else {
        1.0
    };
    let pcap_avg_pps = pcap_stats.total_packets as f64 / dur;
    let pcap_avg_bps = pcap_stats.total_bytes as f64 / dur;
    let filename = Path::new(&path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "history.pcap".to_string());

    let cur_stats = resolve_stats_backend_or_samples(current_samples, use_backend_full);
    let report = compare_network_stats_core(
        &format!("PCAP 历史样本 ({})", filename),
        current_epoch_ms(),
        &pcap_stats,
        pcap_avg_pps,
        pcap_avg_bps,
        &cur_stats,
        &current_buckets,
    )?;
    Ok(Some(report))
}

// ============================================================================
// 4. 行业级网络安全巡检与统计审计报告生成器 (Markdown & HTML)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedNetworkReport {
    pub title: String,
    pub format: String,
    pub content: String,
    pub generated_at_ms: u64,
}

pub fn generate_network_audit_report_core(
    title: &str,
    format: &str,
    stats: &NetworkTrafficStats,
    scan_summary: Option<&NetworkPortScanSummary>,
    comparison: Option<&NetworkComparisonReport>,
) -> Result<GeneratedNetworkReport, String> {
    let safe_title = if title.trim().is_empty() {
        "Omni-Probe 网络深度流量统计与安全审计报告"
    } else {
        title.trim()
    };
    let fmt = format.trim().to_ascii_lowercase();
    if fmt != "markdown" && fmt != "md" && fmt != "html" {
        return Err(format!("不支持的报告格式: {} (仅支持 markdown / html)", format));
    }

    let now_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if fmt == "markdown" || fmt == "md" {
        let mut md = String::new();
        md.push_str(&format!("# {}\n\n", safe_title));
        md.push_str(&format!("- **生成时间**: `{}`\n", now_str));
        md.push_str(&format!(
            "- **统计样本**: `{} 包` | **总吞吐**: `{} Bytes` | **唯一主机**: `{} 台`\n",
            stats.total_packets, stats.total_bytes, stats.unique_ips
        ));
        md.push_str(&format!(
            "- **平均帧长**: `{:.1} B` | **平均信息熵**: `{:.3} bits/byte` | **包间隔均值**: `{:.2} ms` | **MAD 抖动**: `{:.2} ms`\n\n",
            stats.avg_packet_len, stats.avg_entropy, stats.mean_iat_ms, stats.jitter_ms
        ));

        md.push_str("## 1. 协议层次分布 (Protocol Hierarchy)\n\n");
        md.push_str("| 协议 | 包数 | 字节数 | 包占比 | 字节占比 |\n| --- | ---: | ---: | ---: | ---: |\n");
        for p in &stats.protocol_breakdown {
            md.push_str(&format!(
                "| `{}` | {} | {} | {:.1}% | {:.1}% |\n",
                p.protocol, p.packet_count, p.byte_count, p.packet_ratio_pct, p.byte_ratio_pct
            ));
        }

        md.push_str("\n## 2. Top Talkers 活跃终端带宽榜\n\n");
        md.push_str("| 主机 IP | 发送 (B) | 接收 (B) | 合计 (B) | 对端数量 |\n| --- | ---: | ---: | ---: | ---: |\n");
        for t in &stats.top_talkers {
            md.push_str(&format!(
                "| `{}` | {} | {} | {} | {} |\n",
                t.ip, t.tx_bytes, t.rx_bytes, t.total_bytes, t.peer_count
            ));
        }

        md.push_str("\n## 3. RFC 2544 标准报文长度分布\n\n");
        md.push_str("| 长度区间 | 包数 | 占比 |\n| --- | ---: | ---: |\n");
        for b in &stats.length_distribution {
            md.push_str(&format!("| {} | {} | {:.1}% |\n", b.label, b.packet_count, b.ratio_pct));
        }

        if let Some(scan) = scan_summary {
            md.push_str("\n## 4. 主动网段与端口 Banner 扫描台账\n\n");
            md.push_str(&format!(
                "- **目标范围**: `{}` | **端口表达**: `{}` | **开放端口**: `{}/{}` | **高危暴露**: `{}` | **探测口径**: {}\n\n",
                scan.target_spec, scan.port_spec, scan.open_count, scan.total_probes, scan.high_risk_count, scan.probe_method_note
            ));
            if !scan.open_items.is_empty() {
                md.push_str("| IP 地址 | 端口 | 识别协议 | RTT (ms) | 风险标注 | 应用 Banner 摘要 |\n| --- | ---: | --- | ---: | --- | --- |\n");
                for item in scan.open_items.iter().take(60) {
                    md.push_str(&format!(
                        "| `{}` | {} | `{}` | {:.2} | {} | `{}` |\n",
                        item.ip,
                        item.port,
                        item.protocol,
                        item.rtt_ms,
                        item.risk_flag.as_deref().unwrap_or("NORMAL"),
                        if item.banner.is_empty() { "-" } else { &item.banner }
                    ));
                }
            }
        }

        if let Some(cmp) = comparison {
            md.push_str("\n## 5. 实时流量 vs 黄金基线 / PCAP 对比诊断\n\n");
            md.push_str(&format!(
                "- **对比基准**: `{}` | **综合判定**: `{}`\n- **熵值变化**: `{:+.3} bits/byte` | **抖动变化**: `{:+.2} ms` | **新增活跃 IP**: `{}`\n",
                cmp.baseline_name,
                cmp.anomaly_verdict,
                cmp.entropy_delta,
                cmp.jitter_delta_ms,
                cmp.new_external_ips.len()
            ));
            for r in &cmp.anomaly_reasons {
                md.push_str(&format!("  - {}\n", r));
            }
        }

        return Ok(GeneratedNetworkReport {
            title: safe_title.to_string(),
            format: "markdown".to_string(),
            content: md,
            generated_at_ms: current_epoch_ms(),
        });
    }

    // 自包含 HTML 报告（全字段 strict html_escape 防 XSS）
    let mut proto_rows = String::new();
    for p in &stats.protocol_breakdown {
        proto_rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{:.1}%</td><td>{:.1}%</td></tr>",
            html_escape(&p.protocol),
            p.packet_count,
            p.byte_count,
            p.packet_ratio_pct,
            p.byte_ratio_pct
        ));
    }
    let mut talker_rows = String::new();
    for t in &stats.top_talkers {
        talker_rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&t.ip),
            t.tx_bytes,
            t.rx_bytes,
            t.total_bytes,
            t.peer_count
        ));
    }
    let mut len_rows = String::new();
    for b in &stats.length_distribution {
        len_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{:.1}%</td></tr>",
            html_escape(&b.label),
            b.packet_count,
            b.ratio_pct
        ));
    }

    let scan_section = if let Some(scan) = scan_summary {
        let mut items_html = String::new();
        for item in scan.open_items.iter().take(60) {
            items_html.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{:.2} ms</td><td>{}</td><td><code>{}</code></td></tr>",
                html_escape(&item.ip),
                item.port,
                html_escape(&item.protocol),
                item.rtt_ms,
                html_escape(item.risk_flag.as_deref().unwrap_or("NORMAL")),
                html_escape(if item.banner.is_empty() { "-" } else { &item.banner })
            ));
        }
        format!(
            "<h2>4. 主动网段与端口 Banner 扫描台账</h2><p>目标: <code>{}</code> | 端口: <code>{}</code> | 开放: {}/{} | 高危: {}</p><p class=\"note\">{}</p><table><thead><tr><th>IP</th><th>端口</th><th>协议</th><th>RTT</th><th>风险</th><th>Banner</th></tr></thead><tbody>{}</tbody></table>",
            html_escape(&scan.target_spec),
            html_escape(&scan.port_spec),
            scan.open_count,
            scan.total_probes,
            scan.high_risk_count,
            html_escape(&scan.probe_method_note),
            items_html
        )
    } else {
        String::new()
    };

    let cmp_section = if let Some(cmp) = comparison {
        let reasons_html: String = cmp
            .anomaly_reasons
            .iter()
            .map(|r| format!("<li>{}</li>", html_escape(r)))
            .collect();
        format!(
            "<h2>5. 实时流量 vs 黄金基线 / PCAP 对比结论</h2><p>基准: <strong>{}</strong> | 判定: <code>{}</code> | 熵差: {:+.3} | 抖动差: {:+.2} ms</p><ul>{}</ul>",
            html_escape(&cmp.baseline_name),
            html_escape(&cmp.anomaly_verdict),
            cmp.entropy_delta,
            cmp.jitter_delta_ms,
            reasons_html
        )
    } else {
        String::new()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<title>{title}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 28px; color: #1e293b; background: #f8fafc; }}
h1 {{ font-size: 20px; border-bottom: 2px solid #0284c7; padding-bottom: 8px; }}
h2 {{ font-size: 15px; margin-top: 22px; color: #0f172a; }}
.kpi {{ display: grid; grid-template-columns: repeat(4, minmax(140px, 1fr)); gap: 10px; margin: 14px 0; }}
.card {{ background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 10px 12px; }}
.card .v {{ font-size: 16px; font-weight: 700; color: #0369a1; margin-top: 4px; }}
.note {{ font-size: 12px; color: #475569; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 8px; background: #fff; font-size: 12px; }}
th, td {{ border: 1px solid #cbd5e1; padding: 6px 8px; text-align: left; }}
th {{ background: #e2e8f0; }}
code {{ background: #f1f5f9; padding: 1px 4px; border-radius: 3px; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="note">生成时间: {now_str}</p>
<div class="kpi">
  <div class="card"><div>统计总包数</div><div class="v">{pkts}</div></div>
  <div class="card"><div>总吞吐字节</div><div class="v">{bytes} B</div></div>
  <div class="card"><div>唯一终端 IP</div><div class="v">{ips}</div></div>
  <div class="card"><div>MAD 抖动 / 熵值</div><div class="v">{jitter:.2} ms / {entropy:.2}</div></div>
</div>
<h2>1. 协议层次分布</h2>
<table><thead><tr><th>协议</th><th>包数</th><th>字节数</th><th>包占比</th><th>字节占比</th></tr></thead><tbody>{proto_rows}</tbody></table>
<h2>2. Top Talkers 活跃主机带宽榜</h2>
<table><thead><tr><th>主机 IP</th><th>发送 (B)</th><th>接收 (B)</th><th>合计 (B)</th><th>对端数</th></tr></thead><tbody>{talker_rows}</tbody></table>
<h2>3. RFC 2544 报文长度分布</h2>
<table><thead><tr><th>长度区间</th><th>包数</th><th>占比</th></tr></thead><tbody>{len_rows}</tbody></table>
{scan_section}
{cmp_section}
</body>
</html>"#,
        title = html_escape(safe_title),
        now_str = html_escape(&now_str),
        pkts = stats.total_packets,
        bytes = stats.total_bytes,
        ips = stats.unique_ips,
        jitter = stats.jitter_ms,
        entropy = stats.avg_entropy,
        proto_rows = proto_rows,
        talker_rows = talker_rows,
        len_rows = len_rows,
        scan_section = scan_section,
        cmp_section = cmp_section,
    );

    Ok(GeneratedNetworkReport {
        title: safe_title.to_string(),
        format: "html".to_string(),
        content: html,
        generated_at_ms: current_epoch_ms(),
    })
}

#[tauri::command]
pub fn export_network_audit_report_cmd(
    title: Option<String>,
    format: String,
    samples: Option<Vec<NetTrafficSample>>,
    comparison: Option<NetworkComparisonReport>,
    use_backend_full: Option<bool>,
) -> Result<Option<String>, String> {
    let stats = resolve_stats_backend_or_samples(samples, use_backend_full);
    let scan_snapshot = LAST_SCAN_SUMMARY
        .read()
        .ok()
        .and_then(|g| g.clone());
    let report = generate_network_audit_report_core(
        title.as_deref().unwrap_or("Omni-Probe 网络深度流量统计与安全审计报告"),
        &format,
        &stats,
        scan_snapshot.as_ref(),
        comparison.as_ref(),
    )?;

    let (ext, filter_name) = if report.format == "html" {
        ("html", "HTML Audit Report")
    } else {
        ("md", "Markdown Report")
    };
    let default_name = format!(
        "omni_network_audit_{}.{}",
        chrono::Local::now().format("%Y%m%d_%H%M%S"),
        ext
    );
    let outcome = crate::desktop_native::save_text_with_native_dialog(
        &default_name,
        "导出网络深度统计与安全审计报告",
        filter_name,
        &format!("*.{}", ext),
        &report.content,
    )?;
    if outcome.saved {
        Ok(outcome.path)
    } else {
        Ok(None)
    }
}

// ============================================================================
// 5. 全覆盖单元测试与极限边界防御校验
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn sample_pkt(
        proto: &str,
        src: &str,
        dst: &str,
        sport: u16,
        dport: u16,
        len: usize,
        ts_ns: u128,
        entropy: f64,
    ) -> NetTrafficSample {
        NetTrafficSample {
            protocol: proto.to_string(),
            transport: "TCP".to_string(),
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            src_port: sport,
            dst_port: dport,
            length: len,
            timestamp_ns: ts_ns,
            entropy,
        }
    }

    #[test]
    fn test_target_and_port_parser_edge_cases() {
        // 1. 合法 CIDR /30 -> 2 个可用主机 (192.168.1.1, 192.168.1.2)
        let hosts = parse_target_spec("192.168.1.0/30").expect("CIDR /30 解析失败");
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[1], Ipv4Addr::new(192, 168, 1, 2));

        // 2. 连字符 IP 段
        let range_hosts = parse_target_spec("10.0.0.10-12").expect("IP 范围解析失败");
        assert_eq!(range_hosts.len(), 3);

        // 3. 极限边界拒绝: /8 超大网段防止扫描风暴
        assert!(parse_target_spec("10.0.0.0/8").is_err());
        assert!(parse_target_spec("192.168.1.20-10").is_err());
        assert!(parse_target_spec("").is_err());

        // 4. 端口区间 + 别名 + 0端口防错
        let ports = parse_port_spec("21-23,80,443,80").expect("端口解析失败");
        assert_eq!(ports, vec![21, 22, 23, 80, 443]);
        assert!(parse_port_spec("ics").expect("ics 模板失败").contains(&502));
        assert!(parse_port_spec("0,80").is_err());
        assert!(parse_port_spec("443-80").is_err());
    }

    #[test]
    fn test_traffic_stats_empty_and_rfc2544_jitter() {
        // 极限空数据: 不崩溃、不产生 NaN
        let empty = analyze_network_traffic_stats_core(&[]);
        assert_eq!(empty.total_packets, 0);
        assert_eq!(empty.length_distribution.len(), 7);
        assert!(!empty.jitter_ms.is_nan());

        // 构造真实包流含不同长度档位与包间隔
        let samples = vec![
            sample_pkt("HTTP", "192.168.1.10", "10.0.0.5", 50001, 80, 60, 1_000_000_000, 3.2),
            sample_pkt("MODBUS", "192.168.1.20", "192.168.1.30", 50002, 502, 128, 1_010_000_000, 2.1),
            sample_pkt("HTTPS", "192.168.1.10", "10.0.0.5", 50003, 443, 1480, 1_020_000_000, 7.8),
            sample_pkt("HTTPS", "10.0.0.5", "192.168.1.10", 443, 50003, 1600, 1_035_000_000, 7.9),
        ];
        let stats = analyze_network_traffic_stats_core(&samples);
        assert_eq!(stats.total_packets, 4);
        assert_eq!(stats.total_bytes, 60 + 128 + 1480 + 1600);
        assert_eq!(stats.unique_ips, 4);
        assert_eq!(stats.length_distribution[0].packet_count, 1); // 0-63B
        assert_eq!(stats.length_distribution[2].packet_count, 1); // 128-255B
        assert_eq!(stats.length_distribution[5].packet_count, 1); // 1024-1518B
        assert_eq!(stats.length_distribution[6].packet_count, 1); // >1518B
        assert!(stats.mean_iat_ms > 0.0);
        assert!(stats.jitter_ms >= 0.0);
        assert_eq!(stats.protocol_breakdown[0].protocol, "HTTPS");
    }

    #[test]
    fn test_baseline_save_compare_and_xss_escape_report() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "omni_probe_net_intel_test_{}",
            current_epoch_ms()
        ));
        let _ = fs::remove_dir_all(&tmp_dir);

        let base_samples = vec![
            sample_pkt("MODBUS", "192.168.1.10", "192.168.1.50", 4000, 502, 80, 1_000_000_000, 2.0),
            sample_pkt("MODBUS", "192.168.1.50", "192.168.1.10", 502, 4000, 84, 1_020_000_000, 2.1),
        ];
        let base_buckets = vec![IoBucketSummaryInput {
            packet_count: 20,
            byte_count: 1640,
            avg_rtt_ms: 1.5,
            retrans_count: 0,
        }];

        // 空基线拦截
        assert!(save_network_baseline_in_dir(&tmp_dir, "bad", &[], &[]).is_err());

        let saved = save_network_baseline_in_dir(&tmp_dir, "工控基线", &base_samples, &base_buckets)
            .expect("保存基线失败");
        assert_eq!(saved.stats.total_packets, 2);

        // 注入高熵未知协议与新外联 IP 触发对比异常判定
        let cur_samples = vec![
            sample_pkt("<script>alert(1)</script>", "192.168.1.10", "45.33.12.99", 4001, 443, 1400, 2_000_000_000, 7.9),
            sample_pkt("<script>alert(1)</script>", "45.33.12.99", "192.168.1.10", 443, 4001, 1450, 2_100_000_000, 7.8),
        ];
        let cur_buckets = vec![IoBucketSummaryInput {
            packet_count: 200,
            byte_count: 285000,
            avg_rtt_ms: 45.0,
            retrans_count: 3,
        }];

        let cmp = compare_network_with_baseline_in_dir(&tmp_dir, &cur_samples, &cur_buckets)
            .expect("对比基线失败");
        assert_eq!(cmp.anomaly_verdict, "SIGNIFICANT_ANOMALY");
        assert!(cmp.new_external_ips.contains(&"45.33.12.99".to_string()));

        // HTML 报告防 XSS 转义检验
        let stats = analyze_network_traffic_stats_core(&cur_samples);
        let report = generate_network_audit_report_core(
            "<img onerror=alert(1)>",
            "html",
            &stats,
            None,
            Some(&cmp),
        )
        .expect("生成 HTML 报告失败");
        let lower_html = report.content.to_ascii_lowercase();
        assert!(!lower_html.contains("<script>"));
        assert!(!lower_html.contains("<img onerror"));
        assert!(lower_html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn test_loopback_banner_and_port_scan_integration() {
        // 起一个真实本地 TCP Echo/Banner 服务端，验证主动端口扫描 & Banner 提取无幻觉真实闭环
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定测试端口失败");
        let port = listener.local_addr().unwrap().port();
        // 分配独立临时端口并立即关闭，避免 port+1 与其他并行异步测试的 TcpListener::bind(":0") 递增撞车
        let closed_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定关闭参考端口失败");
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        let srv = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"SSH-2.0-OmniProbeMockBanner\r\n").await;
                tokio::time::sleep(Duration::from_millis(80)).await;
            }
        });

        let port_spec = format!("{},{}", port, closed_port);
        let summary = run_network_port_scan_core(
            "127.0.0.1",
            &port_spec,
            Some(800),
            true,
            false,
        )
        .await
        .expect("真实环回扫描失败");

        assert_eq!(summary.open_count, 1);
        assert_eq!(summary.open_items[0].port, port);
        assert!(summary.open_items[0].banner.contains("OmniProbeMockBanner"));
        let _ = srv.await;
    }

    #[tokio::test]
    async fn test_rate_limit_boundaries_512_hosts_and_2048_probes() {
        // 1. /23 可用主机恰为 510 个 (<= 512 上限)，允许执行解析
        let hosts_23 = parse_target_spec("192.168.0.0/23").expect("/23 合法主机数应解析成功");
        assert_eq!(hosts_23.len(), 510);

        // 2. /22 (1022 主机) 或连续 IP 超 512 主机必须 Fail-Fast 硬拒绝
        assert!(parse_target_spec("192.168.0.0/22").is_err());
        assert!(parse_target_spec("192.168.0.0-192.168.2.5").is_err());

        // 3. 254 主机 * 20 端口 = 5080 > 2048，并发引擎必须拦截并禁止派发协程
        let overflow_err = run_network_port_scan_core("192.168.1.0/24", "1-20", Some(200), false, false)
            .await
            .expect_err("超出 2048 探测上限必须被拦截");
        assert!(overflow_err.contains("2048"));
    }

    #[test]
    fn test_live_accumulator_exceeds_2500_cap_and_zero_truncation() {
        let mut acc = LiveNetAccumulator::default();
        let mut all_samples = Vec::with_capacity(5000);
        for i in 0..5000usize {
            let s = sample_pkt(
                if i % 3 == 0 { "MODBUS" } else { "HTTP" },
                "192.168.1.10",
                "192.168.1.50",
                40000 + (i % 100) as u16,
                if i % 3 == 0 { 502 } else { 80 },
                64 + (i % 1500),
                1_700_000_000_000 + (i as u128) * 1_000_000,
                3.5,
            );
            acc.ingest_sample(&s);
            all_samples.push(s);
        }

        let live_stats = acc.snapshot_stats();
        let full_batch_stats = analyze_network_traffic_stats_core(&all_samples);
        assert_eq!(live_stats.total_packets, 5000, "后端累加器禁止出现 2500 条截断");
        assert_eq!(live_stats.total_bytes, full_batch_stats.total_bytes);
        assert_eq!(live_stats.length_distribution.len(), 7);
        let sum_bucket_pkts: usize = live_stats.length_distribution.iter().map(|b| b.packet_count).sum();
        assert_eq!(sum_bucket_pkts, 5000);
    }

    #[tokio::test]
    async fn test_http_head_and_redis_unauth_banner_integration() {
        // 1. 真实本地 HTTP 服务验证 HEAD 探针读取 Server 头
        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = http_listener.local_addr().unwrap().port();
        let http_srv = tokio::spawn(async move {
            if let Ok((mut s, _)) = http_listener.accept().await {
                let mut req_buf = [0u8; 256];
                let _ = s.read(&mut req_buf).await;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nServer: OmniLab-Nginx/1.25\r\nContent-Length: 0\r\n\r\n").await;
            }
        });
        let http_res = probe_single_tcp_banner_with_mode(
            Ipv4Addr::LOCALHOST,
            http_port,
            Duration::from_millis(800),
            TcpProbeMode::Http,
        )
        .await;
        assert_eq!(http_res.status, "OPEN");
        assert!(http_res.banner.contains("OmniLab-Nginx/1.25"));
        let _ = http_srv.await;

        // 2. 真实本地 Redis 模拟服务验证 PING -> +PONG -> UNAUTH_REDIS 风险标注
        let redis_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redis_port = redis_listener.local_addr().unwrap().port();
        let redis_srv = tokio::spawn(async move {
            if let Ok((mut s, _)) = redis_listener.accept().await {
                let mut req_buf = [0u8; 64];
                if let Ok(n) = s.read(&mut req_buf).await {
                    if String::from_utf8_lossy(&req_buf[..n]).contains("PING") {
                        let _ = s.write_all(b"+PONG\r\n").await;
                    }
                }
            }
        });
        let redis_res = probe_single_tcp_banner_with_mode(
            Ipv4Addr::LOCALHOST,
            redis_port,
            Duration::from_millis(800),
            TcpProbeMode::Redis,
        )
        .await;
        assert_eq!(redis_res.status, "OPEN");
        assert_eq!(redis_res.risk_flag.as_deref(), Some("UNAUTH_REDIS"));
        assert!(redis_res.is_high_risk);
        let _ = redis_srv.await;
    }

    #[tokio::test]
    async fn test_udp_payload_triggered_dns_and_ntp_integration() {
        // 1. 真实本地 UDP DNS 服务端仅在收到合理 Query 后才返回响应
        let dns_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_port = dns_sock.local_addr().unwrap().port();
        let dns_srv = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            if let Ok((n, peer)) = dns_sock.recv_from(&mut buf).await {
                if n >= 12 {
                    let mut resp = buf[..n].to_vec();
                    resp[2] |= 0x80; // 设置 QR = 1 (Response)
                    let _ = dns_sock.send_to(&resp, peer).await;
                }
            }
        });
        let dns_res = probe_single_udp_kind(
            Ipv4Addr::LOCALHOST,
            dns_port,
            Duration::from_millis(600),
            UdpProbeKind::Dns,
        )
        .await;
        assert!(dns_res.is_some());
        assert_eq!(dns_res.unwrap().protocol, "DNS_UDP");
        let _ = dns_srv.await;

        // 2. 静默/无服务 UDP 端口严禁假报 OPEN|FILTERED
        let dead_udp_port = if dns_port < 64000 { dns_port + 5 } else { dns_port - 5 };
        let no_resp = probe_single_udp_kind(
            Ipv4Addr::LOCALHOST,
            dead_udp_port,
            Duration::from_millis(180),
            UdpProbeKind::Ntp,
        )
        .await;
        assert!(no_resp.is_none());
    }
}
