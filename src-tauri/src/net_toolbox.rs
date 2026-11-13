// ============================================================================
// Omni-Probe 网工高频原子工具引擎 (Network Engineering Atomic Toolbox)
//
// 核心工业模块：
// 1. IPv4 / IPv6 子网掩码、VLSM 子网规划与 OSPF/ACL 通配符算力核心 (O(1) 位运算)
// 2. 纯原生 RFC 1035 DNS UDP 报文解析器 (A/AAAA/MX/TXT/CNAME/PTR/NS/SRV/SOA, 压缩指针防环)
// 3. 多采样 TCPing (Min/Avg/Max/P95/Mdev 抖动) 与 HTTP(S) 分阶段耗时探针
// 4. 真实 RFC 1350 TFTP UDP 微服务器 (RRQ/WRQ/ACK/DATA/ERROR) + 安全隔离 HTTP 固件分发微服
//    全链路内置 Path Traversal 目录逃逸物理防线与传输 SHA-256 审计记录
// ============================================================================

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const MAX_VLSM_SUBNETS: usize = 512;
const MAX_TRANSFER_LOGS: usize = 128;
const MAX_DNS_POINTER_JUMPS: usize = 16;

// ============================================================================
// 第一部分：IPv4 / IPv6 子网、通配符与 VLSM 划分子网引擎 (O(1) / O(K))
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetCalcResult {
    pub ip_version: u8, // 4 or 6
    pub input_normalized: String,
    pub prefix_len: u8,
    pub network_address: String,
    pub broadcast_address: String,
    pub netmask: String,
    pub wildcard_mask: String,
    pub first_usable_ip: String,
    pub last_usable_ip: String,
    pub total_addresses: String,
    pub usable_hosts: String,
    pub address_class: String,
    pub binary_view: String,
    pub ptr_reverse_domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlsmSubnetSlice {
    pub index: usize,
    pub cidr: String,
    pub network_address: String,
    pub broadcast_address: String,
    pub first_usable: String,
    pub last_usable: String,
    pub usable_hosts: String,
}

fn netmask_v4_to_prefix(mask: Ipv4Addr) -> Result<u8, String> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones() as u8;
    let canonical = if ones == 0 {
        0u32
    } else {
        u32::MAX.checked_shl(32 - ones as u32).unwrap_or(0)
    };
    if bits != canonical {
        return Err(format!("非法非连续子网掩码: {}", mask));
    }
    Ok(ones)
}

fn prefix_v4_to_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_v6_to_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else if prefix >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn classify_ipv4_range(ip: Ipv4Addr) -> &'static str {
    let o = ip.octets();
    if ip.is_loopback() {
        "回环保留地址 (127.0.0.0/8, RFC 1122)"
    } else if ip.is_private() {
        "RFC 1918 私有局域网地址"
    } else if o[0] == 100 && (o[1] & 0xC0) == 64 {
        "RFC 6598 运营商级 NAT (CGNAT 100.64.0.0/10)"
    } else if ip.is_link_local() {
        "RFC 3927 链路本地 APIPA (169.254.0.0/16)"
    } else if ip.is_multicast() {
        "组播/多播地址 (224.0.0.0/4)"
    } else if ip.is_unspecified() {
        "未指定全零地址 (0.0.0.0)"
    } else {
        "公网可路由单播地址 (Global Unicast)"
    }
}

fn classify_ipv6_range(ip: Ipv6Addr) -> &'static str {
    let segs = ip.segments();
    if ip.is_loopback() {
        "IPv6 回环地址 (::1/128)"
    } else if ip.is_unspecified() {
        "IPv6 未指定地址 (::/128)"
    } else if ip.is_multicast() {
        "IPv6 多播地址 (ff00::/8)"
    } else if (segs[0] & 0xFFC0) == 0xFE80 {
        "IPv6 链路本地地址 (fe80::/10)"
    } else if (segs[0] & 0xFE00) == 0xFC00 {
        "IPv6 唯一本地私有地址 ULA (fc00::/7, RFC 4193)"
    } else if (segs[0] & 0xE000) == 0x2000 {
        "IPv6 全球单播地址 (2000::/3)"
    } else {
        "IPv6 特殊/保留前缀"
    }
}

fn parse_cidr_or_mask_input(input: &str) -> Result<(IpAddr, u8), String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("输入不能为空（示例: 192.168.10.5/24 或 10.0.0.1 255.255.252.0 或 2001:db8::1/64）".into());
    }
    if let Some((ip_part, pref_part)) = trimmed.split_once('/') {
        let ip: IpAddr = ip_part
            .trim()
            .parse()
            .map_err(|_| format!("非法 IP 地址格式: {}", ip_part.trim()))?;
        let prefix: u8 = pref_part
            .trim()
            .parse()
            .map_err(|_| format!("非法前缀长度: {}", pref_part.trim()))?;
        match ip {
            IpAddr::V4(_) if prefix <= 32 => Ok((ip, prefix)),
            IpAddr::V6(_) if prefix <= 128 => Ok((ip, prefix)),
            _ => Err(format!("前缀 /{} 超出协议地址位宽边界", prefix)),
        }
    } else {
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() == 2 {
            let ip: Ipv4Addr = parts[0]
                .parse()
                .map_err(|_| format!("非法 IPv4 地址: {}", parts[0]))?;
            let mask: Ipv4Addr = parts[1]
                .parse()
                .map_err(|_| format!("非法点分十进制掩码: {}", parts[1]))?;
            let prefix = netmask_v4_to_prefix(mask)?;
            Ok((IpAddr::V4(ip), prefix))
        } else if parts.len() == 1 {
            let ip: IpAddr = parts[0]
                .parse()
                .map_err(|_| format!("非法 IP 或 CIDR 格式: {}", parts[0]))?;
            let def_pref = match ip {
                IpAddr::V4(_) => 24,
                IpAddr::V6(_) => 64,
            };
            Ok((ip, def_pref))
        } else {
            Err("无法识别的网段格式，请使用 IP/Prefix 或 IP Netmask".into())
        }
    }
}

/// IPv4/IPv6 子网计算核心 (O(1) 位运算)
pub fn calculate_subnet_info_core(input: &str) -> Result<SubnetCalcResult, String> {
    let (ip, prefix) = parse_cidr_or_mask_input(input)?;
    match ip {
        IpAddr::V4(v4) => {
            let ip_u32 = u32::from(v4);
            let mask_u32 = prefix_v4_to_u32(prefix);
            let wild_u32 = !mask_u32;
            let net_u32 = ip_u32 & mask_u32;
            let bcast_u32 = net_u32 | wild_u32;
            let total_addrs: u64 = 1u64 << (32 - prefix);

            let (first_ip, last_ip, usable) = match prefix {
                32 => (Ipv4Addr::from(net_u32), Ipv4Addr::from(net_u32), 1u64),
                31 => (Ipv4Addr::from(net_u32), Ipv4Addr::from(bcast_u32), 2u64), // RFC 3021 点对点链路
                _ => (
                    Ipv4Addr::from(net_u32 + 1),
                    Ipv4Addr::from(bcast_u32 - 1),
                    total_addrs.saturating_sub(2),
                ),
            };
            let octs = v4.octets();
            let ptr = format!("{}.{}.{}.{}.in-addr.arpa", octs[3], octs[2], octs[1], octs[0]);
            let bin_ip = format!(
                "{:08b}.{:08b}.{:08b}.{:08b}",
                octs[0], octs[1], octs[2], octs[3]
            );
            Ok(SubnetCalcResult {
                ip_version: 4,
                input_normalized: format!("{}/{}", v4, prefix),
                prefix_len: prefix,
                network_address: Ipv4Addr::from(net_u32).to_string(),
                broadcast_address: Ipv4Addr::from(bcast_u32).to_string(),
                netmask: Ipv4Addr::from(mask_u32).to_string(),
                wildcard_mask: Ipv4Addr::from(wild_u32).to_string(),
                first_usable_ip: first_ip.to_string(),
                last_usable_ip: last_ip.to_string(),
                total_addresses: total_addrs.to_string(),
                usable_hosts: usable.to_string(),
                address_class: classify_ipv4_range(v4).to_string(),
                binary_view: bin_ip,
                ptr_reverse_domain: ptr,
            })
        }
        IpAddr::V6(v6) => {
            let ip_u128 = u128::from(v6);
            let mask_u128 = prefix_v6_to_u128(prefix);
            let wild_u128 = !mask_u128;
            let net_u128 = ip_u128 & mask_u128;
            let end_u128 = net_u128 | wild_u128;

            let first_u128 = if prefix >= 127 { net_u128 } else { net_u128 + 1 };
            let total_str = if prefix == 0 {
                "2^128".to_string()
            } else {
                let host_bits = 128 - prefix;
                if host_bits <= 64 {
                    (1u128 << host_bits).to_string()
                } else {
                    format!("2^{}", host_bits)
                }
            };
            let usable_str = match prefix {
                128 => "1".to_string(),
                127 => "2".to_string(),
                p if 128 - p <= 64 => ((1u128 << (128 - p)) - 1).to_string(), // IPv6 无广播地址，仅保留全零 Subnet-Router 任播
                p => format!("2^{} - 1", 128 - p),
            };
            let full_hex = format!("{:032x}", ip_u128);
            let ptr = full_hex
                .chars()
                .rev()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(".")
                + ".ip6.arpa";

            let segs = v6.segments();
            let expanded = format!(
                "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7]
            );
            Ok(SubnetCalcResult {
                ip_version: 6,
                input_normalized: format!("{}/{}", v6, prefix),
                prefix_len: prefix,
                network_address: Ipv6Addr::from(net_u128).to_string(),
                broadcast_address: Ipv6Addr::from(end_u128).to_string(),
                netmask: Ipv6Addr::from(mask_u128).to_string(),
                wildcard_mask: Ipv6Addr::from(wild_u128).to_string(),
                first_usable_ip: Ipv6Addr::from(first_u128).to_string(),
                last_usable_ip: Ipv6Addr::from(end_u128).to_string(),
                total_addresses: total_str,
                usable_hosts: usable_str,
                address_class: classify_ipv6_range(v6).to_string(),
                binary_view: expanded,
                ptr_reverse_domain: ptr,
            })
        }
    }
}

/// VLSM 等长子网划分子网器 (受限最多 MAX_VLSM_SUBNETS 防 OOM, 复杂度 O(K))
pub fn split_vlsm_subnets_core(parent_cidr: &str, target_prefix: u8) -> Result<Vec<VlsmSubnetSlice>, String> {
    let (ip, parent_prefix) = parse_cidr_or_mask_input(parent_cidr)?;
    if target_prefix <= parent_prefix {
        return Err(format!(
            "目标子网前缀 /{} 必须大于父网段前缀 /{}",
            target_prefix, parent_prefix
        ));
    }
    let delta = target_prefix - parent_prefix;
    if delta > 12 || (1usize << delta) > MAX_VLSM_SUBNETS {
        return Err(format!(
            "单次子网切分数量过大 (2^{})，安全上限为 {} 个子网",
            delta, MAX_VLSM_SUBNETS
        ));
    }
    let count = 1usize << delta;
    let mut slices = Vec::with_capacity(count);

    match ip {
        IpAddr::V4(v4) => {
            if target_prefix > 32 {
                return Err("IPv4 子网前缀不能超过 /32".into());
            }
            let base = u32::from(v4) & prefix_v4_to_u32(parent_prefix);
            let step = 1u64 << (32 - target_prefix);
            for i in 0..count {
                let net_u32 = base.wrapping_add((i as u64 * step) as u32);
                let bcast_u32 = net_u32.wrapping_add((step - 1) as u32);
                let (first, last, usable) = match target_prefix {
                    32 => (Ipv4Addr::from(net_u32), Ipv4Addr::from(net_u32), 1u64),
                    31 => (Ipv4Addr::from(net_u32), Ipv4Addr::from(bcast_u32), 2u64),
                    _ => (
                        Ipv4Addr::from(net_u32 + 1),
                        Ipv4Addr::from(bcast_u32 - 1),
                        step.saturating_sub(2),
                    ),
                };
                slices.push(VlsmSubnetSlice {
                    index: i + 1,
                    cidr: format!("{}/{}", Ipv4Addr::from(net_u32), target_prefix),
                    network_address: Ipv4Addr::from(net_u32).to_string(),
                    broadcast_address: Ipv4Addr::from(bcast_u32).to_string(),
                    first_usable: first.to_string(),
                    last_usable: last.to_string(),
                    usable_hosts: usable.to_string(),
                });
            }
        }
        IpAddr::V6(v6) => {
            if target_prefix > 128 {
                return Err("IPv6 子网前缀不能超过 /128".into());
            }
            let base = u128::from(v6) & prefix_v6_to_u128(parent_prefix);
            let host_bits = 128 - target_prefix;
            let step: u128 = 1u128 << host_bits;
            for i in 0..count {
                let net_u128 = base.wrapping_add((i as u128).wrapping_mul(step));
                let end_u128 = net_u128.wrapping_add(step - 1);
                let usable = if host_bits <= 64 {
                    if target_prefix >= 127 {
                        step.to_string()
                    } else {
                        (step - 1).to_string()
                    }
                } else {
                    format!("2^{} - 1", host_bits)
                };
                slices.push(VlsmSubnetSlice {
                    index: i + 1,
                    cidr: format!("{}/{}", Ipv6Addr::from(net_u128), target_prefix),
                    network_address: Ipv6Addr::from(net_u128).to_string(),
                    broadcast_address: Ipv6Addr::from(end_u128).to_string(),
                    first_usable: Ipv6Addr::from(if target_prefix >= 127 { net_u128 } else { net_u128 + 1 }).to_string(),
                    last_usable: Ipv6Addr::from(end_u128).to_string(),
                    usable_hosts: usable,
                });
            }
        }
    }
    Ok(slices)
}

#[tauri::command]
pub fn calculate_subnet_info_cmd(input: String) -> Result<SubnetCalcResult, String> {
    calculate_subnet_info_core(&input)
}

#[tauri::command]
pub fn split_vlsm_subnets_cmd(parent_cidr: String, target_prefix: u8) -> Result<Vec<VlsmSubnetSlice>, String> {
    split_vlsm_subnets_core(&parent_cidr, target_prefix)
}

// ============================================================================
// 第二部分：纯原生 RFC 1035 DNS UDP 查询器 + TCPing + HTTP(S) 分阶段诊断
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswerRecord {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryReport {
    pub domain: String,
    pub query_type: String,
    pub dns_server: String,
    pub rcode_name: String,
    pub rtt_ms: f64,
    pub answers: Vec<DnsAnswerRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpingReport {
    pub host: String,
    pub port: u16,
    pub resolved_ip: String,
    pub attempts: usize,
    pub succeeded: usize,
    pub loss_pct: f64,
    pub min_ms: f64,
    pub avg_ms: f64,
    pub max_ms: f64,
    pub p95_ms: f64,
    pub jitter_mdev_ms: f64,
    pub samples_ms: Vec<Option<f64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTimingReport {
    pub url: String,
    pub status_code: u16,
    pub final_url: String,
    pub tcp_connect_ms: f64,
    pub total_ttfb_ms: f64,
    pub body_size_bytes: usize,
    pub server_header: String,
    pub content_type: String,
}

fn dns_qtype_from_str(q: &str) -> Result<(&'static str, u16), String> {
    match q.trim().to_uppercase().as_str() {
        "A" | "" => Ok(("A", 1)),
        "NS" => Ok(("NS", 2)),
        "CNAME" => Ok(("CNAME", 5)),
        "SOA" => Ok(("SOA", 6)),
        "PTR" => Ok(("PTR", 12)),
        "MX" => Ok(("MX", 15)),
        "TXT" => Ok(("TXT", 16)),
        "AAAA" => Ok(("AAAA", 28)),
        "SRV" => Ok(("SRV", 33)),
        other => Err(format!("不支持的 DNS 记录类型: {}", other)),
    }
}

fn dns_qtype_name(code: u16) -> &'static str {
    match code {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        _ => "OTHER",
    }
}

/// 构造 RFC 1035 标准 DNS UDP 查询报文
pub fn encode_dns_query_packet(tx_id: u16, domain: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let clean = domain.trim().trim_end_matches('.');
    if clean.is_empty() || clean.len() > 253 {
        return Err("DNS 查询域名长度非法 (1..253)".into());
    }
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1 (期望递归查询)
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for label in clean.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("非法 DNS 标签长度: {}", label));
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN Class
    Ok(pkt)
}

/// 安全解析 RFC 1035 DNS 域名标签与压缩指针 (`0xC0xx`, 带 MAX_DNS_POINTER_JUMPS=16 防环溢出保护)
fn decode_dns_name(packet: &[u8], start_offset: usize) -> Result<(String, usize), String> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start_offset;
    let mut next_offset_after_name = start_offset;
    let mut jumped = false;
    let mut jumps = 0usize;

    loop {
        if pos >= packet.len() {
            return Err("DNS 域名解析越界".into());
        }
        let len_byte = packet[pos];
        if (len_byte & 0xC0) == 0xC0 {
            if pos + 1 >= packet.len() {
                return Err("DNS 压缩指针截断".into());
            }
            if !jumped {
                next_offset_after_name = pos + 2;
            }
            let ptr = (((len_byte & 0x3F) as usize) << 8) | (packet[pos + 1] as usize);
            if ptr >= packet.len() {
                return Err("DNS 压缩指针指向报文外".into());
            }
            jumps += 1;
            if jumps > MAX_DNS_POINTER_JUMPS {
                return Err("拦截恶意循环 DNS 压缩指针".into());
            }
            pos = ptr;
            jumped = true;
        } else if len_byte == 0 {
            if !jumped {
                next_offset_after_name = pos + 1;
            }
            break;
        } else {
            let l = len_byte as usize;
            if pos + 1 + l > packet.len() {
                return Err("DNS 标签长度越界".into());
            }
            labels.push(String::from_utf8_lossy(&packet[pos + 1..pos + 1 + l]).to_string());
            pos += 1 + l;
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Ok((name, next_offset_after_name))
}

/// 解码 RFC 1035 DNS 响应报文（复杂度 O(N)）
pub fn decode_dns_response_packet(
    packet: &[u8],
    expected_tx_id: u16,
    domain: &str,
    query_type: &str,
    dns_server: &str,
    rtt_ms: f64,
) -> Result<DnsQueryReport, String> {
    if packet.len() < 12 {
        return Err("DNS 响应不足 12 字节头".into());
    }
    let rx_id = u16::from_be_bytes([packet[0], packet[1]]);
    if rx_id != expected_tx_id {
        return Err(format!("DNS 事务 ID 不匹配: 期望 {}, 实收 {}", expected_tx_id, rx_id));
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let rcode = flags & 0x0F;
    let rcode_name = match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER_RCODE",
    }
    .to_string();

    let qd_count = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let an_count = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut off = 12usize;

    for _ in 0..qd_count.min(16) {
        let (_, next) = decode_dns_name(packet, off)?;
        off = next + 4;
        if off > packet.len() {
            return Err("DNS Question 段越界".into());
        }
    }

    let mut answers = Vec::new();
    for _ in 0..an_count.min(64) {
        if off >= packet.len() {
            break;
        }
        let (rr_name, next) = decode_dns_name(packet, off)?;
        off = next;
        if off + 10 > packet.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([packet[off], packet[off + 1]]);
        let ttl = u32::from_be_bytes([packet[off + 4], packet[off + 5], packet[off + 6], packet[off + 7]]);
        let rd_len = u16::from_be_bytes([packet[off + 8], packet[off + 9]]) as usize;
        off += 10;
        if off + rd_len > packet.len() {
            break;
        }
        let rdata = &packet[off..off + rd_len];
        let val_str = match rr_type {
            1 if rd_len == 4 => format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]),
            28 if rd_len == 16 => {
                let arr: [u8; 16] = rdata.try_into().unwrap_or([0; 16]);
                Ipv6Addr::from(arr).to_string()
            }
            2 | 5 | 12 => decode_dns_name(packet, off).map(|(s, _)| s).unwrap_or_else(|_| hex::encode(rdata)),
            15 if rd_len >= 3 => {
                let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
                let exch = decode_dns_name(packet, off + 2)
                    .map(|(s, _)| s)
                    .unwrap_or_default();
                format!("{} {}", pref, exch)
            }
            16 => {
                let mut pos = 0usize;
                let mut parts = Vec::new();
                while pos < rdata.len() {
                    let l = rdata[pos] as usize;
                    pos += 1;
                    let end = (pos + l).min(rdata.len());
                    parts.push(String::from_utf8_lossy(&rdata[pos..end]).to_string());
                    pos = end;
                }
                parts.join("")
            }
            33 if rd_len >= 7 => {
                let prio = u16::from_be_bytes([rdata[0], rdata[1]]);
                let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
                let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                let target = decode_dns_name(packet, off + 6)
                    .map(|(s, _)| s)
                    .unwrap_or_default();
                format!("prio={} weight={} port={} {}", prio, weight, port, target)
            }
            6 => {
                if let Ok((mname, n1)) = decode_dns_name(packet, off) {
                    if let Ok((rname, n2)) = decode_dns_name(packet, n1) {
                        if n2 + 20 <= off + rd_len {
                            let serial = u32::from_be_bytes([packet[n2], packet[n2 + 1], packet[n2 + 2], packet[n2 + 3]]);
                            format!("{} {} (serial={})", mname, rname, serial)
                        } else {
                            format!("{} {}", mname, rname)
                        }
                    } else {
                        mname
                    }
                } else {
                    hex::encode(rdata)
                }
            }
            _ => hex::encode(rdata),
        };
        off += rd_len;
        answers.push(DnsAnswerRecord {
            name: rr_name,
            record_type: dns_qtype_name(rr_type).to_string(),
            ttl,
            value: val_str,
        });
    }

    Ok(DnsQueryReport {
        domain: domain.to_string(),
        query_type: query_type.to_string(),
        dns_server: dns_server.to_string(),
        rcode_name,
        rtt_ms,
        answers,
    })
}

pub async fn dns_native_query_core(
    domain: &str,
    qtype_str: &str,
    dns_server_addr: &str,
    timeout_ms: u64,
) -> Result<DnsQueryReport, String> {
    let (qt_name, qt_code) = dns_qtype_from_str(qtype_str)?;
    let srv_raw = dns_server_addr.trim();
    let srv_with_port = if srv_raw.contains(':') {
        srv_raw.to_string()
    } else {
        format!("{}:53", srv_raw)
    };
    let target: SocketAddr = srv_with_port
        .parse()
        .map_err(|_| format!("非法 DNS 服务器地址: {}", srv_raw))?;

    let tx_id: u16 = ((std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
        & 0xFFFF) as u16)
        ^ 0x4E50;
    let query_pkt = encode_dns_query_packet(tx_id, domain, qt_code)?;
    let bind_addr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("DNS UDP 绑定失败: {}", e))?;

    let t0 = Instant::now();
    sock.send_to(&query_pkt, target)
        .await
        .map_err(|e| format!("DNS 请求发送失败: {}", e))?;

    let mut buf = [0u8; 4096];
    let recv_res = tokio::time::timeout(
        Duration::from_millis(timeout_ms.clamp(200, 8000)),
        sock.recv_from(&mut buf),
    )
    .await
    .map_err(|_| format!("DNS 服务器 {} 响应超时", target))?
    .map_err(|e| format!("DNS 接收异常: {}", e))?;

    let rtt_ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
    decode_dns_response_packet(&buf[..recv_res.0], tx_id, domain.trim(), qt_name, &target.to_string(), rtt_ms)
}

#[tauri::command]
pub async fn dns_native_query_cmd(
    domain: String,
    record_type: Option<String>,
    dns_server: Option<String>,
) -> Result<DnsQueryReport, String> {
    let qt = record_type.unwrap_or_else(|| "A".to_string());
    let srv = dns_server
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "223.5.5.5:53".to_string());
    dns_native_query_core(&domain, &qt, &srv, 2500).await
}

#[tauri::command]
pub async fn tcping_diagnostic_cmd(host: String, port: u16, count: Option<usize>) -> Result<TcpingReport, String> {
    let clean_host = host.trim().to_string();
    if clean_host.is_empty() || port == 0 {
        return Err("主机名/IP 与目标端口必须有效 (1..65535)".into());
    }
    let attempts = count.unwrap_or(5).clamp(1, 20);
    let addr_str = if clean_host.contains(':') && !clean_host.starts_with('[') {
        format!("[{}]:{}", clean_host, port)
    } else {
        format!("{}:{}", clean_host, port)
    };
    let resolved = tokio::net::lookup_host(&addr_str)
        .await
        .map_err(|e| format!("无法解析主机 {}: {}", clean_host, e))?
        .next()
        .ok_or_else(|| format!("主机 {} 无可用地址", clean_host))?;

    let mut samples = Vec::with_capacity(attempts);
    let mut ok_rtts = Vec::new();
    for i in 0..attempts {
        let t0 = Instant::now();
        let conn = tokio::time::timeout(Duration::from_millis(1800), TcpStream::connect(resolved)).await;
        match conn {
            Ok(Ok(_stream)) => {
                let ms = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
                samples.push(Some(ms));
                ok_rtts.push(ms);
            }
            _ => samples.push(None),
        }
        if i + 1 < attempts {
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    }

    let succeeded = ok_rtts.len();
    let loss_pct = (((attempts - succeeded) as f64 / attempts as f64) * 1000.0).round() / 10.0;
    let (min_ms, avg_ms, max_ms, p95_ms, jitter_mdev_ms) = if ok_rtts.is_empty() {
        (0.0, 0.0, 0.0, 0.0, 0.0)
    } else {
        let mut sorted = ok_rtts.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let sum: f64 = sorted.iter().sum();
        let avg = sum / sorted.len() as f64;
        let p95_idx = ((sorted.len() as f64 * 0.95).ceil() as usize).saturating_sub(1).min(sorted.len() - 1);
        let var: f64 = sorted.iter().map(|v| (v - avg).powi(2)).sum::<f64>() / sorted.len() as f64;
        let round2 = |v: f64| (v * 100.0).round() / 100.0;
        (round2(sorted[0]), round2(avg), round2(*sorted.last().unwrap()), round2(sorted[p95_idx]), round2(var.sqrt()))
    };

    Ok(TcpingReport {
        host: clean_host,
        port,
        resolved_ip: resolved.ip().to_string(),
        attempts,
        succeeded,
        loss_pct,
        min_ms,
        avg_ms,
        max_ms,
        p95_ms,
        jitter_mdev_ms,
        samples_ms: samples,
    })
}

#[tauri::command]
pub async fn http_timing_diagnostic_cmd(url: String) -> Result<HttpTimingReport, String> {
    let trimmed = url.trim();
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return Err("URL 必须以 http:// 或 https:// 开头".into());
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|e| format!("URL 解析失败: {}", e))?;
    let host = parsed.host_str().ok_or("URL 缺少主机名")?;
    let port = parsed.port_or_known_default().unwrap_or(80);

    let t_tcp0 = Instant::now();
    let _ = tokio::time::timeout(Duration::from_millis(3000), TcpStream::connect((host, port)))
        .await
        .map_err(|_| "TCP 建连超时".to_string())?
        .map_err(|e| format!("TCP 建连失败: {}", e))?;
    let tcp_ms = (t_tcp0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("HTTP 客户端初始化失败: {}", e))?;

    let t_http0 = Instant::now();
    let resp = client
        .get(trimmed)
        .send()
        .await
        .map_err(|e| format!("HTTP 请求失败: {}", e))?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let server_hdr = resp
        .headers()
        .get(reqwest::header::SERVER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let ctype_hdr = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = resp.bytes().await.unwrap_or_default();
    let total_ms = (t_http0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;

    Ok(HttpTimingReport {
        url: trimmed.to_string(),
        status_code: status,
        final_url,
        tcp_connect_ms: tcp_ms,
        total_ttfb_ms: total_ms,
        body_size_bytes: bytes.len(),
        server_header: server_hdr,
        content_type: ctype_hdr,
    })
}

// ============================================================================
// 第三部分：真实 RFC 1350 TFTP UDP 微服务器 + 安全沙箱 HTTP 文件微服务器
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransferAuditLog {
    pub protocol: String, // "TFTP-RRQ" | "TFTP-WRQ" | "HTTP-GET"
    pub peer_addr: String,
    pub filename: String,
    pub bytes_transferred: usize,
    pub sha256_prefix: String,
    pub status: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileServerRuntimeStatus {
    pub tftp_running: bool,
    pub tftp_bind: String,
    pub tftp_root: String,
    pub tftp_allow_write: bool,
    pub http_running: bool,
    pub http_bind: String,
    pub http_root: String,
    pub transfer_logs: Vec<FileTransferAuditLog>,
}

struct ToolboxServerRegistry {
    tftp_stop: Option<Arc<AtomicBool>>,
    tftp_bind: String,
    tftp_root: String,
    tftp_allow_write: bool,
    http_stop: Option<Arc<AtomicBool>>,
    http_bind: String,
    http_root: String,
    logs: VecDeque<FileTransferAuditLog>,
}

impl Default for ToolboxServerRegistry {
    fn default() -> Self {
        Self {
            tftp_stop: None,
            tftp_bind: String::new(),
            tftp_root: String::new(),
            tftp_allow_write: false,
            http_stop: None,
            http_bind: String::new(),
            http_root: String::new(),
            logs: VecDeque::with_capacity(MAX_TRANSFER_LOGS),
        }
    }
}

static GLOBAL_FILE_SERVERS: Lazy<Mutex<ToolboxServerRegistry>> =
    Lazy::new(|| Mutex::new(ToolboxServerRegistry::default()));
static TFTP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn append_transfer_log(entry: FileTransferAuditLog) {
    if let Ok(mut reg) = GLOBAL_FILE_SERVERS.lock() {
        if reg.logs.len() >= MAX_TRANSFER_LOGS {
            reg.logs.pop_front();
        }
        reg.logs.push_back(entry);
    }
}

/// 沙箱安全路径求解器：绝对拦截路径穿越（../, \\, 绝对路径及符号链接逃逸）
pub fn resolve_sandboxed_file(root: &Path, requested_name: &str, must_exist: bool) -> Result<PathBuf, String> {
    let clean = requested_name.trim().trim_start_matches('/').trim_start_matches('\\');
    if clean.is_empty()
        || clean.contains("..")
        || clean.contains('/')
        || clean.contains('\\')
        || clean.contains(':')
        || clean.contains('\0')
    {
        return Err(format!("安全拦截：非法文件名或路径穿越字符 '{}'", requested_name));
    }

    let canon_root = std::fs::canonicalize(root).map_err(|e| format!("共享根目录无效: {}", e))?;
    if !canon_root.is_dir() {
        return Err("共享路径不是有效目录".into());
    }

    let candidate = canon_root.join(clean);
    if must_exist {
        let canon_file = std::fs::canonicalize(&candidate).map_err(|_| format!("文件不存在: {}", clean))?;
        if !canon_file.starts_with(&canon_root) || !canon_file.is_file() {
            return Err(format!("安全越权拒绝访问: {}", clean));
        }
        Ok(canon_file)
    } else {
        Ok(candidate)
    }
}

fn build_tftp_error(code: u16, msg: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(5 + msg.len());
    pkt.extend_from_slice(&5u16.to_be_bytes());
    pkt.extend_from_slice(&code.to_be_bytes());
    pkt.extend_from_slice(msg.as_bytes());
    pkt.push(0);
    pkt
}

fn build_tftp_ack(block: u16) -> [u8; 4] {
    let b = block.to_be_bytes();
    [0, 4, b[0], b[1]]
}

async fn handle_tftp_session(
    opcode: u16,
    filename: String,
    peer: SocketAddr,
    root: PathBuf,
    allow_write: bool,
) {
    let Ok(xfer_sock) = UdpSocket::bind(if peer.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).await else {
        return;
    };
    let ts = chrono::Local::now().format("%H:%M:%S").to_string();

    if opcode == 1 {
        // RRQ: Read Request -> 分 512 字节块发送
        let safe_path = match resolve_sandboxed_file(&root, &filename, true) {
            Ok(p) => p,
            Err(e) => {
                let err_pkt = build_tftp_error(2, &e);
                let _ = xfer_sock.send_to(&err_pkt, peer).await;
                append_transfer_log(FileTransferAuditLog {
                    protocol: "TFTP-RRQ".into(),
                    peer_addr: peer.to_string(),
                    filename,
                    bytes_transferred: 0,
                    sha256_prefix: String::new(),
                    status: format!("BLOCKED: {}", e),
                    timestamp: ts,
                });
                return;
            }
        };
        let Ok(data) = tokio::fs::read(&safe_path).await else {
            let _ = xfer_sock.send_to(&build_tftp_error(1, "Read failure"), peer).await;
            return;
        };

        let digest_hex = hex::encode(&Sha256::digest(&data)[..8]);
        let mut block_num: u16 = 1;
        let mut offset = 0usize;
        let mut rx_ack = [0u8; 128];
        let mut ok_flag = true;

        loop {
            let end = (offset + 512).min(data.len());
            let chunk = &data[offset..end];
            let mut pkt = Vec::with_capacity(4 + chunk.len());
            pkt.extend_from_slice(&3u16.to_be_bytes()); // DATA
            pkt.extend_from_slice(&block_num.to_be_bytes());
            pkt.extend_from_slice(chunk);

            let mut acked = false;
            for _ in 0..5 {
                if xfer_sock.send_to(&pkt, peer).await.is_err() {
                    break;
                }
                if let Ok(Ok((n, src))) =
                    tokio::time::timeout(Duration::from_millis(900), xfer_sock.recv_from(&mut rx_ack)).await
                {
                    if src == peer && n >= 4 && u16::from_be_bytes([rx_ack[0], rx_ack[1]]) == 4 {
                        let ack_blk = u16::from_be_bytes([rx_ack[2], rx_ack[3]]);
                        if ack_blk == block_num {
                            acked = true;
                            break;
                        }
                    }
                }
            }
            if !acked {
                ok_flag = false;
                break;
            }
            if chunk.len() < 512 {
                break;
            }
            offset = end;
            block_num = block_num.wrapping_add(1);
        }

        append_transfer_log(FileTransferAuditLog {
            protocol: "TFTP-RRQ".into(),
            peer_addr: peer.to_string(),
            filename,
            bytes_transferred: data.len(),
            sha256_prefix: digest_hex,
            status: if ok_flag { "OK" } else { "TIMEOUT" }.to_string(),
            timestamp: ts,
        });
    } else if opcode == 2 {
        // WRQ: Write Request
        if !allow_write {
            let _ = xfer_sock
                .send_to(&build_tftp_error(2, "TFTP Server in Read-Only Mode"), peer)
                .await;
            return;
        }
        let safe_path = match resolve_sandboxed_file(&root, &filename, false) {
            Ok(p) => p,
            Err(e) => {
                let _ = xfer_sock.send_to(&build_tftp_error(2, &e), peer).await;
                return;
            }
        };

        let _ = xfer_sock.send_to(&build_tftp_ack(0), peer).await;
        let mut collected = Vec::new();
        let mut expected_blk: u16 = 1;
        let mut rx_buf = [0u8; 1024];

        loop {
            match tokio::time::timeout(Duration::from_millis(2500), xfer_sock.recv_from(&mut rx_buf)).await {
                Ok(Ok((n, src))) if src == peer && n >= 4 => {
                    let op = u16::from_be_bytes([rx_buf[0], rx_buf[1]]);
                    if op == 3 {
                        let blk = u16::from_be_bytes([rx_buf[2], rx_buf[3]]);
                        let payload = &rx_buf[4..n];
                        if blk == expected_blk {
                            if collected.len() + payload.len() <= 64 * 1024 * 1024 {
                                collected.extend_from_slice(payload);
                            }
                            let _ = xfer_sock.send_to(&build_tftp_ack(blk), peer).await;
                            expected_blk = expected_blk.wrapping_add(1);
                            if payload.len() < 512 {
                                break;
                            }
                        } else if blk < expected_blk {
                            let _ = xfer_sock.send_to(&build_tftp_ack(blk), peer).await;
                        }
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }

        let sha_pref = hex::encode(&Sha256::digest(&collected)[..8]);
        let write_ok = tokio::fs::write(&safe_path, &collected).await.is_ok();
        append_transfer_log(FileTransferAuditLog {
            protocol: "TFTP-WRQ".into(),
            peer_addr: peer.to_string(),
            filename,
            bytes_transferred: collected.len(),
            sha256_prefix: sha_pref,
            status: if write_ok { "OK" } else { "IO_ERROR" }.to_string(),
            timestamp: ts,
        });
    }
}

pub async fn start_tftp_server_core(
    bind_addr: &str,
    root_dir: &str,
    allow_write: bool,
) -> Result<String, String> {
    let canon_root = std::fs::canonicalize(root_dir).map_err(|e| format!("共享目录不可用: {}", e))?;
    if !canon_root.is_dir() {
        return Err("TFTP 根路径必须是存在目录".into());
    }
    let sock = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("TFTP 绑定 {} 失败 (若端口<1024 需管理员权限): {}", bind_addr, e))?;
    let actual_addr = sock.local_addr().map_err(|e| e.to_string())?.to_string();

    let stop_flag = Arc::new(AtomicBool::new(false));
    {
        let mut reg = GLOBAL_FILE_SERVERS.lock().map_err(|_| "状态锁失败".to_string())?;
        if let Some(prev) = reg.tftp_stop.take() {
            prev.store(true, Ordering::SeqCst);
        }
        reg.tftp_stop = Some(stop_flag.clone());
        reg.tftp_bind = actual_addr.clone();
        reg.tftp_root = canon_root.to_string_lossy().to_string();
        reg.tftp_allow_write = allow_write;
    }

    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while !stop_flag.load(Ordering::Relaxed) {
            match tokio::time::timeout(Duration::from_millis(250), sock.recv_from(&mut buf)).await {
                Ok(Ok((n, peer))) if n >= 4 => {
                    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
                    if matches!(opcode, 1 | 2) {
                        if let Some(zero_pos) = buf[2..n].iter().position(|&b| b == 0) {
                            let fname = String::from_utf8_lossy(&buf[2..2 + zero_pos]).to_string();
                            TFTP_COUNTER.fetch_add(1, Ordering::Relaxed);
                            let root_c = canon_root.clone();
                            tokio::spawn(async move {
                                handle_tftp_session(opcode, fname, peer, root_c, allow_write).await;
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    });

    Ok(actual_addr)
}

fn escape_html_text(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub async fn start_http_file_server_core(bind_addr: &str, root_dir: &str) -> Result<String, String> {
    let canon_root = std::fs::canonicalize(root_dir).map_err(|e| format!("HTTP 共享目录无效: {}", e))?;
    if !canon_root.is_dir() {
        return Err("HTTP 根路径必须是有效目录".into());
    }
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| format!("HTTP 文件服务绑定 {} 失败: {}", bind_addr, e))?;
    let actual_addr = listener.local_addr().map_err(|e| e.to_string())?.to_string();

    let stop_flag = Arc::new(AtomicBool::new(false));
    {
        let mut reg = GLOBAL_FILE_SERVERS.lock().map_err(|_| "状态锁失败".to_string())?;
        if let Some(prev) = reg.http_stop.take() {
            prev.store(true, Ordering::SeqCst);
        }
        reg.http_stop = Some(stop_flag.clone());
        reg.http_bind = actual_addr.clone();
        reg.http_root = canon_root.to_string_lossy().to_string();
    }

    tokio::spawn(async move {
        while !stop_flag.load(Ordering::Relaxed) {
            if let Ok(Ok((mut stream, peer))) =
                tokio::time::timeout(Duration::from_millis(250), listener.accept()).await
            {
                let root_c = canon_root.clone();
                tokio::spawn(async move {
                    let mut req_buf = [0u8; 4096];
                    let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut req_buf)).await else {
                        return;
                    };
                    let req = String::from_utf8_lossy(&req_buf[..n]);
                    let first_line = req.lines().next().unwrap_or("");
                    let path_part = first_line.split_whitespace().nth(1).unwrap_or("/");
                    let ts = chrono::Local::now().format("%H:%M:%S").to_string();

                    if path_part == "/" {
                        let mut rows = String::new();
                        if let Ok(entries) = std::fs::read_dir(&root_c) {
                            for e in entries.flatten() {
                                let p = e.path();
                                if p.is_file() {
                                    if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                                        let sz = e.metadata().map(|m| m.len()).unwrap_or(0);
                                        let esc = escape_html_text(name);
                                        rows.push_str(&format!(
                                            "<li><a href=\"/download/{0}\">{0}</a> ({1} bytes)</li>",
                                            esc, sz
                                        ));
                                    }
                                }
                            }
                        }
                        let html = format!(
                            "<!doctype html><html><meta charset=\"utf-8\"><h3>Omni-Probe HTTP File Server</h3><ul>{}</ul></html>",
                            rows
                        );
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            html.len(),
                            html
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if let Some(fname) = path_part.strip_prefix("/download/") {
                        let decoded_name = fname.split('?').next().unwrap_or(fname);
                        match resolve_sandboxed_file(&root_c, decoded_name, true) {
                            Ok(safe_p) => {
                                if let Ok(bytes) = tokio::fs::read(&safe_p).await {
                                    let hdr = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"{}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                        decoded_name.replace('"', ""),
                                        bytes.len()
                                    );
                                    let _ = stream.write_all(hdr.as_bytes()).await;
                                    let _ = stream.write_all(&bytes).await;
                                    let sha_pref = hex::encode(&Sha256::digest(&bytes)[..8]);
                                    append_transfer_log(FileTransferAuditLog {
                                        protocol: "HTTP-GET".into(),
                                        peer_addr: peer.to_string(),
                                        filename: decoded_name.to_string(),
                                        bytes_transferred: bytes.len(),
                                        sha256_prefix: sha_pref,
                                        status: "OK".into(),
                                        timestamp: ts,
                                    });
                                }
                            }
                            Err(_) => {
                                let _ = stream
                                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nForbidden")
                                    .await;
                            }
                        }
                    } else {
                        let _ = stream
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found")
                            .await;
                    }
                });
            }
        }
    });

    Ok(actual_addr)
}

#[tauri::command]
pub async fn start_tftp_server_cmd(
    bind_addr: Option<String>,
    root_dir: String,
    allow_write: Option<bool>,
) -> Result<String, String> {
    let bind = bind_addr.unwrap_or_else(|| "0.0.0.0:69".to_string());
    start_tftp_server_core(&bind, &root_dir, allow_write.unwrap_or(false)).await
}

#[tauri::command]
pub fn stop_tftp_server_cmd() -> bool {
    if let Ok(mut reg) = GLOBAL_FILE_SERVERS.lock() {
        if let Some(flag) = reg.tftp_stop.take() {
            flag.store(true, Ordering::SeqCst);
            reg.tftp_bind.clear();
            return true;
        }
    }
    false
}

#[tauri::command]
pub async fn start_http_file_server_cmd(bind_addr: Option<String>, root_dir: String) -> Result<String, String> {
    let bind = bind_addr.unwrap_or_else(|| "0.0.0.0:8088".to_string());
    start_http_file_server_core(&bind, &root_dir).await
}

#[tauri::command]
pub fn stop_http_file_server_cmd() -> bool {
    if let Ok(mut reg) = GLOBAL_FILE_SERVERS.lock() {
        if let Some(flag) = reg.http_stop.take() {
            flag.store(true, Ordering::SeqCst);
            reg.http_bind.clear();
            return true;
        }
    }
    false
}

#[tauri::command]
pub fn get_file_server_status_cmd() -> FileServerRuntimeStatus {
    GLOBAL_FILE_SERVERS
        .lock()
        .map(|reg| FileServerRuntimeStatus {
            tftp_running: reg.tftp_stop.as_ref().is_some_and(|f| !f.load(Ordering::Relaxed)),
            tftp_bind: reg.tftp_bind.clone(),
            tftp_root: reg.tftp_root.clone(),
            tftp_allow_write: reg.tftp_allow_write,
            http_running: reg.http_stop.as_ref().is_some_and(|f| !f.load(Ordering::Relaxed)),
            http_bind: reg.http_bind.clone(),
            http_root: reg.http_root.clone(),
            transfer_logs: reg.logs.iter().cloned().collect(),
        })
        .unwrap_or(FileServerRuntimeStatus {
            tftp_running: false,
            tftp_bind: String::new(),
            tftp_root: String::new(),
            tftp_allow_write: false,
            http_running: false,
            http_bind: String::new(),
            http_root: String::new(),
            transfer_logs: Vec::new(),
        })
}

// ============================================================================
// 第四部分：单元测试与环回协议实测（含 3 类极限边界防御）
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_ipv4_ipv6_vlsm_and_extreme_boundaries() {
        // 标准 /24
        let c = calculate_subnet_info_core("192.168.10.55/24").unwrap();
        assert_eq!(c.network_address, "192.168.10.0");
        assert_eq!(c.broadcast_address, "192.168.10.255");
        assert_eq!(c.wildcard_mask, "0.0.0.255");
        assert_eq!(c.usable_hosts, "254");

        // RFC 3021 /31 点对点链路 + 点分掩码输入
        let p2p = calculate_subnet_info_core("10.0.0.5 255.255.255.254").unwrap();
        assert_eq!(p2p.prefix_len, 31);
        assert_eq!(p2p.first_usable_ip, "10.0.0.4");
        assert_eq!(p2p.last_usable_ip, "10.0.0.5");
        assert_eq!(p2p.usable_hosts, "2");

        // IPv6 全局地址与 /64 PTR 反解
        let v6 = calculate_subnet_info_core("2001:db8:85a3::8a2e:370:7334/64").unwrap();
        assert_eq!(v6.ip_version, 6);
        assert_eq!(v6.network_address, "2001:db8:85a3::");
        assert!(v6.ptr_reverse_domain.ends_with(".ip6.arpa"));

        // VLSM 切分 /24 -> /26 (4个子网)
        let vlsm = split_vlsm_subnets_core("172.16.10.0/24", 26).unwrap();
        assert_eq!(vlsm.len(), 4);
        assert_eq!(vlsm[0].cidr, "172.16.10.0/26");
        assert_eq!(vlsm[3].cidr, "172.16.10.192/26");

        // 极限防御：非连续掩码、超限 VLSM、空串与越界前缀
        assert!(calculate_subnet_info_core("").is_err());
        assert!(calculate_subnet_info_core("192.168.1.1 255.0.255.0").is_err());
        assert!(calculate_subnet_info_core("10.0.0.1/33").is_err());
        assert!(split_vlsm_subnets_core("10.0.0.0/8", 24).is_err());
    }

    #[test]
    fn test_dns_wire_codec_with_compression_pointer_and_loop_guard() {
        let query = encode_dns_query_packet(0xABCD, "switch.corp.local", 1).unwrap();
        // 构造含 RFC 1035 压缩指针 0xC00C（指向 Query 的 12 偏移）的模拟 DNS 响应
        let mut resp = query[..2].to_vec();
        resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        resp.extend_from_slice(&query[12..]);
        // Answer: Name=0xC00C, Type=A(1), Class=1, TTL=60, RDLEN=4, IP=10.20.30.40
        resp.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 10, 20, 30, 40]);

        let report = decode_dns_response_packet(&resp, 0xABCD, "switch.corp.local", "A", "127.0.0.1:53", 1.2).unwrap();
        assert_eq!(report.rcode_name, "NOERROR");
        assert_eq!(report.answers.len(), 1);
        assert_eq!(report.answers[0].name, "switch.corp.local");
        assert_eq!(report.answers[0].value, "10.20.30.40");

        // 极限畸形防御：自指循环压缩指针（0xC00C 位于偏移 12 指向自身）
        let loop_pkt = [0xAB, 0xCD, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1];
        assert!(decode_dns_response_packet(&loop_pkt, 0xABCD, "x", "A", "127.0.0.1", 0.0).is_err());
    }

    #[tokio::test]
    async fn test_rfc1350_tftp_loopback_write_read_sha256_and_path_traversal_defense() {
        let tmp_dir = std::env::temp_dir().join(format!("omni_tftp_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        // 路径穿越物理防御实测
        assert!(resolve_sandboxed_file(&tmp_dir, "../secret.txt", false).is_err());
        assert!(resolve_sandboxed_file(&tmp_dir, "sub/../../win.ini", false).is_err());

        let bind_addr = start_tftp_server_core("127.0.0.1:0", tmp_dir.to_str().unwrap(), true)
            .await
            .expect("启动测试 TFTP 失败");
        let srv_addr: SocketAddr = bind_addr.parse().unwrap();

        let payload: Vec<u8> = (0..1200u32).map(|i| (i % 251) as u8).collect(); // > 2 个 512B 块 + 尾块
        let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // 1. WRQ 上传 firmware.bin
        let mut wrq = vec![0, 2];
        wrq.extend_from_slice(b"firmware.bin\0octet\0");
        cli.send_to(&wrq, srv_addr).await.unwrap();

        let mut buf = [0u8; 1024];
        let (n, xfer_peer) = tokio::time::timeout(Duration::from_secs(2), cli.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], &[0, 4, 0, 0]); // ACK 0

        for (idx, chunk) in payload.chunks(512).enumerate() {
            let blk = (idx + 1) as u16;
            let mut data_pkt = vec![0, 3];
            data_pkt.extend_from_slice(&blk.to_be_bytes());
            data_pkt.extend_from_slice(chunk);
            cli.send_to(&data_pkt, xfer_peer).await.unwrap();
            let (an, _) = tokio::time::timeout(Duration::from_secs(2), cli.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..an], &build_tftp_ack(blk));
        }

        // 短暂等盘落写并用 RRQ 回读比对 SHA-256
        tokio::time::sleep(Duration::from_millis(80)).await;
        let mut rrq = vec![0, 1];
        rrq.extend_from_slice(b"firmware.bin\0octet\0");
        cli.send_to(&rrq, srv_addr).await.unwrap();

        let mut downloaded = Vec::new();
        loop {
            let (dn, dp) = tokio::time::timeout(Duration::from_secs(2), cli.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 3);
            let blk = u16::from_be_bytes([buf[2], buf[3]]);
            let chunk = &buf[4..dn];
            downloaded.extend_from_slice(chunk);
            cli.send_to(&build_tftp_ack(blk), dp).await.unwrap();
            if chunk.len() < 512 {
                break;
            }
        }
        assert_eq!(Sha256::digest(&downloaded), Sha256::digest(&payload));

        // 2. 验证 TFTP 路径穿越触发 ERROR(2)
        let mut bad_rrq = vec![0, 1];
        bad_rrq.extend_from_slice(b"../hosts\0octet\0");
        cli.send_to(&bad_rrq, srv_addr).await.unwrap();
        let (en, _) = tokio::time::timeout(Duration::from_secs(2), cli.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 5);
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 2);
        assert!(en > 4);

        stop_tftp_server_cmd();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
