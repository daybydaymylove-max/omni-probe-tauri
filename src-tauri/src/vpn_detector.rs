//! Omni-Probe 全环境 VPN / 加密代理隧道多维交叉侦测与方式归因引擎
//!
//! # 工业级四层交叉验证体系
//! 1. **终端本地环境扫描 (Local Host Environment Sensing)**:
//!    - 虚拟网卡与低 MTU 检测 (Wintun / WireGuard / TAP-Windows / Clash / Sing-box / Tailscale / utun / tun0)
//!    - 全路由接管与 Fake-IP 冲突检出 (`0.0.0.0/1 + 128.0.0.0/1` 分流路由及 `198.18.0.0/15` Fake-IP 段)
//!    - Windows 注册表 `Internet Settings` (`ProxyEnable` / `ProxyServer` / `AutoConfigURL`) 与 `127.0.0.1` 代理端口探活及 SOCKS5 握手实证
//!    - 已知代理/VPN 进程与非系统自定义 HTTPS 解密根证书枚举
//! 2. **网络链路层 DPI + DFI 统计学与 MSS 封装缩水分析 (Link-Layer DPI/DFI)**:
//!    - 挂载全局抓包统一收口 $O(1)$ 入包，同时支持离线样本队列分析
//!    - **DPI**: WireGuard (`0x01/0x02/0x04`)、OpenVPN (`0x38/0x40`)、IPsec IKEv2/NAT-T (`500/4500`)、PPTP (`1723`)+GRE、L2TP (`1701`)、明文 SOCKS5 & HTTP `CONNECT`
//!    - **DFI**: 香农熵 ($\ge 7.25\text{ bits/byte}$) + 字节频率卡方均匀度检验 ($\chi^2$)、DoH/DoT (`853`/公共 DoH IP) 加密 DNS 旁路
//!    - **TCP SYN MSS 缩水测算**: RFC 793/9293 TLV 遍历解析真实以太网/IPv4/TCP SYN Option (`Kind=2`)，反推隧道头部封装开销
//! 3. **出口机房 ISP 画像与可控主动代理探测 (ISP Attribution & Active Probing)**:
//!    - 复用离线 `ip2region.xdb` 识别云厂商/数据中心机房长连接节点与 DNS 地理错位
//!    - 支持对指定本地端口或可疑远端代理执行非破坏性 SOCKS5 / HTTP `CONNECT` 主动响应验证
//! 4. **多维置信度评分、方式归因结论与防 XSS 审计报告导出 (Markdown & Self-Contained HTML)**

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const MAX_VPN_EVIDENCES: usize = 200;
const MAX_ACTIVE_FLOWS_TRACKED: usize = 4096;

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

fn current_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ============================================================================
// 1. 数据模型定义
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalVirtualAdapterItem {
    pub name: String,
    pub ipv4: String,
    pub mtu: Option<u32>,
    pub matched_vendor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProxyPortItem {
    pub port: u16,
    pub service_hint: String,
    pub verified_protocol: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalEnvironmentAudit {
    pub virtual_adapters: Vec<LocalVirtualAdapterItem>,
    pub has_split_default_route: bool,
    pub route_flags: Vec<String>,
    pub system_proxy_enabled: bool,
    pub system_proxy_server: String,
    pub system_pac_url: String,
    pub open_proxy_ports: Vec<LocalProxyPortItem>,
    pub matched_processes: Vec<String>,
    pub suspicious_root_certs: Vec<String>,
    pub kernel_tunnel_drivers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnEvidenceItem {
    pub dimension: String,       // "HOST_LOCAL" | "LINK_DPI" | "DFI_STAT_MSS" | "GEO_DNS_RISK"
    pub method_category: String, // 归因分类: e.g. "WireGuard", "OpenVPN", "Clash/v2rayN 代理", ...
    pub confidence: u8,          // 0..=100
    pub summary: String,
    pub detail: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspectedTunnelMethod {
    pub method_name: String,
    pub confidence_pct: u8,
    pub evidence_count: usize,
    pub primary_endpoints: Vec<String>,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnDimensionScores {
    pub host_local_score: u8,
    pub dpi_fingerprint_score: u8,
    pub dfi_entropy_mss_score: u8,
    pub geo_dns_mismatch_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnLinkTrafficTelemetry {
    pub inspected_packets: usize,
    pub high_entropy_flows: usize,
    pub uniform_random_cipher_hits: usize,
    pub fake_ip_connections: usize,
    pub mss_shrink_hits: usize,
    pub min_observed_syn_mss: Option<u16>,
    pub doh_dot_bypass_hits: usize,
    pub dns_geo_mismatch_hits: usize,
    pub datacenter_egress_ips: Vec<String>,
    pub observed_tunnel_protocols: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnDetectionReport {
    pub verdict: String, // "CONFIRMED_VPN_OR_PROXY" | "SUSPECTED_TUNNEL" | "CLEAN"
    pub overall_confidence: u8,
    pub dimension_scores: VpnDimensionScores,
    pub local_env: LocalEnvironmentAudit,
    pub link_telemetry: VpnLinkTrafficTelemetry,
    pub detected_methods: Vec<SuspectedTunnelMethod>,
    pub evidences: Vec<VpnEvidenceItem>,
    pub limitation_note: String,
    pub scanned_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveProxyProbeResult {
    pub target: String,
    pub socks5_supported: bool,
    pub http_connect_supported: bool,
    pub tls_handshake_supported: bool,
    pub tls_probe_behavior: String,
    pub detected_banner: String,
    pub rtt_ms: f64,
    pub verdict_note: String,
}

// ============================================================================
// 2. 终端本地环境侦测 (虚拟网卡 / 路由 / 系统代理 / 端口 / 进程 / 根证书)
// ============================================================================

const VIRTUAL_NIC_KEYWORDS: &[(&str, &str)] = &[
    ("wireguard", "WireGuard Tunnel"),
    ("wintun", "Wintun Userspace TUN (Clash/Sing-box/WireGuard)"),
    ("tap-windows", "TAP-Windows (OpenVPN)"),
    ("openvpn", "OpenVPN Adapter"),
    ("clash", "Clash / Mihomo TUN"),
    ("mihomo", "Mihomo Meta TUN"),
    ("sing-box", "sing-box TUN"),
    ("nekoray", "NekoRay / NekoBox TUN"),
    ("tailscale", "Tailscale Mesh VPN"),
    ("zerotier", "ZeroTier Virtual Switch"),
    ("anyconnect", "Cisco AnyConnect VPN"),
    ("fortinet", "FortiClient SSL VPN"),
    ("palo alto", "GlobalProtect VPN"),
    ("pulse secure", "Ivanti / Pulse Secure VPN"),
    ("cfw-tap", "Clash for Windows TAP"),
    ("outline", "Outline VPN TAP"),
    ("protonvpn", "ProtonVPN Tunnel"),
    ("nordlynx", "NordLynx (WireGuard)"),
    ("mullvad", "Mullvad VPN Tunnel"),
    ("warp", "Cloudflare WARP TUN"),
];

const KNOWN_PROXY_PORTS: &[(u16, &str)] = &[
    (1080, "标准 SOCKS4/SOCKS5 本地代理"),
    (1081, "Shadowsocks / 代理备用端口"),
    (7890, "Clash / Clash Verge Mixed (HTTP+SOCKS5)"),
    (7891, "Clash SOCKS5 专用端口"),
    (7897, "Clash Verge Rev 混合代理端口"),
    (10808, "v2rayN / Xray SOCKS5 入站"),
    (10809, "v2rayN / Xray HTTP 入站"),
    (20170, "v2rayA SOCKS5 入站"),
    (20171, "v2rayA HTTP 入站"),
    (9050, "Tor Browser / Tor SOCKS5 Daemon"),
    (9150, "Tor Browser Bundle SOCKS5"),
    (8118, "Privoxy HTTP 转发代理"),
    (8888, "Fiddler / 调试代理端口"),
    (8889, "Charles / 代理监听端口"),
];

const KNOWN_VPN_PROCESSES: &[(&str, &str)] = &[
    ("clash", "Clash / Mihomo 代理核心"),
    ("mihomo", "Mihomo 代理核心"),
    ("v2ray", "V2Ray / Xray 核心"),
    ("xray", "Xray 代理核心"),
    ("sing-box", "sing-box 通用代理核心"),
    ("shadowsocks", "Shadowsocks 客户端"),
    ("ss-local", "Shadowsocks C/Rust 本地端"),
    ("wireguard", "WireGuard 客户端"),
    ("wg-quick", "WireGuard 隧道工具"),
    ("openvpn", "OpenVPN 客户端"),
    ("hysteria", "Hysteria QUIC 代理核心"),
    ("tuic", "TUIC QUIC 代理"),
    ("naive", "NaiveProxy (Chrome 栈混淆)"),
    ("trojan", "Trojan 代理核心"),
    ("nekobox", "NekoBox 代理"),
    ("nekoray", "NekoRay 代理"),
    ("tailscaled", "Tailscale 守护进程"),
    ("zerotier-one", "ZeroTier 虚拟组网"),
    ("tor.exe", "Tor 匿名洋葱路由"),
    ("sstap", "SSTap 全局代理"),
    ("proxifier", "Proxifier 全局流量接管"),
    ("cloudflare warp", "Cloudflare WARP VPN"),
];

const CUSTOM_PROXY_CERT_KEYWORDS: &[&str] = &[
    "mitmproxy",
    "fiddler",
    "charles proxy",
    "charles root",
    "clash",
    "adguard",
    "surge",
    "reqable",
    "whistle",
    "proxyman",
];

const KERNEL_TUN_DRIVERS: &[(&str, &str)] = &[
    ("wintun", "Wintun TUN 虚拟网卡内核驱动"),
    ("tap0901", "OpenVPN TAP-Windows NDIS 驱动"),
    ("windivert", "WinDivert 透明流量拦截/重定向驱动"),
    ("wireguard", "WireGuardNT Windows 内核态隧道驱动"),
    ("ndisproxy", "NDIS Proxy 过滤驱动"),
];

fn run_hidden_cmd(program: &str, args: &[&str]) -> String {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    match cmd.output() {
        Ok(out) => {
            let s1 = String::from_utf8_lossy(&out.stdout);
            if !s1.trim().is_empty() {
                s1.into_owned()
            } else {
                String::from_utf8_lossy(&out.stderr).into_owned()
            }
        }
        Err(_) => String::new(),
    }
}

fn normalize_ipconfig_adapter_name(raw_header: &str) -> String {
    let mut s = raw_header.trim_end_matches(':').trim();
    for prefix in [
        "未知适配器 ",
        "以太网适配器 ",
        "无线局域网适配器 ",
        "隧道适配器 ",
        "PPP 适配器 ",
        "Unknown adapter ",
        "Ethernet adapter ",
        "Wireless LAN adapter ",
        "Tunnel adapter ",
        "PPP adapter ",
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.trim();
            break;
        }
    }
    s.to_string()
}

/// 解析 Windows `netsh interface ipv4 show interfaces` 与 `ipconfig /all` 片段中的虚拟网卡和低 MTU
pub fn parse_virtual_adapters_output(netsh_out: &str, ipconfig_out: &str) -> Vec<LocalVirtualAdapterItem> {
    let mut found: Vec<LocalVirtualAdapterItem> = Vec::new();
    let mut seen = BTreeSet::new();

    // 1. netsh interface ipv4 show interfaces 输出格式: Idx Met MTU State Name
    for line in netsh_out.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        for &(kw, vendor) in VIRTUAL_NIC_KEYWORDS {
            if lower.contains(kw) {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                let mtu = parts.get(2).and_then(|s| s.parse::<u32>().ok());
                let name = if parts.len() >= 5 {
                    parts[4..].join(" ")
                } else {
                    trimmed.to_string()
                };
                if seen.insert(name.to_ascii_lowercase()) {
                    found.push(LocalVirtualAdapterItem {
                        name,
                        ipv4: String::new(),
                        mtu,
                        matched_vendor: vendor.to_string(),
                    });
                }
                break;
            }
        }
    }

    // 2. 补充从 ipconfig /all 提取适配器和 IPv4（如 198.18.0.1 Fake-IP TUN 或 10.x WireGuard IP）
    let mut current_adapter = String::new();
    let mut current_vendor: Option<&str> = None;
    for line in ipconfig_out.lines() {
        if !line.starts_with(' ') && !line.starts_with('\t') && line.contains(':') {
            current_adapter = normalize_ipconfig_adapter_name(line);
            let lower = current_adapter.to_ascii_lowercase();
            current_vendor = VIRTUAL_NIC_KEYWORDS
                .iter()
                .find(|(kw, _)| lower.contains(*kw))
                .map(|(_, v)| *v);
            if let Some(vendor) = current_vendor {
                if seen.insert(current_adapter.to_ascii_lowercase()) {
                    found.push(LocalVirtualAdapterItem {
                        name: current_adapter.clone(),
                        ipv4: String::new(),
                        mtu: None,
                        matched_vendor: vendor.to_string(),
                    });
                }
            }
        } else if let Some(_vendor) = current_vendor {
            let lower_line = line.to_ascii_lowercase();
            if lower_line.contains("ipv4") || line.contains("IPv4") {
                if let Some((_, rhs)) = line.split_once(':') {
                    let ip_clean = rhs.split('(').next().unwrap_or("").trim().to_string();
                    if let Some(item) = found.iter_mut().find(|i| i.name.eq_ignore_ascii_case(&current_adapter)) {
                        if item.ipv4.is_empty() {
                            item.ipv4 = ip_clean;
                        }
                    }
                }
            }
        }
    }

    found
}

/// 解析路由表识别 `0.0.0.0/1` + `128.0.0.0/1` 对半默认接管及 `198.18.0.0/15` Fake-IP 段
pub fn parse_route_table_for_vpn(route_out: &str) -> (bool, Vec<String>) {
    let mut has_lower_half = false;
    let mut has_upper_half = false;
    let mut flags = Vec::new();

    for line in route_out.lines() {
        let trimmed = line.trim();
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() >= 3 {
            if cols[0] == "0.0.0.0" && cols[1] == "128.0.0.0" {
                has_lower_half = true;
            } else if cols[0] == "128.0.0.0" && cols[1] == "128.0.0.0" {
                has_upper_half = true;
            } else if cols[0].starts_with("198.18.") || cols[0].starts_with("198.19.") {
                flags.push(format!("路由表存在 Fake-IP 虚拟网段 ({} / {})", cols[0], cols[1]));
            }
        }
    }

    let split_takeover = has_lower_half && has_upper_half;
    if split_takeover {
        flags.insert(
            0,
            "检测到 0.0.0.0/1 + 128.0.0.0/1 分裂默认路由接管（典型 OpenVPN/WireGuard/TUN 全局分流策略）".to_string(),
        );
    }
    (split_takeover, flags)
}

async fn probe_local_proxy_port(port: u16, hint: &'static str) -> Option<LocalProxyPortItem> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let mut stream = match tokio::time::timeout(Duration::from_millis(160), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // 发送标准 SOCKS5 方法协商 `05 01 00` 进行真实协议验证
    let mut verified_protocol = "TCP_LISTENING".to_string();
    if tokio::time::timeout(Duration::from_millis(180), stream.write_all(&[0x05, 0x01, 0x00]))
        .await
        .is_ok()
    {
        let mut resp = [0u8; 64];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(180), stream.read(&mut resp)).await {
            if n >= 2 && resp[0] == 0x05 && (resp[1] == 0x00 || resp[1] == 0x02) {
                verified_protocol = "SOCKS5_CONFIRMED".to_string();
            } else if n > 0 && String::from_utf8_lossy(&resp[..n]).contains("HTTP/") {
                verified_protocol = "HTTP_PROXY_CONFIRMED".to_string();
            }
        }
    }

    Some(LocalProxyPortItem {
        port,
        service_hint: hint.to_string(),
        verified_protocol,
    })
}

fn read_system_proxy_settings() -> (bool, String, String) {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(key) = hkcu.open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings") {
            let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
            let server: String = key.get_value("ProxyServer").unwrap_or_default();
            let pac: String = key.get_value("AutoConfigURL").unwrap_or_default();
            return (enabled == 1 || !pac.trim().is_empty(), server, pac);
        }
    }

    #[cfg(not(windows))]
    {
        let http_p = std::env::var("HTTP_PROXY")
            .or_else(|_| std::env::var("http_proxy"))
            .unwrap_or_default();
        let all_p = std::env::var("ALL_PROXY")
            .or_else(|_| std::env::var("all_proxy"))
            .unwrap_or_default();
        let combined = if !all_p.is_empty() { all_p } else { http_p };
        return (!combined.is_empty(), combined, String::new());
    }

    (false, String::new(), String::new())
}

pub async fn scan_local_environment_async() -> LocalEnvironmentAudit {
    let (system_proxy_enabled, system_proxy_server, system_pac_url) = read_system_proxy_settings();

    // 并行/快速探测 14 个已知代理服务端口
    let mut handles = Vec::with_capacity(KNOWN_PROXY_PORTS.len());
    for &(port, hint) in KNOWN_PROXY_PORTS {
        handles.push(tokio::spawn(probe_local_proxy_port(port, hint)));
    }

    let (virtual_adapters, (has_split_default_route, route_flags), matched_processes, suspicious_root_certs, kernel_tunnel_drivers) =
        tokio::task::spawn_blocking(|| {
            #[cfg(windows)]
            {
                let netsh_out = run_hidden_cmd("netsh", &["interface", "ipv4", "show", "interfaces"]);
                let ipconfig_out = run_hidden_cmd("ipconfig", &["/all"]);
                let adapters = parse_virtual_adapters_output(&netsh_out, &ipconfig_out);

                let route_out = run_hidden_cmd("route", &["print", "-4"]);
                let route_res = parse_route_table_for_vpn(&route_out);

                let task_out = run_hidden_cmd("tasklist", &["/FO", "CSV", "/NH"]);
                let mut procs = BTreeSet::new();
                for line in task_out.lines() {
                    let first_col = line.split(',').next().unwrap_or("").trim_matches('"');
                    let lower = first_col.to_ascii_lowercase();
                    for &(kw, desc) in KNOWN_VPN_PROCESSES {
                        if lower.contains(kw) {
                            procs.insert(format!("{} ({})", first_col, desc));
                            break;
                        }
                    }
                }

                let cert_out = run_hidden_cmd("certutil", &["-user", "-store", "Root"]);
                let mut certs = BTreeSet::new();
                for line in cert_out.lines() {
                    let lower = line.to_ascii_lowercase();
                    for &kw in CUSTOM_PROXY_CERT_KEYWORDS {
                        if lower.contains(kw) && (lower.contains("issuer") || lower.contains("subject") || lower.contains("颁发") || lower.contains("使用者")) {
                            certs.insert(line.trim().to_string());
                            break;
                        }
                    }
                }

                let drv_out = run_hidden_cmd("driverquery", &["/FO", "CSV", "/NH"]);
                let mut drivers = BTreeSet::new();
                for line in drv_out.lines() {
                    let lower = line.to_ascii_lowercase();
                    for &(kw, desc) in KERNEL_TUN_DRIVERS {
                        if lower.contains(kw) {
                            let mod_name = line.split(',').next().unwrap_or(kw).trim_matches('"');
                            drivers.insert(format!("{} ({})", mod_name, desc));
                            break;
                        }
                    }
                }

                (
                    adapters,
                    route_res,
                    procs.into_iter().collect::<Vec<_>>(),
                    certs.into_iter().collect::<Vec<_>>(),
                    drivers.into_iter().collect::<Vec<_>>(),
                )
            }

            #[cfg(not(windows))]
            {
                let ip_out = run_hidden_cmd("ip", &["link", "show"]);
                let mut adapters = parse_virtual_adapters_output("", &ip_out);
                // 若容器/极简国产 OS 未安装 iproute2，直接扫 /sys/class/net 与 MTU 补齐
                if adapters.is_empty() {
                    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
                        let mut synthetic_ip_link = String::new();
                        for entry in entries.flatten() {
                            let name = entry.file_name().to_string_lossy().into_owned();
                            let mtu = std::fs::read_to_string(entry.path().join("mtu"))
                                .ok()
                                .and_then(|s| s.trim().parse::<u32>().ok())
                                .unwrap_or(1500);
                            synthetic_ip_link.push_str(&format!("0: {}: <UP> mtu {} state UP\n", name, mtu));
                        }
                        adapters = parse_virtual_adapters_output("", &synthetic_ip_link);
                    }
                }
                let route_out = run_hidden_cmd("ip", &["route"]);
                let mut route_res = parse_route_table_for_vpn(&route_out);
                if !route_res.0 {
                    if let Ok(proc_route) = std::fs::read_to_string("/proc/net/route") {
                        let parsed = crate::platform_net::parse_linux_proc_route(&proc_route);
                        let has_half_0 = parsed.iter().any(|r| r.destination == std::net::Ipv4Addr::UNSPECIFIED && r.mask == std::net::Ipv4Addr::new(128, 0, 0, 0));
                        let has_half_128 = parsed.iter().any(|r| r.destination == std::net::Ipv4Addr::new(128, 0, 0, 0) && r.mask == std::net::Ipv4Addr::new(128, 0, 0, 0));
                        if has_half_0 && has_half_128 {
                            route_res.0 = true;
                            route_res.1.push("/proc/net/route: 0.0.0.0/1 + 128.0.0.0/1 分流劫持".to_string());
                        }
                    }
                }
                let ps_out = run_hidden_cmd("ps", &["-eo", "comm"]);
                let mut procs = BTreeSet::new();
                for line in ps_out.lines() {
                    let lower = line.trim().to_ascii_lowercase();
                    for &(kw, desc) in KNOWN_VPN_PROCESSES {
                        if lower.contains(kw) {
                            procs.insert(format!("{} ({})", line.trim(), desc));
                            break;
                        }
                    }
                }
                (adapters, route_res, procs.into_iter().collect(), Vec::new(), Vec::new())
            }
        })
        .await
        .unwrap_or_default();

    let mut open_proxy_ports = Vec::new();
    for h in handles {
        if let Ok(Some(item)) = h.await {
            open_proxy_ports.push(item);
        }
    }

    LocalEnvironmentAudit {
        virtual_adapters,
        has_split_default_route,
        route_flags,
        system_proxy_enabled,
        system_proxy_server,
        system_pac_url,
        open_proxy_ports,
        matched_processes,
        suspicious_root_certs,
        kernel_tunnel_drivers,
    }
}

// ============================================================================
// 3. 网络链路层 DPI 指纹 + DFI 统计(熵 & 卡方) + TCP SYN MSS 封装测算 + DoH/DoT + 机房画像
// ============================================================================

/// 解码 hex 字符串（忽略空白符）为字节流
fn decode_hex_bytes(hex_str: &str, max_bytes: usize) -> Vec<u8> {
    let clean: String = hex_str
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(max_bytes * 2)
        .collect();
    let even_len = clean.len() & !1;
    hex::decode(&clean[..even_len]).unwrap_or_default()
}

/// 从完整链路层以太网帧 hex 解析 TCP SYN 包里的 MSS Option (Kind=2, Len=4)
/// 时间复杂度: O(1) (仅解析帧头 <= 96B), 空间复杂度: O(1)
pub fn extract_tcp_syn_mss_from_frame_hex(raw_frame_hex: &str) -> Option<u16> {
    let frame = decode_hex_bytes(raw_frame_hex, 96);
    if frame.len() < 14 + 20 + 20 {
        return None;
    }

    // 定位 IPv4 起始偏移（兼容标准 Ethernet 14B 及单层 802.1Q VLAN 18B）
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let ip_off = if ethertype == 0x0800 {
        14usize
    } else if ethertype == 0x8100 && frame.len() >= 18 && u16::from_be_bytes([frame[16], frame[17]]) == 0x0800 {
        18usize
    } else {
        return None;
    };

    if frame.len() < ip_off + 20 {
        return None;
    }
    let ip_ver = frame[ip_off] >> 4;
    let ihl = ((frame[ip_off] & 0x0F) as usize) * 4;
    let ip_proto = frame[ip_off + 9];
    if ip_ver != 4 || ihl < 20 || ip_proto != 6 {
        return None;
    }

    let tcp_off = ip_off + ihl;
    if frame.len() < tcp_off + 20 {
        return None;
    }
    let data_offset = ((frame[tcp_off + 12] >> 4) as usize) * 4;
    let flags = frame[tcp_off + 13];
    let is_syn = (flags & 0x02) != 0;
    if !is_syn || data_offset <= 20 {
        return None;
    }

    let opts_start = tcp_off + 20;
    let opts_end = (tcp_off + data_offset).min(frame.len());
    let mut i = opts_start;
    while i < opts_end {
        let kind = frame[i];
        if kind == 0 {
            break; // End of Options
        } else if kind == 1 {
            i += 1; // NOP
            continue;
        }
        if i + 1 >= opts_end {
            break;
        }
        let len = frame[i + 1] as usize;
        if len < 2 || i + len > opts_end {
            break;
        }
        if kind == 2 && len == 4 {
            return Some(u16::from_be_bytes([frame[i + 2], frame[i + 3]]));
        }
        i += len;
    }
    None
}

/// 字节频数卡方均匀度检验 (Pearson's Chi-Square Test, df=255)
/// 返回归一化卡方统计量 (chi2 / 255.0): 强均匀加密代理随机流典型处于 [0.45, 1.55] 附近，明文/常规头报文显著偏高
/// 时间复杂度: O(L), 空间复杂度: O(1) (256 桶固定数组)
pub fn normalized_byte_uniformity_chi2(payload: &[u8]) -> Option<f64> {
    if payload.len() < 128 {
        return None;
    }
    let mut counts = [0u32; 256];
    for &b in payload {
        counts[b as usize] += 1;
    }
    let expected = payload.len() as f64 / 256.0;
    let mut chi2 = 0.0_f64;
    for &c in &counts {
        let diff = (c as f64) - expected;
        chi2 += (diff * diff) / expected;
    }
    Some(chi2 / 255.0)
}

fn is_standard_tls_or_http_header(payload: &[u8]) -> bool {
    if payload.len() >= 3 && payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x04 {
        return true; // TLS Handshake
    }
    if payload.len() >= 5 && matches!(payload[0], 0x14..=0x17) && payload[1] == 0x03 {
        return true; // TLS Record
    }
    payload.starts_with(b"GET ")
        || payload.starts_with(b"POST ")
        || payload.starts_with(b"HEAD ")
        || payload.starts_with(b"HTTP/")
        || payload.starts_with(b"SSH-")
}

/// 识别传统 VPN 与明文代理协议指纹 (DPI)
pub fn match_vpn_dpi_signature(
    transport: &str,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<(&'static str, u8, String)> {
    let t_upper = transport.to_ascii_uppercase();
    let len = payload.len();

    // 1. WireGuard (UDP Type 1 Initiator 148B / Type 2 Responder 92B / Type 3 Cookie 64B / Type 4 Data >=32B on 51820)
    if t_upper.contains("UDP") && len >= 32 {
        let msg_type = payload[0];
        let reserved_zero = payload[1] == 0 && payload[2] == 0 && payload[3] == 0;
        if reserved_zero && msg_type == 0x01 && len == 148 {
            return Some(("WireGuard", 95, "命中 WireGuard Handshake Initiation (Type=0x01, 148B 固定特征)".to_string()));
        }
        if reserved_zero && msg_type == 0x02 && len == 92 {
            return Some(("WireGuard", 95, "命中 WireGuard Handshake Response (Type=0x02, 92B 固定特征)".to_string()));
        }
        if reserved_zero && msg_type == 0x04 && (src_port == 51820 || dst_port == 51820) {
            return Some(("WireGuard", 82, "命中 WireGuard UDP/51820 加密传输帧 (Type=0x04)".to_string()));
        }
    }

    // 2. OpenVPN (P_CONTROL_HARD_RESET_CLIENT_V2 0x38 / SERVER_V2 0x40)
    if len >= 14 && (src_port == 1194 || dst_port == 1194 || (t_upper.contains("UDP") && matches!(payload[0], 0x38 | 0x40))) {
        if matches!(payload[0], 0x38 | 0x40 | 0x48) {
            return Some(("OpenVPN", 90, format!("命中 OpenVPN 控制重置/密钥握手特征 (Opcode=0x{:02X})", payload[0])));
        }
        if src_port == 1194 || dst_port == 1194 {
            return Some(("OpenVPN", 72, "命中 OpenVPN 默认端口 1194 会话流量".to_string()));
        }
    }

    // 3. IPsec / IKEv2 / NAT-T (UDP 500 / 4500)
    if t_upper.contains("UDP") && (src_port == 500 || dst_port == 500 || src_port == 4500 || dst_port == 4500) && len >= 28 {
        if (src_port == 4500 || dst_port == 4500) && len >= 32 && payload[0..4] == [0, 0, 0, 0] {
            let ver = payload[21]; // ISAKMP version after 4B Non-ESP marker + 16B SPI + 1B NextPayload
            if ver == 0x20 || ver == 0x10 {
                return Some(("IPsec/IKEv2 NAT-T", 92, format!("命中 UDP/4500 Non-ESP Marker + IKEv{} 控制协商", ver >> 4)));
            }
        }
        if payload[17] == 0x20 && matches!(payload[18], 34..=37) {
            return Some(("IPsec/IKEv2", 92, format!("命中 IKEv2 ISAKMP 握手报文 (Exchange={})", payload[18])));
        }
        if src_port == 4500 || dst_port == 4500 {
            return Some(("IPsec ESP-over-UDP", 78, "命中 UDP/4500 IPsec ESP 封装加密隧道流".to_string()));
        }
    }

    // 4. PPTP (TCP 1723) / GRE (Proto 47) / L2TP (UDP 1701)
    if t_upper.contains("GRE") {
        return Some(("PPTP/GRE 隧道", 90, "捕获原生 GRE (IP Protocol 47) 封装隧道帧".to_string()));
    }
    if src_port == 1723 || dst_port == 1723 {
        return Some(("PPTP VPN", 85, "命中 PPTP 控制信道端口 TCP/1723".to_string()));
    }
    if t_upper.contains("UDP") && (src_port == 1701 || dst_port == 1701) {
        return Some(("L2TP VPN", 85, "命中 L2TP 隧道控制与传输端口 UDP/1701".to_string()));
    }

    // 5. 明文 SOCKS5 / HTTP CONNECT 代理隧道
    if len >= 3 && payload[0] == 0x05 && payload[1] >= 1 && payload[1] <= 4 && len == (2 + payload[1] as usize) {
        if payload[2..].iter().all(|&m| m <= 0x09) {
            return Some(("SOCKS5 代理握手", 96, format!("捕获明文 SOCKS5 客户端方法协商报文 ({:02X?})", payload)));
        }
    }
    if len >= 16 && payload.starts_with(b"CONNECT ") {
        let preview = String::from_utf8_lossy(&payload[..len.min(64)]);
        if preview.contains(" HTTP/") {
            return Some(("HTTP CONNECT 代理隧道", 95, format!("捕获明文 HTTP CONNECT 隧道建立请求: {}", preview.lines().next().unwrap_or(""))));
        }
    }

    None
}

const PUBLIC_DOH_IPS: &[&str] = &[
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "223.5.5.5",
];

const DATACENTER_ISP_KEYWORDS: &[&str] = &[
    "amazon", "aws", "digitalocean", "vultr", "linode", "akamai", "choopa", "hetzner",
    "ovh", "cloudflare", "oracle", "google", "microsoft", "azure", "rackspace", "cogent",
    "m247", "datacamp", "leaseweb", "psychz", "zenlayer", "dmit", "bandwagon", "it7",
];

fn is_datacenter_geo(geo_summary: &str) -> bool {
    let lower = geo_summary.to_ascii_lowercase();
    DATACENTER_ISP_KEYWORDS.iter().any(|kw| lower.contains(*kw))
}

/// 严格判定 IPv4/IPv6 是否为内网/环回/链路本地/Fake-IP/CGNAT/无效地址
/// 时间复杂度: O(1), 空间复杂度: O(1)
pub fn is_internal_or_reserved_ip(ip_str: &str) -> bool {
    let trimmed = ip_str.trim();
    if trimmed.is_empty() {
        return true;
    }
    match trimmed.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let oct = v4.octets();
            let is_fake_ip = oct[0] == 198 && (oct[1] == 18 || oct[1] == 19);
            let is_cgnat = oct[0] == 100 && (oct[1] & 0xC0) == 64;
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || is_fake_ip
                || is_cgnat
        }
        Ok(IpAddr::V6(v6)) => {
            let seg = v6.segments();
            let is_ula = (seg[0] & 0xfe00) == 0xfc00;
            let is_ll = (seg[0] & 0xffc0) == 0xfe80;
            v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() || is_ula || is_ll
        }
        Err(_) => true,
    }
}

/// 从 ip2region 摘要提取国家/地区字段用于 DNS 解析与出口归属地错位对比
pub fn extract_geo_country(geo_summary: &str) -> Option<String> {
    let raw = geo_summary
        .split(&['|', '·', ' '][..])
        .next()
        .unwrap_or("")
        .trim();
    let lower = raw.to_ascii_lowercase();
    if raw.is_empty()
        || raw == "0"
        || lower.contains("内网")
        || lower.contains("局域网")
        || lower.contains("保留")
        || lower == "unknown"
        || lower == "未知"
    {
        return None;
    }
    Some(raw.to_string())
}

/// 判定某主机的最近 DNS 归属国与随后高频/高熵公网出口归属国是否存在跨境地理错位
pub fn is_dns_egress_geo_conflict(dns_country: &str, egress_country: &str) -> bool {
    let d = dns_country.trim();
    let e = egress_country.trim();
    if d.is_empty() || e.is_empty() || d.eq_ignore_ascii_case(e) {
        return false;
    }
    // 排除中国大陆与模糊字段、仅当分属不同国家/境外地区时判定错位
    let d_cn = d.contains("中国");
    let e_cn = e.contains("中国");
    d_cn != e_cn || (!d_cn && !e_cn && !d.eq_ignore_ascii_case(e))
}

#[derive(Default)]
struct VpnLinkAccumulator {
    inspected_packets: usize,
    high_entropy_flows: BTreeSet<String>,
    uniform_random_cipher_hits: usize,
    fake_ip_connections: usize,
    mss_shrink_hits: usize,
    min_observed_syn_mss: Option<u16>,
    doh_dot_bypass_hits: usize,
    dns_geo_mismatch_hits: usize,
    host_last_dns_geo: BTreeMap<String, (String, String)>,
    datacenter_egress_ips: BTreeSet<String>,
    observed_tunnel_protocols: BTreeMap<String, usize>,
    evidences: VecDeque<VpnEvidenceItem>,
    seen_evidence_keys: BTreeSet<String>,
}

impl VpnLinkAccumulator {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn push_evidence(&mut self, key: String, item: VpnEvidenceItem) {
        if !self.seen_evidence_keys.insert(key) {
            return;
        }
        if self.evidences.len() >= MAX_VPN_EVIDENCES {
            self.evidences.pop_front();
        }
        self.evidences.push_back(item);
    }

    fn to_telemetry(&self) -> VpnLinkTrafficTelemetry {
        VpnLinkTrafficTelemetry {
            inspected_packets: self.inspected_packets,
            high_entropy_flows: self.high_entropy_flows.len(),
            uniform_random_cipher_hits: self.uniform_random_cipher_hits,
            fake_ip_connections: self.fake_ip_connections,
            mss_shrink_hits: self.mss_shrink_hits,
            min_observed_syn_mss: self.min_observed_syn_mss,
            doh_dot_bypass_hits: self.doh_dot_bypass_hits,
            dns_geo_mismatch_hits: self.dns_geo_mismatch_hits,
            datacenter_egress_ips: self.datacenter_egress_ips.iter().cloned().collect(),
            observed_tunnel_protocols: self.observed_tunnel_protocols.clone(),
        }
    }

    pub fn ingest_packet_fields(
        &mut self,
        transport: &str,
        protocol: &str,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        length: usize,
        entropy: f64,
        payload_hex: &str,
        raw_frame_hex: &str,
        raw_text: Option<&str>,
    ) {
        self.inspected_packets = self.inspected_packets.saturating_add(1);
        let ts_ms = current_epoch_ms();
        let payload = decode_hex_bytes(payload_hex, 512);

        // 1. Fake-IP (198.18.0.0/15) 检测 (Clash/Sing-box TUN 特征段)
        for ip_s in [src_ip, dst_ip] {
            if ip_s.starts_with("198.18.") || ip_s.starts_with("198.19.") {
                self.fake_ip_connections += 1;
                *self.observed_tunnel_protocols.entry("Fake-IP (Clash/Sing-box)".to_string()).or_insert(0) += 1;
                self.push_evidence(
                    format!("FAKEIP_{}", ip_s),
                    VpnEvidenceItem {
                        dimension: "GEO_DNS_RISK".to_string(),
                        method_category: "Clash / Mihomo / sing-box Fake-IP TUN".to_string(),
                        confidence: 94,
                        summary: format!("检测到流量目标/源处于 Fake-IP 保留段 {}", ip_s),
                        detail: format!("{}:{} -> {}:{} ({} B)", src_ip, src_port, dst_ip, dst_port, length),
                        timestamp_ms: ts_ms,
                    },
                );
            }
        }

        // 2. 传统 VPN 与明文代理 DPI 指纹
        if let Some((cat, conf, desc)) = match_vpn_dpi_signature(transport, src_port, dst_port, &payload) {
            *self.observed_tunnel_protocols.entry(cat.to_string()).or_insert(0) += 1;
            self.push_evidence(
                format!("DPI_{}_{}_{}", cat, dst_ip, dst_port),
                VpnEvidenceItem {
                    dimension: "LINK_DPI".to_string(),
                    method_category: cat.to_string(),
                    confidence: conf,
                    summary: desc,
                    detail: format!("{}:{} -> {}:{} [{} {}B]", src_ip, src_port, dst_ip, dst_port, transport, length),
                    timestamp_ms: ts_ms,
                },
            );
        } else if payload.len() >= 5
            && payload[0] == 0x16
            && payload[1] == 0x03
            && payload[2] <= 0x04
            && !matches!(dst_port, 443 | 8443 | 993 | 465 | 995 | 853 | 5228 | 5061)
            && !matches!(src_port, 443 | 8443 | 993 | 465 | 995 | 853 | 5228 | 5061)
            && !is_internal_or_reserved_ip(dst_ip)
        {
            *self.observed_tunnel_protocols.entry("非常规端口 TLS 隧道".to_string()).or_insert(0) += 1;
            self.push_evidence(
                format!("TLS_NONSTD_{}_{}", dst_ip, dst_port),
                VpnEvidenceItem {
                    dimension: "LINK_DPI".to_string(),
                    method_category: "非常规端口 TLS 代理伪装 (Trojan/VLESS-TLS 特征)".to_string(),
                    confidence: 76,
                    summary: format!("在非标准端口 {}:{} 捕获外联 TLS Handshake Client/ServerHello", dst_ip, dst_port),
                    detail: format!("{}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port),
                    timestamp_ms: ts_ms,
                },
            );
        }

        // 3. DoT (TCP 853) / 公共 DoH (443) 加密 DNS 旁路
        if dst_port == 853 || src_port == 853 {
            self.doh_dot_bypass_hits += 1;
            self.push_evidence(
                format!("DOT_{}", dst_ip),
                VpnEvidenceItem {
                    dimension: "GEO_DNS_RISK".to_string(),
                    method_category: "DNS-over-TLS (DoT 853) 加密解析旁路".to_string(),
                    confidence: 80,
                    summary: format!("检测到端口 853 DoT 加密 DNS 会话 ({})", dst_ip),
                    detail: format!("{}:{} -> {}:853", src_ip, src_port, dst_ip),
                    timestamp_ms: ts_ms,
                },
            );
        } else if (dst_port == 443 || protocol.eq_ignore_ascii_case("HTTPS") || protocol.eq_ignore_ascii_case("HTTP3"))
            && PUBLIC_DOH_IPS.contains(&dst_ip)
        {
            self.doh_dot_bypass_hits += 1;
            self.push_evidence(
                format!("DOH_{}", dst_ip),
                VpnEvidenceItem {
                    dimension: "GEO_DNS_RISK".to_string(),
                    method_category: "DNS-over-HTTPS (DoH) 加密解析旁路".to_string(),
                    confidence: 78,
                    summary: format!("检测到向公共 DoH 服务器 {}:443 发起 HTTPS 加密解析请求", dst_ip),
                    detail: format!("{}:{} -> {}:443", src_ip, src_port, dst_ip),
                    timestamp_ms: ts_ms,
                },
            );
        }

        // 4. TCP SYN 报文 MSS 缩水检测 (隧道头部占用反推)
        if let Some(mss) = extract_tcp_syn_mss_from_frame_hex(raw_frame_hex) {
            if self.min_observed_syn_mss.map_or(true, |m| mss < m) {
                self.min_observed_syn_mss = Some(mss);
            }
            if (1260..=1410).contains(&mss) {
                self.mss_shrink_hits += 1;
                let estimated_overhead = 1500u16.saturating_sub(mss + 40);
                self.push_evidence(
                    format!("MSS_{}_{}", src_ip, mss),
                    VpnEvidenceItem {
                        dimension: "DFI_STAT_MSS".to_string(),
                        method_category: "三层/UDP 隧道封装 (MSS/MTU 缩水)".to_string(),
                        confidence: 86,
                        summary: format!(
                            "TCP SYN 握手 MSS 缩水至 {}B（推算外层隧道封装头部开销约 {}B）",
                            mss, estimated_overhead
                        ),
                        detail: format!("{}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port),
                        timestamp_ms: ts_ms,
                    },
                );
            }
        }

        // 5. DFI 高熵无握手随机流特征 (Shadowsocks AEAD / 裸 VMess)
        if entropy >= 7.25 && payload.len() >= 128 && !is_standard_tls_or_http_header(&payload) {
            if let Some(chi2_norm) = normalized_byte_uniformity_chi2(&payload) {
                if (0.45..=1.65).contains(&chi2_norm) {
                    self.uniform_random_cipher_hits += 1;
                    if self.high_entropy_flows.len() < MAX_ACTIVE_FLOWS_TRACKED {
                        self.high_entropy_flows.insert(format!("{}:{}", dst_ip, dst_port));
                    }
                    *self.observed_tunnel_protocols.entry("高熵均匀随机流 (疑似 SS/VMess)".to_string()).or_insert(0) += 1;
                    self.push_evidence(
                        format!("DFI_RAND_{}_{}", dst_ip, dst_port),
                        VpnEvidenceItem {
                            dimension: "DFI_STAT_MSS".to_string(),
                            method_category: "无明文握手纯随机密文流 (疑似 Shadowsocks/VMess)".to_string(),
                            confidence: 83,
                            summary: format!(
                                "无 TLS/HTTP 握手头部且负载熵={:.2} bits/B, 归一化χ²={:.2}（符合 AEAD 均匀随机特征）",
                                entropy, chi2_norm
                            ),
                            detail: format!("{}:{} -> {}:{} ({}B)", src_ip, src_port, dst_ip, dst_port, length),
                            timestamp_ms: ts_ms,
                        },
                    );
                }
            }
        }

        // 6. 离线 ip2region.xdb 公网数据中心/海外机房出口画像 + DNS 解析与出口归属地地理错位
        if !is_internal_or_reserved_ip(dst_ip) {
            let intel = {
                let engine = crate::lock_guard::lock_mutex(&crate::ip_intelligence::GLOBAL_IP_ENGINE, "vpn_detector::classify");
                engine.classify(dst_ip)
            };
            if !intel.is_private && !intel.is_loopback && !intel.is_multicast {
                if dst_port == 53 {
                    if let Some(dns_country) = extract_geo_country(&intel.geo_summary) {
                        if self.host_last_dns_geo.len() >= 512 {
                            if let Some(oldest_k) = self.host_last_dns_geo.keys().next().cloned() {
                                self.host_last_dns_geo.remove(&oldest_k);
                            }
                        }
                        self.host_last_dns_geo.insert(src_ip.to_string(), (dst_ip.to_string(), dns_country));
                    }
                } else if let Some((dns_srv_ip, dns_country)) = self.host_last_dns_geo.get(src_ip).cloned() {
                    if let Some(egress_country) = extract_geo_country(&intel.geo_summary) {
                        let is_suspected_tunnel_flow = is_datacenter_geo(&intel.geo_summary)
                            || entropy >= 7.2
                            || !matches!(dst_port, 80 | 443);
                        if is_suspected_tunnel_flow && is_dns_egress_geo_conflict(&dns_country, &egress_country) {
                            self.dns_geo_mismatch_hits += 1;
                            self.push_evidence(
                                format!("DNS_GEO_MISMATCH_{}_{}", src_ip, dst_ip),
                                VpnEvidenceItem {
                                    dimension: "GEO_DNS_RISK".to_string(),
                                    method_category: "DNS 解析与出口节点地理错位 (Split-Tunnel / 代理分流特征)".to_string(),
                                    confidence: 84,
                                    summary: format!(
                                        "主机 {} 向 [{} ({})] 发起常规 DNS 解析，但同源密文/机房出站直连 [{} ({})]",
                                        src_ip, dns_srv_ip, dns_country, dst_ip, egress_country
                                    ),
                                    detail: format!("{}:{} -> {}:{} ({})", src_ip, src_port, dst_ip, dst_port, intel.geo_summary),
                                    timestamp_ms: ts_ms,
                                },
                            );
                        }
                    }
                }

                if is_datacenter_geo(&intel.geo_summary) {
                    if self.datacenter_egress_ips.len() < 256 {
                        self.datacenter_egress_ips.insert(format!("{} ({})", dst_ip, intel.geo_summary));
                    }
                    if !matches!(dst_port, 80 | 443 | 53) || entropy >= 7.2 {
                        self.push_evidence(
                            format!("DC_IP_{}_{}", dst_ip, dst_port),
                            VpnEvidenceItem {
                                dimension: "GEO_DNS_RISK".to_string(),
                                method_category: "云机房非常规端口/高熵代理节点外联".to_string(),
                                confidence: 74,
                                summary: format!("终端持续连接数据中心/云厂商 IP {}:{} ({})", dst_ip, dst_port, intel.geo_summary),
                                detail: format!("安全域: {}, 来源: {}:{}", intel.zone_name, src_ip, src_port),
                                timestamp_ms: ts_ms,
                            },
                        );
                    }
                }
            }
        }

        if let Some(txt) = raw_text {
            let lower = txt.to_ascii_lowercase();
            if lower.contains("torproject") || lower.contains(".onion") {
                self.push_evidence(
                    "TOR_STR".to_string(),
                    VpnEvidenceItem {
                        dimension: "LINK_DPI".to_string(),
                        method_category: "Tor 匿名洋葱网络".to_string(),
                        confidence: 95,
                        summary: "明文载荷中发现 Tor 洋葱路由特征字段".to_string(),
                        detail: format!("{}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port),
                        timestamp_ms: ts_ms,
                    },
                );
            }
        }
    }
}

static LIVE_VPN_ACC: Lazy<Mutex<VpnLinkAccumulator>> =
    Lazy::new(|| Mutex::new(VpnLinkAccumulator::default()));

/// 挂载在 sniffer.rs 全局抓包统一收口点的 O(1) VPN/隧道实时分析入口
pub fn ingest_vpn_packet(record: &crate::sniffer::PacketRecord) {
    if let Ok(mut guard) = LIVE_VPN_ACC.lock() {
        guard.ingest_packet_fields(
            &record.transport,
            &record.protocol,
            &record.src_ip,
            &record.dst_ip,
            record.src_port,
            record.dst_port,
            record.length,
            record.entropy,
            &record.payload_hex,
            &record.raw_frame_hex,
            record.raw_text.as_deref(),
        );
    }
}

pub fn reset_vpn_link_stats() {
    if let Ok(mut guard) = LIVE_VPN_ACC.lock() {
        guard.reset();
    }
}

// ============================================================================
// 4. 多维交叉评估与方式归因报告生成
// ============================================================================

pub fn evaluate_vpn_detection_core(
    local_env: LocalEnvironmentAudit,
    link: &VpnLinkTrafficTelemetry,
    link_evidences: &[VpnEvidenceItem],
) -> VpnDetectionReport {
    let mut evidences: Vec<VpnEvidenceItem> = Vec::new();
    let ts_ms = current_epoch_ms();

    // 汇总本地终端证据
    let mut host_score: u32 = 0;
    if !local_env.virtual_adapters.is_empty() {
        host_score += 45;
        for nic in &local_env.virtual_adapters {
            evidences.push(VpnEvidenceItem {
                dimension: "HOST_LOCAL".to_string(),
                method_category: nic.matched_vendor.clone(),
                confidence: 96,
                summary: format!("本机存在活跃 VPN/TUN 虚拟网卡 [{}]{}", nic.name, nic.mtu.map(|m| format!(" (MTU={})", m)).unwrap_or_default()),
                detail: format!("IPv4: {} | 厂商特征: {}", if nic.ipv4.is_empty() { "-" } else { &nic.ipv4 }, nic.matched_vendor),
                timestamp_ms: ts_ms,
            });
        }
    }
    if local_env.has_split_default_route || !local_env.route_flags.is_empty() {
        host_score += 35;
        for rf in &local_env.route_flags {
            evidences.push(VpnEvidenceItem {
                dimension: "HOST_LOCAL".to_string(),
                method_category: "全局/TUN 路由表分流接管".to_string(),
                confidence: 95,
                summary: rf.clone(),
                detail: "系统 IPv4 路由表校验命中".to_string(),
                timestamp_ms: ts_ms,
            });
        }
    }
    if local_env.system_proxy_enabled || !local_env.open_proxy_ports.is_empty() {
        host_score += if local_env.open_proxy_ports.iter().any(|p| p.verified_protocol != "TCP_LISTENING") { 45 } else { 28 };
        if local_env.system_proxy_enabled {
            evidences.push(VpnEvidenceItem {
                dimension: "HOST_LOCAL".to_string(),
                method_category: "操作系统全局代理设置".to_string(),
                confidence: 92,
                summary: format!("系统代理已开启: {}", if !local_env.system_proxy_server.is_empty() { &local_env.system_proxy_server } else { &local_env.system_pac_url }),
                detail: format!("ProxyServer={} | PAC={}", local_env.system_proxy_server, local_env.system_pac_url),
                timestamp_ms: ts_ms,
            });
        }
        for p in &local_env.open_proxy_ports {
            let conf = if p.verified_protocol == "SOCKS5_CONFIRMED" || p.verified_protocol == "HTTP_PROXY_CONFIRMED" { 98 } else { 72 };
            evidences.push(VpnEvidenceItem {
                dimension: "HOST_LOCAL".to_string(),
                method_category: format!("本地代理监听 ({})", p.service_hint),
                confidence: conf,
                summary: format!("本机 127.0.0.1:{} 处于开放态 [协议验证: {}]", p.port, p.verified_protocol),
                detail: p.service_hint.clone(),
                timestamp_ms: ts_ms,
            });
        }
    }
    if !local_env.matched_processes.is_empty() {
        host_score += 30;
        evidences.push(VpnEvidenceItem {
            dimension: "HOST_LOCAL".to_string(),
            method_category: "本地代理/VPN 客户端进程".to_string(),
            confidence: 95,
            summary: format!("检出 {} 个正在运行的已知代理/VPN 进程", local_env.matched_processes.len()),
            detail: local_env.matched_processes.join(" | "),
            timestamp_ms: ts_ms,
        });
    }
    if !local_env.kernel_tunnel_drivers.is_empty() {
        host_score += 20;
        evidences.push(VpnEvidenceItem {
            dimension: "HOST_LOCAL".to_string(),
            method_category: "内核态 TUN/拦截过滤驱动".to_string(),
            confidence: 90,
            summary: format!("已加载内核隧道驱动: {}", local_env.kernel_tunnel_drivers.join(", ")),
            detail: "driverquery 内核模块校验".to_string(),
            timestamp_ms: ts_ms,
        });
    }
    if !local_env.suspicious_root_certs.is_empty() {
        host_score += 15;
        evidences.push(VpnEvidenceItem {
            dimension: "HOST_LOCAL".to_string(),
            method_category: "受信任自定义代理/MITM 根证书".to_string(),
            confidence: 88,
            summary: format!("系统 Root 证书区检出 {} 条代理类自签根证书", local_env.suspicious_root_certs.len()),
            detail: local_env.suspicious_root_certs.iter().take(4).cloned().collect::<Vec<_>>().join("; "),
            timestamp_ms: ts_ms,
        });
    }

    // 合并链路层面证据与分组评分
    let mut dpi_score: u32 = 0;
    let mut dfi_score: u32 = 0;
    let mut geo_score: u32 = 0;

    for ev in link_evidences {
        match ev.dimension.as_str() {
            "LINK_DPI" => dpi_score = (dpi_score + (ev.confidence as u32 / 2).max(25)).min(100),
            "DFI_STAT_MSS" => dfi_score = (dfi_score + (ev.confidence as u32 / 3).max(20)).min(100),
            "GEO_DNS_RISK" => geo_score = (geo_score + (ev.confidence as u32 / 3).max(18)).min(100),
            _ => {}
        }
        evidences.push(ev.clone());
    }

    let host_local_score = host_score.min(100) as u8;
    let dpi_fingerprint_score = dpi_score.min(100) as u8;
    let dfi_entropy_mss_score = dfi_score.min(100) as u8;
    let geo_dns_mismatch_score = geo_score.min(100) as u8;

    // 跨维加权交叉判定
    let max_dim = host_local_score
        .max(dpi_fingerprint_score)
        .max(dfi_entropy_mss_score)
        .max(geo_dns_mismatch_score);
    let active_dims = [host_local_score, dpi_fingerprint_score, dfi_entropy_mss_score, geo_dns_mismatch_score]
        .iter()
        .filter(|&&s| s >= 30)
        .count();

    let combined = ((host_local_score as u32 * 40
        + dpi_fingerprint_score as u32 * 30
        + dfi_entropy_mss_score as u32 * 18
        + geo_dns_mismatch_score as u32 * 12)
        / 100)
        .max(if max_dim >= 90 { 85 } else { max_dim as u32 })
        .saturating_add(if active_dims >= 3 { 10 } else { 0 })
        .min(100) as u8;

    let verdict = if host_local_score >= 60 || dpi_fingerprint_score >= 70 || combined >= 70 {
        "CONFIRMED_VPN_OR_PROXY".to_string()
    } else if combined >= 35 {
        "SUSPECTED_TUNNEL".to_string()
    } else {
        "CLEAN".to_string()
    };

    // 聚合成具体「方式归因列表」
    let mut method_groups: BTreeMap<String, Vec<&VpnEvidenceItem>> = BTreeMap::new();
    for ev in &evidences {
        method_groups.entry(ev.method_category.clone()).or_default().push(ev);
    }
    let mut detected_methods: Vec<SuspectedTunnelMethod> = method_groups
        .into_iter()
        .map(|(method_name, list)| {
            let max_conf = list.iter().map(|i| i.confidence).max().unwrap_or(50);
            let endpoints: Vec<String> = list.iter().map(|i| i.detail.clone()).take(3).collect();
            let first_reason = list.first().map(|i| i.summary.clone()).unwrap_or_default();
            SuspectedTunnelMethod {
                method_name,
                confidence_pct: max_conf,
                evidence_count: list.len(),
                primary_endpoints: endpoints,
                rationale: first_reason,
            }
        })
        .collect();
    detected_methods.sort_by(|a, b| b.confidence_pct.cmp(&a.confidence_pct).then_with(|| b.evidence_count.cmp(&a.evidence_count)));

    VpnDetectionReport {
        verdict,
        overall_confidence: combined,
        dimension_scores: VpnDimensionScores {
            host_local_score,
            dpi_fingerprint_score,
            dfi_entropy_mss_score,
            geo_dns_mismatch_score,
        },
        local_env,
        link_telemetry: link.clone(),
        detected_methods,
        evidences,
        limitation_note: "客观声明: 终端本地环境(网卡/路由/端口/进程)与标准 VPN/SOCKS5 DPI 具备极高实证准确度；对 uTLS+真实域名伪装且关闭本地系统代理的旁路设备，纯被动链路层仅通过熵值、χ²随机性、MSS 缩水与机房/DoH 图像给出概率性风险线索。".to_string(),
        scanned_at_ms: ts_ms,
    }
}

#[tauri::command]
pub async fn run_vpn_environment_audit_cmd() -> Result<VpnDetectionReport, String> {
    let local_env = scan_local_environment_async().await;
    let (telemetry, link_evidences) = {
        let guard = crate::lock_guard::lock_mutex(&LIVE_VPN_ACC, "vpn_detector::run_audit");
        let t = guard.to_telemetry();
        let evs: Vec<VpnEvidenceItem> = guard.evidences.iter().cloned().collect();
        (t, evs)
    };
    Ok(evaluate_vpn_detection_core(local_env, &telemetry, &link_evidences))
}

/// 对一组抓包记录（例如离线 .pcap 导入数据）执行独立的链路级四维 VPN/代理侦测
/// 时间复杂度: O(N), 空间复杂度: O(min(N, MAX_VPN_EVIDENCES))
pub fn audit_packet_records_for_vpn(
    records: &[crate::sniffer::PacketRecord],
    local_env: LocalEnvironmentAudit,
    source_desc: &str,
) -> VpnDetectionReport {
    let mut acc = VpnLinkAccumulator::default();
    for rec in records {
        acc.ingest_packet_fields(
            &rec.transport,
            &rec.protocol,
            &rec.src_ip,
            &rec.dst_ip,
            rec.src_port,
            rec.dst_port,
            rec.length,
            rec.entropy,
            &rec.payload_hex,
            &rec.raw_frame_hex,
            rec.raw_text.as_deref(),
        );
    }
    let telemetry = acc.to_telemetry();
    let link_evidences: Vec<VpnEvidenceItem> = acc.evidences.into_iter().collect();
    let mut report = evaluate_vpn_detection_core(local_env, &telemetry, &link_evidences);
    if !source_desc.is_empty() {
        report.limitation_note = format!(
            "离线抓包审计对象: {} (共 {} 帧) | {}",
            source_desc,
            records.len(),
            report.limitation_note
        );
    }
    report
}

/// 选择离线 .pcap/.cap 抓包文件，执行纯链路或结合本机环境的四维 VPN/代理隧道侦测
#[tauri::command]
pub async fn audit_vpn_pcap_file_cmd(include_local_env: Option<bool>) -> Result<Option<VpnDetectionReport>, String> {
    let picked = crate::desktop_native::pick_native_file_dialog(
        "选择离线抓包文件执行 VPN/代理链路审计",
        "PCAP Packet Capture",
        "*.pcap;*.cap",
    )?;
    let Some(path) = picked else {
        return Ok(None);
    };
    let records = crate::export_engine::import_pcap_file(&path)?;
    let local_env = if include_local_env.unwrap_or(false) {
        scan_local_environment_async().await
    } else {
        LocalEnvironmentAudit::default()
    };
    let report = audit_packet_records_for_vpn(&records, local_env, &path);
    Ok(Some(report))
}

#[tauri::command]
pub fn reset_vpn_audit_stats_cmd() {
    reset_vpn_link_stats();
}

/// 构造无害 RFC 5246/8446 最小 TLS 1.2 ClientHello 报文用于主动区分真实 TLS 服务与静音/RST 伪装节点
fn build_minimal_tls_client_hello() -> Vec<u8> {
    let ts_bytes = current_epoch_ms().to_be_bytes();
    let mut random = [0x42u8; 32];
    random[..8].copy_from_slice(&ts_bytes);

    let mut body = Vec::with_capacity(49);
    body.extend_from_slice(&[0x03, 0x03]); // Client Version: TLS 1.2
    body.extend_from_slice(&random);       // 32-byte Random
    body.push(0x00);                       // Session ID Len = 0
    body.extend_from_slice(&[0x00, 0x08]); // Cipher Suites Len = 8
    body.extend_from_slice(&[
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0xC0, 0x2F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    ]);
    body.extend_from_slice(&[0x01, 0x00]); // Compression Methods: 1 (null)
    body.extend_from_slice(&[0x00, 0x00]); // Extensions Len = 0

    let hs_len = body.len() as u32;
    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(0x01); // HandshakeType::client_hello
    hs.push(((hs_len >> 16) & 0xFF) as u8);
    hs.push(((hs_len >> 8) & 0xFF) as u8);
    hs.push((hs_len & 0xFF) as u8);
    hs.extend_from_slice(&body);

    let rec_len = hs.len() as u16;
    let mut record = Vec::with_capacity(5 + hs.len());
    record.extend_from_slice(&[0x16, 0x03, 0x01]); // ContentType::handshake + Legacy TLS 1.0 record ver
    record.extend_from_slice(&rec_len.to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

/// 主动探测指定 IP:Port 是否表现出 SOCKS5 / HTTP CONNECT / 标准 TLS 服务端行为
#[tauri::command]
pub async fn probe_suspected_proxy_endpoint_cmd(
    host: String,
    port: u16,
    timeout_ms: Option<u64>,
) -> Result<ActiveProxyProbeResult, String> {
    let ip: IpAddr = host
        .trim()
        .parse()
        .map_err(|_| format!("非法目标 IP 地址: {}", host.trim()))?;
    if port == 0 {
        return Err("端口号不能为 0".to_string());
    }
    let timeout = Duration::from_millis(timeout_ms.unwrap_or(1000).clamp(200, 4000));
    let addr = SocketAddr::new(ip, port);
    let started = std::time::Instant::now();

    let mut socks5_supported = false;
    let mut http_connect_supported = false;
    let mut tls_handshake_supported = false;
    let mut tls_probe_behavior = "SKIPPED".to_string();
    let mut detected_banner = String::new();

    // 1. 尝试 SOCKS5 协议无认证握手探针
    if let Ok(Ok(mut s1)) = tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        if tokio::time::timeout(timeout, s1.write_all(&[0x05, 0x01, 0x00])).await.is_ok() {
            let mut r1 = [0u8; 32];
            if let Ok(Ok(n)) = tokio::time::timeout(timeout, s1.read(&mut r1)).await {
                if n >= 2 && r1[0] == 0x05 && r1[1] <= 0x02 {
                    socks5_supported = true;
                    detected_banner = format!("SOCKS5 Reply: {:02X} {:02X}", r1[0], r1[1]);
                }
            }
        }
    }

    // 2. 尝试标准 HTTP CONNECT 隧道探针（探测目标响应码，不传递实际业务数据）
    if !socks5_supported {
        if let Ok(Ok(mut s2)) = tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
            if tokio::time::timeout(timeout, s2.write_all(req)).await.is_ok() {
                let mut r2 = [0u8; 256];
                if let Ok(Ok(n)) = tokio::time::timeout(timeout, s2.read(&mut r2)).await {
                    if n > 0 {
                        let line = String::from_utf8_lossy(&r2[..n]).lines().next().unwrap_or("").trim().to_string();
                        if line.contains("200") || line.contains("407") {
                            http_connect_supported = true;
                        }
                        detected_banner = line.chars().take(120).collect();
                    }
                }
            }
        }
    }

    // 3. 若未响应明文 SOCKS5 / HTTP CONNECT，则发送无害 RFC TLS ClientHello 区分真 TLS 与非标准静音/RST 伪装节点
    if !socks5_supported && !http_connect_supported {
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(mut s3)) => {
                let hello = build_minimal_tls_client_hello();
                if tokio::time::timeout(timeout, s3.write_all(&hello)).await.is_ok() {
                    let mut r3 = [0u8; 64];
                    match tokio::time::timeout(timeout, s3.read(&mut r3)).await {
                        Ok(Ok(n)) if n >= 2 && (r3[0] == 0x16 || r3[0] == 0x15) && r3[1] == 0x03 => {
                            tls_handshake_supported = true;
                            tls_probe_behavior = if r3[0] == 0x16 {
                                "SERVER_HELLO".to_string()
                            } else {
                                "TLS_ALERT_RESPONDER".to_string()
                            };
                            if detected_banner.is_empty() {
                                detected_banner = format!("TLS Record {:02X} {:02X}.{:02X} ({}B)", r3[0], r3[1], r3[2], n);
                            }
                        }
                        Ok(Ok(0)) | Ok(Err(_)) => {
                            tls_probe_behavior = "CONNECTION_RESET_OR_EOF".to_string();
                        }
                        Ok(Ok(n)) => {
                            tls_probe_behavior = "NON_TLS_PLAINTEXT".to_string();
                            if detected_banner.is_empty() {
                                detected_banner = String::from_utf8_lossy(&r3[..n]).chars().take(120).collect();
                            }
                        }
                        Err(_) => {
                            tls_probe_behavior = "TIMEOUT_SILENT".to_string();
                        }
                    }
                } else {
                    tls_probe_behavior = "WRITE_FAILED".to_string();
                }
            }
            _ => {
                tls_probe_behavior = "CONNECT_FAILED".to_string();
            }
        }
    }

    let rtt_ms = ((started.elapsed().as_secs_f64() * 1000.0) * 100.0).round() / 100.0;
    let verdict_note = if socks5_supported {
        "实证确认为真实 SOCKS5 代理服务节点".to_string()
    } else if http_connect_supported {
        "实证确认为 HTTP CONNECT 代理转发服务节点".to_string()
    } else if tls_handshake_supported {
        "目标呈现标准 TLS 握手响应（真 HTTPS 站或 TLS/Trojan 伪装隧道，需结合证书与机房进一步甄别）".to_string()
    } else if tls_probe_behavior == "TIMEOUT_SILENT" || tls_probe_behavior == "CONNECTION_RESET_OR_EOF" {
        format!(
            "非标准明文代理且对标准 TLS 探针呈 {}（符合 Shadowsocks/裸 AEAD 抗探测丢弃特征）",
            tls_probe_behavior
        )
    } else {
        format!("未检出标准代理或 TLS 握手响应 [行为: {}]", tls_probe_behavior)
    };

    Ok(ActiveProxyProbeResult {
        target: format!("{}:{}", ip, port),
        socks5_supported,
        http_connect_supported,
        tls_handshake_supported,
        tls_probe_behavior,
        detected_banner,
        rtt_ms,
        verdict_note,
    })
}

/// 生成 VPN / 代理侦测审计报告 (Markdown & 全转义防 XSS HTML)
pub fn generate_vpn_audit_report_content(report: &VpnDetectionReport, format: &str) -> Result<String, String> {
    let fmt = format.trim().to_ascii_lowercase();
    if fmt != "markdown" && fmt != "md" && fmt != "html" {
        return Err(format!("不支持的报告格式: {}", format));
    }
    let now_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if fmt == "markdown" || fmt == "md" {
        let mut md = String::new();
        md.push_str("# Omni-Probe 全环境 VPN / 代理隧道多维侦测与方式归因报告\n\n");
        md.push_str(&format!("- **生成时间**: `{}`\n", now_str));
        md.push_str(&format!("- **综合判定**: `{}` (**置信度**: `{}%`)\n", report.verdict, report.overall_confidence));
        md.push_str(&format!(
            "- **四维得分**: 终端本地 `{}` | 链路 DPI `{}` | DFI 熵与 MSS `{}` | 机房/DNS 错位 `{}`\n\n",
            report.dimension_scores.host_local_score,
            report.dimension_scores.dpi_fingerprint_score,
            report.dimension_scores.dfi_entropy_mss_score,
            report.dimension_scores.geo_dns_mismatch_score
        ));
        md.push_str("## 1. 检出翻墙/VPN 技术方式归因\n\n");
        if report.detected_methods.is_empty() {
            md.push_str("未检出明确的 VPN 或加密代理特征。\n\n");
        } else {
            md.push_str("| 归因方式分类 | 置信度 | 证据数 | 主要依据 |\n| --- | ---: | ---: | --- |\n");
            for m in &report.detected_methods {
                md.push_str(&format!("| `{}` | {}% | {} | {} |\n", m.method_name, m.confidence_pct, m.evidence_count, m.rationale));
            }
        }
        md.push_str("\n## 2. 详细多维实证证据链\n\n");
        for ev in &report.evidences {
            md.push_str(&format!("- `[{} · {}%]` **{}**：{} (`{}`)\n", ev.dimension, ev.confidence, ev.method_category, ev.summary, ev.detail));
        }
        md.push_str(&format!("\n> {}\n", report.limitation_note));
        return Ok(md);
    }

    let mut method_rows = String::new();
    for m in &report.detected_methods {
        method_rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}%</td><td>{}</td><td>{}</td></tr>",
            html_escape(&m.method_name),
            m.confidence_pct,
            m.evidence_count,
            html_escape(&m.rationale)
        ));
    }
    let mut ev_rows = String::new();
    for ev in &report.evidences {
        ev_rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}%</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            html_escape(&ev.dimension),
            ev.confidence,
            html_escape(&ev.method_category),
            html_escape(&ev.summary),
            html_escape(&ev.detail)
        ));
    }

    Ok(format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8" /><title>VPN 与代理隧道多维侦测报告</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 28px; color: #1e293b; background: #f8fafc; }}
h1 {{ font-size: 20px; border-bottom: 2px solid #0284c7; padding-bottom: 8px; }}
.kpi {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 14px 0; }}
.card {{ background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 10px; }}
.v {{ font-size: 16px; font-weight: 700; color: #0369a1; margin-top: 4px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 8px; background: #fff; font-size: 12px; }}
th, td {{ border: 1px solid #cbd5e1; padding: 6px 8px; text-align: left; }}
th {{ background: #e2e8f0; }}
.note {{ font-size: 12px; color: #475569; margin-top: 16px; }}
</style></head><body>
<h1>Omni-Probe 全环境 VPN / 代理隧道多维侦测与方式归因报告</h1>
<p>生成时间: {now_str} | 判定: <strong>{verdict}</strong> (综合置信度 {conf}%)</p>
<div class="kpi">
  <div class="card"><div>终端本地环境分</div><div class="v">{s1}</div></div>
  <div class="card"><div>链路 DPI 指纹分</div><div class="v">{s2}</div></div>
  <div class="card"><div>DFI 熵与 MSS 分</div><div class="v">{s3}</div></div>
  <div class="card"><div>机房/DNS 错位分</div><div class="v">{s4}</div></div>
</div>
<h2>1. 方式归因结论</h2>
<table><thead><tr><th>翻墙 / VPN 方式</th><th>置信度</th><th>证据条数</th><th>核心归因依据</th></tr></thead><tbody>{method_rows}</tbody></table>
<h2>2. 全量实证证据链</h2>
<table><thead><tr><th>侦测维度</th><th>置信度</th><th>归属方式</th><th>摘要</th><th>技术细节</th></tr></thead><tbody>{ev_rows}</tbody></table>
<p class="note">{note}</p>
</body></html>"#,
        now_str = html_escape(&now_str),
        verdict = html_escape(&report.verdict),
        conf = report.overall_confidence,
        s1 = report.dimension_scores.host_local_score,
        s2 = report.dimension_scores.dpi_fingerprint_score,
        s3 = report.dimension_scores.dfi_entropy_mss_score,
        s4 = report.dimension_scores.geo_dns_mismatch_score,
        method_rows = method_rows,
        ev_rows = ev_rows,
        note = html_escape(&report.limitation_note),
    ))
}

#[tauri::command]
pub fn export_vpn_audit_report_cmd(report: VpnDetectionReport, format: String) -> Result<Option<String>, String> {
    let content = generate_vpn_audit_report_content(&report, &format)?;
    let (ext, filter_name) = if format.eq_ignore_ascii_case("html") {
        ("html", "HTML VPN Audit Report")
    } else {
        ("md", "Markdown VPN Audit Report")
    };
    let default_name = format!(
        "omni_vpn_tunnel_audit_{}.{}",
        chrono::Local::now().format("%Y%m%d_%H%M%S"),
        ext
    );
    let outcome = crate::desktop_native::save_text_with_native_dialog(
        &default_name,
        "导出 VPN 与加密代理多维侦测报告",
        filter_name,
        &format!("*.{}", ext),
        &content,
    )?;
    if outcome.saved {
        Ok(outcome.path)
    } else {
        Ok(None)
    }
}

// ============================================================================
// 5. 全维度单元测试与真机环回代理探针验证
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_local_nic_and_route_parser() {
        let netsh_sample = "\
Idx     Met         MTU          State                Name
---  ----------  ----------  ------------  ---------------------------
 12          35        1500  connected     以太网
 18           5        1380  connected     Clash Meta Wintun
";
        let ipconfig_sample = "\
未知适配器 Clash Meta Wintun:
   连接特定的 DNS 后缀 . . . . . . . :
   IPv4 地址 . . . . . . . . . . . . : 198.18.0.1(首选)
";
        let adapters = parse_virtual_adapters_output(netsh_sample, ipconfig_sample);
        assert_eq!(adapters.len(), 1);
        assert_eq!(adapters[0].mtu, Some(1380));
        assert_eq!(adapters[0].ipv4, "198.18.0.1");

        let route_sample = "\
          0.0.0.0        128.0.0.0       198.18.0.2      198.18.0.1     5
        128.0.0.0        128.0.0.0       198.18.0.2      198.18.0.1     5
        198.18.0.0       255.254.0.0     在链路上        198.18.0.1   261
";
        let (split, flags) = parse_route_table_for_vpn(route_sample);
        assert!(split);
        assert!(flags.len() >= 2);
    }

    #[test]
    fn test_dpi_wireguard_openvpn_socks5_http_connect() {
        // WireGuard 148B Type 1
        let mut wg_init = vec![0u8; 148];
        wg_init[0] = 0x01;
        let wg = match_vpn_dpi_signature("UDP", 51820, 51820, &wg_init);
        assert_eq!(wg.unwrap().0, "WireGuard");

        // OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2
        let mut ovpn = vec![0u8; 20];
        ovpn[0] = 0x38;
        let ov = match_vpn_dpi_signature("UDP", 50000, 1194, &ovpn);
        assert_eq!(ov.unwrap().0, "OpenVPN");

        // SOCKS5 handshake 05 01 00
        let s5 = match_vpn_dpi_signature("TCP", 40000, 7890, &[0x05, 0x01, 0x00]);
        assert_eq!(s5.unwrap().0, "SOCKS5 代理握手");

        // HTTP CONNECT
        let hc = match_vpn_dpi_signature("TCP", 40001, 10809, b"CONNECT www.google.com:443 HTTP/1.1\r\n");
        assert_eq!(hc.unwrap().0, "HTTP CONNECT 代理隧道");
    }

    #[test]
    fn test_tcp_syn_mss_shrink_extraction_and_chi2() {
        // 构造真实 Ethernet(14B) + IPv4(20B, proto=6 TCP) + TCP SYN(24B, 包含 MSS Option = 0x02 0x04 0x05 0x50 = 1360)
        let mut frame = vec![0u8; 14 + 20 + 24];
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4
        frame[14] = 0x45; // v4, IHL=5 (20B)
        frame[14 + 9] = 6; // TCP
        frame[34 + 12] = 0x60; // data_offset = 6 * 4 = 24B
        frame[34 + 13] = 0x02; // SYN flag
        frame[34 + 20] = 0x02; // Kind=2 MSS
        frame[34 + 21] = 0x04; // Len=4
        frame[34 + 22..34 + 24].copy_from_slice(&1360u16.to_be_bytes());

        let hex_frame = hex::encode(&frame);
        let mss = extract_tcp_syn_mss_from_frame_hex(&hex_frame);
        assert_eq!(mss, Some(1360));

        // 构造均匀全覆盖字节序列验证 chi2 近似 0.0..1.5（极度均匀随机特征），明文重复字节则是极高卡方值
        let uniform: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        let chi_u = normalized_byte_uniformity_chi2(&uniform).unwrap();
        assert!(chi_u < 1.5);

        let plaintext = vec![b'A'; 512];
        let chi_p = normalized_byte_uniformity_chi2(&plaintext).unwrap();
        assert!(chi_p > 100.0);
    }

    #[test]
    fn test_link_acc_evaluation_and_xss_report() {
        let mut acc = VpnLinkAccumulator::default();
        // 注入 Fake-IP + WireGuard + MSS=1360 混合场景
        let mut wg_init = vec![0u8; 148];
        wg_init[0] = 0x01;
        acc.ingest_packet_fields(
            "UDP",
            "UDP",
            "198.18.0.1",
            "8.8.8.8",
            51820,
            443,
            148,
            7.8,
            &hex::encode(&wg_init),
            "",
            None,
        );

        let local_env = LocalEnvironmentAudit {
            virtual_adapters: vec![LocalVirtualAdapterItem {
                name: "<script>alert(1)</script>Wintun".to_string(),
                ipv4: "198.18.0.1".to_string(),
                mtu: Some(1380),
                matched_vendor: "Wintun Userspace TUN".to_string(),
            }],
            has_split_default_route: true,
            route_flags: vec!["0.0.0.0/1 + 128.0.0.0/1".to_string()],
            system_proxy_enabled: true,
            system_proxy_server: "127.0.0.1:7890".to_string(),
            system_pac_url: String::new(),
            open_proxy_ports: Vec::new(),
            matched_processes: vec!["clash-verge.exe".to_string()],
            suspicious_root_certs: Vec::new(),
            kernel_tunnel_drivers: Vec::new(),
        };

        let link = acc.to_telemetry();
        let evs: Vec<VpnEvidenceItem> = acc.evidences.into_iter().collect();
        let report = evaluate_vpn_detection_core(local_env, &link, &evs);
        assert_eq!(report.verdict, "CONFIRMED_VPN_OR_PROXY");
        assert!(report.overall_confidence >= 85);
        assert!(report.detected_methods.iter().any(|m| m.method_name.contains("WireGuard")));

        let html = generate_vpn_audit_report_content(&report, "html").expect("导出 HTML 失败");
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[tokio::test]
    async fn test_active_socks5_proxy_probe_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 8];
                if let Ok(n) = s.read(&mut buf).await {
                    if n >= 3 && buf[0] == 0x05 {
                        let _ = s.write_all(&[0x05, 0x00]).await;
                    }
                }
            }
        });

        let res = probe_suspected_proxy_endpoint_cmd("127.0.0.1".to_string(), port, Some(800))
            .await
            .expect("SOCKS5 主动探活失败");
        assert!(res.socks5_supported);
        assert!(!res.http_connect_supported);
        assert!(!res.tls_handshake_supported);
        let _ = srv.await;
    }

    #[tokio::test]
    async fn test_active_tls_probe_vs_silent_drop_loopback() {
        // 1. 模拟正常 TLS ServerHello 服务端
        let tls_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_port = tls_listener.local_addr().unwrap().port();
        let tls_srv = tokio::spawn(async move {
            for _ in 0..3 {
                if let Ok((mut s, _)) = tls_listener.accept().await {
                    let mut buf = [0u8; 128];
                    if let Ok(n) = s.read(&mut buf).await {
                        if n >= 5 && buf[0] == 0x16 && buf[1] == 0x03 {
                            let _ = s.write_all(&[0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00]).await;
                        }
                    }
                }
            }
        });

        let res_tls = probe_suspected_proxy_endpoint_cmd("127.0.0.1".to_string(), tls_port, Some(800))
            .await
            .expect("TLS 主动探针失败");
        assert!(res_tls.tls_handshake_supported);
        assert_eq!(res_tls.tls_probe_behavior, "SERVER_HELLO");
        let _ = tls_srv.await;

        // 2. 模拟伪装/加密代理接收到非约定格式 ClientHello 后直接 EOF/RST 断开
        let drop_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let drop_port = drop_listener.local_addr().unwrap().port();
        let drop_srv = tokio::spawn(async move {
            for _ in 0..3 {
                if let Ok((mut s, _)) = drop_listener.accept().await {
                    let mut buf = [0u8; 128];
                    let _ = s.read(&mut buf).await;
                    drop(s);
                }
            }
        });

        let res_drop = probe_suspected_proxy_endpoint_cmd("127.0.0.1".to_string(), drop_port, Some(800))
            .await
            .expect("EOF 探针失败");
        assert!(!res_drop.tls_handshake_supported);
        assert_eq!(res_drop.tls_probe_behavior, "CONNECTION_RESET_OR_EOF");
        let _ = drop_srv.await;
    }

    #[test]
    fn test_private_reserved_ip_filter_and_dns_geo_conflict() {
        // 极限/内网保留 IP 防误报测试
        assert!(is_internal_or_reserved_ip("172.16.0.1"));
        assert!(is_internal_or_reserved_ip("172.31.255.254"));
        assert!(is_internal_or_reserved_ip("198.18.0.1"));
        assert!(is_internal_or_reserved_ip("100.64.0.1"));
        assert!(is_internal_or_reserved_ip("fe80::1"));
        assert!(is_internal_or_reserved_ip("invalid-ip"));
        assert!(!is_internal_or_reserved_ip("8.8.8.8"));
        assert!(!is_internal_or_reserved_ip("114.114.114.114"));

        // 地域提取与跨境错位判断
        assert_eq!(extract_geo_country("中国|0|广东省|深圳市|电信"), Some("中国".to_string()));
        assert_eq!(extract_geo_country("内网IP|内网IP"), None);
        assert!(is_dns_egress_geo_conflict("中国", "美国"));
        assert!(!is_dns_egress_geo_conflict("中国", "中国"));

        // 验证 172.16.x.x 不会计入公网机房节点
        let mut acc = VpnLinkAccumulator::default();
        acc.ingest_packet_fields("TCP", "TLS", "192.168.1.5", "172.16.88.99", 50000, 8443, 256, 7.6, "", "", None);
        assert!(acc.datacenter_egress_ips.is_empty());
    }

    #[test]
    fn test_audit_packet_records_for_vpn_offline_batch() {
        let mut nonstd_tls = vec![0x16, 0x03, 0x01, 0x00, 0x10];
        nonstd_tls.extend_from_slice(&[0xABu8; 16]);
        // 使用确定性 xorshift32 生成 512B 近似均匀独立随机密文，验证归一化卡方自然落在 [0.45, 1.65] 区间
        let mut prng: u32 = 0x9E37_79B9;
        let mut uniform_cipher = Vec::with_capacity(512);
        for _ in 0..512 {
            prng ^= prng << 13;
            prng ^= prng >> 17;
            prng ^= prng << 5;
            uniform_cipher.push((prng >> 16) as u8);
        }

        let records = vec![
            crate::sniffer::PacketRecord {
                id: 1,
                timestamp: "12:00:00".to_string(),
                timestamp_ns: 1,
                direction: "TX".to_string(),
                transport: "TCP".to_string(),
                protocol: "TLS".to_string(),
                src_ip: "198.18.0.1".to_string(),
                dst_ip: "1.1.1.1".to_string(),
                src_port: 55000,
                dst_port: 10443,
                length: 120,
                payload_hex: hex::encode(&nonstd_tls),
                raw_frame_hex: String::new(),
                entropy: 6.5,
                entropy_level: "MEDIUM".to_string(),
                mac_src: String::new(),
                mac_dst: String::new(),
                chain_hash: String::new(),
                business_data: None,
                raw_text: None,
            },
            crate::sniffer::PacketRecord {
                id: 2,
                timestamp: "12:00:01".to_string(),
                timestamp_ns: 2,
                direction: "TX".to_string(),
                transport: "TCP".to_string(),
                protocol: "RAW".to_string(),
                src_ip: "192.168.1.10".to_string(),
                dst_ip: "45.32.100.200".to_string(),
                src_port: 55001,
                dst_port: 28888,
                length: 512,
                payload_hex: hex::encode(&uniform_cipher),
                raw_frame_hex: String::new(),
                entropy: 7.92,
                entropy_level: "HIGH".to_string(),
                mac_src: String::new(),
                mac_dst: String::new(),
                chain_hash: String::new(),
                business_data: None,
                raw_text: None,
            },
        ];

        let report = audit_packet_records_for_vpn(&records, LocalEnvironmentAudit::default(), "mock_offline.pcap");
        assert_eq!(report.link_telemetry.inspected_packets, 2);
        assert!(report.link_telemetry.fake_ip_connections >= 1);
        assert!(report.link_telemetry.uniform_random_cipher_hits >= 1);
        assert!(report.limitation_note.contains("mock_offline.pcap"));
        assert!(report.detected_methods.iter().any(|m| m.method_name.contains("非常规端口 TLS")));
    }
}
