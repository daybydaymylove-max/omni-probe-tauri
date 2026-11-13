use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::Emitter;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// ============================================================
// 局域网被动与主动动态资产感知画像引擎 (LAN Dynamic Asset Discovery Engine)
// 100% 工业生产级实现：自动同步内核邻居表、并发全网段 ARP 雷达扫描、硬件厂商 OUI 画像
// 严格杜绝 127.0.0.1 等非局域网资产混入，全自动后台动态感知
// ============================================================


static ASSET_CACHE: Lazy<Arc<Mutex<HashMap<String, DiscoveredAsset>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// 根据 MAC 地址 OUI 前缀智能识别网络设备硬件厂商画像
pub fn infer_vendor_by_mac(mac: &str) -> String {
    let clean = mac.replace([':', '-'], "").to_uppercase();
    if clean.len() < 6 {
        return "未知厂商".to_string();
    }
    let oui = &clean[..6];
    match oui {
        // 常见路由器与网络基础设施厂商
        "C4518D" | "70AF6A" | "AC84C6" | "D80D17" | "E865D4" | "EC888F" => "TP-Link / 普联技术",
        "001E10" | "00259E" | "00E0FC" | "24DBCF" | "3CD92B" | "70723C" => "Huawei / 华为技术",
        "000FDB" | "001A6B" | "286ED4" | "3C5282" | "50BD5F" | "68DBCA" => "H3C / 新华三",
        "00000C" | "000142" | "000164" | "000196" | "000197" | "000216" => "Cisco / 思科网络",
        "CC81DA" | "3822D6" | "600E56" | "7405A5" | "88C397" | "ACF1DF" => "Xiaomi / 小米生态",
        "001132" | "001392" | "001C42" => "Synology / 群晖 NAS",
        // 常见终端与网卡芯片厂商
        "345A60" | "00E04C" | "40167E" | "525400" => "Realtek / 瑞昱半导体",
        "90D8F3" | "ACBC32" | "F01898" | "F4D488" | "F84D89" => "Apple / 苹果设备",
        "001A11" | "001B21" | "001E67" | "00215C" | "002318" | "0024D7" => "Intel / 英特尔网卡",
        "CCA12B" => "Honor / 荣耀终端",
        "B827EB" | "DCA632" | "E45F01" => "Raspberry Pi / 树莓派",
        _ => "局域网终端设备",
    }.to_string()
}

/// 智能推导局域网设备角色
pub fn infer_device_role(ip: &str) -> String {
    if ip.ends_with(".1") || ip.ends_with(".254") {
        "核心网关/路由器".to_string()
    } else {
        "局域网活跃终端".to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpScope {
    LanPrivate, // 私网局域网 (RFC 1918 / IPv6 ULA)
    LinkLocal,  // 链路本地 (169.254.x.x / fe80::)
    PublicWan,  // 公网/专线/DMZ 节点
}

impl IpScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            IpScope::LanPrivate => "局域网内网",
            IpScope::LinkLocal => "链路本地",
            IpScope::PublicWan => "公网/专线",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAsset {
    pub ip: String,
    pub mac: String,
    pub role: String,
    pub scope: String,
    pub vendor: String,
    pub first_seen_ts: u128,
    pub last_seen_ts: u128,
    pub packet_count: u64,
    pub protocols: Vec<String>,
    pub ports: Vec<u16>,
    pub zone_name: Option<String>,
    pub geo_summary: Option<String>,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpHostnameInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub reverse_ptr: Option<String>,
    pub netbios_name: Option<String>,
}

#[cfg(windows)]
mod winsock_raw {
    #[repr(C)]
    pub struct SockAddrIn {
        pub sin_family: u16,
        pub sin_port: u16,
        pub sin_addr: [u8; 4],
        pub sin_zero: [u8; 8],
    }

    #[repr(C)]
    pub struct SockAddrIn6 {
        pub sin6_family: u16,
        pub sin6_port: u16,
        pub sin6_flowinfo: u32,
        pub sin6_addr: [u8; 16],
        pub sin6_scope_id: u32,
    }

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        pub fn getnameinfo(
            sa: *const std::ffi::c_void,
            salen: i32,
            host: *mut u8,
            hostlen: u32,
            serv: *mut u8,
            servlen: u32,
            flags: i32,
        ) -> i32;
    }
}

/// 基于 Windows Winsock 原生 getnameinfo 的反向 PTR 解析 (RFC 1035)
pub fn probe_reverse_dns(ip: &str) -> Option<String> {
    use std::net::SocketAddr;
    let sock_addr: SocketAddr = format!("{}:0", ip).parse().ok()?;

    #[cfg(windows)]
    {
        let mut host_buf = [0u8; 1024];
        let ret = match sock_addr {
            SocketAddr::V4(v4) => {
                let sin = winsock_raw::SockAddrIn {
                    sin_family: 2, // AF_INET
                    sin_port: 0,
                    sin_addr: v4.ip().octets(),
                    sin_zero: [0; 8],
                };
                unsafe {
                    winsock_raw::getnameinfo(
                        &sin as *const _ as *const _,
                        std::mem::size_of_val(&sin) as i32,
                        host_buf.as_mut_ptr(),
                        host_buf.len() as u32,
                        std::ptr::null_mut(),
                        0,
                        0,
                    )
                }
            }
            SocketAddr::V6(v6) => {
                let sin6 = winsock_raw::SockAddrIn6 {
                    sin6_family: 23, // AF_INET6
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: v6.ip().octets(),
                    sin6_scope_id: 0,
                };
                unsafe {
                    winsock_raw::getnameinfo(
                        &sin6 as *const _ as *const _,
                        std::mem::size_of_val(&sin6) as i32,
                        host_buf.as_mut_ptr(),
                        host_buf.len() as u32,
                        std::ptr::null_mut(),
                        0,
                        0,
                    )
                }
            }
        };

        if ret == 0 {
            let nul_pos = host_buf.iter().position(|&b| b == 0).unwrap_or(host_buf.len());
            if let Ok(s) = std::str::from_utf8(&host_buf[..nul_pos]) {
                let clean = s.trim();
                if !clean.is_empty() && clean != ip {
                    return Some(clean.to_string());
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        let _ = sock_addr;
    }

    None
}

/// 针对局域网私网设备的 NetBIOS Node Status 状态查询 (UDP 137, RFC 1002)
pub fn probe_netbios_name(ip: std::net::Ipv4Addr) -> Option<String> {
    use std::net::UdpSocket;
    use std::time::Duration;

    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_millis(600))).ok()?;

    let query: [u8; 50] = [
        0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
        0x00, 0x01,
    ];

    socket.send_to(&query, format!("{}:137", ip)).ok()?;

    let mut buf = [0u8; 1024];
    let (len, _) = socket.recv_from(&mut buf).ok()?;

    if len > 57 {
        let num_names = buf[56] as usize;
        let mut offset = 57;
        for _ in 0..num_names {
            if offset + 18 <= len {
                let name_bytes = &buf[offset..offset + 15];
                let name_type = buf[offset + 15];
                if name_type == 0x00 {
                    let name_str = String::from_utf8_lossy(name_bytes).trim().to_string();
                    if !name_str.is_empty() {
                        return Some(name_str);
                    }
                }
                offset += 18;
            }
        }
    }

    None
}

/// 工业级非阻塞反向主机名与 PTR 域名解析器
pub async fn resolve_ip_hostname(ip: &str) -> IpHostnameInfo {
    let ip_string = ip.to_string();

    tokio::task::spawn_blocking(move || {
        let ip_parsed: Result<std::net::IpAddr, _> = ip_string.parse();
        let mut reverse_ptr = None;
        let mut hostname = None;
        let mut netbios_name = None;

        if let Ok(addr) = ip_parsed {
            // 1. 标准 DNS PTR 查询
            if let Some(ptr) = probe_reverse_dns(&ip_string) {
                hostname = Some(ptr.clone());
                reverse_ptr = Some(ptr);
            }

            // 2. 针对局域网 IPv4 尝试快速 NetBIOS 状态查询 (UDP 137)
            if let std::net::IpAddr::V4(v4) = addr {
                if v4.is_private() {
                    if let Some(nb_name) = probe_netbios_name(v4) {
                        netbios_name = Some(nb_name.clone());
                        if hostname.is_none() {
                            hostname = Some(nb_name);
                        }
                    }
                }
            }
        }

        IpHostnameInfo {
            ip: ip_string,
            hostname,
            reverse_ptr,
            netbios_name,
        }
    })
    .await
    .unwrap_or_else(|_| IpHostnameInfo {
        ip: ip.to_string(),
        hostname: None,
        reverse_ptr: None,
        netbios_name: None,
    })
}

/// 科学且严谨的 IP 地址分类与合法性校验 (支持 IPv4 / IPv6 全谱系)
/// 严格过滤：回环 (127.0.0.0/8, ::1)、未指定 (0.0.0.0, ::)、受限广播 (255.255.255.255)、组播 (224.0.0.0/4, ff00::/8)
/// 科学保留：局域网私网 (RFC 1918 / ULA)、链路本地 (APIPA / fe80::)、合法公网/专线/DMZ 业务对端
pub fn classify_ip(ip: &str) -> Option<IpScope> {
    let clean = ip.trim();
    if clean.is_empty()
        || clean == "0.0.0.0"
        || clean == "::"
        || clean == "255.255.255.255"
        || clean == "127.0.0.1"
        || clean == "::1"
        || clean.starts_with("127.")
        || clean.eq_ignore_ascii_case("localhost")
        || clean == "HOST_SYSTEM"
        || clean == "LOCAL_HONEYPOT"
        || clean.starts_with("224.")
        || clean.starts_with("239.")
        || clean.starts_with("ff0")
        || clean.starts_with("ff1")
        || clean.starts_with("ff2")
    {
        return None;
    }

    // 1. IPv4 解析与作用域判定
    if let Ok(ipv4) = clean.parse::<std::net::Ipv4Addr>() {
        let oct = ipv4.octets();
        // 组播 (224.0.0.0 ~ 239.255.255.255)
        if (224..=239).contains(&oct[0]) {
            return None;
        }
        // 本地回环 (127.0.0.0/8)
        if oct[0] == 127 {
            return None;
        }
        // RFC 1918 私网
        if (oct[0] == 192 && oct[1] == 168)
            || (oct[0] == 10)
            || (oct[0] == 172 && (16..=31).contains(&oct[1]))
        {
            return Some(IpScope::LanPrivate);
        }
        // 链路本地 (169.254.0.0/16 APIPA)
        if oct[0] == 169 && oct[1] == 254 {
            return Some(IpScope::LinkLocal);
        }
        // 其余为合法公网/专线/DMZ 节点
        return Some(IpScope::PublicWan);
    }

    // 2. IPv6 解析与作用域判定
    if let Ok(ipv6) = clean.parse::<std::net::Ipv6Addr>() {
        let segments = ipv6.segments();
        // 回环 (::1) 与未指定 (::)
        if ipv6.is_loopback() || ipv6.is_unspecified() {
            return None;
        }
        // 组播 (ff00::/8)
        if (segments[0] & 0xff00) == 0xff00 {
            return None;
        }
        // 链路本地 (fe80::/10)
        if (segments[0] & 0xffc0) == 0xfe80 {
            return Some(IpScope::LinkLocal);
        }
        // 唯一本地地址 ULA (fc00::/7)
        if (segments[0] & 0xfe00) == 0xfc00 {
            return Some(IpScope::LanPrivate);
        }
        // 全球单播 (GUA)
        return Some(IpScope::PublicWan);
    }

    None
}

/// 记录/更新资产状态
static LAST_ASSET_NOTIFY_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 记录/更新资产状态
/// 时间复杂度: O(1) amortized
/// 空间复杂度: O(A), A 为网段中发现的活跃设备节点数
/// 返回值: true 表示新插入未知资产，false 表示既有资产属性更新
pub fn record_asset(ip: &str, mac: &str, proto: &str, port: u16) -> bool {
    let scope = match classify_ip(ip) {
        Some(s) => s,
        None => return false, // 彻底丢弃 127.0.0.1、组播、广播与非法地址
    };

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    let mut map = crate::lock_guard::lock_mutex(&ASSET_CACHE, "discovery::upsert_asset_and_notify");
    {
        let mut is_new = false;
        let entry = map.entry(ip.to_string()).or_insert_with(|| {
            is_new = true;
            let role = infer_device_role(ip);
            let vendor = infer_vendor_by_mac(mac);
            let (zone_name, geo_summary) = {
                let engine = crate::lock_guard::lock_mutex(
                    &crate::ip_intelligence::GLOBAL_IP_ENGINE,
                    "discovery::upsert_asset_ip_classify",
                );
                let intel = engine.classify(ip);
                (Some(intel.zone_name), Some(intel.geo_summary))
            };
            DiscoveredAsset {
                ip: ip.to_string(),
                mac: mac.to_string(),
                role,
                scope: scope.as_str().to_string(),
                vendor,
                first_seen_ts: now_ms,
                last_seen_ts: now_ms,
                packet_count: 0,
                protocols: Vec::new(),
                ports: Vec::new(),
                zone_name,
                geo_summary,
                hostname: None,
            }
        });

        entry.packet_count += 1;
        entry.last_seen_ts = now_ms;

        if !mac.is_empty() && mac != "N/A" && mac != "00:00:00:00:00:00" && (entry.mac.is_empty() || entry.mac == "N/A") {
            entry.mac = mac.to_string();
            entry.vendor = infer_vendor_by_mac(mac);
        }

        if !proto.is_empty() && proto != "UNKNOWN" && !entry.protocols.contains(&proto.to_string()) {
            entry.protocols.push(proto.to_string());
        }

        if port > 0 && !entry.ports.contains(&port) {
            entry.ports.push(port);
        }

        let snapshot_ip = entry.ip.clone();
        let snapshot_mac = entry.mac.clone();
        let snapshot_vendor = entry.vendor.clone();
        let snapshot_role = entry.role.clone();
        let snapshot_zone = entry.zone_name.clone();
        drop(map);

        if let Some(mut tree) = crate::lock_guard::try_lock_mutex(
            &crate::snmp_topology::GLOBAL_TOPOLOGY_TREE,
            "discovery::upsert_asset_and_notify_topology",
        ) {
            let leaf = crate::snmp_topology::DiscoveredHostLeaf::new(
                snapshot_ip,
                snapshot_mac,
                snapshot_vendor,
                snapshot_role,
            );
            let zone_opt = snapshot_zone.as_deref().map(|z| (z, z));
            tree.ingest_host(leaf, zone_opt);
        }

        is_new
    }
}

/// 记录/更新资产状态并智能节流向前端推送 assets-updated 事件
pub fn record_asset_with_notify(app: &tauri::AppHandle, ip: &str, mac: &str, proto: &str, port: u16) {
    if classify_ip(ip).is_none() {
        return;
    }
    let is_new = record_asset(ip, mac, proto, port);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let last = LAST_ASSET_NOTIFY_MS.load(std::sync::atomic::Ordering::Relaxed);
    // 全新资产立即通知；既有资产更新限制至少间隔 800ms，彻底消除前端高频刷新抖动
    if is_new || now_ms.saturating_sub(last) >= 800 {
        LAST_ASSET_NOTIFY_MS.store(now_ms, std::sync::atomic::Ordering::Relaxed);
        let _ = app.emit("assets-updated", get_all_assets());
    }
}

/// 同步系统内核 ARP/邻居表（Windows / Linux / macOS 通用，毫秒级就绪）
pub fn sync_kernel_neighbors(app: Option<&tauri::AppHandle>) -> usize {
    let mut added_count = 0;

    #[cfg(windows)]
    {
        if let Ok(output) = std::process::Command::new("arp")
            .arg("-a")
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let ip = parts[0];
                    let mac = parts[1].replace('-', ":").to_uppercase();
                    if classify_ip(ip).is_some() && mac.len() == 17 && mac != "FF:FF:FF:FF:FF:FF" && mac != "00:00:00:00:00:00" {
                        record_asset(ip, &mac, "ARP_KERNEL", 0);
                        added_count += 1;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
            for line in content.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 4 {
                    let ip = cols[0];
                    let mac = cols[3].to_uppercase();
                    if classify_ip(ip).is_some() && mac != "00:00:00:00:00:00" && mac != "FF:FF:FF:FF:FF:FF" {
                        record_asset(ip, &mac, "ARP_KERNEL", 0);
                        added_count += 1;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("arp").arg("-an").output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                // macOS arp -an 格式: ? (192.168.1.1) at c4:51:8d:ad:d4:ea on en0 ifscope [ethernet]
                if let (Some(start), Some(end)) = (line.find('('), line.find(')')) {
                    let ip = &line[start + 1..end];
                    if let Some(at_idx) = line.find(" at ") {
                        let mac_part = &line[at_idx + 4..];
                        let mac = mac_part.split_whitespace().next().unwrap_or("").to_uppercase();
                        if classify_ip(ip).is_some() && mac.contains(':') && mac != "(INCOMPLETE)" {
                            record_asset(ip, &mac, "ARP_KERNEL", 0);
                            added_count += 1;
                        }
                    }
                }
            }
        }
    }

    if let Some(a) = app {
        let _ = a.emit("assets-updated", get_all_assets());
    }

    added_count
}

#[cfg(windows)]
#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn SendARP(
        dest_ip: u32,
        src_ip: u32,
        p_mac_addr: *mut u8,
        p_phy_addr_len: *mut u32,
    ) -> u32;
}

/// 主动全网段深度并发扫描 (Active LAN Subnet Deep Scan)
/// 自动识别本机全部物理与虚拟局域网网段真实 CIDR (支持 /30../16 任意子网，彻底废除硬编码 /24)
pub fn scan_lan_subnet_active(app: tauri::AppHandle) {
    std::thread::spawn(move || {
        let _ = app.emit("system-log", "[ASSET-RADAR] 🚀 正在启动全网卡多网段自适应深度扫描...".to_string());

        // 1. 首先同步一次内核现有邻居
        sync_kernel_neighbors(Some(&app));

        // 2. 收集全部真实物理/内网接口及其真实 CIDR 子网掩码
        let target_subnets = detect_physical_subnet_cidrs();
        let desc_list: Vec<String> = target_subnets
            .iter()
            .map(|(ip, mask)| {
                let prefix = crate::platform_net::netmask_to_prefix_len(*mask);
                format!("{}/{}", ip, prefix)
            })
            .collect();

        let _ = app.emit(
            "system-log",
            format!("[ASSET-RADAR] 🌐 已锁定全部活跃扫描网段 ({}): {:?}", target_subnets.len(), desc_list),
        );

        for (local_ip, netmask) in target_subnets {
            let targets = crate::platform_net::enumerate_cidr_scan_targets(local_ip, netmask, 1024);
            if targets.is_empty() {
                continue;
            }
            let chunk_size = (targets.len() / 8).max(1);
            let mut handles = Vec::new();

            for chunk in targets.chunks(chunk_size) {
                let chunk_ips = chunk.to_vec();
                #[cfg(windows)]
                let app_chunk = app.clone();
                let h = std::thread::spawn(move || {
                    for target_ip in chunk_ips {
                        #[cfg(windows)]
                        {
                            let dest_u32 = u32::from_ne_bytes(target_ip.octets());
                            let mut mac_buf = [0u8; 6];
                            let mut mac_len = 6u32;
                            let ret = unsafe {
                                SendARP(dest_u32, 0, mac_buf.as_mut_ptr(), &mut mac_len as *mut u32)
                            };

                            if ret == 0 && mac_len == 6 {
                                let mac_str = format!(
                                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                    mac_buf[0], mac_buf[1], mac_buf[2], mac_buf[3], mac_buf[4], mac_buf[5]
                                );
                                let ip_str = target_ip.to_string();
                                record_asset_with_notify(&app_chunk, &ip_str, &mac_str, "ARP_ACTIVE", 0);
                            }
                        }

                        #[cfg(not(windows))]
                        {
                            // Linux / macOS: 发送短促 UDP 探测与高频管理端口非阻塞连接触发内核二层 ARP 邻居解析
                            if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
                                let _ = socket.send_to(&[0u8; 4], (target_ip, 65534));
                            }
                            let _ = std::net::TcpStream::connect_timeout(
                                &std::net::SocketAddr::new(std::net::IpAddr::V4(target_ip), 80),
                                Duration::from_millis(25),
                            );
                        }

                        std::thread::sleep(Duration::from_millis(3));
                    }
                });
                handles.push(h);
            }

            for h in handles {
                let _ = h.join();
            }
        }

        // 再次同步一次内核 ARP/邻居表（Linux 下将刚唤醒的同网段 MAC 一并入库）
        sync_kernel_neighbors(Some(&app));

        let total = get_all_assets().len();
        let _ = app.emit(
            "system-log",
            format!("[ASSET-RADAR] ✅ 多网段自适应扫描完成，当前已知资产总数: {} 个节点", total),
        );
    });
}

/// 智能探测全部物理/局域网接口真实 (IPv4, Netmask) 列表（支持多网卡、非 /24 子网及离线内网）
fn detect_physical_subnet_cidrs() -> Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr)> {
    let mut subnets: Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr)> = Vec::new();
    let mut seen_nets = std::collections::BTreeSet::new();

    #[cfg(windows)]
    {
        for iface in crate::sniffer::discover_capture_target_interfaces("") {
            if !iface.ip.is_loopback() && !iface.ip.is_link_local() && !iface.ip.is_unspecified() {
                let net = u32::from(iface.ip) & u32::from(iface.netmask);
                if seen_nets.insert((net, u32::from(iface.netmask))) {
                    subnets.push((iface.ip, iface.netmask));
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        for iface in crate::platform_net::discover_linux_interfaces() {
            if !iface.ip.is_loopback() && !iface.ip.is_link_local() && !iface.ip.is_unspecified() {
                let net = u32::from(iface.ip) & u32::from(iface.netmask);
                if seen_nets.insert((net, u32::from(iface.netmask))) {
                    subnets.push((iface.ip, iface.netmask));
                }
            }
        }
    }

    if subnets.is_empty() {
        let (primary_ip, primary_mask) = crate::sniffer::detect_primary_ipv4_and_subnet();
        if !primary_ip.is_loopback() && !primary_ip.is_link_local() && !primary_ip.is_unspecified() {
            subnets.push((primary_ip, primary_mask));
        }
    }

    subnets
}

/// 启动全局资产自动动态感知守护线程 (在后台自驱动，每 4 秒动态刷新)
pub fn start_asset_discovery_daemon(app: tauri::AppHandle) {
    std::thread::spawn(move || {
        // 启动时立即同步一次系统内核邻居表
        sync_kernel_neighbors(Some(&app));

        let mut ticker = 0u64;

        loop {
            std::thread::sleep(Duration::from_millis(4000));
            ticker += 1;

            // 1. 同步系统内核最新邻居表
            sync_kernel_neighbors(Some(&app));

            // 2. 每隔 20 秒执行一次温和的轻量多网段探活
            if ticker % 5 == 0 {
                let subnets = detect_physical_subnet_cidrs();
                #[cfg(windows)]
                for (ip, mask) in subnets {
                    // 自适应真值网段前 16 个常见关键节点探活（支持任意 /8../31 网段）
                    for target_ip in crate::platform_net::enumerate_cidr_scan_targets(ip, mask, 16) {
                        let dest_u32 = u32::from_ne_bytes(target_ip.octets());
                        let mut mac_buf = [0u8; 6];
                        let mut mac_len = 6u32;
                        let ret = unsafe {
                            SendARP(dest_u32, 0, mac_buf.as_mut_ptr(), &mut mac_len as *mut u32)
                        };
                        if ret == 0 && mac_len == 6 {
                            let mac_str = format!(
                                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                mac_buf[0], mac_buf[1], mac_buf[2], mac_buf[3], mac_buf[4], mac_buf[5]
                            );
                            record_asset_with_notify(&app, &target_ip.to_string(), &mac_str, "ARP_HEARTBEAT", 0);
                        }
                    }
                }
                #[cfg(not(windows))]
                let _ = subnets;
            }
        }
    });
}

/// 针对单个 IP 进行高频常用端口非阻塞并发探测 (Active Port Prober)
/// 覆盖：80 (HTTP), 443 (HTTPS), 5003 (SL651遥测), 502 (Modbus工业), 8080 (Web备用), 
/// 22 (SSH), 1883 (MQTT物联), 445 (SMB共享), 53 (DNS), 21 (FTP), 23 (Telnet), 3389 (RDP)
/// 行业全量默认高价值探测端口列表 (覆盖通用 Web/管理/文件/数据库 + 工控物联网核心端口 共 38 项)
pub const DEFAULT_PROBE_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 102, 110, 135, 139, 143, 443, 445, 502, 1433, 1521, 1883,
    2375, 2404, 3306, 3389, 4840, 5003, 5432, 5900, 6379, 8000, 8080, 8443, 8883,
    8888, 9000, 9090, 9200, 11211, 20000, 27017, 44818, 47808,
];

/// 按指定端口切片与并发批量上限探测目标资产开放端口
/// 时间复杂度: O(P / B), B = 12 批并发限制防 OS 线程枯竭; 空间复杂度: O(P)
pub fn probe_asset_ports_with_list(ip: &str, ports_to_probe: &[u16], timeout_ms: u64) -> Vec<u16> {
    if classify_ip(ip).is_none() || ports_to_probe.is_empty() {
        return Vec::new();
    }

    let ip_parsed = match ip.parse::<std::net::IpAddr>() {
        Ok(addr) => addr,
        Err(_) => return Vec::new(),
    };

    let clamped_timeout = Duration::from_millis(timeout_ms.clamp(100, 5000));
    let mut open_ports = Vec::new();

    for chunk in ports_to_probe.chunks(12) {
        let mut handles = Vec::with_capacity(chunk.len());
        for &port in chunk {
            let h = std::thread::spawn(move || {
                let socket_addr = std::net::SocketAddr::new(ip_parsed, port);
                if std::net::TcpStream::connect_timeout(&socket_addr, clamped_timeout).is_ok() {
                    Some(port)
                } else {
                    None
                }
            });
            handles.push(h);
        }
        for h in handles {
            if let Ok(Some(p)) = h.join() {
                open_ports.push(p);
            }
        }
    }

    open_ports.sort_unstable();
    open_ports.dedup();
    open_ports
}

pub fn probe_asset_ports(ip: &str, timeout_ms: u64) -> Vec<u16> {
    probe_asset_ports_with_list(ip, DEFAULT_PROBE_PORTS, timeout_ms)
}

/// 根据开放端口推断应用协议画像 (覆盖 IT 服务、数据库、远程管理及 OT 工控规约)
pub fn infer_protocol_by_port(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "TELNET",
        25 => "SMTP",
        53 => "DNS",
        80 | 81 | 8000 | 8080 | 8081 | 8888 | 9000 | 9090 => "HTTP",
        102 => "S7COMM",
        110 => "POP3",
        135 => "RPC",
        139 => "NETBIOS",
        143 => "IMAP",
        443 | 8443 => "HTTPS",
        445 => "SMB",
        502 => "MODBUS",
        1433 => "MSSQL",
        1521 => "ORACLE",
        1883 => "MQTT",
        2375 => "DOCKER",
        2404 => "IEC104",
        3306 => "MYSQL",
        3389 => "RDP",
        4840 => "OPC_UA",
        5003 => "SL651_WATER",
        5432 => "POSTGRESQL",
        5900 => "VNC",
        6379 => "REDIS",
        8883 => "MQTT_TLS",
        9200 => "ELASTICSEARCH",
        11211 => "MEMCACHED",
        20000 => "DNP3",
        27017 => "MONGODB",
        44818 => "ETHERNET_IP",
        47808 => "BACNET",
        _ => "TCP_SERVICE",
    }
}

/// 异步探测指定资产端口并回写资产画像与通知前端
pub fn probe_asset_ports_async(app: Option<tauri::AppHandle>, ip: String) {
    std::thread::spawn(move || {
        let open_ports = probe_asset_ports(&ip, 250);
        if !open_ports.is_empty() {
            for &p in &open_ports {
                let proto = infer_protocol_by_port(p);
                record_asset(&ip, "", proto, p);
            }
            if let Some(ref a) = app {
                let _ = a.emit("assets-updated", get_all_assets());
            }
        }
    });
}

/// 异步并发探测全量已知局域网资产开放端口
pub fn probe_all_assets_async(app: Option<tauri::AppHandle>) {
    let assets = get_all_assets();
    std::thread::spawn(move || {
        for asset in assets {
            if asset.scope == "局域网内网" || asset.scope == "链路本地" {
                let ip_clone = asset.ip.clone();
                let app_clone = app.clone();
                probe_asset_ports_async(app_clone, ip_clone);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    });
}

/// 针对 IPv4 / IPv6 字符串转换为自然排序键（用于列表稳定排序）
fn ip_to_sort_key(ip: &str) -> (u8, u128) {
    if let Ok(ipv4) = ip.parse::<std::net::Ipv4Addr>() {
        let oct = ipv4.octets();
        let val = ((oct[0] as u128) << 24)
            | ((oct[1] as u128) << 16)
            | ((oct[2] as u128) << 8)
            | (oct[3] as u128);
        (4, val)
    } else if let Ok(ipv6) = ip.parse::<std::net::Ipv6Addr>() {
        (6, u128::from_be_bytes(ipv6.octets()))
    } else {
        (9, 0)
    }
}

/// 获取全量已知资产列表（工业级稳定排序：网关优先 -> 角色权重 -> 自然 IP 地址递增）
/// 严格杜绝按动态变化的 last_seen_ts 排序，彻底消除前端表格行上下乱跳闪烁
pub fn get_all_assets() -> Vec<DiscoveredAsset> {
    let map = crate::lock_guard::lock_mutex(&ASSET_CACHE, "discovery::get_all_assets");
    let mut list: Vec<DiscoveredAsset> = map.values().cloned().collect();
    list.sort_by(|a, b| {
        // 权重 1: 角色优先级 (核心网关 > 控制中心/服务器 > PLC/RTU > 局域网终端 > 公网/外部)
        let role_weight = |role: &str, ip: &str| -> u32 {
            if ip.ends_with(".1") || ip.ends_with(".254") || role.contains("网关") || role.contains("路由") {
                10
            } else if role.contains("服务器") || role.contains("中心") || role.contains("SERVER") {
                20
            } else if role.contains("PLC") || role.contains("RTU") || role.contains("控制") {
                30
            } else if role.contains("局域网") || role.contains("终端") {
                40
            } else {
                50
            }
        };
        let wa = role_weight(&a.role, &a.ip);
        let wb = role_weight(&b.role, &b.ip);
        if wa != wb {
            return wa.cmp(&wb);
        }
        // 权重 2: IP 地址自然网络序 (192.168.1.1 < 192.168.1.2 < 192.168.1.100)
        ip_to_sort_key(&a.ip).cmp(&ip_to_sort_key(&b.ip))
    });
    list
}

/// 清空资产库
pub fn clear_assets() {
    let mut map = crate::lock_guard::lock_mutex(&ASSET_CACHE, "discovery::clear_assets");
    map.clear();
}

// ============================================================
// 资产快照持久化与多维差分比对引擎 (Asset Snapshot & Multi-dimensional Diff Engine)
// 100% 工业生产级实现：支持快照归档、时间序列回溯、MAC漂移与高危端口突变审计
// ============================================================

/// 资产快照完整归档实体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSnapshot {
    pub id: String,
    pub name: String,
    pub timestamp: u128,
    pub timestamp_str: String,
    pub total_assets: usize,
    pub total_open_ports: usize,
    pub assets: Vec<DiscoveredAsset>,
}

/// 资产快照轻量元数据（供前端列表与快速筛选）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSnapshotSummary {
    pub id: String,
    pub name: String,
    pub timestamp: u128,
    pub timestamp_str: String,
    pub total_assets: usize,
    pub total_open_ports: usize,
}

/// 开放端口差分详情
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetPortDiff {
    pub added_ports: Vec<u16>,
    pub closed_ports: Vec<u16>,
    pub has_high_risk_change: bool,
}

/// 单个资产多维差分审计项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetDiffItem {
    pub ip: String,
    pub diff_type: String, // "ADDED" | "REMOVED" | "MODIFIED" | "UNCHANGED"
    pub base_mac: Option<String>,
    pub target_mac: Option<String>,
    pub is_mac_drift: bool,
    pub base_vendor: Option<String>,
    pub target_vendor: Option<String>,
    pub base_role: Option<String>,
    pub target_role: Option<String>,
    pub port_diff: Option<AssetPortDiff>,
    pub base_ports: Vec<u16>,
    pub target_ports: Vec<u16>,
    pub risk_level: String, // "HIGH" | "MEDIUM" | "LOW" | "NORMAL"
    pub risk_desc: String,
}

/// 资产全景差分比对综合报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetDiffReport {
    pub base_name: String,
    pub base_time: String,
    pub target_name: String,
    pub target_time: String,
    pub total_base: usize,
    pub total_target: usize,
    pub added_count: usize,
    pub removed_count: usize,
    pub modified_count: usize,
    pub high_risk_count: usize,
    pub items: Vec<AssetDiffItem>,
}

/// 获取快照存储主目录
fn get_snapshot_dir() -> std::path::PathBuf {
    let dir = crate::forensics::data_path("asset_snapshots");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// 判断端口是否属于高危管理或工控端口
pub fn is_high_risk_port(port: u16) -> bool {
    matches!(
        port,
        21 | 22 | 23 | 25 | 110 | 135 | 139 | 445 | 1433 | 1521 | 3306 | 3389 | 5432 | 5900 | 6379 | 8080 | 8443 | 27017 // 通用管理/数据库
        | 102 | 502 | 1883 | 2404 | 4840 | 20000 | 44818 | 47808 // 工控 PLC/SCADA 协议端口
    )
}

/// 保存当前活跃资产为历史快照
/// 时间复杂度: O(N), N 为资产节点数
/// 空间复杂度: O(N)
pub fn save_asset_snapshot(name: Option<String>) -> Result<AssetSnapshotSummary, String> {
    let assets = get_all_assets();
    let total_assets = assets.len();
    let total_open_ports: usize = assets.iter().map(|a| a.ports.len()).sum();

    let now = std::time::SystemTime::now();
    let ts_ms = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis();
    let ts_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let snapshot_id = format!("snap_{}", chrono::Local::now().format("%Y%m%d_%H%M%S_%3f"));
    let snapshot_name = name.unwrap_or_else(|| format!("资产全景快照 {}", ts_str));

    let snapshot = AssetSnapshot {
        id: snapshot_id.clone(),
        name: snapshot_name.clone(),
        timestamp: ts_ms,
        timestamp_str: ts_str.clone(),
        total_assets,
        total_open_ports,
        assets,
    };

    let dir = get_snapshot_dir();
    let file_path = dir.join(format!("{}.json", snapshot_id));
    let json_bytes = serde_json::to_vec_pretty(&snapshot)
        .map_err(|e| format!("序列化资产快照失败: {}", e))?;

    std::fs::write(&file_path, json_bytes)
        .map_err(|e| format!("写入快照文件 {:?} 失败: {}", file_path, e))?;

    Ok(AssetSnapshotSummary {
        id: snapshot_id,
        name: snapshot_name,
        timestamp: ts_ms,
        timestamp_str: ts_str,
        total_assets,
        total_open_ports,
    })
}

/// 列出所有已保存的历史资产快照元数据（按时间倒序排列）
/// 时间复杂度: O(K log K), K 为快照文件数
/// 空间复杂度: O(K)
pub fn list_asset_snapshots() -> Result<Vec<AssetSnapshotSummary>, String> {
    let dir = get_snapshot_dir();
    let mut list = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(snap) = serde_json::from_str::<AssetSnapshot>(&content) {
                        list.push(AssetSnapshotSummary {
                            id: snap.id,
                            name: snap.name,
                            timestamp: snap.timestamp,
                            timestamp_str: snap.timestamp_str,
                            total_assets: snap.total_assets,
                            total_open_ports: snap.total_open_ports,
                        });
                    }
                }
            }
        }
    }

    list.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(list)
}

/// 读取指定 ID 的完整快照数据
pub fn get_asset_snapshot(id: &str) -> Result<AssetSnapshot, String> {
    let dir = get_snapshot_dir();
    let file_path = dir.join(format!("{}.json", id));
    if !file_path.exists() {
        return Err(format!("快照文件不存在: {}", id));
    }
    let content = std::fs::read_to_string(&file_path)
        .map_err(|e| format!("读取快照失败: {}", e))?;
    serde_json::from_str::<AssetSnapshot>(&content)
        .map_err(|e| format!("解析快照 JSON 失败: {}", e))
}

/// 删除指定 ID 的快照文件
pub fn delete_asset_snapshot(id: &str) -> Result<bool, String> {
    let dir = get_snapshot_dir();
    let file_path = dir.join(format!("{}.json", id));
    if file_path.exists() {
        std::fs::remove_file(&file_path)
            .map_err(|e| format!("删除快照文件失败: {}", e))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// 资产快照多维专业差分比对引擎
/// 支持：历史快照 vs 历史快照，或 历史快照 vs 当前实时资产
/// 时间复杂度: O(N + M), N 为基准资产数, M 为目标资产数
/// 空间复杂度: O(N + M)
pub fn compare_asset_snapshots(
    base_id: &str,
    target_id: Option<&str>,
) -> Result<AssetDiffReport, String> {
    let base_snap = get_asset_snapshot(base_id)?;

    let (target_name, target_time, target_assets) = match target_id {
        Some(tid) if !tid.is_empty() && tid != "CURRENT_REALTIME" => {
            let t_snap = get_asset_snapshot(tid)?;
            (t_snap.name, t_snap.timestamp_str, t_snap.assets)
        }
        _ => (
            "当前实时感知资产".to_string(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            get_all_assets(),
        ),
    };

    let base_map: HashMap<String, DiscoveredAsset> = base_snap
        .assets
        .into_iter()
        .map(|a| (a.ip.clone(), a))
        .collect();

    let target_map: HashMap<String, DiscoveredAsset> = target_assets
        .into_iter()
        .map(|a| (a.ip.clone(), a))
        .collect();

    let mut items = Vec::new();
    let mut added_count = 0;
    let mut removed_count = 0;
    let mut modified_count = 0;
    let mut high_risk_count = 0;

    // 1. 遍历目标资产集，识别 ADDED 与 MODIFIED
    for (ip, t_asset) in &target_map {
        if let Some(b_asset) = base_map.get(ip) {
            // 资产均存在，比对 MAC 漂移与端口变动
            let mut is_mac_drift = false;
            let mut mac_risk_desc = String::new();

            if !b_asset.mac.is_empty()
                && !t_asset.mac.is_empty()
                && b_asset.mac != "N/A"
                && t_asset.mac != "N/A"
                && b_asset.mac != t_asset.mac
            {
                is_mac_drift = true;
                mac_risk_desc = format!(
                    "⚠️ MAC 物理地址发生突变 ({} ➔ {})，可能存在 ARP 欺骗或网卡更换",
                    b_asset.mac, t_asset.mac
                );
            }

            let b_ports_set: std::collections::HashSet<u16> = b_asset.ports.iter().copied().collect();
            let t_ports_set: std::collections::HashSet<u16> = t_asset.ports.iter().copied().collect();

            let mut added_ports: Vec<u16> = t_ports_set.difference(&b_ports_set).copied().collect();
            let mut closed_ports: Vec<u16> = b_ports_set.difference(&t_ports_set).copied().collect();
            added_ports.sort_unstable();
            closed_ports.sort_unstable();

            let has_high_risk_added = added_ports.iter().any(|&p| is_high_risk_port(p));
            let has_port_diff = !added_ports.is_empty() || !closed_ports.is_empty();

            if is_mac_drift || has_port_diff || b_asset.role != t_asset.role {
                modified_count += 1;
                let mut risk_level = "NORMAL".to_string();
                let mut risk_descs = Vec::new();

                if is_mac_drift {
                    risk_level = "HIGH".to_string();
                    risk_descs.push(mac_risk_desc);
                }
                if has_high_risk_added {
                    risk_level = "HIGH".to_string();
                    let hr_ports: Vec<u16> = added_ports
                        .iter()
                        .copied()
                        .filter(|&p| is_high_risk_port(p))
                        .collect();
                    risk_descs.push(format!("🚨 新开放高危控制或远程管理端口: {:?}", hr_ports));
                } else if has_port_diff {
                    if risk_level != "HIGH" {
                        risk_level = "MEDIUM".to_string();
                    }
                    risk_descs.push(format!(
                        "端口集变动 (新增: {:?}, 关闭: {:?})",
                        added_ports, closed_ports
                    ));
                }

                if risk_level == "HIGH" {
                    high_risk_count += 1;
                }

                items.push(AssetDiffItem {
                    ip: ip.clone(),
                    diff_type: "MODIFIED".to_string(),
                    base_mac: Some(b_asset.mac.clone()),
                    target_mac: Some(t_asset.mac.clone()),
                    is_mac_drift,
                    base_vendor: Some(b_asset.vendor.clone()),
                    target_vendor: Some(t_asset.vendor.clone()),
                    base_role: Some(b_asset.role.clone()),
                    target_role: Some(t_asset.role.clone()),
                    port_diff: Some(AssetPortDiff {
                        added_ports,
                        closed_ports,
                        has_high_risk_change: has_high_risk_added,
                    }),
                    base_ports: b_asset.ports.clone(),
                    target_ports: t_asset.ports.clone(),
                    risk_level,
                    risk_desc: risk_descs.join(" | "),
                });
            }
        } else {
            // 新上线资产
            added_count += 1;
            let has_hr = t_asset.ports.iter().any(|&p| is_high_risk_port(p));
            let (risk_level, risk_desc) = if has_hr {
                high_risk_count += 1;
                (
                    "HIGH".to_string(),
                    format!("🚨 新增未知在线设备且开放高危端口: {:?}", t_asset.ports),
                )
            } else {
                (
                    "MEDIUM".to_string(),
                    format!("新发现入网节点 (厂商: {}, 角色: {})", t_asset.vendor, t_asset.role),
                )
            };

            items.push(AssetDiffItem {
                ip: ip.clone(),
                diff_type: "ADDED".to_string(),
                base_mac: None,
                target_mac: Some(t_asset.mac.clone()),
                is_mac_drift: false,
                base_vendor: None,
                target_vendor: Some(t_asset.vendor.clone()),
                base_role: None,
                target_role: Some(t_asset.role.clone()),
                port_diff: Some(AssetPortDiff {
                    added_ports: t_asset.ports.clone(),
                    closed_ports: Vec::new(),
                    has_high_risk_change: has_hr,
                }),
                base_ports: Vec::new(),
                target_ports: t_asset.ports.clone(),
                risk_level,
                risk_desc,
            });
        }
    }

    // 2. 遍历基准资产集，识别 REMOVED 下线资产
    for (ip, b_asset) in &base_map {
        if !target_map.contains_key(ip) {
            removed_count += 1;
            let (risk_level, risk_desc) = if b_asset.role.contains("网关") || b_asset.ports.iter().any(|&p| is_high_risk_port(p)) {
                (
                    "MEDIUM".to_string(),
                    format!("⚠️ 关键节点或工控设备已离线失联 (原角色: {})", b_asset.role),
                )
            } else {
                (
                    "NORMAL".to_string(),
                    format!("常规终端节点离线下线 (原 MAC: {})", b_asset.mac),
                )
            };

            items.push(AssetDiffItem {
                ip: ip.clone(),
                diff_type: "REMOVED".to_string(),
                base_mac: Some(b_asset.mac.clone()),
                target_mac: None,
                is_mac_drift: false,
                base_vendor: Some(b_asset.vendor.clone()),
                target_vendor: None,
                base_role: Some(b_asset.role.clone()),
                target_role: None,
                port_diff: Some(AssetPortDiff {
                    added_ports: Vec::new(),
                    closed_ports: b_asset.ports.clone(),
                    has_high_risk_change: false,
                }),
                base_ports: b_asset.ports.clone(),
                target_ports: Vec::new(),
                risk_level,
                risk_desc,
            });
        }
    }

    // 排序：高危优先，其次为新增与修改
    items.sort_by(|a, b| {
        let rank = |risk: &str| match risk {
            "HIGH" => 0,
            "MEDIUM" => 1,
            "LOW" => 2,
            _ => 3,
        };
        rank(&a.risk_level).cmp(&rank(&b.risk_level)).then_with(|| ip_to_sort_key(&a.ip).cmp(&ip_to_sort_key(&b.ip)))
    });

    Ok(AssetDiffReport {
        base_name: base_snap.name,
        base_time: base_snap.timestamp_str,
        target_name,
        target_time,
        total_base: base_map.len(),
        total_target: target_map.len(),
        added_count,
        removed_count,
        modified_count,
        high_risk_count,
        items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_protocol_by_port() {
        assert_eq!(infer_protocol_by_port(80), "HTTP");
        assert_eq!(infer_protocol_by_port(443), "HTTPS");
        assert_eq!(infer_protocol_by_port(8443), "HTTPS");
        assert_eq!(infer_protocol_by_port(5003), "SL651_WATER");
        assert_eq!(infer_protocol_by_port(502), "MODBUS");
        assert_eq!(infer_protocol_by_port(102), "S7COMM");
        assert_eq!(infer_protocol_by_port(2404), "IEC104");
        assert_eq!(infer_protocol_by_port(4840), "OPC_UA");
        assert_eq!(infer_protocol_by_port(1883), "MQTT");
        assert_eq!(infer_protocol_by_port(6379), "REDIS");
        assert_eq!(infer_protocol_by_port(3306), "MYSQL");
        assert_eq!(infer_protocol_by_port(22), "SSH");
        assert_eq!(infer_protocol_by_port(445), "SMB");
        assert_eq!(infer_protocol_by_port(53), "DNS");
        assert_eq!(infer_protocol_by_port(9999), "TCP_SERVICE");
        assert!(DEFAULT_PROBE_PORTS.len() >= 38);
    }

    #[test]
    fn test_record_asset_with_ports() {
        clear_assets();
        record_asset("192.168.1.1", "C4:51:8D:AA:BB:CC", "HTTP", 80);
        record_asset("192.168.1.1", "C4:51:8D:AA:BB:CC", "DNS", 53);
        let assets = get_all_assets();
        assert_eq!(assets.len(), 1);
        let a = &assets[0];
        assert_eq!(a.ip, "192.168.1.1");
        assert!(a.ports.contains(&80));
        assert!(a.ports.contains(&53));
        assert!(a.protocols.contains(&"HTTP".to_string()));
        assert!(a.protocols.contains(&"DNS".to_string()));
    }
}
