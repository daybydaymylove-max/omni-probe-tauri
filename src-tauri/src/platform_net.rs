//! 跨平台全网段与国产操作系统 (Kylin / UOS / openEuler / Deepin / Linux / Windows) 原生网络感知底座
//!
//! 职责：
//! 1. 纯 Rust 解析 Linux 内核原生 `/proc/net/route`、`/proc/net/fib_trie`、`/proc/self/status`、`ip -o -4 addr show` 与 `/etc/os-release`；
//! 2. 彻底消灭离线隔离内网靠连 `1.1.1.1` 猜 IP 失败退化为 `127.0.0.1`、或假定 `/24` 网段与 `euid == 0` 假绿灯的降智缺陷；
//! 3. 提供任意 CIDR (`/8`..`/31`) 自适应主机枚举与螺旋优先级收敛算法（支持 `/22`、`/23`、`/25` 等任意企业级子网）。

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformNetIface {
    pub iface_name: String,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub netmask: Ipv4Addr,
    pub default_route_metric: Option<u32>,
    pub has_gateway: bool,
    pub is_tunnel: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxRouteEntry {
    pub iface: String,
    pub destination: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub flags: u32,
    pub metric: u32,
    pub mask: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinuxPrivilegeStatus {
    pub euid: u32,
    pub cap_eff_mask: u64,
    pub has_cap_net_raw: bool,
    pub has_cap_net_admin: bool,
    pub is_capture_capable: bool,
}

/// 根据 CIDR 前缀长度 (0..=32) 推导子网掩码，复杂度 O(1)
#[inline]
pub fn prefix_len_to_netmask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    if prefix_len >= 32 {
        return Ipv4Addr::new(255, 255, 255, 255);
    }
    let mask_u32 = !0u32 << (32 - prefix_len as u32);
    Ipv4Addr::from(mask_u32)
}

/// 从子网掩码反算合法前缀长度 (0..=32)，复杂度 O(1)
#[inline]
pub fn netmask_to_prefix_len(netmask: Ipv4Addr) -> u8 {
    let bits = u32::from(netmask);
    bits.leading_ones() as u8
}

/// 将 Linux `/proc/net/route` 中的 8 位十六进制内核整数还原为 `Ipv4Addr`
/// 说明：Linux 内核按主机整数格式输出 `%08X`（对应内存中的 `__be32` 网络序字节），
/// `u32::to_ne_bytes()` 在 x86_64/ARM64/LoongArch64 小端与大端平台上均与内核输出严格互逆。
pub fn parse_proc_route_hex_ip(hex_str: &str) -> Option<Ipv4Addr> {
    let trimmed = hex_str.trim();
    if trimmed.is_empty() || trimmed.len() > 8 {
        return None;
    }
    let raw = u32::from_str_radix(trimmed, 16).ok()?;
    let bytes = raw.to_ne_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

/// 解析 Linux `/proc/net/route` 内容，提取全部活跃 UP 路由表项
/// 时间复杂度: O(R), 空间复杂度: O(R) (R 为路由条目数)
pub fn parse_linux_proc_route(content: &str) -> Vec<LinuxRouteEntry> {
    let mut entries = Vec::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        let flags = u32::from_str_radix(cols[3], 16).unwrap_or(0);
        if (flags & 0x1) == 0 {
            continue; // 仅保留 RTF_UP 活动路由
        }
        let Some(destination) = parse_proc_route_hex_ip(cols[1]) else {
            continue;
        };
        let Some(gateway) = parse_proc_route_hex_ip(cols[2]) else {
            continue;
        };
        let Some(mask) = parse_proc_route_hex_ip(cols[7]) else {
            continue;
        };
        let metric = cols[6].parse::<u32>().unwrap_or(0);
        entries.push(LinuxRouteEntry {
            iface: cols[0].to_string(),
            destination,
            gateway,
            flags,
            metric,
            mask,
        });
    }
    entries
}

/// 解析 `ip -o -4 addr show` 输出提取所有活跃非回环 IPv4 接口及其精确 CIDR 掩码
/// 时间复杂度: O(L), 空间复杂度: O(M)
pub fn parse_linux_ip_addr_output(output: &str, routes: &[LinuxRouteEntry]) -> Vec<PlatformNetIface> {
    let mut default_metrics: HashMap<String, (u32, bool)> = HashMap::new();
    for r in routes {
        let is_default_or_split = (r.destination == Ipv4Addr::UNSPECIFIED && r.mask == Ipv4Addr::UNSPECIFIED)
            || (r.destination == Ipv4Addr::UNSPECIFIED && r.mask == Ipv4Addr::new(128, 0, 0, 0))
            || (r.destination == Ipv4Addr::new(128, 0, 0, 0) && r.mask == Ipv4Addr::new(128, 0, 0, 0));
        if is_default_or_split {
            default_metrics
                .entry(r.iface.clone())
                .and_modify(|(m, gw)| {
                    if r.metric < *m {
                        *m = r.metric;
                    }
                    *gw = *gw || (r.flags & 0x2 != 0);
                })
                .or_insert((r.metric, r.flags & 0x2 != 0));
        }
    }

    let mut ifaces = Vec::new();
    let mut seen_ips = BTreeSet::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // 标准 `ip -o -4 addr show` 格式:
        // "2: eth0    inet 192.168.10.25/23 brd 192.168.11.255 scope global dynamic eth0"
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let Some(inet_pos) = tokens.iter().position(|&t| t == "inet") else {
            continue;
        };
        if inet_pos < 2 || inet_pos + 1 >= tokens.len() {
            continue;
        }
        let iface_raw = tokens[1].trim_end_matches(':');
        let lower_name = iface_raw.to_ascii_lowercase();
        if lower_name == "lo" || lower_name.starts_with("loopback") {
            continue;
        }

        let cidr_token = tokens[inet_pos + 1];
        let mut split_cidr = cidr_token.split('/');
        let Ok(ip) = split_cidr.next().unwrap_or("").parse::<Ipv4Addr>() else {
            continue;
        };
        let oct = ip.octets();
        if ip.is_loopback() || ip.is_unspecified() || (oct[0] == 169 && oct[1] == 254) {
            continue;
        }
        if !seen_ips.insert(ip) {
            continue;
        }

        let prefix_len = split_cidr
            .next()
            .and_then(|p| p.parse::<u8>().ok())
            .unwrap_or(24)
            .min(32);
        let netmask = prefix_len_to_netmask(prefix_len);
        let is_tunnel = lower_name.starts_with("tun")
            || lower_name.starts_with("tap")
            || lower_name.starts_with("wg")
            || lower_name.contains("tailscale")
            || lower_name.contains("clash")
            || lower_name.contains("utun")
            || lower_name.contains("ppp");

        let route_info = default_metrics.get(iface_raw).copied();
        ifaces.push(PlatformNetIface {
            iface_name: iface_raw.to_string(),
            ip,
            prefix_len,
            netmask,
            default_route_metric: route_info.map(|(m, _)| m),
            has_gateway: route_info.map(|(_, g)| g).unwrap_or(false) || is_tunnel,
            is_tunnel,
        });
    }

    sort_platform_ifaces(&mut ifaces);
    ifaces
}

/// 当极简国产环境/容器缺失 `ip` 命令时，直接从内核 `/proc/net/fib_trie` 提取本地单播地址并结合路由表反推掩码
/// 时间复杂度: O(T), 空间复杂度: O(M)
pub fn parse_linux_fib_trie_locals(fib_content: &str, routes: &[LinuxRouteEntry]) -> Vec<PlatformNetIface> {
    let mut local_ips = BTreeSet::new();
    let lines: Vec<&str> = fib_content.lines().collect();
    for i in 0..lines.len() {
        let cur = lines[i].trim();
        if cur.contains("/32 host LOCAL") {
            // 向上回溯最近一行 `|-- <ip>`
            if i > 0 {
                let prev = lines[i - 1].trim();
                let candidate = prev
                    .trim_start_matches("|--")
                    .trim_start_matches("+--")
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .trim();
                if let Ok(ip) = candidate.parse::<Ipv4Addr>() {
                    let oct = ip.octets();
                    if !ip.is_loopback() && !ip.is_unspecified() && !(oct[0] == 169 && oct[1] == 254) {
                        local_ips.insert(ip);
                    }
                }
            }
        }
    }

    let mut ifaces = Vec::new();
    for ip in local_ips {
        let ip_u32 = u32::from(ip);
        let mut best_iface = "eth0".to_string();
        let mut best_mask = Ipv4Addr::new(255, 255, 255, 0);
        let mut best_prefix = 24u8;

        for r in routes {
            if r.mask != Ipv4Addr::UNSPECIFIED && r.mask != Ipv4Addr::new(255, 255, 255, 255) {
                let m_u32 = u32::from(r.mask);
                let dst_u32 = u32::from(r.destination);
                if (ip_u32 & m_u32) == (dst_u32 & m_u32) {
                    let p = netmask_to_prefix_len(r.mask);
                    if p >= best_prefix || best_iface == "eth0" {
                        best_iface = r.iface.clone();
                        best_mask = r.mask;
                        best_prefix = p;
                    }
                }
            }
        }

        let def_metric = routes
            .iter()
            .filter(|r| r.iface == best_iface && r.destination == Ipv4Addr::UNSPECIFIED)
            .map(|r| r.metric)
            .min();
        let lower = best_iface.to_ascii_lowercase();
        let is_tunnel = lower.starts_with("tun") || lower.starts_with("tap") || lower.starts_with("wg");

        ifaces.push(PlatformNetIface {
            iface_name: best_iface,
            ip,
            prefix_len: best_prefix,
            netmask: best_mask,
            default_route_metric: def_metric,
            has_gateway: def_metric.is_some() || is_tunnel,
            is_tunnel,
        });
    }

    sort_platform_ifaces(&mut ifaces);
    ifaces
}

fn sort_platform_ifaces(ifaces: &mut [PlatformNetIface]) {
    ifaces.sort_by_key(|item| {
        let tier = if item.default_route_metric.is_some() {
            0u8
        } else if item.has_gateway || item.is_tunnel {
            1u8
        } else {
            2u8
        };
        (tier, item.default_route_metric.unwrap_or(u32::MAX), item.ip)
    });
}

/// 解析 `/proc/self/status` 中的 `Uid` 与 `CapEff` 判定国产 Linux 真实底层捕获能力
/// 说明：Linux Capabilities 定义 `CAP_NET_ADMIN = 12`, `CAP_NET_RAW = 13`
pub fn parse_linux_proc_self_status(content: &str) -> LinuxPrivilegeStatus {
    let mut euid = u32::MAX;
    let mut cap_eff = 0u64;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Uid:") {
            // 格式: Uid: <real> <effective> <saved> <fs>
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(u) = parts[1].parse::<u32>() {
                    euid = u;
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("CapEff:") {
            if let Ok(mask) = u64::from_str_radix(rest.trim(), 16) {
                cap_eff = mask;
            }
        }
    }
    let has_cap_net_admin = (cap_eff & (1u64 << 12)) != 0;
    let has_cap_net_raw = (cap_eff & (1u64 << 13)) != 0;
    let is_capture_capable = euid == 0 || has_cap_net_raw;
    LinuxPrivilegeStatus {
        euid,
        cap_eff_mask: cap_eff,
        has_cap_net_raw,
        has_cap_net_admin,
        is_capture_capable,
    }
}

/// 提取当前 Linux/国产发行版名称 (从 `/etc/os-release` 读取 PRETTY_NAME)
pub fn parse_os_release_pretty_name(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("PRETTY_NAME=") {
            return Some(val.trim_matches('"').trim_matches('\'').to_string());
        }
    }
    None
}

/// 采集当前 Linux 本机真实多接口（优先 `ip -o -4 addr show`，缺省时无缝切入 `/proc/net/fib_trie`）
#[cfg(target_os = "linux")]
pub fn discover_linux_interfaces() -> Vec<PlatformNetIface> {
    let route_txt = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    let routes = parse_linux_proc_route(&route_txt);

    if let Ok(out) = std::process::Command::new("ip")
        .args(["-o", "-4", "addr", "show", "up"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let parsed = parse_linux_ip_addr_output(&text, &routes);
            if !parsed.is_empty() {
                return parsed;
            }
        }
    }

    let fib_txt = std::fs::read_to_string("/proc/net/fib_trie").unwrap_or_default();
    parse_linux_fib_trie_locals(&fib_txt, &routes)
}

#[cfg(target_os = "linux")]
pub fn inspect_linux_privilege_and_distro() -> (LinuxPrivilegeStatus, String) {
    let status_txt = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let priv_status = parse_linux_proc_self_status(&status_txt);
    let os_txt = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let distro = parse_os_release_pretty_name(&os_txt).unwrap_or_else(|| "Generic Linux".to_string());
    (priv_status, distro)
}

#[cfg(target_os = "linux")]
pub fn detect_linux_libpcap_library() -> Option<String> {
    let candidates = [
        "/usr/lib/x86_64-linux-gnu/libpcap.so.0.8",
        "/usr/lib/aarch64-linux-gnu/libpcap.so.0.8",
        "/usr/lib/loongarch64-linux-gnu/libpcap.so.0.8",
        "/usr/lib64/libpcap.so.1",
        "/usr/lib64/libpcap.so",
        "/usr/lib/libpcap.so",
        "/lib/x86_64-linux-gnu/libpcap.so.0.8",
        "/lib/aarch64-linux-gnu/libpcap.so.0.8",
    ];
    for p in candidates {
        if std::path::Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    if let Ok(out) = std::process::Command::new("ldconfig").arg("-p").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if line.contains("libpcap.so") {
                if let Some(path_part) = line.split("=>").nth(1) {
                    return Some(path_part.trim().to_string());
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub fn detect_linux_usbmon_node() -> Option<String> {
    for p in ["/dev/usbmon0", "/dev/usbmon1", "/sys/kernel/debug/usb/usbmon"] {
        if std::path::Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    None
}

/// 自适应任意 CIDR (`/8`..`/31`) 主机扫描目标生成算法（彻底替代写死 `/24` 扫描）
///
/// 算法设计：
/// - 若可用主机数 <= `max_hosts`（覆盖 `/30`, `/29`, `/25`, `/24`, `/23`, `/22` 等常见企事业单位子网），按真实网络地址与广播地址边界全量生成；
/// - 若属于超大规模网段 (`/21`..`/8` 等，主机数 > `max_hosts`)，绝不从 `.0.1` 线性盲扫遗漏本机周边设备：
///   优先加入本机所在 `/24` 的全部主机 + 相邻前后 `/24` 主机 + 各个邻近 `/24` 块的标准网关/核心节点 (`.1`, `.2`, `.254`)，按预算上限 `max_hosts` 螺旋收敛。
///
/// 时间复杂度: O(min(H, max_hosts)), 空间复杂度: O(min(H, max_hosts))
pub fn enumerate_cidr_scan_targets(
    local_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    max_hosts: usize,
) -> Vec<Ipv4Addr> {
    if max_hosts == 0 || local_ip.is_loopback() || local_ip.is_unspecified() {
        return Vec::new();
    }
    let mask_u32 = u32::from(netmask);
    let prefix = netmask_to_prefix_len(netmask);
    // 防御非连续掩码或过小/主机路由 (/32) 掩码
    if mask_u32 != u32::from(prefix_len_to_netmask(prefix)) || prefix >= 32 || prefix < 8 {
        return Vec::new();
    }

    let local_u32 = u32::from(local_ip);
    let net_u32 = local_u32 & mask_u32;
    let bcast_u32 = net_u32 | !mask_u32;

    if prefix == 31 {
        let other = if local_u32 == net_u32 { bcast_u32 } else { net_u32 };
        return vec![Ipv4Addr::from(other)];
    }

    let usable_start = net_u32.saturating_add(1);
    let usable_end = bcast_u32.saturating_sub(1);
    if usable_start > usable_end {
        return Vec::new();
    }

    let total_usable = (usable_end - usable_start) as usize + 1;
    if total_usable <= max_hosts {
        let mut out = Vec::with_capacity(total_usable);
        for addr in usable_start..=usable_end {
            if addr != local_u32 {
                out.push(Ipv4Addr::from(addr));
            }
        }
        return out;
    }

    // 超大子网螺旋扩散收敛（以本机所在 /24 区块为中心）
    let mut out = Vec::with_capacity(max_hosts);
    let mut seen = BTreeSet::new();
    let local_slash24_base = local_u32 & 0xFFFF_FF00;

    let mut push_if_valid = |addr: u32, vec: &mut Vec<Ipv4Addr>| {
        if vec.len() < max_hosts
            && addr >= usable_start
            && addr <= usable_end
            && addr != local_u32
            && seen.insert(addr)
        {
            vec.push(Ipv4Addr::from(addr));
        }
    };

    // 1. 先覆盖整个子网的首部关键网关 (net+1, net+2)
    push_if_valid(usable_start, &mut out);
    push_if_valid(usable_start.saturating_add(1), &mut out);

    // 2. 螺旋扩张本机所属 /24 及相邻前后 /24 段
    let mut offset_blocks: i64 = 0;
    let mut step = 0i64;
    while out.len() < max_hosts && step < 32 {
        let base_i64 = local_slash24_base as i64 + offset_blocks * 256;
        if base_i64 >= (net_u32 as i64) && base_i64 <= (bcast_u32 as i64) {
            let base = base_i64 as u32;
            // 先加各块常见的 .1 / .254，再展开全段
            push_if_valid(base + 1, &mut out);
            push_if_valid(base + 254, &mut out);
            for host in 2..=253u32 {
                if out.len() >= max_hosts {
                    break;
                }
                push_if_valid(base + host, &mut out);
            }
        }
        step += 1;
        offset_blocks = if step % 2 == 1 {
            (step + 1) / 2
        } else {
            -(step / 2)
        };
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_proc_route_and_ip_addr_parsing_offline() {
        // 模拟国产麒麟/UOS/openEuler 离线内网（无公网连接，含 /23 企业网段与 tun0 默认接管）
        let route_sample = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
tun0\t00000000\t00000000\t0001\t0\t0\t5\t00000080\t0\t0\t0
eth0\t00000000\t010AA8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t000AA8C0\t00000000\t0001\t0\t0\t100\t00FEFFFF\t0\t0\t0
";
        let routes = parse_linux_proc_route(route_sample);
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[1].gateway, Ipv4Addr::new(192, 168, 10, 1));
        assert_eq!(routes[2].destination, Ipv4Addr::new(192, 168, 10, 0));
        assert_eq!(routes[2].mask, Ipv4Addr::new(255, 255, 254, 0));

        let ip_addr_sample = "\
1: lo    inet 127.0.0.1/8 scope host lo
2: eth0    inet 192.168.10.25/23 brd 192.168.11.255 scope global dynamic eth0
3: tun0    inet 10.66.0.2/24 scope global tun0
";
        let ifaces = parse_linux_ip_addr_output(ip_addr_sample, &routes);
        assert_eq!(ifaces.len(), 2);
        // tun0 Metric=5 分流接管优先排序，eth0 /23 紧随其后
        assert_eq!(ifaces[0].iface_name, "tun0");
        assert_eq!(ifaces[0].default_route_metric, Some(5));
        assert_eq!(ifaces[1].iface_name, "eth0");
        assert_eq!(ifaces[1].prefix_len, 23);
        assert_eq!(ifaces[1].netmask, Ipv4Addr::new(255, 255, 254, 0));
    }

    #[test]
    fn test_linux_fib_trie_zero_cmd_fallback_and_capabilities() {
        let route_sample = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
enp3s0\t00000000\t011010AC\t0003\t0\t0\t50\t00000000\t0\t0\t0
enp3s0\t001010AC\t00000000\t0001\t0\t0\t50\t00F8FFFF\t0\t0\t0
";
        let fib_sample = "\
Main:
  +-- 127.0.0.1/32
     /32 host LOCAL
  +-- 172.16.16.88/32
     /32 host LOCAL
";
        let routes = parse_linux_proc_route(route_sample);
        let ifaces = parse_linux_fib_trie_locals(fib_sample, &routes);
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].iface_name, "enp3s0");
        assert_eq!(ifaces[0].ip, Ipv4Addr::new(172, 16, 16, 88));
        assert_eq!(ifaces[0].prefix_len, 21);

        // 验证 /proc/self/status 权限位识别
        let unpriv = parse_linux_proc_self_status("Uid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n");
        assert!(!unpriv.is_capture_capable);
        assert!(!unpriv.has_cap_net_raw);

        let setcap = parse_linux_proc_self_status("Uid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000003000\n");
        assert!(setcap.has_cap_net_raw);
        assert!(setcap.has_cap_net_admin);
        assert!(setcap.is_capture_capable);

        assert_eq!(
            parse_os_release_pretty_name("NAME=\"Kylin\"\nPRETTY_NAME=\"Kylin Linux Advanced Server V10\""),
            Some("Kylin Linux Advanced Server V10".to_string())
        );
    }

    #[test]
    fn test_enumerate_cidr_scan_targets_all_subnet_sizes_and_extremes() {
        // 1. /30 点对点小网段（仅含 2 个可用主机，排除自身只余 1 个）
        let t30 = enumerate_cidr_scan_targets(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(255, 255, 255, 252), 1024);
        assert_eq!(t30, vec![Ipv4Addr::new(10, 0, 0, 2)]);

        // 2. /23 企业中型网段 (510 台可用主机，排除自身 = 509)
        let t23 = enumerate_cidr_scan_targets(Ipv4Addr::new(192, 168, 10, 25), Ipv4Addr::new(255, 255, 254, 0), 1024);
        assert_eq!(t23.len(), 509);
        assert!(t23.contains(&Ipv4Addr::new(192, 168, 11, 200)), "必须跨入 /23 邻近奇数子段");

        // 3. /16 超大网段螺旋收敛验证：必须在预算内先命中本机所在 .50.x 与总网关 .0.1
        let t16 = enumerate_cidr_scan_targets(Ipv4Addr::new(10, 20, 50, 99), Ipv4Addr::new(255, 255, 0, 0), 600);
        assert_eq!(t16.len(), 600);
        assert!(t16.contains(&Ipv4Addr::new(10, 20, 0, 1)));
        assert!(t16.contains(&Ipv4Addr::new(10, 20, 50, 1)));
        assert!(t16.contains(&Ipv4Addr::new(10, 20, 50, 200)));

        // 4. 极限/畸形边界防御：环回、预算=0、非连续子网掩码、/32 主机路由
        assert!(enumerate_cidr_scan_targets(Ipv4Addr::LOCALHOST, Ipv4Addr::new(255, 0, 0, 0), 100).is_empty());
        assert!(enumerate_cidr_scan_targets(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(255, 255, 255, 0), 0).is_empty());
        assert!(enumerate_cidr_scan_targets(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(255, 0, 255, 0), 100).is_empty());
        assert!(enumerate_cidr_scan_targets(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(255, 255, 255, 255), 100).is_empty());
    }
}
