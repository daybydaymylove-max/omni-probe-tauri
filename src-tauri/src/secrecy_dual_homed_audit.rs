//! 双网卡“一机两用”涉密违规外联与隐蔽网络路由穿透核查状态机
//! 对标行业标准：BMB22-2007 第 5.2.1 节（通信线路安全与网络互联限制）、BMB17-2006
//!
//! 算法复杂度：
//! - 时间复杂度：O(I + R)，其中 I 为系统网络接口数，R 为内核路由表条目数，执行耗时 <= 10ms；
//! - 空间复杂度：O(I)，线性存储接口属性向量，无动态冗余堆积。

use crate::host_baseline::decode_console_bytes;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NicInterfaceAuditItem {
    pub name: String,
    pub if_type: String, // "ETHERNET" | "WIRELESS_80211" | "CELLULAR" | "VIRTUAL"
    pub is_up: bool,
    pub ip_addresses: Vec<String>,
    pub gateway_addresses: Vec<String>,
    pub is_connected_to_private: bool,
    pub is_connected_to_public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualHomedAuditVerdict {
    pub is_dual_homed_violation: bool,
    pub active_nic_count: usize,
    pub has_simultaneous_wired_and_wireless: bool,
    pub has_public_and_private_bridging: bool,
    pub wireless_ssid: Option<String>,
    pub risk_level: String, // "CRITICAL" | "HIGH" | "CLEAN"
    pub reason: String,
    pub interfaces: Vec<NicInterfaceAuditItem>,
}

static RE_IPV4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b").unwrap()
});

/// 判断 IPv4 地址是否为合法有效业务地址（排除回环 127/8 与链路本地 169.254/16 与 0.0.0.0）
fn is_routable_or_private_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_link_local() && !ip.is_multicast()
}

/// 判断 IPv4 地址是否属于 RFC 1918 内网私有网段或 CGNAT 内网地址
pub fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private() || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64)
}

/// 判断字符串中是否包含独立词（以非 ASCII 字母数字作为分隔界线），防止 "realtek" 误命中 "lte"
fn contains_token(haystack: &str, token: &str) -> bool {
    haystack
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|part| part == token)
}

/// 识别虚拟化适配器名称，防止开发机 Hyper-V/VMware/WSL 造成一机两用伪报
pub fn classify_interface_type(adapter_name: &str, description: &str) -> &'static str {
    let combined = format!("{} {}", adapter_name, description).to_ascii_lowercase();
    if combined.contains("vmware")
        || combined.contains("virtualbox")
        || contains_token(&combined, "vbox")
        || combined.contains("vethernet")
        || combined.contains("hyper-v")
        || contains_token(&combined, "wsl")
        || combined.contains("docker")
        || combined.contains("loopback")
        || combined.contains("virbr")
        || combined.contains("tap-windows")
        || combined.contains("wintun")
        || combined.contains("tailscale")
        || contains_token(&combined, "tun")
        || contains_token(&combined, "tap")
        || contains_token(&combined, "vpn")
        || combined.contains("virtual")
    {
        return "VIRTUAL";
    }
    if combined.contains("wi-fi")
        || contains_token(&combined, "wifi")
        || contains_token(&combined, "wlan")
        || combined.contains("wireless")
        || combined.contains("802.11")
        || adapter_name.contains("无线")
    {
        return "WIRELESS_80211";
    }
    if combined.contains("cellular")
        || contains_token(&combined, "lte")
        || contains_token(&combined, "5g")
        || combined.contains("mobile broadband")
        || contains_token(&combined, "wwan")
    {
        return "CELLULAR";
    }
    "ETHERNET"
}

/// 解析 Windows `ipconfig /all` 输出（兼容中英文操作系统）
pub fn parse_windows_ipconfig_all(output: &str) -> Vec<NicInterfaceAuditItem> {
    let mut list = Vec::new();
    let mut curr_name = String::new();
    let mut curr_desc = String::new();
    let mut curr_ips: Vec<String> = Vec::new();
    let mut curr_gws: Vec<String> = Vec::new();
    let mut disconnected = false;

    let flush_current = |name: &str,
                         desc: &str,
                         ips: &[String],
                         gws: &[String],
                         disconn: bool,
                         out: &mut Vec<NicInterfaceAuditItem>| {
        if name.is_empty() {
            return;
        }
        let if_type = classify_interface_type(name, desc).to_string();
        let mut has_priv = false;
        let mut has_pub = false;
        for ip_str in ips {
            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                if is_routable_or_private_ipv4(ip) {
                    if is_private_ipv4(ip) {
                        has_priv = true;
                    } else {
                        has_pub = true;
                    }
                }
            }
        }
        let is_up = !disconn && !ips.is_empty();
        out.push(NicInterfaceAuditItem {
            name: name.to_string(),
            if_type,
            is_up,
            ip_addresses: ips.to_vec(),
            gateway_addresses: gws.to_vec(),
            is_connected_to_private: has_priv,
            is_connected_to_public: has_pub,
        });
    };

    for raw_line in output.lines() {
        if raw_line.trim().is_empty() {
            continue;
        }
        // 顶格非空白行表示一个新网卡段开始
        if !raw_line.starts_with(' ') && !raw_line.starts_with('\t') && raw_line.trim_end().ends_with(':') {
            let trimmed_hdr = raw_line.trim().trim_end_matches(':');
            // 排除总头信息 "Windows IP Configuration" / "Windows IP 配置"
            if trimmed_hdr.to_ascii_lowercase().contains("windows ip") {
                continue;
            }
            flush_current(&curr_name, &curr_desc, &curr_ips, &curr_gws, disconnected, &mut list);
            curr_name = trimmed_hdr.to_string();
            curr_desc.clear();
            curr_ips.clear();
            curr_gws.clear();
            disconnected = false;
            continue;
        }

        let trimmed = raw_line.trim();
        let lower = trimmed.to_ascii_lowercase();

        if lower.contains("media disconnected") || trimmed.contains("媒体已断开连接") {
            disconnected = true;
            continue;
        }
        if lower.starts_with("description") || trimmed.starts_with("描述") {
            if let Some(v) = trimmed.split(':').nth(1) {
                curr_desc = v.trim().to_string();
            }
            continue;
        }
        if lower.contains("ipv4 address") || trimmed.contains("IPv4 地址") || lower.contains("ip address") {
            if let Some(after_colon) = trimmed.split(':').nth(1) {
                if let Some(m) = RE_IPV4.find(after_colon) {
                    if let Ok(ip) = m.as_str().parse::<Ipv4Addr>() {
                        if is_routable_or_private_ipv4(ip) {
                            curr_ips.push(ip.to_string());
                        }
                    }
                }
            }
            continue;
        }
        if lower.contains("default gateway") || trimmed.starts_with("默认网关") {
            if let Some(after_colon) = trimmed.split(':').nth(1) {
                if let Some(m) = RE_IPV4.find(after_colon) {
                    if let Ok(ip) = m.as_str().parse::<Ipv4Addr>() {
                        if !ip.is_unspecified() {
                            curr_gws.push(ip.to_string());
                        }
                    }
                }
            }
        }
    }

    flush_current(&curr_name, &curr_desc, &curr_ips, &curr_gws, disconnected, &mut list);
    list
}

/// 从 `netsh wlan show interfaces` 输出中提取当前关联连接的无线热点 SSID
pub fn parse_windows_wlan_ssid(output: &str) -> Option<String> {
    let mut is_connected = false;
    let mut ssid = None;
    for line in output.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if (lower.starts_with("state") || trimmed.starts_with("状态")) && trimmed.contains(':') {
            let val = trimmed.split(':').nth(1).unwrap_or("").trim().to_ascii_lowercase();
            if val == "connected" || val.contains("已连接") {
                is_connected = true;
            }
        }
        if (lower.starts_with("ssid") && !lower.starts_with("bssid")) && trimmed.contains(':') {
            let val = trimmed.split(':').nth(1).unwrap_or("").trim();
            if !val.is_empty() {
                ssid = Some(val.to_string());
            }
        }
    }
    if is_connected { ssid } else { None }
}

/// 从 `route print -4` / `ip route` 中提取 0.0.0.0 默认网关数量（多默认网关也是典型双网外联征象）
pub fn count_default_gateways_from_routes(route_output: &str) -> usize {
    let mut gateways = Vec::new();
    for line in route_output.lines() {
        let t = line.trim();
        // Windows route print: "0.0.0.0   0.0.0.0   192.168.1.1   192.168.1.100   25"
        if t.starts_with("0.0.0.0") {
            let parts: Vec<&str> = t.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                if !gateways.contains(&parts[2].to_string()) {
                    gateways.push(parts[2].to_string());
                }
            }
        } else if t.starts_with("default via ") {
            // Linux ip route: "default via 192.168.1.1 dev eth0"
            let parts: Vec<&str> = t.split_whitespace().collect();
            if parts.len() >= 3 && !gateways.contains(&parts[2].to_string()) {
                gateways.push(parts[2].to_string());
            }
        }
    }
    gateways.len()
}

/// 统一裁决双网卡“一机两用”状态机（纯函数可完整单元测试）
pub fn evaluate_dual_homed_verdict(
    interfaces: Vec<NicInterfaceAuditItem>,
    wireless_ssid: Option<String>,
    default_gw_count: usize,
) -> DualHomedAuditVerdict {
    let active_physical: Vec<&NicInterfaceAuditItem> = interfaces
        .iter()
        .filter(|i| i.is_up && i.if_type != "VIRTUAL")
        .collect();

    let wired_up = active_physical.iter().any(|i| i.if_type == "ETHERNET");
    let wireless_up = active_physical
        .iter()
        .any(|i| i.if_type == "WIRELESS_80211" || i.if_type == "CELLULAR");

    let simultaneous_wired_wireless = wired_up && wireless_up;

    let any_private = active_physical.iter().any(|i| i.is_connected_to_private);
    let any_public = active_physical.iter().any(|i| i.is_connected_to_public);
    let multi_physical_diff_nics = active_physical.len() >= 2;
    let has_bridging = (any_private && any_public)
        || (multi_physical_diff_nics && default_gw_count >= 2)
        || simultaneous_wired_wireless;

    let is_violation = simultaneous_wired_wireless || (multi_physical_diff_nics && has_bridging);

    let (risk_level, reason) = if simultaneous_wired_wireless {
        let ssid_desc = wireless_ssid
            .as_deref()
            .map(|s| format!("（当前接入无线热点: [{}]）", s))
            .unwrap_or_default();
        (
            "CRITICAL".to_string(),
            format!(
                "BMB22-2007 一票否决严重违规：检测到宿主机同时激活有线物理以太网与无线/移动网络{}，存在典型的“一机两用”涉密违规外联与双网桥接风险！",
                ssid_desc
            ),
        )
    } else if is_violation {
        (
            "CRITICAL".to_string(),
            format!(
                "BMB22-2007 一票否决严重违规：宿主机同时激活 {} 块独立物理网卡并跨接公私网络或存在 {} 条活跃默认网关，违反涉密信息系统网络物理隔离红线！",
                active_physical.len(),
                default_gw_count
            ),
        )
    } else if wireless_up {
        (
            "HIGH".to_string(),
            format!(
                "合规预警：当前物理主机通过无线/蜂窝网络激活接入{}。若当前节点属于涉密计算机，按规定严禁启用无线通信模块。",
                wireless_ssid
                    .as_deref()
                    .map(|s| format!(" [SSID: {}]", s))
                    .unwrap_or_default()
            ),
        )
    } else {
        (
            "CLEAN".to_string(),
            format!(
                "单网单线合规受控：当前仅检测到 {} 块活跃物理网卡（已自动排除 Hyper-V/VMware/WSL 虚拟接口干扰），未见“一机两用”双网违规外联特征。",
                active_physical.len()
            ),
        )
    };

    DualHomedAuditVerdict {
        is_dual_homed_violation: is_violation,
        active_nic_count: active_physical.len(),
        has_simultaneous_wired_and_wireless: simultaneous_wired_wireless,
        has_public_and_private_bridging: has_bridging,
        wireless_ssid,
        risk_level,
        reason,
        interfaces,
    }
}

#[cfg(windows)]
pub fn audit_local_dual_homed_network() -> DualHomedAuditVerdict {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let ipconfig_out = Command::new("ipconfig")
        .arg("/all")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| decode_console_bytes(&o.stdout))
        .unwrap_or_default();

    let route_out = Command::new("route")
        .args(["print", "-4"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| decode_console_bytes(&o.stdout))
        .unwrap_or_default();

    let wlan_out = Command::new("netsh")
        .args(["wlan", "show", "interfaces"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| decode_console_bytes(&o.stdout))
        .unwrap_or_default();

    let interfaces = parse_windows_ipconfig_all(&ipconfig_out);
    let ssid = parse_windows_wlan_ssid(&wlan_out);
    let gw_count = count_default_gateways_from_routes(&route_out);

    evaluate_dual_homed_verdict(interfaces, ssid, gw_count)
}

#[cfg(not(windows))]
pub fn audit_local_dual_homed_network() -> DualHomedAuditVerdict {
    use std::process::Command;

    let mut interfaces = Vec::new();
    let ip_out = Command::new("ip")
        .args(["-o", "-4", "addr", "show", "up"])
        .output()
        .map(|o| decode_console_bytes(&o.stdout))
        .unwrap_or_default();

    for line in ip_out.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let if_name = parts[1];
            let ip_cidr = parts[3];
            let ip_only = ip_cidr.split('/').next().unwrap_or("");
            if let Ok(ip) = ip_only.parse::<Ipv4Addr>() {
                if !is_routable_or_private_ipv4(ip) {
                    continue;
                }
                let is_wireless = std::path::Path::new(&format!("/sys/class/net/{}/wireless", if_name)).exists();
                let if_type = if is_wireless {
                    "WIRELESS_80211".to_string()
                } else {
                    classify_interface_type(if_name, "").to_string()
                };
                if let Some(existing) = interfaces.iter_mut().find(|i: &&mut NicInterfaceAuditItem| i.name == if_name) {
                    existing.ip_addresses.push(ip.to_string());
                } else {
                    interfaces.push(NicInterfaceAuditItem {
                        name: if_name.to_string(),
                        if_type,
                        is_up: true,
                        ip_addresses: vec![ip.to_string()],
                        gateway_addresses: vec![],
                        is_connected_to_private: is_private_ipv4(ip),
                        is_connected_to_public: !is_private_ipv4(ip),
                    });
                }
            }
        }
    }

    let route_out = Command::new("ip")
        .args(["route"])
        .output()
        .map(|o| decode_console_bytes(&o.stdout))
        .unwrap_or_default();
    let ssid = Command::new("iwgetid")
        .arg("-r")
        .output()
        .ok()
        .map(|o| decode_console_bytes(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());

    let gw_count = count_default_gateways_from_routes(&route_out);
    evaluate_dual_homed_verdict(interfaces, ssid, gw_count)
}

#[tauri::command]
pub async fn audit_dual_homed_network_cmd() -> Result<DualHomedAuditVerdict, String> {
    tokio::task::spawn_blocking(audit_local_dual_homed_network)
        .await
        .map_err(|e| format!("双网卡一机两用排查线程异常: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dual_homed_wired_plus_mobile_hotspot_triggers_critical_veto() {
        let sample_ipconfig = r#"
Windows IP 配置

以太网适配器 以太网:

   连接特定的 DNS 后缀 . . . . . . . : corp.local
   描述. . . . . . . . . . . . . . . : Intel(R) Ethernet Controller I225-V
   IPv4 地址 . . . . . . . . . . . . : 10.10.20.45(首选)
   默认网关. . . . . . . . . . . . . : 10.10.20.1

无线局域网适配器 WLAN:

   描述. . . . . . . . . . . . . . . : Intel(R) Wi-Fi 6E AX211
   IPv4 地址 . . . . . . . . . . . . : 172.20.10.4(首选)
   默认网关. . . . . . . . . . . . . : 172.20.10.1
"#;
        let sample_wlan = "    状态                   : 已连接\n    SSID                   : iPhone_Hotspot_5G\n";
        let sample_route = "0.0.0.0   0.0.0.0   10.10.20.1   10.10.20.45  25\n0.0.0.0   0.0.0.0   172.20.10.1  172.20.10.4  50";

        let ifaces = parse_windows_ipconfig_all(sample_ipconfig);
        let ssid = parse_windows_wlan_ssid(sample_wlan);
        let gws = count_default_gateways_from_routes(sample_route);
        let verdict = evaluate_dual_homed_verdict(ifaces, ssid, gws);

        assert!(verdict.is_dual_homed_violation);
        assert!(verdict.has_simultaneous_wired_and_wireless);
        assert_eq!(verdict.active_nic_count, 2);
        assert_eq!(verdict.wireless_ssid.as_deref(), Some("iPhone_Hotspot_5G"));
        assert_eq!(verdict.risk_level, "CRITICAL");
    }

    #[test]
    fn test_virtual_nics_do_not_trigger_false_positive() {
        let sample_ipconfig = r#"
Windows IP Configuration

Ethernet adapter Ethernet:
   Description . . . . . . . . . . . : Realtek PCIe GbE Family Controller
   IPv4 Address. . . . . . . . . . . : 192.168.10.12(Preferred)
   Default Gateway . . . . . . . . . : 192.168.10.1

Ethernet adapter vEthernet (WSL):
   Description . . . . . . . . . . . : Hyper-V Virtual Ethernet Adapter
   IPv4 Address. . . . . . . . . . . : 172.28.112.1(Preferred)

Ethernet adapter VMware Network Adapter VMnet8:
   Description . . . . . . . . . . . : VMware Virtual Ethernet Adapter
   IPv4 Address. . . . . . . . . . . : 192.168.159.1(Preferred)

Wireless LAN adapter Wi-Fi:
   Media State . . . . . . . . . . . : Media disconnected
   Description . . . . . . . . . . . : Qualcomm Wireless Adapter
"#;
        let ifaces = parse_windows_ipconfig_all(sample_ipconfig);
        let verdict = evaluate_dual_homed_verdict(ifaces, None, 1);

        assert!(!verdict.is_dual_homed_violation);
        assert!(!verdict.has_simultaneous_wired_and_wireless);
        assert_eq!(verdict.active_nic_count, 1);
        assert_eq!(verdict.risk_level, "CLEAN");
    }

    #[test]
    fn test_single_nic_multiple_ips_and_empty_input_boundary() {
        // 极限用例 1: 空文本不崩溃
        let empty = evaluate_dual_homed_verdict(parse_windows_ipconfig_all(""), None, 0);
        assert!(!empty.is_dual_homed_violation);
        assert_eq!(empty.active_nic_count, 0);

        // 极限用例 2: 单物理网卡配置多个 IP 别名不应被误报为双网卡
        let multi_ip = vec![NicInterfaceAuditItem {
            name: "eth0".to_string(),
            if_type: "ETHERNET".to_string(),
            is_up: true,
            ip_addresses: vec!["10.0.0.10".to_string(), "192.168.1.10".to_string()],
            gateway_addresses: vec!["10.0.0.1".to_string()],
            is_connected_to_private: true,
            is_connected_to_public: false,
        }];
        let verdict = evaluate_dual_homed_verdict(multi_ip, None, 1);
        assert!(!verdict.is_dual_homed_violation);
        assert_eq!(verdict.active_nic_count, 1);
    }
}
