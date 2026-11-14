//! 非涉密网络与违规外联“历史痕迹”深度取证引擎
//! 对标行业标准：BMB22-2007 第 5.2.1 节（通信线路安全与网络互联限制）、GB/T 29360-2012
//!
//! 解决痛点：即使违规人员在检查前断开 Wi-Fi 或拔除手机 USB 共享热点，依然可穿透提取注册表、
//! WlanSvc XML 历史配置、拨号/VPN 配置簿与 USB CDC-RNDIS 驱动历史，还原过往非涉密外联事实。
//!
//! 算法复杂度：
//! - 时间复杂度：O(P + U + N)，其中 P 为 Wi-Fi 配置数，U 为 Enum\USB 设备实例数，N 为 NetworkList 档案数（耗时 <= 20ms）
//! - 空间复杂度：O(P + R)，线性存储提取出的历史配置与 RNDIS 证据条目

use crate::host_baseline::decode_console_bytes;
use chrono::{DateTime, Local, NaiveDate, Utc};
use regex::Regex;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WifiProfileHistoryItem {
    pub profile_name: String,
    pub ssid: String,
    pub auth_type: String,
    pub cipher: String,
    pub is_mobile_hotspot_feature: bool,
    pub last_modified_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoricNetworkProfileItem {
    pub profile_name: String,
    pub network_category: String, // "PUBLIC" | "PRIVATE" | "DOMAIN"
    pub last_connected_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecrecyNetworkHistoryReport {
    pub scanned_host: String,
    pub scan_time: String,
    pub total_wifi_profiles_found: usize,
    pub suspicious_mobile_hotspots: Vec<WifiProfileHistoryItem>,
    pub all_wifi_profiles: Vec<WifiProfileHistoryItem>,
    pub historic_rndis_devices: Vec<String>,
    pub historic_dialup_connections: Vec<String>,
    pub historic_network_profiles: Vec<HistoricNetworkProfileItem>,
    pub has_historic_violation: bool,
    pub summary_conclusion: String,
    pub degrade_notes: Vec<String>,
}

static RE_XML_NAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)<name>\s*([^<]{1,128})\s*</name>").unwrap());
static RE_XML_AUTH: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)<authentication>\s*([^<]{1,64})\s*</authentication>").unwrap());
static RE_XML_CIPHER: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)<encryption>\s*([^<]{1,64})\s*</encryption>").unwrap());

/// 判定热点名称是否具有智能手机便携热点或公共商业热点特征
pub fn is_mobile_or_public_hotspot_ssid(ssid: &str) -> bool {
    let lower = ssid.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    const PATTERNS: &[&str] = &[
        "iphone",
        "ipad",
        "android",
        "huawei",
        "honor",
        "xiaomi",
        "redmi",
        "mi ",
        "oppo",
        "vivo",
        "oneplus",
        "realme",
        "galaxy",
        "pixel",
        "hotspot",
        "mifi",
        "cmcc",
        "chinanet",
        "chinaunicom",
        "starbucks",
        "kfc",
        "guest",
        "public",
        "随身",
        "热点",
        "手机",
    ];
    PATTERNS.iter().any(|p| lower.contains(p)) || ssid.contains("的 iPhone") || ssid.contains("的手机")
}

/// 解析单个 WlanSvc XML 历史配置文件
pub fn parse_wlan_profile_xml(xml_text: &str, mtime: &str) -> Option<WifiProfileHistoryItem> {
    let trimmed = xml_text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut names = Vec::new();
    for cap in RE_XML_NAME.captures_iter(trimmed) {
        if let Some(m) = cap.get(1) {
            names.push(m.as_str().trim().to_string());
        }
    }
    let profile_name = names.first()?.clone();
    let ssid = names.get(1).cloned().unwrap_or_else(|| profile_name.clone());
    let auth_type = RE_XML_AUTH
        .captures(trimmed)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_ascii_uppercase())
        .unwrap_or_else(|| "UNKNOWN".to_string());
    let cipher = RE_XML_CIPHER
        .captures(trimmed)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_ascii_uppercase())
        .unwrap_or_else(|| "UNKNOWN".to_string());

    let is_mobile = is_mobile_or_public_hotspot_ssid(&ssid) || is_mobile_or_public_hotspot_ssid(&profile_name);
    Some(WifiProfileHistoryItem {
        profile_name,
        ssid,
        auth_type,
        cipher,
        is_mobile_hotspot_feature: is_mobile,
        last_modified_time: mtime.to_string(),
    })
}

/// 解析 Windows `NetworkList\Profiles` 的 16 字节 SYSTEMTIME 二进制结构 (`DateLastConnected`)
pub fn decode_windows_systemtime_16bytes(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 16 {
        return None;
    }
    let year = u16::from_le_bytes([bytes[0], bytes[1]]);
    let month = u16::from_le_bytes([bytes[2], bytes[3]]);
    // bytes[4..6] 为 wDayOfWeek
    let day = u16::from_le_bytes([bytes[6], bytes[7]]);
    let hour = u16::from_le_bytes([bytes[8], bytes[9]]);
    let minute = u16::from_le_bytes([bytes[10], bytes[11]]);
    let second = u16::from_le_bytes([bytes[12], bytes[13]]);

    if !(1980..=2100).contains(&year) || month == 0 || month > 12 || day == 0 || day > 31 {
        return None;
    }
    let naive_utc = NaiveDate::from_ymd_opt(year as i32, month as u32, day as u32)?
        .and_hms_opt(hour as u32, minute as u32, second as u32)?;
    let dt_utc = DateTime::<Utc>::from_naive_utc_and_offset(naive_utc, Utc);
    let dt_local: DateTime<Local> = dt_utc.into();
    Some(dt_local.format("%Y-%m-%d %H:%M:%S").to_string())
}

/// 解析 Windows 拨号/VPN 配置簿 `rasphone.pbk` 中的连接区块名称
pub fn parse_rasphone_pbk(content: &str) -> Vec<String> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with('[') && t.ends_with(']') && t.len() > 2 {
            let name = t[1..t.len() - 1].trim();
            if !name.is_empty() && !entries.iter().any(|x| x == name) {
                entries.push(name.to_string());
            }
        }
    }
    entries
}

/// 从 `netsh wlan show profiles` 文本输出中降级提取历史 Wi-Fi 名称
pub fn parse_netsh_wlan_profiles_list(output: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in output.lines() {
        let t = line.trim();
        let lower = t.to_ascii_lowercase();
        if (lower.starts_with("all user profile") || t.starts_with("所有用户配置文件")) && t.contains(':') {
            if let Some(val) = t.splitn(2, ':').nth(1) {
                let p = val.trim();
                if !p.is_empty() && !names.iter().any(|x| x == p) {
                    names.push(p.to_string());
                }
            }
        }
    }
    names
}

fn format_system_time_to_local(st: std::time::SystemTime) -> String {
    let dt: DateTime<Local> = st.into();
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// 综合评估历史外联取证报告（纯函数支持全路径单测）
pub fn evaluate_network_history_report(
    scanned_host: String,
    all_wifi_profiles: Vec<WifiProfileHistoryItem>,
    historic_rndis_devices: Vec<String>,
    historic_dialup_connections: Vec<String>,
    historic_network_profiles: Vec<HistoricNetworkProfileItem>,
    degrade_notes: Vec<String>,
) -> SecrecyNetworkHistoryReport {
    let suspicious_mobile_hotspots: Vec<WifiProfileHistoryItem> = all_wifi_profiles
        .iter()
        .filter(|w| w.is_mobile_hotspot_feature)
        .cloned()
        .collect();

    let has_public_history = historic_network_profiles
        .iter()
        .any(|p| p.network_category == "PUBLIC");

    let has_historic_violation = !all_wifi_profiles.is_empty()
        || !historic_rndis_devices.is_empty()
        || !historic_dialup_connections.is_empty()
        || has_public_history;

    let mut summary_parts = Vec::new();
    if !all_wifi_profiles.is_empty() {
        summary_parts.push(format!(
            "检出 {} 条历史 Wi-Fi 配置文件（其中含手机/公共热点特征 {} 条）",
            all_wifi_profiles.len(),
            suspicious_mobile_hotspots.len()
        ));
    }
    if !historic_rndis_devices.is_empty() {
        summary_parts.push(format!(
            "检出 {} 条手机 USB 共享网络 (CDC-RNDIS) 历史驱动痕",
            historic_rndis_devices.len()
        ));
    }
    if !historic_dialup_connections.is_empty() {
        summary_parts.push(format!(
            "检出 {} 条拨号/VPN 外部连接档案 (rasphone.pbk)",
            historic_dialup_connections.len()
        ));
    }
    if has_public_history {
        let pub_cnt = historic_network_profiles
            .iter()
            .filter(|p| p.network_category == "PUBLIC")
            .count();
        summary_parts.push(format!("检出 {} 条 Windows 公用外部网络历史接入记录", pub_cnt));
    }

    let summary_conclusion = if summary_parts.is_empty() {
        format!(
            "主机 {} 未发现历史无线热点配置文件、手机 USB 网络共享 (RNDIS) 或拨号外联痕迹。",
            scanned_host
        )
    } else {
        format!("发现历史非涉密外联征象：{}。", summary_parts.join("；"))
    };

    SecrecyNetworkHistoryReport {
        scanned_host,
        scan_time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        total_wifi_profiles_found: all_wifi_profiles.len(),
        suspicious_mobile_hotspots,
        all_wifi_profiles,
        historic_rndis_devices,
        historic_dialup_connections,
        historic_network_profiles,
        has_historic_violation,
        summary_conclusion,
        degrade_notes,
    }
}

#[cfg(windows)]
pub fn audit_local_network_history() -> SecrecyNetworkHistoryReport {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "LOCAL-WINDOWS-HOST".to_string());
    let mut degrade_notes = Vec::new();
    let mut wifi_profiles: Vec<WifiProfileHistoryItem> = Vec::new();
    let mut seen_wifi: HashSet<String> = HashSet::new();

    // 1. 直接读取 WlanSvc XML 历史档案目录
    let wlan_dir = std::path::Path::new(r"C:\ProgramData\Microsoft\WlanSvc\Profiles\Interfaces");
    if wlan_dir.exists() {
        if let Ok(iface_dirs) = std::fs::read_dir(wlan_dir) {
            for iface in iface_dirs.flatten() {
                if iface.path().is_dir() {
                    if let Ok(files) = std::fs::read_dir(iface.path()) {
                        for f in files.flatten() {
                            let p = f.path();
                            if p.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("xml")).unwrap_or(false) {
                                if let Ok(bytes) = std::fs::read(&p) {
                                    let xml_txt = decode_console_bytes(&bytes);
                                    let mtime = p
                                        .metadata()
                                        .and_then(|m| m.modified())
                                        .map(format_system_time_to_local)
                                        .unwrap_or_else(|_| "未知".to_string());
                                    if let Some(item) = parse_wlan_profile_xml(&xml_txt, &mtime) {
                                        if seen_wifi.insert(item.profile_name.clone()) {
                                            wifi_profiles.push(item);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 若非管理员导致 WlanSvc XML 读取不完整，则通过 netsh wlan show profiles 补充
    if let Ok(out) = Command::new("netsh")
        .args(["wlan", "show", "profiles"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        if out.status.success() {
            let txt = decode_console_bytes(&out.stdout);
            for prof in parse_netsh_wlan_profiles_list(&txt) {
                if seen_wifi.insert(prof.clone()) {
                    let is_mobile = is_mobile_or_public_hotspot_ssid(&prof);
                    wifi_profiles.push(WifiProfileHistoryItem {
                        profile_name: prof.clone(),
                        ssid: prof,
                        auth_type: "NETSH_DETECTED".to_string(),
                        cipher: "N/A".to_string(),
                        is_mobile_hotspot_feature: is_mobile,
                        last_modified_time: "历史存在 (Netsh)".to_string(),
                    });
                }
            }
        }
    } else {
        degrade_notes.push("无线服务未启用或 netsh 不可用，跳过 WLAN 配置探测".to_string());
    }

    // 2. 扫描注册表 Enum\USB 寻找 CDC-RNDIS 手机 USB 网络共享历史驱动痕迹
    let mut rndis_devices = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(usb_root) = hklm.open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Enum\USB", KEY_READ) {
        for vidpid in usb_root.enum_keys().flatten() {
            if let Ok(vp_key) = usb_root.open_subkey_with_flags(&vidpid, KEY_READ) {
                for inst in vp_key.enum_keys().flatten() {
                    if let Ok(inst_key) = vp_key.open_subkey_with_flags(&inst, KEY_READ) {
                        let friendly: String = inst_key
                            .get_value("FriendlyName")
                            .or_else(|_| inst_key.get_value("DeviceDesc"))
                            .unwrap_or_default();
                        let compat_ids: Vec<String> = inst_key.get_value("CompatibleIDs").unwrap_or_default();
                        let hw_ids: Vec<String> = inst_key.get_value("HardwareID").unwrap_or_default();
                        let combined = format!(
                            "{} {} {}",
                            friendly.to_ascii_lowercase(),
                            compat_ids.join(" ").to_ascii_lowercase(),
                            hw_ids.join(" ").to_ascii_lowercase()
                        );
                        if combined.contains("rndis")
                            || combined.contains("class_02&subclass_06")
                            || combined.contains("class_e0&subclass_01&prot_03")
                            || combined.contains("apple mobile device ethernet")
                        {
                            rndis_devices.push(format!("USB\\{}\\{} ({})", vidpid, inst, friendly));
                        }
                    }
                }
            }
        }
    } else {
        degrade_notes.push("无法打开 HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB 检查 RNDIS 驱动".to_string());
    }

    // 3. 扫描 NetworkList\Profiles 提取 Windows 曾接入的历史网络清单
    let mut net_profiles = Vec::new();
    if let Ok(nl_key) = hklm.open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
        KEY_READ,
    ) {
        for guid in nl_key.enum_keys().flatten() {
            if let Ok(p_key) = nl_key.open_subkey_with_flags(&guid, KEY_READ) {
                let name: String = p_key.get_value("ProfileName").unwrap_or_else(|_| guid.clone());
                let cat_val: u32 = p_key.get_value("Category").unwrap_or(0);
                let cat_label = match cat_val {
                    1 => "PRIVATE",
                    2 => "DOMAIN",
                    _ => "PUBLIC",
                };
                let last_conn = p_key
                    .get_raw_value("DateLastConnected")
                    .ok()
                    .and_then(|rv| decode_windows_systemtime_16bytes(&rv.bytes))
                    .unwrap_or_else(|| "未知".to_string());
                net_profiles.push(HistoricNetworkProfileItem {
                    profile_name: name,
                    network_category: cat_label.to_string(),
                    last_connected_time: last_conn,
                });
            }
        }
    }

    // 4. 扫描历史拨号与 VPN 档案簿 rasphone.pbk
    let mut dialup_entries = Vec::new();
    let mut pbk_paths = vec![std::path::PathBuf::from(
        r"C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk",
    )];
    if let Ok(appdata) = std::env::var("APPDATA") {
        pbk_paths.push(
            std::path::Path::new(&appdata)
                .join("Microsoft")
                .join("Network")
                .join("Connections")
                .join("Pbk")
                .join("rasphone.pbk"),
        );
    }
    for pbk in pbk_paths {
        if let Ok(bytes) = std::fs::read(&pbk) {
            let txt = decode_console_bytes(&bytes);
            for conn in parse_rasphone_pbk(&txt) {
                if !dialup_entries.iter().any(|x| x == &conn) {
                    dialup_entries.push(conn);
                }
            }
        }
    }

    evaluate_network_history_report(
        hostname,
        wifi_profiles,
        rndis_devices,
        dialup_entries,
        net_profiles,
        degrade_notes,
    )
}

#[cfg(not(windows))]
pub fn audit_local_network_history() -> SecrecyNetworkHistoryReport {
    use std::process::Command;
    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "LOCAL-LINUX-HOST".to_string())
        .trim()
        .to_string();
    let mut degrade_notes = Vec::new();
    let mut wifi_profiles = Vec::new();
    let mut dialup_entries = Vec::new();

    if let Ok(dir) = std::fs::read_dir("/etc/NetworkManager/system-connections") {
        for entry in dir.flatten() {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                let fname = entry.file_name().to_string_lossy().to_string();
                if content.contains("type=wifi") || content.contains("[wifi]") {
                    let ssid = content
                        .lines()
                        .find(|l| l.trim_start().starts_with("ssid="))
                        .map(|l| l.trim_start().trim_start_matches("ssid=").trim().to_string())
                        .unwrap_or_else(|| fname.clone());
                    let is_mobile = is_mobile_or_public_hotspot_ssid(&ssid);
                    wifi_profiles.push(WifiProfileHistoryItem {
                        profile_name: fname,
                        ssid,
                        auth_type: "NM_WIFI".to_string(),
                        cipher: "WPA/RSN".to_string(),
                        is_mobile_hotspot_feature: is_mobile,
                        last_modified_time: "NetworkManager 持久化档案".to_string(),
                    });
                } else if content.contains("type=vpn") || content.contains("type=pppoe") {
                    dialup_entries.push(fname);
                }
            }
        }
    } else if let Ok(out) = Command::new("nmcli").args(["-t", "-f", "NAME,TYPE", "connection", "show"]).output() {
        let txt = decode_console_bytes(&out.stdout);
        for line in txt.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                if parts[1].contains("wireless") {
                    let ssid = parts[0].trim().to_string();
                    wifi_profiles.push(WifiProfileHistoryItem {
                        profile_name: ssid.clone(),
                        ssid: ssid.clone(),
                        auth_type: "NMCLI".to_string(),
                        cipher: "N/A".to_string(),
                        is_mobile_hotspot_feature: is_mobile_or_public_hotspot_ssid(&ssid),
                        last_modified_time: "nmcli 历史记录".to_string(),
                    });
                } else if parts[1].contains("vpn") || parts[1].contains("pppoe") {
                    dialup_entries.push(parts[0].trim().to_string());
                }
            }
        }
    } else {
        degrade_notes.push("无法读取 NetworkManager 系统档案目录".to_string());
    }

    evaluate_network_history_report(hostname, wifi_profiles, vec![], dialup_entries, vec![], degrade_notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wlan_profile_xml_and_mobile_hotspot_detection() {
        let xml = r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>ZhangSan的 iPhone 15</name>
    <SSIDConfig>
        <SSID>
            <name>ZhangSan的 iPhone 15</name>
        </SSID>
    </SSIDConfig>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>"#;

        let item = parse_wlan_profile_xml(xml, "2026-11-10 14:30:00").expect("应成功解析 Wlan XML");
        assert_eq!(item.ssid, "ZhangSan的 iPhone 15");
        assert_eq!(item.auth_type, "WPA2PSK");
        assert_eq!(item.cipher, "AES");
        assert!(item.is_mobile_hotspot_feature);

        // 极限边界：空文本和畸形 XML 不 panic
        assert!(parse_wlan_profile_xml("", "").is_none());
        assert!(parse_wlan_profile_xml("<Broken><NoName>", "").is_none());
    }

    #[test]
    fn test_decode_windows_systemtime_16bytes_and_rasphone_pbk() {
        // 2026-11-14 08:15:30 UTC (wYear=2026, wMonth=11, wDayOfWeek=6, wDay=14, wHour=8, wMinute=15, wSecond=30, wMs=0)
        let mut raw = [0u8; 16];
        raw[0..2].copy_from_slice(&2026u16.to_le_bytes());
        raw[2..4].copy_from_slice(&11u16.to_le_bytes());
        raw[6..8].copy_from_slice(&14u16.to_le_bytes());
        raw[8..10].copy_from_slice(&8u16.to_le_bytes());
        raw[10..12].copy_from_slice(&15u16.to_le_bytes());
        raw[12..14].copy_from_slice(&30u16.to_le_bytes());

        let decoded = decode_windows_systemtime_16bytes(&raw).expect("应能解析合法 16 字节 SYSTEMTIME");
        assert!(decoded.starts_with("2026-11-14"));
        assert!(decode_windows_systemtime_16bytes(&[0u8; 4]).is_none());

        let pbk = "[单位外部VPN拨号]\nType=2\nMedia=rastapi\n[Telecom_PPPoE]\nDevice=WAN Miniport";
        let conns = parse_rasphone_pbk(pbk);
        assert_eq!(conns, vec!["单位外部VPN拨号", "Telecom_PPPoE"]);
    }

    #[test]
    fn test_evaluate_network_history_report_boundaries() {
        // 极限用例 1: 零外联历史记录时不应误触发违规
        let clean = evaluate_network_history_report(
            "HOST-A".to_string(),
            vec![],
            vec![],
            vec![],
            vec![HistoricNetworkProfileItem {
                profile_name: "涉密专网".to_string(),
                network_category: "DOMAIN".to_string(),
                last_connected_time: "2026-11-14 09:00:00".to_string(),
            }],
            vec![],
        );
        assert!(!clean.has_historic_violation);

        // 极限用例 2: 检出历史手机 RNDIS 共享设备立即判定违规
        let rndis = evaluate_network_history_report(
            "HOST-B".to_string(),
            vec![],
            vec!["USB\\VID_18D1&PID_4EE3\\SERIAL (Remote NDIS based Internet Sharing Device)".to_string()],
            vec![],
            vec![],
            vec![],
        );
        assert!(rndis.has_historic_violation);
        assert!(rndis.summary_conclusion.contains("CDC-RNDIS"));
    }
}
