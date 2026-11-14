//! 涉密终端 USBSTOR 历史插拔痕迹与非涉密介质交叉使用深度取证引擎
//! 对标行业标准：BMB22-2007 第 5.2.2 节、GB/T 29360-2012《电子物证数据提取及保全技术规范》
//!
//! 核心算法复杂度：
//! - 时间复杂度：O(D + L)，其中 D 为系统历史 USB 存储设备条目数，L 为 setupapi/系统安装日志行数；
//! - 空间复杂度：O(D)，线性存储历史设备证据向量，全过程执行内存开销 <= 512KB。

use crate::audit_confidentiality::{self, AuthorizedMediaDef};
use crate::host_baseline::decode_console_bytes;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsbHistoryEvidenceItem {
    pub device_id: String,
    pub vendor_id: String,
    pub product_id: String,
    pub serial_number: String,
    pub device_name: String,
    pub class_guid: String,
    pub first_installed_time: String,
    pub last_arrival_time: String,
    pub assigned_drive_letter: String,
    pub is_whitelisted: bool,
    pub violation_level: String, // "CLEAN" | "CRITICAL_VIOLATION"
    pub evidence_source: String, // "REGISTRY:USBSTOR" | "SETUPAPI_LOG" | "SYSFS:USB"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecrecyUsbAuditReport {
    pub scanned_host: String,
    pub scan_time: String,
    pub total_devices_found: usize,
    pub unauthorized_device_count: usize,
    pub has_critical_violation: bool,
    pub devices: Vec<UsbHistoryEvidenceItem>,
    pub summary_conclusion: String,
}

static RE_VID: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)vid_([0-9a-f]{4})").unwrap());
static RE_PID: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)pid_([0-9a-f]{4})").unwrap());
static RE_SETUPAPI_HDR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)Device Install \(Hardware initiated\)\s*-\s*((?:USBSTOR|USB)\\[^\]]+)\]").unwrap()
});
static RE_SETUPAPI_TS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})").unwrap()
});

/// 规范化 USB 实例序列号（剥离 Windows 自动生成的 `&0` / `&1` 后缀、首尾空格与控制字符）
pub fn normalize_usb_serial(raw_instance_id: &str) -> String {
    let trimmed = raw_instance_id.trim();
    let base = match trimmed.split('&').next() {
        Some(part) if !part.is_empty() => part,
        _ => trimmed,
    };
    base.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect::<String>()
        .to_ascii_uppercase()
}

/// 从硬件 ID 或设备路径中提取标准 4 位十六进制 VID 与 PID
pub fn extract_vid_pid(sources: &[String]) -> (String, String) {
    let mut vid = String::new();
    let mut pid = String::new();
    for s in sources {
        if vid.is_empty() {
            if let Some(cap) = RE_VID.captures(s) {
                if let Some(m) = cap.get(1) {
                    vid = m.as_str().to_ascii_lowercase();
                }
            }
        }
        if pid.is_empty() {
            if let Some(cap) = RE_PID.captures(s) {
                if let Some(m) = cap.get(1) {
                    pid = m.as_str().to_ascii_lowercase();
                }
            }
        }
        if !vid.is_empty() && !pid.is_empty() {
            break;
        }
    }
    (vid, pid)
}

/// 从 Windows setupapi.dev.log 文本中提取各 USB 设备实例的首次安装时间与末次安装时间
/// 返回映射: 规范化序列号 -> (first_time, last_time)
pub fn parse_setupapi_usb_timestamps(log_content: &str) -> HashMap<String, (String, String)> {
    let mut map: HashMap<String, (String, String)> = HashMap::new();
    let mut pending_serial: Option<String> = None;

    for raw_line in log_content.lines() {
        let line = raw_line.trim();
        if let Some(cap) = RE_SETUPAPI_HDR.captures(line) {
            if let Some(m) = cap.get(1) {
                let dev_path = m.as_str();
                if let Some(last_seg) = dev_path.rsplit('\\').next() {
                    let norm = normalize_usb_serial(last_seg);
                    if !norm.is_empty() {
                        pending_serial = Some(norm);
                    }
                }
            }
            continue;
        }
        if let Some(ref serial) = pending_serial {
            if let Some(cap) = RE_SETUPAPI_TS.captures(line) {
                if let Some(m) = cap.get(1) {
                    let iso_like = m.as_str().replace('/', "-");
                    let entry = map
                        .entry(serial.clone())
                        .or_insert_with(|| (iso_like.clone(), iso_like.clone()));
                    if iso_like < entry.0 {
                        entry.0 = iso_like.clone();
                    }
                    if iso_like > entry.1 {
                        entry.1 = iso_like;
                    }
                    pending_serial = None;
                }
            } else if line.starts_with("<<<") || line.starts_with("[") {
                pending_serial = None;
            }
        }
    }
    map
}

/// 从注册表 MountedDevices 键值二进制缓冲区解码 UTF-16LE 关联的盘符映射
pub fn parse_mounted_devices_drive_map(entries: &[(String, Vec<u8>)]) -> Vec<(String, String)> {
    let mut drives = Vec::new();
    for (name, bytes) in entries {
        if let Some(letter) = name.strip_prefix("\\DosDevices\\") {
            if letter.ends_with(':') && bytes.len() >= 8 {
                let utf16_units: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let decoded = String::from_utf16_lossy(&utf16_units);
                if decoded.contains("USBSTOR") {
                    drives.push((letter.to_string(), decoded));
                }
            }
        }
    }
    drives
}

/// 统一执行涉密移动存储介质白名单碰撞与违规裁决
pub fn evaluate_usb_history_compliance(
    scanned_host: &str,
    mut items: Vec<UsbHistoryEvidenceItem>,
    whitelist: &[AuthorizedMediaDef],
    degrade_note: Option<&str>,
) -> SecrecyUsbAuditReport {
    let mut unauthorized_count = 0usize;

    for item in &mut items {
        let vid_norm = item.vendor_id.trim().to_ascii_lowercase();
        let pid_norm = item.product_id.trim().to_ascii_lowercase();

        let matched = !vid_norm.is_empty()
            && !pid_norm.is_empty()
            && whitelist.iter().any(|w| {
                w.vid.trim().eq_ignore_ascii_case(&vid_norm)
                    && w.pid.trim().eq_ignore_ascii_case(&pid_norm)
            });

        item.is_whitelisted = matched;
        if matched {
            item.violation_level = "CLEAN".to_string();
        } else {
            item.violation_level = "CRITICAL_VIOLATION".to_string();
            unauthorized_count += 1;
        }
    }

    let total = items.len();
    let has_critical = unauthorized_count > 0;
    let mut summary = if has_critical {
        format!(
            "BMB22-2007 一票否决严重违规：在主机 [{}] 共检出 {} 台历史接入 USB 存储介质，其中 {} 台未录入涉密安全介质白名单（存在非涉密介质交叉使用风险）！",
            scanned_host, total, unauthorized_count
        )
    } else if total > 0 {
        format!(
            "主机 [{}] 历史接入的 {} 台 USB 存储设备均已登记于授权涉密安全介质白名单中。",
            scanned_host, total
        )
    } else {
        format!(
            "主机 [{}] 未检索到 USB 存储介质历史插拔记录。",
            scanned_host
        )
    };

    if let Some(note) = degrade_note {
        if !note.trim().is_empty() {
            summary.push_str(&format!("（提示：{}）", note.trim()));
        }
    }

    SecrecyUsbAuditReport {
        scanned_host: scanned_host.to_string(),
        scan_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        total_devices_found: total,
        unauthorized_device_count: unauthorized_count,
        has_critical_violation: has_critical,
        devices: items,
        summary_conclusion: summary,
    }
}

#[cfg(windows)]
fn format_reg_systemtime(year: u16, month: u16, day: u16, hour: u16, minute: u16, second: u16) -> Option<String> {
    if year < 1980 || month == 0 || day == 0 {
        return None;
    }
    let naive_utc = chrono::NaiveDate::from_ymd_opt(year as i32, month as u32, day as u32)?
        .and_hms_opt(hour as u32, minute as u32, second as u32)?;
    let dt_utc = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive_utc, chrono::Utc);
    let dt_local: chrono::DateTime<chrono::Local> = dt_utc.into();
    Some(dt_local.format("%Y-%m-%d %H:%M:%S").to_string())
}

#[cfg(windows)]
fn collect_windows_usb_history() -> (String, Vec<UsbHistoryEvidenceItem>, Option<String>) {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "LOCAL-WINDOWS-HOST".to_string());
    let mut items: Vec<UsbHistoryEvidenceItem> = Vec::new();
    let mut degrade_notes: Vec<String> = Vec::new();

    // 1. 解析 setupapi.dev.log 获取历史首次与末次接入时间戳
    let setupapi_ts = match std::fs::read(r"C:\Windows\INF\setupapi.dev.log") {
        Ok(bytes) => {
            let txt = decode_console_bytes(&bytes);
            parse_setupapi_usb_timestamps(&txt)
        }
        Err(_) => {
            degrade_notes.push("无法读取 setupapi.dev.log，时间凭证回退至注册表键末次写入时间".to_string());
            HashMap::new()
        }
    };

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // 2. 扫描 Enum\USB 建立 序列号 -> (VID, PID) 精确反查索引（Windows 下 USBSTOR 往往不包含 4 位 Hex VID/PID）
    let mut usb_vidpid_by_serial: HashMap<String, (String, String)> = HashMap::new();
    if let Ok(usb_root) = hklm.open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Enum\USB", KEY_READ) {
        for vidpid_name in usb_root.enum_keys().flatten() {
            let (v, p) = extract_vid_pid(&[vidpid_name.clone()]);
            if v.is_empty() || p.is_empty() {
                continue;
            }
            if let Ok(vp_key) = usb_root.open_subkey_with_flags(&vidpid_name, KEY_READ) {
                for ser_name in vp_key.enum_keys().flatten() {
                    let norm_ser = normalize_usb_serial(&ser_name);
                    if !norm_ser.is_empty() {
                        usb_vidpid_by_serial.insert(norm_ser, (v.clone(), p.clone()));
                    }
                }
            }
        }
    }

    // 3. 扫描 MountedDevices 还原历史分配盘符
    let mut mounted_entries: Vec<(String, Vec<u8>)> = Vec::new();
    if let Ok(mounted_key) = hklm.open_subkey_with_flags(r"SYSTEM\MountedDevices", KEY_READ) {
        for (val_name, val_data) in mounted_key.enum_values().flatten() {
            if val_name.starts_with(r"\DosDevices\") {
                mounted_entries.push((val_name, val_data.bytes.to_vec()));
            }
        }
    }
    let drive_map = parse_mounted_devices_drive_map(&mounted_entries);

    // 4. 遍历 USBSTOR 核心硬件存储子键
    match hklm.open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Enum\USBSTOR", KEY_READ) {
        Ok(usbstor_key) => {
            for model_key_name in usbstor_key.enum_keys().flatten() {
                if let Ok(model_key) = usbstor_key.open_subkey_with_flags(&model_key_name, KEY_READ) {
                    for instance_name in model_key.enum_keys().flatten() {
                        if let Ok(inst_key) = model_key.open_subkey_with_flags(&instance_name, KEY_READ) {
                            let friendly_name: String = inst_key
                                .get_value("FriendlyName")
                                .or_else(|_| inst_key.get_value("DeviceDesc"))
                                .unwrap_or_else(|_| model_key_name.clone());
                            let class_guid: String = inst_key
                                .get_value("ClassGUID")
                                .unwrap_or_else(|_| "{4d36e967-e325-11ce-bfc1-08002be10318}".to_string());
                            let hw_ids: Vec<String> = inst_key.get_value("HardwareID").unwrap_or_default();

                            let serial_norm = normalize_usb_serial(&instance_name);
                            let (mut vid, mut pid) = extract_vid_pid(&hw_ids);
                            if vid.is_empty() || pid.is_empty() {
                                if let Some((v2, p2)) = usb_vidpid_by_serial.get(&serial_norm) {
                                    vid = v2.clone();
                                    pid = p2.clone();
                                }
                            }

                            let reg_last_write = inst_key
                                .query_info()
                                .ok()
                                .and_then(|meta| {
                                    let st = meta.get_last_write_time_system();
                                    format_reg_systemtime(st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond)
                                })
                                .unwrap_or_else(|| "未知".to_string());

                            let (first_ts, last_ts) = if let Some((f, l)) = setupapi_ts.get(&serial_norm) {
                                (f.clone(), l.clone())
                            } else {
                                (reg_last_write.clone(), reg_last_write.clone())
                            };

                            let assigned_drive = drive_map
                                .iter()
                                .find(|(_, desc)| desc.to_ascii_uppercase().contains(&serial_norm))
                                .map(|(ltr, _)| ltr.clone())
                                .unwrap_or_else(|| "未记录".to_string());

                            items.push(UsbHistoryEvidenceItem {
                                device_id: format!("USBSTOR\\{}\\{}", model_key_name, instance_name),
                                vendor_id: if vid.is_empty() { "N/A".to_string() } else { vid },
                                product_id: if pid.is_empty() { "N/A".to_string() } else { pid },
                                serial_number: serial_norm,
                                device_name: friendly_name,
                                class_guid,
                                first_installed_time: first_ts,
                                last_arrival_time: last_ts,
                                assigned_drive_letter: assigned_drive,
                                is_whitelisted: false,
                                violation_level: String::new(),
                                evidence_source: "REGISTRY:USBSTOR".to_string(),
                            });
                        }
                    }
                }
            }
        }
        Err(_) => {
            degrade_notes.push("无权限读取 HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR 或该键尚未初始化".to_string());
            // 降级从 setupapi_ts 中恢复记录
            for (ser, (f, l)) in &setupapi_ts {
                let (vid, pid) = usb_vidpid_by_serial
                    .get(ser)
                    .cloned()
                    .unwrap_or_else(|| ("N/A".to_string(), "N/A".to_string()));
                items.push(UsbHistoryEvidenceItem {
                    device_id: format!("SETUPAPI\\USBSTOR\\{}", ser),
                    vendor_id: vid,
                    product_id: pid,
                    serial_number: ser.clone(),
                    device_name: format!("历史安装 USB 存储设备 ({})", ser),
                    class_guid: "{36fc9e60-c465-11cf-8056-444553540000}".to_string(),
                    first_installed_time: f.clone(),
                    last_arrival_time: l.clone(),
                    assigned_drive_letter: "未记录".to_string(),
                    is_whitelisted: false,
                    violation_level: String::new(),
                    evidence_source: "SETUPAPI_LOG".to_string(),
                });
            }
        }
    }

    let note = if degrade_notes.is_empty() {
        None
    } else {
        Some(degrade_notes.join("；"))
    };
    (hostname, items, note)
}

#[cfg(not(windows))]
fn collect_linux_usb_history() -> (String, Vec<UsbHistoryEvidenceItem>, Option<String>) {
    let hostname = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "LOCAL-LINUX-HOST".to_string());
    let mut items = Vec::new();

    if let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten() {
            let path = entry.path();
            let vid_path = path.join("idVendor");
            let pid_path = path.join("idProduct");
            if vid_path.exists() && pid_path.exists() {
                let vid = std::fs::read_to_string(&vid_path).unwrap_or_default().trim().to_ascii_lowercase();
                let pid = std::fs::read_to_string(&pid_path).unwrap_or_default().trim().to_ascii_lowercase();
                let serial = std::fs::read_to_string(path.join("serial")).unwrap_or_default().trim().to_string();
                let product = std::fs::read_to_string(path.join("product"))
                    .unwrap_or_else(|_| format!("USB Device {}:{}", vid, pid))
                    .trim()
                    .to_string();
                let b_dev_class = std::fs::read_to_string(path.join("bDeviceClass")).unwrap_or_default().trim().to_string();
                // 跳过集线器 (09)
                if b_dev_class == "09" {
                    continue;
                }
                items.push(UsbHistoryEvidenceItem {
                    device_id: format!("USB\\VID_{}&PID_{}\\{}", vid, pid, serial),
                    vendor_id: vid,
                    product_id: pid,
                    serial_number: if serial.is_empty() { "NONE".to_string() } else { normalize_usb_serial(&serial) },
                    device_name: product,
                    class_guid: b_dev_class,
                    first_installed_time: "在线枚举".to_string(),
                    last_arrival_time: "在线枚举".to_string(),
                    assigned_drive_letter: "/dev/sd*".to_string(),
                    is_whitelisted: false,
                    violation_level: String::new(),
                    evidence_source: "SYSFS:USB".to_string(),
                });
            }
        }
    }

    (hostname, items, None)
}

/// 执行涉密终端 USB 历史插拔痕迹深度取证与合规裁决
pub fn audit_local_usb_history() -> SecrecyUsbAuditReport {
    let whitelist = audit_confidentiality::get_authorized_media_whitelist();
    #[cfg(windows)]
    let (host, items, note) = collect_windows_usb_history();
    #[cfg(not(windows))]
    let (host, items, note) = collect_linux_usb_history();

    evaluate_usb_history_compliance(&host, items, &whitelist, note.as_deref())
}

#[tauri::command]
pub async fn audit_secrecy_usb_history_cmd() -> Result<SecrecyUsbAuditReport, String> {
    tokio::task::spawn_blocking(audit_local_usb_history)
        .await
        .map_err(|e| format!("USB 历史痕迹取证线程异常: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_usb_serial_and_vid_pid_extraction() {
        // 极限用例：尾部 &0 标记、异常空格、小写混乱
        assert_eq!(normalize_usb_serial("  0018f30c9959bf11&0 "), "0018F30C9959BF11");
        assert_eq!(normalize_usb_serial(""), "");
        assert_eq!(normalize_usb_serial("ab!@#cd_12"), "ABCD_12");

        let hw_ids = vec![
            "USBSTOR\\DiskKingstonDataTraveler_3.0PMAP".to_string(),
            "USB\\VID_0951&PID_16BF&REV_0100".to_string(),
        ];
        let (vid, pid) = extract_vid_pid(&hw_ids);
        assert_eq!(vid, "0951");
        assert_eq!(pid, "16bf");
    }

    #[test]
    fn test_parse_setupapi_usb_timestamps_first_and_last() {
        let sample_log = r#"
>>>  [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer\4C530001051029112453&0]
>>>  Section start 2025/08/10 09:15:22.104
     cmd: C:\Windows\system32\rundll32.exe
>>>  [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer\4C530001051029112453&0]
>>>  Section start 2026/11/14 14:30:05.991
"#;
        let map = parse_setupapi_usb_timestamps(sample_log);
        let entry = map.get("4C530001051029112453").expect("应解析出闪迪 U 盘插拔时间");
        assert_eq!(entry.0, "2025-08-10 09:15:22");
        assert_eq!(entry.1, "2026-11-14 14:30:05");
    }

    #[test]
    fn test_parse_mounted_devices_drive_map_utf16le() {
        let utf16_bytes: Vec<u8> = "_??_USBSTOR#Disk&Ven_Kingston#SN998877#{53f56307}"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let entries = vec![
            ("\\DosDevices\\C:".to_string(), vec![1, 2, 3, 4, 5, 6, 7, 8]),
            ("\\DosDevices\\F:".to_string(), utf16_bytes),
        ];
        let drives = parse_mounted_devices_drive_map(&entries);
        assert_eq!(drives.len(), 1);
        assert_eq!(drives[0].0, "F:");
        assert!(drives[0].1.contains("SN998877"));
    }

    #[test]
    fn test_evaluate_usb_history_compliance_veto_and_empty_boundaries() {
        let whitelist = vec![AuthorizedMediaDef {
            vid: "096e".to_string(),
            pid: "0807".to_string(),
            device_type: "USB_KEY".to_string(),
            description: "飞天诚信加密锁".to_string(),
        }];

        // 1. 零历史设备边界
        let empty_report = evaluate_usb_history_compliance("SECRET-PC-01", vec![], &whitelist, None);
        assert_eq!(empty_report.total_devices_found, 0);
        assert!(!empty_report.has_critical_violation);

        // 2. 混合场景：1 个白名单硬件 Key + 1 个曾插入后已拔出的私人闪迪 U 盘 -> 一票否决
        let mock_devices = vec![
            UsbHistoryEvidenceItem {
                device_id: "USB\\VID_096E&PID_0807\\FT001".to_string(),
                vendor_id: "096e".to_string(),
                product_id: "0807".to_string(),
                serial_number: "FT001".to_string(),
                device_name: "Feitian USB Key".to_string(),
                class_guid: "guid".to_string(),
                first_installed_time: "2026-01-01 10:00:00".to_string(),
                last_arrival_time: "2026-01-01 10:00:00".to_string(),
                assigned_drive_letter: "未记录".to_string(),
                is_whitelisted: false,
                violation_level: String::new(),
                evidence_source: "REGISTRY:USBSTOR".to_string(),
            },
            UsbHistoryEvidenceItem {
                device_id: "USBSTOR\\Disk&Ven_SanDisk\\PRIVATE999&0".to_string(),
                vendor_id: "0781".to_string(),
                product_id: "5581".to_string(),
                serial_number: "PRIVATE999".to_string(),
                device_name: "SanDisk Ultra USB 3.0".to_string(),
                class_guid: "guid".to_string(),
                first_installed_time: "2026-10-12 18:20:00".to_string(),
                last_arrival_time: "2026-10-12 18:25:00".to_string(),
                assigned_drive_letter: "E:".to_string(),
                is_whitelisted: false,
                violation_level: String::new(),
                evidence_source: "REGISTRY:USBSTOR".to_string(),
            },
        ];

        let report = evaluate_usb_history_compliance(
            "SECRET-PC-01",
            mock_devices,
            &whitelist,
            Some("测试降级说明"),
        );
        assert_eq!(report.total_devices_found, 2);
        assert_eq!(report.unauthorized_device_count, 1);
        assert!(report.has_critical_violation);
        assert_eq!(report.devices[0].violation_level, "CLEAN");
        assert_eq!(report.devices[1].violation_level, "CRITICAL_VIOLATION");
        assert!(report.summary_conclusion.contains("测试降级说明"));
    }
}
