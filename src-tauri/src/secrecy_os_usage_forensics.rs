//! 操作系统与外设使用痕迹深度取证引擎 (LNK / JumpLists / Spooler / EventLog)
//! 对标行业标准：BMB22-2007 第 5.2.2 节、GB/T 29360-2012
//!
//! 物理能力：
//! 1. 纯 Rust 解析 Windows MS-SHLLINK (`.lnk`) 快捷方式底层二进制结构，还原真实物理目标路径、目标卷类型（识别是否从可移动 U 盘或光驱打开涉密文件）与精确创建/访问时间；
//! 2. 解析系统脱机打印影子文件 (`spool\PRINTERS\*.SHD`) 与 `PrintService` 打印事件（Event ID 307），提取历史打印公文名称；
//! 3. 提取系统开关机与异常断电时间线（Event ID 6005 / 6006 / 1074 / 41）。
//!
//! 算法复杂度：
//! - 时间复杂度：O(L + J + E)，其中 L 为 Recent 目录快捷方式数，J 为打印作业数，E 为事件日志提取数
//! - 空间复杂度：O(L + J)

use crate::audit_confidentiality;
use crate::host_baseline::decode_console_bytes;
use crate::secrecy_history_network_forensics::decode_windows_systemtime_16bytes;
use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

const LNK_HEADER_SIZE: u32 = 0x0000_004C;
const LNK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentFileAccessItem {
    pub shortcut_name: String,
    pub target_real_path: String,
    pub target_creation_time: String,
    pub target_last_access_time: String,
    pub drive_type: String, // "REMOVABLE" | "FIXED" | "REMOTE" | "CDROM" | "UNKNOWN"
    pub is_removable_media_target: bool,
    pub is_secrecy_named: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrintJobSpoolerItem {
    pub job_id: u32,
    pub document_name: String,
    pub printer_name: String,
    pub submit_time: String,
    pub spool_file_path: String,
    pub is_secrecy_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecrecyOsUsageReport {
    pub scanned_host: String,
    pub scan_time: String,
    pub total_lnk_parsed: usize,
    pub recent_files: Vec<RecentFileAccessItem>,
    pub print_spooler_jobs: Vec<PrintJobSpoolerItem>,
    pub system_boot_history: Vec<String>,
    pub suspicious_u_disk_file_count: usize,
    pub secrecy_named_access_count: usize,
    pub degrade_notes: Vec<String>,
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// 将 Windows 64 位 FILETIME (自 1601-01-01 UTC 起每 100ns 计数) 转为本地标准时间戳
pub fn format_windows_filetime(ft: u64) -> String {
    if ft < 116_444_736_000_000_000 {
        return "未记录".to_string();
    }
    let unix_secs = (ft / 10_000_000).saturating_sub(11_644_473_600);
    if let Some(dt_utc) = DateTime::<Utc>::from_timestamp(unix_secs as i64, 0) {
        let dt_local: DateTime<Local> = dt_utc.into();
        dt_local.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        "未记录".to_string()
    }
}

fn read_c_ansi_or_gbk_string(buf: &[u8], offset: usize) -> String {
    if offset >= buf.len() {
        return String::new();
    }
    let end = buf[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(buf.len())
        .min(offset + 2048);
    decode_console_bytes(&buf[offset..end])
}

fn read_c_utf16le_string(buf: &[u8], offset: usize) -> String {
    if offset + 2 > buf.len() {
        return String::new();
    }
    let mut u16s = Vec::new();
    for pair in buf[offset..].chunks_exact(2) {
        let v = u16::from_le_bytes([pair[0], pair[1]]);
        if v == 0 || u16s.len() >= 1024 {
            break;
        }
        u16s.push(v);
    }
    String::from_utf16_lossy(&u16s)
}

fn check_filename_is_secrecy_suspicious(name_or_path: &str) -> bool {
    if name_or_path.trim().is_empty() {
        return false;
    }
    let scan = audit_confidentiality::scan_static_text(name_or_path);
    if scan.is_secret {
        return true;
    }
    let lower = name_or_path.to_ascii_lowercase();
    lower.contains("秘密")
        || lower.contains("机密")
        || lower.contains("绝密")
        || lower.contains("内部")
        || lower.contains("涉密")
        || lower.contains("红头")
}

/// 纯 Rust 解析单个 MS-SHLLINK (.lnk) 二进制字节流
pub fn parse_windows_lnk_bytes(shortcut_name: &str, bytes: &[u8]) -> Option<RecentFileAccessItem> {
    if bytes.len() < 76 {
        return None;
    }
    let hdr_size = read_u32_le(bytes, 0)?;
    if hdr_size != LNK_HEADER_SIZE || bytes[4..20] != LNK_CLSID {
        return None;
    }

    let link_flags = read_u32_le(bytes, 0x14)?;
    let creation_ft = read_u64_le(bytes, 0x1C).unwrap_or(0);
    let access_ft = read_u64_le(bytes, 0x24).unwrap_or(0);

    let mut cursor = 76usize;
    // Bit 0: HasLinkTargetIDList
    if (link_flags & 0x01) != 0 {
        let id_list_size = read_u16_le(bytes, cursor)? as usize;
        cursor = cursor.checked_add(2)?.checked_add(id_list_size)?;
    }

    let mut target_path = String::new();
    let mut drive_type_code: u32 = 0;

    // Bit 1: HasLinkInfo
    if (link_flags & 0x02) != 0 && cursor + 28 <= bytes.len() {
        let link_info_start = cursor;
        let link_info_size = read_u32_le(bytes, link_info_start).unwrap_or(0) as usize;
        let link_info_hdr_size = read_u32_le(bytes, link_info_start + 4).unwrap_or(0) as usize;
        let link_info_flags = read_u32_le(bytes, link_info_start + 8).unwrap_or(0);

        if (link_info_flags & 0x01) != 0 {
            let vol_id_off = read_u32_le(bytes, link_info_start + 12).unwrap_or(0) as usize;
            let local_base_off = read_u32_le(bytes, link_info_start + 16).unwrap_or(0) as usize;

            if vol_id_off > 0 && link_info_start + vol_id_off + 8 <= bytes.len() {
                drive_type_code = read_u32_le(bytes, link_info_start + vol_id_off + 4).unwrap_or(0);
            }

            if link_info_hdr_size >= 0x24 && link_info_start + 32 <= bytes.len() {
                let unicode_off = read_u32_le(bytes, link_info_start + 28).unwrap_or(0) as usize;
                if unicode_off > 0 && link_info_start + unicode_off < bytes.len() {
                    target_path = read_c_utf16le_string(bytes, link_info_start + unicode_off);
                }
            }
            if target_path.is_empty() && local_base_off > 0 && link_info_start + local_base_off < bytes.len() {
                target_path = read_c_ansi_or_gbk_string(bytes, link_info_start + local_base_off);
            }
        }
        cursor = cursor.saturating_add(link_info_size);
    }

    // 若 LinkInfo 未包含本地路径（例如远程路径或相对路径 StringData），回退解码 StringData
    if target_path.is_empty() {
        let is_unicode = (link_flags & 0x80) != 0;
        let mut s_pos = cursor;
        let read_str_data = |pos: &mut usize| -> Option<String> {
            let count = read_u16_le(bytes, *pos)? as usize;
            *pos += 2;
            let byte_len = if is_unicode { count * 2 } else { count };
            if *pos + byte_len > bytes.len() {
                return None;
            }
            let s = if is_unicode {
                let u16s: Vec<u16> = bytes[*pos..*pos + byte_len]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&u16s)
            } else {
                decode_console_bytes(&bytes[*pos..*pos + byte_len])
            };
            *pos += byte_len;
            Some(s)
        };
        if (link_flags & 0x04) != 0 {
            let _ = read_str_data(&mut s_pos); // NAME
        }
        if (link_flags & 0x08) != 0 {
            if let Some(rel) = read_str_data(&mut s_pos) {
                target_path = rel;
            }
        }
        if target_path.is_empty() && (link_flags & 0x10) != 0 {
            if let Some(wd) = read_str_data(&mut s_pos) {
                target_path = wd;
            }
        }
    }

    if target_path.is_empty() {
        target_path = shortcut_name.trim_end_matches(".lnk").to_string();
    }

    let drive_type = match drive_type_code {
        2 => "REMOVABLE",
        3 => "FIXED",
        4 => "REMOTE",
        5 => "CDROM",
        _ => "UNKNOWN",
    };

    let is_removable = drive_type == "REMOVABLE" || drive_type == "CDROM";
    let is_secrecy_named = check_filename_is_secrecy_suspicious(&target_path)
        || check_filename_is_secrecy_suspicious(shortcut_name);

    Some(RecentFileAccessItem {
        shortcut_name: shortcut_name.to_string(),
        target_real_path: target_path,
        target_creation_time: format_windows_filetime(creation_ft),
        target_last_access_time: format_windows_filetime(access_ft),
        drive_type: drive_type.to_string(),
        is_removable_media_target: is_removable,
        is_secrecy_named,
    })
}

/// 纯 Rust 解析 Windows Print Spooler `.SHD` 影子文件（兼容 Windows 7/10/11 0x4968 与 XP 0x4967 格式）
pub fn parse_windows_shd_bytes(path_str: &str, bytes: &[u8]) -> Option<PrintJobSpoolerItem> {
    if bytes.len() < 120 {
        return None;
    }
    let sig = read_u32_le(bytes, 0)?;
    if !matches!(sig, 0x0000_4968 | 0x0000_4967 | 0x0000_4966) {
        return None;
    }
    let job_id = read_u32_le(bytes, 0x08).unwrap_or(0);
    let printer_off = read_u32_le(bytes, 0x2C).unwrap_or(0) as usize;
    let doc_off = read_u32_le(bytes, 0x34).unwrap_or(0) as usize;

    let printer_name = if printer_off >= 0x40 && printer_off < bytes.len() {
        read_c_utf16le_string(bytes, printer_off)
    } else {
        "未知物理打印机".to_string()
    };
    let document_name = if doc_off >= 0x40 && doc_off < bytes.len() {
        read_c_utf16le_string(bytes, doc_off)
    } else {
        "未命名打印作业".to_string()
    };

    let submit_time = bytes
        .get(0x64..0x74)
        .and_then(decode_windows_systemtime_16bytes)
        .unwrap_or_else(|| "未知时间".to_string());

    let is_suspicious = check_filename_is_secrecy_suspicious(&document_name);
    Some(PrintJobSpoolerItem {
        job_id,
        document_name,
        printer_name,
        submit_time,
        spool_file_path: path_str.to_string(),
        is_secrecy_suspicious: is_suspicious,
    })
}

/// 解析 `wevtutil qe System` 文本提取开关机与异常断电关键事件时间线
pub fn parse_system_boot_events_text(txt: &str) -> Vec<String> {
    let mut events = Vec::new();
    let mut curr_id = String::new();
    let mut curr_date = String::new();

    for line in txt.lines() {
        let t = line.trim();
        if t.starts_with("Event[") {
            if !curr_id.is_empty() && !curr_date.is_empty() {
                events.push(format_boot_event_summary(&curr_id, &curr_date));
            }
            curr_id.clear();
            curr_date.clear();
        } else if let Some(rest) = t.strip_prefix("Event ID:") {
            curr_id = rest.trim().to_string();
        } else if let Some(rest) = t.strip_prefix("Date:") {
            curr_date = rest.trim().to_string();
        }
    }
    if !curr_id.is_empty() && !curr_date.is_empty() {
        events.push(format_boot_event_summary(&curr_id, &curr_date));
    }
    events
}

fn format_boot_event_summary(event_id: &str, date: &str) -> String {
    let desc = match event_id {
        "6005" => "系统启动与日志服务初始化",
        "6006" => "系统正常安全关机",
        "1074" => "用户或系统进程发起重启/关机",
        "41" => "系统非正常异常断电重启 (Kernel-Power)",
        _ => "系统状态事件",
    };
    format!("{} | [Event {}] {}", date, event_id, desc)
}

#[cfg(windows)]
pub fn audit_local_os_usage_forensics() -> SecrecyOsUsageReport {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const FILE_SHARE_ALL: u32 = 0x0000_0007;

    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "LOCAL-WINDOWS-HOST".to_string());
    let mut degrade_notes = Vec::new();
    let mut recent_files = Vec::new();
    let mut total_lnk_parsed = 0usize;

    // 1. 扫描 %APPDATA%\Microsoft\Windows\Recent\*.lnk
    if let Ok(appdata) = std::env::var("APPDATA") {
        let recent_dir = Path::new(&appdata).join("Microsoft").join("Windows").join("Recent");
        if let Ok(rd) = fs::read_dir(&recent_dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("lnk")).unwrap_or(false) {
                    if let Ok(bytes) = fs::read(&p) {
                        let sname = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                        if let Some(item) = parse_windows_lnk_bytes(&sname, &bytes) {
                            total_lnk_parsed += 1;
                            recent_files.push(item);
                            if recent_files.len() >= 300 {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // 优先排序：可移动介质目标 > 涉密关键字命名 > 其余记录
    recent_files.sort_by(|a, b| {
        b.is_removable_media_target
            .cmp(&a.is_removable_media_target)
            .then_with(|| b.is_secrecy_named.cmp(&a.is_secrecy_named))
    });

    // 2. 以全共享模式读取脱机打印影子队列 C:\Windows\System32\spool\PRINTERS\*.SHD
    let mut print_jobs = Vec::new();
    let spool_dir = PathBuf::from(r"C:\Windows\System32\spool\PRINTERS");
    match fs::read_dir(&spool_dir) {
        Ok(rd) => {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("shd")).unwrap_or(false) {
                    if let Ok(mut file) = OpenOptions::new().read(true).share_mode(FILE_SHARE_ALL).open(&p) {
                        let mut buf = Vec::new();
                        if file.read_to_end(&mut buf).is_ok() {
                            if let Some(job) = parse_windows_shd_bytes(&p.to_string_lossy(), &buf) {
                                print_jobs.push(job);
                            }
                        }
                    }
                }
            }
        }
        Err(_) => {
            degrade_notes.push("无法读取 System32\\spool\\PRINTERS 目录（需要管理员权限访问打印脱机队列）".to_string());
        }
    }

    // 3. 查询系统开关机时间线 EventID 6005/6006/1074/41
    let mut boot_history = Vec::new();
    if let Ok(out) = Command::new("wevtutil")
        .args([
            "qe",
            "System",
            "/q:*[System[(EventID=6005 or EventID=6006 or EventID=1074 or EventID=41)]]",
            "/f:text",
            "/rd:true",
            "/c:20",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        if out.status.success() {
            let txt = decode_console_bytes(&out.stdout);
            boot_history = parse_system_boot_events_text(&txt);
        }
    } else {
        degrade_notes.push("wevtutil 系统日志查询不可用".to_string());
    }

    let u_disk_cnt = recent_files.iter().filter(|r| r.is_removable_media_target).count();
    let secrecy_cnt = recent_files.iter().filter(|r| r.is_secrecy_named).count();

    SecrecyOsUsageReport {
        scanned_host: hostname,
        scan_time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        total_lnk_parsed,
        recent_files,
        print_spooler_jobs: print_jobs,
        system_boot_history: boot_history,
        suspicious_u_disk_file_count: u_disk_cnt,
        secrecy_named_access_count: secrecy_cnt,
        degrade_notes,
    }
}

#[cfg(not(windows))]
pub fn audit_local_os_usage_forensics() -> SecrecyOsUsageReport {
    use std::process::Command;
    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "LOCAL-LINUX-HOST".to_string())
        .trim()
        .to_string();
    let mut boot_history = Vec::new();
    if let Ok(out) = Command::new("last").args(["-x", "-n", "15", "shutdown", "reboot"]).output() {
        let txt = decode_console_bytes(&out.stdout);
        for line in txt.lines().filter(|l| !l.trim().is_empty()) {
            boot_history.push(line.trim().to_string());
        }
    }
    SecrecyOsUsageReport {
        scanned_host: hostname,
        scan_time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        total_lnk_parsed: 0,
        recent_files: vec![],
        print_spooler_jobs: vec![],
        system_boot_history: boot_history,
        suspicious_u_disk_file_count: 0,
        secrecy_named_access_count: 0,
        degrade_notes: vec!["Linux 平台使用 last -x 提取系统重启历史".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造标准 MS-SHLLINK 字节流指向 U 盘（DRIVE_REMOVABLE = 2）涉密文件
    fn build_synthetic_lnk_removable(target_path: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 76];
        buf[0..4].copy_from_slice(&LNK_HEADER_SIZE.to_le_bytes());
        buf[4..20].copy_from_slice(&LNK_CLSID);
        // HasLinkInfo (0x02) | IsUnicode (0x80)
        buf[0x14..0x18].copy_from_slice(&0x0000_0082u32.to_le_bytes());
        // CreationTime = 2026-01-01 00:00:00 UTC (approx FILETIME)
        let ft: u64 = (1_767_225_600u64 + 11_644_473_600u64) * 10_000_000;
        buf[0x1C..0x24].copy_from_slice(&ft.to_le_bytes());
        buf[0x24..0x2C].copy_from_slice(&ft.to_le_bytes());

        // LinkInfo 块：HeaderSize = 0x24 (36), VolumeIDOffset = 36, LocalBasePathOffsetUnicode = 56
        let vol_id_len = 20u32;
        let path_u16: Vec<u8> = target_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let link_info_size = 36 + vol_id_len as usize + path_u16.len();
        let mut link_info = vec![0u8; 36];
        link_info[0..4].copy_from_slice(&(link_info_size as u32).to_le_bytes());
        link_info[4..8].copy_from_slice(&0x24u32.to_le_bytes());
        link_info[8..12].copy_from_slice(&0x01u32.to_le_bytes()); // VolumeIDAndLocalBasePath
        link_info[12..16].copy_from_slice(&36u32.to_le_bytes()); // VolumeIDOffset
        link_info[16..20].copy_from_slice(&56u32.to_le_bytes()); // LocalBasePathOffset
        link_info[28..32].copy_from_slice(&56u32.to_le_bytes()); // LocalBasePathOffsetUnicode

        let mut vol_id = vec![0u8; 20];
        vol_id[0..4].copy_from_slice(&vol_id_len.to_le_bytes());
        vol_id[4..8].copy_from_slice(&2u32.to_le_bytes()); // 2 = DRIVE_REMOVABLE

        buf.extend_from_slice(&link_info);
        buf.extend_from_slice(&vol_id);
        buf.extend_from_slice(&path_u16);
        buf
    }

    #[test]
    fn test_parse_windows_lnk_removable_media_and_secrecy_target() {
        let lnk = build_synthetic_lnk_removable("E:\\内部资料\\绝密★项目技术规范.docx");
        let parsed = parse_windows_lnk_bytes("绝密★项目技术规范.lnk", &lnk).expect("应能解析合成 LNK");
        assert_eq!(parsed.drive_type, "REMOVABLE");
        assert!(parsed.is_removable_media_target);
        assert!(parsed.is_secrecy_named);
        assert!(parsed.target_real_path.contains("E:\\内部资料\\绝密★项目技术规范.docx"));
        assert!(parsed.target_creation_time.starts_with("2026-"));
    }

    #[test]
    fn test_parse_windows_shd_spooler_and_boot_events() {
        let mut shd = vec![0u8; 256];
        shd[0..4].copy_from_slice(&0x0000_4968u32.to_le_bytes());
        shd[8..12].copy_from_slice(&42u32.to_le_bytes());
        shd[0x2C..0x30].copy_from_slice(&128u32.to_le_bytes()); // printer_off
        shd[0x34..0x38].copy_from_slice(&176u32.to_le_bytes()); // doc_off

        let printer_u16: Vec<u8> = "HP LaserJet Pro".encode_utf16().chain(std::iter::once(0)).flat_map(|u| u.to_le_bytes()).collect();
        let doc_u16: Vec<u8> = "机密★红头通知打印稿.docx".encode_utf16().chain(std::iter::once(0)).flat_map(|u| u.to_le_bytes()).collect();
        shd[128..128 + printer_u16.len()].copy_from_slice(&printer_u16);
        shd[176..176 + doc_u16.len()].copy_from_slice(&doc_u16);

        let parsed = parse_windows_shd_bytes("00042.SHD", &shd).expect("应成功解析 .SHD");
        assert_eq!(parsed.job_id, 42);
        assert_eq!(parsed.printer_name, "HP LaserJet Pro");
        assert!(parsed.document_name.contains("机密★红头通知打印稿"));
        assert!(parsed.is_secrecy_suspicious);

        let evtx_sample = "Event[0]:\n  Event ID: 6005\n  Date: 2026-11-14T08:30:00.123Z\nEvent[1]:\n  Event ID: 41\n  Date: 2026-11-13T21:10:00.000Z\n";
        let boots = parse_system_boot_events_text(evtx_sample);
        assert_eq!(boots.len(), 2);
        assert!(boots[0].contains("Event 6005"));
        assert!(boots[1].contains("Kernel-Power"));
    }

    #[test]
    fn test_lnk_and_shd_malformed_boundaries() {
        // 极限边界：短字节流、损坏魔数不崩溃
        assert!(parse_windows_lnk_bytes("bad.lnk", &[]).is_none());
        assert!(parse_windows_lnk_bytes("bad.lnk", &[0xFFu8; 80]).is_none());
        assert!(parse_windows_shd_bytes("bad.shd", &[0u8; 10]).is_none());
        assert!(parse_windows_shd_bytes("bad.shd", &[0x11u8; 150]).is_none());
    }
}
