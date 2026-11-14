//! 常用浏览器与办公即时通信涉密外发痕迹审计引擎 (零 C 依赖纯 Rust SQLite3 B-Tree 解析)
//! 对标行业标准：BMB17-2006、BMB22-2007、GB/T 29360-2012
//!
//! 物理能力：
//! 1. 采用共享只读 / Copy-on-Read 机制规避正在运行浏览器的 SQLite 文件独占锁；
//! 2. 零 C/C++ sqlite3 库依赖，纯 Rust 原生解析 SQLite Format 3 文件头、Varint、SerialType 与 B-Tree 内部页/叶页，精准还原 Chrome/Edge `downloads` 下载文件记录与 `urls` 记录；
//! 3. 检索微信 (WeChat)、企业微信 (WXWork)、钉钉 (DingTalk) 本地文件传输目录中的涉密标识文档与发文字号。
//!
//! 算法复杂度：
//! - 时间复杂度：O(P_sql + F_chat)，受限于受控批次页遍历与每户最多 1,000 份文件上限；
//! - 空间复杂度：O(D + C)，线性存储抽取到的下载与即时通信文件命中记录。

use crate::audit_confidentiality;
use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const MAX_SQLITE_PARSE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CHAT_SCAN_FILES: usize = 1200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDownloadHitItem {
    pub browser_type: String,
    pub target_file_path: String,
    pub original_url: String,
    pub download_time: String,
    pub is_suspicious_secrecy: bool,
    pub matched_marker: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatFileTraceItem {
    pub app_name: String,
    pub file_name: String,
    pub file_path: String,
    pub file_size: u64,
    pub hit_secrecy_marker: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecrecyAppTraceReport {
    pub scanned_host: String,
    pub scan_time: String,
    pub total_downloads_checked: usize,
    pub suspicious_downloads: Vec<BrowserDownloadHitItem>,
    pub recent_downloads_sample: Vec<BrowserDownloadHitItem>,
    pub chat_files_checked: usize,
    pub chat_file_hits: Vec<ChatFileTraceItem>,
    pub degrade_notes: Vec<String>,
}

#[derive(Debug, Clone)]
enum SqliteCellVal {
    Null,
    Int(i64),
    Float(f64),
    Text(String),
    Blob,
}

impl SqliteCellVal {
    fn as_text(&self) -> Option<&str> {
        match self {
            SqliteCellVal::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }
    fn as_int(&self) -> Option<i64> {
        match self {
            SqliteCellVal::Int(v) => Some(*v),
            SqliteCellVal::Float(v) => Some(*v as i64),
            _ => None,
        }
    }
}

/// 读取 SQLite 标准 1..9 字节大端变长整数 (Varint)
fn read_sqlite_varint(buf: &[u8], pos: &mut usize) -> Option<i64> {
    let mut val: u64 = 0;
    for i in 0..9 {
        let &b = buf.get(*pos)?;
        *pos += 1;
        if i == 8 {
            val = (val << 8) | (b as u64);
            return Some(val as i64);
        }
        val = (val << 7) | ((b & 0x7F) as u64);
        if (b & 0x80) == 0 {
            return Some(val as i64);
        }
    }
    Some(val as i64)
}

/// 将 Chromium WebKit 微秒时间戳（自 1601-01-01 UTC 起）格式化为本地时间
pub fn format_webkit_timestamp(webkit_us: i64) -> String {
    const WEBKIT_TO_UNIX_US: i64 = 11_644_473_600_000_000;
    if webkit_us <= WEBKIT_TO_UNIX_US {
        return "未知时间".to_string();
    }
    let unix_secs = (webkit_us - WEBKIT_TO_UNIX_US) / 1_000_000;
    if let Some(dt_utc) = DateTime::<Utc>::from_timestamp(unix_secs, 0) {
        let dt_local: DateTime<Local> = dt_utc.into();
        dt_local.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        "未知时间".to_string()
    }
}

fn decode_sqlite_record_payload(payload: &[u8]) -> Vec<SqliteCellVal> {
    let mut pos = 0usize;
    let Some(hdr_size_raw) = read_sqlite_varint(payload, &mut pos) else {
        return vec![];
    };
    let hdr_size = (hdr_size_raw.max(0) as usize).min(payload.len());
    let mut serial_types = Vec::new();
    while pos < hdr_size && serial_types.len() < 64 {
        if let Some(st) = read_sqlite_varint(payload, &mut pos) {
            serial_types.push(st);
        } else {
            break;
        }
    }

    let mut data_pos = hdr_size;
    let mut cols = Vec::with_capacity(serial_types.len());

    for st in serial_types {
        if data_pos > payload.len() {
            cols.push(SqliteCellVal::Null);
            continue;
        }
        match st {
            0 => cols.push(SqliteCellVal::Null),
            1 => {
                if let Some(&b) = payload.get(data_pos) {
                    cols.push(SqliteCellVal::Int((b as i8) as i64));
                    data_pos += 1;
                } else {
                    cols.push(SqliteCellVal::Null);
                }
            }
            2 => {
                if let Some(s) = payload.get(data_pos..data_pos + 2) {
                    cols.push(SqliteCellVal::Int(i16::from_be_bytes([s[0], s[1]]) as i64));
                    data_pos += 2;
                } else {
                    cols.push(SqliteCellVal::Null);
                }
            }
            3 => {
                if let Some(s) = payload.get(data_pos..data_pos + 3) {
                    let sign = if (s[0] & 0x80) != 0 { 0xFF } else { 0x00 };
                    cols.push(SqliteCellVal::Int(i32::from_be_bytes([sign, s[0], s[1], s[2]]) as i64));
                    data_pos += 3;
                } else {
                    cols.push(SqliteCellVal::Null);
                }
            }
            4 => {
                if let Some(s) = payload.get(data_pos..data_pos + 4) {
                    cols.push(SqliteCellVal::Int(i32::from_be_bytes([s[0], s[1], s[2], s[3]]) as i64));
                    data_pos += 4;
                } else {
                    cols.push(SqliteCellVal::Null);
                }
            }
            5 => {
                if let Some(s) = payload.get(data_pos..data_pos + 6) {
                    let sign = if (s[0] & 0x80) != 0 { 0xFF } else { 0x00 };
                    cols.push(SqliteCellVal::Int(i64::from_be_bytes([
                        sign, sign, s[0], s[1], s[2], s[3], s[4], s[5],
                    ])));
                    data_pos += 6;
                } else {
                    cols.push(SqliteCellVal::Null);
                }
            }
            6 => {
                if let Some(s) = payload.get(data_pos..data_pos + 8) {
                    cols.push(SqliteCellVal::Int(i64::from_be_bytes([
                        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
                    ])));
                    data_pos += 8;
                } else {
                    cols.push(SqliteCellVal::Null);
                }
            }
            7 => {
                if let Some(s) = payload.get(data_pos..data_pos + 8) {
                    cols.push(SqliteCellVal::Float(f64::from_be_bytes([
                        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
                    ])));
                    data_pos += 8;
                } else {
                    cols.push(SqliteCellVal::Null);
                }
            }
            8 => cols.push(SqliteCellVal::Int(0)),
            9 => cols.push(SqliteCellVal::Int(1)),
            n if n >= 12 && n % 2 == 0 => {
                let len = ((n - 12) / 2) as usize;
                cols.push(SqliteCellVal::Blob);
                data_pos += len;
            }
            n if n >= 13 && n % 2 == 1 => {
                let len = ((n - 13) / 2) as usize;
                let end = (data_pos + len).min(payload.len());
                let txt = String::from_utf8_lossy(&payload[data_pos..end]).to_string();
                cols.push(SqliteCellVal::Text(txt));
                data_pos += len;
            }
            _ => cols.push(SqliteCellVal::Null),
        }
    }
    cols
}

fn extract_table_btree_rows(
    db: &[u8],
    page_size: usize,
    root_page: usize,
    max_rows: usize,
) -> Vec<(i64, Vec<SqliteCellVal>)> {
    let mut rows = Vec::new();
    let mut stack = vec![root_page];
    let mut visited = HashSet::new();

    while let Some(page_num) = stack.pop() {
        if page_num == 0 || !visited.insert(page_num) || rows.len() >= max_rows {
            continue;
        }
        let page_off = (page_num - 1).saturating_mul(page_size);
        let Some(page) = db.get(page_off..page_off.saturating_add(page_size).min(db.len())) else {
            continue;
        };
        let hdr_off = if page_num == 1 { 100 } else { 0 };
        if hdr_off + 8 > page.len() {
            continue;
        }

        let flag = page[hdr_off];
        let cell_count = u16::from_be_bytes([page[hdr_off + 3], page[hdr_off + 4]]) as usize;
        let ptr_array_off = match flag {
            0x0D => hdr_off + 8,  // Leaf Table B-Tree
            0x05 => hdr_off + 12, // Interior Table B-Tree
            _ => continue,
        };

        if flag == 0x05 {
            // 先压入最右子页，再逆序压入左子页以保持顺序遍历
            let right_child = u32::from_be_bytes([
                page[hdr_off + 8],
                page[hdr_off + 9],
                page[hdr_off + 10],
                page[hdr_off + 11],
            ]) as usize;
            stack.push(right_child);
            for i in (0..cell_count).rev() {
                let p_off = ptr_array_off + i * 2;
                if let Some(pb) = page.get(p_off..p_off + 2) {
                    let cell_off = u16::from_be_bytes([pb[0], pb[1]]) as usize;
                    if let Some(cb) = page.get(cell_off..cell_off + 4) {
                        let child = u32::from_be_bytes([cb[0], cb[1], cb[2], cb[3]]) as usize;
                        stack.push(child);
                    }
                }
            }
        } else {
            // 0x0D: Leaf Table Page
            for i in 0..cell_count {
                if rows.len() >= max_rows {
                    break;
                }
                let p_off = ptr_array_off + i * 2;
                let Some(pb) = page.get(p_off..p_off + 2) else {
                    continue;
                };
                let cell_off = u16::from_be_bytes([pb[0], pb[1]]) as usize;
                let Some(cell_slice) = page.get(cell_off..) else {
                    continue;
                };
                let mut pos = 0usize;
                let Some(payload_len_i) = read_sqlite_varint(cell_slice, &mut pos) else {
                    continue;
                };
                let Some(rowid) = read_sqlite_varint(cell_slice, &mut pos) else {
                    continue;
                };
                let payload_len = payload_len_i.max(0) as usize;
                let available = cell_slice.len().saturating_sub(pos);
                let slice_end = pos + payload_len.min(available);
                let cols = decode_sqlite_record_payload(&cell_slice[pos..slice_end]);
                if !cols.is_empty() {
                    rows.push((rowid, cols));
                }
            }
        }
    }
    rows
}

fn check_secrecy_keywords_in_name(text: &str) -> Option<String> {
    let scan = audit_confidentiality::scan_static_text(text);
    if scan.is_secret {
        return scan
            .hit_markers
            .first()
            .or_else(|| scan.document_signatures.first())
            .cloned()
            .or(Some(scan.highest_level));
    }
    for kw in ["秘密", "机密", "绝密", "内部", "涉密", "红头"] {
        if text.contains(kw) {
            return Some(kw.to_string());
        }
    }
    None
}

/// 纯 Rust 解析 Chromium / Edge SQLite `History` 数据库原始字节提取下载文件记录
pub fn parse_chromium_history_sqlite_bytes(browser_type: &str, db: &[u8]) -> Result<Vec<BrowserDownloadHitItem>, String> {
    if db.len() < 100 || &db[0..16] != SQLITE_MAGIC {
        return Err("非标准 SQLite Format 3 数据库头".to_string());
    }
    let raw_ps = u16::from_be_bytes([db[16], db[17]]) as usize;
    let page_size = if raw_ps == 1 { 65536 } else { raw_ps };
    if page_size < 512 || !page_size.is_power_of_two() {
        return Err(format!("SQLite 页面尺寸非法: {}", page_size));
    }

    // 1. 解析 sqlite_schema (RootPage = 1) 查找 downloads 与 downloads_url_chains 根页
    let schema_rows = extract_table_btree_rows(db, page_size, 1, 200);
    let mut downloads_root = None;
    let mut chains_root = None;
    for (_, cols) in &schema_rows {
        let obj_type = cols.first().and_then(|c| c.as_text()).unwrap_or("");
        let name = cols.get(1).and_then(|c| c.as_text()).unwrap_or("");
        let root_page = cols.get(3).and_then(|c| c.as_int()).unwrap_or(0);
        if obj_type == "table" && root_page > 0 {
            if name == "downloads" {
                downloads_root = Some(root_page as usize);
            } else if name == "downloads_url_chains" {
                chains_root = Some(root_page as usize);
            }
        }
    }

    let Some(dl_root) = downloads_root else {
        return Ok(vec![]);
    };

    // 2. 构建 download_id -> URL 映射表
    let mut url_by_id: HashMap<i64, String> = HashMap::new();
    if let Some(c_root) = chains_root {
        let chain_rows = extract_table_btree_rows(db, page_size, c_root, 1000);
        for (_, cols) in chain_rows {
            let id = cols.first().and_then(|c| c.as_int());
            let url = cols.get(2).and_then(|c| c.as_text());
            if let (Some(dl_id), Some(u)) = (id, url) {
                url_by_id.entry(dl_id).or_insert_with(|| u.to_string());
            }
        }
    }

    // 3. 提取 downloads 表主记录（Chromium 结构：0:id, 1:guid, 2:current_path, 3:target_path, 4:start_time ...）
    let dl_rows = extract_table_btree_rows(db, page_size, dl_root, 500);
    let mut results = Vec::new();
    for (rowid, cols) in dl_rows {
        let dl_id = cols.first().and_then(|c| c.as_int()).unwrap_or(rowid);
        let current_path = cols.get(2).and_then(|c| c.as_text()).unwrap_or("");
        let target_path = cols.get(3).and_then(|c| c.as_text()).unwrap_or("");
        let chosen_path = if !target_path.is_empty() {
            target_path.to_string()
        } else {
            current_path.to_string()
        };
        if chosen_path.is_empty() {
            continue;
        }
        let start_time_us = cols.get(4).and_then(|c| c.as_int()).unwrap_or(0);
        let original_url = url_by_id
            .get(&dl_id)
            .cloned()
            .unwrap_or_else(|| "未知源地址".to_string());

        let hit_marker = check_secrecy_keywords_in_name(&chosen_path)
            .or_else(|| check_secrecy_keywords_in_name(&original_url));

        results.push(BrowserDownloadHitItem {
            browser_type: browser_type.to_string(),
            target_file_path: chosen_path,
            original_url,
            download_time: format_webkit_timestamp(start_time_us),
            is_suspicious_secrecy: hit_marker.is_some(),
            matched_marker: hit_marker,
        });
    }

    Ok(results)
}

/// 规避浏览器运行锁读取本地 SQLite 文件（共享读模式打开；失败则 Copy-on-Read 到临时副本后读取并销毁）
fn read_sqlite_file_lock_safe(path: &Path) -> Result<Vec<u8>, String> {
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() > MAX_SQLITE_PARSE_BYTES {
        return Err("浏览器数据库超过 64MB 解析上限".to_string());
    }

    #[cfg(windows)]
    let direct_open = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_ALL: u32 = 0x0000_0007;
        OpenOptions::new().read(true).share_mode(FILE_SHARE_ALL).open(path)
    };
    #[cfg(not(windows))]
    let direct_open = OpenOptions::new().read(true).open(path);

    if let Ok(mut f) = direct_open {
        let mut buf = Vec::with_capacity(meta.len() as usize);
        if f.read_to_end(&mut buf).is_ok() {
            return Ok(buf);
        }
    }

    // 回退 Copy-on-Read 沙箱副本
    let tmp_copy = std::env::temp_dir().join(format!(
        "omni_browser_hist_{}.sqlite",
        chrono::Local::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    fs::copy(path, &tmp_copy).map_err(|e| format!("复制 SQLite 历史库失败: {}", e))?;
    let res = fs::read(&tmp_copy).map_err(|e| e.to_string());
    let _ = fs::remove_file(&tmp_copy);
    res
}

fn scan_chat_storage_dir(app_name: &str, dir: &Path, checked_cnt: &mut usize, hits: &mut Vec<ChatFileTraceItem>) {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(curr) = stack.pop() {
        if *checked_cnt >= MAX_CHAT_SCAN_FILES {
            break;
        }
        if let Ok(rd) = fs::read_dir(&curr) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.is_file() {
                    *checked_cnt += 1;
                    let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                    if let Some(marker) = check_secrecy_keywords_in_name(&fname) {
                        let fsize = p.metadata().map(|m| m.len()).unwrap_or(0);
                        hits.push(ChatFileTraceItem {
                            app_name: app_name.to_string(),
                            file_name: fname,
                            file_path: p.to_string_lossy().to_string(),
                            file_size: fsize,
                            hit_secrecy_marker: Some(marker),
                        });
                    }
                    if *checked_cnt >= MAX_CHAT_SCAN_FILES {
                        break;
                    }
                }
            }
        }
    }
}

/// 综合扫描宿主机浏览器历史下载与办公即时通信缓存目录
pub fn audit_local_secrecy_app_traces() -> SecrecyAppTraceReport {
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "LOCAL-HOST".to_string());

    let mut degrade_notes = Vec::new();
    let mut all_downloads = Vec::new();
    let mut browser_dbs: Vec<(&str, PathBuf)> = Vec::new();

    #[cfg(windows)]
    {
        if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
            let local = Path::new(&local_app);
            for prof in ["Default", "Profile 1", "Profile 2"] {
                browser_dbs.push((
                    "Chrome",
                    local.join("Google").join("Chrome").join("User Data").join(prof).join("History"),
                ));
                browser_dbs.push((
                    "Edge",
                    local.join("Microsoft").join("Edge").join("User Data").join(prof).join("History"),
                ));
            }
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let h = Path::new(&home);
            browser_dbs.push(("Chrome", h.join(".config/google-chrome/Default/History")));
            browser_dbs.push(("Chromium", h.join(".config/chromium/Default/History")));
        }
    }

    for (bname, db_path) in browser_dbs {
        if !db_path.exists() {
            continue;
        }
        match read_sqlite_file_lock_safe(&db_path) {
            Ok(bytes) => match parse_chromium_history_sqlite_bytes(bname, &bytes) {
                Ok(items) => all_downloads.extend(items),
                Err(e) => degrade_notes.push(format!("{} 解析异常 ({}): {}", bname, db_path.display(), e)),
            },
            Err(e) => degrade_notes.push(format!("无法读取 {} 历史库: {}", bname, e)),
        }
    }

    let total_downloads_checked = all_downloads.len();
    let suspicious_downloads: Vec<BrowserDownloadHitItem> = all_downloads
        .iter()
        .filter(|d| d.is_suspicious_secrecy)
        .cloned()
        .collect();
    let recent_downloads_sample: Vec<BrowserDownloadHitItem> = all_downloads.into_iter().take(40).collect();

    // 即时通信工具（微信、企业微信、钉钉）传输目录排查
    let mut chat_files_checked = 0usize;
    let mut chat_file_hits = Vec::new();

    #[cfg(windows)]
    {
        if let Ok(user_prof) = std::env::var("USERPROFILE") {
            let docs = Path::new(&user_prof).join("Documents");
            for (app, sub) in [
                ("WeChat", docs.join("WeChat Files")),
                ("WXWork", docs.join("WXWork")),
                ("DingTalk", docs.join("DingTalk")),
            ] {
                if sub.exists() {
                    scan_chat_storage_dir(app, &sub, &mut chat_files_checked, &mut chat_file_hits);
                }
            }
        }
    }

    SecrecyAppTraceReport {
        scanned_host: hostname,
        scan_time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        total_downloads_checked,
        suspicious_downloads,
        recent_downloads_sample,
        chat_files_checked,
        chat_file_hits,
        degrade_notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_sqlite_varint(mut v: u64) -> Vec<u8> {
        let mut parts = Vec::new();
        parts.push((v & 0x7F) as u8);
        v >>= 7;
        while v > 0 {
            parts.push(((v & 0x7F) as u8) | 0x80);
            v >>= 7;
        }
        parts.reverse();
        parts
    }

    fn build_sqlite_record(cols: Vec<SqliteCellVal>) -> Vec<u8> {
        let mut header = Vec::new();
        let mut body = Vec::new();
        for c in cols {
            match c {
                SqliteCellVal::Null => header.extend(encode_sqlite_varint(0)),
                SqliteCellVal::Int(0) => header.extend(encode_sqlite_varint(8)),
                SqliteCellVal::Int(1) => header.extend(encode_sqlite_varint(9)),
                SqliteCellVal::Int(v) => {
                    header.extend(encode_sqlite_varint(6)); // 8-byte int
                    body.extend_from_slice(&v.to_be_bytes());
                }
                SqliteCellVal::Text(s) => {
                    let b = s.as_bytes();
                    header.extend(encode_sqlite_varint((b.len() * 2 + 13) as u64));
                    body.extend_from_slice(b);
                }
                SqliteCellVal::Float(f) => {
                    header.extend(encode_sqlite_varint(7));
                    body.extend_from_slice(&f.to_be_bytes());
                }
                SqliteCellVal::Blob => {}
            }
        }
        // Header total length includes varint of itself (假设 < 127 => 1 byte)
        let hdr_len = 1 + header.len();
        let mut full = Vec::new();
        full.extend(encode_sqlite_varint(hdr_len as u64));
        full.extend(header);
        full.extend(body);
        full
    }

    fn write_leaf_page(page: &mut [u8], hdr_off: usize, cells: &[(i64, Vec<u8>)]) {
        let page_len = page.len();
        page[hdr_off] = 0x0D; // Table Leaf Page
        page[hdr_off + 3..hdr_off + 5].copy_from_slice(&(cells.len() as u16).to_be_bytes());

        let mut content_end = page_len;
        let ptr_start = hdr_off + 8;
        for (idx, (rowid, payload)) in cells.iter().enumerate() {
            let mut cell = Vec::new();
            cell.extend(encode_sqlite_varint(payload.len() as u64));
            cell.extend(encode_sqlite_varint(*rowid as u64));
            cell.extend_from_slice(payload);

            content_end -= cell.len();
            page[content_end..content_end + cell.len()].copy_from_slice(&cell);
            page[ptr_start + idx * 2..ptr_start + idx * 2 + 2]
                .copy_from_slice(&(content_end as u16).to_be_bytes());
        }
        page[hdr_off + 5..hdr_off + 7].copy_from_slice(&(content_end as u16).to_be_bytes());
    }

    #[test]
    fn test_parse_synthetic_chromium_sqlite_downloads_btree() {
        let page_size = 4096usize;
        let mut db = vec![0u8; page_size * 3];
        db[0..16].copy_from_slice(SQLITE_MAGIC);
        db[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());

        // Page 1: sqlite_schema pointing downloads -> page 2, downloads_url_chains -> page 3
        let schema_cells = vec![
            (
                1,
                build_sqlite_record(vec![
                    SqliteCellVal::Text("table".into()),
                    SqliteCellVal::Text("downloads".into()),
                    SqliteCellVal::Text("downloads".into()),
                    SqliteCellVal::Int(2),
                    SqliteCellVal::Text("CREATE TABLE downloads(...)".into()),
                ]),
            ),
            (
                2,
                build_sqlite_record(vec![
                    SqliteCellVal::Text("table".into()),
                    SqliteCellVal::Text("downloads_url_chains".into()),
                    SqliteCellVal::Text("downloads_url_chains".into()),
                    SqliteCellVal::Int(3),
                    SqliteCellVal::Text("CREATE TABLE downloads_url_chains(...)".into()),
                ]),
            ),
        ];
        write_leaf_page(&mut db[0..page_size], 100, &schema_cells);

        // Page 2: downloads rows (row 101 含有涉密红头文件名，row 102 普通文件)
        let webkit_2026: i64 = 11_644_473_600_000_000 + 1_767_225_600_000_000;
        let dl_cells = vec![
            (
                101,
                build_sqlite_record(vec![
                    SqliteCellVal::Int(101),
                    SqliteCellVal::Text("uuid-101".into()),
                    SqliteCellVal::Text("C:\\Users\\test\\Downloads\\绝密★2026内部总体方案.pdf".into()),
                    SqliteCellVal::Text("C:\\Users\\test\\Downloads\\绝密★2026内部总体方案.pdf".into()),
                    SqliteCellVal::Int(webkit_2026),
                ]),
            ),
            (
                102,
                build_sqlite_record(vec![
                    SqliteCellVal::Int(102),
                    SqliteCellVal::Text("uuid-102".into()),
                    SqliteCellVal::Text("C:\\Users\\test\\Downloads\\weather_report.png".into()),
                    SqliteCellVal::Text("C:\\Users\\test\\Downloads\\weather_report.png".into()),
                    SqliteCellVal::Int(webkit_2026),
                ]),
            ),
        ];
        write_leaf_page(&mut db[page_size..page_size * 2], 0, &dl_cells);

        // Page 3: downloads_url_chains
        let chain_cells = vec![(
            1,
            build_sqlite_record(vec![
                SqliteCellVal::Int(101),
                SqliteCellVal::Int(0),
                SqliteCellVal::Text("https://pan.example.com/share/secret.pdf".into()),
            ]),
        )];
        write_leaf_page(&mut db[page_size * 2..page_size * 3], 0, &chain_cells);

        let hits = parse_chromium_history_sqlite_bytes("Chrome", &db).expect("应成功解析合成 SQLite3 历史数据库");
        assert_eq!(hits.len(), 2);
        let secret_dl = hits.iter().find(|d| d.target_file_path.contains("绝密")).unwrap();
        assert!(secret_dl.is_suspicious_secrecy);
        assert_eq!(secret_dl.original_url, "https://pan.example.com/share/secret.pdf");
        assert!(secret_dl.download_time.starts_with("2026-"));

        let normal_dl = hits.iter().find(|d| d.target_file_path.contains("weather_report")).unwrap();
        assert!(!normal_dl.is_suspicious_secrecy);
    }

    #[test]
    fn test_sqlite_malformed_and_empty_boundaries() {
        // 极限边界：空字节、无效头、非法页大小安全拦截
        assert!(parse_chromium_history_sqlite_bytes("Edge", b"").is_err());
        assert!(parse_chromium_history_sqlite_bytes("Edge", b"CORRUPT_HEADER_ONLY").is_err());
        let mut bad_ps = [0u8; 128];
        bad_ps[0..16].copy_from_slice(SQLITE_MAGIC);
        bad_ps[16..18].copy_from_slice(&123u16.to_be_bytes()); // 非2的幂
        assert!(parse_chromium_history_sqlite_bytes("Chrome", &bad_ps).is_err());
    }
}
