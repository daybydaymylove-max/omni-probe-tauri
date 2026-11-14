//! 老旧 OLE2 复合公文 (DOC/XLS/PPT) CFBF 二进制流解构与磁盘空闲簇残片检索引擎
//! 对标行业标准：GB/T 9704-2012、BMB20-2007、GB/T 29360-2012
//!
//! 物理能力：
//! 1. 零 Microsoft Office / COM 组件依赖，纯 Rust 解析 MS-CFB (OLE2) 头文件、FAT/DIFAT、MiniFAT 与目录流；
//! 2. 支持直接对 `WordDocument`、`1Table`、`Workbook`、`PowerPoint Document`、`\x05SummaryInformation` 进行 UTF-16LE 与 GBK 双路正文剥离；
//! 3. 支持对物理卷/磁盘镜像执行 4KB 对齐流式滑窗扫描（带边界重叠缓冲），检出被普通删除后的涉密标密残片；
//!
//! 算法复杂度：
//! - OLE2 解构：时间复杂度 O(S)，空间复杂度 O(F + S_stream)，受限于 30MB 上界与 FAT 环路防死锁校验；
//! - 扇区流式检索：时间复杂度 O(B)，空间复杂度 O(1)（固定 16KB 环形重叠滑窗，绝不随磁盘容量膨胀）。

use crate::audit_confidentiality;
use crate::host_baseline::decode_console_bytes;
use crate::secrecy_document_dissector::{build_masked_snippet, compute_dual_hashes};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

const OLE2_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const FREE_SECT: u32 = 0xFFFF_FFFF;
const END_OF_CHAIN: u32 = 0xFFFF_FFFE;
const MAX_OLE2_FILE_BYTES: u64 = 32 * 1024 * 1024; // 单份 OLE2 文件最高 32MB 熔断
const MAX_OLE2_SCAN_FILES: usize = 1000;
const MAX_RAW_SLACK_SCAN_BYTES: u64 = 64 * 1024 * 1024; // 原始卷/镜像采样窗口上限 64MB，确保响应迅速

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ole2DocumentHit {
    pub file_path: String,
    pub sub_stream_name: String,
    pub sha256_hash: String,
    pub sm3_hash: String,
    pub secrecy_level: String,
    pub matched_markers: Vec<String>,
    pub document_signatures: Vec<String>,
    pub snippet_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackSpaceSnippetHit {
    pub drive_letter: String,
    pub sector_offset: u64,
    pub matched_marker: String,
    pub snippet_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecrecyDeepContentReport {
    pub target_folder: String,
    pub scanned_ole2_files: usize,
    pub ole2_hits: Vec<Ole2DocumentHit>,
    pub slack_scanned_bytes: u64,
    pub slack_hits: Vec<SlackSpaceSnippetHit>,
    pub duration_ms: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct CfbfDirEntry {
    name: String,
    obj_type: u8,
    start_sector: u32,
    stream_size: u64,
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

fn sector_slice<'a>(data: &'a [u8], sector_id: u32, sector_size: usize) -> Option<&'a [u8]> {
    let start = (sector_id as usize).checked_add(1)?.checked_mul(sector_size)?;
    let end = start.checked_add(sector_size)?;
    if end <= data.len() {
        Some(&data[start..end])
    } else if start < data.len() {
        // 截断文件的容错尾扇区读取
        Some(&data[start..])
    } else {
        None
    }
}

/// 按照 FAT 链表读取完整流字节（带环路检测防止恶意 CFBF 死循环）
fn read_fat_chain(
    data: &[u8],
    fat: &[u32],
    start_sector: u32,
    sector_size: usize,
    max_bytes: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut curr = start_sector;
    let mut visited = HashSet::new();
    let max_hops = (fat.len() + 4).min(131072);

    while curr != END_OF_CHAIN && curr != FREE_SECT && curr < 0xFFFF_FFF0 {
        if visited.len() >= max_hops || !visited.insert(curr) {
            break; // 熔断循环链表攻击
        }
        let Some(slice) = sector_slice(data, curr, sector_size) else {
            break;
        };
        let remain = max_bytes.saturating_sub(out.len());
        if remain == 0 {
            break;
        }
        let take_len = slice.len().min(remain);
        out.extend_from_slice(&slice[..take_len]);

        curr = match fat.get(curr as usize) {
            Some(&next) => next,
            None => break,
        };
    }
    out
}

/// 解析 MS-CFB (OLE2) 复合二进制结构并抽取关键公文流名称及原始字节
pub fn parse_cfbf_streams(raw: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    if raw.len() < 512 || !raw.starts_with(&OLE2_MAGIC) {
        return Err("非标准 OLE2/CFBF 复合二进制文件头".to_string());
    }

    let sector_shift = read_u16_le(raw, 0x1E).unwrap_or(9);
    if !(7..=16).contains(&sector_shift) {
        return Err(format!("OLE2 扇区偏移量异常: {}", sector_shift));
    }
    let sector_size = 1usize << sector_shift;
    if raw.len() < sector_size {
        return Err("OLE2 头部长度不完整".to_string());
    }

    let num_fat_sectors = read_u32_le(raw, 0x2C).unwrap_or(0);
    let dir_start = read_u32_le(raw, 0x30).unwrap_or(END_OF_CHAIN);
    let mini_cutoff = read_u32_le(raw, 0x38).unwrap_or(4096) as u64;
    let mini_fat_start = read_u32_le(raw, 0x3C).unwrap_or(END_OF_CHAIN);
    let mut difat_sector = read_u32_le(raw, 0x44).unwrap_or(END_OF_CHAIN);
    let num_difat_sectors = read_u32_le(raw, 0x48).unwrap_or(0);

    // 1. 收集所有 FAT 扇区编号（前 109 个位于 Header 0x4C..0x200）
    let mut fat_sector_ids = Vec::new();
    for i in 0..109 {
        if let Some(sid) = read_u32_le(raw, 0x4C + i * 4) {
            if sid != FREE_SECT && sid < 0xFFFF_FFF0 {
                fat_sector_ids.push(sid);
            }
        }
    }

    let mut difat_visited = HashSet::new();
    let mut difat_hops = 0u32;
    while difat_sector != END_OF_CHAIN
        && difat_sector != FREE_SECT
        && difat_sector < 0xFFFF_FFF0
        && difat_hops < num_difat_sectors.min(512)
        && difat_visited.insert(difat_sector)
    {
        difat_hops += 1;
        if let Some(sec) = sector_slice(raw, difat_sector, sector_size) {
            let entries_per_sec = (sector_size / 4).saturating_sub(1);
            for i in 0..entries_per_sec {
                if let Some(sid) = read_u32_le(sec, i * 4) {
                    if sid != FREE_SECT && sid < 0xFFFF_FFF0 {
                        fat_sector_ids.push(sid);
                    }
                }
            }
            difat_sector = read_u32_le(sec, entries_per_sec * 4).unwrap_or(END_OF_CHAIN);
        } else {
            break;
        }
    }

    if num_fat_sectors > 0 && fat_sector_ids.len() > (num_fat_sectors as usize + 64) {
        fat_sector_ids.truncate(num_fat_sectors as usize);
    }

    // 2. 重建完整 FAT 表
    let mut fat = Vec::with_capacity(fat_sector_ids.len() * (sector_size / 4));
    for sid in fat_sector_ids {
        if let Some(sec) = sector_slice(raw, sid, sector_size) {
            for chunk in sec.chunks_exact(4) {
                fat.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
        }
    }

    // 3. 解析 Directory 目录条目
    let dir_bytes = read_fat_chain(raw, &fat, dir_start, sector_size, 4 * 1024 * 1024);
    let mut dir_entries = Vec::new();
    for entry_chunk in dir_bytes.chunks_exact(128) {
        let name_len = (read_u16_le(entry_chunk, 0x40).unwrap_or(0) as usize).min(64);
        let obj_type = entry_chunk[0x42];
        if obj_type == 0 {
            continue;
        }
        let u16_units: Vec<u16> = entry_chunk[..name_len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        let name = String::from_utf16_lossy(&u16_units);
        let start_sector = read_u32_le(entry_chunk, 0x74).unwrap_or(END_OF_CHAIN);
        let stream_size_raw = read_u64_le(entry_chunk, 0x78).unwrap_or(0);
        // v3 OLE2 高 32 位可能包含脏位，如果 sector_size == 512 则掩码取低 32 位
        let stream_size = if sector_size == 512 {
            stream_size_raw & 0xFFFF_FFFF
        } else {
            stream_size_raw
        };
        dir_entries.push(CfbfDirEntry {
            name,
            obj_type,
            start_sector,
            stream_size,
        });
    }

    // 4. 按需构建 MiniFAT 与 RootEntry MiniStream 容器（支持 < 4KB 小流）
    let root_mini_stream = dir_entries
        .iter()
        .find(|e| e.obj_type == 5)
        .map(|root| read_fat_chain(raw, &fat, root.start_sector, sector_size, 8 * 1024 * 1024))
        .unwrap_or_default();

    let mini_fat_bytes = if mini_fat_start != END_OF_CHAIN && mini_fat_start < 0xFFFF_FFF0 {
        read_fat_chain(raw, &fat, mini_fat_start, sector_size, 1024 * 1024)
    } else {
        Vec::new()
    };
    let mini_fat: Vec<u32> = mini_fat_bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();

    // 5. 提取目标正文相关流
    let mut extracted_streams = Vec::new();
    for entry in dir_entries {
        if entry.obj_type != 2 || entry.stream_size == 0 {
            continue;
        }
        let lower_name = entry.name.to_ascii_lowercase();
        let is_target_stream = lower_name.contains("worddocument")
            || lower_name.contains("1table")
            || lower_name.contains("0table")
            || lower_name.contains("workbook")
            || lower_name == "book"
            || lower_name.contains("powerpoint document")
            || lower_name.contains("summaryinformation")
            || lower_name.contains("contents");
        if !is_target_stream {
            continue;
        }

        let target_len = (entry.stream_size as usize).min(16 * 1024 * 1024);
        let bytes = if entry.stream_size < mini_cutoff && !root_mini_stream.is_empty() && !mini_fat.is_empty() {
            read_mini_chain(&root_mini_stream, &mini_fat, entry.start_sector, target_len)
        } else {
            let mut full = read_fat_chain(raw, &fat, entry.start_sector, sector_size, target_len);
            full.truncate(target_len);
            full
        };
        extracted_streams.push((entry.name, bytes));
    }

    Ok(extracted_streams)
}

fn read_mini_chain(mini_stream: &[u8], mini_fat: &[u32], start_sector: u32, max_bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(max_bytes.min(65536));
    let mut curr = start_sector;
    let mut visited = HashSet::new();
    const MINI_SIZE: usize = 64;

    while curr != END_OF_CHAIN && curr != FREE_SECT && curr < 0xFFFF_FFF0 && out.len() < max_bytes {
        if visited.len() >= 131072 || !visited.insert(curr) {
            break;
        }
        let start = (curr as usize) * MINI_SIZE;
        if start >= mini_stream.len() {
            break;
        }
        let end = (start + MINI_SIZE).min(mini_stream.len());
        let remain = max_bytes - out.len();
        out.extend_from_slice(&mini_stream[start..end.min(start + remain)]);
        curr = match mini_fat.get(curr as usize) {
            Some(&n) => n,
            None => break,
        };
    }
    out
}

fn is_meaningful_unicode_char(ch: char) -> bool {
    ('\u{4E00}'..='\u{9FFF}').contains(&ch)
        || ('\u{3000}'..='\u{303F}').contains(&ch) // 〔〕《》等标点
        || ('\u{FF01}'..='\u{FF5E}').contains(&ch)
        || ch == '★'
        || ch == '●'
        || ('0'..='9').contains(&ch)
        || ('A'..='Z').contains(&ch)
        || ('a'..='z').contains(&ch)
        || matches!(ch, ' ' | '-' | '_' | '(' | ')' | '[' | ']' | ':' | '.' | ',' | '/' | '\n' | '\r')
}

/// 从混杂二进制控制符的 OLE 流中提取清晰可读的 UTF-16LE 与 ASCII/GBK 文本段
pub fn extract_ole2_readable_text(stream: &[u8]) -> String {
    let mut collected = String::new();

    // 1. 扫描 UTF-16LE 双字节对齐游程（Word 2000-2003 / Excel SST / PPT 主文本）
    for align in 0..2 {
        let mut run = String::new();
        let slice = &stream[align..];
        for pair in slice.chunks_exact(2) {
            let code = u16::from_le_bytes([pair[0], pair[1]]);
            if let Some(ch) = char::from_u32(code as u32) {
                if is_meaningful_unicode_char(ch) {
                    run.push(ch);
                    continue;
                }
            }
            if run.chars().count() >= 4 {
                collected.push_str(&run);
                collected.push(' ');
            }
            run.clear();
        }
        if run.chars().count() >= 4 {
            collected.push_str(&run);
            collected.push(' ');
        }
    }

    // 2. 补充扫描单字节 ASCII / GBK/UTF-8 解码可识别游程（Word 95 / 兼容元数据流）
    let mut byte_run = Vec::new();
    for &b in stream {
        if b >= 0x80 || (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\r' {
            byte_run.push(b);
        } else {
            if byte_run.len() >= 6 {
                let decoded = decode_console_bytes(&byte_run);
                if decoded.chars().any(|c| ('\u{4E00}'..='\u{9FFF}').contains(&c) || c == '★') {
                    collected.push_str(&decoded);
                    collected.push(' ');
                }
            }
            byte_run.clear();
        }
    }
    if byte_run.len() >= 6 {
        let decoded = decode_console_bytes(&byte_run);
        if decoded.chars().any(|c| ('\u{4E00}'..='\u{9FFF}').contains(&c) || c == '★') {
            collected.push_str(&decoded);
        }
    }

    collected
}

/// 4KB 扇区对齐滑窗扫描流式检测器（用于物理卷空闲扇区 / 镜像未分配区标密残片提取）
/// 时间复杂度: O(N)，空间复杂度: O(1) 恒定 16KB 重叠缓冲区
pub fn scan_raw_stream_with_sliding_window<R: Read>(
    reader: &mut R,
    drive_label: &str,
    max_scan_bytes: u64,
) -> (u64, Vec<SlackSpaceSnippetHit>) {
    const CHUNK_SIZE: usize = 8192;
    const OVERLAP_TAIL: usize = 256;

    let mut total_read = 0u64;
    let mut hits = Vec::new();
    let mut seen_offsets = HashSet::new();
    let mut window: Vec<u8> = Vec::with_capacity(CHUNK_SIZE + OVERLAP_TAIL);
    let mut chunk_buf = [0u8; CHUNK_SIZE];

    while total_read < max_scan_bytes {
        let to_read = ((max_scan_bytes - total_read) as usize).min(CHUNK_SIZE);
        let n = match reader.read(&mut chunk_buf[..to_read]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        let base_offset = total_read.saturating_sub((window.len()) as u64);
        window.extend_from_slice(&chunk_buf[..n]);
        total_read += n as u64;

        let extracted = extract_ole2_readable_text(&window);
        if !extracted.trim().is_empty() {
            let scan = audit_confidentiality::scan_static_text(&extracted);
            if scan.is_secret {
                let first_kw = scan
                    .hit_markers
                    .first()
                    .or_else(|| scan.document_signatures.first())
                    .cloned()
                    .unwrap_or_else(|| scan.highest_level.clone());
                let aligned_sector = (base_offset / 512) * 512;
                if seen_offsets.insert(aligned_sector) {
                    hits.push(SlackSpaceSnippetHit {
                        drive_letter: drive_label.to_string(),
                        sector_offset: aligned_sector,
                        matched_marker: first_kw.clone(),
                        snippet_preview: build_masked_snippet(&extracted, &first_kw),
                    });
                    if hits.len() >= 100 {
                        break; // 防过多冗余重复扇区冲击内存
                    }
                }
            }
        }

        if window.len() > OVERLAP_TAIL {
            let keep_from = window.len() - OVERLAP_TAIL;
            window.drain(..keep_from);
        }
    }

    (total_read, hits)
}

fn collect_ole2_files(root: &Path, out: &mut Vec<PathBuf>, warnings: &mut Vec<String>) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(curr) = stack.pop() {
        if out.len() >= MAX_OLE2_SCAN_FILES {
            warnings.push(format!("OLE2 扫描数量达到单批上限 ({} 份)", MAX_OLE2_SCAN_FILES));
            break;
        }
        if curr.is_file() {
            out.push(curr);
            continue;
        }
        if let Ok(rd) = fs::read_dir(&curr) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                        if name == ".git" || name == "node_modules" || name == "target" {
                            continue;
                        }
                    }
                    stack.push(p);
                } else if p.is_file() {
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
                    if matches!(ext.as_str(), "doc" | "xls" | "ppt" | "wps" | "et" | "dps") {
                        out.push(p);
                        if out.len() >= MAX_OLE2_SCAN_FILES {
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// 执行老旧 OLE2 文档解析及可选原始扇区/磁盘镜像空闲残片检索
pub fn dissect_secrecy_ole2_and_slack(
    target_path: &str,
    raw_slack_target: Option<&str>,
) -> Result<SecrecyDeepContentReport, String> {
    let trimmed = target_path.trim();
    if trimmed.is_empty() && raw_slack_target.map(|s| s.trim().is_empty()).unwrap_or(true) {
        return Err("必须指定待审查 OLE2 目录路径或原始扇区采样路径".to_string());
    }

    let started = Instant::now();
    let mut warnings = Vec::new();
    let mut scanned_ole2_files = 0usize;
    let mut ole2_hits = Vec::new();

    if !trimmed.is_empty() {
        let root = Path::new(trimmed);
        if !root.exists() {
            return Err(format!("目标路径不存在: {}", trimmed));
        }
        let mut files = Vec::new();
        collect_ole2_files(root, &mut files, &mut warnings);

        for path in files {
            let meta = match fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() > MAX_OLE2_FILE_BYTES {
                warnings.push(format!("跳过超大老式文档 (>32MB): {}", path.to_string_lossy()));
                continue;
            }
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if !bytes.starts_with(&OLE2_MAGIC) {
                continue;
            }
            scanned_ole2_files += 1;
            let (sha256_hash, sm3_hash) = compute_dual_hashes(&bytes);

            match parse_cfbf_streams(&bytes) {
                Ok(streams) => {
                    for (sname, sbytes) in streams {
                        let text = extract_ole2_readable_text(&sbytes);
                        if text.trim().is_empty() {
                            continue;
                        }
                        let scan = audit_confidentiality::scan_static_text(&text);
                        if scan.is_secret {
                            let kw = scan
                                .hit_markers
                                .first()
                                .or_else(|| scan.document_signatures.first())
                                .cloned()
                                .unwrap_or_default();
                            ole2_hits.push(Ole2DocumentHit {
                                file_path: path.to_string_lossy().to_string(),
                                sub_stream_name: sname,
                                sha256_hash: sha256_hash.clone(),
                                sm3_hash: sm3_hash.clone(),
                                secrecy_level: scan.highest_level,
                                matched_markers: scan.hit_markers,
                                document_signatures: scan.document_signatures,
                                snippet_preview: build_masked_snippet(&text, &kw),
                            });
                            break;
                        }
                    }
                }
                Err(err) => warnings.push(format!("{} 解析异常: {}", path.to_string_lossy(), err)),
            }
        }
    }

    let mut slack_scanned_bytes = 0u64;
    let mut slack_hits = Vec::new();
    if let Some(raw_target) = raw_slack_target.map(str::trim).filter(|s| !s.is_empty()) {
        // 规范化盘符如 "C:" -> "\\.\C:"
        let normalized_open = if raw_target.len() == 2 && raw_target.ends_with(':') {
            format!("\\\\.\\{}", raw_target)
        } else {
            raw_target.to_string()
        };
        match File::open(&normalized_open) {
            Ok(mut f) => {
                let (read_bytes, hits) =
                    scan_raw_stream_with_sliding_window(&mut f, raw_target, MAX_RAW_SLACK_SCAN_BYTES);
                slack_scanned_bytes = read_bytes;
                slack_hits = hits;
            }
            Err(e) => {
                warnings.push(format!(
                    "无法打开原始驱动器或镜像 [{}] 执行扇区检索 ({}): 如需直接读取裸卷，请以管理员身份运行软件",
                    raw_target, e
                ));
            }
        }
    }

    Ok(SecrecyDeepContentReport {
        target_folder: trimmed.to_string(),
        scanned_ole2_files,
        ole2_hits,
        slack_scanned_bytes,
        slack_hits,
        duration_ms: started.elapsed().as_millis() as u64,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// 构造一个符合微软 MS-CFB (OLE2) v3 标准的真实最小化 .doc 字节序列（含 WordDocument UTF-16LE 正文）
    fn build_synthetic_ole2_doc(body_text: &str) -> Vec<u8> {
        let sector_size = 512usize;
        // 布局：Header(512) + Sector0(FAT) + Sector1(Directory) + Sector2..N(WordDocument 流)
        let utf16_bytes: Vec<u8> = body_text
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        // 为避免触发 MiniStream（>= 4096 字节直接存标准大流）
        let padded_stream_len = utf16_bytes.len().max(4096);
        let stream_sectors = (padded_stream_len + sector_size - 1) / sector_size;
        let total_sectors = 2 + stream_sectors;

        let mut img = vec![0u8; (1 + total_sectors) * sector_size];
        // Header
        img[0..8].copy_from_slice(&OLE2_MAGIC);
        img[0x18..0x1A].copy_from_slice(&0x003Eu16.to_le_bytes());
        img[0x1A..0x1C].copy_from_slice(&0x0003u16.to_le_bytes()); // v3
        img[0x1C..0x1E].copy_from_slice(&0xFFFEu16.to_le_bytes());
        img[0x1E..0x20].copy_from_slice(&9u16.to_le_bytes()); // 512B sector
        img[0x20..0x22].copy_from_slice(&6u16.to_le_bytes());
        img[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // csectFat = 1
        img[0x30..0x34].copy_from_slice(&1u32.to_le_bytes()); // sectDirStart = 1
        img[0x38..0x3C].copy_from_slice(&4096u32.to_le_bytes()); // ulMiniSectorCutoff
        img[0x3C..0x40].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        img[0x44..0x48].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        for i in 0..109 {
            let val = if i == 0 { 0u32 } else { FREE_SECT };
            img[0x4C + i * 4..0x50 + i * 4].copy_from_slice(&val.to_le_bytes());
        }

        // Sector 0: FAT
        let fat_off = sector_size;
        let set_fat = |buf: &mut [u8], idx: usize, val: u32| {
            buf[fat_off + idx * 4..fat_off + idx * 4 + 4].copy_from_slice(&val.to_le_bytes());
        };
        set_fat(&mut img, 0, 0xFFFF_FFFD); // FATSECT
        set_fat(&mut img, 1, END_OF_CHAIN); // Directory
        for s in 0..stream_sectors {
            let sec_id = 2 + s;
            let next = if s + 1 < stream_sectors {
                (sec_id + 1) as u32
            } else {
                END_OF_CHAIN
            };
            set_fat(&mut img, sec_id, next);
        }

        // Sector 1: Directory (Entry 0 = Root Entry, Entry 1 = WordDocument)
        let dir_off = 2 * sector_size;
        let write_dir = |buf: &mut [u8], entry_idx: usize, name: &str, obj_type: u8, start: u32, size: u64| {
            let base = dir_off + entry_idx * 128;
            let mut u16s: Vec<u16> = name.encode_utf16().collect();
            u16s.push(0);
            for (idx, &ch) in u16s.iter().enumerate() {
                buf[base + idx * 2..base + idx * 2 + 2].copy_from_slice(&ch.to_le_bytes());
            }
            let nbytes = (u16s.len() * 2) as u16;
            buf[base + 0x40..base + 0x42].copy_from_slice(&nbytes.to_le_bytes());
            buf[base + 0x42] = obj_type;
            buf[base + 0x74..base + 0x78].copy_from_slice(&start.to_le_bytes());
            buf[base + 0x78..base + 0x80].copy_from_slice(&size.to_le_bytes());
        };
        write_dir(&mut img, 0, "Root Entry", 5, END_OF_CHAIN, 0);
        write_dir(&mut img, 1, "WordDocument", 2, 2, utf16_bytes.len() as u64);

        // Sector 2..N: WordDocument UTF-16LE 正文
        let data_off = 3 * sector_size;
        img[data_off..data_off + utf16_bytes.len()].copy_from_slice(&utf16_bytes);
        img
    }

    #[test]
    fn test_parse_synthetic_ole2_worddocument_and_detect_secrecy_marker() {
        let doc_bytes = build_synthetic_ole2_doc("某内部单位通知：中办发〔2025〕18号，本文定级为 绝密★30年 严禁外传。");
        let streams = parse_cfbf_streams(&doc_bytes).expect("应成功解析合成 CFBF 文档");
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].0, "WordDocument");

        let extracted = extract_ole2_readable_text(&streams[0].1);
        let scan = audit_confidentiality::scan_static_text(&extracted);
        assert!(scan.is_secret);
        assert_eq!(scan.highest_level, "TOP_SECRET");
        assert!(scan.document_signatures.iter().any(|s| s.contains("2025")));
    }

    #[test]
    fn test_sliding_window_raw_slack_across_8kb_chunk_boundary() {
        // 极限边界：把敏感词跨界切在 8192 字节滑窗边界上，验证重叠滑窗能完整衔接不漏报
        let mut raw_img = vec![0u8; 16384];
        let payload = "   本文件为 机密★20年 保密要害文档   ".as_bytes();
        // 放置在 8184.. 处正好跨越 8192 chunk 边界
        let pos = 8180;
        raw_img[pos..pos + payload.len()].copy_from_slice(payload);

        let mut cursor = Cursor::new(raw_img);
        let (scanned, hits) = scan_raw_stream_with_sliding_window(&mut cursor, "TEST_RAW", 1024 * 1024);
        assert_eq!(scanned, 16384);
        assert!(!hits.is_empty(), "跨 8KB 分块边界处的涉密关键词必须被重叠窗口捕获");
    }

    #[test]
    fn test_ole2_malformed_header_and_empty_inputs() {
        // 极限用例 1: 空路径校验报错不 panic
        assert!(dissect_secrecy_ole2_and_slack("   ", None).is_err());

        // 极限用例 2: 非法魔数或构造死循环 FAT 不崩溃
        assert!(parse_cfbf_streams(b"NOT_AN_OLE2_FILE").is_err());
        let mut loop_doc = build_synthetic_ole2_doc("正常内容");
        // 把 sector 2 的下一跳指针改回指向自身形成自环
        let fat_off = 512;
        loop_doc[fat_off + 2 * 4..fat_off + 2 * 4 + 4].copy_from_slice(&2u32.to_le_bytes());
        let res = parse_cfbf_streams(&loop_doc);
        assert!(res.is_ok(), "遇到 FAT 自环应熔断终止而不卡死");
    }
}
