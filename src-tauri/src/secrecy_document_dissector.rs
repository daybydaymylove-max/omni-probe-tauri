//! 复合 Office / WPS / OFD / PDF / ZIP 深度解构与法定涉密标密穿透检索引擎
//! 零新增外部依赖，纯 Rust 实现 PKZIP 中心目录解包 + DEFLATE 流式解压 + PDF FlateDecode 流文本还原
//! 对标标准：GB/T 9704-2012《党政机关公文格式》、GB/T 33190-2016 (OFD)、BMB20-2007
//!
//! 算法复杂度与内存有界控制：
//! - 时间复杂度：O(N + M)，其中 N 为解压还原后的明文总字节数，M 为多模模式集规模；
//! - 空间复杂度：O(B)，严格有界流式缓冲区，单条目限 10MB、单归档限 30MB、嵌套深度限 3 层，彻底免疫 Zip Bomb。

use crate::audit_confidentiality;
use crate::host_baseline::decode_console_bytes;
use flate2::read::{DeflateDecoder, ZlibDecoder};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sm3::Sm3;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

const MAX_SCAN_FILES: usize = 2000;
const MAX_RAW_FILE_BYTES: u64 = 128 * 1024 * 1024; // 单文件最大 128MB 物理上限
const MAX_ENTRY_UNCOMPRESSED_BYTES: usize = 10 * 1024 * 1024; // 单 XML/文本条目最多解压 10MB
const MAX_TOTAL_ARCHIVE_BYTES: usize = 30 * 1024 * 1024; // 单归档累计解压上限 30MB (防 Zip Bomb)
const MAX_ARCHIVE_DEPTH: usize = 3; // 最大嵌套归档层数

static RE_XML_TAG: Lazy<Regex> = Lazy::new(|| Regex::new(r"<[^>]{0,2048}>").unwrap());
static RE_PDF_PAREN_STR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\(([^()\\]{2,512}(?:\\.[^()\\]{0,256})*)\)").unwrap());

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecrecyDocumentHit {
    pub file_path: String,
    pub file_type: String,
    pub file_size_bytes: u64,
    pub sha256_hash: String,
    pub sm3_hash: String,
    pub secrecy_level: String, // "TOP_SECRET" | "CONFIDENTIAL" | "SECRET" | "COMMERCIAL_SECRET" | "ENCRYPTED_FILE" | "ZIP_BOMB_BLOCKED"
    pub matched_markers: Vec<String>,
    pub document_signatures: Vec<String>,
    pub snippet_preview: String,
    pub is_archive_nested: bool,
    pub nested_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecrecyDissectBatchReport {
    pub target_folder: String,
    pub scanned_files_count: usize,
    pub hit_files_count: usize,
    pub encrypted_or_blocked_count: usize,
    pub duration_ms: u64,
    pub top_secret_count: usize,
    pub confidential_count: usize,
    pub secret_count: usize,
    pub hits: Vec<SecrecyDocumentHit>,
    pub warnings: Vec<String>,
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// 剥离 XML 标签与常见实体并还原可读正文文本（带单标签长度上限防御 ReDoS）
pub fn strip_xml_tags(xml: &str) -> String {
    let without_tags = RE_XML_TAG.replace_all(xml, " ");
    let replaced = without_tags
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ");

    let mut collapsed = String::with_capacity(replaced.len().min(65536));
    let mut prev_space = false;
    for ch in replaced.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                collapsed.push(' ');
                prev_space = true;
            }
        } else {
            collapsed.push(ch);
            prev_space = false;
        }
    }
    collapsed.trim().to_string()
}

/// 计算字节缓冲区的真实 SHA-256 与国密 SM3 十六进制摘要
pub fn compute_dual_hashes(data: &[u8]) -> (String, String) {
    let mut sha_hasher = Sha256::new();
    sha_hasher.update(data);
    let sha_hex = hex::encode(sha_hasher.finalize());

    let mut sm3_hasher = Sm3::new();
    sm3_hasher.update(data);
    let sm3_hex = hex::encode(sm3_hasher.finalize());

    (sha_hex, sm3_hex)
}

/// 生成防二次泄密脱敏预览上下文（仅截取首次命中周边短文本并掩码中间部分字符）
pub(crate) fn build_masked_snippet(text: &str, keyword: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let kw_chars: Vec<char> = keyword.chars().collect();
    if chars.is_empty() {
        return String::new();
    }

    let pos = if !kw_chars.is_empty() {
        chars
            .windows(kw_chars.len())
            .position(|w| w == kw_chars.as_slice())
            .unwrap_or(0)
    } else {
        0
    };

    let start = pos.saturating_sub(18);
    let end = (pos + kw_chars.len() + 36).min(chars.len());
    let slice: String = chars[start..end].iter().collect();

    // 针对数字串（如手机号/编号）进行中间掩码，只保留特征及极少上下文
    let mut masked = String::with_capacity(slice.len());
    let mut digit_run = 0usize;
    for ch in slice.chars() {
        if ch.is_ascii_digit() {
            digit_run += 1;
            if digit_run > 4 {
                masked.push('*');
            } else {
                masked.push(ch);
            }
        } else {
            digit_run = 0;
            masked.push(ch);
        }
    }
    format!("...{}...", masked.trim())
}

#[derive(Debug)]
struct ZipEntryMeta {
    name: String,
    method: u16,
    flags: u16,
    compressed_size: usize,
    local_header_offset: usize,
}

/// 解析 PKZIP 中心目录，不依赖文件头压缩尺寸，完美兼容 DOCX / XLSX / PPTX / OFD
fn parse_zip_central_directory(archive: &[u8]) -> Result<Vec<ZipEntryMeta>, String> {
    if archive.len() < 22 {
        return Err("归档文件长度不足".to_string());
    }
    let search_start = archive.len().saturating_sub(65557);
    let mut eocd_off = None;
    for i in (search_start..=archive.len() - 22).rev() {
        if &archive[i..i + 4] == b"PK\x05\x06" {
            eocd_off = Some(i);
            break;
        }
    }
    let eocd = eocd_off.ok_or_else(|| "未检索到 PKZIP 中心目录结束标志".to_string())?;
    let total_entries = read_u16_le(archive, eocd + 10).unwrap_or(0) as usize;
    let cd_offset = read_u32_le(archive, eocd + 16).unwrap_or(0) as usize;

    if cd_offset >= archive.len() {
        return Err("ZIP 中心目录偏移越界".to_string());
    }

    let mut entries = Vec::new();
    let mut cursor = cd_offset;
    for _ in 0..total_entries.min(4096) {
        if cursor + 46 > archive.len() || &archive[cursor..cursor + 4] != b"PK\x01\x02" {
            break;
        }
        let flags = read_u16_le(archive, cursor + 8).unwrap_or(0);
        let method = read_u16_le(archive, cursor + 10).unwrap_or(0);
        let comp_size = read_u32_le(archive, cursor + 20).unwrap_or(0) as usize;
        let name_len = read_u16_le(archive, cursor + 28).unwrap_or(0) as usize;
        let extra_len = read_u16_le(archive, cursor + 30).unwrap_or(0) as usize;
        let comment_len = read_u16_le(archive, cursor + 32).unwrap_or(0) as usize;
        let local_off = read_u32_le(archive, cursor + 42).unwrap_or(0) as usize;

        let name_start = cursor + 46;
        let name_end = name_start.saturating_add(name_len);
        if name_end > archive.len() {
            break;
        }
        let name = String::from_utf8_lossy(&archive[name_start..name_end]).to_string();
        entries.push(ZipEntryMeta {
            name,
            method,
            flags,
            compressed_size: comp_size,
            local_header_offset: local_off,
        });

        cursor = name_end
            .saturating_add(extra_len)
            .saturating_add(comment_len);
    }
    Ok(entries)
}

/// 抽取指定 ZIP 条目的原始数据负载并受限解压（防止 Zip Bomb 内存耗尽）
fn extract_zip_entry_bounded(archive: &[u8], entry: &ZipEntryMeta) -> Result<Vec<u8>, String> {
    if (entry.flags & 0x0001) != 0 {
        return Err("ENCRYPTED_ENTRY".to_string());
    }
    let off = entry.local_header_offset;
    if off + 30 > archive.len() || &archive[off..off + 4] != b"PK\x03\x04" {
        return Err("无效的 ZIP 本地文件头".to_string());
    }
    let fn_len = read_u16_le(archive, off + 26).unwrap_or(0) as usize;
    let ex_len = read_u16_le(archive, off + 28).unwrap_or(0) as usize;
    let data_start = off.saturating_add(30).saturating_add(fn_len).saturating_add(ex_len);
    let data_end = data_start.saturating_add(entry.compressed_size);
    if data_end > archive.len() {
        return Err("ZIP 压缩数据长度越界".to_string());
    }
    let comp_slice = &archive[data_start..data_end];

    let cap_limit = MAX_ENTRY_UNCOMPRESSED_BYTES as u64;
    match entry.method {
        0 => {
            if comp_slice.len() > MAX_ENTRY_UNCOMPRESSED_BYTES {
                return Err("ZIP_BOMB_DETECTED".to_string());
            }
            Ok(comp_slice.to_vec())
        }
        8 => {
            let mut decoder = DeflateDecoder::new(comp_slice).take(cap_limit + 1);
            let mut out = Vec::with_capacity(comp_slice.len().saturating_mul(2).min(1024 * 1024));
            decoder
                .read_to_end(&mut out)
                .map_err(|e| format!("DEFLATE 解压失败: {}", e))?;
            if out.len() > MAX_ENTRY_UNCOMPRESSED_BYTES {
                return Err("ZIP_BOMB_DETECTED".to_string());
            }
            Ok(out)
        }
        other => Err(format!("不支持的 ZIP 压缩方式: {}", other)),
    }
}

fn is_high_value_zip_entry(entry_name: &str) -> bool {
    let lower = entry_name.to_ascii_lowercase();
    if lower.ends_with('/') {
        return false;
    }
    if lower.starts_with("word/") && lower.ends_with(".xml") {
        return true;
    }
    if lower.starts_with("xl/") && (lower.contains("sharedstrings") || lower.contains("worksheets/")) && lower.ends_with(".xml") {
        return true;
    }
    if lower.starts_with("ppt/slides/") && lower.ends_with(".xml") {
        return true;
    }
    if (lower.starts_with("doc_") || lower.contains("pages/")) && lower.ends_with(".xml") {
        return true;
    }
    lower.ends_with(".xml")
        || lower.ends_with(".txt")
        || lower.ends_with(".md")
        || lower.ends_with(".csv")
        || lower.ends_with(".json")
        || lower.ends_with(".log")
        || lower.ends_with(".docx")
        || lower.ends_with(".xlsx")
        || lower.ends_with(".pptx")
        || lower.ends_with(".ofd")
        || lower.ends_with(".pdf")
        || lower.ends_with(".zip")
}

fn classify_zip_format(ext_hint: &str, entries: &[ZipEntryMeta]) -> &'static str {
    let has_word = entries.iter().any(|e| e.name.eq_ignore_ascii_case("word/document.xml"));
    let has_xl = entries.iter().any(|e| e.name.starts_with("xl/"));
    let has_ppt = entries.iter().any(|e| e.name.starts_with("ppt/"));
    let has_ofd = entries.iter().any(|e| e.name.eq_ignore_ascii_case("OFD.xml") || e.name.contains("Pages/"));

    if has_word {
        "DOCX"
    } else if has_xl {
        "XLSX"
    } else if has_ppt {
        "PPTX"
    } else if has_ofd {
        "OFD"
    } else {
        match ext_hint.to_ascii_lowercase().as_str() {
            "docx" | "wps" => "DOCX",
            "xlsx" | "et" => "XLSX",
            "pptx" | "dps" => "PPTX",
            "ofd" => "OFD",
            _ => "ZIP",
        }
    }
}

/// 从 PDF 原始字节提取文本流（支持明文流与 /FlateDecode Zlib 压缩流，识别 /Encrypt 加密保护）
pub fn extract_pdf_text_and_check_encrypted(raw: &[u8]) -> (String, bool) {
    let lossy = String::from_utf8_lossy(raw);
    let is_encrypted = lossy.contains("/Encrypt ");
    let mut extracted = String::new();

    let mut search_pos = 0usize;
    while let Some(rel_start) = raw[search_pos..].windows(6).position(|w| w == b"stream") {
        let kw_pos = search_pos + rel_start;
        let mut content_start = kw_pos + 6;
        if raw.get(content_start) == Some(&b'\r') && raw.get(content_start + 1) == Some(&b'\n') {
            content_start += 2;
        } else if raw.get(content_start) == Some(&b'\n') {
            content_start += 1;
        }
        if let Some(rel_end) = raw[content_start..].windows(9).position(|w| w == b"endstream") {
            let content_end = content_start + rel_end;
            let stream_bytes = &raw[content_start..content_end];

            // 先尝试 Zlib 解压 (/FlateDecode 最常见格式)
            let mut decoded_buf = Vec::new();
            let mut z = ZlibDecoder::new(stream_bytes).take(MAX_ENTRY_UNCOMPRESSED_BYTES as u64);
            let stream_text = if z.read_to_end(&mut decoded_buf).is_ok() && !decoded_buf.is_empty() {
                decode_console_bytes(&decoded_buf)
            } else {
                decode_console_bytes(stream_bytes)
            };

            for cap in RE_PDF_PAREN_STR.captures_iter(&stream_text) {
                if let Some(m) = cap.get(1) {
                    extracted.push_str(m.as_str());
                    extracted.push(' ');
                }
            }
            if extracted.len() > MAX_ENTRY_UNCOMPRESSED_BYTES {
                break;
            }
            search_pos = content_end + 9;
        } else {
            break;
        }
    }

    // 回退直接扫描 PDF 文本块
    if extracted.trim().is_empty() {
        for cap in RE_PDF_PAREN_STR.captures_iter(&lossy) {
            if let Some(m) = cap.get(1) {
                extracted.push_str(m.as_str());
                extracted.push(' ');
            }
        }
    }

    (extracted, is_encrypted)
}

/// 递归解构与穿透扫描单个文件字节缓冲（带深度限制与 Zip Bomb 累积字节限额）
pub fn dissect_document_bytes(
    file_path: &str,
    ext_hint: &str,
    bytes: &[u8],
    top_sha256: &str,
    top_sm3: &str,
    top_size: u64,
    depth: usize,
    nested_prefix: Option<&str>,
) -> Vec<SecrecyDocumentHit> {
    let mut hits = Vec::new();
    if bytes.is_empty() || depth > MAX_ARCHIVE_DEPTH {
        return hits;
    }

    // 1. 识别 PKZIP / OOXML / OFD
    if bytes.starts_with(b"PK\x03\x04") {
        let entries = match parse_zip_central_directory(bytes) {
            Ok(v) => v,
            Err(_) => return hits,
        };
        let fmt_label = classify_zip_format(ext_hint, &entries).to_string();
        let mut cumulative_uncompressed = 0usize;
        let mut combined_text = String::new();

        for entry in &entries {
            if !is_high_value_zip_entry(&entry.name) {
                continue;
            }
            match extract_zip_entry_bounded(bytes, entry) {
                Ok(entry_bytes) => {
                    cumulative_uncompressed = cumulative_uncompressed.saturating_add(entry_bytes.len());
                    if cumulative_uncompressed > MAX_TOTAL_ARCHIVE_BYTES {
                        hits.push(SecrecyDocumentHit {
                            file_path: file_path.to_string(),
                            file_type: fmt_label,
                            file_size_bytes: top_size,
                            sha256_hash: top_sha256.to_string(),
                            sm3_hash: top_sm3.to_string(),
                            secrecy_level: "ZIP_BOMB_BLOCKED".to_string(),
                            matched_markers: vec!["解压展开总量超过 30MB 安全配额".to_string()],
                            document_signatures: vec![],
                            snippet_preview: format!("触发 Zip Bomb 异常解压熔断，停止解压条目 [{}]", entry.name),
                            is_archive_nested: nested_prefix.is_some(),
                            nested_path: nested_prefix.map(|s| s.to_string()),
                        });
                        return hits;
                    }

                    let lower_name = entry.name.to_ascii_lowercase();
                    let child_nested = match nested_prefix {
                        Some(p) => format!("{}/{}", p, entry.name),
                        None => entry.name.clone(),
                    };
                    if lower_name.ends_with(".zip")
                        || lower_name.ends_with(".docx")
                        || lower_name.ends_with(".xlsx")
                        || lower_name.ends_with(".pptx")
                        || lower_name.ends_with(".ofd")
                        || lower_name.ends_with(".pdf")
                    {
                        let child_ext = lower_name.rsplit('.').next().unwrap_or("");
                        let sub_hits = dissect_document_bytes(
                            file_path,
                            child_ext,
                            &entry_bytes,
                            top_sha256,
                            top_sm3,
                            top_size,
                            depth + 1,
                            Some(&child_nested),
                        );
                        hits.extend(sub_hits);
                    } else {
                        let raw_str = decode_console_bytes(&entry_bytes);
                        let clean = if lower_name.ends_with(".xml") || lower_name.ends_with(".html") {
                            strip_xml_tags(&raw_str)
                        } else {
                            raw_str
                        };
                        combined_text.push_str(&clean);
                        combined_text.push('\n');
                    }
                }
                Err(e) if e == "ENCRYPTED_ENTRY" => {
                    hits.push(SecrecyDocumentHit {
                        file_path: file_path.to_string(),
                        file_type: fmt_label.clone(),
                        file_size_bytes: top_size,
                        sha256_hash: top_sha256.to_string(),
                        sm3_hash: top_sm3.to_string(),
                        secrecy_level: "ENCRYPTED_FILE".to_string(),
                        matched_markers: vec!["口令加密保护归档".to_string()],
                        document_signatures: vec![],
                        snippet_preview: format!("文件条目 [{}] 受加密保护，需人工开箱核验", entry.name),
                        is_archive_nested: nested_prefix.is_some(),
                        nested_path: nested_prefix.map(|s| s.to_string()),
                    });
                    return hits;
                }
                Err(e) if e == "ZIP_BOMB_DETECTED" => {
                    hits.push(SecrecyDocumentHit {
                        file_path: file_path.to_string(),
                        file_type: fmt_label.clone(),
                        file_size_bytes: top_size,
                        sha256_hash: top_sha256.to_string(),
                        sm3_hash: top_sm3.to_string(),
                        secrecy_level: "ZIP_BOMB_BLOCKED".to_string(),
                        matched_markers: vec!["单条目膨胀超 10MB 熔断".to_string()],
                        document_signatures: vec![],
                        snippet_preview: format!("拒绝膨胀异常条目 [{}]", entry.name),
                        is_archive_nested: nested_prefix.is_some(),
                        nested_path: nested_prefix.map(|s| s.to_string()),
                    });
                    return hits;
                }
                Err(_) => continue,
            }
        }

        if let Some(hit) = evaluate_text_to_hit(
            &combined_text,
            file_path,
            fmt_label,
            top_size,
            top_sha256,
            top_sm3,
            nested_prefix,
        ) {
            hits.push(hit);
        }
        return hits;
    }

    // 2. 识别 PDF 文档
    if bytes.starts_with(b"%PDF-") {
        let (pdf_text, is_enc) = extract_pdf_text_and_check_encrypted(bytes);
        if is_enc {
            hits.push(SecrecyDocumentHit {
                file_path: file_path.to_string(),
                file_type: "PDF".to_string(),
                file_size_bytes: top_size,
                sha256_hash: top_sha256.to_string(),
                sm3_hash: top_sm3.to_string(),
                secrecy_level: "ENCRYPTED_FILE".to_string(),
                matched_markers: vec!["PDF 加密保护文档".to_string()],
                document_signatures: vec![],
                snippet_preview: "检测到 PDF /Encrypt 加密字典，需人工核查密级".to_string(),
                is_archive_nested: nested_prefix.is_some(),
                nested_path: nested_prefix.map(|s| s.to_string()),
            });
            return hits;
        }
        if let Some(hit) = evaluate_text_to_hit(
            &pdf_text,
            file_path,
            "PDF".to_string(),
            top_size,
            top_sha256,
            top_sm3,
            nested_prefix,
        ) {
            hits.push(hit);
        }
        return hits;
    }

    // 3. 普通文本/XML/公文文本扫描
    let text = decode_console_bytes(bytes);
    let clean = if ext_hint.eq_ignore_ascii_case("xml") || ext_hint.eq_ignore_ascii_case("html") {
        strip_xml_tags(&text)
    } else {
        text
    };
    if let Some(hit) = evaluate_text_to_hit(
        &clean,
        file_path,
        "PLAIN_TEXT".to_string(),
        top_size,
        top_sha256,
        top_sm3,
        nested_prefix,
    ) {
        hits.push(hit);
    }
    hits
}

/// 统一正文文本法定标密词扫描与命中构造，避免重复评估逻辑
fn evaluate_text_to_hit(
    text: &str,
    file_path: &str,
    file_type: String,
    file_size_bytes: u64,
    sha256_hash: &str,
    sm3_hash: &str,
    nested_prefix: Option<&str>,
) -> Option<SecrecyDocumentHit> {
    if text.trim().is_empty() {
        return None;
    }
    let scan = audit_confidentiality::scan_static_text(text);
    if !scan.is_secret {
        return None;
    }
    let snippet_preview = {
        let first_kw = scan
            .hit_markers
            .first()
            .or_else(|| scan.document_signatures.first())
            .map(|s| s.as_str())
            .unwrap_or("");
        build_masked_snippet(text, first_kw)
    };
    Some(SecrecyDocumentHit {
        file_path: file_path.to_string(),
        file_type,
        file_size_bytes,
        sha256_hash: sha256_hash.to_string(),
        sm3_hash: sm3_hash.to_string(),
        secrecy_level: scan.highest_level,
        matched_markers: scan.hit_markers,
        document_signatures: scan.document_signatures,
        snippet_preview,
        is_archive_nested: nested_prefix.is_some(),
        nested_path: nested_prefix.map(|s| s.to_string()),
    })
}

fn is_supported_document_ext(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "docx" | "xlsx" | "pptx" | "ofd" | "wps" | "et" | "dps" | "pdf" | "zip" | "txt" | "md" | "csv" | "json" | "xml" | "html" | "log"
    )
}

fn collect_files_bounded(root: &Path, out: &mut Vec<PathBuf>, warnings: &mut Vec<String>) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(curr) = stack.pop() {
        if out.len() >= MAX_SCAN_FILES {
            warnings.push(format!("已达到单批次最大扫描文件数熔断阈值 ({} 份)", MAX_SCAN_FILES));
            break;
        }
        if curr.is_file() {
            out.push(curr);
            continue;
        }
        if let Ok(read_dir) = fs::read_dir(&curr) {
            for entry in read_dir.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                        if name == ".git" || name == "node_modules" || name == "target" {
                            continue;
                        }
                    }
                    stack.push(p);
                } else if p.is_file() {
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if is_supported_document_ext(ext) {
                        out.push(p);
                        if out.len() >= MAX_SCAN_FILES {
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// 在指定路径（目录或单文件）执行复合文档穿透涉密检索
pub fn dissect_secrecy_documents_in_path(target_path: &str) -> Result<SecrecyDissectBatchReport, String> {
    let trimmed = target_path.trim();
    if trimmed.is_empty() {
        return Err("待审查目录或文件路径不能为空".to_string());
    }
    let root = Path::new(trimmed);
    if !root.exists() {
        return Err(format!("目标路径不存在: {}", trimmed));
    }

    let started = Instant::now();
    let mut files = Vec::new();
    let mut warnings = Vec::new();
    collect_files_bounded(root, &mut files, &mut warnings);

    let mut hits = Vec::new();
    let mut scanned_count = 0usize;

    for file_path in files {
        let meta = match fs::metadata(&file_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.len() > MAX_RAW_FILE_BYTES {
            warnings.push(format!(
                "跳过超大文件 (>128MB): {}",
                file_path.to_string_lossy()
            ));
            continue;
        }
        let mut f = match File::open(&file_path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut buf = Vec::with_capacity((meta.len() as usize).min(1024 * 1024));
        if f.read_to_end(&mut buf).is_err() {
            continue;
        }
        scanned_count += 1;
        let (sha256_hash, sm3_hash) = compute_dual_hashes(&buf);
        let ext = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let path_str = file_path.to_string_lossy().to_string();
        let file_hits = dissect_document_bytes(
            &path_str,
            ext,
            &buf,
            &sha256_hash,
            &sm3_hash,
            meta.len(),
            0,
            None,
        );
        hits.extend(file_hits);
    }

    let mut top_secret_count = 0usize;
    let mut confidential_count = 0usize;
    let mut secret_count = 0usize;
    let mut encrypted_or_blocked_count = 0usize;

    for h in &hits {
        match h.secrecy_level.as_str() {
            "TOP_SECRET" => top_secret_count += 1,
            "CONFIDENTIAL" => confidential_count += 1,
            "SECRET" | "COMMERCIAL_SECRET" | "INTERNAL" => secret_count += 1,
            "ENCRYPTED_FILE" | "ZIP_BOMB_BLOCKED" => encrypted_or_blocked_count += 1,
            _ => {}
        }
    }

    Ok(SecrecyDissectBatchReport {
        target_folder: trimmed.to_string(),
        scanned_files_count: scanned_count,
        hit_files_count: hits.len(),
        encrypted_or_blocked_count,
        duration_ms: started.elapsed().as_millis() as u64,
        top_secret_count,
        confidential_count,
        secret_count,
        hits,
        warnings,
    })
}

#[tauri::command]
pub async fn dissect_secrecy_documents_in_path_cmd(target_path: String) -> Result<SecrecyDissectBatchReport, String> {
    tokio::task::spawn_blocking(move || dissect_secrecy_documents_in_path(&target_path))
        .await
        .map_err(|e| format!("文档穿透解构线程异常: {}", e))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    /// 内存构造真实标准 PKZIP / DOCX / OFD 二进制字节流（采用 Deflate 压缩）
    fn build_synthetic_zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd_entries = Vec::new();

        for (name, raw_data, encrypted) in entries {
            let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
            enc.write_all(raw_data).unwrap();
            let comp = enc.finish().unwrap();

            let local_off = out.len() as u32;
            let name_bytes = name.as_bytes();
            let flags: u16 = if *encrypted { 0x0001 } else { 0x0000 };
            let crc = crc32fast::hash(raw_data);

            // Local File Header
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&8u16.to_le_bytes()); // method 8 (Deflate)
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            out.extend_from_slice(&(raw_data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra len
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&comp);

            // Record Central Directory Header
            let mut cd = Vec::new();
            cd.extend_from_slice(b"PK\x01\x02");
            cd.extend_from_slice(&20u16.to_le_bytes());
            cd.extend_from_slice(&20u16.to_le_bytes());
            cd.extend_from_slice(&flags.to_le_bytes());
            cd.extend_from_slice(&8u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&crc.to_le_bytes());
            cd.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(raw_data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u32.to_le_bytes());
            cd.extend_from_slice(&local_off.to_le_bytes());
            cd.extend_from_slice(name_bytes);
            cd_entries.push(cd);
        }

        let cd_offset = out.len() as u32;
        let mut cd_size = 0u32;
        for cd in &cd_entries {
            cd_size += cd.len() as u32;
            out.extend_from_slice(cd);
        }

        // End of Central Directory (PK\x05\x06)
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn test_dissect_docx_and_ofd_hexagonal_brackets_through_deflate() {
        let xml_body = r#"<?xml version="1.0" encoding="UTF-8"?>
            <w:document><w:body><w:p><w:r><w:t>水利部水保函〔2024〕128号：本工程调度方案定为绝密★30年，知悉范围限于核心审计人员。</w:t></w:r></w:p></w:body></w:document>"#;
        let docx_bytes = build_synthetic_zip(&[("word/document.xml", xml_body.as_bytes(), false)]);
        let (sha, sm3) = compute_dual_hashes(&docx_bytes);

        let hits = dissect_document_bytes("secret_plan.docx", "docx", &docx_bytes, &sha, &sm3, docx_bytes.len() as u64, 0, None);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].file_type, "DOCX");
        assert_eq!(hits[0].secrecy_level, "TOP_SECRET");
        assert!(hits[0].document_signatures.contains(&"水利部水保函〔2024〕128号".to_string()));
        assert!(hits[0].matched_markers.contains(&"绝密★30年".to_string()));
        assert_eq!(hits[0].sha256_hash.len(), 64);
        assert_eq!(hits[0].sm3_hash.len(), 64);
    }

    #[test]
    fn test_dissect_nested_zip_and_encrypted_entry_boundary() {
        let inner_xml = "<ofd:Page><ofd:TextCode>中办发〔2026〕3号 机密★20年</ofd:TextCode></ofd:Page>";
        let inner_ofd = build_synthetic_zip(&[
            ("OFD.xml", b"<ofd:OFD/>", false),
            ("Doc_0/Pages/Page_0/Content.xml", inner_xml.as_bytes(), false),
        ]);
        let outer_zip = build_synthetic_zip(&[("archive/inner.ofd", &inner_ofd, false)]);
        let (sha, sm3) = compute_dual_hashes(&outer_zip);

        let hits = dissect_document_bytes("bundle.zip", "zip", &outer_zip, &sha, &sm3, outer_zip.len() as u64, 0, None);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].file_type, "OFD");
        assert_eq!(hits[0].secrecy_level, "CONFIDENTIAL");
        assert!(hits[0].is_archive_nested);
        assert_eq!(hits[0].nested_path.as_deref(), Some("archive/inner.ofd"));

        // 口令加密文档不崩溃且标识 ENCRYPTED_FILE
        let enc_zip = build_synthetic_zip(&[("word/document.xml", b"dummy", true)]);
        let enc_hits = dissect_document_bytes("locked.docx", "docx", &enc_zip, &sha, &sm3, 100, 0, None);
        assert_eq!(enc_hits.len(), 1);
        assert_eq!(enc_hits[0].secrecy_level, "ENCRYPTED_FILE");
    }

    #[test]
    fn test_dissect_zip_bomb_and_pdf_zlib_stream_edge_cases() {
        // 1. 构造 > 10MB 膨胀测试包（零字节高压缩率测试 Zip Bomb 防御）
        let huge_payload = vec![b'A'; MAX_ENTRY_UNCOMPRESSED_BYTES + 4096];
        let bomb_zip = build_synthetic_zip(&[("word/document.xml", &huge_payload, false)]);
        let (sha, sm3) = compute_dual_hashes(&bomb_zip);
        let bomb_hits = dissect_document_bytes("bomb.docx", "docx", &bomb_zip, &sha, &sm3, bomb_zip.len() as u64, 0, None);
        assert_eq!(bomb_hits.len(), 1);
        assert_eq!(bomb_hits[0].secrecy_level, "ZIP_BOMB_BLOCKED");

        // 2. 构造带 FlateDecode Zlib 压缩流的 PDF
        let mut z_enc = flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
        z_enc.write_all(b"BT (Secret Code: \xe7\xa7\x98\xe5\xaf\x86\xe2\x98\x85" ).unwrap(); // "秘密★"
        z_enc.write_all(b"10\xe5\xb9\xb4) Tj ET").unwrap(); // "10年"
        let z_stream = z_enc.finish().unwrap();

        let mut pdf_bytes = Vec::new();
        pdf_bytes.extend_from_slice(b"%PDF-1.7\n1 0 obj\n<< /Length 99 /Filter /FlateDecode >>\nstream\n");
        pdf_bytes.extend_from_slice(&z_stream);
        pdf_bytes.extend_from_slice(b"\nendstream\nendobj\n%%EOF");
        let pdf_hits = dissect_document_bytes("report.pdf", "pdf", &pdf_bytes, &sha, &sm3, pdf_bytes.len() as u64, 0, None);
        assert_eq!(pdf_hits.len(), 1);
        assert_eq!(pdf_hits[0].file_type, "PDF");
        assert_eq!(pdf_hits[0].secrecy_level, "SECRET");

        // 3. 零字节与非法路径输入防御
        assert!(dissect_document_bytes("empty.txt", "txt", &[], &sha, &sm3, 0, 0, None).is_empty());
        assert!(dissect_secrecy_documents_in_path("").is_err());
    }
}
