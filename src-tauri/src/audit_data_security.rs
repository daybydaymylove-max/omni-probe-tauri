// ============================================================
// 工业全能网络探针 - 数据安全审查与流式文件还原核心引擎
// 模块名称: audit_data_security.rs
//
// 核心职责与工程规范:
// 1. 严格遵循 GB/T 43697-2024 (数据安全技术 数据分类分级规则) 与 GB/T 38668-2020;
// 2. 严苛个人敏感信息 (PII) 三重核验:
//    - 中国居民二代身份证: 正则 + 省级行政区划码 (11-65) + 出生年月日合理性 + ISO 7064:1983.MOD 11-2 校验位;
//    - 银行卡号: BIN 发卡行前缀 (银联 62 / Visa 4 / MC 51-55 / Amex 34,37) + ISO/IEC 7812 Luhn 模10 算法;
//    - 手机号: 工信部最新三大运营商及广电有效号段验证;
// 3. 工业生产级流式文件还原引擎:
//    - 智能剥离 HTTP/1.x 协议报头与 MIME 边界 (\r\n\r\n);
//    - 自动识别 Content-Encoding: gzip 并调用 flate2 执行动态无损解压缩;
//    - 八大文件魔数 (Magic Bytes) 严格特征比对 (PDF / ZIP / DOCX / OLE2 / GZ / 7Z / PNG / JPEG);
//    - 真实全量 SHA-256 完整性哈希计算与有界截断 (最大 10MB 物理配额);
// 4. 等保三级 180 天法定义务: 结构化追加持久化 (data_security_audit.jsonl);
// 5. 时间复杂度 O(N), 空间复杂度 O(K) 有界内存控制.
// ============================================================

use flate2::read::GzDecoder;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SENSITIVE_FINDINGS: usize = 1000;
const MAX_RECONSTRUCTED_FILES: usize = 200;
const MAX_FILE_BODY_BYTES: usize = 10 * 1024 * 1024; // 10MB 物理截断上限，防 OOM

/// 敏感信息检出记录实体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveDataFinding {
    pub id: u64,
    pub timestamp: String,
    pub rule_id: String,
    pub rule_name: String,
    pub category_code: String, // "CORE_DATA" | "IMPORTANT_DATA" | "SENSITIVE_PII" | "GENERAL_DATA"
    pub severity: String,      // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub matched_sample_masked: String, // 已脱敏脱敏后的样本预览
    pub match_count: usize,
    pub context_summary: String,
}

/// 流式还原文件元数据实体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedFileItem {
    pub id: u64,
    pub timestamp: String,
    pub filename: String,
    pub file_extension: String,
    pub mime_type: String,
    pub size_bytes: usize,
    pub sha256_hash: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub classification: String, // "CORE_DATA" | "IMPORTANT_DATA" | "GENERAL_DATA"
    pub is_truncated: bool,
}

/// 数据安全审查综合汇总报告实体
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DataSecuritySummary {
    pub total_scanned_flows: u64,
    pub total_sensitive_hits: u64,
    pub core_data_hits: u64,
    pub important_data_hits: u64,
    pub pii_hits: u64,
    pub general_data_hits: u64,
    pub reconstructed_files_count: usize,
    pub category_distribution: HashMap<String, usize>,
}

struct DataSecurityState {
    findings: VecDeque<SensitiveDataFinding>,
    files: VecDeque<ReconstructedFileItem>,
    summary: DataSecuritySummary,
}

static DATA_SECURITY_STATE: Lazy<Arc<Mutex<DataSecurityState>>> = Lazy::new(|| {
    Arc::new(Mutex::new(DataSecurityState {
        findings: VecDeque::with_capacity(MAX_SENSITIVE_FINDINGS),
        files: VecDeque::with_capacity(MAX_RECONSTRUCTED_FILES),
        summary: DataSecuritySummary::default(),
    }))
});

static FINDING_ID_SEQ: AtomicU64 = AtomicU64::new(5000);
static FILE_ID_SEQ: AtomicU64 = AtomicU64::new(8000);

// ---- 预编译高性能静态正则引擎 ----
static RE_ID_CARD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b([1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9X])\b").unwrap()
});
static RE_MOBILE_PHONE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:\+?86)?(1(?:3\d|4[5-9]|5[0-35-9]|6[2567]|7[0-8]|8\d|9[0-35-9])\d{8})\b").unwrap()
});
static RE_BANK_CARD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(62\d{14,17}|4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b").unwrap()
});
static RE_EMAIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b").unwrap()
});
static RE_PRIVATE_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----\s*BEGIN[ A-Z0-9_-]+PRIVATE KEY\s*-----").unwrap()
});
static RE_API_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(akid[0-9a-zA-Z]{16,32}|LTAI[0-9a-zA-Z]{16,24}|AKIA[0-9A-Z]{16}|bearer\s+[a-zA-Z0-9_\-\.~+/]{20,})\b").unwrap()
});

/// 中国第二代居民身份证严苛多级真实性校验算法
/// 算法复杂度: 时间复杂度 O(1), 空间复杂度 O(1)
/// 校验维度: 1. 长度与字符格式; 2. 省级行政区划码; 3. 出生年月合法区间; 4. ISO 7064 MOD 11-2 校验位
pub fn verify_chinese_id_card_checksum(id: &str) -> bool {
    let clean = id.trim().to_uppercase();
    if clean.len() != 18 {
        return false;
    }

    // 1. 省级代码过滤 (11-65 为合法中国大陆省自治区直辖市代码)
    let province_code: u32 = match clean[0..2].parse() {
        Ok(code) => code,
        Err(_) => return false,
    };
    const VALID_PROVINCES: &[u32] = &[
        11, 12, 13, 14, 15, // 华北
        21, 22, 23,         // 东北
        31, 32, 33, 34, 35, 36, 37, // 华东
        41, 42, 43, 44, 45, 46,     // 中南
        50, 51, 52, 53, 54,         // 西南
        61, 62, 63, 64, 65,         // 西北
    ];
    if !VALID_PROVINCES.contains(&province_code) {
        return false;
    }

    // 2. 出生年月日区间验证 (1900 年至 2026 年)
    let year: u32 = match clean[6..10].parse() {
        Ok(y) => y,
        Err(_) => return false,
    };
    let month: u32 = match clean[10..12].parse() {
        Ok(m) => m,
        Err(_) => return false,
    };
    let day: u32 = match clean[12..14].parse() {
        Ok(d) => d,
        Err(_) => return false,
    };

    if !(1900..=2026).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return false;
    }

    // 3. ISO 7064:1983.MOD 11-2 权重累加校验
    let chars: Vec<char> = clean.chars().collect();
    let weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    let check_map = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];

    let mut sum = 0usize;
    for i in 0..17 {
        if let Some(digit) = chars[i].to_digit(10) {
            sum += (digit as usize) * weights[i];
        } else {
            return false;
        }
    }
    let mod_val = sum % 11;
    chars[17] == check_map[mod_val]
}

/// 银行卡卡号合法性校验 (BIN 发卡行前缀与 ISO/IEC 7812 Luhn 模10 联合校验)
/// 时间复杂度: O(L), 空间复杂度: O(1)
pub fn verify_luhn_checksum(card_number: &str) -> bool {
    let clean: String = card_number.chars().filter(|c| c.is_ascii_digit()).collect();
    if clean.len() < 13 || clean.len() > 19 {
        return false;
    }

    // 检查主流银行卡发卡行识别码 (BIN / IIN)
    let is_unionpay = clean.starts_with("62");
    let is_visa = clean.starts_with('4');
    let is_mastercard = clean.starts_with("51") || clean.starts_with("52") || clean.starts_with("53") || clean.starts_with("54") || clean.starts_with("55");
    let is_amex = clean.starts_with("34") || clean.starts_with("37");

    if !is_unionpay && !is_visa && !is_mastercard && !is_amex {
        return false;
    }

    let mut sum = 0usize;
    let mut alternate = false;

    for c in clean.chars().rev() {
        let mut d = c.to_digit(10).unwrap() as usize;
        if alternate {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alternate = !alternate;
    }
    sum % 10 == 0
}

/// 对文本载荷执行全维度数据安全与分类分级扫描
pub fn inspect_data_security_payload(
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    _protocol: &str,
    payload: &[u8],
) {
    if payload.is_empty() {
        return;
    }
    let text = String::from_utf8_lossy(payload);
    let now_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();

    let mut detected_findings = Vec::new();

    // 1. 中国居民身份证扫描与严格三级校验
    for cap in RE_ID_CARD.captures_iter(&text) {
        if let Some(m) = cap.get(1) {
            let id_str = m.as_str();
            if verify_chinese_id_card_checksum(id_str) {
                let masked = format!("{}********{}", &id_str[..6], &id_str[14..]);
                detected_findings.push((
                    "RULE-ID-CARD",
                    "中国第二代居民身份证",
                    "SENSITIVE_PII",
                    "HIGH",
                    masked,
                    "会话流中检测到符合 GB 11643 与 ISO 7064 标准的真实公民身份证明文",
                ));
            }
        }
    }

    // 2. 银行卡号扫描与 BIN + Luhn 双重校验
    for cap in RE_BANK_CARD.captures_iter(&text) {
        if let Some(m) = cap.get(1) {
            let card_str = m.as_str();
            if verify_luhn_checksum(card_str) {
                let len = card_str.len();
                let masked = format!("{}******{}", &card_str[..6], &card_str[len - 4..]);
                detected_findings.push((
                    "RULE-BANK-CARD",
                    "银行卡/信用卡卡号 (金融数据)",
                    "SENSITIVE_PII",
                    "HIGH",
                    masked,
                    "会话流中检测到通过发卡行 BIN 与 Luhn 模10 校验的有效银行卡号",
                ));
            }
        }
    }

    // 3. 手机号扫描 (工信部实名制号段)
    for cap in RE_MOBILE_PHONE.captures_iter(&text) {
        if let Some(m) = cap.get(1) {
            let phone_str = m.as_str();
            let masked = format!("{}****{}", &phone_str[..3], &phone_str[7..]);
            detected_findings.push((
                "RULE-MOBILE-PHONE",
                "中国大陆移动电话号码",
                "SENSITIVE_PII",
                "MEDIUM",
                masked,
                "检测到 11 位有效入网号段移动电话号码明文外发",
            ));
        }
    }

    // 4. 电子邮箱地址扫描
    for cap in RE_EMAIL.captures_iter(&text) {
        if let Some(m) = cap.get(1) {
            let email_str = m.as_str();
            let masked = if let Some(at_idx) = email_str.find('@') {
                let user_part = &email_str[..at_idx];
                let domain_part = &email_str[at_idx..];
                let prefix = if user_part.len() > 2 { &user_part[..2] } else { user_part };
                format!("{}***{}", prefix, domain_part)
            } else {
                "***@***.com".to_string()
            };
            detected_findings.push((
                "RULE-EMAIL-PII",
                "个人电子邮箱凭证",
                "SENSITIVE_PII",
                "LOW",
                masked,
                "检测到企业或个人电子邮箱地址明文流动",
            ));
        }
    }

    // 5. 非对称私钥明文证书泄露
    if RE_PRIVATE_KEY.is_match(&text) {
        detected_findings.push((
            "RULE-PRIVATE-KEY",
            "非对称加密私钥明文 (RSA/ECC/SM2)",
            "CORE_DATA",
            "CRITICAL",
            "-----BEGIN PRIVATE KEY...[REDACTED]-----".to_string(),
            "严重高危: 检测到明文 PEM 私钥在网络中裸传，可导致核心系统证书被全面破解",
        ));
    }

    // 6. 云访问凭据与 API Key 扫描
    for cap in RE_API_KEY.captures_iter(&text) {
        if let Some(m) = cap.get(1) {
            let token_str = m.as_str();
            let masked = format!("{}***[TOKEN]", &token_str[..token_str.len().min(8)]);
            detected_findings.push((
                "RULE-API-KEY",
                "云基础设施与微服务访问凭据 (API Key / Token)",
                "IMPORTANT_DATA",
                "HIGH",
                masked,
                "检测到系统级云凭据或 Bearer Token 明文流动，存在接口被仿冒越权风险",
            ));
        }
    }

    // 7. 实体密度评估：工业水利核心测站配置与拓扑
    let core_keywords = ["测站遥测参数", "大坝水情阈值", "闸门控制开度", "PLC工程私钥", "调度自动化中心主站"];
    for &kw in &core_keywords {
        if text.contains(kw) {
            detected_findings.push((
                "RULE-INDUSTRIAL-TOPOLOGY",
                "关键基础设施核心业务配置与水情拓扑",
                "CORE_DATA",
                "CRITICAL",
                format!("[KEYWORD] {}", kw),
                "关键基础设施与水利枢纽核心控制业务词汇流动",
            ));
        }
    }

    // 写入内存并落盘
    if !detected_findings.is_empty() {
        let mut state = crate::lock_guard::lock_mutex(
            &DATA_SECURITY_STATE,
            "audit_data_security::inspect_data_security",
        );
        state.summary.total_scanned_flows += 1;
            for (rule_id, rule_name, cat, sev, masked, desc) in detected_findings {
                state.summary.total_sensitive_hits += 1;
                match cat {
                    "CORE_DATA" => state.summary.core_data_hits += 1,
                    "IMPORTANT_DATA" => state.summary.important_data_hits += 1,
                    "SENSITIVE_PII" => state.summary.pii_hits += 1,
                    _ => state.summary.general_data_hits += 1,
                }
                *state.summary.category_distribution.entry(cat.to_string()).or_insert(0) += 1;

                let id = FINDING_ID_SEQ.fetch_add(1, Ordering::Relaxed);
                let finding = SensitiveDataFinding {
                    id,
                    timestamp: now_str.clone(),
                    rule_id: rule_id.to_string(),
                    rule_name: rule_name.to_string(),
                    category_code: cat.to_string(),
                    severity: sev.to_string(),
                    src_ip: src_ip.to_string(),
                    dst_ip: dst_ip.to_string(),
                    src_port,
                    dst_port,
                    matched_sample_masked: masked,
                    match_count: 1,
                    context_summary: desc.to_string(),
                };

                // 等保三级 180 天法定义务：结构化追加持久化
                if let Ok(line) = serde_json::to_string(&finding) {
                    let path = crate::forensics::data_path("data_security_audit.jsonl");
                    use std::io::Write;
                    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                        let _ = writeln!(f, "{}", line);
                    }
                }

                if state.findings.len() >= MAX_SENSITIVE_FINDINGS {
                    state.findings.pop_front();
                }
                state.findings.push_back(finding);
            }
    }
}

/// 工业级流式文件还原引擎: 支持剥离 HTTP 报头、Content-Encoding: gzip 动态解压缩与魔数识别
/// 算法复杂度: 时间复杂度 O(N), 空间复杂度 O(1) (有界内存截断 10MB)
pub fn inspect_and_reconstruct_file(
    src_ip: &str,
    dst_ip: &str,
    protocol: &str,
    payload: &[u8],
) {
    if payload.len() < 32 {
        return;
    }

    let mut body_bytes: &[u8] = payload;
    let mut header_filename: Option<String> = None;
    let mut is_gzip_encoded = false;

    // 1. 探测并解析 HTTP/1.x 请求或响应报头
    if payload.starts_with(b"HTTP/1.") || payload.starts_with(b"POST ") || payload.starts_with(b"GET ") || payload.starts_with(b"PUT ") {
        // 查找 HTTP 报头与 Body 分隔符 \r\n\r\n 或 \n\n
        let header_end = payload.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
            .or_else(|| payload.windows(2).position(|w| w == b"\n\n").map(|p| p + 2));

        if let Some(split_idx) = header_end {
            let header_slice = &payload[..split_idx];
            body_bytes = &payload[split_idx..];

            let header_text = String::from_utf8_lossy(header_slice);
            for line in header_text.lines() {
                let line_lower = line.to_lowercase();
                if line_lower.starts_with("content-encoding:") && line_lower.contains("gzip") {
                    is_gzip_encoded = true;
                }
                if line_lower.starts_with("content-disposition:") {
                    if let Some(f_idx) = line.find("filename=") {
                        let f_val = &line[f_idx + 9..];
                        let clean_name = f_val.trim().trim_matches('"').trim_matches(';').trim();
                        if !clean_name.is_empty() {
                            header_filename = Some(clean_name.to_string());
                        }
                    }
                }
            }
        }
    }

    if body_bytes.is_empty() {
        return;
    }

    // 2. 动态解压缩处理 (如果遇到 Content-Encoding: gzip)
    let decompressed_buf: Vec<u8>;
    let target_body: &[u8] = if is_gzip_encoded {
        let decoder = GzDecoder::new(body_bytes);
        let mut buf = Vec::new();
        // 限制最大解压 10MB，防止 Zip Bomb 炸弹攻击
        match decoder.take(MAX_FILE_BODY_BYTES as u64).read_to_end(&mut buf) {
            Ok(_) if !buf.is_empty() => {
                decompressed_buf = buf;
                &decompressed_buf
            }
            _ => body_bytes,
        }
    } else {
        body_bytes
    };

    // 3. 八大标准文件魔数深度特征判定
    let (detected_ext, mime) = if target_body.starts_with(b"%PDF") {
        ("pdf", "application/pdf")
    } else if target_body.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        ("docx_or_zip", "application/zip")
    } else if target_body.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) {
        ("doc_or_xls", "application/msword")
    } else if target_body.starts_with(&[0x1F, 0x8B, 0x08]) {
        ("gz", "application/gzip")
    } else if target_body.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        ("7z", "application/x-7z-compressed")
    } else if target_body.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        ("png", "image/png")
    } else if target_body.starts_with(&[0xFF, 0xD8, 0xFF]) {
        ("jpg", "image/jpeg")
    } else if target_body.starts_with(b"{\"") || target_body.starts_with(b"[{") {
        ("json", "application/json")
    } else if target_body.starts_with(b"<?xml") {
        ("xml", "application/xml")
    } else {
        return; // 非已知结构化文件，跳过
    };

    // 4. 真实全量 SHA-256 哈希计算与物理有界截断
    let (effective_body, is_truncated) = if target_body.len() > MAX_FILE_BODY_BYTES {
        (&target_body[..MAX_FILE_BODY_BYTES], true)
    } else {
        (target_body, false)
    };

    let mut hasher = Sha256::new();
    hasher.update(effective_body);
    let sha256_hash = format!("{:x}", hasher.finalize());

    let filename = header_filename.unwrap_or_else(|| {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
        format!("recovered_stream_{}.{}", ts, detected_ext)
    });

    let classification = if filename.ends_with(".pdf") || filename.contains("机密") || filename.contains("涉密") || filename.contains("密码") {
        "IMPORTANT_DATA"
    } else {
        "GENERAL_DATA"
    };

    let id = FILE_ID_SEQ.fetch_add(1, Ordering::Relaxed);
    let ts_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let item = ReconstructedFileItem {
        id,
        timestamp: ts_str,
        filename,
        file_extension: detected_ext.to_string(),
        mime_type: mime.to_string(),
        size_bytes: target_body.len(),
        sha256_hash,
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        protocol: protocol.to_string(),
        classification: classification.to_string(),
        is_truncated,
    };

    {
        let mut state = crate::lock_guard::lock_mutex(
            &DATA_SECURITY_STATE,
            "audit_data_security::inspect_and_reconstruct_file",
        );
        if state.files.len() >= MAX_RECONSTRUCTED_FILES {
            state.files.pop_front();
        }
        state.files.push_back(item);
        state.summary.reconstructed_files_count = state.files.len();
    }
}

pub fn get_sensitive_findings(limit: Option<usize>) -> Vec<SensitiveDataFinding> {
    let state = crate::lock_guard::lock_mutex(
        &DATA_SECURITY_STATE,
        "audit_data_security::get_sensitive_findings",
    );
    let lim = limit.unwrap_or(100);
    state.findings.iter().rev().take(lim).cloned().collect()
}

pub fn get_reconstructed_files() -> Vec<ReconstructedFileItem> {
    let state = crate::lock_guard::lock_mutex(
        &DATA_SECURITY_STATE,
        "audit_data_security::get_reconstructed_files",
    );
    state.files.iter().rev().cloned().collect()
}

pub fn get_data_security_summary() -> DataSecuritySummary {
    let state = crate::lock_guard::lock_mutex(
        &DATA_SECURITY_STATE,
        "audit_data_security::get_data_security_summary",
    );
    state.summary.clone()
}

pub fn clear_data_security_records() {
    let mut state = crate::lock_guard::lock_mutex(
        &DATA_SECURITY_STATE,
        "audit_data_security::clear_data_security_records",
    );
    state.findings.clear();
    state.files.clear();
    state.summary = DataSecuritySummary::default();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chinese_id_card_checksum() {
        // 合法北京二代身份证 (110101199003072391)
        assert!(verify_chinese_id_card_checksum("110101199003072391"));
        // 非法校验码
        assert!(!verify_chinese_id_card_checksum("110101199003072392"));
        // 非法省份代码 (99 开头)
        assert!(!verify_chinese_id_card_checksum("990101199003072391"));
        // 非法出生年份 (2099 年)
        assert!(!verify_chinese_id_card_checksum("110101209903072391"));
    }

    #[test]
    fn test_luhn_checksum() {
        // 银联 62 卡号 (符合 Luhn 算法)
        assert!(verify_luhn_checksum("6222021234567890128"));
        // Visa 4 卡号
        assert!(verify_luhn_checksum("4992739871612342"));
        // 非法校验位
        assert!(!verify_luhn_checksum("4992739871612343"));
    }

    #[test]
    fn test_http_pdf_file_reconstruction() {
        clear_data_security_records();
        // 构造带有真实 HTTP/1.1 报头与 Content-Disposition 的 PDF 会话包
        let http_pdf = b"HTTP/1.1 200 OK\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"annual_audit_report.pdf\"\r\n\
Content-Length: 1024\r\n\
\r\n\
%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF";

        inspect_and_reconstruct_file("192.168.1.100", "192.168.1.50", "HTTP", http_pdf);
        let files = get_reconstructed_files();
        assert_eq!(files.len(), 1, "必须成功穿透 HTTP 报头并还原出 PDF 文件");
        assert_eq!(files[0].filename, "annual_audit_report.pdf");
        assert_eq!(files[0].file_extension, "pdf");
        assert_eq!(files[0].mime_type, "application/pdf");
        assert_eq!(files[0].classification, "IMPORTANT_DATA");
        assert!(!files[0].sha256_hash.is_empty());
    }
}
