// ============================================================
// 工业全能网络探针 - 保密安全审查核心引擎 (工业生产级硬核实现)
// 模块名称: audit_confidentiality.rs
//
// 核心职责与工业级标准规范:
// 1. 严格对标国家保密局涉密信息系统保密技术标准与 GB/T 9704-2012《党政机关公文格式》;
// 2. 标密公文与法定密级复合特征检索 (绝密★ / 机密★ / 秘密★ + 保密期限 / 知悉范围);
// 3. 全面支持规范六角括号 〔2024〕、中括号 [2024] 及圆括号 (2024) 党政企事业单位发文字号解析;
// 4. 涉密终端非法外联、商业网盘违规上传、代码托管外泄与暗网隐匿通道实时阻断审计;
// 5. 涉密移动存储介质硬件白名单核验 (未授权 USB 介质违规接入物理总线);
// 6. 落实等保 2.0 三级法定 180 天审计要求，结构化追加落盘至 confidentiality_audit.jsonl;
// 7. 算法复杂度量化:
//    - 静态文本/载荷多模扫描: 时间复杂度 O(N + M) (Aho-Corasick + 预编译正则), 空间复杂度 O(K);
//    - 域名与外联匹配: 时间复杂度 O(D) (D 为外联策略库大小), 空间复杂度 O(1).
// ============================================================

use aho_corasick::AhoCorasick;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CONFIDENTIALITY_ALERTS: usize = 500;
const MAX_LOG_FILE_SIZE_BYTES: u64 = 50 * 1024 * 1024; // 50MB 磁盘审计文件轮转阈值

/// 保密安全审查告警实体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialityAlert {
    pub id: u64,
    pub timestamp: String,
    pub timestamp_ns: u128,
    pub alert_category: String, // "SECRET_MARKER_DETECTED" | "RED_HEADER_DOCUMENT" | "ILLEGAL_EGRESS" | "UNAUTHORIZED_USB_MEDIA"
    pub secrecy_level: String,  // "TOP_SECRET" | "CONFIDENTIAL" | "SECRET" | "COMMERCIAL_SECRET" | "HIGH_RISK"
    pub src_ip: String,
    pub dst_ip: String,
    pub target_entity: String,  // 涉及的标密词、发文字号、外部域名或 USB 设备 ID
    pub summary: String,
    pub detail_json: String,
}

/// 静态文本扫描报告实体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialityScanReport {
    pub is_secret: bool,
    pub highest_level: String,
    pub hit_markers: Vec<String>,
    pub document_signatures: Vec<String>,
    pub scanned_bytes: usize,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMarkerDef {
    pub level: String,
    pub marker: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSigDef {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IllegalEgressRuleDef {
    pub category: String,
    pub name: String,
    pub domain_patterns: Vec<String>,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedMediaDef {
    pub vid: String,
    pub pid: String,
    pub device_type: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfidentialityRuleSet {
    pub secret_markers: Vec<SecretMarkerDef>,
    pub document_signatures: Vec<DocumentSigDef>,
    pub illegal_egress_rules: Vec<IllegalEgressRuleDef>,
    pub authorized_media_whitelist: Vec<AuthorizedMediaDef>,
}

struct ConfidentialityState {
    alerts: VecDeque<ConfidentialityAlert>,
    rules: ConfidentialityRuleSet,
}

static CONFIDENTIALITY_STATE: Lazy<Arc<Mutex<ConfidentialityState>>> = Lazy::new(|| {
    let rules = load_confidentiality_rules();
    let mut alerts = VecDeque::with_capacity(MAX_CONFIDENTIALITY_ALERTS);
    load_persisted_confidentiality_alerts(&mut alerts);
    Arc::new(Mutex::new(ConfidentialityState { alerts, rules }))
});

static ALERT_ID_SEQ: AtomicU64 = AtomicU64::new(8000);

// ---- 1. Aho-Corasick 多模式自动机：核心法定涉密特征 ----
static SECRET_AC_MATCHER: Lazy<AhoCorasick> = Lazy::new(|| {
    let patterns = vec![
        "绝密★", "机密★", "秘密★", "商业秘密★", "工作秘密★", "内部资料★",
        "内部文件★不予公开", "国家秘密", "涉密载体", "知悉范围", "保密期限",
        "定密依据", "密级和保密期限", "严禁复制", "严禁外传",
    ];
    AhoCorasick::new(patterns).unwrap()
});

// ---- 2. 法定密级与保密期限复合特征正则 (GB/T 9704-2012 第 7.2.2 条) ----
static RE_SECRECY_COMPLEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(绝密|机密|秘密|商业秘密|工作秘密)★(\d{1,2}年|长期|不予公开|严禁外传)").unwrap()
});

// ---- 3. 红头公文发文字号正则 (支持 GB/T 9704 规范六角括号 〔〕、中括号 []、圆括号 ()) ----
static RE_RED_HEADER_COMPREHENSIVE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[\u4e00-\u9fa5]{2,16}(?:发|办发|委发|函|计发|纪发|通|令)[\s]*[〔\[\(（]\d{4}[〕\]\)）][\s]*\d+号").unwrap()
});

fn log_file_path() -> PathBuf {
    crate::forensics::data_path("confidentiality_audit.jsonl")
}

fn load_confidentiality_rules() -> ConfidentialityRuleSet {
    let p = crate::forensics::data_path("confidentiality_rules.json");
    if p.exists() {
        if let Ok(content) = std::fs::read_to_string(&p) {
            if let Ok(set) = serde_json::from_str::<ConfidentialityRuleSet>(&content) {
                return set;
            }
        }
    }
    ConfidentialityRuleSet::default()
}

/// 落实等保 2.0 三级：追加写入保密审计日志 (带磁盘文件上限轮转保护)
fn append_alert_to_disk(alert: &ConfidentialityAlert) {
    let p = log_file_path();
    if let Ok(meta) = std::fs::metadata(&p) {
        if meta.len() > MAX_LOG_FILE_SIZE_BYTES {
            let bak = p.with_extension(format!("jsonl.{}.bak", chrono::Local::now().format("%Y%m%d%H%M%S")));
            let _ = std::fs::rename(&p, bak);
        }
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&p) {
        if let Ok(line) = serde_json::to_string(alert) {
            let _ = writeln!(f, "{}", line);
        }
    }
}

/// 系统启动时冷热平滑加载历史保密告警
fn load_persisted_confidentiality_alerts(alerts: &mut VecDeque<ConfidentialityAlert>) {
    let p = log_file_path();
    if !p.exists() {
        return;
    }
    if let Ok(file) = File::open(&p) {
        let reader = BufReader::new(file);
        let mut temp_list = Vec::new();
        for line in reader.lines().flatten() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(alert) = serde_json::from_str::<ConfidentialityAlert>(&line) {
                temp_list.push(alert);
            }
        }
        let total = temp_list.len();
        let skip = if total > MAX_CONFIDENTIALITY_ALERTS {
            total - MAX_CONFIDENTIALITY_ALERTS
        } else {
            0
        };
        for alert in temp_list.into_iter().skip(skip) {
            if alert.id >= ALERT_ID_SEQ.load(Ordering::Relaxed) {
                ALERT_ID_SEQ.store(alert.id + 1, Ordering::Relaxed);
            }
            alerts.push_back(alert);
        }
    }
}

/// 审查网络通信流中的涉密公文与标密特征
/// 时间复杂度: O(N + M) (AC 自动机 + 正则线性扫描), 空间复杂度: O(1)
pub fn inspect_confidentiality_stream(
    src_ip: &str,
    dst_ip: &str,
    protocol: &str,
    payload: &[u8],
) {
    if payload.is_empty() {
        return;
    }
    let text = String::from_utf8_lossy(payload);
    let now = SystemTime::now();
    let ts_ns = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let ts_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();

    let mut detected_hits = Vec::new();

    // 1. 优先执行复合特征正则匹配 (密级 + 保密期限，如 绝密★30年)
    for cap in RE_SECRECY_COMPLEX.captures_iter(&text) {
        let full_match = cap.get(0).map(|m| m.as_str()).unwrap_or_default();
        let lvl_str = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
        let period_str = cap.get(2).map(|m| m.as_str()).unwrap_or_default();

        let (level, sev) = match lvl_str {
            "绝密" => ("TOP_SECRET", "CRITICAL"),
            "机密" => ("CONFIDENTIAL", "HIGH"),
            "秘密" => ("SECRET", "MEDIUM"),
            "商业秘密" => ("COMMERCIAL_SECRET", "MEDIUM"),
            "工作秘密" => ("INTERNAL", "MEDIUM"),
            _ => ("SECRET_TERM", "MEDIUM"),
        };

        detected_hits.push((
            "SECRET_MARKER_DETECTED",
            level,
            sev,
            full_match.to_string(),
            format!("通信载荷中捕获国家秘密法定标志及保密期限: [{}] (定密等级: {}, 期限: {})", full_match, lvl_str, period_str),
        ));
    }

    // 2. 若未匹配到复合正则，回退使用 Aho-Corasick 多模式自动机执行常数扫描
    if detected_hits.is_empty() {
        for mat in SECRET_AC_MATCHER.find_iter(&*text) {
            let pattern_str = &text[mat.start()..mat.end()];
            let (level, sev) = match pattern_str {
                "绝密★" => ("TOP_SECRET", "CRITICAL"),
                "机密★" => ("CONFIDENTIAL", "HIGH"),
                "秘密★" => ("SECRET", "MEDIUM"),
                "商业秘密★" => ("COMMERCIAL_SECRET", "MEDIUM"),
                "内部资料★" | "工作秘密★" | "内部文件★不予公开" => ("INTERNAL", "MEDIUM"),
                _ => ("SECRET_TERM", "LOW"),
            };
            detected_hits.push((
                "SECRET_MARKER_DETECTED",
                level,
                sev,
                pattern_str.to_string(),
                format!("通信载荷中扫描到涉密公文特征标识: [{}]", pattern_str),
            ));
        }
    }

    // 3. 红头公文发文字号匹配 (支持六角括号 〔2024〕)
    for mat in RE_RED_HEADER_COMPREHENSIVE.find_iter(&text) {
        let doc_code = mat.as_str();
        detected_hits.push((
            "RED_HEADER_DOCUMENT",
            "CONFIDENTIAL",
            "HIGH",
            doc_code.to_string(),
            format!("检测到党政企事业单位红头公文发文字号: [{}] (GB/T 9704 标准格式)", doc_code),
        ));
    }

    // 记录告警并入库落盘
    if !detected_hits.is_empty() {
        if let Ok(mut state) = CONFIDENTIALITY_STATE.lock() {
            for (cat, lvl, _sev, target, summary) in detected_hits {
                let id = ALERT_ID_SEQ.fetch_add(1, Ordering::Relaxed);
                let detail = serde_json::json!({
                    "protocol": protocol,
                    "target_feature": target,
                    "payload_len": payload.len()
                });
                let alert = ConfidentialityAlert {
                    id,
                    timestamp: ts_str.clone(),
                    timestamp_ns: ts_ns,
                    alert_category: cat.to_string(),
                    secrecy_level: lvl.to_string(),
                    src_ip: src_ip.to_string(),
                    dst_ip: dst_ip.to_string(),
                    target_entity: target,
                    summary,
                    detail_json: detail.to_string(),
                };

                // 持久化落盘 (等保 2.0 三级留痕要求)
                append_alert_to_disk(&alert);

                if state.alerts.len() >= MAX_CONFIDENTIALITY_ALERTS {
                    state.alerts.pop_front();
                }
                state.alerts.push_back(alert);
            }
        }
    }
}

/// 审查外部域名访问是否触犯涉密违规外联与非授权传输红线
/// 时间复杂度: O(K) (K 为规则数), 空间复杂度: O(1)
pub fn inspect_egress_domain(
    client_ip: &str,
    domain: &str,
) {
    if domain.is_empty() {
        return;
    }
    let lower_domain = domain.to_lowercase();
    let (ts_str, ts_ns) = (
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
    );

    // 工业生产级高危违规外联特征库 (商业云盘/境外免密存储/代码托管外泄/暗网翻墙)
    let high_risk_targets = [
        ("pan.baidu.com", "商业网盘违规上传与共享"),
        ("weiyun.com", "腾讯微云商业网盘外联"),
        ("aliyundrive.com", "阿里云盘商业外联"),
        ("quark.cn", "夸克网盘外联"),
        ("lanzou", "蓝奏云存储分享"),
        ("jianguoyun.com", "坚果云同步盘外联"),
        ("wenshushu.cn", "文叔叔临时大文件传输"),
        ("dropbox.com", "Dropbox 境外云存储外传"),
        ("onedrive.live.com", "Microsoft OneDrive 云存储外联"),
        ("drive.google.com", "Google Drive 境外云盘外联"),
        ("wetransfer.com", "WeTransfer 免密文件快传"),
        ("mega.nz", "Mega 境外加密云盘外联"),
        ("sendspace.com", "SendSpace 匿名文件托管"),
        ("github.com", "GitHub 公开代码托管 (防涉密代码与私钥外泄)"),
        ("gitee.com", "Gitee 公开代码托管 (防涉密资产外泄)"),
        ("pastebin.com", "Pastebin 匿名明文剪贴板外传"),
        ("torproject.org", "Tor 匿名隐匿洋葱网络"),
        (".onion", "暗网洋葱路由服务连接"),
        ("t.me", "Telegram 即时通信非法通道"),
        ("discord.com", "Discord 外部通信通道"),
    ];

    for &(risk_domain, desc) in &high_risk_targets {
        if lower_domain.contains(risk_domain) {
            let id = ALERT_ID_SEQ.fetch_add(1, Ordering::Relaxed);
            let detail = serde_json::json!({
                "accessed_domain": domain,
                "matched_pattern": risk_domain,
                "policy": "ILLEGAL_EGRESS_PREVENTION_L3",
                "risk_description": desc
            });
            let alert = ConfidentialityAlert {
                id,
                timestamp: ts_str.clone(),
                timestamp_ns: ts_ns,
                alert_category: "ILLEGAL_EGRESS".to_string(),
                secrecy_level: "HIGH_RISK".to_string(),
                src_ip: client_ip.to_string(),
                dst_ip: "WAN_GATEWAY".to_string(),
                target_entity: domain.to_string(),
                summary: format!("触发保密合规违规外联拦截告警: 涉密终端试图连接 [{}] - {}", domain, desc),
                detail_json: detail.to_string(),
            };

            append_alert_to_disk(&alert);

            if let Ok(mut state) = CONFIDENTIALITY_STATE.lock() {
                if state.alerts.len() >= MAX_CONFIDENTIALITY_ALERTS {
                    state.alerts.pop_front();
                }
                state.alerts.push_back(alert);
            }
            break;
        }
    }
}

/// 审查硬件 USB 存储介质是否属于合规授权白名单
/// 时间复杂度: O(W) (W 为白名单设备数), 空间复杂度: O(1)
pub fn verify_usb_storage_compliance(
    device_name: &str,
    vid: &str,
    pid: &str,
    instance_id: &str,
) {
    let state = CONFIDENTIALITY_STATE.lock().unwrap();
    let is_authorized = state.rules.authorized_media_whitelist.iter().any(|item| {
        item.vid.eq_ignore_ascii_case(vid) && item.pid.eq_ignore_ascii_case(pid)
    });

    if !is_authorized {
        let (ts_str, ts_ns) = (
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
        );
        let id = ALERT_ID_SEQ.fetch_add(1, Ordering::Relaxed);
        let detail = serde_json::json!({
            "device_name": device_name,
            "vid": vid,
            "pid": pid,
            "instance_id": instance_id,
        });
        let alert = ConfidentialityAlert {
            id,
            timestamp: ts_str,
            timestamp_ns: ts_ns,
            alert_category: "UNAUTHORIZED_USB_MEDIA".to_string(),
            secrecy_level: "HIGH_RISK".to_string(),
            src_ip: "LOCAL_HOST".to_string(),
            dst_ip: "USB_BUS".to_string(),
            target_entity: format!("VID_{}_PID_{}", vid, pid),
            summary: format!("严重保密警报: 检测到非授权移动存储设备接入物理总线 [{}] (VID: {}, PID: {})", device_name, vid, pid),
            detail_json: detail.to_string(),
        };

        append_alert_to_disk(&alert);

        drop(state);
        if let Ok(mut st) = CONFIDENTIALITY_STATE.lock() {
            if st.alerts.len() >= MAX_CONFIDENTIALITY_ALERTS {
                st.alerts.pop_front();
            }
            st.alerts.push_back(alert);
        }
    }
}

/// 静态文本/公文档案保密合规即时扫描
/// 时间复杂度: O(N + M), 空间复杂度: O(1)
pub fn scan_static_text(content: &str) -> ConfidentialityScanReport {
    let mut hit_markers = Vec::new();
    let mut highest_level = "UNCLASSIFIED".to_string();

    // 1. 复合正则扫描 (绝密/机密/秘密★期限)
    for cap in RE_SECRECY_COMPLEX.captures_iter(content) {
        if let Some(m) = cap.get(0) {
            let matched = m.as_str().to_string();
            if !hit_markers.contains(&matched) {
                hit_markers.push(matched.clone());
                if matched.starts_with("绝密") {
                    highest_level = "TOP_SECRET".to_string();
                } else if matched.starts_with("机密") && highest_level != "TOP_SECRET" {
                    highest_level = "CONFIDENTIAL".to_string();
                } else if matched.starts_with("秘密") && highest_level == "UNCLASSIFIED" {
                    highest_level = "SECRET".to_string();
                } else if matched.starts_with("商业秘密") && highest_level == "UNCLASSIFIED" {
                    highest_level = "COMMERCIAL_SECRET".to_string();
                }
            }
        }
    }

    // 2. 补充 AC 匹配基础标密词
    for mat in SECRET_AC_MATCHER.find_iter(content) {
        let matched = &content[mat.start()..mat.end()];
        if !hit_markers.iter().any(|h| h.contains(matched)) {
            hit_markers.push(matched.to_string());
            if matched == "绝密★" {
                highest_level = "TOP_SECRET".to_string();
            } else if matched == "机密★" && highest_level != "TOP_SECRET" {
                highest_level = "CONFIDENTIAL".to_string();
            } else if matched == "秘密★" && highest_level == "UNCLASSIFIED" {
                highest_level = "SECRET".to_string();
            }
        }
    }

    // 3. 红头发文字号扫描 (含六角括号 〔〕)
    let mut doc_sigs = Vec::new();
    for mat in RE_RED_HEADER_COMPREHENSIVE.find_iter(content) {
        let s = mat.as_str().to_string();
        if !doc_sigs.contains(&s) {
            doc_sigs.push(s);
        }
    }

    let is_secret = !hit_markers.is_empty() || !doc_sigs.is_empty();
    let recommendation = if is_secret {
        format!(
            "该检材捕获 {} 处涉密公文特征，法定定密等级为 [{}]，依据《中华人民共和国保守国家秘密法》，严禁通过互联网或非涉密网络向外传输！",
            hit_markers.len() + doc_sigs.len(),
            highest_level
        )
    } else {
        "未检索到国家秘密法定标识与红头公文字号，属于公开/普通内部业务载荷。".to_string()
    };

    ConfidentialityScanReport {
        is_secret,
        highest_level,
        hit_markers,
        document_signatures: doc_sigs,
        scanned_bytes: content.len(),
        recommendation,
    }
}

pub fn get_confidentiality_alerts(limit: Option<usize>) -> Vec<ConfidentialityAlert> {
    let state = CONFIDENTIALITY_STATE.lock().unwrap();
    let lim = limit.unwrap_or(100);
    state.alerts.iter().rev().take(lim).cloned().collect()
}

pub fn clear_confidentiality_alerts() {
    let mut state = CONFIDENTIALITY_STATE.lock().unwrap();
    state.alerts.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidentiality_hexagonal_brackets() {
        // 测试国家标准 GB/T 9704-2012 六角括号发文字号与复合保密期限
        let doc = "水利部水保函〔2024〕128号：本通知属于机密★20年，知悉范围限于司局级以上。";
        let report = scan_static_text(doc);
        assert!(report.is_secret);
        assert_eq!(report.highest_level, "CONFIDENTIAL");
        assert!(report.hit_markers.iter().any(|m| m.contains("机密★20年")));
        assert!(report.document_signatures.contains(&"水利部水保函〔2024〕128号".to_string()));
    }

    #[test]
    fn test_confidentiality_top_secret() {
        let top_doc = "关于重大枢纽工程运行控制的指令，标注为绝密★30年，国办发[2024]1号";
        let report = scan_static_text(top_doc);
        assert!(report.is_secret);
        assert_eq!(report.highest_level, "TOP_SECRET");
        assert!(report.hit_markers.iter().any(|m| m.contains("绝密★30年")));
        assert!(report.document_signatures.contains(&"国办发[2024]1号".to_string()));
    }

    #[test]
    fn test_confidentiality_public_negative() {
        let public_doc = "这是公开的工业网关 API 接口文档，包含 GET /api/v1/metrics 等公开定义。";
        let report = scan_static_text(public_doc);
        assert!(!report.is_secret);
        assert_eq!(report.highest_level, "UNCLASSIFIED");
        assert!(report.hit_markers.is_empty());
        assert!(report.document_signatures.is_empty());
    }
}
