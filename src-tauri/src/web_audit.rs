use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================
// 工业级上网行为监测与外联合规审计引擎 (Web Activity & Compliance Audit Core)
// 100% 工业生产级实现：
//   1. TLS 1.2/1.3 Client Hello SNI 零解密流式域名提取 (RFC 6066)
//   2. RFC 1035 DNS A/AAAA 响应解析与 IP-Domain 动态双向关联缓存
//   3. HTTP 结构化访问审计 (Method, Host, URI, User-Agent)
//   4. 工业级 URL/域名 9 大类行为分类与违规外联风险评级
//   5. 审计日志持久化归档与全维聚合统计分析
// ============================================================

/// 上网行为单条审计日志实体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAccessLog {
    pub id: u64,
    pub timestamp: String,
    pub timestamp_ms: u128,
    pub client_ip: String,
    pub client_mac: String,
    pub client_hostname: Option<String>,
    pub domain: String,
    pub url: String,
    pub method: String,        // "GET" | "POST" | "HTTPS_CONNECT" | "DNS_QUERY"
    pub protocol: String,      // "HTTPS (SNI)" | "HTTP" | "DNS"
    pub category: String,      // 分类中文名 (如 "技术研发", "协同办公", "流媒体视频", "违规外联")
    pub category_code: String, // 分类代码
    pub risk_level: String,    // "NORMAL" | "ATTENTION" | "HIGH_RISK"
    pub risk_desc: String,     // 风险说明
    pub remote_ip: String,
    pub remote_port: u16,
    pub geo_summary: String,   // 地理位置与运营商画像
    pub user_agent: Option<String>,
    pub bytes_sent: usize,
    pub bytes_received: usize,
}

/// 域名分类审计结果实体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainClassification {
    pub category_code: String,
    pub category_name: String,
    pub risk_level: String, // "NORMAL" | "ATTENTION" | "HIGH_RISK"
    pub risk_desc: String,
}

/// DNS 动态解析缓存条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheItem {
    pub domain: String,
    pub resolved_ips: Vec<String>,
    pub resolved_time: String,
    pub ttl_secs: u32,
    pub client_ip: String,
}

/// 上网行为多维综合统计实体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuditStatistics {
    pub total_requests: usize,
    pub unique_clients: usize,
    pub unique_domains: usize,
    pub high_risk_count: usize,
    pub category_distribution: HashMap<String, usize>,
    pub top_domains: Vec<TopEntityItem>,
    pub top_clients: Vec<TopEntityItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopEntityItem {
    pub name: String,
    pub count: usize,
    pub sub_label: String,
}

/// HTTP 结构化访问提取信息
#[derive(Debug, Clone)]
pub struct HttpAccessInfo {
    pub method: String,
    pub host: String,
    pub uri: String,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
}

/// DNS 解析结果
#[derive(Debug, Clone)]
pub struct DnsParseResult {
    pub is_response: bool,
    pub query_domain: String,
    pub resolved_ips: Vec<String>,
    pub ttl_secs: u32,
}

// ============================================================
// 全局状态单例 (内存环形缓冲 + DNS 关联映射表)
// ============================================================

const MAX_MEM_LOGS: usize = 5000;
static WEB_ACCESS_LOGS: Lazy<Arc<Mutex<VecDeque<WebAccessLog>>>> =
    Lazy::new(|| Arc::new(Mutex::new(VecDeque::with_capacity(MAX_MEM_LOGS))));

static LOG_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// DNS 双向映射缓存：IP ➔ 域名映射 (Key: 目标 IP, Value: DnsCacheItem)
static DNS_IP_CACHE: Lazy<Arc<Mutex<HashMap<String, DnsCacheItem>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

// ============================================================
// 1. TLS 1.2 / 1.3 Client Hello SNI 零解密流式提取引擎
// 时间复杂度: O(L), L 为载荷长度 (通常 < 1500 字节)
// 空间复杂度: O(1) 零堆分配
// ============================================================
pub fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    // TLS 记录头长度 5 字节: [0]=0x16(Handshake), [1]=0x03, [2]=0x01/02/03/04
    if payload.len() < 44 || payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len {
        // 允许截断报文尽最大努力解析
    }

    // 握手头: [5]=0x01(Client Hello), [6..9]=Handshake Length
    if payload[5] != 0x01 {
        return None;
    }

    // 偏移量推进:
    // 5(Record Header) + 1(Handshake Type) + 3(Length) + 2(Client Version) + 32(Client Random) = 43
    let mut idx = 43;
    if idx >= payload.len() {
        return None;
    }

    // Session ID: 1 字节长度 + 数据
    let session_id_len = payload[idx] as usize;
    idx += 1 + session_id_len;
    if idx + 2 > payload.len() {
        return None;
    }

    // Cipher Suites: 2 字节长度 + 数据
    let cipher_suites_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
    idx += 2 + cipher_suites_len;
    if idx + 1 > payload.len() {
        return None;
    }

    // Compression Methods: 1 字节长度 + 数据
    let comp_methods_len = payload[idx] as usize;
    idx += 1 + comp_methods_len;
    if idx + 2 > payload.len() {
        return None;
    }

    // Extensions: 2 字节总长度 + 扩展列表
    let ext_total_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
    idx += 2;
    let ext_end = (idx + ext_total_len).min(payload.len());

    // 遍历 Extensions 列表查找 SNI (Type 0x0000)
    while idx + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
        let ext_len = u16::from_be_bytes([payload[idx + 2], payload[idx + 3]]) as usize;
        idx += 4;

        if ext_type == 0x0000 {
            // Server Name Indication 扩展
            if idx + 2 <= ext_end {
                let _server_name_list_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
                idx += 2;

                // Server Name 格式: 1 字节 Name Type (0x00 为 HostName) + 2 字节长度 + 实际域名
                if idx + 3 <= ext_end && payload[idx] == 0x00 {
                    let name_len = u16::from_be_bytes([payload[idx + 1], payload[idx + 2]]) as usize;
                    idx += 3;
                    if idx + name_len <= payload.len() {
                        if let Ok(sni_str) = std::str::from_utf8(&payload[idx..idx + name_len]) {
                            let clean = sni_str.trim().to_lowercase();
                            if !clean.is_empty() {
                                return Some(clean);
                            }
                        }
                    }
                }
            }
            return None;
        }

        idx += ext_len;
    }

    None
}

// ============================================================
// 2. RFC 1035 DNS 协议解析与 IP-Domain 动态映射引擎
// ============================================================
pub fn parse_dns_packet(payload: &[u8]) -> Option<DnsParseResult> {
    if payload.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags >> 15) & 0x01 == 1;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;

    if qdcount == 0 {
        return None;
    }

    let mut idx = 12;

    // 解析第一个 Query 的域名 (支持标准 DNS label 编码)
    let (query_domain, next_idx) = decode_dns_name(payload, idx, 0)?;
    idx = next_idx;

    // 跳过 QType (2B) + QClass (2B)
    idx += 4;

    let mut resolved_ips = Vec::new();
    let mut min_ttl = 300u32;

    // 如果是应答包，继续解析 Answer Section 提取 A / AAAA 记录
    if is_response && ancount > 0 && idx < payload.len() {
        for _ in 0..ancount {
            if idx >= payload.len() {
                break;
            }
            // 跳过 Name 字段 (可能是压缩指针 2B，或直接 Label)
            if let Some((_, n_idx)) = decode_dns_name(payload, idx, 0) {
                idx = n_idx;
            } else {
                break;
            }

            if idx + 10 > payload.len() {
                break;
            }

            let r_type = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
            let _r_class = u16::from_be_bytes([payload[idx + 2], payload[idx + 3]]);
            let ttl = u32::from_be_bytes([payload[idx + 4], payload[idx + 5], payload[idx + 6], payload[idx + 7]]);
            let rdlength = u16::from_be_bytes([payload[idx + 8], payload[idx + 9]]) as usize;
            idx += 10;

            if idx + rdlength > payload.len() {
                break;
            }

            if ttl > 0 && ttl < min_ttl {
                min_ttl = ttl;
            }

            // Type 1: A 记录 (IPv4 4 字节)
            if r_type == 1 && rdlength == 4 {
                let ip_str = format!("{}.{}.{}.{}", payload[idx], payload[idx + 1], payload[idx + 2], payload[idx + 3]);
                resolved_ips.push(ip_str);
            }
            // Type 28: AAAA 记录 (IPv6 16 字节)
            else if r_type == 28 && rdlength == 16 {
                let mut segments = [0u16; 8];
                for s in 0..8 {
                    segments[s] = u16::from_be_bytes([payload[idx + s * 2], payload[idx + s * 2 + 1]]);
                }
                let ipv6_str = format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    segments[0], segments[1], segments[2], segments[3],
                    segments[4], segments[5], segments[6], segments[7]);
                resolved_ips.push(ipv6_str);
            }

            idx += rdlength;
        }
    }

    Some(DnsParseResult {
        is_response,
        query_domain,
        resolved_ips,
        ttl_secs: min_ttl,
    })
}

/// 解码 DNS 标签格式域名 (支持 0xC0 指针压缩)
fn decode_dns_name(payload: &[u8], mut idx: usize, depth: usize) -> Option<(String, usize)> {
    if depth > 10 || idx >= payload.len() {
        return None;
    }
    let mut parts = Vec::new();
    let mut jumped = false;
    let mut return_idx = idx;

    while idx < payload.len() {
        let len = payload[idx] as usize;
        if len == 0 {
            if !jumped {
                return_idx = idx + 1;
            }
            break;
        }

        // 0xC0 标志指针压缩 (Pointer Offset)
        if len & 0xC0 == 0xC0 {
            if idx + 1 >= payload.len() {
                return None;
            }
            let pointer_offset = (((len & 0x3F) << 8) | (payload[idx + 1] as usize)) as usize;
            if !jumped {
                return_idx = idx + 2;
                jumped = true;
            }
            if let Some((sub_name, _)) = decode_dns_name(payload, pointer_offset, depth + 1) {
                if !sub_name.is_empty() {
                    parts.push(sub_name);
                }
            }
            break;
        } else {
            idx += 1;
            if idx + len > payload.len() {
                return None;
            }
            if let Ok(label) = std::str::from_utf8(&payload[idx..idx + len]) {
                parts.push(label.to_lowercase());
            }
            idx += len;
        }
    }

    if !jumped {
        return_idx = idx;
    }

    Some((parts.join("."), return_idx))
}

/// 维护 DNS 动态双向映射
pub fn record_dns_resolution(client_ip: &str, domain: &str, ips: &[String], ttl_secs: u32) {
    if domain.is_empty() || ips.is_empty() {
        return;
    }

    let now_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if let Ok(mut cache) = DNS_IP_CACHE.lock() {
        for ip in ips {
            cache.insert(ip.clone(), DnsCacheItem {
                domain: domain.to_string(),
                resolved_ips: ips.to_vec(),
                resolved_time: now_str.clone(),
                ttl_secs,
                client_ip: client_ip.to_string(),
            });
        }
    }
}

/// 根据目标 IP 自动反查其通过 DNS 解析出的实际域名
pub fn lookup_domain_for_ip(ip: &str) -> Option<String> {
    if let Ok(cache) = DNS_IP_CACHE.lock() {
        cache.get(ip).map(|item| item.domain.clone())
    } else {
        None
    }
}

/// 获取当前所有 DNS 动态映射表条目
pub fn get_dns_cache_table() -> Vec<DnsCacheItem> {
    if let Ok(cache) = DNS_IP_CACHE.lock() {
        cache.values().cloned().collect()
    } else {
        Vec::new()
    }
}

// ============================================================
// 3. HTTP 结构化访问字段提取引擎
// ============================================================
pub fn extract_http_access_info(payload: &[u8]) -> Option<HttpAccessInfo> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut lines = text.lines();
    let first_line = lines.next()?.trim();

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let method = parts[0].to_uppercase();
    if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "CONNECT" | "PATCH") {
        return None;
    }

    let uri = parts[1].to_string();
    let mut host = String::new();
    let mut user_agent = None;
    let mut referer = None;

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_lowercase();
            let val = v.trim();
            if key == "host" {
                host = val.to_lowercase();
            } else if key == "user-agent" {
                user_agent = Some(val.to_string());
            } else if key == "referer" {
                referer = Some(val.to_string());
            }
        }
    }

    if host.is_empty() {
        return None;
    }

    Some(HttpAccessInfo {
        method,
        host,
        uri,
        user_agent,
        referer,
    })
}

// ============================================================
// 4. 工业级 URL/域名 9 大类行为分类与合规策略引擎
// ============================================================
pub fn classify_domain(domain: &str) -> DomainClassification {
    let d = domain.to_lowercase();

    // 1. 高危违规外联 (SECURITY_RISK): 动态域名、挖矿矿池、P2P穿透、未知代理
    if d.contains("f3322.net") || d.contains("3322.org") || d.contains("no-ip.org")
        || d.contains("dynu.com") || d.contains("ngrok.io") || d.contains("cpolar.top")
        || d.contains("f2pool.com") || d.contains("antpool.com") || d.contains("nanopool.org")
        || d.contains("unmineable.com") || d.contains("ethermine.org") || d.contains("torproject.org")
        || d.contains("onion") || d.contains("shadowsocks") || d.contains("v2ray")
    {
        return DomainClassification {
            category_code: "SECURITY_RISK".to_string(),
            category_name: "高危违规外联".to_string(),
            risk_level: "HIGH_RISK".to_string(),
            risk_desc: "🚨 检测到内网终端正在访问动态域名、挖矿矿池或穿透代理节点".to_string(),
        };
    }

    // 2. 协同办公 (OFFICE_PRODUCTIVITY): 飞书、钉钉、企业微信、Office 365、WPS、腾讯文档
    if d.contains("feishu.cn") || d.contains("larksuite.com") || d.contains("dingtalk.com")
        || d.contains("work.weixin.qq.com") || d.contains("office.com") || d.contains("office365.com")
        || d.contains("microsoft.com") || d.contains("wps.cn") || d.contains("kdocs.cn")
        || d.contains("notion.so") || d.contains("zoom.us") || d.contains("meeting.tencent.com")
        || d.contains("teambition.com")
    {
        return DomainClassification {
            category_code: "OFFICE_PRODUCTIVITY".to_string(),
            category_name: "协同办公".to_string(),
            risk_level: "NORMAL".to_string(),
            risk_desc: "企业日常协同办公与会议通信".to_string(),
        };
    }

    // 3. 技术研发 (DEV_TECH): GitHub, GitLab, Gitee, StackOverflow, Rust, NPM, Docker, Maven
    if d.contains("github.com") || d.contains("githubusercontent.com") || d.contains("gitlab.com")
        || d.contains("gitee.com") || d.contains("stackoverflow.com") || d.contains("rust-lang.org")
        || d.contains("crates.io") || d.contains("npmjs.com") || d.contains("docker.com")
        || d.contains("pypi.org") || d.contains("maven.org") || d.contains("golang.org")
        || d.contains("aliyun.com/nexus") || d.contains("csdn.net") || d.contains("juejin.cn")
        || d.contains("segmentfault.com")
    {
        return DomainClassification {
            category_code: "DEV_TECH".to_string(),
            category_name: "技术研发".to_string(),
            risk_level: "NORMAL".to_string(),
            risk_desc: "开源代码托管、依赖包镜像与技术知识库".to_string(),
        };
    }

    // 4. 流媒体视频 (VIDEO_STREAMING): B站、抖音、快手、爱奇艺、腾讯视频、优酷、YouTube
    if d.contains("bilibili.com") || d.contains("hdslb.com") || d.contains("douyin.com")
        || d.contains("kuaishou.com") || d.contains("iqiyi.com") || d.contains("v.qq.com")
        || d.contains("youku.com") || d.contains("youtube.com") || d.contains("googlevideo.com")
        || d.contains("huya.com") || d.contains("douyu.com")
    {
        return DomainClassification {
            category_code: "VIDEO_STREAMING".to_string(),
            category_name: "流媒体视频".to_string(),
            risk_level: "ATTENTION".to_string(),
            risk_desc: "视频点播、直播与高带宽多媒体流".to_string(),
        };
    }

    // 5. 社交媒体 (SOCIAL_MEDIA): 微信、QQ、微博、知乎、贴吧、小红书、X/Twitter
    if d.contains("weixin.qq.com") || d.contains("wx.qq.com") || d.contains("qq.com")
        || d.contains("weibo.com") || d.contains("zhihu.com") || d.contains("tieba.baidu.com")
        || d.contains("xiaohongshu.com") || d.contains("douban.com") || d.contains("twitter.com")
        || d.contains("x.com") || d.contains("facebook.com") || d.contains("instagram.com")
    {
        return DomainClassification {
            category_code: "SOCIAL_MEDIA".to_string(),
            category_name: "社交网络".to_string(),
            risk_level: "ATTENTION".to_string(),
            risk_desc: "即时通信、社交动态与社区交流".to_string(),
        };
    }

    // 6. 招聘求职 (RECRUITMENT): Boss直聘、猎聘、智联招聘、51job
    if d.contains("zhipin.com") || d.contains("liepin.com") || d.contains("zhaopin.com")
        || d.contains("51job.com") || d.contains("lagou.com") || d.contains("shixiseng.com")
    {
        return DomainClassification {
            category_code: "RECRUITMENT".to_string(),
            category_name: "求职招聘".to_string(),
            risk_level: "ATTENTION".to_string(),
            risk_desc: "⚠️ 招聘求职网站访问，可能存在离职意向倾向".to_string(),
        };
    }

    // 7. 电商金融 (SHOPPING_FINANCE): 淘宝、京东、拼多多、支付宝、各大网银
    if d.contains("taobao.com") || d.contains("tmall.com") || d.contains("jd.com")
        || d.contains("pinduoduo.com") || d.contains("alipay.com") || d.contains("unionpay.com")
        || d.contains("ccb.com") || d.contains("icbc.com.cn") || d.contains("boc.cn")
        || d.contains("abchina.com") || d.contains("cmbchina.com") || d.contains("xueqiu.com")
    {
        return DomainClassification {
            category_code: "SHOPPING_FINANCE".to_string(),
            category_name: "电商金融".to_string(),
            risk_level: "NORMAL".to_string(),
            risk_desc: "电子商务与个人网上银行服务".to_string(),
        };
    }

    // 8. 游戏娱乐 (GAMING_ENTERTAINMENT): Steam、腾讯游戏、网易游戏、米哈游
    if d.contains("steampowered.com") || d.contains("steamcommunity.com") || d.contains("epicgames.com")
        || d.contains("mihoyo.com") || d.contains("riotgames.com") || d.contains("blizzard.com")
        || d.contains("game.qq.com") || d.contains("163.com/game")
    {
        return DomainClassification {
            category_code: "GAMING_ENTERTAINMENT".to_string(),
            category_name: "游戏娱乐".to_string(),
            risk_level: "ATTENTION".to_string(),
            risk_desc: "网络游戏对局、数字分发平台与电竞服务".to_string(),
        };
    }

    // 9. 云基础设施 (CLOUD_INFRA): 阿里云、腾讯云、华为云、AWS、Cloudflare
    if d.contains("aliyun.com") || d.contains("aliyuncs.com") || d.contains("myqcloud.com")
        || d.contains("tencentcloud.com") || d.contains("huaweicloud.com") || d.contains("amazonaws.com")
        || d.contains("cloudflare.com") || d.contains("baidu.com") || d.contains("apple.com")
        || d.contains("icloud.com")
    {
        return DomainClassification {
            category_code: "CLOUD_INFRA".to_string(),
            category_name: "云基础设施".to_string(),
            risk_level: "NORMAL".to_string(),
            risk_desc: "公共云服务、CDN 节点与基础网络设施".to_string(),
        };
    }

    DomainClassification {
        category_code: "OTHER_INTERNET".to_string(),
        category_name: "常规互联网".to_string(),
        risk_level: "NORMAL".to_string(),
        risk_desc: "通用公网域名访问".to_string(),
    }
}

// ============================================================
// 5. 上网审计日志持久化与统计引擎
// ============================================================

/// 获取审计日志文件主目录
fn get_audit_log_dir() -> PathBuf {
    let dir = crate::forensics::data_path("web_access_logs");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// 写入并持久化单条上网审计日志
pub fn record_web_access_log(mut log: WebAccessLog) {
    let log_id = LOG_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    log.id = log_id;

    // 1. 存入内存环形缓冲
    if let Ok(mut logs) = WEB_ACCESS_LOGS.lock() {
        if logs.len() >= MAX_MEM_LOGS {
            logs.pop_back();
        }
        logs.push_front(log.clone());
    }

    // 2. 异步追加持久化至当天 JSONL 文件
    let dir = get_audit_log_dir();
    let today_str = chrono::Local::now().format("%Y-%m-%d").to_string();
    let file_path = dir.join(format!("web_access_{}.jsonl", today_str));

    if let Ok(json_line) = serde_json::to_string(&log) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&file_path) {
            let _ = writeln!(file, "{}", json_line);
        }
    }
}

/// 查询上网审计日志清单 (支持分页与多维过滤)
pub fn get_web_access_logs(
    limit: Option<usize>,
    category_filter: Option<String>,
    risk_filter: Option<String>,
    client_ip_filter: Option<String>,
) -> Vec<WebAccessLog> {
    let limit = limit.unwrap_or(200);
    let mut result = Vec::new();

    if let Ok(logs) = WEB_ACCESS_LOGS.lock() {
        for log in logs.iter() {
            if let Some(ref cat) = category_filter {
                if !cat.is_empty() && cat != "ALL" && log.category_code != *cat {
                    continue;
                }
            }
            if let Some(ref risk) = risk_filter {
                if !risk.is_empty() && risk != "ALL" && log.risk_level != *risk {
                    continue;
                }
            }
            if let Some(ref cip) = client_ip_filter {
                if !cip.is_empty() && !log.client_ip.contains(cip) {
                    continue;
                }
            }
            result.push(log.clone());
            if result.len() >= limit {
                break;
            }
        }
    }

    result
}

/// 清空当前审计日志
pub fn clear_web_access_logs() -> bool {
    if let Ok(mut logs) = WEB_ACCESS_LOGS.lock() {
        logs.clear();
        true
    } else {
        false
    }
}

/// 获取上网行为多维聚合统计数据
pub fn get_web_audit_statistics() -> WebAuditStatistics {
    let mut category_dist: HashMap<String, usize> = HashMap::new();
    let mut domain_counts: HashMap<String, (usize, String)> = HashMap::new();
    let mut client_counts: HashMap<String, (usize, String)> = HashMap::new();
    let mut high_risk_count = 0;
    let total_requests;

    if let Ok(logs) = WEB_ACCESS_LOGS.lock() {
        total_requests = logs.len();
        for log in logs.iter() {
            *category_dist.entry(log.category.clone()).or_insert(0) += 1;

            if log.risk_level == "HIGH_RISK" {
                high_risk_count += 1;
            }

            let d_entry = domain_counts.entry(log.domain.clone()).or_insert((0, log.category.clone()));
            d_entry.0 += 1;

            let c_entry = client_counts.entry(log.client_ip.clone()).or_insert((0, log.client_hostname.clone().unwrap_or_else(|| log.client_mac.clone())));
            c_entry.0 += 1;
        }
    } else {
        total_requests = 0;
    }

    // Top 10 域名
    let mut top_domains_vec: Vec<TopEntityItem> = domain_counts
        .into_iter()
        .map(|(k, v)| TopEntityItem {
            name: k,
            count: v.0,
            sub_label: v.1,
        })
        .collect();
    top_domains_vec.sort_by(|a, b| b.count.cmp(&a.count));
    top_domains_vec.truncate(10);

    // Top 10 客户端
    let mut top_clients_vec: Vec<TopEntityItem> = client_counts
        .into_iter()
        .map(|(k, v)| TopEntityItem {
            name: k,
            count: v.0,
            sub_label: v.1,
        })
        .collect();
    top_clients_vec.sort_by(|a, b| b.count.cmp(&a.count));
    top_clients_vec.truncate(10);

    let unique_domains = top_domains_vec.len();
    let unique_clients = top_clients_vec.len();

    WebAuditStatistics {
        total_requests,
        unique_clients,
        unique_domains,
        high_risk_count,
        category_distribution: category_dist,
        top_domains: top_domains_vec,
        top_clients: top_clients_vec,
    }
}

/// 导出上网行为审计日志为 CSV 或 JSON 格式字符串
pub fn export_web_access_logs(format: &str) -> Result<String, String> {
    let logs = get_web_access_logs(Some(10000), None, None, None);

    if format.eq_ignore_ascii_case("csv") {
        let mut csv = String::from("ID,时间,客户端IP,客户端主机名,MAC地址,访问域名,完整URL,请求方法,协议类型,行为分类,风险等级,目的IP,目的端口,地理归属地,风险说明\n");
        for l in logs {
            let line = format!(
                "{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\"\n",
                l.id,
                l.timestamp,
                l.client_ip,
                l.client_hostname.unwrap_or_default(),
                l.client_mac,
                l.domain,
                l.url.replace('"', "\"\""),
                l.method,
                l.protocol,
                l.category,
                l.risk_level,
                l.remote_ip,
                l.remote_port,
                l.geo_summary,
                l.risk_desc.replace('"', "\"\"")
            );
            csv.push_str(&line);
        }
        Ok(csv)
    } else {
        serde_json::to_string_pretty(&logs)
            .map_err(|e| format!("导出 JSON 序列化失败: {}", e))
    }
}

// ============================================================
// 6. 流水线自动化接入引擎与 Tauri 命令接口
// ============================================================
use tauri::Emitter;

/// 自动分析报文载荷并完成上网行为合规审计与关联归档
pub fn audit_packet_activity(
    app: &tauri::AppHandle,
    src_ip: &str,
    dst_ip: &str,
    src_mac: &str,
    src_port: u16,
    dst_port: u16,
    protocol: &str,
    payload: &[u8],
    geo_summary: &str,
) {
    if payload.is_empty() {
        return;
    }

    let now = chrono::Local::now();
    let timestamp_str = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    // 1. DNS 协议解析与双向缓存关联 (端口 53)
    if src_port == 53 || dst_port == 53 {
        if let Some(dns_res) = parse_dns_packet(payload) {
            if dns_res.is_response && !dns_res.resolved_ips.is_empty() {
                record_dns_resolution(dst_ip, &dns_res.query_domain, &dns_res.resolved_ips, dns_res.ttl_secs);
            }
            // 仅对有效域名记录 DNS 查询审计
            if !dns_res.query_domain.is_empty() {
                let class = classify_domain(&dns_res.query_domain);
                let audit_log = WebAccessLog {
                    id: 0,
                    timestamp: timestamp_str.clone(),
                    timestamp_ms,
                    client_ip: if src_port == 53 { dst_ip.to_string() } else { src_ip.to_string() },
                    client_mac: src_mac.to_string(),
                    client_hostname: None,
                    domain: dns_res.query_domain.clone(),
                    url: format!("dns://{}/", dns_res.query_domain),
                    method: if dns_res.is_response { "DNS_RESP".to_string() } else { "DNS_QUERY".to_string() },
                    protocol: "DNS".to_string(),
                    category: class.category_name,
                    category_code: class.category_code,
                    risk_level: class.risk_level,
                    risk_desc: class.risk_desc,
                    remote_ip: if src_port == 53 { src_ip.to_string() } else { dst_ip.to_string() },
                    remote_port: if src_port == 53 { src_port } else { dst_port },
                    geo_summary: geo_summary.to_string(),
                    user_agent: None,
                    bytes_sent: payload.len(),
                    bytes_received: 0,
                };
                let _ = app.emit("web-access-log", &audit_log);
                record_web_access_log(audit_log);

                // 联动网络审查 DNS 高熵隐蔽隧道与保密违规外联审计
                crate::audit_network::inspect_dns_tunnel(
                    if src_port == 53 { dst_ip } else { src_ip },
                    if src_port == 53 { src_ip } else { dst_ip },
                    src_port,
                    dst_port,
                    &dns_res.query_domain,
                    1,
                );
                crate::audit_confidentiality::inspect_egress_domain(
                    if src_port == 53 { dst_ip } else { src_ip },
                    &dns_res.query_domain,
                );
            }
            return;
        }
    }

    // 2. TLS Client Hello SNI 提取 (HTTPS 加密流量零解密审计)
    if dst_port == 443 || protocol == "TLS" || protocol == "HTTPS" || (payload.len() > 5 && payload[0] == 0x16 && payload[1] == 0x03) {
        if let Some(sni_domain) = extract_tls_sni(payload) {
            let class = classify_domain(&sni_domain);
            let audit_log = WebAccessLog {
                id: 0,
                timestamp: timestamp_str.clone(),
                timestamp_ms,
                client_ip: src_ip.to_string(),
                client_mac: src_mac.to_string(),
                client_hostname: None,
                domain: sni_domain.clone(),
                url: format!("https://{}/", sni_domain),
                method: "TLS_SNI".to_string(),
                protocol: "HTTPS (TLS)".to_string(),
                category: class.category_name,
                category_code: class.category_code,
                risk_level: class.risk_level,
                risk_desc: class.risk_desc,
                remote_ip: dst_ip.to_string(),
                remote_port: dst_port,
                geo_summary: geo_summary.to_string(),
                user_agent: None,
                bytes_sent: payload.len(),
                bytes_received: 0,
            };
            let _ = app.emit("web-access-log", &audit_log);
            record_web_access_log(audit_log);

            // 联动保密审查违规外联审计 (TLS 目标域名)
            crate::audit_confidentiality::inspect_egress_domain(
                src_ip,
                &sni_domain,
            );
            return;
        }
    }

    // 3. HTTP 明文访问审计
    if dst_port == 80 || protocol == "HTTP" || payload.starts_with(b"GET ") || payload.starts_with(b"POST ") || payload.starts_with(b"HEAD ") || payload.starts_with(b"PUT ") || payload.starts_with(b"DELETE ") || payload.starts_with(b"OPTIONS ") || payload.starts_with(b"CONNECT ") {
        if let Some(http_info) = extract_http_access_info(payload) {
            let class = classify_domain(&http_info.host);
            let full_url = if http_info.uri.starts_with("http") {
                http_info.uri.clone()
            } else {
                format!("http://{}{}", http_info.host, http_info.uri)
            };
            let audit_log = WebAccessLog {
                id: 0,
                timestamp: timestamp_str,
                timestamp_ms,
                client_ip: src_ip.to_string(),
                client_mac: src_mac.to_string(),
                client_hostname: None,
                domain: http_info.host.clone(),
                url: full_url,
                method: http_info.method,
                protocol: "HTTP".to_string(),
                category: class.category_name,
                category_code: class.category_code,
                risk_level: class.risk_level,
                risk_desc: class.risk_desc,
                remote_ip: dst_ip.to_string(),
                remote_port: dst_port,
                geo_summary: geo_summary.to_string(),
                user_agent: http_info.user_agent,
                bytes_sent: payload.len(),
                bytes_received: 0,
            };
            let _ = app.emit("web-access-log", &audit_log);
            record_web_access_log(audit_log);

            // 联动保密审查违规外联审计 (HTTP Host)
            crate::audit_confidentiality::inspect_egress_domain(
                src_ip,
                &http_info.host,
            );
            return;
        }
    }

    // 4. DNS 关联回溯反查 (对于非直接域名流量，通过之前解析的 IP 反查所属域名)
    if let Some(associated_domain) = lookup_domain_for_ip(dst_ip) {
        let class = classify_domain(&associated_domain);
        if class.risk_level == "HIGH_RISK" {
            let audit_log = WebAccessLog {
                id: 0,
                timestamp: timestamp_str,
                timestamp_ms,
                client_ip: src_ip.to_string(),
                client_mac: src_mac.to_string(),
                client_hostname: None,
                domain: associated_domain.clone(),
                url: format!("tcp://{}:{}/", associated_domain, dst_port),
                method: "DNS_CORRELATED".to_string(),
                protocol: protocol.to_string(),
                category: class.category_name,
                category_code: class.category_code,
                risk_level: class.risk_level,
                risk_desc: format!("DNS关联识别: {}", class.risk_desc),
                remote_ip: dst_ip.to_string(),
                remote_port: dst_port,
                geo_summary: geo_summary.to_string(),
                user_agent: None,
                bytes_sent: payload.len(),
                bytes_received: 0,
            };
            let _ = app.emit("web-access-log", &audit_log);
            record_web_access_log(audit_log);

            // 联动保密审查违规外联审计 (反查关联域名)
            crate::audit_confidentiality::inspect_egress_domain(
                src_ip,
                &associated_domain,
            );
        }
    }
}

// ============================================================

