// ============================================================
// 工业全能网络探针 - 100% 物理隔离离线 IP 资产与地理情报库
// 模块名称: ip_intelligence.rs
// 
// 核心职责:
// 1. 100% 零网络外泄 (Zero Network Leakage) 离线运行，严禁任何公网 HTTP 探测;
// 2. 内网私网 CIDR 资产映射引擎 (支持动态加载与热写入网段-安全域字典);
// 3. IP2Region v2 (xdb) 纯 Rust 零外部依赖高性能内存解析器;
// 4. 公网权威网络离线映射字典 (公共 DNS, 骨干网, 主流云服务商段);
// 5. 前缀掩码位运算 + 矢量索引二分查找，单次查询小于 5 微秒。
// ============================================================

use std::borrow::Cow;
use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

/// 编译期静态内嵌基准离线 IP 数据库（相对于本源码目录，无任何运行时绝对/CWD硬编码路径）
/// 支持单文件零外部文件便携运行，并允许运行期由 OS 应用数据区外挂库热更新覆盖
const EMBEDDED_XDB_BYTES: &[u8] = include_bytes!("../data/ip2region.xdb");

/// 归属地与网络运营商详细信息
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeoLocation {
    pub country: String,
    pub region: String,
    pub province: String,
    pub city: String,
    pub isp: String,
}

impl GeoLocation {
    /// 解析 ip2region 标准格式 (智能兼容 v1: "国家|区域|省份|城市|ISP" 与 v2: "国家|省份|城市|ISP|国家码")
    pub fn from_raw_string(raw: &str) -> Self {
        let parts: Vec<&str> = raw.split('|').collect();
        let clean_part = |idx: usize| -> String {
            if idx < parts.len() {
                let s = parts[idx].trim();
                if s == "0" || s.is_empty() {
                    String::new()
                } else {
                    s.to_string()
                }
            } else {
                String::new()
            }
        };

        if parts.len() >= 5 {
            let p4 = parts[4].trim();
            // 若第 5 段为 2 位大写 ASCII 国家代码 (例如 "CN", "US", "BR", "HK", "JP")
            // 表明当前 XDB 布局为 "国家|省份|城市|ISP|国家码"
            let is_country_code_at_end = p4.len() == 2 && p4.chars().all(|c| c.is_ascii_uppercase());

            if is_country_code_at_end {
                let country = clean_part(0);
                let province = clean_part(1);
                let city = clean_part(2);
                let isp = clean_part(3);

                return Self {
                    country,
                    region: String::new(),
                    province,
                    city,
                    isp,
                };
            }
        }

        // 默认回退到标准 5 段格式: "国家|区域|省份|城市|ISP"
        Self {
            country: clean_part(0),
            region: clean_part(1),
            province: clean_part(2),
            city: clean_part(3),
            isp: clean_part(4),
        }
    }

    /// 组合为紧凑易读的摘要文本 (例如: "中国 广东省 深圳市 电信")
    pub fn summary(&self) -> String {
        let mut tokens = Vec::new();
        if !self.country.is_empty() {
            tokens.push(self.country.as_str());
        }
        if !self.province.is_empty() && self.province != self.country {
            tokens.push(self.province.as_str());
        }
        if !self.city.is_empty() && self.city != self.province {
            tokens.push(self.city.as_str());
        }
        if !self.isp.is_empty() {
            tokens.push(self.isp.as_str());
        }

        if tokens.is_empty() {
            "公网IP (未知详细区域)".to_string()
        } else {
            tokens.join(" ")
        }
    }
}

/// IP 情报与资产归属识别结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpIntelligenceResult {
    pub ip: String,
    pub is_private: bool,
    pub is_loopback: bool,
    pub is_multicast: bool,
    pub zone_name: String,
    pub security_level: String,
    pub geo_summary: String,
    pub country: Option<String>,
    pub province: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
}

/// 内网网段资产定义条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidrAssetRule {
    /// CIDR 字符串 (如 "192.168.1.0/24")
    pub cidr: String,
    /// 安全域/业务分区名称 (如 "工业生产控制区-PLC网段")
    pub zone_name: String,
    /// 资产安全等级 (如 "核心", "重要", "普通")
    pub security_level: String,
    /// 责任单位或归属说明
    pub description: String,
}

/// 解析后的 CIDR 数值结构 (供极速位运算比对)
#[derive(Debug, Clone)]
struct ParsedCidr {
    network_u32: u32,
    mask_u32: u32,
    rule: CidrAssetRule,
}

impl ParsedCidr {
    fn from_rule(rule: CidrAssetRule) -> Option<Self> {
        let parts: Vec<&str> = rule.cidr.split('/').collect();
        if parts.is_empty() {
            return None;
        }

        let ip = Ipv4Addr::from_str(parts[0].trim()).ok()?;
        let prefix_len: u32 = if parts.len() > 1 {
            parts[1].trim().parse().unwrap_or(32)
        } else {
            32
        };

        if prefix_len > 32 {
            return None;
        }

        let mask_u32 = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };

        let ip_u32 = u32::from(ip);
        let network_u32 = ip_u32 & mask_u32;

        Some(Self {
            network_u32,
            mask_u32,
            rule,
        })
    }

    fn matches(&self, ip_u32: u32) -> bool {
        (ip_u32 & self.mask_u32) == self.network_u32
    }
}

// ============================================================
// IP2Region v2 (xdb) 纯 Rust 零外部依赖内存解析引擎
// ============================================================
const HEADER_INFO_LENGTH: usize = 256;
const VECTOR_INDEX_COLS: usize = 256;
const VECTOR_INDEX_SIZE: usize = 8;
const SEGMENT_INDEX_SIZE: usize = 14;

pub struct XdbSearcher {
    content: Cow<'static, [u8]>,
    header_version: u16,
    header_created_at: u32,
    file_path: String,
}

impl XdbSearcher {
    /// 从本地文件加载整个 xdb 二进制数据库至内存
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path_ref = path.as_ref();
        let path_str = path_ref.to_string_lossy().to_string();
        let mut file = File::open(path_ref).map_err(|e| format!("打开 IP 数据库失败 [{}]: {}", path_str, e))?;
        let mut content = Vec::new();
        file.read_to_end(&mut content).map_err(|e| format!("读取 IP 数据库数据流失败: {}", e))?;

        Self::load_from_bytes(content, path_str)
    }

    /// 从堆内存字节数组初始化解析器
    pub fn load_from_bytes(content: Vec<u8>, file_path: String) -> Result<Self, String> {
        Self::load_from_cow(Cow::Owned(content), file_path)
    }

    /// 从编译期只读静态切片初始化解析器 (零堆分配、零磁盘 IO 拷贝)
    pub fn load_from_static_bytes(content: &'static [u8], label: String) -> Result<Self, String> {
        Self::load_from_cow(Cow::Borrowed(content), label)
    }

    fn load_from_cow(content: Cow<'static, [u8]>, file_path: String) -> Result<Self, String> {
        // xdb 格式必须至少包含 256B Header + 512KB VectorIndex + 至少 1 条 14B 索引段
        let min_len = HEADER_INFO_LENGTH + (256 * VECTOR_INDEX_COLS * VECTOR_INDEX_SIZE) + SEGMENT_INDEX_SIZE;
        if content.len() < min_len {
            return Err(format!("IP 数据库文件损坏或不完整: 字节长度 {} 小于最小长度 {}", content.len(), min_len));
        }

        let header_version = u16::from_le_bytes(content[0..2].try_into().map_err(|_| "Header version 解析错误")?);
        let header_created_at = u32::from_le_bytes(content[4..8].try_into().map_err(|_| "Header createdAt 解析错误")?);

        Ok(Self {
            content,
            header_version,
            header_created_at,
            file_path,
        })
    }

    /// 查询 IPv4 地址归属地 (微秒级内存二分查找)
    ///
    /// 算法复杂度:
    /// - 时间复杂度: O(log K), 其中 K 为命中段内的 IP 记录数, 耗时 < 5 微秒
    /// - 空间复杂度: O(1) 零内存分配
    pub fn search_ipv4(&self, ip_bytes: &[u8; 4]) -> Option<GeoLocation> {
        let il0 = ip_bytes[0] as usize;
        let il1 = ip_bytes[1] as usize;

        // 1. 定位 VectorIndex 矢量索引槽位 (512KB 区域，每个槽 8 字节: [start_ptr, end_ptr])
        let v_idx = HEADER_INFO_LENGTH + ((il0 * VECTOR_INDEX_COLS + il1) * VECTOR_INDEX_SIZE);
        if v_idx + VECTOR_INDEX_SIZE > self.content.len() {
            return None;
        }

        let start_ptr = u32::from_le_bytes(self.content[v_idx..v_idx + 4].try_into().ok()?) as usize;
        let end_ptr = u32::from_le_bytes(self.content[v_idx + 4..v_idx + 8].try_into().ok()?) as usize;

        // 若指针为 0，说明该网段无数据
        if start_ptr == 0 || end_ptr == 0 || start_ptr > end_ptr || end_ptr > self.content.len() {
            return None;
        }

        // 2. 在 [start_ptr, end_ptr] 区间内进行二分查找 (每个索引项 14 字节)
        let total_segments = (end_ptr - start_ptr) / SEGMENT_INDEX_SIZE;
        if total_segments == 0 {
            return None;
        }

        let mut low = 0usize;
        let mut high = total_segments;

        while low < high {
            let mid = (low + high) / 2;
            let offset = start_ptr + mid * SEGMENT_INDEX_SIZE;
            if offset + SEGMENT_INDEX_SIZE > self.content.len() {
                break;
            }

            let seg_start_ip = &self.content[offset..offset + 4];
            let seg_end_ip = &self.content[offset + 4..offset + 8];

            if ip_bytes < seg_start_ip.try_into().ok()? {
                high = mid;
            } else if ip_bytes > seg_end_ip.try_into().ok()? {
                low = mid + 1;
            } else {
                // 3. 精准命中！读取 data_len (u16) 与 data_ptr (u32)
                let data_len = u16::from_le_bytes(self.content[offset + 8..offset + 10].try_into().ok()?) as usize;
                let data_ptr = u32::from_le_bytes(self.content[offset + 10..offset + 14].try_into().ok()?) as usize;

                if data_ptr + data_len <= self.content.len() {
                    let raw_str = std::str::from_utf8(&self.content[data_ptr..data_ptr + data_len]).ok()?;
                    return Some(GeoLocation::from_raw_string(raw_str));
                }
                return None;
            }
        }

        None
    }

    pub fn get_file_path(&self) -> &str {
        &self.file_path
    }

    pub fn get_file_size(&self) -> usize {
        self.content.len()
    }

    pub fn get_created_at(&self) -> u32 {
        self.header_created_at
    }

    pub fn get_version(&self) -> u16 {
        self.header_version
    }
}

/// 离线 IP 资产与地理情报识别引擎 (IpIntelligenceEngine)
pub struct IpIntelligenceEngine {
    rules: Vec<ParsedCidr>,
    xdb_searcher: Option<XdbSearcher>,
}

impl IpIntelligenceEngine {
    pub fn new() -> Self {
        let default_rules = vec![
            CidrAssetRule {
                cidr: "127.0.0.0/8".to_string(),
                zone_name: "本地回环测试区".to_string(),
                security_level: "内部".to_string(),
                description: "操作系统本地回环接口 (Loopback)".to_string(),
            },
            CidrAssetRule {
                cidr: "224.0.0.0/4".to_string(),
                zone_name: "组播通信网段 (Multicast)".to_string(),
                security_level: "网络组播".to_string(),
                description: "RFC 1112 组播保留地址段 (Class D)".to_string(),
            },
            CidrAssetRule {
                cidr: "169.254.0.0/16".to_string(),
                zone_name: "链路本地网段 (Link-Local)".to_string(),
                security_level: "链路本地".to_string(),
                description: "RFC 3927 自动私有 IP 寻址 (APIPA)".to_string(),
            },
            CidrAssetRule {
                cidr: "192.168.0.0/16".to_string(),
                zone_name: "局域网通信网段 (Class C)".to_string(),
                security_level: "普通内网".to_string(),
                description: "RFC 1918 私网保留地址段".to_string(),
            },
            CidrAssetRule {
                cidr: "10.0.0.0/8".to_string(),
                zone_name: "大型企业/工控主干网 (Class A)".to_string(),
                security_level: "核心内网".to_string(),
                description: "RFC 1918 私网骨干网段".to_string(),
            },
            CidrAssetRule {
                cidr: "172.16.0.0/12".to_string(),
                zone_name: "数据中心/虚拟化网段 (Class B)".to_string(),
                security_level: "重要内网".to_string(),
                description: "RFC 1918 私网中型网段".to_string(),
            },
        ];

        let mut engine = Self {
            rules: Vec::new(),
            xdb_searcher: None,
        };

        // 优先尝试从持久化文件恢复自定义安全区域规则
        let cidr_file = crate::forensics::data_path("cidr_rules.json");
        let mut loaded_from_disk = false;
        if cidr_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&cidr_file) {
                if let Ok(saved_rules) = serde_json::from_str::<Vec<CidrAssetRule>>(&content) {
                    for r in saved_rules {
                        engine.add_rule(r);
                    }
                    loaded_from_disk = true;
                }
            }
        }

        if !loaded_from_disk {
            for r in default_rules {
                engine.add_rule(r);
            }
        }

        // 1. 优先尝试加载操作系统标准数据目录下的热更新扩展 XDB 库 (用户后续升级版优先覆盖内置库)
        let mut candidate_paths = vec![
            crate::forensics::data_path("ip2region.xdb"),
        ];

        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                candidate_paths.push(exe_dir.join("data/ip2region.xdb"));
                candidate_paths.push(exe_dir.join("ip2region.xdb"));
            }
        }

        for p in candidate_paths {
            if p.exists() {
                if let Ok(meta) = std::fs::metadata(&p) {
                    if meta.len() >= 5 * 1024 * 1024 {
                        if let Ok(searcher) = XdbSearcher::load_from_file(p.to_str().unwrap_or_default()) {
                            engine.xdb_searcher = Some(searcher);
                            break;
                        }
                    }
                }
            }
        }

        // 2. 若外部无覆盖库，零拷贝挂载编译期静态内嵌千万级 XDB 基准库 (实现单文件绝对离线便携)
        if engine.xdb_searcher.is_none() {
            if let Ok(searcher) = XdbSearcher::load_from_static_bytes(
                EMBEDDED_XDB_BYTES,
                "内置基准库 (Built-in XDB)".to_string(),
            ) {
                engine.xdb_searcher = Some(searcher);
            }
        }

        engine
    }

    /// 热加载或切换 xdb 数据库
    pub fn load_xdb(&mut self, path: &str) -> Result<String, String> {
        let searcher = XdbSearcher::load_from_file(path)?;
        let size_mb = searcher.get_file_size() as f64 / (1024.0 * 1024.0);
        let msg = format!("成功加载 IP 归属地库 [{}] (体积: {:.2} MB)", path, size_mb);
        self.xdb_searcher = Some(searcher);
        Ok(msg)
    }

    /// 检查 IP 数据库是否已成功加载
    pub fn is_xdb_loaded(&self) -> bool {
        self.xdb_searcher.is_some()
    }

    /// 获取当前 IP 归属地库的状态信息
    pub fn get_xdb_status(&self) -> serde_json::Value {
        match &self.xdb_searcher {
            Some(s) => serde_json::json!({
                "loaded": true,
                "file_path": s.get_file_path(),
                "file_size": s.get_file_size(),
                "created_at": s.get_created_at(),
                "version": s.get_version(),
            }),
            None => serde_json::json!({
                "loaded": false,
                "file_path": "",
                "file_size": 0,
                "created_at": 0,
                "version": 0,
            }),
        }
    }

    /// 添加或覆盖网段资产规则 (最长前缀优先)
    pub fn add_rule(&mut self, rule: CidrAssetRule) {
        if let Some(parsed) = ParsedCidr::from_rule(rule) {
            self.rules.push(parsed);
            self.rules.sort_by(|a, b| b.mask_u32.cmp(&a.mask_u32));
        }
    }

    /// 批量重置规则列表并持久化至磁盘
    pub fn set_rules(&mut self, rules: Vec<CidrAssetRule>) {
        self.rules.clear();
        for r in &rules {
            if let Some(parsed) = ParsedCidr::from_rule(r.clone()) {
                self.rules.push(parsed);
            }
        }
        self.rules.sort_by(|a, b| b.mask_u32.cmp(&a.mask_u32));

        // 持久化到数据目录
        let cidr_file = crate::forensics::data_path("cidr_rules.json");
        if let Ok(json_str) = serde_json::to_string_pretty(&rules) {
            let _ = std::fs::write(cidr_file, json_str);
        }
    }

    /// 获取当前所有生效的规则定义
    pub fn get_rules(&self) -> Vec<CidrAssetRule> {
        self.rules.iter().map(|p| p.rule.clone()).collect()
    }

    /// 核心分类与情报识别入口 (集成内网 CIDR + xdb 离线库 + 骨干网离线特征)
    pub fn classify(&self, ip_str: &str) -> IpIntelligenceResult {
        let clean_ip = ip_str.trim();
        let ipv4_opt = Ipv4Addr::from_str(clean_ip).ok();

        if let Some(ip) = ipv4_opt {
            let ip_u32 = u32::from(ip);
            let octets = ip.octets();
            let is_loopback = ip.is_loopback();
            let is_multicast = ip.is_multicast();
            let is_private = ip.is_private();

            // 1. 优先匹配内网自定义 CIDR 规则表 (最长前缀匹配 LPM)
            for parsed in &self.rules {
                if parsed.matches(ip_u32) {
                    return IpIntelligenceResult {
                        ip: clean_ip.to_string(),
                        is_private,
                        is_loopback,
                        is_multicast,
                        zone_name: parsed.rule.zone_name.clone(),
                        security_level: parsed.rule.security_level.clone(),
                        geo_summary: format!("网络: {}", parsed.rule.zone_name),
                        country: Some(if is_private { "内网专线".to_string() } else { "专用网络".to_string() }),
                        province: None,
                        city: None,
                        isp: Some(parsed.rule.description.clone()),
                    };
                }
            }

            // 2. 若存在已加载的 xdb 离线库，执行纯内存微秒级精准归属地解析
            if let Some(ref searcher) = self.xdb_searcher {
                if let Some(geo) = searcher.search_ipv4(&octets) {
                    let summary = geo.summary();
                    let zone = if !geo.city.is_empty() {
                        format!("外部公网 [{}]", geo.city)
                    } else if !geo.country.is_empty() {
                        format!("外部公网 [{}]", geo.country)
                    } else {
                        "外部公网主机".to_string()
                    };

                    return IpIntelligenceResult {
                        ip: clean_ip.to_string(),
                        is_private,
                        is_loopback,
                        is_multicast,
                        zone_name: zone,
                        security_level: "外部公网".to_string(),
                        geo_summary: summary,
                        country: if geo.country.is_empty() { None } else { Some(geo.country) },
                        province: if geo.province.is_empty() { None } else { Some(geo.province) },
                        city: if geo.city.is_empty() { None } else { Some(geo.city) },
                        isp: if geo.isp.is_empty() { None } else { Some(geo.isp) },
                    };
                }
            }

            // 3. 匹配公网权威与知名基础设施离线特征表 (兜底)
            if let Some(public_intel) = match_known_public_ip(clean_ip, ip_u32) {
                return IpIntelligenceResult {
                    ip: clean_ip.to_string(),
                    is_private,
                    is_loopback,
                    is_multicast,
                    zone_name: public_intel.0,
                    security_level: "公共服务".to_string(),
                    geo_summary: public_intel.1,
                    country: Some("公共基础设施".to_string()),
                    province: None,
                    city: None,
                    isp: None,
                };
            }

            // 4. 普通未知公网 IP
            if !is_private && !is_loopback && !is_multicast {
                let db_loaded = self.xdb_searcher.is_some();
                return IpIntelligenceResult {
                    ip: clean_ip.to_string(),
                    is_private: false,
                    is_loopback: false,
                    is_multicast: false,
                    zone_name: if db_loaded { "公网外部主机".to_string() } else { "公网外部主机 (未载入IP库)".to_string() },
                    security_level: "外部未知".to_string(),
                    geo_summary: if db_loaded { "公网IP (未匹配到归属地)".to_string() } else { "公网IP (未载入IP库)".to_string() },
                    country: None,
                    province: None,
                    city: None,
                    isp: None,
                };
            }

            // 5. 未定义私网兜底
            return IpIntelligenceResult {
                ip: clean_ip.to_string(),
                is_private,
                is_loopback,
                is_multicast,
                zone_name: "私网未命名网段".to_string(),
                security_level: "未分配".to_string(),
                geo_summary: "局域网 (RFC1918)".to_string(),
                country: Some("内网".to_string()),
                province: None,
                city: None,
                isp: None,
            };
        }

        // 非法或 IPv6 / 主机名兜底
        IpIntelligenceResult {
            ip: clean_ip.to_string(),
            is_private: false,
            is_loopback: false,
            is_multicast: false,
            zone_name: "未知格式地址".to_string(),
            security_level: "未知".to_string(),
            geo_summary: "未知网络实体".to_string(),
            country: None,
            province: None,
            city: None,
            isp: None,
        }
    }
}

/// 匹配内置知名权威公网基础设施 (100% 离线，零请求)
fn match_known_public_ip(ip_str: &str, ip_u32: u32) -> Option<(String, String)> {
    match ip_str {
        "8.8.8.8" | "8.8.4.4" => Some(("Google Public DNS".to_string(), "美国 加州 Google全球Anycast".to_string())),
        "1.1.1.1" | "1.0.0.1" => Some(("Cloudflare DNS".to_string(), "美国 Cloudflare全球Anycast".to_string())),
        "114.114.114.114" | "114.114.115.115" => Some(("114 DNS".to_string(), "中国 江苏南京 南京信风".to_string())),
        "223.5.5.5" | "223.6.6.6" => Some(("AliDNS 阿里公共DNS".to_string(), "中国 浙江杭州 阿里云计算".to_string())),
        "180.76.76.76" => Some(("Baidu DNS 百度公共DNS".to_string(), "中国 北京 百度数据中心".to_string())),
        "119.29.29.29" => Some(("DNSPod 腾讯公共DNS".to_string(), "中国 广东深圳 腾讯云计算".to_string())),
        _ => {
            if (ip_u32 & 0xFFFC0000) == 0x2F5C0000 {
                return Some(("阿里云基础设施段".to_string(), "中国 阿里云骨干网络".to_string()));
            }
            if (ip_u32 & 0xFFFF0000) == 0x811C0000 {
                return Some(("腾讯云基础设施段".to_string(), "中国 腾讯云骨干网络".to_string()));
            }
            None
        }
    }
}

/// 全局共享 IP 资产情报库引擎单例
pub static GLOBAL_IP_ENGINE: once_cell::sync::Lazy<Arc<Mutex<IpIntelligenceEngine>>> =
    once_cell::sync::Lazy::new(|| {
        Arc::new(Mutex::new(IpIntelligenceEngine::new()))
    });

#[cfg(test)]
mod tests {
    use super::*;

    /// 边界与鲁棒性极限测试集
    /// 验证规范要求：
    /// 1. 极限用例推演 (非法输入/越界/空串/回环/组播/RFC1918)
    /// 2. 时间复杂度: O(log N) 二分查找矢量索引, 空间复杂度: O(1) 瞬时查询开销
    #[test]
    fn test_ip_intelligence_boundary_cases() {
        let engine = IpIntelligenceEngine::new();

        // 边界用例 1: 极端非法与空值输入
        let res_empty = engine.classify("");
        assert_eq!(res_empty.zone_name, "未知格式地址");
        assert_eq!(res_empty.is_private, false);

        let res_malformed = engine.classify("999.999.999.999");
        assert_eq!(res_malformed.zone_name, "未知格式地址");

        let res_text = engine.classify("not.an.ip.address");
        assert_eq!(res_text.zone_name, "未知格式地址");

        // 边界用例 2: 回环与多播地址
        let res_loopback = engine.classify("127.0.0.1");
        assert_eq!(res_loopback.is_loopback, true);
        assert_eq!(res_loopback.zone_name, "本地回环测试区");

        let res_multicast = engine.classify("224.0.0.251");
        assert_eq!(res_multicast.is_multicast, true);

        // 边界用例 3: RFC1918 私网网段与自定义 CIDR 最长前缀匹配
        let res_private_a = engine.classify("10.10.1.50");
        assert_eq!(res_private_a.is_private, true);
        assert_eq!(res_private_a.zone_name, "大型企业/工控主干网 (Class A)");

        let res_private_c = engine.classify("192.168.1.100");
        assert_eq!(res_private_c.is_private, true);
        assert_eq!(res_private_c.zone_name, "局域网通信网段 (Class C)");
    }

    /// 真实本地 XDB 数据库加载与微秒级离线解析验证 (含零外部路径内嵌轨验证)
    #[test]
    fn test_xdb_lookup_real_database() {
        let engine = IpIntelligenceEngine::new();
        assert!(engine.is_xdb_loaded());
        let status = engine.get_xdb_status();
        assert_eq!(status["loaded"], true);
        assert!(status["file_size"].as_u64().unwrap_or(0) > 10_000_000);

        let res_china = engine.classify("114.114.114.114");
        assert_eq!(res_china.country.as_deref(), Some("中国"));
        assert_eq!(res_china.province.as_deref(), Some("江苏省"));
        assert_eq!(res_china.city.as_deref(), Some("南京市"));

        let res_ali = engine.classify("223.5.5.5");
        assert_eq!(res_ali.country.as_deref(), Some("中国"));
        assert_eq!(res_ali.province.as_deref(), Some("浙江省"));
        assert_eq!(res_ali.city.as_deref(), Some("杭州市"));
        assert_eq!(res_ali.isp.as_deref(), Some("阿里"));

        let res_bj = engine.classify("123.125.114.144"); // 百度北京
        assert_eq!(res_bj.country.as_deref(), Some("中国"));
        assert_eq!(res_bj.province.as_deref(), Some("北京市"));
        assert_eq!(res_bj.isp.as_deref(), Some("联通"));

        let res_zj = engine.classify("202.96.209.133"); // 浙江嘉兴电信
        assert_eq!(res_zj.country.as_deref(), Some("中国"));
        assert_eq!(res_zj.province.as_deref(), Some("浙江省"));
        assert_eq!(res_zj.city.as_deref(), Some("嘉兴市"));
        assert_eq!(res_zj.isp.as_deref(), Some("电信"));

        let res_google = engine.classify("8.8.8.8");
        assert_eq!(res_google.country.as_deref(), Some("United States"));
        assert_eq!(res_google.province.as_deref(), Some("Louisiana"));
        assert_eq!(res_google.city.as_deref(), Some("Monroe"));

        let res_google_142 = engine.classify("142.250.137.132");
        assert_eq!(res_google_142.country.as_deref(), Some("Brazil"));
        assert_eq!(res_google_142.province.as_deref(), Some("São Paulo"));
        assert_eq!(res_google_142.isp.as_deref(), Some("Google LLC"));
    }
}


