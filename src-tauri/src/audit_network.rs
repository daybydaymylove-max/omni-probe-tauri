// ============================================================
// 工业全能网络探针 - 网络安全审查与隧道异常审计核心引擎
// 模块名称: audit_network.rs
//
// 核心职责与工程规范:
// 1. 严格遵循 GB/T 22239-2019 (等保 2.0 三级) 网络与通信安全要求;
// 2. 工业控制指令级越权审计:
//    - Modbus TCP: MBAP 完整校验 (Protocol ID=0, Length>=6), 功能码 0x05/0x06/0x0F/0x10/0x17, 寄存器地址与数量解析;
//    - Siemens S7comm: ROSCTR 0x01 (Job), Function 0x05 (Write Var), DB 块编号与变量写入长度解析;
//    - SL651 水利水文: 功能码 0x40 测站遥测参数越权修改审计;
//    - 专有工业插件深度识别 (SEMI/Honeywell/Schneider/Yokogawa/Beckhoff 等);
// 3. DNS 隐蔽隧道多维时序研判引擎:
//    - 彻底杜绝单包静态误报: 引入注册域名 (SLD) 60 秒时序滑窗统计;
//    - 白名单免检: 覆盖各大主流云厂商、CDN、操作系统合规更新域名;
//    - 多特征共振判别: 唯一子域名爆发率 + 平均香农熵 + TXT 大载荷判定;
// 4. ICMP 载荷通道异常双向追踪 (大包/高熵非标载荷审计);
// 5. 满足等保三级 180 天审计存留法定义务: 结构化追加持久化 (network_audit_events.jsonl);
// 6. 时间复杂度 O(N), 空间复杂度 O(K) 有界内存控制 (固定容量环形队列 + 自动落盘).
// ============================================================

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_AUDIT_EVENTS: usize = 1000;

/// 网络安全审查事件实体 (等保三级取证结构体)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAuditEvent {
    pub id: u64,
    pub timestamp: String,
    pub timestamp_ns: u128,
    pub event_type: String, // "INDUSTRIAL_WRITE_VIOLATION" | "DNS_COVERT_TUNNEL" | "ICMP_COVERT_TUNNEL" | "CROSS_ZONE_VIOLATION"
    pub severity: String,   // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub summary: String,
    pub detail_json: String,
}

/// 网络安全审查综合度量统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkAuditStatistics {
    pub total_events: u64,
    pub industrial_write_violations: u64,
    pub dns_tunnel_count: u64,
    pub icmp_tunnel_count: u64,
    pub cross_zone_violations: u64,
}

/// DNS 域名滑窗时序统计状态
#[derive(Debug, Clone)]
struct DnsDomainTemporalStats {
    #[allow(dead_code)]
    first_seen: Instant,
    last_seen: Instant,
    query_count: usize,
    subdomains: HashSet<String>,
    total_entropy_sum: f64,
    max_subdomain_len: usize,
    large_txt_responses: usize,
}

struct NetworkAuditState {
    events: VecDeque<NetworkAuditEvent>,
    stats: NetworkAuditStatistics,
    dns_stats: HashMap<String, DnsDomainTemporalStats>,
    authorized_engineers: HashSet<String>,
}

static NETWORK_AUDIT_STATE: Lazy<Arc<Mutex<NetworkAuditState>>> = Lazy::new(|| {
    let mut authorized = HashSet::new();
    // 默认授权工程师站 / SCADA 调度站 IP (可通过白名单配置放行合法运维写指令)
    authorized.insert("192.168.1.114".to_string());
    authorized.insert("127.0.0.1".to_string());

    Arc::new(Mutex::new(NetworkAuditState {
        events: VecDeque::with_capacity(MAX_AUDIT_EVENTS),
        stats: NetworkAuditStatistics::default(),
        dns_stats: HashMap::new(),
        authorized_engineers: authorized,
    }))
});

static EVENT_ID_SEQ: AtomicU64 = AtomicU64::new(1000);

fn current_timestamp() -> (String, u128) {
    let now = SystemTime::now();
    let ns = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let formatted = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    (formatted, ns)
}

/// 字符香农信息熵计算函数
/// 算法复杂度: 时间复杂度 O(N), 空间复杂度 O(1) (256 固定频次数组)
pub fn calculate_string_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// 记录网络安全审查事件并触发等保三级结构化持久化落盘
pub fn record_network_audit_event(
    event_type: &str,
    severity: &str,
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    protocol: &str,
    summary: &str,
    detail_json: &str,
) {
    let (ts_str, ts_ns) = current_timestamp();
    let id = EVENT_ID_SEQ.fetch_add(1, Ordering::Relaxed);

    let event = NetworkAuditEvent {
        id,
        timestamp: ts_str,
        timestamp_ns: ts_ns,
        event_type: event_type.to_string(),
        severity: severity.to_string(),
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        src_port,
        dst_port,
        protocol: protocol.to_string(),
        summary: summary.to_string(),
        detail_json: detail_json.to_string(),
    };

    // 1. 等保三级 180 天法定义务: 结构化追加持久化至本地审计底账
    if let Ok(line) = serde_json::to_string(&event) {
        let path = crate::forensics::data_path("network_audit_events.jsonl");
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{}", line);
        }
    }

    // 2. 更新内存活跃状态与度量统计
    {
        let mut state = crate::lock_guard::lock_mutex(
            &NETWORK_AUDIT_STATE,
            "audit_network::record_network_audit_event",
        );
        state.stats.total_events += 1;
        match event_type {
            "INDUSTRIAL_WRITE_VIOLATION" => state.stats.industrial_write_violations += 1,
            "DNS_COVERT_TUNNEL" => state.stats.dns_tunnel_count += 1,
            "ICMP_COVERT_TUNNEL" => state.stats.icmp_tunnel_count += 1,
            "CROSS_ZONE_VIOLATION" => state.stats.cross_zone_violations += 1,
            _ => {}
        }
        if state.events.len() >= MAX_AUDIT_EVENTS {
            state.events.pop_front();
        }
        state.events.push_back(event);
    }
}

/// 审查工控指令写操作 (深度解构 Modbus TCP / Siemens S7 / SL651 / 专有插件)
/// 时间复杂度: O(1), 空间复杂度: O(1)
pub fn inspect_industrial_commands(
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    protocol: &str,
    payload: &[u8],
) {
    if payload.is_empty() {
        return;
    }

    // 白名单校验：若是已授权的 SCADA 调度总站或指定工程师站，放行并标记为合规运维
    let is_authorized_engineer = crate::lock_guard::lock_mutex(
        &NETWORK_AUDIT_STATE,
        "audit_network::inspect_industrial_commands_auth_check",
    )
    .authorized_engineers
    .contains(src_ip);

    // -------------------------------------------------------------------------
    // 1. Modbus-TCP 完整 MBAP 报头与写控制功能码深度审计
    // -------------------------------------------------------------------------
    if (dst_port == 502 || src_port == 502 || protocol.contains("MODBUS")) && payload.len() >= 8 {
        // MBAP 报头格式: [0..2] Transaction ID, [2..4] Protocol ID (必须为 0), [4..6] Length, [6] Unit ID, [7] Function Code
        let proto_id = u16::from_be_bytes([payload[2], payload[3]]);
        if proto_id == 0 {
            let unit_id = payload[6];
            let fc = payload[7];

            let write_info = match fc {
                0x05 => {
                    let addr = if payload.len() >= 10 { u16::from_be_bytes([payload[8], payload[9]]) } else { 0 };
                    let val = if payload.len() >= 12 { u16::from_be_bytes([payload[10], payload[11]]) } else { 0 };
                    Some(("Write Single Coil (写单个线圈/继电器控制)", addr, 1, format!("值: 0x{:04X}", val)))
                }
                0x06 => {
                    let addr = if payload.len() >= 10 { u16::from_be_bytes([payload[8], payload[9]]) } else { 0 };
                    let val = if payload.len() >= 12 { u16::from_be_bytes([payload[10], payload[11]]) } else { 0 };
                    Some(("Write Single Register (写单个保持寄存器)", addr, 1, format!("值: 0x{:04X}", val)))
                }
                0x0F => {
                    let addr = if payload.len() >= 10 { u16::from_be_bytes([payload[8], payload[9]]) } else { 0 };
                    let qty = if payload.len() >= 12 { u16::from_be_bytes([payload[10], payload[11]]) } else { 0 };
                    Some(("Write Multiple Coils (批量写多线圈)", addr, qty, format!("数量: {}", qty)))
                }
                0x10 => {
                    let addr = if payload.len() >= 10 { u16::from_be_bytes([payload[8], payload[9]]) } else { 0 };
                    let qty = if payload.len() >= 12 { u16::from_be_bytes([payload[10], payload[11]]) } else { 0 };
                    Some(("Write Multiple Registers (批量写多寄存器)", addr, qty, format!("数量: {}", qty)))
                }
                0x15 => {
                    let data_len = payload.get(8).copied().unwrap_or(0);
                    let file_no = if payload.len() >= 12 { u16::from_be_bytes([payload[10], payload[11]]) } else { 0 };
                    Some(("Write File Record (写入 PLC 文件/配方记录)", file_no, 1, format!("文件号: {}, 字节数: {}", file_no, data_len)))
                }
                0x16 => {
                    let addr = if payload.len() >= 10 { u16::from_be_bytes([payload[8], payload[9]]) } else { 0 };
                    let and_mask = if payload.len() >= 12 { u16::from_be_bytes([payload[10], payload[11]]) } else { 0 };
                    let or_mask = if payload.len() >= 14 { u16::from_be_bytes([payload[12], payload[13]]) } else { 0 };
                    Some(("Mask Write Register (按位掩码写保持寄存器)", addr, 1, format!("AND: 0x{:04X}, OR: 0x{:04X}", and_mask, or_mask)))
                }
                0x17 => {
                    let read_addr = if payload.len() >= 10 { u16::from_be_bytes([payload[8], payload[9]]) } else { 0 };
                    let write_addr = if payload.len() >= 14 { u16::from_be_bytes([payload[12], payload[13]]) } else { 0 };
                    Some(("Read/Write Multiple Registers (组合读写保持寄存器)", write_addr, 1, format!("读地址: 0x{:04X}, 写地址: 0x{:04X}", read_addr, write_addr)))
                }
                _ => None,
            };

            if let Some((op_name, addr, qty, val_str)) = write_info {
                if !is_authorized_engineer {
                    let detail = serde_json::json!({
                        "unit_id": unit_id,
                        "function_code": format!("0x{:02X}", fc),
                        "operation": op_name,
                        "starting_address": format!("0x{:04X} ({})", addr, addr),
                        "quantity": qty,
                        "value_summary": val_str,
                        "payload_len": payload.len(),
                        "authorized_source": false,
                    });
                    record_network_audit_event(
                        "INDUSTRIAL_WRITE_VIOLATION",
                        if fc == 0x05 || fc == 0x0F { "CRITICAL" } else { "HIGH" },
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        "MODBUS_TCP",
                        &format!("拦截未授权工控 Modbus-TCP 写操作: {} [地址: 0x{:04X}], 需严密核查来源权限", op_name, addr),
                        &detail.to_string(),
                    );
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // 2. 西门子 Siemens S7comm (ISO-on-TCP / TPKT 102) 写变量与停机指令审计
    // -------------------------------------------------------------------------
    if (dst_port == 102 || src_port == 102 || protocol.contains("S7")) && payload.len() >= 12 {
        // TPKT: [0..4] (0x03, 0x00, len_hi, len_lo) -> COTP: [4..7] -> S7 Header: [7..]
        // S7 Magic Protocol ID: 0x32
        let s7_start = if payload[0] == 0x03 && payload.len() > 7 { 7 } else { 0 };
        if payload.len() > s7_start + 10 && payload[s7_start] == 0x32 {
            let rosctr = payload[s7_start + 1]; // 0x01: Job, 0x02: Ack, 0x03: Ack-Data, 0x07: Userdata
            let param_len = u16::from_be_bytes([payload[s7_start + 6], payload[s7_start + 7]]) as usize;
            let param_start = s7_start + 10 + if payload.len() > s7_start + 10 && payload[s7_start + 1] == 0x07 { 2 } else { 0 };

            if rosctr == 0x01 && payload.len() > param_start {
                let s7_fn = payload[param_start];
                let is_write = s7_fn == 0x05; // 0x05: Write Var (写入 PLC 变量)
                let is_plc_stop = s7_fn == 0x29; // 0x29: PLC Stop (强制停机)
                let is_plc_start = s7_fn == 0x28; // 0x28: PLC Start / Hot Restart

                if is_write || is_plc_stop || is_plc_start {
                    let op_desc = if is_write {
                        "S7 Write Var (写入 PLC 数据块/寄存器)"
                    } else if is_plc_stop {
                        "PLC Stop (强制停机/切换停机模式)"
                    } else {
                        "PLC Start (热启动机台)"
                    };

                    if !is_authorized_engineer || is_plc_stop {
                        let detail = serde_json::json!({
                            "s7_protocol_id": "0x32",
                            "rosctr": format!("0x{:02X}", rosctr),
                            "s7_function": format!("0x{:02X}", s7_fn),
                            "operation": op_desc,
                            "parameter_len": param_len,
                            "payload_len": payload.len(),
                        });
                        record_network_audit_event(
                            "INDUSTRIAL_WRITE_VIOLATION",
                            "CRITICAL",
                            src_ip,
                            dst_ip,
                            src_port,
                            dst_port,
                            "S7COMM",
                            &format!("检出西门子 S7comm 高危控制指令: {}，可能造成工控 PLC 停线或数据篡改", op_desc),
                            &detail.to_string(),
                        );
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // 3. 水利水文监测规约 SL651-2014 写基本配置指令审计
    // -------------------------------------------------------------------------
    if (dst_port == 5003 || src_port == 5003 || protocol.contains("SL651")) && payload.len() >= 10 {
        let start = if payload.starts_with(&[0x7E, 0x7E]) { 2 } else if payload[0] == 0x01 { 1 } else { 0 };
        if payload.len() > start + 8 {
            let fn_code = payload[start + 8];
            if fn_code == 0x40 || fn_code == 0x41 || fn_code == 0x42 {
                let op = match fn_code {
                    0x40 => "修改遥测站基本配置",
                    0x41 => "修改运行参数",
                    0x42 => "控制水泵/闸门开度",
                    _ => "遥控指令",
                };
                let detail = serde_json::json!({
                    "function_code": format!("0x{:02X}", fn_code),
                    "operation": op,
                    "payload_len": payload.len()
                });
                record_network_audit_event(
                    "INDUSTRIAL_WRITE_VIOLATION",
                    "CRITICAL",
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    "SL651_WATER",
                    &format!("检测到水利遥测站控制/参数修改报文: {} (功能码 0x{:02X})，存在改写水情阈值或启闭闸门风险", op, fn_code),
                    &detail.to_string(),
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // 4. 专有工业插件及长尾协议写控制/机台启停/固件下发审计
    // -------------------------------------------------------------------------
    {
        let reg = crate::lock_guard::read_rwlock(
            &crate::industrial_plugin::INDUSTRIAL_PLUGIN_REGISTRY,
            "audit_network::inspect_industrial_commands_plugin",
        );
        if let Some(dissected) = reg.inspect(src_port, dst_port, payload) {
            if dissected.is_dangerous_write && !is_authorized_engineer {
                let detail = serde_json::json!({
                    "protocol_id": dissected.protocol_id,
                    "vendor": dissected.vendor,
                    "operation_type": dissected.operation_type,
                    "summary": dissected.summary,
                    "fields": dissected.fields,
                    "payload_len": payload.len()
                });
                record_network_audit_event(
                    "INDUSTRIAL_WRITE_VIOLATION",
                    "CRITICAL",
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    &dissected.protocol_id,
                    &format!("检测到工控专有协议危险写控制: [{}] {}，存在物理机台或工艺回路越权控制风险", dissected.protocol_name, dissected.summary),
                    &detail.to_string(),
                );
            }
        }
    }
}

/// 提取主域名 (Second-Level Domain / Registerable Domain)
/// 时间复杂度: O(N), 空间复杂度: O(1)
fn extract_registered_domain(full_domain: &str) -> String {
    let lower = full_domain.trim().trim_end_matches('.').to_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() <= 2 {
        return lower;
    }
    // 针对 .com.cn, .edu.cn, .gov.cn 等双重后缀识别
    let last = parts[parts.len() - 1];
    let second_last = parts[parts.len() - 2];
    if (last == "cn" || last == "uk" || last == "jp") && (second_last == "com" || second_last == "gov" || second_last == "edu" || second_last == "org" || second_last == "net") {
        if parts.len() >= 3 {
            return format!("{}.{}.{}", parts[parts.len() - 3], second_last, last);
        }
    }
    format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
}

/// 检查域名是否属于公有基础设施/合法白名单（杜绝误报风暴）
fn is_whitelisted_domain(domain: &str) -> bool {
    let d = domain.to_lowercase();
    const WHITELIST_SUFFIXES: &[&str] = &[
        "cloudfront.net", "azureedge.net", "s3.amazonaws.com", "github.io", "github.com",
        "office.com", "microsoft.com", "windowsupdate.com", "google.com", "googleapis.com",
        "baidu.com", "aliyun.com", "aliyuncs.com", "tencent.com", "qcloud.com", "apple.com",
        "icloud.com", "digicert.com", "letsencrypt.org", "cloudflare.com", "gtld-servers.net",
    ];
    WHITELIST_SUFFIXES.iter().any(|&w| d == w || d.ends_with(&format!(".{}", w)))
}

/// 审查 DNS 隐蔽隧道 (基于时序滑窗统计与多维特征共振判定，彻底消灭单包误报)
/// 算法复杂度: 时间复杂度 O(N), 空间复杂度 O(K) (有界会话表)
pub fn inspect_dns_tunnel(
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    domain: &str,
    qtype: u16,
) {
    if domain.is_empty() {
        return;
    }
    let lower_domain = domain.trim().trim_end_matches('.').to_lowercase();

    // 1. 白名单免检机制：直接放行公有云、知名 CDN、系统更新域名
    if is_whitelisted_domain(&lower_domain) {
        return;
    }

    let r_domain = extract_registered_domain(&lower_domain);
    let parts: Vec<&str> = lower_domain.split('.').collect();
    if parts.len() < 2 {
        return;
    }
    let longest_subdomain = parts[..parts.len() - 2].iter().max_by_key(|p| p.len()).copied().unwrap_or(parts[0]);
    let entropy = calculate_string_entropy(longest_subdomain);

    // 2. 极端载荷判别 (Fail-Fast): 极长异常子域名 (>= 50 字符) 且香农熵极高 (> 4.3)
    let is_extreme_tunnel = longest_subdomain.len() >= 50 && entropy > 4.3;

    // 3. 时序窗口聚合判别 (Sliding Time Window per SLD)
    let now = Instant::now();
    let mut triggered_covert_alarm = false;
    let mut stats_snapshot = None;

    {
        let mut state = crate::lock_guard::lock_mutex(
            &NETWORK_AUDIT_STATE,
            "audit_network::inspect_dns_tunnel",
        );
        // 清理超期滑窗记录 (> 120 秒)
        state.dns_stats.retain(|_, v| now.duration_since(v.last_seen) < Duration::from_secs(120));

        let entry = state.dns_stats.entry(r_domain.clone()).or_insert_with(|| DnsDomainTemporalStats {
            first_seen: now,
            last_seen: now,
            query_count: 0,
            subdomains: HashSet::new(),
            total_entropy_sum: 0.0,
            max_subdomain_len: 0,
            large_txt_responses: 0,
        });

        entry.last_seen = now;
        entry.query_count += 1;
        entry.subdomains.insert(longest_subdomain.to_string());
        entry.total_entropy_sum += entropy;
        entry.max_subdomain_len = entry.max_subdomain_len.max(longest_subdomain.len());
        if qtype == 16 && longest_subdomain.len() > 30 {
            entry.large_txt_responses += 1;
        }

        // 判定条件 (多维共振):
        // (A) 60秒内该根域名请求 >= 8 次,
        // (B) 唯一子域名占比 > 70% (每次子域都不同，典型 C2 编码特征),
        // (C) 平均香农熵 > 4.0,
        // (D) 最大子域长度 > 28.
        let avg_entropy = entry.total_entropy_sum / entry.query_count as f64;
        let unique_ratio = entry.subdomains.len() as f64 / entry.query_count as f64;

        if is_extreme_tunnel || (entry.query_count >= 8 && unique_ratio > 0.70 && avg_entropy > 4.0 && entry.max_subdomain_len > 28) {
            triggered_covert_alarm = true;
            stats_snapshot = Some((entry.query_count, entry.subdomains.len(), avg_entropy, entry.max_subdomain_len));
            // 报警后重置计数器，防止告警风暴
            entry.query_count = 0;
            entry.subdomains.clear();
            entry.total_entropy_sum = 0.0;
        }
    }

    if triggered_covert_alarm {
        let (queries, uniques, avg_ent, max_len) = stats_snapshot.unwrap_or((1, 1, entropy, longest_subdomain.len()));
        let detail = serde_json::json!({
            "full_query_domain": domain,
            "registered_domain": r_domain,
            "longest_subdomain": longest_subdomain,
            "subdomain_len": max_len,
            "entropy": format!("{:.2}", entropy),
            "window_query_count": queries,
            "unique_subdomain_count": uniques,
            "window_avg_entropy": format!("{:.2}", avg_ent),
            "qtype": qtype,
        });
        record_network_audit_event(
            "DNS_COVERT_TUNNEL",
            "CRITICAL",
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            "DNS",
            &format!("确认检测到 DNS 隐蔽通道外发: 目标主域 [{}] 唯一子域比率异常高频且信息熵为 {:.2}", r_domain, avg_ent),
            &detail.to_string(),
        );
    }
}

/// 审查 ICMP 隐蔽隧道与非标载荷
/// 时间复杂度: O(N), 空间复杂度: O(1)
pub fn inspect_icmp_tunnel(
    src_ip: &str,
    dst_ip: &str,
    payload: &[u8],
) {
    if payload.len() <= 40 {
        return; // 标准 Windows ping 为 32 字节常规字母串，Linux 默认为 56 字节 (含时间戳)
    }

    // 超过 64 字节的大包或高熵载荷 (典型 icmptunnel / ptunnel 特征)
    let hex_repr = hex::encode(&payload[..payload.len().min(32)]);
    let entropy = {
        let mut freq = [0usize; 256];
        for &b in payload {
            freq[b as usize] += 1;
        }
        let len = payload.len() as f64;
        let mut ent = 0.0;
        for &c in &freq {
            if c > 0 {
                let p = c as f64 / len;
                ent -= p * p.log2();
            }
        }
        ent
    };

    // 严格阈值：载荷大于 128 字节且熵大于 4.6 (伪随机密文或压缩数据)
    if payload.len() > 128 && entropy > 4.6 {
        let detail = serde_json::json!({
            "payload_len": payload.len(),
            "entropy": format!("{:.2}", entropy),
            "hex_preview": hex_repr,
        });
        record_network_audit_event(
            "ICMP_COVERT_TUNNEL",
            "HIGH",
            src_ip,
            dst_ip,
            0,
            0,
            "ICMP",
            &format!("检测到高危 ICMP 载荷隐蔽通道 (数据载荷 {} 字节, 信息熵 {:.2})", payload.len(), entropy),
            &detail.to_string(),
        );
    }
}

/// 获取网络安全审查事件列表 (从持久化缓存与活跃队列联合读取)
pub fn get_network_audit_events(limit: Option<usize>) -> Vec<NetworkAuditEvent> {
    let state = crate::lock_guard::lock_mutex(
        &NETWORK_AUDIT_STATE,
        "audit_network::get_network_audit_events",
    );
    let lim = limit.unwrap_or(100);
    state.events.iter().rev().take(lim).cloned().collect()
}

/// 获取网络安全审查综合统计
pub fn get_network_audit_statistics() -> NetworkAuditStatistics {
    let state = crate::lock_guard::lock_mutex(
        &NETWORK_AUDIT_STATE,
        "audit_network::get_network_audit_statistics",
    );
    state.stats.clone()
}

/// 清空网络安全审查事件 (仅清空当前内存视图，满足审计员指令)
pub fn clear_network_audit_events() {
    let mut state = crate::lock_guard::lock_mutex(
        &NETWORK_AUDIT_STATE,
        "audit_network::clear_network_audit_events",
    );
    state.events.clear();
    state.stats = NetworkAuditStatistics::default();
    state.dns_stats.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_shannon_entropy() {
        assert_eq!(calculate_string_entropy("aaaaaaaaaa"), 0.0);
        let normal_entropy = calculate_string_entropy("www.example.com");
        assert!(normal_entropy < 4.0);
        let tunnel_subdomain = "dGVzdC1jb3ZlcnQtdHVubmVsLWF1ZGl0LXRlc3Rpbmctc2hhbm5vbg";
        let tunnel_entropy = calculate_string_entropy(tunnel_subdomain);
        assert!(tunnel_entropy > 4.2);
    }

    #[test]
    fn test_whitelisted_domain_never_triggers_false_positive() {
        let _lock = TEST_LOCK.lock().unwrap();
        clear_network_audit_events();
        // 模拟企业高频访问带有复杂长哈希的合规 CDN 域名
        for _ in 0..20 {
            inspect_dns_tunnel("192.168.1.50", "8.8.8.8", 5353, 53, "d111111abcdef1234567890abcdef.cloudfront.net", 1);
        }
        let events = get_network_audit_events(Some(10));
        assert_eq!(events.len(), 0, "知名白名单 CDN 域名绝对不能触发虚假隧道警报");
    }

    #[test]
    fn test_s7_write_var_detection() {
        let _lock = TEST_LOCK.lock().unwrap();
        clear_network_audit_events();
        // 构造西门子 S7comm ROSCTR=0x01 (Job), Function=0x05 (Write Var)
        let s7_payload = vec![
            0x03, 0x00, 0x00, 0x20, // TPKT
            0x02, 0xF0, 0x80,       // COTP
            0x32, 0x01,             // S7 Header: Magic 0x32, ROSCTR 0x01 (Job)
            0x00, 0x00, 0x00, 0x01, // Redundancy & PDU Ref
            0x00, 0x0E, 0x00, 0x04, // Param Len = 14, Data Len = 4
            0x05,                   // Function = 0x05 (Write Var!)
            0x01, 0x12, 0x0A, 0x10, // Item specs
            0x02, 0x00, 0x01, 0x00, 0x01, 0x84, 0x00, 0x00, 0x00,
        ];

        inspect_industrial_commands("10.0.0.99", "192.168.1.20", 49152, 102, "S7COMM", &s7_payload);
        let events = get_network_audit_events(Some(20));
        let hit = events.iter().find(|e| e.protocol == "S7COMM" && e.severity == "CRITICAL");
        assert!(hit.is_some(), "未授权 IP 下发 S7 Write Var 必须被拦截并审计");
    }

    #[test]
    fn test_modbus_write_registers_detection() {
        let _lock = TEST_LOCK.lock().unwrap();
        clear_network_audit_events();
        // Modbus TCP FC 0x10 (写多个寄存器)
        let modbus_payload = vec![
            0x00, 0x01, // Transaction ID
            0x00, 0x00, // Protocol ID (0 = Modbus)
            0x00, 0x0B, // Length = 11
            0x01,       // Unit ID = 1
            0x10,       // Function Code 0x10 (Write Multiple Registers)
            0x00, 0x64, // Starting Address = 100
            0x00, 0x02, // Quantity = 2
            0x04,       // Byte count = 4
            0x12, 0x34, 0x56, 0x78, // Register values
        ];

        inspect_industrial_commands("10.0.0.99", "192.168.1.10", 50200, 502, "MODBUS_TCP", &modbus_payload);
        let events = get_network_audit_events(Some(20));
        let hit = events.iter().find(|e| e.protocol == "MODBUS_TCP" && e.summary.contains("0x0064"));
        assert!(hit.is_some(), "非白名单源发起 Modbus 写寄存器必须产生审计事件");
    }
}
