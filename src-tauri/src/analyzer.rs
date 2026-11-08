use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::Emitter;

// ===== AI 3-Sigma 异常基线与未知端口盲区探测引擎 =====
struct FlowBaseline {
    events: VecDeque<Instant>,
    ema_rate: f64, 
    ema_var: f64, 
    hist_ports: std::collections::HashSet<u16>,
    current_ports: std::collections::HashSet<u16>,
    last_window_reset: Instant,
}

impl FlowBaseline {
    fn new() -> Self {
        Self { 
            events: VecDeque::new(), 
            ema_rate: 0.0, 
            ema_var: 0.0,
            hist_ports: std::collections::HashSet::new(),
            current_ports: std::collections::HashSet::new(),
            last_window_reset: Instant::now(),
        }
    }

    fn push_and_analyze(&mut self, dst_port: u16) -> (Option<(f64, f64)>, Option<Vec<u16>>) {
        let now = Instant::now();
        self.events.push_back(now);
        let window = Duration::from_secs(30);
        while let Some(&t) = self.events.front() {
            if now.duration_since(t) > window {
                self.events.pop_front();
            } else {
                break;
            }
        }
        let rate = self.events.len() as f64;
        let alpha = 0.05;
        let diff = rate - self.ema_rate;
        self.ema_rate += alpha * diff;
        self.ema_var = (1.0 - alpha) * self.ema_var + alpha * diff * diff;
        let sigma = self.ema_var.sqrt();
        let threshold = self.ema_rate + 3.0 * sigma;
        let rate_alert = if rate > threshold && rate > 5.0 {
            Some((rate, threshold))
        } else {
            None
        };

        // 端口盲区探测算法 (10秒切片差集比对)
        if dst_port > 0 {
            self.current_ports.insert(dst_port);
        }
        let mut scan_alert = None;
        if now.duration_since(self.last_window_reset) >= Duration::from_secs(10) {
            let new_ports: Vec<u16> = self.current_ports.difference(&self.hist_ports).copied().collect();
            if !self.hist_ports.is_empty() && new_ports.len() >= 3 {
                scan_alert = Some(new_ports);
            }
            self.hist_ports.extend(self.current_ports.drain());
            self.last_window_reset = now;
        }

        (rate_alert, scan_alert)
    }
}

static BASELINES: Lazy<Arc<Mutex<HashMap<String, FlowBaseline>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

pub fn check_anomaly(src_ip: &str, dst_port: u16) -> Option<String> {
    let mut map = BASELINES.lock().unwrap();
    let b = map.entry(src_ip.to_string()).or_insert_with(FlowBaseline::new);
    let (rate_res, scan_res) = b.push_and_analyze(dst_port);

    if let Some(new_ports) = scan_res {
        return Some(format!(
            "[AI-PORT] 🚨 端口扫描预警: {} 偏离历史基线! 正在试探未知盲区端口: {:?}",
            src_ip, new_ports
        ));
    }
    if let Some((rate, thresh)) = rate_res {
        return Some(format!(
            "[AI-3σ] 🚨 异常流量检测: {} | 速率={:.1}pps > 阈值={:.1}pps",
            src_ip, rate, thresh
        ));
    }
    None
}

// ===== 实时波形追踪引擎 =====
struct WaveConfig {
    active: bool,
    target_ip: String,
    byte_offset: usize,
    byte_length: usize,
    signed: bool,
    little_endian: bool,
}

static WAVE_CONFIG: Lazy<Arc<Mutex<WaveConfig>>> = Lazy::new(|| {
    Arc::new(Mutex::new(WaveConfig {
        active: false,
        target_ip: String::new(),
        byte_offset: 0,
        byte_length: 2,
        signed: false,
        little_endian: false,
    }))
});

#[derive(Clone, Serialize)]
pub struct WavePoint {
    pub ip: String,
    pub value: i64,
    pub ts_ms: u128,
}

pub fn configure_wave_tracker(ip: String, offset: usize, length: usize, signed: bool, little_endian: bool) {
    let mut cfg = WAVE_CONFIG.lock().unwrap();
    cfg.active = true;
    cfg.target_ip = ip;
    cfg.byte_offset = offset;
    cfg.byte_length = length;
    cfg.signed = signed;
    cfg.little_endian = little_endian;
}

pub fn process_wave_sample(app: &tauri::AppHandle, src_ip: &str, payload: &[u8]) {
    let cfg = WAVE_CONFIG.lock().unwrap();
    if !cfg.active || cfg.target_ip != src_ip {
        return;
    }
    let end = cfg.byte_offset + cfg.byte_length;
    if payload.len() < end {
        return;
    }
    let chunk = &payload[cfg.byte_offset..end];
    let value = decode_wave_bytes(chunk, cfg.signed, cfg.little_endian);
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let _ = app.emit("wave-data", WavePoint { ip: src_ip.to_string(), value, ts_ms });
}

/// 示波器字节解码核心算法（纯函数，零分配）
/// 时间复杂度: O(L), L 为字节长度 (通常 1~8)
/// 空间复杂度: O(1)
pub fn decode_wave_bytes(chunk: &[u8], signed: bool, little_endian: bool) -> i64 {
    if chunk.is_empty() {
        return 0;
    }
    let raw = if little_endian {
        chunk.iter().rev().fold(0i64, |acc, &b| (acc << 8) | b as i64)
    } else {
        chunk.iter().fold(0i64, |acc, &b| (acc << 8) | b as i64)
    };
    if signed && !chunk.is_empty() && chunk.len() <= 8 {
        let sign = 1i64 << (chunk.len() * 8 - 1);
        if raw & sign != 0 {
            raw - (1i64 << (chunk.len() * 8))
        } else {
            raw
        }
    } else {
        raw
    }
}

// ===== LCS 智能矩阵比对引擎 =====
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ByteCell {
    pub hex: String,
    pub ascii: String,
    pub diff_type: String, // "equal"|"replace"|"insert"|"delete"
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HexRow {
    pub offset: String,
    pub cells: Vec<ByteCell>,
    pub ascii_repr: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ParsedPayload {
    pub label: String,
    pub byte_length: usize,
    pub hex_rows: Vec<HexRow>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SmartDiffResult {
    pub mode: String,
    pub payloads: Vec<ParsedPayload>,
    pub summary: String,
}

pub fn smart_diff_payloads(raw_strings: Vec<String>) -> Result<SmartDiffResult, String> {
    smart_diff_payloads_labeled(raw_strings, Vec::new())
}

/// 带样本来源标签的矩阵比对核心（labels 为空或长度不匹配时回退默认"样本 XX"标签）
pub fn smart_diff_payloads_labeled(
    raw_strings: Vec<String>,
    labels: Vec<String>,
) -> Result<SmartDiffResult, String> {
    if raw_strings.len() < 2 {
        return Err("至少需要 2 个样本进行比对".into());
    }

    // 标签有效性裁决：长度不匹配一律回退默认标签（防御性，杜绝错位标注）
    let use_labels = labels.len() == raw_strings.len();
    let label_of = |i: usize| -> String {
        if use_labels {
            labels[i].clone()
        } else if raw_strings.len() == 2 {
            if i == 0 { "样本 A".into() } else { "样本 B".into() }
        } else {
            format!("样本 {:02}", i + 1)
        }
    };

    let payloads: Vec<Vec<u8>> = raw_strings
        .iter()
        .map(|s| {
            let clean = s.replace(' ', "");
            hex::decode(&clean).unwrap_or_else(|_| s.as_bytes().to_vec())
        })
        .collect();

    if payloads.len() == 2 {
        let tags_a = lcs_diff_tags(&payloads[0], &payloads[1], true);
        let tags_b = lcs_diff_tags(&payloads[0], &payloads[1], false);
        let pa = build_hex_rows(&payloads[0], &tags_a, &label_of(0));
        let pb = build_hex_rows(&payloads[1], &tags_b, &label_of(1));
        let changes = tags_a.iter().filter(|t| t.as_str() != "equal").count();
        Ok(SmartDiffResult {
            mode: "smart_diff".into(),
            payloads: vec![pa, pb],
            summary: format!("智能对齐比对: {} 个字节发生突变（替换/插入/删除）", changes),
        })
    } else {
        let max_len = payloads.iter().map(|p| p.len()).max().unwrap_or(0);
        let mutating: std::collections::HashSet<usize> = (0..max_len)
            .filter(|&i| {
                let vals: std::collections::HashSet<u8> =
                    payloads.iter().filter_map(|p| p.get(i)).copied().collect();
                vals.len() > 1
            })
            .collect();

        let parsed: Vec<ParsedPayload> = payloads
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let tags: Vec<String> = (0..p.len())
                    .map(|j| {
                        if mutating.contains(&j) {
                            "replace".into()
                        } else {
                            "equal".into()
                        }
                    })
                    .collect();
                build_hex_rows(p, &tags, &label_of(i))
            })
            .collect();

        Ok(SmartDiffResult {
            mode: "vertical_diff".into(),
            payloads: parsed,
            summary: format!(
                "垂直比对: {} 个字节位跳动（{} 个样本）",
                mutating.len(),
                payloads.len()
            ),
        })
    }
}

/// 固化特征报文为历史基线库 (写入 baseline_payloads.json，锚定统一数据目录)
pub fn save_baseline_payloads(payloads: Vec<String>) -> Result<usize, String> {
    if payloads.is_empty() {
        return Err("传入的基线报文列表为空".into());
    }
    let count = payloads.len();
    let json_str = serde_json::to_string_pretty(&payloads)
        .map_err(|e| format!("基线序列化失败: {}", e))?;
    std::fs::write(crate::forensics::data_path("baseline_payloads.json"), json_str)
        .map_err(|e| format!("写入 baseline_payloads.json 失败: {}", e))?;
    Ok(count)
}

/// 读取历史基线库（锚定统一数据目录）
pub fn load_baseline_payloads() -> Result<Vec<String>, String> {
    let path = crate::forensics::data_path("baseline_payloads.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("读取 baseline_payloads.json 失败: {}", e))?;
    let list: Vec<String> = serde_json::from_str(&content)
        .map_err(|e| format!("解析 baseline_payloads.json 失败: {}", e))?;
    Ok(list)
}

/// 联合历史基线矩阵比对: 将当前选中的报文样本与历史基线样本联合进行多维差分
/// 【样本来源标签】基线样本标记 [历史基线]，当前样本标记 [实时截获]，
/// 透传至前端 ParsedPayload.label，杜绝来源混淆导致的取证误判
pub fn compare_with_historical_baseline(current_payloads: Vec<String>) -> Result<SmartDiffResult, String> {
    let baseline = load_baseline_payloads()?;
    if baseline.is_empty() && current_payloads.len() < 2 {
        return Err("历史基线库为空，且当前输入样本不足 2 个，无法执行矩阵比对".into());
    }
    let baseline_count = baseline.len();
    let current_count = current_payloads.len();
    let mut all_samples = Vec::with_capacity(baseline_count + current_count);
    let mut labels = Vec::with_capacity(baseline_count + current_count);
    for (i, b) in baseline.into_iter().enumerate() {
        all_samples.push(b);
        labels.push(format!("历史基线 {:02}", i + 1));
    }
    for (i, s) in current_payloads.into_iter().enumerate() {
        all_samples.push(s);
        labels.push(format!("实时截获 {:02}", i + 1));
    }
    let mut result = smart_diff_payloads_labeled(all_samples, labels)?;
    result.summary = format!(
        "联合矩阵比对: {} 条历史基线 + {} 条实时截获 | {}",
        baseline_count, current_count, result.summary
    );
    Ok(result)
}


/// LCS (Longest Common Subsequence) 字节差分算法
fn lcs_diff_tags(a: &[u8], b: &[u8], is_a: bool) -> Vec<String> {
    let n = a.len();
    let m = b.len();

    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in 1..=n {
        for j in 1..=m {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }

    let mut ops_a: Vec<(&str, usize)> = Vec::new();
    let mut ops_b: Vec<(&str, usize)> = Vec::new();
    let (mut i, mut j) = (n, m);

    while i > 0 || j > 0 {
        if i > 0 && j > 0 && a[i - 1] == b[j - 1] {
            ops_a.push(("equal", i - 1));
            ops_b.push(("equal", j - 1));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            ops_b.push(("insert", j - 1));
            j -= 1;
        } else {
            ops_a.push(("delete", i - 1));
            i -= 1;
        }
    }

    ops_a.reverse();
    ops_b.reverse();

    let del_c = ops_a.iter().filter(|(t, _)| *t == "delete").count();
    let ins_c = ops_b.iter().filter(|(t, _)| *t == "insert").count();
    let use_replace = del_c > 0 && ins_c > 0;

    let target = if is_a { &ops_a } else { &ops_b };
    let size = if is_a { n } else { m };
    let mut result = vec!["equal".to_string(); size];
    for (op, idx) in target {
        result[*idx] = if use_replace && (*op == "delete" || *op == "insert") {
            "replace".into()
        } else {
            op.to_string()
        };
    }
    result
}

fn build_hex_rows(payload: &[u8], tags: &[String], label: &str) -> ParsedPayload {
    let mut hex_rows = Vec::new();
    for chunk_start in (0..payload.len()).step_by(16) {
        let chunk = &payload[chunk_start..payload.len().min(chunk_start + 16)];
        let cells: Vec<ByteCell> = chunk
            .iter()
            .enumerate()
            .map(|(i, &b)| ByteCell {
                hex: format!("{:02X}", b),
                ascii: if (32..=126).contains(&b) {
                    (b as char).to_string()
                } else {
                    ".".into()
                },
                diff_type: tags
                    .get(chunk_start + i)
                    .cloned()
                    .unwrap_or_else(|| "equal".into()),
            })
            .collect();
        let ascii_repr: String = chunk
            .iter()
            .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })
            .collect();
        hex_rows.push(HexRow {
            offset: format!("{:04X}", chunk_start),
            cells,
            ascii_repr,
        });
    }
    ParsedPayload {
        label: label.to_string(),
        byte_length: payload.len(),
        hex_rows,
    }
}

// ============================================================
// 报文样本库归档与双报文深度差分工作台 (Packet Sample Archival & Deep Dual-Packet Diff)
// 100% 工业生产级实现：Wireshark + Beyond Compare 双栏同步滚动与协议树差分
// ============================================================

/// 报文特征样本归档实体
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StoredPacketSample {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub packet: crate::sniffer::PacketRecord,
}

/// 协议树单字段差异项
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FieldDiffItem {
    pub layer: String,
    pub field_name: String,
    pub val_a: String,
    pub val_b: String,
    pub is_different: bool,
    pub diff_type: String, // "EQUAL" | "CHANGED" | "ADDED_IN_B" | "MISSING_IN_B"
}

/// 双报文深度差分综合结果实体
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DualPacketDiffResult {
    pub packet_a_id: u64,
    pub packet_b_id: u64,
    pub packet_a_desc: String,
    pub packet_b_desc: String,
    pub total_bytes_a: usize,
    pub total_bytes_b: usize,
    pub mutated_bytes_count: usize,
    pub mutation_rate_percent: f64,
    pub hex_diff_a: ParsedPayload,
    pub hex_diff_b: ParsedPayload,
    pub field_diffs: Vec<FieldDiffItem>,
    pub summary: String,
}

/// 获取报文样本归档主目录
fn get_packet_samples_dir() -> std::path::PathBuf {
    let dir = crate::forensics::data_path("packet_samples");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// 保存指定报文至样本归档库
/// 时间复杂度: O(P), P 为报文载荷长度
/// 空间复杂度: O(P)
pub fn save_packet_sample(name: String, packet: crate::sniffer::PacketRecord) -> Result<String, String> {
    let dir = get_packet_samples_dir();
    let sample_id = format!("sample_{}_{}", packet.id, chrono::Local::now().format("%Y%m%d_%H%M%S_%3f"));
    let sample_name = if name.trim().is_empty() {
        format!("报文 #{}_{}", packet.id, packet.protocol)
    } else {
        name
    };
    let created_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let sample = StoredPacketSample {
        id: sample_id.clone(),
        name: sample_name,
        created_at,
        packet,
    };

    let file_path = dir.join(format!("{}.json", sample_id));
    let json_bytes = serde_json::to_vec_pretty(&sample)
        .map_err(|e| format!("序列化报文样本失败: {}", e))?;

    std::fs::write(&file_path, json_bytes)
        .map_err(|e| format!("写入报文样本文件失败: {}", e))?;

    Ok(sample_id)
}

/// 列出所有已保存的报文样本
pub fn list_packet_samples() -> Result<Vec<StoredPacketSample>, String> {
    let dir = get_packet_samples_dir();
    let mut list = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(sample) = serde_json::from_str::<StoredPacketSample>(&content) {
                        list.push(sample);
                    }
                }
            }
        }
    }

    list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(list)
}

/// 删除指定 ID 的报文样本
pub fn delete_packet_sample(id: &str) -> Result<bool, String> {
    let dir = get_packet_samples_dir();
    let file_path = dir.join(format!("{}.json", id));
    if file_path.exists() {
        std::fs::remove_file(&file_path)
            .map_err(|e| format!("删除报文样本失败: {}", e))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// 双报文深度差分对比引擎（Wireshark 协议树 + Beyond Compare 逐字节 Hex 对齐）
/// 时间复杂度: O(N * M) (LCS 矩阵), N、M 分别为两报文载荷字节数
/// 空间复杂度: O(N * M)
pub fn compare_two_packets(
    packet_a: crate::sniffer::PacketRecord,
    packet_b: crate::sniffer::PacketRecord,
) -> Result<DualPacketDiffResult, String> {
    // 1. 协议树逐层字段差分
    let mut field_diffs = Vec::new();

    let mut add_field = |layer: &str, name: &str, val_a: &str, val_b: &str| {
        let is_diff = val_a != val_b;
        let diff_type = if !is_diff {
            "EQUAL".to_string()
        } else if val_a.is_empty() && !val_b.is_empty() {
            "ADDED_IN_B".to_string()
        } else if !val_a.is_empty() && val_b.is_empty() {
            "MISSING_IN_B".to_string()
        } else {
            "CHANGED".to_string()
        };
        field_diffs.push(FieldDiffItem {
            layer: layer.to_string(),
            field_name: name.to_string(),
            val_a: val_a.to_string(),
            val_b: val_b.to_string(),
            is_different: is_diff,
            diff_type,
        });
    };

    // L2 链路层
    add_field("链路层 (L2)", "源 MAC 地址", &packet_a.mac_src, &packet_b.mac_src);
    add_field("链路层 (L2)", "目的 MAC 地址", &packet_a.mac_dst, &packet_b.mac_dst);

    // L3 网络层
    add_field("网络层 (L3)", "协议类型", &packet_a.protocol, &packet_b.protocol);
    add_field("网络层 (L3)", "传输层协议", &packet_a.transport, &packet_b.transport);
    add_field("网络层 (L3)", "数据流向", &packet_a.direction, &packet_b.direction);
    add_field("网络层 (L3)", "源 IP 地址", &packet_a.src_ip, &packet_b.src_ip);
    add_field("网络层 (L3)", "目的 IP 地址", &packet_a.dst_ip, &packet_b.dst_ip);

    // L4 传输层
    add_field("传输层 (L4)", "源端口", &packet_a.src_port.to_string(), &packet_b.src_port.to_string());
    add_field("传输层 (L4)", "目的端口", &packet_a.dst_port.to_string(), &packet_b.dst_port.to_string());
    add_field("传输层 (L4)", "载荷长度", &format!("{} 字节", packet_a.length), &format!("{} 字节", packet_b.length));
    add_field(
        "传输层 (L4)",
        "载荷信息熵",
        &format!("{:.3} ({})", packet_a.entropy, packet_a.entropy_level),
        &format!("{:.3} ({})", packet_b.entropy, packet_b.entropy_level),
    );

    // L7 工业应用层业务数据
    let mut all_business_keys = std::collections::BTreeSet::new();
    if let Some(ref bd_a) = packet_a.business_data {
        for k in bd_a.keys() {
            all_business_keys.insert(k.clone());
        }
    }
    if let Some(ref bd_b) = packet_b.business_data {
        for k in bd_b.keys() {
            all_business_keys.insert(k.clone());
        }
    }

    for k in all_business_keys {
        let val_a = packet_a
            .business_data
            .as_ref()
            .and_then(|bd| bd.get(&k))
            .map(|v| v.to_string().trim_matches('"').to_string())
            .unwrap_or_default();
        let val_b = packet_b
            .business_data
            .as_ref()
            .and_then(|bd| bd.get(&k))
            .map(|v| v.to_string().trim_matches('"').to_string())
            .unwrap_or_default();

        let display_name = match k.as_str() {
            "function_code" => "工业功能码 (Function Code)".to_string(),
            "transaction_id" => "事务元标识 (Transaction ID)".to_string(),
            "unit_id" => "从机/单元号 (Unit ID)".to_string(),
            "register_address" => "寄存器起始地址".to_string(),
            "register_count" => "寄存器读取数量".to_string(),
            other => format!("业务字段 [{}]", other),
        };
        add_field("应用层 (L7)", &display_name, &val_a, &val_b);
    }

    // 2. 逐字节 Hex 对齐差分
    let raw_hex_a = if !packet_a.payload_hex.is_empty() {
        &packet_a.payload_hex
    } else {
        &packet_a.raw_frame_hex
    };
    let raw_hex_b = if !packet_b.payload_hex.is_empty() {
        &packet_b.payload_hex
    } else {
        &packet_b.raw_frame_hex
    };

    let clean_a = raw_hex_a.replace([' ', '\n', '\r'], "");
    let clean_b = raw_hex_b.replace([' ', '\n', '\r'], "");

    let bytes_a = hex::decode(&clean_a).unwrap_or_else(|_| clean_a.as_bytes().to_vec());
    let bytes_b = hex::decode(&clean_b).unwrap_or_else(|_| clean_b.as_bytes().to_vec());

    let tags_a = lcs_diff_tags(&bytes_a, &bytes_b, true);
    let tags_b = lcs_diff_tags(&bytes_a, &bytes_b, false);

    let desc_a = format!("#{} {} ({}:{} ➔ {}:{})", packet_a.id, packet_a.protocol, packet_a.src_ip, packet_a.src_port, packet_a.dst_ip, packet_a.dst_port);
    let desc_b = format!("#{} {} ({}:{} ➔ {}:{})", packet_b.id, packet_b.protocol, packet_b.src_ip, packet_b.src_port, packet_b.dst_ip, packet_b.dst_port);

    let hex_diff_a = build_hex_rows(&bytes_a, &tags_a, &format!("基准报文 A: {}", desc_a));
    let hex_diff_b = build_hex_rows(&bytes_b, &tags_b, &format!("比对报文 B: {}", desc_b));

    let mutated_a = tags_a.iter().filter(|t| t.as_str() != "equal").count();
    let mutated_b = tags_b.iter().filter(|t| t.as_str() != "equal").count();
    let mutated_bytes_count = mutated_a.max(mutated_b);

    let max_len = bytes_a.len().max(bytes_b.len());
    let mutation_rate_percent = if max_len > 0 {
        (mutated_bytes_count as f64 / max_len as f64) * 100.0
    } else {
        0.0
    };

    let diff_fields_count = field_diffs.iter().filter(|f| f.is_different).count();
    let summary = format!(
        "双报文比对完成: 协议字段存在 {} 项差异 | 载荷突变字节数: {}/{} ({:.1}%)",
        diff_fields_count, mutated_bytes_count, max_len, mutation_rate_percent
    );

    Ok(DualPacketDiffResult {
        packet_a_id: packet_a.id,
        packet_b_id: packet_b.id,
        packet_a_desc: desc_a,
        packet_b_desc: desc_b,
        total_bytes_a: bytes_a.len(),
        total_bytes_b: bytes_b.len(),
        mutated_bytes_count,
        mutation_rate_percent,
        hex_diff_a,
        hex_diff_b,
        field_diffs,
        summary,
    })
}

// ============================================================
// IO Graphs 高精时序曲线聚合引擎 (包率/带宽/TCP RTT/重传)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoGraphBucket {
    pub timestamp_sec: u64,
    pub packet_count: u32,
    pub byte_count: u64,
    pub avg_rtt_ms: f64,
    pub rtt_samples: u32,
    pub retrans_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoGraphSeries {
    pub buckets: Vec<IoGraphBucket>,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub global_avg_rtt_ms: f64,
    pub max_bandwidth_bps: u64,
}

static IO_GRAPH_BUFFER: Lazy<Arc<Mutex<VecDeque<IoGraphBucket>>>> =
    Lazy::new(|| Arc::new(Mutex::new(VecDeque::with_capacity(600))));

/// 记录单包时序指标 (供网卡抓包、串口、USB 流式调用)
/// 时间复杂度: O(1)
/// 空间复杂度: O(1)
pub fn record_packet_io(length: usize, rtt_ms: Option<f64>, is_retrans: bool) {
    let now_sec = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    };

    if let Ok(mut buf) = IO_GRAPH_BUFFER.lock() {
        if let Some(last) = buf.back_mut() {
            if last.timestamp_sec == now_sec {
                last.packet_count += 1;
                last.byte_count += length as u64;
                if is_retrans {
                    last.retrans_count += 1;
                }
                if let Some(rtt) = rtt_ms {
                    let total_rtt = last.avg_rtt_ms * (last.rtt_samples as f64) + rtt;
                    last.rtt_samples += 1;
                    last.avg_rtt_ms = total_rtt / (last.rtt_samples as f64);
                }
                return;
            }
        }

        // 新秒时间桶
        let new_bucket = IoGraphBucket {
            timestamp_sec: now_sec,
            packet_count: 1,
            byte_count: length as u64,
            avg_rtt_ms: rtt_ms.unwrap_or(0.0),
            rtt_samples: if rtt_ms.is_some() { 1 } else { 0 },
            retrans_count: if is_retrans { 1 } else { 0 },
        };
        buf.push_back(new_bucket);

        // 维持最多 300 秒 (5分钟) 滑动窗口
        while buf.len() > 300 {
            buf.pop_front();
        }
    }
}

/// 查询指定时间窗口的 IO Graphs 曲线数据
pub fn get_io_graph_series(window_seconds: u32) -> IoGraphSeries {
    let win = window_seconds.clamp(10, 300) as usize;
    let buf = IO_GRAPH_BUFFER.lock().unwrap();

    let count = buf.len();
    let start_idx = count.saturating_sub(win);
    let slice: Vec<IoGraphBucket> = buf.iter().skip(start_idx).cloned().collect();

    let mut total_packets = 0u64;
    let mut total_bytes = 0u64;
    let mut sum_rtt = 0.0;
    let mut rtt_cnt = 0u64;
    let mut max_bw = 0u64;

    for b in &slice {
        total_packets += b.packet_count as u64;
        total_bytes += b.byte_count;
        if b.byte_count > max_bw {
            max_bw = b.byte_count;
        }
        if b.rtt_samples > 0 {
            sum_rtt += b.avg_rtt_ms * (b.rtt_samples as f64);
            rtt_cnt += b.rtt_samples as u64;
        }
    }

    let global_avg_rtt_ms = if rtt_cnt > 0 {
        sum_rtt / (rtt_cnt as f64)
    } else {
        0.0
    };

    IoGraphSeries {
        buckets: slice,
        total_packets,
        total_bytes,
        global_avg_rtt_ms,
        max_bandwidth_bps: max_bw * 8, // 转换为 bps
    }
}

// ============================================================
// 跨总线协同分析与工业网关时延追踪 (Cross-Bus Correlation)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossBusEvent {
    pub bus: String, // "ETHERNET", "SERIAL", "USB"
    pub packet_id: u64,
    pub timestamp_ns: u128,
    pub protocol: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossBusCorrelationRecord {
    pub correlation_id: String,
    pub source_bus: String,
    pub target_bus: String,
    pub source_packet_id: u64,
    pub target_packet_id: u64,
    pub trans_latency_ms: f64,
    pub source_protocol: String,
    pub target_protocol: String,
    pub is_payload_matched: bool,
    pub detail: String,
}

static CROSS_BUS_EVENTS: Lazy<Arc<Mutex<VecDeque<CrossBusEvent>>>> =
    Lazy::new(|| Arc::new(Mutex::new(VecDeque::with_capacity(1000))));

static CROSS_BUS_CORRELATIONS: Lazy<Arc<Mutex<Vec<CrossBusCorrelationRecord>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Vec::new())));

/// 注册跨总线事件并实时触发因果关联计算
/// 时间复杂度: O(M) (M 为近期历史事件队列长度 <= 500)
/// 空间复杂度: O(1)
pub fn record_cross_bus_event(
    bus: &str,
    packet_id: u64,
    timestamp_ns: u128,
    protocol: &str,
    payload: &[u8],
) {
    if payload.is_empty() {
        return;
    }

    let new_evt = CrossBusEvent {
        bus: bus.to_string(),
        packet_id,
        timestamp_ns,
        protocol: protocol.to_string(),
        payload: payload.to_vec(),
    };

    let mut detected_correlation = None;

    {
        let mut events = CROSS_BUS_EVENTS.lock().unwrap();

        // 在近期不同总线的事件中检索因果对 (例如 ETHERNET Modbus-TCP <-> SERIAL Modbus-RTU)
        for prev in events.iter().rev().take(100) {
            if prev.bus != new_evt.bus {
                let dt_ns = new_evt.timestamp_ns.saturating_sub(prev.timestamp_ns);
                let dt_ms = (dt_ns as f64) / 1_000_000.0;

                // 工业网关转换时延通常在 0.1ms ~ 2000ms 之间
                if dt_ms <= 2000.0 {
                    // 场景 1: Modbus TCP -> Modbus RTU (或反向)
                    // Modbus TCP 载荷为 [MBAP 6B] [UnitID 1B] [FC 1B] [Data...]
                    // Modbus RTU 载荷为 [UnitID 1B] [FC 1B] [Data...] [CRC16 2B]
                    let is_modbus_pair = (prev.protocol.contains("MODBUS") && new_evt.protocol.contains("Modbus"))
                        || (prev.protocol.contains("Modbus") && new_evt.protocol.contains("MODBUS"));

                    if is_modbus_pair {
                        let (tcp_payload, rtu_payload) = if prev.protocol.contains("MODBUS_TCP") {
                            (&prev.payload, &new_evt.payload)
                        } else {
                            (&new_evt.payload, &prev.payload)
                        };

                        if tcp_payload.len() >= 8 && rtu_payload.len() >= 4 {
                            let tcp_pdu = &tcp_payload[6..]; // 从 UnitID 开始
                            let rtu_pdu_end = rtu_payload.len().saturating_sub(2); // 除去 CRC
                            let rtu_pdu = &rtu_payload[..rtu_pdu_end];

                            if tcp_pdu == rtu_pdu {
                                detected_correlation = Some(CrossBusCorrelationRecord {
                                    correlation_id: format!("CORR_{}_{}", prev.packet_id, new_evt.packet_id),
                                    source_bus: prev.bus.clone(),
                                    target_bus: new_evt.bus.clone(),
                                    source_packet_id: prev.packet_id,
                                    target_packet_id: new_evt.packet_id,
                                    trans_latency_ms: dt_ms,
                                    source_protocol: prev.protocol.clone(),
                                    target_protocol: new_evt.protocol.clone(),
                                    is_payload_matched: true,
                                    detail: format!(
                                        "网关协议转换确证: {} -> {} (时延: {:.2}ms, 载荷 100% 吻合)",
                                        prev.bus, new_evt.bus, dt_ms
                                    ),
                                });
                                break;
                            }
                        }
                    }

                    // 场景 2: 通用载荷包含比对
                    if prev.payload == new_evt.payload {
                        detected_correlation = Some(CrossBusCorrelationRecord {
                            correlation_id: format!("CORR_{}_{}", prev.packet_id, new_evt.packet_id),
                            source_bus: prev.bus.clone(),
                            target_bus: new_evt.bus.clone(),
                            source_packet_id: prev.packet_id,
                            target_packet_id: new_evt.packet_id,
                            trans_latency_ms: dt_ms,
                            source_protocol: prev.protocol.clone(),
                            target_protocol: new_evt.protocol.clone(),
                            is_payload_matched: true,
                            detail: format!(
                                "跨总线透明透传确证: {} -> {} (时延: {:.2}ms, 相同数据)",
                                prev.bus, new_evt.bus, dt_ms
                            ),
                        });
                        break;
                    }
                }
            }
        }

        events.push_back(new_evt);
        while events.len() > 500 {
            events.pop_front();
        }
    }

    if let Some(corr) = detected_correlation {
        let mut corr_list = CROSS_BUS_CORRELATIONS.lock().unwrap();
        corr_list.push(corr);
        while corr_list.len() > 200 {
            corr_list.remove(0);
        }
    }
}

/// 查询所有识别出的跨总线因果关联与时延记录
pub fn get_cross_bus_correlations() -> Vec<CrossBusCorrelationRecord> {
    let list = CROSS_BUS_CORRELATIONS.lock().unwrap();
    list.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wave_decoding_modes() {
        let be_u = decode_wave_bytes(&[0x01, 0x02], false, false);
        assert_eq!(be_u, 258);

        let le_u = decode_wave_bytes(&[0x02, 0x01], false, true);
        assert_eq!(le_u, 258);

        let be_s = decode_wave_bytes(&[0xFF, 0xFE], true, false);
        assert_eq!(be_s, -2);

        let le_s = decode_wave_bytes(&[0xFE, 0xFF], true, true);
        assert_eq!(le_s, -2);

        assert_eq!(decode_wave_bytes(&[], false, false), 0);
    }

    #[test]
    fn test_io_graph_aggregation() {
        record_packet_io(100, Some(5.0), false);
        record_packet_io(200, Some(15.0), true);

        let series = get_io_graph_series(60);
        assert!(series.total_packets >= 2);
        assert!(series.total_bytes >= 300);
        assert!(series.global_avg_rtt_ms > 0.0);
    }

    #[test]
    fn test_cross_bus_correlation() {
        let ts1 = 1_000_000_000u128;
        let ts2 = 1_005_000_000u128; // 5ms 后

        // Modbus TCP 报文: [MBAP 6B: 00 01 00 00 00 06] + [UnitID: 01] + [FC: 03] + [00 00 00 02]
        let tcp_payload = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02];
        // Modbus RTU 报文: [UnitID: 01] + [FC: 03] + [00 00 00 02] + [CRC16: C4 0B]
        let rtu_payload = vec![0x01, 0x03, 0x00, 0x00, 0x00, 0x02, 0xC4, 0x0B];

        record_cross_bus_event("ETHERNET", 101, ts1, "MODBUS_TCP", &tcp_payload);
        record_cross_bus_event("SERIAL", 102, ts2, "Modbus-RTU", &rtu_payload);

        let correlations = get_cross_bus_correlations();
        let found = correlations.iter().any(|c| c.source_packet_id == 101 && c.target_packet_id == 102);
        assert!(found, "应当成功关联网关从以太网 Modbus-TCP 到串口 Modbus-RTU 的协议转换");
    }

    #[test]
    fn test_smart_diff_identical() {
        let hex_samples = vec![
            "01020304".to_string(),
            "01020304".to_string(),
        ];
        let diff = smart_diff_payloads(hex_samples).expect("比对不应失败");
        assert!(diff.summary.contains("0 个字节发生突变"));
    }

    #[test]
    fn test_smart_diff_mutation() {
        let hex_samples = vec![
            "01020304".to_string(),
            "0102FFA4".to_string(),
        ];
        let diff = smart_diff_payloads(hex_samples).expect("比对不应失败");
        assert!(diff.summary.contains("突变"));
    }

    #[test]
    fn test_baseline_save_and_compare() {
        let samples = vec![
            "010203040506".to_string(),
            "010203040507".to_string(),
        ];
        let saved = save_baseline_payloads(samples.clone()).expect("保存基线失败");
        assert_eq!(saved, 2);

        let loaded = load_baseline_payloads().expect("加载基线失败");
        assert_eq!(loaded.len(), 2);

        let current = vec!["010203040508".to_string()];
        let diff = compare_with_historical_baseline(current).expect("联合比对失败");
        assert_eq!(diff.payloads.len(), 3, "联合比对后总样本数应为 3 (2基准+1当前)");
    }
}

