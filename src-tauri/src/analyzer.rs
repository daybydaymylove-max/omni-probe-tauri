use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    let mut map = crate::lock_guard::lock_mutex(&BASELINES, "analyzer::check_anomaly");
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
    let mut cfg = crate::lock_guard::lock_mutex(&WAVE_CONFIG, "analyzer::configure_wave_tracker");
    let trimmed = ip.trim().to_string();
    if trimmed.is_empty() || length == 0 {
        cfg.active = false;
        cfg.target_ip = String::new();
        return;
    }
    cfg.active = true;
    cfg.target_ip = trimmed;
    cfg.byte_offset = offset;
    cfg.byte_length = length.clamp(1, 8);
    cfg.signed = signed;
    cfg.little_endian = little_endian;
}

pub fn process_wave_sample(app: &tauri::AppHandle, source_key: &str, payload: &[u8]) {
    let cfg = crate::lock_guard::lock_mutex(&WAVE_CONFIG, "analyzer::process_wave_sample");
    if !cfg.active {
        return;
    }
    let matched = cfg.target_ip == "*"
        || cfg.target_ip.eq_ignore_ascii_case(source_key.trim());
    if !matched {
        return;
    }
    let end = match cfg.byte_offset.checked_add(cfg.byte_length) {
        Some(v) => v,
        None => return,
    };
    if payload.len() < end {
        return;
    }
    let chunk = &payload[cfg.byte_offset..end];
    let value = decode_wave_bytes(chunk, cfg.signed, cfg.little_endian);
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let _ = app.emit("wave-data", WavePoint { ip: source_key.to_string(), value, ts_ms });
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
pub struct DiffWaveformPoint {
    pub offset: usize,
    pub val_a: u8,
    pub val_b: u8,
    pub delta: i16,
    pub is_mutated: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WaveformComparisonMetrics {
    pub cosine_similarity: f64,
    pub pearson_correlation: f64,
    pub mean_absolute_deviation: f64,
    pub max_delta_offset: usize,
    pub max_delta_value: i16,
    pub mutation_wave_rate: f64,
    pub waveform_points: Vec<DiffWaveformPoint>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MutationWaveBin {
    pub offset: usize,
    pub mutation_rate: f64,
    pub unique_values_count: usize,
    pub entropy: f64,
    pub dominant_hex: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SmartDiffResult {
    pub mode: String,
    pub payloads: Vec<ParsedPayload>,
    pub summary: String,
    pub mutation_spectrum: Vec<MutationWaveBin>,
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
    let resolved_labels: Vec<String> = (0..raw_strings.len())
        .map(|i| {
            if use_labels {
                labels[i].clone()
            } else if raw_strings.len() == 2 {
                if i == 0 { "样本 A".into() } else { "样本 B".into() }
            } else {
                format!("样本 {:02}", i + 1)
            }
        })
        .collect();

    let payloads: Vec<Vec<u8>> = raw_strings
        .iter()
        .map(|s| {
            let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            if !clean.is_empty() && clean.len() % 2 == 0 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
                hex::decode(&clean).unwrap_or_else(|_| s.as_bytes().to_vec())
            } else {
                s.as_bytes().to_vec()
            }
        })
        .collect();

    if payloads.len() == 2 {
        let spectrum = compute_mutation_spectrum(&payloads);
        let tags_a = lcs_diff_tags(&payloads[0], &payloads[1], true);
        let tags_b = lcs_diff_tags(&payloads[0], &payloads[1], false);
        let pa = build_hex_rows(&payloads[0], &tags_a, &resolved_labels[0]);
        let pb = build_hex_rows(&payloads[1], &tags_b, &resolved_labels[1]);
        let changes = tags_a.iter().filter(|t| t.as_str() != "equal").count();
        Ok(SmartDiffResult {
            mode: "smart_diff".into(),
            payloads: vec![pa, pb],
            summary: format!("智能对齐比对: {} 个字节发生突变（替换/插入/删除）", changes),
            mutation_spectrum: spectrum,
        })
    } else {
        // 3 组及以上采用以第 0 组为锚点的 Center-Star 多序列精准对齐，彻底消除长度差与前插错位导致的雪崩标红
        let alignment = center_star_align_payloads(&payloads, 0);
        let opt_rows: Vec<Vec<Option<u8>>> = alignment
            .matrix
            .iter()
            .map(|row| row.iter().map(|(b, _)| *b).collect())
            .collect();
        let spectrum = compute_mutation_spectrum_opts(&opt_rows);

        let parsed: Vec<ParsedPayload> = alignment
            .matrix
            .iter()
            .enumerate()
            .map(|(idx, row)| build_aligned_parsed_payload(row, payloads[idx].len(), &resolved_labels[idx]))
            .collect();

        let diff_cols = spectrum.iter().filter(|b| b.unique_values_count > 1).count();
        Ok(SmartDiffResult {
            mode: "center_star_multi_diff".into(),
            payloads: parsed,
            summary: format!(
                "多组居中精密对齐: {} 个对齐偏移列存在值差异或长度缺失（共 {} 组样本，总宽 {} 列）",
                diff_cols,
                payloads.len(),
                alignment.aligned_width
            ),
            mutation_spectrum: spectrum,
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


/// 最大二维 DP 单元格上限 (~10MB 平铺缓冲)
const LCS_DP_CELL_LIMIT: usize = 2_500_000;
/// 线性空间 Hirschberg 单纯计算允许的最大乘积量 (防极端 100KB 全异数据阻塞 UI)
const LCS_HIRSCHBERG_OPS_LIMIT: usize = 25_000_000;

/// 小规模一维平铺 DP 精确回溯 LCS 匹配下标对
/// 时间复杂度: O(N * M), 空间复杂度: O(N * M) (受限于 LCS_DP_CELL_LIMIT <= 10MB)
fn lcs_pairs_flat_dp(a: &[u8], b: &[u8], off_a: usize, off_b: usize, out: &mut Vec<(usize, usize)>) {
    let n = a.len();
    let m = b.len();
    if n == 0 || m == 0 {
        return;
    }
    let cols = m + 1;
    let mut dp = vec![0u32; (n + 1) * cols];
    for i in 1..=n {
        let row = i * cols;
        let prev_row = (i - 1) * cols;
        let ai = a[i - 1];
        for j in 1..=m {
            dp[row + j] = if ai == b[j - 1] {
                dp[prev_row + j - 1] + 1
            } else {
                dp[prev_row + j].max(dp[row + j - 1])
            };
        }
    }

    let mut local = Vec::new();
    let (mut i, mut j) = (n, m);
    while i > 0 && j > 0 {
        if a[i - 1] == b[j - 1] {
            local.push((off_a + i - 1, off_b + j - 1));
            i -= 1;
            j -= 1;
        } else if dp[i * cols + (j - 1)] >= dp[(i - 1) * cols + j] {
            j -= 1;
        } else {
            i -= 1;
        }
    }
    local.reverse();
    out.extend(local);
}

/// 线性空间计算正向/反向 LCS 长度末行（供 Hirschberg 分治使用）
fn lcs_last_row_forward(a: &[u8], b: &[u8]) -> Vec<u32> {
    let m = b.len();
    let mut prev = vec![0u32; m + 1];
    let mut curr = vec![0u32; m + 1];
    for &ai in a {
        for j in 1..=m {
            curr[j] = if ai == b[j - 1] {
                prev[j - 1] + 1
            } else {
                prev[j].max(curr[j - 1])
            };
        }
        std::mem::swap(&mut prev, &mut curr);
        curr.fill(0);
    }
    prev
}

fn lcs_last_row_backward(a: &[u8], b: &[u8]) -> Vec<u32> {
    let m = b.len();
    let mut prev = vec![0u32; m + 1];
    let mut curr = vec![0u32; m + 1];
    for &ai in a.iter().rev() {
        for j in (0..m).rev() {
            curr[j] = if ai == b[j] {
                prev[j + 1] + 1
            } else {
                prev[j].max(curr[j + 1])
            };
        }
        std::mem::swap(&mut prev, &mut curr);
        curr.fill(0);
    }
    prev
}

/// Hirschberg 分治线性空间 LCS 对齐（防止中大型报文触发二维矩阵 OOM）
/// 空间复杂度: O(M), 时间复杂度: O(N * M)
fn lcs_pairs_hirschberg(a: &[u8], b: &[u8], off_a: usize, off_b: usize, out: &mut Vec<(usize, usize)>) {
    let n = a.len();
    let m = b.len();
    if n == 0 || m == 0 {
        return;
    }
    if n == 1 {
        let target = a[0];
        if let Some(pos) = b.iter().position(|&ch| ch == target) {
            out.push((off_a, off_b + pos));
        }
        return;
    }
    if m == 1 {
        let target = b[0];
        if let Some(pos) = a.iter().position(|&ch| ch == target) {
            out.push((off_a + pos, off_b));
        }
        return;
    }
    if (n + 1).saturating_mul(m + 1) <= 65_536 {
        lcs_pairs_flat_dp(a, b, off_a, off_b, out);
        return;
    }

    let mid = n / 2;
    let l1 = lcs_last_row_forward(&a[..mid], b);
    let l2 = lcs_last_row_backward(&a[mid..], b);

    let mut split_j = 0usize;
    let mut best_sum = 0u32;
    for j in 0..=m {
        let sum = l1[j] + l2[j];
        if sum >= best_sum {
            best_sum = sum;
            split_j = j;
        }
    }

    lcs_pairs_hirschberg(&a[..mid], &b[..split_j], off_a, off_b, out);
    lcs_pairs_hirschberg(&a[mid..], &b[split_j..], off_a + mid, off_b + split_j, out);
}

/// 巨型差异分块窗口锚定配对兜底（保障 100KB+ 随机大帧毫秒级响应且 O(min(W)) 空间）
fn lcs_pairs_chunked_fallback(a: &[u8], b: &[u8], off_a: usize, off_b: usize, out: &mut Vec<(usize, usize)>) {
    const CHUNK: usize = 512;
    let max_chunks = a.len().div_ceil(CHUNK).max(b.len().div_ceil(CHUNK));
    for c in 0..max_chunks {
        let sa = (c * CHUNK).min(a.len());
        let ea = ((c + 1) * CHUNK).min(a.len());
        let sb = (c * CHUNK).min(b.len());
        let eb = ((c + 1) * CHUNK).min(b.len());
        if sa < ea && sb < eb {
            lcs_pairs_flat_dp(&a[sa..ea], &b[sb..eb], off_a + sa, off_b + sb, out);
        }
    }
}

/// 混合防呆版精确 LCS 匹配下标求解器（前后缀剥离 + 平铺 DP + Hirschberg 线性空间 + 超大帧分窗降级）
fn lcs_matched_pairs(a: &[u8], b: &[u8]) -> Vec<(usize, usize)> {
    let n = a.len();
    let m = b.len();
    let min_len = n.min(m);

    let mut prefix = 0usize;
    while prefix < min_len && a[prefix] == b[prefix] {
        prefix += 1;
    }

    let mut suffix = 0usize;
    while suffix < (min_len - prefix) && a[n - 1 - suffix] == b[m - 1 - suffix] {
        suffix += 1;
    }

    let mut pairs = Vec::with_capacity(min_len);
    for i in 0..prefix {
        pairs.push((i, i));
    }

    let mid_a = &a[prefix..n - suffix];
    let mid_b = &b[prefix..m - suffix];
    let prod = mid_a.len().saturating_mul(mid_b.len());
    if !mid_a.is_empty() && !mid_b.is_empty() {
        if prod <= LCS_DP_CELL_LIMIT {
            lcs_pairs_flat_dp(mid_a, mid_b, prefix, prefix, &mut pairs);
        } else if prod <= LCS_HIRSCHBERG_OPS_LIMIT {
            lcs_pairs_hirschberg(mid_a, mid_b, prefix, prefix, &mut pairs);
        } else {
            lcs_pairs_chunked_fallback(mid_a, mid_b, prefix, prefix, &mut pairs);
        }
    }

    for k in 0..suffix {
        pairs.push((n - suffix + k, m - suffix + k));
    }
    pairs
}

/// 内存安全版 LCS 字节差分标记输出（保持向后兼容标签协议）
/// 时间复杂度: O(N * M)（小中规模精确对齐）/ 分块线控保护（100KB+ 巨帧）
/// 空间复杂度: 常规 <= 10MB，大规模 Hirschberg 降至 O(min(N, M))
pub fn lcs_diff_tags(a: &[u8], b: &[u8], is_a: bool) -> Vec<String> {
    let pairs = lcs_matched_pairs(a, b);
    let mut matched_a = vec![false; a.len()];
    let mut matched_b = vec![false; b.len()];
    for &(ia, ib) in &pairs {
        matched_a[ia] = true;
        matched_b[ib] = true;
    }

    let has_del = matched_a.iter().any(|&m| !m);
    let has_ins = matched_b.iter().any(|&m| !m);
    let use_replace = has_del && has_ins;

    if is_a {
        matched_a
            .into_iter()
            .map(|eq| {
                if eq {
                    "equal".into()
                } else if use_replace {
                    "replace".into()
                } else {
                    "delete".into()
                }
            })
            .collect()
    } else {
        matched_b
            .into_iter()
            .map(|eq| {
                if eq {
                    "equal".into()
                } else if use_replace {
                    "replace".into()
                } else {
                    "insert".into()
                }
            })
            .collect()
    }
}

/// Center-Star 多序列居中对齐产物
struct CenterStarAlignment {
    aligned_width: usize,
    /// matrix[sample_idx][col_idx] = (字节值 Option<u8>, 差异类型标签)
    matrix: Vec<Vec<(Option<u8>, String)>>,
    mutated_counts: Vec<usize>,
}

/// 对任意 N 组（N >= 2）字节流以 anchor_idx 为锚点执行 Center-Star 全局精确对齐
/// 时间复杂度: O(N * L_anchor * L_k), 空间复杂度: O(N * W)
fn center_star_align_payloads(payloads: &[Vec<u8>], anchor_idx: usize) -> CenterStarAlignment {
    let k = payloads.len();
    if k == 0 {
        return CenterStarAlignment {
            aligned_width: 0,
            matrix: Vec::new(),
            mutated_counts: Vec::new(),
        };
    }

    let safe_anchor = anchor_idx.min(k - 1);
    let anchor = &payloads[safe_anchor];
    let len_a = anchor.len();

    // per_sample[s]: 每组相对于 anchor 的 (在每个 anchor[i] 上放置的内容及标签, 在各个间隙 gap[0..=len_a] 插入的字节)
    struct SampleSlotPlan {
        anchor_cells: Vec<(Option<u8>, String)>,
        gaps: Vec<Vec<u8>>,
    }

    let mut plans: Vec<SampleSlotPlan> = Vec::with_capacity(k);
    let mut max_gaps = vec![0usize; len_a + 1];

    for (s_idx, seq) in payloads.iter().enumerate() {
        let mut anchor_cells = vec![(None, "missing".to_string()); len_a];
        let mut gaps = vec![Vec::<u8>::new(); len_a + 1];

        if s_idx == safe_anchor {
            for (i, &b) in seq.iter().enumerate() {
                anchor_cells[i] = (Some(b), "equal".into());
            }
            plans.push(SampleSlotPlan { anchor_cells, gaps });
            continue;
        }

        let mut pairs = lcs_matched_pairs(anchor, seq);
        pairs.push((len_a, seq.len())); // 哨兵统一收尾末段未匹配子序列

        let mut prev_a: isize = -1;
        let mut prev_b: isize = -1;
        for (cur_a, cur_b) in pairs {
            let start_a = (prev_a + 1) as usize;
            let start_b = (prev_b + 1) as usize;
            let span_a = cur_a.saturating_sub(start_a);
            let span_b = cur_b.saturating_sub(start_b);

            let paired_replace = span_a.min(span_b);
            for d in 0..paired_replace {
                anchor_cells[start_a + d] = (Some(seq[start_b + d]), "replace".into());
            }
            // 若 span_a > span_b，剩余 anchor 位置保持默认 (None, "missing")
            // 若 span_b > span_a，多出的字节放入紧邻 cur_a 前方（或末尾 len_a）的间隙槽
            if span_b > paired_replace {
                let extra = &seq[start_b + paired_replace..cur_b];
                gaps[cur_a].extend_from_slice(extra);
                if gaps[cur_a].len() > max_gaps[cur_a] {
                    max_gaps[cur_a] = gaps[cur_a].len();
                }
            }

            if cur_a < len_a && cur_b < seq.len() {
                anchor_cells[cur_a] = (Some(seq[cur_b]), "equal".into());
            }
            prev_a = cur_a as isize;
            prev_b = cur_b as isize;
        }

        plans.push(SampleSlotPlan { anchor_cells, gaps });
    }

    let aligned_width = len_a + max_gaps.iter().sum::<usize>();
    let mut matrix = vec![Vec::with_capacity(aligned_width); k];
    let mut mutated_counts = vec![0usize; k];

    // 先判断哪些列上全样本完全一致（用于锚点自身是否被插入列牵连对比高亮）
    for gap_idx in 0..=len_a {
        let g_width = max_gaps[gap_idx];
        for g_col in 0..g_width {
            for s_idx in 0..k {
                if let Some(&b) = plans[s_idx].gaps[gap_idx].get(g_col) {
                    matrix[s_idx].push((Some(b), "insert".into()));
                    mutated_counts[s_idx] += 1;
                } else {
                    // 在非自身插入间隙处填充 "--" 对齐槽位；由于与锚点同样为 None，不计入相对于锚点的突变数量
                    matrix[s_idx].push((None, "missing".into()));
                }
            }
        }
        if gap_idx < len_a {
            for s_idx in 0..k {
                let (opt_b, tag) = plans[s_idx].anchor_cells[gap_idx].clone();
                if s_idx != safe_anchor && tag != "equal" {
                    mutated_counts[s_idx] += 1;
                }
                matrix[s_idx].push((opt_b, tag));
            }
        }
    }

    // 针对锚点行标出与其他样本真正存在数值/缺失分歧的 anchor 列，便于在矩阵中直观一眼定位突变位
    for col in 0..aligned_width {
        let anchor_byte = matrix[safe_anchor][col].0;
        let col_differs = (0..k).any(|s| matrix[s][col].0 != anchor_byte);
        if col_differs && matrix[safe_anchor][col].1 == "equal" {
            matrix[safe_anchor][col].1 = "replace".into();
        }
    }

    CenterStarAlignment {
        aligned_width,
        matrix,
        mutated_counts,
    }
}

fn build_aligned_parsed_payload(aligned_row: &[(Option<u8>, String)], original_byte_len: usize, label: &str) -> ParsedPayload {
    let mut hex_rows = Vec::new();
    for chunk_start in (0..aligned_row.len()).step_by(16) {
        let chunk = &aligned_row[chunk_start..aligned_row.len().min(chunk_start + 16)];
        let cells: Vec<ByteCell> = chunk
            .iter()
            .map(|(opt_b, tag)| match opt_b {
                Some(b) => ByteCell {
                    hex: format!("{:02X}", b),
                    ascii: if (32..=126).contains(b) { (*b as char).to_string() } else { ".".into() },
                    diff_type: tag.clone(),
                },
                None => ByteCell {
                    hex: "--".into(),
                    ascii: ".".into(),
                    diff_type: tag.clone(),
                },
            })
            .collect();
        let ascii_repr: String = chunk
            .iter()
            .map(|(opt_b, _)| match opt_b {
                Some(b) if (32..=126).contains(b) => *b as char,
                Some(_) => '.',
                None => ' ',
            })
            .collect();
        hex_rows.push(HexRow {
            offset: format!("{:04X}", chunk_start),
            cells,
            ascii_repr,
        });
    }
    ParsedPayload {
        label: label.to_string(),
        byte_length: original_byte_len,
        hex_rows,
    }
}

fn build_hex_rows(payload: &[u8], tags: &[String], label: &str) -> ParsedPayload {
    let aligned_row: Vec<(Option<u8>, String)> = payload
        .iter()
        .enumerate()
        .map(|(i, &b)| (Some(b), tags.get(i).cloned().unwrap_or_else(|| "equal".into())))
        .collect();
    build_aligned_parsed_payload(&aligned_row, payload.len(), label)
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
    pub waveform_metrics: Option<WaveformComparisonMetrics>,
}

/// 通用跨模块比对输入实体 (支持网络包、套接字调试、串口、纯 HEX/ASCII 草稿)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalDiffPayload {
    pub id: Option<u64>,
    pub label: String,
    pub timestamp: Option<String>,
    pub protocol: Option<String>,
    pub endpoint_src: Option<String>,
    pub endpoint_dst: Option<String>,
    pub payload_hex: String,
    pub raw_text: Option<String>,
    pub extra_fields: Option<HashMap<String, String>>,
}

/// 通用跨模块多组比对样本摘要项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiDiffSampleSummary {
    pub sample_index: usize,
    pub label: String,
    pub protocol: String,
    pub endpoint_src: String,
    pub endpoint_dst: String,
    pub byte_length: usize,
    pub mutated_vs_anchor: usize,
    pub mutation_rate_vs_anchor: f64,
    pub cosine_similarity_vs_anchor: f64,
    pub aligned_hex: ParsedPayload,
}

/// 跨多组规约及元数据字段矩阵对比行
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiFieldDiffRow {
    pub layer: String,
    pub field_name: String,
    pub values: Vec<String>,
    pub has_difference: bool,
}

/// 全局多组（N >= 2 不封顶）居中精确比对分析综合结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiUniversalDiffResult {
    pub sample_count: usize,
    pub anchor_index: usize,
    pub aligned_column_count: usize,
    pub samples: Vec<MultiDiffSampleSummary>,
    pub field_matrix: Vec<MultiFieldDiffRow>,
    pub aligned_mutation_spectrum: Vec<MutationWaveBin>,
    pub summary: String,
}

/// 统一载荷字节提取：优先 HEX（严格偶数且全十六进制校验），否则回退 raw_text
/// 当上层显式将 ASCII 明文置于 raw_text 且置空 payload_hex 时，可零失真保留 "CAFE" / "1234" 等明文字符串
fn extract_payload_bytes(item: &UniversalDiffPayload) -> Vec<u8> {
    let clean: String = item
        .payload_hex
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if !clean.is_empty() && clean.len() % 2 == 0 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(&clean) {
            return bytes;
        }
    }
    if !item.payload_hex.trim().is_empty() {
        return item
            .raw_text
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_else(|| clean.as_bytes().to_vec());
    }
    item.raw_text
        .as_ref()
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_default()
}

/// 全局通用的跨模块双样本数据深度差分与波形比对分析引擎
/// 时间复杂度: 常规 O(N * M) / 超大帧分块线性保护 O(N + M)
/// 空间复杂度: 常规 <= 10MB，Hirschberg 降至 O(min(N, M))
pub fn compare_universal_payloads(
    item_a: UniversalDiffPayload,
    item_b: UniversalDiffPayload,
) -> Result<DualPacketDiffResult, String> {
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

    // 基础元信息
    add_field("元数据", "样本标签", &item_a.label, &item_b.label);
    if item_a.timestamp.is_some() || item_b.timestamp.is_some() {
        add_field(
            "元数据",
            "时标记录",
            item_a.timestamp.as_deref().unwrap_or("-"),
            item_b.timestamp.as_deref().unwrap_or("-"),
        );
    }
    if item_a.protocol.is_some() || item_b.protocol.is_some() {
        add_field(
            "规约特征",
            "通信协议/模式",
            item_a.protocol.as_deref().unwrap_or("GENERIC"),
            item_b.protocol.as_deref().unwrap_or("GENERIC"),
        );
    }
    if item_a.endpoint_src.is_some() || item_b.endpoint_src.is_some() {
        add_field(
            "通信端点",
            "源端点 (Source)",
            item_a.endpoint_src.as_deref().unwrap_or("-"),
            item_b.endpoint_src.as_deref().unwrap_or("-"),
        );
    }
    if item_a.endpoint_dst.is_some() || item_b.endpoint_dst.is_some() {
        add_field(
            "通信端点",
            "目的端点 (Destination)",
            item_a.endpoint_dst.as_deref().unwrap_or("-"),
            item_b.endpoint_dst.as_deref().unwrap_or("-"),
        );
    }

    // 扩展业务属性比对
    let mut all_extra_keys = std::collections::BTreeSet::new();
    if let Some(ref map_a) = item_a.extra_fields {
        for k in map_a.keys() {
            all_extra_keys.insert(k.clone());
        }
    }
    if let Some(ref map_b) = item_b.extra_fields {
        for k in map_b.keys() {
            all_extra_keys.insert(k.clone());
        }
    }
    for k in all_extra_keys {
        let val_a = item_a
            .extra_fields
            .as_ref()
            .and_then(|m| m.get(&k))
            .map(|s| s.as_str())
            .unwrap_or("");
        let val_b = item_b
            .extra_fields
            .as_ref()
            .and_then(|m| m.get(&k))
            .map(|s| s.as_str())
            .unwrap_or("");
        add_field("业务扩展属性", &k, val_a, val_b);
    }

    let bytes_a = extract_payload_bytes(&item_a);
    let bytes_b = extract_payload_bytes(&item_b);

    let tags_a = lcs_diff_tags(&bytes_a, &bytes_b, true);
    let tags_b = lcs_diff_tags(&bytes_a, &bytes_b, false);

    let desc_a = if item_a.label.is_empty() {
        format!("样本 A ({} 字节)", bytes_a.len())
    } else {
        item_a.label.clone()
    };
    let desc_b = if item_b.label.is_empty() {
        format!("样本 B ({} 字节)", bytes_b.len())
    } else {
        item_b.label.clone()
    };

    let hex_diff_a = build_hex_rows(&bytes_a, &tags_a, &format!("样本 A: {}", desc_a));
    let hex_diff_b = build_hex_rows(&bytes_b, &tags_b, &format!("样本 B: {}", desc_b));

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
        "通用比对完成: 元数据差异 {} 项 | 载荷突变字节: {}/{} ({:.1}%)",
        diff_fields_count, mutated_bytes_count, max_len, mutation_rate_percent
    );

    let waveform_metrics = Some(compute_waveform_metrics(&bytes_a, &bytes_b));

    Ok(DualPacketDiffResult {
        packet_a_id: item_a.id.unwrap_or(1),
        packet_b_id: item_b.id.unwrap_or(2),
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
        waveform_metrics,
    })
}

/// 跨模块 N >= 2 组数据 Center-Star 居中精确比对引擎
/// 时间复杂度: O(K * N * M) (K 为对比组数), 空间复杂度: O(K * W) (W 为居中对齐总列宽)
pub fn compare_multi_universal_payloads(
    items: Vec<UniversalDiffPayload>,
    anchor_index: Option<usize>,
) -> Result<MultiUniversalDiffResult, String> {
    if items.len() < 2 {
        return Err("多组比对至少需要 2 组数据样本".into());
    }

    let safe_anchor = anchor_index.unwrap_or(0).min(items.len() - 1);
    let byte_lists: Vec<Vec<u8>> = items.iter().map(extract_payload_bytes).collect();
    let alignment = center_star_align_payloads(&byte_lists, safe_anchor);

    let opt_matrix: Vec<Vec<Option<u8>>> = alignment
        .matrix
        .iter()
        .map(|row| row.iter().map(|(b, _)| *b).collect())
        .collect();
    let aligned_mutation_spectrum = compute_mutation_spectrum_opts(&opt_matrix);

    let anchor_bytes = &byte_lists[safe_anchor];
    let samples: Vec<MultiDiffSampleSummary> = items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let cur_bytes = &byte_lists[idx];
            let wm = compute_waveform_metrics(anchor_bytes, cur_bytes);
            let label = if item.label.is_empty() {
                format!("样本 #{}", idx + 1)
            } else {
                item.label.clone()
            };
            let mutated = if idx == safe_anchor {
                0
            } else {
                alignment.mutated_counts[idx]
            };
            let denom = alignment.aligned_width.max(cur_bytes.len()).max(1);
            let mut_rate = if alignment.aligned_width == 0 && cur_bytes.is_empty() {
                0.0
            } else if idx == safe_anchor {
                0.0
            } else {
                (mutated as f64 / denom as f64) * 100.0
            };

            MultiDiffSampleSummary {
                sample_index: idx,
                label: label.clone(),
                protocol: item.protocol.clone().unwrap_or_else(|| "GENERIC".into()),
                endpoint_src: item.endpoint_src.clone().unwrap_or_else(|| "-".into()),
                endpoint_dst: item.endpoint_dst.clone().unwrap_or_else(|| "-".into()),
                byte_length: cur_bytes.len(),
                mutated_vs_anchor: mutated,
                mutation_rate_vs_anchor: mut_rate,
                cosine_similarity_vs_anchor: if idx == safe_anchor { 1.0 } else { wm.cosine_similarity },
                aligned_hex: build_aligned_parsed_payload(&alignment.matrix[idx], cur_bytes.len(), &label),
            }
        })
        .collect();

    // 构造全组字段矩阵
    let mut field_matrix = Vec::new();
    let mut push_matrix_row = |layer: &str, name: &str, values: Vec<String>| {
        let first = values.first().map(|s| s.as_str()).unwrap_or("");
        let has_difference = values.iter().any(|v| v.as_str() != first);
        field_matrix.push(MultiFieldDiffRow {
            layer: layer.into(),
            field_name: name.into(),
            values,
            has_difference,
        });
    };

    push_matrix_row(
        "元数据",
        "样本标签",
        samples.iter().map(|s| s.label.clone()).collect(),
    );
    push_matrix_row(
        "规约特征",
        "通信协议/模式",
        samples.iter().map(|s| s.protocol.clone()).collect(),
    );
    push_matrix_row(
        "通信端点",
        "源端点 (Source)",
        samples.iter().map(|s| s.endpoint_src.clone()).collect(),
    );
    push_matrix_row(
        "通信端点",
        "目的端点 (Destination)",
        samples.iter().map(|s| s.endpoint_dst.clone()).collect(),
    );
    push_matrix_row(
        "载荷度量",
        "原始字节长度",
        samples.iter().map(|s| format!("{} 字节", s.byte_length)).collect(),
    );

    let mut all_extra_keys = std::collections::BTreeSet::new();
    for item in &items {
        if let Some(ref map) = item.extra_fields {
            for k in map.keys() {
                all_extra_keys.insert(k.clone());
            }
        }
    }
    for k in all_extra_keys {
        let values = items
            .iter()
            .map(|it| {
                it.extra_fields
                    .as_ref()
                    .and_then(|m| m.get(&k))
                    .cloned()
                    .unwrap_or_else(|| "—".into())
            })
            .collect();
        push_matrix_row("业务扩展属性", &k, values);
    }

    let diff_field_cnt = field_matrix.iter().filter(|r| r.has_difference).count();
    let diff_col_cnt = aligned_mutation_spectrum
        .iter()
        .filter(|b| b.unique_values_count > 1)
        .count();
    let summary = format!(
        "{} 组多序列精准比对完成（锚点 #{}）：元数据差异 {} 项 | 对齐突变偏移列 {}/{}",
        items.len(),
        safe_anchor + 1,
        diff_field_cnt,
        diff_col_cnt,
        alignment.aligned_width
    );

    Ok(MultiUniversalDiffResult {
        sample_count: items.len(),
        anchor_index: safe_anchor,
        aligned_column_count: alignment.aligned_width,
        samples,
        field_matrix,
        aligned_mutation_spectrum,
        summary,
    })
}

/// 多组居中差分中的连续差异字节段落指令
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiBytePatchHunk {
    pub hunk_index: usize,
    /// "REPLACE" | "INSERT" | "DELETE"
    pub op_kind: String,
    pub anchor_offset: usize,
    pub anchor_len: usize,
    pub target_len: usize,
    pub anchor_hex: String,
    pub target_hex: String,
    pub semantic_hint: String,
}

/// 单组非锚点样本相对于 Anchor 的修订脚本包
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplePatchBundle {
    pub sample_index: usize,
    pub sample_label: String,
    pub target_byte_length: usize,
    pub target_sha256: String,
    pub total_hunks: usize,
    pub hunks: Vec<MultiBytePatchHunk>,
}

/// 全局多组差异字节段 Patch 与可执行修订脚本总成
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiDiffPatchReport {
    pub anchor_index: usize,
    pub anchor_label: String,
    pub anchor_byte_length: usize,
    pub anchor_sha256: String,
    pub samples: Vec<SamplePatchBundle>,
    pub hex_revision_script: String,
    pub python_patch_script: String,
}

fn infer_byte_hunk_semantic(
    anchor_bytes: &[u8],
    target_bytes: &[u8],
    offset: usize,
    total_anchor_len: usize,
) -> String {
    if !anchor_bytes.is_empty() && anchor_bytes.len() == target_bytes.len() {
        if offset + anchor_bytes.len() == total_anchor_len && anchor_bytes.len() == 2 {
            return "尾部 2B 对齐变更 (疑似 CRC16/校验和随载荷变化)".into();
        }
        if anchor_bytes.len() == 1 {
            let d = target_bytes[0] as i16 - anchor_bytes[0] as i16;
            return format!("单字节定长修改 (差值 {:+})", d);
        }
        if anchor_bytes.len() == 2 {
            let va = u16::from_be_bytes([anchor_bytes[0], anchor_bytes[1]]);
            let vb = u16::from_be_bytes([target_bytes[0], target_bytes[1]]);
            return format!("16-bit 大端数值变更 ({} -> {})", va, vb);
        }
        return format!("{} 字节等长域替换", anchor_bytes.len());
    }
    if anchor_bytes.is_empty() {
        format!("前端/中段插入 {} 字节", target_bytes.len())
    } else if target_bytes.is_empty() {
        format!("裁切/删除 {} 字节", anchor_bytes.len())
    } else {
        format!("变长区替换 ({}B -> {}B)", anchor_bytes.len(), target_bytes.len())
    }
}

/// 对一组（N >= 2）比对样本，以指定 Anchor 为基准生成精确到单字节偏移的 Patch 摘要与可逆 Python 修订脚本
/// 时间复杂度: O(N * W), 空间复杂度: O(N * W)
pub fn generate_multi_diff_patch_report(
    items: Vec<UniversalDiffPayload>,
    anchor_index: Option<usize>,
) -> Result<MultiDiffPatchReport, String> {
    if items.len() < 2 {
        return Err("生成 Patch 修订脚本至少需要 2 组数据样本".into());
    }
    let safe_anchor = anchor_index.unwrap_or(0).min(items.len() - 1);
    let byte_lists: Vec<Vec<u8>> = items.iter().map(extract_payload_bytes).collect();
    let alignment = center_star_align_payloads(&byte_lists, safe_anchor);

    let anchor_bytes = &byte_lists[safe_anchor];
    let anchor_sha256 = hex::encode(Sha256::digest(anchor_bytes));
    let anchor_label = if items[safe_anchor].label.is_empty() {
        format!("基准样本 #{}", safe_anchor + 1)
    } else {
        items[safe_anchor].label.clone()
    };

    let anchor_row = &alignment.matrix[safe_anchor];
    let mut bundles = Vec::new();
    let mut hex_script = String::new();
    hex_script.push_str(&format!(
        "; Omni-Probe Multi-Group Binary Revision Summary\n; Anchor: #{} \"{}\" ({} bytes, SHA256={})\n\n",
        safe_anchor + 1, anchor_label, anchor_bytes.len(), anchor_sha256
    ));

    let mut py_targets = String::new();

    for idx in 0..items.len() {
        if idx == safe_anchor {
            continue;
        }
        let target_row = &alignment.matrix[idx];
        let target_raw = &byte_lists[idx];
        let target_sha256 = hex::encode(Sha256::digest(target_raw));
        let label = if items[idx].label.is_empty() {
            format!("样本 #{}", idx + 1)
        } else {
            items[idx].label.clone()
        };

        let mut hunks = Vec::new();
        let mut anchor_cursor = 0usize;
        let mut hunk_start_offset = 0usize;
        let mut in_hunk = false;
        let mut cur_a: Vec<u8> = Vec::new();
        let mut cur_t: Vec<u8> = Vec::new();

        for col in 0..alignment.aligned_width {
            let a_opt = anchor_row[col].0;
            let t_opt = target_row[col].0;

            if a_opt == t_opt {
                if in_hunk {
                    let op_kind = match (cur_a.is_empty(), cur_t.is_empty()) {
                        (true, false) => "INSERT",
                        (false, true) => "DELETE",
                        _ => "REPLACE",
                    };
                    let hint = infer_byte_hunk_semantic(&cur_a, &cur_t, hunk_start_offset, anchor_bytes.len());
                    hunks.push(MultiBytePatchHunk {
                        hunk_index: hunks.len(),
                        op_kind: op_kind.into(),
                        anchor_offset: hunk_start_offset,
                        anchor_len: cur_a.len(),
                        target_len: cur_t.len(),
                        anchor_hex: hex::encode_upper(&cur_a),
                        target_hex: hex::encode_upper(&cur_t),
                        semantic_hint: hint,
                    });
                    cur_a.clear();
                    cur_t.clear();
                    in_hunk = false;
                }
            } else {
                if !in_hunk {
                    hunk_start_offset = anchor_cursor;
                    in_hunk = true;
                }
                if let Some(ba) = a_opt {
                    cur_a.push(ba);
                }
                if let Some(bt) = t_opt {
                    cur_t.push(bt);
                }
            }

            if a_opt.is_some() {
                anchor_cursor += 1;
            }
        }

        if in_hunk {
            let op_kind = match (cur_a.is_empty(), cur_t.is_empty()) {
                (true, false) => "INSERT",
                (false, true) => "DELETE",
                _ => "REPLACE",
            };
            let hint = infer_byte_hunk_semantic(&cur_a, &cur_t, hunk_start_offset, anchor_bytes.len());
            hunks.push(MultiBytePatchHunk {
                hunk_index: hunks.len(),
                op_kind: op_kind.into(),
                anchor_offset: hunk_start_offset,
                anchor_len: cur_a.len(),
                target_len: cur_t.len(),
                anchor_hex: hex::encode_upper(&cur_a),
                target_hex: hex::encode_upper(&cur_t),
                semantic_hint: hint,
            });
        }

        hex_script.push_str(&format!(
            "[TARGET #{} \"{}\" | {} bytes | SHA256={}]\n",
            idx + 1, label, target_raw.len(), target_sha256
        ));
        if hunks.is_empty() {
            hex_script.push_str("  NO_DIFF (100% IDENTICAL TO ANCHOR)\n\n");
        } else {
            for h in &hunks {
                hex_script.push_str(&format!(
                    "  HUNK #{:02} {:<7} @ 0x{:04X} (anchor_len={}, new_len={}) : [{}] -> [{}]  ; {}\n",
                    h.hunk_index,
                    h.op_kind,
                    h.anchor_offset,
                    h.anchor_len,
                    h.target_len,
                    if h.anchor_hex.is_empty() { "-" } else { &h.anchor_hex },
                    if h.target_hex.is_empty() { "-" } else { &h.target_hex },
                    h.semantic_hint
                ));
            }
            hex_script.push('\n');
        }

        // 拼接可逆 Python 片段: (anchor_offset, anchor_len, target_hex)
        let ops_list: Vec<String> = hunks
            .iter()
            .map(|h| format!("({}, {}, \"{}\")", h.anchor_offset, h.anchor_len, h.target_hex))
            .collect();
        py_targets.push_str(&format!(
            "    {{\n        \"index\": {},\n        \"label\": {:?},\n        \"expected_sha256\": \"{}\",\n        \"ops\": [{}],\n    }},\n",
            idx + 1, label, target_sha256, ops_list.join(", ")
        ));

        bundles.push(SamplePatchBundle {
            sample_index: idx,
            sample_label: label,
            target_byte_length: target_raw.len(),
            target_sha256,
            total_hunks: hunks.len(),
            hunks,
        });
    }

    let python_patch_script = format!(
        "#!/usr/bin/env python3\n\
# Auto-generated by Omni-Probe Multi-Diff Patch Generator\n\
import hashlib\n\n\
ANCHOR_HEX = \"{}\"\n\
ANCHOR_SHA256 = \"{}\"\n\n\
PATCH_TARGETS = [\n{}]\n\n\
def apply_ops(anchor: bytes, ops) -> bytes:\n\
    out = bytearray()\n\
    cursor = 0\n\
    for off, old_len, new_hex in ops:\n\
        out.extend(anchor[cursor:off])\n\
        if new_hex:\n\
            out.extend(bytes.fromhex(new_hex))\n\
        cursor = off + old_len\n\
    out.extend(anchor[cursor:])\n\
    return bytes(out)\n\n\
if __name__ == \"__main__\":\n\
    anchor_bytes = bytes.fromhex(ANCHOR_HEX)\n\
    assert hashlib.sha256(anchor_bytes).hexdigest() == ANCHOR_SHA256\n\
    for tgt in PATCH_TARGETS:\n\
        rebuilt = apply_ops(anchor_bytes, tgt[\"ops\"])\n\
        assert hashlib.sha256(rebuilt).hexdigest() == tgt[\"expected_sha256\"], tgt[\"label\"]\n\
        print(f\"Verified Target #{{tgt['index']}} ({{tgt['label']}}): {{len(rebuilt)}} bytes OK\")\n",
        hex::encode_upper(anchor_bytes),
        anchor_sha256,
        py_targets
    );

    Ok(MultiDiffPatchReport {
        anchor_index: safe_anchor,
        anchor_label,
        anchor_byte_length: anchor_bytes.len(),
        anchor_sha256,
        samples: bundles,
        hex_revision_script: hex_script,
        python_patch_script,
    })
}

/// 计算两组字节流的时域与空间域波形比对分析指标（余弦相似度、皮尔逊相关性、波率、差值点阵）
/// 时间复杂度: O(L), 空间复杂度: O(L), L = max(len_a, len_b)
pub fn compute_waveform_metrics(bytes_a: &[u8], bytes_b: &[u8]) -> WaveformComparisonMetrics {
    let len_a = bytes_a.len();
    let len_b = bytes_b.len();
    let max_len = len_a.max(len_b);

    if max_len == 0 {
        return WaveformComparisonMetrics {
            cosine_similarity: 1.0,
            pearson_correlation: 1.0,
            mean_absolute_deviation: 0.0,
            max_delta_offset: 0,
            max_delta_value: 0,
            mutation_wave_rate: 0.0,
            waveform_points: Vec::new(),
        };
    }

    let mut points = Vec::with_capacity(max_len);
    let mut dot_product: f64 = 0.0;
    let mut norm_a_sq: f64 = 0.0;
    let mut norm_b_sq: f64 = 0.0;
    let mut sum_a: f64 = 0.0;
    let mut sum_b: f64 = 0.0;
    let mut total_abs_delta: f64 = 0.0;
    let mut max_delta_val: i16 = 0;
    let mut max_delta_off: usize = 0;
    let mut mutated_count: usize = 0;

    for i in 0..max_len {
        let va = bytes_a.get(i).copied().unwrap_or(0);
        let vb = bytes_b.get(i).copied().unwrap_or(0);
        let fa = va as f64;
        let fb = vb as f64;
        let delta = va as i16 - vb as i16;
        let abs_delta = delta.abs();
        let is_mutated = (i >= len_a) || (i >= len_b) || (va != vb);

        if is_mutated {
            mutated_count += 1;
        }
        if abs_delta > max_delta_val {
            max_delta_val = abs_delta;
            max_delta_off = i;
        }
        total_abs_delta += abs_delta as f64;

        dot_product += fa * fb;
        norm_a_sq += fa * fa;
        norm_b_sq += fb * fb;
        sum_a += fa;
        sum_b += fb;

        points.push(DiffWaveformPoint {
            offset: i,
            val_a: va,
            val_b: vb,
            delta,
            is_mutated,
        });
    }

    // 1. 余弦相似度
    let denom_cos = (norm_a_sq.sqrt() * norm_b_sq.sqrt()).max(1e-12);
    let mut cosine_sim = dot_product / denom_cos;
    if cosine_sim.is_nan() {
        cosine_sim = if norm_a_sq == 0.0 && norm_b_sq == 0.0 { 1.0 } else { 0.0 };
    }
    cosine_sim = cosine_sim.clamp(-1.0, 1.0);

    // 2. 皮尔逊相关系数
    let mean_a = sum_a / max_len as f64;
    let mean_b = sum_b / max_len as f64;
    let mut numerator_pearson: f64 = 0.0;
    let mut var_a: f64 = 0.0;
    let mut var_b: f64 = 0.0;

    for p in &points {
        let da = p.val_a as f64 - mean_a;
        let db = p.val_b as f64 - mean_b;
        numerator_pearson += da * db;
        var_a += da * da;
        var_b += db * db;
    }

    let denom_pearson = (var_a.sqrt() * var_b.sqrt()).max(1e-12);
    let mut pearson = numerator_pearson / denom_pearson;
    if pearson.is_nan() {
        pearson = if var_a == 0.0 && var_b == 0.0 { 1.0 } else { 0.0 };
    }
    pearson = pearson.clamp(-1.0, 1.0);

    let mean_abs_dev = total_abs_delta / max_len as f64;
    let mutation_rate = (mutated_count as f64 / max_len as f64) * 100.0;

    WaveformComparisonMetrics {
        cosine_similarity: cosine_sim,
        pearson_correlation: pearson,
        mean_absolute_deviation: mean_abs_dev,
        max_delta_offset: max_delta_off,
        max_delta_value: max_delta_val,
        mutation_wave_rate: mutation_rate,
        waveform_points: points,
    }
}

/// 计算对齐后多样本（支持缺失态 None 不再误充 0x00）在各偏移列上的变异波率与局部信息熵谱
/// 时间复杂度: O(K * W), 空间复杂度: O(W)
pub fn compute_mutation_spectrum_opts(aligned_rows: &[Vec<Option<u8>>]) -> Vec<MutationWaveBin> {
    if aligned_rows.is_empty() {
        return Vec::new();
    }
    let max_len = aligned_rows.iter().map(|p| p.len()).max().unwrap_or(0);
    let total_samples = aligned_rows.len();
    if max_len == 0 || total_samples == 0 {
        return Vec::new();
    }

    let mut spectrum = Vec::with_capacity(max_len);

    for offset in 0..max_len {
        let mut freq_map: std::collections::HashMap<Option<u8>, usize> = std::collections::HashMap::new();
        for p in aligned_rows {
            let opt_b = p.get(offset).copied().flatten();
            *freq_map.entry(opt_b).or_insert(0usize) += 1;
        }

        let mut max_freq = 0usize;
        let mut dominant_byte: Option<u8> = None;
        let mut entropy = 0.0f64;

        for (&opt_b, &cnt) in &freq_map {
            if cnt > max_freq {
                max_freq = cnt;
                dominant_byte = opt_b;
            }
            let prob = cnt as f64 / total_samples as f64;
            if prob > 0.0 {
                entropy -= prob * prob.log2();
            }
        }

        let non_dominant = total_samples.saturating_sub(max_freq);
        let mutation_rate = (non_dominant as f64 / total_samples as f64) * 100.0;
        let dominant_hex = match dominant_byte {
            Some(b) => format!("{:02X}", b),
            None => "--".to_string(),
        };

        spectrum.push(MutationWaveBin {
            offset,
            mutation_rate,
            unique_values_count: freq_map.len(),
            entropy,
            dominant_hex,
        });
    }

    spectrum
}

/// 计算多样本在各字节偏移量上的变异波率（Mutation Wave Rate）与局部信息熵谱
/// 时间复杂度: O(K * L), 空间复杂度: O(K * L)
pub fn compute_mutation_spectrum(payloads: &[Vec<u8>]) -> Vec<MutationWaveBin> {
    let opt_rows: Vec<Vec<Option<u8>>> = payloads
        .iter()
        .map(|p| p.iter().copied().map(Some).collect())
        .collect();
    compute_mutation_spectrum_opts(&opt_rows)
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

    let waveform_metrics = Some(compute_waveform_metrics(&bytes_a, &bytes_b));

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
        waveform_metrics,
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

static IO_GRAPH_BUS_BUFFERS: Lazy<Arc<Mutex<HashMap<String, VecDeque<IoGraphBucket>>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

fn push_io_bucket(buf: &mut VecDeque<IoGraphBucket>, now_sec: u64, length: usize, rtt_ms: Option<f64>, is_retrans: bool) {
    if let Some(last) = buf.back_mut() {
        if last.timestamp_sec == now_sec {
            last.packet_count = last.packet_count.saturating_add(1);
            last.byte_count = last.byte_count.saturating_add(length as u64);
            if is_retrans {
                last.retrans_count = last.retrans_count.saturating_add(1);
            }
            if let Some(rtt) = rtt_ms {
                let total_rtt = last.avg_rtt_ms * (last.rtt_samples as f64) + rtt;
                last.rtt_samples = last.rtt_samples.saturating_add(1);
                last.avg_rtt_ms = total_rtt / (last.rtt_samples as f64);
            }
            return;
        }
    }

    let new_bucket = IoGraphBucket {
        timestamp_sec: now_sec,
        packet_count: 1,
        byte_count: length as u64,
        avg_rtt_ms: rtt_ms.unwrap_or(0.0),
        rtt_samples: if rtt_ms.is_some() { 1 } else { 0 },
        retrans_count: if is_retrans { 1 } else { 0 },
    };
    buf.push_back(new_bucket);

    while buf.len() > 300 {
        buf.pop_front();
    }
}

/// 标准化总线分类名称 (ETHERNET | SERIAL | USB | WIRELESS)
fn normalize_bus_key(bus: &str) -> String {
    let up = bus.trim().to_uppercase();
    if up.contains("SERIAL") || up.starts_with("COM") {
        "SERIAL".to_string()
    } else if up.contains("USB") {
        "USB".to_string()
    } else if up.contains("WIFI") || up.contains("WLAN") || up.contains("BLUETOOTH") || up.contains("WIRELESS") {
        "WIRELESS".to_string()
    } else {
        "ETHERNET".to_string()
    }
}

/// 记录单包时序指标并按物理总线分类入桶 (时间复杂度 O(1), 空间复杂度 O(1))
pub fn record_packet_io_with_bus(bus: &str, length: usize, rtt_ms: Option<f64>, is_retrans: bool) {
    let now_sec = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    };

    {
        let mut buf = crate::lock_guard::lock_mutex(&IO_GRAPH_BUFFER, "analyzer::record_packet_io");
        push_io_bucket(&mut buf, now_sec, length, rtt_ms, is_retrans);
    }

    let bus_key = normalize_bus_key(bus);
    {
        let mut bus_map = crate::lock_guard::lock_mutex(&IO_GRAPH_BUS_BUFFERS, "analyzer::record_packet_io_bus");
        let entry = bus_map.entry(bus_key).or_insert_with(|| VecDeque::with_capacity(320));
        push_io_bucket(entry, now_sec, length, rtt_ms, is_retrans);
    }
}

/// 记录单包时序指标 (默认归属 ETHERNET 总线，向后兼容现有调用方)
pub fn record_packet_io(length: usize, rtt_ms: Option<f64>, is_retrans: bool) {
    record_packet_io_with_bus("ETHERNET", length, rtt_ms, is_retrans);
}

fn summarize_io_buckets(buf: &VecDeque<IoGraphBucket>, win: usize) -> IoGraphSeries {
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
        max_bandwidth_bps: max_bw * 8,
    }
}

/// 查询指定时间窗口及可选物理总线过滤条件的 IO Graphs 曲线数据
pub fn get_io_graph_series_filtered(window_seconds: u32, bus_filter: Option<&str>) -> IoGraphSeries {
    let win = window_seconds.clamp(10, 300) as usize;
    if let Some(bus_raw) = bus_filter {
        let trimmed = bus_raw.trim();
        if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("ALL") {
            let bus_key = normalize_bus_key(trimmed);
            let bus_map = crate::lock_guard::lock_mutex(&IO_GRAPH_BUS_BUFFERS, "analyzer::get_io_graph_series_filtered");
            if let Some(buf) = bus_map.get(&bus_key) {
                return summarize_io_buckets(buf, win);
            }
            return IoGraphSeries {
                buckets: Vec::new(),
                total_packets: 0,
                total_bytes: 0,
                global_avg_rtt_ms: 0.0,
                max_bandwidth_bps: 0,
            };
        }
    }
    let buf = crate::lock_guard::lock_mutex(&IO_GRAPH_BUFFER, "analyzer::get_io_graph_series");
    summarize_io_buckets(&buf, win)
}

/// 查询指定时间窗口的全局 IO Graphs 曲线数据
pub fn get_io_graph_series(window_seconds: u32) -> IoGraphSeries {
    get_io_graph_series_filtered(window_seconds, None)
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
        let mut events = crate::lock_guard::lock_mutex(&CROSS_BUS_EVENTS, "analyzer::record_cross_bus_event");

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
        let mut corr_list = crate::lock_guard::lock_mutex(&CROSS_BUS_CORRELATIONS, "analyzer::record_cross_bus_correlation");
        corr_list.push(corr);
        while corr_list.len() > 200 {
            corr_list.remove(0);
        }
    }
}

/// 查询所有识别出的跨总线因果关联与时延记录
pub fn get_cross_bus_correlations() -> Vec<CrossBusCorrelationRecord> {
    let list = crate::lock_guard::lock_mutex(&CROSS_BUS_CORRELATIONS, "analyzer::get_cross_bus_correlations");
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

    #[test]
    fn test_waveform_metrics_calculation_and_edge_cases() {
        // 极限用例 1: 零长度
        let m_empty = compute_waveform_metrics(&[], &[]);
        assert_eq!(m_empty.mutation_wave_rate, 0.0);
        assert_eq!(m_empty.cosine_similarity, 1.0);

        // 极限用例 2: 完全一致
        let a = vec![0x10, 0x20, 0x30, 0x40];
        let b = vec![0x10, 0x20, 0x30, 0x40];
        let m_ident = compute_waveform_metrics(&a, &b);
        assert_eq!(m_ident.mutation_wave_rate, 0.0);
        assert!((m_ident.cosine_similarity - 1.0).abs() < 1e-6);
        assert_eq!(m_ident.max_delta_value, 0);

        // 极限用例 3: 局部大幅度突变
        let b_mut = vec![0x10, 0x20, 0xFA, 0x40];
        let m_mut = compute_waveform_metrics(&a, &b_mut);
        assert_eq!(m_mut.mutation_wave_rate, 25.0); // 1 / 4
        assert_eq!(m_mut.max_delta_offset, 2);
        assert_eq!(m_mut.max_delta_value, 0xFA - 0x30); // 250 - 48 = 202
    }

    #[test]
    fn test_mutation_spectrum_entropy_and_rate() {
        let p1 = vec![0x01, 0x02, 0x03, 0xAA];
        let p2 = vec![0x01, 0x02, 0x04, 0xBB];
        let p3 = vec![0x01, 0x02, 0x03, 0xCC];

        let spec = compute_mutation_spectrum(&[p1, p2, p3]);
        assert_eq!(spec.len(), 4);

        // offset 0: 全为 0x01，突变率为 0%
        assert_eq!(spec[0].mutation_rate, 0.0);
        assert_eq!(spec[0].dominant_hex, "01");

        // offset 1: 全为 0x02，突变率为 0%
        assert_eq!(spec[1].mutation_rate, 0.0);

        // offset 2: 2 个 0x03，1 个 0x04，突变率为 1/3 (33.33%)
        assert!((spec[2].mutation_rate - 33.333).abs() < 0.1);
        assert_eq!(spec[2].dominant_hex, "03");

        // offset 3: AA, BB, CC 各不相同，突变率为 2/3 (66.67%)
        assert!((spec[3].mutation_rate - 66.666).abs() < 0.1);
    }

    #[test]
    fn test_universal_payloads_comparison() {
        // 1. 正常十六进制报文比对 (模拟套接字调试或串口通讯响应帧)
        let mut extra_a = HashMap::new();
        extra_a.insert("direction".to_string(), "TX".to_string());
        extra_a.insert("baudrate".to_string(), "115200".to_string());

        let mut extra_b = HashMap::new();
        extra_b.insert("direction".to_string(), "RX".to_string());
        extra_b.insert("baudrate".to_string(), "115200".to_string());

        let item_a = UniversalDiffPayload {
            id: Some(101),
            label: "套接字调试 发送帧".to_string(),
            timestamp: Some("12:00:01.000".to_string()),
            protocol: Some("Modbus-RTU".to_string()),
            endpoint_src: Some("192.168.1.100:502".to_string()),
            endpoint_dst: Some("192.168.1.200:502".to_string()),
            payload_hex: "01 03 00 00 00 02 C4 0B".to_string(),
            raw_text: None,
            extra_fields: Some(extra_a),
        };

        let item_b = UniversalDiffPayload {
            id: Some(102),
            label: "套接字调试 接收帧".to_string(),
            timestamp: Some("12:00:01.025".to_string()),
            protocol: Some("Modbus-RTU".to_string()),
            endpoint_src: Some("192.168.1.200:502".to_string()),
            endpoint_dst: Some("192.168.1.100:502".to_string()),
            payload_hex: "01 03 04 00 12 00 34 89 21".to_string(),
            raw_text: None,
            extra_fields: Some(extra_b),
        };

        let res = compare_universal_payloads(item_a, item_b).expect("通用比对成功");
        assert_eq!(res.total_bytes_a, 8);
        assert_eq!(res.total_bytes_b, 9);
        assert!(res.mutated_bytes_count > 0);
        assert!(res.waveform_metrics.is_some());

        // 验证元数据比对字段中包含 direction 差异
        let dir_diff = res.field_diffs.iter().find(|f| f.field_name == "direction");
        assert!(dir_diff.is_some());
        assert!(dir_diff.unwrap().is_different);

        // 2. 极限用例: 空数据比对
        let empty_a = UniversalDiffPayload {
            id: None,
            label: "草稿 A".to_string(),
            timestamp: None,
            protocol: None,
            endpoint_src: None,
            endpoint_dst: None,
            payload_hex: "".to_string(),
            raw_text: None,
            extra_fields: None,
        };
        let empty_b = UniversalDiffPayload {
            id: None,
            label: "草稿 B".to_string(),
            timestamp: None,
            protocol: None,
            endpoint_src: None,
            endpoint_dst: None,
            payload_hex: "".to_string(),
            raw_text: None,
            extra_fields: None,
        };
        let res_empty = compare_universal_payloads(empty_a, empty_b).expect("空比对应平稳返回");
        assert_eq!(res_empty.total_bytes_a, 0);
        assert_eq!(res_empty.total_bytes_b, 0);
        assert_eq!(res_empty.mutation_rate_percent, 0.0);

        // 3. 极限用例: ASCII 纯文本比对
        let txt_a = UniversalDiffPayload {
            id: None,
            label: "HTTP 请求头 A".to_string(),
            timestamp: None,
            protocol: Some("HTTP".to_string()),
            endpoint_src: None,
            endpoint_dst: None,
            payload_hex: "".to_string(),
            raw_text: Some("GET /api/v1/status HTTP/1.1".to_string()),
            extra_fields: None,
        };
        let txt_b = UniversalDiffPayload {
            id: None,
            label: "HTTP 请求头 B".to_string(),
            timestamp: None,
            protocol: Some("HTTP".to_string()),
            endpoint_src: None,
            endpoint_dst: None,
            payload_hex: "".to_string(),
            raw_text: Some("POST /api/v1/update HTTP/1.1".to_string()),
            extra_fields: None,
        };
        let res_txt = compare_universal_payloads(txt_a, txt_b).expect("文本比对成功");
        assert!(res_txt.total_bytes_a > 10);
        assert!(res_txt.mutated_bytes_count > 0);
    }

    #[test]
    fn test_multi_group_center_star_alignment_and_missing_distinction() {
        // 验证 3 组含前部插入 + 尾部缺失的长度不一致载荷:
        // Anchor(0): 01 03 00 02
        // Group(1) : 01 AA 03 00 02  (第1字节后插入 AA)
        // Group(2) : 01 03 05        (第2字节 00->05 且尾部 02 缺失)
        let items = vec![
            UniversalDiffPayload {
                id: Some(1),
                label: "基准帧 #1".into(),
                timestamp: None,
                protocol: Some("MODBUS".into()),
                endpoint_src: Some("10.0.0.1".into()),
                endpoint_dst: Some("10.0.0.2".into()),
                payload_hex: "01 03 00 02".into(),
                raw_text: None,
                extra_fields: None,
            },
            UniversalDiffPayload {
                id: Some(2),
                label: "前插帧 #2".into(),
                timestamp: None,
                protocol: Some("MODBUS".into()),
                endpoint_src: Some("10.0.0.1".into()),
                endpoint_dst: Some("10.0.0.3".into()),
                payload_hex: "01 AA 03 00 02".into(),
                raw_text: None,
                extra_fields: None,
            },
            UniversalDiffPayload {
                id: Some(3),
                label: "尾缺帧 #3".into(),
                timestamp: None,
                protocol: Some("MODBUS".into()),
                endpoint_src: Some("10.0.0.1".into()),
                endpoint_dst: Some("10.0.0.4".into()),
                payload_hex: "01 03 05".into(),
                raw_text: None,
                extra_fields: None,
            },
        ];

        let multi = compare_multi_universal_payloads(items, Some(0)).expect("3组对齐比对成功");
        assert_eq!(multi.sample_count, 3);
        assert_eq!(multi.aligned_column_count, 5, "对齐总列宽必须包含插入隙共5列");

        let g0_cells = &multi.samples[0].aligned_hex.hex_rows[0].cells;
        let g1_cells = &multi.samples[1].aligned_hex.hex_rows[0].cells;
        let g2_cells = &multi.samples[2].aligned_hex.hex_rows[0].cells;

        // 列 0 全为 01
        assert_eq!(g0_cells[0].hex, "01");
        assert_eq!(g1_cells[0].hex, "01");
        assert_eq!(g2_cells[0].hex, "01");
        // 列 1 插入隙: 组0与组2填 -- (missing), 组1为 AA (insert)
        assert_eq!(g0_cells[1].hex, "--");
        assert_eq!(g1_cells[1].hex, "AA");
        assert_eq!(g1_cells[1].diff_type, "insert");
        assert_eq!(g2_cells[1].hex, "--");
        // 列 2 完美重对齐全为 03
        assert_eq!(g0_cells[2].hex, "03");
        assert_eq!(g1_cells[2].hex, "03");
        assert_eq!(g2_cells[2].hex, "03");
        assert_eq!(g1_cells[2].diff_type, "equal");
        assert_eq!(g2_cells[2].diff_type, "equal");
        // 列 4 尾部 02 缺失，不能混淆为 00
        assert_eq!(g0_cells[4].hex, "02");
        assert_eq!(g1_cells[4].hex, "02");
        assert_eq!(g2_cells[4].hex, "--");
        assert_eq!(multi.aligned_mutation_spectrum[4].dominant_hex, "02");
        assert!(multi.aligned_mutation_spectrum[4].mutation_rate > 30.0);

        // 也验证 ASCII 十六进制同名串 ("CAFE" / "1234") 不走 hex 解码错解
        let ascii_a = UniversalDiffPayload {
            id: None,
            label: "ASCII CAFE".into(),
            timestamp: None,
            protocol: Some("ASCII_TEXT".into()),
            endpoint_src: None,
            endpoint_dst: None,
            payload_hex: "".into(),
            raw_text: Some("CAFE".into()),
            extra_fields: None,
        };
        let ascii_b = UniversalDiffPayload {
            id: None,
            label: "ASCII 1234".into(),
            timestamp: None,
            protocol: Some("ASCII_TEXT".into()),
            endpoint_src: None,
            endpoint_dst: None,
            payload_hex: "".into(),
            raw_text: Some("1234".into()),
            extra_fields: None,
        };
        let res_ascii = compare_universal_payloads(ascii_a, ascii_b).expect("ASCII CAFE 对比成功");
        assert_eq!(res_ascii.total_bytes_a, 4, "CAFE 必须保持 4 字节而非 2 字节 Hex");
        assert_eq!(res_ascii.total_bytes_b, 4, "1234 必须保持 4 字节而非 2 字节 Hex");
    }

    #[test]
    fn test_multi_diff_patch_script_reversible_reconstruction() {
        let base_bytes = vec![0x01u8, 0x03, 0x00, 0x00, 0x00, 0x02, 0xC4, 0x0B];
        // 变体 1: 在最前面插入 0xAA，中段 0x02 改为 0x04
        let v1 = vec![0xAAu8, 0x01, 0x03, 0x00, 0x00, 0x00, 0x04, 0xC4, 0x0B];
        // 变体 2: 截断尾部 2 字节并将 0x00 改为 0x01
        let v2 = vec![0x01u8, 0x03, 0x00, 0x01, 0x00, 0x02];

        let mk = |id: u64, lbl: &str, bytes: &[u8]| UniversalDiffPayload {
            id: Some(id),
            label: lbl.into(),
            timestamp: None,
            protocol: Some("MODBUS-RTU".into()),
            endpoint_src: None,
            endpoint_dst: None,
            payload_hex: hex::encode(bytes),
            raw_text: None,
            extra_fields: None,
        };

        let report = generate_multi_diff_patch_report(
            vec![mk(1, "Anchor", &base_bytes), mk(2, "Variant-1", &v1), mk(3, "Variant-2", &v2)],
            Some(0),
        )
        .expect("生成 Patch 修订脚本应成功");

        assert_eq!(report.samples.len(), 2);
        assert!(report.hex_revision_script.contains("INSERT"));
        assert!(report.python_patch_script.contains("def apply_ops"));

        // 严格用与 python_patch_script 完全相同的重建算子从 base_bytes 逐条回放每个 sample 的 hunks，校验 100% 位级可逆
        for (idx, expected) in [v1, v2].iter().enumerate() {
            let bundle = &report.samples[idx];
            let mut rebuilt = Vec::new();
            let mut cursor = 0usize;
            for h in &bundle.hunks {
                rebuilt.extend_from_slice(&base_bytes[cursor..h.anchor_offset]);
                if !h.target_hex.is_empty() {
                    rebuilt.extend_from_slice(&hex::decode(&h.target_hex).unwrap());
                }
                cursor = h.anchor_offset + h.anchor_len;
            }
            rebuilt.extend_from_slice(&base_bytes[cursor..]);
            assert_eq!(rebuilt, *expected, "通过 Hunks 重放必须 100% 精准重构变体 #{}", idx + 1);
        }
    }

    #[test]
    fn test_large_payload_lcs_oom_defense_hirschberg_and_chunked() {
        // 压测 50KB 级大报文直通 compare_universal_payloads (触发 Hirschberg/分块防呆，严禁分配 20GB OOM)
        let mut raw_a = vec![0x41u8; 40_000];
        let mut raw_b = vec![0x41u8; 40_000];
        raw_a[15_000] = 0xBB;
        raw_b[15_000] = 0xCC;
        raw_b.splice(25_000..25_000, [0x99u8, 0x88u8]); // 插入 2 字节引起后续非相同

        let item_a = UniversalDiffPayload {
            id: Some(1),
            label: "40KB A".into(),
            timestamp: None,
            protocol: None,
            endpoint_src: None,
            endpoint_dst: None,
            payload_hex: hex::encode(&raw_a),
            raw_text: None,
            extra_fields: None,
        };
        let item_b = UniversalDiffPayload {
            id: Some(2),
            label: "40KB B".into(),
            timestamp: None,
            protocol: None,
            endpoint_src: None,
            endpoint_dst: None,
            payload_hex: hex::encode(&raw_b),
            raw_text: None,
            extra_fields: None,
        };
        let t0 = std::time::Instant::now();
        let res = compare_universal_payloads(item_a, item_b).expect("大包 LCS 比对不能 OOM");
        assert!(t0.elapsed().as_millis() < 2000, "40KB 载荷对比应在 2s 内完成: {:?}", t0.elapsed());
        assert_eq!(res.total_bytes_a, 40_000);
        assert_eq!(res.total_bytes_b, 40_002);
        assert!(res.mutated_bytes_count >= 2 && res.mutated_bytes_count < 100, "前缀与公共后缀剥离后仅少数突变，实际={}", res.mutated_bytes_count);
    }
}

