//! COM 物理串口 & USB 总线深度监测、辅助开发、数字信号比对与行业报告生成引擎
//!
//! # 工业级核心能力模块
//! 1. **数字信号与黄金波形智能比对引擎**:
//!    - Cooley-Tukey Radix-2 原地快速傅里叶变换 (FFT + Hann 汉宁窗), 时间 O(N log N), 空间 O(N)
//!    - Pearson 皮尔逊线性相关系数, 时间 O(N), 空间 O(1)
//!    - Sakoe-Chiba 带约束动态时间规整 (DTW) 形态对齐相似度, 时间 O(N * W), 空间 O(N)
//!    - 黄金波形基线持久化存储 (`bus_waveform_baselines.json`) 与智能漂移审计
//! 2. **USB 深度协议逆向与端点吞吐画像**:
//!    - 8 字节 USB Control Setup 包标准请求、Descriptor 类型及 CDC-ACM (`SET_LINE_CODING`/`SET_CONTROL_LINE_STATE`)、HID 类请求解码
//!    - 按 `Bus:Dev:Endpoint` 追踪 IN/OUT 带宽、传输类型分布 (Control/Bulk/Interrupt/Isochronous) 与 `USBD_STATUS` 错包统计
//!    - 标准 `USBPcap (DLT_USBPCAP = 249)` `.pcap` 双向导出与离线重放
//!    - 免 USBPcap 模式下 PnP 插拔持久化落盘修复，统一接入全局存证
//! 3. **COM 串口工控辅助开发工作台**:
//!    - Modbus RTU 实时寄存器矩阵 (`Slave / Func / Addr / Dec / Hex / 变化趋势`)
//!    - 从站/主站交互式规则自动应答引擎 (`SerialAutoResponderRule`) + 自动附加 Modbus CRC16
//!    - 周期定时指令发射控制器 + 工业全协议校验码构造器 (`Modbus-CRC16 / CCITT-CRC16 / SUM8 / XOR8 / LRC`)
//!    - 帧间到达间隔 $\Delta t$ (Inter-Frame Gap) 直方图与异常统计
//! 4. **行业规范巡检报告生成 (Markdown & 自包含 HTML 原子导出)**

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::f64::consts::PI;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

// ============================================================================
// 1. 数据路径与安全辅助
// ============================================================================

fn bus_data_dir() -> Option<PathBuf> {
    crate::forensics::data_path("bus_waveform_baselines.json")
        .parent()
        .map(|p| p.to_path_buf())
}

fn current_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn current_ts_str() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

pub fn decode_hex_flexible(raw: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if cleaned.is_empty() {
        return Err("十六进制输入不能为空".into());
    }
    if cleaned.len() % 2 != 0 {
        return Err("十六进制字节串长度必须为偶数".into());
    }
    hex::decode(&cleaned).map_err(|e| format!("十六进制格式无效: {}", e))
}

// ============================================================================
// 2. 数字信号处理、FFT 频谱与黄金波形智能对比引擎
// ============================================================================

/// 单边 FFT 频率分量条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FftBin {
    pub bin_index: usize,
    pub normalized_freq: f64, // k / N in [0.0, 0.5]
    pub magnitude: f64,
}

/// 持久化黄金波形基线快照
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaveformBaselineSnapshot {
    pub id: String,
    pub name: String,
    pub bus_type: String,     // "SERIAL" | "USB" | "ALL"
    pub source_port: String,  // 例如 "COM3" 或 "ALL"
    pub channel_name: String, // 例如 "temp" 或 "REG_INT16_LE@0"
    pub sample_rate_hz: f64,
    pub saved_at: String,
    pub samples: Vec<f64>,
    pub mean: f64,
    pub stddev: f64,
    pub min_val: f64,
    pub max_val: f64,
    pub dominant_fft_ratio: f64,
}

/// 智能波形比对综合报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartWaveformComparisonResult {
    pub baseline_id: String,
    pub baseline_name: String,
    pub channel_name: String,
    pub sample_count_baseline: usize,
    pub sample_count_realtime: usize,
    pub aligned_length: usize,
    pub pearson_r: f64,
    pub rmse: f64,
    pub mae: f64,
    pub max_deviation: f64,
    pub dtw_distance: f64,
    pub dtw_similarity_pct: f64,
    pub spectral_cosine_similarity: f64,
    pub baseline_dominant_freq: f64,
    pub realtime_dominant_freq: f64,
    pub outlier_point_count: usize,
    pub health_verdict: String,
    pub diagnostic_summary: String,
    pub aligned_baseline: Vec<f64>,
    pub aligned_realtime: Vec<f64>,
    pub pointwise_error: Vec<f64>,
    pub baseline_fft: Vec<FftBin>,
    pub realtime_fft: Vec<FftBin>,
}

/// 清洗非法 IEEE754 浮点 (过滤 NaN / Infinity)
fn sanitize_samples(samples: &[f64]) -> Vec<f64> {
    samples
        .iter()
        .copied()
        .filter(|v| v.is_finite())
        .take(4096)
        .collect()
}

/// 计算基础统计指标 (mean, stddev, min, max), 时间 O(N), 空间 O(1)
fn calc_stats(samples: &[f64]) -> (f64, f64, f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0, 0.0, 0.0);
    }
    let mut min_v = f64::INFINITY;
    let mut max_v = f64::NEG_INFINITY;
    let mut sum = 0.0f64;
    for &v in samples {
        if v < min_v {
            min_v = v;
        }
        if v > max_v {
            max_v = v;
        }
        sum += v;
    }
    let mean = sum / samples.len() as f64;
    let var = samples
        .iter()
        .map(|&v| {
            let d = v - mean;
            d * d
        })
        .sum::<f64>()
        / samples.len() as f64;
    (mean, var.sqrt(), min_v, max_v)
}

/// 分段线性重采样至目标点数，时间复杂度 O(target_len), 空间复杂度 O(target_len)
pub fn resample_linear(data: &[f64], target_len: usize) -> Vec<f64> {
    let clean = sanitize_samples(data);
    if clean.is_empty() || target_len == 0 {
        return Vec::new();
    }
    if clean.len() == 1 {
        return vec![clean[0]; target_len];
    }
    if clean.len() == target_len {
        return clean;
    }
    let src_max = (clean.len() - 1) as f64;
    let dst_max = (target_len.saturating_sub(1)).max(1) as f64;
    let mut out = Vec::with_capacity(target_len);
    for i in 0..target_len {
        let pos = (i as f64 / dst_max) * src_max;
        let idx = (pos.floor() as usize).min(clean.len() - 1);
        let frac = pos - idx as f64;
        let v0 = clean[idx];
        let v1 = clean[(idx + 1).min(clean.len() - 1)];
        out.push(v0 + (v1 - v0) * frac);
    }
    out
}

/// 原地 Cooley-Tukey Radix-2 快速傅里叶变换 (先去直流并施加 Hann 汉宁窗抑制频谱泄漏)
///
/// # 复杂度量化
/// - 时间复杂度: O(N log N) (N 为 <= 512 的 2 的整数次幂)
/// - 空间复杂度: O(N)
pub fn compute_radix2_fft(samples: &[f64]) -> (Vec<FftBin>, f64) {
    let clean = sanitize_samples(samples);
    if clean.len() < 4 {
        return (Vec::new(), 0.0);
    }

    // 取不超过 512 的最小 2 的幂次 (>= 16)
    let clamped_len = clean.len().min(512);
    let mut n = 16usize;
    while n < clamped_len && n < 512 {
        n <<= 1;
    }

    let slice = &clean[clean.len().saturating_sub(n)..];
    let m = slice.len();
    let mean = slice.iter().sum::<f64>() / m as f64;

    let mut re = vec![0.0f64; n];
    let mut im = vec![0.0f64; n];
    let denom = (m.saturating_sub(1)).max(1) as f64;
    for i in 0..m {
        // 施加 Hann 窗减小边界非整周期泄露
        let hann = 0.5 * (1.0 - (2.0 * PI * i as f64 / denom).cos());
        re[i] = (slice[i] - mean) * hann;
    }

    // 位反转置换
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while (j & bit) != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            re.swap(i, j);
            im.swap(i, j);
        }
    }

    // 蝶形迭代计算
    let mut step = 2usize;
    while step <= n {
        let half = step >> 1;
        let angle_step = -2.0 * PI / (step as f64);
        for group_start in (0..n).step_by(step) {
            for k in 0..half {
                let angle = angle_step * (k as f64);
                let wr = angle.cos();
                let wi = angle.sin();
                let idx1 = group_start + k;
                let idx2 = idx1 + half;
                let tr = wr * re[idx2] - wi * im[idx2];
                let ti = wr * im[idx2] + wi * re[idx2];
                re[idx2] = re[idx1] - tr;
                im[idx2] = im[idx1] - ti;
                re[idx1] += tr;
                im[idx1] += ti;
            }
        }
        step <<= 1;
    }

    let half_bins = (n / 2).min(128);
    let mut bins = Vec::with_capacity(half_bins);
    let mut max_mag = 0.0f64;
    let mut dom_ratio = 0.0f64;
    let scale = 2.0 / (m as f64);

    for k in 1..half_bins {
        let mag = (re[k] * re[k] + im[k] * im[k]).sqrt() * scale;
        let ratio = (k as f64) / (n as f64);
        if mag > max_mag {
            max_mag = mag;
            dom_ratio = (ratio * 10000.0).round() / 10000.0;
        }
        bins.push(FftBin {
            bin_index: k,
            normalized_freq: (ratio * 10000.0).round() / 10000.0,
            magnitude: (mag * 1000.0).round() / 1000.0,
        });
    }

    (bins, dom_ratio)
}

/// Pearson 皮尔逊线性相关系数, 时间 O(N), 空间 O(1)
/// 针对零方差平稳常值曲线执行防除零边界处理
pub fn compute_pearson_correlation(a: &[f64], b: &[f64]) -> f64 {
    let n = a.len().min(b.len());
    if n < 2 {
        return if n == 1 && (a[0] - b[0]).abs() < 1e-9 { 1.0 } else { 0.0 };
    }
    let mean_a = a[..n].iter().sum::<f64>() / n as f64;
    let mean_b = b[..n].iter().sum::<f64>() / n as f64;
    let mut num = 0.0f64;
    let mut den_a = 0.0f64;
    let mut den_b = 0.0f64;
    for i in 0..n {
        let da = a[i] - mean_a;
        let db = b[i] - mean_b;
        num += da * db;
        den_a += da * da;
        den_b += db * db;
    }
    if den_a < 1e-12 && den_b < 1e-12 {
        return if (mean_a - mean_b).abs() < 1e-6 { 1.0 } else { 0.0 };
    }
    if den_a < 1e-12 || den_b < 1e-12 {
        return 0.0;
    }
    (num / (den_a.sqrt() * den_b.sqrt())).clamp(-1.0, 1.0)
}

/// 带 Sakoe-Chiba 窗口约束的动态时间规整 (DTW)
///
/// # 复杂度量化
/// - 时间复杂度: O(N * W) (N <= 160, W = max(8, N/6))
/// - 空间复杂度: O(N) (两行滚动数组替代 N*N 矩阵)
pub fn compute_constrained_dtw(a: &[f64], b: &[f64]) -> (f64, f64) {
    let n_raw = a.len().min(b.len());
    if n_raw == 0 {
        return (0.0, 0.0);
    }
    let m = n_raw.min(160);
    let sa = resample_linear(a, m);
    let sb = resample_linear(b, m);

    let (ma, stda, _, _) = calc_stats(&sa);
    let (mb, stdb, _, _) = calc_stats(&sb);
    let norm = |arr: &[f64], mean: f64, std: f64| -> Vec<f64> {
        if std < 1e-9 {
            vec![0.0; arr.len()]
        } else {
            arr.iter().map(|&v| (v - mean) / std).collect()
        }
    };
    let na = norm(&sa, ma, stda);
    let nb = norm(&sb, mb, stdb);

    let band = (m / 6).max(8);
    let mut prev = vec![f64::INFINITY; m + 1];
    let mut curr = vec![f64::INFINITY; m + 1];
    prev[0] = 0.0;

    for i in 1..=m {
        curr.fill(f64::INFINITY);
        let j_start = i.saturating_sub(band).max(1);
        let j_end = (i + band).min(m);
        for j in j_start..=j_end {
            let cost = (na[i - 1] - nb[j - 1]).abs();
            let best_prev = prev[j].min(curr[j - 1]).min(prev[j - 1]);
            curr[j] = cost + best_prev;
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    let dist = prev[m];
    if !dist.is_finite() {
        return (999.0, 0.0);
    }
    let avg_cost = dist / (m as f64);
    // 平稳同形波形 avg_cost -> 0 => similarity -> 100%
    let sim = ((-avg_cost * 0.85).exp() * 100.0).clamp(0.0, 100.0);
    (
        (dist * 100.0).round() / 100.0,
        (sim * 10.0).round() / 10.0,
    )
}

fn cosine_similarity_fft(a: &[FftBin], b: &[FftBin]) -> f64 {
    let n = a.len().min(b.len());
    if n == 0 {
        return 0.0;
    }
    let mut dot = 0.0f64;
    let mut na = 0.0f64;
    let mut nb = 0.0f64;
    for i in 0..n {
        let va = a[i].magnitude;
        let vb = b[i].magnitude;
        dot += va * vb;
        na += va * va;
        nb += vb * vb;
    }
    if na < 1e-12 && nb < 1e-12 {
        return 1.0;
    }
    if na < 1e-12 || nb < 1e-12 {
        return 0.0;
    }
    (dot / (na.sqrt() * nb.sqrt())).clamp(0.0, 1.0)
}

pub fn save_waveform_baseline_in_dir(
    dir: &Path,
    name: &str,
    bus_type: &str,
    source_port: &str,
    channel_name: &str,
    sample_rate_hz: f64,
    raw_samples: &[f64],
) -> Result<WaveformBaselineSnapshot, String> {
    let samples = sanitize_samples(raw_samples);
    if samples.len() < 4 {
        return Err("实时有效波形采样点数不足 4 个，无法固化黄金波形基线".into());
    }
    fs::create_dir_all(dir).map_err(|e| format!("创建基线目录失败: {}", e))?;

    let (mean, stddev, min_val, max_val) = calc_stats(&samples);
    let (_, dom_freq) = compute_radix2_fft(&samples);
    let id = format!("wf_{}_{}", current_epoch_ms(), std::process::id());
    let snap = WaveformBaselineSnapshot {
        id,
        name: if name.trim().is_empty() {
            format!("{} 黄金基线", channel_name)
        } else {
            name.trim().to_string()
        },
        bus_type: bus_type.trim().to_uppercase(),
        source_port: source_port.trim().to_string(),
        channel_name: channel_name.trim().to_string(),
        sample_rate_hz: sample_rate_hz.max(0.1),
        saved_at: current_ts_str(),
        samples: samples.into_iter().take(512).collect(),
        mean: (mean * 1000.0).round() / 1000.0,
        stddev: (stddev * 1000.0).round() / 1000.0,
        min_val,
        max_val,
        dominant_fft_ratio: dom_freq,
    };

    let mut list = list_waveform_baselines_in_dir(dir);
    list.insert(0, snap.clone());
    if list.len() > 32 {
        list.truncate(32);
    }
    persist_waveform_baselines_in_dir(dir, &list)?;
    Ok(snap)
}

fn persist_waveform_baselines_in_dir(
    dir: &Path,
    list: &[WaveformBaselineSnapshot],
) -> Result<(), String> {
    let target = dir.join("bus_waveform_baselines.json");
    let tmp = dir.join(format!("bus_waveform_baselines.tmp_{}", std::process::id()));
    let json = serde_json::to_vec_pretty(list).map_err(|e| format!("序列化基线失败: {}", e))?;
    fs::write(&tmp, &json).map_err(|e| format!("写基线临时文件失败: {}", e))?;
    #[cfg(windows)]
    if target.exists() {
        let _ = fs::remove_file(&target);
    }
    fs::rename(&tmp, &target).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("原子更新波形基线文件失败: {}", e)
    })?;
    Ok(())
}

pub fn list_waveform_baselines_in_dir(dir: &Path) -> Vec<WaveformBaselineSnapshot> {
    let path = dir.join("bus_waveform_baselines.json");
    let Ok(bytes) = fs::read(&path) else {
        return Vec::new();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub fn delete_waveform_baseline_in_dir(dir: &Path, id: &str) -> Result<bool, String> {
    let mut list = list_waveform_baselines_in_dir(dir);
    let before = list.len();
    list.retain(|b| b.id != id);
    if list.len() == before {
        return Ok(false);
    }
    persist_waveform_baselines_in_dir(dir, &list)?;
    Ok(true)
}

/// 智能比对实时传感器/寄存器波形与历史黄金基线
pub fn smart_compare_waveforms_in_dir(
    dir: &Path,
    baseline_id: &str,
    raw_realtime: &[f64],
    channel_name: &str,
) -> Result<SmartWaveformComparisonResult, String> {
    let list = list_waveform_baselines_in_dir(dir);
    let baseline = list
        .into_iter()
        .find(|b| b.id == baseline_id)
        .ok_or_else(|| format!("未找到指定的历史黄金波形基线: {}", baseline_id))?;

    let rt_clean = sanitize_samples(raw_realtime);
    if rt_clean.len() < 4 {
        return Err("当前实时波形有效样本不足 4 点，无法执行智能对齐与频域比对".into());
    }

    let aligned_len = baseline.samples.len().max(rt_clean.len()).clamp(16, 256);
    let aligned_base = resample_linear(&baseline.samples, aligned_len);
    let aligned_rt = resample_linear(&rt_clean, aligned_len);

    let pearson_r = compute_pearson_correlation(&aligned_base, &aligned_rt);
    let mut sq_err = 0.0f64;
    let mut abs_err = 0.0f64;
    let mut max_dev = 0.0f64;
    let mut pointwise_error = Vec::with_capacity(aligned_len);
    let threshold = (baseline.stddev * 2.5).max((baseline.max_val - baseline.min_val) * 0.15).max(1.0);
    let mut outlier_count = 0usize;

    for i in 0..aligned_len {
        let err = aligned_rt[i] - aligned_base[i];
        let aerr = err.abs();
        sq_err += err * err;
        abs_err += aerr;
        if aerr > max_dev {
            max_dev = aerr;
        }
        if aerr > threshold {
            outlier_count += 1;
        }
        pointwise_error.push((err * 1000.0).round() / 1000.0);
    }

    let rmse = (sq_err / aligned_len as f64).sqrt();
    let mae = abs_err / aligned_len as f64;
    let (dtw_dist, dtw_sim) = compute_constrained_dtw(&aligned_base, &aligned_rt);

    let (base_fft, base_dom) = compute_radix2_fft(&baseline.samples);
    let (rt_fft, rt_dom) = compute_radix2_fft(&rt_clean);
    let spec_sim = cosine_similarity_fft(&base_fft, &rt_fft);

    let health_verdict = if dtw_sim >= 82.0 && pearson_r >= 0.75 && outlier_count <= aligned_len / 10 {
        "一致稳定 (与历史黄金波形吻合)".to_string()
    } else if dtw_sim >= 60.0 || pearson_r >= 0.45 {
        "存在相位或幅值漂移 (需复核传感器零漂/周期)".to_string()
    } else {
        "显著波形畸变或异常失真 (触发超差告警)".to_string()
    };

    let diagnostic_summary = format!(
        "[{}] DTW 形态相似度 {:.1}% | Pearson r={:.3} | RMSE={:.2} | 频谱余弦相似度 {:.2} | 超差采样点 {}/{}",
        health_verdict, dtw_sim, pearson_r, rmse, spec_sim, outlier_count, aligned_len
    );

    Ok(SmartWaveformComparisonResult {
        baseline_id: baseline.id,
        baseline_name: baseline.name,
        channel_name: if channel_name.trim().is_empty() {
            baseline.channel_name
        } else {
            channel_name.trim().to_string()
        },
        sample_count_baseline: baseline.samples.len(),
        sample_count_realtime: rt_clean.len(),
        aligned_length: aligned_len,
        pearson_r: (pearson_r * 1000.0).round() / 1000.0,
        rmse: (rmse * 1000.0).round() / 1000.0,
        mae: (mae * 1000.0).round() / 1000.0,
        max_deviation: (max_dev * 1000.0).round() / 1000.0,
        dtw_distance: dtw_dist,
        dtw_similarity_pct: dtw_sim,
        spectral_cosine_similarity: (spec_sim * 1000.0).round() / 1000.0,
        baseline_dominant_freq: base_dom,
        realtime_dominant_freq: rt_dom,
        outlier_point_count: outlier_count,
        health_verdict,
        diagnostic_summary,
        aligned_baseline: aligned_base,
        aligned_realtime: aligned_rt,
        pointwise_error,
        baseline_fft: base_fft,
        realtime_fft: rt_fft,
    })
}

// ============================================================================
// 3. USB 深度协议解剖 (8B Setup / CDC-ACM / HID) & 端点画像与 PCAP 互操作
// ============================================================================

/// USB Control Setup 8 字节请求结构解析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbSetupDissection {
    pub direction: String,    // "Host -> Device" | "Device -> Host"
    pub req_type: String,     // "Standard" | "Class" | "Vendor"
    pub recipient: String,    // "Device" | "Interface" | "Endpoint" | "Other"
    pub bm_request_type: u8,
    pub b_request: u8,
    pub request_name: String,
    pub w_value: u16,
    pub w_index: u16,
    pub w_length: u16,
    pub cdc_line_coding: Option<String>,
    pub summary: String,
}

/// 解码 USB Control 传输 8 字节 Setup Packet (可附带后继 Data Stage，如 CDC SET_LINE_CODING)
/// 时间复杂度: O(1), 空间复杂度: O(1)
pub fn dissect_usb_setup_packet(payload: &[u8]) -> Option<UsbSetupDissection> {
    if payload.len() < 8 {
        return None;
    }
    let bm = payload[0];
    let b_req = payload[1];
    let w_val = u16::from_le_bytes([payload[2], payload[3]]);
    let w_idx = u16::from_le_bytes([payload[4], payload[5]]);
    let w_len = u16::from_le_bytes([payload[6], payload[7]]);

    let dir_in = (bm & 0x80) != 0;
    let direction = if dir_in { "Device -> Host" } else { "Host -> Device" }.to_string();
    let ty_code = (bm >> 5) & 0x03;
    let req_type = match ty_code {
        0 => "Standard",
        1 => "Class",
        2 => "Vendor",
        _ => "Reserved",
    }
    .to_string();
    let rec_code = bm & 0x1F;
    let recipient = match rec_code {
        0 => "Device",
        1 => "Interface",
        2 => "Endpoint",
        3 => "Other",
        _ => "Reserved",
    }
    .to_string();

    // 若 bmRequestType == 0x21 / 0xA1 (Class-Interface) 且符合常见请求码，或 Standard (ty_code==0)
    let mut cdc_line_coding = None;
    let req_name = if ty_code == 0 {
        match b_req {
            0x00 => "GET_STATUS".to_string(),
            0x01 => "CLEAR_FEATURE".to_string(),
            0x03 => "SET_FEATURE".to_string(),
            0x05 => format!("SET_ADDRESS (Addr={})", w_val & 0x7F),
            0x06 => {
                let desc_type = (w_val >> 8) as u8;
                let desc_idx = (w_val & 0xFF) as u8;
                let desc_label = match desc_type {
                    0x01 => "Device",
                    0x02 => "Configuration",
                    0x03 => "String",
                    0x04 => "Interface",
                    0x05 => "Endpoint",
                    0x06 => "Device_Qualifier",
                    0x0F => "BOS",
                    0x21 => "HID",
                    0x22 => "HID_Report",
                    _ => "Descriptor",
                };
                format!("GET_DESCRIPTOR ({} idx={}, len={})", desc_label, desc_idx, w_len)
            }
            0x07 => "SET_DESCRIPTOR".to_string(),
            0x08 => "GET_CONFIGURATION".to_string(),
            0x09 => format!("SET_CONFIGURATION (Cfg={})", w_val & 0xFF),
            0x0A => "GET_INTERFACE".to_string(),
            0x0B => "SET_INTERFACE".to_string(),
            _ => format!("STD_REQ_0x{:02X}", b_req),
        }
    } else if ty_code == 1 {
        match b_req {
            0x20 => {
                // USB CDC-ACM SET_LINE_CODING (若携带 7B 数据: baud u32 LE + stop + parity + databits)
                if payload.len() >= 15 {
                    let baud = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
                    let stop = match payload[12] {
                        0 => "1",
                        1 => "1.5",
                        2 => "2",
                        _ => "?",
                    };
                    let parity = match payload[13] {
                        0 => "N",
                        1 => "O",
                        2 => "E",
                        3 => "M",
                        4 => "S",
                        _ => "?",
                    };
                    let bits = payload[14];
                    cdc_line_coding = Some(format!("{} bps ({}{}{})", baud, bits, parity, stop));
                }
                "CDC_SET_LINE_CODING".to_string()
            }
            0x21 => "CDC_GET_LINE_CODING".to_string(),
            0x22 => {
                let dtr = (w_val & 0x01) != 0;
                let rts = (w_val & 0x02) != 0;
                cdc_line_coding = Some(format!("DTR={}, RTS={}", dtr as u8, rts as u8));
                "CDC_SET_CONTROL_LINE_STATE".to_string()
            }
            0x01 => "HID_GET_REPORT".to_string(),
            0x02 => "HID_GET_IDLE".to_string(),
            0x09 => "HID_SET_REPORT".to_string(),
            0x0A => "HID_SET_IDLE".to_string(),
            0x0B => "HID_SET_PROTOCOL".to_string(),
            0xFF if rec_code == 1 => "MSC_BULK_ONLY_RESET".to_string(),
            0xFE if rec_code == 1 => "MSC_GET_MAX_LUN".to_string(),
            _ => format!("CLASS_REQ_0x{:02X}", b_req),
        }
    } else {
        format!("VENDOR_REQ_0x{:02X}", b_req)
    };

    // 基础合法性检查：避免将随机大端数据误判成 Control Setup（只有 standard<=0x0C 或 class/vendor 合规）
    if ty_code == 3 {
        return None;
    }

    let summary = if let Some(ref cdc) = cdc_line_coding {
        format!("USB {} {} ({}) [{}]", req_type, req_name, direction, cdc)
    } else {
        format!(
            "USB {} {} [{}] wVal=0x{:04X} wIdx=0x{:04X} wLen={}",
            req_type, req_name, direction, w_val, w_idx, w_len
        )
    };

    Some(UsbSetupDissection {
        direction,
        req_type,
        recipient,
        bm_request_type: bm,
        b_request: b_req,
        request_name: req_name,
        w_value: w_val,
        w_index: w_idx,
        w_length: w_len,
        cdc_line_coding,
        summary,
    })
}

/// 单个 USB 端点吞吐与健康统计画像
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbEndpointStats {
    pub endpoint_key: String, // e.g. "Bus1:Dev3:EP81"
    pub bus: u16,
    pub device_addr: u16,
    pub endpoint: u8,
    pub transfer_type: String,
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub urb_count: u64,
    pub error_urb_count: u64,
    pub last_usbd_status: String,
    pub last_protocol: String,
    pub last_seen: String,
}

/// 保留供离线导出 `.pcap` 与 Setup 解剖时间线展示的 USB URB 记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbUrbEventItem {
    pub id: u64,
    pub timestamp: String,
    pub ts_ns: u128,
    pub controller: String,
    pub endpoint_key: String,
    pub transfer_type: String,
    pub direction: String,
    pub protocol: String,
    pub payload_len: usize,
    pub usbd_status: String,
    pub is_error: bool,
    pub summary: String,
    pub setup_decoded: Option<UsbSetupDissection>,
    pub raw_urb_hex: String,
}

/// USB 全局深度指标聚合状态机
pub struct UsbTelemetryEngine {
    pub total_urbs: u64,
    pub total_bytes: u64,
    pub control_urbs: u64,
    pub bulk_urbs: u64,
    pub interrupt_urbs: u64,
    pub isochronous_urbs: u64,
    pub error_urbs: u64,
    pub pnp_attach_count: u64,
    pub pnp_detach_count: u64,
    pub last_persisted_ms: u64,
    pub endpoint_map: HashMap<String, UsbEndpointStats>,
    pub recent_urbs: VecDeque<UsbUrbEventItem>,
}

pub static GLOBAL_USB_TELEMETRY: Lazy<RwLock<UsbTelemetryEngine>> = Lazy::new(|| {
    RwLock::new(UsbTelemetryEngine {
        total_urbs: 0,
        total_bytes: 0,
        control_urbs: 0,
        bulk_urbs: 0,
        interrupt_urbs: 0,
        isochronous_urbs: 0,
        error_urbs: 0,
        pnp_attach_count: 0,
        pnp_detach_count: 0,
        last_persisted_ms: 0,
        endpoint_map: HashMap::new(),
        recent_urbs: VecDeque::with_capacity(160),
    })
});

static NEXT_USB_EVENT_ID: AtomicU64 = AtomicU64::new(1);

/// 由 `usb::build_usb_urb_packet_record` 实时调用：汇总 Endpoint 画像、Setup 请求解码并缓存原生 URB
pub fn record_usb_urb_frame(
    controller_name: &str,
    ts_ns: u128,
    hdr: Option<&crate::usb::UsbPcapHeaderInfo>,
    urb_payload: &[u8],
    raw_urb_frame: &[u8],
    protocol: &str,
    summary: &str,
) {
    let ts_str = chrono::Local::now().format("%H:%M:%S.%3f").to_string();
    let now_ms = current_epoch_ms();

    let (ep_key, bus, dev, ep, ttype, is_in, status_val) = if let Some(h) = hdr {
        (
            format!("Bus{}:Dev{}:EP{:02X}", h.bus, h.device, h.endpoint),
            h.bus,
            h.device,
            h.endpoint,
            h.transfer_type.clone(),
            h.is_in,
            h.usbd_status,
        )
    } else {
        (
            format!("{}:EP00", controller_name),
            0,
            0,
            0,
            "Unknown".to_string(),
            true,
            0,
        )
    };

    let setup_decoded = if ttype == "Control" {
        dissect_usb_setup_packet(urb_payload)
    } else {
        None
    };

    let final_summary = if let Some(ref sd) = setup_decoded {
        sd.summary.clone()
    } else {
        summary.to_string()
    };

    let is_error = status_val != 0;
    let status_hex = format!("0x{:08X}", status_val);

    let mut lock = GLOBAL_USB_TELEMETRY
        .write()
        .unwrap_or_else(|p| p.into_inner());
    lock.total_urbs += 1;
    lock.total_bytes += urb_payload.len() as u64;
    if is_error {
        lock.error_urbs += 1;
    }
    match ttype.as_str() {
        "Control" => lock.control_urbs += 1,
        "Bulk" => lock.bulk_urbs += 1,
        "Interrupt" => lock.interrupt_urbs += 1,
        "Isochronous" => lock.isochronous_urbs += 1,
        _ => {}
    }

    if !lock.endpoint_map.contains_key(&ep_key) && lock.endpoint_map.len() >= 128 {
        if let Some(first_k) = lock.endpoint_map.keys().next().cloned() {
            lock.endpoint_map.remove(&first_k);
        }
    }
    let stats = lock
        .endpoint_map
        .entry(ep_key.clone())
        .or_insert_with(|| UsbEndpointStats {
            endpoint_key: ep_key.clone(),
            bus,
            device_addr: dev,
            endpoint: ep,
            transfer_type: ttype.clone(),
            in_bytes: 0,
            out_bytes: 0,
            urb_count: 0,
            error_urb_count: 0,
            last_usbd_status: status_hex.clone(),
            last_protocol: protocol.to_string(),
            last_seen: ts_str.clone(),
        });
    stats.urb_count += 1;
    if is_in {
        stats.in_bytes += urb_payload.len() as u64;
    } else {
        stats.out_bytes += urb_payload.len() as u64;
    }
    if is_error {
        stats.error_urb_count += 1;
    }
    stats.last_usbd_status = status_hex.clone();
    stats.last_protocol = protocol.to_string();
    stats.last_seen = ts_str.clone();

    if lock.recent_urbs.len() >= 160 {
        lock.recent_urbs.pop_front();
    }
    lock.recent_urbs.push_back(UsbUrbEventItem {
        id: NEXT_USB_EVENT_ID.fetch_add(1, Ordering::Relaxed),
        timestamp: ts_str,
        ts_ns,
        controller: controller_name.to_string(),
        endpoint_key: ep_key,
        transfer_type: ttype,
        direction: if is_in { "IN".into() } else { "OUT".into() },
        protocol: protocol.to_string(),
        payload_len: urb_payload.len(),
        usbd_status: status_hex,
        is_error,
        summary: final_summary,
        setup_decoded,
        raw_urb_hex: hex::encode_upper(raw_urb_frame),
    });

    let should_persist = is_error || now_ms.saturating_sub(lock.last_persisted_ms) >= 1200;
    if should_persist {
        lock.last_persisted_ms = now_ms;
    }
    drop(lock);

    #[cfg(not(test))]
    if should_persist {
        if let Some(dir) = bus_data_dir() {
            append_bus_history_metric_in_dir(
                &dir,
                "USB",
                controller_name,
                urb_payload.len(),
                0.0,
                is_error,
            );
        }
    }
}

/// 补全 USB 免驱动 PnP 模式下插拔事件入账历史与统计状态机
pub fn record_usb_pnp_event(event_type: &str, vid: &str, pid: &str, device_name: &str) {
    let mut lock = GLOBAL_USB_TELEMETRY
        .write()
        .unwrap_or_else(|p| p.into_inner());
    if event_type == "USB_ATTACH" {
        lock.pnp_attach_count += 1;
    } else if event_type == "USB_DETACH" {
        lock.pnp_detach_count += 1;
    }
    drop(lock);

    #[cfg(not(test))]
    if let Some(dir) = bus_data_dir() {
        append_bus_history_metric_in_dir(
            &dir,
            "USB",
            &format!("{}_{}:{}", event_type, vid, pid),
            device_name.len(),
            0.0,
            false,
        );
    }
    #[cfg(test)]
    let _ = (vid, pid, device_name);
}

/// 将内存 USB URB 帧打包为 Wireshark 标准 USBPcap (DLT_USBPCAP = 249) PCAP 字节流
pub fn encode_usb_frames_to_usbpcap_pcap(frames: &[UsbUrbEventItem]) -> Result<(Vec<u8>, usize), String> {
    if frames.is_empty() {
        return Err("当前未捕获到可导出的 USBPcap URB 底层帧（免驱动 PnP 模式仅捕获插拔描述符，URB 导出需开启 USBPcap 或导入过 .pcap）".into());
    }
    let mut out = Vec::with_capacity(24 + frames.len() * 64);
    // PCAP 全局头: Magic=0xA1B2C3D4, v2.4, LinkType=249 (DLT_USBPCAP)
    out.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&249u32.to_le_bytes());

    let mut count = 0usize;
    for fr in frames {
        let Ok(raw) = hex::decode(&fr.raw_urb_hex) else {
            continue;
        };
        if raw.is_empty() || raw.len() > 65535 {
            continue;
        }
        let sec = (fr.ts_ns / 1_000_000_000) as u32;
        let usec = ((fr.ts_ns % 1_000_000_000) / 1_000) as u32;
        let len_u32 = raw.len() as u32;

        out.extend_from_slice(&sec.to_le_bytes());
        out.extend_from_slice(&usec.to_le_bytes());
        out.extend_from_slice(&len_u32.to_le_bytes());
        out.extend_from_slice(&len_u32.to_le_bytes());
        out.extend_from_slice(&raw);
        count += 1;
    }

    if count == 0 {
        return Err("URB 缓存均缺少有效二进制载荷".into());
    }
    Ok((out, count))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbPcapImportResult {
    pub cancelled: bool,
    pub file_path: Option<String>,
    pub imported_urbs: usize,
    pub setup_packets_decoded: usize,
    pub scsi_packets_decoded: usize,
    pub hid_packets_decoded: usize,
    pub diagnostic_message: String,
}

#[tauri::command]
pub async fn export_usb_usbpcap_pcap_cmd() -> Result<crate::bluetooth_monitor::BtsnoopExportResult, String> {
    tokio::task::spawn_blocking(|| {
        let frames: Vec<UsbUrbEventItem> = {
            let lock = GLOBAL_USB_TELEMETRY
                .read()
                .unwrap_or_else(|p| p.into_inner());
            lock.recent_urbs.iter().cloned().collect()
        };
        let (bytes, count) = encode_usb_frames_to_usbpcap_pcap(&frames)?;
        let default_name = format!(
            "omni_probe_usbpcap_{}.pcap",
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        );
        let outcome = crate::desktop_native::save_bytes_with_native_dialog(
            &default_name,
            "导出 Wireshark 标准 USBPcap (DLT 249) 抓包文件",
            "USBPcap 抓包文件 (*.pcap)",
            "*.pcap",
            &bytes,
        )?;
        Ok(crate::bluetooth_monitor::BtsnoopExportResult {
            saved: outcome.saved,
            cancelled: outcome.cancelled,
            path: outcome.path,
            packet_count: count,
            bytes_written: outcome.bytes_written,
            message: if outcome.cancelled {
                "已取消 USBPcap 导出".into()
            } else {
                format!("已将 {} 帧 USB URB 原子导出为标准 USBPcap .pcap ({} 字节)", count, outcome.bytes_written)
            },
        })
    })
    .await
    .map_err(|e| format!("USBPcap 导出线程异常: {}", e))?
}

#[tauri::command]
pub async fn pick_and_import_usb_pcap_cmd() -> Result<UsbPcapImportResult, String> {
    tokio::task::spawn_blocking(|| {
        let picked = crate::desktop_native::pick_native_file_dialog(
            "导入标准 USBPcap 抓包文件 (.pcap)",
            "USBPcap 捕获日志 (*.pcap;*.cap)",
            "*.pcap;*.cap",
        )?;
        let Some(path) = picked else {
            return Ok(UsbPcapImportResult {
                cancelled: true,
                file_path: None,
                imported_urbs: 0,
                setup_packets_decoded: 0,
                scsi_packets_decoded: 0,
                hid_packets_decoded: 0,
                diagnostic_message: "已取消导入 USBPcap 文件".into(),
            });
        };

        let meta = fs::metadata(&path).map_err(|e| format!("无法读取文件元数据: {}", e))?;
        if meta.len() > 64 * 1024 * 1024 {
            return Err("USBPcap 文件超出 64MB 单次导入解析安全上限".into());
        }
        let raw = fs::read(&path).map_err(|e| format!("读取 USBPcap 文件失败: {}", e))?;

        let mut reader = crate::usb::StreamingPcapUrbReader::new();
        let frames = reader.push_bytes(&raw)?;
        let mut imported = 0usize;
        let mut setup_cnt = 0usize;
        let mut scsi_cnt = 0usize;
        let mut hid_cnt = 0usize;

        for (ts_ns, raw_urb) in frames.into_iter().take(15_000) {
            let rec = crate::usb::build_usb_urb_packet_record("USBPcap-Import", ts_ns, &raw_urb);
            imported += 1;
            if rec.protocol == "USB_SCSI" {
                scsi_cnt += 1;
            } else if rec.protocol.starts_with("USB_HID") {
                hid_cnt += 1;
            }
            if let Some((hdr, urb_p)) = crate::usb::parse_usbpcap_header(&raw_urb) {
                if hdr.transfer_type == "Control" && dissect_usb_setup_packet(urb_p).is_some() {
                    setup_cnt += 1;
                }
            }
        }

        Ok(UsbPcapImportResult {
            cancelled: false,
            file_path: Some(path),
            imported_urbs: imported,
            setup_packets_decoded: setup_cnt,
            scsi_packets_decoded: scsi_cnt,
            hid_packets_decoded: hid_cnt,
            diagnostic_message: format!(
                "USBPcap .pcap 导入重放完成: 解析 {} 帧 URB (Control Setup {} 帧, SCSI 存储 {} 帧, HID {} 帧)",
                imported, setup_cnt, scsi_cnt, hid_cnt
            ),
        })
    })
    .await
    .map_err(|e| format!("USBPcap 导入线程异常: {}", e))?
}

// ============================================================================
// 4. COM 串口工控辅助开发引擎 (Modbus 矩阵 / 规则自动应答 / 周期发包 / 校验)
// ============================================================================

/// 工业串口实时 Modbus 寄存器画像条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusRegisterCell {
    pub key: String, // "COM3:S1:F03:0000"
    pub port_name: String,
    pub slave_id: u8,
    pub function_code: u8,
    pub register_addr: u16,
    pub raw_u16: u16,
    pub signed_i16: i16,
    pub hex_value: String,
    pub prev_u16: Option<u16>,
    pub trend: String, // "NEW" | "UP" | "DOWN" | "SAME"
    pub update_count: u64,
    pub last_updated_at: String,
}

/// 单个物理串口的时序到达间隔与误码统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialPortGapMetrics {
    pub port_name: String,
    pub total_rx_frames: u64,
    pub total_rx_bytes: u64,
    pub modbus_crc_errors: u64,
    pub last_gap_ms: f64,
    pub avg_gap_ms: f64,
    pub min_gap_ms: f64,
    pub max_gap_ms: f64,
    /// 直方图分桶: [<5ms黏连风险, 5~20ms高速, 20~100ms标准, 100~500ms中速, >500ms长周期]
    pub gap_histogram: [u64; 5],
}

/// 串口自动应答 / 从站仿真规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialAutoResponderRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub port_filter: String,      // "ALL" 或具体 "COM3"
    pub match_mode: String,       // "HEX_PREFIX" | "HEX_EXACT" | "ASCII_CONTAINS" | "MODBUS_FUNC"
    pub match_pattern: String,    // 如 "01 03" 或 "PING"
    pub response_payload: String, // 如 "01 03 02 00 64" 或 "PONG\r\n"
    pub response_is_hex: bool,
    pub append_modbus_crc16: bool,
    pub delay_ms: u64,
    #[serde(default)]
    pub trigger_count: u64,
    #[serde(default)]
    pub last_triggered_at: Option<String>,
}

/// 周期发包状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialPeriodicTxStatus {
    pub running: bool,
    pub port_name: String,
    pub baud_rate: u32,
    pub interval_ms: u64,
    pub sent_count: u64,
    pub max_iterations: u64,
}

/// 协议校验码计算结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialChecksumOutcome {
    pub algorithm: String,
    pub checksum_hex: String,
    pub combined_frame_hex: String,
    pub byte_length: usize,
}

pub struct SerialPortMetricsInternal {
    total_rx_frames: u64,
    total_rx_bytes: u64,
    modbus_crc_errors: u64,
    last_arrival_ms: u64,
    last_gap_ms: f64,
    avg_gap_ms: f64,
    min_gap_ms: f64,
    max_gap_ms: f64,
    gap_histogram: [u64; 5],
}

pub struct SerialDevEngine {
    pub port_metrics: HashMap<String, SerialPortMetricsInternal>,
    pub modbus_registers: HashMap<String, ModbusRegisterCell>,
    pub last_modbus_req_addr: HashMap<(String, u8, u8), u16>,
    pub auto_rules: Vec<SerialAutoResponderRule>,
    pub last_persisted_ms: u64,
}

pub static GLOBAL_SERIAL_DEV_ENGINE: Lazy<RwLock<SerialDevEngine>> = Lazy::new(|| {
    RwLock::new(SerialDevEngine {
        port_metrics: HashMap::new(),
        modbus_registers: HashMap::new(),
        last_modbus_req_addr: HashMap::new(),
        auto_rules: Vec::new(),
        last_persisted_ms: 0,
    })
});

/// 记录发向串口的 Modbus 读寄存器请求起始地址，供紧接的从站响应精准还原寄存器偏移
pub fn record_serial_tx_context(port_name: &str, payload: &[u8]) {
    if let Some(mb) = crate::serial::dissect_modbus_rtu(payload) {
        if mb.is_crc_valid {
            if let Some(addr) = mb.register_address {
                let mut lock = GLOBAL_SERIAL_DEV_ENGINE
                    .write()
                    .unwrap_or_else(|p| p.into_inner());
                if lock.last_modbus_req_addr.len() > 256 {
                    lock.last_modbus_req_addr.clear();
                }
                lock.last_modbus_req_addr
                    .insert((port_name.to_string(), mb.slave_address, mb.function_code), addr);
            }
        }
    }
}

struct PeriodicTxControl {
    running: bool,
    stop_flag: Arc<AtomicBool>,
    port_name: String,
    baud_rate: u32,
    interval_ms: u64,
    sent_count: u64,
    max_iterations: u64,
}

static SERIAL_PERIODIC_TX: Lazy<Mutex<PeriodicTxControl>> = Lazy::new(|| {
    Mutex::new(PeriodicTxControl {
        running: false,
        stop_flag: Arc::new(AtomicBool::new(false)),
        port_name: String::new(),
        baud_rate: 115200,
        interval_ms: 1000,
        sent_count: 0,
        max_iterations: 0,
    })
});

/// 计算指定算法的工业校验码并生成最终待发帧
pub fn compute_serial_checksum_core(
    algorithm: &str,
    raw_input: &str,
    is_hex: bool,
) -> Result<SerialChecksumOutcome, String> {
    let mut payload = if is_hex {
        decode_hex_flexible(raw_input)?
    } else {
        let bytes = raw_input.as_bytes().to_vec();
        if bytes.is_empty() {
            return Err("输入数据不能为空".into());
        }
        bytes
    };

    let algo_upper = algorithm.trim().to_uppercase();
    let checksum_hex = match algo_upper.as_str() {
        "MODBUS_CRC16" => {
            let crc = crate::serial::calculate_modbus_crc16(&payload);
            let lo = (crc & 0xFF) as u8;
            let hi = (crc >> 8) as u8;
            payload.push(lo);
            payload.push(hi);
            format!("{:02X} {:02X} (0x{:04X} LE)", lo, hi, crc)
        }
        "CCITT_CRC16" => {
            let mut crc: u16 = 0xFFFF;
            for &b in &payload {
                crc ^= (b as u16) << 8;
                for _ in 0..8 {
                    if (crc & 0x8000) != 0 {
                        crc = (crc << 1) ^ 0x1021;
                    } else {
                        crc <<= 1;
                    }
                }
            }
            let hi = (crc >> 8) as u8;
            let lo = (crc & 0xFF) as u8;
            payload.push(hi);
            payload.push(lo);
            format!("{:02X} {:02X} (0x{:04X} BE)", hi, lo, crc)
        }
        "SUM8" => {
            let sum = payload.iter().fold(0u8, |acc, &x| acc.wrapping_add(x));
            payload.push(sum);
            format!("{:02X}", sum)
        }
        "XOR8" => {
            let xor = payload.iter().fold(0u8, |acc, &x| acc ^ x);
            payload.push(xor);
            format!("{:02X}", xor)
        }
        "MODBUS_LRC" => {
            let sum = payload.iter().fold(0u8, |acc, &x| acc.wrapping_add(x));
            let lrc = (!sum).wrapping_add(1);
            payload.push(lrc);
            format!("{:02X}", lrc)
        }
        other => return Err(format!("不支持的校验算法: {}", other)),
    };

    let combined_frame_hex = payload
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");

    Ok(SerialChecksumOutcome {
        algorithm: algo_upper,
        checksum_hex,
        combined_frame_hex,
        byte_length: payload.len(),
    })
}

/// 串口帧入账：更新帧间间隙直方图、Modbus CRC 错误及实时寄存器快照矩阵，并返回命中的自动应答任务
pub fn record_serial_frame_and_match_rules(
    port_name: &str,
    payload: &[u8],
    modbus_opt: Option<&crate::serial::ModbusRtuDissection>,
    modbus_crc_error: bool,
) -> Vec<(u64, Vec<u8>)> {
    let now_ms = current_epoch_ms();
    let ts_str = chrono::Local::now().format("%H:%M:%S.%3f").to_string();

    let mut lock = GLOBAL_SERIAL_DEV_ENGINE
        .write()
        .unwrap_or_else(|p| p.into_inner());

    let pm = lock
        .port_metrics
        .entry(port_name.to_string())
        .or_insert_with(|| SerialPortMetricsInternal {
            total_rx_frames: 0,
            total_rx_bytes: 0,
            modbus_crc_errors: 0,
            last_arrival_ms: 0,
            last_gap_ms: 0.0,
            avg_gap_ms: 0.0,
            min_gap_ms: f64::INFINITY,
            max_gap_ms: 0.0,
            gap_histogram: [0; 5],
        });

    pm.total_rx_frames += 1;
    pm.total_rx_bytes += payload.len() as u64;
    if modbus_crc_error {
        pm.modbus_crc_errors += 1;
    }

    let mut recorded_gap = 0.0f64;
    if pm.last_arrival_ms > 0 && now_ms >= pm.last_arrival_ms {
        let gap = (now_ms - pm.last_arrival_ms) as f64;
        if gap <= 60_000.0 {
            recorded_gap = gap;
            pm.last_gap_ms = gap;
            pm.avg_gap_ms = if pm.total_rx_frames <= 2 {
                gap
            } else {
                (pm.avg_gap_ms * 0.8) + (gap * 0.2)
            };
            if gap < pm.min_gap_ms {
                pm.min_gap_ms = gap;
            }
            if gap > pm.max_gap_ms {
                pm.max_gap_ms = gap;
            }
            let bucket = if gap < 5.0 {
                0
            } else if gap < 20.0 {
                1
            } else if gap < 100.0 {
                2
            } else if gap < 500.0 {
                3
            } else {
                4
            };
            pm.gap_histogram[bucket] += 1;
        }
    }
    pm.last_arrival_ms = now_ms;

    // 沉淀 Modbus RTU 寄存器值快照矩阵 (结合先序请求基址精准映射响应偏移)
    if let Some(mb) = modbus_opt {
        if mb.is_crc_valid {
            if mb.values.is_empty() {
                if let Some(req_addr) = mb.register_address {
                    lock.last_modbus_req_addr
                        .insert((port_name.to_string(), mb.slave_address, mb.function_code), req_addr);
                }
            } else {
                let req_key = (port_name.to_string(), mb.slave_address, mb.function_code);
                let base_addr = mb
                    .register_address
                    .or_else(|| lock.last_modbus_req_addr.get(&req_key).copied())
                    .unwrap_or(0);
                for (idx, &val) in mb.values.iter().enumerate() {
                if lock.modbus_registers.len() >= 512 {
                    break;
                }
                let reg_addr = base_addr.saturating_add(idx as u16);
                let cell_key = format!(
                    "{}:S{}:F{:02X}:{:04X}",
                    port_name, mb.slave_address, mb.function_code, reg_addr
                );
                let entry = lock
                    .modbus_registers
                    .entry(cell_key.clone())
                    .or_insert_with(|| ModbusRegisterCell {
                        key: cell_key,
                        port_name: port_name.to_string(),
                        slave_id: mb.slave_address,
                        function_code: mb.function_code,
                        register_addr: reg_addr,
                        raw_u16: val,
                        signed_i16: val as i16,
                        hex_value: format!("0x{:04X}", val),
                        prev_u16: None,
                        trend: "NEW".into(),
                        update_count: 0,
                        last_updated_at: ts_str.clone(),
                    });
                if entry.update_count > 0 {
                    entry.prev_u16 = Some(entry.raw_u16);
                    entry.trend = if val > entry.raw_u16 {
                        "UP".into()
                    } else if val < entry.raw_u16 {
                        "DOWN".into()
                    } else {
                        "SAME".into()
                    };
                }
                entry.raw_u16 = val;
                entry.signed_i16 = val as i16;
                entry.hex_value = format!("0x{:04X}", val);
                entry.update_count += 1;
                entry.last_updated_at = ts_str.clone();
                }
            }
        }
    }

    // 匹配启用中的串口自动应答规则 (上限 4 条并发回发防御回环雪崩)
    let mut actions = Vec::new();
    let ascii_text = String::from_utf8_lossy(payload);
    for rule in &mut lock.auto_rules {
        if !rule.enabled || actions.len() >= 4 {
            continue;
        }
        if rule.port_filter != "ALL" && !rule.port_filter.eq_ignore_ascii_case(port_name) {
            continue;
        }
        let matched = match rule.match_mode.as_str() {
            "HEX_PREFIX" => decode_hex_flexible(&rule.match_pattern)
                .map(|pat| payload.starts_with(&pat))
                .unwrap_or(false),
            "HEX_EXACT" => decode_hex_flexible(&rule.match_pattern)
                .map(|pat| payload == pat.as_slice())
                .unwrap_or(false),
            "ASCII_CONTAINS" => {
                !rule.match_pattern.is_empty() && ascii_text.contains(&rule.match_pattern)
            }
            "MODBUS_FUNC" => {
                if let Some(mb) = modbus_opt {
                    let want_func = rule.match_pattern.trim().trim_start_matches("0x");
                    u8::from_str_radix(want_func, 16)
                        .map(|f| mb.is_crc_valid && mb.function_code == f)
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            _ => false,
        };
        if matched {
            let mut reply_bytes = if rule.response_is_hex {
                decode_hex_flexible(&rule.response_payload).unwrap_or_default()
            } else {
                rule.response_payload.as_bytes().to_vec()
            };
            if !reply_bytes.is_empty() {
                if rule.append_modbus_crc16 {
                    let crc = crate::serial::calculate_modbus_crc16(&reply_bytes);
                    reply_bytes.push((crc & 0xFF) as u8);
                    reply_bytes.push((crc >> 8) as u8);
                }
                rule.trigger_count = rule.trigger_count.saturating_add(1);
                rule.last_triggered_at = Some(ts_str.clone());
                actions.push((rule.delay_ms.min(5000), reply_bytes));
            }
        }
    }

    let should_persist = modbus_crc_error || now_ms.saturating_sub(lock.last_persisted_ms) >= 1200;
    if should_persist {
        lock.last_persisted_ms = now_ms;
    }
    drop(lock);

    #[cfg(not(test))]
    if should_persist {
        if let Some(dir) = bus_data_dir() {
            append_bus_history_metric_in_dir(
                &dir,
                "SERIAL",
                port_name,
                payload.len(),
                recorded_gap,
                modbus_crc_error,
            );
        }
    }
    #[cfg(test)]
    let _ = recorded_gap;

    actions
}

#[cfg_attr(test, allow(dead_code))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BusHistoryMetricRecord {
    epoch_ms: u64,
    timestamp: String,
    bus: String,
    source: String,
    bytes: usize,
    gap_ms: f64,
    has_error: bool,
}

#[cfg_attr(test, allow(dead_code))]
fn append_bus_history_metric_in_dir(
    dir: &Path,
    bus: &str,
    source: &str,
    bytes: usize,
    gap_ms: f64,
    has_error: bool,
) {
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let path = dir.join("bus_history_metrics.jsonl");
    if let Ok(meta) = fs::metadata(&path) {
        if meta.len() >= 16 * 1024 * 1024 {
            let prev = dir.join("bus_history_metrics.jsonl.prev");
            let _ = fs::remove_file(&prev);
            let _ = fs::rename(&path, &prev);
        }
    }
    let rec = BusHistoryMetricRecord {
        epoch_ms: current_epoch_ms(),
        timestamp: current_ts_str(),
        bus: bus.to_string(),
        source: source.to_string(),
        bytes,
        gap_ms,
        has_error,
    };
    if let Ok(line) = serde_json::to_string(&rec) {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "{}", line);
        }
    }
}

// ============================================================================
// 5. 聚合快照与行业巡检分析报告导出 (Markdown / HTML)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusIntelligenceSnapshot {
    pub serial_gap_metrics: Vec<SerialPortGapMetrics>,
    pub modbus_registers: Vec<ModbusRegisterCell>,
    pub auto_rules: Vec<SerialAutoResponderRule>,
    pub periodic_tx: SerialPeriodicTxStatus,
    pub usb_total_urbs: u64,
    pub usb_total_bytes: u64,
    pub usb_control_urbs: u64,
    pub usb_bulk_urbs: u64,
    pub usb_interrupt_urbs: u64,
    pub usb_isochronous_urbs: u64,
    pub usb_error_urbs: u64,
    pub usb_pnp_attach_count: u64,
    pub usb_pnp_detach_count: u64,
    pub usb_endpoints: Vec<UsbEndpointStats>,
    pub usb_recent_urbs: Vec<UsbUrbEventItem>,
    pub waveform_baselines: Vec<WaveformBaselineSnapshot>,
}

pub fn get_bus_intelligence_snapshot_core() -> BusIntelligenceSnapshot {
    let serial_lock = GLOBAL_SERIAL_DEV_ENGINE
        .read()
        .unwrap_or_else(|p| p.into_inner());
    let mut serial_gap_metrics: Vec<SerialPortGapMetrics> = serial_lock
        .port_metrics
        .iter()
        .map(|(port, m)| SerialPortGapMetrics {
            port_name: port.clone(),
            total_rx_frames: m.total_rx_frames,
            total_rx_bytes: m.total_rx_bytes,
            modbus_crc_errors: m.modbus_crc_errors,
            last_gap_ms: (m.last_gap_ms * 10.0).round() / 10.0,
            avg_gap_ms: (m.avg_gap_ms * 10.0).round() / 10.0,
            min_gap_ms: if m.min_gap_ms.is_finite() {
                (m.min_gap_ms * 10.0).round() / 10.0
            } else {
                0.0
            },
            max_gap_ms: (m.max_gap_ms * 10.0).round() / 10.0,
            gap_histogram: m.gap_histogram,
        })
        .collect();
    serial_gap_metrics.sort_by(|a, b| a.port_name.cmp(&b.port_name));

    let mut modbus_registers: Vec<ModbusRegisterCell> =
        serial_lock.modbus_registers.values().cloned().collect();
    modbus_registers.sort_by(|a, b| a.key.cmp(&b.key));
    let auto_rules = serial_lock.auto_rules.clone();
    drop(serial_lock);

    let ptx = {
        let ctrl = crate::lock_guard::lock_mutex(&SERIAL_PERIODIC_TX, "bus::get_periodic_tx");
        SerialPeriodicTxStatus {
            running: ctrl.running,
            port_name: ctrl.port_name.clone(),
            baud_rate: ctrl.baud_rate,
            interval_ms: ctrl.interval_ms,
            sent_count: ctrl.sent_count,
            max_iterations: ctrl.max_iterations,
        }
    };

    let usb_lock = GLOBAL_USB_TELEMETRY
        .read()
        .unwrap_or_else(|p| p.into_inner());
    let mut usb_endpoints: Vec<UsbEndpointStats> =
        usb_lock.endpoint_map.values().cloned().collect();
    usb_endpoints.sort_by(|a, b| {
        (b.in_bytes + b.out_bytes).cmp(&(a.in_bytes + a.out_bytes))
    });
    let mut usb_recent_urbs: Vec<UsbUrbEventItem> = usb_lock.recent_urbs.iter().cloned().collect();
    usb_recent_urbs.reverse();

    let baselines = bus_data_dir()
        .map(|d| list_waveform_baselines_in_dir(&d))
        .unwrap_or_default();

    BusIntelligenceSnapshot {
        serial_gap_metrics,
        modbus_registers,
        auto_rules,
        periodic_tx: ptx,
        usb_total_urbs: usb_lock.total_urbs,
        usb_total_bytes: usb_lock.total_bytes,
        usb_control_urbs: usb_lock.control_urbs,
        usb_bulk_urbs: usb_lock.bulk_urbs,
        usb_interrupt_urbs: usb_lock.interrupt_urbs,
        usb_isochronous_urbs: usb_lock.isochronous_urbs,
        usb_error_urbs: usb_lock.error_urbs,
        usb_pnp_attach_count: usb_lock.pnp_attach_count,
        usb_pnp_detach_count: usb_lock.pnp_detach_count,
        usb_endpoints,
        usb_recent_urbs,
        waveform_baselines: baselines,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusInspectionReportBundle {
    pub generated_at: String,
    pub markdown: String,
    pub html: String,
}

/// 生成结合在线 COM/USB 设备、实时指标、Modbus 寄存器矩阵、USB 端点吞吐及可选波形对比的完整行业巡检报告
pub fn generate_bus_inspection_report_core(
    snap: &BusIntelligenceSnapshot,
    serial_ports: &[crate::serial::SerialPortDetail],
    usb_devices: &[crate::usb::UsbDeviceInfo],
    wave_compare: Option<&SmartWaveformComparisonResult>,
) -> BusInspectionReportBundle {
    let generated_at = current_ts_str();
    let mut md = String::with_capacity(4096);

    md.push_str("# Omni-Probe 物理总线 (COM & USB) 综合监测与分析报告\n\n");
    md.push_str(&format!("- **生成时间**: {}\n", generated_at));
    md.push_str(&format!(
        "- **在线物理外设**: 串口 {} 个 · USB 设备 {} 个\n",
        serial_ports.len(),
        usb_devices.len()
    ));
    md.push_str(&format!(
        "- **USB 总线累计捕获**: {} URB ({} 字节, 异常状态 {} 帧, Control {} / Bulk {} / Interrupt {} / Isochronous {})\n\n",
        snap.usb_total_urbs,
        snap.usb_total_bytes,
        snap.usb_error_urbs,
        snap.usb_control_urbs,
        snap.usb_bulk_urbs,
        snap.usb_interrupt_urbs,
        snap.usb_isochronous_urbs
    ));

    md.push_str("## 1. 物理/虚拟 COM 串口在线资产与时序健康度\n\n");
    if serial_ports.is_empty() {
        md.push_str("_当前主机未检测到在线 COM 串口。_\n\n");
    } else {
        md.push_str("| 端口 | 描述/芯片 | 硬件标识 | 监听状态 |\n|---|---|---|---|\n");
        for sp in serial_ports {
            md.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                sp.port_name,
                sp.product.as_deref().unwrap_or(&sp.description),
                sp.hardware_id,
                if sp.is_in_use_by_us { "正在监听" } else { "待命" }
            ));
        }
        md.push('\n');
    }

    if !snap.serial_gap_metrics.is_empty() {
        md.push_str("### 串口帧间间隔 (Δt) 与 CRC 误码统计\n\n");
        md.push_str("| 端口 | RX 帧数 | 总字节 | 均值 Δt (ms) | 最小/最大 Δt (ms) | Modbus CRC 错误 |\n|---|---|---|---|---|---|\n");
        for gm in &snap.serial_gap_metrics {
            md.push_str(&format!(
                "| {} | {} | {} | {:.1} | {:.1} / {:.1} | {} |\n",
                gm.port_name,
                gm.total_rx_frames,
                gm.total_rx_bytes,
                gm.avg_gap_ms,
                gm.min_gap_ms,
                gm.max_gap_ms,
                gm.modbus_crc_errors
            ));
        }
        md.push('\n');
    }

    if !snap.modbus_registers.is_empty() {
        md.push_str("## 2. Modbus RTU 实时寄存器画像快照\n\n");
        md.push_str("| 端口 | 从站 | 功能码 | 寄存器地址 | 无符号 / 有符号值 | HEX | 趋势 | 更新次数 |\n|---|---|---|---|---|---|---|---|\n");
        for reg in snap.modbus_registers.iter().take(64) {
            md.push_str(&format!(
                "| {} | {} | 0x{:02X} | 0x{:04X} | {} / {} | {} | {} | {} |\n",
                reg.port_name,
                reg.slave_id,
                reg.function_code,
                reg.register_addr,
                reg.raw_u16,
                reg.signed_i16,
                reg.hex_value,
                reg.trend,
                reg.update_count
            ));
        }
        md.push('\n');
    }

    md.push_str("## 3. USB 物理外设画像与端点吞吐统计\n\n");
    if usb_devices.is_empty() {
        md.push_str("_当前未检出在列 USB 外设。_\n\n");
    } else {
        md.push_str("| 设备名称 | VID:PID | 设备类别 | 驱动服务 |\n|---|---|---|---|\n");
        for d in usb_devices.iter().take(48) {
            md.push_str(&format!(
                "| {} | {}:{} | {} | {} |\n",
                d.device_name, d.vid, d.pid, d.class_desc, d.service
            ));
        }
        md.push('\n');
    }

    if !snap.usb_endpoints.is_empty() {
        md.push_str("### USB 活跃端点 (Endpoint) 吞吐画像\n\n");
        md.push_str("| 端点标识 | 传输类型 | IN (B) | OUT (B) | URB 数量 | 异常数 | 最近 USBD_STATUS |\n|---|---|---|---|---|---|---|\n");
        for ep in snap.usb_endpoints.iter().take(32) {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                ep.endpoint_key,
                ep.transfer_type,
                ep.in_bytes,
                ep.out_bytes,
                ep.urb_count,
                ep.error_urb_count,
                ep.last_usbd_status
            ));
        }
        md.push('\n');
    }

    md.push_str("## 4. 实时 vs 历史黄金波形智能对比评估\n\n");
    if let Some(wc) = wave_compare {
        md.push_str(&format!("- **比对通道**: `{}` vs 基线 `{}`\n", wc.channel_name, wc.baseline_name));
        md.push_str(&format!("- **综合判定**: **{}**\n", wc.health_verdict));
        md.push_str(&format!(
            "- **核心量化指标**: DTW 形态相似度 `{:.1}%` · Pearson 相关系数 `r = {:.3}` · 均方根误差 `RMSE = {:.3}` · FFT 频谱余弦相似度 `{:.3}` · 超差采样点数 `{}/{}`\n\n",
            wc.dtw_similarity_pct,
            wc.pearson_r,
            wc.rmse,
            wc.spectral_cosine_similarity,
            wc.outlier_point_count,
            wc.aligned_length
        ));
    } else {
        md.push_str(&format!(
            "_本次生成未传入即时波形比对结果，系统当前已存档 {} 条黄金波形基线。_\n\n",
            snap.waveform_baselines.len()
        ));
    }

    // 生成自包含极简工业深浅友好 HTML 报告
    let escaped_pre = html_escape(&md);
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Omni-Probe COM & USB 总线分析报告 ({})</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 32px auto; max-width: 1024px; padding: 0 20px; color: #0f172a; background: #f8fafc; line-height: 1.6; }}
.card {{ background: #ffffff; border: 1px solid #cbd5e1; border-radius: 12px; padding: 24px; box-shadow: 0 4px 14px rgba(15, 23, 42, 0.05); }}
h1 {{ margin-top: 0; font-size: 20px; border-bottom: 2px solid #0284c7; padding-bottom: 8px; }}
.meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 16px 0; }}
.kpi {{ background: #f1f5f9; border-radius: 8px; padding: 10px 14px; font-size: 13px; }}
.kpi strong {{ display: block; font-size: 18px; color: #0369a1; }}
pre {{ white-space: pre-wrap; word-break: break-word; font-family: ui-monospace, Consolas, monospace; font-size: 12.5px; background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; }}
</style>
</head>
<body>
<div class="card">
<h1>Omni-Probe 物理总线 (COM & USB) 综合巡检报告</h1>
<div class="meta">
  <div class="kpi">生成时间<strong>{}</strong></div>
  <div class="kpi">在线 COM / USB<strong>{} / {}</strong></div>
  <div class="kpi">捕获 USB URB<strong>{} ({} 错误)</strong></div>
  <div class="kpi">Modbus 活跃寄存器<strong>{} 项</strong></div>
</div>
<h3>完整 Markdown 审计正文</h3>
<pre>{}</pre>
</div>
</body>
</html>"#,
        html_escape(&generated_at),
        html_escape(&generated_at),
        serial_ports.len(),
        usb_devices.len(),
        snap.usb_total_urbs,
        snap.usb_error_urbs,
        snap.modbus_registers.len(),
        escaped_pre
    );

    BusInspectionReportBundle {
        generated_at,
        markdown: md,
        html,
    }
}

// ============================================================================
// 6. Tauri Commands 注册暴露
// ============================================================================

#[tauri::command]
pub fn save_waveform_baseline_cmd(
    name: String,
    bus_type: String,
    source_port: String,
    channel_name: String,
    sample_rate_hz: f64,
    samples: Vec<f64>,
) -> Result<WaveformBaselineSnapshot, String> {
    let dir = bus_data_dir().ok_or_else(|| "无法定位应用数据存储目录".to_string())?;
    save_waveform_baseline_in_dir(
        &dir,
        &name,
        &bus_type,
        &source_port,
        &channel_name,
        sample_rate_hz,
        &samples,
    )
}

#[tauri::command]
pub fn list_waveform_baselines_cmd() -> Vec<WaveformBaselineSnapshot> {
    bus_data_dir()
        .map(|d| list_waveform_baselines_in_dir(&d))
        .unwrap_or_default()
}

#[tauri::command]
pub fn delete_waveform_baseline_cmd(baseline_id: String) -> Result<bool, String> {
    let dir = bus_data_dir().ok_or_else(|| "无法定位应用数据存储目录".to_string())?;
    delete_waveform_baseline_in_dir(&dir, &baseline_id)
}

#[tauri::command]
pub fn smart_compare_waveforms_cmd(
    baseline_id: String,
    realtime_samples: Vec<f64>,
    channel_name: String,
) -> Result<SmartWaveformComparisonResult, String> {
    let dir = bus_data_dir().ok_or_else(|| "无法定位应用数据存储目录".to_string())?;
    smart_compare_waveforms_in_dir(&dir, &baseline_id, &realtime_samples, &channel_name)
}

#[tauri::command]
pub fn compute_waveform_fft_cmd(samples: Vec<f64>) -> Vec<FftBin> {
    compute_radix2_fft(&samples).0
}

#[tauri::command]
pub fn get_bus_intelligence_snapshot_cmd() -> BusIntelligenceSnapshot {
    get_bus_intelligence_snapshot_core()
}

#[tauri::command]
pub fn compute_serial_checksum_cmd(
    algorithm: String,
    payload: String,
    is_hex: bool,
) -> Result<SerialChecksumOutcome, String> {
    compute_serial_checksum_core(&algorithm, &payload, is_hex)
}

#[tauri::command]
pub fn upsert_serial_auto_rule_cmd(mut rule: SerialAutoResponderRule) -> Result<Vec<SerialAutoResponderRule>, String> {
    if rule.match_pattern.trim().is_empty() {
        return Err("匹配模式不能为空".into());
    }
    if rule.response_payload.trim().is_empty() {
        return Err("自动应答内容不能为空".into());
    }
    if rule.id.trim().is_empty() {
        rule.id = format!("rule_{}_{}", current_epoch_ms(), std::process::id());
    }
    let mut lock = GLOBAL_SERIAL_DEV_ENGINE
        .write()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(existing) = lock.auto_rules.iter_mut().find(|r| r.id == rule.id) {
        let triggers = existing.trigger_count;
        let last_ts = existing.last_triggered_at.clone();
        *existing = rule;
        existing.trigger_count = triggers;
        existing.last_triggered_at = last_ts;
    } else {
        if lock.auto_rules.len() >= 32 {
            return Err("自动应答规则上限为 32 条".into());
        }
        lock.auto_rules.push(rule);
    }
    Ok(lock.auto_rules.clone())
}

#[tauri::command]
pub fn delete_serial_auto_rule_cmd(rule_id: String) -> Vec<SerialAutoResponderRule> {
    let mut lock = GLOBAL_SERIAL_DEV_ENGINE
        .write()
        .unwrap_or_else(|p| p.into_inner());
    lock.auto_rules.retain(|r| r.id != rule_id);
    lock.auto_rules.clone()
}

#[tauri::command]
pub fn start_serial_periodic_tx_cmd(
    app: tauri::AppHandle,
    port_name: String,
    baud_rate: u32,
    payload_str: String,
    is_hex: bool,
    append_modbus_crc16: bool,
    interval_ms: u64,
    max_iterations: u64,
) -> Result<SerialPeriodicTxStatus, String> {
    let mut bytes = if is_hex {
        decode_hex_flexible(&payload_str)?
    } else {
        payload_str.as_bytes().to_vec()
    };
    if bytes.is_empty() {
        return Err("周期发送载荷不能为空".into());
    }
    if append_modbus_crc16 {
        let crc = crate::serial::calculate_modbus_crc16(&bytes);
        bytes.push((crc & 0xFF) as u8);
        bytes.push((crc >> 8) as u8);
    }
    let clean_port = port_name.trim().to_string();
    if clean_port.is_empty() {
        return Err("必须指定物理 COM 端口".into());
    }
    let safe_interval = interval_ms.clamp(25, 60_000);

    // 停止旧有循环任务
    let new_stop = Arc::new(AtomicBool::new(false));
    {
        let mut ctrl = crate::lock_guard::lock_mutex(&SERIAL_PERIODIC_TX, "bus::start_periodic_tx");
        ctrl.stop_flag.store(true, Ordering::Release);
        ctrl.running = true;
        ctrl.stop_flag = new_stop.clone();
        ctrl.port_name = clean_port.clone();
        ctrl.baud_rate = baud_rate;
        ctrl.interval_ms = safe_interval;
        ctrl.sent_count = 0;
        ctrl.max_iterations = max_iterations;
    }

    let port_for_thread = clean_port.clone();
    std::thread::spawn(move || {
        let mut iter_cnt = 0u64;
        while !new_stop.load(Ordering::Acquire) {
            if max_iterations > 0 && iter_cnt >= max_iterations {
                break;
            }
            if crate::serial::send_serial_data(app.clone(), &port_for_thread, baud_rate, &bytes).is_err() {
                break;
            }
            iter_cnt += 1;
            {
                let mut ctrl = crate::lock_guard::lock_mutex(&SERIAL_PERIODIC_TX, "bus::tick_periodic_tx");
                if Arc::ptr_eq(&ctrl.stop_flag, &new_stop) {
                    ctrl.sent_count = iter_cnt;
                }
            }
            // 分小步睡眠以便即时响应停止按钮
            let mut slept = 0u64;
            while slept < safe_interval && !new_stop.load(Ordering::Acquire) {
                let step = (safe_interval - slept).min(50);
                std::thread::sleep(std::time::Duration::from_millis(step));
                slept += step;
            }
        }
        let mut ctrl = crate::lock_guard::lock_mutex(&SERIAL_PERIODIC_TX, "bus::finish_periodic_tx");
        if Arc::ptr_eq(&ctrl.stop_flag, &new_stop) {
            ctrl.running = false;
        }
    });

    Ok(SerialPeriodicTxStatus {
        running: true,
        port_name: clean_port,
        baud_rate,
        interval_ms: safe_interval,
        sent_count: 0,
        max_iterations,
    })
}

#[tauri::command]
pub fn stop_serial_periodic_tx_cmd() -> SerialPeriodicTxStatus {
    let mut ctrl = crate::lock_guard::lock_mutex(&SERIAL_PERIODIC_TX, "bus::stop_periodic_tx");
    ctrl.stop_flag.store(true, Ordering::Release);
    ctrl.running = false;
    SerialPeriodicTxStatus {
        running: false,
        port_name: ctrl.port_name.clone(),
        baud_rate: ctrl.baud_rate,
        interval_ms: ctrl.interval_ms,
        sent_count: ctrl.sent_count,
        max_iterations: ctrl.max_iterations,
    }
}

#[tauri::command]
pub fn generate_bus_inspection_report_cmd(
    wave_compare: Option<SmartWaveformComparisonResult>,
) -> BusInspectionReportBundle {
    let snap = get_bus_intelligence_snapshot_core();
    let serial_ports = crate::serial::list_available_serial_ports_detail();
    let usb_devices = crate::usb::scan_connected_usb_devices();
    generate_bus_inspection_report_core(&snap, &serial_ports, &usb_devices, wave_compare.as_ref())
}

#[tauri::command]
pub async fn export_bus_inspection_report_cmd(
    format: String,
    content: String,
) -> Result<crate::desktop_native::NativeSaveOutcome, String> {
    tokio::task::spawn_blocking(move || {
        let is_html = format.trim().eq_ignore_ascii_case("html");
        let ext = if is_html { "html" } else { "md" };
        let default_name = format!(
            "omni_probe_bus_report_{}.{}",
            chrono::Local::now().format("%Y%m%d_%H%M%S"),
            ext
        );
        let title = if is_html {
            "导出 COM & USB 总线巡检分析报告 (HTML)"
        } else {
            "导出 COM & USB 总线巡检分析报告 (Markdown)"
        };
        let filter_name = if is_html {
            "HTML 报告 (*.html)"
        } else {
            "Markdown 报告 (*.md)"
        };
        let filter_pat = if is_html { "*.html" } else { "*.md" };
        crate::desktop_native::save_text_with_native_dialog(
            &default_name,
            title,
            filter_name,
            filter_pat,
            &content,
        )
    })
    .await
    .map_err(|e| format!("报告导出线程异常: {}", e))?
}

// ============================================================================
// 6. 单片机嵌入式专业辅助开发引擎 (VOFA+ JustFloat / Struct 多通道解构 / 阶跃响应 / MCU 算表 / 固件传片 / ANSI 终端)
// ============================================================================

/// 二进制自定义结构帧单字段描述 (供多通道混合协议实时还原波形曲线)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryStructField {
    pub name: String,
    pub field_type: String, // "U8" | "I8" | "U16" | "I16" | "U32" | "I32" | "F32" | "F64"
    pub little_endian: bool,
    pub offset: usize,
    pub scale: f64,
    pub bias: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedStructChannel {
    pub name: String,
    pub samples: Vec<f64>,
    pub latest: f64,
    pub min: f64,
    pub max: f64,
    pub avg: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructBatchDecodeResult {
    pub decoded_frame_count: usize,
    pub skipped_frame_count: usize,
    pub mode_used: String,
    pub channels: Vec<DecodedStructChannel>,
}

fn read_typed_field(bytes: &[u8], f: &BinaryStructField) -> Option<f64> {
    let le = f.little_endian;
    let raw = match f.field_type.trim().to_uppercase().as_str() {
        "U8" => *bytes.get(f.offset)? as f64,
        "I8" => (*bytes.get(f.offset)? as i8) as f64,
        "U16" => {
            let s = bytes.get(f.offset..f.offset + 2)?;
            (if le { u16::from_le_bytes([s[0], s[1]]) } else { u16::from_be_bytes([s[0], s[1]]) }) as f64
        }
        "I16" => {
            let s = bytes.get(f.offset..f.offset + 2)?;
            (if le { i16::from_le_bytes([s[0], s[1]]) } else { i16::from_be_bytes([s[0], s[1]]) }) as f64
        }
        "U32" => {
            let s = bytes.get(f.offset..f.offset + 4)?;
            (if le { u32::from_le_bytes([s[0], s[1], s[2], s[3]]) } else { u32::from_be_bytes([s[0], s[1], s[2], s[3]]) }) as f64
        }
        "I32" => {
            let s = bytes.get(f.offset..f.offset + 4)?;
            (if le { i32::from_le_bytes([s[0], s[1], s[2], s[3]]) } else { i32::from_be_bytes([s[0], s[1], s[2], s[3]]) }) as f64
        }
        "F32" => {
            let s = bytes.get(f.offset..f.offset + 4)?;
            let v = if le {
                f32::from_le_bytes([s[0], s[1], s[2], s[3]])
            } else {
                f32::from_be_bytes([s[0], s[1], s[2], s[3]])
            } as f64;
            if !v.is_finite() {
                return None;
            }
            v
        }
        "F64" => {
            let s = bytes.get(f.offset..f.offset + 8)?;
            let v = if le {
                f64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
            } else {
                f64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
            };
            if !v.is_finite() {
                return None;
            }
            v
        }
        _ => return None,
    };
    let scaled = raw * (if f.scale.is_finite() && f.scale != 0.0 { f.scale } else { 1.0 })
        + (if f.bias.is_finite() { f.bias } else { 0.0 });
    if scaled.is_finite() {
        Some((scaled * 10000.0).round() / 10000.0)
    } else {
        None
    }
}

/// 批量解码二进制结构体流或 VOFA+ JustFloat 多通道数据帧 (O(M * K), 空间 O(M * K))
pub fn parse_binary_struct_batch_core(
    payloads_hex: &[String],
    header_hex: &str,
    fields: &[BinaryStructField],
    parse_justfloat: bool,
) -> Result<StructBatchDecodeResult, String> {
    let mut decoded_count = 0usize;
    let mut skipped_count = 0usize;

    if parse_justfloat {
        // VOFA+ JustFloat 协议：小端 IEEE-754 float32 数组 + 4B 尾标 [0x00, 0x00, 0x80, 0x7F]
        let mut channel_vecs: Vec<Vec<f64>> = Vec::new();
        let mut stream_buf = Vec::new();
        for hex_s in payloads_hex {
            if let Ok(b) = decode_hex_flexible(hex_s) {
                stream_buf.extend_from_slice(&b);
            } else {
                skipped_count += 1;
            }
        }
        let tail = [0x00u8, 0x00u8, 0x80u8, 0x7Fu8];
        let mut cursor = 0usize;
        while cursor + 8 <= stream_buf.len() {
            if let Some(pos) = stream_buf[cursor..].windows(4).position(|w| w == tail) {
                let frame_slice = &stream_buf[cursor..cursor + pos];
                cursor += pos + 4;
                if frame_slice.is_empty() || frame_slice.len() % 4 != 0 {
                    skipped_count += 1;
                    continue;
                }
                let ch_cnt = (frame_slice.len() / 4).min(8);
                while channel_vecs.len() < ch_cnt {
                    channel_vecs.push(Vec::new());
                }
                let mut valid_frame = true;
                let mut vals = Vec::with_capacity(ch_cnt);
                for ci in 0..ch_cnt {
                    let s = &frame_slice[ci * 4..ci * 4 + 4];
                    let v = f32::from_le_bytes([s[0], s[1], s[2], s[3]]) as f64;
                    if !v.is_finite() {
                        valid_frame = false;
                        break;
                    }
                    vals.push((v * 10000.0).round() / 10000.0);
                }
                if valid_frame {
                    decoded_count += 1;
                    for (ci, val) in vals.into_iter().enumerate() {
                        channel_vecs[ci].push(val);
                    }
                } else {
                    skipped_count += 1;
                }
            } else {
                break;
            }
        }
        let channels = channel_vecs
            .into_iter()
            .enumerate()
            .filter(|(_, v)| !v.is_empty())
            .map(|(i, samples)| {
                let (mean, _, min, max) = calc_stats(&samples);
                DecodedStructChannel {
                    name: format!("JustFloat_CH{}", i),
                    latest: *samples.last().unwrap_or(&0.0),
                    samples,
                    min,
                    max,
                    avg: mean,
                }
            })
            .collect();
        return Ok(StructBatchDecodeResult {
            decoded_frame_count: decoded_count,
            skipped_frame_count: skipped_count,
            mode_used: "VOFA_JUSTFLOAT".into(),
            channels,
        });
    }

    if fields.is_empty() {
        return Err("自定义结构体解析至少需要 1 个字段定义".into());
    }
    let header_bytes = if header_hex.trim().is_empty() {
        Vec::new()
    } else {
        decode_hex_flexible(header_hex)?
    };

    let active_fields = &fields[..fields.len().min(8)];
    let mut col_map: Vec<Vec<f64>> = vec![Vec::new(); active_fields.len()];
    for hex_s in payloads_hex {
        let Ok(bytes) = decode_hex_flexible(hex_s) else {
            skipped_count += 1;
            continue;
        };
        if !header_bytes.is_empty() && !bytes.starts_with(&header_bytes) {
            skipped_count += 1;
            continue;
        }
        let mut row_vals = Vec::with_capacity(active_fields.len());
        let mut all_ok = true;
        for f in active_fields {
            if let Some(v) = read_typed_field(&bytes, f) {
                row_vals.push(v);
            } else {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            decoded_count += 1;
            for (ci, v) in row_vals.into_iter().enumerate() {
                col_map[ci].push(v);
            }
        } else {
            skipped_count += 1;
        }
    }

    let channels = active_fields
        .iter()
        .zip(col_map)
        .filter(|(_, s)| !s.is_empty())
        .map(|(f, samples)| {
            let (mean, _, min, max) = calc_stats(&samples);
            DecodedStructChannel {
                name: if f.name.trim().is_empty() {
                    format!("F@{}", f.offset)
                } else {
                    f.name.trim().to_string()
                },
                latest: *samples.last().unwrap_or(&0.0),
                samples,
                min,
                max,
                avg: mean,
            }
        })
        .collect();

    Ok(StructBatchDecodeResult {
        decoded_frame_count: decoded_count,
        skipped_frame_count: skipped_count,
        mode_used: "CUSTOM_STRUCT".into(),
        channels,
    })
}

/// 闭环控制系统瞬态阶跃响应评价结果 (PID 调参核心指标)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResponseMetrics {
    pub sample_count: usize,
    pub initial_value: f64,
    pub target_setpoint: f64,
    pub final_steady_value: f64,
    pub steady_state_error: f64,
    pub peak_value: f64,
    pub overshoot_pct: f64,
    pub rise_time_ms: Option<f64>,
    pub settling_time_ms: Option<f64>,
    pub tolerance_pct: f64,
    pub converged: bool,
    pub summary: String,
}

/// 测算控制回路阶跃响应性能 (Rise Time 10%->90%, Overshoot %, Settling Time ±tol%)
/// 时间复杂度 O(N), 空间复杂度 O(N)
pub fn compute_step_response_core(
    raw_samples: &[f64],
    target_setpoint: f64,
    dt_ms: f64,
    tolerance_pct: f64,
) -> Result<StepResponseMetrics, String> {
    let samples = sanitize_samples(raw_samples);
    if samples.len() < 4 {
        return Err("阶跃响应分析至少需要 4 个有效采样点".into());
    }
    if !target_setpoint.is_finite() {
        return Err("目标设定值必须为有限实数".into());
    }
    let dt = dt_ms.clamp(0.01, 100_000.0);
    let tol_ratio = (tolerance_pct.clamp(0.1, 25.0)) / 100.0;
    let init_val = samples[0];
    let step_span = target_setpoint - init_val;

    let tail_len = (samples.len() / 5).max(1);
    let final_steady = samples[samples.len() - tail_len..].iter().sum::<f64>() / (tail_len as f64);
    let steady_err = target_setpoint - final_steady;

    if step_span.abs() < 1e-9 {
        let (_, stddev, _, _) = calc_stats(&samples);
        return Ok(StepResponseMetrics {
            sample_count: samples.len(),
            initial_value: init_val,
            target_setpoint,
            final_steady_value: (final_steady * 1000.0).round() / 1000.0,
            steady_state_error: (steady_err * 1000.0).round() / 1000.0,
            peak_value: final_steady,
            overshoot_pct: 0.0,
            rise_time_ms: Some(0.0),
            settling_time_ms: Some(0.0),
            tolerance_pct,
            converged: stddev < 1.0,
            summary: format!("稳态恒定序列 (σ={:.3}, 稳态误差 {:.3})", stddev, steady_err),
        });
    }

    let rising = step_span > 0.0;
    let peak_val = if rising {
        samples.iter().copied().fold(f64::NEG_INFINITY, f64::max)
    } else {
        samples.iter().copied().fold(f64::INFINITY, f64::min)
    };
    let overshoot_abs = if rising {
        (peak_val - target_setpoint).max(0.0)
    } else {
        (target_setpoint - peak_val).max(0.0)
    };
    let overshoot_pct = ((overshoot_abs / step_span.abs()) * 100.0 * 100.0).round() / 100.0;

    let lvl10 = init_val + 0.1 * step_span;
    let lvl90 = init_val + 0.9 * step_span;
    let idx10 = samples.iter().position(|&v| if rising { v >= lvl10 } else { v <= lvl10 });
    let idx90 = samples.iter().position(|&v| if rising { v >= lvl90 } else { v <= lvl90 });
    let rise_time_ms = match (idx10, idx90) {
        (Some(i1), Some(i2)) if i2 >= i1 => Some((((i2 - i1) as f64) * dt * 100.0).round() / 100.0),
        _ => None,
    };

    let band = (step_span.abs() * tol_ratio).max(1e-6);
    let last_outside = samples
        .iter()
        .rposition(|&v| (v - target_setpoint).abs() > band);
    let (settling_time_ms, converged) = match last_outside {
        None => (Some(0.0), true),
        Some(idx) if idx + 1 < samples.len() => {
            (Some((((idx + 1) as f64) * dt * 100.0).round() / 100.0), true)
        }
        Some(_) => (None, false),
    };

    let summary = format!(
        "超调量 {:.2}% | 上升时间 {} | ±{:.1}%调节时间 {} | 稳态误差 {:.3}",
        overshoot_pct,
        rise_time_ms.map(|v| format!("{:.2}ms", v)).unwrap_or_else(|| "未达到90%".into()),
        tolerance_pct,
        settling_time_ms.map(|v| format!("{:.2}ms", v)).unwrap_or_else(|| "未收敛入带".into()),
        steady_err
    );

    Ok(StepResponseMetrics {
        sample_count: samples.len(),
        initial_value: (init_val * 1000.0).round() / 1000.0,
        target_setpoint,
        final_steady_value: (final_steady * 1000.0).round() / 1000.0,
        steady_state_error: (steady_err * 1000.0).round() / 1000.0,
        peak_value: (peak_val * 1000.0).round() / 1000.0,
        overshoot_pct,
        rise_time_ms,
        settling_time_ms,
        tolerance_pct,
        converged,
        summary,
    })
}

/// MCU Timer / PWM 分频最优整数解条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McuTimerSolution {
    pub psc: u32,
    pub arr: u32,
    pub actual_freq_hz: f64,
    pub error_ppm: f64,
    pub duty_resolution_bits: f64,
}

/// 基于因子分解在 O(sqrt(N)) 内高效搜索最精确 MCU Timer (PSC+1)*(ARR+1) 配置
pub fn solve_mcu_timer_psc_arr_core(
    timer_clk_hz: u64,
    target_freq_hz: f64,
    is_32bit: bool,
) -> Result<Vec<McuTimerSolution>, String> {
    if timer_clk_hz == 0 || !target_freq_hz.is_finite() || target_freq_hz <= 0.0 {
        return Err("定时器主频与目标频率必须大于 0".into());
    }
    let total_ticks_f = (timer_clk_hz as f64) / target_freq_hz;
    if total_ticks_f < 2.0 {
        return Err("目标频率过高，低于最小 2-tick 分频边界".into());
    }
    let max_arr: u64 = if is_32bit { u32::MAX as u64 } else { 65535 };
    let max_psc: u64 = 65535;
    let center = total_ticks_f.round() as u64;

    let mut candidates: Vec<McuTimerSolution> = Vec::new();
    let span: u64 = 8;
    let low = center.saturating_sub(span).max(2);
    let high = center.saturating_add(span);

    for prod in low..=high {
        let mut d = 1u64;
        while d * d <= prod {
            if prod % d == 0 {
                for &(f1, f2) in &[(d, prod / d), (prod / d, d)] {
                    let psc_cand = f1.saturating_sub(1);
                    let arr_cand = f2.saturating_sub(1);
                    if psc_cand <= max_psc && arr_cand >= 1 && arr_cand <= max_arr {
                        let actual = (timer_clk_hz as f64) / ((psc_cand + 1) as f64 * (arr_cand + 1) as f64);
                        let err_ppm = ((actual - target_freq_hz).abs() / target_freq_hz) * 1_000_000.0;
                        let duty_bits = ((arr_cand + 1) as f64).log2();
                        candidates.push(McuTimerSolution {
                            psc: psc_cand as u32,
                            arr: arr_cand as u32,
                            actual_freq_hz: (actual * 1000.0).round() / 1000.0,
                            error_ppm: (err_ppm * 100.0).round() / 100.0,
                            duty_resolution_bits: (duty_bits * 10.0).round() / 10.0,
                        });
                    }
                }
            }
            d += 1;
        }
    }

    if candidates.is_empty() {
        // 退化直接按最小 PSC 搜索最优整数 ARR
        let min_psc = ((total_ticks_f / ((max_arr + 1) as f64)).ceil() as u64).saturating_sub(1).min(max_psc);
        let arr_calc = ((total_ticks_f / ((min_psc + 1) as f64)).round() as u64).saturating_sub(1).clamp(1, max_arr);
        let actual = (timer_clk_hz as f64) / ((min_psc + 1) as f64 * (arr_calc + 1) as f64);
        let err_ppm = ((actual - target_freq_hz).abs() / target_freq_hz) * 1_000_000.0;
        candidates.push(McuTimerSolution {
            psc: min_psc as u32,
            arr: arr_calc as u32,
            actual_freq_hz: (actual * 1000.0).round() / 1000.0,
            error_ppm: (err_ppm * 100.0).round() / 100.0,
            duty_resolution_bits: (((arr_calc + 1) as f64).log2() * 10.0).round() / 10.0,
        });
    }

    candidates.sort_by(|a, b| {
        a.error_ppm
            .partial_cmp(&b.error_ppm)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.arr.cmp(&a.arr))
    });
    candidates.dedup_by(|a, b| a.psc == b.psc && a.arr == b.arr);
    candidates.truncate(5);
    Ok(candidates)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UartBaudCalcResult {
    pub apb_clk_hz: u64,
    pub target_baud: u32,
    pub oversampling: u8,
    pub brr_div_integer: u32,
    pub actual_baud: f64,
    pub error_pct: f64,
    pub within_spec: bool,
    pub diagnostic: String,
}

pub fn calc_uart_baud_error_core(
    apb_clk_hz: u64,
    target_baud: u32,
    oversampling: u8,
) -> Result<UartBaudCalcResult, String> {
    if apb_clk_hz == 0 || target_baud == 0 {
        return Err("外设总线时钟与目标波特率必须大于 0".into());
    }
    let os = if oversampling == 8 { 8u8 } else { 16u8 };
    let div_exact = (apb_clk_hz as f64) / ((os as f64) * (target_baud as f64));
    let brr = (div_exact.round() as u32).max(1);
    let actual = (apb_clk_hz as f64) / ((os as f64) * (brr as f64));
    let err_pct = ((actual - (target_baud as f64)) / (target_baud as f64)) * 100.0;
    let within_spec = err_pct.abs() <= 2.0;

    let diagnostic = format!(
        "DIV={} → 实测 {:.1} bps (误差 {:+.3}%, {} ±2.0% UART 通信容限)",
        brr,
        actual,
        err_pct,
        if within_spec { "合规稳定" } else { "超标易出现帧错位!" }
    );

    Ok(UartBaudCalcResult {
        apb_clk_hz,
        target_baud,
        oversampling: os,
        brr_div_integer: brr,
        actual_baud: (actual * 10.0).round() / 10.0,
        error_pct: (err_pct * 1000.0).round() / 1000.0,
        within_spec,
        diagnostic,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusWordEndianView {
    pub order_name: String,
    pub raw_hex: String,
    pub float32: String,
    pub int32: i32,
    pub uint32: u32,
}

pub fn decode_modbus_32bit_word_core(raw_hex: &str) -> Result<Vec<ModbusWordEndianView>, String> {
    let b = decode_hex_flexible(raw_hex)?;
    if b.len() < 4 {
        return Err("四字节寄存器端序解码至少需要 4 字节 (8 个 HEX 字符)".into());
    }
    let orders: [(&str, [u8; 4]); 4] = [
        ("ABCD (大端 Big-Endian)", [b[0], b[1], b[2], b[3]]),
        ("DCBA (小端 Little-Endian)", [b[3], b[2], b[1], b[0]]),
        ("BADC (高字节序交换)", [b[1], b[0], b[3], b[2]]),
        ("CDAB (字逆序 Word-Swap)", [b[2], b[3], b[0], b[1]]),
    ];
    Ok(orders
        .into_iter()
        .map(|(name, arr)| {
            let f = f32::from_be_bytes(arr);
            let i = i32::from_be_bytes(arr);
            let u = u32::from_be_bytes(arr);
            ModbusWordEndianView {
                order_name: name.into(),
                raw_hex: format!("{:02X} {:02X} {:02X} {:02X}", arr[0], arr[1], arr[2], arr[3]),
                float32: if f.is_finite() { format!("{:.6}", f) } else { "NaN/Inf".into() },
                int32: i,
                uint32: u,
            }
        })
        .collect())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McuConsoleLogAnalysis {
    pub clean_lines: Vec<String>,
    pub clean_text: String,
    pub error_count: usize,
    pub warning_count: usize,
    pub panic_or_reboot_count: usize,
    pub critical_alerts: Vec<String>,
}

fn strip_ansi_sequences(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else if c != '\r' {
            out.push(c);
        }
    }
    out
}

/// 剥离嵌入式 RTOS ANSI 色彩控制码，按行流式重组并扫描 HardFault/Watchdog/Guru Meditation 异常
pub fn analyze_mcu_console_lines_core(raw_chunks: &[String]) -> McuConsoleLogAnalysis {
    let mut combined = String::new();
    for ch in raw_chunks {
        combined.push_str(&strip_ansi_sequences(ch));
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
    }
    let clean_lines: Vec<String> = combined
        .lines()
        .map(|l| l.trim_end().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let mut error_count = 0usize;
    let mut warning_count = 0usize;
    let mut panic_or_reboot_count = 0usize;
    let mut critical_alerts = Vec::new();

    for (idx, line) in clean_lines.iter().enumerate() {
        let up = line.to_ascii_uppercase();
        let is_panic = up.contains("HARDFAULT")
            || up.contains("GURU MEDITATION")
            || up.contains("BACKTRACE:")
            || up.contains("WATCHDOG")
            || up.contains("WDT")
            || up.contains("RST:0X")
            || up.contains("REBOOTING")
            || up.contains("PANIC");
        if is_panic {
            panic_or_reboot_count += 1;
            if critical_alerts.len() < 32 {
                critical_alerts.push(format!("[L{}] {}", idx + 1, line));
            }
        } else if up.contains("ERROR") || up.contains("[E]") || up.contains(" E (") || up.contains("FAIL") {
            error_count += 1;
            if critical_alerts.len() < 32 {
                critical_alerts.push(format!("[L{}] {}", idx + 1, line));
            }
        } else if up.contains("WARN") || up.contains("[W]") || up.contains(" W (") {
            warning_count += 1;
        }
    }

    let clean_text = clean_lines.join("\n");
    McuConsoleLogAnalysis {
        clean_lines,
        clean_text,
        error_count,
        warning_count,
        panic_or_reboot_count,
        critical_alerts,
    }
}

fn crc32_ieee_calc(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if (crc & 1) != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialBinFileTransferResult {
    pub cancelled: bool,
    pub file_path: Option<String>,
    pub bytes_sent: usize,
    pub chunks_sent: usize,
    pub crc32_hex: String,
    pub elapsed_ms: u64,
    pub message: String,
}

#[tauri::command]
pub fn parse_binary_struct_batch_cmd(
    payloads_hex: Vec<String>,
    header_hex: String,
    fields: Vec<BinaryStructField>,
    parse_justfloat: bool,
) -> Result<StructBatchDecodeResult, String> {
    parse_binary_struct_batch_core(&payloads_hex, &header_hex, &fields, parse_justfloat)
}

#[tauri::command]
pub fn compute_step_response_metrics_cmd(
    samples: Vec<f64>,
    target_setpoint: f64,
    dt_ms: f64,
    tolerance_pct: f64,
) -> Result<StepResponseMetrics, String> {
    compute_step_response_core(&samples, target_setpoint, dt_ms, tolerance_pct)
}

#[tauri::command]
pub fn solve_mcu_timer_psc_arr_cmd(
    timer_clk_hz: u64,
    target_freq_hz: f64,
    is_32bit: bool,
) -> Result<Vec<McuTimerSolution>, String> {
    solve_mcu_timer_psc_arr_core(timer_clk_hz, target_freq_hz, is_32bit)
}

#[tauri::command]
pub fn calc_uart_baud_error_cmd(
    apb_clk_hz: u64,
    target_baud: u32,
    oversampling: u8,
) -> Result<UartBaudCalcResult, String> {
    calc_uart_baud_error_core(apb_clk_hz, target_baud, oversampling)
}

#[tauri::command]
pub fn decode_modbus_32bit_word_cmd(raw_hex: String) -> Result<Vec<ModbusWordEndianView>, String> {
    decode_modbus_32bit_word_core(&raw_hex)
}

#[tauri::command]
pub fn analyze_mcu_console_lines_cmd(raw_chunks: Vec<String>) -> McuConsoleLogAnalysis {
    analyze_mcu_console_lines_core(&raw_chunks)
}

#[tauri::command]
pub async fn pick_and_send_serial_bin_file_cmd(
    app: tauri::AppHandle,
    port_name: String,
    baud_rate: u32,
    chunk_size: usize,
    inter_chunk_ms: u64,
) -> Result<SerialBinFileTransferResult, String> {
    let clean_port = port_name.trim().to_string();
    if clean_port.is_empty() {
        return Err("必须指定物理 COM 端口才能下发二进制固件分片".into());
    }
    tokio::task::spawn_blocking(move || {
        let picked = crate::desktop_native::pick_native_file_dialog(
            "选择下发给单片机的二进制固件或测试文件 (.bin)",
            "二进制固件与字节流 (*.bin;*.fw;*.hex;*.dat)",
            "*.bin;*.fw;*.hex;*.dat",
        )?;
        let Some(path) = picked else {
            return Ok(SerialBinFileTransferResult {
                cancelled: true,
                file_path: None,
                bytes_sent: 0,
                chunks_sent: 0,
                crc32_hex: String::new(),
                elapsed_ms: 0,
                message: "已取消固件/二进制文件下行发送".into(),
            });
        };
        let meta = fs::metadata(&path).map_err(|e| format!("读取文件属性失败: {}", e))?;
        if meta.len() == 0 {
            return Err("选定文件为空 (0 字节)".into());
        }
        if meta.len() > 16 * 1024 * 1024 {
            return Err("单次串口分片文件大小不可超过 16MB".into());
        }
        let bytes = fs::read(&path).map_err(|e| format!("读取二进制文件失败: {}", e))?;
        let crc_val = crc32_ieee_calc(&bytes);
        let c_size = chunk_size.clamp(16, 4096);
        let delay = inter_chunk_ms.min(2000);
        let t0 = std::time::Instant::now();
        let mut chunks_sent = 0usize;

        for chunk in bytes.chunks(c_size) {
            crate::serial::send_serial_data(app.clone(), &clean_port, baud_rate, chunk)?;
            chunks_sent += 1;
            if delay > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }
        let elapsed = t0.elapsed().as_millis() as u64;
        let crc_hex = format!("0x{:08X}", crc_val);
        Ok(SerialBinFileTransferResult {
            cancelled: false,
            file_path: Some(path),
            bytes_sent: bytes.len(),
            chunks_sent,
            crc32_hex: crc_hex.clone(),
            elapsed_ms: elapsed,
            message: format!(
                "已通过 {} (@{} bps) 完成 {} 字节 ({} 片) 二进制下发, CRC32={}, 耗时 {} ms",
                clean_port, baud_rate, bytes.len(), chunks_sent, crc_hex, elapsed
            ),
        })
    })
    .await
    .map_err(|e| format!("固件分片传输线程异常: {}", e))?
}

#[tauri::command]
pub async fn export_serial_stream_log_cmd(
    format: String,
    content: String,
) -> Result<crate::desktop_native::NativeSaveOutcome, String> {
    tokio::task::spawn_blocking(move || {
        let ext = match format.trim().to_ascii_lowercase().as_str() {
            "hex" => "hex",
            "csv" => "csv",
            _ => "txt",
        };
        let default_name = format!(
            "omni_probe_mcu_serial_{}.{}",
            chrono::Local::now().format("%Y%m%d_%H%M%S"),
            ext
        );
        crate::desktop_native::save_text_with_native_dialog(
            &default_name,
            "导出单片机串口终端记录文件",
            &format!("串口数据记录 (*.{})", ext),
            &format!("*.{}", ext),
            &content,
        )
    })
    .await
    .map_err(|e| format!("串口日志导出线程异常: {}", e))?
}

// ============================================================================
// 7. 单元测试全覆盖 (含 3 类极限异常边界验证)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_BUS_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_waveform_fft_dtw_pearson_and_edge_cases() {
        // 1. 生成 64 点纯正弦波，主频索引应命中理论 bin (4 周期 / 64 点 => normalized_freq = 4/64 = 0.0625)
        let mut sine_a = Vec::new();
        let mut sine_shifted = Vec::new();
        for i in 0..64 {
            let phase_a = 2.0 * PI * 4.0 * (i as f64) / 64.0;
            let phase_b = phase_a + 0.35; // 轻微相位偏移
            sine_a.push(100.0 + 50.0 * phase_a.sin());
            sine_shifted.push(100.0 + 50.0 * phase_b.sin());
        }

        let (fft_bins, dom_freq) = compute_radix2_fft(&sine_a);
        assert!(!fft_bins.is_empty());
        assert!((dom_freq - 0.0625).abs() < 0.02, "主频应为 0.0625，实际 {}", dom_freq);

        // 相移正弦波通过 DTW 规整后应保持超高相似度
        let (dtw_dist, dtw_sim) = compute_constrained_dtw(&sine_a, &sine_shifted);
        assert!(dtw_sim >= 85.0, "相移同形波 DTW 相似度应 >=85%, got {} (dist={})", dtw_sim, dtw_dist);

        // 反相干扰波形应出现负相关
        let inverted: Vec<f64> = sine_a.iter().map(|v| 200.0 - v).collect();
        let r_inv = compute_pearson_correlation(&sine_a, &inverted);
        assert!(r_inv < -0.95);

        // 2. 三类极限用例防御：空向量、包含 NaN/Inf、零方差平稳常数值
        assert!(compute_radix2_fft(&[]).0.is_empty());
        assert!(resample_linear(&[f64::NAN, f64::INFINITY], 16).is_empty());
        let flat = vec![25.0; 32];
        assert!((compute_pearson_correlation(&flat, &flat) - 1.0).abs() < 1e-9);
        assert!((compute_pearson_correlation(&flat, &sine_a)).abs() < 1e-9);
    }

    #[test]
    fn test_waveform_baseline_persistence_and_comparison() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "omni_wf_test_{}_{}",
            std::process::id(),
            chrono::Local::now().timestamp_nanos_opt().unwrap_or(1)
        ));
        let _ = fs::create_dir_all(&tmp_dir);

        let golden: Vec<f64> = (0..64).map(|i| 50.0 + 20.0 * (i as f64 * 0.2).sin()).collect();
        let snap = save_waveform_baseline_in_dir(
            &tmp_dir,
            "电机稳态基准",
            "SERIAL",
            "COM3",
            "rpm",
            100.0,
            &golden,
        )
        .unwrap();
        assert_eq!(list_waveform_baselines_in_dir(&tmp_dir).len(), 1);

        // 实时畸变样本对比
        let distorted: Vec<f64> = (0..64).map(|i| if i % 4 == 0 { 160.0 } else { 10.0 }).collect();
        let cmp = smart_compare_waveforms_in_dir(&tmp_dir, &snap.id, &distorted, "rpm").unwrap();
        assert!(cmp.outlier_point_count > 10);
        assert!(cmp.rmse > 15.0);

        // 畸形/不存在 ID 与样本不足 4 点边界拦截
        assert!(smart_compare_waveforms_in_dir(&tmp_dir, "missing_id", &golden, "rpm").is_err());
        assert!(save_waveform_baseline_in_dir(&tmp_dir, "bad", "SERIAL", "COM1", "ch", 10.0, &[1.0, 2.0]).is_err());

        assert!(delete_waveform_baseline_in_dir(&tmp_dir, &snap.id).unwrap());
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_usb_setup_cdc_acm_and_usbpcap_roundtrip() {
        let _guard = TEST_BUS_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        // 1. Standard GET_DESCRIPTOR (Device)
        let get_desc = [0x80u8, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
        let parsed = dissect_usb_setup_packet(&get_desc).unwrap();
        assert_eq!(parsed.req_type, "Standard");
        assert!(parsed.request_name.contains("GET_DESCRIPTOR (Device"));

        // 2. USB CDC-ACM SET_LINE_CODING (115200 8N1 -> 0x0001C200 = [0x00, 0xC2, 0x01, 0x00])
        let mut set_line = vec![0x21u8, 0x20, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00];
        set_line.extend_from_slice(&115200u32.to_le_bytes());
        set_line.extend_from_slice(&[0x00, 0x00, 0x08]); // 1 stop, No parity, 8 bits
        let cdc = dissect_usb_setup_packet(&set_line).unwrap();
        assert_eq!(cdc.cdc_line_coding.as_deref(), Some("115200 bps (8N1)"));

        // 3. 标准 USBPcap DLT=249 编码 + StreamingPcapUrbReader 解码往返验证
        let sample_urb = UsbUrbEventItem {
            id: 1,
            timestamp: "13:00:00.000".into(),
            ts_ns: 1_700_000_000_000_000_000,
            controller: "USBPcap1".into(),
            endpoint_key: "Bus1:Dev2:EP00".into(),
            transfer_type: "Control".into(),
            direction: "OUT".into(),
            protocol: "USB_CONTROL".into(),
            payload_len: 8,
            usbd_status: "0x00000000".into(),
            is_error: false,
            summary: parsed.summary,
            setup_decoded: None,
            raw_urb_hex: {
                // 27B USBPcap Header + 8B GET_DESCRIPTOR Setup
                let mut h = vec![27u8, 0x00];
                h.extend_from_slice(&1u64.to_le_bytes());
                h.extend_from_slice(&0u32.to_le_bytes());
                h.extend_from_slice(&0x0008u16.to_le_bytes());
                h.push(0x00); // OUT
                h.extend_from_slice(&1u16.to_le_bytes());
                h.extend_from_slice(&2u16.to_le_bytes());
                h.push(0x00); // EP0
                h.push(0x02); // Control
                h.extend_from_slice(&8u32.to_le_bytes());
                h.extend_from_slice(&get_desc);
                hex::encode_upper(&h)
            },
        };
        let (pcap_bytes, cnt) = encode_usb_frames_to_usbpcap_pcap(&[sample_urb]).unwrap();
        assert_eq!(cnt, 1);
        let mut reader = crate::usb::StreamingPcapUrbReader::new();
        let decoded = reader.push_bytes(&pcap_bytes).unwrap();
        assert_eq!(decoded.len(), 1);
        let (hdr, payload) = crate::usb::parse_usbpcap_header(&decoded[0].1).unwrap();
        assert_eq!(hdr.transfer_type, "Control");
        assert!(dissect_usb_setup_packet(payload).is_some());

        // 空载荷防护
        assert!(dissect_usb_setup_packet(&[0x80, 0x06]).is_none());
        assert!(encode_usb_frames_to_usbpcap_pcap(&[]).is_err());
    }

    #[test]
    fn test_serial_modbus_matrix_checksum_and_auto_responder() {
        let _guard = TEST_BUS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        {
            let mut lock = GLOBAL_SERIAL_DEV_ENGINE.write().unwrap();
            lock.auto_rules.clear();
            lock.modbus_registers.clear();
        }

        // 1. 校验计算器验证 (Modbus 01 03 00 00 00 02 -> CRC = C4 0B)
        let chk = compute_serial_checksum_core("MODBUS_CRC16", "01 03 00 00 00 02", true).unwrap();
        assert_eq!(chk.combined_frame_hex, "01 03 00 00 00 02 C4 0B");
        assert!(compute_serial_checksum_core("UNKNOWN_ALGO", "01 03", true).is_err());

        // 2. 配置自动应答规则：收到 Modbus 读请求 01 03 自动应答 01 03 02 00 64 (+自动 CRC16)
        upsert_serial_auto_rule_cmd(SerialAutoResponderRule {
            id: "r1".into(),
            name: "模拟从站1".into(),
            enabled: true,
            port_filter: "COM3".into(),
            match_mode: "HEX_PREFIX".into(),
            match_pattern: "01 03".into(),
            response_payload: "01 03 02 00 64".into(),
            response_is_hex: true,
            append_modbus_crc16: true,
            delay_ms: 10,
            trigger_count: 0,
            last_triggered_at: None,
        })
        .unwrap();

        let req_bytes = decode_hex_flexible("01 03 00 00 00 02 C4 0B").unwrap();
        let req_mb = crate::serial::dissect_modbus_rtu(&req_bytes).unwrap();
        let actions = record_serial_frame_and_match_rules("COM3", &req_bytes, Some(&req_mb), false);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].0, 10);
        // 01 03 02 00 64 的 Modbus CRC16 校验本身也是有效 Modbus 帧
        assert!(crate::serial::dissect_modbus_rtu(&actions[0].1).unwrap().is_crc_valid);

        // 3. 模拟收到两次写单寄存器 0x06 更新同一地址测试趋势 NEW -> UP
        let w1 = compute_serial_checksum_core("MODBUS_CRC16", "01 06 00 10 00 20", true).unwrap();
        let w1_b = decode_hex_flexible(&w1.combined_frame_hex).unwrap();
        record_serial_frame_and_match_rules("COM3", &w1_b, crate::serial::dissect_modbus_rtu(&w1_b).as_ref(), false);

        let w2 = compute_serial_checksum_core("MODBUS_CRC16", "01 06 00 10 00 50", true).unwrap();
        let w2_b = decode_hex_flexible(&w2.combined_frame_hex).unwrap();
        record_serial_frame_and_match_rules("COM3", &w2_b, crate::serial::dissect_modbus_rtu(&w2_b).as_ref(), false);

        let snap = get_bus_intelligence_snapshot_core();
        let cell = snap.modbus_registers.iter().find(|c| c.register_addr == 0x0010).unwrap();
        assert_eq!(cell.raw_u16, 0x0050);
        assert_eq!(cell.prev_u16, Some(0x0020));
        assert_eq!(cell.trend, "UP");
        assert_eq!(cell.update_count, 2);

        // 4. 巡检报告生成与 XSS 防注入转义检验
        let xss_port = crate::serial::SerialPortDetail {
            port_name: "COM9".into(),
            description: "<script>alert(1)</script>".into(),
            hardware_id: "USB\\VID_1234".into(),
            manufacturer: None,
            product: None,
            port_type: "USB 虚拟串口".into(),
            is_usb: true,
            is_available: true,
            is_in_use_by_us: true,
        };
        let bundle = generate_bus_inspection_report_core(&snap, &[xss_port], &[], None);
        assert!(bundle.markdown.contains("Modbus RTU 实时寄存器画像快照"));
        assert!(!bundle.html.contains("<script>alert(1)</script>"));
        assert!(bundle.html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn test_mcu_struct_justfloat_step_response_and_peripheral_toolkits() {
        // 1. VOFA+ JustFloat 多通道连续流粘包切帧测试 (Ch0=12.5, Ch1=-3.25)
        let mut jf_pkt = Vec::new();
        for &(c0, c1) in &[(12.5f32, -3.25f32), (24.0f32, 1.5f32)] {
            jf_pkt.extend_from_slice(&c0.to_le_bytes());
            jf_pkt.extend_from_slice(&c1.to_le_bytes());
            jf_pkt.extend_from_slice(&[0x00, 0x00, 0x80, 0x7F]);
        }
        let jf_res = parse_binary_struct_batch_core(&[hex::encode(&jf_pkt)], "", &[], true).unwrap();
        assert_eq!(jf_res.decoded_frame_count, 2);
        assert_eq!(jf_res.channels.len(), 2);
        assert!((jf_res.channels[0].samples[1] - 24.0).abs() < 1e-4);
        assert!((jf_res.channels[1].samples[0] + 3.25).abs() < 1e-4);

        // 2. 自定义结构体帧头 + 多字段物理换算测试 (AA 55 + Float32温度 + I16*0.1转速)
        let mut custom = vec![0xAAu8, 0x55];
        custom.extend_from_slice(&36.75f32.to_le_bytes());
        custom.extend_from_slice(&1500i16.to_le_bytes());
        let st_res = parse_binary_struct_batch_core(
            &[hex::encode(&custom), "DEAD".into()],
            "AA 55",
            &[
                BinaryStructField { name: "TempC".into(), field_type: "F32".into(), little_endian: true, offset: 2, scale: 1.0, bias: 0.0 },
                BinaryStructField { name: "Rpm".into(), field_type: "I16".into(), little_endian: true, offset: 6, scale: 0.1, bias: 0.0 },
            ],
            false,
        ).unwrap();
        assert_eq!(st_res.decoded_frame_count, 1);
        assert_eq!(st_res.skipped_frame_count, 1);
        assert!((st_res.channels[0].latest - 36.75).abs() < 1e-4);
        assert!((st_res.channels[1].latest - 150.0).abs() < 1e-4);

        // 3. PID 阶跃响应与稳态验证 (目标 100.0, 峰值 120.0 -> 20% 超调量)
        let step_samples = vec![0.0, 15.0, 55.0, 95.0, 120.0, 108.0, 101.0, 100.2, 99.9, 100.0];
        let sr = compute_step_response_core(&step_samples, 100.0, 10.0, 2.0).unwrap();
        assert!((sr.overshoot_pct - 20.0).abs() < 0.1);
        assert!(sr.converged);
        assert!(sr.rise_time_ms.unwrap() > 0.0);

        // 4. MCU Timer PWM + UART 波特率误差 + Modbus 四端序 + ANSI 日志崩溃捕获
        let timers = solve_mcu_timer_psc_arr_core(72_000_000, 20_000.0, false).unwrap();
        assert!(!timers.is_empty());
        assert!(timers[0].error_ppm < 1.0); // 72MHz / 3600 = 20kHz 零误差

        let baud = calc_uart_baud_error_core(72_000_000, 115200, 16).unwrap();
        assert!(baud.within_spec);

        let endians = decode_modbus_32bit_word_core("42 28 00 00").unwrap(); // IEEE754 42.0f BE
        assert!(endians[0].float32.starts_with("42.000"));

        let console = analyze_mcu_console_lines_core(&[
            "\x1b[0;32mI (12) boot: start\x1b[0m\r\n\x1b[0;31mGuru Meditation Error: Core 0 panic'ed\x1b[0m".into()
        ]);
        assert_eq!(console.panic_or_reboot_count, 1);
        assert!(!console.clean_lines[0].contains("\x1b"));

        // 5. 极限异常边界防御
        assert!(solve_mcu_timer_psc_arr_core(0, 1000.0, false).is_err());
        assert!(calc_uart_baud_error_core(8_000_000, 0, 16).is_err());
        assert!(decode_modbus_32bit_word_core("11 22").is_err());
        assert!(compute_step_response_core(&[1.0, 2.0], 10.0, 5.0, 2.0).is_err());
    }
}
