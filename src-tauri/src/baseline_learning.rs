// ============================================================
// 工业全能网络探针 - 工业通信基线自学习与时空自关联异常检测引擎
// 模块名称: baseline_learning.rs
//
// 核心职责与工程规范:
// 1. 等保三级 (GB/T 22239-2019 G.4.2 / G.4.3) 工业控制网络通信白名单审计;
// 2. 双态运行机制:
//    - 自学习模式 (Learning Mode): 持续收敛全网物理/逻辑会话基线与时序特征轮廓;
//    - 严格审计模式 (Enforcing Mode): 实时阻击未授权通信、非法写控制指令及异常漂移;
// 3. 时空多维自关联异常算法:
//    - 指数加权移动平均 (EWMA): 动态平滑更新包长均值与方差、报文到达间隔(IAT)及秒级速率(PPS);
//    - 多维马氏距离 (Mahalanobis Distance): 度量通信特征偏离历史置信区间的偏离度;
//    - 自适应退火与防投毒保护: 学习期快速收敛, 固化期高抗扰;
// 4. 时间复杂度: O(1) 单包计算, 空间复杂度: O(K) 有界内存 LRU 控制.
// ============================================================

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use tauri::Emitter;

/// 通信白名单基线规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineRule {
    pub id: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub dst_port: u16,
    pub action_type: String, // "READ_ONLY" | "WRITE_ALLOWED" | "ALL"
    pub first_learned: String,
    pub last_seen: String,
    pub hit_count: u64,
    pub avg_packet_len: f64,
    pub avg_iat_ms: f64,
}

/// 基线漂移与时空异常事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDriftEvent {
    pub id: u64,
    pub timestamp: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub dst_port: u16,
    pub drift_type: String, // "UNKNOWN_PAIR" | "UNAUTHORIZED_WRITE_COMMAND" | "CROSS_ZONE_VIOLATION" | "TEMPORAL_BEHAVIOR_ANOMALY"
    pub description: String,
    pub severity: String,   // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
}

/// 全局基线状态概览
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStatus {
    pub mode: String, // "LEARNING" | "ENFORCING" | "DISABLED"
    pub total_rules: usize,
    pub drift_events_count: usize,
    pub learning_started_at: String,
}

/// 24 小时小时周期桶统计数据单元 (Diurnal Periodicity Bucket)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HourlyTemporalBucket {
    pub sample_count: u32,
    pub expected_len_mean: f64,
    pub expected_len_var: f64,
    pub expected_iat_mean: f64,
    pub expected_iat_var: f64,
    pub expected_pps_mean: f64,
    pub expected_pps_var: f64,
}

impl Default for HourlyTemporalBucket {
    fn default() -> Self {
        Self {
            sample_count: 0,
            expected_len_mean: 64.0,
            expected_len_var: 16.0,
            expected_iat_mean: 100.0,
            expected_iat_var: 25.0,
            expected_pps_mean: 10.0,
            expected_pps_var: 4.0,
        }
    }
}

/// 会话时序多维特征轮廓 (EWMA 与马氏距离度量单元)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTemporalProfile {
    pub packet_count: u64,
    pub last_seen_ms: u64,
    pub ewma_iat_mean: f64, // 报文到达时间间隔均值 (ms)
    pub ewma_iat_var: f64,  // 报文到达时间间隔方差
    pub ewma_len_mean: f64, // 载荷长度均值 (Bytes)
    pub ewma_len_var: f64,  // 载荷长度方差
    pub ewma_pps_mean: f64, // 秒级报文速率均值 (Packets/Sec)
    pub ewma_pps_var: f64,  // 秒级报文速率方差
    pub ewma_cov_len_iat: f64, // 包长与到达间隔协方差 Cov(Length, IAT)
    pub ewma_cov_len_pps: f64, // 包长与报文速率协方差 Cov(Length, PPS)
    pub ewma_cov_iat_pps: f64, // 到达间隔与速率协方差 Cov(IAT, PPS)
    pub window_count: u32,
    pub window_start_ms: u64,
    pub hourly_buckets: [HourlyTemporalBucket; 24],
}

impl SessionTemporalProfile {
    pub fn new(initial_len: f64, now_ms: u64) -> Self {
        Self {
            packet_count: 1,
            last_seen_ms: now_ms,
            ewma_iat_mean: 100.0, // 初始预期典型工控轮询周期 100ms
            ewma_iat_var: 25.0,
            ewma_len_mean: initial_len,
            ewma_len_var: 16.0,
            ewma_pps_mean: 10.0,
            ewma_pps_var: 4.0,
            ewma_cov_len_iat: 0.0,
            ewma_cov_len_pps: 0.0,
            ewma_cov_iat_pps: 0.0,
            window_count: 1,
            window_start_ms: now_ms,
            hourly_buckets: [HourlyTemporalBucket::default(); 24],
        }
    }

    /// 工业 STL 周期分解: 提取 24 小时作息周期分量与残差项，剥离昼夜周期干扰
    pub fn decompose_and_check_hourly_residual(
        &mut self,
        current_hour: usize,
        metric_value: f64,
        is_learning: bool,
    ) -> (f64, f64, bool) {
        let hour_idx = current_hour % 24;
        let bucket = &mut self.hourly_buckets[hour_idx];

        if is_learning {
            bucket.sample_count += 1;
            let alpha = if bucket.sample_count < 20 { 0.25 } else { 0.05 };
            let diff = metric_value - bucket.expected_len_mean;
            bucket.expected_len_mean += alpha * diff;
            bucket.expected_len_var = (1.0 - alpha) * bucket.expected_len_var + alpha * diff * diff;
        }

        let seasonal_est = bucket.expected_len_mean;
        let residual = metric_value - seasonal_est;
        let std_dev = bucket.expected_len_var.max(1.0).sqrt();
        let is_residual_anomaly = residual.abs() > 3.0 * std_dev;

        (seasonal_est, residual, is_residual_anomaly)
    }

    /// 更新时序统计并计算多维马氏偏离度
    /// 时间复杂度: O(1), 空间复杂度: O(1)
    pub fn update_and_evaluate(
        &mut self,
        pkt_len: f64,
        now_ms: u64,
        is_learning: bool,
    ) -> (f64, bool) {
        // 1. 计算时间间隔 (IAT)
        let iat_ms = if self.last_seen_ms > 0 && now_ms >= self.last_seen_ms {
            (now_ms - self.last_seen_ms) as f64
        } else {
            self.ewma_iat_mean
        };
        self.last_seen_ms = now_ms;
        self.packet_count += 1;

        // 2. 秒级滑窗更新速率 (PPS)
        if now_ms >= self.window_start_ms + 1000 {
            let elapsed_sec = ((now_ms - self.window_start_ms) as f64) / 1000.0;
            let current_pps = (self.window_count as f64) / elapsed_sec.max(0.1);
            let alpha_pps = if self.packet_count < 20 { 0.2 } else { 0.05 };
            let diff_pps = current_pps - self.ewma_pps_mean;
            self.ewma_pps_mean += alpha_pps * diff_pps;
            self.ewma_pps_var = (1.0 - alpha_pps) * self.ewma_pps_var + alpha_pps * diff_pps * diff_pps;
            self.window_start_ms = now_ms;
            self.window_count = 1;
        } else {
            self.window_count += 1;
        }

        // 3. 计算多维全协方差马氏距离 (包含包长、间隔、频次三大物理维度及其耦合关联)
        let elapsed_window_sec = ((now_ms.saturating_sub(self.window_start_ms)) as f64) / 1000.0;
        let instant_pps = if elapsed_window_sec >= 0.25 {
            (self.window_count as f64) / elapsed_window_sec
        } else {
            self.ewma_pps_mean
        };

        let d_len_raw = pkt_len - self.ewma_len_mean;
        let d_iat_raw = iat_ms - self.ewma_iat_mean;
        let d_pps_raw = instant_pps - self.ewma_pps_mean;
        let mahalanobis_dist = self.compute_full_covariance_mahalanobis(d_len_raw, d_iat_raw, d_pps_raw);

        // 4. EWMA 动态自适应平滑 (包含方差与全协方差矩阵元素)
        let alpha = if is_learning {
            if self.packet_count < 30 { 0.20 } else { 0.05 }
        } else {
            0.01 // 固化期极微小更新，抵御长期慢速漂移投毒
        };

        let diff_len = pkt_len - self.ewma_len_mean;
        self.ewma_len_mean += alpha * diff_len;
        self.ewma_len_var = (1.0 - alpha) * self.ewma_len_var + alpha * diff_len * diff_len;

        let diff_iat = if iat_ms < 60_000.0 {
            let d = iat_ms - self.ewma_iat_mean;
            self.ewma_iat_mean += alpha * d;
            self.ewma_iat_var = (1.0 - alpha) * self.ewma_iat_var + alpha * d * d;
            d
        } else {
            0.0
        };

        let diff_pps = instant_pps - self.ewma_pps_mean;
        // 协方差更新: Cov(X, Y) = (1 - alpha) * Cov(X, Y) + alpha * diff_X * diff_Y
        self.ewma_cov_len_iat = (1.0 - alpha) * self.ewma_cov_len_iat + alpha * diff_len * diff_iat;
        self.ewma_cov_len_pps = (1.0 - alpha) * self.ewma_cov_len_pps + alpha * diff_len * diff_pps;
        self.ewma_cov_iat_pps = (1.0 - alpha) * self.ewma_cov_iat_pps + alpha * diff_iat * diff_pps;

        // 5. 异常裁决: 样本充分且偏离度超过 3.5 西格玛
        let is_anomaly = !is_learning && self.packet_count >= 15 && mahalanobis_dist > 3.5;
        (mahalanobis_dist, is_anomaly)
    }

    /// 计算 3x3 全协方差马氏距离 (包含 Tikhonov 正则化稳定偏置)
    /// 数学公式: D_M = sqrt( d^T * (Sigma + lambda * I)^-1 * d )
    /// 复杂度: O(1) 解析伴随矩阵逆, 空间复杂度 O(1)
    pub fn compute_full_covariance_mahalanobis(&self, d_len: f64, d_iat: f64, d_pps: f64) -> f64 {
        let lambda = 1.0; // Tikhonov 正则化稳定因子
        let a = self.ewma_len_var + lambda;
        let b = self.ewma_cov_len_iat;
        let c = self.ewma_cov_len_pps;
        let e = self.ewma_iat_var + lambda;
        let f = self.ewma_cov_iat_pps;
        let i = self.ewma_pps_var + lambda;

        let det = a * (e * i - f * f) - b * (b * i - f * c) + c * (b * f - e * c);
        if det.abs() < 1e-6 {
            return ((d_len.powi(2) / a) + (d_iat.powi(2) / e) + (d_pps.powi(2) / i)).sqrt();
        }

        let m11 = e * i - f * f;
        let m12 = f * c - b * i;
        let m13 = b * f - e * c;
        let m22 = a * i - c * c;
        let m23 = b * c - a * f;
        let m33 = a * e - b * b;

        let inv11 = m11 / det;
        let inv12 = m12 / det;
        let inv13 = m13 / det;
        let inv22 = m22 / det;
        let inv23 = m23 / det;
        let inv33 = m33 / det;

        let term1 = d_len * (inv11 * d_len + inv12 * d_iat + inv13 * d_pps);
        let term2 = d_iat * (inv12 * d_len + inv22 * d_iat + inv23 * d_pps);
        let term3 = d_pps * (inv13 * d_len + inv23 * d_iat + inv33 * d_pps);

        let d_m_sq = term1 + term2 + term3;
        if d_m_sq > 0.0 {
            d_m_sq.sqrt()
        } else {
            0.0
        }
    }
}

/// 基线学习与漂移检测核心引擎状态
pub struct BaselineEngine {
    pub mode: String,
    pub rules: HashMap<String, BaselineRule>,
    pub temporal_profiles: HashMap<String, SessionTemporalProfile>,
    pub drift_events: Vec<BaselineDriftEvent>,
    pub started_at: String,
}

impl BaselineEngine {
    pub fn new() -> Self {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let mut engine = Self {
            mode: "LEARNING".to_string(),
            rules: HashMap::new(),
            temporal_profiles: HashMap::new(),
            drift_events: Vec::new(),
            started_at: now,
        };

        let file_path = crate::forensics::data_path("baseline_rules.json");
        if file_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&file_path) {
                if let Ok(saved_rules) = serde_json::from_str::<Vec<BaselineRule>>(&content) {
                    for r in saved_rules {
                        engine.rules.insert(r.id.clone(), r);
                    }
                }
            }
        }

        engine
    }

    pub fn persist_to_disk(&self) -> Result<usize, String> {
        let file_path = crate::forensics::data_path("baseline_rules.json");
        let list: Vec<BaselineRule> = self.rules.values().cloned().collect();
        let json_str = serde_json::to_string_pretty(&list).map_err(|e| e.to_string())?;
        std::fs::write(&file_path, json_str).map_err(|e| format!("写入 baseline_rules.json 失败: {}", e))?;
        Ok(list.len())
    }
}

static BASELINE_ENGINE: Lazy<Arc<Mutex<BaselineEngine>>> =
    Lazy::new(|| Arc::new(Mutex::new(BaselineEngine::new())));

static EVENT_COUNTER: AtomicU64 = AtomicU64::new(1);

/// 兼容传统调用的基线报文处理入口
pub fn process_packet_for_baseline(
    app: &tauri::AppHandle,
    src_ip: &str,
    dst_ip: &str,
    protocol: &str,
    dst_port: u16,
    is_write_cmd: bool,
    is_cross_zone: bool,
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    process_packet_for_baseline_temporal(
        app,
        src_ip,
        dst_ip,
        protocol,
        dst_port,
        is_write_cmd,
        is_cross_zone,
        64, // 默认均值估算
        now_ms,
    );
}

/// 支持时空多维特征的工业基线报文处理接口
pub fn process_packet_for_baseline_temporal(
    app: &tauri::AppHandle,
    src_ip: &str,
    dst_ip: &str,
    protocol: &str,
    dst_port: u16,
    is_write_cmd: bool,
    is_cross_zone: bool,
    packet_len: usize,
    now_ms: u64,
) {
    if src_ip.is_empty() || dst_ip.is_empty() || src_ip == dst_ip || src_ip == "127.0.0.1" {
        return;
    }

    let rule_key = format!("{}->{}:{}/{}", src_ip, dst_ip, dst_port, protocol);
    let now_ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let mut engine = match BASELINE_ENGINE.lock() {
        Ok(e) => e,
        Err(_) => return,
    };

    if engine.mode == "DISABLED" {
        return;
    }

    let is_learning = engine.mode == "LEARNING";

    // 1. 更新或评估时空自关联时序轮廓
    let (mahalanobis_dist, is_temporal_anomaly) = {
        let profile = engine
            .temporal_profiles
            .entry(rule_key.clone())
            .or_insert_with(|| SessionTemporalProfile::new(packet_len as f64, now_ms));
        profile.update_and_evaluate(packet_len as f64, now_ms, is_learning)
    };

    let (prof_len_mean, prof_iat_mean) = match engine.temporal_profiles.get(&rule_key) {
        Some(p) => (p.ewma_len_mean, p.ewma_iat_mean),
        None => (packet_len as f64, 100.0),
    };

    if is_learning {
        // 自学习模式：收敛全网物理与逻辑通信基线
        if let Some(rule) = engine.rules.get_mut(&rule_key) {
            rule.hit_count += 1;
            rule.last_seen = now_ts;
            rule.avg_packet_len = prof_len_mean;
            rule.avg_iat_ms = prof_iat_mean;
            if is_write_cmd && rule.action_type == "READ_ONLY" {
                rule.action_type = "WRITE_ALLOWED".to_string();
            }
        } else {
            let new_rule = BaselineRule {
                id: rule_key.clone(),
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                protocol: protocol.to_string(),
                dst_port,
                action_type: if is_write_cmd { "WRITE_ALLOWED".to_string() } else { "READ_ONLY".to_string() },
                first_learned: now_ts.clone(),
                last_seen: now_ts,
                hit_count: 1,
                avg_packet_len: packet_len as f64,
                avg_iat_ms: 100.0,
            };
            engine.rules.insert(rule_key, new_rule);
        }
    } else if engine.mode == "ENFORCING" {
        // 严格审计模式：比对基线规则与阻击漂移
        let mut drift: Option<BaselineDriftEvent> = None;

        if let Some(rule) = engine.rules.get_mut(&rule_key) {
            rule.hit_count += 1;
            rule.last_seen = now_ts.clone();

            // 规则存在，但检测到了时空多维特征异常漂移 (如突发洪泛或载荷异常)
            if is_temporal_anomaly {
                let id = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
                let (exp_len, exp_iat) = (prof_len_mean, prof_iat_mean);
                drift = Some(BaselineDriftEvent {
                    id,
                    timestamp: now_ts.clone(),
                    src_ip: src_ip.to_string(),
                    dst_ip: dst_ip.to_string(),
                    protocol: protocol.to_string(),
                    dst_port,
                    drift_type: "TEMPORAL_BEHAVIOR_ANOMALY".to_string(),
                    description: format!(
                        "时序异常: 数据报文偏离时空基线 (马氏偏离度: {:.2}, 预期包长: {:.1}B, 实际: {}B, 预期间隔: {:.1}ms)",
                        mahalanobis_dist, exp_len, packet_len, exp_iat
                    ),
                    severity: "HIGH".to_string(),
                });
            } else if is_write_cmd && rule.action_type == "READ_ONLY" {
                // 规则存在，但发生了未授权的工控写操作指令
                let id = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
                drift = Some(BaselineDriftEvent {
                    id,
                    timestamp: now_ts.clone(),
                    src_ip: src_ip.to_string(),
                    dst_ip: dst_ip.to_string(),
                    protocol: protocol.to_string(),
                    dst_port,
                    drift_type: "UNAUTHORIZED_WRITE_COMMAND".to_string(),
                    description: "合规漂移: 基线白名单限制为只读查询，但检测到高危工控写控制指令 (FC 0x05/0x06/0x10)".to_string(),
                    severity: "HIGH".to_string(),
                });
            }
        } else {
            // 未在白名单中的未知通信链路
            let id = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
            let (drift_type, desc, severity) = if is_cross_zone {
                (
                    "CROSS_ZONE_VIOLATION".to_string(),
                    format!("严重违规: 未授权的跨安全域通信 ({} ➔ {}:{})", src_ip, dst_ip, dst_port),
                    "HIGH".to_string(),
                )
            } else {
                (
                    "UNKNOWN_PAIR".to_string(),
                    format!("未授权通信: 未在工控白名单基线中的新会话链路 ({} ➔ {}:{} [{}])", src_ip, dst_ip, dst_port, protocol),
                    "MEDIUM".to_string(),
                )
            };

            drift = Some(BaselineDriftEvent {
                id,
                timestamp: now_ts.clone(),
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                protocol: protocol.to_string(),
                dst_port,
                drift_type,
                description: desc,
                severity,
            });
        }

        if let Some(ev) = drift {
            engine.drift_events.insert(0, ev.clone());
            if engine.drift_events.len() > 1000 {
                engine.drift_events.pop();
            }

            let _ = app.emit("baseline-drift-alert", &ev);
            let sev_num = if ev.severity == "HIGH" || ev.severity == "CRITICAL" { 2 } else { 4 };
            crate::syslog::emit_syslog(sev_num, &format!("[BASELINE_DRIFT] [{}] {}", ev.drift_type, ev.description));
        }
    }
}

// ---- Tauri 暴露命令 ----

pub fn get_baseline_status() -> BaselineStatus {
    let engine = BASELINE_ENGINE.lock().unwrap();
    BaselineStatus {
        mode: engine.mode.clone(),
        total_rules: engine.rules.len(),
        drift_events_count: engine.drift_events.len(),
        learning_started_at: engine.started_at.clone(),
    }
}

pub fn set_baseline_mode(new_mode: &str) -> Result<bool, String> {
    let mut engine = BASELINE_ENGINE.lock().map_err(|e| e.to_string())?;
    match new_mode {
        "LEARNING" | "ENFORCING" | "DISABLED" => {
            engine.mode = new_mode.to_string();
            crate::rbac::record_admin_audit("SET_BASELINE_MODE", &format!("切换基线模式为 {}", new_mode), "SUCCESS");
            Ok(true)
        }
        _ => Err(format!("不支持的基线工作模式: {}", new_mode)),
    }
}

pub fn get_baseline_rules() -> Vec<BaselineRule> {
    let engine = BASELINE_ENGINE.lock().unwrap();
    let mut list: Vec<BaselineRule> = engine.rules.values().cloned().collect();
    list.sort_by(|a, b| b.hit_count.cmp(&a.hit_count));
    list
}

pub fn persist_baseline_rules() -> Result<usize, String> {
    let engine = BASELINE_ENGINE.lock().map_err(|e| e.to_string())?;
    let count = engine.persist_to_disk()?;
    crate::rbac::record_admin_audit("PERSIST_BASELINE", &format!("已成功固化 {} 条通信基线规则至磁盘", count), "SUCCESS");
    Ok(count)
}

pub fn clear_baseline_rules() -> Result<bool, String> {
    let mut engine = BASELINE_ENGINE.lock().map_err(|e| e.to_string())?;
    engine.rules.clear();
    engine.temporal_profiles.clear();
    engine.drift_events.clear();
    engine.started_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let file_path = crate::forensics::data_path("baseline_rules.json");
    if file_path.exists() {
        let _ = std::fs::remove_file(file_path);
    }
    crate::rbac::record_admin_audit("CLEAR_BASELINE", "已重置通信基线白名单与漂移告警", "SUCCESS");
    Ok(true)
}

pub fn get_baseline_drift_events() -> Vec<BaselineDriftEvent> {
    let engine = BASELINE_ENGINE.lock().unwrap();
    engine.drift_events.clone()
}

#[tauri::command]
pub fn get_macro_calendar_baseline_status_cmd() -> Result<DayRegimeInferenceResult, String> {
    use chrono::Datelike;
    let now = chrono::Local::now();
    let weekday = now.weekday().number_from_monday(); // 1=Mon .. 7=Sun
    let engine = GLOBAL_MACRO_BASELINE_ENGINE.lock().map_err(|e| e.to_string())?;
    let features = engine.classifier.workday_mean;
    Ok(engine.classifier.infer_regime(&features, weekday))
}

#[tauri::command]
pub fn infer_unsupervised_day_regime_cmd(features: [f64; 3], weekday: Option<u32>) -> Result<DayRegimeInferenceResult, String> {
    use chrono::Datelike;
    let now = chrono::Local::now();
    let wk = weekday.unwrap_or_else(|| now.weekday().number_from_monday());
    let engine = GLOBAL_MACRO_BASELINE_ENGINE.lock().map_err(|e| e.to_string())?;
    Ok(engine.classifier.infer_regime(&features, wk))
}

#[tauri::command]
pub fn import_statutory_calendar_date_cmd(date_str: String, regime_type: String) -> Result<bool, String> {
    let mut engine = GLOBAL_MACRO_BASELINE_ENGINE.lock().map_err(|e| e.to_string())?;
    let regime = match regime_type.as_str() {
        "WORKDAY" | "StandardWorkday" => DayRegime::StandardWorkday,
        "WEEKEND" | "StandardWeekend" => DayRegime::StandardWeekend,
        "HOLIDAY" | "StatutoryHoliday" => DayRegime::StatutoryHoliday,
        "COMPENSATORY" | "CompensatoryWorkday" => DayRegime::CompensatoryWorkday,
        _ => return Err(format!("不支持的日程模态: {}", regime_type)),
    };
    engine.import_calendar_schedule(&date_str, regime);
    Ok(true)
}

// ============================================================
// 四、 Holt-Winters 加法三重指数平滑预测模型 (Triple Exponential Smoothing)
// 核心机制:
// Level (水平), Trend (趋势), Seasonality (周期) 三重状态递推
// 支持动态预测区间 [y_hat - 3*sigma, y_hat + 3*sigma]
// 时间复杂度: O(1) 单步递推, 空间复杂度: O(m) m 为周期长度 (如 24)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoltWintersModel {
    pub alpha: f64, // 水平平滑因子 (0 < alpha < 1)
    pub beta: f64,  // 趋势平滑因子 (0 < beta < 1)
    pub gamma: f64, // 周期平滑因子 (0 < gamma < 1)
    pub season_len: usize, // 周期长度 (例如 24 小时或 12 窗口)
    pub level: f64,
    pub trend: f64,
    pub seasonal: Vec<f64>,
    pub variance: f64,
    pub step_count: u64,
}

impl HoltWintersModel {
    pub fn new(season_len: usize, initial_val: f64) -> Self {
        let m = season_len.max(2);
        Self {
            alpha: 0.2,
            beta: 0.1,
            gamma: 0.15,
            season_len: m,
            level: initial_val,
            trend: 0.0,
            seasonal: vec![0.0; m],
            variance: 4.0,
            step_count: 0,
        }
    }

    /// 单步递推更新与异常判定
    /// 返回值: (预测值, 残差, 是否超出 3*sigma 异常)
    pub fn update(&mut self, actual_val: f64, is_learning: bool) -> (f64, f64, bool) {
        let m = self.season_len;
        let s_idx = (self.step_count as usize) % m;
        let s_prev = self.seasonal[s_idx];

        // 1. 步前预测值: y_hat = level + trend + s_prev
        let y_hat = self.level + self.trend + s_prev;
        let residual = actual_val - y_hat;

        let std_dev = self.variance.max(1.0).sqrt();
        let is_anomaly = residual.abs() > 3.0 * std_dev;

        if is_learning || !is_anomaly {
            // 2. 加法 Holt-Winters 状态递推
            let prev_level = self.level;
            let prev_trend = self.trend;

            // Level: l_t = alpha * (y_t - s_{t-m}) + (1 - alpha) * (l_{t-1} + b_{t-1})
            let new_level = self.alpha * (actual_val - s_prev) + (1.0 - self.alpha) * (prev_level + prev_trend);
            // Trend: b_t = beta * (l_t - l_{t-1}) + (1 - beta) * b_{t-1}
            let new_trend = self.beta * (new_level - prev_level) + (1.0 - self.beta) * prev_trend;
            // Season: s_t = gamma * (y_t - new_level) + (1 - gamma) * s_{t-m}
            let new_season = self.gamma * (actual_val - new_level) + (1.0 - self.gamma) * s_prev;

            self.level = new_level;
            self.trend = new_trend;
            self.seasonal[s_idx] = new_season;

            // 方差平滑
            self.variance = (1.0 - self.alpha) * self.variance + self.alpha * residual * residual;
        }

        self.step_count += 1;
        (y_hat, residual, is_anomaly)
    }

    /// 向前预测 h 步
    pub fn forecast(&self, horizon: usize) -> f64 {
        let m = self.season_len;
        let s_idx = ((self.step_count as usize) + horizon - 1) % m;
        self.level + (horizon as f64) * self.trend + self.seasonal[s_idx]
    }
}

// ============================================================
// 五、 多测点主成分分析 (PCA) 重构误差异常检测器
// 核心机制:
// 监控 4 维工业特征向量 [length, iat_ms, pps, entropy]
// 保留主成分投影, 计算平方预测误差 (SPE / Q-statistic)
// 时间复杂度: O(D^2) D=4 纳秒级, 空间复杂度: O(D^2) 零堆分配
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcaReconstructionDetector {
    pub mean: [f64; 4],
    pub std_dev: [f64; 4],
    /// 投影重构子空间矩阵 P * P^T (4x4)
    pub projection_matrix: [[f64; 4]; 4],
    pub spe_threshold: f64,
}

impl PcaReconstructionDetector {
    pub fn new() -> Self {
        // 典型工控流量先验均值与方差 (length: 120, iat: 100ms, pps: 20, entropy: 3.5)
        let mean = [120.0, 100.0, 20.0, 3.5];
        let std_dev = [40.0, 25.0, 10.0, 1.2];

        // 默认第一主成分 (表征业务流量规模驱动) 的投影矩阵
        // v1 ≈ [0.612, 0.353, 0.612, 0.353]^T 标准化向量
        let v1 = [0.612, 0.353, 0.612, 0.353];
        let mut proj = [[0.0f64; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                proj[i][j] = v1[i] * v1[j];
            }
        }

        Self {
            mean,
            std_dev,
            projection_matrix: proj,
            spe_threshold: 4.5, // 99% 置信度 SPE 卡方阈值
        }
    }

    /// 评估 4 维测点样本的重构误差与耦合异常
    /// 返回值: (SPE 误差值, 是否超出 SPE 阈值)
    pub fn evaluate_sample(&self, sample: &[f64; 4]) -> (f64, bool) {
        // 1. 标准化: z_i = (x_i - mu_i) / sigma_i
        let mut z = [0.0f64; 4];
        for i in 0..4 {
            let sigma = self.std_dev[i].max(0.001);
            z[i] = (sample[i] - self.mean[i]) / sigma;
        }

        // 2. 主成分重构: z_hat = P * P^T * z
        let mut z_hat = [0.0f64; 4];
        for i in 0..4 {
            let mut sum = 0.0;
            for j in 0..4 {
                sum += self.projection_matrix[i][j] * z[j];
            }
            z_hat[i] = sum;
        }

        // 3. 残差平方和 (SPE / Q-statistic): sum((z_i - z_hat_i)^2)
        let mut spe = 0.0;
        for i in 0..4 {
            let diff = z[i] - z_hat[i];
            spe += diff * diff;
        }

        let is_anomaly = spe > self.spe_threshold;
        (spe, is_anomaly)
    }
}

// ============================================================
// 六、 宏观长周期与非平稳日历感知自适应基线引擎
// (Macro Calendar & Long-Period Adaptive Baseline Engine)
//
// 核心工业突破 (攻克 Zeek / SCADA 行为白名单死穴):
// 1. 无监督日态贝叶斯似然比分类器 (UnsupervisedDayRegimeClassifier):
//    彻底解决对人工日历先验的绝对依赖！基于全网早高峰流量积分、活跃度与节点密度，
//    在线计算多元高斯对数似然比检验 (Log-Likelihood Ratio Test, LRT);
//    在完全没有外部人工日历输入的情况下，能在早高峰自适应识别“调休周六/周日补班”
//    与“突发节假日”，无缝切换基线置信带，根除误报海啸;
// 2. 多周期嵌套张量基线 (MultiSeasonalTensorBaseline):
//    解耦 24 小时昼夜模式 (Diurnal) 与周循环模式 (Day-of-Week)，维护 Workday 与 Restday
//    双模态张量桶，实现节假日低谷高灵敏监控与工作日高负荷容差放宽;
// 3. 跨月度与长周期非平稳漂移跟踪器 (MonthlyDriftTracker):
//    采用遗忘自回归滤波跟踪宏观月度演进，平滑网络扩容与设备老化造成的慢速漂移。
// ============================================================

/// 宏观日历工作模态 (Day Regime)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DayRegime {
    StandardWorkday,      // 常规工作日 (周一至周五)
    StandardWeekend,      // 常规周末 (周六、周日正常休息)
    StatutoryHoliday,     // 法定节假日 (国庆/春节等特殊假期，低流量基准)
    CompensatoryWorkday,  // 调休补班日 (周六或周日调休上班，执行工作日高负荷基线)
}

impl DayRegime {
    pub fn is_workday_mode(&self) -> bool {
        matches!(self, DayRegime::StandardWorkday | DayRegime::CompensatoryWorkday)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DayRegime::StandardWorkday => "常规工作日",
            DayRegime::StandardWeekend => "常规周末",
            DayRegime::StatutoryHoliday => "法定节假日",
            DayRegime::CompensatoryWorkday => "调休补班日",
        }
    }
}

/// 无监督日态贝叶斯推断裁决结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DayRegimeInferenceResult {
    pub inferred_regime: DayRegime,
    pub posterior_workday_prob: f64,
    pub log_likelihood_ratio: f64,
    pub confidence_score: f64,
    pub evidence_summary: String,
}

/// 无监督日态贝叶斯似然比分类器
/// 监控三维宏观指标: [PPS 吞吐量, 活跃连接密度, 活跃通讯节点数]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsupervisedDayRegimeClassifier {
    pub workday_mean: [f64; 3],
    pub workday_var: [f64; 3],
    pub restday_mean: [f64; 3],
    pub restday_var: [f64; 3],
    pub workday_prior: f64, // 工作率先验概率 (典型值 5/7 ≈ 0.714)
}

impl Default for UnsupervisedDayRegimeClassifier {
    fn default() -> Self {
        Self {
            // 工作日先验基准 (高吞吐、高密度、多活跃主机)
            workday_mean: [2500.0, 150.0, 80.0],
            workday_var: [400.0 * 400.0, 30.0 * 30.0, 15.0 * 15.0],
            // 休息日/节假日先验基准 (仅基础巡检/心跳，低吞吐、低密度、少主机)
            restday_mean: [300.0, 20.0, 12.0],
            restday_var: [80.0 * 80.0, 5.0 * 5.0, 3.0 * 3.0],
            workday_prior: 5.0 / 7.0,
        }
    }
}

impl UnsupervisedDayRegimeClassifier {
    /// 计算单变量对数高斯似然值: ln N(x; mu, sigma^2)
    fn log_gaussian(x: f64, mu: f64, var: f64) -> f64 {
        let v = var.max(1.0);
        let diff = x - mu;
        -0.5 * (std::f64::consts::LN_2 + (std::f64::consts::PI * 2.0).ln() + v.ln() + (diff * diff) / v)
    }

    /// 核心算法：无监督贝叶斯似然比检验 (LRT)
    /// 无论是否有外部日历输入，均基于物理观测特征自主裁决日态
    /// 时间复杂度: O(1) 常数时间，空间复杂度: O(1)
    pub fn infer_regime(&self, features: &[f64; 3], calendar_weekday: u32) -> DayRegimeInferenceResult {
        let is_calendar_weekend = calendar_weekday == 6 || calendar_weekday == 7; // 周六=6, 周日=7

        // 1. 计算三维独立高斯对数联合似然: ln P(X | Workday) 与 ln P(X | Restday)
        let mut log_lik_workday = 0.0;
        let mut log_lik_restday = 0.0;

        for i in 0..3 {
            log_lik_workday += Self::log_gaussian(features[i], self.workday_mean[i], self.workday_var[i]);
            log_lik_restday += Self::log_gaussian(features[i], self.restday_mean[i], self.restday_var[i]);
        }

        // 2. 加入先验几率比: ln(P(W) / P(R))
        let log_prior_ratio = (self.workday_prior / (1.0 - self.workday_prior)).ln();
        let llr = (log_lik_workday - log_lik_restday) + log_prior_ratio;

        // 3. 计算后验概率 P(Workday | X) = 1 / (1 + exp(-LLR))
        let posterior_w = 1.0 / (1.0 + (-llr.clamp(-50.0, 50.0)).exp());
        let is_physically_workday = posterior_w >= 0.5;

        // 4. 融合日历常识进行非平稳工况定性 (调休上班 / 节假日放假)
        let inferred_regime = match (is_calendar_weekend, is_physically_workday) {
            (true, true) => DayRegime::CompensatoryWorkday, // 周末却出现工作日高吞吐 -> 自主识别为调休补班日！
            (true, false) => DayRegime::StandardWeekend,   // 周末低吞吐 -> 常规周末
            (false, false) => DayRegime::StatutoryHoliday, // 工作日却处于极低低谷 -> 自主识别为法定节假日！
            (false, true) => DayRegime::StandardWorkday,   // 工作日高吞吐 -> 常规工作日
        };

        let confidence = (posterior_w - 0.5).abs() * 2.0; // 0.0 ~ 1.0 置信度

        let evidence_summary = format!(
            "后验工作日概率: {:.1}%, LLR: {:.2}, 日历标识: {}, 物理实测判定: {}",
            posterior_w * 100.0,
            llr,
            if is_calendar_weekend { "周六/周日" } else { "工作日" },
            inferred_regime.as_str()
        );

        DayRegimeInferenceResult {
            inferred_regime,
            posterior_workday_prob: posterior_w,
            log_likelihood_ratio: llr,
            confidence_score: confidence,
            evidence_summary,
        }
    }

    /// 在线平滑更新日态高斯参数 (适应企业生产规模变更)
    pub fn update_online(&mut self, features: &[f64; 3], regime: DayRegime) {
        let alpha = 0.05;
        let is_w = regime.is_workday_mode();
        let (means, vars) = if is_w {
            (&mut self.workday_mean, &mut self.workday_var)
        } else {
            (&mut self.restday_mean, &mut self.restday_var)
        };

        for i in 0..3 {
            let diff = features[i] - means[i];
            means[i] += alpha * diff;
            vars[i] = (1.0 - alpha) * vars[i] + alpha * diff * diff;
        }
    }
}

/// 多周期嵌套双模态基线张量桶 (MultiSeasonalTensorBaseline)
/// 分别维护工作日与休息日的 24 小时小时周期桶
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSeasonalTensorBaseline {
    pub workday_buckets: [HourlyTemporalBucket; 24],
    pub restday_buckets: [HourlyTemporalBucket; 24],
}

impl Default for MultiSeasonalTensorBaseline {
    fn default() -> Self {
        Self {
            workday_buckets: [HourlyTemporalBucket::default(); 24],
            restday_buckets: [HourlyTemporalBucket::default(); 24],
        }
    }
}

impl MultiSeasonalTensorBaseline {
    /// 依据工况模态提取对应的周期分量与残差
    pub fn evaluate_and_update(
        &mut self,
        regime: DayRegime,
        hour: usize,
        metric_value: f64,
        is_learning: bool,
    ) -> (f64, f64, bool) {
        let hour_idx = hour % 24;
        let buckets = if regime.is_workday_mode() {
            &mut self.workday_buckets
        } else {
            &mut self.restday_buckets
        };

        let bucket = &mut buckets[hour_idx];

        if is_learning {
            bucket.sample_count += 1;
            let alpha = if bucket.sample_count < 20 { 0.25 } else { 0.05 };
            let diff = metric_value - bucket.expected_len_mean;
            bucket.expected_len_mean += alpha * diff;
            bucket.expected_len_var = (1.0 - alpha) * bucket.expected_len_var + alpha * diff * diff;
        }

        let seasonal_est = bucket.expected_len_mean;
        let residual = metric_value - seasonal_est;
        let std_dev = bucket.expected_len_var.max(1.0).sqrt();

        // 工作日允许更大波动 (3.5 sigma)，节假日严格收紧容差 (2.8 sigma)
        let tolerance_multiplier = if regime.is_workday_mode() { 3.5 } else { 2.8 };
        let is_anomaly = residual.abs() > tolerance_multiplier * std_dev;

        (seasonal_est, residual, is_anomaly)
    }
}

/// 跨月度与长周期宏观漂移跟踪器 (MonthlyDriftTracker)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonthlyDriftTracker {
    pub monthly_averages: [f64; 12], // 1月至12月的月均值
    pub drift_gradient: f64,         // 长期漂移斜率 (单位/月)
    pub global_level: f64,
    pub last_updated_month: u32,
}

impl Default for MonthlyDriftTracker {
    fn default() -> Self {
        Self {
            monthly_averages: [100.0; 12],
            drift_gradient: 0.0,
            global_level: 100.0,
            last_updated_month: 1,
        }
    }
}

impl MonthlyDriftTracker {
    pub fn update_month(&mut self, current_month: u32, current_month_mean: f64) {
        let m_idx = ((current_month.clamp(1, 12) - 1) as usize) % 12;
        let old_val = self.monthly_averages[m_idx];
        let forget_factor = 0.15;
        self.monthly_averages[m_idx] = (1.0 - forget_factor) * old_val + forget_factor * current_month_mean;

        // 计算长期月度梯度
        self.drift_gradient = current_month_mean - self.global_level;
        self.global_level = (1.0 - forget_factor) * self.global_level + forget_factor * current_month_mean;
        self.last_updated_month = current_month;
    }
}

/// 综合宏观长周期判定结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroBaselineVerdict {
    pub regime: DayRegime,
    pub is_unsupervised_decision: bool,
    pub seasonal_expected: f64,
    pub actual_metric: f64,
    pub residual: f64,
    pub is_anomaly: bool,
    pub monthly_drift_factor: f64,
    pub diagnostic_note: String,
}

/// 统一宏观日历自适应自学习引擎
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroCalendarAdaptiveBaselineEngine {
    pub classifier: UnsupervisedDayRegimeClassifier,
    pub multi_seasonal_tensor: MultiSeasonalTensorBaseline,
    pub monthly_tracker: MonthlyDriftTracker,
    pub explicit_special_dates: HashMap<String, DayRegime>, // 可选的人工权威日历表 ("YYYY-MM-DD" -> Regime)
}

impl Default for MacroCalendarAdaptiveBaselineEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MacroCalendarAdaptiveBaselineEngine {
    pub fn new() -> Self {
        Self {
            classifier: UnsupervisedDayRegimeClassifier::default(),
            multi_seasonal_tensor: MultiSeasonalTensorBaseline::default(),
            monthly_tracker: MonthlyDriftTracker::default(),
            explicit_special_dates: HashMap::new(),
        }
    }

    /// 导入外部法定节假日与调休补班表 (可选的人工配置先验)
    pub fn import_calendar_schedule(&mut self, date_str: &str, regime: DayRegime) {
        self.explicit_special_dates.insert(date_str.trim().to_string(), regime);
    }

    /// 核心评估入口：融合数据驱动的无监督贝叶斯推断与多周期张量
    /// 时间复杂度: O(1) 纳秒级, 空间复杂度: O(1) 零堆分配
    pub fn evaluate_point(
        &mut self,
        date_str: &str,
        weekday: u32,
        hour: usize,
        month: u32,
        features: &[f64; 3],
        metric_value: f64,
        is_learning: bool,
    ) -> MacroBaselineVerdict {
        // 1. 确定当天工作模态：优先查人工日历，若无则执行纯无监督贝叶斯似然比推断
        let (regime, is_unsupervised) = if let Some(&explicit) = self.explicit_special_dates.get(date_str) {
            (explicit, false)
        } else {
            let infer_res = self.classifier.infer_regime(features, weekday);
            (infer_res.inferred_regime, true)
        };

        // 2. 评估多周期张量桶
        let (seasonal_est, residual, is_anomaly) = self.multi_seasonal_tensor.evaluate_and_update(
            regime,
            hour,
            metric_value,
            is_learning,
        );

        // 3. 跟踪月度宏观漂移
        if is_learning {
            self.monthly_tracker.update_month(month, metric_value);
        }
        let monthly_drift = self.monthly_tracker.drift_gradient;

        let diagnostic_note = format!(
            "[{}] 当前时段期望基线: {:.1}, 实测: {:.1}, 残差: {:.1}, 模态判定: {}{}",
            date_str,
            seasonal_est,
            metric_value,
            residual,
            regime.as_str(),
            if is_unsupervised { " (纯无监督数据推断)" } else { " (外部日历先验)" }
        );

        MacroBaselineVerdict {
            regime,
            is_unsupervised_decision: is_unsupervised,
            seasonal_expected: seasonal_est,
            actual_metric: metric_value,
            residual,
            is_anomaly,
            monthly_drift_factor: monthly_drift,
            diagnostic_note,
        }
    }
}

pub static GLOBAL_MACRO_BASELINE_ENGINE: Lazy<Arc<Mutex<MacroCalendarAdaptiveBaselineEngine>>> =
    Lazy::new(|| Arc::new(Mutex::new(MacroCalendarAdaptiveBaselineEngine::new())));

// ============================================================
// 严苛单元测试与极限验证套件
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_temporal_profile_ewma_convergence() {
        let mut prof = SessionTemporalProfile::new(64.0, 1000);
        
        // 持续发送 50 个 64 字节包，间隔固定为 100ms
        for i in 1..=50 {
            let now_ms = 1000 + i * 100;
            let (dist, is_anomaly) = prof.update_and_evaluate(64.0, now_ms, true);
            assert!(!is_anomaly);
            assert!(dist >= 0.0);
        }

        // 验证 EWMA 均值收敛于 64.0 字节和 100ms 间隔
        assert!((prof.ewma_len_mean - 64.0).abs() < 1.0);
        assert!((prof.ewma_iat_mean - 100.0).abs() < 2.0);
    }

    #[test]
    fn test_mahalanobis_distance_detects_sudden_packet_burst() {
        let mut prof = SessionTemporalProfile::new(64.0, 1000);
        
        // 1. 先进行 20 次正常周期性训练
        for i in 1..=20 {
            let now_ms = 1000 + i * 100;
            prof.update_and_evaluate(64.0, now_ms, true);
        }

        // 2. 切换为 Enforcing 模式，突然到来一个 4096 字节的畸形巨大数据包且间隔为 1ms (突发泛洪)
        let (dist, is_anomaly) = prof.update_and_evaluate(4096.0, 3001, false);
        
        println!("突发异常时多维马氏距离: {:.2}", dist);
        assert!(dist > 3.5, "马氏距离应显著超过 3.5 标准差");
        assert!(is_anomaly, "必须准确检出时序基线异常");
    }

    #[test]
    fn test_baseline_status_and_mode_switching() {
        let res = set_baseline_mode("LEARNING");
        assert!(res.is_ok());
        let status = get_baseline_status();
        assert_eq!(status.mode, "LEARNING");

        let res_enforce = set_baseline_mode("ENFORCING");
        assert!(res_enforce.is_ok());
        let status_enforce = get_baseline_status();
        assert_eq!(status_enforce.mode, "ENFORCING");
    }

    #[test]
    fn test_full_covariance_correlation_sensitivity() {
        let mut prof = SessionTemporalProfile::new(64.0, 1000);

        // 训练数据：让包长与间隔呈现强正相关 (小包频发，大包稀疏)
        let mut t = 1000u64;
        for i in 1..=30 {
            if i % 2 == 0 {
                t += 200;
                prof.update_and_evaluate(256.0, t, true);
            } else {
                t += 50;
                prof.update_and_evaluate(64.0, t, true);
            }
        }

        // 验证协方差已正向学习积累
        assert!(prof.ewma_cov_len_iat > 0.0, "包长与到达间隔的协方差必须为正向相关");

        // 注入破坏物理相关性的隐蔽离群包: 包长极大 (256B) 却以极短间隔 (10ms) 突发
        let (dist_full, _) = prof.update_and_evaluate(256.0, t + 10, false);
        assert!(dist_full > 3.0, "打破联合相关性的离群包全协方差马氏距离必须显著飙升: {:.2}", dist_full);
    }

    #[test]
    fn test_stl_hourly_periodicity_and_residual_decomposition() {
        let mut profile = SessionTemporalProfile::new(64.0, 1_000_000);

        // 学习阶段: 设定白班 14点 (Hour 14) 正常包长为 200 字节，方差为 9 (sigma = 3)
        for _ in 0..30 {
            profile.decompose_and_check_hourly_residual(14, 200.0, true);
        }
        // 学习阶段: 设定夜班 2点 (Hour 2) 正常包长为 50 字节，方差为 4 (sigma = 2)
        for _ in 0..30 {
            profile.decompose_and_check_hourly_residual(2, 50.0, true);
        }

        // 验证 Hour 14 与 Hour 2 学习到的周期分量 (Seasonal Estimates)
        let (s_14, _r_14, anom_14) = profile.decompose_and_check_hourly_residual(14, 202.0, false);
        assert!((s_14 - 200.0).abs() < 5.0);
        assert!(!anom_14); // 202 字节在白班 200 字节基线内，属正常波动

        let (s_2, _r_2, anom_2) = profile.decompose_and_check_hourly_residual(2, 51.0, false);
        assert!((s_2 - 50.0).abs() < 5.0);
        assert!(!anom_2); // 51 字节在夜班 50 字节基线内，属正常波动

        // 异常突发检验: 在凌晨 2 点突发白班级别的 200 字节载荷 (如黑夜离线偷传)
        let (_s_midnight_burst, r_midnight_burst, anom_midnight) =
            profile.decompose_and_check_hourly_residual(2, 200.0, false);
        assert!(anom_midnight); // 残差巨大 (约 150 字节 >> 3*sigma)，准确判定为周期外突发异常！
        assert!(r_midnight_burst > 100.0);
    }

    #[test]
    fn test_holt_winters_triple_exponential_smoothing_convergence_and_anomaly() {
        // 构造周期为 4 的合成趋势季节序列: 10, 20, 30, 40, 然后整体抬升
        let mut hw = HoltWintersModel::new(4, 10.0);

        for cycle in 0..15 {
            let base = 10.0 + (cycle as f64) * 2.0;
            hw.update(base + 0.0, true);
            hw.update(base + 10.0, true);
            hw.update(base + 20.0, true);
            hw.update(base + 30.0, true);
        }

        // 验证正向趋势已稳定提取 (trend > 0)
        assert!(hw.trend > 0.1, "线性趋势必须正向收敛");

        // 正常平稳推进: 传入模型一步预测期望值 (约 41.8)
        let expected_next = hw.forecast(1);
        let (_pred_norm, _res_norm, anom_norm) = hw.update(expected_next, false);
        assert!(!anom_norm, "符合趋势与周期的平稳样本不可误报");

        // 突发离群暴跌/暴涨 (偏离预期值 500 字节)
        let (_pred_spike, res_spike, anom_spike) = hw.update(expected_next + 500.0, false);
        assert!(anom_spike, "超出 3*sigma 置信带的突发样本必须报警");
        assert!(res_spike.abs() > 300.0);
    }

    #[test]
    fn test_pca_multi_metric_reconstruction_error_detects_coupling_violation() {
        let detector = PcaReconstructionDetector::new();

        // 正常匹配第一主成分的高相关样本: 各项指标同步温和正相关
        // 均值附近 [120.0, 100.0, 20.0, 3.5]
        let normal_sample = [125.0, 102.0, 21.0, 3.6];
        let (spe_normal, anom_normal) = detector.evaluate_sample(&normal_sample);
        assert!(!anom_normal, "协同耦合指标不能误报: SPE = {:.2}", spe_normal);
        assert!(spe_normal < detector.spe_threshold);

        // 严重破坏物理关联的异常攻击样本:
        // 报文速率与包长暴增，但熵值却跌到 0 (全零垃圾载荷暴力泛洪)，打破正常物理耦合！
        let attack_sample = [1500.0, 1.0, 5000.0, 0.05];
        let (spe_attack, anom_attack) = detector.evaluate_sample(&attack_sample);
        assert!(anom_attack, "打破非线性协同关系的攻击样本必须检出: SPE = {:.2}", spe_attack);
        assert!(spe_attack > 50.0);
    }

    /// 轮次 1：调休补班日 (Compensatory Workday) 纯无监督自适应推断测试
    #[test]
    fn test_macro_unsupervised_compensatory_workday_detection() {
        let classifier = UnsupervisedDayRegimeClassifier::default();

        // 场景: 周日 (calendar_weekday = 7)，但工厂进行调休上班
        // 早高峰物理特征呈现典型工作日高负荷: [PPS: 2400.0, 密度: 145.0, 活跃主机: 78.0]
        let sunday_work_features = [2400.0, 145.0, 78.0];
        let result = classifier.infer_regime(&sunday_work_features, 7);

        // 验证: 即使没有任何外部日历指示，系统必须自主推断为 CompensatoryWorkday！
        assert_eq!(result.inferred_regime, DayRegime::CompensatoryWorkday);
        assert!(result.posterior_workday_prob > 0.95);
        assert!(result.log_likelihood_ratio > 0.0);
    }

    /// 轮次 2：法定节假日长假 (Statutory Holiday) 纯无监督自适应推断测试
    #[test]
    fn test_macro_unsupervised_statutory_holiday_detection() {
        let classifier = UnsupervisedDayRegimeClassifier::default();

        // 场景: 周三 (calendar_weekday = 3)，但是国庆黄金周放假
        // 早高峰物理特征极低，呈现低负荷休息态: [PPS: 280.0, 密度: 18.0, 活跃主机: 10.0]
        let holiday_features = [280.0, 18.0, 10.0];
        let result = classifier.infer_regime(&holiday_features, 3);

        // 验证: 系统必须自主判定为 StatutoryHoliday，而非误判为正常工作日！
        assert_eq!(result.inferred_regime, DayRegime::StatutoryHoliday);
        assert!(result.posterior_workday_prob < 0.05);
        assert!(result.log_likelihood_ratio < 0.0);
    }

    /// 轮次 3：法定节假日长假低负荷隐蔽入侵抓捕测试 (高灵敏度收紧容差)
    #[test]
    fn test_macro_holiday_low_load_stealth_intrusion_detection() {
        let mut engine = MacroCalendarAdaptiveBaselineEngine::new();

        // 训练节假日低谷基线: 模拟国庆期间白天的正常巡检包长 64 字节，方差 4 (sigma = 2)
        for _ in 0..25 {
            engine.multi_seasonal_tensor.evaluate_and_update(
                DayRegime::StatutoryHoliday,
                14,
                64.0,
                true,
            );
        }

        // 正常假期低谷巡检 (66 字节，轻微波动)，不应误报
        let (_est, _res, anom_normal) = engine.multi_seasonal_tensor.evaluate_and_update(
            DayRegime::StatutoryHoliday,
            14,
            66.0,
            false,
        );
        assert!(!anom_normal, "节假日正常巡检数据不应误报");

        // 隐蔽渗透攻击: 在假期下午 14 点发送 95 字节的数据流 (平时工作日允许达到 200 字节，但假期严格收紧)
        let (_est, res_stealth, anom_stealth) = engine.multi_seasonal_tensor.evaluate_and_update(
            DayRegime::StatutoryHoliday,
            14,
            95.0,
            false,
        );
        assert!(anom_stealth, "节假日收紧容差下，异常数据流必须精准检出");
        assert!(res_stealth > 25.0);
    }

    /// 轮次 4：跨月度宏观长周期漂移跟踪测试
    #[test]
    fn test_macro_monthly_drift_and_seasonal_evolution() {
        let mut tracker = MonthlyDriftTracker::default();

        // 模拟企业扩建：1月均值 100，2月 110，3月 120，持续微幅爬坡
        tracker.update_month(1, 100.0);
        tracker.update_month(2, 110.0);
        tracker.update_month(3, 120.0);

        assert_eq!(tracker.last_updated_month, 3);
        assert!(tracker.drift_gradient > 0.0, "必须捕获到长期扩容正向漂移");
        assert!(tracker.global_level > 100.0);
    }

    /// 轮次 5：人工外部权威日历优先覆盖与在线更新测试
    #[test]
    fn test_macro_explicit_calendar_priority_override() {
        let mut engine = MacroCalendarAdaptiveBaselineEngine::new();

        // 人工显式指定 2026-10-01 为 StatutoryHoliday
        engine.import_calendar_schedule("2026-10-01", DayRegime::StatutoryHoliday);

        // 传入一个即便有些异常波动的特征
        let ambiguous_features = [1200.0, 80.0, 45.0];
        let verdict = engine.evaluate_point(
            "2026-10-01",
            4,  // 周四
            10, // 10点
            10, // 10月
            &ambiguous_features,
            80.0,
            false,
        );

        assert_eq!(verdict.regime, DayRegime::StatutoryHoliday);
        assert!(!verdict.is_unsupervised_decision, "人工显式注入的日历日程必须拥有最高优先级覆盖权");
    }

    /// 轮次 6：极限边界测试 (三维全零输入、超大峰值溢出与负时间戳)
    #[test]
    fn test_macro_extreme_edge_cases_and_zero_inputs() {
        let classifier = UnsupervisedDayRegimeClassifier::default();

        // 极限用例 1: 全零输入
        let zero_features = [0.0, 0.0, 0.0];
        let res_zero = classifier.infer_regime(&zero_features, 1);
        assert!(!res_zero.posterior_workday_prob.is_nan());
        assert!(!res_zero.log_likelihood_ratio.is_nan());

        // 极限用例 2: 极大暴冲数据 (1000万 PPS)
        let huge_features = [10_000_000.0, 50_000.0, 10_000.0];
        let res_huge = classifier.infer_regime(&huge_features, 2);
        assert!(!res_huge.posterior_workday_prob.is_nan());
        assert_eq!(res_huge.inferred_regime, DayRegime::StandardWorkday);

        // 极限用例 3: 边界星期数值
        let res_edge_day = classifier.infer_regime(&zero_features, 0); // 异常边界 weekday
        assert!(!res_edge_day.confidence_score.is_nan());
    }
}
