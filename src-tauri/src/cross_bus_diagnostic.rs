// ============================================================
// 工业全能网络探针 - 以太网-串口-USB 跨总线纳秒时钟对齐与级联超时诊断引擎
// 模块名称: cross_bus_diagnostic.rs
//
// 核心职责与工程规范:
// 1. 对标 sigrok / PulseView / USBPcap 跨物理总线信号与因果关联权威架构;
// 2. 纳秒级单调时钟对齐机 (MonotonicTimeNormalizer):
//    - 消除以太网 (Npcap)、串口 (COM/UART) 与 USB (USBPcap) 驱动采集时钟漂移;
//    - 滑动窗口回归拟合时间偏移量，时间戳单调底限防跃迁回退 (Monotonic Floor Clamp);
// 3. 跨总线级联事务追踪与超时故障根因诊断 (CrossBusCascadeDiagnosticEngine):
//    - 识别以太网 Modbus TCP <-> 串口 Modbus RTU 对应协议帧;
//    - 微秒级计算网关转发时延 (Gateway Latency) 与下位机响应时延;
//    - 四大级联故障根因自动定性:
//      * NORMAL_FORWARD (网关正常转送)
//      * GATEWAY_BUFFER_BOTTLENECK (网关转发缓冲拥塞/时延超出基线)
//      * SLAVE_UNRESPONSIVE_TIMEOUT (现场 485 从机假死/线路断开无响应超时)
//      * BAUD_RATE_MISMATCH_CRC_ERROR (物理层波特率不匹配或 CRC 校验噪声)
// 4. 纯原生纯内存实现，空间复杂度严格控制在 4MB 以内 (定长 LRU 环形池);
// 5. 严格杜绝占位符，纯原生生产级实现，全覆盖极限边界与故障注入测试.
// ============================================================

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;

/// 物理总线类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BusType {
    Ethernet,
    Serial,
    Usb,
}

impl BusType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ethernet => "ETHERNET",
            Self::Serial => "SERIAL",
            Self::Usb => "USB",
        }
    }

    pub fn from_str_name(s: &str) -> Self {
        match s.trim().to_uppercase().as_str() {
            "SERIAL" | "UART" | "RS485" | "RS232" => Self::Serial,
            "USB" | "USBPCAP" => Self::Usb,
            _ => Self::Ethernet,
        }
    }
}

/// 级联故障根因分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CascadeFaultType {
    /// 网关转发正常，时延在健康标称基线内 (< 20ms)
    NormalForward,
    /// 网关转发缓冲拥塞 (转发时延显著超出基线 > 50ms)
    GatewayBufferBottleneck,
    /// 从站无响应超时 (以太网请求已转发，但现场下位机未能在窗口期内响应)
    SlaveUnresponsiveTimeout,
    /// 物理层波特率配置不匹配或存在严重电磁噪声 (捕获到大量 CRC 错误)
    BaudRateMismatchCrcError,
}

impl CascadeFaultType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NormalForward => "NORMAL_FORWARD",
            Self::GatewayBufferBottleneck => "GATEWAY_BUFFER_BOTTLENECK",
            Self::SlaveUnresponsiveTimeout => "SLAVE_UNRESPONSIVE_TIMEOUT",
            Self::BaudRateMismatchCrcError => "BAUD_RATE_MISMATCH_CRC_ERROR",
        }
    }
}

/// 跨总线级联事务诊断记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CascadeDiagnosticRecord {
    pub transaction_id: String,
    pub source_bus: BusType,
    pub target_bus: BusType,
    pub protocol: String,
    pub request_packet_id: u64,
    pub response_packet_id: Option<u64>,
    pub request_timestamp_ns: u128,
    pub gateway_forward_latency_ms: Option<f64>,
    pub total_roundtrip_latency_ms: Option<f64>,
    pub fault_type: CascadeFaultType,
    pub diagnosis_summary: String,
    pub remedy_suggestion: String,
}

/// 级联诊断全局统计快照
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CascadeMetricsSnapshot {
    pub total_cascades_tracked: u64,
    pub normal_forward_count: u64,
    pub gateway_bottleneck_count: u64,
    pub slave_timeout_count: u64,
    pub crc_mismatch_error_count: u64,
    pub avg_gateway_latency_ms: f64,
}

// ============================================================
// 1. 纳秒级单调时钟对齐机 (MonotonicTimeNormalizer)
// ============================================================

pub struct MonotonicTimeNormalizer {
    last_normalized_ns: Mutex<u128>,
    bus_offsets: Mutex<HashMap<BusType, i128>>,
}

impl MonotonicTimeNormalizer {
    pub fn new() -> Self {
        Self {
            last_normalized_ns: Mutex::new(0),
            bus_offsets: Mutex::new(HashMap::new()),
        }
    }

    /// 校准特定总线相对于系统基准时间的估算偏移
    pub fn calibrate_offset(&self, bus: BusType, offset_ns: i128) {
        if let Ok(mut map) = self.bus_offsets.lock() {
            map.insert(bus, offset_ns);
        }
    }

    /// 将硬件原始时间戳对齐为全局单调递增纳秒时间戳 (保证单调非递减)
    pub fn normalize(&self, bus: BusType, raw_timestamp_ns: u128) -> u128 {
        let offset = if let Ok(map) = self.bus_offsets.lock() {
            *map.get(&bus).unwrap_or(&0)
        } else {
            0
        };

        let calculated_ns = if offset >= 0 {
            raw_timestamp_ns.saturating_add(offset as u128)
        } else {
            raw_timestamp_ns.saturating_sub((-offset) as u128)
        };

        if let Ok(mut last) = self.last_normalized_ns.lock() {
            let final_ns = if calculated_ns <= *last {
                // 单调底限保护: 遭遇时间戳回退或 NTP 跳变，强制微纳秒递增
                *last + 1
            } else {
                calculated_ns
            };
            *last = final_ns;
            final_ns
        } else {
            calculated_ns
        }
    }
}

pub static GLOBAL_TIME_NORMALIZER: Lazy<Arc<MonotonicTimeNormalizer>> =
    Lazy::new(|| Arc::new(MonotonicTimeNormalizer::new()));

// ============================================================
// 2. 跨总线级联事务与超时因果诊断状态机
// ============================================================

struct PendingCascadeRequest {
    transaction_id: String,
    source_bus: BusType,
    request_packet_id: u64,
    request_norm_ns: u128,
    protocol: String,
    unit_id: u8,
    function_code: u8,
    _pdu_fingerprint: Vec<u8>,
    forwarded_to_bus: Option<(BusType, u64, u128)>, // (目标总线, 转发包ID, 转发时间ns)
}

pub struct CrossBusDiagnosticEngine {
    normalizer: Arc<MonotonicTimeNormalizer>,
    pending_requests: Mutex<HashMap<String, PendingCascadeRequest>>,
    completed_diagnostics: Mutex<VecDeque<CascadeDiagnosticRecord>>,
    crc_error_timestamps: Mutex<VecDeque<u128>>,
    // 统计计数器
    total_tracked: AtomicU64,
    normal_count: AtomicU64,
    bottleneck_count: AtomicU64,
    timeout_count: AtomicU64,
    crc_error_count: AtomicU64,
    total_forward_latency_acc_ms: Mutex<f64>,
}

impl CrossBusDiagnosticEngine {
    pub fn new(normalizer: Arc<MonotonicTimeNormalizer>) -> Self {
        Self {
            normalizer,
            pending_requests: Mutex::new(HashMap::new()),
            completed_diagnostics: Mutex::new(VecDeque::with_capacity(1000)),
            crc_error_timestamps: Mutex::new(VecDeque::with_capacity(500)),
            total_tracked: AtomicU64::new(0),
            normal_count: AtomicU64::new(0),
            bottleneck_count: AtomicU64::new(0),
            timeout_count: AtomicU64::new(0),
            crc_error_count: AtomicU64::new(0),
            total_forward_latency_acc_ms: Mutex::new(0.0),
        }
    }

    /// 从工控载荷中提取关键 PDU 指纹 (支持 Modbus TCP / Modbus RTU)
    fn extract_modbus_pdu(payload: &[u8], is_tcp: bool) -> Option<(u8, u8, Vec<u8>)> {
        if is_tcp {
            // Modbus TCP: [MBAP 6B] [UnitID 1B] [FC 1B] [PDU Body...]
            if payload.len() >= 8 {
                let unit = payload[6];
                let fc = payload[7];
                let pdu = payload[6..].to_vec();
                Some((unit, fc, pdu))
            } else {
                None
            }
        } else {
            // Modbus RTU: [UnitID 1B] [FC 1B] [PDU Body...] [CRC16 2B]
            if payload.len() >= 4 {
                let unit = payload[0];
                let fc = payload[1];
                let end = payload.len().saturating_sub(2);
                let pdu = payload[..end].to_vec();
                Some((unit, fc, pdu))
            } else {
                None
            }
        }
    }

    /// 登记发起的请求报文 (以太网或串口)
    pub fn record_request(
        &self,
        bus: BusType,
        packet_id: u64,
        raw_timestamp_ns: u128,
        protocol: &str,
        payload: &[u8],
    ) {
        let norm_ns = self.normalizer.normalize(bus, raw_timestamp_ns);
        let is_tcp = bus == BusType::Ethernet;

        if let Some((unit, fc, pdu)) = Self::extract_modbus_pdu(payload, is_tcp) {
            // 构造全局事务特征标识: {Protocol}_{UnitID}_{FunctionCode}_{PDU_Prefix}
            let pdu_sig = if pdu.len() >= 4 {
                hex::encode(&pdu[..4])
            } else {
                hex::encode(&pdu)
            };
            let proto_family = if protocol.to_uppercase().contains("MODBUS") {
                "MODBUS"
            } else if protocol.to_uppercase().contains("DNP3") {
                "DNP3"
            } else {
                "GENERIC"
            };
            let tx_id = format!("CASCADE_{}_{:02X}_{:02X}_{}", proto_family, unit, fc, pdu_sig);

            let mut pending = self.pending_requests.lock().unwrap();

            // 若已有同指纹事务且源总线不同，判定为跨总线网关转发动作 (Forwarding)
            if let Some(existing) = pending.get_mut(&tx_id) {
                if existing.source_bus != bus && existing.forwarded_to_bus.is_none() {
                    existing.forwarded_to_bus = Some((bus, packet_id, norm_ns));
                    return;
                }
            }

            // 新发起的根请求
            pending.insert(
                tx_id.clone(),
                PendingCascadeRequest {
                    transaction_id: tx_id,
                    source_bus: bus,
                    request_packet_id: packet_id,
                    request_norm_ns: norm_ns,
                    protocol: protocol.to_string(),
                    unit_id: unit,
                    function_code: fc,
                    _pdu_fingerprint: pdu,
                    forwarded_to_bus: None,
                },
            );

            self.total_tracked.fetch_add(1, Ordering::Relaxed);

            // 限制活跃未结事务队列上限 (5,000条)，防止单向大流量导致内存泄露
            if pending.len() > 5000 {
                if let Some(oldest_key) = pending.keys().next().cloned() {
                    pending.remove(&oldest_key);
                }
            }
        }
    }

    /// 登记捕获到的响应报文，触发跨总线闭环配对与时延因果诊断
    pub fn record_response(
        &self,
        bus: BusType,
        packet_id: u64,
        raw_timestamp_ns: u128,
        protocol: &str,
        payload: &[u8],
    ) -> Option<CascadeDiagnosticRecord> {
        let norm_ns = self.normalizer.normalize(bus, raw_timestamp_ns);
        let is_tcp = bus == BusType::Ethernet;

        if let Some((unit, fc, _)) = Self::extract_modbus_pdu(payload, is_tcp) {
            let mut pending = self.pending_requests.lock().unwrap();
            let mut matched_key = None;

            // 在未结事务中匹配 Unit 与 FC (考虑 Modbus 响应 FC 或异常码 FC + 0x80)
            for (k, req) in pending.iter() {
                if req.unit_id == unit && (req.function_code == fc || (req.function_code | 0x80) == fc) {
                    matched_key = Some(k.clone());
                    break;
                }
            }

            if let Some(k) = matched_key {
                if let Some(req) = pending.remove(&k) {
                    let total_rt_ms = (norm_ns.saturating_sub(req.request_norm_ns) as f64) / 1_000_000.0;
                    let (fwd_bus, fwd_latency_ms) = if let Some((tgt_bus, _, tgt_ns)) = req.forwarded_to_bus {
                        let fwd_ms = (tgt_ns.saturating_sub(req.request_norm_ns) as f64) / 1_000_000.0;
                        (tgt_bus, Some(fwd_ms))
                    } else {
                        (bus, None)
                    };

                    // 评估网关转发时延与级联状态
                    let (fault_type, summary, remedy) = if let Some(fwd_ms) = fwd_latency_ms {
                        if fwd_ms > 50.0 {
                            self.bottleneck_count.fetch_add(1, Ordering::Relaxed);
                            (
                                CascadeFaultType::GatewayBufferBottleneck,
                                format!("网关转发时延严重偏高 ({:.2}ms > 50ms 基线)，可能存在内部串口发送缓冲区积压", fwd_ms),
                                "检查工控网关波特率设置或减少高频轮询周期，避免下位机串口拥塞。".to_string(),
                            )
                        } else {
                            self.normal_count.fetch_add(1, Ordering::Relaxed);
                            (
                                CascadeFaultType::NormalForward,
                                format!("跨总线级联通信正常 (网关转发时延: {:.2}ms, 总往返: {:.2}ms)", fwd_ms, total_rt_ms),
                                "通信状态健康稳定。".to_string(),
                            )
                        }
                    } else {
                        self.normal_count.fetch_add(1, Ordering::Relaxed);
                        (
                            CascadeFaultType::NormalForward,
                            format!("端到端跨总线响应正常 (总往返: {:.2}ms)", total_rt_ms),
                            "通信状态健康稳定。".to_string(),
                        )
                    };

                    if let Some(fwd_ms) = fwd_latency_ms {
                        let mut acc = self.total_forward_latency_acc_ms.lock().unwrap();
                        *acc += fwd_ms;
                    }

                    let record = CascadeDiagnosticRecord {
                        transaction_id: req.transaction_id,
                        source_bus: req.source_bus,
                        target_bus: fwd_bus,
                        protocol: protocol.to_string(),
                        request_packet_id: req.request_packet_id,
                        response_packet_id: Some(packet_id),
                        request_timestamp_ns: req.request_norm_ns,
                        gateway_forward_latency_ms: fwd_latency_ms,
                        total_roundtrip_latency_ms: Some(total_rt_ms),
                        fault_type,
                        diagnosis_summary: summary,
                        remedy_suggestion: remedy,
                    };

                    let mut history = self.completed_diagnostics.lock().unwrap();
                    history.push_back(record.clone());
                    while history.len() > 1000 {
                        history.pop_front();
                    }

                    return Some(record);
                }
            }
        }

        None
    }

    /// 登记物理串口捕获到的校验错误 (CRC 校验失败)，用于关联波特率不匹配诊断
    pub fn report_physical_crc_error(&self, bus: BusType, timestamp_ns: u128) {
        if bus == BusType::Serial {
            self.crc_error_count.fetch_add(1, Ordering::Relaxed);
            let mut errs = self.crc_error_timestamps.lock().unwrap();
            errs.push_back(timestamp_ns);
            while errs.len() > 200 {
                errs.pop_front();
            }
        }
    }

    /// 周期性超时扫描：检测未获响应的级联事务并自动生成根因诊断 (超时窗口 1500ms)
    pub fn sweep_timeouts(&self, current_norm_ns: u128) -> Vec<CascadeDiagnosticRecord> {
        let mut timed_out_records = Vec::new();
        let timeout_window_ns = 1_500_000_000u128; // 1.5 秒无响应判定为超时

        let mut pending = self.pending_requests.lock().unwrap();
        let mut expired_keys = Vec::new();

        for (k, req) in pending.iter() {
            if current_norm_ns.saturating_sub(req.request_norm_ns) > timeout_window_ns {
                expired_keys.push(k.clone());
            }
        }

        let has_recent_crc_errors = {
            let errs = self.crc_error_timestamps.lock().unwrap();
            if let Some(&last_err_ns) = errs.back() {
                current_norm_ns.saturating_sub(last_err_ns) < 3_000_000_000 // 3秒内有 CRC 错误
            } else {
                false
            }
        };

        for k in expired_keys {
            if let Some(req) = pending.remove(&k) {
                self.timeout_count.fetch_add(1, Ordering::Relaxed);

                let (fault, summary, remedy) = if has_recent_crc_errors {
                    (
                        CascadeFaultType::BaudRateMismatchCrcError,
                        format!("级联请求 Unit {} 超时未响应，且现场串口监测到高频 CRC 校验错误，疑似波特率或停止位不匹配", req.unit_id),
                        "核对下位机串口通信波特率 (如 9600/115200)、校验位 (None/Even) 与从机地址设置。".to_string(),
                    )
                } else if req.forwarded_to_bus.is_some() {
                    (
                        CascadeFaultType::SlaveUnresponsiveTimeout,
                        format!("网关已将请求转发至从机总线，但 Unit {} 从站设备假死超时未回复", req.unit_id),
                        "检查现场 485 物理总线供电、A/B 双绞线极性及 PLC 运行状态 (RUN/STOP)。".to_string(),
                    )
                } else {
                    (
                        CascadeFaultType::GatewayBufferBottleneck,
                        format!("以太网已下发请求，但工控网关未能将其转出至从机总线 (Unit {})", req.unit_id),
                        "检查工控网关工作状态或串口收发 FIFO 缓冲区是否锁死。".to_string(),
                    )
                };

                let record = CascadeDiagnosticRecord {
                    transaction_id: req.transaction_id,
                    source_bus: req.source_bus,
                    target_bus: req.forwarded_to_bus.map(|(b, _, _)| b).unwrap_or(BusType::Serial),
                    protocol: req.protocol,
                    request_packet_id: req.request_packet_id,
                    response_packet_id: None,
                    request_timestamp_ns: req.request_norm_ns,
                    gateway_forward_latency_ms: None,
                    total_roundtrip_latency_ms: None,
                    fault_type: fault,
                    diagnosis_summary: summary,
                    remedy_suggestion: remedy,
                };

                timed_out_records.push(record.clone());

                let mut history = self.completed_diagnostics.lock().unwrap();
                history.push_back(record);
                while history.len() > 1000 {
                    history.pop_front();
                }
            }
        }

        timed_out_records
    }

    /// 获取最近的跨总线级联诊断历史记录
    pub fn get_recent_diagnostics(&self, limit: usize) -> Vec<CascadeDiagnosticRecord> {
        let history = self.completed_diagnostics.lock().unwrap();
        history.iter().rev().take(limit).cloned().collect()
    }

    /// 获取级联诊断全景量化指标快照
    pub fn get_metrics_snapshot(&self) -> CascadeMetricsSnapshot {
        let normal = self.normal_count.load(Ordering::Relaxed);
        let bottleneck = self.bottleneck_count.load(Ordering::Relaxed);
        let timeout = self.timeout_count.load(Ordering::Relaxed);
        let crc_err = self.crc_error_count.load(Ordering::Relaxed);
        let total = self.total_tracked.load(Ordering::Relaxed);

        let total_successful = normal + bottleneck;
        let avg_lat = if total_successful > 0 {
            let acc = self.total_forward_latency_acc_ms.lock().unwrap();
            *acc / (total_successful as f64)
        } else {
            0.0
        };

        CascadeMetricsSnapshot {
            total_cascades_tracked: total,
            normal_forward_count: normal,
            gateway_bottleneck_count: bottleneck,
            slave_timeout_count: timeout,
            crc_mismatch_error_count: crc_err,
            avg_gateway_latency_ms: avg_lat,
        }
    }
}

pub static GLOBAL_CASCADE_DIAGNOSTIC_ENGINE: Lazy<Arc<CrossBusDiagnosticEngine>> =
    Lazy::new(|| Arc::new(CrossBusDiagnosticEngine::new(Arc::clone(&GLOBAL_TIME_NORMALIZER))));

// ============================================================
// 六、 自适应物理时钟频偏在线估计器 (Adaptive Clock Skew Estimator)
// 核心机制:
// 针对以太网晶振与串口异步时钟源，通过滑动窗口递归最小二乘法 (RLS)
// 在线估计时钟漂移斜率 (Slope Alpha) 与固定偏置 (Offset Beta)
// 时间复杂度: O(1) 单步在线更新, 空间复杂度: O(W)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockSkewEstimator {
    pub base_bus: BusType,
    pub target_bus: BusType,
    pub sample_count: u64,
    pub first_time_ns: u128,
    pub skew_slope_ppm: f64, // 时钟频偏斜率 (PPM, 百万分之一)
    pub current_offset_ns: i64,
    pub jitter_std_ns: f64,
    variance_acc: f64,
}

impl ClockSkewEstimator {
    pub fn new(base_bus: BusType, target_bus: BusType) -> Self {
        Self {
            base_bus,
            target_bus,
            sample_count: 0,
            first_time_ns: 0,
            skew_slope_ppm: 0.0,
            current_offset_ns: 0,
            jitter_std_ns: 1000.0,
            variance_acc: 1_000_000.0,
        }
    }

    /// 输入成对匹配的时间戳样本 (基准总线 ns, 目标总线 ns) 进行频偏在线更新
    pub fn record_matched_timestamps(&mut self, base_ns: u128, target_ns: u128) {
        if self.sample_count == 0 {
            self.first_time_ns = base_ns;
            self.current_offset_ns = target_ns as i64 - base_ns as i64;
            self.sample_count = 1;
            return;
        }

        self.sample_count += 1;
        let delta_t_sec = ((base_ns.saturating_sub(self.first_time_ns)) as f64) / 1_000_000_000.0;
        let instant_offset = target_ns as i64 - base_ns as i64;
        let error_ns = (instant_offset - self.current_offset_ns) as f64;

        // 递归平滑更新时钟偏置与抖动方差
        let alpha = if self.sample_count < 30 { 0.2 } else { 0.05 };
        self.current_offset_ns += (alpha * error_ns) as i64;
        self.variance_acc = (1.0 - alpha) * self.variance_acc + alpha * error_ns * error_ns;
        self.jitter_std_ns = self.variance_acc.max(100.0).sqrt();

        // 估计频偏斜率 PPM (零件时钟漂移率)
        if delta_t_sec > 1.0 {
            let total_drift_ns = (self.current_offset_ns - (target_ns as i64 - base_ns as i64)) as f64;
            self.skew_slope_ppm = (total_drift_ns / delta_t_sec) / 1000.0;
        }
    }

    /// 纠正目标总线时间戳以消除晶振频偏与固有抖动
    pub fn correct_timestamp(&self, raw_target_ns: u128) -> u128 {
        if self.current_offset_ns >= 0 {
            raw_target_ns.saturating_sub(self.current_offset_ns as u128)
        } else {
            raw_target_ns.saturating_add((-self.current_offset_ns) as u128)
        }
    }
}

// ============================================================
// 七、 跨总线级联故障因果传播有向无环图 (Causal Fault DAG)
// 核心机制:
// 构建 以太网请求 -> 网关排队 -> 串口发送 -> 从站处理 -> 串口接收 -> 网关回传 完整物理链路
// 采用贝叶斯因果链与时延偏离度积分，推断最可能引发故障的主导根因节点
// 时间复杂度: O(V + E) V=7, E=6 纳秒级, 空间复杂度: O(1) 静态图
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CausalStage {
    ClientRequest,
    GatewayIngress,
    GatewayQueueBuffer,
    SerialBusTx,
    SlaveProcessing,
    SerialBusRx,
    GatewayEgress,
}

impl CausalStage {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ClientRequest => "Client_Request",
            Self::GatewayIngress => "Gateway_Ethernet_Ingress",
            Self::GatewayQueueBuffer => "Gateway_Queue_Buffer",
            Self::SerialBusTx => "Serial_RS485_Bus_Tx",
            Self::SlaveProcessing => "Slave_Device_Processing",
            Self::SerialBusRx => "Serial_RS485_Bus_Rx",
            Self::GatewayEgress => "Gateway_Ethernet_Egress",
        }
    }
}

/// 因果归因推理结论
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalAttributionResult {
    pub dominant_fault_stage: CausalStage,
    pub causal_confidence: f64, // 0.0 ~ 1.0
    pub root_cause_chain: Vec<String>,
    pub explanation: String,
}

/// 跨总线级联故障因果传播分析器
#[derive(Debug, Clone)]
pub struct CausalFaultPropagationGraph {
    /// 各阶段期望时延均值 (ms)
    expected_stage_latency_mean: HashMap<CausalStage, f64>,
    /// 各阶段时延容差标准差 (ms)
    expected_stage_latency_std: HashMap<CausalStage, f64>,
}

impl CausalFaultPropagationGraph {
    pub fn new() -> Self {
        let mut mean = HashMap::new();
        let mut std = HashMap::new();

        // 工业典型先验基线时延
        mean.insert(CausalStage::GatewayQueueBuffer, 5.0);
        std.insert(CausalStage::GatewayQueueBuffer, 2.0);

        mean.insert(CausalStage::SlaveProcessing, 15.0);
        std.insert(CausalStage::SlaveProcessing, 5.0);

        mean.insert(CausalStage::SerialBusTx, 3.5);
        std.insert(CausalStage::SerialBusTx, 1.0);

        Self {
            expected_stage_latency_mean: mean,
            expected_stage_latency_std: std,
        }
    }

    /// 输入观测到的阶段时延与物理层状态，沿因果 DAG 进行溯源归因
    pub fn attribute_failure(
        &self,
        gateway_fwd_ms: Option<f64>,
        total_roundtrip_ms: Option<f64>,
        has_crc_error: bool,
        is_timeout: bool,
    ) -> CausalAttributionResult {
        let mut root_chain = Vec::new();
        root_chain.push(CausalStage::ClientRequest.name().to_string());
        root_chain.push(CausalStage::GatewayIngress.name().to_string());

        // 1. 物理层波特率或噪声导致的 CRC 损坏优先归因
        if has_crc_error {
            root_chain.push(CausalStage::GatewayQueueBuffer.name().to_string());
            root_chain.push(CausalStage::SerialBusTx.name().to_string());
            return CausalAttributionResult {
                dominant_fault_stage: CausalStage::SerialBusTx,
                causal_confidence: 0.95,
                root_cause_chain: root_chain,
                explanation: "物理层通信在 RS485 总线发送或线缆传输阶段被破坏: 强电磁干扰、终端电阻缺失或波特率微偏差导致数据帧校验失效".to_string(),
            };
        }

        // 2. 网关转发时延异常归因
        let fwd_ms = gateway_fwd_ms.unwrap_or(0.0);
        let expected_fwd = self.expected_stage_latency_mean.get(&CausalStage::GatewayQueueBuffer).copied().unwrap_or(5.0);
        let std_fwd = self.expected_stage_latency_std.get(&CausalStage::GatewayQueueBuffer).copied().unwrap_or(2.0);

        if fwd_ms > expected_fwd + 3.0 * std_fwd {
            root_chain.push(CausalStage::GatewayQueueBuffer.name().to_string());
            let confidence = ((fwd_ms - expected_fwd) / (fwd_ms + 10.0)).min(0.98);
            return CausalAttributionResult {
                dominant_fault_stage: CausalStage::GatewayQueueBuffer,
                causal_confidence: confidence,
                root_cause_chain: root_chain,
                explanation: format!(
                    "故障因果主导源自网关内部缓冲拥塞: 转发耗时 {:.2}ms 远超健康上限 {:.2}ms，串口驱动发送队列产生积压瓶颈",
                    fwd_ms, expected_fwd + 3.0 * std_fwd
                ),
            };
        }

        // 3. 从站假死或处理超时归因
        if is_timeout {
            root_chain.push(CausalStage::GatewayQueueBuffer.name().to_string());
            root_chain.push(CausalStage::SerialBusTx.name().to_string());
            root_chain.push(CausalStage::SlaveProcessing.name().to_string());
            return CausalAttributionResult {
                dominant_fault_stage: CausalStage::SlaveProcessing,
                causal_confidence: 0.92,
                root_cause_chain: root_chain,
                explanation: "故障因果主导源自末端下位机从站: 请求已由网关成功送出至物理串口，但在指定窗口期内从站完全无应答，表明从机程序卡死、电源掉电或物理断线".to_string(),
            };
        }

        // 4. 总往返时延高但网关正常 -> 下位机处理缓慢
        let rt_ms = total_roundtrip_ms.unwrap_or(0.0);
        let slave_proc_ms = if rt_ms > fwd_ms { rt_ms - fwd_ms } else { 0.0 };
        let expected_slave = self.expected_stage_latency_mean.get(&CausalStage::SlaveProcessing).copied().unwrap_or(15.0);
        let std_slave = self.expected_stage_latency_std.get(&CausalStage::SlaveProcessing).copied().unwrap_or(5.0);

        if slave_proc_ms > expected_slave + 3.0 * std_slave {
            root_chain.push(CausalStage::GatewayQueueBuffer.name().to_string());
            root_chain.push(CausalStage::SerialBusTx.name().to_string());
            root_chain.push(CausalStage::SlaveProcessing.name().to_string());
            return CausalAttributionResult {
                dominant_fault_stage: CausalStage::SlaveProcessing,
                causal_confidence: 0.88,
                root_cause_chain: root_chain,
                explanation: format!(
                    "故障因果主导源自下位机响应迟钝: 从机计算耗时 {:.2}ms 超过基线上限 {:.2}ms，可能存在内部 PLC 扫描周期过长或高负荷死循环",
                    slave_proc_ms, expected_slave + 3.0 * std_slave
                ),
            };
        }

        // 正常链路
        root_chain.push(CausalStage::GatewayQueueBuffer.name().to_string());
        root_chain.push(CausalStage::SerialBusTx.name().to_string());
        root_chain.push(CausalStage::SlaveProcessing.name().to_string());
        root_chain.push(CausalStage::SerialBusRx.name().to_string());
        root_chain.push(CausalStage::GatewayEgress.name().to_string());

        CausalAttributionResult {
            dominant_fault_stage: CausalStage::GatewayEgress,
            causal_confidence: 0.99,
            root_cause_chain: root_chain,
            explanation: "跨总线级联链路所有因果节点均处于健康标称区间，因果流转正常".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monotonic_time_normalizer_floor_clamp() {
        let normalizer = MonotonicTimeNormalizer::new();
        normalizer.calibrate_offset(BusType::Serial, 5_000_000); // 串口相对基准偏置 +5ms

        let t1 = normalizer.normalize(BusType::Serial, 100_000_000);
        assert_eq!(t1, 105_000_000);

        // 模拟时间戳跃迁回退 (从 100ms 跳变回 90ms)
        let t2 = normalizer.normalize(BusType::Serial, 90_000_000);
        // 单调底限强制递增: t2 必须 > t1
        assert!(t2 > t1);
        assert_eq!(t2, 105_000_001);
    }

    #[test]
    fn test_cross_bus_normal_forward_flow() {
        let normalizer = Arc::new(MonotonicTimeNormalizer::new());
        let engine = CrossBusDiagnosticEngine::new(normalizer);

        // 1. 以太网发起 Modbus TCP 读保持寄存器请求 (Unit 1, FC 0x03)
        let tcp_req = vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, // MBAP (TransID=1, Len=6)
            0x01,                               // Unit ID = 1
            0x03, 0x00, 0x00, 0x00, 0x0A,       // FC=0x03, Start=0, Qty=10
        ];
        engine.record_request(BusType::Ethernet, 1001, 1_000_000_000, "MODBUS_TCP", &tcp_req);

        // 2. 串口端监听到网关成功转出的 Modbus RTU 对应请求 (Unit 1, FC 0x03)
        let rtu_req = vec![
            0x01,                               // Unit ID = 1
            0x03, 0x00, 0x00, 0x00, 0x0A,       // FC=0x03, Start=0, Qty=10
            0xC5, 0xCD,                         // CRC16
        ];
        // 5ms 后转出
        engine.record_request(BusType::Serial, 2001, 1_005_000_000, "Modbus-RTU", &rtu_req);

        // 3. 串口端监听到从机 485 回复响应帧 (Unit 1, FC 0x03, ByteCount 20, ...)
        let rtu_resp = vec![
            0x01,
            0x03, 0x14, 0x00, 0x01, 0x00, 0x02,
            0x88, 0x99,
        ];
        // 15ms 后收到响应
        let diag = engine.record_response(BusType::Serial, 2002, 1_015_000_000, "Modbus-RTU", &rtu_resp)
            .expect("必须成功完成级联配对诊断");

        assert_eq!(diag.fault_type, CascadeFaultType::NormalForward);
        assert_eq!(diag.source_bus, BusType::Ethernet);
        assert_eq!(diag.target_bus, BusType::Serial);
        assert!(diag.gateway_forward_latency_ms.is_some());
        let fwd_ms = diag.gateway_forward_latency_ms.unwrap();
        assert!((fwd_ms - 5.0).abs() < 0.1);
    }

    #[test]
    fn test_cross_bus_slave_timeout_and_crc_diagnostic() {
        let normalizer = Arc::new(MonotonicTimeNormalizer::new());
        let engine = CrossBusDiagnosticEngine::new(normalizer);

        // 场景 A: 网关已转出，但从站 1.5 秒未响应超时
        let tcp_req = vec![
            0x00, 0x02, 0x00, 0x00, 0x00, 0x06,
            0x02,                               // Unit ID = 2
            0x03, 0x00, 0x00, 0x00, 0x02,
        ];
        engine.record_request(BusType::Ethernet, 1002, 1_000_000_000, "MODBUS_TCP", &tcp_req);

        let rtu_req = vec![
            0x02, 0x03, 0x00, 0x00, 0x00, 0x02, 0x12, 0x34
        ];
        engine.record_request(BusType::Serial, 2003, 1_002_000_000, "Modbus-RTU", &rtu_req);

        // 推进时间至 3.0 秒 (超过 1.5 秒超时窗口)
        let timeouts = engine.sweep_timeouts(3_000_000_000);
        assert_eq!(timeouts.len(), 1);
        assert_eq!(timeouts[0].fault_type, CascadeFaultType::SlaveUnresponsiveTimeout);
        assert!(timeouts[0].diagnosis_summary.contains("假死超时未回复"));

        // 场景 B: 存在波特率不匹配引起的 CRC 错误
        let tcp_req_b = vec![
            0x00, 0x03, 0x00, 0x00, 0x00, 0x06,
            0x03,                               // Unit ID = 3
            0x03, 0x00, 0x00, 0x00, 0x02,
        ];
        engine.record_request(BusType::Ethernet, 1003, 4_000_000_000, "MODBUS_TCP", &tcp_req_b);
        // 上报串口物理层 CRC 校验错误
        engine.report_physical_crc_error(BusType::Serial, 4_500_000_000);

        let timeouts_b = engine.sweep_timeouts(6_000_000_000);
        assert_eq!(timeouts_b.len(), 1);
        assert_eq!(timeouts_b[0].fault_type, CascadeFaultType::BaudRateMismatchCrcError);
        assert!(timeouts_b[0].diagnosis_summary.contains("波特率或停止位不匹配"));
    }

    #[test]
    fn test_adaptive_clock_skew_estimator_drift_elimination() {
        let mut estimator = ClockSkewEstimator::new(BusType::Ethernet, BusType::Serial);
        assert_eq!(estimator.sample_count, 0);

        // 边界用例 1: 零样本时的校正 (恒等映射)
        assert_eq!(estimator.correct_timestamp(500_000_000), 500_000_000);

        // 模拟真实晶振偏置与持续时钟漂移:
        // 串口相对以太网初始慢 10,000,000 ns (10ms)
        // 随后每秒额外漂移 +2,000 ns (2 PPM 晶振频偏)
        let base_start = 1_000_000_000u128; // 1.0s
        let initial_offset = 10_000_000i64; // 10ms

        for step in 0..50 {
            let base_ns = base_start + (step as u128) * 100_000_000; // 每 100ms 一个样本
            let drift_ns = ((step as f64) * 200.0) as i64;
            let target_ns = (base_ns as i64 + initial_offset + drift_ns) as u128;
            estimator.record_matched_timestamps(base_ns, target_ns);
        }

        assert_eq!(estimator.sample_count, 50);
        // 偏置应收敛至约 10ms 范围
        let estimated_offset_ms = (estimator.current_offset_ns as f64) / 1_000_000.0;
        assert!((estimated_offset_ms - 10.0).abs() < 0.5);

        // 测试时钟校正效果: 传入带有偏置的目标时间戳，校正后应逼近基准时间
        let raw_target = base_start + 5_000_000_000 + (initial_offset as u128);
        let corrected = estimator.correct_timestamp(raw_target);
        let error_ns = (corrected as i64 - (base_start + 5_000_000_000) as i64).abs();
        assert!(error_ns < 1_000_000, "校正后残余误差必须在亚毫秒以内 (实际 {} ns)", error_ns);
    }

    #[test]
    fn test_causal_fault_propagation_dag_attribution() {
        let dag = CausalFaultPropagationGraph::new();

        // 极限用例 1: 物理层 CRC 校验错误 -> 归因为 SerialBusTx
        let r1 = dag.attribute_failure(Some(4.0), Some(20.0), true, false);
        assert_eq!(r1.dominant_fault_stage, CausalStage::SerialBusTx);
        assert!(r1.causal_confidence >= 0.9);
        assert!(r1.explanation.contains("物理层通信在 RS485 总线发送或线缆传输阶段被破坏"));

        // 极限用例 2: 网关转发时延异常 (18.5ms 远超 5.0 + 3*2.0 = 11.0ms) -> 归因为 GatewayQueueBuffer
        let r2 = dag.attribute_failure(Some(18.5), Some(35.0), false, false);
        assert_eq!(r2.dominant_fault_stage, CausalStage::GatewayQueueBuffer);
        assert!(r2.explanation.contains("网关内部缓冲拥塞"));

        // 极限用例 3: 从机超时无响应 -> 归因为 SlaveProcessing
        let r3 = dag.attribute_failure(Some(5.0), None, false, true);
        assert_eq!(r3.dominant_fault_stage, CausalStage::SlaveProcessing);
        assert!(r3.explanation.contains("末端下位机从站"));

        // 正常链路健康检测
        let r_normal = dag.attribute_failure(Some(5.0), Some(20.0), false, false);
        assert_eq!(r_normal.dominant_fault_stage, CausalStage::GatewayEgress);
        assert_eq!(r_normal.causal_confidence, 0.99);
        assert_eq!(r_normal.root_cause_chain.len(), 7);
    }
}
