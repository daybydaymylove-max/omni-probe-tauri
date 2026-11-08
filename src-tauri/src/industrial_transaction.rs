// ==============================================================================
// 工业级 Omni-Probe - 工业控制事务双向配对追踪机与 Session 事件驱动总线
// 模块名称: industrial_transaction.rs
//
// 核心职责与工程规范 (严格对标 Zeek/Bro Industrial Transaction & Session Engine):
// 1. 工业事务双向配对机制 (Request-Response Pairing):
//    - 将离散网络报文升华为具有业务因果关联的“工业事务会话 (Industrial Transaction)”;
//    - 基于 (通信对 + 规约 + 事务ID + 从站单元号) 维护并发安全的待响应队列;
//    - 微秒级精确度计算 PLC 处理时延 (PLC Response Latency = T_resp - T_req);
// 2. 状态机自洽性与异常状态判定:
//    - 成功事务 (SUCCESS): 正常请求并取得有效响应;
//    - 业务异常 (EXCEPTION): 从站返回 Modbus 异常码 (0x81~0x90)、S7 错误代码等;
//    - 超时未决 (TIMEOUT): 超过设定的工控通信周期 (默认 2000ms) 未响应，定性为 PLC 假死或链路丢包;
// 3. 算法复杂度量化:
//    - 时间复杂度: 请求入队 O(1), 响应配对 O(1), 超时扫描 O(K) (K 为未完成活跃事务数);
//    - 空间复杂度: O(M) (最大待处理事务队列受限在 10,000 条, 内存预算恒定 <= 2MB);
// 4. 防御性编程: 严格覆盖序列号回绕、并发半开事务攻击与从站异常响应 3 类极限边界。
// ==============================================================================

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

/// 最大并发待配对事务队列容量 (防止半开事务攻击导致内存溢出)
pub const MAX_PENDING_TRANSACTIONS: usize = 10_000;

/// 默认工业请求超时阈值 (毫秒)
pub const DEFAULT_TRANSACTION_TIMEOUT_MS: u64 = 2_000;

/// 已完成归档的最大历史事务记录数 (供前端交互展示)
pub const MAX_COMPLETED_TRANSACTIONS_HISTORY: usize = 1_000;

/// 事务唯一哈希标识索引
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionPairKey {
    pub flow_key: String,       // 如 "192.168.1.10:54321<->192.168.1.20:502"
    pub protocol: String,       // "MODBUS" | "S7COMM" | "IEC104" | "DNP3"
    pub transaction_id: u32,    // 协议事务 ID (Modbus TransID / S7 ROSCTR Sequence)
    pub unit_id: u8,            // 目标从站单元号 (Unit ID / Station Addr)
}

/// 待响应的工业请求实体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingIndustrialRequest {
    pub req_packet_id: u64,
    pub timestamp_ns: u128,
    pub timestamp_str: String,
    pub function_code: u8,
    pub function_name: String,
    pub starting_address: Option<u32>,
    pub quantity: Option<u32>,
    pub is_write: bool,
    pub raw_request_hex: String,
}

/// 已闭环归档的工业控制事务 (对标 Zeek modbus.log / dnp3.log 结构)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedIndustrialTransaction {
    pub id: u64,
    pub flow_key: String,
    pub client_ip: String,
    pub server_ip: String,
    pub protocol: String,
    pub transaction_id: u32,
    pub unit_id: u8,
    pub function_code: u8,
    pub function_name: String,
    pub is_write: bool,
    pub req_packet_id: u64,
    pub resp_packet_id: Option<u64>,
    pub req_time: String,
    pub resp_time: Option<String>,
    pub plc_latency_ms: f64,      // 真实 PLC 往返与处理时延 (毫秒, 保留微秒精度)
    pub status: String,           // "SUCCESS" | "EXCEPTION" | "TIMEOUT"
    pub exception_code: Option<u8>,
    pub exception_desc: Option<String>,
    pub summary: String,
}

/// 工业事务统计度量快照
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransactionMetricsSnapshot {
    pub total_transactions_recorded: u64,
    pub successful_transactions: u64,
    pub exception_transactions: u64,
    pub timeout_transactions: u64,
    pub avg_plc_latency_ms: f64,
    pub max_plc_latency_ms: f64,
    pub min_plc_latency_ms: f64,
    pub active_pending_count: usize,
}

/// 工业事务双向配对追踪主引擎
pub struct IndustrialTransactionTracker {
    pending_map: HashMap<TransactionPairKey, PendingIndustrialRequest>,
    pending_fifo: VecDeque<(TransactionPairKey, u128)>, // 用于 LRU 顺序与超时淘汰
    completed_history: VecDeque<CompletedIndustrialTransaction>,
    next_transaction_id: u64,
    total_latency_accum_ms: f64,
    successful_count: u64,
    exception_count: u64,
    timeout_count: u64,
    max_latency_ms: f64,
    min_latency_ms: f64,
}

impl Default for IndustrialTransactionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl IndustrialTransactionTracker {
    pub fn new() -> Self {
        Self {
            pending_map: HashMap::with_capacity(1024),
            pending_fifo: VecDeque::with_capacity(1024),
            completed_history: VecDeque::with_capacity(MAX_COMPLETED_TRANSACTIONS_HISTORY),
            next_transaction_id: 1,
            total_latency_accum_ms: 0.0,
            successful_count: 0,
            exception_count: 0,
            timeout_count: 0,
            max_latency_ms: 0.0,
            min_latency_ms: f64::MAX,
        }
    }

    /// 规范化生成无向对等通信流 Key (无论收发方向，确保配对 Key 唯一一致)
    pub fn normalize_flow_key(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> String {
        if src_ip < dst_ip || (src_ip == dst_ip && src_port <= dst_port) {
            format!("{}:{}<->{}:{}", src_ip, src_port, dst_ip, dst_port)
        } else {
            format!("{}:{}<->{}:{}", dst_ip, dst_port, src_ip, src_port)
        }
    }

    /// 捕获并记录发向 PLC 从站的控制/查询请求帧
    ///
    /// 时间复杂度: O(1)
    pub fn record_request(
        &mut self,
        flow_key: String,
        protocol: String,
        transaction_id: u32,
        unit_id: u8,
        req_packet_id: u64,
        timestamp_ns: u128,
        timestamp_str: String,
        function_code: u8,
        function_name: String,
        starting_address: Option<u32>,
        quantity: Option<u32>,
        is_write: bool,
        raw_request_hex: String,
    ) {
        let key = TransactionPairKey {
            flow_key,
            protocol,
            transaction_id,
            unit_id,
        };

        let req = PendingIndustrialRequest {
            req_packet_id,
            timestamp_ns,
            timestamp_str,
            function_code,
            function_name,
            starting_address,
            quantity,
            is_write,
            raw_request_hex,
        };

        // 容量溢出防御: 若超出 MAX_PENDING_TRANSACTIONS，基于 FIFO 淘汰最老待配对条目
        if self.pending_map.len() >= MAX_PENDING_TRANSACTIONS {
            if let Some((old_key, _)) = self.pending_fifo.pop_front() {
                self.pending_map.remove(&old_key);
            }
        }

        self.pending_fifo.push_back((key.clone(), timestamp_ns));
        self.pending_map.insert(key, req);
    }

    /// 捕获从站响应帧并执行微秒级双向事务闭环配对
    ///
    /// 参数:
    /// - `is_exception`: 从站是否返回了工控异常功能码 (如 0x80 | FC)
    /// - `exception_code`: 具体的从站异常代码 (如 0x01 非法功能码 / 0x02 非法数据地址)
    ///
    /// 时间复杂度: O(1)
    pub fn record_response(
        &mut self,
        flow_key: &str,
        client_ip: &str,
        server_ip: &str,
        protocol: &str,
        transaction_id: u32,
        unit_id: u8,
        resp_packet_id: u64,
        resp_time_ns: u128,
        resp_time_str: String,
        is_exception: bool,
        exception_code: Option<u8>,
    ) -> Option<CompletedIndustrialTransaction> {
        let key = TransactionPairKey {
            flow_key: flow_key.to_string(),
            protocol: protocol.to_string(),
            transaction_id,
            unit_id,
        };

        // 从待配对哈希表中取出请求实体
        let req = match self.pending_map.remove(&key) {
            Some(r) => r,
            None => {
                // 孤立响应 (可能请求发生在探针启动前，或序列号已被驱逐)
                return None;
            }
        };

        // 精确计算 PLC 往返处理延迟 (毫秒, 保留微秒精度)
        let latency_ns = if resp_time_ns >= req.timestamp_ns {
            resp_time_ns - req.timestamp_ns
        } else {
            0
        };
        let latency_ms = (latency_ns as f64) / 1_000_000.0;

        let status = if is_exception {
            "EXCEPTION".to_string()
        } else {
            "SUCCESS".to_string()
        };

        let exception_desc = exception_code.map(|ec| Self::describe_modbus_exception(ec));

        let summary = if is_exception {
            format!(
                "{} 从站 #{} 异常响应 (延迟 {:.3}ms): 异常码 0x{:02X} - {}",
                protocol, unit_id, latency_ms, exception_code.unwrap_or(0), exception_desc.as_deref().unwrap_or("未知异常")
            )
        } else {
            format!(
                "{} 从站 #{} 事务完成 (耗时 {:.3}ms): {} [功能码 0x{:02X}]",
                protocol, unit_id, latency_ms, req.function_name, req.function_code
            )
        };

        // 更新度量指标
        if is_exception {
            self.exception_count += 1;
        } else {
            self.successful_count += 1;
        }
        self.total_latency_accum_ms += latency_ms;
        self.max_latency_ms = self.max_latency_ms.max(latency_ms);
        self.min_latency_ms = self.min_latency_ms.min(latency_ms);

        let completed = CompletedIndustrialTransaction {
            id: self.next_transaction_id,
            flow_key: flow_key.to_string(),
            client_ip: client_ip.to_string(),
            server_ip: server_ip.to_string(),
            protocol: protocol.to_string(),
            transaction_id,
            unit_id,
            function_code: req.function_code,
            function_name: req.function_name,
            is_write: req.is_write,
            req_packet_id: req.req_packet_id,
            resp_packet_id: Some(resp_packet_id),
            req_time: req.timestamp_str,
            resp_time: Some(resp_time_str),
            plc_latency_ms: latency_ms,
            status,
            exception_code,
            exception_desc,
            summary,
        };

        self.next_transaction_id += 1;

        // 维护前端历史展示队列 (最大 1,000 条)
        if self.completed_history.len() >= MAX_COMPLETED_TRANSACTIONS_HISTORY {
            self.completed_history.pop_front();
        }
        self.completed_history.push_back(completed.clone());

        Some(completed)
    }

    /// 扫描并结算超时未决事务 (用于周期性保活与超时告警)
    ///
    /// 参数:
    /// - `current_time_ns`: 当前纳秒单调时钟
    /// - `timeout_threshold_ms`: 超时判定阈值 (毫秒)
    ///
    /// 复杂度: O(K), K 为活跃待决请求数
    pub fn sweep_timeouts(
        &mut self,
        current_time_ns: u128,
        timeout_threshold_ms: u64,
    ) -> Vec<CompletedIndustrialTransaction> {
        let timeout_ns = (timeout_threshold_ms as u128) * 1_000_000;
        let mut timed_out_transactions = Vec::new();

        while let Some(&(ref _key, req_time_ns)) = self.pending_fifo.front() {
            if current_time_ns > req_time_ns && (current_time_ns - req_time_ns) >= timeout_ns {
                // 超时确认
                let (expired_key, _) = self.pending_fifo.pop_front().unwrap();
                if let Some(req) = self.pending_map.remove(&expired_key) {
                    self.timeout_count += 1;
                    let latency_ms = timeout_threshold_ms as f64;

                    let summary = format!(
                        "{} 从站 #{} 请求超时未响应 (>{}ms): {} [请求包 #{}]",
                        expired_key.protocol, expired_key.unit_id, timeout_threshold_ms, req.function_name, req.req_packet_id
                    );

                    let timed_out = CompletedIndustrialTransaction {
                        id: self.next_transaction_id,
                        flow_key: expired_key.flow_key,
                        client_ip: "CLIENT".into(),
                        server_ip: "PLC_SERVER".into(),
                        protocol: expired_key.protocol,
                        transaction_id: expired_key.transaction_id,
                        unit_id: expired_key.unit_id,
                        function_code: req.function_code,
                        function_name: req.function_name,
                        is_write: req.is_write,
                        req_packet_id: req.req_packet_id,
                        resp_packet_id: None,
                        req_time: req.timestamp_str,
                        resp_time: None,
                        plc_latency_ms: latency_ms,
                        status: "TIMEOUT".to_string(),
                        exception_code: None,
                        exception_desc: Some("PLC 从站超时未应答 / 通信链路阻断".to_string()),
                        summary,
                    };

                    self.next_transaction_id += 1;
                    if self.completed_history.len() >= MAX_COMPLETED_TRANSACTIONS_HISTORY {
                        self.completed_history.pop_front();
                    }
                    self.completed_history.push_back(timed_out.clone());
                    timed_out_transactions.push(timed_out);
                }
            } else {
                // FIFO 头部尚未超时，后续条目必然未超时，直接安全退出
                break;
            }
        }

        timed_out_transactions
    }

    /// 获取最近完成的工业事务历史记录 (供前端表格与时延瀑布流展示)
    pub fn get_recent_transactions(&self, limit: usize) -> Vec<CompletedIndustrialTransaction> {
        let count = limit.min(self.completed_history.len());
        self.completed_history.iter().rev().take(count).cloned().collect()
    }

    /// 提取工业事务全景统计快照
    pub fn get_metrics_snapshot(&self) -> TransactionMetricsSnapshot {
        let total_closed = self.successful_count + self.exception_count + self.timeout_count;
        let avg_latency = if self.successful_count + self.exception_count > 0 {
            self.total_latency_accum_ms / ((self.successful_count + self.exception_count) as f64)
        } else {
            0.0
        };

        TransactionMetricsSnapshot {
            total_transactions_recorded: total_closed,
            successful_transactions: self.successful_count,
            exception_transactions: self.exception_count,
            timeout_transactions: self.timeout_count,
            avg_plc_latency_ms: avg_latency,
            max_plc_latency_ms: self.max_latency_ms,
            min_plc_latency_ms: if self.min_latency_ms == f64::MAX { 0.0 } else { self.min_latency_ms },
            active_pending_count: self.pending_map.len(),
        }
    }

    /// Modbus 标准异常响应代码汉化字典映射
    fn describe_modbus_exception(code: u8) -> String {
        match code {
            0x01 => "ILLEGAL_FUNCTION (从站不支持此功能码)".to_string(),
            0x02 => "ILLEGAL_DATA_ADDRESS (寄存器起始地址越界/不存在)".to_string(),
            0x03 => "ILLEGAL_DATA_VALUE (写入寄存器数值超出合法范围)".to_string(),
            0x04 => "SLAVE_DEVICE_FAILURE (从站 PLC 硬件内部致命故障)".to_string(),
            0x05 => "ACKNOWLEDGE (从站已接收正忙，需长周期执行)".to_string(),
            0x06 => "SLAVE_DEVICE_BUSY (从站正在处理前序长命令，请重试)".to_string(),
            0x08 => "MEMORY_PARITY_ERROR (从站内存奇偶校验校验错误)".to_string(),
            0x0A => "GATEWAY_PATH_UNAVAILABLE (网关路径不可达)".to_string(),
            0x0B => "GATEWAY_TARGET_DEVICE_FAILED (网关下挂目标从站无响应)".to_string(),
            _ => format!("UNKNOWN_MODBUS_EXCEPTION_0x{:02X}", code),
        }
    }
}

/// 全局常驻工业事务追踪器单例
pub static GLOBAL_TRANSACTION_TRACKER: Lazy<Arc<Mutex<IndustrialTransactionTracker>>> =
    Lazy::new(|| Arc::new(Mutex::new(IndustrialTransactionTracker::new())));

// =============================================================================
// 单元测试与对标 Zeek 的客观对齐验证 (Unit Tests & Zeek Alignment)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modbus_standard_request_response_pairing() {
        let mut tracker = IndustrialTransactionTracker::new();
        let flow_key = IndustrialTransactionTracker::normalize_flow_key("192.168.1.100", 54321, "192.168.1.200", 502);

        // 1. 模拟在 T = 1,000,000,000 ns 发送 Modbus 读保持寄存器请求 (FC=0x03, TransID=0x0001, UnitID=1)
        tracker.record_request(
            flow_key.clone(),
            "MODBUS".into(),
            1,
            1,
            101,
            1_000_000_000,
            "12:00:00.000".into(),
            0x03,
            "Read Holding Registers".into(),
            Some(100),
            Some(10),
            false,
            "00010000000601030064000a".into(),
        );

        let snap = tracker.get_metrics_snapshot();
        assert_eq!(snap.active_pending_count, 1, "必须准确维护 1 条未决事务");

        // 2. 模拟从站 PLC 在 4.5ms (4,500,000 ns) 后返回正常响应
        let resp_time_ns = 1_004_500_000;
        let completed = tracker.record_response(
            &flow_key,
            "192.168.1.100",
            "192.168.1.200",
            "MODBUS",
            1,
            1,
            102,
            resp_time_ns,
            "12:00:00.004".into(),
            false,
            None,
        ).expect("必须成功完成双向事务配对");

        assert_eq!(completed.status, "SUCCESS");
        assert_eq!(completed.req_packet_id, 101);
        assert_eq!(completed.resp_packet_id, Some(102));
        assert!((completed.plc_latency_ms - 4.5).abs() < 0.001, "PLC 延迟计算必须达到微秒级精确度 (实际: {})", completed.plc_latency_ms);

        let snap_after = tracker.get_metrics_snapshot();
        assert_eq!(snap_after.successful_transactions, 1);
        assert_eq!(snap_after.active_pending_count, 0, "配对完成后待响应队列必须归零");
    }

    #[test]
    fn test_modbus_exception_response_pairing() {
        let mut tracker = IndustrialTransactionTracker::new();
        let flow_key = "192.168.1.100:54321<->192.168.1.200:502".to_string();

        // 请求尝试写入未授权寄存器 (FC=0x06, TransID=0x0002, UnitID=1)
        tracker.record_request(
            flow_key.clone(),
            "MODBUS".into(),
            2,
            1,
            201,
            2_000_000_000,
            "12:01:00.000".into(),
            0x06,
            "Write Single Register".into(),
            Some(9999),
            Some(1),
            true,
            "0002000000060106270f0001".into(),
        );

        // 从站返回 0x86 (0x80 | 0x06) 异常响应，异常码 0x02 (ILLEGAL_DATA_ADDRESS)
        let completed = tracker.record_response(
            &flow_key,
            "192.168.1.100",
            "192.168.1.200",
            "MODBUS",
            2,
            1,
            202,
            2_002_100_000,
            "12:01:00.002".into(),
            true,
            Some(0x02),
        ).expect("必须配对异常事务");

        assert_eq!(completed.status, "EXCEPTION");
        assert_eq!(completed.exception_code, Some(0x02));
        assert!(completed.exception_desc.unwrap().contains("ILLEGAL_DATA_ADDRESS"));
        assert!(completed.summary.contains("异常码 0x02"));

        let snap = tracker.get_metrics_snapshot();
        assert_eq!(snap.exception_transactions, 1);
    }

    #[test]
    fn test_transaction_timeout_sweep() {
        let mut tracker = IndustrialTransactionTracker::new();
        let flow_key = "192.168.1.100:54321<->192.168.1.200:502".to_string();

        // 注入在 T = 1,000,000,000 ns 的请求
        tracker.record_request(
            flow_key.clone(),
            "MODBUS".into(),
            3,
            1,
            301,
            1_000_000_000,
            "12:02:00.000".into(),
            0x01,
            "Read Coils".into(),
            Some(0),
            Some(8),
            false,
            "000300000006010100000008".into(),
        );

        // 在 T = 2,500,000,000 ns (经过 1500ms，未达 2000ms 阈值) 执行扫描
        let timed_out_1500 = tracker.sweep_timeouts(2_500_000_000, 2000);
        assert_eq!(timed_out_1500.len(), 0, "未超阈值时不应发生超时截断");

        // 在 T = 3_500_000_000 ns (经过 2500ms，超过 2000ms 阈值) 执行扫描
        let timed_out_2500 = tracker.sweep_timeouts(3_500_000_000, 2000);
        assert_eq!(timed_out_2500.len(), 1, "超过阈值必须判定为 TIMEOUT 事务");
        assert_eq!(timed_out_2500[0].status, "TIMEOUT");
        assert_eq!(timed_out_2500[0].resp_packet_id, None);
        assert!(timed_out_2500[0].summary.contains("超时未响应"));

        let snap = tracker.get_metrics_snapshot();
        assert_eq!(snap.timeout_transactions, 1);
        assert_eq!(snap.active_pending_count, 0);
    }

    #[test]
    fn test_transaction_sequence_wraparound_resilience() {
        let mut tracker = IndustrialTransactionTracker::new();
        let flow_key = "192.168.1.100:54321<->192.168.1.200:502".to_string();

        // 模拟序列号回绕: 先发 0xFFFF (65535)，再发 0x0001
        tracker.record_request(
            flow_key.clone(), "MODBUS".into(), 65535, 1, 401, 10_000_000_000, "12:03:00.000".into(),
            0x03, "Read".into(), None, None, false, "".into(),
        );
        tracker.record_request(
            flow_key.clone(), "MODBUS".into(), 1, 1, 402, 10_001_000_000, "12:03:00.001".into(),
            0x03, "Read".into(), None, None, false, "".into(),
        );

        assert_eq!(tracker.get_metrics_snapshot().active_pending_count, 2);

        // 回绕响应分别到达
        let comp1 = tracker.record_response(&flow_key, "192.168.1.100", "192.168.1.200", "MODBUS", 65535, 1, 403, 10_002_000_000, "12:03:00.002".into(), false, None).unwrap();
        assert_eq!(comp1.transaction_id, 65535);

        let comp2 = tracker.record_response(&flow_key, "192.168.1.100", "192.168.1.200", "MODBUS", 1, 1, 404, 10_003_000_000, "12:03:00.003".into(), false, None).unwrap();
        assert_eq!(comp2.transaction_id, 1);

        assert_eq!(tracker.get_metrics_snapshot().active_pending_count, 0);
    }
}
