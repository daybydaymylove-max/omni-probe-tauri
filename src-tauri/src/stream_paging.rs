// ============================================================
// 工业全能网络探针 - 高性能流式分页缓冲与分卷落盘引擎
// 模块名称: stream_paging.rs
//
// 核心职责与工程规范:
// 1. 对标 Wireshark dumpcap / Sniffnet 工业级流量解耦架构;
// 2. 遥测传输与明细拉取彻底分离 (IPC Decoupling):
//    - 遥测指标 (PPS / 带宽 / 丢包 / 活跃流) 采用高频节流广播 (Throttle Broadcast);
//    - 数据明细采用虚拟视口惰性分页 (Lazy Paging by Viewport), 彻底根除前端 UI 渲染卡死;
// 3. 有界内存控制与分卷滚动持久化 (Rolling Segment Persistence):
//    - 环形缓冲区上限严格控制 (默认 100,000 帧), 超限自动触发异步后台分卷落盘;
//    - 分卷落盘支持标准司法级 PCAPng 格式, 保障证据链完整性;
// 4. 算法复杂度: 分页查询时间复杂度 O(K) (K 为请求的页大小, 如 50~100 帧),
//    单包压入时间复杂度 O(1), 空间复杂度严格有界 O(MaxFrames).
// ============================================================

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::sniffer::PacketRecord;
use crate::export_engine::export_to_pcapng;

/// 默认最大内存驻留报文帧数 (防止内存无节制膨胀)
pub const DEFAULT_MAX_BUFFERED_PACKETS: usize = 100_000;
/// 默认单卷分卷落盘触发阈值 (50,000 帧自动滚动分卷)
pub const DEFAULT_SEGMENT_FLUSH_THRESHOLD: usize = 50_000;

/// 分页查询响应结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagedPacketsResponse {
    pub total_captured: usize,
    pub current_buffered: usize,
    pub offset: usize,
    pub limit: usize,
    pub returned_count: usize,
    pub records: Vec<PacketRecord>,
}

/// 缓冲池实时运行度量
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamBufferStats {
    pub total_captured: u64,
    pub current_buffered: usize,
    pub max_capacity: usize,
    pub flushed_segments_count: usize,
    pub last_flush_time: String,
    pub last_packet_time: String,
}

/// 流式报文分页环形缓冲池
pub struct StreamPagingBuffer {
    records: VecDeque<PacketRecord>,
    max_capacity: usize,
    flush_threshold: usize,
    total_captured: u64,
    flushed_segments_count: usize,
    last_flush_time: String,
    last_packet_time: String,
}

impl StreamPagingBuffer {
    pub fn new(max_capacity: usize, flush_threshold: usize) -> Self {
        Self {
            records: VecDeque::with_capacity(max_capacity.min(10_000)),
            max_capacity,
            flush_threshold,
            total_captured: 0,
            flushed_segments_count: 0,
            last_flush_time: "从未落盘".into(),
            last_packet_time: "暂无数据".into(),
        }
    }

    /// 压入一条新捕获的数据报文帧
    /// 时间复杂度: O(1)
    pub fn push_packet(&mut self, record: PacketRecord) -> Option<Vec<PacketRecord>> {
        self.total_captured += 1;
        self.last_packet_time = record.timestamp.clone();
        self.records.push_back(record);

        // 检查是否达到分卷滚动落盘阈值
        if self.records.len() >= self.flush_threshold {
            // 切割前半段待分卷持久化数据 (释放内存容量)
            let flush_count = self.flush_threshold / 2;
            let mut segment_to_flush = Vec::with_capacity(flush_count);
            for _ in 0..flush_count {
                if let Some(r) = self.records.pop_front() {
                    segment_to_flush.push(r);
                }
            }
            self.flushed_segments_count += 1;
            self.last_flush_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            return Some(segment_to_flush);
        }

        // 若超出了物理硬上限，淘汰最旧的帧
        if self.records.len() > self.max_capacity {
            self.records.pop_front();
        }

        None
    }

    /// 视口惰性按需分页拉取
    /// 时间复杂度: O(limit)
    pub fn fetch_page(&self, offset: usize, limit: usize) -> PagedPacketsResponse {
        let current_buffered = self.records.len();
        let total_captured = self.total_captured as usize;

        if offset >= current_buffered || limit == 0 {
            return PagedPacketsResponse {
                total_captured,
                current_buffered,
                offset,
                limit,
                returned_count: 0,
                records: Vec::new(),
            };
        }

        let end = (offset + limit).min(current_buffered);
        let mut paged = Vec::with_capacity(end - offset);

        for i in offset..end {
            paged.push(self.records[i].clone());
        }

        let returned_count = paged.len();
        PagedPacketsResponse {
            total_captured,
            current_buffered,
            offset,
            limit,
            returned_count,
            records: paged,
        }
    }

    /// 获取缓冲池当前度量状态
    pub fn get_stats(&self) -> StreamBufferStats {
        StreamBufferStats {
            total_captured: self.total_captured,
            current_buffered: self.records.len(),
            max_capacity: self.max_capacity,
            flushed_segments_count: self.flushed_segments_count,
            last_flush_time: self.last_flush_time.clone(),
            last_packet_time: self.last_packet_time.clone(),
        }
    }

    /// 清空缓冲池
    pub fn clear(&mut self) {
        self.records.clear();
        self.total_captured = 0;
        self.flushed_segments_count = 0;
        self.last_flush_time = "已重置".into();
        self.last_packet_time = "已重置".into();
    }
}

/// 全局单例流式分页缓冲区
pub static GLOBAL_STREAM_BUFFER: Lazy<Arc<Mutex<StreamPagingBuffer>>> = Lazy::new(|| {
    Arc::new(Mutex::new(StreamPagingBuffer::new(
        DEFAULT_MAX_BUFFERED_PACKETS,
        DEFAULT_SEGMENT_FLUSH_THRESHOLD,
    )))
});

/// 压入报文并处理自动分卷持久化
pub fn buffer_packet_and_auto_flush(record: PacketRecord) {
    let segment_to_flush = {
        if let Ok(mut buf) = GLOBAL_STREAM_BUFFER.lock() {
            buf.push_packet(record)
        } else {
            None
        }
    };

    // 若触发了分卷落盘，在后台独立线程执行 PCAPng 结构化封装，不阻塞抓包主链路
    if let Some(segment) = segment_to_flush {
        std::thread::spawn(move || {
            let timestamp_str = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
            let seg_dir = crate::forensics::data_path("capture_segments");
            let _ = std::fs::create_dir_all(&seg_dir);
            let file_name = format!("segment_{}.pcapng", timestamp_str);
            let file_path = seg_dir.join(file_name);

            // 将 PacketRecord 转换为 PacketExportData
            let export_items: Vec<crate::export_engine::PacketExportData> = segment
                .into_iter()
                .map(|r| crate::export_engine::PacketExportData {
                    id: r.id,
                    timestamp: r.timestamp,
                    direction: r.direction,
                    transport: r.transport,
                    protocol: r.protocol,
                    src_ip: r.src_ip,
                    dst_ip: r.dst_ip,
                    src_port: r.src_port,
                    dst_port: r.dst_port,
                    length: r.length,
                    payload_hex: r.payload_hex,
                    entropy: r.entropy,
                    entropy_level: r.entropy_level,
                    mac_src: r.mac_src,
                    mac_dst: r.mac_dst,
                    chain_hash: r.chain_hash,
                    raw_text: r.raw_text,
                })
                .collect();

            let _ = export_to_pcapng(
                &export_items,
                &file_path.to_string_lossy(),
                "omni_rolling_segment",
            );
        });
    }
}

// ============================================================
// 严苛单元测试套件
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_dummy_packet(id: u64) -> PacketRecord {
        PacketRecord {
            id,
            timestamp: "12:00:00.000".to_string(),
            timestamp_ns: 1000,
            direction: "RX".to_string(),
            transport: "TCP".to_string(),
            protocol: "HTTP".to_string(),
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "192.168.1.1".to_string(),
            src_port: 12345,
            dst_port: 80,
            length: 64,
            payload_hex: "00010203".to_string(),
            raw_frame_hex: "00010203".to_string(),
            entropy: 2.5,
            entropy_level: "safe".to_string(),
            mac_src: "00:11:22:33:44:55".to_string(),
            mac_dst: "AA:BB:CC:DD:EE:FF".to_string(),
            chain_hash: "hash".to_string(),
            business_data: None,
            raw_text: Some("GET / HTTP/1.1".to_string()),
        }
    }

    #[test]
    fn test_stream_paging_window_and_slice() {
        let mut buf = StreamPagingBuffer::new(1000, 500);

        // 压入 100 条记录
        for i in 1..=100 {
            buf.push_packet(create_dummy_packet(i));
        }

        // 测试第 1 页: offset=0, limit=20
        let page1 = buf.fetch_page(0, 20);
        assert_eq!(page1.returned_count, 20);
        assert_eq!(page1.records.first().unwrap().id, 1);
        assert_eq!(page1.records.last().unwrap().id, 20);

        // 测试第 5 页: offset=80, limit=20
        let page5 = buf.fetch_page(80, 20);
        assert_eq!(page5.returned_count, 20);
        assert_eq!(page5.records.first().unwrap().id, 81);
        assert_eq!(page5.records.last().unwrap().id, 100);

        // 越界请求: offset=150, limit=20
        let page_out = buf.fetch_page(150, 20);
        assert_eq!(page_out.returned_count, 0);
        assert!(page_out.records.is_empty());
    }

    #[test]
    fn test_stream_paging_rolling_eviction() {
        // 设置 flush_threshold 为 10
        let mut buf = StreamPagingBuffer::new(20, 10);

        let mut flushed_any = false;
        for i in 1..=10 {
            if let Some(flushed) = buf.push_packet(create_dummy_packet(i)) {
                flushed_any = true;
                assert_eq!(flushed.len(), 5); // 弹出前半段 5 条
            }
        }

        assert!(flushed_any, "达到阈值必须触发分卷弹出");
        assert_eq!(buf.records.len(), 5); // 剩余 5 条
        assert_eq!(buf.total_captured, 10);
        assert_eq!(buf.flushed_segments_count, 1);
    }
}
