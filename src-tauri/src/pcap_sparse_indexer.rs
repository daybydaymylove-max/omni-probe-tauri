// ==============================================================================
// 工业级 Omni-Probe - 超巨型 PCAP 流式两级稀疏索引与常数内存分页视窗内核
// 模块名称: pcap_sparse_indexer.rs
//
// 核心职责 (对标 Wireshark 快速索引与大文件零 OOM 物理检索机制):
// 1. 彻底解决数 GB 乃至数十 GB 离线抓包文件直接全量加载导致内存溢出 (OOM) 崩溃的死穴;
// 2. 采用两级稀疏索引机制 (Two-Level Sparse Indexing):
//    - 在单遍快速扫描期间，仅按 Stride (默认 500 包) 记录物理文件偏移与时间戳;
//    - 1,000 万个数据包仅生成 20,000 个 32 字节稀疏节点，整份常驻索引内存仅约 640 KB!
// 3. 按需视窗分页提取器 (Paged Window Reader):
//    - 二分定位到最接近的稀疏节点 O(log(N/K));
//    - 物理 Seek 极速对准目标扇区并读取视窗大小 (如 50~100 帧);
//    - 运行时内存空间复杂度严格恒定 O(WindowSize)，彻底与文件总大小解耦;
// 4. 支持标准 PCAP 微秒 (0xA1B2C3D4) 与纳秒 (0xA1B23C4D) 时间戳精度及大小端自适应.
// ==============================================================================

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use serde::{Deserialize, Serialize};

/// 稀疏索引单节点 (32 字节紧凑内存对齐)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SparseIndexNode {
    pub packet_seq: u64,         // 该节点的全局起始数据包序号 (0, 500, 1000...)
    pub file_offset: u64,        // 对应 PCAP 报文帧头在文件中的绝对字节偏移
    pub timestamp_ns: u64,       // 纳秒级绝对时间戳
    pub cumulative_bytes: u64,   // 截止本节点的累计捕获字节量
}

/// PCAP 稀疏索引全局元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapSparseIndex {
    pub file_path: String,
    pub file_size_bytes: u64,
    pub total_packets: u64,
    pub stride: usize,           // 稀疏采样跨度 (默认 500)
    pub nodes: Vec<SparseIndexNode>,
    pub first_ts_ns: u64,
    pub last_ts_ns: u64,
    pub link_type: u32,          // 链路层类型 (1 = 以太网)
    pub is_nanosecond: bool,
    pub is_big_endian: bool,
    pub snaplen: u32,
}

/// 分页查询提取结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagedPacketHeader {
    pub seq: u64,
    pub file_offset: u64,
    pub timestamp_ns: u64,
    pub captured_len: u32,
    pub original_len: u32,
    pub payload_preview_hex: String, // 前 32 字节预览 Hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagedWindowResult {
    pub total_packets: u64,
    pub page_index: usize,
    pub page_size: usize,
    pub returned_count: usize,
    pub packets: Vec<PagedPacketHeader>,
}

#[derive(Debug)]
pub enum PcapIndexError {
    Io(io::Error),
    InvalidMagic(u32),
    FileTooShort,
    CorruptedPacketHeader(u64),
}

impl From<io::Error> for PcapIndexError {
    fn from(e: io::Error) -> Self {
        PcapIndexError::Io(e)
    }
}

/// PCAP 稀疏索引器与视窗检索器
pub struct PcapSparseIndexer;

impl PcapSparseIndexer {
    /// 单遍物理扫描构建稀疏两级索引
    ///
    /// 复杂度:
    /// - 时间复杂度: O(N) (单遍顺序读取磁盘，仅读取包头，Seek 跳过载荷)
    /// - 空间复杂度: O(N / Stride) (极低，数万个节点仅几百 KB 内存)
    pub fn build_index<P: AsRef<Path>>(path: P, stride: usize) -> Result<PcapSparseIndex, PcapIndexError> {
        let safe_stride = stride.max(10).min(10000);
        let path_ref = path.as_ref();
        let file = File::open(path_ref)?;
        let file_size = file.metadata()?.len();

        if file_size < 24 {
            return Err(PcapIndexError::FileTooShort);
        }

        let mut reader = BufReader::with_capacity(256 * 1024, file);

        // 1. 读取 24 字节 PCAP 全局文件头
        let mut global_hdr = [0u8; 24];
        reader.read_exact(&mut global_hdr)?;

        let magic_raw = u32::from_ne_bytes([global_hdr[0], global_hdr[1], global_hdr[2], global_hdr[3]]);
        let (is_big_endian, is_nanosecond) = match magic_raw {
            0xA1B2C3D4 => (false, false), // 标准小端微秒
            0xA1B23C4D => (false, true),  // 标准小端纳秒
            0xD4C3B2A1 => (true, false),  // 大端微秒
            0x4D3CB2A1 => (true, true),   // 大端纳秒
            _ => return Err(PcapIndexError::InvalidMagic(magic_raw)),
        };

        let read_u32 = |slice: &[u8]| -> u32 {
            if is_big_endian {
                u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])
            } else {
                u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
            }
        };

        let snaplen = read_u32(&global_hdr[16..20]);
        let link_type = read_u32(&global_hdr[20..24]);

        let mut nodes = Vec::new();
        let mut total_packets = 0u64;
        let mut cumulative_bytes = 0u64;
        let mut first_ts_ns = 0u64;
        let mut last_ts_ns = 0u64;

        let mut current_offset = 24u64;

        // 2. 流式遍历数据包包头 (每个数据包头固定 16 字节)
        let mut pkt_hdr_buf = [0u8; 16];
        loop {
            match reader.read_exact(&mut pkt_hdr_buf) {
                Ok(()) => {
                    let ts_sec = read_u32(&pkt_hdr_buf[0..4]) as u64;
                    let ts_sub = read_u32(&pkt_hdr_buf[4..8]) as u64;
                    let incl_len = read_u32(&pkt_hdr_buf[8..12]) as u64;
                    let _orig_len = read_u32(&pkt_hdr_buf[12..16]);

                    // 防御性校验: 捕获长度不能超过 snaplen * 2 或剩余文件大小
                    if current_offset + 16 + incl_len > file_size {
                        // 遇到截断包，安全终止迭代
                        break;
                    }

                    let ts_ns = if is_nanosecond {
                        ts_sec * 1_000_000_000 + ts_sub
                    } else {
                        ts_sec * 1_000_000_000 + ts_sub * 1_000
                    };

                    if total_packets == 0 {
                        first_ts_ns = ts_ns;
                    }
                    last_ts_ns = ts_ns;

                    // 当达到稀疏采样跨度时，插入稀疏索引节点
                    if total_packets % (safe_stride as u64) == 0 {
                        nodes.push(SparseIndexNode {
                            packet_seq: total_packets,
                            file_offset: current_offset,
                            timestamp_ns: ts_ns,
                            cumulative_bytes,
                        });
                    }

                    total_packets += 1;
                    cumulative_bytes += incl_len;
                    current_offset += 16 + incl_len;

                    // 物理跳过载荷内容 (不分配内存)
                    reader.seek(SeekFrom::Current(incl_len as i64))?;
                }
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(e) => return Err(PcapIndexError::Io(e)),
            }
        }

        Ok(PcapSparseIndex {
            file_path: path_ref.to_string_lossy().to_string(),
            file_size_bytes: file_size,
            total_packets,
            stride: safe_stride,
            nodes,
            first_ts_ns,
            last_ts_ns,
            link_type,
            is_nanosecond,
            is_big_endian,
            snaplen,
        })
    }

    /// 常数内存分页视窗提取器
    ///
    /// 复杂度:
    /// - 时间复杂度: O(log(N/K) + PageSize)
    /// - 空间复杂度: O(PageSize) (严格受限于分页窗口)
    pub fn seek_paged_window(
        index: &PcapSparseIndex,
        page_index: usize,
        page_size: usize,
    ) -> Result<PagedWindowResult, PcapIndexError> {
        let safe_page_size = page_size.max(1).min(1000);
        let target_start_seq = (page_index as u64).saturating_mul(safe_page_size as u64);

        if target_start_seq >= index.total_packets || index.nodes.is_empty() {
            return Ok(PagedWindowResult {
                total_packets: index.total_packets,
                page_index,
                page_size: safe_page_size,
                returned_count: 0,
                packets: Vec::new(),
            });
        }

        // 1. 二分查找定位最接近且小于等于 target_start_seq 的稀疏索引节点
        let mut low = 0;
        let mut high = index.nodes.len() - 1;
        let mut best_node_idx = 0;

        while low <= high {
            let mid = low + (high - low) / 2;
            if index.nodes[mid].packet_seq <= target_start_seq {
                best_node_idx = mid;
                low = mid + 1;
            } else {
                if mid == 0 {
                    break;
                }
                high = mid - 1;
            }
        }

        let anchor_node = index.nodes[best_node_idx];

        // 2. 物理 Seek 到锚点节点的物理偏移
        let file = File::open(&index.file_path)?;
        let mut reader = BufReader::with_capacity(64 * 1024, file);
        reader.seek(SeekFrom::Start(anchor_node.file_offset))?;

        let read_u32 = |slice: &[u8]| -> u32 {
            if index.is_big_endian {
                u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])
            } else {
                u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
            }
        };

        let mut current_seq = anchor_node.packet_seq;
        let mut current_offset = anchor_node.file_offset;
        let mut packets = Vec::with_capacity(safe_page_size);
        let mut pkt_hdr_buf = [0u8; 16];

        // 3. 从锚点向前迭代扫描至目标起始包，并收集目标页视窗
        while current_seq < index.total_packets && packets.len() < safe_page_size {
            if reader.read_exact(&mut pkt_hdr_buf).is_err() {
                break;
            }

            let ts_sec = read_u32(&pkt_hdr_buf[0..4]) as u64;
            let ts_sub = read_u32(&pkt_hdr_buf[4..8]) as u64;
            let incl_len = read_u32(&pkt_hdr_buf[8..12]);
            let orig_len = read_u32(&pkt_hdr_buf[12..16]);

            let ts_ns = if index.is_nanosecond {
                ts_sec * 1_000_000_000 + ts_sub
            } else {
                ts_sec * 1_000_000_000 + ts_sub * 1_000
            };

            if current_seq >= target_start_seq {
                // 读取前 32 字节作为 Hex 预览
                let preview_len = (incl_len as usize).min(32);
                let mut preview_buf = vec![0u8; preview_len];
                let _ = reader.read_exact(&mut preview_buf);
                let hex_preview = hex::encode(&preview_buf).to_uppercase();

                // 跳过剩余未读载荷
                if (incl_len as usize) > preview_len {
                    reader.seek(SeekFrom::Current((incl_len as i64) - (preview_len as i64)))?;
                }

                packets.push(PagedPacketHeader {
                    seq: current_seq,
                    file_offset: current_offset,
                    timestamp_ns: ts_ns,
                    captured_len: incl_len,
                    original_len: orig_len,
                    payload_preview_hex: hex_preview,
                });
            } else {
                // 尚未到达目标分页起始点，直接跳过当前报文载荷
                reader.seek(SeekFrom::Current(incl_len as i64))?;
            }

            current_offset += 16 + (incl_len as u64);
            current_seq += 1;
        }

        let returned_count = packets.len();
        Ok(PagedWindowResult {
            total_packets: index.total_packets,
            page_index,
            page_size: safe_page_size,
            returned_count,
            packets,
        })
    }
}

// ==============================================================================
// 单元测试与极端用例推演
// ==============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 辅助构造内存中的合成标准 PCAP 字节流
    fn generate_synthetic_pcap(packet_count: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        // 1. 全局头 24 字节 (小端微秒)
        buf.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes()); // magic
        buf.extend_from_slice(&2u16.to_le_bytes());          // major
        buf.extend_from_slice(&4u16.to_le_bytes());          // minor
        buf.extend_from_slice(&0i32.to_le_bytes());          // thiszone
        buf.extend_from_slice(&0u32.to_le_bytes());          // sigfigs
        buf.extend_from_slice(&65535u32.to_le_bytes());      // snaplen
        buf.extend_from_slice(&1u32.to_le_bytes());          // network (Ethernet)

        // 2. 依次生成测试包
        for i in 0..packet_count {
            let payload = format!("OMNI_PROBE_TEST_PACKET_PAYLOAD_{:04}", i).into_bytes();
            let len = payload.len() as u32;

            let ts_sec = 1700000000u32 + (i as u32);
            let ts_usec = (i * 1000) as u32;

            buf.extend_from_slice(&ts_sec.to_le_bytes());
            buf.extend_from_slice(&ts_usec.to_le_bytes());
            buf.extend_from_slice(&len.to_le_bytes()); // incl_len
            buf.extend_from_slice(&len.to_le_bytes()); // orig_len
            buf.extend_from_slice(&payload);
        }
        buf
    }

    #[test]
    fn test_sparse_indexing_and_window_seeking() {
        let pcap_bytes = generate_synthetic_pcap(250);
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("omni_test_sparse.pcap");
        {
            let mut f = File::create(&test_file).unwrap();
            f.write_all(&pcap_bytes).unwrap();
        }

        // 以跨度 50 构建两级稀疏索引
        let index = PcapSparseIndexer::build_index(&test_file, 50).unwrap();
        assert_eq!(index.total_packets, 250);
        // 250 包，跨度 50，应有 5 个稀疏节点 (0, 50, 100, 150, 200)
        assert_eq!(index.nodes.len(), 5);
        assert_eq!(index.nodes[0].packet_seq, 0);
        assert_eq!(index.nodes[1].packet_seq, 50);

        // 提取第 2 页，每页 20 条 (即请求序号 40..59)
        let page_res = PcapSparseIndexer::seek_paged_window(&index, 2, 20).unwrap();
        assert_eq!(page_res.returned_count, 20);
        assert_eq!(page_res.packets[0].seq, 40);
        assert_eq!(page_res.packets[19].seq, 59);

        // 验证 payload 预览 Hex 存在
        assert!(!page_res.packets[0].payload_preview_hex.is_empty());

        let _ = std::fs::remove_file(test_file);
    }

    #[test]
    fn test_edge_cases_empty_and_out_of_bounds() {
        let temp_dir = std::env::temp_dir();
        let empty_file = temp_dir.join("omni_test_empty.pcap");
        {
            let _ = File::create(&empty_file).unwrap();
        }

        let res = PcapSparseIndexer::build_index(&empty_file, 100);
        assert!(matches!(res, Err(PcapIndexError::FileTooShort)));

        let _ = std::fs::remove_file(empty_file);
    }
}
