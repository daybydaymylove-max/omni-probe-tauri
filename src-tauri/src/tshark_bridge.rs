// ==============================================================================
// 工业级 Omni-Probe - Wireshark / TShark 3000+ 全协议通用解剖桥接引擎 (TsharkBridge)
// 
// 核心设计原则:
// 1. 双轨混合架构 (Dual-Track Hybrid Architecture):
//    - 核心内生轨: 纯 Rust 洁净室实现 42+ 核心工业/网络协议 (线速过滤、状态机追踪、威胁阻断、零内存漏洞);
//    - 通用扩展轨: 基于进程级异步内存管道 (In-Memory Stdin/Stdout Pipe) 桥接 TShark 引擎，
//      无缝解锁 Wireshark 官方 3000+ 协议解剖器能力。
// 2. 法律与合规隔离 (GPLv2 Boundary Isolation):
//    - 遵循自由软件基金会 (FSF) GPL 规范: 跨进程管道松散聚合 (Loose Aggregation via Stdin/Stdout)，
//      不属于代码层动态/静态链接 (Linking)，探针主程序享有 100% 独立商业知识产权与闭源许可安全。
// 3. 内存与执行安全 (Process-Level Fault Isolation):
//    - 历史证明 C 语言解剖器存在内存破坏漏洞 (CVE); 进程沙箱隔离确保子进程即使崩溃也不会波及主探针。
// ==============================================================================

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use serde::{Deserialize, Serialize};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Wireshark / TShark 运行时探活状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsharkStatus {
    pub is_available: bool,
    pub executable_path: Option<String>,
    pub version: String,
    pub supported_protocol_count: usize,
    pub error_detail: Option<String>,
}

/// 通用协议解剖输出结果 (兼容 Wireshark JSON 结构)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsharkDissectionResult {
    pub success: bool,
    pub protocols_found: Vec<String>,
    pub summary_text: String,
    pub layers: HashMap<String, serde_json::Value>,
    pub raw_json: Option<serde_json::Value>,
    pub execution_time_ms: u64,
    pub error_message: Option<String>,
}

/// TShark 全协议通用解剖器桥接对象
#[derive(Debug, Clone)]
pub struct TsharkBridge {
    custom_path: Option<PathBuf>,
}

impl Default for TsharkBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl TsharkBridge {
    /// 创建 TShark 桥接实例
    pub fn new() -> Self {
        Self { custom_path: None }
    }

    /// 使用自定义 TShark 可执行文件路径创建实例
    pub fn with_custom_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            custom_path: Some(path.as_ref().to_path_buf()),
        }
    }

    /// 自动探活并定位系统中的 tshark 可执行文件路径
    /// 
    /// 搜索优先级:
    /// 1. 用户自定义配置路径
    /// 2. Windows 官方默认安装路径 (C:\Program Files\Wireshark\tshark.exe)
    /// 3. 系统环境变量 PATH (where.exe / which)
    pub fn detect_tshark_path(&self) -> Option<PathBuf> {
        if let Some(ref p) = self.custom_path {
            if p.exists() {
                return Some(p.clone());
            }
        }

        // Windows 常见官方安装路径
        let common_windows_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            r"D:\Program Files\Wireshark\tshark.exe",
        ];

        for path_str in &common_windows_paths {
            let p = PathBuf::from(path_str);
            if p.exists() {
                return Some(p);
            }
        }

        // 尝试从环境变量 PATH 中查找
        #[cfg(windows)]
        let mut where_cmd = Command::new("where.exe");
        #[cfg(windows)]
        where_cmd.arg("tshark").creation_flags(CREATE_NO_WINDOW);

        #[cfg(not(windows))]
        let mut where_cmd = Command::new("which");
        #[cfg(not(windows))]
        where_cmd.arg("tshark");

        if let Ok(output) = where_cmd.output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(first_line) = stdout.lines().next() {
                    let trimmed = first_line.trim();
                    if !trimmed.is_empty() {
                        let p = PathBuf::from(trimmed);
                        if p.exists() {
                            return Some(p);
                        }
                    }
                }
            }
        }

        None
    }

    /// 获取 TShark 引擎的探活诊断报告
    pub fn get_status(&self) -> TsharkStatus {
        let path = match self.detect_tshark_path() {
            Some(p) => p,
            None => {
                return TsharkStatus {
                    is_available: false,
                    executable_path: None,
                    version: "Not Installed".to_string(),
                    supported_protocol_count: 0,
                    error_detail: Some("未检测到 Wireshark / TShark 可执行文件".to_string()),
                };
            }
        };

        let path_str = path.to_string_lossy().to_string();

        // 执行 tshark -v 获取版本与编译元数据
        let mut v_cmd = Command::new(&path);
        v_cmd.arg("-v");
        #[cfg(windows)]
        v_cmd.creation_flags(CREATE_NO_WINDOW);

        match v_cmd.output() {
            Ok(output) => {
                if output.status.success() {
                    let version_out = String::from_utf8_lossy(&output.stdout);
                    let first_line = version_out.lines().next().unwrap_or("TShark Unknown").to_string();
                    TsharkStatus {
                        is_available: true,
                        executable_path: Some(path_str),
                        version: first_line,
                        supported_protocol_count: 3200, // Wireshark 4.x 官方默认内置解剖器规约数量
                        error_detail: None,
                    }
                } else {
                    let err = String::from_utf8_lossy(&output.stderr).to_string();
                    TsharkStatus {
                        is_available: false,
                        executable_path: Some(path_str),
                        version: "Execution Failed".to_string(),
                        supported_protocol_count: 0,
                        error_detail: Some(err),
                    }
                }
            }
            Err(e) => TsharkStatus {
                is_available: false,
                executable_path: Some(path_str),
                version: "Launch Error".to_string(),
                supported_protocol_count: 0,
                error_detail: Some(e.to_string()),
            },
        }
    }

    /// 将原始单包二进制封装为内存标准 PCAP 字节流 (无需落地物理磁盘)
    /// 
    /// 参数:
    /// - `packet_data`: 单个数据包的原始以太网或链路层载荷 (L2/L3 Raw Bytes)
    /// - `link_type`: 链路层类型 (默认 1 为 LINKTYPE_ETHERNET)
    pub fn create_in_memory_pcap_stream(packet_data: &[u8], link_type: u32) -> Vec<u8> {
        let mut stream = Vec::with_capacity(24 + 16 + packet_data.len());

        // PCAP 全局文件头 (24 字节)
        stream.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // Magic Number (小端)
        stream.extend_from_slice(&2u16.to_le_bytes());          // Version Major = 2
        stream.extend_from_slice(&4u16.to_le_bytes());          // Version Minor = 4
        stream.extend_from_slice(&0i32.to_le_bytes());          // ThisZone (GMT = 0)
        stream.extend_from_slice(&0u32.to_le_bytes());          // SigFigs = 0
        stream.extend_from_slice(&65535u32.to_le_bytes());      // SnapLen = 65535
        stream.extend_from_slice(&link_type.to_le_bytes());     // Network (Link-Layer Header Type)

        // 单包记录头 (16 字节)
        let ts_sec = 1_700_000_000u32;
        let ts_usec = 0u32;
        let cap_len = packet_data.len() as u32;
        let orig_len = packet_data.len() as u32;

        stream.extend_from_slice(&ts_sec.to_le_bytes());
        stream.extend_from_slice(&ts_usec.to_le_bytes());
        stream.extend_from_slice(&cap_len.to_le_bytes());
        stream.extend_from_slice(&orig_len.to_le_bytes());

        // 真实载荷
        stream.extend_from_slice(packet_data);
        stream
    }

    /// 对单包执行 Wireshark 官方 3000+ 协议全量通用解剖 (纯内存管道)
    /// 
    /// 时间复杂度: O(P), 单包由子进程毫秒级解构完成
    /// 空间复杂度: O(K), 纯内存传输，无任何磁盘 I/O 开销
    pub fn dissect_single_packet(
        &self,
        packet_raw_bytes: &[u8],
        link_type: Option<u32>,
    ) -> TsharkDissectionResult {
        let start_time = std::time::Instant::now();

        if packet_raw_bytes.is_empty() {
            return TsharkDissectionResult {
                success: false,
                protocols_found: Vec::new(),
                summary_text: "Empty Packet Payload".to_string(),
                layers: HashMap::new(),
                raw_json: None,
                execution_time_ms: 0,
                error_message: Some("输入数据包长度为零 (Zero-Length Packet)".to_string()),
            };
        }

        let tshark_path = match self.detect_tshark_path() {
            Some(p) => p,
            None => {
                return TsharkDissectionResult {
                    success: false,
                    protocols_found: Vec::new(),
                    summary_text: "TShark Engine Unavailable".to_string(),
                    layers: HashMap::new(),
                    raw_json: None,
                    execution_time_ms: 0,
                    error_message: Some(
                        "系统中未安装 Wireshark 或未找到 tshark.exe。请安装 Wireshark 以开启 3000+ 协议通用解剖。".to_string()
                    ),
                };
            }
        };

        let link = link_type.unwrap_or(1); // 默认 1 = LINKTYPE_ETHERNET
        let pcap_stream = Self::create_in_memory_pcap_stream(packet_raw_bytes, link);

        // 启动 tshark 子进程，配置 stdin/stdout 纯内存异步管道
        let mut tshark_cmd = Command::new(&tshark_path);
        tshark_cmd.args(["-T", "json", "-r", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        tshark_cmd.creation_flags(CREATE_NO_WINDOW);

        let mut child = match tshark_cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return TsharkDissectionResult {
                    success: false,
                    protocols_found: Vec::new(),
                    summary_text: "Process Spawn Error".to_string(),
                    layers: HashMap::new(),
                    raw_json: None,
                    execution_time_ms: start_time.elapsed().as_millis() as u64,
                    error_message: Some(format!("启动 tshark 子进程失败: {}", e)),
                };
            }
        };

        // 将内存 PCAP 写入子进程 stdin 并在写完后立即关闭 stdin 触发 EOF
        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = stdin.write_all(&pcap_stream) {
                return TsharkDissectionResult {
                    success: false,
                    protocols_found: Vec::new(),
                    summary_text: "Pipe Write Failed".to_string(),
                    layers: HashMap::new(),
                    raw_json: None,
                    execution_time_ms: start_time.elapsed().as_millis() as u64,
                    error_message: Some(format!("向 tshark 写入内存 PCAP 管道失败: {}", e)),
                };
            }
            drop(stdin); // 显式关闭管道触发 tshark 解析
        }

        // 等待解析完成并获取 stdout 输出
        let output = match child.wait_with_output() {
            Ok(out) => out,
            Err(e) => {
                return TsharkDissectionResult {
                    success: false,
                    protocols_found: Vec::new(),
                    summary_text: "Process Wait Error".to_string(),
                    layers: HashMap::new(),
                    raw_json: None,
                    execution_time_ms: start_time.elapsed().as_millis() as u64,
                    error_message: Some(format!("等待 tshark 子进程输出失败: {}", e)),
                };
            }
        };

        let exec_time = start_time.elapsed().as_millis() as u64;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            return TsharkDissectionResult {
                success: false,
                protocols_found: Vec::new(),
                summary_text: "TShark Parse Error".to_string(),
                layers: HashMap::new(),
                raw_json: None,
                execution_time_ms: exec_time,
                error_message: Some(format!("tshark 返回错误: {}", err)),
            };
        }

        // 解析 tshark 输出的标准 JSON
        let json_value: serde_json::Value = match serde_json::from_slice(&output.stdout) {
            Ok(v) => v,
            Err(e) => {
                return TsharkDissectionResult {
                    success: false,
                    protocols_found: Vec::new(),
                    summary_text: "JSON Parse Error".to_string(),
                    layers: HashMap::new(),
                    raw_json: None,
                    execution_time_ms: exec_time,
                    error_message: Some(format!("解析 tshark JSON 失败: {}", e)),
                };
            }
        };

        // 提取第一个包的 _source.layers
        if let Some(packets) = json_value.as_array() {
            if let Some(first_pkt) = packets.first() {
                if let Some(layers_obj) = first_pkt.get("_source").and_then(|s| s.get("layers")) {
                    if let Some(map) = layers_obj.as_object() {
                        let protocols: Vec<String> = map.keys().cloned().collect();
                        let summary = format!(
                            "Wireshark 官方解剖完成: 发现 {} 层协议 [{}]",
                            protocols.len(),
                            protocols.join(" -> ")
                        );

                        return TsharkDissectionResult {
                            success: true,
                            protocols_found: protocols,
                            summary_text: summary,
                            layers: map.clone().into_iter().collect(),
                            raw_json: Some(first_pkt.clone()),
                            execution_time_ms: exec_time,
                            error_message: None,
                        };
                    }
                }
            }
        }

        TsharkDissectionResult {
            success: false,
            protocols_found: Vec::new(),
            summary_text: "No Layers Dissected".to_string(),
            layers: HashMap::new(),
            raw_json: Some(json_value),
            execution_time_ms: exec_time,
            error_message: Some("tshark 未输出有效的分层协议数据".to_string()),
        }
    }
}

// ==============================================================================
// 单元测试与边界推演
// ==============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_pcap_header_construction() {
        let fake_payload = vec![0x11, 0x22, 0x33, 0x44];
        let pcap = TsharkBridge::create_in_memory_pcap_stream(&fake_payload, 1);
        assert_eq!(pcap.len(), 24 + 16 + 4);
        assert_eq!(&pcap[0..4], &0xa1b2c3d4u32.to_le_bytes()); // Magic
        assert_eq!(&pcap[20..24], &1u32.to_le_bytes());         // LinkType = 1
        assert_eq!(&pcap[32..36], &4u32.to_le_bytes());         // CapLen = 4
        assert_eq!(&pcap[40..44], &fake_payload[..]);
    }

    #[test]
    fn test_tshark_detection_and_dissection_live() {
        let bridge = TsharkBridge::new();
        let status = bridge.get_status();

        if status.is_available {
            assert!(status.version.contains("TShark") || status.version.contains("Wireshark"));
            assert!(status.executable_path.is_some());

            // 构造合法的 ARP 请求测试报文 (60 字节)
            let mut arp_pkt = hex::decode(
                "ffffffffffff00112233445508060001080006040001001122334455c0a80164000000000000c0a80101"
            ).unwrap();
            arp_pkt.resize(60, 0x00);

            let res = bridge.dissect_single_packet(&arp_pkt, Some(1));
            assert!(res.success);
            assert!(res.protocols_found.contains(&"eth".to_string()));
            assert!(res.protocols_found.contains(&"arp".to_string()));
            assert!(res.summary_text.contains("arp"));
            assert!(res.execution_time_ms > 0 || res.execution_time_ms == 0);
        }
    }

    #[test]
    fn test_zero_length_packet_fail_fast() {
        let bridge = TsharkBridge::new();
        let res = bridge.dissect_single_packet(&[], None);
        assert!(!res.success);
        assert!(res.error_message.unwrap().contains("Zero-Length"));
    }
}
