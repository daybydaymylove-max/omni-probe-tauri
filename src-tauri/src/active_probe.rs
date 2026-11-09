use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use tauri::Emitter;
use tokio::net::TcpStream;
use tokio::io::AsyncReadExt;

// ============================================================
// 主动出站探测引擎 (Active Outbound Probe Engine)
// 功能一：周期性心跳重连探测（等价于 Python active_tcp_probe 心跳模式）
// 功能二：靶向端口扫描（等价于 Python GUI show_target_probe_window）
// 功能三：主动持续拉流 ACTIVE_PULL（等价于 Python active_tcp_probe 拉流模式：
//         连接目标 → 持续读流 → 50ms 静默组帧 → 入链落盘）
// ============================================================

static ACTIVE_PROBE_ID: AtomicU64 = AtomicU64::new(0);

/// ACTIVE_PULL 持续拉流模式全局运行开关
pub static ACTIVE_PULL_RUNNING: Lazy<Arc<Mutex<bool>>> =
    Lazy::new(|| Arc::new(Mutex::new(false)));

/// 周期心跳探针独立运行开关。
/// 历史缺陷修复：原先复用 PROBE_RUNNING，导致 (1) 主引擎未启动时
/// 心跳循环立即退出；(2) 只能随 stop_capture 整体停止，无法独立停机。
/// 现采用独立标志，生命周期与主嗅探引擎完全解耦。
pub static CONTINUOUS_PROBE_RUNNING: Lazy<Arc<Mutex<bool>>> =
    Lazy::new(|| Arc::new(Mutex::new(false)));

/// 停止 ACTIVE_PULL 拉流模式
pub fn stop_stream_pull() {
    if let Ok(mut r) = ACTIVE_PULL_RUNNING.lock() {
        *r = false;
    }
}

/// 停止周期心跳探针
pub fn stop_continuous_probe() {
    if let Ok(mut r) = CONTINUOUS_PROBE_RUNNING.lock() {
        *r = false;
    }
}

/// 单次探测结果
#[derive(Clone, Serialize, Debug)]
pub struct ProbeResult {
    pub id: u64,
    pub timestamp: String,
    pub target: String,         // "ip:port"
    pub protocol: String,       // "TCP" | "ICMP"
    pub status: String,         // "ONLINE" | "OFFLINE" | "TIMEOUT"
    pub latency_ms: f64,
    pub payload_hex: String,    // 收到的响应载荷（hex）
    pub detected_protocol: String,
}

/// 靶向扫描：并发对多个 (IP, Port) 发起 TCP 连接测试
/// 等价于 Python GUI 中的 show_target_probe_window ICMP+TCP 探针
pub async fn run_target_scan(
    app: tauri::AppHandle,
    targets: Vec<(String, u16)>,
    timeout_ms: u64,
) {
    let _ = app.emit(
        "system-log",
        format!("[PROBE] 靶向扫描启动: {} 个目标, 超时={}ms", targets.len(), timeout_ms),
    );

    let mut handles = Vec::new();
    for (ip, port) in targets {
        let app_clone = app.clone();
        handles.push(tokio::spawn(async move {
            let result = probe_tcp_connect(&ip, port, timeout_ms).await;
            let _ = app_clone.emit("probe-result", &result);

            // 系统日志摘要
            let status_icon = if result.status == "ONLINE" { "✅" } else { "❌" };
            let _ = app_clone.emit(
                "system-log",
                format!(
                    "[PROBE] {} {}:{} | {} | 延迟 {:.1}ms | 协议={}",
                    status_icon, ip, port, result.status, result.latency_ms, result.detected_protocol
                ),
            );
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let _ = app.emit("system-log", "[PROBE] 靶向扫描完成");
}

/// 单个 TCP 连接探测（含载荷接收与协议识别）
async fn probe_tcp_connect(ip: &str, port: u16, timeout_ms: u64) -> ProbeResult {
    let addr = format!("{}:{}", ip, port);
    let id = ACTIVE_PROBE_ID.fetch_add(1, Ordering::Relaxed);
    let _ts_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let start = std::time::Instant::now();

    let connect_result = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&addr),
    ).await;

    match connect_result {
        Ok(Ok(mut stream)) => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

            // 尝试读取 banner / 响应载荷（最多 4096 字节，等待 300ms）
            let mut buf = vec![0u8; 4096];
            let read_result = tokio::time::timeout(
                Duration::from_millis(300),
                stream.read(&mut buf),
            ).await;

            let (payload_hex, detected_protocol) = match read_result {
                Ok(Ok(n)) if n > 0 => {
                    let payload = &buf[..n];
                    let proto = crate::dpi::identify_protocol(0, port, payload);
                    (hex::encode(payload), proto)
                }
                _ => (String::new(), format!("OPEN:{}", port)),
            };

            ProbeResult {
                id,
                timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
                target: addr,
                protocol: "TCP".to_string(),
                status: "ONLINE".to_string(),
                latency_ms,
                payload_hex,
                detected_protocol,
            }
        }
        Ok(Err(_)) => ProbeResult {
            id,
            timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
            target: addr,
            protocol: "TCP".to_string(),
            status: "OFFLINE".to_string(),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            payload_hex: String::new(),
            detected_protocol: "CLOSED".to_string(),
        },
        Err(_) => ProbeResult {
            id,
            timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
            target: addr,
            protocol: "TCP".to_string(),
            status: "TIMEOUT".to_string(),
            latency_ms: timeout_ms as f64,
            payload_hex: String::new(),
            detected_protocol: "FILTERED".to_string(),
        },
    }
}

/// 周期心跳重连探测（等价于 Python active_tcp_probe）
/// 在独立 Tokio 任务中持续运行，直到 CONTINUOUS_PROBE_RUNNING 标志被清除。
/// 使用独立开关而非 PROBE_RUNNING：心跳探针不依赖主嗅探引擎启停。
pub fn start_continuous_probe(
    app: tauri::AppHandle,
    host: String,
    port: u16,
    interval_secs: u64,
) {
    {
        let mut running = CONTINUOUS_PROBE_RUNNING.lock().unwrap();
        if *running {
            let _ = app.emit(
                "system-log",
                "[ACTIVE_PROBE] 心跳探针已在运行，无需重复启动",
            );
            return;
        }
        *running = true;
    }
    let running = CONTINUOUS_PROBE_RUNNING.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("[ACTIVE_PROBE] Tokio runtime 初始化失败");

        rt.block_on(async move {
            let _ = app.emit(
                "system-log",
                format!("[ACTIVE_PROBE] 心跳探针已启动 -> {}:{} (周期={}s)", host, port, interval_secs),
            );

            loop {
                if !*running.lock().unwrap() {
                    break;
                }

                let result = probe_tcp_connect(&host, port, 3000).await;
                let _ = app.emit("probe-result", &result);

                if result.status == "ONLINE" {
                    let _ = app.emit(
                        "system-log",
                        format!("[ACTIVE_PROBE] ✅ {}:{} 在线 | {}ms | {}", host, port, result.latency_ms, result.detected_protocol),
                    );
                } else {
                    let _ = app.emit(
                        "system-log",
                        format!("[ACTIVE_PROBE] ❌ {}:{} {} | 静默退避 {}s...", host, port, result.status, interval_secs),
                    );
                }

                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
            }

            let _ = app.emit("system-log", format!("[ACTIVE_PROBE] 心跳探针 {}:{} 已停止", host, port));
        });
    });
}

/// ICMP Ping 主动探测算法
/// 时间复杂度: O(1), 空间复杂度: O(1)
pub async fn run_icmp_ping(target_ip: &str, timeout_ms: u64) -> ProbeResult {
    let id = ACTIVE_PROBE_ID.fetch_add(1, Ordering::Relaxed);
    let start = std::time::Instant::now();
    #[cfg(any(windows, target_os = "macos"))]
    let timeout_str = timeout_ms.to_string();
    let target = target_ip.to_string();

    let mut cmd = tokio::process::Command::new("ping");

    #[cfg(windows)]
    {
        cmd.args(["-n", "1", "-w", &timeout_str, &target]);
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    #[cfg(target_os = "linux")]
    {
        let timeout_sec = ((timeout_ms + 999) / 1000).max(1).to_string();
        cmd.args(["-c", "1", "-W", &timeout_sec, &target]);
    }

    #[cfg(target_os = "macos")]
    {
        cmd.args(["-c", "1", "-W", &timeout_str, &target]);
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        cmd.args(["-c", "1", &target]);
    }

    let output = cmd.output().await;

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let (status, detected_proto) = match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("TTL=") || stdout.contains("ttl=") {
                ("ONLINE".to_string(), "ICMP_ECHO_REPLY".to_string())
            } else if stdout.contains("请求超时") || stdout.contains("timed out") || stdout.contains("100% 丢失") || stdout.contains("100% loss") {
                ("TIMEOUT".to_string(), "ICMP_TIMEOUT".to_string())
            } else {
                ("OFFLINE".to_string(), "ICMP_UNREACHABLE".to_string())
            }
        }
        Err(_) => ("OFFLINE".to_string(), "PING_EXEC_ERROR".to_string()),
    };

    ProbeResult {
        id,
        timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
        target,
        protocol: "ICMP".to_string(),
        status,
        latency_ms,
        payload_hex: String::new(),
        detected_protocol: detected_proto,
    }
}

/// L4 传输层报文精准回放（修复原版 L2 物理帧注入层级错位缺陷）
/// 时间复杂度: O(N), 空间复杂度: O(N), N = 载荷长度
pub async fn replay_l4_packet(
    target_ip: &str,
    target_port: u16,
    transport: &str,
    payload_hex: &str,
) -> Result<String, String> {
    let bytes = hex::decode(payload_hex.replace(' ', ""))
        .map_err(|e| format!("HEX 解码失败: {}", e))?;
    if bytes.is_empty() {
        return Err("载荷字节为空，无法回放".to_string());
    }

    let proto = transport.to_uppercase();
    if proto == "UDP" {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("绑定临时 UDP 套接字失败: {}", e))?;
        let addr = format!("{}:{}", target_ip, target_port);
        let sent = socket.send_to(&bytes, &addr)
            .await
            .map_err(|e| format!("UDP 发送失败: {}", e))?;
        Ok(format!("[REPLAY] ✅ UDP 传输层回放成功: 发送 {} 字节 -> {}", sent, addr))
    } else {
        let addr = format!("{}:{}", target_ip, target_port);
        let mut stream = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| format!("连接目标主机超时: {}", addr))?
        .map_err(|e| format!("连接目标主机失败: {}", e))?;

        use tokio::io::AsyncWriteExt;
        stream.write_all(&bytes)
            .await
            .map_err(|e| format!("TCP 载荷写入失败: {}", e))?;

        let mut buf = vec![0u8; 4096];
        let read_res = tokio::time::timeout(
            Duration::from_secs(1),
            stream.read(&mut buf),
        ).await;

        let resp_info = match read_res {
            Ok(Ok(n)) if n > 0 => format!("，收到对端响应 {} 字节", n),
            _ => "，无对端载荷返回".to_string(),
        };

        Ok(format!("[REPLAY] ✅ TCP 传输层回放成功: 发送 {} 字节 -> {}{}", bytes.len(), addr, resp_info))
    }
}

/// 端口双向操作数据交互探针结果
#[derive(Clone, Serialize, Debug)]
pub struct PortTransceiveResult {
    pub success: bool,
    pub target: String,
    pub transport: String,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub latency_ms: f64,
    pub response_hex: String,
    pub response_text: String,
    pub detected_protocol: String,
    pub error_msg: Option<String>,
}

/// 端口操作数据双向收发探针（物理发送 TX + 接收回包 RX 全链路闭环）
pub async fn send_and_receive_port_data(
    app: tauri::AppHandle,
    target_ip: &str,
    target_port: u16,
    transport: &str,
    payload_hex: &str,
    timeout_ms: u64,
) -> PortTransceiveResult {
    let clean_hex = payload_hex.replace(' ', "");
    let payload = match hex::decode(&clean_hex) {
        Ok(b) => b,
        Err(e) => {
            return PortTransceiveResult {
                success: false,
                target: format!("{}:{}", target_ip, target_port),
                transport: transport.to_string(),
                bytes_sent: 0,
                bytes_received: 0,
                latency_ms: 0.0,
                response_hex: String::new(),
                response_text: String::new(),
                detected_protocol: "HEX_DECODE_ERR".into(),
                error_msg: Some(format!("载荷 Hex 解码失败: {}", e)),
            };
        }
    };

    let start = std::time::Instant::now();
    let addr = format!("{}:{}", target_ip, target_port);
    let is_udp = transport.eq_ignore_ascii_case("UDP");

    static PORT_OP_COUNTER: AtomicU64 = AtomicU64::new(1);
    let id_tx = PORT_OP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts_ns_tx = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let proto_tx = crate::dpi::identify_protocol(0, target_port, &payload);

    // 1. 记录出向操作数据 (TX)
    let mut b_map_tx = crate::dpi::dissect_payload(&proto_tx, &payload);
    b_map_tx.insert("direction".into(), serde_json::json!("PORT_OUTBOUND"));
    b_map_tx.insert("target_address".into(), serde_json::json!(&addr));
    b_map_tx.insert("transport".into(), serde_json::json!(transport));
    b_map_tx.insert("bytes_sent".into(), serde_json::json!(payload.len()));

    // 统一全局链式哈希（单一司法证据链，杜绝 "PORT_TX_{id}" 独立伪链）+ 应用层 PCAP 落盘
    let (local_ip_tx, _) = crate::sniffer::get_local_identity();
    let chain_hash_tx = crate::sniffer::advance_global_chain(
        ts_ns_tx,
        &format!(
            "PORT_TX|{}->{}:{}|{}",
            local_ip_tx, target_ip, target_port, hex::encode(&payload)
        ),
    );
    crate::forensics::write_app_packet(
        &local_ip_tx, target_ip, 0, target_port, &transport.to_uppercase(), &payload,
    );

    let tx_record = crate::sniffer::PacketRecord {
        id: id_tx,
        timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
        timestamp_ns: ts_ns_tx,
        direction: "PORT_OUTBOUND".into(),
        transport: transport.to_uppercase(),
        protocol: proto_tx.clone(),
        src_ip: local_ip_tx.clone(),
        dst_ip: target_ip.to_string(),
        src_port: 0,
        dst_port: target_port,
        length: payload.len(),
        payload_hex: hex::encode(&payload),
        raw_frame_hex: hex::encode(&payload),
        entropy: crate::forensics::ForensicEngine::calculate_entropy(&payload),
        entropy_level: "safe".into(),
        mac_src: "HOST".into(),
        mac_dst: "REMOTE".into(),
        chain_hash: chain_hash_tx,
        business_data: Some(b_map_tx),
        raw_text: Some(format!("端口出向写出 -> {} [{}] ({} 字节)", addr, transport, payload.len())),
    };
    // jsonl 记录收口（等价 Python received_data.jsonl）
    if let Ok(v) = serde_json::to_value(&tx_record) {
        crate::forensics::write_jsonl_record(&v.to_string());
    }
    let _ = app.emit("packet-received", &tx_record);

    // 2. 物理网络通信与回包侦测
    let to_duration = Duration::from_millis(timeout_ms.max(500));
    if is_udp {
        let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                return PortTransceiveResult {
                    success: false,
                    target: addr,
                    transport: "UDP".into(),
                    bytes_sent: payload.len(),
                    bytes_received: 0,
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    response_hex: String::new(),
                    response_text: String::new(),
                    detected_protocol: proto_tx,
                    error_msg: Some(format!("UDP 套接字绑定失败: {}", e)),
                };
            }
        };

        if let Err(e) = sock.send_to(&payload, &addr).await {
            return PortTransceiveResult {
                success: false,
                target: addr,
                transport: "UDP".into(),
                bytes_sent: payload.len(),
                bytes_received: 0,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                response_hex: String::new(),
                response_text: String::new(),
                detected_protocol: proto_tx,
                error_msg: Some(format!("UDP 发送失败: {}", e)),
            };
        }

        let mut recv_buf = vec![0u8; 4096];
        let recv_res = tokio::time::timeout(to_duration, sock.recv_from(&mut recv_buf)).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match recv_res {
            Ok(Ok((n, peer))) if n > 0 => {
                let rx_data = &recv_buf[..n];
                let rx_proto = crate::dpi::identify_protocol(peer.port(), 0, rx_data);
                let id_rx = PORT_OP_COUNTER.fetch_add(1, Ordering::Relaxed);
                let ts_ns_rx = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();

                let mut b_map_rx = crate::dpi::dissect_payload(&rx_proto, rx_data);
                b_map_rx.insert("direction".into(), serde_json::json!("PORT_INBOUND"));
                b_map_rx.insert("source_peer".into(), serde_json::json!(peer.to_string()));
                b_map_rx.insert("bytes_received".into(), serde_json::json!(n));

                // 统一全局链式哈希（单一司法证据链）+ 应用层 PCAP 落盘（真实五元组）
                let (local_ip_rx, _) = crate::sniffer::get_local_identity();
                let local_port_rx = sock
                    .local_addr()
                    .map(|a| a.port())
                    .unwrap_or(0);
                let chain_hash_rx = crate::sniffer::advance_global_chain(
                    ts_ns_rx,
                    &format!(
                        "PORT_RX|{}:{}->{}:{}|UDP|{}",
                        peer.ip(), peer.port(), local_ip_rx, local_port_rx, hex::encode(rx_data)
                    ),
                );
                crate::forensics::write_app_packet(
                    &peer.ip().to_string(), &local_ip_rx, peer.port(), local_port_rx, "UDP", rx_data,
                );

                let rx_record = crate::sniffer::PacketRecord {
                    id: id_rx,
                    timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
                    timestamp_ns: ts_ns_rx,
                    direction: "PORT_INBOUND".into(),
                    transport: "UDP".into(),
                    protocol: rx_proto.clone(),
                    src_ip: peer.ip().to_string(),
                    dst_ip: local_ip_rx,
                    src_port: peer.port(),
                    dst_port: local_port_rx,
                    length: n,
                    payload_hex: hex::encode(rx_data),
                    raw_frame_hex: hex::encode(rx_data),
                    entropy: crate::forensics::ForensicEngine::calculate_entropy(rx_data),
                    entropy_level: "safe".into(),
                    mac_src: "REMOTE".into(),
                    mac_dst: "HOST".into(),
                    chain_hash: chain_hash_rx,
                    business_data: Some(b_map_rx),
                    raw_text: Some(format!("端口入向应答 <- {} [{}] ({} 字节)", peer, rx_proto, n)),
                };
                // jsonl 记录收口（等价 Python received_data.jsonl）
                if let Ok(v) = serde_json::to_value(&rx_record) {
                    crate::forensics::write_jsonl_record(&v.to_string());
                }
                let _ = app.emit("packet-received", &rx_record);

                PortTransceiveResult {
                    success: true,
                    target: addr,
                    transport: "UDP".into(),
                    bytes_sent: payload.len(),
                    bytes_received: n,
                    latency_ms,
                    response_hex: hex::encode(rx_data),
                    response_text: crate::sniffer::generate_raw_text_preview(rx_data),
                    detected_protocol: rx_proto,
                    error_msg: None,
                }
            }
            _ => PortTransceiveResult {
                success: true,
                target: addr,
                transport: "UDP".into(),
                bytes_sent: payload.len(),
                bytes_received: 0,
                latency_ms,
                response_hex: String::new(),
                response_text: String::new(),
                detected_protocol: proto_tx,
                error_msg: Some("UDP 报文已发出，但在超时窗口内未收到对端应答".into()),
            },
        }
    } else {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let conn_res = tokio::time::timeout(to_duration, tokio::net::TcpStream::connect(&addr)).await;
        let mut stream = match conn_res {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return PortTransceiveResult {
                    success: false,
                    target: addr,
                    transport: "TCP".into(),
                    bytes_sent: payload.len(),
                    bytes_received: 0,
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    response_hex: String::new(),
                    response_text: String::new(),
                    detected_protocol: proto_tx,
                    error_msg: Some(format!("TCP 连接目标端口失败: {}", e)),
                };
            }
            Err(_) => {
                return PortTransceiveResult {
                    success: false,
                    target: addr,
                    transport: "TCP".into(),
                    bytes_sent: payload.len(),
                    bytes_received: 0,
                    latency_ms: timeout_ms as f64,
                    response_hex: String::new(),
                    response_text: String::new(),
                    detected_protocol: proto_tx,
                    error_msg: Some("TCP 连接端口超时".into()),
                };
            }
        };

        if let Err(e) = stream.write_all(&payload).await {
            return PortTransceiveResult {
                success: false,
                target: addr,
                transport: "TCP".into(),
                bytes_sent: payload.len(),
                bytes_received: 0,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                response_hex: String::new(),
                response_text: String::new(),
                detected_protocol: proto_tx,
                error_msg: Some(format!("TCP 载荷发送失败: {}", e)),
            };
        }

        let mut recv_buf = vec![0u8; 4096];
        let read_res = tokio::time::timeout(to_duration, stream.read(&mut recv_buf)).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match read_res {
            Ok(Ok(n)) if n > 0 => {
                let rx_data = &recv_buf[..n];
                let rx_proto = crate::dpi::identify_protocol(target_port, 0, rx_data);
                let id_rx = PORT_OP_COUNTER.fetch_add(1, Ordering::Relaxed);
                let ts_ns_rx = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();

                let mut b_map_rx = crate::dpi::dissect_payload(&rx_proto, rx_data);
                b_map_rx.insert("direction".into(), serde_json::json!("PORT_INBOUND"));
                b_map_rx.insert("target_address".into(), serde_json::json!(&addr));
                b_map_rx.insert("bytes_received".into(), serde_json::json!(n));

                // 统一全局链式哈希（单一司法证据链）+ 应用层 PCAP 落盘（真实五元组）
                let (local_ip_rx, _) = crate::sniffer::get_local_identity();
                let local_port_rx = stream
                    .local_addr()
                    .map(|a| a.port())
                    .unwrap_or(0);
                let chain_hash_rx = crate::sniffer::advance_global_chain(
                    ts_ns_rx,
                    &format!(
                        "PORT_RX|{}:{}->{}:{}|TCP|{}",
                        target_ip, target_port, local_ip_rx, local_port_rx, hex::encode(rx_data)
                    ),
                );
                crate::forensics::write_app_packet(
                    target_ip, &local_ip_rx, target_port, local_port_rx, "TCP", rx_data,
                );

                let rx_record = crate::sniffer::PacketRecord {
                    id: id_rx,
                    timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
                    timestamp_ns: ts_ns_rx,
                    direction: "PORT_INBOUND".into(),
                    transport: "TCP".into(),
                    protocol: rx_proto.clone(),
                    src_ip: target_ip.to_string(),
                    dst_ip: local_ip_rx,
                    src_port: target_port,
                    dst_port: local_port_rx,
                    length: n,
                    payload_hex: hex::encode(rx_data),
                    raw_frame_hex: hex::encode(rx_data),
                    entropy: crate::forensics::ForensicEngine::calculate_entropy(rx_data),
                    entropy_level: "safe".into(),
                    mac_src: "REMOTE".into(),
                    mac_dst: "HOST".into(),
                    chain_hash: chain_hash_rx,
                    business_data: Some(b_map_rx),
                    raw_text: Some(format!("TCP 端口应答 <- {} [{}] ({} 字节)", addr, rx_proto, n)),
                };
                // jsonl 记录收口（等价 Python received_data.jsonl）
                if let Ok(v) = serde_json::to_value(&rx_record) {
                    crate::forensics::write_jsonl_record(&v.to_string());
                }
                let _ = app.emit("packet-received", &rx_record);

                PortTransceiveResult {
                    success: true,
                    target: addr,
                    transport: "TCP".into(),
                    bytes_sent: payload.len(),
                    bytes_received: n,
                    latency_ms,
                    response_hex: hex::encode(rx_data),
                    response_text: crate::sniffer::generate_raw_text_preview(rx_data),
                    detected_protocol: rx_proto,
                    error_msg: None,
                }
            }
            _ => PortTransceiveResult {
                success: true,
                target: addr,
                transport: "TCP".into(),
                bytes_sent: payload.len(),
                bytes_received: 0,
                latency_ms,
                response_hex: String::new(),
                response_text: String::new(),
                detected_protocol: proto_tx,
                error_msg: Some("TCP 载荷已成功发送，对端保持静默未返回应用数据".into()),
            },
        }
    }
}

// ============================================================
// 主动持续拉流模式 ACTIVE_PULL（等价 Python active_tcp_probe 拉流分支）
// 语义：连接目标 → 持续读流 → 50ms 静默组帧 → 统一入链 + 三重落盘
//       → 断线自动重连（reconnect_secs 周期，期间秒级响应停止指令）
// ============================================================

static ACTIVE_PULL_COUNTER: AtomicU64 = AtomicU64::new(1);

/// 启动主动拉流引擎（独立线程 + Tokio 单线程运行时，不阻塞 Tauri 主线程）
pub fn start_stream_pull(
    app: tauri::AppHandle,
    host: String,
    port: u16,
    reconnect_secs: u64,
) {
    {
        let mut running = ACTIVE_PULL_RUNNING.lock().unwrap();
        if *running {
            let _ = app.emit("system-log", "[ACTIVE_PULL] 拉流引擎已在运行，无需重复启动");
            return;
        }
        *running = true;
    }

    let _ = app.emit(
        "system-log",
        format!(
            "[ACTIVE_PULL] 主动拉流引擎启动 -> {}:{} (断线重连间隔 {}s)",
            host, port, reconnect_secs
        ),
    );

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("[ACTIVE_PULL] Tokio runtime 初始化失败");

        rt.block_on(async move {
            let running = ACTIVE_PULL_RUNNING.clone();
            let (local_ip, local_mac) = crate::sniffer::get_local_identity();
            let addr = format!("{}:{}", host, port);

            while *running.lock().unwrap() {
                let conn_res =
                    tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await;

                match conn_res {
                    Ok(Ok(mut stream)) => {
                        // 活动连接计数 + 生命周期事件（复用双轨 SYS_CTRL 构造）
                        crate::sniffer::GLOBAL_ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                        let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
                        crate::sniffer::emit_dual_track_ctrl_event(
                            &app, &host, port, local_port, "TCP_CONNECT",
                        );

                        let mut buf = vec![0u8; 65535];
                        let mut frame_buf: Vec<u8> = Vec::new();
                        let mut last_rx = std::time::Instant::now();

                        loop {
                            if !*running.lock().unwrap() {
                                break;
                            }
                            match tokio::time::timeout(
                                Duration::from_millis(50),
                                stream.read(&mut buf),
                            )
                            .await
                            {
                                Ok(Ok(0)) => break, // 对端正常关闭
                                Ok(Ok(n)) => {
                                    frame_buf.extend_from_slice(&buf[..n]);
                                    last_rx = std::time::Instant::now();
                                }
                                Ok(Err(_)) => break, // 连接错误
                                Err(_) => {
                                    // 50ms 静默组帧定界（对齐 Python tcp_framing_timeout=0.05）
                                    if !frame_buf.is_empty()
                                        && last_rx.elapsed() >= Duration::from_millis(50)
                                    {
                                        let payload = std::mem::take(&mut frame_buf);
                                        emit_active_pull_frame(
                                            &app, &host, port, local_port, &local_ip, &local_mac,
                                            &payload,
                                        );
                                    }
                                }
                            }
                        }

                        // 连接收尾 flush 剩余半帧
                        if !frame_buf.is_empty() {
                            emit_active_pull_frame(
                                &app, &host, port, local_port, &local_ip, &local_mac, &frame_buf,
                            );
                        }

                        crate::sniffer::GLOBAL_ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                        crate::sniffer::emit_dual_track_ctrl_event(
                            &app, &host, port, local_port, "TCP_DISCONNECT",
                        );
                        let _ = app.emit(
                            "system-log",
                            format!("[ACTIVE_PULL] {}:{} 连接断开，准备重连", host, port),
                        );
                    }
                    Ok(Err(e)) => {
                        let _ = app.emit(
                            "system-log",
                            format!("[ACTIVE_PULL] ❌ 连接 {} 失败: {}，进入重连退避", addr, e),
                        );
                    }
                    Err(_) => {
                        let _ = app.emit(
                            "system-log",
                            format!("[ACTIVE_PULL] ⏱️ 连接 {} 超时，进入重连退避", addr),
                        );
                    }
                }

                // 重连退避：秒级粒度轮询停止指令，保证 stop_stream_pull 秒级响应
                for _ in 0..reconnect_secs.max(1) {
                    if !*running.lock().unwrap() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }

            let _ = app.emit("system-log", "[ACTIVE_PULL] 主动拉流引擎已停止");
        });
    });
}

/// ACTIVE_PULL 单帧记录构造与投递：direction="ACTIVE_PULL"，统一入链 + 三重落盘
#[allow(clippy::too_many_arguments)]
fn emit_active_pull_frame(
    app: &tauri::AppHandle,
    host: &str,
    remote_port: u16,
    local_port: u16,
    local_ip: &str,
    local_mac: &str,
    payload: &[u8],
) {
    let id = ACTIVE_PULL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let entropy = crate::forensics::ForensicEngine::calculate_entropy(payload);
    let entropy_level = crate::sniffer::classify_entropy(entropy);
    let payload_hex = hex::encode(payload);
    let protocol = crate::dpi::identify_protocol(remote_port, local_port, payload);

    let raw_text = Some(crate::sniffer::generate_raw_text_preview(payload));
    let mut b_map = crate::dpi::dissect_payload(&protocol, payload);
    if b_map.is_empty() {
        b_map.insert("transport".into(), serde_json::json!("TCP"));
        b_map.insert("remote_endpoint".into(), serde_json::json!(format!("{}:{}", host, remote_port)));
        b_map.insert("inferred_protocol".into(), serde_json::json!(&protocol));
        b_map.insert("stream_length_bytes".into(), serde_json::json!(payload.len()));
    }
    b_map.insert("pull_mode".into(), serde_json::json!("ACTIVE_PULL"));

    // 统一全局链式哈希（单一司法证据链）
    let chain_hash = crate::sniffer::advance_global_chain(
        ts_ns,
        &format!(
            "ACTIVE_PULL|{}:{}->{}:{}|TCP|{}",
            host, remote_port, local_ip, local_port, payload_hex
        ),
    );

    // 应用层报文重组落盘 capture.pcap（等价 Python TruePcapWriter）
    crate::forensics::write_app_packet(host, local_ip, remote_port, local_port, "TCP", payload);

    let record = crate::sniffer::PacketRecord {
        id,
        timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
        timestamp_ns: ts_ns,
        direction: "ACTIVE_PULL".into(),
        transport: "TCP".into(),
        protocol,
        src_ip: host.to_string(),
        dst_ip: local_ip.to_string(),
        src_port: remote_port,
        dst_port: local_port,
        length: payload.len(),
        payload_hex,
        raw_frame_hex: String::new(),
        entropy,
        entropy_level,
        mac_src: "N/A (App-Layer)".into(),
        mac_dst: local_mac.to_string(),
        chain_hash,
        business_data: Some(b_map),
        raw_text,
    };

    // process_incoming_record 内部完成 jsonl 收口 + 云端推送 + 前端 IPC 投递
    crate::sniffer::process_incoming_record(app, record);
}
