use serde::Serialize;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicU64, Ordering};
use tauri::Emitter;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};

// ============================================================
// 主动蜜罐侦听引擎 (Active Honeypot Engine)
// 基于 Tokio 异步运行时，对任意 TCP/UDP 端口进行真实绑定
// 所有连入数据实时推送至 Tauri 前端 IPC 总线
// ============================================================

static HONEYPOT_PACKET_ID: AtomicU64 = AtomicU64::new(0);

/// 独立的蜜罐数据记录（与 sniffer PacketRecord 兼容）
#[derive(Clone, Serialize, Debug)]
pub struct HoneypotRecord {
    pub id: u64,
    pub timestamp: String,
    pub timestamp_ns: u128,
    pub direction: String,     // 固定为 "HONEYPOT_RECV"
    pub transport: String,     // "TCP" or "UDP"
    pub protocol: String,      // DPI 识别结果
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,         // 蜜罐端口（诱饵端口）
    pub length: usize,
    pub payload_hex: String,
    pub entropy: f64,
    pub chain_hash: String,    // 统一全局司法证据链哈希
}

/// 全局蜜罐运行开关
pub static HONEYPOT_RUNNING: once_cell::sync::Lazy<Arc<Mutex<bool>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(false)));

/// 启动蜜罐引擎入口
/// ports: 格式为 (port, "tcp" | "udp") 的列表
/// 此函数在独立 std::thread 中启动一个 tokio runtime，不阻塞 Tauri 主线程
pub fn start_honeypot(app: tauri::AppHandle, ports: Vec<(u16, String)>) {
    {
        let mut running = HONEYPOT_RUNNING.lock().unwrap();
        if *running {
            let _ = app.emit("system-log", "[HONEYPOT] 蜜罐引擎已在运行，无需重复启动");
            return;
        }
        *running = true;
    }

    let _ = app.emit(
        "system-log",
        format!("[HONEYPOT] 蜜罐引擎启动，诱饵端口矩阵: {:?}", ports),
    );

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("[HONEYPOT] Tokio runtime 初始化失败");

        rt.block_on(async move {
            let running = HONEYPOT_RUNNING.clone();
            let mut tasks = Vec::new();

            for (port, proto) in ports {
                let app_clone = app.clone();
                let running_clone = running.clone();

                if proto.to_lowercase() == "udp" {
                    tasks.push(tokio::spawn(async move {
                        run_udp_honeypot(app_clone, port, running_clone).await;
                    }));
                } else {
                    tasks.push(tokio::spawn(async move {
                        run_tcp_honeypot(app_clone, port, running_clone).await;
                    }));
                }
            }

            for t in tasks {
                let _ = t.await;
            }
        });
    });
}

/// 停止蜜罐引擎
pub fn stop_honeypot() {
    if let Ok(mut running) = HONEYPOT_RUNNING.lock() {
        *running = false;
    }
}

/// 单个 TCP 蜜罐侦听协程
async fn run_tcp_honeypot(app: tauri::AppHandle, port: u16, running: Arc<Mutex<bool>>) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            let _ = app.emit("system-log", format!("[HONEYPOT] ✅ TCP 蜜罐已绑定 0.0.0.0:{}", port));
            l
        }
        Err(e) => {
            let _ = app.emit("system-log", format!("[HONEYPOT] ❌ TCP 蜜罐绑定失败 :{} -> {}", port, e));
            return;
        }
    };

    loop {
        if !*running.lock().unwrap() {
            break;
        }

        let accept_result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            listener.accept()
        ).await;

        match accept_result {
            Ok(Ok((mut stream, peer_addr))) => {
                let app_clone = app.clone();
                tokio::spawn(async move {
                    handle_tcp_connection(&mut stream, peer_addr, port, app_clone).await;
                });
            }
            Ok(Err(e)) => {
                let _ = app.emit("system-log", format!("[HONEYPOT] TCP accept 错误: {}", e));
            }
            Err(_) => {} // timeout，继续循环检查 running 标志
        }
    }

    let _ = app.emit("system-log", format!("[HONEYPOT] TCP :{} 蜜罐已停止", port));
}

/// 活动连接计数守卫：进入连接 +1，任意出口（含限速阻断 early return）Drop 时 -1
/// 保证 Prometheus probe_active_connections 指标永不泄漏
struct ActiveConnGuard;

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        crate::sniffer::GLOBAL_ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 处理单个 TCP 蜜罐连接
async fn handle_tcp_connection(
    stream: &mut tokio::net::TcpStream,
    peer_addr: SocketAddr,
    local_port: u16,
    app: tauri::AppHandle,
) {
    let _conn_guard = ActiveConnGuard;
    crate::sniffer::GLOBAL_ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);

    let src_ip = peer_addr.ip().to_string();

    // 蜜罐流量接入令牌桶限速检测
    if crate::throttle::check_and_throttle(&src_ip) {
        let _ = app.emit(
            "system-log",
            format!("[HONEYPOT] 🚫 超频阻断: {} 访问蜜罐端口 :{} 耗尽令牌桶", src_ip, local_port),
        );
        return;
    }

    let _ = app.emit(
        "system-log",
        format!("[HONEYPOT] 🚨 外部连接接入! {} -> 蜜罐端口 :{}", peer_addr, local_port),
    );

    // 发送连接建立事件
    emit_honeypot_record(
        &app, src_ip.clone(), peer_addr.port(), local_port,
        "TCP", b"", "TCP_CONNECT",
    );

    let mut buf = vec![0u8; 65535];
    let mut total_buf: Vec<u8> = Vec::new();

    loop {
        match tokio::time::timeout(
            std::time::Duration::from_millis(200),
            stream.read(&mut buf)
        ).await {
            Ok(Ok(0)) => break, // 连接关闭
            Ok(Ok(n)) => {
                total_buf.extend_from_slice(&buf[..n]);
            }
            Ok(Err(_)) => break,
            Err(_) => {
                if !total_buf.is_empty() {
                    let frame = std::mem::take(&mut total_buf);
                    let proto = crate::dpi::identify_protocol(peer_addr.port(), local_port, &frame);
                    emit_honeypot_record(
                        &app, src_ip.clone(), peer_addr.port(), local_port,
                        "TCP", &frame, &proto,
                    );
                }
            }
        }
    }

    // 连接关闭时 flush 剩余数据
    if !total_buf.is_empty() {
        let proto = crate::dpi::identify_protocol(peer_addr.port(), local_port, &total_buf);
        emit_honeypot_record(
            &app, src_ip, peer_addr.port(), local_port,
            "TCP", &total_buf, &proto,
        );
    }

    let _ = app.emit(
        "system-log",
        format!("[HONEYPOT] 连接断开: {} <- 蜜罐端口 :{}", peer_addr, local_port),
    );
}

/// 单个 UDP 蜜罐侦听协程
async fn run_udp_honeypot(app: tauri::AppHandle, port: u16, running: Arc<Mutex<bool>>) {
    let addr = format!("0.0.0.0:{}", port);
    let socket = match UdpSocket::bind(&addr).await {
        Ok(s) => {
            let _ = app.emit("system-log", format!("[HONEYPOT] ✅ UDP 蜜罐已绑定 0.0.0.0:{}", port));
            s
        }
        Err(e) => {
            let _ = app.emit("system-log", format!("[HONEYPOT] ❌ UDP 蜜罐绑定失败 :{} -> {}", port, e));
            return;
        }
    };

    let mut buf = vec![0u8; 65535];
    loop {
        if !*running.lock().unwrap() {
            break;
        }

        match tokio::time::timeout(
            std::time::Duration::from_secs(1),
            socket.recv_from(&mut buf)
        ).await {
            Ok(Ok((n, peer_addr))) => {
                let src_ip = peer_addr.ip().to_string();
                if crate::throttle::check_and_throttle(&src_ip) {
                    let _ = app.emit(
                        "system-log",
                        format!("[HONEYPOT] 🚫 超频阻断: {} UDP 数据包丢弃", src_ip),
                    );
                    continue;
                }

                let payload = &buf[..n];
                let proto = crate::dpi::identify_protocol(peer_addr.port(), port, payload);
                let _ = app.emit(
                    "system-log",
                    format!("[HONEYPOT] 🚨 UDP 数据包! {} -> 蜜罐:{} Proto={}", peer_addr, port, proto),
                );
                emit_honeypot_record(
                    &app, src_ip, peer_addr.port(), port,
                    "UDP", payload, &proto,
                );
            }
            Ok(Err(e)) => {
                let _ = app.emit("system-log", format!("[HONEYPOT] UDP recv 错误: {}", e));
            }
            Err(_) => {}
        }
    }

    let _ = app.emit("system-log", format!("[HONEYPOT] UDP :{} 蜜罐已停止", port));
}

/// 构造 HoneypotRecord 并通过 IPC 推送至前端及云端
/// 司法取证三重落盘：统一链式哈希 + 应用层 PCAP + received_data.jsonl
fn emit_honeypot_record(
    app: &tauri::AppHandle,
    src_ip: String,
    src_port: u16,
    dst_port: u16,
    transport: &str,
    payload: &[u8],
    protocol: &str,
) {
    let ts_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let entropy = crate::forensics::ForensicEngine::calculate_entropy(payload);

    // 真实本机 IP（杜绝 "0.0.0.0" 造假目标地址）
    let (local_ip, _local_mac) = crate::sniffer::get_local_identity();

    // 统一全局链式哈希（单一司法证据链）
    let chain_hash = crate::sniffer::advance_global_chain(
        ts_ns,
        &format!(
            "HONEYPOT|{}|{}:{}->{}:{}|{}",
            transport, src_ip, src_port, local_ip, dst_port, hex::encode(payload)
        ),
    );

    // 应用层 PCAP 落盘（诱饵端口收到的是真实 IP 报文，按真实五元组重组）
    crate::forensics::write_app_packet(&src_ip, &local_ip, src_port, dst_port, transport, payload);

    // 资产拓扑与威胁画像无缝打通：将外部攻击源/扫描探测源自动录入全局资产引擎
    let proto_tag = format!("HONEYPOT_{}", protocol);
    crate::discovery::record_asset_with_notify(app, &src_ip, "N/A", &proto_tag, dst_port);

    let record = HoneypotRecord {
        id: HONEYPOT_PACKET_ID.fetch_add(1, Ordering::Relaxed),
        timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
        timestamp_ns: ts_ns,
        direction: "HONEYPOT_RECV".to_string(),
        transport: transport.to_string(),
        protocol: protocol.to_string(),
        src_ip,
        dst_ip: local_ip,
        src_port,
        dst_port,
        length: payload.len(),
        payload_hex: hex::encode(payload),
        entropy,
        chain_hash,
    };

    // jsonl 记录收口（等价 Python received_data.jsonl）
    if let Ok(v) = serde_json::to_value(&record) {
        crate::forensics::write_jsonl_record(&v.to_string());
    }
    let _ = crate::cloud::emit_record(serde_json::to_value(&record).unwrap_or_default());
    let _ = app.emit("honeypot-received", &record);
}
