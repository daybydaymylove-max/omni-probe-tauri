use std::sync::atomic::Ordering;
use tauri::Emitter;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

// ============================================================
// Prometheus 指标暴露服务 (Metrics HTTP Exporter)
// 等价于 Python handle_fleet_api + start_fleet_api_server
// 监听 0.0.0.0:9091/metrics，输出 Prometheus text format
// ============================================================

/// 启动 Prometheus 指标 HTTP 服务器（Tokio 轻量实现，无 axum 重依赖）
pub fn start_metrics_server(app: tauri::AppHandle, port: u16) {
    let running = crate::PROBE_RUNNING.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("[METRICS] Tokio runtime 初始化失败");

        rt.block_on(async move {
            let addr = format!("0.0.0.0:{}", port);
            let listener = match TcpListener::bind(&addr).await {
                Ok(l) => {
                    let _ = app.emit(
                        "system-log",
                        format!("[METRICS] ✅ Prometheus 指标服务已启动 http://{}/metrics", addr),
                    );
                    l
                }
                Err(e) => {
                    let _ = app.emit(
                        "system-log",
                        format!("[METRICS] ❌ 指标服务绑定失败 :{} -> {}", port, e),
                    );
                    return;
                }
            };

            loop {
                if !*crate::lock_guard::lock_mutex(&running, "metrics::start_metrics_server_loop") {
                    break;
                }

                let accept = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    listener.accept(),
                ).await;

                if let Ok(Ok((mut stream, _peer))) = accept {
                    tokio::spawn(async move {
                        handle_metrics_request(&mut stream).await;
                    });
                }
            }

            let _ = app.emit("system-log", "[METRICS] Prometheus 指标服务已停止");
        });
    });
}

/// 处理单次 HTTP 请求，支持 GET /metrics (Prometheus) 与 POST /probe/heartbeat (边缘探针上报接入)
async fn handle_metrics_request(stream: &mut tokio::net::TcpStream) {
    let mut buf = vec![0u8; 8192];
    let n = match tokio::time::timeout(
        std::time::Duration::from_millis(500),
        tokio::io::AsyncReadExt::read(stream, &mut buf),
    ).await {
        Ok(Ok(n)) => n,
        _ => return,
    };

    let req = String::from_utf8_lossy(&buf[..n]);
    let response = if req.starts_with("GET /metrics") {
        let body = build_metrics_body();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    } else if req.starts_with("POST /probe/heartbeat") || req.starts_with("POST /api/probe/heartbeat") {
        let body_part = req.split("\r\n\r\n").nth(1).unwrap_or("").trim();
        match serde_json::from_str::<crate::snmp_topology::ProbeHeartbeat>(body_part) {
            Ok(hb) => {
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                if let Ok(mut collector) = crate::snmp_topology::GLOBAL_PROBE_COLLECTOR.lock() {
                    collector.process_heartbeat(hb, now_ns);
                }
                let ok_body = r#"{"status":"accepted"}"#;
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    ok_body.len(),
                    ok_body
                )
            }
            Err(e) => {
                let err_body = format!(r#"{{"status":"error","message":"{}"}}"#, e);
                format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    err_body.len(),
                    err_body
                )
            }
        }
    } else {
        "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nNot Found".to_string()
    };

    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

/// 构建 Prometheus text format 指标体
fn build_metrics_body() -> String {
    let packets_total = crate::sniffer::GLOBAL_PACKETS_TOTAL.load(Ordering::Relaxed);
    let bytes_total = crate::sniffer::GLOBAL_BYTES_TOTAL.load(Ordering::Relaxed);
    let threats_blocked = crate::throttle::THREATS_BLOCKED.load(Ordering::Relaxed);
    let honeypot_running = *crate::lock_guard::lock_mutex(&crate::honeypot::HONEYPOT_RUNNING, "metrics::build_metrics_body");
    // 第 5 指标：当前活动连接数（双轨 TCP + 蜜罐 + ACTIVE_PULL 拉流三路接入统一计数）
    let active_connections = crate::sniffer::GLOBAL_ACTIVE_CONNECTIONS.load(Ordering::Relaxed);

    format!(
        "# HELP probe_packets_total Total packets processed by sniffer engine\n\
         # TYPE probe_packets_total counter\n\
         probe_packets_total {packets_total}\n\
         \n\
         # HELP probe_bytes_total Total bytes processed by sniffer engine\n\
         # TYPE probe_bytes_total counter\n\
         probe_bytes_total {bytes_total}\n\
         \n\
         # HELP probe_threats_blocked_total Total packets dropped by token bucket throttle\n\
         # TYPE probe_threats_blocked_total counter\n\
         probe_threats_blocked_total {threats_blocked}\n\
         \n\
         # HELP probe_honeypot_running Whether the honeypot engine is currently active\n\
         # TYPE probe_honeypot_running gauge\n\
         probe_honeypot_running {honeypot_status}\n\
         \n\
         # HELP probe_active_connections Currently active TCP connections across dual-track, honeypot and active-pull engines\n\
         # TYPE probe_active_connections gauge\n\
         probe_active_connections {active_connections}\n",
        packets_total = packets_total,
        bytes_total = bytes_total,
        threats_blocked = threats_blocked,
        honeypot_status = if honeypot_running { 1 } else { 0 },
        active_connections = active_connections,
    )
}
