use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ============================================================
// 等保三级 (GB/T 22239-2019 8.1.4.3) 审计日志集中外发引擎
// 严格遵循 RFC 5424 (The Syslog Protocol) 标准规范
// 支持 UDP / TCP 异步低开销外发至企业 SIEM / SOC 集中日志中心
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogConfig {
    pub enabled: bool,
    pub server_ip: String,
    pub server_port: u16,
    pub protocol: String, // "UDP" | "TCP"
    pub facility: u8,     // 1 = user-level, 16 = local0
    pub min_severity: u8, // 0=Emerg, 1=Alert, 2=Crit, 3=Err, 4=Warn, 5=Notice, 6=Info, 7=Debug
    pub app_name: String,
    pub sent_count: u64,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_ip: "127.0.0.1".to_string(),
            server_port: 514,
            protocol: "UDP".to_string(),
            facility: 16, // local0
            min_severity: 6, // Info 及以上
            app_name: "OmniProbe".to_string(),
            sent_count: 0,
        }
    }
}

static GLOBAL_SYSLOG: Lazy<Arc<Mutex<SyslogConfig>>> = Lazy::new(|| {
    let path = crate::forensics::data_path("syslog_config.json");
    let initial = if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            serde_json::from_str::<SyslogConfig>(&content).unwrap_or_default()
        } else {
            SyslogConfig::default()
        }
    } else {
        SyslogConfig::default()
    };
    Arc::new(Mutex::new(initial))
});

/// 格式化为标准 RFC 5424 Syslog 报文
/// 
/// 格式定义: <PRI>VERSION TIMESTAMP HOSTNAME APPNAME PROCID MSGID STRUCTURED-DATA MSG
pub fn format_rfc5424(facility: u8, severity: u8, app_name: &str, msg: &str) -> String {
    let pri = (facility & 0x1F) * 8 + (severity & 0x07);
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "OmniProbeHost".to_string());
    let proc_id = std::process::id();

    format!("<{}>1 {} {} {} {} - - {}", pri, ts, hostname, app_name, proc_id, msg)
}

/// 集中外发日志入口（非阻塞安全分流）
pub fn emit_syslog(severity: u8, message: &str) {
    let (enabled, server_ip, server_port, proto, facility, app_name) = {
        if let Ok(mut cfg) = GLOBAL_SYSLOG.lock() {
            if !cfg.enabled || severity > cfg.min_severity {
                return;
            }
            cfg.sent_count += 1;
            (
                cfg.enabled,
                cfg.server_ip.clone(),
                cfg.server_port,
                cfg.protocol.clone(),
                cfg.facility,
                cfg.app_name.clone(),
            )
        } else {
            return;
        }
    };

    if !enabled {
        return;
    }

    let raw_rfc = format_rfc5424(facility, severity, &app_name, message);

    // 异步执行 socket 发送，彻底杜绝网络 I/O 阻塞主嗅探流水线
    tokio::spawn(async move {
        if proto.to_uppercase() == "UDP" {
            if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
                let target = format!("{}:{}", server_ip, server_port);
                let _ = socket.set_write_timeout(Some(Duration::from_millis(500)));
                let _ = socket.send_to(raw_rfc.as_bytes(), target);
            }
        } else {
            // TCP Syslog
            use tokio::io::AsyncWriteExt;
            use tokio::net::TcpStream;
            let target = format!("{}:{}", server_ip, server_port);
            if let Ok(Ok(mut stream)) = tokio::time::timeout(
                Duration::from_millis(800),
                TcpStream::connect(target)
            ).await {
                let _ = stream.write_all(format!("{}\n", raw_rfc).as_bytes()).await;
            }
        }
    });
}

// ---- Tauri 命令支持 ----

pub fn get_syslog_config() -> SyslogConfig {
    GLOBAL_SYSLOG.lock().map(|c| c.clone()).unwrap_or_default()
}

pub fn save_syslog_config(new_cfg: SyslogConfig) {
    let path = crate::forensics::data_path("syslog_config.json");
    if let Ok(json_str) = serde_json::to_string_pretty(&new_cfg) {
        let _ = std::fs::write(path, json_str);
    }
    if let Ok(mut c) = GLOBAL_SYSLOG.lock() {
        *c = new_cfg;
    }
}

pub async fn test_send_syslog(test_msg: &str) -> Result<String, String> {
    let (server_ip, server_port, proto, facility, app_name) = {
        let cfg = GLOBAL_SYSLOG.lock().map_err(|e| e.to_string())?;
        (
            cfg.server_ip.clone(),
            cfg.server_port,
            cfg.protocol.clone(),
            cfg.facility,
            cfg.app_name.clone(),
        )
    };

    let raw_rfc = format_rfc5424(facility, 6, &app_name, &format!("[TEST_AUDIT] {}", test_msg));
    let target = format!("{}:{}", server_ip, server_port);

    if proto.to_uppercase() == "UDP" {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("绑定 UDP 本地端口失败: {}", e))?;
        socket.set_write_timeout(Some(Duration::from_millis(1500))).map_err(|e| e.to_string())?;
        socket.send_to(raw_rfc.as_bytes(), &target).map_err(|e| format!("UDP 发送至 {} 失败: {}", target, e))?;
    } else {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;
        let mut stream = tokio::time::timeout(Duration::from_millis(2000), TcpStream::connect(&target))
            .await
            .map_err(|_| format!("连接 TCP Syslog 服务器 {} 超时", target))?
            .map_err(|e| format!("连接 TCP Syslog 失败: {}", e))?;
        stream.write_all(format!("{}\n", raw_rfc).as_bytes()).await.map_err(|e| e.to_string())?;
    }

    if let Ok(mut cfg) = GLOBAL_SYSLOG.lock() {
        cfg.sent_count += 1;
    }

    Ok(format!("成功发送 RFC 5424 Syslog 报文至 {}", target))
}
