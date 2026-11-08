use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::Emitter;
use tokio::sync::mpsc;

// ============================================================
// 云端微批次流式上报引擎 (Cloud Micro-Batch Streaming Engine)
// 等价于 Python CloudStreamingAdapter (aiohttp + asyncio.Queue)
//
// 架构：
//   sniffer/honeypot 线程 -> mpsc::channel(10000) -> 聚合Worker -> reqwest HTTP POST
//
// 背压策略：
//   - 队列满（10000条）时主动丢弃（Drop Newest），保护本地内存
//   - Worker 每 500ms 或积累 100 条数据触发一次批次发送
// ============================================================

const BATCH_SIZE: usize = 100;
const BATCH_TIMEOUT_MS: u64 = 500;
const QUEUE_CAP: usize = 10_000;

/// 全局 Cloud 发送队列发送端（None 表示未启动）
static CLOUD_TX: Lazy<Arc<Mutex<Option<mpsc::Sender<serde_json::Value>>>>> =
    Lazy::new(|| Arc::new(Mutex::new(None)));

/// 全局 Cloud 配置
static CLOUD_CONFIG: Lazy<Arc<Mutex<CloudConfig>>> =
    Lazy::new(|| Arc::new(Mutex::new(CloudConfig::default())));

#[derive(Clone, Default)]
struct CloudConfig {
    enabled:     bool,
    webhook_url: String,
}

/// 启动云端上报引擎
/// webhook_url: 接收端 HTTP 地址（如 "http://siem.example.com/ingest"）
pub fn start_cloud_streaming(app: tauri::AppHandle, webhook_url: String) {
    // 更新全局配置
    if let Ok(mut cfg) = CLOUD_CONFIG.lock() {
        cfg.enabled = true;
        cfg.webhook_url = webhook_url.clone();
    }

    // 防止重复启动
    if let Ok(tx_lock) = CLOUD_TX.lock() {
        if tx_lock.is_some() {
            let _ = app.emit("system-log", "[CLOUD] 上报引擎已在运行");
            return;
        }
    }

    let (tx, mut rx) = mpsc::channel::<serde_json::Value>(QUEUE_CAP);

    if let Ok(mut tx_lock) = CLOUD_TX.lock() {
        *tx_lock = Some(tx);
    }

    let _ = app.emit("system-log", format!("[CLOUD] ✅ 流式上报引擎已启动 -> {}", webhook_url));

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("[CLOUD] Tokio runtime 初始化失败");

        rt.block_on(async move {
            // 构建 reqwest 客户端（连接池复用，TLS，超时）
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .pool_max_idle_per_host(4)
                .build()
                .expect("[CLOUD] reqwest Client 构建失败");

            let mut batch: Vec<serde_json::Value> = Vec::with_capacity(BATCH_SIZE);

            loop {
                // 等待首条数据或超时
                let first = tokio::time::timeout(
                    Duration::from_millis(BATCH_TIMEOUT_MS),
                    rx.recv(),
                ).await;

                match first {
                    Ok(Some(record)) => {
                        batch.push(record);
                        // 继续非阻塞地拉取更多，直到批次满或队列空
                        while batch.len() < BATCH_SIZE {
                            match rx.try_recv() {
                                Ok(r) => batch.push(r),
                                Err(_) => break,
                            }
                        }
                    }
                    Ok(None) => break, // 发送端已关闭，退出
                    Err(_)   => {}     // 超时：如果有积累数据则 flush
                }

                if batch.is_empty() {
                    continue;
                }

                // 构建批次 payload
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let body = serde_json::json!({
                    "source": "omni-probe-tauri",
                    "batch_ts": ts,
                    "count": batch.len(),
                    "records": batch,
                });

                let url = {
                    CLOUD_CONFIG.lock()
                        .map(|c| c.webhook_url.clone())
                        .unwrap_or_default()
                };

                if !url.is_empty() {
                    match client.post(&url).json(&body).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            let _ = app.emit(
                                "system-log",
                                format!("[CLOUD] ✅ 批次上报成功: {} 条 -> HTTP {}", batch.len(), resp.status()),
                            );
                        }
                        Ok(resp) => {
                            let _ = app.emit(
                                "system-log",
                                format!("[CLOUD] ⚠️ 服务端拒绝: HTTP {}", resp.status()),
                            );
                        }
                        Err(e) => {
                            let _ = app.emit(
                                "system-log",
                                format!("[CLOUD] ❌ 上报失败（网络异常，数据已丢弃）: {}", e),
                            );
                        }
                    }
                }

                batch.clear();
            }

            let _ = app.emit("system-log", "[CLOUD] 流式上报引擎已停止");
        });
    });
}

/// 停止云端上报引擎（关闭发送端，Worker 将自然退出）
pub fn stop_cloud_streaming() {
    if let Ok(mut tx_lock) = CLOUD_TX.lock() {
        *tx_lock = None; // Drop Sender -> rx.recv() 返回 None -> Worker 退出
    }
    if let Ok(mut cfg) = CLOUD_CONFIG.lock() {
        cfg.enabled = false;
    }
}

/// 非阻塞投递一条记录到上报队列
/// 背压溢出时直接丢弃（不阻塞调用方），返回 false 表示被丢弃
pub fn emit_record(record: serde_json::Value) -> bool {
    if let Ok(tx_lock) = CLOUD_TX.lock() {
        if let Some(tx) = tx_lock.as_ref() {
            return tx.try_send(record).is_ok();
        }
    }
    false
}
