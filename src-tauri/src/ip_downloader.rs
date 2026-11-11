// ============================================================
// 工业全能网络探针 - IP 归属地库异步下载与热加载管理器
// 模块名称: ip_downloader.rs
// 
// 核心工业特性:
// 1. 多源故障转移 (Multi-Source Fallback): 官方直连 + 国内加速镜像 + CDN 容灾自动轮询;
// 2. 准确的官方 IPv4 数据库路径 (ip2region_v4.xdb);
// 3. 严格的完整性校验: 阻断低于 5MB 的假包/错误 HTML 页面;
// 4. 双轨持久化: 同步保存至 data/ 与 src-tauri/data/ 并触发内存零泄漏热重载。
// ============================================================

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use crate::ip_intelligence::GLOBAL_IP_ENGINE;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadProgressPayload {
    pub status: String,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub percent: f64,
    pub speed_kbps: f64,
    pub error: Option<String>,
}

/// 官方权威源与高速镜像候选列表 (自动故障转移)
pub const CANDIDATE_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb",
    "https://ghfast.top/https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb",
    "https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb",
    "https://fastly.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb",
    "https://raw.gitmirror.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb",
];

/// 异步安全下载 IP2Region 数据库文件并触发内存热加载
pub async fn download_xdb_database(app: AppHandle, custom_url: Option<String>) -> Result<String, String> {
    // 构造待尝试的 URL 队列
    let mut try_urls: Vec<String> = Vec::new();
    if let Some(ref u) = custom_url {
        let trimmed = u.trim();
        if !trimmed.is_empty() && trimmed != "auto" {
            try_urls.push(trimmed.to_string());
        }
    }
    for &c in CANDIDATE_URLS {
        if !try_urls.iter().any(|x| x == c) {
            try_urls.push(c.to_string());
        }
    }

    // 锚定至 OS 标准持久化数据目录（避免依赖工作目录 CWD 或因 Program Files 权限不足写入失败）
    let primary_target = crate::forensics::data_path("ip2region.xdb");
    let temp_path = crate::forensics::data_path("ip2region.xdb.tmp");
    if let Some(parent) = primary_target.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("创建网络请求客户端失败: {}", e))?;

    let mut last_error = String::new();
    let total_candidates = try_urls.len();

    for (idx, url) in try_urls.iter().enumerate() {
        let candidate_idx = idx + 1;
        let _ = app.emit("ip-db-download-progress", DownloadProgressPayload {
            status: format!("connecting (源 {}/{})", candidate_idx, total_candidates),
            downloaded_bytes: 0,
            total_bytes: 0,
            percent: 0.0,
            speed_kbps: 0.0,
            error: None,
        });

        match download_from_single_source(&app, &client, url, &temp_path, candidate_idx, total_candidates).await {
            Ok(downloaded_size) => {
                // 校验文件体积: 真实 xdb 通常在 10MB~12MB 之间，低于 5MB 判定为伪装错误页
                if downloaded_size < 5 * 1024 * 1024 {
                    let _ = fs::remove_file(&temp_path);
                    last_error = format!("源 [{}] 下载的文件体积异常 (仅 {} 字节，疑似代理错误页)", url, downloaded_size);
                    continue;
                }

                // 成功下载，固化到操作系统标准数据目录 (OS AppData)
                if primary_target.exists() {
                    let _ = fs::remove_file(&primary_target);
                }
                if let Err(e) = fs::rename(&temp_path, &primary_target) {
                    return Err(format!("固化 IP 库至数据目录失败: {}", e));
                }

                // 立即触发全局内存引擎热重载
                let reload_res = {
                    let mut engine = crate::lock_guard::lock_mutex(&GLOBAL_IP_ENGINE, "ip_downloader::download_xdb_database");
                    engine.load_xdb(&primary_target.to_string_lossy())
                };

                let _ = app.emit("ip-db-download-progress", DownloadProgressPayload {
                    status: "completed".to_string(),
                    downloaded_bytes: downloaded_size,
                    total_bytes: downloaded_size,
                    percent: 100.0,
                    speed_kbps: 0.0,
                    error: None,
                });

                return match reload_res {
                    Ok(msg) => Ok(format!("IP 归属地库更新成功! {}", msg)),
                    Err(e) => Err(format!("下载完成但内存热加载失败: {}", e)),
                };
            }
            Err(e) => {
                let _ = fs::remove_file(&temp_path);
                last_error = format!("源 [{}] 下载失败: {}", url, e);
                let _ = app.emit("ip-db-download-progress", DownloadProgressPayload {
                    status: "fallback".to_string(),
                    downloaded_bytes: 0,
                    total_bytes: 0,
                    percent: 0.0,
                    speed_kbps: 0.0,
                    error: Some(format!("源 {}/{} 失败，正在切换备选源...", candidate_idx, total_candidates)),
                });
            }
        }
    }

    let final_err = format!("所有 {} 个下载源均尝试失败。最后一次错误: {}", total_candidates, last_error);
    let _ = app.emit("ip-db-download-progress", DownloadProgressPayload {
        status: "error".to_string(),
        downloaded_bytes: 0,
        total_bytes: 0,
        percent: 0.0,
        speed_kbps: 0.0,
        error: Some(final_err.clone()),
    });

    Err(final_err)
}

/// 单个源流式分块下载执行器
async fn download_from_single_source(
    app: &AppHandle,
    client: &reqwest::Client,
    url: &str,
    temp_path: &Path,
    source_idx: usize,
    total_sources: usize,
) -> Result<u64, String> {
    let res = client.get(url).send().await.map_err(|e| format!("连接建立失败: {}", e))?;

    if !res.status().is_success() {
        return Err(format!("HTTP 状态码异常: {}", res.status()));
    }

    let total_bytes = res.content_length().unwrap_or(11 * 1024 * 1024);
    let mut downloaded: u64 = 0;
    let start_time = std::time::Instant::now();
    let mut last_emit = std::time::Instant::now();

    let mut temp_file = File::create(temp_path).map_err(|e| format!("创建临时文件失败: {}", e))?;
    let mut stream = res;

    while let Some(chunk) = stream.chunk().await.map_err(|e| format!("传输分块失败: {}", e))? {
        temp_file.write_all(&chunk).map_err(|e| format!("写入磁盘失败: {}", e))?;
        downloaded += chunk.len() as u64;

        if last_emit.elapsed().as_millis() > 150 || downloaded >= total_bytes {
            let elapsed_sec = start_time.elapsed().as_secs_f64();
            let speed_kbps = if elapsed_sec > 0.0 { (downloaded as f64 / 1024.0) / elapsed_sec } else { 0.0 };
            let percent = if total_bytes > 0 { (downloaded as f64 / total_bytes as f64) * 100.0 } else { 0.0 };

            let _ = app.emit("ip-db-download-progress", DownloadProgressPayload {
                status: format!("downloading ({}/{})", source_idx, total_sources),
                downloaded_bytes: downloaded,
                total_bytes,
                percent: (percent * 10.0).round() / 10.0,
                speed_kbps: speed_kbps.round(),
                error: None,
            });
            last_emit = std::time::Instant::now();
        }
    }

    temp_file.flush().map_err(|e| format!("刷新磁盘缓冲失败: {}", e))?;
    Ok(downloaded)
}

