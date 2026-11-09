// ==============================================================================
// Omni-Probe 工业级全能探针 - 跨平台 GitHub Releases 自动版本检查与更新引擎
// ==============================================================================

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    pub has_update: bool,
    pub current_version: String,
    pub latest_version: String,
    pub release_name: String,
    pub release_notes: String,
    pub published_at: String,
    pub download_url: String,
    pub html_url: String,
    pub asset_name: String,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    published_at: Option<String>,
    html_url: String,
    assets: Vec<GithubAsset>,
}

/// 语义化版本解析与比较 (SemVer: Major.Minor.Patch)
fn parse_semver(v: &str) -> (u32, u32, u32) {
    let clean = v.trim().trim_start_matches('v').trim_start_matches('V');
    let mut parts = clean.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|p| p.split('-').next().and_then(|x| x.parse().ok())).unwrap_or(0);
    (major, minor, patch)
}

/// 比较远程版本是否严格高于本地版本
fn is_newer_version(latest: &str, current: &str) -> bool {
    let l = parse_semver(latest);
    let c = parse_semver(current);
    l > c
}

/// 异步从 GitHub 获取最新稳定 Release 并分析是否需要更新
pub async fn check_latest_release(current_version: &str) -> Result<UpdateCheckResult, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("构建 HTTP 客户端失败: {}", e))?;

    let url = "https://api.github.com/repos/daybydaymylove-max/omni-probe-tauri/releases/latest";
    let res = client
        .get(url)
        .header("User-Agent", format!("Omni-Probe-Updater/{}", current_version))
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await
        .map_err(|e| format!("请求 GitHub Release API 失败: {}", e))?;

    if !res.status().is_success() {
        return Err(format!("GitHub API 返回异常状态码: {}", res.status()));
    }

    let release: GithubRelease = res
        .json()
        .await
        .map_err(|e| format!("解析 Release JSON 失败: {}", e))?;

    let latest_tag = release.tag_name.clone();
    let has_update = is_newer_version(&latest_tag, current_version);

    // 针对当前操作系统智能挑选首选下载安装包资产
    let mut chosen_asset_url = release.html_url.clone();
    let mut chosen_asset_name = String::new();

    #[cfg(target_os = "windows")]
    {
        for asset in &release.assets {
            let lower = asset.name.to_lowercase();
            if lower.ends_with(".exe") && (lower.contains("setup") || lower.contains("x64")) {
                chosen_asset_url = asset.browser_download_url.clone();
                chosen_asset_name = asset.name.clone();
                break;
            }
        }
        if chosen_asset_name.is_empty() {
            for asset in &release.assets {
                let lower = asset.name.to_lowercase();
                if lower.ends_with(".msi") || lower.ends_with(".exe") {
                    chosen_asset_url = asset.browser_download_url.clone();
                    chosen_asset_name = asset.name.clone();
                    break;
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        for asset in &release.assets {
            let lower = asset.name.to_lowercase();
            if lower.ends_with(".dmg") {
                chosen_asset_url = asset.browser_download_url.clone();
                chosen_asset_name = asset.name.clone();
                break;
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        for asset in &release.assets {
            let lower = asset.name.to_lowercase();
            if lower.ends_with(".appimage") || lower.ends_with(".deb") {
                chosen_asset_url = asset.browser_download_url.clone();
                chosen_asset_name = asset.name.clone();
                break;
            }
        }
    }

    Ok(UpdateCheckResult {
        has_update,
        current_version: current_version.to_string(),
        latest_version: latest_tag,
        release_name: release.name.unwrap_or_else(|| "最新发布版本".to_string()),
        release_notes: release.body.unwrap_or_else(|| "常规维护与工业性能提升更新".to_string()),
        published_at: release.published_at.unwrap_or_default(),
        download_url: chosen_asset_url,
        html_url: release.html_url,
        asset_name: chosen_asset_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_comparisons() {
        assert!(is_newer_version("v0.2.5", "0.2.4"));
        assert!(is_newer_version("v0.3.0", "0.2.4"));
        assert!(is_newer_version("1.0.0", "0.2.4"));
        assert!(!is_newer_version("v0.2.4", "0.2.4"));
        assert!(!is_newer_version("v0.2.3", "0.2.4"));
        assert!(!is_newer_version("v0.1.9", "0.2.4"));
    }
}
