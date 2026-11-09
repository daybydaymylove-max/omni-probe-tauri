// ==============================================================================
// 工业级 Omni-Probe - 底层抓包驱动与协议解剖运行环境诊断与一键官方自动安装引擎 (Environment Inspector)
// 
// 核心目标:
// 1. 深度探活底层核心基础设施:
//    - Npcap / WinPcap 驱动 (L2 数据链路层、混杂模式、全网卡嗅探、发送注入)
//    - Wireshark / TShark 引擎 (3,200+ 全量协议官方层级树解剖)
//    - USBPcap 内核驱动 (USB 物理层 URB 流量审计与反 BadUSB 检测)
//    - 操作系统特权级别 (Administrator 权限，保障原始套接字无阻断抓包)
// 2. 状态分级与防御性降级自愈识别:
//    - 未安装驱动时不卡死、不静默退出，精确指示当前系统的自适应降级模式
//    - 输出环境健康度量化评分 (0 ~ 100) 与优化建议
// 3. 官方源一键流式自动下载与安装向导唤起:
//    - 经用户二次确认后，直接从官方直链 (npcap.com, wireshark.org, desowin.org) 流式安全下载最新稳定包
//    - 实时通过 Tauri 事件广播精确字节下载进度与百分比
//    - 下载完成后安全唤起官方安装程序向导，零破坏性自愈
// ==============================================================================

use std::path::Path;
use serde::{Deserialize, Serialize};
use chrono::Local;

/// 单个核心环境依赖组件诊断状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub id: String,
    pub name: String,
    pub category: String, // "CaptureDriver" | "DissectionEngine" | "HardwareDriver" | "SystemPrivilege"
    pub is_ready: bool,
    pub version: Option<String>,
    pub path: Option<String>,
    pub capability_enabled: String,
    pub fallback_mode: String,
    pub official_url: String,
    pub install_tips: String,
    pub can_auto_install: bool,
    pub installer_filename: Option<String>,
    pub estimated_size_mb: Option<f64>,
}

/// 全局环境就绪度全景评估报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentInspectionReport {
    pub readiness_score: u32,
    pub status_level: String, // "Optimal" | "Standard" | "Degraded"
    pub summary: String,
    pub components: Vec<ComponentStatus>,
    pub checked_at: String,
}

/// 官方安装包流式下载与安装进度事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallerDownloadProgress {
    pub component_id: String,
    pub status: String, // "downloading" | "launching" | "completed" | "error"
    pub percent: f64,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub error_msg: Option<String>,
}

/// 官方安装包元数据描述
#[derive(Debug, Clone)]
pub struct OfficialInstallerMeta {
    pub component_id: String,
    pub direct_download_url: String,
    pub target_filename: String,
    pub estimated_size_bytes: u64,
}

/// 环境诊断与安装向导器核心结构体
pub struct EnvironmentInspector;

impl EnvironmentInspector {
    /// 执行全系统深度探活并生成环境就绪度报告
    /// 
    /// 复杂度: O(1), 单次微秒级至毫秒级文件/API探活
    pub fn inspect_all() -> EnvironmentInspectionReport {
        let mut components = Vec::with_capacity(5);
        let mut score = 0u32;

        // 1. 探活 Npcap / WinPcap 抓包驱动 (权重: 30 分)
        let npcap_status = Self::inspect_npcap();
        if npcap_status.is_ready {
            score += 30;
        }
        components.push(npcap_status);

        // 2. 探活 Wireshark / TShark 官方解剖引擎 (权重: 25 分)
        let tshark_status = Self::inspect_tshark();
        if tshark_status.is_ready {
            score += 25;
        }
        components.push(tshark_status);

        // 3. 探活 USBPcap 物理总线驱动 (权重: 20 分)
        let usbpcap_status = Self::inspect_usbpcap();
        if usbpcap_status.is_ready {
            score += 20;
        }
        components.push(usbpcap_status);

        // 4. 探活 ip2region.xdb 离线 IP 地理情报库 (权重: 15 分)
        let ip_db_status = Self::inspect_ip_db();
        if ip_db_status.is_ready {
            score += 15;
        }
        components.push(ip_db_status);

        // 5. 探活 Windows Administrator 进程特权 (权重: 10 分)
        let admin_status = Self::inspect_admin_privilege();
        if admin_status.is_ready {
            score += 10;
        }
        components.push(admin_status);

        let (status_level, summary) = match score {
            90..=100 => (
                "Optimal".to_string(),
                "系统底层抓包驱动与离线情报工具链已达到【工业级最佳全能态】：支持千兆混杂模式、全量 3200+ 协议官方解剖、物理 USB 深度审计与千万级离线地理情报。".to_string(),
            ),
            50..=89 => (
                "Standard".to_string(),
                "系统处于【工业标准运行态】：多轨并行自愈引擎已全面接管，核心自主功能正常运转，部分高级功能处于安全降级或外围扩展模式。".to_string(),
            ),
            _ => (
                "Degraded".to_string(),
                "系统处于【多轨自愈兜底态】：底层外部驱动与数据库缺失，系统已自动启用纯内置模块（Raw Socket / 内网 LPM 字典 / 原生协议解剖）保障核心功能可用。".to_string(),
            ),
        };

        EnvironmentInspectionReport {
            readiness_score: score,
            status_level,
            summary,
            components,
            checked_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        }
    }

    /// 探活 Npcap / WinPcap 抓包驱动
    pub fn inspect_npcap() -> ComponentStatus {
        let is_dll_loaded = crate::sniffer::is_npcap_driver_available();
        
        let mut found_path = None;
        let candidate_paths = [
            r"C:\Windows\System32\Npcap\wpcap.dll",
            r"C:\Windows\System32\wpcap.dll",
            r"C:\Program Files\Npcap",
        ];

        for p_str in &candidate_paths {
            let p = Path::new(p_str);
            if p.exists() {
                found_path = Some(p_str.to_string());
                break;
            }
        }

        let is_ready = is_dll_loaded || found_path.is_some();
        let version = if is_ready {
            Some("Npcap L2 Driver (Loaded)".to_string())
        } else {
            None
        };

        ComponentStatus {
            id: "npcap".to_string(),
            name: "Npcap / WinPcap 网络捕获驱动".to_string(),
            category: "CaptureDriver".to_string(),
            is_ready,
            version,
            path: found_path,
            capability_enabled: "解锁 L2 数据链路层嗅探、千兆网卡混杂模式、全量 ARP/LLDP/广播捕获与以太网报文主动注入能力。".to_string(),
            fallback_mode: "自愈降级为 Windows 原生 Raw Sockets 模式 (受限于操作系统安全策略，仅能嗅探部分进出单播与双轨监听端口)。".to_string(),
            official_url: "https://npcap.com/#download".to_string(),
            install_tips: "安装时请勾选: ① 'Install Npcap in WinPcap API-compatible Mode'; ② 'Support raw 802.11 traffic'。".to_string(),
            can_auto_install: true,
            installer_filename: Some("npcap-1.80.exe".to_string()),
            estimated_size_mb: Some(1.15),
        }
    }

    /// 探活 Wireshark / TShark 协议解剖引擎
    pub fn inspect_tshark() -> ComponentStatus {
        let bridge = crate::tshark_bridge::TsharkBridge::new();
        let status = bridge.get_status();

        ComponentStatus {
            id: "tshark".to_string(),
            name: "Wireshark / TShark 协议解剖引擎".to_string(),
            category: "DissectionEngine".to_string(),
            is_ready: status.is_available,
            version: if status.is_available { Some(status.version) } else { None },
            path: status.executable_path,
            capability_enabled: "通过跨进程异步内存管道，瞬时解锁 Wireshark 官方 3,200+ 全量通用协议解剖树与详细字段展开。".to_string(),
            fallback_mode: "使用 Omni-Probe 自主纯 Rust 42+ 核心工业控制 (Modbus, S7, DNP3, BACnet, 104, MMS) 与标准网络解剖器，配合 HexDump 转储视窗。".to_string(),
            official_url: "https://www.wireshark.org/download.html".to_string(),
            install_tips: "建议安装官方稳定版 Wireshark 4.x，默认安装路径探针将自动零配置接入。".to_string(),
            can_auto_install: true,
            installer_filename: Some("Wireshark-win64-4.4.1.exe".to_string()),
            estimated_size_mb: Some(80.5),
        }
    }

    /// 探活 USBPcap 物理外设捕获驱动
    pub fn inspect_usbpcap() -> ComponentStatus {
        let candidate_paths = [
            r"C:\Program Files\USBPcap\USBPcapCMD.exe",
            r"C:\Program Files (x86)\USBPcap\USBPcapCMD.exe",
        ];

        let mut found_path = None;
        for p_str in &candidate_paths {
            let p = Path::new(p_str);
            if p.exists() {
                found_path = Some(p_str.to_string());
                break;
            }
        }

        let is_ready = found_path.is_some() || Path::new(r"\\.\USBPcap1").exists();

        ComponentStatus {
            id: "usbpcap".to_string(),
            name: "USBPcap 内核级 USB 总线捕获驱动".to_string(),
            category: "HardwareDriver".to_string(),
            is_ready,
            version: if is_ready { Some("USBPcap Driver Active".to_string()) } else { None },
            path: found_path,
            capability_enabled: "解锁物理 USB 根集线器 (Root Hub) 全双工 URB 数据包微秒级物理抓取、BadUSB 自动化打字机恶意攻击审计 (IAT < 25ms 亚人类击键特征感知)、U 盘物理 SCSI 指令/大容量存储协议还原，以及 USB 转串口芯片底层控制信令分析。".to_string(),
            fallback_mode: "【严重功能受限】缺失 USBPcap 驱动时，系统将被迫放弃物理 USB 总线原始通信截获能力，无法感知 BadUSB 硬件固件伪装与物理层攻击，USB 深度工作台将被迫降级为仅监听只读的 Windows PnP 设备热插拔事件，无法获取任何 USB 载荷与控制帧；网络以太网嗅探与串口 COM 通信不受影响。".to_string(),
            official_url: "https://desowin.org/usbpcap/".to_string(),
            install_tips: "可在安装 Wireshark 时勾选【Install USBPcap】驱动组件；亦可点击右侧【自动从官网安装】一键下载安装。安装完成后需重启操作系统使底层内核服务生效。".to_string(),
            can_auto_install: true,
            installer_filename: Some("USBPcapSetup-1.5.4.0.exe".to_string()),
            estimated_size_mb: Some(0.19),
        }
    }

    /// 探活 Windows 进程是否拥有管理员特权 (Administrator)
    pub fn inspect_admin_privilege() -> ComponentStatus {
        let is_admin = Self::check_is_admin();

        ComponentStatus {
            id: "admin".to_string(),
            name: "操作系统管理员特权 (Administrator)".to_string(),
            category: "SystemPrivilege".to_string(),
            is_ready: is_admin,
            version: None,
            path: None,
            capability_enabled: "开启网卡硬件混杂模式配置权限、Raw Socket SIO_RCVALL 网卡监听与低层驱动安全访问。".to_string(),
            fallback_mode: "普通用户权限下仅能监听本进程绑定的网络端口，无法截获全网段广播与第三方主机流量。".to_string(),
            official_url: "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/".to_string(),
            install_tips: "右键单击 Omni-Probe 桌面图标，选择【以管理员身份运行】即可一键激活全部底层特权。".to_string(),
            can_auto_install: false,
            installer_filename: None,
            estimated_size_mb: None,
        }
    }

    /// 探活 ip2region.xdb 离线 IP 地理情报数据库 (千万级离线地理信息)
    pub fn inspect_ip_db() -> ComponentStatus {
        let is_loaded = if let Ok(engine) = crate::ip_intelligence::GLOBAL_IP_ENGINE.lock() {
            engine.is_xdb_loaded()
        } else {
            false
        };

        let candidate_paths = [
            "data/ip2region.xdb",
            "src-tauri/data/ip2region.xdb",
            "ip2region.xdb",
            "../data/ip2region.xdb",
        ];

        let mut found_path = None;
        let mut file_size_mb = None;

        for p_str in &candidate_paths {
            let p = Path::new(p_str);
            if p.exists() {
                if let Ok(meta) = std::fs::metadata(p) {
                    if meta.len() >= 5 * 1024 * 1024 {
                        found_path = Some(p_str.to_string());
                        file_size_mb = Some((meta.len() as f64) / (1024.0 * 1024.0));
                        break;
                    }
                }
            }
        }

        let is_ready = is_loaded || found_path.is_some();
        let version = if is_ready {
            Some(format!("ip2region v2.0 XDB ({:.2} MB)", file_size_mb.unwrap_or(11.5)))
        } else {
            None
        };

        ComponentStatus {
            id: "ip_db".to_string(),
            name: "ip2region.xdb 离线 IP 地理情报库".to_string(),
            category: "IntelligenceDatabase".to_string(),
            is_ready,
            version,
            path: found_path,
            capability_enabled: "解锁千万级公网 IPv4 物理地理位置（国家、省份、城市、运营商 ISP）微秒级精准离线解析，赋能全球网络态势地图与地理测地追踪。".to_string(),
            fallback_mode: "已自动激活内置多轨自愈引擎：启用内存最长前缀 LPM 内网 CIDR 规则字典、全球权威骨干基础设施静态表与 RFC 1918 私网分类，免外部文件离线运行。".to_string(),
            official_url: "https://github.com/lionsoul2014/ip2region".to_string(),
            install_tips: "可将 ip2region.xdb 文件置于程序根目录下的 data 目录中，亦可点击右侧【自动从官网下载】一键流式载入。".to_string(),
            can_auto_install: true,
            installer_filename: Some("ip2region.xdb".to_string()),
            estimated_size_mb: Some(11.5),
        }
    }

    /// 获取官方安全下载源元数据
    pub fn get_official_installer_meta(component_id: &str) -> Option<OfficialInstallerMeta> {
        match component_id {
            "npcap" => Some(OfficialInstallerMeta {
                component_id: "npcap".to_string(),
                direct_download_url: "https://npcap.com/dist/npcap-1.80.exe".to_string(),
                target_filename: "npcap-1.80.exe".to_string(),
                estimated_size_bytes: 1_202_472,
            }),
            "usbpcap" => Some(OfficialInstallerMeta {
                component_id: "usbpcap".to_string(),
                direct_download_url: "https://github.com/desowin/usbpcap/releases/download/1.5.4.0/USBPcapSetup-1.5.4.0.exe".to_string(),
                target_filename: "USBPcapSetup-1.5.4.0.exe".to_string(),
                estimated_size_bytes: 195_040,
            }),
            "tshark" | "wireshark" => Some(OfficialInstallerMeta {
                component_id: "tshark".to_string(),
                direct_download_url: "https://2.na.dl.wireshark.org/win64/Wireshark-win64-4.4.1.exe".to_string(),
                target_filename: "Wireshark-win64-4.4.1.exe".to_string(),
                estimated_size_bytes: 84_400_000,
            }),
            "ip_db" | "ip2region" => Some(OfficialInstallerMeta {
                component_id: "ip_db".to_string(),
                direct_download_url: "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region.xdb".to_string(),
                target_filename: "ip2region.xdb".to_string(),
                estimated_size_bytes: 12_000_000,
            }),
            _ => None,
        }
    }

    /// 从官方源异步流式下载安装包并安全启动安装程序向导
    pub async fn download_and_launch_installer<R: tauri::Runtime>(
        app: tauri::AppHandle<R>,
        component_id: String,
    ) -> Result<String, String> {
        use tauri::Emitter;
        use tokio::io::AsyncWriteExt;

        let meta = Self::get_official_installer_meta(&component_id)
            .ok_or_else(|| format!("未知的可安装组件: {}", component_id))?;

        let temp_dir = std::env::temp_dir().join("omni_probe_installers");
        if !temp_dir.exists() {
            std::fs::create_dir_all(&temp_dir).map_err(|e| format!("创建临时安装目录失败: {}", e))?;
        }
        let dest_path = temp_dir.join(&meta.target_filename);

        // 广播开始下载事件
        let _ = app.emit("installer-download-progress", InstallerDownloadProgress {
            component_id: component_id.clone(),
            status: "downloading".to_string(),
            percent: 0.0,
            downloaded_bytes: 0,
            total_bytes: meta.estimated_size_bytes,
            error_msg: None,
        });

        // 构造安全请求
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(180))
            .build()
            .map_err(|e| format!("构建 HTTP 下载客户端失败: {}", e))?;

        let mut res = client.get(&meta.direct_download_url)
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .send()
            .await
            .map_err(|e| format!("连接官方下载源失败: {}", e))?;

        if !res.status().is_success() {
            let err_msg = format!("官方下载服务器返回异常状态码: {}", res.status());
            let _ = app.emit("installer-download-progress", InstallerDownloadProgress {
                component_id: component_id.clone(),
                status: "error".to_string(),
                percent: 0.0,
                downloaded_bytes: 0,
                total_bytes: meta.estimated_size_bytes,
                error_msg: Some(err_msg.clone()),
            });
            return Err(err_msg);
        }

        let total_size = res.content_length().unwrap_or(meta.estimated_size_bytes);
        let mut file = tokio::fs::File::create(&dest_path)
            .await
            .map_err(|e| format!("创建安装包本地文件失败: {}", e))?;

        let mut downloaded_bytes = 0u64;
        let mut last_emit_percent = 0.0;

        // 流式分块写入
        while let Some(chunk) = res.chunk().await.map_err(|e| format!("流式下载中断: {}", e))? {
            downloaded_bytes += chunk.len() as u64;
            file.write_all(&chunk).await.map_err(|e| format!("写入磁盘失败: {}", e))?;

            let percent = if total_size > 0 {
                ((downloaded_bytes as f64 / total_size as f64) * 100.0).min(100.0)
            } else {
                50.0
            };

            // 控制事件广播频率（每跨越 2% 广播一次）
            if percent - last_emit_percent >= 2.0 || percent >= 100.0 {
                last_emit_percent = percent;
                let _ = app.emit("installer-download-progress", InstallerDownloadProgress {
                    component_id: component_id.clone(),
                    status: "downloading".to_string(),
                    percent,
                    downloaded_bytes,
                    total_bytes: total_size,
                    error_msg: None,
                });
            }
        }

        file.flush().await.map_err(|e| format!("同步文件磁盘失败: {}", e))?;
        drop(file);

        // 广播准备启动向导事件
        let _ = app.emit("installer-download-progress", InstallerDownloadProgress {
            component_id: component_id.clone(),
            status: "launching".to_string(),
            percent: 100.0,
            downloaded_bytes,
            total_bytes: downloaded_bytes,
            error_msg: None,
        });

        // 区分可执行安装向导与离线数据库热挂载
        if component_id == "ip_db" || meta.target_filename.ends_with(".xdb") {
            let target_dir = std::path::PathBuf::from("data");
            let _ = std::fs::create_dir_all(&target_dir);
            let final_path = target_dir.join("ip2region.xdb");
            let _ = std::fs::copy(&dest_path, &final_path);

            if let Ok(mut engine) = crate::ip_intelligence::GLOBAL_IP_ENGINE.lock() {
                let _ = engine.load_xdb(final_path.to_str().unwrap_or_default());
            }

            // 广播成功挂载事件
            let _ = app.emit("installer-download-progress", InstallerDownloadProgress {
                component_id: component_id.clone(),
                status: "completed".to_string(),
                percent: 100.0,
                downloaded_bytes,
                total_bytes: downloaded_bytes,
                error_msg: None,
            });

            Ok(format!(
                "已成功从官方下载 {} 并热挂载至 IP 地理情报引擎！",
                meta.target_filename
            ))
        } else {
            // 启动 Windows 官方安装向导
            Self::launch_executable_installer(&dest_path)?;

            // 广播成功启动向导事件
            let _ = app.emit("installer-download-progress", InstallerDownloadProgress {
                component_id: component_id.clone(),
                status: "completed".to_string(),
                percent: 100.0,
                downloaded_bytes,
                total_bytes: downloaded_bytes,
                error_msg: None,
            });

            Ok(format!(
                "已成功从官方下载 {} 并唤起安装向导，请在弹出的系统窗口中完成安装。",
                meta.target_filename
            ))
        }
    }

    /// 跨平台安全启动安装包向导可执行程序
    pub fn launch_executable_installer(exe_path: &Path) -> Result<(), String> {
        #[cfg(windows)]
        {
            use std::process::Command;
            Command::new(exe_path)
                .spawn()
                .map_err(|e| format!("启动安装程序向导进程失败: {}", e))?;
            Ok(())
        }

        #[cfg(not(windows))]
        {
            let _ = exe_path;
            Err("非 Windows 平台不支持此格式安装程序".to_string())
        }
    }

    /// 内部安全检测是否以管理员身份运行
    #[cfg(windows)]
    fn check_is_admin() -> bool {
        unsafe {
            #[link(name = "shell32")]
            extern "system" {
                fn IsUserAnAdmin() -> i32;
            }
            IsUserAnAdmin() != 0
        }
    }

    #[cfg(not(windows))]
    fn check_is_admin() -> bool {
        true
    }
}

// ==============================================================================
// 单元测试与边界推演
// ==============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_inspection_sanity_and_scoring() {
        let report = EnvironmentInspector::inspect_all();
        assert!(report.readiness_score <= 100);
        assert_eq!(report.components.len(), 5);
        assert!(!report.checked_at.is_empty());
        assert!(["Optimal", "Standard", "Degraded"].contains(&report.status_level.as_str()));

        // 验证五项核心组件齐全
        let ids: Vec<&str> = report.components.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"npcap"));
        assert!(ids.contains(&"tshark"));
        assert!(ids.contains(&"usbpcap"));
        assert!(ids.contains(&"ip_db"));
        assert!(ids.contains(&"admin"));
    }

    #[test]
    fn test_component_status_fallback_consistency() {
        let npcap = EnvironmentInspector::inspect_npcap();
        assert!(!npcap.capability_enabled.is_empty());
        assert!(!npcap.fallback_mode.is_empty());
        assert!(npcap.official_url.starts_with("https://"));
        assert!(npcap.can_auto_install);
        assert_eq!(npcap.installer_filename.as_deref(), Some("npcap-1.80.exe"));

        let tshark = EnvironmentInspector::inspect_tshark();
        assert!(tshark.official_url.contains("wireshark.org"));
        assert!(tshark.can_auto_install);
    }

    #[test]
    fn test_official_installer_metadata_registry() {
        let npcap_meta = EnvironmentInspector::get_official_installer_meta("npcap").unwrap();
        assert_eq!(npcap_meta.target_filename, "npcap-1.80.exe");
        assert!(npcap_meta.direct_download_url.contains("npcap.com/dist"));
        assert!(npcap_meta.estimated_size_bytes > 1_000_000);

        let usbpcap_meta = EnvironmentInspector::get_official_installer_meta("usbpcap").unwrap();
        assert_eq!(usbpcap_meta.target_filename, "USBPcapSetup-1.5.4.0.exe");

        assert!(EnvironmentInspector::get_official_installer_meta("unknown_xxx").is_none());
    }
}
