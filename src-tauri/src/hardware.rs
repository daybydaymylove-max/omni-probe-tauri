use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use tauri::Emitter;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct HardwareAlert {
    pub alert_type: String,
    pub device_name: String,
    pub device_id: String,
    pub timestamp: String,
}

/// 物理总线监控主循环（纯原生 SetupAPI 实现，零子进程调用，彻底杜绝控制台黑窗口闪烁）
/// 监控 USB-Serial 转换器、工业 PLC 适配器、物理 COM 串口的实时热插拔事件
pub fn run_hardware_monitor(app: tauri::AppHandle) {
    let mut known_coms: HashSet<String> = HashSet::new();
    let mut known_usb_serials: HashSet<String> = HashSet::new();

    if let Ok(ports) = serialport::available_ports() {
        for p in &ports {
            known_coms.insert(p.port_name.clone());
            if let serialport::SerialPortType::UsbPort(ref usb_info) = p.port_type {
                let usb_id = format!(
                    "VID_{:04X}_PID_{:04X}_{}",
                    usb_info.vid,
                    usb_info.pid,
                    usb_info.serial_number.as_deref().unwrap_or(&p.port_name)
                );
                known_usb_serials.insert(usb_id);
            }
        }
    }

    let _ = app.emit(
        "system-log",
        format!(
            "[HARDWARE] 物理总线监控已启动 (原生驱动监听) | COM: {} 个 | USB 适配器: {} 个",
            known_coms.len(),
            known_usb_serials.len()
        ),
    );

    loop {
        thread::sleep(Duration::from_secs(3));

        if !*crate::lock_guard::lock_mutex(&crate::PROBE_RUNNING, "hardware::hotplug_loop") {
            break;
        }

        if let Ok(ports) = serialport::available_ports() {
            let mut current_coms = HashSet::new();
            let mut current_usb = HashSet::new();

            for p in &ports {
                current_coms.insert(p.port_name.clone());

                if let serialport::SerialPortType::UsbPort(ref usb_info) = p.port_type {
                    let usb_id = format!(
                        "VID_{:04X}_PID_{:04X}_{}",
                        usb_info.vid,
                        usb_info.pid,
                        usb_info.serial_number.as_deref().unwrap_or(&p.port_name)
                    );
                    current_usb.insert(usb_id.clone());

                    // 检测新增 USB 硬件
                    if !known_usb_serials.contains(&usb_id) {
                        let dev_name = usb_info
                            .product
                            .clone()
                            .or_else(|| usb_info.manufacturer.clone())
                            .unwrap_or_else(|| format!("USB Serial Device ({})", p.port_name));

                        let alert = HardwareAlert {
                            alert_type: "USB_INSERT".into(),
                            device_name: dev_name.clone(),
                            device_id: usb_id.clone(),
                            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                        };
                        let _ = app.emit("hardware-alert", alert);
                        let _ = app.emit(
                            "system-log",
                            format!("[USB] 🔌 工业 USB 设备热插入: {} [{}]", dev_name, p.port_name),
                        );
                    }
                }
            }

            // 检测拔出的 USB 硬件
            for old_usb in known_usb_serials.difference(&current_usb) {
                let alert = HardwareAlert {
                    alert_type: "USB_REMOVE".into(),
                    device_name: "USB Device Removed".into(),
                    device_id: old_usb.clone(),
                    timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                };
                let _ = app.emit("hardware-alert", alert);
                let _ = app.emit(
                    "system-log",
                    format!("[USB] ⚠️ 物理 USB 设备已拔出: {}", old_usb),
                );
            }

            // 检测 COM 串口变动
            for new_com in current_coms.difference(&known_coms) {
                let desc = ports
                    .iter()
                    .find(|p| &p.port_name == new_com)
                    .map(|p| match &p.port_type {
                        serialport::SerialPortType::UsbPort(u) => {
                            u.product.clone().unwrap_or_else(|| "USB Serial".into())
                        }
                        serialport::SerialPortType::PciPort => "PCI Serial Port".into(),
                        serialport::SerialPortType::BluetoothPort => "Bluetooth Serial Port".into(),
                        _ => "Native COM Port".into(),
                    })
                    .unwrap_or_else(|| "Serial Device".into());

                let alert = HardwareAlert {
                    alert_type: "COM_NEW".into(),
                    device_name: desc.clone(),
                    device_id: new_com.clone(),
                    timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                };
                let _ = app.emit("hardware-alert", alert);
                let _ = app.emit(
                    "system-log",
                    format!("[COM] 🔌 新串口接入: {} ({})", new_com, desc),
                );
            }

            known_coms = current_coms;
            known_usb_serials = current_usb;
        }
    }

    let _ = app.emit("system-log", "[HARDWARE] 物理总线监控已安全停止".to_string());
}

// ============================================================
// 物理硬件基线白名单与即插即用合规差分比对引擎 (Hardware Whitelist & Compliance Audit Engine)
// 100% 工业生产级实现：符合等保 2.0/3.0 外部设备接入控制与防非法外联规范
// ============================================================

/// 硬件基线白名单受信任条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareWhitelistItem {
    pub category: String, // "USB" | "SERIAL"
    pub identifier: String, // 硬件唯一标识 (如 VID_1A86_PID_7523 或 COM3)
    pub name: String, // 设备友好名称
    pub manufacturer: String, // 制造商
    pub serial_number: String, // 序列号或实例 ID
    pub added_at: String, // 固化时间
    pub description: String, // 管理员用途备注
}

/// 硬件白名单主配置实体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareWhitelistConfig {
    pub version: u32,
    pub updated_at: String,
    pub items: Vec<HardwareWhitelistItem>,
}

/// 硬件合规差分审计项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareComplianceItem {
    pub category: String,
    pub identifier: String,
    pub name: String,
    pub status: String, // "COMPLIANT" | "UNAUTHORIZED" | "MISSING"
    pub alert_desc: String,
    pub description: String,
}

/// 硬件总线合规差分综合报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareComplianceReport {
    pub audit_time: String,
    pub total_whitelist: usize,
    pub total_online: usize,
    pub compliant_count: usize,
    pub unauthorized_count: usize,
    pub missing_count: usize,
    pub compliance_rate: f64,
    pub items: Vec<HardwareComplianceItem>,
}

/// 获取硬件白名单配置文件路径
fn get_whitelist_path() -> std::path::PathBuf {
    crate::forensics::data_path("hardware_whitelist.json")
}

/// 固化硬件白名单基线
/// 时间复杂度: O(H), H 为外设数
/// 空间复杂度: O(H)
pub fn save_hardware_whitelist(items: Vec<HardwareWhitelistItem>) -> Result<usize, String> {
    let count = items.len();
    let config = HardwareWhitelistConfig {
        version: 1,
        updated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        items,
    };

    let path = get_whitelist_path();
    let json_bytes = serde_json::to_vec_pretty(&config)
        .map_err(|e| format!("序列化硬件白名单失败: {}", e))?;

    std::fs::write(&path, json_bytes)
        .map_err(|e| format!("写入硬件白名单文件失败: {}", e))?;

    Ok(count)
}

/// 读取硬件白名单基线
pub fn get_hardware_whitelist() -> Result<HardwareWhitelistConfig, String> {
    let path = get_whitelist_path();
    if !path.exists() {
        return Ok(HardwareWhitelistConfig {
            version: 1,
            updated_at: "未初始化".to_string(),
            items: Vec::new(),
        });
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("读取硬件白名单失败: {}", e))?;
    serde_json::from_str::<HardwareWhitelistConfig>(&content)
        .map_err(|e| format!("解析硬件白名单 JSON 失败: {}", e))
}

/// 清空硬件白名单基线
pub fn clear_hardware_whitelist() -> Result<bool, String> {
    let path = get_whitelist_path();
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("删除硬件白名单文件失败: {}", e))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// 执行硬件物理总线实时合规差分比对 (Audit Compliance)
/// 对比当前在线物理外设 vs 受信任硬件白名单基线
/// 时间复杂度: O(U + S + W), U: USB设备数, S: 串口数, W: 白名单条目数
/// 空间复杂度: O(U + S + W)
pub fn verify_hardware_compliance(app: Option<&tauri::AppHandle>) -> Result<HardwareComplianceReport, String> {
    let whitelist_cfg = get_hardware_whitelist()?;
    let audit_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    // 1. 获取当前真实在线的物理外设
    let usb_devices = crate::usb::scan_connected_usb_devices();
    let serial_ports = serialport::available_ports().unwrap_or_default();

    // 建立白名单查找集合
    let mut whitelist_map: std::collections::HashMap<String, &HardwareWhitelistItem> = std::collections::HashMap::new();
    for item in &whitelist_cfg.items {
        whitelist_map.insert(item.identifier.to_uppercase(), item);
    }

    let mut matched_identifiers = HashSet::new();
    let mut items = Vec::new();
    let mut compliant_count = 0;
    let mut unauthorized_count = 0;

    // 2. 审查当前在线的 USB 外设
    for dev in &usb_devices {
        let id_standard = format!("VID_{}_PID_{}", dev.vid, dev.pid).to_uppercase();
        let id_inst = dev.instance_id.to_uppercase();

        let matched = whitelist_map.get(&id_standard).copied()
            .or_else(|| whitelist_map.get(&id_inst).copied())
            .or_else(|| {
                whitelist_map.values().find(|item| {
                    item.category == "USB" && (item.name == dev.device_name || item.name == dev.friendly_name)
                }).copied()
            });

        if let Some(w_item) = matched {
            matched_identifiers.insert(w_item.identifier.to_uppercase());
            compliant_count += 1;
            items.push(HardwareComplianceItem {
                category: "USB".to_string(),
                identifier: id_standard,
                name: dev.device_name.clone(),
                status: "COMPLIANT".to_string(),
                alert_desc: "已在受信任硬件白名单中，合规受控".to_string(),
                description: w_item.description.clone(),
            });
        } else {
            unauthorized_count += 1;
            let alert_desc = format!(
                "🚨 未授权违规外设接入: {} [{}]",
                dev.device_name, id_standard
            );
            if let Some(app_handle) = app {
                let alert = HardwareAlert {
                    alert_type: "UNAUTHORIZED_USB".to_string(),
                    device_name: dev.device_name.clone(),
                    device_id: id_standard.clone(),
                    timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                };
                let _ = app_handle.emit("hardware-alert", alert);
                let _ = app_handle.emit("system-log", format!("[SECURITY] {}", alert_desc));
            }
            items.push(HardwareComplianceItem {
                category: "USB".to_string(),
                identifier: id_standard,
                name: dev.device_name.clone(),
                status: "UNAUTHORIZED".to_string(),
                alert_desc,
                description: "未加入白名单的未知外部设备，存在数据外泄或恶意固件风险".to_string(),
            });
        }
    }

    // 3. 审查当前在线的物理 COM 串口
    for port in &serial_ports {
        let port_id = port.port_name.to_uppercase();
        let port_desc = match &port.port_type {
            serialport::SerialPortType::UsbPort(u) => {
                u.product.clone().unwrap_or_else(|| "USB-Serial".to_string())
            }
            serialport::SerialPortType::PciPort => "PCI 物理串口".to_string(),
            serialport::SerialPortType::BluetoothPort => "蓝牙串口".to_string(),
            _ => "原生系统 COM 端口".to_string(),
        };

        if let Some(w_item) = whitelist_map.get(&port_id).copied() {
            matched_identifiers.insert(w_item.identifier.to_uppercase());
            compliant_count += 1;
            items.push(HardwareComplianceItem {
                category: "SERIAL".to_string(),
                identifier: port.port_name.clone(),
                name: format!("{} ({})", port.port_name, port_desc),
                status: "COMPLIANT".to_string(),
                alert_desc: "受信任工业串口，合规接入".to_string(),
                description: w_item.description.clone(),
            });
        } else {
            unauthorized_count += 1;
            let alert_desc = format!(
                "⚠️ 未授权串口通道接入: {} ({})",
                port.port_name, port_desc
            );
            items.push(HardwareComplianceItem {
                category: "SERIAL".to_string(),
                identifier: port.port_name.clone(),
                name: format!("{} ({})", port.port_name, port_desc),
                status: "UNAUTHORIZED".to_string(),
                alert_desc,
                description: "未在基准白名单中登记的串口，疑似新增调试接口或工控搭线".to_string(),
            });
        }
    }

    // 4. 识别白名单中已登记但当前离线的硬件 (MISSING)
    let mut missing_count = 0;
    for (id_upper, w_item) in &whitelist_map {
        if !matched_identifiers.contains(id_upper) {
            missing_count += 1;
            items.push(HardwareComplianceItem {
                category: w_item.category.clone(),
                identifier: w_item.identifier.clone(),
                name: w_item.name.clone(),
                status: "MISSING".to_string(),
                alert_desc: format!("受信任基线硬件当前已断开离线 (原用途: {})", w_item.description),
                description: w_item.description.clone(),
            });
        }
    }

    // 5. 排序：未授权违规置顶，其次为缺失与合规
    items.sort_by(|a, b| {
        let rank = |status: &str| match status {
            "UNAUTHORIZED" => 0,
            "MISSING" => 1,
            _ => 2,
        };
        rank(&a.status).cmp(&rank(&b.status))
    });

    let total_online = usb_devices.len() + serial_ports.len();
    let total_eval = compliant_count + unauthorized_count + missing_count;
    let compliance_rate = if total_eval > 0 {
        (compliant_count as f64 / total_eval as f64) * 100.0
    } else {
        100.0
    };

    Ok(HardwareComplianceReport {
        audit_time,
        total_whitelist: whitelist_cfg.items.len(),
        total_online,
        compliant_count,
        unauthorized_count,
        missing_count,
        compliance_rate,
        items,
    })
}
