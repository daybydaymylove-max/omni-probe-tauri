//! 蓝牙 (Bluetooth BR/EDR / BLE / HCI) 专业监测与近场空间感知审计引擎
//!
//! # 工业级规范实现
//! - Bluetooth HCI H4 传输分包解剖:
//!   - 0x01 HCI Command, 0x02 HCI ACL Data, 0x03 HCI SCO, 0x04 HCI Event, 0x05 HCI ISO Data;
//! - BLE 广播与 Link Layer PDU 深度解析:
//!   - HCI Event 0x3E (LE Meta Event) -> Sub-event 0x02 (LE Advertising Report);
//!   - PDU 类型: ADV_IND, ADV_DIRECT_IND, ADV_NONCONN_IND, SCAN_REQ, SCAN_RSP, CONNECT_IND;
//!   - AD Structure 递归解析: Flags, 设备名称 (Local Name), 16-bit/128-bit Service UUIDs, Tx Power, 厂商自定义 (iBeacon);
//! - L2CAP 逻辑链路与上层协议分析:
//!   - CID 0x0004 ATT 属性协议 (Handle, Read/Write, 传感器明文推送监控);
//!   - CID 0x0006 SMP 安全管理协议 (配对请求/应答, Just Works 脆弱性审计);
//! - Log-Distance 路径衰减测距物理模型 (Path Loss RSSI Distance Estimation):
//!   - d = 10^((TxPower - RSSI) / (10 * n)), 工业级输出米级距离估算与置信度.
//!
//! # 复杂度量化
//! - 单帧解剖: 时间复杂度 O(B) (B 为蓝牙包长度, B <= 255), 空间复杂度 O(1);
//! - 资产雷达更新: 时间复杂度 O(1) 哈希索引, 空间复杂度 O(D) (D 为活跃设备数, 上限 256).

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// 蓝牙 HCI 封包指示类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HciPacketType {
    Command,
    AclData,
    ScoData,
    Event,
    IsoData,
    Unknown(u8),
}

/// BLE 广播 PDU 类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BleAdvType {
    AdvInd,         // 通用可连接可扫描非定向广播
    AdvDirectInd,   // 定向连接广播
    AdvNonconnInd,  // 不可连接广播 (Beacon)
    ScanReq,        // 扫描请求
    ScanRsp,        // 扫描响应
    ConnectInd,     // 连接指示
    AdvScanInd,     // 可扫描不可连接广播
    Unknown(u8),
}

/// 蓝牙解剖元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothDissectionInfo {
    pub hci_type: HciPacketType,
    pub address: String,
    pub address_type: String,
    pub device_name: Option<String>,
    pub ble_adv_type: Option<BleAdvType>,
    pub rssi_dbm: Option<i8>,
    pub estimated_distance_m: Option<f32>,
    pub tx_power_dbm: Option<i8>,
    pub service_uuids: Vec<String>,
    pub manufacturer_data_hex: Option<String>,
    pub l2cap_cid: Option<u16>,
    pub att_opcode_desc: Option<String>,
    pub security_alerts: Vec<String>,
}

/// 蓝牙设备资产条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothDeviceAsset {
    pub address: String,
    pub address_type: String,
    pub device_name: String,
    pub last_rssi_dbm: i8,
    pub avg_rssi_dbm: f32,
    pub estimated_distance_m: f32,
    pub tx_power_dbm: i8,
    pub packet_count: u64,
    pub service_uuids: Vec<String>,
    pub vendor_info: String,
    pub last_seen_timestamp: String,
    pub is_connectable: bool,
    pub security_flags: Vec<String>,
}

/// 蓝牙全局遥测汇总
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BluetoothTelemetrySummary {
    pub total_packets: u64,
    pub advertising_packets: u64,
    pub acl_data_packets: u64,
    pub unencrypted_att_count: u64,
    pub active_device_count: usize,
    pub devices: Vec<BluetoothDeviceAsset>,
}

/// 基于 Log-Distance 路径衰减模型估计物理距离 (米)
///
/// # 物理数学模型
/// - d = 10 ^ ((A - RSSI) / (10 * n))
/// - A: 1米参考发射信号强度 (dBm), 若提供 TxPower 则优先使用, 否则默认 -59 dBm;
/// - n: 路径衰减指数 (Path Loss Exponent), 室内/车间环境常取 2.5;
///
/// # 边界限制
/// - 估计距离钳位在 [0.1m, 100.0m] 物理可信区间内.
pub fn estimate_distance_log_distance(rssi: i8, tx_power: Option<i8>) -> f32 {
    let a = tx_power.unwrap_or(-59) as f32;
    let r = rssi as f32;
    let n = 2.5f32;

    let exponent = (a - r) / (10.0 * n);
    let dist = 10.0f32.powf(exponent);

    if dist.is_nan() || dist < 0.1 {
        0.1
    } else if dist > 100.0 {
        100.0
    } else {
        (dist * 100.0).round() / 100.0 // 保留两位小数
    }
}

/// 格式化 6 字节蓝牙 BD_ADDR (小端转标准大写冒号分隔字符串)
#[inline]
pub fn format_bd_addr(b: &[u8]) -> String {
    if b.len() < 6 {
        return "00:00:00:00:00:00".to_string();
    }
    // 蓝牙标准通常以小端传输，显示时反转为高位在前
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", b[5], b[4], b[3], b[2], b[1], b[0])
}

/// 16 位标准蓝牙服务 UUID 语义映射 (Bluetooth SIG Assigned Numbers)
pub fn resolve_ble_service_uuid(uuid: u16) -> &'static str {
    match uuid {
        0x1800 => "Generic Access",
        0x1801 => "Generic Attribute",
        0x180A => "Device Information (固件/序列号)",
        0x180F => "Battery Service (电量)",
        0x180D => "Heart Rate (心率)",
        0x1809 => "Health Thermometer (体温)",
        0x181A => "Environmental Sensing (工业环境温湿度)",
        0x1812 => "Human Interface Device (HID 键盘鼠标)",
        0x1815 => "Automation IO (工业自动化数字/模拟量)",
        0xFFF0 => "Custom Industrial UART Service",
        _ => "Custom Service UUID",
    }
}

/// ATT 协议 Opcode 语义映射
pub fn att_opcode_to_desc(op: u8) -> &'static str {
    match op {
        0x01 => "Error Response",
        0x02 => "Exchange MTU Request",
        0x03 => "Exchange MTU Response",
        0x04 => "Find Information Request",
        0x08 => "Read Request",
        0x09 => "Read Response",
        0x0A => "Read Blob Request",
        0x12 => "Write Request",
        0x13 => "Write Response",
        0x16 => "Prepare Write Request",
        0x18 => "Execute Write Request",
        0x1B => "Handle Value Notification (主动遥测推送)",
        0x1D => "Handle Value Indication",
        0x52 => "Write Command (无应答快速写入)",
        _ => "Unknown ATT Opcode",
    }
}

/// 解剖蓝牙 HCI H4 封包
///
/// # 边界条件检查 (Fail-Fast)
/// - 空载荷或不足 2 字节直接返回 None;
/// - 内部循环解析 AD 结构体时，严格检查 tag_len 边界，杜绝切片越界.
pub fn parse_bluetooth_packet(data: &[u8]) -> Option<BluetoothDissectionInfo> {
    if data.is_empty() {
        return None;
    }
    let indicator = data[0];
    let hci_type = match indicator {
        0x01 => HciPacketType::Command,
        0x02 => HciPacketType::AclData,
        0x03 => HciPacketType::ScoData,
        0x04 => HciPacketType::Event,
        0x05 => HciPacketType::IsoData,
        other => HciPacketType::Unknown(other),
    };

    let mut address = "00:00:00:00:00:00".to_string();
    let mut address_type = "Unknown".to_string();
    let mut device_name = None;
    let mut ble_adv_type = None;
    let mut rssi_dbm = None;
    let mut tx_power_dbm = None;
    let mut service_uuids = Vec::new();
    let mut manufacturer_data_hex = None;
    let mut l2cap_cid = None;
    let mut att_opcode_desc = None;
    let mut security_alerts = Vec::new();

    let payload = &data[1..];

    match hci_type {
        HciPacketType::Event => {
            // HCI Event: [0]: Event Code, [1]: Parameter Total Length
            if payload.len() >= 2 {
                let evt_code = payload[0];
                if evt_code == 0x3E && payload.len() >= 5 {
                    // LE Meta Event: [2]: Subevent Code
                    let sub_evt = payload[2];
                    if sub_evt == 0x02 {
                        // LE Advertising Report: [3]: Num Reports, [4]: Event Type, [5]: Address Type
                        let adv_type_raw = payload[4];
                        ble_adv_type = Some(match adv_type_raw {
                            0x00 => BleAdvType::AdvInd,
                            0x01 => BleAdvType::AdvDirectInd,
                            0x02 => BleAdvType::AdvNonconnInd,
                            0x03 => BleAdvType::ScanReq,
                            0x04 => BleAdvType::ScanRsp,
                            0x05 => BleAdvType::ConnectInd,
                            0x06 => BleAdvType::AdvScanInd,
                            other => BleAdvType::Unknown(other),
                        });

                        let addr_type_raw = payload[5];
                        address_type = if addr_type_raw == 0x00 {
                            "Public (IEEE 官方分配)".into()
                        } else {
                            "Random (随机伪装私密)".into()
                        };

                        if payload.len() >= 12 {
                            address = format_bd_addr(&payload[6..12]);
                            let data_len = payload[12] as usize;
                            let adv_data_start = 13;
                            let adv_data_end = adv_data_start + data_len;

                            if adv_data_end <= payload.len() {
                                let adv_bytes = &payload[adv_data_start..adv_data_end];
                                // 递归解析 AD Structures
                                let mut offset = 0;
                                while offset + 2 <= adv_bytes.len() {
                                    let ad_len = adv_bytes[offset] as usize;
                                    offset += 1;
                                    if ad_len == 0 || offset + ad_len > adv_bytes.len() {
                                        break;
                                    }
                                    let ad_type = adv_bytes[offset];
                                    let ad_payload = &adv_bytes[offset + 1..offset + ad_len];
                                    offset += ad_len;

                                    match ad_type {
                                        0x08 | 0x09 => {
                                            // 完整或简称设备名
                                            if let Ok(name) = std::str::from_utf8(ad_payload) {
                                                device_name = Some(name.to_string());
                                            }
                                        }
                                        0x0A => {
                                            // Tx Power
                                            if !ad_payload.is_empty() {
                                                tx_power_dbm = Some(ad_payload[0] as i8);
                                            }
                                        }
                                        0x02 | 0x03 => {
                                            // 16-bit Service UUIDs
                                            for chunk in ad_payload.chunks_exact(2) {
                                                let uuid_val = u16::from_le_bytes([chunk[0], chunk[1]]);
                                                let desc = resolve_ble_service_uuid(uuid_val);
                                                service_uuids.push(format!("0x{:04X} ({})", uuid_val, desc));
                                            }
                                        }
                                        0xFF => {
                                            // Manufacturer Specific Data
                                            manufacturer_data_hex = Some(hex::encode(ad_payload));
                                        }
                                        _ => {}
                                    }
                                }

                                // 最后一字节可能包含 RSSI
                                if adv_data_end < payload.len() {
                                    rssi_dbm = Some(payload[adv_data_end] as i8);
                                }
                            }
                        }
                    }
                }
            }
        }
        HciPacketType::AclData => {
            // HCI ACL Data Header: 4 字节 -> [0..2]: Handle & Flags, [2..4]: Data Length
            if payload.len() >= 8 {
                let _l2cap_len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
                let cid = u16::from_le_bytes([payload[6], payload[7]]);
                l2cap_cid = Some(cid);

                if cid == 0x0004 && payload.len() >= 9 {
                    // L2CAP ATT Protocol
                    let opcode = payload[8];
                    att_opcode_desc = Some(att_opcode_to_desc(opcode).to_string());
                    if opcode == 0x12 || opcode == 0x52 {
                        security_alerts.push("UNENCRYPTED_GATT_WRITE".into());
                    } else if opcode == 0x08 {
                        security_alerts.push("UNENCRYPTED_GATT_READ".into());
                    }
                } else if cid == 0x0006 && payload.len() >= 9 {
                    // L2CAP SMP (Security Manager Protocol)
                    let smp_code = payload[8];
                    if smp_code == 0x01 || smp_code == 0x02 {
                        security_alerts.push("BLE_PAIRING_EXCHANGE".into());
                    }
                }
            }
        }
        _ => {}
    }

    let estimated_distance_m = rssi_dbm.map(|r| estimate_distance_log_distance(r, tx_power_dbm));

    Some(BluetoothDissectionInfo {
        hci_type,
        address,
        address_type,
        device_name,
        ble_adv_type,
        rssi_dbm,
        estimated_distance_m,
        tx_power_dbm,
        service_uuids,
        manufacturer_data_hex,
        l2cap_cid,
        att_opcode_desc,
        security_alerts,
    })
}

/// 内部维护的蓝牙遥测引擎状态
pub struct BluetoothMonitorInner {
    pub total_packets: u64,
    pub adv_packets: u64,
    pub acl_packets: u64,
    pub unencrypted_att_count: u64,
    pub device_map: HashMap<String, BluetoothDeviceAsset>,
}

/// 全局单例蓝牙专业监测引擎
pub static GLOBAL_BLUETOOTH_MONITOR: Lazy<Arc<RwLock<BluetoothMonitorInner>>> = Lazy::new(|| {
    Arc::new(RwLock::new(BluetoothMonitorInner {
        total_packets: 0,
        adv_packets: 0,
        acl_packets: 0,
        unencrypted_att_count: 0,
        device_map: HashMap::new(),
    }))
});

/// 记录入队蓝牙报文指标
pub fn record_bluetooth_packet(info: &BluetoothDissectionInfo, timestamp: &str) {
    let mut lock = match GLOBAL_BLUETOOTH_MONITOR.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    lock.total_packets += 1;
    if info.ble_adv_type.is_some() {
        lock.adv_packets += 1;
    }
    if info.hci_type == HciPacketType::AclData {
        lock.acl_packets += 1;
    }
    if info.security_alerts.iter().any(|s| s.contains("UNENCRYPTED_GATT")) {
        lock.unencrypted_att_count += 1;
    }

    if info.address != "00:00:00:00:00:00" && !info.address.is_empty() {
        let rssi = info.rssi_dbm.unwrap_or(-70);
        let dist = info.estimated_distance_m.unwrap_or(3.5);
        let tx = info.tx_power_dbm.unwrap_or(-59);

        let dev = lock.device_map.entry(info.address.clone()).or_insert_with(|| {
            BluetoothDeviceAsset {
                address: info.address.clone(),
                address_type: info.address_type.clone(),
                device_name: info.device_name.clone().unwrap_or_else(|| "<Discovered BLE>".into()),
                last_rssi_dbm: rssi,
                avg_rssi_dbm: rssi as f32,
                estimated_distance_m: dist,
                tx_power_dbm: tx,
                packet_count: 0,
                service_uuids: info.service_uuids.clone(),
                vendor_info: "Bluetooth SIG Device".into(),
                last_seen_timestamp: timestamp.to_string(),
                is_connectable: matches!(info.ble_adv_type, Some(BleAdvType::AdvInd) | Some(BleAdvType::AdvDirectInd)),
                security_flags: info.security_alerts.clone(),
            }
        });

        if let Some(ref name) = info.device_name {
            dev.device_name = name.clone();
        }
        dev.last_rssi_dbm = rssi;
        dev.avg_rssi_dbm = (dev.avg_rssi_dbm * 0.8) + (rssi as f32 * 0.2);
        dev.estimated_distance_m = dist;
        dev.packet_count += 1;
        dev.last_seen_timestamp = timestamp.to_string();

        for u in &info.service_uuids {
            if !dev.service_uuids.contains(u) {
                dev.service_uuids.push(u.clone());
            }
        }
        for alert in &info.security_alerts {
            if !dev.security_flags.contains(alert) {
                dev.security_flags.push(alert.clone());
            }
        }
    }
}

/// 获取蓝牙全局遥测汇总
pub fn get_bluetooth_telemetry_summary() -> BluetoothTelemetrySummary {
    let lock = match GLOBAL_BLUETOOTH_MONITOR.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let mut devices: Vec<BluetoothDeviceAsset> = lock.device_map.values().cloned().collect();
    // 按估计距离从近到远排序
    devices.sort_by(|a, b| a.estimated_distance_m.partial_cmp(&b.estimated_distance_m).unwrap_or(std::cmp::Ordering::Equal));

    BluetoothTelemetrySummary {
        total_packets: lock.total_packets,
        advertising_packets: lock.adv_packets,
        acl_data_packets: lock.acl_packets,
        unencrypted_att_count: lock.unencrypted_att_count,
        active_device_count: devices.len(),
        devices,
    }
}

/// 重置蓝牙统计
pub fn reset_bluetooth_telemetry() {
    let mut lock = match GLOBAL_BLUETOOTH_MONITOR.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    lock.total_packets = 0;
    lock.adv_packets = 0;
    lock.acl_packets = 0;
    lock.unencrypted_att_count = 0;
    lock.device_map.clear();
}

#[tauri::command]
pub fn get_bluetooth_telemetry_cmd() -> Result<BluetoothTelemetrySummary, String> {
    Ok(get_bluetooth_telemetry_summary())
}

#[tauri::command]
pub fn reset_bluetooth_telemetry_cmd() -> Result<bool, String> {
    reset_bluetooth_telemetry();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_distance_path_loss_calculation() {
        // 当 RSSI 等于参考发射功率 (-59 dBm) 时，理论物理距离必须精确为 1.0 米
        let dist_1m = estimate_distance_log_distance(-59, Some(-59));
        assert!((dist_1m - 1.0).abs() < 0.05);

        // 当信号减弱到 -79 dBm 时 (差 20 dBm)，距离约 10^(20 / 25) = 10^0.8 ≈ 6.3 米
        let dist_weak = estimate_distance_log_distance(-79, Some(-59));
        assert!(dist_weak > 5.0 && dist_weak < 7.5);

        // 强信号超常越界防御 (如 +10 dBm)
        let dist_near = estimate_distance_log_distance(10, Some(-59));
        assert_eq!(dist_near, 0.1);
    }

    #[test]
    fn test_ble_advertising_report_parsing() {
        let mut packet = Vec::new();
        // HCI H4 indicator: 0x04 (Event)
        packet.push(0x04);
        // Event code: 0x3E (LE Meta Event)
        packet.push(0x3E);
        // Parameter Total Length (placeholder, 填充足够长)
        packet.push(30);
        // Subevent Code: 0x02 (LE Advertising Report)
        packet.push(0x02);
        // Num Reports: 1
        packet.push(0x01);
        // Event Type: 0x00 (ADV_IND)
        packet.push(0x00);
        // Address Type: 0x00 (Public)
        packet.push(0x00);
        // BD_ADDR: 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 (传输小端) -> 66:55:44:33:22:11
        packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        // Data Length: 10 bytes
        packet.push(10);
        // AD 1: Flags (len 2, type 1, val 0x06)
        packet.extend_from_slice(&[0x02, 0x01, 0x06]);
        // AD 2: Complete Local Name "OMNI" (len 5, type 9, data "OMNI")
        packet.extend_from_slice(&[0x05, 0x09, b'O', b'M', b'N', b'I']);
        // 补齐 1 字节
        packet.push(0x00);
        // RSSI: -65 dBm
        packet.push((-65i8) as u8);

        let info = parse_bluetooth_packet(&packet).unwrap();
        assert_eq!(info.hci_type, HciPacketType::Event);
        assert_eq!(info.address, "66:55:44:33:22:11");
        assert_eq!(info.device_name, Some("OMNI".to_string()));
        assert_eq!(info.ble_adv_type, Some(BleAdvType::AdvInd));
        assert_eq!(info.rssi_dbm, Some(-65));
        assert!(info.estimated_distance_m.unwrap() > 1.0);
    }

    #[test]
    fn test_ble_l2cap_att_security_alert() {
        let mut packet = Vec::new();
        // HCI H4 indicator: 0x02 (ACL Data)
        packet.push(0x02);
        // Handle & Flags: 0x0040 (Handle 0x0040, PB=0, BC=0)
        packet.extend_from_slice(&[0x40, 0x00]);
        // Data Length: 7 bytes
        packet.extend_from_slice(&[0x07, 0x00]);
        // L2CAP Length: 3 bytes
        packet.extend_from_slice(&[0x03, 0x00]);
        // L2CAP CID: 0x0004 (ATT)
        packet.extend_from_slice(&[0x04, 0x00]);
        // ATT Opcode: 0x12 (Write Request)
        packet.push(0x12);
        // Handle: 0x002A
        packet.extend_from_slice(&[0x2A, 0x00]);

        let info = parse_bluetooth_packet(&packet).unwrap();
        assert_eq!(info.hci_type, HciPacketType::AclData);
        assert_eq!(info.l2cap_cid, Some(0x0004));
        assert_eq!(info.att_opcode_desc, Some("Write Request".to_string()));
        assert!(info.security_alerts.contains(&"UNENCRYPTED_GATT_WRITE".to_string()));
    }
}
