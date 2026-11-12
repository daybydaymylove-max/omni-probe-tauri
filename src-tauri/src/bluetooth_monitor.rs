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
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// BLE AD (Advertising Data) 单段 TLV 结构分解条目
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BleAdSectionItem {
    pub ad_type: u8,
    pub ad_type_name: String,
    pub data_hex: String,
    pub decoded_summary: String,
}

/// 蓝牙实时底层报文时间线条目 (含空口 AD、BTHPORT-ETW 原生 HCI/L2CAP 与 USB-HCI)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothFrameLogItem {
    pub id: u64,
    pub timestamp: String,
    pub source: String,
    pub direction: String,
    pub protocol_layer: String,
    pub address: String,
    pub rssi_dbm: Option<i8>,
    pub length: usize,
    pub summary: String,
    pub raw_hex: String,
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
    #[serde(default)]
    pub company_id: Option<u16>,
    #[serde(default)]
    pub vendor_name: Option<String>,
    #[serde(default)]
    pub phy_desc: Option<String>,
    #[serde(default)]
    pub appearance_desc: Option<String>,
    #[serde(default)]
    pub beacon_decoded: Option<String>,
    #[serde(default)]
    pub ad_sections: Vec<BleAdSectionItem>,
    #[serde(default)]
    pub raw_hex: String,
    #[serde(default)]
    pub arrival_timestamp_ms: Option<u64>,
    #[serde(default)]
    pub source_tag: Option<String>,
    #[serde(default)]
    pub conn_handle: Option<u16>,
    #[serde(default)]
    pub negotiated_mtu: Option<u16>,
    #[serde(default)]
    pub learned_handles: Vec<(u16, String)>,
    #[serde(default)]
    pub att_op_kind: Option<String>,
    #[serde(default)]
    pub encryption_enabled: Option<bool>,
}

/// 蓝牙点对点 ACL / ATT / SMP 会话状态机快照 (按 Connection Handle 追踪)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothConnectionSession {
    pub conn_handle: u16,
    pub peer_address: String,
    pub negotiated_mtu: u16,
    pub att_reads: u64,
    pub att_writes: u64,
    pub att_notifies: u64,
    pub smp_events: u64,
    pub encrypted: bool,
    pub handle_uuid_map: Vec<(u16, String)>,
    pub last_seen_timestamp: String,
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
    #[serde(default)]
    pub min_rssi_dbm: i8,
    #[serde(default)]
    pub max_rssi_dbm: i8,
    #[serde(default)]
    pub phy_desc: String,
    #[serde(default)]
    pub company_id: Option<u16>,
    #[serde(default)]
    pub appearance_desc: Option<String>,
    #[serde(default)]
    pub beacon_summary: Option<String>,
    #[serde(default)]
    pub adv_interval_ms: Option<f32>,
    #[serde(default)]
    pub last_arrival_ms: u64,
    #[serde(default)]
    pub adv_window_start_ms: u64,
    #[serde(default)]
    pub adv_window_count: u32,
    #[serde(default)]
    pub packet_rate_pps: f32,
    #[serde(default)]
    pub ad_sections: Vec<BleAdSectionItem>,
    #[serde(default)]
    pub manufacturer_data_hex: Option<String>,
    #[serde(default)]
    pub raw_frame_hex: String,
    #[serde(default)]
    pub rssi_stddev: f32,
    #[serde(default)]
    pub stability_score: f32,
    #[serde(skip)]
    pub rssi_window: VecDeque<i8>,
    #[serde(skip)]
    pub last_persisted_ms: u64,
}

/// 蓝牙 RSSI 时序采样点 (供前端近场信号趋势折线图绘制)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothRssiSample {
    pub timestamp: String,
    pub address: String,
    pub rssi_dbm: i8,
    pub distance_m: f32,
}

/// 操作系统原生蓝牙适配器信息 (来自 Win32 bthprops.cpl)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeBluetoothAdapterInfo {
    pub name: String,
    pub address: String,
    pub class_of_device: String,
    pub manufacturer_id: u16,
    pub lmp_subversion: u16,
}

/// 操作系统原生已配对/已发现蓝牙设备 (来自 Win32 bthprops.cpl)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeBluetoothDeviceInfo {
    pub name: String,
    pub address: String,
    pub class_of_device: String,
    pub connected: bool,
    pub remembered: bool,
    pub authenticated: bool,
    pub last_seen: String,
    pub last_used: String,
}

/// 原生蓝牙硬件探测聚合结果 (严格区分有硬件与无硬件/无支持平台)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeBluetoothScanResult {
    pub native_scan_available: bool,
    pub platform: String,
    pub inquiry_executed: bool,
    pub ble_adv_count: usize,
    pub adapters: Vec<NativeBluetoothAdapterInfo>,
    pub devices: Vec<NativeBluetoothDeviceInfo>,
    pub diagnostic_message: String,
    pub summary: BluetoothTelemetrySummary,
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
    pub rssi_history: Vec<BluetoothRssiSample>,
    #[serde(default)]
    pub hci_command_packets: u64,
    #[serde(default)]
    pub hci_event_packets: u64,
    #[serde(default)]
    pub continuous_ble_active: bool,
    #[serde(default)]
    pub bthport_etw_active: bool,
    #[serde(default)]
    pub bthport_etw_status: String,
    #[serde(default)]
    pub recent_frames: Vec<BluetoothFrameLogItem>,
    #[serde(default)]
    pub active_sessions: Vec<BluetoothConnectionSession>,
}

/// 蓝牙持久化历史时序记录 (写入 bluetooth_history.jsonl 供实时 vs 历史对比与离线回溯)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothHistoryRecord {
    pub epoch_ms: u64,
    pub timestamp: String,
    pub address: String,
    pub address_type: String,
    pub device_name: String,
    pub vendor_info: String,
    pub rssi_dbm: i8,
    pub estimated_distance_m: f32,
    pub adv_interval_ms: Option<f32>,
    pub packet_rate_pps: f32,
    pub rssi_stddev: f32,
    pub stability_score: f32,
    pub phy_desc: String,
    pub security_flags: Vec<String>,
    #[serde(default)]
    pub protocol_layer: String,
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
        0x181A => "Environmental Sensing (环境温湿度)",
        0x1812 => "HID (键盘/鼠标/手柄)",
        0x1815 => "Automation IO (工业自动化IO)",
        0x1827 => "Mesh Provisioning Service",
        0x1828 => "Mesh Proxy Service",
        0xFE2C => "Google Fast Pair",
        0xFE95 => "Xiaomi MiBeacon (小米 IoT)",
        0xFE9F => "Google Nearby / FastPair",
        0xFEAA => "Google Eddystone Beacon",
        0xFEAB => "Nokia Corp Beacon",
        0xFEED => "Tile Tracker",
        0xFD6F => "COVID-19 Exposure Notification",
        0xFFF0 => "Custom Industrial UART",
        _ => "Custom Service UUID",
    }
}

/// Bluetooth SIG 官方 Company Identifier 厂商名称映射 (O(1) 常数查找)
pub fn resolve_ble_company_name(company_id: u16) -> &'static str {
    match company_id {
        0x0002 => "Intel Corp.",
        0x0006 => "Microsoft",
        0x000A => "Qualcomm Technologies",
        0x000D => "Texas Instruments",
        0x000F => "Broadcom",
        0x001D => "Qualcomm Intl",
        0x004C => "Apple Inc.",
        0x0057 => "Harman / JBL",
        0x0059 => "Nordic Semiconductor",
        0x005D => "Realtek Semiconductor",
        0x006B => "Polar Electro",
        0x0075 => "Samsung Electronics",
        0x0087 => "Garmin",
        0x009E => "Bose Corp.",
        0x00D2 => "Dialog Semiconductor",
        0x00E0 => "Google LLC",
        0x010F => "HiSilicon / Huawei",
        0x012D => "Sony Corp.",
        0x0131 => "Cypress Semiconductor",
        0x0157 => "Anhui Huami (Zepp/Amazfit)",
        0x0171 => "Amazon.com Services",
        0x0227 => "Fitbit",
        0x026B => "Tile Inc.",
        0x027D => "Huawei Technologies",
        0x02E5 => "Espressif Systems (ESP32)",
        0x038F => "Xiaomi Inc.",
        0x0499 => "Ruuvi Innovations",
        0x05A7 => "Sonos Inc.",
        0x0757 => "Honor Device Co.",
        0x0822 => "Shenzhen Goodix",
        _ => "Bluetooth SIG Assigned",
    }
}

/// GAP Appearance 标准外观分类解码 (Bluetooth SIG Assigned Numbers §2.6)
pub fn resolve_ble_appearance(code: u16) -> &'static str {
    match code {
        0x0000 => "Unknown Device",
        0x0040 => "Phone (手机)",
        0x0080 => "Computer (主机/PC)",
        0x00C0 | 0x00C1 => "Watch / Sports Watch",
        0x0140 => "Display (显示器)",
        0x0180 => "Remote Control (遥控器)",
        0x0340 | 0x0341 => "Heart Rate Sensor",
        0x03C0 => "HID Generic",
        0x03C1 => "Keyboard (无线键盘)",
        0x03C2 => "Mouse (无线鼠标)",
        0x03C3 => "Joystick (游戏手柄)",
        0x04C0 => "Thermometer (温度计)",
        0x0540 | 0x0541 => "Pulse Oximeter / Health Sensor",
        0x0941 => "Headphones / Earbuds (耳机)",
        0x0942 => "Speaker (音箱)",
        _ => {
            let category = code >> 6;
            match category {
                1 => "Phone",
                2 => "Computer",
                3 => "Watch",
                15 => "HID Peripheral",
                21 => "Audio / Wearable",
                _ => "Custom Appearance",
            }
        }
    }
}

/// GAP AD Type 协议标签译名
pub fn resolve_ad_type_name(ad_type: u8) -> &'static str {
    match ad_type {
        0x01 => "Flags",
        0x02 => "Incomplete 16-bit Service UUIDs",
        0x03 => "Complete 16-bit Service UUIDs",
        0x04 => "Incomplete 32-bit Service UUIDs",
        0x05 => "Complete 32-bit Service UUIDs",
        0x06 => "Incomplete 128-bit Service UUIDs",
        0x07 => "Complete 128-bit Service UUIDs",
        0x08 => "Shortened Local Name",
        0x09 => "Complete Local Name",
        0x0A => "Tx Power Level",
        0x0D => "Class of Device",
        0x14 => "List of 16-bit Service Solicitation UUIDs",
        0x16 => "Service Data - 16-bit UUID",
        0x19 => "Appearance",
        0x1A => "Advertising Interval",
        0x20 => "Service Data - 32-bit UUID",
        0x21 => "Service Data - 128-bit UUID",
        0x24 => "URI",
        0xFF => "Manufacturer Specific Data",
        _ => "Extended AD Structure",
    }
}

/// 单帧 AD TLV 解析汇总结果
#[derive(Debug, Clone, Default)]
pub struct ParsedAdSummary {
    pub device_name: Option<String>,
    pub tx_power_dbm: Option<i8>,
    pub service_uuids: Vec<String>,
    pub company_id: Option<u16>,
    pub vendor_name: Option<String>,
    pub manufacturer_data_hex: Option<String>,
    pub appearance_desc: Option<String>,
    pub beacon_decoded: Option<String>,
    pub ad_sections: Vec<BleAdSectionItem>,
    pub security_alerts: Vec<String>,
}

/// 深度解读厂商自定义字节段 (0xFF Manufacturer Specific Data)
/// 支持: Apple iBeacon / Continuity / AirPods / FindMy, Microsoft SwiftPair 等
fn decode_manufacturer_payload(company_id: u16, payload: &[u8]) -> (String, Vec<String>) {
    let company = resolve_ble_company_name(company_id);
    let mut alerts = Vec::new();
    match company_id {
        0x004C => {
            if payload.len() >= 23 && payload[0] == 0x02 && payload[1] == 0x15 {
                let uuid = format!(
                    "{}-{}-{}-{}-{}",
                    hex::encode_upper(&payload[2..6]),
                    hex::encode_upper(&payload[6..8]),
                    hex::encode_upper(&payload[8..10]),
                    hex::encode_upper(&payload[10..12]),
                    hex::encode_upper(&payload[12..18])
                );
                let major = u16::from_be_bytes([payload[18], payload[19]]);
                let minor = u16::from_be_bytes([payload[20], payload[21]]);
                let cal_tx = payload[22] as i8;
                return (
                    format!("Apple iBeacon | UUID={} Major={} Minor={} CalTx={}dBm", uuid, major, minor, cal_tx),
                    alerts,
                );
            }
            if !payload.is_empty() {
                let summary = match payload[0] {
                    0x05 => "Apple AirDrop Discovery".to_string(),
                    0x07 => {
                        let status = if payload.len() > 2 { format!("Model=0x{:02X}{:02X}", payload[2], payload[1]) } else { "Proximity".into() };
                        format!("Apple AirPods / Beats Proximity ({})", status)
                    }
                    0x09 => "Apple AirPlay Target".to_string(),
                    0x0C => "Apple Handoff".to_string(),
                    0x0F => "Apple Nearby Action (弹窗/配对动作)".to_string(),
                    0x10 => {
                        let action = payload.get(2).copied().unwrap_or(0);
                        format!("Apple Nearby Info (State=0x{:02X})", action)
                    }
                    0x12 => {
                        alerts.push("APPLE_FINDMY_TRACKER".into());
                        "Apple FindMy / AirTag 离线位置信标".to_string()
                    }
                    t => format!("Apple Continuity Type 0x{:02X} ({}B)", t, payload.len()),
                };
                return (summary, alerts);
            }
            ("Apple Inc. Empty Mfg Payload".to_string(), alerts)
        }
        0x0006 => {
            if payload.len() >= 3 && payload[0] == 0x01 && (payload[1] & 0x0F) == 0x09 {
                return ("Microsoft CDP (跨设备协同接力)".to_string(), alerts);
            }
            if payload.len() >= 3 && payload[0] == 0x03 && payload[1] == 0x00 {
                let tail = String::from_utf8_lossy(&payload[3..]).trim().to_string();
                let label = if tail.is_empty() { "SwiftPair 快速配对弹窗" } else { &tail };
                alerts.push("MSFT_SWIFTPAIR_ACTIVE".into());
                return (format!("Microsoft SwiftPair: {}", label), alerts);
            }
            (format!("Microsoft Data ({}B)", payload.len()), alerts)
        }
        _ => (format!("{} (0x{:04X}) 载荷 {}B", company, company_id, payload.len()), alerts),
    }
}

/// 深度解析 BLE 16-bit Service Data (AD Type 0x16): Eddystone (UID/URL/TLM) & MiBeacon
fn decode_service_data_16(uuid16: u16, data: &[u8]) -> Option<String> {
    match uuid16 {
        0xFEAA if !data.is_empty() => match data[0] {
            0x00 if data.len() >= 18 => {
                let tx = data[1] as i8;
                let ns = hex::encode_upper(&data[2..12]);
                let inst = hex::encode_upper(&data[12..18]);
                Some(format!("Eddystone-UID NS={} Inst={} Tx={}dBm", ns, inst, tx))
            }
            0x10 if data.len() >= 3 => {
                let prefix = match data[2] {
                    0x00 => "http://www.",
                    0x01 => "https://www.",
                    0x02 => "http://",
                    0x03 => "https://",
                    _ => "",
                };
                let url_body = String::from_utf8_lossy(&data[3..]);
                Some(format!("Eddystone-URL {}{}", prefix, url_body))
            }
            0x20 if data.len() >= 14 => {
                let mv = u16::from_be_bytes([data[2], data[3]]);
                let temp = (data[4] as i8) as f32 + (data[5] as f32) / 256.0;
                let adv_cnt = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
                Some(format!("Eddystone-TLM 电量={}mV 芯片温度={:.1}°C 发包={}", mv, temp, adv_cnt))
            }
            ft => Some(format!("Eddystone Frame 0x{:02X} ({}B)", ft, data.len())),
        },
        0xFE95 if data.len() >= 5 => {
            let fctrl = u16::from_le_bytes([data[0], data[1]]);
            let prod_id = u16::from_le_bytes([data[2], data[3]]);
            let seq = data[4];
            let has_obj = (fctrl & 0x0040) != 0;
            Some(format!("Xiaomi MiBeacon Pid=0x{:04X} Seq={} HasObj={}", prod_id, seq, has_obj))
        }
        0x181A => Some(format!("Environmental Sensing Data ({}B)", data.len())),
        0x180F if !data.is_empty() => Some(format!("Battery Level Service Data: {}%", data[0])),
        _ => None,
    }
}

/// 解析原始连续 AD Structure 字节流 ([len, type, payload...])
/// 时间复杂度: O(L) 单遍流式扫描 (L 为 AD 总字节长), 空间复杂度: O(K) 分段数量
pub fn decode_ad_tlv_bytes(raw_ad: &[u8]) -> ParsedAdSummary {
    let mut out = ParsedAdSummary::default();
    let mut offset = 0usize;
    while offset + 2 <= raw_ad.len() {
        let ad_len = raw_ad[offset] as usize;
        offset += 1;
        if ad_len == 0 || offset + ad_len > raw_ad.len() {
            break;
        }
        let ad_type = raw_ad[offset];
        let payload = &raw_ad[offset + 1..offset + ad_len];
        offset += ad_len;
        decode_single_ad_section(ad_type, payload, &mut out);
    }
    out
}

/// 处理单段 (ad_type, ad_payload)，供 HCI TLV 与 WinRT DataSections 统一复用
pub fn decode_single_ad_section(ad_type: u8, payload: &[u8], out: &mut ParsedAdSummary) {
    let type_name = resolve_ad_type_name(ad_type).to_string();
    let data_hex = hex::encode_upper(payload);
    let mut decoded_summary = String::new();

    match ad_type {
        0x01 if !payload.is_empty() => {
            let f = payload[0];
            let mut tags = Vec::new();
            if (f & 0x01) != 0 { tags.push("LE Limited"); }
            if (f & 0x02) != 0 { tags.push("LE General"); }
            if (f & 0x04) != 0 { tags.push("BR/EDR NotSupported"); }
            if (f & 0x08) != 0 { tags.push("Simultaneous LE+BR/EDR(Ctrl)"); }
            if (f & 0x10) != 0 { tags.push("Simultaneous LE+BR/EDR(Host)"); }
            decoded_summary = if tags.is_empty() { format!("0x{:02X}", f) } else { tags.join(" | ") };
        }
        0x02 | 0x03 => {
            let mut list = Vec::new();
            for chunk in payload.chunks_exact(2) {
                let u = u16::from_le_bytes([chunk[0], chunk[1]]);
                let s = format!("0x{:04X} ({})", u, resolve_ble_service_uuid(u));
                if !out.service_uuids.contains(&s) {
                    out.service_uuids.push(s.clone());
                }
                list.push(s);
            }
            decoded_summary = list.join(", ");
        }
        0x06 | 0x07 => {
            let mut list = Vec::new();
            for chunk in payload.chunks_exact(16) {
                let mut rev = chunk.to_vec();
                rev.reverse();
                let u = format!(
                    "{}-{}-{}-{}-{}",
                    hex::encode_upper(&rev[0..4]),
                    hex::encode_upper(&rev[4..6]),
                    hex::encode_upper(&rev[6..8]),
                    hex::encode_upper(&rev[8..10]),
                    hex::encode_upper(&rev[10..16])
                );
                if !out.service_uuids.contains(&u) {
                    out.service_uuids.push(u.clone());
                }
                list.push(u);
            }
            decoded_summary = list.join(", ");
        }
        0x08 | 0x09 => {
            let clean = String::from_utf8_lossy(payload).trim_matches('\0').trim().to_string();
            if !clean.is_empty() {
                if ad_type == 0x09 || out.device_name.is_none() {
                    out.device_name = Some(clean.clone());
                }
                decoded_summary = format!("Name=\"{}\"", clean);
            }
        }
        0x0A if !payload.is_empty() => {
            let tx = payload[0] as i8;
            out.tx_power_dbm = Some(tx);
            decoded_summary = format!("TxPower = {} dBm", tx);
        }
        0x16 if payload.len() >= 2 => {
            let uuid16 = u16::from_le_bytes([payload[0], payload[1]]);
            let svc_name = resolve_ble_service_uuid(uuid16);
            let s_label = format!("0x{:04X} ({})", uuid16, svc_name);
            if !out.service_uuids.contains(&s_label) {
                out.service_uuids.push(s_label);
            }
            if let Some(beacon_txt) = decode_service_data_16(uuid16, &payload[2..]) {
                out.beacon_decoded = Some(beacon_txt.clone());
                decoded_summary = beacon_txt;
            } else {
                decoded_summary = format!("Svc 0x{:04X} ({}) Data {}B", uuid16, svc_name, payload.len() - 2);
            }
        }
        0x19 if payload.len() >= 2 => {
            let code = u16::from_le_bytes([payload[0], payload[1]]);
            let app = resolve_ble_appearance(code);
            out.appearance_desc = Some(app.to_string());
            decoded_summary = format!("0x{:04X} ({})", code, app);
        }
        0xFF if payload.len() >= 2 => {
            let cid = u16::from_le_bytes([payload[0], payload[1]]);
            let cname = resolve_ble_company_name(cid);
            out.company_id = Some(cid);
            out.vendor_name = Some(cname.to_string());
            out.manufacturer_data_hex = Some(data_hex.clone());
            let (desc, alerts) = decode_manufacturer_payload(cid, &payload[2..]);
            for a in alerts {
                if !out.security_alerts.contains(&a) {
                    out.security_alerts.push(a);
                }
            }
            if out.beacon_decoded.is_none() {
                out.beacon_decoded = Some(desc.clone());
            }
            decoded_summary = desc;
        }
        _ => {
            decoded_summary = format!("Raw {}B", payload.len());
        }
    }

    out.ad_sections.push(BleAdSectionItem {
        ad_type,
        ad_type_name: type_name,
        data_hex,
        decoded_summary,
    });
}

/// 将 WinRT DataSections 重组为标准 IEEE/Bluetooth SIG LE Advertising Report (HCI Event 0x3E/0x02) 字节流
pub fn synthesize_hci_le_adv_packet(
    addr_u64: u64,
    addr_type_byte: u8,
    adv_type_byte: u8,
    raw_ad_tlv: &[u8],
    rssi: i8,
) -> Vec<u8> {
    let ad_cap = raw_ad_tlv.len().min(220);
    let mut pkt = Vec::with_capacity(16 + ad_cap);
    pkt.push(0x04); // HCI Event
    pkt.push(0x3E); // LE Meta Event
    pkt.push((12 + ad_cap).min(255) as u8);
    pkt.push(0x02); // Subevent: LE Advertising Report
    pkt.push(0x01); // Num Reports
    pkt.push(adv_type_byte);
    pkt.push(addr_type_byte);
    let b = addr_u64.to_le_bytes();
    pkt.extend_from_slice(&b[0..6]);
    pkt.push(ad_cap as u8);
    pkt.extend_from_slice(&raw_ad_tlv[..ad_cap]);
    pkt.push(rssi as u8);
    pkt
}

/// ATT 协议 Opcode 语义映射
pub fn att_opcode_to_desc(op: u8) -> &'static str {
    match op {
        0x01 => "Error Response",
        0x02 => "Exchange MTU Request",
        0x03 => "Exchange MTU Response",
        0x04 => "Find Information Request",
        0x05 => "Find Information Response",
        0x06 => "Find By Type Value Request",
        0x08 => "Read Request",
        0x09 => "Read Response",
        0x0A => "Read Blob Request",
        0x10 => "Read By Group Type Request",
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

#[inline]
pub fn now_monotonic_ms() -> u64 {
    static BOOT_INSTANT: Lazy<std::time::Instant> = Lazy::new(std::time::Instant::now);
    BOOT_INSTANT.elapsed().as_millis() as u64
}

/// 16 位常见 Bluetooth SIG GATT 特征 / 声明 UUID 解析
#[inline]
pub fn resolve_gatt_char_uuid16(uuid: u16) -> &'static str {
    match uuid {
        0x2800 => "Primary Service",
        0x2801 => "Secondary Service",
        0x2803 => "Characteristic Declaration",
        0x2900 => "Characteristic Extended Properties",
        0x2901 => "Characteristic User Description",
        0x2902 => "Client Characteristic Configuration (CCCD)",
        0x2A00 => "Device Name",
        0x2A01 => "Appearance",
        0x2A05 => "Service Changed",
        0x2A19 => "Battery Level",
        0x2A24 => "Model Number",
        0x2A25 => "Serial Number",
        0x2A26 => "Firmware Revision",
        0x2A27 => "Hardware Revision",
        0x2A29 => "Manufacturer Name",
        0x2A37 => "Heart Rate Measurement",
        0x2A6E => "Temperature",
        0x2A6F => "Humidity",
        _ => resolve_ble_service_uuid(uuid),
    }
}

/// 解剖蓝牙 HCI H4 封包 (支持 HCI Command 0x01 / ACL Data 0x02 / SCO 0x03 / Event 0x04)
/// 显式时空复杂度: 时间复杂度 O(B) (B 为单包字节长), 空间复杂度 O(B)
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
    let mut ble_adv_type = None;
    let mut rssi_dbm = None;
    let mut l2cap_cid = None;
    let mut att_opcode_desc = None;
    let mut security_alerts = Vec::new();
    let mut ad_parsed = ParsedAdSummary::default();
    let mut beacon_extra: Option<String> = None;
    let mut conn_handle_opt: Option<u16> = None;
    let mut negotiated_mtu: Option<u16> = None;
    let mut learned_handles: Vec<(u16, String)> = Vec::new();
    let mut att_op_kind: Option<String> = None;
    let mut encryption_enabled: Option<bool> = None;

    let payload = &data[1..];

    match hci_type {
        HciPacketType::Command => {
            if payload.len() >= 3 {
                let opcode = u16::from_le_bytes([payload[0], payload[1]]);
                let ogf = (opcode >> 10) & 0x3F;
                let ocf = opcode & 0x03FF;
                let cmd_name = match (ogf, ocf) {
                    (0x01, 0x0001) => "HCI_Inquiry",
                    (0x01, 0x0005) => "HCI_Create_Connection",
                    (0x04, 0x0009) => "HCI_Read_BD_ADDR",
                    (0x08, 0x000B) => "LE_Set_Scan_Parameters",
                    (0x08, 0x000C) => "LE_Set_Scan_Enable",
                    (0x08, 0x000D) => "LE_Create_Connection",
                    (0x08, 0x0041) => "LE_Set_Extended_Scan_Parameters",
                    (0x08, 0x0042) => "LE_Set_Extended_Scan_Enable",
                    _ => "HCI_Command",
                };
                beacon_extra = Some(format!("{} (OGF=0x{:02X} OCF=0x{:03X})", cmd_name, ogf, ocf));
            }
        }
        HciPacketType::Event => {
            if payload.len() >= 2 {
                let evt_code = payload[0];
                if evt_code == 0x3E && payload.len() >= 5 {
                    let sub_evt = payload[2];
                    if sub_evt == 0x02 && payload.len() >= 13 {
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
                        address_type = match addr_type_raw {
                            0x00 => "Public (IEEE 固定硬件地址)".into(),
                            0x01 => "Random (随机/RPA 地址)".into(),
                            _ => "Unspecified".into(),
                        };

                        address = format_bd_addr(&payload[6..12]);
                        let data_len = payload[12] as usize;
                        let adv_data_start = 13;
                        let adv_data_end = adv_data_start + data_len;

                        if adv_data_end <= payload.len() {
                            ad_parsed = decode_ad_tlv_bytes(&payload[adv_data_start..adv_data_end]);
                            if adv_data_end < payload.len() {
                                rssi_dbm = Some(payload[adv_data_end] as i8);
                            }
                        }
                    } else if (sub_evt == 0x01 || sub_evt == 0x0A) && payload.len() >= 14 {
                        // LE Connection Complete (0x01) / Enhanced (0x0A): [3]=Status, [4..6]=ConnHandle, [8..14]=PeerAddr
                        let ch = u16::from_le_bytes([payload[4], payload[5]]) & 0x0FFF;
                        conn_handle_opt = Some(ch);
                        address = format_bd_addr(&payload[8..14]);
                        beacon_extra = Some(format!("LE Connection Complete Handle=0x{:03X} Peer={}", ch, address));
                    } else {
                        let sub_name = match sub_evt {
                            0x04 => "LE Read Remote Features Complete",
                            0x0D => "LE Extended Advertising Report",
                            _ => "LE Meta SubEvent",
                        };
                        beacon_extra = Some(format!("{} (0x{:02X})", sub_name, sub_evt));
                    }
                } else {
                    if evt_code == 0x08 && payload.len() >= 6 {
                        let ch = u16::from_le_bytes([payload[3], payload[4]]) & 0x0FFF;
                        let enc = payload[5] != 0;
                        conn_handle_opt = Some(ch);
                        encryption_enabled = Some(enc);
                        beacon_extra = Some(format!("Encryption Change Handle=0x{:03X} Enabled={}", ch, enc));
                    } else {
                        let evt_name = match evt_code {
                            0x03 => "Connection Complete",
                            0x05 => "Disconnection Complete",
                            0x0E => "Command Complete",
                            0x0F => "Command Status",
                            0x13 => "Number Of Completed Packets",
                            _ => "HCI Event",
                        };
                        beacon_extra = Some(format!("{} (0x{:02X})", evt_name, evt_code));
                    }
                }
            }
        }
        HciPacketType::AclData => {
            if payload.len() >= 8 {
                let conn_handle = u16::from_le_bytes([payload[0], payload[1]]) & 0x0FFF;
                conn_handle_opt = Some(conn_handle);
                let cid = u16::from_le_bytes([payload[6], payload[7]]);
                l2cap_cid = Some(cid);
                let upper = &payload[8..];

                if cid == 0x0004 && !upper.is_empty() {
                    let opcode = upper[0];
                    let desc = att_opcode_to_desc(opcode);
                    let handle_hint = if upper.len() >= 3 && !matches!(opcode, 0x02 | 0x03 | 0x05) {
                        format!(" H=0x{:04X}", u16::from_le_bytes([upper[1], upper[2]]))
                    } else {
                        String::new()
                    };
                    att_opcode_desc = Some(desc.to_string());
                    beacon_extra = Some(format!("ACL Conn=0x{:03X} ATT {}{}", conn_handle, desc, handle_hint));

                    match opcode {
                        0x02 | 0x03 if upper.len() >= 3 => {
                            let mtu = u16::from_le_bytes([upper[1], upper[2]]);
                            negotiated_mtu = Some(mtu);
                            att_op_kind = Some("MTU".into());
                            beacon_extra = Some(format!("ACL Conn=0x{:03X} ATT {} MTU={}", conn_handle, desc, mtu));
                        }
                        0x05 if upper.len() >= 6 && upper[1] == 0x01 => {
                            // Find Information Response Format 1: Pairs of [Handle(2B LE), 16-bit UUID(2B LE)]
                            att_op_kind = Some("FIND_INFO".into());
                            for pair in upper[2..].chunks_exact(4) {
                                let h = u16::from_le_bytes([pair[0], pair[1]]);
                                let u16v = u16::from_le_bytes([pair[2], pair[3]]);
                                learned_handles.push((h, format!("0x{:04X} ({})", u16v, resolve_gatt_char_uuid16(u16v))));
                            }
                        }
                        0x08 | 0x09 | 0x0A => {
                            att_op_kind = Some("READ".into());
                            if opcode == 0x08 {
                                security_alerts.push("UNENCRYPTED_GATT_READ".into());
                            }
                        }
                        0x12 | 0x52 | 0x16 | 0x18 => {
                            att_op_kind = Some("WRITE".into());
                            if opcode == 0x12 || opcode == 0x52 {
                                security_alerts.push("UNENCRYPTED_GATT_WRITE".into());
                            }
                        }
                        0x1B | 0x1D => {
                            att_op_kind = Some("NOTIFY".into());
                        }
                        _ => {}
                    }
                } else if cid == 0x0006 && !upper.is_empty() {
                    att_op_kind = Some("SMP".into());
                    let smp_code = upper[0];
                    if (smp_code == 0x01 || smp_code == 0x02) && upper.len() >= 4 {
                        security_alerts.push("BLE_PAIRING_EXCHANGE".into());
                        let io_cap = upper[1];
                        let auth_req = upper[3];
                        let mitm = (auth_req & 0x04) != 0;
                        let sc = (auth_req & 0x08) != 0;
                        if io_cap == 0x03 || !mitm {
                            security_alerts.push("SMP_JUST_WORKS_NO_MITM".into());
                        }
                        if !sc {
                            security_alerts.push("SMP_LEGACY_PAIRING_NO_SC".into());
                        }
                        beacon_extra = Some(format!("SMP Pairing {} IO={} MITM={} SC={}", if smp_code == 1 { "Req" } else { "Rsp" }, io_cap, mitm, sc));
                    } else {
                        beacon_extra = Some(format!("L2CAP SMP Opcode 0x{:02X}", smp_code));
                    }
                } else {
                    beacon_extra = Some(format!("ACL Conn=0x{:03X} L2CAP CID=0x{:04X} ({}B)", conn_handle, cid, upper.len()));
                }
            }
        }
        _ => {}
    }

    for a in ad_parsed.security_alerts {
        if !security_alerts.contains(&a) {
            security_alerts.push(a);
        }
    }

    let estimated_distance_m = rssi_dbm.map(|r| estimate_distance_log_distance(r, ad_parsed.tx_power_dbm));
    let beacon_decoded = ad_parsed.beacon_decoded.or(beacon_extra);

    Some(BluetoothDissectionInfo {
        hci_type,
        address,
        address_type,
        device_name: ad_parsed.device_name,
        ble_adv_type,
        rssi_dbm,
        estimated_distance_m,
        tx_power_dbm: ad_parsed.tx_power_dbm,
        service_uuids: ad_parsed.service_uuids,
        manufacturer_data_hex: ad_parsed.manufacturer_data_hex,
        l2cap_cid,
        att_opcode_desc,
        security_alerts,
        company_id: ad_parsed.company_id,
        vendor_name: ad_parsed.vendor_name,
        phy_desc: Some("LE 1M".into()),
        appearance_desc: ad_parsed.appearance_desc,
        beacon_decoded,
        ad_sections: ad_parsed.ad_sections,
        raw_hex: hex::encode_upper(data),
        arrival_timestamp_ms: Some(now_monotonic_ms()),
        source_tag: None,
        conn_handle: conn_handle_opt,
        negotiated_mtu,
        learned_handles,
        att_op_kind,
        encryption_enabled,
    })
}

/// 全局实时监控开关状态
pub static CONTINUOUS_BLE_RUNNING: AtomicBool = AtomicBool::new(false);
pub static BTHPORT_ETW_ACTIVE: AtomicBool = AtomicBool::new(false);
static NEXT_BT_FRAME_ID: AtomicU64 = AtomicU64::new(1);

/// 内部维护的蓝牙遥测引擎状态
pub struct BluetoothMonitorInner {
    pub total_packets: u64,
    pub adv_packets: u64,
    pub acl_packets: u64,
    pub hci_cmd_packets: u64,
    pub hci_evt_packets: u64,
    pub unencrypted_att_count: u64,
    pub bthport_etw_status: String,
    pub device_map: HashMap<String, BluetoothDeviceAsset>,
    pub rssi_history: VecDeque<BluetoothRssiSample>,
    pub recent_frames: VecDeque<BluetoothFrameLogItem>,
    pub session_map: HashMap<u16, BluetoothConnectionSession>,
}

/// 全局单例蓝牙专业监测引擎
pub static GLOBAL_BLUETOOTH_MONITOR: Lazy<Arc<RwLock<BluetoothMonitorInner>>> = Lazy::new(|| {
    Arc::new(RwLock::new(BluetoothMonitorInner {
        total_packets: 0,
        adv_packets: 0,
        acl_packets: 0,
        hci_cmd_packets: 0,
        hci_evt_packets: 0,
        unencrypted_att_count: 0,
        bthport_etw_status: "未开启 (可选用 BTHPORT-ETW 采集驱动级 HCI/L2CAP 帧)".into(),
        device_map: HashMap::new(),
        rssi_history: VecDeque::new(),
        recent_frames: VecDeque::with_capacity(128),
        session_map: HashMap::new(),
    }))
});

/// 记录入队蓝牙报文指标、广播周期间隔估算与实时报文流水
/// 时间复杂度: O(1) 哈希索引及双端队列操作; 空间复杂度: O(D + W) (D<=512, W<=240)
pub fn record_bluetooth_packet(info: &BluetoothDissectionInfo, timestamp: &str) {
    let mut lock = match GLOBAL_BLUETOOTH_MONITOR.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    lock.total_packets += 1;
    if info.ble_adv_type.is_some() {
        lock.adv_packets += 1;
    }
    match info.hci_type {
        HciPacketType::AclData => lock.acl_packets += 1,
        HciPacketType::Command => lock.hci_cmd_packets += 1,
        HciPacketType::Event => lock.hci_evt_packets += 1,
        _ => {}
    }
    if info.security_alerts.iter().any(|s| s.contains("UNENCRYPTED_GATT") || s.contains("SMP_")) {
        lock.unencrypted_att_count += 1;
    }

    let arrival_ms = info.arrival_timestamp_ms.unwrap_or_else(now_monotonic_ms);

    let proto_layer = match info.hci_type {
        HciPacketType::Command => "HCI-CMD".to_string(),
        HciPacketType::AclData => match info.l2cap_cid {
            Some(0x0004) => "L2CAP-ATT".to_string(),
            Some(0x0006) => "L2CAP-SMP".to_string(),
            Some(0x0001 | 0x0005) => "L2CAP-SIG".to_string(),
            _ => "HCI-ACL".to_string(),
        },
        HciPacketType::Event if info.ble_adv_type.is_some() => "BLE-ADV".to_string(),
        HciPacketType::Event => "HCI-EVT".to_string(),
        _ => "HCI-OTHER".to_string(),
    };

    let mut persist_payload: Option<(BluetoothHistoryRecord, String, usize)> = None;

    if info.address != "00:00:00:00:00:00" && !info.address.is_empty() {
        let rssi = info.rssi_dbm.unwrap_or(-70);
        let dist = info.estimated_distance_m.unwrap_or_else(|| estimate_distance_log_distance(rssi, info.tx_power_dbm));
        let tx = info.tx_power_dbm.unwrap_or(-59);
        let vendor = info.vendor_name.clone().unwrap_or_else(|| "Bluetooth SIG Device".into());
        let phy = info.phy_desc.clone().unwrap_or_else(|| "LE 1M".into());

        // 防止未知地址无限爆内存 (上限 512 设备)
        if !lock.device_map.contains_key(&info.address) && lock.device_map.len() >= 512 {
            if let Some(oldest_k) = lock.device_map.values().min_by_key(|v| v.last_arrival_ms).map(|v| v.address.clone()) {
                lock.device_map.remove(&oldest_k);
            }
        }

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
                vendor_info: vendor.clone(),
                last_seen_timestamp: timestamp.to_string(),
                is_connectable: matches!(info.ble_adv_type, Some(BleAdvType::AdvInd) | Some(BleAdvType::AdvDirectInd)),
                security_flags: info.security_alerts.clone(),
                min_rssi_dbm: rssi,
                max_rssi_dbm: rssi,
                phy_desc: phy.clone(),
                company_id: info.company_id,
                appearance_desc: info.appearance_desc.clone(),
                beacon_summary: info.beacon_decoded.clone(),
                adv_interval_ms: None,
                last_arrival_ms: arrival_ms,
                adv_window_start_ms: arrival_ms,
                adv_window_count: 0,
                packet_rate_pps: 0.0,
                ad_sections: info.ad_sections.clone(),
                manufacturer_data_hex: info.manufacturer_data_hex.clone(),
                raw_frame_hex: info.raw_hex.clone(),
                rssi_stddev: 0.0,
                stability_score: 100.0,
                rssi_window: VecDeque::with_capacity(32),
                last_persisted_ms: 0,
            }
        });

        if let Some(ref name) = info.device_name {
            if !name.trim().is_empty() {
                dev.device_name = name.clone();
            }
        }
        if info.vendor_name.is_some() {
            dev.vendor_info = vendor;
        }
        if info.company_id.is_some() {
            dev.company_id = info.company_id;
        }
        if info.appearance_desc.is_some() {
            dev.appearance_desc = info.appearance_desc.clone();
        }
        if info.beacon_decoded.is_some() {
            dev.beacon_summary = info.beacon_decoded.clone();
        }
        if !info.ad_sections.is_empty() {
            dev.ad_sections = info.ad_sections.clone();
        }
        if info.manufacturer_data_hex.is_some() {
            dev.manufacturer_data_hex = info.manufacturer_data_hex.clone();
        }
        if !info.raw_hex.is_empty() {
            dev.raw_frame_hex = info.raw_hex.clone();
        }
        dev.phy_desc = phy;
        if let Some(t) = info.tx_power_dbm {
            dev.tx_power_dbm = t;
        }

        // 计算真实广播时间间隔 (ms) 与滑动吞吐包率 (pps)
        if dev.packet_count > 0 && arrival_ms > dev.last_arrival_ms {
            let delta = (arrival_ms - dev.last_arrival_ms) as f32;
            if (5.0..=15_000.0).contains(&delta) {
                dev.adv_interval_ms = Some(match dev.adv_interval_ms {
                    Some(prev) => (prev * 0.7) + (delta * 0.3),
                    None => delta,
                });
            }
        }
        dev.last_arrival_ms = arrival_ms;
        dev.adv_window_count = dev.adv_window_count.saturating_add(1);
        let win_elapsed = arrival_ms.saturating_sub(dev.adv_window_start_ms);
        if win_elapsed >= 1000 {
            dev.packet_rate_pps = (dev.adv_window_count as f32) / (win_elapsed as f32 / 1000.0);
            dev.adv_window_start_ms = arrival_ms;
            dev.adv_window_count = 0;
        } else if dev.packet_count > 1 && dev.adv_interval_ms.unwrap_or(0.0) >= 5.0 {
            dev.packet_rate_pps = 1000.0 / dev.adv_interval_ms.unwrap();
        }

        // 安全姿态深度评价：高速异常广播洪泛 & 静态 MAC 可追踪性
        if dev.packet_rate_pps > 25.0 || dev.adv_interval_ms.is_some_and(|ms| ms < 35.0) {
            if !dev.security_flags.contains(&"SUSPICIOUS_FAST_ADV_FLOOD".to_string()) {
                dev.security_flags.push("SUSPICIOUS_FAST_ADV_FLOOD".to_string());
            }
        }
        if dev.address_type.contains("Public") && !dev.security_flags.contains(&"STATIC_MAC_TRACKABLE".to_string()) {
            dev.security_flags.push("STATIC_MAC_TRACKABLE".to_string());
        }

        // 计算 RSSI 滑动窗口方差、标准差与信道链路稳定度评分 (W <= 32, 时间复杂度 O(1))
        if info.rssi_dbm.is_some() || dev.rssi_window.is_empty() {
            if dev.rssi_window.len() >= 32 {
                dev.rssi_window.pop_front();
            }
            dev.rssi_window.push_back(rssi);
            if dev.rssi_window.len() >= 2 {
                let n = dev.rssi_window.len() as f32;
                let mean = dev.rssi_window.iter().map(|&v| v as f32).sum::<f32>() / n;
                let var = dev.rssi_window
                    .iter()
                    .map(|&v| {
                        let d = (v as f32) - mean;
                        d * d
                    })
                    .sum::<f32>()
                    / n;
                let std = var.sqrt();
                dev.rssi_stddev = (std * 100.0).round() / 100.0;
                dev.stability_score = ((100.0 - std * 6.5).clamp(0.0, 100.0) * 10.0).round() / 10.0;
            } else {
                dev.rssi_stddev = 0.0;
                dev.stability_score = 100.0;
            }
        }

        dev.last_rssi_dbm = rssi;
        dev.min_rssi_dbm = dev.min_rssi_dbm.min(rssi);
        dev.max_rssi_dbm = dev.max_rssi_dbm.max(rssi);
        dev.avg_rssi_dbm = (dev.avg_rssi_dbm * 0.75) + (rssi as f32 * 0.25);
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

        // 节流持久化抽样 (首帧 / 关键安全会话事件 / >= 1500ms 间隔写一次，避免阻塞热路径)
        let has_critical = !info.security_alerts.is_empty()
            || info.att_op_kind.is_some()
            || info.conn_handle.is_some()
            || info.negotiated_mtu.is_some();
        if dev.packet_count == 1
            || has_critical
            || arrival_ms.saturating_sub(dev.last_persisted_ms) >= 1500
        {
            dev.last_persisted_ms = arrival_ms;
            let epoch_now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let full_ts = if timestamp.contains('T') || timestamp.contains('-') {
                timestamp.to_string()
            } else {
                format!("{} {}", chrono::Local::now().format("%Y-%m-%d"), timestamp)
            };
            persist_payload = Some((
                BluetoothHistoryRecord {
                    epoch_ms: epoch_now_ms,
                    timestamp: full_ts,
                    address: dev.address.clone(),
                    address_type: dev.address_type.clone(),
                    device_name: dev.device_name.clone(),
                    vendor_info: dev.vendor_info.clone(),
                    rssi_dbm: dev.last_rssi_dbm,
                    estimated_distance_m: dev.estimated_distance_m,
                    adv_interval_ms: dev.adv_interval_ms,
                    packet_rate_pps: dev.packet_rate_pps,
                    rssi_stddev: dev.rssi_stddev,
                    stability_score: dev.stability_score,
                    phy_desc: dev.phy_desc.clone(),
                    security_flags: dev.security_flags.clone(),
                    protocol_layer: proto_layer.clone(),
                },
                info.beacon_decoded
                    .clone()
                    .or_else(|| info.att_opcode_desc.clone())
                    .unwrap_or_default(),
                info.raw_hex.len() / 2,
            ));
        }
    }

    // 更新点对点 HCI/ACL/ATT/SMP 会话状态机 (按 ConnHandle 索引)
    if let Some(handle) = info.conn_handle {
        if !lock.session_map.contains_key(&handle) && lock.session_map.len() >= 64 {
            if let Some(oldest_h) = lock
                .session_map
                .values()
                .min_by(|a, b| a.last_seen_timestamp.cmp(&b.last_seen_timestamp))
                .map(|s| s.conn_handle)
            {
                lock.session_map.remove(&oldest_h);
            }
        }
        let sess = lock
            .session_map
            .entry(handle)
            .or_insert_with(|| BluetoothConnectionSession {
                conn_handle: handle,
                peer_address: if info.address.is_empty() || info.address == "00:00:00:00:00:00" {
                    format!("Handle-0x{:04X}", handle)
                } else {
                    info.address.clone()
                },
                negotiated_mtu: 23,
                att_reads: 0,
                att_writes: 0,
                att_notifies: 0,
                smp_events: 0,
                encrypted: false,
                handle_uuid_map: Vec::new(),
                last_seen_timestamp: timestamp.to_string(),
            });
        if !info.address.is_empty() && info.address != "00:00:00:00:00:00" {
            sess.peer_address = info.address.clone();
        }
        if let Some(mtu) = info.negotiated_mtu {
            sess.negotiated_mtu = mtu;
        }
        if let Some(enc) = info.encryption_enabled {
            sess.encrypted = enc;
        }
        match info.att_op_kind.as_deref() {
            Some("READ") | Some("FIND") => sess.att_reads = sess.att_reads.saturating_add(1),
            Some("WRITE") => sess.att_writes = sess.att_writes.saturating_add(1),
            Some("NOTIFY") | Some("INDICATE") => sess.att_notifies = sess.att_notifies.saturating_add(1),
            _ => {}
        }
        if info.l2cap_cid == Some(0x0006) {
            sess.smp_events = sess.smp_events.saturating_add(1);
        }
        for (h, uuid_label) in &info.learned_handles {
            if !sess.handle_uuid_map.iter().any(|(eh, _)| eh == h) && sess.handle_uuid_map.len() < 128 {
                sess.handle_uuid_map.push((*h, uuid_label.clone()));
            }
        }
        sess.last_seen_timestamp = timestamp.to_string();
    }

    if let Some(rssi) = info.rssi_dbm {
        if lock.rssi_history.len() >= 360 {
            lock.rssi_history.pop_front();
        }
        lock.rssi_history.push_back(BluetoothRssiSample {
            timestamp: timestamp.to_string(),
            address: info.address.clone(),
            rssi_dbm: rssi,
            distance_m: info.estimated_distance_m.unwrap_or_else(|| estimate_distance_log_distance(rssi, info.tx_power_dbm)),
        });
    }

    // 写入实时蓝牙底层帧瀑布时间线 (最多留存最近 120 条)
    let source = info.source_tag.clone().unwrap_or_else(|| {
        if info.ble_adv_type.is_some() { "WinRT-BLE-AD".into() } else { "HCI-Stream".into() }
    });
    let direction = if source.contains("-TX") || matches!(info.hci_type, HciPacketType::Command) {
        "HOST_TX".to_string()
    } else if matches!(info.hci_type, HciPacketType::Event) && info.ble_adv_type.is_some() {
        "AIR_RX".to_string()
    } else {
        "CTRL_RX".to_string()
    };
    let summary = info
        .beacon_decoded
        .clone()
        .or_else(|| info.att_opcode_desc.clone())
        .or_else(|| info.device_name.clone())
        .unwrap_or_else(|| format!("{:?} {}", info.hci_type, info.address));

    if lock.recent_frames.len() >= 120 {
        lock.recent_frames.pop_front();
    }
    lock.recent_frames.push_back(BluetoothFrameLogItem {
        id: NEXT_BT_FRAME_ID.fetch_add(1, Ordering::Relaxed),
        timestamp: timestamp.to_string(),
        source,
        direction,
        protocol_layer: proto_layer,
        address: info.address.clone(),
        rssi_dbm: info.rssi_dbm,
        length: info.raw_hex.len() / 2,
        summary,
        raw_hex: info.raw_hex.clone(),
    });

    // 显式释放写锁后再执行磁盘 JSONL 持久化，防止阻塞高频无线帧处理热路径
    drop(lock);

    #[cfg(not(test))]
    if let Some((rec, note, byte_len)) = persist_payload {
        if let Some(dir) = bluetooth_data_dir() {
            append_bluetooth_history_record_to_dir(&dir, &rec);
        }
        let forensic_rec = serde_json::json!({
            "timestamp": rec.timestamp,
            "transport": "BT_BLE",
            "protocol": rec.protocol_layer,
            "src_ip": rec.address,
            "dst_ip": "LOCAL_ADAPTER",
            "direction": "WIRELESS_RX",
            "length": byte_len,
            "raw_text": format!("{} ({}) RSSI={}dBm d={:.2}m {}", rec.device_name, rec.vendor_info, rec.rssi_dbm, rec.estimated_distance_m, note),
            "business_data": {
                "bus_type": "BLUETOOTH",
                "rssi_dbm": rec.rssi_dbm,
                "distance_m": rec.estimated_distance_m,
                "adv_interval_ms": rec.adv_interval_ms,
                "stability_score": rec.stability_score,
                "security_flags": rec.security_flags
            }
        });
        if let Ok(line) = serde_json::to_string(&forensic_rec) {
            crate::forensics::write_jsonl_record(&line);
        }
    }
    #[cfg(test)]
    let _ = persist_payload;
}

/// 解析应用级蓝牙存证数据目录 (委托 forensics::data_path 获取跨平台持久化位置)
pub fn bluetooth_data_dir() -> Option<PathBuf> {
    crate::forensics::data_path("bluetooth_history.jsonl")
        .parent()
        .map(|p| p.to_path_buf())
}

/// 将单条蓝牙遥测采样记录追加写入指定目录下的 bluetooth_history.jsonl (带 32MB 日志自动轮转与零静默错误审计)
pub fn append_bluetooth_history_record_to_dir(dir: &Path, rec: &BluetoothHistoryRecord) {
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let path = dir.join("bluetooth_history.jsonl");
    if let Ok(meta) = fs::metadata(&path) {
        if meta.len() >= 32 * 1024 * 1024 {
            let rotated = dir.join("bluetooth_history.jsonl.prev");
            let _ = fs::remove_file(&rotated);
            let _ = fs::rename(&path, &rotated);
        }
    }
    let Ok(line) = serde_json::to_string(rec) else {
        return;
    };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{}", line);
        let _ = file.flush();
    }
}

/// 获取蓝牙全局遥测汇总
pub fn get_bluetooth_telemetry_summary() -> BluetoothTelemetrySummary {
    let lock = match GLOBAL_BLUETOOTH_MONITOR.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let mut devices: Vec<BluetoothDeviceAsset> = lock.device_map.values().cloned().collect();
    devices.sort_by(|a, b| {
        a.estimated_distance_m
            .partial_cmp(&b.estimated_distance_m)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut recent: Vec<BluetoothFrameLogItem> = lock.recent_frames.iter().cloned().collect();
    recent.reverse(); // 最新报文优先排在前面

    let mut sessions: Vec<BluetoothConnectionSession> = lock.session_map.values().cloned().collect();
    sessions.sort_by_key(|s| s.conn_handle);

    BluetoothTelemetrySummary {
        total_packets: lock.total_packets,
        advertising_packets: lock.adv_packets,
        acl_data_packets: lock.acl_packets,
        unencrypted_att_count: lock.unencrypted_att_count,
        active_device_count: devices.len(),
        devices,
        rssi_history: lock.rssi_history.iter().cloned().collect(),
        hci_command_packets: lock.hci_cmd_packets,
        hci_event_packets: lock.hci_evt_packets,
        continuous_ble_active: CONTINUOUS_BLE_RUNNING.load(Ordering::Acquire),
        bthport_etw_active: BTHPORT_ETW_ACTIVE.load(Ordering::Acquire),
        bthport_etw_status: lock.bthport_etw_status.clone(),
        recent_frames: recent,
        active_sessions: sessions,
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
    lock.hci_cmd_packets = 0;
    lock.hci_evt_packets = 0;
    lock.unencrypted_att_count = 0;
    lock.device_map.clear();
    lock.rssi_history.clear();
    lock.recent_frames.clear();
    lock.session_map.clear();
}

#[cfg(target_os = "windows")]
mod win_bth {
    use super::{
        estimate_distance_log_distance, get_bluetooth_telemetry_summary, record_bluetooth_packet,
        resolve_ble_service_uuid, BleAdvType, BluetoothDissectionInfo,
        HciPacketType, NativeBluetoothAdapterInfo, NativeBluetoothDeviceInfo,
        NativeBluetoothScanResult,
    };
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;

    pub type Handle = *mut c_void;
    pub type HradioFind = *mut c_void;
    pub type HdevFind = *mut c_void;

    #[repr(C)]
    pub struct BluetoothFindRadioParams {
        pub dw_size: u32,
    }

    #[repr(C)]
    pub struct BluetoothRadioInfo {
        pub dw_size: u32,
        pub address: u64,
        pub sz_name: [u16; 248],
        pub ul_class_of_device: u32,
        pub lmp_subversion: u16,
        pub manufacturer: u16,
    }

    #[repr(C)]
    pub struct BluetoothDeviceSearchParams {
        pub dw_size: u32,
        pub f_return_authenticated: i32,
        pub f_return_remembered: i32,
        pub f_return_unknown: i32,
        pub f_return_connected: i32,
        pub f_issue_inquiry: i32,
        pub c_timeout_multiplier: u8,
        pub h_radio: Handle,
    }

    #[repr(C)]
    pub struct BluetoothDeviceInfo {
        pub dw_size: u32,
        pub address: u64,
        pub ul_class_of_device: u32,
        pub f_connected: i32,
        pub f_remembered: i32,
        pub f_authenticated: i32,
        pub st_last_seen: [u16; 8],
        pub st_last_used: [u16; 8],
        pub sz_name: [u16; 248],
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryA(lp_lib_file_name: *const i8) -> usize;
        fn GetProcAddress(h_module: usize, lp_proc_name: *const u8) -> *const c_void;
        fn FreeLibrary(h_lib_module: usize) -> i32;
        fn CloseHandle(h_object: Handle) -> i32;
    }

    type FnFindFirstRadio = unsafe extern "system" fn(*const BluetoothFindRadioParams, *mut Handle) -> HradioFind;
    type FnFindNextRadio = unsafe extern "system" fn(HradioFind, *mut Handle) -> i32;
    type FnFindRadioClose = unsafe extern "system" fn(HradioFind) -> i32;
    type FnGetRadioInfo = unsafe extern "system" fn(Handle, *mut BluetoothRadioInfo) -> u32;
    type FnFindFirstDevice = unsafe extern "system" fn(*const BluetoothDeviceSearchParams, *mut BluetoothDeviceInfo) -> HdevFind;
    type FnFindNextDevice = unsafe extern "system" fn(HdevFind, *mut BluetoothDeviceInfo) -> i32;
    type FnFindDeviceClose = unsafe extern "system" fn(HdevFind) -> i32;

    fn decode_utf16_z(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len]).trim().to_string()
    }

    fn format_win_bth_addr(raw_u64: u64) -> String {
        let raw = raw_u64.to_le_bytes();
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            raw[5], raw[4], raw[3], raw[2], raw[1], raw[0]
        )
    }

    fn format_systemtime(st: &[u16; 8]) -> String {
        if st[0] == 0 {
            return "-".to_string();
        }
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            st[0], st[1], st[3], st[4], st[5], st[6]
        )
    }

    pub fn scan(issue_inquiry: bool) -> NativeBluetoothScanResult {
        unsafe {
            let hmod = LoadLibraryA(b"bthprops.cpl\0".as_ptr() as *const i8);
            if hmod == 0 {
                return NativeBluetoothScanResult {
                    native_scan_available: false,
                    platform: "windows-bthprops".to_string(),
                    inquiry_executed: false,
                    ble_adv_count: 0,
                    adapters: Vec::new(),
                    devices: Vec::new(),
                    diagnostic_message: "系统未加载 bthprops.cpl，当前系统可能未安装蓝牙驱动栈。".to_string(),
                    summary: get_bluetooth_telemetry_summary(),
                };
            }

            macro_rules! load_fn {
                ($sym:expr, $ty:ty) => {{
                    let ptr = GetProcAddress(hmod, $sym.as_ptr());
                    if ptr.is_null() {
                        FreeLibrary(hmod);
                        return NativeBluetoothScanResult {
                            native_scan_available: false,
                            platform: "windows-bthprops".to_string(),
                            inquiry_executed: false,
                            ble_adv_count: 0,
                            adapters: Vec::new(),
                            devices: Vec::new(),
                            diagnostic_message: "bthprops.cpl 缺少所需蓝牙枚举导出函数，无法执行原生扫描。".to_string(),
                            summary: get_bluetooth_telemetry_summary(),
                        };
                    }
                    std::mem::transmute::<*const c_void, $ty>(ptr)
                }};
            }

            let fn_find_first_radio = load_fn!(b"BluetoothFindFirstRadio\0", FnFindFirstRadio);
            let fn_find_next_radio = load_fn!(b"BluetoothFindNextRadio\0", FnFindNextRadio);
            let fn_find_radio_close = load_fn!(b"BluetoothFindRadioClose\0", FnFindRadioClose);
            let fn_get_radio_info = load_fn!(b"BluetoothGetRadioInfo\0", FnGetRadioInfo);
            let fn_find_first_device = load_fn!(b"BluetoothFindFirstDevice\0", FnFindFirstDevice);
            let fn_find_next_device = load_fn!(b"BluetoothFindNextDevice\0", FnFindNextDevice);
            let fn_find_device_close = load_fn!(b"BluetoothFindDeviceClose\0", FnFindDeviceClose);

            let radio_params = BluetoothFindRadioParams {
                dw_size: size_of::<BluetoothFindRadioParams>() as u32,
            };
            let mut adapters = Vec::new();
            let mut radio_handles: Vec<Handle> = Vec::new();
            let mut h_radio: Handle = std::ptr::null_mut();
            let h_radio_find = fn_find_first_radio(&radio_params, &mut h_radio);
            if !h_radio_find.is_null() {
                loop {
                    if !h_radio.is_null() {
                        let mut radio_info: BluetoothRadioInfo = zeroed();
                        radio_info.dw_size = size_of::<BluetoothRadioInfo>() as u32;
                        if fn_get_radio_info(h_radio, &mut radio_info) == 0 {
                            adapters.push(NativeBluetoothAdapterInfo {
                                name: decode_utf16_z(&radio_info.sz_name),
                                address: format_win_bth_addr(radio_info.address),
                                class_of_device: format!("0x{:06X}", radio_info.ul_class_of_device),
                                manufacturer_id: radio_info.manufacturer,
                                lmp_subversion: radio_info.lmp_subversion,
                            });
                        }
                        radio_handles.push(h_radio);
                    }
                    let mut next_radio: Handle = std::ptr::null_mut();
                    if fn_find_next_radio(h_radio_find, &mut next_radio) == 0 {
                        break;
                    }
                    h_radio = next_radio;
                }
                fn_find_radio_close(h_radio_find);
            }

            let mut devices = Vec::new();
            let mut seen_addrs = std::collections::HashSet::new();
            let search_targets: Vec<Handle> = if radio_handles.is_empty() {
                vec![std::ptr::null_mut()]
            } else {
                radio_handles.clone()
            };

            for target_radio in search_targets {
                let search_params = BluetoothDeviceSearchParams {
                    dw_size: size_of::<BluetoothDeviceSearchParams>() as u32,
                    f_return_authenticated: 1,
                    f_return_remembered: 1,
                    f_return_unknown: 1,
                    f_return_connected: 1,
                    f_issue_inquiry: if issue_inquiry { 1 } else { 0 },
                    c_timeout_multiplier: if issue_inquiry { 2 } else { 0 },
                    h_radio: target_radio,
                };
                let mut dev_info: BluetoothDeviceInfo = zeroed();
                dev_info.dw_size = size_of::<BluetoothDeviceInfo>() as u32;
                let h_dev_find = fn_find_first_device(&search_params, &mut dev_info);
                if !h_dev_find.is_null() {
                    loop {
                        let addr = format_win_bth_addr(dev_info.address);
                        if seen_addrs.insert(addr.clone()) {
                            let name = decode_utf16_z(&dev_info.sz_name);
                            devices.push(NativeBluetoothDeviceInfo {
                                name: if name.is_empty() { format!("BT-{}", addr) } else { name },
                                address: addr,
                                class_of_device: format!("0x{:06X}", dev_info.ul_class_of_device),
                                connected: dev_info.f_connected != 0,
                                remembered: dev_info.f_remembered != 0,
                                authenticated: dev_info.f_authenticated != 0,
                                last_seen: format_systemtime(&dev_info.st_last_seen),
                                last_used: format_systemtime(&dev_info.st_last_used),
                            });
                        }
                        dev_info = zeroed();
                        dev_info.dw_size = size_of::<BluetoothDeviceInfo>() as u32;
                        if fn_find_next_device(h_dev_find, &mut dev_info) == 0 {
                            break;
                        }
                    }
                    fn_find_device_close(h_dev_find);
                }
            }

            for hr in radio_handles {
                CloseHandle(hr);
            }
            FreeLibrary(hmod);

            // 若存在蓝牙无线适配器，同步启用 WinRT COM 原生 BLE AdvertisementWatcher 抓包空气中的低功耗广播帧
            let mut ble_adv_count = 0usize;
            if !adapters.is_empty() {
                let ble_ms = if issue_inquiry { 2600 } else { 1800 };
                let ble_frames = win_ble_winrt::capture_ble_advertisements(ble_ms);
                let ts_now = chrono::Local::now().format("%H:%M:%S.%3f").to_string();
                ble_adv_count = ble_frames.len();
                for pkt in ble_frames {
                    record_bluetooth_packet(&pkt, &ts_now);
                }
            }
            let summary = get_bluetooth_telemetry_summary();

            let diagnostic_message = if adapters.is_empty() {
                "Windows 蓝牙栈已就绪，但未检测到本地蓝牙适配器（硬件缺失或已禁用）。".to_string()
            } else {
                format!(
                    "双模扫描完成：{} 个物理适配器、{} 个经典配对设备，空口捕获 {} 条实时 BLE 广播（活跃 {} 设备）。",
                    adapters.len(),
                    devices.len(),
                    ble_adv_count,
                    summary.active_device_count
                )
            };

            NativeBluetoothScanResult {
                native_scan_available: !adapters.is_empty(),
                platform: "windows-bth+winrt-ble".to_string(),
                inquiry_executed: issue_inquiry && !adapters.is_empty(),
                ble_adv_count,
                adapters,
                devices,
                diagnostic_message,
                summary,
            }
        }
    }

    pub(super) mod win_ble_winrt {
        use super::*;
        use crate::bluetooth_monitor::{
            decode_single_ad_section, now_monotonic_ms, synthesize_hci_le_adv_packet,
            ParsedAdSummary, CONTINUOUS_BLE_RUNNING,
        };
        use std::sync::Mutex;

        #[repr(C)]
        #[derive(Clone, Copy, PartialEq, Eq)]
        struct Guid {
            data1: u32,
            data2: u16,
            data3: u16,
            data4: [u8; 8],
        }

        const IID_IUNKNOWN: Guid = Guid { data1: 0x00000000, data2: 0x0000, data3: 0x0000, data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46] };
        const IID_IAGILE_OBJECT: Guid = Guid { data1: 0x94ea2b94, data2: 0xe9cc, data3: 0x49e0, data4: [0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90] };
        const IID_TYPED_HANDLER: Guid = Guid { data1: 0x90eb4eca, data2: 0xd465, data3: 0x5ea0, data4: [0xa6, 0x1c, 0x03, 0x3c, 0x8c, 0x5e, 0xce, 0xf2] };
        const IID_IWATCHER: Guid = Guid { data1: 0xa6ac336f, data2: 0xf3d3, data3: 0x4297, data4: [0x8d, 0x6c, 0xc8, 0x1e, 0xa6, 0x62, 0x3f, 0x40] };
        const IID_IWATCHER2: Guid = Guid { data1: 0x01bf26bc, data2: 0xb164, data3: 0x5805, data4: [0x90, 0xa3, 0xe8, 0xa7, 0x99, 0x7f, 0xf2, 0x25] };
        const IID_IARGS2: Guid = Guid { data1: 0x12d9c87b, data2: 0x0399, data3: 0x5f0e, data4: [0xa3, 0x48, 0x53, 0xb0, 0x2b, 0x6b, 0x16, 0x2e] };
        const IID_IARGS3: Guid = Guid { data1: 0x8d204b54, data2: 0xff86, data3: 0x5d84, data4: [0xa2, 0x5a, 0x13, 0x7d, 0xcc, 0xd9, 0x6f, 0x7a] };
        const IID_IBUFFER_BYTE_ACCESS: Guid = Guid { data1: 0x905a0fef, data2: 0xbc53, data3: 0x11df, data4: [0x8c, 0x49, 0x00, 0x1e, 0x4f, 0xc6, 0x86, 0xda] };

        type Hstring = *mut c_void;
        type FnRoInitialize = unsafe extern "system" fn(i32) -> i32;
        type FnRoActivateInstance = unsafe extern "system" fn(Hstring, *mut *mut c_void) -> i32;
        type FnWinCreateString = unsafe extern "system" fn(*const u16, u32, *mut Hstring) -> i32;
        type FnWinDeleteString = unsafe extern "system" fn(Hstring) -> i32;
        type FnWinGetStringRawBuffer = unsafe extern "system" fn(Hstring, *mut u32) -> *const u16;

        type FnQi = unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32;
        type FnRelease = unsafe extern "system" fn(*mut c_void) -> u32;
        type FnPutScanningMode = unsafe extern "system" fn(*mut c_void, i32) -> i32;
        type FnPutBool = unsafe extern "system" fn(*mut c_void, u8) -> i32;
        type FnWatcherCmd = unsafe extern "system" fn(*mut c_void) -> i32;
        type FnAddReceived = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut i64) -> i32;
        type FnRemoveReceived = unsafe extern "system" fn(*mut c_void, i64) -> i32;

        type FnGetRssi = unsafe extern "system" fn(*mut c_void, *mut i16) -> i32;
        type FnGetBtAddr = unsafe extern "system" fn(*mut c_void, *mut u64) -> i32;
        type FnGetI32 = unsafe extern "system" fn(*mut c_void, *mut i32) -> i32;
        type FnGetBool = unsafe extern "system" fn(*mut c_void, *mut u8) -> i32;
        type FnGetPtr = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
        type FnGetI16 = unsafe extern "system" fn(*mut c_void, *mut i16) -> i32;

        type FnGetLocalName = unsafe extern "system" fn(*mut c_void, *mut Hstring) -> i32;
        type FnVecGetGuidAt = unsafe extern "system" fn(*mut c_void, u32, *mut Guid) -> i32;
        type FnVecGetPtrAt = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
        type FnVecGetSize = unsafe extern "system" fn(*mut c_void, *mut u32) -> i32;
        type FnGetDataType = unsafe extern "system" fn(*mut c_void, *mut u8) -> i32;
        type FnGetBufLen = unsafe extern "system" fn(*mut c_void, *mut u32) -> i32;
        type FnBufAccess = unsafe extern "system" fn(*mut c_void, *mut *mut u8) -> i32;

        #[repr(C)]
        struct HandlerVtbl {
            qi: unsafe extern "system" fn(*mut BleHandler, *const Guid, *mut *mut c_void) -> i32,
            add_ref: unsafe extern "system" fn(*mut BleHandler) -> u32,
            release: unsafe extern "system" fn(*mut BleHandler) -> u32,
            invoke: unsafe extern "system" fn(*mut BleHandler, *mut c_void, *mut c_void) -> i32,
        }

        #[repr(C)]
        struct BleHandler {
            lp_vtbl: *const HandlerVtbl,
            ref_count: AtomicU32,
            stopped: AtomicBool,
            live_stream: bool,
            captured: Option<Arc<Mutex<Vec<BluetoothDissectionInfo>>>>,
            fn_get_str_buf: FnWinGetStringRawBuffer,
            fn_del_str: FnWinDeleteString,
        }

        static HANDLER_VTBL: HandlerVtbl = HandlerVtbl {
            qi: handler_qi,
            add_ref: handler_add_ref,
            release: handler_release,
            invoke: handler_invoke,
        };

        #[inline]
        unsafe fn vtable_ptr(obj: *mut c_void, idx: usize) -> *const c_void {
            unsafe {
                let vtbl = *(obj as *const *const *const c_void);
                *vtbl.add(idx)
            }
        }

        unsafe extern "system" fn handler_qi(this: *mut BleHandler, riid: *const Guid, out: *mut *mut c_void) -> i32 {
            unsafe {
                if out.is_null() || riid.is_null() {
                    return -2147467261i32; // E_POINTER
                }
                let id = *riid;
                if id == IID_IUNKNOWN || id == IID_IAGILE_OBJECT || id == IID_TYPED_HANDLER {
                    *out = this as *mut c_void;
                    handler_add_ref(this);
                    return 0;
                }
                *out = std::ptr::null_mut();
                -2147467262i32 // E_NOINTERFACE
            }
        }

        unsafe extern "system" fn handler_add_ref(this: *mut BleHandler) -> u32 {
            unsafe { (*this).ref_count.fetch_add(1, Ordering::Relaxed) + 1 }
        }

        unsafe extern "system" fn handler_release(this: *mut BleHandler) -> u32 {
            unsafe {
                let prev = (*this).ref_count.fetch_sub(1, Ordering::Release);
                if prev == 1 {
                    std::sync::atomic::fence(Ordering::Acquire);
                    drop(Box::from_raw(this));
                }
                prev.saturating_sub(1)
            }
        }

        /// 读取 WinRT IBluetoothLEAdvertisementDataSection 队列并提取每一字节原始 AD Payload
        unsafe fn read_winrt_data_sections(
            adv_ptr: *mut c_void,
            ad_parsed: &mut ParsedAdSummary,
            raw_tlv_buf: &mut Vec<u8>,
        ) {
            unsafe {
                let fn_get_sections: FnGetPtr = std::mem::transmute(vtable_ptr(adv_ptr, 12));
                let mut vec_ptr: *mut c_void = std::ptr::null_mut();
                if fn_get_sections(adv_ptr, &mut vec_ptr) != 0 || vec_ptr.is_null() {
                    return;
                }
                let fn_at: FnVecGetPtrAt = std::mem::transmute(vtable_ptr(vec_ptr, 6));
                let fn_size: FnVecGetSize = std::mem::transmute(vtable_ptr(vec_ptr, 7));
                let fn_rel_vec: FnRelease = std::mem::transmute(vtable_ptr(vec_ptr, 2));

                let mut count: u32 = 0;
                if fn_size(vec_ptr, &mut count) == 0 {
                    for idx in 0..count.min(32) {
                        let mut sec_ptr: *mut c_void = std::ptr::null_mut();
                        if fn_at(vec_ptr, idx, &mut sec_ptr) == 0 && !sec_ptr.is_null() {
                            let fn_dtype: FnGetDataType = std::mem::transmute(vtable_ptr(sec_ptr, 6));
                            let fn_data: FnGetPtr = std::mem::transmute(vtable_ptr(sec_ptr, 8));
                            let fn_rel_sec: FnRelease = std::mem::transmute(vtable_ptr(sec_ptr, 2));

                            let mut ad_type: u8 = 0;
                            let mut ibuf: *mut c_void = std::ptr::null_mut();
                            if fn_dtype(sec_ptr, &mut ad_type) == 0 && fn_data(sec_ptr, &mut ibuf) == 0 && !ibuf.is_null() {
                                let fn_len: FnGetBufLen = std::mem::transmute(vtable_ptr(ibuf, 7));
                                let fn_qi_buf: FnQi = std::mem::transmute(vtable_ptr(ibuf, 0));
                                let fn_rel_buf: FnRelease = std::mem::transmute(vtable_ptr(ibuf, 2));

                                let mut byte_len: u32 = 0;
                                let mut access_ptr: *mut c_void = std::ptr::null_mut();
                                if fn_len(ibuf, &mut byte_len) == 0
                                    && byte_len <= 255
                                    && fn_qi_buf(ibuf, &IID_IBUFFER_BYTE_ACCESS, &mut access_ptr) == 0
                                    && !access_ptr.is_null()
                                {
                                    let fn_raw: FnBufAccess = std::mem::transmute(vtable_ptr(access_ptr, 3));
                                    let fn_rel_acc: FnRelease = std::mem::transmute(vtable_ptr(access_ptr, 2));
                                    let mut raw_ptr: *mut u8 = std::ptr::null_mut();
                                    if fn_raw(access_ptr, &mut raw_ptr) == 0 && !raw_ptr.is_null() {
                                        let slice = std::slice::from_raw_parts(raw_ptr, byte_len as usize);
                                        if (slice.len() + 2) <= 255 {
                                            raw_tlv_buf.push((slice.len() + 1) as u8);
                                            raw_tlv_buf.push(ad_type);
                                            raw_tlv_buf.extend_from_slice(slice);
                                        }
                                        decode_single_ad_section(ad_type, slice, ad_parsed);
                                    }
                                    fn_rel_acc(access_ptr);
                                }
                                fn_rel_buf(ibuf);
                            }
                            fn_rel_sec(sec_ptr);
                        }
                    }
                }
                fn_rel_vec(vec_ptr);
            }
        }

        unsafe extern "system" fn handler_invoke(this: *mut BleHandler, _sender: *mut c_void, args: *mut c_void) -> i32 {
            if args.is_null() || this.is_null() {
                return 0;
            }
            unsafe {
                if (*this).stopped.load(Ordering::Acquire) {
                    return 0;
                }
                let fn_get_rssi: FnGetRssi = std::mem::transmute(vtable_ptr(args, 6));
                let fn_get_addr: FnGetBtAddr = std::mem::transmute(vtable_ptr(args, 7));
                let fn_get_adv_type: FnGetI32 = std::mem::transmute(vtable_ptr(args, 8));
                let fn_get_adv: FnGetPtr = std::mem::transmute(vtable_ptr(args, 10));

                let mut rssi_i16: i16 = -85;
                let _ = fn_get_rssi(args, &mut rssi_i16);
                let rssi = rssi_i16.clamp(-127, 20) as i8;

                let mut bt_addr_u64: u64 = 0;
                if fn_get_addr(args, &mut bt_addr_u64) != 0 || bt_addr_u64 == 0 {
                    return 0;
                }
                let b = bt_addr_u64.to_le_bytes();
                let addr_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", b[5], b[4], b[3], b[2], b[1], b[0]);

                let mut adv_t: i32 = 0;
                let _ = fn_get_adv_type(args, &mut adv_t);
                let ble_adv_type = match adv_t {
                    0 => Some(BleAdvType::AdvInd),
                    1 => Some(BleAdvType::AdvDirectInd),
                    2 => Some(BleAdvType::AdvNonconnInd),
                    3 => Some(BleAdvType::AdvScanInd),
                    4 => Some(BleAdvType::ScanRsp),
                    5 => Some(BleAdvType::Unknown(5)),
                    _ => Some(BleAdvType::Unknown(adv_t as u8)),
                };
                let adv_hci_byte = match adv_t {
                    0 => 0x00,
                    1 => 0x01,
                    2 => 0x02,
                    3 => 0x06,
                    4 => 0x04,
                    _ => 0x00,
                };

                // 查询 IBluetoothLEAdvertisementReceivedEventArgs2 (真实地址类型, TxPower, IsConnectable)
                let fn_qi_args: FnQi = std::mem::transmute(vtable_ptr(args, 0));
                let mut addr_type_enum: i32 = -1;
                let mut tx_power_opt: Option<i8> = None;
                let mut is_connectable_opt: Option<bool> = None;
                let mut args2_ptr: *mut c_void = std::ptr::null_mut();
                if fn_qi_args(args, &IID_IARGS2, &mut args2_ptr) == 0 && !args2_ptr.is_null() {
                    let fn_at: FnGetI32 = std::mem::transmute(vtable_ptr(args2_ptr, 6));
                    let fn_tx: FnGetPtr = std::mem::transmute(vtable_ptr(args2_ptr, 7));
                    let fn_conn: FnGetBool = std::mem::transmute(vtable_ptr(args2_ptr, 9));
                    let fn_rel2: FnRelease = std::mem::transmute(vtable_ptr(args2_ptr, 2));

                    let _ = fn_at(args2_ptr, &mut addr_type_enum);
                    let mut conn_b: u8 = 0;
                    if fn_conn(args2_ptr, &mut conn_b) == 0 {
                        is_connectable_opt = Some(conn_b != 0);
                    }
                    let mut iref_tx: *mut c_void = std::ptr::null_mut();
                    if fn_tx(args2_ptr, &mut iref_tx) == 0 && !iref_tx.is_null() {
                        let fn_val: FnGetI16 = std::mem::transmute(vtable_ptr(iref_tx, 6));
                        let fn_rel_tx: FnRelease = std::mem::transmute(vtable_ptr(iref_tx, 2));
                        let mut val_i16: i16 = 0;
                        if fn_val(iref_tx, &mut val_i16) == 0 {
                            tx_power_opt = Some(val_i16.clamp(-127, 20) as i8);
                        }
                        fn_rel_tx(iref_tx);
                    }
                    fn_rel2(args2_ptr);
                }

                // 查询 IBluetoothLEAdvertisementReceivedEventArgs3 (BLE 5.0 Primary / Secondary PHY)
                let mut phy_desc = String::from("LE 1M");
                let mut args3_ptr: *mut c_void = std::ptr::null_mut();
                if fn_qi_args(args, &IID_IARGS3, &mut args3_ptr) == 0 && !args3_ptr.is_null() {
                    let fn_p1: FnGetI32 = std::mem::transmute(vtable_ptr(args3_ptr, 6));
                    let fn_p2: FnGetI32 = std::mem::transmute(vtable_ptr(args3_ptr, 7));
                    let fn_rel3: FnRelease = std::mem::transmute(vtable_ptr(args3_ptr, 2));
                    let mut p1: i32 = 0;
                    let mut p2: i32 = 0;
                    let _ = fn_p1(args3_ptr, &mut p1);
                    let _ = fn_p2(args3_ptr, &mut p2);
                    let name_phy = |code: i32| match code {
                        1 => "LE 1M",
                        2 => "LE 2M",
                        3 => "LE Coded",
                        _ => "",
                    };
                    let n1 = name_phy(p1);
                    let n2 = name_phy(p2);
                    if !n1.is_empty() {
                        phy_desc = if !n2.is_empty() && n2 != n1 { format!("{}/{}", n1, n2) } else { n1.to_string() };
                    }
                    fn_rel3(args3_ptr);
                }

                let mut ad_parsed = ParsedAdSummary::default();
                let mut raw_ad_tlv = Vec::new();
                let mut adv_ptr: *mut c_void = std::ptr::null_mut();

                if fn_get_adv(args, &mut adv_ptr) == 0 && !adv_ptr.is_null() {
                    // 1. 完整读出每一段原始 DataSections TLV 二进制载荷 (不再遗漏任何字节)
                    read_winrt_data_sections(adv_ptr, &mut ad_parsed, &mut raw_ad_tlv);

                    // 2. 补充读取 OS 合并后的 LocalName & ServiceUuids
                    let fn_get_name: FnGetLocalName = std::mem::transmute(vtable_ptr(adv_ptr, 8));
                    let fn_get_uuids: FnGetPtr = std::mem::transmute(vtable_ptr(adv_ptr, 10));
                    let fn_rel_adv: FnRelease = std::mem::transmute(vtable_ptr(adv_ptr, 2));

                    let mut h_name: Hstring = std::ptr::null_mut();
                    if fn_get_name(adv_ptr, &mut h_name) == 0 && !h_name.is_null() {
                        let mut str_len: u32 = 0;
                        let buf = ((*this).fn_get_str_buf)(h_name, &mut str_len);
                        if !buf.is_null() && str_len > 0 {
                            let s = String::from_utf16_lossy(std::slice::from_raw_parts(buf, str_len as usize)).trim().to_string();
                            if !s.is_empty() && ad_parsed.device_name.is_none() {
                                ad_parsed.device_name = Some(s);
                            }
                        }
                        let _ = ((*this).fn_del_str)(h_name);
                    }

                    let mut vec_ptr: *mut c_void = std::ptr::null_mut();
                    if fn_get_uuids(adv_ptr, &mut vec_ptr) == 0 && !vec_ptr.is_null() {
                        let fn_at: FnVecGetGuidAt = std::mem::transmute(vtable_ptr(vec_ptr, 6));
                        let fn_size: FnVecGetSize = std::mem::transmute(vtable_ptr(vec_ptr, 7));
                        let fn_rel_vec: FnRelease = std::mem::transmute(vtable_ptr(vec_ptr, 2));

                        let mut count: u32 = 0;
                        if fn_size(vec_ptr, &mut count) == 0 {
                            for idx in 0..count.min(16) {
                                let mut g = Guid { data1: 0, data2: 0, data3: 0, data4: [0; 8] };
                                if fn_at(vec_ptr, idx, &mut g) == 0 {
                                    let uuid_label = if (g.data1 & 0xFFFF0000) == 0 && g.data2 == 0x0000 && g.data3 == 0x1000 {
                                        let short16 = (g.data1 & 0xFFFF) as u16;
                                        format!("0x{:04X} ({})", short16, resolve_ble_service_uuid(short16))
                                    } else {
                                        format!("{:08X}-{:04X}-{:04X}", g.data1, g.data2, g.data3)
                                    };
                                    if !ad_parsed.service_uuids.contains(&uuid_label) {
                                        ad_parsed.service_uuids.push(uuid_label);
                                    }
                                }
                            }
                        }
                        fn_rel_vec(vec_ptr);
                    }
                    fn_rel_adv(adv_ptr);
                }

                let addr_type_label = match addr_type_enum {
                    0 => "Public (IEEE 固定硬件地址)".to_string(),
                    1 => {
                        if (b[5] & 0xC0) == 0xC0 {
                            "Static Random (静态随机)".to_string()
                        } else if (b[5] & 0xC0) == 0x40 {
                            "Resolvable Private (RPA 隐私轮转)".to_string()
                        } else {
                            "Random (非可解析随机)".to_string()
                        }
                    }
                    _ => if (b[5] & 0xC0) == 0x40 { "Resolvable Private" } else { "Random / Adv" }.to_string(),
                };
                let addr_hci_byte = if addr_type_enum == 0 { 0x00 } else { 0x01 };

                let real_tx = tx_power_opt.or(ad_parsed.tx_power_dbm);
                let dist = estimate_distance_log_distance(rssi, real_tx);
                let raw_pkt = synthesize_hci_le_adv_packet(bt_addr_u64, addr_hci_byte, adv_hci_byte, &raw_ad_tlv, rssi);

                let mut alerts = ad_parsed.security_alerts;
                let connectable = is_connectable_opt.unwrap_or_else(|| matches!(ble_adv_type, Some(BleAdvType::AdvInd) | Some(BleAdvType::AdvDirectInd)));
                if connectable && addr_type_enum == 0 && !alerts.contains(&"CONNECTABLE_BLE_PERIPHERAL".to_string()) {
                    alerts.push("CONNECTABLE_BLE_PERIPHERAL".to_string());
                }

                let info = BluetoothDissectionInfo {
                    hci_type: HciPacketType::Event,
                    address: addr_str,
                    address_type: addr_type_label,
                    device_name: ad_parsed.device_name,
                    ble_adv_type,
                    rssi_dbm: Some(rssi),
                    estimated_distance_m: Some(dist),
                    tx_power_dbm: real_tx,
                    service_uuids: ad_parsed.service_uuids,
                    manufacturer_data_hex: ad_parsed.manufacturer_data_hex,
                    l2cap_cid: None,
                    att_opcode_desc: None,
                    security_alerts: alerts,
                    company_id: ad_parsed.company_id,
                    vendor_name: ad_parsed.vendor_name,
                    phy_desc: Some(phy_desc),
                    appearance_desc: ad_parsed.appearance_desc,
                    beacon_decoded: ad_parsed.beacon_decoded,
                    ad_sections: ad_parsed.ad_sections,
                    raw_hex: hex::encode_upper(&raw_pkt),
                    arrival_timestamp_ms: Some(now_monotonic_ms()),
                    source_tag: Some(if (*this).live_stream { "WinRT-BLE-Live".into() } else { "WinRT-BLE-Scan".into() }),
                    conn_handle: None,
                    negotiated_mtu: None,
                    learned_handles: Vec::new(),
                    att_op_kind: None,
                    encryption_enabled: None,
                };

                if (*this).live_stream {
                    let ts_now = chrono::Local::now().format("%H:%M:%S.%3f").to_string();
                    record_bluetooth_packet(&info, &ts_now);
                } else if let Some(ref cap) = (*this).captured {
                    if let Ok(mut guard) = cap.lock() {
                        if guard.len() < 1024 {
                            guard.push(info);
                        }
                    }
                }
                0
            }
        }

        fn run_watcher_session(duration_ms: Option<u64>) -> Result<Vec<BluetoothDissectionInfo>, String> {
            unsafe {
                let combase = super::LoadLibraryA(b"combase.dll\0".as_ptr() as *const i8);
                if combase == 0 {
                    return Err("系统缺少 combase.dll".into());
                }

                macro_rules! load_cb {
                    ($sym:expr, $ty:ty) => {{
                        let ptr = super::GetProcAddress(combase, $sym.as_ptr());
                        if ptr.is_null() {
                            super::FreeLibrary(combase);
                            return Err("combase.dll 导出符号缺失".into());
                        }
                        std::mem::transmute::<*const c_void, $ty>(ptr)
                    }};
                }

                let fn_ro_init = load_cb!(b"RoInitialize\0", FnRoInitialize);
                let fn_ro_activate = load_cb!(b"RoActivateInstance\0", FnRoActivateInstance);
                let fn_create_str = load_cb!(b"WindowsCreateString\0", FnWinCreateString);
                let fn_del_str = load_cb!(b"WindowsDeleteString\0", FnWinDeleteString);
                let fn_get_str_buf = load_cb!(b"WindowsGetStringRawBuffer\0", FnWinGetStringRawBuffer);

                let init_hr = fn_ro_init(1); // RO_INIT_MULTITHREADED
                if init_hr < 0 && init_hr != -2147417850i32 {
                    super::FreeLibrary(combase);
                    return Err(format!("RoInitialize 失败 (HR=0x{:08X})", init_hr));
                }

                let class_utf16: Vec<u16> = "Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher".encode_utf16().collect();
                let mut h_cls: Hstring = std::ptr::null_mut();
                if fn_create_str(class_utf16.as_ptr(), class_utf16.len() as u32, &mut h_cls) != 0 || h_cls.is_null() {
                    super::FreeLibrary(combase);
                    return Err("WindowsCreateString 失败".into());
                }

                let mut insp_ptr: *mut c_void = std::ptr::null_mut();
                let act_hr = fn_ro_activate(h_cls, &mut insp_ptr);
                let _ = fn_del_str(h_cls);
                if act_hr != 0 || insp_ptr.is_null() {
                    super::FreeLibrary(combase);
                    return Err(format!("激活 WinRT Watcher 失败 (HR=0x{:08X})", act_hr));
                }

                let fn_qi: FnQi = std::mem::transmute(vtable_ptr(insp_ptr, 0));
                let fn_rel_insp: FnRelease = std::mem::transmute(vtable_ptr(insp_ptr, 2));
                let mut watcher_ptr: *mut c_void = std::ptr::null_mut();
                if fn_qi(insp_ptr, &IID_IWATCHER, &mut watcher_ptr) != 0 || watcher_ptr.is_null() {
                    fn_rel_insp(insp_ptr);
                    super::FreeLibrary(combase);
                    return Err("QI IBluetoothLEAdvertisementWatcher 失败".into());
                }

                // 开启 BLE 5.0 扩展广播接收 (IBluetoothLEAdvertisementWatcher2::put_AllowExtendedAdvertisements)
                let mut watcher2_ptr: *mut c_void = std::ptr::null_mut();
                if fn_qi(insp_ptr, &IID_IWATCHER2, &mut watcher2_ptr) == 0 && !watcher2_ptr.is_null() {
                    let fn_put_ext: FnPutBool = std::mem::transmute(vtable_ptr(watcher2_ptr, 7));
                    let fn_rel_w2: FnRelease = std::mem::transmute(vtable_ptr(watcher2_ptr, 2));
                    let _ = fn_put_ext(watcher2_ptr, 1);
                    fn_rel_w2(watcher2_ptr);
                }

                let live_stream = duration_ms.is_none();
                let captured = if live_stream { None } else { Some(Arc::new(Mutex::new(Vec::new()))) };

                let handler = Box::into_raw(Box::new(BleHandler {
                    lp_vtbl: &HANDLER_VTBL,
                    ref_count: AtomicU32::new(1),
                    stopped: AtomicBool::new(false),
                    live_stream,
                    captured: captured.clone(),
                    fn_get_str_buf,
                    fn_del_str,
                }));

                let fn_put_mode: FnPutScanningMode = std::mem::transmute(vtable_ptr(watcher_ptr, 12));
                let fn_start: FnWatcherCmd = std::mem::transmute(vtable_ptr(watcher_ptr, 17));
                let fn_stop: FnWatcherCmd = std::mem::transmute(vtable_ptr(watcher_ptr, 18));
                let fn_add: FnAddReceived = std::mem::transmute(vtable_ptr(watcher_ptr, 19));
                let fn_rem: FnRemoveReceived = std::mem::transmute(vtable_ptr(watcher_ptr, 20));
                let fn_rel_w: FnRelease = std::mem::transmute(vtable_ptr(watcher_ptr, 2));

                let _ = fn_put_mode(watcher_ptr, 1); // Active Scan (同时拉取 ScanRsp 载荷)
                let mut token: i64 = 0;
                if fn_add(watcher_ptr, handler as *mut c_void, &mut token) == 0 {
                    if fn_start(watcher_ptr) == 0 {
                        if let Some(ms) = duration_ms {
                            std::thread::sleep(std::time::Duration::from_millis(ms.clamp(400, 5000)));
                        } else {
                            while CONTINUOUS_BLE_RUNNING.load(Ordering::Acquire) {
                                std::thread::sleep(std::time::Duration::from_millis(120));
                            }
                        }
                        (*handler).stopped.store(true, Ordering::Release);
                        let _ = fn_stop(watcher_ptr);
                    }
                    let _ = fn_rem(watcher_ptr, token);
                }

                (*handler).stopped.store(true, Ordering::Release);
                fn_rel_w(watcher_ptr);
                fn_rel_insp(insp_ptr);
                handler_release(handler);
                super::FreeLibrary(combase);

                Ok(captured
                    .and_then(|c| c.lock().ok().map(|g| g.clone()))
                    .unwrap_or_default())
            }
        }

        pub fn capture_ble_advertisements(duration_ms: u64) -> Vec<BluetoothDissectionInfo> {
            run_watcher_session(Some(duration_ms)).unwrap_or_default()
        }

        pub fn spawn_continuous_ble_watcher() -> Result<(), String> {
            if CONTINUOUS_BLE_RUNNING.swap(true, Ordering::SeqCst) {
                return Ok(());
            }
            std::thread::spawn(move || {
                if let Err(e) = run_watcher_session(None) {
                    eprintln!("[BLE-LIVE] 连续空口 Watcher 异常退出: {}", e);
                }
                CONTINUOUS_BLE_RUNNING.store(false, Ordering::SeqCst);
            });
            Ok(())
        }
    }
}

/// 解析 Windows 内置 `Microsoft-Windows-BTH-BTHPORT` ETW 事件原始二进位为 HCI H4 包
/// 依据官方 BTHPORT ETW Manifest XML Schema:
/// - Event 402 (HCIRAW): `[3]=BIP_Type, [4..8]=BIP_DataLen (u32 LE), [8..8+len]=BIP_Data`
/// - Event 263/264 (Write/Read HCI Packet): `[1..3]=ConnHandle, [3]=PB, [4]=BC, [7..9]=PDU_Len, [9..11]=CID, [15..17]=DataLen, [17..]=Data`
/// 时间复杂度: O(L) (L <= 65536), 空间复杂度: O(L)
pub fn decode_bthport_etw_event(event_id: u16, user_data: &[u8]) -> Option<(&'static str, Vec<u8>)> {
    match event_id {
        402 => {
            if user_data.len() < 9 {
                return None;
            }
            let bip_type = user_data[3];
            let data_len = u32::from_le_bytes([user_data[4], user_data[5], user_data[6], user_data[7]]) as usize;
            if data_len == 0 || data_len > 65535 || user_data.len() < 8 + data_len {
                return None;
            }
            let mut h4 = Vec::with_capacity(1 + data_len);
            h4.push(bip_type);
            h4.extend_from_slice(&user_data[8..8 + data_len]);
            Some(("BTHPORT-HCIRAW", h4))
        }
        263 | 264 => {
            if user_data.len() < 18 {
                return None;
            }
            let conn_handle = u16::from_le_bytes([user_data[1], user_data[2]]) & 0x0FFF;
            let pb_flag = (user_data[3] & 0x03) as u16;
            let bc_flag = (user_data[4] & 0x03) as u16;
            let cid = u16::from_le_bytes([user_data[9], user_data[10]]);
            let data_len = u16::from_le_bytes([user_data[15], user_data[16]]) as usize;
            if data_len > 65535 || user_data.len() < 17 + data_len {
                return None;
            }
            let payload = &user_data[17..17 + data_len];
            let l2cap_pdu_len = u16::from_le_bytes([user_data[7], user_data[8]]).max(data_len as u16);
            let acl_len = (4 + data_len) as u16;
            let handle_word = conn_handle | (pb_flag << 12) | (bc_flag << 14);

            let mut h4 = Vec::with_capacity(9 + data_len);
            h4.push(0x02); // HCI ACL Data
            h4.extend_from_slice(&handle_word.to_le_bytes());
            h4.extend_from_slice(&acl_len.to_le_bytes());
            h4.extend_from_slice(&l2cap_pdu_len.to_le_bytes());
            h4.extend_from_slice(&cid.to_le_bytes());
            h4.extend_from_slice(payload);

            let tag = if event_id == 263 { "BTHPORT-HCI-TX" } else { "BTHPORT-HCI-RX" };
            Some((tag, h4))
        }
        _ => None,
    }
}

#[cfg(target_os = "windows")]
mod win_bth_etw {
    use super::*;
    use std::ffi::c_void;
    use std::sync::mpsc;
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::Etw::{
        CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
        CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
        EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
        EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
        TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
    };

    const BTH_SESSION_NAME: &str = "OmniProbe_BthPort_HCI_Live";
    // Microsoft-Windows-BTH-BTHPORT {8A1F9517-3A8C-4A9E-A018-4F17A200F277}
    const GUID_BTHPORT: GUID = GUID {
        data1: 0x8A1F9517,
        data2: 0x3A8C,
        data3: 0x4A9E,
        data4: [0xA0, 0x18, 0x4F, 0x17, 0xA2, 0x00, 0xF2, 0x77],
    };
    // 0x8000000000000000 (HCIRAW) | 0x4000000000000000 (BTHPORT/HCI)
    const KEYWORDS_BTHPORT_HCI: u64 = 0xC000_0000_0000_0000;

    #[repr(C)]
    struct BthTraceProps {
        props: EVENT_TRACE_PROPERTIES,
        name_buf: [u16; 128],
    }

    impl BthTraceProps {
        fn new() -> Self {
            let p_sz = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
            let mut props: EVENT_TRACE_PROPERTIES = unsafe { std::mem::zeroed() };
            props.Wnode.BufferSize = std::mem::size_of::<Self>() as u32;
            props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            props.Wnode.ClientContext = 1;
            props.BufferSize = 64;
            props.MinimumBuffers = 8;
            props.MaximumBuffers = 32;
            props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            props.FlushTimer = 1;
            props.LoggerNameOffset = p_sz as u32;
            Self {
                props,
                name_buf: [0u16; 128],
            }
        }
    }

    struct BthEtwContext {
        tx: mpsc::SyncSender<(&'static str, Vec<u8>)>,
    }

    unsafe extern "system" fn bth_event_cb(record: *mut EVENT_RECORD) {
        if record.is_null() {
            return;
        }
        let rec = unsafe { &*record };
        if rec.UserData.is_null() || rec.UserDataLength == 0 || rec.UserContext.is_null() {
            return;
        }
        let ctx = unsafe { &*(rec.UserContext as *const BthEtwContext) };
        let raw = unsafe { std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize) };
        if let Some(pkt) = decode_bthport_etw_event(rec.EventHeader.EventDescriptor.Id, raw) {
            let _ = ctx.tx.try_send(pkt);
        }
    }

    unsafe extern "system" fn bth_buffer_cb(_logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
        if BTHPORT_ETW_ACTIVE.load(Ordering::Acquire) { 1 } else { 0 }
    }

    fn stop_session(sess_utf16: &[u16]) {
        let mut p = BthTraceProps::new();
        unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE { Value: 0 },
                sess_utf16.as_ptr(),
                &mut p.props as *mut EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
    }

    pub fn start_bthport_etw() -> Result<String, String> {
        if BTHPORT_ETW_ACTIVE.load(Ordering::Acquire) {
            return Ok("Windows 原生 BTHPORT-ETW HCI/L2CAP 监听已处于活跃运行状态".into());
        }
        let mut sess_utf16: Vec<u16> = BTH_SESSION_NAME.encode_utf16().collect();
        sess_utf16.push(0);
        stop_session(&sess_utf16);

        let mut props = BthTraceProps::new();
        let copy_len = sess_utf16.len().min(props.name_buf.len());
        props.name_buf[..copy_len].copy_from_slice(&sess_utf16[..copy_len]);

        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let rc = unsafe { StartTraceW(&mut handle, sess_utf16.as_ptr(), &mut props.props) };
        if rc == ERROR_ACCESS_DENIED {
            let msg = "系统拒绝启动 BTHPORT ETW 会话 (ERROR_ACCESS_DENIED=5): 请以管理员身份运行解锁驱动级 HCI/L2CAP 原生抓包".to_string();
            if let Ok(mut g) = GLOBAL_BLUETOOTH_MONITOR.write() {
                g.bthport_etw_status = msg.clone();
            }
            return Err(msg);
        }
        if rc != ERROR_SUCCESS && rc != ERROR_ALREADY_EXISTS {
            let msg = format!("StartTraceW 启动 BTHPORT-ETW 失败 (Win32={})", rc);
            if let Ok(mut g) = GLOBAL_BLUETOOTH_MONITOR.write() {
                g.bthport_etw_status = msg.clone();
            }
            return Err(msg);
        }

        let mut ep: ENABLE_TRACE_PARAMETERS = unsafe { std::mem::zeroed() };
        ep.Version = 2;
        let rc_en = unsafe {
            EnableTraceEx2(
                handle,
                &GUID_BTHPORT,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE as u8,
                KEYWORDS_BTHPORT_HCI,
                0,
                0,
                &ep,
            )
        };
        if rc_en != ERROR_SUCCESS {
            stop_session(&sess_utf16);
            return Err(format!("EnableTraceEx2 订阅 BTHPORT 失败 (Win32={})", rc_en));
        }

        let (tx, rx) = mpsc::sync_channel::<(&'static str, Vec<u8>)>(2048);
        let ctx_raw = Box::into_raw(Box::new(BthEtwContext { tx }));

        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        logfile.LoggerName = sess_utf16.as_ptr() as *mut u16;
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(bth_event_cb);
        logfile.BufferCallback = Some(bth_buffer_cb);
        logfile.Context = ctx_raw as *mut c_void;

        let c_handle = unsafe { OpenTraceW(&mut logfile) };
        if c_handle.Value == INVALID_HANDLE_VALUE as u64 || c_handle.Value == 0 {
            let _ = unsafe { Box::from_raw(ctx_raw) };
            stop_session(&sess_utf16);
            return Err("OpenTraceW 打开 BTHPORT 实时通道失败".into());
        }

        BTHPORT_ETW_ACTIVE.store(true, Ordering::SeqCst);
        let ok_msg = "✅ 已启用 Windows 原生 BTHPORT-ETW (HCIRAW + L2CAP) 免 USBPcap 驱动级 HCI 捕获".to_string();
        if let Ok(mut g) = GLOBAL_BLUETOOTH_MONITOR.write() {
            g.bthport_etw_status = ok_msg.clone();
        }

        // 消费者线程
        std::thread::spawn(move || {
            while BTHPORT_ETW_ACTIVE.load(Ordering::Acquire) {
                match rx.recv_timeout(std::time::Duration::from_millis(120)) {
                    Ok((tag, h4)) => {
                        if let Some(mut info) = parse_bluetooth_packet(&h4) {
                            info.source_tag = Some(tag.into());
                            let ts_now = chrono::Local::now().format("%H:%M:%S.%3f").to_string();
                            record_bluetooth_packet(&info, &ts_now);
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });

        // 实时事件分发线程 + 监控停止
        let sess_copy = sess_utf16.clone();
        std::thread::spawn(move || {
            while BTHPORT_ETW_ACTIVE.load(Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
            stop_session(&sess_copy);
        });

        let ctx_addr = ctx_raw as usize;
        std::thread::spawn(move || {
            let mut h = [c_handle];
            unsafe {
                ProcessTrace(h.as_mut_ptr(), 1, std::ptr::null(), std::ptr::null());
                CloseTrace(c_handle);
            }
            stop_session(&sess_utf16);
            let _ = unsafe { Box::from_raw(ctx_addr as *mut BthEtwContext) };
            BTHPORT_ETW_ACTIVE.store(false, Ordering::SeqCst);
        });

        Ok(ok_msg)
    }

    pub fn stop_bthport_etw() {
        BTHPORT_ETW_ACTIVE.store(false, Ordering::SeqCst);
        let mut sess_utf16: Vec<u16> = BTH_SESSION_NAME.encode_utf16().collect();
        sess_utf16.push(0);
        stop_session(&sess_utf16);
        if let Ok(mut g) = GLOBAL_BLUETOOTH_MONITOR.write() {
            g.bthport_etw_status = "已停止 BTHPORT-ETW HCI 抓包".into();
        }
    }
}

#[tauri::command]
pub fn start_continuous_ble_monitor_cmd() -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        win_bth::win_ble_winrt::spawn_continuous_ble_watcher()?;
        Ok(true)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("实时流式 BLE 空口监听当前仅于 Windows WinRT 原生栈实现".into())
    }
}

#[tauri::command]
pub fn stop_continuous_ble_monitor_cmd() -> Result<bool, String> {
    CONTINUOUS_BLE_RUNNING.store(false, Ordering::SeqCst);
    Ok(true)
}

#[tauri::command]
pub fn start_bthport_etw_capture_cmd() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        win_bth_etw::start_bthport_etw()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("BTHPORT ETW 引擎仅适用于 Windows 平台".into())
    }
}

#[tauri::command]
pub fn stop_bthport_etw_capture_cmd() -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    win_bth_etw::stop_bthport_etw();
    Ok(true)
}

/// 跨平台执行操作系统原生蓝牙硬件与附近设备扫描
/// 时间复杂度: O(R + D) (R 为本地适配器数, D 为已缓存/发现设备数); 空间复杂度: O(R + D)
pub fn scan_native_bluetooth_devices(issue_inquiry: bool) -> NativeBluetoothScanResult {
    #[cfg(target_os = "windows")]
    {
        win_bth::scan(issue_inquiry)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = issue_inquiry;
        NativeBluetoothScanResult {
            native_scan_available: false,
            platform: std::env::consts::OS.to_string(),
            inquiry_executed: false,
            ble_adv_count: 0,
            adapters: Vec::new(),
            devices: Vec::new(),
            diagnostic_message: "当前非 Windows 平台暂需通过 USBPcap/HCI 控制器抓包获取蓝牙设备。".to_string(),
            summary: get_bluetooth_telemetry_summary(),
        }
    }
}

#[tauri::command]
pub async fn scan_native_bluetooth_devices_cmd(issue_inquiry: Option<bool>) -> Result<NativeBluetoothScanResult, String> {
    let inquiry = issue_inquiry.unwrap_or(false);
    tokio::task::spawn_blocking(move || scan_native_bluetooth_devices(inquiry))
        .await
        .map_err(|e| format!("蓝牙原生探测线程异常: {}", e))
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

/// BLE GATT 特征安全与访问属性快照
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BleGattCharacteristicInfo {
    pub uuid: String,
    pub handle: u16,
    pub properties: String,
    pub protection_level: String,
    pub security_warning: Option<String>,
    #[serde(default)]
    pub raw_value_hex: Option<String>,
    #[serde(default)]
    pub decoded_value: Option<String>,
}

/// BLE GATT 主服务节点快照
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleGattServiceInfo {
    pub uuid: String,
    pub service_name: String,
    pub handle: u16,
    pub characteristics: Vec<BleGattCharacteristicInfo>,
}

/// BLE GATT 原生穿透枚举响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleGattAuditResult {
    pub target_address: String,
    pub connected: bool,
    pub device_name: Option<String>,
    pub services: Vec<BleGattServiceInfo>,
    pub unauthenticated_write_count: usize,
    pub diagnostic_message: String,
}

/// 严格校验并转换 BD_ADDR ("AA:BB:CC:DD:EE:FF" 或 "AABBCCDDEEFF") 为 48-bit u64
/// 从根源阻止恶意字符串进入底层调用，时间复杂度 O(1), 空间复杂度 O(1)
pub fn parse_mac_to_u64(mac: &str) -> Result<u64, String> {
    let hex_only: String = mac
        .trim()
        .chars()
        .filter(|c| *c != ':' && *c != '-')
        .collect();
    if hex_only.len() != 12 || !hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("非法蓝牙 BD_ADDR 地址格式: '{}'", mac));
    }
    u64::from_str_radix(&hex_only, 16)
        .map_err(|e| format!("蓝牙 MAC 转换失败: {}", e))
}

/// 解析 128-bit 标准蓝牙基 UUID (0000XXXX-0000-1000-8000-00805F9B34FB) 并映射官方 SIG 服务名称
#[inline]
pub fn format_ble_uuid_display(uuid_str: &str) -> (String, String) {
    let upper = uuid_str.trim().to_ascii_uppercase();
    let compact: String = upper.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if compact.len() == 32 && compact.starts_with("0000") && compact.ends_with("00001000800000805F9B34FB") {
        if let Ok(short16) = u16::from_str_radix(&compact[4..8], 16) {
            return (format!("0x{:04X}", short16), resolve_ble_service_uuid(short16).to_string());
        }
    }
    (upper, "Custom / Vendor GATT Service".to_string())
}

/// 按特征 UUID 将只读到的 GATT 原始字节翻译为工业人类可读属性
pub fn decode_gatt_characteristic_value(uuid_disp: &str, raw_hex: &str) -> Option<String> {
    let bytes = hex::decode(raw_hex.trim()).ok()?;
    if bytes.is_empty() {
        return None;
    }
    match uuid_disp {
        "0x2A19" => Some(format!("当前电量: {}%", bytes[0].min(100))),
        "0x2A00" | "0x2A24" | "0x2A25" | "0x2A26" | "0x2A27" | "0x2A28" | "0x2A29" => {
            let txt = String::from_utf8_lossy(&bytes).trim_matches('\0').trim().to_string();
            if txt.is_empty() { None } else { Some(txt) }
        }
        "0x2A01" if bytes.len() >= 2 => {
            let code = u16::from_le_bytes([bytes[0], bytes[1]]);
            Some(format!("外观类别: 0x{:04X} ({})", code, resolve_ble_appearance(code)))
        }
        _ => {
            if bytes.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
                Some(String::from_utf8_lossy(&bytes).to_string())
            } else {
                Some(format!("{} B [{}]", bytes.len(), raw_hex))
            }
        }
    }
}

/// 解析 WinRT GATT 文本行流 (`SVC|<uuid>|<handle>` / `CHR|<uuid>|<handle>|<props>|<prot>[|<val_hex>]`)
/// 时间复杂度: O(L) 单遍流式行解析, 空间复杂度: O(S + C)
pub fn parse_ble_gatt_probe_lines(target_address: &str, raw_output: &str) -> BleGattAuditResult {
    let mut connected = false;
    let mut device_name: Option<String> = None;
    let mut status_msg = String::new();
    let mut services: Vec<BleGattServiceInfo> = Vec::new();
    let mut unauthenticated_write_count = 0usize;

    for raw in raw_output.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        match parts.first().copied().unwrap_or("") {
            "DEV" if parts.len() >= 3 => {
                connected = parts[1] == "OK";
                let name_trim = parts[2].trim();
                if !name_trim.is_empty() && name_trim != "<Unknown>" {
                    device_name = Some(name_trim.to_string());
                }
                if let Some(msg) = parts.get(3) {
                    status_msg = msg.trim().to_string();
                }
            }
            "SVC" if parts.len() >= 3 => {
                let (uuid_disp, svc_name) = format_ble_uuid_display(parts[1]);
                let handle = parts[2].trim().parse::<u16>().unwrap_or(0);
                services.push(BleGattServiceInfo {
                    uuid: uuid_disp,
                    service_name: svc_name,
                    handle,
                    characteristics: Vec::new(),
                });
            }
            "CHR" if parts.len() >= 5 => {
                let (uuid_disp, _) = format_ble_uuid_display(parts[1]);
                let handle = parts[2].trim().parse::<u16>().unwrap_or(0);
                let props = parts[3].trim().to_string();
                let prot = parts[4].trim().to_string();
                let raw_value_hex = parts
                    .get(5)
                    .map(|s| s.trim().to_ascii_uppercase())
                    .filter(|s| !s.is_empty());
                let decoded_value = raw_value_hex
                    .as_deref()
                    .and_then(|hx| decode_gatt_characteristic_value(&uuid_disp, hx));

                let is_writable = props.contains("Write");
                let is_plain = prot.eq_ignore_ascii_case("Plain") || prot.is_empty();
                let warning = if is_writable && is_plain {
                    unauthenticated_write_count += 1;
                    Some("UNAUTHENTICATED_WRITE_CAPABLE".to_string())
                } else {
                    None
                };

                if let Some(last_svc) = services.last_mut() {
                    last_svc.characteristics.push(BleGattCharacteristicInfo {
                        uuid: uuid_disp,
                        handle,
                        properties: props,
                        protection_level: prot,
                        security_warning: warning,
                        raw_value_hex,
                        decoded_value,
                    });
                }
            }
            _ => {}
        }
    }

    let diagnostic_message = if !connected {
        if status_msg.is_empty() {
            format!("未能建连 BLE GATT 设备 {} (可能不在近场范围、非可连接广播或不支持直接未配对 GATT 查询)", target_address)
        } else {
            status_msg
        }
    } else {
        let total_chars: usize = services.iter().map(|s| s.characteristics.len()).sum();
        format!(
            "✅ WinRT 原生 GATT 枚举成功: 发现 {} 个服务, {} 项特征 (无鉴权明文可写告警 {} 项)",
            services.len(),
            total_chars,
            unauthenticated_write_count
        )
    };

    BleGattAuditResult {
        target_address: target_address.to_string(),
        connected,
        device_name,
        services,
        unauthenticated_write_count,
        diagnostic_message,
    }
}

/// 对目标蓝牙 BD_ADDR 发起跨进程超时保护的只读 WinRT BLE GATT 安全枚举
pub fn scan_ble_gatt_services_sync(mac_address: &str) -> BleGattAuditResult {
    let addr_u64 = match parse_mac_to_u64(mac_address) {
        Ok(v) => v,
        Err(e) => {
            return BleGattAuditResult {
                target_address: mac_address.to_string(),
                connected: false,
                device_name: None,
                services: Vec::new(),
                unauthenticated_write_count: 0,
                diagnostic_message: e,
            };
        }
    };

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};

        // 地址已清洗为纯粹无符号 u64 十进制整型，物理杜绝 Shell 注入风险
        let ps_script = format!(
            "$ErrorActionPreference='SilentlyContinue'; \
            Add-Type -AssemblyName System.Runtime.WindowsRuntime; \
            $null=[Windows.Devices.Bluetooth.BluetoothLEDevice,Windows.Devices.Bluetooth,ContentType=WindowsRuntime]; \
            $asOp=([System.WindowsRuntimeSystemExtensions].GetMethods()|Where-Object{{$_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'}})[0]; \
            function AwaitWinRT($op,$ty){{ $t=$asOp.MakeGenericMethod($ty).Invoke($null,@($op)); if(-not $t.Wait(2800)){{return $null}}; return $t.Result }}; \
            $dev=AwaitWinRT ([Windows.Devices.Bluetooth.BluetoothLEDevice]::FromBluetoothAddressAsync([uint64]{addr})) ([Windows.Devices.Bluetooth.BluetoothLEDevice]); \
            if($null -eq $dev){{ Write-Output 'DEV|FAIL|<Unknown>|设备未在线或不可达 (FromBluetoothAddressAsync 返回空)'; exit 0 }}; \
            try {{ \
              $svcRes=AwaitWinRT ($dev.GetGattServicesAsync()) ([Windows.Devices.Bluetooth.GenericAttributeProfile.GattDeviceServicesResult]); \
              if($null -eq $svcRes -or $svcRes.Status -ne 'Success'){{ $st=if($svcRes){{$svcRes.Status}}else{{'Timeout'}}; Write-Output \"DEV|FAIL|$($dev.Name)|GATT 服务发现受阻或超时: $st\"; exit 0 }}; \
              Write-Output \"DEV|OK|$($dev.Name)|OK\"; \
              foreach($s in $svcRes.Services){{ \
                Write-Output \"SVC|$($s.Uuid)|$($s.AttributeHandle)\"; \
                $chrRes=AwaitWinRT ($s.GetCharacteristicsAsync()) ([Windows.Devices.Bluetooth.GenericAttributeProfile.GattCharacteristicsResult]); \
                if($chrRes -and $chrRes.Status -eq 'Success'){{ \
                  foreach($c in $chrRes.Characteristics){{ \
                    $vh=''; \
                    if($c.CharacteristicProperties.ToString() -match 'Read'){{ \
                      $uStr=$c.Uuid.ToString().ToUpper(); \
                      if($uStr -match '^00002A(00|01|19|24|25|26|27|28|29)-'){{ \
                        $rr=AwaitWinRT ($c.ReadValueAsync()) ([Windows.Devices.Bluetooth.GenericAttributeProfile.GattReadResult]); \
                        if($rr -and $rr.Status -eq 'Success' -and $rr.Value){{ \
                          $bytes=[System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::ToArray($rr.Value); \
                          if($bytes){{ $vh=($bytes|ForEach-Object{{$_.ToString('X2')}})-join'' }} \
                        }} \
                      }} \
                    }}; \
                    Write-Output \"CHR|$($c.Uuid)|$($c.AttributeHandle)|$($c.CharacteristicProperties)|$($c.ProtectionLevel)|$vh\" \
                  }} \
                }} \
              }} \
            }} finally {{ $dev.Dispose() }}",
            addr = addr_u64
        );

        match Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
            .creation_flags(0x08000000)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                let start = std::time::Instant::now();
                let limit = std::time::Duration::from_millis(6500);
                loop {
                    if let Ok(Some(_)) = child.try_wait() {
                        break;
                    }
                    if start.elapsed() >= limit {
                        let _ = child.kill();
                        return BleGattAuditResult {
                            target_address: mac_address.to_string(),
                            connected: false,
                            device_name: None,
                            services: Vec::new(),
                            unauthenticated_write_count: 0,
                            diagnostic_message: "BLE GATT 连接探测超出 6.5s 安全熔断阈值（硬件无响应）".into(),
                        };
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                if let Ok(output) = child.wait_with_output() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    return parse_ble_gatt_probe_lines(mac_address, &stdout);
                }
            }
            Err(e) => {
                return BleGattAuditResult {
                    target_address: mac_address.to_string(),
                    connected: false,
                    device_name: None,
                    services: Vec::new(),
                    unauthenticated_write_count: 0,
                    diagnostic_message: format!("启动 WinRT BLE GATT 子进程失败: {}", e),
                };
            }
        }
        BleGattAuditResult {
            target_address: mac_address.to_string(),
            connected: false,
            device_name: None,
            services: Vec::new(),
            unauthenticated_write_count: 0,
            diagnostic_message: "WinRT GATT 执行中断".into(),
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = addr_u64;
        BleGattAuditResult {
            target_address: mac_address.to_string(),
            connected: false,
            device_name: None,
            services: Vec::new(),
            unauthenticated_write_count: 0,
            diagnostic_message: "当前系统暂通过 Linux BlueZ / macOS CoreBluetooth 抓取 HCI ACL 获取 GATT 属性".into(),
        }
    }
}

#[tauri::command]
pub async fn scan_ble_gatt_services_cmd(mac_address: String) -> Result<BleGattAuditResult, String> {
    tokio::task::spawn_blocking(move || scan_ble_gatt_services_sync(&mac_address))
        .await
        .map_err(|e| format!("BLE GATT 枚举线程异常: {}", e))
}

// ============================================================================
// 蓝牙持久化历史对照、白名单基线偏移审计 & BTSnoop (RFC 1761) 双向互操作引擎
// ============================================================================

/// 蓝牙设备基准指纹条目 (用于物理环境基线比对)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothBaselineItem {
    pub address: String,
    pub device_name: String,
    pub vendor_info: String,
    pub address_type: String,
    pub baseline_rssi_dbm: i8,
    pub baseline_distance_m: f32,
    pub baseline_adv_interval_ms: Option<f32>,
    pub phy_desc: String,
}

/// 蓝牙基线快照文件结构 (bluetooth_baseline.json)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothBaselineSnapshot {
    pub saved_at: String,
    pub saved_epoch_ms: u64,
    pub device_count: usize,
    pub items: Vec<BluetoothBaselineItem>,
}

/// 实时状态 vs 历史基线单设备差异审计条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothDeviceDriftItem {
    pub address: String,
    pub device_name: String,
    pub vendor_info: String,
    pub status: String, // "NEW_UNKNOWN" | "MISSING" | "DRIFTED" | "STABLE"
    pub baseline_rssi_dbm: Option<i8>,
    pub realtime_rssi_dbm: Option<i8>,
    pub rssi_delta_db: Option<f32>,
    pub baseline_distance_m: Option<f32>,
    pub realtime_distance_m: Option<f32>,
    pub adv_interval_delta_ms: Option<f32>,
    pub security_flags: Vec<String>,
    pub note: String,
}

/// 实时 vs 历史双线时序对照分桶 (HH:MM:SS 粒度)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothTrendBucket {
    pub time_label: String,
    pub historical_avg_rssi: Option<f32>,
    pub historical_device_count: usize,
    pub realtime_avg_rssi: Option<f32>,
    pub realtime_device_count: usize,
}

/// 实时 vs 历史多维比对完整报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothBaselineComparisonResult {
    pub has_baseline: bool,
    pub baseline_saved_at: Option<String>,
    pub history_records_scanned: u64,
    pub corrupted_history_lines: u64,
    pub realtime_device_count: usize,
    pub baseline_device_count: usize,
    pub new_device_count: usize,
    pub missing_device_count: usize,
    pub drifted_device_count: usize,
    pub stable_device_count: usize,
    pub realtime_mean_rssi_dbm: f32,
    pub historical_mean_rssi_dbm: f32,
    pub drift_items: Vec<BluetoothDeviceDriftItem>,
    pub trend_buckets: Vec<BluetoothTrendBucket>,
    pub diagnostic_message: String,
}

/// 从多种时间戳格式中提取标准 8 字符 HH:MM:SS 分桶键 (O(L))
fn extract_bt_hhmmss(ts: &str) -> String {
    let trimmed = ts.trim();
    if let Some(t_pos) = trimmed.find('T') {
        let after = &trimmed[t_pos + 1..];
        let hhmmss: String = after.chars().take_while(|c| c.is_ascii_digit() || *c == ':').take(8).collect();
        if hhmmss.len() == 8 {
            return hhmmss;
        }
    }
    if let Some(sp) = trimmed.find(' ') {
        let after = trimmed[sp + 1..].trim();
        let hhmmss: String = after.chars().take_while(|c| c.is_ascii_digit() || *c == ':').take(8).collect();
        if hhmmss.len() == 8 {
            return hhmmss;
        }
    }
    if trimmed.len() >= 8 && trimmed.as_bytes().get(2) == Some(&b':') && trimmed.as_bytes().get(5) == Some(&b':') {
        return trimmed[..8].to_string();
    }
    if trimmed.is_empty() {
        "00:00:00".to_string()
    } else {
        trimmed.chars().take(8).collect()
    }
}

/// 将当前活跃蓝牙设备资产列表原子持久化为蓝牙基线快照 (bluetooth_baseline.json)
pub fn save_bluetooth_baseline_in_dir(
    dir: &Path,
    summary: &BluetoothTelemetrySummary,
) -> Result<BluetoothBaselineSnapshot, String> {
    if summary.devices.is_empty() {
        return Err("当前未探测到任何活跃蓝牙资产，请先开启实时监听或执行双模扫描后再建立基线".into());
    }
    fs::create_dir_all(dir).map_err(|e| format!("创建蓝牙基线目录失败: {}", e))?;

    let saved_epoch_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let saved_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let items: Vec<BluetoothBaselineItem> = summary
        .devices
        .iter()
        .map(|d| BluetoothBaselineItem {
            address: d.address.clone(),
            device_name: d.device_name.clone(),
            vendor_info: d.vendor_info.clone(),
            address_type: d.address_type.clone(),
            baseline_rssi_dbm: d.avg_rssi_dbm.round().clamp(-127.0, 127.0) as i8,
            baseline_distance_m: d.estimated_distance_m,
            baseline_adv_interval_ms: d.adv_interval_ms,
            phy_desc: d.phy_desc.clone(),
        })
        .collect();

    let snapshot = BluetoothBaselineSnapshot {
        saved_at,
        saved_epoch_ms,
        device_count: items.len(),
        items,
    };

    let bytes = serde_json::to_vec_pretty(&snapshot)
        .map_err(|e| format!("序列化蓝牙基线快照失败: {}", e))?;
    let target = dir.join("bluetooth_baseline.json");
    let tmp = dir.join(format!("bluetooth_baseline.json.tmp_{}", std::process::id()));
    fs::write(&tmp, &bytes).map_err(|e| format!("写入蓝牙基线临时文件失败: {}", e))?;
    #[cfg(windows)]
    if target.exists() {
        let _ = fs::remove_file(&target);
    }
    fs::rename(&tmp, &target).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("原子保存蓝牙基线文件失败: {}", e)
    })?;

    Ok(snapshot)
}

/// 对比当前实时蓝牙遥测快照与历史持久化档案/基线 (时间 O(N + D), 空间 O(D + B))
pub fn compare_bluetooth_realtime_vs_history_in_dir(
    dir: &Path,
    summary: &BluetoothTelemetrySummary,
) -> Result<BluetoothBaselineComparisonResult, String> {
    let baseline_path = dir.join("bluetooth_baseline.json");
    let baseline_opt: Option<BluetoothBaselineSnapshot> = if baseline_path.exists() {
        match fs::read(&baseline_path) {
            Ok(raw) => serde_json::from_slice(&raw).ok(),
            Err(_) => None,
        }
    } else {
        None
    };

    let mut history_records_scanned = 0u64;
    let mut corrupted_history_lines = 0u64;
    let mut hist_rssi_sum = 0.0f64;
    let mut hist_rssi_count = 0u64;

    // 历史隐式设备画像聚合 & 历史分桶统计
    struct HistAgg {
        device_name: String,
        vendor_info: String,
        address_type: String,
        phy_desc: String,
        rssi_sum: f64,
        dist_sum: f64,
        interval_sum: f64,
        interval_cnt: u64,
        count: u64,
    }
    let mut hist_device_agg: HashMap<String, HistAgg> = HashMap::new();
    let mut hist_buckets: std::collections::BTreeMap<String, (f64, u64, HashSet<String>)> =
        std::collections::BTreeMap::new();

    for fname in ["bluetooth_history.jsonl.prev", "bluetooth_history.jsonl"] {
        let path = dir.join(fname);
        let Ok(file) = fs::File::open(&path) else {
            continue;
        };
        let reader = BufReader::new(file);
        for line_res in reader.lines() {
            let Ok(line) = line_res else {
                corrupted_history_lines += 1;
                continue;
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(rec) = serde_json::from_str::<BluetoothHistoryRecord>(trimmed) else {
                corrupted_history_lines += 1;
                continue;
            };
            history_records_scanned += 1;
            hist_rssi_sum += rec.rssi_dbm as f64;
            hist_rssi_count += 1;

            let bucket_key = extract_bt_hhmmss(&rec.timestamp);
            let entry = hist_buckets.entry(bucket_key).or_insert_with(|| (0.0, 0, HashSet::new()));
            entry.0 += rec.rssi_dbm as f64;
            entry.1 += 1;
            entry.2.insert(rec.address.clone());
            // 仅保最新 60 个分桶防内存上涨
            if hist_buckets.len() > 60 {
                if let Some(first_k) = hist_buckets.keys().next().cloned() {
                    hist_buckets.remove(&first_k);
                }
            }

            let agg = hist_device_agg.entry(rec.address.clone()).or_insert_with(|| HistAgg {
                device_name: rec.device_name.clone(),
                vendor_info: rec.vendor_info.clone(),
                address_type: rec.address_type.clone(),
                phy_desc: rec.phy_desc.clone(),
                rssi_sum: 0.0,
                dist_sum: 0.0,
                interval_sum: 0.0,
                interval_cnt: 0,
                count: 0,
            });
            agg.rssi_sum += rec.rssi_dbm as f64;
            agg.dist_sum += rec.estimated_distance_m as f64;
            if let Some(ms) = rec.adv_interval_ms {
                agg.interval_sum += ms as f64;
                agg.interval_cnt += 1;
            }
            agg.count += 1;
        }
    }

    // 构建比对基准参考字典：优先采用显式保存的 baseline.json，若不存在则自动从历史存档推导基线
    let has_explicit_baseline = baseline_opt.is_some();
    let baseline_saved_at = baseline_opt.as_ref().map(|b| b.saved_at.clone());
    let base_items: Vec<BluetoothBaselineItem> = if let Some(b) = baseline_opt {
        b.items
    } else {
        hist_device_agg
            .iter()
            .map(|(addr, agg)| {
                let cnt = agg.count.max(1) as f64;
                BluetoothBaselineItem {
                    address: addr.clone(),
                    device_name: agg.device_name.clone(),
                    vendor_info: agg.vendor_info.clone(),
                    address_type: agg.address_type.clone(),
                    baseline_rssi_dbm: (agg.rssi_sum / cnt).round().clamp(-127.0, 127.0) as i8,
                    baseline_distance_m: ((agg.dist_sum / cnt) * 100.0).round() as f32 / 100.0,
                    baseline_adv_interval_ms: if agg.interval_cnt > 0 {
                        Some((agg.interval_sum / agg.interval_cnt as f64) as f32)
                    } else {
                        None
                    },
                    phy_desc: agg.phy_desc.clone(),
                }
            })
            .collect()
    };

    let base_map: HashMap<String, &BluetoothBaselineItem> =
        base_items.iter().map(|i| (i.address.clone(), i)).collect();
    let rt_map: HashMap<String, &BluetoothDeviceAsset> =
        summary.devices.iter().map(|d| (d.address.clone(), d)).collect();

    let mut drift_items: Vec<BluetoothDeviceDriftItem> = Vec::new();
    let mut new_device_count = 0usize;
    let mut missing_device_count = 0usize;
    let mut drifted_device_count = 0usize;
    let mut stable_device_count = 0usize;

    for rt in &summary.devices {
        if let Some(base) = base_map.get(&rt.address) {
            let rssi_delta = ((rt.avg_rssi_dbm - base.baseline_rssi_dbm as f32) * 10.0).round() / 10.0;
            let dist_delta = (rt.estimated_distance_m - base.baseline_distance_m).abs();
            let int_delta = match (rt.adv_interval_ms, base.baseline_adv_interval_ms) {
                (Some(r_ms), Some(b_ms)) => Some(((r_ms - b_ms) * 10.0).round() / 10.0),
                _ => None,
            };
            let is_drifted = rssi_delta.abs() >= 8.0
                || dist_delta >= 2.5
                || int_delta.is_some_and(|d| d.abs() >= 150.0);

            if is_drifted {
                drifted_device_count += 1;
                drift_items.push(BluetoothDeviceDriftItem {
                    address: rt.address.clone(),
                    device_name: rt.device_name.clone(),
                    vendor_info: rt.vendor_info.clone(),
                    status: "DRIFTED".into(),
                    baseline_rssi_dbm: Some(base.baseline_rssi_dbm),
                    realtime_rssi_dbm: Some(rt.last_rssi_dbm),
                    rssi_delta_db: Some(rssi_delta),
                    baseline_distance_m: Some(base.baseline_distance_m),
                    realtime_distance_m: Some(rt.estimated_distance_m),
                    adv_interval_delta_ms: int_delta,
                    security_flags: rt.security_flags.clone(),
                    note: format!(
                        "场强漂移 {:+.1} dB ({} -> {} dBm, 距离 {:.2}m -> {:.2}m)",
                        rssi_delta,
                        base.baseline_rssi_dbm,
                        rt.last_rssi_dbm,
                        base.baseline_distance_m,
                        rt.estimated_distance_m
                    ),
                });
            } else {
                stable_device_count += 1;
                drift_items.push(BluetoothDeviceDriftItem {
                    address: rt.address.clone(),
                    device_name: rt.device_name.clone(),
                    vendor_info: rt.vendor_info.clone(),
                    status: "STABLE".into(),
                    baseline_rssi_dbm: Some(base.baseline_rssi_dbm),
                    realtime_rssi_dbm: Some(rt.last_rssi_dbm),
                    rssi_delta_db: Some(rssi_delta),
                    baseline_distance_m: Some(base.baseline_distance_m),
                    realtime_distance_m: Some(rt.estimated_distance_m),
                    adv_interval_delta_ms: int_delta,
                    security_flags: rt.security_flags.clone(),
                    note: format!("基线一致 ({:+.1} dB, {:.2} m)", rssi_delta, rt.estimated_distance_m),
                });
            }
        } else {
            new_device_count += 1;
            drift_items.push(BluetoothDeviceDriftItem {
                address: rt.address.clone(),
                device_name: rt.device_name.clone(),
                vendor_info: rt.vendor_info.clone(),
                status: "NEW_UNKNOWN".into(),
                baseline_rssi_dbm: None,
                realtime_rssi_dbm: Some(rt.last_rssi_dbm),
                rssi_delta_db: None,
                baseline_distance_m: None,
                realtime_distance_m: Some(rt.estimated_distance_m),
                adv_interval_delta_ms: None,
                security_flags: rt.security_flags.clone(),
                note: format!("基线外新增蓝牙设备 ({} dBm · ~{:.2} m)", rt.last_rssi_dbm, rt.estimated_distance_m),
            });
        }
    }

    for base in &base_items {
        if !rt_map.contains_key(&base.address) {
            missing_device_count += 1;
            drift_items.push(BluetoothDeviceDriftItem {
                address: base.address.clone(),
                device_name: base.device_name.clone(),
                vendor_info: base.vendor_info.clone(),
                status: "MISSING".into(),
                baseline_rssi_dbm: Some(base.baseline_rssi_dbm),
                realtime_rssi_dbm: None,
                rssi_delta_db: None,
                baseline_distance_m: Some(base.baseline_distance_m),
                realtime_distance_m: None,
                adv_interval_delta_ms: None,
                security_flags: Vec::new(),
                note: format!("基线资产当前离线/失联 (原基线 {} dBm)", base.baseline_rssi_dbm),
            });
        }
    }

    drift_items.sort_by_key(|item| match item.status.as_str() {
        "NEW_UNKNOWN" => 0,
        "MISSING" => 1,
        "DRIFTED" => 2,
        _ => 3,
    });

    // 构建实时 vs 历史对比时间桶序列 (保留最新 36 个时间桶)
    let mut rt_buckets: std::collections::BTreeMap<String, (f64, u64, HashSet<String>)> =
        std::collections::BTreeMap::new();
    for s in &summary.rssi_history {
        let key = extract_bt_hhmmss(&s.timestamp);
        let entry = rt_buckets.entry(key).or_insert_with(|| (0.0, 0, HashSet::new()));
        entry.0 += s.rssi_dbm as f64;
        entry.1 += 1;
        entry.2.insert(s.address.clone());
    }

    let mut all_keys: std::collections::BTreeSet<String> = hist_buckets.keys().cloned().collect();
    for k in rt_buckets.keys() {
        all_keys.insert(k.clone());
    }
    let key_vec: Vec<String> = all_keys.into_iter().collect();
    let start_idx = key_vec.len().saturating_sub(36);
    let trend_buckets: Vec<BluetoothTrendBucket> = key_vec[start_idx..]
        .iter()
        .map(|k| {
            let h = hist_buckets.get(k);
            let r = rt_buckets.get(k);
            BluetoothTrendBucket {
                time_label: k.clone(),
                historical_avg_rssi: h.map(|(s, c, _)| (((*s / (*c).max(1) as f64) * 10.0).round() / 10.0) as f32),
                historical_device_count: h.map(|(_, _, set)| set.len()).unwrap_or(0),
                realtime_avg_rssi: r.map(|(s, c, _)| (((*s / (*c).max(1) as f64) * 10.0).round() / 10.0) as f32),
                realtime_device_count: r.map(|(_, _, set)| set.len()).unwrap_or(0),
            }
        })
        .collect();

    let realtime_mean_rssi_dbm = if summary.devices.is_empty() {
        0.0
    } else {
        let sum: f32 = summary.devices.iter().map(|d| d.avg_rssi_dbm).sum();
        ((sum / summary.devices.len() as f32) * 10.0).round() / 10.0
    };
    let historical_mean_rssi_dbm = if hist_rssi_count > 0 {
        (((hist_rssi_sum / hist_rssi_count as f64) * 10.0).round() / 10.0) as f32
    } else if !base_items.is_empty() {
        let sum: f32 = base_items.iter().map(|b| b.baseline_rssi_dbm as f32).sum();
        ((sum / base_items.len() as f32) * 10.0).round() / 10.0
    } else {
        0.0
    };

    let diagnostic_message = if !has_explicit_baseline && history_records_scanned == 0 {
        "尚未创建蓝牙环境基线且历史记录为空，请先采集数秒实时报文并点击「保存资产基线」".into()
    } else if has_explicit_baseline {
        format!(
            "已对照基线 ({}, {} 台) 与 {} 条历史采样: 新增陌生 {} 台, 失联 {} 台, 显著漂移 {} 台, 稳定 {} 台",
            baseline_saved_at.as_deref().unwrap_or("-"),
            base_items.len(),
            history_records_scanned,
            new_device_count,
            missing_device_count,
            drifted_device_count,
            stable_device_count
        )
    } else {
        format!(
            "未检测到显式基线文件，已自动回溯历史库 {} 条采样 ({} 台历史设备): 新增 {} 台, 失联 {} 台, 漂移 {} 台",
            history_records_scanned,
            base_items.len(),
            new_device_count,
            missing_device_count,
            drifted_device_count
        )
    };

    Ok(BluetoothBaselineComparisonResult {
        has_baseline: has_explicit_baseline || !base_items.is_empty(),
        baseline_saved_at,
        history_records_scanned,
        corrupted_history_lines,
        realtime_device_count: summary.devices.len(),
        baseline_device_count: base_items.len(),
        new_device_count,
        missing_device_count,
        drifted_device_count,
        stable_device_count,
        realtime_mean_rssi_dbm,
        historical_mean_rssi_dbm,
        drift_items,
        trend_buckets,
        diagnostic_message,
    })
}

#[tauri::command]
pub async fn save_bluetooth_baseline_cmd() -> Result<BluetoothBaselineSnapshot, String> {
    tokio::task::spawn_blocking(|| {
        let dir = bluetooth_data_dir().ok_or_else(|| "无法定位应用数据存储目录".to_string())?;
        let summary = get_bluetooth_telemetry_summary();
        save_bluetooth_baseline_in_dir(&dir, &summary)
    })
    .await
    .map_err(|e| format!("保存蓝牙基线线程异常: {}", e))?
}

#[tauri::command]
pub async fn compare_bluetooth_realtime_vs_history_cmd() -> Result<BluetoothBaselineComparisonResult, String> {
    tokio::task::spawn_blocking(|| {
        let dir = bluetooth_data_dir().ok_or_else(|| "无法定位应用数据存储目录".to_string())?;
        let summary = get_bluetooth_telemetry_summary();
        compare_bluetooth_realtime_vs_history_in_dir(&dir, &summary)
    })
    .await
    .map_err(|e| format!("对比蓝牙实时与历史线程异常: {}", e))?
}

// ============================================================================
// BTSnoop (RFC 1761) 标准二进制格式导出与 Wireshark / Android HCI 日志重放导入
// ============================================================================

const BTSNOOP_MAGIC: &[u8; 8] = b"btsnoop\0";
const BTSNOOP_UNIX_TO_0000_OFFSET_US: u64 = 0x00dc_ddb3_0f2f_8000;

/// BTSnoop 导出回执
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtsnoopExportResult {
    pub saved: bool,
    pub cancelled: bool,
    pub path: Option<String>,
    pub packet_count: usize,
    pub bytes_written: u64,
    pub message: String,
}

/// BTSnoop 导入重放与统计汇总
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtsnoopImportResult {
    pub cancelled: bool,
    pub file_path: Option<String>,
    pub datalink_type: u32,
    pub imported_packets: usize,
    pub skipped_records: usize,
    pub adv_packets: usize,
    pub acl_packets: usize,
    pub cmd_packets: usize,
    pub evt_packets: usize,
    pub summary: BluetoothTelemetrySummary,
    pub diagnostic_message: String,
}

/// 将内存帧集合编码为行业标准 RFC 1761 BTSnoop (Datalink 1002 HCI UART H4) 二进制字节流
/// 时间复杂度: O(N * B); 空间复杂度: O(N * B)
pub fn encode_frames_to_btsnoop(frames: &[BluetoothFrameLogItem]) -> Result<(Vec<u8>, usize), String> {
    if frames.is_empty() {
        return Err("当前缓存中没有任何可导出的蓝牙 HCI/BLE 原始帧，请先开启监听或扫描抓包".into());
    }
    let mut ordered: Vec<&BluetoothFrameLogItem> = frames.iter().collect();
    ordered.sort_by_key(|f| f.id);

    let mut out = Vec::with_capacity(16 + ordered.len() * 64);
    out.extend_from_slice(BTSNOOP_MAGIC);
    out.extend_from_slice(&1u32.to_be_bytes()); // Version = 1
    out.extend_from_slice(&1002u32.to_be_bytes()); // Datalink = HCI UART (H4)

    let base_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;
    let base_ts_us = BTSNOOP_UNIX_TO_0000_OFFSET_US.saturating_add(base_us);

    let mut exported = 0usize;
    for (idx, frame) in ordered.iter().enumerate() {
        let clean_hex: String = frame.raw_hex.chars().filter(|c| !c.is_whitespace()).collect();
        let Ok(mut payload) = hex::decode(&clean_hex) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        // 确保帧以合法 H4 指示字节开头
        if !matches!(payload[0], 0x01..=0x05) {
            let indicator = match frame.protocol_layer.as_str() {
                "HCI-CMD" => 0x01,
                "HCI-ACL" | "L2CAP-ATT" | "L2CAP-SMP" | "L2CAP-SIG" => 0x02,
                _ => 0x04,
            };
            payload.insert(0, indicator);
        }
        if payload.len() > 65535 {
            continue;
        }

        let is_rx = frame.direction != "HOST_TX";
        let is_cmd_or_evt = matches!(payload[0], 0x01 | 0x04);
        let flags: u32 = (if is_rx { 1 } else { 0 }) | (if is_cmd_or_evt { 2 } else { 0 });
        let len_u32 = payload.len() as u32;
        let ts_us = base_ts_us.saturating_add((idx as u64) * 1000);

        out.extend_from_slice(&len_u32.to_be_bytes()); // original length
        out.extend_from_slice(&len_u32.to_be_bytes()); // included length
        out.extend_from_slice(&flags.to_be_bytes()); // packet flags
        out.extend_from_slice(&0u32.to_be_bytes()); // cumulative drops
        out.extend_from_slice(&ts_us.to_be_bytes()); // timestamp microseconds since 0 AD
        out.extend_from_slice(&payload);
        exported += 1;
    }

    if exported == 0 {
        return Err("缓存帧均缺少有效二进制 HEX 载荷，无法生成标准 .btsnoop 文件".into());
    }
    Ok((out, exported))
}

/// 解析标准 RFC 1761 BTSnoop 文件字节流 (兼容 Datalink 1001/1002/2001 与 Android btsnoop_hci.log)
/// 带严格边界截断与 OOM 防护 (单帧 > 64KB 或总帧 > 20000 安全截断)
pub fn decode_btsnoop_file_bytes(data: &[u8]) -> Result<(u32, Vec<(bool, u64, Vec<u8>)>, usize), String> {
    if data.len() < 16 {
        return Err("文件长度不足 16 字节，非有效 RFC 1761 BTSnoop 文件".into());
    }
    if &data[0..8] != BTSNOOP_MAGIC {
        return Err("文件头魔数不是 \"btsnoop\\0\"，无法按 BTSnoop 格式解析".into());
    }
    let version = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    if version != 1 {
        return Err(format!("不支持的 BTSnoop 版本号: {} (仅支持 Version 1)", version));
    }
    let datalink = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    if !matches!(datalink, 1001 | 1002 | 2001) {
        return Err(format!("不支持的 BTSnoop Datalink 类型: {} (仅支持 HCI 1001 / UART H4 1002 / Monitor 2001)", datalink));
    }

    let mut offset = 16usize;
    let mut records: Vec<(bool, u64, Vec<u8>)> = Vec::new();
    let mut skipped = 0usize;
    let mut first_ts_us: Option<u64> = None;

    while offset + 24 <= data.len() {
        if records.len() >= 20_000 {
            skipped += 1;
            break;
        }
        let _orig_len = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        let incl_len = u32::from_be_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]) as usize;
        let flags = u32::from_be_bytes([data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]]);
        let ts_us = u64::from_be_bytes([
            data[offset + 16], data[offset + 17], data[offset + 18], data[offset + 19],
            data[offset + 20], data[offset + 21], data[offset + 22], data[offset + 23],
        ]);
        offset += 24;

        if incl_len == 0 || incl_len > 65_536 || offset + incl_len > data.len() {
            skipped += 1;
            break;
        }
        let payload = &data[offset..offset + incl_len];
        offset += incl_len;

        let is_tx = (flags & 0x01) == 0;
        let is_cmd_evt = (flags & 0x02) != 0;
        let rel_ms = match first_ts_us {
            Some(first) => ts_us.saturating_sub(first) / 1000,
            None => {
                first_ts_us = Some(ts_us);
                0
            }
        };

        let h4_packet = match datalink {
            1002 => payload.to_vec(),
            1001 => {
                let ind = if is_cmd_evt {
                    if is_tx { 0x01 } else { 0x04 }
                } else {
                    0x02
                };
                let mut v = Vec::with_capacity(1 + payload.len());
                v.push(ind);
                v.extend_from_slice(payload);
                v
            }
            2001 => {
                // BlueZ Monitor (4 字节小端 opcode) 简化映射到 H4
                if payload.len() >= 4 {
                    let opcode = u16::from_le_bytes([payload[0], payload[1]]);
                    let ind = match opcode {
                        2 => 0x01,
                        3 => 0x04,
                        4 | 5 => 0x02,
                        _ => 0x00,
                    };
                    if ind != 0 {
                        let mut v = Vec::with_capacity(1 + payload.len() - 4);
                        v.push(ind);
                        v.extend_from_slice(&payload[4..]);
                        v
                    } else {
                        skipped += 1;
                        continue;
                    }
                } else {
                    skipped += 1;
                    continue;
                }
            }
            _ => payload.to_vec(),
        };

        records.push((is_tx, rel_ms, h4_packet));
    }

    Ok((datalink, records, skipped))
}

#[tauri::command]
pub async fn export_bluetooth_btsnoop_cmd() -> Result<BtsnoopExportResult, String> {
    tokio::task::spawn_blocking(|| {
        let frames: Vec<BluetoothFrameLogItem> = {
            let lock = GLOBAL_BLUETOOTH_MONITOR
                .read()
                .unwrap_or_else(|p| p.into_inner());
            lock.recent_frames.iter().cloned().collect()
        };
        let (bytes, count) = encode_frames_to_btsnoop(&frames)?;
        let default_name = format!(
            "omni_probe_bt_{}.btsnoop",
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        );
        let outcome = crate::desktop_native::save_bytes_with_native_dialog(
            &default_name,
            "导出标准 BTSnoop (RFC 1761) 抓包文件",
            "BTSnoop 蓝牙协议抓包 (*.btsnoop)",
            "*.btsnoop",
            &bytes,
        )?;
        Ok(BtsnoopExportResult {
            saved: outcome.saved,
            cancelled: outcome.cancelled,
            path: outcome.path,
            packet_count: count,
            bytes_written: outcome.bytes_written,
            message: if outcome.cancelled {
                "已取消 BTSnoop 导出".into()
            } else {
                format!("已将 {} 帧原生蓝牙流量导出为 Wireshark 标准 .btsnoop ({} 字节)", count, outcome.bytes_written)
            },
        })
    })
    .await
    .map_err(|e| format!("BTSnoop 导出线程异常: {}", e))?
}

#[tauri::command]
pub async fn pick_and_import_bluetooth_btsnoop_cmd() -> Result<BtsnoopImportResult, String> {
    tokio::task::spawn_blocking(|| {
        let picked = crate::desktop_native::pick_native_file_dialog(
            "选择要导入重放的 BTSnoop 抓包文件 (Wireshark / Android btsnoop_hci.log)",
            "BTSnoop 捕获日志 (*.btsnoop;*.log;*.hci)",
            "*.btsnoop;*.log;*.hci",
        )?;
        let Some(path) = picked else {
            return Ok(BtsnoopImportResult {
                cancelled: true,
                file_path: None,
                datalink_type: 0,
                imported_packets: 0,
                skipped_records: 0,
                adv_packets: 0,
                acl_packets: 0,
                cmd_packets: 0,
                evt_packets: 0,
                summary: get_bluetooth_telemetry_summary(),
                diagnostic_message: "已取消导入 BTSnoop 文件".into(),
            });
        };

        let meta = fs::metadata(&path).map_err(|e| format!("无法读取文件元数据: {}", e))?;
        if meta.len() > 64 * 1024 * 1024 {
            return Err("BTSnoop 文件超过 64MB 单次分析安全阈值，请截取片段后再导入".into());
        }
        let raw = fs::read(&path).map_err(|e| format!("读取 BTSnoop 文件失败: {}", e))?;
        let (datalink, records, mut skipped) = decode_btsnoop_file_bytes(&raw)?;

        reset_bluetooth_telemetry();
        let base_ms = now_monotonic_ms();
        let mut imported = 0usize;
        let mut adv_cnt = 0usize;
        let mut acl_cnt = 0usize;
        let mut cmd_cnt = 0usize;
        let mut evt_cnt = 0usize;

        for (idx, (is_tx, rel_ms, h4)) in records.into_iter().enumerate() {
            if let Some(mut info) = parse_bluetooth_packet(&h4) {
                info.arrival_timestamp_ms = Some(base_ms.saturating_add(rel_ms));
                info.source_tag = Some(if is_tx { "BTSnoop-TX".into() } else { "BTSnoop-RX".into() });
                if info.ble_adv_type.is_some() {
                    adv_cnt += 1;
                }
                match info.hci_type {
                    HciPacketType::AclData => acl_cnt += 1,
                    HciPacketType::Command => cmd_cnt += 1,
                    HciPacketType::Event => evt_cnt += 1,
                    _ => {}
                }
                let sec = (rel_ms / 1000) % 86400;
                let ts_label = format!(
                    "{:02}:{:02}:{:02}.{:03}",
                    (sec / 3600) % 24,
                    (sec / 60) % 60,
                    sec % 60,
                    rel_ms % 1000
                );
                record_bluetooth_packet(&info, &ts_label);
                imported += 1;
            } else {
                skipped += 1;
                let _ = idx;
            }
        }

        let summary = get_bluetooth_telemetry_summary();
        Ok(BtsnoopImportResult {
            cancelled: false,
            file_path: Some(path.clone()),
            datalink_type: datalink,
            imported_packets: imported,
            skipped_records: skipped,
            adv_packets: adv_cnt,
            acl_packets: acl_cnt,
            cmd_packets: cmd_cnt,
            evt_packets: evt_cnt,
            summary,
            diagnostic_message: format!(
                "已重放 BTSnoop (Datalink {}): 成功还原 {} 帧 (ADV {}, ACL {}, CMD {}, EVT {}), 跳过 {} 条不支持/截断记录",
                datalink, imported, adv_cnt, acl_cnt, cmd_cnt, evt_cnt, skipped
            ),
        })
    })
    .await
    .map_err(|e| format!("BTSnoop 导入重放线程异常: {}", e))?
}

// ============================================================================
// BLE GATT 单可读特征实时直接读取 (WinRT Uncached Read + 物理语义译码)
// ============================================================================

/// 单特征实时读取返回值
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleGattCharacteristicReadResult {
    pub target_address: String,
    pub characteristic_uuid: String,
    pub success: bool,
    pub raw_value_hex: Option<String>,
    pub decoded_value: Option<String>,
    pub diagnostic_message: String,
}

/// 严格校验并标准化 UUID (支持 0xXXXX / XXXX 16-bit 短码与完整 128-bit GUID)，杜绝任何命令行拼接注入风险
fn validate_uuid_chars(uuid: &str) -> Result<String, String> {
    let trimmed = uuid.trim().to_ascii_lowercase();
    let short_candidate = trimmed.strip_prefix("0x").unwrap_or(&trimmed);
    if short_candidate.len() == 4 && short_candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(format!("0000{}-0000-1000-8000-00805f9b34fb", short_candidate));
    }
    let hex_only: String = trimmed.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if trimmed.len() <= 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == '-') && hex_only.len() == 32 {
        return Ok(format!(
            "{}-{}-{}-{}-{}",
            &hex_only[0..8],
            &hex_only[8..12],
            &hex_only[12..16],
            &hex_only[16..20],
            &hex_only[20..32]
        ));
    }
    Err(format!("非法 UUID 字符串: {}", uuid))
}

/// 从真实 BLE 外设只读读取指定 GATT 特征的实时未缓存寄存器字节并做物理量译码
pub fn read_ble_gatt_characteristic_sync(
    mac_address: &str,
    char_uuid: &str,
) -> BleGattCharacteristicReadResult {
    let addr_u64 = match parse_mac_to_u64(mac_address) {
        Ok(v) => v,
        Err(e) => {
            return BleGattCharacteristicReadResult {
                target_address: mac_address.to_string(),
                characteristic_uuid: char_uuid.to_string(),
                success: false,
                raw_value_hex: None,
                decoded_value: None,
                diagnostic_message: e,
            };
        }
    };
    let clean_uuid = match validate_uuid_chars(char_uuid) {
        Ok(u) => u,
        Err(e) => {
            return BleGattCharacteristicReadResult {
                target_address: mac_address.to_string(),
                characteristic_uuid: char_uuid.to_string(),
                success: false,
                raw_value_hex: None,
                decoded_value: None,
                diagnostic_message: e,
            };
        }
    };

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};

        let ps_script = format!(
            "$ErrorActionPreference='SilentlyContinue'; \
            Add-Type -AssemblyName System.Runtime.WindowsRuntime; \
            $null=[Windows.Devices.Bluetooth.BluetoothLEDevice,Windows.Devices.Bluetooth,ContentType=WindowsRuntime]; \
            $asOp=([System.WindowsRuntimeSystemExtensions].GetMethods()|Where-Object{{$_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'}})[0]; \
            function AwaitWinRT($op,$ty){{ $t=$asOp.MakeGenericMethod($ty).Invoke($null,@($op)); if(-not $t.Wait(2800)){{return $null}}; return $t.Result }}; \
            $dev=AwaitWinRT ([Windows.Devices.Bluetooth.BluetoothLEDevice]::FromBluetoothAddressAsync([uint64]{addr})) ([Windows.Devices.Bluetooth.BluetoothLEDevice]); \
            if($null -eq $dev){{ Write-Output 'ERR|设备当前未在连接范围或不可达'; exit 0 }}; \
            try {{ \
              $svcRes=AwaitWinRT ($dev.GetGattServicesAsync()) ([Windows.Devices.Bluetooth.GenericAttributeProfile.GattDeviceServicesResult]); \
              if($null -eq $svcRes -or $svcRes.Status -ne 'Success'){{ Write-Output 'ERR|GATT 服务发现失败'; exit 0 }}; \
              $target='{uuid}'; \
              foreach($s in $svcRes.Services){{ \
                $chrRes=AwaitWinRT ($s.GetCharacteristicsAsync()) ([Windows.Devices.Bluetooth.GenericAttributeProfile.GattCharacteristicsResult]); \
                if($chrRes -and $chrRes.Status -eq 'Success'){{ \
                  foreach($c in $chrRes.Characteristics){{ \
                    if($c.Uuid.ToString().ToLower() -eq $target){{ \
                      $rr=AwaitWinRT ($c.ReadValueAsync([Windows.Devices.Bluetooth.BluetoothCacheMode]::Uncached)) ([Windows.Devices.Bluetooth.GenericAttributeProfile.GattReadResult]); \
                      if($rr -and $rr.Status -eq 'Success' -and $rr.Value){{ \
                        $bytes=[System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::ToArray($rr.Value); \
                        $vh=if($bytes){{($bytes|ForEach-Object{{$_.ToString('X2')}})-join''}}else{{''}}; \
                        Write-Output \"OK|$vh\"; exit 0 \
                      }} else {{ \
                        $st=if($rr){{$rr.Status}}else{{'Timeout'}}; Write-Output \"ERR|ReadValueAsync 返回状态: $st\"; exit 0 \
                      }} \
                    }} \
                  }} \
                }} \
              }}; \
              Write-Output 'ERR|未在该设备发现匹配的 GATT 特征 UUID'; \
            }} finally {{ $dev.Dispose() }}",
            addr = addr_u64,
            uuid = clean_uuid
        );

        match Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
            .creation_flags(0x08000000)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                let start = std::time::Instant::now();
                let limit = std::time::Duration::from_millis(6000);
                loop {
                    if let Ok(Some(_)) = child.try_wait() {
                        break;
                    }
                    if start.elapsed() >= limit {
                        let _ = child.kill();
                        return BleGattCharacteristicReadResult {
                            target_address: mac_address.to_string(),
                            characteristic_uuid: clean_uuid,
                            success: false,
                            raw_value_hex: None,
                            decoded_value: None,
                            diagnostic_message: "GATT 特征读取超时 (6.0s 熔断)".into(),
                        };
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                if let Ok(output) = child.wait_with_output() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        let t = line.trim();
                        if let Some(hex_val) = t.strip_prefix("OK|") {
                            let (disp_uuid, _) = format_ble_uuid_display(&clean_uuid);
                            let decoded = decode_gatt_characteristic_value(&disp_uuid, hex_val);
                            return BleGattCharacteristicReadResult {
                                target_address: mac_address.to_string(),
                                characteristic_uuid: disp_uuid,
                                success: true,
                                raw_value_hex: Some(hex_val.to_string()),
                                decoded_value: decoded,
                                diagnostic_message: "Uncached 实时读取成功".into(),
                            };
                        } else if let Some(err_msg) = t.strip_prefix("ERR|") {
                            return BleGattCharacteristicReadResult {
                                target_address: mac_address.to_string(),
                                characteristic_uuid: clean_uuid,
                                success: false,
                                raw_value_hex: None,
                                decoded_value: None,
                                diagnostic_message: err_msg.to_string(),
                            };
                        }
                    }
                }
            }
            Err(e) => {
                return BleGattCharacteristicReadResult {
                    target_address: mac_address.to_string(),
                    characteristic_uuid: clean_uuid,
                    success: false,
                    raw_value_hex: None,
                    decoded_value: None,
                    diagnostic_message: format!("启动 WinRT GATT 读取子进程失败: {}", e),
                };
            }
        }
        BleGattCharacteristicReadResult {
            target_address: mac_address.to_string(),
            characteristic_uuid: clean_uuid,
            success: false,
            raw_value_hex: None,
            decoded_value: None,
            diagnostic_message: "WinRT GATT 特征读取无输出".into(),
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = addr_u64;
        BleGattCharacteristicReadResult {
            target_address: mac_address.to_string(),
            characteristic_uuid: clean_uuid,
            success: false,
            raw_value_hex: None,
            decoded_value: None,
            diagnostic_message: "当前非 Windows 平台暂不支持 WinRT Uncached GATT 特征直接读取".into(),
        }
    }
}

#[tauri::command]
pub async fn read_ble_gatt_characteristic_cmd(
    mac_address: String,
    char_uuid: String,
) -> Result<BleGattCharacteristicReadResult, String> {
    tokio::task::spawn_blocking(move || read_ble_gatt_characteristic_sync(&mac_address, &char_uuid))
        .await
        .map_err(|e| format!("GATT 特征读取线程异常: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_GLOBAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    #[test]
    fn test_bluetooth_rssi_history_and_native_scan_boundary() {
        let _guard = TEST_GLOBAL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_bluetooth_telemetry();
        let adv = vec![
            0x04, 0x3E, 17, 0x02, 0x01, 0x00, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x03, 0x02, 0x01, 0x06,
            (-58i8) as u8,
        ];
        if let Some(parsed) = parse_bluetooth_packet(&adv) {
            record_bluetooth_packet(&parsed, "18:00:00");
        }
        let summary = get_bluetooth_telemetry_summary();
        assert_eq!(summary.rssi_history.len(), 1);
        assert_eq!(summary.rssi_history[0].rssi_dbm, -58);

        #[cfg(target_os = "windows")]
        {
            assert_eq!(std::mem::size_of::<win_bth::BluetoothFindRadioParams>(), 4);
            assert_eq!(std::mem::size_of::<win_bth::BluetoothRadioInfo>(), 520);
            assert_eq!(std::mem::size_of::<win_bth::BluetoothDeviceSearchParams>(), 40);
            assert_eq!(std::mem::size_of::<win_bth::BluetoothDeviceInfo>(), 560);
        }

        let res = scan_native_bluetooth_devices(false);
        assert!(!res.diagnostic_message.is_empty());
        assert_eq!(res.summary.active_device_count >= res.ble_adv_count.min(1), true);
    }

    #[test]
    fn test_ble_gatt_parser_mac_validation_and_unauthenticated_write_audit() {
        // 1. 强校验合法与恶意注入 MAC 地址
        assert_eq!(parse_mac_to_u64("AA:BB:CC:11:22:33").unwrap(), 0xAABBCC112233);
        assert!(parse_mac_to_u64("AA:BB:CC; calc.exe").is_err());
        assert!(parse_mac_to_u64("").is_err());

        // 2. 模拟 WinRT GATT 输出文本解析与未鉴权明文可写告警检测
        let sample_lines = "\
DEV|OK|Sensor-Node-A1|OK\n\
SVC|0000180f-0000-1000-8000-00805f9b34fb|16\n\
CHR|00002a19-0000-1000-8000-00805f9b34fb|17|Read, Notify|Plain\n\
SVC|0000fe95-0000-1000-8000-00805f9b34fb|32\n\
CHR|0000ffe1-0000-1000-8000-00805f9b34fb|33|WriteWithoutResponse, Notify|Plain\n\
";
        let audit = parse_ble_gatt_probe_lines("AA:BB:CC:11:22:33", sample_lines);
        assert!(audit.connected);
        assert_eq!(audit.device_name.as_deref(), Some("Sensor-Node-A1"));
        assert_eq!(audit.services.len(), 2);
        assert_eq!(audit.services[0].uuid, "0x180F");
        assert!(audit.services[0].service_name.contains("Battery"));
        assert_eq!(audit.unauthenticated_write_count, 1);
        assert_eq!(
            audit.services[1].characteristics[0].security_warning.as_deref(),
            Some("UNAUTHENTICATED_WRITE_CAPABLE")
        );

        // 3. 验证离线不存在设备的真实超时与诚实失败反馈（0 幻觉服务）
        let offline = scan_ble_gatt_services_sync("11:22:33:44:55:66");
        assert!(!offline.connected);
        assert!(offline.services.is_empty());
        assert!(!offline.diagnostic_message.is_empty());
    }

    #[test]
    fn test_deep_ad_tlv_beacons_smp_and_bthport_etw_decoding() {
        // 1. iBeacon + Name + TxPower 完整解析测试
        let mut ibeacon_ad = Vec::new();
        ibeacon_ad.extend_from_slice(&[2, 0x01, 0x06]); // Flags
        ibeacon_ad.extend_from_slice(&[2, 0x0A, (-59i8) as u8]); // TxPower -59
        ibeacon_ad.extend_from_slice(&[2, 0x19]); // invalid placeholder skip? No, let's do valid Appearance Watch 0x00C0
        ibeacon_ad.pop();
        ibeacon_ad.pop();
        ibeacon_ad.extend_from_slice(&[3, 0x19, 0xC0, 0x00]);
        // Manufacturer Apple (0x004C) iBeacon: 27 bytes -> len=26 (type 0xFF + 25B payload)
        let mut mfg = vec![26, 0xFF, 0x4C, 0x00, 0x02, 0x15];
        mfg.extend_from_slice(&[0xFD, 0xA5, 0x06, 0x93, 0xA4, 0xE2, 0x4F, 0xB1, 0xAF, 0xCF, 0xC6, 0xEB, 0x07, 0x64, 0x78, 0x25]);
        mfg.extend_from_slice(&1001u16.to_be_bytes()); // Major 1001
        mfg.extend_from_slice(&2u16.to_be_bytes());    // Minor 2
        mfg.push((-59i8) as u8);
        assert_eq!(mfg.len(), 27);
        ibeacon_ad.extend_from_slice(&mfg);

        let pkt = synthesize_hci_le_adv_packet(0xAABBCCDDEEFF, 0x00, 0x00, &ibeacon_ad, -62);
        let dissected = parse_bluetooth_packet(&pkt).expect("合成 HCI LE 广播必须解析成功");
        assert_eq!(dissected.vendor_name.as_deref(), Some("Apple Inc."));
        assert_eq!(dissected.company_id, Some(0x004C));
        assert!(dissected.appearance_desc.as_deref().unwrap().contains("Watch"));
        let beacon_txt = dissected.beacon_decoded.as_deref().unwrap();
        assert!(beacon_txt.contains("iBeacon") && beacon_txt.contains("Major=1001") && beacon_txt.contains("Minor=2"));
        assert!(dissected.ad_sections.len() >= 4);

        // 2. Eddystone TLM (0xFEAA Service Data) 电压温度解析验证
        let mut tlm_ad = Vec::new();
        // [len=17, type=0x16, uuid=AA FE, frame=0x20, ver=0, mv=3000(0x0BB8), temp=25.5C(25,128), adv_cnt=100, sec=10]
        tlm_ad.extend_from_slice(&[
            17, 0x16, 0xAA, 0xFE,
            0x20, 0x00,
            0x0B, 0xB8, // 3000 mV
            25, 128,    // 25.5 °C
            0x00, 0x00, 0x00, 100,
            0x00, 0x00, 0x00, 10,
        ]);
        let ed_parsed = decode_ad_tlv_bytes(&tlm_ad);
        let ed_txt = ed_parsed.beacon_decoded.unwrap();
        assert!(ed_txt.contains("Eddystone-TLM") && ed_txt.contains("3000mV") && ed_txt.contains("25.5"));

        // 3. Apple FindMy Tracker + Microsoft SwiftPair 安全告警验证
        let findmy = decode_ad_tlv_bytes(&[7, 0xFF, 0x4C, 0x00, 0x12, 0x19, 0x00, 0x01]);
        assert!(findmy.security_alerts.contains(&"APPLE_FINDMY_TRACKER".to_string()));
        let swift = decode_ad_tlv_bytes(&[7, 0xFF, 0x06, 0x00, 0x03, 0x00, 0x80, b'B']);
        assert!(swift.security_alerts.contains(&"MSFT_SWIFTPAIR_ACTIVE".to_string()));

        // 4. SMP Just Works (CID 0x0006, Code 0x01 Pairing Req, IOCap=0x03 NoInputNoOutput, AuthReq=0x01 Bonding only)
        let smp_pkt = vec![0x02, 0x40, 0x00, 0x0B, 0x00, 0x07, 0x00, 0x06, 0x00, 0x01, 0x03, 0x00, 0x01, 0x10, 0x01, 0x01];
        let smp_info = parse_bluetooth_packet(&smp_pkt).unwrap();
        assert!(smp_info.security_alerts.contains(&"SMP_JUST_WORKS_NO_MITM".to_string()));
        assert!(smp_info.security_alerts.contains(&"SMP_LEGACY_PAIRING_NO_SC".to_string()));

        // 5. Microsoft-Windows-BTH-BTHPORT ETW Event 402 (HCIRAW) & Event 263 (Write HCI) 解码验证
        let mut etw402 = vec![0x01, 0x04, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00, 0x0E, 0x04, 0x01, 0x03];
        let (tag402, h4_402) = decode_bthport_etw_event(402, &etw402).unwrap();
        assert_eq!(tag402, "BTHPORT-HCIRAW");
        assert_eq!(h4_402, vec![0x04, 0x0E, 0x04, 0x01, 0x03]);
        // 畸形超大长度截断防御
        etw402[4..8].copy_from_slice(&99999u32.to_le_bytes());
        assert!(decode_bthport_etw_event(402, &etw402).is_none());

        // Event 263: Write HCI Packet -> L2CAP ATT Write Request 还原
        let mut etw263 = vec![0u8; 17];
        etw263[1..3].copy_from_slice(&0x0040u16.to_le_bytes()); // ConnHandle
        etw263[7..9].copy_from_slice(&3u16.to_le_bytes());      // PDU_Length
        etw263[9..11].copy_from_slice(&0x0004u16.to_le_bytes()); // CID ATT
        etw263[15..17].copy_from_slice(&3u16.to_le_bytes());     // Data_Length
        etw263.extend_from_slice(&[0x12, 0x2A, 0x00]);           // ATT Write Request Handle 0x002A
        let (tag263, h4_263) = decode_bthport_etw_event(263, &etw263).unwrap();
        assert_eq!(tag263, "BTHPORT-HCI-TX");
        let etw_parsed = parse_bluetooth_packet(&h4_263).unwrap();
        assert!(etw_parsed.security_alerts.contains(&"UNENCRYPTED_GATT_WRITE".to_string()));

        // 6. GATT 读取数值解码 (Battery 0x2A19 -> 87%)
        let gatt_val_lines = "\
DEV|OK|Sensor-B1|OK\n\
SVC|0000180f-0000-1000-8000-00805f9b34fb|16\n\
CHR|00002a19-0000-1000-8000-00805f9b34fb|17|Read, Notify|Plain|57\n\
";
        let gatt_res = parse_ble_gatt_probe_lines("11:22:33:44:55:66", gatt_val_lines);
        assert_eq!(gatt_res.services[0].characteristics[0].decoded_value.as_deref(), Some("当前电量: 87%"));

        // 7. 极端截断畸形 TLV 边界防御与连续广播间隔测量
        assert!(decode_ad_tlv_bytes(&[0xFF, 0x01, 0x02]).ad_sections.is_empty());
        assert!(parse_bluetooth_packet(&[]).is_none());

        let _guard = TEST_GLOBAL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_bluetooth_telemetry();
        let mut p1 = dissected.clone();
        p1.arrival_timestamp_ms = Some(1000);
        let mut p2 = dissected;
        p2.arrival_timestamp_ms = Some(1020); // 20ms 间隔 -> 50 pps 触发异常极速泛洪告警
        record_bluetooth_packet(&p1, "12:00:00.000");
        record_bluetooth_packet(&p2, "12:00:00.020");
        let sum = get_bluetooth_telemetry_summary();
        assert_eq!(sum.recent_frames.len(), 2);
        let dev = &sum.devices[0];
        assert!(dev.adv_interval_ms.unwrap() < 25.0);
        assert!(dev.security_flags.contains(&"SUSPICIOUS_FAST_ADV_FLOOD".to_string()));
        assert!(dev.security_flags.contains(&"STATIC_MAC_TRACKABLE".to_string()));
    }

    #[test]
    fn test_bluetooth_history_persistence_baseline_and_drift_comparison() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "omni_bt_test_{}_{}",
            std::process::id(),
            chrono::Local::now().timestamp_nanos_opt().unwrap_or(1)
        ));
        let _ = fs::create_dir_all(&tmp_dir);

        // 1. 构造基线时的两台设备 A(稳定) 与 B(之后失联) 与 C(之后大幅靠近漂移)
        let mk_dev = |addr: &str, name: &str, rssi: i8, dist: f32| BluetoothDeviceAsset {
            address: addr.to_string(),
            address_type: "Random".to_string(),
            device_name: name.to_string(),
            last_rssi_dbm: rssi,
            avg_rssi_dbm: rssi as f32,
            estimated_distance_m: dist,
            tx_power_dbm: -59,
            packet_count: 10,
            service_uuids: vec!["0x180F".into()],
            vendor_info: "Nordic".into(),
            last_seen_timestamp: "10:00:01.000".into(),
            is_connectable: true,
            security_flags: Vec::new(),
            min_rssi_dbm: rssi,
            max_rssi_dbm: rssi,
            phy_desc: "LE 1M".into(),
            company_id: Some(0x0059),
            appearance_desc: None,
            beacon_summary: None,
            adv_interval_ms: Some(100.0),
            last_arrival_ms: 1000,
            adv_window_start_ms: 1000,
            adv_window_count: 1,
            packet_rate_pps: 10.0,
            ad_sections: Vec::new(),
            manufacturer_data_hex: None,
            raw_frame_hex: String::new(),
            rssi_stddev: 1.0,
            stability_score: 93.5,
            rssi_window: VecDeque::new(),
            last_persisted_ms: 0,
        };

        let base_summary = BluetoothTelemetrySummary {
            devices: vec![
                mk_dev("AA:00:00:00:00:01", "Node-Stable", -65, 1.7),
                mk_dev("BB:00:00:00:00:02", "Node-Offline", -72, 3.3),
                mk_dev("CC:00:00:00:00:03", "Node-Drifting", -80, 6.9),
            ],
            ..Default::default()
        };
        let snap = save_bluetooth_baseline_in_dir(&tmp_dir, &base_summary).unwrap();
        assert_eq!(snap.device_count, 3);

        // 2. 写入持久化历史记录并故意混入畸形 JSON 行检验防御恢复力
        append_bluetooth_history_record_to_dir(
            &tmp_dir,
            &BluetoothHistoryRecord {
                epoch_ms: 1000,
                timestamp: "2026-11-12 10:00:01.000".into(),
                address: "AA:00:00:00:00:01".into(),
                address_type: "Random".into(),
                device_name: "Node-Stable".into(),
                vendor_info: "Nordic".into(),
                rssi_dbm: -65,
                estimated_distance_m: 1.7,
                adv_interval_ms: Some(100.0),
                packet_rate_pps: 10.0,
                rssi_stddev: 1.0,
                stability_score: 93.5,
                phy_desc: "LE 1M".into(),
                security_flags: Vec::new(),
                protocol_layer: "BLE-ADV".into(),
            },
        );
        let hist_file = tmp_dir.join("bluetooth_history.jsonl");
        let mut f = OpenOptions::new().append(true).open(&hist_file).unwrap();
        writeln!(f, "{{CORRUPTED_JSON_LINE_XYZ").unwrap();
        drop(f);

        // 3. 构造实时场景：A 保持 (-66dBm), B 失联, C 移近到 -55dBm(漂移+25dB), D 未知新入侵
        let rt_summary = BluetoothTelemetrySummary {
            devices: vec![
                mk_dev("AA:00:00:00:00:01", "Node-Stable", -66, 1.9),
                mk_dev("CC:00:00:00:00:03", "Node-Drifting", -55, 0.7),
                mk_dev("DD:00:00:00:00:04", "Unknown-Rogue", -60, 1.1),
            ],
            rssi_history: vec![BluetoothRssiSample {
                timestamp: "10:00:01.500".into(),
                address: "DD:00:00:00:00:04".into(),
                rssi_dbm: -60,
                distance_m: 1.1,
            }],
            ..Default::default()
        };

        let cmp = compare_bluetooth_realtime_vs_history_in_dir(&tmp_dir, &rt_summary).unwrap();
        assert!(cmp.has_baseline);
        assert_eq!(cmp.history_records_scanned, 1);
        assert_eq!(cmp.corrupted_history_lines, 1);
        assert_eq!(cmp.new_device_count, 1);
        assert_eq!(cmp.missing_device_count, 1);
        assert_eq!(cmp.drifted_device_count, 1);
        assert_eq!(cmp.stable_device_count, 1);
        assert_eq!(cmp.drift_items[0].status, "NEW_UNKNOWN");
        assert!(!cmp.trend_buckets.is_empty());

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_btsnoop_rfc1761_roundtrip_and_boundary_defense() {
        // 1. 构造 H4 BLE ADV 与 ATT 报文往返编码与解码
        let sample_frames = vec![
            BluetoothFrameLogItem {
                id: 1,
                timestamp: "12:00:00.000".into(),
                source: "WinRT".into(),
                direction: "AIR_RX".into(),
                protocol_layer: "BLE-ADV".into(),
                address: "66:55:44:33:22:11".into(),
                rssi_dbm: Some(-65),
                length: 19,
                summary: "ADV".into(),
                raw_hex: "043E110201000011223344556605020106BF".into(),
            },
            BluetoothFrameLogItem {
                id: 2,
                timestamp: "12:00:00.050".into(),
                source: "BTHPORT".into(),
                direction: "HOST_TX".into(),
                protocol_layer: "L2CAP-ATT".into(),
                address: "Handle-0x0040".into(),
                rssi_dbm: None,
                length: 10,
                summary: "ATT MTU".into(),
                raw_hex: "02400007000300040002F700".into(),
            },
        ];

        let (encoded, cnt) = encode_frames_to_btsnoop(&sample_frames).unwrap();
        assert_eq!(cnt, 2);
        assert_eq!(&encoded[0..8], b"btsnoop\0");

        let (datalink, recs, skipped) = decode_btsnoop_file_bytes(&encoded).unwrap();
        assert_eq!(datalink, 1002);
        assert_eq!(skipped, 0);
        assert_eq!(recs.len(), 2);
        assert!(!recs[0].0); // AIR_RX -> is_tx=false
        assert!(recs[1].0);  // HOST_TX -> is_tx=true
        let p_mtu = parse_bluetooth_packet(&recs[1].2).unwrap();
        assert_eq!(p_mtu.negotiated_mtu, Some(247));

        // 2. 验证 Datalink 1001 无头封装与边界异常拦截 (OOM / 短头 / 错误魔数)
        assert!(decode_btsnoop_file_bytes(b"short").is_err());
        assert!(decode_btsnoop_file_bytes(b"NOT_BTSNOOP_FILE_123456").is_err());

        let mut malformed = vec![];
        malformed.extend_from_slice(b"btsnoop\0");
        malformed.extend_from_slice(&1u32.to_be_bytes());
        malformed.extend_from_slice(&1001u32.to_be_bytes());
        malformed.extend_from_slice(&999999u32.to_be_bytes()); // orig_len
        malformed.extend_from_slice(&999999u32.to_be_bytes()); // incl_len 超大 OOM 诱饵
        malformed.extend_from_slice(&0u32.to_be_bytes());
        malformed.extend_from_slice(&0u32.to_be_bytes());
        malformed.extend_from_slice(&0u64.to_be_bytes());
        malformed.extend_from_slice(&[0x01, 0x02]);
        let (dl, ok_recs, sk) = decode_btsnoop_file_bytes(&malformed).unwrap();
        assert_eq!(dl, 1001);
        assert!(ok_recs.is_empty());
        assert_eq!(sk, 1);
    }

    #[test]
    fn test_bluetooth_session_state_machine_handle_learning_and_rssi_stddev() {
        let _guard = TEST_GLOBAL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_bluetooth_telemetry();

        // 1. HCI LE Connection Complete (Handle = 0x0041, Peer = AA:BB:CC:11:22:33)
        let mut conn_evt = vec![0x04, 0x3E, 19, 0x01, 0x00, 0x41, 0x00, 0x00, 0x01];
        conn_evt.extend_from_slice(&[0x33, 0x22, 0x11, 0xCC, 0xBB, 0xAA]); //小端地址 -> AA:BB:CC:11:22:33
        conn_evt.extend_from_slice(&[0x18, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00]);
        let p_conn = parse_bluetooth_packet(&conn_evt).unwrap();
        assert_eq!(p_conn.conn_handle, Some(0x0041));
        assert_eq!(p_conn.address, "AA:BB:CC:11:22:33");
        record_bluetooth_packet(&p_conn, "12:10:00.000");

        // 2. ATT Exchange MTU Req (MTU = 247)
        let mtu_acl = vec![0x02, 0x41, 0x00, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x02, 0xF7, 0x00];
        let p_mtu = parse_bluetooth_packet(&mtu_acl).unwrap();
        record_bluetooth_packet(&p_mtu, "12:10:00.010");

        // 3. ATT Find Information Response (Format=1 16-bit UUID): Handle 0x001A -> UUID 0x2A19 (Battery Level)
        let find_rsp = vec![
            0x02, 0x41, 0x00, 0x0A, 0x00, 0x06, 0x00, 0x04, 0x00,
            0x05, 0x01, // Opcode FindInfoRsp, Format=1 (2B handle + 2B UUID)
            0x1A, 0x00, // Handle 0x001A
            0x19, 0x2A, // UUID 0x2A19 (Battery Level)
        ];
        let p_find = parse_bluetooth_packet(&find_rsp).unwrap();
        assert_eq!(p_find.learned_handles.len(), 1);
        assert!(p_find.learned_handles[0].1.contains("2A19"));
        record_bluetooth_packet(&p_find, "12:10:00.020");

        // 4. HCI Encryption Change (Handle 0x0041, Enabled = 1)
        let enc_evt = vec![0x04, 0x08, 0x04, 0x00, 0x41, 0x00, 0x01];
        let p_enc = parse_bluetooth_packet(&enc_evt).unwrap();
        assert_eq!(p_enc.encryption_enabled, Some(true));
        record_bluetooth_packet(&p_enc, "12:10:00.030");

        // 5. 写入一组波动 RSSI 验证标准差和稳态评分
        for (i, rssi) in [-60i8, -70, -60, -70].iter().enumerate() {
            let mut adv = parse_bluetooth_packet(&[
                0x04, 0x3E, 17, 0x02, 0x01, 0x00, 0x00,
                0x33, 0x22, 0x11, 0xCC, 0xBB, 0xAA,
                0x03, 0x02, 0x01, 0x06, (*rssi) as u8,
            ]).unwrap();
            adv.arrival_timestamp_ms = Some(2000 + (i as u64) * 100);
            record_bluetooth_packet(&adv, "12:10:01.000");
        }

        let summary = get_bluetooth_telemetry_summary();
        assert_eq!(summary.active_sessions.len(), 1);
        let sess = &summary.active_sessions[0];
        assert_eq!(sess.conn_handle, 0x0041);
        assert_eq!(sess.peer_address, "AA:BB:CC:11:22:33");
        assert_eq!(sess.negotiated_mtu, 247);
        assert!(sess.encrypted);
        assert_eq!(sess.handle_uuid_map[0].0, 0x001A);
        assert!(sess.handle_uuid_map[0].1.contains("2A19"));

        let dev = summary.devices.iter().find(|d| d.address == "AA:BB:CC:11:22:33").unwrap();
        assert!(dev.rssi_stddev >= 4.5, "stddev should reflect +-5dB swing, got {}", dev.rssi_stddev);
        assert!(dev.stability_score < 75.0);

        // 6. 验证 UUID 字符防注入守卫与 16-bit 短码展开
        assert_eq!(validate_uuid_chars("0x2A19").unwrap(), "00002a19-0000-1000-8000-00805f9b34fb");
        assert!(validate_uuid_chars("00002a19-0000-1000-8000-00805f9b34fb").is_ok());
        assert!(validate_uuid_chars("2a19; calc.exe").is_err());
    }
}
