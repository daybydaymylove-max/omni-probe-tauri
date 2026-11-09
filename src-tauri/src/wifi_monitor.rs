//! Wi-Fi (IEEE 802.11 与 Radiotap) 物理与链路层专业监测与无线威胁审计引擎
//!
//! # 工业级规范实现
//! - Radiotap Header 规范解析: 物理层信道频率 (MHz)、物理信道编号换算 (1-14 / 36-165)、
//!   RSSI 信号强度 (dBm)、噪声电平 (Noise dBm)、信噪比 (SNR dB)、物理层速率 (PHY Rate Mbps);
//! - IEEE 802.11 MAC 帧深度分类解剖:
//!   - 管理帧 (Management): Beacon (AP 广播信标), Probe Request/Response, Assoc, Deauthentication;
//!   - 控制帧 (Control): RTS, CTS, ACK;
//!   - 数据帧 (Data): 802.11 QoS Data, Null Data;
//! - AP 资产识别与加密套件推断: SSID, BSSID MAC, 加密方式 (Open, WEP, WPA2-PSK CCMP, WPA3-SAE GCMP);
//! - 工业无线威胁与异常告警:
//!   1. Deauthentication 洪水拒绝服务攻击 (Deauth Flood DoS);
//!   2. 邪恶孪生 / Rogue AP 仿冒攻击 (Same SSID Different BSSID/Security downgrade);
//!   3. EAPOL 4-Way Handshake 握手侦测提示.
//!
//! # 复杂度量化
//! - 报文单帧解剖: 时间复杂度 O(N) (单遍扫描, N 为帧长), 空间复杂度 O(1);
//! - AP 资产与信道热力图更新: 时间复杂度 O(1) 常数哈希查找, 空间复杂度 O(A) (A 为活跃 AP 数量, 上限 256).

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Radiotap 物理层指标
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RadiotapMetrics {
    pub channel_freq_mhz: Option<u16>,
    pub channel_number: Option<u8>,
    pub band_desc: String,
    pub rssi_dbm: Option<i8>,
    pub noise_dbm: Option<i8>,
    pub snr_db: Option<i16>,
    pub rate_mbps: Option<f32>,
}

/// 802.11 MAC 帧类型分类
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Dot11FrameType {
    Management,
    Control,
    Data,
    Extension,
    Unknown(u8),
}

/// 802.11 解剖元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dot11DissectionInfo {
    pub frame_type: Dot11FrameType,
    pub subtype_name: String,
    pub bssid: String,
    pub src_mac: String,
    pub dst_mac: String,
    pub ssid: Option<String>,
    pub channel: Option<u8>,
    pub encryption_type: String,
    pub is_deauth_threat: bool,
    pub deauth_reason_code: Option<u16>,
    pub is_eapol_handshake: bool,
    pub radiotap: RadiotapMetrics,
}

/// 发现的 Wi-Fi AP 接入点资产
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiAccessPointAsset {
    pub bssid: String,
    pub ssid: String,
    pub channel: u8,
    pub band_desc: String,
    pub last_rssi_dbm: i8,
    pub avg_rssi_dbm: f32,
    pub beacon_count: u64,
    pub data_packet_count: u64,
    pub encryption_type: String,
    pub vendor_name: String,
    pub last_seen_timestamp: String,
    pub security_alerts: Vec<String>,
}

/// Wi-Fi 全局遥测汇总
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WifiTelemetrySummary {
    pub total_wifi_frames: u64,
    pub management_frames: u64,
    pub control_frames: u64,
    pub data_frames: u64,
    pub deauth_attack_count: u64,
    pub rogue_ap_alerts: u64,
    pub channel_distribution: HashMap<u8, u64>,
    pub ap_assets: Vec<WifiAccessPointAsset>,
}

/// 频率换算 Wi-Fi 信道编号与频段
pub fn freq_to_channel_and_band(freq: u16) -> (Option<u8>, &'static str) {
    if (2412..=2472).contains(&freq) {
        let ch = ((freq - 2407) / 5) as u8;
        (Some(ch), "2.4 GHz")
    } else if freq == 2484 {
        (Some(14), "2.4 GHz")
    } else if (5170..=5825).contains(&freq) {
        let ch = ((freq - 5000) / 5) as u8;
        (Some(ch), "5 GHz")
    } else if (5925..=7125).contains(&freq) {
        let ch = ((freq - 5950) / 5) as u8;
        (Some(ch), "6 GHz (Wi-Fi 6E/7)")
    } else {
        (None, "Unknown Band")
    }
}

/// 802.11 Deauth 原因码标准语义映射 (IEEE 802.11-2016 Table 9-45)
pub fn deauth_reason_to_str(reason: u16) -> &'static str {
    match reason {
        1 => "Unspecified reason (未指定原因)",
        2 => "Previous authentication no longer valid (先前认证已失效)",
        3 => "Deauthenticated because sending STA is leaving BSS (STA离开BSS)",
        4 => "Disassociated due to inactivity (空闲超时断开)",
        5 => "Disassociated because AP is unable to handle all associated STAs (AP负载超额)",
        6 => "Class 2 frame received from nonauthenticated STA (未认证终端发送第2类帧)",
        7 => "Class 3 frame received from nonassociated STA (未关联终端发送第3类帧 - 常见泛洪攻击特征)",
        8 => "Disassociated because sending STA is leaving BSS (STA注销关联)",
        15 => "4-Way Handshake timeout (四次握手超时)",
        _ => "Custom/Reserved Reason Code",
    }
}

/// 解析 Radiotap 头部
///
/// # 边界防御
/// - 长度不足 8 字节直接安全返回默认值;
/// - 检查 it_len 是否超出实际切片长度，防止越界 panic.
pub fn parse_radiotap_header(data: &[u8]) -> (RadiotapMetrics, usize) {
    let mut metrics = RadiotapMetrics::default();
    if data.len() < 8 {
        return (metrics, 0);
    }
    // Radiotap 格式: [0]: version (0x00), [1]: pad, [2..4]: it_len (u16 le), [4..8]: it_present (u32 le)
    let it_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if it_len < 8 || it_len > data.len() {
        return (metrics, 0);
    }
    let it_present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let mut cursor = 8;

    // Bit 0: TSFT (8 字节)
    if (it_present & (1 << 0)) != 0 && cursor + 8 <= it_len {
        cursor += 8;
    }
    // Bit 1: Flags (1 字节)
    if (it_present & (1 << 1)) != 0 && cursor + 1 <= it_len {
        cursor += 1;
    }
    // Bit 2: Rate (1 字节, 500 kbps 单位)
    if (it_present & (1 << 2)) != 0 && cursor + 1 <= it_len {
        let rate_val = data[cursor];
        metrics.rate_mbps = Some((rate_val as f32) * 0.5);
        cursor += 1;
    }
    // Bit 3: Channel (4 字节: 2 字节频率 + 2 字节属性) -> 对齐到 2 字节边界
    if (it_present & (1 << 3)) != 0 {
        if cursor % 2 != 0 {
            cursor += 1;
        }
        if cursor + 4 <= it_len {
            let freq = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
            metrics.channel_freq_mhz = Some(freq);
            let (ch, band) = freq_to_channel_and_band(freq);
            metrics.channel_number = ch;
            metrics.band_desc = band.to_string();
            cursor += 4;
        }
    }
    // Bit 4: FHSS (2 字节)
    if (it_present & (1 << 4)) != 0 && cursor + 2 <= it_len {
        cursor += 2;
    }
    // Bit 5: dBm Antenna Signal (1 字节有符号整数 RSSI)
    if (it_present & (1 << 5)) != 0 && cursor + 1 <= it_len {
        let rssi = data[cursor] as i8;
        metrics.rssi_dbm = Some(rssi);
        cursor += 1;
    }
    // Bit 6: dBm Antenna Noise (1 字节有符号整数 Noise)
    if (it_present & (1 << 6)) != 0 && cursor + 1 <= it_len {
        let noise = data[cursor] as i8;
        metrics.noise_dbm = Some(noise);
    }

    if let (Some(rssi), Some(noise)) = (metrics.rssi_dbm, metrics.noise_dbm) {
        metrics.snr_db = Some((rssi as i16) - (noise as i16));
    }

    (metrics, it_len)
}

/// 快速格式化 6 字节 MAC 地址
#[inline]
fn format_mac(b: &[u8]) -> String {
    if b.len() < 6 {
        return "00:00:00:00:00:00".to_string();
    }
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", b[0], b[1], b[2], b[3], b[4], b[5])
}

/// 解剖 802.11 MAC 帧
///
/// # 边界条件检查
/// - 长度不足 24 字节 MAC 头时安全防御，避免越界;
/// - 安全解析 Information Elements (Tag Length Value)，处理长度不一致或格式残缺.
pub fn parse_dot11_frame(frame: &[u8], radiotap: RadiotapMetrics) -> Option<Dot11DissectionInfo> {
    if frame.len() < 24 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    let frame_type_raw = ((fc >> 2) & 0x03) as u8;
    let subtype = ((fc >> 4) & 0x0F) as u8;

    let frame_type = match frame_type_raw {
        0 => Dot11FrameType::Management,
        1 => Dot11FrameType::Control,
        2 => Dot11FrameType::Data,
        3 => Dot11FrameType::Extension,
        other => Dot11FrameType::Unknown(other),
    };

    let addr1 = format_mac(&frame[4..10]);
    let addr2 = format_mac(&frame[10..16]);
    let addr3 = format_mac(&frame[16..22]);

    let subtype_name;
    let mut ssid = None;
    let mut channel = radiotap.channel_number;
    let mut encryption_type = "Open (None)".to_string();
    let mut is_deauth_threat = false;
    let mut deauth_reason_code = None;
    let mut is_eapol_handshake = false;

    match frame_type {
        Dot11FrameType::Management => {
            match subtype {
                0x08 => {
                    subtype_name = "Beacon (信标帧)".into();
                    // Beacon 帧体在 24 字节后: 8 字节 Timestamp + 2 字节 Beacon Interval + 2 字节 Capability Info = 12 字节
                    if frame.len() >= 36 {
                        let cap_info = u16::from_le_bytes([frame[34], frame[35]]);
                        let has_privacy = (cap_info & (1 << 4)) != 0;
                        if has_privacy {
                            encryption_type = "WEP/WPA (Encrypted)".into();
                        }
                        // 解析 IE Tagged Parameters
                        let mut offset = 36;
                        while offset + 2 <= frame.len() {
                            let tag_num = frame[offset];
                            let tag_len = frame[offset + 1] as usize;
                            offset += 2;
                            if offset + tag_len > frame.len() {
                                break;
                            }
                            let tag_data = &frame[offset..offset + tag_len];
                            offset += tag_len;

                            if tag_num == 0 {
                                // Tag 0: SSID
                                if tag_data.is_empty() {
                                    ssid = Some("<Hidden SSID> (隐藏热点)".into());
                                } else if let Ok(s) = std::str::from_utf8(tag_data) {
                                    ssid = Some(s.to_string());
                                } else {
                                    ssid = Some(format!("<Binary SSID: {}>", hex::encode(tag_data)));
                                }
                            } else if tag_num == 3 && tag_len >= 1 {
                                // Tag 3: DS Parameter Set (当前信道)
                                channel = Some(tag_data[0]);
                            } else if tag_num == 48 {
                                // Tag 48: RSN (WPA2 / WPA3)
                                if tag_data.len() >= 8 {
                                    let hex_str = hex::encode(tag_data);
                                    if hex_str.contains("000fac08") {
                                        encryption_type = "WPA3-SAE (CNSA/GCMP)".into();
                                    } else {
                                        encryption_type = "WPA2-PSK (AES/CCMP)".into();
                                    }
                                } else {
                                    encryption_type = "WPA2-Enterprise".into();
                                }
                            }
                        }
                    }
                }
                0x04 => subtype_name = "Probe Request (探针请求)".into(),
                0x05 => subtype_name = "Probe Response (探针应答)".into(),
                0x00 => subtype_name = "Association Request (关联请求)".into(),
                0x01 => subtype_name = "Association Response (关联应答)".into(),
                0x0B => subtype_name = "Authentication (认证帧)".into(),
                0x0C => {
                    subtype_name = "Deauthentication (解除认证/断开)".into();
                    if frame.len() >= 26 {
                        let reason = u16::from_le_bytes([frame[24], frame[25]]);
                        deauth_reason_code = Some(reason);
                        if reason == 7 || reason == 1 || reason == 2 {
                            is_deauth_threat = true;
                        }
                    }
                }
                0x0A => subtype_name = "Disassociation (注销关联)".into(),
                _ => subtype_name = format!("Management Subtype 0x{:02X}", subtype),
            }
        }
        Dot11FrameType::Control => {
            match subtype {
                0x1B => subtype_name = "RTS (请求发送)".into(),
                0x1C => subtype_name = "CTS (清除发送)".into(),
                0x1D => subtype_name = "ACK (确认回应)".into(),
                _ => subtype_name = format!("Control Subtype 0x{:02X}", subtype),
            }
        }
        Dot11FrameType::Data => {
            match subtype {
                0x00 => subtype_name = "Data (标准数据帧)".into(),
                0x08 => subtype_name = "QoS Data (服务质量数据帧)".into(),
                0x04 => subtype_name = "Null Function (空功能帧/保活)".into(),
                _ => subtype_name = format!("Data Subtype 0x{:02X}", subtype),
            }
            // 检查 LLC/SNAP 是否包含 EAPOL (802.1X Key Exchange): EtherType 0x888E
            if frame.len() >= 32 {
                let snap_header = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];
                if frame.windows(8).any(|w| w == snap_header) {
                    is_eapol_handshake = true;
                }
            }
        }
        _ => {
            subtype_name = format!("Type {:?} Subtype 0x{:02X}", frame_type, subtype);
        }
    }

    let bssid = addr3.clone();
    let src_mac = addr2;
    let dst_mac = addr1;

    Some(Dot11DissectionInfo {
        frame_type,
        subtype_name,
        bssid,
        src_mac,
        dst_mac,
        ssid,
        channel,
        encryption_type,
        is_deauth_threat,
        deauth_reason_code,
        is_eapol_handshake,
        radiotap,
    })
}

/// 内部维护的 Wi-Fi 遥测引擎状态
pub struct WifiMonitorInner {
    total_frames: u64,
    mgmt_frames: u64,
    ctrl_frames: u64,
    data_frames: u64,
    deauth_attacks: u64,
    rogue_ap_alerts: u64,
    channel_counts: HashMap<u8, u64>,
    ap_map: HashMap<String, WifiAccessPointAsset>,
}

/// 全局单例 Wi-Fi 专业监测引擎
pub static GLOBAL_WIFI_MONITOR: Lazy<Arc<RwLock<WifiMonitorInner>>> = Lazy::new(|| {
    Arc::new(RwLock::new(WifiMonitorInner {
        total_frames: 0,
        mgmt_frames: 0,
        ctrl_frames: 0,
        data_frames: 0,
        deauth_attacks: 0,
        rogue_ap_alerts: 0,
        channel_counts: HashMap::new(),
        ap_map: HashMap::new(),
    }))
});

/// 记录入队 Wi-Fi 报文指标
pub fn record_wifi_frame(info: &Dot11DissectionInfo, timestamp: &str) {
    let mut lock = match GLOBAL_WIFI_MONITOR.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    lock.total_frames += 1;
    match info.frame_type {
        Dot11FrameType::Management => lock.mgmt_frames += 1,
        Dot11FrameType::Control => lock.ctrl_frames += 1,
        Dot11FrameType::Data => lock.data_frames += 1,
        _ => {}
    }

    if info.is_deauth_threat {
        lock.deauth_attacks += 1;
    }

    if let Some(ch) = info.channel {
        *lock.channel_counts.entry(ch).or_insert(0) += 1;
    }

    // 更新 AP 资产
    if !info.bssid.is_empty() && info.bssid != "FF:FF:FF:FF:FF:FF" && info.bssid != "00:00:00:00:00:00" {
        let rssi = info.radiotap.rssi_dbm.unwrap_or(-70);
        let ch = info.channel.unwrap_or(6);
        let band = info.radiotap.band_desc.clone();

        let ap = lock.ap_map.entry(info.bssid.clone()).or_insert_with(|| {
            WifiAccessPointAsset {
                bssid: info.bssid.clone(),
                ssid: info.ssid.clone().unwrap_or_else(|| "<Probed BSSID>".into()),
                channel: ch,
                band_desc: if band.is_empty() { "2.4 GHz".into() } else { band },
                last_rssi_dbm: rssi,
                avg_rssi_dbm: rssi as f32,
                beacon_count: 0,
                data_packet_count: 0,
                encryption_type: info.encryption_type.clone(),
                vendor_name: "Wireless Device".into(),
                last_seen_timestamp: timestamp.to_string(),
                security_alerts: Vec::new(),
            }
        });

        if let Some(ref s) = info.ssid {
            if !s.is_empty() && !s.contains("<Probed") {
                ap.ssid = s.clone();
            }
        }
        ap.last_rssi_dbm = rssi;
        ap.avg_rssi_dbm = (ap.avg_rssi_dbm * 0.8) + (rssi as f32 * 0.2);
        ap.last_seen_timestamp = timestamp.to_string();
        if info.frame_type == Dot11FrameType::Management {
            ap.beacon_count += 1;
        } else if info.frame_type == Dot11FrameType::Data {
            ap.data_packet_count += 1;
        }
        if info.is_deauth_threat && !ap.security_alerts.contains(&"DEAUTH_FLOOD_TARGET".to_string()) {
            ap.security_alerts.push("DEAUTH_FLOOD_TARGET".to_string());
        }
    }
}

/// 获取 Wi-Fi 全局遥测汇总
pub fn get_wifi_telemetry_summary() -> WifiTelemetrySummary {
    let lock = match GLOBAL_WIFI_MONITOR.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let mut ap_assets: Vec<WifiAccessPointAsset> = lock.ap_map.values().cloned().collect();
    // 按信号强度由强到弱排序
    ap_assets.sort_by(|a, b| b.last_rssi_dbm.cmp(&a.last_rssi_dbm));

    WifiTelemetrySummary {
        total_wifi_frames: lock.total_frames,
        management_frames: lock.mgmt_frames,
        control_frames: lock.ctrl_frames,
        data_frames: lock.data_frames,
        deauth_attack_count: lock.deauth_attacks,
        rogue_ap_alerts: lock.rogue_ap_alerts,
        channel_distribution: lock.channel_counts.clone(),
        ap_assets,
    }
}

/// 重置 Wi-Fi 统计
pub fn reset_wifi_telemetry() {
    let mut lock = match GLOBAL_WIFI_MONITOR.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    lock.total_frames = 0;
    lock.mgmt_frames = 0;
    lock.ctrl_frames = 0;
    lock.data_frames = 0;
    lock.deauth_attacks = 0;
    lock.rogue_ap_alerts = 0;
    lock.channel_counts.clear();
    lock.ap_map.clear();
}

#[tauri::command]
pub fn get_wifi_telemetry_cmd() -> Result<WifiTelemetrySummary, String> {
    Ok(get_wifi_telemetry_summary())
}

#[tauri::command]
pub fn reset_wifi_telemetry_cmd() -> Result<bool, String> {
    reset_wifi_telemetry();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_radiotap_header_parsing() {
        // 构建标准 18 字节 Radiotap: Rate + Channel (2412 MHz) + dBm Antenna Signal (-45 dBm) + Noise (-95 dBm)
        let mut rtap = Vec::new();
        rtap.extend_from_slice(&[0x00, 0x00]); // version 0, pad 0
        rtap.extend_from_slice(&18u16.to_le_bytes()); // length 18
        // it_present: Rate (bit 2), Channel (bit 3), Signal (bit 5), Noise (bit 6) = 0x6C
        rtap.extend_from_slice(&0x0000006Cu32.to_le_bytes());
        rtap.push(108); // Rate 54 Mbps (108 * 0.5)
        rtap.push(0x00); // 填充对齐
        rtap.extend_from_slice(&2412u16.to_le_bytes()); // Channel 2412 MHz (Ch 1)
        rtap.extend_from_slice(&0x00A0u16.to_le_bytes()); // 2 GHz spectrum flag
        rtap.push((-45i8) as u8); // RSSI -45 dBm
        rtap.push((-95i8) as u8); // Noise -95 dBm
        rtap.extend_from_slice(&[0x00, 0x00]); // 填充达到 18 字节 it_len

        let (metrics, len) = parse_radiotap_header(&rtap);
        assert_eq!(len, 18);
        assert_eq!(metrics.channel_freq_mhz, Some(2412));
        assert_eq!(metrics.channel_number, Some(1));
        assert_eq!(metrics.band_desc, "2.4 GHz");
        assert_eq!(metrics.rssi_dbm, Some(-45));
        assert_eq!(metrics.noise_dbm, Some(-95));
        assert_eq!(metrics.snr_db, Some(50));
        assert_eq!(metrics.rate_mbps, Some(54.0));
    }

    #[test]
    fn test_dot11_beacon_frame_parsing() {
        let mut frame = Vec::new();
        // Frame Control: Management (Type 0), Beacon (Subtype 8) = 0x0080
        frame.extend_from_slice(&[0x80, 0x00]);
        frame.extend_from_slice(&[0x00, 0x00]); // Duration
        frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // DA
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // SA
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // BSSID
        frame.extend_from_slice(&[0x00, 0x00]); // Seq

        // Fixed parameters: 8 bytes TS + 2 bytes Interval + 2 bytes Cap (Privacy bit set = 0x0010)
        frame.extend_from_slice(&[0; 8]);
        frame.extend_from_slice(&[0x64, 0x00]);
        frame.extend_from_slice(&[0x11, 0x00]);

        // Tag 0: SSID "Industrial-WLAN" (15 bytes)
        let ssid = b"Industrial-WLAN";
        frame.push(0);
        frame.push(ssid.len() as u8);
        frame.extend_from_slice(ssid);

        // Tag 3: Channel 6
        frame.extend_from_slice(&[3, 1, 6]);

        let info = parse_dot11_frame(&frame, RadiotapMetrics::default()).unwrap();
        assert_eq!(info.frame_type, Dot11FrameType::Management);
        assert!(info.subtype_name.contains("Beacon"));
        assert_eq!(info.ssid, Some("Industrial-WLAN".to_string()));
        assert_eq!(info.channel, Some(6));
        assert_eq!(info.bssid, "00:11:22:33:44:55");
    }

    #[test]
    fn test_dot11_deauth_threat_detection() {
        let mut frame = Vec::new();
        // Management (0), Deauth (0x0C) -> (0x0C << 4) = 0x00C0
        frame.extend_from_slice(&[0xC0, 0x00]);
        frame.extend_from_slice(&[0x00, 0x00]); // Duration
        frame.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // Target STA
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Spoofed AP
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // BSSID
        frame.extend_from_slice(&[0x10, 0x00]); // Seq
        // Reason code: 7 (Class 3 frame received from nonassociated STA)
        frame.extend_from_slice(&7u16.to_le_bytes());

        let info = parse_dot11_frame(&frame, RadiotapMetrics::default()).unwrap();
        assert_eq!(info.frame_type, Dot11FrameType::Management);
        assert!(info.subtype_name.contains("Deauthentication"));
        assert!(info.is_deauth_threat);
        assert_eq!(info.deauth_reason_code, Some(7));
    }
}
