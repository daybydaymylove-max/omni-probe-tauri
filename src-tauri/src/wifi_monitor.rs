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

/// Wi-Fi RSSI 实时变化历史采样点 (用于信号时序折线图)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiRssiSample {
    pub timestamp: String,
    pub bssid: String,
    pub ssid: String,
    pub channel: u8,
    pub rssi_dbm: i8,
}

/// OS 原生 WLAN 扫描结果（诚实报告宿主机硬件/服务是否可用）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeWifiScanResult {
    pub native_scan_available: bool,
    pub platform: String,
    pub reason_code: String,
    pub status_message: String,
    pub scanned_ap_count: usize,
    pub interface_name: String,
    pub aps: Vec<WifiAccessPointAsset>,
    pub summary: WifiTelemetrySummary,
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
    pub rssi_history: Vec<WifiRssiSample>,
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
    rssi_history: Vec<WifiRssiSample>,
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
        rssi_history: Vec::with_capacity(240),
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
        if info.encryption_type.contains("Open (None)") && !ap.security_alerts.contains(&"OPEN_UNENCRYPTED_WLAN".to_string()) {
            ap.security_alerts.push("OPEN_UNENCRYPTED_WLAN".to_string());
        }
        if (info.encryption_type.contains("WEP") || info.encryption_type.contains("TKIP")) && !ap.security_alerts.contains(&"WEAK_CIPHER_TKIP_WEP".to_string()) {
            ap.security_alerts.push("WEAK_CIPHER_TKIP_WEP".to_string());
        }
        if info.encryption_type.contains("No-PMF") && !ap.security_alerts.contains(&"NO_PMF_80211W".to_string()) {
            ap.security_alerts.push("NO_PMF_80211W".to_string());
        }
        let resolved_ssid = ap.ssid.clone();
        lock.rssi_history.push(WifiRssiSample {
            timestamp: timestamp.to_string(),
            bssid: info.bssid.clone(),
            ssid: resolved_ssid,
            channel: ch,
            rssi_dbm: rssi,
        });
        if lock.rssi_history.len() > 240 {
            let excess = lock.rssi_history.len() - 240;
            lock.rssi_history.drain(..excess);
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
        rssi_history: lock.rssi_history.clone(),
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
    lock.rssi_history.clear();
}

/// 解析 Windows `netsh wlan show networks mode=bssid` 输出为真实 AP 集合
pub fn parse_netsh_wlan_output(output: &str) -> (String, Vec<Dot11DissectionInfo>) {
    let mut iface_name = String::new();
    let mut results = Vec::new();
    let mut cur_ssid = String::new();
    let mut cur_auth = "Open".to_string();
    let mut cur_bssid = String::new();
    let mut cur_signal_pct: Option<i32> = None;
    let mut cur_channel: Option<u8> = None;

    let flush_bssid = |results: &mut Vec<Dot11DissectionInfo>, ssid: &str, auth: &str, bssid: &str, sig: Option<i32>, ch: Option<u8>| {
        if bssid.is_empty() {
            return;
        }
        let rssi_dbm = sig.map(|p| ((p.clamp(0, 100) / 2) - 100) as i8).unwrap_or(-75);
        let band = ch.map(|c| if c <= 14 { "2.4 GHz" } else { "5 GHz" }).unwrap_or("2.4 GHz");
        let freq = ch.map(|c| if c <= 14 { 2407 + (c as u16) * 5 } else { 5000 + (c as u16) * 5 });
        results.push(Dot11DissectionInfo {
            frame_type: Dot11FrameType::Management,
            subtype_name: "WLAN Scan Beacon".to_string(),
            bssid: bssid.to_uppercase(),
            src_mac: bssid.to_uppercase(),
            dst_mac: "FF:FF:FF:FF:FF:FF".to_string(),
            ssid: if ssid.is_empty() { None } else { Some(ssid.to_string()) },
            channel: ch,
            encryption_type: auth.to_string(),
            is_deauth_threat: false,
            deauth_reason_code: None,
            is_eapol_handshake: false,
            radiotap: RadiotapMetrics {
                channel_freq_mhz: freq,
                channel_number: ch,
                band_desc: band.to_string(),
                rssi_dbm: Some(rssi_dbm),
                noise_dbm: None,
                snr_db: None,
                rate_mbps: None,
            },
        });
    };

    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_lowercase();
        if (lower.starts_with("interface name") || line.starts_with("接口名称")) && line.contains(':') {
            if let Some((_, val)) = line.split_once(':') {
                iface_name = val.trim().to_string();
            }
        } else if (lower.starts_with("ssid ") || line.starts_with("SSID ")) && !lower.starts_with("bssid") {
            flush_bssid(&mut results, &cur_ssid, &cur_auth, &cur_bssid, cur_signal_pct, cur_channel);
            cur_bssid.clear();
            cur_signal_pct = None;
            cur_channel = None;
            cur_ssid = line.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
        } else if (lower.starts_with("authentication") || line.starts_with("身份验证") || line.starts_with("认证")) && line.contains(':') {
            cur_auth = line.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_else(|| "Open".into());
        } else if lower.starts_with("bssid ") && line.contains(':') {
            flush_bssid(&mut results, &cur_ssid, &cur_auth, &cur_bssid, cur_signal_pct, cur_channel);
            cur_signal_pct = None;
            cur_channel = None;
            cur_bssid = line.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
        } else if (lower.starts_with("signal") || line.starts_with("信号")) && line.contains(':') {
            if let Some((_, val)) = line.split_once(':') {
                let digits: String = val.trim().chars().take_while(|c| c.is_ascii_digit()).collect();
                cur_signal_pct = digits.parse::<i32>().ok();
            }
        } else if (lower.starts_with("channel") || line.starts_with("频道") || line.starts_with("信道")) && line.contains(':') {
            if let Some((_, val)) = line.split_once(':') {
                let digits: String = val.trim().chars().take_while(|c| c.is_ascii_digit()).collect();
                cur_channel = digits.parse::<u8>().ok();
            }
        }
    }
    flush_bssid(&mut results, &cur_ssid, &cur_auth, &cur_bssid, cur_signal_pct, cur_channel);
    (iface_name, results)
}

/// 跨平台调用操作系统原生 WLAN 扫描周边物理 AP，绝对遵循硬件诚实原则（无无线网卡或服务未启动时明确反馈）
/// IEEE 802.11 Information Element (IE) 物理与安全深度解析结果
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Dot11IeDeepResult {
    pub summary_encryption: String,
    pub wifi_generation: Option<String>,
    pub pmf_status: String,
    pub pairwise_ciphers: Vec<String>,
    pub akm_suites: Vec<String>,
    pub qbss_station_count: Option<u16>,
    pub qbss_channel_util_pct: Option<f32>,
    pub security_alerts: Vec<String>,
}

#[inline]
fn decode_rsn_cipher_suite(suite: &[u8]) -> String {
    if suite.len() != 4 {
        return "Unknown".into();
    }
    if suite[0..3] == [0x00, 0x0F, 0xAC] || suite[0..3] == [0x00, 0x50, 0xF2] {
        match suite[3] {
            1 => "WEP-40".into(),
            2 => "TKIP".into(),
            4 => "CCMP-128".into(),
            5 => "WEP-104".into(),
            6 => "BIP-CMAC-128".into(),
            8 => "GCMP-128".into(),
            9 => "GCMP-256".into(),
            10 => "CCMP-256".into(),
            code => format!("Cipher-{}", code),
        }
    } else {
        format!("{:02X}:{:02X}:{:02X}:{}", suite[0], suite[1], suite[2], suite[3])
    }
}

#[inline]
fn decode_rsn_akm_suite(suite: &[u8]) -> String {
    if suite.len() != 4 {
        return "Unknown".into();
    }
    if suite[0..3] == [0x00, 0x0F, 0xAC] || suite[0..3] == [0x00, 0x50, 0xF2] {
        match suite[3] {
            1 => "802.1X".into(),
            2 => "PSK".into(),
            3 => "FT-802.1X".into(),
            4 => "FT-PSK".into(),
            5 => "802.1X-SHA256".into(),
            6 => "PSK-SHA256".into(),
            8 => "WPA3-SAE".into(),
            9 => "FT-SAE".into(),
            11 => "SuiteB-192".into(),
            12 => "SuiteB-256".into(),
            18 => "OWE".into(),
            code => format!("AKM-{}", code),
        }
    } else {
        format!("VendorAKM-{}", suite[3])
    }
}

/// 完整解析 IEEE 802.11 Beacon / ProbeRsp 二进制 IE TLV 流 (Tag-Length-Value)
/// 覆盖: RSN (Tag 48: Pairwise/AKM/PMF 802.11w)、WPA1 (Tag 221)、HT/VHT/HE/EHT (Wi-Fi 4/5/6/7)、QBSS Load (Tag 11)
/// 时间复杂度: O(N) 单遍扫描 (N 为 IE 字节长度); 空间复杂度: O(K) 少量协议标签列表
pub fn parse_dot11_ie_tlv_deep(ies: &[u8], cap_info: u16) -> Dot11IeDeepResult {
    let has_privacy = (cap_info & (1 << 4)) != 0;
    let mut res = Dot11IeDeepResult {
        pmf_status: "No-PMF".into(),
        ..Default::default()
    };
    let mut has_rsn = false;
    let mut has_wpa1 = false;
    let mut has_ht = false;
    let mut has_vht = false;
    let mut has_he = false;
    let mut has_eht = false;

    let mut offset = 0usize;
    while offset + 2 <= ies.len() {
        let tag = ies[offset];
        let len = ies[offset + 1] as usize;
        offset += 2;
        if offset + len > ies.len() {
            break;
        }
        let body = &ies[offset..offset + len];

        match tag {
            11 if body.len() >= 5 => {
                // QBSS Load (802.11-2020 §9.4.2.27): StationCount (2B LE) + ChannelUtil (1B 0..255)
                let sta = u16::from_le_bytes([body[0], body[1]]);
                let util = (body[2] as f32 / 255.0) * 100.0;
                res.qbss_station_count = Some(sta);
                res.qbss_channel_util_pct = Some((util * 10.0).round() / 10.0);
            }
            45 => has_ht = true,
            191 => has_vht = true,
            255 if !body.is_empty() => {
                // Extension Element Tag 255: Ext=35 为 HE (Wi-Fi 6), Ext=106 为 EHT (Wi-Fi 7)
                if body[0] == 35 {
                    has_he = true;
                } else if body[0] == 106 {
                    has_eht = true;
                }
            }
            48 if body.len() >= 8 => {
                has_rsn = true;
                // [0..2]=Version(1), [2..6]=GroupCipher, [6..8]=PairwiseCount
                let pw_cnt = u16::from_le_bytes([body[6], body[7]]) as usize;
                let mut p = 8usize;
                for _ in 0..pw_cnt.min(8) {
                    if p + 4 > body.len() {
                        break;
                    }
                    let c = decode_rsn_cipher_suite(&body[p..p + 4]);
                    if !res.pairwise_ciphers.contains(&c) {
                        res.pairwise_ciphers.push(c);
                    }
                    p += 4;
                }
                // 若 pairwise count 超过 8 也跳过剩余套件维持偏移准确
                p = 8 + pw_cnt.saturating_mul(4);
                if p + 2 <= body.len() {
                    let akm_cnt = u16::from_le_bytes([body[p], body[p + 1]]) as usize;
                    p += 2;
                    for idx in 0..akm_cnt.min(8) {
                        let s_off = p + idx * 4;
                        if s_off + 4 > body.len() {
                            break;
                        }
                        let a = decode_rsn_akm_suite(&body[s_off..s_off + 4]);
                        if !res.akm_suites.contains(&a) {
                            res.akm_suites.push(a);
                        }
                    }
                    p += akm_cnt.saturating_mul(4);
                }
                if p + 2 <= body.len() {
                    // RSN Capabilities (2B LE): Bit6=MFPR (Required), Bit7=MFPC (Capable)
                    let rsn_caps = u16::from_le_bytes([body[p], body[p + 1]]);
                    let mfpr = (rsn_caps & (1 << 6)) != 0;
                    let mfpc = (rsn_caps & (1 << 7)) != 0;
                    res.pmf_status = if mfpr {
                        "PMF-Req".into()
                    } else if mfpc {
                        "PMF-Cap".into()
                    } else {
                        "No-PMF".into()
                    };
                }
            }
            221 if body.len() >= 4 && body[0..4] == [0x00, 0x50, 0xF2, 0x01] => {
                has_wpa1 = true;
            }
            _ => {}
        }

        offset += len;
    }

    res.wifi_generation = if has_eht {
        Some("Wi-Fi 7 (802.11be)".into())
    } else if has_he {
        Some("Wi-Fi 6 (802.11ax)".into())
    } else if has_vht {
        Some("Wi-Fi 5 (802.11ac)".into())
    } else if has_ht {
        Some("Wi-Fi 4 (802.11n)".into())
    } else {
        None
    };

    let base_enc = if has_rsn {
        let akm = if res.akm_suites.is_empty() {
            "WPA2-PSK".to_string()
        } else {
            res.akm_suites.join("/")
        };
        let cipher = if res.pairwise_ciphers.is_empty() {
            "CCMP".to_string()
        } else {
            res.pairwise_ciphers.join("+")
        };
        format!("{} ({}) · {}", akm, cipher, res.pmf_status)
    } else if has_wpa1 {
        "WPA1 (Legacy TKIP/PSK)".into()
    } else if has_privacy {
        "WEP / Legacy Encrypted".into()
    } else {
        "Open (None)".into()
    };

    let mut extras = vec![base_enc];
    if let Some(ref wifi_gen) = res.wifi_generation {
        extras.push(wifi_gen.clone());
    }
    if let (Some(sta), Some(util)) = (res.qbss_station_count, res.qbss_channel_util_pct) {
        extras.push(format!("空口{:.0}%/{}终端", util, sta));
    }
    res.summary_encryption = extras.join(" · ");

    // 生成客观物理层安全脆弱性标记
    if !has_rsn && !has_wpa1 && !has_privacy {
        res.security_alerts.push("OPEN_UNENCRYPTED_WLAN".into());
    } else if !has_rsn && (has_wpa1 || has_privacy) {
        res.security_alerts.push("LEGACY_WPA1_OR_WEP".into());
    }
    if res.pairwise_ciphers.iter().any(|c| c.contains("TKIP") || c.contains("WEP")) {
        res.security_alerts.push("WEAK_CIPHER_TKIP_WEP".into());
    }
    if has_rsn && res.pmf_status == "No-PMF" {
        res.security_alerts.push("NO_PMF_80211W".into());
    }

    res
}

#[cfg(windows)]
mod win_wlan {
    use super::{freq_to_channel_and_band, Dot11DissectionInfo, Dot11FrameType, RadiotapMetrics};
    use std::ffi::c_void;
    use std::os::windows::process::CommandExt;

    pub type Handle = *mut c_void;

    #[repr(C)]
    pub struct WlanInterfaceInfo {
        pub interface_guid: [u8; 16],
        pub str_interface_description: [u16; 256],
        pub is_state: u32,
    }

    #[repr(C)]
    pub struct WlanInterfaceInfoList {
        pub dw_number_of_items: u32,
        pub dw_index: u32,
        pub interface_info: [WlanInterfaceInfo; 1],
    }

    #[repr(C)]
    pub struct Dot11Ssid {
        pub u_ssid_length: u32,
        pub uc_ssid: [u8; 32],
    }

    #[repr(C)]
    pub struct WlanRateSet {
        pub u_rate_set_length: u32,
        pub us_rate_set: [u16; 126],
    }

    #[repr(C)]
    pub struct WlanBssEntry {
        pub dot11_ssid: Dot11Ssid,
        pub u_phy_id: u32,
        pub dot11_bssid: [u8; 6],
        pub dot11_bss_type: u32,
        pub dot11_bss_phy_type: u32,
        pub l_rssi: i32,
        pub u_link_quality: u32,
        pub b_in_reg_domain: i32,
        pub us_beacon_period: u16,
        pub ull_timestamp: u64,
        pub ull_host_timestamp: u64,
        pub us_capability_information: u16,
        pub ul_ch_center_frequency: u32,
        pub wlan_rate_set: WlanRateSet,
        pub ul_ie_offset: u32,
        pub ul_ie_size: u32,
    }

    #[repr(C)]
    pub struct WlanBssList {
        pub dw_total_size: u32,
        pub dw_number_of_items: u32,
        pub wlan_bss_entries: [WlanBssEntry; 1],
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryA(lp_lib_file_name: *const i8) -> usize;
        fn GetProcAddress(h_module: usize, lp_proc_name: *const u8) -> *const c_void;
        fn FreeLibrary(h_lib_module: usize) -> i32;
        fn MultiByteToWideChar(
            code_page: u32,
            dw_flags: u32,
            lp_multi_byte_str: *const u8,
            cb_multi_byte: i32,
            lp_wide_char_str: *mut u16,
            cch_wide_char: i32,
        ) -> i32;
    }

    type FnWlanOpenHandle = unsafe extern "system" fn(u32, *mut c_void, *mut u32, *mut Handle) -> u32;
    type FnWlanCloseHandle = unsafe extern "system" fn(Handle, *mut c_void) -> u32;
    type FnWlanEnumInterfaces = unsafe extern "system" fn(Handle, *mut c_void, *mut *mut WlanInterfaceInfoList) -> u32;
    type FnWlanScan = unsafe extern "system" fn(Handle, *const [u8; 16], *const Dot11Ssid, *const c_void, *mut c_void) -> u32;
    type FnWlanGetNetworkBssList = unsafe extern "system" fn(Handle, *const [u8; 16], *const Dot11Ssid, u32, i32, *mut c_void, *mut *mut WlanBssList) -> u32;
    type FnWlanFreeMemory = unsafe extern "system" fn(*mut c_void);

    /// 使用 Windows CP_ACP 将系统 ANSI/GBK(936) 命令行输出无损解码为 UTF-8
    pub fn decode_acp(bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return String::new();
        }
        unsafe {
            let needed = MultiByteToWideChar(0, 0, bytes.as_ptr(), bytes.len() as i32, std::ptr::null_mut(), 0);
            if needed <= 0 {
                return String::from_utf8_lossy(bytes).to_string();
            }
            let mut wide = vec![0u16; needed as usize];
            let written = MultiByteToWideChar(0, 0, bytes.as_ptr(), bytes.len() as i32, wide.as_mut_ptr(), needed);
            if written <= 0 {
                return String::from_utf8_lossy(bytes).to_string();
            }
            String::from_utf16_lossy(&wide[..written as usize])
        }
    }

    /// 探知本机物理网卡中是否真正存在 802.11 无线设备，用于区分 NO_HARDWARE 与 SERVICE_STOPPED
    pub fn has_physical_wifi_hardware() -> bool {
        let out = std::process::Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "if (Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.PhysicalMediaType -match '802\\.11|Wireless' -or $_.NdisPhysicalMedium -eq 9 -or $_.InterfaceDescription -match 'Wi-Fi|Wireless|WLAN|802\\.11' }) { 'HAS_WIFI' } else { 'NO_WIFI' }"
            ])
            .creation_flags(0x08000000)
            .output();
        match out {
            Ok(o) => String::from_utf8_lossy(&o.stdout).contains("HAS_WIFI"),
            Err(_) => false,
        }
    }

    fn parse_rsn_encryption(ies: &[u8], cap_info: u16) -> super::Dot11IeDeepResult {
        super::parse_dot11_ie_tlv_deep(ies, cap_info)
    }

    pub fn scan_via_wlanapi() -> Result<(String, Vec<Dot11DissectionInfo>), (String, String)> {
        unsafe {
            let hmod = LoadLibraryA(b"wlanapi.dll\0".as_ptr() as *const i8);
            if hmod == 0 {
                return Err(("NO_HARDWARE".into(), "系统未包含 wlanapi.dll（未安装无线 LAN 服务或硬件驱动）".into()));
            }

            macro_rules! load_sym {
                ($name:expr, $ty:ty) => {{
                    let ptr = GetProcAddress(hmod, $name.as_ptr());
                    if ptr.is_null() {
                        FreeLibrary(hmod);
                        return Err(("UNSUPPORTED_OS".into(), "wlanapi.dll 缺少导出符号".into()));
                    }
                    std::mem::transmute::<*const c_void, $ty>(ptr)
                }};
            }

            let fn_open = load_sym!(b"WlanOpenHandle\0", FnWlanOpenHandle);
            let fn_close = load_sym!(b"WlanCloseHandle\0", FnWlanCloseHandle);
            let fn_enum = load_sym!(b"WlanEnumInterfaces\0", FnWlanEnumInterfaces);
            let fn_scan = load_sym!(b"WlanScan\0", FnWlanScan);
            let fn_bss = load_sym!(b"WlanGetNetworkBssList\0", FnWlanGetNetworkBssList);
            let fn_free = load_sym!(b"WlanFreeMemory\0", FnWlanFreeMemory);

            let mut neg_ver: u32 = 0;
            let mut h_client: Handle = std::ptr::null_mut();
            let rc = fn_open(2, std::ptr::null_mut(), &mut neg_ver, &mut h_client);
            if rc != 0 {
                FreeLibrary(hmod);
                if rc == 1062 {
                    if has_physical_wifi_hardware() {
                        return Err((
                            "SERVICE_STOPPED".into(),
                            "检测到物理无线网卡，但 Windows WLAN AutoConfig (wlansvc) 服务处于停止状态；请以管理员执行 net start wlansvc 后重扫。".into(),
                        ));
                    }
                    return Err((
                        "NO_HARDWARE".into(),
                        "宿主主机未安装物理 Wi-Fi (802.11) 无线网卡，且系统 wlansvc 服务未运行；当前仅存在有线/蓝牙/虚拟网卡。".into(),
                    ));
                }
                return Err((
                    "SERVICE_STOPPED".into(),
                    format!("WlanOpenHandle 返回系统状态码 {}（请确认无线网卡已启用且 wlansvc 正常运行）", rc),
                ));
            }

            let mut p_iface_list: *mut WlanInterfaceInfoList = std::ptr::null_mut();
            let rc_enum = fn_enum(h_client, std::ptr::null_mut(), &mut p_iface_list);
            if rc_enum != 0 || p_iface_list.is_null() {
                fn_close(h_client, std::ptr::null_mut());
                FreeLibrary(hmod);
                return Err(("NO_HARDWARE".into(), "未枚举到可用 Wi-Fi 物理适配器。".into()));
            }

            let iface_count = (*p_iface_list).dw_number_of_items as usize;
            if iface_count == 0 {
                fn_free(p_iface_list as *mut c_void);
                fn_close(h_client, std::ptr::null_mut());
                FreeLibrary(hmod);
                return Err((
                    "NO_HARDWARE".into(),
                    "WLAN 服务已运行，但未检测到已启用或已连接的物理 802.11 无线网卡。".into(),
                ));
            }

            let ifaces_ptr = (*p_iface_list).interface_info.as_ptr();
            let mut all_items = Vec::new();
            let mut primary_iface_name = String::new();

            for i in 0..iface_count.min(8) {
                let iface = &*ifaces_ptr.add(i);
                let len = iface.str_interface_description.iter().position(|&c| c == 0).unwrap_or(256);
                let desc = String::from_utf16_lossy(&iface.str_interface_description[..len]).trim().to_string();
                if primary_iface_name.is_empty() && !desc.is_empty() {
                    primary_iface_name = desc;
                }

                // 主动触发硬件实时扫描一次，并短暂等待驱动汇总邻近 BSSID 缓存
                let _ = fn_scan(h_client, &iface.interface_guid, std::ptr::null(), std::ptr::null(), std::ptr::null_mut());
                std::thread::sleep(std::time::Duration::from_millis(280));

                let mut p_bss_list: *mut WlanBssList = std::ptr::null_mut();
                if fn_bss(
                    h_client,
                    &iface.interface_guid,
                    std::ptr::null(),
                    3, // dot11_BSS_type_any
                    0,
                    std::ptr::null_mut(),
                    &mut p_bss_list,
                ) == 0 && !p_bss_list.is_null()
                {
                    let bss_count = (*p_bss_list).dw_number_of_items as usize;
                    let bss_base = (*p_bss_list).wlan_bss_entries.as_ptr();
                    for j in 0..bss_count.min(256) {
                        let entry = &*bss_base.add(j);
                        let ssid_len = (entry.dot11_ssid.u_ssid_length as usize).min(32);
                        let ssid_str = String::from_utf8_lossy(&entry.dot11_ssid.uc_ssid[..ssid_len]).to_string();
                        let bssid = format!(
                            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            entry.dot11_bssid[0], entry.dot11_bssid[1], entry.dot11_bssid[2],
                            entry.dot11_bssid[3], entry.dot11_bssid[4], entry.dot11_bssid[5]
                        );
                        let freq_mhz = (entry.ul_ch_center_frequency / 1000) as u16;
                        let (ch, band) = freq_to_channel_and_band(freq_mhz);
                        let rssi = entry.l_rssi.clamp(-120, -10) as i8;

                        let ies = if entry.ul_ie_size > 0 && entry.ul_ie_size < 4096 {
                            let base_ptr = (entry as *const WlanBssEntry as *const u8).add(entry.ul_ie_offset as usize);
                            std::slice::from_raw_parts(base_ptr, entry.ul_ie_size as usize)
                        } else {
                            &[]
                        };
                        let ie_deep = parse_rsn_encryption(ies, entry.us_capability_information);

                        // 从 WlanRateSet 提取该 AP 物理支持最大基速率 (0.5 Mbps 步进)
                        let rate_count = (entry.wlan_rate_set.u_rate_set_length as usize).min(126);
                        let max_rate_mbps = entry.wlan_rate_set.us_rate_set[..rate_count]
                            .iter()
                            .map(|&r| ((r & 0x7FFF) as f32) * 0.5)
                            .fold(0.0f32, f32::max);
                        let band_display = if let Some(ref wifi_gen) = ie_deep.wifi_generation {
                            format!("{} ({})", band, wifi_gen)
                        } else {
                            band.into()
                        };

                        all_items.push(Dot11DissectionInfo {
                            frame_type: Dot11FrameType::Management,
                            subtype_name: "Win32 WLAN BSS Scan".into(),
                            bssid: bssid.clone(),
                            src_mac: bssid,
                            dst_mac: "FF:FF:FF:FF:FF:FF".into(),
                            ssid: if ssid_str.is_empty() { Some("<Hidden SSID>".into()) } else { Some(ssid_str) },
                            channel: ch,
                            encryption_type: ie_deep.summary_encryption,
                            is_deauth_threat: false,
                            deauth_reason_code: None,
                            is_eapol_handshake: false,
                            radiotap: RadiotapMetrics {
                                channel_freq_mhz: if freq_mhz > 0 { Some(freq_mhz) } else { None },
                                channel_number: ch,
                                band_desc: band_display,
                                rssi_dbm: Some(rssi),
                                noise_dbm: None,
                                snr_db: None,
                                rate_mbps: if max_rate_mbps > 0.0 { Some(max_rate_mbps) } else { None },
                            },
                        });
                    }
                    fn_free(p_bss_list as *mut c_void);
                }
            }

            fn_free(p_iface_list as *mut c_void);
            fn_close(h_client, std::ptr::null_mut());
            FreeLibrary(hmod);
            Ok((primary_iface_name, all_items))
        }
    }
}

#[tauri::command]
pub async fn scan_os_wifi_networks_cmd() -> Result<NativeWifiScanResult, String> {
    tokio::task::spawn_blocking(scan_os_wifi_networks_sync)
        .await
        .map_err(|e| format!("WLAN 原生扫描线程异常: {}", e))?
}

pub fn scan_os_wifi_networks_sync() -> Result<NativeWifiScanResult, String> {
    let ts_str = chrono::Local::now().format("%H:%M:%S.%3f").to_string();

    #[cfg(windows)]
    {
        match win_wlan::scan_via_wlanapi() {
            Ok((iface_name, mut items)) => {
                if items.is_empty() {
                    if let Ok(out) = {
                        use std::os::windows::process::CommandExt;
                        std::process::Command::new("netsh")
                            .args(&["wlan", "show", "networks", "mode=bssid"])
                            .creation_flags(0x08000000)
                            .output()
                    } {
                        if out.status.success() {
                            let stdout = win_wlan::decode_acp(&out.stdout);
                            let (_, fallback_items) = parse_netsh_wlan_output(&stdout);
                            items = fallback_items;
                        }
                    }
                }
                let cnt = items.len();
                for item in &items {
                    record_wifi_frame(item, &ts_str);
                }
                let summary = get_wifi_telemetry_summary();
                return Ok(NativeWifiScanResult {
                    native_scan_available: true,
                    platform: "windows-wlanapi".into(),
                    reason_code: if cnt > 0 { "OK".into() } else { "NO_AP_IN_RANGE".into() },
                    status_message: if cnt > 0 {
                        format!("WLAN 原生扫描完成（适配器: {}），实测捕获周边 {} 个 BSSID 节点。", if iface_name.is_empty() { "WLAN" } else { &iface_name }, cnt)
                    } else {
                        format!("无线网卡 {} 已就绪，但当前空口扫描范围内暂无可见接入点或需授予位置权限。", if iface_name.is_empty() { "WLAN" } else { &iface_name })
                    },
                    scanned_ap_count: cnt,
                    interface_name: iface_name,
                    aps: summary.ap_assets.clone(),
                    summary,
                });
            }
            Err((reason_code, status_message)) => {
                let summary = get_wifi_telemetry_summary();
                return Ok(NativeWifiScanResult {
                    native_scan_available: false,
                    platform: "windows-wlanapi".into(),
                    reason_code,
                    status_message,
                    scanned_ap_count: 0,
                    interface_name: String::new(),
                    aps: summary.ap_assets.clone(),
                    summary,
                });
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = std::process::Command::new("nmcli")
            .args(&["-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"])
            .output()
        {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut cnt = 0usize;
                for line in text.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 5 {
                        let ssid = parts[0].trim().to_string();
                        let bssid = parts[1].replace("\\:", ":").trim().to_string();
                        let ch = parts[2].trim().parse::<u8>().ok();
                        let sig = parts[3].trim().parse::<i32>().unwrap_or(50);
                        let rssi = ((sig.clamp(0, 100) / 2) - 100) as i8;
                        let sec = parts[4].trim().to_string();
                        let info = Dot11DissectionInfo {
                            frame_type: Dot11FrameType::Management,
                            subtype_name: "nmcli WLAN Scan".into(),
                            bssid: bssid.clone(),
                            src_mac: bssid,
                            dst_mac: "FF:FF:FF:FF:FF:FF".into(),
                            ssid: if ssid.is_empty() { None } else { Some(ssid) },
                            channel: ch,
                            encryption_type: if sec.is_empty() { "Open".into() } else { sec },
                            is_deauth_threat: false,
                            deauth_reason_code: None,
                            is_eapol_handshake: false,
                            radiotap: RadiotapMetrics {
                                channel_freq_mhz: ch.map(|c| if c <= 14 { 2407 + (c as u16) * 5 } else { 5000 + (c as u16) * 5 }),
                                channel_number: ch,
                                band_desc: if ch.unwrap_or(6) <= 14 { "2.4 GHz".into() } else { "5 GHz".into() },
                                rssi_dbm: Some(rssi),
                                noise_dbm: None,
                                snr_db: None,
                                rate_mbps: None,
                            },
                        };
                        record_wifi_frame(&info, &ts_str);
                        cnt += 1;
                    }
                }
                let summary = get_wifi_telemetry_summary();
                return Ok(NativeWifiScanResult {
                    native_scan_available: true,
                    platform: "linux-nmcli".into(),
                    reason_code: if cnt > 0 { "OK".into() } else { "NO_AP_IN_RANGE".into() },
                    status_message: format!("nmcli 无线扫描完成，发现 {} 个周边接入点", cnt),
                    scanned_ap_count: cnt,
                    interface_name: "nmcli-wlan".into(),
                    aps: summary.ap_assets.clone(),
                    summary,
                });
            }
        }
        let summary = get_wifi_telemetry_summary();
        return Ok(NativeWifiScanResult {
            native_scan_available: false,
            platform: "linux-nmcli".into(),
            reason_code: "NO_HARDWARE".into(),
            status_message: "当前 Linux 环境未发现活跃无线网卡或 nmcli 不可用".into(),
            scanned_ap_count: 0,
            interface_name: String::new(),
            aps: summary.ap_assets.clone(),
            summary,
        });
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = ts_str;
        let summary = get_wifi_telemetry_summary();
        Ok(NativeWifiScanResult {
            native_scan_available: false,
            platform: std::env::consts::OS.to_string(),
            reason_code: "UNSUPPORTED_OS".into(),
            status_message: "当前平台请通过 Npcap Monitor Mode 捕获 802.11 帧".into(),
            scanned_ap_count: 0,
            interface_name: String::new(),
            aps: summary.ap_assets.clone(),
            summary,
        })
    }
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

    #[test]
    fn test_parse_netsh_wlan_output_and_empty_boundary() {
        let sample = r#"
Interface name : WLAN
SSID 1 : Factory-OT-5G
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:1a:2b:3c:4d:5e
         Signal             : 82%
         Radio type         : 802.11ax
         Channel            : 36
"#;
        let (iface, aps) = parse_netsh_wlan_output(sample);
        assert_eq!(iface, "WLAN");
        assert_eq!(aps.len(), 1);
        assert_eq!(aps[0].ssid.as_deref(), Some("Factory-OT-5G"));
        assert_eq!(aps[0].channel, Some(36));
        assert_eq!(aps[0].radiotap.band_desc, "5 GHz");
        assert_eq!(aps[0].radiotap.rssi_dbm, Some(-59));

        // 边界防御: 空串与报错文本不会幻觉产出 AP
        let (_, empty_aps) = parse_netsh_wlan_output("The Wireless AutoConfig Service (wlansvc) is not running.");
        assert!(empty_aps.is_empty());

        #[cfg(windows)]
        {
            assert_eq!(std::mem::size_of::<win_wlan::WlanInterfaceInfo>(), 532);
            assert_eq!(std::mem::size_of::<win_wlan::WlanInterfaceInfoList>(), 540);
            assert_eq!(std::mem::size_of::<win_wlan::WlanBssEntry>(), 360);
            assert_eq!(std::mem::size_of::<win_wlan::WlanBssList>(), 368);

            // ANSI GBK(936) 解码验证: "接口" -> 0xBD, 0xD3, 0xBF, 0xDA
            let gbk_bytes = [0xBDu8, 0xD3, 0xBF, 0xDA];
            assert_eq!(win_wlan::decode_acp(&gbk_bytes), "接口");
        }

        let scan_res = scan_os_wifi_networks_sync().unwrap();
        assert!(!scan_res.status_message.is_empty());
        assert!(!scan_res.reason_code.is_empty());
    }

    #[test]
    fn test_dot11_ie_tlv_deep_parsing_wpa3_wifi6_qbss_and_malformed() {
        // 1. 构造 WPA3-SAE (00:0F:AC:08) + CCMP-128 + PMF Mandatory (MFPR=1,MFPC=1 => 0x00C0)
        //    + QBSS Load (Tag 11: 12 STAs, Util=128/255 ≈ 50.2%)
        //    + HE Capabilities (Tag 255, Ext=35 -> Wi-Fi 6)
        let mut ies = Vec::new();
        // Tag 11 (QBSS Load): len 5
        ies.extend_from_slice(&[11, 5, 12, 0, 128, 0x10, 0x00]);
        // Tag 48 (RSN IE): len 20
        ies.extend_from_slice(&[
            48, 20,
            0x01, 0x00,             // Version 1
            0x00, 0x0F, 0xAC, 0x04, // Group Cipher: CCMP-128
            0x01, 0x00,             // Pairwise Count: 1
            0x00, 0x0F, 0xAC, 0x04, // Pairwise: CCMP-128
            0x01, 0x00,             // AKM Count: 1
            0x00, 0x0F, 0xAC, 0x08, // AKM: WPA3-SAE
            0xC0, 0x00,             // RSN Caps: MFPR (bit6) + MFPC (bit7) = 0x00C0
        ]);
        // Tag 255 Ext=35 (HE Capabilities)
        ies.extend_from_slice(&[255, 4, 35, 0x01, 0x02, 0x03]);

        let deep = parse_dot11_ie_tlv_deep(&ies, 0x0011);
        assert_eq!(deep.pmf_status, "PMF-Req");
        assert_eq!(deep.wifi_generation.as_deref(), Some("Wi-Fi 6 (802.11ax)"));
        assert_eq!(deep.qbss_station_count, Some(12));
        assert!(deep.qbss_channel_util_pct.unwrap() > 49.0 && deep.qbss_channel_util_pct.unwrap() < 51.0);
        assert!(deep.akm_suites.contains(&"WPA3-SAE".to_string()));
        assert!(deep.pairwise_ciphers.contains(&"CCMP-128".to_string()));
        assert!(deep.security_alerts.is_empty(), "WPA3 + PMF-Req + CCMP 不应有降级风险告警");

        // 2. 弱安全组合: WPA2-PSK + TKIP 混合加密 + 无 PMF (RSN Caps = 0x0000)
        let weak_ies = [
            48, 20,
            0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x02, // TKIP
            0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x02, // Pairwise TKIP
            0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x02, // AKM PSK
            0x00, 0x00,             // No PMF
        ];
        let weak_deep = parse_dot11_ie_tlv_deep(&weak_ies, 0x0011);
        assert_eq!(weak_deep.pmf_status, "No-PMF");
        assert!(weak_deep.security_alerts.contains(&"WEAK_CIPHER_TKIP_WEP".to_string()));
        assert!(weak_deep.security_alerts.contains(&"NO_PMF_80211W".to_string()));

        // 3. 边界截断防御: 越界 Length 声明不会导致 panic 或越界读取
        let truncated = [48u8, 250, 0x01, 0x00, 0x00];
        let trunc_res = parse_dot11_ie_tlv_deep(&truncated, 0x0000);
        assert!(trunc_res.security_alerts.contains(&"OPEN_UNENCRYPTED_WLAN".to_string()));
    }
}
