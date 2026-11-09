//! 无线网络 (Wi-Fi, 蓝牙) 与虚拟局域网 (VLAN) 统一多协议诊断与解剖接口
//!
//! # 工业级规范实现
//! - 支持 Hex 报文字符串的高性能抗错解析 (自动滤除空格、换行符、0x 前缀);
//! - 自动感知或显式指定协议模式 (VLAN, Wi-Fi 802.11/Radiotap, Bluetooth HCI/BLE);
//! - 统一输出结构化诊断对象，无缝供前端大屏与单包深度溯源使用.
//!
//! # 复杂度量化
//! - 时间复杂度: O(N) (单遍 Hex 解码与协议特定状态机解析);
//! - 空间复杂度: O(N) (输出结构化 JSON 视图).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedWirelessVlanDissectionResult {
    pub mode: String,
    pub identified_protocol: String,
    pub raw_bytes_count: usize,
    pub success: bool,
    pub error_message: Option<String>,
    pub structured_details: Value,
    pub security_threats: Vec<String>,
}

/// 解码 Hex 字符串，容错处理各种格式（如空格、逗号、冒号、换行、0x 前缀）
pub fn sanitize_and_decode_hex(raw_hex: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = raw_hex
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if cleaned.is_empty() {
        return Err("输入 Hex 字符串为空或不包含有效十六进制字符".to_string());
    }
    if cleaned.len() % 2 != 0 {
        return Err(format!("十六进制字符长度为奇数 ({})，不符合完整字节对齐", cleaned.len()));
    }

    hex::decode(&cleaned).map_err(|e| format!("Hex 解码失败: {}", e))
}

#[tauri::command]
pub fn dissect_wireless_or_vlan_hex_cmd(
    raw_hex: String,
    mode: Option<String>,
) -> Result<UnifiedWirelessVlanDissectionResult, String> {
    let data = match sanitize_and_decode_hex(&raw_hex) {
        Ok(d) => d,
        Err(err) => {
            return Ok(UnifiedWirelessVlanDissectionResult {
                mode: mode.unwrap_or_else(|| "auto".into()),
                identified_protocol: "UNKNOWN".into(),
                raw_bytes_count: 0,
                success: false,
                error_message: Some(err),
                structured_details: json!({}),
                security_threats: vec![],
            });
        }
    };

    let target_mode = mode.unwrap_or_else(|| "auto".into()).to_lowercase();

    // 1. 尝试 Wi-Fi (Radiotap / 802.11)
    if target_mode == "wifi" || target_mode == "auto" {
        // 判定 Radiotap: 前 2 字节通常为 0x00, 0x00 且 it_len >= 8
        if data.len() >= 8 && data[0] == 0x00 && data[1] == 0x00 {
            let (radiotap, rtap_len) = crate::wifi_monitor::parse_radiotap_header(&data);
            if rtap_len > 0 && rtap_len <= data.len() {
                let dot11_payload = &data[rtap_len..];
                if let Some(info) = crate::wifi_monitor::parse_dot11_frame(dot11_payload, radiotap) {
                    let mut threats = Vec::new();
                    if info.is_deauth_threat {
                        threats.push(format!("Deauth Flood Attack Threat (Reason: {:?})", info.deauth_reason_code));
                    }
                    if info.is_eapol_handshake {
                        threats.push("EAPOL 4-Way Handshake Key Exchange Frame Captured".into());
                    }
                    return Ok(UnifiedWirelessVlanDissectionResult {
                        mode: "wifi".into(),
                        identified_protocol: "IEEE 802.11 with Radiotap".into(),
                        raw_bytes_count: data.len(),
                        success: true,
                        error_message: None,
                        structured_details: json!(info),
                        security_threats: threats,
                    });
                }
            }
        }
        // 若为裸 802.11 帧 (无 Radiotap)
        if data.len() >= 24 {
            if let Some(info) = crate::wifi_monitor::parse_dot11_frame(&data, crate::wifi_monitor::RadiotapMetrics::default()) {
                let mut threats = Vec::new();
                if info.is_deauth_threat {
                    threats.push(format!("Deauth Attack (Reason: {:?})", info.deauth_reason_code));
                }
                return Ok(UnifiedWirelessVlanDissectionResult {
                    mode: "wifi".into(),
                    identified_protocol: "IEEE 802.11 Raw MAC Frame".into(),
                    raw_bytes_count: data.len(),
                    success: true,
                    error_message: None,
                    structured_details: json!(info),
                    security_threats: threats,
                });
            }
        }
    }

    // 2. 尝试 Bluetooth (HCI H4)
    if target_mode == "bluetooth" || target_mode == "auto" {
        if !data.is_empty() && (1..=5).contains(&data[0]) {
            if let Some(info) = crate::bluetooth_monitor::parse_bluetooth_packet(&data) {
                let threats = info.security_alerts.clone();
                return Ok(UnifiedWirelessVlanDissectionResult {
                    mode: "bluetooth".into(),
                    identified_protocol: format!("Bluetooth HCI {:?}", info.hci_type),
                    raw_bytes_count: data.len(),
                    success: true,
                    error_message: None,
                    structured_details: json!(info),
                    security_threats: threats,
                });
            }
        }
    }

    // 3. 尝试 VLAN (802.1Q / QinQ)
    if target_mode == "vlan" || target_mode == "auto" {
        // 假定以太网帧或直接为带 TPID 的 VLAN 报文
        let (initial_tpid, vlan_payload) = if data.len() >= 14 && (data[12] == 0x81 || data[12] == 0x88 || data[12] == 0x91) {
            let tpid = u16::from_be_bytes([data[12], data[13]]);
            (tpid, &data[14..])
        } else if data.len() >= 4 {
            (crate::vlan_monitor::ETHERTYPE_VLAN_8021Q, &data[..])
        } else {
            (0, &[][..])
        };

        if crate::vlan_monitor::is_vlan_ethertype(initial_tpid) {
            let stripped = crate::vlan_monitor::strip_vlan_tags(initial_tpid, vlan_payload);
            if !stripped.tags.is_empty() {
                let mut threats = Vec::new();
                if stripped.has_vlan_hopping_threat {
                    threats.push(stripped.threat_summary.clone().unwrap_or_else(|| "VLAN Hopping Attack".into()));
                }
                return Ok(UnifiedWirelessVlanDissectionResult {
                    mode: "vlan".into(),
                    identified_protocol: if stripped.is_double_tagged { "IEEE 802.1ad (QinQ Double Tagging)" } else { "IEEE 802.1Q VLAN" }.into(),
                    raw_bytes_count: data.len(),
                    success: true,
                    error_message: None,
                    structured_details: json!({
                        "tags": stripped.tags,
                        "inner_ethertype": format!("0x{:04X}", stripped.inner_ethertype),
                        "inner_payload_bytes": stripped.inner_payload.len(),
                        "is_double_tagged": stripped.is_double_tagged,
                        "has_vlan_hopping_threat": stripped.has_vlan_hopping_threat,
                        "threat_summary": stripped.threat_summary,
                    }),
                    security_threats: threats,
                });
            }
        }
    }

    Ok(UnifiedWirelessVlanDissectionResult {
        mode: target_mode,
        identified_protocol: "RAW_UNKNOWN".into(),
        raw_bytes_count: data.len(),
        success: false,
        error_message: Some("未匹配到合法的 Wi-Fi, 蓝牙或 VLAN 协议特征结构".into()),
        structured_details: json!({ "hex_preview": hex::encode(&data[..data.len().min(32)]) }),
        security_threats: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_and_decode_hex() {
        let valid_spaced = "00 11 22 33 AA BB";
        let decoded = sanitize_and_decode_hex(valid_spaced).unwrap();
        assert_eq!(decoded, vec![0x00, 0x11, 0x22, 0x33, 0xAA, 0xBB]);

        let invalid_odd = "123";
        assert!(sanitize_and_decode_hex(invalid_odd).is_err());
    }

    #[test]
    fn test_dissect_wireless_or_vlan_hex_cmd_vlan() {
        // 构造以太网头 (14 字节): 6 字节 dst, 6 字节 src, 2 字节 EtherType 0x8100 (VLAN)
        // 接着 4 字节 VLAN: TCI 0x200A (PCP 1, VID 10), Next 0x0800 (IPv4)
        let mut raw = Vec::new();
        raw.extend_from_slice(&[0xFF; 6]);
        raw.extend_from_slice(&[0x11; 6]);
        raw.extend_from_slice(&[0x81, 0x00]); // VLAN EtherType
        raw.extend_from_slice(&[0x20, 0x0A, 0x08, 0x00]); // PCP 1, VID 10, Next IPv4
        raw.extend_from_slice(&[0x45, 0x00, 0x00, 0x20]); // Dummy IPv4

        let hex_s = hex::encode(&raw);
        let res = dissect_wireless_or_vlan_hex_cmd(hex_s, Some("vlan".into())).unwrap();
        assert!(res.success);
        assert_eq!(res.mode, "vlan");
        assert!(res.identified_protocol.contains("802.1Q"));
    }
}
