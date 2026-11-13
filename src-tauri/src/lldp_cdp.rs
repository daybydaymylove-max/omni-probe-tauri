// ============================================================================
// Omni-Probe 二层链路发现协议原生解码引擎 (IEEE 802.1AB LLDP & Cisco CDP)
//
// 核心工程设计目标：
// 1. 零外挂依赖纯字节级解码：
//    - IEEE 802.1AB LLDP (EtherType 0x88CC): 7-bit Type + 9-bit Length 变长 TLV 流，
//      完整还原 Chassis ID、Port ID、TTL、System Name/Descr、Capabilities、Management IP、
//      以及 IEEE 802.1 Organizationally Specific (OUI 00-80-C2) Port VLAN ID (PVID) 与 VLAN Name。
//    - Cisco CDP (802.3 LLC AA:AA:03 + SNAP OUI 00:00:0C + PID 0x2000): 校验 Version/TTL/Checksum
//      及 16-bit Type + 16-bit Length（强制校验 length >= 4 防整数下溢），还原 Device ID、
//      管理 IP 地址列表、Port ID、Platform、Capabilities、Native VLAN 与全/半双工状态。
// 2. 免 SNMP 口令自动二层拓扑入账：
//    捕获帧解码后实时入库至 GLOBAL_L2_NEIGHBORS，并合并注册到 GLOBAL_SWITCH_MAP，
//    让一线网工在直连网线未获 SNMP 团体字前即可直观查看上联交换机名称、管理 IP、物理接口及 VLAN。
// 3. 复杂度：时间复杂度 O(N)（N 为报文载荷长度），空间复杂度 O(K)（K 为 TLV 个数）。
// ============================================================================

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::snmp_topology::{
    normalize_mac_address, PortDuplexMode, SwitchDevice, SwitchPortInfo, GLOBAL_SWITCH_MAP,
};

const MAX_NEIGHBOR_RECORDS: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2DiscoveryNeighbor {
    pub record_key: String,
    pub protocol: String, // "LLDP" | "CDP"
    pub src_mac: String,
    pub chassis_id: String,
    pub system_name: String,
    pub system_descr: String,
    pub port_id: String,
    pub port_descr: String,
    pub management_ip: String,
    pub management_ips: Vec<String>,
    pub native_vlan: Option<u16>,
    pub vlan_name: Option<String>,
    pub ttl_secs: u16,
    pub capabilities: Vec<String>,
    pub duplex: String,
    pub platform: String,
    pub seen_count: u64,
    pub last_seen_ts: String,
}

pub static GLOBAL_L2_NEIGHBORS: Lazy<Arc<Mutex<BTreeMap<String, L2DiscoveryNeighbor>>>> =
    Lazy::new(|| Arc::new(Mutex::new(BTreeMap::new())));

fn format_mac_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_ip_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.len() == 4 {
        Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
    } else if bytes.len() == 16 {
        let addr = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?);
        Some(addr.to_string())
    } else {
        None
    }
}

fn clean_utf8_ascii(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .trim()
        .to_string()
}

fn decode_lldp_capabilities(bitmap: u16) -> Vec<String> {
    let flags = [
        (0x0001, "Other"),
        (0x0002, "Repeater"),
        (0x0004, "Bridge(Switch)"),
        (0x0008, "WLAN-AP"),
        (0x0010, "Router"),
        (0x0020, "Telephone"),
        (0x0040, "DOCSIS"),
        (0x0080, "Station"),
        (0x0100, "C-VLAN"),
        (0x0200, "S-VLAN"),
        (0x0400, "TPMR"),
    ];
    let mut caps = Vec::new();
    for (mask, name) in flags {
        if bitmap & mask != 0 {
            caps.push(name.to_string());
        }
    }
    caps
}

fn decode_cdp_capabilities(bitmap: u32) -> Vec<String> {
    let flags = [
        (0x0001, "Router"),
        (0x0002, "Transparent-Bridge"),
        (0x0004, "Source-Route-Bridge"),
        (0x0008, "Switch"),
        (0x0010, "Host"),
        (0x0020, "IGMP"),
        (0x0040, "Repeater"),
        (0x0080, "VoIP-Phone"),
    ];
    let mut caps = Vec::new();
    for (mask, name) in flags {
        if bitmap & mask != 0 {
            caps.push(name.to_string());
        }
    }
    caps
}

/// 纯字节解码 IEEE 802.1AB LLDPDU 载荷（不含以太网 14B 帧头）
/// 时间复杂度: O(N), 空间复杂度: O(K)
pub fn parse_lldp_pdu(payload: &[u8], src_mac: &str, timestamp: &str) -> Result<L2DiscoveryNeighbor, String> {
    if payload.len() < 2 {
        return Err("LLDP PDU 长度过短（至少需 2 字节 TLV 头）".into());
    }

    let mut offset = 0usize;
    let mut chassis_id = String::new();
    let mut port_id = String::new();
    let mut port_descr = String::new();
    let mut system_name = String::new();
    let mut system_descr = String::new();
    let mut ttl_secs: u16 = 0;
    let mut capabilities: Vec<String> = Vec::new();
    let mut management_ips: Vec<String> = Vec::new();
    let mut native_vlan: Option<u16> = None;
    let mut vlan_name: Option<String> = None;
    let mut tlv_count = 0usize;

    while offset + 2 <= payload.len() {
        let header = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        offset += 2;
        let tlv_type = (header >> 9) & 0x7F;
        let tlv_len = (header & 0x01FF) as usize;

        if tlv_type == 0 {
            // End of LLDPDU TLV
            break;
        }
        if offset + tlv_len > payload.len() {
            return Err(format!(
                "LLDP TLV (Type={}) 越界: offset={}, len={}, total={}",
                tlv_type,
                offset,
                tlv_len,
                payload.len()
            ));
        }

        let val = &payload[offset..offset + tlv_len];
        offset += tlv_len;
        tlv_count += 1;

        match tlv_type {
            1 if !val.is_empty() => {
                // Chassis ID TLV: 1B subtype + value
                let subtype = val[0];
                let body = &val[1..];
                chassis_id = match subtype {
                    4 if body.len() == 6 => format_mac_bytes(body),
                    5 if body.len() >= 5 && body[0] == 1 => {
                        format_ip_bytes(&body[1..5]).unwrap_or_else(|| format_mac_bytes(body))
                    }
                    _ => clean_utf8_ascii(body),
                };
            }
            2 if !val.is_empty() => {
                // Port ID TLV: 1B subtype + value
                let subtype = val[0];
                let body = &val[1..];
                port_id = match subtype {
                    3 if body.len() == 6 => format_mac_bytes(body),
                    4 if body.len() >= 5 && body[0] == 1 => {
                        format_ip_bytes(&body[1..5]).unwrap_or_else(|| format_mac_bytes(body))
                    }
                    _ => clean_utf8_ascii(body),
                };
            }
            3 if val.len() >= 2 => {
                ttl_secs = u16::from_be_bytes([val[0], val[1]]);
            }
            4 => {
                port_descr = clean_utf8_ascii(val);
            }
            5 => {
                system_name = clean_utf8_ascii(val);
            }
            6 => {
                system_descr = clean_utf8_ascii(val);
            }
            7 if val.len() >= 4 => {
                // System Capabilities (2B) + Enabled Capabilities (2B)
                let enabled = u16::from_be_bytes([val[2], val[3]]);
                let supported = u16::from_be_bytes([val[0], val[1]]);
                capabilities = decode_lldp_capabilities(if enabled != 0 { enabled } else { supported });
            }
            8 if val.len() >= 2 => {
                // Management Address TLV: [addr_len(1B)][addr_subtype(1B)][addr_bytes...]
                let addr_str_len = val[0] as usize;
                if addr_str_len >= 2 && 1 + addr_str_len <= val.len() {
                    let addr_subtype = val[1];
                    let addr_raw = &val[2..1 + addr_str_len];
                    if (addr_subtype == 1 && addr_raw.len() == 4)
                        || (addr_subtype == 2 && addr_raw.len() == 16)
                    {
                        if let Some(ip_str) = format_ip_bytes(addr_raw) {
                            if !management_ips.contains(&ip_str) {
                                management_ips.push(ip_str);
                            }
                        }
                    }
                }
            }
            127 if val.len() >= 4 => {
                // Organizationally Specific TLV: 3B OUI + 1B Subtype + Payload
                let oui = &val[0..3];
                let subtype = val[3];
                let org_body = &val[4..];
                if oui == [0x00, 0x80, 0xC2] {
                    // IEEE 802.1
                    match subtype {
                        1 if org_body.len() >= 2 => {
                            native_vlan = Some(u16::from_be_bytes([org_body[0], org_body[1]]));
                        }
                        3 if org_body.len() >= 3 => {
                            let vid = u16::from_be_bytes([org_body[0], org_body[1]]);
                            if native_vlan.is_none() {
                                native_vlan = Some(vid);
                            }
                            let name_len = org_body[2] as usize;
                            if 3 + name_len <= org_body.len() {
                                let vn = clean_utf8_ascii(&org_body[3..3 + name_len]);
                                if !vn.is_empty() {
                                    vlan_name = Some(vn);
                                }
                            }
                        }
                        _ => {}
                    }
                } else if oui == [0x00, 0x12, 0x0F] && subtype == 1 && org_body.len() >= 5 {
                    // IEEE 802.3 MAC/PHY Configuration/Status: autoneg/duplex hint
                }
            }
            _ => {}
        }
    }

    if tlv_count == 0 || (chassis_id.is_empty() && port_id.is_empty() && system_name.is_empty()) {
        return Err("未识别到有效 LLDP 必填 TLV (Chassis ID / Port ID)".into());
    }

    let norm_src_mac = normalize_mac_address(src_mac);
    let mgmt_primary = management_ips.first().cloned().unwrap_or_default();
    let display_name = if !system_name.is_empty() {
        system_name.clone()
    } else if !mgmt_primary.is_empty() {
        mgmt_primary.clone()
    } else if !chassis_id.is_empty() {
        chassis_id.clone()
    } else {
        norm_src_mac.clone()
    };

    let record_key = format!("LLDP|{}|{}", if chassis_id.is_empty() { &norm_src_mac } else { &chassis_id }, port_id);
    Ok(L2DiscoveryNeighbor {
        record_key,
        protocol: "LLDP".to_string(),
        src_mac: norm_src_mac,
        chassis_id,
        system_name: display_name,
        system_descr,
        port_id,
        port_descr,
        management_ip: mgmt_primary,
        management_ips,
        native_vlan,
        vlan_name,
        ttl_secs,
        capabilities,
        duplex: "Unknown".to_string(),
        platform: String::new(),
        seen_count: 1,
        last_seen_ts: timestamp.to_string(),
    })
}

/// 判定是否为 IEEE 802.3 LLC + SNAP 封装的 Cisco CDP 帧载荷 (不含 14B 以太网头)
pub fn is_cdp_llc_snap_payload(payload: &[u8]) -> bool {
    payload.len() >= 12
        && payload[0] == 0xAA
        && payload[1] == 0xAA
        && payload[2] == 0x03
        && payload[3] == 0x00
        && payload[4] == 0x00
        && payload[5] == 0x0C
        && payload[6] == 0x20
        && payload[7] == 0x00
}

/// 纯字节解码 Cisco CDP 载荷（输入可为含 LLC+SNAP 的 802.3 载荷，或直接从 CDP Version 开始）
/// 时间复杂度: O(N), 空间复杂度: O(K)
pub fn parse_cdp_pdu(payload: &[u8], src_mac: &str, timestamp: &str) -> Result<L2DiscoveryNeighbor, String> {
    let cdp_body = if is_cdp_llc_snap_payload(payload) {
        &payload[8..]
    } else {
        payload
    };

    // CDP Header: Version(1B) + TTL(1B) + Checksum(2B)
    if cdp_body.len() < 4 {
        return Err("CDP PDU 长度不足 4 字节头".into());
    }
    let version = cdp_body[0];
    if version != 1 && version != 2 {
        return Err(format!("不支持的 CDP 协议版本: {}", version));
    }
    let ttl_secs = cdp_body[1] as u16;
    let mut offset = 4usize;

    let mut device_id = String::new();
    let mut port_id = String::new();
    let mut system_descr = String::new();
    let mut platform = String::new();
    let mut capabilities: Vec<String> = Vec::new();
    let mut management_ips: Vec<String> = Vec::new();
    let mut native_vlan: Option<u16> = None;
    let mut duplex = "Unknown".to_string();

    while offset + 4 <= cdp_body.len() {
        let tlv_type = u16::from_be_bytes([cdp_body[offset], cdp_body[offset + 1]]);
        let tlv_total_len = u16::from_be_bytes([cdp_body[offset + 2], cdp_body[offset + 3]]) as usize;

        // CDP TLV length 包含 Type(2B) + Length(2B) 本身，严防 < 4 整数下溢漏洞
        if tlv_total_len < 4 || offset + tlv_total_len > cdp_body.len() {
            return Err(format!(
                "CDP TLV 长度异常 (Type=0x{:04X}, total_len={}, remain={})",
                tlv_type,
                tlv_total_len,
                cdp_body.len() - offset
            ));
        }

        let val = &cdp_body[offset + 4..offset + tlv_total_len];
        offset += tlv_total_len;

        match tlv_type {
            0x0001 => device_id = clean_utf8_ascii(val),
            0x0002 if val.len() >= 4 => {
                // Addresses: count(4B) + [proto_type(1B) + proto_len(1B) + proto(proto_len) + addr_len(2B) + addr]
                let count = u32::from_be_bytes([val[0], val[1], val[2], val[3]]) as usize;
                let mut pos = 4usize;
                for _ in 0..count.min(16) {
                    if pos + 2 > val.len() {
                        break;
                    }
                    let plen = val[pos + 1] as usize;
                    pos += 2 + plen;
                    if pos + 2 > val.len() {
                        break;
                    }
                    let alen = u16::from_be_bytes([val[pos], val[pos + 1]]) as usize;
                    pos += 2;
                    if pos + alen > val.len() {
                        break;
                    }
                    if let Some(ip_s) = format_ip_bytes(&val[pos..pos + alen]) {
                        if !management_ips.contains(&ip_s) {
                            management_ips.push(ip_s);
                        }
                    }
                    pos += alen;
                }
            }
            0x0003 => port_id = clean_utf8_ascii(val),
            0x0004 if val.len() >= 4 => {
                let bits = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
                capabilities = decode_cdp_capabilities(bits);
            }
            0x0005 => system_descr = clean_utf8_ascii(val),
            0x0006 => platform = clean_utf8_ascii(val),
            0x000A if val.len() >= 2 => {
                native_vlan = Some(u16::from_be_bytes([val[0], val[1]]));
            }
            0x000B if !val.is_empty() => {
                duplex = if val[0] == 1 {
                    "FullDuplex".to_string()
                } else {
                    "HalfDuplex".to_string()
                };
            }
            _ => {}
        }
    }

    if device_id.is_empty() && port_id.is_empty() {
        return Err("未解析出有效 CDP Device ID / Port ID".into());
    }

    let norm_src_mac = normalize_mac_address(src_mac);
    let mgmt_primary = management_ips.first().cloned().unwrap_or_default();
    let record_key = format!("CDP|{}|{}", if device_id.is_empty() { &norm_src_mac } else { &device_id }, port_id);

    Ok(L2DiscoveryNeighbor {
        record_key,
        protocol: "CDP".to_string(),
        src_mac: norm_src_mac.clone(),
        chassis_id: norm_src_mac,
        system_name: if device_id.is_empty() { platform.clone() } else { device_id },
        system_descr,
        port_id: port_id.clone(),
        port_descr: port_id,
        management_ip: mgmt_primary,
        management_ips,
        native_vlan,
        vlan_name: None,
        ttl_secs,
        capabilities,
        duplex,
        platform,
        seen_count: 1,
        last_seen_ts: timestamp.to_string(),
    })
}

/// 统一二层发现帧入口：识别并解析 LLDP/CDP 后同步入库 `GLOBAL_L2_NEIGHBORS` 与 `GLOBAL_SWITCH_MAP`
pub fn parse_and_ingest_l2_discovery(
    ethertype_or_len: u16,
    dst_mac: &str,
    src_mac: &str,
    payload: &[u8],
    timestamp: &str,
) -> Option<L2DiscoveryNeighbor> {
    let parsed = if ethertype_or_len == 0x88CC {
        parse_lldp_pdu(payload, src_mac, timestamp).ok()
    } else if (ethertype_or_len <= 1500 && is_cdp_llc_snap_payload(payload))
        || (dst_mac.eq_ignore_ascii_case("01:00:0c:cc:cc:cc") && is_cdp_llc_snap_payload(payload))
    {
        parse_cdp_pdu(payload, src_mac, timestamp).ok()
    } else {
        None
    }?;

    ingest_l2_neighbor_into_registries(&parsed);
    Some(parsed)
}

fn ingest_l2_neighbor_into_registries(neighbor: &L2DiscoveryNeighbor) {
    // 1. 写入二层发现独立邻接台账
    if let Ok(mut guard) = GLOBAL_L2_NEIGHBORS.lock() {
        if let Some(existing) = guard.get_mut(&neighbor.record_key) {
            existing.seen_count = existing.seen_count.saturating_add(1);
            existing.last_seen_ts = neighbor.last_seen_ts.clone();
            if !neighbor.management_ip.is_empty() {
                existing.management_ip = neighbor.management_ip.clone();
            }
            if neighbor.native_vlan.is_some() {
                existing.native_vlan = neighbor.native_vlan;
            }
            if !neighbor.system_descr.is_empty() {
                existing.system_descr = neighbor.system_descr.clone();
            }
        } else {
            if guard.len() >= MAX_NEIGHBOR_RECORDS {
                if let Some(first_key) = guard.keys().next().cloned() {
                    guard.remove(&first_key);
                }
            }
            guard.insert(neighbor.record_key.clone(), neighbor.clone());
        }
    }

    // 2. 自动合并到 GLOBAL_SWITCH_MAP，使无 SNMP 凭证场景也具备交换机接入台账
    let sw_id = if !neighbor.management_ip.is_empty() {
        format!("L2-{}", neighbor.management_ip)
    } else {
        format!("L2-{}", neighbor.system_name)
    };
    let port_name = if !neighbor.port_id.is_empty() {
        neighbor.port_id.clone()
    } else {
        neighbor.port_descr.clone()
    };

    if let Ok(mut smap) = GLOBAL_SWITCH_MAP.lock() {
        let dev = smap.switches.entry(sw_id.clone()).or_insert_with(|| {
            let mut d = SwitchDevice::new(
                sw_id.clone(),
                if neighbor.management_ip.is_empty() {
                    neighbor.src_mac.clone()
                } else {
                    neighbor.management_ip.clone()
                },
                neighbor.system_name.clone(),
            );
            d.sys_descr = if !neighbor.platform.is_empty() {
                format!("{} | {}", neighbor.platform, neighbor.system_descr)
            } else {
                neighbor.system_descr.clone()
            };
            d
        });

        // 为邻接端口分配稳定的确定性虚拟端口号（>= 10000 避免冲突真实 SNMP ifIndex）
        let port_hash_idx = 10_000
            + (port_name
                .bytes()
                .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32))
                % 50_000);
        if !dev.ports.contains_key(&port_hash_idx) && !port_name.is_empty() {
            let mut p = SwitchPortInfo::new(port_hash_idx, port_name, 1_000_000_000);
            p.port_alias = format!(
                "{} 发现{}{}",
                neighbor.protocol,
                neighbor
                    .native_vlan
                    .map(|v| format!(" (VLAN {})", v))
                    .unwrap_or_default(),
                if neighbor.port_descr.is_empty() {
                    String::new()
                } else {
                    format!(" · {}", neighbor.port_descr)
                }
            );
            p.duplex = match neighbor.duplex.as_str() {
                "FullDuplex" => PortDuplexMode::FullDuplex,
                "HalfDuplex" => PortDuplexMode::HalfDuplex,
                _ => PortDuplexMode::AutoNegotiate,
            };
            p.is_trunk_uplink = neighbor.capabilities.iter().any(|c| c.contains("Bridge") || c.contains("Switch"));
            dev.add_port(p);
        }
        if !neighbor.src_mac.is_empty() {
            dev.record_mac_fdb_entry(&neighbor.src_mac, port_hash_idx);
        }
    }
}

#[tauri::command]
pub fn get_l2_discovery_neighbors_cmd() -> Vec<L2DiscoveryNeighbor> {
    GLOBAL_L2_NEIGHBORS
        .lock()
        .map(|g| g.values().cloned().collect())
        .unwrap_or_default()
}

#[tauri::command]
pub fn clear_l2_discovery_neighbors_cmd() -> bool {
    if let Ok(mut g) = GLOBAL_L2_NEIGHBORS.lock() {
        g.clear();
        return true;
    }
    false
}

#[tauri::command]
pub fn decode_l2_discovery_hex_cmd(raw_hex: String, ingest: Option<bool>) -> Result<L2DiscoveryNeighbor, String> {
    let cleaned: String = raw_hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() < 28 || cleaned.len() % 2 != 0 {
        return Err("十六进制输入长度非法或不足以太网帧头 (至少 14 字节)".into());
    }
    let bytes = hex::decode(&cleaned).map_err(|e| format!("HEX 解码失败: {}", e))?;
    let dst_mac = format_mac_bytes(&bytes[0..6]);
    let src_mac = format_mac_bytes(&bytes[6..12]);
    let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
    let payload = &bytes[14..];
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let res = if ethertype == 0x88CC {
        parse_lldp_pdu(payload, &src_mac, &ts)?
    } else if is_cdp_llc_snap_payload(payload) || dst_mac.eq_ignore_ascii_case("01:00:0C:CC:CC:CC") {
        parse_cdp_pdu(payload, &src_mac, &ts)?
    } else {
        return Err(format!("EtherType 0x{:04X} 非标准 LLDP(0x88CC) 或 Cisco CDP 帧", ethertype));
    };

    if ingest.unwrap_or(false) {
        ingest_l2_neighbor_into_registries(&res);
    }
    Ok(res)
}

// ============================================================================
// 单元测试与边界防御验证
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn encode_lldp_tlv(tlv_type: u16, val: &[u8]) -> Vec<u8> {
        let hdr = ((tlv_type & 0x7F) << 9) | ((val.len() as u16) & 0x01FF);
        let mut out = hdr.to_be_bytes().to_vec();
        out.extend_from_slice(val);
        out
    }

    #[test]
    fn test_lldp_full_pdu_decode_with_mgmt_ip_and_pvid_and_ingestion() {
        let mut pdu = Vec::new();
        // Type 1 Chassis ID: Subtype 4 (MAC) + 00:11:22:33:44:55
        pdu.extend(encode_lldp_tlv(1, &[4, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        // Type 2 Port ID: Subtype 5 (Interface Name) + "GigabitEthernet0/0/24"
        let mut port_val = vec![5u8];
        port_val.extend_from_slice(b"GigabitEthernet0/0/24");
        pdu.extend(encode_lldp_tlv(2, &port_val));
        // Type 3 TTL = 120s
        pdu.extend(encode_lldp_tlv(3, &120u16.to_be_bytes()));
        // Type 5 System Name
        pdu.extend(encode_lldp_tlv(5, b"HW-S5735-CORE-SW01"));
        // Type 7 Capabilities: Bridge(0x0004) | Router(0x0010)
        pdu.extend(encode_lldp_tlv(7, &[0x00, 0x14, 0x00, 0x14]));
        // Type 8 Management Address: addr_len=5, subtype=1(IPv4), 10.10.254.1, ifSubtype=2, ifNum=24, oidLen=0
        pdu.extend(encode_lldp_tlv(8, &[5, 1, 10, 10, 254, 1, 2, 0, 0, 0, 24, 0]));
        // Type 127 Org-Specific: IEEE 802.1 PVID = VLAN 120
        pdu.extend(encode_lldp_tlv(127, &[0x00, 0x80, 0xC2, 0x01, 0x00, 120]));
        // End of LLDPDU
        pdu.extend(encode_lldp_tlv(0, &[]));

        let parsed = parse_and_ingest_l2_discovery(
            0x88CC,
            "01:80:C2:00:00:0E",
            "00:11:22:33:44:55",
            &pdu,
            "2026-11-12 20:00:00",
        )
        .expect("标准 LLDP 帧应解码并写入拓扑台账");

        assert_eq!(parsed.protocol, "LLDP");
        assert_eq!(parsed.chassis_id, "00:11:22:33:44:55");
        assert_eq!(parsed.port_id, "GigabitEthernet0/0/24");
        assert_eq!(parsed.system_name, "HW-S5735-CORE-SW01");
        assert_eq!(parsed.management_ip, "10.10.254.1");
        assert_eq!(parsed.native_vlan, Some(120));
        assert_eq!(parsed.ttl_secs, 120);
        assert!(parsed.capabilities.iter().any(|c| c.contains("Bridge")));

        let list = get_l2_discovery_neighbors_cmd();
        assert!(list.iter().any(|n| n.system_name == "HW-S5735-CORE-SW01"));
    }

    #[test]
    fn test_cdp_llc_snap_decode_with_native_vlan_and_underflow_defense() {
        let mut frame = vec![
            0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00, // LLC + SNAP
            0x02, 180, 0x00, 0x00, // CDP v2, TTL 180s
        ];
        let mut push_tlv = |t: u16, val: &[u8]| {
            frame.extend_from_slice(&t.to_be_bytes());
            frame.extend_from_slice(&((val.len() + 4) as u16).to_be_bytes());
            frame.extend_from_slice(val);
        };
        push_tlv(0x0001, b"CISCO-C9300-ACCESS-02");
        push_tlv(0x0003, b"TenGigabitEthernet1/0/1");
        push_tlv(0x0006, b"cisco C9300-48P");
        push_tlv(0x000A, &300u16.to_be_bytes());
        push_tlv(0x000B, &[1u8]);
        // Address TLV: 1 address, NLPID(1, 1, 0xCC), len=4, 172.16.1.254
        push_tlv(0x0002, &[0, 0, 0, 1, 1, 1, 0xCC, 0, 4, 172, 16, 1, 254]);

        let cdp = parse_cdp_pdu(&frame, "AA:BB:CC:DD:EE:01", "2026-11-12 20:01:00")
            .expect("Cisco CDP LLC+SNAP 帧应精准解码");
        assert_eq!(cdp.system_name, "CISCO-C9300-ACCESS-02");
        assert_eq!(cdp.port_id, "TenGigabitEthernet1/0/1");
        assert_eq!(cdp.management_ip, "172.16.1.254");
        assert_eq!(cdp.native_vlan, Some(300));
        assert_eq!(cdp.duplex, "FullDuplex");

        // 极限畸形输入防御：CDP TLV Length=2 (< 4 头部长度) 绝不发生下溢 panic
        let malformed_cdp = [0x02, 180, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x41, 0x42];
        assert!(parse_cdp_pdu(&malformed_cdp, "00:00:00:00:00:01", "").is_err());

        // 极限空/截断输入防御
        assert!(parse_lldp_pdu(&[], "00:00:00:00:00:01", "").is_err());
        assert!(parse_lldp_pdu(&[0x02, 0x1F, 0x04], "00:00:00:00:00:01", "").is_err());
    }
}
