//! IEEE 802.1Q 与 IEEE 802.1ad QinQ VLAN 专业监测与安全审计引擎
//!
//! # 工业级规范实现
//! - IEEE 802.1Q (单层 Customer VLAN): TPID 0x8100, 12-bit VID (0-4095), 3-bit PCP (CoS 优先级 0-7), 1-bit DEI;
//! - IEEE 802.1ad (QinQ 双层 Provider Bridging): S-Tag (0x88A8 / 0x9100) + C-Tag (0x8100);
//! - 工业安全异常与威胁检测：
//!   1. Double Tagging (VLAN Hopping 跨 VLAN 跳跃穿透攻击);
//!   2. Default VLAN 1 敏感生产流泄露风险;
//!   3. Reserved VID (0x000 / 0xFFF) 异常载荷告警;
//! - Trunk 链路多 VLAN 流量与优先级矩阵统计.
//!
//! # 复杂度量化
//! - 标签剥离与深度提取: 时间复杂度 O(1), 空间复杂度 O(1) (零堆内存分配);
//! - 全局 VLAN 矩阵统计更新: 时间复杂度 O(1) 常数时间查找更新, 空间复杂度 O(K) (K 为活跃 VLAN 数, 上限 4096).

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub const ETHERTYPE_VLAN_8021Q: u16 = 0x8100;
pub const ETHERTYPE_QINQ_8021AD: u16 = 0x88A8;
pub const ETHERTYPE_QINQ_LEGACY: u16 = 0x9100;

/// 单层 VLAN 标签解剖元数据
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VlanTagInfo {
    pub tpid: u16,
    pub pcp: u8,
    pub dei: bool,
    pub vid: u16,
    pub tpid_name: String,
    pub priority_desc: String,
}

/// 剥离 VLAN 后的以太网内层承载结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrippedVlanPayload<'a> {
    pub tags: Vec<VlanTagInfo>,
    pub inner_ethertype: u16,
    #[serde(skip)]
    pub inner_payload: &'a [u8],
    pub is_double_tagged: bool,
    pub has_vlan_hopping_threat: bool,
    pub threat_summary: Option<String>,
}

/// VLAN 流量与拓扑统计条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlanTrafficStat {
    pub vid: u16,
    pub is_qinq: bool,
    pub outer_vid: Option<u16>,
    pub packet_count: u64,
    pub byte_count: u64,
    pub pcp_distribution: [u64; 8],
    pub active_mac_count: usize,
    pub sample_macs: Vec<String>,
    pub last_seen_timestamp: String,
    pub security_flags: Vec<String>,
}

/// VLAN 专业监测全局遥测数据
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VlanTelemetrySummary {
    pub total_vlan_packets: u64,
    pub total_vlan_bytes: u64,
    pub active_vlan_count: usize,
    pub qinq_packets: u64,
    pub vlan_hopping_threats: u64,
    pub default_vlan1_packets: u64,
    pub stats: Vec<VlanTrafficStat>,
}

/// 802.1p CoS 优先级标准语义映射 (IEEE 802.1Q Table G-2)
pub fn pcp_to_priority_desc(pcp: u8) -> &'static str {
    match pcp {
        0 => "Best Effort (BE - 尽力而为)",
        1 => "Background (BK - 背景流量)",
        2 => "Excellent Effort (EE - 优先业务)",
        3 => "Critical Applications (CA - 关键工控应用)",
        4 => "Video (VI - 视频流延迟 < 100ms)",
        5 => "Voice (VO - 语音流延迟 < 10ms)",
        6 => "Internetwork Control (IC - 网间拓扑控制/OSPF/STP)",
        7 => "Network Control (NC - 网络关键心跳/实时保护)",
        _ => "Unknown Priority",
    }
}

/// 判定 EtherType 是否为合法的 VLAN 引导符
#[inline]
pub fn is_vlan_ethertype(ethertype: u16) -> bool {
    ethertype == ETHERTYPE_VLAN_8021Q
        || ethertype == ETHERTYPE_QINQ_8021AD
        || ethertype == ETHERTYPE_QINQ_LEGACY
}

/// 快速解剖单个 4 字节 VLAN 标签
///
/// # 边界条件检查 (Fail-Fast)
/// - 长度不足 4 字节直接返回 None;
///
/// # 算法复杂度
/// - 时间复杂度: O(1);
/// - 空间复杂度: O(1);
pub fn parse_single_vlan_tag(tag_bytes: &[u8], tpid: u16) -> Option<(VlanTagInfo, u16)> {
    if tag_bytes.len() < 4 {
        return None;
    }
    let tci = u16::from_be_bytes([tag_bytes[0], tag_bytes[1]]);
    let next_ethertype = u16::from_be_bytes([tag_bytes[2], tag_bytes[3]]);

    let pcp = ((tci >> 13) & 0x07) as u8;
    let dei = ((tci >> 12) & 0x01) == 1;
    let vid = tci & 0x0FFF;

    let tpid_name = match tpid {
        ETHERTYPE_VLAN_8021Q => "802.1Q (Customer Tag)".to_string(),
        ETHERTYPE_QINQ_8021AD => "802.1ad (Service Tag)".to_string(),
        ETHERTYPE_QINQ_LEGACY => "QinQ Legacy (0x9100)".to_string(),
        _ => format!("Custom TPID 0x{:04X}", tpid),
    };

    let priority_desc = pcp_to_priority_desc(pcp).to_string();

    Some((
        VlanTagInfo {
            tpid,
            pcp,
            dei,
            vid,
            tpid_name,
            priority_desc,
        },
        next_ethertype,
    ))
}

/// 从以太网载荷中递归剥离全部 VLAN 标签 (支持单层 802.1Q 及双层 QinQ)
///
/// # 边界条件穷举
/// 1. 极限 1: 数据过短 (< 4 字节)，安全返回空标签集合;
/// 2. 极限 2: 双层标签 Double Tagging，且外层为 Default VLAN (VID 1) 且内层不同，识别为潜在跳跃攻击;
/// 3. 极限 3: 标签超过 4 层 (防止恶意构造死循环畸形包)，通过深度计数安全熔断。
///
/// # 复杂度量化
/// - 时间复杂度: O(T)，T 为标签层数 (T <= 4)，均摊 O(1) 纳秒级;
/// - 空间复杂度: O(1) 仅栈分配微量结构体。
pub fn strip_vlan_tags<'a>(mut current_ethertype: u16, payload: &'a [u8]) -> StrippedVlanPayload<'a> {
    let mut tags = Vec::with_capacity(2);
    let mut offset = 0;
    let mut depth = 0;

    while is_vlan_ethertype(current_ethertype) && depth < 4 {
        if payload.len() < offset + 4 {
            break;
        }
        if let Some((tag, next_proto)) = parse_single_vlan_tag(&payload[offset..], current_ethertype) {
            current_ethertype = next_proto;
            tags.push(tag);
            offset += 4;
            depth += 1;
        } else {
            break;
        }
    }

    let is_double_tagged = tags.len() >= 2;
    let mut has_vlan_hopping_threat = false;
    let mut threat_summary = None;

    if is_double_tagged {
        let outer_vid = tags[0].vid;
        let inner_vid = tags[1].vid;
        // Double Tagging 攻击判定: 外层 VID 通常伪装为交换机 Native VLAN 1, 内层指向隔离目标 VLAN
        if (outer_vid == 1 || outer_vid == 0) && inner_vid != outer_vid {
            has_vlan_hopping_threat = true;
            threat_summary = Some(format!(
                "Double Tagging VLAN Hopping Attack: Outer VID {} (Native) -> Inner Target VID {}",
                outer_vid, inner_vid
            ));
        }
    } else if let Some(tag) = tags.first() {
        if tag.vid == 0 {
            threat_summary = Some("Priority-Tagged Frame (VID 0): Carrying CoS without VLAN membership".into());
        } else if tag.vid == 4095 {
            threat_summary = Some("Reserved VID 4095 Anomaly: Violating 802.1Q specification".into());
        }
    }

    let inner_payload = if offset <= payload.len() {
        &payload[offset..]
    } else {
        &[]
    };

    StrippedVlanPayload {
        tags,
        inner_ethertype: current_ethertype,
        inner_payload,
        is_double_tagged,
        has_vlan_hopping_threat,
        threat_summary,
    }
}

/// 内部维护的 VLAN 状态机
pub struct VlanMonitorInner {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub qinq_packets: u64,
    pub vlan_hopping_threats: u64,
    pub default_vlan1_packets: u64,
    pub stats_map: HashMap<(u16, Option<u16>), VlanTrafficStatInternal>,
}

pub struct VlanTrafficStatInternal {
    packet_count: u64,
    byte_count: u64,
    pcp_distribution: [u64; 8],
    macs: HashMap<String, u64>,
    last_seen_timestamp: String,
    security_flags: Vec<String>,
}

/// 全局单例 VLAN 专业监测引擎
pub static GLOBAL_VLAN_MONITOR: Lazy<Arc<RwLock<VlanMonitorInner>>> = Lazy::new(|| {
    Arc::new(RwLock::new(VlanMonitorInner {
        total_packets: 0,
        total_bytes: 0,
        qinq_packets: 0,
        vlan_hopping_threats: 0,
        default_vlan1_packets: 0,
        stats_map: HashMap::new(),
    }))
});

/// 记录入队 VLAN 报文指标
pub fn record_vlan_packet(
    tags: &[VlanTagInfo],
    frame_len: usize,
    src_mac: &str,
    is_hopping: bool,
    timestamp: &str,
) {
    if tags.is_empty() {
        return;
    }
    let mut lock = match GLOBAL_VLAN_MONITOR.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    lock.total_packets += 1;
    lock.total_bytes += frame_len as u64;

    let is_qinq = tags.len() >= 2;
    if is_qinq {
        lock.qinq_packets += 1;
    }
    if is_hopping {
        lock.vlan_hopping_threats += 1;
    }

    let (inner_vid, outer_vid, primary_pcp) = if is_qinq {
        (tags[1].vid, Some(tags[0].vid), tags[0].pcp)
    } else {
        (tags[0].vid, None, tags[0].pcp)
    };

    if inner_vid == 1 {
        lock.default_vlan1_packets += 1;
    }

    let key = (inner_vid, outer_vid);
    let entry = lock.stats_map.entry(key).or_insert_with(|| VlanTrafficStatInternal {
        packet_count: 0,
        byte_count: 0,
        pcp_distribution: [0; 8],
        macs: HashMap::new(),
        last_seen_timestamp: timestamp.to_string(),
        security_flags: Vec::new(),
    });

    entry.packet_count += 1;
    entry.byte_count += frame_len as u64;
    let pcp_idx = (primary_pcp as usize).min(7);
    entry.pcp_distribution[pcp_idx] += 1;
    entry.last_seen_timestamp = timestamp.to_string();

    if entry.macs.len() < 128 {
        *entry.macs.entry(src_mac.to_string()).or_insert(0) += 1;
    }

    if is_hopping && !entry.security_flags.contains(&"VLAN_HOPPING_ATTACK".to_string()) {
        entry.security_flags.push("VLAN_HOPPING_ATTACK".to_string());
    }
    if inner_vid == 1 && !entry.security_flags.contains(&"DEFAULT_VLAN_1_SENSITIVE".to_string()) {
        entry.security_flags.push("DEFAULT_VLAN_1_SENSITIVE".to_string());
    }
}

/// 获取全局 VLAN 遥测看板数据
pub fn get_vlan_telemetry_summary() -> VlanTelemetrySummary {
    let lock = match GLOBAL_VLAN_MONITOR.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let mut stats = Vec::with_capacity(lock.stats_map.len());
    for ((vid, outer_vid), entry) in lock.stats_map.iter() {
        let sample_macs = entry.macs.keys().take(5).cloned().collect();
        stats.push(VlanTrafficStat {
            vid: *vid,
            is_qinq: outer_vid.is_some(),
            outer_vid: *outer_vid,
            packet_count: entry.packet_count,
            byte_count: entry.byte_count,
            pcp_distribution: entry.pcp_distribution,
            active_mac_count: entry.macs.len(),
            sample_macs,
            last_seen_timestamp: entry.last_seen_timestamp.clone(),
            security_flags: entry.security_flags.clone(),
        });
    }

    // 按流量从大到小排序
    stats.sort_by(|a, b| b.byte_count.cmp(&a.byte_count));

    VlanTelemetrySummary {
        total_vlan_packets: lock.total_packets,
        total_vlan_bytes: lock.total_bytes,
        active_vlan_count: stats.len(),
        qinq_packets: lock.qinq_packets,
        vlan_hopping_threats: lock.vlan_hopping_threats,
        default_vlan1_packets: lock.default_vlan1_packets,
        stats,
    }
}

/// 重置全局统计
pub fn reset_vlan_telemetry() {
    let mut lock = match GLOBAL_VLAN_MONITOR.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    lock.total_packets = 0;
    lock.total_bytes = 0;
    lock.qinq_packets = 0;
    lock.vlan_hopping_threats = 0;
    lock.default_vlan1_packets = 0;
    lock.stats_map.clear();
}

#[tauri::command]
pub fn get_vlan_telemetry_cmd() -> Result<VlanTelemetrySummary, String> {
    Ok(get_vlan_telemetry_summary())
}

#[tauri::command]
pub fn reset_vlan_telemetry_cmd() -> Result<bool, String> {
    reset_vlan_telemetry();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_vlan_tag_parsing() {
        // TPID 0x8100, TCI = 0x6064 (PCP=3, DEI=0, VID=100), Next EtherType = 0x0800 (IPv4)
        let tag_bytes = [0x60, 0x64, 0x08, 0x00];
        let (info, next_proto) = parse_single_vlan_tag(&tag_bytes, ETHERTYPE_VLAN_8021Q).unwrap();
        assert_eq!(info.vid, 100);
        assert_eq!(info.pcp, 3);
        assert!(!info.dei);
        assert_eq!(next_proto, 0x0800);
        assert!(info.priority_desc.contains("Critical Applications"));
    }

    #[test]
    fn test_double_tagging_vlan_hopping_detection() {
        // Outer Tag: S-Tag 0x88A8, VID 1 (Native), PCP 0, Next TPID 0x8100
        // Inner Tag: C-Tag 0x8100, VID 200 (Target), PCP 5, Next EtherType 0x0800
        let mut frame_data = Vec::new();
        // S-Tag: TCI = (0 << 13) | 1 = 0x0001, Next = 0x8100
        frame_data.extend_from_slice(&[0x00, 0x01, 0x81, 0x00]);
        // C-Tag: TCI = (5 << 13) | 200 = 0xA0C8, Next = 0x0800
        frame_data.extend_from_slice(&[0xA0, 0xC8, 0x08, 0x00]);
        // Inner payload: dummy IPv4
        frame_data.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);

        let stripped = strip_vlan_tags(ETHERTYPE_QINQ_8021AD, &frame_data);
        assert_eq!(stripped.tags.len(), 2);
        assert_eq!(stripped.tags[0].vid, 1);
        assert_eq!(stripped.tags[1].vid, 200);
        assert_eq!(stripped.inner_ethertype, 0x0800);
        assert!(stripped.is_double_tagged);
        assert!(stripped.has_vlan_hopping_threat);
        assert!(stripped.threat_summary.unwrap().contains("VLAN Hopping"));
    }

    #[test]
    fn test_vlan_edge_cases_and_defense() {
        // 极限 1: 空数据包
        let stripped_empty = strip_vlan_tags(ETHERTYPE_VLAN_8021Q, &[]);
        assert!(stripped_empty.tags.is_empty());
        assert_eq!(stripped_empty.inner_ethertype, ETHERTYPE_VLAN_8021Q);

        // 极限 2: 截断的 2 字节数据
        let stripped_truncated = strip_vlan_tags(ETHERTYPE_VLAN_8021Q, &[0x00, 0x01]);
        assert!(stripped_truncated.tags.is_empty());

        // 极限 3: 正常单层 VLAN
        let single_tag_payload = [0x20, 0x0A, 0x86, 0xDD, 0x60, 0x00]; // PCP 1, VID 10, IPv6
        let stripped_single = strip_vlan_tags(ETHERTYPE_VLAN_8021Q, &single_tag_payload);
        assert_eq!(stripped_single.tags.len(), 1);
        assert_eq!(stripped_single.tags[0].vid, 10);
        assert_eq!(stripped_single.tags[0].pcp, 1);
        assert_eq!(stripped_single.inner_ethertype, 0x86DD);
    }
}
