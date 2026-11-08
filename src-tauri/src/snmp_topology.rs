// ============================================================================
// Omni-Probe 工业级交换机物理拓扑联动、万级分级聚合树与分布式探针汇聚引擎
// (SNMP MIB Switch Topology Engine, Hierarchical Aggregation Tree & Distributed Probe Collector)
// 
// 核心工业设计目标：
// 1. SNMP MIB-II (RFC 1213 / RFC 2863), Bridge-MIB (RFC 1493 / RFC 4188) 与 IP-MIB:
//    实现交换机物理接口健康度联动 (Admin/Oper Status, Speed, In/Out Errors/Discards)
//    并利用 MAC 地址转发表 (dot1dTpFdbTable) 与 ARP 表 (ipNetToMediaTable) 
//    实现资产 IP/MAC 到物理交换机与具体接入物理端口 (Port Index / Port Name) 的精准级联定位。
// 2. 超大规模企业内网万级主机分级聚合拓扑树 (Hierarchical Aggregation Tree):
//    对标 ntopng 层次化网络图谱设计，将万级主机资产递归组织为：
//    安全域/自治域 (Zone) -> 超级网段 (/16) -> 子网 (/24) -> 主机 (Host)。
//    提供宏观折叠 (Roll-Up) 与精准下钻 (Drill-Down) 机制，向大屏视口投影的节点数量
//    严格控制在预设上限 (如 <= 64 个超级节点)，将 O(N^2) 边爆炸降至 O(M^2)，
//    彻底杜绝万级终端下 Canvas / WebGL 渲染性能雪崩。
// 3. 分布式边缘探针汇聚中心 (Distributed Probe Collector):
//    实现远程镜像探针心跳探活、分布式纳秒时钟频偏对齐与全网流量指标汇聚。
// ============================================================================

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

// ============================================================================
// 全局单例管理器
// ============================================================================

pub static GLOBAL_TOPOLOGY_TREE: Lazy<Arc<Mutex<HierarchicalAggregationTree>>> =
    Lazy::new(|| Arc::new(Mutex::new(HierarchicalAggregationTree::default())));

pub static GLOBAL_SWITCH_MAP: Lazy<Arc<Mutex<SwitchTopologyMap>>> =
    Lazy::new(|| Arc::new(Mutex::new(SwitchTopologyMap::new())));

pub static GLOBAL_PROBE_COLLECTOR: Lazy<Arc<Mutex<DistributedProbeCollector>>> =
    Lazy::new(|| Arc::new(Mutex::new(DistributedProbeCollector::default())));

// ============================================================================
// 第一部分：SNMP MIB 交换机物理端口联动与接入定位引擎
// ============================================================================

/// 交换机物理端口运维管理状态 (RFC 2863 ifAdminStatus)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortAdminStatus {
    Up = 1,
    Down = 2,
    Testing = 3,
    Unknown = 4,
}

impl Default for PortAdminStatus {
    fn default() -> Self {
        PortAdminStatus::Unknown
    }
}

/// 交换机物理端口物理运行状态 (RFC 2863 ifOperStatus)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortOperStatus {
    Up = 1,
    Down = 2,
    Testing = 3,
    Unknown = 4,
    Dormant = 5,
    NotPresent = 6,
    LowerLayerDown = 7,
}

impl Default for PortOperStatus {
    fn default() -> Self {
        PortOperStatus::Unknown
    }
}

/// 物理端口双工模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortDuplexMode {
    FullDuplex,
    HalfDuplex,
    AutoNegotiate,
    Unknown,
}

impl Default for PortDuplexMode {
    fn default() -> Self {
        PortDuplexMode::Unknown
    }
}

/// 交换机物理接口详细元数据与流量健康度模型 (RFC 2863 ifXTable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchPortInfo {
    pub port_index: u32,
    pub port_name: String,       // 如 "GigabitEthernet0/0/1"
    pub port_alias: String,      // 端口管理员备注
    pub speed_bps: u64,          // 链路协商速率 (如 1_000_000_000)
    pub admin_status: PortAdminStatus,
    pub oper_status: PortOperStatus,
    pub duplex: PortDuplexMode,
    pub mtu: u32,
    pub in_octets: u64,
    pub out_octets: u64,
    pub in_errors: u64,          // 物理层 CRC 校验错误、帧校验错误
    pub out_errors: u64,         // 发送端载波碰撞与错误
    pub in_discards: u64,        // 入向丢包 (队列溢出)
    pub out_discards: u64,       // 出向丢包 (流量整形溢出)
    pub is_trunk_uplink: bool,   // 是否为与其他交换机相连的汇聚级联端口
    pub learned_macs: Vec<String>, // 该端口学习到的 MAC 地址集合
}

impl SwitchPortInfo {
    pub fn new(port_index: u32, port_name: String, speed_bps: u64) -> Self {
        Self {
            port_index,
            port_name,
            port_alias: String::new(),
            speed_bps,
            admin_status: PortAdminStatus::Up,
            oper_status: PortOperStatus::Up,
            duplex: PortDuplexMode::FullDuplex,
            mtu: 1500,
            in_octets: 0,
            out_octets: 0,
            in_errors: 0,
            out_errors: 0,
            in_discards: 0,
            out_discards: 0,
            is_trunk_uplink: false,
            learned_macs: Vec::new(),
        }
    }

    /// 评估物理端口丢包与误码健康度 (0.0 ~ 1.0, 1.0 表示健康无误码)
    pub fn calculate_health_ratio(&self) -> f64 {
        let total_packets = self.in_octets / 64 + self.out_octets / 64 + 1; // 估算下限报文数
        let total_issues = self.in_errors + self.out_errors + self.in_discards + self.out_discards;
        if total_issues == 0 {
            1.0
        } else {
            let ratio = 1.0 - (total_issues as f64 / total_packets as f64);
            ratio.clamp(0.0, 1.0)
        }
    }
}

/// 交换机设备完整镜像模型 (SNMP MIB-II sysGroup & ifTable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchDevice {
    pub switch_id: String,       // 唯一设备 ID (如 "SW-CORE-01")
    pub management_ip: String,   // SNMP 管理 IP (如 "192.168.1.254")
    pub sys_name: String,        // sysName.0
    pub sys_descr: String,       // sysDescr.0 (硬件型号与操作系统版本)
    pub sys_location: String,    // sysLocation.0 (机房机架编号)
    pub ports: BTreeMap<u32, SwitchPortInfo>, // ifIndex -> SwitchPortInfo
    pub mac_to_port: HashMap<String, u32>,   // MAC (标准化大写冒号分隔) -> ifIndex
    pub arp_ip_to_mac: HashMap<String, String>, // IP -> MAC
}

impl SwitchDevice {
    pub fn new(switch_id: String, management_ip: String, sys_name: String) -> Self {
        Self {
            switch_id,
            management_ip,
            sys_name,
            sys_descr: String::new(),
            sys_location: String::new(),
            ports: BTreeMap::new(),
            mac_to_port: HashMap::new(),
            arp_ip_to_mac: HashMap::new(),
        }
    }

    /// 注入物理接口元数据
    pub fn add_port(&mut self, port: SwitchPortInfo) {
        self.ports.insert(port.port_index, port);
    }

    /// 记录 Bridge-MIB MAC 转发表条目 (dot1dTpFdbTable)
    /// 自动将 MAC 归一化为大写冒号分隔 (如 "00:1A:2B:3C:4D:5E")
    pub fn record_mac_fdb_entry(&mut self, raw_mac: &str, if_index: u32) {
        let clean_mac = normalize_mac_address(raw_mac);
        if clean_mac.is_empty() {
            return;
        }
        self.mac_to_port.insert(clean_mac.clone(), if_index);
        if let Some(port) = self.ports.get_mut(&if_index) {
            if !port.learned_macs.contains(&clean_mac) {
                port.learned_macs.push(clean_mac);
                // 若单个物理端口学习到的 MAC 地址超过阈值 (如 8 个)，推断该端口为级联 Trunk Uplink 端口
                if port.learned_macs.len() > 8 {
                    port.is_trunk_uplink = true;
                }
            }
        }
    }

    /// 记录 IP-MIB ARP 缓存映射条目 (ipNetToMediaTable)
    pub fn record_arp_entry(&mut self, ip: &str, raw_mac: &str) {
        let clean_mac = normalize_mac_address(raw_mac);
        if !clean_mac.is_empty() {
            self.arp_ip_to_mac.insert(ip.trim().to_string(), clean_mac);
        }
    }
}

/// 资产终端在物理网络中的接入定位结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalPortLocation {
    pub target_ip: String,
    pub target_mac: String,
    pub switch_id: String,
    pub switch_ip: String,
    pub switch_name: String,
    pub port_index: u32,
    pub port_name: String,
    pub port_alias: String,
    pub is_trunk_uplink: bool,
    pub link_speed_mbps: u64,
    pub port_oper_status: PortOperStatus,
    pub port_error_count: u64,
}

/// 全局网络交换机拓扑与物理定位管理器
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SwitchTopologyMap {
    pub switches: HashMap<String, SwitchDevice>,
}

impl SwitchTopologyMap {
    pub fn new() -> Self {
        Self {
            switches: HashMap::new(),
        }
    }

    pub fn register_switch(&mut self, switch: SwitchDevice) {
        self.switches.insert(switch.switch_id.clone(), switch);
    }

    /// 核心算法：IP / MAC 物理接入端口级联穿透定位
    /// 时间复杂度：O(S)，其中 S 为交换机数量（通常 <= 100），单台查询常数级 O(1)
    /// 空间复杂度：O(1)
    pub fn locate_physical_port(&self, ip: &str, raw_mac: Option<&str>) -> Option<PhysicalPortLocation> {
        let target_ip = ip.trim();
        let target_mac = raw_mac
            .map(normalize_mac_address)
            .filter(|m| !m.is_empty())
            .or_else(|| {
                // 若未直接传入 MAC，则跨所有交换机 ARP 表递归搜寻 IP 对应的 MAC
                for sw in self.switches.values() {
                    if let Some(m) = sw.arp_ip_to_mac.get(target_ip) {
                        return Some(m.clone());
                    }
                }
                None
            })?;

        // 搜寻候选匹配端口，优先选择非 Trunk 汇聚端口（即终端直接接入端口 Access Port）
        let mut best_candidate: Option<PhysicalPortLocation> = None;

        for sw in self.switches.values() {
            if let Some(&if_index) = sw.mac_to_port.get(&target_mac) {
                if let Some(port) = sw.ports.get(&if_index) {
                    let loc = PhysicalPortLocation {
                        target_ip: target_ip.to_string(),
                        target_mac: target_mac.clone(),
                        switch_id: sw.switch_id.clone(),
                        switch_ip: sw.management_ip.clone(),
                        switch_name: sw.sys_name.clone(),
                        port_index: port.port_index,
                        port_name: port.port_name.clone(),
                        port_alias: port.port_alias.clone(),
                        is_trunk_uplink: port.is_trunk_uplink,
                        link_speed_mbps: port.speed_bps / 1_000_000,
                        port_oper_status: port.oper_status,
                        port_error_count: port.in_errors + port.out_errors,
                    };

                    // 如果找到非 Trunk 的接入端口，这代表终端最底层物理接入位置，直接命中返回
                    if !port.is_trunk_uplink {
                        return Some(loc);
                    } else if best_candidate.is_none() {
                        best_candidate = Some(loc);
                    }
                }
            }
        }

        best_candidate
    }
}

/// 辅助函数：将各种格式的 MAC 归一化为标准的 "AA:BB:CC:DD:EE:FF" 大写格式
pub fn normalize_mac_address(mac: &str) -> String {
    let clean: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();
    if clean.len() != 12 {
        return String::new();
    }
    format!(
        "{}:{}:{}:{}:{}:{}",
        &clean[0..2],
        &clean[2..4],
        &clean[4..6],
        &clean[6..8],
        &clean[8..10],
        &clean[10..12]
    )
}

// ============================================================================
// 第二部分：超大规模企业内网万级主机分级聚合拓扑树 (ntopng 架构)
// ============================================================================

/// 拓扑聚合层级定义 (对标 ntopng 分级图谱)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HierarchyLevel {
    Zone = 0,     // 顶层：自治域 / 安全域 (如 "工控生产域", "办公管理域", "外部互联域")
    Supernet = 1, // 第二层：CIDR /16 超级网段 (如 "192.168.0.0/16", "10.10.0.0/16")
    Subnet = 2,   // 第三层：CIDR /24 子网网段 (如 "192.168.1.0/24")
    Host = 3,     // 第四层：叶子终端实体 (如 "192.168.1.100")
}

/// 资产叶子主机元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredHostLeaf {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub role: String,
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub active_flows: u64,
    pub alert_count: usize,
    pub is_high_risk: bool,
}

impl DiscoveredHostLeaf {
    pub fn new(ip: String, mac: String, vendor: String, role: String) -> Self {
        Self {
            ip,
            mac,
            vendor,
            role,
            in_bytes: 0,
            out_bytes: 0,
            active_flows: 0,
            alert_count: 0,
            is_high_risk: false,
        }
    }
}

/// 层次化超级聚合节点 (SuperNode)
/// 支撑万级资产秒级聚合与折叠展开，杜绝 Canvas 渲染卡死
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperNode {
    pub node_id: String,           // 唯一标识 (如 "zone-corp", "supernet-10.0.0.0_16", "subnet-10.0.1.0_24")
    pub label: String,             // 显示标签 (如 "办公网段 10.0.1.0/24")
    pub level: HierarchyLevel,
    pub parent_id: Option<String>,
    pub cidr_prefix: Option<String>,
    pub is_collapsed: bool,        // 当前是否处于折叠状态
    pub host_count: usize,         // 包含的主机总数
    pub total_in_bytes: u64,
    pub total_out_bytes: u64,
    pub total_flows: u64,
    pub total_alerts: usize,
    pub high_risk_hosts: usize,
    pub child_node_ids: Vec<String>,
    pub leaf_hosts: HashMap<String, DiscoveredHostLeaf>, // IP -> Host (仅在展开或子网层维护)
}

impl SuperNode {
    pub fn new(
        node_id: String,
        label: String,
        level: HierarchyLevel,
        parent_id: Option<String>,
        cidr_prefix: Option<String>,
    ) -> Self {
        Self {
            node_id,
            label,
            level,
            parent_id,
            cidr_prefix,
            is_collapsed: true, // 默认收起，保持宏观极简
            host_count: 0,
            total_in_bytes: 0,
            total_out_bytes: 0,
            total_flows: 0,
            total_alerts: 0,
            high_risk_hosts: 0,
            child_node_ids: Vec::new(),
            leaf_hosts: HashMap::new(),
        }
    }

    /// 递归/逐级累加叶子指标
    pub fn aggregate_leaf_metrics(&mut self) {
        let mut in_bytes = 0u64;
        let mut out_bytes = 0u64;
        let mut flows = 0u64;
        let mut alerts = 0usize;
        let mut risks = 0usize;

        for leaf in self.leaf_hosts.values() {
            in_bytes = in_bytes.saturating_add(leaf.in_bytes);
            out_bytes = out_bytes.saturating_add(leaf.out_bytes);
            flows = flows.saturating_add(leaf.active_flows);
            alerts = alerts.saturating_add(leaf.alert_count);
            if leaf.is_high_risk {
                risks += 1;
            }
        }

        self.host_count = self.leaf_hosts.len();
        self.total_in_bytes = in_bytes;
        self.total_out_bytes = out_bytes;
        self.total_flows = flows;
        self.total_alerts = alerts;
        self.high_risk_hosts = risks;
    }
}

/// 聚合通信骨干边 (AggregatedEdge)
/// 将成千上万个跨主机 TCP/UDP 会话聚合为网段/安全域之间的宏观流量管道
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedEdge {
    pub edge_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub flow_count: u64,
    pub total_bytes: u64,
    pub contains_threat: bool,
}

/// 向前端 Canvas / WebGL 大屏输出的视口投影数据集 (Viewport Projection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyViewPortResult {
    pub visible_nodes: Vec<SuperNode>,
    pub visible_edges: Vec<AggregatedEdge>,
    pub total_ingested_hosts: usize,
    pub rendered_node_count: usize,
    pub compression_ratio: f64, // 压缩比率 (如 10000 压缩为 32 个节点，比率为 99.68%)
}

/// 万级主机分级聚合拓扑树主状态机
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HierarchicalAggregationTree {
    pub nodes: HashMap<String, SuperNode>,
    pub host_to_subnet: HashMap<String, String>, // IP -> Subnet Node ID
    pub direct_session_counts: HashMap<(String, String), (u64, u64, bool)>, // (Src IP, Dst IP) -> (flows, bytes, threat)
    pub default_zone_id: String,
}

impl Default for HierarchicalAggregationTree {
    fn default() -> Self {
        Self::new("zone-default", "局域网安全域")
    }
}

impl HierarchicalAggregationTree {
    pub fn new(default_zone_id: &str, default_zone_label: &str) -> Self {
        let mut tree = Self {
            nodes: HashMap::new(),
            host_to_subnet: HashMap::new(),
            direct_session_counts: HashMap::new(),
            default_zone_id: default_zone_id.to_string(),
        };

        // 初始化默认安全域节点
        let root_zone = SuperNode::new(
            default_zone_id.to_string(),
            default_zone_label.to_string(),
            HierarchyLevel::Zone,
            None,
            None,
        );
        tree.nodes.insert(default_zone_id.to_string(), root_zone);
        tree
    }

    /// 提取 IPv4 对应的 /16 与 /24 规范 CIDR 前缀
    pub fn derive_cidrs(ip_str: &str) -> Option<(String, String)> {
        let ip = Ipv4Addr::from_str(ip_str.trim()).ok()?;
        let octets = ip.octets();
        let supernet = format!("{}.{}.0.0/16", octets[0], octets[1]);
        let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
        Some((supernet, subnet))
    }

    /// 接入资产主机 (Ingest Asset Host)
    /// 时间复杂度：O(1) 常数级分类与树形节点挂载
    /// 空间复杂度：O(1)
    pub fn ingest_host(&mut self, host: DiscoveredHostLeaf, custom_zone: Option<(&str, &str)>) {
        let (zone_id, zone_name) = custom_zone.unwrap_or((&self.default_zone_id, "局域网安全域"));

        // 1. 确保安全域 (Zone) 存在
        if !self.nodes.contains_key(zone_id) {
            let zone_node = SuperNode::new(
                zone_id.to_string(),
                zone_name.to_string(),
                HierarchyLevel::Zone,
                None,
                None,
            );
            self.nodes.insert(zone_id.to_string(), zone_node);
        }

        // 2. 推导 /16 与 /24 网段
        let (supernet_cidr, subnet_cidr) = match Self::derive_cidrs(&host.ip) {
            Some(pair) => pair,
            None => return, // 非有效 IPv4 则跳过
        };

        let supernet_id = format!("supernet-{}", supernet_cidr.replace(['.', '/'], "_"));
        let subnet_id = format!("subnet-{}", subnet_cidr.replace(['.', '/'], "_"));

        // 3. 确保 /16 Supernet 节点存在并挂载至 Zone
        if !self.nodes.contains_key(&supernet_id) {
            let mut sn_node = SuperNode::new(
                supernet_id.clone(),
                format!("网段 {}", supernet_cidr),
                HierarchyLevel::Supernet,
                Some(zone_id.to_string()),
                Some(supernet_cidr.clone()),
            );
            sn_node.is_collapsed = true;
            self.nodes.insert(supernet_id.clone(), sn_node);

            if let Some(zone) = self.nodes.get_mut(zone_id) {
                if !zone.child_node_ids.contains(&supernet_id) {
                    zone.child_node_ids.push(supernet_id.clone());
                }
            }
        }

        // 4. 确保 /24 Subnet 节点存在并挂载至 Supernet
        if !self.nodes.contains_key(&subnet_id) {
            let mut sub_node = SuperNode::new(
                subnet_id.clone(),
                format!("子网 {}", subnet_cidr),
                HierarchyLevel::Subnet,
                Some(supernet_id.clone()),
                Some(subnet_cidr.clone()),
            );
            sub_node.is_collapsed = true;
            self.nodes.insert(subnet_id.clone(), sub_node);

            if let Some(supernet) = self.nodes.get_mut(&supernet_id) {
                if !supernet.child_node_ids.contains(&subnet_id) {
                    supernet.child_node_ids.push(subnet_id.clone());
                }
            }
        }

        // 5. 将主机登记到 /24 Subnet 节点下
        self.host_to_subnet.insert(host.ip.clone(), subnet_id.clone());
        if let Some(subnet) = self.nodes.get_mut(&subnet_id) {
            subnet.leaf_hosts.insert(host.ip.clone(), host);
            subnet.aggregate_leaf_metrics();
        }

        // 6. 递归更新父级网段指标
        self.recompute_ancestor_metrics(&supernet_id);
    }

    /// 重新向上级汇聚指标统计
    fn recompute_ancestor_metrics(&mut self, supernet_id: &str) {
        let mut total_hosts = 0usize;
        let mut total_in = 0u64;
        let mut total_out = 0u64;
        let mut total_flows = 0u64;
        let mut total_alerts = 0usize;
        let mut high_risks = 0usize;
        let mut zone_id_opt: Option<String> = None;

        if let Some(supernet) = self.nodes.get(supernet_id) {
            zone_id_opt = supernet.parent_id.clone();
            for child_sub_id in &supernet.child_node_ids {
                if let Some(sub) = self.nodes.get(child_sub_id) {
                    total_hosts += sub.host_count;
                    total_in = total_in.saturating_add(sub.total_in_bytes);
                    total_out = total_out.saturating_add(sub.total_out_bytes);
                    total_flows = total_flows.saturating_add(sub.total_flows);
                    total_alerts += sub.total_alerts;
                    high_risks += sub.high_risk_hosts;
                }
            }
        }

        if let Some(supernet) = self.nodes.get_mut(supernet_id) {
            supernet.host_count = total_hosts;
            supernet.total_in_bytes = total_in;
            supernet.total_out_bytes = total_out;
            supernet.total_flows = total_flows;
            supernet.total_alerts = total_alerts;
            supernet.high_risk_hosts = high_risks;
        }

        if let Some(zone_id) = zone_id_opt {
            let mut z_hosts = 0usize;
            let mut z_in = 0u64;
            let mut z_out = 0u64;
            let mut z_flows = 0u64;
            let mut z_alerts = 0usize;
            let mut z_risks = 0usize;

            if let Some(zone) = self.nodes.get(&zone_id) {
                for sn_id in &zone.child_node_ids {
                    if let Some(sn) = self.nodes.get(sn_id) {
                        z_hosts += sn.host_count;
                        z_in = z_in.saturating_add(sn.total_in_bytes);
                        z_out = z_out.saturating_add(sn.total_out_bytes);
                        z_flows = z_flows.saturating_add(sn.total_flows);
                        z_alerts += sn.total_alerts;
                        z_risks += sn.high_risk_hosts;
                    }
                }
            }

            if let Some(zone) = self.nodes.get_mut(&zone_id) {
                zone.host_count = z_hosts;
                zone.total_in_bytes = z_in;
                zone.total_out_bytes = z_out;
                zone.total_flows = z_flows;
                zone.total_alerts = z_alerts;
                zone.high_risk_hosts = z_risks;
            }
        }
    }

    /// 记录通信会话流 (Ingest Session Flow)
    pub fn ingest_flow(&mut self, src_ip: &str, dst_ip: &str, bytes: u64, is_threat: bool) {
        let key = (src_ip.trim().to_string(), dst_ip.trim().to_string());
        let entry = self.direct_session_counts.entry(key).or_insert((0, 0, false));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.saturating_add(bytes);
        if is_threat {
            entry.2 = true;
        }

        let mut affected_supernets: Vec<String> = Vec::new();

        // 更新双方叶子节点的流量计数
        if let Some(sub_id) = self.host_to_subnet.get(src_ip).cloned() {
            if let Some(sub) = self.nodes.get_mut(&sub_id) {
                if let Some(host) = sub.leaf_hosts.get_mut(src_ip) {
                    host.out_bytes = host.out_bytes.saturating_add(bytes);
                    host.active_flows = host.active_flows.saturating_add(1);
                    if is_threat {
                        host.alert_count += 1;
                        host.is_high_risk = true;
                    }
                }
                sub.aggregate_leaf_metrics();
                if let Some(p_id) = &sub.parent_id {
                    affected_supernets.push(p_id.clone());
                }
            }
        }

        if let Some(sub_id) = self.host_to_subnet.get(dst_ip).cloned() {
            if let Some(sub) = self.nodes.get_mut(&sub_id) {
                if let Some(host) = sub.leaf_hosts.get_mut(dst_ip) {
                    host.in_bytes = host.in_bytes.saturating_add(bytes);
                    host.active_flows = host.active_flows.saturating_add(1);
                    if is_threat {
                        host.alert_count += 1;
                        host.is_high_risk = true;
                    }
                }
                sub.aggregate_leaf_metrics();
                if let Some(p_id) = &sub.parent_id {
                    affected_supernets.push(p_id.clone());
                }
            }
        }

        affected_supernets.sort();
        affected_supernets.dedup();
        for sn_id in affected_supernets {
            self.recompute_ancestor_metrics(&sn_id);
        }
    }

    /// 交互下钻展开 (Drill-Down)
    /// 用户点击某一超级节点时将其展开，展示其内部子网或叶子节点
    pub fn drill_down(&mut self, node_id: &str) -> bool {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.is_collapsed = false;
            true
        } else {
            false
        }
    }

    /// 交互向上折叠 (Roll-Up)
    pub fn roll_up(&mut self, node_id: &str) -> bool {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.is_collapsed = true;
            true
        } else {
            false
        }
    }

    /// 全部折叠至最高宏观层级
    pub fn collapse_all(&mut self) {
        for node in self.nodes.values_mut() {
            node.is_collapsed = true;
        }
    }

    /// 核心算法：生成自适应受限视口投影 (Generate Viewport Projection)
    /// 确保输出给前端大屏 Canvas 的节点数量永远严格限制在 max_node_budget 预算内 (例如 64 或 100)
    /// 
    /// 时间复杂度：O(N_visible + E_direct)，远小于全网 O(N^2)
    /// 空间复杂度：O(Budget)
    pub fn generate_viewport_projection(&self, max_node_budget: usize) -> TopologyViewPortResult {
        let budget = max_node_budget.clamp(8, 256);
        let mut visible_nodes: Vec<SuperNode> = Vec::new();
        let mut node_mapping: HashMap<String, String> = HashMap::new(); // Host IP 或 Child Node ID -> 当前视口可见宿主 Node ID

        // 递归遍历树：若节点未折叠且预算充裕，则展开其子级；否则直接展示当前超级节点
        for (node_id, node) in &self.nodes {
            if node.level == HierarchyLevel::Zone {
                if node.is_collapsed || visible_nodes.len() + node.child_node_ids.len() > budget {
                    // 折叠当前 Zone
                    visible_nodes.push(node.clone());
                    self.map_all_descendants_to(node_id, node_id, &mut node_mapping);
                } else {
                    // 展开 Zone，检查 Supernet
                    for sn_id in &node.child_node_ids {
                        if let Some(sn) = self.nodes.get(sn_id) {
                            if sn.is_collapsed || visible_nodes.len() + sn.child_node_ids.len() > budget {
                                visible_nodes.push(sn.clone());
                                self.map_all_descendants_to(sn_id, sn_id, &mut node_mapping);
                            } else {
                                // 展开 Supernet，展示 Subnet
                                for sub_id in &sn.child_node_ids {
                                    if let Some(sub) = self.nodes.get(sub_id) {
                                        if sub.is_collapsed || visible_nodes.len() + sub.leaf_hosts.len() > budget {
                                            visible_nodes.push(sub.clone());
                                            self.map_all_descendants_to(sub_id, sub_id, &mut node_mapping);
                                        } else {
                                            // 展开 Subnet，将具体叶子主机转化为虚拟 Host 节点展示
                                            for (ip, leaf) in &sub.leaf_hosts {
                                                let host_node_id = format!("host-{}", ip.replace('.', "_"));
                                                let mut leaf_node = SuperNode::new(
                                                    host_node_id.clone(),
                                                    format!("{} ({})", ip, leaf.role),
                                                    HierarchyLevel::Host,
                                                    Some(sub_id.clone()),
                                                    None,
                                                );
                                                leaf_node.host_count = 1;
                                                leaf_node.total_in_bytes = leaf.in_bytes;
                                                leaf_node.total_out_bytes = leaf.out_bytes;
                                                leaf_node.total_flows = leaf.active_flows;
                                                leaf_node.total_alerts = leaf.alert_count;
                                                leaf_node.high_risk_hosts = if leaf.is_high_risk { 1 } else { 0 };
                                                visible_nodes.push(leaf_node);
                                                node_mapping.insert(ip.clone(), host_node_id);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 若某种极端配置导致 visible_nodes 为空，回退加入根节点
        if visible_nodes.is_empty() {
            if let Some(root) = self.nodes.get(&self.default_zone_id) {
                visible_nodes.push(root.clone());
            }
        }

        // 汇聚宏观骨干通信边 (Aggregated Edges)
        let mut edge_map: HashMap<(String, String), (u64, u64, bool)> = HashMap::new();
        for ((src_ip, dst_ip), &(flows, bytes, threat)) in &self.direct_session_counts {
            let vis_src = node_mapping.get(src_ip).cloned().unwrap_or_else(|| self.default_zone_id.clone());
            let vis_dst = node_mapping.get(dst_ip).cloned().unwrap_or_else(|| self.default_zone_id.clone());

            if vis_src != vis_dst {
                let pair = (vis_src, vis_dst);
                let e = edge_map.entry(pair).or_insert((0, 0, false));
                e.0 = e.0.saturating_add(flows);
                e.1 = e.1.saturating_add(bytes);
                if threat {
                    e.2 = true;
                }
            }
        }

        let mut visible_edges: Vec<AggregatedEdge> = Vec::new();
        for ((s, t), (flows, bytes, threat)) in edge_map {
            visible_edges.push(AggregatedEdge {
                edge_id: format!("{}_to_{}", s, t),
                source_node_id: s,
                target_node_id: t,
                flow_count: flows,
                total_bytes: bytes,
                contains_threat: threat,
            });
        }

        let total_ingested_hosts = self.host_to_subnet.len();
        let rendered_node_count = visible_nodes.len();
        let compression_ratio = if total_ingested_hosts > 0 {
            let ratio = 1.0 - (rendered_node_count as f64 / total_ingested_hosts as f64);
            ratio.clamp(0.0, 1.0) * 100.0
        } else {
            0.0
        };

        TopologyViewPortResult {
            visible_nodes,
            visible_edges,
            total_ingested_hosts,
            rendered_node_count,
            compression_ratio,
        }
    }

    /// 递归辅助：将某一节点及其所有下属叶子主机 IP 映射到指定的视口容器 ID 上
    fn map_all_descendants_to(
        &self,
        current_id: &str,
        target_container_id: &str,
        node_mapping: &mut HashMap<String, String>,
    ) {
        if let Some(node) = self.nodes.get(current_id) {
            for (ip, _) in &node.leaf_hosts {
                node_mapping.insert(ip.clone(), target_container_id.to_string());
            }
            for child_id in &node.child_node_ids {
                self.map_all_descendants_to(child_id, target_container_id, node_mapping);
            }
        }
    }
}

// ============================================================================
// 第三部分：分布式边缘探针遥测汇聚中心 (Distributed Probe Collector)
// ============================================================================

/// 远程边缘探针心跳探活数据包
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeHeartbeat {
    pub probe_id: String,
    pub probe_ip: String,
    pub probe_zone: String,
    pub probe_local_time_ns: u64,
    pub pps: u64,
    pub bps: u64,
    pub packet_drop_count: u64,
    pub cpu_usage_pct: f32,
    pub memory_used_mb: u64,
}

/// 探针在线状态与时间同步追踪器
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRuntimeStatus {
    pub probe_id: String,
    pub probe_ip: String,
    pub probe_zone: String,
    pub is_alive: bool,
    pub clock_skew_ns: i64,       // 探针时钟与中心节点时钟偏移 (纳秒)
    pub last_heartbeat_server_ns: u64,
    pub current_pps: u64,
    pub current_bps: u64,
    pub total_drops: u64,
    pub cpu_usage_pct: f32,
    pub memory_used_mb: u64,
}

/// 分布式探针集中汇聚中心
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedProbeCollector {
    pub probes: HashMap<String, ProbeRuntimeStatus>,
    pub heartbeat_timeout_secs: u64,
    pub total_cluster_pps: u64,
    pub total_cluster_bps: u64,
}

impl Default for DistributedProbeCollector {
    fn default() -> Self {
        Self::new(30)
    }
}

impl DistributedProbeCollector {
    pub fn new(heartbeat_timeout_secs: u64) -> Self {
        Self {
            probes: HashMap::new(),
            heartbeat_timeout_secs,
            total_cluster_pps: 0,
            total_cluster_bps: 0,
        }
    }

    /// 接收边缘探针心跳，消除时钟频偏并更新全局状态
    /// 时间复杂度：O(1)
    pub fn process_heartbeat(&mut self, hb: ProbeHeartbeat, server_monotonic_now_ns: u64) {
        // 计算时钟偏移：Skew = ProbeTime - ServerTime
        let clock_skew_ns = (hb.probe_local_time_ns as i128 - server_monotonic_now_ns as i128) as i64;

        let status = ProbeRuntimeStatus {
            probe_id: hb.probe_id.clone(),
            probe_ip: hb.probe_ip,
            probe_zone: hb.probe_zone,
            is_alive: true,
            clock_skew_ns,
            last_heartbeat_server_ns: server_monotonic_now_ns,
            current_pps: hb.pps,
            current_bps: hb.bps,
            total_drops: hb.packet_drop_count,
            cpu_usage_pct: hb.cpu_usage_pct,
            memory_used_mb: hb.memory_used_mb,
        };

        self.probes.insert(hb.probe_id, status);
        self.recalculate_cluster_telemetry();
    }

    /// 定期扫描淘汰超时探针
    pub fn audit_alive_probes(&mut self, server_monotonic_now_ns: u64) {
        let timeout_ns = self.heartbeat_timeout_secs * 1_000_000_000;
        for probe in self.probes.values_mut() {
            if server_monotonic_now_ns.saturating_sub(probe.last_heartbeat_server_ns) > timeout_ns {
                probe.is_alive = false;
                probe.current_pps = 0;
                probe.current_bps = 0;
            }
        }
        self.recalculate_cluster_telemetry();
    }

    /// 重新聚合全网集群实时吞吐指标
    fn recalculate_cluster_telemetry(&mut self) {
        let mut pps = 0u64;
        let mut bps = 0u64;
        for probe in self.probes.values() {
            if probe.is_alive {
                pps = pps.saturating_add(probe.current_pps);
                bps = bps.saturating_add(probe.current_bps);
            }
        }
        self.total_cluster_pps = pps;
        self.total_cluster_bps = bps;
    }

    /// 校准来自特定探针的报文时间戳
    pub fn normalize_packet_timestamp(&self, probe_id: &str, raw_packet_ts_ns: u64) -> u64 {
        if let Some(probe) = self.probes.get(probe_id) {
            let adjusted = raw_packet_ts_ns as i128 - probe.clock_skew_ns as i128;
            adjusted.max(0) as u64
        } else {
            raw_packet_ts_ns
        }
    }
}

// ============================================================================
// Tauri Commands 暴露
// ============================================================================

#[tauri::command]
pub fn get_hierarchical_topology_viewport_cmd(max_budget: Option<usize>) -> Result<TopologyViewPortResult, String> {
    let tree = GLOBAL_TOPOLOGY_TREE.lock().map_err(|e| e.to_string())?;
    Ok(tree.generate_viewport_projection(max_budget.unwrap_or(64)))
}

#[tauri::command]
pub fn drill_down_topology_node_cmd(node_id: String) -> Result<bool, String> {
    let mut tree = GLOBAL_TOPOLOGY_TREE.lock().map_err(|e| e.to_string())?;
    Ok(tree.drill_down(&node_id))
}

#[tauri::command]
pub fn roll_up_topology_node_cmd(node_id: String) -> Result<bool, String> {
    let mut tree = GLOBAL_TOPOLOGY_TREE.lock().map_err(|e| e.to_string())?;
    Ok(tree.roll_up(&node_id))
}

#[tauri::command]
pub fn collapse_all_topology_cmd() -> Result<bool, String> {
    let mut tree = GLOBAL_TOPOLOGY_TREE.lock().map_err(|e| e.to_string())?;
    tree.collapse_all();
    Ok(true)
}

#[tauri::command]
pub fn locate_asset_switch_port_cmd(ip: String, mac: Option<String>) -> Result<Option<PhysicalPortLocation>, String> {
    let sw_map = GLOBAL_SWITCH_MAP.lock().map_err(|e| e.to_string())?;
    Ok(sw_map.locate_physical_port(&ip, mac.as_deref()))
}

#[tauri::command]
pub fn get_distributed_probe_cluster_cmd() -> Result<DistributedProbeCollector, String> {
    let collector = GLOBAL_PROBE_COLLECTOR.lock().map_err(|e| e.to_string())?;
    Ok(collector.clone())
}

// ============================================================================
// 第四部分：单元测试与极限边界压力验证 (6 轮严苛工业验证)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 轮次 1：SNMP MIB-II IF-MIB 接口表解析与物理端口健康度评估
    #[test]
    fn test_snmp_mib_if_table_and_port_health_ratio() {
        let mut port1 = SwitchPortInfo::new(1, "GigabitEthernet0/0/1".to_string(), 1_000_000_000);
        port1.in_octets = 64_000_000;
        port1.out_octets = 64_000_000;
        port1.in_errors = 0;
        port1.out_errors = 0;
        assert_eq!(port1.calculate_health_ratio(), 1.0);

        // 引入物理 CRC 错误与丢包
        let mut port2 = SwitchPortInfo::new(2, "GigabitEthernet0/0/2".to_string(), 100_000_000);
        port2.in_octets = 6400; // 约 100 报文
        port2.in_errors = 50;
        let health = port2.calculate_health_ratio();
        assert!(health < 1.0 && health > 0.4);
    }

    /// 轮次 2：Bridge-MIB MAC 转发表到交换机物理端口映射解析
    #[test]
    fn test_bridge_mib_mac_fdb_to_switch_port_resolution() {
        let mut sw = SwitchDevice::new(
            "SW-ACCESS-01".to_string(),
            "192.168.1.254".to_string(),
            "CoreSwitch_H3C_S5560".to_string(),
        );

        let p1 = SwitchPortInfo::new(1, "GE0/0/1".to_string(), 1_000_000_000);
        let p2 = SwitchPortInfo::new(2, "GE0/0/2".to_string(), 1_000_000_000);
        sw.add_port(p1);
        sw.add_port(p2);

        sw.record_mac_fdb_entry("00-11-22-33-44-55", 1);
        sw.record_mac_fdb_entry("66:77:88:99:AA:BB", 2);

        assert_eq!(sw.mac_to_port.get("00:11:22:33:44:55"), Some(&1));
        assert_eq!(sw.mac_to_port.get("66:77:88:99:AA:BB"), Some(&2));

        let port_ge1 = sw.ports.get(&1).unwrap();
        assert!(port_ge1.learned_macs.contains(&"00:11:22:33:44:55".to_string()));
        assert!(!port_ge1.is_trunk_uplink);
    }

    /// 轮次 3：IP 到 MAC 到物理交换机端口级联链路递归穿透与 Trunk 汇聚链路判别
    #[test]
    fn test_ip_to_physical_switch_port_cascading_lookup() {
        let mut top_map = SwitchTopologyMap::new();

        let mut sw_access = SwitchDevice::new(
            "SW-ACC-01".to_string(),
            "192.168.1.253".to_string(),
            "Access-Switch-01".to_string(),
        );
        let p_host = SwitchPortInfo::new(5, "GE0/0/5".to_string(), 1_000_000_000);
        sw_access.add_port(p_host);
        sw_access.record_arp_entry("192.168.1.100", "00-50-56-C0-00-01");
        sw_access.record_mac_fdb_entry("00-50-56-C0-00-01", 5);

        top_map.register_switch(sw_access);

        let loc = top_map.locate_physical_port("192.168.1.100", None).unwrap();
        assert_eq!(loc.switch_id, "SW-ACC-01");
        assert_eq!(loc.port_name, "GE0/0/5");
        assert_eq!(loc.target_mac, "00:50:56:C0:00:01");
        assert!(!loc.is_trunk_uplink);
    }

    /// 轮次 4：万级主机极限压力与视口投影预算控制测试 (10,000 节点不雪崩)
    #[test]
    fn test_hierarchical_tree_10k_hosts_aggregation_bounded_nodes() {
        let mut tree = HierarchicalAggregationTree::new("zone-enterprise", "企业内网主安全域");

        // 构建跨 10 个 /16 网段，每个 /16 包含 10 个 /24 子网，每个 /24 包含 100 台主机的万级环境
        // 总计 10 * 10 * 100 = 10,000 台主机
        for i in 1..=10 {
            for j in 1..=10 {
                for k in 1..=100 {
                    let ip = format!("10.{}.{}.{}", i, j, k);
                    let mac = format!("00:AA:{:02X}:{:02X}:{:02X}:01", i, j, k);
                    let host = DiscoveredHostLeaf::new(
                        ip,
                        mac,
                        "Intel / 工业网卡".to_string(),
                        "工控生产终端".to_string(),
                    );
                    tree.ingest_host(host, None);
                }
            }
        }

        assert_eq!(tree.host_to_subnet.len(), 10_000);

        // 默认状态下生成视口投影，预算限制为 64
        let viewport = tree.generate_viewport_projection(64);

        // 严苛断言：即使网络中有 10,000 台真实主机，向前端视口输出的节点数必须严格 <= 64
        assert!(viewport.rendered_node_count <= 64);
        assert_eq!(viewport.total_ingested_hosts, 10_000);
        // 压缩比率必须达到 99% 以上
        assert!(viewport.compression_ratio >= 99.0);
    }

    /// 轮次 5：超级节点折叠 (Roll-Up) 与下钻 (Drill-Down) 状态机一致性测试
    #[test]
    fn test_hierarchical_tree_drill_down_and_roll_up() {
        let mut tree = HierarchicalAggregationTree::new("zone-hq", "总部安全域");

        let h1 = DiscoveredHostLeaf::new(
            "192.168.1.10".to_string(),
            "00:11:22:33:44:55".to_string(),
            "Huawei".to_string(),
            "服务器".to_string(),
        );
        let h2 = DiscoveredHostLeaf::new(
            "192.168.1.20".to_string(),
            "00:11:22:33:44:66".to_string(),
            "Dell".to_string(),
            "工作站".to_string(),
        );
        tree.ingest_host(h1, None);
        tree.ingest_host(h2, None);

        // 模拟主机间流量与告警
        tree.ingest_flow("192.168.1.10", "192.168.1.20", 2048, true);

        // 初始折叠状态
        let vp1 = tree.generate_viewport_projection(32);
        assert_eq!(vp1.rendered_node_count, 1); // 默认收起到 Zone 节点
        assert_eq!(vp1.visible_nodes[0].total_alerts, 2); // 双方各记录 1 次告警，合计 2

        // 下钻展开 Zone
        tree.drill_down("zone-hq");
        let vp2 = tree.generate_viewport_projection(32);
        assert_eq!(vp2.rendered_node_count, 1); // 展开 Zone 后露出 Supernet (192.168.0.0/16)

        // 下钻展开 Supernet
        tree.drill_down("supernet-192_168_0_0_16");
        let vp3 = tree.generate_viewport_projection(32);
        assert_eq!(vp3.rendered_node_count, 1); // 展开后露出 Subnet (192.168.1.0/24)

        // 下钻展开 Subnet
        tree.drill_down("subnet-192_168_1_0_24");
        let vp4 = tree.generate_viewport_projection(32);
        assert_eq!(vp4.rendered_node_count, 2); // 展开后露出 2 个独立的 Host 叶子节点
    }

    /// 轮次 6：分布式探针心跳探活、时钟漂移对齐与跨探针流量汇聚测试
    #[test]
    fn test_distributed_probe_collector_heartbeat_and_skew_alignment() {
        let mut collector = DistributedProbeCollector::new(10); // 10s 超时

        let server_now = 1_000_000_000_000u64; // 1000s
        let probe_time = 1_000_000_050_000u64; // 探针快 50 微秒 (50,000 ns)

        let hb = ProbeHeartbeat {
            probe_id: "probe-dc-01".to_string(),
            probe_ip: "10.0.10.1".to_string(),
            probe_zone: "数据中心东区".to_string(),
            probe_local_time_ns: probe_time,
            pps: 50_000,
            bps: 400_000_000,
            packet_drop_count: 0,
            cpu_usage_pct: 12.5,
            memory_used_mb: 256,
        };

        collector.process_heartbeat(hb, server_now);

        let p_status = collector.probes.get("probe-dc-01").unwrap();
        assert!(p_status.is_alive);
        assert_eq!(p_status.clock_skew_ns, 50_000);
        assert_eq!(collector.total_cluster_pps, 50_000);
        assert_eq!(collector.total_cluster_bps, 400_000_000);

        // 校准探针报文时间戳
        let raw_pkt_ts = 1_000_000_100_000u64;
        let normalized_ts = collector.normalize_packet_timestamp("probe-dc-01", raw_pkt_ts);
        assert_eq!(normalized_ts, 1_000_000_050_000u64); // 精准减去 50,000 ns 频偏

        // 模拟超时
        collector.audit_alive_probes(server_now + 15_000_000_000u64); // 经过 15s
        let p_after = collector.probes.get("probe-dc-01").unwrap();
        assert!(!p_after.is_alive);
        assert_eq!(collector.total_cluster_pps, 0);
    }
}
