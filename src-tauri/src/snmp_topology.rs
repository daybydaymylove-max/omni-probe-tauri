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
pub fn list_registered_switches_cmd() -> Result<Vec<SwitchDevice>, String> {
    let sw_map = GLOBAL_SWITCH_MAP.lock().map_err(|e| e.to_string())?;
    Ok(sw_map.switches.values().cloned().collect())
}

#[tauri::command]
pub fn get_distributed_probe_cluster_cmd() -> Result<DistributedProbeCollector, String> {
    refresh_local_probe_heartbeat();
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut collector = GLOBAL_PROBE_COLLECTOR.lock().map_err(|e| e.to_string())?;
    collector.audit_alive_probes(now_ns);
    Ok(collector.clone())
}

/// 将本机主探针实时吞吐与内存状况写入全局集群聚合中心
pub fn refresh_local_probe_heartbeat() {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let (local_ip, _) = crate::sniffer::get_local_identity();
    let pkts = crate::sniffer::GLOBAL_PACKETS_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
    let bytes = crate::sniffer::GLOBAL_BYTES_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
    let zc = crate::zero_copy_pool::get_runtime_zero_copy_telemetry();
    let hb = ProbeHeartbeat {
        probe_id: format!("local-probe-{}", local_ip),
        probe_ip: local_ip,
        probe_zone: "本机主引擎 (Local Host)".to_string(),
        probe_local_time_ns: now_ns,
        pps: pkts,
        bps: bytes * 8,
        packet_drop_count: zc.ring_drops_total + zc.pool_exhaustion_drops,
        cpu_usage_pct: 0.0,
        memory_used_mb: (zc.pool_total_memory_bytes / (1024 * 1024)) as u64,
    };
    if let Ok(mut collector) = GLOBAL_PROBE_COLLECTOR.lock() {
        collector.process_heartbeat(hb, now_ns);
    }
}

// ============================================================================
// 原生 RFC 1157 / 3416 ASN.1 BER SNMPv2c UDP 客户端（真实交换机 MIB-II & Bridge-MIB 采集）
// ============================================================================

const MAX_SNMP_WALK_STEPS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpBerValue {
    Integer(i64),
    OctetString(Vec<u8>),
    ObjectIdentifier(Vec<u32>),
    Null,
    EndOfMibView,
    Other(u8, Vec<u8>),
}

fn push_ber_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
    }
}

fn wrap_tlv(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.push(tag);
    push_ber_len(&mut out, payload.len());
    out.extend_from_slice(payload);
    out
}

pub fn encode_ber_integer(val: i32) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let mut start = 0usize;
    while start < 3 {
        let sign_ext = if (bytes[start + 1] & 0x80) != 0 { 0xFF } else { 0x00 };
        if bytes[start] == sign_ext && ((val >= 0 && bytes[start] == 0) || (val < 0 && bytes[start] == 0xFF)) {
            start += 1;
        } else {
            break;
        }
    }
    wrap_tlv(0x02, &bytes[start..])
}

pub fn encode_ber_oid(oid: &[u32]) -> Vec<u8> {
    if oid.len() < 2 {
        return wrap_tlv(0x06, &[0]);
    }
    let mut body = Vec::with_capacity(oid.len() * 2);
    body.push((oid[0].saturating_mul(40).saturating_add(oid[1])) as u8);
    for &sub in &oid[2..] {
        if sub < 0x80 {
            body.push(sub as u8);
        } else {
            let mut tmp = [0u8; 5];
            let mut n = sub;
            let mut idx = 5usize;
            while n > 0 || idx == 5 {
                idx -= 1;
                tmp[idx] = (n & 0x7F) as u8;
                if idx < 4 {
                    tmp[idx] |= 0x80;
                }
                n >>= 7;
            }
            body.extend_from_slice(&tmp[idx..]);
        }
    }
    wrap_tlv(0x06, &body)
}

/// 构造 SNMPv2c GetRequest (0xA0) / GetNextRequest (0xA1) 报文
pub fn encode_snmp_v2c_pdu(community: &str, req_id: i32, pdu_tag: u8, oid: &[u32]) -> Vec<u8> {
    let oid_tlv = encode_ber_oid(oid);
    let null_tlv = vec![0x05, 0x00];
    let mut varbind_inner = oid_tlv;
    varbind_inner.extend_from_slice(&null_tlv);
    let varbind = wrap_tlv(0x30, &varbind_inner);
    let varbind_list = wrap_tlv(0x30, &varbind);

    let mut pdu_inner = encode_ber_integer(req_id);
    pdu_inner.extend_from_slice(&encode_ber_integer(0)); // error-status
    pdu_inner.extend_from_slice(&encode_ber_integer(0)); // error-index
    pdu_inner.extend_from_slice(&varbind_list);
    let pdu = wrap_tlv(pdu_tag, &pdu_inner);

    let mut msg_inner = encode_ber_integer(1); // version: SNMPv2c (1)
    msg_inner.extend_from_slice(&wrap_tlv(0x04, community.as_bytes()));
    msg_inner.extend_from_slice(&pdu);
    wrap_tlv(0x30, &msg_inner)
}

fn read_tlv(data: &[u8], off: usize) -> Result<(u8, &[u8], usize), String> {
    if off + 2 > data.len() {
        return Err("SNMP BER 报文长度截断".to_string());
    }
    let tag = data[off];
    let len_b = data[off + 1];
    let (val_len, val_start) = if (len_b & 0x80) == 0 {
        (len_b as usize, off + 2)
    } else {
        let num_bytes = (len_b & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || off + 2 + num_bytes > data.len() {
            return Err("SNMP BER 非法长长度字段".to_string());
        }
        let mut l = 0usize;
        for b in &data[off + 2..off + 2 + num_bytes] {
            l = (l << 8) | (*b as usize);
        }
        (l, off + 2 + num_bytes)
    };
    let val_end = val_start.checked_add(val_len).ok_or_else(|| "SNMP BER 长度溢出".to_string())?;
    if val_end > data.len() {
        return Err("SNMP BER 载荷越界".to_string());
    }
    Ok((tag, &data[val_start..val_end], val_end))
}

fn decode_ber_oid(raw: &[u8]) -> Vec<u32> {
    if raw.is_empty() {
        return Vec::new();
    }
    let mut oid = Vec::with_capacity(raw.len() + 1);
    let first = raw[0] as u32;
    oid.push((first / 40).min(2));
    oid.push(first - oid[0] * 40);
    let mut cur = 0u32;
    for &b in &raw[1..] {
        cur = (cur << 7) | ((b & 0x7F) as u32);
        if (b & 0x80) == 0 {
            oid.push(cur);
            cur = 0;
        }
    }
    oid
}

fn decode_ber_integer(raw: &[u8], unsigned: bool) -> i64 {
    if raw.is_empty() {
        return 0;
    }
    let mut val: i64 = if !unsigned && (raw[0] & 0x80) != 0 { -1 } else { 0 };
    for &b in raw.iter().take(8) {
        val = (val << 8) | (b as i64);
    }
    val
}

pub fn decode_snmp_v2c_response(buf: &[u8]) -> Result<(i32, i32, Vec<(Vec<u32>, SnmpBerValue)>), String> {
    let (tag, msg_body, _) = read_tlv(buf, 0)?;
    if tag != 0x30 {
        return Err("非法 SNMP 顶层 Sequence".to_string());
    }
    let (_, _, p1) = read_tlv(msg_body, 0)?; // version
    let (_, _, p2) = read_tlv(msg_body, p1)?; // community
    let (pdu_tag, pdu_body, _) = read_tlv(msg_body, p2)?;
    if !matches!(pdu_tag, 0xA2 | 0xA0 | 0xA1) {
        return Err(format!("非预期 SNMP PDU 类型: 0x{:02X}", pdu_tag));
    }
    let (_, req_b, q1) = read_tlv(pdu_body, 0)?;
    let (_, err_b, q2) = read_tlv(pdu_body, q1)?;
    let (_, _, q3) = read_tlv(pdu_body, q2)?; // error-index
    let req_id = decode_ber_integer(req_b, false) as i32;
    let err_status = decode_ber_integer(err_b, false) as i32;

    let (_, vbl_body, _) = read_tlv(pdu_body, q3)?;
    let mut off = 0usize;
    let mut items = Vec::new();
    while off < vbl_body.len() {
        let (_, vb_body, next_off) = read_tlv(vbl_body, off)?;
        off = next_off;
        let (oid_tag, oid_raw, v1) = read_tlv(vb_body, 0)?;
        if oid_tag != 0x06 {
            continue;
        }
        let oid = decode_ber_oid(oid_raw);
        let (val_tag, val_raw, _) = read_tlv(vb_body, v1)?;
        let val = match val_tag {
            0x02 => SnmpBerValue::Integer(decode_ber_integer(val_raw, false)),
            0x41 | 0x42 | 0x43 | 0x46 => SnmpBerValue::Integer(decode_ber_integer(val_raw, true)),
            0x04 => SnmpBerValue::OctetString(val_raw.to_vec()),
            0x06 => SnmpBerValue::ObjectIdentifier(decode_ber_oid(val_raw)),
            0x05 => SnmpBerValue::Null,
            0x80..=0x82 => SnmpBerValue::EndOfMibView,
            other => SnmpBerValue::Other(other, val_raw.to_vec()),
        };
        items.push((oid, val));
    }
    Ok((req_id, err_status, items))
}

fn snmp_udp_exchange(
    sock: &std::net::UdpSocket,
    target: std::net::SocketAddr,
    community: &str,
    req_id: i32,
    pdu_tag: u8,
    oid: &[u32],
) -> Result<(Vec<u32>, SnmpBerValue), String> {
    let req_bytes = encode_snmp_v2c_pdu(community, req_id, pdu_tag, oid);
    sock.send_to(&req_bytes, target).map_err(|e| format!("SNMP UDP 发送失败: {}", e))?;
    let mut rx_buf = [0u8; 4096];
    let (n, _) = sock
        .recv_from(&mut rx_buf)
        .map_err(|e| format!("SNMP 目标 {} 无响应或超时: {}", target, e))?;
    let (_, err_st, items) = decode_snmp_v2c_response(&rx_buf[..n])?;
    if err_st != 0 {
        return Err(format!("SNMP Agent 返回错误状态码 errStatus={}", err_st));
    }
    items.into_iter().next().ok_or_else(|| "SNMP 响应缺少 VarBind".to_string())
}

trait SnmpExchangeClient {
    fn exchange(&mut self, req_id: i32, pdu_tag: u8, oid: &[u32]) -> Result<(Vec<u32>, SnmpBerValue), String>;
}

struct SnmpV2cClient<'a> {
    sock: &'a std::net::UdpSocket,
    target: std::net::SocketAddr,
    community: &'a str,
}

impl<'a> SnmpExchangeClient for SnmpV2cClient<'a> {
    fn exchange(&mut self, req_id: i32, pdu_tag: u8, oid: &[u32]) -> Result<(Vec<u32>, SnmpBerValue), String> {
        snmp_udp_exchange(self.sock, self.target, self.community, req_id, pdu_tag, oid)
    }
}

fn snmp_walk_with_client<C: SnmpExchangeClient>(
    client: &mut C,
    root_oid: &[u32],
    next_req_id: &mut i32,
) -> Vec<(Vec<u32>, SnmpBerValue)> {
    let mut rows = Vec::new();
    let mut cur_oid = root_oid.to_vec();
    for _ in 0..MAX_SNMP_WALK_STEPS {
        *next_req_id = next_req_id.wrapping_add(1);
        let Ok((ret_oid, val)) = client.exchange(*next_req_id, 0xA1, &cur_oid) else {
            break;
        };
        if !ret_oid.starts_with(root_oid) || ret_oid == cur_oid || matches!(val, SnmpBerValue::EndOfMibView) {
            break;
        }
        cur_oid = ret_oid.clone();
        rows.push((ret_oid, val));
    }
    rows
}

fn poll_snmp_tables_with_client<C: SnmpExchangeClient>(
    ip_str: &str,
    client: &mut C,
) -> Result<SwitchDevice, String> {
    let mut req_id = 100i32;
    let (_, sys_name_val) = client.exchange(req_id, 0xA0, &[1, 3, 6, 1, 2, 1, 1, 5, 0])?;
    let sys_name = match sys_name_val {
        SnmpBerValue::OctetString(b) => String::from_utf8_lossy(&b).trim().to_string(),
        _ => format!("Switch-{}", ip_str),
    };

    req_id += 1;
    let sys_descr = match client.exchange(req_id, 0xA0, &[1, 3, 6, 1, 2, 1, 1, 1, 0]) {
        Ok((_, SnmpBerValue::OctetString(b))) => String::from_utf8_lossy(&b).trim().to_string(),
        _ => String::new(),
    };

    let mut sw = SwitchDevice::new(
        format!("SW-{}", ip_str),
        ip_str.to_string(),
        if sys_name.is_empty() {
            format!("SW-{}", ip_str)
        } else {
            sys_name
        },
    );
    sw.sys_descr = sys_descr;

    // 1. 拉取 IF-MIB 接口名称、速率与入向错包 (1.3.6.1.2.1.2.2.1.2 & .5 & .14)
    let if_descr_root = [1, 3, 6, 1, 2, 1, 2, 2, 1, 2];
    let if_speed_root = [1, 3, 6, 1, 2, 1, 2, 2, 1, 5];
    let if_err_root = [1, 3, 6, 1, 2, 1, 2, 2, 1, 14];

    for (oid, val) in snmp_walk_with_client(client, &if_descr_root, &mut req_id) {
        if let (Some(&if_idx), SnmpBerValue::OctetString(bytes)) = (oid.last(), val) {
            let name = String::from_utf8_lossy(&bytes).trim().to_string();
            sw.add_port(SwitchPortInfo::new(if_idx, name, 1_000_000_000));
        }
    }
    for (oid, val) in snmp_walk_with_client(client, &if_speed_root, &mut req_id) {
        if let (Some(&if_idx), SnmpBerValue::Integer(spd)) = (oid.last(), val) {
            if let Some(p) = sw.ports.get_mut(&if_idx) {
                p.speed_bps = spd.max(0) as u64;
            }
        }
    }
    for (oid, val) in snmp_walk_with_client(client, &if_err_root, &mut req_id) {
        if let (Some(&if_idx), SnmpBerValue::Integer(errs)) = (oid.last(), val) {
            if let Some(p) = sw.ports.get_mut(&if_idx) {
                p.in_errors = errs.max(0) as u64;
            }
        }
    }

    // 2. 拉取 Bridge-MIB MAC 转发表 (1.3.6.1.2.1.17.4.3.1.2.<6 MAC bytes> -> BridgePort)
    let fdb_root = [1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2];
    for (oid, val) in snmp_walk_with_client(client, &fdb_root, &mut req_id) {
        if oid.len() >= fdb_root.len() + 6 {
            if let SnmpBerValue::Integer(port_num) = val {
                let tail = &oid[oid.len() - 6..];
                let mac_str = format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    tail[0], tail[1], tail[2], tail[3], tail[4], tail[5]
                );
                let if_idx = port_num.max(1) as u32;
                sw.ports
                    .entry(if_idx)
                    .or_insert_with(|| SwitchPortInfo::new(if_idx, format!("Port-{}", if_idx), 1_000_000_000));
                sw.record_mac_fdb_entry(&mac_str, if_idx);
            }
        }
    }

    // 3. 拉取 IP-MIB ARP 表 (1.3.6.1.2.1.4.22.1.2.<ifIdx>.<4 IP bytes> -> 6B MAC)
    let arp_root = [1, 3, 6, 1, 2, 1, 4, 22, 1, 2];
    for (oid, val) in snmp_walk_with_client(client, &arp_root, &mut req_id) {
        if oid.len() >= arp_root.len() + 4 {
            if let SnmpBerValue::OctetString(mac_bytes) = val {
                if mac_bytes.len() == 6 {
                    let ip_t = &oid[oid.len() - 4..];
                    let ip_str = format!("{}.{}.{}.{}", ip_t[0], ip_t[1], ip_t[2], ip_t[3]);
                    let mac_str = format!(
                        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
                    );
                    sw.record_arp_entry(&ip_str, &mac_str);
                }
            }
        }
    }

    if let Ok(mut map) = GLOBAL_SWITCH_MAP.lock() {
        map.register_switch(sw.clone());
    }
    Ok(sw)
}

/// 通过标准 SNMPv2c UDP 协议真实轮询交换机 MIB-II 与 Bridge-MIB 并写入 `GLOBAL_SWITCH_MAP`
pub fn poll_snmp_switch_core(
    switch_ip: &str,
    community: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<SwitchDevice, String> {
    let ip: std::net::IpAddr = switch_ip
        .trim()
        .parse()
        .map_err(|_| format!("非法交换机管理 IP: {}", switch_ip))?;
    let target = std::net::SocketAddr::new(ip, port);
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("创建 UDP 套接字失败: {}", e))?;
    let _ = sock.set_read_timeout(Some(std::time::Duration::from_millis(timeout_ms.clamp(200, 5000))));

    let mut client = SnmpV2cClient {
        sock: &sock,
        target,
        community,
    };
    poll_snmp_tables_with_client(&ip.to_string(), &mut client)
}

#[tauri::command]
pub async fn poll_snmp_switch_cmd(
    switch_ip: String,
    community: Option<String>,
    port: Option<u16>,
) -> Result<SwitchDevice, String> {
    let comm = community.unwrap_or_else(|| "public".to_string());
    let p = port.unwrap_or(161);
    tokio::task::spawn_blocking(move || poll_snmp_switch_core(&switch_ip, &comm, p, 1200))
        .await
        .map_err(|e| format!("SNMP 异步任务异常: {}", e))?
}

// ============================================================================
// 第三部分(B)：RFC 3414 / RFC 3826 / RFC 7860 SNMPv3 USM 安全鉴权与加密采集引擎
// 支持 noAuthNoPriv / authNoPriv (MD5, SHA-1, SHA-256) / authPriv (AES-128-CFB)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnmpV3AuthAlgo {
    None,
    Md5,
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnmpV3PrivAlgo {
    None,
    Aes128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpV3Credentials {
    pub username: String,
    pub auth_algo: SnmpV3AuthAlgo,
    pub auth_password: String,
    pub priv_algo: SnmpV3PrivAlgo,
    pub priv_password: String,
}

/// 纯 Rust RFC 1321 MD5 摘要实现 (无额外 crate 依赖)
pub fn rfc1321_md5(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]).rotate_left(S[i]));
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// 纯 Rust RFC 3174 SHA-1 摘要实现 (无额外 crate 依赖)
pub fn rfc3174_sha1(input: &[u8]) -> [u8; 20] {
    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, val) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

fn digest_by_algo(algo: SnmpV3AuthAlgo, data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    match algo {
        SnmpV3AuthAlgo::None => Vec::new(),
        SnmpV3AuthAlgo::Md5 => rfc1321_md5(data).to_vec(),
        SnmpV3AuthAlgo::Sha1 => rfc3174_sha1(data).to_vec(),
        SnmpV3AuthAlgo::Sha256 => sha2::Sha256::digest(data).to_vec(),
    }
}

fn hmac_by_algo(algo: SnmpV3AuthAlgo, key: &[u8], data: &[u8]) -> Vec<u8> {
    let block_size = 64usize;
    let k_norm = if key.len() > block_size {
        digest_by_algo(algo, key)
    } else {
        key.to_vec()
    };
    let mut ipad = vec![0x36u8; block_size];
    let mut opad = vec![0x5Cu8; block_size];
    for (i, &b) in k_norm.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    ipad.extend_from_slice(data);
    let inner = digest_by_algo(algo, &ipad);
    opad.extend_from_slice(&inner);
    digest_by_algo(algo, &opad)
}

fn auth_mac_len(algo: SnmpV3AuthAlgo) -> usize {
    match algo {
        SnmpV3AuthAlgo::None => 0,
        SnmpV3AuthAlgo::Md5 | SnmpV3AuthAlgo::Sha1 => 12,
        SnmpV3AuthAlgo::Sha256 => 24, // RFC 7860 usmHMAC192SHA256AuthProtocol
    }
}

/// RFC 3414 Appendix A.2 SNMPv3 密钥本地化算法 (`Password -> Ku -> Kul`)
/// 时间复杂度: O(1) 常数 1MB 扩展, 空间复杂度: O(1)
pub fn snmpv3_password_to_key(algo: SnmpV3AuthAlgo, password: &str, engine_id: &[u8]) -> Vec<u8> {
    if algo == SnmpV3AuthAlgo::None || password.is_empty() {
        return Vec::new();
    }
    let pw = password.as_bytes();
    let mut buf = Vec::with_capacity(1_048_576);
    while buf.len() < 1_048_576 {
        let take = (1_048_576 - buf.len()).min(pw.len());
        buf.extend_from_slice(&pw[..take]);
    }
    let ku = digest_by_algo(algo, &buf);
    let mut localize_input = Vec::with_capacity(ku.len() * 2 + engine_id.len());
    localize_input.extend_from_slice(&ku);
    localize_input.extend_from_slice(engine_id);
    localize_input.extend_from_slice(&ku);
    digest_by_algo(algo, &localize_input)
}

/// RFC 3826 SNMPv3 AES-128-CFB 加解密（使用本地已有的 `aes::Aes128`，零外部 CFB crate 依赖）
pub fn snmpv3_aes128_cfb_crypt(
    priv_key_16: &[u8],
    engine_boots: i32,
    engine_time: i32,
    salt_8: &[u8; 8],
    data: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, String> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes128;

    if priv_key_16.len() < 16 {
        return Err("SNMPv3 AES-128 密钥长度不足 16 字节".into());
    }
    let cipher = Aes128::new_from_slice(&priv_key_16[..16]).map_err(|e| format!("初始化 AES-128 失败: {}", e))?;

    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
    iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
    iv[8..16].copy_from_slice(salt_8);

    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = aes::Block::clone_from_slice(&iv);
        cipher.encrypt_block(&mut block);
        let mut c_block = [0u8; 16];
        for i in 0..chunk.len() {
            let out_b = chunk[i] ^ block[i];
            out.push(out_b);
            c_block[i] = if encrypt { out_b } else { chunk[i] };
        }
        iv = c_block;
    }
    Ok(out)
}

#[derive(Debug, Clone)]
struct SnmpV3MessageDecoded {
    msg_flags: u8,
    engine_id: Vec<u8>,
    engine_boots: i32,
    engine_time: i32,
    _username: Vec<u8>,
    auth_params: Vec<u8>,
    priv_params: Vec<u8>,
    auth_params_offset_in_msg: Option<(usize, usize)>,
    raw_scoped_pdu: Vec<u8>,
    encrypted_scoped_pdu: bool,
}

#[allow(clippy::too_many_arguments)]
fn encode_snmpv3_message(
    msg_id: i32,
    msg_flags: u8,
    engine_id: &[u8],
    engine_boots: i32,
    engine_time: i32,
    username: &str,
    auth_algo: SnmpV3AuthAlgo,
    auth_key: &[u8],
    priv_params: &[u8],
    scoped_pdu_or_cipher: &[u8],
    is_encrypted: bool,
) -> Vec<u8> {
    // msgGlobalData
    let mut gd = encode_ber_integer(msg_id);
    gd.extend_from_slice(&encode_ber_integer(65507));
    gd.extend_from_slice(&wrap_tlv(0x04, &[msg_flags]));
    gd.extend_from_slice(&encode_ber_integer(3)); // USM (3)
    let global_data = wrap_tlv(0x30, &gd);

    let mac_len = if (msg_flags & 0x01) != 0 && auth_algo != SnmpV3AuthAlgo::None {
        auth_mac_len(auth_algo)
    } else {
        0
    };
    let zero_auth_params = vec![0u8; mac_len];

    // UsmSecurityParameters Sequence -> OctetString
    let mut usm = wrap_tlv(0x04, engine_id);
    usm.extend_from_slice(&encode_ber_integer(engine_boots));
    usm.extend_from_slice(&encode_ber_integer(engine_time));
    usm.extend_from_slice(&wrap_tlv(0x04, username.as_bytes()));
    let auth_tlv = wrap_tlv(0x04, &zero_auth_params);
    usm.extend_from_slice(&auth_tlv);
    usm.extend_from_slice(&wrap_tlv(0x04, priv_params));
    let usm_seq = wrap_tlv(0x30, &usm);
    let sec_params_tlv = wrap_tlv(0x04, &usm_seq);

    let scoped_part = if is_encrypted {
        wrap_tlv(0x04, scoped_pdu_or_cipher)
    } else {
        scoped_pdu_or_cipher.to_vec()
    };

    let mut body = encode_ber_integer(3); // SNMPv3 (3)
    body.extend_from_slice(&global_data);
    body.extend_from_slice(&sec_params_tlv);
    body.extend_from_slice(&scoped_part);
    let mut full_msg = wrap_tlv(0x30, &body);

    if mac_len > 0 && !auth_key.is_empty() {
        let mac = hmac_by_algo(auth_algo, auth_key, &full_msg);
        // 定位 zero_auth_params 在 full_msg 中的精确位置（紧跟 username TLV 之后）
        let decoded = decode_snmpv3_message(&full_msg).ok();
        if let Some(d) = decoded {
            if let Some((start, len)) = d.auth_params_offset_in_msg {
                if len == mac_len && mac.len() >= mac_len {
                    full_msg[start..start + len].copy_from_slice(&mac[..len]);
                }
            }
        }
    }
    full_msg
}

fn decode_snmpv3_message(buf: &[u8]) -> Result<SnmpV3MessageDecoded, String> {
    let (tag, msg_body, _) = read_tlv(buf, 0)?;
    if tag != 0x30 {
        return Err("非法 SNMPv3 顶层 Sequence".into());
    }
    let msg_body_abs = buf.len() - msg_body.len();
    let (_, ver_b, p1) = read_tlv(msg_body, 0)?;
    if decode_ber_integer(ver_b, false) != 3 {
        return Err("非 SNMPv3 版本报文".into());
    }
    let (_, gd_b, p2) = read_tlv(msg_body, p1)?;
    // msgGlobalData: msgID, msgMaxSize, msgFlags, msgSecurityModel
    let (_, _, g1) = read_tlv(gd_b, 0)?;
    let (_, _, g2) = read_tlv(gd_b, g1)?;
    let (_, flags_b, _) = read_tlv(gd_b, g2)?;
    let msg_flags = flags_b.first().copied().unwrap_or(0);

    let (_, sec_octets, p3) = read_tlv(msg_body, p2)?;
    let sec_octets_abs = msg_body_abs + (p2 + (sec_octets.as_ptr() as usize - msg_body[p2..].as_ptr() as usize));
    let (_, usm_body, _) = read_tlv(sec_octets, 0)?;
    let usm_abs = sec_octets_abs + (usm_body.as_ptr() as usize - sec_octets.as_ptr() as usize);

    let (_, eng_b, u1) = read_tlv(usm_body, 0)?;
    let (_, boots_b, u2) = read_tlv(usm_body, u1)?;
    let (_, time_b, u3) = read_tlv(usm_body, u2)?;
    let (_, user_b, u4) = read_tlv(usm_body, u3)?;
    let (_, auth_b, u5) = read_tlv(usm_body, u4)?;
    let (_, priv_b, _) = read_tlv(usm_body, u5)?;

    let auth_abs = if !auth_b.is_empty() {
        let off = usm_abs + (auth_b.as_ptr() as usize - usm_body.as_ptr() as usize);
        Some((off, auth_b.len()))
    } else {
        None
    };

    let (scoped_tag, scoped_val, _) = read_tlv(msg_body, p3)?;
    let (raw_scoped_pdu, encrypted_scoped_pdu) = if scoped_tag == 0x04 {
        (scoped_val.to_vec(), true)
    } else {
        (msg_body[p3..].to_vec(), false)
    };

    Ok(SnmpV3MessageDecoded {
        msg_flags,
        engine_id: eng_b.to_vec(),
        engine_boots: decode_ber_integer(boots_b, false) as i32,
        engine_time: decode_ber_integer(time_b, false) as i32,
        _username: user_b.to_vec(),
        auth_params: auth_b.to_vec(),
        priv_params: priv_b.to_vec(),
        auth_params_offset_in_msg: auth_abs,
        raw_scoped_pdu,
        encrypted_scoped_pdu,
    })
}

fn encode_scoped_pdu(engine_id: &[u8], req_id: i32, pdu_tag: u8, oid: &[u32]) -> Vec<u8> {
    let oid_tlv = encode_ber_oid(oid);
    let mut vb_inner = oid_tlv;
    vb_inner.extend_from_slice(&[0x05, 0x00]);
    let vbl = wrap_tlv(0x30, &wrap_tlv(0x30, &vb_inner));
    let mut pdu_inner = encode_ber_integer(req_id);
    pdu_inner.extend_from_slice(&encode_ber_integer(0));
    pdu_inner.extend_from_slice(&encode_ber_integer(0));
    pdu_inner.extend_from_slice(&vbl);
    let pdu = wrap_tlv(pdu_tag, &pdu_inner);

    let mut sp = wrap_tlv(0x04, engine_id);
    sp.extend_from_slice(&wrap_tlv(0x04, &[])); // contextName = ""
    sp.extend_from_slice(&pdu);
    wrap_tlv(0x30, &sp)
}

fn decode_scoped_pdu(raw_scoped: &[u8]) -> Result<(u8, i32, i32, Vec<(Vec<u32>, SnmpBerValue)>), String> {
    let (tag, sp_body, _) = read_tlv(raw_scoped, 0)?;
    if tag != 0x30 {
        return Err("非法 ScopedPDU Sequence".into());
    }
    let (_, _, s1) = read_tlv(sp_body, 0)?; // contextEngineID
    let (_, _, s2) = read_tlv(sp_body, s1)?; // contextName
    let (pdu_tag, pdu_body, _) = read_tlv(sp_body, s2)?;
    let (_, req_b, q1) = read_tlv(pdu_body, 0)?;
    let (_, err_b, q2) = read_tlv(pdu_body, q1)?;
    let (_, _, q3) = read_tlv(pdu_body, q2)?;
    let req_id = decode_ber_integer(req_b, false) as i32;
    let err_status = decode_ber_integer(err_b, false) as i32;
    let (_, vbl_body, _) = read_tlv(pdu_body, q3)?;
    let mut off = 0usize;
    let mut items = Vec::new();
    while off < vbl_body.len() {
        let (_, vb_body, next_off) = read_tlv(vbl_body, off)?;
        off = next_off;
        let (oid_tag, oid_raw, v1) = read_tlv(vb_body, 0)?;
        if oid_tag != 0x06 {
            continue;
        }
        let oid = decode_ber_oid(oid_raw);
        let (val_tag, val_raw, _) = read_tlv(vb_body, v1)?;
        let val = match val_tag {
            0x02 => SnmpBerValue::Integer(decode_ber_integer(val_raw, false)),
            0x41 | 0x42 | 0x43 | 0x46 => SnmpBerValue::Integer(decode_ber_integer(val_raw, true)),
            0x04 => SnmpBerValue::OctetString(val_raw.to_vec()),
            0x06 => SnmpBerValue::ObjectIdentifier(decode_ber_oid(val_raw)),
            0x05 => SnmpBerValue::Null,
            0x80..=0x82 => SnmpBerValue::EndOfMibView,
            other => SnmpBerValue::Other(other, val_raw.to_vec()),
        };
        items.push((oid, val));
    }
    Ok((pdu_tag, req_id, err_status, items))
}

struct SnmpV3Client<'a> {
    sock: &'a std::net::UdpSocket,
    target: std::net::SocketAddr,
    creds: &'a SnmpV3Credentials,
    engine_id: Vec<u8>,
    engine_boots: i32,
    engine_time: i32,
    auth_key: Vec<u8>,
    priv_key: Vec<u8>,
    msg_counter: i32,
    salt_counter: u64,
}

impl<'a> SnmpExchangeClient for SnmpV3Client<'a> {
    fn exchange(&mut self, req_id: i32, pdu_tag: u8, oid: &[u32]) -> Result<(Vec<u32>, SnmpBerValue), String> {
        self.msg_counter = self.msg_counter.wrapping_add(1);
        self.salt_counter = self.salt_counter.wrapping_add(1);
        let use_auth = self.creds.auth_algo != SnmpV3AuthAlgo::None;
        let use_priv = use_auth && self.creds.priv_algo == SnmpV3PrivAlgo::Aes128;
        let flags = 0x04 | if use_auth { 0x01 } else { 0 } | if use_priv { 0x02 } else { 0 };

        let scoped = encode_scoped_pdu(&self.engine_id, req_id, pdu_tag, oid);
        let (priv_params, scoped_or_cipher) = if use_priv {
            let salt = self.salt_counter.to_be_bytes();
            let enc = snmpv3_aes128_cfb_crypt(
                &self.priv_key,
                self.engine_boots,
                self.engine_time,
                &salt,
                &scoped,
                true,
            )?;
            (salt.to_vec(), enc)
        } else {
            (Vec::new(), scoped)
        };

        let pkt = encode_snmpv3_message(
            self.msg_counter,
            flags,
            &self.engine_id,
            self.engine_boots,
            self.engine_time,
            &self.creds.username,
            self.creds.auth_algo,
            &self.auth_key,
            &priv_params,
            &scoped_or_cipher,
            use_priv,
        );

        self.sock
            .send_to(&pkt, self.target)
            .map_err(|e| format!("SNMPv3 发送失败: {}", e))?;
        let mut rx = [0u8; 4096];
        let (n, _) = self
            .sock
            .recv_from(&mut rx)
            .map_err(|e| format!("SNMPv3 目标 {} 无响应或超时: {}", self.target, e))?;
        let raw_rx = &mut rx[..n];
        let dec = decode_snmpv3_message(raw_rx)?;
        self.engine_boots = dec.engine_boots;
        self.engine_time = dec.engine_time;

        // 若报文带 Auth Flag，校验响应 HMAC 防止被篡改或口令错配静默失败
        if use_auth && (dec.msg_flags & 0x01) != 0 {
            if let Some((start, len)) = dec.auth_params_offset_in_msg {
                let mut rx_copy = raw_rx.to_vec();
                rx_copy[start..start + len].fill(0);
                let expected = hmac_by_algo(self.creds.auth_algo, &self.auth_key, &rx_copy);
                if expected.len() < len || expected[..len] != dec.auth_params[..] {
                    return Err("SNMPv3 响应 HMAC 鉴权校验不通过（密钥可能不匹配）".into());
                }
            }
        }

        let plain_scoped = if dec.encrypted_scoped_pdu {
            if !use_priv || dec.priv_params.len() != 8 {
                return Err("收到加密 SNMPv3 ScopedPDU 但本地未启用或缺少 8B Salt".into());
            }
            let salt_arr: [u8; 8] = dec.priv_params.as_slice().try_into().map_err(|_| "Salt 非 8 字节")?;
            snmpv3_aes128_cfb_crypt(
                &self.priv_key,
                dec.engine_boots,
                dec.engine_time,
                &salt_arr,
                &dec.raw_scoped_pdu,
                false,
            )?
        } else {
            dec.raw_scoped_pdu
        };

        let (_, _, err_st, items) = decode_scoped_pdu(&plain_scoped)?;
        if err_st != 0 {
            return Err(format!("SNMPv3 Agent 返回错误状态码 errStatus={}", err_st));
        }
        items.into_iter().next().ok_or_else(|| "SNMPv3 响应缺少 VarBind".into())
    }
}

/// 标准 RFC 3414 / 3826 SNMPv3 采集核心入口：自动执行 EngineID Discovery -> 密钥本地化 -> Walk 交换机转发表
pub fn poll_snmp_v3_switch_core(
    switch_ip: &str,
    port: u16,
    creds: &SnmpV3Credentials,
    timeout_ms: u64,
) -> Result<SwitchDevice, String> {
    if creds.username.trim().is_empty() {
        return Err("SNMPv3 USM 用户名不能为空".into());
    }
    let ip: std::net::IpAddr = switch_ip
        .trim()
        .parse()
        .map_err(|_| format!("非法交换机管理 IP: {}", switch_ip))?;
    let target = std::net::SocketAddr::new(ip, port);
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("创建 UDP 套接字失败: {}", e))?;
    let _ = sock.set_read_timeout(Some(std::time::Duration::from_millis(timeout_ms.clamp(200, 5000))));

    // Step 1: EngineID Discovery（发送空 EngineID Report 请求）
    let probe_scoped = encode_scoped_pdu(&[], 1, 0xA0, &[1, 3, 6, 1, 2, 1, 1, 5, 0]);
    let discovery_pkt = encode_snmpv3_message(
        1,
        0x04, // reportable, noAuth, noPriv
        &[],
        0,
        0,
        "",
        SnmpV3AuthAlgo::None,
        &[],
        &[],
        &probe_scoped,
        false,
    );
    sock.send_to(&discovery_pkt, target)
        .map_err(|e| format!("SNMPv3 EngineID 探测发送失败: {}", e))?;
    let mut rx_buf = [0u8; 4096];
    let (n, _) = sock
        .recv_from(&mut rx_buf)
        .map_err(|e| format!("SNMPv3 EngineID 探测超时: {}", e))?;
    let disc = decode_snmpv3_message(&rx_buf[..n])?;
    if disc.engine_id.is_empty() {
        return Err("SNMPv3 Agent 未返回有效的 authoritativeEngineID".into());
    }

    // Step 2: RFC 3414 密钥本地化 (Kul)
    let auth_key = snmpv3_password_to_key(creds.auth_algo, &creds.auth_password, &disc.engine_id);
    let priv_key = if creds.priv_algo == SnmpV3PrivAlgo::Aes128 {
        snmpv3_password_to_key(creds.auth_algo, &creds.priv_password, &disc.engine_id)
    } else {
        Vec::new()
    };

    let mut client = SnmpV3Client {
        sock: &sock,
        target,
        creds,
        engine_id: disc.engine_id,
        engine_boots: disc.engine_boots,
        engine_time: disc.engine_time,
        auth_key,
        priv_key,
        msg_counter: 10,
        salt_counter: 0x0001_0001,
    };
    poll_snmp_tables_with_client(&ip.to_string(), &mut client)
}

#[tauri::command]
pub async fn poll_snmp_v3_switch_cmd(
    switch_ip: String,
    port: Option<u16>,
    creds: SnmpV3Credentials,
) -> Result<SwitchDevice, String> {
    let p = port.unwrap_or(161);
    tokio::task::spawn_blocking(move || poll_snmp_v3_switch_core(&switch_ip, p, &creds, 1500))
        .await
        .map_err(|e| format!("SNMPv3 异步任务异常: {}", e))?
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

    /// 轮次 7：真实 UDP 环回模拟标准 SNMPv2c 交换机验证 ASN.1 BER Get/Walk 与物理端口穿透定位
    #[test]
    fn test_native_snmp_v2c_udp_loopback_switch_poll_and_port_locate() {
        let srv = std::net::UdpSocket::bind("127.0.0.1:0").expect("绑定测试 SNMP Agent 失败");
        let port = srv.local_addr().unwrap().port();
        let _ = srv.set_read_timeout(Some(std::time::Duration::from_secs(2)));

        let agent_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let sys_name_oid = vec![1, 3, 6, 1, 2, 1, 1, 5, 0];
            let sys_descr_oid = vec![1, 3, 6, 1, 2, 1, 1, 1, 0];
            let if7_descr_oid = vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 7];
            let if7_speed_oid = vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 5, 7];
            let fdb_mac_oid = vec![1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2, 0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33];
            let arp_ip_oid = vec![1, 3, 6, 1, 2, 1, 4, 22, 1, 2, 7, 192, 168, 10, 88];

            for _ in 0..16 {
                let Ok((n, peer)) = srv.recv_from(&mut buf) else { break };
                let (_, msg_body, _) = read_tlv(&buf[..n], 0).unwrap();
                let (_, _, p1) = read_tlv(msg_body, 0).unwrap();
                let (_, comm_b, p2) = read_tlv(msg_body, p1).unwrap();
                let (pdu_tag, pdu_body, _) = read_tlv(msg_body, p2).unwrap();
                let (_, req_b, q1) = read_tlv(pdu_body, 0).unwrap();
                let (_, _, q2) = read_tlv(pdu_body, q1).unwrap();
                let (_, _, q3) = read_tlv(pdu_body, q2).unwrap();
                let (_, vbl_b, _) = read_tlv(pdu_body, q3).unwrap();
                let (_, vb_b, _) = read_tlv(vbl_b, 0).unwrap();
                let (_, oid_raw, _) = read_tlv(vb_b, 0).unwrap();
                let req_oid = decode_ber_oid(oid_raw);
                let req_id = decode_ber_integer(req_b, false) as i32;

                let (resp_oid, resp_val_tlv): (Vec<u32>, Vec<u8>) = if pdu_tag == 0xA0 && req_oid == sys_name_oid {
                    (sys_name_oid.clone(), wrap_tlv(0x04, b"H3C-Core-S5560"))
                } else if pdu_tag == 0xA0 && req_oid == sys_descr_oid {
                    (sys_descr_oid.clone(), wrap_tlv(0x04, b"Comware V7 Switch"))
                } else if pdu_tag == 0xA1 && req_oid == vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 2] {
                    (if7_descr_oid.clone(), wrap_tlv(0x04, b"GigabitEthernet0/0/7"))
                } else if pdu_tag == 0xA1 && req_oid == vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 5] {
                    (if7_speed_oid.clone(), encode_ber_integer(1_000_000_000))
                } else if pdu_tag == 0xA1 && req_oid == vec![1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2] {
                    (fdb_mac_oid.clone(), encode_ber_integer(7))
                } else if pdu_tag == 0xA1 && req_oid == vec![1, 3, 6, 1, 2, 1, 4, 22, 1, 2] {
                    (arp_ip_oid.clone(), wrap_tlv(0x04, &[0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]))
                } else {
                    (req_oid, vec![0x82, 0x00]) // EndOfMibView
                };

                let mut vb = encode_ber_oid(&resp_oid);
                vb.extend_from_slice(&resp_val_tlv);
                let vbl = wrap_tlv(0x30, &wrap_tlv(0x30, &vb));
                let mut pdu_inner = encode_ber_integer(req_id);
                pdu_inner.extend_from_slice(&encode_ber_integer(0));
                pdu_inner.extend_from_slice(&encode_ber_integer(0));
                pdu_inner.extend_from_slice(&vbl);
                let mut msg_inner = encode_ber_integer(1);
                msg_inner.extend_from_slice(&wrap_tlv(0x04, comm_b));
                msg_inner.extend_from_slice(&wrap_tlv(0xA2, &pdu_inner));
                let resp = wrap_tlv(0x30, &msg_inner);
                let _ = srv.send_to(&resp, peer);
            }
        });

        let sw = poll_snmp_switch_core("127.0.0.1", "public", port, 800).expect("SNMP UDP 实采失败");
        assert_eq!(sw.sys_name, "H3C-Core-S5560");
        assert_eq!(sw.ports.get(&7).unwrap().port_name, "GigabitEthernet0/0/7");

        let loc = locate_asset_switch_port_cmd("192.168.10.88".to_string(), None)
            .expect("定位调用异常")
            .expect("应成功定位到物理端口 7");
        assert_eq!(loc.port_name, "GigabitEthernet0/0/7");
        assert_eq!(loc.target_mac, "AA:BB:CC:11:22:33");
        let _ = agent_thread.join();
    }

    #[test]
    fn test_rfc_md5_sha1_and_snmpv3_key_localization() {
        assert_eq!(
            hex::encode(rfc1321_md5(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex::encode(rfc3174_sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );

        // RFC 3414 Appendix A.3.1 / A.3.2 标准测试向量
        let engine_id = hex::decode("000000000000000000000002").unwrap();
        let kul_md5 = snmpv3_password_to_key(SnmpV3AuthAlgo::Md5, "maplesyrup", &engine_id);
        assert_eq!(hex::encode(&kul_md5), "526f5eed9fcce26f8964c2930787d82b");

        let kul_sha1 = snmpv3_password_to_key(SnmpV3AuthAlgo::Sha1, "maplesyrup", &engine_id);
        assert_eq!(
            hex::encode(&kul_sha1),
            "6695febc9288e36282235fc7151f128497b38f3f"
        );

        // AES-128-CFB 加解密与边界错误拦截测试
        let salt = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let pt = b"OMNI_PROBE_SNMPV3_AES128_CFB_PAYLOAD_VERIFICATION_3826";
        let ct = snmpv3_aes128_cfb_crypt(&kul_sha1[..16], 12, 3456, &salt, pt, true).unwrap();
        assert_ne!(&ct, pt);
        let rt = snmpv3_aes128_cfb_crypt(&kul_sha1[..16], 12, 3456, &salt, &ct, false).unwrap();
        assert_eq!(&rt, pt);
        assert!(snmpv3_aes128_cfb_crypt(&[0u8; 8], 1, 1, &salt, pt, true).is_err());
    }

    #[test]
    fn test_native_snmp_v3_authpriv_aes128_udp_loopback_switch_poll() {
        let srv = std::net::UdpSocket::bind("127.0.0.1:0").expect("绑定 UDP 模拟交换机失败");
        let port = srv.local_addr().unwrap().port();
        let _ = srv.set_read_timeout(Some(std::time::Duration::from_secs(3)));

        let agent_engine_id = vec![0x80, 0x00, 0x07, 0xDB, 0x03, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let auth_pass = "OmniAuthPass2026!";
        let priv_pass = "OmniPrivAes128Pass!";
        let auth_key = snmpv3_password_to_key(SnmpV3AuthAlgo::Sha1, auth_pass, &agent_engine_id);
        let priv_key = snmpv3_password_to_key(SnmpV3AuthAlgo::Sha1, priv_pass, &agent_engine_id);
        let boots = 17i32;
        let etime = 8420i32;

        let agent_eid_clone = agent_engine_id.clone();
        let auth_key_c = auth_key.clone();
        let priv_key_c = priv_key.clone();

        let agent_thread = std::thread::spawn(move || {
            let sys_name_oid = vec![1, 3, 6, 1, 2, 1, 1, 5, 0];
            let sys_descr_oid = vec![1, 3, 6, 1, 2, 1, 1, 1, 0];
            let if24_descr_oid = vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 24];
            let fdb_mac_oid = vec![1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
            let arp_ip_oid = vec![1, 3, 6, 1, 2, 1, 4, 22, 1, 2, 24, 10, 88, 1, 77];

            let mut buf = [0u8; 4096];
            // 1 次 EngineID 探测 + 多轮 Get/GetNext 采集
            for step in 0..16 {
                let Ok((n, peer)) = srv.recv_from(&mut buf) else { break };
                let rx_pkt = &buf[..n];
                let dec = decode_snmpv3_message(rx_pkt).unwrap();

                if dec.engine_id.is_empty() {
                    // 回复 Report PDU (0xA8) 携带 authoritativeEngineID / boots / time
                    let report_oid = vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0];
                    let mut vb = encode_ber_oid(&report_oid);
                    vb.extend_from_slice(&encode_ber_integer(1));
                    let vbl = wrap_tlv(0x30, &wrap_tlv(0x30, &vb));
                    let mut pdu_in = encode_ber_integer(1);
                    pdu_in.extend_from_slice(&encode_ber_integer(0));
                    pdu_in.extend_from_slice(&encode_ber_integer(0));
                    pdu_in.extend_from_slice(&vbl);
                    let mut sp = wrap_tlv(0x04, &agent_eid_clone);
                    sp.extend_from_slice(&wrap_tlv(0x04, &[]));
                    sp.extend_from_slice(&wrap_tlv(0xA8, &pdu_in));
                    let sp_seq = wrap_tlv(0x30, &sp);
                    let resp = encode_snmpv3_message(
                        1,
                        0x00,
                        &agent_eid_clone,
                        boots,
                        etime,
                        "",
                        SnmpV3AuthAlgo::None,
                        &[],
                        &[],
                        &sp_seq,
                        false,
                    );
                    let _ = srv.send_to(&resp, peer);
                    continue;
                }

                // 验证客户端 HMAC-SHA1-96 摘要
                assert_eq!(dec.msg_flags & 0x03, 0x03, "应开启 authPriv");
                let (a_start, a_len) = dec.auth_params_offset_in_msg.unwrap();
                let mut rx_zero = rx_pkt.to_vec();
                rx_zero[a_start..a_start + a_len].fill(0);
                let expect_mac = hmac_by_algo(SnmpV3AuthAlgo::Sha1, &auth_key_c, &rx_zero);
                assert_eq!(&expect_mac[..a_len], &dec.auth_params[..]);

                // 解密 ScopedPDU
                let salt_arr: [u8; 8] = dec.priv_params.as_slice().try_into().unwrap();
                let plain_sp = snmpv3_aes128_cfb_crypt(
                    &priv_key_c,
                    dec.engine_boots,
                    dec.engine_time,
                    &salt_arr,
                    &dec.raw_scoped_pdu,
                    false,
                )
                .unwrap();
                let (pdu_tag, req_id, _, items) = decode_scoped_pdu(&plain_sp).unwrap();
                let req_oid = &items[0].0;

                let (resp_oid, resp_val_tlv): (Vec<u32>, Vec<u8>) = if pdu_tag == 0xA0 && *req_oid == sys_name_oid {
                    (sys_name_oid.clone(), wrap_tlv(0x04, b"Huawei-CE6865-SNMPv3"))
                } else if pdu_tag == 0xA0 && *req_oid == sys_descr_oid {
                    (sys_descr_oid.clone(), wrap_tlv(0x04, b"VRP V800R022 AuthPriv"))
                } else if pdu_tag == 0xA1 && *req_oid == vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 2] {
                    (if24_descr_oid.clone(), wrap_tlv(0x04, b"10GE1/0/24"))
                } else if pdu_tag == 0xA1 && *req_oid == vec![1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2] {
                    (fdb_mac_oid.clone(), encode_ber_integer(24))
                } else if pdu_tag == 0xA1 && *req_oid == vec![1, 3, 6, 1, 2, 1, 4, 22, 1, 2] {
                    (arp_ip_oid.clone(), wrap_tlv(0x04, &[0x10, 0x20, 0x30, 0x40, 0x50, 0x60]))
                } else {
                    (req_oid.clone(), vec![0x82, 0x00])
                };

                let mut vb = encode_ber_oid(&resp_oid);
                vb.extend_from_slice(&resp_val_tlv);
                let vbl = wrap_tlv(0x30, &wrap_tlv(0x30, &vb));
                let mut pdu_in = encode_ber_integer(req_id);
                pdu_in.extend_from_slice(&encode_ber_integer(0));
                pdu_in.extend_from_slice(&encode_ber_integer(0));
                pdu_in.extend_from_slice(&vbl);
                let mut sp = wrap_tlv(0x04, &agent_eid_clone);
                sp.extend_from_slice(&wrap_tlv(0x04, &[]));
                sp.extend_from_slice(&wrap_tlv(0xA2, &pdu_in));
                let plain_resp_sp = wrap_tlv(0x30, &sp);

                let resp_salt: [u8; 8] = [0xAA, 0, 0, 0, 0, 0, 0, step as u8];
                let enc_resp_sp = snmpv3_aes128_cfb_crypt(
                    &priv_key_c,
                    boots,
                    etime,
                    &resp_salt,
                    &plain_resp_sp,
                    true,
                )
                .unwrap();

                let resp = encode_snmpv3_message(
                    100 + step as i32,
                    0x03,
                    &agent_eid_clone,
                    boots,
                    etime,
                    "netops_admin",
                    SnmpV3AuthAlgo::Sha1,
                    &auth_key_c,
                    &resp_salt,
                    &enc_resp_sp,
                    true,
                );
                let _ = srv.send_to(&resp, peer);
            }
        });

        let creds = SnmpV3Credentials {
            username: "netops_admin".to_string(),
            auth_algo: SnmpV3AuthAlgo::Sha1,
            auth_password: auth_pass.to_string(),
            priv_algo: SnmpV3PrivAlgo::Aes128,
            priv_password: priv_pass.to_string(),
        };
        let sw = poll_snmp_v3_switch_core("127.0.0.1", port, &creds, 1200).expect("SNMPv3 authPriv 实采失败");
        assert_eq!(sw.sys_name, "Huawei-CE6865-SNMPv3");
        assert_eq!(sw.ports.get(&24).unwrap().port_name, "10GE1/0/24");

        let loc = locate_asset_switch_port_cmd("10.88.1.77".to_string(), None)
            .expect("定位失败")
            .expect("应反查到 SNMPv3 采集的 10GE1/0/24");
        assert_eq!(loc.port_name, "10GE1/0/24");
        assert_eq!(loc.target_mac, "10:20:30:40:50:60");
        let _ = agent_thread.join();
    }
}
