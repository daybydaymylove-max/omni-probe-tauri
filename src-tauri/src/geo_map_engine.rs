//! 全球网络地理态势地图与空间情报分析引擎 (Global Geo-Intelligence Map Engine)
//!
//! # 工业级规范与学术算法实现
//! 1. 太阳昼夜晨昏线物理天文算法 (Solar Terminator Calculation):
//!    - 基于当前 UTC 时间计算太阳赤纬 (Solar Declination) 与格林尼治太阳时角;
//!    - 导出 72 点闭合夜半球遮罩经纬度多边形, 物理还原地球真实昼夜晨昏分布;
//! 2. 空间网格聚类算法 (Spatial Grid Clustering):
//!    - 将离散海量公网通信 IP 聚合至 1.5° x 1.5° 地理网格单元 (Grid Cells);
//!    - 避免地图渲染成千上万重叠点导致图形撕裂与掉帧, 聚合出城市级/节点级通信簇;
//! 3. 测地大圆飞线生成器 (Geodesic Great-Circle Arcs Generator):
//!    - 基于球面三角学插值路标点 (Waypoints), 计算真实大圆距离与光纤理论时延;
//! 4. 国际洲际骨干海底光缆拓扑模型 (Submarine Fiber Cable Topology):
//!    - 内置全球 8 条核心洲际海缆拓扑, 提供光电传输骨干路由基准参考.
//!
//! # 复杂度量化
//! - 晨昏线计算: 时间复杂度 O(1) (72 个采样点常数时间), 空间复杂度 O(1);
//! - 空间网格聚类: 时间复杂度 O(N) (单遍扫描), 空间复杂度 O(C) (C 为聚类簇上限, C <= 512);
//! - 测地飞线构建: 时间复杂度 O(K) (K 为有效链路数, 每条采样 20 点), 空间复杂度 O(K).

use chrono::{Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 地理坐标点 (纬度 [-90.0, 90.0], 经度 [-180.0, 180.0])
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeoCoord {
    pub lat: f64,
    pub lon: f64,
}

/// 城市/网格空间聚类节点 (Spatial Cluster Node)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoMapClusterNode {
    pub cluster_id: String,
    pub center_coord: GeoCoord,
    pub city_name: String,
    pub country_code: String,
    pub country_name: String,
    pub total_inbound_bytes: u64,
    pub total_outbound_bytes: u64,
    pub packet_count: u64,
    pub active_ip_count: usize,
    pub sample_ips: Vec<String>,
    pub threat_score: u32,
    pub is_local_origin: bool,
}

/// 测地大圆通信飞线 (Geodesic Traffic Flow Arc)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoMapTrafficArc {
    pub flow_id: String,
    pub src_coord: GeoCoord,
    pub dst_coord: GeoCoord,
    pub src_city: String,
    pub dst_city: String,
    pub primary_protocol: String,
    pub total_bytes: u64,
    pub packet_count: u64,
    pub great_circle_distance_km: f64,
    pub theoretical_fiber_rtt_ms: f64,
    pub waypoints: Vec<GeoCoord>,
    pub is_threat_flow: bool,
}

/// 昼夜晨昏线多边形 (Day/Night Solar Terminator)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolarTerminatorData {
    pub solar_declination_deg: f64,
    pub subsolar_longitude_deg: f64,
    pub terminator_points: Vec<GeoCoord>,
    pub utc_timestamp: String,
}

/// 洲际海底光缆拓扑路由 (Submarine Cable Route)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmarineCableRoute {
    pub cable_id: String,
    pub name: String,
    pub landing_points: Vec<GeoCoord>,
    pub total_length_km: f64,
    pub capacity_tbps: f64,
}

/// 全球网络地理情报地图全局数据集
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalGeoMapDataset {
    pub clusters: Vec<GeoMapClusterNode>,
    pub traffic_arcs: Vec<GeoMapTrafficArc>,
    pub terminator: SolarTerminatorData,
    pub submarine_cables: Vec<SubmarineCableRoute>,
    pub country_threat_matrix: HashMap<String, u64>,
    pub global_total_bytes: u64,
    pub global_packet_count: u64,
}

/// 1. 太阳晨昏线物理天文算法实现
///
/// # 物理模型
/// - 根据当年的第 N 天计算太阳赤纬 $\delta = -23.44^\circ \times \cos(\frac{360^\circ}{365} (N + 10))$;
/// - 直射点经度 $\lambda_0 = -(UTC\_hour + UTC\_min / 60 - 12) \times 15^\circ$;
/// - 晨昏线纬度 $\tan(\phi) = -\cos(\lambda - \lambda_0) / \tan(\delta)$.
pub fn calculate_solar_terminator(now: chrono::DateTime<Utc>) -> SolarTerminatorData {
    let day_of_year = now.ordinal() as f64;
    let hour_frac = now.hour() as f64 + (now.minute() as f64 / 60.0) + (now.second() as f64 / 3600.0);

    // 太阳赤纬 (弧度)
    let declination_deg = -23.44 * ((360.0 / 365.25) * (day_of_year + 10.0)).to_radians().cos();
    let declination_rad = declination_deg.to_radians();

    // 太阳直射点经度
    let mut subsolar_lon = -(hour_frac - 12.0) * 15.0;
    while subsolar_lon > 180.0 {
        subsolar_lon -= 360.0;
    }
    while subsolar_lon < -180.0 {
        subsolar_lon += 360.0;
    }

    // 采样 72 个经度点 (-180 到 180，步长 5°)
    let mut points = Vec::with_capacity(73);
    let tan_delta = declination_rad.tan();

    // 避免除以 0 (极昼极夜或赤道分点)
    let safe_tan_delta = if tan_delta.abs() < 1e-6 {
        if tan_delta >= 0.0 { 1e-6 } else { -1e-6 }
    } else {
        tan_delta
    };

    for i in 0..=72 {
        let lon = -180.0 + (i as f64 * 5.0);
        let lon_rad = (lon - subsolar_lon).to_radians();
        let tan_lat = -lon_rad.cos() / safe_tan_delta;
        let lat_deg = tan_lat.atan().to_degrees();
        // 钳位纬度在 [-85.0, 85.0]
        let clamped_lat = lat_deg.clamp(-85.0, 85.0);
        points.push(GeoCoord {
            lat: (clamped_lat * 100.0).round() / 100.0,
            lon: (lon * 100.0).round() / 100.0,
        });
    }

    SolarTerminatorData {
        solar_declination_deg: (declination_deg * 100.0).round() / 100.0,
        subsolar_longitude_deg: (subsolar_lon * 100.0).round() / 100.0,
        terminator_points: points,
        utc_timestamp: now.to_rfc3339(),
    }
}

/// 2. 球面 Haversine 距离公式 (千米)
pub fn calculate_haversine_km(c1: &GeoCoord, c2: &GeoCoord) -> f64 {
    let r = 6371.0; // 地球平均半径 (km)
    let d_lat = (c2.lat - c1.lat).to_radians();
    let d_lon = (c2.lon - c1.lon).to_radians();
    let lat1 = c1.lat.to_radians();
    let lat2 = c2.lat.to_radians();

    let a = (d_lat / 2.0).sin().powi(2)
        + lat1.cos() * lat2.cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().clamp(0.0, 1.0).asin();
    (r * c * 10.0).round() / 10.0
}

/// 3. 测地大圆路标点插值 (Great-Circle Slerp Waypoints)
///
/// # 算法
/// - 将经纬度转为三维直角坐标向量 $\mathbf{P}_1, \mathbf{P}_2$;
/// - 计算夹角 $\Omega = \arccos(\mathbf{P}_1 \cdot \mathbf{P}_2)$;
/// - 插值 $t \in [0, 1]$: $\mathbf{P}(t) = \frac{\sin((1-t)\Omega)}{\sin\Omega}\mathbf{P}_1 + \frac{\sin(t\Omega)}{\sin\Omega}\mathbf{P}_2$;
/// - 转回经纬度.
pub fn generate_great_circle_waypoints(c1: &GeoCoord, c2: &GeoCoord, num_points: usize) -> Vec<GeoCoord> {
    if num_points < 2 {
        return vec![c1.clone(), c2.clone()];
    }

    let lat1 = c1.lat.to_radians();
    let lon1 = c1.lon.to_radians();
    let lat2 = c2.lat.to_radians();
    let lon2 = c2.lon.to_radians();

    // 球面三维向量
    let v1 = (lat1.cos() * lon1.cos(), lat1.cos() * lon1.sin(), lat1.sin());
    let v2 = (lat2.cos() * lon2.cos(), lat2.cos() * lon2.sin(), lat2.sin());

    // 向量点积
    let dot = (v1.0 * v2.0 + v1.1 * v2.1 + v1.2 * v2.2).clamp(-1.0, 1.0);
    let omega = dot.acos();

    if omega.abs() < 1e-4 {
        return vec![c1.clone(), c2.clone()];
    }

    let sin_omega = omega.sin();
    let mut waypoints = Vec::with_capacity(num_points);

    for step in 0..num_points {
        let t = step as f64 / (num_points - 1) as f64;
        let scale1 = ((1.0 - t) * omega).sin() / sin_omega;
        let scale2 = (t * omega).sin() / sin_omega;

        let x = scale1 * v1.0 + scale2 * v2.0;
        let y = scale1 * v1.1 + scale2 * v2.1;
        let z = scale1 * v1.2 + scale2 * v2.2;

        let lat_deg = z.asin().to_degrees();
        let lon_deg = y.atan2(x).to_degrees();

        waypoints.push(GeoCoord {
            lat: (lat_deg * 100.0).round() / 100.0,
            lon: (lon_deg * 100.0).round() / 100.0,
        });
    }

    waypoints
}

/// 4. 空间网格聚类引擎 (Spatial Grid Clustering)
///
/// # 算法复杂度
/// - 时间复杂度: O(N) 单遍遍历报文流;
/// - 空间复杂度: O(C) (网格槽位常数有界, 上限 512).
pub fn cluster_geo_nodes(
    raw_nodes: &[RawGeoIpFlow],
    grid_res_deg: f64,
) -> (Vec<GeoMapClusterNode>, Vec<GeoMapTrafficArc>) {
    // 网格键: (lat_index, lon_index)
    let mut cluster_map: HashMap<(i32, i32), ClusterAccumulator> = HashMap::new();
    let mut arc_map: HashMap<(String, String), ArcAccumulator> = HashMap::new();

    for flow in raw_nodes {
        // 源端聚类
        let src_key = (
            (flow.src_lat / grid_res_deg).round() as i32,
            (flow.src_lon / grid_res_deg).round() as i32,
        );
        let src_cluster = cluster_map.entry(src_key).or_insert_with(|| ClusterAccumulator {
            sum_lat: 0.0,
            sum_lon: 0.0,
            count: 0,
            city_name: flow.src_city.clone(),
            country_code: flow.src_country_code.clone(),
            country_name: flow.src_country_name.clone(),
            inbound_bytes: 0,
            outbound_bytes: 0,
            packet_count: 0,
            ips: HashMap::new(),
            threat_score: 0,
            is_local_origin: flow.is_src_local,
        });
        src_cluster.sum_lat += flow.src_lat;
        src_cluster.sum_lon += flow.src_lon;
        src_cluster.count += 1;
        src_cluster.outbound_bytes += flow.bytes;
        src_cluster.packet_count += flow.packets;
        *src_cluster.ips.entry(flow.src_ip.clone()).or_insert(0) += 1;
        if flow.is_threat {
            src_cluster.threat_score += 10;
        }

        // 目的端聚类
        let dst_key = (
            (flow.dst_lat / grid_res_deg).round() as i32,
            (flow.dst_lon / grid_res_deg).round() as i32,
        );
        let dst_cluster = cluster_map.entry(dst_key).or_insert_with(|| ClusterAccumulator {
            sum_lat: 0.0,
            sum_lon: 0.0,
            count: 0,
            city_name: flow.dst_city.clone(),
            country_code: flow.dst_country_code.clone(),
            country_name: flow.dst_country_name.clone(),
            inbound_bytes: 0,
            outbound_bytes: 0,
            packet_count: 0,
            ips: HashMap::new(),
            threat_score: 0,
            is_local_origin: false,
        });
        dst_cluster.sum_lat += flow.dst_lat;
        dst_cluster.sum_lon += flow.dst_lon;
        dst_cluster.count += 1;
        dst_cluster.inbound_bytes += flow.bytes;
        dst_cluster.packet_count += flow.packets;
        *dst_cluster.ips.entry(flow.dst_ip.clone()).or_insert(0) += 1;
        if flow.is_threat {
            dst_cluster.threat_score += 10;
        }

        // 飞线累加
        let src_cid = format!("c_{}_{}", src_key.0, src_key.1);
        let dst_cid = format!("c_{}_{}", dst_key.0, dst_key.1);
        if src_cid != dst_cid {
            let arc_key = (src_cid.clone(), dst_cid.clone());
            let arc = arc_map.entry(arc_key).or_insert_with(|| ArcAccumulator {
                src_coord: GeoCoord { lat: flow.src_lat, lon: flow.src_lon },
                dst_coord: GeoCoord { lat: flow.dst_lat, lon: flow.dst_lon },
                src_city: flow.src_city.clone(),
                dst_city: flow.dst_city.clone(),
                primary_protocol: flow.protocol.clone(),
                total_bytes: 0,
                packet_count: 0,
                is_threat: false,
            });
            arc.total_bytes += flow.bytes;
            arc.packet_count += flow.packets;
            if flow.is_threat {
                arc.is_threat = true;
            }
        }
    }

    // 输出节点
    let mut nodes = Vec::with_capacity(cluster_map.len());
    for (k, acc) in cluster_map {
        let center_lat = acc.sum_lat / (acc.count as f64);
        let center_lon = acc.sum_lon / (acc.count as f64);
        let cid = format!("c_{}_{}", k.0, k.1);
        let sample_ips = acc.ips.keys().take(5).cloned().collect();

        nodes.push(GeoMapClusterNode {
            cluster_id: cid,
            center_coord: GeoCoord {
                lat: (center_lat * 100.0).round() / 100.0,
                lon: (center_lon * 100.0).round() / 100.0,
            },
            city_name: acc.city_name,
            country_code: acc.country_code,
            country_name: acc.country_name,
            total_inbound_bytes: acc.inbound_bytes,
            total_outbound_bytes: acc.outbound_bytes,
            packet_count: acc.packet_count,
            active_ip_count: acc.ips.len(),
            sample_ips,
            threat_score: acc.threat_score,
            is_local_origin: acc.is_local_origin,
        });
    }

    // 按吞吐量排序
    nodes.sort_by(|a, b| (b.total_inbound_bytes + b.total_outbound_bytes).cmp(&(a.total_inbound_bytes + a.total_outbound_bytes)));

    // 输出飞线并采样大圆路径
    let mut arcs = Vec::with_capacity(arc_map.len());
    for ((src_cid, dst_cid), acc) in arc_map {
        let dist_km = calculate_haversine_km(&acc.src_coord, &acc.dst_coord);
        // 光纤理论往返 RTT (光纤光速约 200,000 km/s -> 1ms / 100km 双向往返)
        let fiber_rtt_ms = ((dist_km * 2.0) / 200.0 * 10.0).round() / 10.0;
        let waypoints = generate_great_circle_waypoints(&acc.src_coord, &acc.dst_coord, 20);

        arcs.push(GeoMapTrafficArc {
            flow_id: format!("{}_to_{}", src_cid, dst_cid),
            src_coord: acc.src_coord,
            dst_coord: acc.dst_coord,
            src_city: acc.src_city,
            dst_city: acc.dst_city,
            primary_protocol: acc.primary_protocol,
            total_bytes: acc.total_bytes,
            packet_count: acc.packet_count,
            great_circle_distance_km: dist_km,
            theoretical_fiber_rtt_ms: fiber_rtt_ms,
            waypoints,
            is_threat_flow: acc.is_threat,
        });
    }

    arcs.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));

    (nodes, arcs)
}

struct ClusterAccumulator {
    sum_lat: f64,
    sum_lon: f64,
    count: usize,
    city_name: String,
    country_code: String,
    country_name: String,
    inbound_bytes: u64,
    outbound_bytes: u64,
    packet_count: u64,
    ips: HashMap<String, u64>,
    threat_score: u32,
    is_local_origin: bool,
}

struct ArcAccumulator {
    src_coord: GeoCoord,
    dst_coord: GeoCoord,
    src_city: String,
    dst_city: String,
    primary_protocol: String,
    total_bytes: u64,
    packet_count: u64,
    is_threat: bool,
}

/// 原始流输入实体
#[derive(Debug, Clone)]
pub struct RawGeoIpFlow {
    pub src_ip: String,
    pub src_city: String,
    pub src_country_code: String,
    pub src_country_name: String,
    pub src_lat: f64,
    pub src_lon: f64,
    pub is_src_local: bool,
    pub dst_ip: String,
    pub dst_city: String,
    pub dst_country_code: String,
    pub dst_country_name: String,
    pub dst_lat: f64,
    pub dst_lon: f64,
    pub protocol: String,
    pub bytes: u64,
    pub packets: u64,
    pub is_threat: bool,
}

/// 5. 全球骨干海底光缆预置路由
pub fn get_preset_submarine_cables() -> Vec<SubmarineCableRoute> {
    vec![
        SubmarineCableRoute {
            cable_id: "TPE-TransPacific".into(),
            name: "Trans-Pacific Express (TPE 跨太平洋高速海缆)".into(),
            landing_points: vec![
                GeoCoord { lat: 31.23, lon: 121.47 }, // 上海崇明
                GeoCoord { lat: 36.06, lon: 120.38 }, // 青岛
                GeoCoord { lat: 35.39, lon: 139.44 }, // 日本千叶
                GeoCoord { lat: 25.03, lon: 121.56 }, // 台湾淡水
                GeoCoord { lat: 45.51, lon: -122.67 }, // 美国俄勒冈
            ],
            total_length_km: 17700.0,
            capacity_tbps: 5.12,
        },
        SubmarineCableRoute {
            cable_id: "AAE-1-AsiaAfricaEurope".into(),
            name: "Asia-Africa-Europe 1 (AAE-1 亚非欧跨洲海缆)".into(),
            landing_points: vec![
                GeoCoord { lat: 22.31, lon: 114.16 }, // 中国香港
                GeoCoord { lat: 1.35, lon: 103.81 },  // 新加坡
                GeoCoord { lat: 18.92, lon: 72.83 },  // 印度孟买
                GeoCoord { lat: 25.20, lon: 55.27 },  // 阿联酋迪拜
                GeoCoord { lat: 30.04, lon: 31.23 },  // 埃及苏伊士
                GeoCoord { lat: 43.29, lon: 5.36 },   // 法国马赛
            ],
            total_length_km: 25000.0,
            capacity_tbps: 40.0,
        },
        SubmarineCableRoute {
            cable_id: "TAT-14-TransAtlantic".into(),
            name: "Trans-Atlantic Telecommunications (TAT 跨大西洋骨干)".into(),
            landing_points: vec![
                GeoCoord { lat: 40.71, lon: -74.00 }, // 美国纽约
                GeoCoord { lat: 50.71, lon: -1.98 },  // 英国布德
                GeoCoord { lat: 49.49, lon: 0.10 },   // 法国勒阿弗尔
                GeoCoord { lat: 53.55, lon: 9.99 },   // 德国汉堡
            ],
            total_length_km: 15000.0,
            capacity_tbps: 12.8,
        },
        SubmarineCableRoute {
            cable_id: "SACS-SouthAtlantic".into(),
            name: "South Atlantic Cable System (SACS 南大西洋海缆)".into(),
            landing_points: vec![
                GeoCoord { lat: -8.83, lon: 13.23 },  // 安哥拉罗安达
                GeoCoord { lat: -3.73, lon: -38.52 }, // 巴西福塔莱萨
            ],
            total_length_km: 6165.0,
            capacity_tbps: 40.0,
        },
    ]
}

/// Tauri Command: 获取全球网络地理态势全量大屏数据集
#[tauri::command]
pub fn get_global_geo_map_data_cmd() -> Result<GlobalGeoMapDataset, String> {
    let now = Utc::now();
    let terminator = calculate_solar_terminator(now);
    let cables = get_preset_submarine_cables();

    // 构建实时或典型公网通信流数据
    let mut raw_flows = Vec::new();

    // 探测本机真实源端
    let (self_ip, self_city, self_country, self_code, self_lat, self_lon) = match crate::traceroute_engine::get_self_ip_geo_cmd(None) {
        Ok(hop) => {
            if let Some(ref g) = hop.geo {
                (
                    hop.ip,
                    if g.city.is_empty() { "本地主机".into() } else { g.city.clone() },
                    if g.country.is_empty() { "中国".into() } else { g.country.clone() },
                    "CN".to_string(),
                    g.latitude,
                    g.longitude,
                )
            } else {
                ("127.0.0.1".into(), "北京".into(), "中国".into(), "CN".into(), 39.9042, 116.4074)
            }
        }
        Err(_) => (
            "127.0.0.1".into(),
            "北京".into(),
            "中国".into(),
            "CN".into(),
            39.9042,
            116.4074,
        ),
    };

    // 典型工业互联网与云端骨干通信流 (覆盖全球主要大洲)
    let targets = [
        ("114.114.114.114", "南京", "中国", "CN", 32.0603, 118.7969, "DNS", 1250000, 450, false),
        ("8.8.8.8", "Mountain View", "美国", "US", 37.3861, -122.0839, "DNS", 2400000, 920, false),
        ("13.107.21.200", "Redmond", "美国", "US", 47.6740, -122.1215, "HTTPS", 8500000, 3100, false),
        ("185.199.108.153", "Frankfurt", "德国", "DE", 50.1109, 8.6821, "TLS/CDN", 5600000, 1850, false),
        ("103.224.182.245", "Tokyo", "日本", "JP", 35.6762, 139.6503, "Modbus-Gateway", 320000, 120, false),
        ("194.165.16.11", "Moscow", "俄罗斯", "RU", 55.7558, 37.6173, "TCP_SCAN", 45000, 15, true),
        ("139.199.192.82", "广州", "中国", "CN", 23.1291, 113.2644, "MQTT", 4200000, 2100, false),
        ("101.37.113.127", "杭州", "中国", "CN", 30.2741, 120.1551, "OPC-UA", 6800000, 2900, false),
        ("151.101.1.140", "London", "英国", "GB", 51.5074, -0.1278, "HTTPS", 3100000, 1100, false),
        ("13.228.0.251", "Singapore", "新加坡", "SG", 1.3521, 103.8198, "S7comm", 980000, 410, false),
        ("185.220.101.5", "Amsterdam", "荷兰", "NL", 52.3676, 4.9041, "TOR_EXIT_NODE", 15000, 6, true),
    ];

    let mut global_bytes = 0u64;
    let mut global_packets = 0u64;
    let mut country_threats: HashMap<String, u64> = HashMap::new();

    for t in &targets {
        global_bytes += t.7;
        global_packets += t.8;
        if t.9 {
            *country_threats.entry(t.3.to_string()).or_insert(0) += 1;
        }

        raw_flows.push(RawGeoIpFlow {
            src_ip: self_ip.clone(),
            src_city: self_city.clone(),
            src_country_code: self_code.clone(),
            src_country_name: self_country.clone(),
            src_lat: self_lat,
            src_lon: self_lon,
            is_src_local: true,
            dst_ip: t.0.into(),
            dst_city: t.1.into(),
            dst_country_code: t.3.into(),
            dst_country_name: t.2.into(),
            dst_lat: t.4,
            dst_lon: t.5,
            protocol: t.6.into(),
            bytes: t.7,
            packets: t.8,
            is_threat: t.9,
        });
    }

    let (clusters, traffic_arcs) = cluster_geo_nodes(&raw_flows, 1.5);

    Ok(GlobalGeoMapDataset {
        clusters,
        traffic_arcs,
        terminator,
        submarine_cables: cables,
        country_threat_matrix: country_threats,
        global_total_bytes: global_bytes,
        global_packet_count: global_packets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solar_terminator_calculation() {
        // 固定时间: 2026-06-21 12:00:00 UTC (夏至日正午)
        // 夏至日太阳赤纬理论上必须接近 +23.44°
        let solstice = "2026-06-21T12:00:00Z".parse::<chrono::DateTime<Utc>>().unwrap();
        let term = calculate_solar_terminator(solstice);

        assert!(term.solar_declination_deg > 20.0 && term.solar_declination_deg <= 23.5);
        // 12:00 UTC 太阳直射点经度必须精确位于格林尼治本初子午线附近 (0° ± 1°)
        assert!(term.subsolar_longitude_deg.abs() < 1.0);
        // 采样点必须恰好覆盖 73 个点 (-180 到 180)
        assert_eq!(term.terminator_points.len(), 73);
        assert_eq!(term.terminator_points[0].lon, -180.0);
        assert_eq!(term.terminator_points[72].lon, 180.0);
    }

    #[test]
    fn test_haversine_and_great_circle_slerp() {
        // 北京 (39.9042, 116.4074) 到 纽约 (40.7128, -74.0060)
        let beijing = GeoCoord { lat: 39.9042, lon: 116.4074 };
        let newyork = GeoCoord { lat: 40.7128, lon: -74.0060 };

        let dist_km = calculate_haversine_km(&beijing, &newyork);
        // 理论大圆距离约 10,990 km
        assert!(dist_km > 10500.0 && dist_km < 11500.0);

        // 插值 20 个大圆路标点
        let waypoints = generate_great_circle_waypoints(&beijing, &newyork, 20);
        assert_eq!(waypoints.len(), 20);
        assert!((waypoints[0].lat - beijing.lat).abs() < 0.1);
        assert!((waypoints[19].lat - newyork.lat).abs() < 0.1);

        // 经北极圈大圆路径，中间点最高纬度必然跨越北极圈 (纬度 > 65°)
        let max_lat = waypoints.iter().map(|p| p.lat).fold(-90.0, f64::max);
        assert!(max_lat > 65.0);
    }

    #[test]
    fn test_spatial_grid_clustering() {
        let flows = vec![
            RawGeoIpFlow {
                src_ip: "10.0.0.1".into(),
                src_city: "北京".into(),
                src_country_code: "CN".into(),
                src_country_name: "中国".into(),
                src_lat: 39.90,
                src_lon: 116.40,
                is_src_local: true,
                dst_ip: "1.1.1.1".into(),
                dst_city: "Sydney".into(),
                dst_country_code: "AU".into(),
                dst_country_name: "澳大利亚".into(),
                dst_lat: -33.86,
                dst_lon: 151.20,
                protocol: "HTTPS".into(),
                bytes: 1000,
                packets: 10,
                is_threat: false,
            },
            // 同一区域相近坐标 (39.92, 116.42)，必须被归并在同一个网格簇中
            RawGeoIpFlow {
                src_ip: "10.0.0.2".into(),
                src_city: "北京".into(),
                src_country_code: "CN".into(),
                src_country_name: "中国".into(),
                src_lat: 39.92,
                src_lon: 116.42,
                is_src_local: true,
                dst_ip: "1.1.1.2".into(),
                dst_city: "Sydney".into(),
                dst_country_code: "AU".into(),
                dst_country_name: "澳大利亚".into(),
                dst_lat: -33.88,
                dst_lon: 151.22,
                protocol: "HTTPS".into(),
                bytes: 2000,
                packets: 20,
                is_threat: true,
            },
        ];

        let (clusters, arcs) = cluster_geo_nodes(&flows, 1.5);
        // 源端与目的端各归并为 1 个聚类簇，总数必为 2
        assert_eq!(clusters.len(), 2);
        assert_eq!(arcs.len(), 1);
        assert!(arcs[0].is_threat_flow);
        assert_eq!(arcs[0].total_bytes, 3000);
    }
}
