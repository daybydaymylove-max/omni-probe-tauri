// ============================================================
// 工业全能网络探针 - 基于 TTL 逐跳探测与离线地理情报的
// 测地线路由追踪与地球拓扑可视化引擎 (TASK-43)
// 模块名称: traceroute_engine.rs
//
// 核心工程职责与执行规范:
// 1. 深度对标 NextTrace / VisualRoute / MTR 权威网络拓扑测绘标杆;
// 2. 100% 物理隔离与纯离线设计: 零外部商业地图 API 依赖, 内置全球与全国离线经纬度坐标矩阵;
// 3. 逐跳 (Hop-by-Hop) 真实路径嗅探: 执行跨平台系统级路由追踪 (Windows tracert -d / Linux traceroute -n),
//    强制禁用反向 DNS 避免停顿, 实现微秒/毫秒级流式响应;
// 4. IP 情报深度联动: 每跳响应 IP 实时与 ip2region.xdb 对照, 提取国家、省份、城市与 ISP;
// 5. 测地距离与物理时延评估: 基于严格的大圆球面距离公式 (Haversine Formula) 实时推算
//    累计跳步物理线缆距离 (km), 并计算光纤理论传播时延与排队拥塞膨胀率 (Bufferbloat Analysis);
// 6. 实时流式事件推送: 支持通过 Tauri Event (traceroute-hop-event) 逐跳推送,
//    驱动前端矢量世界地图动态点亮节点并绘制测地线航路光斑;
// 7. 防御性极限编程与零占位符 (Zero Placeholders): 严格覆盖超时丢包、私网保留段、跨国越野等边界测试.
// ============================================================

use std::net::Ipv4Addr;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::ip_intelligence::GLOBAL_IP_ENGINE;
pub use crate::geo_coordinates_catalog::{GeoCoordinates, OfflineGeoCatalog, GLOBAL_GEO_CATALOG};

/// 全局任务取消标志
pub static CANCEL_TRACEROUTE: AtomicBool = AtomicBool::new(false);
/// 全局任务正在运行标志
pub static TRACEROUTE_RUNNING: AtomicBool = AtomicBool::new(false);

/// 单跳路由探测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteHop {
    /// 跳数序号 (从 1 开始，0 为本机起点)
    pub hop: u32,
    /// 兼容前端历史命名字段 hop_number
    #[serde(default)]
    pub hop_number: u32,
    /// 响应路由器 IP 地址
    pub ip: String,
    /// 往返时延 RTT (毫秒)
    pub rtt_ms: Option<f64>,
    /// 是否超时丢包 (即显示 *)
    pub is_timeout: bool,
    /// 经纬度地理坐标 (若可解析)
    pub geo: Option<GeoCoordinates>,
    /// 平铺纬度 (-90.0 ~ +90.0)
    #[serde(default)]
    pub latitude: f64,
    /// 平铺经度 (-180.0 ~ +180.0)
    #[serde(default)]
    pub longitude: f64,
    /// 是否具备有效地理空间坐标
    #[serde(default)]
    pub has_geo: bool,
    /// 归属国家
    pub country: String,
    /// 归属省份
    pub province: String,
    /// 归属城市
    pub city: String,
    /// 运营商 / 机构 (ISP)
    pub isp: String,
    /// 内网安全域或私网标记
    pub zone_name: String,
    /// 自本地探针起点以来的累计测地物理距离 (公里 km)
    pub cumulative_distance_km: f64,
    /// 理论光纤单向传播时延 (毫秒 ms)
    pub theoretical_fiber_rtt_ms: f64,
    /// 是否为使用者自我主机源点 IP (Hop 0)
    #[serde(default)]
    pub is_self: bool,
    /// 是否属于局域网范围私有地址 (RFC 1918)
    #[serde(default)]
    pub is_lan: bool,
    /// 局域网网络架构拓扑角色 (如 默认网关, 汇聚交换机, 目标资产)
    pub lan_role: Option<String>,
    /// 局域网所属子网网段 (例如 192.168.31.0/24)
    pub subnet_cidr: Option<String>,
    /// 是否为最终到达目标端点
    #[serde(default)]
    pub is_destination: bool,
    /// 缓冲排队拥塞膨胀率 (实测 RTT / 理论光纤 RTT)
    #[serde(default)]
    pub bufferbloat_ratio: f64,
}

/// 完整路由追踪诊断报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteReport {
    /// 探测目标原始输入
    pub target: String,
    /// 目标解析后的 IPv4 地址
    pub target_ip: String,
    /// 追踪是否成功抵达终点
    pub is_completed: bool,
    /// 总跳数
    pub total_hops: u32,
    /// 端到端总时延 RTT (毫秒)
    pub end_to_end_rtt_ms: Option<f64>,
    /// 全链路累计测地线直线距离 (公里 km)
    pub total_distance_km: f64,
    /// 逐跳记录明细列表
    pub hops: Vec<TracerouteHop>,
    /// 探测启动时间戳 (ISO 8601)
    pub start_time: String,
    /// 全程耗时 (毫秒)
    pub duration_ms: u64,
    /// 诊断结论摘要
    pub summary: String,
    /// 探测目标是否属于局域网范围
    #[serde(default)]
    pub is_lan_target: bool,
}

// ============================================================
// 1. 球面测地大圆距离与时延计算 (Haversine Formula)
// ============================================================

/// 地球平均半径 (公里 km)
const EARTH_RADIUS_KM: f64 = 6371.0;

/// 光在玻璃光纤中的有效传播速度约 200,000 km/s (真空光速的 2/3)
const SPEED_OF_LIGHT_IN_FIBER_KM_S: f64 = 200000.0;

/// 使用 Haversine 公式计算两个经纬度坐标点之间的测地大圆最短物理距离 (公里)
/// 时间复杂度: O(1), 空间复杂度: O(1)
pub fn calculate_haversine_distance_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();

    let a = (d_lat / 2.0).sin().powi(2)
        + lat1_rad.cos() * lat2_rad.cos() * (d_lon / 2.0).sin().powi(2);

    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    EARTH_RADIUS_KM * c
}

/// 依据物理测地距离推算往返双向理论光纤光速时延 (RTT 毫秒)
/// 公式: (2 * distance_km / 200,000 km/s) * 1000 ms/s = distance_km / 100 ms
pub fn estimate_theoretical_fiber_rtt_ms(distance_km: f64) -> f64 {
    if distance_km <= 0.0 {
        return 0.1;
    }
    // 考虑实际线缆由于地理拐弯与路由中继的曲折系数 (Routing Detour Factor 约 1.35)
    let cable_distance = distance_km * 1.35;
    let rtt = (2.0 * cable_distance / SPEED_OF_LIGHT_IN_FIBER_KM_S) * 1000.0;
    (rtt * 10.0).round() / 10.0
}

// ============================================================
// 2. 全球与全国离线高精经纬度坐标地理空间引擎
// 模块已解耦迁移至 crate::geo_coordinates_catalog，提供 333+ 中国地级市与全球 200+ 国家全覆盖
// ============================================================

/// 自动探测使用者访问指定目标时所使用的本地活跃出站 IPv4 地址 (无需网络通信，由 OS 路由表内核判定)
pub fn detect_outbound_local_ip(target: &str) -> Ipv4Addr {
    use std::net::UdpSocket;
    let probe_target = if let Ok(ip) = target.parse::<Ipv4Addr>() {
        format!("{}:80", ip)
    } else {
        "114.114.114.114:80".to_string()
    };
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect(&probe_target).is_ok() {
            if let Ok(std::net::SocketAddr::V4(local)) = socket.local_addr() {
                return *local.ip();
            }
        }
    }
    Ipv4Addr::new(127, 0, 0, 1)
}

/// 判断指定 IPv4 字符串是否属于局域网私网范围 (RFC 1918 / Loopback / Link-Local)
pub fn is_lan_private_ip(ip_str: &str) -> bool {
    if let Ok(ip) = Ipv4Addr::from_str(ip_str) {
        let octets = ip.octets();
        if octets[0] == 10 {
            return true;
        }
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return true;
        }
        if octets[0] == 192 && octets[1] == 168 {
            return true;
        }
        if octets[0] == 127 {
            return true;
        }
        if octets[0] == 169 && octets[1] == 254 {
            return true;
        }
        if octets[0] == 100 && (64..=127).contains(&octets[1]) {
            return true;
        }
    }
    false
}

/// 推断局域网节点的子网 CIDR (如 192.168.31.0/24)
pub fn infer_lan_subnet_cidr(ip_str: &str) -> Option<String> {
    if let Ok(ip) = Ipv4Addr::from_str(ip_str) {
        let octets = ip.octets();
        if octets[0] == 192 && octets[1] == 168 {
            return Some(format!("192.168.{}.0/24", octets[2]));
        } else if octets[0] == 10 {
            return Some(format!("10.{}.{}.0/24", octets[1], octets[2]));
        } else if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return Some(format!("172.{}.{}.0/24", octets[1], octets[2]));
        } else if octets[0] == 127 {
            return Some("127.0.0.0/8".to_string());
        }
    }
    None
}

/// 局域网网络架构拓扑角色推断
pub fn infer_lan_topology_role(
    hop_num: u32,
    is_self: bool,
    is_destination: bool,
    ip_str: &str,
    _self_ip_str: &str,
) -> String {
    if is_self || hop_num == 0 {
        return "本机源端主机 (Probe Host)".to_string();
    }
    if is_destination {
        return "目标内网资产/主机 (Target Asset)".to_string();
    }
    if hop_num == 1 {
        if ip_str.ends_with(".1") || ip_str.ends_with(".254") {
            return "局域网默认网关 / 接入交换机 (Default Gateway)".to_string();
        }
        return "局域网首跳接入设备 (Access Switch)".to_string();
    }
    if ip_str.ends_with(".1") || ip_str.ends_with(".254") {
        return format!("跨网段核心路由 / VLAN 网关 #{}", hop_num);
    }
    format!("汇聚层交换节点 #{}", hop_num)
}

/// 基于 ip2region.xdb 离线库与操作系统路由表，精准解析使用者的自我 IP 及其地理位置 (Hop 0)
pub fn resolve_self_ip_geo(target: Option<&str>) -> (Ipv4Addr, TracerouteHop) {
    let local_ip = detect_outbound_local_ip(target.unwrap_or("114.114.114.114"));
    let local_ip_str = local_ip.to_string();
    let is_self_lan = is_lan_private_ip(&local_ip_str);
    let lan_role = Some("本机源端主机 (Probe Host)".to_string());
    let subnet_cidr = infer_lan_subnet_cidr(&local_ip_str);

    let engine = crate::lock_guard::lock_mutex(&GLOBAL_IP_ENGINE, "traceroute_engine::build_local_source_hop");
    let intel = engine.classify(&local_ip_str);

    let (country, province, city, isp, zone_name) = (
        intel.country.unwrap_or_else(|| "中国".to_string()),
        intel.province.unwrap_or_default(),
        intel.city.unwrap_or_default(),
        intel.isp.unwrap_or_else(|| "本地网络适配器".to_string()),
        intel.zone_name,
    );

    let geo = if intel.is_private || intel.is_loopback {
        // 内网或回环 IP: 初始锚定在本地基准
        Some(GLOBAL_GEO_CATALOG.get_local_anchor())
    } else {
        GLOBAL_GEO_CATALOG
            .lookup(&country, &province, &city)
            .or_else(|| Some(GLOBAL_GEO_CATALOG.get_local_anchor()))
    };

    let (latitude, longitude, has_geo) = if let Some(ref g) = geo {
        (g.latitude, g.longitude, true)
    } else {
        (0.0, 0.0, false)
    };

    let hop = TracerouteHop {
        hop: 0,
        hop_number: 0,
        ip: local_ip_str,
        rtt_ms: Some(0.0),
        is_timeout: false,
        geo,
        latitude,
        longitude,
        has_geo,
        country,
        province,
        city,
        isp,
        zone_name,
        cumulative_distance_km: 0.0,
        theoretical_fiber_rtt_ms: 0.0,
        is_self: true,
        is_lan: is_self_lan,
        lan_role,
        subnet_cidr,
        is_destination: false,
        bufferbloat_ratio: 1.0,
    };

    (local_ip, hop)
}

// ============================================================
// 3. 跨平台路由追踪执行机与流式事件推送
// ============================================================

/// 解析 tracert / traceroute 单行输出文本
/// 提取格式示例:
/// "  1     2 ms     1 ms     1 ms  192.168.1.1"
/// "  2     *        *        *     请求超时。"
/// "  5    14 ms    15 ms    14 ms  202.97.94.137"
pub fn parse_traceroute_line(line: &str) -> Option<(u32, Option<f64>, Option<String>, bool)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    // 第一个词必须是纯数字跳数 (Hop)
    let hop_num = match parts[0].parse::<u32>() {
        Ok(n) => n,
        Err(_) => return None,
    };

    // 检查是否全行超时 (*)
    let has_timeout = trimmed.contains('*') || trimmed.contains("请求超时") || trimmed.contains("Request timed out");
    let mut ip_found: Option<String> = None;
    let mut rtt_ms: Option<f64> = None;

    // 寻找行内符合 IPv4 规范的段
    for part in parts.iter().rev() {
        let clean = part.trim_matches(|c| c == '(' || c == ')' || c == '[' || c == ']');
        if Ipv4Addr::from_str(clean).is_ok() {
            ip_found = Some(clean.to_string());
            break;
        }
    }

    // 寻找时延数值 (例如 "14 ms" 或 "<1 ms")
    for i in 0..parts.len().saturating_sub(1) {
        if parts[i + 1].eq_ignore_ascii_case("ms") {
            let val_str = parts[i].trim_start_matches('<');
            if let Ok(v) = val_str.parse::<f64>() {
                rtt_ms = Some(v);
                break;
            }
        }
    }

    let is_timeout = has_timeout && ip_found.is_none();
    Some((hop_num, rtt_ms, ip_found, is_timeout))
}

/// 执行真实路由追踪并逐跳向前端推送流式事件
pub async fn execute_traceroute(
    app: Option<AppHandle>,
    target: String,
    max_hops: u32,
    timeout_ms: u64,
) -> Result<TracerouteReport, String> {
    let start_time_instant = Instant::now();
    let start_time_iso = chrono::Local::now().to_rfc3339();
    let hops_limit = max_hops.clamp(1, 64);
    let timeout = timeout_ms.clamp(200, 5000);

    // 1. 启动跨平台系统级跟踪进程
    // Windows 平台强制加 -d 参数禁止 DNS 解析，毫秒级快速返回
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = Command::new("tracert");
        c.creation_flags(0x08000000);
        c.arg("-d")
            .arg("-h")
            .arg(hops_limit.to_string())
            .arg("-w")
            .arg(timeout.to_string())
            .arg(&target);
        c
    };

    #[cfg(not(target_os = "windows"))]
    let mut cmd = {
        let mut c = Command::new("traceroute");
        c.arg("-n")
            .arg("-m")
            .arg(hops_limit.to_string())
            .arg("-w")
            .arg((timeout / 1000).max(1).to_string())
            .arg(&target);
        c
    };

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    CANCEL_TRACEROUTE.store(false, Ordering::SeqCst);
    TRACEROUTE_RUNNING.store(true, Ordering::SeqCst);

    let mut child = cmd.spawn().map_err(|e| {
        TRACEROUTE_RUNNING.store(false, Ordering::SeqCst);
        format!("启动路由追踪进程失败: {}", e)
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        TRACEROUTE_RUNNING.store(false, Ordering::SeqCst);
        "无法捕获进程标准输出".to_string()
    })?;
    let mut reader = BufReader::new(stdout);

    // 1. 立即探测并确定使用者的自我 IP (Self Local/Public IP) 与地理坐标 (Hop 0)
    let (self_ip, self_hop) = resolve_self_ip_geo(Some(&target));
    let mut last_coord = self_hop.geo.clone().unwrap_or_else(|| GLOBAL_GEO_CATALOG.get_local_anchor());
    let mut hops_records = Vec::new();
    let mut self_geo_refined = !self_ip.is_private() && !self_ip.is_loopback();

    // 立即向前端发射 Hop 0: 使用者自我主机源点
    if let Some(ref a) = app {
        let _ = a.emit("traceroute-hop-event", &self_hop);
    }
    hops_records.push(self_hop);

    let mut cumulative_dist = 0.0;
    let mut final_resolved_target_ip = target.clone();
    let mut is_completed = false;
    let mut last_valid_rtt = None;

    let mut line_buf = Vec::new();
    while let Ok(bytes_read) = reader.read_until(b'\n', &mut line_buf).await {
        if bytes_read == 0 {
            break; // 进程已到达 EOF
        }

        if CANCEL_TRACEROUTE.load(Ordering::SeqCst) {
            let _ = child.kill().await;
            break;
        }

        // 工业级容错解码: 优先尝试 UTF-8, 若包含 GBK/OEM 非法字节则使用 GB18030 保证 Windows 中文控制台输出 100% 完整解析
        let line = match std::str::from_utf8(&line_buf) {
            Ok(s) => s.to_string(),
            Err(_) => {
                let (cow, _, _) = encoding_rs::GB18030.decode(&line_buf);
                cow.into_owned()
            }
        };
        line_buf.clear();
        // 尝试从首部提取解析出的目标 IP (如 "通过最多 30 个跃点跟踪到 8.8.8.8 的路由:")
        if final_resolved_target_ip == target {
            for word in line.split_whitespace() {
                let clean = word.trim_matches(|c| c == '(' || c == ')' || c == '[' || c == ']' || c == ':');
                if let Ok(ip) = Ipv4Addr::from_str(clean) {
                    final_resolved_target_ip = ip.to_string();
                    break;
                }
            }
        }

        if let Some((hop_num, rtt, ip_opt, is_timeout)) = parse_traceroute_line(&line) {
            let hop_ip = ip_opt.unwrap_or_else(|| "*".to_string());
            if rtt.is_some() {
                last_valid_rtt = rtt;
            }

            // 联动 ip2region.xdb 获取详细地理与运营商情报
            let (country, province, city, isp, zone_name) = if hop_ip != "*" {
                let engine = crate::lock_guard::lock_mutex(&GLOBAL_IP_ENGINE, "traceroute_engine::trace_route_hop");
                let intel = engine.classify(&hop_ip);
                (
                    intel.country.unwrap_or_default(),
                    intel.province.unwrap_or_default(),
                    intel.city.unwrap_or_default(),
                    intel.isp.unwrap_or_default(),
                    intel.zone_name,
                )
            } else {
                (
                    "未知".to_string(),
                    String::new(),
                    String::new(),
                    "路由节点超时".to_string(),
                    "TIMEOUT_NODE".to_string(),
                )
            };

            // 联动全球离线地理坐标库
            let geo_coord = if hop_ip != "*" {
                if zone_name.contains("RFC1918") || zone_name.contains("私网") {
                    // 内网节点继承上一个有效坐标
                    Some(last_coord.clone())
                } else {
                    GLOBAL_GEO_CATALOG.lookup(&country, &province, &city)
                }
            } else {
                None
            };

            // 动态自适应校准使用者本机真实地理归属:
            // 如果使用者机器通过私网 NAT (如 192.168.x.x) 出网，链路上的第 1 个公网 IP 代表其城域网出口机房
            if !self_geo_refined && (self_ip.is_private() || self_ip.is_loopback()) {
                if let Some(ref curr_geo) = geo_coord {
                    if !zone_name.contains("RFC1918") && !zone_name.contains("私网") && country != "未知" {
                        hops_records[0].country = country.clone();
                        hops_records[0].province = province.clone();
                        hops_records[0].city = city.clone();
                        hops_records[0].isp = format!("{} (出口宽带)", isp);
                        hops_records[0].geo = Some(curr_geo.clone());
                        hops_records[0].latitude = curr_geo.latitude;
                        hops_records[0].longitude = curr_geo.longitude;
                        hops_records[0].has_geo = true;
                        last_coord = curr_geo.clone();
                        self_geo_refined = true;

                        // 重新向前端推送校准后的 Hop 0，使地图源点精准锚定在用户所在城市
                        if let Some(ref a) = app {
                            let _ = a.emit("traceroute-hop-event", &hops_records[0]);
                        }
                    }
                }
            }

            // 测地大圆距离积分与理论光纤时延计算
            let is_hop_lan = is_lan_private_ip(&hop_ip);
            let is_target_hop = (hop_ip == final_resolved_target_ip || hop_ip == target) && hop_ip != "*";

            if let Some(ref curr) = geo_coord {
                let hop_dist = calculate_haversine_distance_km(
                    last_coord.latitude,
                    last_coord.longitude,
                    curr.latitude,
                    curr.longitude,
                );
                // 局域网同城/同园区微观线缆模型: 若两点物理经纬度重合或为私网跳，按机房物理双绞线/跳线累加 0.035km (35m)
                let actual_dist = if is_hop_lan && hop_dist < 0.1 {
                    0.035
                } else {
                    hop_dist
                };
                cumulative_dist += actual_dist;
                last_coord = curr.clone();
            }

            let theoretical_fiber = estimate_theoretical_fiber_rtt_ms(cumulative_dist);
            let lan_role = if is_hop_lan {
                Some(infer_lan_topology_role(
                    hop_num,
                    false,
                    is_target_hop,
                    &hop_ip,
                    &self_ip.to_string(),
                ))
            } else {
                None
            };
            let subnet_cidr = infer_lan_subnet_cidr(&hop_ip);

            let (hop_lat, hop_lon, hop_has_geo) = if let Some(ref g) = geo_coord {
                (g.latitude, g.longitude, true)
            } else {
                (0.0, 0.0, false)
            };

            let bufferbloat_ratio = if let Some(rtt_val) = rtt {
                if theoretical_fiber > 0.05 {
                    (rtt_val / theoretical_fiber).max(1.0)
                } else {
                    1.0
                }
            } else {
                1.0
            };

            let hop_item = TracerouteHop {
                hop: hop_num,
                hop_number: hop_num,
                ip: hop_ip.clone(),
                rtt_ms: rtt,
                is_timeout,
                geo: geo_coord,
                latitude: hop_lat,
                longitude: hop_lon,
                has_geo: hop_has_geo,
                country,
                province,
                city,
                isp,
                zone_name,
                cumulative_distance_km: (cumulative_dist * 1000.0).round() / 1000.0,
                theoretical_fiber_rtt_ms: theoretical_fiber,
                is_self: false,
                is_lan: is_hop_lan,
                lan_role,
                subnet_cidr,
                is_destination: is_target_hop,
                bufferbloat_ratio,
            };

            // 边探测边向前端发射流式事件 (驱动前端地图实时动态绘制测地飞线)
            if let Some(ref a) = app {
                let _ = a.emit("traceroute-hop-event", &hop_item);
            }

            // 判定是否已抵达终点目标
            if hop_ip == final_resolved_target_ip && hop_ip != "*" {
                is_completed = true;
            }

            hops_records.push(hop_item);

            if is_completed {
                break;
            }
        }
    }

    let _ = child.wait().await;
    TRACEROUTE_RUNNING.store(false, Ordering::SeqCst);
    CANCEL_TRACEROUTE.store(false, Ordering::SeqCst);

    let duration = start_time_instant.elapsed().as_millis() as u64;

    let summary = if is_completed {
        format!(
            "测地线追踪成功完成: 共跃迁 {} 跳，端到端时延 {:.1}ms，累计大圆物理跨度 {:.1}km。",
            hops_records.len(),
            last_valid_rtt.unwrap_or(0.0),
            cumulative_dist
        )
    } else {
        format!(
            "测地线追踪达到最大跃点上限 ({} 跳)，已探测到累计物理跨度 {:.1}km。",
            hops_records.len(),
            cumulative_dist
        )
    };

    let is_lan_target = is_lan_private_ip(&final_resolved_target_ip) || is_lan_private_ip(&target);

    Ok(TracerouteReport {
        target,
        target_ip: final_resolved_target_ip,
        is_completed,
        total_hops: hops_records.len() as u32,
        end_to_end_rtt_ms: last_valid_rtt,
        total_distance_km: (cumulative_dist * 10.0).round() / 10.0,
        hops: hops_records,
        start_time: start_time_iso,
        duration_ms: duration,
        summary,
        is_lan_target,
    })
}

// ============================================================
// 4. Tauri IPC 对外指令
// ============================================================

#[tauri::command]
pub async fn start_traceroute_cmd(
    app: AppHandle,
    target: String,
    max_hops: Option<u32>,
    timeout_ms: Option<u64>,
) -> Result<TracerouteReport, String> {
    execute_traceroute(
        Some(app),
        target,
        max_hops.unwrap_or(30),
        timeout_ms.unwrap_or(1000),
    )
    .await
}

#[tauri::command]
pub fn lookup_ip_geo_coordinates_cmd(ip: String) -> Result<Option<GeoCoordinates>, String> {
    let engine = GLOBAL_IP_ENGINE.lock().map_err(|e| e.to_string())?;
    let intel = engine.classify(&ip);

    let country = intel.country.unwrap_or_default();
    let province = intel.province.unwrap_or_default();
    let city = intel.city.unwrap_or_default();

    if intel.is_private || intel.is_loopback {
        return Ok(Some(GLOBAL_GEO_CATALOG.get_local_anchor()));
    }

    Ok(GLOBAL_GEO_CATALOG.lookup(&country, &province, &city))
}

#[tauri::command]
pub fn get_self_ip_geo_cmd(target: Option<String>) -> Result<TracerouteHop, String> {
    let (_, self_hop) = resolve_self_ip_geo(target.as_deref());
    Ok(self_hop)
}

#[tauri::command]
pub async fn stop_traceroute_cmd() -> Result<bool, String> {
    CANCEL_TRACEROUTE.store(true, Ordering::SeqCst);
    Ok(true)
}

// ============================================================
// 5. 严苛工业单元测试套件 (DoD 质量门禁)
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_outbound_local_ip_and_self_geo() {
        // 测试本地出站 IP 探测 (路由表内核瞬时裁决)
        let local_ip = detect_outbound_local_ip("8.8.8.8");
        assert!(!local_ip.is_unspecified(), "Local outbound IP must not be 0.0.0.0");

        // 测试自我 IP 解析与 Hop 0 结构
        let (ip, self_hop) = resolve_self_ip_geo(Some("8.8.8.8"));
        assert_eq!(ip, local_ip);
        assert_eq!(self_hop.hop, 0);
        assert!(self_hop.is_self);
        assert_eq!(self_hop.rtt_ms, Some(0.0));
        assert!(self_hop.geo.is_some());
    }

    #[test]
    fn test_haversine_distance_accuracy() {
        // 北京 (39.9042, 116.4074) 到 上海 (31.2304, 121.4737)
        // 权威测地线距离约为 1068 km
        let dist_bj_sh = calculate_haversine_distance_km(39.9042, 116.4074, 31.2304, 121.4737);
        assert!(
            (dist_bj_sh - 1068.0).abs() < 25.0,
            "Beijing to Shanghai distance must be ~1068km, got {:.2}",
            dist_bj_sh
        );

        // 北京到东京 (35.6762, 139.6503) 约为 2100 km
        let dist_bj_tyo = calculate_haversine_distance_km(39.9042, 116.4074, 35.6762, 139.6503);
        assert!(
            (dist_bj_tyo - 2100.0).abs() < 50.0,
            "Beijing to Tokyo distance must be ~2100km, got {:.2}",
            dist_bj_tyo
        );

        // 自测距离为 0
        let zero_dist = calculate_haversine_distance_km(39.9042, 116.4074, 39.9042, 116.4074);
        assert_eq!(zero_dist, 0.0);
    }

    #[test]
    fn test_fiber_speed_propagation_rtt() {
        // 1000 km 物理距离的光纤往返理论时延
        let rtt = estimate_theoretical_fiber_rtt_ms(1000.0);
        // (2 * 1350km / 200,000 km/s) * 1000 = 13.5 ms
        assert!(rtt >= 10.0 && rtt <= 18.0, "1000km fiber RTT should be ~13.5ms, got {}", rtt);
    }

    #[test]
    fn test_geo_catalog_hierarchical_fallback() {
        let catalog = &GLOBAL_GEO_CATALOG;

        // 1. 精准城市匹配: 深圳
        let sz = catalog.lookup("中国", "广东", "深圳市").unwrap();
        assert_eq!(sz.city, "深圳市");
        assert!((sz.latitude - 22.54).abs() < 0.1);

        // 2. 省份二级回退: 无法识别具体县城时匹配省会
        let fallback_province = catalog.lookup("中国", "四川省", "某个偏远工业园区").unwrap();
        assert_eq!(fallback_province.province, "四川省");
        assert!((fallback_province.latitude - 30.57).abs() < 0.1);

        // 3. 国家三级回退: 仅知国家
        let fallback_country = catalog.lookup("德国", "", "").unwrap();
        assert_eq!(fallback_country.country, "德国");

        // 4. 本地锚点
        let local = catalog.get_local_anchor();
        assert_eq!(local.city, "本地探针终端");
    }

    #[test]
    fn test_parse_traceroute_output_lines() {
        // 格式 1: 正常跳
        let l1 = "  5    14 ms    15 ms    14 ms  202.97.94.137";
        let (hop1, rtt1, ip1, timeout1) = parse_traceroute_line(l1).unwrap();
        assert_eq!(hop1, 5);
        assert_eq!(rtt1, Some(14.0));
        assert_eq!(ip1.unwrap(), "202.97.94.137");
        assert_eq!(timeout1, false);

        // 格式 2: 超时跳 (*)
        let l2 = "  7     *        *        *     请求超时。";
        let (hop2, rtt2, ip2, timeout2) = parse_traceroute_line(l2).unwrap();
        assert_eq!(hop2, 7);
        assert_eq!(rtt2, None);
        assert_eq!(ip2, None);
        assert_eq!(timeout2, true);

        // 格式 3: 杂质行/标题行忽略
        let l3 = "通过最多 30 个跃点跟踪到 8.8.8.8 的路由:";
        assert!(parse_traceroute_line(l3).is_none());
    }

    #[test]
    fn test_edge_zero_and_boundary_coordinates() {
        // 对跖点极限距离 (北极到南极)
        let antipodal = calculate_haversine_distance_km(90.0, 0.0, -90.0, 0.0);
        // 半球周长约为 20015 km
        assert!((antipodal - 20015.0).abs() < 50.0);
    }

    #[test]
    fn test_lan_private_ip_and_topology_roles() {
        // 1. 局域网私网 IP 判定 (RFC 1918 / Loopback)
        assert!(is_lan_private_ip("192.168.1.1"));
        assert!(is_lan_private_ip("10.0.0.1"));
        assert!(is_lan_private_ip("172.16.10.50"));
        assert!(is_lan_private_ip("127.0.0.1"));
        assert!(!is_lan_private_ip("8.8.8.8"));
        assert!(!is_lan_private_ip("114.114.114.114"));

        // 2. 子网推断
        assert_eq!(infer_lan_subnet_cidr("192.168.31.205"), Some("192.168.31.0/24".to_string()));
        assert_eq!(infer_lan_subnet_cidr("10.10.1.1"), Some("10.10.1.0/24".to_string()));

        // 3. 局域网拓扑角色推断
        let role_self = infer_lan_topology_role(0, true, false, "192.168.31.205", "192.168.31.205");
        assert!(role_self.contains("本机源端"));

        let role_gw = infer_lan_topology_role(1, false, false, "192.168.31.1", "192.168.31.205");
        assert!(role_gw.contains("局域网默认网关"));

        let role_target = infer_lan_topology_role(3, false, true, "10.0.0.88", "192.168.31.205");
        assert!(role_target.contains("目标内网资产"));
    }
}
