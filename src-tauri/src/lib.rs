pub mod lock_guard;
pub mod sniffer;
pub mod analyzer;
pub mod forensics;
pub mod hardware;
pub mod serial;
pub mod bus_intelligence;
pub mod dpi;
pub mod cloud;
pub mod config;
// Sprint 1 新增模块
pub mod throttle;
pub mod honeypot;
pub mod active_probe;
pub mod metrics;
pub mod usb;
pub mod discovery;
// Sprint 3: 专业流量分析与持久化模块
pub mod pcap_engine;
pub mod stream_reassembly;
pub mod ip_intelligence;
pub mod export_engine;
pub mod ip_downloader;
// 等保三级 (Level 3) 关键扩展模块
pub mod syslog;
pub mod rbac;
pub mod baseline_learning;
// 全息上网行为监测与外联合规审计模块
pub mod web_audit;
// 流量解密与过滤级防火墙系统
pub mod tls_keylog;
pub mod firewall_filter;
pub mod tls_proxy;
pub mod passive_tls_decryptor;
// 四维安全审查与合规体系 (网络安全/数据安全/保密安全/脱敏清洗)
pub mod audit_network;
pub mod audit_data_security;
pub mod audit_confidentiality;
pub mod audit_sanitizer;
// 工业协议插件化解包器扩展子系统 (SEMI/Honeywell/Yokogawa/Schneider/Beckhoff 及长尾自定义)
pub mod industrial_plugin;
// 工业协议深度知识库与符号语义字典
pub mod industrial_knowledge;
// 单实例互斥保护与崩溃诊断子系统
pub mod instance_guard;
// 工业级 Display Filter 抽象语法树 (AST) 编译引擎
pub mod filter_ast;
// Aho-Corasick 高性能多模式威胁特征检测引擎 (对标 Snort / Suricata Hyperscan)
pub mod threat_detector;
// 流式分页与分卷落盘解耦子系统 (对标 dumpcap)
pub mod stream_paging;
// Wireshark / TShark 3000+ 全协议通用解剖桥接引擎 (双轨万能解剖架构)
pub mod tshark_bridge;
// 底层抓包驱动与协议解剖运行环境诊断引擎
pub mod env_inspector;
// 原生递归语法树解剖器与长尾未知协议启发式盲探引擎 (对标 Wireshark Heuristic Dissector & TLV Tree)
pub mod dpi_heuristic;
// 工业控制事务双向配对追踪机与 Session 事件驱动总线 (对标 Zeek / Bro Event Engine)
pub mod industrial_transaction;
// 全协议标准目录与硬件厂商 OUI 特征知识库 (对标 Wireshark 3,200+ 规约库、services 与 manuf)
pub mod protocol_catalog;
pub mod protocol_registry_generated;
pub mod industrial_gb_dissector;
pub mod simd_matcher;
// Suricata/Snort 工业入侵规则 DSL 扩展编译器与两阶段执行引擎
pub mod threat_dsl;
pub use threat_dsl::{
    get_suricata_dsl_metrics_cmd,
    load_suricata_dsl_rules_cmd,
};
// 工控细粒度访问控制列表 (ICS-ACL) 状态机引擎
pub mod ics_acl;
// 国密 GM/T 0024-2014 SSL VPN 协议深度解析器 (对标涉密工控商密安全标准)
pub mod gm_ssl;
// 高并发无锁密钥环持久化与跨 TCP 分段握手重组引擎 (对标 mitmproxy / Wireshark TLS)
pub mod tls_keyring;
// JA3/JA3S 与 JA4/JA4S 全标准 TLS 指纹提取与已知威胁 C2 碰撞引擎 (对标 Salesforce JA3 & FoxIO JA4+)
pub mod tls_fingerprint;
pub use tls_fingerprint::get_tls_fingerprint_telemetry_cmd;
// 以太网-串口-USB 跨总线纳秒时钟对齐与级联超时诊断引擎 (对标 sigrok / PulseView)
pub mod cross_bus_diagnostic;
// 轻量级内存多分辨率时序聚合器与工业资产通信热力雷达 (对标 Sniffnet / ntopng)
pub mod metrics_timeseries;
// 图灵完备安全分析脚本引擎与事件驱动沙箱 (对标 Zeek Scripting Framework & Wireshark Lua Dissector Engine)
pub mod script_engine;
pub use script_engine::evaluate_audit_script_cmd;
// 高精度脱机时间戳调度重放与虚拟网络接口注入引擎 (对标 tcpreplay)
pub mod pcap_replay;
// 双缓冲无锁有界内存池与零拷贝报文调度引擎 (对标 DPDK rte_mempool & PF_RING)
pub mod zero_copy_pool;
// 全协议原生逐字段语义解剖器集与长尾自省展开引擎 (对标 Wireshark 3000+ 原生解剖器)
pub mod protocol_dissectors;
// SNMP MIB 交换机物理端口联动、万级主机分级聚合拓扑树与分布式探针汇聚引擎 (对标 ntopng / RFC 1213 / RFC 2863)
pub mod snmp_topology;
// 跨平台自动版本检查与在线更新引擎
pub mod updater;
pub use snmp_topology::{
    collapse_all_topology_cmd,
    drill_down_topology_node_cmd,
    get_distributed_probe_cluster_cmd,
    get_hierarchical_topology_viewport_cmd,
    locate_asset_switch_port_cmd,
    roll_up_topology_node_cmd,
};
pub use baseline_learning::{
    get_macro_calendar_baseline_status_cmd,
    import_statutory_calendar_date_cmd,
    infer_unsupervised_day_regime_cmd,
};
// 基于 UDP 的 HTTP/3 (QUIC) 深度多流解密与解剖引擎 (RFC 9000 / RFC 9001 / RFC 9114)
pub mod quic_engine;
pub use quic_engine::{
    get_quic_streams_cmd,
    get_quic_telemetry_cmd,
    inspect_and_decrypt_quic_packet_cmd,
};
// CAN / CAN-FD 现场总线原生解剖与跨以太网网关因果诊断引擎 (ISO 11898-1:2015 / SocketCAN)
pub mod can_diagnostic;
pub use can_diagnostic::{
    dissect_can_packet_cmd,
    get_can_bus_health_cmd,
    get_can_causal_records_cmd,
};
// 物理硬件逻辑分析仪原生采样位流驱动与纳秒电气级信号解调分析引擎 (sigrok / PulseView / Saleae Logic 对标)
pub mod hardware_logic_analyzer;
pub use hardware_logic_analyzer::{
    capture_sump_logic_samples_cmd,
    decode_multibus_vcd_cmd,
    demodulate_physical_uart_cmd,
    evaluate_signal_integrity_cmd,
    probe_sump_logic_analyzer_cmd,
};
// 基于 eBPF / XDP 的内核级高性能 TCP 流线速分流与旁路直通引擎 (TASK-41)
pub mod xdp_engine;
pub use xdp_engine::{
    apply_xdp_policy_preset_cmd,
    evaluate_xdp_packet_cmd,
    get_xdp_bypass_metrics_cmd,
    mark_flow_bypassed_cmd,
};
// Windows Filtering Platform (WFP via fwpuclnt.dll) 内核态网络过滤引擎
pub mod wfp_engine;
// 免 Npcap Windows 内置 NDIS-PacketCapture ETW 原始 L2 以太网帧捕获引擎
pub mod win_ndis_capture;
// 跨平台内建驱动级串口透明拦截引擎 (POSIX PTY / Win32 NamedPipe / RFC2217 / WDM IRP Tap)
pub mod serial_intercept;
// 工业级流式磁盘大文件 Myers 线性分治比对、目录比较与双向原子合并引擎
pub mod file_diff_merge;
// 原生桌面系统文件系统弹窗 (Open/Folder/SaveAs)、原子落盘与资源管理器交互引擎
pub mod desktop_native;
// 基于 Glushkov 构造算法与位并行 (Bit-Parallel) 的 Hyperscan 风格高性能正则/多模式匹配引擎 (TASK-42)
pub mod glushkov_engine;
pub use glushkov_engine::{
    get_glushkov_engine_metrics_cmd,
    scan_payload_glushkov_cmd,
    reset_glushkov_engine_metrics_cmd,
};
// 测地线可视路由追踪与地球地理情报引擎 (TASK-43)
pub mod traceroute_engine;
pub use traceroute_engine::{
    start_traceroute_cmd,
    lookup_ip_geo_coordinates_cmd,
    get_self_ip_geo_cmd,
};

// Wi-Fi / 802.11 物理与链路层专业监测
pub mod wifi_monitor;
pub use wifi_monitor::{
    get_wifi_telemetry_cmd,
    reset_wifi_telemetry_cmd,
};

// IEEE 802.1Q / 802.1ad VLAN 与 QinQ 专业监测
pub mod vlan_monitor;
pub use vlan_monitor::{
    get_vlan_telemetry_cmd,
    reset_vlan_telemetry_cmd,
};

// COM / USB 深度开发、数字信号比对与巡检报告引擎
pub use bus_intelligence::{
    analyze_mcu_console_lines_cmd,
    calc_uart_baud_error_cmd,
    compute_serial_checksum_cmd,
    compute_step_response_metrics_cmd,
    compute_waveform_fft_cmd,
    decode_modbus_32bit_word_cmd,
    delete_serial_auto_rule_cmd,
    delete_waveform_baseline_cmd,
    export_bus_inspection_report_cmd,
    export_serial_stream_log_cmd,
    export_usb_usbpcap_pcap_cmd,
    generate_bus_inspection_report_cmd,
    get_bus_intelligence_snapshot_cmd,
    list_waveform_baselines_cmd,
    parse_binary_struct_batch_cmd,
    pick_and_import_usb_pcap_cmd,
    pick_and_send_serial_bin_file_cmd,
    save_waveform_baseline_cmd,
    smart_compare_waveforms_cmd,
    solve_mcu_timer_psc_arr_cmd,
    start_serial_periodic_tx_cmd,
    stop_serial_periodic_tx_cmd,
    upsert_serial_auto_rule_cmd,
};

// 蓝牙 BR/EDR / BLE / HCI 专业监测与近场空间感知
pub mod bluetooth_monitor;
pub use bluetooth_monitor::{
    compare_bluetooth_realtime_vs_history_cmd,
    export_bluetooth_btsnoop_cmd,
    get_bluetooth_telemetry_cmd,
    pick_and_import_bluetooth_btsnoop_cmd,
    read_ble_gatt_characteristic_cmd,
    reset_bluetooth_telemetry_cmd,
    save_bluetooth_baseline_cmd,
    scan_ble_gatt_services_cmd,
    start_bthport_etw_capture_cmd,
    start_continuous_ble_monitor_cmd,
    stop_bthport_etw_capture_cmd,
    stop_continuous_ble_monitor_cmd,
};

// 无线与 VLAN 统一诊断分析器
pub mod wireless_analyzer;
pub use wireless_analyzer::dissect_wireless_or_vlan_hex_cmd;

// 全球网络空间地理态势与流量测绘引擎
pub mod geo_map_engine;
pub use geo_map_engine::{
    get_global_geo_map_data_cmd,
    resolve_real_traffic_geo_cmd,
    probe_active_os_sockets_cmd,
};

// 工业级网络调试助手通信引擎 (对标 NetAssist / TCP Client / TCP Server / UDP)
pub mod net_assist;
pub use net_assist::{
    start_net_assist_session_cmd,
    stop_net_assist_session_cmd,
    send_net_assist_data_cmd,
    get_net_assist_clients_cmd,
    calculate_checksum_cmd,
    get_local_ip_addresses_cmd,
};

// 网络深度主动扫描、Wireshark 级多维统计、基线/.pcap 比对与行业审计报告引擎
pub mod net_intelligence;
pub use net_intelligence::{
    run_network_port_scan_cmd,
    analyze_network_traffic_stats_cmd,
    reset_live_net_stats_cmd,
    save_network_baseline_cmd,
    get_network_baseline_cmd,
    compare_network_with_baseline_cmd,
    pick_and_compare_network_pcap_cmd,
    export_network_audit_report_cmd,
};

use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use tauri::Emitter;

/// 全局探针运行状态 (多线程控制开关)
pub static PROBE_RUNNING: Lazy<Arc<Mutex<bool>>> = Lazy::new(|| Arc::new(Mutex::new(false)));

// ============================================================
// Tauri Command: 探针主引擎
// ============================================================

#[tauri::command]
async fn start_capture(app: tauri::AppHandle, iface: String, bpf_filter: Option<String>) -> Result<String, String> {
    let mut running = crate::lock_guard::lock_mutex(&PROBE_RUNNING, "lib::start_capture");
    if *running {
        return Ok("[PROBE] 探针引擎已在运行，无需重复启动".to_string());
    }
    *running = true;
    drop(running);

    let app_clone = app.clone();
    let iface_clone = iface.clone();
    let filter = bpf_filter.unwrap_or_default();

    // 0. 加载配置（config.json 驱动端口表/探测目标/阈值，缺失时自动生成默认配置）
    let cfg = config::get_config();

    // 0a. 威胁防御阈值初始化（对齐 Python threat_defense.max_packets_per_sec）
    if cfg.enterprise_features.threat_defense.enabled {
        throttle::update_throttle_config(
            cfg.enterprise_features.threat_defense.max_packets_per_sec,
            cfg.enterprise_features.threat_defense.max_packets_per_sec,
        );
    }

    // 1. 启动 Npcap L2 全流量嗅探引擎（专属线程）
    std::thread::spawn(move || {
        sniffer::run_sniffer_pipeline(app_clone, &iface_clone, &filter);
    });

    // 2. 启动物理硬件监控（USB + COM 串口）
    let app_hw = app.clone();
    std::thread::spawn(move || {
        hardware::run_hardware_monitor(app_hw);
    });

    // 3. 启动 Prometheus 指标服务（端口由 config.json fleet_management.api_port 驱动）
    let app_metrics = app.clone();
    let api_port = if cfg.enterprise_features.fleet_management.enabled {
        cfg.enterprise_features.fleet_management.api_port
    } else {
        9091
    };
    metrics::start_metrics_server(app_metrics, api_port);

    // 3a. 主动探测目标自动拉流（对齐 Python active_probes 表：连接→持续读→ACTIVE_PULL 记录）
    if !cfg.active_probes.is_empty() {
        let _ = app.emit(
            "system-log",
            format!("[CONFIG] 启动 {} 个主动拉流探测目标（active_probes）", cfg.active_probes.len()),
        );
        for probe in &cfg.active_probes {
            if probe.protocol.eq_ignore_ascii_case("tcp") {
                active_probe::start_stream_pull(
                    app.clone(),
                    probe.host.clone(),
                    probe.port,
                    probe.reconnect_interval,
                );
            }
        }
    }

    // 4. 启动 DPI 动态字典热监听（自动感知 protocol_signatures.json 变化）
    let app_dpi = app.clone();
    let sig_path = {
        // 优先查找与二进制同目录的签名文件，否则使用当前工作目录
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));
        let local_path = exe_dir
            .map(|d| d.join("protocol_signatures.json"))
            .filter(|p| p.exists());
        local_path
            .unwrap_or_else(|| std::path::PathBuf::from("protocol_signatures.json"))
            .to_string_lossy()
            .to_string()
    };
    dpi::start_hot_reload_watcher(sig_path, app_dpi);

    // 5. 启动司法哈希封条引擎（周期由 config.json sealing_interval_secs 驱动，默认 60s）
    //    对齐 Python ForensicIntegritySealer 的完整证据文件清单（文件名注册表运行时求值）
    let app_forensic = app.clone();
    forensics::start_periodic_sealing(
        app_forensic,
        cfg.sealing_interval_secs.max(1),
        forensics::evidence_files(),
        "forensic_evidence_chain.sha256".to_string(),
    );

    let _ = app.emit("system-log", format!("[PROBE] 全能探针引擎已启动 -> 接口: {}", iface));
    sniffer::resume_sniffer();
    Ok(iface)
}

#[tauri::command]
async fn pause_capture(app: tauri::AppHandle) -> Result<String, String> {
    sniffer::pause_sniffer();
    let _ = app.emit("sniffer-state-changed", "paused");
    let _ = app.emit("system-log", "[PROBE] ⏸️ 网络嗅探已暂停（底层网卡驱动保持热备，数据流已挂起）".to_string());
    Ok("paused".to_string())
}

#[tauri::command]
async fn resume_capture(app: tauri::AppHandle) -> Result<String, String> {
    sniffer::resume_sniffer();
    let _ = app.emit("sniffer-state-changed", "running");
    let _ = app.emit("system-log", "[PROBE] ▶️ 网络嗅探已恢复（毫秒级无缝继续抓包）".to_string());
    Ok("running".to_string())
}

#[tauri::command]
async fn stop_capture(app: tauri::AppHandle) -> Result<String, String> {
    let mut running = crate::lock_guard::lock_mutex(&PROBE_RUNNING, "lib::stop_capture");
    *running = false;
    drop(running);

    sniffer::resume_sniffer();

    // 同步停止物理串口与 USB 嗅探
    serial::stop_serial_probe(None);
    usb::stop_usb_sniffer();
    // 同步停止蜜罐引擎
    honeypot::stop_honeypot();
    // 同步停止主动拉流引擎
    active_probe::stop_stream_pull();
    // 同步停止云端上报（优雅关闭发送队列）
    cloud::stop_cloud_streaming();

    let _ = app.emit("system-log", "[PROBE] 探针引擎已停止");
    Ok("[PROBE] 探针引擎已停止".to_string())
}

#[tauri::command]
async fn inject_raw_packet(raw_hex: String, iface: String) -> Result<String, String> {
    sniffer::inject_packet(&raw_hex, &iface)
}

#[tauri::command]
async fn list_interfaces() -> Result<Vec<String>, String> {
    sniffer::list_network_interfaces()
}

#[tauri::command]
async fn list_serial_ports() -> Result<Vec<String>, String> {
    Ok(serial::list_available_serial_ports())
}

#[tauri::command]
async fn list_serial_ports_detail() -> Result<Vec<serial::SerialPortDetail>, String> {
    Ok(serial::list_available_serial_ports_detail())
}

#[tauri::command]
async fn list_active_serial_probes() -> Result<Vec<serial::ActiveSerialProbeInfo>, String> {
    Ok(serial::list_active_serial_probes())
}

#[tauri::command]
async fn list_active_serial_bridges() -> Result<Vec<serial::ActiveSerialBridgeInfo>, String> {
    Ok(serial::list_active_serial_bridges())
}

#[tauri::command]
async fn start_serial_capture(app: tauri::AppHandle, port: String, baud_rate: u32) -> Result<String, String> {
    serial::start_serial_probe(app, &port, baud_rate)?;
    Ok(format!("[SERIAL] 串口 {} @ {} bps 嗅探已启动", port, baud_rate))
}

#[tauri::command]
async fn start_serial_capture_with_config(
    app: tauri::AppHandle,
    port: String,
    config: serial::SerialCommunicationConfig,
) -> Result<String, String> {
    let msg = serial::start_serial_probe_with_config(app, &port, config)?;
    Ok(msg)
}

#[tauri::command]
async fn get_serial_modem_status(port: String) -> Result<serial::SerialModemStatus, String> {
    serial::get_serial_modem_status(&port)
}

#[tauri::command]
async fn set_serial_pin_state(
    port: String,
    rts: Option<bool>,
    dtr: Option<bool>,
) -> Result<(), String> {
    serial::set_serial_pin_state(&port, rts, dtr)
}

#[tauri::command]
async fn start_serial_bridge_cmd(
    app: tauri::AppHandle,
    port_a: String,
    config_a: serial::SerialCommunicationConfig,
    port_b: String,
    config_b: serial::SerialCommunicationConfig,
) -> Result<String, String> {
    serial::start_serial_bridge(app, &port_a, config_a, &port_b, config_b)
}

#[tauri::command]
async fn stop_serial_bridge_cmd(bridge_id: Option<String>) -> Result<String, String> {
    Ok(serial::stop_serial_bridge(bridge_id.as_deref()))
}

#[tauri::command]
async fn get_serial_intercept_capabilities_cmd() -> Result<serial_intercept::SerialInterceptCapabilities, String> {
    Ok(serial_intercept::get_serial_intercept_capabilities())
}

#[tauri::command]
async fn list_active_intercept_sessions_cmd() -> Result<Vec<serial_intercept::InterceptSessionInfo>, String> {
    Ok(serial_intercept::list_active_intercept_sessions())
}

#[tauri::command]
async fn start_rfc2217_intercept_gateway_cmd(
    app: tauri::AppHandle,
    listen_port: u16,
    target_port: String,
    config: serial::SerialCommunicationConfig,
) -> Result<serial_intercept::InterceptSessionInfo, String> {
    serial_intercept::start_rfc2217_intercept_gateway(Some(app), listen_port, &target_port, config)
}

#[tauri::command]
async fn start_windows_named_pipe_intercept_cmd(
    app: tauri::AppHandle,
    pipe_suffix: String,
    target_port: String,
    config: serial::SerialCommunicationConfig,
) -> Result<serial_intercept::InterceptSessionInfo, String> {
    serial_intercept::start_windows_named_pipe_intercept(Some(app), &pipe_suffix, &target_port, config)
}

#[tauri::command]
async fn start_unix_pty_intercept_cmd(
    app: tauri::AppHandle,
    symlink_alias: Option<String>,
    target_port: String,
    config: serial::SerialCommunicationConfig,
) -> Result<serial_intercept::InterceptSessionInfo, String> {
    serial_intercept::start_unix_pty_intercept(Some(app), symlink_alias.as_deref(), &target_port, config)
}

#[tauri::command]
async fn start_kernel_filter_tap_cmd(app: tauri::AppHandle) -> Result<serial_intercept::InterceptSessionInfo, String> {
    serial_intercept::start_kernel_filter_tap(Some(app))
}

#[tauri::command]
async fn smart_start_serial_intercept_cmd(
    app: tauri::AppHandle,
    target_port: String,
    prefer_mode: Option<String>,
    config: serial::SerialCommunicationConfig,
) -> Result<serial_intercept::SmartInterceptOutcome, String> {
    Ok(serial_intercept::smart_start_serial_intercept(
        Some(app),
        &target_port,
        prefer_mode.as_deref(),
        config,
    ))
}

#[tauri::command]
async fn stop_intercept_session_cmd(session_id: Option<String>) -> Result<String, String> {
    Ok(serial_intercept::stop_intercept_session(session_id.as_deref()))
}

#[tauri::command]
async fn stop_serial_capture(port: Option<String>) -> Result<String, String> {
    let msg = serial::stop_serial_probe(port.as_deref());
    Ok(msg)
}

#[tauri::command]
async fn start_usb_capture(app: tauri::AppHandle, hub_device: Option<String>) -> Result<String, String> {
    usb::start_usb_sniffer_on_hub(app, hub_device)
}

#[tauri::command]
async fn list_usbpcap_hubs_cmd() -> Result<Vec<usb::UsbPcapHubInfo>, String> {
    Ok(usb::list_usbpcap_hubs())
}

#[tauri::command]
async fn get_captured_usb_descriptor_cmd(vid: String, pid: String) -> Result<String, String> {
    usb::get_captured_usb_descriptor_hex(&vid, &pid)
}

/// Tauri 接口：解析 IEEE 1364 VCD 逻辑分析仪物理电平波形成为 UART 字节流
#[tauri::command]
async fn decode_vcd_uart_waveform_cmd(
    vcd_content: String,
    target_signal: String,
    baud_rate: u32,
    parity: Option<String>,
) -> Result<serial::VcdUartDecodedResult, String> {
    tokio::task::spawn_blocking(move || {
        serial::decode_vcd_uart_waveform_with_options(
            &vcd_content,
            &target_signal,
            baud_rate,
            parity.as_deref(),
        )
    })
    .await
    .map_err(|e| format!("VCD 解调线程异常: {}", e))?
}

#[tauri::command]
async fn stop_usb_capture() -> Result<String, String> {
    usb::stop_usb_sniffer();
    Ok("[USB] USB 嗅探已停止".to_string())
}

#[tauri::command]
async fn list_usb_devices() -> Result<Vec<usb::UsbDeviceInfo>, String> {
    Ok(usb::scan_connected_usb_devices())
}

#[tauri::command]
async fn is_honeypot_running_cmd() -> Result<bool, String> {
    let running = crate::lock_guard::lock_mutex(&honeypot::HONEYPOT_RUNNING, "lib::is_honeypot_running_cmd");
    Ok(*running)
}

#[tauri::command]
async fn parse_usb_descriptor_tree_cmd(raw_hex: String) -> Result<usb::UsbDescriptorTree, String> {
    let raw_bytes = hex::decode(raw_hex.replace(' ', "")).map_err(|e| format!("HEX 解码失败: {}", e))?;
    usb::parse_usb_descriptor_tree(&raw_bytes)
}

#[tauri::command]
async fn get_io_graph_series_cmd(
    window_seconds: u32,
    bus_filter: Option<String>,
) -> Result<analyzer::IoGraphSeries, String> {
    Ok(analyzer::get_io_graph_series_filtered(window_seconds, bus_filter.as_deref()))
}

#[tauri::command]
async fn get_cross_bus_correlations_cmd() -> Result<Vec<analyzer::CrossBusCorrelationRecord>, String> {
    Ok(analyzer::get_cross_bus_correlations())
}

#[tauri::command]
async fn send_serial_data_cmd(
    app: tauri::AppHandle,
    port: String,
    baud_rate: u32,
    payload: String,
    is_hex: bool,
) -> Result<usize, String> {
    let raw_bytes = if is_hex {
        hex::decode(payload.replace(' ', "")).map_err(|e| format!("HEX 解码失败: {}", e))?
    } else {
        payload.into_bytes()
    };
    serial::send_serial_data(app, &port, baud_rate, &raw_bytes)
}

#[tauri::command]
async fn send_serial_probe_frame_cmd(
    app: tauri::AppHandle,
    port: String,
    baud_rate: u32,
) -> Result<String, String> {
    serial::send_serial_probe_frame(app, &port, baud_rate)
}

#[tauri::command]
async fn send_port_transceive_cmd(
    app: tauri::AppHandle,
    target_ip: String,
    target_port: u16,
    transport: String,
    payload_hex: String,
    timeout_ms: Option<u64>,
) -> Result<active_probe::PortTransceiveResult, String> {
    let to = timeout_ms.unwrap_or(2000);
    Ok(active_probe::send_and_receive_port_data(app, &target_ip, target_port, &transport, &payload_hex, to).await)
}

#[tauri::command]
async fn run_icmp_ping_cmd(target_ip: String, timeout_ms: Option<u64>) -> Result<active_probe::ProbeResult, String> {
    let to = timeout_ms.unwrap_or(3000);
    Ok(active_probe::run_icmp_ping(&target_ip, to).await)
}

#[tauri::command]
async fn replay_l4_packet_cmd(target_ip: String, target_port: u16, transport: String, payload_hex: String) -> Result<String, String> {
    active_probe::replay_l4_packet(&target_ip, target_port, &transport, &payload_hex).await
}

#[tauri::command]
async fn run_matrix_compare(payloads: Vec<String>) -> Result<analyzer::SmartDiffResult, String> {
    analyzer::smart_diff_payloads(payloads)
}

#[tauri::command]
async fn run_matrix_compare_labeled_cmd(payloads: Vec<String>, labels: Vec<String>) -> Result<analyzer::SmartDiffResult, String> {
    analyzer::smart_diff_payloads_labeled(payloads, labels)
}

#[tauri::command]
async fn save_baseline_payloads_cmd(payloads: Vec<String>) -> Result<usize, String> {
    analyzer::save_baseline_payloads(payloads)
}

#[tauri::command]
async fn load_baseline_payloads_cmd() -> Result<Vec<String>, String> {
    analyzer::load_baseline_payloads()
}

#[tauri::command]
async fn compare_with_historical_baseline_cmd(current_payloads: Vec<String>) -> Result<analyzer::SmartDiffResult, String> {
    analyzer::compare_with_historical_baseline(current_payloads)
}

#[tauri::command]
async fn compare_text_files_streaming_cmd(
    left_path: String,
    right_path: String,
    options: Option<file_diff_merge::FileDiffOptions>,
    max_preview_hunks: Option<usize>,
) -> Result<file_diff_merge::TextFileDiffReport, String> {
    tokio::task::spawn_blocking(move || {
        file_diff_merge::compare_text_files_streaming(
            &left_path,
            &right_path,
            options.unwrap_or_default(),
            max_preview_hunks,
        )
    })
    .await
    .map_err(|e| format!("后台线程调度失败: {}", e))?
}

#[tauri::command]
async fn apply_text_merge_and_save_cmd(
    left_path: String,
    right_path: String,
    output_path: String,
    options: Option<file_diff_merge::FileDiffOptions>,
    decisions: Vec<file_diff_merge::HunkMergeDecision>,
    default_choice: file_diff_merge::MergeChoice,
    create_backup: bool,
) -> Result<file_diff_merge::MergeSaveOutcome, String> {
    tokio::task::spawn_blocking(move || {
        file_diff_merge::apply_text_merge_and_save(
            &left_path,
            &right_path,
            &output_path,
            options.unwrap_or_default(),
            decisions,
            default_choice,
            create_backup,
        )
    })
    .await
    .map_err(|e| format!("后台 Merge 线程调度失败: {}", e))?
}

#[tauri::command]
async fn export_unified_patch_file_cmd(
    left_path: String,
    right_path: String,
    patch_output_path: String,
    options: Option<file_diff_merge::FileDiffOptions>,
) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        file_diff_merge::export_unified_patch_file(
            &left_path,
            &right_path,
            &patch_output_path,
            options.unwrap_or_default(),
        )
    })
    .await
    .map_err(|e| format!("后台导出线程调度失败: {}", e))?
}

#[tauri::command]
async fn compare_binary_files_streaming_cmd(
    left_path: String,
    right_path: String,
    chunk_size: Option<usize>,
) -> Result<file_diff_merge::BinaryFileDiffSummary, String> {
    tokio::task::spawn_blocking(move || {
        file_diff_merge::compare_binary_files_streaming(&left_path, &right_path, chunk_size)
    })
    .await
    .map_err(|e| format!("后台二进制对比线程调度失败: {}", e))?
}

#[tauri::command]
async fn compare_binary_files_fastcdc_cmd(
    left_path: String,
    right_path: String,
) -> Result<file_diff_merge::FastCdcBinaryDiffReport, String> {
    tokio::task::spawn_blocking(move || {
        file_diff_merge::compare_binary_files_fastcdc(&left_path, &right_path)
    })
    .await
    .map_err(|e| format!("后台 FastCDC 对比线程调度失败: {}", e))?
}

#[tauri::command]
async fn read_binary_diff_dual_offset_page_cmd(
    left_path: String,
    right_path: String,
    left_offset: u64,
    right_offset: u64,
    page_size: usize,
) -> Result<file_diff_merge::BinaryDiffPageResult, String> {
    tokio::task::spawn_blocking(move || {
        file_diff_merge::read_binary_diff_dual_offset_page(
            &left_path,
            &right_path,
            left_offset,
            right_offset,
            page_size,
        )
    })
    .await
    .map_err(|e| format!("后台读取双偏移二进制页失败: {}", e))?
}

#[tauri::command]
async fn read_binary_diff_page_cmd(
    left_path: String,
    right_path: String,
    start_offset: u64,
    page_size: usize,
) -> Result<file_diff_merge::BinaryDiffPageResult, String> {
    tokio::task::spawn_blocking(move || {
        file_diff_merge::read_binary_diff_page(&left_path, &right_path, start_offset, page_size)
    })
    .await
    .map_err(|e| format!("后台读取二进制页失败: {}", e))?
}

#[tauri::command]
async fn compare_directories_cmd(
    left_dir: String,
    right_dir: String,
    verify_equal_size_contents: bool,
) -> Result<file_diff_merge::DirectoryCompareReport, String> {
    tokio::task::spawn_blocking(move || {
        file_diff_merge::compare_directories(&left_dir, &right_dir, verify_equal_size_contents)
    })
    .await
    .map_err(|e| format!("后台目录比较线程调度失败: {}", e))?
}

#[tauri::command]
async fn get_discovered_assets_cmd(app: tauri::AppHandle) -> Result<Vec<discovery::DiscoveredAsset>, String> {
    discovery::sync_kernel_neighbors(Some(&app));
    let assets = discovery::get_all_assets();
    // 若存在端口为空的活跃局域网节点，异步触发轻量端口探活
    if assets.iter().any(|a| a.ports.is_empty() && (a.scope == "局域网内网" || a.scope == "链路本地")) {
        discovery::probe_all_assets_async(Some(app));
    }
    Ok(assets)
}

#[tauri::command]
async fn trigger_asset_scan_cmd(app: tauri::AppHandle) -> Result<String, String> {
    discovery::scan_lan_subnet_active(app);
    Ok("局域网全网段主动深度扫描已启动".to_string())
}

#[tauri::command]
async fn probe_asset_ports_cmd(app: tauri::AppHandle, ip: String) -> Result<Vec<u16>, String> {
    let open_ports = discovery::probe_asset_ports(&ip, 300);
    for &p in &open_ports {
        let proto = discovery::infer_protocol_by_port(p);
        discovery::record_asset(&ip, "", proto, p);
    }
    let _ = app.emit("assets-updated", discovery::get_all_assets());
    Ok(open_ports)
}

#[tauri::command]
async fn probe_all_assets_cmd(app: tauri::AppHandle) -> Result<String, String> {
    discovery::probe_all_assets_async(Some(app));
    Ok("全量资产端口探活已在后台启动".to_string())
}

#[tauri::command]
async fn clear_discovered_assets_cmd() -> Result<(), String> {
    discovery::clear_assets();
    Ok(())
}

#[tauri::command]
async fn set_wave_tracker(ip: String, offset: usize, length: usize, signed: bool, little_endian: Option<bool>) -> Result<(), String> {
    analyzer::configure_wave_tracker(ip, offset, length, signed, little_endian.unwrap_or(false));
    Ok(())
}

#[tauri::command]
async fn clear_logs() -> Result<String, String> {
    // 等保三级 (GB/T 22239-2019 8.1.4.1/8.1.4.3) 严格访问控制拦截：
    // 普通用户与非审计员禁止清空审计日志；仅【安全审计员 (AuditAdmin)】具有审计处置权限
    let current_user = rbac::get_current_user();
    if current_user.role != "AuditAdmin" {
        rbac::record_admin_audit("CLEAR_LOGS", &format!("用户 [{}] 试图清空审计取证数据被拦截", current_user.username), "BLOCKED");
        return Err("等保三级访问控制拦截：依据 GB/T 22239-2019 规范，仅【安全审计员 (AuditAdmin)】具有审计处置权限，普通角色禁止物理清空审计记录。".to_string());
    }

    rbac::record_admin_audit("CLEAR_LOGS", "安全审计员执行了证据文件截断与重置", "SUCCESS");
    let mut cleared = 0;

    // 1. 四大证据文件安全截断（统一走 forensics 收口，句柄重建避免 Windows 文件锁冲突）
    if forensics::ForensicEngine::truncate_pcap().is_ok() {
        cleared += 1; // forensic_capture.pcap
    }
    if forensics::truncate_app_pcap().is_ok() {
        cleared += 1; // capture.pcap
    }
    if forensics::truncate_jsonl().is_ok() {
        cleared += 1; // received_data.jsonl（含历史轮转归档一并删除）
    }
    if forensics::truncate_log().is_ok() {
        cleared += 1; // listener.log
    }

    // 2. 删除历史封条文件（证据已清空，旧封条哈希不再对应任何文件；锚定数据目录）
    let _ = std::fs::remove_file(forensics::data_path("forensic_evidence_chain.sha256"));

    // 3. 删除历史比对基线（等价 Python 基线重置语义；锚定数据目录）
    let _ = std::fs::remove_file(forensics::data_path("baseline_payloads.json"));
    net_intelligence::reset_live_net_stats();

    Ok(format!(
        "[CLEANUP] 取证数据彻底清空完成：{}/4 个证据文件已截断，封条与基线已重置",
        cleared
    ))
}

// ============================================================
// Tauri Command: 蜜罐引擎控制
// ============================================================

#[tauri::command]
async fn start_honeypot_cmd(
    app: tauri::AppHandle,
    ports: Vec<serde_json::Value>,
) -> Result<String, String> {
    // ports 格式: [{"port": 1883, "proto": "tcp"}, ...]
    let parsed: Vec<(u16, String)> = ports
        .into_iter()
        .filter_map(|v| {
            let port = v["port"].as_u64()? as u16;
            let proto = v["proto"].as_str().unwrap_or("tcp").to_string();
            Some((port, proto))
        })
        .collect();

    if parsed.is_empty() {
        return Err("[HONEYPOT] 端口列表为空，至少配置一个诱饵端口".to_string());
    }

    honeypot::start_honeypot(app, parsed);
    Ok("[HONEYPOT] 蜜罐引擎启动指令已下发".to_string())
}

#[tauri::command]
async fn stop_honeypot_cmd() -> Result<String, String> {
    honeypot::stop_honeypot();
    Ok("[HONEYPOT] 蜜罐引擎停止指令已下发".to_string())
}

// ============================================================
// Tauri Command: 靶向主动探测
// ============================================================

#[tauri::command]
async fn run_target_scan_cmd(
    app: tauri::AppHandle,
    targets: Vec<serde_json::Value>,
    timeout_ms: Option<u64>,
) -> Result<String, String> {
    // targets 格式: [{"ip": "192.168.1.1", "port": 80}, ...]
    let parsed: Vec<(String, u16)> = targets
        .into_iter()
        .filter_map(|v| {
            let ip = v["ip"].as_str()?.to_string();
            let port = v["port"].as_u64()? as u16;
            Some((ip, port))
        })
        .collect();

    if parsed.is_empty() {
        return Err("[PROBE] 扫描目标列表为空".to_string());
    }

    let to = timeout_ms.unwrap_or(3000);
    let app_clone = app.clone();

    // 在独立线程内运行异步扫描，避免阻塞 Tauri 主线程
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(active_probe::run_target_scan(app_clone, parsed, to));
    });

    Ok(format!("[PROBE] 靶向扫描已启动，超时 {}ms", to))
}

#[tauri::command]
async fn start_continuous_probe_cmd(
    app: tauri::AppHandle,
    host: String,
    port: u16,
    interval_secs: Option<u64>,
) -> Result<String, String> {
    let interval = interval_secs.unwrap_or(5);
    active_probe::start_continuous_probe(app, host.clone(), port, interval);
    Ok(format!("[ACTIVE_PROBE] 心跳探针已启动 -> {}:{} (周期={}s)", host, port, interval))
}

#[tauri::command]
async fn stop_continuous_probe_cmd() -> Result<String, String> {
    active_probe::stop_continuous_probe();
    Ok("[ACTIVE_PROBE] 心跳探针停止指令已下发".to_string())
}

#[tauri::command]
async fn start_stream_pull_cmd(
    app: tauri::AppHandle,
    host: String,
    port: u16,
    reconnect_secs: Option<u64>,
) -> Result<String, String> {
    let reconnect = reconnect_secs.unwrap_or(5);
    active_probe::start_stream_pull(app, host.clone(), port, reconnect);
    Ok(format!(
        "[ACTIVE_PULL] 主动拉流引擎已启动 -> {}:{} (断线重连间隔={}s)",
        host, port, reconnect
    ))
}

#[tauri::command]
async fn stop_stream_pull_cmd() -> Result<String, String> {
    active_probe::stop_stream_pull();
    Ok("[ACTIVE_PULL] 拉流引擎停止指令已下发".to_string())
}

#[tauri::command]
async fn manual_seal_cmd() -> Result<String, String> {
    forensics::manual_seal()
}

#[tauri::command]
async fn verify_evidence_chain_cmd() -> Result<forensics::EvidenceVerificationReport, String> {
    forensics::verify_evidence_chain()
}

#[tauri::command]
async fn get_forensic_vault_cmd() -> Result<Vec<forensics::FileIntegrityResult>, String> {
    let rep = forensics::verify_evidence_chain()?;
    Ok(rep.items)
}

#[tauri::command]
async fn get_chain_of_custody_cmd() -> Result<Vec<forensics::ChainOfCustodyRecord>, String> {
    Ok(forensics::get_chain_of_custody_records())
}

#[tauri::command]
async fn set_worm_lock_cmd(file_name: String) -> Result<bool, String> {
    forensics::set_worm_lock(&file_name)
}

#[tauri::command]
async fn generate_tsa_timestamp_cmd(file_name: String) -> Result<forensics::TsaTimestampToken, String> {
    forensics::generate_tsa_timestamp(&file_name)
}

#[tauri::command]
async fn generate_judicial_report_cmd(
    investigator: String,
    reviewer: String,
    case_number: String,
) -> Result<forensics::ForensicInspectionReport, String> {
    forensics::generate_judicial_inspection_report(&investigator, &reviewer, &case_number)
}

#[tauri::command]
async fn export_pcapng_cmd(if_name: Option<String>) -> Result<String, String> {
    let iface = if_name.unwrap_or_else(|| "Default Capture Interface".to_string());
    let packets = crate::lock_guard::lock_mutex(&pcap_engine::GLOBAL_RING_BUFFER, "lib::export_pcapng_cmd").snapshot();
    let total_drops = crate::sniffer::CAPTURE_DROPPED_DRIVER.load(std::sync::atomic::Ordering::Relaxed)
        + crate::sniffer::CAPTURE_DROPPED_INTERFACE.load(std::sync::atomic::Ordering::Relaxed);
    let pcapng_bytes = pcap_engine::encode_packets_to_pcapng(&packets, &iface, total_drops);
    
    let path = forensics::data_path("forensic_capture.pcapng");
    std::fs::write(&path, &pcapng_bytes).map_err(|e| format!("写入 PCAPNG 失败: {}", e))?;
    
    let sz = pcapng_bytes.len() as u64;
    forensics::record_coc_event(
        "EXPORT_PCAPNG",
        "AUDITOR_01",
        "SUPERVISOR_02",
        "forensic_capture.pcapng",
        &format!("导出 {} 帧至 PCAPNG 格式 (物理丢包记录: {})", packets.len(), total_drops),
        sz,
        "",
        "",
    );
    
    Ok(format!("[FORENSICS] ✅ 已成功生成工业级 PCAPNG 证据文件 ({} 帧, {} 字节) -> {}", packets.len(), sz, path.display()))
}

#[tauri::command]
async fn get_fidelity_certificate_cmd() -> Result<pcap_engine::CaptureFidelityCertificate, String> {
    let recv = crate::sniffer::CAPTURE_RECEIVED_PACKETS.load(std::sync::atomic::Ordering::Relaxed);
    let drop_drv = crate::sniffer::CAPTURE_DROPPED_DRIVER.load(std::sync::atomic::Ordering::Relaxed);
    let drop_if = crate::sniffer::CAPTURE_DROPPED_INTERFACE.load(std::sync::atomic::Ordering::Relaxed);
    let count = if recv > 0 {
        recv
    } else {
        crate::lock_guard::lock_mutex(&pcap_engine::GLOBAL_RING_BUFFER, "lib::get_fidelity_certificate_cmd")
            .stats()
            .0 as u64
    };
    Ok(pcap_engine::generate_fidelity_certificate(count, drop_drv, drop_if))
}

// ============================================================
// Tauri Command: 配置体系（config.json 读写）
// ============================================================

#[tauri::command]
async fn get_config_cmd() -> Result<config::ProbeConfig, String> {
    Ok(config::get_config())
}

#[tauri::command]
async fn save_config_cmd(cfg: config::ProbeConfig) -> Result<String, String> {
    config::save_config(cfg)?;
    Ok("[CONFIG] ✅ 配置已保存至 config.json（部分配置项重启探针后生效）".to_string())
}

// ============================================================
// Tauri Command: 限速阈值动态更新
// ============================================================

#[tauri::command]
async fn update_throttle_config_cmd(capacity: f64, fill_rate: f64) -> Result<String, String> {
    throttle::update_throttle_config(capacity, fill_rate);
    Ok(format!("[THROTTLE] 限速配置已更新: 容量={} 补充速率={}/s", capacity, fill_rate))
}

// ============================================================
// Tauri Command: 云端流式上报控制
// ============================================================

#[tauri::command]
async fn start_cloud_streaming_cmd(
    app: tauri::AppHandle,
    webhook_url: String,
) -> Result<String, String> {
    if webhook_url.is_empty() {
        return Err("[CLOUD] Webhook URL 不能为空".to_string());
    }
    cloud::start_cloud_streaming(app, webhook_url.clone());
    Ok(format!("[CLOUD] 流式上报已启动 -> {}", webhook_url))
}

#[tauri::command]
async fn stop_cloud_streaming_cmd() -> Result<String, String> {
    cloud::stop_cloud_streaming();
    Ok("[CLOUD] 流式上报已停止".to_string())
}

// ============================================================
// Tauri Command: DPI 动态字典手动重载
// ============================================================

#[tauri::command]
async fn reload_dpi_signatures_cmd(path: Option<String>) -> Result<String, String> {
    let sig_path = path.unwrap_or_else(|| "protocol_signatures.json".to_string());
    match dpi::reload_signatures(&sig_path) {
        Ok(n) => Ok(format!("[DPI] 动态字典重载成功: {} 条规则 <- {}", n, sig_path)),
        Err(e) => Err(format!("[DPI] 重载失败: {}", e)),
    }
}

// ============================================================
// Tauri Command: 窗口控制
// ============================================================

use tauri::Manager;

#[tauri::command]
fn minimize_app(app: tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.minimize();
    }
}

#[tauri::command]
fn maximize_app(app: tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        if let Ok(is_max) = window.is_maximized() {
            if is_max { let _ = window.unmaximize(); } else { let _ = window.maximize(); }
        }
    }
}

#[tauri::command]
fn close_app(app: tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.close();
    }
    std::process::exit(0);
}

#[tauri::command]
fn drag_app(app: tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.start_dragging();
    }
}

#[tauri::command]
fn hide_to_tray_cmd(app: tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
}

#[tauri::command]
async fn pick_native_file_dialog_cmd(
    title: Option<String>,
    filter_name: Option<String>,
    filter_patterns: Option<String>,
) -> Result<Option<String>, String> {
    tokio::task::spawn_blocking(move || {
        desktop_native::pick_native_file_dialog(
            title.as_deref().unwrap_or("选择磁盘文件 - Omni-Probe"),
            filter_name.as_deref().unwrap_or("常见支持文件"),
            filter_patterns.as_deref().unwrap_or("*.*"),
        )
    })
    .await
    .map_err(|e| format!("文件对话线程调度失败: {}", e))?
}

#[tauri::command]
async fn pick_native_folder_dialog_cmd(title: Option<String>) -> Result<Option<String>, String> {
    tokio::task::spawn_blocking(move || {
        desktop_native::pick_native_folder_dialog(
            title.as_deref().unwrap_or("选择目录文件夹 - Omni-Probe"),
        )
    })
    .await
    .map_err(|e| format!("目录对话线程调度失败: {}", e))?
}

#[tauri::command]
async fn save_text_with_native_dialog_cmd(
    default_filename: String,
    title: Option<String>,
    filter_name: Option<String>,
    filter_patterns: Option<String>,
    content: String,
) -> Result<desktop_native::NativeSaveOutcome, String> {
    tokio::task::spawn_blocking(move || {
        desktop_native::save_text_with_native_dialog(
            &default_filename,
            title.as_deref().unwrap_or("导出并原子写入磁盘 - Omni-Probe"),
            filter_name.as_deref().unwrap_or("导出文档"),
            filter_patterns.as_deref().unwrap_or("*.*"),
            &content,
        )
    })
    .await
    .map_err(|e| format!("另存为线程调度失败: {}", e))?
}

#[tauri::command]
async fn reveal_in_file_manager_cmd(path: String) -> Result<String, String> {
    desktop_native::reveal_in_file_manager(&path)
}

#[tauri::command]
async fn check_app_update_cmd() -> Result<updater::UpdateCheckResult, String> {
    updater::check_latest_release(env!("CARGO_PKG_VERSION")).await
}

// ============================================================
// 专业流量分析与持久化命令 (Sprint 3: Professional Traffic Analysis)
// ============================================================

#[tauri::command]
async fn set_snaplen_mode_cmd(mode: String, limit: Option<u32>) -> Result<String, String> {
    let snaplen = match mode.to_lowercase().as_str() {
        "header_only" | "header" => pcap_engine::SnaplenMode::HeaderOnly(limit.unwrap_or(96)),
        _ => pcap_engine::SnaplenMode::Full,
    };
    let mut writer = pcap_engine::GLOBAL_ROLLING_WRITER
        .lock()
        .map_err(|e| format!("获取滚动落盘引擎锁失败: {}", e))?;
    writer.set_snaplen_mode(snaplen);
    Ok(format!("Snaplen 模式已持久写入落盘引擎: {:?}", snaplen))
}

#[tauri::command]
async fn set_rolling_pcap_config_cmd(
    enabled: bool,
    output_dir: String,
    max_size_mb: u64,
    max_duration_secs: u64,
    max_quota_gb: u64,
) -> Result<String, String> {
    let mut writer = crate::lock_guard::lock_mutex(
        &pcap_engine::GLOBAL_ROLLING_WRITER,
        "lib::set_rolling_pcap_config_cmd",
    );
    *writer = pcap_engine::RollingPcapWriter::new(pcap_engine::RollingPcapConfig {
        enabled,
        output_dir,
        max_file_size_bytes: max_size_mb * 1024 * 1024,
        max_file_duration_secs: max_duration_secs,
        max_disk_quota_bytes: max_quota_gb * 1024 * 1024 * 1024,
        snaplen_mode: pcap_engine::SnaplenMode::Full,
    });
    Ok("持续滚动落盘配置已成功更新".to_string())
}

#[tauri::command]
async fn export_packets_pcap_cmd(packets: Vec<export_engine::PacketExportData>, file_path: String) -> Result<usize, String> {
    export_engine::export_to_pcap(&packets, &file_path)
}

#[tauri::command]
async fn export_packets_pcapng_cmd(
    packets: Vec<export_engine::PacketExportData>,
    file_path: String,
    iface_name: Option<String>,
    forensic_comment: Option<String>,
) -> Result<usize, String> {
    let iface = iface_name.as_deref().unwrap_or("any");
    export_engine::export_to_pcapng_with_comment(&packets, &file_path, iface, forensic_comment.as_deref())
}

#[tauri::command]
async fn export_packets_csv_cmd(packets: Vec<export_engine::PacketExportData>, file_path: String) -> Result<usize, String> {
    export_engine::export_to_csv(&packets, &file_path)
}

#[tauri::command]
async fn export_packets_json_cmd(packets: Vec<export_engine::PacketExportData>, file_path: String) -> Result<usize, String> {
    export_engine::export_to_json(&packets, &file_path)
}

#[tauri::command]
async fn export_packets_har_cmd(packets: Vec<export_engine::PacketExportData>, file_path: String) -> Result<usize, String> {
    export_engine::export_to_har(&packets, &file_path)
}

#[tauri::command]
async fn import_pcap_file_cmd(file_path: String) -> Result<Vec<sniffer::PacketRecord>, String> {
    export_engine::import_pcap_file(&file_path)
}

#[tauri::command]
async fn load_pcap_replay_file_cmd(file_path: String) -> Result<pcap_engine::CaptureFileInfo, String> {
    let bytes = std::fs::read(&file_path).map_err(|e| format!("打开报文文件失败: {}", e))?;
    let mut replay = pcap_replay::GLOBAL_REPLAY_ENGINE.lock().map_err(|e| e.to_string())?;
    replay.load_capture_bytes(&bytes)
}

#[tauri::command]
async fn start_pcap_replay_cmd(
    app: tauri::AppHandle,
    mode: Option<String>,
    speed_multiplier: Option<f64>,
    loop_count: Option<usize>,
) -> Result<String, String> {
    let replay_mode = match mode.as_deref() {
        Some("top_speed") => pcap_replay::ReplayMode::TopSpeed,
        Some("step") => pcap_replay::ReplayMode::Step,
        _ => pcap_replay::ReplayMode::Paced(speed_multiplier.unwrap_or(1.0)),
    };

    let mut replay = pcap_replay::GLOBAL_REPLAY_ENGINE.lock().map_err(|e| e.to_string())?;
    replay.set_config(pcap_replay::ReplayConfig {
        mode: replay_mode,
        loop_count: loop_count.unwrap_or(1),
        max_step_delay_micros: 5_000_000,
        spoof_mac: true,
        ..Default::default()
    });
    replay.start(Some(app))?;
    Ok("高精度重放引擎已启动".to_string())
}

#[tauri::command]
async fn pause_pcap_replay_cmd() -> Result<String, String> {
    let replay = pcap_replay::GLOBAL_REPLAY_ENGINE.lock().map_err(|e| e.to_string())?;
    replay.pause();
    Ok("重放已暂停".to_string())
}

#[tauri::command]
async fn resume_pcap_replay_cmd() -> Result<String, String> {
    let replay = pcap_replay::GLOBAL_REPLAY_ENGINE.lock().map_err(|e| e.to_string())?;
    replay.resume();
    Ok("重放已恢复".to_string())
}

#[tauri::command]
async fn stop_pcap_replay_cmd() -> Result<String, String> {
    let mut replay = pcap_replay::GLOBAL_REPLAY_ENGINE.lock().map_err(|e| e.to_string())?;
    replay.stop();
    Ok("重放已停止".to_string())
}

#[tauri::command]
async fn step_pcap_replay_cmd() -> Result<String, String> {
    let replay = pcap_replay::GLOBAL_REPLAY_ENGINE.lock().map_err(|e| e.to_string())?;
    replay.step();
    Ok("单步推送触发成功".to_string())
}

#[tauri::command]
async fn get_pcap_replay_telemetry_cmd() -> Result<pcap_replay::ReplayTelemetry, String> {
    let replay = pcap_replay::GLOBAL_REPLAY_ENGINE.lock().map_err(|e| e.to_string())?;
    Ok(replay.get_telemetry())
}

#[tauri::command]
async fn get_zero_copy_pool_metrics_cmd() -> Result<zero_copy_pool::ZeroCopyPoolMetrics, String> {
    let pool = crate::lock_guard::lock_mutex(
        &zero_copy_pool::GLOBAL_ZERO_COPY_POOL,
        "lib::get_zero_copy_pool_metrics_cmd",
    );
    Ok(pool.get_metrics())
}

#[tauri::command]
async fn get_kernel_zero_copy_telemetry_cmd() -> Result<zero_copy_pool::KernelZeroCopyTelemetry, String> {
    Ok(zero_copy_pool::get_runtime_zero_copy_telemetry())
}

#[tauri::command]
async fn get_biflow_sessions_cmd() -> Result<Vec<stream_reassembly::FlowSummary>, String> {
    let engine = crate::lock_guard::lock_mutex(
        &stream_reassembly::GLOBAL_FLOW_ENGINE,
        "lib::get_biflow_sessions_cmd",
    );
    Ok(engine.get_flow_summaries())
}

#[tauri::command]
async fn follow_tcp_stream_cmd(
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    transport: String,
) -> Result<Vec<stream_reassembly::StreamChunk>, String> {
    let engine = crate::lock_guard::lock_mutex(
        &stream_reassembly::GLOBAL_FLOW_ENGINE,
        "lib::follow_tcp_stream_cmd",
    );
    engine
        .get_follow_stream(&src_ip, &dst_ip, src_port, dst_port, &transport)
        .ok_or_else(|| "未找到对应的 TCP 会话流".to_string())
}

#[tauri::command]
async fn classify_ip_cmd(ip: String) -> Result<ip_intelligence::IpIntelligenceResult, String> {
    let engine = crate::lock_guard::lock_mutex(
        &ip_intelligence::GLOBAL_IP_ENGINE,
        "lib::classify_ip_cmd",
    );
    Ok(engine.classify(&ip))
}

#[tauri::command]
async fn get_cidr_rules_cmd() -> Result<Vec<ip_intelligence::CidrAssetRule>, String> {
    let engine = crate::lock_guard::lock_mutex(
        &ip_intelligence::GLOBAL_IP_ENGINE,
        "lib::get_cidr_rules_cmd",
    );
    Ok(engine.get_rules())
}

#[tauri::command]
async fn save_cidr_rules_cmd(rules: Vec<ip_intelligence::CidrAssetRule>) -> Result<usize, String> {
    let mut engine = crate::lock_guard::lock_mutex(
        &ip_intelligence::GLOBAL_IP_ENGINE,
        "lib::save_cidr_rules_cmd",
    );
    let count = rules.len();
    engine.set_rules(rules);
    Ok(count)
}

#[tauri::command]
async fn download_ip_db_cmd(app: tauri::AppHandle, custom_url: Option<String>) -> Result<String, String> {
    ip_downloader::download_xdb_database(app, custom_url).await
}

#[tauri::command]
fn load_local_ip_db_cmd(file_path: String) -> Result<String, String> {
    let mut engine = crate::lock_guard::lock_mutex(
        &ip_intelligence::GLOBAL_IP_ENGINE,
        "lib::load_local_ip_db_cmd",
    );
    engine.load_xdb(&file_path)
}

#[tauri::command]
fn get_ip_db_status_cmd() -> Result<serde_json::Value, String> {
    let engine = crate::lock_guard::lock_mutex(
        &ip_intelligence::GLOBAL_IP_ENGINE,
        "lib::get_ip_db_status_cmd",
    );
    Ok(engine.get_xdb_status())
}

#[tauri::command]
fn test_lookup_ip_cmd(ip: String) -> Result<ip_intelligence::IpIntelligenceResult, String> {
    let engine = crate::lock_guard::lock_mutex(
        &ip_intelligence::GLOBAL_IP_ENGINE,
        "lib::test_lookup_ip_cmd",
    );
    Ok(engine.classify(&ip))
}

#[tauri::command]
async fn resolve_ip_hostname_cmd(ip: String) -> Result<discovery::IpHostnameInfo, String> {
    Ok(discovery::resolve_ip_hostname(&ip).await)
}

// ============================================================
// 等保三级 (Level 3) 扩展 Commands
// ============================================================

#[tauri::command]
fn get_syslog_config_cmd() -> Result<syslog::SyslogConfig, String> {
    Ok(syslog::get_syslog_config())
}

#[tauri::command]
fn save_syslog_config_cmd(config: syslog::SyslogConfig) -> Result<String, String> {
    syslog::save_syslog_config(config);
    rbac::record_admin_audit("UPDATE_SYSLOG_CFG", "已更新 Syslog RFC 5424 外发配置", "SUCCESS");
    Ok("Syslog 配置保存成功".to_string())
}

#[tauri::command]
async fn test_send_syslog_cmd(message: String) -> Result<String, String> {
    syslog::test_send_syslog(&message).await
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct AuditComplianceSnapshot {
    rbac_security: rbac::RbacSecurityStatus,
    cidr_rule_count: usize,
    baseline_mode: String,
    baseline_rule_count: usize,
    syslog_enabled: bool,
    syslog_configured: bool,
    ics_acl_rule_count: usize,
    has_hsm_hardware: bool,
    admin_audit_count: usize,
    level3_rate_pct: f64,
    level2_rate_pct: f64,
    level4_rate_pct: f64,
}

#[tauri::command]
fn get_current_user_cmd() -> Result<rbac::CurrentUser, String> {
    Ok(rbac::get_current_user())
}

#[tauri::command]
fn get_rbac_security_status_cmd() -> Result<rbac::RbacSecurityStatus, String> {
    Ok(rbac::get_rbac_security_status())
}

#[tauri::command]
fn get_audit_compliance_snapshot_cmd() -> Result<AuditComplianceSnapshot, String> {
    let rbac_security = rbac::get_rbac_security_status();
    let cidr_rule_count = {
        let engine = crate::lock_guard::lock_mutex(
            &ip_intelligence::GLOBAL_IP_ENGINE,
            "lib::get_audit_compliance_snapshot_cidr",
        );
        engine.get_rules().len()
    };
    let baseline_status = baseline_learning::get_baseline_status();
    let baseline_rule_count = baseline_learning::get_baseline_rules().len();
    let syslog_cfg = syslog::get_syslog_config();
    let syslog_enabled = syslog_cfg.enabled;
    let syslog_configured = syslog_enabled && !syslog_cfg.server_ip.trim().is_empty();
    let ics_acl_rule_count = {
        let acl_guard = crate::lock_guard::read_rwlock(
            &sniffer::GLOBAL_ICS_ACL_ENGINE,
            "lib::get_audit_compliance_snapshot_ics_acl",
        );
        acl_guard.rules.len()
    };
    let admin_audit_count = rbac::get_admin_audit_trail().len();
    let has_hsm_hardware = false;

    // 精确映射等保二级与三级实时条款判定（不预设任何默认达标率）
    let c_8111 = rbac_security.all_credentials_hardened;
    let c_8121 = cidr_rule_count > 0;
    let c_8122 = baseline_status.mode == "ENFORCING" && cidr_rule_count > 0;
    let c_8141 = rbac_security.active_roles_count >= 3 && rbac_security.all_credentials_hardened;
    let c_8143 = syslog_configured;
    let c_8144 = false; // 单次会话需主动触发核验，初始待核验，由前端按实际核验结果动态聚合
    let c_g42 = baseline_status.mode != "DISABLED" && baseline_rule_count > 0;
    let c_g43 = ics_acl_rule_count > 0;

    let l3_checks = [c_8111, c_8121, c_8122, c_8141, c_8143, c_8144, c_g42, c_g43];
    let l3_pass = l3_checks.iter().filter(|&&x| x).count();
    let level3_rate_pct = ((l3_pass as f64 / l3_checks.len() as f64) * 1000.0).round() / 10.0;

    let l2_checks = [c_8111, c_8121, c_8141, c_8143, c_8144];
    let l2_pass = l2_checks.iter().filter(|&&x| x).count();
    let level2_rate_pct = ((l2_pass as f64 / l2_checks.len() as f64) * 1000.0).round() / 10.0;

    let level4_rate_pct = if has_hsm_hardware { 100.0 } else { 0.0 };

    Ok(AuditComplianceSnapshot {
        rbac_security,
        cidr_rule_count,
        baseline_mode: baseline_status.mode,
        baseline_rule_count,
        syslog_enabled,
        syslog_configured,
        ics_acl_rule_count,
        has_hsm_hardware,
        admin_audit_count,
        level3_rate_pct,
        level2_rate_pct,
        level4_rate_pct,
    })
}

#[tauri::command]
fn switch_user_role_cmd(target_role: String, password: String) -> Result<rbac::CurrentUser, String> {
    rbac::switch_user_role(&target_role, &password)
}

#[tauri::command]
fn get_admin_audit_trail_cmd() -> Result<Vec<rbac::AdminAuditRecord>, String> {
    Ok(rbac::get_admin_audit_trail())
}



#[tauri::command]
fn validate_display_filter_cmd(expression: String) -> Result<bool, String> {
    filter_ast::CompiledFilter::compile(&expression)
        .map(|_| true)
        .map_err(|e| e)
}

#[tauri::command]
fn filter_packets_by_ast_cmd(
    expression: String,
    records: Vec<sniffer::PacketRecord>,
) -> Result<Vec<sniffer::PacketRecord>, String> {
    let compiled = filter_ast::CompiledFilter::compile(&expression)
        .map_err(|e| e)?;

    let filtered = records
        .into_iter()
        .filter(|r| {
            let p_text = r.raw_text.as_deref().unwrap_or("");
            compiled.matches_with_fields(
                &r.src_ip,
                &r.dst_ip,
                r.src_port,
                r.dst_port,
                &r.protocol,
                r.length,
                r.entropy,
                p_text,
                r.business_data.as_ref(),
            )
        })
        .collect();

    Ok(filtered)
}

#[tauri::command]
fn get_standard_field_registry_cmd() -> Result<Vec<filter_ast::FieldDefinition>, String> {
    Ok(filter_ast::get_standard_field_registry())
}

#[tauri::command]
fn fetch_paged_packets_cmd(offset: usize, limit: usize) -> Result<stream_paging::PagedPacketsResponse, String> {
    let buf = crate::lock_guard::lock_mutex(
        &stream_paging::GLOBAL_STREAM_BUFFER,
        "lib::fetch_paged_packets_cmd",
    );
    Ok(buf.fetch_page(offset, limit))
}

#[tauri::command]
fn get_stream_buffer_stats_cmd() -> Result<stream_paging::StreamBufferStats, String> {
    let buf = crate::lock_guard::lock_mutex(
        &stream_paging::GLOBAL_STREAM_BUFFER,
        "lib::get_stream_buffer_stats_cmd",
    );
    Ok(buf.get_stats())
}

#[tauri::command]
fn get_baseline_status_cmd() -> Result<baseline_learning::BaselineStatus, String> {
    Ok(baseline_learning::get_baseline_status())
}

#[tauri::command]
fn set_baseline_mode_cmd(mode: String) -> Result<bool, String> {
    baseline_learning::set_baseline_mode(&mode)
}

#[tauri::command]
fn get_baseline_rules_cmd() -> Result<Vec<baseline_learning::BaselineRule>, String> {
    Ok(baseline_learning::get_baseline_rules())
}

#[tauri::command]
fn clear_baseline_rules_cmd() -> Result<bool, String> {
    baseline_learning::clear_baseline_rules()
}

#[tauri::command]
fn get_baseline_drift_events_cmd() -> Result<Vec<baseline_learning::BaselineDriftEvent>, String> {
    Ok(baseline_learning::get_baseline_drift_events())
}

#[tauri::command]
fn persist_baseline_rules_cmd() -> Result<usize, String> {
    baseline_learning::persist_baseline_rules()
}

#[tauri::command]
fn change_role_password_cmd(target_role: String, old_password: String, new_password: String) -> Result<String, String> {
    rbac::change_role_password(&target_role, &old_password, &new_password)
}

// ============================================================
// 三大优先级：数据保存与专业差分比对 Tauri 接口
// ============================================================

// 1. 第一优先级：全网资产快照与多维差分
#[tauri::command]
async fn save_asset_snapshot_cmd(name: Option<String>) -> Result<discovery::AssetSnapshotSummary, String> {
    discovery::save_asset_snapshot(name)
}

#[tauri::command]
async fn list_asset_snapshots_cmd() -> Result<Vec<discovery::AssetSnapshotSummary>, String> {
    discovery::list_asset_snapshots()
}

#[tauri::command]
async fn get_asset_snapshot_cmd(id: String) -> Result<discovery::AssetSnapshot, String> {
    discovery::get_asset_snapshot(&id)
}

#[tauri::command]
async fn delete_asset_snapshot_cmd(id: String) -> Result<bool, String> {
    discovery::delete_asset_snapshot(&id)
}

#[tauri::command]
async fn compare_asset_snapshots_cmd(base_id: String, target_id: Option<String>) -> Result<discovery::AssetDiffReport, String> {
    discovery::compare_asset_snapshots(&base_id, target_id.as_deref())
}

// 2. 第二优先级：报文特征样本归档与双报文深度差分
#[tauri::command]
async fn save_packet_sample_cmd(name: String, packet: sniffer::PacketRecord) -> Result<String, String> {
    analyzer::save_packet_sample(name, packet)
}

#[tauri::command]
async fn list_packet_samples_cmd() -> Result<Vec<analyzer::StoredPacketSample>, String> {
    analyzer::list_packet_samples()
}

#[tauri::command]
async fn delete_packet_sample_cmd(id: String) -> Result<bool, String> {
    analyzer::delete_packet_sample(&id)
}

#[tauri::command]
async fn compare_two_packets_cmd(packet_a: sniffer::PacketRecord, packet_b: sniffer::PacketRecord) -> Result<analyzer::DualPacketDiffResult, String> {
    analyzer::compare_two_packets(packet_a, packet_b)
}

#[tauri::command]
async fn compare_universal_payloads_cmd(
    item_a: analyzer::UniversalDiffPayload,
    item_b: analyzer::UniversalDiffPayload,
) -> Result<analyzer::DualPacketDiffResult, String> {
    analyzer::compare_universal_payloads(item_a, item_b)
}

#[tauri::command]
async fn compare_multi_universal_payloads_cmd(
    items: Vec<analyzer::UniversalDiffPayload>,
    anchor_index: Option<usize>,
) -> Result<analyzer::MultiUniversalDiffResult, String> {
    analyzer::compare_multi_universal_payloads(items, anchor_index)
}

#[tauri::command]
async fn export_multi_diff_patch_cmd(
    items: Vec<analyzer::UniversalDiffPayload>,
    anchor_index: Option<usize>,
) -> Result<analyzer::MultiDiffPatchReport, String> {
    analyzer::generate_multi_diff_patch_report(items, anchor_index)
}

// 3. 第三优先级：物理硬件基线白名单与合规差分比对
#[tauri::command]
async fn save_hardware_whitelist_cmd(items: Vec<hardware::HardwareWhitelistItem>) -> Result<usize, String> {
    hardware::save_hardware_whitelist(items)
}

#[tauri::command]
async fn get_hardware_whitelist_cmd() -> Result<hardware::HardwareWhitelistConfig, String> {
    hardware::get_hardware_whitelist()
}

#[tauri::command]
async fn clear_hardware_whitelist_cmd() -> Result<bool, String> {
    hardware::clear_hardware_whitelist()
}

#[tauri::command]
async fn verify_hardware_compliance_cmd(app: tauri::AppHandle) -> Result<hardware::HardwareComplianceReport, String> {
    hardware::verify_hardware_compliance(Some(&app))
}

// 4. 全息上网行为监测与外联合规审计
#[tauri::command]
async fn get_web_access_logs_cmd(
    limit: Option<usize>,
    category_filter: Option<String>,
    risk_filter: Option<String>,
    client_ip_filter: Option<String>,
) -> Result<Vec<web_audit::WebAccessLog>, String> {
    Ok(web_audit::get_web_access_logs(limit, category_filter, risk_filter, client_ip_filter))
}

#[tauri::command]
async fn get_web_audit_statistics_cmd() -> Result<web_audit::WebAuditStatistics, String> {
    Ok(web_audit::get_web_audit_statistics())
}

#[tauri::command]
async fn clear_web_access_logs_cmd() -> Result<bool, String> {
    Ok(web_audit::clear_web_access_logs())
}

#[tauri::command]
async fn get_dns_cache_table_cmd() -> Result<Vec<web_audit::DnsCacheItem>, String> {
    Ok(web_audit::get_dns_cache_table())
}

#[tauri::command]
async fn export_web_access_logs_cmd(format: String) -> Result<String, String> {
    web_audit::export_web_access_logs(&format)
}

// 5. 流量解密与过滤级防火墙系统
#[tauri::command]
async fn start_tls_proxy_cmd(app: tauri::AppHandle, port: u16) -> Result<String, String> {
    tls_proxy::start_tls_proxy(app, port)
}

#[tauri::command]
async fn stop_tls_proxy_cmd() -> Result<String, String> {
    tls_proxy::stop_tls_proxy()
}

#[tauri::command]
async fn get_proxy_status_cmd() -> Result<tls_proxy::ProxyStatus, String> {
    Ok(tls_proxy::get_proxy_status())
}

#[tauri::command]
async fn get_ca_cert_pem_cmd() -> Result<String, String> {
    tls_proxy::get_ca_cert_pem()
}

#[tauri::command]
async fn load_sslkeylog_file_cmd(file_path: String) -> Result<usize, String> {
    tls_keylog::import_keylog_file(&file_path)
}

#[tauri::command]
async fn get_keylog_status_cmd() -> Result<tls_keylog::TlsKeyLogStatus, String> {
    Ok(tls_keylog::get_keylog_status())
}

#[tauri::command]
async fn clear_keylog_cache_cmd() -> Result<bool, String> {
    Ok(tls_keylog::clear_keylog_cache())
}

#[tauri::command]
async fn get_firewall_rules_cmd() -> Result<Vec<firewall_filter::FirewallRule>, String> {
    Ok(firewall_filter::get_firewall_rules())
}

#[tauri::command]
async fn save_firewall_rules_cmd(rules: Vec<firewall_filter::FirewallRule>) -> Result<bool, String> {
    Ok(firewall_filter::save_firewall_rules(rules))
}

#[tauri::command]
async fn wfp_block_ip_cmd(target: String, reason: String) -> Result<wfp_engine::WfpBlockOutcome, String> {
    let outcome = wfp_engine::block_ip_kernel_wfp(&target, &reason);
    // 联动 XDP 前端旁路黑名单：若为单主机 IP 或 /32 规则，同步注入实时 Drop 表
    let bare_ip = target.trim().strip_suffix("/32").unwrap_or(target.trim());
    if !bare_ip.contains('/') {
        xdp_engine::sync_block_ip_to_xdp(bare_ip, true);
    }
    Ok(outcome)
}

#[tauri::command]
async fn wfp_unblock_ip_cmd(target: String) -> Result<String, String> {
    let bare_ip = target.trim().strip_suffix("/32").unwrap_or(target.trim());
    if !bare_ip.contains('/') {
        xdp_engine::sync_block_ip_to_xdp(bare_ip, false);
    }
    wfp_engine::unblock_ip_kernel_wfp(&target)
}

#[tauri::command]
async fn get_wfp_status_cmd() -> Result<wfp_engine::WfpStatusReport, String> {
    Ok(wfp_engine::get_wfp_kernel_status())
}

#[tauri::command]
async fn get_decrypted_traffic_logs_cmd(limit: Option<usize>) -> Result<Vec<tls_proxy::DecryptedTrafficRecord>, String> {
    Ok(tls_proxy::get_decrypted_traffic_logs(limit))
}

#[tauri::command]
async fn clear_decrypted_traffic_logs_cmd() -> Result<bool, String> {
    Ok(tls_proxy::clear_decrypted_traffic_logs())
}

#[tauri::command]
async fn set_active_blocking_mode_cmd(enforced: bool) -> Result<bool, String> {
    Ok(tls_proxy::set_active_blocking_mode(enforced))
}

#[tauri::command]
async fn decrypt_stream_with_keylog_cmd(
    client_hex: String,
    server_hex: String,
    stream_id: String,
) -> Result<Vec<passive_tls_decryptor::DecryptedTlsPayload>, String> {
    let client_bytes = hex::decode(&client_hex).map_err(|e| format!("客户端报文十六进制解码失败: {}", e))?;
    let server_bytes = hex::decode(&server_hex).map_err(|e| format!("服务端报文十六进制解码失败: {}", e))?;
    passive_tls_decryptor::decrypt_stream_payload(&client_bytes, &server_bytes, &stream_id)
        .map_err(|e| e.to_string())
}

// ============================================================
// 四维安全合规审查专属指令 (网络安全/数据安全/保密安全/脱敏清洗)
// ============================================================

#[tauri::command]
async fn get_network_audit_events_cmd(limit: Option<usize>) -> Result<Vec<audit_network::NetworkAuditEvent>, String> {
    Ok(audit_network::get_network_audit_events(limit))
}

#[tauri::command]
async fn get_network_audit_statistics_cmd() -> Result<audit_network::NetworkAuditStatistics, String> {
    Ok(audit_network::get_network_audit_statistics())
}

#[tauri::command]
async fn clear_network_audit_events_cmd() -> Result<(), String> {
    audit_network::clear_network_audit_events();
    Ok(())
}

#[tauri::command]
async fn get_data_security_summary_cmd() -> Result<audit_data_security::DataSecuritySummary, String> {
    Ok(audit_data_security::get_data_security_summary())
}

#[tauri::command]
async fn get_sensitive_findings_cmd(limit: Option<usize>) -> Result<Vec<audit_data_security::SensitiveDataFinding>, String> {
    Ok(audit_data_security::get_sensitive_findings(limit))
}

#[tauri::command]
async fn get_reconstructed_files_cmd() -> Result<Vec<audit_data_security::ReconstructedFileItem>, String> {
    Ok(audit_data_security::get_reconstructed_files())
}

#[tauri::command]
async fn clear_data_security_records_cmd() -> Result<(), String> {
    audit_data_security::clear_data_security_records();
    Ok(())
}

#[tauri::command]
async fn get_confidentiality_alerts_cmd(limit: Option<usize>) -> Result<Vec<audit_confidentiality::ConfidentialityAlert>, String> {
    Ok(audit_confidentiality::get_confidentiality_alerts(limit))
}

#[tauri::command]
async fn scan_confidentiality_text_cmd(content: String) -> Result<audit_confidentiality::ConfidentialityScanReport, String> {
    Ok(audit_confidentiality::scan_static_text(&content))
}

#[tauri::command]
async fn clear_confidentiality_alerts_cmd() -> Result<(), String> {
    audit_confidentiality::clear_confidentiality_alerts();
    Ok(())
}

#[tauri::command]
async fn apply_data_sanitization_cmd(
    input_text: String,
    policy_id: Option<String>,
) -> Result<audit_sanitizer::SanitizationResult, String> {
    let pid = policy_id.unwrap_or_else(|| "POLICY-STRICT-COMPLIANCE".to_string());
    Ok(audit_sanitizer::sanitize_payload(&input_text, &pid))
}

#[tauri::command]
async fn verify_sanitization_compliance_cmd(
    sanitized_text: String,
) -> Result<audit_sanitizer::SanitizationAuditProof, String> {
    Ok(audit_sanitizer::verify_sanitization_compliance(&sanitized_text))
}

#[tauri::command]
async fn get_sanitization_policies_cmd() -> Result<Vec<audit_sanitizer::SanitizationPolicy>, String> {
    Ok(audit_sanitizer::get_sanitization_policies())
}

#[tauri::command]
async fn generate_comprehensive_audit_report_cmd(
    examiner: String,
    scope: String,
) -> Result<serde_json::Value, String> {
    let net_stats = audit_network::get_network_audit_statistics();
    let data_summary = audit_data_security::get_data_security_summary();
    let conf_alerts = audit_confidentiality::get_confidentiality_alerts(Some(50));
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let report = serde_json::json!({
        "report_title": "四维安全合规审查综合勘验技术报告",
        "standard_reference": "GB/T 22239-2019 / GB/T 43697-2024 / 国家保密标准",
        "generated_at": now,
        "examiner": if examiner.is_empty() { "安全合规审查组" } else { &examiner },
        "audit_scope": if scope.is_empty() { "全域网络流量、通信数据与涉密载体" } else { &scope },
        "network_security": {
            "total_events": net_stats.total_events,
            "industrial_write_violations": net_stats.industrial_write_violations,
            "dns_tunnel_detected": net_stats.dns_tunnel_count,
            "icmp_tunnel_detected": net_stats.icmp_tunnel_count,
            "verdict": if net_stats.total_events == 0 { "合规" } else { "存在违规异常" }
        },
        "data_security": {
            "scanned_flows": data_summary.total_scanned_flows,
            "sensitive_hits": data_summary.total_sensitive_hits,
            "core_data_hits": data_summary.core_data_hits,
            "important_data_hits": data_summary.important_data_hits,
            "pii_hits": data_summary.pii_hits,
            "reconstructed_files": data_summary.reconstructed_files_count
        },
        "confidentiality_security": {
            "total_alerts": conf_alerts.len(),
            "critical_secret_markers": conf_alerts.iter().filter(|a| a.secrecy_level == "TOP_SECRET" || a.secrecy_level == "CONFIDENTIAL").count(),
            "illegal_egress_attempts": conf_alerts.iter().filter(|a| a.alert_category == "ILLEGAL_EGRESS").count(),
            "unauthorized_usb_devices": conf_alerts.iter().filter(|a| a.alert_category == "UNAUTHORIZED_USB_MEDIA").count()
        },
        "sanitization_status": {
            "status": "READY",
            "enforced_policy": "POLICY-STRICT-COMPLIANCE"
        }
    });

    Ok(report)
}

#[tauri::command]
async fn get_industrial_plugins_info_cmd() -> Result<Vec<serde_json::Value>, String> {
    let reg = industrial_plugin::INDUSTRIAL_PLUGIN_REGISTRY.read().map_err(|e| e.to_string())?;
    Ok(reg.get_plugins_metadata())
}

// ============================================================
// 兼容性适配别名指令 (提供双向防御，彻底消除历史缓存/未更新前端可能产生的命令断层)
// ============================================================
#[tauri::command]
async fn get_network_audit_stats_cmd() -> Result<audit_network::NetworkAuditStatistics, String> {
    get_network_audit_statistics_cmd().await
}

#[tauri::command]
async fn clear_data_security_audit_cmd() -> Result<(), String> {
    clear_data_security_records_cmd().await
}

#[tauri::command]
async fn sanitize_text_cmd(
    content: Option<String>,
    input_text: Option<String>,
    policy_id: Option<String>,
    policy_id_camel: Option<String>,
    _hmac_salt: Option<String>,
) -> Result<audit_sanitizer::SanitizationResult, String> {
    let text = input_text.or(content).unwrap_or_default();
    let pid = policy_id.or(policy_id_camel);
    apply_data_sanitization_cmd(text, pid).await
}

// ============================================================
// Wireshark / TShark 3000+ 全协议通用解剖桥接指令
// ============================================================
#[tauri::command]
fn check_tshark_status_cmd() -> tshark_bridge::TsharkStatus {
    let bridge = tshark_bridge::TsharkBridge::new();
    bridge.get_status()
}

#[tauri::command]
fn dissect_packet_with_tshark_cmd(
    packet_hex: String,
    link_type: Option<u32>,
) -> tshark_bridge::TsharkDissectionResult {
    let raw_bytes = hex::decode(packet_hex.trim()).unwrap_or_default();
    let bridge = tshark_bridge::TsharkBridge::new();
    bridge.dissect_single_packet(&raw_bytes, link_type)
}

#[tauri::command]
fn get_environment_inspection_cmd() -> env_inspector::EnvironmentInspectionReport {
    env_inspector::EnvironmentInspector::inspect_all()
}

#[tauri::command]
async fn download_and_install_component_cmd(
    app: tauri::AppHandle,
    component_id: String,
) -> Result<String, String> {
    env_inspector::EnvironmentInspector::download_and_launch_installer(app, component_id).await
}

// ============================================================
// 工业控制事务双向追踪指令 (对标 Zeek / Bro Event Engine)
// ============================================================
#[tauri::command]
fn get_recent_industrial_transactions_cmd(
    limit: Option<usize>,
) -> Vec<industrial_transaction::CompletedIndustrialTransaction> {
    let tracker = crate::lock_guard::lock_mutex(
        &industrial_transaction::GLOBAL_TRANSACTION_TRACKER,
        "lib::get_recent_industrial_transactions_cmd",
    );
    tracker.get_recent_transactions(limit.unwrap_or(50))
}

#[tauri::command]
fn get_industrial_transaction_stats_cmd() -> industrial_transaction::TransactionMetricsSnapshot {
    let tracker = crate::lock_guard::lock_mutex(
        &industrial_transaction::GLOBAL_TRANSACTION_TRACKER,
        "lib::get_industrial_transaction_stats_cmd",
    );
    tracker.get_metrics_snapshot()
}

// ============================================================
// 全协议目录、厂商 OUI 与工控 ACL 指令 (对标 Wireshark 3,200+ 规约库与 Suricata)
// ============================================================
#[tauri::command]
fn get_service_port_info_cmd(port: u16) -> Option<protocol_catalog::ServicePortInfo> {
    protocol_catalog::lookup_service_port(port)
}

#[tauri::command]
fn resolve_mac_vendor_cmd(mac_str: String) -> Option<protocol_catalog::MacVendorInfo> {
    let cleaned = mac_str.replace([':', '-'], "");
    match hex::decode(&cleaned) {
        Ok(bytes) => protocol_catalog::resolve_mac_vendor(&bytes),
        Err(e) => {
            eprintln!(
                "{{\"level\":\"WARN\",\"event\":\"INVALID_MAC_INPUT\",\"mac\":\"{}\",\"error\":\"{}\"}}",
                mac_str.replace('"', "\\\""),
                e
            );
            None
        }
    }
}

#[tauri::command]
fn lookup_ethertype_cmd(ether_type: u16) -> Option<protocol_catalog::EtherTypeInfo> {
    protocol_catalog::lookup_ethertype(ether_type)
}

#[tauri::command]
fn lookup_gm_cipher_suite_cmd(suite_id: u16) -> Option<gm_ssl::GmCipherSuiteInfo> {
    gm_ssl::lookup_gm_cipher_suite(suite_id)
}

#[tauri::command]
fn get_keyring_total_keys_cmd() -> usize {
    tls_keyring::GLOBAL_KEYRING_CACHE.total_keys()
}

#[tauri::command]
fn get_recent_cascade_diagnostics_cmd(
    limit: Option<usize>,
) -> Vec<cross_bus_diagnostic::CascadeDiagnosticRecord> {
    cross_bus_diagnostic::GLOBAL_CASCADE_DIAGNOSTIC_ENGINE.get_recent_diagnostics(limit.unwrap_or(50))
}

#[tauri::command]
fn get_cascade_metrics_cmd() -> cross_bus_diagnostic::CascadeMetricsSnapshot {
    cross_bus_diagnostic::GLOBAL_CASCADE_DIAGNOSTIC_ENGINE.get_metrics_snapshot()
}

// ============================================================
// 多分辨率时序遥测与工业资产通信热力雷达 (对标 Sniffnet / ntopng)
// ============================================================
#[tauri::command]
fn get_timeseries_metrics_cmd(
    resolution: String,
) -> Vec<metrics_timeseries::TimeSeriesBucket> {
    let res = metrics_timeseries::TimeResolution::from_str_name(&resolution);
    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    metrics_timeseries::GLOBAL_TIMESERIES_POOL.get_series(res, now_s)
}

#[tauri::command]
fn get_industrial_heatmap_matrix_cmd(
    limit: Option<usize>,
) -> Vec<metrics_timeseries::TopologyHeatmapCell> {
    metrics_timeseries::GLOBAL_TOPOLOGY_HEATMAP.get_top_heatmap(limit.unwrap_or(50))
}

pub fn run() {
    // 0. 启动崩溃审计与全局未捕获 panic 拦截
    instance_guard::setup_panic_hook();

    // 1. Windows 原生命名互斥体保护 (防多实例 EBWebView 锁死崩溃与竞态冲突)
    instance_guard::ensure_single_instance();

    // 2. EBWebView 孤立锁自愈清理
    instance_guard::cleanup_stale_webview_locks();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            use tauri::Manager;
            // 【证据路径注入——必须先于一切子系统启动】
            // 顺序铁律：init_data_dir → get_config（触发 config.json 读写）→ init_evidence_names
            // → 其它子系统。任何 writer Lazy 在 init_evidence_names 之前触发，
            // 都会以默认文件名打开证据文件，导致 config 自定义文件名失效。
            match app.path().app_data_dir() {
                Ok(dir) => forensics::init_data_dir(dir),
                Err(e) => eprintln!(
                    "[FORENSICS] ⚠️ app_data_dir 获取失败（{}），证据文件回退 exe 同目录",
                    e
                ),
            }
            let cfg = config::get_config();
            forensics::init_evidence_names(
                cfg.data_storage.pcap_file.clone(),
                cfg.data_storage.file.clone(),
                cfg.logging.file.clone(),
            );

            // 【主动加载 IP 资产情报离线库 (外部热更库优先覆盖；未提供时自动运行编译期内嵌零拷贝基准库)】
            let mut candidate_paths = vec![
                forensics::data_path("ip2region.xdb"),
            ];
            if let Ok(app_dir) = app.path().app_data_dir() {
                candidate_paths.push(app_dir.join("ip2region.xdb"));
                candidate_paths.push(app_dir.join("data/ip2region.xdb"));
            }
            if let Ok(res_dir) = app.path().resource_dir() {
                candidate_paths.push(res_dir.join("data/ip2region.xdb"));
                candidate_paths.push(res_dir.join("ip2region.xdb"));
            }
            if let Ok(exe_path) = std::env::current_exe() {
                if let Some(exe_dir) = exe_path.parent() {
                    candidate_paths.push(exe_dir.join("data/ip2region.xdb"));
                    candidate_paths.push(exe_dir.join("ip2region.xdb"));
                }
            }

            let mut external_loaded = false;
            for p in &candidate_paths {
                if p.exists() {
                    if let Ok(meta) = std::fs::metadata(p) {
                        if meta.len() >= 5 * 1024 * 1024 {
                            let mut engine = crate::lock_guard::lock_mutex(
                                &ip_intelligence::GLOBAL_IP_ENGINE,
                                "lib::setup_load_external_xdb",
                            );
                            if let Ok(msg) = engine.load_xdb(&p.to_string_lossy()) {
                                println!("[IP_INTELLIGENCE] ✓ 已挂载外部扩展库: {}", msg);
                                external_loaded = true;
                                break;
                            }
                        }
                    }
                }
            }
            if !external_loaded {
                let engine = crate::lock_guard::lock_mutex(
                    &ip_intelligence::GLOBAL_IP_ENGINE,
                    "lib::setup_check_builtin_xdb",
                );
                println!(
                    "[IP_INTELLIGENCE] ✓ 无外部覆盖库，已激活内置零拷贝 XDB 基准轨 (Ready: {})",
                    engine.is_xdb_loaded()
                );
            }

            discovery::start_asset_discovery_daemon(app.handle().clone());
            serial::start_serial_hotplug_detector(app.handle().clone());
            app.manage(net_assist::NetAssistManager::new());

            // 挂载原生桌面系统托盘与原生右键上下文菜单 (彻底脱离 Web 浏览器形态)
            {
                use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
                use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

                let show_i = MenuItem::with_id(app, "tray_show", "显示主监控控制台", true, None::<&str>)?;
                let diff_i = MenuItem::with_id(app, "tray_diff", "大文件 / 目录比对工作台", true, None::<&str>)?;
                let hide_i = MenuItem::with_id(app, "tray_hide", "最小化隐藏至系统托盘", true, None::<&str>)?;
                let sep_i = PredefinedMenuItem::separator(app)?;
                let quit_i = MenuItem::with_id(app, "tray_quit", "安全终止探针并退出", true, None::<&str>)?;
                let tray_menu = Menu::with_items(app, &[&show_i, &diff_i, &hide_i, &sep_i, &quit_i])?;

                let mut builder = TrayIconBuilder::with_id("omni-probe-tray")
                    .menu(&tray_menu)
                    .tooltip("Omni-Probe 工业全能网络与总线探针系统")
                    .show_menu_on_left_click(false)
                    .on_menu_event(|app_h, event| match event.id.as_ref() {
                        "tray_show" => {
                            if let Some(w) = app_h.get_webview_window("main") {
                                let _ = w.unminimize();
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        }
                        "tray_diff" => {
                            if let Some(w) = app_h.get_webview_window("main") {
                                let _ = w.unminimize();
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                            let _ = app_h.emit("desktop-open-file-diff", ());
                        }
                        "tray_hide" => {
                            if let Some(w) = app_h.get_webview_window("main") {
                                let _ = w.hide();
                            }
                        }
                        "tray_quit" => {
                            honeypot::stop_honeypot();
                            active_probe::stop_stream_pull();
                            serial::stop_serial_probe(None);
                            serial::stop_serial_bridge(None);
                            serial_intercept::stop_intercept_session(None);
                            usb::stop_usb_sniffer();
                            cloud::stop_cloud_streaming();
                            app_h.exit(0);
                        }
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            let app_h = tray.app_handle();
                            if let Some(w) = app_h.get_webview_window("main") {
                                let _ = w.unminimize();
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        }
                    });

                if let Some(icon) = app.default_window_icon() {
                    builder = builder.icon(icon.clone());
                }
                if let Err(e) = builder.build(app) {
                    eprintln!("[TRAY] ⚠️ 宿主桌面环境未启用系统托盘 (已优雅降级，主窗口正常运行): {}", e);
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // 探针主引擎
            start_capture,
            pause_capture,
            resume_capture,
            stop_capture,
            inject_raw_packet,
            list_interfaces,
            // 物理串口与 USB 嗅探及端口操作数据收发
            list_serial_ports,
            list_serial_ports_detail,
            list_active_serial_probes,
            list_active_serial_bridges,
            start_serial_capture,
            start_serial_capture_with_config,
            get_serial_modem_status,
            set_serial_pin_state,
            start_serial_bridge_cmd,
            stop_serial_bridge_cmd,
            stop_serial_capture,
            send_serial_data_cmd,
            list_usb_devices,
            list_usbpcap_hubs_cmd,
            get_captured_usb_descriptor_cmd,
            decode_vcd_uart_waveform_cmd,
            parse_usb_descriptor_tree_cmd,
            start_usb_capture,
            stop_usb_capture,
            send_serial_probe_frame_cmd,
            send_port_transceive_cmd,
            // 分析工具与基线管理
            run_matrix_compare,
            run_matrix_compare_labeled_cmd,
            save_baseline_payloads_cmd,
            load_baseline_payloads_cmd,
            compare_with_historical_baseline_cmd,
            get_discovered_assets_cmd,
            trigger_asset_scan_cmd,
            probe_asset_ports_cmd,
            probe_all_assets_cmd,
            clear_discovered_assets_cmd,
            set_wave_tracker,
            get_io_graph_series_cmd,
            get_cross_bus_correlations_cmd,
            // 蜜罐引擎
            start_honeypot_cmd,
            stop_honeypot_cmd,
            is_honeypot_running_cmd,
            // 主动探测与报文重放
            run_target_scan_cmd,
            start_continuous_probe_cmd,
            stop_continuous_probe_cmd,
            start_stream_pull_cmd,
            stop_stream_pull_cmd,
            run_icmp_ping_cmd,
            replay_l4_packet_cmd,
            // 司法手动封条与证据链验真
            manual_seal_cmd,
            verify_evidence_chain_cmd,
            get_forensic_vault_cmd,
            get_chain_of_custody_cmd,
            set_worm_lock_cmd,
            generate_tsa_timestamp_cmd,
            generate_judicial_report_cmd,
            export_pcapng_cmd,
            get_fidelity_certificate_cmd,
            // 配置体系（config.json 读写）
            get_config_cmd,
            save_config_cmd,
            // 限速配置
            update_throttle_config_cmd,
            // 云端流式上报
            start_cloud_streaming_cmd,
            stop_cloud_streaming_cmd,
            // DPI 动态字典手动重载
            reload_dpi_signatures_cmd,
            // 日志管理
            clear_logs,
            // 专业流量分析与持久化 (Sprint 3)
            set_snaplen_mode_cmd,
            set_rolling_pcap_config_cmd,
            export_packets_pcap_cmd,
            export_packets_pcapng_cmd,
            export_packets_csv_cmd,
            export_packets_json_cmd,
            export_packets_har_cmd,
            import_pcap_file_cmd,
            get_biflow_sessions_cmd,
            follow_tcp_stream_cmd,
            classify_ip_cmd,
            get_cidr_rules_cmd,
            save_cidr_rules_cmd,
            // 离线 IP 归属地库管理与主机名解析
            download_ip_db_cmd,
            load_local_ip_db_cmd,
            get_ip_db_status_cmd,
            test_lookup_ip_cmd,
            resolve_ip_hostname_cmd,
            // 等保三级扩展 (RBAC、Syslog RFC 5424、工业通信基线自学习)
            get_syslog_config_cmd,
            save_syslog_config_cmd,
            test_send_syslog_cmd,
            get_current_user_cmd,
            get_rbac_security_status_cmd,
            get_audit_compliance_snapshot_cmd,
            switch_user_role_cmd,
            get_admin_audit_trail_cmd,
            validate_display_filter_cmd,
            filter_packets_by_ast_cmd,
            get_standard_field_registry_cmd,
            fetch_paged_packets_cmd,
            get_stream_buffer_stats_cmd,
            get_baseline_status_cmd,
            set_baseline_mode_cmd,
            get_baseline_rules_cmd,
            clear_baseline_rules_cmd,
            get_baseline_drift_events_cmd,
            persist_baseline_rules_cmd,
            change_role_password_cmd,
            // 三大优先级：数据保存与专业差分比对
            save_asset_snapshot_cmd,
            list_asset_snapshots_cmd,
            get_asset_snapshot_cmd,
            delete_asset_snapshot_cmd,
            compare_asset_snapshots_cmd,
            save_packet_sample_cmd,
            list_packet_samples_cmd,
            delete_packet_sample_cmd,
            compare_two_packets_cmd,
            compare_universal_payloads_cmd,
            compare_multi_universal_payloads_cmd,
            export_multi_diff_patch_cmd,
            save_hardware_whitelist_cmd,
            get_hardware_whitelist_cmd,
            clear_hardware_whitelist_cmd,
            verify_hardware_compliance_cmd,
            // 全息上网行为监测与外联合规审计
            get_web_access_logs_cmd,
            get_web_audit_statistics_cmd,
            clear_web_access_logs_cmd,
            get_dns_cache_table_cmd,
            export_web_access_logs_cmd,
            // 流量解密与过滤级防火墙系统
            start_tls_proxy_cmd,
            stop_tls_proxy_cmd,
            get_proxy_status_cmd,
            get_ca_cert_pem_cmd,
            load_sslkeylog_file_cmd,
            get_keylog_status_cmd,
            clear_keylog_cache_cmd,
            get_firewall_rules_cmd,
            save_firewall_rules_cmd,
            get_decrypted_traffic_logs_cmd,
            clear_decrypted_traffic_logs_cmd,
            set_active_blocking_mode_cmd,
            decrypt_stream_with_keylog_cmd,
            // 四维安全合规审查专属指令
            get_network_audit_events_cmd,
            get_network_audit_statistics_cmd,
            clear_network_audit_events_cmd,
            get_data_security_summary_cmd,
            get_sensitive_findings_cmd,
            get_reconstructed_files_cmd,
            clear_data_security_records_cmd,
            get_confidentiality_alerts_cmd,
            scan_confidentiality_text_cmd,
            clear_confidentiality_alerts_cmd,
            apply_data_sanitization_cmd,
            verify_sanitization_compliance_cmd,
            get_sanitization_policies_cmd,
            generate_comprehensive_audit_report_cmd,
            get_industrial_plugins_info_cmd,
            // 兼容性适配别名注册
            get_network_audit_stats_cmd,
            clear_data_security_audit_cmd,
            sanitize_text_cmd,
            // Wireshark 3000+ 全协议通用解剖器
            check_tshark_status_cmd,
            dissect_packet_with_tshark_cmd,
            // 底层环境就绪度全景诊断
            get_environment_inspection_cmd,
            download_and_install_component_cmd,
            // 工业事务双向追踪指令
            get_recent_industrial_transactions_cmd,
            get_industrial_transaction_stats_cmd,
            get_service_port_info_cmd,
            resolve_mac_vendor_cmd,
            lookup_ethertype_cmd,
            lookup_gm_cipher_suite_cmd,
            get_keyring_total_keys_cmd,
            get_recent_cascade_diagnostics_cmd,
            get_cascade_metrics_cmd,
            get_timeseries_metrics_cmd,
            get_industrial_heatmap_matrix_cmd,
            // 窗口控制
            minimize_app,
            maximize_app,
            close_app,
            drag_app,
            // 离线报文高精调度重放与零拷贝内存池 (TASK-20 / TASK-21)
            load_pcap_replay_file_cmd,
            start_pcap_replay_cmd,
            pause_pcap_replay_cmd,
            resume_pcap_replay_cmd,
            stop_pcap_replay_cmd,
            step_pcap_replay_cmd,
            get_pcap_replay_telemetry_cmd,
            get_zero_copy_pool_metrics_cmd,
            get_kernel_zero_copy_telemetry_cmd,
            // 交换机物理端口联动、万级主机分级聚合拓扑树与分布式探针汇聚 (TASK-36)
            get_hierarchical_topology_viewport_cmd,
            drill_down_topology_node_cmd,
            roll_up_topology_node_cmd,
            collapse_all_topology_cmd,
            locate_asset_switch_port_cmd,
            get_distributed_probe_cluster_cmd,
            // 宏观长周期与非平稳日历自适应自学习基线 (TASK-37)
            get_macro_calendar_baseline_status_cmd,
            infer_unsupervised_day_regime_cmd,
            import_statutory_calendar_date_cmd,
            // 基于 UDP 的 HTTP/3 (QUIC) 深度多流解密与解剖 (TASK-38)
            inspect_and_decrypt_quic_packet_cmd,
            get_quic_streams_cmd,
            get_quic_telemetry_cmd,
            // CAN / CAN-FD 现场总线原生解剖与跨以太网网关因果诊断 (TASK-39)
            dissect_can_packet_cmd,
            get_can_causal_records_cmd,
            get_can_bus_health_cmd,
            // 物理硬件逻辑分析仪原生采样位流驱动与纳秒电气级信号解调 (TASK-40 + SUMP 探头 + 4总线解码)
            demodulate_physical_uart_cmd,
            evaluate_signal_integrity_cmd,
            probe_sump_logic_analyzer_cmd,
            capture_sump_logic_samples_cmd,
            decode_multibus_vcd_cmd,
            get_xdp_bypass_metrics_cmd,
            mark_flow_bypassed_cmd,
            evaluate_xdp_packet_cmd,
            apply_xdp_policy_preset_cmd,
            // Windows Filtering Platform (WFP) 内核态入出站阻断联动
            wfp_block_ip_cmd,
            wfp_unblock_ip_cmd,
            get_wfp_status_cmd,
            // 基于 Glushkov 构造算法与位并行 (Bit-Parallel) 的 Hyperscan 风格高性能正则/多模式匹配 (TASK-42)
            get_glushkov_engine_metrics_cmd,
            scan_payload_glushkov_cmd,
            reset_glushkov_engine_metrics_cmd,
            // TLS JA3/JA4 指纹与 Suricata DSL 入侵检测及安全脚本沙箱引擎
            get_tls_fingerprint_telemetry_cmd,
            get_suricata_dsl_metrics_cmd,
            load_suricata_dsl_rules_cmd,
            evaluate_audit_script_cmd,
            // 测地线可视路由追踪与地球地理情报 (TASK-43)
            start_traceroute_cmd,
            lookup_ip_geo_coordinates_cmd,
            get_self_ip_geo_cmd,
            // Wi-Fi / 802.11 无线与链路监测
            get_wifi_telemetry_cmd,
            reset_wifi_telemetry_cmd,
            wifi_monitor::scan_os_wifi_networks_cmd,
            // VLAN / QinQ 专业虚拟局域网监测
            get_vlan_telemetry_cmd,
            reset_vlan_telemetry_cmd,
            // 蓝牙 BR/EDR / BLE / HCI 专业监测与 GATT 服务枚举 + BTHPORT ETW 原生抓取 + BTSnoop & 基线对比
            get_bluetooth_telemetry_cmd,
            reset_bluetooth_telemetry_cmd,
            bluetooth_monitor::scan_native_bluetooth_devices_cmd,
            bluetooth_monitor::scan_ble_gatt_services_cmd,
            read_ble_gatt_characteristic_cmd,
            save_bluetooth_baseline_cmd,
            compare_bluetooth_realtime_vs_history_cmd,
            export_bluetooth_btsnoop_cmd,
            pick_and_import_bluetooth_btsnoop_cmd,
            start_continuous_ble_monitor_cmd,
            stop_continuous_ble_monitor_cmd,
            start_bthport_etw_capture_cmd,
            stop_bthport_etw_capture_cmd,
            // COM & USB 深度辅助开发、黄金波形 FFT/DTW 智能比对与专业巡检报告引擎
            save_waveform_baseline_cmd,
            list_waveform_baselines_cmd,
            delete_waveform_baseline_cmd,
            smart_compare_waveforms_cmd,
            compute_waveform_fft_cmd,
            get_bus_intelligence_snapshot_cmd,
            compute_serial_checksum_cmd,
            upsert_serial_auto_rule_cmd,
            delete_serial_auto_rule_cmd,
            start_serial_periodic_tx_cmd,
            stop_serial_periodic_tx_cmd,
            export_usb_usbpcap_pcap_cmd,
            pick_and_import_usb_pcap_cmd,
            generate_bus_inspection_report_cmd,
            export_bus_inspection_report_cmd,
            // 嵌入式单片机开发伴侣 (VOFA JustFloat/Struct多通道 / PID阶跃 / MCU外设速算 / 固件分片下发 / ANSI终端)
            parse_binary_struct_batch_cmd,
            compute_step_response_metrics_cmd,
            solve_mcu_timer_psc_arr_cmd,
            calc_uart_baud_error_cmd,
            decode_modbus_32bit_word_cmd,
            analyze_mcu_console_lines_cmd,
            pick_and_send_serial_bin_file_cmd,
            export_serial_stream_log_cmd,
            // 历史总线索归档流式回溯
            forensics::query_historical_bus_archive_cmd,
            // 无线与 VLAN 统一诊断解剖
            dissect_wireless_or_vlan_hex_cmd,
            // 全球网络空间地理态势地图与双向测绘数据 (TASK-46)
            get_global_geo_map_data_cmd,
            resolve_real_traffic_geo_cmd,
            probe_active_os_sockets_cmd,
            // 工业级网络调试助手 (NetAssist)
            start_net_assist_session_cmd,
            stop_net_assist_session_cmd,
            send_net_assist_data_cmd,
            get_net_assist_clients_cmd,
            calculate_checksum_cmd,
            get_local_ip_addresses_cmd,
            // 网络深度主动扫描、多维流量统计、基线/.pcap 比对与行业报告导出
            run_network_port_scan_cmd,
            analyze_network_traffic_stats_cmd,
            reset_live_net_stats_cmd,
            save_network_baseline_cmd,
            get_network_baseline_cmd,
            compare_network_with_baseline_cmd,
            pick_and_compare_network_pcap_cmd,
            export_network_audit_report_cmd,
            // 自动版本检查与在线更新
            check_app_update_cmd,
            // 跨平台内建驱动级串口透明拦截 (PTY / Win32 NamedPipe / RFC2217 / WDM IRP Tap)
            get_serial_intercept_capabilities_cmd,
            list_active_intercept_sessions_cmd,
            start_rfc2217_intercept_gateway_cmd,
            start_windows_named_pipe_intercept_cmd,
            start_unix_pty_intercept_cmd,
            start_kernel_filter_tap_cmd,
            smart_start_serial_intercept_cmd,
            stop_intercept_session_cmd,
            // Beyond Compare 级流式大文件 Myers Diff、FastCDC 滚动锚点、目录对比与原子双向合并
            compare_text_files_streaming_cmd,
            apply_text_merge_and_save_cmd,
            export_unified_patch_file_cmd,
            compare_binary_files_streaming_cmd,
            compare_binary_files_fastcdc_cmd,
            read_binary_diff_page_cmd,
            read_binary_diff_dual_offset_page_cmd,
            compare_directories_cmd,
            // 原生桌面文件系统对话、原子导出与资源管理器定位
            hide_to_tray_cmd,
            pick_native_file_dialog_cmd,
            pick_native_folder_dialog_cmd,
            save_text_with_native_dialog_cmd,
            reveal_in_file_manager_cmd
        ])
        .on_window_event(|_window, event| match event {
            tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed => {
                {
                    let mut running = crate::lock_guard::lock_mutex(&PROBE_RUNNING, "lib::on_window_event_close");
                    *running = false;
                }
                honeypot::stop_honeypot();
                active_probe::stop_stream_pull();
                serial::stop_serial_probe(None);
                bus_intelligence::stop_serial_periodic_tx_cmd();
                serial::stop_serial_bridge(None);
                serial_intercept::stop_intercept_session(None);
                usb::stop_usb_sniffer();
                cloud::stop_cloud_streaming();
                std::process::exit(0);
            }
            _ => {}
        })
        .run(tauri::generate_context!())
        .expect("Tauri application runtime error");
}
