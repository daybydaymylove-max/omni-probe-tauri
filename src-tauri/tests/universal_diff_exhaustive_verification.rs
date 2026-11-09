//! ==============================================================================
//! Omni-Probe 全局通用数据比对、分析与统计引擎——硬核全源集成测试与极限验证
//! ==============================================================================
//! 覆盖 5 大数据源形态：
//! 1. 网络嗅探抓包报文 (Wireshark-grade PacketRecord)
//! 2. NetAssist 网络调试助手收发历史帧 (TX Request vs RX Response)
//! 3. 硬件串口/工业总线交互数据 (Serial Modbus-RTU / Bus IO)
//! 4. TLS/HTTPS 全息解密明文流 (Decrypted HTTP Payload)
//! 5. 自由草稿即时输入 (Scratchpad Hex & Raw String)
//! 
//! 并严格穷举验证 3 类极限边界用例：
//! 1. 零数据边界 (0 字节空载荷)
//! 2. 全零向量数学边界 (All Zeros Vector，防 NaN / 除以零溢出)
//! 3. 巨量数据压力边界 (100,000 字节超长载荷突变验证)
//! ==============================================================================

use omni_probe_tauri_lib::analyzer::{
    compare_universal_payloads, compute_waveform_metrics, compute_mutation_spectrum,
    UniversalDiffPayload,
};
use std::collections::HashMap;

#[test]
fn test_datasource_1_network_sniffing_packets_diff() {
    // 数据源 1: 真实网络嗅探报文 (以 Modbus-TCP 读取保持寄存器请求 vs 响应为例)
    let mut extra_a = HashMap::new();
    extra_a.insert("transaction_id".to_string(), "0x0001".to_string());
    extra_a.insert("function_code".to_string(), "0x03 (Read Holding Registers)".to_string());
    extra_a.insert("register_count".to_string(), "2".to_string());

    let mut extra_b = HashMap::new();
    extra_b.insert("transaction_id".to_string(), "0x0001".to_string());
    extra_b.insert("function_code".to_string(), "0x03 (Read Holding Registers)".to_string());
    extra_b.insert("byte_count".to_string(), "4".to_string());

    let packet_a = UniversalDiffPayload {
        id: Some(1001),
        label: "以太网嗅探 #1001 [Modbus-TCP]".to_string(),
        timestamp: Some("17:00:01.120".to_string()),
        protocol: Some("Modbus-TCP".to_string()),
        endpoint_src: Some("192.168.1.100:50201".to_string()),
        endpoint_dst: Some("192.168.1.200:502".to_string()),
        payload_hex: "00 01 00 00 00 06 01 03 00 00 00 02".to_string(), // 12 字节请求
        raw_text: None,
        extra_fields: Some(extra_a),
    };

    let packet_b = UniversalDiffPayload {
        id: Some(1002),
        label: "以太网嗅探 #1002 [Modbus-TCP]".to_string(),
        timestamp: Some("17:00:01.145".to_string()),
        protocol: Some("Modbus-TCP".to_string()),
        endpoint_src: Some("192.168.1.200:502".to_string()),
        endpoint_dst: Some("192.168.1.100:50201".to_string()),
        payload_hex: "00 01 00 00 00 07 01 03 04 00 12 00 34".to_string(), // 13 字节响应
        raw_text: None,
        extra_fields: Some(extra_b),
    };

    let diff = compare_universal_payloads(packet_a, packet_b).expect("网络报文比对成功");
    assert_eq!(diff.total_bytes_a, 12);
    assert_eq!(diff.total_bytes_b, 13);
    assert!(diff.mutated_bytes_count > 0, "必定存在差异变异字节");
    assert!(diff.waveform_metrics.is_some(), "必须产出五维波形统计指标");

    let wm = diff.waveform_metrics.unwrap();
    // 余弦相似度必须在 [0.0, 1.0] 闭区间内
    assert!(wm.cosine_similarity >= 0.0 && wm.cosine_similarity <= 1.0);
    // 皮尔逊系数必须在 [-1.0, 1.0] 闭区间内且不能为 NaN
    assert!(!wm.pearson_correlation.is_nan());
    assert!(wm.pearson_correlation >= -1.0 && wm.pearson_correlation <= 1.0);
    // 突变率必须大于 0%
    assert!(wm.mutation_wave_rate > 0.0);
    // 必定捕获到最大跳变峰
    assert!(wm.max_delta_value > 0);
}

#[test]
fn test_datasource_2_netassist_tx_vs_rx_diff() {
    // 数据源 2: NetAssist 网络调试助手 (发送区指令 vs 接收端回包)
    let mut extra_tx = HashMap::new();
    extra_tx.insert("通信流向".to_string(), "TX".to_string());
    extra_tx.insert("规约模式".to_string(), "TCP_CLIENT".to_string());

    let mut extra_rx = HashMap::new();
    extra_rx.insert("通信流向".to_string(), "RX".to_string());
    extra_rx.insert("规约模式".to_string(), "TCP_CLIENT".to_string());

    let net_tx = UniversalDiffPayload {
        id: Some(1),
        label: "[TX 请求帧] 127.0.0.1:8080".to_string(),
        timestamp: Some("17:10:00.000".to_string()),
        protocol: Some("TCP".to_string()),
        endpoint_src: Some("本地发送端".to_string()),
        endpoint_dst: Some("127.0.0.1:8080".to_string()),
        payload_hex: "01 03 00 00 00 02 C4 0B".to_string(),
        raw_text: None,
        extra_fields: Some(extra_tx),
    };

    let net_rx = UniversalDiffPayload {
        id: Some(2),
        label: "[RX 最新回复] 127.0.0.1:8080".to_string(),
        timestamp: Some("17:10:00.015".to_string()),
        protocol: Some("TCP".to_string()),
        endpoint_src: Some("127.0.0.1:8080".to_string()),
        endpoint_dst: Some("本地接收端".to_string()),
        payload_hex: "01 03 04 00 12 00 34 89 21".to_string(),
        raw_text: None,
        extra_fields: Some(extra_rx),
    };

    let diff = compare_universal_payloads(net_tx, net_rx).expect("NetAssist 比对执行成功");
    assert_eq!(diff.total_bytes_a, 8);
    assert_eq!(diff.total_bytes_b, 9);
    // 检查字段比对列表中存在流向差异 (TX vs RX)
    let dir_field = diff.field_diffs.iter().find(|f| f.field_name == "通信流向");
    assert!(dir_field.is_some());
    assert_eq!(dir_field.unwrap().diff_type, "CHANGED");
}

#[test]
fn test_datasource_3_hardware_serial_bus_diff() {
    // 数据源 3: 硬件串口与总线交互流水 (Serial / CAN / USB)
    let mut extra_bus = HashMap::new();
    extra_bus.insert("波特率".to_string(), "115200".to_string());
    extra_bus.insert("端口".to_string(), "COM3 (USB-SERIAL CH340)".to_string());

    let ser_tx = UniversalDiffPayload {
        id: Some(501),
        label: "[硬件发送] 串口 COM3 ➔ 01号从机".to_string(),
        timestamp: Some("17:20:00.100".to_string()),
        protocol: Some("Modbus-RTU".to_string()),
        endpoint_src: Some("COM3".to_string()),
        endpoint_dst: Some("从机01".to_string()),
        payload_hex: "01 06 00 01 00 64 D9 E1".to_string(), // 写单寄存器 100
        raw_text: None,
        extra_fields: Some(extra_bus.clone()),
    };

    let ser_rx = UniversalDiffPayload {
        id: Some(502),
        label: "[硬件回包] 串口 COM3 ➔ 01号从机".to_string(),
        timestamp: Some("17:20:00.122".to_string()),
        protocol: Some("Modbus-RTU".to_string()),
        endpoint_src: Some("从机01".to_string()),
        endpoint_dst: Some("COM3".to_string()),
        payload_hex: "01 06 00 01 00 64 D9 E1".to_string(), // 正常响应回显
        raw_text: None,
        extra_fields: Some(extra_bus),
    };

    let diff = compare_universal_payloads(ser_tx, ser_rx).expect("串口帧比对成功");
    // 写寄存器成功时的回包与请求完全相同，突变率应为 0%
    assert_eq!(diff.mutated_bytes_count, 0);
    assert_eq!(diff.mutation_rate_percent, 0.0);
    let wm = diff.waveform_metrics.unwrap();
    assert_eq!(wm.mutation_wave_rate, 0.0);
    assert!((wm.cosine_similarity - 1.0).abs() < 1e-6);
    assert_eq!(wm.max_delta_value, 0);
}

#[test]
fn test_datasource_4_tls_decrypted_payload_diff() {
    // 数据源 4: TLS 全息代理解密明文 (HTTP 报文)
    let dec_req = UniversalDiffPayload {
        id: Some(9001),
        label: "[解密请求] GET https://api.industrial.internal/v1/sensors".to_string(),
        timestamp: Some("17:30:00.000".to_string()),
        protocol: Some("HTTP/1.1".to_string()),
        endpoint_src: Some("10.0.0.5:54321".to_string()),
        endpoint_dst: Some("10.0.0.1:443".to_string()),
        payload_hex: "".to_string(),
        raw_text: Some("GET /v1/sensors HTTP/1.1\r\nHost: api.industrial.internal\r\nAccept: application/json\r\n\r\n".to_string()),
        extra_fields: None,
    };

    let dec_resp = UniversalDiffPayload {
        id: Some(9002),
        label: "[解密响应] 200 OK".to_string(),
        timestamp: Some("17:30:00.035".to_string()),
        protocol: Some("HTTP/1.1".to_string()),
        endpoint_src: Some("10.0.0.1:443".to_string()),
        endpoint_dst: Some("10.0.0.5:54321".to_string()),
        payload_hex: "".to_string(),
        raw_text: Some("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\",\"temperature\":24.5}".to_string()),
        extra_fields: None,
    };

    let diff = compare_universal_payloads(dec_req, dec_resp).expect("解密明文比对成功");
    assert!(diff.total_bytes_a > 20);
    assert!(diff.total_bytes_b > 20);
    assert!(diff.mutated_bytes_count > 0);
    assert!(diff.waveform_metrics.is_some());
}

#[test]
fn test_datasource_5_scratchpad_free_paste_diff() {
    // 数据源 5: 自由草稿箱 (纯文本、乱序空格、非格式化 HEX 码流输入)
    let scratch_a = UniversalDiffPayload {
        id: None,
        label: "草稿 A (带乱序空白的 Hex)".to_string(),
        timestamp: None,
        protocol: None,
        endpoint_src: None,
        endpoint_dst: None,
        payload_hex: "  41 42 43 \n 44   45  ".to_string(), // "ABCDE"
        raw_text: None,
        extra_fields: None,
    };

    let scratch_b = UniversalDiffPayload {
        id: None,
        label: "草稿 B (突变尾字节)".to_string(),
        timestamp: None,
        protocol: None,
        endpoint_src: None,
        endpoint_dst: None,
        payload_hex: "41 42 43 44 5A".to_string(), // "ABCDZ"
        raw_text: None,
        extra_fields: None,
    };

    let diff = compare_universal_payloads(scratch_a, scratch_b).expect("草稿箱比对成功");
    assert_eq!(diff.total_bytes_a, 5);
    assert_eq!(diff.total_bytes_b, 5);
    // 只有第 5 字节发生突变 (0x45 'E' -> 0x5A 'Z')
    assert_eq!(diff.mutated_bytes_count, 1);
    assert_eq!(diff.mutation_rate_percent, 20.0);
    let wm = diff.waveform_metrics.unwrap();
    assert_eq!(wm.max_delta_offset, 4); // 偏移下标 4
    assert_eq!(wm.max_delta_value, 0x5A - 0x45); // 90 - 69 = 21
}

#[test]
fn test_edge_cases_and_extremes_resilience() {
    // 极限用例 1: 零字节空数据对
    let empty_a = UniversalDiffPayload {
        id: None,
        label: "空 A".to_string(),
        timestamp: None,
        protocol: None,
        endpoint_src: None,
        endpoint_dst: None,
        payload_hex: "".to_string(),
        raw_text: None,
        extra_fields: None,
    };
    let empty_b = UniversalDiffPayload {
        id: None,
        label: "空 B".to_string(),
        timestamp: None,
        protocol: None,
        endpoint_src: None,
        endpoint_dst: None,
        payload_hex: "".to_string(),
        raw_text: None,
        extra_fields: None,
    };
    let diff_empty = compare_universal_payloads(empty_a, empty_b).expect("零字节不能 panic");
    assert_eq!(diff_empty.total_bytes_a, 0);
    assert_eq!(diff_empty.total_bytes_b, 0);
    assert_eq!(diff_empty.mutation_rate_percent, 0.0);

    // 极限用例 2: 全零纯向量 (模长为 0，验证防除零崩溃)
    let zeros_a = vec![0u8; 64];
    let zeros_b = vec![0u8; 64];
    let wm_zeros = compute_waveform_metrics(&zeros_a, &zeros_b);
    assert_eq!(wm_zeros.mutation_wave_rate, 0.0);
    assert!(!wm_zeros.cosine_similarity.is_nan(), "全零向量余弦相似度不能产生 NaN");
    assert!(!wm_zeros.pearson_correlation.is_nan(), "全零向量皮尔逊系数不能产生 NaN");

    // 极限用例 3: 100KB 超长高负载突变压测
    let large_a = vec![0x55u8; 100_000];
    let mut large_b = vec![0x55u8; 100_000];
    // 在中间与末尾各注入突变点
    large_b[50_000] = 0xAA;
    large_b[99_999] = 0xFF;

    let start = std::time::Instant::now();
    let wm_large = compute_waveform_metrics(&large_a, &large_b);
    let elapsed = start.elapsed();

    // 100KB 数据五维计算耗时必须在 50ms 以内（工业级高效吞吐）
    assert!(elapsed.as_millis() < 50, "100KB 指标计算必须超快速响应，实际耗时: {:?}", elapsed);
    assert_eq!(wm_large.waveform_points.len(), 100_000);
    assert_eq!(wm_large.max_delta_offset, 99_999);
    assert_eq!(wm_large.max_delta_value, 0xFF - 0x55); // 255 - 85 = 170

    // 验证多报文变异波率谱与局部信息熵
    let p1 = vec![0x10, 0x20, 0x30];
    let p2 = vec![0x10, 0x25, 0x30];
    let p3 = vec![0x10, 0x99, 0x30];
    let spec = compute_mutation_spectrum(&[p1, p2, p3]);
    assert_eq!(spec.len(), 3);
    assert_eq!(spec[0].mutation_rate, 0.0);
    assert!(spec[1].mutation_rate > 0.0);
    assert_eq!(spec[2].mutation_rate, 0.0);
    assert!(spec[1].entropy > 0.0, "发生突变的偏移位局部信息熵必定大于 0");
}
