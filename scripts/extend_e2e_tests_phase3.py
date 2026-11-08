with open("src-tauri/tests/hardcore_e2e_pipeline_verification.rs", "r", encoding="utf-8") as f:
    text = f.read()

new_tests = """
/// 测试 14: 端到端 Wireshark 级正则 matches 与离散集合 in [set] AST 编译求值
#[test]
fn test_e2e_ast_regex_matches_and_discrete_set_membership() {
    let filter = omni_probe_tauri_lib::filter_ast::CompiledFilter::compile(
        r#"payload matches "(?i)malicious_injection" && tcp.dstport in [502, 20000, 47808]"#
    ).unwrap();

    let pkt_match = create_mock_packet_record(
        1001, "192.168.1.10", "192.168.1.50", 12345, 502, "MODBUS", "00", 64,
    );
    let is_matched = filter.matches(
        &pkt_match.src_ip, &pkt_match.dst_ip, pkt_match.src_port, pkt_match.dst_port,
        &pkt_match.protocol, pkt_match.length, pkt_match.entropy,
        "ALERT: Detected malicious_injection in payload"
    );
    assert!(is_matched);

    let is_not_matched_port = filter.matches(
        &pkt_match.src_ip, &pkt_match.dst_ip, pkt_match.src_port, 80, // port 80 不在 [502, 20000, 47808] 中
        &pkt_match.protocol, pkt_match.length, pkt_match.entropy,
        "ALERT: Detected malicious_injection in payload"
    );
    assert!(!is_not_matched_port);
}

/// 测试 15: 端到端 Suricata / Snort 标准规则 DSL 动态解析与 Aho-Corasick 线速匹配
#[test]
fn test_e2e_suricata_dsl_rule_loading_and_pipeline_detection() {
    let dsl = r#"
alert tcp any any -> any 502 (msg:"Modbus Disruption Command"; content:"|00 00 00 00 00 06 01 05|"; sid:800001; rev:1; metadata:severity critical, category ics_disruption;)
    "#;
    let mut ac = omni_probe_tauri_lib::threat_detector::AhoCorasickAutomaton::new();
    let count = omni_probe_tauri_lib::threat_detector::load_suricata_rules_dsl(dsl, &mut ac).unwrap();
    assert_eq!(count, 1);

    let frame = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x00];
    let hits = ac.scan(&frame);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].signature_id, 800001);
    assert_eq!(hits[0].name, "Modbus Disruption Command");
}

/// 测试 16: 端到端 RFC 3161 TSA DER 编码与 PCAPng 防伪凭据封装
#[test]
fn test_e2e_rfc3161_tsa_and_merkle_authenticity() {
    let merkle_root = [0xABu8; 32];
    let req = omni_probe_tauri_lib::export_engine::TsaRequest::new(&merkle_root);
    let der = req.encode_der();
    assert_eq!(der[0], 0x30); // Sequence Tag

    let token = omni_probe_tauri_lib::export_engine::generate_deterministic_tsa_token(
        &req, "National Time Service Center", "20261108034500Z",
    );
    assert_eq!(token.status, 0);
    assert!(token.token_der.starts_with(b"RFC3161_TSA_AUTH_TOKEN_V1_"));
}

/// 测试 17: 端到端 DNP3 (IEEE 1815) 与 BACnet/IP (ISO 16484-5) 工业规约解构
#[test]
fn test_e2e_dnp3_and_bacnet_protocol_dissection() {
    let dnp3_bytes = vec![
        0x05, 0x64, 0x0B, 0xC4, 0x01, 0x00, 0x02, 0x00, 0xAA, 0xBB, 0xC0, 0xC0, 0x01,
    ];
    let dnp3_map = omni_probe_tauri_lib::dpi::dissect_payload("DNP3", &dnp3_bytes);
    assert_eq!(dnp3_map.get("dnp3_func_name").unwrap(), &serde_json::json!("READ"));

    let bacnet_bytes = vec![
        0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x00, 0x0C,
    ];
    let bacnet_map = omni_probe_tauri_lib::dpi::dissect_payload("BACNET", &bacnet_bytes);
    assert_eq!(bacnet_map.get("bacnet_service_name").unwrap(), &serde_json::json!("ReadProperty"));
}

/// 测试 18: 端到端 VCD 逻辑分析仪物理采样波形 UART 字节恢复
#[test]
fn test_e2e_vcd_waveform_physical_uart_decoding() {
    let vcd = r#"
$timescale 1 us $end
$var wire 1 ! rx $end
$enddefinitions $end
#0
1!
#10
0!
#19
1!
#27
0!
#71
1!
#79
0!
#88
1!
#120
1!
"#;
    let res = omni_probe_tauri_lib::serial::decode_vcd_uart_waveform(vcd, "rx", 115200).unwrap();
    assert_eq!(res.decoded_bytes, vec![b'A']);
}
"""

text_lf = text.replace("\r\n", "\n")
if "test_e2e_ast_regex_matches_and_discrete_set_membership" not in text_lf:
    text_lf = text_lf.rstrip() + "\n" + new_tests

with open("src-tauri/tests/hardcore_e2e_pipeline_verification.rs", "w", encoding="utf-8") as f:
    f.write(text_lf)

print("Added E2E tests 14-18 successfully.")
