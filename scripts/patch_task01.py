with open('src-tauri/src/sniffer.rs', 'r', encoding='utf-8') as f:
    text = f.read()

target = '''    // (6) 违规外联审查 (非授信外网连接与黑名单资产审计)
    crate::audit_confidentiality::inspect_egress_domain(&record.src_ip, &record.dst_ip);'''

replacement = '''    // (6) 违规外联审查 (非授信外网连接与黑名单资产审计)
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
    }'''

if target in text:
    text = text.replace(target, replacement, 1)
    with open('src-tauri/src/sniffer.rs', 'w', encoding='utf-8') as f:
        f.write(text)
    print("TASK01_SNIFFER_INTEGRATED")
else:
    print("TARGET_NOT_FOUND")
