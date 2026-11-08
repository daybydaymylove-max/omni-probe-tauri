with open("src-tauri/src/dpi.rs", "r", encoding="utf-8") as f:
    text = f.read()

# 1. Update match_by_port to use validate_dnp3 and validate_bacnet
old_ports = """    if p(47808) { return "BACNET".to_string(); }              // BACnet/IP
    if p(20000) { return "DNP3".to_string(); }                // DNP3"""

new_ports = """    if p(47808) { return validate_bacnet(payload); }          // BACnet/IP
    if p(20000) { return validate_dnp3(payload); }            // DNP3"""

assert old_ports in text, "old_ports not found"
text = text.replace(old_ports, new_ports, 1)

# 2. Add validate_dnp3 and validate_bacnet functions
validators = """
/// 校验 DNP3 (IEEE 1815) 报文
fn validate_dnp3(payload: &[u8]) -> String {
    if payload.len() >= 10 && payload[0] == 0x05 && payload[1] == 0x64 {
        "DNP3".to_string()
    } else {
        "DNP3_INVALID".to_string()
    }
}

/// 校验 BACnet/IP (ISO 16484-5) 报文
fn validate_bacnet(payload: &[u8]) -> String {
    if payload.len() >= 4 && payload[0] == 0x81 {
        let bvll_fn = payload[1];
        if bvll_fn == 0x0A || bvll_fn == 0x0B || bvll_fn == 0x04 {
            return "BACNET".to_string();
        }
    }
    "BACNET_INVALID".to_string()
}
"""

marker_val = "/// 阶段一：基于众所周知端口（IANA Well-Known Ports）的精确匹配"
assert marker_val in text
text = text.replace(marker_val, validators + "\n" + marker_val, 1)

# 3. Add DNP3 and BACnet dissection to dissect_payload
dnp3_bacnet_dissection = """    // DNP3 (Distributed Network Protocol 3.0 / IEEE 1815) 工业电力解构
    if protocol.to_uppercase().contains("DNP3") || (payload.len() >= 10 && payload[0] == 0x05 && payload[1] == 0x64) {
        result.insert("dnp3_start_bytes".into(), serde_json::json!("0x0564"));
        let length = payload[2];
        result.insert("dnp3_length".into(), serde_json::json!(length));
        let ctrl = payload[3];
        result.insert("dnp3_ctrl_hex".into(), serde_json::json!(format!("0x{:02X}", ctrl)));
        result.insert("dnp3_ctrl_dir".into(), serde_json::json!((ctrl & 0x80) != 0));
        result.insert("dnp3_ctrl_prm".into(), serde_json::json!((ctrl & 0x40) != 0));

        let dst = u16::from_le_bytes([payload[4], payload[5]]);
        let src = u16::from_le_bytes([payload[6], payload[7]]);
        result.insert("dnp3_dst".into(), serde_json::json!(dst));
        result.insert("dnp3_src".into(), serde_json::json!(src));

        if payload.len() >= 13 {
            let app_ctrl = payload[11];
            let func_code = payload[12];
            result.insert("dnp3_app_ctrl_hex".into(), serde_json::json!(format!("0x{:02X}", app_ctrl)));
            result.insert("dnp3_func_code".into(), serde_json::json!(func_code));

            let func_name = match func_code {
                0x01 => "READ",
                0x02 => "WRITE",
                0x03 => "SELECT",
                0x04 => "OPERATE",
                0x05 => "DIRECT_OPERATE",
                0x06 => "DIRECT_OPERATE_NR",
                0x0D => "COLD_RESTART",
                0x0E => "WARM_RESTART",
                0x81 => "RESPONSE",
                0x82 => "UNSOLICITED_RESPONSE",
                _ => "CUSTOM_FUNCTION",
            };
            result.insert("dnp3_func_name".into(), serde_json::json!(func_name));
            result.insert("summary".into(), serde_json::json!(format!("DNP3 {} (Src: {}, Dst: {})", func_name, src, dst)));
        } else {
            result.insert("summary".into(), serde_json::json!(format!("DNP3 Link Frame (Src: {}, Dst: {})", src, dst)));
        }
        return result;
    }

    // BACnet/IP (Building Automation and Control Networks / ISO 16484-5) 楼宇智控解构
    if protocol.to_uppercase().contains("BACNET") || (payload.len() >= 4 && payload[0] == 0x81) {
        result.insert("bacnet_bvll_type".into(), serde_json::json!(payload[0]));
        let bvll_fn = payload[1];
        result.insert("bacnet_bvll_function".into(), serde_json::json!(bvll_fn));
        let bvll_fn_name = match bvll_fn {
            0x04 => "Forwarded-NPDU",
            0x0A => "BACnet-Unicast-NPDU",
            0x0B => "BACnet-Broadcast-NPDU",
            _ => "BACnet-BVLL-Other",
        };
        result.insert("bacnet_bvll_func_name".into(), serde_json::json!(bvll_fn_name));
        let bvll_len = u16::from_be_bytes([payload[2], payload[3]]);
        result.insert("bacnet_bvll_length".into(), serde_json::json!(bvll_len));

        if payload.len() >= 6 {
            result.insert("bacnet_npdu_version".into(), serde_json::json!(payload[4]));
            result.insert("bacnet_npdu_control".into(), serde_json::json!(payload[5]));
        }

        if payload.len() >= 8 {
            let apdu_type = payload[6] >> 4;
            let service_choice = payload[7];
            result.insert("bacnet_apdu_type".into(), serde_json::json!(apdu_type));
            result.insert("bacnet_service_choice".into(), serde_json::json!(service_choice));

            let service_name = match (apdu_type, service_choice) {
                (0, 0x0C) => "ReadProperty",
                (0, 0x0E) => "ReadPropertyMultiple",
                (0, 0x0F) => "WriteProperty",
                (0, 0x10) => "WritePropertyMultiple",
                (1, 0x08) => "Who-Is",
                (1, 0x00) => "I-Am",
                (1, 0x01) => "I-Have",
                _ => "BACnet-Service",
            };
            result.insert("bacnet_service_name".into(), serde_json::json!(service_name));
            result.insert("summary".into(), serde_json::json!(format!("BACnet/IP {} - {}", bvll_fn_name, service_name)));
        } else {
            result.insert("summary".into(), serde_json::json!(format!("BACnet/IP {}", bvll_fn_name)));
        }
        return result;
    }
"""

marker_dissect = "    // 优先尝试工控插件化解包器扩展"
assert marker_dissect in text
text = text.replace(marker_dissect, dnp3_bacnet_dissection + "\n" + marker_dissect, 1)

# 4. Add unit test for DNP3 and BACnet
test_dnp3_bacnet = """
    #[test]
    fn test_dnp3_and_bacnet_dpi_dissection() {
        // 1. DNP3 Direct Operate 指令测试
        let mut dnp3_payload = vec![
            0x05, 0x64, // Start
            0x0B,       // Length
            0xC4,       // Control: DIR=1, PRM=1, FCB=0, FCV=0, Func=4
            0x01, 0x00, // Dst = 1
            0x02, 0x00, // Src = 2
            0xAA, 0xBB, // CRC
            0xC0,       // Transport Header
            0xC0,       // App Control
            0x05,       // Func = DIRECT_OPERATE (0x05)
        ];
        let dnp3_res = dissect_payload("DNP3", &dnp3_payload);
        assert_eq!(dnp3_res.get("dnp3_src").unwrap(), &serde_json::json!(2));
        assert_eq!(dnp3_res.get("dnp3_dst").unwrap(), &serde_json::json!(1));
        assert_eq!(dnp3_res.get("dnp3_func_code").unwrap(), &serde_json::json!(5));
        assert_eq!(dnp3_res.get("dnp3_func_name").unwrap(), &serde_json::json!("DIRECT_OPERATE"));

        // 2. BACnet/IP Unicast ReadProperty 测试
        let bacnet_payload = vec![
            0x81,       // BVLL Type
            0x0A,       // Function: BACnet-Unicast-NPDU
            0x00, 0x08, // Length: 8
            0x01,       // NPDU Version: 1
            0x00,       // NPDU Control: normal priority
            0x00,       // APDU Type: Confirmed-Request (0)
            0x0C,       // Service Choice: ReadProperty (0x0C)
        ];
        let bacnet_res = dissect_payload("BACNET", &bacnet_payload);
        assert_eq!(bacnet_res.get("bacnet_bvll_function").unwrap(), &serde_json::json!(0x0A));
        assert_eq!(bacnet_res.get("bacnet_service_name").unwrap(), &serde_json::json!("ReadProperty"));
        let summary = bacnet_res.get("summary").unwrap().as_str().unwrap();
        assert!(summary.contains("ReadProperty"));
    }
"""

last_brace = text.rfind("}")
assert last_brace != -1
text = text[:last_brace] + test_dnp3_bacnet + "\n}\n"

with open("src-tauri/src/dpi.rs", "w", encoding="utf-8") as f:
    f.write(text)

print("Added DNP3 and BACnet dissectors successfully.")
